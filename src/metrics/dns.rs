//! DNS health probe: resolves a rotating name against each configured resolver and
//! records lookup latency (or failure). Uses `hickory-resolver`.
//!
//! Building resolvers and performing lookups needs the network / OS resolver config, so
//! this is covered by an ignored integration test; the reducer handling of DNS samples is
//! unit-tested separately.
//!
//! [`DnsIntegrityProbe`] asks a different question from the timing one: not "how fast did
//! the resolver answer" but "was the answer its own". Both of its rules are shaped to have
//! almost no false positives, because an integrity warning accuses somebody of something.
//!
//! Raw answer *divergence* between resolvers is deliberately not one of them. CDNs steer by
//! resolver location, so two resolvers returning completely different addresses for the same
//! name is the normal case, not a signal — an alarm on it would fire constantly and mean
//! nothing.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use hickory_resolver::Resolver;
use hickory_resolver::TokioResolver;
use hickory_resolver::config::{NameServerConfig, ResolverConfig};
use hickory_resolver::net::runtime::TokioRuntimeProvider;

use crate::config::Resolver as ResolverCfg;
use crate::metrics::{Probe, Sample};

/// Rotating set of names to look up (rotating reduces resolver-cache hits so the timing
/// reflects real work).
fn default_names() -> Vec<String> {
    [
        "example.com",
        "wikipedia.org",
        "github.com",
        "cloudflare.com",
        "mozilla.org",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

fn build_resolver(cfg: &ResolverCfg) -> Option<TokioResolver> {
    match &cfg.addr {
        Some(addr) => {
            let ip: IpAddr = addr.parse().ok()?;
            let config =
                ResolverConfig::from_parts(None, vec![], vec![NameServerConfig::udp_and_tcp(ip)]);
            Resolver::builder_with_config(config, TokioRuntimeProvider::default())
                .build()
                .ok()
        }
        None => Resolver::builder_tokio().ok()?.build().ok(),
    }
}

/// Whether answers to a name that cannot exist mean somebody is synthesizing replies.
///
/// A random label under `.com` has no owner, so the only correct reply is NXDOMAIN. An
/// address instead means a resolver (or something in front of it) is answering on the
/// domain's behalf, and every typo the user makes lands on whatever is at that address.
///
/// `0.0.0.0` / `::` are excluded: that is how a filtering resolver says "no", and it sends
/// the client nowhere. A policy answer, not an interception.
pub fn nxdomain_is_hijacked(answers: &[IpAddr]) -> bool {
    answers.iter().any(|ip| !ip.is_unspecified())
}

/// Whether answers for a *public* name point somewhere on the local network.
///
/// A name that resolves globally cannot legitimately live at an RFC1918, loopback or
/// link-local address. When it does, something between here and the resolver is redirecting
/// the name to a box on this network — a portal, a filter, or something worse.
pub fn answers_look_intercepted(answers: &[IpAddr]) -> bool {
    answers.iter().any(|ip| match ip {
        IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_unspecified()
        }
        // `is_unique_local` is still unstable, so fc00::/7 is checked by hand.
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                || (v6.segments()[0] & 0xffc0) == 0xfe80
        }
    })
}

/// A name nobody can have registered, for the NXDOMAIN check.
///
/// Under `.com` rather than `.invalid`: the point is to see what the real resolution path
/// does with a real NXDOMAIN, and resolvers short-circuit the reserved TLDs. Deterministic in
/// `seed` so the tests are not at the mercy of a random number.
pub fn nonexistent_name(seed: u64) -> String {
    format!("np{seed:016x}nx.com")
}

/// Checks that resolvers are answering honestly, rather than quickly.
///
/// Two lookups per resolver per tick, on a cadence measured in minutes — a DNS query is a
/// few hundred bytes, so this stays well inside the no-flooding rule.
pub struct DnsIntegrityProbe {
    resolvers: Vec<(String, TokioResolver)>,
    timeout: Duration,
    /// Advanced each tick so each round asks about a name the previous round did not — a fixed
    /// name would sit in the resolver's negative cache and stop testing anything.
    seed: u64,
}

impl DnsIntegrityProbe {
    pub fn new(cfgs: &[ResolverCfg], timeout: Duration, seed: u64) -> Self {
        Self {
            resolvers: cfgs
                .iter()
                .filter_map(|c| build_resolver(c).map(|r| (c.name.clone(), r)))
                .collect(),
            timeout,
            seed,
        }
    }

    /// Seeded from the wall clock, for callers with no seed of their own.
    pub fn with_clock_seed(cfgs: &[ResolverCfg], timeout: Duration) -> Self {
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos() as u64);
        Self::new(cfgs, timeout, seed)
    }
}

impl Probe for DnsIntegrityProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        self.seed = self
            .seed
            .wrapping_mul(6_364_136_223_846_793_005)
            .wrapping_add(1);
        let missing = nonexistent_name(self.seed);
        let resolvers = &self.resolvers;
        let timeout = self.timeout;
        async move {
            let futs = resolvers.iter().map(|(rname, resolver)| {
                let missing = missing.clone();
                async move {
                    let hijacked = lookup_addrs(timeout, resolver, &missing)
                        .await
                        .is_some_and(|a| nxdomain_is_hijacked(&a));
                    let intercepted = lookup_addrs(timeout, resolver, "example.com")
                        .await
                        .is_some_and(|a| answers_look_intercepted(&a));
                    Sample::DnsIntegrity {
                        resolver: rname.clone(),
                        hijacked: hijacked || intercepted,
                    }
                }
            });
            futures::future::join_all(futs).await
        }
    }
}

/// One lookup under `timeout`, yielding the addresses. `None` when the lookup failed — which
/// for the NXDOMAIN check is the *healthy* answer, and for the interception check is simply
/// no evidence either way.
async fn lookup_addrs(
    timeout: Duration,
    resolver: &TokioResolver,
    name: &str,
) -> Option<Vec<IpAddr>> {
    match tokio::time::timeout(timeout, resolver.lookup_ip(name)).await {
        Ok(Ok(r)) => Some(r.iter().collect()),
        _ => None,
    }
}

/// Benchmarks a set of DNS resolvers.
pub struct DnsProbe {
    resolvers: Vec<(String, TokioResolver)>,
    names: Vec<String>,
    idx: usize,
    /// Per-lookup deadline. Without it, hickory retries a stuck resolver for up to
    /// ~10s (5s × 2 attempts); since `tick` joins across resolvers, one slow resolver
    /// would then stall the whole DNS cycle past its cadence and freeze the panel.
    timeout: Duration,
}

impl DnsProbe {
    pub fn new(cfgs: &[ResolverCfg], timeout: Duration) -> Self {
        let resolvers = cfgs
            .iter()
            .filter_map(|c| build_resolver(c).map(|r| (c.name.clone(), r)))
            .collect();
        Self {
            resolvers,
            names: default_names(),
            idx: 0,
            timeout,
        }
    }

    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }
}

/// Await one DNS lookup under `timeout`. Returns the elapsed lookup time in milliseconds
/// on success, or `None` if the lookup errored *or* exceeded the deadline (both are
/// treated as a failed resolution by the reducer). Bounding the wait is what keeps a
/// slow/unreachable resolver from stretching the probe cycle past its cadence.
async fn measure_lookup<F, T, E>(timeout: Duration, fut: F) -> Option<f64>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let start = Instant::now();
    match tokio::time::timeout(timeout, fut).await {
        Ok(Ok(_)) => Some(start.elapsed().as_secs_f64() * 1000.0),
        Ok(Err(_)) | Err(_) => None,
    }
}

impl Probe for DnsProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        let name = self.names[self.idx % self.names.len()].clone();
        self.idx = self.idx.wrapping_add(1);
        let resolvers = &self.resolvers;
        let timeout = self.timeout;
        async move {
            let futs = resolvers.iter().map(|(rname, resolver)| {
                let name = name.clone();
                async move {
                    let latency_ms =
                        measure_lookup(timeout, resolver.lookup_ip(name.as_str())).await;
                    Sample::Dns {
                        resolver: rname.clone(),
                        latency_ms,
                    }
                }
            });
            futures::future::join_all(futs).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use pretty_assertions::assert_eq;

    // --- integrity ---

    fn ips(addrs: &[&str]) -> Vec<IpAddr> {
        addrs.iter().map(|a| a.parse().unwrap()).collect()
    }

    #[test]
    fn any_real_answer_for_a_name_that_cannot_exist_is_a_hijack() {
        assert!(nxdomain_is_hijacked(&ips(&["92.242.140.21"])));
        assert!(nxdomain_is_hijacked(&ips(&["2001:db8::1"])));
    }

    #[test]
    fn no_answer_at_all_is_the_correct_answer() {
        assert!(!nxdomain_is_hijacked(&[]));
    }

    #[test]
    fn an_unspecified_address_is_a_refusal_rather_than_a_redirect() {
        // 0.0.0.0 / :: is how a filtering resolver says "no". It sends the client nowhere,
        // so it is a policy answer, not an interception.
        assert!(!nxdomain_is_hijacked(&ips(&["0.0.0.0", "::"])));
    }

    #[test]
    fn a_public_name_answered_with_a_local_address_is_intercepted() {
        for addr in ["10.0.0.1", "192.168.1.1", "172.16.0.1", "127.0.0.1"] {
            assert!(
                answers_look_intercepted(&ips(&[addr])),
                "{addr} cannot host a public name"
            );
        }
        assert!(answers_look_intercepted(&ips(&["fd00::1"])), "unique-local");
        assert!(answers_look_intercepted(&ips(&["169.254.1.1"])), "APIPA");
    }

    #[test]
    fn ordinary_public_answers_are_left_alone() {
        assert!(!answers_look_intercepted(&ips(&[
            "93.184.215.14",
            "2606:2800:21f:cb07:6820:80da:af6b:8b2c"
        ])));
    }

    #[test]
    fn the_probe_name_is_unguessable_and_stable_for_a_given_seed() {
        let a = nonexistent_name(0x0123_4567_89ab_cdef);
        assert_eq!(a, nonexistent_name(0x0123_4567_89ab_cdef), "deterministic");
        assert_ne!(
            a,
            nonexistent_name(1),
            "a different seed is a different name"
        );
        assert!(
            a.ends_with(".com"),
            "a real TLD, so the NXDOMAIN is real: {a}"
        );
        assert!(
            a.len() > 16,
            "long enough that nobody has registered it: {a}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network / DNS"]
    async fn resolves_against_default_resolvers() {
        let cfg = Config::default();
        let mut probe = DnsProbe::new(&cfg.resolvers, Duration::from_secs(2));
        assert!(probe.resolver_count() >= 1);
        let samples = probe.tick().await;
        assert_eq!(samples.len(), probe.resolver_count());
    }

    // A lookup that outlives its deadline must be reported as a failure *promptly*, rather
    // than blocking the whole probe cycle past its cadence (which froze the DNS panel).
    #[tokio::test(start_paused = true)]
    async fn slow_lookup_times_out_as_failure() {
        let out = measure_lookup(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
            Ok::<(), ()>(())
        })
        .await;
        assert_eq!(out, None);
    }

    #[tokio::test(start_paused = true)]
    async fn fast_lookup_reports_latency() {
        let out = measure_lookup(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_millis(5)).await;
            Ok::<(), ()>(())
        })
        .await;
        assert!(
            out.is_some(),
            "a lookup within the deadline reports latency"
        );
    }

    #[tokio::test]
    async fn failed_lookup_is_none() {
        let out = measure_lookup(Duration::from_secs(1), async { Err::<(), ()>(()) }).await;
        assert_eq!(out, None);
    }
}
