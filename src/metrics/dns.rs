//! DNS health probe: resolves a rotating name against each configured resolver and
//! records lookup latency (or failure). Uses `hickory-resolver`.
//!
//! Building resolvers and performing lookups needs the network / OS resolver config, so
//! this is covered by an ignored integration test; the reducer handling of DNS samples is
//! unit-tested separately.
//!
//! [`DnsIntegrityProbe`] asks a different question from the timing one: not "how fast did
//! the resolver answer" but "was the answer its own". It can catch a resolver answering for
//! names it does not own ([`Integrity::Hijacked`]) or something answering *in place of* the
//! resolver ([`Integrity::Forged`]). Every rule is shaped to have almost no false positives,
//! because an integrity warning accuses somebody of something — and each one withholds its
//! verdict on silence, since during an outage nothing answers and nobody is to blame.
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
use hickory_resolver::proto::rr::RecordType;

use crate::config::Resolver as ResolverCfg;
use crate::metrics::{Probe, Sample};

/// What one lookup actually did.
///
/// The distinction between the last two is the whole point. `Option<f64>` collapsed them,
/// so a resolver that answered promptly — and whose answer had simply been replaced with an
/// empty one somewhere in the path — was reported identically to a resolver that was down.
/// One of those is the resolver's fault and the other is not.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Answer {
    /// Addresses came back, in `ms`.
    Addresses(f64),
    /// A well-formed, prompt "I have nothing" (NODATA or NXDOMAIN). The resolver is *up*.
    /// For a name that must resolve globally this is evidence of forgery — but it is never
    /// evidence that the resolver is unreachable.
    Empty(f64),
    /// Nothing arrived before the deadline, or the transport failed outright.
    Silence,
}

impl Answer {
    /// Elapsed time, for the answers that had one. `Silence` never has a latency: the
    /// deadline is ours, not a measurement of the resolver.
    pub fn latency_ms(&self) -> Option<f64> {
        match self {
            Self::Addresses(ms) | Self::Empty(ms) => Some(*ms),
            Self::Silence => None,
        }
    }

    /// Whether the resolver proved it is reachable, whatever it had to say.
    pub fn reached(&self) -> bool {
        !matches!(self, Self::Silence)
    }
}

/// The honesty verdict for one resolver.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Integrity {
    #[default]
    Honest,
    /// Answering for names it does not own: an address for a name that cannot exist, or a
    /// public name pointed at a box on this network.
    Hijacked,
    /// Something is answering *instead of* the resolver. Names that must resolve globally
    /// come back well-formed and empty from a server that is plainly reachable — the reply
    /// is not the resolver's own, and following it gets you nowhere.
    Forged,
}

/// Names that resolve for everyone, used as controls.
///
/// Two of them, and forgery is only claimed when *both* come back empty: one name can be
/// blocked by a filtering resolver as a matter of policy, but a resolver with nothing to say
/// about either of these is not the one answering.
pub fn control_names() -> [String; 2] {
    [absolute("example.com"), absolute("wikipedia.org")]
}

/// Ask for a name as an absolute one.
///
/// Without the trailing dot the OS search list is appended to anything with fewer dots than
/// `ndots`, so `np…nx.com` leaves the machine as `np…nx.com.corp.example.` — we then measure,
/// and pass judgement on, a name we never meant to ask about. `dig` does not do this to the
/// same name, which is exactly why the two disagreed.
pub fn absolute(name: &str) -> String {
    if name.ends_with('.') {
        name.to_string()
    } else {
        format!("{name}.")
    }
}

/// Reduce the control replies to the single answer the ruleset judges.
///
/// Forgery is only claimed when *every* control came back empty: a filtering resolver may
/// refuse one name as a matter of policy, but a resolver with nothing to say about any name
/// that resolves for everyone is not the one answering. One real answer clears it, and any
/// silence withholds the claim — during an outage there is nothing to accuse anyone of.
pub fn combine_controls(answers: &[Answer]) -> Answer {
    if let Some(a) = answers
        .iter()
        .find(|a| matches!(a, Answer::Addresses(_)))
        .copied()
    {
        return a;
    }
    if answers.is_empty() || answers.iter().any(|a| !a.reached()) {
        return Answer::Silence;
    }
    Answer::Empty(
        answers
            .iter()
            .filter_map(Answer::latency_ms)
            .fold(0.0, f64::max),
    )
}

/// The integrity ruleset, kept pure so every branch is testable without a socket.
///
/// `missing` is the reply for a name that cannot exist; `control` is the reply for names that
/// must resolve. Silence yields no verdict at all — during an outage every lookup fails, and
/// an outage is not evidence of dishonesty.
pub fn verdict(control: Answer, control_addrs: &[IpAddr], missing_addrs: &[IpAddr]) -> Integrity {
    if nxdomain_is_hijacked(missing_addrs) || answers_look_intercepted(control_addrs) {
        return Integrity::Hijacked;
    }
    if matches!(control, Answer::Empty(_)) {
        return Integrity::Forged;
    }
    Integrity::Honest
}

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
                    let (_, missing_addrs) = lookup_a(timeout, resolver, &missing).await;
                    let mut answers = Vec::new();
                    let mut control_addrs = Vec::new();
                    for name in control_names() {
                        let (a, addrs) = lookup_a(timeout, resolver, &name).await;
                        answers.push(a);
                        control_addrs.extend(addrs);
                    }
                    Sample::DnsIntegrity {
                        resolver: rname.clone(),
                        verdict: verdict(
                            combine_controls(&answers),
                            &control_addrs,
                            &missing_addrs,
                        ),
                    }
                }
            });
            futures::future::join_all(futs).await
        }
    }
}

/// One A lookup under `timeout`, reduced to what happened and whatever addresses came back.
///
/// A-only on purpose. `lookup_ip` asks for A and AAAA and fails the pair when the AAAA half
/// comes back empty, which turned honest resolvers into intermittent failures; the integrity
/// rules only ever need one address family to reason about.
async fn lookup_a(
    timeout: Duration,
    resolver: &TokioResolver,
    name: &str,
) -> (Answer, Vec<IpAddr>) {
    match timed(timeout, resolver.lookup(absolute(name), RecordType::A)).await {
        Some((ms, Ok(l))) => {
            let addrs: Vec<IpAddr> = l
                .answers()
                .iter()
                .filter_map(|r| r.data.ip_addr())
                .collect();
            if addrs.is_empty() {
                (Answer::Empty(ms), addrs)
            } else {
                (Answer::Addresses(ms), addrs)
            }
        }
        // The resolver replied — it simply had no records. That is a live resolver, and the
        // distinction from silence is the whole reason this function exists.
        Some((ms, Err(e))) if e.is_no_records_found() => (Answer::Empty(ms), Vec::new()),
        Some((_, Err(_))) | None => (Answer::Silence, Vec::new()),
    }
}

/// Await `fut` under `timeout`, reporting how long it took.
///
/// `None` is the deadline expiring. Bounding the wait is what keeps a slow or unreachable
/// resolver from stretching the probe cycle past its cadence — without it hickory retries for
/// ~10s and the DNS panel freezes.
async fn timed<F, T>(timeout: Duration, fut: F) -> Option<(f64, T)>
where
    F: std::future::Future<Output = T>,
{
    let start = Instant::now();
    match tokio::time::timeout(timeout, fut).await {
        Ok(v) => Some((start.elapsed().as_secs_f64() * 1000.0, v)),
        Err(_) => None,
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

/// Await one dual-stack lookup under `timeout` and say what it did.
///
/// Dual-stack rather than A-only because this probe measures what an application waits for,
/// and applications call `getaddrinfo`. Bounding the wait is what keeps a slow/unreachable
/// resolver from stretching the probe cycle past its cadence.
async fn measure_lookup(timeout: Duration, resolver: &TokioResolver, name: &str) -> Answer {
    match timed(timeout, resolver.lookup_ip(absolute(name))).await {
        Some((ms, Ok(r))) if r.iter().next().is_some() => Answer::Addresses(ms),
        // Answered, with nothing in it. The resolver is up; whether the emptiness is honest
        // is the integrity probe's question, not this one's.
        Some((ms, Ok(_))) => Answer::Empty(ms),
        Some((ms, Err(e))) if e.is_no_records_found() => Answer::Empty(ms),
        Some((_, Err(_))) | None => Answer::Silence,
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
                    Sample::Dns {
                        resolver: rname.clone(),
                        answer: measure_lookup(timeout, resolver, &name).await,
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

    // --- asking the question we meant to ask ---

    #[test]
    fn names_are_asked_as_absolute_so_the_search_list_cannot_rewrite_them() {
        // `np…nx.com` has one dot and the default ndots is 1, so the OS search list gets
        // appended and the query that leaves the machine is `np…nx.com.corp.example.` —
        // a different name, owned by somebody else, whose answer we then judge.
        assert_eq!(absolute("example.com"), "example.com.");
        assert_eq!(
            absolute(&nonexistent_name(7)),
            format!("{}.", nonexistent_name(7))
        );
    }

    #[test]
    fn an_already_absolute_name_is_left_alone() {
        assert_eq!(absolute("example.com."), "example.com.");
    }

    #[test]
    fn every_control_name_is_absolute() {
        for n in control_names() {
            assert!(n.ends_with('.'), "control name must be absolute: {n}");
        }
    }

    // --- what a lookup actually did ---

    #[test]
    fn silence_has_no_latency_but_an_empty_answer_does() {
        assert_eq!(Answer::Addresses(12.0).latency_ms(), Some(12.0));
        assert_eq!(Answer::Empty(4.0).latency_ms(), Some(4.0));
        assert_eq!(
            Answer::Silence.latency_ms(),
            None,
            "the deadline is ours, not a measurement of the resolver"
        );
    }

    #[test]
    fn a_resolver_that_said_anything_at_all_was_reached() {
        assert!(Answer::Addresses(1.0).reached());
        assert!(
            Answer::Empty(1.0).reached(),
            "an empty answer is still an answer"
        );
        assert!(!Answer::Silence.reached());
    }

    // --- the integrity ruleset ---

    #[test]
    fn a_resolver_that_answers_normally_is_honest() {
        assert_eq!(
            verdict(Answer::Addresses(10.0), &ips(&["93.184.215.14"]), &[]),
            Integrity::Honest
        );
    }

    #[test]
    fn an_address_for_a_name_that_cannot_exist_is_still_a_hijack() {
        assert_eq!(
            verdict(
                Answer::Addresses(10.0),
                &ips(&["93.184.215.14"]),
                &ips(&["92.242.140.21"])
            ),
            Integrity::Hijacked
        );
    }

    #[test]
    fn a_public_name_pointed_at_this_network_is_still_a_hijack() {
        assert_eq!(
            verdict(Answer::Addresses(10.0), &ips(&["192.168.1.1"]), &[]),
            Integrity::Hijacked
        );
    }

    // The bug this whole change exists for: a middlebox intercepting UDP/53 to a public
    // resolver and replying with a well-formed empty answer in 4ms. The resolver is up and
    // reachable, and every name it is asked about comes back with nothing.
    #[test]
    fn a_name_that_must_resolve_coming_back_empty_is_forged() {
        assert_eq!(
            verdict(Answer::Empty(4.0), &[], &[]),
            Integrity::Forged,
            "a reachable resolver with nothing to say about a name that resolves for \
             everyone is not the one answering"
        );
    }

    // --- combining the controls ---

    #[test]
    fn one_real_answer_clears_the_resolver() {
        assert_eq!(
            combine_controls(&[Answer::Empty(3.0), Answer::Addresses(20.0)]),
            Answer::Addresses(20.0),
            "a resolver that answered one control properly is answering"
        );
    }

    #[test]
    fn every_control_empty_is_a_forgery() {
        assert_eq!(
            combine_controls(&[Answer::Empty(3.0), Answer::Empty(4.0)]),
            Answer::Empty(4.0)
        );
    }

    #[test]
    fn one_blocked_name_is_policy_rather_than_forgery() {
        // A filtering resolver refusing a single name must not be accused of forgery; the
        // other control answering proves it is the one replying.
        assert_eq!(
            combine_controls(&[Answer::Empty(3.0), Answer::Addresses(15.0)]),
            Answer::Addresses(15.0)
        );
    }

    #[test]
    fn any_silence_withholds_the_claim() {
        assert_eq!(
            combine_controls(&[Answer::Empty(3.0), Answer::Silence]),
            Answer::Silence,
            "a lookup that never came back is not evidence of an empty answer"
        );
        assert_eq!(combine_controls(&[]), Answer::Silence);
    }

    // The guard that keeps this from firing during an ordinary outage, when every lookup
    // fails and nothing is being tampered with.
    #[test]
    fn silence_is_never_evidence_of_dishonesty() {
        assert_eq!(
            verdict(Answer::Silence, &[], &[]),
            Integrity::Honest,
            "an outage makes every lookup fail; that is not forgery"
        );
    }

    // The correct reply for the nonexistent name is nothing at all, and that must not be
    // read as the control name having come back empty.
    #[test]
    fn an_empty_answer_for_the_name_that_cannot_exist_is_the_right_answer() {
        assert_eq!(
            verdict(Answer::Addresses(10.0), &ips(&["93.184.215.14"]), &[]),
            Integrity::Honest
        );
    }

    // A hijack and a forgery at once: naming somebody for the redirect is more use than
    // reporting that their reply was empty.
    #[test]
    fn a_hijack_outranks_a_forgery() {
        assert_eq!(
            verdict(Answer::Empty(4.0), &[], &ips(&["92.242.140.21"])),
            Integrity::Hijacked
        );
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

    /// The system resolver, or `None` when the host has none configured — an absent
    /// capability, which the live tier skips rather than fails.
    fn live_resolver() -> Option<TokioResolver> {
        build_resolver(&ResolverCfg {
            name: "system".into(),
            addr: None,
        })
    }

    // The bug these two guard is not reachable from a unit test: hickory reports "the resolver
    // replied, and it has no records" as an *Err*, and only a real resolver produces it.
    // Reading that Err as silence is what painted working resolvers FAIL.

    #[tokio::test]
    #[ignore = "requires network / DNS"]
    async fn a_name_with_no_address_is_empty_rather_than_silent() {
        let Some(resolver) = live_resolver() else {
            return;
        };
        let timeout = Duration::from_secs(4);

        // If DNS itself is unavailable there is nothing here to test; skip rather than fail.
        let (control, _) = lookup_a(timeout, &resolver, "example.com").await;
        if !matches!(control, Answer::Addresses(_)) {
            return;
        }

        // Exists, and deliberately holds no A record (DMARC policy lives in TXT).
        let (answer, addrs) = lookup_a(timeout, &resolver, "_dmarc.google.com").await;
        assert!(addrs.is_empty(), "a NODATA reply carries no addresses");
        assert!(
            matches!(answer, Answer::Empty(_)),
            "a resolver that says 'I have nothing' is up, not silent: {answer:?}"
        );
    }

    #[tokio::test]
    #[ignore = "requires network / DNS"]
    async fn an_nxdomain_is_empty_rather_than_silent() {
        let Some(resolver) = live_resolver() else {
            return;
        };
        let timeout = Duration::from_secs(4);

        let (control, _) = lookup_a(timeout, &resolver, "example.com").await;
        if !matches!(control, Answer::Addresses(_)) {
            return;
        }

        let (answer, addrs) = lookup_a(timeout, &resolver, &nonexistent_name(0xfeed)).await;
        assert!(addrs.is_empty(), "an NXDOMAIN carries no addresses");
        assert!(
            matches!(answer, Answer::Empty(_)),
            "NXDOMAIN is an answer, not a timeout: {answer:?}"
        );
    }

    // Same distinction, one layer up: the timing probe's own lookup path.
    #[tokio::test]
    #[ignore = "requires network / DNS"]
    async fn the_timing_probe_does_not_read_an_empty_answer_as_unreachable() {
        let Some(resolver) = live_resolver() else {
            return;
        };
        let timeout = Duration::from_secs(4);

        if !matches!(
            measure_lookup(timeout, &resolver, "example.com").await,
            Answer::Addresses(_)
        ) {
            return;
        }

        let answer = measure_lookup(timeout, &resolver, "_dmarc.google.com").await;
        assert!(
            matches!(answer, Answer::Empty(_)),
            "the DNS panel must not read a NODATA as FAIL: {answer:?}"
        );
    }

    // A lookup that outlives its deadline must be abandoned *promptly*, rather than blocking
    // the whole probe cycle past its cadence (which froze the DNS panel).
    #[tokio::test(start_paused = true)]
    async fn slow_lookup_is_abandoned_at_the_deadline() {
        let out = timed(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_secs(30)).await;
        })
        .await;
        assert!(out.is_none(), "the deadline must cut the lookup off");
    }

    #[tokio::test(start_paused = true)]
    async fn fast_lookup_reports_latency() {
        let out = timed(Duration::from_millis(100), async {
            tokio::time::sleep(Duration::from_millis(5)).await;
        })
        .await;
        assert!(
            out.is_some(),
            "a lookup within the deadline reports latency"
        );
    }
}
