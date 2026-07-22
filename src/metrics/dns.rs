//! DNS health probe: resolves a rotating name against each configured resolver and
//! records lookup latency (or failure). Uses `hickory-resolver`.
//!
//! Building resolvers and performing lookups needs the network / OS resolver config, so
//! this is covered by an ignored integration test; the reducer handling of DNS samples is
//! unit-tested separately.

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
