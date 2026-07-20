//! DNS health probe: resolves a rotating name against each configured resolver and
//! records lookup latency (or failure). Uses `hickory-resolver`.
//!
//! Building resolvers and performing lookups needs the network / OS resolver config, so
//! this is covered by an ignored integration test; the reducer handling of DNS samples is
//! unit-tested separately.

use std::net::IpAddr;
use std::time::Instant;

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
}

impl DnsProbe {
    pub fn new(cfgs: &[ResolverCfg]) -> Self {
        let resolvers = cfgs
            .iter()
            .filter_map(|c| build_resolver(c).map(|r| (c.name.clone(), r)))
            .collect();
        Self {
            resolvers,
            names: default_names(),
            idx: 0,
        }
    }

    pub fn resolver_count(&self) -> usize {
        self.resolvers.len()
    }
}

impl Probe for DnsProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        let name = self.names[self.idx % self.names.len()].clone();
        self.idx = self.idx.wrapping_add(1);
        let resolvers = &self.resolvers;
        async move {
            let futs = resolvers.iter().map(|(rname, resolver)| {
                let name = name.clone();
                async move {
                    let start = Instant::now();
                    let latency_ms = match resolver.lookup_ip(name.as_str()).await {
                        Ok(_) => Some(start.elapsed().as_secs_f64() * 1000.0),
                        Err(_) => None,
                    };
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

    #[tokio::test]
    #[ignore = "requires network / DNS"]
    async fn resolves_against_default_resolvers() {
        let cfg = Config::default();
        let mut probe = DnsProbe::new(&cfg.resolvers);
        assert!(probe.resolver_count() >= 1);
        let samples = probe.tick().await;
        assert_eq!(samples.len(), probe.resolver_count());
    }
}
