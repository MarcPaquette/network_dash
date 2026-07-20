//! ICMP latency/loss probe using an unprivileged datagram socket (no root on macOS).
//!
//! Each `tick` pings every target once and emits a [`Sample::Latency`] (with `rtt_ms ==
//! None` on timeout, which the reducer counts as loss). The socket/ping calls need the
//! network, so they are covered by an ignored integration test; the pure target-resolution
//! logic is unit-tested.

use std::net::IpAddr;
use std::time::Duration;

use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};

use crate::metrics::{Probe, Sample};

/// Parse target strings into IPv4 addresses, dropping anything unparseable or non-IPv4.
/// (IPv4-only for now: the client is built for ICMPv4.)
pub fn resolve_ipv4_targets(targets: &[String]) -> Vec<(String, IpAddr)> {
    targets
        .iter()
        .filter_map(|t| match t.parse::<IpAddr>() {
            Ok(ip) if ip.is_ipv4() => Some((t.clone(), ip)),
            _ => None,
        })
        .collect()
}

/// Pings a fixed set of IPv4 targets over one shared datagram ICMP client.
pub struct PingProbe {
    client: Client,
    targets: Vec<(String, IpAddr)>,
    seq: u16,
    timeout: Duration,
}

impl PingProbe {
    pub fn new(targets: &[String], timeout: Duration) -> Result<Self, surge_ping::SurgeError> {
        let config = Config::builder()
            .kind(ICMP::V4)
            .sock_type_hint(socket2::Type::DGRAM)
            .build();
        let client = Client::new(&config)?;
        Ok(Self {
            client,
            targets: resolve_ipv4_targets(targets),
            seq: 0,
            timeout,
        })
    }

    /// Number of resolved (pingable) targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }
}

impl Probe for PingProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let timeout = self.timeout;
        let client = &self.client;
        let targets = &self.targets;
        async move {
            let futs = targets
                .iter()
                .enumerate()
                .map(|(i, (name, ip))| async move {
                    let mut pinger = client.pinger(*ip, PingIdentifier(i as u16)).await;
                    pinger.timeout(timeout);
                    let payload = [0u8; 8];
                    let rtt_ms = match pinger.ping(PingSequence(seq), &payload).await {
                        Ok((_packet, dur)) => Some(dur.as_secs_f64() * 1000.0),
                        Err(_) => None,
                    };
                    Sample::Latency {
                        target: name.clone(),
                        rtt_ms,
                    }
                });
            futures::future::join_all(futs).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn resolves_ipv4_and_drops_the_rest() {
        let targets = vec![
            "1.1.1.1".to_string(),
            "not-an-ip".to_string(),
            "2606:4700:4700::1111".to_string(), // IPv6, dropped
            "8.8.8.8".to_string(),
        ];
        let resolved = resolve_ipv4_targets(&targets);
        let names: Vec<_> = resolved.iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["1.1.1.1", "8.8.8.8"]);
    }

    #[tokio::test]
    #[ignore = "requires a working ICMP datagram socket / network"]
    async fn pings_loopback() {
        let mut probe = PingProbe::new(&["127.0.0.1".to_string()], Duration::from_secs(1)).unwrap();
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 1);
        match &samples[0] {
            Sample::Latency { target, rtt_ms } => {
                assert_eq!(target, "127.0.0.1");
                assert!(rtt_ms.is_some(), "loopback should reply");
            }
            _ => panic!("expected a latency sample"),
        }
    }
}
