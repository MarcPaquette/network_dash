//! ICMP latency/loss probe using an unprivileged datagram socket (no root on macOS).
//!
//! Each `tick` pings every target once and emits a [`Sample::Latency`] (with `rtt_ms ==
//! None` on timeout, which the reducer counts as loss). The socket/ping calls need the
//! network, so they are covered by an ignored integration test; the pure target-resolution
//! logic is unit-tested.
//!
//! Dual-stack: ICMPv4 and ICMPv6 are separate protocols needing separate sockets, so the
//! probe holds one client per family and builds each only if that family has targets it can
//! actually reach. The two are worth measuring side by side — a v6 path takes different
//! routers than the v4 path to the same operator, and "the internet is slow" is frequently
//! "one of the two stacks is slow and something is preferring it".

use std::net::{IpAddr, UdpSocket};
use std::time::Duration;

use surge_ping::{Client, Config, ICMP, PingIdentifier, PingSequence};

use crate::metrics::{Probe, Sample};

/// A ping target: the string it was configured as, and the address it resolved to.
pub type Target = (String, IpAddr);

/// Parse target strings into addresses of either family, dropping anything unparseable.
pub fn resolve_targets(targets: &[String]) -> Vec<Target> {
    targets
        .iter()
        .filter_map(|t| t.parse::<IpAddr>().ok().map(|ip| (t.clone(), ip)))
        .collect()
}

/// Split resolved targets into `(v4, v6)`. Each family needs its own ICMP socket, so they
/// are separated once here rather than re-tested at every use.
pub fn split_by_family(targets: &[Target]) -> (Vec<Target>, Vec<Target>) {
    targets.iter().cloned().partition(|(_, ip)| ip.is_ipv4())
}

/// The targets worth pinging, given whether this host has IPv6 at all.
///
/// Pure, and separated from the socket setup, because it is the whole of the dual-stack
/// policy: on a v4-only host the v6 targets are dropped rather than pinged into timeouts.
pub fn pingable_targets(targets: &[String], ipv6: bool) -> Vec<Target> {
    let (v4, v6) = split_by_family(&resolve_targets(targets));
    match ipv6 {
        true => v4.into_iter().chain(v6).collect(),
        false => v4,
    }
}

/// Whether this host has a usable IPv6 route.
///
/// A UDP `connect` sends no packets — it only asks the kernel to choose a source address and
/// a route. On a v4-only network that fails immediately with "network unreachable", which is
/// the distinction that matters: "IPv6 is broken" is an alarm, "this network doesn't do IPv6"
/// is not news, and they are indistinguishable from timeouts alone.
pub fn has_ipv6_route() -> bool {
    UdpSocket::bind("[::]:0")
        .and_then(|s| s.connect("[2606:4700:4700::1111]:53"))
        .is_ok()
}

/// Pings a fixed set of targets, one shared datagram ICMP client per address family.
pub struct PingProbe {
    /// One client per family, `None` when that family has no reachable targets. Kept as a
    /// pair rather than a map so a missing stack is a compile-time-visible case.
    v4: Option<Client>,
    v6: Option<Client>,
    targets: Vec<Target>,
    seq: u16,
    timeout: Duration,
}

impl PingProbe {
    pub fn new(targets: &[String], timeout: Duration) -> Result<Self, surge_ping::SurgeError> {
        Self::with_ipv6(targets, timeout, has_ipv6_route())
    }

    /// As [`PingProbe::new`], with the IPv6 verdict supplied — the seam the tests use to
    /// exercise a v4-only host without one.
    pub fn with_ipv6(
        targets: &[String],
        timeout: Duration,
        ipv6: bool,
    ) -> Result<Self, surge_ping::SurgeError> {
        let targets = pingable_targets(targets, ipv6);
        let (v4_targets, v6_targets) = split_by_family(&targets);
        let client = |kind| {
            Client::new(
                &Config::builder()
                    .kind(kind)
                    .sock_type_hint(socket2::Type::DGRAM)
                    .build(),
            )
        };
        // The v4 client is required; a machine that cannot open an ICMPv4 socket has nothing
        // to offer this probe. The v6 one is best-effort — no targets, no route, or a kernel
        // that refuses the socket all mean the same thing: don't ping over v6.
        let v4 = if v4_targets.is_empty() {
            None
        } else {
            Some(client(ICMP::V4)?)
        };
        let v6 = match v6_targets.is_empty() {
            false => client(ICMP::V6).ok(),
            true => None,
        };
        // A v6 socket the kernel refused leaves its targets unpingable, so drop them here
        // too — otherwise every one of them reports as loss forever.
        let targets = match v6.is_some() {
            true => targets,
            false => v4_targets,
        };
        Ok(Self {
            v4,
            v6,
            targets,
            seq: 0,
            timeout,
        })
    }

    /// Number of resolved (pingable) targets.
    pub fn target_count(&self) -> usize {
        self.targets.len()
    }

    /// The targets this probe will actually ping, as configured.
    pub fn target_names(&self) -> Vec<String> {
        self.targets.iter().map(|(n, _)| n.clone()).collect()
    }
}

impl Probe for PingProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        self.seq = self.seq.wrapping_add(1);
        let seq = self.seq;
        let timeout = self.timeout;
        let (v4, v6) = (&self.v4, &self.v6);
        let targets = &self.targets;
        async move {
            let futs = targets
                .iter()
                .enumerate()
                .filter_map(|(i, (name, ip))| {
                    // A target whose family has no client is not skipped silently in effect:
                    // it was never added to `targets` in the first place. This is the
                    // belt-and-braces arm for a client that vanished from under us.
                    let client = if ip.is_ipv4() { v4 } else { v6 };
                    client.as_ref().map(|c| (i, name, ip, c))
                })
                .map(|(i, name, ip, client)| async move {
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
    fn resolves_both_families_and_drops_what_is_not_an_address() {
        let targets = vec![
            "1.1.1.1".to_string(),
            "not-an-ip".to_string(),
            "2606:4700:4700::1111".to_string(),
            "8.8.8.8".to_string(),
        ];
        let names: Vec<_> = resolve_targets(&targets)
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        assert_eq!(
            names,
            vec!["1.1.1.1", "2606:4700:4700::1111", "8.8.8.8"],
            "both families are pingable; only the garbage is dropped"
        );
    }

    #[test]
    fn the_two_families_are_kept_apart() {
        let targets = vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()];
        let (v4, v6) = split_by_family(&resolve_targets(&targets));
        assert_eq!(v4.len(), 1, "one v4 target");
        assert_eq!(v6.len(), 1, "one v6 target");
        assert!(v4[0].1.is_ipv4() && v6[0].1.is_ipv6());
    }

    #[test]
    fn a_host_without_ipv6_pings_nothing_over_it() {
        // The v6 targets are silently dropped rather than reported as 100% loss: a network
        // that does not do IPv6 at all is not a fault, and alarming about it would be the
        // loudest possible way to say "this is normal".
        let targets = vec!["1.1.1.1".to_string(), "2606:4700:4700::1111".to_string()];
        let names: Vec<_> = pingable_targets(&targets, false)
            .iter()
            .map(|(n, _)| n.clone())
            .collect();
        assert_eq!(names, vec!["1.1.1.1"], "only the v4 target survives");
        assert_eq!(
            pingable_targets(&targets, true).len(),
            2,
            "a dual-stack host pings both"
        );
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
