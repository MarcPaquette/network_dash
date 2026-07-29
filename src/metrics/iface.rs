//! Interface error counters — the cheapest fault signal there is.
//!
//! Every OS keeps per-NIC error and drop counters, and reading them costs nothing: no
//! traffic, no subprocess, no socket. A cable with a bad crimp, a duplex mismatch, or a
//! radio dropping frames shows up here as a rising count long before it shows up as latency,
//! and it points at *your hardware* rather than at the network — a distinction none of the
//! other probes can make.
//!
//! The pure part ([`is_physical`]) is what makes the numbers usable: macOS carries a fleet of
//! pseudo-interfaces whose counters are meaningless, and including them means warning about
//! nothing forever.

use sysinfo::Networks;

use crate::metrics::{Probe, Sample};

/// Interface-name prefixes whose error counters say nothing about the network.
///
/// `awdl`/`llw` (Apple Wireless Direct Link and its low-latency sibling) are the important
/// ones on macOS: they accumulate errors constantly by design, and counting them means the
/// dashboard warns about a healthy machine forever. The rest are loopback, tunnels and
/// virtual bridges — traffic that never touches a wire.
const PSEUDO_PREFIXES: &[&str] = &[
    "lo", "utun", "gif", "stf", "ipsec", "ppp", "awdl", "llw", "bridge", "vmnet", "docker", "veth",
    "ap",
];

/// Whether an interface's counters reflect real network hardware.
///
/// Prefix matching, deliberately: interfaces are numbered (`utun0`, `utun1`, …) and new ones
/// appear whenever a VPN connects, so an exact-name list would go stale the first time
/// someone opened a tunnel.
pub fn is_physical(name: &str) -> bool {
    !PSEUDO_PREFIXES
        .iter()
        .any(|p| name.starts_with(p) && name[p.len()..].chars().all(|c| c.is_ascii_digit()))
}

/// Reads per-interface error counters. Passive — it only asks the OS what it already knows.
pub struct InterfaceProbe {
    networks: Networks,
}

impl Default for InterfaceProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl InterfaceProbe {
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
        }
    }
}

impl Probe for InterfaceProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        // Refreshing the list (rather than just the data) so an interface that appeared
        // since the last tick — a VPN, a dock being plugged in — is seen at all.
        self.networks.refresh(true);
        let (rx_errors, tx_errors) = self
            .networks
            .iter()
            .filter(|(name, _)| is_physical(name))
            .fold((0u64, 0u64), |(r, t), (_, data)| {
                (
                    r + data.errors_on_received(),
                    t + data.errors_on_transmitted(),
                )
            });
        async move {
            vec![Sample::InterfaceErrors {
                rx_errors,
                tx_errors,
            }]
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn real_hardware_counts_and_pseudo_interfaces_do_not() {
        for name in ["en0", "en1", "eth0", "anpi0", "wlan0"] {
            assert!(is_physical(name), "{name} is a real NIC");
        }
        for name in [
            "lo0",
            "utun4",
            "awdl0",
            "llw0",
            "bridge100",
            "gif0",
            "stf0",
            "vmnet1",
            "docker0",
            "ipsec0",
            "ap1",
        ] {
            assert!(!is_physical(name), "{name} counters mean nothing");
        }
    }

    #[test]
    fn a_prefix_match_does_not_swallow_a_real_interface() {
        // "lo" is a pseudo-prefix, but "lom0" is a name in its own right — only a prefix
        // followed by digits is the numbered pseudo-interface it is meant to catch.
        assert!(is_physical("lomax"), "not a loopback");
        assert!(is_physical("apple0"), "not the Apple AP interface");
        assert!(!is_physical("ap1"), "but this one is");
    }

    #[tokio::test]
    async fn produces_one_interface_sample() {
        let mut probe = InterfaceProbe::new();
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 1);
        assert!(
            matches!(samples[0], Sample::InterfaceErrors { .. }),
            "{samples:?}"
        );
    }
}
