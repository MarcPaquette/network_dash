//! Metric identities and (later) probe sample types.
//!
//! Concrete probes and the `Sample` payload are added in later phases; for now this
//! defines the stable identity used to key state, config, and incidents.

use std::collections::VecDeque;
use std::future::Future;

use serde::{Deserialize, Serialize};

pub mod dns;
pub mod iface;
pub mod link;
pub mod ping;
pub mod proc;
pub mod pubip;
pub mod reachability;
pub mod routing;
pub mod tcp;
pub mod throughput;
pub mod tls;

/// Stable identifier for each dashboard section / metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricId {
    Latency,
    Loss,
    Jitter,
    Dns,
    Routing,
    /// Capacity — how much the link can carry.
    Throughput,
    /// Latency added under load. Drawn in the throughput panel, but a distinct fault with a
    /// distinct fix, so it is logged and correlated under its own name.
    Bufferbloat,
    /// Frames the local NIC failed to send or receive — a hardware fault, not a network one.
    InterfaceErrors,
    Reachability,
    /// Time to complete a TCP handshake — reachability plus everything a real connection
    /// waits on that ICMP never sees.
    TcpHandshake,
    /// Time to negotiate TLS on top of an open connection.
    TlsHandshake,
    /// How long the presented certificate has left. Not a network fault at all — nothing is
    /// slow and nothing is down — but on a known date everything stops.
    CertExpiry,
    /// Web traffic is being intercepted and a sign-in is required.
    CaptivePortal,
    /// The WAN-side address changed — an event rather than a fault (see [`MetricId::label`]).
    PublicIp,
    Link,
    /// The dashboard reporting on itself — currently only "the incident log is unwritable".
    Log,
}

impl MetricId {
    /// Short human label used in headers and the incident log.
    pub fn label(self) -> &'static str {
        match self {
            MetricId::Latency => "latency",
            MetricId::Loss => "loss",
            MetricId::Jitter => "jitter",
            MetricId::Dns => "dns",
            MetricId::Routing => "routing",
            MetricId::Throughput => "throughput",
            MetricId::Bufferbloat => "bufferbloat",
            MetricId::InterfaceErrors => "interface errors",
            MetricId::Reachability => "reachability",
            MetricId::TcpHandshake => "tcp",
            MetricId::TlsHandshake => "tls",
            MetricId::CertExpiry => "cert expiry",
            MetricId::CaptivePortal => "captive portal",
            MetricId::PublicIp => "public ip",
            MetricId::Link => "link",
            MetricId::Log => "log",
        }
    }
}

/// A single reading produced by a probe. Variants are added as probes come online; the
/// reducer routes each to the relevant metric state.
#[derive(Debug, Clone, PartialEq)]
pub enum Sample {
    /// One ICMP echo to a ping target. `rtt_ms == None` means the probe timed out (loss).
    Latency { target: String, rtt_ms: Option<f64> },
    /// One DNS lookup, and what it did. An empty answer is not a failed one: the resolver
    /// replied, so it is up — reporting it as down is how an intercepted resolver came to be
    /// painted the same red as an unreachable one.
    Dns {
        resolver: String,
        answer: dns::Answer,
    },
    /// Whether a resolver's answers were its own — and if not, in which direction.
    DnsIntegrity {
        resolver: String,
        verdict: dns::Integrity,
    },
    /// Passive throughput reading in bytes/sec.
    Throughput { rx_bps: f64, tx_bps: f64 },
    /// Active capacity-probe result in Mbps.
    ThroughputProbe { mbps: f64 },
    /// Latency measured while idle vs while the link is saturated (bufferbloat), in ms.
    Bufferbloat { idle_ms: f64, loaded_ms: f64 },
    /// Frames the local NIC failed to receive/transmit since the previous reading.
    InterfaceErrors { rx_errors: u64, tx_errors: u64 },
    /// Time to complete a TCP handshake. `connect_ms == None` means the port never opened.
    TcpHandshake {
        endpoint: String,
        connect_ms: Option<f64>,
    },
    /// TLS negotiation time and how long the presented certificate has left. Either is
    /// `None` when the handshake did not complete — which is itself the finding.
    Tls {
        endpoint: String,
        handshake_ms: Option<f64>,
        expires_in_days: Option<i64>,
    },
    /// Reachability check for a named endpoint.
    Reachability { endpoint: String, ok: bool },
    /// Captive-portal detection result (a login page intercepting web traffic).
    CaptivePortal { detected: bool },
    /// The observed public/WAN IP address (for ISP/WAN-change detection).
    PublicIp { ip: String },
    /// Wireless link reading: RSSI/noise in dBm, negotiated Tx rate (Mbps), and current SSID.
    Link {
        rssi_dbm: Option<f64>,
        noise_dbm: Option<f64>,
        tx_rate: Option<f64>,
        ssid: Option<String>,
    },
    /// Routing/path result for a target: hop count, reachability, whether the path changed
    /// since the last probe, and per-hop detail (address, best RTT, probe loss).
    Routing {
        target: String,
        hops: usize,
        reachable: bool,
        changed: bool,
        detail: Vec<Hop>,
    },
}

/// One traceroute hop: its address (`"*"` if it never responded), the best RTT seen across
/// the probes to it, and the fraction of probes lost (0–100).
#[derive(Debug, Clone, PartialEq)]
pub struct Hop {
    pub addr: String,
    pub min_rtt_ms: Option<f64>,
    pub loss_pct: f64,
}

/// A source of [`Sample`]s. Each metric family is one probe, driven on its own cadence by
/// the scheduler. `tick` yields zero or more samples per invocation.
pub trait Probe {
    fn tick(&mut self) -> impl Future<Output = Vec<Sample>> + Send;
}

/// Test probe that replays scripted rounds of samples, then yields empty rounds forever.
pub struct FakeProbe {
    rounds: VecDeque<Vec<Sample>>,
}

impl FakeProbe {
    pub fn new(rounds: impl IntoIterator<Item = Vec<Sample>>) -> Self {
        Self {
            rounds: rounds.into_iter().collect(),
        }
    }

    pub fn remaining(&self) -> usize {
        self.rounds.len()
    }
}

impl Probe for FakeProbe {
    fn tick(&mut self) -> impl Future<Output = Vec<Sample>> + Send {
        let out = self.rounds.pop_front().unwrap_or_default();
        async move { out }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    #[test]
    fn metric_labels_are_stable() {
        assert_eq!(MetricId::Latency.label(), "latency");
        assert_eq!(MetricId::Dns.label(), "dns");
    }

    #[tokio::test]
    async fn fake_probe_replays_rounds_then_empties() {
        let mut p = FakeProbe::new(vec![
            vec![Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(1.0),
            }],
            vec![],
        ]);
        assert_eq!(p.remaining(), 2);
        assert_eq!(p.tick().await.len(), 1);
        assert_eq!(p.tick().await.len(), 0);
        assert_eq!(p.tick().await.len(), 0); // exhausted → empty forever
        assert_eq!(p.remaining(), 0);
    }
}
