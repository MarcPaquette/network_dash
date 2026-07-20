//! Metric identities and (later) probe sample types.
//!
//! Concrete probes and the `Sample` payload are added in later phases; for now this
//! defines the stable identity used to key state, config, and incidents.

use std::collections::VecDeque;
use std::future::Future;

use serde::{Deserialize, Serialize};

pub mod dns;
pub mod link;
pub mod ping;
pub mod reachability;
pub mod routing;
pub mod throughput;

/// Stable identifier for each dashboard section / metric family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MetricId {
    Latency,
    Loss,
    Jitter,
    Dns,
    Routing,
    Throughput,
    Reachability,
    Link,
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
            MetricId::Reachability => "reachability",
            MetricId::Link => "link",
        }
    }
}

/// A single reading produced by a probe. Variants are added as probes come online; the
/// reducer routes each to the relevant metric state.
#[derive(Debug, Clone, PartialEq)]
pub enum Sample {
    /// One ICMP echo to a ping target. `rtt_ms == None` means the probe timed out (loss).
    Latency { target: String, rtt_ms: Option<f64> },
    /// One DNS lookup. `latency_ms == None` means the lookup failed.
    Dns {
        resolver: String,
        latency_ms: Option<f64>,
    },
    /// Passive throughput reading in bytes/sec.
    Throughput { rx_bps: f64, tx_bps: f64 },
    /// Active capacity-probe result in Mbps.
    ThroughputProbe { mbps: f64 },
    /// Reachability check for a named endpoint.
    Reachability { endpoint: String, ok: bool },
    /// Wireless link reading: RSSI in dBm and current SSID.
    Link {
        rssi_dbm: Option<f64>,
        ssid: Option<String>,
    },
    /// Routing/path result for a target: hop count, reachability, and whether the path
    /// changed since the last probe.
    Routing {
        target: String,
        hops: usize,
        reachable: bool,
        changed: bool,
    },
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
