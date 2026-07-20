//! Passive throughput probe: reads per-interface byte counters via `sysinfo` and reports
//! send/receive rates. Generates no test traffic (the active capacity probe is separate).

use std::time::Duration;

use sysinfo::Networks;

use crate::metrics::{Probe, Sample};

/// Reports aggregate rx/tx byte rates from OS interface counters.
pub struct ThroughputProbe {
    networks: Networks,
    interval_secs: f64,
}

impl ThroughputProbe {
    pub fn new(interval: Duration) -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            interval_secs: interval.as_secs_f64().max(0.001),
        }
    }
}

impl Probe for ThroughputProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        // `received`/`transmitted` report bytes since the previous refresh.
        self.networks.refresh(false);
        let (rx, tx) = self
            .networks
            .iter()
            .fold((0u64, 0u64), |(r, t), (_name, data)| {
                (r + data.received(), t + data.transmitted())
            });
        let rx_bps = rx as f64 / self.interval_secs;
        let tx_bps = tx as f64 / self.interval_secs;
        async move { vec![Sample::Throughput { rx_bps, tx_bps }] }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn produces_one_throughput_sample() {
        let mut probe = ThroughputProbe::new(Duration::from_millis(1000));
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Throughput { .. }));
    }
}
