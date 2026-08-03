//! Throughput probes. The passive [`ThroughputProbe`] reads per-interface byte counters via
//! `sysinfo` and reports send/receive rates (no test traffic). The active [`CapacityProbe`]
//! times a bounded download to estimate link capacity in Mbps — it runs on a slow cadence so
//! it stays lightweight.

use std::time::{Duration, Instant};

use sysinfo::Networks;

use crate::metrics::{Probe, Sample};

/// Bytes observed over the time they were observed in.
///
/// A non-positive interval reports 0 rather than infinity: two refreshes landing in the same
/// instant mean the rate is *unknown*, and a spike to infinity would poison the rolling
/// series it lands in for as long as the window is deep.
pub fn rate_bps(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        bytes as f64 / secs
    }
}

/// Reports aggregate rx/tx byte rates from OS interface counters.
pub struct ThroughputProbe {
    networks: Networks,
    /// When the counters were last read. The divisor has to be the interval actually
    /// measured, not the configured cadence: a tick delayed by a busy runtime, a laptop
    /// sleeping, or the gap between construction and the first tick would otherwise be
    /// reported as a proportionally inflated rate.
    last_read: Instant,
}

impl Default for ThroughputProbe {
    fn default() -> Self {
        Self::new()
    }
}

impl ThroughputProbe {
    pub fn new() -> Self {
        Self {
            networks: Networks::new_with_refreshed_list(),
            last_read: Instant::now(),
        }
    }
}

impl Probe for ThroughputProbe {
    fn tick(&mut self) -> impl std::future::Future<Output = Vec<Sample>> + Send {
        // `received`/`transmitted` report bytes since the previous refresh.
        self.networks.refresh(false);
        let elapsed = self.last_read.elapsed().as_secs_f64();
        self.last_read = Instant::now();
        let (rx, tx) = self
            .networks
            .iter()
            .fold((0u64, 0u64), |(r, t), (_name, data)| {
                (r + data.received(), t + data.transmitted())
            });
        let rx_bps = rate_bps(rx, elapsed);
        let tx_bps = rate_bps(tx, elapsed);
        async move { vec![Sample::Throughput { rx_bps, tx_bps }] }
    }
}

/// Convert a completed download into a Mbps estimate. Guards against a zero/negative
/// elapsed time (returns 0.0) so a same-instant read can't divide by zero.
pub fn mbps_from_download(bytes: u64, secs: f64) -> f64 {
    if secs <= 0.0 {
        0.0
    } else {
        (bytes as f64 * 8.0) / secs / 1_000_000.0
    }
}

/// A small endpoint used to time round-trip latency (idle and under load) for bufferbloat.
const LATENCY_URL: &str = "https://speed.cloudflare.com/__down?bytes=1000";

/// Active capacity probe: times a bounded HTTP download to report the achieved Mbps, and —
/// while that download saturates the link — measures the added latency (bufferbloat).
/// Runs infrequently (its own slow cadence) so it does not flood the link.
pub struct CapacityProbe {
    client: reqwest::Client,
    url: String,
    latency_url: String,
}

impl CapacityProbe {
    pub fn new(url: impl Into<String>) -> Self {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(30))
            .user_agent("network_dash/0.1")
            .build()
            .unwrap_or_default();
        Self {
            client,
            url: url.into(),
            latency_url: LATENCY_URL.to_string(),
        }
    }

    /// Time a single small round-trip in milliseconds.
    async fn latency_once(&self) -> Option<f64> {
        let start = Instant::now();
        let resp = self.client.get(&self.latency_url).send().await.ok()?;
        resp.bytes().await.ok()?;
        Some(start.elapsed().as_secs_f64() * 1000.0)
    }

    /// Download the capacity file, returning the achieved Mbps.
    async fn download(&self) -> Option<f64> {
        let start = Instant::now();
        let resp = self.client.get(&self.url).send().await.ok()?;
        let body = resp.bytes().await.ok()?;
        Some(mbps_from_download(
            body.len() as u64,
            start.elapsed().as_secs_f64(),
        ))
    }
}

impl Probe for CapacityProbe {
    async fn tick(&mut self) -> Vec<Sample> {
        // Idle baseline: best (lowest) of two quick round-trips before loading the link.
        let mut idle: Option<f64> = None;
        for _ in 0..2 {
            if let Some(ms) = self.latency_once().await {
                idle = Some(idle.map_or(ms, |cur: f64| cur.min(ms)));
            }
        }

        // Saturate the link with the big download while sampling latency concurrently; keep
        // the worst (highest) loaded round-trip seen during the transfer.
        let download = self.download();
        let loaded = async {
            let mut worst: Option<f64> = None;
            for _ in 0..3 {
                if let Some(ms) = self.latency_once().await {
                    worst = Some(worst.map_or(ms, |cur: f64| cur.max(ms)));
                }
            }
            worst
        };
        let (mbps, loaded_ms) = tokio::join!(download, loaded);

        let mut out = Vec::new();
        if let Some(mbps) = mbps {
            out.push(Sample::ThroughputProbe { mbps });
        }
        if let (Some(idle_ms), Some(loaded_ms)) = (idle, loaded_ms) {
            out.push(Sample::Bufferbloat { idle_ms, loaded_ms });
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn produces_one_throughput_sample() {
        let mut probe = ThroughputProbe::new();
        let samples = probe.tick().await;
        assert_eq!(samples.len(), 1);
        assert!(matches!(samples[0], Sample::Throughput { .. }));
    }

    #[test]
    fn a_rate_is_bytes_over_the_time_they_actually_took() {
        // 100 kB in half a second is 200 kB/s, whatever cadence was configured.
        assert_eq!(rate_bps(100_000, 0.5), 200_000.0);
    }

    #[test]
    fn a_zero_interval_reports_no_traffic_rather_than_infinity() {
        // Two refreshes in the same instant: unknowable, not infinite.
        assert_eq!(rate_bps(100_000, 0.0), 0.0);
        assert_eq!(rate_bps(100_000, -1.0), 0.0);
    }

    #[tokio::test]
    async fn a_slow_tick_is_not_reported_as_a_fast_one() {
        // The probe is built, then ticked much later than any configured cadence. Dividing
        // by the cadence instead of the elapsed time would inflate the rate by that ratio.
        let mut probe = ThroughputProbe::new();
        tokio::time::sleep(Duration::from_millis(30)).await;
        let first = probe.tick().await;
        assert_eq!(first.len(), 1);
        // Nothing to assert about the value on a live machine — but the elapsed clock must
        // have advanced, so a second immediate tick divides by a tiny interval, not by a
        // fixed one. Both must stay finite.
        let second = probe.tick().await;
        for s in first.iter().chain(second.iter()) {
            let Sample::Throughput { rx_bps, tx_bps } = s else {
                panic!("expected a throughput sample: {s:?}");
            };
            assert!(rx_bps.is_finite() && tx_bps.is_finite(), "{s:?}");
        }
    }

    #[test]
    fn mbps_math_is_bits_over_time() {
        // 3 MB in 0.24 s = 24 Mbit / 0.24 s = 100 Mbps.
        let m = mbps_from_download(3_000_000, 0.24);
        assert!((m - 100.0).abs() < 0.001, "expected ~100 Mbps, got {m}");
    }

    #[test]
    fn zero_elapsed_is_not_a_divide_by_zero() {
        assert_eq!(mbps_from_download(1_000_000, 0.0), 0.0);
    }

    #[tokio::test]
    #[ignore = "requires network"]
    async fn capacity_probe_downloads_and_measures() {
        let mut probe = CapacityProbe::new("https://speed.cloudflare.com/__down?bytes=3000000");
        // tick() emits a ThroughputProbe and (when latency sampling succeeds) a Bufferbloat.
        let samples = probe.tick().await;
        let mbps = samples.iter().find_map(|s| match s {
            Sample::ThroughputProbe { mbps } => Some(*mbps),
            _ => None,
        });
        assert!(
            mbps.is_some_and(|m| m > 0.0),
            "should measure > 0 Mbps: {samples:?}"
        );
    }
}
