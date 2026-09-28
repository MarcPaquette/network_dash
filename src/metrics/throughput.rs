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

/// Interface name prefixes whose byte counters are not the link's own traffic: loopback,
/// tunnels, the Wi-Fi radio's secondary personalities, bridges and VM/container plumbing.
///
/// Excluded because their bytes are either never on the wire at all (`lo`) or are the *same*
/// bytes the physical interface underneath already counted (`utun` while a VPN is up, `awdl`
/// and `llw` sharing the Wi-Fi radio with `en0`, `bridge` aggregating its members). Summing
/// everything double-bills them, and a VPN session then reads as twice the traffic it is.
const NOT_LINK_TRAFFIC: &[&str] = &[
    "lo", "utun", "awdl", "llw", "gif", "stf", "bridge", "anpi", "ap", "vmenet", "vnic", "veth",
    "pktap", "XHC",
];

/// Whether an interface's counters should be added to the reported rx/tx rate.
///
/// A prefix only excludes when what follows it is an interface index, so `lo0` and `ap1` are
/// dropped while a real device that merely starts with those letters is not.
pub fn counts_toward_throughput(name: &str) -> bool {
    !NOT_LINK_TRAFFIC.iter().any(|p| {
        name.strip_prefix(p)
            .is_some_and(|rest| rest.chars().all(|c| c.is_ascii_digit()))
    })
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
            .filter(|(name, _)| counts_toward_throughput(name))
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

/// Where the latest capacity reading sits against what this link has demonstrated.
///
/// Capacity is judged **relative to the link's own history**, never against an absolute Mbps
/// floor. A floor is a spec check, not a fault detector: it answers "is this link fast?",
/// which is a property of the plan someone bought, and it paints a perfectly healthy 8 Mbps
/// line critical forever while saying nothing when a gigabit line falls to 30. What is worth
/// reporting is the *collapse* — the link is carrying a fraction of what it repeatedly has.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CapacityBaseline {
    /// Median of every reading *before* the latest.
    pub typical_mbps: f64,
    pub latest_mbps: f64,
    /// The latest reading as a percentage of `typical_mbps`.
    pub pct_of_typical: f64,
    /// How many readings the baseline was drawn from.
    pub samples: usize,
}

/// Read the latest entry of `samples` against the median of the ones before it.
///
/// `None` — no opinion at all — until there are `min_samples` readings, and likewise when the
/// baseline is zero. Both are states in which any verdict would be invented: a link that has
/// not been watched long enough to have a normal cannot be said to have fallen below it.
pub fn capacity_baseline(samples: &[f64], min_samples: usize) -> Option<CapacityBaseline> {
    if samples.len() < min_samples.max(2) {
        return None;
    }
    let (prior, latest) = samples.split_at(samples.len() - 1);
    let latest_mbps = latest[0];
    let mut sorted: Vec<f64> = prior.to_vec();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    // Nearest-rank median, matching `Series::percentile` so the two never disagree by a
    // half-step on the same data.
    let typical_mbps = sorted[(sorted.len().div_ceil(2)).clamp(1, sorted.len()) - 1];
    if typical_mbps <= 0.0 {
        return None;
    }
    Some(CapacityBaseline {
        typical_mbps,
        latest_mbps,
        pct_of_typical: latest_mbps / typical_mbps * 100.0,
        samples: prior.len(),
    })
}

/// One capacity download, split at the response headers.
///
/// The split is the whole point. A download has two phases and only one of them measures the
/// link: `setup_secs` covers DNS, the TCP handshake, TLS and the server's think time — round
/// trips during which nothing is being carried — while `body_secs` is the transfer itself.
/// Charging setup to the transfer scales the answer down by however many round trips the
/// connection cost, which on a distant endpoint is most of the reading.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DownloadTiming {
    pub bytes: u64,
    pub setup_secs: f64,
    pub body_secs: f64,
}

impl DownloadTiming {
    /// The achieved rate: body bytes over body time.
    pub fn mbps(&self) -> f64 {
        mbps_from_download(self.bytes, self.body_secs)
    }
}

/// A small endpoint used to time round-trip latency (idle and under load) for bufferbloat.
const LATENCY_URL: &str = "https://speed.cloudflare.com/__down?bytes=1000";

/// Active capacity probe: times a bounded HTTP download to report the achieved Mbps, and —
/// while that download saturates the link — measures the added latency (bufferbloat).
/// Runs infrequently (its own slow cadence) so it does not flood the link.
pub struct CapacityProbe {
    client: reqwest::Client,
    /// A *separate* client — and therefore a separate connection pool — for the latency
    /// probes. Sharing one client shares one pooled connection to the endpoint, and since
    /// HTTP/2 is negotiated with it, the latency requests would multiplex onto the very
    /// connection carrying the download: same congestion window, head-of-line blocked behind
    /// download frames. That inflates the "loaded" reading and steals from the download at
    /// once, so the probe manufactures the bufferbloat it then reports. A second connection
    /// still shares the bottleneck *link* — which is what we want to measure — without
    /// sharing the transfer's own flow control.
    latency_client: reqwest::Client,
    url: String,
    latency_url: String,
}

impl CapacityProbe {
    pub fn new(url: impl Into<String>) -> Self {
        let build = || {
            reqwest::Client::builder()
                .timeout(Duration::from_secs(30))
                .user_agent("network_dash/0.1")
                .build()
                .unwrap_or_default()
        };
        Self {
            client: build(),
            latency_client: build(),
            url: url.into(),
            latency_url: LATENCY_URL.to_string(),
        }
    }

    /// Time a single small round-trip in milliseconds.
    async fn latency_once(&self) -> Option<f64> {
        let start = Instant::now();
        let resp = self
            .latency_client
            .get(&self.latency_url)
            .send()
            .await
            .ok()?;
        resp.bytes().await.ok()?;
        Some(start.elapsed().as_secs_f64() * 1000.0)
    }

    /// Download the capacity file, returning the achieved Mbps.
    async fn download(&self) -> Option<f64> {
        let start = Instant::now();
        // `send()` resolves on the response headers, so this is where setup ends and the
        // transfer begins. See [`DownloadTiming`] for why the two are not one number.
        let resp = self.client.get(&self.url).send().await.ok()?;
        let headers_at = Instant::now();
        let body = resp.bytes().await.ok()?;
        Some(
            DownloadTiming {
                bytes: body.len() as u64,
                setup_secs: (headers_at - start).as_secs_f64(),
                body_secs: headers_at.elapsed().as_secs_f64(),
            }
            .mbps(),
        )
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

    // Loopback never leaves the machine, and tunnel / AWDL / bridge counters are the *same
    // bytes* the physical interface underneath already reported. Summing every interface
    // double-bills a VPN session and charges the link for traffic that never touched it.
    #[test]
    fn loopback_and_virtual_interfaces_are_not_link_traffic() {
        for name in [
            "lo0", "utun3", "awdl0", "llw0", "bridge0", "gif0", "stf0", "anpi1", "ap1", "vmenet0",
        ] {
            assert!(!counts_toward_throughput(name), "{name} should not count");
        }
    }

    #[test]
    fn physical_interfaces_still_count() {
        for name in ["en0", "en1", "eth0", "ppp0", "pdp_ip0"] {
            assert!(counts_toward_throughput(name), "{name} should count");
        }
    }

    // Prefix matching has to stop at the digits, or `anpi1` gets excluded twice over and any
    // future `apfoo0` silently disappears with it.
    #[test]
    fn a_prefix_only_excludes_when_the_rest_is_an_index() {
        assert!(counts_toward_throughput("loopish0"));
        assert!(counts_toward_throughput("apple0"));
        assert!(!counts_toward_throughput("lo0"));
        assert!(!counts_toward_throughput("ap1"));
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
    fn a_link_is_measured_against_what_it_has_shown_it_can_do() {
        // Four readings around 400 Mbps, then 30. The fault is the collapse, and it is the
        // same collapse whether this is a gigabit line or a hotspot.
        let b = capacity_baseline(&[410.0, 395.0, 420.0, 400.0, 30.0], 5).expect("enough readings");
        assert_eq!(b.latest_mbps, 30.0);
        assert!((b.typical_mbps - 400.0).abs() < 0.01, "{b:?}");
        assert!((b.pct_of_typical - 7.5).abs() < 0.01, "{b:?}");
    }

    // The whole point of the baseline. An absolute floor called a steady 8 Mbps line
    // critical every five minutes forever; it is not broken, it is small.
    #[test]
    fn a_small_link_is_not_a_broken_one() {
        let b = capacity_baseline(&[8.0, 7.6, 8.2, 7.9, 8.1], 5).unwrap();
        assert!(b.pct_of_typical > 95.0, "{b:?}");
    }

    // Nothing to compare against yet. Forming a verdict from two readings is how a
    // dashboard alerts in its first minutes about a link it has never seen working.
    #[test]
    fn there_is_no_opinion_until_the_baseline_has_something_in_it() {
        assert_eq!(capacity_baseline(&[400.0, 30.0], 5), None);
        assert!(capacity_baseline(&[400.0, 395.0, 410.0, 400.0, 30.0], 5).is_some());
    }

    #[test]
    fn a_baseline_of_zero_yields_no_verdict() {
        // Every reading failed. A ratio against zero is not a measurement of anything.
        assert_eq!(capacity_baseline(&[0.0; 5], 5), None);
    }

    // The baseline is a median of everything *before* the latest reading, so a collapse
    // cannot quietly excuse itself by joining the average it is being judged against.
    #[test]
    fn one_slow_reading_does_not_drag_the_baseline_down_with_it() {
        let mut s = vec![400.0; 10];
        s.push(40.0);
        let b = capacity_baseline(&s, 5).unwrap();
        assert!((b.typical_mbps - 400.0).abs() < 0.01, "{b:?}");
        assert!((b.pct_of_typical - 10.0).abs() < 0.01, "{b:?}");
    }

    // Capacity is bytes over the time the *body* took. Setup — DNS, the TCP handshake, TLS,
    // and the server's think time before the first body byte — is time the link spent idle
    // waiting on round trips, and billing it to the transfer reports a fast link as a thin
    // one. Measured here: 3 MB of body in 0.45 s is ~53 Mbps, but charged the whole 3.45 s
    // it reads as 7 Mbps, which is under the default crit floor of 25.
    #[test]
    fn capacity_is_the_body_transfer_not_the_whole_round_trip() {
        let t = DownloadTiming {
            bytes: 3_000_000,
            setup_secs: 3.0,
            body_secs: 0.45,
        };
        let m = t.mbps();
        assert!((m - 53.33).abs() < 0.01, "expected ~53 Mbps, got {m}");
    }

    #[test]
    fn a_slow_handshake_does_not_make_a_fast_link_look_thin() {
        let quick = DownloadTiming {
            bytes: 3_000_000,
            setup_secs: 0.01,
            body_secs: 0.45,
        };
        let sluggish = DownloadTiming {
            setup_secs: 2.98,
            ..quick
        };
        assert_eq!(quick.mbps(), sluggish.mbps());
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
