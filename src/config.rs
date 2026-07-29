//! Configuration: strongly-typed settings with complete built-in defaults so the app
//! runs with zero config, plus TOML load where any omitted field falls back to its
//! default (partial configs merge over defaults).

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::health::Thresholds;

/// Top-level configuration.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub targets: Targets,
    pub resolvers: Vec<Resolver>,
    pub cadence: Cadence,
    pub thresholds: ThresholdConfig,
    pub throughput: ThroughputConfig,
    pub alerts: AlertConfig,
    pub ui: UiConfig,
    /// Deprecated keys found in the loaded file, for the caller to report. Not part of the
    /// schema: it describes the file that was read, not a setting, so it neither
    /// deserializes nor round-trips back out.
    #[serde(skip)]
    pub deprecated_keys: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Targets::default(),
            resolvers: default_resolvers(),
            cadence: Cadence::default(),
            thresholds: ThresholdConfig::default(),
            throughput: ThroughputConfig::default(),
            alerts: AlertConfig::default(),
            ui: UiConfig::default(),
            deprecated_keys: Vec::new(),
        }
    }
}

/// Ping / routing targets.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Targets {
    /// Auto-detect the default gateway at startup.
    pub gateway_auto: bool,
    /// Manual gateway override (used when `gateway_auto` is false or detection fails).
    pub gateway: Option<String>,
    /// Internet hosts pinged for latency/loss (e.g. `1.1.1.1`, `8.8.8.8`).
    ///
    /// IPv6 literals belong here alongside the v4 ones: the probe drops them on a host with
    /// no v6 route rather than reporting them as loss, so listing them costs nothing on a
    /// v4-only network and shows both stacks on a dual-stack one.
    pub internet: Vec<String>,
    /// Stable target for the routing / traceroute probe.
    pub routing_target: String,
    /// Maximum TTL the path probe walks before giving up. Raising it lengthens every
    /// traceroute; the default reaches any reasonable destination.
    pub max_hops: usize,
}

impl Default for Targets {
    fn default() -> Self {
        Self {
            gateway_auto: true,
            gateway: None,
            internet: vec![
                "1.1.1.1".to_string(),
                "8.8.8.8".to_string(),
                // The v6 side of the same two operators, so a difference between the stacks
                // is a difference in the path and not in who is at the far end of it.
                "2606:4700:4700::1111".to_string(),
                "2001:4860:4860::8888".to_string(),
            ],
            routing_target: "1.1.1.1".to_string(),
            max_hops: 15,
        }
    }
}

/// A DNS resolver to benchmark.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Resolver {
    /// Display name, e.g. `system`, `cloudflare`, `google`.
    pub name: String,
    /// Resolver IP; `None` uses the OS-configured resolver.
    pub addr: Option<String>,
}

fn default_resolvers() -> Vec<Resolver> {
    vec![
        Resolver {
            name: "system".into(),
            addr: None,
        },
        Resolver {
            name: "cloudflare".into(),
            addr: Some("1.1.1.1".into()),
        },
        Resolver {
            name: "google".into(),
            addr: Some("8.8.8.8".into()),
        },
    ]
}

/// Probe cadences, in milliseconds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Cadence {
    pub ping_ms: u64,
    pub dns_ms: u64,
    /// DNS honesty checks. Minutes apart on purpose: hijacking is a configuration, not a
    /// weather condition — it does not start and stop between one lookup and the next.
    pub dns_integrity_ms: u64,
    pub routing_ms: u64,
    pub throughput_passive_ms: u64,
    pub throughput_probe_ms: u64,
    pub reachability_ms: u64,
    pub link_ms: u64,
    /// TCP handshake timing. Slower than ping: it opens a real connection on a remote host,
    /// and there is no reason to do that every second.
    pub tcp_ms: u64,
    /// NIC error counters. Cheap enough to poll often — it is a counter read, not a probe —
    /// but errors are counted per interval, so a short one makes every burst look small.
    pub interface_ms: u64,
    pub public_ip_ms: u64,
    pub render_ms: u64,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            ping_ms: 1000,
            dns_ms: 5000,
            dns_integrity_ms: 120_000,
            routing_ms: 60_000,
            throughput_passive_ms: 1000,
            throughput_probe_ms: 300_000,
            reachability_ms: 15_000,
            link_ms: 15_000,
            tcp_ms: 20_000,
            interface_ms: 10_000,
            public_ip_ms: 300_000,
            render_ms: 200,
        }
    }
}

impl Cadence {
    pub fn ping(&self) -> Duration {
        Duration::from_millis(self.ping_ms)
    }
    pub fn render(&self) -> Duration {
        Duration::from_millis(self.render_ms)
    }
}

/// Warn/crit thresholds and window sizes.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThresholdConfig {
    pub latency_internet: Thresholds,
    pub latency_gateway: Thresholds,
    pub jitter: Thresholds,
    pub loss: Thresholds,
    pub dns: Thresholds,
    pub rssi: Thresholds,
    /// Wi-Fi signal-to-noise ratio in dB (higher is better).
    pub snr: Thresholds,
    /// Added latency under load (bufferbloat) in ms (higher is worse).
    pub bufferbloat: Thresholds,
    /// Measured link capacity in Mbps (lower is worse).
    pub throughput: Thresholds,
    /// TCP handshake time in ms (higher is worse). Looser than the ping thresholds on
    /// purpose: a handshake is a full round trip plus the far end's accept queue, so it is
    /// legitimately slower than ICMP to the same host and would cry wolf at ping's limits.
    pub tcp_handshake: Thresholds,
    /// NIC errors seen in one probe interval (higher is worse). A healthy interface reports
    /// exactly zero, so the warn level sits at 1 — anything at all is worth knowing about.
    pub interface_errors: Thresholds,
    /// How long a degradation must persist before it is reported, in seconds.
    pub trip_after_secs: f64,
    /// How long a recovery must hold before it is reported, in seconds. Longer than
    /// `trip_after_secs` on purpose — see [`crate::health::Debouncer`].
    pub clear_after_secs: f64,
    /// **Deprecated** — superseded by `trip_after_secs`/`clear_after_secs`. Still accepted
    /// so existing configs keep working, but it cannot be converted: a sample count means
    /// a different duration on every probe (3 samples is 3s of ping and 45s of Wi-Fi
    /// polling), so there is no honest number to migrate it to. Dropped on load.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub debounce_samples: Option<usize>,
    /// Number of ping outcomes retained for the loss window.
    pub loss_window: usize,
    /// Number of points retained per history series (chart width).
    pub history_len: usize,
}

impl Default for ThresholdConfig {
    fn default() -> Self {
        Self {
            latency_internet: Thresholds::higher_is_worse(80.0, 150.0),
            latency_gateway: Thresholds::higher_is_worse(15.0, 50.0),
            jitter: Thresholds::higher_is_worse(15.0, 40.0),
            loss: Thresholds::higher_is_worse(1.0, 5.0),
            dns: Thresholds::higher_is_worse(100.0, 300.0),
            rssi: Thresholds::lower_is_worse(-70.0, -80.0),
            snr: Thresholds::lower_is_worse(20.0, 10.0),
            bufferbloat: Thresholds::higher_is_worse(100.0, 300.0),
            throughput: Thresholds::lower_is_worse(100.0, 25.0),
            tcp_handshake: Thresholds::higher_is_worse(250.0, 1000.0),
            interface_errors: Thresholds::higher_is_worse(1.0, 10.0),
            trip_after_secs: 3.0,
            clear_after_secs: 15.0,
            debounce_samples: None,
            loss_window: 60,
            history_len: 120,
        }
    }
}

impl ThresholdConfig {
    /// Dwell before a degradation is committed.
    pub fn trip_after(&self) -> chrono::Duration {
        secs_to_duration(self.trip_after_secs)
    }

    /// Dwell before a recovery is committed.
    pub fn clear_after(&self) -> chrono::Duration {
        secs_to_duration(self.clear_after_secs)
    }
}

/// Seconds → `chrono::Duration` at millisecond resolution. Negative values clamp to zero:
/// a "negative dwell" is a typo, and treating it as "commit immediately" is the reading
/// that cannot surprise anyone.
fn secs_to_duration(secs: f64) -> chrono::Duration {
    chrono::Duration::milliseconds((secs.max(0.0) * 1000.0) as i64)
}

/// Noise controls for the event feed and the incident log.
///
/// These sit downstream of the debounce: debouncing decides whether a change is *real*,
/// these decide whether reporting it again tells the reader anything new.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct AlertConfig {
    /// Committed transitions within `flap_window_secs` before a metric is called unstable
    /// and its individual swings are collapsed into one "flapping" incident. Below 2 the
    /// detector is disabled — every transition would qualify and nothing would be reported.
    pub flap_count: usize,
    /// The window flap transitions are counted over, in seconds.
    pub flap_window_secs: f64,
    /// Drop an incident identical to one already reported (same metric, target and
    /// severity) within this many seconds. A short-range backstop for anything that raises
    /// alerts on edges rather than on debounced state.
    ///
    /// Kept below `trip_after_secs + clear_after_secs` on purpose: a debounced metric cannot
    /// break, recover and break again faster than that, so the cooldown can only ever
    /// swallow a true duplicate — never a second, genuine failure.
    pub dedup_secs: f64,
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            flap_count: 4,
            flap_window_secs: 120.0,
            dedup_secs: 10.0,
        }
    }
}

impl AlertConfig {
    /// Window flap transitions are counted over.
    pub fn flap_window(&self) -> chrono::Duration {
        secs_to_duration(self.flap_window_secs)
    }

    /// Cooldown before an identical alert may be reported again.
    pub fn dedup_window(&self) -> chrono::Duration {
        secs_to_duration(self.dedup_secs)
    }
}

/// Throughput probe settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThroughputConfig {
    /// Endpoint for the active capacity probe. The transfer size is part of the URL, so
    /// there is no separate byte-count knob to keep in sync with it.
    pub probe_url: String,
    /// **Deprecated** — superseded by `thresholds.throughput`, which can also express a
    /// critical bound. Still accepted so existing configs keep working: on load it seeds
    /// `thresholds.throughput` (see [`Config::migrate_deprecated`]) and is then dropped,
    /// so it never round-trips back out.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub floor_mbps: Option<f64>,
}

impl Default for ThroughputConfig {
    fn default() -> Self {
        Self {
            probe_url: "https://speed.cloudflare.com/__down?bytes=3000000".to_string(),
            floor_mbps: None,
        }
    }
}

/// UI/theme toggles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub color: bool,
    /// Color theme name; must be one of the built-in catalog (see `Theme::NAMES` in
    /// `ui::theme` — `default`, `neon_sunset`, `dracula`, `nord`, …). Unknown names fall
    /// back to `default`. Can also be chosen live at runtime via the `t` theme picker.
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            color: true,
            theme: "neon_sunset".to_string(),
        }
    }
}

impl Config {
    /// Parse from a TOML string. Omitted fields fall back to their defaults, and
    /// deprecated keys are folded into their replacements.
    pub fn from_toml_str(s: &str) -> Result<Config, toml::de::Error> {
        let mut c: Config = toml::from_str(s)?;
        c.migrate_deprecated();
        Ok(c)
    }

    /// Fold deprecated keys into the fields that replaced them, then clear them so they
    /// do not round-trip back out.
    ///
    /// `throughput.floor_mbps` only ever expressed a *warn* bound, so it seeds `warn` and
    /// drags `crit` underneath it — leaving the stock 25 Mbps crit in place would classify
    /// every merely-slow reading under a low floor as critical. An explicitly configured
    /// `thresholds.throughput` always wins.
    ///
    /// `thresholds.debounce_samples` is dropped rather than converted, and recorded in
    /// [`Config::deprecated_keys`] so the caller can say so: silently ignoring a knob
    /// someone set is how you get a bug report about debouncing that nobody can reproduce.
    fn migrate_deprecated(&mut self) {
        let stock = ThresholdConfig::default().throughput;
        if let Some(floor) = self.throughput.floor_mbps.take() {
            self.deprecated_keys
                .push("throughput.floor_mbps (migrated into thresholds.throughput)".to_string());
            if self.thresholds.throughput == stock {
                self.thresholds.throughput =
                    Thresholds::lower_is_worse(floor, stock.crit.min(floor / 4.0));
            }
        }
        if self.thresholds.debounce_samples.take().is_some() {
            self.deprecated_keys.push(
                "thresholds.debounce_samples (ignored — use trip_after_secs / clear_after_secs)"
                    .to_string(),
            );
        }
    }

    /// Serialize to a TOML string.
    pub fn to_toml_string(&self) -> Result<String, toml::ser::Error> {
        toml::to_string_pretty(self)
    }

    /// Load config from `path` if it exists, otherwise return defaults. Parse errors are
    /// surfaced (a malformed config should not be silently ignored).
    pub fn load_or_default(path: &Path) -> Result<Config, ConfigError> {
        match std::fs::read_to_string(path) {
            Ok(s) => Self::from_toml_str(&s).map_err(ConfigError::Parse),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Config::default()),
            Err(e) => Err(ConfigError::Io(e)),
        }
    }

    /// One human-readable line per retired key found in `path`, ready for stderr.
    ///
    /// Reported rather than migrated-in-silence: a setting that stopped doing what its name
    /// says is worse than one that is gone, and the only person who can fix the file is the
    /// one who wrote it. Returns strings instead of printing so it stays testable and the
    /// caller decides where they land.
    pub fn deprecation_warnings(&self, path: &Path) -> Vec<String> {
        self.deprecated_keys
            .iter()
            .map(|k| format!("warning: {} in {}", k, path.display()))
            .collect()
    }

    /// Default on-disk config path (`<config_dir>/network_dash/config.toml`).
    pub fn default_path() -> Option<PathBuf> {
        directories::ProjectDirs::from("", "", "network_dash")
            .map(|d| d.config_dir().join("config.toml"))
    }
}

/// Error loading configuration.
#[derive(Debug)]
pub enum ConfigError {
    Io(std::io::Error),
    Parse(toml::de::Error),
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::Io(e) => write!(f, "reading config: {e}"),
            ConfigError::Parse(e) => write!(f, "parsing config: {e}"),
        }
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::Direction;
    use pretty_assertions::assert_eq;

    #[test]
    fn defaults_are_complete_and_sane() {
        let c = Config::default();
        assert!(
            c.targets.gateway_auto,
            "gateway should auto-detect by default"
        );
        assert!(
            !c.targets.internet.is_empty(),
            "need default internet targets"
        );
        assert!(!c.targets.routing_target.is_empty());
        assert!(c.targets.max_hops > 0, "a 0-hop traceroute probes nothing");
        assert_eq!(c.resolvers.len(), 3, "system + cloudflare + google");
        assert!(c.cadence.ping_ms > 0);
        assert!(c.cadence.render_ms > 0);
        assert_eq!(
            c.thresholds.latency_internet.direction,
            Direction::HigherIsWorse
        );
        assert_eq!(c.thresholds.rssi.direction, Direction::LowerIsWorse);
        assert!(c.thresholds.trip_after_secs > 0.0);
        assert!(
            c.thresholds.clear_after_secs > c.thresholds.trip_after_secs,
            "recovery must be slower to commit than a fault, or a flap reads as a fix"
        );
        assert_eq!(
            c.thresholds.debounce_samples, None,
            "the retired knob must not come back as a default"
        );
        assert!(c.thresholds.loss_window > 0);
        assert!(c.thresholds.history_len > 0);
        assert!(!c.throughput.probe_url.is_empty());
        assert!(c.ui.color);
        assert_eq!(
            c.ui.theme, "neon_sunset",
            "neon sunset theme out of the box"
        );
    }

    #[test]
    fn ui_theme_parses_from_toml() {
        let c = Config::from_toml_str("[ui]\ntheme = \"moss_goblin\"\n").unwrap();
        assert_eq!(c.ui.theme, "moss_goblin");
        // Sibling ui fields keep their defaults.
        assert_eq!(c.ui.color, Config::default().ui.color);
    }

    #[test]
    fn throughput_thresholds_default_to_lower_is_worse() {
        let t = Config::default().thresholds.throughput;
        assert_eq!(t.direction, Direction::LowerIsWorse);
        assert!(
            t.crit < t.warn,
            "crit must be the deeper degradation: {t:?}"
        );
    }

    #[test]
    fn deprecated_floor_mbps_seeds_the_throughput_warn_threshold() {
        let c = Config::from_toml_str("[throughput]\nfloor_mbps = 20.0\n").unwrap();
        assert_eq!(c.thresholds.throughput.warn, 20.0);
        // ...and crit must stay strictly below it, or `evaluate` would classify every
        // merely-warning value as critical.
        assert!(
            c.thresholds.throughput.crit < 20.0,
            "crit should scale under the migrated floor: {:?}",
            c.thresholds.throughput
        );
    }

    #[test]
    fn explicit_throughput_thresholds_beat_the_deprecated_floor() {
        let c = Config::from_toml_str(
            "[throughput]\nfloor_mbps = 20.0\n\n\
             [thresholds.throughput]\nwarn = 500.0\ncrit = 100.0\ndirection = \"lower_is_worse\"\n",
        )
        .unwrap();
        assert_eq!(c.thresholds.throughput.warn, 500.0);
        assert_eq!(c.thresholds.throughput.crit, 100.0);
    }

    #[test]
    fn alert_defaults_collapse_noise_without_silencing_the_feed() {
        let a = Config::default().alerts;
        assert!(
            a.flap_count >= 2,
            "under 2 would call every single transition a flap and mute everything"
        );
        assert!(a.flap_window_secs > 0.0);
        assert!(
            a.dedup_secs > 0.0 && a.dedup_secs < a.flap_window_secs,
            "dedup is the short-range backstop, flap detection the long one: {a:?}"
        );
        let t = Config::default().thresholds;
        assert!(
            a.dedup_secs < t.trip_after_secs + t.clear_after_secs,
            "a debounced metric can't round-trip faster than trip+clear, so a longer \
             cooldown than that would swallow a genuine second failure: {a:?}"
        );
        assert_eq!(
            a.flap_window(),
            chrono::Duration::seconds(a.flap_window_secs as i64)
        );
        assert_eq!(
            a.dedup_window(),
            chrono::Duration::seconds(a.dedup_secs as i64)
        );
    }

    #[test]
    fn alerts_are_configurable_and_partial() {
        let c = Config::from_toml_str("[alerts]\nflap_count = 9\n").unwrap();
        assert_eq!(c.alerts.flap_count, 9);
        assert_eq!(
            c.alerts.flap_window_secs,
            Config::default().alerts.flap_window_secs,
            "omitted siblings keep their defaults"
        );
    }

    #[test]
    fn dwell_helpers_convert_seconds_to_durations() {
        let c = Config::default();
        assert_eq!(c.thresholds.trip_after(), chrono::Duration::seconds(3));
        assert_eq!(c.thresholds.clear_after(), chrono::Duration::seconds(15));
        // Sub-second dwells are expressible; a negative one is a typo, not a time machine.
        let t = ThresholdConfig {
            trip_after_secs: 0.25,
            clear_after_secs: -5.0,
            ..ThresholdConfig::default()
        };
        assert_eq!(t.trip_after(), chrono::Duration::milliseconds(250));
        assert_eq!(t.clear_after(), chrono::Duration::zero());
    }

    #[test]
    fn deprecated_debounce_samples_is_dropped_and_reported() {
        let c = Config::from_toml_str("[thresholds]\ndebounce_samples = 5\n")
            .expect("a retired knob must not reject the whole config");
        assert_eq!(c.thresholds.debounce_samples, None, "must not round-trip");
        assert_eq!(
            c.thresholds.trip_after_secs,
            Config::default().thresholds.trip_after_secs,
            "there is no honest conversion from a sample count, so defaults stand"
        );
        assert!(
            c.deprecated_keys
                .iter()
                .any(|k| k.contains("debounce_samples")),
            "an ignored setting must be reported, not swallowed: {:?}",
            c.deprecated_keys
        );
        assert!(
            !c.to_toml_string().unwrap().contains("debounce_samples"),
            "the retired key must not be written back out"
        );
    }

    #[test]
    fn deprecation_warnings_name_the_file_and_every_key() {
        let c = Config::from_toml_str(
            "[thresholds]\ndebounce_samples = 5\n\n[throughput]\nfloor_mbps = 40.0\n",
        )
        .unwrap();
        let w = c.deprecation_warnings(Path::new("/etc/np.toml"));
        assert_eq!(w.len(), 2, "one line per retired key: {w:?}");
        for line in &w {
            assert!(line.starts_with("warning: "), "{line}");
            assert!(
                line.contains("/etc/np.toml"),
                "say which file to edit: {line}"
            );
        }
        assert!(w.iter().any(|l| l.contains("debounce_samples")), "{w:?}");
        assert!(w.iter().any(|l| l.contains("floor_mbps")), "{w:?}");
    }

    #[test]
    fn a_config_with_nothing_retired_warns_about_nothing() {
        let c = Config::from_toml_str("[thresholds]\nloss_window = 30\n").unwrap();
        assert!(c.deprecation_warnings(Path::new("/etc/np.toml")).is_empty());
    }

    #[test]
    fn removed_keys_do_not_break_an_existing_config() {
        // `probe_bytes` and `sparkline_points` were never read and have been dropped from
        // the schema. Someone's config file on disk still has them, and must still load.
        let c = Config::from_toml_str(
            "[throughput]\nprobe_bytes = 3000000\n\n[ui]\nsparkline_points = 120\ntheme = \"nord\"\n",
        )
        .expect("retired keys must be ignored, not rejected");
        assert_eq!(c.ui.theme, "nord");
    }

    #[test]
    fn empty_toml_parses_to_defaults() {
        assert_eq!(Config::from_toml_str("").unwrap(), Config::default());
    }

    #[test]
    fn partial_config_merges_over_defaults() {
        let c = Config::from_toml_str("[cadence]\nping_ms = 500\n").unwrap();
        // The overridden field takes effect...
        assert_eq!(c.cadence.ping_ms, 500);
        // ...while sibling fields and untouched sections keep their defaults.
        assert_eq!(c.cadence.dns_ms, Config::default().cadence.dns_ms);
        assert_eq!(c.resolvers, Config::default().resolvers);
        assert_eq!(c.targets, Config::default().targets);
    }

    #[test]
    fn default_round_trips_through_toml() {
        let c = Config::default();
        let s = c.to_toml_string().unwrap();
        assert_eq!(Config::from_toml_str(&s).unwrap(), c);
    }

    #[test]
    fn malformed_toml_is_an_error() {
        assert!(Config::from_toml_str("this is = = not valid").is_err());
    }

    #[test]
    fn cadence_duration_helpers() {
        let c = Cadence {
            ping_ms: 1000,
            render_ms: 200,
            ..Cadence::default()
        };
        assert_eq!(c.ping(), Duration::from_millis(1000));
        assert_eq!(c.render(), Duration::from_millis(200));
    }
}
