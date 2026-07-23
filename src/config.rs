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
    pub ui: UiConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            targets: Targets::default(),
            resolvers: default_resolvers(),
            cadence: Cadence::default(),
            thresholds: ThresholdConfig::default(),
            throughput: ThroughputConfig::default(),
            ui: UiConfig::default(),
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
    pub internet: Vec<String>,
    /// Stable target for the routing / traceroute probe.
    pub routing_target: String,
}

impl Default for Targets {
    fn default() -> Self {
        Self {
            gateway_auto: true,
            gateway: None,
            internet: vec!["1.1.1.1".to_string(), "8.8.8.8".to_string()],
            routing_target: "1.1.1.1".to_string(),
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
    pub routing_ms: u64,
    pub throughput_passive_ms: u64,
    pub throughput_probe_ms: u64,
    pub reachability_ms: u64,
    pub link_ms: u64,
    pub public_ip_ms: u64,
    pub render_ms: u64,
}

impl Default for Cadence {
    fn default() -> Self {
        Self {
            ping_ms: 1000,
            dns_ms: 5000,
            routing_ms: 60_000,
            throughput_passive_ms: 1000,
            throughput_probe_ms: 300_000,
            reachability_ms: 15_000,
            link_ms: 15_000,
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
    /// Consecutive samples required to commit a health change (debounce).
    pub debounce_samples: usize,
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
            debounce_samples: 3,
            loss_window: 60,
            history_len: 120,
        }
    }
}

/// Throughput probe settings.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct ThroughputConfig {
    pub probe_url: String,
    pub probe_bytes: u64,
    /// Warn if a capacity probe measures below this many Mbps.
    pub floor_mbps: f64,
}

impl Default for ThroughputConfig {
    fn default() -> Self {
        Self {
            probe_url: "https://speed.cloudflare.com/__down?bytes=3000000".to_string(),
            probe_bytes: 3_000_000,
            floor_mbps: 100.0,
        }
    }
}

/// UI/theme toggles.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct UiConfig {
    pub color: bool,
    pub sparkline_points: usize,
    /// Color theme name; must be one of the built-in catalog (see `Theme::NAMES` in
    /// `ui::theme` — `default`, `neon_sunset`, `dracula`, `nord`, …). Unknown names fall
    /// back to `default`. Can also be chosen live at runtime via the `t` theme picker.
    pub theme: String,
}

impl Default for UiConfig {
    fn default() -> Self {
        Self {
            color: true,
            sparkline_points: 120,
            theme: "neon_sunset".to_string(),
        }
    }
}

impl Config {
    /// Parse from a TOML string. Omitted fields fall back to their defaults.
    pub fn from_toml_str(s: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(s)
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
        assert_eq!(c.resolvers.len(), 3, "system + cloudflare + google");
        assert!(c.cadence.ping_ms > 0);
        assert!(c.cadence.render_ms > 0);
        assert_eq!(
            c.thresholds.latency_internet.direction,
            Direction::HigherIsWorse
        );
        assert_eq!(c.thresholds.rssi.direction, Direction::LowerIsWorse);
        assert!(c.thresholds.debounce_samples >= 1);
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
