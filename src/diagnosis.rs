//! Root-cause correlation: turn the per-metric health streams into a localized,
//! plain-language verdict — the "what is wrong with my network (and where)" answer.
//!
//! Everything here is pure: [`diagnose`] reads an [`AppState`] snapshot, projects it into a
//! small [`Signals`] struct, and runs an ordered ruleset over it. The projection
//! ([`Signals::from_state`]) is the only part that touches app state; the ruleset
//! ([`diagnose_signals`]) is a pure function of `Signals`, so each rule is unit-tested by
//! constructing `Signals` directly rather than driving the whole reducer.

use crate::app::AppState;
use crate::health::Health;

/// The network segment a fault localizes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Layer {
    /// Local wireless radio (weak signal / bad SNR).
    Wifi,
    /// The LAN path to the default gateway / router.
    Gateway,
    /// Everything beyond the gateway — the ISP / WAN.
    Isp,
    /// Name resolution.
    Dns,
    /// A specific remote host, while the rest of the connection is healthy.
    Remote,
}

impl Layer {
    /// Short tag shown in the diagnosis panel.
    pub fn tag(self) -> &'static str {
        match self {
            Layer::Wifi => "WI-FI",
            Layer::Gateway => "GATEWAY",
            Layer::Isp => "ISP/WAN",
            Layer::Dns => "DNS",
            Layer::Remote => "REMOTE",
        }
    }
}

/// A single localized verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnosis {
    /// The layer the fault localizes to; `None` for the all-healthy verdict.
    pub layer: Option<Layer>,
    pub severity: Health,
    /// One-line, plain-language description of the problem.
    pub headline: String,
    /// Short supporting facts (shown under the headline).
    pub evidence: Vec<String>,
}

/// A pure snapshot of the signals the ruleset reasons over, projected from [`AppState`].
#[derive(Debug, Clone, PartialEq)]
struct Signals {
    /// Worst health across gateway ping targets (`None` if no gateway is registered).
    gateway: Option<Health>,
    /// Worst health across internet (non-gateway) ping targets.
    internet: Health,
    /// Total / unhealthy internet target counts (to tell "one host" from "the whole ISP").
    internet_total: usize,
    internet_bad: usize,
    /// Name of the worst internet host, if any is unhealthy.
    worst_internet_host: Option<String>,
    /// Health of the OS-configured ("system") resolver, if present.
    dns_system: Option<Health>,
    /// Worst health across the public resolvers (everything but "system").
    dns_public: Health,
    /// Any reachability endpoint currently OK / all of them failing.
    reach_any_ok: bool,
    reach_all_fail: bool,
    /// Routing probe: whether it has run, and whether the target is reachable.
    routing_seen: bool,
    routing_reachable: bool,
    /// Wi-Fi signal health (from RSSI) vs link-quality health (from SNR), kept apart so a
    /// weak signal and interference get different plain-language explanations.
    wifi_signal: Health,
    wifi_quality: Health,
    rssi_dbm: Option<f64>,
    snr_db: Option<f64>,
    tx_rate: Option<f64>,
    /// A captive portal is intercepting web traffic (sign-in required).
    captive: bool,
    /// Bufferbloat: health and the added latency (ms) measured under load.
    bufferbloat: Health,
    bufferbloat_ms: Option<f64>,
}

impl Default for Signals {
    /// A fully-healthy baseline; tests tweak individual fields off this.
    fn default() -> Self {
        Self {
            gateway: Some(Health::Ok),
            internet: Health::Ok,
            internet_total: 2,
            internet_bad: 0,
            worst_internet_host: None,
            dns_system: Some(Health::Ok),
            dns_public: Health::Ok,
            reach_any_ok: true,
            reach_all_fail: false,
            routing_seen: true,
            routing_reachable: true,
            wifi_signal: Health::Ok,
            wifi_quality: Health::Ok,
            rssi_dbm: Some(-55.0),
            snr_db: Some(45.0),
            tx_rate: Some(866.0),
            captive: false,
            bufferbloat: Health::Ok,
            bufferbloat_ms: None,
        }
    }
}

impl Signals {
    /// Project the current [`AppState`] into a diagnosis snapshot.
    fn from_state(state: &AppState) -> Self {
        // Gateway: worst of latency/loss across any gateway-flagged targets.
        let mut gateway: Option<Health> = None;
        for t in state.targets.values().filter(|t| t.is_gateway) {
            let h = t.latency_health_current().worst(t.loss_health_current());
            gateway = Some(gateway.map_or(h, |cur| cur.worst(h)));
        }

        // Internet: worst over non-gateway targets, plus how many are unhealthy.
        let mut internet = Health::Ok;
        let mut internet_total = 0;
        let mut internet_bad = 0;
        let mut worst_internet_host = None;
        let mut worst_h = Health::Ok;
        for (name, t) in state.targets.iter().filter(|(_, t)| !t.is_gateway) {
            internet_total += 1;
            let h = t.latency_health_current().worst(t.loss_health_current());
            internet = internet.worst(h);
            if h > Health::Ok {
                internet_bad += 1;
                if h >= worst_h {
                    worst_h = h;
                    worst_internet_host = Some(name.clone());
                }
            }
        }

        // DNS: split the OS-configured "system" resolver from the public ones.
        let dns_system = state.resolvers.get("system").map(|r| r.health_current());
        let dns_public = Health::worst_of(
            state
                .resolvers
                .iter()
                .filter(|(name, _)| name.as_str() != "system")
                .map(|(_, r)| r.health_current()),
        );

        // Reachability endpoints.
        let mut reach_any_ok = false;
        let mut reach_seen = false;
        let mut reach_all_fail = true;
        for r in state.reachability.values() {
            reach_seen = true;
            if r.ok {
                reach_any_ok = true;
                reach_all_fail = false;
            }
        }
        if !reach_seen {
            reach_all_fail = false;
        }

        // Wi-Fi: classify RSSI (signal) and SNR (quality) against their thresholds — a live,
        // un-debounced read. SNR = signal − noise, only when both are known.
        let rssi_dbm = state.link.rssi_dbm;
        let wifi_signal = rssi_dbm.map_or(Health::Ok, |v| state.config.thresholds.rssi.evaluate(v));
        let snr_db = match (rssi_dbm, state.link.noise_dbm) {
            (Some(r), Some(n)) => Some(r - n),
            _ => None,
        };
        let wifi_quality = snr_db.map_or(Health::Ok, |v| state.config.thresholds.snr.evaluate(v));
        let tx_rate = state.link.tx_rate;

        Self {
            gateway,
            internet,
            internet_total,
            internet_bad,
            worst_internet_host,
            dns_system,
            dns_public,
            reach_any_ok,
            reach_all_fail,
            routing_seen: state.routing.seen,
            routing_reachable: state.routing.reachable,
            wifi_signal,
            wifi_quality,
            rssi_dbm,
            snr_db,
            tx_rate,
            captive: state.captive_portal,
            bufferbloat: state.throughput.bufferbloat_health_current(),
            bufferbloat_ms: match (
                state.throughput.idle_latency_ms,
                state.throughput.loaded_latency_ms,
            ) {
                (Some(i), Some(l)) => Some((l - i).max(0.0)),
                _ => None,
            },
        }
    }
}

/// Diagnose the current state: a plain-language, worst-first list of what is wrong and where.
/// Never empty — an all-healthy state yields a single `Ok` "No problems detected" verdict.
pub fn diagnose(state: &AppState) -> Vec<Diagnosis> {
    diagnose_signals(&Signals::from_state(state))
}

/// The pure ruleset over a [`Signals`] snapshot.
fn diagnose_signals(s: &Signals) -> Vec<Diagnosis> {
    let mut out = Vec::new();

    let gateway_unhealthy = matches!(s.gateway, Some(h) if h > Health::Ok);
    // Treat a missing gateway as "not a local problem" so we don't wrongly blame the LAN.
    let gateway_ok_or_absent = !gateway_unhealthy;

    // 1. Wi-Fi radio. Distinguish a weak *signal* (RSSI) from poor *quality* (low SNR /
    // interference); a weak signal paired with gateway loss points at the local link.
    let wifi = s.wifi_signal.worst(s.wifi_quality);
    if wifi > Health::Ok {
        let mut evidence = Vec::new();
        if let Some(r) = s.rssi_dbm {
            evidence.push(format!("RSSI {r:.0} dBm"));
        }
        if let Some(snr) = s.snr_db {
            evidence.push(format!("SNR {snr:.0} dB"));
        }
        if let Some(tx) = s.tx_rate {
            evidence.push(format!("{tx:.0} Mbps"));
        }
        let (headline, severity) = if s.wifi_signal > Health::Ok {
            if gateway_unhealthy {
                evidence.push("gateway shows latency/loss".into());
                (
                    "Weak Wi-Fi signal — likely a local Wi-Fi problem".to_string(),
                    wifi.worst(s.gateway.unwrap_or(Health::Ok)),
                )
            } else {
                ("Weak Wi-Fi signal".to_string(), wifi)
            }
        } else {
            // RSSI is fine, so the culprit is interference / low SNR.
            (
                "Wi-Fi link quality is poor (interference / low SNR)".to_string(),
                wifi,
            )
        };
        out.push(Diagnosis {
            layer: Some(Layer::Wifi),
            severity,
            headline,
            evidence,
        });
    }

    // 2. Gateway / LAN. Only when Wi-Fi looks fine, so a weak radio isn't reported twice.
    if gateway_unhealthy && wifi == Health::Ok {
        out.push(Diagnosis {
            layer: Some(Layer::Gateway),
            severity: s.gateway.unwrap_or(Health::Crit),
            headline: "High latency/loss to your gateway — local network problem".into(),
            evidence: vec!["gateway ping degraded".into()],
        });
    }

    // A captive portal is a specific, actionable cause — report it before the generic
    // "internet unreachable" rules (which it would otherwise trip).
    if s.captive {
        out.push(Diagnosis {
            layer: Some(Layer::Isp),
            severity: Health::Crit,
            headline: "Captive portal — sign-in required to reach the internet".into(),
            evidence: vec!["a web request was intercepted by a login page".into()],
        });
    }

    // 3. ISP / WAN. The gateway is fine but the path beyond it is not.
    if gateway_ok_or_absent && !s.captive {
        let internet_all_bad = s.internet_total > 0 && s.internet_bad == s.internet_total;
        let route_down = s.routing_seen && !s.routing_reachable;
        if s.reach_all_fail && (internet_all_bad || route_down) {
            out.push(Diagnosis {
                layer: Some(Layer::Isp),
                severity: Health::Crit,
                headline: "Internet unreachable — your router is fine, likely an ISP/WAN outage"
                    .into(),
                evidence: vec![
                    "web endpoints unreachable".into(),
                    if route_down {
                        "route to the internet is down".into()
                    } else {
                        "all internet hosts failing".into()
                    },
                ],
            });
        } else if internet_all_bad {
            out.push(Diagnosis {
                layer: Some(Layer::Isp),
                severity: s.internet,
                headline: "Internet path degraded beyond your gateway (ISP/WAN)".into(),
                evidence: vec!["all internet hosts show latency/loss".into()],
            });
        } else if s.reach_all_fail {
            out.push(Diagnosis {
                layer: Some(Layer::Isp),
                severity: Health::Warn,
                headline:
                    "Web (HTTP/HTTPS) unreachable though ping works — possible filtering or captive portal"
                        .into(),
                evidence: vec!["reachability checks all failing".into()],
            });
        }
    }

    // Bufferbloat: latency balloons when the link is saturated (independent of gateway/ISP
    // health, since a link can be "up and fast" yet unusable for calls/gaming under load).
    if s.bufferbloat > Health::Ok {
        let mut evidence = Vec::new();
        if let Some(d) = s.bufferbloat_ms {
            evidence.push(format!("+{d:.0}ms latency under load"));
        }
        out.push(Diagnosis {
            layer: Some(Layer::Isp),
            severity: s.bufferbloat,
            headline: "Bufferbloat — latency spikes when the connection is busy".into(),
            evidence,
        });
    }

    // 4. DNS. Only when some connectivity exists (otherwise DNS failing is a symptom).
    let dns_system_bad = matches!(s.dns_system, Some(h) if h > Health::Ok);
    let dns_public_bad = s.dns_public > Health::Ok;
    let some_connectivity =
        s.reach_any_ok || s.internet == Health::Ok || (s.routing_seen && s.routing_reachable);
    if (dns_system_bad || dns_public_bad) && some_connectivity {
        if dns_system_bad && !dns_public_bad {
            out.push(Diagnosis {
                layer: Some(Layer::Dns),
                severity: s.dns_system.unwrap_or(Health::Warn),
                headline:
                    "Your configured DNS server is failing; public resolvers work — a DNS configuration problem"
                        .into(),
                evidence: vec!["system resolver failing, 1.1.1.1 / 8.8.8.8 OK".into()],
            });
        } else {
            out.push(Diagnosis {
                layer: Some(Layer::Dns),
                severity: s.dns_system.unwrap_or(Health::Ok).worst(s.dns_public),
                headline: "DNS resolution is failing while connectivity is fine".into(),
                evidence: vec!["resolvers slow or not answering".into()],
            });
        }
    }

    // 5. Remote host. Some internet hosts are bad while others are fine.
    if gateway_ok_or_absent
        && s.internet_total > 0
        && s.internet_bad > 0
        && s.internet_bad < s.internet_total
    {
        let host = s
            .worst_internet_host
            .clone()
            .unwrap_or_else(|| "a remote host".into());
        out.push(Diagnosis {
            layer: Some(Layer::Remote),
            severity: s.internet,
            headline: format!(
                "Some hosts are slow or lossy ({}/{}); the rest of your connection is healthy",
                s.internet_bad, s.internet_total
            ),
            evidence: vec![format!("worst host: {host}")],
        });
    }

    // 6. Nothing wrong.
    if out.is_empty() {
        out.push(Diagnosis {
            layer: None,
            severity: Health::Ok,
            headline: "No problems detected".into(),
            evidence: Vec::new(),
        });
    }

    // Worst-first; the stable sort preserves the layer precedence above for equal severities.
    out.sort_by_key(|d| std::cmp::Reverse(d.severity));
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::metrics::Sample;
    use chrono::{DateTime, TimeZone, Utc};
    use pretty_assertions::assert_eq;

    fn healthy() -> Signals {
        Signals::default()
    }

    fn top(s: &Signals) -> Diagnosis {
        diagnose_signals(s).into_iter().next().unwrap()
    }

    #[test]
    fn all_healthy_reports_no_problems() {
        let d = diagnose_signals(&healthy());
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].layer, None);
        assert_eq!(d[0].severity, Health::Ok);
        assert_eq!(d[0].headline, "No problems detected");
    }

    #[test]
    fn isp_outage_when_gateway_ok_but_everything_beyond_is_down() {
        let s = Signals {
            internet: Health::Crit,
            internet_bad: 2,
            reach_any_ok: false,
            reach_all_fail: true,
            routing_reachable: false,
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Isp));
        assert_eq!(t.severity, Health::Crit);
        assert!(
            t.headline.to_lowercase().contains("isp") || t.headline.to_lowercase().contains("wan"),
            "headline should blame the ISP/WAN: {}",
            t.headline
        );
    }

    #[test]
    fn dns_only_failure_is_attributed_to_dns_not_connectivity() {
        // Connectivity fine, only the system resolver failing while public resolvers work.
        let s = Signals {
            dns_system: Some(Health::Crit),
            dns_public: Health::Ok,
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Dns));
        assert!(
            t.headline.to_lowercase().contains("dns"),
            "headline should name DNS: {}",
            t.headline
        );
        assert!(
            t.headline.to_lowercase().contains("configured")
                || t.headline.to_lowercase().contains("public"),
            "should distinguish the configured resolver from public ones: {}",
            t.headline
        );
    }

    #[test]
    fn dns_failure_during_outage_is_suppressed() {
        // Full outage: DNS is failing too, but that's a symptom — don't emit a DNS verdict.
        let s = Signals {
            internet: Health::Crit,
            internet_bad: 2,
            reach_any_ok: false,
            reach_all_fail: true,
            routing_reachable: false,
            dns_system: Some(Health::Crit),
            dns_public: Health::Crit,
            ..healthy()
        };
        let d = diagnose_signals(&s);
        assert!(
            d.iter().all(|x| x.layer != Some(Layer::Dns)),
            "DNS should be suppressed during a full outage: {d:?}"
        );
    }

    #[test]
    fn captive_portal_is_reported_before_a_generic_outage() {
        // A portal makes reachability fail; without the captive signal this looks like an
        // ISP outage. The dedicated captive verdict should lead and be the only ISP verdict.
        let s = Signals {
            captive: true,
            internet: Health::Crit,
            internet_bad: 2,
            reach_any_ok: false,
            reach_all_fail: true,
            ..healthy()
        };
        let d = diagnose_signals(&s);
        let t = &d[0];
        assert_eq!(t.layer, Some(Layer::Isp));
        assert!(
            t.headline.to_lowercase().contains("captive")
                || t.headline.to_lowercase().contains("sign-in"),
            "should name the captive portal: {}",
            t.headline
        );
        assert_eq!(
            d.iter().filter(|x| x.layer == Some(Layer::Isp)).count(),
            1,
            "captive should be the only ISP verdict: {d:?}"
        );
    }

    #[test]
    fn weak_wifi_with_bad_gateway_blames_local_wifi() {
        let s = Signals {
            wifi_signal: Health::Crit,
            rssi_dbm: Some(-82.0),
            gateway: Some(Health::Warn),
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Wifi));
        assert!(
            t.headline.to_lowercase().contains("wi-fi")
                || t.headline.to_lowercase().contains("wifi"),
            "headline should name Wi-Fi: {}",
            t.headline
        );
    }

    #[test]
    fn good_signal_but_low_snr_is_a_link_quality_problem() {
        // RSSI is fine, but SNR is poor — interference, not a weak signal.
        let s = Signals {
            wifi_signal: Health::Ok,
            wifi_quality: Health::Warn,
            rssi_dbm: Some(-55.0),
            snr_db: Some(12.0),
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Wifi));
        assert!(
            t.headline.to_lowercase().contains("quality")
                || t.headline.to_lowercase().contains("snr")
                || t.headline.to_lowercase().contains("interference"),
            "headline should describe poor link quality: {}",
            t.headline
        );
    }

    #[test]
    fn bad_gateway_with_good_wifi_is_a_gateway_problem() {
        let s = Signals {
            gateway: Some(Health::Crit),
            wifi_signal: Health::Ok,
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Gateway));
    }

    #[test]
    fn bufferbloat_is_reported_even_when_links_are_healthy() {
        let s = Signals {
            bufferbloat: Health::Warn,
            bufferbloat_ms: Some(180.0),
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Isp));
        assert!(
            t.headline.to_lowercase().contains("bufferbloat")
                || t.headline.to_lowercase().contains("under load")
                || t.headline.to_lowercase().contains("busy"),
            "headline should describe bufferbloat: {}",
            t.headline
        );
    }

    #[test]
    fn one_bad_host_among_many_is_a_remote_problem() {
        let s = Signals {
            internet: Health::Warn,
            internet_total: 2,
            internet_bad: 1,
            worst_internet_host: Some("example.com".into()),
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Remote));
        assert!(
            t.headline.to_lowercase().contains("host"),
            "headline should mention the host: {}",
            t.headline
        );
    }

    #[test]
    fn verdicts_are_sorted_worst_first() {
        // A weak-Wi-Fi warn plus an ISP-degraded warn plus a DNS crit → DNS crit leads.
        let s = Signals {
            wifi_signal: Health::Warn,
            rssi_dbm: Some(-72.0),
            dns_system: Some(Health::Crit),
            dns_public: Health::Crit,
            ..healthy()
        };
        let d = diagnose_signals(&s);
        assert!(d.len() >= 2, "expected multiple verdicts: {d:?}");
        assert_eq!(d[0].severity, Health::Crit);
        for pair in d.windows(2) {
            assert!(
                pair[0].severity >= pair[1].severity,
                "not worst-first: {d:?}"
            );
        }
    }

    // --- integration: from_state projection ---

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap()
    }

    fn integ_config() -> Config {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = Some("192.168.1.1".into());
        c.targets.gateway_auto = false;
        c.thresholds.debounce_samples = 2;
        c
    }

    #[test]
    fn diagnose_reads_dns_failure_from_real_state() {
        let mut state = AppState::new(integ_config());
        // Healthy pings to both gateway and internet.
        for _ in 0..3 {
            state.apply_sample(
                now(),
                Sample::Latency {
                    target: "192.168.1.1".into(),
                    rtt_ms: Some(3.0),
                },
            );
            state.apply_sample(
                now(),
                Sample::Latency {
                    target: "1.1.1.1".into(),
                    rtt_ms: Some(20.0),
                },
            );
        }
        // System resolver fails; public resolvers succeed.
        for _ in 0..3 {
            state.apply_sample(
                now(),
                Sample::Dns {
                    resolver: "system".into(),
                    latency_ms: None,
                },
            );
            state.apply_sample(
                now(),
                Sample::Dns {
                    resolver: "cloudflare".into(),
                    latency_ms: Some(15.0),
                },
            );
            state.apply_sample(
                now(),
                Sample::Dns {
                    resolver: "google".into(),
                    latency_ms: Some(18.0),
                },
            );
        }
        let d = diagnose(&state);
        assert_eq!(
            d[0].layer,
            Some(Layer::Dns),
            "top verdict should be DNS: {d:?}"
        );
    }
}
