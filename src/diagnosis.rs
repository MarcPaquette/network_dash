//! Root-cause correlation: turn the per-metric health streams into a localized,
//! plain-language verdict — the "what is wrong with my network (and where)" answer.
//!
//! Everything here is pure: [`diagnose`] reads an [`AppState`] snapshot, projects it into a
//! small [`Signals`] struct, and runs an ordered ruleset over it. The projection
//! ([`Signals::from_state`]) is the only part that touches app state; the ruleset
//! ([`diagnose_signals`]) is a pure function of `Signals`, so each rule is unit-tested by
//! constructing `Signals` directly rather than driving the whole reducer.

use serde::{Deserialize, Serialize};

use crate::app::AppState;
use crate::health::Health;
use crate::metrics::dns::Integrity;

/// The network segment a fault localizes to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Layer {
    /// The local network card itself — errors and dropped frames on your own hardware.
    Nic,
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
            Layer::Nic => "NIC",
            Layer::Wifi => "WI-FI",
            Layer::Gateway => "GATEWAY",
            Layer::Isp => "ISP/WAN",
            Layer::Dns => "DNS",
            Layer::Remote => "REMOTE",
        }
    }

    /// How far down the path from you the layer sits. Faults propagate one way: a dead radio
    /// makes every hop past it look broken, and nothing past it can break the radio.
    ///
    /// DNS and a single bad remote host share a rank — both live past the ISP, on branches
    /// that don't touch each other. The NIC sits ahead of the radio: the card is the thing
    /// the radio runs on, so a card shedding frames breaks the link and never the reverse.
    fn distance(self) -> u8 {
        match self {
            Layer::Nic => 0,
            Layer::Wifi => 1,
            Layer::Gateway => 2,
            Layer::Isp => 3,
            Layer::Dns | Layer::Remote => 4,
        }
    }

    /// Whether a fault here would account for a symptom reported at `other` — the test for
    /// "this alert is an echo of the one above it, not news".
    pub fn explains(self, other: Layer) -> bool {
        self.distance() < other.distance()
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
    /// Worst *honesty* verdict across resolvers, and who earned it. Kept apart from the two
    /// above because a resolver being spoofed is fast and answers promptly — its timing is
    /// spotless, and reading only the timing is how the fault stayed invisible here.
    dns_integrity: Health,
    /// Resolvers something else is answering for, and resolvers answering for names they do
    /// not own. Different culprits, so the verdict names them separately.
    dns_forged: Vec<String>,
    dns_hijacked: Vec<String>,
    /// Any reachability endpoint currently OK / all of them failing.
    reach_any_ok: bool,
    reach_all_fail: bool,
    /// How many endpoints are checked and how many are failing. `reach_all_fail` cannot tell
    /// "one host is down" from "the internet is down", and those are different verdicts.
    reach_total: usize,
    reach_bad: usize,
    /// Worst TCP/TLS handshake health, and the endpoints that failed outright. Ping cannot
    /// see this: a host can answer ICMP instantly and still refuse every connection.
    transport: Health,
    transport_failed: Vec<String>,
    /// Certificate expiry: worst health, and the endpoint running out soonest with its days
    /// remaining. Kept apart from `transport` because a valid-but-expiring certificate is
    /// not a transport fault — the handshake it came from was perfect.
    cert: Health,
    cert_soonest: Option<(String, i64)>,
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
    /// Local NIC error health, and the error count that produced it.
    nic_errors: Health,
    nic_error_count: Option<f64>,
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
            dns_integrity: Health::Ok,
            dns_forged: Vec::new(),
            dns_hijacked: Vec::new(),
            reach_any_ok: true,
            reach_all_fail: false,
            reach_total: 2,
            reach_bad: 0,
            transport: Health::Ok,
            transport_failed: Vec::new(),
            cert: Health::Ok,
            cert_soonest: None,
            routing_seen: true,
            routing_reachable: true,
            wifi_signal: Health::Ok,
            wifi_quality: Health::Ok,
            rssi_dbm: Some(-55.0),
            snr_db: Some(45.0),
            tx_rate: Some(866.0),
            captive: false,
            nic_errors: Health::Ok,
            nic_error_count: None,
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

        // Honesty, which the timing verdicts above cannot see. It reaches the DNS panel and
        // therefore the header, so it has to reach the diagnosis too — otherwise the banner
        // says PROBLEM while the panel below it says nothing is wrong.
        let dns_integrity = Health::worst_of(
            state
                .resolvers
                .values()
                .map(|r| r.integrity_health_current()),
        );
        let named = |want: Integrity| -> Vec<String> {
            state
                .resolvers
                .iter()
                .filter(|(_, r)| r.integrity == want)
                .map(|(name, _)| name.clone())
                .collect()
        };
        let dns_forged = named(Integrity::Forged);
        let dns_hijacked = named(Integrity::Hijacked);

        // Reachability endpoints.
        let mut reach_any_ok = false;
        let mut reach_seen = false;
        let mut reach_all_fail = true;
        let mut reach_total = 0;
        let mut reach_bad = 0;
        for r in state.reachability.values() {
            reach_seen = true;
            reach_total += 1;
            if r.ok {
                reach_any_ok = true;
                reach_all_fail = false;
            } else {
                reach_bad += 1;
            }
        }
        if !reach_seen {
            reach_all_fail = false;
        }

        // Transport: TCP and TLS timings together. They are one panel and one complaint —
        // "a real connection to this host does not work well" — and splitting the verdict
        // would report the same outage twice for endpoints that appear in both probes.
        let transport = Health::worst_of(
            state
                .tcp
                .values()
                .map(|t| t.health_current())
                .chain(state.tls.values().map(|t| t.health_current())),
        );
        let mut transport_failed: Vec<String> = state
            .tcp
            .iter()
            .filter(|(_, t)| !t.last_ok)
            .map(|(n, _)| n.clone())
            .chain(
                state
                    .tls
                    .iter()
                    .filter(|(_, t)| !t.last_ok)
                    .map(|(n, _)| n.clone()),
            )
            .collect();
        transport_failed.sort();
        transport_failed.dedup();

        let cert = Health::worst_of(state.tls.values().map(|t| t.expiry_health_current()));
        let cert_soonest = state
            .tls
            .iter()
            .filter_map(|(n, t)| t.expires_in_days.map(|d| (n.clone(), d)))
            .min_by_key(|(_, d)| *d);

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
            dns_integrity,
            dns_forged,
            dns_hijacked,
            reach_any_ok,
            reach_all_fail,
            reach_total,
            reach_bad,
            transport,
            transport_failed,
            cert,
            cert_soonest,
            routing_seen: state.routing.seen,
            routing_reachable: state.routing.reachable,
            wifi_signal,
            wifi_quality,
            rssi_dbm,
            snr_db,
            tx_rate,
            captive: state.captive_portal,
            nic_errors: state.iface.health_current(),
            nic_error_count: match (state.iface.rx_errors, state.iface.tx_errors) {
                (Some(rx), Some(tx)) => Some((rx + tx) as f64),
                _ => None,
            },
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

/// The layer to blame for whatever is worst right now — the one thing worth fixing first.
/// `None` when nothing is wrong, or when the worst verdict doesn't localize.
///
/// This is deliberately a *reading* of [`diagnose`] rather than a second ruleset: the moment
/// two correlation engines exist they disagree, and the panel and the event feed start
/// telling the user different stories about the same outage.
pub fn primary_layer(state: &AppState) -> Option<Layer> {
    primary_of(&diagnose(state))
}

/// The blamed layer of the worst verdict in an already-sorted list.
fn primary_of(verdicts: &[Diagnosis]) -> Option<Layer> {
    verdicts
        .iter()
        .find(|d| d.severity > Health::Ok)
        .and_then(|d| d.layer)
}

/// The pure ruleset over a [`Signals`] snapshot.
fn diagnose_signals(s: &Signals) -> Vec<Diagnosis> {
    let mut out = Vec::new();

    let gateway_unhealthy = matches!(s.gateway, Some(h) if h > Health::Ok);
    // Treat a missing gateway as "not a local problem" so we don't wrongly blame the LAN.
    let gateway_ok_or_absent = !gateway_unhealthy;

    // 0. The card itself. First, because it is upstream of every other layer and because it
    // is the one fault none of the network-side probes can see: a NIC shedding frames looks
    // like a weak radio, a bad gateway and a flaky ISP all at once, and none of those is what
    // needs replacing.
    if s.nic_errors > Health::Ok {
        let mut evidence = vec!["errors on the local interface".to_string()];
        if let Some(n) = s.nic_error_count {
            evidence.insert(0, format!("{n:.0} errors in the last interval"));
        }
        out.push(Diagnosis {
            layer: Some(Layer::Nic),
            severity: s.nic_errors,
            headline: "Network interface is dropping frames — check the cable, port or driver"
                .into(),
            evidence,
        });
    }

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

    // 4a. DNS honesty. Reported regardless of connectivity, and separately from the timing
    // rule above: interception is at its most convincing when everything else looks perfect,
    // and a resolver being spoofed answers faster than the real one ever could.
    if s.dns_integrity > Health::Ok {
        let (headline, evidence) = if !s.dns_forged.is_empty() {
            (
                "Something on this network is answering DNS in place of your resolvers".to_string(),
                vec![format!(
                    "{} replied to nothing that must resolve — the answers are not theirs",
                    s.dns_forged.join(", ")
                )],
            )
        } else {
            (
                "A resolver is answering for names it does not own".to_string(),
                vec![format!(
                    "{} returns addresses for names that should not resolve",
                    s.dns_hijacked.join(", ")
                )],
            )
        };
        out.push(Diagnosis {
            layer: Some(Layer::Dns),
            severity: s.dns_integrity,
            headline,
            evidence,
        });
    }

    // 4b. Transport. A host that answers ICMP can still refuse every connection, and a
    // handshake that succeeds slowly is invisible to every other probe on the dashboard.
    // Reported even when the ISP rules above fired, because "your ISP is degraded" does not
    // tell you that a specific service is refusing you outright.
    if s.transport > Health::Ok {
        let evidence = if s.transport_failed.is_empty() {
            vec!["handshakes are slow".to_string()]
        } else {
            vec![format!(
                "no connection to {}",
                s.transport_failed.join(", ")
            )]
        };
        let headline = if s.transport_failed.is_empty() {
            "Connections are slow to establish though the path itself looks healthy".to_string()
        } else {
            "Connections are being refused or timing out (TCP/TLS)".to_string()
        };
        out.push(Diagnosis {
            layer: Some(Layer::Isp),
            severity: s.transport,
            headline,
            evidence,
        });
    }

    // 4c. Certificate expiry. Deliberately unlocalized: every layer is working, the
    // handshake succeeded, and the only thing wrong is a date. Blaming a layer for it would
    // be false, and would let an unrelated outage suppress the one warning nothing repeats.
    if s.cert > Health::Ok {
        let (headline, evidence) = match &s.cert_soonest {
            Some((name, days)) if *days < 0 => (
                "A TLS certificate has expired".to_string(),
                vec![format!("{name}: expired {}d ago", -days)],
            ),
            Some((name, days)) => (
                format!("A TLS certificate expires in {days} days"),
                vec![format!("{name}: {days}d left")],
            ),
            None => (
                "A TLS certificate is close to expiry".to_string(),
                Vec::new(),
            ),
        };
        out.push(Diagnosis {
            layer: None,
            severity: s.cert,
            headline,
            evidence,
        });
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

    // 5b. A minority of web endpoints failing. Not an outage — the others answered — but the
    // panel goes red for it, so something has to say why. Without this the header claims a
    // problem the panel below it cannot name.
    if !s.reach_all_fail && s.reach_bad > 0 && s.reach_bad < s.reach_total {
        out.push(Diagnosis {
            layer: Some(Layer::Remote),
            severity: Health::Crit,
            headline: format!(
                "{} of {} web endpoints unreachable; the rest of your connection is healthy",
                s.reach_bad, s.reach_total
            ),
            evidence: vec!["likely that service rather than your network".into()],
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
    use crate::metrics::dns::Answer;
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

    /// Every state the header can call unhealthy must be a state the diagnosis panel can
    /// explain. Otherwise the banner says PROBLEM while the panel directly beneath it says
    /// "No problems detected", and the user is left to decide which half to believe.
    #[test]
    fn the_header_never_claims_worse_than_the_diagnosis_can_explain() {
        let mut cfg = Config::default();
        cfg.thresholds.trip_after_secs = 0.0;
        cfg.thresholds.clear_after_secs = 0.0;
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 12, 0, 0).unwrap();

        let faults: Vec<(&str, Vec<Sample>)> = vec![
            (
                "one endpoint unreachable while the others answer",
                vec![
                    Sample::Reachability {
                        endpoint: "https".into(),
                        ok: true,
                    },
                    Sample::Reachability {
                        endpoint: "ipv6".into(),
                        ok: false,
                    },
                ],
            ),
            (
                "a port that will not open",
                vec![Sample::TcpHandshake {
                    endpoint: "cloudflare".into(),
                    connect_ms: None,
                }],
            ),
            (
                "a negotiation that never completes",
                vec![Sample::Tls {
                    endpoint: "cloudflare".into(),
                    handshake_ms: None,
                    expires_in_days: None,
                }],
            ),
            (
                "a certificate about to expire",
                vec![Sample::Tls {
                    endpoint: "cloudflare".into(),
                    handshake_ms: Some(20.0),
                    expires_in_days: Some(1),
                }],
            ),
            (
                "a resolver answering for names it does not own",
                vec![Sample::DnsIntegrity {
                    resolver: "system".into(),
                    verdict: Integrity::Hijacked,
                }],
            ),
            (
                "something on the network answering in a resolver's place",
                vec![Sample::DnsIntegrity {
                    resolver: "cloudflare".into(),
                    verdict: Integrity::Forged,
                }],
            ),
        ];

        for (what, samples) in faults {
            let mut state = AppState::new(cfg.clone());
            for sample in samples {
                state.apply_sample(now, sample);
            }
            let worst = diagnose(&state)
                .iter()
                .map(|d| d.severity)
                .max()
                .expect("diagnose is never empty");
            assert_eq!(
                worst,
                state.overall_health(),
                "the header and the diagnosis disagree about {what}"
            );
        }
    }

    #[test]
    fn a_refused_handshake_is_explained_rather_than_left_to_the_header() {
        let s = Signals {
            transport: Health::Crit,
            transport_failed: vec!["cloudflare".into()],
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Isp));
        assert_eq!(t.severity, Health::Crit);
        assert!(
            t.evidence.iter().any(|e| e.contains("cloudflare")),
            "the verdict should name what failed: {t:?}"
        );
    }

    // Interception is most convincing when every other signal is perfect, so this rule must
    // not be gated on something else already being wrong.
    #[test]
    fn a_forged_resolver_is_explained_on_an_otherwise_perfect_network() {
        let s = Signals {
            dns_integrity: Health::Warn,
            dns_forged: vec!["cloudflare".into(), "google".into()],
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Dns));
        assert_eq!(t.severity, Health::Warn);
        assert!(
            t.evidence.iter().any(|e| e.contains("cloudflare")),
            "the verdict must name who is being answered for: {t:?}"
        );
        assert!(
            t.headline.to_lowercase().contains("in place of"),
            "a forgery is somebody else answering, not the resolver misbehaving: {t:?}"
        );
    }

    #[test]
    fn a_hijacking_resolver_is_blamed_rather_than_the_network() {
        let s = Signals {
            dns_integrity: Health::Warn,
            dns_hijacked: vec!["system".into()],
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(t.layer, Some(Layer::Dns));
        assert!(
            t.evidence.iter().any(|e| e.contains("system")),
            "name the resolver that is answering: {t:?}"
        );
    }

    // A resolver whose timing is spotless can still be the one being spoofed — that is the
    // normal case, since the middlebox answers faster than the real resolver could.
    #[test]
    fn perfect_timing_does_not_clear_a_forged_resolver() {
        let s = Signals {
            dns_system: Some(Health::Ok),
            dns_public: Health::Ok,
            dns_integrity: Health::Warn,
            dns_forged: vec!["cloudflare".into()],
            ..healthy()
        };
        assert_eq!(top(&s).layer, Some(Layer::Dns));
    }

    #[test]
    fn an_expiring_certificate_is_reported_without_blaming_the_network() {
        let s = Signals {
            cert: Health::Warn,
            cert_soonest: Some(("cloudflare".into(), 9)),
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(
            t.layer, None,
            "nothing on the path is broken, so no layer is at fault"
        );
        assert_eq!(t.severity, Health::Warn);
        assert!(t.headline.to_lowercase().contains("certificate"), "{t:?}");
    }

    #[test]
    fn one_dead_endpoint_among_several_is_not_an_outage() {
        let s = Signals {
            reach_bad: 1,
            reach_total: 3,
            ..healthy()
        };
        let t = top(&s);
        assert_eq!(
            t.layer,
            Some(Layer::Remote),
            "the rest of the connection works, so this is one host's problem"
        );
        assert!(
            !t.headline.to_lowercase().contains("outage"),
            "{}",
            t.headline
        );
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
    fn a_failing_nic_is_blamed_ahead_of_everything_it_breaks() {
        // A card shedding frames looks exactly like a weak radio and a bad gateway from
        // every other probe. It is neither, and replacing the access point won't fix it.
        let d = diagnose_signals(&Signals {
            nic_errors: Health::Crit,
            nic_error_count: Some(42.0),
            wifi_signal: Health::Warn,
            gateway: Some(Health::Warn),
            ..Default::default()
        });
        let top = d.first().expect("a verdict");
        assert_eq!(top.layer, Some(Layer::Nic));
        assert_eq!(top.severity, Health::Crit);
        assert!(
            top.headline.to_lowercase().contains("interface")
                || top.headline.to_lowercase().contains("nic"),
            "should name the hardware: {}",
            top.headline
        );
        assert_eq!(primary_of(&d), Some(Layer::Nic));
    }

    #[test]
    fn a_clean_nic_is_never_mentioned() {
        let d = diagnose_signals(&Signals {
            nic_errors: Health::Ok,
            wifi_signal: Health::Warn,
            ..Default::default()
        });
        assert!(
            d.iter().all(|x| x.layer != Some(Layer::Nic)),
            "nothing to say about a card that works: {d:?}"
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

    // --- root-cause ordering ---

    const ALL_LAYERS: [Layer; 6] = [
        Layer::Nic,
        Layer::Wifi,
        Layer::Gateway,
        Layer::Isp,
        Layer::Dns,
        Layer::Remote,
    ];

    #[test]
    fn an_upstream_fault_explains_a_downstream_symptom() {
        // The card is upstream of everything, radio included: a NIC shedding frames breaks
        // the Wi-Fi link, never the other way round.
        assert!(Layer::Nic.explains(Layer::Wifi));
        assert!(Layer::Nic.explains(Layer::Remote));
        assert!(Layer::Wifi.explains(Layer::Gateway));
        assert!(Layer::Wifi.explains(Layer::Dns));
        assert!(Layer::Gateway.explains(Layer::Isp));
        assert!(Layer::Isp.explains(Layer::Dns));
        assert!(Layer::Isp.explains(Layer::Remote));
    }

    #[test]
    fn a_downstream_fault_never_explains_its_upstream() {
        assert!(!Layer::Wifi.explains(Layer::Nic));
        assert!(!Layer::Dns.explains(Layer::Isp));
        assert!(!Layer::Isp.explains(Layer::Gateway));
        assert!(!Layer::Remote.explains(Layer::Wifi));
        assert!(!Layer::Gateway.explains(Layer::Wifi));
    }

    #[test]
    fn a_layer_does_not_explain_itself() {
        for l in ALL_LAYERS {
            assert!(!l.explains(l), "{l:?} explaining itself is circular");
        }
    }

    #[test]
    fn layers_at_the_same_distance_do_not_explain_each_other() {
        // DNS and a single bad remote host both sit past the ISP; neither is evidence for
        // the other, and calling one the cause of the other would hide a real second fault.
        assert!(!Layer::Dns.explains(Layer::Remote));
        assert!(!Layer::Remote.explains(Layer::Dns));
    }

    #[test]
    fn primary_layer_is_the_worst_localized_verdict() {
        let s = Signals {
            gateway: Some(Health::Crit),
            ..healthy()
        };
        assert_eq!(primary_of(&diagnose_signals(&s)), Some(Layer::Gateway));
    }

    #[test]
    fn a_healthy_network_blames_nothing() {
        assert_eq!(primary_of(&diagnose_signals(&healthy())), None);
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
        c.thresholds.trip_after_secs = 0.0;
        c.thresholds.clear_after_secs = 0.0;
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
                    answer: Answer::Silence,
                },
            );
            state.apply_sample(
                now(),
                Sample::Dns {
                    resolver: "cloudflare".into(),
                    answer: Answer::Addresses(15.0),
                },
            );
            state.apply_sample(
                now(),
                Sample::Dns {
                    resolver: "google".into(),
                    answer: Answer::Addresses(18.0),
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
