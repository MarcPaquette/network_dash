//! Application state and the pure reducer.
//!
//! [`AppState`] owns all dashboard state. [`AppState::apply_sample`] folds a probe
//! [`Sample`] in — updating history, re-evaluating debounced health, and emitting an
//! [`Incident`] on any confirmed transition. [`AppState::apply_action`] handles control
//! input. Everything here is pure and synchronous: the caller supplies the timestamp, so
//! the reducer is fully deterministic and testable without a clock, network, or terminal.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Utc};

use crate::config::Config;
use crate::health::{Debouncer, Health, Thresholds};
use crate::history::{LossWindow, Series};
use crate::incidents::Incident;
use crate::metrics::{MetricId, Sample};
use crate::ui::theme::Theme;

/// Control actions (mapped from key input by the event loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    TogglePause,
    ClearEvents,
    ForceRefresh,
    /// Advance to the next color theme (live cycle).
    CycleTheme,
}

/// Per-ping-target rolling state and debounced health streams.
#[derive(Debug, Clone)]
pub struct TargetState {
    pub is_gateway: bool,
    pub latency_ms: Series,
    pub loss: LossWindow,
    /// Rolling history of the loss-window percentage, for the loss line graph.
    pub loss_history: Series,
    latency_health: Debouncer,
    jitter_health: Debouncer,
    loss_health: Debouncer,
}

impl TargetState {
    fn new(is_gateway: bool, cfg: &Config) -> Self {
        let t = &cfg.thresholds;
        Self {
            is_gateway,
            latency_ms: Series::new(t.history_len),
            loss: LossWindow::new(t.loss_window),
            loss_history: Series::new(t.history_len),
            latency_health: Debouncer::new(Health::Ok, t.debounce_samples),
            jitter_health: Debouncer::new(Health::Ok, t.debounce_samples),
            loss_health: Debouncer::new(Health::Ok, t.debounce_samples),
        }
    }

    fn latency_thresholds<'a>(&self, cfg: &'a Config) -> &'a Thresholds {
        if self.is_gateway {
            &cfg.thresholds.latency_gateway
        } else {
            &cfg.thresholds.latency_internet
        }
    }

    pub fn latency_health_current(&self) -> Health {
        self.latency_health.current()
    }
    pub fn jitter_health_current(&self) -> Health {
        self.jitter_health.current()
    }
    pub fn loss_health_current(&self) -> Health {
        self.loss_health.current()
    }
}

/// Per-DNS-resolver rolling state.
#[derive(Debug, Clone)]
pub struct ResolverState {
    pub latency_ms: Series,
    pub last_ok: bool,
    health: Debouncer,
}

/// Per-endpoint reachability state.
#[derive(Debug, Clone)]
pub struct ReachState {
    pub ok: bool,
    health: Debouncer,
}

/// Throughput state: passive rx/tx history and the last capacity-probe result.
#[derive(Debug, Clone, Default)]
pub struct ThroughputState {
    pub rx_bps: Option<Series>,
    pub tx_bps: Option<Series>,
    pub last_mbps: Option<f64>,
    health: Option<Debouncer>,
}

/// Wireless link state.
#[derive(Debug, Clone, Default)]
pub struct LinkState {
    pub rssi_dbm: Option<f64>,
    pub ssid: Option<String>,
    health: Option<Debouncer>,
}

/// Routing/path state for the routing target.
#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    pub hops: usize,
    pub reachable: bool,
    pub changed: bool,
    pub seen: bool,
    health: Option<Debouncer>,
}

/// All dashboard state.
#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Config,
    /// Active color theme, resolved from `config.ui.theme` and cycled by [`Action::CycleTheme`].
    pub theme: Theme,
    pub targets: BTreeMap<String, TargetState>,
    pub resolvers: BTreeMap<String, ResolverState>,
    pub reachability: BTreeMap<String, ReachState>,
    pub throughput: ThroughputState,
    pub link: LinkState,
    pub routing: RoutingState,
    pub events: VecDeque<Incident>,
    pub max_events: usize,
    pub paused: bool,
    pub should_quit: bool,
}

impl AppState {
    /// Build state from config, pre-registering the configured ping targets.
    pub fn new(config: Config) -> Self {
        let theme = Theme::resolve(&config.ui.theme);
        let mut state = Self {
            theme,
            targets: BTreeMap::new(),
            resolvers: BTreeMap::new(),
            reachability: BTreeMap::new(),
            throughput: ThroughputState::default(),
            link: LinkState::default(),
            routing: RoutingState::default(),
            events: VecDeque::new(),
            max_events: 200,
            paused: false,
            should_quit: false,
            config,
        };
        let internet = state.config.targets.internet.clone();
        for addr in internet {
            state.register_target(addr, false);
        }
        if let Some(gw) = state.config.targets.gateway.clone() {
            state.register_target(gw, true);
        }
        state
    }

    /// Register (or re-flag) a ping target. Used at startup and after gateway detection.
    pub fn register_target(&mut self, addr: impl Into<String>, is_gateway: bool) {
        let cfg = self.config.clone();
        self.targets
            .entry(addr.into())
            .or_insert_with(|| TargetState::new(is_gateway, &cfg))
            .is_gateway = is_gateway;
    }

    /// Fold one sample into state, returning any incidents produced by the update. Emitted
    /// incidents are also appended to the in-memory `events` ring.
    pub fn apply_sample(&mut self, now: DateTime<Utc>, sample: Sample) -> Vec<Incident> {
        let incidents = match sample {
            Sample::Latency { target, rtt_ms } => self.apply_latency(now, &target, rtt_ms),
            Sample::Dns {
                resolver,
                latency_ms,
            } => self.apply_dns(now, &resolver, latency_ms),
            Sample::Reachability { endpoint, ok } => self.apply_reachability(now, &endpoint, ok),
            Sample::Throughput { rx_bps, tx_bps } => {
                self.apply_throughput(rx_bps, tx_bps);
                Vec::new()
            }
            Sample::ThroughputProbe { mbps } => self.apply_throughput_probe(now, mbps),
            Sample::Link { rssi_dbm, ssid } => self.apply_link(now, rssi_dbm, ssid),
            Sample::Routing {
                target,
                hops,
                reachable,
                changed,
            } => self.apply_routing(now, &target, hops, reachable, changed),
        };
        for inc in &incidents {
            self.push_event(inc.clone());
        }
        incidents
    }

    fn apply_latency(
        &mut self,
        now: DateTime<Utc>,
        target: &str,
        rtt_ms: Option<f64>,
    ) -> Vec<Incident> {
        if !self.targets.contains_key(target) {
            self.register_target(target.to_string(), false);
        }
        let cfg = self.config.clone();
        let t = self.targets.get_mut(target).expect("just registered");

        match rtt_ms {
            Some(rtt) => {
                t.latency_ms.push(rtt);
                t.loss.record(true);
            }
            None => t.loss.record(false),
        }

        let mut out = Vec::new();

        // Latency (uses gateway or internet thresholds depending on the target's role).
        let lat_thr = *t.latency_thresholds(&cfg);
        if let Some(latest) = t.latency_ms.latest() {
            let raw = lat_thr.evaluate(latest);
            if let Some(sev) = t.latency_health.update(raw) {
                out.push(incident_for(
                    now,
                    MetricId::Latency,
                    target,
                    sev,
                    latest,
                    "ms",
                    &lat_thr,
                ));
            }
        }

        // Jitter (shares the Latency panel).
        let jit_thr = cfg.thresholds.jitter;
        if let Some(jitter) = t.latency_ms.jitter() {
            let raw = jit_thr.evaluate(jitter);
            if let Some(sev) = t.jitter_health.update(raw) {
                out.push(incident_for(
                    now,
                    MetricId::Jitter,
                    target,
                    sev,
                    jitter,
                    "ms",
                    &jit_thr,
                ));
            }
        }

        // Loss.
        let loss_thr = cfg.thresholds.loss;
        let loss_pct = t.loss.loss_pct();
        t.loss_history.push(loss_pct);
        let raw = loss_thr.evaluate(loss_pct);
        if let Some(sev) = t.loss_health.update(raw) {
            out.push(incident_for(
                now,
                MetricId::Loss,
                target,
                sev,
                loss_pct,
                "%",
                &loss_thr,
            ));
        }

        out
    }

    fn apply_dns(
        &mut self,
        now: DateTime<Utc>,
        resolver: &str,
        latency_ms: Option<f64>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let thr = cfg.thresholds.dns;
        let state = self
            .resolvers
            .entry(resolver.to_string())
            .or_insert_with(|| ResolverState {
                latency_ms: Series::new(cfg.thresholds.history_len),
                last_ok: true,
                health: Debouncer::new(Health::Ok, cfg.thresholds.debounce_samples),
            });
        let raw = match latency_ms {
            Some(ms) => {
                state.latency_ms.push(ms);
                state.last_ok = true;
                thr.evaluate(ms)
            }
            None => {
                state.last_ok = false;
                Health::Crit // a failed lookup is critical
            }
        };
        let last_ok = state.last_ok;
        let latest = state.latency_ms.latest().unwrap_or(0.0);
        match state.health.update(raw) {
            Some(sev) if sev == Health::Ok => vec![status_incident(
                now,
                MetricId::Dns,
                resolver,
                sev,
                format!("dns recovered ({resolver})"),
            )],
            Some(sev) if !last_ok => {
                vec![status_incident(
                    now,
                    MetricId::Dns,
                    resolver,
                    sev,
                    format!("dns failed ({resolver})"),
                )]
            }
            Some(sev) => vec![incident_for(
                now,
                MetricId::Dns,
                resolver,
                sev,
                latest,
                "ms",
                &thr,
            )],
            None => Vec::new(),
        }
    }

    fn apply_reachability(
        &mut self,
        now: DateTime<Utc>,
        endpoint: &str,
        ok: bool,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let state = self
            .reachability
            .entry(endpoint.to_string())
            .or_insert_with(|| ReachState {
                ok: true,
                health: Debouncer::new(Health::Ok, cfg.thresholds.debounce_samples),
            });
        state.ok = ok;
        let raw = if ok { Health::Ok } else { Health::Crit };
        match state.health.update(raw) {
            Some(Health::Ok) => {
                vec![status_incident(
                    now,
                    MetricId::Reachability,
                    endpoint,
                    Health::Ok,
                    format!("{endpoint} reachable"),
                )]
            }
            Some(sev) => {
                vec![status_incident(
                    now,
                    MetricId::Reachability,
                    endpoint,
                    sev,
                    format!("{endpoint} unreachable"),
                )]
            }
            None => Vec::new(),
        }
    }

    fn apply_throughput(&mut self, rx_bps: f64, tx_bps: f64) {
        let cap = self.config.thresholds.history_len;
        self.throughput
            .rx_bps
            .get_or_insert_with(|| Series::new(cap))
            .push(rx_bps);
        self.throughput
            .tx_bps
            .get_or_insert_with(|| Series::new(cap))
            .push(tx_bps);
    }

    fn apply_throughput_probe(&mut self, now: DateTime<Utc>, mbps: f64) -> Vec<Incident> {
        let cfg = self.config.clone();
        self.throughput.last_mbps = Some(mbps);
        let floor = cfg.throughput.floor_mbps;
        let raw = if mbps < floor {
            Health::Warn
        } else {
            Health::Ok
        };
        let health = self
            .throughput
            .health
            .get_or_insert_with(|| Debouncer::new(Health::Ok, cfg.thresholds.debounce_samples));
        match health.update(raw) {
            Some(Health::Ok) => {
                vec![status_incident(
                    now,
                    MetricId::Throughput,
                    "probe",
                    Health::Ok,
                    "throughput recovered".to_string(),
                )]
            }
            Some(sev) => vec![
                Incident::new(
                    now,
                    MetricId::Throughput,
                    sev,
                    format!("throughput {mbps:.0}Mbps below floor"),
                )
                .with_value(mbps, "Mbps")
                .with_threshold(floor),
            ],
            None => Vec::new(),
        }
    }

    fn apply_link(
        &mut self,
        now: DateTime<Utc>,
        rssi_dbm: Option<f64>,
        ssid: Option<String>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let thr = cfg.thresholds.rssi;
        if ssid.is_some() {
            self.link.ssid = ssid;
        }
        let Some(rssi) = rssi_dbm else {
            return Vec::new();
        };
        self.link.rssi_dbm = Some(rssi);
        let raw = thr.evaluate(rssi);
        let health = self
            .link
            .health
            .get_or_insert_with(|| Debouncer::new(Health::Ok, cfg.thresholds.debounce_samples));
        match health.update(raw) {
            Some(sev) => vec![incident_for(
                now,
                MetricId::Link,
                "wifi",
                sev,
                rssi,
                "dBm",
                &thr,
            )],
            None => Vec::new(),
        }
    }

    fn apply_routing(
        &mut self,
        now: DateTime<Utc>,
        target: &str,
        hops: usize,
        reachable: bool,
        changed: bool,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        self.routing.hops = hops;
        self.routing.reachable = reachable;
        self.routing.changed = changed;
        self.routing.seen = true;
        let raw = if !reachable {
            Health::Crit
        } else if changed {
            Health::Warn
        } else {
            Health::Ok
        };
        let health = self
            .routing
            .health
            .get_or_insert_with(|| Debouncer::new(Health::Ok, cfg.thresholds.debounce_samples));
        let message = match raw {
            Health::Crit => format!("route to {target} unreachable"),
            Health::Warn => format!("route to {target} changed ({hops} hops)"),
            Health::Ok => format!("route to {target} stable ({hops} hops)"),
        };
        match health.update(raw) {
            Some(sev) => vec![status_incident(
                now,
                MetricId::Routing,
                target,
                sev,
                message,
            )],
            None => Vec::new(),
        }
    }

    fn push_event(&mut self, incident: Incident) {
        self.events.push_front(incident);
        while self.events.len() > self.max_events {
            self.events.pop_back();
        }
    }

    /// Apply a control action.
    pub fn apply_action(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::TogglePause => self.paused = !self.paused,
            Action::ClearEvents => self.events.clear(),
            Action::ForceRefresh => {} // handled by the event loop (re-triggers probes)
            Action::CycleTheme => self.theme = self.theme.next(),
        }
    }

    /// Health of a dashboard panel, rolled up across its constituent streams.
    pub fn panel_health(&self, metric: MetricId) -> Health {
        match metric {
            MetricId::Latency | MetricId::Jitter => Health::worst_of(
                self.targets
                    .values()
                    .map(|t| t.latency_health.current().worst(t.jitter_health.current())),
            ),
            MetricId::Loss => {
                Health::worst_of(self.targets.values().map(|t| t.loss_health.current()))
            }
            MetricId::Dns => Health::worst_of(self.resolvers.values().map(|r| r.health.current())),
            MetricId::Throughput => self
                .throughput
                .health
                .as_ref()
                .map_or(Health::Ok, |d| d.current()),
            MetricId::Routing => self
                .routing
                .health
                .as_ref()
                .map_or(Health::Ok, |d| d.current()),
            // The "Link & Reachability" panel combines the wireless link and all endpoints.
            MetricId::Link | MetricId::Reachability => {
                let link = self
                    .link
                    .health
                    .as_ref()
                    .map_or(Health::Ok, |d| d.current());
                let reach =
                    Health::worst_of(self.reachability.values().map(|r| r.health.current()));
                link.worst(reach)
            }
        }
    }

    /// Worst health across all panels (drives the header banner).
    pub fn overall_health(&self) -> Health {
        Health::worst_of([
            self.panel_health(MetricId::Latency),
            self.panel_health(MetricId::Loss),
            self.panel_health(MetricId::Dns),
            self.panel_health(MetricId::Throughput),
            self.panel_health(MetricId::Routing),
            self.panel_health(MetricId::Link),
        ])
    }
}

/// Build an incident for a boolean/status metric transition (no scalar threshold).
fn status_incident(
    now: DateTime<Utc>,
    metric: MetricId,
    target: &str,
    severity: Health,
    message: String,
) -> Incident {
    Incident::new(now, metric, severity, message).with_target(target)
}

/// Build an incident for a scalar-threshold metric transition. Recoveries (`Ok`) carry no
/// threshold; warn/crit carry the boundary they crossed.
fn incident_for(
    now: DateTime<Utc>,
    metric: MetricId,
    target: &str,
    severity: Health,
    value: f64,
    unit: &str,
    thr: &Thresholds,
) -> Incident {
    let message = if severity == Health::Ok {
        format!("{} recovered ({target})", metric.label())
    } else {
        format!("{} {value:.0}{unit} ({target})", metric.label())
    };
    let inc = Incident::new(now, metric, severity, message)
        .with_value(value, unit)
        .with_target(target);
    match severity {
        Health::Crit => inc.with_threshold(thr.crit),
        Health::Warn => inc.with_threshold(thr.warn),
        Health::Ok => inc,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use pretty_assertions::assert_eq;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap()
    }

    /// Config with a fast debounce and small windows for deterministic tests. Jitter
    /// thresholds are set out of reach so latency/loss tests are not perturbed by the
    /// jitter that large latency swings naturally produce; a dedicated test covers jitter.
    fn test_config() -> Config {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = None;
        c.thresholds.debounce_samples = 2;
        c.thresholds.loss_window = 4;
        c.thresholds.history_len = 16;
        c.thresholds.jitter = Thresholds::higher_is_worse(10_000.0, 20_000.0);
        c
    }

    fn latency(target: &str, rtt: f64) -> Sample {
        Sample::Latency {
            target: target.into(),
            rtt_ms: Some(rtt),
        }
    }
    fn timeout(target: &str) -> Sample {
        Sample::Latency {
            target: target.into(),
            rtt_ms: None,
        }
    }

    #[test]
    fn new_registers_configured_targets() {
        let mut c = test_config();
        c.targets.internet = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        c.targets.gateway = Some("192.168.1.1".into());
        let s = AppState::new(c);
        assert_eq!(s.targets.len(), 3);
        assert!(s.targets["192.168.1.1"].is_gateway);
        assert!(!s.targets["1.1.1.1"].is_gateway);
    }

    #[test]
    fn latency_sample_updates_history_and_loss() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), latency("1.1.1.1", 20.0));
        let t = &s.targets["1.1.1.1"];
        assert_eq!(t.latency_ms.latest(), Some(20.0));
        assert_eq!(t.loss.len(), 1);
    }

    #[test]
    fn loss_history_records_a_point_per_sample() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), latency("1.1.1.1", 20.0));
        s.apply_sample(now(), timeout("1.1.1.1"));
        s.apply_sample(now(), latency("1.1.1.1", 22.0));
        let t = &s.targets["1.1.1.1"];
        // One loss-% point per ping sample, so the panel can draw a line.
        assert_eq!(t.loss_history.len(), 3);
        // After 1 drop out of 3, the latest loss is ~33%.
        assert!((t.loss_history.latest().unwrap() - (100.0 / 3.0)).abs() < 1e-6);
    }

    #[test]
    fn timeout_records_loss_without_latency() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), timeout("1.1.1.1"));
        let t = &s.targets["1.1.1.1"];
        assert_eq!(t.latency_ms.latest(), None);
        assert_eq!(t.loss.len(), 1);
    }

    #[test]
    fn healthy_latency_produces_no_incidents() {
        let mut s = AppState::new(test_config());
        for _ in 0..5 {
            let inc = s.apply_sample(now(), latency("1.1.1.1", 12.0));
            assert!(inc.is_empty());
        }
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    #[test]
    fn single_spike_is_debounced_away() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), latency("1.1.1.1", 12.0));
        let inc = s.apply_sample(now(), latency("1.1.1.1", 400.0)); // one spike
        assert!(
            inc.is_empty(),
            "one spike should not commit with debounce 2"
        );
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    #[test]
    fn sustained_high_latency_emits_crit_incident() {
        let mut s = AppState::new(test_config());
        let first = s.apply_sample(now(), latency("1.1.1.1", 400.0));
        assert!(first.is_empty(), "not yet committed");
        let second = s.apply_sample(now(), latency("1.1.1.1", 410.0));
        assert_eq!(second.len(), 1);
        let inc = &second[0];
        assert_eq!(inc.metric, MetricId::Latency);
        assert_eq!(inc.severity, Health::Crit);
        assert_eq!(inc.target.as_deref(), Some("1.1.1.1"));
        assert_eq!(inc.value, Some(410.0));
        assert_eq!(inc.threshold, Some(150.0)); // crit boundary
        assert_eq!(s.panel_health(MetricId::Latency), Health::Crit);
        assert_eq!(s.events.len(), 1); // mirrored into the ring
    }

    #[test]
    fn latency_recovery_emits_ok_incident() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), latency("1.1.1.1", 400.0));
        s.apply_sample(now(), latency("1.1.1.1", 410.0)); // -> Crit
        s.apply_sample(now(), latency("1.1.1.1", 10.0));
        let rec = s.apply_sample(now(), latency("1.1.1.1", 11.0)); // -> Ok
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].severity, Health::Ok);
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    #[test]
    fn gateway_uses_stricter_thresholds() {
        let mut c = test_config();
        c.targets.gateway = Some("gw".into());
        let mut s = AppState::new(c);
        // 20ms is Ok for internet (<80) but Warn for the gateway (>=15).
        s.apply_sample(now(), latency("gw", 20.0));
        s.apply_sample(now(), latency("gw", 21.0));
        assert_eq!(s.targets["gw"].latency_health_current(), Health::Warn);
    }

    #[test]
    fn sustained_jitter_reddens_latency_panel() {
        let mut c = test_config();
        c.thresholds.jitter = Thresholds::higher_is_worse(15.0, 40.0); // normal jitter bounds
        let mut s = AppState::new(c);
        // Oscillate 10/60ms: each latency is Ok (<80) but the swing drives jitter ~50ms.
        s.apply_sample(now(), latency("1.1.1.1", 10.0));
        s.apply_sample(now(), latency("1.1.1.1", 60.0));
        let third = s.apply_sample(now(), latency("1.1.1.1", 10.0));
        let jitter: Vec<_> = third
            .iter()
            .filter(|i| i.metric == MetricId::Jitter)
            .collect();
        assert_eq!(jitter.len(), 1);
        assert_eq!(jitter[0].severity, Health::Crit);
        // The combined Latency & Jitter panel reflects the jitter problem...
        assert_eq!(s.panel_health(MetricId::Latency), Health::Crit);
        // ...even though latency alone is fine.
        assert_eq!(s.targets["1.1.1.1"].latency_health_current(), Health::Ok);
    }

    #[test]
    fn sustained_loss_emits_incident() {
        let mut s = AppState::new(test_config()); // loss_window 4 => 1 drop = 25% > crit 5%
        let a = s.apply_sample(now(), timeout("1.1.1.1"));
        assert!(a.is_empty());
        let b = s.apply_sample(now(), timeout("1.1.1.1"));
        assert_eq!(b.len(), 1);
        assert_eq!(b[0].metric, MetricId::Loss);
        assert_eq!(b[0].severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Loss), Health::Crit);
    }

    #[test]
    fn overall_health_is_worst_panel() {
        let mut s = AppState::new(test_config());
        s.apply_sample(now(), timeout("1.1.1.1"));
        s.apply_sample(now(), timeout("1.1.1.1")); // loss -> Crit
        assert_eq!(s.overall_health(), Health::Crit);
    }

    #[test]
    fn actions_mutate_flags() {
        let mut s = AppState::new(test_config());
        assert!(!s.paused);
        s.apply_action(Action::TogglePause);
        assert!(s.paused);
        s.apply_action(Action::TogglePause);
        assert!(!s.paused);

        s.events
            .push_front(Incident::new(now(), MetricId::Loss, Health::Crit, "x"));
        s.apply_action(Action::ClearEvents);
        assert!(s.events.is_empty());

        assert!(!s.should_quit);
        s.apply_action(Action::Quit);
        assert!(s.should_quit);
    }

    #[test]
    fn new_resolves_configured_theme() {
        let mut c = test_config();
        c.ui.theme = "cottage_fire".into();
        assert_eq!(AppState::new(c).theme, Theme::resolve("cottage_fire"));
    }

    #[test]
    fn new_falls_back_to_default_theme_for_unknown_name() {
        let mut c = test_config();
        c.ui.theme = "does_not_exist".into();
        assert_eq!(AppState::new(c).theme, Theme::default_theme());
    }

    #[test]
    fn cycle_theme_advances_and_wraps() {
        let mut s = AppState::new(test_config());
        assert_eq!(s.theme, Theme::default_theme());
        s.apply_action(Action::CycleTheme);
        assert_eq!(s.theme, Theme::default_theme().next());
        assert_ne!(s.theme, Theme::default_theme());
        // Cycling through the rest returns to the start.
        for _ in 1..Theme::NAMES.len() {
            s.apply_action(Action::CycleTheme);
        }
        assert_eq!(s.theme, Theme::default_theme());
    }

    #[test]
    fn dns_failure_emits_crit_incident() {
        let mut s = AppState::new(test_config());
        s.apply_sample(
            now(),
            Sample::Dns {
                resolver: "cloudflare".into(),
                latency_ms: None,
            },
        );
        let out = s.apply_sample(
            now(),
            Sample::Dns {
                resolver: "cloudflare".into(),
                latency_ms: None,
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metric, MetricId::Dns);
        assert_eq!(out[0].severity, Health::Crit);
        assert!(out[0].message.contains("failed"), "msg: {}", out[0].message);
        assert_eq!(s.panel_health(MetricId::Dns), Health::Crit);
    }

    #[test]
    fn dns_slow_lookup_warns_with_value() {
        let mut s = AppState::new(test_config()); // dns warn 100 / crit 300
        s.apply_sample(
            now(),
            Sample::Dns {
                resolver: "system".into(),
                latency_ms: Some(150.0),
            },
        );
        let out = s.apply_sample(
            now(),
            Sample::Dns {
                resolver: "system".into(),
                latency_ms: Some(160.0),
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(out[0].value, Some(160.0));
    }

    #[test]
    fn reachability_down_then_recovers() {
        let mut s = AppState::new(test_config());
        s.apply_sample(
            now(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: false,
            },
        );
        let down = s.apply_sample(
            now(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: false,
            },
        );
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Link), Health::Crit); // combined panel

        s.apply_sample(
            now(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        let up = s.apply_sample(
            now(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].severity, Health::Ok);
    }

    #[test]
    fn throughput_passive_fills_series_without_incident() {
        let mut s = AppState::new(test_config());
        let out = s.apply_sample(
            now(),
            Sample::Throughput {
                rx_bps: 1000.0,
                tx_bps: 200.0,
            },
        );
        assert!(out.is_empty());
        assert_eq!(s.throughput.rx_bps.as_ref().unwrap().latest(), Some(1000.0));
        assert_eq!(s.throughput.tx_bps.as_ref().unwrap().latest(), Some(200.0));
    }

    #[test]
    fn throughput_probe_below_floor_warns() {
        let mut c = test_config();
        c.throughput.floor_mbps = 100.0;
        let mut s = AppState::new(c);
        s.apply_sample(now(), Sample::ThroughputProbe { mbps: 50.0 });
        let out = s.apply_sample(now(), Sample::ThroughputProbe { mbps: 40.0 });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(out[0].value, Some(40.0));
        assert_eq!(s.throughput.last_mbps, Some(40.0));
    }

    #[test]
    fn link_weak_rssi_warns_and_keeps_ssid() {
        let mut s = AppState::new(test_config()); // rssi warn -70 / crit -80 (lower is worse)
        s.apply_sample(
            now(),
            Sample::Link {
                rssi_dbm: Some(-75.0),
                ssid: Some("MyNet".into()),
            },
        );
        let out = s.apply_sample(
            now(),
            Sample::Link {
                rssi_dbm: Some(-76.0),
                ssid: None,
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].metric, MetricId::Link);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(s.link.ssid.as_deref(), Some("MyNet"));
        assert_eq!(s.link.rssi_dbm, Some(-76.0));
    }

    #[test]
    fn routing_unreachable_is_crit() {
        let mut s = AppState::new(test_config());
        let r = Sample::Routing {
            target: "1.1.1.1".into(),
            hops: 0,
            reachable: false,
            changed: false,
        };
        s.apply_sample(now(), r.clone());
        let out = s.apply_sample(now(), r);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Routing), Health::Crit);
    }

    #[test]
    fn routing_change_warns() {
        let mut s = AppState::new(test_config());
        s.apply_sample(
            now(),
            Sample::Routing {
                target: "t".into(),
                hops: 8,
                reachable: true,
                changed: true,
            },
        );
        let out = s.apply_sample(
            now(),
            Sample::Routing {
                target: "t".into(),
                hops: 9,
                reachable: true,
                changed: true,
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
    }

    #[test]
    fn events_ring_is_capped() {
        let mut s = AppState::new(test_config());
        s.max_events = 3;
        for _ in 0..10 {
            // alternate crit/ok on loss to keep generating transitions
            s.apply_sample(now(), timeout("1.1.1.1"));
            s.apply_sample(now(), timeout("1.1.1.1"));
            s.apply_sample(now(), latency("1.1.1.1", 5.0));
            s.apply_sample(now(), latency("1.1.1.1", 5.0));
        }
        assert!(
            s.events.len() <= 3,
            "events ring exceeded cap: {}",
            s.events.len()
        );
    }
}
