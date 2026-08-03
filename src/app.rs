//! Application state and the pure reducer.
//!
//! [`AppState`] owns all dashboard state. [`AppState::apply_sample`] folds a probe
//! [`Sample`] in — updating history, re-evaluating debounced health, and emitting an
//! [`Incident`] on any confirmed transition. [`AppState::apply_action`] handles control
//! input. Everything here is pure and synchronous: the caller supplies the timestamp, so
//! the reducer is fully deterministic and testable without a clock, network, or terminal.

use std::collections::{BTreeMap, VecDeque};

use chrono::{DateTime, Timelike, Utc};

use crate::config::{AlertConfig, Config};
use crate::diagnosis::Layer;
use crate::health::{Debouncer, FlapDetector, Health, Thresholds};
use crate::history::{LossWindow, RingBuffer, Series};
use crate::incidents::Incident;
use crate::metrics::{Hop, MetricId, Sample};
use crate::ui::theme::Theme;

/// Control actions (mapped from key input by the event loop).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    Quit,
    TogglePause,
    ClearEvents,
    ForceRefresh,
    /// Open the theme picker overlay (browse + live-preview themes).
    OpenThemePicker,
    /// Move the picker selection to the previous/next theme, live-previewing it.
    ThemePreviewUp,
    ThemePreviewDown,
    /// Keep the previewed theme and close the picker.
    ThemePickerConfirm,
    /// Revert to the theme active before opening and close the picker.
    ThemePickerCancel,
    /// Toggle the keybinding help overlay.
    ToggleHelp,
    /// Scroll the events feed toward older / newer incidents.
    ScrollUp,
    ScrollDown,
    ScrollPageUp,
    ScrollPageDown,
}

/// Per-ping-target rolling state and debounced health streams.
#[derive(Debug, Clone)]
pub struct TargetState {
    pub is_gateway: bool,
    /// The address this target was registered under. Kept so the state can answer questions
    /// about itself (family, display label) without the caller re-deriving them from the
    /// map key it happens to be filed under.
    addr: String,
    pub latency_ms: Series,
    pub loss: LossWindow,
    /// Rolling history of the loss-window percentage, for the loss line graph.
    pub loss_history: Series,
    latency_health: Debouncer,
    jitter_health: Debouncer,
    loss_health: Debouncer,
}

impl TargetState {
    fn new(addr: String, is_gateway: bool, cfg: &Config) -> Self {
        let t = &cfg.thresholds;
        Self {
            is_gateway,
            addr,
            latency_ms: Series::new(t.history_len),
            loss: LossWindow::new(t.loss_window),
            loss_history: Series::new(t.history_len),
            latency_health: Debouncer::new(Health::Ok, t.trip_after(), t.clear_after()),
            jitter_health: Debouncer::new(Health::Ok, t.trip_after(), t.clear_after()),
            loss_health: Debouncer::new(Health::Ok, t.trip_after(), t.clear_after()),
        }
    }

    /// Whether this target is pinged over IPv6.
    pub fn is_ipv6(&self) -> bool {
        self.addr
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_ipv6())
    }

    /// The address, shortened if it cannot fit the panel's 15-wide name column.
    ///
    /// v6 literals routinely run past 20 characters, and the middle groups are the part
    /// nobody reads: the prefix says whose network it is and the last group says which host.
    /// Elided from the middle so both ends survive.
    pub fn label(&self) -> String {
        const WIDTH: usize = 15;
        if self.addr.chars().count() <= WIDTH {
            return self.addr.clone();
        }
        match (self.addr.split_once(':'), self.addr.rsplit_once(':')) {
            (Some((head, _)), Some((_, tail))) => format!("{head}:…:{tail}"),
            // Not a v6 literal (a long hostname, say) — truncate from the right, where the
            // distinguishing part of a name usually isn't.
            _ => self.addr.chars().take(WIDTH - 1).chain(['…']).collect(),
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
    /// Whether this resolver was last seen answering for names it does not own.
    pub hijacked: bool,
    pub latency_ms: Series,
    pub last_ok: bool,
    health: Debouncer,
    /// Honesty, debounced apart from timing: the two are different faults, and a resolver
    /// that answers quickly and wrongly must not have its speed excuse its answers.
    integrity_health: Debouncer,
}

impl ResolverState {
    fn new(cfg: &Config) -> Self {
        let t = &cfg.thresholds;
        Self {
            hijacked: false,
            latency_ms: Series::new(t.history_len),
            last_ok: true,
            health: Debouncer::new(Health::Ok, t.trip_after(), t.clear_after()),
            integrity_health: Debouncer::new(Health::Ok, t.trip_after(), t.clear_after()),
        }
    }

    /// Current debounced health of this resolver (read by the diagnosis engine).
    pub fn health_current(&self) -> Health {
        self.health.current()
    }

    /// Current debounced integrity verdict.
    pub fn integrity_health_current(&self) -> Health {
        self.integrity_health.current()
    }
}

/// Per-endpoint reachability state.
#[derive(Debug, Clone)]
pub struct ReachState {
    pub ok: bool,
    health: Debouncer,
}

/// Per-endpoint TCP handshake state.
///
/// Separate from [`ReachState`] even though both ask "does this endpoint answer": reachability
/// is a yes/no over HTTP, this is a *timing* below it, and a handshake that succeeds slowly is
/// exactly the case the boolean cannot express.
#[derive(Debug, Clone)]
pub struct TcpState {
    pub connect_ms: Series,
    /// Whether the last handshake completed at all.
    pub last_ok: bool,
    health: Debouncer,
}

impl TcpState {
    /// Current debounced handshake health for this endpoint.
    pub fn health_current(&self) -> Health {
        self.health.current()
    }
}

/// Per-endpoint TLS state: how long negotiation takes, and how long the certificate has
/// left.
///
/// The two live together because one handshake produces both, but they are judged apart:
/// a certificate three days from expiry is not slow, is not down, and would be invisible
/// to any timing threshold right up until the morning it takes the site off the air.
#[derive(Debug, Clone)]
pub struct TlsState {
    pub handshake_ms: Series,
    /// Days of validity left on the leaf certificate, negative once it has expired.
    /// Retained across a failed handshake — no reading is not the same as no time left.
    pub expires_in_days: Option<i64>,
    /// Whether the last negotiation completed at all.
    pub last_ok: bool,
    health: Debouncer,
    expiry_health: Debouncer,
}

impl TlsState {
    fn new(cfg: &Config) -> Self {
        let (trip, clear) = (cfg.thresholds.trip_after(), cfg.thresholds.clear_after());
        Self {
            handshake_ms: Series::new(cfg.thresholds.history_len),
            expires_in_days: None,
            last_ok: true,
            health: Debouncer::new(Health::Ok, trip, clear),
            expiry_health: Debouncer::new(Health::Ok, trip, clear),
        }
    }

    /// Current debounced negotiation-timing health for this endpoint.
    pub fn health_current(&self) -> Health {
        self.health.current()
    }

    /// Current debounced certificate-expiry health for this endpoint.
    pub fn expiry_health_current(&self) -> Health {
        self.expiry_health.current()
    }
}

/// Throughput state: passive rx/tx history, the last capacity-probe result, and the last
/// bufferbloat (latency idle-vs-loaded) reading.
#[derive(Debug, Clone, Default)]
pub struct ThroughputState {
    pub rx_bps: Option<Series>,
    pub tx_bps: Option<Series>,
    pub last_mbps: Option<f64>,
    /// Capacity-probe results over time. Kept apart from `rx_bps`/`tx_bps` because the
    /// probe runs on a minutes-long cadence and cannot share their per-second axis.
    pub capacity_mbps: Option<Series>,
    pub idle_latency_ms: Option<f64>,
    pub loaded_latency_ms: Option<f64>,
    /// Latency added under load, per bufferbloat measurement. History because bloat is
    /// usually intermittent — the latest reading routinely misses it.
    pub added_latency_ms: Option<Series>,
    health: Option<Debouncer>,
    bufferbloat_health: Option<Debouncer>,
}

impl ThroughputState {
    /// Current debounced bufferbloat health (read by the diagnosis engine).
    pub fn bufferbloat_health_current(&self) -> Health {
        self.bufferbloat_health
            .as_ref()
            .map_or(Health::Ok, |d| d.current())
    }
}

/// Wireless link state.
#[derive(Debug, Clone, Default)]
pub struct LinkState {
    pub rssi_dbm: Option<f64>,
    pub noise_dbm: Option<f64>,
    pub tx_rate: Option<f64>,
    pub ssid: Option<String>,
    /// Signal and noise floor over time, in dBm. A radio decaying over ten minutes looks
    /// entirely plausible at every individual reading; only the trend gives it away.
    pub rssi_history: Option<Series>,
    pub noise_history: Option<Series>,
    health: Option<Debouncer>,
}

/// Local NIC error counters, as of the last reading.
///
/// `None` until the first sample lands: "no interface probe has run yet" and "the NIC is
/// clean" look identical as a zero, and only one of them is worth putting on screen.
#[derive(Debug, Clone, Default)]
pub struct InterfaceState {
    pub rx_errors: Option<u64>,
    pub tx_errors: Option<u64>,
    /// Total errors per interval over time. Errors usually arrive in bursts, so the trend
    /// distinguishes "one bad moment" from "this cable is failing".
    pub history: Option<Series>,
    health: Option<Debouncer>,
}

impl InterfaceState {
    /// Committed NIC-error health (`Ok` before the first reading).
    pub fn health_current(&self) -> Health {
        self.health.as_ref().map_or(Health::Ok, |d| d.current())
    }
}

/// Routing/path state for the routing target.
#[derive(Debug, Clone, Default)]
pub struct RoutingState {
    pub hops: usize,
    pub reachable: bool,
    pub changed: bool,
    pub seen: bool,
    /// Per-hop detail from the last traceroute (address, best RTT, probe loss).
    pub detail: Vec<Hop>,
    health: Option<Debouncer>,
}

/// Minutes of history the availability strip retains — about one cell per column on the
/// target 222-wide terminal, i.e. a little under four hours at a glance.
pub const AVAILABILITY_MINUTES: usize = 220;

/// Minute counts behind the availability strip's headline.
///
/// `unknown` minutes are excluded from `uptime_pct` on purpose: the dashboard cannot
/// vouch for time it was not running, and counting it either way would be a guess.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AvailabilityRollup {
    pub ok: usize,
    pub degraded: usize,
    pub down: usize,
    pub unknown: usize,
    pub uptime_pct: f64,
}

/// Live state of the theme-picker overlay (open only while `Some`).
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ThemePicker {
    /// Index into [`Theme::NAMES`] of the highlighted (live-previewed) theme.
    pub index: usize,
    /// Theme active before the picker opened, restored on cancel.
    original: Theme,
}

/// All dashboard state.
#[derive(Debug, Clone)]
pub struct AppState {
    pub config: Config,
    /// Active color theme, resolved from `config.ui.theme` and chosen via the theme picker
    /// ([`Action::OpenThemePicker`]).
    pub theme: Theme,
    pub targets: BTreeMap<String, TargetState>,
    pub resolvers: BTreeMap<String, ResolverState>,
    pub reachability: BTreeMap<String, ReachState>,
    /// Per-endpoint TCP handshake timings.
    pub tcp: BTreeMap<String, TcpState>,
    /// Per-endpoint TLS negotiation timing and certificate expiry.
    pub tls: BTreeMap<String, TlsState>,
    pub throughput: ThroughputState,
    pub link: LinkState,
    /// Local NIC error counters — the only signal that points at your own hardware.
    pub iface: InterfaceState,
    pub routing: RoutingState,
    /// Whether a captive portal is currently intercepting web traffic.
    pub captive_portal: bool,
    /// Debounce for the captive-portal verdict, so one intercepted request can't put
    /// "sign-in required" on screen. Lazily built to pick up config at first sample.
    captive_health: Option<Debouncer>,
    /// Public/WAN IP (from the public-IP probe), for ISP/WAN-change detection.
    pub public_ip: Option<String>,
    /// Default-route interface, its MTU, and whether it runs over a VPN.
    pub interface: Option<String>,
    pub mtu: Option<u32>,
    pub vpn: bool,
    pub events: VecDeque<Incident>,
    pub max_events: usize,
    /// Instability bookkeeping, one entry per (metric, target) that has ever transitioned.
    /// A `BTreeMap` rather than a hash map so the settle incidents a single fold emits come
    /// out in the same order every run.
    flaps: BTreeMap<(MetricId, String), FlapState>,
    /// When each (metric, target, severity) was last reported, for the dedup cooldown.
    recent_alerts: BTreeMap<(MetricId, String, Health), DateTime<Utc>>,
    /// First incident-log write failure, kept so the header can say the on-disk history is
    /// no longer being recorded. `None` means the log is healthy (or was never opened).
    pub log_error: Option<String>,
    /// One bucket per wall-clock minute holding the worst health observed in it, oldest
    /// first. `None` means the minute was never observed (the process was down or asleep).
    pub availability: RingBuffer<(DateTime<Utc>, Option<Health>)>,
    /// How many newest incidents are scrolled past in the events feed.
    pub events_scroll: usize,
    /// Whether the keybinding help overlay is showing.
    pub show_help: bool,
    /// The theme picker overlay state, `Some` while open.
    pub theme_picker: Option<ThemePicker>,
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
            tcp: BTreeMap::new(),
            tls: BTreeMap::new(),
            throughput: ThroughputState::default(),
            link: LinkState::default(),
            iface: InterfaceState::default(),
            routing: RoutingState::default(),
            captive_portal: false,
            captive_health: None,
            public_ip: None,
            interface: None,
            mtu: None,
            vpn: false,
            events: VecDeque::new(),
            max_events: 200,
            flaps: BTreeMap::new(),
            recent_alerts: BTreeMap::new(),
            log_error: None,
            availability: RingBuffer::new(AVAILABILITY_MINUTES),
            events_scroll: 0,
            show_help: false,
            theme_picker: None,
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
        let addr = addr.into();
        self.targets
            .entry(addr.clone())
            .or_insert_with(|| TargetState::new(addr, is_gateway, &cfg))
            .is_gateway = is_gateway;
    }

    /// Drop every ping target not in `keep`.
    ///
    /// Called once the ping probe has decided what it can actually reach — on a v4-only host
    /// the configured IPv6 targets are never pinged, and a target with no samples renders as
    /// a flawless `0ms / 0% loss`. Silence that reads as perfect health is worse than no row
    /// at all.
    pub fn retain_targets(&mut self, keep: &[String]) {
        self.targets.retain(|name, _| keep.contains(name));
    }

    /// Fold one sample into state, returning any incidents produced by the update. Emitted
    /// incidents are also appended to the in-memory `events` ring.
    pub fn apply_sample(&mut self, now: DateTime<Utc>, sample: Sample) -> Vec<Incident> {
        let mut incidents = match sample {
            Sample::Latency { target, rtt_ms } => self.apply_latency(now, &target, rtt_ms),
            Sample::Dns {
                resolver,
                latency_ms,
            } => self.apply_dns(now, &resolver, latency_ms),
            Sample::DnsIntegrity { resolver, hijacked } => {
                self.apply_dns_integrity(now, &resolver, hijacked)
            }
            Sample::TcpHandshake {
                endpoint,
                connect_ms,
            } => self.apply_tcp_handshake(now, &endpoint, connect_ms),
            Sample::Tls {
                endpoint,
                handshake_ms,
                expires_in_days,
            } => self.apply_tls(now, &endpoint, handshake_ms, expires_in_days),
            Sample::Reachability { endpoint, ok } => self.apply_reachability(now, &endpoint, ok),
            Sample::CaptivePortal { detected } => self.apply_captive(now, detected),
            Sample::PublicIp { ip } => self.apply_public_ip(now, ip),
            Sample::Throughput { rx_bps, tx_bps } => {
                self.apply_throughput(rx_bps, tx_bps);
                Vec::new()
            }
            Sample::ThroughputProbe { mbps } => self.apply_throughput_probe(now, mbps),
            Sample::Bufferbloat { idle_ms, loaded_ms } => {
                self.apply_bufferbloat(now, idle_ms, loaded_ms)
            }
            Sample::InterfaceErrors {
                rx_errors,
                tx_errors,
            } => self.apply_interface_errors(now, rx_errors, tx_errors),
            Sample::Link {
                rssi_dbm,
                noise_dbm,
                tx_rate,
                ssid,
            } => self.apply_link(now, rssi_dbm, noise_dbm, tx_rate, ssid),
            Sample::Routing {
                target,
                hops,
                reachable,
                changed,
                detail,
            } => self.apply_routing(now, &target, hops, reachable, changed, detail),
        };
        self.attribute(&mut incidents);
        let incidents = self.filter_noise(now, incidents);
        for inc in &incidents {
            self.push_event(inc.clone());
        }
        // After the fold, so the minute reflects the sample just applied. Ticking here as
        // well as from the render loop keeps the strip alive on headless paths, where
        // nothing ever renders.
        self.tick(now);
        incidents
    }

    /// Tag each newly-raised incident with the upstream layer that already accounts for it.
    ///
    /// Runs *after* the handler has folded the sample in, so the attribution reflects the
    /// state the incident was born into rather than the one before it. Nothing is dropped —
    /// the tag only tells the UI to render the echo quietly (see [`Incident::cause`]).
    ///
    /// Recoveries are left alone: a metric coming back is its own news whatever else is
    /// still broken, and dimming it would hide the one line that says things are improving.
    fn attribute(&self, incidents: &mut [Incident]) {
        if !incidents.iter().any(|i| i.severity > Health::Ok) {
            return;
        }
        // One diagnose() per fold that raised something, never one per incident: the ruleset
        // walks every target and resolver, and nothing about it moves between two incidents
        // out of the same sample.
        let Some(primary) = crate::diagnosis::primary_layer(self) else {
            return;
        };
        for inc in incidents.iter_mut().filter(|i| i.severity > Health::Ok) {
            if self
                .incident_layer(inc)
                .is_some_and(|l| primary.explains(l))
            {
                inc.cause = Some(primary);
            }
        }
    }

    /// Collapse the noise out of a fold's incidents before they reach the feed and the log.
    ///
    /// Two independent mechanisms, deliberately kept apart because they answer different
    /// questions at different ranges. Flap detection is long-range and about *a metric*: once
    /// one has swung too often it stops reporting the swings and reports the instability
    /// instead. Dedup is short-range and about *an alert*: the identical line, twice, inside a
    /// few seconds, is once.
    ///
    /// Correlated incidents are deliberately left in — [`attribute`](Self::attribute) already
    /// decided the right treatment for those is to dim them, not to drop them.
    fn filter_noise(&mut self, now: DateTime<Utc>, incidents: Vec<Incident>) -> Vec<Incident> {
        let alerts = self.config.alerts.clone();
        let mut out = Vec::new();

        // Age out swings across *every* tracked metric, not just the one this fold touched:
        // settling happens through the passage of time, and a metric that has gone quiet has
        // no samples of its own left to notice it with.
        for (key, st) in self.flaps.iter_mut() {
            if st.detector.observe(now, false) == Some(false) {
                out.push(settle_incident(now, key, st.last_suppressed.take()));
            }
        }

        for inc in incidents {
            let key = (inc.metric, inc.target.clone().unwrap_or_default());
            let st = self
                .flaps
                .entry(key.clone())
                .or_insert_with(|| FlapState::new(&alerts));
            match st.detector.observe(now, true) {
                Some(true) => out.push(flapping_incident(now, &key, &st.detector, &alerts)),
                _ if st.detector.is_flapping() => {
                    // Held back, not discarded: when the metric settles this is what says
                    // where it actually ended up.
                    st.last_suppressed = Some(inc);
                }
                _ => out.push(inc),
            }
        }

        let cooldown = alerts.dedup_window();
        out.retain(|inc| {
            let key = (
                inc.metric,
                inc.target.clone().unwrap_or_default(),
                inc.severity,
            );
            match self.recent_alerts.get(&key) {
                // `last <= now` guards a clock corrected backwards, which would otherwise
                // leave a future timestamp suppressing the metric until it caught up.
                Some(&last) if last <= now && now.signed_duration_since(last) < cooldown => false,
                _ => {
                    self.recent_alerts.insert(key, now);
                    true
                }
            }
        });
        // An entry older than the cooldown can never suppress anything again, so the table
        // stays bounded by the number of metrics alerting inside one window.
        self.recent_alerts
            .retain(|_, t| *t <= now && now.signed_duration_since(*t) < cooldown);
        out
    }

    /// Which segment of the path an incident is a symptom of.
    ///
    /// Ping metrics against a non-gateway target map to the ISP rather than to
    /// [`Layer::Remote`], even though a single bad host is a remote problem: those pings are
    /// the *evidence* for an ISP verdict, and an incident must never be dimmed by the
    /// conclusion it produced. `None` leaves the incident uncorrelated.
    fn incident_layer(&self, inc: &Incident) -> Option<Layer> {
        match inc.metric {
            MetricId::Latency | MetricId::Loss | MetricId::Jitter => {
                let gateway = inc
                    .target
                    .as_ref()
                    .and_then(|t| self.targets.get(t))
                    .is_some_and(|t| t.is_gateway);
                Some(if gateway { Layer::Gateway } else { Layer::Isp })
            }
            // The NIC is upstream of everything, including the radio: a card dropping
            // frames breaks the Wi-Fi link rather than the other way round.
            MetricId::InterfaceErrors => Some(Layer::Nic),
            MetricId::Link => Some(Layer::Wifi),
            // Same layer as reachability: both are end-to-end checks against a remote
            // service, and both are evidence for an ISP verdict rather than consequences
            // of one.
            MetricId::TcpHandshake
            | MetricId::TlsHandshake
            | MetricId::Reachability
            | MetricId::Routing
            | MetricId::Throughput
            | MetricId::Bufferbloat
            // A portal and a WAN address both localize to the ISP, which is also where
            // `diagnose` puts them — so neither can be dimmed by the verdict it fed.
            | MetricId::CaptivePortal
            | MetricId::PublicIp => Some(Layer::Isp),
            MetricId::Dns => Some(Layer::Dns),
            // A certificate running out is not a fault anywhere on the path — every layer
            // is working perfectly and the date is still coming. Correlating it would let
            // an unrelated ISP verdict dim the one warning nothing else will repeat.
            MetricId::CertExpiry => None,
            // The dashboard complaining about its own log has no place on the network.
            MetricId::Log => None,
        }
    }

    /// Advance the availability strip to `now`.
    ///
    /// Called from both the reducer and the render loop: samples alone would leave the
    /// strip frozen during a total outage (no samples arrive to fold), and renders alone
    /// would leave it empty under `--once`. Idempotent within a minute, so calling it at
    /// the render rate costs nothing but a worst-of merge.
    pub fn tick(&mut self, now: DateTime<Utc>) {
        let Some(bucket) = now.with_second(0).and_then(|t| t.with_nanosecond(0)) else {
            return;
        };
        let health = self.overall_health();
        match self.availability.latest().copied() {
            // Same minute (or a clock that stepped backwards): merge, never regress.
            Some((last, _)) if last >= bucket => {
                if let Some((_, h)) = self.availability.latest_mut() {
                    let merged = h.map_or(health, |prev| prev.worst(health));
                    *h = Some(merged);
                }
            }
            Some((last, _)) => {
                // Minutes nobody observed are unknown, not healthy — back-filling `Ok`
                // would invent uptime across a laptop sleep. Bounded by the strip length so
                // waking after a week is one full strip, not ten thousand pushes.
                let missing = (bucket - last)
                    .num_minutes()
                    .saturating_sub(1)
                    .clamp(0, AVAILABILITY_MINUTES as i64);
                for k in 0..missing {
                    let ts = bucket - chrono::Duration::minutes(missing - k);
                    self.availability.push((ts, None));
                }
                self.availability.push((bucket, Some(health)));
            }
            None => self.availability.push((bucket, Some(health))),
        }
    }

    /// Summarize the availability strip for the panel headline.
    pub fn availability_rollup(&self) -> AvailabilityRollup {
        let mut r = AvailabilityRollup {
            ok: 0,
            degraded: 0,
            down: 0,
            unknown: 0,
            uptime_pct: 100.0,
        };
        for (_, h) in self.availability.iter() {
            match h {
                Some(Health::Ok) => r.ok += 1,
                Some(Health::Warn) => r.degraded += 1,
                Some(Health::Crit) => r.down += 1,
                None => r.unknown += 1,
            }
        }
        let known = r.ok + r.degraded + r.down;
        if known > 0 {
            r.uptime_pct = 100.0 * r.ok as f64 / known as f64;
        }
        r
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
        // A timed-out ping is a latency failure in its own right: evaluating the *stale*
        // last-good RTT would keep reporting "healthy" straight through a total outage.
        let lat_thr = *t.latency_thresholds(&cfg);
        match rtt_ms {
            Some(rtt) => {
                let raw = lat_thr.evaluate(rtt);
                if let Some(sev) = t.latency_health.update(now, raw) {
                    out.push(incident_for(
                        now,
                        MetricId::Latency,
                        target,
                        sev,
                        rtt,
                        "ms",
                        &lat_thr,
                    ));
                }
            }
            None => {
                if let Some(sev) = t.latency_health.update(now, Health::Crit) {
                    out.push(status_incident(
                        now,
                        MetricId::Latency,
                        target,
                        sev,
                        format!("latency probe timed out ({target})"),
                    ));
                }
            }
        }

        // Jitter (shares the Latency panel).
        let jit_thr = cfg.thresholds.jitter;
        if let Some(jitter) = t.latency_ms.jitter() {
            let raw = jit_thr.evaluate(jitter);
            if let Some(sev) = t.jitter_health.update(now, raw) {
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
        if let Some(sev) = t.loss_health.update(now, raw) {
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
            .or_insert_with(|| ResolverState::new(&cfg));
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
        match state.health.update(now, raw) {
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

    fn apply_tcp_handshake(
        &mut self,
        now: DateTime<Utc>,
        endpoint: &str,
        connect_ms: Option<f64>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let thr = cfg.thresholds.tcp_handshake;
        let state = self
            .tcp
            .entry(endpoint.to_string())
            .or_insert_with(|| TcpState {
                connect_ms: Series::new(cfg.thresholds.history_len),
                last_ok: true,
                health: Debouncer::new(
                    Health::Ok,
                    cfg.thresholds.trip_after(),
                    cfg.thresholds.clear_after(),
                ),
            });
        let raw = match connect_ms {
            Some(ms) => {
                state.connect_ms.push(ms);
                state.last_ok = true;
                thr.evaluate(ms)
            }
            None => {
                // Deliberately nothing pushed: a refusal has no duration, and recording it as
                // a zero would drag the rolling average down at exactly the moment the panel
                // needs to look worse, not better.
                state.last_ok = false;
                Health::Crit
            }
        };
        let last_ok = state.last_ok;
        let latest = state.connect_ms.latest().unwrap_or(0.0);
        match state.health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::TcpHandshake,
                endpoint,
                Health::Ok,
                format!("tcp handshake recovered ({endpoint})"),
            )],
            Some(sev) if !last_ok => vec![status_incident(
                now,
                MetricId::TcpHandshake,
                endpoint,
                sev,
                format!("tcp connect refused ({endpoint})"),
            )],
            Some(sev) => vec![incident_for(
                now,
                MetricId::TcpHandshake,
                endpoint,
                sev,
                latest,
                "ms",
                &thr,
            )],
            None => Vec::new(),
        }
    }

    /// Fold one TLS reading: negotiation time and certificate expiry, judged separately.
    ///
    /// Two debouncers because they are two faults with two fixes — a slow handshake is the
    /// network's problem and an expiring certificate is the operator's — and folding them
    /// would let a fast negotiation vouch for a certificate that is about to expire.
    fn apply_tls(
        &mut self,
        now: DateTime<Utc>,
        endpoint: &str,
        handshake_ms: Option<f64>,
        expires_in_days: Option<i64>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let state = self
            .tls
            .entry(endpoint.to_string())
            .or_insert_with(|| TlsState::new(&cfg));
        let raw = match handshake_ms {
            Some(ms) => {
                state.handshake_ms.push(ms);
                state.last_ok = true;
                cfg.thresholds.tls_handshake.evaluate(ms)
            }
            None => {
                // As with TCP: a negotiation that never finished has no duration, and a zero
                // would flatter the average precisely when the panel should look worse.
                state.last_ok = false;
                Health::Crit
            }
        };
        // Only advance the expiry verdict when there is a reading. A failed handshake says
        // nothing about the date on the certificate, and feeding it `Ok` would quietly
        // retract a warning that is still true.
        if let Some(days) = expires_in_days {
            state.expires_in_days = Some(days);
        }
        let mut out = self.tls_timing_incident(now, endpoint, raw);
        if let Some(days) = expires_in_days {
            out.extend(self.tls_expiry_incident(now, endpoint, days));
        }
        out
    }

    fn tls_timing_incident(
        &mut self,
        now: DateTime<Utc>,
        endpoint: &str,
        raw: Health,
    ) -> Vec<Incident> {
        let thr = self.config.thresholds.tls_handshake;
        let Some(state) = self.tls.get_mut(endpoint) else {
            return Vec::new();
        };
        let last_ok = state.last_ok;
        let latest = state.handshake_ms.latest().unwrap_or(0.0);
        match state.health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::TlsHandshake,
                endpoint,
                Health::Ok,
                format!("tls handshake recovered ({endpoint})"),
            )],
            Some(sev) if !last_ok => vec![status_incident(
                now,
                MetricId::TlsHandshake,
                endpoint,
                sev,
                format!("tls handshake failed ({endpoint})"),
            )],
            Some(sev) => vec![incident_for(
                now,
                MetricId::TlsHandshake,
                endpoint,
                sev,
                latest,
                "ms",
                &thr,
            )],
            None => Vec::new(),
        }
    }

    fn tls_expiry_incident(
        &mut self,
        now: DateTime<Utc>,
        endpoint: &str,
        days: i64,
    ) -> Vec<Incident> {
        let thr = self.config.thresholds.cert_expiry_days;
        let Some(state) = self.tls.get_mut(endpoint) else {
            return Vec::new();
        };
        let raw = thr.evaluate(days as f64);
        match state.expiry_health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::CertExpiry,
                endpoint,
                Health::Ok,
                format!("certificate renewed, {days}d left ({endpoint})"),
            )],
            // Spelled out rather than left to `incident_for`, which would render an expired
            // certificate as "cert expiry -2d" — a number nobody should have to decode.
            Some(sev) => {
                let message = if days < 0 {
                    format!("certificate expired {}d ago ({endpoint})", -days)
                } else {
                    format!("certificate expires in {days}d ({endpoint})")
                };
                let threshold = if sev == Health::Crit {
                    thr.crit
                } else {
                    thr.warn
                };
                vec![
                    Incident::new(now, MetricId::CertExpiry, sev, message)
                        .with_value(days as f64, "d")
                        .with_target(endpoint)
                        .with_threshold(threshold),
                ]
            }
            None => Vec::new(),
        }
    }

    /// Fold a DNS-honesty verdict, kept on its own debouncer.
    ///
    /// Separate from the timing verdict because they are different faults with different
    /// fixes — a hijacking resolver is usually fast, and swapping resolvers fixes the one
    /// but not the other. Both feed the DNS panel, so the border still reflects the worse.
    fn apply_dns_integrity(
        &mut self,
        now: DateTime<Utc>,
        resolver: &str,
        hijacked: bool,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let state = self
            .resolvers
            .entry(resolver.to_string())
            .or_insert_with(|| ResolverState::new(&cfg));
        state.hijacked = hijacked;
        // Warn, never Crit: the resolver is answering and names still resolve. What is wrong
        // is who is answering, which is worth knowing and is not an outage.
        let raw = if hijacked { Health::Warn } else { Health::Ok };
        match state.integrity_health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::Dns,
                resolver,
                Health::Ok,
                format!("dns answers are the resolver's own again ({resolver})"),
            )],
            Some(sev) => vec![status_incident(
                now,
                MetricId::Dns,
                resolver,
                sev,
                format!("dns integrity: {resolver} answers for names it does not own"),
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
                health: Debouncer::new(
                    Health::Ok,
                    cfg.thresholds.trip_after(),
                    cfg.thresholds.clear_after(),
                ),
            });
        state.ok = ok;
        let raw = if ok { Health::Ok } else { Health::Crit };
        match state.health.update(now, raw) {
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

    /// Record default-route facts (interface, MTU, VPN) detected at startup.
    pub fn apply_route_info(&mut self, info: &crate::net::RouteInfo) {
        if info.interface.is_some() {
            self.interface = info.interface.clone();
        }
        if info.mtu.is_some() {
            self.mtu = info.mtu;
        }
        self.vpn = info.is_vpn();
    }

    fn apply_public_ip(&mut self, now: DateTime<Utc>, ip: String) -> Vec<Incident> {
        let out = match &self.public_ip {
            Some(old) if *old != ip => vec![status_incident(
                now,
                MetricId::PublicIp,
                "wan",
                Health::Warn,
                format!("public IP changed {old} → {ip}"),
            )],
            _ => Vec::new(), // first observation or unchanged — no incident
        };
        self.public_ip = Some(ip);
        out
    }

    fn apply_bufferbloat(
        &mut self,
        now: DateTime<Utc>,
        idle_ms: f64,
        loaded_ms: f64,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        self.throughput.idle_latency_ms = Some(idle_ms);
        self.throughput.loaded_latency_ms = Some(loaded_ms);
        let delta = (loaded_ms - idle_ms).max(0.0);
        self.throughput
            .added_latency_ms
            .get_or_insert_with(|| Series::new(cfg.thresholds.history_len))
            .push(delta);
        let thr = cfg.thresholds.bufferbloat;
        let raw = thr.evaluate(delta);
        let health = self.throughput.bufferbloat_health.get_or_insert_with(|| {
            Debouncer::new(
                Health::Ok,
                cfg.thresholds.trip_after(),
                cfg.thresholds.clear_after(),
            )
        });
        match health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::Bufferbloat,
                "bufferbloat",
                Health::Ok,
                "bufferbloat cleared".to_string(),
            )],
            Some(sev) => {
                let inc = Incident::new(
                    now,
                    MetricId::Bufferbloat,
                    sev,
                    format!("bufferbloat +{delta:.0}ms under load"),
                )
                .with_value(delta, "ms")
                .with_target("bufferbloat");
                vec![match sev {
                    Health::Crit => inc.with_threshold(thr.crit),
                    _ => inc.with_threshold(thr.warn),
                }]
            }
            None => Vec::new(),
        }
    }

    fn apply_interface_errors(
        &mut self,
        now: DateTime<Utc>,
        rx_errors: u64,
        tx_errors: u64,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        self.iface.rx_errors = Some(rx_errors);
        self.iface.tx_errors = Some(tx_errors);
        let total = (rx_errors + tx_errors) as f64;
        self.iface
            .history
            .get_or_insert_with(|| Series::new(cfg.thresholds.history_len))
            .push(total);
        let thr = cfg.thresholds.interface_errors;
        let raw = thr.evaluate(total);
        let health = self.iface.health.get_or_insert_with(|| {
            Debouncer::new(
                Health::Ok,
                cfg.thresholds.trip_after(),
                cfg.thresholds.clear_after(),
            )
        });
        match health.update(now, raw) {
            Some(Health::Ok) => vec![status_incident(
                now,
                MetricId::InterfaceErrors,
                "nic",
                Health::Ok,
                "interface errors cleared".to_string(),
            )],
            Some(sev) => {
                // Both directions named even when one is zero: inbound errors point at the
                // cable, the port or the radio, outbound ones at the driver or the card, and
                // the split is the whole diagnostic value of the number.
                let inc = Incident::new(
                    now,
                    MetricId::InterfaceErrors,
                    sev,
                    format!("interface errors: {rx_errors} rx, {tx_errors} tx"),
                )
                .with_value(total, "")
                .with_target("nic");
                vec![match sev {
                    Health::Crit => inc.with_threshold(thr.crit),
                    _ => inc.with_threshold(thr.warn),
                }]
            }
            None => Vec::new(),
        }
    }

    fn apply_captive(&mut self, now: DateTime<Utc>, detected: bool) -> Vec<Incident> {
        let cfg = self.config.thresholds.clone();
        // Debounced like every other verdict: a single intercepted request is as likely to be
        // a flaky proxy as a portal, and "sign-in required" is an expensive thing to be wrong
        // about — it sends the user to a browser instead of at the actual fault.
        let raw = if detected { Health::Crit } else { Health::Ok };
        let debouncer = self
            .captive_health
            .get_or_insert_with(|| Debouncer::new(Health::Ok, cfg.trip_after(), cfg.clear_after()));
        let Some(committed) = debouncer.update(now, raw) else {
            return Vec::new();
        };
        let detected = committed > Health::Ok;
        self.captive_portal = detected;
        let (sev, msg) = if detected {
            (
                Health::Crit,
                "captive portal detected (sign-in required)".to_string(),
            )
        } else {
            (Health::Ok, "captive portal cleared".to_string())
        };
        vec![status_incident(
            now,
            MetricId::CaptivePortal,
            "captive",
            sev,
            msg,
        )]
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
        self.throughput
            .capacity_mbps
            .get_or_insert_with(|| Series::new(cfg.thresholds.history_len))
            .push(mbps);
        let thr = cfg.thresholds.throughput;
        let raw = thr.evaluate(mbps);
        let health = self.throughput.health.get_or_insert_with(|| {
            Debouncer::new(
                Health::Ok,
                cfg.thresholds.trip_after(),
                cfg.thresholds.clear_after(),
            )
        });
        match health.update(now, raw) {
            Some(Health::Ok) => {
                vec![status_incident(
                    now,
                    MetricId::Throughput,
                    "probe",
                    Health::Ok,
                    "throughput recovered".to_string(),
                )]
            }
            Some(sev) => {
                // Report the bound actually crossed, so a crit incident doesn't quote the
                // warn floor and read as a milder problem than it is.
                let crossed = if sev == Health::Crit {
                    thr.crit
                } else {
                    thr.warn
                };
                vec![
                    Incident::new(
                        now,
                        MetricId::Throughput,
                        sev,
                        format!("throughput {mbps:.0}Mbps below floor"),
                    )
                    .with_value(mbps, "Mbps")
                    .with_threshold(crossed),
                ]
            }
            None => Vec::new(),
        }
    }

    fn apply_link(
        &mut self,
        now: DateTime<Utc>,
        rssi_dbm: Option<f64>,
        noise_dbm: Option<f64>,
        tx_rate: Option<f64>,
        ssid: Option<String>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        let thr = cfg.thresholds.rssi;
        if ssid.is_some() {
            self.link.ssid = ssid;
        }
        if noise_dbm.is_some() {
            self.link.noise_dbm = noise_dbm;
        }
        if tx_rate.is_some() {
            self.link.tx_rate = tx_rate;
        }
        let Some(rssi) = rssi_dbm else {
            // No reading at all (radio off, or the shell-out failed). Recording that as a
            // data point would draw a cliff in the trend line that never happened.
            return Vec::new();
        };
        self.link.rssi_dbm = Some(rssi);
        let cap = cfg.thresholds.history_len;
        self.link
            .rssi_history
            .get_or_insert_with(|| Series::new(cap))
            .push(rssi);
        // Pushed in the same breath as the signal so the two series stay index-aligned —
        // SNR is read off the chart as the vertical gap between them.
        if let Some(n) = noise_dbm {
            self.link
                .noise_history
                .get_or_insert_with(|| Series::new(cap))
                .push(n);
        }
        let raw = thr.evaluate(rssi);
        let health = self.link.health.get_or_insert_with(|| {
            Debouncer::new(
                Health::Ok,
                cfg.thresholds.trip_after(),
                cfg.thresholds.clear_after(),
            )
        });
        match health.update(now, raw) {
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
        detail: Vec<Hop>,
    ) -> Vec<Incident> {
        let cfg = self.config.clone();
        self.routing.hops = hops;
        self.routing.reachable = reachable;
        self.routing.changed = changed;
        self.routing.detail = detail;
        self.routing.seen = true;
        let raw = if !reachable {
            Health::Crit
        } else if changed {
            Health::Warn
        } else {
            Health::Ok
        };
        let health = self.routing.health.get_or_insert_with(|| {
            Debouncer::new(
                Health::Ok,
                cfg.thresholds.trip_after(),
                cfg.thresholds.clear_after(),
            )
        });
        let message = match raw {
            Health::Crit => format!("route to {target} unreachable"),
            Health::Warn => format!("route to {target} changed ({hops} hops)"),
            Health::Ok => format!("route to {target} stable ({hops} hops)"),
        };
        match health.update(now, raw) {
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

    /// Record that writing to the incident log failed.
    ///
    /// Only the *first* failure is reported: the causes (full disk, read-only volume,
    /// revoked permissions) are all sticky, so re-reporting would emit one event per
    /// incident forever and bury the network problems the feed exists to show.
    pub fn note_log_error(&mut self, now: DateTime<Utc>, err: &str) {
        if self.log_error.is_some() {
            return;
        }
        self.log_error = Some(err.to_string());
        self.push_event(Incident::new(
            now,
            MetricId::Log,
            Health::Warn,
            format!("incident log unwritable, history is not being saved: {err}"),
        ));
    }

    fn push_event(&mut self, incident: Incident) {
        self.events.push_front(incident);
        while self.events.len() > self.max_events {
            self.events.pop_back();
        }
    }

    /// Apply a control action.
    pub fn apply_action(&mut self, action: Action) {
        // Highest incident index we can scroll to (keep at least one visible).
        let max_scroll = self.events.len().saturating_sub(1);
        match action {
            Action::Quit => self.should_quit = true,
            Action::TogglePause => self.paused = !self.paused,
            Action::ClearEvents => {
                self.events.clear();
                self.events_scroll = 0;
            }
            Action::ForceRefresh => {} // handled by the event loop (re-triggers probes)
            Action::OpenThemePicker => {
                if self.theme_picker.is_none() {
                    let index = Theme::NAMES
                        .iter()
                        .position(|n| *n == self.theme.name)
                        .unwrap_or(0);
                    self.theme_picker = Some(ThemePicker {
                        index,
                        original: self.theme,
                    });
                    self.show_help = false; // don't stack overlays
                }
            }
            Action::ThemePreviewUp => {
                if let Some(p) = self.theme_picker.as_mut() {
                    p.index = (p.index + Theme::NAMES.len() - 1) % Theme::NAMES.len();
                    self.theme = Theme::resolve(Theme::NAMES[p.index]);
                }
            }
            Action::ThemePreviewDown => {
                if let Some(p) = self.theme_picker.as_mut() {
                    p.index = (p.index + 1) % Theme::NAMES.len();
                    self.theme = Theme::resolve(Theme::NAMES[p.index]);
                }
            }
            Action::ThemePickerConfirm => self.theme_picker = None, // keep the previewed theme
            Action::ThemePickerCancel => {
                if let Some(p) = self.theme_picker.take() {
                    self.theme = p.original;
                }
            }
            Action::ToggleHelp => self.show_help = !self.show_help,
            Action::ScrollUp => self.events_scroll = (self.events_scroll + 1).min(max_scroll),
            Action::ScrollDown => self.events_scroll = self.events_scroll.saturating_sub(1),
            Action::ScrollPageUp => self.events_scroll = (self.events_scroll + 5).min(max_scroll),
            Action::ScrollPageDown => self.events_scroll = self.events_scroll.saturating_sub(5),
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
            // Speed and honesty both land on the DNS panel: a resolver answering instantly
            // for names it does not own is not a healthy resolver.
            MetricId::Dns => Health::worst_of(
                self.resolvers
                    .values()
                    .map(|r| r.health.current().worst(r.integrity_health.current())),
            ),
            // Capacity and bufferbloat share the Throughput panel: a link can be "up and
            // fast" yet unusable under load, so the border must reflect the worse of the two.
            MetricId::Throughput | MetricId::Bufferbloat => {
                let capacity = self
                    .throughput
                    .health
                    .as_ref()
                    .map_or(Health::Ok, |d| d.current());
                capacity.worst(self.throughput.bufferbloat_health_current())
            }
            MetricId::Routing => self
                .routing
                .health
                .as_ref()
                .map_or(Health::Ok, |d| d.current()),
            // The "Link & Reachability" panel combines the wireless link, all endpoints, and
            // the captive-portal verdict — a sign-in wall is a total loss of web access even
            // while every endpoint below HTTP answers.
            MetricId::Link
            | MetricId::Reachability
            | MetricId::CaptivePortal
            | MetricId::InterfaceErrors => {
                let link = self
                    .link
                    .health
                    .as_ref()
                    .map_or(Health::Ok, |d| d.current());
                let reach =
                    Health::worst_of(self.reachability.values().map(|r| r.health.current()));
                let captive = self
                    .captive_health
                    .as_ref()
                    .map_or(Health::Ok, |d| d.current());
                link.worst(reach)
                    .worst(captive)
                    .worst(self.iface.health_current())
            }
            // Self-reporting, not a network panel. A broken log must not turn the overall
            // verdict red — the network is fine, the disk isn't; the header badge says so.
            // A new WAN address is news, not a fault: nothing is broken, so nothing goes
            // red. Same for the dashboard's own log — the network is fine, the disk isn't,
            // and the header badge is where that belongs.
            // The transport panel stands alone: a handshake that is slow while ping is fine
            // is the whole point of measuring it, and rolling it into another panel would
            // hide exactly that case.
            MetricId::TcpHandshake | MetricId::TlsHandshake | MetricId::CertExpiry => {
                let tcp = Health::worst_of(self.tcp.values().map(TcpState::health_current));
                // Negotiation timing and expiry are separate faults on separate debouncers,
                // but they are drawn on one border, so it shows the worse.
                let tls = Health::worst_of(
                    self.tls
                        .values()
                        .map(|t| t.health_current().worst(t.expiry_health_current())),
                );
                tcp.worst(tls)
            }
            MetricId::PublicIp | MetricId::Log => Health::Ok,
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
            self.panel_health(MetricId::TcpHandshake),
        ])
    }
}

/// Instability bookkeeping for one (metric, target).
#[derive(Debug, Clone)]
struct FlapState {
    detector: FlapDetector,
    /// The most recent transition held back while flapping, re-reported on settle so the feed
    /// says where the metric actually landed rather than just going quiet.
    last_suppressed: Option<Incident>,
}

impl FlapState {
    fn new(alerts: &AlertConfig) -> Self {
        Self {
            detector: FlapDetector::new(alerts.flap_count, alerts.flap_window()),
            last_suppressed: None,
        }
    }
}

/// The one line that stands in for a burst of individual swings.
///
/// `Warn`, never `Crit`, whichever way the metric happens to be pointing as it trips: this
/// says "you can't trust this reading", which is a different and lesser claim than "this is
/// down". The swing that mattered is reported on its own when the metric settles.
fn flapping_incident(
    now: DateTime<Utc>,
    key: &(MetricId, String),
    detector: &FlapDetector,
    alerts: &AlertConfig,
) -> Incident {
    let (metric, target) = key;
    let message = format!(
        "{} flapping ({target}): {} changes in {:.0}s",
        metric.label(),
        detector.recent(),
        alerts.flap_window_secs,
    );
    status_incident(now, *metric, target, Health::Warn, message)
}

/// Closes out a flapping episode by reporting the swing that was held back last, re-stamped
/// at the moment the metric went quiet.
///
/// `last` is `None` when nothing was suppressed — the detector tripped on the very transition
/// that was reported as "flapping", and nothing came after it. There is no landing state to
/// report in that case, only the fact that the noise stopped.
fn settle_incident(
    now: DateTime<Utc>,
    key: &(MetricId, String),
    last: Option<Incident>,
) -> Incident {
    let (metric, target) = key;
    match last {
        Some(inc) => Incident {
            ts: now,
            message: format!("{} · settled after flapping", inc.message),
            ..inc
        },
        None => status_incident(
            now,
            *metric,
            target,
            Health::Ok,
            format!("{} stopped flapping ({target})", metric.label()),
        ),
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
    use crate::diagnosis::Layer;
    use chrono::TimeZone;
    use pretty_assertions::assert_eq;

    fn now() -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap()
    }

    /// A clock that advances one second per sample, matching the real ping cadence.
    ///
    /// Debouncing is time-based, so a frozen clock can never commit a transition — every
    /// test that expects one has to let time pass, exactly as the running app does.
    struct Clock(DateTime<Utc>);

    impl Clock {
        fn new() -> Self {
            Self(now())
        }

        /// The current instant, then advance a second.
        fn tick(&mut self) -> DateTime<Utc> {
            let at = self.0;
            self.0 += chrono::Duration::seconds(1);
            at
        }
    }

    /// Config with a fast debounce and small windows for deterministic tests. Jitter
    /// thresholds are set out of reach so latency/loss tests are not perturbed by the
    /// jitter that large latency swings naturally produce; a dedicated test covers jitter.
    ///
    /// The 1-second dwells pair with [`Clock`]: a change is committed by the second
    /// differing sample, which keeps these tests reading as "one blip is ignored, two in a
    /// row are believed".
    fn test_config() -> Config {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = None;
        c.thresholds.trip_after_secs = 1.0;
        c.thresholds.clear_after_secs = 1.0;
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

    /// The health recorded in each availability bucket, oldest → newest.
    fn strip(s: &AppState) -> Vec<Option<Health>> {
        s.availability.iter().map(|(_, h)| *h).collect()
    }

    #[test]
    fn tick_opens_one_availability_bucket_per_minute() {
        let mut s = AppState::new(test_config());
        let t = now();
        s.tick(t);
        s.tick(t + chrono::Duration::seconds(20));
        s.tick(t + chrono::Duration::seconds(59));
        assert_eq!(strip(&s).len(), 1, "one minute is one bucket");
        s.tick(t + chrono::Duration::seconds(60));
        assert_eq!(strip(&s).len(), 2);
    }

    #[test]
    fn a_minute_is_recorded_at_its_worst_not_its_last() {
        let mut s = AppState::new(test_config());
        let t = now();
        s.tick(t); // healthy
        // One total outage inside the minute, then recovery — the minute was not "ok".
        // Seconds pass between samples (the debounce is a duration), but every one of them
        // lands inside minute 0, so the whole episode belongs to a single bucket.
        for i in 0..4 {
            s.apply_sample(t + chrono::Duration::seconds(i), timeout("1.1.1.1"));
        }
        s.tick(t + chrono::Duration::seconds(10));
        for i in 0..8 {
            s.apply_sample(
                t + chrono::Duration::seconds(10 + i),
                latency("1.1.1.1", 10.0),
            );
        }
        s.tick(t + chrono::Duration::seconds(50));
        assert_eq!(
            strip(&s),
            vec![Some(Health::Crit)],
            "an outage that healed inside the minute still happened"
        );
    }

    #[test]
    fn skipped_minutes_are_recorded_as_unknown_not_healthy() {
        let mut s = AppState::new(test_config());
        let t = now();
        s.tick(t);
        // The laptop slept for four minutes: we have no idea what the link was doing, and
        // back-filling "ok" would invent uptime the dashboard never observed.
        s.tick(t + chrono::Duration::minutes(5));
        assert_eq!(
            strip(&s),
            vec![Some(Health::Ok), None, None, None, None, Some(Health::Ok)]
        );
    }

    #[test]
    fn a_gap_longer_than_the_strip_does_not_replay_every_missing_minute() {
        let mut s = AppState::new(test_config());
        let t = now();
        s.tick(t);
        s.tick(t + chrono::Duration::days(3));
        assert_eq!(
            s.availability.len(),
            s.availability.capacity(),
            "the strip is bounded; a long sleep should fill it, not iterate for days"
        );
    }

    #[test]
    fn applying_a_sample_advances_the_availability_strip() {
        // Samples arrive far more often than renders under `--once`, and the strip must
        // still be populated for the panel to have anything to draw.
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), latency("1.1.1.1", 12.0));
        assert_eq!(strip(&s).len(), 1);
    }

    #[test]
    fn availability_rollup_counts_each_grade_and_ignores_unknown_minutes() {
        let mut s = AppState::new(test_config());
        let t = now();
        s.tick(t); // minute 0: healthy
        for i in 0..4 {
            // minute 1: total outage (each sample ticks the strip itself). Spread across
            // seconds so the debounce dwell elapses, but all still inside minute 1.
            s.apply_sample(
                t + chrono::Duration::minutes(1) + chrono::Duration::seconds(i),
                timeout("1.1.1.1"),
            );
        }
        s.tick(t + chrono::Duration::minutes(4)); // still down, after a 2-minute gap
        let r = s.availability_rollup();
        assert_eq!((r.ok, r.degraded, r.down, r.unknown), (1, 0, 2, 2));
        // Unknown minutes are not counted against uptime — we did not observe them.
        assert!((r.uptime_pct - 100.0 / 3.0).abs() < 0.01, "{r:?}");
    }

    #[test]
    fn availability_rollup_of_an_empty_strip_is_not_zero_percent() {
        // A dashboard that just started has not had an outage; reporting 0% would be a lie.
        let s = AppState::new(test_config());
        assert_eq!(s.availability_rollup().uptime_pct, 100.0);
    }

    #[test]
    fn link_samples_accumulate_signal_history() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for (rssi, noise) in [(-45.0, -92.0), (-52.0, -91.0), (-61.0, -90.0)] {
            s.apply_sample(
                c.tick(),
                Sample::Link {
                    rssi_dbm: Some(rssi),
                    noise_dbm: Some(noise),
                    tx_rate: Some(400.0),
                    ssid: Some("MyNet".into()),
                },
            );
        }
        // A radio decaying from -45 to -61 dBm is invisible in the current reading alone.
        let rssi = s.link.rssi_history.as_ref().expect("rssi history");
        assert_eq!(rssi.values(), vec![-45.0, -52.0, -61.0]);
        let noise = s.link.noise_history.as_ref().expect("noise history");
        assert_eq!(noise.values(), vec![-92.0, -91.0, -90.0]);
    }

    #[test]
    fn a_link_sample_without_a_reading_does_not_pad_the_history() {
        // The Wi-Fi probe returns `None` when the radio is off or the shell-out failed;
        // recording that as a data point would draw a cliff that never happened.
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Link {
                rssi_dbm: None,
                noise_dbm: None,
                tx_rate: None,
                ssid: None,
            },
        );
        assert!(s.link.rssi_history.is_none());
    }

    #[test]
    fn capacity_probes_accumulate_history() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for mbps in [420.0, 380.0, 55.0] {
            s.apply_sample(c.tick(), Sample::ThroughputProbe { mbps });
        }
        assert_eq!(
            s.throughput
                .capacity_mbps
                .as_ref()
                .expect("capacity history")
                .values(),
            vec![420.0, 380.0, 55.0]
        );
    }

    #[test]
    fn bufferbloat_samples_record_the_added_latency_not_the_raw_pair() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Bufferbloat {
                idle_ms: 18.0,
                loaded_ms: 143.0,
            },
        );
        let h = s
            .throughput
            .added_latency_ms
            .as_ref()
            .expect("bufferbloat history");
        assert_eq!(h.values(), vec![125.0], "the delta is the metric");
    }

    #[test]
    fn bufferbloat_never_records_a_negative_delta() {
        // Loaded latency below idle is measurement noise, not a negative stall.
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Bufferbloat {
                idle_ms: 30.0,
                loaded_ms: 22.0,
            },
        );
        assert_eq!(
            s.throughput.added_latency_ms.as_ref().unwrap().values(),
            vec![0.0]
        );
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
        let mut c = Clock::new();
        s.apply_sample(c.tick(), latency("1.1.1.1", 20.0));
        let t = &s.targets["1.1.1.1"];
        assert_eq!(t.latency_ms.latest(), Some(20.0));
        assert_eq!(t.loss.len(), 1);
    }

    #[test]
    fn loss_history_records_a_point_per_sample() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), latency("1.1.1.1", 20.0));
        s.apply_sample(c.tick(), timeout("1.1.1.1"));
        s.apply_sample(c.tick(), latency("1.1.1.1", 22.0));
        let t = &s.targets["1.1.1.1"];
        // One loss-% point per ping sample, so the panel can draw a line.
        assert_eq!(t.loss_history.len(), 3);
        // After 1 drop out of 3, the latest loss is ~33%.
        assert!((t.loss_history.latest().unwrap() - (100.0 / 3.0)).abs() < 1e-6);
    }

    #[test]
    fn timeout_records_loss_without_latency() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), timeout("1.1.1.1"));
        let t = &s.targets["1.1.1.1"];
        assert_eq!(t.latency_ms.latest(), None);
        assert_eq!(t.loss.len(), 1);
    }

    #[test]
    fn total_outage_does_not_report_healthy_latency() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        // One good reply, then the link dies entirely.
        s.apply_sample(c.tick(), latency("1.1.1.1", 20.0));
        for _ in 0..4 {
            s.apply_sample(c.tick(), timeout("1.1.1.1"));
        }
        // Loss obviously goes bad...
        assert_eq!(s.panel_health(MetricId::Loss), Health::Crit);
        // ...and latency must not keep reporting the stale last-good RTT as healthy.
        assert!(
            s.panel_health(MetricId::Latency) > Health::Ok,
            "a timed-out ping is not a healthy latency"
        );
    }

    #[test]
    fn healthy_latency_produces_no_incidents() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for _ in 0..5 {
            let inc = s.apply_sample(c.tick(), latency("1.1.1.1", 12.0));
            assert!(inc.is_empty());
        }
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    #[test]
    fn single_spike_is_debounced_away() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), latency("1.1.1.1", 12.0));
        let inc = s.apply_sample(c.tick(), latency("1.1.1.1", 400.0)); // one spike
        assert!(
            inc.is_empty(),
            "one spike should not commit with debounce 2"
        );
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    #[test]
    fn sustained_high_latency_emits_crit_incident() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let first = s.apply_sample(c.tick(), latency("1.1.1.1", 400.0));
        assert!(first.is_empty(), "not yet committed");
        let second = s.apply_sample(c.tick(), latency("1.1.1.1", 410.0));
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
        let mut c = Clock::new();
        s.apply_sample(c.tick(), latency("1.1.1.1", 400.0));
        s.apply_sample(c.tick(), latency("1.1.1.1", 410.0)); // -> Crit
        s.apply_sample(c.tick(), latency("1.1.1.1", 10.0));
        let rec = s.apply_sample(c.tick(), latency("1.1.1.1", 11.0)); // -> Ok
        assert_eq!(rec.len(), 1);
        assert_eq!(rec[0].severity, Health::Ok);
        assert_eq!(s.panel_health(MetricId::Latency), Health::Ok);
    }

    // --- root-cause attribution ---

    /// Config with a gateway registered, so faults can be localized to the LAN.
    fn gateway_config() -> Config {
        let mut c = test_config();
        c.targets.gateway = Some("192.168.1.1".into());
        c.targets.gateway_auto = false;
        c
    }

    fn dns_timeout(resolver: &str) -> Sample {
        Sample::Dns {
            resolver: resolver.into(),
            latency_ms: None,
        }
    }

    #[test]
    fn a_dns_failure_behind_a_dead_gateway_is_marked_as_downstream() {
        let mut s = AppState::new(gateway_config());
        let mut c = Clock::new();
        for _ in 0..3 {
            s.apply_sample(c.tick(), timeout("192.168.1.1"));
        }
        assert_eq!(crate::diagnosis::primary_layer(&s), Some(Layer::Gateway));

        let mut raised = Vec::new();
        for _ in 0..3 {
            raised.extend(s.apply_sample(c.tick(), dns_timeout("system")));
        }
        let dns = raised
            .iter()
            .find(|i| i.metric == MetricId::Dns && i.severity > Health::Ok)
            .expect("a failing resolver must still be logged");
        assert_eq!(
            dns.cause,
            Some(Layer::Gateway),
            "DNS can't work through a dead gateway — this is an echo, not a second fault"
        );
    }

    #[test]
    fn the_root_cause_itself_is_never_marked_as_downstream() {
        let mut s = AppState::new(gateway_config());
        let mut c = Clock::new();
        let mut raised = Vec::new();
        for _ in 0..3 {
            raised.extend(s.apply_sample(c.tick(), timeout("192.168.1.1")));
        }
        assert!(
            !raised.is_empty(),
            "the gateway going down must be reported"
        );
        for inc in &raised {
            assert_eq!(
                inc.cause, None,
                "the fault to fix must not be dimmed: {inc:?}"
            );
        }
    }

    #[test]
    fn a_dns_failure_on_an_otherwise_healthy_network_stands_on_its_own() {
        let mut s = AppState::new(gateway_config());
        let mut c = Clock::new();
        for _ in 0..3 {
            s.apply_sample(c.tick(), latency("192.168.1.1", 2.0));
            s.apply_sample(c.tick(), latency("1.1.1.1", 20.0));
        }
        let mut raised = Vec::new();
        for _ in 0..3 {
            raised.extend(s.apply_sample(c.tick(), dns_timeout("system")));
        }
        let dns = raised
            .iter()
            .find(|i| i.metric == MetricId::Dns)
            .expect("a failing resolver must be logged");
        assert_eq!(dns.cause, None, "nothing upstream is broken: {dns:?}");
    }

    #[test]
    fn internet_latency_is_not_dimmed_by_the_verdict_it_is_the_evidence_for() {
        // All internet hosts degrade -> the diagnosis blames the ISP. The pings that proved
        // it must stay legible; dimming them hides the only numbers on screen.
        let mut cfg = gateway_config();
        cfg.targets.internet = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        let mut s = AppState::new(cfg);
        let mut c = Clock::new();
        let mut raised = Vec::new();
        for _ in 0..3 {
            s.apply_sample(c.tick(), latency("192.168.1.1", 2.0));
            raised.extend(s.apply_sample(c.tick(), latency("1.1.1.1", 400.0)));
            raised.extend(s.apply_sample(c.tick(), latency("8.8.8.8", 400.0)));
        }
        assert!(!raised.is_empty());
        for inc in &raised {
            assert_eq!(inc.cause, None, "{inc:?}");
        }
    }

    #[test]
    fn a_recovery_is_never_attributed_to_an_upstream_fault() {
        let mut s = AppState::new(gateway_config());
        let mut c = Clock::new();
        // DNS fails, then comes back, all while the gateway stays down.
        for _ in 0..3 {
            s.apply_sample(c.tick(), timeout("192.168.1.1"));
            s.apply_sample(c.tick(), dns_timeout("system"));
        }
        let mut raised = Vec::new();
        for _ in 0..3 {
            s.apply_sample(c.tick(), timeout("192.168.1.1"));
            raised.extend(s.apply_sample(
                c.tick(),
                Sample::Dns {
                    resolver: "system".into(),
                    latency_ms: Some(12.0),
                },
            ));
        }
        let rec = raised
            .iter()
            .find(|i| i.metric == MetricId::Dns && i.severity == Health::Ok)
            .expect("DNS coming back must be reported");
        assert_eq!(
            rec.cause, None,
            "a metric recovering is its own news, whatever else is broken"
        );
    }

    // --- alert noise ---

    /// Feed `n` samples of `make`, collecting whatever they raise.
    fn drive(
        s: &mut AppState,
        c: &mut Clock,
        n: usize,
        make: impl Fn() -> Sample,
    ) -> Vec<Incident> {
        (0..n)
            .flat_map(|_| s.apply_sample(c.tick(), make()))
            .collect()
    }

    /// A config whose flap detector trips on 4 swings in 10s — the same shape as the
    /// defaults, scaled to the 1s-per-sample test [`Clock`].
    fn flappy_config() -> Config {
        let mut c = test_config();
        c.alerts.flap_count = 4;
        c.alerts.flap_window_secs = 10.0;
        c.alerts.dedup_secs = 0.0;
        c
    }

    /// Swing latency bad→good `cycles` times; each half commits one transition.
    fn swing(s: &mut AppState, c: &mut Clock, cycles: usize) -> Vec<Incident> {
        let mut out = Vec::new();
        for _ in 0..cycles {
            out.extend(drive(s, c, 2, || latency("1.1.1.1", 400.0)));
            out.extend(drive(s, c, 2, || latency("1.1.1.1", 10.0)));
        }
        out
    }

    #[test]
    fn a_metric_that_keeps_changing_its_mind_is_reported_unstable_once() {
        let mut s = AppState::new(flappy_config());
        let mut c = Clock::new();
        let raised = swing(&mut s, &mut c, 6);
        let flapping: Vec<_> = raised
            .iter()
            .filter(|i| i.message.contains("flapping"))
            .collect();
        assert_eq!(flapping.len(), 1, "say it once, not per swing: {raised:#?}");
        assert_eq!(
            raised.len(),
            4,
            "three real swings, then one 'this is unstable' standing in for the other nine: \
             {raised:#?}"
        );
        assert_eq!(flapping[0].metric, MetricId::Latency);
        assert_eq!(flapping[0].target.as_deref(), Some("1.1.1.1"));
    }

    #[test]
    fn a_settled_metric_reports_where_it_actually_landed() {
        let mut s = AppState::new(flappy_config());
        let mut c = Clock::new();
        swing(&mut s, &mut c, 6);
        // Leave it bad, then go quiet for longer than the flap window.
        let tail = drive(&mut s, &mut c, 14, || latency("1.1.1.1", 400.0));
        assert_eq!(tail.len(), 1, "one line closes it out: {tail:#?}");
        assert_eq!(
            tail[0].severity,
            Health::Crit,
            "the noise stopped with latency still broken; saying 'ok' would be a lie: {:?}",
            tail[0]
        );
        assert!(
            tail[0].message.contains("settled"),
            "explain why this line is appearing now: {:?}",
            tail[0]
        );
    }

    #[test]
    fn a_metric_that_settles_can_be_reported_normally_again() {
        let mut s = AppState::new(flappy_config());
        let mut c = Clock::new();
        swing(&mut s, &mut c, 6);
        drive(&mut s, &mut c, 14, || latency("1.1.1.1", 10.0)); // quiet, healthy
        let again = drive(&mut s, &mut c, 2, || latency("1.1.1.1", 400.0));
        assert_eq!(
            again.len(),
            1,
            "suppression must not be permanent: {again:#?}"
        );
        assert_eq!(again[0].severity, Health::Crit);
        assert!(!again[0].message.contains("flapping"), "{:?}", again[0]);
    }

    #[test]
    fn a_steady_metric_is_never_called_unstable() {
        let mut s = AppState::new(flappy_config());
        let mut c = Clock::new();
        // One clean break, then a long healthy stretch: two transitions, well spread.
        let mut raised = drive(&mut s, &mut c, 4, || latency("1.1.1.1", 400.0));
        raised.extend(drive(&mut s, &mut c, 30, || latency("1.1.1.1", 10.0)));
        assert!(
            raised.iter().all(|i| !i.message.contains("flapping")),
            "a link that broke once and recovered is not thrashing: {raised:#?}"
        );
        assert_eq!(raised.len(), 2, "{raised:#?}");
    }

    #[test]
    fn an_identical_alert_inside_the_cooldown_is_dropped() {
        // The dedup backstop works on the incidents themselves, so it can be exercised
        // without a probe that alerts on edges: push the same transition twice.
        let mut cfg = test_config();
        cfg.alerts.dedup_secs = 10.0;
        cfg.alerts.flap_count = 0; // one mechanism at a time
        let mut s = AppState::new(cfg);
        let t = now();
        let inc = || {
            vec![
                status_incident(t, MetricId::Reachability, "wan", Health::Warn, "x".into()),
                status_incident(t, MetricId::Reachability, "wan", Health::Warn, "x".into()),
            ]
        };
        let out = s.filter_noise(t, inc());
        assert_eq!(out.len(), 1, "the same news twice is once: {out:#?}");
        // ...and still dropped on a later fold inside the cooldown.
        assert!(
            s.filter_noise(t + chrono::Duration::seconds(5), inc())
                .is_empty()
        );
        // Past the cooldown it is news again.
        let later = s.filter_noise(t + chrono::Duration::seconds(11), inc());
        assert_eq!(later.len(), 1, "{later:#?}");
    }

    #[test]
    fn a_single_intercepted_request_does_not_announce_a_captive_portal() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let blip = s.apply_sample(c.tick(), Sample::CaptivePortal { detected: true });
        assert!(
            blip.is_empty(),
            "one bad HTTP response is not a portal: {blip:#?}"
        );
        assert!(
            !s.captive_portal,
            "and the diagnosis must not claim one either"
        );
        let confirmed = s.apply_sample(c.tick(), Sample::CaptivePortal { detected: true });
        assert_eq!(
            confirmed.len(),
            1,
            "a portal that persists is real: {confirmed:#?}"
        );
        assert_eq!(confirmed[0].severity, Health::Crit);
        assert!(s.captive_portal);
    }

    #[test]
    fn a_captive_portal_clears_once_the_interception_stops() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: true,
        });
        let cleared = drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: false,
        });
        assert_eq!(cleared.len(), 1, "{cleared:#?}");
        assert_eq!(cleared[0].severity, Health::Ok);
        assert!(!s.captive_portal);
    }

    // --- dual-stack ---

    #[test]
    fn a_v6_target_is_recognised_as_one() {
        let mut s = AppState::new(test_config());
        s.register_target("2606:4700:4700::1111", false);
        s.register_target("1.1.1.1", false);
        assert!(s.targets["2606:4700:4700::1111"].is_ipv6());
        assert!(!s.targets["1.1.1.1"].is_ipv6());
    }

    #[test]
    fn a_v6_address_is_shortened_to_fit_the_name_column() {
        let mut s = AppState::new(test_config());
        s.register_target("2606:4700:4700::1111", false);
        let label = s.targets["2606:4700:4700::1111"].label();
        assert!(
            label.chars().count() <= 15,
            "the panel's name column is 15 wide: {label:?}"
        );
        assert!(
            label.starts_with("2606") && label.ends_with("1111"),
            "both ends identify the address; the middle is the part nobody reads: {label:?}"
        );
    }

    #[test]
    fn a_v4_address_is_left_exactly_as_it_is() {
        let mut s = AppState::new(test_config());
        s.register_target("192.168.1.1", false);
        assert_eq!(s.targets["192.168.1.1"].label(), "192.168.1.1");
    }

    #[test]
    fn a_target_nothing_will_ever_ping_is_dropped_rather_than_shown_as_healthy() {
        let mut s = AppState::new(test_config());
        s.register_target("1.1.1.1", false);
        s.register_target("2606:4700:4700::1111", false);
        s.retain_targets(&["1.1.1.1".to_string()]);
        assert!(s.targets.contains_key("1.1.1.1"));
        assert!(
            !s.targets.contains_key("2606:4700:4700::1111"),
            "an unpingable target has an empty series, which renders as a perfect 0ms/0% \
             — the most misleading thing the panel could say"
        );
    }

    // --- dns integrity ---

    fn integrity(resolver: &str, hijacked: bool) -> Sample {
        Sample::DnsIntegrity {
            resolver: resolver.into(),
            hijacked,
        }
    }

    #[test]
    fn an_honest_resolver_is_not_remarked_upon() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let quiet = drive(&mut s, &mut c, 4, || integrity("system", false));
        assert!(quiet.is_empty(), "{quiet:#?}");
        assert!(!s.resolvers["system"].hijacked);
        assert_eq!(s.panel_health(MetricId::Dns), Health::Ok);
    }

    #[test]
    fn a_hijacking_resolver_warns_and_reddens_the_dns_panel() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let out = drive(&mut s, &mut c, 3, || integrity("system", true));
        assert_eq!(out.len(), 1, "{out:#?}");
        assert_eq!(out[0].metric, MetricId::Dns);
        assert_eq!(out[0].target.as_deref(), Some("system"));
        // Warn, not Crit: the resolver is answering, it is just answering for names it has
        // no business answering for. Names still resolve; the dashboard is not down.
        assert_eq!(out[0].severity, Health::Warn);
        assert!(s.resolvers["system"].hijacked);
        assert_eq!(s.panel_health(MetricId::Dns), Health::Warn);
    }

    #[test]
    fn a_resolver_that_stops_hijacking_says_so() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        drive(&mut s, &mut c, 3, || integrity("system", true));
        let out = drive(&mut s, &mut c, 3, || integrity("system", false));
        assert_eq!(out.len(), 1, "{out:#?}");
        assert_eq!(out[0].severity, Health::Ok);
        assert!(!s.resolvers["system"].hijacked);
    }

    #[test]
    fn a_hijack_does_not_disturb_the_resolvers_timing_verdict() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        drive(&mut s, &mut c, 3, || integrity("system", true));
        assert_eq!(
            s.resolvers["system"].health_current(),
            Health::Ok,
            "lookups are still fast; only their honesty is in question"
        );
    }

    // --- tcp handshake ---

    fn handshake(endpoint: &str, ms: Option<f64>) -> Sample {
        Sample::TcpHandshake {
            endpoint: endpoint.into(),
            connect_ms: ms,
        }
    }

    #[test]
    fn a_fast_handshake_is_recorded_without_comment() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let quiet = drive(&mut s, &mut c, 4, || handshake("cloudflare", Some(20.0)));
        assert!(quiet.is_empty(), "{quiet:#?}");
        let ep = s.tcp.get("cloudflare").expect("registered on first sample");
        assert_eq!(ep.connect_ms.latest(), Some(20.0));
        assert_eq!(s.panel_health(MetricId::TcpHandshake), Health::Ok);
    }

    #[test]
    fn a_port_that_will_not_open_is_critical() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || handshake("cloudflare", None));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::TcpHandshake);
        assert_eq!(raised[0].severity, Health::Crit);
        assert_eq!(raised[0].target.as_deref(), Some("cloudflare"));
        assert_eq!(s.panel_health(MetricId::TcpHandshake), Health::Crit);
    }

    #[test]
    fn a_slow_handshake_warns_before_it_fails() {
        let mut cfg = test_config();
        cfg.thresholds.tcp_handshake = crate::health::Thresholds::higher_is_worse(100.0, 500.0);
        let mut s = AppState::new(cfg);
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || handshake("google", Some(220.0)));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].severity, Health::Warn);
        assert_eq!(raised[0].threshold, Some(100.0), "{:?}", raised[0]);
    }

    #[test]
    fn one_bad_endpoint_does_not_condemn_the_others() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for _ in 0..2 {
            let t = c.tick();
            s.apply_sample(t, handshake("cloudflare", Some(15.0)));
            s.apply_sample(t, handshake("google", None));
        }
        assert_eq!(
            s.tcp["cloudflare"].health_current(),
            Health::Ok,
            "a healthy endpoint stays healthy"
        );
        assert_eq!(
            s.panel_health(MetricId::TcpHandshake),
            Health::Crit,
            "but the panel reports the worst of them"
        );
    }

    #[test]
    fn a_failed_handshake_records_no_timing() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), handshake("google", Some(30.0)));
        s.apply_sample(c.tick(), handshake("google", None));
        let ep = &s.tcp["google"];
        assert_eq!(
            ep.connect_ms.len(),
            1,
            "a refusal is not a zero-millisecond connection"
        );
        assert!(!ep.last_ok);
    }

    // --- tls handshake & certificate expiry ---

    fn tls(endpoint: &str, ms: Option<f64>, days: Option<i64>) -> Sample {
        Sample::Tls {
            endpoint: endpoint.into(),
            handshake_ms: ms,
            expires_in_days: days,
        }
    }

    #[test]
    fn a_fast_handshake_and_a_distant_expiry_are_recorded_without_comment() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let quiet = drive(&mut s, &mut c, 4, || {
            tls("cloudflare", Some(40.0), Some(90))
        });
        assert!(quiet.is_empty(), "{quiet:#?}");
        let ep = s.tls.get("cloudflare").expect("registered on first sample");
        assert_eq!(ep.handshake_ms.latest(), Some(40.0));
        assert_eq!(ep.expires_in_days, Some(90));
        assert_eq!(s.panel_health(MetricId::TlsHandshake), Health::Ok);
    }

    #[test]
    fn a_handshake_that_never_completes_is_critical() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || tls("cloudflare", None, None));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::TlsHandshake);
        assert_eq!(raised[0].severity, Health::Crit);
        assert_eq!(raised[0].target.as_deref(), Some("cloudflare"));
    }

    #[test]
    fn a_failed_negotiation_records_no_timing() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), tls("google", Some(50.0), Some(60)));
        s.apply_sample(c.tick(), tls("google", None, None));
        let ep = &s.tls["google"];
        assert_eq!(
            ep.handshake_ms.len(),
            1,
            "a failed negotiation is not a zero-millisecond one"
        );
        assert!(!ep.last_ok);
    }

    #[test]
    fn a_failed_handshake_does_not_erase_what_the_certificate_last_said() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), tls("google", Some(50.0), Some(60)));
        s.apply_sample(c.tick(), tls("google", None, None));
        assert_eq!(
            s.tls["google"].expires_in_days,
            Some(60),
            "no reading is not the same as no time left"
        );
    }

    #[test]
    fn a_certificate_running_out_warns_while_the_handshake_is_fine() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || tls("google", Some(40.0), Some(9)));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::CertExpiry);
        assert_eq!(raised[0].severity, Health::Warn);
        assert_eq!(
            s.tls["google"].health_current(),
            Health::Ok,
            "the negotiation itself is quick; it is the paperwork that is running out"
        );
    }

    #[test]
    fn an_expired_certificate_is_critical() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || tls("google", Some(40.0), Some(-2)));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::CertExpiry);
        assert_eq!(raised[0].severity, Health::Crit);
    }

    #[test]
    fn a_slow_negotiation_warns_before_it_fails() {
        let mut cfg = test_config();
        cfg.thresholds.tls_handshake = crate::health::Thresholds::higher_is_worse(100.0, 500.0);
        let mut s = AppState::new(cfg);
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || tls("google", Some(240.0), Some(90)));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::TlsHandshake);
        assert_eq!(raised[0].severity, Health::Warn);
        assert_eq!(raised[0].threshold, Some(100.0), "{:?}", raised[0]);
    }

    #[test]
    fn the_transport_panel_reports_the_worst_of_tcp_and_tls() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for _ in 0..2 {
            let t = c.tick();
            s.apply_sample(t, handshake("google", Some(15.0)));
            s.apply_sample(t, tls("google", None, None));
        }
        assert_eq!(
            s.panel_health(MetricId::TcpHandshake),
            Health::Crit,
            "the connection opens, so only TLS can explain this — but it is one panel"
        );
        assert_eq!(s.panel_health(MetricId::TlsHandshake), Health::Crit);
        assert_eq!(s.overall_health(), Health::Crit);
    }

    #[test]
    fn an_expiring_certificate_is_not_blamed_on_the_network() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || tls("google", Some(40.0), Some(1)));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(
            s.incident_layer(&raised[0]),
            None,
            "nothing on the path is broken; an ISP verdict must not dim this"
        );
    }

    /// Everything the reducer can emit must survive the trip to disk and back.
    ///
    /// The log is the only record that outlives the process, and a new `MetricId` that fails
    /// to serialize — or a field silently dropped by `to_jsonl_line` — would be invisible
    /// until someone went looking for an incident that was never written properly. The sink
    /// is injected, so this runs in the fast suite without touching the filesystem.
    #[test]
    fn every_incident_the_reducer_raises_survives_the_log_round_trip() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let faults: Vec<Sample> = vec![
            handshake("cloudflare", None),
            tls("cloudflare", None, None),
            tls("google", Some(20.0), Some(-2)),
            integrity("system", true),
            Sample::Reachability {
                endpoint: "https".into(),
                ok: false,
            },
            errors(40, 0),
        ];
        let mut raised = Vec::new();
        for _ in 0..3 {
            let t = c.tick();
            for f in &faults {
                raised.extend(s.apply_sample(t, f.clone()));
            }
        }
        assert!(raised.len() >= faults.len(), "{raised:#?}");

        let mut log = crate::incidents::IncidentLog::new(Vec::new());
        for inc in &raised {
            log.append(inc).expect("a Vec sink cannot fail");
        }
        let bytes = log.into_inner();
        let text = String::from_utf8(bytes).expect("JSONL is utf-8");
        let parsed: Vec<Incident> = text
            .lines()
            .map(|l| Incident::from_jsonl_line(l).unwrap_or_else(|e| panic!("{l}: {e}")))
            .collect();
        assert_eq!(
            parsed, raised,
            "an incident changed shape on the way to disk"
        );
    }

    // --- interface errors ---

    fn errors(rx: u64, tx: u64) -> Sample {
        Sample::InterfaceErrors {
            rx_errors: rx,
            tx_errors: tx,
        }
    }

    #[test]
    fn a_clean_nic_reports_nothing() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let quiet = drive(&mut s, &mut c, 4, || errors(0, 0));
        assert!(
            quiet.is_empty(),
            "zero errors is the normal case: {quiet:#?}"
        );
        assert_eq!(s.panel_health(MetricId::InterfaceErrors), Health::Ok);
        assert_eq!(s.iface.rx_errors, Some(0));
    }

    #[test]
    fn a_nic_dropping_frames_warns_and_says_which_direction() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || errors(3, 0));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].metric, MetricId::InterfaceErrors);
        assert_eq!(raised[0].severity, Health::Warn);
        assert!(
            raised[0].message.contains("rx"),
            "name the direction — inbound and outbound errors have different causes: {:?}",
            raised[0]
        );
        assert_eq!(s.iface.rx_errors, Some(3));
        assert_eq!(s.iface.tx_errors, Some(0));
    }

    #[test]
    fn a_flood_of_interface_errors_is_critical() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let raised = drive(&mut s, &mut c, 2, || errors(40, 20));
        assert_eq!(raised.len(), 1, "{raised:#?}");
        assert_eq!(raised[0].severity, Health::Crit);
    }

    #[test]
    fn interface_errors_colour_the_link_panel_and_clear_again() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        drive(&mut s, &mut c, 2, || errors(40, 0));
        assert_eq!(
            s.panel_health(MetricId::Link),
            Health::Crit,
            "a NIC shedding frames is a link fault, whatever the radio says"
        );
        let cleared = drive(&mut s, &mut c, 2, || errors(0, 0));
        assert_eq!(cleared.len(), 1, "{cleared:#?}");
        assert_eq!(cleared[0].severity, Health::Ok);
        assert_eq!(s.panel_health(MetricId::Link), Health::Ok);
    }

    #[test]
    fn interface_errors_keep_a_history() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        for n in [1u64, 5, 2] {
            s.apply_sample(c.tick(), errors(n, 0));
        }
        let h = s.iface.history.as_ref().expect("a series after samples");
        assert_eq!(h.len(), 3);
        assert_eq!(h.max(), Some(5.0));
    }

    // --- metric identity ---

    #[test]
    fn each_concern_is_logged_under_its_own_metric_id() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();

        let bloat = drive(&mut s, &mut c, 2, || Sample::Bufferbloat {
            idle_ms: 10.0,
            loaded_ms: 400.0,
        });
        assert_eq!(bloat[0].metric, MetricId::Bufferbloat, "{bloat:#?}");

        let portal = drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: true,
        });
        assert_eq!(portal[0].metric, MetricId::CaptivePortal, "{portal:#?}");

        s.apply_sample(
            c.tick(),
            Sample::PublicIp {
                ip: "1.2.3.4".into(),
            },
        );
        let wan = s.apply_sample(
            c.tick(),
            Sample::PublicIp {
                ip: "5.6.7.8".into(),
            },
        );
        assert_eq!(wan[0].metric, MetricId::PublicIp, "{wan:#?}");

        // Capacity keeps the generic id — it is what "throughput" has always meant.
        let cap = drive(&mut s, &mut c, 2, || Sample::ThroughputProbe { mbps: 0.5 });
        assert_eq!(cap[0].metric, MetricId::Throughput, "{cap:#?}");
    }

    #[test]
    fn a_split_out_metric_still_colours_the_panel_it_is_drawn_in() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        drive(&mut s, &mut c, 2, || Sample::Bufferbloat {
            idle_ms: 10.0,
            loaded_ms: 400.0,
        });
        drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: true,
        });

        assert_eq!(
            s.panel_health(MetricId::Bufferbloat),
            s.panel_health(MetricId::Throughput),
            "bufferbloat is drawn in the throughput panel; one border, one verdict"
        );
        assert_eq!(s.panel_health(MetricId::Bufferbloat), Health::Crit);
        assert_eq!(
            s.panel_health(MetricId::CaptivePortal),
            s.panel_health(MetricId::Reachability),
            "the portal is drawn in the link & reachability panel"
        );
    }

    #[test]
    fn a_captive_portal_turns_its_panel_red() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        assert_eq!(s.panel_health(MetricId::Reachability), Health::Ok);
        drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: true,
        });
        assert_eq!(
            s.panel_health(MetricId::Reachability),
            Health::Crit,
            "a sign-in wall is a total loss of web access; the border must say so"
        );
        assert_eq!(s.overall_health(), Health::Crit);

        drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: false,
        });
        assert_eq!(s.panel_health(MetricId::Reachability), Health::Ok);
    }

    #[test]
    fn a_changed_public_ip_does_not_turn_a_panel_red() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::PublicIp {
                ip: "1.2.3.4".into(),
            },
        );
        let wan = s.apply_sample(
            c.tick(),
            Sample::PublicIp {
                ip: "5.6.7.8".into(),
            },
        );
        assert_eq!(wan.len(), 1);
        assert_eq!(
            s.panel_health(MetricId::PublicIp),
            Health::Ok,
            "a new address is news, not a fault — nothing is broken"
        );
        assert_eq!(s.overall_health(), Health::Ok);
    }

    #[test]
    fn recovery_is_slower_to_commit_than_the_fault_was() {
        let mut cfg = test_config();
        cfg.thresholds.trip_after_secs = 2.0;
        cfg.thresholds.clear_after_secs = 10.0;
        let mut s = AppState::new(cfg);
        let mut c = Clock::new();

        // Two seconds of bad latency is enough to report the fault.
        assert!(
            s.apply_sample(c.tick(), latency("1.1.1.1", 400.0))
                .is_empty()
        );
        assert!(
            s.apply_sample(c.tick(), latency("1.1.1.1", 400.0))
                .is_empty()
        );
        let tripped = s.apply_sample(c.tick(), latency("1.1.1.1", 400.0));
        assert_eq!(
            tripped.len(),
            1,
            "reported once the 2s trip dwell has passed"
        );
        assert_eq!(s.panel_health(MetricId::Latency), Health::Crit);

        // The same two seconds of health is *not* enough to call it recovered.
        for _ in 0..3 {
            assert!(
                s.apply_sample(c.tick(), latency("1.1.1.1", 10.0))
                    .is_empty()
            );
        }
        assert_eq!(
            s.panel_health(MetricId::Latency),
            Health::Crit,
            "a link that is briefly fine mid-flap is not fixed"
        );

        // Ten seconds of it is.
        let mut recovered = Vec::new();
        for _ in 0..8 {
            recovered.extend(s.apply_sample(c.tick(), latency("1.1.1.1", 10.0)));
        }
        assert_eq!(
            recovered.len(),
            1,
            "recovery reported after the 10s clear dwell"
        );
        assert_eq!(recovered[0].severity, Health::Ok);
    }

    #[test]
    fn gateway_uses_stricter_thresholds() {
        let mut c = test_config();
        c.targets.gateway = Some("gw".into());
        let mut s = AppState::new(c);
        let mut c = Clock::new();
        // 20ms is Ok for internet (<80) but Warn for the gateway (>=15).
        s.apply_sample(c.tick(), latency("gw", 20.0));
        s.apply_sample(c.tick(), latency("gw", 21.0));
        assert_eq!(s.targets["gw"].latency_health_current(), Health::Warn);
    }

    #[test]
    fn sustained_jitter_reddens_latency_panel() {
        let mut c = test_config();
        c.thresholds.jitter = Thresholds::higher_is_worse(15.0, 40.0); // normal jitter bounds
        let mut s = AppState::new(c);
        let mut c = Clock::new();
        // Oscillate 10/60ms: each latency is Ok (<80) but the swing drives jitter ~50ms.
        s.apply_sample(c.tick(), latency("1.1.1.1", 10.0));
        s.apply_sample(c.tick(), latency("1.1.1.1", 60.0));
        let third = s.apply_sample(c.tick(), latency("1.1.1.1", 10.0));
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
        let mut c = Clock::new();
        let a = s.apply_sample(c.tick(), timeout("1.1.1.1"));
        assert!(a.is_empty());
        let b = s.apply_sample(c.tick(), timeout("1.1.1.1"));
        // Sustained timeouts are both a loss problem and a latency problem, so the second
        // drop commits each debouncer and emits one incident for each.
        let loss = b
            .iter()
            .find(|i| i.metric == MetricId::Loss)
            .expect("a loss incident");
        assert_eq!(loss.severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Loss), Health::Crit);

        let lat = b
            .iter()
            .find(|i| i.metric == MetricId::Latency)
            .expect("a latency incident");
        assert_eq!(lat.severity, Health::Crit);
        assert!(lat.message.contains("timed out"));
        assert_eq!(b.len(), 2);
    }

    #[test]
    fn overall_health_is_worst_panel() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(c.tick(), timeout("1.1.1.1"));
        s.apply_sample(c.tick(), timeout("1.1.1.1")); // loss -> Crit
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
    fn theme_picker_opens_at_current_theme() {
        let mut s = AppState::new(test_config());
        let start = s.theme;
        assert!(s.theme_picker.is_none());
        s.apply_action(Action::OpenThemePicker);
        let p = s.theme_picker.expect("picker should open");
        assert_eq!(
            Theme::NAMES[p.index],
            start.name,
            "opens at the active theme"
        );
        assert_eq!(s.theme, start, "opening does not change the theme");
    }

    #[test]
    fn theme_picker_preview_changes_theme_live_and_wraps() {
        let mut s = AppState::new(test_config());
        let start = s.theme;
        s.apply_action(Action::OpenThemePicker);
        s.apply_action(Action::ThemePreviewDown);
        assert_eq!(s.theme, start.next(), "down previews the next theme live");
        // Wrap all the way around back to the start.
        for _ in 1..Theme::NAMES.len() {
            s.apply_action(Action::ThemePreviewDown);
        }
        assert_eq!(s.theme, start, "preview wraps back to the start");
        // Step up to the first theme, then once more to confirm Up wraps to the last theme.
        while s.theme.name != Theme::NAMES[0] {
            s.apply_action(Action::ThemePreviewUp);
        }
        s.apply_action(Action::ThemePreviewUp);
        assert_eq!(
            s.theme.name,
            *Theme::NAMES.last().unwrap(),
            "up from the first theme wraps to the last"
        );
    }

    #[test]
    fn theme_picker_confirm_keeps_preview() {
        let mut s = AppState::new(test_config());
        let start = s.theme;
        s.apply_action(Action::OpenThemePicker);
        s.apply_action(Action::ThemePreviewDown);
        let previewed = s.theme;
        assert_ne!(previewed, start);
        s.apply_action(Action::ThemePickerConfirm);
        assert!(s.theme_picker.is_none(), "confirm closes the picker");
        assert_eq!(s.theme, previewed, "confirm keeps the previewed theme");
    }

    #[test]
    fn theme_picker_cancel_reverts_to_original() {
        let mut s = AppState::new(test_config());
        let start = s.theme;
        s.apply_action(Action::OpenThemePicker);
        s.apply_action(Action::ThemePreviewDown);
        s.apply_action(Action::ThemePreviewDown);
        assert_ne!(s.theme, start);
        s.apply_action(Action::ThemePickerCancel);
        assert!(s.theme_picker.is_none(), "cancel closes the picker");
        assert_eq!(
            s.theme, start,
            "cancel reverts to the theme active before opening"
        );
    }

    #[test]
    fn dns_failure_emits_crit_incident() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Dns {
                resolver: "cloudflare".into(),
                latency_ms: None,
            },
        );
        let out = s.apply_sample(
            c.tick(),
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
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Dns {
                resolver: "system".into(),
                latency_ms: Some(150.0),
            },
        );
        let out = s.apply_sample(
            c.tick(),
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
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: false,
            },
        );
        let down = s.apply_sample(
            c.tick(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: false,
            },
        );
        assert_eq!(down.len(), 1);
        assert_eq!(down[0].severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Link), Health::Crit); // combined panel

        s.apply_sample(
            c.tick(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        let up = s.apply_sample(
            c.tick(),
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        assert_eq!(up.len(), 1);
        assert_eq!(up[0].severity, Health::Ok);
    }

    #[test]
    fn captive_portal_sets_state_and_logs_on_change() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        // First "clear" reading matches the default — no spurious incident.
        assert!(
            s.apply_sample(c.tick(), Sample::CaptivePortal { detected: false })
                .is_empty()
        );
        assert!(!s.captive_portal);

        // A portal that persists past the trip dwell flips the state and logs a crit.
        let hit = drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: true,
        });
        assert!(s.captive_portal);
        assert_eq!(hit.len(), 1);
        assert_eq!(hit[0].severity, Health::Crit);

        // Steady portal readings after that do not re-log.
        assert!(
            drive(&mut s, &mut c, 3, || Sample::CaptivePortal {
                detected: true
            })
            .is_empty()
        );

        // Clearing flips back and logs recovery.
        let cleared = drive(&mut s, &mut c, 2, || Sample::CaptivePortal {
            detected: false,
        });
        assert!(!s.captive_portal);
        assert_eq!(cleared.len(), 1);
        assert_eq!(cleared[0].severity, Health::Ok);
    }

    #[test]
    fn public_ip_change_is_logged_but_first_sight_is_silent() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        // First observation just records the IP — no incident.
        assert!(
            s.apply_sample(
                c.tick(),
                Sample::PublicIp {
                    ip: "1.2.3.4".into()
                }
            )
            .is_empty()
        );
        assert_eq!(s.public_ip.as_deref(), Some("1.2.3.4"));
        // Same IP again — still silent.
        assert!(
            s.apply_sample(
                c.tick(),
                Sample::PublicIp {
                    ip: "1.2.3.4".into()
                }
            )
            .is_empty()
        );
        // A change is logged (WAN flap / failover / CGNAT shuffle).
        let out = s.apply_sample(
            c.tick(),
            Sample::PublicIp {
                ip: "5.6.7.8".into(),
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(s.public_ip.as_deref(), Some("5.6.7.8"));
    }

    #[test]
    fn bufferbloat_over_threshold_warns() {
        let mut s = AppState::new(test_config()); // bufferbloat warn 100 / crit 300 ms
        let mut c = Clock::new();
        // +150 ms under load → Warn once debounced.
        let sample = Sample::Bufferbloat {
            idle_ms: 20.0,
            loaded_ms: 170.0,
        };
        s.apply_sample(c.tick(), sample.clone());
        let out = s.apply_sample(c.tick(), sample);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(s.throughput.loaded_latency_ms, Some(170.0));
    }

    #[test]
    fn bufferbloat_crit_reddens_the_throughput_panel() {
        let mut s = AppState::new(test_config()); // bufferbloat warn 100 / crit 300 ms
        let mut c = Clock::new();
        // +380 ms under load → Crit once debounced.
        let sample = Sample::Bufferbloat {
            idle_ms: 20.0,
            loaded_ms: 400.0,
        };
        s.apply_sample(c.tick(), sample.clone());
        let out = s.apply_sample(c.tick(), sample);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Crit);
        // The incident is worthless if the panel it belongs to still looks healthy.
        assert_eq!(s.panel_health(MetricId::Throughput), Health::Crit);
    }

    #[test]
    fn route_info_populates_interface_mtu_and_vpn() {
        let mut s = AppState::new(test_config());
        s.apply_route_info(&crate::net::RouteInfo {
            gateway: Some("10.8.0.1".into()),
            interface: Some("utun3".into()),
            mtu: Some(1400),
        });
        assert_eq!(s.interface.as_deref(), Some("utun3"));
        assert_eq!(s.mtu, Some(1400));
        assert!(s.vpn, "utun3 default route should mark VPN active");
    }

    #[test]
    fn throughput_passive_fills_series_without_incident() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        let out = s.apply_sample(
            c.tick(),
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
        c.thresholds.throughput = Thresholds::lower_is_worse(100.0, 25.0);
        let mut s = AppState::new(c);
        let mut c = Clock::new();
        s.apply_sample(c.tick(), Sample::ThroughputProbe { mbps: 50.0 });
        let out = s.apply_sample(c.tick(), Sample::ThroughputProbe { mbps: 40.0 });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
        assert_eq!(out[0].value, Some(40.0));
        assert_eq!(out[0].threshold, Some(100.0));
        assert_eq!(s.throughput.last_mbps, Some(40.0));
    }

    #[test]
    fn throughput_far_below_floor_is_crit() {
        let mut c = test_config();
        c.thresholds.throughput = Thresholds::lower_is_worse(100.0, 25.0);
        let mut s = AppState::new(c);
        let mut c = Clock::new();
        // 4 Mbps on a link expected to do 100 is not a "warning", it is unusable.
        s.apply_sample(c.tick(), Sample::ThroughputProbe { mbps: 5.0 });
        let out = s.apply_sample(c.tick(), Sample::ThroughputProbe { mbps: 4.0 });
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Crit);
        assert_eq!(out[0].value, Some(4.0));
        // The reported threshold must be the one actually crossed, not the warn bound.
        assert_eq!(out[0].threshold, Some(25.0));
        assert_eq!(s.panel_health(MetricId::Throughput), Health::Crit);
    }

    #[test]
    fn link_weak_rssi_warns_and_keeps_ssid() {
        let mut s = AppState::new(test_config()); // rssi warn -70 / crit -80 (lower is worse)
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Link {
                rssi_dbm: Some(-75.0),
                noise_dbm: None,
                tx_rate: None,
                ssid: Some("MyNet".into()),
            },
        );
        let out = s.apply_sample(
            c.tick(),
            Sample::Link {
                rssi_dbm: Some(-76.0),
                noise_dbm: None,
                tx_rate: None,
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
        let mut c = Clock::new();
        let r = Sample::Routing {
            target: "1.1.1.1".into(),
            hops: 0,
            reachable: false,
            changed: false,
            detail: vec![],
        };
        s.apply_sample(c.tick(), r.clone());
        let out = s.apply_sample(c.tick(), r);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Crit);
        assert_eq!(s.panel_health(MetricId::Routing), Health::Crit);
    }

    #[test]
    fn routing_change_warns() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.apply_sample(
            c.tick(),
            Sample::Routing {
                target: "t".into(),
                hops: 8,
                reachable: true,
                changed: true,
                detail: vec![],
            },
        );
        let out = s.apply_sample(
            c.tick(),
            Sample::Routing {
                target: "t".into(),
                hops: 9,
                reachable: true,
                changed: true,
                detail: vec![],
            },
        );
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Health::Warn);
    }

    #[test]
    fn help_toggles_and_clear_resets_scroll() {
        let mut s = AppState::new(test_config());
        assert!(!s.show_help);
        s.apply_action(Action::ToggleHelp);
        assert!(s.show_help);
        s.apply_action(Action::ToggleHelp);
        assert!(!s.show_help);

        // Scrolling is clamped to the number of events (can't scroll an empty feed).
        s.apply_action(Action::ScrollUp);
        assert_eq!(s.events_scroll, 0, "no events → no scroll");
    }

    #[test]
    fn scroll_is_bounded_by_event_count() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        // Generate a few incidents (loss crit transitions).
        for _ in 0..3 {
            s.apply_sample(c.tick(), timeout("1.1.1.1"));
        }
        assert!(!s.events.is_empty());
        // Scroll far past the end — clamps to len-1, and never underflows.
        for _ in 0..50 {
            s.apply_action(Action::ScrollUp);
        }
        assert_eq!(s.events_scroll, s.events.len() - 1);
        for _ in 0..50 {
            s.apply_action(Action::ScrollDown);
        }
        assert_eq!(s.events_scroll, 0);
    }

    #[test]
    fn events_ring_is_capped() {
        let mut s = AppState::new(test_config());
        let mut c = Clock::new();
        s.max_events = 3;
        for _ in 0..10 {
            // alternate crit/ok on loss to keep generating transitions
            s.apply_sample(c.tick(), timeout("1.1.1.1"));
            s.apply_sample(c.tick(), timeout("1.1.1.1"));
            s.apply_sample(c.tick(), latency("1.1.1.1", 5.0));
            s.apply_sample(c.tick(), latency("1.1.1.1", 5.0));
        }
        assert!(
            s.events.len() <= 3,
            "events ring exceeded cap: {}",
            s.events.len()
        );
    }

    #[test]
    fn log_write_failure_surfaces_once() {
        let mut s = AppState::new(test_config());
        s.note_log_error(now(), "no space left on device");
        s.note_log_error(now(), "no space left on device");
        s.note_log_error(now(), "still broken");

        assert_eq!(
            s.log_error.as_deref(),
            Some("no space left on device"),
            "the first failure is the diagnostic one"
        );
        let reports: Vec<_> = s
            .events
            .iter()
            .filter(|e| e.metric == MetricId::Log)
            .collect();
        assert_eq!(
            reports.len(),
            1,
            "one self-report, not one per failed write — otherwise a broken disk floods \
             the feed and buries the network events it is there to show"
        );
        assert_eq!(reports[0].severity, Health::Warn);
        assert!(
            reports[0].message.contains("no space left on device"),
            "got: {}",
            reports[0].message
        );
    }
}
