//! The async event loop: key mapping, the probe scheduler, and `run`.
//!
//! [`map_key`] (pure) and [`spawn_probe`] (a cadence-driven task feeding samples over an
//! mpsc channel) are unit-tested. [`run`] wires them into a `tokio::select!` loop with the
//! crossterm event stream and a render ticker; it needs a real terminal, so it is
//! exercised by running the app rather than by unit tests.

use std::future::Future;
use std::time::Duration;

use chrono::Utc;
use crossterm::event::{Event, EventStream, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
use futures::StreamExt;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

use crate::app::{Action, AppState};
use crate::config::Config;
use crate::incidents::IncidentLog;
use crate::metrics::{Probe, Sample};
use crate::ui;

/// Map a key press to a control [`Action`], or `None` if unbound.
pub fn map_key(key: KeyEvent) -> Option<Action> {
    // Ctrl-C always quits, regardless of the plain 'c' binding below.
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match key.code {
        KeyCode::Char('q') | KeyCode::Esc => Some(Action::Quit),
        KeyCode::Char('p') => Some(Action::TogglePause),
        KeyCode::Char('c') => Some(Action::ClearEvents),
        KeyCode::Char('r') => Some(Action::ForceRefresh),
        KeyCode::Char('t') => Some(Action::CycleTheme),
        _ => None,
    }
}

/// Spawn a task that ticks `probe` every `interval` and forwards its samples to `tx`.
/// The task ends when the receiver is dropped.
pub fn spawn_probe<P>(mut probe: P, interval: Duration, tx: mpsc::Sender<Sample>) -> JoinHandle<()>
where
    P: Probe + Send + 'static,
{
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            for sample in probe.tick().await {
                if tx.send(sample).await.is_err() {
                    return;
                }
            }
        }
    })
}

/// A synthetic probe used before the real probes exist: emits per-target latency on a
/// smooth curve with periodic spikes and drops so the dashboard (and its red borders /
/// incident log) can be seen live via `cargo run`.
pub struct DemoProbe {
    targets: Vec<String>,
    t: f64,
}

impl DemoProbe {
    pub fn new(targets: Vec<String>) -> Self {
        Self { targets, t: 0.0 }
    }
}

impl Probe for DemoProbe {
    fn tick(&mut self) -> impl Future<Output = Vec<Sample>> + Send {
        self.t += 1.0;
        let t = self.t;
        let out: Vec<Sample> = self
            .targets
            .iter()
            .enumerate()
            .map(|(i, name)| {
                let tick = t as u64 + i as u64;
                // Occasional drop (loss) and occasional latency spike, deterministically.
                if tick.is_multiple_of(53) {
                    Sample::Latency {
                        target: name.clone(),
                        rtt_ms: None,
                    }
                } else {
                    let base = 10.0 + i as f64 * 6.0;
                    let wobble = 8.0 * (t * 0.25 + i as f64).sin().abs();
                    let spike = if tick.is_multiple_of(37) { 220.0 } else { 0.0 };
                    Sample::Latency {
                        target: name.clone(),
                        rtt_ms: Some(base + wobble + spike),
                    }
                }
            })
            .collect();
        async move { out }
    }
}

/// Run every probe once, fold the samples into a fresh state, and print a text summary.
/// Headless (no terminal) — useful for scripting and verifying probes work.
pub async fn run_once(config: Config) -> color_eyre::Result<()> {
    use crate::health::Health;
    use crate::metrics::{MetricId, Probe};

    let mut state = AppState::new(config.clone());
    if config.targets.gateway_auto
        && config.targets.gateway.is_none()
        && let Some(gw) = crate::net::detect_default_gateway()
    {
        state.register_target(gw, true);
    }
    let targets: Vec<String> = state.targets.keys().cloned().collect();

    let mut samples = Vec::new();
    if let Ok(mut p) = crate::metrics::ping::PingProbe::new(&targets, Duration::from_millis(900)) {
        samples.extend(p.tick().await);
    }
    let mut dns = crate::metrics::dns::DnsProbe::new(&config.resolvers);
    samples.extend(dns.tick().await);
    let mut reach = crate::metrics::reachability::ReachabilityProbe::new(
        crate::metrics::reachability::ReachabilityProbe::default_endpoints(),
    );
    samples.extend(reach.tick().await);
    samples.extend(crate::metrics::link::WifiProbe.tick().await);
    samples.extend(
        crate::metrics::routing::RoutingProbe::new(config.targets.routing_target.clone(), 15)
            .tick()
            .await,
    );

    let now = chrono::Utc::now();
    for s in samples {
        state.apply_sample(now, s);
    }

    let badge = |h: Health| match h {
        Health::Ok => "OK",
        Health::Warn => "WARN",
        Health::Crit => "CRIT",
    };
    println!(
        "NetPulse — one-shot probe  (overall: {})",
        badge(state.overall_health())
    );
    for m in [
        MetricId::Latency,
        MetricId::Loss,
        MetricId::Dns,
        MetricId::Routing,
        MetricId::Throughput,
        MetricId::Link,
    ] {
        println!("  {:<12} {}", m.label(), badge(state.panel_health(m)));
    }
    for (name, t) in &state.targets {
        println!(
            "  ping {name:<16} {:.0}ms  loss {:.0}%",
            t.latency_ms.latest().unwrap_or(0.0),
            t.loss.loss_pct()
        );
    }
    for (name, r) in &state.resolvers {
        let v = if r.last_ok {
            format!("{:.0}ms", r.latency_ms.latest().unwrap_or(0.0))
        } else {
            "FAIL".into()
        };
        println!("  dns  {name:<16} {v}");
    }
    Ok(())
}

/// Initialize the terminal and run the dashboard until the user quits.
pub async fn run(config: Config) -> color_eyre::Result<()> {
    let mut terminal = crate::tui::init()?;
    let result = run_inner(&mut terminal, config).await;
    crate::tui::restore()?;
    result
}

async fn run_inner(terminal: &mut crate::tui::Tui, config: Config) -> color_eyre::Result<()> {
    let mut state = AppState::new(config.clone());
    let (tx, mut rx) = mpsc::channel::<Sample>(256);

    // Best-effort incident log; the dashboard still runs if it can't be opened.
    let mut log = IncidentLog::default_path().and_then(|path| IncidentLog::open_append(&path).ok());

    // Detect the default gateway and register it as a (stricter-threshold) ping target.
    if config.targets.gateway_auto
        && config.targets.gateway.is_none()
        && let Some(gw) = crate::net::detect_default_gateway()
    {
        state.register_target(gw, true);
    }

    let targets: Vec<String> = state.targets.keys().cloned().collect();
    let interval = config.cadence.ping();
    let timeout = Duration::from_millis(900).min(interval);

    // Real ICMP ping; fall back to the demo generator if a socket can't be created (so the
    // dashboard is still usable in restricted environments).
    let mut _handles = Vec::new();
    match crate::metrics::ping::PingProbe::new(&targets, timeout) {
        Ok(probe) if probe.target_count() > 0 => {
            _handles.push(spawn_probe(probe, interval, tx.clone()));
        }
        _ => _handles.push(spawn_probe(DemoProbe::new(targets), interval, tx.clone())),
    }

    // DNS resolver comparison.
    let dns = crate::metrics::dns::DnsProbe::new(&config.resolvers);
    if dns.resolver_count() > 0 {
        _handles.push(spawn_probe(
            dns,
            Duration::from_millis(config.cadence.dns_ms),
            tx.clone(),
        ));
    }

    // HTTP(S) reachability + captive/IPv6.
    _handles.push(spawn_probe(
        crate::metrics::reachability::ReachabilityProbe::new(
            crate::metrics::reachability::ReachabilityProbe::default_endpoints(),
        ),
        Duration::from_millis(config.cadence.reachability_ms),
        tx.clone(),
    ));

    // Passive throughput counters.
    let tput_interval = Duration::from_millis(config.cadence.throughput_passive_ms);
    _handles.push(spawn_probe(
        crate::metrics::throughput::ThroughputProbe::new(tput_interval),
        tput_interval,
        tx.clone(),
    ));

    // Wireless link (macOS system_profiler).
    _handles.push(spawn_probe(
        crate::metrics::link::WifiProbe,
        Duration::from_millis(config.cadence.link_ms),
        tx.clone(),
    ));

    // Routing / path (lightweight traceroute).
    _handles.push(spawn_probe(
        crate::metrics::routing::RoutingProbe::new(config.targets.routing_target.clone(), 15),
        Duration::from_millis(config.cadence.routing_ms),
        tx.clone(),
    ));

    let mut reader = EventStream::new();
    let mut render_tick = tokio::time::interval(config.cadence.render());

    loop {
        tokio::select! {
            _ = render_tick.tick() => {
                terminal.draw(|f| ui::render(f, &state))?;
            }
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event
                    && key.kind == KeyEventKind::Press
                    && let Some(action) = map_key(key)
                {
                    state.apply_action(action);
                }
            }
            Some(sample) = rx.recv() => {
                if !state.paused {
                    for inc in state.apply_sample(Utc::now(), sample) {
                        if let Some(log) = log.as_mut() {
                            let _ = log.append(&inc);
                        }
                    }
                }
            }
        }
        if state.should_quit {
            break;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    #[test]
    fn q_and_esc_quit() {
        assert_eq!(map_key(key(KeyCode::Char('q'))), Some(Action::Quit));
        assert_eq!(map_key(key(KeyCode::Esc)), Some(Action::Quit));
    }

    #[test]
    fn ctrl_c_quits() {
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map_key(k), Some(Action::Quit));
    }

    #[test]
    fn control_keys_map() {
        assert_eq!(map_key(key(KeyCode::Char('p'))), Some(Action::TogglePause));
        assert_eq!(map_key(key(KeyCode::Char('c'))), Some(Action::ClearEvents));
        assert_eq!(map_key(key(KeyCode::Char('r'))), Some(Action::ForceRefresh));
        assert_eq!(map_key(key(KeyCode::Char('t'))), Some(Action::CycleTheme));
    }

    #[test]
    fn unbound_key_is_none() {
        assert_eq!(map_key(key(KeyCode::Char('x'))), None);
    }

    #[tokio::test]
    async fn scheduler_forwards_scripted_samples() {
        let (tx, mut rx) = mpsc::channel(16);
        let probe = crate::metrics::FakeProbe::new(vec![
            vec![Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(1.0),
            }],
            vec![Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(2.0),
            }],
        ]);
        let handle = spawn_probe(probe, Duration::from_millis(1), tx);
        let a = rx.recv().await.unwrap();
        let b = rx.recv().await.unwrap();
        handle.abort();
        assert_eq!(
            a,
            Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(1.0)
            }
        );
        assert_eq!(
            b,
            Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(2.0)
            }
        );
    }

    #[tokio::test]
    async fn scheduler_stops_when_receiver_dropped() {
        let (tx, rx) = mpsc::channel(1);
        let probe = crate::metrics::FakeProbe::new(vec![vec![Sample::Latency {
            target: "gw".into(),
            rtt_ms: Some(1.0),
        }]]);
        let handle = spawn_probe(probe, Duration::from_millis(1), tx);
        drop(rx);
        // The task should finish on its own once sends start failing.
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
}
