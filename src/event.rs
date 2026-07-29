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
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinHandle;

use crate::app::{Action, AppState};
use crate::config::Config;
use crate::incidents::RotatingLog;
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
        KeyCode::Char('t') => Some(Action::OpenThemePicker),
        KeyCode::Char('?') => Some(Action::ToggleHelp),
        KeyCode::Up | KeyCode::Char('k') => Some(Action::ScrollUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::ScrollDown),
        KeyCode::PageUp => Some(Action::ScrollPageUp),
        KeyCode::PageDown => Some(Action::ScrollPageDown),
        _ => None,
    }
}

/// Key mapping while the theme picker overlay is open (modal): the same keys that normally
/// scroll or quit instead drive the picker. `↑`/`k` and `↓`/`j` move the live preview,
/// Enter/`t` keep the highlighted theme, Esc/`q` revert to the pre-open theme, and Ctrl-C
/// still quits the app.
pub fn map_picker_key(key: KeyEvent) -> Option<Action> {
    if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
        return Some(Action::Quit);
    }
    match key.code {
        KeyCode::Up | KeyCode::Char('k') => Some(Action::ThemePreviewUp),
        KeyCode::Down | KeyCode::Char('j') => Some(Action::ThemePreviewDown),
        KeyCode::Enter | KeyCode::Char('t') => Some(Action::ThemePickerConfirm),
        KeyCode::Esc | KeyCode::Char('q') => Some(Action::ThemePickerCancel),
        _ => None,
    }
}

/// Spawn a task that ticks `probe` every `interval` — or as soon as `wake` fires — and
/// forwards its samples to `tx`. The task ends when the receiver is dropped.
///
/// `wake` is what makes [`Action::ForceRefresh`] real: without it, `r` could not do
/// anything for a probe on a 60-second cadence, which is exactly when it's pressed.
pub fn spawn_probe<P>(
    mut probe: P,
    interval: Duration,
    tx: mpsc::Sender<Sample>,
    wake: &broadcast::Sender<()>,
) -> JoinHandle<()>
where
    P: Probe + Send + 'static,
{
    // Subscribe before spawning, so a refresh sent right after this call can't slip
    // through the gap before the task first runs.
    let mut wake = wake.subscribe();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        // If a tick overruns (a slow probe), re-align to the cadence grid rather than
        // replaying every missed tick back-to-back (the default `Burst`), which makes a
        // panel go quiet and then jump instead of updating on regular intervals.
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                _ = ticker.tick() => {}
                recv = wake.recv() => {
                    // `Lagged` just means several refreshes piled up while a slow probe was
                    // mid-tick; one catch-up run answers all of them. `Closed` means the app
                    // is shutting down.
                    if matches!(recv, Err(broadcast::error::RecvError::Closed)) {
                        return;
                    }
                    // Restart the cadence from now, so a manual refresh isn't immediately
                    // followed by the scheduled tick it just pre-empted.
                    ticker.reset();
                }
            }
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
    if let Some(info) = crate::net::detect_route_info() {
        if config.targets.gateway_auto
            && config.targets.gateway.is_none()
            && let Some(gw) = info.gateway.clone()
        {
            state.register_target(gw, true);
        }
        state.apply_route_info(&info);
    }
    let targets: Vec<String> = state.targets.keys().cloned().collect();

    let mut samples = Vec::new();
    if let Ok(mut p) = crate::metrics::ping::PingProbe::new(&targets, Duration::from_millis(900)) {
        // Whatever the probe won't ping (IPv6 targets on a v4-only host) leaves state now,
        // before it can occupy a row reporting a flawless 0ms.
        state.retain_targets(&p.target_names());
        samples.extend(p.tick().await);
    }
    let mut dns = crate::metrics::dns::DnsProbe::new(&config.resolvers, Duration::from_secs(2));
    samples.extend(dns.tick().await);
    samples.extend(
        crate::metrics::dns::DnsIntegrityProbe::with_clock_seed(
            &config.resolvers,
            Duration::from_secs(2),
        )
        .tick()
        .await,
    );
    let mut reach = crate::metrics::reachability::ReachabilityProbe::new(
        crate::metrics::reachability::ReachabilityProbe::default_endpoints(),
    );
    samples.extend(reach.tick().await);
    samples.extend(crate::metrics::link::WifiProbe.tick().await);
    samples.extend(crate::metrics::iface::InterfaceProbe::new().tick().await);
    samples.extend(
        crate::metrics::tcp::TcpProbe::new(
            crate::metrics::tcp::TcpProbe::default_endpoints(),
            Duration::from_secs(3),
        )
        .tick()
        .await,
    );
    samples.extend(
        crate::metrics::routing::RoutingProbe::new(
            config.targets.routing_target.clone(),
            config.targets.max_hops,
        )
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
    for d in crate::diagnosis::diagnose(&state) {
        let tag = d.layer.map_or("ok", |l| l.tag());
        println!("  diag [{tag}] {}", d.headline);
    }
    for m in [
        MetricId::Latency,
        MetricId::Loss,
        MetricId::Dns,
        MetricId::Routing,
        MetricId::Throughput,
        MetricId::Link,
        MetricId::TcpHandshake,
    ] {
        println!("  {:<16} {}", m.label(), badge(state.panel_health(m)));
    }
    if let (Some(rx), Some(tx)) = (state.iface.rx_errors, state.iface.tx_errors) {
        println!(
            "  {:<16} {}  ({rx} rx, {tx} tx)",
            MetricId::InterfaceErrors.label(),
            badge(state.iface.health_current())
        );
    }
    for (name, ep) in &state.tcp {
        let v = if ep.last_ok {
            format!("{:.0}ms", ep.connect_ms.latest().unwrap_or(0.0))
        } else {
            "REFUSED".into()
        };
        println!("  tcp  {name:<16} {v}");
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
        let integrity = if r.hijacked { "  HIJACK" } else { "" };
        println!("  dns  {name:<16} {v}{integrity}");
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
    // Broadcast wake channel: `r` (Action::ForceRefresh) pokes every probe at once.
    let (wake, _) = broadcast::channel::<()>(8);

    // Best-effort incident log; the dashboard still runs if it can't be opened.
    let mut log = RotatingLog::open_default();

    // Detect the default route: register the gateway (as a stricter-threshold ping target)
    // and record the interface / MTU / VPN facts.
    if let Some(info) = crate::net::detect_route_info() {
        if config.targets.gateway_auto
            && config.targets.gateway.is_none()
            && let Some(gw) = info.gateway.clone()
        {
            state.register_target(gw, true);
        }
        state.apply_route_info(&info);
    }

    let targets: Vec<String> = state.targets.keys().cloned().collect();
    let interval = config.cadence.ping();
    let timeout = Duration::from_millis(900).min(interval);

    // Real ICMP ping; fall back to the demo generator if a socket can't be created (so the
    // dashboard is still usable in restricted environments).
    let mut handles = Vec::new();
    match crate::metrics::ping::PingProbe::new(&targets, timeout) {
        Ok(probe) if probe.target_count() > 0 => {
            state.retain_targets(&probe.target_names());
            handles.push(spawn_probe(probe, interval, tx.clone(), &wake));
        }
        _ => handles.push(spawn_probe(
            DemoProbe::new(targets),
            interval,
            tx.clone(),
            &wake,
        )),
    }

    // DNS resolver comparison. Bound each lookup well under the cadence so a slow or
    // unreachable resolver can't stretch a tick past its interval and desync the panel.
    let dns_interval = Duration::from_millis(config.cadence.dns_ms);
    let dns_timeout = Duration::from_secs(2).min(dns_interval);
    let dns = crate::metrics::dns::DnsProbe::new(&config.resolvers, dns_timeout);
    if dns.resolver_count() > 0 {
        handles.push(spawn_probe(dns, dns_interval, tx.clone(), &wake));
    }

    // HTTP(S) reachability + captive/IPv6.
    handles.push(spawn_probe(
        crate::metrics::reachability::ReachabilityProbe::new(
            crate::metrics::reachability::ReachabilityProbe::default_endpoints(),
        ),
        Duration::from_millis(config.cadence.reachability_ms),
        tx.clone(),
        &wake,
    ));

    // Local NIC error counters — free, and the only probe that can blame your own hardware.
    handles.push(spawn_probe(
        crate::metrics::iface::InterfaceProbe::new(),
        Duration::from_millis(config.cadence.interface_ms),
        tx.clone(),
        &wake,
    ));

    // Is the resolver answering honestly? A different question from how fast it answers,
    // asked far less often, because a hijack is a configuration and not a condition.
    handles.push(spawn_probe(
        crate::metrics::dns::DnsIntegrityProbe::with_clock_seed(
            &config.resolvers,
            Duration::from_secs(2),
        ),
        Duration::from_millis(config.cadence.dns_integrity_ms),
        tx.clone(),
        &wake,
    ));

    // TCP handshake timing: what a real connection waits on, which ICMP cannot see. Slow
    // cadence — it opens a connection on someone else's host, so it stays occasional.
    handles.push(spawn_probe(
        crate::metrics::tcp::TcpProbe::new(
            crate::metrics::tcp::TcpProbe::default_endpoints(),
            Duration::from_secs(3),
        ),
        Duration::from_millis(config.cadence.tcp_ms),
        tx.clone(),
        &wake,
    ));

    // Passive throughput counters. The probe measures its own interval, so the cadence here
    // only decides how often it is asked, not how the rate is scaled.
    handles.push(spawn_probe(
        crate::metrics::throughput::ThroughputProbe::new(),
        Duration::from_millis(config.cadence.throughput_passive_ms),
        tx.clone(),
        &wake,
    ));

    // Active capacity probe (a bounded download on a slow cadence).
    handles.push(spawn_probe(
        crate::metrics::throughput::CapacityProbe::new(config.throughput.probe_url.clone()),
        Duration::from_millis(config.cadence.throughput_probe_ms),
        tx.clone(),
        &wake,
    ));

    // Public/WAN IP (for ISP-change detection), on a slow cadence.
    handles.push(spawn_probe(
        crate::metrics::pubip::PublicIpProbe::cloudflare(),
        Duration::from_millis(config.cadence.public_ip_ms),
        tx.clone(),
        &wake,
    ));

    // Wireless link (macOS system_profiler).
    handles.push(spawn_probe(
        crate::metrics::link::WifiProbe,
        Duration::from_millis(config.cadence.link_ms),
        tx.clone(),
        &wake,
    ));

    // Routing / path (lightweight traceroute).
    handles.push(spawn_probe(
        crate::metrics::routing::RoutingProbe::new(
            config.targets.routing_target.clone(),
            config.targets.max_hops,
        ),
        Duration::from_millis(config.cadence.routing_ms),
        tx.clone(),
        &wake,
    ));

    let mut reader = EventStream::new();
    let mut render_tick = tokio::time::interval(config.cadence.render());

    loop {
        tokio::select! {
            _ = render_tick.tick() => {
                // Advance the availability strip from the clock, not from samples: during a
                // total outage no samples arrive at all, and a strip that stops moving is
                // exactly the wrong thing to show when everything is down.
                state.tick(Utc::now());
                terminal.draw(|f| ui::render(f, &state))?;
            }
            maybe_event = reader.next() => {
                if let Some(Ok(Event::Key(key))) = maybe_event
                    && key.kind == KeyEventKind::Press
                {
                    // While the theme picker is open it is modal: route keys through it so
                    // ↑/↓ preview and Esc reverts instead of scrolling / quitting.
                    let action = if state.theme_picker.is_some() {
                        map_picker_key(key)
                    } else {
                        map_key(key)
                    };
                    if let Some(action) = action {
                        if action == Action::ForceRefresh {
                            // Ignore the error: no subscribers just means no probes running.
                            let _ = wake.send(());
                        }
                        state.apply_action(action);
                    }
                }
            }
            Some(sample) = rx.recv() => {
                if !state.paused {
                    for inc in state.apply_sample(Utc::now(), sample) {
                        if let Some(log) = log.as_mut()
                            && let Err(e) = log.append(&inc)
                        {
                            // Reported once, in-memory only: the sink we would log it to is
                            // the thing that just failed.
                            state.note_log_error(Utc::now(), &e.to_string());
                        }
                    }
                }
            }
        }
        if state.should_quit {
            break;
        }
    }

    // Stop the probes before returning. Aborting drops each task's future, which for the
    // shell-out probes kills any in-flight child (`run_capture` sets `kill_on_drop`), so an
    // in-progress `traceroute`/`system_profiler` can't stall shutdown while the runtime is
    // torn down.
    for handle in &handles {
        handle.abort();
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
        assert_eq!(
            map_key(key(KeyCode::Char('t'))),
            Some(Action::OpenThemePicker)
        );
    }

    #[test]
    fn picker_keys_drive_the_overlay() {
        // Preview navigation (arrows and vi keys).
        assert_eq!(
            map_picker_key(key(KeyCode::Up)),
            Some(Action::ThemePreviewUp)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Char('k'))),
            Some(Action::ThemePreviewUp)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Down)),
            Some(Action::ThemePreviewDown)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Char('j'))),
            Some(Action::ThemePreviewDown)
        );
        // Enter / t confirm; Esc / q cancel.
        assert_eq!(
            map_picker_key(key(KeyCode::Enter)),
            Some(Action::ThemePickerConfirm)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Char('t'))),
            Some(Action::ThemePickerConfirm)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Esc)),
            Some(Action::ThemePickerCancel)
        );
        assert_eq!(
            map_picker_key(key(KeyCode::Char('q'))),
            Some(Action::ThemePickerCancel)
        );
        // Ctrl-C still quits from within the picker; unrelated keys are swallowed.
        let ctrl_c = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(map_picker_key(ctrl_c), Some(Action::Quit));
        assert_eq!(map_picker_key(key(KeyCode::Char('p'))), None);
    }

    #[test]
    fn help_and_scroll_keys_map() {
        assert_eq!(map_key(key(KeyCode::Char('?'))), Some(Action::ToggleHelp));
        assert_eq!(map_key(key(KeyCode::Up)), Some(Action::ScrollUp));
        assert_eq!(map_key(key(KeyCode::Char('k'))), Some(Action::ScrollUp));
        assert_eq!(map_key(key(KeyCode::Down)), Some(Action::ScrollDown));
        assert_eq!(map_key(key(KeyCode::Char('j'))), Some(Action::ScrollDown));
        assert_eq!(map_key(key(KeyCode::PageUp)), Some(Action::ScrollPageUp));
        assert_eq!(
            map_key(key(KeyCode::PageDown)),
            Some(Action::ScrollPageDown)
        );
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
        let (wake, _) = broadcast::channel(1);
        let handle = spawn_probe(probe, Duration::from_millis(1), tx, &wake);
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

    /// A probe whose first `tick` overruns the interval, then returns instantly. Used to
    /// exercise the scheduler's missed-tick handling.
    struct SlowFirstProbe {
        first: bool,
        overrun: Duration,
    }

    impl Probe for SlowFirstProbe {
        fn tick(&mut self) -> impl Future<Output = Vec<Sample>> + Send {
            let slow = std::mem::take(&mut self.first);
            let overrun = self.overrun;
            async move {
                if slow {
                    tokio::time::sleep(overrun).await;
                }
                vec![Sample::Latency {
                    target: "x".into(),
                    rtt_ms: Some(1.0),
                }]
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn slow_tick_does_not_burst_missed_ticks() {
        // The first tick blocks for 10 periods. With the default `Burst` behavior the
        // scheduler would replay all ten missed ticks back-to-back at the same instant,
        // so the panel goes quiet and then jumps — the reported symptom. The fix
        // re-aligns to the cadence instead.
        let period = Duration::from_millis(100);
        let (tx, mut rx) = mpsc::channel(64);
        let (wake, _) = broadcast::channel(1);
        let start = tokio::time::Instant::now();
        let handle = spawn_probe(
            SlowFirstProbe {
                first: true,
                overrun: period * 10,
            },
            period,
            tx,
            &wake,
        );

        let mut stamps = Vec::new();
        for _ in 0..6 {
            rx.recv().await.unwrap();
            stamps.push(start.elapsed());
        }
        handle.abort();

        // Under a burst, all six samples land at ~t=10·period together. Re-aligned, the
        // later samples are spread across subsequent periods.
        let spread = stamps[5] - stamps[0];
        assert!(
            spread >= period * 3,
            "samples bursted instead of spreading across the cadence: {stamps:?}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wake_ticks_a_probe_before_its_next_interval() {
        // The routing probe runs once a minute. Pressing `r` has to mean something sooner
        // than that, or the key is decoration.
        let period = Duration::from_secs(60);
        let (tx, mut rx) = mpsc::channel(16);
        let (wake, _) = broadcast::channel(4);
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
        let handle = spawn_probe(probe, period, tx, &wake);

        // `tokio::time::interval` fires immediately, so this is the startup tick.
        rx.recv().await.unwrap();
        wake.send(()).unwrap();
        let forced = tokio::time::timeout(Duration::from_secs(1), rx.recv())
            .await
            .expect("a forced refresh must not wait out the 60s cadence")
            .unwrap();
        handle.abort();
        assert_eq!(
            forced,
            Sample::Latency {
                target: "gw".into(),
                rtt_ms: Some(2.0)
            }
        );
    }

    #[tokio::test(start_paused = true)]
    async fn wake_resets_the_cadence_instead_of_double_ticking() {
        // A manual refresh should restart the clock, not leave a scheduled tick pending
        // right behind it — otherwise `r` costs two probe runs back to back.
        let period = Duration::from_secs(10);
        let (tx, mut rx) = mpsc::channel(16);
        let (wake, _) = broadcast::channel(4);
        let handle = spawn_probe(
            crate::metrics::FakeProbe::new(std::iter::repeat_n(
                vec![Sample::Latency {
                    target: "gw".into(),
                    rtt_ms: Some(1.0),
                }],
                8,
            )),
            period,
            tx,
            &wake,
        );

        rx.recv().await.unwrap(); // startup tick at t=0
        tokio::time::sleep(period / 2).await; // t=5s
        wake.send(()).unwrap();
        rx.recv().await.unwrap(); // the forced tick

        // The cadence restarted at t=5s, so the next scheduled tick is t=15s — nothing
        // should arrive in the 9s that follow the refresh.
        assert!(
            tokio::time::timeout(period - Duration::from_secs(1), rx.recv())
                .await
                .is_err(),
            "a scheduled tick fired immediately after the forced one"
        );
        handle.abort();
    }

    #[tokio::test]
    async fn scheduler_stops_when_receiver_dropped() {
        let (tx, rx) = mpsc::channel(1);
        let probe = crate::metrics::FakeProbe::new(vec![vec![Sample::Latency {
            target: "gw".into(),
            rtt_ms: Some(1.0),
        }]]);
        let (wake, _) = broadcast::channel(1);
        let handle = spawn_probe(probe, Duration::from_millis(1), tx, &wake);
        drop(rx);
        // The task should finish on its own once sends start failing.
        let _ = tokio::time::timeout(Duration::from_millis(200), handle).await;
    }
}
