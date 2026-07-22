//! Dashboard panels and the top-level layout.
//!
//! Each panel is a `pub fn(frame, area, &AppState)` so it can be rendered — and
//! asserted on — in isolation with a `TestBackend`. [`render`] composes them into the
//! full-screen grid (designed for ~222×56 but computed from the real frame size).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, List, ListItem, Paragraph};

use crate::app::AppState;
use crate::health::Health;
use crate::metrics::MetricId;
use crate::ui::theme;
use crate::ui::widgets::{LineSeries, line_chart, metric_block};

/// Split a panel's inner area into a fixed-height summary region and a chart region below.
/// The chart region is `None` when there isn't enough height to draw a useful line graph.
fn summary_and_chart(inner: Rect, summary_rows: u16) -> (Rect, Option<Rect>) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(summary_rows), Constraint::Min(0)])
        .split(inner);
    let chart = (rows[1].height >= 3).then_some(rows[1]);
    (rows[0], chart)
}

/// Compute `(x_max, y_max)` for a set of series, with `y_max` never below `y_floor`.
fn chart_bounds(series: &[LineSeries], y_floor: f64) -> (f64, f64) {
    let x_max = series
        .iter()
        .map(|s| s.points.len())
        .max()
        .unwrap_or(1)
        .saturating_sub(1) as f64;
    let y_max = series
        .iter()
        .flat_map(|s| s.points.iter().map(|p| p.1))
        .fold(y_floor, f64::max);
    (x_max, y_max)
}

/// Render the whole dashboard.
pub fn render(frame: &mut Frame, state: &AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(5), // diagnosis: what's wrong (worst-first verdicts)
            Constraint::Length(4), // detail band: link | routing (2 content rows + border)
            Constraint::Min(0),    // metric grid (2×2 charts)
            Constraint::Length(6), // events
            Constraint::Length(1), // footer
        ])
        .split(frame.area());

    header(frame, root[0], state);
    diagnosis(frame, root[1], state);

    // Detail band — two compact, text-only panels side by side.
    let detail = halves(root[2]);
    link(frame, detail[0], state);
    routing(frame, detail[1], state);

    // Metric grid — the four chart panels in a roomy 2×2.
    let bands = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root[3]);
    let top = halves(bands[0]);
    let bottom = halves(bands[1]);

    latency(frame, top[0], state);
    dns(frame, top[1], state);

    loss(frame, bottom[0], state);
    throughput(frame, bottom[1], state);

    events(frame, root[4], state);
    footer(frame, root[5], state);

    // The help overlay draws on top of everything when toggled.
    if state.show_help {
        help_overlay(frame, frame.area(), state);
    }
}

/// A centered rectangle of at most `width`×`height` within `area`.
fn centered_rect(area: Rect, width: u16, height: u16) -> Rect {
    let w = width.min(area.width);
    let h = height.min(area.height);
    Rect {
        x: area.x + (area.width - w) / 2,
        y: area.y + (area.height - h) / 2,
        width: w,
        height: h,
    }
}

/// Keybinding help, drawn as a centered overlay (toggled with `?`).
pub fn help_overlay(frame: &mut Frame, area: Rect, state: &AppState) {
    let rows = [
        "q / Esc     quit",
        "p           pause / resume",
        "r           force refresh",
        "c           clear events",
        "t           cycle theme",
        "↑ / ↓  k/j  scroll events",
        "PgUp/PgDn   page events",
        "?           toggle this help",
    ];
    let rect = centered_rect(area, 34, rows.len() as u16 + 2);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" HELP ")
        .border_style(Style::default().fg(state.theme.accent));
    let lines: Vec<Line> = rows.iter().map(|r| Line::from(*r)).collect();
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

fn halves(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area)
}

/// Header banner: app name, overall health, the top verdict, and status fields.
pub fn header(frame: &mut Frame, area: Rect, state: &AppState) {
    let overall = state.overall_health();
    let color = state.theme.health_color(overall);
    let mut spans = vec![
        Span::styled("NetPulse", Style::default().fg(state.theme.accent).bold()),
        Span::raw("  "),
        Span::styled(
            theme::health_symbol(overall),
            Style::default().fg(color).bold(),
        ),
        Span::raw(" "),
        Span::styled(
            theme::health_label(overall),
            Style::default().fg(color).bold(),
        ),
    ];
    // Name the culprit inline when there is one, so the header says *what* — not just *that*.
    if let Some(top) = crate::diagnosis::diagnose(state).first()
        && top.severity > Health::Ok
    {
        spans.push(Span::raw("  "));
        spans.push(Span::styled(
            top.headline.clone(),
            Style::default().fg(color).bold(),
        ));
    }
    spans.push(Span::raw(format!("   targets: {}", state.targets.len())));
    if let Some(ip) = &state.public_ip {
        spans.push(Span::raw(format!("   wan {ip}")));
    }
    spans.push(Span::raw(if state.paused { "   [PAUSED]" } else { "" }));
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(overall));
    frame.render_widget(Paragraph::new(Line::from(spans)).block(block), area);
}

/// Top "what's wrong" panel: the worst-first, localized verdicts from the diagnosis engine.
/// This is the at-a-glance answer — the border and each verdict carry the health color, and
/// the healthy state renders a single "No problems detected" line.
pub fn diagnosis(frame: &mut Frame, area: Rect, state: &AppState) {
    let verdicts = crate::diagnosis::diagnose(state);
    let worst = verdicts.first().map_or(Health::Ok, |d| d.severity);
    let block = metric_block("DIAGNOSIS", worst, &state.theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items: Vec<ListItem> = verdicts
        .iter()
        .take(inner.height as usize)
        .map(|d| {
            let color = state.theme.health_color(d.severity);
            let tag = d.layer.map_or("OK", |l| l.tag());
            let mut spans = vec![
                Span::styled(theme::health_symbol(d.severity), Style::default().fg(color)),
                Span::raw(" "),
                Span::styled(format!("[{tag}]"), Style::default().fg(color).bold()),
                Span::raw(" "),
                Span::raw(d.headline.clone()),
            ];
            if let Some(ev) = d.evidence.first() {
                spans.push(Span::styled(
                    format!("  ({ev})"),
                    Style::default().fg(state.theme.muted),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    frame.render_widget(List::new(items), inner);
}

/// Latency & jitter panel: sparkline + stats for the first internet target.
pub fn latency(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "LATENCY & JITTER",
        state.panel_health(MetricId::Latency),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some((name, t)) = state.targets.iter().next() else {
        return;
    };
    let (summary, chart) = summary_and_chart(inner, 1);

    let cur = t.latency_ms.latest().unwrap_or(0.0);
    let avg = t.latency_ms.mean().unwrap_or(0.0);
    let max = t.latency_ms.max().unwrap_or(0.0);
    let jit = t.latency_ms.jitter().unwrap_or(0.0);
    let stat = Line::from(format!(
        "{name}  cur {cur:.0}ms  avg {avg:.0}ms  max {max:.0}ms  jitter {jit:.0}ms"
    ));
    frame.render_widget(Paragraph::new(stat), summary);

    if let Some(area) = chart {
        let series = vec![LineSeries::from_values(
            name.clone(),
            state.theme.accent,
            &t.latency_ms.values(),
        )];
        let (x_max, y_max) = chart_bounds(&series, 20.0); // at least 0–20ms
        frame.render_widget(
            line_chart(
                &series,
                x_max,
                [0.0, y_max],
                vec!["0".into(), format!("{y_max:.0}ms")],
            ),
            area,
        );
    }
}

/// Packet-loss panel: one line per target with its loss %.
pub fn loss(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "PACKET LOSS",
        state.panel_health(MetricId::Loss),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.targets.is_empty() {
        return;
    }
    let (summary, chart) = summary_and_chart(inner, state.targets.len() as u16);

    let items: Vec<ListItem> = state
        .targets
        .iter()
        .map(|(name, t)| {
            let pct = t.loss.loss_pct();
            let color = state.theme.health_color(t.loss_health_current());
            ListItem::new(Line::from(vec![
                Span::raw(format!("{name:<16} ")),
                Span::styled(format!("{pct:>5.1}%"), Style::default().fg(color)),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), summary);

    if let Some(area) = chart {
        let series: Vec<LineSeries> = state
            .targets
            .iter()
            .enumerate()
            .map(|(i, (name, t))| {
                LineSeries::from_values(
                    name.clone(),
                    state.theme.series_color(i),
                    &t.loss_history.values(),
                )
            })
            .collect();
        let (x_max, y_max) = chart_bounds(&series, 5.0); // always show at least 0–5%
        frame.render_widget(
            line_chart(
                &series,
                x_max,
                [0.0, y_max],
                vec!["0".into(), format!("{y_max:.0}%")],
            ),
            area,
        );
    }
}

/// DNS panel: one row per resolver with latency and status.
pub fn dns(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "DNS HEALTH",
        state.panel_health(MetricId::Dns),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.resolvers.is_empty() {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "resolving…",
                Style::default().fg(state.theme.muted),
            )),
            inner,
        );
        return;
    }
    let (summary, chart) = summary_and_chart(inner, state.resolvers.len() as u16);
    let items: Vec<ListItem> = state
        .resolvers
        .iter()
        .map(|(name, r)| {
            let (text, color) = if r.last_ok {
                (
                    format!("{:.0}ms", r.latency_ms.latest().unwrap_or(0.0)),
                    state.theme.ok,
                )
            } else {
                ("FAIL".to_string(), state.theme.crit)
            };
            ListItem::new(Line::from(vec![
                Span::raw(format!("{name:<12} ")),
                Span::styled(format!("{text:>8}"), Style::default().fg(color)),
            ]))
        })
        .collect();
    frame.render_widget(List::new(items), summary);

    if let Some(area) = chart {
        let series: Vec<LineSeries> = state
            .resolvers
            .iter()
            .enumerate()
            .map(|(i, (name, r))| {
                LineSeries::from_values(
                    name.clone(),
                    state.theme.series_color(i),
                    &r.latency_ms.values(),
                )
            })
            .collect();
        let (x_max, y_max) = chart_bounds(&series, 50.0); // at least 0–50ms
        frame.render_widget(
            line_chart(
                &series,
                x_max,
                [0.0, y_max],
                vec!["0".into(), format!("{y_max:.0}ms")],
            ),
            area,
        );
    }
}

/// Link & reachability panel: wireless signal + endpoint checklist.
pub fn link(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "LINK & REACHABILITY",
        state.panel_health(MetricId::Link),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let ssid = state.link.ssid.clone().unwrap_or_else(|| "—".to_string());
    let rssi = state
        .link
        .rssi_dbm
        .map(|v| format!("{v:.0} dBm"))
        .unwrap_or_else(|| "—".into());

    // Signal quality (SNR) and negotiated rate — the clearest "Wi-Fi is slow" signals.
    let mut wifi_parts = vec![format!("WiFi  {ssid}"), rssi];
    if let (Some(r), Some(n)) = (state.link.rssi_dbm, state.link.noise_dbm) {
        wifi_parts.push(format!("SNR {:.0} dB", r - n));
    }
    if let Some(tx) = state.link.tx_rate {
        wifi_parts.push(format!("{tx:.0} Mbps"));
    }
    if let Some(iface) = &state.interface {
        wifi_parts.push(iface.clone());
    }
    if let Some(mtu) = state.mtu {
        wifi_parts.push(format!("MTU {mtu}"));
    }
    if state.vpn {
        wifi_parts.push("VPN".into());
    }

    // Endpoint checklist packed onto a single line to fit the compact band.
    let mut spans = Vec::new();
    for (endpoint, r) in &state.reachability {
        let (glyph, color) = if r.ok {
            ("✓", state.theme.ok)
        } else {
            ("✗", state.theme.crit)
        };
        spans.push(Span::raw(format!("{endpoint} ")));
        spans.push(Span::styled(glyph, Style::default().fg(color)));
        spans.push(Span::raw("  "));
    }

    let lines = vec![Line::from(wifi_parts.join("   ")), Line::from(spans)];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Routing panel: hop count, reachability, and route-change status.
pub fn routing(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "ROUTING & PATH",
        state.panel_health(MetricId::Routing),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if !state.routing.seen {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "tracing…",
                Style::default().fg(state.theme.muted),
            )),
            inner,
        );
        return;
    }
    let r = &state.routing;
    let (status, color) = if !r.reachable {
        ("unreachable", state.theme.crit)
    } else if r.changed {
        ("route changed", state.theme.warn)
    } else {
        ("stable", state.theme.ok)
    };
    // Per-hop detail: the path RTT when reachable, or where it dies when not.
    let hop_info = if r.reachable {
        r.detail
            .last()
            .and_then(|h| h.min_rtt_ms)
            .map(|ms| format!("  {ms:.0}ms"))
            .unwrap_or_default()
    } else {
        r.detail
            .iter()
            .rposition(|h| h.addr != "*")
            .map(|i| format!("  stops @ hop {} ({})", i + 1, r.detail[i].addr))
            .unwrap_or_default()
    };
    let lines = vec![
        Line::from(format!("hops: {}{}", r.hops, hop_info)),
        Line::from(vec![
            Span::raw("path: "),
            Span::styled(status, Style::default().fg(color)),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Throughput panel: passive rx/tx rates + last capacity-probe result.
pub fn throughput(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "THROUGHPUT",
        state.panel_health(MetricId::Throughput),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let rx = state
        .throughput
        .rx_bps
        .as_ref()
        .and_then(|s| s.latest())
        .unwrap_or(0.0);
    let tx = state
        .throughput
        .tx_bps
        .as_ref()
        .and_then(|s| s.latest())
        .unwrap_or(0.0);
    let probe = state
        .throughput
        .last_mbps
        .map(|m| format!("{m:.0} Mbps"))
        .unwrap_or_else(|| "—".into());
    // Append the bufferbloat delta (added latency under load) when measured.
    let probe_line = match (
        state.throughput.idle_latency_ms,
        state.throughput.loaded_latency_ms,
    ) {
        (Some(i), Some(l)) => format!("probe: {probe}   load +{:.0}ms", (l - i).max(0.0)),
        _ => format!("probe: {probe}"),
    };
    let (summary, chart) = summary_and_chart(inner, 3);
    let lines = vec![
        Line::from(vec![
            Span::styled("▼ rx ", Style::default().fg(state.theme.rx)),
            Span::raw(human_rate(rx)),
        ]),
        Line::from(vec![
            Span::styled("▲ tx ", Style::default().fg(state.theme.tx)),
            Span::raw(human_rate(tx)),
        ]),
        Line::from(probe_line),
    ];
    frame.render_widget(Paragraph::new(lines), summary);

    if let Some(area) = chart {
        let mut series = Vec::new();
        if let Some(s) = &state.throughput.rx_bps {
            series.push(LineSeries::from_values("rx", state.theme.rx, &s.values()));
        }
        if let Some(s) = &state.throughput.tx_bps {
            series.push(LineSeries::from_values("tx", state.theme.tx, &s.values()));
        }
        let (x_max, y_max) = chart_bounds(&series, 1.0);
        frame.render_widget(
            line_chart(
                &series,
                x_max,
                [0.0, y_max],
                vec!["0".into(), human_rate(y_max)],
            ),
            area,
        );
    }
}

/// Format a bytes-per-second rate compactly.
fn human_rate(bps: f64) -> String {
    if bps >= 1_000_000.0 {
        format!("{:.1} MB/s", bps / 1_000_000.0)
    } else if bps >= 1_000.0 {
        format!("{:.1} KB/s", bps / 1_000.0)
    } else {
        format!("{bps:.0} B/s")
    }
}

/// Recent incident feed (newest first).
pub fn events(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" EVENTS ")
        .border_style(Style::default().fg(state.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let items: Vec<ListItem> = state
        .events
        .iter()
        .skip(state.events_scroll)
        .take(inner.height as usize)
        .map(|inc| {
            let color = state.theme.health_color(inc.severity);
            let mut spans = vec![
                Span::styled(
                    inc.ts.format("%H:%M:%S").to_string(),
                    Style::default().fg(state.theme.muted),
                ),
                Span::raw(" "),
                Span::styled(
                    theme::health_symbol(inc.severity),
                    Style::default().fg(color),
                ),
                Span::raw(" "),
                Span::raw(inc.message.clone()),
            ];
            // Surface the threshold that was crossed — logged but previously never shown.
            if let Some(thr) = inc.threshold {
                spans.push(Span::styled(
                    format!("  · thr {thr:.0}{}", inc.unit),
                    Style::default().fg(state.theme.muted),
                ));
            }
            ListItem::new(Line::from(spans))
        })
        .collect();
    let content = if items.is_empty() {
        List::new(vec![ListItem::new(Line::from(Span::styled(
            "no incidents recorded",
            Style::default().fg(state.theme.muted),
        )))])
    } else {
        List::new(items)
    };
    frame.render_widget(content, inner);
}

/// Keybind hint bar.
pub fn footer(frame: &mut Frame, area: Rect, state: &AppState) {
    let hint = Line::from(vec![Span::styled(
        " q quit · r refresh · p pause · c clear events · t theme · ? help ",
        Style::default().fg(state.theme.muted),
    )]);
    frame.render_widget(Paragraph::new(hint), area);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::health::Health;
    use crate::metrics::{Hop, Sample};
    use crate::ui::theme::Theme;
    use chrono::{TimeZone, Utc};
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;

    fn test_state() -> AppState {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = None;
        c.thresholds.debounce_samples = 1;
        c.thresholds.loss_window = 4;
        AppState::new(c)
    }

    /// Concatenate the whole buffer into a searchable string.
    fn buffer_text(term: &Terminal<TestBackend>) -> String {
        let buf = term.backend().buffer();
        let area = *buf.area();
        let mut s = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                s.push_str(buf[(x, y)].symbol());
            }
            s.push('\n');
        }
        s
    }

    /// True if any cell holds a braille glyph — i.e. a line chart drew a line.
    fn has_braille(term: &Terminal<TestBackend>) -> bool {
        buffer_text(term)
            .chars()
            .any(|c| ('\u{2800}'..='\u{28FF}').contains(&c))
    }

    /// The x of the rightmost cell holding a plotted-graph glyph — braille (line chart) or
    /// block bar (sparkline) — anywhere in the buffer, or `None` if nothing was plotted.
    /// Used to check a chart spans the full width of its panel rather than underfilling it.
    fn rightmost_graph_column(term: &Terminal<TestBackend>) -> Option<u16> {
        let buf = term.backend().buffer();
        let area = *buf.area();
        let is_graph = |s: &str| {
            s.chars().any(|c| {
                ('\u{2800}'..='\u{28FF}').contains(&c)   // braille (line_chart)
                    || ('\u{2581}'..='\u{2588}').contains(&c) // block bars (sparkline)
            })
        };
        let mut rightmost = None;
        for y in 0..area.height {
            for x in 0..area.width {
                if is_graph(buf[(x, y)].symbol()) {
                    rightmost = Some(rightmost.map_or(x, |r: u16| r.max(x)));
                }
            }
        }
        rightmost
    }

    #[test]
    fn loss_panel_draws_line_graph() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        // Vary loss so the line isn't trivially flat.
        for ok in [true, false, true, true, false, true] {
            state.apply_sample(
                now,
                Sample::Latency {
                    target: "1.1.1.1".into(),
                    rtt_ms: ok.then_some(20.0),
                },
            );
        }
        let mut term = Terminal::new(TestBackend::new(60, 16)).unwrap();
        term.draw(|f| loss(f, f.area(), &state)).unwrap();
        assert!(has_braille(&term), "loss panel should draw a line graph");
    }

    #[test]
    fn dns_panel_draws_line_graph() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for ms in [10.0, 40.0, 25.0, 60.0, 30.0] {
            state.apply_sample(
                now,
                Sample::Dns {
                    resolver: "system".into(),
                    latency_ms: Some(ms),
                },
            );
        }
        let mut term = Terminal::new(TestBackend::new(60, 16)).unwrap();
        term.draw(|f| dns(f, f.area(), &state)).unwrap();
        assert!(has_braille(&term), "dns panel should draw a line graph");
    }

    #[test]
    fn throughput_panel_draws_line_graph() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for rx in [1.0e6, 2.0e6, 0.5e6, 3.0e6, 1.5e6] {
            state.apply_sample(
                now,
                Sample::Throughput {
                    rx_bps: rx,
                    tx_bps: rx / 4.0,
                },
            );
        }
        let mut term = Terminal::new(TestBackend::new(60, 16)).unwrap();
        term.draw(|f| throughput(f, f.area(), &state)).unwrap();
        assert!(
            has_braille(&term),
            "throughput panel should draw a line graph"
        );
    }

    #[test]
    fn latency_panel_graph_spans_full_width() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        // A handful of points — far fewer than the panel is wide. A left-aligned sparkline
        // would fill only the first few columns; a line chart spans the whole frame.
        for ms in [10.0, 40.0, 25.0, 60.0, 30.0, 45.0] {
            state.apply_sample(
                now,
                Sample::Latency {
                    target: "1.1.1.1".into(),
                    rtt_ms: Some(ms),
                },
            );
        }
        let width = 60u16;
        let mut term = Terminal::new(TestBackend::new(width, 16)).unwrap();
        term.draw(|f| latency(f, f.area(), &state)).unwrap();

        let rightmost = rightmost_graph_column(&term).expect("latency graph should render");
        assert!(
            rightmost >= width - 4,
            "latency graph stops at column {rightmost} of {width}; it should span the frame"
        );
    }

    #[test]
    fn full_dashboard_renders_at_222x56() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("NetPulse"));
        assert!(text.contains("DIAGNOSIS"));
        assert!(text.contains("LATENCY & JITTER"));
        assert!(text.contains("PACKET LOSS"));
        assert!(text.contains("DNS HEALTH"));
        assert!(text.contains("THROUGHPUT"));
        assert!(text.contains("EVENTS"));
    }

    /// Drive a state into a "system resolver failing, public resolvers fine, connectivity OK"
    /// condition — the classic DNS-config problem the diagnosis engine should name.
    fn dns_problem_state() -> AppState {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = Some("192.168.1.1".into());
        c.targets.gateway_auto = false;
        c.thresholds.debounce_samples = 1;
        let mut state = AppState::new(c);
        let now = Utc.with_ymd_and_hms(2026, 7, 22, 12, 0, 0).unwrap();
        for _ in 0..2 {
            state.apply_sample(
                now,
                Sample::Latency {
                    target: "192.168.1.1".into(),
                    rtt_ms: Some(3.0),
                },
            );
            state.apply_sample(
                now,
                Sample::Latency {
                    target: "1.1.1.1".into(),
                    rtt_ms: Some(20.0),
                },
            );
            state.apply_sample(
                now,
                Sample::Dns {
                    resolver: "system".into(),
                    latency_ms: None,
                },
            );
            state.apply_sample(
                now,
                Sample::Dns {
                    resolver: "cloudflare".into(),
                    latency_ms: Some(15.0),
                },
            );
            state.apply_sample(
                now,
                Sample::Dns {
                    resolver: "google".into(),
                    latency_ms: Some(18.0),
                },
            );
        }
        state
    }

    #[test]
    fn diagnosis_panel_names_the_problem() {
        let state = dns_problem_state();
        let mut term = Terminal::new(TestBackend::new(120, 8)).unwrap();
        term.draw(|f| diagnosis(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("DIAGNOSIS"), "panel title missing: {text}");
        assert!(text.contains("DNS"), "should name the DNS layer: {text}");
        assert!(
            text.to_lowercase().contains("configured") || text.to_lowercase().contains("public"),
            "should describe the configured-DNS problem: {text}"
        );
    }

    #[test]
    fn diagnosis_panel_border_goes_red_on_a_crit_problem() {
        let state = dns_problem_state(); // failed lookup => Crit
        let mut term = Terminal::new(TestBackend::new(120, 8)).unwrap();
        term.draw(|f| diagnosis(f, f.area(), &state)).unwrap();
        let buf = term.backend().buffer();
        let crit = Theme::default().crit;
        // The top-left border corner carries the panel's health color.
        assert_eq!(
            buf[(0, 0)].fg,
            crit,
            "crit diagnosis should paint the border red"
        );
    }

    #[test]
    fn diagnosis_panel_healthy_reports_no_problems() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(120, 8)).unwrap();
        term.draw(|f| diagnosis(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("No problems detected"),
            "healthy state should say so: {text}"
        );
    }

    #[test]
    fn header_appends_the_top_verdict() {
        let state = dns_problem_state();
        let mut term = Terminal::new(TestBackend::new(180, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("NetPulse"), "header identity: {text}");
        assert!(
            text.to_lowercase().contains("dns"),
            "header should name the culprit, not just the severity word: {text}"
        );
    }

    #[test]
    fn detail_band_holds_link_and_routing() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let buf = term.backend().buffer();
        let area = *buf.area();
        // Text of the detail band region: header (3) + diagnosis (5) = rows 0..8, then the
        // link | routing detail band (4 rows) at rows 8..12.
        let mut band = String::new();
        for y in 8..12 {
            for x in 0..area.width {
                band.push_str(buf[(x, y)].symbol());
            }
            band.push('\n');
        }
        assert!(
            band.contains("LINK & REACHABILITY"),
            "link should sit in the top band: {band}"
        );
        assert!(
            band.contains("ROUTING & PATH"),
            "routing should sit in the top band: {band}"
        );

        // The four chart panels and events still render below.
        let all = buffer_text(&term);
        for title in [
            "LATENCY & JITTER",
            "DNS HEALTH",
            "PACKET LOSS",
            "THROUGHPUT",
            "EVENTS",
        ] {
            assert!(all.contains(title), "missing panel: {title}");
        }
    }

    #[test]
    fn help_overlay_renders_when_toggled() {
        let mut state = test_state();
        state.show_help = true;
        let mut term = Terminal::new(TestBackend::new(120, 40)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("HELP"), "overlay title should show: {text}");
        assert!(
            text.contains("cycle theme"),
            "overlay body should show keys"
        );
    }

    #[test]
    fn events_feed_shows_threshold_detail() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        // Drive a latency crit so an incident with a threshold is logged.
        for _ in 0..3 {
            state.apply_sample(
                now,
                Sample::Latency {
                    target: "1.1.1.1".into(),
                    rtt_ms: Some(500.0),
                },
            );
        }
        let mut term = Terminal::new(TestBackend::new(120, 8)).unwrap();
        term.draw(|f| events(f, f.area(), &state)).unwrap();
        assert!(
            buffer_text(&term).contains("thr"),
            "events should surface the crossed threshold"
        );
    }

    #[test]
    fn header_shows_public_ip_when_known() {
        let mut state = test_state();
        state.public_ip = Some("203.0.113.7".into());
        let mut term = Terminal::new(TestBackend::new(120, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        assert!(
            buffer_text(&term).contains("wan 203.0.113.7"),
            "header should show the WAN IP"
        );
    }

    #[test]
    fn link_panel_shows_interface_mtu_and_vpn() {
        let mut state = test_state();
        state.interface = Some("utun3".into());
        state.mtu = Some(1400);
        state.vpn = true;
        let mut term = Terminal::new(TestBackend::new(80, 8)).unwrap();
        term.draw(|f| link(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("utun3"), "should show interface: {text}");
        assert!(text.contains("MTU 1400"), "should show MTU: {text}");
        assert!(text.contains("VPN"), "should badge VPN: {text}");
    }

    #[test]
    fn header_shows_healthy_by_default() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(80, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        assert!(buffer_text(&term).contains("HEALTHY"));
    }

    #[test]
    fn header_shows_problem_when_crit() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        // debounce 1 => one drop (25% > crit 5%) commits Crit immediately.
        state.apply_sample(
            now,
            Sample::Latency {
                target: "1.1.1.1".into(),
                rtt_ms: None,
            },
        );
        assert_eq!(state.overall_health(), Health::Crit);
        let mut term = Terminal::new(TestBackend::new(80, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        assert!(buffer_text(&term).contains("PROBLEM"));
    }

    #[test]
    fn loss_panel_border_turns_red_when_crit() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Latency {
                target: "1.1.1.1".into(),
                rtt_ms: None,
            },
        );
        let mut term = Terminal::new(TestBackend::new(40, 10)).unwrap();
        term.draw(|f| loss(f, f.area(), &state)).unwrap();
        // top-left border corner should be red
        assert_eq!(term.backend().buffer()[(0, 0)].fg, Color::Red);
    }

    #[test]
    fn dns_panel_shows_resolver_latency_and_fail() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Dns {
                resolver: "cloudflare".into(),
                latency_ms: Some(19.0),
            },
        );
        state.apply_sample(
            now,
            Sample::Dns {
                resolver: "google".into(),
                latency_ms: None,
            },
        );
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| dns(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("cloudflare"));
        assert!(text.contains("19ms"));
        assert!(text.contains("FAIL"));
    }

    #[test]
    fn link_panel_shows_ssid_and_endpoints() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Link {
                rssi_dbm: Some(-45.0),
                noise_dbm: Some(-90.0),
                tx_rate: Some(866.0),
                ssid: Some("MyNet".into()),
            },
        );
        state.apply_sample(
            now,
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        state.apply_sample(
            now,
            Sample::Reachability {
                endpoint: "ipv6".into(),
                ok: false,
            },
        );
        let mut term = Terminal::new(TestBackend::new(60, 8)).unwrap();
        term.draw(|f| link(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("MyNet"));
        assert!(text.contains("-45 dBm"));
        // SNR (−45 − −90 = 45 dB) and negotiated rate are surfaced, not discarded.
        assert!(text.contains("SNR 45 dB"), "should show SNR: {text}");
        assert!(text.contains("866 Mbps"), "should show Tx rate: {text}");
        // Endpoints render together on a single compact row (band layout).
        let buf = term.backend().buffer();
        let area = *buf.area();
        let mut endpoints_share_a_row = false;
        for y in 0..area.height {
            let mut row = String::new();
            for x in 0..area.width {
                row.push_str(buf[(x, y)].symbol());
            }
            if row.contains("http") && row.contains("ipv6") {
                endpoints_share_a_row = true;
            }
        }
        assert!(
            endpoints_share_a_row,
            "endpoints should share one row: {text}"
        );
    }

    #[test]
    fn routing_panel_shows_hops_and_status() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Routing {
                target: "1.1.1.1".into(),
                hops: 8,
                reachable: true,
                changed: false,
                detail: vec![
                    Hop {
                        addr: "192.168.1.1".into(),
                        min_rtt_ms: Some(1.0),
                        loss_pct: 0.0,
                    },
                    Hop {
                        addr: "1.1.1.1".into(),
                        min_rtt_ms: Some(12.0),
                        loss_pct: 0.0,
                    },
                ],
            },
        );
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("hops: 8"), "text: {text}");
        assert!(text.contains("stable"));
        // The final-hop RTT is surfaced now that we parse per-hop timings.
        assert!(text.contains("12ms"), "should show final-hop RTT: {text}");
    }

    #[test]
    fn throughput_panel_shows_rates() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Throughput {
                rx_bps: 2_000_000.0,
                tx_bps: 500_000.0,
            },
        );
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| throughput(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("2.0 MB/s"), "text: {text}");
        assert!(text.contains("500.0 KB/s"));
    }

    #[test]
    fn events_panel_shows_placeholder_when_empty() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(60, 8)).unwrap();
        term.draw(|f| events(f, f.area(), &state)).unwrap();
        assert!(buffer_text(&term).contains("no incidents"));
    }

    #[test]
    fn header_title_uses_active_theme_accent() {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = None;
        c.ui.theme = "cybercity_night".into();
        let state = AppState::new(c);
        let mut term = Terminal::new(TestBackend::new(80, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        // "NetPulse" begins just inside the top-left border; it's styled with the accent.
        let accent = Theme::resolve("cybercity_night").accent;
        assert_eq!(term.backend().buffer()[(1, 1)].symbol(), "N");
        assert_eq!(term.backend().buffer()[(1, 1)].fg, accent);
        // Sanity: this differs from the default theme's accent, so theming really took effect.
        assert_ne!(accent, Theme::default_theme().accent);
    }
}
