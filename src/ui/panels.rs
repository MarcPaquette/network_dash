//! Dashboard panels and the top-level layout.
//!
//! Each panel is a `pub fn(frame, area, &AppState)` so it can be rendered — and
//! asserted on — in isolation with a `TestBackend`. [`render`] composes them into the
//! full-screen grid (designed for ~222×56 but computed from the real frame size).

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph};

use crate::app::AppState;
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
            Constraint::Length(4), // detail band: link | routing (2 content rows + border)
            Constraint::Min(0),    // metric grid (2×2 charts)
            Constraint::Length(6), // events
            Constraint::Length(1), // footer
        ])
        .split(frame.area());

    header(frame, root[0], state);

    // Detail band — two compact, text-only panels side by side.
    let detail = halves(root[1]);
    link(frame, detail[0], state);
    routing(frame, detail[1], state);

    // Metric grid — the four chart panels in a roomy 2×2.
    let bands = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root[2]);
    let top = halves(bands[0]);
    let bottom = halves(bands[1]);

    latency(frame, top[0], state);
    dns(frame, top[1], state);

    loss(frame, bottom[0], state);
    throughput(frame, bottom[1], state);

    events(frame, root[3], state);
    footer(frame, root[4], state);
}

fn halves(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area)
}

/// Header banner: app name, overall health, and status fields.
pub fn header(frame: &mut Frame, area: Rect, state: &AppState) {
    let overall = state.overall_health();
    let color = state.theme.health_color(overall);
    let line = Line::from(vec![
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
        Span::raw(format!("   targets: {}", state.targets.len())),
        Span::raw(if state.paused { "   [PAUSED]" } else { "" }),
    ]);
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(state.theme.border_style(overall));
    frame.render_widget(Paragraph::new(line).block(block), area);
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

    let lines = vec![
        Line::from(format!("WiFi  {ssid}   {rssi}")),
        Line::from(spans),
    ];
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
    let lines = vec![
        Line::from(format!("hops: {}", r.hops)),
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
        Line::from(format!("probe: {probe}")),
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
        .take(inner.height as usize)
        .map(|inc| {
            let color = state.theme.health_color(inc.severity);
            ListItem::new(Line::from(vec![
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
            ]))
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
    use crate::metrics::Sample;
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
        assert!(text.contains("LATENCY & JITTER"));
        assert!(text.contains("PACKET LOSS"));
        assert!(text.contains("DNS HEALTH"));
        assert!(text.contains("THROUGHPUT"));
        assert!(text.contains("EVENTS"));
    }

    #[test]
    fn detail_band_holds_link_and_routing() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let buf = term.backend().buffer();
        let area = *buf.area();
        // Text of just the top band region: header (3 rows) + detail band (4 rows).
        let mut band = String::new();
        for y in 0..7 {
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
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| link(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("MyNet"));
        assert!(text.contains("-45 dBm"));
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
            },
        );
        let mut term = Terminal::new(TestBackend::new(40, 8)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("hops: 8"), "text: {text}");
        assert!(text.contains("stable"));
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
