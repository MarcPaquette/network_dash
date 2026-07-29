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

/// Compute `[y_min, y_max]` for series that live away from zero — dBm readings sit in the
/// −30..−100 band, where [`chart_bounds`]' zero-based axis would flatten every trace onto
/// the top edge. Widened to at least `min_span` so a steady signal isn't drawn as noise.
fn chart_span(series: &[LineSeries], min_span: f64) -> [f64; 2] {
    let (mut lo, mut hi) = (f64::INFINITY, f64::NEG_INFINITY);
    for y in series.iter().flat_map(|s| s.points.iter().map(|p| p.1)) {
        lo = lo.min(y);
        hi = hi.max(y);
    }
    if !lo.is_finite() {
        return [0.0, min_span];
    }
    let half = ((hi - lo).max(min_span) / 2.0) + 1.0;
    let mid = (lo + hi) / 2.0;
    [mid - half, mid + half]
}

/// Render the whole dashboard.
pub fn render(frame: &mut Frame, state: &AppState) {
    let root = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3), // header
            Constraint::Length(5), // diagnosis: what's wrong (worst-first verdicts)
            Constraint::Length(3), // availability heat strip (1 content row + border)
            Constraint::Length(4), // detail band: link | transport (2 content rows + border)
            Constraint::Min(0),    // metric grid (2×3 charts)
            Constraint::Length(6), // events
            Constraint::Length(1), // footer
        ])
        .split(frame.area());

    header(frame, root[0], state);
    diagnosis(frame, root[1], state);
    availability(frame, root[2], state);

    // Detail band — two compact, text-only panels side by side.
    let detail = halves(root[3]);
    link(frame, detail[0], state);
    transport(frame, detail[1], state);

    // Metric grid — six chart panels in a 2×3. Routing graduated from a two-line text
    // summary to a full panel here, because a per-hop profile needs the room.
    let bands = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(root[4]);
    let top = thirds(bands[0]);
    let bottom = thirds(bands[1]);

    latency(frame, top[0], state);
    dns(frame, top[1], state);
    loss(frame, top[2], state);

    throughput(frame, bottom[0], state);
    wifi_signal(frame, bottom[1], state);
    routing(frame, bottom[2], state);

    events(frame, root[5], state);
    footer(frame, root[6], state);

    // The help overlay draws on top of everything when toggled.
    if state.show_help {
        help_overlay(frame, frame.area(), state);
    }
    // The theme picker (modal) draws on top when open.
    if state.theme_picker.is_some() {
        theme_picker_overlay(frame, frame.area(), state);
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
        "t           theme picker",
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

/// Theme picker overlay: browse the catalog with a live preview of the whole dashboard
/// (opened with `t`; ↑/↓ preview, Enter keeps, Esc reverts). Each row shows the theme's
/// ok/warn/crit swatch so a palette can be judged without selecting it.
pub fn theme_picker_overlay(frame: &mut Frame, area: Rect, state: &AppState) {
    let Some(picker) = state.theme_picker else {
        return;
    };
    let names = theme::Theme::NAMES;
    let mut lines: Vec<Line> = Vec::with_capacity(names.len() + 2);
    for (i, name) in names.iter().enumerate() {
        let t = theme::Theme::resolve(name);
        let selected = i == picker.index;
        let name_style = if selected {
            Style::default().fg(state.theme.accent).bold()
        } else {
            Style::default().fg(state.theme.muted)
        };
        lines.push(Line::from(vec![
            Span::raw(if selected { "▶ " } else { "  " }),
            Span::styled("●", Style::default().fg(t.ok)),
            Span::styled("●", Style::default().fg(t.warn)),
            Span::styled("●", Style::default().fg(t.crit)),
            Span::raw(" "),
            Span::styled(*name, name_style),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "↑↓ preview · enter keep · esc revert",
        Style::default().fg(state.theme.muted),
    )));

    let rect = centered_rect(area, 40, lines.len() as u16 + 2);
    let block = Block::default()
        .borders(Borders::ALL)
        .title(" THEME ")
        .border_style(Style::default().fg(state.theme.accent));
    frame.render_widget(Clear, rect);
    frame.render_widget(Paragraph::new(lines).block(block), rect);
}

fn halves(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
        .split(area)
}

/// Split a row into three columns. `Fill` rather than `Percentage(33)` so the remainder
/// of a width that isn't divisible by three is handed back out instead of left as a seam.
fn thirds(area: Rect) -> std::rc::Rc<[Rect]> {
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Fill(1),
            Constraint::Fill(1),
            Constraint::Fill(1),
        ])
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
    // A log that stopped recording is invisible by nature — badge it, or the operator only
    // finds out when they go looking for history that was never written.
    if state.log_error.is_some() {
        spans.push(Span::styled(
            "   [LOG ERR]",
            Style::default()
                .fg(state.theme.health_color(Health::Warn))
                .bold(),
        ));
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

/// Availability heat strip: one cell per minute of recorded history, coloured by the worst
/// health seen in that minute. A single glance answers "has this been solid all afternoon?",
/// which no instantaneous panel can.
pub fn availability(frame: &mut Frame, area: Rect, state: &AppState) {
    let r = state.availability_rollup();
    let title = format!(
        "AVAILABILITY  {:.1}%  ·  {}m ok · {}m degraded · {}m down{}",
        r.uptime_pct,
        r.ok,
        r.degraded,
        r.down,
        // Only mention unobserved minutes when there are some, so the usual case stays terse.
        if r.unknown > 0 {
            format!(" · {}m unknown", r.unknown)
        } else {
            String::new()
        }
    );
    let block = metric_block(&title, state.overall_health(), &state.theme);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.width == 0 || inner.height == 0 {
        return;
    }

    // Right-aligned: the strip is a timeline and "now" is its right edge, so a part-full
    // strip must grow leftwards rather than leaving now stranded mid-panel.
    let width = inner.width as usize;
    let skip = state.availability.len().saturating_sub(width);
    let cells: Vec<Span> = state
        .availability
        .iter()
        .skip(skip)
        .map(|(_, h)| match h {
            Some(h) => Span::styled("█", Style::default().fg(state.theme.health_color(*h))),
            // A minute nobody watched is not a healthy minute; give it its own glyph.
            None => Span::styled("·", Style::default().fg(state.theme.muted)),
        })
        .collect();
    let pad = width.saturating_sub(cells.len());
    let line = Line::from(
        std::iter::once(Span::raw(" ".repeat(pad)))
            .chain(cells)
            .collect::<Vec<_>>(),
    );
    frame.render_widget(Paragraph::new(line), inner);
}

/// Transport panel: TCP handshake timing per endpoint, plus the TLS/cert row still to come.
///
/// One line for every endpoint on a single row rather than a line each, so the panel keeps
/// its two-row slot in the detail band no matter how many endpoints are configured.
pub fn transport(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "TRANSPORT",
        state.panel_health(MetricId::TcpHandshake),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let dim = Style::default().fg(state.theme.muted);
    let mut tcp_row = vec![Span::raw("tcp  ")];
    if state.tcp.is_empty() {
        tcp_row.push(Span::styled("—", dim));
    }
    for (name, ep) in &state.tcp {
        let style = Style::default().fg(state.theme.health_color(ep.health_current()));
        // "refused" rather than the last good time: a stale number next to a live label reads
        // as the current state, and here the current state is that nothing connected.
        let reading = match (ep.last_ok, ep.connect_ms.latest()) {
            (true, Some(ms)) => format!("{ms:.0}ms"),
            (true, None) => "—".to_string(),
            (false, _) => "refused".to_string(),
        };
        tcp_row.push(Span::styled(format!("{name} {reading}   "), style));
    }
    let lines = vec![
        Line::from(tcp_row),
        Line::from(vec![
            Span::raw("tls  "),
            Span::styled("—", dim),
            Span::raw("    cert "),
            Span::styled("—", dim),
        ]),
    ];
    frame.render_widget(Paragraph::new(lines), inner);
}

/// Wi-Fi signal panel: the radio's own trend line. Separate from LINK because a slowly
/// decaying RSSI is only visible as history — the current number always looks plausible.
pub fn wifi_signal(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "WI-FI SIGNAL",
        state.panel_health(MetricId::Link),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let Some(rssi) = state.link.rssi_dbm else {
        frame.render_widget(
            Paragraph::new(Span::styled(
                "no wireless link",
                Style::default().fg(state.theme.muted),
            )),
            inner,
        );
        return;
    };
    let mut parts = vec![format!("rssi {rssi:.0} dBm")];
    if let Some(n) = state.link.noise_dbm {
        parts.push(format!("snr {:.0} dB", rssi - n));
        parts.push(format!("noise {n:.0} dBm"));
    }
    if let Some(tx) = state.link.tx_rate {
        parts.push(format!("tx {tx:.0} Mbps"));
    }
    let (summary, chart) = summary_and_chart(inner, 1);
    frame.render_widget(Paragraph::new(Line::from(parts.join("   "))), summary);

    let (Some(area), Some(history)) = (chart, state.link.rssi_history.as_ref()) else {
        return;
    };
    let values = history.values();
    let x_max = values.len().saturating_sub(1) as f64;
    let mut series = vec![LineSeries::from_values(
        "rssi",
        state.theme.series_color(0),
        &values,
    )];
    // Noise only while it has kept pace with the signal: a shorter series is stretched
    // across the same x axis, and SNR read off two misaligned traces is a fiction.
    if let Some(noise) = state
        .link
        .noise_history
        .as_ref()
        .filter(|n| n.len() == values.len())
    {
        series.push(LineSeries::from_values(
            "noise",
            state.theme.series_color(1),
            &noise.values(),
        ));
    }
    // Both bounds are always banded here, unlike latency: dBm has a narrow natural domain,
    // so a -80 crit line can't squash the trace the way a 150ms one would.
    let thr = &state.config.thresholds.rssi;
    for (level, color) in [(thr.warn, state.theme.warn), (thr.crit, state.theme.crit)] {
        series.push(LineSeries::reference(color, level, x_max));
    }
    let y = chart_span(&series, 12.0);
    frame.render_widget(
        line_chart(
            &series,
            x_max,
            y,
            vec![format!("{:.0}", y[0]), format!("{:.0} dBm", y[1])],
        ),
        area,
    );
}

/// Latency & jitter panel: one trace per ping target, banded with the warn/crit bounds.
///
/// Every target is plotted, not just the first: a gateway that is fine while the internet
/// target degrades is the single most useful comparison on the dashboard, and it only
/// exists if both lines share an axis. The colour-keyed summary rows double as the legend.
pub fn latency(frame: &mut Frame, area: Rect, state: &AppState) {
    let block = metric_block(
        "LATENCY & JITTER",
        state.panel_health(MetricId::Latency),
        &state.theme,
    );
    let inner = block.inner(area);
    frame.render_widget(block, area);

    if state.targets.is_empty() {
        return;
    }
    let (summary, chart) = summary_and_chart(inner, state.targets.len() as u16);

    let rows: Vec<ListItem> = state
        .targets
        .iter()
        .enumerate()
        .map(|(i, (name, t))| {
            let cur = t.latency_ms.latest().unwrap_or(0.0);
            let avg = t.latency_ms.mean().unwrap_or(0.0);
            let p95 = t.latency_ms.p95().unwrap_or(0.0);
            let max = t.latency_ms.max().unwrap_or(0.0);
            let jit = t.latency_ms.jitter().unwrap_or(0.0);
            ListItem::new(Line::from(vec![
                Span::styled(
                    format!("{name:<15} "),
                    Style::default().fg(state.theme.series_color(i)),
                ),
                Span::styled(
                    format!("{cur:>4.0}ms"),
                    Style::default().fg(state.theme.health_color(t.latency_health_current())),
                ),
                Span::raw(format!(
                    "  avg {avg:>4.0}  p95 {p95:>4.0}  max {max:>4.0}  jit {jit:>3.0}ms"
                )),
            ]))
        })
        .collect();
    frame.render_widget(List::new(rows), summary);

    let Some(area) = chart else { return };
    let mut series: Vec<LineSeries> = state
        .targets
        .iter()
        .enumerate()
        .map(|(i, (name, t))| {
            LineSeries::from_values(
                name.clone(),
                state.theme.series_color(i),
                &t.latency_ms.values(),
            )
        })
        .collect();

    // Scale on the data, then add whichever bands are actually relevant to it. Only the
    // internet bounds are banded — the gateway's 15/50ms and the internet's 80/150ms cannot
    // both be truthful on one axis, and a four-line grid would drown the traces anyway.
    let (x_max, data_max) = chart_bounds(&series, 20.0); // at least 0–20ms
    let thr = &state.config.thresholds.latency_internet;
    let mut y_max = data_max;
    for (level, color) in [(thr.warn, state.theme.warn), (thr.crit, state.theme.crit)] {
        // Within shouting distance only: a 150ms crit line over a healthy 8ms trace
        // squashes the real signal into the axis and tells the operator nothing.
        if data_max >= level * 0.6 {
            y_max = y_max.max(level * 1.05);
            series.push(LineSeries::reference(color, level, x_max));
        }
    }
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
    // Only when there is something to report. A permanent "err 0 rx, 0 tx" costs a quarter
    // of the line to say "normal", and trains the eye to skip the place the number appears.
    if let (Some(rx), Some(tx)) = (state.iface.rx_errors, state.iface.tx_errors)
        && rx + tx > 0
    {
        wifi_parts.push(format!("err {rx} rx / {tx} tx"));
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

/// Eighth-resolution horizontal bar covering `frac` of `width` cells.
///
/// Partial blocks matter here: hop RTTs on a LAN-to-WAN path routinely span two orders of
/// magnitude, and whole-cell rounding would collapse every near-hop to nothing — which
/// reads as "no measurement" rather than "fast".
fn hop_bar(frac: f64, width: u16) -> String {
    const PARTIALS: [char; 8] = ['▏', '▎', '▍', '▌', '▋', '▊', '▉', '█'];
    let eighths = (frac.clamp(0.0, 1.0) * f64::from(width) * 8.0).round() as usize;
    let mut s = "█".repeat(eighths / 8);
    match eighths % 8 {
        0 if s.is_empty() && frac > 0.0 => s.push(PARTIALS[0]),
        0 => {}
        rem => s.push(PARTIALS[rem - 1]),
    }
    s
}

/// Routing panel: hop count, reachability, and a per-hop latency profile.
///
/// The profile is the payload — "8 hops, stable" says the path exists, but only the
/// per-hop bars say *which* hop the 90ms is coming from.
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
    let summary_rows = 2u16;
    let lines = vec![
        Line::from(format!("hops: {}{}", r.hops, hop_info)),
        Line::from(vec![
            Span::raw("path: "),
            Span::styled(status, Style::default().fg(color)),
        ]),
    ];
    let summary = Rect {
        height: summary_rows.min(inner.height),
        ..inner
    };
    frame.render_widget(Paragraph::new(lines), summary);

    let rows = inner.height.saturating_sub(summary_rows);
    if rows == 0 || r.detail.is_empty() {
        return;
    }
    let profile = Rect {
        x: inner.x,
        y: inner.y + summary_rows,
        width: inner.width,
        height: rows,
    };

    // Bars are relative to the slowest hop on this path, so the profile always uses its
    // full width — an absolute scale would flatten every LAN path into one column.
    let worst = r
        .detail
        .iter()
        .filter_map(|h| h.min_rtt_ms)
        .fold(0.0_f64, f64::max);
    // Reserve room for "NN addr" and the trailing "  NNNNms  !NN%" fields.
    let bar_width = profile.width.saturating_sub(44).clamp(4, 28);
    let last = r.detail.len().saturating_sub(1);

    // A path longer than the panel loses its *tail* — but the tail is the interesting end,
    // so say how many rows went missing rather than pretending the path ended here.
    let shown = if r.detail.len() > rows as usize {
        rows as usize - 1
    } else {
        r.detail.len()
    };
    let mut items: Vec<ListItem> = Vec::with_capacity(rows as usize);
    for (i, hop) in r.detail.iter().take(shown).enumerate() {
        let idx = Span::styled(
            format!("{:>2} ", i + 1),
            Style::default().fg(state.theme.muted),
        );
        let Some(rtt) = hop.min_rtt_ms else {
            items.push(ListItem::new(Line::from(vec![
                idx,
                Span::styled(
                    format!("{:<17} ·· no reply", "*"),
                    Style::default().fg(state.theme.muted),
                ),
            ])));
            continue;
        };
        let frac = if worst > 0.0 { rtt / worst } else { 0.0 };
        // The final hop is the destination, so its RTT is the one worth judging against
        // the latency thresholds; intermediate hops are just where the time accrues.
        let rtt_style = if i == last {
            Style::default().fg(state
                .theme
                .health_color(state.config.thresholds.latency_internet.evaluate(rtt)))
        } else {
            Style::default()
        };
        let mut spans = vec![
            idx,
            Span::raw(format!("{:<17} ", truncate(&hop.addr, 17))),
            Span::styled(
                format!(
                    "{:<width$}",
                    hop_bar(frac, bar_width),
                    width = bar_width as usize
                ),
                Style::default().fg(state.theme.series_color(0)),
            ),
            Span::styled(format!(" {rtt:>5.0}ms"), rtt_style),
        ];
        if hop.loss_pct > 0.0 {
            // Mid-path loss is usually the router rate-limiting its own TTL-exceeded
            // replies, not dropped traffic — visible, but muted so it doesn't read as a
            // fault. Loss at the final hop really is loss, so that one gets a health color.
            let style = if i == last {
                Style::default().fg(state
                    .theme
                    .health_color(state.config.thresholds.loss.evaluate(hop.loss_pct)))
            } else {
                Style::default().fg(state.theme.muted)
            };
            spans.push(Span::styled(format!("  !{:.0}%", hop.loss_pct), style));
        }
        items.push(ListItem::new(Line::from(spans)));
    }
    if shown < r.detail.len() {
        items.push(ListItem::new(Line::from(Span::styled(
            format!("   +{} more hops", r.detail.len() - shown),
            Style::default().fg(state.theme.muted),
        ))));
    }
    frame.render_widget(List::new(items), profile);
}

/// Clip `s` to `max` characters, marking the cut so a truncated address is never mistaken
/// for a real one.
fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    s.chars().take(max.saturating_sub(1)).chain(['…']).collect()
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
    // Append the bufferbloat delta (added latency under load) when measured, with its tail:
    // bloat is intermittent, so the latest reading alone routinely misses it entirely.
    let mut probe_line = format!("capacity: {probe}");
    if let Some(bloat) = &state.throughput.added_latency_ms
        && let Some(cur) = bloat.latest()
    {
        probe_line.push_str(&format!("   load +{cur:.0}ms"));
        if let Some(p95) = bloat.p95() {
            probe_line.push_str(&format!(" (p95 +{p95:.0}ms)"));
        }
    }
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

    let Some(chart) = chart else { return };

    let mut rates = Vec::new();
    if let Some(s) = &state.throughput.rx_bps {
        rates.push(LineSeries::from_values("rx", state.theme.rx, &s.values()));
    }
    if let Some(s) = &state.throughput.tx_bps {
        rates.push(LineSeries::from_values("tx", state.theme.tx, &s.values()));
    }
    let capacity = state
        .throughput
        .capacity_mbps
        .as_ref()
        .filter(|s| !s.is_empty());

    // Capacity gets its own chart rather than a third trace: it is Mbps sampled every few
    // minutes, and laying it over per-second byte rates would put two different instants
    // at the same x. Split only when both have data and there's height for two charts.
    let (rate_area, capacity_area) = match (rates.is_empty(), capacity.is_some()) {
        (false, true) if chart.height >= 6 => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Fill(1), Constraint::Fill(1)])
                .split(chart);
            (Some(rows[0]), Some(rows[1]))
        }
        (false, _) => (Some(chart), None),
        (true, true) => (None, Some(chart)),
        (true, false) => (None, None),
    };

    if let Some(area) = rate_area {
        let (x_max, y_max) = chart_bounds(&rates, 1.0);
        frame.render_widget(
            line_chart(
                &rates,
                x_max,
                [0.0, y_max],
                vec!["0".into(), human_rate(y_max)],
            ),
            area,
        );
    }

    if let (Some(area), Some(history)) = (capacity_area, capacity) {
        let values = history.values();
        let x_max = values.len().saturating_sub(1) as f64;
        let mut series = vec![LineSeries::from_values(
            "capacity",
            state.theme.accent,
            &values,
        )];
        // Same relevance rule as latency, mirrored for a lower-is-worse metric: band a
        // bound only once the line has come down near it.
        let floor = values.iter().copied().fold(f64::INFINITY, f64::min);
        let thr = &state.config.thresholds.throughput;
        for (level, color) in [(thr.warn, state.theme.warn), (thr.crit, state.theme.crit)] {
            if floor <= level * 1.6 {
                series.push(LineSeries::reference(color, level, x_max));
            }
        }
        let (_, y_max) = chart_bounds(&series, 10.0);
        frame.render_widget(
            line_chart(
                &series,
                x_max,
                [0.0, y_max],
                vec!["0".into(), format!("{y_max:.0} Mbps")],
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
            // An incident an upstream fault already explains is drawn entirely in the muted
            // colour and indented under it. Still there to read — just not competing with
            // the one line that says what to actually go and fix.
            let muted = Style::default().fg(state.theme.muted);
            let (glyph_style, text_style) = match inc.cause {
                Some(_) => (muted, muted),
                None => (
                    Style::default().fg(state.theme.health_color(inc.severity)),
                    Style::default(),
                ),
            };
            let mut spans = vec![
                Span::styled(inc.ts.format("%H:%M:%S").to_string(), muted),
                Span::raw(if inc.is_downstream() { "   " } else { " " }),
                Span::styled(theme::health_symbol(inc.severity), glyph_style),
                Span::raw(" "),
                Span::styled(inc.message.clone(), text_style),
            ];
            // Surface the threshold that was crossed — logged but previously never shown.
            if let Some(thr) = inc.threshold {
                spans.push(Span::styled(format!("  · thr {thr:.0}{}", inc.unit), muted));
            }
            // Name the fault that accounts for it, so the dimming reads as an explanation
            // rather than as the dashboard losing interest.
            if let Some(cause) = inc.cause {
                spans.push(Span::styled(
                    format!("  ↳ explained by {}", cause.tag()),
                    muted,
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
    use crate::diagnosis::Layer;
    use crate::health::Health;
    use crate::incidents::Incident;
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
        // Frozen clock in the render tests: no dwell, so a fed sample is committed at once.
        c.thresholds.trip_after_secs = 0.0;
        c.thresholds.clear_after_secs = 0.0;
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

    /// One row of a buffer as a string.
    fn row_text(buf: &ratatui::buffer::Buffer, y: u16) -> String {
        (0..buf.area().width)
            .map(|x| buf[(x, y)].symbol())
            .collect()
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

    /// Every distinct foreground colour used by a plotted-graph glyph (braille).
    fn graph_colors(term: &Terminal<TestBackend>) -> std::collections::HashSet<Color> {
        let buf = term.backend().buffer();
        let area = *buf.area();
        let mut out = std::collections::HashSet::new();
        for y in 0..area.height {
            for x in 0..area.width {
                let cell = &buf[(x, y)];
                if cell
                    .symbol()
                    .chars()
                    .any(|c| ('\u{2800}'..='\u{28FF}').contains(&c))
                {
                    out.insert(cell.fg);
                }
            }
        }
        out
    }

    /// Feed `rtts` to `target`, registering it as an internet target.
    fn feed_latency(state: &mut AppState, target: &str, rtts: &[f64]) {
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for ms in rtts {
            state.apply_sample(
                now,
                Sample::Latency {
                    target: target.into(),
                    rtt_ms: Some(*ms),
                },
            );
        }
    }

    #[test]
    fn latency_panel_plots_every_target() {
        let mut state = test_state();
        feed_latency(&mut state, "1.1.1.1", &[20.0, 24.0, 22.0, 26.0]);
        feed_latency(&mut state, "8.8.8.8", &[40.0, 44.0, 42.0, 46.0]);
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| latency(f, f.area(), &state)).unwrap();

        let text = buffer_text(&term);
        assert!(text.contains("1.1.1.1"), "first target missing: {text}");
        assert!(
            text.contains("8.8.8.8"),
            "a second ping target was silently dropped from the panel: {text}"
        );
        // Two traces in two different series colours — one line for two targets would
        // hide exactly the asymmetry the panel exists to show.
        let colors = graph_colors(&term);
        assert!(
            colors.contains(&state.theme.series_color(0))
                && colors.contains(&state.theme.series_color(1)),
            "expected one trace per target, got colours {colors:?}"
        );
    }

    #[test]
    fn latency_summary_reports_the_p95_not_just_the_mean() {
        let mut state = test_state();
        feed_latency(&mut state, "1.1.1.1", &[20.0, 20.0, 20.0, 20.0, 400.0]);
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| latency(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        // The mean hides a single 400ms stall; the p95 is what an operator judges by.
        assert!(text.contains("p95"), "summary should report p95: {text}");
        assert!(text.contains("400"), "p95 should surface the tail: {text}");
    }

    #[test]
    fn latency_panel_bands_the_thresholds_when_the_data_is_near_them() {
        let mut state = test_state();
        // Internet defaults: warn 80ms, crit 150ms. Data straddling both.
        feed_latency(&mut state, "1.1.1.1", &[60.0, 120.0, 90.0, 180.0, 110.0]);
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| latency(f, f.area(), &state)).unwrap();
        let colors = graph_colors(&term);
        assert!(
            colors.contains(&state.theme.warn),
            "warn threshold band missing; a trace with no scale is just a squiggle: {colors:?}"
        );
        assert!(
            colors.contains(&state.theme.crit),
            "crit threshold band missing: {colors:?}"
        );
    }

    #[test]
    fn latency_panel_omits_bands_the_data_is_nowhere_near() {
        let mut state = test_state();
        // A healthy 8ms link: drawing the 150ms crit line would squash the trace flat.
        feed_latency(&mut state, "1.1.1.1", &[8.0, 9.0, 7.0, 10.0, 8.0]);
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| latency(f, f.area(), &state)).unwrap();
        let colors = graph_colors(&term);
        assert!(
            !colors.contains(&state.theme.crit),
            "crit band should stay off a chart scaled to 10ms: {colors:?}"
        );
        assert!(
            !colors.contains(&state.theme.warn),
            "warn band should stay off a chart scaled to 10ms: {colors:?}"
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
        assert!(text.contains("AVAILABILITY"));
        assert!(text.contains("LATENCY & JITTER"));
        assert!(text.contains("PACKET LOSS"));
        assert!(text.contains("DNS HEALTH"));
        assert!(text.contains("THROUGHPUT"));
        assert!(text.contains("WI-FI SIGNAL"));
        assert!(text.contains("ROUTING & PATH"));
        assert!(text.contains("EVENTS"));
    }

    #[test]
    fn thirds_splits_a_row_into_three_panels_that_tile_it() {
        let area = Rect {
            x: 4,
            y: 2,
            width: 222,
            height: 17,
        };
        let cols = thirds(area);
        assert_eq!(cols.len(), 3);
        // No gaps and no overlap: each column starts where the previous one ended, and the
        // last one ends exactly at the right edge — a chart panel losing a column to
        // rounding is a visible seam in a full-screen grid.
        assert_eq!(cols[0].x, area.x);
        assert_eq!(cols[1].x, cols[0].x + cols[0].width);
        assert_eq!(cols[2].x, cols[1].x + cols[1].width);
        assert_eq!(cols[2].x + cols[2].width, area.x + area.width);
        for c in cols.iter() {
            assert_eq!(c.height, area.height);
            assert_eq!(c.y, area.y);
        }
    }

    #[test]
    fn metric_grid_is_two_rows_of_three_chart_panels() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let buf = term.backend().buffer();
        let area = *buf.area();
        // Fixed chrome above the grid: header 3 + diagnosis 5 + availability 3 + detail 4.
        // Below it: events 6 + footer 1. Everything between is the 2×3 metric grid.
        let (grid_top, grid_bottom) = (15u16, area.height - 7);
        let row_of = |title: &str| -> Option<u16> {
            (0..area.height).find(|&y| {
                let mut row = String::new();
                for x in 0..area.width {
                    row.push_str(buf[(x, y)].symbol());
                }
                row.contains(title)
            })
        };
        // Row 1 titles share a line; so do row 2's. Two distinct lines, both in the grid.
        let top: Vec<u16> = ["LATENCY & JITTER", "DNS HEALTH", "PACKET LOSS"]
            .iter()
            .map(|t| row_of(t).unwrap_or_else(|| panic!("missing panel: {t}")))
            .collect();
        let bottom: Vec<u16> = ["THROUGHPUT", "WI-FI SIGNAL", "ROUTING & PATH"]
            .iter()
            .map(|t| row_of(t).unwrap_or_else(|| panic!("missing panel: {t}")))
            .collect();
        assert!(
            top.iter().all(|&y| y == top[0]),
            "row 1 panels should be side by side, found rows {top:?}"
        );
        assert!(
            bottom.iter().all(|&y| y == bottom[0]),
            "row 2 panels should be side by side, found rows {bottom:?}"
        );
        assert!(
            top[0] >= grid_top,
            "grid row 1 at {} overlaps chrome",
            top[0]
        );
        assert!(
            bottom[0] > top[0] && bottom[0] < grid_bottom,
            "grid row 2 at {} should sit below row 1 and above the events feed",
            bottom[0]
        );
    }

    /// Drive a state into a "system resolver failing, public resolvers fine, connectivity OK"
    /// condition — the classic DNS-config problem the diagnosis engine should name.
    fn dns_problem_state() -> AppState {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into()];
        c.targets.gateway = Some("192.168.1.1".into());
        c.targets.gateway_auto = false;
        // Frozen clock in the render tests: no dwell, so a fed sample is committed at once.
        c.thresholds.trip_after_secs = 0.0;
        c.thresholds.clear_after_secs = 0.0;
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
        let crit = state.theme.crit; // active theme's crit color
        // The top-left border corner carries the panel's health color.
        assert_eq!(
            buf[(0, 0)].fg,
            crit,
            "crit diagnosis should paint the border with the active theme's crit color"
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
    fn detail_band_holds_link_and_transport() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        let buf = term.backend().buffer();
        let area = *buf.area();
        // Text of the detail band region: header (3) + diagnosis (5) + availability (3)
        // = rows 0..11, then the link | transport detail band (4 rows) at rows 11..15.
        let mut band = String::new();
        for y in 11..15 {
            for x in 0..area.width {
                band.push_str(buf[(x, y)].symbol());
            }
            band.push('\n');
        }
        assert!(
            band.contains("LINK & REACHABILITY"),
            "link should sit in the detail band: {band}"
        );
        assert!(
            band.contains("TRANSPORT"),
            "transport should sit in the detail band: {band}"
        );
        // Routing graduated from the text band to a full chart panel in the grid below.
        assert!(
            !band.contains("ROUTING & PATH"),
            "routing belongs in the metric grid now, not the detail band: {band}"
        );

        // The six chart panels and events still render below.
        let all = buffer_text(&term);
        for title in [
            "LATENCY & JITTER",
            "DNS HEALTH",
            "PACKET LOSS",
            "THROUGHPUT",
            "WI-FI SIGNAL",
            "ROUTING & PATH",
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
            text.contains("theme picker"),
            "overlay body should show keys"
        );
    }

    #[test]
    fn theme_picker_overlay_renders_when_open() {
        use crate::app::Action;
        use ratatui::style::Modifier;
        let mut state = test_state();
        state.apply_action(Action::OpenThemePicker);
        state.apply_action(Action::ThemePreviewDown); // move the highlight off the first row
        // Tall enough to fit the whole catalog overlay (one row per theme + footer).
        let mut term = Terminal::new(TestBackend::new(60, 30)).unwrap();
        term.draw(|f| theme_picker_overlay(f, f.area(), &state))
            .unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("THEME"), "overlay title should show: {text}");
        assert!(
            text.contains("dracula") && text.contains("gruvbox"),
            "theme names should be listed: {text}"
        );
        assert!(
            text.contains("preview") && text.contains("revert"),
            "footer hint should show: {text}"
        );
        // The selected row is the only bold text, so a bold cell proves the highlight.
        let buf = term.backend().buffer();
        assert!(
            buf.content
                .iter()
                .any(|c| c.modifier.contains(Modifier::BOLD)),
            "selected theme row should be highlighted (bold)"
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
    fn header_badges_an_unwritable_incident_log() {
        let mut state = test_state();
        state.log_error = Some("no space left on device".into());
        let mut term = Terminal::new(TestBackend::new(120, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("LOG"),
            "a silently-unwritable log is worse than a noisy one: {text}"
        );
    }

    #[test]
    fn healthy_header_has_no_log_badge() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(120, 3)).unwrap();
        term.draw(|f| header(f, f.area(), &state)).unwrap();
        assert!(!buffer_text(&term).contains("LOG"));
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
    fn link_panel_stays_quiet_about_a_clean_nic() {
        let mut state = test_state();
        state.iface.rx_errors = Some(0);
        state.iface.tx_errors = Some(0);
        let mut term = Terminal::new(TestBackend::new(80, 8)).unwrap();
        term.draw(|f| link(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            !text.contains("err"),
            "zero errors is the normal case; a permanent 'err 0' is just noise: {text}"
        );
    }

    #[test]
    fn link_panel_names_the_direction_of_nic_errors() {
        let mut state = test_state();
        state.iface.rx_errors = Some(7);
        state.iface.tx_errors = Some(2);
        let mut term = Terminal::new(TestBackend::new(80, 8)).unwrap();
        term.draw(|f| link(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("err 7 rx"), "should show rx errors: {text}");
        assert!(text.contains("2 tx"), "should show tx errors: {text}");
    }

    /// Fold one handshake reading into a fresh state.
    fn with_handshake(state: &mut AppState, endpoint: &str, connect_ms: Option<f64>) {
        state.apply_sample(
            Utc::now(),
            Sample::TcpHandshake {
                endpoint: endpoint.into(),
                connect_ms,
            },
        );
    }

    #[test]
    fn transport_panel_waits_for_data_rather_than_inventing_it() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(80, 4)).unwrap();
        term.draw(|f| transport(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("tcp"), "the row is always labelled: {text}");
        assert!(
            !text.contains("ms"),
            "no probe has run, so there is no timing to show: {text}"
        );
    }

    #[test]
    fn transport_panel_times_every_endpoint() {
        let mut state = test_state();
        with_handshake(&mut state, "cloudflare", Some(12.0));
        with_handshake(&mut state, "google", Some(31.0));
        let mut term = Terminal::new(TestBackend::new(80, 4)).unwrap();
        term.draw(|f| transport(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("cloudflare 12ms"), "{text}");
        assert!(text.contains("google 31ms"), "{text}");
    }

    #[test]
    fn transport_panel_says_refused_rather_than_showing_a_stale_time() {
        let mut state = test_state();
        with_handshake(&mut state, "google", Some(31.0));
        with_handshake(&mut state, "google", None);
        let mut term = Terminal::new(TestBackend::new(80, 4)).unwrap();
        term.draw(|f| transport(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("google refused"), "{text}");
        assert!(
            !text.contains("31ms"),
            "the last good time is not the current state: {text}"
        );
    }

    #[test]
    fn a_refused_handshake_reddens_the_transport_border() {
        let mut state = test_state();
        with_handshake(&mut state, "google", None);
        let mut term = Terminal::new(TestBackend::new(80, 4)).unwrap();
        term.draw(|f| transport(f, f.area(), &state)).unwrap();
        assert_eq!(
            term.backend().buffer()[(0, 0)].fg,
            state.theme.crit,
            "the core visual contract: a broken transport shows on the border"
        );
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
        // top-left border corner should carry the active theme's crit color
        assert_eq!(term.backend().buffer()[(0, 0)].fg, state.theme.crit);
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

    /// Feed a run of Wi-Fi readings, holding tx rate and SSID constant.
    fn feed_link(state: &mut AppState, readings: &[(f64, f64)]) {
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for (rssi, noise) in readings {
            state.apply_sample(
                now,
                Sample::Link {
                    rssi_dbm: Some(*rssi),
                    noise_dbm: Some(*noise),
                    tx_rate: Some(400.0),
                    ssid: Some("MyNet".into()),
                },
            );
        }
    }

    #[test]
    fn wifi_panel_charts_signal_and_noise() {
        let mut state = test_state();
        feed_link(
            &mut state,
            &[
                (-45.0, -92.0),
                (-51.0, -91.0),
                (-58.0, -90.0),
                (-62.0, -89.0),
            ],
        );
        let mut term = Terminal::new(TestBackend::new(60, 14)).unwrap();
        term.draw(|f| wifi_signal(f, f.area(), &state)).unwrap();

        assert!(has_braille(&term), "wifi panel should plot signal history");
        // Two traces, not one: SNR is the vertical gap between them, so both must be drawn.
        let colors = graph_colors(&term);
        assert!(
            colors.contains(&state.theme.series_color(0)),
            "signal trace missing: {colors:?}"
        );
        assert!(
            colors.contains(&state.theme.series_color(1)),
            "noise trace missing: {colors:?}"
        );
        // The summary line survives the chart.
        let text = buffer_text(&term);
        assert!(text.contains("-62 dBm"), "current rssi missing: {text}");
    }

    #[test]
    fn wifi_panel_bands_the_rssi_warn_threshold() {
        let mut state = test_state();
        // Decaying towards the warn bound (-70 dBm by default): the band belongs on screen.
        feed_link(
            &mut state,
            &[
                (-58.0, -92.0),
                (-63.0, -92.0),
                (-67.0, -92.0),
                (-69.0, -92.0),
            ],
        );
        let mut term = Terminal::new(TestBackend::new(60, 14)).unwrap();
        term.draw(|f| wifi_signal(f, f.area(), &state)).unwrap();
        assert!(
            graph_colors(&term).contains(&state.theme.warn),
            "a signal near the warn bound should be banded with it"
        );
    }

    #[test]
    fn wifi_panel_without_a_radio_says_so_instead_of_charting() {
        let state = test_state();
        let mut term = Terminal::new(TestBackend::new(60, 14)).unwrap();
        term.draw(|f| wifi_signal(f, f.area(), &state)).unwrap();
        assert!(buffer_text(&term).contains("no wireless link"));
        assert!(!has_braille(&term), "nothing to chart without a radio");
    }

    #[test]
    fn throughput_panel_charts_capacity_history() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for mbps in [420.0, 400.0, 380.0, 120.0] {
            state.apply_sample(now, Sample::ThroughputProbe { mbps });
        }
        let mut term = Terminal::new(TestBackend::new(60, 20)).unwrap();
        term.draw(|f| throughput(f, f.area(), &state)).unwrap();

        let text = buffer_text(&term);
        assert!(
            text.contains("capacity"),
            "capacity chart unlabelled: {text}"
        );
        // Capacity is plotted in its own colour — it cannot share rx/tx's axis, which is
        // bytes/sec on a 2-second cadence against a 5-minute probe.
        assert!(
            graph_colors(&term).contains(&state.theme.accent),
            "capacity history should be plotted"
        );
    }

    #[test]
    fn throughput_summary_reports_the_bufferbloat_tail() {
        let mut state = test_state();
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for (idle, loaded) in [(20.0, 40.0), (20.0, 45.0), (20.0, 220.0)] {
            state.apply_sample(
                now,
                Sample::Bufferbloat {
                    idle_ms: idle,
                    loaded_ms: loaded,
                },
            );
        }
        let mut term = Terminal::new(TestBackend::new(60, 20)).unwrap();
        term.draw(|f| throughput(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        // The current reading alone hides an intermittent stall; the tail is the story.
        assert!(text.contains("+200ms"), "current delta missing: {text}");
        assert!(
            text.contains("p95 +200ms"),
            "bufferbloat tail missing: {text}"
        );
    }

    /// A dashboard with every panel carrying real data, on a frozen clock.
    ///
    /// Deliberately mixed health — a healthy screenshot proves the grid tiles but not that
    /// a degraded one still fits, and overflow only ever shows up under long text.
    fn populated_state() -> AppState {
        let mut c = Config::default();
        c.targets.internet = vec!["1.1.1.1".into(), "8.8.8.8".into()];
        c.targets.gateway = Some("192.168.1.1".into());
        // Frozen clock in the render tests: no dwell, so a fed sample is committed at once.
        c.thresholds.trip_after_secs = 0.0;
        c.thresholds.clear_after_secs = 0.0;
        c.thresholds.loss_window = 8;
        let mut s = AppState::new(c);
        let t0 = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();

        for (i, ms) in [18.0, 22.0, 19.0, 31.0, 24.0, 27.0].iter().enumerate() {
            let at = t0 + chrono::Duration::seconds(i as i64 * 20);
            for (target, scale) in [("1.1.1.1", 1.0), ("8.8.8.8", 1.4)] {
                s.apply_sample(
                    at,
                    Sample::Latency {
                        target: target.into(),
                        rtt_ms: Some(ms * scale),
                    },
                );
            }
            // The gateway drops one probe: enough to put loss on the board without
            // reddening the whole dashboard.
            s.apply_sample(
                at,
                Sample::Latency {
                    target: "192.168.1.1".into(),
                    rtt_ms: (i != 3).then_some(2.0),
                },
            );
            s.apply_sample(
                at,
                Sample::Dns {
                    resolver: "system".into(),
                    latency_ms: Some(14.0 + i as f64),
                },
            );
            s.apply_sample(
                at,
                Sample::Throughput {
                    rx_bps: 1.0e6 + i as f64 * 2.0e5,
                    tx_bps: 2.0e5,
                },
            );
            s.apply_sample(
                at,
                Sample::Link {
                    rssi_dbm: Some(-52.0 - i as f64 * 2.0),
                    noise_dbm: Some(-92.0),
                    tx_rate: Some(866.0),
                    ssid: Some("MyNet".into()),
                },
            );
        }
        for mbps in [430.0, 410.0, 380.0] {
            s.apply_sample(t0, Sample::ThroughputProbe { mbps });
        }
        s.apply_sample(
            t0,
            Sample::Bufferbloat {
                idle_ms: 20.0,
                loaded_ms: 88.0,
            },
        );
        s.apply_sample(
            t0,
            Sample::Reachability {
                endpoint: "http".into(),
                ok: true,
            },
        );
        s.apply_sample(
            t0,
            Sample::PublicIp {
                ip: "203.0.113.7".into(),
            },
        );
        s.apply_sample(
            t0,
            Sample::Routing {
                target: "1.1.1.1".into(),
                hops: 4,
                reachable: true,
                changed: false,
                detail: vec![
                    Hop {
                        addr: "192.168.1.1".into(),
                        min_rtt_ms: Some(1.8),
                        loss_pct: 0.0,
                    },
                    Hop {
                        addr: "10.0.0.1".into(),
                        min_rtt_ms: Some(9.4),
                        loss_pct: 0.0,
                    },
                    Hop {
                        addr: "*".into(),
                        min_rtt_ms: None,
                        loss_pct: 100.0,
                    },
                    Hop {
                        addr: "1.1.1.1".into(),
                        min_rtt_ms: Some(24.0),
                        loss_pct: 0.0,
                    },
                ],
            },
        );
        s
    }

    #[test]
    fn dashboard_layout_snapshot() {
        // A whole-screen snapshot is the only assertion that catches a panel silently
        // stealing rows from its neighbour — every targeted test still passes when the
        // grid is one row off.
        let state = populated_state();
        let mut term = Terminal::new(TestBackend::new(222, 56)).unwrap();
        term.draw(|f| render(f, &state)).unwrap();
        insta::assert_snapshot!(buffer_text(&term));
    }

    /// Drive `minutes` consecutive one-minute buckets, marking `down_at` as a total outage.
    fn availability_state(minutes: i64, down_at: &[i64]) -> AppState {
        let mut state = test_state();
        let t0 = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        for m in 0..minutes {
            let at = t0 + chrono::Duration::minutes(m);
            if down_at.contains(&m) {
                for _ in 0..4 {
                    state.apply_sample(
                        at,
                        Sample::Latency {
                            target: "1.1.1.1".into(),
                            rtt_ms: None,
                        },
                    );
                }
            } else {
                for _ in 0..8 {
                    state.apply_sample(
                        at,
                        Sample::Latency {
                            target: "1.1.1.1".into(),
                            rtt_ms: Some(12.0),
                        },
                    );
                }
            }
        }
        state
    }

    #[test]
    fn availability_strip_paints_a_cell_per_minute() {
        // Outage at the *end* of the window: a healthy minute following an outage is
        // itself partly unhealthy (the loss window drains over several samples), and
        // worst-of-minute records that honestly — which would muddy the count here.
        let state = availability_state(10, &[8, 9]);
        let mut term = Terminal::new(TestBackend::new(222, 3)).unwrap();
        term.draw(|f| availability(f, f.area(), &state)).unwrap();
        let buf = term.backend().buffer();
        let area = *buf.area();
        let mut ok = 0;
        let mut down = 0;
        for x in 0..area.width {
            let c = &buf[(x, 1)];
            if c.symbol() == "█" && c.fg == state.theme.ok {
                ok += 1;
            }
            if c.symbol() == "█" && c.fg == state.theme.crit {
                down += 1;
            }
        }
        assert_eq!(down, 2, "two outage minutes should paint two red cells");
        assert_eq!(ok, 8, "the other eight minutes should paint healthy cells");
    }

    #[test]
    fn availability_strip_puts_the_newest_minute_at_the_right_edge() {
        // The strip reads like a timeline: time flows left-to-right, and "now" is the end
        // you glance at. Left-aligning a part-full strip would put now in the middle.
        let state = availability_state(3, &[2]);
        let mut term = Terminal::new(TestBackend::new(40, 3)).unwrap();
        term.draw(|f| availability(f, f.area(), &state)).unwrap();
        let buf = term.backend().buffer();
        let last = &buf[(38, 1)]; // rightmost inner column
        assert_eq!(last.symbol(), "█");
        assert_eq!(last.fg, state.theme.crit, "the newest minute was an outage");
    }

    #[test]
    fn availability_title_reports_the_uptime_rollup() {
        let state = availability_state(10, &[8, 9]);
        let mut term = Terminal::new(TestBackend::new(222, 3)).unwrap();
        term.draw(|f| availability(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(text.contains("AVAILABILITY"), "{text}");
        assert!(
            text.contains("80.0%"),
            "8 of 10 minutes healthy should read as 80.0%: {text}"
        );
        assert!(
            text.contains("2m down"),
            "the headline should quantify the downtime: {text}"
        );
    }

    #[test]
    fn hop_bar_scales_to_the_available_width() {
        assert_eq!(hop_bar(1.0, 10).chars().count(), 10);
        assert!(hop_bar(1.0, 10).chars().all(|c| c == '█'));
        assert_eq!(hop_bar(0.5, 10), "█████");
        assert_eq!(hop_bar(0.0, 10), "");
    }

    #[test]
    fn hop_bar_never_rounds_a_real_reading_away() {
        // A hop at 2% of the worst still took time; an empty cell would read as "no data".
        assert_eq!(hop_bar(0.02, 10).chars().count(), 1);
    }

    /// Push one routing sample built from `(addr, rtt, loss)` triples.
    fn feed_path(state: &mut AppState, hops: &[(&str, Option<f64>, f64)]) {
        let now = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.apply_sample(
            now,
            Sample::Routing {
                target: "1.1.1.1".into(),
                hops: hops.len(),
                reachable: true,
                changed: false,
                detail: hops
                    .iter()
                    .map(|(addr, rtt, loss)| Hop {
                        addr: (*addr).into(),
                        min_rtt_ms: *rtt,
                        loss_pct: *loss,
                    })
                    .collect(),
            },
        );
    }

    /// Rows of the rendered buffer as strings.
    fn rows(term: &Terminal<TestBackend>) -> Vec<String> {
        buffer_text(term).lines().map(str::to_string).collect()
    }

    #[test]
    fn routing_panel_profiles_each_hop_with_a_bar() {
        let mut state = test_state();
        feed_path(
            &mut state,
            &[
                ("192.168.1.1", Some(2.0), 0.0),
                ("10.0.0.1", Some(9.0), 0.0),
                ("203.0.113.9", Some(40.0), 0.0),
            ],
        );
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let rows = rows(&term);

        let bar_len = |addr: &str| -> usize {
            rows.iter()
                .find(|r| r.contains(addr))
                .unwrap_or_else(|| panic!("no row for hop {addr}"))
                .chars()
                .filter(|c| {
                    ('\u{2588}'..='\u{2589}').contains(c) || ('\u{258A}'..='\u{258F}').contains(c)
                })
                .count()
        };
        // The whole point of a path profile: see *where* the time is spent. The 40ms hop
        // must draw a visibly longer bar than the 2ms one.
        assert!(
            bar_len("203.0.113.9") > bar_len("10.0.0.1"),
            "hop bars should scale with RTT: {rows:#?}"
        );
        assert!(
            bar_len("10.0.0.1") > bar_len("192.168.1.1"),
            "hop bars should scale with RTT: {rows:#?}"
        );
    }

    #[test]
    fn routing_panel_marks_hops_that_never_answered() {
        let mut state = test_state();
        feed_path(
            &mut state,
            &[("192.168.1.1", Some(2.0), 0.0), ("*", None, 100.0)],
        );
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("no reply"),
            "a silent hop is normal (ICMP-throttled routers), so say so rather than \
             drawing it as 0ms: {text}"
        );
    }

    #[test]
    fn routing_panel_flags_a_lossy_hop() {
        let mut state = test_state();
        feed_path(
            &mut state,
            &[
                ("192.168.1.1", Some(2.0), 0.0),
                ("10.0.0.1", Some(9.0), 40.0),
            ],
        );
        let mut term = Terminal::new(TestBackend::new(74, 17)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let row = rows(&term)
            .into_iter()
            .find(|r| r.contains("10.0.0.1"))
            .expect("lossy hop row");
        assert!(row.contains("40%"), "hop loss should be shown: {row}");
    }

    #[test]
    fn routing_panel_truncates_a_long_path_and_says_how_much_it_dropped() {
        let mut state = test_state();
        let hops: Vec<(&str, Option<f64>, f64)> =
            (0..20).map(|_| ("10.0.0.1", Some(5.0), 0.0)).collect();
        feed_path(&mut state, &hops);
        // Only a handful of content rows: 8 minus the border and the two summary lines.
        let mut term = Terminal::new(TestBackend::new(74, 8)).unwrap();
        term.draw(|f| routing(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("more"),
            "a clipped path must admit it is clipped: {text}"
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
    fn events_mark_a_downstream_incident_as_an_echo() {
        let mut state = test_state();
        let ts = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        state.events.push_front(
            Incident::new(ts, MetricId::Dns, Health::Crit, "dns timed out (system)")
                .with_target("system")
                .caused_by(Layer::Gateway),
        );
        let mut term = Terminal::new(TestBackend::new(120, 5)).unwrap();
        term.draw(|f| events(f, f.area(), &state)).unwrap();
        let text = buffer_text(&term);
        assert!(
            text.contains("dns timed out"),
            "a downstream incident is dimmed, never dropped: {text}"
        );
        assert!(
            text.to_lowercase().contains("gateway"),
            "say what already explains it, or the dimming is a mystery: {text}"
        );
    }

    #[test]
    fn a_downstream_incident_is_dimmer_than_the_fault_that_caused_it() {
        let mut state = test_state();
        let ts = Utc.with_ymd_and_hms(2026, 7, 20, 14, 0, 0).unwrap();
        // Newest first: the echo on row 0, the root cause on row 1.
        state.events.push_front(
            Incident::new(ts, MetricId::Loss, Health::Crit, "loss 100% (192.168.1.1)")
                .with_target("192.168.1.1"),
        );
        state.events.push_front(
            Incident::new(ts, MetricId::Dns, Health::Crit, "dns timed out (system)")
                .caused_by(Layer::Gateway),
        );
        let mut term = Terminal::new(TestBackend::new(120, 5)).unwrap();
        term.draw(|f| events(f, f.area(), &state)).unwrap();
        let buf = term.backend().buffer();
        assert!(
            row_text(buf, 2).contains("loss 100%"),
            "{}",
            row_text(buf, 2)
        );

        // The severity glyph carries the alarm colour; the echo's must be muted instead.
        let sym = theme::health_symbol(Health::Crit);
        let glyph_at = |y: u16| {
            (0..buf.area().width)
                .find(|&x| buf[(x, y)].symbol() == sym)
                .unwrap_or_else(|| panic!("no severity glyph on row {y}: {}", row_text(buf, y)))
        };
        let (echo_x, root_x) = (glyph_at(1), glyph_at(2));
        assert_eq!(
            buf[(root_x, 2)].fg,
            state.theme.crit,
            "the real fault stays loud"
        );
        assert_eq!(
            buf[(echo_x, 1)].fg,
            state.theme.muted,
            "an echo of a known fault must not shout as loudly as the fault"
        );
        assert!(
            echo_x > root_x,
            "the echo should sit indented under the fault: {echo_x} vs {root_x}"
        );
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
