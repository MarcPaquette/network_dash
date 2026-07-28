//! Reusable widget builders shared across panels.

use ratatui::style::{Color, Style};
use ratatui::symbols::Marker;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Axis, Block, Borders, Chart, Dataset, GraphType};

use crate::health::Health;
use crate::ui::theme::Theme;

/// A bordered [`Block`] whose frame + title color reflect `health`, drawn in `theme`'s
/// palette. This is the single place the "red frame on issue" contract is applied, so
/// every panel gets it for free.
pub fn metric_block(title: &str, health: Health, theme: &Theme) -> Block<'static> {
    let style = theme.border_style(health);
    let title = Line::from(vec![
        Span::styled(" ", Style::default()),
        Span::styled(title.to_string(), style),
        Span::styled(" ", Style::default()),
    ]);
    Block::default()
        .borders(Borders::ALL)
        .border_style(style)
        .title(title)
}

/// One named, colored line for a [`line_chart`].
pub struct LineSeries {
    pub name: String,
    pub color: Color,
    pub points: Vec<(f64, f64)>,
}

impl LineSeries {
    /// Build a series from y-values, using the sample index as the x coordinate.
    pub fn from_values(name: impl Into<String>, color: Color, values: &[f64]) -> Self {
        let points = values
            .iter()
            .enumerate()
            .map(|(i, v)| (i as f64, *v))
            .collect();
        Self {
            name: name.into(),
            color,
            points,
        }
    }

    /// A flat horizontal line at `y` spanning the chart — a threshold band. Deliberately
    /// unnamed: it is a scale marker, not a measurement, and naming it would put it in the
    /// panel's colour key alongside the real targets.
    pub fn reference(color: Color, y: f64, x_max: f64) -> Self {
        Self {
            name: String::new(),
            color,
            // Matches `line_chart`'s own `x_max.max(1.0)` floor, so a band on a
            // one-sample chart still crosses the full width.
            points: vec![(0.0, y), (x_max.max(1.0), y)],
        }
    }
}

/// A braille line chart over `series`, x spanning `0..=x_max`, y clamped to `y_bounds`.
/// `y_labels` are drawn at the bottom and top of the y-axis (2 entries expected).
pub fn line_chart<'a>(
    series: &'a [LineSeries],
    x_max: f64,
    y_bounds: [f64; 2],
    y_labels: Vec<String>,
) -> Chart<'a> {
    let datasets: Vec<Dataset<'a>> = series
        .iter()
        .filter(|s| !s.points.is_empty())
        .map(|s| {
            let d = Dataset::default()
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(s.color))
                .data(&s.points);
            // Naming a dataset is what enrols it in ratatui's legend accounting, so
            // reference bands stay anonymous.
            if s.name.is_empty() {
                d
            } else {
                d.name(s.name.clone())
            }
        })
        .collect();
    Chart::new(datasets)
        .legend_position(None)
        .x_axis(Axis::default().bounds([0.0, x_max.max(1.0)]))
        .y_axis(
            Axis::default()
                .bounds(y_bounds)
                .labels(y_labels.into_iter().map(Span::from).collect::<Vec<_>>()),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;
    use ratatui::style::Color;

    /// Render a block and return the foreground color of the top-left border corner.
    fn border_corner_color(health: Health) -> Color {
        let theme = Theme::default_theme();
        let mut terminal = Terminal::new(TestBackend::new(20, 5)).unwrap();
        terminal
            .draw(|f| {
                let block = metric_block("PANEL", health, &theme);
                f.render_widget(block, f.area());
            })
            .unwrap();
        terminal.backend().buffer()[(0, 0)].fg
    }

    #[test]
    fn crit_panel_renders_red_border() {
        assert_eq!(border_corner_color(Health::Crit), Color::Red);
    }

    #[test]
    fn warn_panel_renders_yellow_border() {
        assert_eq!(border_corner_color(Health::Warn), Color::Yellow);
    }

    #[test]
    fn ok_panel_border_is_not_alarming() {
        let c = border_corner_color(Health::Ok);
        assert_ne!(c, Color::Red);
        assert_ne!(c, Color::Yellow);
    }

    #[test]
    fn reference_line_is_flat_and_spans_the_x_range() {
        let r = LineSeries::reference(Color::Red, 150.0, 47.0);
        assert_eq!(r.points, vec![(0.0, 150.0), (47.0, 150.0)]);
        assert!(
            r.name.is_empty(),
            "a threshold band is chart furniture, not a data series — it must not be named"
        );
    }

    #[test]
    fn reference_line_still_spans_a_single_point_chart() {
        // With one sample, `line_chart` widens x to [0,1]; the band has to match or it
        // collapses to a dot in the corner.
        assert_eq!(LineSeries::reference(Color::Red, 5.0, 0.0).points[1].0, 1.0);
    }

    #[test]
    fn chart_draws_no_legend() {
        // Panels carry their own colour-keyed summary rows; ratatui's legend box would
        // sit on top of the plot and steal columns from the trace.
        let series = vec![LineSeries::from_values(
            "cloudflare",
            Color::Cyan,
            &[1.0, 5.0, 3.0],
        )];
        let mut terminal = Terminal::new(TestBackend::new(60, 12)).unwrap();
        terminal
            .draw(|f| {
                let c = line_chart(&series, 2.0, [0.0, 5.0], vec!["0".into(), "5".into()]);
                f.render_widget(c, f.area());
            })
            .unwrap();
        let buf = terminal.backend().buffer();
        let area = *buf.area();
        let mut text = String::new();
        for y in 0..area.height {
            for x in 0..area.width {
                text.push_str(buf[(x, y)].symbol());
            }
        }
        assert!(
            !text.contains("cloudflare"),
            "series names should not render a legend box: {text}"
        );
    }
}
