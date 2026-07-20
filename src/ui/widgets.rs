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
            Dataset::default()
                .name(s.name.clone())
                .marker(Marker::Braille)
                .graph_type(GraphType::Line)
                .style(Style::default().fg(s.color))
                .data(&s.points)
        })
        .collect();
    Chart::new(datasets)
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
}
