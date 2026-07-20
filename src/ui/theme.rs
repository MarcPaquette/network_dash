//! Colors and health-driven styling shared by all panels.
//!
//! Every semantic color lives on a [`Theme`]. The central contract is unchanged: a panel's
//! border and title style is derived purely from its [`Health`] — a healthy panel gets a
//! quiet `border_ok`, `Warn` goes to the theme's amber/yellow, `Crit` to its red — so an
//! unhealthy section's frame always lights up regardless of the active theme.
//!
//! A [`Theme`] is a plain `Copy` struct; the app resolves a name (from config or the
//! live-cycle key) into one via [`Theme::resolve`] and carries it on the app state.

use ratatui::style::{Color, Modifier, Style};

use crate::health::Health;

/// A complete color palette. All fields are `Copy`, so the whole theme is trivially copied
/// into the render path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Theme {
    /// Stable identifier (matches the config `ui.theme` value and [`Theme::NAMES`]).
    pub name: &'static str,
    /// Healthy accent (status dots, gauges).
    pub ok: Color,
    /// Warning accent + warn border.
    pub warn: Color,
    /// Critical accent + crit border.
    pub crit: Color,
    /// Quiet border color for a healthy panel (low emphasis).
    pub border_ok: Color,
    /// Primary highlight: titles, the "NetPulse" banner, the latency sparkline.
    pub accent: Color,
    /// Download / receive rate.
    pub rx: Color,
    /// Upload / transmit rate.
    pub tx: Color,
    /// De-emphasized text: placeholders, footer, event timestamps.
    pub muted: Color,
    /// Distinct colors for multi-line charts (indexed, wraps).
    pub series: [Color; 6],
}

impl Theme {
    /// All selectable theme names, in cycle order. `default` is first (out-of-box look).
    pub const NAMES: [&'static str; 5] = [
        "default",
        "neon_sunset",
        "moss_goblin",
        "cybercity_night",
        "cottage_fire",
    ];

    /// The neutral built-in theme — reproduces the original hardcoded palette exactly.
    pub fn default_theme() -> Theme {
        Theme {
            name: "default",
            ok: Color::Green,
            warn: Color::Yellow,
            crit: Color::Red,
            border_ok: Color::DarkGray,
            accent: Color::Cyan,
            rx: Color::Green,
            tx: Color::Blue,
            muted: Color::DarkGray,
            series: [
                Color::Cyan,
                Color::Magenta,
                Color::Green,
                Color::Yellow,
                Color::Blue,
                Color::LightRed,
            ],
        }
    }

    /// Warm neon gradient: hot pink accent, teal/amber health, sunset chart palette.
    fn neon_sunset() -> Theme {
        Theme {
            name: "neon_sunset",
            ok: Color::Rgb(64, 224, 208),
            warn: Color::Rgb(255, 176, 59),
            crit: Color::Rgb(255, 66, 84),
            border_ok: Color::Rgb(120, 92, 140),
            accent: Color::Rgb(255, 79, 163),
            rx: Color::Rgb(64, 224, 208),
            tx: Color::Rgb(255, 140, 66),
            muted: Color::Rgb(120, 100, 130),
            series: [
                Color::Rgb(255, 79, 163),  // hot pink
                Color::Rgb(255, 140, 66),  // orange
                Color::Rgb(178, 102, 255), // purple
                Color::Rgb(64, 224, 208),  // teal
                Color::Rgb(255, 205, 84),  // gold
                Color::Rgb(255, 105, 220), // magenta
            ],
        }
    }

    /// Earthy forest: moss accent, ochre/rust health, mushroom chart palette.
    fn moss_goblin() -> Theme {
        Theme {
            name: "moss_goblin",
            ok: Color::Rgb(140, 190, 90),
            warn: Color::Rgb(198, 160, 58),
            crit: Color::Rgb(190, 74, 58),
            border_ok: Color::Rgb(90, 105, 70),
            accent: Color::Rgb(122, 156, 78),
            rx: Color::Rgb(130, 180, 90),
            tx: Color::Rgb(150, 120, 70),
            muted: Color::Rgb(100, 110, 90),
            series: [
                Color::Rgb(122, 156, 78),  // moss
                Color::Rgb(198, 160, 58),  // ochre
                Color::Rgb(190, 74, 58),   // rust
                Color::Rgb(150, 186, 122), // sage
                Color::Rgb(150, 120, 70),  // bark
                Color::Rgb(214, 205, 160), // spore cream
            ],
        }
    }

    /// Classic cyberpunk: cyan accent, neon green/magenta health on a steel-blue frame.
    fn cybercity_night() -> Theme {
        Theme {
            name: "cybercity_night",
            ok: Color::Rgb(57, 255, 136),
            warn: Color::Rgb(255, 214, 10),
            crit: Color::Rgb(255, 45, 85),
            border_ok: Color::Rgb(70, 90, 120),
            accent: Color::Rgb(0, 229, 255),
            rx: Color::Rgb(0, 229, 255),
            tx: Color::Rgb(214, 93, 255),
            muted: Color::Rgb(80, 95, 120),
            series: [
                Color::Rgb(0, 229, 255),   // cyan
                Color::Rgb(214, 93, 255),  // magenta
                Color::Rgb(57, 255, 136),  // green
                Color::Rgb(255, 214, 10),  // yellow
                Color::Rgb(80, 140, 255),  // blue
                Color::Rgb(255, 105, 180), // pink
            ],
        }
    }

    /// Cozy hearth: warm orange accent, ember/gold health, firelit chart palette.
    fn cottage_fire() -> Theme {
        Theme {
            name: "cottage_fire",
            ok: Color::Rgb(150, 170, 90),
            warn: Color::Rgb(232, 168, 56),
            crit: Color::Rgb(208, 70, 44),
            border_ok: Color::Rgb(130, 110, 92),
            accent: Color::Rgb(230, 126, 48),
            rx: Color::Rgb(224, 168, 84),
            tx: Color::Rgb(180, 92, 64),
            muted: Color::Rgb(140, 120, 100),
            series: [
                Color::Rgb(230, 126, 48),  // ember orange
                Color::Rgb(224, 168, 84),  // gold
                Color::Rgb(180, 92, 64),   // brick
                Color::Rgb(150, 170, 90),  // sage
                Color::Rgb(226, 210, 172), // cream
                Color::Rgb(160, 52, 40),   // deep red
            ],
        }
    }

    /// Look up a theme by its stable name. Unknown names return `None`.
    pub fn by_name(name: &str) -> Option<Theme> {
        match name {
            "default" => Some(Self::default_theme()),
            "neon_sunset" => Some(Self::neon_sunset()),
            "moss_goblin" => Some(Self::moss_goblin()),
            "cybercity_night" => Some(Self::cybercity_night()),
            "cottage_fire" => Some(Self::cottage_fire()),
            _ => None,
        }
    }

    /// Resolve a name to a theme, falling back to [`Theme::default_theme`] for unknown names
    /// (config should never hard-fail on a typo'd theme).
    pub fn resolve(name: &str) -> Theme {
        Self::by_name(name).unwrap_or_else(Self::default_theme)
    }

    /// The next theme in [`Theme::NAMES`] cycle order (wraps).
    pub fn next(&self) -> Theme {
        let idx = Self::NAMES
            .iter()
            .position(|n| *n == self.name)
            .unwrap_or(0);
        let next = Self::NAMES[(idx + 1) % Self::NAMES.len()];
        Self::resolve(next)
    }

    /// Border+title style for a panel in the given health state.
    pub fn border_style(&self, health: Health) -> Style {
        match health {
            Health::Ok => Style::new().fg(self.border_ok),
            Health::Warn => Style::new().fg(self.warn).add_modifier(Modifier::BOLD),
            Health::Crit => Style::new().fg(self.crit).add_modifier(Modifier::BOLD),
        }
    }

    /// Accent color for a health state (status dots, gauges, text emphasis).
    pub fn health_color(&self, health: Health) -> Color {
        match health {
            Health::Ok => self.ok,
            Health::Warn => self.warn,
            Health::Crit => self.crit,
        }
    }

    /// Distinct color for the `i`-th series in a multi-line chart (wraps).
    pub fn series_color(&self, i: usize) -> Color {
        self.series[i % self.series.len()]
    }
}

impl Default for Theme {
    fn default() -> Self {
        Self::default_theme()
    }
}

/// A status glyph that differs per state (a redundant, color-blind-friendly signal on top
/// of the health color).
pub fn health_symbol(health: Health) -> &'static str {
    match health {
        Health::Ok => "●",
        Health::Warn => "▲",
        Health::Crit => "✖",
    }
}

/// Human label for the header banner.
pub fn health_label(health: Health) -> &'static str {
    match health {
        Health::Ok => "HEALTHY",
        Health::Warn => "DEGRADED",
        Health::Crit => "PROBLEM",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use pretty_assertions::assert_eq;

    // --- Default theme preserves the original hardcoded palette (visual contract) ---

    #[test]
    fn default_crit_border_is_bold_red() {
        let s = Theme::default_theme().border_style(Health::Crit);
        assert_eq!(s.fg, Some(Color::Red));
        assert!(s.add_modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn default_warn_border_is_yellow() {
        assert_eq!(
            Theme::default_theme().border_style(Health::Warn).fg,
            Some(Color::Yellow)
        );
    }

    #[test]
    fn default_ok_border_is_quiet() {
        // Not red or yellow — a calm, low-emphasis color.
        let fg = Theme::default_theme().border_style(Health::Ok).fg;
        assert_ne!(fg, Some(Color::Red));
        assert_ne!(fg, Some(Color::Yellow));
    }

    #[test]
    fn default_health_colors_are_distinct() {
        let t = Theme::default_theme();
        assert_eq!(t.health_color(Health::Ok), Color::Green);
        assert_eq!(t.health_color(Health::Warn), Color::Yellow);
        assert_eq!(t.health_color(Health::Crit), Color::Red);
    }

    #[test]
    fn default_series_colors_cycle() {
        let t = Theme::default_theme();
        assert_eq!(t.series_color(0), Color::Cyan);
        assert_ne!(t.series_color(0), t.series_color(1));
        assert_eq!(t.series_color(0), t.series_color(6)); // wraps
    }

    // --- Catalog ---

    #[test]
    fn all_named_themes_resolve() {
        for name in Theme::NAMES {
            let t = Theme::by_name(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(t.name, name, "theme name must match its catalog key");
        }
    }

    #[test]
    fn requested_themes_exist() {
        for name in [
            "neon_sunset",
            "moss_goblin",
            "cybercity_night",
            "cottage_fire",
        ] {
            assert!(Theme::by_name(name).is_some(), "{name} should exist");
        }
    }

    #[test]
    fn unknown_theme_is_none_but_resolves_to_default() {
        assert!(Theme::by_name("nope").is_none());
        assert_eq!(Theme::resolve("nope"), Theme::default_theme());
    }

    #[test]
    fn themes_are_visually_distinct() {
        // Accents differ across every pair of themes.
        let accents: Vec<Color> = Theme::NAMES
            .iter()
            .map(|n| Theme::resolve(n).accent)
            .collect();
        let unique: std::collections::HashSet<_> = accents.iter().collect();
        assert_eq!(unique.len(), Theme::NAMES.len(), "accents must be distinct");
    }

    #[test]
    fn every_theme_keeps_the_contract() {
        for name in Theme::NAMES {
            let t = Theme::resolve(name);
            // Crit border is bold.
            assert!(
                t.border_style(Health::Crit)
                    .add_modifier
                    .contains(Modifier::BOLD),
                "{name}: crit border must be bold"
            );
            // Three distinct health colors.
            let (ok, warn, crit) = (
                t.health_color(Health::Ok),
                t.health_color(Health::Warn),
                t.health_color(Health::Crit),
            );
            assert_ne!(ok, warn, "{name}: ok/warn must differ");
            assert_ne!(warn, crit, "{name}: warn/crit must differ");
            assert_ne!(ok, crit, "{name}: ok/crit must differ");
            // Healthy border is quiet — never the crit color.
            assert_ne!(
                t.border_style(Health::Ok).fg,
                Some(crit),
                "{name}: healthy border must not be the crit color"
            );
            // Six series colors, indexing wraps.
            assert_eq!(t.series_color(0), t.series_color(6), "{name}: series wraps");
        }
    }

    #[test]
    fn next_cycles_through_all_themes_and_wraps() {
        let mut t = Theme::default_theme();
        let mut seen = vec![t.name];
        for _ in 1..Theme::NAMES.len() {
            t = t.next();
            seen.push(t.name);
        }
        assert_eq!(seen, Theme::NAMES.to_vec(), "next() visits all in order");
        // One more step wraps back to the start.
        assert_eq!(t.next(), Theme::default_theme());
    }

    #[test]
    fn health_symbols_are_distinct() {
        let syms = [
            health_symbol(Health::Ok),
            health_symbol(Health::Warn),
            health_symbol(Health::Crit),
        ];
        assert_eq!(
            syms.iter().collect::<std::collections::HashSet<_>>().len(),
            3
        );
    }
}
