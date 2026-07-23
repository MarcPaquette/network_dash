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
    pub const NAMES: [&'static str; 20] = [
        "default",
        "neon_sunset",
        "moss_goblin",
        "cybercity_night",
        "cottage_fire",
        "arctic_aurora",
        "vaporwave",
        "dracula",
        "nord",
        "gruvbox",
        "tokyo_night",
        "catppuccin",
        "solarized_dark",
        "monokai",
        "rose_pine",
        "sakura",
        "deep_ocean",
        "desert_dune",
        "synthwave",
        "harvest",
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

    /// Icy aurora: glacier-blue accent, mint/amber health, cool northern-lights palette.
    fn arctic_aurora() -> Theme {
        Theme {
            name: "arctic_aurora",
            ok: Color::Rgb(126, 224, 184),
            warn: Color::Rgb(240, 200, 96),
            crit: Color::Rgb(240, 96, 112),
            border_ok: Color::Rgb(70, 100, 130),
            accent: Color::Rgb(94, 205, 255),
            rx: Color::Rgb(126, 224, 184),
            tx: Color::Rgb(150, 150, 255),
            muted: Color::Rgb(96, 116, 140),
            series: [
                Color::Rgb(94, 205, 255),  // glacier blue
                Color::Rgb(126, 224, 184), // mint
                Color::Rgb(168, 140, 255), // periwinkle
                Color::Rgb(120, 240, 220), // ice teal
                Color::Rgb(240, 200, 96),  // amber
                Color::Rgb(255, 120, 160), // rose
            ],
        }
    }

    /// 80s vaporwave: purple accent, teal/gold health, hot-pink & cyan chart palette.
    fn vaporwave() -> Theme {
        Theme {
            name: "vaporwave",
            ok: Color::Rgb(94, 234, 212),
            warn: Color::Rgb(255, 214, 102),
            crit: Color::Rgb(255, 84, 132),
            border_ok: Color::Rgb(108, 92, 160),
            accent: Color::Rgb(178, 112, 255),
            rx: Color::Rgb(94, 234, 212),
            tx: Color::Rgb(255, 128, 224),
            muted: Color::Rgb(130, 110, 160),
            series: [
                Color::Rgb(255, 113, 206), // hot pink
                Color::Rgb(1, 205, 254),   // cyan
                Color::Rgb(178, 112, 255), // purple
                Color::Rgb(5, 255, 161),   // mint
                Color::Rgb(255, 214, 102), // gold
                Color::Rgb(255, 128, 224), // magenta
            ],
        }
    }

    /// Dracula: canonical purple accent, green/orange health, pink & cyan chart palette.
    fn dracula() -> Theme {
        Theme {
            name: "dracula",
            ok: Color::Rgb(80, 250, 123),
            warn: Color::Rgb(255, 184, 108),
            crit: Color::Rgb(255, 85, 85),
            border_ok: Color::Rgb(98, 114, 164),
            accent: Color::Rgb(189, 147, 249),
            rx: Color::Rgb(139, 233, 253),
            tx: Color::Rgb(255, 121, 198),
            muted: Color::Rgb(98, 114, 164),
            series: [
                Color::Rgb(189, 147, 249), // purple
                Color::Rgb(255, 121, 198), // pink
                Color::Rgb(139, 233, 253), // cyan
                Color::Rgb(80, 250, 123),  // green
                Color::Rgb(255, 184, 108), // orange
                Color::Rgb(241, 250, 140), // yellow
            ],
        }
    }

    /// Nord: frost-blue accent, muted green/yellow health, arctic aurora chart palette.
    fn nord() -> Theme {
        Theme {
            name: "nord",
            ok: Color::Rgb(163, 190, 140),
            warn: Color::Rgb(235, 203, 139),
            crit: Color::Rgb(191, 97, 106),
            border_ok: Color::Rgb(76, 86, 106),
            accent: Color::Rgb(136, 192, 208),
            rx: Color::Rgb(143, 188, 187),
            tx: Color::Rgb(180, 142, 173),
            muted: Color::Rgb(97, 110, 136),
            series: [
                Color::Rgb(136, 192, 208), // frost
                Color::Rgb(180, 142, 173), // purple
                Color::Rgb(163, 190, 140), // green
                Color::Rgb(235, 203, 139), // yellow
                Color::Rgb(129, 161, 193), // blue
                Color::Rgb(208, 135, 112), // orange
            ],
        }
    }

    /// Gruvbox: retro orange accent, green/yellow health, warm earthy chart palette.
    fn gruvbox() -> Theme {
        Theme {
            name: "gruvbox",
            ok: Color::Rgb(184, 187, 38),
            warn: Color::Rgb(250, 189, 47),
            crit: Color::Rgb(251, 73, 52),
            border_ok: Color::Rgb(102, 92, 84),
            accent: Color::Rgb(254, 128, 25),
            rx: Color::Rgb(142, 192, 124),
            tx: Color::Rgb(131, 165, 152),
            muted: Color::Rgb(146, 131, 116),
            series: [
                Color::Rgb(254, 128, 25),  // orange
                Color::Rgb(184, 187, 38),  // green
                Color::Rgb(250, 189, 47),  // yellow
                Color::Rgb(131, 165, 152), // blue
                Color::Rgb(211, 134, 155), // purple
                Color::Rgb(142, 192, 124), // aqua
            ],
        }
    }

    /// Tokyo Night: soft indigo accent, muted green/amber health, storm-blue chart palette.
    fn tokyo_night() -> Theme {
        Theme {
            name: "tokyo_night",
            ok: Color::Rgb(158, 206, 106),
            warn: Color::Rgb(224, 175, 104),
            crit: Color::Rgb(247, 118, 142),
            border_ok: Color::Rgb(86, 95, 137),
            accent: Color::Rgb(122, 162, 247),
            rx: Color::Rgb(125, 207, 255),
            tx: Color::Rgb(187, 154, 247),
            muted: Color::Rgb(86, 95, 137),
            series: [
                Color::Rgb(122, 162, 247), // blue
                Color::Rgb(187, 154, 247), // magenta
                Color::Rgb(125, 207, 255), // cyan
                Color::Rgb(158, 206, 106), // green
                Color::Rgb(224, 175, 104), // orange
                Color::Rgb(247, 118, 142), // red
            ],
        }
    }

    /// Catppuccin Mocha: mauve accent, green/peach health, pastel chart palette.
    fn catppuccin() -> Theme {
        Theme {
            name: "catppuccin",
            ok: Color::Rgb(166, 227, 161),
            warn: Color::Rgb(250, 179, 135),
            crit: Color::Rgb(243, 139, 168),
            border_ok: Color::Rgb(108, 112, 134),
            accent: Color::Rgb(203, 166, 247),
            rx: Color::Rgb(148, 226, 213),
            tx: Color::Rgb(245, 194, 231),
            muted: Color::Rgb(108, 112, 134),
            series: [
                Color::Rgb(203, 166, 247), // mauve
                Color::Rgb(245, 194, 231), // pink
                Color::Rgb(137, 180, 250), // blue
                Color::Rgb(166, 227, 161), // green
                Color::Rgb(249, 226, 175), // yellow
                Color::Rgb(250, 179, 135), // peach
            ],
        }
    }

    /// Solarized Dark: cyan accent, olive/amber health, the classic solarized accents.
    fn solarized_dark() -> Theme {
        Theme {
            name: "solarized_dark",
            ok: Color::Rgb(133, 153, 0),
            warn: Color::Rgb(181, 137, 0),
            crit: Color::Rgb(220, 50, 47),
            border_ok: Color::Rgb(88, 110, 117),
            accent: Color::Rgb(42, 161, 152),
            rx: Color::Rgb(38, 139, 210),
            tx: Color::Rgb(211, 54, 130),
            muted: Color::Rgb(88, 110, 117),
            series: [
                Color::Rgb(42, 161, 152),  // cyan
                Color::Rgb(38, 139, 210),  // blue
                Color::Rgb(133, 153, 0),   // green
                Color::Rgb(181, 137, 0),   // yellow
                Color::Rgb(211, 54, 130),  // magenta
                Color::Rgb(108, 113, 196), // violet
            ],
        }
    }

    /// Monokai: cyan accent, lime/yellow health, the signature hot-pink chart palette.
    fn monokai() -> Theme {
        Theme {
            name: "monokai",
            ok: Color::Rgb(166, 226, 46),
            warn: Color::Rgb(230, 219, 116),
            crit: Color::Rgb(249, 38, 114),
            border_ok: Color::Rgb(117, 113, 94),
            accent: Color::Rgb(102, 217, 239),
            rx: Color::Rgb(102, 217, 239),
            tx: Color::Rgb(174, 129, 255),
            muted: Color::Rgb(117, 113, 94),
            series: [
                Color::Rgb(249, 38, 114),  // pink
                Color::Rgb(166, 226, 46),  // lime
                Color::Rgb(102, 217, 239), // cyan
                Color::Rgb(253, 151, 31),  // orange
                Color::Rgb(174, 129, 255), // purple
                Color::Rgb(230, 219, 116), // yellow
            ],
        }
    }

    /// Rosé Pine: rose accent, foam/gold health, iris & pine chart palette.
    fn rose_pine() -> Theme {
        Theme {
            name: "rose_pine",
            ok: Color::Rgb(156, 207, 216),
            warn: Color::Rgb(246, 193, 119),
            crit: Color::Rgb(235, 111, 146),
            border_ok: Color::Rgb(110, 106, 134),
            accent: Color::Rgb(235, 188, 186),
            rx: Color::Rgb(156, 207, 216),
            tx: Color::Rgb(196, 167, 231),
            muted: Color::Rgb(110, 106, 134),
            series: [
                Color::Rgb(196, 167, 231), // iris
                Color::Rgb(235, 111, 146), // love
                Color::Rgb(156, 207, 216), // foam
                Color::Rgb(246, 193, 119), // gold
                Color::Rgb(49, 116, 143),  // pine
                Color::Rgb(235, 188, 186), // rose
            ],
        }
    }

    /// Sakura: blossom-pink accent, leaf-green/amber health, soft spring chart palette.
    fn sakura() -> Theme {
        Theme {
            name: "sakura",
            ok: Color::Rgb(150, 205, 140),
            warn: Color::Rgb(240, 190, 100),
            crit: Color::Rgb(235, 90, 110),
            border_ok: Color::Rgb(150, 120, 135),
            accent: Color::Rgb(255, 145, 175),
            rx: Color::Rgb(150, 205, 140),
            tx: Color::Rgb(200, 150, 220),
            muted: Color::Rgb(160, 130, 145),
            series: [
                Color::Rgb(255, 145, 175), // blossom
                Color::Rgb(255, 183, 197), // petal
                Color::Rgb(200, 150, 220), // wisteria
                Color::Rgb(150, 205, 140), // leaf
                Color::Rgb(240, 190, 100), // amber
                Color::Rgb(120, 180, 200), // sky
            ],
        }
    }

    /// Deep Ocean: teal accent, aquamarine/gold health, abyssal blue chart palette.
    fn deep_ocean() -> Theme {
        Theme {
            name: "deep_ocean",
            ok: Color::Rgb(72, 207, 173),
            warn: Color::Rgb(240, 196, 84),
            crit: Color::Rgb(240, 98, 110),
            border_ok: Color::Rgb(40, 70, 95),
            accent: Color::Rgb(0, 168, 204),
            rx: Color::Rgb(72, 207, 173),
            tx: Color::Rgb(94, 140, 220),
            muted: Color::Rgb(70, 100, 125),
            series: [
                Color::Rgb(0, 168, 204),   // teal
                Color::Rgb(72, 207, 173),  // aquamarine
                Color::Rgb(94, 140, 220),  // blue
                Color::Rgb(240, 196, 84),  // gold
                Color::Rgb(240, 98, 110),  // coral
                Color::Rgb(130, 110, 200), // violet
            ],
        }
    }

    /// Desert Dune: sand accent, sage/gold health, terracotta chart palette.
    fn desert_dune() -> Theme {
        Theme {
            name: "desert_dune",
            ok: Color::Rgb(166, 180, 110),
            warn: Color::Rgb(226, 170, 70),
            crit: Color::Rgb(200, 80, 55),
            border_ok: Color::Rgb(120, 100, 80),
            accent: Color::Rgb(210, 155, 100),
            rx: Color::Rgb(166, 180, 110),
            tx: Color::Rgb(180, 130, 90),
            muted: Color::Rgb(140, 120, 100),
            series: [
                Color::Rgb(210, 155, 100), // sand
                Color::Rgb(226, 170, 70),  // gold
                Color::Rgb(200, 80, 55),   // terracotta
                Color::Rgb(166, 180, 110), // sage
                Color::Rgb(228, 205, 160), // dune cream
                Color::Rgb(150, 110, 80),  // clay
            ],
        }
    }

    /// Synthwave '84: electric-purple accent, neon mint/gold health, retro chart palette.
    fn synthwave() -> Theme {
        Theme {
            name: "synthwave",
            ok: Color::Rgb(63, 240, 180),
            warn: Color::Rgb(255, 199, 95),
            crit: Color::Rgb(255, 66, 110),
            border_ok: Color::Rgb(90, 70, 140),
            accent: Color::Rgb(211, 54, 255),
            rx: Color::Rgb(0, 240, 255),
            tx: Color::Rgb(255, 113, 206),
            muted: Color::Rgb(120, 95, 160),
            series: [
                Color::Rgb(211, 54, 255),  // electric purple
                Color::Rgb(255, 113, 206), // hot pink
                Color::Rgb(0, 240, 255),   // cyan
                Color::Rgb(63, 240, 180),  // neon mint
                Color::Rgb(255, 199, 95),  // gold
                Color::Rgb(255, 66, 110),  // neon red
            ],
        }
    }

    /// Harvest: golden accent, olive/pumpkin health, warm autumnal chart palette.
    fn harvest() -> Theme {
        Theme {
            name: "harvest",
            ok: Color::Rgb(150, 168, 72),
            warn: Color::Rgb(223, 146, 42),
            crit: Color::Rgb(194, 58, 40),
            border_ok: Color::Rgb(110, 92, 66),
            accent: Color::Rgb(230, 175, 45),
            rx: Color::Rgb(150, 168, 72),
            tx: Color::Rgb(176, 98, 54),
            muted: Color::Rgb(140, 118, 86),
            series: [
                Color::Rgb(230, 175, 45),  // gold
                Color::Rgb(176, 98, 54),   // rust
                Color::Rgb(194, 58, 40),   // deep red
                Color::Rgb(150, 168, 72),  // olive
                Color::Rgb(222, 196, 140), // wheat
                Color::Rgb(120, 90, 60),   // bark
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
            "arctic_aurora" => Some(Self::arctic_aurora()),
            "vaporwave" => Some(Self::vaporwave()),
            "dracula" => Some(Self::dracula()),
            "nord" => Some(Self::nord()),
            "gruvbox" => Some(Self::gruvbox()),
            "tokyo_night" => Some(Self::tokyo_night()),
            "catppuccin" => Some(Self::catppuccin()),
            "solarized_dark" => Some(Self::solarized_dark()),
            "monokai" => Some(Self::monokai()),
            "rose_pine" => Some(Self::rose_pine()),
            "sakura" => Some(Self::sakura()),
            "deep_ocean" => Some(Self::deep_ocean()),
            "desert_dune" => Some(Self::desert_dune()),
            "synthwave" => Some(Self::synthwave()),
            "harvest" => Some(Self::harvest()),
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
    fn catalog_has_twenty_themes() {
        assert_eq!(Theme::NAMES.len(), 20);
    }

    #[test]
    fn new_themes_exist() {
        for name in [
            // first expansion (5)
            "arctic_aurora",
            "vaporwave",
            "dracula",
            "nord",
            "gruvbox",
            // second expansion (10)
            "tokyo_night",
            "catppuccin",
            "solarized_dark",
            "monokai",
            "rose_pine",
            "sakura",
            "deep_ocean",
            "desert_dune",
            "synthwave",
            "harvest",
        ] {
            let t = Theme::by_name(name).unwrap_or_else(|| panic!("{name} missing"));
            assert_eq!(t.name, name, "theme name must match its catalog key");
            assert!(Theme::NAMES.contains(&name), "{name} must be in NAMES");
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
