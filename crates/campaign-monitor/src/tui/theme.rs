//! Color depth, the semantic styles views draw with, and the glyph set.
//! A theme is resolved once for one depth; under `NO_COLOR` every color is
//! `Reset` and modifiers carry selection and emphasis, because crossterm's
//! empty SGR for a color would cancel them.

use ratatui::buffer::Buffer;
use ratatui::style::{Color, Modifier, Style};

use crate::outcome::{Domain, Outcome};
use crate::signals::Severity;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ColorDepth {
    /// No color; modifiers keep the selection and emphasis visible.
    None,
    Ansi16,
    Indexed256,
    TrueColor,
}

impl ColorDepth {
    /// `override_depth` when given, else the depth `NO_COLOR`, `COLORTERM`
    /// and `TERM` name.
    pub fn detect(override_depth: Option<ColorDepth>) -> Self {
        Self::from_env(
            override_depth,
            std::env::var_os("NO_COLOR").is_some_and(|value| !value.is_empty()),
            std::env::var("COLORTERM").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
        )
    }

    pub fn from_env(
        override_depth: Option<ColorDepth>,
        no_color: bool,
        colorterm: Option<&str>,
        term: Option<&str>,
    ) -> Self {
        if let Some(depth) = override_depth {
            return depth;
        }
        if no_color {
            return Self::None;
        }
        if matches!(colorterm, Some("truecolor" | "24bit")) {
            return Self::TrueColor;
        }
        match term {
            Some(term) if term.contains("256") => Self::Indexed256,
            Some("dumb") => Self::None,
            _ => Self::Ansi16,
        }
    }
}

/// The symbols the views draw. Views draw Unicode; [`Glyphs::Ascii`] maps
/// every non-ASCII symbol they use to an ASCII one after the frame is
/// drawn, so a console without those glyphs shows the same layout. Box
/// borders stay as drawn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Glyphs {
    Unicode,
    Ascii,
}

/// Each non-ASCII symbol a view draws, outside borders and snapshot text,
/// and its one-column ASCII stand-in.
const ASCII: [(&str, &str); 21] = [
    ("✓", "+"),
    ("✗", "x"),
    ("▶", ">"),
    ("…", "."),
    ("·", "-"),
    ("●", "*"),
    ("▸", ">"),
    ("▌", ">"),
    ("▏", "|"),
    ("↑", "^"),
    ("↓", "v"),
    ("←", "<"),
    ("→", ">"),
    ("▁", "_"),
    ("▂", "."),
    ("▃", "-"),
    ("▄", "="),
    ("▅", "+"),
    ("▆", "*"),
    ("▇", "%"),
    ("█", "#"),
];

impl Glyphs {
    /// The ASCII stand-in for `symbol`, or `None` for a symbol drawn as is.
    pub fn ascii(symbol: &str) -> Option<&'static str> {
        ASCII
            .iter()
            .find(|(unicode, _)| *unicode == symbol)
            .map(|(_, ascii)| *ascii)
    }

    /// Rewrites the drawn `buffer` to this glyph set.
    pub fn apply(self, buffer: &mut Buffer) {
        if self == Self::Unicode {
            return;
        }
        for cell in &mut buffer.content {
            if let Some(ascii) = Self::ascii(cell.symbol()) {
                cell.set_symbol(ascii);
            }
        }
    }
}

/// The marker drawn beside a severity's color, so the severity reads
/// without hue.
pub fn marker(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "!!",
        Severity::Warning => "!",
        Severity::Info => "i",
    }
}

/// Semantic styles resolved for one color depth. `selection` marks the
/// focused list's row and the current tab; `selection_inactive` the row of
/// a list whose search has the keys. The domain roles color outcomes by
/// failure domain; `unsettled` colors outcomes without one that are not a
/// pass.
#[derive(Clone, Copy, Debug)]
pub struct Theme {
    pub glyphs: Glyphs,
    pub text: Style,
    pub muted: Style,
    pub heading: Style,
    pub border: Style,
    pub border_focused: Style,
    pub selection: Style,
    pub selection_inactive: Style,
    pub matched: Style,
    pub key_hint: Style,
    pub error: Style,
    pub warning: Style,
    pub info: Style,
    pub success: Style,
    pub service: Style,
    pub simulator: Style,
    pub campaign: Style,
    pub host: Style,
    pub chaos: Style,
    pub unsettled: Style,
}

impl Theme {
    pub fn resolve(depth: ColorDepth, glyphs: Glyphs) -> Self {
        let c = |rgb: (u8, u8, u8), ansi: Color| pick(depth, rgb, ansi);
        let mono = |modifier: Modifier| {
            if depth == ColorDepth::None {
                modifier
            } else {
                Modifier::empty()
            }
        };
        let fg = |rgb, ansi| Style::new().fg(c(rgb, ansi));
        Self {
            glyphs,
            text: fg((220, 220, 220), Color::Reset),
            muted: fg((128, 128, 128), Color::DarkGray).add_modifier(mono(Modifier::DIM)),
            heading: Style::new().add_modifier(Modifier::BOLD),
            border: fg((88, 88, 88), Color::DarkGray),
            border_focused: fg((97, 175, 239), Color::Blue).add_modifier(Modifier::BOLD),
            selection: Style::new()
                .fg(c((20, 20, 20), Color::Black))
                .bg(c((97, 175, 239), Color::Blue))
                .add_modifier(mono(Modifier::REVERSED)),
            selection_inactive: Style::new()
                .bg(c((60, 60, 60), Color::DarkGray))
                .add_modifier(mono(Modifier::REVERSED | Modifier::DIM)),
            matched: fg((229, 192, 123), Color::Yellow)
                .add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            key_hint: fg((97, 175, 239), Color::Cyan).add_modifier(Modifier::BOLD),
            error: fg((224, 108, 117), Color::Red).add_modifier(Modifier::BOLD),
            warning: fg((229, 192, 123), Color::Yellow),
            info: fg((86, 182, 194), Color::Cyan),
            success: fg((152, 195, 121), Color::Green),
            service: fg((224, 108, 117), Color::Red).add_modifier(Modifier::BOLD),
            simulator: fg((198, 120, 221), Color::Magenta),
            campaign: fg((229, 192, 123), Color::Yellow),
            host: fg((240, 140, 120), Color::LightRed),
            chaos: fg((97, 175, 239), Color::Blue),
            unsettled: fg((171, 178, 191), Color::Gray),
        }
    }

    pub fn severity(&self, severity: Severity) -> Style {
        match severity {
            Severity::Critical => self.error,
            Severity::Warning => self.warning,
            Severity::Info => self.info,
        }
    }

    /// The style of an outcome with `domain`; a pass, which has no domain,
    /// is `success`.
    pub fn domain(&self, domain: Option<Domain>, pass: bool) -> Style {
        match domain {
            None if pass => self.success,
            None => self.unsettled,
            Some(Domain::Service) => self.service,
            Some(Domain::Simulator) => self.simulator,
            Some(Domain::Campaign) => self.campaign,
            Some(Domain::Host) => self.host,
            Some(Domain::Chaos) => self.chaos,
        }
    }

    pub fn outcome(&self, outcome: &Outcome) -> Style {
        self.domain(outcome.domain, outcome.is_pass())
    }
}

fn pick(depth: ColorDepth, (r, g, b): (u8, u8, u8), ansi: Color) -> Color {
    match depth {
        ColorDepth::TrueColor => Color::Rgb(r, g, b),
        ColorDepth::Indexed256 => Color::Indexed(rgb_to_256(r, g, b)),
        ColorDepth::Ansi16 => ansi,
        ColorDepth::None => Color::Reset,
    }
}

const CUBE_LEVELS: [u8; 6] = [0, 95, 135, 175, 215, 255];

/// Nearest xterm 256-color index by squared RGB distance, choosing between
/// the closest 6x6x6 cube entry (16..=231, levels `CUBE_LEVELS`) and the
/// closest grey-ramp entry (232..=255, levels `8 + 10 * i`).
pub fn rgb_to_256(r: u8, g: u8, b: u8) -> u8 {
    let nearest_level = |v: u8| {
        (0..CUBE_LEVELS.len())
            .min_by_key(|&i| CUBE_LEVELS[i].abs_diff(v))
            .unwrap_or(0)
    };
    let dist = |(r2, g2, b2): (u8, u8, u8)| {
        let d = |a: u8, b: u8| u32::from(a.abs_diff(b)).pow(2);
        d(r, r2) + d(g, g2) + d(b, b2)
    };
    let (ci, cj, ck) = (nearest_level(r), nearest_level(g), nearest_level(b));
    let cube = (CUBE_LEVELS[ci], CUBE_LEVELS[cj], CUBE_LEVELS[ck]);
    let cube_index = 16 + 36 * ci + 6 * cj + ck;
    let mean = (u32::from(r) + u32::from(g) + u32::from(b)) / 3;
    let grey_step = ((mean.saturating_sub(8) + 5) / 10).min(23);
    let level = u8::try_from(8 + 10 * grey_step).unwrap_or(u8::MAX);
    if dist((level, level, level)) < dist(cube) {
        232 + u8::try_from(grey_step).unwrap_or(23)
    } else {
        u8::try_from(cube_index).unwrap_or(231)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_override_beats_the_environment() {
        let depth = ColorDepth::from_env(Some(ColorDepth::TrueColor), true, None, Some("xterm"));
        assert_eq!(depth, ColorDepth::TrueColor);
    }

    #[test]
    fn detection_reads_no_color_then_colorterm_then_term() {
        let d = |no_color, colorterm, term| ColorDepth::from_env(None, no_color, colorterm, term);
        assert_eq!(d(true, Some("truecolor"), None), ColorDepth::None);
        assert_eq!(d(false, Some("24bit"), None), ColorDepth::TrueColor);
        assert_eq!(
            d(false, None, Some("tmux-256color")),
            ColorDepth::Indexed256
        );
        assert_eq!(d(false, None, Some("xterm")), ColorDepth::Ansi16);
        assert_eq!(d(false, None, Some("dumb")), ColorDepth::None);
    }

    #[test]
    fn rgb_maps_to_the_nearer_of_the_grey_ramp_and_the_cube() {
        assert_eq!(rgb_to_256(0, 0, 0), 16);
        assert_eq!(rgb_to_256(255, 255, 255), 231);
        assert_eq!(rgb_to_256(238, 238, 238), 255);
        assert_eq!(rgb_to_256(128, 128, 128), 244);
        assert_eq!(rgb_to_256(255, 0, 0), 196);
        assert_eq!(rgb_to_256(0, 0, 255), 21);
    }

    #[test]
    fn no_color_keeps_the_selection_visible_with_reverse_video() {
        let theme = Theme::resolve(ColorDepth::None, Glyphs::Unicode);
        assert!(theme.selection.add_modifier.contains(Modifier::REVERSED));
        assert_eq!(theme.selection.bg, Some(Color::Reset));
        let colored = Theme::resolve(ColorDepth::Ansi16, Glyphs::Unicode);
        assert!(!colored.selection.add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn every_sparkline_bar_level_has_an_ascii_stand_in() {
        let bars = ratatui::symbols::bar::Set::default();
        for level in [
            bars.one_eighth,
            bars.one_quarter,
            bars.three_eighths,
            bars.half,
            bars.five_eighths,
            bars.three_quarters,
            bars.seven_eighths,
            bars.full,
        ] {
            assert!(Glyphs::ascii(level).is_some(), "{level}");
        }
    }

    #[test]
    fn every_mapped_glyph_has_a_one_column_ascii_stand_in() {
        for (unicode, ascii) in ASCII {
            assert_eq!(unicode.chars().count(), 1, "{unicode}");
            assert!(ascii.is_ascii() && ascii.len() == 1, "{unicode} -> {ascii}");
        }
        assert_eq!(Glyphs::ascii("x"), None);
    }
}
