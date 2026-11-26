//! Display text for terminal cells. Snapshot text passes [`sanitize`] once,
//! so no control character reaches the buffer, and every cut here is
//! measured in display columns and made between grapheme clusters.

use std::borrow::Cow;

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

/// Columns between tab stops when a tab is expanded.
const TAB: usize = 8;

/// `text` with each tab expanded to spaces up to the next tab stop and
/// every other control character written as its Rust escape (`\n`,
/// `\u{1b}`). Borrowed when `text` holds no control character.
pub fn sanitize(text: &str) -> Cow<'_, str> {
    if is_clean(text) {
        return Cow::Borrowed(text);
    }
    let mut shown = String::with_capacity(text.len() + 8);
    let mut column = 0;
    for grapheme in text.graphemes(true) {
        if grapheme == "\t" {
            let spaces = TAB - column % TAB;
            shown.extend(std::iter::repeat_n(' ', spaces));
            column += spaces;
        } else if grapheme.contains(char::is_control) {
            for c in grapheme.chars() {
                if c.is_control() {
                    let escaped: String = c.escape_default().collect();
                    column += escaped.len();
                    shown.push_str(&escaped);
                } else {
                    column += c.to_string().width();
                    shown.push(c);
                }
            }
        } else {
            column += grapheme.width();
            shown.push_str(grapheme);
        }
    }
    Cow::Owned(shown)
}

/// Whether `text` holds no control character, so [`sanitize`] returns it
/// unchanged.
pub fn is_clean(text: &str) -> bool {
    !text.contains(char::is_control)
}

/// Replaces `text` with its [`sanitize`]d form and returns whether that
/// changed it.
pub fn clean(text: &mut String) -> bool {
    match sanitize(text) {
        Cow::Borrowed(_) => false,
        Cow::Owned(shown) => {
            *text = shown;
            true
        }
    }
}

/// Display columns of `text`.
pub fn width(text: &str) -> usize {
    text.width()
}

/// The longest leading part of `text` that fits in `width` columns, cut
/// between grapheme clusters.
pub fn prefix(text: &str, width: usize) -> &str {
    let mut used = 0;
    for (start, grapheme) in text.grapheme_indices(true) {
        used += grapheme.width();
        if used > width {
            return &text[..start];
        }
    }
    text
}

/// `text` cut to `width` columns, ending in `…` after a cut.
pub fn clip(text: &str, width: usize) -> String {
    if self::width(text) <= width {
        return text.to_owned();
    }
    format!("{}…", prefix(text, width.saturating_sub(1)))
}

/// `text` cut from the left to `width` columns, starting with `…` after a
/// cut, so the most specific end of a path stays.
pub fn clip_left(text: &str, width: usize) -> String {
    if self::width(text) <= width {
        return text.to_owned();
    }
    let room = width.saturating_sub(1);
    let mut used = 0;
    let mut start = text.len();
    for (index, grapheme) in text.grapheme_indices(true).rev() {
        used += grapheme.width();
        if used > room {
            break;
        }
        start = index;
    }
    format!("…{}", &text[start..])
}

/// The first of `candidates` that fits in `width` columns, or the last one
/// clipped to `width`.
pub fn fit<const N: usize>(candidates: [String; N], width: usize) -> String {
    let last = candidates.last().cloned().unwrap_or_default();
    candidates
        .into_iter()
        .find(|line| self::width(line) <= width)
        .unwrap_or_else(|| clip(&last, width))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A tab erases cells and an ESC prints as stray text when they reach
    /// the buffer, so both become visible, fixed-width text.
    #[test]
    fn sanitize_expands_tabs_and_escapes_other_controls() {
        assert!(matches!(sanitize("plain"), Cow::Borrowed("plain")));
        assert_eq!(sanitize("a\tb"), "a       b");
        assert_eq!(sanitize("abcdefgh\tc"), "abcdefgh        c");
        assert_eq!(sanitize("x\u{1b}[31my\n"), "x\\u{1b}[31my\\n");
        let mut text = "ok".to_owned();
        assert!(!clean(&mut text));
        text.push('\r');
        assert!(clean(&mut text));
        assert_eq!(text, "ok\\r");
    }

    /// Wide characters take two columns, so a cut that counted characters
    /// would overflow a fixed column.
    #[test]
    fn cuts_count_display_columns_and_keep_graphemes_whole() {
        assert_eq!(prefix("日本語", 5), "日本");
        assert_eq!(clip("日本語abc", 6), "日本…");
        assert_eq!(width(&clip("日本語abc", 6)), 5);
        assert_eq!(clip("short", 5), "short");
        assert_eq!(clip_left("/a/日本/c", 6), "…本/c");
        assert_eq!(prefix("e\u{301}x", 1), "e\u{301}");
        assert_eq!(
            fit(["a long form".to_owned(), "short".to_owned()], 6),
            "short"
        );
        assert_eq!(fit(["toolong".to_owned()], 4), "too…");
    }
}
