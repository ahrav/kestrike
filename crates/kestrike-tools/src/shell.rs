//! The shell split of one argument, as Python's `shlex.split` performs it in POSIX mode.
//!
//! Words split on space, tab, carriage return and line feed. Text in `'...'` is literal. In `"..."` a
//! backslash escapes `"` and `\`, and stays in the word before any other code point. Outside quotes a
//! backslash takes the next code point literally, a line feed included. Adjacent pieces join into one word, and
//! a quoted empty piece alone is an empty word.

use crate::text::Text;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The text ends inside `'...'` or `"..."`.
    UnclosedQuotation,
    /// The text ends after an unescaped backslash inside `"..."` or outside quotes.
    TrailingBackslash,
}

/// `Word` holds a word that is nonempty or holds a quoted piece, so a separator in `Word` ends a word.
#[derive(Clone, Copy, PartialEq, Eq)]
enum State {
    Space,
    Word,
    Single,
    Double,
    /// `Escape` awaits the next code point. `in_double` selects double-quote escape rules and resumes
    /// `Double` afterward.
    Escape {
        in_double: bool,
    },
}

const BACKSLASH: u32 = 0x5c;
const SINGLE: u32 = 0x27;
const DOUBLE: u32 = 0x22;

fn is_separator(code: u32) -> bool {
    matches!(code, 0x20 | 0x9 | 0xd | 0xa)
}

fn push(word: &mut Text, code: u32) {
    word.push_code_point(code)
        .expect("a code point of a text is at most U+10FFFF");
}

/// # Errors
///
/// The text ends inside a quotation or after an unescaped backslash.
pub fn split(text: &Text) -> Result<Vec<Text>, Error> {
    let mut words = Vec::new();
    let mut word = Text::new();
    let mut state = State::Space;
    for code in text.code_points() {
        state = match state {
            State::Space | State::Word if is_separator(code) => {
                if state == State::Word {
                    words.push(std::mem::take(&mut word));
                }
                State::Space
            }
            State::Space | State::Word => match code {
                BACKSLASH => State::Escape { in_double: false },
                SINGLE => State::Single,
                DOUBLE => State::Double,
                _ => {
                    push(&mut word, code);
                    State::Word
                }
            },
            State::Single if code == SINGLE => State::Word,
            State::Double if code == DOUBLE => State::Word,
            State::Double if code == BACKSLASH => State::Escape { in_double: true },
            State::Single | State::Double => {
                push(&mut word, code);
                state
            }
            State::Escape { in_double } => {
                if in_double && code != BACKSLASH && code != DOUBLE {
                    push(&mut word, BACKSLASH);
                }
                push(&mut word, code);
                if in_double {
                    State::Double
                } else {
                    State::Word
                }
            }
        };
    }
    match state {
        State::Single | State::Double => Err(Error::UnclosedQuotation),
        State::Escape { .. } => Err(Error::TrailingBackslash),
        State::Word => {
            words.push(word);
            Ok(words)
        }
        State::Space => Ok(words),
    }
}
