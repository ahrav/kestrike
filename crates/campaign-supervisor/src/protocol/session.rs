//! The session form's output, `session: N windows, chain HEX` and its end
//! line, and the session replay's verdict line.
//!
//! The end line's `stop`, `terminal` and `failure` values hold spaces, so
//! each of its values ends at the next field's marker; `failure`, the
//! debug text of the first failed check, ends at the last ` carried=`, so
//! its text may hold any marker. A divergence names the first window and
//! record that differ, and a turn's virtual time and candidate when the
//! worker prints them for a differing turn record.

use crate::record::Digest;

use super::Error;
use super::pairs::{Pairs, count, digest, fill, flag, hex};
use super::summary::stopped;
use super::terminal::Terminal;

/// Hexadecimal digits of a turn's candidate, 16 bytes.
const CANDIDATE: usize = 32;

const END: &str = "stop={} terminal={} counts={} turns={} virtual_us={} skipped_us={} rested_us={} \
    apply_ms={} failure={*} carried={} registry={} outstanding={} kept={} window_bytes={}";

/// The session form's output: the committed window count, their chain
/// digest and the end line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Session {
    pub windows: u64,
    pub chain: Digest,
    pub end: End,
}

/// How a session's run ended. `virtual_us` is the clock at the end,
/// `skipped_us` its whole advance and `rested_us` the idle part of that
/// advance between phases; `apply_ms` is wall time spent applying turns.
/// The last five are high-water marks: uploads carried, registry entries
/// per partition, outstanding GETs at a cut, records per link audit and
/// window bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct End {
    pub stop: String,
    pub terminal: Terminal,
    pub counts: bool,
    pub turns: u64,
    pub virtual_us: u64,
    pub skipped_us: u64,
    pub rested_us: u64,
    pub apply_ms: u64,
    /// The debug text of the first failed check, or `None` when none failed.
    pub failure: Option<String>,
    pub carried: u64,
    pub registry: u64,
    pub outstanding: u64,
    pub kept: u64,
    pub window_bytes: u64,
}

/// The session replay's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionReplay {
    Reproduced { windows: u64, chain: Digest },
    Diverged(Divergence),
}

/// Where a replayed session first departs from the committed one. Window
/// and record indexes count from 0.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Divergence {
    /// The window counts differ from window `at`, the smaller count.
    Windows {
        at: u64,
        committed: u64,
        replayed: u64,
    },
    /// Every window matched and the end lines differ.
    End,
    /// Record `record` of window `window` is a turn that differs. The
    /// virtual time and candidate come from the committed session's
    /// record, or from the replayed one's when the committed window ends
    /// before that record.
    Turn {
        window: u64,
        record: u64,
        virtual_us: u64,
        candidate: Candidate,
    },
    /// Record `record` of window `window`, of this one-byte tag, differs.
    /// A turn record whose body does not decode reads as this form.
    Record { window: u64, record: u64, tag: u8 },
}

/// A turn's 16-byte candidate as the 32 lowercase hexadecimal digits the
/// worker printed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Candidate(pub(super) String);

impl Candidate {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Session {
    /// The session form's output `text`.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for output cut short; [`Error::Unpaired`] for a
    /// line with no `": "`; [`Error::Missing`] and [`Error::Repeated`] for
    /// an absent or doubled `session` or `end` line; [`Error::Unknown`] for
    /// a line of another key; [`Error::Value`] for a `session` line outside
    /// its form; and the errors of [`End::parse`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        let [windows, chain] = fill(lines.one("session")?, "{} windows, chain {}", "session")?;
        let session = Self {
            windows: count(windows, "session")?,
            chain: digest(chain, "session")?,
            end: End::parse(lines.one("end")?)?,
        };
        lines.finish()?;
        Ok(session)
    }
}

impl End {
    /// The value of the stdout `end:` line, whose `counts` must hold
    /// exactly when its terminal passes and which names no failure when it
    /// counts. A counting end reaches `goal`. The stored end file appends its windows, chain and tail
    /// fields to this value; this grammar reads the value without them.
    ///
    /// # Errors
    ///
    /// [`Error::Value`] for a value outside its form, and
    /// [`Error::Inconsistent`] for a `counts` that disagrees with the
    /// terminal, a counting end short of its goal or naming a failure, or times outside
    /// `rested_us <= skipped_us <= virtual_us`.
    pub fn parse(line: &str) -> Result<Self, Error> {
        let key = "end";
        let [
            stop,
            terminal,
            counts,
            turns,
            virtual_us,
            skipped_us,
            rested_us,
            apply_ms,
            failure,
            carried,
            registry,
            outstanding,
            kept,
            window_bytes,
        ] = fill(line, END, key)?;
        let failure = match failure {
            "None" => None,
            _ => Some(
                failure
                    .strip_prefix("Some(")
                    .and_then(|text| text.strip_suffix(')'))
                    .filter(|text| !text.is_empty())
                    .ok_or(Error::Value(key))?,
            ),
        };
        let (terminal, counts) = (Terminal::parse(terminal, key)?, flag(counts, key)?);
        if counts != terminal.passes() {
            return Err(Error::Inconsistent("counts disagrees with the terminal"));
        }
        let stop = stopped(stop, &[]).map_err(|_| Error::Value(key))?;
        if counts && stop != "goal" {
            return Err(Error::Inconsistent(
                "a counting end stops short of its goal",
            ));
        }
        // A failed check ends the run short of a pass.
        if counts && failure.is_some() {
            return Err(Error::Inconsistent("a counting end names a failure"));
        }
        // Twelve digits keep the line's length the same on every run.
        let twelve = apply_ms.len() == 12 && apply_ms.bytes().all(|byte| byte.is_ascii_digit());
        let (virtual_us, skipped_us, rested_us) = (
            count(virtual_us, key)?,
            count(skipped_us, key)?,
            count(rested_us, key)?,
        );
        if rested_us > skipped_us || skipped_us > virtual_us {
            return Err(Error::Inconsistent(
                "the rested time exceeds the skipped time or that exceeds the clock",
            ));
        }
        Ok(Self {
            stop,
            terminal,
            counts,
            turns: count(turns, key)?,
            virtual_us,
            skipped_us,
            rested_us,
            apply_ms: twelve
                .then(|| apply_ms.parse().ok())
                .flatten()
                .ok_or(Error::Value(key))?,
            failure: failure.map(ToOwned::to_owned),
            // Closing high-water marks use u64; window payload words saturate at u32.
            carried: count(carried, key)?,
            registry: count(registry, key)?,
            outstanding: count(outstanding, key)?,
            kept: count(kept, key)?,
            window_bytes: count(window_bytes, key)?,
        })
    }
}

impl SessionReplay {
    /// The replay's verdict `text`.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for output cut short; [`Error::Unpaired`] for a
    /// line with no `": "`; [`Error::Missing`], [`Error::Repeated`] and
    /// [`Error::Unknown`] unless the output is one `replay` line; [`Error::Value`] for a verdict outside every form;
    /// and [`Error::Inconsistent`] for a window-count divergence whose
    /// counts agree or whose window is not the smaller count.
    pub fn parse(text: &str) -> Result<Self, Error> {
        let mut lines = Pairs::lines(text)?;
        let verdict = lines.one("replay")?;
        lines.finish()?;
        let n = |value| count(value, "replay");
        if let Ok([windows, chain]) = fill(verdict, "reproduced, {} windows, chain {}", "replay") {
            return Ok(Self::Reproduced {
                windows: n(windows)?,
                chain: digest(chain, "replay")?,
            });
        }
        let diverged = if verdict == "diverged after the last window: the end differs" {
            Divergence::End
        } else if let Ok([at, committed, replayed]) = fill(
            verdict,
            "diverged at window {}: {} windows were committed, {} replayed",
            "replay",
        ) {
            let (at, committed, replayed) = (n(at)?, n(committed)?, n(replayed)?);
            if committed == replayed || at != committed.min(replayed) {
                return Err(Error::Inconsistent(
                    "a window-count divergence names counts that differ, at the smaller",
                ));
            }
            Divergence::Windows {
                at,
                committed,
                replayed,
            }
        } else if let Ok([window, record, virtual_us, candidate]) = fill(
            verdict,
            "diverged at window {} record {}: a turn at virtual_us={} candidate={}",
            "replay",
        ) {
            let candidate = Candidate(hex(candidate, CANDIDATE, "replay")?);
            Divergence::Turn {
                window: n(window)?,
                record: n(record)?,
                virtual_us: n(virtual_us)?,
                candidate,
            }
        } else {
            let [window, record, tag] = fill(
                verdict,
                "diverged at window {} record {} of tag {}",
                "replay",
            )?;
            Divergence::Record {
                window: n(window)?,
                record: n(record)?,
                tag: u8::try_from(n(tag)?).map_err(|_| Error::Value("replay"))?,
            }
        };
        Ok(Self::Diverged(diverged))
    }
}
