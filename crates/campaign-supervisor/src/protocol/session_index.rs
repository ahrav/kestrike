//! Stored session index and end lines use canonical decimal counts and SHA-256 digests.
//! The final windows, chain and tail fields delimit the stored end footer.

use super::pairs::{count, digest, fill};
use super::{End, Error};
use crate::record::Digest;

/// The index and digests from one parsed window line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowLine {
    pub index: u32,
    pub digest: Digest,
    pub chain: Digest,
    /// Whether the window checker passed.
    pub passed: bool,
}

impl WindowLine {
    /// Parses one index line, with its trailing newline removed.
    ///
    /// # Errors
    ///
    /// [`Error::Value`] for malformed fields, noncanonical counts, payload counters
    /// beyond u32, or a verdict other than `pass` or `failed`.
    pub fn parse(line: &str) -> Result<Self, Error> {
        let [
            index,
            turns,
            digest_text,
            chain,
            verdict,
            carried,
            registry,
            outstanding,
            kept,
            published,
            hits,
            faults,
            reused,
            healed,
        ] = fill(
            line,
            "window {} turns={} digest={} chain={} verdict={} carried={} registry={} outstanding={} kept={} published={} hits={} faults={} reused={} healed={}",
            "window",
        )?;
        // Turns use u64; the nine window payload counters use u32 words.
        count(turns, "window")?;
        for value in [
            carried,
            registry,
            outstanding,
            kept,
            published,
            hits,
            faults,
            reused,
            healed,
        ] {
            u32::try_from(count(value, "window")?).map_err(|_| Error::Value("window"))?;
        }
        if !matches!(verdict, "pass" | "failed") {
            return Err(Error::Value("window"));
        }
        Ok(Self {
            index: u32::try_from(count(index, "window")?).map_err(|_| Error::Value("window"))?,
            digest: digest(digest_text, "window")?,
            chain: digest(chain, "window")?,
            passed: verdict == "pass",
        })
    }
}

/// The end facts, window count, final chain and tail digest from a stored end.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionEnd {
    pub end: SessionEnding,
    pub windows: u64,
    pub chain: Digest,
    pub tail: Digest,
}

impl SessionEnd {
    /// Parses one newline-terminated stored end line. The last `windows=` marker
    /// separates closing facts or a panic identity from the digest footer.
    ///
    /// # Errors
    ///
    /// [`Error::Torn`] for a missing final newline. Other malformed framing or
    /// footer fields return [`Error::Value`]; closing contradictions return
    /// [`Error::Inconsistent`].
    pub fn parse(text: &str) -> Result<Self, Error> {
        let line = text.strip_suffix('\n').ok_or(Error::Torn)?;
        let line = Some(line)
            .filter(|line| !line.contains(['\n', '\r']))
            .and_then(|line| line.strip_prefix("end: "))
            .ok_or(Error::Value("end"))?;
        let (end, suffix) = line.rsplit_once(" windows=").ok_or(Error::Value("end"))?;
        let [windows, chain, tail] = fill(suffix, "{} chain={} tail={}", "end")?;
        Ok(Self {
            end: if let Some(panic) = end.strip_prefix("panicked ") {
                if panic.is_empty() {
                    return Err(Error::Value("end"));
                }
                SessionEnding::Panicked(panic.to_owned())
            } else {
                SessionEnding::Ended(End::parse(end)?)
            },
            windows: count(windows, "end")?,
            chain: digest(chain, "end")?,
            tail: digest(tail, "end")?,
        })
    }

    /// Compares every field except elapsed apply time.
    pub fn reproduces(&self, other: &Self) -> bool {
        let (mut ours, mut theirs) = (self.clone(), other.clone());
        if let SessionEnding::Ended(end) = &mut ours.end {
            end.apply_ms = 0;
        }
        if let SessionEnding::Ended(end) = &mut theirs.end {
            end.apply_ms = 0;
        }
        ours == theirs
    }
}

/// A session's closing facts or the worker's panic identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionEnding {
    Ended(End),
    Panicked(String),
}
