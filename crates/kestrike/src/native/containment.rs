//! The first `contain` call sends the request; every call returns only after
//! the controller acknowledges it. A lost channel parks each calling thread
//! for the life of the process.
//!
//! The channel carries frames of at most [`FRAME`] bytes, each ended by one
//! `\n`; an acknowledgement matches when the bytes before it are exactly
//! `contained <id>`. An endpoint id is a nonempty single line short enough
//! for both frames, so a request is always one line and an acknowledgement
//! can always match.
//! A frame that reaches the limit without a line break, or an unterminated
//! frame at the end of the stream, ends the exchange: the supervisor reads
//! nothing more and keeps the caller parked instead of buffering an
//! unbounded line. The process stays alive with its memory held, which is
//! the posture a lost channel also takes.

use std::io::{BufRead, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Mutex, PoisonError};
use std::thread;

use super::watchdog::Supervisor;

/// The longest frame, in bytes including its line break, the supervisor
/// writes or reads.
pub const FRAME: usize = 4096;

const REQUEST: &str = "contain ";
const ACKNOWLEDGEMENT: &str = "contained ";

/// Why an endpoint id was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointError {
    /// The id is empty, so a request names nothing.
    Empty,
    /// The id holds `\n` or `\r`, so a request would span frames.
    LineBreak,
    /// `contained <id>` and its line break overrun [`FRAME`].
    Long,
}

/// A [`Supervisor`] that asks an external controller to fence and contain
/// the endpoint `id` names: it writes `contain <id>` and reads frames until
/// `contained <id>`, the end of the stream, or an oversized frame. The
/// acknowledgement is the containment it verifies.
pub struct ControllerSupervisor<W, R> {
    id: String,
    channel: Mutex<(W, R)>,
    calls: AtomicU32,
    requested: AtomicBool,
    acknowledged: AtomicBool,
}

impl<W: Write + Send, R: BufRead + Send> ControllerSupervisor<W, R> {
    /// A supervisor over the endpoint `id`, requesting on `controller` and
    /// reading `acknowledgements`.
    ///
    /// # Errors
    ///
    /// [`EndpointError`] when `id` is empty, holds a line break, or makes
    /// `contained <id>` overrun [`FRAME`].
    pub fn new(
        id: impl Into<String>,
        controller: W,
        acknowledgements: R,
    ) -> Result<Self, EndpointError> {
        let id = id.into();
        if id.is_empty() {
            return Err(EndpointError::Empty);
        }
        if id.contains(['\n', '\r']) {
            return Err(EndpointError::LineBreak);
        }
        if ACKNOWLEDGEMENT.len() + id.len() + 1 > FRAME {
            return Err(EndpointError::Long);
        }
        Ok(Self {
            id,
            channel: Mutex::new((controller, acknowledgements)),
            calls: AtomicU32::new(0),
            requested: AtomicBool::new(false),
            acknowledged: AtomicBool::new(false),
        })
    }

    /// Calls of `contain` so far, held at `u32::MAX` once the count reaches
    /// it; only the first sends a request.
    pub fn calls(&self) -> u32 {
        self.calls.load(Ordering::Acquire)
    }

    /// Sets the count of calls, under the channel lock as `contain` updates
    /// it, so a test can reach the count's largest value. Call it after the
    /// first `contain` call, with a nonzero count, so that call stays the
    /// only one that makes the exchange.
    #[cfg(test)]
    pub(crate) fn set_calls(&self, calls: u32) {
        let _channel = self.channel.lock().unwrap_or_else(PoisonError::into_inner);
        self.calls.store(calls, Ordering::Release);
    }

    /// Whether the request was written and flushed.
    pub fn requested(&self) -> bool {
        self.requested.load(Ordering::Acquire)
    }

    /// Whether the controller acknowledged the request.
    pub fn acknowledged(&self) -> bool {
        self.acknowledged.load(Ordering::Acquire)
    }

    /// Writes and flushes the request, then reads frames until the
    /// acknowledgement, the end of the stream or an oversized frame; returns
    /// whether the acknowledgement arrived.
    fn exchange(&self, (controller, acknowledgements): &mut (W, R)) -> bool {
        if writeln!(controller, "{REQUEST}{}", self.id)
            .and_then(|()| controller.flush())
            .is_err()
        {
            return false;
        }
        self.requested.store(true, Ordering::Release);
        let expected = format!("{ACKNOWLEDGEMENT}{}\n", self.id).into_bytes();
        let mut frame = Vec::new();
        loop {
            frame.clear();
            match acknowledgements
                .by_ref()
                .take(FRAME as u64)
                .read_until(b'\n', &mut frame)
            {
                Ok(0) | Err(_) => return false,
                Ok(_) if frame.last() != Some(&b'\n') => return false,
                Ok(_) if frame == expected => return true,
                Ok(_) => {}
            }
        }
    }
}

impl<W: Write + Send, R: BufRead + Send> Supervisor for ControllerSupervisor<W, R> {
    fn contain(&self) {
        let mut channel = self.channel.lock().unwrap_or_else(PoisonError::into_inner);
        // The count stops at `u32::MAX`, so it is zero only before the first
        // call and only that call makes the exchange.
        let first = self
            .calls
            .try_update(Ordering::AcqRel, Ordering::Acquire, |calls| {
                calls.checked_add(1)
            })
            == Ok(0);
        if first && self.exchange(&mut channel) {
            self.acknowledged.store(true, Ordering::Release);
        }
        drop(channel);
        while !self.acknowledged() {
            thread::park();
        }
    }

    fn verified(&self) -> bool {
        self.acknowledged()
    }
}
