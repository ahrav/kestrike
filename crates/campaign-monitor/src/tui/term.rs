//! Terminal lifecycle: the session enters raw mode, the alternate screen and
//! bracketed paste, and undoes exactly the modes it recorded, in reverse
//! order, on every exit path: `Drop` on a normal or `?` return, and the
//! panic hook on a panic on any thread, which restores and then exits so no
//! thread keeps drawing on the restored terminal.

use std::io::{self, BufWriter, Stdout, Write};
use std::sync::Mutex;
use std::sync::atomic::{AtomicU8, Ordering};

use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::{
    cursor,
    event::{DisableBracketedPaste, EnableBracketedPaste},
    execute, queue,
    terminal::{
        self, BeginSynchronizedUpdate, EndSynchronizedUpdate, EnterAlternateScreen,
        LeaveAlternateScreen,
    },
};

/// `BufWriter` batches a frame into 8 KiB writes instead of `Stdout`'s
/// 1 KiB `LineWriter` chunks.
pub type Backend = CrosstermBackend<BufWriter<Stdout>>;

const PASTE: u8 = 1;
const SCREEN: u8 = 2;
/// `start` sets this bit before any mode turns on, so one caller at a time
/// holds the session.
const LIVE: u8 = 4;

/// Modes enabled by the live session, with `LIVE` while a session holds
/// the process. The panic hook reads `ENABLED`.
static ENABLED: AtomicU8 = AtomicU8::new(0);

static ON_PANIC: Mutex<Option<Box<dyn Fn() + Send>>> = Mutex::new(None);

/// The live terminal session; at most one exists per process.
pub struct Session {
    terminal: Terminal<Backend>,
}

impl Session {
    /// Enters raw mode, the alternate screen with the cursor hidden, and
    /// bracketed paste, after installing a panic hook that restores the
    /// terminal before the previous hook prints the panic message.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` while another session is live, or the error of a
    /// mode that failed to enable, after every recorded mode is restored.
    pub fn start() -> io::Result<Self> {
        if ENABLED
            .compare_exchange(0, LIVE, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "a terminal session is already active in this process",
            ));
        }
        install_panic_hook();
        Self::enter().inspect_err(|_| {
            restore_modes();
        })
    }

    fn enter() -> io::Result<Self> {
        // Each mode is recorded before it turns on: an enable that fails
        // after the terminal acted on it still gets its disable, and a
        // disable for a mode that never turned on is harmless. SCREEN stands
        // for raw mode as well.
        let mark = |bit| ENABLED.fetch_or(bit, Ordering::SeqCst);
        mark(SCREEN);
        terminal::enable_raw_mode()?;
        let mut out = io::stdout();
        execute!(out, EnterAlternateScreen, cursor::Hide)?;
        mark(PASTE);
        // A terminal that rejects bracketed paste still runs the monitor.
        let _ = execute!(out, EnableBracketedPaste);
        let terminal = Terminal::new(CrosstermBackend::new(BufWriter::new(io::stdout())))?;
        Ok(Self { terminal })
    }

    /// Draws one frame inside a synchronized update (DEC mode 2026), so a
    /// terminal that supports it paints the frame at once; others ignore
    /// the private mode.
    ///
    /// # Errors
    ///
    /// The terminal's write or size error.
    pub fn draw(&mut self, render: impl FnOnce(&mut ratatui::Frame)) -> io::Result<()> {
        queue!(self.terminal.backend_mut(), BeginSynchronizedUpdate)?;
        let drawn = self.terminal.draw(render).map(|_| ());
        // The update ends even when the draw failed, or the terminal stays
        // frozen.
        queue!(self.terminal.backend_mut(), EndSynchronizedUpdate)?;
        self.terminal.backend_mut().flush()?;
        drawn
    }
}

impl Session {
    pub fn on_panic(&mut self, cleanup: impl Fn() + Send + 'static) {
        *panic_cleanup() = Some(Box::new(cleanup));
    }

    /// Asks the terminal to put `text` on the clipboard with OSC 52. A
    /// terminal that ignores OSC 52 leaves the clipboard as it was; only a
    /// write error is reported.
    ///
    /// # Errors
    ///
    /// The terminal's write error.
    pub fn copy(&mut self, text: &str) -> io::Result<()> {
        let out = self.terminal.backend_mut();
        write!(out, "\x1b]52;c;{}\x07", base64(text.as_bytes()))?;
        out.flush()
    }
}

/// Standard base64 with padding, as OSC 52 carries its payload.
fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let word = chunk.iter().enumerate().fold(0u32, |word, (index, byte)| {
            word | u32::from(*byte) << (16 - 8 * index)
        });
        for index in 0..4 {
            if index <= chunk.len() {
                let sextet = (word >> (18 - 6 * index)) & 0x3f;
                out.push(char::from(ALPHABET[sextet as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.terminal.backend_mut().flush();
        *panic_cleanup() = None;
        restore_modes();
    }
}

fn panic_cleanup() -> std::sync::MutexGuard<'static, Option<Box<dyn Fn() + Send>>> {
    ON_PANIC
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Undoes the enabled modes in reverse order of `enter`; every step runs
/// even when an earlier one fails. The swap makes a second call, from the
/// panic hook and then `Drop`, a no-op. Returns whether the alternate
/// screen was recorded; a reservation with only `LIVE` set returns `false`.
fn restore_modes() -> bool {
    let enabled = ENABLED.swap(0, Ordering::SeqCst);
    if enabled & SCREEN == 0 {
        return false;
    }
    let mut out = io::stdout();
    let _ = execute!(out, EndSynchronizedUpdate);
    if enabled & PASTE != 0 {
        let _ = execute!(out, DisableBracketedPaste);
    }
    let _ = execute!(out, LeaveAlternateScreen, cursor::Show);
    let _ = terminal::disable_raw_mode();
    true
}

fn install_panic_hook() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let previous = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            let restored = restore_modes();
            previous(info);
            // Exiting stops the loop from drawing on the restored terminal
            // after a panic on another thread, and discards the frame still
            // buffered in the `BufWriter`. `exit` bypasses destructors.
            if restored {
                if let Some(cleanup) = panic_cleanup().as_ref() {
                    cleanup();
                }
                std::process::exit(101);
            }
        }));
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_the_standard_alphabet_and_padding() {
        assert_eq!(base64(b""), "");
        assert_eq!(base64(b"f"), "Zg==");
        assert_eq!(base64(b"fo"), "Zm8=");
        assert_eq!(base64(b"foo"), "Zm9v");
        assert_eq!(base64(b"foobar"), "Zm9vYmFy");
        assert_eq!(base64(&[0xff, 0xfe]), "//4=");
    }

    #[test]
    fn start_refuses_an_overlapping_session() {
        ENABLED.store(SCREEN, Ordering::SeqCst);
        let result = Session::start();
        let still_live = ENABLED.load(Ordering::SeqCst);
        ENABLED.store(0, Ordering::SeqCst);
        assert_eq!(still_live, SCREEN, "a refused start keeps the live record");
        match result {
            Err(error) => assert_eq!(error.kind(), io::ErrorKind::AlreadyExists, "{error}"),
            Ok(_) => panic!("a second session started"),
        }
    }
}
