//! The terminal monitor's run loop. The signal listener is registered
//! before the terminal session starts, so the first SIGTERM, SIGHUP or
//! SIGINT ends the loop through the session's restore; a second signal
//! exits at once, which skips the restore. On every return the loop also
//! kills the process group of the snapshot command in flight.
//!
//! One input thread, the snapshot poller and the signal listener feed one
//! bounded channel. The loop blocks on it, handles at most
//! [`CHANNEL_CAPACITY`] queued messages, then draws once if anything
//! changed: at once after input, and at most one frame per [`MIN_FRAME`]
//! for snapshots. Its one timer is the age tick, a draw when the shown
//! snapshot age next changes.

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::thread;
use std::time::{Duration, Instant};

use ratatui::crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::cli::Options;
use crate::history::History;
use crate::poll::{self, Fetch};
use crate::source::InFlight;
use crate::state::derived::Derived;
use crate::state::{App, Effect, Level};
use crate::tui::keymap::{Action, Context, Dispatch, Keymap, key_label};
use crate::tui::term::Session;
use crate::tui::theme::{ColorDepth, Glyphs, Theme};
use crate::view;

pub const MIN_FRAME: Duration = Duration::from_millis(33);
pub const CHANNEL_CAPACITY: usize = 256;

/// A message to the run loop.
pub enum Msg {
    Input(Event),
    InputError(io::Error),
    /// A poller result, derived on the poller thread.
    Fetched(Fetch),
    /// The first SIGTERM, SIGHUP or SIGINT, by signal number.
    Terminate(i32),
}

/// Turns the first SIGTERM, SIGHUP or SIGINT into `Msg::Terminate`, so the
/// loop returns and `Session`'s `Drop` restores the terminal. A second
/// signal kills `running`'s command and exits at once with `128 + signal`.
/// When the queue is full, a helper thread completes the blocking send, so
/// the listener stays responsive to the second signal while the first still
/// reaches the loop.
fn spawn_signal_listener(
    tx: SyncSender<Msg>,
    running: InFlight,
) -> io::Result<signal_hook::iterator::Handle> {
    use signal_hook::consts::{SIGHUP, SIGINT, SIGTERM};
    let mut signals = signal_hook::iterator::Signals::new([SIGTERM, SIGHUP, SIGINT])?;
    let handle = signals.handle();
    thread::Builder::new()
        .name("signals".into())
        .spawn(move || {
            let mut seen = false;
            for sig in signals.forever() {
                if let Some(code) = on_signal(&tx, &mut seen, sig) {
                    running.kill();
                    std::process::exit(code);
                }
            }
        })?;
    Ok(handle)
}

/// Closes the listener when dropped, on every return of [`run`], so a later
/// run never shares the process with a stale listener.
struct SignalListener(signal_hook::iterator::Handle);

impl Drop for SignalListener {
    fn drop(&mut self) {
        self.0.close();
    }
}

/// Queues the first signal for the loop and returns the exit code for a
/// second one, or for a first one the loop can no longer receive.
fn on_signal(tx: &SyncSender<Msg>, seen: &mut bool, sig: i32) -> Option<i32> {
    if *seen {
        return Some(128 + sig);
    }
    *seen = true;
    match tx.try_send(Msg::Terminate(sig)) {
        Ok(()) => None,
        Err(TrySendError::Full(msg)) => {
            let tx = tx.clone();
            let spawned = thread::Builder::new()
                .name("signal-delivery".into())
                .spawn(move || {
                    let _ = tx.send(msg);
                });
            spawned.err().map(|_| 128 + sig)
        }
        Err(TrySendError::Disconnected(_)) => Some(128 + sig),
    }
}

fn spawn_input_reader(tx: SyncSender<Msg>) -> io::Result<()> {
    thread::Builder::new().name("input".into()).spawn(move || {
        loop {
            let msg = match event::read() {
                Ok(event) => Msg::Input(event),
                Err(error) => Msg::InputError(error),
            };
            let stop = matches!(msg, Msg::InputError(_));
            if tx.send(msg).is_err() || stop {
                return;
            }
        }
    })?;
    Ok(())
}

/// Runs the terminal monitor until `q`, ctrl-c or a signal. Returns the
/// signal that ended it, if one did.
///
/// # Errors
///
/// A terminal error, or a thread failing to start.
pub fn run(options: Options, history: History) -> io::Result<Option<i32>> {
    let (tx, rx) = mpsc::sync_channel(CHANNEL_CAPACITY);
    let running = InFlight::default();
    // Declared before `session`, so it is dropped after the terminal is
    // restored.
    let _signals = SignalListener(spawn_signal_listener(tx.clone(), running.clone())?);
    let mut session = Session::start()?;
    let stop = running.clone();
    session.on_panic(move || stop.kill());
    let result = start(&mut session, tx, &rx, options, history, &running);
    running.kill();
    drop(session);
    result
}

fn start(
    session: &mut Session,
    tx: SyncSender<Msg>,
    rx: &Receiver<Msg>,
    options: Options,
    history: History,
    running: &InFlight,
) -> io::Result<Option<i32>> {
    let (refresh, requested) = mpsc::sync_channel::<Instant>(1);
    let source = options.source.clone();
    let (interval, limits) = (options.interval, options.limits);
    let fetching = running.clone();
    let results = tx.clone();
    thread::Builder::new()
        .name("snapshot poller".into())
        .spawn(move || {
            poll::poll(
                || source.fetch_tracked(limits, &fetching),
                history,
                &results,
                Msg::Fetched,
                &requested,
                interval,
            )
        })?;
    spawn_input_reader(tx)?;
    let glyphs = if options.ascii {
        Glyphs::Ascii
    } else {
        Glyphs::Unicode
    };
    let theme = Theme::resolve(ColorDepth::detect(options.color), glyphs);
    let mut app = App::new(options.source.describe(), interval);
    let ui = Ui {
        theme,
        keymap: Keymap::default_map(),
        panic_probe: std::env::var_os(PANIC_PROBE).is_some_and(|value| value == "1"),
    };
    event_loop(session, &mut app, &ui, rx, &refresh)
}

pub const PANIC_PROBE: &str = "CAMPAIGN_MONITOR_PANIC";

/// What the loop draws with and dispatches keys through, and whether
/// [`PANIC_PROBE`] was set at startup.
struct Ui {
    theme: Theme,
    keymap: Keymap,
    panic_probe: bool,
}

/// What one message did to the loop.
enum Handled {
    /// Whether the state changed, and whether input changed it.
    Changed { changed: bool, input: bool },
    /// The loop ends, with the signal that ended it, if one did.
    Quit(Option<i32>),
}

fn event_loop(
    session: &mut Session,
    app: &mut App,
    ui: &Ui,
    rx: &Receiver<Msg>,
    refresh: &SyncSender<Instant>,
) -> io::Result<Option<i32>> {
    let mut drawn = draw(session, app, ui)?;
    let mut dirty = false;
    let mut pending: Option<Instant> = None;
    loop {
        let wake = earliest(drawn.tick, pending);
        let first = match wake {
            None => match rx.recv() {
                Ok(msg) => msg,
                Err(_) => return Ok(None),
            },
            Some(at) => match rx.recv_timeout(at.saturating_duration_since(Instant::now())) {
                Ok(msg) => msg,
                Err(RecvTimeoutError::Timeout) => {
                    drawn = draw(session, app, ui)?;
                    (dirty, pending) = (false, None);
                    continue;
                }
                Err(RecvTimeoutError::Disconnected) => return Ok(None),
            },
        };
        let mut urgent = false;
        for msg in batch(first, rx) {
            let key = matches!(msg, Msg::Input(Event::Key(_)));
            assert!(!(ui.panic_probe && key), "{PANIC_PROBE} is set");
            match handle(session, app, &ui.keymap, msg, refresh)? {
                Handled::Quit(signal) => return Ok(signal),
                Handled::Changed { changed, input } => {
                    dirty |= changed;
                    urgent |= changed && input;
                }
            }
        }
        match schedule(dirty, urgent, wake, drawn.at, Instant::now()) {
            Frame::Now => {
                drawn = draw(session, app, ui)?;
                (dirty, pending) = (false, None);
            }
            Frame::At(at) => pending = Some(at),
            Frame::Idle => {}
        }
    }
}

/// When a frame was drawn, and when the age it shows next changes.
struct Drawn {
    at: Instant,
    tick: Option<Instant>,
}

fn draw(session: &mut Session, app: &App, ui: &Ui) -> io::Result<Drawn> {
    session.draw(|frame| view::draw(frame, app, &ui.theme, &ui.keymap))?;
    let at = Instant::now();
    Ok(Drawn {
        at,
        tick: app.next_change(at),
    })
}

fn earliest(a: Option<Instant>, b: Option<Instant>) -> Option<Instant> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (a, b) => a.or(b),
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Frame {
    Now,
    At(Instant),
    Idle,
}

/// Decides what happens after a batch: draw now, draw at a deadline, or
/// wait for the next message. `wake` is the earliest scheduled draw, the
/// age tick or a deferred frame; one that passed while messages kept
/// arriving is honored here, since `recv_timeout` reports it only when the
/// queue is empty.
fn schedule(
    dirty: bool,
    urgent: bool,
    wake: Option<Instant>,
    last_frame: Instant,
    now: Instant,
) -> Frame {
    let due = wake.is_some_and(|at| now >= at);
    if !dirty {
        return match wake {
            Some(_) if due => Frame::Now,
            Some(at) => Frame::At(at),
            None => Frame::Idle,
        };
    }
    let next_allowed = last_frame + MIN_FRAME;
    if urgent || due || now >= next_allowed {
        Frame::Now
    } else {
        Frame::At(next_allowed)
    }
}

/// One frame's messages: `first` plus up to `CHANNEL_CAPACITY - 1` already
/// queued. The cap keeps a producer that refills the channel during the
/// drain from postponing the draw.
fn batch(first: Msg, rx: &Receiver<Msg>) -> impl Iterator<Item = Msg> + '_ {
    std::iter::once(first).chain(rx.try_iter().take(CHANNEL_CAPACITY - 1))
}

/// Frees a replaced snapshot on a thread of its own: at 10^5 jobs its
/// strings take tens of milliseconds to free, which input should not wait
/// for. A thread that fails to start drops its closure, and with it the
/// snapshot, here.
fn free(replaced: Arc<Derived>) {
    let _ = thread::Builder::new()
        .name("free snapshot".into())
        .spawn(move || drop(replaced));
}

fn handle(
    session: &mut Session,
    app: &mut App,
    keymap: &Keymap,
    msg: Msg,
    refresh: &SyncSender<Instant>,
) -> io::Result<Handled> {
    let changed = |input| Handled::Changed {
        changed: true,
        input,
    };
    Ok(match msg {
        Msg::InputError(error) => return Err(error),
        Msg::Terminate(signal) => Handled::Quit(Some(signal)),
        Msg::Fetched(fetch) => {
            if let Some(replaced) = app.apply(fetch) {
                free(replaced);
            }
            changed(false)
        }
        Msg::Input(Event::Resize(..)) => changed(true),
        Msg::Input(Event::Paste(text)) => {
            app.paste(&sanitize_paste(&text));
            changed(true)
        }
        Msg::Input(Event::Key(key)) if key.kind == KeyEventKind::Press => {
            let effect = press(app, keymap, key);
            if let Some(replaced) = app.take_resumed() {
                free(replaced);
            }
            match effect {
                Effect::Quit => Handled::Quit(None),
                Effect::Refresh => {
                    let _ = refresh.try_send(Instant::now());
                    changed(true)
                }
                Effect::Yank(text) => {
                    if let Err(error) = session.copy(&text) {
                        app.notify(Level::Error, format!("copy failed: {error}"));
                    }
                    changed(true)
                }
                Effect::None => changed(true),
            }
        }
        Msg::Input(_) => Handled::Changed {
            changed: false,
            input: true,
        },
    })
}

/// Runs one key press through `keymap` into `app`, clearing the flash of
/// the previous key. A key bound only on
/// another tab flashes where it acts, a key a pending `g` or `z` does not
/// take cancels the prefix and flashes, and an unbound printable key types
/// into an open search.
pub fn press(app: &mut App, keymap: &Keymap, key: KeyEvent) -> Effect {
    app.flash = None;
    let context = app.context();
    match keymap.dispatch(context, key) {
        Dispatch::Act(action) => app.update(action),
        Dispatch::Elsewhere(scope, label) => {
            app.notify(
                Level::Warn,
                format!("{} ({label}) acts on {}", key_label(key, ""), scope.name()),
            );
            Effect::None
        }
        Dispatch::Unbound => {
            match (context, key.code) {
                (Context::Search, KeyCode::Char(c))
                    if !key
                        .modifiers
                        .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT) =>
                {
                    app.type_char(c);
                }
                (Context::PendingG | Context::PendingZ, _) => {
                    app.update(Action::CancelPrefix);
                    app.notify(
                        Level::Warn,
                        format!(
                            "{} is not a key; ? lists the keys",
                            key_label(key, context.prefix())
                        ),
                    );
                }
                _ => {}
            }
            Effect::None
        }
    }
}

/// Pasted text as one line of printable characters. Whole escape sequences
/// are removed: CSI (`ESC [ ... final`), the string controls OSC, DCS, SOS,
/// PM and APC (`ESC ]`, `ESC P`, `ESC X`, `ESC ^`, `ESC _` through BEL or
/// `ESC \\`), `ESC intermediate final` (such as `ESC ( B`), and two-byte
/// `ESC x` forms. Newlines and tabs become spaces.
fn sanitize_paste(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => match chars.next() {
                Some('[') => {
                    // Parameter and intermediate bytes run 0x20..=0x3F; the
                    // final byte is 0x40..=0x7E.
                    for c in chars.by_ref() {
                        if ('\x40'..='\x7e').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']' | 'P' | 'X' | '^' | '_') => {
                    // String controls end with ST (`ESC \\`); OSC also
                    // accepts BEL.
                    while let Some(c) = chars.next() {
                        if c == '\x07' || (c == '\x1b' && chars.next_if_eq(&'\\').is_some()) {
                            break;
                        }
                    }
                }
                Some(c) if ('\x20'..='\x2f').contains(&c) => {
                    // Any number of intermediate bytes, then one final byte.
                    while chars.next_if(|c| ('\x20'..='\x2f').contains(c)).is_some() {}
                    chars.next();
                }
                _ => {}
            },
            '\n' | '\r' | '\t' => out.push(' '),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
#[path = "event_loop_tests.rs"]
mod tests;
