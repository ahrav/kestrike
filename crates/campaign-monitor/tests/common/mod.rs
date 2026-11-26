//! A dedicated reader thread drains PTY output to prevent deadlock when the
//! PTY buffer fills, and `Replies` answers cursor-position queries.

#![allow(dead_code)]

use std::io::{Read, Write};
use std::num::NonZeroU16;
use std::path::PathBuf;
use std::sync::mpsc::{Receiver, channel};
use std::thread;
use std::time::{Duration, Instant};

use portable_pty::{CommandBuilder, PtySize, native_pty_system};

pub const ROWS: u16 = 24;
pub const COLS: u16 = 80;

#[derive(Default)]
pub struct Replies {
    pending: Vec<u8>,
}

impl vt100::Callbacks for Replies {
    fn unhandled_csi(
        &mut self,
        screen: &mut vt100::Screen,
        _i1: Option<u8>,
        _i2: Option<u8>,
        params: &[&[u16]],
        c: char,
    ) {
        if c == 'n' && params.first() == Some(&&[6][..]) {
            let (row, col) = screen.cursor_position();
            self.pending
                .extend(format!("\x1b[{};{}R", row + 1, col + 1).into_bytes());
        }
    }
}

pub struct Harness {
    pub parser: vt100::Parser<Replies>,
    pub raw: Vec<u8>,
    pub output: Receiver<Vec<u8>>,
    pub writer: Box<dyn Write + Send>,
    pub child: Box<dyn portable_pty::Child + Send + Sync>,
}

pub fn snapshot(name: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!(
        "campaign-monitor-pty-{name}-{}.json",
        std::process::id()
    ));
    let id = format!("{:064x}", 1);
    let text = format!(
        r#"{{"format": 1, "observed_ms": 10000000, "state": "/state", "config": null,
            "space": {{"free_bytes": 1099511627776, "free_inodes": 1000000}}, "probes": 0, "held_probes": [],
            "jobs": [{{"id": "{id}", "profile": "get", "campaign": "c", "run": 0,
                      "variant": "v", "state": "settled", "attempts_allowed": 1,
                      "result": {{"attempt": 1, "class": "violation"}},
                      "attempts": [{{"number": 1, "intent_ms": 1, "finished_ms": 9,
                                    "finished": {{"class": "violation", "binding": "matching"}}}}]}}],
            "findings": [{{"id": "{id}-0001"}}],
            "failure_groups": [{{"kind": "violation", "identity": "02aa",
                                "findings": ["{id}-0001"], "profiles": ["get"], "runs": [0],
                                "unresolved": 1}}]}}"#
    );
    std::fs::write(&path, text).unwrap();
    path
}

impl Harness {
    /// The child's environment holds only `TERM` and `env`, so the parent's
    /// `NO_COLOR`, `COLORTERM` and `CI` cannot change what it draws.
    pub fn spawn(bin: &str, args: &[&str], env: &[(&str, &str)]) -> Self {
        let pair = native_pty_system()
            .openpty(PtySize {
                rows: ROWS,
                cols: COLS,
                pixel_width: 0,
                pixel_height: 0,
            })
            .unwrap();
        let mut cmd = CommandBuilder::new(bin);
        cmd.args(args);
        cmd.env_clear();
        cmd.env("TERM", "xterm-256color");
        for (key, value) in env {
            cmd.env(key, value);
        }
        let child = pair.slave.spawn_command(cmd).unwrap();
        drop(pair.slave);
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (tx, output) = channel();
        thread::spawn(move || {
            let mut buf = [0u8; 8192];
            while let Ok(n) = reader.read(&mut buf) {
                if n == 0 || tx.send(buf[..n].to_vec()).is_err() {
                    break;
                }
            }
        });
        let writer = pair.master.take_writer().unwrap();
        let rows = NonZeroU16::new(ROWS).unwrap();
        let cols = NonZeroU16::new(COLS).unwrap();
        Self {
            parser: vt100::Parser::new_with_callbacks(rows, cols, 0, Replies::default()),
            raw: Vec::new(),
            output,
            writer,
            child,
        }
    }

    pub fn pump(&mut self, wait: Duration) {
        if let Ok(bytes) = self.output.recv_timeout(wait) {
            self.parser.process(&bytes);
            self.raw.extend_from_slice(&bytes);
            let replies = std::mem::take(&mut self.parser.callbacks_mut().pending);
            if !replies.is_empty() {
                self.writer.write_all(&replies).unwrap();
                self.writer.flush().unwrap();
            }
        }
    }

    pub fn wait_until(&mut self, what: &str, pred: impl Fn(&str) -> bool) {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let screen = self.parser.screen().contents();
            if pred(&screen) {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "timed out waiting for {what}:\n{screen}"
            );
            self.pump(Duration::from_millis(50));
        }
    }

    pub fn wait_exit(&mut self) -> portable_pty::ExitStatus {
        let deadline = Instant::now() + Duration::from_secs(10);
        let status = loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                break status;
            }
            assert!(Instant::now() < deadline, "the monitor did not exit");
            self.pump(Duration::from_millis(20));
        };
        while let Ok(bytes) = self.output.recv_timeout(Duration::from_millis(100)) {
            self.parser.process(&bytes);
            self.raw.extend_from_slice(&bytes);
        }
        status
    }

    pub fn send(&mut self, bytes: &[u8]) {
        self.writer.write_all(bytes).unwrap();
        self.writer.flush().unwrap();
    }

    pub fn assert_restored(&self) {
        let screen = self.parser.screen();
        assert!(!screen.alternate_screen(), "left the alternate screen");
        assert!(!screen.hide_cursor(), "restored the cursor");
        assert!(!screen.bracketed_paste(), "turned bracketed paste off");
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
