//! The shared reconciler replay driver loads a committed ITF trace of a Quint model and runs each production
//! operation of the trace on a thread of its own, over a [`Proxy`] store that parks every request until the replay
//! thread answers it.
//!
//! # Threads
//!
//! The replay thread owns the simulated store. [`Op::start`] runs an operation on its own thread over a [`Proxy`]
//! store that sends each request to the replay thread and blocks for the reply, and waits, up to [`WAIT`], for the
//! operation's first message. [`Op::answer`] sends the reply to the pending request and waits, up to [`WAIT`], for
//! the next message: a request, or the operation's result. The replay thread waits for each message and the
//! operation waits for each reply, so each production request falls on the step that answers it. [`Op::read_of`]
//! and [`Op::write_of`] match the pending request against the record a model step names, and [`Op::call`] matches a
//! pending provider create.
//!
//! # Traces
//!
//! [`states`] rejects a trace before replay if its recorded model digest differs from the SHA-256 of the model text
//! or its state count differs from its recorded step count plus one, and returns the states with every ITF big
//! integer replaced by a JSON number, beside the family's `#meta` object.

use std::rc::Rc;
use std::sync::mpsc::{Receiver, RecvTimeoutError, Sender, channel};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::failover::loss::{CreateError, Provider};
use crate::failover::records::{Layout, Namespace, VolumeId};
use crate::storage::store::sim::NAMESPACE;
use crate::storage::store::{Item, Key, Outcome, Store, Unavailable, Write};

/// How long the replay thread blocks for an operation's next message. An operation that sends none in this time
/// fails the replay.
pub(in crate::failover) const WAIT: Duration = Duration::from_secs(20);

/// What an operation's thread sends the thread that holds the store: a store request, a provider create with its
/// token and layout, or the operation's result string.
pub(in crate::failover) enum Message {
    Read(Key),
    Write(Key, Write),
    Call(String, Layout),
    Done(String),
}

pub(in crate::failover) enum Reply {
    Read(Result<Option<Item>, Unavailable>),
    Write(Outcome),
    Call(Result<VolumeId, CreateError>),
}

/// The store and the provider of one operation: each store request and each provider create crosses the channel and
/// blocks for its reply, and the clones of one `Proxy` share its channel. Once the thread that answers drops its
/// end, a read returns `Unavailable`, a write returns `Outcome::Unknown` and a create returns
/// `CreateError::Unknown`.
#[derive(Clone)]
pub(in crate::failover) struct Proxy {
    calls: Sender<Message>,
    replies: Rc<Receiver<Reply>>,
}

impl Proxy {
    pub(in crate::failover) fn new(calls: Sender<Message>, replies: Receiver<Reply>) -> Self {
        Self {
            calls,
            replies: Rc::new(replies),
        }
    }
}

impl Store for Proxy {
    fn read(&mut self, key: &Key) -> Result<Option<Item>, Unavailable> {
        let _ = self.calls.send(Message::Read(*key));
        match self.replies.recv() {
            Ok(Reply::Read(read)) => read,
            _ => Err(Unavailable),
        }
    }

    fn write(&mut self, key: &Key, write: &Write) -> Outcome {
        let _ = self.calls.send(Message::Write(*key, write.clone()));
        match self.replies.recv() {
            Ok(Reply::Write(outcome)) => outcome,
            _ => Outcome::Unknown,
        }
    }

    fn namespace(&self) -> Namespace {
        NAMESPACE
    }
}

impl Provider for Proxy {
    fn create(&mut self, token: &str, layout: Layout) -> Result<VolumeId, CreateError> {
        let _ = self.calls.send(Message::Call(token.to_owned(), layout));
        match self.replies.recv() {
            Ok(Reply::Call(created)) => created,
            _ => Err(CreateError::Unknown),
        }
    }
}

/// One production operation running on its own thread over a [`Proxy`], and the message it sent last.
///
/// Dropping an `Op` closes its reply channel, so a request the operation waits in returns `Unavailable`,
/// `Outcome::Unknown` or `CreateError::Unknown`. The drop then takes the operation's messages for up to the
/// operation's wait and joins its thread once the result arrives or the thread ends; an operation that sends
/// neither in that time, and one that missed a deadline of [`Op::answer`], is detached and is not joined.
pub(in crate::failover) struct Op {
    replies: Option<Sender<Reply>>,
    calls: Receiver<Message>,
    pending: Message,
    /// [`Op::answer`] waits this long for the operation's next message. [`Op::start`] sets it to [`WAIT`].
    wait: Duration,
    thread: Option<JoinHandle<()>>,
}

impl Op {
    /// Runs `operation` over a [`Proxy`] on a thread of its own and returns once the operation sent its first
    /// message.
    ///
    /// # Errors
    ///
    /// `the operation issued no request` when no message arrives within [`WAIT`]; the thread is then detached.
    pub(in crate::failover) fn start(
        operation: impl FnOnce(Proxy) -> String + Send + 'static,
    ) -> Result<Self, String> {
        let (calls, inbox) = channel();
        let (replies, answers) = channel();
        let done = calls.clone();
        let thread = std::thread::spawn(move || {
            let result = operation(Proxy::new(calls, answers));
            let _ = done.send(Message::Done(result));
        });
        let pending = inbox
            .recv_timeout(WAIT)
            .map_err(|_| String::from("the operation issued no request"))?;
        Ok(Self {
            replies: Some(replies),
            calls: inbox,
            pending,
            wait: WAIT,
            thread: Some(thread),
        })
    }

    /// The message the operation sent last: the request the next step answers, or its result.
    pub(in crate::failover) fn pending(&self) -> &Message {
        &self.pending
    }

    /// Requires the pending message to be a read of `key`.
    ///
    /// # Errors
    ///
    /// `the operation reads <key>`, `the operation writes <key>` or `the operation ended <result>` when the pending
    /// message is another request or the operation's result.
    pub(in crate::failover) fn read_of(&self, key: &Key) -> Result<(), String> {
        match &self.pending {
            Message::Read(asked) if asked == key => Ok(()),
            _ => Err(self.mismatch()),
        }
    }

    /// Requires the pending message to be a write of `key` and returns the write.
    ///
    /// # Errors
    ///
    /// The texts of [`Op::read_of`] when the pending message is another request or the operation's result.
    pub(in crate::failover) fn write_of(&self, key: &Key) -> Result<&Write, String> {
        match &self.pending {
            Message::Write(asked, write) if asked == key => Ok(write),
            _ => Err(self.mismatch()),
        }
    }

    /// Requires the pending message to be a provider create and returns its token.
    ///
    /// # Errors
    ///
    /// The texts of [`Op::read_of`] when the pending message is a store request or the operation's result.
    pub(in crate::failover) fn call(&self) -> Result<(&str, Layout), String> {
        match &self.pending {
            Message::Call(token, layout) => Ok((token, *layout)),
            _ => Err(self.mismatch()),
        }
    }

    fn mismatch(&self) -> String {
        match &self.pending {
            Message::Read(asked) => format!("the operation reads {asked:?}"),
            Message::Write(asked, _) => format!("the operation writes {asked:?}"),
            Message::Call(token, _) => format!("the operation calls the provider under {token}"),
            Message::Done(result) => format!("the operation ended {result}"),
        }
    }

    /// Sends `reply` to the pending request and waits for the operation's next message.
    ///
    /// # Errors
    ///
    /// `the operation is gone` when the operation's thread dropped its channel, and `the operation issued no request`
    /// when its thread ended without a message or no message arrives within [`WAIT`]. A missed deadline closes the
    /// reply channel and detaches the thread, which goes on running until it returns.
    pub(in crate::failover) fn answer(&mut self, reply: Reply) -> Result<(), String> {
        self.replies
            .as_ref()
            .ok_or("the operation is gone")?
            .send(reply)
            .map_err(|_| String::from("the operation is gone"))?;
        match self.calls.recv_timeout(self.wait) {
            Ok(message) => {
                self.pending = message;
                Ok(())
            }
            Err(RecvTimeoutError::Timeout) => {
                self.replies = None;
                self.thread = None;
                Err("the operation issued no request".into())
            }
            Err(RecvTimeoutError::Disconnected) => Err("the operation issued no request".into()),
        }
    }

    /// Joins an operation whose result arrived.
    ///
    /// # Errors
    ///
    /// `the operation continues` when the pending message is a request, and `the operation panicked` when the
    /// thread panicked after it sent the result.
    pub(in crate::failover) fn finish(mut self) -> Result<(), String> {
        if !matches!(self.pending, Message::Done(_)) {
            return Err("the operation continues".into());
        }
        self.thread
            .take()
            .map_or(Ok(()), JoinHandle::join)
            .map_err(|_| String::from("the operation panicked"))
    }
}

impl Drop for Op {
    fn drop(&mut self) {
        self.replies = None;
        let Some(thread) = self.thread.take() else {
            return;
        };
        let deadline = Instant::now() + self.wait;
        let mut done = matches!(self.pending, Message::Done(_));
        while !done {
            // `recv_timeout` can return a queued request when `left` is zero. The zero check ends the drain in that
            // case.
            let left = deadline.saturating_duration_since(Instant::now());
            match self.calls.recv_timeout(left) {
                Ok(Message::Done(_)) | Err(RecvTimeoutError::Disconnected) => done = true,
                Ok(_) if left.is_zero() => return,
                Ok(_) => {}
                Err(RecvTimeoutError::Timeout) => return,
            }
        }
        let _ = thread.join();
    }
}

/// Replaces every ITF big integer with a JSON number.
///
/// # Errors
///
/// `fixture integer <value>` for a `#bigint` object with another member or whose value is not the decimal text of
/// an `i64`.
pub(in crate::failover) fn plain(v: &mut Value) -> Result<(), String> {
    match v {
        Value::Object(map) if map.contains_key("#bigint") => {
            let parsed = (map.len() == 1)
                .then(|| map["#bigint"].as_str()?.parse::<i64>().ok())
                .flatten()
                .ok_or_else(|| format!("fixture integer {}", Value::Object(map.clone())))?;
            *v = parsed.into();
        }
        Value::Object(map) => map.values_mut().try_for_each(plain)?,
        Value::Array(list) => list.iter_mut().try_for_each(plain)?,
        _ => {}
    }
    Ok(())
}

fn digest(model: &[u8]) -> String {
    Sha256::digest(model)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Loads the trace `json` of the model family `key`, whose metadata stands under `#meta.<key>`, and returns its
/// states with every ITF big integer replaced by a JSON number, beside that metadata object. The digest check binds
/// the trace to the model bytes `model`; it does not show that Quint wrote the states.
///
/// # Errors
///
/// - The JSON parser's message for a trace that fails to parse.
/// - `fixture model digest` when `#meta.<key>.model_sha256` differs from the SHA-256 of `model`.
/// - `fixture integer <value>` for a malformed ITF big integer ([`plain`]).
/// - `fixture states` when the trace holds no state array.
/// - `fixture length` when `#meta.<key>.steps` is missing, is not an unsigned integer, or differs from the state
///   count less one.
pub(in crate::failover) fn states(
    json: &str,
    model: &[u8],
    key: &str,
) -> Result<(Vec<Value>, Value), String> {
    let mut trace: Value = serde_json::from_str(json).map_err(|e| e.to_string())?;
    if trace["#meta"][key]["model_sha256"] != digest(model) {
        return Err("fixture model digest".into());
    }
    plain(&mut trace)?;
    let meta = trace["#meta"][key].take();
    let states = match trace["states"].take() {
        Value::Array(states) => states,
        _ => return Err("fixture states".into()),
    };
    let steps = meta["steps"]
        .as_u64()
        .and_then(|steps| steps.checked_add(1));
    if Some(states.len() as u64) != steps {
        return Err("fixture length".into());
    }
    Ok((states, meta))
}

/// A trace's step count with no successor is a length mismatch, a malformed big integer is refused, and a trace of
/// zero steps holds one state.
#[test]
fn a_trace_is_refused_on_its_step_count_and_its_integers() {
    let model = b"model";
    let trace = |steps: Value, held: Value| {
        serde_json::json!({"#meta": {"t": {"model_sha256": digest(model), "steps": steps}}, "states": held})
            .to_string()
    };
    let one = serde_json::json!([{ "x": { "#bigint": "-3" } }]);
    for held in [one.clone(), serde_json::json!([])] {
        assert_eq!(
            states(&trace(u64::MAX.into(), held), model, "t").err(),
            Some("fixture length".into())
        );
    }
    assert_eq!(
        states(&trace("0".into(), one.clone()), model, "t").err(),
        Some("fixture length".into())
    );
    let (held, meta) = states(&trace(0.into(), one), model, "t").unwrap();
    assert_eq!(held, [serde_json::json!({ "x": -3 })]);
    assert_eq!(meta["steps"], 0);
    for integer in [
        serde_json::json!({ "#bigint": true }),
        serde_json::json!({ "#bigint": "9223372036854775808" }),
        serde_json::json!({ "#bigint": "1", "y": 2 }),
    ] {
        let error = states(
            &trace(0.into(), serde_json::json!([{ "x": integer }])),
            model,
            "t",
        )
        .unwrap_err();
        assert!(error.starts_with("fixture integer "), "{error}");
    }
}

/// An operation that repeats its provider create after every `Unknown` keeps sending requests once its reply channel
/// closes, and dropping its `Op` returns within the operation's wait.
#[test]
fn an_operation_that_repeats_its_create_after_every_unknown_drops_within_its_wait() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use crate::failover::sim::layout;

    let stop = Arc::new(AtomicBool::new(false));
    let stopped = Arc::clone(&stop);
    let mut op = Op::start(move |mut proxy| {
        while !stopped.load(Ordering::Relaxed) {
            if proxy.create("token", layout()).is_ok() {
                return "created".into();
            }
        }
        "stopped".into()
    })
    .unwrap();
    op.wait = Duration::from_millis(200);
    assert!(op.call().is_ok());
    op.answer(Reply::Call(Err(CreateError::Unknown))).unwrap();
    assert_eq!(
        op.call().map(|(token, _)| token.to_owned()),
        Ok("token".into())
    );
    let (dropped, gone) = channel();
    std::thread::spawn(move || {
        drop(op);
        let _ = dropped.send(());
    });
    let returned = gone.recv_timeout(WAIT).is_ok();
    stop.store(true, Ordering::Relaxed);
    assert!(
        returned,
        "the drop of a repeating operation waited past its wait"
    );
}

/// `recv_timeout` can return a queued message with a zero timeout. After receiving a `Call`, `Op::drop` checks the
/// deadline so it can return before reaching `Done` and joining the blocked thread.
#[test]
fn a_drop_past_its_wait_returns_while_the_result_is_queued_behind_requests() {
    use crate::failover::sim::layout;

    let (calls, inbox) = channel();
    let (release, held) = channel::<()>();
    for _ in 0..3 {
        calls.send(Message::Call("token".into(), layout())).unwrap();
    }
    calls.send(Message::Done("late".into())).unwrap();
    let thread = std::thread::spawn(move || {
        let _ = held.recv();
    });
    let op = Op {
        replies: None,
        calls: inbox,
        pending: Message::Call("token".into(), layout()),
        wait: Duration::ZERO,
        thread: Some(thread),
    };
    let (dropped, gone) = channel();
    std::thread::spawn(move || {
        drop(op);
        let _ = dropped.send(());
    });
    let returned = gone.recv_timeout(WAIT).is_ok();
    drop(release);
    assert!(
        returned,
        "the drop took the messages queued past its wait and joined the held thread"
    );
}

/// An operation that takes one reply and then sends nothing within the deadline fails the answer, and dropping its
/// `Op` returns while the operation is still held.
#[test]
fn an_operation_that_stalls_after_a_reply_fails_the_answer_and_drops_without_a_join() {
    use crate::net::ownership::Shard;

    let (release, held) = channel::<()>();
    let (took, taken) = channel::<()>();
    let key = Key::Shard(Shard::new(1).unwrap());
    let mut op = Op::start(move |mut proxy| {
        let _ = proxy.read(&key);
        let _ = took.send(());
        let _ = held.recv();
        "late".into()
    })
    .unwrap();
    op.wait = Duration::from_millis(50);
    assert!(op.read_of(&key).is_ok());
    assert_eq!(
        op.answer(Reply::Read(Ok(None))),
        Err("the operation issued no request".into())
    );
    taken.recv_timeout(WAIT).unwrap();
    let (dropped, gone) = channel();
    std::thread::spawn(move || {
        drop(op);
        let _ = dropped.send(());
    });
    assert!(
        gone.recv_timeout(WAIT).is_ok(),
        "the drop of a timed-out operation waited for its held thread"
    );
    drop(release);
}

/// Running `finish` on a thread of its own lets `recv_timeout(WAIT)` fail the test when `finish` joins an operation
/// that waits for a reply.
#[test]
fn finish_refuses_an_operation_that_still_waits_for_a_reply() {
    use crate::net::ownership::Shard;

    let key = Key::Shard(Shard::new(1).unwrap());
    let op = Op::start(move |mut proxy| {
        let _ = proxy.read(&key);
        "done".into()
    })
    .unwrap();
    assert!(op.read_of(&key).is_ok());
    let (finished, result) = channel();
    std::thread::spawn(move || {
        let _ = finished.send(op.finish());
    });
    assert_eq!(
        result.recv_timeout(WAIT),
        Ok(Err("the operation continues".into()))
    );
}
