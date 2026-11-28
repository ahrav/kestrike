//! [`Calls`], the plane's AWS calls: each call takes its reply, in order, from the list a case gives,
//! and is logged with its words and its limit. A call under an armed record with a signal stored
//! raises before it is logged, as a call raises before its child starts; a reply given to a call of
//! another operation stops the case.
//!
//! A reply takes the time the case sets for it on the plane's clock. A reply that takes longer than
//! its call's limit is no reply, and the call takes its limit, as a call the limit cuts does.

use std::collections::VecDeque;
use std::ffi::OsString;
use std::time::Duration;

use kestrike_tools::host_stop::{Interrupted, Record};
use kestrike_tools::json::Value;

use super::clock::Clock;

/// One reply: the service and operation of the call it answers, as `fis get-experiment`, its value,
/// or none for a call that ended without one, and the time it takes.
pub(crate) struct Reply {
    pub(crate) operation: &'static str,
    pub(crate) value: Option<Value>,
    pub(crate) takes: Duration,
}

/// One call the plane received: its words and its limit.
#[derive(Clone, Debug, PartialEq)]
pub(crate) struct Called {
    pub(crate) words: Vec<String>,
    pub(crate) limit: Duration,
}

/// The replies still to give and the calls received.
#[derive(Default)]
pub(crate) struct Calls {
    replies: VecDeque<Reply>,
    pub(crate) log: Vec<Called>,
}

impl Calls {
    pub(crate) fn new(replies: Vec<Reply>) -> Self {
        Self {
            replies: replies.into(),
            log: Vec::new(),
        }
    }

    /// Answers one call of `words` within `limit` on `clock`.
    ///
    /// # Errors
    ///
    /// The signal the record raised while the call's time passed.
    pub(crate) fn call(
        &mut self,
        clock: &Clock,
        record: &mut Record<'_>,
        words: &[OsString],
        limit: Duration,
    ) -> Result<Option<Value>, Interrupted> {
        record.read()?;
        let words: Vec<String> = words
            .iter()
            .map(|word| word.to_string_lossy().into_owned())
            .collect();
        self.log.push(Called {
            words: words.clone(),
            limit,
        });
        let reply = self
            .replies
            .pop_front()
            .unwrap_or_else(|| panic!("the plane holds a reply for the call {words:?}"));
        assert_eq!(
            words
                .get(..2)
                .map(|operation| operation.join(" "))
                .as_deref(),
            Some(reply.operation),
            "the reply answers the call's operation"
        );
        if reply.takes > limit {
            clock.pass(record, limit)?;
            return Ok(None);
        }
        clock.pass(record, reply.takes)?;
        Ok(reply.value)
    }
}
