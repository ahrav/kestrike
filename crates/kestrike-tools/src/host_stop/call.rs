//! The call a command makes: one `aws` child through the seam, and its standard output read as one
//! strict JSON object.

use super::launch::{Call, Ended};
use super::record::{Interrupted, Record};
use super::replies::FailedCall;
use super::seam::Seam;
use super::words::sentence;
use crate::gameday::decode;
use crate::json::{Object, Value};

/// Why [`reply`] returned no object: a failed call, or a signal the record raised during it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CallError {
    Failed(FailedCall),
    Interrupted(Interrupted),
}

impl From<FailedCall> for CallError {
    fn from(failed: FailedCall) -> Self {
        Self::Failed(failed)
    }
}

/// `reply` runs `call` through `seam` and returns the JSON object its child prints.
///
/// # Errors
///
/// [`CallError::Interrupted`] for a signal the record raised, passed on as the seam returns it;
/// [`CallError::Failed`] for the launch's failed call, `the reply of <what> is not strict JSON: <reason>`
/// and `the reply of <what> is no JSON object`, `<what>` the call's first two arguments.
pub fn reply(
    seam: &mut (impl Seam + ?Sized),
    record: &mut Record<'_>,
    call: &Call<'_>,
) -> Result<Object, CallError> {
    let text = seam.call(record, call).map_err(|ended| match ended {
        Ended::Failed(failed) => CallError::Failed(FailedCall::Launch(failed)),
        Ended::Interrupted(raised) => CallError::Interrupted(raised),
    })?;
    let what = call.argv[..call.argv.len().min(2)].join(" ");
    match decode(&text, &sentence!("the reply of ", what)) {
        Ok(Value::Object(reply)) => Ok(reply),
        Ok(_) => {
            Err(FailedCall::Reply(sentence!("the reply of ", what, " is no JSON object")).into())
        }
        Err(refusal) => Err(FailedCall::Reply(refusal.message().clone()).into()),
    }
}
