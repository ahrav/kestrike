//! A cancelled upload whose DATA the owner accepted never reports that it did not start.
//!
//! Property: a cancelled upload whose DATA the owner accepted never reports that it did not start.
//! The rule this file judges is the one `cancelled_outcome` of `histories.rs` raises under
//! `Obligation::History`: "a cancelled upload whose DATA was accepted claimed no effect".
//!
//! - `cu1-put-cancelled-after-its-data`: the history holds the owner's write commands,
//!   then the uploading client begins, prepares and supplies an upload of key 1. Once the device holds a
//!   write the owner submitted after the supply, the owner has accepted the DATA, and the client cancels
//!   the upload. The step that sees the upload decided fails with the rule when the client's outcome is
//!   `NotStarted`. The holds end after the verdict and the peer's requests drain.
//! - `cu1-put-uncancelled-after-its-data`: the same upload, held at the same
//!   write, with no cancel. The holds end and the upload must publish.
//!
//! Every step is one of `histories.rs`; this file adds the two scripts and their registration.

use super::*;

const CANCELLED: [Step; 10] = [
    step("arm", always, arm_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("cancel-put", always, cancel_put),
    step("cancelled-outcome", put_decided, cancelled_outcome),
    step("release", always, release_everything),
    step("cancelled-drained", upload_drained, mark_drained),
    JUDGE,
];

const UNCANCELLED: [Step; 8] = [
    step("arm", always, arm_writes),
    step("put-begin", active_put, put_begin),
    step("put-prepare", always, put_prepare),
    step("put-supply", always, put_supply),
    step("write-held", write_held, mark_write_held),
    step("release", always, release_everything),
    step("put-result", put_decided, put_published),
    JUDGE,
];

const CANCELLED_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    "owner write held",
    "upload cancelled with its DATA accepted",
    "the cancelled upload's outcome matched its phase",
    "the cancelled request drained after its terminal",
];

const UNCANCELLED_WITNESSES: &[&str] = &[
    "upload prepared",
    "upload DATA supplied",
    "owner write held",
    "upload published",
];

const CANCELLED_JUDGED: &[Obligation] = &[Obligation::History, Obligation::Resources];
const UNCANCELLED_JUDGED: &[Obligation] = &[Obligation::History];

pub(super) const CANCELLED_UPLOADS: [History; 2] = [
    uploading(
        history(
            "cu1-put-cancelled-after-its-data",
            &CANCELLED,
            CANCELLED_WITNESSES,
            CANCELLED_JUDGED,
            Expect::Pass,
        ),
        1,
    ),
    uploading(
        history(
            "cu1-put-uncancelled-after-its-data",
            &UNCANCELLED,
            UNCANCELLED_WITNESSES,
            UNCANCELLED_JUDGED,
            Expect::Pass,
        ),
        1,
    ),
];
