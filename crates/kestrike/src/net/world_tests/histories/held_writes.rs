//! Held-write history: an upload whose DATA the device still holds publishes once the holds end under an
//! open owner.
//!
//! `h3-put` of `histories.rs` closes the owner while an upload's DATA is accepted with its device
//! references held, and judges that the close keeps them. `hw1-put-open` is its sibling with no close: the
//! same upload, the same holds and the same premises, and the owner stays open. The holds end, the owner's
//! write completes, its RESULT reaches the client and the upload must publish, the rule `put_published` of
//! `histories.rs` raises. Every reference must then be reclaimed with zero device commands within the
//! bound, the rule `released_in_domain` raises.
//!
//! The premises are the marks of the held steps: the link's device keeps the reference of the client's
//! DATA, the storage device holds the owner's write of that DATA, and the client holds the owner's receipt
//! of every fragment. The last step ends a run unsuccessful under the witness that did not form.

use super::*;

/// The steps of `h3-put` with its close skipped: the holds end in the turn the close's judgment took, and
/// the upload's publication is judged before the references' return.
const OPEN: [Step; 12] = replaced(
    replaced(
        replaced(H3_PUT, "close", step("close-skipped", always, removed_step)),
        "close-retained",
        step("release-open", always, release_everything),
    ),
    "release",
    step("put-published", put_decided, put_published),
);

const OPEN_WITNESSES: &[&str] = &[
    "upload DATA supplied",
    "upload DATA held by the device",
    "owner write held",
    "upload receipt acknowledged",
    "holds released",
    "upload published",
    "each custody domain released after its proof",
];

const OPEN_JUDGED: &[Obligation] = &[
    Obligation::History,
    Obligation::Progress,
    Obligation::Resources,
];

pub(super) const HELD_WRITES: [History; 1] = [uploading(
    history(
        "hw1-put-open",
        &OPEN,
        OPEN_WITNESSES,
        OPEN_JUDGED,
        Expect::Pass,
    ),
    1,
)];
