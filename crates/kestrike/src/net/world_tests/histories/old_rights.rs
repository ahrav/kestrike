//! A GET whose read was running when its key was invalidated and replaced ends Complete with its
//! own version's exact bytes.
//!
//! Property: a GET that acquired the resident version before its key was invalidated ends with that
//! version, rule text "the old right ended without its version" (narrate/rules.rs).
//!
//! The first history holds the old GET's read at the device, invalidates the key through the owner, sees a fresh
//! GET miss, fills and publishes a replacement while the old read is still held, and then releases the read.
//! Its judge step requires the old GET to end `Complete` with the old version's exact bytes. H1's judge
//! (`judge_old`) also accepts a failure that delivered a prefix of the old version; this one does not, so a
//! read the invalidation cancels fails the history through the rule. A later GET reads the replacement
//! exactly. The sibling runs the same GET, the same hold and the same judge step with no invalidation and no
//! replacement. `or1-get-ended-over-a-prefix` is a control: the first history's steps, whose judge step is
//! handed a planted ending, `Incomplete` over a prefix of the old version, and fails it through the rule.
//!
//! The held read is the one premise: `mark_read_held` leaves "old read held" unmarked when the device
//! held no read, and `JUDGE` then ends a run that recorded no failure `Unsuccessful` under that witness.
//! The invalidation, the fresh miss and the replacement's publication are H1's checks. Each records a
//! violation of its own rule: "the invalidation removed no mapping", "a GET after the acknowledged
//! invalidation saw a removed version" and "the replacement never published".

use super::*;

/// The rule the family judges.
pub(super) const ENDED_SHORT: &str = "the old right ended without its version";

/// The old GET's ending is read and judged.
fn old_complete(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let get = world.gets[1].as_ref().expect("the old GET");
    let (outcome, bytes) = (get.outcome, get.bytes.clone());
    judge_complete(world, outcome, &bytes)
}

/// A control: the judgment is handed an old GET that ended `Incomplete` over a prefix of its version, as
/// a read the invalidation cancelled would end.
fn old_prefix(world: &mut Mixed<'_, '_, '_>, _: u64) -> u64 {
    world.read(1);
    let version = version_a();
    judge_complete(
        world,
        Some(Outcome::Incomplete(Status::Cancelled)),
        &version[..version.len() / 2],
    )
}

/// The old right ends `Complete` with its own version's exact bytes. Any other ending, a failure that
/// delivered a prefix of the version included, breaks the rule.
pub(super) fn judge_complete(
    world: &mut Mixed<'_, '_, '_>,
    outcome: Option<Outcome>,
    bytes: &[u8],
) -> u64 {
    if outcome != Some(Outcome::Complete) || bytes != version_a() {
        return fail(world, Obligation::Bytes, ENDED_SHORT);
    }
    mark(world, "old right returned its version")
}

/// The old read and its DATA references held across an acknowledged invalidation, a fresh miss and the
/// replacement's publication; the old right then ends `Complete` with its own version, and a later GET
/// reads the replacement.
const REPLACED: [Step; 14] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("invalidate", always, invalidate),
    step("fresh-get", active_put, fresh_get),
    step("fresh-miss", fresh_decided, fresh_missed),
    step("fill-replacement", always, fill_b),
    step("publish-replacement", fill_written, publish_fill),
    step("release-old-read", always, release_reads),
    step("old-right-complete", old_decided, old_complete),
    step("release-nic", always, release_nic),
    step("qualified-get", active_put, fresh_get),
    step("qualified-read", fresh_decided, fresh_exact_b),
    JUDGE,
];

const PREFIX_JUDGED: [Step; 14] = replaced(
    REPLACED,
    "old-right-complete",
    step("old-right-prefix", old_decided, old_prefix),
);

/// The same GET, hold, release and judge step with no invalidation and no replacement.
const UNDISTURBED: [Step; 7] = [
    step("arm", always, arm),
    step("old-get", active_get, old_get),
    step("old-read-held", read_held_or_done, mark_read_held),
    step("release-old-read", always, release_reads),
    step("old-right-complete", old_decided, old_complete),
    step("release-nic", always, release_nic),
    JUDGE,
];

const REPLACED_WITNESSES: &[&str] = &[
    "old read held",
    "invalidation acknowledged",
    "fresh GET missed",
    "replacement published",
    "old read released",
    "old right returned its version",
    "qualified exact read",
];

const UNDISTURBED_WITNESSES: &[&str] = &[
    "old read held",
    "old read released",
    "old right returned its version",
];

const REPLACED_JUDGED: &[Obligation] = &[Obligation::Bytes, Obligation::History];

pub(super) const OLD_RIGHTS: [History; 3] = [
    history(
        "or1-get-across-a-replacement",
        &REPLACED,
        REPLACED_WITNESSES,
        REPLACED_JUDGED,
        Expect::Pass,
    ),
    history(
        "or1-get-undisturbed",
        &UNDISTURBED,
        UNDISTURBED_WITNESSES,
        &[Obligation::Bytes],
        Expect::Pass,
    ),
    control(
        history(
            "or1-get-ended-over-a-prefix",
            &PREFIX_JUDGED,
            REPLACED_WITNESSES,
            REPLACED_JUDGED,
            Expect::Violation(Obligation::Bytes, ENDED_SHORT),
        ),
        &["old read held"],
    ),
];
