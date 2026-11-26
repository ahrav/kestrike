//! The rule texts a run can record as a violation, so a narrative names a
//! violation's full rule from the SHA-256 its identity holds; a violation
//! record keeps at most 41 bytes of it. This file copies each text written
//! beside the check that raises it, by producer, and its test scans the
//! crate's sources so a rule raised without its copy here, or through an
//! expression the scan cannot resolve, fails. Unsuccessful and
//! inconclusive checks record no identity, so their texts are not here.

use sha2::{Digest, Sha256};

/// The rule of a complete read with wrong bytes. The world's read check
/// raises it for a complete read whose bytes are the body of no registered
/// content of the key, and the oracle for one whose bytes differ from its
/// label's content. [`WORLD`] names it, [`ORACLE`] holds its text, and a
/// scripted control names it as its declared ending.
pub(crate) const COMPLETE_MISREAD: &str =
    "a complete read returned bytes other than the label's content";

/// The violations the stopped-boundary and teardown observer raises.
const OBSERVER: &[&str] = &[
    "a binding names a slot holding no resident object at its incarnation",
    "a binding names a slot of another key",
    "a bound slot's bytes match no registered content",
    "a bound slot's extent lies outside the device",
    "a bound slot's record fails its header or chunk checks",
    "a datagram a link delivered to an owner has no single account",
    "a held extent overlaps another or lies outside the volume",
    "a ledger term differs from the slot words or the free units",
    "a resident slot has no binding",
    "a slot word is malformed",
    "an unexpected binding",
    "the free runs differ from the units no slot holds",
    "two bindings name one slot",
    "two bindings route one fingerprint",
];

/// The oracle's rules, which a world raises as an oracle verdict or, in a recovery run, as its Restart violation.
const ORACLE: &[&str] = &[
    "Expired without a published label past its deadline",
    "NotStarted after the owner saw the attempt",
    "Published names another label",
    "Published without the attempt's publication",
    "a Failed result after the authority names no serial",
    "a NIC release returned a tenure its attempt never took",
    "a NIC take of a source slot exceeded the active grant",
    "a NIC take of a source slot followed its retention release",
    "a NIC take of a source slot followed no retransmission take of its fragment",
    "a changed retry replayed the attempt",
    "a client accepted a response tagged below its high-water",
    "a client's recorded high-water fell",
    "a clock sample regressed behind an earlier one",
    "a colliding candidate delivered another key's bytes",
    "a colliding candidate passed header verification",
    "a complete read returned bytes other than the label's content",
    "a counted resource was taken while held",
    "a delivery of content from a superseded session",
    "a deposed tenure's medium command, accepted after its successor's fence, succeeded",
    "a failed owner returned custody its unproven stop retained",
    "a failed read exposed bytes outside the verified prefix",
    "a failed read exposed bytes past a verified chunk boundary",
    "a fill admitted after the cache closed",
    "a fill revoked by an invalidation or a tenure change published",
    "a fragment was validated beyond the active grant",
    "a fragment's payload disagrees with the attempt's manifest",
    "a healthy checkpoint began with holders outstanding",
    "a healthy owner served no exact bytes",
    "a healthy owner starved past its fixture bound",
    "a held extent was taken under different geometry",
    "a hit after a recorded removal of its label in the same tenure",
    "a hit at or past the deadline",
    "a hit of a version an acknowledged invalidation covered",
    "a hit of a version no linearized fill published",
    "a holder took a completed incarnation",
    "a known attempt result changed",
    "a lookup answered after the cache closed",
    "a production report disagreed with the independent count",
    "a publication acknowledged without a clock sample",
    "a publication after the cache closed",
    "a publication at or past its deadline",
    "a publication before every write of its attempt delivered success",
    "a publication before its writes completed",
    "a publication label was published twice",
    "a publication whose write commands overlap on the device",
    "a publication without an acknowledged fill",
    "a qualified checkpoint began with a lease outstanding",
    "a qualified checkpoint began with holders outstanding",
    "a qualified funded interval produced no exact hit",
    "a receipt base counted fragments never received",
    "a receipt mask named a fragment never received",
    "a receive after the cache closed",
    "a recorded restore from a checkpoint the store did not name",
    "a recorded restore of a covered version",
    "a recorded restore of a version never published",
    "a recovered candidate was found without admission",
    "a recovered candidate was served without freshness, expiry, serving or replay authority",
    "a recovered expiry without portable expiry authority",
    "a recovery restored an entry its cut never captured",
    "a recovery-safe exclusion was readmitted",
    "a recovery-safe exclusion was revived after restart",
    "a recovery-time stale refusal stood in for a recorded eviction",
    "a refused read exposed bytes",
    "a released checkpoint kept capacity its obligations no longer justify",
    "a released checkpoint left a publication's visibility open",
    "a removal of a label the key never held",
    "a removal selected a label already removed",
    "a removal selected a label an invalidation covered",
    "a resource was retaken under an earlier incarnation",
    "a resource was reused while a custodian held an earlier incarnation",
    "a retained entry outside every damage set was lost on host loss",
    "a retained entry outside every damage set was never served after host loss",
    "a retention release ended a tenure its attempt never took",
    "a retention release named another fragment than its take",
    "a slot was reused before its publication's visibility ended",
    "a slot was taken under another publication",
    "a source slot cancel named no retained tenure",
    "a source slot named a fragment beyond the attempt's manifest",
    "a source slot tenure was released more often than taken",
    "a source slot tenure was taken twice",
    "a source slot took a fragment the receipt base had passed",
    "a source slot was taken after the attempt's result or cancel",
    "a span-measured resource was taken without geometry",
    "a successor recovered from a cut other than the one its volume last made durable",
    "a tenure served a version only a later tenure published",
    "a visibility end by expiry before the deadline",
    "a visibility end named a publication its slot did not hold",
    "a visibility end returned no held custody",
    "a withdrawn tenure's device accepted a medium command",
    "a write completion was taken as durable payload evidence",
    "a write quota returned before its command's terminal",
    "a write quota was taken without its command",
    "abstract action lacks declared recovery semantics",
    "acquisition has no label",
    "admission has no key or label",
    "admission lacked binding, payload, identity or ownership evidence",
    "an abandonment of an attempt that was not Unknown",
    "an attempt published twice",
    "an attempt that did not publish published",
    "an attempt took one fragment into two source slots",
    "an attempt validated one fragment twice",
    "an eviction while a fill is current",
    "an exclusive custodian retook an incarnation it had returned",
    "an exclusive custodian took a resource it already held",
    "an invalidation after the cache closed",
    "an isolated stop retained custody no custodian held",
    "an owner flow row of the attempt names no serial",
    "an owner row beyond the attempt's manifest",
    "an unproven stop returned retained custody",
    "attempt activity after a known result",
    "bytes from a failed chunk or a later one were exposed",
    "bytes were exposed before a header mismatch",
    "delivered identity differs from the acquired content",
    "delivered label has no content",
    "delivered lengths differ from the label's content",
    "expiry removed a label before its deadline",
    "funded recovery exceeded its action bound",
    "host loss activated a cut no capture recorded",
    "host loss replaced a retained cut with a cold start",
    "no legal order of the key's operations",
    "publication has no label",
    "recovered acquisition has no key or label",
    "recovered acquisition precedes restart",
    "retransmission retention ended before the receipt base passed its fragment",
    "the attempt's phases are out of order",
    "the attempt's receipt base or grant regressed",
    "the owner filled after the attempt's authority",
    "the owner prepared another manifest",
    "the rows of one attempt name two keys",
    "the rows of one attempt name two serials",
    "two attempts share one serial",
    "two exclusive custodians held one incarnation",
    "writable extents overlapped",
];

/// The violations the mixed world and its scripted histories raise.
const MIXED: &[&str] = &[
    "a GET a PUT frame named ended other than with its exact version",
    "a GET after a lost final frame ended without the object",
    "a GET after a lost final frame reported bytes other than the object's",
    "a GET after the acknowledged invalidation saw a removed version",
    "a GET at its expiry sample served the version",
    "a GET disagreed with the upload's judged outcome",
    "a GET past a peer's share ended without a typed pressure outcome",
    "a GET past a peer's share outlived its one deadline",
    "a GET past the share ended without a typed pressure outcome",
    "a GET under an exhausted read pool ended without its typed pressure",
    "a PUT frame naming a GET changed more than its counter",
    "a cancel released custody before the read's terminal",
    "a cancelled upload whose DATA was accepted claimed no effect",
    "a close released DATA the device still held",
    "a closed owner kept sending",
    "a closed owner settled an upload from its receipt",
    "a cohort's setup, effect and check named different identities",
    "a cohort's setup, effect and check ran out of order",
    "a custody domain kept a reference after its proof",
    "a cut upload settled as published",
    "a damaged read ended other than with a verified prefix and a typed failure",
    "a deadline recycled sources the device still held",
    "a deferred upload ended with an outcome its deadline cannot give",
    "a deferred upload outlived its one deadline",
    "a deferred upload published bytes its supplier never gave",
    "a delayed matching RESULT left the unknown upload unresolved",
    "a device stop ended the links' custody",
    "a displaced session freed its draining slot while its read was held",
    "a displaced upload released sources the device still held",
    "a displaced upload whose DATA was accepted claimed no effect",
    "a displacement dropped the old session's live charges",
    "a duplicate fragment created credit",
    "a failed owner's unproven stop read as proven",
    "a healed funded upload never published",
    "a healed request settled without its update",
    "a healed request stalled past its bound",
    "a healed saturated GET missed its exact bytes",
    "a key was granted a second fill beside its current attempt",
    "a known upload outcome regressed",
    "a lookup leased an object past its right limit",
    "a late old-session ACK moved the successor's receipt",
    "a lost RESULT ended the upload as a failure",
    "a lost fragment's source was released before its receipt",
    "a peer's charge left its live requests or its share",
    "a peer's share was charged with another peer's work",
    "a pressured request outlived its one deadline",
    "a pressured upload outlived its one deadline",
    "a proven stop kept a command on the device",
    "a qualified GET missed the visible version's exact bytes",
    "a refused GET's wire identity stayed unsettled",
    "a rejected upload erased the incumbent",
    "a relaunch replaced the shared media",
    "a replacement client's GET ran under the displaced session",
    "a request on an ended upload's wire slot was refused while its write drained",
    "a retained GET left its peer's share before its release",
    "a retry reused its identity across the replacement",
    "a sample below the deadline missed the live version",
    "a settled GET's row held an admitted request",
    "a settled upload's row held an admitted attempt",
    "a stalled upload's request was not charged",
    "a stop without proof ended custody",
    "a successor published a FILL its predecessor's acknowledged INVALIDATE covers",
    "a successor took its predecessor's wire identity",
    "a successor's result came from its predecessor",
    "a timed-out upload claimed no effect after its DATA reached the owner",
    "a timed-out upload claimed publication before its RESULT",
    "a write command went to a peer at its share while a peer below its share waited",
    "an abort with a write outstanding unwound",
    "an admitted upload whose write submit unwound claimed no effect",
    "an attach wrote a root generation at or below one the root slots held",
    "an eligible peer's GET starved behind a saturated share",
    "an eligible peer's GET starved beside a stalled upload",
    "an owner turn sampled a tick other than its projection",
    "an owner turn unwound after the upload's write submit",
    "an upload claimed publication without a delivered RESULT",
    "an upload collected as published without its result",
    "an upload passed its granted credit",
    "an upload past its share ended without its typed pressure",
    "an upload resolved its unknown outcome before its RESULT was received",
    "an upload resolved its unknown outcome without a matching RESULT",
    "an upload under pressure ended without a typed refusal",
    "an upload whose write submit unwound published",
    "an upload's held count left its lane ring's entries",
    "the concurrent GET ended other than with its exact version",
    "the credit check saw no captured fragment",
    "the handshake's second copies moved its session",
    "the held sample began at or past the deadline",
    "the invalidation removed no mapping",
    "the old right ended without its version",
    "the old right returned bytes other than its own version",
    "the owner accepted the displaced session's frames",
    "the owner's close unwound after the upload's write submit",
    "the owner's displaced pending handshake left its client without a session",
    "the owner's turn unwound submitting the upload's write",
    "the replacement never published",
    "the replacement's GET missed the visible version",
    "the upload's result was other than published",
    "unrelated work stalled or read bytes outside the visible versions",
];

/// The violations the cluster checker raises.
const CLUSTER: &[&str] = &[
    "a GET exposed bytes under an outcome that hands none out",
    "a GET returned a version its owner reported as not published",
    "a GET returned a version older than one collected or removed before it",
    "a GET returned bytes no upload of its key wrote",
    "a key was served from an owner its routing contract does not name",
    "an incomplete GET exposed bytes no one upload of its key wrote",
    "an incomplete GET exposed bytes of a version or owner it could not read",
    "an incomplete GET exposed no bytes",
    "an invalidation removed bytes no upload of its key wrote",
    "an owner binds a version an acknowledged invalidation covered",
    "an owner binds a version an invalidation removed",
    "an owner binds a version it reported as not published",
    "an owner binds a version older than one it published",
    "an owner binds bytes no upload of its key wrote",
    "an owner reported a publication while its index binds another version",
    "an owner reported a removal while its index binds the key",
    "an owner reported a version a GET read as not published",
    "an owner reported a version an invalidation removed as not published",
    "an owner reported a version it binds as not published",
    "an owner reported no removal while its index bound the key",
    "an owner reported removing an allocation its index did not bind",
];

/// The violations the single-owner world raises itself, outside its
/// scripted histories: a subset of the oracle's and the mixed world's
/// texts.
const WORLD: &[&str] = &[
    COMPLETE_MISREAD,
    "a failed read exposed bytes outside the verified prefix",
    "a healed request settled without its update",
    "a healed request stalled past its bound",
    "a hit of a version no linearized fill published",
    "a refused read exposed bytes",
    "an upload collected as published without its result",
];

/// The oracle's texts that a scripted history's own step also raises: the
/// key-operation histories', the two isolation controls', the late
/// BEGIN's, the covered version's, the prepared manifest's and the known-result
/// incident histories'.
const HISTORY_SHARED: &[&str] = &[
    "the owner filled after the attempt's authority",
    "a hit of a version an acknowledged invalidation covered",
    "the owner prepared another manifest",
    "a fill admitted after the cache closed",
    "a lookup answered after the cache closed",
    "a fill revoked by an invalidation or a tenure change published",
    "a publication at or past its deadline",
    "a publication before its writes completed",
    "an eviction while a fill is current",
    "a resource was reused while a custodian held an earlier incarnation",
    "a publication after the cache closed",
    "a receive after the cache closed",
    "an invalidation after the cache closed",
    "a failed owner returned custody its unproven stop retained",
    "a healthy owner served no exact bytes",
    "a hit after a recorded removal of its label in the same tenure",
    "a known attempt result changed",
    "a publication before every write of its attempt delivered success",
];

/// The cluster checker and the tenure-binding history steps raise the same
/// text.
const CLUSTER_SHARED: &[&str] = &["an owner binds a version an acknowledged invalidation covered"];

/// The rule catalog form's version.
pub(crate) const RULES: u32 = 1;

/// Every cataloged rule with the check that raises it: `boundary` for the
/// stopped-boundary and teardown observer, which judges every single-owner
/// and cluster run; `world` for the single-owner world's own checks;
/// `cluster` for the cluster checker; `history` for a scripted history's
/// own checks; and `oracle` for the oracle over recorded rows. A text the
/// single-owner world raises beside the oracle appears under `world` and
/// `oracle`, and a text of [`HISTORY_SHARED`] under `history` and
/// `oracle`. The `oracle` scope comes last. Each [`CLUSTER_SHARED`] text
/// appears under both `cluster` and `history`.
pub(crate) fn scoped() -> impl Iterator<Item = (&'static str, &'static str)> {
    let world = |text: &&str| WORLD.contains(text);
    let scope = |name: &'static str, texts: &'static [&'static str]| {
        texts.iter().map(move |text| (name, *text))
    };
    scope("boundary", OBSERVER)
        .chain(scope("world", WORLD))
        .chain(scope("cluster", CLUSTER))
        .chain(
            MIXED
                .iter()
                .filter(move |text| !world(text))
                .map(|text| ("history", *text)),
        )
        .chain(scope("history", HISTORY_SHARED))
        .chain(scope("history", CLUSTER_SHARED))
        .chain(scope("oracle", ORACLE))
}

/// The rule catalog form: its version, then one `rule: SCOPE TEXT` line
/// for each entry of [`scoped`].
pub(crate) fn listing() -> String {
    let mut out = format!("rules: {RULES}\n");
    for (scope, text) in scoped() {
        out.push_str(&format!("rule: {scope} {text}\n"));
    }
    out
}

/// Every cataloged rule.
pub(crate) fn texts() -> impl Iterator<Item = &'static str> {
    [OBSERVER, ORACLE, MIXED, CLUSTER]
        .into_iter()
        .flatten()
        .copied()
}

/// The cataloged rule whose SHA-256 is `hash`: a text is selected by its
/// hash alone.
pub(crate) fn resolve(hash: &[u8]) -> Option<&'static str> {
    texts().find(|text| Sha256::digest(text.as_bytes())[..] == *hash)
}

#[cfg(test)]
mod tests;
