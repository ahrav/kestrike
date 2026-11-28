//! The judge's fixed names, bounds and texts. GD-2's texts stand as the judge's rules were written from
//! them, and [`crate::gameday::gd2_entry`] refuses a catalog whose texts differ.

/// The game-day catalog, relative to the tree's top.
pub const CATALOG: &str = "verification/readiness/gamedays.json";
/// The package the judge and its controller run.
pub(super) const PACKAGE: &str = "GD-2";
/// The largest file the judge reads, in bytes.
pub const FILE_LIMIT: u64 = 64 << 20;
/// The fewest shards the target owns before the stop.
pub(super) const MIN_OWNED: usize = 2;
/// The fewest shards the target stands by for before the stop.
pub(super) const MIN_STOOD: usize = 1;
/// The largest attempt count of a shard's version.
pub(super) const ATTEMPTS_MAX: u64 = (1 << 31) - 2;
/// The most origin intervals a run window holds.
pub(super) const MAX_INTERVALS: u32 = 1_000_000;
/// Each observation a simulated world may lack, with the file that holds it.
pub(super) const OBSERVATION_FILES: [(&str, &str); 3] = [
    ("origin", "origin.jsonl"),
    ("provider", "provider.jsonl"),
    ("re-enrollment", "blockers.jsonl"),
];
/// The causes an abort mark names.
pub(super) const CAUSES: [&str; 6] = [
    "guardrail",
    "deadline",
    "exception",
    "signal",
    "reach",
    "stop-not-shown",
];
/// The outcomes of a witness read.
pub(super) const OUTCOMES: [&str; 3] = ["hit", "miss", "error"];
/// Each package kind with the catalog mode it runs.
pub(super) const KINDS: [(&str, &str); 2] = [("staging", "causal"), ("simulation", "simulation")];
/// The longest `hosts`, `shards` and `witness` lists of a package, each the constant its file declares,
/// which the zone's fleet directory refuses a longer host or shard listing by: (list, file of the tree,
/// constant).
pub(super) const FLEET_BOUNDS: [(&str, &str, &str); 3] = [
    (
        "hosts",
        "crates/kestrike/src/failover/zone_loop/directory.rs",
        "MAX_HOSTS",
    ),
    (
        "shards",
        "crates/kestrike/src/failover/standbys.rs",
        "MAX_SLOTS",
    ),
    (
        "witness",
        "crates/kestrike/src/failover/standbys.rs",
        "MAX_SLOTS",
    ),
];
/// The sentence of the witness rule, which GD-2's `oracle.expected` holds.
pub(super) const WITNESS: &str = "each of the filled package's witness keys from the certified pre-fault cut, at \
least one per shard, is first hit on the successor with its recorded bytes and no origin request for that key \
before the hit";
/// GD-2's hypothesis clauses, each with the budget that bounds it.
pub(super) const WRITTEN_CLAUSES: [(&str, Option<&str>); 5] = [
    (
        "each owned shard is taken over by its named standby at the same generation and volume",
        None,
    ),
    (
        "every shard the stopped host did not own keeps its owner",
        None,
    ),
    (
        "no volume is created, no generation changes and each shard has one owner per tenure",
        None,
    ),
    (
        "each shard the stopped host owned or stood by for has an enrolled standby again within the \
re-enrollment drain or reports a named blocker",
        Some("re-enrollment-drain"),
    ),
    (
        "the zone's origin request rate above its baseline before the injection stays within the \
origin-load budget",
        Some("origin-load"),
    ),
];
/// GD-2's guardrails, in the catalog's order.
pub(super) const WRITTEN_GUARDRAILS: [&str; 8] = [
    "any generation change",
    "any CreateVolume by the reconciler principal",
    "any replacement receipt written by the reconciler principal",
    "a takeover of a shard with no role on the stopped host",
    "a shard that changes hands twice",
    "the zone's origin request rate above its baseline past the origin-load budget",
    "a shard without a standby or a named blocker past the re-enrollment drain",
    "two hosts activating one tenure of a shard",
];
/// The SHA-256 of the UTF-8 bytes of GD-2's `oracle.reach` in the catalog.
pub(super) const WRITTEN_REACH: &str =
    "61ee57c75da6a905e9388ddd4e88da65966475424b199077be2f74734d47cc0b";
/// The SHA-256 of the UTF-8 bytes of GD-2's `oracle.expected` in the catalog.
pub(super) const WRITTEN_EXPECTED: &str =
    "20bea5125462d542f16749914573e4dedf7c844746d10f0390268583b2b9f575";
/// The mark of a text the readiness catalog leaves to be written, which blocks a run.
pub const TBD: &str = "TBD - BLOCKS EXECUTION";
/// The directories of the evidence layout.
pub(super) const LAYOUT_DIRS: [&str; 2] = ["injection", "records"];
/// The files a collector writes beside `records/`, which `coverage.json` spans with each `records/` file.
pub(super) const COLLECTED: [&str; 5] = [
    "activations.jsonl",
    "witness.jsonl",
    "origin.jsonl",
    "provider.jsonl",
    "blockers.jsonl",
];
/// The marks, in the layout's order, that the seal names where they stand when it is written: each file
/// of `injection/` but the seal itself.
pub(super) const MARKS: [&str; 5] = [
    "injection/roles.json",
    "injection/stop.json",
    "injection/stopped.json",
    "injection/abort.json",
    "injection/restoration.json",
];
