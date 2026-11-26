//! `O-*` aliases name the eight obligations for traceability; canonical
//! coverage uses `P-E-NN` and `P-N-NN` identifiers, and `PROPOSED_RECORDS`
//! lists the records the registry owner has yet to accept. Remote PUT coverage reuses the upload
//! records in `PUT_RECORDS`; a PUT subclaim no record covers is handed to
//! the registry owner by a descriptive alias in `HANDOFF_ALIASES`.

/// Declaration order indexes `ALL`, `OBLIGATIONS` and `Activations`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub(crate) enum Obligation {
    Bytes,
    History,
    Custody,
    Resources,
    Restart,
    Progress,
    Isolation,
    Contain,
}

/// Uncovered subclaims for the registry owner: each proposed record with
/// the obligation it supports, or `None` for oracle-wide and lane records.
pub(crate) static PROPOSED_RECORDS: &[(&str, &str, Option<Obligation>)] = &[
    (
        "P-E-45",
        "record-header-layout-and-chunk-table",
        Some(Obligation::Contain),
    ),
    (
        "P-E-46",
        "record-header-crc-span-field-zero",
        Some(Obligation::Contain),
    ),
    (
        "P-E-47",
        "header-encoders-write-header-only-fill-zeroes-tail",
        Some(Obligation::Contain),
    ),
    (
        "P-E-48",
        "codec-paths-allocate-nothing",
        Some(Obligation::Contain),
    ),
    (
        "P-E-49",
        "frame-header-layout-two-crcs-and-corpus",
        Some(Obligation::Contain),
    ),
    (
        "P-E-50",
        "frame-parse-order-and-encoder-canonical",
        Some(Obligation::Contain),
    ),
    (
        "P-E-51",
        "kind-status-frozen-per-kind-constraints",
        Some(Obligation::Contain),
    ),
    (
        "P-E-52",
        "frame-tag-hmac-bound-to-endpoint-direction-principal-epoch",
        Some(Obligation::Contain),
    ),
    (
        "P-E-53",
        "buffer-and-command-partitions-conserved",
        Some(Obligation::Resources),
    ),
    (
        "P-E-54",
        "nic-reference-pins-buffer-incarnation-not-extent",
        Some(Obligation::Custody),
    ),
    (
        "P-E-55",
        "cancel-and-deadline-keep-dma-custody-until-terminal",
        Some(Obligation::Custody),
    ),
    (
        "P-E-56",
        "retained-chunk-until-receipt-and-device-return",
        Some(Obligation::Custody),
    ),
    (
        "P-E-57",
        "lease-credits-and-engine-budget-accounting",
        Some(Obligation::Resources),
    ),
    (
        "P-E-58",
        "unproven-stop-retains-every-custody-share-and-charge",
        Some(Obligation::Resources),
    ),
    (
        "P-E-59",
        "funded-healthy-interval-restores-capacity-and-publishes-within-bound",
        Some(Obligation::Progress),
    ),
    (
        "P-E-60",
        "per-peer-request-share-conserved-held-while-draining",
        Some(Obligation::Resources),
    ),
    (
        "P-E-61",
        "failed-or-slow-peer-delays-no-healthy-peer",
        Some(Obligation::Isolation),
    ),
    (
        "P-E-62",
        "life-long-counters-independent-of-the-event-ring",
        None,
    ),
    (
        "P-E-63",
        "two-owners-share-no-engine-state-healthy-owner-serves",
        Some(Obligation::Isolation),
    ),
    ("P-N-42", "oracle-sound-on-bounded-histories", None),
    (
        "P-N-43",
        "inconclusive-on-bound-truncation-malformed-unresolved-poison",
        None,
    ),
    ("P-N-44", "expected-values-independent-of-production", None),
    (
        "P-N-45",
        "publication-label-immutable-content-identity",
        Some(Obligation::History),
    ),
    (
        "P-N-46",
        "acquisition-delivery-eligibility-separate-judgments",
        Some(Obligation::Bytes),
    ),
    (
        "P-N-47",
        "real-time-precedence-pending-retention-two-ordinals",
        Some(Obligation::History),
    ),
    (
        "P-N-48",
        "refusal-is-not-acknowledgment-unknown-outcomes-carry-nothing",
        Some(Obligation::History),
    ),
    (
        "P-N-49",
        "custody-per-resource-and-independent-totals",
        Some(Obligation::Custody),
    ),
    (
        "P-N-50",
        "write-completion-adds-no-durable-evidence",
        Some(Obligation::Restart),
    ),
    (
        "P-N-51",
        "conditional-recovery-rows-inconclusive",
        Some(Obligation::Restart),
    ),
    (
        "P-N-52",
        "controls-fail-through-oracle-and-verdicts-survive-panics",
        None,
    ),
    (
        "P-N-53",
        "progress-only-at-qualified-checkpoints",
        Some(Obligation::Progress),
    ),
    (
        "P-N-54",
        "lane-selection-exact-inventory-registry-and-full-execution",
        None,
    ),
    (
        "P-N-55",
        "first-failure-preserved-and-n-passes-mean-not-reproduced",
        None,
    ),
    ("P-N-56", "selected-ignored-test-executes", None),
    (
        "P-N-57",
        "build-once-resolve-one-executable-one-match",
        None,
    ),
    (
        "P-N-58",
        "qualified-native-runner-preflight-and-loom-bounds",
        None,
    ),
    (
        "P-N-59",
        "evidence-retained-on-failure-and-interruption",
        None,
    ),
    (
        "P-N-60",
        "stuck-request-stages-within-retry-bound",
        Some(Obligation::Progress),
    ),
];

/// The upload records PUT coverage reuses, each proposed until the registry
/// owner accepts it; every one appears in at least one obligation's coverage.
pub(crate) static PUT_RECORDS: &[(&str, &str)] = &[
    ("P-N-111", "permission-then-authority-before-any-grant"),
    ("P-N-112", "begin-refusal-owns-nothing-permanent-typed"),
    (
        "P-N-113",
        "prepare-admission-deadline-and-authority-lifetime",
    ),
    ("P-N-114", "ready-after-priming-and-empty-object"),
    ("P-N-115", "receipt-and-grant-conserved-across-wire"),
    ("P-N-116", "duplicate-exact-or-digest-conflict-terminates"),
    ("P-N-117", "write-debited-units-conserved-readiness"),
    ("P-N-118", "publish-once-row-before-result-poison-unknown"),
    (
        "P-N-119",
        "logical-failure-keeps-fill-until-outstanding-zero",
    ),
    (
        "P-N-120",
        "identity-checks-before-mutation-predecessors-inert",
    ),
    ("P-N-121", "retained-terminal-window-and-expired-evidence"),
    ("P-N-122", "session-retirement-ends-evidence-keeps-custody"),
    (
        "P-N-123",
        "control-and-cleanup-progress-under-body-pressure",
    ),
    ("P-N-124", "one-receive-path-peer-and-endpoint-ceilings"),
    ("P-N-125", "put-capacity-charged-once-refused-at-start"),
    ("P-N-126", "duplicate-replays-per-kind-fingerprint"),
    ("P-N-127", "close-lost-volume-stalled-drain-blockers"),
    ("P-N-128", "one-wire-identity-one-operation-slot-reuse"),
    ("P-N-129", "canonical-full-body-mac"),
    ("P-N-130", "known-not-started-unknown-abandon-and-cancel"),
    ("P-N-131", "authority-prepare-input-and-source-slots"),
    ("P-N-132", "slot-custody-initialized-range-and-resend"),
    ("P-N-133", "client-send-order-stall-recovery-and-holes"),
    ("P-N-134", "full-receipt-not-success-outcome-meanings"),
];

/// PUT subclaims no record covers, each named by a descriptive alias for the
/// registry owner. Each alias maps to the obligation whose checker judges
/// the subclaim; `None` marks a checker-coverage gap.
pub(crate) static HANDOFF_ALIASES: &[(&str, &str, Option<Obligation>)] = &[
    (
        "put-failure-preserves-incumbent-publication",
        "A failed or not-started upload preserves any incumbent or concurrent publication of its key.",
        None,
    ),
    (
        "put-historical-success-never-revives",
        "A historical Published replays after invalidation without making the covered version eligible again.",
        Some(Obligation::History),
    ),
    (
        "put-receipt-adds-no-durable-evidence",
        "A receipt ACK, including a full receipt, adds no persistence evidence.",
        Some(Obligation::Restart),
    ),
    (
        "put-unknown-releases-unretained-source",
        "An Unknown attempt keeps its request identity until a matching terminal or an abandonment and drain, while source slots whose retention and NIC custody ended return.",
        Some(Obligation::Custody),
    ),
];

impl Obligation {
    pub(crate) const ALL: [Self; 8] = [
        Self::Bytes,
        Self::History,
        Self::Custody,
        Self::Resources,
        Self::Restart,
        Self::Progress,
        Self::Isolation,
        Self::Contain,
    ];

    pub(crate) const fn spec(self) -> &'static ObligationSpec {
        &OBLIGATIONS[self as usize]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Family {
    E,
    N,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PropertyId {
    pub(crate) family: Family,
    pub(crate) number: u16,
}

impl PropertyId {
    /// Parses `P-E-NN`, `P-N-NN`, or either prefix with a three-digit number
    /// without a leading zero; zero and every other form return `None`.
    pub(crate) fn parse(text: &str) -> Option<Self> {
        let (family, digits) = match (text.strip_prefix("P-E-"), text.strip_prefix("P-N-")) {
            (Some(rest), _) => (Family::E, rest),
            (None, Some(rest)) => (Family::N, rest),
            (None, None) => return None,
        };
        let three_digits = digits.len() == 3 && !digits.starts_with('0');
        if !(digits.len() == 2 || three_digits) || !digits.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let number: u16 = digits.parse().ok()?;
        (number > 0).then_some(Self { family, number })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CheckerLocation {
    PerKey,
    Global,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EvidenceLabel {
    Live,
    Abstract,
    Qualified,
}

#[derive(Debug)]
pub(crate) struct ObligationSpec {
    pub(crate) obligation: Obligation,
    pub(crate) alias: &'static str,
    pub(crate) rule: &'static str,
    pub(crate) operation_path: &'static str,
    pub(crate) checkpoint: &'static str,
    pub(crate) permitted: &'static [&'static str],
    pub(crate) forbidden: &'static [&'static str],
    pub(crate) premises: &'static [&'static str],
    pub(crate) coverage: &'static [&'static str],
    pub(crate) fault_witness: &'static [&'static str],
    pub(crate) checker: CheckerLocation,
    pub(crate) counterexample_owner: &'static str,
    /// The evidence classes the obligation is judged from.
    pub(crate) evidence: &'static [EvidenceLabel],
}

pub(crate) static OBLIGATIONS: [ObligationSpec; 8] = [
    ObligationSpec {
        obligation: Obligation::Bytes,
        alias: "O-BYTES",
        rule: "A successful complete read, including GET after a visible Published PUT, returns its allowed full key, label, lengths and exact bytes; a later damaged chunk may follow an exact verified prefix and never yields a successful whole read or exposes failed or later bytes.",
        operation_path: "lookup, acquire, volume read, chunk hand-off, terminal status, and GET after a remote PUT's publication",
        checkpoint: "the delivery's terminal outcome, with its owned payload copy",
        permitted: &[
            "Complete with the acquired label's exact bytes and lengths",
            "an exact verified prefix followed by a typed failure",
            "zero bytes and a header mismatch for a colliding candidate",
            "a GET after a visible Published PUT returning the uploaded label's exact bytes",
        ],
        forbidden: &[
            "Complete with bytes of another key, session, allocation or label",
            "bytes from a failed chunk or any later chunk",
            "a successful whole-read status after a damaged chunk",
        ],
        premises: &["one key", "one acquired label", "one episode"],
        coverage: &["P-E-12", "P-N-11", "P-N-46", "P-N-118", "P-N-134"],
        fault_witness: &[
            "wrong key",
            "wrong session",
            "wrong allocation",
            "header damage",
            "later-chunk damage",
            "remote PUT followed by an exact GET",
        ],
        checker: CheckerLocation::PerKey,
        counterexample_owner: "per-key golden scenario 7, damaged later chunk",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::History,
        alias: "O-HISTORY",
        rule: "Acquisitions have a legal order that sorts operations by tenure tag and by real time inside one tenure, between operations the history's ordinals order; a hit returns a published, uncovered version with its exact bytes before its deadline in its tenure's clock, a deadline of another tenure's clock counted as unjudged, and only an acknowledged or landed invalidation makes a version permanently ineligible, in its tenure and every later one; a hit after a recorded removal of its label in the same tenure fails unless a recorded restore of that label follows the removal; each client accepts only tags at or above its per-shard high-water, which never falls; a pre-removal right finishes its immutable data; refusals are distinct from acknowledged effects; a PUT outcome describes its attempt only, Unknown keeps publication open, and a failed or not-started upload never publishes its label.",
        operation_path: "fill, publish, replace, lookup, invalidate, expire, release, and a remote PUT's begin, authority, receipt, publication, result, retry and abandonment",
        checkpoint: "every lookup response, against the eligible mapping at its permitted point",
        permitted: &[
            "old-right delivery of the acquired label after invalidation",
            "Missing after an acknowledged invalidation",
            "old, new or Contended for a lookup overlapping replacement",
            "Expired at whole-second deadline equality",
            "an Unknown attempt with or without its publication",
            "a historical Published replayed after invalidation, replacement, expiry or eviction",
            "an incumbent or concurrent publication surviving a failed or not-started upload",
            "a miss at any point, with or without a restart",
            "a hit of an older uncovered version, after a replacement or a restart",
            "a deposed tenure's hit of a version its successor covered, for a client below the successor",
            "a restarted client accepting a deposed tenure's response",
        ],
        forbidden: &[
            "a covered version from the acknowledging tenure, invoked after the acknowledgment, or from any later tenure",
            "a hit on a write-complete unpublished fill",
            "a tenure serving a version only a later tenure published",
            "a client accepting a tag below its high-water, or a recorded high-water that falls",
            "a hit after a recorded removal of its label in the same tenure with no recorded restore of that label between",
            "a recorded restore of a covered version or from a checkpoint the store did not name",
            "a refusal treated as an acknowledgment",
            "Published at a full receipt",
            "a second publication of one attempt",
        ],
        premises: &[
            "one key",
            "at most two labels",
            "at most two holders",
            "one episode",
            "one shard",
        ],
        coverage: &[
            "P-E-02", "P-E-04", "P-E-05", "P-E-06", "P-E-07", "P-E-08", "P-E-09", "P-E-13",
            "P-E-21", "P-N-07", "P-N-12", "P-N-13", "P-N-42", "P-N-45", "P-N-47", "P-N-48",
            "P-N-118", "P-N-120", "P-N-121", "P-N-122", "P-N-126", "P-N-130", "P-N-134",
        ],
        fault_witness: &[
            "overlapping lookup, publication and invalidation",
            "unpublished fill",
            "invalidation between receive and publish",
            "expiry equality",
            "fingerprint collision",
            "lost RESULT then a matching retry",
            "a changed retry",
            "a tenure change with a live session",
            "client crash and restart",
            "an invalidation of unknown outcome",
            "store outage",
        ],
        checker: CheckerLocation::PerKey,
        counterexample_owner: "per-key stale-version control and the premature-Published-at-receipt PUT control",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::Custody,
        alias: "O-CUSTODY",
        rule: "No writable extent overlaps or is reused while an extent right or grace interval remains; a buffer stays immutable and unavailable while storage or the NIC holds that incarnation; stale tokens and duplicate returns never affect a successor; a client source slot stays immutable and unavailable while retransmission retention or NIC custody of its fragment remains.",
        operation_path: "extent claim and return, buffer take and free, command submit and terminal, NIC return, and a client source slot's supply, receipt, decision and NIC return",
        checkpoint: "stopped fixture action boundaries",
        permitted: &[
            "disk reuse after the extent right and grace obligations end",
            "a counted, ineffective duplicate or reordered return",
            "retransmission retention ended by a receipt base past the fragment, a decision or a cancellation while NIC custody stays",
        ],
        forbidden: &[
            "overlapping writable extents",
            "reuse of a held response-buffer incarnation",
            "a stale token changing a reused slot",
            "source slot reuse while retransmission retention or NIC custody remains",
            "retransmission retention ended by a receipt mask bit alone",
        ],
        premises: &["one resource", "one incarnation", "one episode"],
        coverage: &[
            "P-E-08", "P-E-10", "P-E-17", "P-E-19", "P-N-09", "P-E-53", "P-E-54", "P-E-55",
            "P-E-56", "P-N-49", "P-N-119", "P-N-127", "P-N-132",
        ],
        fault_witness: &[
            "held reader across retirement",
            "cancelled command",
            "delayed NIC return",
            "slot reuse",
            "receipt before NIC return and NIC return before receipt",
            "short write, cancel or invalidation with outstanding writes",
        ],
        checker: CheckerLocation::Global,
        counterexample_owner: "global early-reuse control and the source-reuse-during-NIC-custody PUT control",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::Resources,
        alias: "O-RESOURCES",
        rule: "Extents, slots, buffers, commands, credits and funded work are counted independently; cancellation releases no DMA custody; an unproven stop retains ownership and charges; a released healthy checkpoint returns what its obligations no longer justify, engine budget bytes excepted.",
        operation_path: "every take and return of a counted resource, and each production report",
        checkpoint: "stopped boundaries and equivalent fully released healthy checkpoints",
        permitted: &[
            "charges retained after an unproven stop",
            "engine budget charge kept after release",
        ],
        forbidden: &[
            "an independent count disagreeing with a production report",
            "a slot, extent, buffer, credit or request share missing at a released checkpoint",
            "a duplicate fragment growing credit",
        ],
        premises: &["one resource kind", "one checkpoint", "one episode"],
        coverage: &[
            "P-E-10", "P-E-17", "P-E-18", "P-E-22", "P-N-09", "P-E-53", "P-E-57", "P-E-58",
            "P-E-60", "P-N-49", "P-N-115", "P-N-117", "P-N-124", "P-N-125", "P-N-128",
        ],
        fault_witness: &[
            "cancel then late terminal",
            "refusal before submit",
            "saturated pool",
            "unproven stop",
            "checkpoint leak",
            "duplicate fragment and credit",
        ],
        checker: CheckerLocation::Global,
        counterexample_owner: "global leaked-capacity control and the duplicate-credit-growth PUT control",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::Restart,
        alias: "O-RESTART",
        rule: "A restart starts a new tenure; an activation naming a retained cut restores every entry of its retained set outside the damage set, and an activation naming no cut, or a cut no capture recorded, after a capture replaces the retained cut with a cold start, which only whole-volume damage recorded before the tenure's first lookup permits; a recovered candidate needs separate persistence, identity, ownership, freshness and expiry evidence, abstract under a hypothesis or qualified under a profile, recorded before the latest restart its lookup follows; recovery-safe exclusions survive every later restart and admission; live acknowledgment establishes no persistence.",
        operation_path: "abstract or qualified persistence, admission and restart rows under a hypothesis or a qualified profile",
        checkpoint: "each recovered lookup, at the latest restart before it",
        permitted: &[
            "a miss after cold restart",
            "a withheld recovered candidate missing freshness or clock authority",
            "B or a miss after stated exclusion evidence, under its hypothesis or any qualified profile",
        ],
        forbidden: &[
            "durable eligibility derived from a write completion",
            "durable eligibility derived from a receipt ACK",
            "admission with fewer than its four facts",
            "fresh A after a recovery-safe exclusion and restart",
            "readmission of a mapping a recovery-safe exclusion excluded",
            "a retained entry outside every damage set lost on host loss, even when every lookup misses",
            "a recovery-time stale refusal standing in for a recorded eviction",
            "a restore of an entry its cut never captured",
            "a cold start after a capture without whole-volume damage before the first lookup",
            "an activation naming a cut no capture recorded, after a capture, without whole-volume damage before the first lookup",
            "admission or recovery derived from a qualified fact under a mismatched profile, identity, boundary or incarnation, or recorded before its predecessors",
        ],
        premises: &[
            "one key",
            "one shard",
            "one hypothesis, or one qualified profile and identity, with qualified exclusions, and the restarts that set the writing incarnation, counted across qualified profiles and identities",
            "one qualified persistence row per command within a profile, identity and incarnation",
            "one episode",
        ],
        coverage: &[
            "P-E-11", "P-E-15", "P-N-03", "P-N-04", "P-N-05", "P-N-06", "P-N-10", "P-N-11",
            "P-N-13", "P-N-50", "P-N-51",
        ],
        fault_witness: &[
            "prepopulated device",
            "abstract exclusion then restart",
            "missing freshness or clock evidence",
            "lost successor",
        ],
        checker: CheckerLocation::PerKey,
        counterexample_owner: "per-key completion-as-durability control",
        evidence: &[EvidenceLabel::Abstract, EvidenceLabel::Qualified],
    },
    ObligationSpec {
        obligation: Obligation::Progress,
        alias: "O-PROGRESS",
        rule: "In a funded healthy interval with space and holders released, accepted complete fills publish and produce exact hits; funded reclamation completes within the fixture's bound; a live request with empty queues and no outstanding command stages a frame within the declared retry bound; always-miss or always-reject fails the interval.",
        operation_path: "fill, publish, lookup and read across a funded maintenance interval",
        checkpoint: "qualified checkpoints only: conflicts stopped, budget and space established, holders released, device healed",
        permitted: &["cold restart misses", "authority withholding misses"],
        forbidden: &[
            "always-miss across a qualified interval",
            "always-reject admission across a qualified interval",
            "a live request with empty queues and no outstanding command that stages no frame within the retry bound",
        ],
        premises: &["one funded interval", "one episode"],
        coverage: &[
            "P-E-18", "P-E-22", "P-N-02", "P-E-59", "P-N-53", "P-N-60", "P-N-123", "P-N-133",
        ],
        fault_witness: &[
            "fill, publication and read plus a healed reclaim suffix",
            "a live request with empty queues and no outstanding command across the retry bound",
            "healthy GET progress under upload pressure",
        ],
        checker: CheckerLocation::Global,
        counterexample_owner: "global always-miss and retention-off-by-one controls",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::Isolation,
        alias: "O-ISOLATION",
        rule: "A failed owner retains only bounded attributable custody while a healthy independent owner serves exact bytes; reclamation is not demanded without stop proof.",
        operation_path: "two owners over separate storages, one in an unproven stop, one serving a GET",
        checkpoint: "isolated checkpoints naming the failed owner's custody; healthy checkpoints for the healthy one",
        permitted: &[
            "the failed owner's census held at its pre-stop value",
            "arena release refused for the failed owner",
        ],
        forbidden: &[
            "unsafe return of the failed owner's custody",
            "healthy-peer starvation past the fixture bound",
        ],
        premises: &["two owners", "one healthy request", "one episode"],
        coverage: &[
            "P-E-17", "P-E-22", "P-E-58", "P-E-61", "P-E-63", "P-N-123", "P-N-124",
        ],
        fault_witness: &[
            "two owners",
            "one unproven stop with held work",
            "one healthy request",
        ],
        checker: CheckerLocation::Global,
        counterexample_owner: "endpoint two-owner scenario and its routing control",
        evidence: &[EvidenceLabel::Live],
    },
    ObligationSpec {
        obligation: Obligation::Contain,
        alias: "O-CONTAIN",
        rule: "Damage and unauthorized state produce the typed rejection or withholding before prohibited bytes or effects; detection never erases an admitted-content corruption failure.",
        operation_path: "record header and chunk verification, frame parse and authentication, abstract admission",
        checkpoint: "the first typed rejection, before any prohibited byte",
        permitted: &[
            "a typed rejection after damage",
            "withholding without admission evidence",
        ],
        forbidden: &[
            "prohibited bytes before the rejection",
            "a detected later corruption clearing an earlier Complete status",
        ],
        premises: &["one key or frame", "one episode"],
        coverage: &[
            "P-E-12", "P-N-03", "P-N-04", "P-N-11", "P-E-45", "P-E-46", "P-E-47", "P-E-48",
            "P-E-49", "P-E-50", "P-E-51", "P-E-52", "P-N-46", "P-N-111", "P-N-112", "P-N-113",
            "P-N-114", "P-N-115", "P-N-116", "P-N-120", "P-N-129", "P-N-131",
        ],
        fault_witness: &[
            "identity mismatch",
            "frame tamper",
            "damaged later chunk",
            "missing admission evidence",
            "a PUT body tampered with its crc repaired",
        ],
        checker: CheckerLocation::PerKey,
        counterexample_owner: "per-key golden scenario 7 and the pinned frame vectors",
        evidence: &[EvidenceLabel::Live],
    },
];
