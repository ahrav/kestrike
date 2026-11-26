//! Configuration pair coverage: the committed constrained pairwise rows over
//! the configuration factors, an enumerator of the factor model that
//! shares no code with the production validators, and the production start
//! of an owner over every row.
//!
//! The model and its rows live in `verification/pairs`. The enumerator walks
//! every factor combination, derives each combination's full
//! configuration by its own arithmetic and judges it against every
//! configuration constraint, so a pair counts as satisfiable only when some
//! combination holding it passes them all. Coverage holds when every
//! satisfiable pair appears in an admitted row; removing a row that alone
//! covers a pair makes the check fail and name that pair. Conformance is the
//! production side's: storage, index, arena and volume attach validation and
//! the owner's start accept every row's derived configuration, and refuse the
//! one combination the model constrains away.

use std::collections::{BTreeMap, BTreeSet};

use crate::index::{IndexConfig, Ratio, ShardLimits};
use crate::storage::owner_fixture::{
    Device, Fault, TestPlatform, attach_shaped, publish, read_tokens, storage_from_configs,
    work_bound,
};
use crate::storage::{
    AttachError, BufferArena, BufferConfig, EngineBudget, HugepageSize, IO_UNIT, NodeMask,
    PoolKind, PoolSpec, RecordConfig, Storage, StorageConfig, VolumeConfig, VolumeWatermarks,
};

use super::datagram::MAX_DATAGRAM;
use super::fetch::{Outcome, Releases};
use super::frame::Status;
use super::link::{Faults, NetReport, network};
use super::owner::{Bundle, Keys, Owner, OwnerConfig, OwnerError};
use super::owner_tests::{
    Mux, OWNER, PRINCIPALS, client, collect, drive, entries, hold_next_read, key, open, payload,
    pool,
};
use super::put::PutConfig;
use super::serve::ServeConfig;
use super::session::Caps;

const MODEL: &str = include_str!("../../../../verification/pairs/model.pict");
const ROWS: &str = include_str!("../../../../verification/pairs/rows.tsv");

/// The factor table: each factor's model name and its levels, in model order.
pub(super) const FACTORS: [(&str, &[&str]); 11] = [
    ("VolumeUnits", &["19", "63", "64", "65", "129"]),
    ("StorageSlots", &["4", "16", "33"]),
    ("ChunkBytes", &["4096", "8192", "16384"]),
    ("SpanBytes", &["8192", "16384"]),
    ("Depth", &["4", "8"]),
    ("RequestSlots", &["2", "4"]),
    ("ReadAhead", &["0", "1"]),
    ("Principals", &["1", "2"]),
    ("GetReserve", &["1", "2"]),
    ("BodyCap", &["200", "32768"]),
    (
        "FaultProfile",
        &["healthy", "gray", "error-omission", "hostile-media"],
    ),
];

/// One combination: the level index each factor takes, in [`FACTORS`] order.
pub(super) type Assignment = [usize; 11];

/// One factor-level pair: two factors in increasing order and the level
/// index each takes.
type Pair = (usize, usize, usize, usize);

/// Factor positions in [`FACTORS`] and in an [`Assignment`].
const UNITS: usize = 0;
const SLOTS: usize = 1;
pub(super) const CHUNK: usize = 2;
pub(super) const SPAN: usize = 3;
const DEPTH: usize = 4;
const REQUESTS: usize = 5;
const READ_AHEAD: usize = 6;
const PRINCIPALS_PER_OWNER: usize = 7;
const GET_RESERVE: usize = 8;
const BODY: usize = 9;
pub(super) const FAULTS: usize = 10;

/// Level positions the constrained pair names: a 16-KiB chunk and an 8-KiB
/// span.
pub(super) const CHUNK_16K: usize = 2;
pub(super) const SPAN_8K: usize = 0;

/// Metadata bytes every derived configuration admits.
const METADATA_CAP: u64 = 8;

/// Bytes a row's object leaves below its unit charge for the record header.
pub(super) const HEADER_SLACK: usize = 300;

/// Table slots every derived volume reserves for metadata commands, beside the derived depth's read and write slots.
const METADATA_COMMANDS: u64 = 1;

/// The table depth a derived volume attaches with: its read and write slots plus the metadata share.
pub(super) fn table_depth(derived: &Derived) -> u16 {
    (derived.depth + METADATA_COMMANDS) as u16
}

/// The owner's PUT copy room holds two whole datagrams at every level.
const _: () = assert!((1 << 16) >= 2 * MAX_DATAGRAM);

/// A combination's full configuration, derived from its factor levels by
/// this module's own arithmetic. The values the factors leave free are
/// chosen so that every constraint over them alone holds; a combination is
/// then satisfiable exactly when this derivation passes every constraint,
/// and [`every_constraint_refuses_a_derivation_that_breaks_it`] keeps each
/// constraint live.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Derived {
    pub(super) units: u64,
    pub(super) slots: u64,
    pub(super) chunk: u64,
    pub(super) span: u64,
    pub(super) depth: u64,
    pub(super) request_slots: u64,
    pub(super) read_ahead: u64,
    pub(super) principals: u64,
    pub(super) body_cap: u64,
    pub(super) profile: usize,
    /// Header bytes of the largest admitted record.
    pub(super) header_max: u64,
    /// Units the largest admitted record charges, `Cmax`.
    pub(super) record_units: u64,
    /// The clean reserve `R`.
    pub(super) reserve: u64,
    /// The retired allowance `T`.
    pub(super) retired_units: u64,
    /// The headroom target `H`, the structural floor `R + puts × Cmax + T`.
    pub(super) low_units: u64,
    pub(super) min_free_slots: u64,
    /// The one index shard's visible limit.
    pub(super) visible: u64,
    pub(super) read_ops: u64,
    pub(super) read_commands: u64,
    pub(super) response_buffers: u64,
    pub(super) peer_requests: u64,
    /// Request slots the PUT caps leave to GETs.
    pub(super) get_reserve: u64,
    /// Slots of each peer's share the per-peer PUT cap leaves to that peer's GETs.
    pub(super) peer_get_reserve: u64,
    /// Fill records on the one index shard, which bound the live PUTs.
    pub(super) fill_records: u64,
    /// The owner's datagram batch.
    pub(super) batch: u64,
    /// The receive packet pool's buffers and its control reserve.
    pub(super) packets: u64,
    pub(super) packet_reserve: u64,
    /// Packets each simulated link keeps posted for receive.
    pub(super) rx_ring: u64,
    pub(super) puts: u64,
    pub(super) peer_puts: u64,
    pub(super) put_window: u64,
    pub(super) put_command_bytes: u64,
}

/// The value of factor `factor` at level `level`, for a numeric factor.
fn value(factor: usize, level: usize) -> u64 {
    FACTORS[factor].1[level].parse().expect("a numeric level")
}

impl Derived {
    fn put_room(request_slots: u64, get_reserve: u64) -> u64 {
        2.min(request_slots - get_reserve)
    }
    fn header_bytes(payload: u64, chunk: u64) -> u64 {
        108 + 4 * (payload.div_ceil(chunk) + 1)
    }

    pub(super) fn of(assignment: &Assignment) -> Self {
        let get = |factor| value(factor, assignment[factor]);
        let (chunk, body_cap) = (get(CHUNK), get(BODY));
        let payload = METADATA_CAP + body_cap;
        let header_max = Self::header_bytes(payload, chunk);
        let record_units = (header_max + payload).div_ceil(IO_UNIT as u64);
        let (depth, request_slots) = (get(DEPTH), get(REQUESTS));
        let (read_ahead, principals) = (get(READ_AHEAD), get(PRINCIPALS_PER_OWNER));
        let reserve = 2;
        let peer_requests = request_slots / principals;
        let (get_reserve, peer_get_reserve) = (get(GET_RESERVE), 1);
        let (units, slots) = (get(UNITS), get(SLOTS));
        // The most PUTs, up to two, whose floor at an allowance of one
        // largest charge leaves a unit above it for the published object.
        let puts = (0..=Self::put_room(request_slots, get_reserve))
            .rev()
            .find(|&puts| reserve + (puts + 1) * record_units < units)
            .unwrap_or(0);
        // The allowance is every slot's largest charge, which no retired
        // backlog passes, within half the units the floor's other terms and
        // the published object leave, and at least one largest charge.
        let room = units - 1 - reserve - puts * record_units;
        let retired_units = (slots * record_units).min(room / 2).max(record_units);
        // The peer cap also fits an even split of the global cap, so the peers' caps sum within it.
        let peer_puts = 1
            .min(peer_requests - peer_get_reserve)
            .min(puts / principals);
        Self {
            units,
            slots,
            chunk,
            span: get(SPAN),
            depth,
            request_slots,
            read_ahead,
            principals,
            body_cap,
            profile: assignment[FAULTS],
            header_max,
            record_units,
            reserve,
            retired_units,
            low_units: reserve + puts * record_units + retired_units,
            min_free_slots: 1,
            visible: get(SLOTS),
            read_ops: request_slots,
            read_commands: depth / 2,
            response_buffers: request_slots * (2 + read_ahead),
            peer_requests,
            get_reserve,
            peer_get_reserve,
            fill_records: 2,
            batch: 8,
            packets: 32,
            packet_reserve: 8,
            rx_ring: 0,
            puts,
            peer_puts,
            put_window: 4,
            put_command_bytes: 1 << 20,
        }
    }

    /// The empty volume's placeable units, as
    /// [`ValidatedConfig::placeable_ceiling`](crate::storage::ValidatedConfig::placeable_ceiling)
    /// counts them.
    fn placeable_ceiling(&self) -> u64 {
        self.units - self.units % self.record_units
    }

    /// Every configuration constraint by name, with whether it holds.
    fn checks(&self) -> [(&'static str, bool); 16] {
        let write_cap = self.depth.saturating_sub(self.read_commands);
        [
            (
                "reserve, largest record and headroom fit the volume",
                self.reserve + self.record_units <= self.low_units
                    && self.low_units <= self.placeable_ceiling(),
            ),
            (
                FLOOR,
                self.puts == 0
                    || self.low_units
                        >= self.reserve + self.puts * self.record_units + self.retired_units,
            ),
            (ALLOWANCE, self.retired_units >= self.record_units),
            (
                "free-slot threshold below the slots",
                0 < self.min_free_slots && self.min_free_slots < self.slots,
            ),
            (
                "shard visible limits sum within the slots",
                self.visible <= self.slots,
            ),
            (
                "span at least a fragment and a chunk",
                self.span >= 8192 && self.span >= self.chunk,
            ),
            (
                "header windows fit the span",
                (self.header_max / self.chunk + 1) * self.chunk <= self.span
                    && self.header_max <= self.span,
            ),
            (
                "chunk divides the receive-write buffer",
                self.span.is_multiple_of(self.chunk),
            ),
            (
                "read commands below the table depth",
                1 <= self.read_commands && self.read_commands < self.depth,
            ),
            (
                "read operations cover the request slots",
                self.read_ops >= self.request_slots,
            ),
            (
                "response buffers cover two per request and its read-ahead",
                self.response_buffers >= self.request_slots * (2 + self.read_ahead),
            ),
            (
                "peer shares fit the request slots",
                self.peer_requests >= 1
                    && self.principals * self.peer_requests <= self.request_slots,
            ),
            ("batch of at least two", self.batch >= 2),
            (
                "control reserve covers the batch and the receive ring",
                self.batch + self.rx_ring <= self.packet_reserve,
            ),
            (
                "PUT fits its peers, slots, fills, data room and write commands",
                self.principals * self.peer_puts <= self.puts
                    && self.puts <= self.request_slots
                    && self.puts <= self.fill_records
                    && self.puts * self.put_window <= self.packets - self.packet_reserve
                    && write_cap >= self.principals
                    && self.put_command_bytes >= self.span,
            ),
            (
                "GET reserves are positive and leave the PUT caps their slots",
                self.get_reserve >= 1
                    && self.peer_get_reserve >= 1
                    && (self.request_slots.checked_sub(self.get_reserve))
                        .is_some_and(|room| self.puts <= room)
                    && (self.peer_requests.checked_sub(self.peer_get_reserve))
                        .is_some_and(|room| self.peer_puts <= room),
            ),
        ]
    }

    /// The configuration constraints this configuration breaks, by name.
    pub(super) fn violations(&self) -> Vec<&'static str> {
        self.checks()
            .into_iter()
            .filter_map(|(name, holds)| (!holds).then_some(name))
            .collect()
    }
}

/// Every combination of factor levels, in lexicographic level order.
fn combinations() -> Vec<Assignment> {
    let mut all = vec![[0; 11]];
    for (factor, (_, levels)) in FACTORS.iter().enumerate() {
        all = all
            .into_iter()
            .flat_map(|prefix| {
                (0..levels.len()).map(move |level| {
                    let mut next = prefix;
                    next[factor] = level;
                    next
                })
            })
            .collect();
    }
    all
}

/// The pairs `assignment` holds.
fn pairs(assignment: &Assignment) -> impl Iterator<Item = Pair> + '_ {
    (0..11).flat_map(move |a| (a + 1..11).map(move |b| (a, assignment[a], b, assignment[b])))
}

/// The pairs some admitted combination holds.
fn satisfiable_pairs() -> BTreeSet<Pair> {
    combinations()
        .iter()
        .filter(|assignment| Derived::of(assignment).violations().is_empty())
        .flat_map(|assignment| pairs(assignment).collect::<Vec<_>>())
        .collect()
}

/// The satisfiable pairs no admitted row of `rows` holds; a row the model
/// refuses covers nothing.
fn uncovered(rows: &[Assignment], satisfiable: &BTreeSet<Pair>) -> Vec<Pair> {
    let covered: BTreeSet<Pair> = rows
        .iter()
        .filter(|row| Derived::of(row).violations().is_empty())
        .flat_map(|row| pairs(row).collect::<Vec<_>>())
        .collect();
    satisfiable.difference(&covered).copied().collect()
}

/// The committed rows as level indices, after checking the header names the
/// factors in model order.
pub(super) fn rows() -> Vec<Assignment> {
    let mut lines = ROWS.lines();
    let header: Vec<&str> = lines.next().expect("a header").split('\t').collect();
    let names: Vec<&str> = FACTORS.iter().map(|(name, _)| *name).collect();
    assert_eq!(header, names, "the row header names the factors in order");
    lines
        .map(|line| {
            let cells: Vec<&str> = line.split('\t').collect();
            assert_eq!(cells.len(), 11, "row {line:?}");
            let mut row = [0; 11];
            for (factor, cell) in cells.iter().enumerate() {
                row[factor] = FACTORS[factor]
                    .1
                    .iter()
                    .position(|level| level == cell)
                    .unwrap_or_else(|| panic!("{cell:?} is no level of {}", FACTORS[factor].0));
            }
            row
        })
        .collect()
}

fn show(pair: Pair) -> String {
    let (a, la, b, lb) = pair;
    format!(
        "{}={} with {}={}",
        FACTORS[a].0, FACTORS[a].1[la], FACTORS[b].0, FACTORS[b].1[lb]
    )
}

/// The model file declares exactly the factor table, level for level, and
/// one constraint: a 16-KiB chunk needs a 16-KiB span.
#[test]
fn the_model_declares_the_factor_table_and_its_one_constraint() {
    let content: Vec<&str> = MODEL
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .collect();
    let (parameters, constraints): (Vec<&str>, Vec<&str>) =
        content.iter().partition(|line| !line.starts_with("IF "));
    let declared: Vec<(String, Vec<String>)> = parameters
        .iter()
        .map(|line| {
            let (name, levels) = line.split_once(':').expect("a parameter line");
            let levels = levels.split(',').map(|level| level.trim().to_owned());
            (name.trim().to_owned(), levels.collect())
        })
        .collect();
    let expected: Vec<(String, Vec<String>)> = FACTORS
        .iter()
        .map(|(name, levels)| {
            let levels = levels.iter().map(|level| (*level).to_owned());
            ((*name).to_owned(), levels.collect())
        })
        .collect();
    assert_eq!(declared, expected);
    assert_eq!(
        constraints,
        ["IF [ChunkBytes] = 16384 THEN [SpanBytes] = 16384;"]
    );
}

/// The enumerator judges all 23,040 combinations: exactly the 3,840 that pair
/// a 16-KiB chunk with an 8-KiB span break a constraint, and every committed
/// row is admitted and together they cover every satisfiable pair.
#[test]
fn the_rows_cover_every_satisfiable_pair_over_the_whole_product() {
    let all = combinations();
    assert_eq!(all.len(), 23_040);
    let refused: Vec<&Assignment> = all
        .iter()
        .filter(|assignment| !Derived::of(assignment).violations().is_empty())
        .collect();
    for assignment in &all {
        let d = Derived::of(assignment);
        if d.puts < Derived::put_room(d.request_slots, d.get_reserve) {
            assert!(
                d.reserve + (d.puts + 2) * d.record_units >= d.units,
                "a PUT cap the floor lowered admits one more: {assignment:?}"
            );
        }
    }
    assert_eq!(refused.len(), 3_840);
    for assignment in &refused {
        assert_eq!(
            (assignment[CHUNK], assignment[SPAN]),
            (CHUNK_16K, SPAN_8K),
            "{assignment:?}"
        );
        assert_eq!(
            Derived::of(assignment).violations(),
            [
                "span at least a fragment and a chunk",
                "header windows fit the span",
                "chunk divides the receive-write buffer",
            ]
        );
    }
    let satisfiable = satisfiable_pairs();
    let product: usize = (0..11)
        .flat_map(|a| (a + 1..11).map(move |b| FACTORS[a].1.len() * FACTORS[b].1.len()))
        .sum();
    assert_eq!(satisfiable.len(), product - 1);
    assert!(!satisfiable.contains(&(CHUNK, CHUNK_16K, SPAN, SPAN_8K)));
    let rows = rows();
    assert_eq!(rows.len(), 21, "the model header's row count");
    for row in &rows {
        assert_eq!(Derived::of(row).violations(), Vec::<&str>::new(), "{row:?}");
    }
    let derived: Vec<Derived> = rows.iter().map(Derived::of).collect();
    assert!(
        derived.iter().any(|d| d.peer_puts == 0 && d.puts > 0),
        "a row derives a zero peer PUT cap beside a positive global cap"
    );
    assert!(
        derived
            .iter()
            .any(|d| d.get_reserve == d.request_slots && d.puts == 0),
        "a row reserves every request slot for GETs"
    );
    assert!(
        derived
            .iter()
            .any(|d| d.puts < Derived::put_room(d.request_slots, d.get_reserve)),
        "a row's one-charge floor lowers its PUT cap below its slot room"
    );
    let missing: Vec<String> = uncovered(&rows, &satisfiable)
        .into_iter()
        .map(show)
        .collect();
    assert_eq!(missing, Vec::<String>::new());
}

/// Each row that alone covers some pair is load-bearing: the rows without it
/// fail the coverage check, which names exactly the pairs only it held. A
/// row the model refuses covers nothing, so substituting one fails too.
#[test]
fn removing_a_sole_covering_row_fails_coverage_and_names_its_pairs() {
    let (rows, satisfiable) = (rows(), satisfiable_pairs());
    let mut holders: BTreeMap<Pair, Vec<usize>> = BTreeMap::new();
    for (index, row) in rows.iter().enumerate() {
        for pair in pairs(row) {
            holders.entry(pair).or_default().push(index);
        }
    }
    let mut sole: BTreeMap<usize, Vec<Pair>> = BTreeMap::new();
    for (pair, rows) in &holders {
        if let [only] = rows[..] {
            sole.entry(only).or_default().push(*pair);
        }
    }
    assert!(!sole.is_empty(), "no row alone covers a pair");
    for (index, only) in &sole {
        let mut fewer = rows.clone();
        fewer.remove(*index);
        assert_eq!(&uncovered(&fewer, &satisfiable), only, "row {index}");
        let mut refused = rows.clone();
        refused[*index][CHUNK] = CHUNK_16K;
        refused[*index][SPAN] = SPAN_8K;
        assert!(
            only.iter()
                .all(|pair| uncovered(&refused, &satisfiable).contains(pair)),
            "row {index} replaced by a refused combination"
        );
    }
}

/// An arena of `derived`'s response buffers, receive-write buffers and one
/// maintenance buffer; the response and receive-write buffers each span one
/// command.
pub(super) fn arena(derived: &Derived) -> BufferArena<TestPlatform> {
    let span = derived.span as u32;
    let pools = [
        PoolSpec {
            kind: PoolKind::ReadResponse,
            count: derived.response_buffers as u32,
            buffer_len: span,
        },
        PoolSpec {
            kind: PoolKind::ReceiveWrite,
            count: derived.fill_records as u32 + 2,
            buffer_len: span,
        },
        PoolSpec {
            kind: PoolKind::Maintenance,
            count: 1,
            buffer_len: IO_UNIT as u32,
        },
    ];
    let validated = BufferConfig {
        hugepage: HugepageSize::TwoMiB,
        nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
        pools: &pools,
    }
    .validate()
    .expect("a valid arena configuration");
    BufferArena::initialize(
        &validated,
        TestPlatform::heap(IO_UNIT),
        &mut EngineBudget::new(usize::MAX),
    )
    .expect("an arena")
}

/// `derived`'s storage: its volume, slots, record format, reserve,
/// headroom, read share and caps, over one index shard of its fill records.
pub(super) fn storage(derived: &Derived) -> Storage<TestPlatform> {
    let limits = [derived.visible as usize];
    let fills = [derived.fill_records as usize];
    let index = IndexConfig {
        shards: ShardLimits::Explicit(&limits),
        load: Ratio {
            numerator: 1,
            denominator: 2,
        },
        overflow: Ratio {
            numerator: 1,
            denominator: 1,
        },
        depth: 1,
        batch_max: 4,
        fills: &fills,
    };
    let config = StorageConfig {
        page_size: IO_UNIT,
        engine_budget: 1 << 24,
        body_cap: derived.body_cap as usize,
        metadata_cap: Some(METADATA_CAP as usize),
        lease_limit: 16,
        object_rights: 8,
        reader_limit: 2,
        volume: VolumeConfig {
            raw_bytes: (derived.units + crate::storage::TEST_METADATA_UNITS) as usize * IO_UNIT,
            metadata_units: crate::storage::TEST_METADATA_UNITS,
            slot_count: derived.slots as usize,
            alloc_search_words: work_bound(
                derived.units,
                derived.slots as usize,
                derived.record_units,
            ),
            read_ops: derived.read_ops as u32,
            read_commands: derived.read_commands as u32,
            read_ahead: derived.read_ahead as u8,
            metadata_commands: METADATA_COMMANDS as u32,
            metadata_retries: 2,
            clock: crate::storage::TEST_CLOCK,
            feed: crate::storage::TEST_FEED,
            record: RecordConfig {
                chunk_len: derived.chunk as u32,
            },
            nodes: NodeMask::from_nodes(&[0]).expect("node 0"),
            block_roots: 0,
            reserve_units: derived.reserve,
            maintenance: Some(VolumeWatermarks {
                low_units: derived.low_units,
                min_free_slots: derived.min_free_slots as usize,
                retired_units: derived.retired_units,
            }),
            recovery: crate::storage::test_recovery(),
        },
    };
    storage_from_configs(&config, &index)
}

/// `derived`'s owner configuration. The maintenance work is the storage's
/// own minimum, which the factor model leaves to the storage to derive.
pub(super) fn owner_config(derived: &Derived, maintain_minimum: usize) -> OwnerConfig {
    let slots = derived.request_slots as u32;
    OwnerConfig {
        caps: Caps { slots, window: 4 },
        serve: ServeConfig {
            slots,
            ..OWNER.serve
        },
        batch: derived.batch as u32,
        request_slots: slots,
        peer_requests: derived.peer_requests as u32,
        get_reserve: derived.get_reserve as u32,
        peer_get_reserve: derived.peer_get_reserve as u32,
        maintain_work: maintain_minimum,
        put: PutConfig {
            puts: derived.puts as u32,
            peer_puts: derived.peer_puts as u32,
            run_waiters: derived.puts as u32,
            get_backlog: u32::MAX,
            commands: 8,
            command_bytes: derived.put_command_bytes as usize,
            window: derived.put_window as u32,
            copy_bytes: 1 << 16,
            publish_tries: 4,
            publish_work: 1 << 12,
        },
        ..OWNER
    }
}

/// The link faults toward and from the GET client under `profile`, and
/// whether the device corrupts the GET's read: healthy runs fault-free,
/// gray delays and reorders, error-omission loses and duplicates, and
/// hostile media hands back a read whose bytes fail their checksum.
fn profile_faults(profile: usize) -> (Faults, bool) {
    match FACTORS[FAULTS].1[profile] {
        "healthy" => (Faults::default(), false),
        "gray" => (
            Faults {
                delay: 30,
                reorder: 50,
                ..Faults::default()
            },
            false,
        ),
        "error-omission" => (
            Faults {
                loss: 30,
                duplicate: 20,
                ..Faults::default()
            },
            false,
        ),
        "hostile-media" => (Faults::default(), true),
        other => panic!("{other:?} is no fault profile"),
    }
}

/// What one row's GET did: its outcome, the bytes it delivered, the object
/// it read and each link direction's fault counters.
struct Served {
    outcome: Outcome,
    bytes: Vec<u8>,
    object: Vec<u8>,
    reports: [NetReport; 2],
}

/// Starts an owner over `derived`'s storage, arena, volume and peers with
/// one published object that fits above the headroom target, then runs one
/// GET from the first peer under the row's fault profile, or returns the
/// first production refusal as text.
fn start(derived: &Derived) -> Result<Served, String> {
    let client_pool = pool();
    let releases = Releases::new(4, &mut EngineBudget::new(1 << 20)).expect("a board");
    let storage = storage(derived);
    let arena = arena(derived);
    let (volume, control) =
        attach_shaped(&storage, &arena, table_depth(derived), derived.span as u32)
            .map_err(|error| format!("attach: {error:?}"))?;
    // Headroom counts free runs in whole charges of the largest object's
    // first extent, which is `record_units` since every row's largest object
    // spans one extent. The object leaves the target rounded up to whole
    // charges free in one run, so maintenance keeps it resident through the
    // GET.
    let charge = derived.record_units;
    let ceiling = storage
        .domain_report()
        .ok_or("the attached storage reports no domain")?
        .placeable_units;
    if ceiling != derived.placeable_ceiling() {
        return Err(format!(
            "the empty volume's {ceiling} placeable units disagree with the {charge}-unit charge"
        ));
    }
    let kept = derived.low_units.div_ceil(charge) * charge;
    let room = derived
        .units
        .checked_sub(kept)
        .filter(|&units| units > 0)
        .ok_or(format!("no unit beside the {kept}-unit target"))?;
    let resident = room as usize * IO_UNIT - HEADER_SLACK;
    let object = payload((derived.body_cap as usize).min(resident), 7);
    let mut device = Device { volume, control };
    publish(&storage, &mut device, &key(1), 0, &object);
    let Device { volume, control } = device;
    let cache = storage.issue_cache().expect("a cache");
    let registration = cache.register().expect("a registration");
    let peers = derived.principals as usize;
    let entries = entries();
    let keys = Keys {
        principals: &PRINCIPALS[..peers],
        entries: &entries[..peers],
        epoch: 1,
        put: &PRINCIPALS[peers - 1..peers],
    };
    let (faults, corrupt) = profile_faults(derived.profile);
    let (client_end, first_end, net) = network(64, 8384, 1, [faults; 2]);
    let mut ends = vec![first_end];
    ends.extend((1..peers).map(|peer| network(4, 8384, peer as u64 + 1, [Faults::default(); 2]).1));
    let receive = pool();
    let config = owner_config(derived, storage.maintain_minimum());
    let bundle = Bundle {
        cache,
        registration,
        volume,
    };
    // The owner's budget is its envelope share exactly, which start charges in full.
    let share = super::owner_tests::TestOwner::charges(&config, &bundle.volume, peers as u16)
        .and_then(|charges| charges.total())
        .ok_or("the owner's charges overflow")?;
    let mut budget = EngineBudget::new(share);
    let mut owner = Owner::start(config, bundle, keys, Mux::new(ends), &receive, &mut budget)
        .map_err(|refused| format!("owner: {:?}", refused.error))?;
    if budget.used() != share {
        return Err(format!(
            "owner charged {} of its {share}-byte envelope share",
            budget.used()
        ));
    }
    let mut client = client(0, &client_pool, &releases, client_end);
    let nets = [net];
    let mut turn = open(&mut client, &mut owner, &control, &nets, 0);
    let id = client
        .get(key(1), 0, 1 << 20, turn * 100, 30_000_000)
        .expect("an admitted GET");
    if corrupt {
        let (token, at) = hold_next_read(&mut client, &mut owner, &control, &nets[0], turn);
        control.fault(token, Fault::CorruptSuccess);
        for read in read_tokens(&control)
            .into_iter()
            .filter(|&read| read != token)
        {
            let _ = control.try_fault(read, Fault::CorruptSuccess);
        }
        control.release(token);
        turn = at;
    }
    let mut bytes = Vec::new();
    drive(
        &mut [&mut client],
        &mut owner,
        &control,
        &nets,
        turn,
        50_000,
        |clients| {
            collect(clients[0], id, &mut bytes);
            clients[0].outcome(id).is_some()
        },
    );
    collect(&mut client, id, &mut bytes);
    let outcome = client.outcome(id).ok_or("the GET never ended")?;
    let net = nets[0].borrow();
    Ok(Served {
        outcome,
        bytes,
        object,
        reports: [net.report(0), net.report(1)],
    })
}

/// Every committed row's derived configuration passes storage, index and
/// arena validation, attaches its volume and starts an owner over its peers,
/// and one GET under the row's fault profile delivers the exact object, or
/// under hostile media ends `IntegrityError` with no byte exposed.
#[test]
fn production_serves_a_get_over_every_row_under_its_fault_profile() {
    for (index, row) in rows().iter().enumerate() {
        let derived = Derived::of(row);
        let profile = FACTORS[FAULTS].1[derived.profile];
        let Served {
            outcome,
            bytes,
            object,
            reports,
        } = start(&derived).unwrap_or_else(|refusal| panic!("row {index}: {refusal}"));
        let expected = if profile == "hostile-media" {
            (Outcome::Failed(Status::IntegrityError), Vec::new())
        } else {
            (Outcome::Complete, object)
        };
        assert_eq!((outcome, bytes), expected, "row {index}: {derived:?}");
        let fired = |count: fn(&NetReport) -> u64| reports.iter().map(count).sum::<u64>();
        let configured: &[fn(&NetReport) -> u64] = match profile {
            "gray" => &[|r| r.delayed, |r| r.reordered],
            "error-omission" => &[|r| r.lost, |r| r.duplicated],
            _ => &[],
        };
        for count in configured {
            assert!(fired(*count) > 0, "row {index} ({profile}): {reports:?}");
        }
        // Deliveries are counted whatever the row's faults, so the
        // comparison leaves them out.
        let unconfigured: fn(&NetReport) -> NetReport = match profile {
            "gray" => |r| NetReport {
                delayed: 0,
                reordered: 0,
                delivered: 0,
                ..*r
            },
            "error-omission" => |r| NetReport {
                lost: 0,
                duplicated: 0,
                delivered: 0,
                ..*r
            },
            _ => |r| NetReport { delivered: 0, ..*r },
        };
        for report in &reports {
            assert_eq!(
                unconfigured(report),
                NetReport::default(),
                "row {index} ({profile}): {reports:?}"
            );
        }
    }
}

/// Every committed row's headroom target and largest charge, from this
/// module's arithmetic, are the structural floor of the row's PUT cap and
/// the `Cmax` its storage records, so each row's owner starts at the floor.
#[test]
fn every_row_s_headroom_target_is_the_structural_floor_of_its_put_cap() {
    for (index, row) in rows().iter().enumerate() {
        let derived = Derived::of(row);
        let terms = storage(&derived).floor_terms().expect("a live storage");
        assert_eq!(terms.record_units, derived.record_units, "row {index}");
        assert_eq!(
            terms.floor(derived.puts as u32),
            Ok(derived.low_units),
            "row {index}: {derived:?}"
        );
    }
}

/// The first committed row whose owner takes PUTs from every peer, so each
/// PUT limit it breaks is live.
fn putting() -> Derived {
    rows()
        .iter()
        .map(Derived::of)
        .find(|derived| derived.puts > 0 && derived.peer_puts > 0)
        .expect("a row whose owner takes PUTs from every peer")
}

/// One way to break a derivation, and the constraint that must refuse it.
type Break = (fn(&mut Derived), &'static str);

const FLOOR: &str = "headroom covers the structural floor of the PUT cap";

const ALLOWANCE: &str = "retired allowance covers the largest record";

const RESERVE: &str = "GET reserves are positive and leave the PUT caps their slots";

const RESERVE_BREAKS: [fn(&mut Derived); 6] = [
    |d| d.get_reserve = 0,
    |d| (d.get_reserve, d.puts, d.peer_puts) = (d.request_slots + 1, 0, 0),
    |d| d.peer_get_reserve = 0,
    |d| (d.peer_get_reserve, d.peer_puts) = (d.peer_requests + 1, 0),
    |d| d.get_reserve = d.request_slots - d.puts + 1,
    |d| d.peer_get_reserve = d.peer_requests - d.peer_puts + 1,
];

/// Each constraint is live: breaking a value it judges in an otherwise
/// admitted derivation makes it refuse the configuration.
#[test]
fn every_constraint_refuses_a_derivation_that_breaks_it() {
    let base = putting();
    assert_eq!(base.violations(), Vec::<&str>::new());
    let mut breaks: Vec<Break> = vec![
        (
            |d| d.low_units = d.placeable_ceiling() + 1,
            "reserve, largest record and headroom fit the volume",
        ),
        (
            |d| d.low_units = d.reserve + d.record_units - 1,
            "reserve, largest record and headroom fit the volume",
        ),
        (|d| d.low_units -= 1, FLOOR),
        (|d| d.retired_units = d.record_units - 1, ALLOWANCE),
        (
            |d| d.min_free_slots = d.slots,
            "free-slot threshold below the slots",
        ),
        (
            |d| d.visible = d.slots + 1,
            "shard visible limits sum within the slots",
        ),
        (|d| d.span = 4096, "span at least a fragment and a chunk"),
        (|d| d.header_max = d.span + 1, "header windows fit the span"),
        (
            |d| (d.chunk, d.header_max) = (4096, d.span),
            "header windows fit the span",
        ),
        (
            |d| (d.chunk, d.span) = (8192, 12288),
            "chunk divides the receive-write buffer",
        ),
        (
            |d| d.read_commands = d.depth,
            "read commands below the table depth",
        ),
        (
            |d| d.read_ops = d.request_slots - 1,
            "read operations cover the request slots",
        ),
        (
            |d| d.response_buffers -= 1,
            "response buffers cover two per request and its read-ahead",
        ),
        (|d| d.peer_requests = 0, "peer shares fit the request slots"),
        (|d| d.batch = 1, "batch of at least two"),
        (
            |d| d.rx_ring = d.packet_reserve,
            "control reserve covers the batch and the receive ring",
        ),
        (
            |d| d.puts = d.fill_records + 1,
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
        (
            |d| d.peer_puts = d.puts + 1,
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
        (
            |d| d.put_window = d.packets,
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
        (
            |d| d.read_commands = d.depth - d.principals + 1,
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
        (
            |d| d.put_command_bytes = d.span - 1,
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
        (
            |d| (d.fill_records, d.puts) = (d.request_slots + 2, d.request_slots + 1),
            "PUT fits its peers, slots, fills, data room and write commands",
        ),
    ];
    breaks.extend(RESERVE_BREAKS.map(|breaking| (breaking, RESERVE)));
    let named: BTreeSet<&str> = base.checks().iter().map(|&(name, _)| name).collect();
    let broken: BTreeSet<&str> = breaks.iter().map(|&(_, name)| name).collect();
    assert_eq!(named, broken, "every constraint has a break");
    for (breaking, name) in breaks {
        let mut broken = base;
        breaking(&mut broken);
        assert!(broken.violations().contains(&name), "{name}: {broken:?}");
    }
}

/// A headroom target one unit under the structural floor of an owner with
/// PUTs breaks the floor constraint alone, and production start refuses it
/// naming both values.
#[test]
fn production_refuses_a_headroom_target_under_the_floor() {
    let base = putting();
    let mut broken = base;
    broken.low_units -= 1;
    assert_eq!(broken.violations(), [FLOOR], "{broken:?}");
    let expected = format!(
        "owner: {:?}",
        OwnerError::WatermarkFloor {
            low_units: broken.low_units,
            floor: Ok(base.low_units),
        }
    );
    assert_eq!(start(&broken).err(), Some(expected));
}

#[test]
fn an_owner_without_puts_is_exempt_from_the_floor() {
    let mut putless = putting();
    (putless.puts, putless.peer_puts) = (0, 0);
    putless.retired_units = 2 * putless.record_units;
    putless.low_units = putless.reserve + putless.record_units;
    assert!(putless.low_units < putless.reserve + putless.retired_units);
    assert_eq!(putless.violations(), Vec::<&str>::new(), "{putless:?}");
    assert!(start(&putless).is_ok(), "{putless:?}");
}

#[test]
fn production_refuses_every_get_reserve_break() {
    every_get_reserve_break_is_refused(|broken| start(broken).err());
}

/// Applies each reserve break to an admitted derivation and asserts that `refusal` names the `GetReserve` cause
/// for it.
fn every_get_reserve_break_is_refused(refusal: impl Fn(&Derived) -> Option<String>) {
    let base = putting();
    for (index, breaking) in RESERVE_BREAKS.iter().enumerate() {
        let mut broken = base;
        breaking(&mut broken);
        assert_eq!(broken.violations(), [RESERVE], "break {index}: {broken:?}");
        let refusal = refusal(&broken);
        assert_eq!(
            refusal.as_deref(),
            Some("owner: GetReserve"),
            "break {index}"
        );
    }
}

/// A reserve check that subtracts each reserve from its slots with wrapping: a reserve one above the request
/// slots leaves a room of `u64::MAX`, so the check admits the configuration with no PUT and the witness of
/// `production_refuses_every_get_reserve_break` finds no refusal at break 1.
#[test]
#[should_panic(expected = "break 1\n  left: None\n right: Some(\"owner: GetReserve\")")]
fn negative_control_a_reserve_check_with_wrapping_subtraction_admits_a_reserve_above_the_slots() {
    every_get_reserve_break_is_refused(|derived| {
        let fits = |reserve: u64, slots: u64, puts: u64| {
            reserve > 0 && puts <= slots.wrapping_sub(reserve)
        };
        let fit = fits(derived.get_reserve, derived.request_slots, derived.puts)
            && fits(
                derived.peer_get_reserve,
                derived.peer_requests,
                derived.peer_puts,
            );
        (!fit).then(|| "owner: GetReserve".to_owned())
    });
}

/// The combination the model constrains away, a 16-KiB chunk over an 8-KiB
/// span, is refused by the volume attach.
#[test]
fn production_refuses_a_chunk_longer_than_the_span() {
    let mut refused = rows()[0];
    refused[CHUNK] = CHUNK_16K;
    refused[SPAN] = SPAN_8K;
    let derived = Derived::of(&refused);
    assert!(!derived.violations().is_empty());
    let storage = storage(&derived);
    let arena = arena(&derived);
    let error = attach_shaped(&storage, &arena, table_depth(&derived), derived.span as u32)
        .err()
        .expect("a refused attach");
    assert_eq!(
        error,
        AttachError::ChunkLenNotDividingBuffer {
            chunk_len: 16384,
            buffer_len: 8192
        }
    );
}

crate::sim::round::generated_corpus!(generated_orders_keep_every_listed_outcome:
    production_serves_a_get_over_every_row_under_its_fault_profile,
);
