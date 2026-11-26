// The history checker. The `store_history` target of `kestrike` and the
// `store_record` target of `kestrike-aws` include this file; the module
// doc of `store_history.rs` states the history format and the checks. It
// names only `std`, `serde` and `serde_json`, which resolve in both targets,
// and holds no test.

use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::hash::{BuildHasherDefault, Hasher};
use std::io::{BufRead, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Deserializer};

/// The error code a history records for a write whose condition did not hold.
const CONDITION_FAILED: &str = "ConditionalCheckFailedException";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Op {
    Read,
    Cas,
    Update,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
enum Outcome {
    Ok,
    Fail,
    Unknown,
}

impl Outcome {
    fn name(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Fail => "fail",
            Outcome::Unknown => "unknown",
        }
    }
}

/// One recorded request as a history line holds it. Its strings borrow the line; a JSON string that holds an escape decodes into an owned string.
#[derive(Debug, Clone, Deserialize)]
struct Event<'a> {
    op: Op,
    #[serde(borrow)]
    scenario: Cow<'a, str>,
    #[serde(borrow)]
    client: Cow<'a, str>,
    #[serde(borrow)]
    key: Cow<'a, str>,
    invoke: u64,
    complete: u64,
    outcome: Outcome,
    #[serde(borrow)]
    code: Cow<'a, str>,
    #[serde(default)]
    expect: Option<u64>,
    #[serde(default, borrow, deserialize_with = "optional_text")]
    wid: Option<Cow<'a, str>>,
    #[serde(default)]
    ver: Option<u64>,
    #[serde(default)]
    reported: Option<u64>,
    #[serde(default)]
    consistent: Option<bool>,
}

impl Event<'_> {
    fn strong(&self) -> bool {
        self.consistent != Some(false)
    }
}

/// One entry of the store's change log, with strings borrowed as in [`Event`].
#[derive(Debug, Clone)]
struct Commit<'a> {
    key: Cow<'a, str>,
    ver: u64,
    wid: Option<Cow<'a, str>>,
}

/// A JSON string that borrows its source text unless it holds an escape.
#[derive(Deserialize)]
struct Text<'a>(#[serde(borrow)] Cow<'a, str>);

/// The JSON form of a [`Commit`]. A missing or null `wid` reads as `None`; the array form needs all three fields.
#[derive(Deserialize)]
#[serde(rename = "Commit")]
struct CommitRecord<'a> {
    #[serde(borrow)]
    key: Cow<'a, str>,
    ver: u64,
    #[serde(borrow)]
    wid: Option<Text<'a>>,
}

impl<'de: 'a, 'a> Deserialize<'de> for Commit<'a> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let record = CommitRecord::deserialize(deserializer)?;
        Ok(Commit {
            key: record.key,
            ver: record.ver,
            wid: record.wid.map(|Text(wid)| wid),
        })
    }
}

/// Reads a null or a string, borrowing the string as [`Text`] does.
fn optional_text<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Cow<'de, str>>, D::Error> {
    Ok(Option::<Text<'de>>::deserialize(deserializer)?.map(|Text(text)| text))
}

/// One committed version's write: its interval, with `None` for a completion the client never learned.
#[derive(Debug, Clone, Copy)]
struct Writer {
    invoke: u64,
    complete: Option<u64>,
}

/// One scenario's counts. Each well-formed write whose commits all lie in `1..=u64::MAX - 2` counts under `outcome:code`, `ok:` for a success, split by whether it committed.
#[derive(Debug, Default)]
struct Tally {
    committed_codes: BTreeMap<String, u64>,
    uncommitted_codes: BTreeMap<String, u64>,
    eventual_reads: u64,
    /// Eventually consistent reads that returned a version a later committed write with a known outcome had replaced before the read began.
    stale_eventual_reads: u64,
    /// Well-formed `update` writes; the checks leave their named-field conditions unjudged.
    unjudged_field_conditions: u64,
}

/// What a history showed: every violation, in the phase order [`check_runs`] lists, and each scenario's counts.
#[derive(Debug, Default)]
struct Verdict {
    violations: Vec<String>,
    scenarios: BTreeMap<String, Tally>,
}

/// A multiply-add word hasher for the checker's maps and write ID shards. Its keys are write IDs, names and codes from the campaign under check, a trusted input.
#[derive(Default)]
struct WordHasher(u64);

impl WordHasher {
    fn mix(&mut self, word: u64) {
        self.0 = self
            .0
            .wrapping_add(word)
            .wrapping_mul(0xf135_7aea_2e62_a9c5);
    }
}

impl Hasher for WordHasher {
    fn write(&mut self, bytes: &[u8]) {
        let (words, rest) = bytes.as_chunks::<8>();
        for word in words {
            self.mix(u64::from_le_bytes(*word));
        }
        if !rest.is_empty() {
            let mut word = [0; 8];
            word[..rest.len()].copy_from_slice(rest);
            self.mix(u64::from_le_bytes(word));
        }
    }

    fn write_u8(&mut self, n: u8) {
        self.mix(u64::from(n));
    }

    fn write_u32(&mut self, n: u32) {
        self.mix(u64::from(n));
    }

    fn write_u64(&mut self, n: u64) {
        self.mix(n);
    }

    fn write_usize(&mut self, n: usize) {
        self.mix(n as u64);
    }

    /// Bit `k` of a product depends only on operand bits `0..=k`, so the rotation moves the top 26 bits into the low bits a hash table indexes by.
    fn finish(&self) -> u64 {
        self.0.rotate_left(26)
    }
}

type WordMap<K, V> = HashMap<K, V, BuildHasherDefault<WordHasher>>;

/// Dense ids for distinct strings, in first-seen order. Consecutive lookups of one string skip the map.
#[derive(Default)]
struct Names {
    names: Vec<String>,
    index: WordMap<String, u32>,
    last: u32,
}

impl Names {
    fn id(&mut self, name: &str) -> u32 {
        if self
            .names
            .get(self.last as usize)
            .is_some_and(|last| last == name)
        {
            return self.last;
        }
        let id = match self.index.get(name) {
            Some(&id) => id,
            None => {
                let id = self.names.len() as u32;
                self.names.push(name.to_owned());
                self.index.insert(name.to_owned(), id);
                id
            }
        };
        self.last = id;
        id
    }

    fn name(&self, id: u32) -> &str {
        &self.names[id as usize]
    }
}

/// Where a write ID's bytes lie in its run's [`WidText`]; [`Span::NONE`] marks an element with no write ID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Span {
    start: u32,
    len: u32,
}

impl Span {
    const NONE: Span = Span {
        start: u32::MAX,
        len: 0,
    };
}

/// The write IDs of one run, end to end in one string.
struct WidText(String);

impl WidText {
    /// Room for `capacity` write IDs of [`WID_BYTES`] bytes.
    fn new(capacity: usize) -> Self {
        WidText(String::with_capacity(capacity * WID_BYTES))
    }

    /// Appends `wid` and returns where it lies, or [`Span::NONE`] for `None`.
    fn push(&mut self, wid: Option<&str>) -> Span {
        let Some(wid) = wid else {
            return Span::NONE;
        };
        let start = self.0.len() as u32;
        self.0.push_str(wid);
        Span {
            start,
            len: wid.len() as u32,
        }
    }

    fn get(&self, span: Span) -> Option<&str> {
        (span != Span::NONE).then(|| &self.0[span.start as usize..(span.start + span.len) as usize])
    }
}

/// One request as the checks hold it, with its strings as ids in its run's [`Names`] and its write ID as a [`Span`] of the run's text.
#[derive(Debug, Clone, Copy)]
struct Request {
    invoke: u64,
    complete: u64,
    /// A read's `ver` or a write's `expect` when [`Request::HAS_OPERAND`] is set, and 0 otherwise.
    operand: u64,
    wid: Span,
    key: u32,
    scenario: u32,
    client: u32,
    code: u32,
    op: Op,
    outcome: Outcome,
    flags: u8,
}

impl Request {
    const HAS_OPERAND: u8 = 1;
    /// Its `consistent` field is `false`: for a read, an eventually consistent one.
    const EVENTUAL: u8 = 2;
    /// Its code is [`CONDITION_FAILED`].
    const CONDITION_FAILED: u8 = 4;
    /// An `ok` `cas` whose `reported` version is other than `expect + 1`.
    const MISREPORTED: u8 = 8;

    fn strong(&self) -> bool {
        self.flags & Request::EVENTUAL == 0
    }

    fn condition_failed(&self) -> bool {
        self.flags & Request::CONDITION_FAILED != 0
    }

    /// A read's `ver` or a write's `expect`.
    fn operand(&self) -> Option<u64> {
        (self.flags & Request::HAS_OPERAND != 0).then_some(self.operand)
    }
}

/// Returns log2 of the shard count for `uses` write ID uses: the smallest power of two at or above `uses / per_shard`, at most 256 shards.
fn shard_bits(uses: usize, per_shard: usize) -> u32 {
    (uses / per_shard)
        .next_power_of_two()
        .min(256)
        .trailing_zeros()
}

/// The shard of `wid` among `1 << bits` shards: the top `bits` bits of its [`WordHasher`] hash.
fn shard_of(wid: &str, bits: u32) -> usize {
    let mut hasher = WordHasher::default();
    hasher.write(wid.as_bytes());
    hasher.finish().checked_shr(64 - bits).unwrap_or(0) as usize
}

/// Bytes of write ID text a run reserves per element, the length of the 32-hex-digit write IDs the fixtures record.
const WID_BYTES: usize = 32;
/// How [`check`] and [`check_campaign`] divide their work into parallel tasks. The verdict is the same for every split.
#[derive(Debug, Clone, Copy)]
struct Split {
    /// Bytes of a campaign file per parse task; a task parses the lines that start in its bytes.
    span: u64,
    /// Events or commits per run when an in-memory history is split.
    run: usize,
    /// Write ID uses per shard that [`shard_bits`] aims for.
    uses_per_shard: usize,
}

impl Split {
    const DEFAULT: Split = Split {
        span: 1 << 20,
        run: 4096,
        uses_per_shard: 4096,
    };
}
/// The [`Uses::of`] entry of an element that carries no write ID.
const NO_USE: u32 = u32::MAX;

/// The write ID uses of one run, a use being an element that carries a write ID: each element's shard and rank among the run's uses in that shard, and each shard's elements in run order.
struct Uses {
    of: Vec<(u32, u32)>,
    by_shard: Vec<Vec<u32>>,
    bits: u32,
}

impl Uses {
    fn new(bits: u32, capacity: usize) -> Self {
        Uses {
            of: Vec::with_capacity(capacity),
            by_shard: vec![Vec::new(); 1 << bits],
            bits,
        }
    }

    fn push(&mut self, wid: Option<&str>) {
        let at = self.of.len() as u32;
        match wid {
            Some(wid) => {
                let shard = shard_of(wid, self.bits);
                self.of
                    .push((shard as u32, self.by_shard[shard].len() as u32));
                self.by_shard[shard].push(at);
            }
            None => self.of.push((NO_USE, NO_USE)),
        }
    }
}

/// A run of consecutive requests of one history, with the names and write IDs they carry. Its name ids are local to the run; [`check_runs`] maps keys and scenarios to global ids.
struct EventRun {
    requests: Vec<Request>,
    keys: Names,
    scenarios: Names,
    clients: Names,
    codes: Names,
    text: WidText,
    uses: Uses,
}

impl EventRun {
    /// An empty run with room for `capacity` requests and its write ID uses in `1 << bits` shards.
    fn new(bits: u32, capacity: usize) -> Self {
        EventRun {
            requests: Vec::with_capacity(capacity),
            keys: Names::default(),
            scenarios: Names::default(),
            clients: Names::default(),
            codes: Names::default(),
            text: WidText::new(capacity),
            uses: Uses::new(bits, capacity),
        }
    }

    fn push(&mut self, event: &Event) {
        let wid = self.text.push(event.wid.as_deref());
        self.uses.push(event.wid.as_deref());
        let operand = if event.op == Op::Read {
            event.ver
        } else {
            event.expect
        };
        let mut flags = 0;
        if operand.is_some() {
            flags |= Request::HAS_OPERAND;
        }
        if !event.strong() {
            flags |= Request::EVENTUAL;
        }
        if event.code == CONDITION_FAILED {
            flags |= Request::CONDITION_FAILED;
        }
        let next = event.expect.and_then(|expect| expect.checked_add(1));
        if event.op == Op::Cas
            && event.outcome == Outcome::Ok
            && event
                .reported
                .is_some_and(|reported| next != Some(reported))
        {
            flags |= Request::MISREPORTED;
        }
        self.requests.push(Request {
            invoke: event.invoke,
            complete: event.complete,
            operand: operand.unwrap_or(0),
            wid,
            key: self.keys.id(&event.key),
            scenario: self.scenarios.id(&event.scenario),
            client: self.clients.id(&event.client),
            code: self.codes.id(&event.code),
            op: event.op,
            outcome: event.outcome,
            flags,
        });
    }

    fn wid(&self, request: &Request) -> Option<&str> {
        self.text.get(request.wid)
    }

    /// Returns the first history-form rule `request` breaks.
    fn malformed(&self, request: &Request) -> Option<&'static str> {
        if request.complete < request.invoke {
            return Some("completes before it begins");
        }
        if request.outcome == Outcome::Ok && !self.codes.name(request.code).is_empty() {
            return Some("succeeds with an error code");
        }
        if request.outcome == Outcome::Fail && self.codes.name(request.code).is_empty() {
            return Some("fails without an error code");
        }
        let wid = self.wid(request);
        match request.op {
            Op::Cas | Op::Update if wid.is_none() => Some("carries no write ID"),
            Op::Cas if request.operand().is_none() => Some("carries no expected version"),
            Op::Cas if request.flags & Request::MISREPORTED != 0 => {
                Some("reports a version other than its expected version plus one")
            }
            Op::Read
                if request.outcome == Outcome::Ok
                    && !matches!(
                        (request.operand(), wid),
                        (None, None) | (Some(1..), Some(_))
                    ) =>
            {
                Some("returns neither an absent item nor a version with its write ID")
            }
            _ => None,
        }
    }
}

/// A run of consecutive entries of the commit log: each entry's version, write ID span and run-local key id.
struct CommitRun {
    entries: Vec<(u64, Span, u32)>,
    keys: Names,
    text: WidText,
    uses: Uses,
}

impl CommitRun {
    /// An empty run with room for `capacity` entries and its write ID uses in `1 << bits` shards.
    fn new(bits: u32, capacity: usize) -> Self {
        CommitRun {
            entries: Vec::with_capacity(capacity),
            keys: Names::default(),
            text: WidText::new(capacity),
            uses: Uses::new(bits, capacity),
        }
    }

    fn push(&mut self, commit: &Commit) {
        let wid = self.text.push(commit.wid.as_deref());
        self.uses.push(commit.wid.as_deref());
        self.entries
            .push((commit.ver, wid, self.keys.id(&commit.key)));
    }

    fn wid(&self, span: Span) -> Option<&str> {
        self.text.get(span)
    }
}

/// One write ID's state after the whole log: whether a recorded write carries it, whether an out-of-range commit carries it, and the global key id and version of its last in-range commit. While `commit` is `None`, `first_read` holds the global key id and version of the first well-formed `ok` read below its key's first logged version that returns the ID.
#[derive(Debug, Default, Clone, Copy)]
struct WriteId {
    issued: bool,
    out_of_range: bool,
    commit: Option<(usize, u64)>,
    first_read: Option<(usize, u64)>,
}

/// One scenario's counts over one run's requests, with codes keyed by outcome and code text. [`Counts::add`] sums the counts of a scenario's runs.
#[derive(Default)]
struct Counts<'a> {
    committed: WordMap<(Outcome, &'a str), u64>,
    uncommitted: WordMap<(Outcome, &'a str), u64>,
    eventual_reads: u64,
    stale_eventual_reads: u64,
    unjudged_field_conditions: u64,
}

impl<'a> Counts<'a> {
    /// Adds `other`'s counts to these.
    fn add(&mut self, other: Counts<'a>) {
        for (code, n) in other.committed {
            *self.committed.entry(code).or_default() += n;
        }
        for (code, n) in other.uncommitted {
            *self.uncommitted.entry(code).or_default() += n;
        }
        self.eventual_reads += other.eventual_reads;
        self.stale_eventual_reads += other.stale_eventual_reads;
        self.unjudged_field_conditions += other.unjudged_field_conditions;
    }

    fn tally(self) -> Tally {
        let named = |codes: WordMap<(Outcome, &str), u64>| {
            codes
                .into_iter()
                .map(|((outcome, code), n)| (format!("{}:{code}", outcome.name()), n))
                .collect()
        };
        Tally {
            committed_codes: named(self.committed),
            uncommitted_codes: named(self.uncommitted),
            eventual_reads: self.eventual_reads,
            stale_eventual_reads: self.stale_eventual_reads,
            unjudged_field_conditions: self.unjudged_field_conditions,
        }
    }
}

/// Parses each line of `text` that holds more than whitespace as one `T`.
///
/// # Panics
///
/// - If a line does not parse. The message names `origin` and the line's 1-based number.
fn parse<'a, T: Deserialize<'a>>(origin: &str, text: &'a str) -> Vec<T> {
    text.lines()
        .enumerate()
        .filter(|(_, line)| !line.trim().is_empty())
        .map(|(at, line)| {
            serde_json::from_str(line)
                .unwrap_or_else(|error| panic!("{origin}:{}: {error}", at + 1))
        })
        .collect()
}

/// Runs `task` on each index of `0..tasks` across the host's available parallelism and returns the results in index order. Workers claim indexes in ascending order. A panic in a task resumes in the caller.
fn in_parallel<T: Send>(tasks: usize, task: impl Fn(usize) -> T + Sync) -> Vec<T> {
    let workers = std::thread::available_parallelism()
        .map_or(1, usize::from)
        .min(tasks);
    if workers <= 1 {
        return (0..tasks).map(task).collect();
    }
    let next = AtomicUsize::new(0);
    let mut results: Vec<Option<T>> = std::iter::repeat_with(|| None).take(tasks).collect();
    std::thread::scope(|scope| {
        let running: Vec<_> = (0..workers)
            .map(|_| {
                scope.spawn(|| {
                    let mut done = Vec::new();
                    loop {
                        let at = next.fetch_add(1, Ordering::Relaxed);
                        if at >= tasks {
                            return done;
                        }
                        done.push((at, task(at)));
                    }
                })
            })
            .collect();
        for worker in running {
            match worker.join() {
                Ok(done) => {
                    for (at, result) in done {
                        results[at] = Some(result);
                    }
                }
                Err(payload) => std::panic::resume_unwind(payload),
            }
        }
    });
    results
        .into_iter()
        .map(|result| result.expect("every task ran"))
        .collect()
}

/// Checks `events` against the whole commit log `commits`, each in its recorded order. `events` holds every request on every key the log names, as the recorder rule in the module doc of `store_history.rs` requires; a commit whose write ID no write carries is an ST7 violation.
fn check(events: &[Event], commits: &[Commit]) -> Verdict {
    check_with(events, commits, Split::DEFAULT)
}

/// [`check`] with its work divided by `split`: each run of `split.run` events or commits is built in parallel.
fn check_with(events: &[Event], commits: &[Commit], split: Split) -> Verdict {
    let bits = shard_bits(events.len() + commits.len(), split.uses_per_shard);
    let event_runs: Vec<EventRun> = in_parallel(events.len().div_ceil(split.run), |run| {
        let chunk = events.chunks(split.run).nth(run).expect("a run of events");
        let mut built = EventRun::new(bits, chunk.len());
        for event in chunk {
            built.push(event);
        }
        built
    });
    let commit_runs: Vec<CommitRun> = in_parallel(commits.len().div_ceil(split.run), |run| {
        let chunk = commits
            .chunks(split.run)
            .nth(run)
            .expect("a run of commits");
        let mut built = CommitRun::new(bits, chunk.len());
        for commit in chunk {
            built.push(commit);
        }
        built
    });
    check_runs(&event_runs, &commit_runs)
}

/// What one shard of write IDs resolved, with each use's result in the order of its runs.
struct Shard {
    /// Each event use's index in `states` of its write ID, with [`Shard::REPEATED`] on a write when an earlier write carries the same ID.
    events: Vec<u32>,
    /// Per commit use: whether a recorded write carries its ID, and whether the commit is in range and follows an earlier in-range commit of its ID.
    commits: Vec<(bool, bool)>,
    /// Per event run, the position in `events` of its first use here.
    event_starts: Vec<usize>,
    /// Per commit run, the position in `commits` of its first use here.
    commit_starts: Vec<usize>,
    states: Vec<WriteId>,
}

impl Shard {
    /// The flag bit of a write's `events` entry. Indexes stay below it while a shard holds fewer than `1 << 31` write IDs.
    const REPEATED: u32 = 1 << 31;

    /// Write use `rank` of event run `run`: whether an earlier write carries its ID, and the ID's state.
    fn write(&self, run: usize, rank: u32) -> (bool, WriteId) {
        let id = self.events[self.event_starts[run] + rank as usize];
        (
            id & Shard::REPEATED != 0,
            self.states[(id & !Shard::REPEATED) as usize],
        )
    }

    fn read(&self, run: usize, rank: u32) -> WriteId {
        self.states[self.events[self.event_starts[run] + rank as usize] as usize]
    }

    fn commit(&self, run: usize, rank: u32) -> (bool, bool) {
        self.commits[self.commit_starts[run] + rank as usize]
    }
}

#[derive(Default)]
struct ShardIds<'r> {
    index: WordMap<&'r str, u32>,
    states: Vec<WriteId>,
}

impl<'r> ShardIds<'r> {
    fn id(&mut self, wid: &'r str) -> usize {
        let fresh = self.states.len() as u32;
        let id = *self.index.entry(wid).or_insert(fresh);
        if id == fresh {
            self.states.push(WriteId::default());
        }
        id as usize
    }
}

/// Resolves one shard's write ID uses: each write in event order, then each commit in log order, then each read in event order. `event_keys` and `commit_keys` map each run's key ids to global ones; `first_logged` is each key's lowest in-range logged version, as [`check_runs`] computes it. Every use of an ID falls in one shard and each pass walks the runs in order, so an ID's first write, its last in-range commit, the first well-formed `ok` read below its key's first logged version of an ID with no in-range commit, and whether a write issued it are those of the whole history.
fn resolve_shard(
    shard: usize,
    event_runs: &[EventRun],
    commit_runs: &[CommitRun],
    event_keys: &[&[usize]],
    commit_keys: &[Vec<usize>],
    first_logged: &[u64],
) -> Shard {
    let mut known = ShardIds::default();
    let mut found = Shard {
        events: Vec::new(),
        commits: Vec::new(),
        event_starts: Vec::with_capacity(event_runs.len()),
        commit_starts: Vec::with_capacity(commit_runs.len()),
        states: Vec::new(),
    };
    for run in event_runs {
        found.event_starts.push(found.events.len());
        for &at in &run.uses.by_shard[shard] {
            let request = &run.requests[at as usize];
            if request.op == Op::Read {
                found.events.push(NO_USE);
                continue;
            }
            let id = known.id(run.wid(request).expect("a use carries a write ID"));
            let repeated = if known.states[id].issued {
                Shard::REPEATED
            } else {
                0
            };
            found.events.push(id as u32 | repeated);
            known.states[id].issued = true;
        }
    }
    for (run, keys) in commit_runs.iter().zip(commit_keys) {
        found.commit_starts.push(found.commits.len());
        for &at in &run.uses.by_shard[shard] {
            let (ver, span, key) = run.entries[at as usize];
            let id = known.id(run.wid(span).expect("a use carries a write ID"));
            let state = &mut known.states[id];
            let twice = if (1..=u64::MAX - 2).contains(&ver) {
                state.commit.replace((keys[key as usize], ver)).is_some()
            } else {
                state.out_of_range = true;
                false
            };
            found.commits.push((known.states[id].issued, twice));
        }
    }
    for ((run, keys), &start) in event_runs.iter().zip(event_keys).zip(&found.event_starts) {
        for (rank, &at) in run.uses.by_shard[shard].iter().enumerate() {
            let request = &run.requests[at as usize];
            if request.op == Op::Read {
                let wid = run.wid(request).expect("a use carries a write ID");
                let id = known.id(wid);
                found.events[start + rank] = id as u32;
                let state = &mut known.states[id];
                let key = keys[request.key as usize];
                let ver = request.operand().unwrap_or(0);
                if request.outcome == Outcome::Ok
                    && run.malformed(request).is_none()
                    && ver < first_logged[key]
                    && state.commit.is_none()
                    && state.first_read.is_none()
                {
                    state.first_read = Some((key, ver));
                }
            }
        }
    }
    found.states = known.states;
    found
}

/// The write of each committed version, per key. A key's slots follow its distinct logged versions in ascending order; a version holds the write that, last in event order, committed it.
struct Writers {
    versions: Vec<Vec<u64>>,
    slots: Vec<Vec<Option<Writer>>>,
}

impl Writers {
    /// Slots for every distinct version of each key's log `versions`, all empty.
    fn new(versions: &[Vec<u64>]) -> Self {
        let versions: Vec<Vec<u64>> = in_parallel(versions.len(), |key| {
            let mut distinct = versions[key].clone();
            distinct.sort_unstable();
            distinct.dedup();
            distinct
        });
        let slots = versions
            .iter()
            .map(|distinct| vec![None; distinct.len()])
            .collect();
        Writers { versions, slots }
    }

    fn slot(&self, key: usize, ver: u64) -> Option<usize> {
        self.versions[key].binary_search(&ver).ok()
    }

    fn get(&self, key: usize, ver: u64) -> Option<Writer> {
        self.slot(key, ver).and_then(|slot| self.slots[key][slot])
    }
}

/// The global ids of one event run's keys and scenarios, by run-local id.
struct RunIds {
    keys: Vec<usize>,
    scenarios: Vec<usize>,
}

/// What one run of events showed before reads are judged: its history-form and write violations, its counts, the versions its writes committed, and its well-formed requests.
struct WriteFindings<'r> {
    form: Vec<String>,
    writes: Vec<String>,
    counts: Vec<Counts<'r>>,
    /// Each committed write's global key id, version slot and offset in the run, in event order.
    committed: Vec<(u32, u32, u32)>,
    /// Each well-formed request's offset in the run and global key id, in event order.
    formed: Vec<(u32, u32)>,
    /// The same requests ordered by key id, each key's in event order.
    by_key: Vec<(u32, u32)>,
}

impl WriteFindings<'_> {
    /// The offsets of the run's well-formed requests on `key`, in event order.
    fn on_key(&self, key: usize) -> impl Iterator<Item = usize> + '_ {
        let key = key as u32;
        let from = self.by_key.partition_point(|&(on, _)| on < key);
        self.by_key[from..]
            .iter()
            .take_while(move |&&(on, _)| on == key)
            .map(|&(_, offset)| offset as usize)
    }
}

/// One task's result in the stage of [`check_runs`] that judges reads and key orders.
enum Judged<'r> {
    Order(Option<String>),
    Reads((Vec<String>, Vec<Counts<'r>>)),
}

/// What every stage of [`check_runs`] shares once the commit log is read.
struct Context<'r> {
    event_runs: &'r [EventRun],
    ids: Vec<RunIds>,
    resolved: Vec<Shard>,
    keys: Vec<&'r str>,
    /// Each key's in-range logged versions in log order, by global key id.
    versions: Vec<Vec<u64>>,
    scenario_count: usize,
}

impl<'r> Context<'r> {
    /// One empty [`Counts`] per scenario.
    fn counts(&self) -> Vec<Counts<'r>> {
        std::iter::repeat_with(Counts::default)
            .take(self.scenario_count)
            .collect()
    }
}

/// [`check`] over a history and a commit log split into runs: the events are those of `event_runs` in order, the commits those of `commit_runs`. Every run shards its write ID uses `1 << bits` ways for one `bits`, which `check_runs` reads from the first run; [`check_with`] and [`check_campaign_with`] build every run with one `bits`.
///
/// Runs, write ID shards and keys are checked in parallel, and each stage merges its results in run or key-name order, so the verdict is the same for every split. The violations come in phases:
/// 1. each request's form, in event order;
/// 2. each commit log entry's version range, write ID and repeated commit, in log order;
/// 3. each key's consecutive versions, in key-name order;
/// 4. each write's commit, in event order;
/// 5. each `ok` read, in event order;
/// 6. each linearized key's linearization, in key-name order.
fn check_runs<'r>(event_runs: &'r [EventRun], commit_runs: &'r [CommitRun]) -> Verdict {
    let bits = event_runs
        .iter()
        .map(|run| run.uses.bits)
        .chain(commit_runs.iter().map(|run| run.uses.bits))
        .next()
        .unwrap_or(0);
    let mut key_names: WordMap<&str, usize> = WordMap::default();
    let mut keys: Vec<&str> = Vec::new();
    let mut key_id = |name| {
        let fresh = keys.len();
        let id = *key_names.entry(name).or_insert(fresh);
        if id == fresh {
            keys.push(name);
        }
        id
    };
    // Every scenario in the history gets a tally, including one that holds only reads.
    let mut scenario_names: WordMap<&str, usize> = WordMap::default();
    let mut scenarios: Vec<&str> = Vec::new();
    let ids: Vec<RunIds> = event_runs
        .iter()
        .map(|run| RunIds {
            keys: run.keys.names.iter().map(|name| key_id(name)).collect(),
            scenarios: run
                .scenarios
                .names
                .iter()
                .map(|name| {
                    let fresh = scenarios.len();
                    let id = *scenario_names.entry(name).or_insert(fresh);
                    if id == fresh {
                        scenarios.push(name);
                    }
                    id
                })
                .collect(),
        })
        .collect();
    let event_keys: Vec<&[usize]> = ids.iter().map(|run| run.keys.as_slice()).collect();
    let commit_keys: Vec<Vec<usize>> = commit_runs
        .iter()
        .map(|run| run.keys.names.iter().map(|name| key_id(name)).collect())
        .collect();
    let mut first_logged: Vec<u64> = vec![0; keys.len()];
    for (run, keys) in commit_runs.iter().zip(&commit_keys) {
        for &(ver, _, local) in &run.entries {
            if (1..=u64::MAX - 2).contains(&ver) {
                let first = &mut first_logged[keys[local as usize]];
                *first = if *first == 0 { ver } else { (*first).min(ver) };
            }
        }
    }
    let resolved = in_parallel(1 << bits, |shard| {
        resolve_shard(
            shard,
            event_runs,
            commit_runs,
            &event_keys,
            &commit_keys,
            &first_logged,
        )
    });
    let logged = in_parallel(commit_runs.len(), |at| {
        let run = &commit_runs[at];
        let mut messages = Vec::new();
        let mut in_range = Vec::new();
        let mut out_of_range = Vec::new();
        for (entry, &(ver, span, local)) in run.entries.iter().enumerate() {
            let key = commit_keys[at][local as usize];
            let name = run.keys.name(local);
            if (1..=u64::MAX - 2).contains(&ver) {
                in_range.push((key, ver));
            } else {
                messages.push(format!("history: {name} version {ver} is out of range"));
                out_of_range.push(key);
            }
            let Some(wid) = run.wid(span) else {
                messages.push(format!(
                    "ST7: {name} version {ver} committed with no write ID"
                ));
                continue;
            };
            let (shard, rank) = run.uses.of[entry];
            let (issued, twice) = resolved[shard as usize].commit(at, rank);
            if !issued {
                messages.push(format!(
                    "ST7: {name} version {ver} committed by write {wid}, which no recorded client issued"
                ));
            }
            if twice {
                messages.push(format!("ST1: write {wid} committed twice"));
            }
        }
        (messages, in_range, out_of_range)
    });
    let mut versions: Vec<Vec<u64>> = vec![Vec::new(); keys.len()];
    let mut unordered: Vec<bool> = vec![false; keys.len()];
    let mut log_messages = Vec::new();
    for (messages, in_range, out_of_range) in logged {
        log_messages.extend(messages);
        for (key, ver) in in_range {
            versions[key].push(ver);
        }
        for key in out_of_range {
            unordered[key] = true;
        }
    }
    let mut by_name: Vec<usize> = (0..keys.len()).collect();
    by_name.sort_unstable_by_key(|&key| keys[key]);
    let mut order_messages = Vec::new();
    for &key in &by_name {
        if let Some(pair) = versions[key]
            .windows(2)
            .find(|pair| pair[0].checked_add(1) != Some(pair[1]))
        {
            order_messages.push(format!(
                "ST1: {} versions {} then {} are not consecutive",
                keys[key], pair[0], pair[1]
            ));
            unordered[key] = true;
        }
    }
    let mut writers = Writers::new(&versions);
    let context = Context {
        event_runs,
        ids,
        resolved,
        keys,
        versions,
        scenario_count: scenarios.len(),
    };
    let findings = in_parallel(event_runs.len(), |run| {
        check_writes(&context, &writers, run)
    });
    for (run, found) in event_runs.iter().zip(&findings) {
        for &(key, slot, offset) in &found.committed {
            let request = &run.requests[offset as usize];
            writers.slots[key as usize][slot as usize] = Some(Writer {
                invoke: request.invoke,
                complete: (request.outcome != Outcome::Unknown).then_some(request.complete),
            });
        }
    }
    let mut requested = vec![false; context.keys.len()];
    for found in &findings {
        for &(_, key) in &found.formed {
            requested[key as usize] = true;
        }
    }
    // Linearization covers each requested key whose logged versions are in range and consecutive.
    let linearized: Vec<usize> = by_name
        .iter()
        .copied()
        .filter(|&key| requested[key] && !unordered[key])
        .collect();
    let replaced_by: Vec<OnceLock<Vec<(u64, u64)>>> = std::iter::repeat_with(OnceLock::new)
        .take(context.keys.len())
        .collect();
    let replaced = |key: usize| -> &[(u64, u64)] {
        replaced_by[key].get_or_init(|| {
            let mut earliest = u64::MAX;
            let mut suffix: Vec<(u64, u64)> = writers.versions[key]
                .iter()
                .rev()
                .map(|&ver| {
                    if let Some(done) = writers.get(key, ver).and_then(|w| w.complete) {
                        earliest = earliest.min(done);
                    }
                    (ver, earliest)
                })
                .collect();
            suffix.reverse();
            suffix
        })
    };
    // One parallel stage judges each linearized key and each run's reads. Key tasks take the lowest indexes, which `in_parallel` hands out first, because one key can hold most of the history.
    let judged = in_parallel(linearized.len() + event_runs.len(), |at| {
        match at.checked_sub(linearized.len()) {
            None => {
                let key = linearized[at];
                let requests = event_runs.iter().zip(&findings).flat_map(|(run, found)| {
                    found
                        .on_key(key)
                        .map(move |offset| (run, &run.requests[offset]))
                });
                Judged::Order(linearize(
                    context.keys[key],
                    &context.versions[key],
                    requests,
                    &writers.slots[key],
                ))
            }
            Some(run) => Judged::Reads(check_reads(
                &context,
                &writers,
                replaced,
                run,
                &findings[run].formed,
            )),
        }
    });
    let mut orders = Vec::new();
    let mut reads = Vec::new();
    for judged in judged {
        match judged {
            Judged::Order(order) => orders.extend(order),
            Judged::Reads(found) => reads.push(found),
        }
    }
    let mut counts = context.counts();
    let mut violations = Vec::new();
    let mut write_messages = Vec::new();
    for found in findings {
        violations.extend(found.form);
        write_messages.extend(found.writes);
        for (total, part) in counts.iter_mut().zip(found.counts) {
            total.add(part);
        }
    }
    violations.extend(log_messages);
    violations.extend(order_messages);
    violations.extend(write_messages);
    for (messages, part) in reads {
        violations.extend(messages);
        for (total, part) in counts.iter_mut().zip(part) {
            total.add(part);
        }
    }
    violations.extend(orders);
    let scenarios = scenarios
        .iter()
        .zip(counts)
        .map(|(name, counts)| ((*name).to_owned(), counts.tally()))
        .collect();
    Verdict {
        violations,
        scenarios,
    }
}

/// Checks the form and the writes of event run `at`: a write ID on two writes and a malformed request are form violations; each well-formed write whose commits all lie in `1..=u64::MAX - 2` has its commit checked against its outcome, key and expected version and is counted under its outcome and code. The log phase reports the out-of-range commit of every other write. `writers` gives each logged version's slot.
fn check_writes<'r>(context: &Context<'r>, writers: &Writers, at: usize) -> WriteFindings<'r> {
    let runs: &'r [EventRun] = context.event_runs;
    let run = &runs[at];
    let ids = &context.ids[at];
    let mut found = WriteFindings {
        form: Vec::new(),
        writes: Vec::new(),
        counts: context.counts(),
        committed: Vec::new(),
        formed: Vec::with_capacity(run.requests.len()),
        by_key: Vec::new(),
    };
    for (offset, request) in run.requests.iter().enumerate() {
        let (shard, rank) = run.uses.of[offset];
        let (repeated, known) = if request.op != Op::Read && shard != NO_USE {
            context.resolved[shard as usize].write(at, rank)
        } else {
            (false, WriteId::default())
        };
        let wid = run.wid(request);
        if repeated {
            let wid = wid.expect("a write use carries a write ID");
            found
                .form
                .push(format!("history: write ID {wid} is on two writes"));
            continue;
        }
        if let Some(rule) = run.malformed(request) {
            found.form.push(format!(
                "history: {:?} by {} on {} {rule}",
                request.op,
                run.clients.name(request.client),
                run.keys.name(request.key)
            ));
            continue;
        }
        let key = ids.keys[request.key as usize];
        found.formed.push((offset as u32, key as u32));
        if request.op == Op::Read || known.out_of_range {
            continue;
        }
        let wid = wid.expect("a formed write carries a write ID");
        let mut committed = known.commit;
        if let Some((on, _)) = committed
            && on != key
        {
            found.writes.push(format!(
                "ST1: write {wid} on {} committed on {}",
                run.keys.name(request.key),
                context.keys[on]
            ));
            committed = None;
        }
        let code = run.codes.name(request.code);
        let tally = &mut found.counts[ids.scenarios[request.scenario as usize]];
        if request.op == Op::Update {
            tally.unjudged_field_conditions += 1;
        }
        let codes = if committed.is_some() {
            &mut tally.committed
        } else {
            &mut tally.uncommitted
        };
        *codes.entry((request.outcome, code)).or_default() += 1;
        match (request.outcome, committed) {
            (Outcome::Ok, None) => found.writes.push(format!(
                "ST2/ST4: acknowledged write {wid} is not in the commit log"
            )),
            (Outcome::Fail, Some(_)) => found.writes.push(format!(
                "ST4: {code} write {wid} reported not committed but committed"
            )),
            _ => {}
        }
        if let Some((on, ver)) = committed {
            if request.op == Op::Cas
                && request.operand().and_then(|e| e.checked_add(1)) != Some(ver)
            {
                found.writes.push(format!(
                    "ST1: write {wid} expected {:?} but committed {ver}",
                    request.operand()
                ));
            }
            let slot = writers
                .slot(on, ver)
                .expect("a committed write's version is logged");
            found
                .committed
                .push((on as u32, slot as u32, offset as u32));
        }
    }
    found.by_key = found
        .formed
        .iter()
        .map(|&(offset, key)| (key, offset))
        .collect();
    found.by_key.sort_unstable();
    found
}

/// The function checks the `ok` reads in `formed` for event run `at` against the commit log. `replaced_by` gives, per key and distinct logged version in ascending order, the earliest completion of a committed write with a known outcome at or above that version. The function returns violations and, per scenario, counts of eventually consistent `ok` reads at or below their key's highest logged version and the stale reads among them.
fn check_reads<'r, 'k>(
    context: &Context<'r>,
    writers: &Writers,
    replaced_by: impl Fn(usize) -> &'k [(u64, u64)],
    at: usize,
    formed: &[(u32, u32)],
) -> (Vec<String>, Vec<Counts<'r>>) {
    let run = &context.event_runs[at];
    let mut violations = Vec::new();
    let mut counts = context.counts();
    for &(offset, key) in formed {
        let (offset, key) = (offset as usize, key as usize);
        let request = &run.requests[offset];
        if request.op != Op::Read || request.outcome != Outcome::Ok {
            continue;
        }
        let name = run.keys.name(request.key);
        let client = run.clients.name(request.client);
        let ver = request.operand().unwrap_or(0);
        let seen = writers.versions[key].as_slice();
        if ver > seen.last().copied().unwrap_or(0) {
            violations.push(format!(
                "ST3: {name} read of version {ver} by {client} is above every committed version"
            ));
            continue;
        }
        if ver > 0 {
            let (shard, rank) = run.uses.of[offset];
            let state = (shard != NO_USE).then(|| context.resolved[shard as usize].read(at, rank));
            let image = state.and_then(|state| state.commit);
            let logged = seen.first().is_some_and(|&first| ver >= first);
            let issued = state.is_some_and(|state| state.issued && !state.out_of_range);
            if (logged && image != Some((key, ver))) || (!logged && (image.is_some() || issued)) {
                violations.push(format!(
                    "ST3: {name} read of version {ver} by {client} returned write {:?}, committed at {:?}",
                    run.wid(request),
                    image.map(|(on, ver)| (context.keys[on], ver))
                ));
            } else if let Some((on, first)) = state.and_then(|state| state.first_read)
                && (on, first) != (key, ver)
            {
                violations.push(format!(
                    "ST1: {name} read of version {ver} by {client} returned write {}, which a read of {} version {first} also returned",
                    run.wid(request).unwrap_or_default(),
                    context.keys[on]
                ));
            }
            if writers
                .get(key, ver)
                .is_some_and(|w| w.invoke > request.complete)
            {
                violations.push(format!(
                    "ST3: {name} read of version {ver} by {client} ends before its write begins"
                ));
            }
        }
        if !request.strong() {
            let suffix = replaced_by(key);
            let above = suffix.partition_point(|&(at, _)| at <= ver);
            let replaced = suffix
                .get(above)
                .is_some_and(|&(_, done)| done < request.invoke);
            let tally = &mut counts[context.ids[at].scenarios[request.scenario as usize]];
            tally.eventual_reads += 1;
            tally.stale_eventual_reads += u64::from(replaced);
        }
    }
    (violations, counts)
}

/// The function checks whether a key's history admits a linearization in commit order and returns a violation on failure. `versions` contains consecutive committed versions; `writers` contains their writes at matching indices. `requests` contains the well-formed requests and runs supplied by [`check`], with `invoke <= complete`. Version `v` takes effect at `p_v`, where `p_v <= p_{v+1}`. The base `b` precedes the first logged version. When the log starts at version 1, version 0 represents absence from the start. In later slices, reads and condition failures bound versions `1..=b`. The point after the last commit is `NEVER`. The constraints:
/// - a committed write: `invoke <= p_v <= complete`, with no upper bound for an unknown outcome;
/// - an `ok` read of `v` in `1..=` the last logged version: `p_v <= complete`; a strong read also `invoke <= p_{v+1}`;
/// - a strong read of version 0 below `b`: `invoke <= p_1`;
/// - a condition failure on `e`: `p_e >= invoke` or `p_{e+1} <= complete`.
///
/// Every constraint links consecutive versions, so a forward pass computes the feasible interval of each `p_v` under the constraints on versions up to `v`: `p_{v+1}` keeps its own bounds, rises to the lowest feasible `p_v`, and, for each failure on `v` whose invoke exceeds the highest feasible `p_v`, falls to that failure's completion. The history has a linearization exactly when every interval is nonempty.
///
/// Each version holds one image, so all `ok` reads of a version in `1..=b` return the same write ID.
fn linearize<'r>(
    key: &str,
    versions: &[u64],
    requests: impl Iterator<Item = (&'r EventRun, &'r Request)>,
    writers: &[Option<Writer>],
) -> Option<String> {
    const START: i128 = i128::MIN;
    const NEVER: i128 = i128::MAX;
    // As `i128` values, `START` and `NEVER` lie below and above every `u64` time.
    let first = versions.first().copied().unwrap_or(1);
    let last = versions.last().copied().unwrap_or(0);
    let base = first - 1;
    let slot = |ver: u64| (ver >= base && ver <= last).then(|| (ver - base) as usize);
    let len = (last + 2 - base) as usize;
    let mut lower = vec![START; len];
    let mut upper = vec![NEVER; len];
    if base == 0 {
        upper[0] = START;
    }
    lower[len - 1] = NEVER;
    for (at, writer) in writers.iter().enumerate() {
        if let Some(writer) = writer {
            lower[at + 1] = lower[at + 1].max(i128::from(writer.invoke));
            if let Some(done) = writer.complete {
                upper[at + 1] = upper[at + 1].min(i128::from(done));
            }
        }
    }
    // `sparse` stores bounds for versions below `b` that a read or condition failure constrains, including successor versions bounded by strong reads and failures.
    struct Bounds {
        from: i128,
        until: i128,
        failures: Vec<(i128, i128)>,
    }
    fn bounds(sparse: &mut BTreeMap<u64, Bounds>, ver: u64) -> &mut Bounds {
        sparse.entry(ver).or_insert_with(|| Bounds {
            from: START,
            until: if ver == 0 { START } else { NEVER },
            failures: Vec::new(),
        })
    }
    let mut sparse: BTreeMap<u64, Bounds> = BTreeMap::new();
    // Condition failures by the slot of their expected version, as offsets into one array.
    let mut failure_starts = vec![0; len + 1];
    let mut failed: Vec<(usize, i128, i128)> = Vec::new();
    let mut below: WordMap<u64, &'r str> = WordMap::default();
    for (run, request) in requests {
        let (invoke, complete) = (i128::from(request.invoke), i128::from(request.complete));
        match (request.op, request.outcome) {
            (Op::Read, Outcome::Ok) => {
                let ver = request.operand().unwrap_or(0);
                if (1..=base).contains(&ver) {
                    let wid = run
                        .wid(request)
                        .expect("a well-formed read of a positive version carries a write ID");
                    let first_seen = *below.entry(ver).or_insert(wid);
                    if first_seen != wid {
                        return Some(format!(
                            "ST1/ST3: {key} has no linearization: reads of version {ver} returned writes {first_seen} and {wid}"
                        ));
                    }
                }
                match slot(ver) {
                    Some(at) => {
                        upper[at] = upper[at].min(complete);
                        if request.strong() {
                            lower[at + 1] = lower[at + 1].max(invoke);
                        }
                    }
                    None if ver < base => {
                        if ver > 0 {
                            let at = bounds(&mut sparse, ver);
                            at.until = at.until.min(complete);
                        }
                        if request.strong() {
                            if ver + 1 == base {
                                lower[0] = lower[0].max(invoke);
                            } else {
                                let next = bounds(&mut sparse, ver + 1);
                                next.from = next.from.max(invoke);
                            }
                        }
                    }
                    None => {}
                }
            }
            (Op::Cas, Outcome::Fail) if request.condition_failed() => {
                let expect = request.operand().unwrap_or(0);
                match slot(expect) {
                    Some(at) => {
                        failure_starts[at + 1] += 1;
                        failed.push((at, invoke, complete));
                    }
                    None if expect < base => {
                        bounds(&mut sparse, expect)
                            .failures
                            .push((invoke, complete));
                        if expect + 1 < base {
                            bounds(&mut sparse, expect + 1);
                        }
                    }
                    None => {}
                }
            }
            _ => {}
        }
    }
    for at in 0..len {
        failure_starts[at + 1] += failure_starts[at];
    }
    let mut failures = vec![(0, 0); failed.len()];
    let mut next = failure_starts.clone();
    for (at, invoke, complete) in failed {
        failures[next[at]] = (invoke, complete);
        next[at] += 1;
    }
    let unplaced = |ver: u64| {
        format!(
            "ST1/ST3: {key} has no linearization: no point for version {ver} satisfies every write, read and condition failure that bounds it"
        )
    };
    // The upper bound of `p_{v+1}` falls to the completion of each failure on `v` that began after the highest feasible `p_v`.
    let fallen = |mut high: i128, failures: &[(i128, i128)], before: i128| {
        for &(invoke, complete) in failures {
            if invoke > before {
                high = high.min(complete);
            }
        }
        high
    };
    let (mut low, mut high) = (START, NEVER);
    let mut previous: Option<(u64, &[(i128, i128)])> = None;
    for (&ver, at) in &sparse {
        let mut next_high = at.until;
        if let Some((before, failures)) = previous
            && before + 1 == ver
        {
            next_high = fallen(next_high, failures, high);
        }
        low = low.max(at.from);
        high = next_high;
        if low > high {
            return Some(unplaced(ver));
        }
        previous = Some((ver, &at.failures));
    }
    let mut next_high = upper[0];
    if let Some((before, failures)) = previous
        && before + 1 == base
    {
        next_high = fallen(next_high, failures, high);
    }
    low = low.max(lower[0]);
    high = next_high;
    for at in 0..len {
        if at > 0 {
            high = fallen(
                upper[at],
                &failures[failure_starts[at - 1]..failure_starts[at]],
                high,
            );
            low = lower[at].max(low);
        }
        if low > high {
            return Some(unplaced(base + at as u64));
        }
    }
    None
}

/// What one parse task found in its part of a campaign file.
enum Part {
    Events(EventRun),
    Commits(CommitRun),
    Unreadable(std::io::Error),
    /// A line of the part holds bytes that are not UTF-8.
    NotText,
    /// The first line of the part that does not parse, by the file byte it starts at.
    Unparsed(u64, serde_json::Error),
}

/// Bytes of the buffer [`parse_part`] reads a part through.
const BLOCK: usize = 64 << 10;

/// Parses the lines of `path` that start at a byte in `start..end` as one run: of commits when `commits` is set, of events otherwise. A line starts at byte 0 and after each line feed, and is read whole. The part streams through one buffer of [`BLOCK`] bytes; the run is sized for `expected` bytes at the line density of the first buffer. The part reads every line, including those after one that does not parse, and checks each for UTF-8, so a read failure or non-text byte anywhere in the part takes precedence over a parse failure. `bits` picks the run's write ID shards.
fn parse_part(path: &Path, start: u64, end: u64, expected: u64, commits: bool, bits: u32) -> Part {
    let read = || -> std::io::Result<Part> {
        let mut file = std::fs::File::open(path)?;
        let mut at = start.saturating_sub(1);
        file.seek(SeekFrom::Start(at))?;
        let mut reader = std::io::BufReader::with_capacity(BLOCK, file);
        let mut line = Vec::new();
        // The first line here starts at byte 0 or after the first line feed at or past `start - 1`.
        if start > 0 {
            at += reader.read_until(b'\n', &mut line)? as u64;
        }
        let sample = reader.fill_buf()?;
        let feeds = sample.iter().filter(|&&b| b == b'\n').count().max(1) as u64;
        let capacity = usize::try_from(expected * feeds / (sample.len() as u64).max(1) * 9 / 8)
            .unwrap_or(0)
            + 16;
        let (mut event_run, mut commit_run) = if commits {
            (EventRun::new(bits, 0), CommitRun::new(bits, capacity))
        } else {
            (EventRun::new(bits, capacity), CommitRun::new(bits, 0))
        };
        let mut unparsed = None;
        let mut not_text = false;
        while at < end {
            line.clear();
            let read = reader.read_until(b'\n', &mut line)?;
            if read == 0 {
                break;
            }
            let first = at;
            at += read as u64;
            match std::str::from_utf8(&line) {
                Err(_) => not_text = true,
                Ok(_) if not_text || unparsed.is_some() => {}
                Ok(piece) => {
                    let line = piece
                        .strip_suffix('\n')
                        .map_or(piece, |line| line.strip_suffix('\r').unwrap_or(line));
                    if !line.trim().is_empty() {
                        let parsed = if commits {
                            serde_json::from_str(line)
                                .map(|commit: Commit| commit_run.push(&commit))
                        } else {
                            serde_json::from_str(line).map(|event: Event| event_run.push(&event))
                        };
                        if let Err(error) = parsed {
                            unparsed = Some((first, error));
                        }
                    }
                }
            }
        }
        Ok(if not_text {
            Part::NotText
        } else if let Some((offset, error)) = unparsed {
            Part::Unparsed(offset, error)
        } else if commits {
            Part::Commits(commit_run)
        } else {
            Part::Events(event_run)
        })
    };
    read().unwrap_or_else(Part::Unreadable)
}

/// Concatenates the histories of the campaign directory `dir` in path order into one history on their shared clock and checks it against the directory's `commits.jsonl`. Returns each history's path and event count with the verdict. Panics when a file cannot be read, holds a byte that is not UTF-8 or holds a line that does not parse, when the directory cannot be listed or holds an entry other than a `*.jsonl` file or no history, and when a history holds no event. Files are read and parsed in parallel parts; the checks of a file, and the panics they raise, run in the order of the files: the commit log, the directory listing, then each history in path order. Within a file, a read failure panics before a byte that is not UTF-8, which panics before the file's first line that does not parse; that panic names the line's number in the whole file.
fn check_campaign(dir: &Path) -> (Vec<(String, usize)>, Verdict) {
    check_campaign_with(dir, Split::DEFAULT)
}

/// [`check_campaign`] with its work divided by `split`.
fn check_campaign_with(dir: &Path, split: Split) -> (Vec<(String, usize)>, Verdict) {
    let commits_path = dir.join("commits.jsonl");
    let listing: std::io::Result<Vec<std::io::Result<(PathBuf, bool)>>> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .map(|entry| {
                    let path = entry?.path();
                    let history = path.is_file() && path.extension().is_some_and(|e| e == "jsonl");
                    Ok((path, history))
                })
                .collect()
        });
    let mut paths: Vec<&Path> = listing
        .iter()
        .flatten()
        .flatten()
        .filter(|(path, history)| {
            *history && path.file_name().is_some_and(|n| n != "commits.jsonl")
        })
        .map(|(path, _)| path.as_path())
        .collect();
    paths.sort();
    let files: Vec<&Path> = std::iter::once(commits_path.as_path())
        .chain(paths.iter().copied())
        .collect();
    let sizes: Vec<u64> = files
        .iter()
        .map(|path| std::fs::metadata(path).map_or(0, |meta| meta.len()))
        .collect();
    // Shards are sized for one write ID use per 128 bytes of campaign text, above the density of recorded campaigns: a history line carries at most one write ID in about 240 bytes, a commit line one in about 74.
    let bits = shard_bits(
        usize::try_from(sizes.iter().sum::<u64>() / 128).unwrap_or(usize::MAX),
        split.uses_per_shard,
    );
    let parts: Vec<(usize, u64, u64)> = sizes
        .iter()
        .enumerate()
        .flat_map(|(file, &size)| {
            let count = size.div_ceil(split.span).max(1);
            (0..count).map(move |part| {
                let end = if part + 1 == count {
                    u64::MAX
                } else {
                    (part + 1) * split.span
                };
                (file, part * split.span, end)
            })
        })
        .collect();
    let parsed = in_parallel(parts.len(), |at| {
        let (file, start, end) = parts[at];
        let expected = end.min(sizes[file]).saturating_sub(start);
        parse_part(files[file], start, end, expected, file == 0, bits)
    });
    let mut file_parts: Vec<Vec<Part>> =
        std::iter::repeat_with(Vec::new).take(files.len()).collect();
    for (&(file, ..), part) in parts.iter().zip(parsed) {
        file_parts[file].push(part);
    }
    let mut event_runs = Vec::new();
    let mut commit_runs = Vec::new();
    let mut counts = Vec::new();
    for (file, (path, parts)) in files.iter().zip(file_parts).enumerate() {
        let origin = path.display().to_string();
        if let Some(error) = parts.iter().find_map(|part| match part {
            Part::Unreadable(error) => Some(error),
            _ => None,
        }) {
            panic!("{origin}: {error}");
        }
        if parts.iter().any(|part| matches!(part, Part::NotText)) {
            panic!("{origin}: stream did not contain valid UTF-8");
        }
        let mut parsed_events = 0;
        for part in parts {
            match part {
                Part::Commits(run) => commit_runs.push(run),
                Part::Events(run) => {
                    parsed_events += run.requests.len();
                    event_runs.push(run);
                }
                Part::Unparsed(offset, error) => {
                    let bytes =
                        std::fs::read(path).unwrap_or_else(|error| panic!("{origin}: {error}"));
                    let offset = usize::try_from(offset).expect("a line offset inside the file");
                    let line = bytes[..offset].iter().filter(|&&b| b == b'\n').count() + 1;
                    panic!("{origin}:{line}: {error}")
                }
                Part::Unreadable(_) | Part::NotText => unreachable!("checked above"),
            }
        }
        if file == 0 {
            let listing = listing
                .as_ref()
                .unwrap_or_else(|error| panic!("{}: {error}", dir.display()));
            for entry in listing {
                let (path, history) = entry.as_ref().expect("a directory entry");
                assert!(*history, "{} is not a history file", path.display());
            }
            assert!(!paths.is_empty(), "{} holds no history", dir.display());
        } else {
            assert!(parsed_events > 0, "{origin} holds no event");
            counts.push((origin, parsed_events));
        }
    }
    (counts, check_runs(&event_runs, &commit_runs))
}
