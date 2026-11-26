//! Store-contract checks over recorded conditional-write histories of the off-volume store class.
//!
//! A history is the JSON lines of one or more scenarios on one monotonic clock. Each line is one request a client issued:
//! - `op`: `read`, `cas` (a write conditioned on the item's exact version) or `update` (a write conditioned on named fields);
//! - `scenario`, `client`, `key`, and `invoke` and `complete` times;
//! - `outcome`: `ok`, `fail` (the store refused the request: for a write, the store reported it not committed) or `unknown`; and `code`, empty on success, the store's error code on a `fail`, and on an `unknown` either the store's error code or the recorder's note of what it saw instead, such as a lost reply or an HTTP status;
//! - a write's `wid`, the unique write ID it stored in the item, and a `cas`'s `expect`, the version it requires;
//! - an `ok` `cas`'s `reported`, when present, the version the store's reply reports the write committed;
//! - an `ok` read's `ver` and `wid`, the version and write ID of the image it returned, both absent for an absent item; and `consistent`, `false` for an eventually consistent read and `true` or absent for a strongly consistent one.
//!
//! A recorder journals every request before it sends it, so the history holds every request on its keys; a request whose result the client never learned appears as `unknown` with its write ID, its invoke time, and as `complete` the time the client stopped waiting, which only the history-form check reads for an unknown outcome. ST7 rests on this journaling.
//!
//! The commit log is the store's own change log: every committed item image in commit order per key, with its version and write ID. A writer stores version `expect + 1` on a `cas` and raises the version by one on an `update`, so the versions of one key run consecutively from 1. A recorder for any store class with such versioned items and a change log produces these two files; it maps the store's condition-failure error to [`CONDITION_FAILED`].
//!
//! The checks:
//! - History form: every interval ends at or after its start; every `ok` request carries an empty code and every `fail` request a nonempty one; every write carries a write ID no other write carries; every `cas` carries its expected version, and an `ok` `cas` that carries `reported` reports `expect + 1`; every `ok` read returns either an absent item or a positive version with its write ID; every committed version lies in `1..=u64::MAX - 2`.
//! - ST1: each key's versions in the commit log run consecutively with no gap, repeat or rollback; each write ID commits at most once and on the key its write names; a committed `cas` committed version `expect + 1`.
//! - ST1 and ST3 linearization, per key: the committed versions take effect in commit order at points inside their writers' intervals, every read returns a version committed before it completed, every strong read returns the version current at a point inside its interval, and every condition failure on version `e` has a point inside its interval where `e` is not current. A committed write with an unknown outcome takes effect at or after its invoke time. Linearization covers each key that a well-formed request names and whose logged versions are in range and consecutive. Linearizability is local, so per-key orders compose into one order of the history.
//! - ST2 and ST4: every `ok` write is in the commit log; no `fail` write is, whatever its code.
//! - ST7: every commit in the log, on any key, carries the write ID of a recorded write.
//! - Reads: every read returns the committed image of its version.
//!
//! A slice whose log starts above version 1 judges the version just before its first logged one through the reads and condition failures on it. It judges each earlier version through the reads that return it and the condition failures on it: the log holds none of their images, and each strong read begins at or before the point where the next version takes effect. All reads of one version below the first logged one return the same write ID, and a write ID the log holds nowhere is read at one key and version. The commit log records versions and write IDs, so the checks judge an `update` by its version raise and its place in the commit order and count its named-field conditions as unjudged.
//!
//! The checker divides its work by a [`Split`]: [`check_campaign`] parses each file in parts of `span` bytes, each part holding the lines that start in it, and [`check`] cuts an in-memory history into runs of `run` requests or commits. Write IDs resolve in hash shards; each shard walks every run in order, so it sees each of its IDs' uses in history order. Runs, shards and keys are checked in parallel, and each stage merges its results in run order or key-name order. The verdict is the same for every split: the violations come in the phase order [`check_runs`] lists, each phase's in event, log or key-name order, and each scenario's counts are sums over runs.
//!
//! `STORE_HISTORY_DIR` names a campaign directory: its `commits.jsonl` and, as histories, every other `*.jsonl` file directly in it; any other entry is refused. The fixtures in `store_histories/` are two recorded slices, each with its own commit log: `lin-one-item` satisfies every check and `client-retry` holds one ST4 violation. The tests plant further violations in code, in copies of the first.

#![allow(
    clippy::disallowed_methods,
    clippy::disallowed_types,
    reason = "this offline checker reads recorded store histories outside the simulator"
)]

include!("support/store_check.rs");

const LIN_ONE_ITEM: &str = include_str!("store_histories/lin-one-item.jsonl");
const LIN_ONE_ITEM_COMMITS: &str = include_str!("store_histories/lin-one-item.commits.jsonl");

fn recorded(name: &str) -> (Vec<Event<'static>>, Vec<Commit<'static>>) {
    let (events, commits) = match name {
        "lin-one-item" => (LIN_ONE_ITEM, LIN_ONE_ITEM_COMMITS),
        "client-retry" => (
            include_str!("store_histories/client-retry.jsonl"),
            include_str!("store_histories/client-retry.commits.jsonl"),
        ),
        other => panic!("no fixture {other}"),
    };
    (parse(name, events), parse(name, commits))
}

fn violations(events: &[Event], commits: &[Commit]) -> Vec<String> {
    check(events, commits).violations
}

fn assert_flags(events: &[Event], commits: &[Commit], needle: &str) {
    let found = violations(events, commits);
    assert!(
        found.iter().any(|v| v.contains(needle)),
        "expected a violation containing {needle:?}: {found:#?}"
    );
}

fn assert_clean(events: &[Event], commits: &[Commit]) -> Verdict {
    let verdict = check(events, commits);
    assert!(verdict.violations.is_empty(), "{:#?}", verdict.violations);
    verdict
}

/// The position of the write that committed version `ver`.
fn writer_of(events: &[Event], commits: &[Commit], ver: u64) -> usize {
    let wid = &commits
        .iter()
        .find(|c| c.ver == ver)
        .expect("a committed version")
        .wid;
    events
        .iter()
        .position(|e| e.op != Op::Read && e.wid == *wid)
        .expect("the version's writer")
}

/// The position of the first strong read of version `ver`.
fn read_of(events: &[Event], ver: u64) -> usize {
    events
        .iter()
        .position(|e| e.op == Op::Read && e.strong() && e.ver == Some(ver))
        .expect("a read of the version")
}

/// A version current for more than two ticks, and its write's completion time.
fn current_gap(events: &[Event], commits: &[Commit]) -> (u64, u64) {
    (1..commits.len() as u64)
        .find_map(|ver| {
            let done = events[writer_of(events, commits, ver)].complete;
            let next = events[writer_of(events, commits, ver + 1)].invoke;
            (next > done + 2).then_some((ver, done))
        })
        .expect("the slice holds a version current for more than two ticks")
}

/// Records `write` as a lost reply: an unknown outcome with a timeout code.
fn lose_reply(write: &mut Event) {
    write.outcome = Outcome::Unknown;
    write.code = "ReadTimeoutError".into();
}

/// A recorded slice of a DynamoDB history, in which client `init` creates one item and clients `c0` to `c3` write and read it, holds acknowledged writes, condition failures and strong reads, and satisfies every check.
#[test]
fn recorded_slice_satisfies_the_store_contract() {
    let (events, commits) = recorded("lin-one-item");
    let verdict = assert_clean(&events, &commits);
    let tally = &verdict.scenarios["lin-one-item"];
    assert_eq!(tally.committed_codes.get("ok:"), Some(&11));
    assert_eq!(
        tally
            .uncommitted_codes
            .get(&format!("fail:{CONDITION_FAILED}")),
        Some(&28)
    );
}

/// A recorded history whose client retried each conditional write once holds a write whose first attempt committed while its reply was lost; the retry failed its condition on that commit, and the client reported `ConditionalCheckFailedException`. The checker reports exactly that write as a committed write reported not committed.
#[test]
fn a_committed_write_reported_as_a_condition_failure_fails_st4() {
    let (events, commits) = recorded("client-retry");
    let found = violations(&events, &commits);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].starts_with(&format!("ST4: {CONDITION_FAILED} write ")),
        "{found:#?}"
    );
    assert!(found[0].ends_with(" reported not committed but committed"));
}

/// A committed write whose reply was lost, recorded as an unknown outcome that ended early, satisfies the contract with a strong read that shows the write taking effect after its recorded end, and counts as a committed unknown outcome.
#[test]
fn a_committed_unknown_outcome_satisfies_the_store_contract() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 5);
    lose_reply(&mut events[at]);
    events[at].complete = events[at].invoke;
    let mut late = events[read_of(&events, 4)].clone();
    late.invoke = events[at].invoke + 1;
    late.complete = events[at].invoke + 2;
    events.push(late);
    let verdict = assert_clean(&events, &commits);
    assert_eq!(
        verdict.scenarios["lin-one-item"]
            .committed_codes
            .get("unknown:ReadTimeoutError"),
        Some(&1)
    );
}

/// A write with an unknown outcome that never committed satisfies the contract and counts as an uncommitted unknown outcome.
#[test]
fn an_uncommitted_unknown_outcome_satisfies_the_store_contract() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut lost = events[writer_of(&events, &commits, 6)].clone();
    lost.wid = Some("planted".into());
    lose_reply(&mut lost);
    events.push(lost);
    let verdict = assert_clean(&events, &commits);
    assert_eq!(
        verdict.scenarios["lin-one-item"]
            .uncommitted_codes
            .get("unknown:ReadTimeoutError"),
        Some(&1)
    );
}

/// A committed field-scoped `update` satisfies the contract by its version raise and its place in the commit order, and counts as an unjudged field condition.
#[test]
fn a_committed_update_counts_as_an_unjudged_field_condition() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 6);
    events[at].op = Op::Update;
    events[at].expect = None;
    let verdict = assert_clean(&events, &commits);
    assert_eq!(
        verdict.scenarios["lin-one-item"].unjudged_field_conditions,
        1
    );
}

/// A write that fails with a code other than [`CONDITION_FAILED`] while its expected version is current bounds no linearization point.
#[test]
fn a_non_condition_failure_on_the_current_version_satisfies_the_store_contract() {
    let (mut events, commits) = recorded("lin-one-item");
    let (expect, installed) = current_gap(&events, &commits);
    let mut refused = events[writer_of(&events, &commits, expect)].clone();
    refused.wid = Some("planted".into());
    refused.expect = Some(expect);
    refused.outcome = Outcome::Fail;
    refused.code = "ValidationException".into();
    refused.invoke = installed + 1;
    refused.complete = installed + 2;
    events.push(refused);
    assert_clean(&events, &commits);
}

/// A condition failure on version 5 that begins when version 5's write begins has a point where version 4 is still current.
#[test]
fn a_condition_failure_while_its_version_is_installed_satisfies_the_store_contract() {
    let (mut events, commits) = recorded("lin-one-item");
    let writer = events[writer_of(&events, &commits, 5)].clone();
    let mut early = writer.clone();
    early.wid = Some("planted".into());
    early.outcome = Outcome::Fail;
    early.code = CONDITION_FAILED.into();
    early.expect = Some(5);
    early.complete = writer.invoke + 1;
    events.push(early);
    assert_clean(&events, &commits);
}

/// A second key's history linearizes on its own commit order, independent of the first key's points on the shared clock.
#[test]
fn each_key_linearizes_on_its_own_commit_order() {
    let (mut events, mut commits) = recorded("lin-one-item");
    let mut create = events[0].clone();
    create.key = "two/shard".into();
    create.wid = Some("second".into());
    create.invoke = 1;
    create.complete = 2;
    let mut read = events[read_of(&events, 1)].clone();
    read.key = "two/shard".into();
    read.wid = Some("second".into());
    read.invoke = 3;
    read.complete = 4;
    events.extend([create, read]);
    commits.push(Commit {
        key: "two/shard".into(),
        ver: 1,
        wid: Some("second".into()),
    });
    assert_clean(&events, &commits);
}

/// A commit log that repeats a version under a fresh write ID fails the consecutive-version check.
#[test]
fn a_repeated_version_fails_st1() {
    let (events, mut commits) = recorded("lin-one-item");
    let at = commits.iter().position(|c| c.ver == 2).expect("version 2");
    let mut repeat = commits[at].clone();
    repeat.wid = Some("planted".into());
    commits.insert(at + 1, repeat);
    assert_flags(&events, &commits, "versions 2 then 2 are not consecutive");
}

/// A commit log that returns to an older version fails the consecutive-version check.
#[test]
fn a_rolled_back_version_fails_st1() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut rollback = commits[0].clone();
    rollback.wid = Some("planted".into());
    commits.push(rollback);
    assert_flags(&events, &commits, "versions 11 then 1 are not consecutive");
}

/// After a rollback the log's last entry is below its highest version, so the reads of versions 2 to 11 are inside the log's range.
#[test]
fn reads_of_a_rolled_back_log_are_judged_against_its_version_range() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut rollback = commits[0].clone();
    rollback.wid = Some("planted".into());
    commits.push(rollback);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [
            "ST7: one/shard version 1 committed by write planted, which no recorded client issued",
            "ST1: one/shard versions 11 then 1 are not consecutive",
        ],
        "{found:#?}"
    );
}

/// A write ID that commits on two versions fails ST1.
#[test]
fn a_write_committed_twice_fails_st1() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut again = commits[commits.len() - 1].clone();
    again.ver += 1;
    commits.push(again);
    assert_flags(&events, &commits, "committed twice");
}

/// A commit whose write ID no recorded request carries is a record change without a write, an ST7 violation.
#[test]
fn an_unrequested_commit_fails_st7() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut extra = commits[commits.len() - 1].clone();
    extra.ver += 1;
    extra.wid = Some("planted".into());
    commits.push(extra);
    assert_flags(&events, &commits, "which no recorded client issued");
}

/// A commit on a key no recorded request names is a record change without a write, an ST7 violation.
#[test]
fn a_commit_on_an_unrequested_key_fails_st7() {
    let (events, mut commits) = recorded("lin-one-item");
    commits.push(Commit {
        key: "untouched".into(),
        ver: 1,
        wid: Some("planted".into()),
    });
    assert_flags(
        &events,
        &commits,
        "untouched version 1 committed by write planted, which no recorded client issued",
    );
}

/// A commit with no write ID is a record change no write accounts for, an ST7 violation.
#[test]
fn a_commit_without_a_write_id_fails_st7() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut anonymous = commits[commits.len() - 1].clone();
    anonymous.ver += 1;
    anonymous.wid = None;
    commits.push(anonymous);
    assert_flags(&events, &commits, "committed with no write ID");
}

/// An acknowledged write missing from the commit log fails ST2 and ST4.
#[test]
fn a_lost_acknowledged_write_fails_st2() {
    let (events, mut commits) = recorded("lin-one-item");
    commits.retain(|c| c.ver != 11);
    assert_flags(&events, &commits, "ST2/ST4: acknowledged write");
}

/// A write reported failed with any code that is in the commit log fails ST4.
#[test]
fn a_failed_write_that_committed_fails_st4() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 4);
    events[at].outcome = Outcome::Fail;
    events[at].code = "ThrottlingException".into();
    assert_flags(&events, &commits, "ST4: ThrottlingException write");
}

/// A `cas` that committed a version other than `expect + 1` fails ST1.
#[test]
fn a_cas_committed_off_its_expected_version_fails_st1() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 6);
    events[at].expect = Some(4);
    assert_flags(&events, &commits, "expected Some(4) but committed 6");
}

/// A write recorded against one key whose ID committed on another key fails ST1 and counts as an acknowledged write missing from the log.
#[test]
fn a_write_committed_on_another_key_fails_st1() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 7);
    events[at].key = "other/key".into();
    let wid = events[at].wid.clone().expect("a write ID");
    let found = violations(&events, &commits);
    assert!(
        found.contains(&format!(
            "ST1: write {wid} on other/key committed on one/shard"
        )),
        "{found:#?}"
    );
    assert!(
        found.contains(&format!(
            "ST2/ST4: acknowledged write {wid} is not in the commit log"
        )),
        "{found:#?}"
    );
}

/// A later version whose acknowledged write completed before an earlier version's write began has no linearization, from the commit order alone.
#[test]
fn a_real_time_inversion_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    events.retain(|e| e.op != Op::Read);
    let at = writer_of(&events, &commits, 3);
    events[at].invoke = 1;
    events[at].complete = 2;
    assert_flags(&events, &commits, "has no linearization");
}

/// A condition failure on a version that was current for its whole call has no linearization.
#[test]
fn a_condition_failure_on_the_current_version_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    let (expect, installed) = current_gap(&events, &commits);
    let mut stuck = events[writer_of(&events, &commits, expect)].clone();
    stuck.client = "planted".into();
    stuck.expect = Some(expect);
    stuck.invoke = installed + 1;
    stuck.complete = installed + 2;
    stuck.outcome = Outcome::Fail;
    stuck.code = CONDITION_FAILED.into();
    stuck.wid = Some("planted".into());
    events.push(stuck);
    assert_flags(&events, &commits, "has no linearization");
}

/// A failed create on an item no write ever created has no linearization.
#[test]
fn a_condition_failure_on_an_absent_item_has_no_linearization() {
    let (events, _) = recorded("lin-one-item");
    let mut create = events[0].clone();
    create.outcome = Outcome::Fail;
    create.code = CONDITION_FAILED.into();
    assert_flags(&[create], &[], "has no linearization");
}

/// A failed write with a blank code fails the history-form check, so a refusal always names the code that classified it.
#[test]
fn a_failed_write_without_a_code_fails_the_form_check() {
    let (events, _) = recorded("lin-one-item");
    let mut create = events[0].clone();
    create.outcome = Outcome::Fail;
    create.code = "".into();
    assert_flags(&[create], &[], "fails without an error code");
}

/// A failed read with a blank code fails the history-form check as a failed write does.
#[test]
fn a_failed_read_without_a_code_fails_the_form_check() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = events
        .iter()
        .position(|e| e.op == Op::Read)
        .expect("a read");
    events[at].outcome = Outcome::Fail;
    events[at].ver = None;
    events[at].wid = None;
    events[at].code = "ThrottlingException".into();
    assert_clean(&events, &commits);
    events[at].code = "".into();
    assert_flags(&events, &commits, "fails without an error code");
}

/// An acknowledged `cas` whose reply reports version `expect + 1` satisfies the history-form check, and one that reports another version fails it.
#[test]
fn an_acknowledged_write_reporting_another_version_fails_the_form_check() {
    let (mut events, commits) = recorded("lin-one-item");
    for event in &mut events {
        if event.op == Op::Cas && event.outcome == Outcome::Ok {
            event.reported = event.expect.map(|expect| expect + 1);
        }
    }
    assert_clean(&events, &commits);
    let at = events
        .iter()
        .position(|e| e.op == Op::Cas && e.outcome == Outcome::Ok)
        .expect("an acknowledged write");
    for reported in [0, 2] {
        events[at].reported = events[at].expect.map(|expect| expect + reported);
        assert_flags(
            &events,
            &commits,
            "reports a version other than its expected version plus one",
        );
    }
}

/// The code rule binds a refusal alone: a write with an unknown outcome and a blank code passes the history-form check.
#[test]
fn an_unknown_write_without_a_code_passes_the_form_check() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = events
        .iter()
        .position(|e| e.op == Op::Cas && e.outcome == Outcome::Ok)
        .expect("an acknowledged write");
    events[at].outcome = Outcome::Unknown;
    events[at].code = "".into();
    assert_clean(&events, &commits);
}

/// The reported version is judged on an acknowledged `cas` alone: a `cas` with an unknown or failed outcome that carries one passes the history-form check.
#[test]
fn a_reported_version_on_an_unacknowledged_write_is_not_judged() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = events
        .iter()
        .position(|e| e.op == Op::Cas && e.outcome == Outcome::Ok)
        .expect("an acknowledged write");
    lose_reply(&mut events[at]);
    events[at].reported = events[at].expect.map(|expect| expect + 2);
    assert_clean(&events, &commits);
    let refused = events
        .iter()
        .position(|e| e.op == Op::Cas && e.outcome == Outcome::Fail)
        .expect("a refused write");
    events[refused].reported = events[refused].expect.map(|expect| expect + 2);
    assert_clean(&events, &commits);
}

/// A read of version 1 recorded with no `consistent` field, which makes it strong, that begins after version 3's write completes has no linearization, even when version 2's write has an unknown outcome.
#[test]
fn a_stale_strong_read_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut stale = events[read_of(&events, 1)].clone();
    stale.consistent = None;
    events.retain(|e| e.op != Op::Read);
    let between = writer_of(&events, &commits, 2);
    lose_reply(&mut events[between]);
    let replaced = events[writer_of(&events, &commits, 3)].complete;
    stale.invoke = replaced + 1;
    stale.complete = replaced + 2;
    events.push(stale);
    assert_flags(&events, &commits, "has no linearization");
}

/// A strong read of the absent item that begins after version 1's acknowledged write completed has no linearization.
#[test]
fn a_strong_read_of_a_created_item_as_absent_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut absent = events[read_of(&events, 1)].clone();
    absent.ver = None;
    absent.wid = None;
    absent.invoke = events[0].complete + 1;
    absent.complete = events[0].complete + 2;
    events.push(absent);
    assert_flags(&events, &commits, "has no linearization");
}

/// In a slice whose log starts above version 1, a strong read of an earlier version that begins after the first logged version's write completed has no linearization.
#[test]
fn a_stale_strong_read_below_a_slice_has_no_linearization() {
    let (mut events, mut commits) = recorded("lin-one-item");
    let wid = commits[0].wid.clone();
    commits.remove(0);
    events.retain(|e| e.wid != wid || e.op == Op::Read);
    let mut stale = events[read_of(&events, 1)].clone();
    stale.invoke = events[writer_of(&events, &commits, 2)].complete + 1;
    stale.complete = stale.invoke + 1;
    events.retain(|e| e.op != Op::Read);
    events.push(stale);
    assert_flags(&events, &commits, "has no linearization");
}

/// A strong read of version 1 that begins after a strong read of version 2 completed has no linearization, even when version 2's write has an unknown outcome and the history holds only acknowledged writes besides the two reads.
#[test]
fn descending_strong_reads_have_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    let newer = events[read_of(&events, 2)].clone();
    let mut older = events[read_of(&events, 1)].clone();
    older.invoke = newer.complete + 1;
    older.complete = newer.complete + 2;
    events.retain(|e| e.op != Op::Read && e.outcome == Outcome::Ok);
    let at = writer_of(&events, &commits, 2);
    lose_reply(&mut events[at]);
    events.extend([newer, older]);
    assert_flags(&events, &commits, "has no linearization");
}

/// An eventually consistent read of a version that completes before its predecessor's write began has no linearization: the version it returned could not yet have committed.
#[test]
fn an_eventual_read_before_its_predecessor_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    let predecessor = events[writer_of(&events, &commits, 1)].invoke;
    let at = writer_of(&events, &commits, 2);
    events[at].invoke = predecessor - 10;
    let mut early = events[read_of(&events, 2)].clone();
    early.consistent = Some(false);
    early.invoke = predecessor - 5;
    early.complete = predecessor - 4;
    events.push(early);
    assert_flags(&events, &commits, "has no linearization");
}

/// An eventually consistent read of a replaced version counts as stale and violates nothing.
#[test]
fn a_stale_eventual_read_is_counted() {
    let (mut events, commits) = recorded("lin-one-item");
    let replaced = events[writer_of(&events, &commits, 2)].complete;
    let read = read_of(&events, 1);
    events[read].consistent = Some(false);
    events[read].invoke = replaced + 1;
    events[read].complete = replaced + 2;
    let verdict = assert_clean(&events, &commits);
    let tally = &verdict.scenarios["lin-one-item"];
    assert_eq!((tally.stale_eventual_reads, tally.eventual_reads), (1, 1));
}

/// An eventually consistent read of version 1 after version 3's acknowledgment counts as stale when version 2's write has an unknown outcome.
#[test]
fn an_eventual_read_replaced_two_versions_later_is_counted() {
    let (mut events, commits) = recorded("lin-one-item");
    let between = writer_of(&events, &commits, 2);
    lose_reply(&mut events[between]);
    let replaced = events[writer_of(&events, &commits, 3)].complete;
    let read = read_of(&events, 1);
    events[read].consistent = Some(false);
    events[read].invoke = replaced + 1;
    events[read].complete = replaced + 2;
    let verdict = assert_clean(&events, &commits);
    let tally = &verdict.scenarios["lin-one-item"];
    assert_eq!((tally.stale_eventual_reads, tally.eventual_reads), (1, 1));
}

/// An eventually consistent read of a version whose write began after the read completed fails ST3.
#[test]
fn an_eventual_read_before_its_write_fails_st3() {
    let (mut events, commits) = recorded("lin-one-item");
    let begun = events[writer_of(&events, &commits, 2)].invoke;
    let read = read_of(&events, 2);
    events[read].consistent = Some(false);
    events[read].invoke = begun - 2;
    events[read].complete = begun - 1;
    assert_flags(&events, &commits, "ends before its write begins");
}

/// A read of a version above every commit fails ST3.
#[test]
fn a_read_above_every_commit_fails_st3() {
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].ver = Some(12);
    let found = violations(&events, &commits);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].contains("above every committed version"),
        "{found:#?}"
    );
}

/// A read of an image the log holds at another version fails ST3.
#[test]
fn a_read_of_another_versions_image_fails_st3() {
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].wid = commits[1].wid.clone();
    assert_flags(&events, &commits, "returned write");
}

/// A request whose interval ends before it begins is refused with that form violation alone: its write ID still counts as issued, so its commit is not reported as unrequested, and its outcome is not judged.
#[test]
fn an_inverted_interval_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 3);
    events[at].complete = events[at].invoke - 1;
    let found = violations(&events, &commits);
    assert!(
        found
            .iter()
            .all(|v| v.ends_with("completes before it begins")),
        "{found:#?}"
    );
    assert_eq!(found.len(), 1, "{found:#?}");
}

/// A write without a write ID is refused.
#[test]
fn a_write_without_a_write_id_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut anonymous = events[writer_of(&events, &commits, 3)].clone();
    anonymous.wid = None;
    events.push(anonymous);
    assert_flags(&events, &commits, "carries no write ID");
}

/// Two writes sharing one write ID are refused.
#[test]
fn a_shared_write_id_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    events.push(events[writer_of(&events, &commits, 3)].clone());
    assert_flags(&events, &commits, "is on two writes");
}

/// A `cas` without an expected version is refused.
#[test]
fn a_cas_without_an_expected_version_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut unbound = events[writer_of(&events, &commits, 3)].clone();
    unbound.wid = Some("planted".into());
    unbound.outcome = Outcome::Fail;
    unbound.code = CONDITION_FAILED.into();
    unbound.expect = None;
    events.push(unbound);
    assert_flags(&events, &commits, "carries no expected version");
}

/// An `ok` read that returns a write ID without a version is refused.
#[test]
fn a_read_with_an_image_but_no_version_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].ver = None;
    assert_flags(
        &events,
        &commits,
        "returns neither an absent item nor a version with its write ID",
    );
}

fn assert_only_out_of_range(ver: u64) {
    let (events, mut commits) = recorded("lin-one-item");
    commits[0].ver = ver;
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [format!("history: one/shard version {ver} is out of range")]
    );
}

/// A committed version 0 is refused with that form violation alone.
#[test]
fn a_zero_version_is_refused() {
    assert_only_out_of_range(0);
}

/// A committed version too large for its two successors is refused with that form violation alone.
#[test]
fn a_version_without_two_successors_is_refused() {
    assert_only_out_of_range(u64::MAX - 1);
}

/// An `ok` write or read that carries an error code is refused.
#[test]
fn a_success_with_an_error_code_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let at = writer_of(&events, &commits, 3);
    events[at].code = "ThrottlingException".into();
    assert_flags(&events, &commits, "succeeds with an error code");
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].code = "ReadTimeoutError".into();
    assert_flags(&events, &commits, "succeeds with an error code");
}

/// An `update` without a write ID is refused.
#[test]
fn an_update_without_a_write_id_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let mut anonymous = events[writer_of(&events, &commits, 3)].clone();
    anonymous.op = Op::Update;
    anonymous.wid = None;
    let expected = format!(
        "history: Update by {} on one/shard carries no write ID",
        anonymous.client
    );
    events.push(anonymous);
    assert_flags(&events, &commits, &expected);
}

/// An `ok` read of version 0 that carries a write ID is refused.
#[test]
fn a_read_of_version_zero_with_an_image_is_refused() {
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].ver = Some(0);
    assert_flags(
        &events,
        &commits,
        "returns neither an absent item nor a version with its write ID",
    );
}

/// A committed write with an unknown outcome takes effect no earlier than its invoke: moved after version 6's acknowledged completion, version 5's write has no linearization.
#[test]
fn a_committed_unknown_outcome_after_its_successor_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    events.retain(|e| e.op != Op::Read);
    let successor = events[writer_of(&events, &commits, 6)].complete;
    let at = writer_of(&events, &commits, 5);
    lose_reply(&mut events[at]);
    events[at].invoke = successor + 1;
    events[at].complete = successor + 2;
    assert_flags(&events, &commits, "has no linearization");
}

/// An `update` whose write completed before an earlier version's write began has no linearization.
#[test]
fn an_update_real_time_inversion_has_no_linearization() {
    let (mut events, commits) = recorded("lin-one-item");
    events.retain(|e| e.op != Op::Read);
    let at = writer_of(&events, &commits, 3);
    events[at].op = Op::Update;
    events[at].expect = None;
    events[at].invoke = 1;
    events[at].complete = 2;
    assert_flags(&events, &commits, "has no linearization");
}

/// A failed `update` bounds no linearization point, whatever version it names: its conditions are on named fields.
#[test]
fn a_failed_update_on_the_current_version_satisfies_the_store_contract() {
    let (mut events, commits) = recorded("lin-one-item");
    let (expect, installed) = current_gap(&events, &commits);
    let mut refused = events[writer_of(&events, &commits, expect)].clone();
    refused.op = Op::Update;
    refused.wid = Some("planted".into());
    refused.expect = Some(expect);
    refused.outcome = Outcome::Fail;
    refused.code = CONDITION_FAILED.into();
    refused.invoke = installed + 1;
    refused.complete = installed + 2;
    events.push(refused);
    assert_clean(&events, &commits);
}

/// A slice log that starts above version 1 and returns below its first version fails the consecutive-version check and is not placed.
#[test]
fn a_slice_rolled_back_below_its_first_version_fails_st1() {
    let (events, mut commits) = recorded("lin-one-item");
    let mut rollback = commits[1].clone();
    rollback.wid = Some("planted".into());
    commits.drain(..4);
    commits.push(rollback);
    assert_flags(&events, &commits, "versions 11 then 2 are not consecutive");
}

/// A fresh eventually consistent read counts as an eventual read that is not stale.
#[test]
fn a_fresh_eventual_read_is_counted() {
    let (mut events, commits) = recorded("lin-one-item");
    let read = read_of(&events, 1);
    events[read].consistent = Some(false);
    let verdict = assert_clean(&events, &commits);
    let tally = &verdict.scenarios["lin-one-item"];
    assert_eq!((tally.stale_eventual_reads, tally.eventual_reads), (0, 1));
}

/// A slice that drops version 1 from the log, keeping the writes after it.
fn slice_from_version_2() -> (Vec<Event<'static>>, Vec<Commit<'static>>) {
    let (mut events, mut commits) = recorded("lin-one-item");
    let wid = commits.remove(0).wid;
    events.retain(|e| e.wid != wid || e.op == Op::Read);
    (events, commits)
}

/// In a slice from version 2, a strong read of version 1 that overlaps version 2's write, and an eventual read of version 1 after it, satisfy the contract.
#[test]
fn reads_below_a_slice_inside_their_bounds_satisfy_the_store_contract() {
    let (mut events, commits) = slice_from_version_2();
    let writer = events[writer_of(&events, &commits, 2)].clone();
    let mut overlapping = events[read_of(&events, 1)].clone();
    overlapping.invoke = writer.invoke;
    overlapping.complete = writer.complete;
    let mut eventual = overlapping.clone();
    eventual.consistent = Some(false);
    eventual.invoke = writer.complete + 1;
    eventual.complete = writer.complete + 2;
    events.retain(|e| e.op != Op::Read);
    events.extend([overlapping, eventual]);
    assert_clean(&events, &commits);
}

/// In a slice from version 3, a strong read of version 1 that begins after version 3's write completed has no linearization.
#[test]
fn a_stale_strong_read_two_below_a_slice_has_no_linearization() {
    let (mut events, mut commits) = slice_from_version_2();
    let wid = commits.remove(0).wid;
    events.retain(|e| e.wid != wid || e.op == Op::Read);
    let mut stale = events[read_of(&events, 1)].clone();
    stale.invoke = events[writer_of(&events, &commits, 3)].complete + 1;
    stale.complete = stale.invoke + 1;
    events.retain(|e| e.op != Op::Read);
    events.push(stale);
    assert_flags(&events, &commits, "has no linearization");
}

/// In a slice from version 2, a condition failure on version 1 that begins after a strong read of version 1 and ends before version 2's write begins has no linearization.
#[test]
fn a_condition_failure_on_the_version_below_a_slice_has_no_linearization() {
    let (mut events, commits) = slice_from_version_2();
    let begun = events[writer_of(&events, &commits, 2)].invoke;
    let mut current = events[read_of(&events, 1)].clone();
    assert!(
        current.complete + 2 < begun,
        "the read of version 1 ends before version 2's write begins"
    );
    events.retain(|e| e.op != Op::Read && e.outcome == Outcome::Ok);
    let mut stuck = events[writer_of(&events, &commits, 2)].clone();
    stuck.wid = Some("planted".into());
    stuck.outcome = Outcome::Fail;
    stuck.code = CONDITION_FAILED.into();
    stuck.expect = Some(1);
    stuck.invoke = current.complete + 1;
    stuck.complete = current.complete + 2;
    current.invoke = current.complete - 1;
    events.extend([current, stuck]);
    assert_flags(&events, &commits, "has no linearization");
}

/// A read below a slice that returns an image the log holds at a logged version fails ST3.
#[test]
fn a_read_below_a_slice_of_a_logged_image_fails_st3() {
    let (mut events, commits) = slice_from_version_2();
    let mut read = events[read_of(&events, 1)].clone();
    read.wid = commits[0].wid.clone();
    events.retain(|e| e.op != Op::Read);
    events.push(read);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [format!(
            "ST3: one/shard read of version 1 by c1 returned write {:?}, committed at Some((\"one/shard\", 2))",
            commits[0].wid.as_deref()
        )],
        "{found:#?}"
    );
}

/// A read below a slice that returns the write ID of a recorded write that failed fails ST3: the write committed nothing.
#[test]
fn a_read_below_a_slice_of_a_failed_write_fails_st3() {
    let (mut events, commits) = slice_from_version_2();
    let failed = events
        .iter()
        .find(|e| e.op == Op::Cas && e.outcome == Outcome::Fail)
        .expect("a condition failure")
        .wid
        .clone();
    let mut read = events[read_of(&events, 1)].clone();
    read.wid = failed;
    events.retain(|e| e.op != Op::Read);
    events.push(read);
    assert_flags(&events, &commits, "returned write");
}

/// In a slice from version 4, a strong read of version 1 that begins after a strong read of version 2 completed has no linearization: version 1 was replaced before the read began.
#[test]
fn a_descending_pair_of_strong_reads_below_a_slice_has_no_linearization() {
    let (mut events, mut commits) = slice_from_version_2();
    for _ in 0..2 {
        let wid = commits.remove(0).wid;
        events.retain(|e| e.wid != wid || e.op == Op::Read);
    }
    let second = events[read_of(&events, 2)].clone();
    let mut late = events[read_of(&events, 1)].clone();
    late.invoke = second.complete + 1;
    late.complete = late.invoke + 1;
    events.push(late);
    assert_flags(&events, &commits, "has no linearization");
}

/// The linearization sizes its slots by the logged range and the reads below it, so a slice logged at `u64::MAX - 2` with a read of version 1 is judged in a few slots.
#[test]
fn a_slice_at_the_highest_version_with_a_read_of_version_1_satisfies_the_store_contract() {
    let (events, commits) = recorded("lin-one-item");
    let mut create = events[writer_of(&events, &commits, 2)].clone();
    create.expect = Some(u64::MAX - 3);
    let mut read = events[read_of(&events, 1)].clone();
    read.wid = Some("planted".into());
    let commits = [Commit {
        key: "one/shard".into(),
        ver: u64::MAX - 2,
        wid: create.wid.clone(),
    }];
    assert_clean(&[read, create], &commits);
}

/// In a slice from version 4, a condition failure on version 1 between two strong reads of version 1 has no linearization: version 1 was current throughout the failure.
#[test]
fn a_condition_failure_two_below_a_slice_between_reads_of_its_version_has_no_linearization() {
    let (mut events, mut commits) = slice_from_version_2();
    for _ in 0..2 {
        let wid = commits.remove(0).wid;
        events.retain(|e| e.wid != wid || e.op == Op::Read);
    }
    let before = events[read_of(&events, 1)].clone();
    let mut stuck = events[writer_of(&events, &commits, 4)].clone();
    stuck.wid = Some("planted".into());
    stuck.outcome = Outcome::Fail;
    stuck.code = CONDITION_FAILED.into();
    stuck.expect = Some(1);
    stuck.invoke = before.complete + 1;
    stuck.complete = before.complete + 2;
    let mut after = before.clone();
    after.invoke = stuck.complete + 1;
    after.complete = stuck.complete + 2;
    events.retain(|e| e.op != Op::Read);
    events.extend([before, stuck, after]);
    assert_flags(&events, &commits, "has no linearization");
}

/// A read above every committed version produces only its ST3 line; the reads of the same write ID below the slice pass.
#[test]
fn a_read_above_a_slice_leaves_the_reads_of_its_image_below_it_judged_on_their_own() {
    let (mut events, commits) = slice_from_version_2();
    let read = read_of(&events, 1);
    events[read].ver = Some(12);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        ["ST3: one/shard read of version 12 by c1 is above every committed version"],
        "{found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

/// In a slice from version 3, a condition failure on version 1 between two strong reads of version 1 has no linearization: version 1 is the one below the base, so the failure bounds the base's point.
#[test]
fn a_condition_failure_one_below_a_slice_between_reads_of_its_version_has_no_linearization() {
    let (mut events, mut commits) = slice_from_version_2();
    let wid = commits.remove(0).wid;
    events.retain(|e| e.wid != wid || e.op == Op::Read);
    let before = events[read_of(&events, 1)].clone();
    let mut stuck = events[writer_of(&events, &commits, 3)].clone();
    stuck.wid = Some("planted".into());
    stuck.outcome = Outcome::Fail;
    stuck.code = CONDITION_FAILED.into();
    stuck.expect = Some(1);
    stuck.invoke = before.complete + 1;
    stuck.complete = before.complete + 2;
    let mut after = before.clone();
    after.invoke = stuck.complete + 1;
    after.complete = stuck.complete + 2;
    events.retain(|e| e.op != Op::Read);
    events.extend([before, stuck, after]);
    assert_flags(&events, &commits, "has no linearization");
}

/// A malformed read produces only its form violation; well-formed reads of the same write ID pass.
#[test]
fn a_refused_read_leaves_the_reads_of_its_image_judged_on_their_own() {
    let (mut events, commits) = slice_from_version_2();
    let read = read_of(&events, 1);
    events[read].ver = None;
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [
            "history: Read by c1 on one/shard returns neither an absent item nor a version with its write ID"
        ],
        "{found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

/// Reads of version 1 must agree on the write ID even when the log slice starts at version 2.
#[test]
fn reads_below_a_slice_of_two_images_of_one_version_have_no_linearization() {
    let (mut events, commits) = slice_from_version_2();
    let mut other = events[read_of(&events, 1)].clone();
    other.wid = Some("planted".into());
    events.push(other);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [format!(
            "ST1/ST3: one/shard has no linearization: reads of version 1 returned writes {} and planted",
            events[read_of(&events, 1)]
                .wid
                .as_deref()
                .expect("a read image")
        )],
        "{found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

/// Below a slice, one write ID read at two versions is a write committed twice.
#[test]
fn reads_below_a_slice_of_one_image_at_two_versions_fail_st1() {
    let (mut events, mut commits) = slice_from_version_2();
    let wid = commits.remove(0).wid;
    events.retain(|e| e.wid != wid || e.op == Op::Read);
    let mut first = events[read_of(&events, 1)].clone();
    let mut second = events[read_of(&events, 2)].clone();
    first.wid = Some("planted".into());
    second.wid = Some("planted".into());
    events.retain(|e| e.op != Op::Read);
    events.extend([first, second]);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [
            "ST1: one/shard read of version 2 by c1 returned write planted, which a read of one/shard version 1 also returned"
        ],
        "{found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

/// Below the slices of two keys, one write ID read on both is a write committed on two keys.
#[test]
fn reads_below_the_slices_of_two_keys_of_one_image_fail_st1() {
    let (mut events, mut commits) = slice_from_version_2();
    let mut create = events[writer_of(&events, &commits, 2)].clone();
    create.key = "two/shard".into();
    create.wid = Some("second".into());
    commits.push(Commit {
        key: "two/shard".into(),
        ver: 2,
        wid: Some("second".into()),
    });
    let mut first = events[read_of(&events, 1)].clone();
    first.wid = Some("planted".into());
    let mut other = first.clone();
    other.key = "two/shard".into();
    events.retain(|e| e.op != Op::Read);
    events.extend([create, first, other]);
    let found = violations(&events, &commits);
    assert_eq!(
        found,
        [
            "ST1: two/shard read of version 1 by c1 returned write planted, which a read of one/shard version 1 also returned"
        ],
        "{found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

fn campaign_dir(name: &str) -> std::path::PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("store_history-{}-{name}", std::process::id()));
    if dir.exists() {
        std::fs::remove_dir_all(&dir).expect("remove the previous campaign directory");
    }
    std::fs::create_dir_all(&dir).expect("create the campaign directory");
    dir
}

/// A campaign whose writes and reads of one key sit in two files satisfies every check, which holds only when the files are checked as one history.
#[test]
fn a_campaign_split_across_files_satisfies_the_store_contract() {
    let dir = campaign_dir("split");
    let (reads, writes): (Vec<&str>, Vec<&str>) = LIN_ONE_ITEM
        .lines()
        .partition(|line| line.contains("\"op\": \"read\""));
    std::fs::write(dir.join("reads.jsonl"), reads.join("\n")).expect("write reads");
    std::fs::write(dir.join("writes.jsonl"), writes.join("\n")).expect("write writes");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    let (counts, verdict) = check_campaign(&dir);
    assert_eq!(counts.len(), 2);
    assert!(verdict.violations.is_empty(), "{:#?}", verdict.violations);
}

/// A campaign whose second file holds a strong read of version 1 after the last write's acknowledgment has no linearization once the files are checked as one history.
#[test]
fn a_campaign_split_across_files_checks_them_as_one_history() {
    let dir = campaign_dir("inversion");
    let (events, commits) = recorded("lin-one-item");
    let replaced = events[writer_of(&events, &commits, 11)].complete;
    let stale = LIN_ONE_ITEM
        .lines()
        .find(|line| line.contains("\"op\": \"read\"") && line.contains("\"ver\": 1,"))
        .expect("a read of version 1")
        .to_owned();
    let read = read_of(&events, 1);
    let stale = stale
        .replace(
            &events[read].invoke.to_string(),
            &(replaced + 1).to_string(),
        )
        .replace(
            &events[read].complete.to_string(),
            &(replaced + 2).to_string(),
        );
    std::fs::write(dir.join("a.jsonl"), LIN_ONE_ITEM).expect("write history");
    std::fs::write(dir.join("b.jsonl"), stale).expect("write stale read");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    let (_, verdict) = check_campaign(&dir);
    assert!(
        verdict
            .violations
            .iter()
            .any(|v| v.contains("has no linearization")),
        "{:#?}",
        verdict.violations
    );
}

/// A campaign directory entry other than a `*.jsonl` file is refused.
#[test]
#[should_panic(expected = "is not a history file")]
fn a_campaign_with_another_entry_is_refused() {
    let dir = campaign_dir("stray");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    std::fs::write(dir.join("history.jsonl"), LIN_ONE_ITEM).expect("write history");
    std::fs::write(dir.join("reads.json"), "").expect("write stray entry");
    check_campaign(&dir);
}

/// A campaign directory with a commit log and no history is refused.
#[test]
#[should_panic(expected = "holds no history")]
fn a_campaign_without_histories_is_refused() {
    let dir = campaign_dir("empty");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    check_campaign(&dir);
}

/// A campaign history file with no event is refused.
#[test]
#[should_panic(expected = "holds no event")]
fn a_campaign_with_an_empty_history_is_refused() {
    let dir = campaign_dir("blank");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    std::fs::write(dir.join("history.jsonl"), "").expect("write history");
    check_campaign(&dir);
}

/// Splits that put every request in its own run, or spread the work over a few runs and many write ID shards.
const SPLITS: [Split; 3] = [
    Split {
        span: 61,
        run: 1,
        uses_per_shard: 1,
    },
    Split {
        span: 257,
        run: 7,
        uses_per_shard: 3,
    },
    Split {
        span: 4096,
        run: 50,
        uses_per_shard: 16,
    },
];

/// A verdict's violations and per-scenario counts as one comparable text.
fn verdict_text(verdict: &Verdict) -> String {
    format!("{:#?}\n{:#?}", verdict.violations, verdict.scenarios)
}

/// Both recorded slices with violations of most kinds planted: a write ID on two writes, a write with no write ID, a failed write that committed, a commit no request issued, an out-of-range version, a stale strong read, a stale eventually consistent read and a field-scoped update.
fn planted_history() -> (Vec<Event<'static>>, Vec<Commit<'static>>) {
    let (mut events, mut commits) = recorded("lin-one-item");
    let (retry_events, retry_commits) = recorded("client-retry");
    let twice = events[writer_of(&events, &commits, 3)].clone();
    events.push(twice);
    let mut anonymous = events[writer_of(&events, &commits, 4)].clone();
    anonymous.wid = None;
    events.push(anonymous);
    let at = writer_of(&events, &commits, 5);
    events[at].outcome = Outcome::Fail;
    events[at].code = "ThrottlingException".into();
    let at = writer_of(&events, &commits, 6);
    events[at].op = Op::Update;
    let replaced = events[writer_of(&events, &commits, 8)].complete;
    let mut stale = events[read_of(&events, 2)].clone();
    stale.invoke = replaced + 1;
    stale.complete = replaced + 2;
    events.push(stale);
    let read = read_of(&events, 1);
    events[read].consistent = Some(false);
    events[read].invoke = replaced + 3;
    events[read].complete = replaced + 4;
    commits.push(Commit {
        key: "untouched".into(),
        ver: 1,
        wid: Some("planted".into()),
    });
    commits.push(Commit {
        key: "range/k".into(),
        ver: 0,
        wid: events[0].wid.clone(),
    });
    events.extend(retry_events);
    commits.extend(retry_commits);
    (events, commits)
}

/// The checks give the same violations, in the same order, and the same counts however the work is split into runs and write ID shards.
#[test]
fn every_split_of_a_history_gives_the_same_verdict() {
    let (events, commits) = planted_history();
    let verdict = check(&events, &commits);
    for marker in [
        "is on two writes",
        "carries no write ID",
        "ST4: ThrottlingException write",
        "which no recorded client issued",
        "is out of range",
        "has no linearization",
        "ST4: ConditionalCheckFailedException write",
    ] {
        assert!(
            verdict.violations.iter().any(|v| v.contains(marker)),
            "expected a violation containing {marker:?}: {:#?}",
            verdict.violations
        );
    }
    let expected = verdict_text(&verdict);
    for split in SPLITS {
        assert_eq!(
            verdict_text(&check_with(&events, &commits, split)),
            expected,
            "{split:?}"
        );
    }
}

/// Violations come in the order of the checks: the requests' form, then each commit log entry's range and write ID in log order, then each key's version order, then writes, then reads, then each key's linearization.
#[test]
fn violations_follow_the_order_of_the_checks() {
    let (mut events, mut commits) = planted_history();
    for ver in [1, 3] {
        commits.push(Commit {
            key: "gap/k".into(),
            ver,
            wid: Some(format!("gap{ver}").into()),
        });
    }
    let mut above = events[read_of(&events, 1)].clone();
    above.ver = Some(99);
    events.push(above);
    let phases = [
        "history: write ID",
        "history: Cas",
        "ST7: untouched",
        "history: range/k",
        "ST1: gap/k versions 1 then 3",
        "ST4: ThrottlingException",
        "ST3: one/shard read of version 99",
        "ST1/ST3: one/shard has no linearization",
    ];
    let found = check(&events, &commits).violations;
    let positions: Vec<usize> = phases
        .iter()
        .map(|phase| {
            found
                .iter()
                .position(|v| v.starts_with(phase))
                .unwrap_or_else(|| panic!("no violation starts with {phase:?}: {found:#?}"))
        })
        .collect();
    assert!(
        positions.windows(2).all(|pair| pair[0] < pair[1]),
        "{positions:?}: {found:#?}"
    );
    for split in SPLITS {
        assert_eq!(
            check_with(&events, &commits, split).violations,
            found,
            "{split:?}"
        );
    }
}

fn write_both_slices(name: &str) -> std::path::PathBuf {
    let dir = campaign_dir(name);
    let retry = include_str!("store_histories/client-retry.jsonl");
    let spaced: String = retry
        .lines()
        .enumerate()
        .map(|(at, line)| match at % 3 {
            0 => format!("{line}\r\n\r\n"),
            1 => format!("{line}\r\n \t\n"),
            _ => format!("{line}\r\n"),
        })
        .collect();
    let commits = [
        LIN_ONE_ITEM_COMMITS,
        include_str!("store_histories/client-retry.commits.jsonl"),
    ]
    .concat();
    std::fs::write(dir.join("a.jsonl"), LIN_ONE_ITEM).expect("write history a");
    std::fs::write(dir.join("b.jsonl"), spaced).expect("write history b");
    std::fs::write(dir.join("commits.jsonl"), commits).expect("write commits");
    dir
}

/// A campaign read in parts of any size gives the verdict of its histories checked in memory: lines that cross part ends, CRLF line ends and blank lines read as they do from a whole file.
#[test]
fn every_split_of_a_campaign_gives_the_verdict_of_its_histories() {
    let dir = write_both_slices("splits");
    let (mut events, mut commits) = recorded("lin-one-item");
    let (retry_events, retry_commits) = recorded("client-retry");
    events.extend(retry_events);
    commits.extend(retry_commits);
    let expected = check(&events, &commits);
    assert_eq!(expected.violations.len(), 1, "{:#?}", expected.violations);
    let expected = verdict_text(&expected);
    let (counts, verdict) = check_campaign(&dir);
    assert_eq!(verdict_text(&verdict), expected);
    for split in SPLITS {
        let (split_counts, verdict) = check_campaign_with(&dir, split);
        assert_eq!(split_counts, counts, "{split:?}");
        assert_eq!(verdict_text(&verdict), expected, "{split:?}");
    }
}

/// The panic message of checking the campaign `dir` under `split`.
fn campaign_panic(dir: &Path, split: Split) -> String {
    let payload = std::panic::catch_unwind(|| check_campaign_with(dir, split))
        .expect_err("the campaign is refused");
    match payload.downcast::<String>() {
        Ok(message) => *message,
        Err(payload) => (*payload.downcast::<&str>().expect("a text panic")).to_owned(),
    }
}

/// A line that does not parse is refused with its line number in the whole file in every split, including parts that start after the file's first byte.
#[test]
fn a_line_that_does_not_parse_is_named_by_its_file_line_in_every_split() {
    let dir = campaign_dir("bad-line");
    let mut lines: Vec<&str> = LIN_ONE_ITEM.lines().collect();
    lines.insert(40, "{\"op\": \"read\"");
    std::fs::write(dir.join("h.jsonl"), lines.join("\n")).expect("write history");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    for split in [Split::DEFAULT].into_iter().chain(SPLITS) {
        let message = campaign_panic(&dir, split);
        assert!(message.contains("h.jsonl:41: "), "{split:?}: {message}");
    }
}

/// A byte that is not UTF-8 refuses its file as unreadable text in every split, even when an earlier line of the file does not parse, in the same part or another.
#[test]
fn a_non_text_byte_refuses_the_file_before_an_earlier_bad_line_in_every_split() {
    let dir = campaign_dir("not-text");
    let mut bytes = Vec::new();
    for (at, line) in LIN_ONE_ITEM.lines().enumerate() {
        bytes.extend_from_slice(if at == 1 { b"{" } else { line.as_bytes() });
        bytes.push(b'\n');
    }
    bytes.extend_from_slice(b"{\"op\": \"\xff\"}\n");
    std::fs::write(dir.join("h.jsonl"), bytes).expect("write history");
    std::fs::write(dir.join("commits.jsonl"), LIN_ONE_ITEM_COMMITS).expect("write commits");
    for split in [Split::DEFAULT].into_iter().chain(SPLITS) {
        let message = campaign_panic(&dir, split);
        assert!(
            message.ends_with("h.jsonl: stream did not contain valid UTF-8"),
            "{split:?}: {message}"
        );
    }
}

/// Every history of the campaign directory `STORE_HISTORY_DIR`, merged into one history on the campaign's monotonic clock, satisfies every check; the run prints each scenario's error-code tallies, its eventually consistent stale reads and its unjudged field conditions.
#[test]
#[ignore = "reads the recorded campaign STORE_HISTORY_DIR names; run it with --ignored"]
fn campaign_histories_satisfy_the_store_contract() {
    let dir = std::env::var_os("STORE_HISTORY_DIR").expect("STORE_HISTORY_DIR names a campaign");
    assert!(
        Path::new(&dir).is_absolute(),
        "STORE_HISTORY_DIR {} is an absolute path",
        Path::new(&dir).display()
    );
    let (counts, verdict) = check_campaign(Path::new(&dir));
    for (path, events) in &counts {
        println!("{path}: {events} events");
    }
    for (scenario, tally) in &verdict.scenarios {
        println!(
            "{scenario}: committed {:?}, uncommitted {:?}, stale eventual reads {}/{}, unjudged field conditions {}",
            tally.committed_codes,
            tally.uncommitted_codes,
            tally.stale_eventual_reads,
            tally.eventual_reads,
            tally.unjudged_field_conditions
        );
    }
    assert!(verdict.violations.is_empty(), "{:#?}", verdict.violations);
}
