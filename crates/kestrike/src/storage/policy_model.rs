//! Loom kernel for policy membership across reuse: a retirement parked
//! without the pool gate, the last right's release, service's sighting and
//! return, and the claim and bind of the slot's next incarnation, over
//! every schedule the search reaches within the recorded preemption bound.
//!
//! The list code under test is the `policy` module's [`Queue`], called
//! unchanged over the model's [`Slot`] records, and every write of the
//! slot's word goes through the production transitions of the `word`
//! module or the queue's bit writes, which are the `policy` module's
//! production policy-bit bodies run over the loom word. Model
//! substitutions:
//!
//! - The pool gate is a loom mutex over [`Gate`], holding the slot states,
//!   the `next` links and the one domain; every gate-owned value the
//!   protocol reads lives there or in a slot's `prev`, which only the
//!   mutex's holder touches, so the mutex is the gate's acquire and release.
//! - A [`Slot`]'s `word` is its lifetime word: incarnation, flags, visited
//!   bit, policy bits and count, written without the gate as in production,
//!   and by the gate holder's policy bit writes. The retirer parks with the
//!   production park exchange, conditioned on the incarnation it was issued
//!   for, and releases its right with a release `fetch_sub`; service sights
//!   the word with one acquire load.
//! - Service is the production decision reduced to one slot: a flag always
//!   describes the incarnation beside it, so a flagged resident is held while
//!   the count is nonzero, and that hold detaches a linked member; a zero
//!   count returns the block, clearing every flag and policy bit with one
//!   read-modify-write whose replaced word the queue's clear reads. Claim
//!   installs the next incarnation from the `Free` value, checked against a
//!   tiny maximum, and quarantines on exhaustion; bind links at the head.
//!
//! Two slots, one domain: slot 0 cycles through retirement and reuse while
//! slot 1 stays a member, so every unlink repairs a real neighbour. After
//! releasing its right the retirer parks once more for incarnation zero, an
//! occupant before the first, as a stale transfer would, so the park can land
//! on either incarnation's word. After every gate hold the kernel checks the
//! domain's structure and that no `Free` or quarantined slot has a link or a
//! policy bit, and at the end that the first incarnation unlinked at most
//! once and the second, when bound, is linked with a clear history.
//!
//! Negative control: a park without the incarnation compare lets the stale
//! park flag a word that holds another incarnation, so service returns the
//! reused slot, unlinking it, or the claim meets a flagged free word.
//!
//! Three further kernels cover the word's gate-free writers:
//!
//! - Visited versus reuse: a reader that validated incarnation one retains
//!   through the production transition, setting the visited bit in the
//!   exchange, and releases; the anchor's holder releases too; service,
//!   under the gate, returns the block once it reads the count at zero and
//!   claims incarnation two, whose publication installs its anchor. The word
//!   incarnation two carries has the bit clear. Negative control: a retain
//!   whose expected word omits the incarnation lands on incarnation two and
//!   records its hit there.
//! - Visited versus hand clear: starting clear and visited, a retain races
//!   selection, which loads the word and, when it reads visited, clears the
//!   bit with one `fetch_and`, as production's selection does. The retain's
//!   right is never lost to the clear, the bit is set unless the clear
//!   followed the retain, and the policy bits, which only the gate holder
//!   writes, are unchanged.
//! - Policy bit writes versus lock-free writers: under the gate the queue
//!   takes a member off its list and releases the mark, while a reader
//!   retains and releases a right and a parker parks the current
//!   incarnation. The tests check that policy writes, a linked member's
//!   mark, and a retirement carrying the mark preserve lock-free writers'
//!   bits:
//!   the word ends with the anchor, the visited and abandoned bits and
//!   `DETACHED` alone among the policy bits.
//!   Each kernel counts, outside the model, the executions in which the
//!   retain's exchange failed on a word whose policy bits had changed, and
//!   asserts the count is nonzero. Negative controls: a load and a plain
//!   store in place of one bit write loses a racing write, for the move of
//!   a linked member's mark, and, in the detach kernel, for the set of a
//!   detached member's `EVICTED` and for its clear.
//!
//!   The kernel's word writers are the retain, the release, the park and
//!   the queue. The anchor release's exchange and the claim's install
//!   exchange retry from the value they find, as the retain does, so a
//!   policy write between their load and their exchange costs them a retry
//!   and keeps their bits. `link`'s write runs before the threads spawn;
//!   it is one `fetch_or`, as the detached slot's mark is, which the kernel
//!   races.
//!
//! A last kernel races eviction against invalidation on one key: selection
//! under the model's pool gate, the exact commit and the invalidation's
//! clear under the shard gate, each winner's retirement with one pool-gate
//! try that parks on the slot's word when busy, and the eviction mark
//! applied by one try or by a later hold. Exactly one retirement, one unlink
//! and one detach follow; the other member stays linked. It calls
//! production [`Queue`] for every list change, including `mark_evicted`.
//!
//! The membership kernel with reuse and the visited-versus-reuse kernel
//! count, outside the model, the executions that reach their race: a stale
//! park reading the reused word, and a retain meeting incarnation two. Each
//! positive run asserts its count is nonzero.
//!
//! Run with
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release policy_model`.

use std::sync::Arc;
use std::sync::atomic::Ordering;

use loom::sync::Mutex;
use loom::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize};
use loom::thread;

use super::credit::PlainBits;
use super::policy::{
    Domain, Node, POLICY_NONE, PolicySlot, Queue, check_domain, clear_policy_bits,
    move_policy_bits, policy_word, set_policy_bits,
};
use super::word::{
    self, ABANDONED, DETACHED, FLAGS, INCARNATION, LINKED, POLICY, REF, RETIRED, VISITED,
};

const PREEMPTION_BOUND: usize = 9;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum State {
    Free,
    Resident,
    Quarantined,
}

/// One slot's record in the model: its lifetime word, over a loom atomic,
/// and its `prev` link, which only the model gate's holder touches, so a
/// std atomic adds no schedule. The policy's reads and bit writes are the
/// production bodies `Record` runs; the bit write `plain` names runs over
/// the negative control's load and plain store in place of its
/// read-modify-write.
struct Slot {
    word: AtomicU64,
    prev: std::sync::atomic::AtomicU32,
    plain: Plain,
}

impl Slot {
    fn new(word: u64, plain: Plain) -> Self {
        Self {
            word: AtomicU64::new(word),
            prev: std::sync::atomic::AtomicU32::new(POLICY_NONE),
            plain,
        }
    }
}

/// Which policy bit write, if any, a negative control runs over a load and
/// a plain store.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Plain {
    Off,
    Set,
    Clear,
    Move,
}

impl PolicySlot for Slot {
    fn word(&self) -> u64 {
        policy_word(&self.word)
    }

    fn set_bits(&self, bits: u64) {
        if self.plain == Plain::Set {
            set_policy_bits(&PlainBits(&self.word), bits);
        } else {
            set_policy_bits(&self.word, bits);
        }
    }

    fn clear_bits(&self, bits: u64) {
        if self.plain == Plain::Clear {
            clear_policy_bits(&PlainBits(&self.word), bits);
        } else {
            clear_policy_bits(&self.word, bits);
        }
    }

    fn move_bits(&self, from: u64, to: u64) {
        if self.plain == Plain::Move {
            move_policy_bits(&PlainBits(&self.word), from, to);
        } else {
            move_policy_bits(&self.word, from, to);
        }
    }

    fn prev(&self) -> u32 {
        self.prev.load(Ordering::Relaxed)
    }

    fn set_prev(&self, prev: u32) {
        self.prev.store(prev, Ordering::Relaxed);
    }
}

/// Every gate-owned value of the two slots and their domain besides the
/// slots' `prev` links.
struct Gate {
    state: [State; 2],
    next: [u32; 2],
    domain: Domain,
    /// Unlinks of slot 0's first incarnation by an observer.
    first_detached: usize,
}

impl Gate {
    fn queue<'a>(&'a mut self, slots: &'a [Slot]) -> Queue<'a, Slot> {
        Queue::new(slots, &mut self.next, &mut self.domain)
    }

    /// The structural invariants every hold must leave: the domain's own,
    /// no link or policy bit on a slot that is not resident, and at most
    /// one unlink of the first incarnation.
    fn check(&mut self, slots: &[Slot]) {
        let nodes = self.queue(slots).nodes();
        check_domain(&nodes, &self.domain, |_| true);
        for (state, node) in self.state.iter().zip(&nodes) {
            if *state != State::Resident {
                assert_eq!(
                    *node,
                    Node::CLEAR,
                    "a free slot with a link or a policy bit"
                );
            }
        }
        assert!(self.first_detached <= 1, "an incarnation unlinked twice");
    }
}

struct Shared {
    gate: Mutex<Gate>,
    /// Slot 0, whose word the retirer parks on and releases, and slot 1,
    /// which stays a member.
    slots: [Slot; 2],
}

impl Shared {
    /// Slot 0's lifetime word.
    fn word(&self) -> &AtomicU64 {
        &self.slots[0].word
    }
}

/// Parks an obligation for `incarnation` of slot 0 without the gate:
/// the production exchange, or with `compare` off the control's park that
/// sets the flag whatever incarnation the word holds. Returns the
/// incarnation of the word the park last read.
fn park(shared: &Shared, incarnation: u32, compare: bool) -> u32 {
    let mut current = shared.word().load(Ordering::Relaxed);
    loop {
        let seen = if compare {
            incarnation
        } else {
            word::incarnation(current)
        };
        let Some(next) = word::parked(current, seen, 0) else {
            return word::incarnation(current);
        };
        match shared
            .word()
            .compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed)
        {
            Ok(_) => return word::incarnation(current),
            Err(seen) => current = seen,
        }
    }
}

/// One service visit of slot 0, then a claim and bind if it is free.
fn service(shared: &Shared, maximum: u32) {
    let mut gate = shared.gate.lock().unwrap();
    let slots = &shared.slots;
    let sighted = shared.word().load(Ordering::Acquire);
    if sighted & ABANDONED != 0 && gate.state[0] == State::Resident {
        if word::refs(sighted) != 0 {
            if gate.queue(slots).detach(0) && word::incarnation(sighted) == 1 {
                gate.first_detached += 1;
            }
        } else {
            // The return: one read-modify-write clears every flag and
            // policy bit, and the slot leaves the list or the count from
            // the bits it replaced.
            let previous = shared
                .word()
                .fetch_and(!(FLAGS | VISITED | POLICY), Ordering::Relaxed);
            gate.queue(slots).clear(0, 1, previous);
            gate.state[0] = State::Free;
        }
    }
    let mut free_flagged = false;
    if gate.state[0] == State::Free {
        let free = shared.word().load(Ordering::Relaxed);
        match word::incarnation(free)
            .checked_add(1)
            .filter(|&next| next <= maximum)
        {
            Some(next) => {
                free_flagged = shared
                    .word()
                    .compare_exchange(
                        free & INCARNATION,
                        u64::from(next),
                        Ordering::Release,
                        Ordering::Relaxed,
                    )
                    .is_err();
                if !free_flagged {
                    gate.state[0] = State::Resident;
                    gate.queue(slots).link(0);
                }
            }
            None => gate.state[0] = State::Quarantined,
        }
    }
    gate.check(slots);
    drop(gate);
    // Asserted after the gate is released: a panic under a loom mutex guard
    // aborts the model instead of reporting.
    assert!(!free_flagged, "a stale park flagged a free slot");
}

fn model(maximum: u32, compare: bool) {
    // Executions in which the stale park read the reused word, counted
    // outside the model so the search is known to reach that race.
    let stale_on_reuse = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reached = Arc::clone(&stale_on_reuse);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let reached = Arc::clone(&reached);
        let slots = [
            Slot::new(1 | REF, Plain::Off),
            Slot::new(1 | REF, Plain::Off),
        ];
        let mut gate = Gate {
            state: [State::Resident; 2],
            next: [POLICY_NONE; 2],
            domain: Domain::EMPTY,
            first_detached: 0,
        };
        gate.queue(&slots).link(1);
        gate.queue(&slots).link(0);
        let shared = Arc::new(Shared {
            gate: Mutex::new(gate),
            slots,
        });
        let retirer = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                park(&shared, 1, compare);
                shared.word().fetch_sub(REF, Ordering::Release);
                // A stale transfer for an earlier occupant parks late; the
                // yield lets service run between the release and the park.
                thread::yield_now();
                if park(&shared, 0, compare) == 2 {
                    reached.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
            })
        };
        // Without a scheduling point before each visit loom runs both
        // visits before the retirer in every execution it explores; the
        // yields let the retirer's writes land before, between and after
        // them.
        for _ in 0..2 {
            thread::yield_now();
            service(&shared, maximum);
        }
        retirer.join().unwrap();
        service(&shared, maximum);
        service(&shared, maximum);
        let mut gate = shared.gate.lock().unwrap();
        gate.check(&shared.slots);
        // The obligation is serviced by now: the first incarnation is gone
        // and was unlinked at most once, slot 1 is untouched, and slot 0 is
        // the second incarnation, linked with a clean word, or quarantined.
        assert_eq!(gate.state[1], State::Resident);
        assert_eq!(
            shared.slots[1].word.load(Ordering::Relaxed),
            1 | REF | LINKED
        );
        let current = shared.word().load(Ordering::Relaxed);
        match maximum {
            1 => assert_eq!(gate.state[0], State::Quarantined),
            _ => {
                assert!(
                    gate.state[0] == State::Resident
                        && current == 2 | LINKED
                        && gate.domain.head == 0,
                    "a stale park unlinked the reused slot"
                );
            }
        }
        assert_eq!(gate.domain.detached, 0);
    });
    if maximum > 1 {
        assert!(
            stale_on_reuse.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "no explored execution parked stale on the reused word"
        );
    }
}

#[test]
fn unlink_versus_relink_after_reuse() {
    model(2, true);
}

#[test]
fn an_exhausted_incarnation_never_links() {
    model(1, true);
}

#[test]
#[should_panic(expected = "a stale park")]
fn negative_control_a_park_without_the_incarnation_compare_unlinks_the_reused_slot() {
    model(2, false);
}

/// Parks of one current incarnation racing each other, and with
/// `retirement` the gate holder's retirement too, as production counts
/// them: each park counts itself, then gives its entry back unless its own
/// exchange set `ABANDONED`, and the retirement's compare-exchange, which
/// also moves the member's `LINKED` to `DETACHED`, absorbs an entry when it
/// finds `ABANDONED` set. `ABANDONED` is set once, the policy bits move
/// once, and the counter keeps one entry, or none once the retirement
/// absorbed it.
fn parks_of_one_incarnation(retirement: bool) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let shared = Arc::new((AtomicU64::new(1 | REF | LINKED), AtomicUsize::new(0)));
        let parker = |shared: &(AtomicU64, AtomicUsize)| {
            let (slot_word, pending) = shared;
            pending.fetch_add(1, Ordering::Relaxed);
            if !super::grace_model::park_word(slot_word, 1, 0) {
                pending.fetch_sub(1, Ordering::Relaxed);
            }
        };
        let parkers: Vec<_> = (0..2)
            .map(|_| {
                let shared = Arc::clone(&shared);
                thread::spawn(move || parker(&shared))
            })
            .collect();
        let (slot_word, pending) = &*shared;
        if retirement {
            let (Ok(previous) | Err(previous)) =
                slot_word.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                    Some((current | ABANDONED | RETIRED) ^ (LINKED ^ DETACHED))
                });
            if previous & ABANDONED != 0 {
                pending.fetch_sub(1, Ordering::Relaxed);
            }
        }
        for parker in parkers {
            parker.join().unwrap();
        }
        let flags = if retirement {
            ABANDONED | RETIRED | DETACHED
        } else {
            ABANDONED | LINKED
        };
        assert_eq!(slot_word.load(Ordering::Relaxed), 1 | REF | flags);
        assert_eq!(
            pending.load(Ordering::Relaxed),
            usize::from(!retirement),
            "a park's counter entry was lost or doubled"
        );
    });
}

#[test]
fn parks_of_one_incarnation_set_the_flag_once() {
    parks_of_one_incarnation(false);
    parks_of_one_incarnation(true);
}

/// A retain on incarnation `incarnation` expecting `current`, through the
/// production transition, or with `compare` off the control's transition
/// that accepts whatever incarnation the word holds; takes a right and
/// returns whether an exchange failed on a word whose policy bits differed
/// from the expected word's, or refuses with the word it last read.
fn retain(
    slot_word: &AtomicU64,
    mut current: u64,
    incarnation: u32,
    compare: bool,
) -> Result<bool, u64> {
    let mut after_policy_write = false;
    loop {
        let expected = if compare {
            incarnation
        } else {
            word::incarnation(current)
        };
        let Some(next) = word::retained(current, expected) else {
            return Err(current);
        };
        match slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return Ok(after_policy_write),
            Err(seen) => {
                after_policy_write |= (seen ^ current) & POLICY != 0;
                current = seen;
            }
        }
    }
}

/// The visited kernel: a reader that validated incarnation one retains and
/// releases while the anchor's holder releases and service returns the
/// block and claims incarnation two, whose publication installs its
/// anchor.
fn visited_versus_reuse(compare: bool) {
    // Executions in which the reader's retain met incarnation two, counted
    // outside the model so the search is known to reach that race.
    let moved = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reached = Arc::clone(&moved);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let reached = Arc::clone(&reached);
        struct Slot {
            gate: Mutex<State>,
            word: AtomicU64,
        }
        let slot = Arc::new(Slot {
            gate: Mutex::new(State::Resident),
            word: AtomicU64::new(1 | REF),
        });
        // Service's return and the next claim and publication, under the
        // gate, once the count of incarnation one is seen at zero.
        let service = |slot: &Slot| {
            let _gate = slot.gate.lock().unwrap();
            let current = slot.word.load(Ordering::Acquire);
            if word::incarnation(current) == 1 && word::refs(current) == 0 {
                let cleared = FLAGS | VISITED | POLICY;
                let free = slot.word.fetch_and(!cleared, Ordering::Relaxed) & !cleared;
                if slot
                    .word
                    .compare_exchange(free, 2, Ordering::Release, Ordering::Relaxed)
                    .is_ok()
                {
                    slot.word.fetch_add(REF, Ordering::Release);
                }
            }
        };
        let reader = {
            let slot = Arc::clone(&slot);
            thread::spawn(move || {
                let validated = slot.word.load(Ordering::Acquire);
                if word::incarnation(validated) == 1 && word::refs(validated) != 0 {
                    match retain(&slot.word, validated, 1, compare) {
                        Ok(_) => {
                            slot.word.fetch_sub(REF, Ordering::Release);
                        }
                        Err(seen) if word::incarnation(seen) == 2 => {
                            reached.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(_) => {}
                    }
                }
            })
        };
        // The anchor's holder lets go.
        slot.word.fetch_sub(REF, Ordering::Release);
        service(&slot);
        reader.join().unwrap();
        service(&slot);
        let current = slot.word.load(Ordering::Relaxed);
        assert_eq!(word::incarnation(current), 2);
        assert_eq!(
            current & VISITED,
            0,
            "incarnation 2 read a hit on incarnation 1"
        );
        assert_eq!(word::refs(current), 1);
    });
    assert!(
        moved.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "no explored execution met the reuse in the retain"
    );
}

#[test]
fn a_reused_slot_reads_a_clear_visited_bit() {
    visited_versus_reuse(true);
}

#[test]
#[should_panic(expected = "incarnation 2 read a hit on incarnation 1")]
fn negative_control_a_retain_whose_expected_word_omits_the_incarnation_fails() {
    visited_versus_reuse(false);
}

#[test]
fn a_retain_racing_the_hand_clear_keeps_its_right() {
    for start in [0, VISITED] {
        let mut builder = loom::model::Builder::new();
        builder.preemption_bound = Some(PREEMPTION_BOUND);
        builder.check(move || {
            let slot_word = Arc::new(AtomicU64::new(1 | REF | LINKED | start));
            let gate = Arc::new(Mutex::new(()));
            let hit = {
                let slot_word = Arc::clone(&slot_word);
                thread::spawn(move || {
                    let validated = slot_word.load(Ordering::Acquire);
                    assert!(retain(&slot_word, validated, 1, true).is_ok());
                })
            };
            // Without a scheduling point here loom runs the selection first
            // in every execution it explores; the yield lets the hit land
            // before, between and after the selection's two accesses.
            thread::yield_now();
            // Selection under the gate: a load that reads visited is
            // followed by one `fetch_and`, as in production.
            let cleared_after_hit = {
                let guard = gate.lock().unwrap();
                let read = slot_word.load(Ordering::Relaxed);
                let cleared =
                    (read & VISITED != 0).then(|| slot_word.fetch_and(!VISITED, Ordering::Relaxed));
                drop(guard);
                cleared.is_some_and(|previous| word::refs(previous) == 2)
            };
            hit.join().unwrap();
            let last = slot_word.load(Ordering::Relaxed);
            assert_eq!(
                word::refs(last),
                2,
                "the hand's clear lost a retain's right"
            );
            assert_eq!(word::incarnation(last), 1);
            assert_eq!(
                last & VISITED != 0,
                !cleared_after_hit,
                "a retain's visited bit was lost or kept against the clear"
            );
            assert_eq!(
                last & POLICY,
                LINKED,
                "a retain or the hand's clear changed a policy bit"
            );
        });
    }
}

#[derive(Clone, Copy)]
enum Departure {
    Detach,
    MarkLinked,
    /// The retirement's compare-exchange carrying the mark of the linked
    /// member; it sets `RETIRED` and leaves `ABANDONED` to the parker.
    RetireMarked,
}

/// Races the gate holder's policy bit writes against a reader's retain and
/// release and a parker's park of incarnation 1 on one word. The bit write
/// `plain` names is the negative control's load and plain store.
fn policy_writes_versus_lock_free_writers(departure: Departure, plain: Plain) {
    // Executions in which the retain's exchange failed on a word a policy
    // write had changed, counted outside the model so the search is known
    // to reach that race.
    let raced = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let reached = Arc::clone(&raced);
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(move || {
        let reached = Arc::clone(&reached);
        struct Shared {
            gate: Mutex<([u32; 1], Domain)>,
            slots: [Slot; 1],
        }
        let slots = [Slot::new(1 | REF, plain)];
        let (mut next, mut domain) = ([POLICY_NONE], Domain::EMPTY);
        Queue::new(&slots, &mut next, &mut domain).link(0);
        let shared = Arc::new(Shared {
            gate: Mutex::new((next, domain)),
            slots,
        });
        let reader = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let slot_word = &shared.slots[0].word;
                let validated = slot_word.load(Ordering::Acquire);
                if retain(slot_word, validated, 1, true).expect("the retain refused") {
                    reached.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                }
                slot_word.fetch_sub(REF, Ordering::Release);
            })
        };
        let parker = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                assert!(super::grace_model::park_word(&shared.slots[0].word, 1, 0));
            })
        };
        {
            let mut gate = shared.gate.lock().unwrap();
            let (next, domain) = &mut *gate;
            let mut queue = Queue::new(&shared.slots, next, domain);
            match departure {
                Departure::Detach => {
                    assert!(queue.detach(0));
                    assert!(!queue.mark_evicted(0, 1));
                }
                Departure::MarkLinked => assert!(queue.mark_evicted(0, 1)),
                Departure::RetireMarked => {
                    let slot_word = &shared.slots[0].word;
                    queue.mark_evicted_with(0, 1, |mask| {
                        let _ = slot_word.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |c| {
                            Some((c | RETIRED) ^ mask)
                        });
                    });
                }
            }
            queue.release_evicted(0, 1);
        }
        reader.join().unwrap();
        parker.join().unwrap();
        // Asserted before the gate is taken: a panic under a loom mutex
        // guard aborts the model instead of reporting.
        let last = shared.slots[0].word.load(Ordering::Relaxed);
        let retired = match departure {
            Departure::RetireMarked => RETIRED,
            Departure::Detach | Departure::MarkLinked => 0,
        };
        assert_eq!(
            last,
            1 | REF | ABANDONED | VISITED | DETACHED | retired,
            "a policy bit write lost a lock-free writer's bits: {last:#x}"
        );
        let mut gate = shared.gate.lock().unwrap();
        let (next, domain) = &mut *gate;
        let nodes = Queue::new(&shared.slots, next, domain).nodes();
        check_domain(&nodes, domain, |_| true);
        assert_eq!((domain.detached, domain.in_flight), (1, 0));
    });
    if plain == Plain::Off {
        assert!(
            raced.load(std::sync::atomic::Ordering::Relaxed) > 0,
            "no explored execution failed a retain on a policy write"
        );
    }
}

#[test]
fn policy_writes_keep_every_lock_free_writers_bits() {
    policy_writes_versus_lock_free_writers(Departure::Detach, Plain::Off);
}

#[test]
fn a_linked_members_mark_keeps_every_lock_free_writers_bits() {
    policy_writes_versus_lock_free_writers(Departure::MarkLinked, Plain::Off);
}

#[test]
fn a_retirement_carrying_the_mark_keeps_every_lock_free_writers_bits() {
    policy_writes_versus_lock_free_writers(Departure::RetireMarked, Plain::Off);
}

#[test]
#[should_panic(expected = "a policy bit write lost a lock-free writer's bits")]
fn negative_control_a_plain_store_moving_the_mark_loses_a_lock_free_write() {
    policy_writes_versus_lock_free_writers(Departure::MarkLinked, Plain::Move);
}

#[test]
#[should_panic(expected = "a policy bit write lost a lock-free writer's bits")]
fn negative_control_a_plain_store_setting_the_mark_loses_a_lock_free_write() {
    policy_writes_versus_lock_free_writers(Departure::Detach, Plain::Set);
}

#[test]
#[should_panic(expected = "a policy bit write lost a lock-free writer's bits")]
fn negative_control_a_plain_store_clearing_the_mark_loses_a_lock_free_write() {
    policy_writes_versus_lock_free_writers(Departure::Detach, Plain::Clear);
}

/// Eviction versus invalidation on one key: the evictor selects slot 0
/// under the pool gate, releases it, and commits by exact identity under the
/// shard gate; the invalidator clears the same pair under the shard gate.
/// Whoever clears it records the retirement with one pool-gate try, parking
/// it when the gate is busy. The evictor records retirement and applies its
/// eviction mark under the same pool-gate hold; when its retirement parks,
/// the evictor leaves its mark pending and
/// tries once to apply it. A final service hold sights a parked retirement
/// and applies a mark still pending. Exactly one retirement, one unlink and
/// one detach follow, and `in_flight` counts the slot's evicted bit.
#[test]
fn eviction_versus_invalidation_retires_once() {
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    enum Held {
        Resident,
        Retired,
    }
    struct Pool {
        state: [Held; 2],
        next: [u32; 2],
        domain: Domain,
    }
    struct Shared {
        pool: Mutex<Pool>,
        /// The key's pair: the incarnation it names, or none.
        pair: Mutex<Option<u64>>,
        /// Slot 0, whose word a retirement parks on, and slot 1, which
        /// stays a member.
        slots: [Slot; 2],
        /// The pending mark, or zero.
        mark: AtomicU64,
        retirements: AtomicUsize,
        /// Whether the evictor's commit cleared the pair.
        evicted: AtomicBool,
    }
    impl Shared {
        fn queue<'a>(&'a self, pool: &'a mut Pool) -> Queue<'a, Slot> {
            Queue::new(&self.slots, &mut pool.next, &mut pool.domain)
        }
        /// `retire` returns `true` when retirement completes under the pool
        /// gate and `false` when retirement is parked.
        fn retire(&self, evicted: bool) -> bool {
            self.retirements.fetch_add(1, Ordering::Relaxed);
            match self.pool.try_lock() {
                Ok(mut pool) => {
                    pool.state[0] = Held::Retired;
                    let word = &self.slots[0].word;
                    let retire = |departure: u64| {
                        let set = ABANDONED | RETIRED | super::word::ANCHORED;
                        let _ = word.fetch_update(Ordering::AcqRel, Ordering::Relaxed, |current| {
                            Some((current | set) ^ departure)
                        });
                    };
                    if evicted {
                        self.queue(&mut pool).mark_evicted_with(0, 1, retire);
                    } else {
                        self.queue(&mut pool).detach_with(0, retire);
                    }
                    true
                }
                Err(_) => {
                    assert!(super::grace_model::park_word(
                        &self.slots[0].word,
                        1,
                        super::word::ANCHORED
                    ));
                    false
                }
            }
        }
        /// Applies a pending mark under the gate, as production takes it:
        /// one load and, when a mark is pending, one store, the words having
        /// one writer. Incarnation 1 is the only one, so the guard is the
        /// resident-or-retired state.
        fn apply(&self, pool: &mut Pool) {
            if self.mark.load(Ordering::Relaxed) == 1 {
                self.mark.store(0, Ordering::Relaxed);
                self.queue(pool).mark_evicted(0, 1);
            }
        }
    }
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(PREEMPTION_BOUND);
    builder.check(|| {
        let slots = [
            Slot::new(1 | REF, Plain::Off),
            Slot::new(1 | REF, Plain::Off),
        ];
        let mut pool = Pool {
            state: [Held::Resident; 2],
            next: [POLICY_NONE; 2],
            domain: Domain::EMPTY,
        };
        // Slot 0 at the tail, where selection starts.
        Queue::new(&slots, &mut pool.next, &mut pool.domain).link(0);
        Queue::new(&slots, &mut pool.next, &mut pool.domain).link(1);
        let shared = Arc::new(Shared {
            pool: Mutex::new(pool),
            pair: Mutex::new(Some(1)),
            slots,
            mark: AtomicU64::new(0),
            retirements: AtomicUsize::new(0),
            evicted: AtomicBool::new(false),
        });
        let evictor = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let candidate = {
                    let mut pool = shared.pool.lock().unwrap();
                    shared.apply(&mut pool);
                    let start = shared.queue(&mut pool).start();
                    (start == 0 && pool.state[0] == Held::Resident).then_some(1u64)
                };
                let Some(incarnation) = candidate else {
                    return;
                };
                let cleared = {
                    let mut pair = shared.pair.lock().unwrap();
                    let found = *pair == Some(incarnation);
                    if found {
                        *pair = None;
                    }
                    found
                };
                if cleared {
                    shared.evicted.store(true, Ordering::Relaxed);
                    if !shared.retire(true) {
                        shared.mark.store(incarnation, Ordering::Relaxed);
                        if let Ok(mut pool) = shared.pool.try_lock() {
                            shared.apply(&mut pool);
                        }
                    }
                }
            })
        };
        let invalidator = {
            let shared = Arc::clone(&shared);
            thread::spawn(move || {
                let cleared = shared.pair.lock().unwrap().take().is_some();
                if cleared {
                    shared.retire(false);
                }
            })
        };
        evictor.join().unwrap();
        invalidator.join().unwrap();
        let mut pool = shared.pool.lock().unwrap();
        if pool.state[0] == Held::Resident
            && shared.slots[0].word.load(Ordering::Acquire) & ABANDONED != 0
        {
            shared.queue(&mut pool).detach(0);
        }
        shared.apply(&mut pool);
        assert_eq!(shared.retirements.load(Ordering::Relaxed), 1);
        assert_eq!(*shared.pair.lock().unwrap(), None);
        let nodes = shared.queue(&mut pool).nodes();
        check_domain(&nodes, &pool.domain, |_| true);
        assert_eq!(pool.domain.members, 1, "slot 1 stays the only member");
        assert_eq!(pool.domain.head, 1);
        assert_eq!(pool.domain.detached, 1, "one unlink, one detach");
        // Nothing releases the anchor here, so the evictor's mark always
        // counts its victim, and only its victim, in flight.
        assert_eq!(
            pool.domain.in_flight,
            u32::from(shared.evicted.load(Ordering::Relaxed))
        );
        if shared.evicted.load(Ordering::Relaxed) {
            EVICTED_RUNS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    });
    assert!(
        EVICTED_RUNS.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "no explored execution evicted"
    );
}

/// Executions of the eviction kernel in which the evictor's commit won,
/// counted outside the model so the search is known to reach that branch.
static EVICTED_RUNS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
