//! Loom kernel for the snapshot/update protocol: one shard of two base
//! buckets and one overflow bucket, two keys with distinct tags, a writer
//! mutating under the sequence bracket and one or two readers copying under
//! the sequence, plus, in the handoff model, a next gate holder after the
//! writer, exploring every interleaving within each model's recorded bound.
//!
//! A pair is one atomic word, as in the mapped bucket. Nine writer shapes
//! run. `Insert` is the mutation publication performs: the pair word into
//! an empty overflow bucket, its occupancy bit, then the link from the
//! chain's tail, all inside one bracket. `Replace` is the exact-key
//! replacement: the word of an occupied pair overwritten in place, then the
//! occupancy bit's no-op set. `Remove` is exact removal of an overflow
//! bucket's sole entry: the occupancy bit cleared, the predecessor relinked,
//! the bucket's own link cleared. `Recycle` is overflow reuse compressed
//! into one bracket, and a stronger adversary than any single production
//! commit: the overflow bucket is unlinked from one chain, its pair word
//! overwritten, and relinked into the other chain, so a reader whose bucket
//! is recycled under it reads a link of one state and a pair of another.
//! `RecycleAcross` is overflow reuse in production's two brackets: a removal
//! that empties and unlinks the bucket, then a publication that fills and
//! relinks it into the other chain, so a reader can straddle both; the free
//! stack's push and pop are writer-only and not modelled. `Activate` is a
//! pending pair's publication: the overflow bucket, linked behind `B`'s base
//! bucket, holds `B`'s identity reserved under a pending lane, and the
//! bracket stores the lane that makes the pair occupied, one control store,
//! and then the chain summary, which did not yet name `B`. `Cancel` frees
//! a pending lane holding `A`'s second identity behind `A`'s base bucket,
//! outside any bracket, as `Bucket::cancel_pair` requires.
//! `ReserveAfterRemove` is `Remove` followed, outside any bracket, by a
//! reservation of the freed pair for another identity of `A`, so a reader
//! holding the control word from before the removal can load the reserved
//! word, and the reservation's release fence lets the sequence check
//! reject a copy holding it. The reservation runs in the bracket's thread
//! after the release fence `Busy::begin` issued, and a fence orders every
//! store sequenced after it in its thread, so the earlier fence already
//! covers the reservation's stores and alone satisfies the model's
//! ordering requirement. `ReserveByNextHolder` runs that reservation in a
//! distinct holder that takes the shard gate, a loom mutex, after the
//! removal's holder releases it, so the reservation's own release fence is
//! the one fence that orders its stores for a reader whose copy spans the
//! handoff; its negative control omits that fence and a reader accepts a
//! torn copy of `A` under the pre-removal sequence. The removal's holder
//! starts the next holder's thread while it holds the gate, so that thread
//! takes the gate after the removal's holder releases it and every run
//! reserves after the removal; one reader, of `A`, copies across the
//! handoff. The two keys' tags differ in their low three bits, so every
//! rewrite of a pair also rewrites its control lane, and a reader that pairs
//! one state's lane with the other's word is a torn copy the model must
//! reject.
//!
//! Model substitutions: the buckets are [`ModelBucket`]s of loom atomics
//! implementing the same [`BucketView`] the mapped buckets implement, so the
//! scan under test is the production `scan_chain`; the chain summaries are
//! loom `AtomicU64`s read through the production `excludes` before the
//! scan, as the snapshot reads them, and stored by the writer where the
//! production insert stores them; the sequence is a loom
//! `AtomicU64` driven by the production `read_stable`, `still` and `Busy`;
//! the writer's stores are spelled out here in the production order and at
//! the production strength, `Relaxed` behind the bracket's release fence,
//! since the mapped bucket's methods take mapped atomics; the shard gate is
//! a loom mutex the writer holds for its last bracket and any reservation
//! that follows it, and a next holder takes it afterwards; a reader makes
//! one attempt where the snapshot retries.
//!
//! The property: a reader that returns a copy under two equal loads of an even
//! sequence value returned exactly the candidates of the stable shard state
//! that value names, never a mix of two and never a later state, whether the
//! copy came from the scan or from a summary that excluded the key; a reader
//! whose chain was rewritten under it returns no copy; a malformed chain under
//! an unchanged sequence is never seen, so `Corrupt` from the scan fails the
//! model there, while across brackets it is rejected like any torn copy. A
//! pending pair is in no stable state, so a copy that holds it before
//! activation, or a copy that holds it twice, fails the model, and after
//! activation every quiescent copy holds it exactly once. The negative controls
//! "wrap sequence" end the `Recycle`, the `Replace` and the `Activate` bracket
//! on the starting even value and fail: a reader accepts a copy of the new
//! state under the old state's sequence value.
//!
//! Bounds: loom `0.7.2`. The models with one writer and two readers set
//! preemption bound 3 and explore every interleaving within it. The
//! next-holder handoff and the delayed reader run under `loom::model`,
//! which reads its preemption bound from `LOOM_MAX_PREEMPTIONS`; the Loom
//! lane clears every `LOOM_*` variable, so these models run with no
//! preemption bound and explore every interleaving. Each model completes in
//! a few seconds. Loom `0.7.2` models coherence, release/acquire and
//! fences, the vocabulary the sequence module's happens-before argument is
//! written in, so a green run checks that argument, the bracket logic and
//! the scan's bounds under every interleaving. Its
//! `rt::thread::Set::seq_cst` is a no-op, so the cross-location `SeqCst`
//! total order lies outside the model, and a change to the orderings needs
//! its own proof beside a green run here. Run with `LOOM_*` unset and
//! `RUSTFLAGS="--cfg loom" cargo test -p kestrike --lib --release scan_model`.

use std::sync::atomic::Ordering;

use loom::sync::atomic::{AtomicU64, AtomicUsize, fence};
use loom::sync::{Arc, Mutex};
use loom::thread;

use super::bucket::{
    Identity, OverflowLink, PAIRS, control_pending, control_with, control_without,
};
use super::scan::{BucketView, ScanWork, scan_chain};
use super::sequence::{Busy, read_stable, still};
use super::summary::{excludes, summary_bits};
use crate::storage::{AllocationId, SlotIndex};

struct ModelBucket {
    control: AtomicU64,
    next: AtomicUsize,
    pairs: [AtomicU64; PAIRS],
}

impl ModelBucket {
    fn empty() -> Self {
        Self {
            control: AtomicU64::new(0),
            next: AtomicUsize::new(0),
            pairs: std::array::from_fn(|_| AtomicU64::new(0)),
        }
    }

    /// The pair store of `Bucket::publish_pair`, without the lane store.
    fn store_pair(&self, pair: usize, identity: Identity) {
        self.pairs[pair].store(identity.pack(), Ordering::Relaxed);
    }

    /// `Bucket::publish_pair`: the pair word, then the pair's lane stored
    /// over `control`, the word the writer loaded before its bracket.
    fn publish_pair(&self, pair: usize, control: u64, identity: Identity) {
        self.store_pair(pair, identity);
        self.control
            .store(control_with(control, pair, identity.tag), Ordering::Relaxed);
    }

    /// `Bucket::link`.
    fn link(&self, link: OverflowLink) {
        self.next.store(link.raw(), Ordering::Relaxed);
    }

    /// `Bucket::reserve_pair` on a free pair: the writer's own load of the
    /// control word, a release fence, the pair word, then the pending lane.
    fn reserve_pair(&self, pair: usize, identity: Identity) {
        self.reserve_pair_fenced(pair, identity, true);
    }

    /// [`reserve_pair`](Self::reserve_pair), issuing the release fence when
    /// `fenced`; the negative control passes `false`.
    fn reserve_pair_fenced(&self, pair: usize, identity: Identity, fenced: bool) {
        let control = self.control.load(Ordering::Relaxed);
        if fenced {
            fence(Ordering::Release);
        }
        self.store_pair(pair, identity);
        self.control
            .store(control_pending(control, pair), Ordering::Relaxed);
    }

    /// `Bucket::activate_pair` on a pending pair: one store of the lane its
    /// reserved word's tag selects over the pending one; returns the tag.
    fn activate_pair(&self, pair: usize) -> u16 {
        let control = self.control.load(Ordering::Relaxed);
        let tag = Identity::unpack(self.pairs[pair].load(Ordering::Relaxed)).tag;
        self.control
            .store(control_with(control, pair, tag), Ordering::Relaxed);
        tag
    }

    /// `Bucket::cancel_pair` on a pending pair: a release fence, then the
    /// freed lane.
    fn cancel_pair(&self, pair: usize) {
        let control = self.control.load(Ordering::Relaxed);
        fence(Ordering::Release);
        self.clear_pair(pair, control);
    }

    /// The caller supplies `control` loaded before `Busy::begin`.
    fn clear_pair(&self, pair: usize, control: u64) {
        self.control
            .store(control_without(control, pair), Ordering::Relaxed);
    }
}

impl BucketView for ModelBucket {
    fn control(&self) -> u64 {
        self.control.load(Ordering::SeqCst)
    }

    fn next(&self) -> usize {
        self.next.load(Ordering::SeqCst)
    }

    fn identity(&self, pair: usize) -> Identity {
        Identity::unpack(self.pairs[pair].load(Ordering::SeqCst))
    }
}

const BASE: usize = 2;
const DEPTH: usize = 1;
/// Two tags whose control lanes differ (low three bits `010` and `011`) and
/// whose chain summaries differ (`A` sets bits 0 and 1, `B` bits 0 and 3).
const KEY_A: u16 = 0xA;
const KEY_B: u16 = 0x1B;
const _: () = assert!(summary_bits(KEY_A) != summary_bits(KEY_B));

fn id(tag: u16, slot: usize, incarnation: u32) -> Identity {
    Identity::new(tag, AllocationId::new(SlotIndex(slot), incarnation))
}

/// `A`'s identity in base bucket zero, present from the start.
fn a_first() -> Identity {
    id(KEY_A, 3, 1)
}

/// `A`'s identity in the overflow bucket.
fn a_second() -> Identity {
    id(KEY_A, 9, 2)
}

/// `A`'s replacement identity for base bucket zero.
fn a_replaced() -> Identity {
    id(KEY_A, 5, 3)
}

/// The identity of `A` a reservation writes into the pair a removal freed.
fn a_reserved() -> Identity {
    id(KEY_A, 11, 4)
}

/// `B`'s identity in the overflow bucket.
fn b_only() -> Identity {
    id(KEY_B, 7, 1)
}

struct Shard {
    /// The shard gate: the writer holds it from before its last bracket's
    /// control loads through any reservation the writer makes after that
    /// bracket, and a next holder takes it after the writer releases it.
    gate: Mutex<()>,
    sequence: AtomicU64,
    buckets: [ModelBucket; 3],
    /// One chain summary per base bucket.
    summaries: [AtomicU64; BASE],
}

impl Shard {
    fn empty() -> Self {
        Self {
            gate: Mutex::new(()),
            sequence: AtomicU64::new(0),
            buckets: [
                ModelBucket::empty(),
                ModelBucket::empty(),
                ModelBucket::empty(),
            ],
            summaries: [AtomicU64::new(0), AtomicU64::new(0)],
        }
    }
}

#[derive(Clone, Copy)]
enum Mutation {
    /// Publication: `A`'s second identity into the empty overflow bucket,
    /// linked from base bucket zero. Before: `A` has one identity, `B` none.
    /// After: `A` has two.
    Insert,
    /// Exact-key replacement: `A`'s pair in base bucket zero is overwritten
    /// with `A`'s replacement identity. Before and after: `A` one.
    Replace,
    /// Exact removal of the overflow bucket's sole entry, `A`'s second
    /// identity: unlinked and freed. Before: `A` two. After: `A` one.
    Remove,
    /// Overflow reuse in two brackets: `Remove`, then `B` published into the
    /// freed bucket, linked behind base bucket one. Before: `A` two, `B`
    /// none. After: `A` one, `B` one.
    RecycleAcross,
    /// Overflow reuse in one bracket: the overflow bucket, which starts
    /// linked behind `A` holding `A`'s second identity, is unlinked, its
    /// pair word and lane overwritten with `B`'s identity, and linked behind
    /// base bucket one. Before: `A` two, `B` none. After: `A` one, `B` one.
    Recycle,
    /// A pending pair's publication: the overflow bucket, linked behind base
    /// bucket one, holds `B`'s identity pending; the bracket stores the
    /// occupied lane, then `B`'s chain summary. Before: `A` one, `B` none.
    /// After: `A` one, `B` one.
    Activate,
    /// A pending pair's cancel outside any bracket: the overflow bucket,
    /// linked behind base bucket zero, holds `A`'s second identity pending,
    /// and its lane is freed. Before and after: `A` one.
    Cancel,
    /// `Remove`, then a reservation of the freed pair for `A`'s reserved
    /// identity outside any bracket. Before: `A` two. After: `A` one.
    ReserveAfterRemove,
    /// `Remove` under the shard gate, then, by a distinct holder that takes
    /// the gate next, the reservation of the freed pair outside any
    /// bracket, its own release fence present when `fenced`. Before: `A`
    /// two. After: `A` one.
    ReserveByNextHolder { fenced: bool },
}

impl Mutation {
    fn setup(self, shard: &Shard) {
        shard.buckets[0].publish_pair(0, 0, a_first());
        shard.summaries[0].store(summary_bits(KEY_A), Ordering::Relaxed);
        if let Self::Recycle
        | Self::Remove
        | Self::RecycleAcross
        | Self::ReserveAfterRemove
        | Self::ReserveByNextHolder { .. } = self
        {
            shard.buckets[BASE].publish_pair(0, 0, a_second());
            shard.buckets[0].link(OverflowLink::encode(0).unwrap());
        }
        match self {
            Self::Activate => {
                shard.buckets[BASE].reserve_pair(0, b_only());
                shard.buckets[1].link(OverflowLink::encode(0).unwrap());
            }
            Self::Cancel => {
                shard.buckets[BASE].reserve_pair(0, a_second());
                shard.buckets[0].link(OverflowLink::encode(0).unwrap());
            }
            _ => {}
        }
    }

    /// The commit, inside one bracket, or two for `RecycleAcross`. With the
    /// wrap fault the last bracket ends on the starting even value instead
    /// of the next. The writer loads the target's control word under the
    /// gate before the bracket, as the production commit does, and an insert
    /// stores the chain's summary inside the bracket as the production
    /// insert does; a removal leaves the summary in place. For
    /// `ReserveByNextHolder` the writer starts the next holder while it holds
    /// the gate and returns after joining that holder's thread.
    fn commit(self, shard: &Arc<Shard>, wrap: bool) {
        let overflow = &shard.buckets[BASE];
        let remove = |control: u64| {
            overflow.clear_pair(0, control);
            shard.buckets[0].link(OverflowLink::NONE);
            overflow.link(OverflowLink::NONE);
        };
        let mut stable = 0;
        if let Self::Cancel = self {
            overflow.cancel_pair(0);
            return;
        }
        if let Self::RecycleAcross = self {
            let control = overflow.control();
            let busy = Busy::begin(&shard.sequence, stable);
            remove(control);
            stable = busy.commit();
        }
        let held = shard.gate.lock().unwrap();
        let next = self.start_next_holder(shard);
        let control = overflow.control();
        let base_control = shard.buckets[0].control();
        let busy = Busy::begin(&shard.sequence, stable);
        match self {
            Self::Insert => {
                overflow.publish_pair(0, control, a_second());
                shard.summaries[0].store(summary_bits(KEY_A), Ordering::Relaxed);
                shard.buckets[0].link(OverflowLink::encode(0).unwrap());
            }
            Self::Replace => shard.buckets[0].publish_pair(0, base_control, a_replaced()),
            Self::Remove | Self::ReserveAfterRemove | Self::ReserveByNextHolder { .. } => {
                remove(control)
            }
            Self::Recycle => {
                shard.buckets[0].link(OverflowLink::NONE);
                overflow.publish_pair(0, control, b_only());
                shard.summaries[1].store(summary_bits(KEY_B), Ordering::Relaxed);
                shard.buckets[1].link(OverflowLink::encode(0).unwrap());
            }
            Self::RecycleAcross => {
                overflow.publish_pair(0, control, b_only());
                shard.summaries[1].store(summary_bits(KEY_B), Ordering::Relaxed);
                shard.buckets[1].link(OverflowLink::encode(0).unwrap());
            }
            Self::Activate => {
                // The occupied lane first, then the summary, from the tag
                // the reserved word carries, as the production commit stores
                // them; a reader rejects any copy taken across the bracket,
                // whichever store it saw.
                let tag = overflow.activate_pair(0);
                assert_eq!(tag, KEY_B);
                shard.summaries[1].store(summary_bits(tag), Ordering::Relaxed);
            }
            Self::Cancel => unreachable!("a cancel runs outside any bracket"),
        }
        if wrap {
            shard.sequence.store(stable, Ordering::SeqCst);
        } else {
            busy.commit();
        }
        if let Self::ReserveAfterRemove = self {
            // The gate holder reserves the freed pair after the bracket.
            overflow.reserve_pair(0, a_reserved());
        }
        drop(held);
        if let Some(next) = next {
            next.join().unwrap();
        }
    }

    /// Starts the next holder for `ReserveByNextHolder` and returns `None`
    /// for every other mutation. The writer calls it while holding the gate,
    /// so the thread takes the gate after the writer releases it and then
    /// reserves the freed pair outside any bracket. The gate's
    /// release/acquire orders the removal before the reservation. The
    /// reservation's stores rely on its own release fence, because the
    /// writer's bracket fence orders only stores sequenced after it in the
    /// writer's thread.
    fn start_next_holder(self, shard: &Arc<Shard>) -> Option<thread::JoinHandle<()>> {
        let Self::ReserveByNextHolder { fenced } = self else {
            return None;
        };
        let shard = Arc::clone(shard);
        Some(thread::spawn(move || {
            let _held = shard.gate.lock().unwrap();
            shard.buckets[BASE].reserve_pair_fenced(0, a_reserved(), fenced);
        }))
    }

    /// Brackets the mutation commits: two for `RecycleAcross`, none for
    /// `Cancel`, else one.
    fn commits(self) -> u64 {
        match self {
            Self::RecycleAcross => 2,
            Self::Cancel => 0,
            _ => 1,
        }
    }

    /// `key`'s candidates in the stable state the even `sequence` names,
    /// the state after `sequence / 2` committed brackets.
    fn state(self, key: u16, sequence: u64) -> Vec<Identity> {
        let committed = sequence / 2;
        match (self, key, committed) {
            (Self::Insert | Self::Replace, KEY_A, 0)
            | (Self::Cancel | Self::Activate, KEY_A, _) => {
                vec![a_first()]
            }
            (Self::Insert, KEY_A, _) => vec![a_first(), a_second()],
            (Self::Replace, KEY_A, _) => vec![a_replaced()],
            (
                Self::Remove
                | Self::Recycle
                | Self::RecycleAcross
                | Self::ReserveAfterRemove
                | Self::ReserveByNextHolder { .. },
                KEY_A,
                0,
            ) => vec![a_first(), a_second()],
            (
                Self::Remove
                | Self::Recycle
                | Self::RecycleAcross
                | Self::ReserveAfterRemove
                | Self::ReserveByNextHolder { .. },
                KEY_A,
                _,
            ) => vec![a_first()],
            (Self::Recycle | Self::Activate, _, 1..) | (Self::RecycleAcross, _, 2..) => {
                vec![b_only()]
            }
            _ => Vec::new(),
        }
    }

    /// A copy taken under two equal loads of `sequence` is that state's.
    fn check(self, key: u16, (sequence, copy): (u64, Vec<Identity>)) {
        let name = if key == KEY_A { "A" } else { "B" };
        assert_eq!(
            copy,
            self.state(key, sequence),
            "torn copy of {name} at sequence {sequence}"
        );
    }
}

/// One snapshot attempt of `tag` from its base bucket, as the snapshot
/// path performs it: stable sequence, the chain summary and, unless it
/// excludes the tag, the scan, then the same sequence, returning the
/// sequence with the copy. A scan that reports a malformed chain under an
/// unchanged sequence fails the model: no stable state is malformed; under
/// a changed one the links were read across brackets and the attempt is
/// rejected like any other.
fn attempt(shard: &Shard, tag: u16) -> Option<(u64, Vec<Identity>)> {
    let start = if tag == KEY_A { 0 } else { 1 };
    let started = read_stable(&shard.sequence).ok()?;
    if excludes(shard.summaries[start].load(Ordering::SeqCst), tag) {
        return still(&shard.sequence, started).then(|| (started, Vec::new()));
    }
    let mut scratch = [Identity::unpack(0); PAIRS * (1 + DEPTH)];
    match scan_chain(
        &shard.buckets,
        BASE,
        start,
        DEPTH,
        tag,
        &mut scratch,
        &mut ScanWork::default(),
    ) {
        Ok(copied) => {
            still(&shard.sequence, started).then(|| (started, scratch[..copied].to_vec()))
        }
        Err(_) => {
            assert!(
                !still(&shard.sequence, started),
                "malformed under a stable sequence"
            );
            None
        }
    }
}

fn model(mutation: Mutation, wrap: bool) {
    let mut builder = loom::model::Builder::new();
    builder.preemption_bound = Some(3);
    builder.check(move || {
        let shard = Arc::new(Shard::empty());
        mutation.setup(&shard);
        let writer = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || mutation.commit(&shard, wrap))
        };
        let reader_b = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || {
                if let Some(copy) = attempt(&shard, KEY_B) {
                    mutation.check(KEY_B, copy);
                }
            })
        };
        if let Some(copy) = attempt(&shard, KEY_A) {
            mutation.check(KEY_A, copy);
        }
        writer.join().unwrap();
        reader_b.join().unwrap();
        // A wrapped bracket leaves the old sequence on the new state, so the
        // quiescent check runs only on the correct commit: the controls fail
        // on a reader's copy taken while the writer ran.
        if !wrap {
            check_quiescent(&shard, mutation);
        }
    });
}

/// Checks the shard after the writer joins: each key's attempt returns a
/// copy of the final state under sequence `2 * commits`.
fn check_quiescent(shard: &Shard, mutation: Mutation) {
    for key in [KEY_A, KEY_B] {
        let copy = attempt(shard, key).expect("a quiescent shard is stable");
        mutation.check(key, copy.clone());
        assert_eq!(copy.0, 2 * mutation.commits());
    }
}

/// Runs `ReserveByNextHolder` under `loom::model` with three threads: the
/// writer, the next holder the writer starts, and the main thread's attempt
/// on `A`, the key whose chain spans the removal and the reservation; then
/// checks the quiescent shard.
fn handoff_model(fenced: bool) {
    let mutation = Mutation::ReserveByNextHolder { fenced };
    loom::model(move || {
        let shard = Arc::new(Shard::empty());
        mutation.setup(&shard);
        let writer = {
            let shard = Arc::clone(&shard);
            thread::spawn(move || mutation.commit(&shard, false))
        };
        if let Some(copy) = attempt(&shard, KEY_A) {
            mutation.check(KEY_A, copy);
        }
        writer.join().unwrap();
        check_quiescent(&shard, mutation);
    });
}

#[test]
fn readers_return_no_copy_or_a_copy_of_one_stable_state_across_an_insert() {
    model(Mutation::Insert, false);
}

#[test]
fn readers_return_no_copy_or_a_copy_of_one_stable_state_across_a_replacement() {
    model(Mutation::Replace, false);
}

#[test]
fn readers_return_no_copy_or_a_copy_of_one_stable_state_across_a_removal() {
    model(Mutation::Remove, false);
}

#[test]
fn readers_return_no_copy_or_a_copy_of_one_stable_state_across_a_recycle() {
    model(Mutation::Recycle, false);
}

#[test]
fn readers_return_no_copy_or_a_copy_of_one_stable_state_across_two_recycling_brackets() {
    model(Mutation::RecycleAcross, false);
}

#[test]
fn readers_never_copy_a_pending_pair_and_copy_its_activation_once() {
    model(Mutation::Activate, false);
}

#[test]
fn readers_never_copy_a_pending_pair_across_its_cancel() {
    model(Mutation::Cancel, false);
}

#[test]
fn readers_never_copy_a_pair_reserved_after_a_removal_freed_it() {
    model(Mutation::ReserveAfterRemove, false);
}

/// The wrapped activation bracket: a reader accepts the activated pair
/// under the sequence value of the state that held it pending.
#[test]
#[should_panic(expected = "torn copy of B")]
fn negative_control_wrapping_an_activation_fails() {
    model(Mutation::Activate, true);
}

/// The wrapped `Recycle` bracket: some reader accepts a torn identity.
#[test]
#[should_panic(expected = "torn copy of")]
fn negative_control_wrapping_the_sequence_fails() {
    model(Mutation::Recycle, true);
}

/// The wrapped `Replace` bracket: a reader accepts the replacement's
/// identity under the sequence value of the state before it.
#[test]
#[should_panic(expected = "torn copy of A")]
fn negative_control_wrapping_a_replacement_fails() {
    model(Mutation::Replace, true);
}

/// A distinct next holder's reservation of the freed pair carries its own
/// release fence, so a reader whose copy spans the handoff rejects it.
#[test]
fn readers_never_copy_a_pair_a_next_holder_reserved_after_a_removal_freed_it() {
    handoff_model(true);
}

/// The next holder's reservation omits its release fence: a reader accepts
/// a torn copy of `A` under the pre-removal sequence.
#[test]
#[should_panic(expected = "torn copy of A at sequence 0")]
fn negative_control_a_next_holders_reservation_without_its_fence_fails() {
    handoff_model(false);
}

/// A reader delayed across a whole commit rejects its copy: the sequence
/// moved on.
#[test]
fn a_reader_delayed_across_a_commit_returns_no_copy() {
    loom::model(|| {
        let shard = Arc::new(Shard::empty());
        Mutation::Recycle.setup(&shard);
        let started = read_stable(&shard.sequence).unwrap();
        let mut scratch = [Identity::unpack(0); PAIRS * (1 + DEPTH)];
        let copied = scan_chain(
            &shard.buckets,
            BASE,
            0,
            DEPTH,
            KEY_A,
            &mut scratch,
            &mut ScanWork::default(),
        )
        .unwrap();
        assert_eq!(copied, 2);
        Mutation::Recycle.commit(&shard, false);
        assert!(!still(&shard.sequence, started));
    });
}
