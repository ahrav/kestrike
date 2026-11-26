//! The custody decisions of the command table, the buffer pool and client source slots: which record a completion or cancel reaches, what each terminal does with the buffer, how submit and close move admission, which token a slot issues next, which events a buffer's obligation set accepts and the set each leaves, which incarnation a freed buffer starts, whether a device hold or return applies, and when a source slot is writable or frees.
//!
//! The table, the pool and the client source slots apply each decision's effects; every decision reads plain values, and the verifier checks it with the lemmas in `verification/verus/src/proof.rs`.
//! Tokens put the slot in the low [`SLOT_BITS`] bits and the generation above them.

#[cfg(verus_keep_ghost)]
use vstd::prelude::*;

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const SLOT_BITS: u32 = 16;
/// The largest generation a token carries; a slot that issued it retires.
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(crate) const GENERATION_MAX: u64 = 0xFFFF_FFFF_FFFF;

/// Whether the table accepts new submissions.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    Open,
    /// [`CommandTable::close`](super::CommandTable::close) or a quiesce ran; outstanding commands still finish.
    Closed,
    /// The driver refused a submit with `DeviceGone`, or a submit's driver call did not return; sticky.
    Lost,
    /// The driver proved a stop. `Stopped` is final; the table's later driver calls are limited to [`attach_facts`](super::CommandTable::attach_facts), which reads attach-time data the driver owns.
    Stopped,
}

/// Where a pending command stands with its driver and its requester.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Phase {
    /// The driver call never returned: no completion matches the command and cancel cannot detach it, so only a proven stop returns its buffer.
    Reserved,
    /// The driver returned `Ok`; the buffer returns to its requester in the terminal event.
    Accepted,
    /// Cancelled after acceptance; the buffer is quarantined and frees inside the table at the terminal event.
    Detached,
}

/// How a submit's driver call ended when it left a command held.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Submitted {
    Accepted,
    /// The driver call unwound.
    Unwound,
}

/// What a terminal does with a pending command's buffer.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Ending {
    /// The buffer returns to its requester in the terminal event.
    Return,
    /// The quarantined buffer frees inside the table, and the event reports the command abandoned.
    Free,
}

/// The shared stop guard: poll, quiesce, service and medium admission reach the driver only while admission is not `Stopped`.
#[cfg_attr(verus_keep_ghost, verus_spec(open =>
    ensures open == !(admission is Stopped),
))]
#[inline(always)]
pub(super) fn reaches_driver(admission: Admission) -> bool {
    !matches!(admission, Admission::Stopped)
}

/// Submit reaches the driver only while admission is `Open`.
#[cfg_attr(verus_keep_ghost, verus_spec(open =>
    ensures open == (admission is Open),
))]
#[inline(always)]
pub(super) fn admits_submit(admission: Admission) -> bool {
    matches!(admission, Admission::Open)
}

/// Closing refuses later submissions; a lost or stopped table stays as it is.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        admission is Open ==> next is Closed,
        !(admission is Open) ==> next == admission,
))]
#[inline(always)]
pub(super) fn close(admission: Admission) -> Admission {
    match admission {
        Admission::Open => Admission::Closed,
        other => other,
    }
}

/// The phase a held command takes and the admission after its driver call; the table calls the driver only while open:
///
/// - an accepted command is held accepted and admission stays open;
/// - an unwound call holds the command reserved and loses the device.
#[cfg_attr(verus_keep_ghost, verus_spec(held =>
    requires admission is Open,
    ensures
        outcome is Accepted ==> held == (Phase::Accepted, admission),
        outcome is Unwound ==> held == (Phase::Reserved, Admission::Lost),
))]
#[inline(always)]
pub(super) fn after_submit(admission: Admission, outcome: Submitted) -> (Phase, Admission) {
    match outcome {
        Submitted::Accepted => (Phase::Accepted, admission),
        Submitted::Unwound => (Phase::Reserved, Admission::Lost),
    }
}

/// The admission after a driver refused a submit, which holds nothing: a `DeviceGone` refusal loses the device.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    requires admission is Open,
    ensures next == if gone { Admission::Lost } else { admission },
))]
#[inline(always)]
pub(super) fn after_refusal(admission: Admission, gone: bool) -> Admission {
    if gone { Admission::Lost } else { admission }
}

/// Whether a completion or cancel naming `token` reaches the record whose slot last issued `issued` and holds `phase`: only an accepted or detached command whose token is exactly this one.
#[cfg_attr(verus_keep_ghost, verus_spec(hit =>
    ensures hit == (issued == token && (phase is Accepted || phase is Detached)),
))]
#[inline(always)]
pub(super) fn targets(issued: u64, phase: Phase, token: u64) -> bool {
    issued == token && matches!(phase, Phase::Accepted | Phase::Detached)
}

/// Whether a cancel detaches the command it targets, holding `phase`: only an accepted one, and only while admission is open or lost.
#[cfg_attr(verus_keep_ghost, verus_spec(detach =>
    ensures detach == (phase == Phase::Accepted && !(admission is Closed) && !(admission is Stopped)),
))]
#[inline(always)]
pub(super) fn cancels(admission: Admission, phase: Phase) -> bool {
    !matches!(admission, Admission::Closed | Admission::Stopped) && matches!(phase, Phase::Accepted)
}

/// What a command's terminal does with its buffer, at a matched completion or in the stopped drain: a detached buffer frees, and every other phase's buffer returns.
#[cfg_attr(verus_keep_ghost, verus_spec(ending =>
    ensures (ending is Free) == (phase is Detached),
))]
#[inline(always)]
pub(super) fn ending(phase: Phase) -> Ending {
    match phase {
        Phase::Detached => Ending::Free,
        _ => Ending::Return,
    }
}

/// Whether a slot whose last token is `issued` retires when it frees: it issued the maximum generation.
#[cfg_attr(verus_keep_ghost, verus_spec(retired =>
    ensures retired == (issued as int / 0x10000 == GENERATION_MAX as int),
))]
#[inline(always)]
pub(super) fn retires(issued: u64) -> bool {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::shift_is_division(issued); }
    issued >> SLOT_BITS == GENERATION_MAX
}

/// The token a free slot issues next: the same slot at the next generation, so a slot's tokens strictly increase and never repeat; `None` only after the slot issued the maximum generation, and such a slot retires and issues no further token.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        (issued as int) / 0x10000 < GENERATION_MAX as int ==> (next matches Some(token) && {
            &&& token as int % 0x10000 == issued as int % 0x10000
            &&& token as int / 0x10000 == issued as int / 0x10000 + 1
            &&& token > issued
        }),
))]
#[inline(always)]
pub(super) fn next_token(issued: u64) -> Option<u64> {
    #[cfg(verus_keep_ghost)]
    proof! { if (issued as int) / 0x10000 < GENERATION_MAX as int { crate::proof::next_generation(issued); } }
    issued.checked_add(1 << SLOT_BITS)
}

#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const APPLICATION: u8 = 1;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const STORAGE: u8 = 2;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const DETACHED: u8 = 4;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const NIC: u8 = 8;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const RECEIVE: u8 = 16;
#[cfg_attr(verus_keep_ghost, verus_verify)]
pub(super) const RETIRED: u8 = 32;

/// One pool event on one buffer's obligation set.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Event {
    /// A free buffer becomes a live handle.
    Acquire,
    /// A free buffer is posted to a device for receive.
    Post,
    /// The device finished writing a posted buffer, which becomes a live handle.
    Complete,
    /// A posting ends unused.
    Unpost,
    /// A driver accepted the handle's command, or its submit unwound.
    IntoStorage,
    /// The command's terminal hands the buffer back.
    IntoBuffer,
    /// The command was cancelled.
    Detach,
    /// A cancelled command's terminal or a proven stop.
    FreeDetached,
    /// The handle dropped.
    Drop,
    /// The last device reference returned.
    LastReturn,
}

/// Where an event leaves a buffer.
#[cfg_attr(verus_keep_ghost, verus_verify)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Next {
    /// The buffer's set becomes this one.
    Set(u8),
    /// Every obligation ended, so the buffer frees; `next_incarnation` then decides between a new incarnation on the free stack and retirement.
    Free,
}

/// Whether `event` may act on a buffer whose set is `set` and which carries `nic` device references.
///
/// A storage, receive or detached buffer has no handle and so no device reference, and only the table or the device moves it; a device-held handle takes no device write.
#[cfg_attr(verus_keep_ghost, verus_spec(ok =>
    ensures ok == crate::model::legal_event(set, nic, event),
))]
#[inline(always)]
pub(super) fn legal(set: u8, nic: u16, event: Event) -> bool {
    match event {
        Event::Acquire | Event::Post => set == 0 && nic == 0,
        Event::Complete | Event::Unpost => set == RECEIVE && nic == 0,
        Event::IntoStorage => set == APPLICATION && nic == 0,
        Event::IntoBuffer | Event::Detach => set == STORAGE && nic == 0,
        Event::FreeDetached => set == STORAGE | DETACHED && nic == 0,
        Event::Drop => set == APPLICATION,
        Event::LastReturn => nic == 0 && (set == NIC || set == APPLICATION),
    }
}

/// The set a legal event leaves, or `Free` once every obligation ended: a dropped handle with device references becomes `{NIC}`, and the last return frees only a buffer whose handle already dropped.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    requires crate::model::legal_event(set, nic, event),
    ensures
        next is Free ==> nic == 0 && (set == RECEIVE || set == STORAGE | DETACHED || set == APPLICATION || set == NIC),
        next is Free ==> !(event is Acquire || event is Post || event is Complete || event is IntoStorage || event is IntoBuffer || event is Detach),
        next matches Next::Set(to) ==> crate::model::legal_set(to) && to != 0 && to != RETIRED,
        event is Drop ==> (next is Free) == (nic == 0),
        event is LastReturn ==> (next is Free) == (set == NIC),
        next == crate::model::step(set, nic, event),
))]
#[inline(always)]
pub(super) fn after(set: u8, nic: u16, event: Event) -> Next {
    #[cfg(verus_keep_ghost)]
    proof! { crate::proof::quarantined_bits(); }
    match event {
        Event::Acquire | Event::Complete | Event::IntoBuffer => Next::Set(APPLICATION),
        Event::Post => Next::Set(RECEIVE),
        Event::IntoStorage => Next::Set(STORAGE),
        Event::Detach => Next::Set(STORAGE | DETACHED),
        Event::Unpost | Event::FreeDetached => Next::Free,
        Event::Drop if nic > 0 => Next::Set(NIC),
        Event::LastReturn if set == APPLICATION => Next::Set(APPLICATION),
        Event::Drop | Event::LastReturn => Next::Free,
    }
}

/// The incarnation a freed buffer starts, or `None` when the count would wrap and the buffer retires.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        incarnation < u64::MAX ==> next == Some((incarnation + 1) as u64),
        incarnation == u64::MAX ==> next is None,
))]
#[inline(always)]
pub(super) fn next_incarnation(incarnation: u64) -> Option<u64> {
    incarnation.checked_add(1)
}

/// The device reference count after one more hold, or `None` when the count is full and the hold is refused.
#[cfg_attr(verus_keep_ghost, verus_spec(next =>
    ensures
        nic < u16::MAX ==> next == Some((nic + 1) as u16),
        nic == u16::MAX ==> next is None,
))]
#[inline(always)]
pub(super) fn holds(nic: u16) -> Option<u16> {
    nic.checked_add(1)
}

/// Whether a raw device return names a live reference: the buffer's current incarnation with a positive count. Any other return changes nothing.
#[cfg_attr(verus_keep_ghost, verus_spec(matched =>
    ensures matched == (current == named && count > 0),
))]
#[inline(always)]
pub(super) fn returns(current: u64, named: u64, count: u16) -> bool {
    current == named && count > 0
}

/// Whether a client source slot's bytes are writable: it holds no fragment and no device reads its buffer.
#[cfg_attr(verus_keep_ghost, verus_spec(writable =>
    ensures writable == (!holds_fragment && !device_held),
))]
#[inline(always)]
pub(crate) fn source_writable(holds_fragment: bool, device_held: bool) -> bool {
    !holds_fragment && !device_held
}

/// Whether a held source slot frees: its upload's retention of the fragment ended (a receipt passed it, or the upload was decided or cancelled) and no device reads its buffer. Either alone keeps the slot and its bytes.
#[cfg_attr(verus_keep_ghost, verus_spec(frees =>
    ensures frees == (retention_ended && !device_held),
))]
#[inline(always)]
pub(crate) fn source_frees(retention_ended: bool, device_held: bool) -> bool {
    retention_ended && !device_held
}
