//! Recovery metadata: the qualified blocks of the metadata prefix, the root slots, the session every attach writes under, the RESET root a cold attach makes durable before its first payload write, and the slot position words and durable prefix that gate extent reuse.
//!
//! Invariants owned by this module:
//!
//! - ONE-QUALIFIED-WRITE-PER-BLOCK: the prefix `[0, M * IO_UNIT)` splits into blocks of the persistence profile's unit `U`, block 0 root slot A and block 1 root slot B; attach admits only a prefix that is a whole number of at least two blocks, each of whose ranges qualifies, and each metadata block reaches the device as one write of its whole range ([`Area`]).
//! - EVIDENCE-ORDER: [`Persisted`] stands only for a successful write terminal of a mapped metadata command of that area; a write that depends on a block waits for its `Persisted`.
//! - WHOLE-OR-ABSENT: a block decodes only when its magic, version, layout, crc32c, role, format ID, generation and self-index match, in the order `block` states.
//! - NO-REISSUE: every RESET and format root, and every payload record header, carries the tenure's [`Session`] `g·2^32 + a`, taken from the shard record: `g` is the record's generation and `a = 2n + 2` the activated epoch of the attempt's own acknowledged `E` bump from `n`. The store raises `E` with every committed bump and `g` with every flip, so no two tenures of a shard share a session. The bootstrap refuses `StaleSession` when a valid root holds a generation at or above the session, so the roots it writes stay the highest. A stale write that lowers a root slot changes no later session, since no session input sits on the medium.
//!   Premise: a `Written` terminal stands for persistence under the profile's completion-without-volatile-cache assumption, which the backend service contract carries and Identify evidence alone cannot prove, so the claims here are ordering claims under that assumption.
//! - RESET-BEFORE-OVERWRITE: the RESET goes first to the slot without the highest valid root, or to A when both hold the same root, and then to the other slot once the first is persisted; payload writes start only after both are persisted, or, on the warm bootstrap, which writes no root, after its allocation-readiness commit. A late root write of a dropped volume can lower one slot after that; the next attach's session still exceeds it.
//! - EXCLUSION-BEFORE-REUSE: a resident retirement's position is `NO_RECORD`, or the suffix position of the newest recorded removal once one exists, and [`reusable`] admits a retired slot's return once no right remains; a slot whose position names a block is admitted only once that block lies inside the durable prefix.
//!
//! The one role `block` frames is the root.
//!
//! A version with its high bit set marks the encoding provisional, and every version keeps the issuance prefix's offsets.
//!
//! # Corruption classes
//!
//! The table names each class of damage or refusal a recovery reader distinguishes in what it reads from the device, a root block or the root pair, the activation record, a checkpoint unit or slot, or a delta block or suffix, and in the verdicts the load guard and the warm attach give the entries those readers yield. A row names the class label its typed refusal maps to, or `none` for a class with no typed refusal, and the damage cell of a row of each label's class names the variants that map to it. The action is the reader's own: `recover` proceeds and loses nothing beyond what the damage destroyed, `skip` yields nothing from the damaged unit, or from the damaged record of a decoded delta block, and continues without what depends on it, and `refuse` ends the load or the attach with a typed outcome and installs nothing. A `skip` row states what the warm attach then does. The attach takes the first refusal that applies, in the order of these: the slot's verdict, `Unreadable`, `StaleWrite` for damaged suffix history or a slot left with no whole entry, then `Unrestorable`. A row's attach consequence holds when no refusal earlier in that order applies. Test paths are relative to `storage`. The test `recovery::corruption_tests::every_corruption_class_has_a_row_and_a_running_test` checks the table against the label functions of the refusal types and against the source its `SOURCES` list pairs with each cited test's module: each cited test is an unindented `fn` outside block comments with `#[test]` on the line above it, and the nearest line above that attribute that has code before any `//` ends in `}` or `;` and does not start with `#[`. The check fails a cited test when a line between its `fn` line and the next line that is `}` alone has `#![` as its first non-whitespace characters.
//!
//! | Row | Unit and reader | Damage and outcome | Class | Action | Tests |
//! |---|---|---|---|---|---|
//! | `root-invalid` | Root block: block open and root decode | The block has another length, or its magic, crc, role, format ID, generation, self-index or a root payload field fails its check (`Undecodable::Invalid`). The slot holds no root, and the RESET goes over it. | `root-invalid` | recover | `recovery::root_tests::decode_checks_each_header_field_in_the_whole_or_absent_order`, `volume::bootstrap_tests::corrupting_one_slot_after_a_reset_still_admits_a_higher_session_and_corrupting_both_writes_nothing` |
//! | `root-unformatted` | Root pair: decision | Both slots decode invalid. The bootstrap ends `Unformatted` and writes nothing before a format. | `root-unformatted` | refuse | `volume::bootstrap_tests::corrupting_one_slot_after_a_reset_still_admits_a_higher_session_and_corrupting_both_writes_nothing` |
//! | `root-unsupported` | Root block: block open | The magic matches and the version differs (`Undecodable::Unsupported`). The bootstrap ends `Unsupported` with the slot and the version, and writes nothing. | `root-unsupported` | refuse | `volume::bootstrap_tests::format_refuses_and_writes_nothing_unless_both_slots_decode_invalid` |
//! | `root-format` | Root block and root pair | A slot records the layout of another prefix or block length (`Undecodable::ForeignLayout`), or the slots hold roots of two format IDs. The bootstrap ends `FormatMismatch` and writes nothing. | `root-format` | refuse | `volume::bootstrap_tests::format_refuses_and_writes_nothing_unless_both_slots_decode_invalid`, `volume::bootstrap_tests::foreign_format_ids_tied_roots_and_a_root_above_the_session_refuse_with_no_write` |
//! | `root-tied` | Root pair: validation | Both slots hold roots of equal generation and root sequence whose other fields differ. The bootstrap ends `TiedRoots` and writes nothing. | `root-tied` | refuse | `volume::bootstrap_tests::foreign_format_ids_tied_roots_and_a_root_above_the_session_refuse_with_no_write` |
//! | `root-stale-session` | Root pair: decision | A valid root holds a generation at or above the tenure's session. The bootstrap ends `StaleSession` and writes no root. | `root-stale-session` | refuse | `volume::bootstrap_tests::foreign_format_ids_tied_roots_and_a_root_above_the_session_refuse_with_no_write` |
//! | `root-slot-unreadable` | Root block: probe read | The read of a root slot fails. The bootstrap ends `SlotUnreadable` with that slot and writes nothing. | `root-slot-unreadable` | refuse | `volume::bootstrap_tests::format_refuses_and_writes_nothing_unless_both_slots_decode_invalid`, `volume::bootstrap_tests::a_failed_read_at_each_probe_position_refuses_slot_unreadable_with_no_write` |
//! | `root-below-session` | Root pair: decision | A valid root lies below the session. The RESET goes first to the slot without the highest valid root, or to A when both hold the same root, then to the other. | none | recover | `volume::bootstrap_tests::a_cold_attach_resets_over_a_root_that_names_history_reading_only_the_root_slots` |
//! | `activation-torn` | Activation record: read-back | The read-back returns no bytes, has another length or fails its crc32c (`Damage::Torn`). The step reads once more, and a second torn read refuses `Fault::Damaged(Torn)`. | `activation-torn` | refuse | `volume::activation_tests::torn_readback_retries_once_then_refuses`, `volume::activation_tests::activation_record_refuses_torn_and_invalid_records` |
//! | `activation-invalid` | Activation record: read-back | The crc32c matches and the bytes match no record the encoder writes for any volume and tenure (`Damage::Invalid`). The step refuses `Fault::Damaged(Invalid)`. | `activation-invalid` | refuse | `volume::activation_tests::torn_readback_retries_once_then_refuses`, `volume::activation_tests::activation_record_refuses_torn_and_invalid_records` |
//! | `activation-foreign` | Activation record: read-back | The read-back decodes the record of another volume or another tenure (`Fault::Foreign`). | `activation-foreign` | refuse | `volume::activation_tests::torn_readback_retries_once_then_refuses`, `volume::activation_tests::foreign_session_refuses` |
//! | `header-framing` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The bytes end before the fixed fields or before the header their lengths derive, or the magic or the version differs (`Truncated`, `Magic`, `Version`). Both readers pass only whole units to the header check and read short bytes as unread, as rows `unit-unread` and `block-unread` state; `Truncated` comes from the record header's own readers, such as `claim_header`. The unit yields nothing, and the attach does what row `unit-header` or `block-header` states. | `header-framing` | skip | `record::header_tests::each_forged_field_yields_its_own_mismatch_in_order`, `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action`, `recovery::stored_generation_tests::every_stored_checkpoint_generation_loads_its_entries_or_refuses_at_its_version`, `recovery::stored_generation_tests::every_stored_delta_generation_decodes_to_its_records_or_refuses_at_its_version` |
//! | `header-lengths` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The whole lengths, the verified length or the chunk parameters differ from the extent's (`Lengths`, `ExtentLength`, `ChunkParameters`). The unit yields nothing, and the attach does what row `unit-header` or `block-header` states. | `header-lengths` | skip | `record::header_tests::each_forged_field_yields_its_own_mismatch_in_order`, `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action` |
//! | `header-checksum` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The header crc or the context crc differs from the computed one (`HeaderCrc`, `ContextCrc`); an edited key byte with no reseal fails here, before the identity. The unit yields nothing, and the attach does what row `unit-header` or `block-header` states. | `header-checksum` | skip | `record::header_tests::each_forged_field_yields_its_own_mismatch_in_order`, `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action` |
//! | `header-identity` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The key, allocation, session or cache version differs from the expected unit's or block's (`Key`, `Allocation`, `Session`, `CacheVersion`): a unit of another capture, session or shard, or a block of another LSN, session or shard. The unit yields nothing, and the attach does what row `unit-header` or `block-header` states. | `header-identity` | skip | `recovery::checkpoint_tests::a_unit_of_another_checkpoint_fails_its_identity`, `recovery::delta_tests::a_block_of_another_lsn_session_or_shard_fails_identity_before_its_payload`, `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action` |
//! | `header-session` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The identity matches and the session has another generation than the reader's, or an odd, zero or later epoch (`ForeignSession`). Every unit of the slot fails and the slot loads warm and empty, so the attach refuses `Unloadable(StaleWrite)` whenever the slot has a data unit and every unit and suffix block was read; a block is a hole, as row `block-header` states. | `header-session` | skip | `record::header_tests::session_predicate_rejects_foreign_or_future_sessions`, `checkpoint::tests::a_later_tenure_reads_the_checkpoint_and_another_generation_does_not`, `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action` |
//! | `header-position` | Record header of a checkpoint unit or a delta block: checkpoint unit decode and delta block decode | The extent index or the payload offset differs from the reader's (`ExtentIndex`, `Offset`); both readers expect a one-extent record at index 0 and offset 0. The unit yields nothing, and the attach does what row `unit-header` or `block-header` states. | `header-position` | skip | `record::header_tests::each_forged_field_yields_its_own_mismatch_in_order` |
//! | `unit-header` | Checkpoint unit: unit decode | The unit's record header fails (`UnitDamage::Header` with the mismatch of a `header-` row). The unit adds no row and is listed as failed, the entries with a row on it are lost, and the alarm is `StaleWrite`. The attach refuses `Unloadable(StaleWrite)` when the failed data units left no whole entry of the slot. | `unit-header` | skip | `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action`, `recovery::checkpoint_tests::a_unit_of_another_checkpoint_fails_its_identity`, `recovery::checkpoint_tests::a_torn_unit_loses_only_the_entries_with_a_row_on_it` |
//! | `unit-chunk` | Checkpoint unit: unit decode | The payload's chunk crc differs from the header's (`UnitDamage::Chunk`). The unit adds no row and is listed as failed, the entries with a row on it are lost, and the alarm is `StaleWrite`. The attach refuses `Unloadable(StaleWrite)` when the failed data units left no whole entry of the slot. | `unit-chunk` | skip | `recovery::checkpoint_tests::a_torn_unit_loses_only_the_entries_with_a_row_on_it`, `checkpoint::tests::a_torn_unit_zero_loses_no_entry_and_raises_the_stale_write_alarm`, `recovery::stored_generation_tests::every_stored_checkpoint_generation_loads_its_entries_or_refuses_at_its_version` |
//! | `unit-data-content` | Checkpoint unit: unit decode | A data unit's row count is zero or above a unit's rows, a reserved byte or a byte after its rows is nonzero, or a row is malformed (`UnitDamage::Content`). The unit adds no row and is listed as failed, and the entries with a row on it are lost. The attach refuses `Unloadable(StaleWrite)` when the failed data units left no whole entry of the slot. | `unit-content` | skip | `recovery::checkpoint_tests::a_unit_with_a_zero_row_count_adds_no_row`, `recovery::checkpoint_tests::a_unit_with_a_nonzero_byte_anywhere_in_4_to_8_of_its_payload_adds_no_row`, `recovery::checkpoint_tests::a_unit_with_a_row_count_above_its_rows_adds_no_row`, `recovery::checkpoint_tests::a_unit_with_a_nonzero_byte_after_its_rows_adds_no_row` |
//! | `unit-count` | Checkpoint unit 0: unit decode | An intact unit 0 records another unit count than the store names (`UnitDamage::Units`). The slot loads cold with `StaleWrite`. | `unit-count` | refuse | `recovery::checkpoint_tests::an_intact_unit_0_naming_another_unit_count_loads_the_slot_cold` |
//! | `unit-0-counts` | Checkpoint unit 0: unit decode | An intact unit 0 whose entry count exceeds its row count, whose row count spans another number of units than the named count, or whose payload holds a nonzero byte from offset 20 (`UnitDamage::Content { unit: 0 }`). The slot loads cold with `StaleWrite`; a torn unit 0 is row `unit-header` or `unit-chunk` and loses no entry. | `unit-content` | refuse | `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action` |
//! | `unit-unread` | Checkpoint unit: slot read | The device could not read the unit, or its read returned fewer bytes than the whole unit (`UnitDamage::Unread`), which a failed check outranks. The unit adds no row, the entries with a row on it are lost, and the alarm is `Unreadable`. The attach refuses `Unloadable(Unreadable)` when the slot passes the guard. | `unit-unread` | skip | `recovery::checkpoint_tests::a_unit_arriving_after_its_failed_read_stays_unread`, `recovery::checkpoint_tests::a_slot_missing_a_unit_keeps_the_rest_and_a_unit_0_naming_another_count_fails`, `checkpoint::tests::a_failed_read_loses_only_its_units_and_a_failed_check_outranks_it`, `checkpoint::tests::a_short_completion_counts_its_missing_units_as_unread`, `checkpoint::tests::an_entry_straddling_a_failed_read_is_lost_as_unreadable`, `volume::warm::read_tests::a_failed_slot_read_counts_as_unread_and_installs_nothing`, `recovery::corruption_tests::a_slot_with_each_unit_unfed_in_turn_skips_that_unit_as_unread`, `volume::warm::read_tests::a_failed_read_at_each_position_of_a_warm_attach_installs_nothing` |
//! | `slot-contradiction` | Checkpoint slot: slot finish | Intact units contradict each other or unit 0's counts: a row breaks an entry other than by continuing the entry an undecoded unit cut, a data unit before the last is short, or the rows miss or exceed the counts (`UnitDamage::Content` of the unit that shows it, or the lowest failed unit's damage when a unit failed its own check). The slot loads cold with `StaleWrite`. | `unit-content` | refuse | `recovery::checkpoint_tests::a_slot_whose_intact_units_break_an_entry_loads_cold`, `recovery::checkpoint_tests::a_short_unit_before_the_last_loads_cold_beside_a_damaged_unit`, `recovery::checkpoint_tests::an_entry_shortfall_beyond_the_lost_rows_loads_cold`, `recovery::checkpoint_tests::an_entry_surplus_over_unit_0s_count_loads_cold` |
//! | `slot-repeat` | Checkpoint slot: slot decode | A unit arrives twice or out of order. Its first landing decides it, and the slot loads as it does in unit order. | none | recover | `recovery::checkpoint_tests::a_unit_arriving_twice_decodes_once_before_and_after_it_stitches`, `recovery::checkpoint_tests::a_slot_round_trips_in_any_arrival_order` |
//! | `block-header` | Delta block: block decode | The block's record header fails (`BlockHole::Header` with the mismatch of a `header-` row), and the block is a hole. The attach refuses `Unloadable(StaleWrite)` when the hole lies below the certified end or before a block of its suffix that passed its identity and crc checks, as row `suffix-damage` states. | `block-header` | skip | `recovery::corruption_tests::every_matrix_case_ends_in_its_declared_refusal_and_action`, `recovery::delta_tests::a_block_of_another_lsn_session_or_shard_fails_identity_before_its_payload` |
//! | `block-chunk` | Delta block: block decode | The payload's chunk crc differs from the header's (`BlockHole::Chunk`), and the block is a hole. The attach refuses `Unloadable(StaleWrite)` when the hole lies below the certified end or before a block of its suffix that passed its identity and crc checks, as row `suffix-damage` states. | `block-chunk` | skip | `recovery::delta_tests::a_flipped_or_truncated_block_is_a_hole_and_never_another_decode`, `recovery::stored_generation_tests::every_stored_delta_generation_decodes_to_its_records_or_refuses_at_its_version` |
//! | `block-content` | Delta block: block decode and record assembler | The block decode finds the parts malformed, or the assembler finds that the block does not continue the record or sequence before it (`BlockHole::Content`); the block is a hole and yields nothing. Or a record of a decoded block is not one body of its kind, its body passes the widest body, or its insert lies outside the reader's limits or is of a session the reader does not admit (`BlockHole::Content`); the block is a hole at that record, which yields nothing, the block's earlier records apply as any record before the suffix's first hole does, and its later records are records behind that hole, as row `suffix-dropped` states. The block passed its identity and crc checks, so the hole is damage at any LSN and the attach refuses `Unloadable(StaleWrite)`. | `block-content` | skip | `recovery::delta_tests::a_block_whose_parts_do_not_chain_or_hold_a_malformed_body_is_a_hole`, `recovery::delta_replay_tests::an_oversized_or_misshapen_record_is_a_content_hole`, `recovery::delta_replay_tests::a_suffix_whose_first_block_continues_an_unseen_record_is_a_hole`, `recovery::delta_replay_tests::a_malformed_record_or_an_unopened_continuation_is_a_hole_that_names_the_inserts_it_drops` |
//! | `block-unread` | Delta block: suffix read | The device could not read the block, or the bytes are not a whole unit (`BlockHole::Unread`). The replay lists the LSN as unread, and the attach refuses `Unloadable(Unreadable)` when the slot passes the guard. | `block-unread` | skip | `recovery::delta_tests::a_flipped_or_truncated_block_is_a_hole_and_never_another_decode`, `recovery::delta_replay_tests::a_remove_that_never_reached_the_medium_keeps_its_entry`, `recovery::delta_replay_tests::a_failed_read_at_each_position_of_a_suffix_lists_its_lsn_unread_and_holds_the_load`, `volume::warm::read_tests::a_failed_read_at_each_position_of_a_warm_attach_installs_nothing` |
//! | `suffix-damage` | Suffix replay | On a read failure, the replay lists the LSN as unread and treats its block as a hole. The replay classifies the suffix's first hole as damage when it lies below the certified end, its block passed its identity and crc checks, or a later block of the suffix passed those checks; otherwise the hole is the tail. A record still open at the suffix's end is damage. Damage or an unread LSN blocks installation. | none | refuse | `recovery::delta_replay_tests::a_hole_is_damage_below_the_certified_end_or_before_a_passed_block_and_otherwise_the_tail`, `recovery::delta_replay_tests::a_remove_that_never_reached_the_medium_keeps_its_entry`, `recovery::delta_replay_tests::a_replace_on_another_extent_excludes_the_old_identity_and_installs_the_new_or_neither`, `recovery::delta_replay_tests::a_failed_read_at_each_position_of_a_suffix_lists_its_lsn_unread_and_holds_the_load` |
//! | `suffix-tail` | Suffix replay | Any other hole ends the suffix's unflushed tail, and the records before it apply. | none | recover | `recovery::delta_replay_tests::a_hole_is_damage_below_the_certified_end_or_before_a_passed_block_and_otherwise_the_tail` |
//! | `suffix-dropped` | Suffix replay | Each insert behind a suffix's first hole, in a whole record that passes its own checks, is dropped and named. It comes from a block that passed its identity and crc checks, so that suffix's hole is damage, and the attach refuses `Unloadable(Unreadable)` when a unit or block went unread and `Unloadable(StaleWrite)` otherwise, as rows `attach-unreadable` and `attach-stale-write` state. | none | skip | `recovery::delta_replay_tests::a_damaged_remove_block_stops_inserts_and_leaves_one_owner_per_unit`, `recovery::delta_replay_tests::a_malformed_record_or_an_unopened_continuation_is_a_hole_that_names_the_inserts_it_drops` |
//! | `guard-refusal` | Load guard, batch and streamed | The entries break a guard rule: more than `n_max` entries (`Entries`), an entry out of bounds (`Bounds`), a shared key (`Key`) or slot (`Slot`), an extent total past the capacity (`Units`), or overlapping extents (`Overlap`). Nothing loads, and the attach refuses `Unloadable` with the rule. | `guard-refusal` | refuse | `recovery::capture_tests::load_guard_refuses`, `recovery::load_guard_tests::random_checkpoints_get_the_reference_verdict`, `recovery::checkpoint_tests::an_out_of_bounds_row_outranks_units_wherever_it_lies` |
//! | `attach-unreadable` | Warm attach: stage | A unit of the slot or a block of its suffix went unread, and the slot passed the guard. The attach refuses `Unloadable(Unreadable)` and installs nothing. | `attach-unreadable` | refuse | `volume::warm::read_tests::a_failed_slot_read_counts_as_unread_and_installs_nothing`, `volume::warm::read_tests::a_failed_read_at_each_position_of_a_warm_attach_installs_nothing` |
//! | `attach-stale-write` | Warm attach: stage | The slot loads cold with `StaleWrite`, the suffix history is damaged, or the slot's failed data units left no whole entry. The attach refuses `Unloadable(StaleWrite)` and installs nothing. | `attach-stale-write` | refuse | `volume::warm::tests::a_damaged_load_installs_its_survivors_only_with_its_loss_record`, `volume::warm::read_tests::a_suffix_remove_reaches_the_warm_load_and_the_predecessor_suffix_is_certified_to_its_hole` |
//! | `withheld-entry` | Slot decode, suffix replay and warm attach | A valid checkpoint unit holds an entry of a session the reader does not admit, or two suffix entries of one level, neither superseded, share a unit or a slot. The reader withholds them, and the attach refuses `Unloadable(Unrestorable)` and installs nothing. | `attach-unrestorable` | refuse | `recovery::delta_replay_tests::entries_of_one_level_sharing_a_unit_or_slot_are_both_withheld_and_adjacent_spans_are_kept`, `recovery::delta_replay_tests::a_withheld_entry_bars_its_units_from_earlier_levels`, `recovery::delta_replay_tests::many_entries_claiming_one_unit_are_withheld_together_or_superseded_by_a_later_level`, `volume::warm::tests::a_slot_entry_the_decode_withholds_refuses_the_stage` |

mod capture;
#[cfg(test)]
pub(crate) use capture::NO_SIDE_CAP;
pub use capture::{
    Capture, CaptureEntry, CaptureEpoch, CaptureError, CaptureStarted, CutIntact, SideCap,
};
mod capture_policy;
pub use capture_policy::{CaptureConfig, CapturePolicy};
mod load_guard;
#[cfg(kani)]
mod load_guard_kani;
pub use load_guard::{
    EvictCause, GuardedLoad, LoadEvent, LoadLimits, LoadRefusal, guarded_load, load_guard,
};
mod block;
#[cfg(test)]
pub(crate) mod capture_tests;
#[cfg(test)]
#[path = "capture_trace_tests.rs"]
pub(crate) mod capture_trace;
#[cfg(test)]
mod capture_unrecorded_leave_tests;
pub mod checkpoint;
#[cfg(test)]
pub(crate) mod checkpoint_tests;
#[cfg(test)]
mod corruption_tests;
#[cfg(test)]
mod damaged_slot_tests;
pub(crate) mod delta;
pub(crate) mod delta_replay;
#[cfg(test)]
mod delta_replay_tests;
#[cfg(test)]
pub(crate) mod delta_tests;
mod durable;
pub(crate) mod io_share;
#[cfg(test)]
mod io_share_tests;
pub use io_share::HostShare;
pub(crate) use io_share::{IoClass, IoShare};
mod journal;
mod layout;
#[cfg(test)]
mod layout_tests;
#[cfg(test)]
mod load_guard_tests;
mod persisted;
#[cfg(test)]
mod persisted_tests;
mod root;
#[cfg(test)]
mod root_tests;
mod session;
#[cfg(test)]
mod session_tests;
#[cfg(test)]
mod stale_root_tests;
#[cfg(test)]
mod stored_generation_tests;
pub(crate) mod suffix;
#[cfg(test)]
pub(crate) mod suffix_tests;
#[cfg(test)]
pub(crate) use session_tests::{next_session, restart_sessions, session_at, upcoming_session};

pub use block::FormatId;
#[cfg(test)]
pub(crate) use block::Layout;
pub(crate) use block::{field, zero};
pub(crate) use durable::{LSN_LIMIT, NO_RECORD, reusable};
#[cfg(all(test, loom))]
pub(crate) use durable::{advance, position as journal_position};
pub(crate) use journal::{JournalHold, JournalWords, PARKED_EPOCH, epoch_of};
pub use layout::{Slot, TileRefusal};
pub use persisted::AreaRefusal;
pub(crate) use persisted::{Area, Persisted, Recorded};
pub(crate) use root::{Decision, Probed, Root, decide, decode, encode};
pub use session::{Session, SessionRefusal};

/// What the volume's metadata did: its attach bootstrap's progress or refusal, and whether a metadata write failed for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MetadataOutcome {
    /// The bootstrap is waiting for serving authority or running its attach gate, probing the root slots, writing its RESET roots, or loading a warm bootstrap, or a stop or the volume's loss ended it with no evidence of whether a root write landed.
    Bootstrapping,
    /// Both root slots decode invalid; the volume writes to them only after [`Volume::format`](super::Volume::format).
    Unformatted,
    /// Both RESET roots are persisted and payload writes are admitted, or a warm bootstrap committed allocation readiness over its guarded slot load with no root write.
    Open,
    /// The read of `slot` ended in a failure or a stop, or the table refused its submit for good while the device stayed live.
    SlotUnreadable { slot: Slot },
    /// `slot` holds a block of encoding version `version`, which this build reads as foreign.
    Unsupported { slot: Slot, version: u16 },
    /// The slots hold roots of two format IDs, or a slot records the layout of another prefix or block length.
    FormatMismatch,
    /// Both slots hold roots of equal `(generation, root sequence)` whose other decoded fields differ.
    TiedRoots,
    /// A valid root holds a generation at or above the tenure's session; the bootstrap writes no root.
    StaleSession,
    /// The attach refused at its gate for the reason given, before any medium command.
    Unfenced(super::volume::GateRefusal),
    /// The format's entropy draw failed or returned all zeros.
    EntropyUnavailable,
    /// A metadata write failed past its retries, or the table refused its submit for good while the device stayed live; or a warm bootstrap's setup, allocator rebuild, worker, pool or capture gate, or index publication failed, its recovery helpers could not start, or one of its helper jobs panicked, with no device or record write. Admission closed.
    MetadataFailed,
    /// Two restored keys share one fingerprint under this storage's hasher.
    Collided,
    /// A warm load refused for the reason given before its readiness commit, with no device or record write: the guard's verdict, an unread unit or suffix block (`Unreadable`), damaged suffix history (`StaleWrite`), warm allocations past the engine budget (`Memory`), an extent, tail or slot past this storage's geometry, or a chunk or a place in its run that 32 bits cannot name (`Bounds`), an entry the install cannot restore, a slot or suffix entry the decode withheld, or a clock contract, reading or sample that withholds every pair (`Unrestorable`), overlapping restored extents (`Overlap`), or a restored slot the pool cannot take or an exhausted insertion clock (`Slot`).
    Unloadable(LoadRefusal),
}
