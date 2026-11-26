//! The ownership protocol's pure decision cores: checked identity values and the reservation-key codec, Report evidence, the serving table that gates operations and metadata by token and Report window, the off-volume store records with the generation flip computed over them, the comparison of a volume's control-plane attachment listing with the desired state, the owner's poll, the standby's spare check and the fresh path's check over those records and that listing, the admission of the retirement request a check produces, and the arbiter's flip nomination, with `reconcile` making the reconciler's record writes, the same-host restart sequence (`restart`), the fresh first acquisition (`fresh`) and the named standby's same-volume takeover (`takeover`). Outside the hosts, `standbys` judges which shards need a standby designated and holds the per-AZ census record that caps the shards with a standby slot, and `loss` separates actual volume loss, which provisions a replacement of the next generation, from impairment, which retains the volume, and from correlated impairment, which holds for an operator; `reconcile` keeps each replacement's receipt, calls the volume provider under it, and releases a correlated hold only under an operator's authorization. The host report (`report`) carries authenticated observations to the reconciler and the monitors; the reconciler's census reservation takes its candidate host and headroom from an accepted report, and no ownership or device write derives from one. A planned request (`planned`) asks one owner tenure for a transfer to its named standby or a same-host restart, and confers no ownership; the pure exit machine `planned::Planned` orders the drain of such an exit or of an owner-raised roll. `zone_loop` observes one zone each tick under its validated reconciler bounds and fleet directory: it reads host reports and the instance and volume listings through its source traits and the zone's store records through the reconciler, and forms the host and volume verdicts. `attachments::ControlPlane` is the seam of the listing client, whose implementation lives outside this module.
//!
//! Decision cores are pure functions of their inputs; `reconcile` makes store requests through `storage::store::Client`, and so does `restart` for its record reads and its `E` bump, `fresh` for its record reads, its `E` bump, its Confirm and its page fences, and `takeover` for its record reads and its takeover compare-and-swap; `standbys` and `loss` are pure, and `reconcile` writes the census. `report` reads procfs and sysfs files for host headroom and `/proc/self/exe` for the build digest, and draws a writer's boot nonce from the operating system. `NoEpochReuse` holds over sessions `(g, a)`: every epoch is the activated epoch of the shard-record session, and no two attempts activate one `(g, n)` of a shard record. `NoPreemptOfForeignKey`: a core issues a preempt naming its own key, or, in the takeover sequence after its acknowledged compare-and-swap and while the shard record names its tenure, the key of a recorded holder whose tenure on the same volume that write superseded: its predecessor's, or one its predecessor's line of takeovers succeeded; a cross-host change of ownership is a generation flip to the spare or the standby's same-volume takeover at the retained generation.

//! The detector forms typed suspicion from observed heartbeat windows. The arbiter turns it into a flip nomination
//! that names the `(g, owner, E)` it targets. The shard record's standby, running `takeover` on the retained
//! volume, accepts that target, and a standby's detector mints no takeover witness while it suspects itself. Volume
//! loss and generation flips stay with the reconciler: it flips to a spare when a retirement request passes admission
//! and an operator authorizes the flip. The reconciler flips to a replacement after `loss` confirms volume loss from
//! control-plane evidence. The client route preserves `RouteMonotonic` over `(g, a)`: equal-tenure identity conflicts
//! withhold requests and responses until a higher tenure.

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod admission;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod arbiter;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod arbiter_kani;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod assignment;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod attachments;
pub mod bounds;
pub mod detect;
pub mod evidence;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod flip;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod flip_kani;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod fresh;
pub mod identity;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod loss;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod loss_kani;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod planned;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod poll;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod reconcile;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod record;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod records;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod report;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod restart;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod retire;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod route;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod route_kani;
pub mod route_merge;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod serving;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod serving_kani;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod standbys;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod symbolic_kani;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod takeover;
mod window;
pub mod withhold;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod zone_loop;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod add_spare_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod admission_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod admitted_record_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod assignment_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod fence_search;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod fence_search_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod fencing_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod flip_for_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod flip_tenure_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod poll_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod reconcile_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod reconcile_witness_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod record_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod retained_refusal_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod search;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod serving_boundary_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod serving_window_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod sim;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tenure_search;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tenure_search_tests;

#[cfg(test)]
mod attachment_key_tests;
#[cfg(test)]
mod bounds_tests;
#[cfg(test)]
mod bounds_window_tests;
#[cfg(test)]
mod encoded_key_order_tests;
#[cfg(test)]
mod evidence_tests;
#[cfg(test)]
mod field_lanes_tests;
#[cfg(test)]
mod identity_tests;
#[cfg(test)]
mod registrants_holder_tests;

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod admission_rerun_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod arbiter_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod census_live_attach_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod create_shard_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod detect_route_replay_tests;
#[cfg(test)]
mod detect_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod flip_record_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod nominate_pure_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod report_gauge_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod restart_warm_source_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod route_conflict_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod route_high_water_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod route_order_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod route_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod stale_suspicion_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod superseded_flip_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod token_admission_tests;
