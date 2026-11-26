//! The network GET and PUT endpoints' substrate: one endpoint's fixed memory over the arena's packet pools, charged once, and the one datagram seam it drives.
//!
//! Invariants owned by this module:
//!
//! - BOUNDED: packet buffers are the [`BufferArena`](crate::storage::BufferArena)'s packet kinds, whose backing, padding, records and device reference counts the arena charges once; every request slot and census entry is allocated at initialization from a validated [`EndpointConfig`] and charged once to the caller's [`EngineBudget`](crate::storage::EngineBudget), and the transport's constructors charge their own retained state, the payload descriptor memory included, to that budget; a refused initialization leaves the caller's budget and configuration unchanged. Steady-state lease, admit, drain, release and send calls allocate nothing.
//! - A [`PacketLease`] holds one arena buffer exclusively, stays on its pool's thread, cannot outlive its pool and returns its buffer to that pool when dropped, so leases outlive an endpoint's polling and close safely. Data leases never take the receive pool's control reserve.
//! - A [`RequestId`] names a 16-bit slot and a 48-bit generation; a released request's handle never names its successor, and a slot whose generation is exhausted retires. Live requests are active or draining, and both count against their peer's share and the table's total until released.
//! - A [`FragmentGeometry`] exists only for a storage geometry under which every 8192-byte fragment intersects at most two consecutive backing buffers.
//! - A [`Datagrams`] implementation handles bounded, nonblocking batches and reports a send's accepted prefix. It copies a datagram's header and inline pieces before the call returns; for a [`Payload::Retained`] piece it takes a [`NicHold`](crate::storage::NicHold) on the source's buffer incarnation before publishing the datagram to a device and releases every hold of a datagram it refused before returning, so a retained buffer returns to its free stack only after the device's last reference. A receive yields leases over buffers the device finished writing.
//! - Every received frame is authenticated per principal by a [`KeyRing`] before [`Sessions`] or any request state reads it; sessions bootstrap through HELLO, CHALLENGE, CONFIRM and READY, drop replays per direction, and re-key only while quiescent.
//! - An [`Owner`] consumes one cache facade, one registration and one volume of a single storage, serves each GET with a fresh lookup and one volume read bound to its request, releases a request only once its read drained, and writes each PUT from a principal its PUT grant names into a fill it publishes.
//! - A [`Client`] runs to completion on its caller's thread: it drives one session and its GETs through one bounded poll per call and reports its earliest timer deadline through [`Client::next_deadline_us`].
//! - The owner's [`ServeCore`] schedules the GET records held in [`OwnerRequests`], and the client's [`FetchCore`] carries one acquired version per request. A chunk remains retained until every device reference to its buffer returns and either the receipt base passes its last fragment or its request ends. The client's cumulative grant grows by one for each [`FragmentLease`] the application drops.
//! - [`parse`] accepts exactly the canonical frames, checking in the specified order up to the header crc with no allocation and no read past the received bytes; [`encode`] writes only canonical headers, folding the body crc over at most two borrowed payload slices and the header crc over the header.
//!
//! # Lifecycle
//!
//! Both endpoints run on one thread each and do bounded, nonblocking work per call, outside the owner volume's warm bootstrap, whose ticks the `volume` module's Tick bounds state; the caller owns the loop and the clock, passing the current time in microseconds to every call that takes `now_us`. Clients on several threads share one [`ShardRoutes`] table. A client call whose session tenure is its shard's Bound tenure reads the table without a lock. So does a call whose frame leaves a route that holds a tenure, as a Candidate or Bound, unchanged: a response below that tenure, or an ownership frame that merges as a candidate and names that tenure or a lower one. Every other call that merges a frame into a route, and a read of a route that holds no tenure, waits for the table's lock, held for one route merge, read or count.
//!
//! An owner starts from a [`Bundle`] of one storage's cache facade, registration and attached volume, its peers' [`Keys`] with their PUT grant, a [`Datagrams`] transport and a receive [`PacketPool`]; [`Owner::start`] checks the bundle and charges every structure once, and a refusal returns the bundle whole in [`Refused`]. The caller then calls [`Owner::poll`] each turn; when the bootstrap reads `Unformatted`, it calls [`Owner::format`] once and, on `Ok`, keeps polling while the RESET writes land; on `Err` the bootstrap is withheld, and the caller closes the owner, polls until [`Owner::blockers`] returns `None` and shuts it down. Once [`Owner::readiness`] reads `Loaded`, the caller calls [`Owner::begin_replay`], and over restored bindings [`Owner::complete_replay`]; PUT reservations refuse `Bootstrapping` until readiness reads `Live`. Between turns it may stream local fills through [`Owner::receive_fill`] and [`Owner::publish_fill`], invalidate through [`Owner::invalidate`], or, with a fencing installed by [`Owner::install_coverage`], through [`Owner::invalidate_interval`] with [`Owner::cover_pending`] writing the coverage pages that acknowledge it, or [`Owner::cover_begin`] and [`Owner::cover_end`] around store requests the caller runs, and re-key with [`Owner::rekey`] while no request is live. [`Owner::close`] stops admission and sends and closes the volume; the caller keeps polling until [`Owner::blockers`] returns `None`, then [`Owner::shutdown`] returns the facade, the registration, the quiesce proof, the volume's driver, the transport and the counters in a [`Shutdown`], or the owner whole with its blockers. A turn that unwound poisons admission, reported by [`Owner::poisoned`], while every read keeps its custody until it drains.
//!
//! A client initializes from a [`ClientConfig`], its [`ClientMemory`] and one peer key with [`Client::initialize`]. The application builds one [`ShardRoutes`] table, whose capacity covers every shard its clients route over the table's life, charges it to its budget, and gives each client's memory a clone of the table's `Arc`. A client opens a session with [`Client::session`], and calls [`Client::poll`] in its own loop, sleeping no later than [`Client::next_deadline_us`] when it has nothing else to do. Under an active session, [`Client::get`] starts a GET or refuses it with a [`GetRefused`]; [`Client::take`] hands out its fragments in order as [`FragmentLease`]s, [`Client::outcome`] reports its one [`Outcome`], [`Client::cancel`] ends it early, and [`Client::retire`] frees its slot once its outcome is decided and any CANCEL went out. Taken leases stay readable after a timeout, a cancel or the client's close, and return their buffers when they drop. [`Client::put`] starts a PUT or refuses it with a [`PutRefused`]; [`Client::prepare`] declares its metadata and body lengths and TTL, [`Client::supply`] copies in one fragment's bytes, [`Client::put_outcome`] reports its one [`UploadOutcome`], and [`Client::abandon`] lets [`Client::retire`] free a PUT whose outcome is `Unknown`. GETs and PUTs share each endpoint's one request table, peer shares and wire generations, so a client's own uploads can fill its session slot cap and refuse its GET locally with [`GetRefused::RequestPressure`], while the owner's GET reserves keep slots of the owner's table for GETs and the application bounds its concurrent uploads to keep its own slots free for GETs. [`Client::close`] cancels every undecided GET, decides each live PUT `Unknown` or `NotStarted` as its possible send makes it, and sends the GETs' CANCELs, a batch per turn, until every one went out or the transport refuses a send, then returns the transport, whose device the caller stops before undoing its registration.
//!
//! # Transport
//!
//! In production both endpoints drive [`crate::native::Burst`] over an
//! [`EnaPort`](crate::native::EnaPort) on the host's dataplane ENI: the
//! owner in its poll loop, beside the SPDK volume, and the client on
//! the caller's thread, which initializes the environment, starts the port
//! and polls. Each turn's reclaim services the port's timers and returns
//! finished transmits, so retained read buffers come back with no further
//! incoming traffic. Taking the transport back from [`Owner::shutdown`] or
//! [`Client::close`] lets the caller prove the port stopped before it undoes
//! the shared registration. The owner's shutdown also hands back the
//! volume's driver, which the caller quiesces to a proven stop and detaches
//! once that registration was undone. The `kestrike-bind` tool moves each
//! owner's controller and ENI, and each client's ENI, to `vfio-pci` before
//! the process starts, on a host with hugepages reserved, a verified VFIO
//! posture and the approved write-combining modules.
//!
//! An owner is one process serving one volume; a host runs one owner
//! process per volume, each its own peer to clients at its own ENI address.
//!
//! # Production gates
//!
//! The simulated disk and network checks in this module's tests establish software behavior; the ignored host-pair suites in `ena_hardware_tests` and `host_pair_tests` exercise the bypass stack. Production use requires each external gate below, resolved by its owner with evidence from the approved host pair:
//!
//! - Host gate, host owner: hugepages and boot parameters, locked-memory and mapping limits, the verified VFIO mode, the approved write-combining modules with the live mapping evidence, supervisor containment, and, in no-IOMMU mode, the accepted abrupt-death limitation, on both host roles.
//! - Transport gate, transport owner: the host-pair suites passing over the dataplane ENIs, with low-latency placement, the allowance counters, the proven port stop, and in-place recovery, approved by the transport owner.
//! - Storage gate, storage owner: the SPDK driver's outcome rows, canary, proven stop and teardown order on a disposable EBS volume, before the endpoints serve a real one.
//! - Security gate, security and deployment owners: the threat envelope, unique keys, one live instance per principal, and the exact encrypted path, PMTU and rates, before production use of authentication and the transport. Every frame's tag covers its body, GET DATA's through a POLYVAL digest under a per-session data key (the `polyval` crate, a 32-block AVX-512 pass on x86_64 with `avx512f`, `avx512bw`, `avx512vbmi2` and `vpclmulqdq`, or a 64-block `pmull` pass on aarch64 with `neon`, `aes` and `sha3`, each computing the same function), so an on-path attacker without the peer key cannot change a body, including one that keeps its crc32c, without the receiver dropping the frame; the encrypted path is defense in depth for GET bytes.
//! - Capacity gate, capacity and service owners: object and metadata caps, every initialized memory, read, slot, pool, lease and right budget, same-key and local reserves, demand and bursts, poll gap and packet rates, before production sizing.
//! - Performance gate, performance owner: the latency, goodput, noncompletion and CPU targets and their confidence, measured on matched hardware, before production exit.

pub mod activation;
#[cfg(test)]
mod activation_tests;
#[cfg(test)]
mod adapters;
#[cfg(test)]
mod adapters_tests;
#[cfg(test)]
pub(crate) use adapters::fills_written_in;
#[cfg(test)]
mod attribution_tests;
#[cfg(test)]
pub(crate) mod audit;
mod auth;
pub(crate) use auth::SHA256_IV;
pub(crate) use auth::{Keyed, digest_bytes, keyed, outer_block, padded};
#[cfg(test)]
mod auth_tests;
#[cfg(test)]
mod campaign_tests;
#[cfg(test)]
mod challenge_epoch_tests;
mod client;
#[cfg(test)]
mod client_close_sources_tests;
#[cfg(test)]
mod client_due_put_data_tests;
mod client_namespace;
#[cfg(kani)]
mod client_namespace_kani;
#[cfg(test)]
mod client_namespace_tests;
#[cfg(test)]
mod client_repeated_ready_tests;
#[cfg(test)]
mod client_route_full_table_tests;
#[cfg(test)]
mod client_tests;
#[cfg(test)]
mod closed_put_drain_tests;
#[cfg(test)]
mod composed_custody_tests;
#[cfg(test)]
mod composed_down_link_tests;
#[cfg(test)]
mod composed_tests;
#[cfg(test)]
mod coverage_tests;
mod data_hash;
#[cfg(test)]
mod data_hash_tests;
#[cfg(test)]
mod data_tag_digest_tests;
mod datagram;
#[cfg(test)]
mod ena_hardware_tests;
#[cfg(test)]
pub(crate) mod entropy_tests;
pub mod envelope;
#[cfg(test)]
mod envelope_tests;
mod fetch;
#[cfg(test)]
mod fetch_tests;
mod frame;
#[cfg(any(test, fuzzing))]
mod frame_differential;
#[cfg(test)]
mod frame_differential_tests;
#[cfg(test)]
mod frame_kind_set_tests;
#[cfg(any(test, fuzzing))]
mod frame_reference;
#[cfg(test)]
mod frame_seed_tests;
#[cfg(test)]
mod frame_tests;
#[cfg(test)]
mod frame_vector_tests;
mod geometry;
#[cfg(test)]
mod geometry_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod history_tests;
#[cfg(test)]
mod host_loss_recovery_tests;
#[cfg(test)]
mod host_pair_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod hot_cold_tests;
#[cfg(test)]
mod lifecycle_tests;
pub(crate) mod linear_probe;
#[cfg(test)]
pub(crate) mod link;
#[cfg(test)]
mod link_tests;
#[cfg(test)]
mod lost_link_close_tests;
mod memory;
#[cfg(test)]
mod memory_tests;
mod namespace;
#[cfg(kani)]
mod namespace_kani;
#[cfg(kani)]
mod namespace_route_kani;
#[cfg(test)]
mod namespace_tests;
#[cfg(test)]
mod observe;
#[cfg(test)]
mod owner_put_begin_unavailable_tests;
pub mod ownership;
#[cfg(test)]
pub(crate) use observe::teardowns;
#[cfg(test)]
mod observe_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod oracle_endpoint_tests;
mod owner;
#[cfg(test)]
pub(crate) use owner::tests as owner_tenure_tests;
#[cfg(test)]
pub(crate) mod owner_drain_tests;
#[cfg(test)]
mod owner_entry_tests;
#[cfg(test)]
pub(crate) mod owner_tests;
mod owner_view;
mod pace;
#[cfg(test)]
mod pace_model_tests;
#[cfg(test)]
mod packed_scene_tests;
#[cfg(test)]
mod packed_tests;
mod packet;
#[cfg(test)]
mod packet_tests;
mod parked;
#[cfg(test)]
mod parked_tests;
mod permit;
#[cfg(test)]
mod permit_tests;
mod put;
#[cfg(test)]
mod put_at_get_row_tests;
#[cfg(test)]
mod put_conflict_tests;
#[cfg(test)]
mod put_expired_clock_tests;
#[cfg(test)]
mod put_fragment_length_tests;
#[cfg(test)]
mod put_replay_tests;
#[cfg(test)]
pub(crate) mod put_tests;
#[cfg(test)]
mod q1_replay_tests;
#[cfg(test)]
mod receipt_mask_tests;
#[cfg(test)]
mod replacement_tests;
mod requests;
#[cfg(test)]
mod reserve_tests;
#[cfg(test)]
mod restart;
#[cfg(test)]
mod restart_tests;
#[cfg(test)]
mod retired_upload_reply_tests;
#[cfg(test)]
pub(crate) mod rules;
#[cfg(test)]
mod same_boot_replacement_tests;
mod serve;
#[cfg(test)]
mod serve_clone_tests;
#[cfg(test)]
mod serve_data_crc_tests;
#[cfg(test)]
mod serve_linger_tests;
#[cfg(test)]
mod serve_search_tests;
#[cfg(test)]
mod serve_tests;
mod served;
pub(crate) mod serving;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod serving_tests;
mod session;
#[cfg(test)]
mod session_bootstrap_floor_tests;
#[cfg(test)]
mod session_repeat_confirm_tests;
#[cfg(test)]
mod settle_replay_tests;
mod sha_lanes;
#[cfg(test)]
mod sha_lanes_tests;
#[cfg(all(target_arch = "aarch64", target_endian = "little", not(miri)))]
pub(crate) mod sha_one;
mod slot_index;
#[cfg(test)]
mod status_literal_tests;
#[cfg(test)]
mod tag_compare_tests;
#[cfg(test)]
mod tag_group_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod takeover_history_tests;
#[cfg(test)]
pub(crate) mod terminal_tests;
#[cfg(test)]
mod transport_tests;
mod upload;
#[cfg(test)]
mod upload_full_receipt_tests;
#[cfg(test)]
mod upload_outcome_tests;
#[cfg(test)]
mod upload_publication_tests;
#[cfg(test)]
mod upload_source_slot_tests;
#[cfg(test)]
mod upload_tests;
#[cfg(test)]
mod window_tests;
#[cfg(test)]
pub(crate) mod witness;
#[cfg(test)]
mod witness_tests;
#[cfg(test)]
#[warn(clippy::disallowed_methods)]
pub(crate) mod world_tests;
#[cfg(test)]
mod write_tiling_tests;

pub use auth::{
    AuthError, Authenticated, EntropyError, KEY_LEN, KeyEntry, KeyError, KeyRing, TAG_LEN,
    boot_nonce,
};
pub use client::{
    AdmissionRefusals, Client, ClientConfig, ClientError, ClientMemory, GetRefused, Invalidated,
    PollReport, PutRefused, SessionState, route::ShardRoutes,
};
pub use client_namespace::{
    ClientNamespace, ClientRecord, ClientRequest, ClientRequests, IdentityPressure,
};
pub use datagram::{
    DatagramError, Datagrams, FRAME_OVERHEAD, HEADER_LEN, MAX_DATAGRAM, MAX_PACKED_GETS,
    MAX_PAYLOAD_SLICES, MAX_PEERS, Outgoing, Payload, PeerId, Received,
};
pub use fetch::{
    Ask, Decider, FIRST_SEND_BUCKETS, Fetch, FetchConfig, FetchCore, FetchCoreError, FetchLimits,
    FetchPressure, FetchReport, FragmentLease, Outcome, OutcomeCounts, Releases, Terminal, Wanted,
};
pub use frame::{
    AUTHENTICATED_LEN, BOOTSTRAP_BODY_LEN, Direction, Field, Frame, FrameError, Header, Kind,
    MAGIC, MAX_SLOT_CAP, MAX_WINDOW, MacInput, RETRY_DOUBLINGS, Status, VERSION, encode,
    mac_input_for, parse, seal,
};
#[cfg(fuzzing)]
pub use frame_differential::{Verdict, judge};
pub use geometry::{
    BUFFERS_PER_READ, FRAGMENT_LEN, FragmentGeometry, GeometryError, GeometryInputs,
    GeometryRefusal,
};
pub use memory::{
    EndpointConfig, EndpointConfigError, EndpointMemory, SourcesError, ValidEndpointConfig, sources,
};
pub use namespace::{
    Cached, Namespace, Operated, Operation, Refusal as NamespaceRefusal, Route, WireSlot,
};
pub use owner::{
    Blockers, Bundle, DrainStage, DropReason, Handoff, Keys, Owner, OwnerCharges, OwnerConfig,
    OwnerError, OwnerRekeyError, OwnerReport, POLL_GAP_BUCKETS, Refused, RetainedCensus, Shutdown,
    TurnSources,
};
pub use pace::Pacer;
pub use packet::{
    PacketExhausted, PacketLease, PacketPool, PacketPoolError, PacketPoolReport, PacketUse,
};
pub use parked::{FollowConfig, ParkedReport};
pub use put::{PutConfig, PutReport};
pub use requests::{
    GENERATION_LIMIT, MAX_REQUEST_SLOTS, PeerCensus, RequestCensus, RequestId, RequestPressure,
    RequestTable,
};
pub use serve::{
    Chunk, ChunkInput, GetOutcome, GetRow, Manifest, Out, PressureRefusals, ReadEnd, Retained,
    Serve, ServeConfig, ServeCore, ServeReport,
};
pub use served::{Outcome as OwnerOutcome, Request as OwnerRequest, Requests as OwnerRequests};
pub use session::{
    Activation, Admitted, Bootstrap, CONFIRM_REPEATS, Caps, RekeyError, Replaced, Role,
    SessionReject, SessionReport, Sessions,
};
pub use upload::{
    PrepareRefused, SourceSlot, SupplyRefused, Upload, UploadConfig, UploadCore, UploadOutcome,
};
