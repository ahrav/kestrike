//! Storage for one device volume: configuration validation, checked record
//! layout, the extent allocator and its raw-byte ledger, work budgets, the
//! owned control mappings that realize a validated configuration, and the
//! device fill and hit paths through the one owner-thread volume.
//!
//! Invariants owned by this module:
//!
//! - The named invariants, each stated in full by the bullet or module it names:
//!   - REUSE: an extent returns to the allocator only after service observes its slot's count at zero, so no lease, read operation, write set or quarantined command names a reused extent (in-flight rights, below).
//!   - TERMINAL: a buffer a device command holds comes back only in that command's terminal event or at a proven stop (the `device` module).
//!   - REJECT-OWNS-NOTHING: a refused reservation, submit, read or receive leaves the buffer with its caller and keeps no token or record; a right it took is released before it returns (typed refusals, below).
//!   - PUBLISH-COMPLETE: a fill publishes only once every write of its record reached a successful terminal and its write right was released.
//!   - REVOKE: an invalidation revokes the key's current attempt in the hold that ends its mapping, so a revoked fill never publishes (the fill tables, below).
//!   - EVICT-NO-REUSE: an evicted, replaced or abandoned object's extent stays held while any right names it, so a command in flight never meets a reused extent.
//!   - BOUNDED: buffers, table slots, read operations, write sets, quarantine, the allocator's work and each tick's work have validated finite limits; reaching one is a typed refusal, except an admitted read whose command finds the read share, the table or the device queue full, which waits under a kept grant with no buffer and no table slot until a tick submits the command or the read's deadline ends it. Every claim leaves the validated clean reserve `R` of free units: a claim of `C` charged units needs `free_units >= C + R + U` under the pool gate, where `U` is the escrow of units promised to multi-extent builders, and otherwise refuses `CleanReserve` with no slot, free-set, extent or ledger change.
//!   - NO-HIT-ALLOC: lookup, lease reads, the tick, table submits and buffer acquires allocate nothing after construction; the exceptions are the warm bootstrap, whose ticks allocate its held bitmap and lane batches and start and join scoped workers, and a suffix log's delta writer, for an open log and for a closed one whose sealed blocks still drain, whose stage encodes and checksums one sealed block into the write's buffer and whose sealed and written blocks grow the log's two block queues and its spare-payload list, each when its occupancy passes the capacity it holds, within the queue bound (the `volume` module's Tick bounds).
//!   - NO-UNINIT-SEND: payload bytes leave only as verified chunks of device-read data; the fill zeroes padding before its submit, and a failed, short or quiesced buffer returns uninspected.
//!   - COLD-START: a new storage's allocator starts with every payload unit free and its index starts empty; every attach makes its tenure's session durable on both root slots before its first payload write, through a RESET, except that the warm bootstrap writes no root and opens over the guarded slot load under the tenure's acknowledged session, and every read checks the record's session against the slot's record generation, which `bind` sets to that session.
//!   - ONE-WRITER: a [`Storage`] attaches at most one [`Volume`] over its life; that volume owns the command table and stays on the thread that attached it, which submits every device command, every metadata command included.
//!   - ONE-QUALIFIED-WRITE-PER-BLOCK: the metadata prefix splits into blocks of the attach-time persistence profile's unit, every one of them qualifying, and each metadata block reaches the device as one write of its whole range (the `recovery` module).
//!   - EVIDENCE-ORDER: a metadata write that depends on a block is submitted only after that block's `Persisted`, the evidence a successful write terminal of its qualifying range gives (the `recovery` module).
//!   - WHOLE-OR-ABSENT: a metadata block decodes only when its magic, version, recorded layout, whole-block crc32c, role, format ID, generation and self-index all match (the `recovery` module).
//!   - NO-REISSUE: an attach writes under its tenure's session `g·2^32 + a` from the shard record's acknowledged `E` bump, never a value derived from the medium, and refuses a medium holding a valid root at or above it, so no two attaches of one shard write under one session (the `recovery` module).
//!   - RESET-BEFORE-OVERWRITE: the RESET writes the slot without the highest valid root first and the other slot only after the first is persisted, and payload writes start only after both are, or after the warm bootstrap's allocation-readiness commit, which writes no root (the `recovery` module).
//!   - EXCLUSION-BEFORE-REUSE: a resident retirement's position is `NO_RECORD`, or, once the tenure's suffix recorded a removal, the position of the newest recorded removal's last block, and service returns the retired slot's extents once no right remains and that block lies inside the durable prefix; a reused extent fails the header identity a checkpoint names for it, and after a pool-gate holder observes close it returns held slots, since every later fill write meets the `SeqCst` cutoff (the `recovery` module).
//!   - GAPLESS-PREFIX: the durable prefix word is an exclusive LSN frontier that ends a gapless run of the tenure's persisted suffix blocks from its start and certifies no predecessor LSN; it starts at zero, never decreases, and the volume's delta writer is its one writer, storing it with release for service's acquire load (the `volume` module's checkpoint).
//!   - ALLOCATION-READY: fill reservations and builder promises proceed only while no volume attached or the attached volume's readiness word reads `Live`; `Storage::withdraw` moves it to `Withheld` and passes the pool gate before it returns (the `readiness` module).
//!   - REPORT-BOUNDED: the recovery report holds counts, byte totals, tick times and typed states in fixed-size fields, and no key, identity or request value (the `volume` module's report).
//!   - BOUNDED, ADOPT-ONCE, CONTAINED, PLACED for recovery helpers: a warm attempt's slot, conversion and free jobs own their inputs, stay within the attach's recovery limits, are adopted only under their attempt's tag, end a panic as a typed terminal that closes the attempt with no write, and run on the configured recovery CPUs (the `volume` module's helpers).
//!   - READ-READY: a slot carrying the recovered-origin marker grants a lease or a lookup only while the readiness word reads `Live`; the warm bootstrap installs every restored slot with that marker (the `volume` module's warm).
//!   - RAW-CONSERVATION: the volume's [`RawPartition`] (metadata, free, reserved, resident, retired, waste) sums to its raw bytes after every gate-held change, and its metadata term stays `M * IO_UNIT`.
//!   - IDENTITY-BEFORE-BYTES: a volume read exposes payload bytes only as chunks whose crc32c matched the header's table, after the record header's own crc32c matched, its key, incarnation, session and cache version passed the read predicate against the index entry and the volume's session, and its extent index, payload offset and context crc32c matched.
//! - Acknowledgements apply to the live storage that performed each operation:
//!   - Completed: every write of a fill's record reached a successful device terminal ([`WritableFill::is_ready`]).
//!   - Published: [`WritableFill::publish`] made the mapping visible to this process and returned the object's first lease.
//!   - Invalidated: [`Storage::invalidate`] ended the fingerprint's RAM mapping and revoked the key's current attempt in one shard gate hold.
//!   - Evicted: eviction ended the resident's mapping; its extent stays held while any right names it (EVICT-NO-REUSE).
//!   - Released: service returned an extent to the allocator after observing its slot's count at zero (REUSE).
//!   - Restarted: each storage instance starts with an empty index and an all-free allocator, and its volume's attach RESETs both root slots under its session or opens a warm bootstrap's guarded slot load under it (COLD-START).
//! - A [`ValidatedConfig`] exists only for a configuration that passed every
//!   check in [`StorageConfig::validate`]; no numeric limit has a default.
//! - An [`AllocationLayout`] lays out one extent's record: the header's bytes, whose
//!   length follows from the payload length, then metadata, then the body
//!   immediately after it, with only trailing padding to a whole
//!   [`IO_UNIT`]. `body_len <= Bmax` and `metadata_len <= Mmax` are checked
//!   independently, both fit the header's 32-bit fields, and `AllocationLayout::new`
//!   requires the payload to fit one extent, `EXTENT_PAYLOAD` bytes, else [`LayoutError::MultipleExtents`];
//!   an object of several extents is laid out one record per extent, the first
//!   through `AllocationLayout::of_extent`, with `payload()` the whole object's. An empty
//!   allocation still spans one unit, and validation keeps the largest
//!   object's payload, `Mmax + Bmax`, within 512 MiB and its charge, every
//!   extent's summed, inside the payload range, so every admissible layout
//!   fits an empty volume.
//! - Volume geometry: the configured `V` units split into `M` metadata units at device units `[0, M)` and `P = V - M` payload units at `[M, V)`, with `1 <= M < V`; [`ValidatedConfig::geometry`] yields both, and the allocator, its tables, the work bounds, the ledger and `PoolDescriptor::device_range` take their units from it.
//!   Payload unit `u` lies at device byte `(M + u) * IO_UNIT`.
//! - Partition totals are checked, never wrapped. RAW-CONSERVATION: the
//!   volume's [`RawPartition`] (metadata, free, reserved, resident, retired,
//!   waste) sums to its raw bytes, and the slot partition to `O`, after every
//!   gate-held change.
//! - Every refusal is a distinct typed value carrying fixed data. A refusal
//!   leaves the caller's inputs and claims untouched; what a refused call may
//!   change is the work budget it debited before the refusing step, the
//!   telemetry counting the refusal, a shard's terminal or poisoned state
//!   where the refusal names it, the reader's own scratch, and a slot's
//!   count, which a refused device submission raises by its transient right
//!   and lowers again before returning; an observer that reads the raised
//!   count holds the slot for one service pass and revisits it.
//! - A record's body follows its metadata directly; control types use their
//!   natural Rust alignment.
//! - A [`Storage`] owner exists only after its root and control
//!   mappings (and the index mapping, when configured) are advised for
//!   transparent huge pages, bound to their node masks, then populated,
//!   checked page by page for residency (`mincore`) and chunk by chunk
//!   against the mask (one `MPOL_MF_STRICT` walk), advised for normal pages,
//!   which keeps the populated huge pages and disables later collapse, and every
//!   control value is written in place; a
//!   failed initialization rolls back every acquired mapping at its original
//!   extent exactly once or reports incomplete cleanup. The owner is `Live`,
//!   `Finalizing` or `Drained` ([`Phase`]); exclusive, resumable finalization
//!   releases the extents in reverse ownership order and reports drained
//!   only after every release completed, and dropping an owner without
//!   finalizing abandons its mappings.
//!   `E_used` counts every mapping at its full extent plus the volume handle
//!   and, with an index, its geometry tables, hash state, bucket runs and
//!   shard placement records; `E_init_peak` adds the 1024-byte residency
//!   scratch. Initialization refuses `Envelope` when either exceeds `E`.
//! - Every allocation structure (the extent allocator's root record, its
//!   free-unit bitmap with run summaries and its run index, one 32-byte
//!   record per slot, the free-slot set,
//!   the retired bitmap, cursors) lives in the
//!   volume's control mapping, is sized once from the validated
//!   configuration, initialized in place and charged once to `E`, and never
//!   moves or grows. The allocator is reached only under the pool gate,
//!   through a view over its tables.
//! - Each slot's record is 32 bytes, two to a cache line: the lifetime word
//!   at 0, the fingerprint at 8, the locator at 16 (one extent, or a
//!   sequence handle naming the arena block that lists the object's
//!   extents), the deadline's
//!   whole seconds at 24 and the eviction policy's `prev` link at 28. One
//!   overlay shares a field: once a retired object's mapping has ended the
//!   fingerprint holds its retirement era. A record's lengths and
//!   chunk checksums live in its header on the device, which a volume read
//!   verifies before any payload byte. The ledger takes a held slot's payload
//!   length from its extents' units and the slot's 2-byte tail, the last
//!   extent's record length modulo [`IO_UNIT`] that the claim stores, every
//!   earlier extent of a sequence carrying a full extent's payload. The slot record holds
//!   the lifetime word, fingerprint, locator, deadline and `prev` link; the
//!   `slot` module states it.
//! - Each slot's lifetime word is one `AtomicU64`: the incarnation in bits 0
//!   to 31, the abandoned, retired and anchored flags in bits 32 to 34,
//!   SIEVE's visited bit in bit 35, the slot state in bits 36 to 38, the
//!   eviction policy's linked, detached and evicted bits in bits 39 to 41,
//!   the recovered-origin marker in bit 42, bits 43 to 45 zero, and the
//!   reference count in bits 46 to 63. Only the
//!   pool gate's holder, or a restore lane worker it starts and joins within
//!   its hold, writes the state and policy bits, and readers without the gate
//!   ignore them. A nonzero reserved bit fails closed wherever the
//!   word is read, and a state encoding past `Quarantined` wherever a gate
//!   holder reads it. Every write is a read-modify-write: the claim's
//!   exchange from the `Free` value once the extent is reserved, the
//!   restored install's release exchange from the `Free` value, the
//!   publication's release exchange installing the anchor on a zero count,
//!   the volume's release exchange installing a fill's write right on a zero
//!   count, the retain's exchange expecting the word it validated, which a
//!   lookup and a volume read make, the release `fetch_sub` of a lease, a
//!   refunded reservation, a refused fill publication and a write or read
//!   operation's right, the park's exchange conditioned on its incarnation,
//!   the gate-held retirement's `fetch_update`, the gate holder's state moves and
//!   policy bit writes, the anchor release's one exchange, and the return's
//!   and the hand's `fetch_and`. So a flag always describes the incarnation
//!   beside it and every release sequence on the word reaches the next claim.
//!   The `word` module states the layout and transitions.
//! - Free slots form the `free` module's set, one bit per slot under
//!   summary words. A claim made for a key takes the lowest free slot of
//!   the key's placement window, the four slots whose records fill two
//!   cache lines that the fingerprint selects, or the first free slot after
//!   the window when it is full; a claim without a key takes the first free
//!   slot at or after the claim cursor, which then moves past it; a return
//!   gives the slot back and a reservation refused after its claim gives
//!   its slot back unchanged. A lookup hints its window's lines beside its
//!   bucket hint, and hints each candidate's record line for writing ahead
//!   of the lifetime-word load to request the line's ownership for the
//!   retain's exchange; a fill's grant hints the window's lines
//!   before its claim on targets whose atomic exchange proceeds past
//!   outstanding hints. A slot's
//!   incarnation advances
//!   by one per object that held the slot, with checked arithmetic, and a
//!   slot whose counter is exhausted is quarantined, so a full
//!   `(slot, incarnation)` names at most one object. An index pair copies
//!   the incarnation's low 16 bits, which match a later occupant after
//!   `2^16` reuses of the slot; a lookup's copy lives inside one pinned
//!   interval that grace certification outlasts, so the slot stays anchored
//!   and unreused for the copy's lifetime.
//! - A reservation claims one slot and an extent of
//!   `ceil((header_bytes + metadata_len + body_len) / IO_UNIT)` units by the
//!   allocator's fit rule, then advances the slot's incarnation with checked
//!   arithmetic before the identity is issued; the largest extent's work
//!   bound plus one give-back step is preflighted from the caller's [`WorkBudget`] and
//!   the search's visits debited, and a shortage or an unfunded search
//!   restores the slot and refuses with the free set, the ledgers and the
//!   slot's word unchanged. The [`ExtentReservation`]
//!   owner borrows the storage, is not `Clone`, names the slot,
//!   incarnation, extent and layout, and on drop records abandonment in pre-reserved state without waiting
//!   for the gate. After close, admission refuses and every existing owner
//!   stays valid.
//! - An extent comes back only through a [`ReturnTransfer`] made by
//!   consuming its owner, spent at most once by construction and rejected
//!   when the slot's word no longer matches, or through service. A return
//!   merges the extent with its free neighbours; it preflights the extent
//!   work bound for its extent, with the gate attempt on a transfer's return
//!   and with the slot's bundle in service, and debits the visits the merge
//!   counted, and a rollback of an unwritten reservation returns
//!   uncharged. A return that cannot take the gate or fund that bound parks
//!   the obligation in pre-reserved state; bounded service walks slots from a
//!   persistent cursor, prepays its call controls and one whole bundle per
//!   examined slot, funds a flagged slot's return bound the same way, and
//!   stops in front of a slot it cannot fund. After
//!   admission closes, the bounded close service sweeps the index, services
//!   the volume and certifies grace behind a persistent cursor and reports
//!   only what it observed; finalization's inspection blocks while any
//!   owner or pending obligation remains and fails on a poisoned gate, so
//!   drained is never early.
//! - Completing a reservation, under the gate, checks the slot's word,
//!   writes the key's fingerprint and the deadline's whole seconds,
//!   moves the slot from `Filling` to `Resident` and its payload bytes from
//!   reserved to resident, and consumes the unique owner; a refusal hands
//!   the owner back and the issued incarnation stays consumed. The
//!   [`Completed`] owner holds the storage borrow and the object's identity.
//!   The locator, the tail and the deadline change again only after the
//!   return of the extent, which consumes the owner; an owner that reaches
//!   the return holds a zero count, since no write was submitted or its last
//!   write's terminal released the right. The fingerprint changes once
//!   before that return: it takes the retirement era when the mapping ends.
//! - A lease holds one engine-wide credit within `L` and one per-slot read
//!   right, and a reserved fill holds two credits within `L`, the
//!   publisher's, which its first lease takes, and its terminal read
//!   right's; a slot's `refs` is its rights, the leases', the in-flight
//!   operations' below and a fill row's retained right, plus an anchor in
//!   `{0, 1}`, and `C + 1` fits the word's 18-bit count.
//!   [`WritableFill::publish`] counts the anchor and the publisher's right together, with the row's retained right when a follower is joined, and returns one [`ExtentLease`]; `C` is at least two so that count stays within `C + 1`.
//!   [`Volume::read`] reads the object's record from the device under an
//!   [`ExtentLease`]. Dropping a lease releases its right, returns its
//!   credit, then ends its borrow, and touches nothing else.
//!   Clearing the object's mapping, by invalidation or by a replacement's commit, retires the object: the slot is flagged for service, the era is bumped
//!   once and the slot is stamped with the era it retired at; the anchor
//!   stays counted. Service returns a flagged slot only after observing
//!   `refs == 0`, which requires every right released and the anchor gone; a
//!   retired slot with rights or its anchor outstanding is held, counted, and
//!   revisited. Finalization drains only when no slot is held or pending, no
//!   credit is reserved, no count is nonzero and no registration record is
//!   claimed. The `lease` module states the ordering proof.
//! - In-flight rights: a fill's write set holds one right in its slot's
//!   count while any of its write commands is outstanding. The submit that
//!   finds none outstanding installs it on the `Filling` slot with a
//!   compare-exchange from a zero count, and the terminal that leaves none
//!   outstanding releases it with a `Release` `fetch_sub` before the progress
//!   it completes, so a set is never ready while its right is counted. A read
//!   operation holds the right its lease or its lookup reserved, taken over
//!   before its first submit and released on the volume's thread when its
//!   record frees, after its last terminal. Service returns an extent only after observing the count
//!   at zero, so every read, write and quarantined command of the extent has
//!   reached its terminal before the extent returns: the count carries lease
//!   authority and device quiescence together. A read adds no right to the
//!   count, so the rights an unmapped object can still gain come only from
//!   lookups that copied its identity before the unmapping, which keeps a
//!   park's retries finite. Releasing a quiesced volume applies every terminal it
//!   took and frees every live read, so every right it took ends with it.
//! - The volume has one eviction policy domain, a list linked through each
//!   slot's record (`prev`) and one gate-owned `u32` per slot (`next`) in its
//!   control mapping, charged to `E` once with it, with its linked, detached
//!   and evicted bits in the slot's word. A slot links at the head in the
//!   hold where `bind` makes it resident, inside that call's one update
//!   debit, and leaves in the first hold that finds its current incarnation's
//!   retirement while it is linked (`abandon` with the gate, or service
//!   sighting a parked retirement), which marks it detached and counts it, or
//!   at its extent's return, whose read-modify-write that frees the word
//!   clears its bits. The gate holder writes the bits with one `fetch_or`,
//!   `fetch_and` or `fetch_xor` per write, or inside `bind`'s `move_state`
//!   and the retirement's `fetch_update`, so a racing retain, release or
//!   park keeps its own bits,
//!   and `link_with`, `detach` and `mark_evicted` assert their preconditions on
//!   the bits, so a violated one panics and poisons the gate;
//!   `release_evicted` clears the evicted bit only when it is set. The linked bit is the single authority,
//!   so each incarnation unlinks once and a stale park, which changes no bit
//!   of the word, never unlinks the current occupant; a free slot is never
//!   linked. A registered hit, scalar or batch element,
//!   records SIEVE's visited bit in the retain's exchange that takes its
//!   right, and a refusal before the retain records nothing. No correctness
//!   check reads the bit. The `policy` module states why a reused slot never
//!   inherits a stale hit.
//! - One internal eviction step selects a victim in the domain by SIEVE
//!   under the pool gate: parked retirements are detached, unpublished and
//!   leased members are retained with their visited bits untouched, visited
//!   bits are cleared with a `fetch_and`, and the candidate is a resident,
//!   unflagged, anchor-only member. Selection spends only the allowance
//!   above a reserved commit bundle. After the pool gate is released the
//!   candidate is removed by exact identity under the shard gate, refused as
//!   replacing while a current, undeparted attempt's key has its
//!   fingerprint; the fill table keeps each attempt's fingerprint beside its
//!   key for that check.
//!   The commit tries the pool gate under the shard gate only when an in-flight pass needs the member's entry or a required suffix its identity, one nonblocking try whose failure refuses the commit. A found commit retires the
//!   object through the ordinary path. A hold that records a resident's
//!   retirement also applies the mark; a parked retirement leaves one
//!   pending mark, applied only while the slot still
//!   holds the victim's incarnation, which counts the slot and its extent's
//!   units in flight while its anchor is still counted, until its return or
//!   until service finds the anchor released while rights remain. The
//!   `evict` module states the rules.
//! - One internal expiry step reads the volume's published deadline bound,
//!   the least deadline seconds any resident may have as the gate holder
//!   last published it, samples the monotonic clock once per call, before
//!   taking the pool gate, and walks slots from a
//!   persistent cursor when the sample's whole seconds reach the bound; the
//!   first resident, unflagged, anchor-only slot whose deadline seconds the
//!   sample's whole seconds have reached (equality is expired) is removed by
//!   exact identity after the gate is released, without the replacement
//!   check, and counted in flight by the same mark. A missing sample skips
//!   the stage, as does a sample below the bound, with no gate taken. The
//!   sweep applies lookup's whole-second rule, so it removes only an object
//!   lookup already refuses as `Expired`; on the sampling thread's timeline
//!   removal precedes a deadline within `u32::MAX` seconds by less than one
//!   second, and any later removal is sweep delay. Lookup alone decides
//!   validity. The `expire` module states the rules.
//! - [`Storage::maintain`] runs the persistent cycle Fills, Certify,
//!   Reclaim, Expiry, Headroom (fill service, one certification call, slot
//!   service, one expiry step and one headroom decision), each under a
//!   persistent cursor that advances after its unit, behind a root gate
//!   distinct from the grace maintenance and close gates; busy inner gates
//!   are counted and skipped. It reports the bytes of the full extents
//!   Reclaim returned and the storage I/O the call debited, which is zero. It refuses below a minimum derived
//!   from the configuration, does nothing at zero budget, and evicts only
//!   while the domain has members and the volume's placeable units (each
//!   free run's whole charges of the largest object's first extent) less
//!   the escrow, clamped at zero, plus in-flight units, fall short of
//!   `low_units`, or its free plus in-flight slots fall short of
//!   `min_free_slots`; a domain whose remaining members are all held stops
//!   without a victim. After close it delegates to the close service
//!   without taking its root gate. Watermarks are validated configuration
//!   with no defaults; a storage without them refuses maintenance while
//!   admission is open. The `maintain` module states the rules.
//! - Readers register into one of `R` preallocated 64-byte records in the
//!   root control mapping through a non-`Clone` [`Registration`] that borrows
//!   the storage. A protected interval pins the current era into the record
//!   with one `SeqCst` store after reading the inactive zero, reads the
//!   admission cutoff once more, and clears the pin on exit; any observation
//!   of reclaimable state must happen inside such an interval, and one
//!   interval exists per registration by the exclusive borrow it takes.
//!   Entry, exit and the candidate snapshot are private to the crate: the
//!   synchronous lookup is the only path that pins, and it ends the pin
//!   before its lease or refusal escapes, so no guard or copied candidate
//!   leaves an interval. A retired slot's anchor
//!   is released by service only once a completed, resumable, budgeted
//!   certification pass ([`Storage::certify`]) has proved that every reader
//!   still pinned started after the retirement; the `grace` module states
//!   the ordering argument and the accepted tradeoff that a paused reader
//!   stalls reclamation in its domain while memory stays bounded.
//!   Certification and service prepay their work in whole bundles and a
//!   test-only observer counts the steps they take against the charge. Every
//!   retirement stamped in the terminal era band closes admission before it
//!   publishes its mark, allocation rechecks the cutoff under the pool gate
//!   before its claim commits, and validation keeps the summed slot count
//!   within the stamps above the band, so nothing wraps or resets.
//! - One non-`Clone` [`Cache`] facade borrows the storage and is issued at
//!   most once, through a fixed bit in the root image claimed by one
//!   compare-exchange; issuance on closed storage is `Closed` and a second
//!   issuance is `AlreadyIssued`. The facade adds no second
//!   lookup engine: it forwards to [`Storage::register`] and
//!   [`Registration::lookup`]. Registrations and leases borrow the storage,
//!   not the facade, and stay valid after it is dropped. Dropping the facade
//!   is one `SeqCst` store of the admission cutoff, the store
//!   [`Storage::close`] makes; it neither waits nor sweeps nor releases a
//!   mapping. Every admission path reads that one cutoff with `SeqCst`;
//!   [`Storage::close`] states which stores that orders against and who
//!   consumes the order. Existing leases, exit, release, return, internal
//!   removal, certification and service stay legal after close. The storage
//!   itself is destroyed only by its owner, and never while a facade,
//!   registration or lease borrows it.
//! - [`Registration::lookup`] pins the interval before any bucket load,
//!   copies the key's candidates under a stable shard sequence, validates a
//!   candidate's slot bound, its current incarnation and a
//!   positive count before reading its record's fingerprint, compares that
//!   with the key's, reserves, and then takes a fresh `CLOCK_MONOTONIC` sample and the
//!   cutoff inside a bracket the unchanged sequence closes; that sample's
//!   instant is the Hit witness. A moved sequence refunds and retries within
//!   the attempt allowance; `Expired` needs the same unchanged mapping.
//!   Every refusal ends the pin and refunds before it returns, and a
//!   candidate that fails a check before the fingerprint fails closed as
//!   `Contended`, never as `Missing`. A fingerprint load that reads a
//!   retirement era never yields `Missing` or a hit: the attempt's closing
//!   bracket finds the sequence moved and spends the attempt, and every
//!   earlier exit returns another error. Existing leases stay valid through expiry
//!   and close.
//! - The fingerprint is an object's identity in RAM. Each slot record holds
//!   the key's fingerprint, the fill table holds each attempt's full key,
//!   and the record header on the device holds the object's full key.
//!   Every lease carries the key it was taken for, and [`Volume::read`]
//!   checks the record header's key against it before any byte, so a lease
//!   on an object of a different key with an equal fingerprint ends its
//!   read `HeaderMismatch(Key)` and counts in
//!   [`VolumeReport::lookup_false_positives`]. The index holds at most one
//!   visible object per fingerprint: publication takes an incumbent with an
//!   equal fingerprint as its place, so two such keys displace each other
//!   and the displaced object retires as a replaced incumbent. Invalidation
//!   removes every visible object with the key's fingerprint, whichever key
//!   it was published under, so it may remove another key's object as well.
//! - A batch ([`Registration::lookup_batch`]) is the scalar lookup applied in
//!   input order to `n <= BatchMax` keys and `n` empty caller-owned slots:
//!   one pin, one set of attempts, one right and one witness per element,
//!   with earlier leases kept across later refusals, and one structural
//!   refusal before any element when the width, the lengths, an occupied
//!   slot, the prepaid overhead or the cutoff forbids the call. The scalar
//!   scratch is reused across elements.
//! - An index pair is one 8-byte word: the key's 16-bit tag, a slot and the
//!   low 16 bits of its incarnation. It names an [`AllocationId`] only when
//!   the slot lies below the slot count and its current incarnation carries
//!   those bits; a lookup candidate that fails either check is refused before
//!   any fingerprint read and never yields a hit, and a gate holder that
//!   meets one poisons the gate. A tag match is a candidate only: the
//!   fingerprint decides, so a tag shared by two keys costs one record read.
//! - Publication, replacement, removal and invalidation walk the key's
//!   bounded chain under the shard gate and share the sequence bracket;
//!   replacement, removal and invalidation record each ended mapping through
//!   one retirement path; lookup scans the same chain under a stable
//!   sequence alone. Removal clears exactly one pair and returns an overflow
//!   bucket it empties to the shard's free stack.
//! - Each index shard owns a fixed fill table of `F[s]` records in the root
//!   mapping, laid out, checked and charged with the root extent at
//!   initialization. [`Storage::begin_fill`] grants at most one current
//!   attempt per full key per shard under the shard gate, as a non-`Clone`
//!   [`FillAttempt`] that borrows the storage and promises no storage and no
//!   publication; its identity is the shard and a checked serial that never
//!   wraps or resets, and a shard whose serial is exhausted grants nothing
//!   further while cleanup and invalidation keep working. Each record has a
//!   row, laid out and charged with the table, that holds its producer's
//!   terminal, its joined followers and the object a follower reads, as the
//!   `row` and `join` modules state; service frees a departed record only
//!   once no follower is joined. Aborting or
//!   dropping the attempt departs its record with one `Release`
//!   compare-exchange and never waits; the record stays occupied, and the key refuses
//!   `InProgress`, until [`Storage::service_fills`] observes the departure
//!   with `Acquire` under the gate and frees it. Invalidation is joint: one
//!   hold ends the resident mapping with the key's fingerprint and revokes
//!   the key's current attempt
//!   before the same even sequence store, and revocation clears the
//!   association only, never the record. Finalization blocks on every
//!   forgotten attempt, unserviced departed record and custody reference.
//! - [`FillAttempt::reserve_storage`] consumes the attempt on every outcome and, on success, yields the non-`Clone`, non-`Send`, non-`Sync` [`WritableFill`] that uniquely owns the object's extents and streams each extent's record to the device through the volume, in order, each extent's header after its payload.
//!   The advisory [`Admitted`] decision is verified against the lengths the caller passes and the live storage's record format, and an object of several extents is claimed by promising its whole charge and placing every extent, so a forged decision grants nothing beyond what the live storage would; the extent is claimed outside the shard hold and the record revalidated under it, with no gate held while another is taken.
//!   A receive copies payload bytes into staged receive-write buffers at their record offsets, folding each chunk's crc32c, zeroing the bytes from the record's end to the extent's end, and submits each full segment; the segment holding the header, with the volume's session, submits last, once every chunk checksum is known, and a refused submit leaves its buffer staged and copies nothing further. A refused reservation returns or parks its claims once and departs only its own record.
//!   Abort and drop dispose of the extent through the reservation's own owner path before the record departs, and a disposal panic leaves the record occupied.
//!   Revocation forbids publication and further receives: a revoked owner keeps its extent and record until it ends.
//! - [`WritableFill::publish`] refuses `ForeignVolume` for another storage's volume, then `Lost` for a lost volume, then `Closed` when the volume's serving token is absent or of another lineage than the fill's, or refuses fills at the owner's latest deadline sample, then `Incomplete` unless every write of the record reached a successful terminal and none failed, each before binding the record or taking the shard gate and leaving the index unchanged, while consuming the refused fill can try the pool gate; it then revalidates under the shard gate and records custody of the candidate, incumbent, and phase before suppressing candidate destruction, so unwinding leaves every claim discoverably owned.
//!   The anchor, the publisher's right and its lease credit, and with a follower joined the row's retained right and the terminal credit, are owned before exposure; with none joined the terminal credit returns once custody names the claims.
//!   Inside the odd–even bracket the clock is read at most once and the cutoff once; the clock and cutoff verdicts `Closed`, `ClockUnavailable` and `Expired`, then a required suffix's refusal of the record, or of a publication whose bound on the set a replay could rebuild lies past the suffix layout's entry cap, `History`, are the refusals there, each with a fresh even and no index mutation, and the incumbent stays visible through every refusal.
//!   An unwind while the sequence is odd leaves it odd and poisons the gate; an unwind after the even store and before settlement makes the shard terminal and keeps every claim.
//!   Each flagged-record load in the credit path is one paid visit.
//! - The [`device`] submodule holds the storage-device substrate: a
//!   hugepage-backed buffer arena that is charged, bound, populated and
//!   verified at startup, carved into the configured pools of exclusive buffer
//!   handles (the storage kinds, and the packet kinds a network endpoint
//!   receives into and builds headers in, whose buffers a device may keep
//!   referencing after their handle dropped), and unmapped at most once, after every buffer is free; and
//!   the `unsafe` `Disk` seam a storage driver implements, with its range,
//!   geometry and status rules; and the command table, the only safe
//!   submission path, which owns every submitted buffer until its terminal
//!   event or a proven stop. Its one storage-side owner is the volume
//!   below. The production driver is [`SpdkDisk`], the SPDK NVMe poll-mode
//!   driver on the EBS controller `kestrike-bind` bound to `vfio-pci`,
//!   with one I/O qpair and the arena registered through the shared
//!   registration guard.
//! - The `extent` submodule holds the volume's extent allocator: one bit
//!   per [`IO_UNIT`], set while free, under a radix tree of free-run
//!   summaries over 512-unit chunks, and an index of maximal free runs
//!   keyed `(len.min(2^24 - 1), start)`, one B+ tree per run length below
//!   256 units and one for longer runs, capped at
//!   `slot_count.div_ceil(8)` entries; a full index keeps its largest keys
//!   and drops the smallest of its entries and the offered run, which stays
//!   free in the bitmap. A reservation takes the smallest indexed key that
//!   fits, the exact best fit among indexed runs shorter than `2^24 - 1`
//!   units, and falls back to address-ordered first fit through the
//!   summaries when the index holds none; a return sets its extent's bits,
//!   so free neighbours coalesce, and indexes the joined run. Every
//!   reservation and return counts the words and nodes it visits, updates
//!   included, within the bound derived for its extent and at most
//!   `alloc_search_words`, which validation checks against the bound for the
//!   largest extent; a reservation or a return preflights that bound, which
//!   equals every admitted extent's, from the caller's [`WorkBudget`] and
//!   debits its visits, and the
//!   [`RawPartition`] ledger sums to the volume's raw bytes. The storage is
//!   its one caller, over tables in the volume's control mapping.
//! - The `record` submodule holds the record format: crc32c computed by one
//!   mechanism chosen at [`Crc32c::detect`], the [`RecordLayout`] of the
//!   header's bytes, metadata and body cut into record-aligned chunks, and
//!   the checksummed header, whose verification derives the layout from the
//!   header's own lengths and admits its identity under the read predicate
//!   before any payload chunk can be checked. A fill encodes the header into
//!   its first write buffer once every chunk checksum is known, and the
//!   volume verifies every read through the same codec.
//! - ONE-WRITER: a [`Storage`] attaches at most one [`Volume`] over its
//!   life, through one set-once bit in its root image claimed by one
//!   atomic swap after every attach check passed; a second attach,
//!   before or after release, is `AlreadyAttached`. The volume borrows the
//!   storage and the integrator's buffer arena, owns the command table, is
//!   neither `Send` nor `Sync`, and keeps both borrows to the end of its
//!   scope, so the storage cannot be finalized and the arena cannot be
//!   released under it. Its tick does bounded work and allocates nothing
//!   outside the warm bootstrap, which the `volume` module's Tick bounds
//!   states;
//!   every buffer, token and operation record stays held until the
//!   command's terminal event or a proven stop, and `release` succeeds only
//!   after a proven quiesce.
//! - IDENTITY-BEFORE-BYTES: a volume read exposes payload bytes only as
//!   verified chunks, after the record header's magic, version, lengths
//!   against the extent's units, chunk parameters, own crc32c over the span
//!   those lengths derive, and the read predicate of the IDENTITY-BEFORE-BYTES
//!   statement above all passed, and
//!   only chunks whose crc32c matched
//!   the header's table; a failed chunk ends the read with nothing from it
//!   or any later chunk exposed. An integrity failure is the read's typed
//!   `HeaderMismatch` or `ChunkMismatch` outcome: it changes no index entry
//!   or slot state, and the operation's right ends as at any other outcome.
//!   One payload path: object bytes live only on
//!   the device, written by a fill through the volume and read by
//!   [`Volume::read`] under a lease; RAM holds root control, volume control,
//!   the index, the buffer arena and the volume's heap arrays.
//!
//! # Devices and gates
//!
//! In production a volume runs over [`SpdkDisk`], the SPDK NVMe poll-mode
//! driver on the EBS controller that `kestrike-bind` moved to `vfio-pci`,
//! registered with the arena it shares with the owner's ENA port. One owner
//! process serves one volume, so a host runs one owner process per volume,
//! each with its own controller, arena and state directory, on hugepages of
//! the arena's configured size and a verified VFIO posture. The host-pair
//! production gates, by subject, are listed in the `net` module's
//! documentation.

mod block_order;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod blocks;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod blocks_tests;
mod budget;
#[cfg(test)]
mod budget_command_refusal_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod builder;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod builder_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod certify_pass_tests;
mod config;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod coverage_rejected_write_tests;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod credit;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod credit_lost_attempt_tests;
#[cfg(all(test, loom))]
mod credit_model;
#[cfg(all(test, loom))]
mod credit_steps;
#[cfg(all(test, loom))]
mod escrow_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod extent_census_churn_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod facade_drop_tests;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod fill;
#[cfg(all(test, loom))]
mod fill_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod fill_replay_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod fixture_ledger_tests;
mod geometry;
pub(crate) use geometry::EXTENT_PAYLOAD;
#[cfg(all(test, loom, target_os = "linux", target_pointer_width = "64"))]
mod durable_prefix_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod geometry_tests;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod grace;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod grace_kani;
#[cfg(all(test, loom))]
mod grace_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod grace_replay_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod held;
#[cfg(all(kani, target_os = "linux", target_pointer_width = "64"))]
mod held_kani;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod held_successor_eviction_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod later_header_key_tests;
mod layout;
mod ledger;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod place_claim;
#[cfg(all(test, loom))]
mod publication_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod reclaim_replay_tests;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod row;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod sequence_read_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod sequence_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod sequence_write_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod visit_replay_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod visit_tests;
#[cfg(all(test, loom))]
mod writable_model;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod acquire;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod admission;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod allocation;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod attempt;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod attempt_tests;
#[cfg(all(
    test,
    target_arch = "aarch64",
    target_os = "linux",
    not(miri),
    not(loom)
))]
mod barrier_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod batch;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod batch_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod begin_fill_gate_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod boundary_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod cache;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use cache::coverage as page_coverage;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod churn_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod claim_exit_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod clean_reserve_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod closing;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod closing_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod completed;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod conservation;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod control;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod coverage;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod device;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod drain_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod entropy_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod evict;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod evict_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod expire;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod expire_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod extent;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod store;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod store_crash_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod store_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod store_transfer_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use extent::work_bound;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod capture;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod capture_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod checkpoint;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod finalize;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod free;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod gate;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod grace_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod hit_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod image;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod init;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod join;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod join_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod keyops_replay_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod lease;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod lease_fault_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod lenses;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod lookup;
#[cfg(all(test, loom))]
mod lookup_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod lookup_replay_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod lookup_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod maintain;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod maintain_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod maintenance_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod mapping;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod media_fault_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod oracle_custody_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod os;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod owner;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod owner_fixture;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod owner_tests;
#[cfg(all(test, loom))]
mod parked_model;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod pending;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod placement;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod policy;
#[cfg(all(test, loom))]
mod policy_model;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod policy_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub mod portable;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod prefetch;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod prefix_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod prepare;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod prepare_tests;
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
mod probe;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod publication;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod publication_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod publish;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod publish_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod readiness;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod readiness_tests;
#[cfg(not(test))]
mod record;
#[cfg(test)]
pub(crate) mod record;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod recovery;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod register;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod register_replay_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod release;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod release_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod release_unwind_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod remove;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod remove_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod reserve;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod reserve_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod retire_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod seeded;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod service_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod shards;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod slot;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod slot_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod snapshot;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod strength_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod superseded_session_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod tables;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod tables_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod terminal_invalidate_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod test_platform;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod visited_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod volume;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::activation;
#[cfg(all(test, not(loom), target_os = "linux", target_pointer_width = "64"))]
mod litmus_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) mod volume_fixture;
#[cfg(all(test, not(loom), target_os = "linux", target_pointer_width = "64"))]
mod weak_memory_tests;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod witness_tests;
mod word;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod word_tests;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
mod writable;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
mod writable_tests;

pub use budget::{
    BudgetDimension, BudgetExhausted, BudgetShort, WorkBudget, WorkCounters, WorkKind,
};
pub use config::{ConfigError, StorageConfig, ValidatedConfig};
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
pub use fill::SERIAL_MAX;
pub use layout::{AllocationLayout, LayoutError};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use ledger::PoolLedger;
pub use ledger::{EngineBudget, EngineBudgetExceeded, LedgerOverflow, SlotPartition};
#[cfg(any(all(target_os = "linux", target_pointer_width = "64"), all(test, loom)))]
pub use row::FillFailure;

#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use admission::{Admitted, Decision, Ineligible};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use allocation::{AllocationId, ExtentReservation, Retained, RetireOutcome};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use attempt::{
    BeginError, CacheVersion, FILL_SERVICE_PER_RECORD, FillAttempt, FillServiceError,
    FillServiceReport,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use batch::{BatchError, BatchSlot};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use builder::{Builder, PromiseError};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use cache::{Cache, CacheError};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use closing::{CloseBlockers, CloseError, CloseStage, ClosingReport};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use completed::{CompleteError, Completed};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use coverage::{Advance, CoverageError, FeedContract, FeedError};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub use device::CanaryError;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use device::Native;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use device::{
    Admission, CommandTable, Failure, Operation, PollReport, QuiesceProgress, Quiesced, ReadDone,
    Refusal, Rejected, Stale, TableError, TableReport, Terminal,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use device::{
    ArenaBacking, ArenaFailure, Buffer, BufferArena, BufferConfig, BufferConfigError,
    BufferPoolReport, Classification, CommandToken, Completion, CompletionSink, ControllerEvent,
    DeviceGeometry, DeviceGeometryError, DeviceRange, DeviceRangeError, DeviceStatus, Disk,
    DmaRange, HoldError, IO_UNIT, NicHold, PacketLayout, PoolExhausted, PoolKind, PoolSpec,
    QuiesceStatus, RefusalReason, RegistrationHold, ReleaseBlocked, Released, RxPosted, SECTOR,
    SourceRange, SpanError, SubmitRefusal, ValidDeviceGeometry, ValidatedBufferConfig,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use device::{
    AtomicsRefusal, AttachFacts, AttachedIdentity, Boundary, DeriveRefusal, IDENTIFY_LEN,
    IdentifyFacts, IdentifyMalformed, IdentifyRaw, IdentifyRecord, IdentifySnapshot,
    NamespaceAtomics, NvmeVersion, PersistenceProfile, ProfileKind, ProfileRefusal,
    TornWriteFields, TransferLimits, UnitSource, VolatileWriteCache, completion_is_durable,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use device::{
    EbsStatistics, EndedPreempt, EndedRefusal, HolderRefusal, HostIdFailure, LatencyBin,
    LatencyHistogram, LimitsError, LineagePreempt, Reading, ReportError, ReservationCommand,
    ReservationLimits, ReservationLimitsError, SelfPreempt, SpdkAttachError, SpdkConfig, SpdkDisk,
    StatisticsError, StatisticsFailure, StatisticsHandle, check_own_record, parse_extended_report,
    report_exhid,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use device::{held_by_recorded, unheld_among_recorded};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use device::{source_frees, source_writable};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use extent::{
    ExtentLocator, LOCATOR_LEN_LIMIT, LOCATOR_START_LIMIT, LocatorError, RawPartition,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use finalize::{Blockers, Finalization, FinalizeError, Phase, Progress};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use gate::GateError;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use image::FillImage;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use image::{PoolDescriptor, RootDescriptor};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use init::{Cleanup, InitError, InitFailure, InitPhase, RetainedMappings, StorageCharges};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use join::{
    FillEnd, FillFollower, JoinError, JoinedReadError, JoinedVersion, ObserveError, Observed,
    Sought, SoughtError,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use lease::{ExtentLease, LeaseReport};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use lease::{HandoffError, Resident};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use lookup::LookupError;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use lookup::{INTERPOSE, Pause};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use maintain::{
    CertifyStall, DomainReport, MaintainError, MaintainReport, MaintainStage, MaintainTotals,
    Maintained, RemovedMember, StageReport,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use mapping::{Region, RetainedMapping};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use os::{HugepageSize, LinuxPlatform, OsCode, Platform};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use owner::{PlacementReport, PoolReport, Storage};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use place_claim::FILL_CREDITS;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use placement::{MAX_NODES, NodeMask, PlacementConfig, PlacementError, Topology};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use portable::{
    Absent, AbsentCounts, ClockContract, ClockReport, ClockScale, ContractError, PhysicalClock,
    SegmentV2, SegmentV2Error, Trust, Untrusted,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use prepare::{AHEAD, Preparation, PreparedLookup};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use publication::FillPublishError;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use publish::{PublishError, Replacement};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use readiness::{ReadinessError, State as Readiness};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use record::take_zero_run_builds;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use record::{
    Crc32c, Finding, HeaderMismatch, Image, RecordConfig, RecordConfigError, RecordIdentity,
    RecordLayout, Report, RunningCrc, ValidRecordConfig, Verdict, Window, WindowError, ZeroRun,
    ZeroRuns, inspect,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::LSN_LIMIT;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::capture_tests::{
    ORACLES as CAPTURE_ORACLES, finish as finish_test_capture, mutate as capture_mutate,
    recorded as capture_recorded,
};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::capture_trace::{CaptureOracle, CaptureTrace, TraceEvent};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::checkpoint::SlotLoad;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::suffix::SuffixBacklog;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::suffix::SuffixRefusal;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use recovery::{
    AreaRefusal, CaptureConfig, CaptureEntry, CaptureError, CapturePolicy, CaptureStarted,
    EvictCause, FormatId, GuardedLoad, HostShare, LoadEvent, LoadLimits, LoadRefusal,
    MetadataOutcome, Session, SessionRefusal, Slot, TileRefusal, guarded_load, load_guard,
};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use recovery::{next_session, restart_sessions, session_at, upcoming_session};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use register::{EraReport, RegisterError, Registration, RegistrationIndex, RegistrationReport};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use release::{
    CERTIFY_CONTROLS, CertifyReport, Outstanding, ReturnError, ReturnOutcome, ReturnTransfer,
    SERVICE_CONTROLS, SERVICE_PER_SLOT, ServiceError, ServiceReport, certify_minimum,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use remove::{InvalidateError, Invalidation};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use reserve::ReserveError;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use shards::ShardImage;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use shards::ShardReport;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use tables::{SlotIndex, SlotState, TableInventory};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::ENCODE_PANIC;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use volume::WarmSource;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::checkpoint::{Encode, Encoded, Leftovers, Panicked, UnitDone, UnitRefused};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::contain;
#[cfg(all(test, not(loom), target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::helpers_run_on_one_thread;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use volume::{
    AttachError, ControlRefusal, CpuSet, Fenced, GateRefusal, GateStep, GeometryRefusal, Grant,
    KeyReadError, MAX_CPUS, MAX_READ_AHEAD, PhaseReport, RECOVERY_PHASES, RECOVERY_TRANSITIONS,
    ReadEvent, ReadOp, ReadRefusal, ReadRefused, ReadStatus, RecoveryLimits, RecoveryPhase,
    RecoveryReport, TickConfig, TickReport, Transition, ValidatedChunk, VerifiedReadInfo, Volume,
    VolumeConfig, VolumeGeometry, VolumeReport, VolumeWatermarks, WriteProgress,
};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::{Bomb, Bound, Dropped, INLINE_RECOVERY, PARK_RECOVERY};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::{JoinedRefusal, KeyRead};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::{ReadShape, ReadSpan};
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::{
    TEST_CLOCK, TEST_FEED, TEST_METADATA_UNITS, test_recovery, test_volume, test_volume_with,
};
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use writable::{FillReserveError, PlacingFill, ReceiveError, WritableFill};

#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::gate_fixture;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::lapse_plant;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::reclaim_plant;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::warm_cycle;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::warm_sim;
#[cfg(all(test, target_os = "linux", target_pointer_width = "64"))]
pub(crate) use volume::write_guard;
#[cfg(all(target_os = "linux", target_pointer_width = "64"))]
pub use volume::{
    AuthorityRefusal, AuthorityReport, BootClock, HoldState, PolledReport, RegistrantJudgment,
    ServingAuthority, ServingClock,
};
