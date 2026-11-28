# CI scheduling

Read this before changing workflows or reasoning about lane order and runner
capacity, as `AGENTS.md` directs. Each script documents its own mechanics in
its header; this file holds the policy that chooses what runs where.

## Fast tier

Pull requests and pushes to `main` run, in dependency order:

1. Comment policy, script and workflow contract tests, hardware smoke checks,
   lane cancellation tests, and pinned stable rustfmt over every tracked Rust
   file, including the Verus, GenMC, and fuzz sources outside the workspace.
2. The small RC11 checker after step 1. Native preflight starts independently
   on the build runners.
3. The workspace after native preflight: format, check, clippy, the ordinary
   test suite, the atomic-site census self-test
   `scripts/test-classify-atomics.py`, which runs
   here because the `mc-atomic-classification` record's credit needs the
   census the lane's witness tests validate, and the simulation worker's
   protocol contract case under `--cfg protocol_contract`, in its own target
   directory, which feeds each worker output form the supervisor's parser
   reads through that parser.
4. Three shallow qualified lanes: `campaigns` and `search` after the
   workspace, reusing its target cache on the same registration, and
   `fuzz-smoke` after preflight.

Receipt self-tests run in a pool of at most four processes, capped by the
available CPUs; a failed worker or interrupted pool fails the check. Hardware
harness tests stay serial because their cancellation scenarios create
independent process sessions. Pull requests and pushes run the hardware
harness's mappings, host-fact, readiness, and stop-proof smoke checks; the
full fault matrix runs on schedule and manual events and on changes to its
scripts, inputs, or workflow. An unavailable or uncertain change comparison
selects the full suite.

## Scheduled and manual tier

The daily 06:17 UTC schedule and manual runs add, after the workspace: the
long-run gate, the nightly ServeCore searches, Verus, Loom, Miri, the
weak-memory sweep, fuzz, GenMC, Kani, TLC, Quint, the address-sanitized
library tests, the QEMU guest binder, and the architecture qualification
lanes that have their prerequisites. They run the shallow lanes too.

The native AArch64 barrier and ISA lanes are deferred until a dedicated Linux
runner is provisioned. Their workflow jobs stay disabled and `PENDING_JOBS`
names the missing prerequisite. Every gate summary reports them as pending with no coverage credit; passing the enabled software
lanes does not establish AArch64 barrier or ISA qualification.
Activation restores the job condition, moves `barriers` to `FAST_JOBS` and
`isa-aarch64` to `HEAVY_JOBS`, and removes their `PENDING_JOBS` entries after
the native prerequisites and receipts have been validated. Before the
condition of `isa-aarch64` is restored, each step the job runs beside its
lane is measured on the runner from a cold target directory at the job's
Cargo job and test-thread counts, its peak memory is checked against the
runner's memory limit, and its deadlines, its budget and the job's
`timeout-minutes` are set from that measurement. The measurement is repeated
when the step's test selection or the nightly pin changes.

- Qualified lanes (`campaigns`, `search`, `search-nightly`, `long-run`, the
  fuzz lanes, `isa-*`) run the rows of their `qualified` entry in
  `scripts/test-inventory.json` by exact ID. `scripts/select-tests.py`
  states what credits a row; the lane summary names each blocked row.
- GenMC, Kani, and TLC run their `scheduled` profiles on the schedule and
  their `pr` profiles on manual runs. GenMC's and Kani's `scheduled` profiles
  are wider: a `scheduled` receipt credits both record sets and a `pr` receipt
  credits only the `pr` records. TLC's two profiles hold the same cases.
  `scripts/rust-lane.sh` holds the Kani run deadlines, 30 minutes for `pr`
  and 210 for `scheduled`, and the measurement behind them. The lane runs
  Kani at two workers for `pr` and three for `scheduled`, or at
  `CARGO_BUILD_JOBS` where that is lower, with two malloc arenas
  (`MALLOC_ARENA_MAX=2`); `KANI_JOBS` sets another count within the bound.
  Every figure here is from an aarch64 host, a whole Graviton4 socket unless
  another is named, on 2026-11-23 and 2026-11-24, and on 2026-11-26 for the
  45-harness `pr` runs; none is from the x86-64 runner, which took 0.82
  of that host's seconds over the 193 harnesses of its nightly run of
  2026-11-20. The heavy runner's limits are a four-CPU quota on eight
  processors, the 11 GiB memory-high threshold and the 12 GiB maximum. The
  `pr` profile holds 45 harnesses. With no memory bound the lane's run of
  42 of them, build included, took 527 seconds and its verification 779
  CPU-seconds. The
  longest harness is the ownership round-trip proof,
  `net::ownership::verification::ownership_fields_round_trip_at_every_byte_and_close_flags_state_and_reserved_bytes`,
  at 96 seconds and a peak of 4.2 GiB. The lane's CBMC argument keeps that
  proof inside the profile: its 65-byte body is one element past CBMC's
  default, and without the argument the proof took 3,109 to 5,132 seconds
  and 21.4 GiB. Under the runner's limits `pr` completed in each of four
  runs in 488 to 501 seconds at a peak of 8.7 to 9.9 GiB, with no
  memory-high event. At three workers its 41 harnesses of an earlier day
  peaked at 10.1 to 10.7 GiB, and at four workers they reached the threshold
  in three of four runs with two arenas and were killed for memory in both
  runs with the allocator's default arenas. The `scheduled` profile holds
  225 harnesses. At three workers under the four-CPU quota with a 40 GiB
  memory maximum the command over 222 of them, build included, took 184
  minutes, its
  verification 32,267 CPU-seconds, and it peaked at 14.6 GiB; at four
  workers with no quota and no memory bound it took 136 minutes. The largest
  CBMC process of the lane takes 5.3 GiB. `kani-driver` keeps every finished
  harness's parsed result, traces included, to the end of the run: in that
  run it held 7.6 GiB from the 75th finished harness on and 9.9 GiB at its
  peak. Under the runner's limits `scheduled` is therefore short of memory
  at three workers and of time at two. The next three runs held the 221
  harnesses of the profile before `main` added its newest one. At three
  workers, on a second aarch64 host with 16 processors, the twelve census
  admission proofs over two and three entries stalled at the threshold and
  the 209 other harnesses were stopped by the 210-minute deadline with 204
  verified. At two workers the lane's run of the 221 was credited after 301
  minutes at a peak of 11.8 GiB with 654,022 memory-high events, and the
  209 without the twelve completed in 275 minutes at a peak of 10.9 GiB with
  no memory-high event. The 222 harnesses run in two halves at two workers,
  each half its own `cargo kani` process, took 201 minutes for the first
  111 cases at a
  peak of 11.8 GiB with 635,894 memory-high events, and 110 minutes at 2.8
  GiB for the last 111. The profile fits the runner's memory when the lane
  runs it in batches or the runner's memory maximum holds the 14.6 GiB.
  In the 35 batches the declaration cut on 2026-11-24, at three workers
  under the runner's limits, the lane's run of the 222 was credited five
  times with no memory-high event. Four runs that shared a 16-vCPU Graviton4 host
  peaked at 10.39 GiB in 263 to 288 minutes. One run alone on that host
  peaked at 10.51 GiB in 280 minutes, build included, with 32,736
  CPU-seconds of verification. The 210-minute deadline is shorter than that
  run, and than the 230 minutes the runner's 0.82 gives for it: a
  `scheduled` run that reaches the deadline is judged a timeout and credits
  no record. The declared cut is 40 batches now, since the four harnesses
  over the standby credit of the pending count each run alone; no
  `scheduled` run has measured it.
  A revision is fit for
  the runner when each profile at its default worker count peaks at or below
  10.5 GiB under the runner's limits with no memory-high event. The
  35-batch cut is 6 MiB over that line in the run alone, so it is not fit
  by this rule there, and under the line in the four other runs. It stays
  as declared at that figure because its peak is one proof,
  `failover::standbys::population_kani::verification::an_admission_into_one_entry_keeps_the_cap_and_the_other_entry`,
  which already runs alone, so no weight or budget lowers it. A
  `scheduled` run above the line whose peak is a batch of several harnesses
  needs a heavier weight or a smaller budget first. Where the peak is a
  harness that already runs alone, that proof's CBMC result must shrink
  first. `pr` is cut the same way by its own budget of 41, which puts the
  ownership round-trip proof in its last batch, away from the other
  `pr` harnesses that weigh 14. As one batch, its 42 harnesses of
  2026-11-24 peaked at 10.37, 9.16 and
  9.18 GiB in three more runs of 509 to 526 seconds: `kani-driver` held
  2.3 to 3.5 GiB of finished results while the ownership proof's CBMC ran
  beside another, 5.6 to 5.7 GiB together. In the two batches of that day's cut, three runs
  beside one single-threaded test script peaked at 9.37, 8.23 and 7.84 GiB
  in 539 to 553 seconds with no memory-high event. With the pending-count
  control the profile held 43 harnesses in two batches of summed weight 41
  each. Under the runner's limits, alone on a 16-vCPU Graviton4 share, three
  runs peaked at 9.91, 7.20 and 7.21 GiB in 610, 530 and 530 seconds with no
  memory-high event; the first built the crate inside its memory scope and
  the other two ran with the build cached. With the four harnesses over the
  standby credit of the pending count, each at weight 14, the profile holds
  45 harnesses in four batches of 15, 4, 14 and 12. Under the runner's
  limits, alone on a 32-vCPU Graviton4 share, three runs peaked at 8.63,
  7.15 and 7.14 GiB in 931, 833 and 829 seconds with no memory-high event;
  the first built the crate inside its memory scope and the other two ran
  with the build cached. A `pr` run above the
  line needs a smaller `pr` budget first, measured in three runs. The lane runs each
  profile in the batches that
  `verification/kani/expected.json` declares through its `batch_budget`
  and `weights`: the profile's sorted harnesses cut in order, each batch
  taking harnesses while their summed weight stays within the profile's
  budget, one `cargo kani` process a batch, in order, in one target
  directory, under one shared deadline. A harness weighs 1 unless it
  declares a weight. A harness whose CBMC process reaches 2 GiB resident, or
  whose CBMC result reaches 1 GB of JSON, weighs the `scheduled` budget and
  runs alone. Measure both from the CBMC command Kani prints for the harness
  under `cargo kani -p kestrike --exact --harness NAME --verbose` (the
  `[Kani] Running: cbmc ...` line): run that command as
  `/usr/bin/time -f %M COMMAND` for the peak resident set in KiB, and as
  `COMMAND --json-ui | wc -c` for the result's bytes. The judge reads only
  Kani's terse output, which names neither size, so the weights rest on
  this measurement and on the declaration's review. A heavy harness left at
  weight 1 shows as a memory-high event or a kill in its batch when the
  changed profile runs under the runner's limits. A profile of one batch
  writes `kani.argv`, `kani.txt` and `kani.exit`; a profile of several
  writes `kani-N.argv`, `kani-N.txt` and `kani-N.exit` for batch N. The
  lane writes `kani-run.json` as the batches run, and
  `scripts/judge-kani.py` credits the profile only when every batch credits
  on its own against that record. A change that adds a Kani harness
  measures its profile against that figure; for a `pr` harness that is
  three runs of `pr` under the runner's limits, each peak stated. It also runs `bash scripts/rust-lane.sh
  kani-compare HARNESS`, which runs the new harness once with the CBMC
  argument omitted and once under it, each with `--export-json`, records
  both commands and has `scripts/judge-kani.py compare` compare the two
  runs. The
  harness meets the comparison when every check reported under the argument
  appears without it with the same function, category, description, place
  and status, the only checks missing under the argument are unwinding
  assertions that succeeded without it, and the covers, their statuses and
  the unreachable count are the same. The change then lists the harness in
  `compared` of `verification/kani/expected.json`, or in `argument_only`
  with the figures of a run without the argument that ran out of memory or
  time. The judge refuses a declared harness that is in neither list or in
  both. A comparison holds for the harness and the code it reached when it
  was made; a paired run of both arms over the lane covers a later change
  of either. A run that loses one proof is refused whole
  and credits no record of the profile. The Kani command ends with `-Z unstable-options
  --cbmc-args` and the `cbmc` list of `verification/kani/expected.json`,
  `--max-field-sensitivity-array-size` with its size: CBMC keeps the elements
  of an array of at most that size as separate values, 64 by default, which
  the census admission proofs over two and three entries need to fit in
  memory. The argument reaches every harness and disables no check. Where it
  lets symbolic execution decide a loop exit, CBMC states no unwinding
  assertion for that loop, so a harness's check total can fall: the
  ownership round-trip proof reports one check fewer. `scripts/judge-kani.py`
  refuses a run with another list. The list holds for the Kani release and
  the size under which every harness of the `compared` list met that
  comparison, 0.68.0 with CBMC 6.11.0 at size 128. On 2026-11-24 that was
  210 harnesses and 69,070 checks; the ownership round-trip proof alone
  drops one unwinding assertion under the argument. The twelve admission
  proofs of the `argument_only` list each passed 34 GiB in CBMC within 135
  seconds without the argument. The
  judge refuses the list beside another declared
  Kani version, a declared list with another size, and a run whose output
  names another CBMC, so a Kani upgrade or another size repeats that
  comparison: the change records the new release or size in `COMPARED` and
  the declaration, runs both arms, and keeps the record only when `compare`
  accepts every compared harness.
- The ASan lane (`scripts/rust-lane.sh asan`) is advisory: the gate waits for
  it and accepts failure or cancellation, so a registration without the
  sanitized install at `/opt/spdk-v25.05.1-asan` leaves the gate to the other
  lanes. Its deadlines derive from `verification/asan/measurement.json`,
  taken on a workstation. Re-measure on the runner at the lane's first
  dispatch and whenever the suite or toolchain grows, and update the record.
  A header digest that differs on the runner calls for a portable sanitized
  install and record (`--target-arch=x86-64-v2 --enable-asan`).
- The QEMU lane (`scripts/rust-lane.sh qemu`) is a required heavy lane. Runner
  provisioning owns its inputs file, `/etc/kestrike/guest-inputs.env`, as the
  lane's header lists them. `verification/qemu/measurement.json` records a
  KVM measurement under the heavy runner's 4-CPU, 12 GiB quota with a guest
  of two CPUs, 2048 MiB, and a 64 MiB backing file; the envelope and receipt
  reject other guest settings. Before changing guest inputs, accelerator, or
  runner capacity, re-measure under the intended quota. Deadlines are at
  least four (handshake) and ten (run) times the measured seconds, rounded up
  to whole minutes, at most 60 minutes each, with the handshake at most the
  run deadline. After its binder checks the guest case runs each member of the
  QEMU inventory's `namespace_cases` by exact ID in a child process, and the
  guest judge and receipt require every member once. The run deadline also
  covers, for each member, its `deadline_seconds` and the inventory's
  `member_drain_seconds`, the longest the member's two output pipes hold the
  guest case after the member ends. The guest needs a Linux 5.14 or later
  kernel, `ip`
  with JSON output, `unshare`, `mount`, `umount`, the dummy and veth link
  types, IPv6 with policy routing, and user, network and mount
  namespaces; a guest without them fails the lane. A measured run over 360
  seconds needs a separately reviewed
  harness-bound change. The lane step holds two 15-minute listings, the
  15-minute build, and the guest deadline plus one minute; the job adds the
  toolchain step and ten minutes of margin.
- The Quint lane checks `quint/session.qnt`, `quint/detect.qnt`,
  `quint/route.qnt`, `quint/tenure.qnt`, `quint/prefix.qnt`,
  `quint/coverage.qnt`, `quint/capture.qnt`, `quint/preserve.qnt`,
  `quint/suffix.qnt`, `quint/saturation.qnt`, `quint/keyops.qnt`,
  `quint/binder.qnt`, `quint/creation.qnt`, `quint/standbys.qnt`,
  `quint/loss.qnt` and the composed projections of
  `quint/joins.qnt` with the tools that `verification/quint/expected.json`
  pins; `quint/check.py` and
  `scripts/judge-quint.py` state the cases and the credit rule. Its self-tests
  run in the fast tier. Schedule and dispatch split every declared case
  between two jobs on the Linux heavy registrations and preserve each case's
  worker count. Each job has a 360-minute deadline. The Quint judge credits
  one receipt only after rechecking both raw artifacts from that attempt.
  The `quint` job runs after every shard result except a skip, so a shard
  that failed a case or passed its deadline yields the lane's refused
  receipt from the evidence it uploaded. A refused judgment uploads the raw
  shards it read as `quint-refused-RUN-ATTEMPT`, kept 90 days. The two
  shards share a VM: each TLC case claims its server port by holding the UDP
  socket of the same number, and a runner that finds the number claimed
  draws another port.
  The original deadline was about twice the 186 minutes the 508 cases of
  that measurement took with eight workers on a
  128-core AMD EPYC 9R14 workstation. Cases added since are outside that
  measurement, among them the 24 join cases, which took 544 seconds at eight
  workers on a shared development workstation, the 53 binder cases, which
  took 365 seconds at eight workers on a shared 128-core development host,
  the 14 binder cases of `RollbackOnlyMoved` and `UnlinkOnlyAfterRestores`,
  which took 140 seconds at eight workers on a shared 192-CPU development
  host,
  the 38 creation cases that check the model, which took 397 seconds at eight
  workers on a shared
  64-core arm64 development host under Quint 0.33.0 and Apalache 0.62.1 with
  that host's Node.js and JDK, the 216 standbys cases, with the attach end in
  their scheduler, 215 of which took 3,222 case-seconds at eight workers
  (issue blotter issue 1805 assumed 20 minutes and about 75 cases) on a 16-vCPU Graviton4 host
  with nothing else running, under Quint 0.33.0 and Apalache 0.62.1 with
  that host's aarch64 builds of Temurin 21.0.12.1 and Node.js v24.22.3, the
  230 tenure cases with the admitted-set poll and the reclaim schedule,
  which took 9,545 case-seconds at six workers in two parallel runs on that
  host under its earlier Node.js v24.22.0 build and otherwise those builds,
  1,399 of them in the 85 cases of the reclaim schedule, the 30 tenure cases
  that an audit of that model's checks added, which took 264 case-seconds
  there, the 312 tenure
  cases with the restart's lineage arm and #263's poll withdrawal, whose
  280 cases before that withdrawal took 12,613 case-seconds on that host
  under those builds, the 49 free-scheduler cases at seven workers two at a
  time and the rest at three workers five at a time, 489 of them in the 20
  cases the arm adds, and 132 of whose 134 cases from `reclaimInit` took 2,409
  case-seconds after #263's review fixes at three workers four at a time
  on that host under those builds with Node.js v24.22.3,
  the 384 tenure cases with the handoff schedule, whose 365 cases before
  #263's review fixes took 14,481 case-seconds on that host under those
  builds with Node.js v24.22.3, the 48 free-scheduler cases at seven
  workers two at a time and the rest at three workers, and whose 325 cases
  outside the free scheduler took 9,219 case-seconds after those fixes,
  the 199 from `reclaimInit` at three workers four at a time and the rest
  at three workers five at a time, 1,425 of them in the 67 handoff cases,
  whose five cases of a transfer to a target whose attach ended took
  30 to 31 case-seconds in each of three runs, one case at a time, on such
  a host under those builds, and whose six cases that the review fixes of
  #263 and blotter pull request 2012 added took 40 case-seconds there, one case at a time
  beside other checks,
  the 98 suffix cases with the planned exit, which took 1,185 case-seconds
  at three workers five at a time on that host under that JDK and Node.js
  v24.22.3, 237 of them in the 22 drain cases, the 24 join cases, which keep
  their state counts with that exit and took 985 case-seconds in that run,
  the 225 standbys
  cases with the planned transfer, #263's storm instance and its review
  fixes, each case's instance pruned to what the case reaches, which took
  4,324 case-seconds at seven workers two at a time on that host under
  those builds with Node.js v24.22.3, `standbys-cross-safety` 322 seconds
  for 9,234,583 distinct states,
  the 18 standbys reach cases of a planned transfer past a root's prefix,
  which took 187 case-seconds at four workers four at a time on that host
  under those builds,
  the three standbys cases of the fresh contender's order, which took 22
  case-seconds one case at a time on that host under those builds with
  Node.js v24.22.3, beside other checks,
  the `creation-replay` and
  `detect-witness-replay` cases, whose tests took 21 and 18 seconds on 16
  cores of a 96-vCPU Graviton4 (Neoverse V2) host under Quint 0.33.0 and
  Node.js v24.22.3, after the build,
  the `standbys-replay` case, whose test regenerated its 93 traces eight
  Quint runs at a time and replayed them in 33.6 to 34.0 seconds in four
  runs on a 16-vCPU Graviton4 (Neoverse V2) host under Quint 0.33.0 and that
  host's aarch64 build of Node.js v24.22.3, after the build, 33.7 to 34.0
  seconds as the case's command with cargo's start in those four runs,
  the 125 loss cases, which took 1,455 and 1,402 seconds in two runs at
  eight workers on 16 cores of that host under Quint 0.33.0 and Apalache
  0.62.1 with that host's aarch64 builds of Node.js v24.22.3 and Temurin
  21.0.12.1,
  the `loss-replay` case, whose test regenerated its 110 traces eight Quint
  runs at a time and replayed them in 36.72 to 36.79 seconds in three runs on
  a shared 16-vCPU Graviton4 host under Quint 0.33.0 and that host's aarch64
  build of Node.js v24.22.3, after the build, 36.81 to 36.88 seconds in the
  same three runs as the case with cargo's start,
  the 19 declared-hold detect cases, which took 87 seconds at eight workers
  on a 96-vCPU Graviton4 (Neoverse V2) host under Quint 0.33.0 and Apalache
  0.62.1 with that host's aarch64 builds of Node.js v24.22.0 and Temurin
  21.0.12.1, where `detect-safety` grew from 412,463 to 6,572,653 distinct
  states and from 8 to 113 seconds,
  the 96 put, identity and settle cases, which took 726 seconds at eight
  workers on a shared 128-core development host, the two `put-beside-`
  cases, which took 5 seconds each there,
  and the 207 gate, grace, visit, extent, lookup and escrow cases, which took
  707 seconds at eight workers on an 18-core Apple silicon workstation, under
  macOS builds of Node.js v24.22.0 and the pinned JDK version. The runner has
  completed no run of the suite: in two scheduled
  runs under its quota the 32 cases before `safety` took 0.7 to 0.8 times
  their workstation seconds, and `quint/README.md` records the rate `safety`
  reached there. The lane step holds five ten-minute tool-install deadlines, the
  run deadline, and ten minutes of margin; the job adds the toolchain step and
  fifteen minutes. Re-measure on the runner at the lane's first complete run
  and whenever the suite grows, and resize the three limits together. The 407
  cases of the board, mempool, custody, episode, claims, window, watermark,
  allowance, report and parked families, the `settle-run-pressure` and
  `settle-run-replaced` runs and `mutant-step-drops-reboot` took 2,968
  seconds at eight workers on a shared 64-core AArch64 development host,
  under that host's builds of JDK 21 and Node.js 26; no runner measurement
  covers them. Four cases are outside that measurement and took 25 seconds
  at eight workers on a 64-core AArch64 development host under JDK 21 and
  Node.js 26: the `watermark-run-timeout-after-other` run, its reachability
  case, `watermark-uncommitted-timeout-is-unwitnessed` and
  `custody-mutant-FailedRestartReturnsEvery-charged`.
- The architecture lanes `isa-x86-64` and `isa-aarch64` require native hosts
  labelled `kestrike-isa-x86-64` and `kestrike-isa-aarch64`. Each lane's
  inventory entry declares its `arch` and the `/proc/cpuinfo` features its
  kernels need; a host short of one fails the lane with every row uncredited.
  The evidence is test-build execution on the lane's host; release-build code
  inspection is a separate claim.
- `.cargo/config.toml` enables LSE atomics for aarch64 builds with
  `-C target-feature=+lse` as `rustflags` and `rustdocflags`. Cargo reads it
  when the build starts inside the repository. For an aarch64 target the
  table takes the place of `build.rustflags`, `build.rustdocflags`,
  `CARGO_BUILD_RUSTFLAGS` and `CARGO_BUILD_RUSTDOCFLAGS`, so other rustc flags
  for such a build go in `RUSTFLAGS` and other rustdoc flags in
  `RUSTDOCFLAGS`, each beside `-C target-feature=+lse`. Without
  `--target` the table also applies to build scripts and proc macros, so every
  aarch64 host that builds in the repository, the arm64 `kestrike-hardware` and
  `kestrike-aarch64-native` registrations included, must report `atomics`: on
  a CPU without LSE such a build can stop with an illegal instruction, and
  neither Cargo nor the crate checks the CPU. kestrike refuses to compile
  for aarch64 without the feature unless the build sets `miri`, `kani`, `loom`
  or `protocol_contract`. A set `RUSTFLAGS` or `CARGO_ENCODED_RUSTFLAGS`
  replaces the config file's `rustflags`, and a set `RUSTDOCFLAGS` or
  `CARGO_ENCODED_RUSTDOCFLAGS` its `rustdocflags`, so whatever sets one for an
  aarch64 build of kestrike outside those four cfgs carries the flag, as the
  `barriers` and `tag-compare-aarch64` lanes do. The GenMC checker sets
  `RUSTFLAGS` for its own build of the kernels package, which holds no guard,
  so the bitcode it checks is compiled without `lse`. cargo-fuzz sets
  `RUSTFLAGS` for its build and appends the caller's value, and Cargo prefers
  `CARGO_ENCODED_RUSTFLAGS`, even empty, over both, so an aarch64 `cargo fuzz`
  run needs
  `env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="-C target-feature=+lse"`. The
  `fuzz` and `fuzz-smoke` lanes run on x64 runners, and their frame step runs
  `cargo fuzz` without that prefix; a fuzz lane moved to an arm64 runner adds
  it to the step.
  `isa-aarch64`
  requires `atomics` on every processor. The guard checks only that a
  non-exempt aarch64 compilation of kestrike has the feature; it says
  nothing about the flags of a deployed binary built outside the repository.
- The tag comparison inspection lanes, `tag-compare-x86-64` and
  `tag-compare-aarch64` (`scripts/scan-tag-compare.py`), stay pending
  (`if: false && ...` and `PENDING_JOBS`) until the security and build owner
  confirms the inspected artifact and procedure on the pull request.
  Activation replaces each `if:` with the heavy jobs' condition and moves both
  to `HEAVY_JOBS`; their summaries also report no coverage credit while pending.
- Quarantine runs after preflight, independent of the workspace, as a
  diagnostic outside the gate. The FIS controller suite,
  `scripts/test-fis-controller.py`, runs in its own job outside the gate; a
  pull request's author runs it locally.

The Rust gate requires every selected lane except the advisory ASan lane to
succeed and checks that unselected heavy lanes are skipped on pull requests and
pushes. It runs after failed dependencies, but a cancelled pull-request run does
not queue a gate job. A cancelled pull-request run provides
no passing gate or successful receipt aggregation: its gate job is skipped.
GitHub reports a skipped job as a successful required status check, so the
merge rule in [Concurrency](#concurrency) reads the run's conclusion, and a
branch rule that required only the gate check would admit a cancelled run.
Scheduled and manual runs retain their
advisory ASan cancellation rule. While no online runner carries an enabled
lane's label, the job stays queued, the gate stays unsuccessful, and the run stays open until GitHub ends
it after a day; `hardware.yml` cannot start and the next scheduled run waits
behind it. A manual run confirms that a new registration takes jobs.

### The ThreadSanitizer step

The `isa-aarch64` job runs `bash scripts/rust-lane.sh tsan` after its
qualification step, with its own evidence directory, `evidence/tsan`. The step
credits no obligation record. It builds the kestrike library tests on the
pinned nightly with `-Zsanitizer=thread`, `-C target-feature=+lse` and
`-Zbuild-std`. The LSE flag satisfies the aarch64 build guard. The sanitizer
replaces each atomic `load`, `store`, `swap` and `compare_exchange`, and each
`fetch_add`, `fetch_sub`, `fetch_and`, `fetch_or`, `fetch_xor` and
`fetch_nand`, with a call into its runtime. The pinned toolchain's pass leaves
`fetch_max` and `fetch_min` as native atomic instructions that the sanitizer
does not record. The tests this step runs reach `fetch_max` in
`crates/kestrike/src/storage/coverage/advance.rs`,
`crates/kestrike/src/storage/register.rs` and
`crates/kestrike/src/storage/publish.rs`; the crate calls no `fetch_min`.
The step holds two rules:

- The selection, the tests matched by `storage::`, `index::` and
  `net::client::route`, runs with the planted race skipped and passes only
  with no failed test, a passed test for each filter, the production gate's
  contention test among them, and no report file. An ignored test stays
  ignored and does not run.
- The planted race, `storage::gate::tests::negative_control_a_relaxed_take_races_the_guarded_counter`,
  runs alone in the same executable and must report `ThreadSanitizer: data race`
  with a frame in `storage::gate::tests::contend` and a data-race summary line
  in `storage/gate.rs`, the file of the guarded counter the workload's holders
  touch. The check matches the file, not the counter's line. A build without
  the sanitizer compiles no control, so the step fails.

The runtime writes each process's reports to `log_path.PID`, not to the test
output, so the step reads the run's reports under `evidence/tsan/tsan-run/`
and the control's under `evidence/tsan/tsan-control/`.

A clean run judges only the schedules that ran. The sanitizer derives no edge
from a fence and sees no access made by inline assembly, by the uninstrumented
native library, by a device, or by the kernel outside an intercepted call. It
sees no lock the native library builds from its own atomics, and neither the
access nor the ordering of a native `fetch_max` or `fetch_min`. A race through
any of these goes unreported, and an exclusion that rests on one can be
reported. Its other atomic accesses go through its runtime, so a clean run is
no evidence about reordering on a weakly ordered CPU. Ordering defects are
judged by the model lanes (RC11, GenMC, loom and the Miri sweep), not by this
step.

This table covers the fence call sites and the barrier instructions the
selection reaches:

| Site | On aarch64 | What the sanitizer sees | Stand-in under the sanitizer |
| --- | --- | --- | --- |
| `Busy::begin` and `terminate`, `reserve_pair` and `cancel_pair`, the terminal-shard branch of removal, `Binding::publish` | Release fence before `Relaxed` stores. The barrier scan declares the first two | No edge. Every store it orders and every load that reads one is atomic, and a reader discards a rejected copy, so no plain access rests on the edge | Each store after the fence that a reader may acquire, at `Release`. Not needed |
| `load_run` | Acquire fence after `Relaxed` loads; a scan site | No edge to the owner's `Release` departure. Plain memory the owner wrote and the service pass then reads would be reported | The loads at `Acquire` |
| `serialize_before_sample`, `serialize_after_sample`, `order_loads` | `dsb sy` and `isb`; `isb`; `dmb ishld` (a scan site) | Nothing. They order a clock sample and the kernel's loads inside `pread`; no plain access between threads rests on them | None |
| The `svc` entropy draw, the hash kernels | aarch64-only assembly | Their memory accesses are invisible, so a race through them goes unreported | None |

The language gives `SeqCst` operations a single total order. The sanitizer
is reported to treat a `SeqCst` load as `Acquire` and a `SeqCst` store as
`Release`, without that order. The total order adds no happens-before edge by
itself, so at a `SeqCst` store-then-load point the sanitizer judges plain
memory by the release and acquire edges the run took, as it judges any other
access. A clean run there says nothing about the store-then-load argument on
aarch64, and a report there is classified like any other report.

When the selection writes a report, in a hand run on an aarch64 host or on
the runner, classify it under the
[simulation guide's class table](simulation.md#classify-every-result) before
any change. A race on guarded cache memory breaks that site's invariant, a
race in a test fixture is a minor bug, and a report whose exclusion the
sanitizer cannot see is a harness result. Change no code until the owner
answers: a stand-in and a named skip beside the filters each need the
owner's approval. Every invocation of the step, a refused one included,
first clears `tsan-run/`, `tsan-control/` and the step's record files in its
evidence directory, so copy a hand run's evidence directory aside before
running the step again there. Give a hand run its own `EVIDENCE`, as the job
does: the step's record names are the names every lane writes.

A stand-in is a stronger ordering compiled only under the sanitizer so that
it can see an order a fence provides. A stand-in enters production code only
for a classified report that needs it, with the owner's approval.

## Hardware and FIS

`.github/workflows/hardware.yml` starts when a scheduled or manual
`agent-checks` run completes and runs at that revision only when its
comment-policy, preflight and workspace succeeded. The comment-policy job runs
the hardware harness self-tests, so live devices run only a revision whose
fault matrix passed. All three jobs are outside the gate. The hardware job runs
`scripts/hardware-lane.py sweep` over the roles `KESTRIKE_HARDWARE_ROLES`
names from `scripts/hardware-profiles.json`; the FIS job runs
`scripts/fis-controller.py campaign` over the profiles
`KESTRIKE_FIS_PROFILES` names from `scripts/fis-profiles.json`, after the
FIS controller suite succeeded in the completed attempt. A host's profiles
share one attachment mode, since its one volume admits one: the `single`
profiles need Multi-Attach disabled, and the `-multi-attach` profiles need
Multi-Attach enabled with exactly one settled attachment, the declared one.
The FIS controller suite's fake AWS covers that guard; it is no hardware or
provider qualification. A campaign lists the other mode's profiles as unrun,
so with the checked-in manifest the matrix is covered once the campaigns on
hosts of each mode together leave every profile with a HELD receipt. Each
script's header
states its envelope, custody markers, exit codes, and operator procedure.

The manifest holds three platform rows: `x86_64-nitro-ebs` and one aarch64
row per `r8gb` size, `aarch64-r8gb-4xlarge-ebs` and
`aarch64-r8gb-8xlarge-ebs`. Each is unsupported with every envelope field
empty, so no profile credits until the platform owner fills a row and sets
`supported`. A row's envelope includes `cpu_family`, the raw `/proc/cpuinfo`
identity lines (`CPU implementer` and `CPU part` on aarch64, `vendor_id`,
`cpu family` and `model` on x86_64), which the host must report exactly. Each
profile names a disposition on every row: `runs`, `pending` while the
platform owner has not decided whether the profile runs there, or `excluded`
when the profile does not run on that row, as the FIS profiles do not on the
aarch64 rows because the FIS job routes to x64 hosts. `cr1-controller-reset`
and `pk1-process-kill` are `pending` on every row, whatever a row's approval:
their tenures run under fixture authority with a harness-built record and
coverage copy, and the process-kill case kills a device-holding child outside
the lane's kill custody. They move to `runs` once their tenures recover
authority and coverage through the restart path on the SPDK driver and that
kill runs under the lane's kill custody;
`Lane.test_each_r8gb_size_has_its_own_unsupported_aarch64_row_and_every_profile_a_disposition_there`
pins the hold. A profile credits only on a row where
it `runs`, and `judge` credits it only when every role's receipt names that
one row: the receipt's `platform.row` selects the row, and the current
manifest supplies its support, machine, envelope and disposition. A hardware
host names its row in `KESTRIKE_HARDWARE_PLATFORM`; a sweep on a host
without one refuses, and so do the FIS job and the FIS controller, whose lane
runs read the same variable. While a custody marker under `/var/tmp/kestrike-hardware-custody`
holds a host, also take its runner offline: a revision from before
`hardware.yml` reads no marker, and one from before the FIS marker removes it
after a reboot.

The manifest's `qualification` object is the predeclared hit-latency and
recovery protocol of the `hit-gate` profile, so each lane receipt's manifest
digest binds it. `scripts/hit-gate.py judge` reads a campaign file, the lane
receipts and the sample files it names, and writes a gate receipt whose
verdict is `pass`, `fail`, `inconclusive` or `handoff`; its header states the
campaign file's fields and the schedule, statistics, pacing, recovery and
campaign safety rules. `python3 scripts/hit-gate.py check` lists what keeps
the committed protocol from passing. A campaign on an unsupported row is
research evidence and credits no obligation.

The manifest's `packages` object defines the controller-reset package (CR-1)
and the process-kill control of the reboot package (PK-1) over the
`cr1-controller-reset` and `pk1-process-kill` profiles: each package's class,
its warm recovery class, its injection, its persistence statement, its
simulated-device proxy and its unrun legs, with the repeat, restoration and
stop contract every repeat follows. The lane checks only that the object is an
object and binds its bytes through the manifest digest every receipt records;
`scripts/recovery-packages.py` validates its fields. Each repeat runs as its
own lane run under a fresh observer log (`hardware-lane.py run --observer DIR
--episode <run identity>`; a sweep qualifies only with `KESTRIKE_EPISODE`
set to the run identity on a host that runs the package role alone), since the
judge reads the case's start event and its observed lines from the receipt and
checks them against the raw output.
`scripts/recovery-packages.py judge` reads a package campaign file and each
repeat's lane receipt and raw output, and writes a package receipt with S, its
served, eligible, unaffected and affected bytes, the first warm hit, the
signed residual inventory, the injection observable and five separate
verdicts: safety, containment, retention, progress and residuals. Its header
states the campaign file's fields and the rules. A cycle that breaks a rule
fails its case, so its repeat earns no lane credit and reads as missing
evidence with every verdict inconclusive; a `fail` verdict marks an admitted
repeat whose lines disagree. `python3
scripts/recovery-packages.py check` lists what keeps each package
uncredited: the unsupported rows, each row on which a package's profile is not
`runs` (both are `pending` on every row, so the lane credits no repeat), the
repeat count, the qualified authority and coverage legs, each package's
injection authority, the native class and credit interface, the restoration
record no package binds and the host reservation and custody check no repeat
binds. It also lists each unrun leg, which stays outside its package's
credit: PK-1's reboot leg runs in no case, so PK-1 covers process kill only.

The warm-recovery measurement frame lives in `verification/measurement/`:
`frame.json`, `statistics.json` and `policy.json`, whose policy names the
frame and statistics versions by SHA-256, and `revisions.json`, which logs
each version's digest. Changing a record's bytes takes a new version and a new
log entry, and a new frame or statistics version also re-pins
`verification/measurement/sizing.json`. CI runs
`python3 scripts/measurement-frame.py check --base REV` with REV the pull
request's base commit, the previous main commit for a push
to main, and `origin/main` for scheduled and manual runs; it refuses a log
that rewrites or drops an entry REV holds, and a REV it cannot read.
`check` also refuses when the manifest's `qualification` object changes or a
source declaration named in `frame.json` is renamed or moved: the frame then
needs a new version pinning the new qualification digest or anchor, the policy
a new version naming that frame, and the log an entry for each, and the
refusal prints the expected digest. A record edit beyond its owner inputs also
changes the record's entry in the script's `FIXED` table, which the same
change updates. `check` validates the records, their field
sources and their pin of the hit-gate qualification, and lists the inputs the
records leave null and the provisional alpha and power; it does not show
whether the producers that fields hand off to have landed. It resolves a Rust
source anchor against the declarations `crates/source-anchors` parses from the
file, so the script's commands and its test file run `cargo` and the
`comment-policy` job installs the pinned toolchain for them. `report` reads a
campaign file and writes a receipt under the frame's floor, admission, clock,
control and policy rules, with H judged by `scripts/hit-gate.py`;
`scripts/measurement-frame.py`'s header states the measurement campaign
file's fields and the receipt's. A campaign registered under an earlier policy
version reads `retained` and is never judged again under a later one. A
`retained` receipt establishes no verdict; a receipt issued under the
campaign's own policy version shows whether it was judged and how. Every
receipt judged under the current policy holds the four evidence columns. A
campaign that declares a class or revision contrast also carries its C2
calibration, seeded ABBA and BAAB blocks and AWS safety manifest, and its
receipt holds the bounds and, for a revision contrast, the bound verdict.
`python3 scripts/measurement-frame.py ticket` reports the campaign again,
refuses a receipt file it does not derive and prints the verdict above a
`Gate head:` line with the receipt's SHA-256. Only PASS merges as a
performance change.

`verification/measurement/sizing.json` is the shared-volume warm-recovery
sizing worksheet. It pins the frame and statistics versions it reads and
defines its inputs, resource rows and conditional scenarios: the named
standby's takeover, the fresh-host recovery after owner and standby loss, and
the actual-volume-loss control. `python3 scripts/sizing-worksheet.py check`
validates the records as `measurement-frame.py check` does, then the
worksheet, and lists the open inputs: unrecorded owner inputs and quantiles,
null envelope keys and inputs with no measured source. It resolves Rust
anchors as the frame check does, so it also runs `cargo`, and it compares each
structural input with the value of the Rust constant it names.
CI runs `check`. `python3 scripts/sizing-worksheet.py evaluate --inputs F`
reads an inputs file that cites a comparison receipt and writes, per
scenario, each step's per-host L_h and shared L_S, the binding row, resource
and path, elasticities and occupancy rows. Every scenario reads conditional
with its probability not identified, a row with a missing input reads
unscored and names it, and `scripts/sizing-worksheet.py`'s header states the
rules.

`verification/measurement/acceptance.json` is the warm-recovery acceptance
record. It pins the frame, statistics, policy and sizing worksheet and names
each evidence source as its own receipt identity: the seeded cycle histories,
the composed model joins, the implementation history records, the package
proxies, the hardware packages, the actual-volume-loss record and the
comparison receipts. Each failure class (host loss with warm takeover,
same-host restart, controller reset, process kill and the actual-volume-loss
cold control) cites those sources by evidence kind and column. `python3
scripts/acceptance.py check` refuses a citation that crosses evidence kinds or
classes or claims cold retention, and lists the open gates and unrun domains.
CI runs `check`. `python3 scripts/acceptance.py judge --inputs F` re-derives
each supplied lane, package and comparison receipt through its own judge
(`scripts/verify-receipts.py credit`, `scripts/recovery-packages.py` and
`scripts/measurement-frame.py`) and writes per class the structural verdict
of each column by evidence kind and its quantitative verdict, with H under
R6 and F apart. An optional sizing input adds the worksheet's conditional
scenarios from `scripts/sizing-worksheet.py` with no verdict. A citation
whose input is absent reads unrun, a supplied input its judge refuses reads
inconclusive, and either keeps the column from passing. Lane credit runs
`scripts/verify-receipts.py credit --read-only`, which leaves the lane's
evidence directory and the step summary unchanged. Both commands run
measurement-frame's check, which calls `cargo` to resolve source anchors, so
they need the pinned Rust toolchain. `scripts/acceptance.py`'s header states
the rules.

`verification/readiness/failover.json` is the failover readiness record. It
names the 19 gates that keep failover closed, each with an owner, its lifting
condition and `lifted: false`, and pins the acceptance record and the hardware
and fault-injection profile manifests, the game-day catalog and the runbook
index by SHA-256. A change to a file whose pin is not null updates that pin in
the record in the same change, so the pin matches the final bytes, a resolved
merge included. The game-day catalog, runbook index and alarm catalog pins may
read null, and `check` lists each null pin as an open item of its gate, noting
when its file exists. The readiness record holds one row per failure scenario,
each mapped to a failure class FC1 to FC12 or to the requirement it evidences,
with citations by evidence kind (`model`, `simulation`, `hardware`, `store`,
`staging`, `rehearsal`, `review`) or a written exclusion per kind. `staging` is
always cited or excluded; another kind may be left open.
The readiness rows for the five classes the acceptance record judges cite only
`acceptance:<class>` and name the failure class that acceptance class
evidences. `python3 scripts/readiness.py check` refuses a dropped gate, a lift
the repository's evidence contradicts, a pin other than its file's bytes, a
citation under another kind than its source's, a source, catalog record or
package the acceptance record already cites, a failure class FC1 to FC12 that
no row names and no `unmapped` entry explains, and a failure class whose every
row excludes every kind. It prints every unlifted gate, the open items of each
gate whose lift it contradicts, the failure-class map, the `unmapped` reasons,
each row's open and excluded kinds (with the acceptance record's unrun kinds
for a row delegated to it) and the line `NOT READY`.
A gate without open items stays open while it reads `lifted: false`; its lift
is a reviewed diff of the record. CI runs `python3 scripts/test-readiness.py`
and `check`. `check` runs the
acceptance check, which calls `cargo`, so it needs the pinned Rust toolchain.
Only `scripts/readiness.py`, its tests and the game-day judge's self-test
read the record, and the header of `scripts/readiness.py` states the rules.

The record's `items` grade one criterion each in 14 evidence domains, from a
named source or as an open gap with its owner; `floors` names the floors, the
classes of item an exception never covers, and each item names its floor;
`waves` names the az-color unit and the fields a wave's authorization names,
and `authority` the launch and risk roles, all null.
`docs/runbooks/failover/index.json` lists one entry per runbook slug: an
entry's `id` is the slug an alarm catalog row names in `runbook`, and its
`file` is the runbook under `docs/runbooks/failover/`. One file may serve
several slugs, one entry each. Every alarm catalog `runbook` slug needs an
entry, and an entry no row names holds no alarms, of either kind. An entry's
`executor` and `author` are opaque handles copied from a rehearsal record that
stays outside the repository; `check` compares the handles and reads no record.
`check` refuses an item with no criterion or of a kind its class excludes, a
runbook slug off its form, an unresolved runbook action anchor (naming the
runbook STALE), an action anchor in test code, a runbook file outside
`docs/runbooks/failover/` or in another spelling, rehearsal `paths` that name
no anchor of the file, an index entry whose alarms are not the present
catalog's rows that link it, a VERIFIED entry without a MET tabletop rehearsal
naming at least one path, or without each action source's SHA-256, and a
rehearsal executed by its author. It lists a runbook whose bytes, or whose action source's bytes,
changed after verification as STALE, a VERIFIED WITH LIMITATIONS entry with its
limitations and a catalog row with no index entry as open under `runbooks`,
where a standing reason also stays while the gate is unlifted, since `check`
holds no inventory of operator actions; `judge` grades a lift of `runbooks`
against the runbook and operator-procedures items. It lists each null
`max_age_days` as POLICY UNDEFINED under `evidence-age`, each not-applicable
item without an approver under `authority`, and, while the alarm catalog is
absent, `monitors` open with the alarm cross-check skipped. While the catalog
is pinned, `check` keeps `monitors` open for a catalog with no row and for
each row whose basis is `assumed` or stated as no text, and while the gate is
unlifted it adds the note that it judges only the rows' basis. Once no row
blocks it, `check` admits a lift, and `judge` grades that lift against the
observability and alarm-routing items. Beside the open
reasons, the report lists `domains` and `floors` (item ids), `not_applicable`
(each waived item with its reason and approver), `gaps` (each applicable item
with no source, with its gap owner; a source names where an item's grade is
read, so an item with a source may still hold no evidence), `runbooks` (each
index entry's status) and
`alarm_cross_check`. A pass judges the shape and links of these files, never a
receipt.
`check` reads a runbook's anchors line by line over a subset of Markdown. Of
the page's structure it models two blocks and nothing else: a fenced block that
opens and closes on a line that starts with the fence run behind at most three
spaces, and a comment block that opens on a line led by `<!--` and closes on
the line holding `-->`. A quote, a list item, a raw HTML block, indented code
and a span that runs across the lines of a paragraph are unseen. An explicit
anchor counts where its whole `<a id="...">` open tag leads its line, after the
quote and list markers the line begins with; `check` refuses by name a path to
an anchor that follows other content on its line. It can count an anchor or
heading where the page shows none on a line that an unseen construct holds, and
on a line after its fence state has left the page's: after a fenced block
inside a list item, or a fence run inside a raw HTML block such as `<details>`,
it can read the later fenced blocks as text and the text between them as
fenced. The `anchors` docstring in `scripts/readiness.py` states what the scan
reads and where it differs from the page.

`verification/readiness/gamedays.json` defines the game-day packages GD-1 to
GD-14: each names its mode (causal and rehearsal packages run in staging, a
tabletop rehearses), the hypothesis clauses with the budgets that bound them,
the injection (a fault-injection profile by its name in
`scripts/fis-profiles.json` where one applies), an oracle that shows the
intended fault was reached and the expected outcome, abort guardrails, a
restoration class and the prerequisites, a missing one reading `TBD - BLOCKS
EXECUTION`. Budgets stay null until the owner sets them. The catalog's
`run_rule` states what every run obeys: what its filled package pins before any
injection, when a phase failed to inject, and which observations grade a
clause. An oracle text that leaves a precondition unnamed is decided by that
rule. `check` refuses a class row with neither a staging citation nor a written
staging exclusion, a citation of a package that grades none of the row's items,
a class a package grades that does not cite it, a package that grades no item,
a package whose prerequisites are not as many distinct texts as
`GAMEDAY_PREREQUISITES` counts (a met prerequisite stays listed without the
marker), a bounded clause that grades a floor item, a package whose safety
floor items are not the ones `GAMEDAY_SAFETY` fixes, a tabletop item without
the `runbook` invalidator, a package item without the `guardrail` invalidator
or, where its package names a profile, the `manifest` one, and a package that
stops or restarts hosts, a partition or an AZ (GD-2 to GD-5, GD-7, GD-10, GD-12
and GD-13) without the guardrails against a generation change and a
CreateVolume by the reconciler principal. It lists each package's blocking
prerequisites and null budgets, and a tabletop that names no runbook, under
`gamedays` and `budgets`. While the gate is unlifted it notes under `gamedays`
that it judges the definitions only; once no package is blocked, `check` admits
a lift, and `judge` grades the run records against each package's digest and
the lift against the game-day items. Filled packages and run records stay
outside the repository.

`python3 scripts/readiness.py judge --inputs F [--output F]` runs `check`,
then re-derives each supplied receipt through its owning judge, read-only:
the acceptance inputs through `scripts/acceptance.py judge` (recovery package
campaigns go in that file, since the acceptance record owns them), lanes
through `scripts/verify-receipts.py credit --receipt --read-only`, a hit-gate
campaign through `scripts/hit-gate.py` and a fault-injection episode's lane
receipt through `scripts/hardware-lane.py`. A HELD episode verifies only when
it names the SHA-256 of that lane receipt, the digest of its pinned profile
row and the SHA-256 of the pinned `scripts/fis-profiles.json` bytes, which
`scripts/fis-controller.py` records in a credited episode, and when
the lane receipt's observed events witness the fault window the episode names:
a timeout after the controller's fault-start mark, then restored bytes after
its fault-end mark or the named stop under the fault. The episode's status and
verdict are the controller's attestation of what the provider reported. `judge`
checks a game-day run record against its committed package's digest. For
GD-2, the package `scripts/gameday-judge.py` judges, the inputs entry also
pins `seal_sha256`, the SHA-256 of the evidence directory's seal as the stop
controller printed it, and names that directory under `evidence`. `judge`
refuses a record whose seal differs from the pin, reruns the game-day judge's
loader and rules in its own process over the directory, refuses evidence whose
seal differs from the pin, and refuses a record that differs from the rerun's,
naming both verdicts. Either seal refusal reads MISSING; a record that differs
from the rerun's reads FAILED when the rerun reads DISPROVEN and MISSING
otherwise. Absent evidence, or evidence the game-day judge refuses, leaves a
HELD record UNVERIFIED with that reason. For every other package `judge` reads
the record's verdict as its producer attests it. Each grade read
from a run record is marked `run_record_graded`. A reviewer entry names the release
revision it graded and reads STALE under another. The inputs name each
runbook's rehearsal record by its file, and `judge` compares the SHA-256 of
its bytes with the digest the index entry records. `--output` names a new
path: `judge` creates its receipt and replaces no file. It grades every item
VERIFIED, FAILED, STALE, MISSING, UNVERIFIED or NOT APPLICABLE and writes a
receipt with each
grade, the unresolved items per domain, each class's cells by evidence kind,
the open gates, the exception register, `recommended_verdict` and `ready`. On
the committed record with no evidence every applicable item reads MISSING and
the verdict NOT READY. The register rejects an exception for a floor item,
and a null authority reads NOT READY. `judge` exits 0 only for READY with no
open gate and no lift the evidence contradicts. Like `check`, it needs the
pinned Rust toolchain. It reads the record, the pinned files, the committed
evidence and every script a judge loads from the tree it runs in, so it runs in
a git checkout of the inputs' `revision` and refuses a checkout at another
commit or with a tracked file that differs from that commit. Untracked files,
such as the inputs, the evidence and the receipt, are admitted. It runs by
hand in the readiness review, outside CI,
because its inputs are the release's receipts, which the review collects and
the repository does not hold. The receipt is a recommendation, and its reader
is the named human who authorizes each writable wave in a separate artifact.
The header of `scripts/readiness.py` states the inputs and the grade rules.

### The game-day judge

`python3 scripts/gameday-judge.py --evidence DIR --record FILE` derives the
verdict of one run of GD-2 from an evidence directory and writes the run
record that `scripts/readiness.py judge` reads under `gamedays`. It reads GD-2
from `verification/readiness/gamedays.json` and the fleet bounds below from
two Rust files, all of its own tree, and makes no git or network call. It creates FILE and replaces no entry, and exits 0 on a
`HELD` record, 1 on any other record and 2 when the run delivers no record.
Exit 2 acknowledges no record of this run, and an entry at FILE after it is
no judged record: one that stood before the run, one another writer made
during it (the message says it appeared), or this run's record whose removal
after a failed directory sync is not known to be durable (the message says it
may stand). These statements assume a local file system with POSIX file and
directory sync. A staging run, the
simulated rehearsal and the stop controller write the one layout below; every
file is a regular file of at most 64 MiB holding JSON or JSON lines with
exactly the keys listed, and a time is seconds on the clock `package.json`
names. A link, a special file or a directory other than `injection` and
`records` is refused. A shard name starts with an ASCII letter or digit,
continues with letters, digits, `.`, `_` or `-`, and is not `receipts`, since
it names `records/<shard>.jsonl` beside `records/receipts.jsonl`. A
fractional number's decimal value equals that of its double's shortest form
(`1.2300` is accepted, `0.10000000000000001` refused). The
subsection below states each field's type, its writer and every refusal.

| File | Keys |
|---|---|
| `package.json` | `id` (`GD-2`), `kind` (`staging` or `simulation`), `revision`, `date`, `clock`, `target` {`host`, `instance`}, `hosts`, `shards`, `witness` [{`key`, `shard`, `sha256`}], `baseline` and `run` {`start`, `end`}, `interval`, `reconciler_principal`, `working_budgets` {budget: value}, `outside` {observation: reason}, `clock_error_seconds`, optional `note` |
| `injection/roles.json` | `package_sha256`, `time`, `shards` {shard: {`owner`, `standby`, `generation`, `volume`, `attempts`}}, `standbys` {host: {`instance`, `instance_state`, `host_report`}} |
| `injection/stop.json` | `instance`, `time`, `identity` |
| `injection/stopped.json` | `instance`, `state`, `time`, `request` {`instance`, `time`, `identity`} |
| `injection/abort.json` | `cause`, `guardrail`, `time`, `detail` |
| `injection/restoration.json` | `instance`, `state`, `time`, `reviewed_sha256` (the SHA-256 of the operator's record of GD-2's abort steps after an abort, else null) |
| `injection/collected.json` | `time`, `files` {file: SHA-256} for `coverage.json`, each collected file present and each other mark under `injection/` that stood when it was written |
| `records/<shard>.jsonl` | `time`, `owner`, `standby`, `generation`, `volume`, `attempts` |
| `records/receipts.jsonl` | `time`, `shard`, `principal` |
| `activations.jsonl` | `host`, `activations` [{`shard`, `generation`, `attempt`, `time`}] |
| `witness.jsonl` | `key`, `host`, `time`, `outcome` (`hit`, `miss`, `error`), `sha256` |
| `origin.jsonl` | `time`, `key` |
| `provider.jsonl` | `event` (`volume` with `volume`, or `CreateVolume` with `principal`), `time` |
| `blockers.jsonl` | `shard`, `time`, `name` |
| `coverage.json` | {file: {`from`, `to`, `lines`}} for each collected file present |

`injection/roles.json` and `injection/collected.json` are required; the other
four marks under `injection/` are optional. `collected.json` is the stop
controller's seal of the collections and the marks, written by its `seal`
once the run window has ended; the judge refuses a collected file,
`coverage.json` or a mark whose bytes differ from the digest it names, a file
it names that is missing, and a mark it does not name, except a
`restoration.json` that ends no observation (dated at or after the run
window's end plus `clock_error_seconds`), which `restore` may write after the
seal. An evidence directory without it is refused (exit 2). `origin.jsonl`, `provider.jsonl` and `blockers.jsonl` hold
the observations `origin`, `provider` and `re-enrollment`; a `simulation`
package names those its world lacks under `outside`, their files stand
absent, and the rules that read them read `outside`. A package whose `hosts`,
`shards` or `witness` list holds more entries than its bound in
`FLEET_BOUNDS` is refused once `package.json` is decoded, before any entry is
checked against the schema, put in a set or used to lay out files. The zone's
fleet directory refuses a listing of more than `MAX_HOSTS` hosts
(`crates/kestrike/src/failover/zone_loop/directory.rs`) or `MAX_SLOTS`
shards (`crates/kestrike/src/failover/standbys.rs`), and the judge bounds
`hosts` and `shards` by those constants. No record declares a count of
witness keys, so the judge bounds `witness` by `MAX_SLOTS` too, a working
value in keys: one key for each shard a zone may hold. The judge compares GD-2's five
clauses with their bound names, its eight guardrails and both oracle texts
with the texts its eleven rules were written from, and exits 2 on any
difference. The record holds `id`, `mode` (`causal` for `staging`,
`simulation` for `simulation`), `kind`, `revision`, `date`, `run_status`,
`verdict`, `package_sha256` (the SHA-256 of `package.json`), `catalog_sha256`
(the package digest `readiness.py check` reports), `reach`, `abort`, `rules`
(each rule's `result`, `text`, `guardrail`, `past_stop_condition` and
`detail`), `budgets` (each bound's `value` and `source`), `seal` (the SHA-256
of `injection/collected.json` and its `time`) and `result`. While
GD-2 is blocked, `readiness.py judge` reads a `HELD` staging record as
UNVERIFIED, and it refuses a `simulation` record under a staging item.
`python3 -I scripts/test-gameday-judge.py` runs the judge over the committed
fixture `scripts/gameday-fixtures/held/` and the copies it plants. The
pre-push hook runs it for a push that changes the judge, its self-test, its
fixtures, `scripts/readiness.py` or a script it loads or hashes at import,
`scripts/fis-profiles.json`,
`verification/readiness/gamedays.json`, a file that declares one of its
`FLEET_BOUNDS` or
`verification/readiness/failover.json`. No CI job runs it yet: the line that
adds it to the "Script self-checks" step after `python3 scripts/readiness.py
check` waits for a login with the `workflow` scope, so a clone without the
hook runs it by hand.

#### The evidence layout, the rules and the record

The judge follows this statement; its names in capitals are constants of
`scripts/gameday-judge.py`.

```text
The evidence directory. Every file is UTF-8 JSON (`.json`) or JSON lines (`.jsonl`, one object per line, each line
ending in a newline), a regular file of at most FILE_LIMIT (64 MiB) bytes; a link or a special file in DIR, or a
directory other than `injection` and `records`, is refused. Every object holds exactly the keys listed, decoded with
distinct keys; NaN, infinities, a number beyond a double's range or with an exponent `decimal` cannot hold, and a
fractional number whose decimal value differs from that of its double's shortest form are refused, so each number
decodes to its literal's value. A time is seconds on the clock `package.json` names: a JSON number of at most 2^53 in
magnitude; a positive number (`interval`, a working budget, a catalog budget) is one too. Every text (a host, shard,
key, instance, principal, volume, state, report, identity, clock, reason, blocker name, note or detail) holds a
character other than whitespace and has no lone surrogate, so it UTF-8 encodes; a shard starts with an ASCII letter or
digit followed by letters, digits, `.`, `_` or `-`, and is not `receipts`, since it names `records/<shard>.jsonl`
beside `records/receipts.jsonl`. A `generation` is an integer from 1 to 2^32 - 1, a record's `attempts` from 0 to
ATTEMPTS_MAX (2^31 - 2), an activation's `attempt` (the activated epoch) from 0 to 2 x ATTEMPTS_MAX, and a line count
from 0 to 2^53. Windows are half-open: a time t lies in [start, end) when start <= t < end. No other file or directory
stands in DIR, which the judge names by its last component and opens following no link there (`link`, `link/` and
`link/.` alike); an empty name is refused.
  package.json              {id, kind, revision, date, clock, target, hosts, shards, witness, baseline, run, interval,
                             reconciler_principal, working_budgets, outside, clock_error_seconds} and optionally
                             `note`, a text (a synthetic
                             fixture says so there). `id` "GD-2"; `kind` "staging" or "simulation"; `revision` the
                             40-hex commit the run ran; `date` YYYY-MM-DD; `clock` the clock's name; `target` {host,
                             instance}, the host the run stops, one of `hosts`; `hosts` and `shards` every host and
                             shard of the zone, distinct; `witness` [{key, shard, sha256}], distinct keys, each the
                             SHA-256 (64 lowercase hex) of the key's bytes recorded before the fault from a reference
                             outside the cache; `baseline` and `run` {start, end}, the baseline window and the run
                             window, the baseline ending at or before the stop and at or after the run window's
                             start, and the run window holding the stop;
                             `hosts` holds at most the MAX_HOSTS and `shards` at most the MAX_SLOTS that their
                             FLEET_BOUNDS files declare, the bounds the zone's fleet directory refuses a longer
                             listing by, and `witness` at most MAX_SLOTS keys, a working value; a longer list is
                             refused after the file is decoded and before any of its entries is checked;
                             `interval` the seconds of one origin-rate interval, positive, a whole number of which
                             spans the run window; `reconciler_principal`; `working_budgets` {budget: positive
                             number}, a working value for a budget GD-2's clauses name; `outside` {observation: reason}
                             with observations of OBSERVATION_FILES, empty for `staging`; `clock_error_seconds` a
                             number >= 0, 0 for `simulation`, the largest difference between two writers' clocks the
                             operator vouches for. `package_sha256` is the SHA-256 of this file's bytes.
  injection/roles.json      {package_sha256, time, shards, standbys}: the package's digest; the read's time, before the
                             stop; `shards` {shard: {owner, standby, generation, volume, attempts}} for exactly the
                             package's shards, each equal to its last version stamped before `time` by more than
                             `clock_error_seconds` (at or before `time` when that is 0) or to a version stamped
                             within `clock_error_seconds` of `time` (`standby` a host or null; `generation` and
                             `attempts` counts);
                             `standbys` {host: {instance, instance_state, host_report}}, the control plane's state of
                             each standby host of the target's owned shards (`running` when running) and the host's own
                             report (`healthy` when healthy). Required.
  injection/stop.json       {instance, time, identity}: the stop request. Optional.
  injection/stopped.json    {instance, state, time, request}: the control plane's report, `state` "stopped" when the
                             instance stopped, and its record of the stop request {instance, time, identity}, read apart
                             from the stop request's reply. Its `time` is "the stop" when it names the target's
                             instance `stopped`: the injection has occurred when the instance is reported stopped, and
                             every window that starts at the stop starts there; any other report gives no stop.
                             Optional.
  injection/abort.json      {cause, guardrail, time, detail}: `cause` one of CAUSES, `guardrail` one of GD-2's guardrail
                             texts when `cause` is "guardrail" and null otherwise, `detail` a text or null. Optional.
  injection/restoration.json {instance, state, time, reviewed_sha256}: the instance `stop.json` names (the target's
                             with no `stop.json`) observed `running` again, at or after the stop request, the abort
                             mark and a stopped report of that instance read inside the run window, where they stand,
                             and the SHA-256 of the
                             operator's record that GD-2's abort steps were done before the start: 64 hex digits when
                             `abort.json` stands, null when it does not. A `time` at or after the run window's start and
                             less than `clock_error_seconds` after its end ends observation (the rules' common part
                             below). Optional.
  injection/collected.json  {time, files}: the controller's seal of the collections, `time` at or after the run
                             window's end and each `coverage.json` span's `to`, `files` {file: sha256} for
                             `coverage.json`, each file `coverage.json` names and each other mark under `injection/`
                             that stood when the seal was written, the SHA-256 of its bytes. A named file that is
                             missing, a mark it does not name (a `restoration.json` that ends no observation
                             excepted) and a file whose bytes differ from its digest are refused, collected files
                             before the marks and `coverage.json`. Required.
  records/<shard>.jsonl     one per package shard: each committed version of the shard record over both windows, in
                             commit order (times never decrease): {time, owner, standby, generation, volume, attempts}.
  records/receipts.jsonl    each replacement receipt: {time, shard, principal}.
  activations.jsonl         one line per host, at most one each: {host, activations}, `activations` a list of {shard,
                             generation, attempt, time}, `attempt` the activated epoch, twice the record's attempt
                             counter, each activation the host made over both windows. A package host with no line
                             has missing activation records.
  witness.jsonl             each GET of a witness key from the stop request on, in send order (times never decrease,
                             none before `stop.json`'s time by more than the clock error), `time` the client's send
                             time (one time per GET, so the
                             judge sees no latency): {key, host, time, outcome, sha256}, `outcome` one of OUTCOMES, `sha256` the
                             SHA-256 of the bytes received, 64 hex for a hit and a digest or null otherwise.
  origin.jsonl              each origin request over both windows: {time, key}. Observation `origin`.
  provider.jsonl            each volume created in the run window, {event: "volume", volume, time}, and each
                             CreateVolume call, {event: "CreateVolume", principal, time}. Observation `provider`.
  blockers.jsonl            each named blocker: {shard, time, name}. Observation `re-enrollment`; a standby's enrollment
                             is read from `records/`.
  coverage.json             {file: {from, to, lines}} for exactly each `records/` file, `activations.jsonl`,
                             `witness.jsonl`, `origin.jsonl`, `provider.jsonl` and `blockers.jsonl` present: the span its
                             collector covered (`from` <= `to`, on the package's clock) and its line count, which equals
                             the file's, and its `to` at or before the seal's `time`. A span that does not cover the
                             window a rule reads leaves the rule unobserved: the run window up to the end of
                             observation, the baseline window too for
                             origin-load and for the versions and activations one-owner-per-tenure reads, and for a
                             shard's `records/` file the span from the roles read on when that read precedes the
                             window. A rule that reads a collection ending before the end of
                             observation is judged as if observation ended at the earliest such end: a contradiction
                             the collected rows show still stands, a row of a longer collection after that end
                             included, and a rule that needs a row past that end (a first hit, an enrollment, a
                             takeover's end state, the version an activation is made under) reads unobserved.
A file of an observation the package names in `outside` stands absent, with no coverage entry. Every other file above is
required, except the four optional marks under `injection/`. The writers: `package.json` and `coverage.json` the
operator; `injection/` the controller, `collected.json` by its `seal` once every collection is in DIR; `records/` the
operator's collection of the store; `activations.jsonl` the hosts; `witness.jsonl` the client; `origin.jsonl` the
origin; `provider.jsonl` the provider; `blockers.jsonl` the hosts and the reconciler. Stamps of one writer compare
exactly. Two stamps of different writers within `clock_error_seconds` of each other, a difference of exactly that
bound included, are undecided, and the rule that reads the comparison reads
unobserved: a witness GET against the stop or its
shard's takeover write, an origin request against the stop or a first hit, an enrollment or a blocker against the
drain's ends, an activation against the reference of its shard, the shard versions against the roles read and the
stop. A roles read that names a version within the clock error of it is ordered against that shard's other versions by
commit order (the rules' common part below). The judge opens DIR and its two directories once,
following no link, lists each directory and reads each file relative to the directory it listed, and reads
`package.json` first: every other listed path, and every required path missing from the listing, is checked against
the layout it names before any of them is read. The catalog and `scripts/fis-profiles.json` are parsed as
`scripts/readiness.py` parses them.

What the record vouches for. The judge derives each rule's result from the row files under the committed GD-2 texts. It
refuses a file, host, shard or key outside the package's lists, a package off the digest `roles.json` carries and a
coverage count other than its file's. Four statements it takes as their writers' declarations and checks for shape
alone: that `hosts` and `shards` are every host and shard of the zone, that each collected file held every row of the
span `coverage.json` names when the controller sealed it, that the run ran `revision` on `date`, and that
`reviewed_sha256` names the operator's record. The seal binds each collected file, `coverage.json` and each mark that stood to the bytes the
controller read after the run window's end: a row removed from a collection after the seal, with its count lowered to
match, a span widened after it, or an abort or restoration mark removed, added or changed after it, changes what the
seal names, and the judge refuses it. A restoration that ends no observation, dated at or after the run window's end
plus `clock_error_seconds`, may stand unsealed. The seal itself is a file
of DIR, checked for shape: a seal removed and written again over changed files, by the controller or another writer,
reads to the judge as the first one does. The record carries the seal's SHA-256 and time, and `seal` prints that digest.
The inputs file of `readiness.py judge` pins the printed digest as GD-2's `seal_sha256`, outside DIR, and `judge`
refuses a record or a directory whose seal differs from it, so a second seal over changed files is told from the first
there. The run's producers write every file of DIR,
so a directory with a shard, a row or a date left out or changed reads as an honest one does, and a `HELD` record states
that the evidence delivered meets GD-2's oracle. The record's `package_sha256` covers `package.json` alone (the lists,
the revision and the date): `readiness.py judge` compares it with its inputs entry, which binds them when that entry's
digest was taken from the package as filled before the injection, and compares `revision` with the release revision.
`coverage.json`, the row files and the marks stand in the seal's digests, inside DIR, and the record's `seal` carries the seal's
own digest; `reviewed_sha256` stands in the seal's digest of a sealed `restoration.json`, and in no digest of an
unsealed one. While GD-2 is blocked, `readiness.py judge` grades
a `HELD` staging record UNVERIFIED.

GD-2's texts. The judge holds the five hypothesis clauses with their bound names, the eight guardrail texts, and the
SHA-256 of `oracle.reach` and of `oracle.expected` its rules were written from (WRITTEN), and a catalog that holds any other text, or
GD-2 under another mode, is exit 2. `prerequisites`, `runbooks` and the budget values are read as they stand. A bound is
the catalog's budget value, null or a positive number; where that is null, the package's working value; with neither, a
rule it bounds reads unobserved.

Reach (`oracle.reach`, with "several" read as at least MIN_OWNED and "others" as at least MIN_STOOD, working values):
the target owns at least MIN_OWNED shards in `roles.json` and is the standby of at least MIN_STOOD; each owned shard
names a standby other than the target; each such standby host has a `standbys` entry reading `running` and `healthy`
with an instance other than the target's; and the stop is shown. The stop is shown when the roles were read before
the stop and at or after the baseline window's start; each shard's `records/` collection spans the roles read to the
stop request; no version committed
from the roles read to the stop request, or stamped within `clock_error_seconds` of either, names another owner or
standby than `roles.json`; `stop.json` names the target's instance; and
`stopped.json` names it `stopped`, records a request of the same instance and identity as `stop.json` at a time within
`clock_error_seconds` of its (equal when that is 0), and was read at or after the request and before the run window's
end. Any of these unmet fails to inject. The conditions read before the stop (the roles, the standbys' states and
reports) are `roles_reach`, a function of the roles mark and the package alone, which the stop controller calls before
it sends the stop and the reach calls too. A shard with no version the roles read can have seen and that equals it
is read from `roles.json` alone; a shard whose history starts after a late roles read's stop takes its first version
as the reference, and its later versions after it. The judge compares a standby's reported instance with the
target's alone: the package maps no other host to its instance. Each owned shard needs a witness key, owned as the
reference version reads (the last version before the stop for a late read, and then only a shard that each version
the stop may follow names the target's).

The eleven rules (RULES). The target "owned" a shard, or "stood by" for it, as `roles.json` reads. The successor of a
witness key is the standby `roles.json` names for its shard, which the target owned. An owned shard's takeover write is
its first version in commit order after the roles read and before the end of observation naming an owner other than
the target; the rules that read the versions from it on read them in commit order from it. Rules 2,
4 and 11 read each shard's versions before the run window's end from a reference version on: from a roles read before
the stop, the version of `roles.json` and the versions committed after the version the read names; from a read at or
after the stop, the last
version committed before the stop (`roles.json` for a shard with none) and the versions from the stop on. After such a
read a version stamped within the clock error of the stop may be that last version or may follow the stop, so the stop
has one place for each such version: a rule is disproven on a shard when the versions contradict it at every place,
unobserved when they do at some, and held when they do at none; others-keep-owner names its guardrail when it is met
at every place. The version
a roles read names is the first in commit order that equals `roles.json` among the shard's last version stamped
before the read by more than the clock error and its versions stamped within the clock error of the read, so a version
committed after it is read even when its stamp precedes the read; a shard with no such version has every version read.
The end of observation is the run window's end, or, when the time of `injection/restoration.json` lies at or after the
run window's start and less than `clock_error_seconds` after its end, that time less `clock_error_seconds`: the fault is over when the instance runs again, and a row stamped by
another writer within the clock error of the controller's restoration is undecided. No rule reads a line of `records/`,
`activations.jsonl` (each activation by its own time), `witness.jsonl`, `origin.jsonl`, `provider.jsonl` or
`blockers.jsonl` at or after the end of observation, a row's time and that end compared as the decimal values their
digits state; each window below that ends at the run window's end reads up to
the end of observation, and a coverage span needs to reach that end alone. A rule whose window or deadline that end
leaves open reads unobserved, unless a line before it contradicts the rule, and that contradiction is kept; a rule
whose window closed before it is judged as stated. Eight rules read the run window to its end, so under an earlier end
of observation they read unobserved unless disproven (takeover's end state is then not read; a takeover write's other
generation or volume still contradicts it). The other three are judged on the lines before that end: standby-again,
where a drain that ends within the clock error of the end of observation, or after it, is open; witness-first-hit and
no-origin-before-hit, where a requested key with no first hit before the end leaves them unobserved, and a takeover
write or first hit that is not read counts as at the end of observation. Origin-load keeps the run window's intervals,
the stop's cut interval joined to the next as planned. A restoration at or after the run window's end plus
`clock_error_seconds` changes nothing.
  takeover               clause 1: each owned shard's last version before the run window's end names its standby as
                         owner at the generation and volume of `roles.json`, and its takeover write and each later
                         version before that end name that generation and volume.
  others-keep-owner      clause 2: every version a shard the target did not own holds after its reference names the
                         reference's owner; a change of a shard with no role on the target meets the guardrail "a
                         takeover of a shard with no role on the stopped host".
  no-volume-created      clause 3: `provider.jsonl` holds no volume created in the run window and no CreateVolume call
                         by the reconciler principal in it, the guardrail "any CreateVolume by the reconciler
                         principal".
  no-generation-change   clause 3: every version after its reference holds the reference's generation; guardrail "any
                         generation change".
  one-owner-per-tenure   clause 3 and the expected outcome's last clause: the version `roles.json` pins and the versions
                         of a shard before the run window's end name one owner per (generation, attempts); each
                         activation (shard, g, a) after the reference and before that end has an even epoch a >= 2, is
                         made by the host a version of that shard names owner at generation g and attempts a / 2, and
                         is the tenure's only activation; two activating hosts meet the guardrail "two hosts
                         activating one tenure of a shard". A conflict counts when one of its versions or activations
                         follows the reference (after a roles read before the stop, from the stop for a late read);
                         earlier ones are compared against. An activation within the clock error of the reference is
                         undecided: one that breaks the epoch or owner rule, or repeats a tenure activated only
                         before the reference, leaves the rule unobserved. An activation that no version read names
                         its host owner for contradicts the rule where its shard's versions are read to the run
                         window's end and the activation precedes the end of each collection the rule reads; under a
                         restoration that ends observation, or where that shard's `records/` collection ends early,
                         the owning version may stand unread and the rule reads unobserved. With nothing
                         contradicted, a package host with no activation line leaves it unobserved. The rule
                         compares the versions and activations of both windows, so a `records/` file or the
                         activations collected from after the baseline window's start leave it unobserved; an owner
                         named or a tenure activated only before the collections start is outside what it compares.
  standby-again          clause 4: each shard the target owned or stood by for has, within the drain and before the run
                         window's end, a version naming a standby other than the target and the version's owner, or a
                         line of `blockers.jsonl`, a stamp of another writer than the drain's start counting only
                         beyond the clock error inside each end. The drain is [start, start + bound]; it starts at
                         the later of the
                         stop and an owned shard's takeover write, and at the stop for a stood-by shard. An owned shard
                         with no takeover write starts no drain and reads unobserved; a drain that ends at or past the
                         run window's end with neither reads unobserved; guardrail "a shard without a standby or a
                         named blocker past the re-enrollment drain".
  origin-load            clause 5: for each interval [run.start + i * interval, run.start + (i + 1) * interval) of the
                         run window, the origin requests at or after the stop over the part of the interval from the
                         stop on, as a rate, less the baseline window's rate, stay within the bound. The part of the
                         interval that holds the stop after the stop joins the next interval, so no graded span is
                         shorter than one interval, unless the stop lies in the last interval, which is graded over
                         [stop, run.end); with no stop the whole run window is read. A request within the clock error
                         of the stop is undecided and is counted, as a possible request, in the interval its stamp
                         falls in or in the first graded interval, whichever is later; an interval that passes the
                         bound only with its possible requests leaves the rule unobserved. The arithmetic is exact
                         over the decimal values; guardrail "the
                         zone's origin request rate above its baseline past the origin-load budget".
  witness-first-hit      the witness sentence of `oracle.expected`: each requested witness key's first hit in the run
                         window is served by its successor with the pinned digest, at or after its shard's takeover
                         write; a key requested and never hit in the window contradicts it (leaves it unobserved
                         under an earlier end of observation); a key never requested leaves it unobserved. A GET
                         within the clock error of the stop is no request after it: a hit among such GETs, which may
                         be the first hit after the stop, or a key with no other GET leaves this rule and the next
                         unobserved, and any other key is judged on its GETs beyond the clock error.
  no-origin-before-hit   the same sentence: no origin request for a requested key in [stop, its first hit), or [stop,
                         run.end) when it has none; a key never requested leaves it unobserved. It reads the first
                         hit's time alone: a first hit within the clock error of its shard's takeover write leaves
                         witness-first-hit unobserved and this rule judged.
  no-replacement-receipt guardrail "any replacement receipt written by the reconciler principal", over the run window.
  changes-hands-once     guardrail "a shard that changes hands twice": no shard's owner changes more than once over its
                         versions after its reference, counted from the reference's owner.
The safety rules are no-volume-created, no-generation-change, one-owner-per-tenure, no-replacement-receipt and
changes-hands-once. A rule reads `held`, `disproven`, `unobserved` or, for a rule that reads an observation the
package names outside its world, `outside`. A rule's guardrail is named when the evidence meets its condition, and the
record names it as a run that went on past its stop condition unless `abort.json` names that guardrail as its cause.

The record, written as sorted JSON with one space of indent and a final newline, so two runs over one directory are
byte-equal:
  id, revision, date      the package's; `mode` "causal" for a `staging` package and "simulation" for a `simulation`
                          one, set by `kind` alone; `kind` the package's kind.
  run_status, verdict     by the first row that applies, in this order. Reach unmet: FAILED_TO_INJECT, INCONCLUSIVE, and
                          HALTED, DISPROVEN when a safety rule of RULES is disproven; the other rules then read
                          unobserved, since the phase grades none of its clauses. The guardrails of others-keep-owner
                          and origin-load are still read, and that of standby-again when the stop is shown; a met one
                          adds the observations behind it to the rule's detail. `abort.json` with the
                          reach met, before or after the stop request (`abort.before_stop` tells which): HALTED,
                          DISPROVEN with a rule disproven, else INCONCLUSIVE. A rule disproven: COMPLETED, DISPROVEN.
                          A rule unobserved: COMPLETED, INCONCLUSIVE. Else COMPLETED, HELD.
  package_sha256          the SHA-256 of `package.json`'s bytes.
  catalog_sha256          `package_digest` of `scripts/readiness.py`, loaded by path, over GD-2 with the catalog's run
                          rule and budgets as committed, the digest `readiness.py check` reports; a working budget
                          leaves it unchanged.
  rules                   {rule: {result, text, guardrail, past_stop_condition, detail}}: `text` the GD-2 text the rule
                          judges, `guardrail` the guardrail text whose condition the evidence meets or null,
                          `past_stop_condition` true when that guardrail is met and `abort.json` names another cause or
                          stands absent, `detail` a list of the observations behind the result.
  reach                   {met, detail}; `abort` {cause, guardrail, before_stop} of `abort.json`, `before_stop` true
                          for a mark earlier than the stop request, `stop.json`'s time (both are the controller's
                          stamps), or null.
  budgets                 {budget: {value, source}}: the bound each bounded rule used, `source` "catalog", "package"
                          (a working value) or null (none).
  seal                    {sha256, time}: the SHA-256 of `injection/collected.json`'s bytes and its `time`.
  result                  one line: "held on N rules", with ", K outside its world" for a simulation package, then the
                          rules disproven and unobserved by name, and a note when the abort mark precedes the stop
                          request.

Exit 2 delivers no record of this run: a file of the layout missing, unreadable or malformed; an unknown file or
directory in DIR, a link or a special file; a package off the digest in `roles.json`; `roles.json` reading a shard other
than its last version stamped before the read by more than the clock error and each version within the clock error
of the read; a
restoration mark of another instance, another state or a time
before the stop request, the abort mark or the matching stopped report; a baseline window that ends before the run
window starts; a run window that is not a whole number of origin intervals, from 1 to
MAX_INTERVALS; an owned shard with no witness key, or, with the reach met, a witness key of a shard the target did not
own; a coverage entry missing, extra, backwards, with another line count or spanning past the seal's time; a seal
missing, dated before the run window's end, leaving out `coverage.json`, a collected file or a mark that stands (a
restoration that ends no observation excepted), naming a file that is missing or one outside them, or naming
a digest other than its file's; a `hosts`, `shards` or `witness` list longer than its FLEET_BOUNDS bound, or
a FLEET_BOUNDS file that cannot be read, is not UTF-8 or declares its constant other than once as `pub const NAME:
usize = N;` (a CRLF read as LF) or as a value past a 64-bit `usize`; a `simulation`
package with a clock error other than 0; a `staging` package naming an observation as outside; a file of an outside
observation present; a GD-2 text other
than WRITTEN or a catalog budget other than null or a positive number; a record path at which an entry exists or whose
directory lies inside DIR; and a failed write. The record's directory is opened once, before the evidence is read, as
the kernel resolves the path given (a missing or non-directory component before `..` is refused), and every check and
entry acts on that descriptor: the containment check on the directory it names, then a new file created there with
the mode an ordinary create gets (the umask or the directory's default ACL), synced, linked to FILE's name (which fails
if an entry appeared there) and the directory synced. When that sync fails the record is removed and the directory
synced again; when the removal or that sync fails too, the judge exits 2 naming the record that may stand, which is no
judged record. A failed close of the directory after these steps leaves the outcome, and a standard error that cannot
be written leaves exit 2. The descriptor keeps the record in the directory that was checked; it does not stop another
writer inside that directory.
```

### The host stop controller

`python3 scripts/host-stop-controller.py run --operator F --package F
--evidence DIR` stops the one target instance of a GD-2 run and writes the
marks under `DIR/injection/` in
[the evidence layout](#the-evidence-layout-the-rules-and-the-record) of the
game-day judge; `restore` records the instance
running again after the operator starts it. `roles.json` holds the digest of
the `--package` bytes, so the operator copies the same package to
`DIR/package.json` before the run, and the controller refuses a run whose
`DIR/package.json` holds other bytes. The operator file, kept outside the
repository, names the
region, the caller identity, the owner's approval of the package digest and
target, the declared instance set, the snapshot of shard records and host
reports, one CloudWatch metric alarm for each of GD-2's eight guardrail texts
and four time bounds. Before the stop request the controller refuses a run
while the catalog marks a GD-2 prerequisite `TBD - BLOCKS EXECUTION`, and a
run that lacks the approval, a declared target, the caller, a fresh snapshot
cut at or after the start of the package's baseline window, a run inside the
package's run window or every declared instance running. It
aborts on the judge's pre-stop reach conditions (`roles_reach`), loaded by
path, and on an alarm that is not
`OK`, changed state since the read before the stop, or is configured so that
it can read `OK` without data. That check covers the alarm's configuration:
it does not show that a guardrail's source still reports, so the owner
qualifies each alarm to signal the loss of its source within
`observe_seconds`. The controller shows the stop by a status read and a
`describe-instances` record apart from the request's reply, and its one abort
path writes `abort.json` and sends no call that changes an instance. The abort
path starts once `roles.json` stands: a failure before that removes
`injection/` again and ends as a refusal, so the controller writes
`abort.json` only beside `roles.json`. The abort mark's `detail` ends with the
SHA-256 of the restoration steps text the run printed: the digest stands at
the end of `detail` because the layout fixes the mark's four keys. After an
abort, `restore` needs the operator's reviewed record of those steps, the text
with that digest whatever the catalog holds when `restore` runs,
kept outside `DIR` since the judge admits no file outside its layout,
and keeps its digest in `restoration.json`. `restore` serves runs of this
controller: it refuses an abort mark whose `detail` ends otherwise, which
includes one another writer made, such as the simulation export's.
`restore` writes the mark once a status read shows the target running with
both checks `ok`, and dates it from the target's `describe-instances` record:
the record's `LaunchTime` less the clock difference the controller admits
(`SKEW_SECONDS`), and at least the latest time among the stop request, the
stopped report and the abort mark. That is the earliest time at which the
target may have run again, so a target started inside the run window ends the
judge's observation there, and a start less than
`2 * SKEW_SECONDS + 1` seconds plus `clock_error_seconds` after the run
window's end may still end it before the run window's end; `run` prints that
bound. A record that dates no return (unread, of another state, without a
`LaunchTime` in UTC, or one that shows no start after the stopped report)
ends `restore` with exit 1 and no mark; the judge reads the whole run window
where no restoration stands, so that evidence is not to be judged as it
stands. That a start from `stopped` sets `LaunchTime` is read from the AWS
CLI reference ("the time that the instance was last launched"); the self-test's
fake pins the field, and no test reads a real control plane.
`restore` reads and writes the marks by the pathname
`DIR/injection`, so the operator keeps that directory under that name until
`restore` ends. `seal --operator F --evidence DIR`, run once the run window
has ended and every collection named in `DIR/coverage.json` is in DIR, writes
`collected.json`: the SHA-256 of `coverage.json`, of each collected file and
of each mark under `injection/`, dated by the wall clock at its start, and prints the mark's own SHA-256,
also for a mark it linked whose sync then failed (exit 1), since that mark
stands or may stand again after a crash. It makes no AWS call. It lists DIR, `records/` and `injection/` as the judge
does and refuses an entry outside the layout before it reads any file but
`package.json`. It reads each file relative to the descriptor of its
directory, following no link, syncs each file, then `records/`, `injection/` and DIR, and runs
the judge's loader over the bytes it seals with the mark it would write, so
it refuses evidence the loader would refuse; the judge's witness checks
against `roles.json` run in the judge alone. The seal names a restoration
that stands, so an operator who started the target before the seal runs
`restore` first. A `restore` after the seal reads DIR as the judge does
before any call, refuses a package other than the approval's and any evidence
the judge's loader refuses of the directory as it stands (a seal that leaves
out a collected file, `coverage.json` or a standing mark, a sealed file that
is missing or holds other bytes, a file outside the layout), and writes
the restoration with its true time; one that ends observation exits 1, and
the judge refuses the evidence while that unsealed mark stands. `seal` also refuses a
package other than the approval's, a package of kind other than `staging` (a
simulation export seals its own files), a second seal, a held lock and a time
before the run window's end, when a collection may still grow. A signal
before the mark's write is held ends it with nothing written; one during the
write waits for the write's end. `seal` checks for an existing mark and writes its own by
the pathname `DIR/injection`, as `restore` does. The judge refuses a file
whose bytes differ from the seal, so a row removed after the seal with its
count lowered to match is refused. A collection that was short when sealed
is the collector's declaration, and a seal removed and written again reads
as the first, so the operator keeps the digest `seal` printed.
The five AWS calls of `run` and `restore` run under the environment the run
read at its start. The script's header states the operator file, the
snapshot's two file shapes, the five AWS calls and the reply fields it reads.
`python3 -I scripts/test-host-stop-controller.py` runs it
over an in-process fake control plane and judges what it wrote on a copy of
the held fixture; no test calls a real control plane. The pre-push hook runs
it for a push that changes the controller, its self-test, its fixtures, the
held fixture or a file it loads or reads, as [the pre-push checks](#pre-push-checks)
list.

## Lane admission

Put expensive formal verification, model checking, fuzzing, and long-running
tests on schedule and manual events after the workspace. Add nothing long to
the pull-request or push path without explicit user approval. Keep the small
RC11 lane in the fast tier. Preserve pinned tools, negative controls,
deadlines, receipts, and artifacts when changing a lane's schedule.

The shallow bounds are the worker campaigns over the sample suffix tree, the
ServeCore search to depth 5, and 10, 20, 10, and 10 seconds for the frame,
campaign, record, and wire fuzz targets. The nightly bounds are the search to
depth 6, the seeded pre-final-ACK and completed-held searches to depth 5, the
reply-pressure search at a batch of two to depth 7 with its replies-first
control, the long-run lane, and fuzz budgets of 60, 120, 60, and 60 seconds.
The `search-nightly` lane also runs the fleet's scheduled roots in its row
`fleet-scheduled-roots`: the ignored library cases that run a fleet scenario's
further roots and crash cells. It is the nightly lane that selects ignored
tests of the `kestrike` library target.

Lane policy lives once, in `FAST_JOBS`, `HEAVY_JOBS`, `ADVISORY_JOBS`,
`PENDING_JOBS`, and `EVENT_HEAVY` of `scripts/verify-receipts.py`; its `gate`
command judges job results and its `aggregate` command judges receipts. Run
the event matrix, fail-closed cases, and catalog admission before publishing a
change. A skipped proof lane is not proof credit.

## Pre-push checks

With `git config --local core.hooksPath .githooks`, `.githooks/pre-push` runs
`bash scripts/tool.sh pre-push-checks REMOTE` with Git's ref lines on standard
input, then the user-wide hook. The tool `pre-push-checks` runs the checks
`AGENTS.md` requires before a push, each in a worktree of the pushed tip that
it adds under `TMPDIR`, or `/tmp` when `TMPDIR` is unset or empty, and removes
at the end. The worktree checks run the pushed tip's own scripts, a fetched
commit pushed under a new name included. A failed check blocks the push. CI
runs the selection and reconciliation checks on every PR; the model links check
and its self-test run in the hook. The chaos contract check, the receipt
replay, the judges' test and the game-day judge's and the host stop
controller's self-tests run in the hook and by hand; no CI job runs them.

Git gives one line per ref, `<local ref> <local sha> <remote ref> <remote sha>`.
For each pushed tip the tool lists the files the push changes against the
remote commit, or against the tip's merge base with `origin/main` for a new
branch or a remote commit this clone lacks, and runs the checks those files
require:

- `python3 scripts/test-select-tests.py` and
  `python3 scripts/verify-receipts.py admit` for a change to the test inventory
  or registry, the selection and receipt scripts and their judges
  (`scripts/judge-*.py`), the obligation catalog and
  `verification/control-less.json`, a checker's `expected.json`, a file under
  `verification/intake/`, the atomic census and its classifier, the TLC and
  Quint runners, the Verus inventory, `.github/workflows/agent-checks.yml`, or
  a Rust change to an `#[ignore]` or `cfg_attr(.., ignore)` attribute or to the
  name of the fn it marks;
- `python3 scripts/judge-verus.py reconcile` for a change under
  `verification/verus/` or to a source its inventory names;
- at a tip that holds `verification/models/links.json`,
  `python3 scripts/model-links.py check` for a change to the registry, a model
  it enrolls, a file one of its rows cites, `tla/check.py`, the Verus or RC11
  judge, or the links check or its self-test, and for a change to one of those
  scripts also `python3 scripts/test-model-links.py`. A push that removes the
  registry from a tip that keeps the links check runs the check, which refuses
  the tree;
- for `chaos` itself or a path under `chaos/`, the contract check
  `python3 -I chaos/tools/validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml --receipts chaos/receipts --check-claim chaos/READINESS.md`,
  then, at a tip that holds it, `python3 -I scripts/chaos-receipt-replay.py`,
  which runs each run receipt's judge again on its evidence and fails a receipt
  that differs from the one the judge writes, in the verdict or in any other
  field but the time and the interpreter of the judging; its header lists its
  other refusals. A change to the replay runs it at any tip, so a push that
  removes it fails on the missing file. A change at or under `chaos/harness`,
  `chaos/judges`, `chaos/tests`, `chaos/tools` or `chaos/receipts`, or to
  `chaos/ledger.json`, `chaos/project.yaml` or `chaos/approval-policy.md`,
  also runs the judges' test, `python3 -I chaos/tests/test_judges.py`, which
  reads each of them;
- the judges' test, at a tip that holds it, for a change to
  `crates/campaign-supervisor/src/campaign/calibration/controls.rs`,
  `crates/campaign-supervisor/src/campaign/seeds/required.rs`,
  `crates/campaign-supervisor/src/campaign/seeds.rs` or
  `crates/campaign-supervisor/src/protocol/summary.rs`. That run checks each
  of those files only where a test under `chaos/tests/` reads it; where none
  does, a pass says nothing about it;
- `python3 -I scripts/test-gameday-judge.py`, at a tip that holds it, for a
  change to `scripts/gameday-judge.py`, its self-test, a path under
  `scripts/gameday-fixtures/`, `scripts/readiness.py`, a script of its
  `OWNING` tuple (which it loads or hashes at import),
  `scripts/fis-profiles.json`, `verification/readiness/gamedays.json`, a file
  that declares one of the judge's `FLEET_BOUNDS`
  (`crates/kestrike/src/failover/zone_loop/directory.rs`,
  `crates/kestrike/src/failover/standbys.rs`) or
  `verification/readiness/failover.json`. A change to the judge or its
  self-test runs it at any tip, so a push that removes the self-test fails on
  the missing file;
- `python3 -I scripts/test-host-stop-controller.py`, at a tip that holds it,
  for a change to `scripts/host-stop-controller.py`, its self-test, a path
  under `scripts/host-stop-fixtures/` or `scripts/gameday-fixtures/`,
  `scripts/fis-controller.py`, or a file the game-day judge reads
  (`scripts/gameday-judge.py`, `scripts/readiness.py`, a script of its `OWNING`
  tuple, `scripts/fis-profiles.json`, `verification/readiness/gamedays.json` or
  a file that declares one of its `FLEET_BOUNDS`). A change to the controller
  or its self-test runs it at any tip, so a push that removes the self-test
  fails on the missing file.

The five checks above that start as `python3 -I` take their imports from the
interpreter's installation, so a file beside the program at the pushed tip and
the `PYTHON*` variables have no effect on them. Each check starts with the
push's environment, the tool's three streams and the worktree as its working
directory.

Before the worktree checks, the tool guards the chaos records: the receipts
(each `.json` path under `chaos/receipts/` or `chaos/tests/receipts/`) and the
run records (`run.json` of each run directory under `chaos/runs/` or
`chaos/tests/runs/`), which carry the harness's own paths, commands and
output. At a tip with a change under `chaos/` or with no comparison base, it
refuses the tip when an entry at or under `chaos/` is a link or a submodule,
when `chaos`, `chaos/tests` or a record directory is not a directory, when a
record path is not a regular file, and when a record holds what may be an AWS
account number. For every ref it also reads each record that a pushed commit
adds or changes, merges' side branches included. A pushed commit is one the
tip reaches and the destination is not known to hold. The destination holds
the remote commit of the ref line and each commit that a remote-tracking ref
of REMOTE reaches, as of this clone's last fetch or push. REMOTE is the hook's
first argument, the name of the remote the push goes to; a URL or a missing
name selects no remote-tracking ref, and the remote commit alone bounds the
history. The refs of another remote whose name starts with `REMOTE/` are left
out, and a REMOTE whose own name starts with another remote's name and `/`
selects no remote-tracking ref either. A refused record in a commit the
destination holds therefore refuses no later push. The tool refuses the push
when a pushed commit's record holds such a number, or when a pushed commit
makes a record path a link or a submodule, naming that commit. It decodes a
record as JSON and matches each key, string and integer in it; a record that
is not JSON, or that Git cannot read, refuses the push. A match is 12 digits
with no ASCII letter or digit beside them, so a digit run inside a SHA-256
digest is no match, or three groups of 4 joined by `-` with no ASCII letter,
digit or `-` beside them. Every Git command of the tool reads the original
objects and ignores `refs/replace/`, since a push sends the originals, and
reads pathspecs with their magic whatever pathspec mode
(`GIT_LITERAL_PATHSPECS` and its kin) the push set; the checks and the scan
start in that environment too.

Any other Rust change runs no worktree check here, although the census and
witness checks read production source and the intake checks of `admit` read
the regression files, their crates' `Cargo.toml` and the module files on their
paths, `narrate/rules.rs`, the history sources, the `site.path` file of each
escape whose fix is not delivered, and, for a model reference, the `tla/` and
`quint/` models, the TLC configurations and the Quint case modules. After
moving or renaming such a file, run `python3 scripts/verify-receipts.py admit`
yourself; CI runs the selection and reconciliation checks on every PR.

Before the guard, each ref line with a comparison base runs the weakened-test
scan of `scan-weakened-tests` over BASE..TIP inside the tool, with the push's
environment and the tool's standard error as its report stream, and prints
`pre-push: TIP: tool.sh scan-weakened-tests --base BASE` before it. Every
nonzero scan exit is a failed check, named
`scripts/tool.sh scan-weakened-tests --base BASE --head TIP`, and the
worktree checks still run after it. A ref line with no comparison base prints
that its scan was skipped and runs every worktree check: the links checks only
at a tip that holds the registry or the links check, the contract check only
at a tip that holds `chaos/ledger.json`, the replay only beside it, and the
judges' test and the two self-tests each only at a tip that holds it; it also
guards that tip's chaos records. A deleted ref needs no check, and a blank
line is skipped.

The tool prints each failure as `pre-push: failed: FAILURE` at the end. Exit 0
passes, 1 is a failed check, 2 a malformed ref line or a failed Git read
(`pre-push: ` and Git's text), and 120 a failed write to standard error.

The tool records the first of SIGTERM, SIGHUP and SIGINT that reaches it,
whatever disposition it inherited, and reads the record between its steps
and while it waits for a check. Each check leads a process group of its own.
On a record the tool sends SIGKILL to the running check's group while the
check's leader is its own child that it has not reaped, then reaps the leader;
a leader already reaped gets no signal. It removes the worktree once, prints
nothing more and exits `128 + n`. A Git read or the scan is not interrupted;
the record is acted on when it returns, also when it failed. No check has a
time limit.

No handler covers a signal that never reaches the tool. Git starts the hook
in a process group of its own and signals no group. Dying of a signal, Git
2.50.1 to 2.53 signals no hook process (run on 2.50.1), and Git 2.54.0 to
2.56.1 signals the hook's own process id alone (read in Git's
`run-command.c`). The hook's bash then dies, or waits on SIGINT, and the tool
with its check runs to its end. While the launcher builds the tool at line 6
of the hook, the same holds for Cargo (read, not run).

CI runs the same scanner in the `Weakened-test scan` step of
the `comment-policy` job, after `Obligation catalog admission`. On a pull
request that step scans from the first parent of the test merge, so its range
holds the pull request's commits alone. The hook's range starts at the remote
tip, so a pushed tip that merges `main` also brings `main`'s commits and their
acknowledgements into it. The scanner compares the head with the merge base of
the base and the head, so a change made only on the base side is no finding.

A change that ignores an existing test or changes the condition of its
conditional ignore (`ignore-existing`), lowers a declared test budget
(`budget-lowered`), or removes a case of the tools crate (`case-removed`),
fails the push and the CI step until a commit in
the scanned range carries this line, with the `CLASS:PATH` key the report
prints and a nonempty reason:

```text
Weakens-Test: CLASS:PATH: REASON
```

The report and the hint write each control character of a key as `\r` or
`\x7f`; the acknowledging line carries the character itself, as Git stores
the path.

The scanner reads its rule for a case from the Git trees of the merge base and
the head, apart from the build's check of the directory that
[the tools guide](tools.md#adding-a-tool) describes. A case is a top-level
entry of `crates/kestrike-tools/tests`: a regular file `<id>.rs`, or a
directory `<id>` with a regular `mod.rs`, where `<id>` matches
`[a-z][a-z0-9_]*` and is not `tools`; the rule counts `std` and the Rust
keywords, which the build refuses.
A tree without a regular `tools.rs`, the root of the one test executable, also
recognizes `<id>/main.rs`, at the base and at the head alike. A case of the base
blocks when the head holds no case of the same id; a change of shape for the
same id passes, and a rename to another id is the absence of the old one. Its
key names the base entry's path, such as
`case-removed:crates/kestrike-tools/tests/mutants_diff`. Unit test files under
`src/` are not cases.

One line clears every finding of that class in that file. The scanner's other
findings print and never block. A pushed ref with no comparison base prints
that its scan was skipped; CI still scans the pull request.

## Lane evidence and flaky tests

Reviewers and authors apply these rules to CI results;
[the review policy](../../REVIEW.md#tests-and-evidence) links here. A reviewer
who decides whether to ask for a mutation run on a kestrike change, and a
pull request that cites a mutation report, follow
[the mutation-run rules](#mutation-runs-on-kestrike-changes).

- Rust lanes are evidence only when the qualified runner ran them and the job
  summary credits each lane. Each lane writes `receipt.json` and `credit.json`
  into its `evidence-LANE-RUN-ATTEMPT` artifact (the barrier lane's
  `report.json` serves as its receipt), and `scripts/verify-receipts.py`
  credits `verification/obligations.json` only from a completed receipt bound
  to the revision. The gate's aggregate takes the expected revision, run and
  attempt from the workflow's `github.sha`, `github.run_id` and
  `github.run_attempt`, and a lane whose receipt records another or no value
  for any of them is incomplete. It reads only the current attempt's
  artifacts, so rerunning failed jobs alone leaves the earlier passing lanes
  without a receipt in that attempt; a full rerun supplies every lane. A
  cancelled lane step records exit 143 and its receipt completes as `timeout`.
  An earlier failure stays under the flaky-test policy until its reproduction
  is cited.
- A new record of `verification/obligations.json` carries a control or a
  `no_control` member stating why it has none.
  `scripts/verify-receipts.py admit` refuses a record with neither as
  `control-ratchet` unless it stands on `verification/control-less.json`, the
  list of records that had neither when the ratchet began; the list excuses
  the missing control and reason alone. No pull request adds an entry to the
  list. `admit` checks each entry against its record and compares no base
  list, so it admits an entry added together with a new record; the reviewer
  reports a pull request that adds an entry, a removed one restored included.
- A test that failed once in CI is run with `scripts/reproduce-test.py` before
  the next merge that touches the same Cargo package. Cite the run's
  `artifact.json` path and result line in the PR. `not reproduced` covers
  single-test isolation only. Rebuild with the failing lane's compiler and
  environment: `RUSTUP_TOOLCHAIN` set to the `STABLE` pin in
  `.github/workflows/agent-checks.yml`; on x86-64, `SPDK_PKG_CONFIG_PATH` set
  to `/opt/spdk-v25.05.1-x86-64-v2/lib/pkgconfig`, since `build.rs` defaults
  to `/usr/local/lib/pkgconfig`; for the workspace lane,
  `CARGO_PROFILE_DEV_OPT_LEVEL=1` and
  `CARGO_PROFILE_DEV_DEBUG=line-tables-only`, and for its protocol contract
  case also `CARGO_ENCODED_RUSTFLAGS` unset and
  `RUSTFLAGS="--cfg protocol_contract"`, with `CARGO_TARGET_DIR` set to the
  workspace target directory with `-contract` appended, as
  `scripts/rust-lane.sh` runs it; for a loom lane, `--release`
  with `RUSTFLAGS="--cfg loom"`; for the ASan lane, the `NIGHTLY` pin,
  `SPDK_PKG_CONFIG_PATH=/opt/spdk-v25.05.1-asan/lib/pkgconfig`,
  `CARGO_BUILD_TARGET=x86_64-unknown-linux-gnu`,
  `CARGO_UNSTABLE_BUILD_STD=std`, the workspace profile variables,
  `RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"`, and
  `ASAN_OPTIONS=detect_leaks=0`, as `scripts/rust-lane.sh asan` sets them.
- A change to a site that `verification/orderings/expected.json` catalogs,
  or to a test one of its rows names, reruns those rows with the `run`
  command of `scripts/weaken-orderings.py` on an aarch64 host. The pull
  request cites the run's report: its revision, the tool pins and host,
  each result's command, exit, output digest and result, and each row's
  agreement. A decided row records the revision of the run that set it.
- A pull request that claims a bug fix under
  [Prove a bug](simulation.md#prove-a-bug) cites the receipt of its regression
  test from `scripts/red-green.py`: the path of its `receipt.json` and its
  result line, `red-green: ID failed on BASE with "TEXT" and passed on HEAD`.
  The command runs the test through `scripts/reproduce-test.py` on the base
  with the test files carried from the head, then on the head; run it with the
  toolchain and environment that the reproduction bullet above lists for the
  lane that runs the regression test. For a scripted history, the regression
  test is the seeded test that pins it. A reviewer checks that TEXT names the
  intended failure in the base leg's attempt output. The receipt is a local
  record that the pull request cites: it credits no lane or obligation, and
  `scripts/verify-receipts.py` does not read it. When the command refuses
  because the test body or its `mod` line sits in the fixed production file, or
  because the base crashes as the declared defect, the pull request cites the
  `red-green refused:` line, or the `red-green rejected:` line when the fixed
  file is the only changed path, and states the red and green runs in prose.
- Every ignored test has one row in `scripts/test-registry.json` with a class
  and a cause that repeats the source attribute's text;
  `scripts/test-select-tests.py` checks the match and the registry's
  `baseline` revision. A flaky ignore needs a reviewed tracker ticket, an
  expiry at most 90 days from the row's date, the reproducer recipe, and the
  first-failure reference; renewal is a reviewed registry edit citing the
  still-open ticket. The validator reports a row lacking these, or expired, as
  a `policy gap`; report it without blocking the pull request. The nightly
  quarantine job over that registry is the one repeat path for an ignored
  test.

### Intake

`verification/intake/` holds one JSON row per file for each escape, incident,
contract change and disagreement, and `exclusions/` holds one file per
exclusion. `python3 scripts/verify-receipts.py admit` refuses a malformed row
under the code `intake` and prints the open escapes, disagreements and
exclusions. A row's `id` is its file name and its `kind` is `escape`,
`incident`, `contract-change` or `disagreement`.

- An escape holds `class` (`safety bug` or `correctness bug`), `property`
  (nonblank `text` and `pointer`, and a `place`: `obligation`, `rule`,
  `spec`, `documentation`, `model` or `pull-request`), `site` and `fix`.
  `admit` resolves three places: an `obligation` pointer is a record id of
  `verification/obligations.json`, a `rule` property's `text` is a rule text
  (a string literal of an array that `scoped` in `narrate/rules.rs` lists),
  and a `model` property names its file in `model` (a `.tla` file directly
  under `tla/` or a `.qnt` file directly under `quint/`) and in `pointer` a
  property the model's runner checks in a case that passes on the committed
  text. A `spec`, `documentation` or `pull-request` pointer is checked by
  review.
- `site` holds `path`, relative to the checkout, and `function`: each
  function of `site.path` the defect lies in, written `Type::method` for a
  method. A second site in another file goes in `note` with its own path, and
  a planted control's row names its control. While `fix` is
  `not-delivered`, `site.path` names a file of the repository.
- `fix` holds `state` `merged` with its `pull_request` number, or
  `not-delivered`, and optionally `fix.regression`: a `path`, a Rust file
  under the `src/` or `tests/` of a crate (a directory of `crates/` that
  holds its `Cargo.toml`), and a nonempty `tests` list of test IDs without
  repeats. Each ID is the path cargo prints: its modules follow the `mod`
  declarations from the crate root (or the integration test's root) to
  that file, and its last name is a `#[test]` fn there outside comments.
  `admit` reads the sources and runs no test. It takes a crate's roots from
  its files (`src/lib.rs`, `src/main.rs` and the roots under `tests/`) and
  reads nothing of the manifest beyond its presence, so review checks that
  the cited file belongs to a target cargo builds with its test harness. A
  target's `path`, `test = false`, `harness = false` or `required-features`,
  or a package's `autolib`, `autobins` or `autotests` set to `false`, can
  take a file out of those targets.
- A `pair` names the record of the same defect. A `cause` (`workload`,
  `environment`, `ordering` or `property`) comes with its nonblank
  `evidence` keys (`steps` and `sweep`, `gap` and `standing_check`,
  `constraint` and `sweep`, `unjudged` and `sweep`; `standing_check` names
  the library regression or says none; a `sweep` names its archive by the
  build digest, 64 lowercase hexadecimal characters), and then `catch` or
  `exclusion`. `catch` holds `history`, a quoted history name (the first
  literal of a history constructor in an array that `every` or `scenarios`
  of `histories.rs` chains), `rule`, a rule text, and a nonempty `tally`
  object of the run on the unfixed build, which the fix's pull request
  replaces with the run on the fixed code: its `build` is that run's archive
  digest, and it holds, at any depth, a `missed` count and a `runs` count.
  Every `missed` is 0, and every `runs` is a positive integer or the text
  `first..last` of two run numbers, the last no smaller. The catch of an
  escape fixed before its history existed names the history that passes on
  the fixed code in `history`, the planted control in `control`, a quoted
  history name as `history` is, and in `rule` the text the control ends in;
  its `tally` holds the history's tally under `history` and one for each
  control in the list `controls`, each an object with its history's `name`
  and its own `runs` and `missed`. `admit` checks the two names and the rule
  text, refuses a `control` that repeats `history` and a tally that lacks
  the entry named for `history` or for `control`, and leaves each ending and
  the run behind each tally to review. A defect with a further site
  holds each further history in the list `catch.also`: an object with
  `history`, a quoted history name that no other history of the catch
  repeats, the `site` it fails through, and a `tally` under the same rules;
  the catch then names its own `site`. Each of them fails `catch.rule`.
  `admit` reads no history's declared ending, so review checks each one:
  `catch.control` and each history of `catch.also` declare the rule's
  violation, and `catch.history` declares it in a catch without a `control`
  and passes in a catch with one. A row with neither
  `catch` nor `exclusion` stays open. A planted control that a sweep misses
  is an escape row whose `site` names the control, with `fix`
  `not-delivered`.
- An exclusion file `exclusions/<id>.json` holds `id`, `reason` and
  `covers`, the ids of the escape rows it excludes, each once; each of those
  rows names the file's id, without `.json`, in its `exclusion`. `approval`
  stays absent until the owner approves, and is then the citation of that
  approval. `admit` checks that the citation is nonblank text and leaves its
  authenticity to review.
- An incident or contract change holds `property_action`: `action` `added`
  with a `place` (`obligation`, `rule` or `model`, with `model` a file under
  `tla/` or `quint/`) and the `reference` there that states the property, or
  `action` `none` with a `reason`. A disagreement holds two distinct
  `sources`, and `holds` (the owner's answer) with `corrected` (the pull
  request number that corrected the other text) once the owner answers.
- An intake row's `evidence` supports its `cause` with a run or a file a
  reviewer can read: the root and the profiles swept on the unfixed build, or
  the path and the command that show the gap. A cause without that evidence
  is unverified; report it as unverified.
- A pull request that fixes an escape, changing the code its row's `site`
  names, sets that row's `fix` (state `merged`, its pull request, its
  regression) and, where the row holds `catch`, replaces `catch.tally`, and
  each tally under `catch.also`, with the tally of the run on the fixed code.
  Every `missed` count is 0 there as
  well: a history that still expects its violation and passes on the fixed
  code counts as missed. A reviewer reports such a pull request that leaves
  the row unchanged.
- A pull request is a contract change when it changes an `invariant` of
  `verification/obligations.json`, a rule text of
  `crates/kestrike/src/net/world_tests/narrate/rules.rs`, a model under
  `tla/` or `quint/`, or an item a row of `verification/models/links.json`
  cites. It adds its `contract-change` row with `property_action`: `added`
  with the place and the reference that states the new contract, or `none`
  with the reason. A reviewer reports a contract change without its row.

## Mutation runs on kestrike changes

The author of a kestrike change who cites a mutation report, and any
reviewer of a kestrike change, apply these rules. One command lists the
mutants `cargo-mutants` generates for the lines a commit range adds or changes
under `crates/kestrike/src`, runs the library tests against each mutant in
a temporary worktree of the head commit, and writes
`target/mutants/<run id>/report.json`:

```sh
bash scripts/tool.sh mutants-diff --base BASE --head HEAD
```

It prints the result line, then one `missed:` line per survivor (missed
mutant):

```text
mutants: HEAD against BASE on aarch64: N listed, C caught, M missed, T timeout, U unviable; complete
```

HEAD and BASE there are the first 12 characters of the two commit ids;
`report.json` holds the full ids.

`bash scripts/tool.sh mutants-diff --help` states the runner's options, the report
fields and the exit codes.
The run needs a native aarch64 Linux host whose CPU reports every feature the
`isa-aarch64` entry of `scripts/test-inventory.json` declares, so the library
tests run the aarch64 kernels. The host also needs the `STABLE` toolchain of
`.github/workflows/agent-checks.yml`, the native SPDK install at the build
script's default path, `cargo-mutants` at the pin in `.cargo/mutants.toml` and
a disk-backed `target/`. The run builds for the host target. The result line
names the host's architecture and checks neither the CPU features nor the
build target.

On 2026-11-20, on an `aarch64-r8gb-4xlarge-ebs` host (r8gb.4xlarge, 16 vCPUs)
with light concurrent use, the run over merge `63b9da21b` took 16 minutes for
11 mutants of one function: a 163-second baseline build and an 11-second test
pass, then 53 to 66 seconds of rebuild and 11 seconds of tests per mutant. One
of the 11 ran to the 55-second test timeout the tool derived from the
baseline, so each timeout costs about 44 seconds more than a mutant whose
tests finished in 11 seconds.
Rebuild time depends on the file a mutant changes. As a planning figure from
that run, the default limit of 40 mutants takes 46 to 54 minutes, plus the
cost of each timeout. The build directory held 6.6 to 6.9 GB on disk after
such runs; plan for about 7 GB.

The run is optional. A reviewer asks for one when a change claims new test
coverage or edits a guard. No check enforces the rules below, and the report
credits no lane or obligation and gates nothing. A mutant is caught when some
selected test failed or its process died. That is a signal about the suite as a
whole, so a report supports no oracle-strength claim and no kill-rate claim.

A pull request that cites a report gives its `report.json` path and its result
line, which reads `on aarch64` and ends `complete`. A report that lists no
mutant prints `mutants: 0 listed` in place of the result line; the pull
request cites that line and the report's `base` and `head` commit ids,
`machine` (`aarch64`), `shard` (K and N, or `null` for an unsharded run) and
`complete` (`true`). Such a report holds no survivor and
shows that no test ran. The pull request gives each survivor exactly one
class, with what the class cites, and lists each timeout, which `report.json`
records with `"outcome": "timeout"`, without a class:

| Class | What the pull request cites |
| --- | --- |
| `gap` | A test added in the same pull request, or a ticket |
| `equivalent` | The reason no observable behavior changes. The reason names the inputs the code supports and the precondition that keeps behavior equal. A search that found no distinguishing test is a `gap` with a ticket |
| `covered` | The named check that fails on the mutant, with the run that showed it, or the Verus inventory item that states it in the form the three existing `equivalent mutant, covered by the verified <name>:` items use |
| `out of scope` | An exclusion added to `.cargo/mutants.toml` with its reason, or, for code the aarch64 production build does not compile, the `cfg` predicate that gates it, such as the `test` predicate of an inline test module whose helper the tool mutated |

- A survivor is an observation about the tests. Before anyone calls one a
  cache bug, classify it under [the simulation rules](simulation.md#classify-every-result).
- Every class is stated for aarch64. An `equivalent` reason holds on aarch64,
  which is weakly ordered: a mutant that removes a barrier changes the
  generated code, so its class is `gap` or `covered`. A mutant that removes
  only a barrier passes the library tests and reads as missed.
- The `barriers` lane's fence scan checks each site that
  `verification/barriers/expected.json` declares for a sufficient DMB in the
  site's linked function extent; it does not count barriers or check their
  placement. A barrier mutant outside the declared sites is a `gap`. The
  `barriers` job scans only the unmutated head when it runs, so an author who
  classes a barrier survivor `covered` runs `scripts/rust-lane.sh barriers`
  twice on the aarch64 host, one run after the other since both build into
  one target directory. The environment holds the workflow-level `env` values
  of `.github/workflows/agent-checks.yml` and the `barriers` job's
  `SPDK_PKG_CONFIG_PATH`, with `EVIDENCE` unset. One run is in a temporary
  worktree of the head commit, where the run passes, and the other in a second
  temporary worktree of the head where `patch -p0` at the top level applied
  the mutant's `diff` from the run directory's `list.json`. With `EVIDENCE`
  unset each run writes the `evidence/` directory of its own worktree, which
  stays until the pull request cites it. The pull request cites both
  runs' `report.json` files, whose `sha256` values differ; equal values show
  the mutated run scanned an earlier build and settle nothing. The survivor is
  `covered` only when the
  mutated run's scan gives the verdict `fail` to a declared site; since the
  unmutated run passed every site, the mutant caused that verdict. A mutated
  run that passes makes the survivor a `gap`; a failure before the scan or a
  `refused` verdict settles nothing.
- The report flags a file whose viable mutants were all missed. Each survivor
  in it takes its class from the table; a file compiled only under a gate
  takes one exclusion with its reason.
- A triage rerun replaces the test selection with `--tests=ARGS`, for example
  `--tests="--test sim_worker"`, and uses Miri only with the owner's approval.
- A pull request that cites sharded runs (`--shard K/N`) cites all N reports,
  one for each K from 0 to N-1, the tool's shard index range. The N reports
  hold one `base`, one `head`, one N, one `tests` selection, one
  `diff_sha256`, one `config_sha256` and one `tool_version`. Reports from
  separate clones share one `diff_sha256` only when the clones' diff
  attributes match. Runs that share an artifacts directory go one at a time,
  since a second run exits 2 while the first holds its `build.lock`; shards
  that run at once each pass their own `--artifacts`, and each such directory
  builds from scratch.

## Runner roles

- GitHub-hosted `ubuntu-24.04`: comment policy, lane scripts, rustfmt and the
  Rust gate on every event, and reviews, one fresh machine per job.
- `kestrike-vm-build`: pull-request and push preflight, workspace, campaigns,
  search, and fuzz-smoke on the two registrations of the first Linux VM. The
  legacy label `kestrike-ci-build` stays on Linux while old jobs drain; new
  builds select only the Linux VM and queue while it is offline.
- `kestrike-ci-heavy`: RC11 on every event, whose runner carries the pinned
  `herd7`, and every other schedule and manual job, on the two registrations
  of the second Linux VM, plus the pending x86-64 tag comparison once
  activated. Jobs queue while Linux is
  offline.
- `kestrike-hardware` and `kestrike-fis`: the hardware and FIS jobs, each on a
  host provisioned with its inputs. The hardware job runs one leg per
  architecture, on `[self-hosted, linux, x64, kestrike-hardware]` and
  `[self-hosted, linux, arm64, kestrike-hardware]`, so an aarch64 row's roles
  run on a native arm64 host; the FIS job runs on x64 hosts. A host provisioned for both runs one
  registration carrying both labels, which takes one job at a time and so
  keeps a FIS fault off the devices under a hardware case. These
  registrations carry no other build label. While no host with the label is
  online the job stays queued, GitHub ends it after a day, and no result
  exists for that night.
- `kestrike-isa-x86-64` and `kestrike-isa-aarch64`: the architecture lanes, on
  native hosts whose CPUs report every declared feature, with no other build
  label and no fallback registration.
- `kestrike-aarch64-native`: the deferred barrier scan and the pending
  AArch64 tag comparison once activated. It refuses any host other than a
  native AArch64 Linux machine and has no fallback registration. The barrier
  job is disabled with no coverage credit until this runner is provisioned.

The review workflow uses the `pull_request_target` trigger, so each review runs
the base branch's copy of the workflow, and it runs for pull requests into
`main` from branches of this repository. The pinned action runs the review for
an event of a person with write access to the repository or of the GitHub App
`kestrike-swarm`, the one name its `allowed_bots` input holds, and fails the
job for an event of any other App or bot. Its model token is a secret of the
`claude-review` environment, which admits `main` and no other ref. A pull
request stacked on another branch is reviewed when it is retargeted to `main`.
`.github/CODEOWNERS` names the owner of `.github/`, and a ruleset on `main`
requires that owner's review of a change under it.

Keep the build roles on separate registrations. Each registration takes one
job at a time; there is no shared job-level lock. Preserve legacy labels while old jobs drain, then
retire them after verifying that no queued workflow needs them. Cancel no
other runs to complete the transition. Adding labels does not create capacity.

Runner provisioning installs the pinned LLVM's `llvm-objdump-<major>` and
`llvm-cxxfilt-<major>` (the workflow's `LLVM` version) where the barrier and
tag comparison lanes run, and `llvm-symbolizer` where the ASan lane runs and
on `kestrike-isa-aarch64` for the ThreadSanitizer step. In a hand run on an
r8gb.4xlarge aarch64 host (Neoverse V2, 16 CPUs) the step's cold build peaked
at 11.5 GB of cgroup memory, page cache included, at four Cargo jobs; that
figure is an observation, and the activation measurement checks the runner's
own peak against its limit.
The `crates/campaign-supervisor` store tests create state directories under
the Cargo target directory, so provisioning places each runner's target
directory on a read-write xfs mount, or a read-write ext4 mount with a journal
in ordered or journal data mode and barriers enabled, on Linux 5.8 or later,
and runs the tests under a umask that clears no owner permission bit; the store
refuses every other mount configuration and umask.

## Runner capacity and isolation

Each Linux VM has eight vCPUs, 32 GiB RAM, and a 256 GiB disk. Each of its two
runner services uses a separate non-admin account and work directory, a
four-CPU quota, and a 12 GiB memory maximum, with autostart enabled. Each job
uses four Cargo workers and four Rust test threads. Miri runs single-threaded;
Loom admits at most two matrix jobs at once; TLC and Quint's TLC runs declare
eight workers and a 4 GiB Java heap within the same limits. Measure TLC,
Quint, and Kani against their deadlines under these limits before activating
routing.

Separate registrations reserve job slots without guaranteeing resource
fairness.

Keep personal homes, data, model credentials, and Tailscale state out of the
VMs. Restrict guest networking from the host, home LAN, and Tailscale; allow
required outbound GitHub and package traffic with no public inbound ports.
Keep fork pull-request workflows disabled and preserve the same-repository
event guards. Labels alone do not isolate untrusted code.

Every x64 registration that runs preflight, workspace, heavy, hardware, or FIS
jobs needs the portable SPDK install at
`/opt/spdk-v25.05.1-x86-64-v2`, built as `crates/spdk-sys/src/lib.rs`
describes; the AArch64
barrier job and the arm64 hardware leg keep the native install under `/usr/local`. Build native
dependencies inside the guests for their architecture. `crates/spdk-sys/native/install.sh` is the one writer
of an install record's lineage, and the `spdk-sys` build script, the native
lanes, and the envelope and receipt scripts verify it. Provision the install
before a registration takes jobs; the first job that reads it fails otherwise.

Before activating routing, verify that all four Linux registrations are online, native preflight succeeds on the new runners,
and concurrent short, build, and nightly work respects the resource and network
limits. Verify actual GitHub runner assignment and the required workflow result
before claiming the migration complete.

## Concurrency

Workflow-level concurrency supersedes older runs of the same pull request, so
a newer push to the pull request starts even when the previous revision awaits
an unavailable runner; enabled lanes still require their own passing evidence.
Pushes to a branch queue behind the running run of that branch instead of cancelling it, so every
merge to `main` is followed by a completed run of the merged revision or of a
later one. Scheduled and manual runs keep non-cancelling groups. A pull request
merges only after its latest `agent-checks` run completed; a cancelled or
pending run is not a passing gate. The closed-event workflow
shares the pull-request group and has no runnable job, checkout, token
permissions, or Rust gate. Verify cancellation of queued and running work on
GitHub; the local contract test does not exercise GitHub's scheduler.
