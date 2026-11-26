# Simulation hosts

Read this before you prepare, run or change a simulation host, the
publisher, the watch host or the [fuzz host](#fuzz-host), or change
`crates/sim-host`. A simulation host is an EC2
instance whose `sim-host run` service sweeps simulation seeds with
`campaign` around the clock. The hosts of one S3 bucket share its
assignment and no coordinator: one publisher stores each build of
`main` once, and every host fetches the assigned build, sweeps it under its own campaign name,
confirms new suspects beside the sweep, uploads its roots' snapshots and
keeps a health record that `sim-host status` reads. Each bucket's
watch host runs `sim-host watch`, which keeps the last report in the bucket and stores an
event for each new failure, each cycle in which a host alert opens, and
each UTC day.

## Host contract

Every simulation host and the publisher meet all of these. The watch host
meets the pinned image, the `aws` CLI and the role items; it reads no
instance id, runs no `campaign` and keeps its state on any local mount. The
[fuzz host](#fuzz-host) meets the kernel, cgroup-v2, systemd and
filesystem items on an aarch64 instance and image of its own.

- An On-Demand x86_64 EC2 instance whose instance metadata service answers
  IMDSv2 requests. `sim-host run` and `sim-host check` refuse a host with
  no instance id; the id is part of every root's campaign name. The
  service leaves `SIM_HOST_METADATA` unset; that variable names another
  metadata address as `host:port` and exists for the host tests, and
  `check` prints the address it read as `metadata`.
- Linux 5.14 or later, with the cgroup-v2 hierarchy mounted at
  `/sys/fs/cgroup` and systemd 247 or later.
- The state directory, which holds the sweep roots and the builds, on a
  read-write xfs mount or a journaled ext4 mount (`data=ordered` or
  `data=journal`, barriers on), as the
  [supervisor's host requirements](../../crates/campaign-supervisor/README.md#host-requirements)
  state for every `campaign` directory.
- One pinned machine image for every host, the publisher and the watch
  host. An archive
  pins the host's program interpreter by digest, so a host of another
  image cannot run an archive built on the publisher.
- AWS CLI version 2 with `put-object --if-none-match`, and GNU `tar`, on
  `PATH`. The publisher also needs `git` and the Rust toolchain. The
  watch's unit sets no `PATH`, so `aws` sits in a directory of systemd's
  default `PATH`, such as `/usr/local/bin` or `/usr/bin`.
- An instance role with the [access](#access) its kind needs.

## The bucket

`sim-host` reaches the bucket through the `aws` CLI. Every object is
written with a SHA-256 checksum, and a whole-object download checks it.

| Key | Written by | Holds |
| --- | --- | --- |
| `builds/<build>/archive.tar` | publisher, once | the archive from `campaign sim archive`, as an uncompressed tar of its directory in the GNU format (`tar --format=gnu`); `<build>` is the SHA-256 of the archive's `build` record |
| `builds/<build>/campaign` | publisher, once | the `campaign` binary built from the same commit |
| `commits/<sha>.json` | publisher, once | `{"format": 1, "commit", "build", "campaign"}`: the build commit `<sha>` produced and the SHA-256 of its `campaign` binary |
| `current.json` | publisher | a copy of the commit record to sweep |
| `assignment.json` | operator | [the assignment](#the-assignment) |
| `roots/<campaign>/suspects.jsonl` | the runner that created the root | the root's suspect list up to its last complete line |
| `roots/<campaign>/findings.json` | the same runner | `campaign findings` for the root's `confirm/state` |
| `roots/<campaign>/status.json` | the same runner | the envelope of the root's `sweep-status` output, written after the two lists it summarizes |
| `hosts/<instance-id>/health.json` | that instance's runner | the runner's [health record](#health-and-status), byte for byte |
| `reports/latest.json` | watch | `{"document", "previous_seconds", "seconds", "written"}`: the last cycle's report document, the whole seconds of the cycle the watch completed before it (`null` until one completed since the watch started), the cycle's seconds from its start to just before this put, and the Unix second it was written |
| `events/failure-<id>.json` | watch, once | [a failure record](#failure-records) |
| `events/hosts-<unix seconds>.json` | watch, once | [a host event](#host-events) |
| `events/digest-<yyyy-mm-dd>.json` | watch, once | [the day's summary](#the-daily-summary) |

The `status.json` envelope holds `format`, `build`, `host` (the instance
id), `campaign`, `stint`, `stint_seconds` (the assigned stint length,
`null` when the runner holds no assignment), `written` (Unix seconds),
`cpu_usec` and `capacity_usec` (the root's summed sweep CPU and CPU
capacity), and `sweep_status`, the output of `campaign sweep-status`. A
root that no `confirm` has read stores
`{"findings":[],"release_blockers":[]}` as its findings. When
`sweep-status` or `findings` fails, or a root's count, list or binary
cannot be read or checked, the runner stores nothing for that root in
that pass and names the cause under `upload_error`, so the stored objects
stay as the last successful upload left them.

### Access

| Host kind | Read | Write |
| --- | --- | --- |
| publisher | `builds/`, `commits/`, `current.json` | `builds/`, `commits/`, `current.json` |
| sweeping host | `builds/`, `commits/`, `current.json`, `assignment.json`, and its own `roots/<name>.<instance-id>.*` | its own `roots/<name>.<instance-id>.*` and its own `hosts/<instance-id>/` |
| watch | lists the bucket; `roots/`, `hosts/`, and `events/` to read back a host event it finds present | `reports/`, `events/` |
| operator | everything | `assignment.json`; deletes `hosts/<instance-id>/health.json` to retire a host |

Reads need `s3:GetObject`; the runner's check of its stored objects is a
`head-object` with checksum mode, which needs `s3:GetObject` on its own
roots. Writes need `s3:PutObject`; nothing in `sim-host` deletes an
object. The operator's retirement of a host needs `s3:DeleteObject` on
`hosts/<instance-id>/health.json`, granted to the operator alone. Grant
`s3:ListBucket` on the bucket ARN with no `s3:prefix` condition, so a
missing object answers `NoSuchKey` instead of `AccessDenied`: the
publisher depends on that answer for `commits/<sha>.json` and
`current.json`, a sweeping host for its own stored objects, and the watch
and `report` for root objects a listing shows absent or empty. A bucket
encrypted with SSE-KMS also needs `kms:Decrypt` for every read and
`kms:GenerateDataKey` for every write on its key.

## Prepare a host

Run these steps once per host, as root unless a step says otherwise.

1. Create the unprivileged user and its state directory on the xfs or
   ext4 mount, and a directory for the pinned checkout that `sim` owns:

   ```sh
   useradd --system --create-home sim
   install -d -o sim -g sim -m 0700 /data/sim-host
   install -d -o sim -g sim -m 0700 /data/sim-host-src
   ```

2. As `sim`, with the pinned Rust toolchain on its `PATH`, check out the
   pinned revision into `/data/sim-host-src` and build `sim-host` there.
   Then, as root, install it. The runner takes `campaign` from each build
   it fetches.

   ```sh
   # as sim, in /data/sim-host-src
   cargo build --release -p sim-host
   # as root
   install -m 0755 /data/sim-host-src/target/release/sim-host /usr/local/bin/
   ```

3. With the operator's credentials, store `assignment.json` in the bucket
   as [the assignment](#the-assignment) describes, unless it is there.
   `check` reads it; `run` also needs the publisher's `current.json`.

4. Install the unit from `crates/sim-host/sim-host.service` with the
   bucket's name in place of `SIM_BUCKET`, run the check in a transient
   unit beside it, and start the unit:

   ```sh
   sed "s/SIM_BUCKET/$BUCKET/" /data/sim-host-src/crates/sim-host/sim-host.service \
     > /etc/systemd/system/sim-host.service
   systemctl daemon-reload
   systemd-run --wait --pipe --uid sim -p Delegate=yes \
     /usr/local/bin/sim-host check --bucket "$BUCKET" --confirm-slots 1 --system-cores 0
   systemctl enable --now sim-host.service
   ```

   `check` must exit 0 before the unit is enabled. Give it the same
   `--confirm-slots` and `--system-cores` as the unit's `ExecStart`. The
   transient unit shares the slice and its ancestors with
   `sim-host.service`, so `check` reads their limits; it does not read
   settings made on `sim-host.service` alone, which therefore sets no
   `CPUQuota=`, `MemoryMax=` or `TasksMax=` limit. Run `check` again after
   a change to the assignment's `memory`, `--confirm-slots` or
   `--system-cores`. `run` checks the memory partition again before every
   sweep, with its own `--system-memory`, and records phase `blocked` for
   an assignment whose workers, confirmation and system reserve pass
   `MemTotal`.

### Prepare the publisher

The publisher is one host and the one writer of `builds/`, `commits/`
and `current.json`. `sim-host publish` locks `publisher.lock` in its
state directory and exits 2 while another publisher holds it; give each
publisher its own checkout as well, since the lock covers only the state
directory.

1. Create the user as in step 1 above, and the publisher's directory:

   ```sh
   install -d -o sim -g sim -m 0700 /data/sim-publish
   ```

2. As `sim`, install the pinned Rust toolchain under `/home/sim/.cargo`
   (the unit's `PATH` starts with `/home/sim/.cargo/bin`), clone the
   repository to `/data/sim-publish/checkout`, leave it clean, and build
   and install `sim-host` as in step 2 above. The repository is private:
   the clone and every later fetch authenticate with a read-only
   credential for this repository alone, held by `sim` on the publisher.
   The checkout's `origin` is the repository itself, so `sim-host publish`
   fetches the head of the repository's `main`.

3. Install `crates/sim-host/sim-host-publish.service` with the bucket's
   name in place of `SIM_BUCKET`, run `systemctl daemon-reload`, and
   enable and start it with `systemctl enable --now sim-host-publish.service`.

`sim-host publish` fetches `main` every `--interval` seconds. For a head
with no `commits/<sha>.json` it checks the head out detached, builds
`campaign` with `cargo build --release -p campaign-supervisor`, runs
`campaign sim archive` with `CARGO_PROFILE_DEV_OPT_LEVEL=3` (optimized,
debug assertions on), stores the archive and the binary, writes the
commit record and then replaces `current.json`. A write that finds its
object present keeps the stored object, and the commit record names the
stored binary's SHA-256 from its header. A stored commit record whose
`commit` is not the head is reported and promotes nothing. `git` waits at
most 600 seconds and each build step at most four hours.

The publisher removes `target/release/campaign` as one file before it
builds; a directory at that path stays and fails the interval. A dirty
checkout, a `cargo build` that exits with a code or that exits 0 and
writes no `target/release/campaign`, a `campaign sim archive` that exits
with any code but 4 or 5, an archive whose build record's
`record.provenance` does not name the head as its `revision` with `dirty`
false and `untracked` 0, and an `archive.tar` past 5,000,000,000 bytes or a
binary past 4 GiB publish nothing, and that head is tried again only after `main` moves or the
publisher restarts. A `campaign sim archive` that exits 4 (a host fault)
or 5 (interrupted), a build step ended by a signal, one that outlives its
wait, and a failed `git` or store call are tried again at the next
interval. A checkout that a kill cut off
part way reads as dirty; recover it as `sim` with
`git -C /data/sim-publish/checkout checkout --force --detach origin/main`
and check that `git status --porcelain` prints nothing.

### Prepare the watch host

The watch runs on its own host of the pinned image, with a role that
lists and reads the bucket and writes only `reports/` and `events/`. It
parses data that the hosts wrote, so it runs on its own host with its own
role, apart from the publisher and every sweeping host. One state
directory serves one bucket.

1. As root, create the user as step 1 of [Prepare a host](#prepare-a-host)
   does, the watch's state directory and a checkout directory that `sim`
   owns:

   ```sh
   useradd --system --create-home sim
   install -d -o sim -g sim -m 0700 /data/sim-watch
   install -d -o sim -g sim -m 0700 /data/sim-host-src
   ```

2. As `sim`, with the pinned Rust toolchain on its `PATH`, check out the
   pinned revision into `/data/sim-host-src`, then build and install
   `sim-host` with the commands of step 2 of
   [Prepare a host](#prepare-a-host).

3. Enable the wait unit of the image's time service, such as
   `chrony-wait.service` or `systemd-time-wait-sync.service`, so
   `time-sync.target` waits for a synchronized clock; the watch's unit
   orders itself after that target, because the watch names events by the
   clock. A wait unit that gives up after its own limit, as
   `chrony-wait.service` does, still releases the target, and the watch
   then starts on the clock the host has. For a hard gate, add a drop-in to
   `sim-host-watch.service` with `Requires=` and `After=` on the wait unit.
   The ordering covers the unit's start only.
   Install `/data/sim-host-src/crates/sim-host/sim-host-watch.service` with
   the bucket's name in place of `SIM_BUCKET`, run
   `systemctl daemon-reload`, and enable and start it with
   `systemctl enable --now sim-host-watch.service`.

The platform owner points a bucket notification for object creation
under `events/` at a topic with its recipients. `sim-host` stores the
events, and the bucket notification delivers them at least once, so a
message can repeat. The bucket keeps every `events/failure-*` object: a
rule that expires or deletes one makes the next watch start record and
announce that identity again.

### Replace `sim-host` on a host

Build the new binary from the pinned revision. Compare the installed
unit with that revision's `crates/sim-host/sim-host.service` and carry
the host's own values, such as `--confirm-slots`, `--system-cores`,
`--disk-reserve` and `TimeoutStopSec=`, into the new unit; its
`ExecStart` names the flags the binary takes. Run `check` with those
values, then:

```sh
install -m 0755 /data/sim-host-src/target/release/sim-host /usr/local/bin/sim-host.new
systemctl stop sim-host.service
mv /usr/local/bin/sim-host.new /usr/local/bin/sim-host
systemctl daemon-reload
systemctl start sim-host.service
```

Replace the publisher's binary the same way with
`sim-host-publish.service`, and the watch's with `sim-host-watch.service`.
The watch keeps its state directory across the replacement. A cache entry
written under other read rules carries another format and reads as a
miss, so the new watch reads each such root from the bucket once. On a
state filesystem without the free space [the cache](#the-cache) requires
for a new entry, the watch removes the old entry and reads the root on
every cycle until the space admits its entry.

Before merging a build that adds a report verdict to `main`, verify that
`sim-host-watch.service` is running the updated reader and that every
standalone report site has installed it. If either check is incomplete, run
`systemctl stop sim-host-publish.service` on the publisher before the merge.
Restart publication only after both checks pass. The publisher can promote
the new head within one `--interval`. The [report](#report) section explains
how each reader reports the root and the host.

Stopping `sim-host.service` waits for the sweep to end its current runs. The new runner
resumes the same root when the instance id, the state directory and
`--confirm-slots` are unchanged; another slot count opens a new root.
A root recorded with more confirm slots than the runner has gets no
`confirm` until the runner has as many again, as
[confirmation](#confirmation) describes. Before you start the unit with
fewer slots, after `systemctl stop` returns, check every root in
`state.json` whose `confirm_slots` exceeds the new count, the former
current root included: its `confirmation` is `{"state":"idle"}`, its
`pending` is `false`, and `roots/<campaign>/confirm/confirmed` counts
every complete line of its `suspects.jsonl`, where an absent count is 0.
`sim-host status` does not show this for earlier roots. When a root fails
the check, start the unit with the old slot count, let confirmation run,
and check again after the next stop; each start sweeps again and can add
lines.

## The service unit

`crates/sim-host/sim-host.service` runs `sim-host run` as `sim` and
restarts it whenever it exits. `Delegate=cpu memory pids` hands the unit's
cgroup to the runner. The unit sets no `CPUQuota=` or `MemoryMax=`, and
`TasksMax=infinity` lifts the default process cap. `check` reads `cpu.max`
and `memory.max`; `campaign sweep` itself refuses an ancestor `pids.max`
below its workers' process total. `KillMode=mixed` sends the stop signal
to the runner alone. The runner passes it to `campaign`, whose sweep stops
after each worker's current run. The runner kills its own `aws`, `tar` and
report helpers, and after the sweep exits it spends at most 120 seconds
storing the last stint's snapshot, plus up to 5 seconds for the output
of a helper that exited just before that deadline. `TimeoutStopSec=900` covers an assignment `wall` of 600 seconds
plus the sweep's exit waits, flush and archive check, the runner's
observation of the stopped root of at most 60 seconds and that upload;
raise it with the unit before you assign a larger `wall`.
`LimitNOFILE=65536` exceeds the five descriptors the sweep holds per
worker.

At start the runner moves itself into `runner/` under the unit's cgroup,
enables the `cpu`, `memory` and `pids` controllers for that cgroup's
children and for the children of `confirm/`, and passes the sibling
`campaign/` to `campaign sweep` as `--cgroup-root`. The sweep runs in
`campaign/sweep/`. Each root's `campaign confirm` gets its own cgroup
root, `confirm/<nonce>/`, named by the root's nonce, so a group that one
root's confirmation leaves behind never holds another root's.

## Measured partition

The first hosts of the host set, On-Demand `c7i.8xlarge` instances (32
vCPUs, 64 GiB) of one AL2023 image, measured these values, and the unit
and the assignment below use them:

- With 29 workers, the host's busy CPU less the sweep group's CPU over
  60 seconds was 0.13 CPU: the system, the runner and its store calls.
- With 29 workers, one worker's cgroup peaked at 210 MiB of memory and
  the sweep group at 3.9 GB. The assignment's `memory` is 1 GiB per
  worker, about five times that peak.
- A state directory with two builds and their roots held 350 MB of a
  200 GiB root volume. The unit sets `--disk-reserve` to 16 GiB.
- `--confirm-slots 1 --system-cores 0` gives 30 workers. With them the
  stint share of [Health and `status`](#health-and-status) measured 0.933
  on each of five hosts. The workers' one-CPU quotas sum to 30 / 32 =
  0.9375 of the host; the share also counts the sweep controller, which
  has no quota.
- The assignment's `stint` is 600 seconds. With 600-second stints a new
  build reached every host 15 to 19 minutes after it was published.

```json
{"format":1,"name":"sim","profiles":["cluster-swarm","cluster-swarm","cluster-pressure","upload","contended"],"counts":{},"batch":30,"wall":600,"memory":1073741824,"processes":64,"stint":600}
```

`contended` runs the `faulted` upload plan with the storage's chaos points
armed, so the hosts sweep the rare outcomes those points return: a busy
gate or capture mutex, and a credit reservation whose exchanges are counted
as lost. The hosts sweep it once the operator stores the changed
`assignment.json` in the
hosts' bucket with the operator's credentials; each host reads it at the
start of its next stint, and a change of `profiles` alone keeps each
host's root. The build that `current.json` names lists `contended`, as
every build of `main` since the profile was added does; a sweep whose
build lacks a profile of the assignment exits 2 before any worker starts.

With `wall` equal to `stint`, a run that starts just before the `--for`
time can keep the sweep open for about one more stint length, as step 7
of [a stint](#a-stint) describes. Over that tail only the runs still
going add CPU while the capacity grows with the elapsed time, so the
stint's share can fall below 0.9.

Measure again on another instance type.

A second example assignment sweeps the three recovery profiles,
`recovery-16k`, `recovery-512` and `recovery-torn`, at `restarts=20`,
which lets a run of each take every cut of its built-in table, as
[Recovery crash windows](../../crates/campaign-supervisor/README.md#recovery-crash-windows)
describes:

```json
{"format":1,"name":"sim-recovery","profiles":["recovery-16k","recovery-512","recovery-torn"],"counts":{"restarts":20},"batch":30,"wall":600,"memory":1073741824,"processes":64,"stint":600}
```

One assignment holds one `counts` object, which every sweep of its roots
takes, and a bucket holds one `assignment.json`. So the first example's
hosts keep the default counts, and the recovery profiles sweep from a
bucket of their own, with its own hosts, publisher and watch host, each
prepared as [Prepare a host](#prepare-a-host),
[Prepare the publisher](#prepare-the-publisher) and
[Prepare the watch host](#prepare-the-watch-host) describe with that
bucket's name and grants.

The recovery assignment's `memory`, `processes`, `batch`, `wall` and
`stint` are the first example's. The list above chose `memory` from one
worker's measured peak and measured the build spread at that `stint`,
both for the first example's profiles. Before the operator stores the
recovery assignment, measure a recovery worker's peak on one host of the
type: run the hand sweep that
[Recovery crash windows](../../crates/campaign-supervisor/README.md#recovery-crash-windows)
gives, at `--set restarts=20`, with the unit's worker count and
`--memory 1073741824` in place of the sweep's 2 GiB default, and read
`memory.peak` of each worker's cgroup under the sweep's cgroup root
before the sweep ends. The first example's `memory` is about five times
its measured peak; set the recovery document's `memory` from its own
peak the same way. A suspect of class `out of memory` or a missing peak
is no measurement of headroom. A raise of `memory` after the store needs
`check` again, as step 4 of [Prepare a host](#prepare-a-host) says.

The count of 20 is ruled as it reads, by the workstream's lead on the
owner's delegation of 25 November 2026 (OQ-2.1 of `chaos/interview.md`,
"Ruled for the owner"), and the assignment runs at that count. To put
this assignment in force, the operator stores that
document, with the operator's credentials, as the `assignment.json` of
the bucket whose hosts sweep the recovery profiles, as step 3 of
[Prepare a host](#prepare-a-host) describes.

In a root at `restarts=20` or more, `campaign sweep` also exits 1 for
`no_window`: each profile with 64 runs or more lists its stored planned
crash windows with a zero or folded total, and a profile with an empty
`windows` map stays off it, its coverage unknown, as
[Recovery crash windows](../../crates/campaign-supervisor/README.md#recovery-crash-windows)
describes. That exit sets `alarm` in the host record as it does for
`unreached`. `report` flags the root `no_window`, with each listed
profile's windows in the flag's detail, and exits 2 for it whatever the
host's state, as [`report`](#report) describes. `watch` counts that flag
in its daily summary, and its alert opens for the `unhealthy` state of a
running host, whose reasons name the alarm, as [Host events](#host-events)
describes. The entries stand under `sweep_status.no_window` of the root's
`status.json`. Classify each entry as `docs/agents/simulation.md`
describes.

## The assignment

`assignment.json` in the bucket is one JSON object, at most 1 MiB. When
it starts and at the start of every stint the runner reads it and
`current.json`, waiting at most 15 seconds, and builds the copy the stint
runs from: the document with the commit record of the build to sweep. It
stores the copy at `assignments/<sha256>.json` in its state directory and
records that SHA-256 in `state.json` after the copy is synced, then
removes every other copy. A copy whose encoding would pass 1,052,672
bytes (1 MiB plus 4 KiB) is refused and the previous copy stays in force. A read that fails
or does not parse leaves the copy that `state.json` names in force, and
the health record names the error under `assignment_error`. A copy that
is missing or differs from its digest is written again from the next
read. The read at start gives the stint length of the waits the runner
sets on its roots after a restart.

| Field | Meaning |
| --- | --- |
| `format` | 1 |
| `name` | 1 to 64 letters, digits, `-` or `_`; the first part of each root's campaign name |
| `profiles` | at least one profile, swept in order; each 1 to 242 bytes of printable ASCII other than space, `,` and `/`, and neither `.` nor `..`; a profile listed twice gets twice the batches; joined by commas, the profiles hold at most 131071 bytes, the longest argument a host passes to `campaign` |
| `counts` | the `--set KEY=COUNT` values of every sweep, an object of whole numbers whose keys are printable ASCII other than space and `=`, and other than `root`; each `KEY=COUNT` holds at most 131071 bytes; may be empty or absent. The joined profiles and the counts' `--set KEY=COUNT` arguments take at most 1048576 bytes of `execve` space together, counting each argument's bytes, its NUL and an 8-byte pointer |
| `batch` | seconds per worker batch (`--batch`), 1 to 4294967295 |
| `wall` | seconds one run may take (`--wall`), 1 to 4294967295 |
| `memory` | bytes of memory per worker (`--memory`), at least 1 |
| `processes` | processes per worker (`--processes`), 1 to 4194304 |
| `stint` | seconds per stint (`--for`), and the wait after a failure, 1 to 4294967295 |

Any other field makes the document unreadable. The build comes from
`current.json`. A change to the build, `name` or `counts` opens a new root
at the next stint that has the build on disk, because a root binds one
build, one campaign and one set of counts. A change to any other field
applies to the next stint of the same root.

### Fetching a build

A build that `current.json` names and that is not on disk is fetched on
its own thread beside the sweep, one at a time:

1. `head-object` gives the length and ETag of `archive.tar` and
   `campaign`. The fetch refuses an archive past 5,000,000,000 bytes, the
   largest body of one put, a binary past 4 GiB, and a download when the state directory's free space less
   `--disk-reserve` holds less than twice the archive plus the binary:
   the tar stays on disk until its members are unpacked.
2. Both objects go to `builds/.fetch-<build>/` with `--if-match` on that
   ETag, checked against their stored checksums and their header
   lengths, so an object replaced after its header was read is refused.
3. The runner reads the tar's headers before it unpacks. The first must
   be a ustar header, so a compressed file is refused. Every header must
   hold its own checksum and a plain octal size, and be a regular file, a
   directory with no data, or a GNU long name of at most 4096 bytes. A
   pax header, a link, and a regular file whose name ends in `/` are
   refused. The entries are the regular-file members and the
   directories, including each directory on the path to a member that
   has no header of its own, at most 100000 in all, with at most 8 MiB
   of directory paths. Free space less the
   reserve must hold each file rounded up to 4 KiB plus one 4 KiB block
   for each entry, with an inode each and 64 more.
   `tar --no-same-owner -xf` then unpacks the archive into a directory
   of its own, which must hold only the directory `archive`, made of
   directories and regular files, at most 100000 entries and 16 levels
   deep.
4. The build record's SHA-256 must be `<build>` and the binary's SHA-256
   the commit record's `campaign`. The binary's
   `campaign sim capabilities` must accept the archive within 600
   seconds.
5. The tree is synced, file by file and then directory by directory, and
   renamed to `builds/<build>/`, replacing a directory there that failed
   the check.

Any failed step removes the staging directory, giving its directories
owner access first when a read-only one blocks the removal, and names the
cause under `fetch_error`. A step that fails before the replacement
leaves an existing `builds/<build>/` as it was. The replacement removes
the old `builds/<build>/` before its rename, so a failed rename leaves no
build there, and a failed sync after the rename removes the new
`builds/<build>/`; either way the next fetch publishes it again; the
host keeps sweeping the build it has, and the fetch is tried again after
one stint length. A fetched build is adopted at the next stint, also when
`current.json` has moved again since. A new commit on `main` reaches a
host within two stints when the download finishes within the stint that
read it.

A build already at `builds/<build>/` is admitted when its build record
and binary have the digests of its own `record.json` and that record
names the commit's binary. A build whose record is missing or damaged
while its build record and binary still have the commit record's digests
gets a new `record.json` and no download, so the archive a running sweep
or `confirm` uses stays in place; any other build without a valid record
is fetched again. The sweep's archive verification checks the other members before
each use. Before each sweep, each `confirm` and each snapshot the runner
checks the binary against `builds/<build>/record.json`; a binary whose
length, inode and change times are unchanged is not read again.

## A stint

Each stint the runner:

1. Reads the assignment as above, and starts the store pass and a fetch
   on their own threads. With no assignment in force, it records phase
   `blocked` and tries again after 60 seconds or when a fetch adopts a
   build.
2. Checks that `builds/<build>/` holds the assigned build and binary; when
   it does not, it records phase `blocked` and tries again after one
   stint length. The current root stays current.
3. Resumes the current root when its recorded instance id equals this
   host's, its build, name and counts equal the assignment's, its confirm
   slot count equals `--confirm-slots`, and fewer than three stints in a
   row failed on it. Otherwise it opens a new root named
   `<name>.<instance-id>.<nonce>`, with 16 random bytes drawn once, and
   leaves the old root on disk as it was. A root opened after three
   failures keeps the old root's wait. When `state.json` cannot record a
   new root, the runner keeps the current root, records phase `blocked`
   and tries again after one stint length.
4. Records phase `waiting` while a failed sweep's wait lasts, and phase
   `held` while the root's confirmation is held.
5. Skips the stint and records phase `full` when the roots' filesystem has
   less than `--disk-reserve` bytes free, and phase `blocked` when its
   free space cannot be read, the partition leaves no worker count from
   1 to 1024, or the root has used every stint number.
6. Records phase `blocked` when the workers' `memory`, 2 GiB for each
   confirm slot and its triage slot, and `--system-memory` pass
   `MemTotal`.
7. Runs `campaign sweep --for <stint>` with
   `online CPUs - (confirm slots + 1 + system cores)` workers. After the
   `--for` time the sweep starts no run; each run in progress continues
   until it ends or reaches its `wall` limit, and the sweep then spends
   its exit waits, flush and archive check before it ends. When the
   sweep ends, the runner reads the root's `sweep-status` and suspect list
   length beside the CPU sums, waiting at most 60 seconds, and the next
   pass builds the root's snapshot from that observation, so the stored
   status pairs the work and the CPU sums of the same stint. A current root
   with no such observation, as after a restart, is observed at the top of
   the next stint, before its sweep starts. A check for the root's
   `sweep.json` that fails there is named under `upload_error` by the next
   pass.
8. Runs one `campaign confirm` at a time beside the sweep, as
   [confirmation](#confirmation) describes.
9. Replaces the health record.

| Sweep exit | What follows |
| --- | --- |
| 0 | the next stint, with `alarm` cleared |
| 1 | the next stint, with `alarm` set for the root |
| any other code, a signal, or a sweep that does not start | phase `waiting` for one stint length; after three failed stints in a row, a new root for the same build |
| any exit after SIGTERM or SIGINT reached the runner | the runner stops; the stint counts as no failure |

A failed sweep's wait is kept in `state.json` as a deadline on the boot
clock (`CLOCK_BOOTTIME`) with the kernel's boot id, so wall-clock steps
leave it unchanged. A restart on the same boot waits the remainder, cut to
one stint length; a restart after a reboot waits one full stint length.
The wait clears when the next sweep starts.

SIGTERM and SIGINT go to the running children and halt the store calls in
flight, which then record no error; the runner then stores the snapshots
of its roots, the current root first, within the first 105 of 120
seconds, names each of its roots the time ran out on under
`upload_error`, writes phase `stopped` to its health record, and stores
that record as soon as the snapshots end, within what is left of the same
120 seconds, at least 15 seconds when the local snapshot work stops at its
cutoff. It then exits 0. The 120 seconds count from the start of the
final uploads, after the runner's helper threads end. A stop that the
platform cuts short, or a put of the `stopped` record that fails before
it writes, leaves the last stored record of the running runner; a put
that times out or is cut short leaves either record, because the bucket
may have taken it. A failed put is named under `upload_error` in the
local record. From the stop signal until the `stopped` record lands, the
stored record is the last one stored while the runner ran, and the report
judges its age from its `written`. An error
inside a stint, such as a failed write of `state.json`, halts the store
calls and stops both children first, and the runner exits 1. A runner that
cannot start exits 2: another runner holds the state directory, or the
instance id, `state.json`, the cgroup layout or the signal handlers fail.
After taking the lock, a runner that cannot start writes a health record
with phase `blocked` and the reason.

## Confirmation

The runner starts `campaign confirm` for a root of this instance when its
`suspects.jsonl` holds more complete lines than `confirm/confirmed`
records, or, unless the current root is held on `backlog`, when an
earlier `confirm` admitted jobs and ended before its dispatch queue was
empty, or when its confirmation is `failed`. A list or cursor that cannot
be read also starts one, so `campaign` names the fault. A symlink at the
list's path starts none, since `campaign` reads it without a fault; the
store pass names it under `upload_error` and keeps the root. Each poll made
while no `confirm` runs
considers the current root and one earlier root of this instance in
order, and starts a `confirm` for the first that needs one. It counts the
newline-terminated lines in at most 1 MiB of each list it reads. The
current root comes first, unless its confirmation ran last. The earlier
roots are taken in turn, and a root keeps its turn until a poll considers
it: a poll that starts the current root's `confirm` first leaves the
earlier root for the next poll. The turn order is kept in memory and
starts again at the first earlier root when the runner restarts. Each
root is confirmed with its own build, its own slot count and its own
cgroup root. Roots of another instance are left as they are. A root
configured with more confirm slots than the runner has now waits until
the runner has as many again. An earlier root in `backlog` with admitted
jobs still queued is confirmed again after one stint length, also with no
new suspect line.

The runner reads `confirm`'s JSON report from its whole standard output.
It reads a refusal as the backlog hold when the refusal begins
`backlog holds ` and ends `; dispose findings or raise backlog`, the text
`campaign confirm` prints for that hold, and a report as complete when
standard error lacks `omitted refusals:`. An exit 4 whose standard error
log cannot be read is `held`. The dispatch tests of
`campaign-supervisor` check the hold text that `campaign` produces with
the runner's `is_backlog_hold` and search the omission text it produces
for the runner's `OMITTED_REFUSALS`, so a change to either text fails
`cargo test -p campaign-supervisor` until the tests' expected text and the
runner's readers match it. Its confirm tests check that the report names
its dispatch under the runner's `DISPATCH` key with the runner's
`QUEUE_EMPTY`, and that the interrupted dispatch state prints as the
runner's `INTERRUPTED`.

| `confirm` exit | Confirmation | What follows |
| --- | --- | --- |
| 0, with a dispatch other than `interrupted` | `idle` | a dispatch other than `queue_empty` is retried after one stint length |
| 0, with dispatch `interrupted` or no readable report | unchanged | the next `confirm` waits one stint length |
| 4, its standard output reporting only the `backlog` hold | `backlog` | the sweep continues; the next `confirm` waits one stint length and a new suspect line |
| 4 for any other reason | `held` | no stint starts on the root until a `confirm`, retried after each stint length, exits 0 |
| any other code, a signal, or a `confirm` that does not start | `failed` | the sweep continues; the next `confirm` waits one stint length |

A root whose build fails its check against `builds/<build>/record.json`
gets no `confirm`: the runner records `failed` with that reason and tries
again after one stint length. Each root waits on its own outcome, so a
held old root delays no other root. A held root stays `held` through
later `backlog` and
`failed` exits until a `confirm` exits 0. A `confirm` the runner signalled
to stop changes nothing; one that exited before the signal keeps its
outcome. A root with a non-`idle` outcome or queued jobs also waits one
stint length after the runner restarts before its next `confirm`. The
current root held on `backlog` keeps its queued jobs until a new suspect
line starts the next `confirm`.

A `confirm` killed with SIGKILL while its jobs run leaves their cgroups
under `confirm/<nonce>/`, and the next `confirm` of that root holds on
them. A SIGKILL of the runner makes systemd kill the unit's remaining
processes with SIGKILL, `confirm` included. Recovering those attempts
takes `campaign dispatch` on the root's `confirm/state`, run as `sim` by a
process inside the unit's cgroup: the kernel lets a process move between
cgroups only when it may write `cgroup.procs` of their common ancestor. No
procedure for that has been checked on a host yet.

## Snapshots and root deletion

The store pass walks the roots this instance created. For each root with
a `sweep.json` it takes a snapshot: it reads `confirm/confirmed` before
it runs `campaign findings`, so a count that covers every line was
written before the listing was read. It reads the root's files as plain
files: a symlink there is an error, and so is a `confirm/confirmed` of
more than 64 bytes. A count above the list's complete
lines, or a list that no longer starts with the last stored copy, keeps
the root and its stored objects as they are and is named under
`upload_error`. It uploads the snapshot when its
digest differs from the `receipt` in `uploads/<campaign>/`: the receipt is
removed before the first local copy changes, the suspect list and the
findings are stored before the status, and the receipt is written after
all three puts succeed. A failed upload is tried again at the next pass
and named under `upload_error`.

The runner deletes a root, whole, when all of these hold:

- this runner created the root on this instance, it is not the current
  root, and no `confirm` of it ran or started during the pass;
- the build the host is assigned is known, from a read of `current.json`
  or the stored copy, and is not the root's build, also when the runner
  applies the pass's result;
- the root's last `confirm` exited 0 and left no admitted job queued;
- `confirm/confirmed` counts every complete line of `suspects.jsonl`;
- `campaign findings` lists every finding resolved and no release
  blocker;
- the three stored objects have the SHA-256 of the runner's local copies
  under `uploads/<campaign>/`; a missing or differing object is stored
  again first, and a check that fails is named under `upload_error` and
  keeps the root.

A root that holds no `sweep.json`, no `suspects.jsonl` and no `confirm`,
such as one whose sweeps never started, needs only the first two
conditions.

The runner first takes the root directory's lock, the one
`campaign sweep` holds on its root, and the lock of `confirm/state`, the
one `campaign` commands that write findings hold, and keeps the root
while another process holds either. Under both locks it compares the
metadata of `sweep.json`, `suspects.jsonl`, `confirm`, `confirm/confirmed`,
`confirm/state` and every directory below it with what the store pass saw
before it read the root, and keeps the root when any differs. A file below
`confirm/state` rewritten in place is not seen. Still under both locks, it
marks the root `deleting` in `state.json` and renames the root to
`.trash-<campaign>`. The mark is final, also across restarts. The runner
then renames the root's local copies the same way, removes both trash
entries, removes the root's `confirm/<nonce>/` cgroup, and drops the root
from `state.json`; `state.json` refuses a mark on the current root or on
a root whose confirmation is unfinished. A runner that starts finishes the
deletion of every marked root whose recorded instance id equals this
host's, and every pass removes `.trash-*` entries. A marked root recorded
under another instance id stays in `state.json`, and its build stays on
disk.
After it has read `current.json` once, the runner deletes every
`builds/<build>/` directory that no remaining root names and that is
neither the assigned build, the build of the stored copy, the last
fetched build nor the build being fetched, and every `.fetch-*` directory
no fetch is using. It leaves an entry under `builds/` whose name is no
SHA-256. A removal that fails, or a listing of `assignments/` or `builds/`
that fails, is named under `cleanup_error` and tried again at the next
pass; a failed listing removes nothing from that directory in that pass.
The sweep continues. The bucket keeps every object.

Leave the `builds/<build>/` directory of every root in `state.json` on
disk: a root is swept and confirmed with its own build, and the runner
removes the directory, as above, once no root names it.

## Run a stored suspect line again

A suspect line names the `build`, `campaign`, `profile`, `run` and
`counts` of a run. On any host of the pinned image, with `jq` on `PATH`:

1. Download the build and check both parts against their records before
   anything runs:

   ```sh
   aws s3api get-object --bucket "$BUCKET" --key "builds/$BUILD/archive.tar" archive.tar
   aws s3api get-object --bucket "$BUCKET" --key "builds/$BUILD/campaign" campaign
   tar -xf archive.tar                                  # makes ./archive
   test "$(sha256sum archive/build | cut -d' ' -f1)" = "$BUILD"
   REVISION=$(jq -r .record.provenance.revision archive/build)
   aws s3api get-object --bucket "$BUCKET" --key "commits/$REVISION.json" commit.json
   test "$(jq -r .build commit.json)" = "$BUILD"
   test "$(sha256sum campaign | cut -d' ' -f1)" = "$(jq -r .campaign commit.json)"
   chmod 0755 campaign
   ```

   Stop at the first `test` that fails. The checks find a binary or an
   archive that differs from the records in the bucket; they do not
   authenticate the records.

2. In a delegated cgroup, configure a state directory as step 3 of
   [Run a supervised campaign](../../crates/campaign-supervisor/README.md#run-a-supervised-campaign)
   describes, then admit the line's run and dispatch it:

   ```sh
   ./campaign admit --state "$STATE" --archive archive --campaign "$CAMPAIGN" \
     --profile "$PROFILE" --run "$RUN" --set KEY=COUNT   # one --set per count
   ./campaign dispatch --state "$STATE" --archive archive
   ./campaign findings --state "$STATE"
   ```

The job's seed is the line's `seed`, since admission derives it from the
same archive, campaign, profile, run and counts. A run that fails records
a finding as it did on the host that swept it. `admit` refuses a control
profile's run and a history whose expected result is not a pass, as step 2
of that README section states.

## `report`

`sim-host report --bucket NAME [--build ID]` reads its clock once to judge
ages, then every `roots/<campaign>/` prefix and every host record under
`hosts/`, in key order, through the `aws` CLI, and prints one JSON
document. Reading the roots first means a host whose first record and
snapshot land between the two listings has its record read. It reads the
clock again after each root's `status.json` download and after each host
record's download, and checks a `written` ahead of the clock against that
later reading. It reads at most one `status.json` per root, so it
prints the same totals however often it runs, and a host that stopped
contributes its last snapshot. For fixed bucket contents and fixed clock
readings its output is byte-equal under any listing order. It feeds no
admission, credit or state directory.

`--build ID` takes a build's SHA-256 in 64 lowercase hex digits, the
`build` of `current.json` or of a commit record; any other value exits 64.
The totals, root rows and per-root flags then cover that build's roots
alone. Three kinds of flag stay global and can set the exit code under any
`--build`: every host flag, from the host section below; a `missing` flag
for a root whose `status.json` is absent, not read, unparseable or
contradicts its root; and a `missing` flag for a root of another build
whose `host`, `written` or `stint_seconds` is unusable. A build that no
root names raises `missing` with a `root` of `null`.

Replace `sim-host` where `report` and `watch` run before hosts sweep a
build whose `campaign sweep` can exit 1 for `unreached` or `no_window`.
That exit sets `alarm` in the host record. An older reporter shows
`unhealthy` with `alarm` in `reasons` for a fresh, valid record while the
host is running. A fresh stopped record shows `stopped`; a stale record
shows `silent`. The updated reporter flags `unreached` and `no_window` on
the root independently of the host state.

The document holds `format` (1), `builds`, `roots`, `hosts`,
`host_counts`, `flags` and `exit`, the exit code below.

- `builds` holds one entry per build, and no field adds across builds:
  `roots`, `hosts` (distinct instance ids, `unknown` when a root names
  none), and the sums over the build's roots of `runs`, `uncredited`,
  `suspects`, `replays`, `missed_controls` (`controls.missed` of
  `sweep-status`), `missed_histories` (`histories.missed`), `elapsed_s`,
  `cpu_usec` and `capacity_usec`; `pass`, the passes of unalarmed roots,
  and `unproven`, the passes of alarmed roots; `runs_per_s`, summed runs
  over summed `elapsed_s`; and `cpu_share`, summed `cpu_usec` over summed
  `capacity_usec`. Each root contributes its own sweep time, so
  `runs_per_s` is the rate of one root-second of sweeping, weighted by
  each root's `elapsed_s`. Aggregate host-set throughput needs a shared
  wall-clock interval, which this figure does not measure.
- Each build's `failures` groups its suspect lines by profile and `key`.
  Each group holds `count`, the sum of that key's `suspect_keys` count in
  each root that lists it, `roots`, the roots that saw it, and `rerun`, the
  campaign, profile, run and counts of one listed line, the lowest
  campaign and run, for [running it again](#run-a-stored-suspect-line-again).
  `count` is a lower bound: a root whose list holds a line that its
  `suspect_keys` map does not count yet adds 0, because the sweep appends
  a line before it counts the suspect. A missing profile or `suspect_keys`
  map still prints `unknown` and raises `missing`.
  `unkeyed` lists the campaign, profile, run and counts of each line
  without `key`, which a sweep of an older build writes.
  A root binds one set of counts, so the report reads a line only when
  its `counts` equal the `counts` of its root's `sweep-status`, and every
  `rerun` and `unkeyed` entry prints those. A root whose `sweep-status`
  holds no `counts` of whole numbers under printable names lists none of
  its lines. One root adds at most 65,536 keys to `failures` and 65,536
  lines to `unkeyed`; a further line of a key the root already lists
  still counts.
- Each build's `findings` lists every object row of each `findings.json`
  whose `findings` array holds at most 65,536 rows, with its root, `id`,
  `resolved` and `disposition`, the decision of its latest disposition or
  `null` for a row with none. A held row prints `held` and `held_code`,
  `resolved` as `unknown` and `disposition` as `null`, and raises `held`.
- `hosts` holds one row per instance, by instance id, with its `state`
  and, from its record, `phase`, `reasons`, `reason`, `build`, `root`,
  `share` (the stint's CPU share), `written` and `stint_seconds`, plus
  `error`, `null` for a classified record. `reasons` holds the reasons
  `status` gives the record at its age, and the report's own reason when
  the record's stint length is absent or out of range. A value the
  record lacks prints `unknown`. A text in a row longer than 4096 bytes,
  such as a record field, a reason or an error that quotes one, prints
  as `a text of N bytes`. A `missing` row prints `unknown` for
  every record field and names its cause under `error` and `reasons`.
  `host_counts` holds one count per state: `active`, `degraded`,
  `missing`, `silent`, `stopped` and `unhealthy`. `--build` leaves both,
  and the host flags, as they are. A valid stint length is 1 to
  4294967295 seconds, the assignment's range. Each host takes the state
  of the first rule that matches:
  1. A key under `hosts/` whose instance part is no instance id raises
     `missing` with the key and no row; the report reads it from the
     listing alone. The key `hosts/` itself, a folder marker, is skipped.
  2. A record past the 1 MiB health bound, which the report flags unread,
     one that is no JSON object, does not parse, names no instance or
     another instance than its key, or is written more than 300 seconds
     ahead of the report's clock as read right after its download is
     `missing`, exit 1. A record the listing showed and the read found
     gone counts as no record.
  3. A record with a valid stint length that is older than two of them is
     `silent`, exit 2, in any phase. A `written` up to 300 seconds ahead
     is age 0.
  4. A record in phase `stopped` with a valid stint length and a
     `written` is `stopped`: listed with no flag and not counted active.
  5. Every other record takes the verdict `status` gives it at its age:
     critical is `unhealthy` (exit 2), warning is `degraded` (exit 1) and
     ok is `active`. A record with no valid stint length is `unhealthy`
     at any age, in any phase.
  6. A host with no record whose newest root snapshot is at most two of
     that snapshot's stint lengths old is `missing`, exit 1. A host with
     only older snapshots and no record has no row and no flag.

  A planned restart reads as `stopped` and then as the new runner's
  state, with no flag, while the stored records' `written` stays within
  two stint lengths; the stop itself counts, because the last running
  record stays stored until the `stopped` record lands. A host that stops
  and does not return turns `silent`. A runner that fails in a stint,
  exits 1 and restarts in a loop stores a `starting` record and then a
  `stopped` record in each run, so it reads as `active` or `stopped`
  with no flag; the `reason` of its `stopped` row names the error. An
  operator retires a host,
  stopped or dead, by deleting `hosts/<instance-id>/health.json`. The
  host shows as `missing` until its newest snapshot is older than two
  stint lengths, and then it has no row. Its roots stay in the totals. A
  runner of a binary that stores no record shows as `missing` while it
  uploads snapshots and no record is stored for its host, so the host
  flags hold only once every runner stores its record. A host returned
  to such a binary keeps the last record its newer binary stored, which
  reads `stopped` and then `silent` once it is older than two stint
  lengths. To have that host read `missing` instead, delete its
  `hosts/<instance-id>/health.json` after `systemctl stop` and before the
  older binary starts.
- `roots` holds a row per root of a listed build: `build`, `host`, `stint`,
  `written`, `stint_seconds`, each summed value, `pass` and `alarmed`. A
  root whose `status.json` cannot be read has no row and appears only
  under `flags`.
- `flags` lists each distinct flag once with its `root`, `flag` and a
  `detail` that names the value, object or profile:
  - `silent`, `unhealthy`, `degraded` and the host's `missing` for each
    host of that state, with a `root` of `null` and a `detail` that names
    the `host` and its `reasons`; a key whose instance part is no instance
    id raises `missing` with the `key` instead. The report's clock, read
    once before the `roots/` listing, judges every record and snapshot
    age.
  - `alarm` for a root whose `sweep-status` carries an `alarm` other than
    `null`. An `alarm` that is not text raises the flag with the detail
    `a value that is not text`.
  - `no_pass` for a root whose `sweep-status` carries `no_pass`, the
    profiles that earned nothing. The runner records the same sweep exit
    as the root's alarm.
  - `unreached` for a root whose `sweep_status.unreached` maps profile names
    to arrays of event-name strings within the limits under `missing`, with at
    least one nonempty array.
    The flag detail lists the nonempty arrays. Profile and event names longer
    than 242 bytes appear as `a name of N bytes`. An absent member, null, an
    empty object or an object with only empty arrays leaves the flags unchanged.
    A malformed member, including a top-level array or a number outside the
    `f64` range, raises `missing` instead.
    The runner records the sweep exit as the root's alarm. The build's
    `pass` sum keeps these passes unless `sweep-status` itself carries `alarm`.
  - `no_window` for a root whose `sweep_status.no_window` maps profile names
    to arrays of planned crash-window names, with at least one nonempty
    array. The member has the shape and the limits of `unreached`, with a
    budget of names of its own. The flag detail lists each nonempty array
    under `windows` beside its `profile`. A window name longer than 256
    bytes, and a profile name longer than 242, appears as
    `a name of N bytes`. An absent member, null, an empty object or an
    object with only empty arrays leaves the flags unchanged, and a
    malformed member raises `missing` instead. The runner records the
    sweep exit as the root's alarm, and the build's `pass` sum keeps these
    passes unless `sweep-status` itself carries `alarm`.
  - `other` for a profile whose `other` key counts more suspects than the
    lines it lists, at most eight.
  - `held` for a row of `findings.json` that carries a `held` other than
    `null`. A `held` that is not text prints `unknown`.
  - `missing` for an absent or mistyped value, which adds to no sum and
    prints `unknown` in the field the document shows for it, where a
    `stint_seconds` outside the assignment's 1 to 4294967295, an array
    `no_pass`, `findings` or `dispositions` of more than 65,536 elements
    or a name array of `unreached` or `no_window` past that limit, and an
    object `profiles`, `unreached`, `no_window`, `suspect_keys` or `counts`
    of more than 65,536 distinct keys read as mistyped. The name arrays of
    one root's `unreached` object together may hold at most 65,536 names,
    and so may those of its `no_window` object. Repeated profile
    keys contribute only their last arrays. Exceeding the total raises `missing`
    for the field. The report also raises `missing` for an object that is absent,
    past its bound or unparseable, with its reason; for a root whose name
    holds a byte outside printable ASCII, whose `status.json` is flagged
    as not read and which costs no download or length read; for an
    envelope of another format or campaign, whose `build` is not 64
    lowercase hex digits, whose `host` is not the instance its campaign
    names, or whose `sweep_status` does not name the root's campaign; for
    a `written` more than 300 seconds ahead of the report's clock when the
    report read it, which then counts as no snapshot of its host; for
    suspect lines that do not parse, name another campaign, build or
    counts than their root's, carry no `key`, or pass the 65,536 keys or
    65,536 keyless lines one root lists, where a line whose `counts` hold
    more than 65,536 names does not parse; for a suspect list that ends in
    a record without its newline, which is left out; for a profile's keys
    that are counted with no listed line, and for those whose count is not
    a whole number, one flag each with the number of keys under `keys` and
    the lowest under `first`; for a `findings.json` without an array of at
    most 65,536 findings, which lists none of its rows; for a
    `findings.json` row that is not an object, which the list omits; for a
    row without a text `id`, `resolved`, `dispositions` or a latest
    decision; and, with a `root` of `null`, for a build sum past 2^64 - 1.

A sum with values from some of its roots prints their sum, a sum with no
value from any root prints `unknown`, and `pass` or `unproven` of a build
with no root in that class prints 0. A ratio prints `unknown` unless
every root of the build supplies both of its values.

The report's judgment differs from `status` in these rules: a snapshot
whose `written` or `stint_seconds` is missing raises `missing` with exit
1, a root's alarm comes from its uploaded `sweep-status` alone, and a
record written up to 300 seconds after the report's clock is judged at
age 0, where `status` rates a record written after its clock as stale.
Host rules 2 to 5 above add the rest: a record's identity and its
stint length are checked, and a fresh `stopped` record raises no flag
where `status` exits 2.

`report` reads `status.json` first and the runner uploads it last, so the
findings a report reads are at least as new as the counts, and every key
the counts hold has its lines in the list the report reads. The listing is
older than every read. A listed length from 1 byte up to the object's
bound leads to a download, which reads the object as it is then. For a
root object the listing shows absent or empty, and for a host record it
shows empty, the report asks the bucket for its length again before it
answers. Four answers come from the listing alone: a listed length past
the object's bound, which is flagged unread with that length; a key under
`hosts/` whose instance part is no instance id; an empty or absent suspect
list of a root whose `status.json` holds no `suspect_keys` entry; and the
`status.json` of a root whose name holds a byte outside printable ASCII,
which is flagged as not read. A line stored after the listing under a key
that status lacks appears in the next report. The bounds are the report's
read limits: 256 MiB for `status.json` and `findings.json` and 1 GiB for
`suspects.jsonl`, and a download takes at most one byte past its bound.
The runner bounds the `campaign findings` output it stores as
`findings.json` and the `sweep-status` output inside `status.json` at 256
MiB each. It refuses to store a `status.json` past 256 MiB or a
`suspects.jsonl` whose complete lines pass 1 GiB; the refusal is named
under `upload_error`, and the root keeps its earlier stored objects and
its local evidence. A suspect list only grows, so a root past that bound
is refused at every pass and is never deleted; nothing recovers it on its
own. Keep the root and its build, and remove them only by an operator
step the owner approves.

A report makes one listing call per 1,000 objects under `hosts/` and under
`roots/`, one download for each nonempty host record within its bound, one
`status.json` download for each printably named root of every build, and
up to two more downloads for each root of a reported build; a root without
suspects costs two downloads. An object the listing shows absent or empty
adds at most one length read. `--build` leaves the `status.json` downloads
in place, because rule 6 judges each host without a record by its newest
snapshot of any build. The calls run one after another, so a report's run
time grows with the number of roots the bucket holds, and `report` refuses
a `hosts/` or a `roots/` prefix of more than 1,048,576 objects. A stored
root stays under `roots/` until an operator deletes its
`roots/<campaign>/` prefix; `sim-host` lists, reads and writes stored
objects. Deleting the prefix with credentials that allow it shortens later
reports and takes that root out of its build's totals.

`report` exits 2 when any host is `silent` or `unhealthy` or any root is
flagged `alarm`, `no_pass`, `unreached` or `no_window`, 1 when any other
flag is set, 3
when a bucket listing fails or passes its bound, or a download, a length
read, the creation of the scratch directory or the signal handlers fail,
which prints no document, or when writing the document fails, which can
leave part of it written and its `exit` member differing from the process
exit, and 0 otherwise. A download that exits 0 and leaves no file counts
as failed. SIGTERM or SIGINT halts the bucket call in flight or the next
one, which fails that listing, download or length read: the report removes
its scratch directory and exits 3. The report removes that directory as it
ends on every path; when the removal fails, the directory stays under the
temporary directory and the document and exit code stand.

## `watch`

`sim-host watch --bucket NAME --state DIR [--interval SECONDS]` locks
`watch.lock` in its state directory, runs one cycle, waits `--interval`
seconds (1 to 4294967295, default 300), and repeats until SIGTERM or
SIGINT, which end the wait at once and the cycle at its bucket call in
flight or before its next root; it then exits 0. It exits 2 when it
cannot start: another watch holds the state directory, the state
directory or the signal handlers fail, or the `events/failure-` listing
passes 1,048,576 objects. Each cycle that completes prints one JSON line
on standard output: `roots`, `read` (the roots read from the bucket),
`cached` (the roots folded from the cache), `calls` (the bucket calls it
made), `hosts_event` (the key of the event stored or found present, or
`null`), `failures` (the records created or found present), `waiting`
(the identities still due), `digest` (the key of the summary stored or
found present, or `null`) and `seconds` (the whole cycle). A cycle that
fails prints its error on standard error and no line. Before the failed
call it can have replaced `reports/latest.json`, stored its host event
and saved the open alerts, and created some failure records; no printed
line names those keys, and they stay stored. The first cycle's
`calls` also count the `events/failure-` listing and the day's summary
put, so a check that the cache serves roots reads `read` and `cached`.

Before its first cycle can run, the watch lists `events/failure-` to
learn the known failure identities; a bucket error on that listing is
printed and retried at the next interval, and no failure record is
created before it succeeds. The watch checks the bound of 1,048,576
objects on that first listing. A running watch keeps creating records
after the prefix holds that many, and each later start then exits 2
until the prefix holds at most 1,048,576 objects. To recover, stop the
unit and delete objects under `events/failure-`; the next start records
and announces again each deleted identity that a report still lists.

One cycle runs these steps in order:

1. List `roots/`, then read every host record after the roots, as
   `report` does. Each root whose cache entry matches the listing is
   folded from the cache; every other root is read in the report's order,
   `status.json` first.
2. Fold the report document, with no `--build`.
3. Replace `reports/latest.json` with one put.
4. When at least one alert opened, store one host event. Once the event
   is stored, or when none is due, save the open alerts in the state
   directory. A failed event put ends the cycle after saving the alerts
   that were open and are still shown, so the closures it saw stay saved
   and the alerts that opened stay due.
5. Create up to 16 failure records, lowest id first.
6. Create the summary of the current UTC day when the watch has yet to
   see it stored.

A cycle that fails on a bucket call prints the error, stores nothing
further and runs again at the next interval. The next cycle that
succeeds derives its writes from its own document and day: each alert it
shows that is not in the watch's open set, each identity it lists that is not
known, and that day's summary. Each bucket call ends by the store's
waits, and a cycle has no deadline of its own. Every event is a
create-once put. A failure record or summary put that finds its object
present counts as stored. A host event put that finds its object present
counts as stored only when the object holds this event's bytes; another
event at that second fails the cycle, and a later second stores the
alerts. The watch's bucket writes are puts under `reports/` and
`events/`. The publisher and the sweeping hosts read only the prefixes
the Access table lists for them, so admission, credit and `campaign`
state directories stay independent of the watch. The clock reading taken
at the start of a cycle judges the document's host section, the alerts
and the summary's day; each root is judged at its own reading, as
[the cache](#the-cache) states.

The stored `seconds` covers the cycle from its start to just before the
report put. The printed `seconds` also covers that put and steps 4 to 6:
at most one host event, 16 failure records and one summary. The next
report stores that whole figure as `previous_seconds`; a failed cycle
leaves it as it was. A check of cycle length against the interval reads
the printed `seconds`, or `previous_seconds` when it reads the bucket
alone, which lags the last completed cycle by one report.

### The cache

The cache lives under `cache/` in the state directory and holds root
objects only; host records are read on every cycle, and `report` reads
every object. For each root an entry holds the objects the listing
showed, with their lengths and ETags, and what the report's read of that
root produced. A root is folded from its entry only when the listing
shows the same objects with the same lengths and ETags, every object
with an ETag. A read from the bucket conditions the download of each
object listed with bytes and an ETag on that ETag; a download that finds
the object replaced reads it again with no condition, as `report` does.
An object listed without an ETag, and one listed absent or empty that
holds bytes when asked, is downloaded with no condition. The read enters
the cache only when every call agreed with the listing: each download
matched its listed ETag, no object was gone at its download, and each
object the listing showed absent or empty was still so when asked. An
entry is one file replaced by
a staged write and a rename. Its first line is the SHA-256 of the rest of
the file, the header and the body, and every read checks it, so a cycle
folds a whole entry or none. An entry of another format reads as a miss.
Each cycle starts by removing the files under `cache/` whose names start
with a dot, the staged writes a kill left, and removes every file of a
root the listing no longer shows; a directory under `cache/` stays in
place and is printed. A `cache/` that is a symlink or no directory is
refused for lookups, writes and removals, and a symlinked entry is a
miss. The reserve is 2 GiB and 2 bytes free on the state filesystem,
twice the suspect list's download bound, so the cycle's downloads and
staged puts keep room; a stored report larger than about 1 GiB is
outside that reserve. The cache writes an entry only when the free space
holds the entry's bytes and twice the reserve, 4 GiB and 4 bytes, so a
cache that fills the filesystem stops one reserve above the level that
removes it. A state filesystem with less free space than that stores no
entry: each refused entry prints one line, and its root is read from the
bucket on every cycle. A refusal also removes the entry the root already
had, which the lookup read as a miss, and its bytes become free space for
later entries. Each cycle
removes the `scratch/` an earlier cycle left and lists `roots/`; once
the listing succeeds it reads the free space, and with less than the
reserve free it removes every entry before it creates `scratch/` and
reads a root. The files a killed cycle left in `scratch/` are unlinked
before that reading. A filesystem such as xfs returns an unlinked file's
blocks in the background, shortly after the unlink, and the listing call
gives it that time. The cache keeps its entries when those files alone
held the missing space and their blocks are back by the reading; when
the blocks are still held, the cycle removes the entries and reads every
root from the bucket. When an entry
cannot be read, the cycle reads
that root from the bucket; a failed entry write or removal is printed
and the cycle continues. A root read from the bucket is judged at the
clock reading taken right after its `status.json` download, as `report`
judges it, and a root from the cache at the reading taken when its entry
is folded. The cache holds no judgment that depends on time, so the
document equals one folded from a full read of the same bucket contents
at the same readings.

### Failure records

A failure identity is a profile and a suspect key, across builds. Its
record is `events/failure-<id>.json`, where `<id>` is the SHA-256 of the
profile, a zero byte and the key; this derivation is part of the stored
contract, and a change to it announces every known identity again. The
record holds `format` (1), `id`, and the `build`, `profile`, `key`,
`count`, `roots` and `rerun` of the report group of the lowest build id
that lists the identity in the cycle that creates it. It names the build
by its SHA-256; [running it again](#run-a-stored-suspect-line-again)
reads the revision from the fetched archive.

### Host events

An alert is a host state of `unhealthy`, `silent` or `missing` and an
instance. It opens in the first cycle whose document shows it and closes
in the first that omits it. `events/hosts-<unix seconds>.json` holds
`format`, `written` and `alerts`, each alert that opened in the cycle with
its `flag`, `instance` and the host row's `reasons`. The watch holds the
open alerts in memory and saves them in `alerts.json` once the event is
stored, or when none is due; it reads `alerts.json` at its first
decision after a start. A missing, unreadable or symlinked `alerts.json`
reads as no open alerts, so a lost `alerts.json`, or a watch killed
between the event and the save, stores the alerts still shown once more
after the next start. A save that fails is printed, and the watch then
attempts to unlink the file or symlink at `alerts.json` and sync the
state directory, so a restart stores the alerts still shown once more
instead of trusting an older set; the running watch keeps its open set
and repeats no alert. When that removal fails too, its error is printed
and `alerts.json` can still hold an older set: stop the watch, inspect
the entry and remove it before the next start. `alerts.json` also holds
the second of the last host event stored; a cycle whose clock reads no
later second, as after the clock stepped back, keeps its alerts due
until a later second, so its event key is never one an earlier event
of the saved state took. A put whose call fails after the bucket stored its event, as at a
lost reply or a stop, leaves the alerts unsaved, so a later cycle stores
them again under its own second. An alert still shown in the next cycle
is therefore stored at least once. An alarmed current
root reaches a person through its host's `unhealthy` state, whose reasons
name the alarm.

### The daily summary

`events/digest-<yyyy-mm-dd>.json` holds `format`, `day`, `written`,
`host_counts`, `builds` (each build's totals from the document, without
its `failures`, `findings` and `unkeyed` lists), `failure_identities` (the
count of known identities) and `flags` (the document's flag count by
kind). Every UTC day with a successful cycle has one summary; a restart
on that day finds it present and creates no second one. One watch runs,
so a stopped watch stops the summaries, and a missing summary shows it.

### The watch's state directory

| Path under the watch's `--state` | Holds |
| --- | --- |
| `watch.lock` | the lock one watch holds while it runs |
| `alerts.json` | `{"format": 1, "open": [{"flag", "instance"}], "event"}`: the open alerts and the second of the last host event stored |
| `cache/<sha256 of the campaign>` | one root's cache entry |
| `scratch/` | one cycle's downloads and staged puts |

## State layout

| Path under `--state` | Written by | Holds |
| --- | --- | --- |
| `runner.lock` | runner | the lock one runner holds while it runs |
| `state.json` | runner | `format`, the stored assignment's SHA-256, the current root, and every root this runner created with its name, instance id, nonce, build, counts, confirm slots, stints, failures, CPU sums, alarm, confirmation, `pending` (admitted jobs not yet dispatched), `retry` (a failed sweep's boot id and boot-clock deadline) and `deleting` |
| `assignments/<sha256>.json` | runner | each stored copy of the assignment, with its commit record |
| `health.json` | runner | the health record |
| `logs/sweep.out`, `logs/sweep.err`, `logs/confirm.out`, `logs/confirm.err` | runner | the last child's standard output and error |
| `builds/<build>/archive`, `builds/<build>/campaign`, `builds/<build>/record.json` | runner | a fetched build and its commit record |
| `builds/.fetch-<build>/` | runner | a fetch in progress |
| `uploads/<campaign>/` | runner | the local copy of each of a root's three objects, and `receipt`, the digest of the snapshot whose upload of all three completed |
| `store/` | runner | downloads of `assignment.json` and `current.json` in progress, and the staged copy of the health record an upload reads |
| `roots/<campaign>/` | `campaign` | a sweep root and its `confirm/state` |

The runner replaces `state.json`, each assignment copy, `health.json`
and the local copies by a staged write, sync, rename and parent sync, and
refuses a `state.json` that would pass its 16 MiB read bound. A loaded
`state.json` must name each root by its campaign name, with a valid name,
instance id, nonce and build, and its current root among them, or the
runner does not start. A root recorded without `deleting` loads as not
marked. It writes inside a root only through `campaign`.
The state directory and its `roots`, `logs`, `builds`, `assignments` and
`uploads` directories must belong to `sim` and be writable by no group or
other user, and every existing directory above the state directory must
be a real directory owned by root or `sim` and writable by no group or
other user unless it is sticky. These checks run at start; they constrain
other users, not root or `sim`.

## Health and `status`

`health.json` holds `format`, `written` (Unix seconds), `instance`,
`build`, `root`, `assignment` (the digest), `assignment_error`,
`upload_error`, `fetch_error`, `cleanup_error`, `stint` (the root's stint
count), `stint_seconds`, `phase`, `reason`, `sweep_overdue`, `exits`
(each child's last exit code, 128 plus the signal for a signalled child),
`alarm`, `confirmation` (`idle`, `running`, `backlog`, `held` or
`failed`), `confirmation_reason`, `confirming` (the root whose `confirm`
runs), `confirm_exit_root` (the root of `exits.confirm`), `held_roots`
and `held_root_names` (earlier roots of this instance whose confirmation
is held, at most eight names), `share_stint`, `stint_cpu_usec` and
`stint_capacity_usec`, and the root's running sums `cpu_usec` and
`capacity_usec`. Reasons and errors are cut to 4096 bytes. The phase is
`starting`, `sweeping`, `waiting`, `held`, `full`, `blocked` or
`stopped`. `alarm` and `confirmation` describe the current root. Of an
earlier root the record carries a held confirmation, in `held_roots`. An
earlier root's `failed` or `backlog` confirmation stays in `state.json`,
and its `alarm` in `state.json` and in that root's own totals.

The runner stores the record at `hosts/<instance-id>/health.json`, byte
for byte as the local file holds it, and writes the local record just
before each upload reads it, so the stored `written` is the upload's
start. An upload starts only after that write succeeds: a failed write is
printed to the runner's standard error and retried at each poll, and the
upload starts at the first poll whose write succeeds. Until a stop is
requested, an upload starts at least every half stint length and at least
every 300 seconds, in every phase, paused phases included, while the
runner's 100-millisecond poll runs, the previous upload has ended and the
local record can be written; a snapshot observation, which can take up to
60 seconds, holds the poll. The stored record's age can pass that period
by the time one put takes. With no assignment in force the stint length is
60 seconds.
A change of the stint length in force starts an upload at the next poll,
and until an upload stores the new length, uploads follow the shorter of
it and the length the stored record states, so the stored record states
the stint length that judges its age. Each upload runs on its own thread,
one at a time, so a failing or hung put delays no stint, and the store's
120-second wait or a stop signal ends it. A failed read or upload of the
record is named under `upload_error`, ahead of any store pass error, until
an upload of the record succeeds or a stop begins; a store pass that
succeeds leaves that error in place, and an error polled after the stop
signal leaves the earlier one. The stop clears it before it writes the
`stopped` record, and a failed final put names its own error. The upload
that succeeds after a failure is followed by another at the next poll,
which stores a record that no longer names the failure. At a stop the
record with phase `stopped` is the last one stored, after the final
snapshot upload. A stop whose local write of the `stopped` record fails
makes no final put, so the last stored record stays. A `stopped` record
can carry the `reason` of an earlier pause, because the runner clears
`reason` only when a sweep starts.

`sweep_overdue` is true while the running sweep has lasted longer than
the assignment's `stint` plus its `wall` plus 300 seconds on the runner's
monotonic clock, and false otherwise; the runner computes it at each
write of the record. The record of a runner that cannot start holds
`null` there. A sweep ends its stint after `stint` seconds, each worker
then finishes a run of at most `wall` seconds, and the 300 seconds are the
allowance for the sweep's other work: its two archive verifications, its
reads of the worker's listing and rule catalog, its workers' exit wait
and its last write of `sweep.json`. The runner keeps waiting for an
overdue sweep and keeps replacing the health record, so the record stays
fresh and marks the current root's sweep overdue.

A stint's CPU share is the change in `usage_usec` of `campaign/sweep/`
over the stint, divided by online CPUs times the stint's wall time:
`stint_cpu_usec / stint_capacity_usec`, measured in stint `share_stint`
of the current root. The share includes worker start-up and the sweep
controller. A group that does not exist before the sweep starts counts
from 0. A counter that cannot be read, or reads lower after the stint
than before, leaves the stint unmeasured: its fields are absent and the
root's sums skip it. A failed sweep adds to the sums and publishes no
stint share. The root's share is `cpu_usec / capacity_usec` over the
stints whose exit the runner recorded; a stint that a kill of the runner
interrupted is in neither sum.

Each worker has one CPU, so the workers' part of a stint's share is at
most `workers / online CPUs`, and the sweep controller's CPU time adds to
it. With the unit's 1 confirm slot and 0 system cores a host has
`online CPUs - 2` workers: on 32 CPUs the 30 workers bound their part at
0.9375. With the command-line defaults of 8 confirm slots and 4 system
cores a host has `online CPUs - 13` workers: on 96 CPUs the 83 workers
bound their part at about 0.865, and it reaches 0.9 from 130 online CPUs. `check` accepts a
partition below that, and `status` then exits 1 for each measured stint
below 0.9 while the host sweeps at its partition's limit.

`sim-host status --state DIR` prints the record with `share`,
`root_share`, `stale`, `verdict` and `reasons` added. A missing field
prints `unknown`; an error field with no error prints `null`. With no readable record it prints only `error` and
`verdict: unknown`.

| Exit | When |
| --- | --- |
| 2 | `format` is not 1, `alarm` is set, `sweep_overdue` is set, the phase is `waiting`, `held`, `full`, `blocked`, `stopped`, missing or unrecognized, confirmation is `held` or an unrecognized value, a record that names a root lacks `alarm` or `confirmation`, `held_roots` is above 0, the record is older than two stint lengths, its age is unknown or in the future, or its stint length is outside 1 to 4294967295, or no record reads |
| 1 | confirmation is `backlog` or `failed`, the stint's share is below 0.9, or an assignment, upload, fetch or cleanup error is recorded |
| 0 | otherwise |

## `check`

`sim-host check --bucket NAME [--cgroup DIR] [--confirm-slots N] [--system-cores N] [--system-memory BYTES]`
takes a `--cgroup` that is an absolute path without `..` and that passes
through no symlink, as `run` does, and
reads only `assignment.json` from the bucket, into a new private
directory under the temporary directory that it removes, prints the
partition, and exits 2 when any of these holds, 0 otherwise:

- the host has no instance id;
- the worker count is not 1 to 1024;
- the process's CPU affinity holds fewer CPUs than are online, which the
  partition takes in full;
- the workers' memory, 2 GiB for each confirm slot, 2 GiB for
  confirmation's one triage slot, and `--system-memory` (default 4 GiB)
  for the system, the runner and the controllers pass `MemTotal`;
- the unit's cgroup lacks a delegated `cpu`, `memory` or `pids`
  controller, or this user may not write the unit's cgroup, its
  `cgroup.procs` or its `cgroup.subtree_control`;
- the unit's cgroup or an ancestor sets `cpu.max` or `memory.max`.

The unit keeps the `--system-memory` default; the
[measured partition](#measured-partition) records no system memory
figure. `check` exits 2 as well when the assignment, the cgroup, the
affinity mask or `MemTotal` cannot be read.

## Fuzz host

A fuzz host runs `campaign fuzz` on the archived worker's `campaign`
fuzz target around the clock, as
[the supervisor README](../../crates/campaign-supervisor/README.md#fuzz-the-archived-worker)
describes the command. It is one dedicated host outside the sweeping host
set. It is an aarch64 instance with Neoverse V2 cores, the production
architecture, on an aarch64 machine image of its own, and it runs only
the archive it builds: an archive pins the host's program interpreter by
digest. Of the [host contract](#host-contract) it meets the kernel,
cgroup-v2, systemd and filesystem items. It reads no instance id and
reads and writes no bucket object, so it needs no `aws` CLI and no role.
Its findings stay on the host and are lost with it, which is accepted
while an operator reads `fuzz-status` daily.

Prepare the host once, as root unless a step says otherwise:

1. Create the user and its directories on the xfs or ext4 mount. Every
   path below holds only the bytes `A-Za-z0-9/._=,-`, because libFuzzer
   passes the root and archive paths to a shell when it merges the
   corpus, and `campaign fuzz` refuses another byte. Give a separate
   data volume an `/etc/fstab` entry or a mount unit; `nofail` serves.
   The unit waits for the mounts of `/data/fuzz` that systemd has a unit
   for:

   ```sh
   useradd --system --create-home fuzz
   install -d -o fuzz -g fuzz -m 0700 /data/fuzz /data/fuzz-src
   ```

2. Build and install the pinned native SPDK under `/usr/local`; the
   worker links it. The archive build accepts only an install whose
   header digest equals the one in
   `crates/spdk-sys/src/generated/installs/aarch64-unknown-linux-gnu-neoverse-v2`,
   which was taken from an install configured with
   `--prefix=/usr/local`. The installed `rte_build_config.h` holds the
   prefix, so an install under another prefix has another digest, and
   step 3's archive build then fails and names that digest and the
   record. `native/install.sh build` takes only a prefix that is absent
   or empty, which `/usr/local` is not, so build from the SPDK tree with
   the `configure`, `make` and `make install` commands under
   "Prerequisite install" in `crates/spdk-sys/src/lib.rs`, at the SPDK
   and DPDK commits that section names. Step 3 sets no
   `SPDK_PKG_CONFIG_PATH`, and with the variable unset the archive build
   reads `/usr/local/lib/pkgconfig`.
3. As `fuzz`, install the pinned stable and nightly Rust toolchains,
   check out the revision to fuzz into `/data/fuzz-src`, leave it clean,
   and build `campaign` and the instrumented archive. The archive build
   keeps the flags of `campaign_fuzz` in `scripts/rust-lane.sh`,
   AddressSanitizer with coverage counters, and adds two for this host.
   `-C target-feature=+lse` compiles atomic operations to the LSE
   instructions of the host's cores. `-Clink-arg=-Wl,-z,start-stop-gc`
   lets GNU `ld` drop libFuzzer's unused entry point; a link that keeps
   it fails on the undefined `rust_fuzzer_test_input`. `RUSTFLAGS`
   replaces the flags a Cargo configuration file sets, so every flag is
   named here. Compare the flags through `-Cdebug-assertions` with the
   lane script before each build:

   ```sh
   # as fuzz, in /data/fuzz-src
   STABLE=$(sed -n 's/^ *STABLE: "\(.*\)"$/\1/p' \
     .github/workflows/agent-checks.yml)
   NIGHTLY=$(sed -n 's/^ *NIGHTLY: "\(.*\)"$/\1/p' \
     .github/workflows/agent-checks.yml)
   RUSTUP_TOOLCHAIN="${STABLE:?}" cargo build --release -p campaign-supervisor
   FLAGS="-Zsanitizer=address -Cpasses=sancov-module"
   FLAGS="$FLAGS -Cllvm-args=-sanitizer-coverage-level=4"
   FLAGS="$FLAGS -Cllvm-args=-sanitizer-coverage-inline-8bit-counters"
   FLAGS="$FLAGS -Cllvm-args=-sanitizer-coverage-pc-table"
   FLAGS="$FLAGS -Cllvm-args=-sanitizer-coverage-trace-compares"
   FLAGS="$FLAGS -Cdebug-assertions -C target-feature=+lse"
   FLAGS="$FLAGS -Clink-arg=-Wl,-z,start-stop-gc"
   RUSTUP_TOOLCHAIN="${NIGHTLY:?}" CARGO_PROFILE_DEV_OPT_LEVEL=3 \
     RUSTFLAGS="$FLAGS" \
     target/release/campaign sim archive --output /data/fuzz/archive
   # as root
   install -m 0755 /data/fuzz-src/target/release/campaign /usr/local/bin/
   ```

   `STABLE` and `NIGHTLY` are the workflow's pins at the checked-out
   revision, the toolchains to install: the block builds `campaign` with
   the first and the archive with the second. With no target set the
   archive build binds the host's own triple,
   `aarch64-unknown-linux-gnu`. `sim archive` exits 0 once the archive
   is written and verified.
4. Install the unit and read back what systemd loaded:

   ```sh
   install -m 0644 /data/fuzz-src/crates/sim-host/campaign-fuzz.service \
     /etc/systemd/system/
   systemctl daemon-reload
   systemctl show campaign-fuzz.service -p Restart -p RestartUSec \
     -p RestartPreventExitStatus -p RequiresMountsFor -p TimeoutStopUSec
   ```

   The readback shows `on-success`, 30 seconds, the four signals,
   `/data/fuzz` and a stop timeout above the supervisor's 180 seconds
   of grace. It shows the loaded values and exercises none of them.
5. Run three one-hour runs, as root, one after another on the root,
   before the unit's first start on an archive whose nightly or
   `libfuzzer-sys` has no such runs on the host. One run holds the root,
   so `campaign-fuzz.service` stays stopped through them. Each takes the
   installed unit's shell line with `--for 3600` and runs it in a
   transient unit with the unit's user, mount, delegation and stop
   settings:

   ```sh
   LINE=$(sed -n "/^ExecStart=/{s|^ExecStart=/bin/sh -c '\(.*\)'\$|\1|
     s|--for [0-9]* |--for 3600 |p}" /etc/systemd/system/campaign-fuzz.service)
   [ -n "$LINE" ] && systemd-run --wait --collect --unit campaign-fuzz-hour \
     --uid fuzz --gid fuzz -p RequiresMountsFor=/data/fuzz \
     -p 'Delegate=cpu memory pids' -p KillMode=mixed \
     -p TimeoutStopSec=300 -p LimitNOFILE=65536 -p TasksMax=infinity \
     /bin/sh -c "$LINE"
   ```

   `systemd-run` exits with the command's code. The run's number `N` is
   `next` in the `fuzz-status` read before it. On a root that holds no
   fuzz run, that read exits 2 with `the root holds no fuzz run`, and
   `N` is 0. From a second shell, read worker 0's last `ft` three times
   while the run goes: once `runs/N/w0.stderr` is 2 minutes old and
   holds libFuzzer's `INITED` line, which ends its load of a kept
   corpus, again when the file is 20 minutes old, and again near the
   run's end:

   ```sh
   grep -o ' ft: [0-9]*' /data/fuzz/root/runs/N/w0.stderr | tail -n 1
   ```

   The runs pass when each exits 0, its `run.json` holds `ending`
   `deadline`, and its last `ft` is above its first. Repeat a run whose
   worker 0 failed, since its replacement writes another file. Keep the
   nine values with the nightly and the `libfuzzer-sys` version they
   belong to.
6. Start the unit once by hand:

   ```sh
   campaign fuzz-status --root /data/fuzz/root
   systemctl start campaign-fuzz.service
   ```

   Enable the unit, with `systemctl enable campaign-fuzz.service`, only
   after one run started by it ended with exit 0, caught its control and
   adopted its merge. The run's number `N` is `next` in the
   `fuzz-status` read before the start, and 0 on a root that holds no
   fuzz run, as in step 5. The run passed when `runs/N/run.json`
   holds `ending` `deadline`, `archive` null and `merge.adopted` true and
   the unit then starts run `N+1`: `deadline` is the ending of a run
   whose control was caught, and the unit starts a next run 30 seconds
   after an exit 0 alone. The merge's time is measured on one-hour runs,
   and this check is the first four-hour corpus under its bound. Enable
   the unit only for the pinned nightly and `libfuzzer-sys` whose three
   one-hour runs on the host, the first measured runs or step 5's,
   showed libFuzzer's `ft` still rising after 120 seconds. A change of
   the workflow's `NIGHTLY` or of `libfuzzer-sys` in
   `crates/kestrike/Cargo.toml` repeats step 5 before the unit starts
   on the new archive.

`crates/sim-host/campaign-fuzz.service` runs
`campaign fuzz --root /data/fuzz/root --archive /data/fuzz/archive --for
14400 --workers 8` as `fuzz`, once `/data/fuzz` is mounted.
`Delegate=cpu memory pids` hands the unit's cgroup to the command.
Controllers are enabled for a cgroup's children only while the cgroup
itself holds no process, and the command takes a cgroup root of its own,
so the unit's shell line moves itself into a `command/` child, enables
the three controllers for the unit cgroup's children and passes the
sibling `campaign/` as `--cgroup-root`. `KillMode=mixed` sends the stop
signal to the command alone, which passes it to its workers and adopts no
merge. A stopped run that closes without error exits 0; a control
already missed still exits 1, and a failed closing check or write exits
4. The command kills a worker that still runs 180 seconds after the
stop, and `TimeoutStopSec=300` is the budget for that grace and the
closing writes; a longer grace in the supervisor moves the unit's value
with it. `Restart=on-success` with
`RestartPreventExitStatus=` starts the next run 30 seconds after an exit
0 and after no other end: a missed control (1), a refusal (2), a busy
root (3), a held record (4) and a death by signal stop the unit and stay
visible in `systemctl status`. The shell line itself fails with 1 or 2
when a cgroup write fails; such an exit leaves no new `runs/N/`, and
`journalctl -u campaign-fuzz` holds its message. After an exit 1 of the
command, `alarm` stays set in that root: explain the miss first, then
start a new root with the old corpus, as for a full key table below.
Every later start on that root, a boot's included, exits 4 and leaves
`control/`, which holds the missed control's files, as that run stored
it.

To follow `main`, stop the unit, build a new archive at a new path and
reinstall `campaign` from the same checkout, rename `/data/fuzz/archive`
to a path named for its build digest and put the new one in its place.
Compare the installed unit with that revision's
`crates/sim-host/campaign-fuzz.service`, carry the host's own values,
such as `--workers`, into the new unit, run `systemctl daemon-reload`
and read the unit back as in step 4. When the new revision changes the
workflow's `NIGHTLY` or `libfuzzer-sys` in
`crates/kestrike/Cargo.toml`, repeat step 5's three one-hour runs
before the start. Take `N` from `next` in `fuzz-status`, then start the
unit; the corpus carries over. Keep each old archive until the findings
of its build are triaged, since a finding reruns on the archive that
`record.json` names. The new archive passed when `runs/N/run.json`
holds a `build` equal to the SHA-256 of the new archive's `build` file,
`ending` `deadline`, `archive` null and `merge.adopted` true.

Size the workers by cores, memory and the state volume. Each worker runs
in a cgroup with a ceiling of one CPU and `--memory` bytes, 8 GiB by
default, so keep the worker count at or below the host's cores and the
workers' summed limits below the host's memory: 8 workers take 64 GiB of
limit. `campaign fuzz` checks that sum against the cgroup limits above
its root alone, and the unit sets none. The first runs on an
r8gb.4xlarge instance (16 Neoverse V2 cores, 128 GiB nominal, 123 GiB
reported) measured 8 workers of the AddressSanitizer build, and the
largest pen peak over three one-hour runs was 718 MiB, so the unit
keeps that count and the default limit. More workers add corpus files,
and one worker with one CPU merges them within 1,800 seconds, so the
first run at another count passes step 6's merge check before the
count stays. A root keeps 16 run directories,
and the command kills a worker or a merge whose output file it finds
past 64 MiB. It reads the sizes every 100 ms, so a file can end larger
than that. A run starts at most 15 replacement workers, each with an
output file of its own, so budget `N + 16` GiB of run output for a root
with `N` workers. Keep free space above that budget for the corpus, a
merge's second copy of it, each kept run's merge control file, 1.2 MB
in the first runs and larger with the corpus, the failure directories,
each with a rerun's output under the same threshold, and every retired
root, hand merge directory and old archive.
The three first runs of one hour with 8 workers left a root of 9 MB.

Read the root every day, and keep each day's output to compare with the
next:

```sh
campaign fuzz-status --root /data/fuzz/root
systemctl status campaign-fuzz.service
df -h /data/fuzz
```

`alarm`, a rise in `control.missed`, a new key or a risen count in
`keys`, a `failed_merges` above 0, a `run.json` written since the last
read whose `ending` is other than `deadline` or whose `merge.adopted` is
other than true, and a unit that is not running each need a look. The
newest `runs/N/` of a running unit holds no `run.json` yet. For a merge
left unadopted, `merge.cause` in `run.json` and `runs/N/merge.stderr`
give the cause. A run that 16 failed workers ended exits 0, so the unit
keeps restarting through such runs and only the counts and the ending
show them. Triage a new key as
[the simulation guide](simulation.md#triage-a-fuzz-finding) says. When
the unit has stopped, the command's last message in
`journalctl -u campaign-fuzz.service` names the cause: a root that holds
a failure past its keys, or whose planted control was missed, takes the
new root below, a corpus past the
files a run starts from takes the manual merge below, and
[the exit table](../../crates/campaign-supervisor/README.md#findings)
covers the rest. A death by signal and a failed mount dependency leave
no message of the command: `systemctl status` names the signal on its
main process line, and the journal holds systemd's `Dependency failed`
line. Save the status output before the next start replaces it.

A root whose key table is full, or whose `alarm` is set, exits 4 at
every start. As root, stop
the unit with `systemctl disable --now campaign-fuzz.service`, so that
a boot starts no run on a root without its corpus. After the move,
start it with `systemctl start campaign-fuzz.service`, and enable it
again only when it was enabled before. Between the two, as `fuzz`,
start a new root with the old corpus and keep the old root as the
record, under a name that no earlier root has:

```sh
# as fuzz, with the unit stopped
cd /data/fuzz
OLD=root-$(date -u +%Y%m%dT%H%M%SZ)
mv -T root "$OLD" && mkdir -m 0700 root &&
  mv -T "$OLD/corpus" root/corpus && sync . root "$OLD"
```

The block ends with a sync of the three directories it changed, so
start the unit only after it exits 0. When the block stopped early,
finish it from the same `$OLD`: make `root` when it is absent, run the
last rename when `$OLD/corpus` still exists, then run the sync.

A run refuses a corpus past 65,536 files with exit 4, before the one step
that shrinks it. A merge that runs past 1,800 seconds is killed and
leaves the corpus as it was, and `merge.cause` in `run.json` names the
time bound. Merge either corpus by hand, as `fuzz`, with the unit
stopped and disabled as above, and start it as above after the
replacement. A hand merge has no time bound. The
merges of the first runs read 9 to 18 files a second, one to two hours
for 65,536 files at those rates, so run it in a session that outlives a
logout, such as `tmux`. Of the three limit flags, `-max_len` and
`-timeout` are `LIMITS` and `-rss_limit_mb` is `rss_limit_mb` of the
default `--memory`, in
`crates/campaign-supervisor/src/campaign/seeds/fuzz.rs` at the installed
revision; compare them first. A hand merge reads the corpus alone, and
the next run writes the worker's seeds again. Each attempt takes a
directory of its own, which holds its output, its artifacts, its control
file, its log, its exit status and the digest of the archive's build:

```sh
# as fuzz, with the unit stopped
cd /data/fuzz
M=merge-$(date -u +%Y%m%dT%H%M%SZ)
mkdir "$M" "$M/merged" "$M/artifacts" &&
  sha256sum < archive/build > "$M/build" &&
  { env -i LD_LIBRARY_PATH=/data/fuzz/archive/lib \
    /data/fuzz/archive/worker --fuzz campaign \
    --artifacts "/data/fuzz/$M/artifacts" -- -merge=1 \
    "-merge_control_file=/data/fuzz/$M/merge.txt" -max_len=65536 \
    -timeout=60 -rss_limit_mb=6144 \
    "-artifact_prefix=/data/fuzz/$M/artifacts/" \
    "/data/fuzz/$M/merged" /data/fuzz/root/corpus > "$M/log" 2>&1
    echo $? > "$M/status"; }
```

A merge exits 0 even when every inner process failed, and it prints its
success line before it writes `merged/`. Replace the corpus only when
the attempt's status is 0, its log holds the success line, and `merged/`
holds exactly the files the log counts, 1 to 65,536 regular files and no
other entry, each named by the SHA-1 of its bytes as libFuzzer names it.
The block counts the files whose whole name is the SHA-1 of their bytes,
so a file that it cannot read fails the check, and it moves nothing when
a check fails:

```sh
N=$(sed -n 's/^MERGE-OUTER: \([0-9]*\) new files.*/\1/p' "$M/log")
[ "$(cat "$M/status")" = 0 ] &&
  grep -q 'MERGE-OUTER: successful in' "$M/log" &&
  [ "$N" -ge 1 ] && [ "$N" -le 65536 ] &&
  [ "$(find "$M/merged" -mindepth 1 -maxdepth 1 -type f | wc -l)" = "$N" ] &&
  [ -z "$(find "$M/merged" -mindepth 1 ! -type f)" ] &&
  [ "$(cd "$M/merged" && find . -type f -exec sha1sum {} + |
    awk '$0 == $1 "  ./" $1' | wc -l)" = "$N" ] &&
  sync -f "$M/merged" &&
  mv -T root/corpus "$M/corpus-before" && mv -T "$M/merged" root/corpus &&
  sync root "$M"
```

As the run's own swap does, the block syncs the filesystem that holds
`merged/` before the first rename, so the merged files are durable
before a rename publishes them, and it syncs the two directories the
renames changed, `root` and `$M`, after the second. After either recovery
below, run `sync root "$M"` before restarting the unit. If the rename
already restored the corpus, run just the sync. Keep the unit stopped
until the sync succeeds.

When the first rename ran alone the root holds no corpus, and a start
of the unit makes a new one, which its workers fill. With the unit
stopped, `mv -T "$M/corpus-before" root/corpus` puts the corpus back
over an absent or empty `root/corpus`; move a `root/corpus` that holds
files to `$M/corpus-started` first. To undo a replacement, with the
unit stopped:

```sh
[ -d "$M/corpus-before" ] && [ ! -e "$M/merged-undone" ] &&
  mv -T root/corpus "$M/merged-undone" &&
  mv -T "$M/corpus-before" root/corpus && sync root "$M"
```

When the undo's first rename ran alone,
`mv -T "$M/merged-undone" root/corpus` puts the merged corpus back. An
undo after a run of the unit leaves that run's new inputs in
`merged-undone`. The undo lasts while `corpus-before` exists: keep it
until the first run of the unit that started after the replacement has
written a `run.json` with a `corpus.before` equal to `N`, which shows it
started from the merged corpus, and that run or a later one has written
a `run.json` with `ending` `deadline`. A later run starts from the
corpus the earlier runs changed, so only the first run's
`corpus.before` shows the merged corpus.

A file in `$M/artifacts` is an input that ended an inner process, and
the merge passed over it: `first-failure.*` holds the worker's record of
the first, and each file that libFuzzer wrote, such as a `crash-`,
`timeout-` or `oom-` file, is one such input. An attempt count above 1
in the success line is a reason to look there. Such a file is a failure
that no run of the unit files, so keep `$M` as its record and keep the
archive until it is triaged. Triage each input from step 2 of
[the simulation guide](simulation.md#triage-a-fuzz-finding) with these
in place of a failure directory: the input file for `input`,
`first-failure.claim` and `first-failure.bundle` for the first input's
`claim` and `bundle`, `log` for `stderr.tail`, and the digest alone,
`BUILD=$(cut -d' ' -f1 "$M/build")`, for the one step 2 reads from
`record.json`: `build` holds the digest followed by two spaces and `-`,
as `sha256sum` prints it. A kept input has no key and no stored
rerun result. Remove `$M` once `corpus-before` is done with and
`artifacts` is empty or triaged.

## Tests

`cargo test -p sim-host` runs the unit tests and the `host` target, which
drives the `sim-host` binary against fake `campaign`, `aws`, `git` and
`cargo` binaries, the system `tar`, a directory in place of the bucket, a
loopback metadata service and a directory tree in place of the cgroup.
The one-host run of the pinned image and the two-host check are the
end-to-end checks.
