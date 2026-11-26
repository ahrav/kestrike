# Zone reconciler service

Read this before you deploy, configure or run the zone reconciler service,
or change `crates/kestrike-reconciler`. The service runs one zone's
reconciler loop. It observes and plans: it reads the store and the EC2
control plane, and it writes no store record and makes no mutating provider
call.

## Commands

Each command takes one argument, the absolute path of the configuration
file:

```sh
kestrike-reconciler init --config /etc/kestrike-reconciler/config.json
kestrike-reconciler run --config /etc/kestrike-reconciler/config.json
```

- `init` validates the configuration and every file it names, creates the
  state directory with mode 0700 when it is absent (its parent must exist),
  syncs the directory's parent, takes the directory's lock and records the
  empty store watermark. It runs once per state directory: a directory that
  already holds a watermark is refused, so a watermark the service raised is
  never reset. A directory that holds no watermark but another entry is
  refused too (a `watermark.tmp` left by an interrupted `init` aside). The
  entry can be a status file of an earlier run whose watermark was lost, and
  `init` cannot tell that from an entry that was there before the service,
  such as a file system root's `lost+found`.
- `run` validates the same files, takes the state directory's lock, loads
  the recorded watermark before it sends any request, opens the store
  client over it, and starts a tick at most once per `tick_us`. Each tick
  rereads the directory file, surveys the zone with `ZoneLoop::tick`,
  replaces the status files in the state directory and then prints one
  status line on standard output ([Status output](#status-output)).
  SIGTERM or SIGINT ends the run after the tick in progress with exit 0; a
  stop that arrives before a tick starts ends the run before that tick. A
  tick after which the store client reads withdrawn ends it with exit 3. A
  directory file that fails a check during a run, or names another zone,
  leaves that tick's shards `Unobserved` and names the failed check on
  standard error. The loop admits a reread directory when it repeats the
  one it last admitted, with the same listing (hosts, shards, `zone_hold`
  and `host_roles_max`) and the same report keys at the same `version`, or
  its successor: a higher `version` that keeps every host it listed, with
  its instance and zone, and every retired host retired. A report key edit
  at the same `version` is therefore refused like a listing edit; at a
  higher `version` it is admitted, and the loop forgets the report state of
  each host whose key changed. Otherwise the tick reads `Unobserved` with
  source `Succession`, reads no store record, and names the refusal on
  standard error by its check, and its host where it has one, as
  `refused by succession (Version)` or
  `refused by succession (Departed(Host(13)))`. The loop keeps the
  directory it last admitted, so every later tick is refused the same way
  until the file is one the loop admits. Raise
  `version` with every edit; a restart starts the chain again from the file
  on disk.

Each command checks the configuration file, then the directory file, then
the zone values, then the status key file, then that the zone name extends
the region's name, and stops at the first failed check, which the error
message names. Every input file must be a regular file that belongs to root
or to the service's user and that neither its group nor others may write.
The checks read the opened file; protect the directories above it so that
only root or the service's user can replace an entry.

### Tick timing

The loop reads `CLOCK_BOOTTIME`, which counts the time the host spends
suspended, for each tick's time and for its sleep, so a suspend reads as
elapsed time and a gap of more than `LISTING_GAP_TICKS` (2) tick periods
restarts the zone's dwells and error runs, as
`crates/kestrike/src/failover/zone_loop/evidence.rs` states. `tick_us`
is the least spacing between tick starts: a tick runs its reads in series,
two EC2 listings of up to 10 s each and store reads of up to 1 s each for
every shard, so a large zone or a slow endpoint makes a tick longer than
`tick_us`, and the next tick then starts at once. A tick that takes longer
than `tick_us` is named on standard error with its duration, the same
duration its `status.json` reads as `ended_us - observed_us` with
`overran` true. A tick that starts more than two tick periods after the
previous one is named on standard error with the time between the two
starts; its `overran` follows its own duration. No deadline bounds a whole
tick, so `TimeoutStopSec` bounds a stop only for a zone whose tick fits
within it.

The run writes its lines to standard output and standard error in the
loop's thread. A reader that stops draining either stream stalls the loop
until the stream drains or systemd ends the process at `TimeoutStopSec`;
under the unit the streams go to the journal.

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | `init` recorded the watermark, or `run` stopped on SIGTERM or SIGINT after its tick in progress. |
| 1 | The store table failed to open (its `DescribeTable` call failed, returned an error or an unusable reply, or the table client's draw from the operating system's entropy failed), the signal handlers failed to install, the boot clock failed to read, or the status writer's draw from the operating system's entropy failed. A boot clock that fails to read at the end of the withdrawing tick is named on standard error and the run exits 3. |
| 2 | The command line, the configuration or a file it names failed a check, or the zone name does not extend the region's name. |
| 3 | The store client withdrew (`ClientWithdrawn`) under its alarm: `Regression` (a record's version or value fell below its mark, or a marked record was absent), `Checkpoint` (at the adopted checkpoint's generation, a shard record named no checkpoint, an earlier `(session, capture)`, or the adopted `(session, capture)` with another slot or unit count), `Log` (the watermark failed to record, or a batch unwound) or `Namespace` (a record named another store instance). Inspect the store before a restart; the watermark keeps the marks the client raised. |
| 4 | The state directory failed a check, another process holds its lock, it holds no watermark (`run`), already holds one or holds another entry without one (`init`), the recorded watermark failed to reload, or a status failed to publish into it on a tick after which the store client reads admitted. A publish that fails on the withdrawing tick is named on standard error and the run exits 3. |

## Configuration file

One JSON object, `"format": 1`. An unknown field is refused by name, and
so is a `null` in place of any field's value.

| Field | Meaning |
| --- | --- |
| `state` | The state directory, an absolute path. |
| `region` | The AWS region the store and EC2 clients sign for, such as `us-east-1`. |
| `table` | The store's DynamoDB table name. |
| `pages` | The most pages one zone listing reads per describe action, 1 to 65535. It must cover every volume and instance the account holds in the zone. The volume listing asks for at most 100 volumes a page and EC2 may return fewer, so the zone's volume count divided by 100 is a lower bound. Every page of one listing also shares EC2's 10 s deadline for that read: the volume listing spends one deadline on the pages of both `DescribeVolumes` and `DescribeVolumeStatus`, and the instance listing has its own. A listing whose pages do not arrive within its deadline leaves its source out of `complete` on that tick, whatever `pages` is. |
| `writer` | The nonzero host number the reconciler status names as its writer. |
| `status_key` | The absolute path of the status key file. |
| `zone`, `name` | The zone's number and its EC2 availability-zone name, such as `us-east-1a`. |
| `directory` | The absolute path of the fleet directory file. |
| `report_period_us` | The host report producers' sealing period. |
| `owner` | The owners' serving bounds: `registrant_max`, `retry_max`, `window`, `report_deadline`, `report_period`, `clock_error`. |
| `replacement` | The replacement volume layout: `units`, `slots`, `slot_units`, `entries`. |

Every other field of `ZoneConfig` in
`crates/kestrike/src/failover/zone_loop/config.rs` may be given under its
own name (`tick_us`, `loss_ticks`, `host_hold` as
`{"numerator": 1, "denominator": 4}`, and so on). An absent field takes the
owner default the constant of the same name states, and an absent
`population_cap` is the directory's shard count when the service starts.
`calls_per_tick` must be above `enroll_inflight_max` (the defaults are 8
and 4), so that the enrollments' attach requests leave a call of every tick
to the detaches and to a volume replacement; the service refuses to start
otherwise, with `zone configuration refused: Calls`.
The service reads the configuration file and the status key file once, at
its start: a change to either takes effect at the next start. A directory
change the loop admits applies at the next tick, a shard it adds included,
while an absent `population_cap` keeps the shard count of the directory read
at the start until the next start; the census admits no more members than
that cap, and the status's `cap_below` reports a shard count above it.

## Directory file

One JSON object, `"format": 1`, private to the service's user (owner-only
permissions), since it holds keys. It lists `version`, `zone`, `zone_hold`,
`host_roles_max`, `hosts` (`host`, `instance`, `zone`, `partition`,
`color`, `state` as `active`, `draining` or `retired`), `shards` (`shard`,
`layout`) and `report_keys` (`host`, `key` as 64 lowercase hexadecimal
digits): the report key of every listed host and no other kind of key. Its
`zone` must be the configuration's. The directory checks of
`zone_loop::directory` apply. An error about the file quotes none of its
text: a parse error names the line and column, and for a missing or repeated
field its name, so an unknown field is refused by its line and column; a
value error names the field and its host or shard number.

Replace the file whole: write a new file with mode 0600, owned by the
service's user, and rename it over the old one, so no reader sees it half
written.

## Status key file

64 lowercase hexadecimal digits, optionally followed by a newline: the
reconciler key, from which the service derives the key that seals its
status records. The file is private to the service's user.

## State directory

The state directory belongs to the service's user with mode 0700. `init`
creates it when its parent exists and the user may write there; otherwise
create it first, for example
`install -d -o kestrike-reconciler -g kestrike-reconciler -m 0700 /var/lib/kestrike-reconciler`.
Each command holds an exclusive `flock` on it while it runs, so a second
process on the same directory exits 4. It holds `watermark`, the store
client's durable watermark, which only `init` creates. Each command reaches
the files through the directory it opened and locked, so renaming the
configured path while a command runs leaves it working in the locked
directory.

Give `init` an empty directory. The root of an ext4 file system holds
`lost+found`, so on a volume mounted for the service use a subdirectory of
the mount point as the state directory. The configured path names the
directory itself: a symlink there is refused, with or without a trailing
`/`.

Keep the directory on a read-write xfs mount or a journaled ext4 mount
(`data=ordered` or `data=journal`, barriers on), whose syncs make a renamed
file and its directory entry durable; the service checks the mount type at
no point. A state directory that has run before and lost its `watermark` has
lost the floor the store client checks reads against. The client takes its
floor from the `watermark` file it finds at its start, so restore a copy that
holds every raise the service made, such as one taken after the service last
stopped. A copy older than the last raise lowers the floor to the copy's
marks, and the client then accepts a store that has gone back to any version
at or above them. When no copy is known to hold every raise, keep the service
stopped: starting it over an older copy accepts that regression. `init`
refuses a directory that holds other entries, since a run over an empty
watermark accepts a store that has gone back to any version.

## Status output

Each tick replaces two files in the state directory, each by a rename,
and then prints one line of `key=value` fields: `tick`, `zone`,
`shards`, `states` and `blockers` (each name with its shard count, or
`-`), `census` (`-` when unread), `cap`, `inflight` (`unread` when the
census was unread), `holds` (the holds that apply),
`complete` (the sources that answered in full) and `client` (`Admitted`,
or `ClientWithdrawn(<alarm>)`). A line reports that its tick's publish
completed; it is no handle on the files. The two paths always hold the
latest tick's files, so a later tick can replace either file before a
reader opens it. A reader that pairs the two requires the document's
`tick` to equal the sealed zone part's `tick` and its `observed_at_us` to
equal the seal's `sealed_at_us`. A tick stamps its seal with the wall-clock
reading in its document's `observed_at_us`, and two runs' readings differ
unless the wall clock stepped back to the same microsecond between them.
Tick numbers repeat across runs: each run counts from 1. A publish replaces
`status.sealed` and then `status.json`, so a new run's first seal stands
beside the previous run's last document between those two renames, and
after a crash or a failure between them until a later publish replaces
`status.json`; both read `tick` 1 when that document is the previous
run's first. When the wall
clock steps back during a run, the seal carries the run's previous stamp,
and each pair reads unmatched until the clock reaches that stamp. A tick
whose publish fails prints no line. The files stay after the run ends, so
`Admitted` in an old document describes the client at that tick: judge
liveness by whether new statuses keep arriving.

Each tick stages and syncs both files while the previous ones stay in
place, then replaces `status.sealed` (or removes it for a tick whose seal
failed), syncs the directory, replaces `status.json` and syncs the
directory again, all before the line prints. A sealed status in the
directory is therefore the same tick as `status.json` or a newer one, on a
running host and after a host crash. A failure while staging leaves the
previous tick's files in place.

The state directory is private to the service's user, so under the unit
only that user and root can open the files. A verifier that checks
`status.sealed` needs a copy of the file and the derived status key, and
neither the state directory nor the reconciler key.

The files:

- `status.json`, `"format": 2`: the tick's `ZoneStatus`. Per zone: `zone`
  (the zone's number), `tick`,
  `started_us` (the run's first tick), `observed_us` (the tick's start)
  and `ended_us` (the tick's end, read after its survey and seal) on the
  loop's clock, `overran` (true when `ended_us - observed_us` is above
  `tick_us`), `observed_at_us` (the tick's start) on the wall clock,
  `directory_version` (the directory the tick admitted, `null` when it
  admitted none), `census` (the census length, `null` when unread), `cap`,
  `cap_below`, `inflight` (the in-flight count, `null` when the census was
  unread), `holds`, `verdicts` (`live`, `lost`, `conflict` and `unknown`
  host counts, `null` when the tick admitted no directory and so formed no
  host verdicts), `complete`, `unnamed_volumes` (the count of listed
  volumes that read impaired or lost, hold a record short of retired and
  are named by no shard the tick read, `null` when the tick holds no
  count), and `client` with `store_alarm`. Per shard:
  `shard`, `state` with its fields (`need`, `phase`, `host` for
  `Enrolling`; `phase` and `volume` for `Replacing`; `source` and `error`
  for `Unobserved`), `blocker`, `closed` (for a shard that reads `Closed`
  on its active volume's attach bound, the bound: `LiveCap`, `EntryCap`,
  `PairCap`, `OwnEntry` or `KeyTaken`; `null` otherwise), `target`
  (`generation`, `owner`, `attempts`), `exposure_us` and `overdue`. An `Unobserved` shard's
  `error` is the store error for source `Store`, the succession refusal
  for source `Succession` (`Zone`, `Version`, or `Departed`, `Unretired`,
  `Reassigned` or `Rezoned` with the host, as `Departed(Host(13))`), and
  `null` for source `Directory`. A tick that overran is published and
  sealed like any other; a reader that must discard one reads `overran`. The
  states and blockers are the names of `ShardState` and `Blocker` in
  `crates/kestrike/src/failover/zone_loop/status.rs`, whose module
  documentation gives their precedence, and the closed causes are the
  names of `Closed` in `crates/kestrike/src/failover/standbys.rs`.
- `status.sealed`: the tick's reconciler status, sealed under the key the
  status key file derives and named for the configured `writer`, in the
  layout `crates/kestrike/src/failover/report/status_contract.json`
  pins. A verifier accepts it with `StatusReader::accept`. A tick whose
  seal fails names the error on standard error and leaves no
  `status.sealed`. A verifier keeps the last four boots of a writer
  (`BOOTS`), and each run of the service is a new boot that stamps its
  seals with the wall clock. After the wall clock steps back across a
  restart, a verifier can refuse the new run's statuses as `Duplicate`
  until a new seal carries a stamp above the lowest seal stamp it kept, and
  `status-absent` fires meanwhile. Correct the clock against a trusted
  source and keep the verifier's replay state; within one run the writer
  stamps the higher of the wall clock and its previous stamp.

The report source answers `Unreachable` for every host, so each active or
draining host reads `Unknown` and a retired host reads `Lost` from its
retirement. While the admitted directory lists a host in the zone,
`complete` never lists `reports`. The warm-up hold ends once the settle
time has passed and each source has read complete on some tick of the run
(the store: answered, as below), so it stays on for a run whose every
admitted directory listed a host in the zone. An admitted directory with no host in the zone counts as a
complete report read, and a later directory that adds hosts does not
restore the hold. A directory refused before the run admits one yields a
document with no shard rows; once a directory is admitted, a refused
reread marks its shards `Unobserved`.

For the store source the warm-up hold waits for a tick on which the store
answered every read, and stored bytes that do not decode count as an
answer. A shard record, or a shard's own volume record or replacement
receipt, whose stored bytes do not decode leaves that shard `Unobserved`
with source `Store`, a `Codec` error and the blocker `StoreUnavailable`;
`complete` omits `store` on that tick, and the hold still ends. A
looked-up volume record, or the reread receipt of a shard the directory
omits, that does not decode leaves every shard read and `store` in
`complete`. The volume whose record does not decode counts nothing beside
a loss, and no lost active volume earns a new decision while the record
or receipt stays undecodable. An undecided loss reads `LossUnconfirmed`.
A loss confirmed on an earlier tick reads `ReplacementHeld`
(`ReplacementExhausted` when no later generation remains) while the tick
still counts another impaired volume, and `LossUnconfirmed` on a tick
that counts none. A read the store did not answer, a withdrawn store
client and a census that does not decode keep the hold.

The stock `status-absent` alarm of
`crates/kestrike/src/failover/report/alarms.json` reads a zone's status
absent after 60 s without a new accepted status, counted on the
evaluator's receive clock. Keep `tick_us`, plus the tick's own duration and
the collection delay, below that window, or deploy the evaluator with that
row's window raised to match.

## Deployment

`crates/kestrike-reconciler/kestrike-reconciler.service` runs `run`
as the user `kestrike-reconciler` with the configuration at
`/etc/kestrike-reconciler/config.json`, whose `state` names
`/var/lib/kestrike-reconciler`. Create that directory and run `init`
once as that user before the first start:

```sh
install -d -o kestrike-reconciler -g kestrike-reconciler -m 0700 /var/lib/kestrike-reconciler
sudo -u kestrike-reconciler kestrike-reconciler init --config /etc/kestrike-reconciler/config.json
```

The unit mounts the file system read-only for the service
(`ProtectSystem=strict`) and opens `/var/lib/kestrike-reconciler` for
writes with `ReadWritePaths=`, which leaves the directory's owner and mode
as they are on disk. `run` checks both at each start and exits 4 for a
directory that is absent, belongs to another user, or grants its group or
others a permission. `RequiresMountsFor=` orders the unit after the mounts
that path needs. To keep `state` elsewhere, change both settings to the new
path.

The unit restarts the service after every exit except 2, 3 and 4, which
need an operator: a configuration or state directory to repair, or a
withdrawn store client to diagnose. A stop waits for the tick in progress,
up to `TimeoutStopSec` ([Tick timing](#tick-timing)).

The run opens the store table once, by `DescribeTable`, and reads the
table its name names for the life of the run. Keep the configured `table`
bound to one table for that life: stop the service before you delete,
restore or repoint the table, and start it again after. A restart against a
restored table whose shard records name the old table's namespace
withdraws under `Namespace` and exits 3.

The service reads its AWS credentials from the instance role, through
IMDSv2, and from no other source. Grant the role these actions and no
other:

- `dynamodb:DescribeTable` and `dynamodb:GetItem` on the store table;
- `ec2:DescribeVolumes`, `ec2:DescribeVolumeStatus` and
  `ec2:DescribeInstanceStatus`.

The run sends those five actions only. The loop calls `ZoneLoop::tick`
and `ZoneLoop::deadline`, whose survey reads, and its zone listings send
the three describe actions. The reconciler's gated steps take a gate the
crate cannot construct, and the run calls none of its ungated write steps.
Three checks back this: that call path, the service test's check that its
fake table receives no `PutItem`, and the role's limits, which refuse every
other action at the deployment.
