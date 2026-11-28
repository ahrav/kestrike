# Judge tests and recorded runs

`test_judges.py` judges the recorded runs under `runs/`, apart from `fixture-reach-live`, and the
cases it builds from them, and checks the harness against a fake `campaign` binary and the
interface of `chaos/judges/core/common.py`:

```sh
python3 chaos/tests/test_judges.py
```

It starts no sweep, needs only `python3`, and runs in no CI suite. A case it builds is a copy of
a recorded run in a temporary directory, with one record edited the way one falsifier of the
verdict mapping describes: an absent or incomplete run record, a recorded sweep exit 1, 2, 3 or 4
beside a clean status document, an empty or unreadable status document, a profile with no
replay, a `panic` suspect key, a declared-failure history with no caught run, a minimum unmet, a
violation suspect under the row's rule with and without the finding of `campaign confirm`, a
violation under another rule, a finding of another run, a break on a run with a totals flag or
another build, a control whose defect is only its label, has no replay or has a run a kill
ended, control totals that disagree with the control entries, a control marker that is no
boolean, counts no sweep writes, a missed run beside totals that carry no flag, a suspect total
unlike the sum of its keys, a run counted as a pass and as caught, a listed suspect the status
does not count, under `other` too, a sweep command line without its archive or its root, and a
receipt path outside `chaos/receipts/`. No real sweep has produced a `violation` suspect, so
that case is built from the supervisor's record format.

`test_ordering.py` does the same for the ordering family, `chaos/judges/ordering/`, with the
runs named `fixture-ordering-*`, and `test_judges.py` runs its tests with its own.

`ledger.json` here is the test's own ledger. It holds the scenario `ks-h1-get-stale-declared`,
one sweep of the scripted history `h1-get-stale`, and the history invariant
`ks-qualified-get-reads-visible-bytes` of the rule that history declares,
`a qualified GET missed the visible version's exact bytes`, obligation 2. The judges read it in
a temporary tree whose `chaos/ledger.json` it is.

## The recorded runs

Each run is one harness invocation on the aarch64 worker (an r8gb.8xlarge share of a Graviton4,
32 vCPUs), with the row's 28 workers, `--batch 30` and `--for 120`, default counts, a new root
under `/data/tsw/campaigns/2079-r6/` and the campaign binary
`f09cb27621560a7a2d7f6dfe5880b940b253e61e136139483a98de7a7a034420` built by
`cargo build --release -p campaign-supervisor` at commit
`b7a0414dea969f179b243e4b81deafd20558e3a2` and kept as
`/data/tsw/campaigns/2079-r6/campaign-b7a0414d`. The harness ran as
`chaos/harness/run_scenario.py` with SHA-256
`6a764f8492d7b6f96357f5dfb0036802078c7266a03444c6a759c9d667036857` (beside `reach.py`,
`fcb258d619accd33e1a1fa226551cc8367b562b2279549d774075bd97b7c38d1`; each `run.json` names both).

Each run had a delegated systemd user scope of its own, set up as
`crates/campaign-supervisor/README.md`, "Host requirements", describes: the shell that started
the harness sat in the scope's `controller` group, and the scope's child group `campaign` was
the run's `CAMPAIGN_CGROUP_ROOT`. The harness needs that layout. It refuses a cgroup root in
which a group other than an earlier sweep's worker group lists a process, and it counts every
process under the root at the run's end, so the harness and its caller run outside the root and
no other command uses the root during the run.

Two limits of the harness that no case covers:

- After a stop (the deadline, SIGTERM, SIGINT or SIGHUP) the harness sends SIGTERM to the
  `campaign` command alone, and SIGKILL to its process group only when the command is still
  running `STOP_WAIT_S` later, which
  `test_a_command_that_outlives_a_signal_is_killed_with_its_process_group_stop_wait_later`
  covers. A process of the command's group that outlives a command that exited on SIGTERM gets no
  signal from the harness. A worker or an attempt is killed through its cgroup, a process left in
  another group under the root is counted in `left_a_process` and refuses the next start on that
  root, and the run is incomplete either way.
- The harness reads `load.multiple` of a scenario row and applies nothing for it. Every row
  holds 1. A row with another multiple would sweep as the same row with 1.

Two archives of that commit:

| Archive | Built with | Build digest |
| --- | --- | --- |
| `A`, debug assertions on | `CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive --output A` | `81f802d48d10117ec0c4c345f8aa61299f99a315e90f129a952a3ee911c5b3a3` |
| `N`, debug assertions off | `CARGO_PROFILE_DEV_OPT_LEVEL=3 CARGO_PROFILE_DEV_DEBUG_ASSERTIONS=false campaign sim archive --output N` | `386c0fe6d1339d2edb272af302d5b3d866c35c5f9cfb9e3eecbd05797f1ace50` |

Each command below runs from the repository root and ends in
`--campaign /data/tsw/campaigns/2079-r6/campaign-b7a0414d --roots /data/tsw/campaigns/2079-r6`:

| Run | Command | Swept | Runs of each swept profile | Verdicts |
| --- | --- | --- | --- | --- |
| `fixture-upload-live` | `python3 chaos/harness/run_scenario.py ks-upload-no-fault fixture-upload-live --archive A` | `upload` | upload 1,038,416 | validity held; bound-record held |
| `fixture-cluster-live` | `python3 chaos/harness/run_scenario.py ks-cluster-link-faults fixture-cluster-live --archive A` | `cluster-broad` | cluster-broad 245,107 | validity held; not-older held, though the unnamed control `cluster-stale-read` was caught under its text; bound-record held |
| `fixture-upload-corrupted` | `python3 chaos/harness/run_scenario.py ks-upload-no-fault fixture-upload-corrupted --control corrupted --archive A` | `upload,corrupted` | upload 525,444; corrupted 533,465 | validity held; bound-record broken |
| `fixture-cluster-stale-read` | `python3 chaos/harness/run_scenario.py ks-cluster-link-faults fixture-cluster-stale-read --control cluster-stale-read --archive A` | `cluster-broad,cluster-stale-read` | cluster-broad 122,233; cluster-stale-read 73,294 | validity held; not-older broken; bound-record invalid, the control caught under another rule |
| `fixture-upload-asserting` | `python3 chaos/harness/run_scenario.py ks-upload-no-fault fixture-upload-asserting --control asserting --archive N` | `upload,asserting` | upload 566,824; asserting 427,967 | sweep exit 1 with `alarm`; validity invalid; bound-record invalid |
| `fixture-upload-interrupted` | `python3 chaos/harness/run_scenario.py ks-upload-no-fault fixture-upload-interrupted --archive A`, sent SIGTERM 50 s after it started | `upload` | none recorded | both incomplete |
| `fixture-h1-get-stale-live` | `python3 chaos/harness/run_scenario.py ks-h1-get-stale-declared fixture-h1-get-stale-live --archive A`, run from a tree that holds copies of `chaos/harness/` and `chaos/judges/` and this directory's `ledger.json` as `chaos/ledger.json` | `h1-get-stale` | h1-get-stale 1,244,782 | validity held; the history invariant broken through the history's declared violation |

Each run took 123 s of wall clock, except the interrupted one, which ran 50 s. The
directory of `fixture-upload-interrupted`, whose sweep did not end by itself, holds `run.json`
alone; each other run's directory holds `run.json`, `history.jsonl`, `suspects.jsonl`,
`sweep-status.json` and `findings.json`. The copies hold no wall-clock field. The harness
wrote each receipt to `chaos/receipts/<run-id>/`. The run directories moved to `runs/` and
their receipts to `receipts/<run-id>/` here, so the contract's own receipt directory holds no
fixture: the test writes its receipts under `chaos/receipts/` of its temporary trees. Each
receipt names the digests of the two ledger rows it judged, of every file of
`chaos/judges/core/`, of the harness files and of each evidence file.

The runs were recorded on 2026-11-24 from 09:21 to 09:34 UTC with the harness whose digests
each `run.json` names. Whoever changes a ledger row a run was judged
against, a judge file or the harness records the affected runs again in the same change.
`test_each_recorded_run_keeps_receipts_that_name_the_rows_judges_and_harness_of_the_tree`
fails until then: it compares each `run.json` and each kept receipt with the rows of the
ledger the run used, the files of `chaos/judges/core/` and `chaos/harness/`, and the run's
evidence files.

## The reach run

`test_reach.py` judges the recorded run `runs/fixture-reach-live` with the two judges of
`chaos/judges/reach/` and builds its other cases from it in a temporary directory:

```sh
python3 chaos/tests/test_reach.py
```

It holds the seven verdict cases of the reach judge (held; broken by `unreached` and by
`no_pass`; incomplete under the 64-pass floor and on a recorded exit 4 of a changed archive;
invalid on `alarm`; the control, whose table requires `invalidated` of `cluster-pressure`), the
falsifiers of the judges' other branches, and checks against the files the judges stand for. Each
falsifier's edit keeps the per-profile counts the judges read (runs, pass, caught, covered,
reached) and the profile's member of the status's derived `reach` map as a sweep could print
them, apart from the one the case is about; the root totals and the histories aggregates keep
their recorded values. For each receipt a judge writes on a run that has a run record, the test
calls `receipt_accepted` of `chaos/harness/run_scenario.py` with the binding the harness builds
for that judgement, and fails when the harness would drop the receipt. The harness keeps a broken
receipt only when its detail holds the row's `control.expect`, so that field of
`ks-required-events-reached` is the row's property text. The checks: the scope sentence is the
line of `chaos/project.yaml`, `chaos/READINESS.md` prints it, every
committed reach receipt ends with it, a second load of `shared.py` keeps one scope sentence, the
required-event table's rows, excused pairs and `REQUIRED_PASSES` and the coverage counters with
their declared length are those of `crates/campaign-supervisor/src/campaign/seeds/required.rs`
and `crates/campaign-supervisor/src/protocol/summary.rs`, and the count relations of
`counts_agree`, their 32-bit and 64-bit widths and the missed suspect classes are those of
`crates/campaign-supervisor/src/campaign/seeds.rs`, the gate of `required.rs` is armed at
`REQUIRED_PASSES` covered passes and reads a counter absent from `reached` as unreached, as the
judge does, the `no_pass` floor that `chaos/project.yaml` prints and the judges hold is
`NO_PASS_RUNS` of `seeds.rs`, and the receipts of the committed witness `reach-live-1125b` and control
`reach-control-1125b`, read by run id, are held and broken on the planted pair. It starts no sweep and runs
in no CI suite.
`test_judges.py` runs it in a process of its own, started as `python3 -I`. The pre-push hook runs `test_judges.py` on a
push that changes a path at or under `chaos/harness/`, `chaos/judges/`, `chaos/tests/`,
`chaos/tools/` or `chaos/receipts/`, or `chaos/ledger.json`, `chaos/project.yaml` or
`chaos/approval-policy.md`, and on a push that changes `controls.rs`, `required.rs`, `seeds.rs` or
`summary.rs` under `crates/campaign-supervisor/src/`. In a clone without the hook, run
`test_judges.py` by hand after such a change, as `AGENTS.md` says.

`runs/fixture-reach-live` is one harness invocation on the worker of the session of 25 November
2026 (an r8gb.8xlarge share of a Graviton4, 32 vCPUs, another instance than the worker of the
runs above), started 2026-11-25T07:35:46Z, inside a delegated systemd user scope:

```sh
python3 chaos/harness/run_scenario.py ks-reach-required-events fixture-reach-live \
  --campaign /data/tsw/campaigns/2082t/campaign --archive /data/tsw/campaigns/2082t/archive \
  --roots /data/tsw/campaigns/2082t/roots
```

The campaign binary, SHA-256
`c47c899a6747f1c318980ca2ba8da8cb182a5454b5ffe698a1f9028d267dc4f1`, is
`cargo build --release -p campaign-supervisor` at commit
`bba1b428a08134793e08527ec28810560cc90e2f`. The archive, build digest
`c948fcfa86a0408965ecccda9755efeb50cad7c417e9d750215a04c958b0a3fe`, is
`CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive` at the same commit, the archive of the
contract's runs `reach-live-1125b` and `reach-control-1125b`. The sweep ran 28
workers, `--batch 30` and `--for 120` at default counts and took 123 s of wall clock: cluster-swarm
14,111 runs and 10,903 covered passes, cluster-broad 84,395 and 70,955, cluster-pressure 33,889 and
33,478. Both judges held it. Its receipts were removed and the directory moved here, as for the
runs above. It replaces the run of 2026-11-24T11:31:18Z, recorded against the row
`ks-reach-required-events` as it stood before its `restoration` text changed; that run stands
at commit `5755aacea`.

## The ordering family's recorded runs

`ledger.json` also holds a copy of the contract's row `ks-ordering-controls-caught`, which
`test_ordering.py` holds equal to it, and two scenarios that differ from the contract's
`ks-ordering-figure` in their id, judge command, text, load settings and `restoration` text:
`ks-ordering-figure-short`, `--for 120`, and `ks-ordering-figure-few`, one worker in batches of
1 s for 2 s. Both keep the `restoration` sentence their fixtures were recorded against, which the
contract's rows held until 25 November 2026. Each run below is one harness invocation on the same worker, run with
`python3 -I -B` from a tree that holds copies of `chaos/harness/` and `chaos/judges/` at #302's
commit `6844595482fe216ad57b3bd300b46909844b2763` and this directory's `ledger.json` as
`chaos/ledger.json`, with default counts, a new root under `/data/tsw/campaigns/2092/fixtures-r5/`,
a delegated cgroup root, and the campaign binary
`0a7d40a714c44166fd51f192b81e47f4c6c5db30f7775eed5b225b2734d5c3b4`, built by
`cargo build --release -p campaign-supervisor` at the merge of that commit into this branch.

The runs sweep two archives, each built with `CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim
archive` from a tree of commit `d7bba991f8f69996767bc10a0fecd80dee4e5c8a`; each run's `run.json`
names its archive's build digest as `system_build`:

| Archive | Tree | Build digest | `Cargo.lock` SHA-256 |
| --- | --- | --- | --- |
| `O` | the commit | `13056bc7ab0275221231118eb2ef21728bb42dc065048840a677a59c70fc1ea1` | `c3eb617f8a955948635e6b0a1c89090c06ea9ccb325e4bb4a15b12f7eaf45c7f` |
| `U` | the commit with the one line `Plant::Depth1 => true,` of `Order::decided` in `crates/kestrike/src/net/world_tests/cluster/order.rs` changed to `Plant::Depth1 => false,`, so the depth-1 plant selects no read | `f3e8bed95fd39fbf161e6fbee9b14753f589067b2e65ba50fc41e60de9f67335` | `565299458673ee80dd4d62f20ff11f345eeab505d1ccc6be85d163758cbb7266` |

| Run | Command | Runs of each control | Verdicts |
| --- | --- | --- | --- |
| `fixture-ordering-live` | `python3 -I -B chaos/harness/run_scenario.py ks-ordering-figure-short fixture-ordering-live --archive O` | 85,653; 85,389; 85,367 | validity held; figure held |
| `fixture-ordering-premise-unmet` | `python3 -I -B chaos/harness/run_scenario.py ks-ordering-figure-short fixture-ordering-premise-unmet --control cluster-order-1-premise-unmet --archive U` | 82,020; 81,649; 81,721 | validity held; figure broken, `cluster-order-1` not found in its runs |
| `fixture-ordering-few` | `python3 -I -B chaos/harness/run_scenario.py ks-ordering-figure-few fixture-ordering-few --archive O` | 107; 68; 0 | validity invalid, no replay; figure incomplete |

Each archive retains the `Cargo.lock` its build resolved. `U`'s was resolved anew in the scratch
worktree, so the two differ, with `ahash` 0.8.12 against 0.8.13 and its `getrandom` 0.3.4
against 0.4.3: `U` differs from `O` by that resolution as well as by the one line. Both build
records name a dirty tree, so the text above rebuilds neither digest; a replay uses the retained
archives under `/data/tsw/campaigns/2092/`.

The contract's runs of record, `chaos/runs/ordering-live-1125b` and
`chaos/runs/ordering-premise-unmet-1125b`, sweep two archives of commit
`bba1b428a08134793e08527ec28810560cc90e2f`, which holds the harness, the core and the ordering
judges each receipt names, through `python3 -I -B chaos/harness/run_scenario.py
ks-ordering-figure` in that commit's checkout, each in a delegated scope of its own, with a new
root under `/data/tsw/campaigns/2082t/roots/`. They replace `ordering-live-r7` and
`ordering-premise-unmet-r7`, which stand at commit `5755aacea`
(`chaos/loop/stops/escape-restoration-text.md`):

| Archive | Tree | Build digest | `Cargo.lock` SHA-256 |
| --- | --- | --- | --- |
| `O8` | the commit, a clean tree | `c948fcfa86a0408965ecccda9755efeb50cad7c417e9d750215a04c958b0a3fe` | `57ec81470e2c103996bde8f74a9970c5cd384d6fe988a3fb4662100208339cc2` |
| `U8` | a scratch worktree of the commit with the one line `Plant::Depth1 => true,` of `Order::decided` changed to `Plant::Depth1 => false,` and the checkout's `Cargo.lock` copied in | `d490e18bd0e6681c966d9af286093e5307a56f0b95a1c3dad056590364b3a11b` | `57ec81470e2c103996bde8f74a9970c5cd384d6fe988a3fb4662100208339cc2` |

Both archives hold one `Cargo.lock`, so `U8` differs from `O8` by the one line alone. `O8`'s build
record names the commit and a clean tree; `U8`'s names the commit and a dirty tree, so a replay of
the control uses the archive retained on the worker of the session of 25 November 2026 with the
step's records, `~/research/2082/helper-restoration-text/archive-premise-unmet`. That worker is
another instance than the worker of 24 November, which the fixtures above and their retained
archives and binary name; it holds none of them, and this text states nothing about where they
stand now. Each `run.json` names its
archive's build as `system_build` and its campaign binary as `campaign_binary.sha256`,
`c47c899a6747f1c318980ca2ba8da8cb182a5454b5ffe698a1f9028d267dc4f1`, built by
`cargo build --release -p campaign-supervisor` at the same commit. `ordering-live-1125b` ran
426,713, 426,378 and 426,357 runs of the three controls and both judges held it;
`ordering-premise-unmet-1125b`, with `--control cluster-order-1-premise-unmet`, ran 426,208,
425,378 and 425,158, its validity held and its figure is broken, `cluster-order-1` not found in
its runs. Each sweep took 601 s.

The first two fixtures took about 125 s of wall clock each and the third 5 s. The control `U` is
a change to the worker's build, which the worker lists under no profile name, so
`cluster-order-1-premise-unmet` is the run's label alone. A run whose status names another
campaign than its `run.json` cannot come from the harness, so `test_ordering.py` builds that
case from `fixture-ordering-live`.

## The recorded miss

`fixture-ordering-missed` is one more harness invocation of `ks-ordering-figure-short` on the
same worker, with the campaign binary and the harness of the three runs above, default counts, a
new root under `/data/tsw/campaigns/2092/probe-roots/`, a delegated cgroup root and no
`--control`, so its `run.json` names mode `live`. It sweeps archive `M`, built with
`CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive` and retained at
`/data/tsw/campaigns/2092/probe-archives/W3`:

| Archive | Tree | Build digest | `Cargo.lock` SHA-256 |
| --- | --- | --- | --- |
| `M` | commit `7a123f129a6568c01a42cf27b8c47b11c2df9103` with the call `self.foreign("a GET returned bytes no upload of its key wrote");` removed from the cluster checker's judgement of a complete read in `crates/kestrike/src/net/world_tests/cluster.rs`, so a read of bytes no upload wrote meets no check | `a22e9a716a03bb68c52d41299e06f65bd59a2ed09936b495808dce300ad9ab46` | `48e5da470ced50076dbab8a9d74d2e4421b42c9a6b2cb07f0ece597a834e5b15` |

| Run | Command | Runs of each control | Missed runs of each control | Verdicts |
| --- | --- | --- | --- | --- |
| `fixture-ordering-missed` | `python3 -I -B chaos/harness/run_scenario.py ks-ordering-figure-short fixture-ordering-missed --archive M` | 86,264; 86,184; 86,007 | 5,740; 1,819; 1,099 | sweep exit 1 with `alarm`; validity invalid; figure broken, each control missed |

In this build each ordering plant changes its read and no check fails. The supervisor lists each
such run as a suspect of class `control met no check` under the key `control met no check: `,
counts it under `missed`, raises `alarm` and exits 1. The run took 123 s of wall clock. The
change to the checker was made in a scratch worktree and is not pushed, and the build record
names a dirty tree, so a replay uses the retained archive.
