# Survey: the simulated Kestrike

Read on 2026-11-23 on this aarch64 worker, at commit
`6240a6fd99b2c684620db01f448f2b519cfba5c6` of `main`, by the session that writes this
contract. Each line names its source. The survey brings leads; the owner's answers in
`chaos/interview.md` decide. The survey read and changed nothing, except the one
sweep of the entry gate below, which ran before any other run.

## Entry gate: no worker process opens a network connection

The gate, from #301: before any other run, a sweep's worker processes open no network
connection. Result: none did. A sweep of `upload` for 60 s with 28 workers ran in a
new network namespace whose one interface, `lo`, was down, under a trace of every
network system call, and exited 0.

The archive is a dev build with `CARGO_PROFILE_DEV_OPT_LEVEL=3`, build digest
`fdc5e739b313c80a784624d7af3d81eebb4fc9327d4bcee4f5e154dbe7cb52f6`, made with
`CARGO_PROFILE_DEV_OPT_LEVEL=3 campaign sim archive --output /data/tsw/campaigns/archive-2078`.
The gate ran as the worker's user `tsw` inside a delegated cgroup scope, as
`crates/campaign-supervisor/README.md`, "Host requirements", describes:
`systemd-run --user --scope -p Delegate=yes --unit=gate-2078 -- bash gate.sh`. The
script, verbatim:

```sh
#!/bin/bash
# Entry gate of #301: a sweep of `upload` for 60 s in a network namespace
# with no interface up, traced for every network syscall.
set -u
D=/sys/fs/cgroup$(cut -d: -f3 /proc/self/cgroup)
mkdir "$D/controller" && echo $$ > "$D/controller/cgroup.procs"
echo '+cpu +memory +pids' > "$D/cgroup.subtree_control"
mkdir "$D/campaign"
OUT=$HOME/research/2078/gate
CHECKOUT=/data/tsw/checkout
sudo unshare --net -- sh -c '
  echo $$ > "'"$D"'/controller/cgroup.procs" || exit 90
  exec setpriv --reuid=tsw --regid=tsw --init-groups -- env -i \
    HOME=/home/tsw PATH="'"$CHECKOUT"'/target/release:/usr/bin:/bin" \
    CAMPAIGN_CGROUP_ROOT="'"$D"'/campaign" \
    sh -c "umask 077; cd '"$CHECKOUT"';
      python3 '"$OUT"'/interfaces.py;
      readlink /proc/self/ns/net;
      strace -f --seccomp-bpf -qq -e trace=%network -o '"$OUT"'/strace.log \
        campaign sweep --root /data/tsw/campaigns/gate-2078-root \
          --archive /data/tsw/campaigns/archive-2078 --campaign gate-2078 \
          --profiles upload --workers 28 --for 60;
      echo sweep-exit=\$?"
' > "$OUT/sweep.out" 2> "$OUT/sweep.err"
echo "gate-exit=$?" >> "$OUT/sweep.out"
readlink /proc/self/ns/net >> "$OUT/sweep.out"
touch "$OUT/done"
```

The script moves its shell into the scope's `controller` child cgroup, and the root shell of the new
network namespace moves itself back there before `setpriv` drops root, so
`CAMPAIGN_CGROUP_ROOT` names a delegated `campaign` child. `interfaces.py`, verbatim:

```python
"""Print each network interface of this process's namespace and whether it is up."""
import fcntl, socket, struct
SIOCGIFFLAGS, IFF_UP = 0x8913, 0x1
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
for index, name in socket.if_nameindex():
    flags = struct.unpack("16sH", fcntl.ioctl(s, SIOCGIFFLAGS, struct.pack("16sH", name.encode(), 0)))[1]
    print(f"interface {index} {name}: {'up' if flags & IFF_UP else 'down'}")
```

What the run printed:

- the namespace's interfaces, read through `SIOCGIFFLAGS` before the sweep:
  `interface 1 lo: down`, and no other;
- `sweep-exit=0`, 60.7 s; 625,749 runs, 562,112 passes, 0 suspects, 29 replays; no
  `alarm`, `no_pass` or `unreached`; controls 33,557 runs, 33,251 caught, 0 missed;
  histories 44,780 runs, 3 of 285 ran;
- the trace of every process of the sweep, workers and replays among them: 87
  `socketpair(AF_UNIX, ...)` calls and 87 `recvfrom` calls on those pairs, and no
  `socket`, `connect`, `bind`, `sendto`, `sendmsg` or `accept` call.

## The copy

- Kestrike as the archived simulation worker runs it under `campaign`: the
  worker binary and its libraries in the archive that `campaign sim archive` writes,
  verified by `sweep` before its first run and after its last
  (`crates/campaign-supervisor/README.md`, "Explore seeds with a sweep").
- A run is one `campaign sweep` of a new root under its own campaign name, then
  `sweep-status`, `confirm` and `findings` (#297, "Words"). The root, its archive and
  its state live under `/data/tsw/campaigns`, mode 0700, on xfs, as "Host
  requirements" asks.
- The two profiles of the first ledger: `upload`, a single-owner upload and read-back
  with nine controls, among them `corrupted`; and `cluster-broad`, several owners and
  clients over links that lose, duplicate, reorder and delay datagrams (README,
  "Explore seeds with a sweep"), with the controls `cluster-wrong-owner` and
  `cluster-stale-read` (README, "Controls in a sweep").

## Entry points and load

| Entry point | Does | Real rate | Source |
| --- | --- | --- | --- |
| `campaign sweep` | runs seeds of the named profiles in worker processes, with their controls and the scripted histories in turn | no production figure applies: runs go at the rate the worker's cores allow | README, "Explore seeds with a sweep"; #297, KTD8 |
| `campaign confirm` | admits each listed suspect as a supervised job and records a finding when it fails | one job a suspect | README, "Explore seeds with a sweep" |
| `campaign fuzz` | runs the worker's fuzz target under libFuzzer | outside this contract | README, "Fuzz the archived worker" |

#297, "Run sizing": about 349 seed runs a worker-second for `upload` and 74 for
`cluster-broad` with 28 workers; #297 does not say which runs and which worker time
its figures divide. The gate above is one 60 s sweep, traced by `strace` in the
network namespace, with no spread measured. It ran 625,749 runs of every kind in
60.7 s with 28 workers, about 368 a worker-second on the status document's
`runs_per_s` basis. Of these, 547,412 were `upload` runs
(`profiles.upload.runs`); the 33,557 control and 44,780 history runs ran in the
control and history batches.

## State and where it becomes durable

- Inside a run: the simulated device's media, the owners' index bindings, slot words
  and extent allocator, checked at every stopped boundary and at teardown by the
  observer of `crates/kestrike/src/net/observe.rs` (a `cfg(test)` module).
- Outside a run: `sweep.json` under the root holds the totals and each profile's next
  run number; `suspects.jsonl` holds the first eight suspects of each key; `confirm`
  keeps a state directory under the root (README, "Explore seeds with a sweep").
  No run writes outside its root and the artifacts directory.

## Dependencies

| Dependency | Owner | In the copy | Source |
| --- | --- | --- | --- |
| Storage device | the cache's own simulated device | `storage::device::sim`, with the differences of `crates/kestrike/src/storage/device/fidelity_tests.rs` | `docs/agents/simulation.md`, "Determinism lint" and the paragraph on the differences table |
| Network | the simulated datagram links of each world | the world's links, in one process | README, "Explore seeds with a sweep", on `cluster-swarm` |
| Clock, entropy, threads | the simulation's controlled interfaces | virtual time and seeded choices; the determinism lint matches listed paths only, and its production-code exceptions leave unverified whether a result depends on host hash keys, host nonces, a contended sleep or warm workers (`project.yaml`, `differs_from_production`) | #31, C5; `crates/kestrike/clippy.toml`; `docs/agents/simulation.md`, "Determinism lint" |
| AWS | the owner's account | not reached by the traced `upload` sweep of the entry gate; no traced sweep covered `cluster-broad`; the worker's role answers the credential probes | the entry gate; "Reach" below |
| GitHub | the owner | not reached by the traced `upload` sweep of the entry gate; `gh` and `git` push this work | "Reach" below |

A sweep's dependencies are its host's as far as the entry gate shows: the traced
sweep of `upload`, with the controls and the three histories its 60 s reached,
called nothing outside it. No traced sweep covered `cluster-broad`, whose links are
in-process datagram links of one world.

## Topology and failure domains

- One worker host, 32 vCPUs, 256 GiB; one sweep at a time on a root, and each sweep
  worker in a cgroup of its own with one CPU, 2 GiB and 64 pids by default (README,
  "Controls in a sweep", the paragraph on worker cgroups).
- Inside a run, owners and clients are logical nodes of one deterministic process
  (#31, "Goal"). Production runs a fleet of hosts with EBS volumes and the native
  driver, which no sweep runs.

## Failure history

- #297, "Problem": 47 cache bugs proven since 2026-11-19 were found by code reading
  and proof lanes, none by a sweep. M0-4 registers one escape.
- `KNOWN` in `crates/campaign-supervisor/src/campaign/known.rs` is empty at this
  commit: no open finding is registered.

## Telemetry: the records a judge reads

- The status document of `campaign sweep-status --root ROOT`: totals, `controls`,
  `histories`, `profiles.<name>` with `runs`, `pass`, `caught`, `caught_rules`,
  `missed`, `covered`, `reached`, `replays`, `suspect_keys` and `uncredited`, and the
  keys `alarm`, `no_pass` and `unreached` when they hold (README, "Explore seeds with
  a sweep" to "Known findings in a sweep"; `caught_rules` from
  `crates/campaign-supervisor/src/campaign/seeds.rs` and #297, P-CC-E2). The gate's
  document was 139 KB.
- `suspects.jsonl` under the root, one line for each listed suspect with its `key`.
- The output of `campaign findings` after `campaign confirm`.
- The exit code of `campaign sweep`: 0, or 1 for `alarm`, `no_pass` or `unreached`, or
  2, 3 or 4 (README, "Exit codes").
- Gap: no record of the sweep names which suspect key carries which obligation code
  in words; a judge reads the code from the key's hex identity, as `explains` in
  `known.rs` does.

## Existing checks

- The controls of each swept profile, caught under named rules, and the alarm on a
  missed one (README, "Controls in a sweep"); the scripted histories a sweep takes in
  turn (README, "Histories in a sweep"); the required-event gate (README, "Events
  reached by passing runs").
- The guards `every_listed_difference_is_pinned`, `every_row_is_complete`,
  `every_armed_point_is_reached_and_fires_in_the_pinned_roots`,
  `chaos::no_binary_holds_a_chaos_point`, `every_drawn_device_fault_is_honest` and
  `each_history_replays_in_a_fresh_process` (#297, "Constraints and Invariants").

## Deploy and rollback

- A change reaches the copy as a commit and a new archive built from it, swept into a
  new root; a rollback is an archive of the earlier commit. A root takes one build, so
  a new build needs a new root (README, "Explore seeds with a sweep").
- Nothing on this worker deploys to production.

## Tools

- `campaign`, built with `cargo build --release -p campaign-supervisor` from this
  commit; the archive above; Rust 1.99.0; python3; the AWS CLI; `gh`; `strace` and
  `unshare` for the entry gate.
- The skill `chaos-enrollment` of plugin `chaos-testing` release 0.4.0, its
  marketplace checkout at `c1231963e85f7b4601109052bc6aa7ece629b451`: its
  `scripts/probe_fence.py` wrote the fence receipts, and `chaos/tools/` pins its
  validator.

## Reach

The campaign runs as this session does. `python3 -I chaos/harness/reach.py identity`
printed `unix user tsw; aws role bsw-ct1-worker-host; github login ahrav`, the
identity each receipt under `chaos/receipts/fences/` records. The AWS role comes from
the profile `worker` of `~/.aws/config`, region `us-west-2`, whose credentials are the
instance role's.

### The four fences

| Fence | Probe, a dry run or a read | Refused with | Where the same probe goes through |
| --- | --- | --- | --- |
| `ks-fleet-object-storage-is-unreachable` | `aws s3api list-buckets` | `AccessDenied`: not authorized to perform `s3:ListAllMyBuckets` | as an identity whose policy allows `s3:ListAllMyBuckets`, such as the account's administrator |
| `ks-fleet-compute-is-unreachable` | `aws ec2 stop-instances --dry-run` on this worker's own instance | `UnauthorizedOperation` on `ec2:StopInstances` | as an identity that holds `ec2:StopInstances`, where EC2 answers `DryRunOperation` |
| `ks-no-new-paid-resource` | `aws ec2 create-volume --dry-run`, 1 GiB in `us-west-2a` | `UnauthorizedOperation` on `ec2:CreateVolume` | as an identity that holds `ec2:CreateVolume`, where EC2 answers `DryRunOperation` |
| `ks-no-workflow-file-push` | the OAuth scopes GitHub reports for the `gh` token | the scopes are `admin:public_key`, `gist`, `read:org` and `repo`, without `workflow` | with a token that holds `workflow` |

Each AWS probe runs through `chaos/harness/reach.py aws`, which runs only the three
probe argument lists of the ledger, prints only the CLI's error line for the probe's
own operation, replaces every IAM unique id with `<id>` and every account number with
`<account>`, and cuts the encoded authorization message, so no receipt holds an
account number. A refusal for workflow files comes only when a push reaches GitHub,
so `chaos/harness/reach.py token-scope` reads the scope list github.com reports and exits 1 with
the refusal text when `workflow` is absent. GitHub admits a workflow file without the
scope when a file with the same path and contents already stands on another branch
of the repository, so the fence covers every other workflow file. That scope list
bounds a push because git on this host
pushes over HTTPS to `https://github.com/ahrav/kestrike` with the token `gh` holds,
through the credential helper `gh auth git-credential` of `~/.gitconfig`, and the host
holds no SSH key (`~/.ssh` is absent). The token's scope `admin:public_key` could
register an account SSH key, and its scope `repo` lets the login, an admin of the
repository, register a deploy key with write access; no OAuth scope limits a push
over either key. Both routes belong to the token's reach below, and `trusted_base`
lists them.

The worker's configuration names no bucket and no instance of the live fleets: the
object-storage probe reads the role's own account, and the compute probe targets this
worker's instance. A grant of a named fleet bucket to the role, by an identity-based
policy or by a bucket policy, and a stop permission scoped to fleet instances, by tag
or by id, stay unprobed, and
`trusted_base` lists that limit. The workstream's lead was asked for a named fleet
resource (request `2078-fence-targets`) and ruled that the account-level probes
stand and that no fleet name enters the repository (decision L037, stated in pull
request blotter pull request 2104, "Asking the lead for help"). Only the owner
can name the fleets; the read or dry run on them then runs on this worker as the
campaign's identity, `tsw` with the role `bsw-ct1-worker-host`, and the owner records
that identity with the result. As L037 asked, one
read adds to the compute fence's evidence: on 2026-11-23, as `tsw` with the role
`bsw-ct1-worker-host`, `aws ec2 describe-instances --region us-east-1 --max-items 1`
exited 254 with `UnauthorizedOperation`: the role is not authorized to perform
`ec2:DescribeInstances` because no identity-based policy allows it, so it cannot list
the instances of the region the live fleets run in. The read is evidence in this
survey, not a fifth fence.

### The four reaches with no boundary (OQ-3)

| Reach | What the survey read | The owner's act that closes it |
| --- | --- | --- |
| `main` has no protection applied to admins | `gh api repos/ahrav/kestrike/branches/main/protection` answers that branch protection needs GitHub Pro or a public repository; the login holds `admin` on the repository. A rule file on this host refuses a push to `main`, and it is an instruction to the agent's harness, no boundary of the credential | protect `main` with the rule applied to admins, then a probe of a push as the campaign is refused |
| the token is scoped to every repository of its login | the scope `repo` covers every repository the login reaches and lets the login, an admin here, register a write deploy key; the scope `admin:public_key` can register an account SSH key; no OAuth scope limits a push over either key | a fine-grained token scoped to this repository without the Administration and Workflows repository permissions and without the account permission for Git SSH keys, for the campaign; it reports no OAuth scope list, so `reach.py token-scope` exits 2 on it and the workflow fence then needs a new probe and row, agreed at the same freeze |
| no second Unix user owns the frozen paths and the receipts, and `tsw` can run commands as root through `sudo`, as the entry gate's `sudo unshare` did | `tsw` owns the checkout and can write `chaos/harness/`, `chaos/judges/`, `chaos/project.yaml`, `chaos/approval-policy.md`, `chaos/runs/` and `chaos/receipts/` and their parent directories, directly or as root; the scope of the sudo grant was not read | a runner-owned tree, with every ancestor directory outside `tsw`'s write control, that holds every frozen path, `chaos/runs/` and `chaos/receipts/`, owned by a second Unix user that runs the harness, and no sudo right for `tsw`; then a read-only check of `tsw`'s effective write permission on each of those paths and their parents, directly and through `sudo -n`, shows none |
| the simulation hosts' buckets are unnamed | `docs/agents/sim-hosts.md` names each bucket only as `SIM_BUCKET`: the first example assignment's and the recovery assignment's | each bucket's name, so a probe at each bucket can show the campaign's role is refused there |

## Leads taken to the owner

| Lead | From | Answer |
| --- | --- | --- |
| A GET never returns a version older than one collected or removed before it | array `CLUSTER`, judged by `cluster-broad`, caught under `cluster-stale-read` | row `ks-get-not-older-than-collected`; OQ-6 open |
| A bound slot's record passes its header and chunk checks | array `OBSERVER`, caught under `corrupted` | row `ks-bound-record-passes-its-checks`; OQ-6 open |
| A healed owner keeps no resources of finished work | the rule caught under `cluster-swarm-leak` | excluded as a hypothesis: OQ-5 open |
| A required event is reached at its measured rate | the required-event table | excluded: M2-4 (#315) added `ks-required-events-reached`, which judges reach at all, and the rate stays excluded until the owner adopts a rate a sweep must sustain |
| The owner storage's tables agree after every turn | the conservation rule, caught under `leaked` | excluded as `no-oracle` |
| A recovery profile passes the restart check | the oracle's restart verdict | excluded as `no-control` |
| Lying and out-of-contract device faults | `every_drawn_device_fault_is_honest`; the row `fault-kinds` | excluded as `out-of-envelope` for M4-4 |
