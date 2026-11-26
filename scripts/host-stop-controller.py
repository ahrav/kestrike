#!/usr/bin/env python3
"""Stop the one declared staging instance of a run of the game-day package GD-2, show the stop by a read apart from
the stop request, and write the `injection/` marks that `scripts/gameday-judge.py` reads.

Usage:
  host-stop-controller.py run --operator F --package F --evidence DIR
  host-stop-controller.py restore --operator F --evidence DIR [--reviewed F]
  host-stop-controller.py seal --operator F --evidence DIR

Every file read is UTF-8 JSON (`.json`) or JSON lines (`.jsonl`), opened without following a link or waiting on a
pipe, and checked by the judge's `decode`, `parsed` and `conform` (loaded by path): distinct keys, finite numbers,
exactly the keys listed. The judge's `check_package`, which `run` and `seal` call, also reads the two Rust files its
FLEET_BOUNDS names for their list bounds. A time in a file is POSIX seconds on the wall clock, which the package's
`clock` names and which agrees with AWS's within SKEW_SECONDS (chrony on EC2 keeps it so); an ISO time reads
`YYYY-MM-DDTHH:MM:SSZ`, seconds 00 to 59. The deadline, the effect timeout, the observation, the snapshot's age at the stop and the restoration's poll
run on the monotonic clock; the snapshot's age is also checked on the wall clock, which counts a suspend, and a stop leaves only
while the two clocks have moved within SKEW_SECONDS of each other since the run's start. `roles.json` holds the SHA-256
of the `--package` bytes, which the judge requires `DIR/package.json` to hold: the operator copies the package there
first. The operator file, the snapshot and the reviewed record stay outside DIR, where the judge admits no file outside its layout. Marks
need Linux: DIR's file system takes unnamed files (`O_TMPFILE`), and `/proc/self/fd` resolves to link one to a name.

The operator file, kept outside the repository:
  {region, identity, approval, instances, snapshot, snapshot_max_age_seconds, alarms, effect_timeout_seconds,
   observe_seconds, deadline_seconds}. `region` an AWS region name; `identity` the ARN `sts get-caller-identity`
  returns for the run's caller; `approval` {approver, package_sha256, instance, not_after}, the owner's recorded
  approval of this run: the SHA-256 of the filled package's bytes, the target instance and the ISO time at which the
  approval lapses; `instances` the declared instance set, at most 100 distinct IDs of `i-` and up to 17 lowercase
  letters and digits; `snapshot` the snapshot directory, relative to the operator file's directory unless absolute;
  `alarms` {guardrail text: alarm name}, keyed by exactly GD-2's eight guardrail texts at run time, with distinct
  CloudWatch metric alarm names; and four bounds in seconds, each positive and at most LIMIT_SECONDS: the snapshot's
  age, the wait for the stop to show, the observation after it and the run's deadline, which holds the other two.

The snapshot directory, written by the store's reader:
  shards.jsonl  one line per shard of the package: {shard, owner, standby, generation, volume, attempts, time}, the
                shard record as the store holds it and the time it was read, one time for every line: the cut at
                which every record is the store's last committed version. `standby` a host or null, owner and standby
                hosts of the package, `generation` an integer from 1 to 2^32 - 1, `attempts` one from 0 to 2^31 - 2.
  hosts.jsonl   at most one line per host of the package: {host, instance, report}, the host's instance and its
                latest report {time, healthy}, `healthy` true or false, or null when it has none. The target host's
                line names the package's target instance, and no two lines name one instance.
  Every time in it lies within `snapshot_max_age_seconds` before the run reads it, and none after. The controller
  checks the shape, times and roles it reads; that the files come from the store's reader as one export is the
  operator's to keep.

`run`, in this order:
  1. Refuse, with no call and nothing written: a malformed operator file, package or key set; a package of kind other
     than `staging`; an approval of another package digest or instance, or one that lapses less than SKEW_SECONDS after
     the run's deadline; a run whose start lies before the package's baseline window ends or its run window starts, or
     whose deadline passes the run window's end; a target outside `instances`; `alarms` keyed other than by GD-2's
     guardrail texts; GD-2 texts other than those the judge and this controller were written from, or restoration
     steps that are empty or have no UTF-8 form; a GD-2 prerequisite that holds the catalog's mark of one not met
     (`TBD` of `scripts/readiness.py`); an evidence directory that is unnamed, missing, a link, holds an entry
     `injection`, takes no unnamed file it can link, or whose `package.json` is no regular file of the `--package`
     bytes; a snapshot path or alarm name with a control character or no UTF-8 form.
  2. Refuse unless `sts get-caller-identity` names `identity`. From here each call is cut at the run's deadline, and a
     deadline passed before `injection/` is made is a refusal.
  3. Refuse a malformed, stale or inconsistent snapshot, a cut before the package's baseline window starts (the judge
     shows no stop from one), an owned shard with no witness key in the package or a witness key of a shard the target
     does not own, a status read of the declared set that fails, names another set or shows an instance not running (a
     run left open), a `roles.json` past the judge's file size, and a deadline passed before `injection/` is made. Make
     `injection/`, hold its lock (`flock`) to the run's end and write `roles.json`; a failure before it stands removes
     `injection/` again and is a refusal. Apply the judge's pre-stop reach conditions (`roles_reach`, with its working
     role counts MIN_OWNED and MIN_STOOD); unmet, the abort path runs with cause `reach`.
  4. Read the alarms, which must each be quiet (`quiet`): `OK`, missing data treated as `missing` or `breaching` as
     the row states it, no `EvaluationState`, no PromQL alarm (`EvaluationCriteria`), no metric query expression
     (metric math, FILL or Metrics Insights) and no percentile that ignores a low sample count, each of which can read
     `OK` while its source is silent. Else the abort path runs with cause `guardrail`. Each alarm's
     `StateTransitionedTimestamp` from this read is the baseline every later read must match, so an alarm that fires
     and recovers between two reads aborts the run. A quiet read shows the alarm's configuration and state; that its
     source still reports is the owner's to qualify for each alarm within `observe_seconds`.
  5. Check that the stop may leave (`ready`): the snapshot's oldest time within its bound (cause `reach`); the clocks
     within SKEW_SECONDS of each other, more than the observation and one POLL_SECONDS left before the deadline, and
     the wall clock after the snapshot's cut, inside the run window and SKEW_SECONDS before the approval's lapse
     (cause `deadline`). Write `stop.json` with the time that check read, then read the alarms again and check again,
     then send the stop request once, with the CLI's retries off, cut at half the effect timeout so the polls keep the
     other half. Its reply is never evidence; a request that never left aborts the run with cause `stop-not-shown`.
  6. Poll the alarms and the target's status, at once and then after a pause of POLL_SECONDS. On `stopped`, read at or
     after the request and before the run window's end, read `describe-instances`: a record of the instance stopped by
     a user-initiated shutdown shows the stop when its transition second lies whole in the stop call's window, from
     SKEW_SECONDS before its launch to SKEW_SECONDS after its return, and both reads end within
     `effect_timeout_seconds` of the request. With no such pair, the abort path runs with cause `stop-not-shown`. A
     match is a correlation of time and reason; it names no caller.
  7. Poll the alarms for `observe_seconds`, ending with a read that starts at or after its end, then write
     `stopped.json` with the time of step 6's status read and exit 0 with the restoration pending. `stopped.json`
     stands only after the observation or after `abort.json`, so a run killed between the stop and either leaves
     `stop.json` alone, which `restore` refuses as an unknown outcome and the judge reads as not injected.
A status read that fails in step 6 shows nothing and the poll goes on. An alarm read that fails, an alarm missing from
the reply and one not quiet each abort the run; a failed read of all of them names GD-2's first guardrail text (the
abort mark names one text for cause `guardrail`), and its detail says that no alarm was read. Step 6 cuts its alarm
reads at the effect timeout too: one that fails at or after it shows no stop, and the cause is `stop-not-shown`.

The abort path, the one end of a run once `roles.json` stands, for the reach condition, a guardrail alarm, the
deadline (`deadline_seconds` after the run's start), an exception and a signal (SIGINT, SIGTERM, SIGHUP, each not
ignored at start): it writes `abort.json` {cause, guardrail, time, detail}, the detail saying whether no stop request
was sent, one was sent and answered, or one may have left with its outcome unknown and the call's failure, and ending
with `; restoration steps sha256 ` and the SHA-256 of the restoration steps text this run prints, and then
`stopped.json` when the stop was shown. It reads the target's status once when a request may have left, prints that
read and GD-2's restoration steps from the catalog, and exits 1. It sends no call that changes an instance, and the
controller holds no call that starts one. A signal raises only before `injection/` is made (exit 2; one that arrives
before step 1 waits for it) and in steps 3 to 7 (the abort path); during a mark's write it waits for the write's end,
and during the abort path and the final `stopped.json` it is left unraised. In `restore` a signal raises during the
poll; in `seal` it raises from the lock to the mark's write, which writes nothing (exit 2), and waits for that write.

`restore`, run by the operator after starting the instance themselves, refuses: an evidence root or `injection/` that
is a link, no directory or one that takes no unnamed file; a missing or malformed `stop.json`, or one of another
instance or identity than the approval's target and the operator file's `identity`; an existing `restoration.json`;
evidence a run or restore still holds; a `restoration.json`, `stopped.json` or `abort.json` whose lookup fails, which
leaves unknown whether the mark stands; neither `stopped.json` nor `abort.json` (a run that ended unrecorded, whose
outcome is unknown); a `roles.json` of another package than the approval's; a `stopped.json` that does not show this
stop read from the request's time to restore's start; with no abort, a `--reviewed`; with `abort.json` standing, an
abort dated before the stop, an abort mark whose detail does not end with its run's steps digest, a missing,
mismatched or future `--reviewed`, or one inside DIR; and a wrong caller. It reads `stopped.json` before
`abort.json`, since the abort path writes `abort.json` first. The reviewed record is the
operator's {abort_sha256, steps, reviewer, time}, kept outside DIR, since the judge admits no file outside its layout:
GD-2's restoration steps as the aborted run printed them (`steps`, the text whose SHA-256 ends that abort mark's
detail, the one text `restore` compares it with) were done, at `time`, from the abort's time to restore's start, after
the abort whose `abort.json` bytes `abort_sha256` digests. It then requires the caller as `run` does and polls the
target's status for up to `deadline_seconds` until a read dated at or after restore's start shows it running with the
instance and system checks `ok` and the target's record, read after that read, dates its return. The record's
`LaunchTime` L is the time of the instance's last launch on AWS's clock, so on this clock the launch lies within
SKEW_SECONDS of L. `restore` writes `restoration.json` {instance, state, time, reviewed_sha256}: `time` the later of
L - SKEW_SECONDS, the earliest time at which the target may have run again, and the latest time among the stop request,
the stopped report and the abort mark, which the judge requires it to reach; `reviewed_sha256` the SHA-256 of the
reviewed record's bytes after an abort and null otherwise. A record dates no return when it is unread, reads a state
other than `running`, names no `LaunchTime` in the form the calls paragraph states, dates the launch more than
SKEW_SECONDS before the stopped report (it shows no start after the stop) or more than SKEW_SECONDS after the ready
read. The poll then goes on, and at its bound `restore` exits 1 with no mark and says that the evidence is not to be
judged as it stands, since the judge reads the whole run window where no restoration stands. Where no `stopped.json`
stands, an abort whose stop was never shown, an earlier launch is admitted and the time is the abort's. The judge ends
its observation at a restoration dated inside the run window, and `time` may precede the start by 2 * SKEW_SECONDS and
the second `LaunchTime` leaves out, so a start less than that after the run window's end may be dated inside it.
`restore` reads and writes the marks by the pathname `DIR/injection`: its lock excludes a run and another restore of
the directory it opened, keeping that directory under that name until `restore` ends is the operator's, and exit 0
says the mark stands in the directory so named when the mark was linked.

`seal`, run by the operator once the run window has ended and every collection named in `DIR/coverage.json` is in
DIR, makes no AWS call and refuses: an evidence root or `injection/` that is a link, no directory or one that takes no
unnamed file; evidence a run, restore or seal still holds; an existing `collected.json`; a `records/` that is a link
or no directory; a `package.json` whose SHA-256 is not the approval's, of kind other than `staging` (a simulation
export seals its own files), or a `roles.json` of another package; a wall clock before the package's run window ends;
a `coverage.json` off the judge's layout or naming other files than the package's collected files (the judge's
`collected`: each `records/` file, `activations.jsonl`, `witness.jsonl` and each observation file of its world); a
collected file missing, malformed, holding another line count than its coverage entry or spanned past the seal's time;
an entry of DIR or `records/` outside the judge's layout, which the judge refuses when it lists them; a file or
directory sync that fails; and any evidence the judge's `load_evidence` refuses, run over the bytes it read
with the mark it would write. It reads every file relative to the descriptor of its directory, following no link, and
syncs each file it reads, then `records/` and DIR, before the mark. It writes `collected.json` {time, files}: `time`
the wall clock read at its start, at or after the run window's end, and `files` the SHA-256 of `coverage.json` and of
each collected file's bytes as it read them; it prints the mark's own SHA-256, also (exit 1) for a mark it linked
whose sync then failed, which stands or may stand again after a crash. The judge refuses a file whose bytes
differ from that digest, so a row removed from a collection after the seal, with its count lowered to match, is
refused. A collection short before the seal stays the collector's declaration, and a seal removed and written again
reads as the first, so the operator keeps the printed digest, which the judge's record carries. `seal` checks for an
existing mark and links its own by the pathname `DIR/injection`, as `restore` does, and keeping DIR under that name
until `seal` ends is the operator's.

The marks, in the judge's field names, each written once by `publish`: an unnamed file in `injection/`, synced, linked
to the mark's name (failing when an entry stands there), synced again, then the directory synced; when a sync after
the link fails the mark is removed again, and when the removal fails it stands with its durability unknown, as the
controller says. roles.json {package_sha256, time, shards, standbys}, `time` the snapshot's cut and `standbys` each
standby host of the target's owned shards whose snapshot line names a declared instance; stop.json {instance, time,
identity}; stopped.json {instance, state, time, request}; abort.json, its detail DETAIL_MAX characters at most, cut
ahead of the steps' digest; restoration.json; collected.json. Each is at most the judge's file size. Nothing is
written outside DIR/injection.

The five calls, each made through `Controller.aws` and the one process launch of `aws_cli`, and the fields read: `sts
get-caller-identity` (Arn); `ec2 describe-instance-status --include-all-instances` (InstanceStatuses[]: InstanceId,
InstanceState.Name, InstanceStatus.Status, SystemStatus.Status); `ec2 describe-instances` (Reservations[].Instances[]:
InstanceId, State.Name, StateReason.Code, StateTransitionReason, and for `restore` LaunchTime, a UTC time
`YYYY-MM-DDTHH:MM:SS` with an optional fraction of up to nine digits and then `Z` or `+00:00`); `ec2 stop-instances`
(none); `cloudwatch describe-alarms --alarm-types MetricAlarm` (MetricAlarms[]: AlarmName, StateValue,
TreatMissingData, EvaluationState, StateTransitionedTimestamp, EvaluationCriteria, Metrics[].Expression).
Each runs with `--no-paginate` (a split listing shows its `NextToken`) and configured endpoint URLs ignored, under the
environment the run read at its start, so all five use one profile and one set of credentials. A reply that is no JSON
object, holds a `NextToken`, names an instance or alarm twice or outside the request, holds a composite alarm, or
holds a read field off its type counts as a failed call, whose outcome is unknown.

Exit 0: a run ended with the restoration pending, a restoration written, or a seal written. 1: an abort, a
restoration not shown within its bound, cut by a signal or unwritten, or a seal unwritten or left standing with its
durability unknown, which a later `seal` refuses as existing and the judge reads. 2: a refusal or a signal
before `roles.json` stands, which leave no mark, or a failure the controller did not foresee, whose message names the
marks that stand.
"""

import argparse
import calendar
import contextlib
import errno
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import re
import signal
import stat
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    """The module at `path`, run with bytecode writes off for it and the modules it loads."""
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    previous, sys.dont_write_bytecode = sys.dont_write_bytecode, True
    try:
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module


judge = load("gameday_judge", HERE / "gameday-judge.py")
fis = load("fis_controller", HERE / "fis-controller.py")
readiness = load("readiness", HERE / "readiness.py")
need, Refusal = judge.need, judge.Refusal

AWS = "aws"
ACTION = "stop the instance of one host that owns several shards and is the named standby of others"
RESTORATION = "persistent-manual"
BOUNDS = ("snapshot_max_age_seconds", "effect_timeout_seconds", "observe_seconds", "deadline_seconds")
OPERATOR = {"region": "name", "identity": "name", "instances": ["name"], "snapshot": "name",
            "approval": {"approver": "name", "package_sha256": "digest", "instance": "name", "not_after": "name"},
            "alarms": judge.Each("guardrail", "name", True), **dict.fromkeys(BOUNDS, "positive")}
SHARD_LINE = {"shard": "shard", "time": "time", **judge.VERSION}
REVIEWED = {"abort_sha256": "digest", "steps": "name", "reviewer": "name", "time": "time"}
# Working values: the longest bound an operator file may set, the pause between polls, the longest one CLI call may
# take, the clock difference admitted between the controller and the control plane, and the longest abort detail.
LIMIT_SECONDS, POLL_SECONDS, CALL_SECONDS, SKEW_SECONDS, DETAIL_MAX = 86400, 5, 60, 5, 4000
MAX_INSTANCES, ALARM_NAME_MAX = 100, 255
MARK_LIMIT = judge.FILE_LIMIT
# The ways a metric alarm may treat missing data, stated in its row, and still read ALARM or INSUFFICIENT_DATA without
# data.
MISSING_DATA = ("missing", "breaching")
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
REGION = re.compile(r"[a-z]{2}(-[a-z]+)+-[0-9]+")
INSTANCE = re.compile(r"i-[0-9a-z]{1,17}")
ISO = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9]Z")
USER_STOP = re.compile(r"User initiated \(([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-5][0-9]) GMT\)")
USER_SHUTDOWN = "Client.UserInitiatedShutdown"
STEPS_TAIL = re.compile(r"; restoration steps sha256 [0-9a-f]{64}")
LAUNCH = re.compile(r"([0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-5][0-9])(\.[0-9]{1,9})?(?:Z|\+00:00)")
HEALTH = {True: "healthy", False: "unhealthy", None: "no report"}


class CallFailed(Exception):
    """A call whose outcome is unknown: the CLI failed or timed out, or its reply is off the shape the header states."""


class Aborted(Exception):
    """A cause of the abort path other than an exception or a signal, with the guardrail text it names and a detail."""

    def __init__(self, cause, guardrail=None, detail=None):
        super().__init__(detail or cause)
        self.cause, self.guardrail, self.detail = cause, guardrail, detail


class Interrupted(BaseException):
    """A process signal, raised by the handler; a BaseException, so no `except Exception` keeps it from the abort."""

    def __init__(self, signum):
        super().__init__(signal.Signals(signum).name)


class Unwritten(Exception):
    """A mark `publish` left not durable: removed again, or, when `stands`, linked with its durability unknown."""

    def __init__(self, message, stands=False):
        super().__init__(message)
        self.stands = stands


def say(text, err=False):
    """Prints one status line; a failing stream (a closed pipe, EIO, an unencodable text) changes no outcome."""
    with contextlib.suppress(OSError, ValueError):
        print(text, file=sys.stderr if err else sys.stdout, flush=True)


def aws_cli(argv, retry, timeout, env):
    """Runs the AWS CLI once as the header's five calls state, under `env`, one attempt when `retry` is false, and
    returns its JSON object reply; every other outcome raises CallFailed."""
    # `env` is the environment the run read at its start, so every call carries one set of credentials and one profile.
    env = dict(env, AWS_PAGER="", AWS_CLI_AUTO_PROMPT="off", AWS_IGNORE_CONFIGURED_ENDPOINT_URLS="true")
    if not retry:
        env.update(AWS_MAX_ATTEMPTS="1", AWS_RETRY_MODE="standard")
    cut, what = str(max(1, math.ceil(timeout))), " ".join(argv[:2])
    command = [AWS, *argv, "--no-paginate", "--output", "json", "--cli-read-timeout", cut, "--cli-connect-timeout",
               cut]
    try:
        done = subprocess.run(command, stdin=subprocess.DEVNULL, capture_output=True, encoding="utf-8",
                              timeout=timeout, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired, ValueError) as error:
        raise CallFailed(f"{what} gave no answer: {error}") from error
    if done.returncode != 0:
        raise CallFailed(f"{what} exited {done.returncode}: {done.stderr.strip()[-400:]}")
    try:
        reply = judge.decode(done.stdout, f"the reply of {what}")
    except Refusal as error:
        raise CallFailed(str(error)) from error
    if not isinstance(reply, dict):
        raise CallFailed(f"the reply of {what} is no JSON object")
    return reply


def field(value, kind, what):
    """`value` when it is a `kind`, else CallFailed naming `what`."""
    if not isinstance(value, kind):
        raise CallFailed(f"{what} is no {kind.__name__}: {value!r}"[:400])
    return value


def nested(row, outer, inner, optional=False):
    """The text `row[outer][inner]`; None when `optional` and `row` holds no `outer`."""
    if optional and row.get(outer) is None:
        return None
    return field(field(row.get(outer), dict, outer).get(inner), str, f"{outer}.{inner}")


def whole(reply, what):
    if reply.get("NextToken") is not None:
        raise CallFailed(f"{what} holds a NextToken, so its listing is partial")


def read_statuses(reply, instances):
    """{instance: {state, instance, system}} for exactly `instances`; a check the reply leaves out reads None."""
    whole(reply, "describe-instance-status")
    found = {}
    for row in field(reply.get("InstanceStatuses"), list, "InstanceStatuses"):
        instance = field(field(row, dict, "an instance status").get("InstanceId"), str, "InstanceId")
        if instance in found:
            raise CallFailed(f"describe-instance-status names {instance} twice")
        found[instance] = {"state": nested(row, "InstanceState", "Name"),
                           "instance": nested(row, "InstanceStatus", "Status", optional=True),
                           "system": nested(row, "SystemStatus", "Status", optional=True)}
    if set(found) != set(instances):
        raise CallFailed(f"describe-instance-status names {sorted(found)}, not {sorted(instances)}")
    return found


def read_record(reply, instance):
    """{state, code, transition} of the one instance a describe-instances reply names, which must be `instance`."""
    whole(reply, "describe-instances")
    rows = [row for reservation in field(reply.get("Reservations"), list, "Reservations")
            for row in field(field(reservation, dict, "a reservation").get("Instances"), list, "Instances")]
    if len(rows) != 1 or field(rows[0], dict, "an instance").get("InstanceId") != instance:
        raise CallFailed(f"describe-instances names {len(rows)} instances, not {instance} alone")
    row = rows[0]
    return {"state": nested(row, "State", "Name"), "code": nested(row, "StateReason", "Code", optional=True),
            "transition": field(row.get("StateTransitionReason", ""), str, "StateTransitionReason"),
            "launch": optional_text(row, "LaunchTime")}


def launch_time(text):
    """The POSIX seconds of a record's LaunchTime `text`, a UTC time as the header's calls paragraph states it; any
    other text, and None for a record that names none, is a failed call."""
    found = LAUNCH.fullmatch(text or "")
    if found is None:
        raise CallFailed(f"LaunchTime {text!r} is no UTC time YYYY-MM-DDTHH:MM:SS[.fraction] ending in Z or +00:00")
    try:
        return calendar.timegm(time.strptime(found.group(1), "%Y-%m-%dT%H:%M:%S")) + float(found.group(2) or 0)
    except ValueError as error:
        raise CallFailed(f"LaunchTime {text!r} is no calendar time") from error


def optional_text(row, key):
    """The text `row[key]`, or None when `row` holds no `key`; a key present with another value is a failed call."""
    return None if key not in row else field(row[key], str, key)


def query_kind(row):
    """What makes `row` an alarm that can read OK while its source is silent (a PromQL query, a metric query
    expression, a percentile ignoring a low sample count), whatever it treats missing data as; else None."""
    if "EvaluationCriteria" in row:
        return "a PromQL alarm"
    for query in field(row.get("Metrics", []), list, "Metrics"):
        if optional_text(field(query, dict, "a metric query"), "Expression") is not None:
            return "an alarm on a metric query expression"
    if optional_text(row, "EvaluateLowSampleCountPercentile") == "ignore":
        return "a percentile alarm that ignores a low sample count"
    return None


def read_alarms(reply, names):
    """{alarm name: {state, missing, evaluation, transitioned, kind}} of metric alarms, none twice or outside `names`;
    `missing` and `evaluation` read None when left out, and every other read field must be text."""
    whole(reply, "describe-alarms")
    if field(reply.get("CompositeAlarms", []), list, "CompositeAlarms"):
        raise CallFailed("describe-alarms names a composite alarm, which can read OK while its children have no data")
    alarms = {}
    for row in field(reply.get("MetricAlarms", []), list, "MetricAlarms"):
        name = field(field(row, dict, "an alarm").get("AlarmName"), str, "AlarmName")
        if name in alarms or name not in names:
            raise CallFailed(f"describe-alarms names {name} twice or unasked")
        missing = row.get("TreatMissingData")
        alarms[name] = {"state": field(row.get("StateValue"), str, "StateValue"),
                        "missing": None if missing is None else field(missing, str, "TreatMissingData"),
                        "evaluation": optional_text(row, "EvaluationState"), "kind": query_kind(row),
                        "transitioned": field(row.get("StateTransitionedTimestamp"), str,
                                              "StateTransitionedTimestamp")}
    return alarms


def read_bytes(path, what):
    """The bytes of the regular file at `path`, at most the judge's FILE_LIMIT of them, or a Refusal. The file opens
    without following a link and without blocking, so a named pipe is refused as no regular file."""
    try:
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as handle:
            need(stat.S_ISREG(os.fstat(handle.fileno()).st_mode), f"{what} is no regular file")
            data = handle.read(judge.FILE_LIMIT + 1)
    except OSError as error:
        raise Refusal(f"{what} cannot be read: {error.strerror}") from error
    except ValueError as error:
        raise Refusal(f"{what} has a path no file can have: {error}") from error
    need(len(data) <= judge.FILE_LIMIT, f"{what} holds more than {judge.FILE_LIMIT} bytes")
    return data


def read_json(path, what):
    return judge.parsed(read_bytes(path, what), what)


def stands(path, what):
    """Whether an entry stands at `path`, by a lookup of the path itself, which reads a link as an entry. A lookup
    error other than a missing entry leaves the answer unknown and raises a Refusal."""
    try:
        os.lstat(path)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise Refusal(f"{what} cannot be looked up: {error.strerror}") from error
    return True


def encoded(value, what):
    """The bytes a mark of `value` holds, or a Refusal when they pass the judge's file size."""
    data = (json.dumps(value, indent=1, sort_keys=True) + "\n").encode("utf-8")
    need(len(data) <= MARK_LIMIT, f"{what} would hold {len(data)} bytes, more than the judge reads ({MARK_LIMIT})")
    return data


def sync(directory_fd):
    os.fsync(directory_fd)


def publish(path, data):
    """Writes the mark `data` at `path` once, as the header's marks paragraph states (synced again once named, since
    btrfs logs an inode in full only then); FileExistsError when an entry stands there."""
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        handle = os.open(".", os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC, 0o644, dir_fd=directory)
        linked = False
        try:
            view = memoryview(data)
            while view:
                written = os.write(handle, view)
                if written <= 0:
                    raise OSError(errno.EIO, f"a write of {path.name} made no progress")
                view = view[written:]
            os.fsync(handle)
            os.link(f"/proc/self/fd/{handle}", path.name, dst_dir_fd=directory, follow_symlinks=True)
            linked = True
            os.fsync(handle)
            sync(directory)
        except OSError as error:
            if not linked:
                raise
            withdraw(directory, path, error)
        finally:
            # The data is synced before the link; Linux frees the descriptor even when close reports an error.
            with contextlib.suppress(OSError):
                os.close(handle)
    finally:
        with contextlib.suppress(OSError):
            os.close(directory)


def withdraw(directory, path, error):
    """Removes the mark at `path` after `error`, a failed sync once linked, and raises Unwritten, with `stands` when
    the removal fails and the mark stays linked with its durability unknown."""
    try:
        os.unlink(path.name, dir_fd=directory)
    except OSError:
        raise Unwritten(f"{path} stands, but it cannot be synced ({error.strerror}) and cannot be removed, so it may "
                        "not survive a crash", stands=True) from error
    try:
        sync(directory)
    except OSError:
        raise Unwritten(f"{path} cannot be synced ({error.strerror}), so it is removed; the removal is unsynced, so "
                        "the mark may stand again after a crash") from error
    raise Unwritten(f"{path} cannot be synced, so the mark is removed: {error.strerror}") from error


def instance_id(value, what):
    need(isinstance(value, str) and INSTANCE.fullmatch(value) is not None, f"{what} is no instance ID: {value!r}")
    return value


def iso_time(value, what):
    """The POSIX seconds of an ISO time `YYYY-MM-DDTHH:MM:SSZ` with seconds 00 to 59."""
    need(isinstance(value, str) and ISO.fullmatch(value) is not None, f"{what} {value!r} is no time "
         "YYYY-MM-DDTHH:MM:SSZ")
    try:
        return calendar.timegm(time.strptime(value, "%Y-%m-%dT%H:%M:%SZ"))
    except ValueError as error:
        raise Refusal(f"{what} {value!r} is no calendar time") from error


def gd2_of(catalog):
    """GD-2 of the catalog with the texts the judge and this controller were written from, or a Refusal."""
    gd2 = judge.gd2_entry(catalog)
    need(isinstance(gd2.get("injection"), dict) and gd2["injection"].get("action") == ACTION, "GD-2's injection "
         "action differs from the action this controller was written for")
    restoration = gd2.get("restoration")
    need(isinstance(restoration, dict) and restoration.get("class") == RESTORATION
         and isinstance(restoration.get("steps"), str) and restoration["steps"].strip()
         and judge.encodable(restoration["steps"]), f"GD-2's restoration is not "
         f"of class {RESTORATION} with its steps")
    return gd2


def steps_tail(steps):
    """The end of an abort mark's detail, which STEPS_TAIL matches: the SHA-256 of the restoration steps text `steps`
    that the aborting run prints."""
    return f"; restoration steps sha256 {hashlib.sha256(steps.encode('utf-8')).hexdigest()}"


def plain(text):
    """Whether `text` holds no control character and has a UTF-8 form (no lone surrogate)."""
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return not any(ord(c) < 0x20 or ord(c) == 0x7F for c in text)


def read_operator(path, gd2):
    """The operator file at `path`, checked against the header's shape and bounds, or a Refusal."""
    o = read_json(path, "the operator file")
    need(isinstance(o, dict) and isinstance(o.get("approval"), dict), "the operator file holds no approval of this run")
    judge.conform(o, OPERATOR, "the operator file", {"guardrail": set(gd2["guardrail"])})
    need(REGION.fullmatch(o["region"]) is not None, f"region {o['region']!r} is no AWS region name")
    instance_id(o["approval"]["instance"], "approval instance")
    iso_time(o["approval"]["not_after"], "approval not_after")
    instances = [instance_id(v, f"instances[{i}]") for i, v in enumerate(o["instances"])]
    need(0 < len(instances) <= MAX_INSTANCES, f"instances holds {len(instances)} IDs, not 1 to {MAX_INSTANCES}")
    need(len(set(instances)) == len(instances), "instances repeats an instance")
    for bound in BOUNDS:
        need(o[bound] <= LIMIT_SECONDS, f"{bound} {o[bound]} is past its limit of {LIMIT_SECONDS} s")
    need(o["effect_timeout_seconds"] + o["observe_seconds"] <= o["deadline_seconds"], "deadline_seconds holds less "
         "than effect_timeout_seconds and observe_seconds together")
    for text, alarm in o["alarms"].items():
        need(len(alarm) <= ALARM_NAME_MAX and not alarm.startswith("-") and alarm.strip() == alarm, f"the alarm of "
             f"{text!r} is no alarm name: {alarm!r}")
    need(len(set(o["alarms"].values())) == len(o["alarms"]), "alarms names one alarm for two guardrails")
    for what, text in (("snapshot", o["snapshot"]), *((f"the alarm of {k!r}", v) for k, v in o["alarms"].items())):
        need(plain(text), f"{what} holds a control character or text with no UTF-8 form: {text!r}")
    o["snapshot"] = os.path.join(os.path.dirname(os.path.abspath(path)), o["snapshot"])
    return o


def check_run(raw, operator, now):
    """Step 1 on the package's bytes at the wall-clock start `now`: (package, names, sha256, instance), or a Refusal."""
    p = judge.parsed(raw, "package.json")
    need(isinstance(p, dict), "the package is no object")
    names = judge.check_package(p)
    need(p["kind"] == "staging", f"the package is of kind {p['kind']}: only a staging run stops an instance")
    package_sha256, approval = hashlib.sha256(raw).hexdigest(), operator["approval"]
    instance = instance_id(p["target"]["instance"], "the package's target instance")
    end = now + operator["deadline_seconds"]
    need(approval["package_sha256"] == package_sha256, "the approval names another package digest")
    need(approval["instance"] == instance, f"the approval names instance {approval['instance']}, not the target "
         f"{instance}")
    need(end + SKEW_SECONDS <= iso_time(approval["not_after"], "approval not_after"), f"the approval lapses at "
         f"{approval['not_after']}, less than {SKEW_SECONDS} s after the run's deadline")
    need(p["baseline"]["end"] <= now, f"the run's start {now} lies inside the package's baseline window "
         f"{p['baseline']}")
    need(p["run"]["start"] <= now and end <= p["run"]["end"], f"the run from {now} to its deadline {end} lies "
         f"outside the package's run window {p['run']}")
    need(instance in operator["instances"], f"the target {instance} is outside the declared set")
    return p, names, package_sha256, instance


def read_snapshot(operator, package, names, now):
    """({shard: version}, {host: line}, cut, oldest) of the snapshot read at wall time `now`: `cut` the shard lines'
    one read time and `oldest` its earliest time; or a Refusal."""
    root, oldest = operator["snapshot"], now - operator["snapshot_max_age_seconds"]

    def fresh(t, what):
        need(oldest <= t <= now, f"{what} {t} lies outside [{oldest}, {now}]: the snapshot is stale or ahead")
        return t

    def lines(name):
        return enumerate(judge.parsed(read_bytes(os.path.join(root, name), name), name), 1)

    records, reports, times = {}, {}, set()
    for i, row in lines("shards.jsonl"):
        what = f"shards.jsonl line {i}"
        judge.conform(row, SHARD_LINE, what, names)
        need(row["shard"] not in records, f"{what} repeats shard {row['shard']}")
        times.add(fresh(row["time"], f"{what} time"))
        records[row["shard"]] = {k: row[k] for k in judge.VERSION}
    need(set(records) == set(package["shards"]), f"shards.jsonl misses shards "
         f"{sorted(set(package['shards']) - set(records))}")
    need(len(times) == 1, f"shards.jsonl holds read times {sorted(times)}, not one cut")
    (cut,), earliest = times, set(times)
    need(package["baseline"]["start"] <= cut, f"shards.jsonl's cut {cut} lies before the baseline window starts")
    for i, row in lines("hosts.jsonl"):
        what = f"hosts.jsonl line {i}"
        need(isinstance(row, dict) and set(row) == {"host", "instance", "report"}, f"{what} holds other keys than "
             "host, instance and report")
        need(isinstance(row["host"], str) and row["host"] in names["host"] and row["host"] not in reports,
             f"{what} names no host of the package or repeats one")
        instance_id(row["instance"], f"{what} instance")
        report = row["report"]
        if report is not None:
            need(isinstance(report, dict) and set(report) == {"time", "healthy"} and judge.finite(report["time"])
                 and isinstance(report["healthy"], bool), f"{what} report is neither null nor {{time, healthy}}")
            earliest.add(fresh(report["time"], f"{what} report time"))
        reports[row["host"]] = row
    need(len({r["instance"] for r in reports.values()}) == len(reports), "hosts.jsonl names one instance twice")
    target = package["target"]
    need(reports.get(target["host"], {}).get("instance") == target["instance"], "hosts.jsonl does not name the "
         "package's target instance for the target host")
    owned = {s for s in package["shards"] if records[s]["owner"] == target["host"]}
    keyed = {w["shard"] for w in package["witness"]}
    need(owned <= keyed, f"owned shards {sorted(owned - keyed)} have no witness key in the package, so the judge "
         "would refuse the run's evidence")
    need(keyed <= owned, f"the package's witness keys name shards {sorted(keyed - owned)} the target does not own, "
         "so the judge would refuse the run's evidence")
    return records, reports, cut, min(earliest)


def build_roles(package, names, package_sha256, records, reports, states, cut):
    """roles.json at the snapshot's cut, its `standbys` as the header's marks paragraph states."""
    target, standbys = package["target"]["host"], {}
    for s in package["shards"]:
        host = records[s]["standby"]
        row = reports.get(host)
        if records[s]["owner"] == target and host not in (None, target) and row and row["instance"] in states:
            report = row["report"]
            standbys[host] = {"instance": row["instance"], "instance_state": states[row["instance"]]["state"],
                              "host_report": HEALTH[None if report is None else report["healthy"]]}
    roles = {"package_sha256": package_sha256, "time": cut, "shards": records, "standbys": standbys}
    judge.conform(roles, judge.LAYOUT["injection/roles.json"][0], "injection/roles.json", names)
    return roles


def check_reviewed(reviewed, abort_path, evidence, now, stop):
    """(the SHA-256 of the reviewed record at `reviewed`, the abort's time). The record must lie outside `evidence`
    and name the bytes of `abort_path` and the steps whose digest ends that mark's detail, at a time from the abort's
    to `now`, for an abort dated no earlier than `stop`, the stop mark it closes; else a Refusal. The abort is tied
    to the stop by time order alone, since the judge's abort mark names no request."""
    need(reviewed is not None, "an abort stands: restore needs --reviewed, the operator's record that GD-2's "
         "restoration steps were done")
    root = os.path.realpath(evidence)
    need(os.path.commonpath([root, os.path.realpath(reviewed)]) != root, "the reviewed record lies inside the "
         "evidence directory, where the judge admits no file outside its layout; keep it outside")
    raw, abort_raw = read_bytes(reviewed, "the reviewed record"), read_bytes(abort_path, "abort.json")
    record = judge.parsed(raw, "the reviewed record")
    judge.conform(record, REVIEWED, "the reviewed record", {})
    abort = judge.parsed(abort_raw, "injection/abort.json")
    judge.conform(abort, judge.LAYOUT["injection/abort.json"][0], "injection/abort.json", {})
    need((abort["cause"] == "guardrail") == (abort["guardrail"] is not None), "injection/abort.json names a guardrail "
         "without cause guardrail, or none with it, which the judge refuses")
    need(record["abort_sha256"] == hashlib.sha256(abort_raw).hexdigest(), "the reviewed record names another abort")
    tail = (abort["detail"] or "")[-len(steps_tail("")):]
    need(STEPS_TAIL.fullmatch(tail) is not None, "injection/abort.json's detail does not end with the digest of the "
         "restoration steps its run printed, so no review can be compared with it")
    need(tail == steps_tail(record["steps"]), "the reviewed record names steps other than those the aborted run "
         "printed")
    need(abort["time"] >= stop["time"], "injection/abort.json is dated before the stop it would close")
    need(record["time"] >= abort["time"], "the reviewed record is dated before the abort it reviews")
    need(record["time"] <= now, f"the reviewed record is dated {record['time']}, after restore's start {now}")
    return hashlib.sha256(raw).hexdigest(), abort["time"]


def check_stopped(stopped_path, stop, now):
    """The time of the stopped.json at `stopped_path`. Refuses one off the judge's layout, one other than a report of
    `stop`'s instance stopped for exactly the request `stop` holds, and one read before that request's time or after
    `now`."""
    stopped = judge.parsed(read_bytes(stopped_path, "injection/stopped.json"), "injection/stopped.json")
    judge.conform(stopped, judge.LAYOUT["injection/stopped.json"][0], "injection/stopped.json", {})
    need((stopped["instance"], stopped["state"], stopped["request"]) == (stop["instance"], "stopped", stop)
         and stopped["time"] >= stop["time"], "injection/stopped.json shows no stop of injection/stop.json's request "
         "read at or after it")
    need(stopped["time"] <= now, f"injection/stopped.json is dated {stopped['time']}, after restore's start {now}")
    return stopped["time"]


class Controller:
    """One run, restoration or seal under one operator file, `env` the environment read when it is made. `call(argv, retry=, timeout=,
    env=)` runs one AWS CLI call, `clock` gives wall seconds, `elapsed` monotonic seconds and `sleep` passes seconds;
    the self-test replaces all four. `deadline` and every `until` are on the monotonic clock.

    A signal raises Interrupted only while `armed` and no mark is `held`; otherwise it waits in `pending`, and a hold
    ends by raising it only while armed. `armed` stands only inside code whose caller turns Interrupted into its end:
    the steps before `injection/` is made, `inject`, the restoration's poll and a seal's reads, so the abort path and
    every mark's write run unarmed."""

    def __init__(self, operator, gd2, call, clock, sleep, elapsed):
        self.operator, self.gd2, self.call, self.clock, self.sleep = operator, gd2, call, clock, sleep
        self.deadline = self.injection = self.instance = self.pending = self.shown = None
        self.package = self.fresh_until = self.transitions = self.stop_failure = self.lock = None
        self.cut = self.oldest = self.origin = self.request_at = self.launched = self.returned = None
        self.sent = self.answered = self.held = self.armed = False
        self.written, self.env, self.elapsed = [], dict(os.environ), elapsed

    def on_signal(self, signum, frame):
        if self.armed and not self.held:
            self.armed = False
            raise Interrupted(signum)
        self.pending = self.pending or signum

    def release(self):
        """Ends a hold and raises the signal that arrived during it, when armed."""
        self.held = False
        if self.pending is not None and self.armed:
            signum, self.pending, self.armed = self.pending, None, False
            raise Interrupted(signum)

    @contextlib.contextmanager
    def hold(self):
        self.held = True
        try:
            yield
        except BaseException:
            self.held = False
            raise
        self.release()

    def aws(self, argv, retry=True, until=None, mutating=False):
        """Every call's one path, cut at CALL_SECONDS, the deadline and `until`: one that starts, answers or fails past
        the deadline aborts. `mutating` turns `sent` true before the launch and keeps its times, failure and answer."""
        self.within_deadline()
        ends = [end - self.elapsed() for end in (self.deadline, until) if end is not None]
        timeout = min([CALL_SECONDS, *ends])
        if timeout <= 0:
            raise CallFailed(f"{' '.join(argv[:2])} has no time left before its window ends")
        if mutating:
            self.sent, self.launched = True, self.elapsed()
        try:
            reply = self.call((*argv, "--region", self.operator["region"]), retry=retry, timeout=timeout, env=self.env)
        except CallFailed as error:
            if mutating:
                self.returned, self.stop_failure = self.elapsed(), str(error)
            self.within_deadline()
            raise
        except BaseException:
            if mutating:
                self.returned = self.elapsed()
            raise
        if mutating:
            self.returned, self.answered = self.elapsed(), True
        self.within_deadline()
        return reply

    def within_deadline(self):
        if self.deadline is not None and self.elapsed() >= self.deadline:
            raise Aborted("deadline", detail=f"the deadline of {self.operator['deadline_seconds']} s passed")

    def statuses(self, instances, until=None):
        reply = self.aws(("ec2", "describe-instance-status", "--include-all-instances", "--instance-ids", *instances),
                         until=until)
        return read_statuses(reply, instances)

    def record(self, instance, until):
        return read_record(self.aws(("ec2", "describe-instances", "--instance-ids", instance), until=until), instance)

    def stop(self, until):
        """Reads the alarms and checks `ready` again once stop.json stands, then sends the stop request once, cut at
        `until`; a request that never left aborts the run, and one that may have left keeps its failure."""
        self.quiet()
        self.ready()
        try:
            self.aws(("ec2", "stop-instances", "--instance-ids", self.instance), retry=False, until=until,
                     mutating=True)
        except CallFailed as error:
            if not self.sent:
                raise Aborted("stop-not-shown", detail=f"the stop request never left: {error}") from error
            say(f"host-stop-controller: the stop request's outcome is unknown: {error}; the polls decide")

    def ready(self):
        """The wall time at which a stop request may leave, now, as the header's step 5 states; else raises
        Aborted."""
        package, deadline, fresh_until, origin = self.package, self.deadline, self.fresh_until, self.origin
        if package is None or deadline is None or fresh_until is None or origin is None:
            raise RuntimeError("a stop request is checked before the run's preflight")
        at = self.elapsed()
        now, left, bound = self.clock(), deadline - at, self.operator["snapshot_max_age_seconds"]
        if at > fresh_until or now - self.oldest > bound:
            raise Aborted("reach", detail=f"the snapshot passed its age bound of {bound} s before the stop request")
        drift = (now - origin[0]) - (at - origin[1])
        if abs(drift) > SKEW_SECONDS:
            raise Aborted("deadline", detail=f"the wall clock moved {drift:.1f} s apart from the monotonic clock since "
                          "the run's start")
        if left <= self.operator["observe_seconds"] + POLL_SECONDS:
            raise Aborted("deadline", detail=f"{left:.1f} s before the deadline cannot hold the observation of "
                          f"{self.operator['observe_seconds']} s and one poll")
        lapse, window = iso_time(self.operator["approval"]["not_after"], "approval not_after"), package["run"]
        if not (now + SKEW_SECONDS <= lapse and package["baseline"]["end"] <= now and self.cut < now
                and window["start"] <= now < window["end"]):
            raise Aborted("deadline", detail=f"the wall clock reads {now}, at or before the snapshot's cut, outside "
                          f"the run window {window} or past {SKEW_SECONDS} s before the approval's lapse "
                          f"{self.operator['approval']['not_after']}")
        return now

    def alarms(self, until=None):
        names = [self.operator["alarms"][text] for text in self.gd2["guardrail"]]
        return read_alarms(self.aws(("cloudwatch", "describe-alarms", "--alarm-types", "MetricAlarm",
                                     "--alarm-names", *names), until=until), names)

    def require_caller(self):
        try:
            arn = field(self.aws(("sts", "get-caller-identity")).get("Arn"), str, "Arn")
        except CallFailed as error:
            raise Refusal(f"the caller is unknown: {error}") from error
        need(arn == self.operator["identity"], f"the caller is {arn}, not {self.operator['identity']}")

    def quiet(self, until=None):
        """Returns when every guardrail's alarm is quiet as the header's step 4 states and, after the first read, holds
        the transition timestamp of that read; else raises Aborted naming the first guardrail unshown quiet. `until`
        cuts the read, and a read that fails at or after `until` raises its CallFailed in place of Aborted."""
        try:
            alarms = self.alarms(until)
        except CallFailed as error:
            if until is not None and self.elapsed() >= until:
                raise
            raise Aborted("guardrail", self.gd2["guardrail"][0], f"the alarms are unread, so no guardrail is shown "
                          f"quiet: {error}") from error
        for text in self.gd2["guardrail"]:
            name = self.operator["alarms"][text]
            alarm = alarms.get(name)
            if alarm is None or alarm["state"] != "OK":
                raise Aborted("guardrail", text, f"alarm {name} reads {alarm['state'] if alarm else 'no answer'}")
            if alarm["missing"] not in MISSING_DATA:
                raise Aborted("guardrail", text, f"alarm {name} treats missing data as {alarm['missing']}, so it can "
                              "read OK without data")
            if alarm["evaluation"] is not None:
                raise Aborted("guardrail", text, f"alarm {name} reads OK with evaluation state {alarm['evaluation']}")
            if alarm["kind"] is not None:
                raise Aborted("guardrail", text, f"alarm {name} is {alarm['kind']}, which reads OK without data")
            if self.transitions is not None and alarm["transitioned"] != self.transitions[name]:
                raise Aborted("guardrail", text, f"alarm {name} changed state at {alarm['transitioned']} since the "
                              f"read before the stop ({self.transitions[name]})")
        if self.transitions is None:
            self.transitions = {name: alarm["transitioned"] for name, alarm in alarms.items()}

    def pause(self, until):
        """Sleeps one poll period, or less when `until` or the deadline comes first."""
        if self.deadline is None:
            raise RuntimeError("a poll pauses with no deadline set")
        self.sleep(max(0, min(POLL_SECONDS, min(until, self.deadline) - self.elapsed())))

    def mark(self, name, value, names=None):
        """Writes the mark `name` once, with a signal held to the write's end, checked first against the judge's layout
        under `names` (roles.json in `build_roles`); one standing with its durability unknown counts as written."""
        if name != "roles":
            judge.conform(value, judge.LAYOUT[f"injection/{name}.json"][0], f"injection/{name}.json", names or {})
        data = encoded(value, f"injection/{name}.json")
        if self.injection is None:
            raise RuntimeError(f"the mark {name} has no injection directory to stand in")
        with self.hold():
            try:
                publish(self.injection / f"{name}.json", data)
            except Unwritten as error:
                if error.stands:
                    self.written.append(name)
                raise
            self.written.append(name)

    def run(self, package_path, evidence):
        """Steps 1 to 7 of the header; returns the exit code, or raises a Refusal or Interrupted while no mark
        stands."""
        self.armed = True
        try:
            self.release()
            at, start = self.elapsed(), self.clock()
            self.origin, self.deadline = (start, at), at + self.operator["deadline_seconds"]
            owed = self.gd2.get("prerequisites")
            need(isinstance(owed, list) and all(isinstance(text, str) and readiness.TBD not in text for text in owed),
                 f"GD-2's prerequisites are not all met, so the catalog blocks its execution: {owed!r}")
            raw = read_bytes(package_path, "the package")
            package, names, package_sha256, self.instance = check_run(raw, self.operator, start)
            self.package, root = package, Path(evidence)
            need(evidence != "" and root.is_dir() and not root.is_symlink(), f"{evidence!r} is no directory")
            need(not os.path.lexists(root / "injection"), f"{root / 'injection'} exists: a run's marks are written "
                 "once")
            probe(root)
            need(read_bytes(root / "package.json", f"{root / 'package.json'}") == raw, f"{root / 'package.json'} "
                 "holds other bytes than --package, so the judge would refuse the run's evidence")
            try:
                self.require_caller()
                at, now = self.elapsed(), self.clock()
                records, reports, self.cut, self.oldest = read_snapshot(self.operator, package, names, now)
                self.fresh_until = at + self.oldest + self.operator["snapshot_max_age_seconds"] - now
                try:
                    states = self.statuses(self.operator["instances"])
                except CallFailed as error:
                    raise Refusal(f"the declared instances' status is unknown: {error}") from error
                left_open = sorted(i for i, s in states.items() if s["state"] != "running")
                need(not left_open, f"declared instances {left_open} are not running: a run is left open")
                roles = build_roles(package, names, package_sha256, records, reports, states, self.cut)
                encoded(roles, "injection/roles.json")
                self.within_deadline()
            except Aborted as abort:
                raise Refusal(f"{abort} before injection/ was made") from abort
        finally:
            self.armed = False
        self.held = True
        try:
            os.mkdir(root / "injection")
        except OSError as error:
            self.held = False
            raise Refusal(f"{root / 'injection'} cannot be made: {error.strerror}") from error
        self.injection = root / "injection"
        try:
            try:
                self.lock = lock(self.injection)
                return self.inject(root, package, roles)
            except Aborted as abort:
                end = abort.cause, abort.guardrail, abort.detail
            except Interrupted as interrupted:
                end = "signal", None, f"signal {interrupted}"
            except Exception as error:
                end = "exception", None, f"{type(error).__name__}: {error}"
            if "roles" in self.written:
                return self.abort(*end)
        finally:
            unlock(self.lock)
        # No roles.json stands, so the judge reads no mark here: the run's own `injection/` goes, for another run.
        what = f"{end[2] or end[0]} before roles.json stood; {self.injection}"
        try:
            os.rmdir(self.injection)
            fis.sync_directory(root)
        except OSError as error:
            raise Refusal(f"{what} may stand, since its removal failed or is unsynced ({error.strerror}): remove it "
                          "before another run", written=True) from error
        raise Refusal(f"{what} is removed")

    def inject(self, root, package, roles):
        """Steps 3 to 7 once `injection/` stands under `root`, armed until the observation ends; the hold `run` starts
        before making `injection/` ends with the roles' write. `stopped.json` is written unarmed."""
        self.armed = True
        try:
            fis.sync_directory(root)
            self.mark("roles", roles)
            unmet = judge.roles_reach(roles, package)
            if unmet:
                raise Aborted("reach", detail="; ".join(unmet))
            self.quiet()
            self.request_at, effect = self.elapsed(), self.operator["effect_timeout_seconds"]
            request = {"instance": self.instance, "time": self.ready(), "identity": self.operator["identity"]}
            self.mark("stop", request)
            self.stop(self.request_at + effect / 2)
            self.shown = self.await_stop(request, self.request_at + effect)
            # The observation ends with an alarm read that starts at or after its end.
            end = self.elapsed() + self.operator["observe_seconds"]
            while True:
                self.pause(end)
                started = self.elapsed()
                self.quiet()
                if started >= end:
                    break
        finally:
            self.armed = False
        self.mark("stopped", self.shown)
        late = package["run"]["end"] + 2 * SKEW_SECONDS + 1
        say(f"host-stop-controller: {self.instance} stopped and observed for {self.operator['observe_seconds']} s; "
            "the restoration is pending and the alarms are no longer watched: start the instance, then run restore. "
            f"A start before {late} may be dated inside the run window, where the judge's observation then ends")
        return 0

    def await_stop(self, request, until):
        """stopped.json's value once step 6's two reads show the stop by `until`; else Aborted with cause
        stop-not-shown, naming the last read. The first poll runs at once."""
        if self.package is None:
            raise RuntimeError("the stop is awaited before the run's preflight")
        seen, first, run_end = "no status read was made", True, self.package["run"]["end"]
        while True:
            if not first:
                self.pause(until)
            first = False
            if self.elapsed() >= until:
                break
            try:
                self.quiet(until)
                state = self.statuses([self.instance], until)[self.instance]["state"]
            except CallFailed as error:
                seen = f"a read failed: {error}"
                continue
            at, seen = self.clock(), f"the target reads {state}"
            if state != "stopped":
                continue
            if not request["time"] <= at < run_end:
                seen = f"the target reads stopped at {at}, outside [the stop request, the run window's end)"
                continue
            try:
                record = self.record(self.instance, until)
            except CallFailed as error:
                seen = f"the target reads stopped and its record is unread: {error}"
                continue
            if self.elapsed() > until:
                seen = "the target reads stopped and its record answered past the effect timeout"
                break
            if self.confirms(record, request):
                return {"instance": self.instance, "state": "stopped", "time": at, "request": dict(request)}
            seen = f"the target reads stopped and its record {record} does not show the request"
        raise Aborted("stop-not-shown", detail=f"the stop was not shown within "
                      f"{self.operator['effect_timeout_seconds']} s: {seen}")

    def confirms(self, record, request):
        """Whether the record shows the stop as step 6 states, the window's ends the request's wall reading plus
        monotonic offsets and the record's whole second lying inside it; a malformed time confirms nothing."""
        found = USER_STOP.fullmatch(record["transition"])
        if record["state"] != "stopped" or record["code"] != USER_SHUTDOWN or found is None:
            return False
        try:
            at = calendar.timegm(time.strptime(found.group(1), "%Y-%m-%d %H:%M:%S"))
        except ValueError:
            return False
        if self.launched is None or self.returned is None or self.request_at is None:
            return False
        lower = request["time"] + (self.launched - self.request_at) - SKEW_SECONDS
        upper = request["time"] + (self.returned - self.request_at) + SKEW_SECONDS
        return lower <= at and at + 1 <= upper

    def abort(self, cause, guardrail, detail):
        """The header's abort path; returns 1. It makes no call that changes an instance."""
        self.deadline = None
        if not self.sent:
            sent = "no stop request was sent"
        elif self.answered:
            sent = "the stop request was sent and answered"
        else:
            sent = "a stop request may have left and its outcome is unknown" + (
                f": {self.stop_failure}" if self.stop_failure else "")
        # Whether a stop request was sent leads and the steps' digest ends the detail, so the cut keeps both whole.
        text, tail = f"{sent}; {detail}" if detail else sent, steps_tail(self.gd2["restoration"]["steps"])
        mark = {"cause": cause, "guardrail": guardrail, "time": self.clock(),
                "detail": text[:DETAIL_MAX - len(tail)] + tail}
        for name, value in (("abort", mark), ("stopped", self.shown)):
            if name == "stopped" and (value is None or "abort" not in self.written or "stopped" in self.written):
                continue
            try:
                self.mark(name, value)
            except Exception as error:
                standing = "stands with its durability unknown" if name in self.written else "is unwritten"
                say(f"host-stop-controller: {name}.json {standing}: {type(error).__name__}: {error}", err=True)
        say(f"host-stop-controller: aborted on {cause}" + (f" ({guardrail})" if guardrail else "")
            + f": {mark['detail']}")
        if self.sent:
            try:
                say(f"host-stop-controller: the target reads {self.statuses([self.instance])[self.instance]}")
            except Exception as error:
                say(f"host-stop-controller: the target's state is unknown: {type(error).__name__}: {error}")
        say(f"GD-2's restoration steps: {self.gd2['restoration']['steps']}")
        return 1

    def dated(self, at, floor, stopped_at):
        """(the restoration's time, None) once the target's record dates its return for a ready read at wall time
        `at`, else (None, what the record shows). The launch lies within SKEW_SECONDS of the record's LaunchTime on
        this clock, and the time is that interval's start, at least `floor`. A record of another state, a launch
        interval that ends before the stopped report at `stopped_at`, and one that starts after `at` date no return."""
        record = self.record(self.instance, None)
        launch = launch_time(record["launch"])
        if record["state"] != "running":
            return None, f"the target's record reads {record['state']}"
        if stopped_at is not None and launch + SKEW_SECONDS < stopped_at:
            return None, (f"the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s before "
                          f"the stopped report at {stopped_at}, so it shows no start after the stop")
        if launch - SKEW_SECONDS > at:
            return None, (f"the target's record dates its last launch at {launch}, more than {SKEW_SECONDS} s after "
                          f"the read at {at} that shows it running")
        return max(floor, launch - SKEW_SECONDS), None

    def restore(self, evidence, reviewed):
        """The header's `restore`, holding the evidence's lock from its first check of the outcome to its mark."""
        try:
            return self.restoration(evidence, reviewed)
        finally:
            unlock(self.lock)

    def restoration(self, evidence, reviewed):
        """Returns 0 with restoration.json written, 1 with none written, or raises a Refusal."""
        start, root = self.clock(), Path(evidence)
        injection = root / "injection"
        need(root.is_dir() and not root.is_symlink(), f"{evidence} is no directory")
        need(injection.is_dir() and not injection.is_symlink(), f"{injection} is no directory: no stop to restore "
             "from")
        probe(injection)
        stop = judge.parsed(read_bytes(injection / "stop.json", "injection/stop.json"), "injection/stop.json")
        judge.conform(stop, judge.REQUEST, "injection/stop.json", {})
        need(not stands(injection / "restoration.json", "injection/restoration.json"), "injection/restoration.json "
             "exists: the restoration is written once")
        self.instance = instance_id(stop["instance"], "injection/stop.json instance")
        need(self.instance in self.operator["instances"], f"the stop's instance {self.instance} is outside the "
             "declared set")
        need((self.instance, stop["identity"]) == (self.operator["approval"]["instance"], self.operator["identity"]),
             "injection/stop.json names another instance or identity than the approval's target and the operator's")
        self.lock = lock(injection)
        # stopped.json is read first: the abort path writes abort.json before it.
        shown = stands(injection / "stopped.json", "injection/stopped.json")
        aborted = stands(injection / "abort.json", "injection/abort.json")
        need(aborted or shown, "the run ended with neither stopped.json nor abort.json, so its outcome is unknown and "
             "restore records nothing; follow GD-2's restoration steps")
        roles = judge.parsed(read_bytes(injection / "roles.json", "injection/roles.json"), "injection/roles.json")
        need(isinstance(roles, dict) and roles.get("package_sha256") == self.operator["approval"]["package_sha256"],
             "injection/roles.json names another package than the approval's")
        stopped_at = check_stopped(injection / "stopped.json", stop, start) if shown else None
        if aborted:
            reviewed_sha256, aborted_at = check_reviewed(reviewed, injection / "abort.json", evidence, start, stop)
            say(f"host-stop-controller: reviewed record sha256 {reviewed_sha256}")
        else:
            need(reviewed is None, "--reviewed names a review of an abort, and no abort stands")
            reviewed_sha256 = aborted_at = None
        # `floor` is the latest mark's time, which the judge requires the restoration's time to reach.
        floor = max(t for t in (stop["time"], stopped_at, aborted_at) if t is not None)
        self.injection, seen, ready = injection, "no status read was made", None
        self.armed = True
        try:
            self.release()
            self.require_caller()
            self.deadline = self.elapsed() + self.operator["deadline_seconds"]
            while self.elapsed() < self.deadline:
                try:
                    status = self.statuses([self.instance])[self.instance]
                    at, seen = self.clock(), f"the target reads {status}"
                    if (status["state"], status["instance"], status["system"]) == ("running", "ok", "ok"):
                        # The checks above refuse a mark dated after `start`, so a read dated at or after `start` is
                        # at least as late as each mark. A read dated before `start` shows the wall clock stepped
                        # back and leads to another poll.
                        if at >= start:
                            ready, seen = self.dated(at, floor, stopped_at)
                            if ready is not None:
                                break
                        else:
                            seen = f"{seen} at {at}, before restore's start {start}"
                except CallFailed as error:
                    seen = f"a read failed: {error}"
                self.pause(self.deadline)
        except Aborted as abort:
            seen = f"{seen}; {abort}"
        except Interrupted as interrupted:
            say(f"host-stop-controller: signal {interrupted}: the restoration is unwritten: {seen}")
            return 1
        finally:
            self.armed, self.deadline = False, None
        if ready is None:
            say(f"host-stop-controller: the restoration was not shown within {self.operator['deadline_seconds']} s, "
                f"so it is unrecorded and the evidence is not to be judged as it stands: {seen}")
            return 1
        try:
            self.mark("restoration", {"instance": self.instance, "state": "running", "time": ready,
                                      "reviewed_sha256": reviewed_sha256})
        except Unwritten as error:
            say(f"host-stop-controller: {error}", err=True)
            return 1
        except OSError as error:
            # `publish` raises OSError only before it links restoration.json, so another restore can write the mark.
            say(f"host-stop-controller: restoration.json is unwritten: {error}", err=True)
            return 1
        say(f"host-stop-controller: {self.instance} runs again with both status checks ok")
        return 0


    def seal(self, evidence):
        """The header's `seal`, holding the evidence's lock from its read of the collections to its mark."""
        try:
            return self.sealing(evidence)
        finally:
            self.armed = False
            unlock(self.lock)

    def sealing(self, evidence):
        """Returns 0 with collected.json written, or 1 with none written or with one that stands with its durability
        unknown, or raises a Refusal, or Interrupted before the mark's write. Every file is read relative to the
        descriptor of the directory it stands in, following no link, and synced before the mark; the mark is checked
        first by the judge's own loader over the bytes it seals. The digest of a mark it linked is printed."""
        now, root = self.clock(), Path(evidence)
        injection = root / "injection"
        need(root.is_dir() and not root.is_symlink(), f"{evidence} is no directory")
        need(injection.is_dir() and not injection.is_symlink(), f"{injection} is no directory: no run to seal")
        probe(injection)
        self.lock = lock(injection)
        # Armed once the lock is held, so a signal from here to the mark's write ends the seal with nothing written.
        self.armed = True
        self.release()
        need(not stands(injection / "collected.json", "injection/collected.json"), "injection/collected.json exists: "
             "the seal is written once")
        with contextlib.ExitStack() as held:
            fds = {}
            for rel, parent in (("", None), ("records", ""), ("injection", "")):
                fds[rel] = judge.open_dir(rel or str(root), rel or evidence, fds.get(parent))
                held.callback(os.close, fds[rel])

            def read(rel):
                where, _, name = rel.rpartition("/")
                return synced(name, rel, fds[where])

            files = {"package.json": read("package.json")}
            approved = self.operator["approval"]["package_sha256"]
            need(hashlib.sha256(files["package.json"]).hexdigest() == approved, "package.json holds other bytes than "
                 "the approval's package")
            package, names = judge.package_of(files["package.json"])
            need(package["kind"] == "staging", f"package.json is of kind {package['kind']}: seal serves the "
                 "controller's staging runs, and a simulation export seals its own files")
            need(package["run"]["end"] <= now, f"the run window ends at {package['run']['end']}, after the seal's time "
                 f"{now}, so its collections may still grow")
            try:
                marks = sorted(os.listdir(fds["injection"]))
            except OSError as error:
                raise Refusal(f"injection cannot be listed: {error.strerror}") from error
            files.update((f"injection/{name}", read(f"injection/{name}")) for name in marks)
            roles = judge.parsed(files.get("injection/roles.json", b"null"), "injection/roles.json")
            need(isinstance(roles, dict) and roles.get("package_sha256") == approved,
                 "injection/roles.json names another package than the approval's")
            names["observed"] = judge.collected(package)
            names["sealed"] = names["observed"] | {"coverage.json"}
            files["coverage.json"] = read("coverage.json")
            coverage = judge.parsed(files["coverage.json"], "coverage.json")
            judge.conform(coverage, judge.LAYOUT["coverage.json"][0], "coverage.json", names)
            for rel in sorted(names["observed"]):
                files[rel] = read(rel)
                rows, span = judge.parsed(files[rel], rel), coverage[rel]
                need(len(rows) == span["lines"], f"{rel} holds {len(rows)} lines, but coverage.json counts "
                     f"{span['lines']}")
                need(span["to"] <= now, f"coverage.json spans {rel} to {span['to']}, after the seal's time {now}")
            # The judge lists DIR and `records/` and refuses an entry outside the layout, so the seal lists them too.
            stand = {rel for at in ("", "records") for rel, is_dir in judge.entries(fds[at], at and f"{at}/").items()
                     if not is_dir}
            judge.admit(package, stand | {rel for rel in files if rel.startswith("injection/")}
                        | {"injection/collected.json"})
            for rel in ("records", ""):
                try:
                    os.fsync(fds[rel])
                except OSError as error:
                    raise Refusal(f"{rel or evidence} cannot be synced: {error.strerror}") from error
        mark = {"time": now, "files": {rel: hashlib.sha256(files[rel]).hexdigest() for rel in sorted(names["sealed"])}}
        data = encoded(mark, "injection/collected.json")
        digest = hashlib.sha256(data).hexdigest()
        # The judge's loader refuses here what it would refuse once the seal stands, so no seal names such evidence.
        judge.load_evidence({**files, "injection/collected.json": data})
        self.injection = injection
        try:
            # The hold starts armed, so a signal raises until the write is held and waits from then on.
            with self.hold():
                self.armed = False
                self.mark("collected", mark, names)
        except FileExistsError as error:
            raise Refusal("injection/collected.json exists: the seal is written once") from error
        except Unwritten as error:
            # The mark was linked, and it stands or may stand again after a crash, so its digest is printed too.
            say(f"host-stop-controller: {error}", err=True)
            say(f"host-stop-controller: the mark this seal linked: injection/collected.json sha256 {digest}")
            return 1
        except OSError as error:
            say(f"host-stop-controller: collected.json is unwritten: {error}", err=True)
            return 1
        say(f"host-stop-controller: sealed {len(mark['files'])} files at {now}; injection/collected.json sha256 "
            f"{digest}")
        return 0

def synced(name, rel, dir_fd):
    """The bytes of the regular file `name` in the directory open at `dir_fd`, at most the judge's FILE_LIMIT, read
    following no link and without blocking, and the file synced, or a Refusal naming `rel`."""
    try:
        handle = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, dir_fd=dir_fd)
    except OSError as error:
        raise Refusal(f"{rel} cannot be read: {error.strerror}") from error
    with os.fdopen(handle, "rb") as file:
        need(stat.S_ISREG(os.fstat(file.fileno()).st_mode), f"{rel} is no regular file")
        try:
            data = file.read(judge.FILE_LIMIT + 1)
            os.fsync(file.fileno())
        except OSError as error:
            raise Refusal(f"{rel} cannot be read and synced: {error.strerror}") from error
    need(len(data) <= judge.FILE_LIMIT, f"{rel} holds more than {judge.FILE_LIMIT} bytes")
    return data


def lock(directory):
    """An open descriptor of `directory` holding its exclusive lock, so a run, a restore and a seal of one evidence
    directory exclude each other; a Refusal when another holds it. The lock adds no file to the layout."""
    try:
        fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    except OSError as error:
        raise Refusal(f"{directory} cannot be opened: {error.strerror}") from error
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError as error:
        os.close(fd)
        raise Refusal(f"{directory} is held by a run, restore or seal that has not ended: {error.strerror}") from error
    return fd


def unlock(fd):
    if fd is not None:
        with contextlib.suppress(OSError):
            os.close(fd)


def probe(root):
    """Refuses an evidence directory that takes no unnamed file, in which `publish` could write no mark; the probe's
    file is gone once it closes."""
    try:
        handle = os.open(root, os.O_TMPFILE | os.O_WRONLY | os.O_CLOEXEC, 0o644)
    except OSError as error:
        raise Refusal(f"{root} takes no unnamed file, so no mark can be written there: {error.strerror}") from error
    try:
        need(os.path.exists(f"/proc/self/fd/{handle}"), f"/proc/self/fd/{handle} does not resolve, so no unnamed "
             f"file in {root} can be linked to a mark's name")
    finally:
        os.close(handle)


def parser():
    p = argparse.ArgumentParser(description="Stop one declared staging instance for a run of GD-2.")
    commands = p.add_subparsers(dest="command", required=True)
    run = commands.add_parser("run", help="stop the target and write the marks")
    run.add_argument("--operator", required=True, help="the operator file")
    run.add_argument("--package", required=True, help="the filled package, whose bytes DIR/package.json must hold")
    run.add_argument("--evidence", required=True, help="the evidence directory")
    restore = commands.add_parser("restore", help="record the target running again after the operator's start")
    restore.add_argument("--operator", required=True, help="the operator file")
    restore.add_argument("--evidence", required=True, help="the evidence directory")
    restore.add_argument("--reviewed", help="the operator's record, kept outside DIR, that GD-2's restoration steps "
                         "were done")
    seal = commands.add_parser("seal", help="seal the collected files once the run window has ended")
    seal.add_argument("--operator", required=True, help="the operator file")
    seal.add_argument("--evidence", required=True, help="the evidence directory")
    return p


def main(argv=None, call=aws_cli, clock=time.time, sleep=time.sleep, elapsed=time.monotonic):
    previous = {s: signal.getsignal(s) for s in SIGNALS}
    # The handler stands before the first read, unarmed: a signal waits in `pending` until `run`, `restore` or `seal`
    # arms.
    controller = Controller({}, {}, call, clock, sleep, elapsed)
    try:
        for s, handler in previous.items():
            if handler is not signal.SIG_IGN:
                signal.signal(s, controller.on_signal)
        args = parser().parse_args(argv)
        controller.gd2 = gd2_of(read_json(judge.CATALOG, "the game-day catalog"))
        controller.operator = read_operator(args.operator, controller.gd2)
        if args.command == "run":
            return controller.run(args.package, args.evidence)
        if args.command == "seal":
            return controller.seal(args.evidence)
        return controller.restore(args.evidence, args.reviewed)
    except Refusal as error:
        say(f"host-stop-controller: refused: {error}" + ("" if error.written else "; nothing written"), err=True)
    except Interrupted as interrupted:
        say(f"host-stop-controller: signal {interrupted} before any mark; nothing written", err=True)
    except Exception as error:
        written = f"marks written: {controller.written}" if controller.written else "nothing written"
        say(f"host-stop-controller: {type(error).__name__}: {error}; {written}", err=True)
    finally:
        for s, handler in previous.items():
            if handler is not None:
                signal.signal(s, handler)
    return 2


if __name__ == "__main__":
    code = main()
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.flush()
        except (OSError, ValueError, AttributeError):
            # A stream is gone; leaving without the interpreter's own flush keeps the exit code the outcome's.
            os._exit(code)
    sys.exit(code)
