#!/usr/bin/env python3
"""Qualify the SPDK driver under one AWS FIS fault and record a versioned receipt.

Usage:
  fis-controller.py episode --profile P --operator F [--manifest F] [--artifacts DIR]
      [--episode ID] [--observer DIR] [--aws CMD] [--lane CMD] [--poll S]
  fis-controller.py campaign --operator F [--profiles "P ..."] [--budget-seconds S] [...]

The operator file is the qualification contract: account, region, role ARN,
the exact volume IDs, each volume's attachments, the effect timeout, a
positive whole number of seconds, and the stop alarms. Every field has one
shape: strings for the account, region and role ARN, a list of strings for
the volumes and the stop alarms, and a map from volume ID to a list of
instance IDs for the attachments; any other shape is rejected input before
any call. Before any injection
the controller requires the targets to be
exactly the volume the case's mappings file records, of a type the action
supports, tagged `disposable=true`, with every volume's attachments equal to
the declared set, each in state `attached`. A profile's `attachment` mode,
which the receipt records, names the volumes it admits: a `single` profile
refuses a volume with Multi-Attach enabled or more than one attachment, and a
`multi-attach-one` profile admits a volume only with Multi-Attach enabled and
exactly one settled attachment, the one instance the contract declares for it.
A contract that declares other than one instance for a `multi-attach-one`
profile's volume, and a campaign whose profiles name two modes, are rejected
input before any call, since one volume's Multi-Attach setting admits one mode.
Any other target is INVALID and nothing is injected. The same checks run
again once the case is ready, once more after the experiment template is
created, right before the experiment starts, and before every retry of a start
whose response was lost, so a target that changed during the readiness wait,
the template's creation or the retries is refused too; cleanup looks for a
start FIS may have accepted before a retry's refusal under its token, asks FIS
to stop it when a listing shows it live, and the receipt names it by its
experiment ID, or by the token when no listing confirms it. For a `multi-attach-one` profile the checks
also run at every poll of the readiness wait, since a Multi-Attach volume takes
a second attachment at any moment, so a second attachment a poll observes is
refused even when it has left by the readiness check; one that comes and goes
between two polls is unseen. A describe in that wait that fails or that the
readiness deadline cuts leaves the episode INCONCLUSIVE, and after any refusal
the wait goes on without further checks until the case is ready or ends, since
a case reads the abandon mark only once it is ready. The
controller's own calls only describe the volumes and drive FIS: it attaches,
detaches and takes over nothing. The checks read the attachments at their
moment; an EBS fault reaches every
instance attached to the volume for its duration, so the operator contract's
volumes are disposable ones that only the controller's role may attach or
detach, which the account's IAM policy holds through the fault.

An episode runs the hardware lane's case, waits for its readiness, appended
to the episode's observer log after the case was launched, creates and starts the experiment, and, once the
experiment and its fault action report running, marks the fault started in
the observer log and in the file `KESTRIKE_FIS_STARTED` names, which the
case waits for before it issues I/O, and records the experiment ID, its
effect window and the first timeout the case observes after that mark. A
running experiment without that timeout is
incomplete: the controller issues `stop-experiment`, waits up to the effect
timeout for the experiment to end, and records the stop as an abort, which
never counts as release proof; an experiment seen to end before any timeout
is recorded from that terminal state, with no stop issued. The start carries
one client token and a lost response is retried with it within the effect
timeout, so FIS answers with the experiment it already started. Each start
request runs the AWS CLI with `AWS_MAX_ATTEMPTS=1`, so the controller owns
every resend and checks the targets before it; a custom `--aws` command passes
that setting through to the CLI and makes at most one CLI request per
invocation. A start whose
outcome stays unknown lists the template's experiments until one is named or
the effect timeout passes, and stops any live one. A stop that is refused, a
stop whose end stays unconfirmed, and a listing that never answers leave the fault's end
unconfirmed in the receipt until a terminal state is observed, and the
campaign starts no profile after an episode that left it unconfirmed. A stop
the case proves counts as proven under the fault only when its monotonic time
precedes the start request plus the profile's duration, before which the
action cannot have run its course, and a fresh `get-experiment` after the
event still reports the action running; only then does the controller stop
the experiment early, and an experiment that reports `stopped` without the
controller's accepted stop, as a stop alarm leaves it, is INCONCLUSIVE because
its fault window is unknown. Once the experiment ends the controller requires
it completed, or stopped by its own accepted abort, polls the volume's status
until it reads ok within the effect timeout, then marks the fault ended in the
observer log and in the file `KESTRIKE_FIS_ENDED` names, and, after the
case ends, requires the case's restored bytes after
that mark or its stop proven under the fault, which it records as the release
proof. After the case ends and
before the restored-bytes check, the controller judges the case: held
custody or a receipt without a readable credit is INCONCLUSIVE, an uncredited
receipt whose test reported a failure or whose case died by a signal the lane
did not send is DISPROVEN, and a receipt the lane
left uncredited for its own reason, such as an unsupported platform row, is
INCONCLUSIVE with that reason. A receipt the lane marks credited earns credit
only when the hardware lane's judge validates its evidence against the
hardware manifest, `--hardware-manifest`, that the controller passed to the
lane, and the receipt's profile, role, episode, revision and mappings facts
equal what the controller launched: the lane profile and role, the episode,
the checkout's HEAD and the facts of the `KESTRIKE_MAPPINGS` file. A
credited episode records that manifest's path and SHA-256 as
`hardware_manifest`, the SHA-256 of the lane receipt bytes the judge validated
as `lane_receipt_sha256`, the SHA-256 of the `--manifest` file's bytes as
`fis_profiles_sha256`, and the SHA-256 of its profile row's sorted, compact
JSON as `profile_sha256`; `scripts/readiness.py judge` compares the three
digests with the lane receipt, the pinned manifest file and the pinned profile
it reads. A
rejection is INCONCLUSIVE with the judge's first reason and records no
release proof or digest. Controller loss, missing telemetry, failed
restoration and partial injection leave the receipt INCONCLUSIVE or INVALID
without credit, and any live experiment is stopped. The run status
(NOT_STARTED, COMPLETED, HALTED, FAILED_TO_INJECT, CONTROLLER_LOST) is
recorded apart from the verdict (HELD, DISPROVEN, INCONCLUSIVE, INVALID), and
the first failure persists, except that a case that failed or died after the
fault started replaces an INCONCLUSIVE one as DISPROVEN, with the earlier
failure kept as `diagnostic`; an INVALID verdict stands, and an experiment
another principal started from the template turns a DISPROVEN row INCONCLUSIVE,
with the case's failure kept as `diagnostic`.

The first observation of the experiment binds it to the template the
controller created (its action and parameters, target volumes, role and stop
conditions); an experiment that differs, started from a template another
principal updated, is INVALID and stopped. When the first observation comes
only during the stop's wait or the discovery of a lost start, the fault's end
stays unconfirmed and the failure recorded first stands.

The experiment template is deleted after the case ends, with the deletion
retried within the effect timeout; a template that stays is recorded as
retained and leaves the episode INCONCLUSIVE with the fault's end unconfirmed,
since a template that stays admits starts. Once the template is gone its
experiments are listed: one another principal started from it, live, ended or
unlisted, contaminates the row and keeps the fault's end unconfirmed, since FIS
runs an experiment past its template's deletion. A creation or a start whose
every response was lost is discovered by cleanup under its tag or token; one no
listing confirms leaves the fault's end unconfirmed too, since FIS may have
accepted it, and the receipt names the tag or token an operator finds it under.

Before the template's creation request, the controller writes the custody
marker `<custody>/fis-<episode>.json`, naming the creation's tag and the
start's token. It removes the marker once the template is confirmed gone, the
experiment ended and the volume reads ok, or when no start was requested.
Otherwise the marker stays and names what an operator must confirm: it holds
across reboots while the fault's end or the template is in doubt, and for the
current boot while only the case's custody is unknown.

When the controller abandons a case, it writes the file `KESTRIKE_FIS_ABANDONED`
names; a case outside a live fault stops issuing I/O at that mark, settles and
exits on its own within the effect timeout. A case that does not exit is
terminated through the lane, which stops and holds its group for an operator,
since it may still own device memory. The fault-end mark is written when the
experiment is seen completed or stopped after the case's first timeout, a stop
condition's included, and the volume has read ok; on every other terminal
path the controller abandons the case.

One episode's phases are bounded. The run, from the case's spawn, holds the
case's readiness, the action's duration, five windows of the operator's
effect timeout (the template, the start, the first timeout, the terminal state
or stop, and the restoration status), and the target checks after readiness
and after the template and the stop request of a proven stop, one AWS call of
`--aws-seconds` each; every AWS call is cut at the deadline of the window its
loop polls toward and, during the run, at that run deadline.
Cleanup then holds one stop request for an experiment a cut run left live, two
more windows, the abandon wait and the template's deletion, each of which may
end with one AWS call of `--aws-seconds`, and the listing of the deleted
template's experiments, one more such call; the observer log's reads and
marks that run past a window or between windows each wait at most the lane's
lock timeout, counted once per such operation. The sum
is the deadline the case receives, and a profile
whose `case_seconds` cannot hold it under the operator contract is rejected
input; the campaign budget sums one pre-run AWS call, the bound, the lane's
close and `case_seconds` over the chosen profiles. A case that ends before the
start is sent gets no fault.

`episode` exits 0 for HELD, 1 for DISPROVEN or INCONCLUSIVE, 2 for INVALID or
rejected input, 4 when the case left custody held or the quarantine marker
could not be written or removed, and 5 when interrupted; both
commands exit 4 before any call while a custody marker under `--custody`
quarantines the host or another controller or sweep holds the host's
reservation `<custody>/fis.lock`, and reject a profile whose cleanup after a
signal, with the marker and the receipt after it, cannot fit
`--kill-grace-seconds`, the caller's `timeout --kill-after`; both commands
exit 2 before any call when `KESTRIKE_HARDWARE_PLATFORM` names no platform
row of the `--hardware-manifest` the case runs under;
`campaign` exits 2 for rejected input, including a profile name the manifest
does not declare or a profile set past its budget, else with the most severe
episode's code, held custody first, and starts no profile after one that left
custody held, was interrupted or left its fault's end unconfirmed.
"""

import argparse
import contextlib
import errno
import hashlib
import importlib.util
import json
import math
import os
import shlex
import signal
import stat
import subprocess
import sys
import time
import uuid
from pathlib import Path

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


lane = load("hardware_lane", HERE / "hardware-lane.py")
HELD_EXIT = lane.HELD
TERMINAL = ("completed", "stopped", "failed", "cancelled")
ENVELOPE = {"version": 1, "section": "fis"}
# Sequential phases of one episode that each wait up to the operator's effect timeout: five while the run is under
# way (the template, the start, the first timeout, the terminal state or stop, the restoration status), then the
# abandon wait and the template's deletion in cleanup.
RUN_WINDOWS, CLEANUP_WINDOWS = 5, 2
# AWS calls made outside those windows: during the run the target checks after readiness and after the template and
# the stop request before a proven stop's window; in cleanup one stop request for an experiment a cut run left live
# or one cleanup first identifies from the deleted template's listing after a lost start, and, after the windows, the
# listing of the deleted template's experiments.
RUN_CALLS, CLEANUP_CALLS = 3, 2
OBSERVER_OPERATIONS = 7
# The kill grace a run has for its cleanup after a signal when the caller names none with --kill-grace-seconds;
# a CI step passes its own `timeout --kill-after`. The cleanup's longest path holds CLEANUP_PATH_WINDOWS effect
# windows, and an operator contract whose cleanup passes the grace is rejected input.
KILL_GRACE_SECONDS, CLEANUP_PATH_WINDOWS = 900, 5
# Seconds reserved after the cleanup, within the grace, for the quarantine marker and the receipt.
CLOSE_OUT_SECONDS = 60
# FIS caps a tag value at 256 characters; Linux caps a file name component at 255 bytes.
TAG_VALUE_MAX, NAME_MAX = 256, 255
# The campaign budget a run receives when the caller names none with --budget-seconds; a CI step passes what its
# own budget leaves after its build.
DEFAULT_BUDGET_SECONDS = 13000
OPERATOR_KEYS = {"account", "region", "role_arn", "volumes", "attachments", "effect_timeout_seconds",
                 "stop_alarms"}
# `single` admits a volume with Multi-Attach disabled and at most one attachment; `multi-attach-one` admits a volume
# with Multi-Attach enabled and exactly one settled attachment, the declared one.
ATTACHMENT_MODES = ("single", "multi-attach-one")
# The mappings file's byte bound, the binder's own: 65535 peers' next hops of at most 34 bytes each, plus 1 MiB.
MAPPINGS_BYTES = 65535 * 34 + (1 << 20)
# The errors a malformed reply, receipt or log raises in the controller's reads; an episode records each as a failure
# and still runs its cleanup and writes its receipt.
FAULTS = (*lane.FAULTS, RecursionError, lane.Stop)


class Rejected(Exception):
    pass


def write_file(path, text):
    """Writes a mark, marker or receipt whole or not at all: the text goes to a temporary name beside it, is synced,
    and replaces the file in one step, so a reader sees the previous version or the new one and a write that fails
    leaves the previous version; a symlink under the file's name is an error rather than a path to follow."""
    make_directory(path.parent)
    if path.is_symlink():
        raise OSError(errno.ELOOP, os.strerror(errno.ELOOP), str(path))
    partial = path.with_name(path.name + ".partial")
    try:
        with contextlib.suppress(FileNotFoundError):
            partial.unlink()
        descriptor = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o644)
        with os.fdopen(descriptor, "w") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(partial, path)
    except OSError:
        with contextlib.suppress(OSError):
            partial.unlink()
        raise
    sync_directory(path.parent)


def make_directory(directory):
    """Creates the directory with any missing ancestors and syncs each parent that gained an entry, so the path
    survives a power loss with the files later written under it."""
    directory, missing = Path(directory), []
    while not directory.exists() and directory not in missing:
        missing.append(directory)
        directory = directory.parent
    for made in reversed(missing):
        made.mkdir(exist_ok=True)
        sync_directory(made.parent)


def sync_directory(directory):
    """Syncs a directory's entries, so a file written or removed under it survives a power loss right after."""
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def mapped_volume():
    path = os.environ.get("KESTRIKE_MAPPINGS")
    if not path:
        raise Rejected("KESTRIKE_MAPPINGS names no mappings file")
    try:
        # O_NONBLOCK opens a FIFO at once, which the regular-file check refuses; the read stops one byte past the
        # binder's bound.
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK)
        try:
            if not stat.S_ISREG(os.fstat(descriptor).st_mode):
                raise OSError(errno.EINVAL, "not a regular file", path)
            data = os.read(descriptor, MAPPINGS_BYTES + 1)
        finally:
            os.close(descriptor)
    except OSError as error:
        # A released host has no mappings file; that is the target refusal a volume-less file is, not a controller loss.
        raise Rejected(f"the mappings file cannot be read: {error}") from None
    if len(data) > MAPPINGS_BYTES:
        raise Rejected(f"the mappings file is larger than {MAPPINGS_BYTES} bytes")
    for line in data.decode(errors="replace").splitlines():
        key, _, value = line.partition("=")
        if key == "nvme.volume":
            return value
    raise Rejected("the mappings record no volume")


def paged(response):
    """Whether a listing response is one page of several: it carries a non-null service `nextToken` or truncated CLI
    `NextToken`, as `template_experiments` counts a continuation."""
    return isinstance(response, dict) and any(response.get(key) is not None for key in ("nextToken", "NextToken"))


def acknowledged(reply, kind):
    """The ID a create or start reply acknowledges under `kind`, or None for a reply that names no nonempty string
    ID, which counts as a lost response."""
    found = reply.get(kind) if isinstance(reply, dict) else None
    ident = found.get("id") if isinstance(found, dict) else None
    return ident if isinstance(ident, str) and ident else None


def readable(described):
    """Whether a describe-volumes reply has the shape the target checks read: an object whose `Volumes` is a list of
    objects, each with a string `VolumeId` and `VolumeType`, a `MultiAttachEnabled` that is a boolean or null when
    present, `Attachments`, when present, a list of objects with a string `InstanceId` and a string `State` when
    present, and `Tags`, when present, a list of objects with a string `Key` and `Value`."""
    found = described.get("Volumes") if isinstance(described, dict) else None
    if not isinstance(found, list):
        return False
    for volume in found:
        if not (isinstance(volume, dict) and isinstance(volume.get("VolumeId"), str)
                and isinstance(volume.get("VolumeType"), str)):
            return False
        attachments, tags = volume.get("Attachments", []), volume.get("Tags", [])
        if not (isinstance(attachments, list) and isinstance(tags, list)
                and isinstance(volume.get("MultiAttachEnabled", False), (bool, type(None)))):
            return False
        if not all(isinstance(one, dict) and isinstance(one.get("InstanceId"), str)
                   and isinstance(one.get("State", ""), str) for one in attachments):
            return False
        if not all(isinstance(one, dict) and isinstance(one.get("Key"), str) and isinstance(one.get("Value"), str)
                   for one in tags):
            return False
    return True


class Episode:
    def __init__(self, args, manifest, profile_name, operator, manifest_sha256=None):
        self.args, self.manifest, self.operator = args, manifest, operator
        self.manifest_sha256 = manifest_sha256
        self.name, self.profile = profile_name, manifest["profiles"][profile_name]
        self.receipt = {"envelope": ENVELOPE, "fis": {
            "profile": profile_name, "episode": args.episode, "action": self.profile["action"],
            "attachment": self.profile["attachment"], "targets": operator["volumes"], "status": "NOT_STARTED",
            "verdict": "HELD", "first_failure": None,
            "abort": None, "release_proof": False, "timeouts": {
                "test_timeout_io_us": self.profile["timeout_io_us"],
                "production_timeout_io_us": manifest["production_timeout_io_us"],
                "kernel_nvme_io_timeout": self.kernel_timeout()}}}
        self.observer = lane.Observer(args.observer, args.episode, self.profile["lane"]["profile"], "fis")
        if self.observer.path is not None and self.observer.path.is_symlink():
            raise Rejected(f"the observer log {self.observer.path} is a symlink")
        # The receipt's path is refused here, before any call or spawn; a symlink planted later is refused by
        # `write_file`'s O_NOFOLLOW, never followed.
        self.receipt_path = Path(args.artifacts) / f"fis-{profile_name}-{args.episode}.json"
        if self.receipt_path.is_symlink():
            raise Rejected(f"the receipt path {self.receipt_path} is a symlink")
        self.experiment_id, self.case, self.template_id = None, None, None
        self.case_log = None
        self.launch_identity = None
        # `lost_creation` holds the creation request's token and `template_gone` records the template's confirmed
        # deletion: cleanup discovers the template under `lost_creation` while `template_id` is unset, and the
        # quarantine holds while a token is held and the template is not confirmed gone.
        self.lost_creation, self.template_gone = None, False
        self.binding_checked = False
        self.close_seconds = close_seconds(self.profile, args.hardware_manifest)
        self.restoration_result = None
        self.terminal, self.interrupted = False, False
        self.requested_ns = None
        self.least_latency_ms = self.manifest["bounds"]["latency_min_ms"]["default"]
        self.run_deadline = None
        # The directory is resolved and the mark's own name is kept, so a symlink planted under that name is seen
        # as such rather than followed.
        marks = Path(args.artifacts).resolve()
        self.started = marks / f"fis-{args.episode}.started"
        self.abandoned = marks / f"fis-{args.episode}.abandoned"
        self.ended = marks / f"fis-{args.episode}.ended"

    @property
    def section(self):
        return self.receipt["fis"]

    @staticmethod
    def kernel_timeout():
        try:
            return Path("/sys/module/nvme_core/parameters/io_timeout").read_text().strip()
        except OSError:
            return None

    def fail(self, verdict, reason, status=None):
        if self.section["first_failure"] is None:
            self.section["first_failure"], self.section["verdict"] = reason, verdict
            if status:
                self.section["status"] = status

    def contaminate(self, reason):
        """Another principal's experiment ran, or may have run, the volume beside the controller's, so a case failure
        recorded as DISPROVEN cannot be attributed to the declared profile: the verdict becomes INCONCLUSIVE with the
        failure kept as `diagnostic`; a DISPROVEN that replaced an earlier INCONCLUSIVE failure gives that failure
        back its place, since it fails the row on its own. Any other first failure stands, and a passing row fails
        with the reason; the experiments stay named in `unconfirmed_experiments` and the marker."""
        if self.section["verdict"] == "DISPROVEN":
            earlier = self.section.get("diagnostic")
            self.section["diagnostic"] = self.section["first_failure"]
            self.section["first_failure"], self.section["verdict"] = earlier or reason, "INCONCLUSIVE"
        else:
            self.fail("INCONCLUSIVE", reason)

    def disprove(self, reason):
        """A case that failed or died after the fault started disproves the row: the verdict is DISPROVEN even when
        an INCONCLUSIVE failure, such as a timeout the case never observed, was recorded first; that diagnostic is
        kept beside it. An INVALID verdict stands, since a fault that did not satisfy the profile qualifies nothing,
        and without a fault started the first failure stands as recorded."""
        if self.section["first_failure"] is None or "effect_window" not in self.section:
            return self.fail("DISPROVEN", reason)
        if self.section["verdict"] == "INCONCLUSIVE":
            self.section["diagnostic"] = self.section["first_failure"]
            self.section["first_failure"], self.section["verdict"] = reason, "DISPROVEN"

    def aws(self, *argv, deadline=None):
        """Runs one AWS CLI call cut at `--aws-seconds`, at the phase `deadline` its caller polls toward, and at the
        run deadline while the run's phases are under way, so no call outlives the window or the bound the campaign
        admitted. The deadline stands through the case's end and cleanup's wait for a live experiment, and is
        cleared before cleanup's own windows."""
        command = [*shlex.split(self.args.aws), *argv, "--region", self.operator["region"], "--output", "json"]
        limit = self.args.aws_seconds
        for cut in (deadline, self.run_deadline):
            if cut is not None:
                limit = min(limit, cut - time.monotonic())
        if limit <= 0:
            return None
        env = dict(os.environ, AWS_MAX_ATTEMPTS="1") if argv[:2] == ("fis", "start-experiment") else None
        try:
            done = subprocess.run(command, capture_output=True, text=True, timeout=limit, check=False, env=env)
            return json.loads(done.stdout) if done.returncode == 0 else None
        except (OSError, subprocess.TimeoutExpired, ValueError, RecursionError):
            # Deeply nested JSON can exceed the decoder's recursion limit; such a reply counts as unanswered.
            return None

    def validate(self, deadline=None):
        """Refuses every target the contract does not allow, before any injection, and returns True only when a
        complete describe shows every target eligible; the describe is cut at the phase `deadline` of a caller polling
        toward one, and a describe that deadline cut records nothing and returns None, leaving the caller to record
        the window's end."""
        volumes = self.operator["volumes"]
        if not volumes:
            self.fail("INVALID", "empty target list")
            return
        try:
            mapped = mapped_volume()
        except Rejected as error:
            self.fail("INVALID", str(error))
            return
        if set(volumes) != {mapped}:
            self.fail("INVALID", f"unexpected targets {sorted(volumes)}")
            return
        described = self.aws("ec2", "describe-volumes", "--volume-ids", *volumes, deadline=deadline)
        if described is None:
            if deadline is None or time.monotonic() < deadline:
                self.fail("INCONCLUSIVE", "the volumes could not be described")
            return
        if not readable(described):
            self.fail("INCONCLUSIVE", "the volumes were described in an unreadable shape")
            return
        if sorted(volume["VolumeId"] for volume in described["Volumes"]) != sorted(volumes):
            self.fail("INVALID", "a target volume was not described: the reply names "
                                 f"{sorted(volume['VolumeId'] for volume in described['Volumes'])}")
            return
        eligible = self.manifest["eligible_types"][self.profile["action"]]
        mode = self.profile["attachment"]
        for volume in described["Volumes"]:
            vid, attached = volume["VolumeId"], sorted(a["InstanceId"] for a in volume.get("Attachments", []))
            if volume["VolumeType"] not in eligible:
                self.fail("INVALID", f"{vid} is {volume['VolumeType']}, ineligible for the action")
                return
            # An attachment in transition may complete before the fault runs, handing the volume to another
            # consumer; only a settled attachment is a target.
            transitional = sorted(a.get("State", "unknown") for a in volume.get("Attachments", [])
                                  if a.get("State") != "attached")
            if transitional:
                self.fail("INVALID", f"{vid} has an attachment in state {transitional[0]!r}, not attached")
                return
            tags = {tag["Key"]: tag["Value"] for tag in volume.get("Tags", [])}
            if tags.get("disposable") != "true":
                self.fail("INVALID", f"{vid} is not tagged disposable")
                return
            if mode == "single":
                if len(attached) > 1:
                    self.fail("INVALID", f"{vid} has {len(attached)} attachments under a single-attachment profile")
                    return
                if volume.get("MultiAttachEnabled"):
                    self.fail("INVALID", f"{vid} has Multi-Attach enabled under a single-attachment profile")
                    return
            elif mode == "multi-attach-one":
                # A second attachment is a consumer the fault would reach and whose writes share the case's medium.
                if volume.get("MultiAttachEnabled") is not True:
                    self.fail("INVALID", f"{vid} has Multi-Attach disabled or unreported under a Multi-Attach profile")
                    return
                if len(attached) != 1:
                    self.fail("INVALID", f"{vid} has {len(attached)} attachments under a Multi-Attach profile, "
                                         "which admits exactly one")
                    return
            else:
                self.fail("INVALID", f"{vid} is checked under the attachment mode {mode!r}, which no target check "
                                     "implements")
                return
            if sorted(self.operator["attachments"].get(vid, [])) != attached:
                self.fail("INVALID", f"{vid} attachments {attached} are not the declared set")
                return
            if "latency_ms" in self.profile:
                least = self.manifest["bounds"]["latency_min_ms"].get(volume["VolumeType"],
                                                                     self.manifest["bounds"]["latency_min_ms"]["default"])
                # The disabled direction receives the least latency for the target's volume type.
                self.least_latency_ms = least
                if not least <= self.profile["latency_ms"] <= self.manifest["bounds"]["latency_max_ms"]:
                    most = self.manifest["bounds"]["latency_max_ms"]
                    self.fail("INVALID", f"latency {self.profile['latency_ms']} ms outside {least} to {most} ms")
                    return
        return True

    def template(self, request):
        # The volumes live in the partition of the operator's role, which the contract names.
        partition = self.operator["role_arn"].split(":")[1]
        arns = [f"arn:{partition}:ec2:{self.operator['region']}:{self.operator['account']}:volume/{v}"
                for v in self.operator["volumes"]]
        duration = f"PT{self.profile['duration_seconds']}S"
        if self.profile["action"] == "aws:ebs:volume-io-latency":
            read, write = self.profile["read"], self.profile["write"]
            latency = str(self.profile["latency_ms"])
            # The action takes percentages from 0.1 to 100: the direction under test receives 100 percent at the profile's
            # latency, the disabled direction 0.1 percent at the least latency for the target's volume type.
            least = str(self.least_latency_ms)
            parameters = {"readIOPercentage": "100" if read else "0.1",
                          "readIOLatencyMilliseconds": latency if read else least,
                          "writeIOPercentage": "100" if write else "0.1",
                          "writeIOLatencyMilliseconds": latency if write else least, "duration": duration}
        else:
            parameters = {"duration": duration}
        stops = [{"source": "aws:cloudwatch:alarm", "value": alarm} for alarm in self.operator["stop_alarms"]]
        return {"description": f"{self.name} {self.args.episode}", "roleArn": self.operator["role_arn"],
                "targets": {"Volumes": {"resourceType": "aws:ec2:ebs-volume", "resourceArns": arns,
                                        "selectionMode": "ALL"}},
                "actions": {"fault": {"actionId": self.profile["action"], "parameters": parameters,
                                      "targets": {"Volumes": "Volumes"}}},
                "stopConditions": stops or [{"source": "none"}],
                "tags": {"episode": self.args.episode, "request": request}}

    def window(self, seconds):
        """The deadline of a phase window: `seconds` from now, cut at the run deadline while the run's phases are
        under way, so a phase ends with the run rather than at a later local deadline of its own."""
        deadline = time.monotonic() + seconds
        return deadline if self.run_deadline is None else min(deadline, self.run_deadline)

    def quarantine(self, note, request=None, final=False):
        """Writes the custody marker that quarantines this host for the next sweep and campaign. While the fault is
        in doubt the marker is durable and holds across boots, since a reboot ends nothing of a FIS fault, until an
        operator confirms the experiment ended and the volume restored and removes it; a marker for a case in doubt
        alone is boot-scoped, as the lane's group markers are, since a reboot ends that process hazard."""
        marker = Path(self.args.custody) / f"fis-{self.args.episode}.json"
        # A start whose outcome is unknown may be an experiment apart from the listed ones, so both are named.
        named = list(self.section.get("unconfirmed_experiments") or [])
        if self.experiment_id and not self.terminal and self.experiment_id not in named:
            named.insert(0, self.experiment_id)
        if not self.section.get("experiment_id") and (self.section.get("start_unconfirmed") or not named):
            named.append(f"the unlisted start tagged {self.section.get('start_token')}")
        named = named or [self.section["experiment_id"]]
        # The text names what is in doubt: the fault's end while it is unconfirmed or still to be started, a template
        # that may remain and admits starts, the case's custody when its lane may still hold the devices.
        doubts = []
        fault_in_doubt = self.section.get("fault_end_unconfirmed") or "custody_unknown" not in self.section
        tag = request or self.section.get("template_unconfirmed") or self.lost_creation
        template = self.section.get("template_id") or self.section.get("template_retained") or f"tagged request={tag}"
        fault = (f"the FIS fault's end is unconfirmed ({note}): experiment {', '.join(named)}, template {template}, "
                 f"start token {self.section.get('start_token')}")
        if fault_in_doubt and final:
            # The episode is over, so each doubt is named apart: a template not confirmed gone admits starts, so the
            # operator deletes it or confirms its tag lists none; an experiment whose end or restoration is
            # unconfirmed, the controller's or another principal's, is named for the operator to confirm.
            if self.section.get("template_retained") or (self.lost_creation and not self.template_gone):
                doubts.append(f"the FIS template {template} may remain and admits starts ({note}); delete it or "
                              f"confirm the tag request={tag} lists none")
            if self.section.get("template_experiments_unconfirmed"):
                doubts.append(f"the experiments of the deleted FIS template {template} are unconfirmed ({note}): "
                              f"{self.section['template_experiments_unconfirmed']}; list the experiments under the "
                              "template's ID and confirm each ended with the volume restored")
            if self.section.get("unconfirmed_experiments") or self.section.get("start_unconfirmed") \
                    or "unbound_targets" in self.section or self.section.get("binding_unconfirmed") \
                    or (self.requested_ns is not None and self.restoration_result is not True) or not doubts:
                doubts.append(fault)
        elif fault_in_doubt:
            # The marker armed before the creation names every identifier a start may yet carry.
            doubts.append(fault)
        if "custody_unknown" in self.section:
            doubts.append(f"the case's custody is unknown ({note}): {self.section['custody_unknown']}")
        # A fault in doubt outlives this host's processes, so its marker is durable across boots; a case in doubt
        # alone is a process hazard a reboot ends, so its marker is boot-scoped, as the lane's group markers are.
        record = {"pgid": None, "boot": lane.boot_id(), "episode": self.args.episode,
                  "profile": self.profile["lane"]["profile"], "role": self.profile["lane"]["role"],
                  "custody": "; ".join(doubts), **({"durable": True} if fault_in_doubt else {})}
        write_file(marker, json.dumps(record, sort_keys=True) + "\n")
        self.section["quarantine"] = str(marker)
        return marker

    def nap(self, *deadlines):
        """Sleeps one polling interval, cut at the earliest of the given deadlines and the run deadline, so a wide
        interval never carries a loop past the window it polls."""
        limit = self.args.poll
        for deadline in (*deadlines, self.run_deadline):
            if deadline is not None:
                limit = min(limit, max(deadline - time.monotonic(), 0.0))
        time.sleep(limit)

    def event(self, name, after):
        """The first observed event `name` of this episode's own lane role past the ordinal `after`; an event another
        role or profile appended to the shared log is no witness for this case."""
        lane_cfg = self.profile["lane"]
        return next((event for event in self.observer.events()
                     if event.get("name") == name and event["ordinal"] > after
                     and event.get("profile") == lane_cfg["profile"] and event.get("role") == lane_cfg["role"]), None)

    @staticmethod
    def observed(got):
        """The experiment a get-experiment reply carries, or None for a reply that is missing or of another shape: an
        experiment is an object whose `state` is an object with a string `status` and whose `actions`, when present,
        is an object of objects, each with a `state` that, when present, is an object, so a malformed sample reads as
        an unanswered one."""
        experiment = got.get("experiment") if isinstance(got, dict) else None
        state = experiment.get("state") if isinstance(experiment, dict) else None
        actions = experiment.get("actions", {}) if isinstance(experiment, dict) else None
        if not (isinstance(state, dict) and isinstance(state.get("status"), str) and isinstance(actions, dict)
                and all(isinstance(action, dict) and isinstance(action.get("state", {}), dict)
                        for action in actions.values())):
            return None
        return experiment

    def experiment(self, experiment_id, deadline=None):
        """The experiment's telemetry, tried three times within the window its caller polls toward."""
        for _ in range(3):
            got = self.observed(self.aws("fis", "get-experiment", "--id", experiment_id, deadline=deadline))
            if got:
                return got
            self.nap(deadline)
        return None

    @staticmethod
    def faulting(experiment):
        """Whether the experiment and its fault action both report running."""
        return experiment["state"]["status"] == "running" and \
            experiment.get("actions", {}).get("fault", {}).get("state", {}).get("status") == "running"

    def bound(self, experiment):
        """Whether the experiment FIS runs is the template the controller created: one fault action with the
        profile's action and exactly the parameters the controller set, one target group holding the contract's
        volumes under the template's resource type and selection mode and nothing else, its role and its stop
        conditions. A template another principal updated between its creation and the start would start a
        different experiment, which qualifies nothing."""
        expected = self.template("")
        want, have = expected["actions"]["fault"], experiment.get("actions", {}).get("fault", {})
        conditions = sorted(json.dumps(one, sort_keys=True) for one in experiment.get("stopConditions", []))
        targets = experiment.get("targets") or {}
        return (set(experiment.get("actions", {})) == {"fault"} and have.get("actionId") == want["actionId"]
                and (have.get("parameters") or {}) == want["parameters"]
                and have.get("targets") == want["targets"]
                and set(targets) == set(expected["targets"])
                and all(self.target(targets[name]) == self.target(expected["targets"][name]) for name in targets)
                and experiment.get("roleArn") == expected["roleArn"]
                and conditions == sorted(json.dumps(one, sort_keys=True) for one in expected["stopConditions"]))

    @staticmethod
    def target(group):
        """A target group in a form two can be compared in: the resource ARNs sorted, and only the selectors that
        hold a value, so an empty selector and an absent one compare equal."""
        group = {key: value for key, value in (group or {}).items() if value}
        if "resourceArns" in group:
            group["resourceArns"] = sorted(group["resourceArns"])
        return group

    def unbound(self, experiment):
        """Binds the experiment to the template on its first full observation, whichever path reads it, and records
        a mismatch's targets; whether the experiment is unbound, which keeps the fault's end unconfirmed on every
        path, since its targets may be volumes other than the contract's, whose restoration the poll does not cover."""
        if not self.binding_checked:
            try:
                matched = self.bound(experiment)
            except FAULTS:
                matched = False
            if not matched:
                try:
                    arns = sorted(experiment["targets"]["Volumes"]["resourceArns"])
                except FAULTS:
                    arns = []
                self.section["unbound_targets"] = arns
            self.binding_checked = True
        return "unbound_targets" in self.section

    @staticmethod
    def partial(experiment):
        """Whether any action of the experiment reports failed."""
        return any(action.get("state", {}).get("status") == "failed"
                   for action in experiment.get("actions", {}).values())

    def stop(self, experiment_id):
        """Asks FIS to stop the experiment, waits up to the effect timeout for it to end and then for the volume's
        I/O to be restored, returning the terminal experiment it observed; the stop is an abort, never release
        proof. `abort` records `refused` for a call whose acceptance was never seen, `issued` with the end
        unconfirmed, or `stopped`; the fault's end is confirmed only once the experiment ended and the volume
        reports `ok`."""
        # A call that failed may still have been accepted, its response lost, so the experiment is polled to its
        # end either way; `refused` names a stop whose acceptance was never seen. Unconfirmed until the experiment
        # is seen ended and the volume restored, so a signal that cuts the wait short leaves the flag. The request
        # takes one AWS call allowance, which the run bound counts, before the wait's effect window opens.
        accepted = self.aws("fis", "stop-experiment", "--id", experiment_id)
        self.section["abort"] = "issued" if accepted else "refused"
        self.section["fault_end_unconfirmed"] = True
        return self.await_end(experiment_id)

    def attribute_stop(self, state):
        """Records the controller's stop as `stopped` once the experiment ended: an accepted stop ended it, and so did
        a stop whose acceptance was never seen when the contract names no stop alarm, since nothing else could have
        stopped it. With alarms declared such a stop stays `refused`, a stop condition's possible work."""
        if self.section["abort"] == "issued" or (self.section["abort"] == "refused" and state == "stopped"
                                                 and not self.operator["stop_alarms"]):
            self.section["abort"] = "stopped"

    def await_end(self, experiment_id):
        """Waits one effect window for the stopped experiment to end, then confirms the volume's restoration; the
        terminal experiment is returned. Cleanup calls this again for a wait a signal cut short."""
        deadline = self.window(self.operator["effect_timeout_seconds"])
        while time.monotonic() < deadline:
            got = self.observed(self.aws("fis", "get-experiment", "--id", experiment_id, deadline=deadline))
            if got and got["state"]["status"] in TERMINAL:
                self.attribute_stop(got["state"]["status"])
                unbound = self.unbound(got)
                self.terminal = True
                self.restored()
                if unbound:
                    self.section["fault_end_unconfirmed"] = True
                return got
            self.nap(deadline)
        return None

    def restored(self):
        """Polls the volume status for one effect window after the experiment ended; the fault's end is confirmed
        once every target reports `ok`, and stays unconfirmed, failing the episode, when the window passes first.
        One poll per episode: a later caller on the same terminal experiment gets the recorded result."""
        if self.restoration_result is None:
            self.restoration_result = self.poll_restored()
        if self.restoration_result:
            self.section.pop("fault_end_unconfirmed", None)
        return self.restoration_result

    def poll_restored(self):
        # Unconfirmed until a listing shows every target `ok`, so a signal that cuts the poll short leaves the flag.
        self.section["fault_end_unconfirmed"] = True
        deadline = self.window(self.operator["effect_timeout_seconds"])
        while True:
            status = self.aws("ec2", "describe-volume-status", "--volume-ids", *self.operator["volumes"],
                              deadline=deadline)
            statuses = status.get("VolumeStatuses") if isinstance(status, dict) else None
            statuses = statuses if isinstance(statuses, list) and all(isinstance(item, dict) for item in statuses) \
                else []
            reported = {item.get("VolumeId"): (item.get("VolumeStatus") or {}).get("Status")
                        if isinstance(item.get("VolumeStatus") or {}, dict) else None for item in statuses}
            if status is not None:
                # The last answered listing is the status the receipt records; a call the window cut adds nothing.
                self.section["volume_status"] = list(reported.values())
            # Restoration needs one `ok` row for each target, named by its volume ID.
            if len(statuses) == len(self.operator["volumes"]) and \
                    reported == dict.fromkeys(self.operator["volumes"], "ok"):
                self.section.pop("fault_end_unconfirmed", None)
                return True
            if time.monotonic() > deadline:
                self.section["fault_end_unconfirmed"] = True
                self.fail("INCONCLUSIVE", "the volume's I/O was not restored")
                return False
            self.nap(deadline)

    def on_signal(self, signum, _frame):
        """A signal to the controller ends the episode; cleanup stops any experiment still live."""
        self.interrupted = True
        self.fail("INCONCLUSIVE", f"the controller was interrupted by signal {signum}")
        self.section["status"] = "CONTROLLER_LOST"
        raise KeyboardInterrupt

    def cleanup(self):
        """Stops a live experiment, ends the case and records it, and deletes the template. A run its deadline cut
        has spent its windows: a live experiment gets one stop request, its end unconfirmed for an operator, and
        cleanup goes on to the windows the bound still holds; a run a signal ended early has its windows left, so
        the stop's wait and the restoration poll run again. The deadline stands until a live experiment's wait or a
        lost start's discovery is done, so a wait that outlasts it is cut like the run's own windows."""
        cut = self.run_deadline is not None and time.monotonic() > self.run_deadline and not self.interrupted
        if cut or self.interrupted:
            self.run_deadline = None
        try:
            self.reconcile(cut)
        except FAULTS as error:
            # A malformed reply ends the fault's reconciliation, whose end stays unconfirmed; the case and the
            # template are still settled below.
            self.fail("INCONCLUSIVE", f"cleanup failed: {type(error).__name__}: {error}")
            self.section["status"] = "CONTROLLER_LOST"
            self.section["cleanup_failure"] = f"{type(error).__name__}: {error}"
            if self.experiment_id or self.requested_ns is not None:
                self.section["fault_end_unconfirmed"] = True
        self.run_deadline = None
        if self.case is not None and "case_exit" not in self.section:
            self.finish(abandon=True)
        self.delete_template()

    def reconcile(self, cut):
        """Stops a live experiment, resumes a wait or a restoration poll a signal cut short, or discovers a start
        whose outcome is unknown."""
        if cut and self.experiment_id and not self.terminal:
            if self.section["abort"] in (None, "refused"):
                accepted = self.aws("fis", "stop-experiment", "--id", self.experiment_id)
                self.section["abort"] = "issued" if accepted else "refused"
            self.section["fault_end_unconfirmed"] = True
        elif self.experiment_id and not self.terminal and self.section["abort"] in (None, "refused"):
            # A live experiment is stopped; a stop whose acceptance was never seen is asked for again.
            self.stop(self.experiment_id)
        elif self.experiment_id and not self.terminal:
            # The accepted stop's wait was cut short, by a signal; the wait runs again on that request.
            self.await_end(self.experiment_id)
        elif self.experiment_id and self.terminal and self.restoration_result is None:
            # The experiment ended but its restoration poll was cut short, by a signal; the poll runs again here.
            self.restored()
        elif not self.experiment_id and self.template_id and self.requested_ns is not None \
                and self.section["abort"] is None:
            self.stop_unknown(self.template_id)

    def delete_template(self):
        """Discovers a template whose creation was lost, deletes the template and confirms its experiments."""
        # The discovery of a template whose creation was lost and the deletion share one window, so cleanup
        # holds the two windows the bound counts on every path; every call in the window is cut at the window's
        # deadline, and the deletion's confirmation and the listing after it each have one AWS-call allowance past it.
        deadline = time.monotonic() + self.operator["effect_timeout_seconds"]
        if not self.template_id and self.lost_creation:
            self.template_id = self.discover_template(self.lost_creation, deadline)
            if self.template_id:
                self.section["template_id"] = self.template_id
        if self.template_id:
            template, gone = self.template_id, True
            self.template_gone = False
            while not self.aws("fis", "delete-experiment-template", "--id", template, deadline=deadline):
                if time.monotonic() > deadline:
                    gone = self.deleted(template, deadline + self.args.aws_seconds)
                    if not gone:
                        # A template that stays admits starts, so the host stays quarantined until it is gone.
                        self.section["template_retained"] = template
                        self.section["fault_end_unconfirmed"] = True
                        self.fail("INCONCLUSIVE", f"the experiment template {template} was not deleted")
                    break
                self.nap(deadline)
            self.template_id, self.template_gone = None, gone
            # The controller's own experiment is the one it started or the one its discovery listed, or none when
            # no start was sent; the listing has its own AWS-call allowance past the deletion's window, which the
            # bounds count.
            own = self.experiment_id or self.section.get("experiment_id")
            if gone:
                self.confirm_quiet(template, own, max(deadline, time.monotonic()) + self.args.aws_seconds)

    def confirm_quiet(self, template, own, deadline):
        """Lists the deleted template's experiments once the deletion is confirmed, with one AWS-call allowance past
        the deletion's window, before the quarantine lifts: the template admits nothing once deleted, the controller's
        own experiment, when it sent a start, is left out of the others, since `quarantine()` and `stop_listed` name
        it while its end is unseen, and an experiment another principal started from the template, live or ended,
        contaminates the row and leaves the fault's end unconfirmed; the experiments it names join those
        `stop_listed` left unconfirmed. `template_experiments` reads every page of the listing under the one
        `deadline`; the experiments its answered pages name are recorded under `experiment_ids`, and another
        principal's join the unconfirmed ones, whether or not the listing is complete. An incomplete listing and one
        without the controller's own experiment vouch for nothing more, so they contaminate the row too, with the
        reason recorded under `template_experiments_unconfirmed` for the marker. A listing seen quiet lifts nothing by
        itself."""
        experiments, incomplete = self.template_experiments(template, deadline)
        if self.section["experiment_pages"]:
            self.section["experiment_ids"] = [found["id"] for found in experiments]
        if own is None and self.requested_ns is not None:
            own = self.late_start(experiments)
        others = list(dict.fromkeys(found["id"] for found in experiments if found["id"] != own))
        if others:
            # Another principal's experiment ran the volume under a fault the controller did not watch, live or
            # ended, so the row's evidence is contaminated and the volume's restoration after it is unconfirmed. An
            # experiment on an answered page contaminates the row even when a later page is missing.
            self.section["fault_end_unconfirmed"] = True
            earlier = self.section.get("unconfirmed_experiments") or []
            self.section["unconfirmed_experiments"] = earlier + [one for one in others if one not in earlier]
            self.contaminate(f"experiments {others} from the template ran beside the controller's")
        if incomplete:
            return self.unlisted(incomplete)
        if own is not None and own not in self.section["experiment_ids"]:
            return self.unlisted("the template's listing omits the controller's own experiment, so it vouches for no "
                                 "other")

    def late_start(self, experiments):
        """The controller's own start when the deleted template's listing first names it, by its token, or None.
        One unambiguous match binds the receipt's experiment to it, its listed state sets the run status, and a live
        one is asked to stop with the one AWS-call allowance cleanup holds for a cut run's live experiment, which a
        start whose outcome is unknown never spends. Its end stays unconfirmed, so the quarantine holds."""
        token = self.section.get("start_token")
        mine = [found for found in experiments if found.get("tags", {}).get("request") == token]
        if len(mine) != 1:
            return None
        found = mine[0]
        self.section["experiment_id"] = found["id"]
        state = found.get("state", {}).get("status")
        state = state if isinstance(state, str) else None
        if self.section["status"] != "CONTROLLER_LOST":
            self.section["status"] = {"completed": "COMPLETED", "failed": "FAILED_TO_INJECT"}.get(state or "", "HALTED")
        if state not in TERMINAL:
            accepted = self.aws("fis", "stop-experiment", "--id", found["id"])
            self.section["abort"] = "issued" if accepted else "refused"
        self.section["fault_end_unconfirmed"] = True
        earlier = self.section.get("unconfirmed_experiments") or []
        if found["id"] not in earlier:
            self.section["unconfirmed_experiments"] = earlier + [found["id"]]
        return found["id"]

    def template_experiments(self, template, deadline):
        """The experiments every answered page of the template's listing names, and the reason the listing is
        incomplete, or None once its last page is read. The listing follows each page's continuation token into the
        next request, all under the one `deadline`, so each request gets only the window left through the per-call
        allowance; `experiment_pages` records the pages read. A page that never answers by the deadline, one of
        another shape, one that names two continuation tokens and a token that is not a fresh string leave the
        listing incomplete."""
        # `starts` holds each page's starting token, None for the first, so its length counts the pages read.
        experiments, starts, resume = [], [], ()
        self.section["experiment_pages"] = 0
        while True:
            listed = self.aws("fis", "list-experiments", "--experiment-template-id", template, *resume,
                              deadline=deadline)
            if listed is None:
                if time.monotonic() > deadline:
                    return experiments, ("the template's experiments were not listed before the quarantine lifted"
                                         + (f", after {len(starts)} pages" if starts else ""))
                self.nap(deadline)
                continue
            page = self.listed(listed, "experiments", "tags", "state")
            if page is None:
                return experiments, "the template's experiments were listed in an unreadable shape"
            experiments += page
            starts.append(resume[1] if resume else None)
            self.section["experiment_pages"] = len(starts)
            # The service's `nextToken` resumes through `--next-token`; a truncated CLI result's `NextToken` resumes
            # through `--starting-token`. Only non-null values count as continuation tokens, and two of them make
            # the continuation ambiguous.
            named = [(flag, listed[key]) for key, flag in (("nextToken", "--next-token"),
                                                           ("NextToken", "--starting-token"))
                     if listed.get(key) is not None]
            if len(named) > 1:
                tokens = [token for _, token in named]
                return experiments, (f"the template's experiment listing named two continuation tokens {tokens!r}, "
                                     "so its pages may be incomplete")
            if not named:
                return experiments, None
            resume = named[0]
            token = resume[1]
            if not isinstance(token, str) or not token or token in starts:
                return experiments, (f"the template's experiment listing returned the continuation token {token!r} "
                                     "again or in another shape, so its pages may be incomplete")

    def unlisted(self, reason):
        """The deleted template's experiments are unconfirmed for `reason`: the row is contaminated, since one another
        principal started cannot be ruled out, and the marker sends the operator to the template's listing."""
        self.section["fault_end_unconfirmed"] = True
        self.section["template_experiments_unconfirmed"] = reason
        self.contaminate(reason)

    @staticmethod
    def listed(response, collection, *objects):
        """The entries under `collection` in a listing response, each an object with a string `id` whose `objects`
        fields, when present, are objects, or None for a response of another shape, which vouches for nothing."""
        entries = response.get(collection) if isinstance(response, dict) else None
        if isinstance(entries, list) and all(isinstance(found, dict) and isinstance(found.get("id"), str)
                                             and all(isinstance(found.get(field, {}), dict) for field in objects)
                                             for found in entries):
            return entries
        return None

    def deleted(self, template, deadline):
        """Whether a listing answers by `deadline` and no longer names the template; an unanswered listing counts as
        retained, and so does one of a shape the controller cannot read or one that carries a `nextToken` or a CLI
        `NextToken`, a page rather than the whole listing. The confirmation has the window's one AWS-call
        allowance past the deletion's deadline."""
        listed = self.aws("fis", "list-experiment-templates", deadline=deadline)
        templates = self.listed(listed, "experimentTemplates")
        return (templates is not None and not paged(listed)
                and template not in {item["id"] for item in templates})

    def run(self):
        self.validate()
        if self.section["first_failure"]:
            return
        lane_cfg = self.profile["lane"]
        patience = phase_bound(self.profile, self.operator, self.args.aws_seconds)
        env = dict(os.environ, KESTRIKE_FIS_TIMEOUT_US=str(self.profile["timeout_io_us"]),
                   KESTRIKE_FIS_STARTED=str(self.started), KESTRIKE_FIS_ENDED=str(self.ended),
                   KESTRIKE_FIS_ABANDONED=str(self.abandoned),
                   KESTRIKE_FIS_DEADLINE_SECONDS=str(math.ceil(patience)))
        for mark in (self.started, self.ended, self.abandoned):
            if mark.is_symlink():
                raise Rejected(f"the mark {mark} is a symlink")
            mark.unlink(missing_ok=True)
        argv = [*shlex.split(self.args.lane), "run", "--profile", lane_cfg["profile"], "--role", lane_cfg["role"],
                "--episode", self.args.episode, "--observer", self.args.observer, "--artifacts", self.args.artifacts,
                "--custody", self.args.custody, "--manifest", self.args.hardware_manifest]
        # The identity the case's receipt must carry comes from what the controller launches, not from the receipt.
        mappings = {"KESTRIKE_MAPPINGS": os.environ.get("KESTRIKE_MAPPINGS", "")}
        self.launch_identity = {"profile": lane_cfg["profile"], "role": lane_cfg["role"], "episode": self.args.episode,
                                "revision": lane.git_revision(), "mappings": lane.mappings_facts(mappings)}
        # The frontier is taken before the spawn, so every event the new case appends lies past it.
        launched = max((event["ordinal"] for event in self.observer.events()), default=0)
        # The child inherits the host reservation, so a controller killed before the lane publishes its own custody
        # leaves the host reserved by the lane it spawned.
        inherited = (self.args.reservation,) if getattr(self.args, "reservation", None) is not None else ()
        # The case's output goes to its own log under the artifacts, so a chatty case never blocks on a pipe the
        # controller is not reading; the lane's receipt line is read from that log once the case ends.
        self.case_log = Path(self.args.artifacts).resolve() / f"fis-{self.args.episode}.case.log"
        make_directory(self.case_log.parent)
        log = os.open(self.case_log, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o644)
        try:
            case = subprocess.Popen(argv, env=env, stdout=log, stderr=log, pass_fds=inherited)
        finally:
            os.close(log)
        self.case = case
        self.run_deadline = time.monotonic() + run_bound(self.profile, self.operator, self.args.aws_seconds)
        deadline = self.window(self.profile["ready_seconds"])
        unverified = False
        while self.observer.ready(lane_cfg["role"], after=launched) is None:
            if case.poll() is not None or time.monotonic() > deadline:
                self.fail("INCONCLUSIVE", "the case ended or stalled before its readiness")
                return
            # A second attachment can appear between readiness polls. A check that fails stops the checks, and the
            # wait goes on until the case is ready or ends.
            if self.profile["attachment"] == "multi-attach-one" and not unverified:
                unverified = not self.validate(deadline)
            self.nap(deadline)
        if unverified:
            # validate() recorded a refusal or a failed describe; a describe the readiness deadline cut recorded
            # nothing, and `fail` keeps the first failure, so this records only that cut.
            self.fail("INCONCLUSIVE", "the volumes were not described before the readiness deadline")
            return
        self.validate()
        if self.section["first_failure"]:
            return
        # Armed before the first request FIS may accept, the template's creation: a hard kill or a reboot from here
        # on leaves the marker, and only a template confirmed gone with the fault's end confirmed lifts it, since a
        # template that remains admits starts. The tokens the creation and the start carry are recorded first, so the
        # receipt and the marker name them whatever the requests' outcome, and an operator left with the marker alone
        # can find the template and the experiment; each token is 41 characters of fixed shape, within FIS's
        # 64-character client token, and the template's `episode` tag carries the episode name. Cleanup discovers a
        # template only under a request this arming marked.
        request = f"template-{uuid.uuid4().hex}"
        self.section["start_token"] = f"start-{uuid.uuid4().hex}"
        self.section["template_token"] = request
        self.quarantine("armed before the template's creation", request)
        self.lost_creation = request
        self.template_id = self.create(request)
        self.section["template_id"] = self.template_id
        if not self.template_id:
            # Cleanup discovers the template under the tag, or records that one may remain.
            return self.fail("INCONCLUSIVE", f"the experiment template was not created; one tagged {request} may "
                                             "remain", "FAILED_TO_INJECT")
        if self.section["first_failure"]:
            return
        self.validate()
        if self.section["first_failure"]:
            return
        # The action cannot start before this request, so it cannot end before the request plus its duration.
        self.requested_ns = time.monotonic_ns()
        started = self.start(self.template_id)
        if not started:
            if self.section["first_failure"]:
                return None
            return self.fail("INCONCLUSIVE", "the case ended before the experiment started" if self.case_exited()
                             else "the experiment did not start", "FAILED_TO_INJECT")
        self.experiment_id = started["experiment"]["id"]
        self.section["experiment_id"] = self.experiment_id
        self.watch()
        self.finish(abandon=self.section["first_failure"] is not None)

    def create(self, token):
        """Creates the experiment template with the client token `token`, retrying a lost response within the effect
        timeout; FIS answers a repeated token with the template it already created. The token was recorded, and the
        marker armed, before this first request, so a creation a signal or a kill interrupts is still discovered by
        cleanup or found by an operator."""
        document = json.dumps(self.template(token))
        deadline = self.window(self.operator["effect_timeout_seconds"])
        while True:
            created = self.aws("fis", "create-experiment-template", "--cli-input-json", document,
                               "--client-token", token, deadline=deadline)
            template = acknowledged(created, "experimentTemplate")
            if template:
                return template
            if time.monotonic() > deadline:
                # A request FIS accepted may list its template later; cleanup's discovery window looks for the tag.
                return None
            self.nap(deadline)

    def tagged_templates(self, request, deadline=None):
        """The one template FIS lists under this creation request's tag, or None when the listing failed, came in a
        shape the controller cannot read, is one page of several, listed nothing under the tag yet, or listed
        several; a template an earlier run of the same episode left carries another request tag."""
        response = self.aws("fis", "list-experiment-templates", deadline=deadline)
        listed = self.listed(response, "experimentTemplates", "tags")
        if listed is None or paged(response):
            return None
        matching = [item["id"] for item in listed if item.get("tags", {}).get("request") == request]
        return matching[0] if len(matching) == 1 else None

    def discover_template(self, request, deadline):
        """Polls the discovery listing until the deadline for the one template under this request tag, which the
        deletion then takes; a tag no listing confirmed by then is recorded as the one whose template may remain."""
        while True:
            found = self.tagged_templates(request, deadline)
            if found:
                return found
            if time.monotonic() > deadline:
                # A template that may remain admits starts, as a retained one does, so the host stays quarantined
                # until an operator confirms no template carries the tag or deletes it.
                self.section["template_unconfirmed"] = request
                self.section["fault_end_unconfirmed"] = True
                self.fail("INCONCLUSIVE", f"no listing confirmed the template; one tagged {request} may remain")
                return None
            self.nap(deadline)

    def start(self, template):
        """Starts the experiment with one client token, retrying a lost response within the effect timeout; FIS
        answers a repeated token with the experiment it already started."""
        token = self.section["start_token"]
        deadline = self.window(self.operator["effect_timeout_seconds"])
        first = True
        while True:
            # A case that ended gets no fault; a request already sent is discovered and stopped by cleanup.
            if self.case_exited():
                if first:
                    self.requested_ns = None
                return None
            if not first:
                # The retry's target check ends with the start window, so a slow describe leaves the window for the
                # unknown start's discovery; a window already past retries nothing.
                if time.monotonic() > deadline:
                    return None
                self.validate(deadline)
                if self.section["first_failure"] or self.case_exited() or time.monotonic() > deadline:
                    return None
            first = False
            started = self.aws("fis", "start-experiment", "--experiment-template-id", template, "--client-token", token,
                               "--tags", f"request={token}", deadline=deadline)
            if acknowledged(started, "experiment"):
                return started
            if time.monotonic() > deadline:
                return None
            self.nap(deadline)

    def case_exited(self):
        """Whether the case process has exited; polled before every request that could inject a fault."""
        return self.case is not None and self.case.poll() is not None

    def stop_unknown(self, template):
        """A start whose outcome is unknown may have launched an experiment; the listing is retried within the
        effect timeout until it names one, and any live experiment is stopped. The fault's end stays unconfirmed
        until an experiment is found and observed ended: a listing that never answers, or answers empty until the
        deadline, leaves a start FIS may still have accepted, and a listing of a shape the controller cannot read
        counts as unanswered. A listing that names the controller's own start is taken as far as its pages were
        read: a later page that fails is asked for again until the deadline, which holds the stop requests until
        then, and a later page of an unreadable shape or with an unusable continuation token ends the listing at
        once."""
        if not template:
            return
        deadline = self.window(self.operator["effect_timeout_seconds"])
        answered, token = None, self.section.get("start_token")

        def mine(found):
            return found.get("tags", {}).get("request") == token

        while True:
            listed, _ = self.template_experiments(template, deadline)
            if self.section["experiment_pages"]:
                answered = list({**{found["id"]: found for found in answered or []},
                                 **{found["id"]: found for found in listed}}.values())
                # The listing is taken once it names the controller's own start, the one tagged with its token;
                # another experiment under the template is stopped too, and confirms nothing about this start.
                if any(mine(found) for found in listed):
                    break
            if time.monotonic() > deadline:
                self.section["fault_end_unconfirmed"] = True
                self.section["start_unconfirmed"] = ("no listing answered" if answered is None
                                                     else "no experiment listed")
                if self.section["status"] == "NOT_STARTED":
                    # FAILED_TO_INJECT records a start request whose outcome stays unconfirmed at the deadline.
                    self.section["status"] = "FAILED_TO_INJECT"
                if answered:
                    self.section["start_unconfirmed"] = "the controller's own start was never listed"
                    self.stop_listed(answered)
                    self.section["fault_end_unconfirmed"] = True
                return
            self.nap(deadline)
        self.stop_listed(answered)

    def stop_listed(self, experiments):
        """Asks every live listed experiment to stop, awaits them all within one window and polls the volume once."""
        # Every live experiment is asked to stop, then all are awaited within one window and the one volume's
        # restoration is polled once, so the cleanup bound holds whatever the listing's length; the fault's end is
        # confirmed only when every listed experiment was seen ended and the volume read ok.
        self.section["experiment_ids"] = [found["id"] for found in experiments]
        token = self.section.get("start_token")
        own = next((found for found in experiments if found.get("tags", {}).get("request") == token), None)
        # The receipt's experiment is the controller's own start; a listing without it names the start by its token.
        if own is not None:
            self.section["experiment_id"] = own["id"]
        live = [found["id"] for found in experiments if found.get("state", {}).get("status") not in TERMINAL]
        ended = {found["id"]: found.get("state", {}).get("status") for found in experiments if found["id"] not in live}
        self.section["fault_end_unconfirmed"] = True
        if own is not None and self.section["status"] != "CONTROLLER_LOST":
            # The run status follows the controller's own start, its listed terminal state or HALTED while live; a
            # loss of the controller already recorded stands.
            state = ended.get(own["id"])
            self.section["status"] = {"completed": "COMPLETED", "failed": "FAILED_TO_INJECT"}.get(state or "", "HALTED")
        # Every stop request and every poll runs under the one window, so the bound holds whatever the listing's
        # length; a stop request the window cut counts as unseen.
        deadline = self.window(self.operator["effect_timeout_seconds"])
        # The controller's own start is asked to stop first, so another experiment's slow stop takes nothing from it.
        live.sort(key=lambda one: own is None or one != own["id"])
        accepted = {one for one in live if self.aws("fis", "stop-experiment", "--id", one, deadline=deadline)}
        if live:
            self.section["abort"] = "issued" if len(accepted) == len(live) else "refused"
        unbound = False
        if own is not None and not self.binding_checked:
            # The stop requests go first, so a slow read takes nothing from them. The listing carries no targets, so
            # the controller's own experiment is read once to bind it to the template; one that was never read stays
            # unbound, and the fault's end unconfirmed.
            got = self.observed(self.aws("fis", "get-experiment", "--id", own["id"], deadline=deadline))
            unbound = self.unbound(got) if got else True
            if got is None:
                self.section["binding_unconfirmed"] = "the controller's own experiment was never read"
        if live:
            while time.monotonic() < deadline and len(ended) < len(experiments):
                for one in live:
                    if one in ended:
                        continue
                    got = self.observed(self.aws("fis", "get-experiment", "--id", one, deadline=deadline))
                    status = got["state"]["status"] if got else None
                    if status in TERMINAL:
                        ended[one] = status
                    elif status not in (None, "stopping") and one not in accepted \
                            and self.aws("fis", "stop-experiment", "--id", one, deadline=deadline):
                        # A stop whose acceptance was never seen is asked for again while the experiment runs.
                        accepted.add(one)
                if len(ended) < len(experiments):
                    self.nap(deadline)
            self.section["abort"] = "issued" if len(accepted) == len(live) else "refused"
            if len(ended) == len(experiments) and self.section["abort"] == "issued":
                self.section["abort"] = "stopped"
        unconfirmed = [found["id"] for found in experiments if found["id"] not in ended]
        if unconfirmed:
            self.section["unconfirmed_experiments"] = unconfirmed
            return
        self.terminal = True
        self.restored()
        if unbound:
            self.section["fault_end_unconfirmed"] = True

    def watch(self):
        """Marks the fault started once the fault action reports running, waits for the case's timeout after
        that mark, then for the experiment to end; a stop the case proves before the action can have run its
        course, with the action still running in a fresh observation, is recorded as proven under the fault
        and stops the experiment early."""
        deadline = self.window(self.operator["effect_timeout_seconds"])
        start, timeout = None, None
        while not timeout:
            experiment = self.experiment(self.experiment_id, deadline)
            if experiment is None:
                # Telemetry the window cut marks the window's end; telemetry lost inside it is the controller's loss.
                if time.monotonic() < deadline:
                    self.fail("INCONCLUSIVE", "the experiment's telemetry was lost", "CONTROLLER_LOST")
                else:
                    self.fail("INCONCLUSIVE", "the experiment ran without an observed timeout", "HALTED")
                return self.stop(self.experiment_id)
            if not self.binding_checked and self.unbound(experiment):
                # The start took a snapshot of the template; the first observation binds the experiment to the
                # template the controller created, and one that differs is stopped and qualifies nothing.
                self.fail("INVALID", "the experiment differs from the template the controller created", "HALTED")
                ended = self.stop(self.experiment_id)
                self.section["fault_end_unconfirmed"] = True
                return ended
            if experiment["state"]["status"] == "failed":
                self.terminal = True
                if self.partial(experiment):
                    self.fail("INVALID", "the fault injected partially", "FAILED_TO_INJECT")
                else:
                    self.fail("INCONCLUSIVE", "the experiment failed to inject", "FAILED_TO_INJECT")
                return self.restored()
            if experiment["state"]["status"] in TERMINAL:
                self.terminal = True
                # A timeout the case appended after the last running poll stands: it followed the fault's start.
                timeout = self.event("timeout", start) if start is not None else None
                if timeout:
                    self.section["first_timeout"] = timeout
                    return self.restoration(experiment, timeout["ordinal"])
                state = experiment["state"]["status"]
                self.fail("INCONCLUSIVE", f"the experiment ended {state} before the case observed a timeout",
                          "COMPLETED" if state == "completed" else "HALTED")
                return self.restored()
            if self.partial(experiment):
                self.fail("INVALID", "the fault injected partially", "FAILED_TO_INJECT")
                return self.stop(self.experiment_id)
            if self.faulting(experiment):
                if start is None:
                    mark = self.observer.append("fault-start", experiment=self.experiment_id)
                    start = mark["ordinal"]
                    self.section["effect_window"] = {"start_ordinal": start}
                    write_file(self.started, str(start))
                timeout = self.event("timeout", start)
            if not timeout and (time.monotonic() > deadline or (self.case and self.case.poll() is not None)):
                self.fail("INCONCLUSIVE", "the experiment ran without an observed timeout", "HALTED")
                return self.stop(self.experiment_id)
            if not timeout:
                self.nap(deadline)
        self.section["first_timeout"] = timeout
        end = self.window(self.profile["duration_seconds"] + self.operator["effect_timeout_seconds"])
        while time.monotonic() < end:
            experiment = self.experiment(self.experiment_id, end)
            if experiment is None:
                if time.monotonic() >= end:
                    break
                self.fail("INCONCLUSIVE", "the experiment's final state was lost", "CONTROLLER_LOST")
                return self.stop(self.experiment_id)
            if experiment["state"]["status"] in TERMINAL:
                self.terminal = True
                return self.restoration(experiment, timeout["ordinal"])
            stop = self.event("stop", timeout["ordinal"])
            if stop and self.section["abort"] is None and "stop_under_fault" not in self.section:
                lift_ns = self.requested_ns + self.profile["duration_seconds"] * 10**9
                fresh = self.experiment(self.experiment_id, end) if stop["monotonic_ns"] < lift_ns else None
                if fresh and self.faulting(fresh):
                    self.section["stop_under_fault"] = stop["ordinal"]
                    ended = self.stop(self.experiment_id)
                    if ended is not None:
                        self.terminal = True
                        return self.restoration(ended, timeout["ordinal"])
            self.nap(end)
        self.fail("INCONCLUSIVE", "the experiment outlived its duration", "HALTED")
        self.stop(self.experiment_id)

    def finish(self, abandon=False):
        case = self.case
        if case is None:
            return
        # A case left to run has its declared seconds; an abandoned one was given the effect timeout to end, then
        # terminated, so only the lane's close remains. A case that outlives its seconds is abandoned the same way.
        if abandon and case.poll() is None:
            self.abandon(case)
        try:
            case.wait(timeout=self.close_seconds if abandon else self.profile["case_seconds"])
        except subprocess.TimeoutExpired:
            if abandon:
                self.kill(case)
            else:
                # A live experiment is cleanup's to stop, under the bound it holds for a cut run or the kill grace.
                self.abandon(case)
                try:
                    case.wait(timeout=self.close_seconds)
                except subprocess.TimeoutExpired:
                    self.kill(case)
        self.section["case_exit"] = case.returncode
        if case.returncode is not None and case.returncode < 0 and "custody_unknown" not in self.section:
            # The lane's supervisor died by a signal after spawning its case, whose group may still hold the devices;
            # the lane leaves that group's marker, and the controller holds the host as for a kill of its own.
            self.section["custody_unknown"] = (f"the lane's supervisor died by signal {-case.returncode}; its case "
                                               "group may still hold the devices")
        self.started.unlink(missing_ok=True)
        if "custody_unknown" not in self.section:
            # A case whose group may still run keeps the abandon mark, so a test resuming from a stall settles
            # rather than issuing I/O; the operator's containment removes it with the group.
            self.abandoned.unlink(missing_ok=True)
        receipt = receipt_line(self.case_log) if self.case_log else None
        self.section["lane_receipt"] = receipt
        try:
            data = Path(receipt).read_bytes() if receipt else b"{}"
            document = json.loads(data)
            hardware = document["hardware"]
            credited = hardware["credited"]
            cases = hardware.get("cases") or []
            failed = any(line.startswith("test result: FAILED") for entry in cases for line in entry.get("summary") or [])
            died = next((entry["exit"] for entry in cases
                         if isinstance(entry.get("exit"), int) and entry["exit"] < 0), None)
        except FAULTS:
            data, document, hardware, credited, failed, died = b"", {}, {}, None, False, None
        if case.returncode == HELD_EXIT or "custody_unknown" in self.section:
            self.fail("INCONCLUSIVE", "the case left custody held")
        elif credited is None:
            self.fail("INCONCLUSIVE", "the case wrote no readable lane receipt")
        elif not credited and failed:
            self.disprove("the case's lane receipt is uncredited and its test failed")
        elif not credited and died is not None:
            self.disprove(f"the case's lane receipt is uncredited and its case died by signal {-died}")
        elif not credited:
            self.fail("INCONCLUSIVE",
                      f"the case's lane receipt is uncredited with its test passing: {hardware.get('first_failure')}")
        else:
            # The producer's flag is a summary: the hardware judge and the launched identity decide credit, and a
            # rejected receipt records no release proof.
            try:
                defects = lane.judge_launch(self.args.hardware_manifest, document, self.launch_identity)
            except FAULTS as error:
                defects = [f"the case's lane receipt cannot be judged against the hardware manifest "
                           f"{self.args.hardware_manifest}: {error}"]
            if defects:
                self.fail("INCONCLUSIVE", f"the hardware judge rejects the case's lane receipt: {defects[0]}")
                return
            # The judge matched the receipt's digest to this manifest's, so the receipt names the manifest credit used.
            self.section["hardware_manifest"] = {"path": str(Path(self.args.hardware_manifest).resolve()),
                                                 "sha256": hardware["manifest_sha256"]}
            # The credit binds to the receipt bytes the judge validated, to the manifest file whose top-level fields
            # admitted the targets, and to the profile row this episode ran, the row's digest being the SHA-256 of
            # its sorted, compact JSON.
            self.section["lane_receipt_sha256"] = hashlib.sha256(data).hexdigest()
            self.section["fis_profiles_sha256"] = self.manifest_sha256
            self.section["profile_sha256"] = hashlib.sha256(
                json.dumps(self.profile, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.witnessed()

    def kill(self, case):
        """Kills a case whose lane did not close within its allowance and records that its custody is unknown."""
        case.kill()
        case.wait()
        self.section["custody_unknown"] = "the lane was killed; its case may still hold the devices"

    def abandon(self, case):
        """Writes the abandon mark so a case outside a live fault ends itself within the effect timeout; a case
        that stays is terminated through the lane, which holds its group rather than signal a case that may still
        own device memory."""
        write_file(self.abandoned, "abandoned")
        try:
            case.wait(timeout=self.operator["effect_timeout_seconds"])
        except subprocess.TimeoutExpired:
            case.terminate()

    def witnessed(self):
        """After the case ended, requires its restored bytes after the fault ended or its stop proven under the
        fault, and records that witness as the release proof."""
        timeout, ended = self.section.get("first_timeout"), self.section.get("effect_window", {}).get("end_ordinal")
        if not timeout:
            return
        if "stop_under_fault" in self.section or (ended and self.event("restored", ended)):
            self.section["release_proof"] = True
        else:
            self.fail("INCONCLUSIVE",
                      "the case observed no restored bytes after the fault ended or proven stop under it")

    def restoration(self, experiment, after):
        state = experiment["state"]["status"]
        self.section["effect_window"].update(start_time=experiment.get("startTime"), end_time=experiment.get("endTime"),
                                             end_after_ordinal=after)
        # A fault that failed or applied partially may still be lifting; the volume's restoration is confirmed
        # on every terminal path.
        if self.partial(experiment):
            self.fail("INVALID", "the fault injected partially", "FAILED_TO_INJECT")
            return self.restored()
        if state not in ("completed", "stopped"):
            self.fail("INCONCLUSIVE", f"the experiment ended {state}",
                      "FAILED_TO_INJECT" if state == "failed" else "HALTED")
            return self.restored()
        self.section["status"] = "COMPLETED" if state == "completed" else "HALTED"
        if self.section["abort"] is not None:
            self.attribute_stop(state)
        if state == "stopped" and self.section["abort"] != "stopped":
            self.section.pop("stop_under_fault", None)
            self.fail("INCONCLUSIVE", "a stop condition ended the experiment, so its fault window is unknown")
        # The case reads at normal latency once the fault-end mark appears, so the mark follows the volume's
        # restoration; a volume that stays impaired gets no mark, and cleanup abandons the case.
        if not self.restored():
            return
        mark = self.observer.append("fault-end", experiment=self.experiment_id)
        self.section["effect_window"]["end_ordinal"] = mark["ordinal"]
        write_file(self.ended, str(mark["ordinal"]))


def episode(args, manifest, name, operator, manifest_sha256=None):
    """Runs one episode, writes its receipt and returns its exit code with the receipt's `fis` section;
    `manifest_sha256` is the SHA-256 of the bytes `manifest` was parsed from."""
    run = Episode(args, manifest, name, operator, manifest_sha256)
    signal.signal(signal.SIGTERM, run.on_signal)
    signal.signal(signal.SIGINT, run.on_signal)
    try:
        run.run()
    except KeyboardInterrupt:
        pass
    except Rejected as error:
        # A target the contract refuses after the spawn, such as a mapping that went missing, is recorded like the
        # other target refusals, and the episode still writes its receipt.
        run.fail("INVALID", str(error))
    except FAULTS as error:
        run.fail("INCONCLUSIVE", f"the controller failed: {type(error).__name__}: {error}", "CONTROLLER_LOST")
    finally:
        def late(signum, _frame):
            # Cleanup runs on; the interruption is the episode's failure and its run status before the receipt.
            run.interrupted = True
            run.fail("INCONCLUSIVE", f"the controller was interrupted by signal {signum} during cleanup")
            run.section["status"] = "CONTROLLER_LOST"
        signal.signal(signal.SIGTERM, late)
        signal.signal(signal.SIGINT, late)
        try:
            run.cleanup()
        except FAULTS as error:
            # A cleanup that fails partway leaves whatever it did not confirm unconfirmed, and the quarantine marker
            # and receipt below still follow.
            run.fail("INCONCLUSIVE", f"cleanup failed: {type(error).__name__}: {error}")
            run.section["status"] = "CONTROLLER_LOST"
            run.section["cleanup_failure"] = f"{type(error).__name__}: {error}"
            if (run.experiment_id or run.requested_ns is not None) and run.restoration_result is not True:
                run.section["fault_end_unconfirmed"] = True
            if run.lost_creation and not run.template_gone:
                # A template created, or requested, and not confirmed gone admits starts, so the host stays
                # quarantined.
                run.section["fault_end_unconfirmed"] = True
                run.section.setdefault("template_unconfirmed", run.lost_creation)
            if run.case is not None and run.case.poll() is None:
                run.section["custody_unknown"] = "cleanup failed before the case ended; it may still hold the devices"
    # The late handler stays installed through the quarantine marker and the receipt, so a signal now is recorded
    # and both files are still written.
    quarantined = True
    marker = Path(args.custody) / f"fis-{args.episode}.json"
    if run.section.get("fault_end_unconfirmed") or "custody_unknown" in run.section:
        # A fault whose end is unconfirmed, or a case that may still hold the devices once this process exits and
        # releases the host, keeps the host quarantined through the custody marker, durable while the fault is in
        # doubt: the marker armed before the template's creation stays, naming what the controller knows now, and a run
        # interrupted before the arming writes it here.
        try:
            run.quarantine("after the episode", final=True)
        except OSError as error:
            # With no marker the host cannot be trusted to the next job; the episode exits held.
            run.section["quarantine"] = f"unwritten: {error}"
            quarantined = False
    elif marker.exists() or marker.is_symlink():
        # The experiment ended and the volume restored, or no start was requested: the armed marker is lifted. A
        # marker that stays for want of permission keeps the host quarantined, and the episode exits held.
        try:
            marker.unlink()
            sync_directory(marker.parent)
            run.section.pop("quarantine", None)
        except OSError as error:
            run.section["quarantine"] = f"{marker} stays: {error}"
            quarantined = False
    out = run.receipt_path
    # The receipt is committed with the signals blocked: a signal pending by the end of a write is taken into the
    # outcome through the late handler and the receipt is written again, and the handlers are reset before the
    # signals are unblocked, so a signal from then on ends the process after the committed outcome, by its default
    # action, with the receipt agreeing with the exit the campaign sees.
    signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGTERM, signal.SIGINT})
    try:
        for _ in range(3):
            write_file(out, json.dumps(run.receipt, indent=2, sort_keys=True) + "\n")
            pending = signal.sigpending() & {signal.SIGTERM, signal.SIGINT}
            if not pending:
                break
            # The pending signal is taken into the outcome here and discarded by SIG_IGN; when both are pending, the
            # unblock delivers the other to `late`.
            late(min(pending), None)
            signal.signal(min(pending), signal.SIG_IGN)
            signal.pthread_sigmask(signal.SIG_UNBLOCK, pending)
            signal.pthread_sigmask(signal.SIG_BLOCK, pending)
        written = True
    except OSError as error:
        # An episode with no receipt has no evidence, so it is INCONCLUSIVE at best; the exit code still carries a
        # held or interrupted result first. A version written before the failure is removed, so no receipt
        # disagreeing with the exit stays readable.
        with contextlib.suppress(OSError):
            out.unlink()
            sync_directory(out.parent)
        print(f"receipt unwritten: {out}: {error}", file=sys.stderr)
        run.fail("INCONCLUSIVE", f"the receipt {out} could not be written: {error}")
        written = False
    finally:
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_UNBLOCK, {signal.SIGTERM, signal.SIGINT})
    verdict = run.section["verdict"]
    print(f"{name}: {verdict}{'' if verdict == 'HELD' else ': ' + run.section['first_failure']}")
    if written:
        print(f"receipt: {out}", file=sys.stderr)
    if run.section.get("case_exit") == HELD_EXIT or "custody_unknown" in run.section or not quarantined:
        return HELD_EXIT, run.section
    if run.interrupted:
        return lane.INTERRUPTED, run.section
    return {"HELD": 0, "DISPROVEN": 1, "INCONCLUSIVE": 1}.get(verdict, 2), run.section


def parser():
    root = argparse.ArgumentParser(description="Qualify the SPDK driver under one AWS FIS fault.")
    sub = root.add_subparsers(dest="command", required=True)
    for name in ("episode", "campaign"):
        command = sub.add_parser(name)
        command.add_argument("--operator", required=True)
        command.add_argument("--manifest", default=str(HERE / "fis-profiles.json"))
        command.add_argument("--artifacts", default="evidence/fis")
        command.add_argument("--episode", type=lane.episode_name, default=f"fis-{os.getpid()}-{time.time_ns()}")
        command.add_argument("--observer", default="evidence/fis/observer")
        command.add_argument("--aws", default="aws")
        command.add_argument("--lane", default=shlex.join([sys.executable, str(HERE / "hardware-lane.py")]))
        command.add_argument("--hardware-manifest", default=str(lane.MANIFEST),
                             help="the hardware manifest the case runs under and its receipt is judged against")
        command.add_argument("--poll", type=positive_seconds, default=2.0)
        command.add_argument("--custody", default=lane.CUSTODY_DIR)
        command.add_argument("--kill-grace-seconds", type=lane.finite_seconds, default=KILL_GRACE_SECONDS,
                             help="the caller's kill grace after a signal, which the cleanup of every admitted contract fits")
        command.add_argument("--aws-seconds", type=lane.finite_seconds, default=60.0,
                             help="seconds one AWS CLI call may take; each cleanup window allows one such call")
        if name == "episode":
            command.add_argument("--profile", required=True)
        else:
            command.add_argument("--profiles", default=os.environ.get("KESTRIKE_FIS_PROFILES", ""))
            command.add_argument("--budget-seconds", type=int, default=DEFAULT_BUDGET_SECONDS)
    return root


def strings(value):
    return isinstance(value, list) and all(isinstance(item, str) for item in value)


def positive_seconds(text):
    """A finite duration above zero: the pause between polls, which every retry loop sleeps before its next call."""
    seconds = lane.finite_seconds(text)
    if seconds <= 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a duration above zero")
    return seconds


def check_manifest(manifest):
    """Rejects a manifest the controller cannot run as declared, before any call or spawn: a profile name that is not
    one plain file name component, since the campaign appends it to the episode name the marks, the receipt and the
    observer log are named after; an attachment mode other than the ones the target checks implement; an action the
    manifest lists no eligible volume types for; and, for the latency action, direction flags that are not JSON
    booleans, flags that enable no direction, or a `latency_ms` that is not a whole number, the shapes the template
    and the bounds check read."""
    for name, profile in manifest["profiles"].items():
        try:
            lane.episode_name(name)
        except argparse.ArgumentTypeError as error:
            raise Rejected(f"manifest profile {error}") from None
        if profile.get("attachment") not in ATTACHMENT_MODES:
            raise Rejected(f"manifest profile {name!r} declares attachment mode {profile.get('attachment')!r}; "
                           f"the controller implements {list(ATTACHMENT_MODES)}")
        if profile.get("action") not in manifest["eligible_types"]:
            raise Rejected(f"manifest profile {name!r} names action {profile.get('action')!r}, which the manifest's "
                           "eligible_types does not list")
        if profile["action"] == "aws:ebs:volume-io-latency":
            for key in ("read", "write"):
                if not isinstance(profile.get(key), bool):
                    raise Rejected(f"manifest profile {name!r} has {key} {profile.get(key)!r}, not a JSON boolean")
            if not (profile["read"] or profile["write"]):
                raise Rejected(f"manifest profile {name!r} enables no direction; the template takes 100 percent of the "
                               "direction under test")
            latency = profile.get("latency_ms")
            if not isinstance(latency, int) or isinstance(latency, bool):
                raise Rejected(f"manifest profile {name!r} has latency_ms {latency!r}, not a whole number of milliseconds")


def check_attachments(manifest, names, operator):
    """Rejects a profile set no one volume can serve, before any call: profiles of two attachment modes, since a
    volume's Multi-Attach setting admits one, and a `multi-attach-one` profile whose contract declares other than one
    instance for a volume, since that mode admits exactly the one declared attachment."""
    modes = sorted({manifest["profiles"][name]["attachment"] for name in names})
    if len(modes) > 1:
        raise Rejected(f"the chosen profiles name the attachment modes {modes}; one volume serves one mode")
    if modes == ["multi-attach-one"]:
        for volume in operator["volumes"]:
            declared = operator["attachments"].get(volume, [])
            if len(declared) != 1:
                raise Rejected(f"attachments declares {declared!r} for {volume}; a multi-attach-one profile takes "
                               "exactly one instance")


def check_episode(episode, manifest):
    """Rejects an episode name whose derived names overflow. The campaign's episode is `{episode}-{profile}`; the
    template's `episode` tag must fit FIS's 256-character tag value, and the receipt's temporary
    `fis-{profile}-{episode}-{profile}.json.partial`, the longest file name, must fit one file name component; the
    marks and the observer log are shorter. The check runs before any case is spawned."""
    widest = max(map(len, manifest["profiles"]))
    tag = len(episode) + 1 + widest
    if tag > TAG_VALUE_MAX:
        raise Rejected(f"episode {episode!r} is {tag - TAG_VALUE_MAX} characters too long for the template's "
                       "episode tag")
    receipt = len("fis-") + widest + 1 + len(episode) + 1 + widest + len(".json.partial")
    if receipt > NAME_MAX:
        raise Rejected(f"episode {episode!r} is {receipt - NAME_MAX} characters too long for the receipt file "
                       "name derived from it")


def receipt_line(log):
    """The lane's receipt path from its log, the last `receipt:` line, read line by line so a chatty case's log
    costs the controller one line of memory at a time; None when the log has none or cannot be read."""
    receipt = None
    try:
        with open(log, errors="replace") as lines:
            for line in lines:
                if line.startswith("receipt: "):
                    receipt = line[len("receipt: "):].rstrip("\n")
    except OSError:
        return None
    return receipt


def run_bound(profile, operator, aws_seconds):
    """Seconds from the case's spawn by which the run's phases have ended: the readiness, the action's duration,
    the run's effect-timeout windows, the target checks after readiness and after the template and the stop request
    of a proven stop, one AWS call each; AWS calls made during the run are cut at this deadline."""
    return (profile["ready_seconds"] + profile["duration_seconds"] + RUN_WINDOWS * operator["effect_timeout_seconds"]
            + RUN_CALLS * aws_seconds)


def phase_bound(profile, operator, aws_seconds):
    """Seconds one episode's controller phases can take before the case must have ended: the run bound, then the
    cleanup windows, each of which may end with one AWS call of up to `aws_seconds`, the cleanup calls outside
    them, the stop request for an experiment a cut run left live and the listing after the template's deletion, and
    `OBSERVER_OPERATIONS` observer log reads and marks that run past a window or between windows, each waiting at
    most the lane's lock timeout: the frontier read before the spawn, the readiness poll past its window, the
    fault-start mark and the timeout read past the first-timeout window, the stop read past the terminal window, the
    fault-end mark, and the restored read after the case; the case's deadline and the campaign budget both derive
    from it."""
    return (run_bound(profile, operator, aws_seconds) + CLEANUP_CALLS * aws_seconds
            + CLEANUP_WINDOWS * (operator["effect_timeout_seconds"] + aws_seconds)
            + OBSERVER_OPERATIONS * lane.OBSERVER_SECONDS)


def close_seconds(profile, hardware_manifest):
    """Seconds the lane's close takes after the controller terminates a case that outlived its declared seconds:
    the role's longest case grace in the hardware manifest the case runs under, then the lane's stop and controller
    windows."""
    try:
        manifest = json.loads(Path(hardware_manifest).read_text())
        role = manifest["profiles"][profile["lane"]["profile"]]["roles"][profile["lane"]["role"]]
        return max(case["grace"] for case in role["cases"]) + lane.STOP_SECONDS + lane.CONTROLLER_SECONDS
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Rejected(f"the hardware manifest names no lane role for {profile['lane']}: {error}") from None


def episode_bound(profile, operator, aws_seconds, hardware_manifest):
    """Seconds one episode can take from the controller's first call: the pre-run target check, one AWS call of up
    to `aws_seconds` made before the case is spawned, then the phases `phase_bound` measures from the spawn, the
    case's declared seconds and the lane's close after a case that outlived them is terminated. The campaign budget
    sums it over the chosen profiles."""
    return (aws_seconds + phase_bound(profile, operator, aws_seconds) + profile["case_seconds"]
            + close_seconds(profile, hardware_manifest))


def cleanup_bound(profile, operator, aws_seconds, hardware_manifest):
    """Seconds the controller's cleanup after a signal can take on its longest path, a start whose outcome is
    unknown: the discovery listing, the stop's end, its restoration poll, the abandon wait and the template's
    deletion, five effect windows each ending in one AWS call, with the stop request and the listing after the
    deletion, one call each, then the lane's close."""
    return (CLEANUP_PATH_WINDOWS * (operator["effect_timeout_seconds"] + aws_seconds) + CLEANUP_CALLS * aws_seconds
            + close_seconds(profile, hardware_manifest))


def check_profiles(manifest, names, operator, aws_seconds):
    """Rejects a profile whose case's declared seconds cannot hold the controller's phases under this contract."""
    for name in names:
        profile = manifest["profiles"][name]
        bound = phase_bound(profile, operator, aws_seconds)
        if bound > profile["case_seconds"]:
            raise Rejected(f"profile {name} needs up to {bound:g} s before its case ends, past its "
                           f"{profile['case_seconds']} s case; lower effect_timeout_seconds")


def check_grace(manifest, names, operator, aws_seconds, grace, hardware_manifest):
    """Rejects a profile whose cleanup after a signal, plus the close-out that writes the quarantine marker and the
    receipt after it, the caller's kill grace cannot hold."""
    for name in names:
        cleanup = (cleanup_bound(manifest["profiles"][name], operator, aws_seconds, hardware_manifest)
                   + CLOSE_OUT_SECONDS)
        if cleanup > grace:
            raise Rejected(f"profile {name} needs up to {cleanup:g} s of cleanup and close-out after a signal, past "
                           f"the {grace:g} s kill grace; lower effect_timeout_seconds or --aws-seconds")


def check_operator(operator):
    """Rejects an operator contract whose keys or field shapes differ from the documented ones."""
    if not isinstance(operator, dict):
        raise Rejected(f"the operator contract is {type(operator).__name__}, not an object")
    if set(operator) != OPERATOR_KEYS:
        raise Rejected(f"operator contract keys {sorted(operator)}")
    for name in ("account", "region", "role_arn"):
        if not isinstance(operator[name], str):
            raise Rejected(f"{name} {operator[name]!r} is not a string")
    role = operator["role_arn"].split(":")
    if (len(role) != 6 or role[:1] != ["arn"] or role[2:4] != ["iam", ""] or not role[1]
            or not role[5].startswith("role/")):
        raise Rejected(f"role_arn {operator['role_arn']!r} is not an IAM role ARN; the target ARNs take its partition")
    for name in ("volumes", "stop_alarms"):
        if not strings(operator[name]):
            raise Rejected(f"{name} {operator[name]!r} is not a list of strings")
    attachments = operator["attachments"]
    if not isinstance(attachments, dict) or not all(isinstance(k, str) and strings(v) for k, v in attachments.items()):
        raise Rejected(f"attachments {attachments!r} is not a map from volume ID to a list of instance IDs")
    effect = operator["effect_timeout_seconds"]
    if not isinstance(effect, int) or isinstance(effect, bool) or effect <= 0:
        raise Rejected(f"effect_timeout_seconds {effect!r} is not a positive whole number of seconds")


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        manifest_data = Path(args.manifest).read_bytes()
        manifest, manifest_sha256 = json.loads(manifest_data), hashlib.sha256(manifest_data).hexdigest()
        operator = json.loads(Path(args.operator).read_text())
        check_operator(operator)
        check_manifest(manifest)
        check_episode(args.episode, manifest)
        try:
            platforms = lane.read_manifest(args.hardware_manifest)[0]
        except (lane.Stop, *lane.FAULTS) as error:
            raise Rejected(f"the hardware manifest {args.hardware_manifest} is unusable: {error}") from None
        if (row := os.environ.get("KESTRIKE_HARDWARE_PLATFORM")) not in platforms:
            raise Rejected(lane.platform_refusal(row, "KESTRIKE_HARDWARE_PLATFORM"))
        # The quarantine fails closed, as the sweep's does: a custody directory this account cannot list or write
        # refuses the run, since a held group or an unconfirmed fault could leave no marker.
        try:
            make_directory(args.custody)
            os.listdir(args.custody)
        except OSError as error:
            raise Rejected(f"the custody directory {args.custody} is unusable: {error}") from None
        if not os.access(args.custody, os.W_OK | os.X_OK):
            raise Rejected(f"the custody directory {args.custody} is not writable by this account, so a held group "
                           "or an unconfirmed fault could leave no marker")
        # One campaign or sweep at a time holds the host: the lane's host reservation is taken for the process's
        # life before the markers are read, so two campaigns, or a campaign and a sweep, cannot both pass an empty
        # check and spawn cases.
        reservation = lane.reserve_host(args.custody)
        if reservation is None:
            print(f"another sweep or FIS controller holds this host through {Path(args.custody) / 'fis.lock'}",
                  flush=True)
            return HELD_EXIT
        args.reservation = reservation
        # A held case group from any earlier job quarantines the host through its custody marker; the sweep refuses
        # the host the same way, and the cases this controller spawns write their markers under the same directory.
        held = lane.held_custody(args.custody)
        if held:
            print(f"custody held on this host: {held}; contain the groups and remove their markers under "
                  f"{args.custody} before any FIS profile runs here", flush=True)
            return HELD_EXIT
        if args.command == "episode":
            if args.profile not in manifest["profiles"]:
                raise Rejected(f"no FIS profile {args.profile!r}")
            check_profiles(manifest, [args.profile], operator, args.aws_seconds)
            check_attachments(manifest, [args.profile], operator)
            check_grace(manifest, [args.profile], operator, args.aws_seconds, args.kill_grace_seconds,
                        args.hardware_manifest)
            return episode(args, manifest, args.profile, operator, manifest_sha256)[0]
        undeclared = set(args.profiles.split()) - set(manifest["profiles"])
        if undeclared:
            raise Rejected(f"KESTRIKE_FIS_PROFILES names undeclared profiles {sorted(undeclared)}")
        chosen = [name for name in manifest["profiles"] if name in args.profiles.split()]
        if not chosen:
            raise Rejected("KESTRIKE_FIS_PROFILES names no profile, so the contract would qualify nothing; "
                           "name the provisioned profiles")
        check_profiles(manifest, chosen, operator, args.aws_seconds)
        check_attachments(manifest, chosen, operator)
        needed = sum(episode_bound(manifest["profiles"][name], operator, args.aws_seconds, args.hardware_manifest)
                     for name in chosen)
        if needed > args.budget_seconds:
            raise Rejected(f"the chosen profiles need up to {needed:g} s, past the {args.budget_seconds} s budget")
        check_grace(manifest, chosen, operator, args.aws_seconds, args.kill_grace_seconds, args.hardware_manifest)
        worst, stopped, unrun = 0, None, 0
        for name in manifest["profiles"]:
            if name not in chosen or stopped:
                unrun += 1
                print(f"- {name}: unrun; {stopped if name in chosen else 'this host is not provisioned for it'}")
                continue
            code, section = episode(argparse.Namespace(**{**vars(args), "episode": f"{args.episode}-{name}"}),
                                    manifest, name, operator, manifest_sha256)
            stopped = {HELD_EXIT: "custody is held", lane.INTERRUPTED: "the campaign was interrupted"}.get(code)
            if stopped is None and section.get("fault_end_unconfirmed"):
                stopped = "the previous fault's end is unconfirmed"
                code = max(code, 1)
            worst = HELD_EXIT if HELD_EXIT in (worst, code) else max(worst, code)
        print(f"- the matrix credits only with every profile HELD; {unrun} unrun")
        return worst
    except (Rejected, *lane.FAULTS) as error:
        print(f"rejected input: {type(error).__name__}: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
