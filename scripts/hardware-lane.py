#!/usr/bin/env python3
"""Run declared hardware cases by exact ID, once each, and judge their credit.

Usage:
  hardware-lane.py run --profile P --role R [--platform ROW] [--episode ID] [--observer DIR]
      [--controller CMD] [--controller-seconds S] [--environment FILE]
      [--manifest F] [--artifacts DIR] [--run-id ID] [--cargo PATH]
  hardware-lane.py judge --profile P [--manifest F] [--revision SHA] RECEIPT...
  hardware-lane.py sweep [--platform ROW] [--manifest F] [--artifacts DIR] [--budget-seconds S] [--cargo PATH]

`run` and `sweep` take the host's platform row from `--platform`, by default
`KESTRIKE_HARDWARE_PLATFORM`, and refuse a name the manifest lacks.

`run` builds the `kestrike` library tests once with the reproducer's build
step, hashes the executable, and for each case of the role lists its exact ID
plainly and with `--ignored`, then runs it once in its own process group with
`--exact ID --test-threads=1 --ignored --nocapture`, under the case's
deadline. The case receives the inherited environment with every
`KESTRIKE_*` value replaced by exactly the inputs the case declares, the
values the role's `env` pins, and `KESTRIKE_EPISODE`, so an ambient control
the manifest does not name for that case, such as `KESTRIKE_ALLOW_RESET`
on a host provisioned for another profile, never changes what the case does.
The case environment omits `RUNNER_TRACKING_ID`, the key a GitHub runner's end-of-job orphan cleanup
kills by, so a held group outlives the job stopped. Evidence file names spell each `::`
of a test ID as `-`, because the artifact upload refuses a colon in a path.
A deadline or a SIGTERM or SIGINT to the lane closes the case. A case whose manifest
entry sets `closes_on_sigterm` and whose role's readiness line has appeared
receives SIGTERM, which asks a serving owner to close, and the case's grace;
one that exits 0 within it closed itself. The readiness line is printed by the
installed close handler, so it proves SIGTERM has a handler. Any
other case may still hold device custody, and SIGTERM's default action would
end it and release its memory, so the lane stops its group with SIGSTOP
first. Then the lane asks the containment controller to contain the stopped
group: on an acknowledgement the lane kills the group, and otherwise it leaves
the group stopped, with its memory, for the operator, and writes the group's
marker under `--custody` (`/var/tmp/kestrike-hardware-custody` by default),
which quarantines the host: the next `sweep` exits 4 before any role while
the group lives, and removes the marker once the group is gone. The marker
goes down when the case starts, so a supervisor the runner kills mid-case
leaves the group's identity behind, and a case that ended takes its marker
with it. A role whose supervisor died by a signal leaves a marker with no
group beside any marker its case left, and that marker holds until an
operator removes it. An observer write
failure while a case runs takes the same path, and so does a descendant left
running in the group after the case exited, which inherited the case's device
descriptors. Any other lane error that
leaves the case running stops its group with SIGSTOP and holds it for the
operator; the receipt records `stop: lane error`. A case
starts after its `after` role's readiness event in the same profile of the
episode's observer log, waiting every case deadline, and each of those cases'
observer lock waits, of every role in its `after` chain, since every role of a
profile starts at once. A `run` without `--episode` names a fresh episode;
paired roles share the episode their caller passes, and the lane acknowledges
any readiness event that episode's log already holds, so a caller supplies an
episode the log has not seen. An episode is one file name of letters, digits,
`.`, `_` and `-`, starting with a letter or digit, so its log stays inside the
observer directory. Once a case fails or a group is held, the role
runs no further case: the role stays uncredited, so it stops to limit the
privileged work it runs against devices the failed case left as they were.

Credit needs a supported platform row of the host's machine, named by
`--platform`, on which the
profile's disposition is `runs`, whose approved envelope the host reproduces,
its `cpu_family` identity lines included, and which declares every PCI
function a case's mappings file binds,
a clean tree, every declared input set, every value
the role's `env` declares present with that value among the inputs, the
expected listed and ignored counts, the `after` role's readiness
acknowledged, one attempt that executed exactly the expected tests with a
passing summary and every witness in its output, no descendant left running,
and no deadline, interruption or containment request; a role the lane kills
at its declared point is credited from its kill instead of a summary. A row
that is unsupported, names another machine, carries another disposition or
excludes the host from its envelope builds and runs nothing, runs no cargo or
rustc probe, and the receipt's first failure reads `Inconclusive` with the
reason; the receipt records the revision and the `dirty` flag but no toolchain
or dependencies. A tree with tracked
modifications, or
an untracked file outside the lane's own artifacts directory, builds and runs
nothing; the receipt records every untracked file and the artifacts directory,
both relative to the checkout, and `judge` applies the same rule. The receipt
keeps the first failure; later checks never replace it.

A case whose inputs name `KESTRIKE_CONTROLLER_REQUESTS` and
`KESTRIKE_CONTROLLER_ACKS` gets them as FIFOs in its run directory. The
channel's first frame, when it is `contain <endpoint>` naming the case's
`KESTRIKE_MAPPINGS` value, goes to the controller as `contain-endpoint`
with the case's custody census lines printed so far on either stream; the
lane writes `contained <endpoint>` back only when the controller exits 0
after printing `fenced`, `device contained`, `host contained` and
`contained`, each followed by the endpoint. Any other first frame is
recorded and never relayed; a frame past 4096 bytes, or any frame after the
first, ends the relay with that frame recorded. Credit needs
exactly one exchange, acknowledged and carrying a census, and nothing else
on the channel. Such a case declares no `closes_on_sigterm`, so a deadline
or lane signal stops its group and asks the controller to contain it before
any signal reaches it, whether it is parked on its channel or wrote no
request; a refusal leaves its group stopped and held. Without a controller
such a case is reported unrun.

Each `observe: <name> <detail>` line a case prints on either stream
becomes an `observed` event in the episode's observer log, with its
ordinal and, as `after`, the ordinal of each other role's latest event
appended before it; that frontier, never wall time, orders the hosts.
`judge` refuses a receipt carrying an event of another role, profile or
episode, an event without an ordinal, and a frontier that names a later
ordinal or omits an earlier event of another role. A profile may declare a
`conjunction`, chains of `role:name detail` entries, each entry naming an
observed event's name or a lane event's kind and a substring of its detail
into which the role's recorded inputs fill `{NAME}` fields; `judge` requires
each chain in one episode in its order. A profile may declare an `evidence`
input naming the deployment owner's abrupt-death evidence file, without
which every case of the profile is reported unrun. A role with one case
may declare `kill`, a finite number of seconds after its readiness at
which the lane sends SIGKILL to its group, only in a profile that declares
`evidence`; the case is credited only when the lane killed it then and
every member of its group ended within the case's grace, and a group still
alive after the grace stays held. A deadline or lane signal that arrives by
the kill point takes the close path instead.

`run` exits 0 when the role is
credited, 1 when it is not, 2 for rejected input, an unusable tool, a failed
build, an unwritable receipt or an end event the observer log would not take,
4 when it left a process group held, whatever
else failed, and 5 when interrupted. The receipt's `credited` flag follows the
exit status, so a failure after the cases ran leaves it false.

`judge` credits a profile only from one credited receipt per declared role
whose cases are exactly the role's declared cases with their expected
counts, all from one clean tree, episode, revision, toolchain and resolved
dependency set, and from
the revision `--revision` names, the checkout's HEAD by default. Each role
builds its own executable, so the receipts' digests identify what ran on
each host; the toolchain and the dependency versions Cargo resolved, which an
ignored `Cargo.lock` leaves to each host, are what the roles must share. It recomputes
every credit condition from the manifest and the evidence each receipt
recorded: the platform row against the receipt's host, the
episode, revision, toolchain, dependencies and executable digest, the inputs, the readiness acknowledgement, which must
name a readiness event the `after` role's receipt recorded under the same
profile and episode, the exit
status, the counts, the witnesses and the custody fields; a receipt's own
`credited` flag, `missing_witnesses` list and platform copy never credit on their own.
Every role's receipt names one platform row, the same for all roles; its `platform.row` only selects that
row, and the current manifest supplies the row's support, machine and envelope and the profile's disposition
on it, so a name the manifest lacks earns no credit.
Credit follows the current manifest: each receipt records `manifest_sha256`, the digest of the
manifest bytes its run parsed, which must equal the digest of the manifest `judge` reads, and
each case records `witness_counts`, how often its output held each witness the case declared,
from which `judge` derives the witnesses the current manifest declares that the output lacked.
A receipt missing either field earns no credit, and the reason names the field. `sweep` runs each role that
`KESTRIKE_HARDWARE_ROLES`, a space-separated list of `profile/role` or
`profile/role=/path/role.env` entries, names as provisioned on this host, one
profile after another in manifest order and each profile's roles at once, in
one episode; consecutive profiles the `--platform` row does not run, because
the row is unsupported or their disposition there is not `runs`, start their
roles at once as one group, since each such role stops before its build. A
credited containment case leaves its endpoint fenced until the
controller restores it, so the manifest lists `spdk-containment` after every
other profile that uses the endpoint, before only the kill profile, whose
killed host awaits containment and ends the sweep. A
role's environment file holds one `KESTRIKE_*=value` assignment per line,
supplies every input the role's cases declare and every value its `env`
pins, and overrides the ambient environment for that role's case, so
same-host roles of one profile each take their own mappings file and client
index; `run` takes it as `--environment` and records its path and digest. A role's
`env` in the manifest declares the values its inputs must carry, which
`run` checks and `judge` recomputes, and one profile declares each
`KESTRIKE_CLIENT` index for one role. The sweep runs the roles in one
episode
(`KESTRIKE_EPISODE`, else the CI run and attempt followed by the platform
row) with the observer
directory `KESTRIKE_HARDWARE_OBSERVER` and the controller
`KESTRIKE_HARDWARE_CONTROLLER`, and lists every other role as unrun; it
forwards a SIGTERM to the roles it started, starts no later profile once a
role left custody held or its supervisor died by a signal, whose case's
custody is then unknown, refuses a host provisioned for no role, exits 4 before
any role while a marker under `--custody` names a group a past run left held
or unknown on this host or another sweep or FIS controller holds the host's
reservation `<custody>/fis.lock`, refuses an entry the
manifest does not declare, an episode that is not one file name of letters, digits, `.`, `_` and `-` starting
with a letter or digit, an episode whose observer log already exists, and a
role set whose longest run exceeds `--budget-seconds`, and never credits a
profile. A role's longest run counts, per case, the readiness wait, which is
every case deadline and each of those cases' observer lock waits of every role
in its `after` chain, the deadline, the grace, the stop proof and its repeat,
the controller window and the observer lock waits, plus the role's end event.
A profile that does not run on a supported `--platform` row, because the row is
unsupported or the profile's disposition there is not `runs`, is charged only
its roles' end events, since each such role stops before its build; a role the
host's machine or envelope refuses keeps its full bound.
A profile declaring `kill` is the manifest's last, and the sweep exits 4 after
a kill as after held custody: SIGKILL ended the owner before its teardown, so
the host awaits the deployment owner's containment before it serves again: the
role writes a `killed-<episode>.json` marker with no group under `--custody`
before its SIGKILL, which holds the next sweep and the FIS campaign off the
host until an operator removes it or a reboot, which ends the process hazard,
clears it.
"""

import argparse
import contextlib
import fcntl
import hashlib
import importlib.util
import json
import math
import os
import platform
import re
import resource
import select
import shlex
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path, PurePosixPath

HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


reproducer = load("reproduce_test", HERE / "reproduce-test.py")
selector = load("select_tests", HERE / "select-tests.py")
Stop = reproducer.Stop
CREDITED, UNCREDITED, REJECTED, HELD, INTERRUPTED = 0, 1, 2, 4, 5
ENVELOPE = {"version": 1, "section": "hardware"}
MANIFEST = HERE / "hardware-profiles.json"
PACKAGE, TARGET, CRATE = "kestrike", "lib", "kestrike"
POLL = 0.05
CONTROLLER_SECONDS = 30.0
STOP_SECONDS = 10.0
OBSERVER_SECONDS = 5.0
# Where a held group's marker outlives the job, so the next sweep on this host refuses to start beside it.
CUSTODY_DIR = "/var/tmp/kestrike-hardware-custody"
# The observer operations a case may wait on, each bounded by OBSERVER_SECONDS: the readiness poll that overruns
# its deadline, the acknowledgement, the start, the readiness and the exit events.
OBSERVER_OPERATIONS = 5
# The one mappings file format `Mappings::read` (crates/kestrike/src/bind/mappings.rs, FORMAT) accepts.
MAPPINGS_FORMAT = "3"
# The reproducer's recorded environment names that change what a build produces; the roles of a profile must share them.
BUILD_ENVIRONMENT = ("RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_TARGET", "CARGO_PROFILE_DEV_OPT_LEVEL",
                     "CARGO_PROFILE_DEV_DEBUG", "RUSTC", "RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER", "SPDK_PKG_CONFIG_PATH")
FAULTS = (OSError, ValueError, KeyError, TypeError, AttributeError)
# A case naming these inputs gets them from the lane as the two ends of its containment channel.
CHANNEL = ("KESTRIKE_CONTROLLER_REQUESTS", "KESTRIKE_CONTROLLER_ACKS")
CONTAINED = ("fenced", "device contained", "host contained", "contained")
# The longest channel frame in bytes, line break included.
FRAME = 4096
PROFILE_KEYS = {"platforms", "roles", "retries"}
# A profile's disposition on each platform row; credit requires `runs`.
DISPOSITIONS = ("runs", "pending", "excluded")
OPTIONAL_PROFILE_KEYS = {"conjunction", "evidence"}
CASE_KEYS = {"id", "expected", "inputs", "deadline", "grace", "witnesses", "restoration", "closes_on_sigterm"}
ROLE_KEYS = {"cases", "after", "ready", "closing", "env", "kill"}
ENVIRONMENT_NAME = re.compile(r"KESTRIKE_[A-Z0-9_]+")
EPISODE_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")


def check_manifest(document):
    """Return the manifest's platforms and profiles, or raise Stop naming the first malformed field."""
    def need(condition, message):
        if not condition:
            raise Stop(REJECTED, f"malformed hardware manifest: {message}")

    need(isinstance(document, dict) and {"version", "platforms", "profiles"} <= set(document)
         <= {"version", "platforms", "profiles", "qualification", "packages"}
         and isinstance(document.get("qualification", {}), dict) and isinstance(document.get("packages", {}), dict),
         "top-level keys")
    need(document["version"] == 1, f"version {document['version']!r}")
    platforms, profiles = document["platforms"], document["profiles"]
    need(isinstance(platforms, dict) and isinstance(profiles, dict), "platforms and profiles must be objects")
    for name, row in platforms.items():
        need(EPISODE_NAME.fullmatch(name), f"platform name {name!r} is not an episode name of letters, digits, '.', "
             "'_' and '-' starting with a letter or digit, which a CI episode needs")
        need({"machine", "supported", "owner"} <= set(row) <= {"machine", "supported", "owner", "envelope"}
             and isinstance(row["supported"], bool), f"platform {name}")
        identity_lines = reproducer.IDENTITY_LINES.get(row["machine"], ()) if isinstance(row["machine"], str) else ()
        need(identity_lines, f"platform {name} names machine {row['machine']!r}, which has no CPU identity lines")
        envelope = row.get("envelope", {})
        need(isinstance(envelope, dict) and set(envelope) <= set(ENVELOPE_FIELDS), f"platform {name} envelope")
        devices, family, features = envelope.get("devices"), envelope.get("cpu_family"), envelope.get("cpu_features")
        shaped = {
            "devices": isinstance(devices, dict) and all(
                isinstance(identity, str) and re.fullmatch(r"0x[0-9a-f]{4}:0x[0-9a-f]{4}", identity)
                for identity in devices.values()),
            "cpu_family": isinstance(family, dict) and set(family) == set(identity_lines) and all(
                isinstance(value, str) and value and value == value.strip() and value not in UNREAD
                for value in family.values()),
            "cpu_features": isinstance(features, list) and all(
                isinstance(feature, str) and feature and feature.split() == [feature] for feature in features),
        }
        empty = (None, "", [], {}, *UNREAD)
        short = [field for field in ENVELOPE_FIELDS if envelope.get(field) in empty or not shaped.get(field, True)]
        need(not row["supported"] or not short, f"platform {name} is supported with an envelope short of {short}")
    killer = None
    for name, profile in profiles.items():
        need(PROFILE_KEYS <= set(profile) <= PROFILE_KEYS | OPTIONAL_PROFILE_KEYS, f"profile {name}")
        need(isinstance(profile["platforms"], dict) and set(profile["platforms"]) == set(platforms)
             and all(disposition in DISPOSITIONS for disposition in profile["platforms"].values()),
             f"profile {name} needs one disposition of {DISPOSITIONS} per platform row")
        need(killer is None, f"profile {name} follows the kill profile {killer}, whose host awaits containment")
        killer = name if any("kill" in role for role in profile["roles"].values()) else None
        need(profile["retries"] == 0, f"profile {name} declares retries")
        need(isinstance(profile["roles"], dict) and profile["roles"], f"profile {name} has no roles")
        need(isinstance(profile.get("conjunction", []), list)
             and all(isinstance(chain, list) and chain
                     and all(isinstance(entry, str) and entry.partition(":")[0] in profile["roles"] and entry.partition(":")[2]
                             for entry in chain)
                     for chain in profile.get("conjunction", [])), f"profile {name} conjunction")
        need(str(profile.get("evidence", "KESTRIKE_")).startswith("KESTRIKE_"), f"profile {name} evidence")
        need("evidence" in profile or not any("kill" in role for role in profile["roles"].values()),
             f"profile {name} kills a role without an evidence gate")
        for role_name, role in profile["roles"].items():
            need(set(role) <= ROLE_KEYS and role.get("cases"), f"role {name}/{role_name}")
            env = role.get("env", {})
            need(isinstance(env, dict) and all(isinstance(key, str) and ENVIRONMENT_NAME.fullmatch(key)
                                              and isinstance(value, str) for key, value in env.items()),
                 f"role {name}/{role_name} env")
            need(role.get("after") in (None, *profile["roles"]), f"role {name}/{role_name} waits on an unknown role")
            need(role.get("after") is None or isinstance(profile["roles"][role["after"]].get("ready"), str)
                 and profile["roles"][role["after"]]["ready"],
                 f"role {name}/{role_name} waits on {role.get('after')}, which declares no readiness line")
            need(predecessors(profile, role_name) is not None, f"role {name}/{role_name} waits on itself")
            need(all(isinstance(role[key], str) and role[key] for key in ("ready", "closing") if key in role),
                 f"role {name}/{role_name} readiness and closing lines are non-empty strings")
            need((role.get("ready") and role.get("closing")) or not any(case.get("closes_on_sigterm") for case in role["cases"]),
                 f"role {name}/{role_name} closes on SIGTERM without a readiness and a closing line")
            # A kill delay is a finite non-negative number, as JSON booleans count as integers in Python.
            need("kill" not in role or (isinstance(role["kill"], (int, float)) and not isinstance(role["kill"], bool)
                                        and math.isfinite(role["kill"]) and role["kill"] >= 0 and role.get("ready")),
                 f"role {name}/{role_name} kill")
            # SIGKILL ends the role's owner without its teardown, so the role runs nothing after its killed case.
            need("kill" not in role or len(role["cases"]) == 1, f"role {name}/{role_name} kill role runs one case")
            ids = [case.get("id") for case in role["cases"]]
            need(len(ids) == len(set(ids)), f"role {name}/{role_name} names a case twice")
            for case in role["cases"]:
                need(set(case) == CASE_KEYS, f"case {case.get('id')!r} keys {sorted(case)}")
                need(isinstance(case["expected"], int) and case["expected"] >= 1, f"case {case['id']} expects no test")
                need(all(isinstance(limit, (int, float)) and not isinstance(limit, bool) and math.isfinite(limit) and limit > 0
                         for limit in (case["deadline"], case["grace"])),
                     f"case {case['id']} needs a finite positive deadline and grace")
                need(all(name.startswith("KESTRIKE_") for name in case["inputs"]), f"case {case['id']} inputs")
                need(len(set(CHANNEL) & set(case["inputs"])) in (0, 2), f"case {case['id']} names half a channel")
                need(not (CHANNEL[0] in case["inputs"] and case.get("closes_on_sigterm")),
                     f"case {case['id']} closes on SIGTERM while parked on its containment channel")
                need("KESTRIKE_EPISODE" not in case["inputs"] and "KESTRIKE_EPISODE" not in env,
                     f"case {case['id']} names KESTRIKE_EPISODE, which the lane sets itself")
                need(isinstance(case["closes_on_sigterm"], bool), f"case {case['id']} closes_on_sigterm")
        clients = [role["env"]["KESTRIKE_CLIENT"] for role in profile["roles"].values()
                   if "KESTRIKE_CLIENT" in role.get("env", {})]
        need(len(clients) == len(set(clients)), f"profile {name} declares one client index for two roles")
    return platforms, profiles


def role_environment(path, role=None, label=None):
    """The `KESTRIKE_*` assignments a role's environment file holds, one `NAME=value` per line.

    With `role`, the file must supply every input the role's cases declare, apart from the channel's two the
    lane creates, and every value its `env` pins, so the ambient environment supplies nothing to a role that
    brought its own.
    """
    if not os.path.isabs(path):
        raise Stop(REJECTED, f"role environment {path} is not an absolute path")
    if not os.path.isfile(path):
        raise Stop(REJECTED, f"role environment {path} is not a regular file")
    try:
        text = Path(path).read_text()
    except OSError as error:
        raise Stop(REJECTED, f"role environment {path} is unreadable: {error}") from error
    pairs = {}
    for number, line in enumerate(text.split("\n"), 1):
        if not line.strip():
            continue
        name, separator, value = line.partition("=")
        if not separator or not ENVIRONMENT_NAME.fullmatch(name):
            raise Stop(REJECTED, f"role environment {path} line {number} is not an KESTRIKE_ assignment")
        pairs[name] = value
    if role is not None:
        required = ({name for case in role["cases"] for name in case["inputs"]} - set(CHANNEL)) | set(role.get("env", {}))
        missing = sorted(required - set(pairs))
        if missing:
            raise Stop(REJECTED, f"role environment {path} lacks {missing} for {label}")
    return pairs


def stray_untracked(untracked, artifacts):
    """The untracked files that are not descendants of the lane's artifacts directory, both relative to the checkout.

    The reproducer records every untracked file by name, so the files the lane writes under the checkout are the
    untracked content a clean run leaves; any other untracked file is an input the revision does not name. The
    checkout itself is no artifacts directory, so `.` or a path above the checkout leaves every untracked file stray.
    """
    if not isinstance(untracked, list) or not isinstance(artifacts, str):
        return ["unrecorded"]
    inside = PurePosixPath(artifacts).parts
    if not inside or inside[0] == "..":
        return list(untracked)
    return [entry for entry in untracked if PurePosixPath(entry).parts[:len(inside)] != inside]


def readiness_wait(profile, role_name):
    """The longest a role waits for its `after` role's readiness: every case deadline, and every case's bounded
    observer waits, of every role in its `after` chain, since each predecessor's own wait precedes its startup and
    its readiness may come in its last case."""
    seconds, roles = 0, profile["roles"]
    while (role_name := roles[role_name].get("after")) is not None:
        seconds += sum(case["deadline"] + OBSERVER_OPERATIONS * OBSERVER_SECONDS for case in roles[role_name]["cases"])
    return seconds


def predecessors(profile, role_name):
    """How many roles `role_name` waits on through its `after` chain, or None when the chain loops."""
    depth, roles = 0, profile["roles"]
    while (role_name := roles[role_name].get("after")) is not None:
        depth += 1
        if depth > len(roles):
            return None
    return depth


def git_revision():
    done = subprocess.run(["git", "-C", str(HERE), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    if done.returncode != 0:
        raise Stop(REJECTED, f"git rev-parse HEAD exited {done.returncode}: {done.stderr.strip()}")
    return done.stdout.strip()


def registry_rows(profiles):
    """The ordinary hardware-privileged registry rows by test ID, from a registry at the inventory's baseline.

    Every such row belongs to a profile and every profile case is such a row,
    so no privileged test goes unscheduled and no profile names an ordinary test.
    """
    try:
        inventory = selector.load_inventory(selector.INVENTORY)
        registry = selector.load_registry(selector.REGISTRY, inventory["baseline"])
    except selector.Refusal as refusal:
        raise Stop(REJECTED, f"the registry was refused: {refusal}") from refusal
    rows = {row["id"]: row for (cfg, target, _), row in registry.items()
            if cfg == "ordinary" and target == CRATE and row["class"] == "hardware-privileged"}
    declared = {case["id"] for profile in profiles.values() for role in profile["roles"].values()
                for case in role["cases"]}
    if declared != set(rows):
        raise Stop(REJECTED, f"the profiles and the hardware-privileged registry rows differ: "
                             f"{sorted(declared ^ set(rows))}")
    return rows


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as source:
        for block in iter(lambda: source.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def read(path):
    try:
        return Path(path).read_text(errors="replace").strip()
    except OSError:
        return None


def artifact_name(case_id):
    """The evidence file stem for a test ID; a Rust path never holds `-`, so each stem names one ID."""
    return case_id.replace("::", "-")


def group_alive(pgid):
    """Whether any process of the group `pgid` still runs."""
    try:
        os.killpg(pgid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def stat_fields(path):
    """The fields after the command of a `/proc` stat file, or None when the process or task is gone."""
    try:
        return path.read_text().rpartition(")")[2].split()
    except OSError:
        return None


def group_members(pgid, proc=Path("/proc")):
    """Each process of the group `pgid` other than a zombie, by pid, with the start time `/proc` reports for it.

    The start time (field 22 of `/proc/<pid>/stat`, index 19 after the command) names one process for the life of
    the host, so a later process that reused the pid is told apart from the member recorded at hold time.
    """
    members = {}
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        fields = stat_fields(entry / "stat")
        if fields is not None and len(fields) >= 20 and int(fields[2]) == pgid and fields[0] not in "ZX":
            members[int(entry.name)] = int(fields[19])
    return members


def members_hold_memory(recorded):
    """Whether any recorded member, a pid with the start time it had at hold time, still exists other than as a
    zombie; a stopped or running member keeps its memory, and a pid reused by another process is no member."""
    for pid, started in recorded.items():
        fields = stat_fields(Path("/proc") / str(pid) / "stat")
        if fields is not None and len(fields) >= 20 and fields[0] not in "ZX" and int(fields[19]) == started:
            return True
    return False


def group_running(pgid, proc=Path("/proc")):
    """The members of the group `pgid` with any task `/proc` reports in a state other than stopped or ended.

    `/proc/<pid>/stat` reports the thread-group leader alone; libtest runs the case body on another thread, so
    every task under `/proc/<pid>/task` counts.
    """
    running = []
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        fields = stat_fields(entry / "stat")
        if fields is None or len(fields) < 3 or int(fields[2]) != pgid:
            continue
        try:
            tasks = [stat_fields(task / "stat") for task in (entry / "task").iterdir()]
        except OSError:
            tasks = []
        if any(task[0] not in "TtZX" for task in [fields, *tasks] if task):
            running.append(int(entry.name))
    return running


def stopped(pgid, limit):
    """Waits up to `limit` seconds for every live member of the group to stop; returns the members still running.

    `killpg(SIGSTOP)` only queues the signal, so this is the proof the containment protocol's promise of a stopped
    group rests on.
    """
    deadline = time.monotonic() + limit
    while True:
        running = group_running(pgid)
        if not running or time.monotonic() >= deadline:
            return running
        time.sleep(POLL)


# The platform owner's approved envelope of a platform row. The first group the receipt's host facts must
# reproduce (`OBSERVED`); the rest, the DMA address mode the platform runs under among them, are the modes,
# identities, limits and authorities the owner approves, which the row records and the receipt copies.
OBSERVED = ("instance_type", "cpu_features", "cpu_family", "kernel", "firmware", "vfio", "numa_nodes", "page_size",
            "hugepage_size", "devices")
ENVELOPE_FIELDS = (*OBSERVED, "address_mode", "volume", "eni", "limits", "coherence", "disposable_resources",
                   "reset_blast_radius", "fis_blast_radius", "restoration_authority", "containment_authority")
# UNREAD represents a host fact the lane cannot read.
UNREAD = ("unreadable",)


def envelope_gaps(row, host):
    """Why `host`, a receipt's host facts, is not the platform row's approved envelope: each observed field
    whose host value differs, with `cpu_features` a set the host's must contain and `devices` the vendor and
    device of each declared PCI function, which every host of the platform presents whether or not its roles
    bind it."""
    envelope, gaps = row.get("envelope") or {}, []
    for field in OBSERVED:
        wanted, seen = envelope.get(field), host.get(field)
        if field == "cpu_features":
            features = seen if isinstance(seen, list) and all(isinstance(flag, str) for flag in seen) else []
            missing = sorted(set(wanted or []) - set(features))
            if missing or not wanted:
                gaps.append(f"the host lacks the envelope's cpu_features {missing or wanted}")
        elif field == "devices":
            presented = seen if isinstance(seen, dict) else {}
            differing = sorted(bdf for bdf, identity in (wanted or {}).items()
                               if identity is None or presented.get(bdf) != identity)
            if differing or not wanted:
                gaps.append(f"the host's devices {differing or wanted} are not the envelope's {wanted}")
        elif wanted is None or seen != wanted:
            gaps.append(f"the host's {field} {seen!r} is not the envelope's {wanted!r}")
    return gaps


def manifest_refusal(name, row, profile):
    """Why the manifest alone keeps `profile` off platform row `name`, or None when the profile runs there.

    The row is unsupported or the profile's disposition on it is not `runs`. `platform_defect` returns this reason
    before any host check, and the sweep starts the roles of consecutive profiles it refuses at once, since each such
    role stops before its build."""
    if not row["supported"]:
        return f"Inconclusive: platform row unsupported: {name}"
    if (disposition := profile["platforms"].get(name)) != "runs":
        return f"Inconclusive: the profile's disposition on platform row {name} is {disposition}"
    return None


def platform_defect(name, row, profile, host):
    """Why a role of `profile` on platform row `name` earns no credit on `host`, its recorded host facts, or None.

    Each reason reads `Inconclusive`: the manifest refuses the profile on the row (`manifest_refusal`), the row names
    another machine, or the host is outside its approved envelope, so the run says nothing about the cases."""
    if refusal := manifest_refusal(name, row, profile):
        return refusal
    if (machine := host.get("machine")) != row["machine"]:
        seen = f"the host's {machine!r}" if machine is not None else "a host that records no machine"
        return f"Inconclusive: platform row {name} names machine {row['machine']}, not {seen}"
    if gaps := envelope_gaps(row, host):
        return f"Inconclusive: the host is outside platform row {name}'s envelope: {gaps[0]}"
    return None


def device_identities(bdfs):
    """The `vendor:device` of each PCI function in `bdfs`, or None where sysfs names none."""
    identities = {}
    for bdf in bdfs:
        base = Path("/sys/bus/pci/devices") / bdf
        vendor, device = read(str(base / "vendor")), read(str(base / "device"))
        identities[bdf] = f"{vendor}:{device}" if vendor and device else None
    return identities


def host_facts(row=None):
    """The platform, kernel, firmware, VFIO, DMA and memory facts the receipt records, with the identities of
    the PCI functions `row`'s envelope declares."""
    meminfo = read("/proc/meminfo") or ""
    groups = Path("/sys/kernel/iommu_groups")
    cpuinfo = read("/proc/cpuinfo") or ""
    flags = reproducer.cpu_features(cpuinfo)
    noiommu = read("/sys/module/vfio/parameters/enable_unsafe_noiommu_mode")
    members = list(groups.iterdir()) if groups.is_dir() else []
    hugepage = next((line.split(":", 1)[1].strip() for line in meminfo.splitlines() if line.startswith("Hugepagesize")), None)
    return {
        "instance_type": read("/sys/devices/virtual/dmi/id/product_name") or "unreadable",
        "cpu_features": flags,
        "cpu_family": reproducer.cpu_identity(cpuinfo, platform.machine()) or "unreadable",
        "kernel": platform.release(),
        "vfio": "noiommu" if noiommu == "Y" else "iommu" if members else "unavailable",
        "numa_nodes": read("/sys/devices/system/node/online") or "unreadable",
        "page_size": os.sysconf("SC_PAGE_SIZE"),
        "hugepage_size": hugepage or "unreadable",
        "devices": device_identities(sorted(((row or {}).get("envelope") or {}).get("devices") or {})),
        "machine": platform.machine(),
        "uname": " ".join(platform.uname()),
        "cpu": reproducer.cpu_model(cpuinfo),
        "kernel_cmdline": read("/proc/cmdline"),
        "instance": read("/sys/devices/virtual/dmi/id/board_asset_tag"),
        "firmware": read("/sys/devices/virtual/dmi/id/bios_version") or "unreadable",
        "vfio_pci_loaded": Path("/sys/module/vfio_pci").exists(),
        "vfio_noiommu": noiommu,
        "iommu_groups": len(members),
        "hugepages": [line for line in meminfo.splitlines() if line.startswith(("HugePages_", "Hugepagesize"))],
        "memlock": list(resource.getrlimit(resource.RLIMIT_MEMLOCK)),
    }


# The inputs that name a path the case opens from the package root, so each must be absolute.
PATH_INPUTS = ("KESTRIKE_MAPPINGS", "KESTRIKE_RELEASE_STATE_DIR")


def mappings_path(inputs):
    """The mappings file a case's inputs name: `KESTRIKE_MAPPINGS` itself, or `mappings` under the state
    directory `KESTRIKE_RELEASE_STATE_DIR` names, which is where `bind::binder::mappings_path` reads it."""
    if "KESTRIKE_MAPPINGS" in inputs:
        return inputs["KESTRIKE_MAPPINGS"]
    if "KESTRIKE_RELEASE_STATE_DIR" in inputs:
        return os.path.join(inputs["KESTRIKE_RELEASE_STATE_DIR"], "mappings")
    return None


MAPPED_FUNCTIONS = ("nvme.bdf", "eni.bdf")
MAPPED_VOLUME = "nvme.volume"
MAPPED_ADDRESS = "eni.ipv4"


def mappings_facts(inputs):
    """The identity of the mappings file a case's inputs name, with the PCI functions it binds, the volume it binds
    and the ENI address it binds, each None for a mappings file that binds none."""
    path = mappings_path(inputs)
    if not path or not Path(path).is_file():
        return None
    try:
        data = Path(path).read_bytes()
    except OSError:
        return None
    # One read supplies the digest and every parsed field, so the recorded facts describe the digested bytes.
    lines = data.decode(errors="replace").splitlines()
    version = next((line.split("=", 1)[1] for line in lines if line.startswith("format=")), None)
    pairs = [line.partition("=") for line in lines]
    functions = sorted(value for key, _, value in pairs if key in MAPPED_FUNCTIONS)
    volume, address = (next((value for key, _, value in pairs if key == name), None)
                       for name in (MAPPED_VOLUME, MAPPED_ADDRESS))
    return {"path": path, "sha256": hashlib.sha256(data).hexdigest(), "format": version, "functions": functions,
            "volume": volume, "address": address}


def function_gap(name, row, entry):
    """Why the PCI functions a case's recorded mappings file binds are not all functions platform row `name`'s
    envelope declares, or None when every one is."""
    mappings = entry.get("mappings")
    functions = mappings.get("functions") if isinstance(mappings, dict) else None
    if not (isinstance(functions, list) and functions and all(isinstance(bdf, str) for bdf in functions)):
        return f"records no PCI function its mappings file binds: {functions!r}"
    declared = (row.get("envelope") or {}).get("devices") or {}
    if outside := sorted(set(functions) - set(declared)):
        return f"binds PCI functions {outside} outside platform row {name}'s envelope devices {sorted(declared)}"
    return None


def lock(log, operation, path):
    """Takes the observer log's lock within `OBSERVER_SECONDS`, retrying a nonblocking `flock`.

    A supervisor must keep checking its case's deadline and signals, so a lock another participant holds, or a
    stalled shared filesystem, surfaces as an observer failure instead of a wait without bound.
    """
    deadline = time.monotonic() + OBSERVER_SECONDS
    while True:
        try:
            fcntl.flock(log, operation | fcntl.LOCK_NB)
            return
        except BlockingIOError as error:
            if time.monotonic() >= deadline:
                raise OSError(error.errno, f"the observer log {path} stayed locked for {OBSERVER_SECONDS} s") from error
            time.sleep(POLL)


class Observer:
    """The shared episode log: one JSON event per line, appended under an exclusive lock, ordinals in order."""

    def __init__(self, directory, episode, profile, role):
        self.path = Path(directory) / f"{episode}.jsonl" if directory else None
        self.episode, self.profile, self.role = episode, profile, role

    def opened(self, flags):
        """The log opened with `flags` and O_NOFOLLOW, so a symlink planted under its name is an error rather than
        a path to follow; every read and append goes through here."""
        return os.fdopen(os.open(self.path, flags | os.O_NOFOLLOW, 0o644), "r+" if flags & os.O_RDWR else "r")

    def events(self):
        if self.path is None:
            return []
        try:
            log = self.opened(os.O_RDONLY)
        except FileNotFoundError:
            # An absent log has no events yet; a dangling symlink under the log's name is an error, as a live one is.
            return []
        with log:
            lock(log, fcntl.LOCK_SH, self.path)
            lines = log.read().splitlines()
        try:
            return [json.loads(line) for line in lines if line]
        except ValueError as error:
            raise Stop(REJECTED, f"the observer log {self.path} is malformed: {error}") from error

    def append(self, kind, frontier=False, **fields):
        """Appends one event; with `frontier`, its `after` names each other role's latest ordinal in this profile."""
        if self.path is None:
            return None
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.opened(os.O_RDWR | os.O_CREAT | os.O_APPEND) as log:
            lock(log, fcntl.LOCK_EX, self.path)
            log.seek(0)
            earlier = [json.loads(line) for line in log if line.strip()]
            ordinal = len(earlier) + 1
            if frontier:
                fields["after"] = {event["role"]: event["ordinal"] for event in earlier
                                   if event.get("profile") == self.profile and event["role"] != self.role}
            event = {"episode": self.episode, "ordinal": ordinal, "profile": self.profile, "role": self.role,
                     "kind": kind,
                     "monotonic_ns": time.monotonic_ns(), "wall_diagnostic": time.time(),
                     "host": platform.node(), **fields}
            log.write(json.dumps(event, sort_keys=True) + "\n")
        return event

    def role_events(self, role):
        """The role's events under this profile from one read of the log, so readiness and end are judged together."""
        return [event for event in self.events() if event.get("profile") == self.profile and event["role"] == role]

    def ready(self, role, after=0):
        """The first readiness event of `role` in this profile with an ordinal past `after`: the FIS controller's
        entry point, which takes the log's frontier before it spawns a case and waits for that case's readiness."""
        return next((event for event in self.role_events(role) if event["kind"] == "ready" and event["ordinal"] > after),
                    None)


class Lane:
    def __init__(self, args, profile, manifest_sha256):
        self.args, self.profile, self.role = args, profile, profile["roles"][args.role]
        self.wait = readiness_wait(profile, args.role)
        # Role-specific overrides let same-host roles use distinct KESTRIKE_* inputs.
        self.environment = dict(os.environ)
        if args.environment:
            self.environment.update(role_environment(args.environment, self.role, f"{args.profile}/{args.role}"))
        self.run = reproducer.Run(argparse.Namespace(
            test=args.role, package=PACKAGE, target=TARGET, attempts=1, watchdog=None, release=False,
            artifacts=str(Path(args.artifacts).resolve()), run_id=args.run_id,
            lane=f"hardware-{args.profile}-{args.role}", cargo=args.cargo,
        ))
        self.observer = Observer(args.observer, args.episode, args.profile, args.role)
        self.receipt = {"envelope": ENVELOPE, "hardware": {
            "profile": args.profile, "role": args.role, "episode": args.episode, "attempts_allowed": 1,
            "retries": 0, "cases": [], "first_failure": None, "credited": False, "manifest_sha256": manifest_sha256,
            "environment_file": {"path": args.environment, "sha256": sha256(args.environment)} if args.environment else None,
        }}
        self.case = None
        self.terminated = None
        self.held = []
        self.case_group = None

    @property
    def section(self):
        return self.receipt["hardware"]

    def fail(self, reason):
        if self.section["first_failure"] is None:
            self.section["first_failure"] = reason

    def save(self):
        if self.run.dir is not None:
            (self.run.dir / "receipt.json").write_text(json.dumps(self.receipt, indent=2, sort_keys=True) + "\n")

    def on_signal(self, signum, _frame):
        """A SIGTERM or SIGINT to the lane stops the running case through its close path, then the lane."""
        self.terminated = signum
        if self.run.spawning:
            self.run.pending = signum
        elif self.case is None and self.run.child is not None:
            reproducer.stop_group(self.run.child)
            raise Stop(INTERRUPTED, f"interrupted by signal {signum}")

    def contain(self, case, process):
        """Asks the controller to contain the unfinished case and records what it answered; an answer is no proof."""
        request = {"episode": self.args.episode, "profile": self.args.profile, "role": self.args.role,
                   "case": case["id"], "pid": process.pid, "restoration": case["restoration"]}
        entry = {"requested": request, "acknowledged": False, "answer": None}
        if not self.args.controller:
            entry["answer"] = "no controller"
            return entry
        code, out = self.ask("contain", request)
        if code is None:
            entry["answer"] = out
            return entry
        answer = out.strip()
        entry["answer"] = f"exit {code}: {answer}"
        entry["acknowledged"] = code == 0 and answer == f"contained {case['id']}"
        return entry

    def ask(self, verb, request):
        """Runs the controller once with `verb` and the JSON request; returns its exit status and stdout, or
        None and the reason it gave no answer. The controller runs in its own session, and its whole group
        ends with its window, so a helper it forked cannot keep working on the devices after the lane
        recorded no acknowledgement."""
        try:
            controller = subprocess.Popen([*shlex.split(self.args.controller), verb, json.dumps(request)],
                                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True)
        except OSError as error:
            return None, f"unavailable: {error}"
        try:
            out, _ = controller.communicate(timeout=self.args.controller_seconds)
            return controller.returncode, out.decode(errors="replace")
        except subprocess.TimeoutExpired:
            return None, f"no answer within {self.args.controller_seconds} s"
        finally:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(controller.pid, signal.SIGKILL)
            controller.communicate()

    def bridge(self, case, endpoint, requests, acks, streams, exchanges, done):
        """Relays the channel's first frame, when it is a request naming `endpoint`, to the controller and
        acknowledges it once the controller reports it contained. A frame past FRAME bytes or a second frame ends
        the relay with that frame recorded unrelayed, so the case is held at its close."""
        pending = b""
        while True:
            stopping = done.is_set()
            if select.select([requests], [], [], 0 if stopping else POLL)[0]:
                pending += os.read(requests, FRAME)
            elif stopping:
                if pending:
                    exchanges.append({"request": pending.decode(errors="replace"), "census": [],
                                      "acknowledged": False, "answer": "unterminated at the case's exit"})
                return
            *lines, pending = pending.split(b"\n")
            if len(pending) >= FRAME:
                lines.append(pending[:FRAME])
            for line in lines:
                text = line[:FRAME].decode(errors="replace")
                named = text.removeprefix("contain ")
                census = [row for stream in streams for row in (read(stream) or "").splitlines() if "census" in row]
                exchange = {"request": text, "census": census, "acknowledged": False}
                exchanges.append(exchange)
                if len(line) >= FRAME:
                    exchange["answer"] = f"not relayed: frame past {FRAME} bytes"
                    return
                if len(exchanges) > 1:
                    exchange["answer"] = "not relayed: a second exchange"
                    return
                if stopping or not text.startswith("contain ") or not named:
                    exchange["answer"] = "not relayed"
                    continue
                if named != endpoint:
                    exchange["answer"] = "not relayed: endpoint is not KESTRIKE_MAPPINGS"
                    continue
                request = {"episode": self.args.episode, "profile": self.args.profile, "role": self.args.role,
                           "case": case["id"], "endpoint": endpoint, "census": census}
                code, out = self.ask("contain-endpoint", request)
                if code is None:
                    exchange["answer"] = out
                    continue
                # The protocol's lines end at LF alone; an endpoint may hold the other separators `splitlines` knows.
                said = out.split("\n")
                exchange["answer"] = f"exit {code}: {said}"
                if code == 0 and all(f"{word} {endpoint}" in said for word in CONTAINED):
                    os.write(acks, f"contained {endpoint}\n".encode())
                    exchange["acknowledged"] = True

    def hold(self, entry, process):
        """Stops the group with SIGSTOP and waits for every task to report stopped before reporting custody held;
        a stopped group keeps its memory and issues no further device work."""
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGSTOP)
        running = stopped(process.pid, STOP_SECONDS)
        entry.setdefault("stopped", f"members {running} still running {STOP_SECONDS} s after SIGSTOP" if running
                         else "every member stopped before custody was reported")
        process.poll()
        if group_alive(process.pid):
            entry["custody"] = (f"unknown: members {running} of process group {process.pid} still ran after SIGSTOP; "
                                f"the group is left for an operator" if running
                                else f"held: process group {process.pid} stopped until an operator contains it")
            self.mark_custody(process.pid, entry)
            self.held.append((process.pid, entry["custody"]))

    def mark_custody(self, pgid, entry, custody=None):
        """Writes the case group's marker, which `sweep` reads before starting any role on this host.

        The marker goes down when the case starts, so a supervisor the runner kills mid-case, before `hold` could
        run, still leaves the group's identity behind; `hold` rewrites it with the custody it decided, and a group
        that ended takes its marker with it. A marker that could not be written is named in the custody line the
        operator reads, since nothing else guards the host then.
        """
        custody = custody if custody is not None else entry["custody"]
        try:
            members = {str(pid): started for pid, started in group_members(pgid).items()}
            write_custody_marker(self.args.custody, str(pgid), pgid=pgid, members=members, episode=self.args.episode,
                                 profile=self.args.profile, role=self.args.role, case=entry["id"], custody=custody)
            return True
        except OSError as error:
            if "custody" in entry:
                entry["custody"] += (f"; its marker could not be written under {self.args.custody} ({error}), "
                                     f"so take this host offline")
            else:
                self.fail(f"{entry['id']}'s custody marker could not be written under {self.args.custody}: {error}")
            return False

    def unmark_custody(self, pgid):
        """Removes the marker of a case group that ended; a held group keeps the marker `hold` rewrote."""
        with contextlib.suppress(OSError):
            (Path(self.args.custody) / f"{pgid}.json").unlink()

    def unmark_sentinel(self, sentinel):
        """Removes the pre-spawn sentinel once a group's marker, or the absence of any group, replaces it."""
        with contextlib.suppress(OSError):
            (Path(self.args.custody) / f"{sentinel}.json").unlink()

    def supervise(self, case, entry, argv, env, stdout, stderr):
        """Runs one case in its own group; returns its exit status, or None when the lane stopped it."""
        with open(stdout, "w") as out, open(stderr, "w") as err:
            # A sentinel with no group goes down first, so a supervisor killed between the spawn and the group's
            # marker still leaves the host quarantined; the group's marker replaces it.
            sentinel = f"starting-{os.getpid()}"
            try:
                write_custody_marker(self.args.custody, sentinel, pgid=None, supervisor=os.getpid(),
                                     episode=self.args.episode, profile=self.args.profile, role=self.args.role,
                                     case=case["id"], custody=f"unknown: {case['id']} was starting when its supervisor ended")
            except OSError as error:
                # Without the sentinel nothing would guard the host, so the case does not start.
                raise Stop(REJECTED, f"{case['id']}'s custody sentinel could not be written under {self.args.custody}: "
                                     f"{error}") from error
            # The sentinel write may have waited on the custody directory; a signal that arrived meanwhile, or a
            # spawn that fails, starts no case, and the sentinel then guards nothing.
            if self.terminated is not None:
                self.unmark_sentinel(sentinel)
                raise Stop(INTERRUPTED, f"interrupted by signal {self.terminated} before {case['id']} started")
            self.run.spawning = True
            try:
                process = subprocess.Popen(argv, stdout=out, stderr=err, env=env, start_new_session=True,
                                           cwd=self.run.package_root)
                self.run.child, self.case, self.case_group = process, case, process.pid
            except OSError:
                self.unmark_sentinel(sentinel)
                raise
            finally:
                self.run.spawning = False
            # The sentinel stays until the group's marker is down, so a failed marker write leaves the host quarantined.
            if self.mark_custody(process.pid, entry, f"running: process group {process.pid} started {case['id']}; "
                                                      f"its supervisor has not recorded an end"):
                self.unmark_sentinel(sentinel)
            started = time.monotonic()
            ready = self.role.get("ready")
            relayed, ready_at = {stdout: 0, stderr: 0}, None

            def note_ready():
                """Records the role's readiness line once it appears; a recording failure closes the case."""
                nonlocal ready_at
                if ready and "ready" not in entry and ready in (read(stdout) or "") + (read(stderr) or ""):
                    try:
                        entry["ready"] = self.observer.append("ready", case=case["id"])
                    except OSError as error:
                        self.fail(f"{case['id']} could not record its readiness: {error}")
                        entry["stop"] = f"observer failure: {error}"
                        return False
                    ready_at = time.monotonic()
                return True

            def note_observations():
                """Relays the observation lines completed since the last poll; a recording failure closes the case."""
                try:
                    self.relay(case, entry, relayed)
                except OSError as error:
                    self.fail(f"{case['id']} could not record an observation: {error}")
                    entry["stop"] = f"observer failure: {error}"
                    return False
                return True

            try:
                while process.poll() is None:
                    if not note_ready() or not note_observations():
                        return self.close(case, entry, process)
                    late = time.monotonic() - started > case["deadline"]
                    if late or self.terminated is not None:
                        entry["stop"] = "deadline" if late else f"lane signal {self.terminated}"
                        return self.close(case, entry, process)
                    if "kill" in self.role and ready_at is not None and \
                            time.monotonic() - ready_at >= self.role["kill"]:
                        return self.kill(case, entry, process, relayed)
                    time.sleep(POLL)
                # A case that printed its readiness line or an observation and exited within one poll still reports it.
                note_ready()
                note_observations()
                self.survivors(case, entry, process)
                return process.returncode
            finally:
                entry["seconds"] = round(time.monotonic() - started, 3)
                if process.pid not in [group for group, _ in self.held]:
                    if process.poll() is None:
                        # An exception left the case running, and a running case may hold custody.
                        entry.setdefault("stop", "lane error")
                        self.hold(entry, process)
                    else:
                        reproducer.stop_group(process)
                self.run.child, self.case = None, None

    def kill(self, case, entry, process, relayed):
        """SIGKILLs the case's group at its declared point and waits at most the case's grace for every
        member to end. A member still alive then, such as one in uninterruptible device teardown, may hold
        custody, so the group is held for an operator like an unacknowledged close. The host's kill marker goes
        down before the SIGKILL: SIGKILL ends the owner before its teardown and leaves its DMA unproven, so the
        next sweep and the FIS campaign refuse the host from the moment of the kill, whatever ends this supervisor
        or the runner afterwards, until an operator contains the host and removes the marker or a reboot ends the
        process hazard. A case whose group already ended gets no kill and no marker; a kill whose marker could not
        be written is withheld and the case closed as on a lane signal, since nothing would guard the host. Once the
        SIGKILL is sent the marker stays, whatever the leader's exit status, since any member may have taken it."""
        if process.poll() is not None and not group_alive(process.pid):
            return process.returncode
        marker = Path(self.args.custody) / f"killed-{self.args.episode}.json"
        try:
            write_custody_marker(self.args.custody, marker.stem, pgid=None, episode=self.args.episode,
                                 profile=self.args.profile, role=self.args.role, case=case["id"],
                                 custody="the killed owner's host awaits the deployment owner's containment")
        except OSError as error:
            self.fail(f"{case['id']} was not killed: its kill marker could not be written under {self.args.custody}: "
                      f"{error}")
            entry["stop"] = "kill withheld: its marker could not be written"
            return self.close(case, entry, process)
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            # The group ended between the check and the signal, so nothing took the SIGKILL and the marker goes.
            with contextlib.suppress(OSError):
                marker.unlink()
            process.poll()
            return process.returncode
        try:
            entry["killed"] = self.observer.append("killed", case=case["id"])
        except OSError as error:
            # The kill was sent, so the receipt records it for the sweep even without the observer's record.
            entry["killed"] = {"unrecorded": str(error)}
            self.fail(f"{case['id']} could not record its kill: {error}")
        ends = time.monotonic() + case["grace"]
        while (process.poll() is None or group_alive(process.pid)) and time.monotonic() < ends:
            time.sleep(POLL)
        with contextlib.suppress(OSError):
            self.relay(case, entry, relayed)
        if process.poll() is None or group_alive(process.pid):
            self.hold(entry, process)
        return process.returncode

    def relay(self, case, entry, relayed):
        """Appends the `observe:` lines each stream completed past the byte offset `relayed` keeps for it as
        observed events. Each poll reads only the bytes past that offset and decodes whole lines with
        replacement, so a line split across writes waits for its newline and no byte stops the case."""
        for stream, offset in relayed.items():
            try:
                with stream.open("rb") as source:
                    source.seek(offset)
                    data = source.read()
            except OSError:
                continue
            complete = data[:data.rfind(b"\n") + 1]
            relayed[stream] = offset + len(complete)
            for line in complete.decode(errors="replace").splitlines():
                if not line.startswith("observe: "):
                    continue
                name, _, detail = line.removeprefix("observe: ").partition(" ")
                event = self.observer.append("observed", frontier=True, name=name, detail=detail, case=case["id"])
                if event is not None:
                    entry.setdefault("observed", []).append(event)

    def close(self, case, entry, process):
        """A case that declares `closes_on_sigterm` and has reported its readiness gets SIGTERM and
        its grace, and one that exits 0 within it closed itself. The readiness line is printed by the
        installed close handler, so before it SIGTERM's default action would end the case and release
        its memory; that case, like one that never closes on SIGTERM, has its group stopped before
        the controller is asked. Only an acknowledged containment lets the lane kill the stopped
        group; otherwise it stays stopped with its memory held."""
        if case["closes_on_sigterm"] and "ready" in entry:
            entry["close_requested"] = time.monotonic()
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGTERM)
            try:
                process.wait(timeout=case["grace"])
                entry["grace"] = "exited within grace"
            except subprocess.TimeoutExpired:
                entry["grace"] = "alive after grace"
            if process.returncode == 0:
                self.survivors(case, entry, process)
                return None
        else:
            entry["grace"] = ("not requested: the case does not close on SIGTERM" if not case["closes_on_sigterm"]
                              else "not requested: the case had not reported the readiness its close handler prints")
        self.contain_or_hold(case, entry, process)
        return None

    def survivors(self, case, entry, process):
        """A descendant left in the group after the leader exited inherited its device descriptors, so it
        holds custody as the case did and takes the same containment path."""
        if group_alive(process.pid):
            entry["descendants"] = "left running after the case exited"
            self.contain_or_hold(case, entry, process)

    def contain_or_hold(self, case, entry, process):
        """Stops the group, asks the controller to contain it once every member reports stopped, and kills it
        only on an acknowledgement. A member still running past the stop window leaves the group held unasked."""
        with contextlib.suppress(ProcessLookupError):
            os.killpg(process.pid, signal.SIGSTOP)
        running = stopped(process.pid, STOP_SECONDS)
        if running:
            entry["stopped"] = f"members {running} still running {STOP_SECONDS} s after SIGSTOP"
            entry["containment"] = {"requested": None, "acknowledged": False,
                                    "answer": "not asked: the group had not stopped"}
            self.hold(entry, process)
            return
        entry["stopped"] = "every member stopped before the controller was asked"
        entry["containment"] = self.contain(case, process)
        if entry["containment"]["acknowledged"]:
            # SIGKILL ends stopped processes; stop_group's SIGTERM stays pending until they resume.
            with contextlib.suppress(ProcessLookupError):
                os.killpg(process.pid, signal.SIGKILL)
            reproducer.stop_group(process)
        else:
            self.hold(entry, process)

    def wait_after(self, case):
        """Waits for the `after` role's readiness for as long as the roles in the chain before this one may take,
        because every role of a profile starts at once and each predecessor's own wait precedes its startup.
        The wait ends early once the `after` role's `run` recorded its end, since a role that exited before its
        readiness line will never print it, and the end of each role in a failed chain ends the next wait. One
        snapshot of the log decides both, so a readiness published just before the end still acknowledges."""
        after = self.role.get("after")
        if after is None:
            return None
        deadline = time.monotonic() + self.wait
        while time.monotonic() < deadline and self.terminated is None:
            events = self.observer.role_events(after)
            event = next((event for event in events if event["kind"] == "ready"), None)
            if event is not None:
                return self.observer.append("ack", acknowledges=event["ordinal"], case=case["id"])
            if any(event["kind"] == "end" for event in events):
                return None
            time.sleep(POLL)
        return None

    def run_case(self, executable, case, rows):
        entry = {"id": case["id"], "expected": case["expected"], "restoration": case["restoration"]}
        self.section["cases"].append(entry)
        entry["registry_cause"] = rows[case["id"]]["cause"]
        listed = {}
        stem = artifact_name(case["id"])
        for flag in ([], ["--ignored"]):
            name = "ignored" if flag else "listed"
            out = self.run.dir / f"{stem}.{name}"
            status = reproducer.supervise(self.run, [str(executable), "--list", "--exact", *flag, case["id"]],
                                          out, self.run.dir / f"{stem}.{name}.stderr", cwd=self.run.package_root)
            lines = (read(out) or "").splitlines()
            listed[name] = sum(line == f"{case['id']}: test" for line in lines) if status == 0 else -1
        entry.update(listed)
        if listed["listed"] != case["expected"] or listed["ignored"] != case["expected"]:
            return self.fail(f"{case['id']} listed {listed['listed']} and ignored {listed['ignored']}, "
                             f"declared {case['expected']}")
        missing = [name for name in case["inputs"] if name not in self.environment and name not in CHANNEL]
        if missing:
            return self.fail(f"{case['id']} lacks inputs {missing}")
        evidence = self.profile.get("evidence")
        if evidence and not Path(self.environment.get(evidence, "/nonexistent")).is_file():
            entry["unrun"] = f"no abrupt-death evidence named by {evidence}"
            return self.fail(f"{case['id']} unrun: {entry['unrun']}")
        if evidence:
            entry["evidence"] = {"path": self.environment[evidence], "sha256": sha256(Path(self.environment[evidence]))}
        channel = CHANNEL[0] in case["inputs"]
        if channel and not self.args.controller:
            entry["unrun"] = "no containment controller to fence the endpoint and contain the device and host"
            return self.fail(f"{case['id']} unrun: {entry['unrun']}")
        # The case runs from the package root, so only an absolute path names one file to both the lane and the case.
        for name in PATH_INPUTS:
            if name in case["inputs"] and not os.path.isabs(self.environment[name]):
                return self.fail(f"{case['id']} names a relative {name} {self.environment[name]!r}; the lane takes an absolute path")
        # The declared-input and role-env allowlist isolates the case from ambient KESTRIKE_* controls; the
        # channel's two inputs are the FIFOs the lane creates below.
        declared = set(case["inputs"]) | set(self.role.get("env", {}))
        inputs = {name: self.environment[name] for name in sorted(declared) if name in self.environment}
        entry["inputs"] = inputs
        entry["mappings"] = mappings_facts(inputs)
        # The judge requires the identity of the mappings file a case opens; a case that cannot earn credit runs no
        # device work.
        if any(name in case["inputs"] for name in PATH_INPUTS) and not mappings_identity(entry):
            return self.fail(f"{case['id']} names no readable mappings file of format {MAPPINGS_FORMAT} at "
                             f"{mappings_path(inputs)!r}")
        if any(name in case["inputs"] for name in PATH_INPUTS) and (
                gap := function_gap(self.args.platform, self.section["platform"], entry)):
            return self.fail(f"{case['id']} {gap}")
        differing = declared_inputs_differ(self.role, inputs)
        if differing:
            return self.fail(f"{case['id']} inputs {differing} differ from the role's declared {self.role['env']}")
        if self.role.get("after"):
            entry["ack"] = self.wait_after(case)
            if entry["ack"] is None:
                return self.fail(f"{case['id']} started without the {self.role['after']} role's readiness")
        # The runner's end-of-job cleanup kills every process carrying the job's RUNNER_TRACKING_ID.
        env = {name: value for name, value in self.environment.items()
               if name != "RUNNER_TRACKING_ID" and not name.startswith("KESTRIKE_")}
        env.update(inputs, KESTRIKE_EPISODE=self.args.episode)
        argv = [str(executable), *case_arguments(case)]
        entry["command"] = argv
        stdout, stderr = self.run.dir / f"{stem}.stdout", self.run.dir / f"{stem}.stderr"
        if self.terminated is not None:
            return self.fail(f"interrupted by signal {self.terminated} before {case['id']} started")
        with contextlib.ExitStack() as stack:
            if channel:
                ends = []
                for name in CHANNEL:
                    path = self.run.dir / f"{stem}.{name.rsplit('_', 1)[1].lower()}"
                    os.mkfifo(path, 0o600)
                    # A FIFO is no evidence, and the artifact upload refuses one; it goes once the relay has ended.
                    stack.callback(os.unlink, path)
                    # Read-write opens never wait for the case to open its end.
                    ends.append(os.open(path, os.O_RDWR))
                    stack.callback(os.close, ends[-1])
                    env[name] = inputs[name] = str(path)
                entry["channel"], done = [], threading.Event()
                relay = threading.Thread(target=self.bridge, daemon=True,
                                         args=(case, inputs.get("KESTRIKE_MAPPINGS"), *ends, (stdout, stderr),
                                               entry["channel"], done))
                relay.start()
                stack.callback(relay.join)
                stack.callback(done.set)
            entry["start"] = self.observer.append("start", case=case["id"])
            # The start append may have waited on the observer lock; a signal that arrived meanwhile starts no case.
            if self.terminated is not None:
                return self.fail(f"interrupted by signal {self.terminated} before {case['id']} started")
            status = self.supervise(case, entry, argv, env, stdout, stderr)
            # The file's digest once the case ended, None when it is unreadable then. It stays out of
            # `entry["mappings"]`, whose facts a role's cases must share.
            entry["mappings_after"] = (mappings_facts(inputs) or {}).get("sha256")
            if all(pgid != self.case_group for pgid, _ in self.held):
                self.unmark_custody(self.case_group)
        entry["exit"] = status
        entry["end"] = self.observer.append("exit", case=case["id"], status=status)
        output = (read(stdout) or "") + "\n" + (read(stderr) or "")
        summary = [line for line in output.splitlines() if line.startswith("test result:")]
        entry["summary"] = summary
        try:
            parsed = list(selector.parse_summaries("\n".join(summary)).values())
        except selector.Refusal:
            parsed = []
        counts = parsed[0] if len(parsed) == 1 and parsed[0]["lines"] == 1 else None
        entry["executed"] = counts and counts["passed"] + counts["failed"]
        entry["witness_counts"] = {witness: output.count(witness) for witness in case["witnesses"]}
        entry["missing_witnesses"] = [witness for witness in case["witnesses"] if not entry["witness_counts"][witness]]
        closing = self.role.get("closing")
        entry["closed"] = closing if closing and closing in output else None
        if "kill" in self.role:
            if "custody" in entry:
                return self.fail(f"{case['id']}'s process group outlived its scheduled SIGKILL")
            if "killed" not in entry or status != -signal.SIGKILL:
                return self.fail(f"{case['id']} was not killed at its declared point; exit {status}")
            if entry["missing_witnesses"]:
                return self.fail(f"{case['id']} lacks witnesses {entry['missing_witnesses']}")
            return None
        if status is None:
            return self.fail(f"{case['id']} stopped by {entry['stop']}; its output is cut off")
        if entry["closed"]:
            # An owner's closing line invalidates the run even when its test summary passes.
            return self.fail(f"{case['id']} closed on a SIGTERM the lane did not send; its run was cut short")
        if status != 0 or not counts or counts["failed"] or counts["passed"] != case["expected"]:
            return self.fail(f"{case['id']} exited {status} with {summary}")
        if "descendants" in entry:
            return self.fail(f"{case['id']} left descendants running")
        if entry["missing_witnesses"]:
            return self.fail(f"{case['id']} lacks witnesses {entry['missing_witnesses']}")
        if channel and [(e["acknowledged"], bool(e["census"])) for e in entry["channel"]] != [(True, True)]:
            return self.fail(f"{case['id']} made {len(entry['channel'])} containment exchanges, "
                             "not one acknowledged with a census")
        return None

    def execute(self, platforms, rows):
        self.run.open()
        # The receipt records the inputs each case received; the build record keeps the build-affecting names.
        self.run.record["environment"] = {name: value for name, value in self.run.record["environment"].items()
                                          if not name.startswith("KESTRIKE_")}
        self.run.save()
        row = platforms[self.args.platform]
        self.section.update(revision=self.run.record["revision"],
                            build_environment={name: value for name, value in self.run.record["environment"].items()
                                               if name in BUILD_ENVIRONMENT},
                            host=host_facts(row), dirty=self.run.record["dirty"])
        self.section["platform"] = {"row": self.args.platform, **row}
        # The platform check gates the cargo and rustc probes, so a receipt's toolchain and dependencies describe the
        # build of a row the role runs on.
        if defect := platform_defect(self.args.platform, row, self.profile, self.section["host"]):
            self.fail(defect)
            return UNCREDITED
        self.run.resolve()
        self.section.update(toolchain=self.run.record["toolchain"], dependencies=self.run.record["dependencies"])
        if self.run.record["dirty"]:
            self.fail("the role ran from a modified tree")
            return UNCREDITED
        artifacts = os.path.relpath(Path(self.args.artifacts).resolve(), Path.cwd())
        self.section.update(untracked=self.run.record["untracked"], artifacts=artifacts)
        stray = stray_untracked(self.section["untracked"], artifacts)
        if stray:
            self.fail(f"the tree holds untracked files {stray} outside the artifacts")
            return UNCREDITED
        executable = reproducer.build(self.run)
        self.section["executable"] = self.run.record["executable"]
        for case in self.role["cases"]:
            if self.terminated is not None:
                self.fail(f"interrupted by signal {self.terminated} before {case['id']}")
                break
            self.run_case(executable, case, rows)
            self.save()
            if self.section["first_failure"] is not None:
                # The role stays uncredited after its first failure, so it stops to limit privileged work.
                if self.held:
                    self.fail(f"custody held after {case['id']}; the role runs no further case")
                break
        self.section["credited"] = self.section["first_failure"] is None and self.terminated is None
        return CREDITED if self.section["credited"] else UNCREDITED


def platform_refusal(name, named_by="--platform or KESTRIKE_HARDWARE_PLATFORM"):
    named = "no platform row named" if name is None else f"no platform row {name!r}"
    return f"{named}; name the host's row with {named_by}"


def read_manifest(path):
    """The checked manifest's platforms and profiles with the SHA-256 of the bytes they were parsed from."""
    text = Path(path).read_bytes()
    try:
        return (*check_manifest(json.loads(text)), hashlib.sha256(text).hexdigest())
    except (*FAULTS, RecursionError, OverflowError) as error:
        raise Stop(REJECTED, f"malformed hardware manifest: {type(error).__name__}: {error}") from error


def read_judged_manifest(path):
    """`read_manifest` for a judge: a manifest whose cases differ from the registry's hardware-privileged rows
    raises Stop before any receipt is judged against it."""
    platforms, profiles, manifest_sha256 = read_manifest(path)
    registry_rows(profiles)
    return platforms, profiles, manifest_sha256


def command_run(args):
    try:
        platforms, profiles, manifest_sha256 = read_manifest(args.manifest)
        if args.profile not in profiles or args.role not in profiles[args.profile]["roles"]:
            raise Stop(REJECTED, f"no role {args.role!r} in profile {args.profile!r}")
        if args.platform not in platforms:
            raise Stop(REJECTED, platform_refusal(args.platform))
        if args.controller is not None:
            try:
                command = shlex.split(args.controller)
            except ValueError as error:
                raise Stop(REJECTED, f"--controller is not a shell command: {error}") from error
            if not command:
                raise Stop(REJECTED, "--controller names no command")
        lane = Lane(args, profiles[args.profile], manifest_sha256)
    except (Stop, *FAULTS):
        # On input rejection, command_run attempts to record the role's end so dependent roles stop waiting for
        # readiness.
        with contextlib.suppress(OSError, ValueError):
            Observer(args.observer, args.episode, args.profile, args.role).append("end", status=REJECTED)
        raise
    signal.signal(signal.SIGTERM, lane.on_signal)
    signal.signal(signal.SIGINT, lane.on_signal)
    try:
        code = lane.execute(platforms, registry_rows(profiles))
    except Stop as stop:
        lane.fail(str(stop))
        code = INTERRUPTED if stop.code == reproducer.INTERRUPTED else REJECTED
    except FAULTS as error:
        lane.fail(f"{type(error).__name__}: {error}")
        code = REJECTED
    if lane.terminated is not None:
        lane.fail(f"interrupted by signal {lane.terminated}")
        code = INTERRUPTED
    # The role-level end event releases every role waiting on this one's readiness.
    try:
        lane.observer.append("end", status=code)
    except (OSError, ValueError) as error:
        lane.fail(f"the role could not record its end: {error}")
        code = REJECTED if code == CREDITED else code
    # The end append may have waited on the observer lock; a signal that arrived meanwhile interrupted the role.
    if lane.terminated is not None and code == CREDITED:
        lane.fail(f"interrupted by signal {lane.terminated}")
        code = INTERRUPTED
    # The flag follows the final status, so a failure after the cases ran reads as uncredited.
    lane.section["credited"] = code == CREDITED
    try:
        lane.save()
    except OSError as error:
        print(f"rejected input: receipt.json could not be written ({error})")
        code = REJECTED
    else:
        verdict = (f"credited on platform row {args.platform}" if code == CREDITED
                   else f"not credited: {lane.section['first_failure']}")
        print(f"{args.profile}/{args.role}: {verdict}")
        if lane.run.dir is not None:
            print(f"receipt: {lane.run.dir / 'receipt.json'}", file=sys.stderr)
    for _, custody in lane.held:
        print(f"custody {custody}; contain it before releasing its memory")
    return HELD if lane.held else code


def declared_inputs_differ(role, inputs):
    """The role's declared `env` names whose recorded input is another value or absent, with what was recorded."""
    return {name: inputs.get(name) for name, value in role.get("env", {}).items() if inputs.get(name) != value}


def passing_summary(entry, case):
    """Whether the receipt's recorded libtest summary is exactly one passing line counting the expected tests."""
    summary = entry.get("summary")
    if not isinstance(summary, list) or len(summary) != 1:
        return False
    try:
        parsed = list(selector.parse_summaries(summary[0]).values())
    except selector.Refusal:
        return False
    return (len(parsed) == 1 and parsed[0]["lines"] == 1 and parsed[0]["failed"] == 0
            and parsed[0]["passed"] == case["expected"])


def recorded_row(section):
    """The platform row name one role's receipt records, or None when it records no string row."""
    recorded = section.get("platform")
    name = recorded.get("row") if isinstance(recorded, dict) else None
    return name if isinstance(name, str) else None


def recorded_defects(platforms, profile, role, section):
    """The credit conditions `run` checked, recomputed from what one role's receipt recorded.

    The receipt's `credited` flag and `missing_witnesses` list are its producer's summaries; a
    profile credits only when the platform row the receipt's `platform.row` selects in the manifest
    and the recorded identity, inputs,
    readiness, exit, counts, witness counts and custody support it. Each witness the current
    manifest declares for a case needs a positive count among the output observations the case
    recorded, so a witness the manifest adds after the run leaves the receipt uncredited.
    """
    row_name = recorded_row(section)
    if row_name not in platforms:
        yield ("the receipt names no platform row" if row_name is None
               else f"the receipt names no platform row of the manifest: {row_name!r}")
        return
    row = platforms[row_name]
    host = section.get("host")
    if defect := platform_defect(row_name, row, profile, host if isinstance(host, dict) else {}):
        yield defect
    if not section.get("episode") or not section.get("revision"):
        yield "the receipt names no episode or revision"
    digest = (section.get("executable") or {}).get("sha256")
    if not (isinstance(digest, str) and re.fullmatch(r"[0-9a-f]{64}", digest)):
        yield "the receipt names no executable digest"
    toolchain = section.get("toolchain")
    if not (isinstance(toolchain, dict)
            and all(isinstance(toolchain.get(tool), str) and toolchain[tool] for tool in ("rustc", "cargo"))):
        yield "the receipt names no toolchain"
    dependencies = section.get("dependencies")
    if not (isinstance(dependencies, list) and dependencies and all(isinstance(entry, str) for entry in dependencies)):
        yield "the receipt names no resolved dependencies"
    environment = section.get("build_environment")
    if not (isinstance(environment, dict)
            and all(isinstance(name, str) and isinstance(value, str) for name, value in environment.items())):
        yield "the receipt records no build environment"
    if not (ordinal(section.get("attempts_allowed")) and section["attempts_allowed"] == 1
            and ordinal(section.get("retries")) and section["retries"] == 0):
        yield "the receipt allows a retry: every case runs exactly once"
    entries = section.get("cases", [])
    # One role runs its cases from one environment, so a repeated input carries one value across them.
    values = {}
    for entry in entries:
        for name, value in (entry.get("inputs") or {}).items() if isinstance(entry, dict) else ():
            values.setdefault(name, set()).add(json.dumps(value))
        if isinstance(entry, dict) and isinstance(entry.get("mappings"), dict):
            values.setdefault("mappings", set()).add(json.dumps(entry["mappings"], sort_keys=True))
    varying = sorted(name for name, seen in values.items() if len(seen) > 1)
    if varying:
        yield f"the role's cases record different values for {varying}"
    for index, case in enumerate(role["cases"]):
        entry = entries[index] if index < len(entries) else {}
        command = entry.get("command")
        if not (isinstance(command, list) and len(command) == 1 + len(case_arguments(case))
                and command[0] == (section.get("executable") or {}).get("path") and command[1:] == case_arguments(case)):
            yield f"{case['id']} records a command other than the exact-ID run of the recorded executable: {command!r}"
        inputs = entry.get("inputs")
        if not (isinstance(inputs, dict) and all(isinstance(name, str) and isinstance(value, str)
                                                 for name, value in inputs.items())):
            yield f"{case['id']} records inputs that are not an environment of strings: {inputs!r}"
        missing = [name for name in case["inputs"] if name not in (entry.get("inputs") or {})]
        if missing:
            yield f"{case['id']} lacks inputs {missing}"
        differing = declared_inputs_differ(role, entry.get("inputs") or {})
        if differing:
            yield f"{case['id']} inputs {differing} differ from the role's declared {role['env']}"
        undeclared = sorted(set(entry.get("inputs") or {}) - set(case["inputs"]) - set(role.get("env", {})))
        if undeclared:
            yield f"{case['id']} ran with inputs {undeclared} the manifest does not declare for it"
        if any(name in case["inputs"] for name in PATH_INPUTS) and not mappings_identity(entry):
            yield f"{case['id']} records no mappings identity for the mappings file its inputs name"
        if any(name in case["inputs"] for name in PATH_INPUTS) and (gap := function_gap(row_name, row, entry)):
            yield f"{case['id']} {gap}"
        if CHANNEL[0] in case["inputs"] and not acknowledged_exchange(entry):
            yield f"{case['id']} records no single acknowledged containment exchange naming its endpoint with a census"
        if role.get("after") and not entry.get("ack"):
            yield f"{case['id']} started without the {role['after']} role's readiness"
        if "stop" in entry:
            yield f"{case['id']} stopped by {entry['stop']}; its output is cut off"
        # A credited case ran within its deadline; the poll interval and the readiness record's lock bound are
        # the most the supervisor adds after the case exited.
        # A killed case adds its grace, the wait for the group to end after SIGKILL.
        seconds, limit = entry.get("seconds"), case["deadline"] + POLL + OBSERVER_SECONDS + (case["grace"] if "kill" in role else 0)
        if isinstance(seconds, bool) or not isinstance(seconds, (int, float)) or not 0 <= seconds <= limit:
            yield f"{case['id']} records no duration within its {case['deadline']} s deadline: {seconds!r}"
        if entry.get("closed"):
            yield f"{case['id']} closed on a SIGTERM; its run was cut short"
        if "kill" in role:
            # A killed role prints no summary; its recorded kill event and SIGKILL exit stand for the run.
            killed = entry.get("killed")
            if not (isinstance(killed, dict) and killed.get("kind") == "killed" and ordinal(killed.get("ordinal"))
                    and entry.get("exit") == -signal.SIGKILL):
                yield f"{case['id']} was not killed at its declared point; exit {entry.get('exit')}"
        elif entry.get("exit") != 0 or entry.get("executed") != case["expected"] or not passing_summary(entry, case):
            yield f"{case['id']} exited {entry.get('exit')} with {entry.get('summary')}"
        if "descendants" in entry:
            yield f"{case['id']} left descendants running"
        if "containment" in entry or "custody" in entry:
            yield f"{case['id']} asked for containment or holds custody"
        counts = entry.get("witness_counts")
        if not isinstance(counts, dict):
            yield f"{case['id']} records no witness_counts"
        elif lacking := [witness for witness in case["witnesses"]
                         if not (ordinal(counts.get(witness)) and counts[witness] > 0)]:
            yield f"{case['id']} lacks witnesses {lacking}"
        if entry.get("missing_witnesses") != []:
            yield f"{case['id']} lacks witnesses {entry.get('missing_witnesses')}"


def judge_profile(platforms, profile_name, profile, receipts, manifest_sha256, revision=None):
    """Returns (credited, reasons) for a profile from its roles' receipts.

    `platforms` and `profile` are the current manifest's, and `manifest_sha256` is the digest of
    the bytes they were parsed from. Credit follows these current requirements: each receipt must
    record that digest as the manifest its run used, and each case's evidence must satisfy the
    current case declaration.
    """
    reasons, by_role = [], {}
    for receipt in receipts:
        section = receipt.get("hardware", {})
        if receipt.get("envelope") != ENVELOPE or section.get("profile") != profile_name:
            reasons.append(f"a receipt outside profile {profile_name}")
            continue
        by_role.setdefault(section.get("role"), []).append(section)
    reasons += [f"role {role} is not declared" for role in by_role if role not in profile["roles"]]
    for role, declared in profile["roles"].items():
        found = by_role.get(role, [])
        if len(found) != 1:
            reasons.append(f"role {role} has {len(found)} receipts")
            continue
        section = found[0]
        if "manifest_sha256" not in section:
            reasons.append(f"role {role} records no manifest_sha256")
        elif section["manifest_sha256"] != manifest_sha256:
            reasons.append(f"role {role} ran under manifest_sha256 {section['manifest_sha256']!r}, "
                           f"not the current manifest's {manifest_sha256}")
        expected = [(case["id"], case["expected"]) for case in declared["cases"]]
        # A role the lane kills prints no summary; its kill stands for the run.
        killed = "kill" in declared and all(case.get("killed") and case.get("exit") == -signal.SIGKILL
                                            for case in section.get("cases", []))
        ran = [(case.get("id"), case.get("listed") if killed else case.get("executed"))
               for case in section.get("cases", [])]
        counted = all(case.get("listed") == case.get("ignored") == (case.get("listed") if killed else case.get("executed"))
                      for case in section.get("cases", []))
        if section.get("credited") is not True or section.get("first_failure") is not None:
            reasons.append(f"role {role} uncredited: {section.get('first_failure')}")
        elif ran != expected or not counted:
            reasons.append(f"role {role} ran {ran}, declared {expected}")
        elif section.get("dirty") is not False:
            reasons.append(f"role {role} ran from a modified tree")
        elif stray_untracked(section.get("untracked"), section.get("artifacts")):
            reasons.append(f"role {role} ran with untracked files "
                           f"{stray_untracked(section.get('untracked'), section.get('artifacts'))} outside the artifacts")
        else:
            reasons += [f"role {role} uncredited by its evidence: {defect}"
                        for defect in recorded_defects(platforms, profile, declared, section)][:1]
    sections = [found[0] for found in by_role.values() if len(found) == 1]
    reasons += judge_order(profile, sections)
    if profile.get("evidence"):
        hashes = {case["evidence"].get("sha256") if isinstance(case.get("evidence"), dict) else None
                  for section in sections for case in section.get("cases", [])}
        if None in hashes or len(hashes) != 1:
            reasons.append(f"the roles do not share one {profile['evidence']} evidence file")
    if len({recorded_row(section) for section in sections}) > 1:
        reasons.append("the roles ran under different platform rows")
    for field in ("episode", "revision"):
        if len({section.get(field) for section in sections}) > 1:
            reasons.append(f"the roles ran under different {field}s")
    revisions = {section.get("revision") for section in sections}
    if revision is not None and sections and revisions != {revision}:
        reasons.append(f"the receipts name revision {sorted(map(str, revisions))}, not {revision}")
    if len({json.dumps(section.get("toolchain"), sort_keys=True) for section in sections}) > 1:
        reasons.append("the roles ran under different toolchains")
    if len({json.dumps(section.get("dependencies")) for section in sections}) > 1:
        reasons.append("the roles built different dependencies")
    if len({json.dumps(section.get("build_environment"), sort_keys=True) for section in sections}) > 1:
        reasons.append("the roles built under different build environments")
    reasons += unmatched_acknowledgements(profile_name, profile, by_role)
    return not reasons, reasons


def judge_launch(manifest_path, receipt, expected):
    """The reasons one role's receipt earns no credit as the run its caller launched, empty when it credits.

    `expected` holds the `profile`, `role`, `episode` and `revision` the caller launched the role under and the
    `mappings` facts of the file it supplied. Those values come from the caller, never from the receipt, which is
    only evidence of what ran: a component the receipt records otherwise, or omits, is a reason naming it. The
    evidence is then judged as `judge` does, against the manifest at `manifest_path`.
    """
    platforms, profiles, manifest_sha256 = read_judged_manifest(manifest_path)
    section = receipt.get("hardware") if isinstance(receipt, dict) else None
    section = section if isinstance(section, dict) else {}
    reasons = [f"the receipt names {name} {section.get(name)!r}, not the launched {expected[name]!r}"
               for name in ("profile", "role", "episode", "revision") if section.get(name) != expected[name]]
    recorded = [entry.get("mappings") if isinstance(entry, dict) else None for entry in section.get("cases") or []]
    if not recorded or any(facts != expected["mappings"] for facts in recorded):
        reasons.append(f"the receipt records mappings {recorded!r}, not the launched {expected['mappings']!r}")
    if expected["profile"] not in profiles:
        return [*reasons, f"the manifest declares no profile {expected['profile']!r}"]
    return reasons + judge_profile(platforms, expected["profile"], profiles[expected["profile"]], [receipt],
                                   manifest_sha256)[1]


def judge_order(profile, sections):
    """Reasons the receipts' observed events fail observer order or one of the profile's conjunction chains."""
    reasons, events, inputs = [], {}, {}
    for section in sections:
        for case in section.get("cases", []):
            inputs.setdefault(section.get("role"), {}).update(case.get("inputs") or {})
            for event in [*case.get("observed", []), *(case[kind] for kind in ("killed", "ready") if case.get(kind))]:
                if not isinstance(event, dict) or not isinstance(event.get("ordinal"), int):
                    reasons.append(f"role {section.get('role')} orders an event by wall time only")
                elif (event.get("role"), event.get("profile"), event.get("episode")) != \
                        (section.get("role"), section.get("profile"), section.get("episode")):
                    reasons.append(f"role {section.get('role')} carries a misrouted event")
                elif events.setdefault(event["ordinal"], event) != event:
                    reasons.append(f"two events claim observer ordinal {event['ordinal']}")
    for event in events.values():
        if "after" not in event and event["kind"] != "observed":
            continue
        after = event.get("after") if isinstance(event.get("after"), dict) else {"": event["ordinal"]}
        earlier = [other for other in events.values() if other["ordinal"] < event["ordinal"]
                   and other["role"] != event["role"]]
        if any(not isinstance(ordinal, int) or ordinal >= event["ordinal"]
               or (ordinal in events and events[ordinal]["role"] != role) for role, ordinal in after.items()) or \
                any(after.get(other["role"], 0) < other["ordinal"] for other in earlier):
            reasons.append(f"event {event['ordinal']} names a frontier its observer order contradicts")
    ordered = sorted(events.values(), key=lambda event: event["ordinal"])
    for chain in profile.get("conjunction", []):
        position = 0
        for entry in chain:
            role, _, wanted = entry.partition(":")
            name, _, detail = wanted.partition(" ")
            try:
                detail = detail.format(**inputs.get(role, {}))
            except (KeyError, IndexError, ValueError) as missing:
                reasons.append(f"the conjunction entry {entry} names input {missing} role {role} did not record")
                break
            found = next((event["ordinal"] for event in ordered if event["ordinal"] > position and event["role"] == role
                          and (event.get("name") or event["kind"]) == name and detail in event.get("detail", "")), None)
            if found is None:
                reasons.append(f"the episode lacks {entry} after the conjunction's earlier entries")
                break
            position = found
    return reasons


def case_arguments(case):
    """The arguments after the executable that run exactly one declared case, as `run` passes them and `judge` expects."""
    return ["--exact", case["id"], "--test-threads=1", "--ignored", "--nocapture"]


def mappings_identity(entry):
    """Whether the case's recorded `mappings` names the file its input points at, with its digest and the supported format.

    `run` records them from one read before it spawns the case, so the receipt identifies the mappings file as it
    was then, and records the file's digest again as `mappings_after` when the case ends. The case takes the
    state directory's bind lock before its own read and holds it until it exits.
    """
    facts, inputs = entry.get("mappings"), entry.get("inputs") or {}
    return (isinstance(facts, dict) and facts.get("path") == mappings_path(inputs if isinstance(inputs, dict) else {})
            and isinstance(facts["path"], str) and os.path.isabs(facts["path"])
            and isinstance(facts.get("sha256"), str) and re.fullmatch(r"[0-9a-f]{64}", facts["sha256"]) is not None
            and facts.get("format") == MAPPINGS_FORMAT)


def acknowledged_exchange(entry):
    """Whether the case's channel transcript is one acknowledged request for its mappings endpoint with a census."""
    exchanges, inputs = entry.get("channel"), entry.get("inputs") or {}
    return (isinstance(exchanges, list) and len(exchanges) == 1 and isinstance(exchanges[0], dict)
            and exchanges[0].get("request") == f"contain {inputs.get('KESTRIKE_MAPPINGS')}"
            and exchanges[0].get("acknowledged") is True
            and isinstance(exchanges[0].get("census"), list) and exchanges[0]["census"] != [])


def ordinal(value):
    """Whether `value` is a JSON integer, such as an observer ordinal or a witness count, excluding the booleans
    Python counts as ints."""
    return isinstance(value, int) and not isinstance(value, bool)


def unmatched_acknowledgements(profile_name, profile, by_role):
    """One reason per dependent role whose acknowledgement proves no startup order after its `after` role.

    A recorded readiness event carries the profile, episode, role, case and ordinal of the observer log, and counts
    only when its predecessor case recorded it after that case's start. The dependent case's `ack` must name that
    ordinal under the same profile, episode, its own role and its own case, and the log's order must read
    readiness, then acknowledgement, then the case's own start.
    """
    reasons = []
    for role, declared in profile["roles"].items():
        after = declared.get("after")
        if after is None or len(by_role.get(role, [])) != 1 or len(by_role.get(after, [])) != 1:
            continue
        section, predecessor = by_role[role][0], by_role[after][0]
        # A readiness event counts only inside the predecessor case that recorded it, after that case's own start.
        ready = {event["ordinal"] for entry in predecessor.get("cases", []) if isinstance(event := entry.get("ready"), dict)
                 and event.get("kind") == "ready" and event.get("profile") == profile_name
                 and event.get("role") == after and event.get("episode") == section.get("episode")
                 and event.get("case") == entry.get("id") and isinstance(start := entry.get("start"), dict)
                 and start.get("kind") == "start" and start.get("profile") == profile_name and start.get("role") == after
                 and start.get("case") == entry.get("id") and start.get("episode") == section.get("episode")
                 and ordinal(start.get("ordinal")) and ordinal(event.get("ordinal"))
                 and start["ordinal"] < event["ordinal"]}
        for entry in section.get("cases", []):
            ack, start = entry.get("ack"), entry.get("start")
            if not (isinstance(ack, dict) and isinstance(start, dict) and ack.get("kind") == "ack"
                    and start.get("kind") == "start" and ack.get("profile") == start.get("profile") == profile_name
                    and ack.get("role") == start.get("role") == role and ack.get("case") == start.get("case") == entry.get("id")
                    and ack.get("episode") == start.get("episode") == section.get("episode")
                    and ack.get("acknowledges") in ready
                    and ordinal(ack.get("ordinal")) and ordinal(start.get("ordinal")) and ordinal(ack.get("acknowledges"))
                    and ack["acknowledges"] < ack["ordinal"] < start["ordinal"]):
                reasons.append(f"role {role} acknowledges no readiness the {after} role recorded before its start")
                break
    return reasons


def command_judge(args):
    platforms, profiles, manifest_sha256 = read_judged_manifest(args.manifest)
    receipts = [json.loads(Path(path).read_text()) for path in args.receipts]
    credited, reasons = judge_profile(platforms, args.profile, profiles[args.profile], receipts, manifest_sha256,
                                      args.revision or git_revision())
    if credited:
        print(f"{args.profile}: credited on platform row {recorded_row(receipts[0]['hardware'])}")
    else:
        print(f"{args.profile}: not credited: {'; '.join(reasons)}")
    return CREDITED if credited else UNCREDITED


def role_seconds(profile, role_name):
    """The longest the case phase of `run` may take over a role: per case the readiness wait `wait_after` allows,
    the deadline, the grace, the stop proof and its repeat in `hold`, the controller window and the observer
    operations' lock waits, plus the role's end event. The build and the listings are budgeted by the caller."""
    wait = readiness_wait(profile, role_name)
    return OBSERVER_SECONDS + sum(wait + case["deadline"] + case["grace"] + 2 * STOP_SECONDS + CONTROLLER_SECONDS
                                  + OBSERVER_OPERATIONS * OBSERVER_SECONDS
                                  for case in profile["roles"][role_name]["cases"])


BOOT_ID = "/proc/sys/kernel/random/boot_id"
# The kernel prints a boot identity as a lower-case UUID.
BOOT_IDENTITY = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")


def boot_id():
    """The kernel's boot identity, or None while it is unreadable or has another shape than the kernel's; a marker
    from another boot names processes that ended with that boot, and a marker is neither written nor judged
    without the current identity."""
    identity = read(BOOT_ID)
    return identity if identity and BOOT_IDENTITY.fullmatch(identity) else None


def write_custody_marker(directory, name, **record):
    """Writes `<directory>/<name>.json` holding `record` and the boot it was written in, the marker `held_custody`
    reads on the next sweep. Without the boot identity the marker could not be judged later, so none is written."""
    boot = boot_id()
    if boot is None:
        raise OSError(f"the boot identity at {BOOT_ID} is unreadable, so no custody marker can be written")
    Path(directory).mkdir(parents=True, exist_ok=True)
    (Path(directory) / f"{name}.json").write_text(json.dumps({"boot": boot, **record}, sort_keys=True) + "\n")


def group_still_held(pgid, recorded):
    """Whether the group `pgid`, whose members at marking time were `recorded` (pid to start time), still holds
    memory: a recorded member that lives, or any later member while the pid `pgid` is not a new, unrecorded
    process. Linux keeps a pid number while a task uses it as a pid, a process group or a session, so a group
    whose leader ended lives on in its descendants until the last of them ends; a process `pgid` with another
    start time is a new process that reused the number, and then the group is that process's own. An empty
    `recorded` holds no start time to tell such a process from the group it marked, so the group is held while
    it has any live member."""
    if members_hold_memory(recorded):
        return True
    current = group_members(pgid)
    if not current:
        return False
    if not recorded:
        return True
    leader = current.get(pgid)
    return leader is None or leader == recorded.get(pgid)


def reserve_host(directory):
    """Takes the host reservation `<directory>/fis.lock` for the process's life, before the markers are read, so a
    sweep and a FIS campaign, or two campaigns, never both pass an empty custody check and run cases together on
    one host; the descriptor is returned for the holder to pass to the lanes it spawns, or None while another process
    holds the reservation."""
    reservation = os.open(Path(directory) / "fis.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o644)
    try:
        fcntl.flock(reservation, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(reservation)
        return None
    return reservation


def held_custody(directory):
    """The custody markers under `directory` that still quarantine this host, with the others removed.

    A held group outlives the job that stopped it, so its marker quarantines the host: no sweep starts beside it until
    an operator contains the group, which ends it. The marker records the boot it was written in and each member's pid
    and start time; a marker from another boot names processes that ended with it, and a pid another process reused
    counts for nothing, while a group whose leader ended lives on in its descendants. A marker whose group is gone, or
    left only zombies holding no memory, names a group an operator already ended, so it is removed here. A marker that
    records no member holds while its group has a live member. While the current boot identity is unreadable every
    marker is held, and so is a marker whose recorded boot is malformed. A marker with no group, left when a role's
    supervisor died by a signal, holds until an operator removes it after containing whatever that role's case left
    behind; a case that had started left its own group's marker too. A marker flagged `durable`, left for a hazard
    outside this host's processes, holds across boots until an operator removes it.
    """
    held, boot = [], boot_id()
    for marker in sorted(Path(directory).glob("*.json")) if os.path.isdir(directory) else ():
        try:
            record = json.loads(marker.read_text())
            pgid = record["pgid"]
        except (OSError, ValueError, KeyError, TypeError):
            held.append(f"{marker} (unreadable)")
            continue
        where = f"{record.get('profile')}/{record.get('role')} (episode {record.get('episode')}): {record.get('custody')}"
        members = record.get("members")
        if record.get("durable"):
            # A marker for a hazard outside this host's processes, such as a fault whose end is unconfirmed, names
            # nothing a reboot ends; it holds across boots until an operator removes it.
            held.append(f"{where}; remove {marker} once the hazard is confirmed over")
        elif boot is None or not (isinstance(record.get("boot"), str) and BOOT_IDENTITY.fullmatch(record["boot"])):
            held.append(f"{marker} (the boot identity at {BOOT_ID} or the one the marker records is unreadable, "
                        "so the marker is judged held)")
        elif record.get("boot") != boot:
            # Every process of that boot ended with it; the marker names nothing on this one.
            with contextlib.suppress(OSError):
                marker.unlink()
        elif pgid is None:
            held.append(f"an unknown group of {where}; remove {marker} once its case is contained")
        elif not (isinstance(pgid, int) and not isinstance(pgid, bool) and pgid > 0):
            held.append(f"{marker} (unreadable process group {pgid!r})")
        elif not (isinstance(members, dict) and all(
                isinstance(k, str) and k.isascii() and k.isdigit() and k[0] != "0"
                and isinstance(v, int) and not isinstance(v, bool) and v > 0 for k, v in members.items())):
            held.append(f"{marker} (unreadable members)")
        elif group_still_held(pgid, {int(pid): started for pid, started in members.items()}):
            held.append(f"process group {pgid} of {where}" if members else
                        f"process group {pgid} of {where}; {marker} records no member, so identify the group before "
                        "containing it")
        else:
            with contextlib.suppress(OSError):
                marker.unlink()
    return held


def mark_dead_supervisor(directory, label, supervisor, episode, custody):
    """Leaves a marker with no group for a role whose supervisor died by a signal, so the host stays quarantined
    until an operator contains whatever the case left and removes the marker. The marker takes over from the
    sentinel that supervisor wrote before a spawn, naming its case, so one marker records the lost supervisor."""
    profile, _, role = label.partition("/")
    sentinel = Path(directory) / f"starting-{supervisor}.json"
    record = {}
    try:
        case = json.loads(sentinel.read_text()).get("case")
    except (OSError, ValueError, AttributeError):
        case = None
    if isinstance(case, str):
        record["case"], custody = case, f"{custody}; {case} was starting"
    try:
        write_custody_marker(directory, f"supervisor-{supervisor}", pgid=None, supervisor=supervisor, episode=episode,
                             profile=profile, role=role, custody=custody, **record)
    except OSError as error:
        with contextlib.suppress(OSError):
            print(f"- {label}: the custody marker could not be written under {directory}: {error}", flush=True)
        return
    with contextlib.suppress(OSError):
        sentinel.unlink()


def collect(started):
    """Yields each started role as it exits, whichever finishes first, so a lost supervisor is seen at once."""
    pending = list(started)
    while pending:
        done = [(label, child) for label, child in pending if child.poll() is not None]
        if not done:
            time.sleep(POLL)
            continue
        pending = [item for item in pending if item not in done]
        yield from done


def command_sweep(args):
    """Runs the provisioned roles profile by profile, each profile's roles at once; a SIGTERM reaches every started role.
    Consecutive profiles `manifest_refusal` refuses on the row start as one group: `platform_defect` returns that
    refusal for each of their roles before its build.
    A host whose lane sent a role its SIGKILL exits held: SIGKILL ends the role before its teardown, and process
    exit leaves its DMA unproven, so the host awaits the deployment owner's containment; the role wrote the host's
    kill marker before its SIGKILL, for the next sweep and the FIS campaign, which share the custody directory. The
    manifest check keeps the kill profile last, so the host runs nothing after it."""
    platforms, profiles, _ = read_manifest(args.manifest)
    if args.platform not in platforms:
        raise Stop(REJECTED, platform_refusal(args.platform))
    provisioned, environments = set(), {}
    for entry in os.environ.get("KESTRIKE_HARDWARE_ROLES", "").split():
        label, _, path = entry.partition("=")
        provisioned.add(label)
        if path:
            role_environment(path)
            environments[label] = path
    declared = {f"{name}/{role}" for name, profile in profiles.items() for role in profile["roles"]}
    if provisioned - declared:
        raise Stop(REJECTED, f"KESTRIKE_HARDWARE_ROLES names undeclared roles {sorted(provisioned - declared)}")
    # A host provisioned for no role is the wrong host for this job: red, so a misrouted run is seen.
    if not provisioned:
        raise Stop(REJECTED, "KESTRIKE_HARDWARE_ROLES names no role: this host is provisioned for no hardware case")
    # The quarantine fails closed: a custody directory this account cannot list or write refuses the sweep.
    try:
        Path(args.custody).mkdir(parents=True, exist_ok=True)
        os.listdir(args.custody)
    except OSError as error:
        raise Stop(REJECTED, f"the custody directory {args.custody} is unusable: {error}") from error
    if not os.access(args.custody, os.W_OK | os.X_OK):
        raise Stop(REJECTED, f"the custody directory {args.custody} is not writable by this account, "
                             f"so a held group could leave no marker")
    # The reservation is taken before the markers are read, so a FIS campaign in its own checks and this sweep
    # never both pass an empty check; the sweep holds it for its life.
    reservation = reserve_host(args.custody)
    if reservation is None:
        print(f"another sweep or FIS controller holds this host through {Path(args.custody) / 'fis.lock'}", flush=True)
        return HELD
    held = held_custody(args.custody)
    if held:
        print(f"custody held on this host: {held}; contain the groups and remove their markers under {args.custody} "
              f"before any role runs here", flush=True)
        return HELD
    for label, path in environments.items():
        name, _, role = label.partition("/")
        role_environment(path, profiles[name]["roles"][role], label)
    row = platforms[args.platform]
    eligible = {name for name, profile in profiles.items() if manifest_refusal(args.platform, row, profile) is None}
    needed = sum(max((role_seconds(profile, role_name) if name in eligible else OBSERVER_SECONDS
                      for role_name in profile["roles"] if f"{name}/{role_name}" in provisioned), default=0)
                 for name, profile in profiles.items())
    if args.budget_seconds is not None and needed > args.budget_seconds:
        raise Stop(REJECTED, f"the provisioned roles need up to {needed} s, past the {args.budget_seconds} s budget")
    episode = os.environ.get("KESTRIKE_EPISODE") or (
        f"{os.environ['GITHUB_RUN_ID']}-{os.environ.get('GITHUB_RUN_ATTEMPT', '1')}-{args.platform}"
        if os.environ.get("GITHUB_RUN_ID") else f"local-{os.getpid()}-{time.time_ns()}")
    try:
        episode_name(episode)
    except argparse.ArgumentTypeError as error:
        raise Stop(REJECTED, f"KESTRIKE_EPISODE {error}") from error
    observer = os.environ.get("KESTRIKE_HARDWARE_OBSERVER") or str(Path(args.artifacts) / "observer")
    # The sweep opens its episode; a log already there would hand this episode's roles another run's events.
    if (Path(observer) / f"{episode}.jsonl").exists():
        raise Stop(REJECTED, f"episode {episode} already has an observer log under {observer}")
    controller = os.environ.get("KESTRIKE_HARDWARE_CONTROLLER")
    started, stopping = [], []

    def forward(signum, _frame):
        stopping.append(signum)
        for _, child in started:
            with contextlib.suppress(ProcessLookupError):
                child.send_signal(signum)

    signal.signal(signal.SIGTERM, forward)
    signal.signal(signal.SIGINT, forward)
    worst, killed = CREDITED, False
    groups = []
    for name in profiles:
        if name not in eligible and groups and groups[-1][-1] not in eligible:
            groups[-1].append(name)
        else:
            groups.append([name])
    for group in groups:
        started.clear()
        try:
            for name in group:
                for role in profiles[name]["roles"]:
                    if f"{name}/{role}" not in provisioned or stopping or worst == HELD:
                        reason = ("custody is held or unknown" if worst == HELD else "the sweep was interrupted"
                                  if stopping else "this host is not provisioned for it")
                        print(f"- {name}/{role}: unrun; {reason}", flush=True)
                        continue
                    argv = [sys.executable, __file__, "run", "--profile", name, "--role", role,
                            "--manifest", args.manifest, "--platform", args.platform,
                            "--artifacts", args.artifacts, "--cargo", args.cargo, "--episode", episode,
                            "--observer", observer, "--custody", args.custody,
                            *(["--controller", controller] if controller else []),
                            *(["--environment", environments[f"{name}/{role}"]]
                              if f"{name}/{role}" in environments else [])]
                    # Each role supervisor inherits the host reservation; the host stays reserved if the sweep exits
                    # first.
                    supervisor = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                                                  pass_fds=(reservation,))
                    started.append((f"{name}/{role}", supervisor))
                    if stopping:
                        started[-1][1].send_signal(stopping[0])
            for label, child in collect(started):
                output, _ = child.communicate()
                print(f"- {label} (episode {episode}): {output.strip()}", flush=True)
                code = child.returncode
                if code < 0:
                    custody = f"unknown; its supervisor died by signal {-code} and its case's process group may still run"
                    print(f"- {label}: custody {custody}", flush=True)
                    mark_dead_supervisor(args.custody, label, child.pid, episode, custody)
                    code = HELD
                if code == HELD:
                    # Held or unknown custody requires stopping the profile's remaining role supervisors.
                    for _, other in started:
                        if other.poll() is None:
                            with contextlib.suppress(ProcessLookupError):
                                other.send_signal(signal.SIGTERM)
                worst = HELD if HELD in (worst, code) else max(worst, code)
                name, _, role = label.partition("/")
                killed = killed or ("kill" in profiles[name]["roles"][role] and sent_kill(output))
        except OSError as error:
            # A supervisor left running would keep its case outside every containment path the lane owns.
            for _, child in started:
                with contextlib.suppress(ProcessLookupError):
                    child.send_signal(signal.SIGTERM)
            reason = (f"profile {', '.join(group)} failed while its roles started or reported ({error}); "
                      f"its {len(started)} started roles were stopped and collected")
            # The roles' own exits still decide custody: a held or unknown group outranks the sweep's failure.
            held = []
            for label, child in started:
                if child.returncode is None:
                    output, _ = child.communicate()
                    with contextlib.suppress(OSError):
                        print(f"- {label} (episode {episode}): {output.strip()}", flush=True)
                if child.returncode < 0:
                    custody = f"unknown; its supervisor died by signal {-child.returncode}"
                    mark_dead_supervisor(args.custody, label, child.pid, episode, custody)
                    held.append(f"{label} (custody {custody})")
                elif child.returncode == HELD:
                    held.append(f"{label} (custody held)")
            if held:
                with contextlib.suppress(OSError):
                    print(f"- {reason}; custody stays with {held}; contain the groups before releasing their memory", flush=True)
                return HELD
            raise Stop(REJECTED, reason) from error
    if killed:
        print("- the killed owner's host awaits the deployment owner's containment", flush=True)
    print("- a profile credits only through `judge` over every role's receipt; a sweep credits none")
    return HELD if worst == HELD or killed else worst if not stopping else INTERRUPTED


def sent_kill(output):
    """Whether the run whose output names its receipt appended a `killed` event; an unreadable receipt counts as one."""
    path = next((line.split(": ", 1)[1] for line in output.splitlines() if line.startswith("receipt: ")), None)
    try:
        cases = json.loads(Path(path).read_text())["hardware"]["cases"] if path else []
    except (OSError, ValueError, KeyError, TypeError):
        return True
    return not path or any("killed" in case for case in cases)


def episode_name(text):
    """An episode name that is one plain file name component, so the observer log stays inside its directory."""
    if not EPISODE_NAME.fullmatch(text):
        raise argparse.ArgumentTypeError(
            f"{text!r} is not an episode name of letters, digits, '.', '_' and '-' starting with a letter or digit")
    return text


def finite_seconds(text):
    """A finite duration of zero or more seconds, so a controller wait reaches its timeout path and a sweep budget binds."""
    seconds = float(text)
    if not math.isfinite(seconds) or seconds < 0:
        raise argparse.ArgumentTypeError(f"{text!r} is not a finite duration of zero or more seconds")
    return seconds


def parser():
    top = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = top.add_subparsers(dest="command", required=True)
    for name in ("run", "judge", "sweep"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", default=str(MANIFEST))
        if name != "judge":
            command.add_argument("--artifacts", default="target/hardware")
            command.add_argument("--custody", default=CUSTODY_DIR)
            if name == "sweep":
                command.add_argument("--budget-seconds", type=finite_seconds)
            command.add_argument("--cargo", default="cargo")
            command.add_argument("--platform", default=os.environ.get("KESTRIKE_HARDWARE_PLATFORM"))
        if name != "sweep":
            command.add_argument("--profile", required=True)
    run = commands.choices["run"]
    run.add_argument("--role", required=True)
    run.add_argument("--episode", type=episode_name, default=f"local-{os.getpid()}-{time.time_ns()}")
    run.add_argument("--observer")
    run.add_argument("--controller")
    run.add_argument("--environment")
    run.add_argument("--controller-seconds", type=finite_seconds, default=CONTROLLER_SECONDS)
    run.add_argument("--run-id")
    commands.choices["judge"].add_argument("--revision")
    commands.choices["judge"].add_argument("receipts", nargs="+")
    return top


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        return {"run": command_run, "judge": command_judge, "sweep": command_sweep}[args.command](args)
    except Stop as stop:
        print(f"rejected input: {stop}")
        return REJECTED
    except FAULTS as error:
        print(f"rejected input: {type(error).__name__}: {error}")
        return REJECTED


if __name__ == "__main__":
    sys.exit(main())
