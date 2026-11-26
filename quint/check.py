#!/usr/bin/env python3
"""Check session, detector, route, tenure, prefix, coverage, capture, preserve, suffix, saturation, key-operation, fill, watchdog, burst, join, binder, creation, standbys and loss types, reachability, safety, controls and Rust replay.

Session cases import `session.qnt`; detector, route, tenure, prefix, coverage, capture, preserve, suffix, saturation, key-operation, fill, watchdog, burst, binder and standbys cases import
their model, apply their mutations and may restrict the scheduler to a legal
recipe. Join cases check composed projections of two of those models, each a module of `joins.qnt` that imports
both as instances, stepped by its joint scheduler after a prefix of its actions; `projection_cases` states their
cases and the cases of the standbys prefix roots. Every command runs in its own session under an 1100-second deadline, or under the deadline its case declares,
which the session `safety` case alone does; the deadline, a SIGTERM to the runner or a terminal interrupt stops the
whole session, SIGKILL following a ten-second grace, and `results.json` names the case that was running. Detect and
route replay
regenerate their committed traces, require them to equal the fixtures and
replay them against the Rust cores; the key-operation replay does the same
against `Storage` and the history oracle, the binder replay against two
binder processes, the creation, standbys and loss replays against `Reconciler`, and the detect
witness replay against the detector and arbiter cores; Connect replay uses
Sessions. Detector
cases add temporal checking of nomination progress.

Session cases write an instance module that imports `session.qnt` with the
case's constants, copies the model beside it, applies the case's one
mutation to that copy, and runs Quint on it. A `tlc` case runs `quint verify
--backend tlc` with the case's invariant or temporal property; a `simulate`
case runs `quint run` on the TypeScript simulator under a pinned seed and
reports every witness's trace count and the trace lengths; a `replay` case
checks that `replay.qnt` imports the model at the runner's constants, runs
the ignored `cargo test` in which Quint Connect generates traces of
`replay.qnt` and replays them against `Sessions`, with a `quint` shim on
`PATH` that selects the TypeScript simulator, and reports the traces,
actions, longest trace and executions of each action it replayed, with
`init` and every choice of the model's `step` reached; `typecheck` runs
`quint typecheck` on the case's copy of the model. A case passes only with
the outcome it declares: a completed check without violation, or a violation
of its property after at least one step, and for the broken variant a lasso
in which one peer's pending handshake was displaced and whose loop repeats
that peer's CONFIRM and the owner's mismatch of it under a pending handshake
naming another client nonce. A mutation case that runs under a recipe and
declares a violation must violate at the recipe's last action, so a violation
during the recipe's setup fails the case, unless the case declares as `trace`
the length of the earlier trace at which its mutated rule fails. A `tlc`
case's log names that outcome as the one terminal line TLC reports, so a
failure TLC prints beside it fails the case. Every other outcome stops the run with a
nonzero exit, and `results.json` records the failing case.
"""

from __future__ import annotations

import argparse
import contextlib
import errno
import hashlib
import importlib.util
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

_spec = importlib.util.spec_from_file_location("tenure_checks", Path(__file__).resolve().parent / "tenure_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load tenure_check.py")
tenure_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(tenure_checks)

_spec = importlib.util.spec_from_file_location("prefix_checks", Path(__file__).resolve().parent / "prefix_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load prefix_check.py")
prefix_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(prefix_checks)

_spec = importlib.util.spec_from_file_location("coverage_checks", Path(__file__).resolve().parent / "coverage_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load coverage_check.py")
coverage_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(coverage_checks)

_spec = importlib.util.spec_from_file_location("capture_checks", Path(__file__).resolve().parent / "capture_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load capture_check.py")
capture_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(capture_checks)

_spec = importlib.util.spec_from_file_location("preserve_checks", Path(__file__).resolve().parent / "preserve_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load preserve_check.py")
preserve_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(preserve_checks)


_spec = importlib.util.spec_from_file_location("suffix_checks", Path(__file__).resolve().parent / "suffix_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load suffix_check.py")
suffix_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(suffix_checks)


_spec = importlib.util.spec_from_file_location("fill_checks", Path(__file__).resolve().parent / "fill_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load fill_check.py")
fill_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fill_checks)

_spec = importlib.util.spec_from_file_location("watchdog_checks", Path(__file__).resolve().parent / "watchdog_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load watchdog_check.py")
watchdog_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watchdog_checks)

_spec = importlib.util.spec_from_file_location("put_checks", Path(__file__).resolve().parent / "put_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load put_check.py")
put_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(put_checks)
_spec = importlib.util.spec_from_file_location("identity_checks", Path(__file__).resolve().parent / "identity_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load identity_check.py")
identity_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(identity_checks)

_spec = importlib.util.spec_from_file_location("saturation_checks", Path(__file__).resolve().parent / "saturation_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load saturation_check.py")
saturation_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(saturation_checks)


_spec = importlib.util.spec_from_file_location("keyops_checks", Path(__file__).resolve().parent / "keyops_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load keyops_check.py")
keyops_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(keyops_checks)


_spec = importlib.util.spec_from_file_location("join_checks", Path(__file__).resolve().parent / "join_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load join_check.py")
join_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(join_checks)


_spec = importlib.util.spec_from_file_location("binder_checks", Path(__file__).resolve().parent / "binder_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load binder_check.py")
binder_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(binder_checks)


_spec = importlib.util.spec_from_file_location("board_checks", Path(__file__).resolve().parent / "board_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load board_check.py")
board_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(board_checks)

_spec = importlib.util.spec_from_file_location("read_checks", Path(__file__).resolve().parent / "read_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load read_check.py")
read_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(read_checks)

_spec = importlib.util.spec_from_file_location("burst_checks", Path(__file__).resolve().parent / "burst_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load burst_check.py")
burst_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(burst_checks)
_spec = importlib.util.spec_from_file_location("settle_checks", Path(__file__).resolve().parent / "settle_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load settle_check.py")
settle_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(settle_checks)

_spec = importlib.util.spec_from_file_location("episode_checks", Path(__file__).resolve().parent / "episode_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load episode_check.py")
episode_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(episode_checks)

_spec = importlib.util.spec_from_file_location("pool_checks", Path(__file__).resolve().parent / "pool_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load pool_check.py")
pool_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pool_checks)

_spec = importlib.util.spec_from_file_location("gate_checks", Path(__file__).resolve().parent / "gate_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load gate_check.py")
gate_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gate_checks)

_spec = importlib.util.spec_from_file_location("escrow_checks", Path(__file__).resolve().parent / "escrow_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load escrow_check.py")
escrow_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(escrow_checks)

_spec = importlib.util.spec_from_file_location("window_checks", Path(__file__).resolve().parent / "window_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load window_check.py")
window_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(window_checks)

_spec = importlib.util.spec_from_file_location("extent_checks", Path(__file__).resolve().parent / "extent_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load extent_check.py")
extent_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(extent_checks)

_spec = importlib.util.spec_from_file_location("report_checks", Path(__file__).resolve().parent / "report_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load report_check.py")
report_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(report_checks)

_spec = importlib.util.spec_from_file_location("creation_checks", Path(__file__).resolve().parent / "creation_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load creation_check.py")
creation_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(creation_checks)

_spec = importlib.util.spec_from_file_location("standbys_checks", Path(__file__).resolve().parent / "standbys_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load standbys_check.py")
standbys_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(standbys_checks)

_spec = importlib.util.spec_from_file_location("parked_checks", Path(__file__).resolve().parent / "parked_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load parked_check.py")
parked_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(parked_checks)

_spec = importlib.util.spec_from_file_location("detect_route_checks", Path(__file__).resolve().parent / "detect_route_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load detect_route_check.py")
detect_route_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect_route_checks)

_spec = importlib.util.spec_from_file_location("mempool_checks", Path(__file__).resolve().parent / "mempool_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load mempool_check.py")
mempool_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(mempool_checks)

_spec = importlib.util.spec_from_file_location("custody_checks", Path(__file__).resolve().parent / "custody_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load custody_check.py")
custody_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(custody_checks)

_spec = importlib.util.spec_from_file_location("claims_checks", Path(__file__).resolve().parent / "claims_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load claims_check.py")
claims_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(claims_checks)

_spec = importlib.util.spec_from_file_location("grace_checks", Path(__file__).resolve().parent / "grace_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load grace_check.py")
grace_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(grace_checks)

_spec = importlib.util.spec_from_file_location("visit_checks", Path(__file__).resolve().parent / "visit_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load visit_check.py")
visit_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(visit_checks)

_spec = importlib.util.spec_from_file_location("reclaim_checks", Path(__file__).resolve().parent / "reclaim_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load reclaim_check.py")
reclaim_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(reclaim_checks)

_spec = importlib.util.spec_from_file_location("watermark_checks", Path(__file__).resolve().parent / "watermark_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load watermark_check.py")
watermark_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(watermark_checks)

_spec = importlib.util.spec_from_file_location("loss_checks", Path(__file__).resolve().parent / "loss_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load loss_check.py")
loss_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(loss_checks)

_spec = importlib.util.spec_from_file_location("lookup_checks", Path(__file__).resolve().parent / "lookup_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load lookup_check.py")
lookup_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(lookup_checks)

_spec = importlib.util.spec_from_file_location("allowance_checks", Path(__file__).resolve().parent / "allowance_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load allowance_check.py")
allowance_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(allowance_checks)

_spec = importlib.util.spec_from_file_location("register_checks", Path(__file__).resolve().parent / "register_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load register_check.py")
register_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(register_checks)

_spec = importlib.util.spec_from_file_location("marklog_checks", Path(__file__).resolve().parent / "marklog_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load marklog_check.py")
marklog_checks = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(marklog_checks)

_spec = importlib.util.spec_from_file_location("creation_fixtures", Path(__file__).resolve().parent / "creation_fixtures.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load creation_fixtures.py")
creation_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(creation_fixtures)

_spec = importlib.util.spec_from_file_location("standbys_fixtures", Path(__file__).resolve().parent / "standbys_fixtures.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load standbys_fixtures.py")
standbys_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(standbys_fixtures)

_spec = importlib.util.spec_from_file_location("loss_fixtures", Path(__file__).resolve().parent / "loss_fixtures.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load loss_fixtures.py")
loss_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(loss_fixtures)

_spec = importlib.util.spec_from_file_location("detect_witness_fixtures", Path(__file__).resolve().parent / "detect_witness_fixtures.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load detect_witness_fixtures.py")
detect_witness_fixtures = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(detect_witness_fixtures)

CONSTANTS = {
    "CLIENTS": 'Set("c1", "c2")', "BOOTS": "2", "REKEYS": "1", "FAULTS": "2", "CAP_TO_OWNER": "2",
    "CAP_TO_CLIENT": "1", "COPIES": "2", "REPEATS": "2",
}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "session.qnt").read_text()))
SEED, SAMPLES, STEPS = "0x51", "400", "40"
# The ignored Connect replay test and the traces it generates: 50 of `replay.qnt`'s `step` and 10 of its
# `openThenReopen` recipe, which reaches the reopen that `step`'s random traces miss.
REPLAY_TEST = "net::q1_replay_tests::connect_replays_generated_q1_traces"
REPLAY_TRACES = 60
# The detect and route replays read the committed traces in this directory, relative to the repository root.
DETECT_ROUTE_FIXTURES = "crates/kestrike/src/failover/detect_route_fixtures"
# The key-operation replay reads the committed traces in this directory, relative to the repository root.
KEYOPS_FIXTURES = "crates/kestrike/src/storage/keyops_fixtures"
CASE_SECONDS, KILL_GRACE_SECONDS = 1100, 10
# The session `safety` case's deadline: its exhaustive search at three faults outlasts `CASE_SECONDS`, and
# quint/README.md records the measurement this allowance is sized from.
SAFETY_SECONDS = 5400


def model_actions(text):
    """Return `init` and the actions the model's `step` chooses among, in their order in `step`."""
    block = re.search(r"(?ms)^  action step = any \{\n(.*?)^  \}$", text)
    if not block:
        raise ValueError("the model has no `step` action")
    choices = re.sub(r"\([^()]*\)", "", re.sub(r"(?m)^\s*nondet .*$", "", block[1]))
    return ("init", *(name for name in re.findall(r"\w+", choices) if name != "any"))


# The model's actions; the Connect replay must reach each one.
REPLAY_ACTIONS = model_actions((Path(__file__).resolve().parent / "session.qnt").read_text())


@dataclass
class Case:
    """One Quint run and the only outcome that passes it.

    `settings` override the instance constants. `invariant` or `temporal`
    names the property a `tlc` case checks, `step` the action it steps under
    in place of the model's default `step` action, `extra` adds definitions to the instance module, and
    `mutations` replace unique texts of the model's copy. `expected` is `ok` or `violation`; `lasso` also requires the
    broken variant's loop, and `trace`, when set, is the number of states the violation's trace must hold. A mutation
    case with a `recipe` and a violation outcome that sets no `trace` must violate at its recipe's last action: its
    trace holds `len(recipe) + 1` states. `depth`,
    when set, is the depth a passing check must report, and `after` the number of states a violation's trace must
    exceed; where the case's constants declare `BOUND`, that trace also holds at most `BOUND + 1` states. Every
    invariant violation's trace carries the state labels 1 to N in order. `deadline`, when set, is the case's deadline
    in seconds in place of `CASE_SECONDS`. A case that sets `depth` on a violation, `trace` or `after` on a passing
    check, a `step` beside a `recipe`, a `step` or a `recipe` on a session case, whose command passes none, both
    `invariant` and `temporal`, or a `tlc` case without one property named by an identifier raises ValueError.
    """

    name: str
    command: str = "tlc"
    settings: dict[str, str] = field(default_factory=dict)
    invariant: str | None = None
    temporal: str | None = None
    extra: str = ""
    expected: str = "ok"
    lasso: bool = False
    family: str = "session"
    recipe: list[str] = field(default_factory=list)
    mutations: list[tuple[str, str]] = field(default_factory=list)
    step: str | None = None
    trace: int | None = None
    depth: int | None = None
    after: int | None = None
    deadline: int | None = None

    def __post_init__(self):
        if self.depth is not None and self.expected != "ok":
            raise ValueError(f"{self.name}: a depth applies only to a passing check")
        if (self.trace is not None or self.after is not None) and self.expected != "violation":
            raise ValueError(f"{self.name}: a trace length applies only to a violation")
        if self.step and (self.recipe or self.family == "session"):
            raise ValueError(f"{self.name}: a step applies only to a family case without a recipe")
        if self.invariant and self.temporal:
            raise ValueError(f"{self.name}: a case checks one property, an invariant or a temporal property")
        prop = self.invariant or self.temporal or ""
        if self.command == "tlc" and (not re.fullmatch(r"\w+", prop) or prop in ("true", "false")):
            raise ValueError(f"{self.name}: a tlc case names one property, a model definition, as its invariant or "
                             f"temporal property, not {prop!r}")
        if self.recipe and self.family == "session":
            raise ValueError(f"{self.name}: a recipe applies only to a family case, whose command steps under it")


def cases():
    yield Case("typecheck", command="typecheck")
    yield Case("connect-replay", command="replay")
    yield Case("simulation", command="simulate", invariant="safety")
    for witness in WITNESSES:
        yield Case(f"reach-{witness}", invariant="unreached", extra=f"  val unreached = not({witness})\n",
                   expected="violation")
    yield Case("safety", settings={"FAULTS": "3"}, invariant="safety", deadline=SAFETY_SECONDS)
    yield Case("progress", temporal="progress")
    yield Case("broken-progress", settings={"REPEATS": "-1"}, temporal="progress", expected="violation", lasso=True)
    yield Case("mutant-reuse-epoch", invariant="distinctEpochs", expected="violation",
               mutations=[("val epoch = raised.issued + 1", "val epoch = raised.issued")])
    yield Case("mutant-data-ignores-epoch", invariant="dataNamesActive", expected="violation",
               mutations=[("val admitted = names(c.active, f)",
                         "val admitted = handshake(c.active).client == f.client and isSome(c.active)")])
    yield Case("mutant-hello-drops-active", invariant="agreement", expected="violation",
               mutations=[("pending: Some(h) }", "pending: Some(h), active: None }")])
    yield Case("mutant-reopen-untracked", invariant="agreement", expected="violation",
               mutations=[("sendHello(s, peer, { ...c, opening: true })", "sendHello(s, peer, c)")])
    yield Case("mutant-mismatch-drops-pending", invariant="staleChangesNothing", expected="violation",
               mutations=[('if (f.client != c.nonce) (st, { ...ev, verdict: "mismatch" })',
                         'if (f.client != c.nonce) ({ ...st, clients: st.clients.set(f.peer, { ...c, pending: None }) }, '
                         '{ ...ev, verdict: "mismatch" })')])
    yield Case("mutant-confirm-shifts-epoch", invariant="activationBinds", expected="violation",
               mutations=[("val h = { epoch: f.epoch, client: f.client }", "val h = { epoch: f.epoch + 1, client: f.client }")])
    yield Case("mutant-ready-skips-pending", settings={"FAULTS": "3"}, invariant="activationBinds",
               expected="violation",
               mutations=[('      else if (not(names(c.pending, f))) (st, { ...ev, verdict: "mismatch" })\n'
                         '      else if (f.seq != c.sent) (st, { ...ev, verdict: "stale" })\n',
                         '      else if (not(isSome(c.pending))) (st, { ...ev, verdict: "mismatch" })\n')])
    # A step that never reboots a client leaves the reboot witness unreached, so its reach check finds no trace.
    yield Case("mutant-step-drops-reboot", invariant="unreached", extra="  val unreached = not(witnessReboot)\n",
               mutations=[("          reboot(peer), reopen(peer) },", "          reopen(peer) },")])

    yield from detect_route_checks.cases(Case)
    yield from tenure_checks.cases(Case)
    yield from prefix_checks.cases(Case)
    yield from coverage_checks.cases(Case)
    yield from capture_checks.cases(Case)
    yield from preserve_checks.cases(Case)
    yield from suffix_checks.cases(Case)
    yield from fill_checks.cases(Case)
    yield from watchdog_checks.cases(Case)
    yield from put_checks.cases(Case)
    yield from identity_checks.cases(Case)
    yield from board_checks.cases(Case)
    yield from read_checks.cases(Case)
    yield from burst_checks.cases(Case)
    yield from escrow_checks.cases(Case)
    yield from mempool_checks.cases(Case)
    yield from custody_checks.cases(Case)
    yield from settle_checks.cases(Case)
    yield from episode_checks.cases(Case)
    yield from claims_checks.cases(Case)
    yield from pool_checks.cases(Case)
    yield from gate_checks.cases(Case)
    yield from grace_checks.cases(Case)
    yield from window_checks.cases(Case)
    yield from visit_checks.cases(Case)
    yield from reclaim_checks.cases(Case)
    yield from extent_checks.cases(Case)
    yield from watermark_checks.cases(Case)
    yield from loss_checks.cases(Case)
    yield from lookup_checks.cases(Case)
    yield from allowance_checks.cases(Case)
    yield from report_checks.cases(Case)
    yield from creation_checks.cases(Case)
    yield from standbys_checks.cases(Case)
    for name, projection in standbys_checks.PROJECTIONS.items():
        yield from projection_cases("standbys", name, projection)
    yield from parked_checks.cases(Case)
    yield from register_checks.cases(Case)
    yield from marklog_checks.cases(Case)
    yield from saturation_checks.cases(Case)
    yield from keyops_checks.cases(Case)
    yield Case("join-typecheck", command="typecheck", family="join")
    for name, projection in join_checks.PROJECTIONS.items():
        yield from projection_cases("join", name, projection)
    yield from binder_checks.cases(Case)


def projection_cases(family, name, projection):
    """Yield the cases of one prefix-rooted projection: its module stepped by the projection's `step` action after
    the actions of its `prefix`, one per turn of the module's `turn`, fix a root state.

    `BOUND` counts every action from the initial state, the prefix's included. The `safety` case checks every
    continuation of the prefix under the projection's scheduler up to `BOUND` and must reach depth `BOUND + 1`. Each
    witness case must reach its witness, and each mutant case, which applies the mutant's text replacements, must
    violate the mutant's property, both after the prefix and within `BOUND + 1` states. Each mutant names a witness of
    the projection, a state the unmutated projection reaches that exercises the rule the mutant changes; the runner
    checks only that the witness is declared, and no case shows that a violating schedule holds it. A `BOUND` that
    leaves no step after the prefix, a mutant that names no declared witness, or two mutants with one property and one
    mutation list raise ValueError.
    """
    prefix, settings = projection.get("prefix", []), projection["settings"]
    bound = int(settings["BOUND"])
    if bound <= len(prefix):
        raise ValueError(f"{family}-{name}: BOUND {bound} leaves no step after its prefix")
    extra, step = "", projection["step"]
    if prefix:
        extra = "  action component = any {\n" + "".join(
            f"    all {{ turn == {at}, {action} }},\n" for at, action in enumerate(prefix)) + \
            f"    all {{ turn >= {len(prefix)}, {step} }},\n  }}\n"
        step = "component"
    base = f"{family}-{name}"
    identities = [(prop, list(mutations)) for prop, _, mutations in projection["mutants"].values()]
    if any(identities.count(identity) > 1 for identity in identities):
        raise ValueError(f"{base}: two mutants check one property under one mutation list")
    yield Case(f"{base}-safety", invariant="safety", family=family, settings=settings, step=step, extra=extra,
               depth=bound + 1)
    for witness in projection["witnesses"]:
        yield Case(f"{base}-reach-{witness}", invariant="unreached", expected="violation", family=family,
                   settings=settings, step=step, after=len(prefix) + 1,
                   extra=extra + f"  val unreached = not({witness})\n")
    for mutant, (prop, witness, mutations) in projection["mutants"].items():
        if witness not in projection["witnesses"]:
            raise ValueError(f"{base}-mutant-{mutant}: its trigger {witness} is not a witness of the projection")
        yield Case(f"{base}-mutant-{mutant}", invariant=prop, expected="violation", family=family, settings=settings,
                   step=step, extra=extra, mutations=list(mutations), after=len(prefix) + 1)


def instance(case):
    """Return the instance module a case checks."""
    constants = {**CONSTANTS, **case.settings}
    bindings = ", ".join(f"{name} = {value}" for name, value in constants.items())
    return f"module q1case {{\n  import session({bindings}).* from \"./session\"\n{case.extra}}}\n"


def model(case, source):
    """Return the model text a case checks: the committed model with the case's mutation applied."""
    text = (source / "session.qnt").read_text()
    return apply_mutations(case, text)


def apply_mutations(case, text):
    """Return `text` with each of the case's mutations applied to its one occurrence."""
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target count is {text.count(old)}, expected 1")
        text = text.replace(old, new)
    return text


def verify_fixtures(directory, source, key, declared):
    """Bind the committed traces in `directory` to their declared models, metadata and final actions.

    `declared` maps each trace name to its model file under `source` and the metadata that the trace records under
    `#meta[key]`: its `recipe`, its `steps`, or both. The recorded `model_sha256` must equal the model's current
    digest. The trace must hold one state more than its declared `steps`, or one more than its recipe's actions
    when the declaration names no `steps`. Any other trace file in `directory` is refused.
    """
    paths = {p.name.removesuffix(".itf.json"): p for p in directory.glob("*.itf.json")}
    if set(paths) != set(declared):
        raise ValueError(f"{directory.name}: fixture names differ from the declaration")
    digests = {model: hashlib.sha256((source / model).read_bytes()).hexdigest() for model, _ in declared.values()}
    for name, (model, metadata) in declared.items():
        expected = {**metadata, "model_sha256": digests[model]}
        try:
            data = json.loads(paths[name].read_text())
            recorded = data["#meta"][key]
            drifted = any(recorded.get(field) != value for field, value in expected.items())
            states = len(data["states"])
        except (KeyError, TypeError, ValueError, AttributeError) as error:
            raise ValueError(f"{name}: fixture is malformed: {error}") from error
        if drifted:
            raise ValueError(f"{name}: fixture model, recipe or bounds drifted")
        if states != declared_steps(metadata) + 1:
            raise ValueError(f"{name}: fixture stopped before its final action")


def declared_steps(metadata):
    """Return the steps a trace's declaration gives it: its `steps`, or its recipe's actions when it names none."""
    return metadata["steps"] if "steps" in metadata else len(metadata["recipe"])


def replay_traces(case):
    """Return the committed traces a replay case regenerates and replays: their directory under the repository root,
    their `#meta` key and their declaration, or None for a case that replays none, the Connect replay included.

    The detect and route replays share one directory and declaration; `replay_steps` selects each case's own traces.
    """
    if case.command != "replay":
        return None
    family = family_checks(case)
    if case.name == detect_route_checks.WITNESS_REPLAY:
        return detect_witness_fixtures.FIXTURES, "cores", detect_witness_fixtures.fixtures()
    if family is detect_route_checks:
        return DETECT_ROUTE_FIXTURES, "cores", detect_route_checks.fixtures()
    if family is keyops_checks:
        return KEYOPS_FIXTURES, "keyops", keyops_checks.fixtures()
    if family is binder_checks:
        return binder_checks.FIXTURES, "binder", binder_checks.fixtures()
    if family is creation_checks:
        return creation_fixtures.FIXTURES, "creation", creation_fixtures.fixtures()
    if family is standbys_checks:
        return standbys_fixtures.FIXTURES, "standbys", standbys_fixtures.fixtures()
    if family is loss_checks:
        return loss_fixtures.FIXTURES, "loss", loss_fixtures.fixtures()
    return None


def replay_steps(case):
    """Return the declared steps of each trace a replay case replays, the traces of its family's model among those
    `replay_traces` gives it, or None where that gives none."""
    traces = replay_traces(case)
    if traces is None:
        return None
    return [declared_steps(metadata) for model, metadata in traces[2].values() if model == case.family + ".qnt"]


def replay_instance(source):
    """Return `replay.qnt`, the instance the Connect replay runs, once its bindings equal the runner's constants."""
    text = (source / "replay.qnt").read_text()
    imported = re.search(r"import session\((.*?)\) as Q", text, re.S)
    bindings = dict(re.findall(r"(\w+) = (Set\([^)]*\)|-?\w+)", imported[1])) if imported else {}
    if bindings != CONSTANTS:
        differ = sorted(name for name in {*bindings, *CONSTANTS} if bindings.get(name) != CONSTANTS.get(name))
        raise ValueError(f"replay.qnt binds {differ} other than the runner's constants {CONSTANTS}")
    return text


def inputs(case, source):
    """Return the texts a case checks by name: the model's copy and the instance, `replay.qnt` for the replay.

    A setting that names no constant of the case's family, or any setting on a typecheck or replay, which apply
    none, raises ValueError."""
    family = family_checks(case)
    unknown = set(case.settings) - set(family_constants(case))
    if unknown:
        raise ValueError(f"{case.name}: settings {sorted(unknown)} name no {case.family} constant")
    if case.settings and case.command in ("typecheck", "replay"):
        raise ValueError(f"{case.name}: a {case.command} applies no settings")
    traces = replay_traces(case)
    if traces is not None:
        directory, key, declared = traces
        verify_fixtures(source.parent / directory, source, key, declared)
    if family is not None:
        return family.inputs(case, source)
    if case.command == "replay":
        return {"session.qnt": model(case, source), "replay.qnt": replay_instance(source)}
    return {"session.qnt": model(case, source), "case.qnt": instance(case)}


def shim(quint):
    """Return the `quint` the Connect replay runs: the pinned one, on the TypeScript simulator for `quint run`."""
    quoted = shlex.quote(quint)
    return (f'#!/bin/sh\nif [ "$1" = run ]; then exec {quoted} "$@" --backend typescript; fi\n'
            f'exec {quoted} "$@"\n')


def free_port():
    """Return a localhost port that no socket holds when the call returns."""
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def claim_port():
    """Return a free localhost TCP port and the UDP socket, bound to the same number, that claims it.

    Quint's server binds the TCP port only after this call returns, so another runner on the host can draw the same
    free port in between. A runner holds its claim until its case ends, and a runner that finds a number claimed
    draws again, so the runners of one network namespace start no two servers on one port.
    """
    while True:
        port = free_port()
        claim = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            claim.bind(("127.0.0.1", port))
        except OSError as error:
            claim.close()
            if error.errno != errno.EADDRINUSE:
                raise
            continue
        return port, claim


def command(case, quint, directory, port=None):
    """Return the case's Quint argv; a `tlc` case translates through the Apalache server Quint starts on `port`.

    Quint reuses any server already answering at its endpoint. A fresh port per case keeps this run's previous server,
    while it shuts down, from translating the case, and the port's claim (`claim_port`) keeps another runner on the
    host from starting its server there while the case runs. A `tlc` case that declares a
    `step` raises ValueError unless its family's argv passes that step after `--step`, and one that declares a `recipe`
    unless its family's argv passes `recipe` after `--step`.
    """
    family = family_checks(case)
    if family is not None:
        argv = family.command(case, quint, directory, port)
        at = argv.index("--step") + 1 if "--step" in argv else len(argv)
        if case.command == "tlc" and case.step and argv[at:at + 1] != [case.step]:
            raise ValueError(f"{case.name}: the {case.family} command drops the case's step {case.step}")
        if case.command == "tlc" and case.recipe and argv[at:at + 1] != ["recipe"]:
            raise ValueError(f"{case.name}: the {case.family} command drops the case's recipe")
        return argv
    if case.command == "typecheck":
        return [quint, "typecheck", "session.qnt"]
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact", REPLAY_TEST, "--nocapture"]
    if case.command == "simulate":
        return [quint, "run", "case.qnt", "--main", "q1case", "--backend", "typescript", "--seed", SEED,
                "--max-samples", SAMPLES, "--max-steps", STEPS, "--invariant", case.invariant,
                "--witnesses", *WITNESSES]
    prop = ["--invariant", case.invariant] if case.invariant else ["--temporal", case.temporal]
    return [quint, "verify", "case.qnt", "--main", "q1case", "--backend", "tlc", "--server-endpoint",
            f"127.0.0.1:{port}", "--tlc-config", str(directory / "tlc.json"), *prop]


def blocks(log):
    """Return the trace's states, keyed by number, as the text TLC prints for each."""
    parts = re.split(r"(?m)^State (\d+): ", log)
    return {int(parts[at]): parts[at + 1] for at in range(1, len(parts) - 1, 2)}


# TLC prints one of these whole lines between a violation and the states of its trace.
TRACE_HEADINGS = frozenset({"Error: The behavior up to this point is:",
                            "Error: The following behavior constitutes a counter-example:"})


def terminals(log):
    """Return every terminal line TLC reports in the log, in order: TLC opens its completion report with
    `Model checking completed.` and each violation, run failure and trace heading with `Error: `, and the trace
    headings are no outcome. A run that reached one outcome and reported no failure holds exactly one."""
    return [line for line in log.splitlines()
            if line.startswith(("Model checking completed.", "Error: ")) and line not in TRACE_HEADINGS]


def event(text):
    """Return the text of the `last` variable in a state's block."""
    match = re.search(r"session_last = (.*?)(?:\n/\\ |\n\n|\Z)", text, re.S)
    return match.group(1) if match else ""


def lasso(log):
    """Check the broken variant's loop and return its first and last state numbers."""
    back = re.findall(r"Back to state (\d+)", log)
    states = blocks(log)
    if len(back) != 1 or not states:
        raise RuntimeError("the counterexample is not one lasso")
    start, end = int(back[0]), max(states)
    loop = [event(states[number]) for number in range(start, end + 1)]
    prefix = [event(states[number]) for number in range(1, start)]
    def peers(events, *marks):
        return {found[0] for e in events if all(mark in e for mark in marks)
                for found in [re.findall(r'peer \|-> "(\w+)"', e)] if found}

    mismatch = peers(loop, 'act |-> "deliverToOwner"', 'kind |-> "confirm"', 'verdict |-> "mismatch"',
                     'pendingForeign |-> TRUE')
    repeat = peers(loop, 'act |-> "retry"', 'verdict |-> "confirm"')
    displaced = peers(prefix + loop, 'pendingDisplaced |-> TRUE')
    if not mismatch & repeat & displaced:
        raise RuntimeError(f"no peer's lasso shows the displaced pending handshake ({sorted(displaced)}), a repeated "
                           f"CONFIRM ({sorted(repeat)}) and its mismatch under the foreign pending handshake ({sorted(mismatch)})")
    return [start, end]


def judge(case, log, returncode):
    """Return the facts of a run that reached the case's declared outcome, or raise.

    The family resolves before any arm reads the log, so an undeclared family raises ValueError for every command,
    and a replay or simulation of a family other than session raises ValueError unless the family declares it.
    """
    if type(returncode) is not int:
        raise RuntimeError(f"{case.name}: exit status {returncode!r} is not an integer")
    if returncode < 0 or returncode > 255 or returncode in (124, 130, 137, 143):
        raise Incomplete(f"{case.name}: interrupted exit {returncode}")
    family = family_checks(case)
    if case.command == "typecheck":
        if returncode != 0 or re.search(r"(?i)\berror\b", log):
            raise RuntimeError(f"{case.name}: the model does not typecheck")
        return {}
    steps = replay_steps(case)
    if steps is not None:
        report = re.search(r"(?m)^core replay: traces=(\d+) actions=(\d+) agreement=all$", log)
        if returncode != 0 or not report or "test result: ok. 1 passed;" not in log or int(report[1]) != len(steps) or int(report[2]) != sum(steps):
            raise RuntimeError(f"{case.name}: core replay failed or reported no agreement")
        return {"traces": int(report[1]), "actions": int(report[2])}
    if case.command in ("replay", "simulate") and family is not None:
        raise ValueError(f"{case.name}: family {case.family} has no {case.command} verdict")
    if case.command == "replay":
        report = re.search(r"(?m)^q1 connect replay: traces=(\d+) actions=(\d+) longest=(\d+) "
                           r"per_action=([\w:,]+) agreement=all$", log)
        if returncode != 0 or not report or "test result: ok. 1 passed;" not in log:
            raise RuntimeError(f"{case.name}: the Connect replay diverged, failed or reported no agreement")
        traces, actions, longest = (int(value) for value in report.groups()[:3])
        per_action = {name: int(count) for name, count in (pair.split(":") for pair in report[4].split(","))}
        if traces != REPLAY_TRACES or actions <= traces or any(per_action.get(name, 0) == 0 for name in REPLAY_ACTIONS):
            raise RuntimeError(f"{case.name}: the replay ran {traces} traces of {actions} actions reaching {per_action}")
        return {"traces": traces, "actions": actions, "longest": longest, "per_action": per_action}
    if case.command == "simulate":
        if returncode != 0 or "[ok] No violation found" not in log:
            raise RuntimeError(f"{case.name}: the simulation found a violation or failed")
        lengths = re.search(r"Trace length statistics: max=(\d+), min=(\d+), average=([\d.]+)", log)
        counts = {name: (int(hit), int(total)) for name, hit, total in
                  re.findall(r"(?m)^(\w+) was witnessed in (\d+) trace\(s\) out of (\d+) explored", log)}
        if not lengths or sorted(counts) != sorted(WITNESSES):
            raise RuntimeError(f"{case.name}: the simulation reported no trace lengths or other witnesses")
        traces = {total for _, total in counts.values()}
        if len(traces) != 1:
            raise RuntimeError(f"{case.name}: the witnesses count different trace sets")
        # A trace of `STEPS` steps contains `STEPS + 1` states.
        explored, shortest = traces.pop(), int(lengths[2])
        if explored != int(SAMPLES):
            raise RuntimeError(f"{case.name}: the simulation explored {explored} traces of {SAMPLES}")
        if shortest < int(STEPS) + 1:
            raise RuntimeError(f"{case.name}: the shortest trace holds {shortest} states, short of {STEPS} steps")
        return {"traces": explored, "lengths": {"max": int(lengths[1]), "min": shortest,
                                               "average": float(lengths[3])},
                "witnessed": {name: hit for name, (hit, _) in sorted(counts.items())}}
    if case.expected == "ok":
        if returncode != 0 or "[ok] No violation found" not in log \
                or terminals(log) != ["Model checking completed. No error has been found."]:
            raise RuntimeError(f"{case.name}: expected a completed check without violation (exit {returncode})")
    else:
        want = "Error: Invariant q_inv is violated." if case.invariant else \
            "Error: Temporal property q_temporalProps was violated."
        if returncode == 0 or "[violation] Found an issue" not in log or terminals(log) != [want]:
            raise RuntimeError(f"{case.name}: expected {want!r} (exit {returncode})")
    states = re.findall(r"(\d+) states generated, (\d+) distinct states found, (\d+) states left on queue", log)
    depth = re.findall(r"The depth of the complete state graph search is (\d+)", log)
    if not states or int(states[-1][1]) == 0:
        raise RuntimeError(f"{case.name}: TLC reports no explored state")
    facts = {"states": [int(value) for value in states[-1]], "depth": int(depth[-1]) if depth else None}
    if case.expected == "ok" and facts["states"][2] != 0:
        raise RuntimeError(f"{case.name}: the search stopped with {facts['states'][2]} states left on its queue")
    if case.recipe and case.expected == "ok" and facts["depth"] != len(case.recipe) + 1:
        raise RuntimeError(f"{case.name}: recipe stopped before its final action")
    if case.depth is not None and case.expected == "ok" and facts["depth"] != case.depth:
        raise RuntimeError(f"{case.name}: the search reached depth {facts['depth']}, not {case.depth}")
    if case.expected == "violation":
        facts["trace"] = len(blocks(log))
        if facts["trace"] < 2:
            raise RuntimeError(f"{case.name}: the violation holds in the initial state")
        # A temporal violation's loop repeats state labels, so the order rule covers invariant violations. The order
        # rule reads each `State ` header whose label matches `[^\s:]+` before `: `, the headers `blocks` splits on
        # among them, so a label other than an ASCII number breaks the order.
        labels = re.findall(r"(?m)^State ([^\s:]+): ", log)
        ordered = labels == [str(n) for n in range(1, facts["trace"] + 1)]
        if case.invariant and not ordered:
            raise RuntimeError(f"{case.name}: the violation's trace holds {facts['trace']} states labelled {labels}, "
                               f"not states 1 to N in order")
        if case.after is not None:
            bound = constants(case).get("BOUND")
            limit = int(bound) + 1 if bound is not None else facts["trace"]
            if not ordered or not case.after < facts["trace"] <= limit:
                raise RuntimeError(f"{case.name}: the violation's trace holds {facts['trace']} states labelled "
                                   f"{labels}, not states 1 to N in order with {case.after} < N <= {limit}")
        at_recipe_end = case.trace is None and bool(case.mutations and case.recipe)
        required = len(case.recipe) + 1 if at_recipe_end else case.trace
        if required is not None and (facts["trace"] != required or not ordered):
            raise RuntimeError(f"{case.name}: the violation's trace holds {facts['trace']} states, not states 1 to "
                               f"{required} in order" + (", which end at its recipe's last action" if at_recipe_end else ""))
    if case.lasso:
        facts["lasso"] = lasso(log)
    return facts


class Incomplete(RuntimeError):
    """A command stopped before its declared outcome completed."""


def family_constants(case):
    """Return the constants of the case's family: the session model's for session."""
    family = family_checks(case)
    return CONSTANTS if family is None else family.CONSTANTS


def constants(case):
    return {**family_constants(case), **case.settings}


def family_checks(case):
    """Return the module that declares the case's family: `binder_checks` for binder, `tenure_checks` for tenure, `prefix_checks` for prefix, `coverage_checks` for coverage, `capture_checks` for capture, `preserve_checks` for preserve, `suffix_checks` for suffix, `saturation_checks` for saturation, `keyops_checks` for keyops, `fill_checks` for fill, `watchdog_checks` for watchdog, `burst_checks` for burst, `creation_checks` for creation, `standbys_checks` for standbys, `loss_checks` for loss, `join_checks` for join, `detect_route_checks` for
    detect and route, and None for session; any other family raises ValueError."""
    if case.family == "tenure":
        return tenure_checks
    if case.family == "prefix":
        return prefix_checks
    if case.family == "capture":
        return capture_checks
    if case.family == "preserve":
        return preserve_checks
    if case.family == "suffix":
        return suffix_checks
    if case.family == "saturation":
        return saturation_checks
    if case.family == "keyops":
        return keyops_checks
    if case.family == "coverage":
        return coverage_checks
    if case.family == "fill":
        return fill_checks
    if case.family == "watchdog":
        return watchdog_checks
    if case.family == "put":
        return put_checks
    if case.family == "identity":
        return identity_checks
    if case.family == "board":
        return board_checks
    if case.family == "read":
        return read_checks
    if case.family == "burst":
        return burst_checks
    if case.family == "escrow":
        return escrow_checks
    if case.family == "mempool":
        return mempool_checks
    if case.family == "custody":
        return custody_checks
    if case.family == "settle":
        return settle_checks
    if case.family == "episode":
        return episode_checks
    if case.family == "claims":
        return claims_checks
    if case.family == "pool":
        return pool_checks
    if case.family == "gate":
        return gate_checks
    if case.family == "grace":
        return grace_checks
    if case.family == "window":
        return window_checks
    if case.family == "visit":
        return visit_checks
    if case.family == "reclaim":
        return reclaim_checks
    if case.family == "extent":
        return extent_checks
    if case.family == "watermark":
        return watermark_checks
    if case.family == "loss":
        return loss_checks
    if case.family == "lookup":
        return lookup_checks
    if case.family == "allowance":
        return allowance_checks
    if case.family == "report":
        return report_checks
    if case.family == "creation":
        return creation_checks
    if case.family == "standbys":
        return standbys_checks
    if case.family == "parked":
        return parked_checks
    if case.family == "register":
        return register_checks
    if case.family == "marklog":
        return marklog_checks
    if case.family == "join":
        return join_checks
    if case.family == "binder":
        return binder_checks
    if case.family in ("detect", "route"):
        return detect_route_checks
    if case.family == "session":
        return None
    raise ValueError(f"{case.name}: unknown family {case.family}")


def stop_session(leader):
    """Send SIGTERM to every process of `leader`'s session, then SIGKILL to those left after `KILL_GRACE_SECONDS`.

    The loop reaps the leader itself, because a zombie leader keeps its process group present.
    """
    with contextlib.suppress(ProcessLookupError):
        os.killpg(leader, signal.SIGTERM)
        limit = time.monotonic() + KILL_GRACE_SECONDS
        while time.monotonic() < limit:
            with contextlib.suppress(ChildProcessError):
                os.waitpid(leader, os.WNOHANG)
            os.killpg(leader, 0)
            time.sleep(0.05)
        os.killpg(leader, signal.SIGKILL)


def run_bounded(argv, cwd, environment, log_file, seconds):
    """Run `argv` in its own session; return its exit status, or 124 when `seconds` pass first.

    The deadline and a SIGTERM to the runner both stop the whole session, so descendants of the
    command stop with it; a SIGTERM then exits the runner with status 143, and a SIGINT the runner
    would otherwise take as a KeyboardInterrupt exits it with status 130. The handlers are installed
    before the command starts; a signal that arrives while it starts is kept and acted on once the
    session exists.
    """
    expired = threading.Event()
    process, pending = None, None

    def expire(session):
        expired.set()
        stop_session(session.pid)

    def terminated(signum, frame):
        nonlocal pending
        if process is None:
            pending = signum
            return
        stop_session(process.pid)
        raise SystemExit(128 + signum)

    handled = [signal.SIGTERM]
    if signal.getsignal(signal.SIGINT) is signal.default_int_handler:
        handled.append(signal.SIGINT)
    previous = {signum: signal.signal(signum, terminated) for signum in handled}
    try:
        process = subprocess.Popen(argv, cwd=cwd, env=environment, stdout=log_file, stderr=subprocess.STDOUT,
                                   start_new_session=True)
        if pending is not None:
            terminated(pending, None)
        timer = threading.Timer(seconds, expire, [process])
        timer.start()
        try:
            status = process.wait()
        finally:
            timer.cancel()
            timer.join()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return 124 if expired.is_set() else status


def run_case(case, source, output, quint, workers):
    directory = output / case.name
    directory.mkdir()
    texts = inputs(case, source)
    for name, text in texts.items():
        (directory / name).write_text(text)
    (directory / "tlc.json").write_text(json.dumps({"workers": workers}) + "\n")
    port, claim = claim_port() if case.command == "tlc" else (None, contextlib.nullcontext())
    with claim:
        argv = command(case, quint, directory, port)
        environment, cwd = None, directory
        if case.command == "replay":
            (directory / "bin").mkdir()
            (directory / "bin/quint").write_text(shim(quint) if family_checks(case) is None else f'#!/bin/sh\nexec {shlex.quote(quint)} "$@"\n')
            (directory / "bin/quint").chmod(0o755)
            environment = {**os.environ, "PATH": f"{directory / 'bin'}{os.pathsep}{os.environ['PATH']}"}
            environment.pop("TMPDIR", None)
            cwd = source.parent
        started = time.monotonic()
        print(f"RUN  {case.name}", flush=True)
        with (directory / "quint.log").open("w") as log_file:
            returncode = run_bounded(argv, cwd, environment, log_file, case.deadline or CASE_SECONDS)
    if (directory / "_apalache-out").is_dir():
        shutil.rmtree(directory / "_apalache-out")
    if returncode < 0 or returncode in (124, 130, 137, 143):
        raise Incomplete(f"{case.name}: incomplete command exit {returncode}")
    log = (directory / "quint.log").read_text()
    facts = judge(case, log, returncode)
    elapsed = round(time.monotonic() - started, 2)
    print(f"PASS {case.name} ({elapsed}s)", flush=True)
    return {"case": case.name, "command": argv[1:], "expected": case.expected, "returncode": returncode,
            "seconds": elapsed, "port": port, "constants": constants(case), **facts,
            "inputs": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in texts}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", type=Path, required=True, help="the pinned quint executable")
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--case", action="append", dest="selected")
    parser.add_argument("--output", type=Path, help="A new directory for inputs, logs, and results")
    args = parser.parse_args()
    if args.workers < 1:
        parser.error("--workers must be positive")
    selected = list(cases())
    if args.selected:
        unknown = set(args.selected) - {case.name for case in selected}
        if unknown:
            parser.error(f"unknown cases: {sorted(unknown)}")
        selected = [case for case in selected if case.name in args.selected]
    output = args.output or Path(tempfile.mkdtemp(prefix="kestrike-quint-"))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    source = Path(__file__).resolve().parent
    quint = str(args.quint.resolve())
    print(f"Evidence: {output}", flush=True)
    version = subprocess.run([quint, "--version"], text=True, stdout=subprocess.PIPE, check=True).stdout.strip()
    runtime = subprocess.run(["java", "-version"], text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=True).stdout
    revision = subprocess.run(["git", "-C", str(source), "rev-parse", "HEAD"], text=True,
                              stdout=subprocess.PIPE, check=False).stdout.strip()
    dirty = subprocess.run(["git", "-C", str(source), "status", "--porcelain", "--untracked-files=no"], text=True,
                           stdout=subprocess.PIPE, check=False).stdout.splitlines()
    record = {"date": datetime.now(timezone.utc).isoformat(), "revision": revision, "dirty": dirty, "quint": version,
              "runtime": runtime, "results": [], "complete": False, "failure": None,
              "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}}
    try:
        for case in selected:
            try:
                record["results"].append(run_case(case, source, output, quint, args.workers))
            except SystemExit as error:
                record["failure"] = {"case": case.name, "reason": f"{case.name}: the runner stopped on a signal (exit {error.code})"}
                raise
            except Exception as error:
                record["failure"] = {"case": case.name, "reason": str(error)}
                raise
        record["complete"] = True
    finally:
        (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"All {len(selected)} expected outcomes verified.", flush=True)


if __name__ == "__main__":
    try:
        main()
    except Incomplete:
        raise SystemExit(124) from None
