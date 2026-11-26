"""Volume-loss model traces for the replay against `Reconciler`: directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `loss.qnt`. A directed trace follows the recipe of one directed run of
`loss_check.py` or of one `REPLAY_RECIPES` entry of this file; a seeded trace follows the prefix of one root of
`loss_check.py` and then takes `FREE` steps of the model's own `step` under the seed its name carries. Every trace
records under `#meta.loss` the model's digest and its recipe, or its root, the root's prefix and its seed, and the Rust
replay refuses a trace whose digest differs from the model's. Generation refuses a trace whose states equal another
trace's, and a trace that holds an interleaving `left_out` names: one in which a store write the production code makes
and the model leaves out changes what a later step of the model reads.

    python3 quint/loss_fixtures.py --quint QUINT --output DIRECTORY [--jobs N] [--timeout SECONDS]

Generation refuses a DIRECTORY that holds any entry. Each trace's Quint inputs stay in a working directory of its own
beside the trace, and only the top-level `*.itf.json` files belong in
`crates/kestrike/src/failover/loss_replay_fixtures`.
"""

import argparse
import concurrent.futures
import hashlib
import importlib.util
import json
import os
import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace

SOURCE = Path(__file__).resolve().parent
_spec = importlib.util.spec_from_file_location("loss_check", SOURCE / "loss_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load loss_check.py")
loss_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(loss_check)

FIXTURES = "crates/kestrike/src/failover/loss_replay_fixtures"
# `SEEDED` maps `loss_check.ROOTS` keys to trace seeds. Each trace follows its root's prefix, then takes `FREE` steps
# of the model's `step`.
SEEDED = {root: tuple(range(0x7900, 0x7904)) for root in loss_check.ROOTS}
FREE = 20
# `--timeout` defaults to `TIMEOUT` seconds per `quint run`.
TIMEOUT = 300

_op = loss_check.op
_CREATED, _ISSUED, _OPENED = loss_check.CREATED, loss_check.ISSUED, loss_check.OPENED
REPLAY_RECIPES = {
    "replay_absentBeforeLoss": (_op(1, "replacement", 1, 1) + _op(2, "create", 1, 1) + _op(0, "release", 1, 1)
                                + _op(1, "abandon", 1, 1)),
    "replay_hostsLost": (["hostLoss(1)", "hostLoss(2)", "impair(1)", "recover(1)"] + _op(1, "replacement", 1, 1)
                         + _op(2, "create", 1, 1) + _op(1, "abandon", 1, 1)),
    "replay_startRacesStart": (["lose(1)", 'begin(1, "replacement", 1)', 'begin(2, "replacement", 1)', "request(1)",
                                "request(1)", "request(2)", "request(2)", "request(1)", "request(2)"]),
    "replay_latchAndRelease": (_OPENED + _op(2, "replacement", 1, 2) + ["impair(2)"] + _op(2, "replacement", 1, 3)
                               + _op(0, "release", 1, 2) + _op(0, "release", 1, 1)),
    "replay_unknownStart": ["lose(1)"] + _op(1, "replacement", 1, 2) + ["unknown(1)"] + _op(2, "replacement", 1, 2),
    "replay_unknownCreates": (_OPENED + _op(1, "create", 1, 2) + ["unknown(1)"] + _op(2, "create", 1, 2)
                              + ['call(2, "drop", false)'] + _op(1, "create", 1, 2) + ['call(1, "make", false)']
                              + _op(2, "create", 1, 2) + ['call(2, "make", false)'] + _op(1, "create", 1, 2)
                              + ['call(1, "make", true)', "unknown(1)"] + _op(2, "create", 1, 2)
                              + ['call(2, "make", true)', "request(2)", "request(2)", "request(2)"]),
    "replay_keptRefusal": (_ISSUED + _op(2, "create", 1, 2) + ['call(1, "fail", true)', "request(1)",
                                                               'call(2, "make", true)', "request(2)"]),
    "replay_createLatches": _OPENED + ["impair(2)"] + _op(2, "create", 1, 2) + _op(1, "create", 1, 1),
    "replay_createdThenPast": (_CREATED + _op(2, "create", 1, 2) + loss_check.FLIP + _op(2, "create", 1, 2)
                               + _op(2, "replacement", 1, 1) + ["lose(3)"] + _op(2, "abandon", 1, 3)
                               + _op(2, "flip", 1, 1)),
    "replay_abandonReplayed": _CREATED + ["lose(3)"] + _op(1, "abandon", 1, 4) + _op(2, "abandon", 1, 5) + ["request(1)"],
    "replay_abandonHeld": (_CREATED + ["lose(3)"] + _op(1, "abandon", 1, 4) + ["impair(2)"] + _op(2, "create", 1, 2)
                           + ["request(1)"]),
    "replay_abandonOpensHeld": _CREATED + ["lose(3)", "impair(2)"] + _op(1, "abandon", 1, 7) + _op(0, "release", 1, 2),
    "replay_fenceRefusesRetire": loss_check.RACING + ["request(2)"] * 4 + ["request(1)", "request(2)", "request(2)"],
    "replay_abandonNamedSpare": loss_check.FENCED + _op(2, "abandon", 1, 3) + ["request(1)", "request(1)"],
    "replay_duelingFlips": loss_check.DUELING + ["request(1)", "request(2)"],
    "replay_flipRefusesHeld": loss_check.COVERED + _op(1, "flip", 1, 3),
    "replay_flipOfRetired": loss_check.FAILED + ["request(1)"] + _op(2, "flip", 1, 2) + ["request(1)"] * 3,
    "replay_retiredFlipPast": (loss_check.FAILED + ["request(1)"] + _op(2, "flip", 1, 0) + ["request(1)"] * 3
                               + _op(1, "create", 1, 3) + ['call(1, "make", true)', "request(1)", "request(1)"]
                               + loss_check.FLIP + ["request(2)"]),
    "replay_spareOfRetired": _CREATED + _op(1, "flip", 1, 1) + ["lose(3)"] + _op(2, "abandon", 1, 4) + ["request(1)"],
    "replay_raiseOverReleased": loss_check.RELEASED + _op(1, "create", 1, 3) + ['call(1, "fail", true)', "request(1)"],
    "replay_abandonStale": (_CREATED + ["lose(3)"] + _op(1, "abandon", 1, 4) + ["impair(2)"] + _op(2, "create", 1, 2)
                            + _op(0, "release", 1, 2) + ["request(1)"]),
    "replay_refusalUnknown": (_ISSUED + ['call(1, "fail", false)'] + _op(2, "create", 1, 2)
                              + ['call(2, "make", false)'] + _op(1, "create", 1, 2) + ['call(1, "make", true)', "request(1)"]),
    "replay_unknownFlips": (_CREATED + _op(1, "flip", 1, 3) + ["unknown(1)"] + _op(2, "flip", 1, 4) + ["unknown(2)"]
                            + _op(1, "flip", 1, 6) + ["unknown(1)"]),
    "replay_flipHeldAtRecheck": (_CREATED + _op(1, "flip", 1, 7) + ["impair(2)"] + _op(2, "create", 1, 2)
                                 + ["request(1)"]),
    "replay_rereadFindsRecorded": (_ISSUED + _op(2, "create", 1, 2) + ['call(1, "make", true)', "request(1)", "request(1)",
                                                                     "lose(3)"]
                                   + _op(1, "abandon", 1, 4) + ['call(2, "make", true)'] + ["request(2)"] * 3
                                   + ["request(1)"] * 3),
    "replay_flipPastAtReread": _CREATED + _op(1, "flip", 1, 4) + _op(2, "flip", 1, 7) + ["request(1)"],
    "replay_spareAndFenceRefused": (_CREATED + _op(1, "flip", 1, 3) + _op(2, "flip", 1, 3) + ["request(1)", "request(2)"]
                                    + ["request(1)"] * 2 + _op(2, "flip", 1, 4) + ["request(1)", "request(2)"]),
    "replay_shardTwoCreates": (_CREATED + ["lose(2)"] + _op(2, "replacement", 2, 3) + _op(0, "release", 2, 2)
                               + _op(2, "create", 2, 3) + ['call(2, "make", true)', "request(2)", "request(2)"]),
    "replay_issueRefused": _OPENED + _op(1, "create", 1, 2) + _op(2, "create", 1, 2) + ["request(1)", "request(2)"],
    "replay_holdRefused": (_OPENED + ["impair(2)"] + _op(1, "create", 1, 1) + _op(2, "create", 1, 1)
                           + ["request(1)", "request(2)"]),
    "replay_latchRefused": (_OPENED + ["impair(2)"] + _op(1, "replacement", 1, 2) + _op(2, "replacement", 1, 2)
                            + ["request(1)", "request(2)"]),
    "replay_latchUnknown": _OPENED + ["impair(2)"] + _op(2, "replacement", 1, 2) + ["unknown(2)"],
    "replay_raiseRefused": (_CREATED + ["lose(3)"] + _op(1, "abandon", 1, 6) + _op(2, "abandon", 1, 4)
                            + ["request(1)", "request(2)"]),
    "replay_crashedStarts": (["lose(1)", 'begin(1, "replacement", 1)', "crash(1)"] + _op(1, "replacement", 1, 1)
                             + ["crash(1)"] + _op(1, "replacement", 1, 2) + ["crash(1)", "impair(2)"]
                             + _op(1, "replacement", 1, 3) + ['begin(0, "release", 1)', "crash(0)"]
                             + _op(0, "release", 1, 1) + ["crash(0)"] + _op(0, "release", 1, 1)
                             + ["unknown(0)", 'begin(1, "create", 1)', "crash(1)"] + _op(1, "create", 1, 1)
                             + ["crash(1)"]),
    "replay_crashedCreates": (_OPENED + ["impair(2)"] + _op(1, "create", 1, 1) + ["crash(1)", "recover(2)"]
                              + _op(1, "create", 1, 3) + ['call(1, "fail", true)', "unknown(1)"]),
    "replay_crashedAbandons": (_CREATED + ["lose(3)", 'begin(1, "abandon", 1)', "crash(1)"] + _op(1, "abandon", 1, 3)
                               + ["crash(1)"] + _op(1, "abandon", 1, 3) + ["unknown(1)"] + _op(1, "abandon", 1, 2)
                               + ["crash(1)"] + _op(1, "abandon", 1, 4) + ["crash(1)"]),
    "replay_crashedFlips": (_CREATED + ['begin(1, "flip", 1)', "crash(1)"] + _op(1, "flip", 1, 3) + ["crash(1)"]
                            + _op(1, "flip", 1, 4) + ["crash(1)"] + _op(1, "flip", 1, 3) + ["crash(1)"]
                            + _op(1, "flip", 1, 5) + ["crash(1)"] + _op(1, "flip", 1, 6) + ["crash(1)"]),
    "replay_impairedRetained": ["impair(1)"] + _op(1, "replacement", 1, 1),
    "replay_releasedNotLatched": loss_check.RELEASED + _op(1, "replacement", 1, 2),
    "replay_heldStaysWhenIsolated": (loss_check.HELD + ["recover(2)"] + _op(1, "replacement", 1, 2)
                                     + _op(1, "create", 1, 1)),
    "replay_settleKeepsSpare": (_CREATED + ["lose(3)"] + _op(1, "abandon", 1, 1) + _op(2, "abandon", 1, 7)
                                + _op(2, "create", 1, 3) + ['call(2, "make", true)', "request(2)", "request(2)"]
                                + _op(2, "flip", 1, 4) + ["request(1)"] * 2),
    "replay_abandonStaleAfterTwoRaises": (_CREATED + ["lose(3)"] + _op(1, "abandon", 1, 1) + _op(2, "abandon", 1, 7)
                                          + _op(2, "create", 1, 3)
                                          + ['call(2, "make", true)', "request(2)", "request(2)", "lose(4)"]
                                          + _op(2, "abandon", 1, 7) + ["request(1)"] * 2),
    "replay_unknownReceiptWrites": (_OPENED + ["impair(2)"] + _op(1, "create", 1, 1) + ["unknown(1)"]
                                    + _op(0, "release", 1, 2) + ["recover(2)"] + _op(1, "create", 1, 3)
                                    + ['call(1, "make", true)', "request(1)", "unknown(1)"] + _op(2, "create", 1, 2)
                                    + ["lose(3)"] + _op(1, "abandon", 1, 6) + ["unknown(1)"]),
}


def plain(value):
    """`value` with every ITF big integer, map, set and tuple as a Python int, dict, tuple and tuple."""
    if isinstance(value, dict):
        if set(value) == {"#bigint"}:
            return int(value["#bigint"])
        if set(value) == {"#map"}:
            return {plain(key): plain(held) for key, held in value["#map"]}
        if set(value) == {"#set"}:
            return tuple(plain(member) for member in value["#set"])
        if set(value) == {"#tup"}:
            return tuple(plain(member) for member in value["#tup"])
        return {key: plain(held) for key, held in value.items()}
    if isinstance(value, list):
        return tuple(plain(member) for member in value)
    return value


PROVISIONED, RETIRED = 1, 3


def left_out(states):
    """The reason the replay leaves out the trace `states`, as `plain` returns them, or None.

    The production code makes three store writes the model leaves out: the caller's `record_attach`, after a create
    returns its volume and at the start of a flip, writes the volume record when the record is provisioned and holds
    no attach event; and `retire`'s settling write of the shard record, conditioned on its shard read, follows its
    retired-state write and follows a volume read that finds the volume retired. A trace is left out where such a
    write changes what a later model step reads: an attach write while an abandon of that volume holds its volume
    read and that abandon then sends a retirement write the model commits, a create's provision read of a provisioned volume whose attach is written, a retirement whose settling
    write fails because a shard write committed since its shard read, a settling write that clears the retired
    volume from the spare slot, and a settling write followed by a shard write of a flip of that shard that read the
    shard record before it."""
    attached = set()
    named = {}
    settled = {}
    for at in range(1, len(states)):
        pre, post = states[at - 1][STATE], states[at][STATE]
        ev = post["ev"]
        p, act, op, pc = ev["proc"], ev["act"], ev["op"], ev["pc"]
        before = pre["procs"][p]
        reason = _attach_reason(states, at, attached) or _provision_reason(pre, ev, at, attached)
        if reason:
            return reason
        shard = ev["shard"]
        if act == "read" and op == "abandon" and pc == "named":
            named[p] = pre["shards"][shard]["ver"] + settled.get(shard, 0)
        if not _settles(pre, ev):
            continue
        if pc == "retire" and pre["shards"][shard]["ver"] + settled.get(shard, 0) != named.get(p):
            return f"state {at}: a shard write precedes the settling write of process {p}"
        if pre["shards"][shard]["spare"] == before["vol"]:
            return f"state {at}: the settling write of process {p} clears the spare it retired"
        reason = _flip_reason(states, at, p, shard)
        if reason:
            return reason
        settled[shard] = settled.get(shard, 0) + 1
    return None


STATE = "lossCase::loss::st"


def _attach_reason(states, at, attached):
    """Adds to `attached` the volume whose attach write the step at `at` makes, and names an abandon of it that holds
    its volume read and then sends a retirement write the model commits."""
    pre, post = states[at - 1][STATE], states[at][STATE]
    ev = post["ev"]
    p, act, op, pc, res = ev["proc"], ev["act"], ev["op"], ev["pc"], ev["res"]
    before = pre["procs"][p]
    attach = None
    if act == "begin" and op == "flip":
        attach = post["procs"][p]["vol"]
    elif act == "write" and op == "create" and pc == "record" and res == "record":
        attach = before["vol"]
    elif act == "read" and op == "create" and pc == "shard" and res == "created":
        attach = before["rc"]["vol"]
    elif act == "read" and op == "create" and pc == "reread" and res == "created":
        attach = before["vol"]
    if attach is None or attach in attached or post["vrecs"][attach]["state"] != PROVISIONED:
        return None
    attached.add(attach)
    for q, proc in pre["procs"].items():
        if q != p and proc["op"] == "abandon" and proc["vol"] == attach and proc["pc"] in ("named", "retire") \
                and _retires(states, at, q):
            return f"state {at}: the attach of volume {attach} precedes the retirement write of process {q}"
    return None


def _retires(states, at, q):
    """Whether process `q`, after the step at `at` and before it leaves its abandon, sends a retirement write that
    commits in the model: a write the model's condition admits, or a write with a lost reply that changes the volume
    record."""
    for index in range(at + 1, len(states)):
        before, after = states[index - 1][STATE], states[index][STATE]
        ev = after["ev"]
        if ev["proc"] == q and ev["pc"] == "retire" and ev["act"] == "write":
            return ev["res"] != "condition"
        if ev["proc"] == q and ev["pc"] == "retire" and ev["act"] == "unknown":
            vol = before["procs"][q]["vol"]
            return after["vrecs"][vol] != before["vrecs"][vol]
        if after["procs"][q]["op"] != "abandon":
            return False
    return False


def _provision_reason(pre, ev, at, attached):
    """Names a create's provision read, at `at`, of a provisioned volume in `attached`."""
    vol = pre["procs"][ev["proc"]]["vol"]
    if (ev["act"], ev["op"], ev["pc"]) == ("read", "create", "provRead") and vol in attached and \
            pre["vrecs"][vol]["state"] == PROVISIONED:
        return f"state {at}: a provision read of volume {vol}, whose attach is written"
    return None


def _settles(pre, ev):
    """Whether the step of `ev` makes `retire`'s settling write: a committed retired-state write, or an abandon's
    volume read that finds the volume retired."""
    act, op, pc = ev["act"], ev["op"], ev["pc"]
    vol = pre["procs"][ev["proc"]]["vol"]
    return (act, op, pc, ev["res"]) == ("write", "abandon", "retire", "ok") or (
        (act, op, pc) == ("read", "abandon", "volume") and pre["vrecs"][vol]["state"] == RETIRED)


def _flip_reason(states, at, p, shard):
    """Names a flip of `shard` that read the shard record before the settling write at `at` and writes the shard
    record after it, before its own reread."""
    for q, proc in states[at - 1][STATE]["procs"].items():
        if q == p or proc["op"] != "flip" or proc["shard"] != shard or proc["pc"] in ("shard", "reread"):
            continue
        for later in states[at + 1:]:
            after = later[STATE]
            mine = after["ev"]["proc"] == q
            if mine and after["ev"]["act"] in ("write", "unknown") and after["ev"]["pc"] in ("spare", "flip"):
                return f"state {at}: the settling write of process {p} precedes a shard write of process {q}"
            if (mine and (after["ev"]["act"], after["ev"]["pc"]) == ("read", "reread")) or \
                    after["procs"][q]["op"] != "flip":
                break
    return None


def directed():
    """Every directed run of `loss_check.py` and the `REPLAY_RECIPES`, which reach results and faults no run reaches:
    each one's name and recipe."""
    rows = {f"run_{name.removeprefix('loss-run-').replace('-', '_')}": recipe
            for name, (recipe, _) in loss_check.RUNS.items()}
    rows.update(REPLAY_RECIPES)
    return rows


def executable(quint):
    """The absolute path of the Quint executable `quint` names: a path with a slash from the caller's directory, or a
    bare name on `PATH`."""
    if os.sep in quint:
        return str(Path(quint).resolve())
    found = shutil.which(quint)
    if found is None:
        raise ValueError(f"{quint}: no executable of that name on PATH")
    return os.path.abspath(found)


def run(quint, directory, steps, seed, recipe, root, model, timeout):
    """Write one trace of `steps` steps into the new directory `directory` and return it. A recipe restricts the
    scheduler to its schedule; a root takes its prefix and then free steps of the model's `step`. The model copy Quint
    runs must have the SHA-256 `model`, and `timeout` bounds the run in seconds, or None for no bound."""
    extra = loss_check.rooted(loss_check.ROOTS[root][0]) if root is not None else ""
    case = SimpleNamespace(name=directory.name, mutations=[], extra=extra, recipe=recipe, settings={"BOUND": str(steps)})
    directory.mkdir(parents=True)
    for filename, text in loss_check.inputs(case, SOURCE).items():
        (directory / filename).write_text(text)
    if hashlib.sha256((directory / "loss.qnt").read_bytes()).hexdigest() != model:
        raise ValueError(f"{directory.name}: the model copy differs from the model whose digest the trace records")
    raw = directory / "quint.itf.json"
    step = ["--step", "recipe"] if recipe else ["--step", "rooted"] if root is not None else []
    subprocess.run([quint, "run", "case.qnt", "--main", "lossCase", *step, "--backend", "typescript", "--mbt",
                    "--invariant", "safety", "--seed", hex(seed), "--max-samples", "1", "--max-steps", str(steps),
                    "--n-traces", "1", "--out-itf", str(raw)], cwd=directory, check=True, timeout=timeout,
                   stdout=subprocess.DEVNULL)
    try:
        data = json.loads(raw.read_text())
        if not isinstance(data["#meta"]["format"], str):
            raise ValueError("the ITF format is not a string")
        states = data["states"]
        if not isinstance(states, list) or not all(isinstance(state, dict) for state in states):
            raise ValueError("the states are not a list of objects")
    except (OSError, ValueError, KeyError, TypeError, RecursionError) as error:
        raise ValueError(f"{directory.name}: Quint wrote no readable trace: {error}") from error
    if len(states) != steps + 1:
        raise ValueError(f"{directory.name}: the trace stopped before its final action")
    try:
        reason = left_out([plain(state) for state in states])
    except (KeyError, TypeError, ValueError, IndexError, AttributeError, RecursionError) as error:
        raise ValueError(f"{directory.name}: the trace holds no loss state: {error!r}") from error
    if reason is not None:
        raise ValueError(f"{directory.name}: the replay leaves this trace out: {reason}")
    return data


def fixtures():
    """Each committed trace: its model and the seed and step count it records under `#meta.loss`, with the recipe of a
    directed trace, or the root and the root's prefix of a seeded trace."""
    declared = {name: {"seed": hex(0x79f0), "steps": len(recipe), "recipe": recipe}
                for name, recipe in directed().items()}
    declared.update({f"step_{root}_{seed:x}": {"root": root, "prefix": list(loss_check.ROOTS[root][0]),
                                               "seed": hex(seed), "steps": len(loss_check.ROOTS[root][0]) + FREE}
                     for root, seeds in SEEDED.items() for seed in seeds})
    return {name: ("loss.qnt", metadata) for name, metadata in declared.items()}


def generate(quint, output, jobs=1, timeout=None):
    """Write every trace `fixtures` declares into `output`, a new or empty directory, `jobs` Quint runs at a time,
    each bounded by `timeout` seconds or by none for None. Each trace runs in a working directory of its own under
    `output`, and the traces are renamed into `output` once every run has passed and no two hold equal states."""
    quint = executable(quint)
    output = Path(output).resolve()
    if output.exists() and any(output.iterdir()):
        raise ValueError(f"{output}: the output directory holds entries")
    declared = fixtures()
    digests = {model: hashlib.sha256((SOURCE / model).read_bytes()).hexdigest()
               for model in {model for model, _ in declared.values()}}

    def one(name):
        model, metadata = declared[name]
        data = run(quint, output / name, metadata["steps"], int(metadata["seed"], 16), metadata.get("recipe"),
                   metadata.get("root"), digests[model], timeout)
        data["#meta"] = {"format": data["#meta"]["format"], "loss": {"model_sha256": digests[model], **metadata}}
        return name, data

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        traces = dict(pool.map(one, declared))
    seen = {}
    for name, data in traces.items():
        text = json.dumps(data["states"], sort_keys=True)
        if text in seen:
            raise ValueError(f"{name}: its states equal those of {seen[text]}")
        seen[text] = name
    for name, data in traces.items():
        written = output / name / (name + ".itf.json")
        written.write_text(json.dumps(data, separators=(",", ":")) + "\n")
        os.replace(written, output / (name + ".itf.json"))


def main(argv=None):
    """Parse the command line `argv`, or `sys.argv` for None, and generate the traces it names."""
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--quint", required=True, help="the Quint executable: a path, or a name on PATH")
    parser.add_argument("--output", type=Path, required=True,
                        help="a new or empty directory; each trace's working directory stays beside it")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="Quint runs at a time")
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help="seconds one Quint run may take; 0 sets no bound, for a caller that bounds the whole run")
    args = parser.parse_args(argv)
    if args.jobs < 1 or args.timeout < 0:
        parser.error("--jobs must be positive and --timeout must not be negative")
    generate(args.quint, args.output.resolve(), args.jobs, args.timeout or None)


if __name__ == "__main__":
    main()
