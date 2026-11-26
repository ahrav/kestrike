"""Standby-census model traces for the replay against `Reconciler`: directed recipes and seeded runs of `step`.

Each trace is one `quint run --mbt` of `standbys.qnt` in one instance of `standbys_check.py`. A directed trace follows
the recipe of one run or recipe case of that script, or of one `REPLAY_RECIPES` entry of this file, in that recipe's
instance; a seeded trace takes `steps` steps of the model's own `step` under the seed its name carries, in the instance
`SEEDED` assigns to that seed. Every trace records under `#meta.standbys` the model's digest, its instance's settings
and limits, and its recipe or seed, and the Rust replay refuses a trace whose digest differs from the model's.
Generation refuses a trace whose states equal another trace's.

    python3 quint/standbys_fixtures.py --quint QUINT --output DIRECTORY [--jobs N] [--timeout SECONDS]

DIRECTORY must be new or empty. Each trace's Quint inputs stay in a working directory of its own beside the trace,
and only the top-level `*.itf.json` files belong in `crates/kestrike/src/failover/standbys_replay_fixtures`.
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
_spec = importlib.util.spec_from_file_location("standbys_check", SOURCE / "standbys_check.py")
if _spec is None or _spec.loader is None:
    raise RuntimeError("cannot load standbys_check.py")
standbys_check = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(standbys_check)

FIXTURES = "crates/kestrike/src/failover/standbys_replay_fixtures"
# `SEEDED` maps instance names to `(settings, seeds, step count)`. Seeds 0x5b03, 0x5b33 and 0x5b34 draw the traces of
# 0x5b00, 0x5b30 and 0x5b31, which generation refuses as equal, so S2 and S3 each take the next seeds past their range.
SEEDED = {"S2": ({}, (*range(0x5b00, 0x5b03), *range(0x5b04, 0x5b11)), 24),
          "S2H": (standbys_check.S2H, tuple(range(0x5b20, 0x5b28)), 24),
          "S3": (standbys_check.S3, (0x5b30, 0x5b31, 0x5b32, *range(0x5b35, 0x5b3a)), 24)}
# `--timeout` defaults to `TIMEOUT` seconds per `quint run`.
TIMEOUT = 300


def limits(settings):
    """The constants of the instance `settings` overrides that the replay reads from no state: the census cap and the
    host attachment limit."""
    constants = {**standbys_check.CONSTANTS, **settings}
    return {"cap": int(constants["CAP"]), "attach": int(constants["ATTACH"])}


_op, _reserve = standbys_check.op, standbys_check.reserve


def _record(r, s, h):
    """An attach record that ends in its last shard read."""
    return _op(r, "record", s, h, 3)


def _enroll(r, s, h):
    """An enrollment that ends in its last shard read."""
    return _op(r, "enroll", s, h, 3)


_ENDS = ["endRead(1, 3)", "endWrite(1, 3)"]
REPLAY_RECIPES = {
    "replay_designationStale": (standbys_check.DESIGNATED + ["takeover(1)"] + _op(0, "designate", 1, 2, 1), {}),
    "replay_designationAsIs": (standbys_check.DESIGNATED + _op(0, "designate", 1, 2, 2), {}),
    "replay_designationUnenrolled": (_reserve(0, 2, 1) + _op(0, "designate", 2, 1, 2), {}),
    "replay_reservationExcluded": (standbys_check.STORM_FREED + _reserve(0, 2, 2) + ['begin(0, "reserve", 3, 2)'],
                                   standbys_check.S3),
    "replay_recordUnknownCommitted": (_reserve(0, 1, 3) + _op(0, "record", 1, 3, 1) + ['unknown(0, "commit")'],
                                      standbys_check.S2E),
    "replay_recordHeldDelivered": (_reserve(0, 1, 3) + _op(0, "record", 1, 3, 1) + ['unknown(0, "hold")', "deliver"],
                                   standbys_check.S2E),
    "replay_enrollUnknownLost": (_reserve(0, 1, 3) + _record(0, 1, 3) + ["attachEnds(1, 3, true)"]
                                 + _op(0, "enroll", 1, 3, 1) + ['unknown(0, "lost")'], standbys_check.S2E),
    "replay_enrollConditionLost": (_reserve(0, 1, 3) + _record(0, 1, 3)
                                   + ["attachEnds(1, 3, true)", 'begin(0, "enroll", 1, 3)', 'begin(1, "enroll", 1, 3)',
                                      "request(0)", "request(1)", "request(0)", "request(1)"], standbys_check.S2E),
    "replay_releaseAbsent": (_op(0, "release", 1, 1, 0), {}),
    "replay_occupiedRefusesHeadroom": (["occupy(3)"] + _op(0, "reserve", 1, 3, 2), standbys_check.S2H),
    "replay_releaseKeptStandby": (standbys_check.DESIGNATED + ["bump(1)", "suspect(1, 2)"]
                                  + _op(1, "release", 1, 1, 2), {}),
    "replay_designationStaleByAttempt": (standbys_check.RESERVED + ["bump(1)"] + _op(0, "designate", 1, 2, 1), {}),
    "replay_designationStaleByGeneration": (standbys_check.DESIGNATED + ['begin(0, "designate", 1, 2)', "takeover(1)",
                                                                       "flip(1, 1)", "fresh(1)", "request(0)"], {}),
    "replay_reserveIneligibleUnacquired": (["flip(1, 3)"] + _op(0, "reserve", 1, 2, 2), {}),
    "replay_releaseHeldDelivered": (standbys_check.RESERVED + ["bump(1)", "lose(2)", "learn(1, 2)"]
                                    + _op(1, "release", 1, 1, 2) + ['unknown(1, "hold")', "deliver"], {}),
    "replay_endRecordedAttach": (_reserve(0, 1, 3) + _record(0, 1, 3) + _ENDS, standbys_check.S2E),
    "replay_endEnrolledAttach": (_reserve(0, 1, 3) + _record(0, 1, 3) + ["attachEnds(1, 3, true)"]
                                 + _enroll(0, 1, 3) + _ENDS, standbys_check.S2E),
    "replay_endFailedAttach": (_reserve(0, 1, 3) + _record(0, 1, 3) + ["attachEnds(1, 3, false)"] + _ENDS,
                               standbys_check.S2E),
}
LEFT_OUT = {"run_renewedEntryKeptWhileRecording": "its release keeps the entry under the loop's stuck bound, which "
                                                  "`Census::released` does not apply"}


def directed():
    """Every run and recipe case of `standbys_check.py` but those `LEFT_OUT` names, and the `REPLAY_RECIPES`, which
    reach results and faults no run reaches: each one's name, recipe and instance settings."""
    standbys_check.single_instances()
    rows = {f"run_{name}": (recipe, instance) for name, (recipe, _, _, *instance) in standbys_check.RUNS.items()}
    rows.update({f"recipe_{name}": (recipe, instance) for name, (recipe, _, *instance) in
                 standbys_check.RECIPES.items()})
    rows = {name: (recipe, instance[0] if instance else {}) for name, (recipe, instance) in rows.items()
            if name not in LEFT_OUT}
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


def run(quint, directory, steps, seed, instance, recipe, model, timeout):
    """Write one trace of `steps` steps in the instance `instance` overrides into the new directory `directory` and
    return it; a recipe restricts the scheduler to its schedule. The model copy Quint runs must have the SHA-256
    `model`, and `timeout` bounds the run in seconds, or None for no bound."""
    settings = {**instance, "BOUND": str(steps)}
    # `standbys_check.inputs` writes the whole model text for `typecheck` and `replay` and a pruned copy otherwise;
    # the trace records the digest of the whole text.
    case = SimpleNamespace(name=directory.name, command="typecheck", mutations=[], extra="", recipe=recipe,
                           settings=settings)
    directory.mkdir(parents=True)
    for filename, text in standbys_check.inputs(case, SOURCE).items():
        (directory / filename).write_text(text)
    if hashlib.sha256((directory / "standbys.qnt").read_bytes()).hexdigest() != model:
        raise ValueError(f"{directory.name}: the model copy differs from the model whose digest the trace records")
    raw = directory / "quint.itf.json"
    step = ["--step", "recipe"] if recipe else []
    subprocess.run([quint, "run", "case.qnt", "--main", "standbysCase", *step, "--backend", "typescript", "--mbt",
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
    return data


def fixtures():
    """Each committed trace: its model and the instance, seed, step count and, for a directed trace, the recipe it
    records under `#meta.standbys`."""
    declared = {name: {"settings": instance, "limits": limits(instance), "seed": hex(0x5af0), "steps": len(recipe),
                       "recipe": recipe} for name, (recipe, instance) in directed().items()}
    for instance, seeds, steps in SEEDED.values():
        declared.update({f"step_{seed:x}": {"settings": instance, "limits": limits(instance), "seed": hex(seed),
                                            "steps": steps} for seed in seeds})
    return {name: ("standbys.qnt", metadata) for name, metadata in declared.items()}


def generate(quint, output, jobs=1, timeout=None):
    """Write every trace `fixtures` declares into `output`, `jobs` Quint runs at a time, each bounded by `timeout`
    seconds or by none for None. Each trace is written in its working directory and then renamed over its name in
    `output`."""
    quint = executable(quint)
    declared = fixtures()
    models = {model: (SOURCE / model).read_bytes() for model, _ in declared.values()}
    digests = {model: hashlib.sha256(text).hexdigest() for model, text in models.items()}

    def one(name):
        model, metadata = declared[name]
        directory = output / name
        data = run(quint, directory, metadata["steps"], int(metadata["seed"], 16), metadata["settings"],
                   metadata.get("recipe"), digests[model], timeout)
        data["#meta"] = {"format": data["#meta"]["format"], "standbys": {"model_sha256": digests[model], **metadata}}
        written = directory / (name + ".itf.json")
        written.write_text(json.dumps(data, separators=(",", ":")) + "\n")
        os.replace(written, output / (name + ".itf.json"))
        return name, json.dumps(data["states"], sort_keys=True)

    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        states = dict(pool.map(one, declared))
    seen = {}
    for name, text in states.items():
        if text in seen:
            raise ValueError(f"{name}: its states equal those of {seen[text]}")
        seen[text] = name


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--quint", required=True, help="the Quint executable: a path, or a name on PATH")
    parser.add_argument("--output", type=Path, required=True,
                        help="a new or empty directory; each trace's working directory stays beside it")
    parser.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1), help="Quint runs at a time")
    parser.add_argument("--timeout", type=int, default=TIMEOUT,
                        help="seconds one Quint run may take; 0 sets no bound, for a caller that bounds the whole run")
    args = parser.parse_args()
    if args.jobs < 1 or args.timeout < 0:
        parser.error("--jobs must be positive and --timeout must not be negative")
    generate(args.quint, args.output.resolve(), args.jobs, args.timeout or None)
