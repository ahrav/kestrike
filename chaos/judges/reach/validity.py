#!/usr/bin/env python3
"""Judge whether a run is a sound sweep of the reach scenario, whatever its reach verdict.

    python3 -I -B chaos/judges/reach/validity.py <scenario-id> --evidence chaos/runs/<run-id> [--receipt FILE]

Exit 0 means valid: `sound` in shared.py accepts the run, and its docstring lists what that
takes. `no_pass` and `unreached` are the reach invariant's to judge, and so are the row's fault,
its reach minimums, the reached map's agreement with the table and the covered-pass floor, which
the reach judge reads from its own row's threshold: a run that misses them stays valid. Exit 2
means the run shows nothing about the scenario, and exit 3 that it stopped before its evidence was
complete. This judge decides validity alone, so it never exits 1. Every receipt ends with the
scope sentence (shared.py).
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import sys
from pathlib import Path
from typing import NoReturn


def refuse(text: str) -> NoReturn:
    """Exit 2 with one line on standard error, which may be closed."""
    with contextlib.suppress(OSError):
        os.write(2, f"{text}\n".encode())
    os._exit(2)


# A standard stream the caller closed is opened on /dev/null, so no file the judge opens takes its number.
for number in (0, 1, 2):
    try:
        os.fstat(number)
    except OSError:
        os.open(os.devnull, os.O_RDWR)
if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    refuse(f"start the judge as python3 -I -B {sys.argv[0]} ...")
here = Path(__file__).resolve().parent
core = here.parent / "core"
try:
    # The judge executes the same common.py and shared.py bytes it reads, and hashes common.py's for LOADED_SHA256.
    for folder in {here, core}:
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False):
                raise OSError(f"{entry.name} beside the judge is no regular file")
    for name, path in (("common", str(core / "common.py")), ("shared", str(here / "shared.py"))):
        with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW), "rb") as file:
            source = file.read()

        class Checked(importlib.machinery.SourceFileLoader):
            def get_data(self, path: str, source: bytes = source) -> bytes:
                if path != self.path:
                    raise OSError(f"the judge reads {Path(self.path).name}'s source alone")
                return source

        spec = importlib.util.spec_from_file_location(name, path, loader=Checked(name, path))
        if spec is None or spec.loader is None:
            raise ImportError(f"{Path(path).name} has no loader")
        module = importlib.util.module_from_spec(spec)
        if name == "common":
            module.__dict__["LOADED_SHA256"] = hashlib.sha256(source).hexdigest()
        sys.modules[name] = module
        spec.loader.exec_module(module)
    from common import HELD, Evidence, main, scenario_profiles  # pyright: ignore[reportMissingImports]
    from shared import REACH_KEYS, sound  # pyright: ignore[reportMissingImports]
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")


def decide(row: dict, scenario: dict, evidence: Evidence) -> tuple[int, str]:
    sweep = sound(scenario, evidence)
    entries = sweep.status["profiles"]
    parts = [f"{profile} {entries[profile]['runs']} runs, {entries[profile]['replays']} replays"
             for profile in scenario_profiles(scenario)]
    keys = [key for key in REACH_KEYS if key in sweep.status]
    verdict = f"; the sweep's reach verdict {', '.join(keys)} is the reach invariant's" if keys else ""
    return HELD, f"valid: campaign sweep exited {sweep.code}; {'; '.join(parts)}{verdict}"


if __name__ == "__main__":
    sys.exit(main("scenarios", decide))
