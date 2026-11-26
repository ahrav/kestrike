#!/usr/bin/env python3
"""Judge whether a run is a valid run of its scenario row.

    python3 -I -B chaos/judges/core/validity.py <scenario-id> --evidence chaos/runs/<run-id> [--receipt FILE]

Exit 0 means valid: campaign sweep returned by itself with exit 0 and no alarm, no_pass or
unreached in its totals, on a root that holds the archive's build; the run left no process in a
cgroup under its cgroup root and its archive verified after the sweep, as run.json records them; each
profile of the scenario met its witness minimum and the row's reach minimums, was replayed in a
fresh process and listed suspects of class violation only; and when the root holds controls, they
have runs and at least one caught run, a rule of the whole root, so in a row of several profiles
the controls of one profile meet it for all. A control run also needs its defect swept with runs,
a replay, no miss and suspects of class violation only. Exit 2 means the run shows nothing about
the scenario, and exit 3 that it stopped before its evidence was complete. This judge decides
validity alone, so it never exits 1.
"""
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import os
import stat
import sys
from pathlib import Path
from typing import NoReturn


def refuse(text: str) -> NoReturn:
    """Exit 2 with one line on standard error, which may be closed; no text of the line can stop the exit."""
    with contextlib.suppress(OSError):
        os.write(2, f"{text}\n".encode("utf-8", "backslashreplace"))
    os._exit(2)


# A standard stream the caller closed is opened on /dev/null, so no file the judge opens takes its number.
for number in (0, 1, 2):
    try:
        os.fstat(number)
    except OSError:
        try:
            opened = os.open(os.devnull, os.O_RDWR)
        except OSError:
            refuse("cannot open /dev/null in place of a closed standard stream")
        if opened != number:
            refuse("a closed standard stream could not be opened again on /dev/null")
if not sys.flags.isolated or not sys.flags.dont_write_bytecode:
    refuse(f"start the judge as python3 -I -B {sys.argv[0]} ...")
here = Path(__file__).resolve().parent
core = here.parent / "core"
try:
    # The judge executes the common.py bytes it read once and hashes for LOADED_SHA256, through a
    # loader that returns those bytes alone, so no bytecode cache takes part. The bound is
    # common.SOURCE_BYTES.
    for folder in {here, core}:
        for entry in os.scandir(folder):
            if not entry.is_file(follow_symlinks=False):
                raise OSError(f"{entry.name} beside the judge is no regular file")
    path = str(core / "common.py")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        if not stat.S_ISREG(os.fstat(file.fileno()).st_mode):
            raise OSError("common.py is no regular file")
        source = file.read((1 << 22) + 1)
    if len(source) > 1 << 22:
        raise OSError("common.py holds more than its bound of bytes")

    class Checked(importlib.machinery.SourceFileLoader):
        def get_data(self, path: str) -> bytes:
            if path != self.path:
                raise OSError("the judge reads common.py's source alone")
            return source

    spec = importlib.util.spec_from_file_location("common", path, loader=Checked("common", path))
    if spec is None or spec.loader is None:
        raise ImportError("common.py has no loader")
    module = importlib.util.module_from_spec(spec)
    module.__dict__["LOADED_SHA256"] = hashlib.sha256(source).hexdigest()
    sys.modules["common"] = module
    spec.loader.exec_module(module)
    from common import HELD, Evidence, main, validity
except Exception as error:  # an import that fails is no verdict
    refuse(f"cannot load the judge: {error.__class__.__name__}: {error}")


def decide(row: dict, scenario: dict, evidence: Evidence) -> tuple[int, str]:
    return HELD, validity(scenario, evidence)


if __name__ == "__main__":
    sys.exit(main("scenarios", decide))
