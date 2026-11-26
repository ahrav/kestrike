#!/usr/bin/env python3
"""Run receipt self-tests with at most four concurrent cases and ordered output."""

import argparse
import contextlib
import importlib.util
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_WORKERS = 4


def discover(script):
    name = "_script_selftests"
    spec = importlib.util.spec_from_file_location(name, script)
    if spec is None or spec.loader is None:
        raise ValueError(f"cannot import {script}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    with contextlib.redirect_stdout(sys.stderr):
        spec.loader.exec_module(module)
        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(module)
    if loader.errors:
        raise ValueError("\n".join(loader.errors))

    def flatten(tests):
        for test in tests:
            if isinstance(test, unittest.TestSuite):
                yield from flatten(test)
            elif isinstance(test, unittest.TestCase) and test.id().startswith(name + "."):
                yield test.id()[len(name) + 1:]
            else:
                raise ValueError(f"cannot select discovered test {test!r} in {script}")

    names = sorted(flatten(suite))
    if not names or len(names) != len(set(names)):
        raise ValueError(f"{script}: discovery must contain nonempty, unique test IDs")
    return names


def signal_group(process, signum):
    try:
        os.killpg(process.pid, signum)
        return True
    except ProcessLookupError:
        return False


class Supervisor:
    def __init__(self):
        self.cancelled = 0
        self.processes = []
        self.handlers = {}

    def __enter__(self):
        for signum in (signal.SIGINT, signal.SIGTERM):
            self.handlers[signum] = signal.signal(signum, self.cancel)
        return self

    def cancel(self, signum, _frame):
        self.cancelled = self.cancelled or signum

    def cleanup(self, processes=None):
        processes = list(self.processes) if processes is None else processes
        remaining = [process for process in processes if signal_group(process, signal.SIGTERM)]
        if remaining:
            for process in remaining:
                signal_group(process, signal.SIGCONT)
            deadline = time.monotonic() + 0.5
            while remaining and time.monotonic() < deadline:
                for process in remaining:
                    process.poll()
                remaining = [process for process in remaining if signal_group(process, 0)]
                time.sleep(0.01)
            # A grandchild can outlive its group leader and ignore the graceful signal.
            for process in remaining:
                signal_group(process, signal.SIGKILL)
        for process in processes:
            process.wait()
            self.processes.remove(process)

    def __exit__(self, *_args):
        try:
            self.cleanup()
        finally:
            for signum, handler in self.handlers.items():
                signal.signal(signum, handler)

    def run(self, commands, workers, directory, stderr=subprocess.STDOUT):
        active, results = {}, {}
        next_index = 0
        try:
            while (next_index < len(commands) or active) and not self.cancelled:
                while next_index < len(commands) and len(active) < workers and not self.cancelled:
                    index = next_index
                    output = directory / f"{index}.log"
                    with output.open("wb") as stream:
                        process = subprocess.Popen(commands[index], stdout=stream, stderr=stderr,
                                                   start_new_session=True)
                    self.processes.append(process)
                    active[index] = (process, output)
                    next_index += 1
                for index, (process, output) in list(active.items()):
                    code = process.poll()
                    if code is not None:
                        self.cleanup([process])
                        results[index] = (code, output)
                        del active[index]
                if active:
                    time.sleep(0.01)
        finally:
            self.cleanup()
        for index, (process, output) in active.items():
            results[index] = (process.returncode, output)
        return results


def default_workers():
    available = len(os.sched_getaffinity(0)) if hasattr(os, "sched_getaffinity") else os.cpu_count() or 1
    return min(MAX_WORKERS, max(1, available))


def worker_count(value):
    try:
        count = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("workers must be an integer from 1 to 4") from error
    if not 1 <= count <= MAX_WORKERS:
        raise argparse.ArgumentTypeError("workers must be an integer from 1 to 4")
    return count


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("script", nargs="?", type=Path, default=ROOT / "scripts/test-verify-receipts.py",
                        help="receipt-style unittest script whose descendants stay in their process group")
    parser.add_argument("--workers", type=worker_count, default=default_workers())
    parser.add_argument("--discover", type=Path, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    workers = min(args.workers, default_workers())
    if args.discover is not None:
        print(json.dumps(discover(args.discover.resolve())))
        return 0
    script = args.script.resolve()
    with Supervisor() as supervisor, tempfile.TemporaryDirectory(prefix="kestrike-selftests-") as temporary:
        directory = Path(temporary)
        discovery = directory / "discovery"
        discovery.mkdir()
        commands = [[sys.executable, str(Path(__file__).resolve()), "--discover", str(script)]]
        # Discovery stderr stays on the parent's stderr so the log holds only the JSON case list.
        results = supervisor.run(commands, 1, discovery, stderr=sys.stderr.fileno())
        if supervisor.cancelled:
            print(f"Interrupted by {signal.Signals(supervisor.cancelled).name}", file=sys.stderr)
            return 128 + supervisor.cancelled
        code, output = results[0]
        text = output.read_text(errors="replace")
        if code:
            print(text, end="", file=sys.stderr)
            raise ValueError(f"discovery failed for {script} (exit {code})")
        try:
            cases = json.loads(text)
        except ValueError as error:
            print(text, end="", file=sys.stderr)
            raise ValueError(f"invalid discovery output for {script}: {error}") from error
        if (not isinstance(cases, list) or not cases or not all(isinstance(name, str) for name in cases)
                or len(cases) != len(set(cases))):
            raise ValueError(f"invalid discovery output for {script}")
        print(f"Running {len(cases)} self-tests with {workers} workers", flush=True)
        execution = directory / "execution"
        execution.mkdir()
        commands = [[sys.executable, str(script), "-v", name] for name in cases]
        results = supervisor.run(commands, workers, execution)
        failed = 0
        for index, name in enumerate(cases):
            if index not in results:
                continue
            code, output = results[index]
            text = output.read_text(errors="replace")
            print(f"\n=== {script.name}: {name} ===", flush=True)
            print(text, end="" if text.endswith("\n") else "\n", flush=True)
            if code != 0 or not re.search(r"(?m)^Ran 1 test in [^\n]+$", text):
                failed += 1
                print(f"Unsuccessful test process: exit {code}; exactly one test must run", flush=True)
        print(f"Self-tests: {len(cases)} selected; {len(results)} completed; {failed} failed", flush=True)
        if supervisor.cancelled:
            print(f"Interrupted by {signal.Signals(supervisor.cancelled).name}", file=sys.stderr)
            return 128 + supervisor.cancelled
        return int(failed != 0 or len(results) != len(cases))


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, RuntimeError) as error:
        print(f"run-receipt-selftests: {error}", file=sys.stderr)
        sys.exit(1)
