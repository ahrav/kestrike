#!/usr/bin/env python3
"""Run the ignored guest binder case in a disposable QEMU guest and record it.

Usage:
  guest-binder.py --qemu PATH --kernel PATH --initrd PATH --artifacts DIR
      [--accel kvm|tcg] [--memory-mib N] [--cpus N] [--backing-mib N]
      [--handshake-seconds N] [--deadline-seconds N]

The harness owns the guest and its backing. It creates a sparse backing file
in a private directory, starts QEMU in its own process group on a q35
machine with an Intel guest IOMMU and one emulated NVMe controller over that
backing, and reads the guest's serial console. The controller reports the
serial of `VOLUME`, QEMU's NVMe model and PCI identity `1b36:0010`; SMBIOS
gives the guest `INSTANCE` as its board asset tag, which the binder reads as
its instance identity.

The guest's init, in the initrd, is an exact input: through the kernel
command line its environment receives the `KESTRIKE_GUEST_*` inputs the
case reads and `KESTRIKE_GUEST_TEST_ID`, the case's exact ID; the
initrd holds the library test executable built for the guest (the guest
lane appends the one it builds at `/usr/lib/kestrike/kestrike-tests`)
and the approved write-combining manifest at
`/etc/kestrike/wc-manifest.json`. It prints `guest-binder: ready <facts>`,
with `kernel=`, `modules=` and `iommu=` among the facts, once the guest can
run the case, runs the case as root by exact ID among the ignored cases with
`--test-threads=1 --nocapture`, prints `guest-binder: exit <code>` and
powers the guest off. A well-formed `<code>` is an optional `-` and one to
three ASCII digits. The case's registry rows have class `guest-privileged`:
this harness runs the case, and `hardware-lane.py` schedules only
`hardware-privileged` rows.

The guest must print its ready line within the handshake deadline and exit
within the run deadline, both measured from QEMU's start. After the console
closes, QEMU has `GRACE` seconds to exit on its own; a QEMU still running after
them is stopped and the run ends at the deadline. Once QEMU starts, every
outcome stops QEMU's process group and reaps QEMU; once the backing exists,
every outcome removes it, and a backing the host keeps rejects the run after
the guest is stopped. A run passes only when the guest reported ready,
libtest ran one test that passed, the case reported its default refusal,
its refusals of a substituted regular file, a different block node and a
partition open in a process, the namespace's claim, bind and release in order,
each inventory namespace ID earned exactly one passing witness after release,
the namespace tools witness appeared once, the guest reported exit 0 and QEMU
exited zero. Namespace child output belongs to its own exact-child oracle;
the console's libtest summary describes the outer binder case.
Once the run creates its new directory in `--artifacts`, `guest.json` there
records the inputs with their digests, QEMU's version and
arguments, the guest identity, the guest's reports, the summary, both exit
statuses, the outcome, the bounds and the cleanup; `console.log` holds the
console.

Exit 0 is a qualified pass, 1 a failed case, 2 a rejected input, a missing
prerequisite or a harness resource the host refused or kept, 3 a ready line missed
by the handshake deadline or before the console closed, 4 a guest or QEMU
that ended without exactly one well-formed `exit <code>` report, 5 an interruption
and 6 the run deadline. The console log stops growing once it holds 64 Mi characters
and the run is judged from the console it logs; the reader holds at most 64 Ki
characters of a line at a time, and the record keeps at most `REPORT_BOUND`
reports. A run that reads a report past that bound sets `reports_overflow`
in its record, and a run whose console passes the log's bound sets
`console_truncated`; either turns a qualified pass into a failed case.
"""

import argparse
import contextlib
import hashlib
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path

PASSED, FAILED, REJECTED, HANDSHAKE, CRASHED, INTERRUPTED, DEADLINE = range(7)
OUTCOMES = {
    PASSED: "qualified pass",
    FAILED: "case failed",
    REJECTED: "rejected input",
    HANDSHAKE: "handshake missed",
    CRASHED: "ended without a result",
    INTERRUPTED: "interrupted",
    DEADLINE: "run deadline",
}
TEST = "bind::guest_tests::the_binder_binds_and_releases_the_guest_s_controller"
VOLUME = "vol-0123456789abcdef0"
INSTANCE = "i-0123456789abcdef0"
MODEL = "QEMU NVMe Ctrl"
PCI = "1b36:0010"
PREFIX = "guest-binder: "
EXIT_CODE = re.compile(r"-?[0-9]{1,3}")
GRACE = 10
CONSOLE_BYTES = 64 << 20
LINE_CHARS = 64 << 10
REPORT_BOUND = 256
NAMESPACE_CASES = json.loads((Path(__file__).resolve().with_name("test-inventory.json")).read_text())["qemu"]["namespace_cases"]
NAMESPACE_REPORTS = [f"namespace {case['id']} passed" for case in NAMESPACE_CASES]
REPORTS = ("default refused", "substituted file refused", "other block node refused", "holder refused", "claimed", "bound", "released")
PASSING = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured;"
BOUNDS = {
    "memory_mib": (512, 65536),
    "cpus": (1, 64),
    "backing_mib": (16, 65536),
    "handshake_seconds": (1, 3600),
    "deadline_seconds": (1, 3600),
}


class Stop(Exception):
    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def parser():
    p = argparse.ArgumentParser(description="Run the ignored guest binder case in a disposable QEMU guest.")
    p.add_argument("--qemu", required=True)
    p.add_argument("--kernel", required=True)
    p.add_argument("--initrd", required=True)
    p.add_argument("--artifacts", required=True)
    p.add_argument("--accel", choices=("kvm", "tcg"), default="kvm")
    p.add_argument("--memory-mib", type=int, default=2048)
    p.add_argument("--cpus", type=int, default=2)
    p.add_argument("--backing-mib", type=int, default=64)
    p.add_argument("--handshake-seconds", type=int, default=120)
    p.add_argument("--deadline-seconds", type=int, default=600)
    return p


def sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as file:
        for block in iter(lambda: file.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def check(args):
    """Refuse a missing prerequisite or an out-of-range bound before anything starts."""
    for name, (low, high) in BOUNDS.items():
        value = getattr(args, name)
        if not low <= value <= high:
            raise Stop(REJECTED, f"--{name.replace('_', '-')} {value} is outside {low}..{high}")
    if args.handshake_seconds > args.deadline_seconds:
        raise Stop(REJECTED, "the handshake deadline exceeds the run deadline")
    for flag, path in (("--kernel", args.kernel), ("--initrd", args.initrd)):
        if not os.path.isfile(path) or not os.access(path, os.R_OK):
            raise Stop(REJECTED, f"{flag} {path} is not a readable file")
    if not os.path.isfile(args.qemu) or not os.access(args.qemu, os.X_OK):
        raise Stop(REJECTED, f"--qemu {args.qemu} is not an executable file")
    if args.accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise Stop(REJECTED, "--accel kvm needs read and write access to /dev/kvm")
    try:
        version = subprocess.run([args.qemu, "--version"], capture_output=True, text=True, timeout=10, check=True)
    except (OSError, subprocess.SubprocessError) as error:
        raise Stop(REJECTED, f"--qemu {args.qemu} --version failed: {error}") from error
    # The first line names the version; later ones carry the copyright.
    return version.stdout.strip().splitlines()[0] if version.stdout.strip() else ""


def guest_argv(args, backing):
    environment = {
        "KESTRIKE_GUEST_VOLUME": VOLUME,
        "KESTRIKE_GUEST_MODEL": f'"{MODEL}"',
        "KESTRIKE_GUEST_PCI": PCI,
        "KESTRIKE_GUEST_STATE_DIR": "/run/kestrike-guest",
        "KESTRIKE_GUEST_WC_MANIFEST": "/etc/kestrike/wc-manifest.json",
        "KESTRIKE_GUEST_TEST_ID": TEST,
    }
    append = " ".join(
        ["console=ttyS0", "loglevel=5", "intel_iommu=on", "iommu=nopt", "panic=-1"] + [f"{k}={v}" for k, v in environment.items()]
    )
    serial = VOLUME.replace("-", "")
    return [
        # The guest's userspace, like the portable artifact, needs the x86-64-v2 instructions QEMU's default
        # CPU model lacks; `max` passes the host's under KVM and every model feature under TCG.
        args.qemu, "-machine", f"q35,accel={args.accel},kernel-irqchip=split", "-cpu", "max",
        "-device", "intel-iommu,intremap=on,caching-mode=on",
        "-m", str(args.memory_mib), "-smp", str(args.cpus),
        "-nographic", "-no-reboot", "-nodefaults", "-no-user-config", "-serial", "stdio",
        "-smbios", f"type=2,asset={INSTANCE}",
        "-kernel", args.kernel, "-initrd", args.initrd, "-append", append,
        "-drive", f"file={backing},if=none,id=volume,format=raw",
        "-device", f"nvme,serial={serial},drive=volume",
    ]


def ordered(reports):
    """Whether `reports` holds every report in `REPORTS`, in that order."""
    found = [reports.index(report) for report in REPORTS if report in reports]
    return len(found) == len(REPORTS) and found == sorted(found)


def namespace_gaps(reports):
    """Require the tools and every exact namespace result once after binder release."""
    members = [report for report in reports if report.startswith("namespace ")]
    expected = ["namespace tools ready", *NAMESPACE_REPORTS]
    if Counter(members) != Counter(expected):
        return [f"namespace witnesses differ: expected {expected}, got {members}"]
    if "released" not in reports or reports.index("released") > min(reports.index(report) for report in expected):
        return ["namespace witnesses must follow binder release"]
    return []


def kind(report, ready):
    """Classify `report`, a console line's text after `PREFIX`: `"ready"` for the handshake, which is the first
    `ready` report alone (`ready` tells whether one came before), `"exit"` for the guest's exit report, and
    `"report"` for every other, which counts toward `REPORT_BOUND`; the record keeps the first `REPORT_BOUND`
    of them."""
    word = report.split()[:1]
    if word == ["ready"] and not ready:
        return "ready"
    return "exit" if word == ["exit"] else "report"


def console_reports(lines):
    """The reports console `lines` hold that count toward `REPORT_BOUND`, in order: every report but the
    handshake and the exit reports. A record keeps the first `REPORT_BOUND` of them, and
    `verify-receipts.py credit` compares the two on the lane's copy of the logged console."""
    ready, reports = False, []
    for line in lines:
        if PREFIX in line:
            report = line.split(PREFIX, 1)[1]
            found = kind(report, ready)
            ready = ready or found == "ready"
            if found == "report":
                reports.append(report)
    return reports


def overflowed(lines):
    """Whether console `lines` hold more reports than `REPORT_BOUND`, the count a record keeps.
    `verify-receipts.py credit` calls this on the lane's copy of the logged console, so the overflow it
    refuses is the console's own."""
    return len(console_reports(lines)) > REPORT_BOUND


def stop_group(process):
    """Stop QEMU's process group: SIGTERM, up to `GRACE` seconds for QEMU to
    exit, then SIGKILL for every member still alive; then reap QEMU."""
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGTERM)
    with contextlib.suppress(subprocess.TimeoutExpired):
        process.wait(timeout=GRACE)
    with contextlib.suppress(ProcessLookupError):
        os.killpg(process.pid, signal.SIGKILL)
    process.wait()


class Run:
    def __init__(self, args):
        self.args = args
        self.interrupted = None
        self.record = {
            "test_id": TEST,
            "identity": {"volume": VOLUME, "instance": INSTANCE, "model": MODEL, "pci": PCI},
            "bounds": {name: getattr(args, name) for name in BOUNDS} | {"accel": args.accel},
            "reports": [],
            "reports_overflow": False,
            "ready": None,
            "summary": [],
            "guest_exit": None,
            "exit_reports": 0,
            "qemu_exit": None,
            "qemu_pid": None,
            "cleanup": {},
        }
        self.dir = None

    def interrupt(self, signum, _frame):
        self.interrupted = signum

    def open(self):
        run_id = os.environ.get("GITHUB_RUN_ID") or f"local-{int(time.time())}-{os.getpid()}"
        attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
        base = Path(self.args.artifacts) / f"{run_id}-{attempt}-guest"
        candidate, suffix = base, 1
        while True:
            try:
                candidate.mkdir(parents=True)
                break
            except FileExistsError:
                suffix += 1
                candidate = base.with_name(f"{base.name}.{suffix}")
            except OSError as error:
                raise Stop(REJECTED, f"--artifacts refused {candidate}: {error}") from error
        self.dir = candidate
        self.record.update(run_id=run_id, run_attempt=attempt)

    def guest(self):
        version = check(self.args)
        self.record["inputs"] = {
            flag: {"path": os.path.abspath(path), "sha256": sha256(path)}
            for flag, path in (("qemu", self.args.qemu), ("kernel", self.args.kernel), ("initrd", self.args.initrd))
        }
        self.record["qemu_version"] = version
        self.open()
        private = tempfile.mkdtemp(prefix="guest-binder-")
        backing = os.path.join(private, "volume.raw")
        self.record["backing"] = {"path": backing, "bytes": self.args.backing_mib << 20}
        try:
            with open(backing, "wb") as file:
                file.truncate(self.args.backing_mib << 20)
            argv = guest_argv(self.args, backing)
            self.record["argv"] = argv
            code = self.supervise(argv)
        finally:
            shutil.rmtree(private, ignore_errors=True)
            removed = not os.path.exists(private)
            self.record["cleanup"]["backing_removed"] = removed
        if not removed:
            raise Stop(REJECTED, f"the host kept the backing under {private}")
        return code

    def supervise(self, argv):
        if self.interrupted is not None:
            return INTERRUPTED
        lines = queue.Queue()
        start = time.monotonic()
        assert self.dir is not None
        with open(self.dir / "console.log", "w") as console:
            process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                       stderr=subprocess.STDOUT, start_new_session=True, text=True,
                                       errors="replace")
            self.record["qemu_pid"] = process.pid
            output = process.stdout
            assert output is not None

            def read():
                written = 0
                try:
                    # Each piece is judged as logged, so the queue holds at most
                    # the console bound's worth of text.
                    for piece in iter(lambda: output.readline(LINE_CHARS), ""):
                        kept = piece[: CONSOLE_BYTES - written]
                        if len(kept) < len(piece):
                            self.record["console_truncated"] = True
                        if kept:
                            console.write(kept)
                            console.flush()
                            written += len(kept)
                            lines.put(kept.rstrip("\n"))
                except OSError as error:
                    self.record["console_error"] = str(error)
                finally:
                    lines.put(None)

            reader = threading.Thread(target=read, daemon=True)
            try:
                try:
                    reader.start()
                except RuntimeError as error:
                    raise Stop(REJECTED, f"the host refused the console reader: {error}") from error
                code = self.follow(lines, start)
                if code is None:
                    try:
                        process.wait(timeout=GRACE)
                    except subprocess.TimeoutExpired:
                        code = INTERRUPTED if self.interrupted is not None else DEADLINE
                        raise Stop(code, f"QEMU outlived the {GRACE}-second grace period after the console closed") from None
            finally:
                stop_group(process)
                self.record["qemu_exit"] = process.returncode
                self.record["cleanup"]["qemu_reaped"] = True
                if reader.ident is not None:
                    reader.join(timeout=10)
                self.record["seconds"] = round(time.monotonic() - start, 3)
        if "console_error" in self.record:
            raise Stop(REJECTED, f"the console log refused a write: {self.record['console_error']}")
        if code is None:
            code = INTERRUPTED if self.interrupted is not None else self.judge()
        return code

    def follow(self, lines, start):
        """Read console lines until the console closes, or a bound or an interruption ends the run.

        Returns the outcome that ended the run, or `None` when the console closed.
        """
        while True:
            if self.interrupted is not None:
                return INTERRUPTED
            elapsed = time.monotonic() - start
            if self.record["ready"] is None and elapsed > self.args.handshake_seconds:
                return HANDSHAKE
            if elapsed > self.args.deadline_seconds:
                return DEADLINE
            try:
                line = lines.get(timeout=0.1)
            except queue.Empty:
                continue
            if line is None:
                return None
            if (line.startswith("test result: ") or line == "running 1 test") and len(self.record["summary"]) < 4:
                self.record["summary"].append(line)
            if PREFIX not in line:
                continue
            report = line.split(PREFIX, 1)[1]
            found = kind(report, self.record["ready"] is not None)
            if found == "ready":
                self.record["ready"] = report[len("ready"):].strip()
            elif found == "exit":
                words = report.split()
                code = words[1] if len(words) == 2 else ""
                self.record["exit_reports"] += 1
                well_formed = self.record["exit_reports"] == 1 and EXIT_CODE.fullmatch(code)
                self.record["guest_exit"] = int(code) if well_formed else None
            elif len(self.record["reports"]) < REPORT_BOUND:
                self.record["reports"].append(report)
            else:
                self.record["reports_overflow"] = True

    def judge(self):
        """From its reports, summary and exit statuses, classify a run whose console closed."""
        record = self.record
        if record["ready"] is None:
            return HANDSHAKE
        if record["guest_exit"] is None:
            return CRASHED
        summary = record["summary"]
        passed = (
            len(summary) == 2
            and summary[0] == "running 1 test"
            and summary[1].startswith(PASSING)
            and ordered(record["reports"])
            and not namespace_gaps(record["reports"])
            and not record["reports_overflow"]
            and not record.get("console_truncated")
            and record["guest_exit"] == 0
            and record["qemu_exit"] == 0
        )
        return PASSED if passed else FAILED

    def finish(self, code, reason=None):
        self.record.update(outcome=OUTCOMES[code], exit=code, reason=reason)
        if self.dir is not None:
            (self.dir / "guest.json").write_text(json.dumps(self.record, indent=2, sort_keys=True) + "\n")
            print(f"record: {self.dir / 'guest.json'}", file=sys.stderr)
        print(OUTCOMES[code] if reason is None else f"{OUTCOMES[code]}: {reason}")
        return code


def main(argv=None):
    args = parser().parse_args(argv)
    run = Run(args)
    signal.signal(signal.SIGTERM, run.interrupt)
    signal.signal(signal.SIGINT, run.interrupt)
    try:
        code = run.guest()
    except Stop as stop:
        return run.finish(stop.code, str(stop))
    except OSError as error:
        return run.finish(REJECTED, f"the host refused a harness resource: {error}")
    return run.finish(code)


if __name__ == "__main__":
    sys.exit(main())
