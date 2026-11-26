#!/usr/bin/env python3
"""Cancel lane steps the way the Actions runner does and check what survives.

On cancellation the runner sends SIGINT to the step's shell process, waits 7.5
seconds, sends SIGTERM, waits 2.5 seconds, then kills the process tree. Each
test runs a lane step's `run:` text from agent-checks.yml under the runner's
`bash -eo pipefail` shell, with a stub `cargo` on PATH whose long command
takes a second to exit after SIGTERM. When the step process exits, no process
carrying the step's RUNNER_TRACKING_ID may remain: a survivor would still be
writing evidence while the `if: always()` Summary and Evidence steps run.

Further checks guard the workflow's shape and the lane script's evidence:
every Rust lane installs the pinned toolchains under its own bound, while
checker lanes verify their provisioned prerequisites. `needs` orders jobs
without binding them to one runner, and every lane's job timeout keeps a
ten-minute margin above its prerequisites and run; a command failure anywhere
in the script still writes `failure.txt` for the always-run upload.
"""

import ast
import contextlib
import gzip
import hashlib
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import signal
import subprocess
import sys
import textwrap
import tempfile
import time
import unittest
import uuid
from pathlib import Path
from typing import Any, Dict, Optional

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/agent-checks.yml"
# The hardware job waits for a provisioned host, so it runs from its own workflow and holds back only itself.
HARDWARE_WORKFLOW = ROOT / ".github/workflows/hardware.yml"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


genmc_fixture = load("test_judge_genmc", ROOT / "scripts/test-judge-genmc.py")
select_fixture = load("test_select_tests", ROOT / "scripts/test-select-tests.py")
LANES = ("preflight", "workspace", "campaigns", "search", "fuzz-smoke", "long-run", "search-nightly", "isa-x86-64", "isa-aarch64", "loom", "miri", "asan", "qemu", "sweep", "rc11", "verus", "genmc", "kani", "tlc", "quint", "fuzz", "quarantine",
         "hardware", "fis", "barriers", "tag-compare-x86-64", "tag-compare-aarch64")
# The jobs that need a native AArch64 host, and their runner selectors.
AARCH64 = {"barriers": "[self-hosted, linux, arm64, kestrike-aarch64-native]",
           "isa-aarch64": "[self-hosted, linux, arm64, kestrike-isa-aarch64]",
           "tag-compare-aarch64": "[self-hosted, linux, arm64, kestrike-aarch64-native]"}
# Jobs that run on a GitHub-hosted runner on every event.
HOSTED = {"comment-policy", "lane-script", "rust-format", "rust-gate"}
# Jobs that run on a dedicated host rather than the shared pool: the hardware and FIS hosts, and the native
# x86-64 host whose CPU carries every feature the x86-64 architecture qualification lane declares.
DEDICATED = {"hardware": '[self-hosted, linux, "${{ matrix.arch }}", kestrike-hardware]',
             "fis": "[self-hosted, linux, x64, kestrike-fis]",
             "isa-x86-64": "[self-hosted, linux, x64, kestrike-isa-x86-64]"}
# The jobs of the hardware workflow: the gate reads the completed agent-checks run, then the lane and the FIS
# campaign run for it, each on its own registration.
HARDWARE_JOBS = {"gate", "hardware", "fis"}
CHECKER_LANES = ("rc11",)
RUST_LANES = tuple(lane for lane in LANES if lane not in CHECKER_LANES)
# A lane whose cases run in a job other than the one that judges and credits them: the Quint shards run the cases
# and the `quint` job joins their evidence.
RUNNERS = {"quint": "quint-shard"}
MARGIN_MINUTES = 10
# Steps a job runs beside its lane, each under its own evidence directory, with the deadline constants of
# rust-lane.sh its budget must cover.
ADDED_STEPS = {"isa-aarch64": {"tsan": ("TSAN_BUILD_MINUTES", "TSAN_RUN_MINUTES", "TSAN_CONTROL_MINUTES"),
                               "litmus": ("LITMUS_BUILD_MINUTES", "LITMUS_RUN_MINUTES")}}
SIGINT_GRACE, SIGTERM_GRACE = 7.5, 2.5

STUB_CARGO = r"""#!/usr/bin/env bash
[ -z "${STUB_ENV_DUMP:-}" ] || env > "$STUB_ENV_DUMP"

if [ -n "${STUB_ENV:-}" ]; then
  if [ -n "${CARGO_ENCODED_RUSTFLAGS+set}" ]; then
    echo "encoded=[$CARGO_ENCODED_RUSTFLAGS] $*"
  else
    echo "encoded unset $*"
  fi >> "$STUB_ENV"
fi
case " $* " in
  *" config get "*) echo "${STUB_CARGO_CONFIG:-{\}}"; exit 0 ;;
  *" tree "*) echo "loom v$LOOM"; exit 0 ;;
  *" fuzz --version "*) echo "cargo-fuzz $CARGO_FUZZ"; exit 0 ;;
  *" miri setup "*) exit 0 ;;
  *" miri --version "*) echo "miri 0.1.0 (stub)"; exit 0 ;;
  *" --no-run --message-format=json-render-diagnostics "*) [ -z "${STUB_BUILD:-}" ] || { cat "$STUB_BUILD"; exit 0; } ;;
  *" --list --ignored "*) [ -z "${STUB_IGNORED:-}" ] || { cat "$STUB_IGNORED"; exit 0; } ;;
  *" --list "*) [ -z "${STUB_LIST:-}" ] || { cat "$STUB_LIST"; exit 0; } ;;
  *" --exact "*"::negative_control_"*) [ -z "${STUB_CONTROL:-}" ] || { cat "$STUB_CONTROL"; exit "${STUB_CONTROL_EXIT:-1}"; } ;;&
  *) [ -z "${STUB_RUN:-}" ] || { cat "$STUB_RUN"; exit "${STUB_RUN_EXIT:-0}"; } ;;
esac
[ -z "${STUB_EXIT:-}" ] || exit "$STUB_EXIT"
echo "$$" >> "$STUB_PIDS"
trap 'sleep 1; exit 143' TERM
while :; do sleep 0.1; done
"""


# A stub `cargo` for the Kani lane's batches: the listing writes every declared harness, and a run prints Kani's
# terse output for the harnesses its argv names, each at its declared covers and unreachable count. The harness
# STUB_FAIL names fails one check, and at STUB_HANG's harness the run records its pid and waits to be stopped. At
# STUB_LINGER's harness the run forks a process that ignores TERM and records its pid, and the run goes on once the
# pid is recorded, so the lane's drain finds the process in the group.
KANI_STUB = """#!/usr/bin/env python3
import importlib.util, json, os, signal, sys, time
from pathlib import Path

args = sys.argv[1:]
if "config" in args:
    print("{}")
    sys.exit(0)
spec = importlib.util.spec_from_file_location("judge_kani", Path(os.environ["STUB_ROOT"]) / "scripts/judge-kani.py")
judge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(judge)
expected = judge.declaration()
if args[:2] == ["kani", "list"]:
    Path("kani-list.json").write_text(json.dumps({"standard-harnesses": {"src/lib.rs": sorted(expected["harnesses"])}}))
    sys.exit(0)
names = [args[at + 1] for at in range(len(args) - 1) if args[at] == "--harness"]
with open(os.environ["STUB_KANI_LOG"], "a") as log:
    log.write(" ".join(names) + "\\n")
if os.environ.get("STUB_HANG") in names:
    with open(os.environ["STUB_PIDS"], "a") as pids:
        pids.write(f"{os.getpid()}\\n")
    while True:
        time.sleep(0.1)
if os.environ.get("STUB_LINGER") in names:
    ready, recorded = os.pipe()
    if os.fork() == 0:
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
        with open(os.environ["STUB_PIDS"], "a") as pids:
            pids.write(f"{os.getpid()}\\n")
        os.write(recorded, b"1")
        while True:
            time.sleep(0.1)
    os.read(ready, 1)
print("Kani Rust Verifier 0.68.0 (cargo plugin)")
print("CBMC 6.11.0")
failed = 0
for index, name in enumerate(names):
    declared = expected["harnesses"][name]
    unreachable, bad = declared["unreachable"], name == os.environ.get("STUB_FAIL")
    failed += bad
    print(f"Thread {index % 2}: Checking harness {name}...")
    print(f"Thread {index % 2}: ")
    print("VERIFICATION RESULT:")
    print(f" ** {int(bad)} of {max(40, unreachable + 1)} failed" + (f" ({unreachable} unreachable)" if unreachable else ""))
    print(f" ** {declared['covers']} of {declared['covers']} cover properties satisfied")
    print("VERIFICATION:- FAILED" if bad else "VERIFICATION:- SUCCESSFUL")
    print("Verification Time: 1.25s")
print("Manual Harness Summary:")
print(f"Complete - {len(names) - failed} successfully verified harnesses, {failed} failures, {len(names)} total.")
sys.exit(1 if failed else 0)
"""

# A stub rustc's `--print cfg` prints `lse` only when its arguments hold `-C` followed by
# `target-feature=+lse` as two arguments, as rustc reads them.
STUB_LSE = ("previous=; for argument; do [ \"$previous $argument\" != '-C target-feature=+lse' ] || "
            "echo 'target_feature=\"lse\"'; previous=$argument; done")


def env_dump(path):
    """The variables of the `env` output at `path`, one `NAME=value` per line."""
    return dict(line.split("=", 1) for line in Path(path).read_text().splitlines() if "=" in line)


def lane_commands(text):
    """Map each lane to the `run:` text of the step that launches it.

    Handles the two forms the workflow uses: an inline scalar and a folded
    `>-` block, whose lines join with single spaces.
    """
    lines = text.splitlines()
    commands = {}
    for index, line in enumerate(lines):
        found = re.match(r"^(\s*)run: (.*)$", line)
        if not found:
            continue
        indent, value = len(found.group(1)), found.group(2)
        if value == ">-":
            body = []
            for following in lines[index + 1:]:
                if following.strip() and len(following) - len(following.lstrip()) <= indent:
                    break
                body.append(following.strip())
            value = " ".join(part for part in body if part)
        lane = re.search(r"scripts/rust-lane\.sh ([\w-]+)", value)
        if lane and lane.group(1) in LANES:
            commands[lane.group(1)] = value
    return commands


def workflow_jobs(text):
    """Map each workflow job to its YAML body."""
    jobs, name = {}, None
    for line in text.partition("\njobs:\n")[2].splitlines():
        found = re.match(r"^  ([\w-]+):$", line)
        if found:
            name = found.group(1)
            jobs[name] = []
        elif name:
            jobs[name].append(line)
    return {name: "\n".join(body) for name, body in jobs.items()}


PROFILE_CHOICE = re.compile(r"_PROFILE: >-\n\s+\$\{\{ github\.event_name == '(\w+)' && '(\w+)' \|\| '(\w+)' \}\}")


def gate_lanes(text, event, loom_modules):
    """The lanes whose evidence the rust-gate selects on `event`, keyed (job, module) as the aggregate keys them.

    A lane is a selected job with a credit step, or the barrier job, whose scan report stands in for its receipt.
    A Loom lane is one per module, and a GenMC, Kani or TLC lane carries the profile its job's environment picks
    for `event`.
    """
    jobs = workflow_jobs(text)
    lanes = set()
    for job in load("verify_receipts", ROOT / "scripts/verify-receipts.py").selected_jobs(event):
        body = jobs[job]
        if job != "barriers" and f"verify-receipts.py credit --job {job}" not in body:
            continue
        if job == "loom":
            lanes |= {("loom", module) for module in loom_modules}
        elif "_PROFILE: >-" in body:
            when, chosen, otherwise = matched(PROFILE_CHOICE, body).groups()
            lanes.add((job, chosen if event == when else otherwise))
        else:
            lanes.add((job, None))
    return lanes


def rust_jobs(text):
    """Map each lane that needs Rust toolchains rather than a provisioned checker to the job that runs its cases."""
    jobs = workflow_jobs(text)
    return {lane: jobs[RUNNERS.get(lane, lane)] for lane in RUST_LANES if RUNNERS.get(lane, lane) in jobs}


def tracked(marker):
    """Live processes whose environment carries RUNNER_TRACKING_ID=marker."""
    needle = f"RUNNER_TRACKING_ID={marker}\0".encode()
    found = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            if needle not in (entry / "environ").read_bytes():
                continue
            stat = (entry / "stat").read_text()
        except OSError:
            continue
        if stat[stat.rindex(")") + 2] == "Z":
            continue
        found.append((int(entry.name), (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode().strip()))
    return found


def host_cpu(cpuinfo):
    """The CPU name `target_dir` keys the target cache with: the x86 `model name`, else the first AArch64 core's
    implementer and part."""
    fields = {}
    for line in cpuinfo.splitlines():
        key, _, value = line.partition(": ")
        fields.setdefault(key.rstrip(), value)
    if "model name" in fields:
        return fields["model name"]
    return f"implementer {fields['CPU implementer']} part {fields['CPU part']}"


def matched(pattern, text, flags=0, message=None):
    """Return the first match of `pattern` in `text`; a text the pattern misses fails the test here."""
    match = re.search(pattern, text, flags)
    if match is None:
        raise AssertionError(message or f"{pattern!r} matched nothing")
    return match


def default_sigint():
    """Give a process the default SIGINT before it runs a lane. A runner's step starts with it, and a non-interactive
    bash cannot trap a signal it started with ignored, which a test run started as a shell's background job passes
    to its children."""
    signal.signal(signal.SIGINT, signal.SIG_DFL)


def wait_exit(process, seconds):
    try:
        process.wait(timeout=seconds)
        return True
    except subprocess.TimeoutExpired:
        return False


# A worker the fuzz lane drives: `--seeds` writes the plan's seeds, the planted control audits and aborts, a seed
# pass passes every seed it names, and a timed run loads its seeds and prints the plan's counts line for its target.
FUZZ_WORKER = textwrap.dedent("""\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    plan, args = json.loads(os.environ["STUB_FUZZ_PLAN"]), sys.argv[1:]
    if args[0] == "--seeds":
        for name in plan["seeds"].get(args[1], ["one"]):
            (Path(args[2]) / f"{name}.input").write_text(name)
        sys.exit(0)
    target, rest = args[1], args[args.index("--") + 1:]
    if target == "planted":
        print("fuzz: audited and tore down planted: planted: complete violation", file=sys.stderr)
        print("==1== ERROR: libFuzzer: deadly signal", file=sys.stderr)
        sys.exit(1)
    if any(arg.startswith("-max_total_time=") for arg in rest):
        seeds = len(list(Path(rest[-1]).iterdir()))
        print(f"INFO: seed corpus: files: {seeds} min: 1b max: 1b", file=sys.stderr)
        print("Done 500 runs in 20 second(s)", file=sys.stderr)
        print(plan["lines"][target], file=sys.stderr)
    else:
        print(f"fuzz: {target} executed={len(rest)} pass={len(rest)} unsuccessful=0 invalid=0 incomplete=0 "
              "unsupported=0 failure=0", file=sys.stderr)
""")


class LaneCancellation(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-lane-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.marker = f"lane-test-{uuid.uuid4()}"
        self.addCleanup(self.kill_tracked)
        stub = self.dir / "bin"
        stub.mkdir()
        (stub / "cargo").write_text(STUB_CARGO)
        (stub / "cargo").chmod(0o755)
        (stub / "rustc").write_text(
            '#!/usr/bin/env bash\ncase " $* " in\n'
            '  *" --print sysroot "*) echo "${STUB_SYSROOT:-/stub-sysroot}" ;;\n'
            '  *" -vV "*) echo "rustc ${1#+} (stub)"; echo "LLVM version: 22.1.8" ;;\n'
            '  *) echo "rustc ${1#+} (stub)" ;;\nesac\n')
        (stub / "rustc").chmod(0o755)
        (stub / "ldd").write_text('#!/usr/bin/env bash\nprintf \'\\tlibLLVM.so.22.1 => %s (0x00007f00)\\n\' "$STUB_LDD_LIBLLVM"\n')
        (stub / "ldd").chmod(0o755)
        self.pids = self.dir / "pids"
        self.env = dict(
            os.environ,
            PATH=f"{stub}:{os.environ['PATH']}",
            STABLE="1.99.0",
            NIGHTLY="nightly-2026-07-27",
            CARGO_FUZZ="0.13.2",
            LOOM="0.7.2",
            HERDTOOLS7="7.58",
            LLVM="22.1.8",
            SPDK_COMMIT="spdk-commit",
            SPDK_VERSION="25.5.1",
            DPDK_COMMIT="dpdk-commit",
            DPDK_VERSION="25.03.0",
            SPDK_PKG_CONFIG_PATH=str(self.dir / "pkgconfig"),
            KESTRIKE_HARDWARE_PLATFORM="x86_64-nitro-ebs",
            EVIDENCE=str(self.dir / "evidence"),
            GITHUB_STEP_SUMMARY=str(self.dir / "summary.md"),
            RUNNER_TRACKING_ID=self.marker,
            STUB_PIDS=str(self.pids),
        )
        self.commands = lane_commands(WORKFLOW.read_text() + HARDWARE_WORKFLOW.read_text())

    def test_quint_summary_accepts_core_replay_and_blocked_cases(self):
        evidence = Path(self.env["EVIDENCE"])
        evidence.mkdir()
        (evidence / "report.json").write_text(json.dumps({"credited": True, "cases": {
            "detect-replay": {"command": "replay", "traces": 2, "actions": 45},
            "detect-progress": {"command": "tlc", "distinct": 10, "depth": 7, "seconds": 1, "blocked": "AQ-15"},
        }}))
        result = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "quint"], cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn("detect-replay: core replay, 2 traces, 45 actions", summary)
        self.assertIn("detect-progress: withheld at AQ-15; no credit", summary)

    def test_tlc_summary_prints_each_unreached_span_or_the_one_empty_line(self):
        """A credited TLC report prints one line per unreached span with its model, section, location and text in a
        code span; three empty lists print the one line with the cases and span lines read; a refusal string prints
        that string and no empty line."""
        evidence = Path(self.env["EVIDENCE"])
        evidence.mkdir()
        empty = {"tla/Recovery.tla": [], "tla/Lifecycle.tla": [], "tla/Identity.tla": []}
        stale = {"section": "CReturnStale", "at": "333:27-333:41", "text": "UNCHANGED board"}
        line = "no listed span is unreached: 24 cases and 12854 span lines read"
        for name, unreached, present, absent in (
            ("one span", {**empty, "tla/Identity.tla": [stale]},
             "- tla/Identity.tla: unreached span of CReturnStale at 333:27-333:41: `UNCHANGED board`", line),
            ("no span", empty, f"- {line}", "unreached span of"),
            ("a refused log", {**empty, "tla/Lifecycle.tla": "put: tlc.log has no complete coverage report"},
             "- tla/Lifecycle.tla: unreached spans unread: put: tlc.log has no complete coverage report", line),
        ):
            with self.subTest(name):
                (evidence / "report.json").write_text(json.dumps({
                    "credited": True, "cases": {"put": {"distinct": 5255, "seconds": 1.0, "liveness": False}},
                    "unreached": unreached, "unreached_read": {"cases": 24, "span_lines": 12854}}))
                (self.dir / "summary.md").unlink(missing_ok=True)
                result = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "tlc", "pr"], cwd=ROOT, env=self.env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                summary = (self.dir / "summary.md").read_text()
                self.assertIn(present, summary)
                self.assertNotIn(absent, summary)

    def kill_tracked(self):
        for pid, _ in tracked(self.marker):
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)

    def cancel(self, lane, command):
        script = self.dir / "step.sh"
        script.write_text(command.replace("${{ matrix.module }}", "credit_model") + "\n")
        step = subprocess.Popen(
            ["bash", "--noprofile", "--norc", "-eo", "pipefail", str(script)],
            cwd=ROOT, env=self.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True, preexec_fn=default_sigint,
        )
        deadline = time.monotonic() + 60
        while not (self.pids.exists() and self.pids.read_text().strip()):
            if step.poll() is not None:
                self.fail(f"the {lane} step exited {step.returncode} before its long command started")
            if time.monotonic() > deadline:
                step.kill()
                self.fail(f"the {lane} step never started its long command")
            time.sleep(0.05)
        os.kill(step.pid, signal.SIGINT)
        if not wait_exit(step, SIGINT_GRACE):
            os.kill(step.pid, signal.SIGTERM)
            if not wait_exit(step, SIGTERM_GRACE):
                step.kill()
                step.wait()
        return tracked(self.marker)

    def test_every_lane_step_execs_its_deadline(self):
        self.assertEqual(sorted(self.commands), sorted(LANES))
        for lane, command in self.commands.items():
            with self.subTest(lane=lane):
                self.assertRegex(
                    command,
                    rf"^exec timeout --kill-after=\d+s \d+m bash scripts/rust-lane\.sh {lane}\b",
                )

    def test_software_jobs_use_only_dedicated_build_runner_roles(self):
        jobs = workflow_jobs(WORKFLOW.read_text())
        self.assertEqual(set(jobs), {*LANES, *RUNNERS.values(), "comment-policy", "lane-script", "rust-format", "rust-gate",
                                     "fis-controller"} - HARDWARE_JOBS)
        hardware = workflow_jobs(HARDWARE_WORKFLOW.read_text())
        self.assertEqual(set(hardware), HARDWARE_JOBS)
        jobs |= hardware
        for name, body in jobs.items():
            with self.subTest(job=name):
                if name in AARCH64 or name in DEDICATED:
                    self.assertIn(f"    runs-on: {(AARCH64 | DEDICATED)[name]}\n", body)
                    continue
                if name in HOSTED:
                    self.assertIn("    runs-on: ubuntu-24.04\n", body)
                    self.assertNotIn("self-hosted", body)
                    continue
                self.assertRegex(body, r'(?m)^    runs-on: \[self-hosted, linux, x64, (?:kestrike-ci-heavy|"\$\{\{ .+ \}\}")\]$')
        for name in ("comment-policy", "lane-script", "rust-format", "preflight", *CHECKER_LANES):
            self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", jobs[name])
        # The FIS controller suite is a long test by the lane admission rule: it runs on the schedule and on dispatch
        # after the workspace, in a job no lane needs, so its failure holds back no other lane.
        controller = jobs["fis-controller"]
        self.assertIn("github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch'", controller)
        self.assertIn("needs: workspace", controller)
        self.assertIn("python3 scripts/test-fis-controller.py", controller)
        self.assertNotIn("test-fis-controller", jobs["lane-script"])
        for name, body in jobs.items():
            self.assertNotRegex(body, r"needs:.*fis-controller", f"{name} waits on the controller suite")
        self.assertIn("if: always()", jobs["rust-gate"])
        self.assertIn("python3 scripts/verify-receipts.py gate", jobs["rust-gate"])
        self.assertIn('CARGO_BUILD_JOBS: "4"', WORKFLOW.read_text())
        self.assertIn('RUST_TEST_THREADS: "4"', WORKFLOW.read_text())

    def test_the_hardware_workflow_reads_its_pins_from_the_checked_out_revision(self):
        """The workflow runs from the default branch, so it declares no pins; a step reads agent-checks.yml's env
        block from the checkout into the job environment before the toolchains install."""
        text = HARDWARE_WORKFLOW.read_text()
        self.assertNotRegex(text.partition("\njobs:\n")[0], r"(?m)^env:", "no pin lives in two workflows")
        job = workflow_jobs(text)["hardware"]
        steps = re.findall(r"(?m)^      - (?:name|uses): (.+)$", job)
        self.assertEqual(steps[:3], ["actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                                     "Pins and workflow shape of the checked-out revision", "Pinned toolchains"])
        self.assertIn('open(".github/workflows/agent-checks.yml")', job)
        self.assertIn('os.environ["GITHUB_ENV"]', job)
        # A revision whose agent-checks.yml still carries the hardware job ran the lane there; this workflow skips it.
        self.assertIn('re.search(r"(?m)^  hardware:$", text) is None', job)
        self.assertEqual(job.count("if: steps.revision.outputs.split == 'true'"), 2, "toolchains and the lane wait on the split")
        self.assertIn("if: always() && steps.revision.outputs.split == 'true'", job)
        # Each machine the manifest's platform rows name has a leg on native hosts of that architecture, and the
        # arm64 leg builds against the host's native SPDK install, the rule docs/agents/ci.md states for AArch64 hosts.
        legs = dict(re.findall(r"(?m)^          - arch: (\w+)\n            spdk: (.*)$", job))
        self.assertEqual(legs, {"x64": '""', "arm64": "/usr/local/lib/pkgconfig"})
        rows = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())["platforms"].values()
        self.assertEqual({{"x86_64": "x64", "aarch64": "arm64"}[row["machine"]] for row in rows}, set(legs))
        self.assertIn("          NATIVE_SPDK: ${{ matrix.spdk }}\n", job)
        override = "print(f\"SPDK_PKG_CONFIG_PATH={os.environ['NATIVE_SPDK']}\", file=environment)"
        self.assertIn('              if os.environ["NATIVE_SPDK"]:\n                  ' + override, job,
                      "only a leg naming a native install replaces the pinned SPDK_PKG_CONFIG_PATH")
        self.assertLess(job.index('print(f"{name}={value}", file=environment)'), job.index(override),
                        "the native SPDK install replaces the pinned SPDK_PKG_CONFIG_PATH")
        self.assertIn("    strategy:\n      fail-fast: false\n", job, "one leg's failure leaves the other leg's cases running")
        self.assertIn("evidence-hardware-${{ matrix.arch }}-${{ github.run_id", job)
        guide = (ROOT / "docs/agents/ci.md").read_text()
        self.assertIn("`[self-hosted, linux, arm64, kestrike-hardware]`", guide)
        self.assertIn("native install under `/usr/local`", guide)

    def test_every_rust_job_installs_toolchains_before_its_lane(self):
        jobs = rust_jobs(WORKFLOW.read_text()) | rust_jobs(HARDWARE_WORKFLOW.read_text())
        self.assertEqual(sorted(jobs), sorted(RUST_LANES))
        for lane, body in jobs.items():
            with self.subTest(lane=lane):
                calls = re.findall(r"scripts/rust-lane\.sh ([\w-]+)", body)
                self.assertEqual(calls[:2], ["toolchains", lane])
                self.assertNotIn("needs.preflight.outputs.target-dir", body)

    def test_the_quint_join_judges_the_evidence_of_every_shard_that_ran(self):
        """A shard that fails a case or passes its deadline still uploads its raw evidence, so the join runs after
        every shard result but a skip, and its judgment of that evidence is the lane's receipt; skipped shards ran
        nothing and leave the lane without one. The join's own artifact holds reports alone, so a refused judgment
        uploads the raw shards it read for the 90 days a failed lane keeps its evidence."""
        jobs = workflow_jobs(WORKFLOW.read_text())
        shard, join = jobs[RUNNERS["quint"]], jobs["quint"]
        self.assertIn("    strategy:\n      fail-fast: false\n", shard, "one shard's failure leaves the other's cases running")
        self.assertIn("      - name: Raw shard evidence\n        if: always() && steps.prepare.outputs.path != ''\n", shard)
        self.assertIn("    if: >-\n      always() && needs.quint-shard.result != 'skipped' &&\n"
                      "      (github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch')\n"
                      "    needs: quint-shard\n", join)
        self.assertEqual(re.findall(r"scripts/rust-lane\.sh ([\w-]+)", join), ["summary"], "the join runs no case")
        self.assertEqual(len(re.findall(r"timeout-minutes: (\d+)", join)), 1, join)
        refused = "      - name: Raw shards of a refused judgment\n        if: failure() && steps.prepare.outputs.path != ''\n"
        self.assertIn(refused, join)
        step = join.split(refused, 1)[1].split("\n      - ", 1)[0]
        # The gate downloads every `evidence-*` artifact as a lane and the join every `quint-shard-*` one as a shard.
        self.assertRegex(step, r"name: >-\n\s+quint-refused-\$\{\{ github\.run_id\s+\}\}-\$\{\{ github\.run_attempt \}\}\n")
        self.assertIn("path: ${{ steps.prepare.outputs.path }}/shards\n", step)
        self.assertIn("retention-days: 90\n", step)

    def test_each_qualified_job_spells_its_own_lane_in_every_step(self):
        """The workflow parsers read jobs line by line, so every job spells its steps without YAML anchors or aliases."""
        text = WORKFLOW.read_text()
        self.assertNotRegex(text, r"(?m)^\s*(?:- )?(?:[\w-]+: )?[*&][\w-]+$")
        self.assertNotIn("github.job", text)
        jobs = workflow_jobs(text)
        for job in ("campaigns", "search", "fuzz-smoke", "search-nightly"):
            with self.subTest(job=job):
                body = jobs[job]
                self.assertEqual(re.findall(r"scripts/rust-lane\.sh ([\w-]+)", body), ["toolchains", job, "summary"])
                self.assertIn(f"run: bash scripts/rust-lane.sh summary {job}\n", body)
                self.assertIn(f"verify-receipts.py credit --job {job} --evidence evidence", body)
                self.assertIn(f"evidence-{job}-${{{{ github.run_id", body)

    def test_only_the_tlc_run_step_receives_the_repository_token(self):
        workflow = WORKFLOW.read_text()
        self.assertEqual(workflow.count("github.token"), 1)
        self.assertNotIn("secrets.", workflow)
        self.assertIn(
            "      - name: TLC profile under the pinned JDK and TLA+ tools\n        env:\n"
            "          GH_TOKEN: ${{ github.token }}\n        run: >-\n", workflow_jobs(workflow)["tlc"],
        )

    def test_the_tlc_run_deadline_ends_five_minutes_before_its_workflow_step(self):
        """The run's limit counts from the lane's start, so the tool check, the identity and the run together end
        at least five minutes before the workflow step's `timeout`, which leaves that time to the stop and the
        judgment; a deadline or a step edited alone fails here."""
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        deadline = int(matched(r'deadline "\$\(\((\d+) \* 60 - SECONDS\)\)s" "\$\{argv\[@\]\}" > "\$EVIDENCE/tlc\.txt"',
                               lane)[1])
        step = int(matched(r"--kill-after=\d+s (\d+)m\s+bash scripts/rust-lane\.sh tlc ",
                           workflow_jobs(WORKFLOW.read_text())["tlc"])[1])
        self.assertLessEqual(deadline + 5, step)

    def test_the_tlc_run_deadline_is_what_the_tool_check_and_identity_left(self):
        """The tool check and the identity spend the lane's time before the run, so the run's limit is the lane's
        allowance less that time: an identity that takes two seconds leaves the run at least two seconds less,
        and a slow tool install shortens the run instead of taking the time the stop and the judgment need."""
        declared = json.loads((ROOT / "verification/tlc/expected.json").read_text())
        entry = self.dir / "home/.cache/kestrike-tlc" / f"{declared['java']['sha256'][:16]}-{declared['jar']['sha256'][:16]}"
        entry.mkdir(parents=True)
        (entry / "tla2tools.jar").write_text("")
        # The lane stops the timer as soon as the run exits, so the run stub waits, for up to five seconds, until
        # the timer stub has recorded its limit.
        sleep = shutil.which("sleep")
        stubs = {
            "python3": '#!/usr/bin/env bash\ncase "${1:-} ${2:-}" in\n'
                       f'  "scripts/judge-tlc.py identity") exec {sleep} 2 ;;\n'
                       '  "scripts/judge-tlc.py judge") exit 0 ;;\n'
                       f'  tla/check.py\\ *) for _ in {{1..500}}; do [ ! -s "$STUB_LIMITS" ] || break; {sleep} 0.01; done; exit 0 ;;\n'
                       f'esac\nexec {shutil.which("python3")} "$@"\n',
            "sleep": f'#!/usr/bin/env bash\nprintf "%s\\n" "$1" >> "$STUB_LIMITS"\nexec {sleep} "$@"\n',
        }
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        env = dict(self.env, HOME=str(self.dir / "home"), STUB_LIMITS=str(self.dir / "limits"))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "tlc", "pr"], cwd=ROOT, env=env, capture_output=True,
                              text=True, timeout=60, check=False)
        self.assertEqual(step.returncode, 0, step.stderr)
        limits = (self.dir / "limits").read_text().split()
        self.assertEqual(len(limits), 1, limits)
        amount, unit = matched(r"^(\d+)([sm])$", limits[0]).groups()
        seconds = int(amount) * {"s": 1, "m": 60}[unit]
        allowance = 60 * int(matched(r"deadline \D*(\d+)", matched(r'\n  deadline .* > "\$EVIDENCE/tlc\.txt"',
                                                                (ROOT / "scripts/rust-lane.sh").read_text())[0])[1])
        self.assertLessEqual(seconds, allowance - 2, "the identity's two seconds left the run's limit")
        self.assertGreaterEqual(seconds, allowance - 10, limits)

    def test_every_lane_keeps_its_prerequisite_and_run_deadlines(self):
        jobs = workflow_jobs(WORKFLOW.read_text()) | workflow_jobs(HARDWARE_WORKFLOW.read_text())
        for lane in LANES:
            body = jobs[RUNNERS.get(lane, lane)]
            with self.subTest(lane=lane):
                budgets = [int(m) for m in re.findall(r"--kill-after=\d+s (\d+)m", body)]
                # A job's steps beside its lane, each with its own budget, add to the toolchain and lane steps.
                added = sum(body.count(f"scripts/rust-lane.sh {step}\n") for step in ADDED_STEPS.get(lane, ()))
                self.assertEqual(len(budgets), 2 + added, body)
                timeouts = re.findall(r"timeout-minutes: (\d+)", body)
                self.assertEqual(len(timeouts), 1, body)
                self.assertGreaterEqual(int(timeouts[0]) - sum(budgets), MARGIN_MINUTES)

    def test_each_added_step_keeps_its_own_evidence_and_budget(self):
        """A step beside a job's lane writes a strict subdirectory of the job's evidence, so its red `failure.txt`
        and its controls stay out of the lane's receipt inputs; it runs unless the job was cancelled, and its budget
        covers the deadlines its lane function sets."""
        jobs = workflow_jobs(WORKFLOW.read_text())
        lane_script = (ROOT / "scripts/rust-lane.sh").read_text()
        for job, added in ADDED_STEPS.items():
            body = jobs[job]
            self.assertIn("    env:\n      EVIDENCE: ${{ github.workspace }}/evidence\n", body)
            # A comment line ahead of a step ends the previous step's text.
            steps = [re.sub(r"(\n\s*#.*)+$", "", text) for text in body.split("\n      - ")[1:]]
            directories = {}
            for step, constants in added.items():
                with self.subTest(job=job, step=step):
                    found = [text for text in steps if text.endswith(f"bash scripts/rust-lane.sh {step}")]
                    self.assertEqual(len(found), 1, steps)
                    lane = [index for index, text in enumerate(steps) if text.endswith(f"bash scripts/rust-lane.sh {job}")]
                    self.assertEqual(len(lane), 1, steps)
                    self.assertGreater(steps.index(found[0]), lane[0], "the added step runs after the job's lane")
                    upload = [index for index, text in enumerate(steps) if text.startswith("name: Evidence\n")]
                    self.assertEqual(len(upload), 1, steps)
                    self.assertIn("\n          path: evidence\n", steps[upload[0]])
                    self.assertLess(steps.index(found[0]), upload[0], "the job's evidence upload holds the added step's evidence")
                    self.assertIn("\n        if: ${{ !cancelled() }}\n", found[0])
                    self.assertNotIn("continue-on-error", found[0])
                    self.assertRegex(found[0], rf"\n        run: >-\n          exec timeout --kill-after=60s \d+m\n          bash scripts/rust-lane\.sh {step}$")
                    body_of = re.search(rf"\n{step}\(\) {{\n(.*?)\n}}\n", lane_script, re.DOTALL)
                    self.assertIsNotNone(body_of)
                    # The budget check counts `deadline` commands at the start of a line, directly or through `step NAME`.
                    calls = re.findall(r"^\s*(?:step \w+ )?deadline\s+(\S+)", body_of.group(1), re.MULTILINE)
                    used = [re.fullmatch(r'"\$\{(\w+)\}m"', call) for call in calls]
                    self.assertNotIn(None, used, f"each deadline in the step's function names a minute constant: {calls}")
                    used = [match.group(1) for match in used]
                    self.assertEqual(sorted(set(used)), sorted(constants), "the budget covers every deadline the step's function sets")
                    evidence = re.findall(r"\n          EVIDENCE: \$\{\{ github\.workspace \}\}/evidence/([\w-]+)\n", found[0])
                    self.assertEqual(len(evidence), 1, found[0])
                    self.assertNotIn(evidence[0], directories, "each added step writes its own evidence subdirectory")
                    directories[evidence[0]] = step
                    budget = int(re.search(r"--kill-after=\d+s (\d+)m", found[0]).group(1))
                    minutes = {name: int(re.search(rf"^{name}=(\d+)$", lane_script, re.MULTILINE).group(1)) for name in constants}
                    # The step budget reserves at least five minutes beyond the combined deadlines, counting repeated
                    # calls separately.
                    self.assertGreaterEqual(budget - sum(minutes[name] for name in used), 5, (budget, used))

    def test_the_barrier_scan_runs_on_every_event_with_its_evidence(self):
        body = workflow_jobs(WORKFLOW.read_text())["barriers"]
        self.assertEqual(re.findall(r"scripts/rust-lane\.sh ([\w-]+)", body), ["toolchains", "barriers"])
        self.assertIn("needs: [comment-policy, lane-script, rust-format]", body)
        self.assertNotIn("github.event_name == 'schedule'", body)
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", body)
        self.assertIn("- name: Evidence\n        if: always()", body)
        self.assertIn("retention-days: ${{ job.status == 'success' && 14 || 90 }}", body)
        self.assertIn("if-no-files-found: error", body)
        self.assertIn("python3 scripts/test-scan-barriers.py", WORKFLOW.read_text())

    AARCH64_CPUINFO = ("processor\t: 0\nBogoMIPS\t: 2100.00\nCPU implementer\t: 0x41\nCPU architecture: 8\n"
                       "CPU variant\t: 0x1\nCPU part\t: 0xd40\nCPU revision\t: 1\n\n"
                       "processor\t: 1\nCPU implementer\t: 0x41\nCPU part\t: 0xd40\n")
    X86_CPUINFO = "processor\t: 0\nvendor_id\t: GenuineIntel\nmodel name\t: Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz\n"
    ARTIFACT_PROFILE = {"opt_level": "1", "debuginfo": "line-tables-only", "debug_assertions": True,
                        "overflow_checks": True, "test": True}

    def barriers_lane(self, cpuinfo, demangler="LLVM (http://llvm.org/):\n  LLVM version 22.1.8\n", llvm="22.1.8"):
        """Run `rust-lane.sh barriers` from a copy of the lane that reads `cpuinfo` and a pinned SPDK header, under
        stub native pins, an AArch64 `uname -m`, a stub `llvm-cxxfilt-22` reporting `demangler`, the `LLVM` pin
        `llvm`, a build naming one stub test executable whose declared callers pass, and return the step and its
        evidence directory. The stub executable is no ELF file, so the scan refuses it after the lane has written
        its pins and identity."""
        run = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run / "root", run / "evidence"
        (root / "scripts").mkdir(parents=True)
        (run / "cpuinfo").write_text(cpuinfo)
        (run / "include" / "spdk").mkdir(parents=True)
        (run / "include" / "spdk" / "version.h").write_text("#define SPDK_VERSION_MAJOR 25\n#define SPDK_VERSION_MINOR 5\n"
                                                         "#define SPDK_VERSION_PATCH 1\n")
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        self.assertIn("/proc/cpuinfo", lane)
        lane = lane.replace("/proc/cpuinfo", str(run / "cpuinfo"))
        (root / "scripts/rust-lane.sh").write_text(lane)
        (root / "scripts/scan-barriers.py").symlink_to(ROOT / "scripts/scan-barriers.py")
        (root / "verification").symlink_to(ROOT / "verification")
        exe = run / "kestrike-0000000000000001"
        callers = len(json.loads((ROOT / "verification/barriers/expected.json").read_text())["callers"])
        exe.write_text(f"#!/usr/bin/env bash\necho 'test result: ok. {callers} passed; 0 failed; 0 ignored; 0 measured; "
                       "900 filtered out; finished in 0.01s'\n")
        exe.chmod(0o755)
        messages = [
            {"reason": "compiler-artifact", "executable": None, "profile": dict(self.ARTIFACT_PROFILE, test=False),
             "target": {"name": "kestrike", "kind": ["lib"]}},
            {"reason": "compiler-artifact", "executable": str(exe), "profile": self.ARTIFACT_PROFILE,
             "target": {"name": "kestrike", "kind": ["lib"]}},
            {"reason": "build-finished", "success": True},
        ]
        (run / "build.json").write_text("".join(f"{json.dumps(message)}\n" for message in messages))
        stubs = {
            "uname": f'#!/usr/bin/env bash\n[ "$*" != -m ] || {{ echo aarch64; exit 0; }}\nexec {shutil.which("uname")} "$@"\n',
            "pkg-config": f"#!/usr/bin/env bash\ncase \" $* \" in\n  *' --variable=includedir libdpdk '*) echo {shlex.quote(str(run / 'include'))} ;;\n"
                          "  *) echo 25.03.0 ;;\nesac\n",
            "rustc": "#!/usr/bin/env bash\ncase \" $* \" in\n"
                     "  *' --print cfg '*) printf '%s\\n' 'target_arch=\"aarch64\"' 'target_feature=\"neon\"'\n"
                     f"    {STUB_LSE} ;;\n"
                     '  *) echo "rustc ${1#+} (stub)" ;;\nesac\n',
        }
        stubs["llvm-cxxfilt-22"] = f"#!/usr/bin/env bash\n[ \"$*\" != --version ] || {{ printf '%s' {shlex.quote(demangler)}; exit 0; }}\nexec cat\n"
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        env = dict(self.env, HOME=str(run / "home"), EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(run / "summary.md"),
                   STUB_RUN=str(run / "build.json"), GITHUB_RUN_ID="4242", GITHUB_RUN_ATTEMPT="2", GITHUB_JOB="barriers",
                   LLVM=llvm, STUB_ENV_DUMP=str(run / "cargo-env.txt"), CARGO_ENCODED_RUSTFLAGS="-Ctarget-feature=-lse")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "barriers"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        return step, evidence

    def test_the_hardware_step_writes_only_under_the_artifacts_directory_the_roles_accept(self):
        """A role refuses a checkout holding an untracked file outside `--artifacts`; the step's own log and the
        `toolchains.txt` the job's earlier step left are such files, so the job's evidence tree is the artifacts."""
        run = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run / "root", run / "root" / "evidence"
        (root / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/rust-lane.sh", root / "scripts/rust-lane.sh")
        (root / "scripts/hardware-lane.py").write_text(textwrap.dedent("""\
            import os, subprocess, sys
            status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True)
            untracked = [line[3:] for line in status.stdout.splitlines() if line.startswith("??")]
            artifacts = os.path.relpath(sys.argv[sys.argv.index("--artifacts") + 1])
            stray = [path for path in untracked if not path.startswith(artifacts + "/")]
            print("stray", stray)
            sys.exit(1 if stray else 0)
            """))
        git = ["git", "-c", "user.name=lane", "-c", "user.email=lane@example", "-c", "commit.gpgsign=false"]
        for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "lane"]):
            subprocess.run([*git, *command], cwd=root, check=True, capture_output=True)
        evidence.mkdir()
        (evidence / "toolchains.txt").write_text("installed\n")
        env = dict(self.env, EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(run / "summary.md"))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "hardware"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        log = evidence / "hardware.txt"
        self.assertEqual(step.returncode, 0, f"{step.stderr}\n{log}: {log.read_text() if log.exists() else sorted(evidence.rglob('*'))}")
        self.assertIn("stray []", log.read_text(), "every untracked file the job wrote lies under the artifacts")

    def test_the_fis_step_writes_only_under_the_artifacts_directory_the_cases_accept(self):
        """The controller hands its `--artifacts` to every case, which refuses a checkout holding an untracked file
        outside it; the step's own log, `fis-build.txt` and the `toolchains.txt` the job's earlier step left are such
        files, so the job's evidence tree is the artifacts."""
        run = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run / "root", run / "root" / "evidence"
        (root / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/rust-lane.sh", root / "scripts/rust-lane.sh")
        for script in ("hardware-profiles.json", "hardware-lane.py", "reproduce-test.py", "select-tests.py"):
            shutil.copy(ROOT / "scripts" / script, root / "scripts" / script)
        (root / "scripts/fis-controller.py").write_text(textwrap.dedent("""\
            import os, subprocess, sys
            status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], capture_output=True, text=True)
            untracked = [line[3:] for line in status.stdout.splitlines() if line.startswith("??")]
            artifacts = os.path.relpath(sys.argv[sys.argv.index("--artifacts") + 1])
            stray = [path for path in untracked if not path.startswith(artifacts + "/")]
            print("stray", stray)
            sys.exit(1 if stray else 0)
            """))
        git = ["git", "-c", "user.name=lane", "-c", "user.email=lane@example", "-c", "commit.gpgsign=false"]
        for command in (["init", "-q"], ["add", "."], ["commit", "-q", "-m", "lane"]):
            subprocess.run([*git, *command], cwd=root, check=True, capture_output=True)
        evidence.mkdir()
        (evidence / "toolchains.txt").write_text("installed\n")
        build = self.dir / "run"
        build.write_text("    Finished `test` profile\n")
        env = dict(self.env, EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(run / "summary.md"),
                   HOME=str(self.dir / "home"), KESTRIKE_FIS_OPERATOR=str(self.dir / "operator.json"), STUB_RUN=str(build))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        log = evidence / "fis.txt"
        self.assertEqual(step.returncode, 0, f"{step.stderr}\n{log}: {log.read_text() if log.exists() else sorted(evidence.rglob('*'))}")
        self.assertIn("stray []", log.read_text(), "every untracked file the job wrote lies under the artifacts")

    def test_the_barrier_identity_names_the_scanned_build_and_binds_its_revision(self):
        step, evidence = self.barriers_lane(self.AARCH64_CPUINFO)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the barrier scan exited 2", (evidence / "failure.txt").read_text(), step.stderr)
        identity = json.loads((evidence / "identity.json").read_text())
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        self.assertEqual(identity["profile"], "test")
        self.assertEqual(identity["cargo_profile"], self.ARTIFACT_PROFILE)
        self.assertEqual(identity["lto"], "false")
        self.assertEqual(identity["revision"], revision)
        self.assertEqual(identity["ci"], {"GITHUB_RUN_ID": "4242", "GITHUB_RUN_ATTEMPT": "2", "GITHUB_JOB": "barriers"})
        self.assertEqual(identity["rustflags"], "-C symbol-mangling-version=v0 -C target-feature=+lse")
        # The library-test build, the stub cargo's last call, ran under the flags the identity records, and the
        # encoded variable the caller set, which would replace them, was cleared.
        build_env = env_dump(evidence.parent / "cargo-env.txt")
        self.assertEqual(build_env["RUSTFLAGS"], identity["rustflags"])
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", build_env)
        self.assertEqual(identity["target_features"], ["neon", "lse"])
        self.assertEqual(json.loads((evidence / "report.json").read_text())["identity"], identity)
        summary = (evidence.parent / "summary.md").read_text()
        self.assertIn(f"- revision {revision}, run 4242 attempt 2; the scan gates rust-gate and credits no "
                      "obligation record\n", summary)

    def test_the_barrier_scan_requires_the_pinned_demangler_before_building(self):
        version = "LLVM (http://llvm.org/):\n  LLVM version 22.1.8\n"
        for demangler, llvm, message in ((version, "99.0.0", "llvm-cxxfilt-99 is missing from PATH; provision LLVM 99.0.0 on the runner"),
                                         ("LLVM (http://llvm.org/):\n  LLVM version 22.1.7\n", "22.1.8", "the runner requires LLVM 22.1.8"),
                                         ("", "22.1.8", "the runner requires LLVM 22.1.8")):
            with self.subTest(demangler=demangler, llvm=llvm):
                step, evidence = self.barriers_lane(self.AARCH64_CPUINFO, demangler=demangler, llvm=llvm)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn(message, (evidence / "failure.txt").read_text())
                self.assertFalse((evidence / "build.json").exists())
        step, evidence = self.barriers_lane(self.AARCH64_CPUINFO)
        self.assertIn("the barrier scan exited 2", (evidence / "failure.txt").read_text(), step.stderr)
        report = json.loads((evidence / "report.json").read_text())
        self.assertEqual(report["demangler"]["command"], [str(self.dir / "bin" / "llvm-cxxfilt-22")])
        self.assertEqual(report["demangler"]["version"], ["LLVM (http://llvm.org/):", "  LLVM version 22.1.8"])

    def test_the_lane_pins_name_the_aarch64_core_and_keep_the_x86_cache_key(self):
        import hashlib

        for cpuinfo, cpu in ((self.AARCH64_CPUINFO, "implementer 0x41 part 0xd40"),
                             (self.X86_CPUINFO, "Intel(R) Xeon(R) Platinum 8375C CPU @ 2.90GHz")):
            with self.subTest(cpu=cpu):
                step, evidence = self.barriers_lane(cpuinfo)
                self.assertTrue((evidence / "pins.txt").exists(), step.stderr)
                pins = (evidence / "pins.txt").read_text()
                self.assertIn(f"; CPU {cpu}\n", pins)
                self.assertIn(f"- target cache {hashlib.sha256(f'{cpu} 1.99.0'.encode()).hexdigest()[:16]}\n", pins)
        step, evidence = self.barriers_lane("processor\t: 0\n")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("names no CPU model", (evidence / "failure.txt").read_text())
        self.assertFalse((evidence / "pins.txt").exists())

    def tag_compare_lane(self, lane, machine, objdump="LLVM (http://llvm.org/):\n  LLVM version 22.1.8\n"):
        """Run `rust-lane.sh LANE` for a tag comparison inspection lane under a `uname -m` reporting `machine`, stub
        native pins, stub `llvm-cxxfilt-22` and `llvm-objdump-22` (the latter reporting `objdump`), and a release
        build naming one stub test executable whose caller passes; return the step and its evidence directory. The
        stub executable is no ELF file, so the inspection refuses it after the lane has written its pins and
        identity."""
        run = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run / "root", run / "evidence"
        (root / "scripts").mkdir(parents=True)
        (run / "include" / "spdk").mkdir(parents=True)
        (run / "include" / "spdk" / "version.h").write_text("#define SPDK_VERSION_MAJOR 25\n#define SPDK_VERSION_MINOR 5\n"
                                                         "#define SPDK_VERSION_PATCH 1\n")
        (run / "cpuinfo").write_text(self.AARCH64_CPUINFO if machine == "aarch64" else self.X86_CPUINFO)
        (root / "scripts/rust-lane.sh").write_text((ROOT / "scripts/rust-lane.sh").read_text().replace("/proc/cpuinfo", str(run / "cpuinfo")))
        for script in ("scan-tag-compare.py", "scan-barriers.py", "judge-rc11.py"):
            (root / "scripts" / script).symlink_to(ROOT / "scripts" / script)
        (root / "verification").symlink_to(ROOT / "verification")
        exe = run / "kestrike-0000000000000002"
        exe.write_text("#!/usr/bin/env bash\necho 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; "
                       "900 filtered out; finished in 0.01s'\n")
        exe.chmod(0o755)
        profile = {"opt_level": "3", "debuginfo": 0, "debug_assertions": False, "overflow_checks": False, "test": True}
        messages = [{"reason": "compiler-artifact", "executable": str(exe), "profile": profile,
                     "target": {"name": "kestrike", "kind": ["lib"]}},
                    {"reason": "build-finished", "success": True}]
        (run / "build.json").write_text("".join(f"{json.dumps(message)}\n" for message in messages))
        version = "LLVM (http://llvm.org/):\n  LLVM version 22.1.8\n"
        stubs = {
            "uname": f'#!/usr/bin/env bash\n[ "$*" != -m ] || {{ echo {machine}; exit 0; }}\nexec {shutil.which("uname")} "$@"\n',
            "pkg-config": f"#!/usr/bin/env bash\ncase \" $* \" in\n  *' --variable=includedir libdpdk '*) echo {shlex.quote(str(run / 'include'))} ;;\n"
                          "  *) echo 25.03.0 ;;\nesac\n",
            "rustc": "#!/usr/bin/env bash\ncase \" $* \" in\n"
                     "  *' --print cfg '*) printf '%s\\n' 'target_feature=\"neon\"' 'target_feature=\"aes\"'\n"
                     f"    {STUB_LSE} ;;\n"
                     '  *) echo "rustc ${1#+} (stub)" ;;\nesac\n',
            "llvm-cxxfilt-22": f"#!/usr/bin/env bash\n[ \"$*\" != --version ] || {{ printf '%s' {shlex.quote(version)}; exit 0; }}\nexec cat\n",
            "llvm-objdump-22": f"#!/usr/bin/env bash\n[ \"$*\" != --version ] || {{ printf '%s' {shlex.quote(objdump)}; exit 0; }}\nexit 3\n",
        }
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        env = dict(self.env, HOME=str(run / "home"), EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(run / "summary.md"),
                   STUB_RUN=str(run / "build.json"), GITHUB_RUN_ID="4243", GITHUB_RUN_ATTEMPT="1", GITHUB_JOB=lane,
                   LLVM="22.1.8", STUB_ENV_DUMP=str(run / "cargo-env.txt"), CARGO_ENCODED_RUSTFLAGS="-Ctarget-feature=-lse")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", lane], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        return step, evidence, exe

    def test_the_tag_compare_lane_binds_the_release_build_and_refuses_another_host_or_objdump(self):
        step, evidence, exe = self.tag_compare_lane("tag-compare-aarch64", "aarch64")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the inspection exited 2 before writing report.json", (evidence / "failure.txt").read_text())
        identity = json.loads((evidence / "identity.json").read_text())
        self.assertEqual((identity["profile"], identity["lto"], identity["rustflags"], identity["target_features"]),
                         ("release", "false", "-C symbol-mangling-version=v0 -C target-feature=+lse", ["neon", "aes", "lse"]))
        build_env = env_dump(evidence.parent / "cargo-env.txt")
        self.assertEqual(build_env["RUSTFLAGS"], identity["rustflags"])
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", build_env)
        self.assertEqual(identity["sha256"], hashlib.sha256(exe.read_bytes()).hexdigest())
        self.assertIn("CARGO_PROFILE_RELEASE_LTO", identity["profile_env"])
        self.assertIn("- objdump LLVM (http://llvm.org/):   LLVM version 22.1.8", (evidence / "pins.txt").read_text())
        step, evidence, _ = self.tag_compare_lane("tag-compare-x86-64", "x86_64")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the inspection exited 2 before writing report.json", (evidence / "failure.txt").read_text())
        identity = json.loads((evidence / "identity.json").read_text())
        self.assertEqual((identity["rustflags"], identity["target_features"]), ("-C symbol-mangling-version=v0", ["neon", "aes"]), step.stderr)
        build_env = env_dump(evidence.parent / "cargo-env.txt")
        self.assertEqual(build_env["RUSTFLAGS"], "-C symbol-mangling-version=v0")
        self.assertNotIn("CARGO_ENCODED_RUSTFLAGS", build_env)
        for lane, machine, objdump, message in (
                ("tag-compare-x86-64", "aarch64", None, "tag-compare-x86-64 inspects x86-64 code; this host is aarch64"),
                ("tag-compare-aarch64", "x86_64", None, "tag-compare-aarch64 inspects aarch64 code; this host is x86_64"),
                ("tag-compare-aarch64", "aarch64", "LLVM version 15.0.7\n", "the runner requires LLVM 22.1.8")):
            with self.subTest(lane=lane, machine=machine):
                step, evidence, _ = self.tag_compare_lane(lane, machine, *([objdump] if objdump else []))
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn(message, (evidence / "failure.txt").read_text())
                self.assertFalse((evidence / "build.json").exists())

    TSAN_CONTROL = "storage::gate::tests::negative_control_a_relaxed_take_races_the_guarded_counter"
    TSAN_POSITIVE = "storage::gate::tests::contending_takers_and_waiters_never_overlap_and_see_each_other"
    TSAN_LIST = (f"storage::gate::tests::gate_is_exclusive_and_reopens_on_release: test\n{TSAN_POSITIVE}: test\n{TSAN_CONTROL}: test\n"
                 "index::bucket::tests::a_bucket_holds_its_chains: test\n"
                 "net::client::route_tests::a_route_reaches_its_peer: test\n\n5 tests, 0 benchmarks\n")
    TSAN_PASSED = (f"test {TSAN_POSITIVE} ... ok\ntest index::bucket::tests::a_bucket_holds_its_chains ... ok\n"
                   "test net::client::route_tests::a_route_reaches_its_peer ... ok\n")
    TSAN_RESULT = "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 6100 filtered out; finished in 9.10s\n"
    # Report texts a control's process may write, by kind, trimmed from the aarch64 runtime's report: the racing
    # access's frames, then the creation stacks, which name the workload for any race between its threads.
    TSAN_CREATED = ("  Thread T3 (tid=4246, running) created by main thread at:\n"
                    "    #1 std::thread::scoped::Scope::spawn::<kestrike::storage::gate::tests::contend<…>::{closure#0}::{closure#0}> "
                    "scoped.rs:179\n")
    TSAN_RACE_FRAMES = ("WARNING: ThreadSanitizer: data race (pid=4243)\n  Read of size 8 at 0xffff953eb0e0 by thread T3:\n"
                        "    #0 {closure#0}<kestrike::storage::gate::WeakGate<core::sync::atomic::Atomic<u32>, true>> "
                        "/src/crates/kestrike/src/storage/gate.rs:355:34 (kestrike+0x40715b0)\n"
                        "    #1 std::sys::backtrace::__rust_begin_short_backtrace::<kestrike::storage::gate::tests::contend<…>::{closure#0}> "
                        "backtrace.rs:166:18\n" + TSAN_CREATED)
    TSAN_RACE_SUMMARY = "SUMMARY: ThreadSanitizer: data race /src/crates/kestrike/src/storage/gate.rs:355:34 in {closure#0}<…WeakGate…>\n"
    # A tuple is one report file per process, in order.
    TSAN_REPORTS = {
        "race": "==================\n" + TSAN_RACE_FRAMES + TSAN_RACE_SUMMARY + "==================\n",
        "other-frame": ("WARNING: ThreadSanitizer: data race (pid=4243)\n  Write of size 8 at 0x7b0400000010 by thread T2:\n"
                        "    #0 std::sync::poison::mutex::Mutex::lock /rust/library/std/src/sync/poison/mutex.rs:400:9\n" + TSAN_CREATED +
                        "SUMMARY: ThreadSanitizer: data race /rust/library/std/src/sync/poison/mutex.rs:400:9 in Mutex::lock\n"),
        "other-kind": ("WARNING: ThreadSanitizer: lock-order-inversion (potential deadlock) (pid=4243)\n"
                       "    #0 {closure#0} /src/crates/kestrike/src/storage/gate.rs:355:34\n" + TSAN_CREATED +
                       "SUMMARY: ThreadSanitizer: lock-order-inversion (potential deadlock) /src/crates/kestrike/src/storage/gate.rs:355:34 "
                       "in {closure#0}<\u2026WeakGate\u2026>\n"),
        "no-workload": TSAN_RACE_FRAMES.replace("storage::gate::tests::contend", "storage::gate::tests::other") + TSAN_RACE_SUMMARY,
        "split": (TSAN_RACE_FRAMES, "WARNING: ThreadSanitizer: data race (pid=4244)\n" + TSAN_RACE_SUMMARY),
    }

    def tsan_lane(self, machine="aarch64", symbolizer="usable", listing=None, list_exit=0, run=None, run_exit=0, run_report=False,
                  report="race", report_to="file", control_exit=66, cut=None, stale=None, relative=False, linked=False,
                  evidence_name="evidence"):
        """Run `rust-lane.sh tsan` under a `uname -m` reporting `machine`, stub native pins and a stub cargo that
        works in the package directory, as Cargo runs tests, whose listing prints `listing` and exits `list_exit`,
        and whose run prints `run` (with `@EXE@` naming the stub test executable) and exits `run_exit`, writing a
        report under the run's log_path when `run_report`. The run names a stub test executable whose control run
        writes the `TSAN_REPORTS` texts `report` (none for None) to its log_path files, or to stderr when
        `report_to` is `stderr`, then exits `control_exit`. `cut` (`build`, `run` or `control`) sets that phase's
        deadline to one second, which starts counting once the phase has written its report and begun to sleep
        past it. `stale` maps evidence-relative paths to files placed before the step. `symbolizer` is `usable`,
        `broken` (its `--version` fails) or `absent` (PATH holds no llvm-symbolizer). The evidence directory is
        `evidence_name` beside the checkout, passed relative to the lane's working directory when `relative`, and
        reached through a directory symlink when `linked`. HOME holds a space. The ambient environment asks Cargo
        for a colored, quiet and verbose display. The stub cargo fails as Cargo does when a call keeps both quiet and
        verbose, and otherwise applies the settings a call keeps to the run's `Running` status line as Cargo does:
        colored wraps the word in escapes, quiet drops the line, and verbose replaces the line with the backquoted
        command line, which holds the skipped control's ID. Return the step, its evidence directory and the cargo and
        executable call logs."""
        run_dir = Path(tempfile.mkdtemp(dir=self.dir))
        if linked:
            (run_dir.parent / f"{run_dir.name}-link").symlink_to(run_dir)
            run_dir = run_dir.parent / f"{run_dir.name}-link"
        root, evidence = run_dir / "root", run_dir / evidence_name
        (root / "scripts").mkdir(parents=True)
        (run_dir / "include" / "spdk").mkdir(parents=True)
        (run_dir / "include" / "spdk" / "version.h").write_text("#define SPDK_VERSION_MAJOR 25\n#define SPDK_VERSION_MINOR 5\n"
                                                             "#define SPDK_VERSION_PATCH 1\n")
        (run_dir / "cpuinfo").write_text(self.AARCH64_CPUINFO)
        lane = (ROOT / "scripts/rust-lane.sh").read_text().replace("/proc/cpuinfo", str(run_dir / "cpuinfo"))
        phase = {"build": "TSAN_BUILD_MINUTES", "run": "TSAN_RUN_MINUTES", "control": "TSAN_CONTROL_MINUTES"}.get(cut)
        if phase:
            self.assertIn(f'deadline "${{{phase}}}m"', lane)
            lane = lane.replace(f'deadline "${{{phase}}}m"', "deadline 1")
        (root / "scripts/rust-lane.sh").write_text(lane)
        for name, text in (stale or {}).items():
            (evidence / name).parent.mkdir(parents=True, exist_ok=True)
            (evidence / name).write_text(text, encoding="utf-8")
        calls, executions = run_dir / "cargo-calls", run_dir / "exe-calls"
        exe = run_dir / "kestrike-0000000000000003"
        texts = () if report is None else self.TSAN_REPORTS[report]
        texts = (texts,) if isinstance(texts, str) else texts
        # The one-second deadline starts after the cut phase touches `ready`, so any report writes finish before the
        # countdown.
        ready = shlex.quote(str(run_dir / "ready"))
        lines = ["#!/usr/bin/env bash", f'echo "$0 $* | $TSAN_OPTIONS" >> {shlex.quote(str(executions))}']
        for index, text in enumerate(texts):
            target = f'"${{TSAN_OPTIONS##*log_path=}}.{4243 + index}"' if report_to == "file" else "/dev/stderr"
            lines.append(f"printf '%s' {shlex.quote(text)} > {target}")
        lines += [f'[ {int(cut == "control")} = 0 ] || {{ touch {ready}; sleep 5; }}', f"exit {control_exit}"]
        exe.write_text("\n".join(lines) + "\n", encoding="utf-8")
        exe.chmod(0o755)
        self.assertTrue(exe.read_bytes().startswith(b"#!/usr/bin/env bash\n"))
        if run is None:
            run = f"     Running unittests src/lib.rs (@EXE@)\n\nrunning 3 tests\n{self.TSAN_PASSED}\n{self.TSAN_RESULT}\n"
        (run_dir / "list.txt").write_text(self.TSAN_LIST if listing is None else listing)
        run = run.replace("@EXE@", str(exe))
        status = re.compile(r"^( *Running)( .*\n)", re.MULTILINE)
        (run_dir / "run.txt").write_text(run)
        (run_dir / "run-colored.txt").write_text(status.sub("\x1b[1m\x1b[92m\\1\x1b[0m\\2", run))
        (run_dir / "run-quiet.txt").write_text(status.sub("", run))
        command = f"\\1 `\\2 'storage::' 'index::' 'net::client::route' --skip '{self.TSAN_CONTROL}'`\n"
        (run_dir / "run-verbose.txt").write_text(re.sub(r"^( *Running) unittests src/lib\.rs \((.*)\)\n", command, run,
                                                        flags=re.MULTILINE))
        cargo = textwrap.dedent(f"""\
            #!/usr/bin/env bash
            echo "$* | RUSTFLAGS=$RUSTFLAGS | TSAN_OPTIONS=$TSAN_OPTIONS | encoded=${{CARGO_ENCODED_RUSTFLAGS-unset}} | opt=$CARGO_PROFILE_DEV_OPT_LEVEL | debug=${{CARGO_PROFILE_DEV_DEBUG-unset}} | color=${{CARGO_TERM_COLOR-unset}} | quiet=${{CARGO_TERM_QUIET-unset}} | verbose=${{CARGO_TERM_VERBOSE-unset}} | target=$CARGO_TARGET_DIR" >> {shlex.quote(str(calls))}
            shown=run.txt
            [ "${{CARGO_TERM_COLOR-}}" != always ] || shown=run-colored.txt
            [ "${{CARGO_TERM_VERBOSE-}}" != true ] || shown=run-verbose.txt
            [ "${{CARGO_TERM_QUIET-}}" != true ] || shown=run-quiet.txt
            [ "${{CARGO_TERM_QUIET-}}${{CARGO_TERM_VERBOSE-}}" != truetrue ] || {{ echo 'error: cannot set both `term.verbose` and `term.quiet`' >&2; exit 101; }}
            mkdir -p crates/kestrike && cd crates/kestrike
            case " $* " in
              *" fuzz --version "*) echo "cargo-fuzz $CARGO_FUZZ"; exit 0 ;;
              *" --list "*)
                [ {int(cut == "build")} = 0 ] || {{ touch {ready}; sleep 5; }}
                cat {shlex.quote(str(run_dir / 'list.txt'))}; exit {list_exit} ;;
              *" --skip "*)
                [ {int(run_report)} = 0 ] || printf 'WARNING: ThreadSanitizer: data race\\n' > "${{TSAN_OPTIONS##*log_path=}}.4242"
                [ {int(cut == "run")} = 0 ] || {{ touch {ready}; sleep 5; }}
                cat {shlex.quote(str(run_dir))}/"$shown"; exit {run_exit} ;;
            esac
            echo "unexpected cargo $*" >&2; exit 97
            """)
        sleep = shutil.which("sleep")
        stubs = {
            "cargo": cargo,
            "uname": f'#!/usr/bin/env bash\n[ "$*" != -m ] || {{ echo {machine}; exit 0; }}\nexec {shutil.which("uname")} "$@"\n',
            "pkg-config": f"#!/usr/bin/env bash\ncase \" $* \" in\n  *' --variable=includedir libdpdk '*) echo {shlex.quote(str(run_dir / 'include'))} ;;\n"
                          "  *) echo 25.03.0 ;;\nesac\n",
            "sleep": (f'#!/usr/bin/env bash\n[ "$*" != 1 ] || for _ in $(seq 600); do [ ! -e {ready} ] || break; {sleep} 0.05; done\n'
                      f'exec {sleep} "$@"\n'),
        }
        bin_dir = run_dir / "bin"
        bin_dir.mkdir()
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        if symbolizer != "absent":
            self.symbolizer_stub(usable=symbolizer == "usable", directory=bin_dir)
        env = {name: value for name, value in self.env.items() if name not in {"CARGO_PROFILE_DEV_DEBUG", "CARGO_PROFILE_DEV_OPT_LEVEL"}}
        env.update(PATH=f"{bin_dir}:{self.tsan_system()}", HOME=str(run_dir / "home dir"),
                   EVIDENCE=f"../{evidence_name}" if relative else str(evidence),
                   GITHUB_STEP_SUMMARY=str(run_dir / "summary.md"), CARGO_ENCODED_RUSTFLAGS="--cfg ambient",
                   CARGO_TERM_COLOR="always", CARGO_TERM_QUIET="true", CARGO_TERM_VERBOSE="true")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "tsan"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=120, check=False)
        read = lambda path: path.read_text() if path.exists() else ""
        return step, evidence, read(calls), read(executions)

    def tsan_system(self):
        """A directory linking every command on this test's PATH except llvm-symbolizer, first entry per name, so a
        host llvm-symbolizer stays off the tsan fixture's PATH; built once per test."""
        system = self.dir / "tsan-system"
        if not system.exists():
            system.mkdir()
            for directory in self.env["PATH"].split(os.pathsep):
                if not os.path.isdir(directory):
                    continue
                for entry in os.scandir(directory):
                    if entry.name != "llvm-symbolizer" and not os.path.lexists(system / entry.name):
                        (system / entry.name).symlink_to(entry.path)
        return system

    def test_the_tsan_step_runs_the_selection_then_requires_the_control_to_race(self):
        step, evidence, calls, executions = self.tsan_lane()
        self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
        build = "+nightly-2026-07-27 test -Zbuild-std --target aarch64-unknown-linux-gnu -p kestrike --lib --"
        self.assertIn(f"{build} --list | RUSTFLAGS=-Zsanitizer=thread -C target-feature=+lse |", calls)
        self.assertIn(f"{build} storage:: index:: net::client::route --skip {self.TSAN_CONTROL} |", calls)
        self.assertIn("TSAN_OPTIONS=halt_on_error=0 allocator_may_return_null=1 log_path=" + str(evidence / "tsan-run/report"), calls)
        # An ambient encoded flag variable would replace RUSTFLAGS; the build runs without it, at the lanes' profile,
        # in a target cache of its own.
        # The step needs Cargo's `Running` line visible, uncolored and in its concise form to extract the executable path.
        self.assertEqual(len(re.findall(r"\| encoded=unset \| opt=1 \| debug=line-tables-only \| color=never \| quiet=false "
                                        r"\| verbose=false \| target=[^|\n]+-tsan\n", calls)), 2, calls)
        self.assertEqual((evidence / "exit.txt").read_text(), "0\n")
        target = re.search(r"\| target=([^|\n]+-tsan)\n", calls).group(1)
        self.assertIn(" ", target, "HOME holds a space, so the replay must quote the target directory")
        replay = [shlex.split(line) for line in (evidence / "replay.txt").read_text().splitlines()]
        self.assertEqual(replay, [
            ["env", "-u", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_DEV_OPT_LEVEL=1", "CARGO_PROFILE_DEV_DEBUG=line-tables-only",
             "CARGO_TERM_COLOR=never", "CARGO_TERM_QUIET=false", "CARGO_TERM_VERBOSE=false",
             f"CARGO_TARGET_DIR={target}", f"SPDK_PKG_CONFIG_PATH={self.env['SPDK_PKG_CONFIG_PATH']}",
             "RUSTFLAGS=-Zsanitizer=thread -C target-feature=+lse",
             f"TSAN_OPTIONS=halt_on_error=0 allocator_may_return_null=1 log_path={evidence / 'tsan-run/report'}",
             "cargo", "+nightly-2026-07-27", "test", "-Zbuild-std", "--target", "aarch64-unknown-linux-gnu", "-p", "kestrike",
             "--lib", "--", "storage::", "index::", "net::client::route", "--skip", self.TSAN_CONTROL],
            ["env", f"TSAN_OPTIONS=halt_on_error=1 allocator_may_return_null=1 log_path={evidence / 'tsan-control/report'}",
             str(evidence.parent / "kestrike-0000000000000003"), "--exact", self.TSAN_CONTROL]])
        # The control runs alone, by exact ID, in the executable the run named, halting on its first report.
        self.assertEqual(executions.count("\n"), 1, executions)
        self.assertRegex(executions, rf"kestrike-0000000000000003 --exact {re.escape(self.TSAN_CONTROL)} \| halt_on_error=1 "
                                     rf"allocator_may_return_null=1 log_path={re.escape(str(evidence / 'tsan-control/report'))}\n")
        self.assertEqual((evidence / "controls.txt").read_text(), f"{self.TSAN_CONTROL}\t66\tfound\n")
        self.assertIn("RUSTFLAGS=-Zsanitizer=thread -C target-feature=+lse; TSAN_OPTIONS=halt_on_error=0", (evidence / "pins.txt").read_text())
        self.assertIn(f"- llvm-symbolizer {evidence.parent / 'bin/llvm-symbolizer'}; LLVM (http://llvm.org/): LLVM version 22.1.8\n",
                      (evidence / "pins.txt").read_text())
        summary = (evidence.parent / "summary.md").read_text()
        for filter, listed in (("storage::", 3), ("index::", 1), ("net::client::route", 1)):
            self.assertIn(f"- ThreadSanitizer filter {filter} lists {listed} tests by prefix\n", summary)
        for filter, passed in (("storage::", 1), ("index::", 1), ("net::client::route", 1)):
            self.assertIn(f"- ThreadSanitizer filter {filter} passed {passed} tests\n", summary)
        self.assertIn("- this step credits no obligation record; a clean run judges only the schedules that ran and is no evidence "
                      "about reordering on a weakly ordered CPU\n", summary)
        self.assertFalse((evidence / "failure.txt").exists())

    def test_the_tsan_step_clears_earlier_reports_and_records_before_it_runs(self):
        """Reports and records an earlier invocation left in the evidence directory neither fail a clean run nor
        stand in for this run's control or verdict."""
        with self.subTest(case="a selection report and a failure record"):
            step, evidence, _, _ = self.tsan_lane(stale={"tsan-run/report.1": self.TSAN_REPORTS["race"], "failure.txt": "old\n"})
            self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
            self.assertFalse((evidence / "failure.txt").exists())
        with self.subTest(case="a control report"):
            step, evidence, _, _ = self.tsan_lane(report=None, stale={"tsan-control/report.1": self.TSAN_REPORTS["race"]})
            self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
            self.assertIn("exited 66 with its report absent", (evidence / "failure.txt").read_text())
        with self.subTest(case="a passing control record and exit record"):
            step, evidence, _, _ = self.tsan_lane(list_exit=101, stale={"controls.txt": f"{self.TSAN_CONTROL}\t66\tfound\n",
                                                                        "exit.txt": "0\n"})
            self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
            self.assertIn("list failed", (evidence / "failure.txt").read_text())
            self.assertFalse((evidence / "controls.txt").exists())
            self.assertFalse((evidence / "exit.txt").exists())

    def test_the_tsan_step_reads_reports_at_the_evidence_path_cargo_s_test_processes_write(self):
        """The stub cargo runs the tests from the package directory, as Cargo does. A relative EVIDENCE still
        collects the run's reports, a symlinked one keeps its spelling, and a path TSAN_OPTIONS cannot carry in
        log_path is refused before any build."""
        with self.subTest(case="relative"):
            step, evidence, _, _ = self.tsan_lane(relative=True)
            self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
        with self.subTest(case="relative with a run report"):
            step, evidence, _, executions = self.tsan_lane(relative=True, run_report=True)
            self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
            self.assertIn("the sanitized run wrote reports report.4242", (evidence / "failure.txt").read_text())
            self.assertEqual(executions, "")
        with self.subTest(case="linked"):
            step, evidence, calls, executions = self.tsan_lane(linked=True)
            self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
            self.assertIn(f"log_path={evidence / 'tsan-run/report'} |", calls)
            self.assertIn(f"log_path={evidence / 'tsan-control/report'}\n", executions)
        for name, options in (("a space", {"evidence_name": "evi dence"}), ("a colon", {"evidence_name": "evi:dence"}),
                              ("a comma in a relative path's ancestor", {"evidence_name": "a,b/evidence", "relative": True})):
            with self.subTest(case=name):
                step, evidence, calls, executions = self.tsan_lane(**options)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertIn("holds a character TSAN_OPTIONS cannot carry in log_path", (evidence / "failure.txt").read_text())
                self.assertEqual((calls, executions), ("", ""))

    def test_the_tsan_constants_name_the_gate_workload_and_its_miri_roles(self):
        """The lane's control, positive test and frame name functions of the gate's tests, and the control and
        positive test hold the Miri lane's control and test roles, so a rename the lane misses fails here."""
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        constants = {name: re.search(rf"^{name}=(\S+)$", lane, re.MULTILINE).group(1)
                     for name in ("TSAN_CONTROL", "TSAN_POSITIVE", "TSAN_FRAME")}
        self.assertEqual((constants["TSAN_CONTROL"], constants["TSAN_POSITIVE"]), (self.TSAN_CONTROL, self.TSAN_POSITIVE))
        gate = (ROOT / "crates/kestrike/src/storage/gate.rs").read_text()
        for name, value in constants.items():
            with self.subTest(constant=name):
                self.assertTrue(value.startswith("storage::gate::tests::"), value)
                self.assertRegex(gate, rf"\n    fn {re.escape(value.rsplit('::', 1)[1])}\b[<(]")
        select = load("select_tests", ROOT / "scripts/select-tests.py")
        miri = select.load_inventory(select.INVENTORY)["miri"]
        self.assertIn(constants["TSAN_CONTROL"], [control["test"] for control in miri["controls"]])
        self.assertIn(constants["TSAN_POSITIVE"], miri["tests"])

    NO_CREDIT = "- this step credits no obligation record;"
    TSAN_RECORDS = ("pins", "pkg-config", "replay", "list", "run", "exit", "control", "controls", "failure")

    def test_the_tsan_step_refuses_another_host_or_a_missing_symbolizer_before_building(self):
        stale = {f"{name}.txt": "old\n" for name in self.TSAN_RECORDS}
        stale.update({"tsan-run/report.1": "old\n", "tsan-control/report.1": "old\n"})
        for machine, symbolizer, message in (("x86_64", "usable", "the ThreadSanitizer run needs a native AArch64 host, not x86_64"),
                                             ("aarch64", "absent", "llvm-symbolizer is missing from PATH"),
                                             ("aarch64", "broken", "llvm-symbolizer --version failed")):
            with self.subTest(machine=machine, symbolizer=symbolizer):
                step, evidence, calls, executions = self.tsan_lane(machine=machine, symbolizer=symbolizer, stale=stale)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn(message, (evidence / "failure.txt").read_text())
                self.assertEqual((calls, executions), ("", ""))
                summary = (evidence.parent / "summary.md").read_text()
                self.assertIn(self.NO_CREDIT, summary)
                self.assertIn(f"- red: {message}", summary)
                # The TSAN step clears stale reports and records before writing failure.txt for a refused invocation.
                self.assertEqual(sorted(path.name for path in evidence.iterdir()), ["failure.txt"])

    def test_the_tsan_step_fails_each_unclean_run_before_the_control(self):
        absent = str(self.dir / "absent")
        clean = lambda body, exe=absent: f"     Running unittests src/lib.rs ({exe})\n\nrunning 3 tests\n{body}\n"
        cases = (
            ("a failed listing", dict(list_exit=101), "list failed"),
            ("a cut build", dict(cut="build"), "list failed"),
            ("an empty filter", dict(listing=self.TSAN_LIST.replace("index::bucket", "storage::index::bucket")),
             "no listed test starts with the filter index::"),
            ("a listing without the control", dict(listing=self.TSAN_LIST.replace(f"{self.TSAN_CONTROL}: test\n", "")),
             "compiled without cfg(kestrike_tsan)"),
            ("a report beside exit 0", dict(run_report=True), "the sanitized run wrote reports report.4242"),
            ("a failed test", dict(run_exit=101, run=clean(self.TSAN_PASSED + "test storage::x ... FAILED\n\ntest result: FAILED. 3 passed; 1 failed;")),
             "the sanitized run exited 101"),
            ("a cut run", dict(cut="run"), "the sanitized run reached its"),
            ("a cut run after a report", dict(cut="run", run_report=True),
             "deadline after writing reports report.4242; see run.txt and tsan-run/"),
            ("a 0 passed summary", dict(run=clean("test result: ok. 0 passed; 0 failed; 0 ignored;")), "reported no passing test result"),
            ("no positive gate line", dict(run=clean(self.TSAN_PASSED.replace(f"test {self.TSAN_POSITIVE} ... ok\n", "") + self.TSAN_RESULT)),
             f"no passing line for {self.TSAN_POSITIVE}"),
            ("a run that executed the control", dict(run=clean(self.TSAN_PASSED + f"test {self.TSAN_CONTROL} ... ok\n" + self.TSAN_RESULT)),
             f"the sanitized run executed {self.TSAN_CONTROL}"),
            ("a filter whose tests were all ignored",
             dict(run=clean(self.TSAN_PASSED.replace("index::bucket::tests::a_bucket_holds_its_chains ... ok",
                                                     "index::bucket::tests::a_bucket_holds_its_chains ... ignored\n"
                                                     "test storage::index::bucket::tests::a_nested_bucket ... ok") + self.TSAN_RESULT)),
             "passed no test that starts with the filter index::"),
            ("an executable that does not exist", dict(run=clean(self.TSAN_PASSED + self.TSAN_RESULT)),
             "names no one library-test executable"),
            ("two executables", dict(run=clean(self.TSAN_PASSED + self.TSAN_RESULT, exe="@EXE@") + "     Running unittests src/lib.rs (@EXE@)\n"),
             "names no one library-test executable"),
        )
        for name, options, message in cases:
            with self.subTest(case=name):
                step, evidence, _, executions = self.tsan_lane(**options)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertIn(message, (evidence / "failure.txt").read_text())
                self.assertEqual(executions, "", "the control ran after a refused run")
                self.assertIn(self.NO_CREDIT, (evidence.parent / "summary.md").read_text())
                if options.get("cut"):
                    self.assertEqual((evidence / "exit.txt").read_text(), "124\n")

    def test_the_tsan_step_fails_each_control_without_its_race_report(self):
        """The control must exit nonzero inside its deadline and write one report file holding a data race summarized
        in storage/gate.rs and a frame of the gate's contention workload; each condition fails the step on its own."""
        for name, options, record in (
                ("a race report beside exit 0", dict(control_exit=0), "0\tfound"),
                ("a race report and a cut control", dict(cut="control"), "124\tfound"),
                ("no report", dict(report=None, control_exit=101), "101\tabsent"),
                ("a race summarized outside gate.rs", dict(report="other-frame"), "66\tabsent"),
                ("a gate.rs race outside the workload", dict(report="no-workload"), "66\tabsent"),
                ("the summary and the frame in two files", dict(report="split"), "66\tabsent"),
                ("another report kind in the workload", dict(report="other-kind"), "66\tabsent"),
                ("the race on stderr alone", dict(report_to="stderr"), "66\tabsent")):
            with self.subTest(case=name):
                step, evidence, _, _ = self.tsan_lane(**options)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertEqual((evidence / "controls.txt").read_text(), f"{self.TSAN_CONTROL}\t{record}\n")
                code, found = record.split("\t")
                self.assertIn(f"exited {code} with its report {found}", (evidence / "failure.txt").read_text())
                self.assertIn(self.NO_CREDIT, (evidence.parent / "summary.md").read_text())
                control = shlex.split((evidence / "replay.txt").read_text().splitlines()[-1])
                self.assertEqual(control[2:], [str(evidence.parent / "kestrike-0000000000000003"), "--exact", self.TSAN_CONTROL])
                self.assertTrue(control[1].startswith("TSAN_OPTIONS=halt_on_error=1 "), control)
                if code == "124":
                    self.assertEqual((evidence / "exit.txt").read_text(), "124\n")

    LITMUS = (("storage::litmus_tests::a_parked_credit_keeps_its_record_flagged_against_a_scan", "credit"),
              ("storage::litmus_tests::a_pinned_reader_is_seen_by_a_pass_that_starts_past_the_bump", "grace"),
              ("storage::litmus_tests::a_departed_failure_is_seen_with_its_terminal", "fill"))

    def litmus_output(self, lines=None):
        """A run's output: one `ok` test per loop, each printing `lines[name]` (by default a clean line)."""
        lines = lines or {}
        body = "".join(f"test {test} ... {lines.get(name, f'litmus: {name} ran 10000000 rounds; aarch64 forbidden=0 control=1500')}\nok\n"
                       for test, name in self.LITMUS)
        return f"\nrunning 3 tests\n{body}\ntest result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 6168 filtered out\n"

    def litmus_lane(self, machine="aarch64", run=None, run_exit=0, build_exit=0, cut=None, locale=None):
        """Run `rust-lane.sh litmus` under a `uname -m` reporting `machine`, stub native pins and a stub cargo whose
        build exits `build_exit` and whose run prints `run` and exits `run_exit`; `cut` (`build` or `run`) sets
        that phase's deadline to one second and makes it sleep past it. `run` may be bytes. `locale` holds the only
        locale variables the lane's environment carries, by default `LC_ALL=C.UTF-8`; ambient flag and profile
        variables conflict with the lane's own. Return the step, its evidence directory and the cargo call log."""
        run_dir = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run_dir / "root", run_dir / "evidence"
        (root / "scripts").mkdir(parents=True)
        (run_dir / "include" / "spdk").mkdir(parents=True)
        (run_dir / "include" / "spdk" / "version.h").write_text("#define SPDK_VERSION_MAJOR 25\n#define SPDK_VERSION_MINOR 5\n"
                                                             "#define SPDK_VERSION_PATCH 1\n")
        (run_dir / "cpuinfo").write_text(self.AARCH64_CPUINFO)
        lane = (ROOT / "scripts/rust-lane.sh").read_text().replace("/proc/cpuinfo", str(run_dir / "cpuinfo"))
        if cut:
            phase = {"build": "LITMUS_BUILD_MINUTES", "run": "LITMUS_RUN_MINUTES"}[cut]
            self.assertIn(f'deadline "${{{phase}}}m"', lane)
            lane = lane.replace(f'deadline "${{{phase}}}m"', "deadline 1")
        (root / "scripts/rust-lane.sh").write_text(lane)
        run = self.litmus_output() if run is None else run
        (run_dir / "run.txt").write_bytes(run if isinstance(run, bytes) else run.encode())
        calls = run_dir / "cargo-calls"
        stubs = {
            "cargo": textwrap.dedent(f"""\
                #!/usr/bin/env bash
                echo "$* | RUSTFLAGS=${{RUSTFLAGS-unset}} | encoded=${{CARGO_ENCODED_RUSTFLAGS-unset}} | opt=$CARGO_PROFILE_DEV_OPT_LEVEL | debug=$CARGO_PROFILE_DEV_DEBUG | target=$CARGO_TARGET_DIR" >> {shlex.quote(str(calls))}
                case " $* " in
                  *" fuzz --version "*) echo "cargo-fuzz $CARGO_FUZZ"; exit 0 ;;
                  *" --no-run "*)
                    [ {int(cut == "build")} = 0 ] || sleep 5
                    echo "built"; exit {build_exit} ;;
                  *" --nocapture "*)
                    [ {int(cut == "run")} = 0 ] || sleep 5
                    cat {shlex.quote(str(run_dir / 'run.txt'))}; exit {run_exit} ;;
                esac
                echo "unexpected cargo $*" >&2; exit 97
                """),
            "uname": f'#!/usr/bin/env bash\n[ "$*" != -m ] || {{ echo {machine}; exit 0; }}\nexec {shutil.which("uname")} "$@"\n',
            "pkg-config": f"#!/usr/bin/env bash\ncase \" $* \" in\n  *' --variable=includedir libdpdk '*) echo {shlex.quote(str(run_dir / 'include'))} ;;\n"
                          "  *) echo 25.03.0 ;;\nesac\n",
        }
        bin_dir = run_dir / "bin"
        bin_dir.mkdir()
        for name, body in stubs.items():
            (bin_dir / name).write_text(body)
            (bin_dir / name).chmod(0o755)
        ambient = {name: value for name, value in self.env.items() if name != "LANG" and not name.startswith("LC_")}
        env = dict(ambient, **({"LC_ALL": "C.UTF-8"} if locale is None else locale),
                   PATH=f"{bin_dir}:{self.env['PATH']}", HOME=str(run_dir / "home dir"), EVIDENCE=str(evidence),
                   GITHUB_STEP_SUMMARY=str(run_dir / "summary.md"), RUSTFLAGS="--cfg ambient", CARGO_ENCODED_RUSTFLAGS="--cfg ambient",
                   CARGO_PROFILE_DEV_OPT_LEVEL="3", CARGO_PROFILE_DEV_DEBUG="full")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "litmus"], cwd=root, env=env,
                              capture_output=True, text=True, errors="replace", timeout=120, check=False)
        return step, evidence, calls.read_text() if calls.exists() else ""

    def test_the_litmus_step_runs_each_loop_by_exact_id_and_reports_its_line(self):
        step, evidence, calls = self.litmus_lane()
        self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
        ids = " ".join(test for test, _ in self.LITMUS)
        # The ambient flag and profile variables conflict with the lane's; each Cargo call runs without the flag
        # variables, at the lane's profile, in the target cache pins selected.
        flags = r"RUSTFLAGS=unset \| encoded=unset \| opt=1 \| debug=line-tables-only \| target=([^|\n]+)"
        build = matched(rf"^\+1\.99\.0 test -p kestrike --lib --no-run \| {flags}$", calls, re.MULTILINE)
        arguments = ["+1.99.0", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--nocapture", "--test-threads=1",
                     "--exact", *(test for test, _ in self.LITMUS)]
        run = matched(rf"^{re.escape(' '.join(arguments))} \| {flags}$", calls, re.MULTILINE)
        self.assertLess(build.start(), run.start())
        self.assertEqual(build.group(1), run.group(1))
        self.assertIn(" ", run.group(1), "HOME holds a space, so the replay must quote the target directory")
        replay = [shlex.split(line) for line in (evidence / "replay.txt").read_text().splitlines()]
        self.assertEqual(replay, [[
            "env", "-u", "RUSTFLAGS", "-u", "CARGO_ENCODED_RUSTFLAGS", "CARGO_PROFILE_DEV_OPT_LEVEL=1",
            "CARGO_PROFILE_DEV_DEBUG=line-tables-only", f"CARGO_TARGET_DIR={run.group(1)}",
            f"SPDK_PKG_CONFIG_PATH={self.env['SPDK_PKG_CONFIG_PATH']}", "cargo", *arguments]])
        self.assertIn("- rustc 1.99.0 (stub)", (evidence / "pins.txt").read_text())
        summary = (evidence.parent / "summary.md").read_text()
        self.assertIn("- this step credits no obligation record; zero forbidden outcomes is a finite sample for one build on one CPU\n",
                      summary)
        for _, name in self.LITMUS:
            self.assertIn(f"- litmus: {name} ran 10000000 rounds; aarch64 forbidden=0 control=1500\n", summary)
        self.assertEqual((evidence / "exit.txt").read_text(), "0\n")

    def test_the_litmus_step_refuses_another_host_before_building(self):
        for machine in ("x86_64", "arm64"):
            with self.subTest(machine=machine):
                step, evidence, calls = self.litmus_lane(machine=machine)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn(f"the litmus loops need a native AArch64 host, not {machine}", (evidence / "failure.txt").read_text())
                self.assertEqual(calls, "")
                self.assertEqual((evidence.parent / "summary.md").read_text(),
                                 "- this step credits no obligation record; zero forbidden outcomes is a finite sample for one build on one CPU\n"
                                 f"- red: the litmus loops need a native AArch64 host, not {machine}\n")

    def test_the_litmus_step_fails_each_line_it_does_not_accept(self):
        clean = "litmus: grace ran 10000000 rounds; aarch64 forbidden=0 control=1500"
        for name, options, message in (
                ("a missing line", dict(run=self.litmus_output({"grace": ""})), "the grace loop printed 0 lines"),
                ("a repeated line", dict(run=self.litmus_output({"grace": f"{clean}\n{clean}"})), "the grace loop printed 2 lines"),
                ("another round count", dict(run=self.litmus_output({"grace": clean.replace("10000000", "1000000")})),
                 "the grace loop did not report aarch64, 10000000 rounds"),
                ("a line without aarch64", dict(run=self.litmus_output({"grace": clean.replace("aarch64", "x86_64")})),
                 "the grace loop did not report aarch64"),
                ("forbidden=1", dict(run=self.litmus_output({"grace": clean.replace("forbidden=0", "forbidden=1")}), run_exit=101),
                 "the grace loop did not report aarch64, 10000000 rounds, forbidden=0"),
                ("control=0", dict(run=self.litmus_output({"grace": clean.replace("control=1500", "control=0")})),
                 "and a positive control"),
                ("text after the control", dict(run=self.litmus_output({"grace": clean + "x"})), "and a positive control"),
                ("a failed run with clean lines", dict(run_exit=101), "the litmus loops exited 101"),
                ("a cut run", dict(cut="run"), "reached their 5-minute deadline"),
                ("a failed build", dict(build_exit=101), "build failed"),
                ("a cut build", dict(cut="build"), "build failed")):
            with self.subTest(case=name):
                step, evidence, _ = self.litmus_lane(**options)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertIn(message, (evidence / "failure.txt").read_text())
                if options.get("cut"):
                    self.assertEqual((evidence / "exit.txt").read_text(), "124\n")

    def test_the_litmus_step_judges_each_line_by_bytes_in_any_locale(self):
        """Under a UTF-8 locale, a byte that is not UTF-8 after a valid control would end grep's match early and
        leave a clean-looking line; the lane judges bytes, so the line keeps the byte and fails. grep takes its
        locale from the lane's environment, where `LC_ALL` selects UTF-8 or `LANG` alone does."""
        clean = "litmus: grace ran 10000000 rounds; aarch64 forbidden=0 control=1500"
        run = self.litmus_output({"grace": "GRACE"}).encode().replace(b"GRACE", clean.encode() + b"\xff0")
        for locale in ({"LC_ALL": "C.UTF-8"}, {"LANG": "C.UTF-8"}):
            with self.subTest(locale=locale):
                step, evidence, _ = self.litmus_lane(run=run, locale=locale)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertIn(b"the grace loop did not report aarch64, 10000000 rounds, forbidden=0 and a positive control",
                              (evidence / "failure.txt").read_bytes())

    def test_the_litmus_step_fails_a_run_that_holds_a_nul_byte(self):
        """GNU grep treats output that holds a NUL byte as binary and can suppress its matching lines, which would
        hide a loop's second line past the NUL; the lane fails such a run whatever its lines say. The filler places
        the NUL beyond the first block grep reads, after it has printed the first line."""
        second = "litmus: fill ran 10000000 rounds; aarch64 forbidden=0 control=0"
        run = (self.litmus_output() + ("p" * 63 + "\n") * 4096).encode() + b"\0\n" + second.encode() + b"\n"
        step, evidence, _ = self.litmus_lane(run=run)
        self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
        self.assertIn("the litmus run wrote a NUL byte", (evidence / "failure.txt").read_text())

    def test_the_litmus_ids_are_exactly_the_registered_native_loops(self):
        """Every registered native loop runs in the lane, and the lane runs no unregistered test, so a renamed or
        added loop fails here rather than at the next live run."""
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        block = re.search(r"^LITMUS_TESTS=\(\n(.*?)\n\)$", lane, re.MULTILINE | re.DOTALL)
        self.assertIsNotNone(block)
        entries = dict(line.strip().strip('"').split() for line in block.group(1).splitlines())
        ids = set(entries)
        rows = json.loads((ROOT / "scripts/test-registry.json").read_text())["rows"]
        cause = "native litmus loop; the litmus lane runs it on aarch64"
        # A row joins by its module or by the lane's cause, so a loop with other cause text and a foreign row with
        # this cause both fail.
        litmus = [row for row in rows if row["id"].startswith("storage::litmus_tests::") or row["cause"] == cause]
        for cfg in ("ordinary", "miri"):
            registered = {row["id"] for row in litmus if row["cfg"] == cfg and row["target"] == "kestrike"}
            self.assertEqual(registered, ids, cfg)
        self.assertEqual({(row["target"], row["class"], row["cause"]) for row in litmus}, {("kestrike", "search-bound", cause)})
        self.assertEqual(entries, dict(self.LITMUS))

    def test_the_loops_print_the_line_the_lane_parses(self):
        """Each loop's report renders, at the lane's round count, the clean line the stub cases show the lane
        accepts, and names the kernel the lane pairs with that loop's test ID."""
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        entries = dict(line.strip().strip('"').split()
                       for line in matched(r"^LITMUS_TESTS=\(\n(.*?)\n\)$", lane, re.MULTILINE | re.DOTALL).group(1).splitlines())
        source = (ROOT / "crates/kestrike/src/storage/litmus_tests.rs").read_text()
        rounds = int(matched(r"^const ROUNDS: u64 = ([\d_]+);$", source, re.MULTILINE).group(1).replace("_", ""))
        self.assertEqual(rounds, int(matched(r"^LITMUS_ROUNDS=(\d+)$", lane, re.MULTILINE).group(1)))
        template = matched(r'println!\(\s*"(litmus: [^"]*)",\s*std::env::consts::ARCH\s*\)', source).group(1)
        for test, name in self.LITMUS:
            with self.subTest(name=name):
                line = template.replace("{}", "aarch64", 1).format(name=name, ROUNDS=rounds, forbidden=0, control=1500)
                self.assertIn(f"test {test} ... {line}\n", self.litmus_output())
        reports = dict(re.findall(r'^fn (\w+)\(\) \{\s*report\(\s*"(\w+)",', source, re.MULTILINE))
        self.assertEqual({f"storage::litmus_tests::{test}": name for test, name in reports.items()}, entries)

    def isa_lane(self, lane, cpuinfo, machine):
        """Run `rust-lane.sh LANE` for an architecture qualification lane from a copy of the lane that reads
        `cpuinfo`, under a `uname -m` reporting `machine`; `qualified` is stubbed to record that the host check
        passed, so the step's result is the host check's alone."""
        run = Path(tempfile.mkdtemp(dir=self.dir))
        root, evidence = run / "root", run / "evidence"
        (root / "scripts").mkdir(parents=True)
        (run / "cpuinfo").write_text(cpuinfo)
        lane_script = (ROOT / "scripts/rust-lane.sh").read_text().replace("/proc/cpuinfo", str(run / "cpuinfo"))
        lane_script = lane_script.replace('\ncase "${1:-}" in\n', '\nqualified() { echo "qualified $1" > "$EVIDENCE/qualified.txt"; }\ncase "${1:-}" in\n', 1)
        (root / "scripts/rust-lane.sh").write_text(lane_script)
        (root / "scripts/test-inventory.json").symlink_to(ROOT / "scripts/test-inventory.json")
        uname = self.dir / "bin" / "uname"
        uname.write_text(f'#!/usr/bin/env bash\n[ "$*" != -m ] || {{ echo {machine}; exit 0; }}\nexec {shutil.which("uname")} "$@"\n')
        uname.chmod(0o755)
        env = dict(self.env, EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(run / "summary.md"))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", lane], cwd=root, env=env,
                              capture_output=True, text=True, timeout=60, check=False)
        return step, evidence

    def test_an_isa_lane_refuses_another_architecture_or_a_missing_feature_before_building(self):
        """The lane runs its rows only on a host of its architecture whose every processor record reports every
        declared feature; any other host fails the lane, naming the missing features, so no row credits."""
        x86 = "flags\t\t: fpu sse4_2 pclmulqdq avx512f avx512bw vpclmulqdq\n"
        arm = "Features\t: fp asimd aes pmull sha1 sha2 sha3 crc32 atomics\n"
        cases = (
            ("isa-x86-64", f"processor\t: 0\n{x86}\nprocessor\t: 1\n{x86}", "x86_64", None),
            ("isa-aarch64", f"processor\t: 0\n{arm}", "aarch64", None),
            ("isa-x86-64", f"processor\t: 0\n{x86}", "aarch64", "isa-x86-64 qualifies x86_64 kernels; this host is aarch64"),
            ("isa-x86-64", f"processor\t: 0\n{x86.replace(' avx512bw', '')}", "x86_64", "lacks the isa-x86-64 features avx512bw;"),
            ("isa-x86-64", f"processor\t: 0\n{x86}\nprocessor\t: 1\n{x86.replace(' vpclmulqdq', '')}", "x86_64",
             "lacks the isa-x86-64 features vpclmulqdq;"),
            ("isa-aarch64", f"processor\t: 0\n{arm.replace(' sha1 sha2', '')}", "aarch64", "lacks the isa-aarch64 features sha1 sha2;"),
            ("isa-aarch64", f"processor\t: 0\n{arm.replace(' sha3', '')}", "aarch64", "lacks the isa-aarch64 features sha3;"),
            ("isa-aarch64", f"processor\t: 0\n{arm}\nprocessor\t: 1\n{arm.replace(' atomics', '')}", "aarch64",
             "lacks the isa-aarch64 features atomics;"),
            ("isa-aarch64", "processor\t: 0\n", "aarch64", "lacks the isa-aarch64 features asimd crc32 aes pmull sha1 sha2 sha3 atomics;"),
        )
        for lane, cpuinfo, machine, refusal in cases:
            with self.subTest(lane=lane, machine=machine, refusal=refusal):
                step, evidence = self.isa_lane(lane, cpuinfo, machine)
                if refusal is None:
                    self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
                    self.assertEqual((evidence / "qualified.txt").read_text(), f"qualified {lane}\n")
                else:
                    self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                    self.assertIn(refusal, (evidence / "failure.txt").read_text())
                    self.assertFalse((evidence / "qualified.txt").exists())

    def test_the_gate_aggregates_this_attempts_lane_evidence(self):
        gate = workflow_jobs(WORKFLOW.read_text())["rust-gate"]
        steps = gate.split("\n      - ")
        names = [step.split("\n", 1)[0] for step in steps[1:]]
        self.assertEqual(names, ["name: Fork pull requests run no lanes", "uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
                                 "name: Every selected Rust lane succeeded", "name: This attempt's lane evidence",
                                 "name: Every selected lane credited its declared domain",
                                 "name: The Verus trust inventory matches its sources"])
        guard = ("always() && (github.event_name != 'pull_request' ||\n"
                 "          github.event.pull_request.head.repo.full_name == github.repository)")
        self.assertTrue(all(guard in step for step in [steps[2], *steps[4:]]), steps)
        self.assertIn("evidence-*-${{ github.run_id }}-${{ github.run_attempt }}", gate)
        self.assertIn("uses: actions/download-artifact@37930b1c2abaa49bbe596cd826c3c89aef350131", gate)
        self.assertIn('--run-attempt "${{ github.run_attempt }}"', gate)

    def test_the_aggregate_requires_exactly_the_lanes_and_profiles_the_workflow_selects(self):
        verify = load("verify_receipts", ROOT / "scripts/verify-receipts.py")
        select = verify.load_select_tests()
        inventory = select.load_inventory(select.INVENTORY)
        text = WORKFLOW.read_text()
        for event in sorted(verify.EVENT_HEAVY):
            with self.subTest(event=event):
                self.assertEqual(set(verify.lane_domains(event, inventory)), gate_lanes(text, event, inventory["loom"]))

    def test_rc11_requires_the_provisioned_checker_and_complete_receipt(self):
        workflow = WORKFLOW.read_text()
        jobs = workflow_jobs(workflow)
        body = jobs["rc11"]
        self.assertEqual(re.findall(r"scripts/rust-lane\.sh ([\w-]+)", body), ["herdtools", "rc11", "summary"])
        self.assertEqual(re.findall(r"--kill-after=(\d+)s (\d+)m", body), [("60", "25"), ("60", "15")])
        self.assertIn("timeout-minutes: 50", body)
        self.assertIn('HERDTOOLS7: "7.58"', workflow)
        self.assertIn(
            "if: >-\n      github.event_name != 'pull_request' ||\n"
            "      github.event.pull_request.head.repo.full_name == github.repository", body,
        )
        self.assertRegex(body, r"- name: Summary\n        if: always\(\)\n        run: bash scripts/rust-lane\.sh summary rc11")
        self.assertIn(
            "- name: Obligation receipt and credit\n        if: always()\n        run: >-\n"
            "          python3 scripts/verify-receipts.py credit --job rc11\n"
            "          --receipt evidence/receipt.json --evidence evidence", body,
        )
        self.assertIn("- name: Evidence\n        if: always()", body)
        self.assertIn("if-no-files-found: error", body)
        self.assertNotIn("continue-on-error", body)
        needs = re.search(r"needs: \[([^\]]+)\]", jobs["rust-gate"])
        if needs is None:
            self.fail("rust-gate names no needs")
        self.assertIn("rc11", needs.group(1).split(", "))
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        checker = script.split("herdtools() {", 1)[1].split("\nfuzz() {", 1)[0]
        self.assertNotRegex(checker, r"\b(?:sudo|apt-get|opam|eval)\b")
        self.assertIn('deadline 1m "${argv[@]}"', checker)
        expected = json.loads((ROOT / "verification/rc11/expected.json").read_text())
        self.assertEqual(expected["herd7"], "7.58")
        self.assertGreaterEqual(len(expected["tests"]), 23)
        self.assertEqual(sorted(expected["tests"]), sorted(path.stem for path in (ROOT / "verification/rc11/litmus").glob("*.litmus")))

    def checker_prerequisite(self, version, exit_code=0, lane="herdtools"):
        stub = self.dir / "checker-bin"
        stub.mkdir(exist_ok=True)
        tools = {name: shutil.which(name) for name in ("bash", "mkdir")}
        for name, found in tools.items():
            if found is None:
                self.fail(f"{name} is not on PATH")
            if not (stub / name).exists():
                (stub / name).symlink_to(found)
        installs = self.dir / "installs"
        for name in ("sudo", "apt-get", "opam"):
            path = stub / name
            path.write_text('#!/usr/bin/env bash\necho "${0##*/}" >> "$STUB_INSTALLS"\nexit 91\n')
            path.chmod(0o755)
        herd = stub / "herd7"
        herd.unlink(missing_ok=True)
        if version is not None:
            herd.write_text(f"#!/usr/bin/env bash\nprintf '%s\\n' {shlex.quote(version)}\nexit {exit_code}\n")
            herd.chmod(0o755)
        result = subprocess.run(
            [str(stub / "bash"), "scripts/rust-lane.sh", lane], cwd=ROOT, capture_output=True, text=True, timeout=60,
            env=dict(self.env, PATH=str(stub), STUB_INSTALLS=str(installs)),
        )
        self.assertFalse(installs.exists(), "a job tried to provision its checker")
        return result

    def test_provisioned_herdtools_is_verified_without_installing_anything(self):
        result = self.checker_prerequisite("7.58, Rev: provisioned")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse((self.dir / "evidence" / "failure.txt").exists())

    def test_missing_herdtools_fails_both_prerequisite_and_lane_without_installing(self):
        for lane in ("herdtools", "rc11"):
            with self.subTest(lane=lane):
                result = self.checker_prerequisite(None, lane=lane)
                self.assertEqual(result.returncode, 1, result.stderr)
                failure = (self.dir / "evidence" / "failure.txt").read_text()
                self.assertIn("herd7 is missing from PATH; provision herdtools7 7.58 on the runner", failure)

    def test_wrong_or_unusable_herdtools_fails_without_installing(self):
        for version, code in (("7.57, Rev: old", 0), ("7.59, Rev: new", 0), ("7x58, Rev: malformed", 0),
                              ("7.580, Rev: wrong", 0), ("", 0), ("7.58, Rev: broken", 1)):
            for lane in ("herdtools", "rc11"):
                with self.subTest(version=version, code=code, lane=lane):
                    result = self.checker_prerequisite(version, code, lane)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    failure = (self.dir / "evidence" / "failure.txt").read_text()
                    self.assertIn("herdtools7 7.58", failure)
                    self.assertIn("herd7 -version failed" if code else "herd7 reports", failure)

    def test_unguarded_command_failure_writes_evidence(self):
        stub = self.dir / "bin" / "python3"
        stub.write_text("#!/usr/bin/env bash\necho 'inventory unreadable' >&2\nexit 1\n")
        stub.chmod(0o755)
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "summary", "fuzz"],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(step.returncode, 1, step.stderr)
        failure = self.dir / "evidence" / "failure.txt"
        self.assertTrue(failure.exists(), step.stderr)
        self.assertIn("failed at line", failure.read_text())
        self.assertIn("- red: ", (self.dir / "summary.md").read_text())

    def test_cancelled_fis_step_leaves_no_process(self):
        """`timeout` forwards the runner's signal to its process group, so the controller receives it directly
        and runs its own handler; the lane's trap then records the interruption once the controller exits."""
        python = self.dir / "bin" / "python3"
        python.write_text(
            '#!/usr/bin/env bash\n'
            'case " $* " in *" scripts/fis-controller.py campaign "*)\n'
            '  echo "$$" >> "$STUB_PIDS"\n  trap \'sleep 1; exit 130\' INT TERM\n  while :; do sleep 0.1; done ;;\n'
            'esac\n'
            f'exec {shutil.which("python3")} "$@"\n'
        )
        python.chmod(0o755)
        run = self.dir / "run"
        run.write_text("    Finished `test` profile\n")
        self.env.update(HOME=str(self.dir / "home"), KESTRIKE_FIS_OPERATOR=str(self.dir / "operator.json"),
                        STUB_RUN=str(run))
        self.assertEqual(self.cancel("fis", self.commands["fis"]), [])
        self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "143\n")
        self.assertIn("### FIS: interrupted", (self.dir / "summary.md").read_text(),
                      "the episodes the campaign reported reach the summary")

    def test_the_fis_lane_builds_the_library_tests_before_its_campaign(self):
        """The controller's readiness deadline starts when it spawns the lane, so the lane's own build must find
        the `fis` target directory warm: the step builds the `kestrike` library tests first, under the same
        toolchain and target directory, and the campaign runs only after that build succeeded."""
        python = self.dir / "bin" / "python3"
        python.write_text(
            '#!/usr/bin/env bash\n'
            f'[ "$1" = -c ] && exec {sys.executable} "$@"\n'
            'cp "$STUB_ENV" "$STUB_AT_CAMPAIGN" 2>/dev/null || : > "$STUB_AT_CAMPAIGN"\n'
            'printf "%s\\n" "$* target=$CARGO_TARGET_DIR toolchain=$RUSTUP_TOOLCHAIN" >> "$STUB_AT_CAMPAIGN"\n'
        )
        python.chmod(0o755)
        run = self.dir / "run"
        run.write_text("    Finished `test` profile\n")
        env = dict(self.env, HOME=str(self.dir / "home"), KESTRIKE_FIS_OPERATOR=str(self.dir / "operator.json"),
                   STUB_ENV=str(self.dir / "cargo-calls"), STUB_ENV_DUMP=str(self.dir / "cargo-env"),
                   STUB_AT_CAMPAIGN=str(self.dir / "at-campaign"), STUB_RUN=str(run))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        at_campaign = (self.dir / "at-campaign").read_text().splitlines()
        self.assertIn("encoded unset +1.99.0 test -p kestrike --lib --no-run", at_campaign,
                      "the library tests were built before the campaign started")
        campaign = next(line for line in at_campaign if line.startswith("scripts/fis-controller.py campaign"))
        cargo_env = env_dump(self.dir / "cargo-env")
        self.assertTrue(cargo_env["CARGO_TARGET_DIR"].endswith("-fis"), cargo_env["CARGO_TARGET_DIR"])
        self.assertIn(f"target={cargo_env['CARGO_TARGET_DIR']} toolchain=1.99.0", campaign,
                      "the campaign's lane builds in the same target directory under the same toolchain")
        env["STUB_EXIT"] = "101"
        del env["STUB_RUN"]
        (self.dir / "at-campaign").unlink()
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertFalse((self.dir / "at-campaign").exists(), "no campaign ran after a failed build")
        self.assertIn("did not build", (self.dir / "evidence" / "failure.txt").read_text())

    def test_a_fis_host_without_an_operator_contract_is_red(self):
        """Only a registration provisioned with the contract carries the FIS job's label, so a host without one is
        misprovisioned and the step fails rather than pass with no evidence."""
        env = dict(self.env, HOME=str(self.dir / "home"))
        env.pop("KESTRIKE_FIS_OPERATOR", None)
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("no operator contract", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertIn("### FIS: unrun", (self.dir / "summary.md").read_text())

    def test_a_fis_host_naming_no_platform_row_is_red_before_the_build(self):
        """Each case the campaign spawns runs the hardware lane under the host's platform row, so a host naming no row
        of the manifest fails before the build instead of failing every episode after it."""
        for row in (None, "no-such-row"):
            with self.subTest(row=row):
                env = dict(self.env, HOME=str(self.dir / "home"), KESTRIKE_FIS_OPERATOR=str(self.dir / "operator.json"))
                env.pop("KESTRIKE_HARDWARE_PLATFORM", None)
                if row is not None:
                    env["KESTRIKE_HARDWARE_PLATFORM"] = row
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=ROOT, env=env, capture_output=True,
                                      text=True)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn("cannot run the hardware lane: no platform row",
                              (self.dir / "evidence" / "failure.txt").read_text())
                self.assertFalse((self.dir / "evidence" / "fis-build.txt").exists(), "the refusal precedes the build")

    def test_the_fis_campaign_budget_is_what_the_build_left_of_the_step(self):
        """The workflow step's `timeout` covers the build and the campaign together: the lane hands the controller
        the step's seconds less the build's elapsed time and two minutes for the summary, so a cold build
        shrinks the campaign's budget instead of letting the step's timeout interrupt a live fault."""
        step_seconds = int(matched(r"^FIS_STEP_SECONDS=(\d+)$", (ROOT / "scripts/rust-lane.sh").read_text(), re.M)[1])
        job = workflow_jobs(HARDWARE_WORKFLOW.read_text())["fis"]
        kill_after, minutes = map(int, matched(r"--kill-after=(\d+)s (\d+)m\s+bash scripts/rust-lane\.sh fis", job).groups())
        self.assertEqual(step_seconds, minutes * 60, "the lane's constant is the workflow step's budget")
        self.assertLessEqual(minutes + kill_after / 60, int(matched(r"timeout-minutes: (\d+)", job)[1]))
        # After the signal the controller's longest cleanup, a start whose outcome is unknown, holds the discovery
        # listing, the stop's end, its restoration poll, the abandon wait and the template's deletion: five windows
        # of the effect timeout, each loop checking its deadline between calls so each may end one AWS call past
        # it, then the listing of the deleted template's experiments, one more call, plus the lane's close. The grace
        # covers that under a 60 s effect timeout and 60 s AWS calls, and the job holds the toolchains step with its
        # grace, this step with its grace and the margin every lane keeps.
        controller = load("fis_controller", ROOT / "scripts/fis-controller.py")
        profiles = json.loads((ROOT / "scripts/fis-profiles.json").read_text())["profiles"]
        cleanup = max(controller.cleanup_bound(profile, {"effect_timeout_seconds": 60}, 60.0, controller.lane.MANIFEST)
                      for profile in profiles.values())
        self.assertGreaterEqual(kill_after, cleanup + controller.CLOSE_OUT_SECONDS, (kill_after, cleanup))
        # The step leaves the build at least five minutes before the largest campaign's sum is refused, a campaign
        # running the profiles of one attachment mode since one volume serves one, and the build's allowance ends
        # where the smallest profile could no longer start; both read the controller's own bounds, so a step or
        # floor edited alone fails here on the pull request.
        bound = {name: controller.episode_bound(profile, {"effect_timeout_seconds": 60}, 60.0, controller.lane.MANIFEST)
                 for name, profile in profiles.items()}
        bounds = list(bound.values())
        largest = max(sum(bound[name] for name, profile in profiles.items() if profile["attachment"] == mode)
                      for mode in controller.ATTACHMENT_MODES)
        self.assertGreaterEqual(step_seconds - 120 - largest, 300, (step_seconds, largest))
        least = int(matched(r"^FIS_LEAST_BUDGET_SECONDS=(\d+)$", (ROOT / "scripts/rust-lane.sh").read_text(), re.M)[1])
        self.assertEqual(least, min(bounds), "the least budget is the smallest profile's bound")
        grace = int(matched(r"^FIS_KILL_GRACE_SECONDS=(\d+)$", (ROOT / "scripts/rust-lane.sh").read_text(), re.M)[1])
        self.assertEqual(kill_after, grace, "the lane hands the controller the step's grace, so it admits only "
                                            "contracts whose cleanup fits it")
        toolchains_kill, toolchains = map(int, matched(r"--kill-after=(\d+)s (\d+)m\s+bash scripts/rust-lane\.sh toolchains", job).groups())
        self.assertGreaterEqual(int(matched(r"timeout-minutes: (\d+)", job)[1]),
                                toolchains + toolchains_kill / 60 + minutes + kill_after / 60 + MARGIN_MINUTES)
        python = self.dir / "bin" / "python3"
        python.write_text('#!/usr/bin/env bash\nprintf "%s\\n" "$*" >> "$STUB_AT_CAMPAIGN"\n')
        python.chmod(0o755)
        run = self.dir / "run"
        run.write_text("    Finished `test` profile\n")
        (self.dir / "bin" / "cargo").write_text("#!/usr/bin/env bash\nsleep 2\n" + STUB_CARGO.split("\n", 1)[1])
        env = dict(self.env, HOME=str(self.dir / "home"), KESTRIKE_FIS_OPERATOR=str(self.dir / "operator.json"),
                   STUB_AT_CAMPAIGN=str(self.dir / "at-campaign"), STUB_RUN=str(run))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fis"], cwd=ROOT, env=env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        campaign = (self.dir / "at-campaign").read_text()
        budget = int(matched(r"--budget-seconds (\d+)", campaign)[1])
        self.assertLessEqual(budget, step_seconds - 120 - 2, "the build's two seconds left the budget")
        self.assertGreaterEqual(budget, step_seconds - 120 - 10, campaign)
        self.assertIn(f"--kill-grace-seconds {grace}", campaign, "the campaign received the step's grace")

    def test_the_workspace_summary_names_the_executed_witnesses(self):
        evidence = self.dir / "evidence"
        evidence.mkdir()
        report = {
            "baseline": "0123456789abcdef0123456789abcdef01234567", "verdict": "credited", "reason": None,
            "targets": {"kestrike": {
                "executed": 1696, "observed_ignored": 15,
                "witnesses": {"controls": ["net::put_tests::one", "net::upload_tests::two"],
                              "runnable_modules": {"net::put_tests": 36, "oracle": 249},
                              "executed_modules": {"net::put_tests": 36, "oracle": 249}},
            }},
        }
        (evidence / "report.json").write_text(json.dumps(report))
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "summary", "workspace"],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn("### Workspace suite: selection credited", summary)
        self.assertIn(
            "- 1696 executed; ignored per crate: 0 campaign-monitor, 0 campaign-supervisor, "
            "0 sim-host, 15 kestrike, 0 kestrike-aws, 0 kestrike-reconciler, 0 source-anchors, 0 spdk-sys",
            summary,
        )
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        self.assertIn(f"- revision {revision}; census baseline 0123456789abcdef0123456789abcdef01234567", summary)
        self.assertIn(
            "- kestrike witnesses: 2 required controls "
            "executed; tests executed per required module: net::put_tests 36, oracle 249",
            summary,
        )
        del report["targets"]["kestrike"]["witnesses"]["executed_modules"]
        report.update(verdict="execution mismatch", reason="kestrike executed 2 of 3 runnable tests")
        (evidence / "report.json").write_text(json.dumps(report))
        # A refused judgment exits nonzero under the ERR trap, so a real lane leaves failure.txt beside every
        # refused report; the heading keeps the judgment's verdict.
        (evidence / "failure.txt").write_text("rust-lane.sh failed at line 246: python3 scripts/select-tests.py run\n")
        (self.dir / "summary.md").unlink()
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "summary", "workspace"],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn("### Workspace suite: selection execution mismatch", summary)
        self.assertIn(f"- revision {revision}; census baseline 0123456789abcdef0123456789abcdef01234567", summary)
        self.assertIn("- reason: kestrike executed 2 of 3 runnable tests", summary)
        self.assertNotIn("rust-lane.sh failed at line", summary)
        self.assertNotIn("witnesses", summary)
        (evidence / "report.json").unlink()
        (evidence / "failure.txt").unlink()
        (self.dir / "summary.md").unlink()
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "summary", "workspace"],
            cwd=ROOT, env=self.env, capture_output=True, text=True,
        )
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn(f"### Workspace suite: red\n- revision {revision}\n- listing not reached", summary)

    def test_the_loom_summary_names_the_registry_ignores(self):
        """The summary reads the declared inventory, whose Loom ignores come from the registry, so a committed
        Loom entry carries no `ignored` key of its own."""
        evidence = self.dir / "evidence"
        evidence.mkdir()
        report = {"baseline": "0123456789abcdef0123456789abcdef01234567", "verdict": "credited", "reason": None,
                  "targets": {"credit_model": {"listed": 8, "executed": 8, "observed_ignored": 0}}}
        (evidence / "report.json").write_text(json.dumps(report))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "loom", "credit_model"],
                              cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        select = load("select_tests", ROOT / "scripts/select-tests.py")
        fences = select.load_inventory(select.INVENTORY)["loom"]["credit_model"]["ignored"]
        self.assertIn("### Loom credit_model: selection credited", summary)
        self.assertIn("- 8 listed, 8 executed, 0 ignored", summary)
        self.assertIn(f"- excluded fence controls: {', '.join(fences) if fences else 'none'}", summary)

    def test_the_loom_summary_reads_inline_models_without_sibling_bounds(self):
        fixture = self.dir / "checkout"
        for name in ("scripts/rust-lane.sh", "scripts/select-tests.py", "scripts/test-inventory.json",
                     "scripts/test-registry.json", "verification/obligations.json"):
            destination = fixture / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, destination)
        source = fixture / "crates/kestrike/src/storage/readiness.rs"
        source.parent.mkdir(parents=True)
        source.write_text("mod authority_model {\n    loom::model(|| {});\n}\n"
                          "mod other_model {\n    loom::model(|| {});\n}\n")
        evidence = self.dir / "evidence"
        evidence.mkdir()
        (evidence / "report.json").write_text(json.dumps({
            "baseline": "0123456789abcdef0123456789abcdef01234567", "verdict": "credited", "reason": None,
            "targets": {"authority_model": {"listed": 2, "executed": 2, "observed_ignored": 0}},
        }))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "loom", "authority_model"],
                              cwd=fixture, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn("### Loom authority_model: selection credited", summary)
        self.assertIn("preemption bounds: unbounded (loom::model) at 1 sites", summary)
        self.assertIn("- 2 listed, 2 executed, 0 ignored", summary)
        self.assertFalse((evidence / "failure.txt").exists())

    def test_the_genmc_summary_names_the_records_its_receipt_credits(self):
        evidence = self.dir / "evidence"
        evidence.mkdir()
        (evidence / "report.json").write_text(json.dumps({"credited": True, "cases": {}}))
        for profile, credited in (("scheduled", "the pr and scheduled records"), ("pr", "the pr records only")):
            with self.subTest(profile=profile):
                step = subprocess.run(
                    ["bash", "scripts/rust-lane.sh", "summary", "genmc", profile],
                    cwd=ROOT, env=self.env, capture_output=True, text=True,
                )
                self.assertEqual(step.returncode, 0, step.stderr)
                summary = (self.dir / "summary.md").read_text()
                self.assertIn(f"### GenMC {profile} profile: credited", summary)
                self.assertIn(f"; this receipt credits {credited}\n", summary)
                (self.dir / "summary.md").unlink()

    def test_the_miri_summary_states_its_detectors_and_limits(self):
        evidence = self.dir / "evidence"
        evidence.mkdir()
        selected = len(json.loads((ROOT / "scripts/test-inventory.json").read_text())["miri"]["tests"])
        report = {"baseline": "0123456789abcdef0123456789abcdef01234567", "verdict": "credited", "reason": None,
                  "targets": {"kestrike": {"executed": selected, "interpreter_ignored": 46}}}
        (evidence / "report.json").write_text(json.dumps(report))
        (evidence / "pins.txt").write_text("- miri 0.1.0 (stub); MIRIFLAGS=-Zmiri-seed=0 -Zmiri-permissive-provenance\n")
        control = "storage::gate::tests::negative_control_a_relaxed_take_races_the_guarded_counter"
        (evidence / "controls.txt").write_text(f"{control}\t1\tfound\n")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "miri"], cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        for line in (
            "### Miri ownership corpus: selection credited",
            f"- {selected} of {selected} selected IDs executed at seed 0 on one test thread; 46 interpreter ignores reconciled",
            f"- control `{control}`: exit 1, diagnostic found",
            "with isolation enabled; no detector is disabled",
            "- limit: one sampled schedule at seed 0; weak-memory emulation bounds store buffers and is incomplete",
            "- limit: integer-to-pointer casts are accepted without warning across the run",
            "- miri 0.1.0 (stub); MIRIFLAGS=-Zmiri-seed=0 -Zmiri-permissive-provenance",
        ):
            self.assertIn(line, summary)
        # A control that failed after the judged corpus was credited leaves failure.txt beside the credited
        # report; the heading follows the failure, and the control's row shows how it ran.
        (evidence / "controls.txt").write_text(f"{control}\t124\tfound\n")
        (evidence / "failure.txt").write_text(f"the Miri control {control} exited 124 without the diagnostic 'Data race detected'; see control-1.txt\n")
        (self.dir / "summary.md").unlink()
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "miri"], cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        self.assertIn("### Miri ownership corpus: red", summary)
        self.assertIn(f"- reason: the Miri control {control} exited 124 without the diagnostic", summary)
        self.assertIn(f"- control `{control}`: exit 124, diagnostic found", summary)
        self.assertNotIn("credited", summary.split("\n")[0])

    def test_the_fuzz_summary_names_the_revision_on_both_verdicts(self):
        evidence = self.dir / "evidence"
        evidence.mkdir()
        revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
        campaign = {"seeds": 4, "runs": 400, "seconds": 120, "executed": 400, "pass": 390, "failure": 0,
                    "nonseed_pass": 11}
        parsers = {name: {"seeds": 9, "runs": 9000, "seconds": 60, "executed": 9000, "pass": 8000, "failure": 0,
                          "nonseed_pass": 7900} for name in ("record", "wire")}
        frame = {"seeds": 22, "runs": 1000, "seconds": 61}
        for verdict, record, line in (
                ("passed", {**frame, "campaign": campaign, "parsers": parsers}, "- cargo-fuzz 0.13.2, sanitizer address, 22 seed files"),
                ("passed", {**frame, "campaign": campaign, "parsers": parsers},
                 "- campaign: instrumented worker, 4 seeds each passed, wrong-byte control audited before its abort, "
                 "400 runs in 120 s, none failed, 11 generated passes"),
                ("passed", {**frame, "campaign": campaign, "parsers": parsers},
                 "- wire: instrumented worker, 9 seeds each passed, 9000 runs in 60 s, none failed, 7900 generated "
                 "passes; the real path against its literal reference"),
                ("red", frame, "- reason: the run did not finish"),
                ("passed", {**frame, "campaign": campaign, "parsers": parsers},
                 "- record: instrumented worker, 9 seeds each passed, 9000 runs in 60 s, none failed, 7900 generated "
                 "passes; the real path against its literal reference"),
                ("red", {**frame, "campaign": campaign}, "- reason: the run did not finish"),
                ("red", {**frame, "runs": 23, "campaign": campaign, "parsers": parsers}, "- reason: the run did not finish"),
                ("red", {**frame, "campaign": campaign, "parsers": {"record": parsers["record"]}},
                 "- reason: the run did not finish"),
                ("red", {**frame, "campaign": campaign, "parsers": parsers}, "- reason: the fuzz run exited 1")):
            with self.subTest(verdict=verdict, line=line):
                (evidence / "fuzz.json").write_text(json.dumps(record))
                if line == "- reason: the fuzz run exited 1":
                    (evidence / "failure.txt").write_text("the fuzz run exited 1\n")
                (self.dir / "summary.md").unlink(missing_ok=True)
                step = subprocess.run(
                    ["bash", "scripts/rust-lane.sh", "summary", "fuzz"],
                    cwd=ROOT, env=self.env, capture_output=True, text=True,
                )
                self.assertEqual(step.returncode, 0, step.stderr)
                summary = (self.dir / "summary.md").read_text()
                self.assertIn(f"### Frame, campaign and parser fuzz: {verdict}\n- revision {revision}\n", summary)
                self.assertIn(line, summary)

    def test_pin_discovery_failure_writes_evidence(self):
        stub = self.dir / "bin" / "pkg-config"
        for diagnostic in ("Package libdpdk was not found", ""):
            with self.subTest(diagnostic=diagnostic):
                stub.write_text(f"#!/usr/bin/env bash\necho {shlex.quote(diagnostic)} >&2\nexit 1\n")
                stub.chmod(0o755)
                step = subprocess.run(
                    ["bash", "scripts/rust-lane.sh", "preflight"],
                    cwd=ROOT, env=self.env, capture_output=True, text=True,
                )
                self.assertEqual(step.returncode, 1, step.stderr)
                failure = self.dir / "evidence" / "failure.txt"
                self.assertTrue(failure.exists(), step.stderr)
                self.assertIn(f"DPDK metadata unavailable in {self.env['SPDK_PKG_CONFIG_PATH']}", failure.read_text())
                self.assertIn(diagnostic, failure.read_text())
                self.assertIn("- red: ", (self.dir / "summary.md").read_text())

    HEADER_DIGEST = "2" * 64

    def install_sh_crate(self, crate):
        """A scratch crate holding a copy of install.sh, a stub header-digest.sh that prints HEADER_DIGEST for any
        install, and an empty installs directory, so `install.sh record` runs against this test's records."""
        (crate / "native").mkdir(parents=True)
        shutil.copy(ROOT / "crates/spdk-sys/native/install.sh", crate / "native/install.sh")
        (crate / "native/header-digest.sh").write_text(f"#!/usr/bin/env bash\necho {self.HEADER_DIGEST}\n")
        (crate / "native/header-digest.sh").chmod(0o755)
        (crate / "src/generated/installs").mkdir(parents=True)

    def native_install(self, march, archives=("libspdk_nvme.a", "librte_eal.a"), sanitizer=False, flags_first="-I{root}",
                       instrumented=None):
        """A stub install under this test's directory whose pkg-config flags open with `flags_first` (its include root by
        default) and name `-march=march`, with `archives` of one compiled object; `sanitizer` makes its DPDK link
        metadata name -lasan, as an --enable-asan install's does, and compiles the object under -fsanitize=address
        unless `instrumented` is False."""
        install = self.dir / "install"
        root = f"{install}/include"
        first = flags_first.format(root=root)
        asan = " -lasan" if sanitizer else ""
        (install / "include" / "spdk").mkdir(parents=True)
        (install / "lib").mkdir()
        (install / "include" / "spdk" / "version.h").write_text(
            "#define SPDK_VERSION_MAJOR 25\n#define SPDK_VERSION_MINOR 5\n#define SPDK_VERSION_PATCH 1\n")
        (install / "include" / "spdk" / "config.h").write_text(f"#define SPDK_CONFIG_ARCH {march}\n#undef SPDK_CONFIG_ASAN\n")
        (install / "include" / "rte_build_config.h").write_text(f"#define RTE_MACHINE {march}\n")
        # An instrumented object also names thousands of undefined symbols that sort after __asan_init, so the
        # lane's nm output runs past the pipe buffer once the match has printed, as a real archive's does.
        flags = ["-fsanitize=address"] if (sanitizer if instrumented is None else instrumented) else []
        externs = "".join(f"extern int zz_{i}(void);\n" for i in range(8000)) if flags else ""
        calls = "int many(void) { int s = 0;\n" + "".join(f"s += zz_{i}();\n" for i in range(8000)) + "return s; }\n" if flags else ""
        (install / "x.c").write_text(f"int x;\nint f(int *p) {{ return p[1]; }}\n{externs}{calls}")
        subprocess.run(["cc", *flags, "-c", str(install / "x.c"), "-o", str(install / "x.o")], check=True)
        for name in archives:
            subprocess.run(["ar", "rcs", str(install / "lib" / name), str(install / "x.o")], check=True)
        stub = self.dir / "bin" / "pkg-config"
        stub.write_text("#!/usr/bin/env bash\n"
                        '[ "$PKG_CONFIG_LIBDIR" = "$SPDK_PKG_CONFIG_PATH" ] || exit 1\n'
                        "case \" $* \" in\n"
                        "  *' --variable=includedir spdk_nvme '*) ;;\n"
                        f"  *' --variable=includedir libdpdk '*) echo {root} ;;\n"
                        f"  *' --variable=libdir '*) echo {install / 'lib'} ;;\n"
                        f"  *' --cflags '*) echo '{first} -include rte_config.h -march={march} -mrtm ' ;;\n"
                        f"  *' --static --libs libdpdk '*) echo '-L{install}/lib -Wl,--whole-archive -l:librte_eal.a -Wl,--no-whole-archive{asan} -lm' ;;\n"
                        "  *) echo 25.03.0 ;;\nesac\n")
        stub.chmod(0o755)

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_preflight_records_the_selected_install_and_refuses_an_unrecorded_one(self):
        self.native_install("x86-64-v2")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "preflight"], cwd=ROOT,
                              env=dict(self.env, STUB_EXIT="0"), capture_output=True, text=True, timeout=120)
        native = (self.dir / "evidence" / "native.txt").read_text()
        # The stub sits under this test's directory, so its selection is the relocated portable install's.
        self.assertIn("record crates/spdk-sys/src/generated/installs/x86_64-unknown-linux-gnu-x86-64-v2 with generated "
                      "crates/spdk-sys/src/generated/outputs/", native, step.stderr)
        output = matched(r"generated (crates/spdk-sys/src/generated/outputs/[0-9a-f]{16}) for", native).group(1)
        self.assertTrue((ROOT / output / "bindings.rs").exists(), output)
        self.assertRegex(native, r"- install compilers (GCC|clang)")
        self.assertIn("#define SPDK_CONFIG_ARCH x86-64-v2;#define RTE_MACHINE x86-64-v2", native)
        listing = (self.dir / "evidence" / "native-archives.txt").read_text()
        archive = (self.dir / "install" / "lib" / "libspdk_nvme.a").read_bytes()
        self.assertIn(f"{hashlib.sha256(archive).hexdigest()}  libspdk_nvme.a\n", listing)
        self.assertIn(f"- install archives 2 with sha256 {hashlib.sha256(listing.encode()).hexdigest()} ", native)
        self.assertIn("is evidence for x86_64 alone", native)
        self.assertIn("renamed, shared or static duplicates are outside its evidence", native)
        self.assertIn(native.splitlines()[0], (self.dir / "summary.md").read_text())
        shutil.rmtree(self.dir / "install")
        shutil.rmtree(self.dir / "evidence")
        for march, sanitizer, selected in [("x86-64-v3", False, None), ("x86-64-v2", True, None),
                                           ("native", True, "x86_64-unknown-linux-gnu-native-asan"),
                                           ("native", False, "x86_64-unknown-linux-gnu-native")]:
            with self.subTest(march=march, sanitizer=sanitizer):
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                self.native_install(march, sanitizer=sanitizer)
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "preflight"], cwd=ROOT,
                                      env=dict(self.env, STUB_EXIT="0"), capture_output=True, text=True, timeout=120)
                if selected is None:
                    self.assertEqual(step.returncode, 1, step.stderr)
                    self.assertIn("0 install records name", (self.dir / "evidence" / "failure.txt").read_text())
                else:
                    native = (self.dir / "evidence" / "native.txt").read_text()
                    self.assertIn(f"record crates/spdk-sys/src/generated/installs/{selected} with", native, step.stderr)
        shutil.rmtree(self.dir / "install", ignore_errors=True)
        shutil.rmtree(self.dir / "evidence", ignore_errors=True)
        self.native_install("x86-64-v2", flags_first="-include")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "preflight"], cwd=ROOT,
                              env=dict(self.env, STUB_EXIT="0"), capture_output=True, text=True, timeout=120)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("flags open with -include, not its include root", (self.dir / "evidence" / "failure.txt").read_text())

    def build_inputs(self, install):
        """Write `install`'s build-inputs.txt with every configure option and make variable install.sh names."""
        script = (ROOT / "crates/spdk-sys/native/install.sh").read_text()
        configure = matched(r"CONFIGURE=\((.*?)\)\n", script, re.S).group(1).split()
        variables = matched(r'MAKE_VARIABLES=\((\S+)\s+"(DPDK_DRIVERS=[^"]*)"\)', script).groups()
        (install / "share/spdk-sys").mkdir(parents=True, exist_ok=True)
        (install / "share/spdk-sys/build-inputs.txt").write_text(
            "".join(f"configure {option}\n" for option in configure) + "".join(f"make {variable}\n" for variable in variables))

    def lineage_preflight(self, lineage, patch=False):
        """Run preflight from a copy of the lane whose one install record names the stub install's flags on this
        machine, followed by `lineage`, with one patch in the copy's patch set when `patch`, and return the step,
        the record and the evidence directory."""
        root = self.dir / "root"
        shutil.rmtree(root, ignore_errors=True)
        shutil.rmtree(self.dir / "evidence", ignore_errors=True)
        (root / "scripts").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/rust-lane.sh", root / "scripts/rust-lane.sh")
        (root / "scripts/test-inventory.json").symlink_to(ROOT / "scripts/test-inventory.json")
        native = root / "crates/spdk-sys/native"
        native.mkdir(parents=True)
        (native / "install.sh").symlink_to(ROOT / "crates/spdk-sys/native/install.sh")
        if patch:
            (native / "patches").mkdir()
            (native / "patches" / "0001-fix.patch").write_text("--- a\n+++ b\n")
        generated = root / "crates/spdk-sys/src/generated"
        (generated / "outputs" / "o").mkdir(parents=True)
        (generated / "installs").mkdir()
        record = generated / "installs" / "stub"
        target = f"{platform.machine()}-unknown-linux-gnu"
        record.write_text(f"Target: {target}. Flags: -I/elsewhere/include -include rte_config.h -march=stub -mrtm -Inative\n"
                          f"Header digest: {'1' * 64}\nOutput: o\n{lineage}")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "preflight"], cwd=root, env=dict(self.env, STUB_EXIT="0"),
                              capture_output=True, text=True, timeout=120)
        return step, record, self.dir / "evidence"

    def test_preflight_binds_the_record_lineage_and_refuses_one_the_install_does_not_measure(self):
        self.native_install("stub")
        self.build_inputs(self.dir / "install")
        # The stub cargo lists no registry tests, so preflight stops after the identity this test reads.
        step, record, evidence = self.lineage_preflight("")
        self.assertIn("- install record lineage unrecorded", (evidence / "native.txt").read_text(), step.stderr)
        self.assertIn("- install record crates/spdk-sys/src/generated/installs/stub lineage unrecorded",
                      (self.dir / "summary.md").read_text())
        measured = subprocess.run(["bash", str(ROOT / "crates/spdk-sys/native/install.sh"), "measure",
                                   str(self.dir / "install" / "lib"), str(self.dir / "install" / "include"), str(self.dir)],
                                  capture_output=True, text=True, check=True).stdout
        lineage = f"Source: SPDK {self.env['SPDK_COMMIT']} DPDK {self.env['DPDK_COMMIT']}\n{measured}"
        inputs = (self.dir / "install/share/spdk-sys/build-inputs.txt").read_bytes()
        self.assertIn(f"Build inputs: {hashlib.sha256(inputs).hexdigest()}\n", measured)
        step, record, evidence = self.lineage_preflight(lineage)
        self.assertNotIn("lineage", (evidence / "failure.txt").read_text(), step.stderr)
        digest = hashlib.sha256(record.read_bytes()).hexdigest()
        self.assertIn(f"- install record lineage {digest}", (evidence / "native.txt").read_text())
        for stale, change in (("an archive", lambda text: text.replace(text.split("Archive: ")[1][:8], "00000000", 1)),
                              ("a source commit", lambda text: text.replace(self.env["SPDK_COMMIT"], "0" * 40)),
                              ("a compiler", lambda text: text.replace("Compilers: ", "Compilers: other;")),
                              ("a configuration", lambda text: text.replace("Configure: ", "Configure: 0", 1)),
                              ("the build inputs", lambda text: text.replace("Build inputs: ", "Build inputs: 0", 1)),
                              ("the patch set", None)):
            with self.subTest(stale=stale):
                step, _, evidence = self.lineage_preflight(change(lineage) if change else lineage, patch=change is None)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn("records a lineage this install does not measure", (evidence / "failure.txt").read_text())

    def test_the_controlled_build_records_its_install_and_leaves_no_tree(self):
        """`install.sh build`, over a stub clone, configure and make, keeps its build inputs, records the install's
        lineage and exits 0; a failed clone exits 1. Either way its scratch tree is gone. The stub clone holds no
        submodule, and the stub configure exits as the pinned SPDK configure does on x86_64 and aarch64 unless the
        `isa-l` and `isa-l-crypto` submodules are initialized, so the build must initialize them with `dpdk`. The
        stub `make install` delivers the staged install into PREFIX, which the build requires to start empty."""
        self.native_install("stub")
        staged = self.dir / "staged"
        shutil.move(self.dir / "install", staged)
        script = (ROOT / "crates/spdk-sys/native/install.sh").read_text()
        commits = {name: matched(rf"(?m)^{name}=(\w+)$", script).group(1) for name in ("SPDK_COMMIT", "DPDK_COMMIT")}
        crate = self.dir / "crate"
        self.install_sh_crate(crate)
        record = crate / f"src/generated/installs/{platform.machine()}-unknown-linux-gnu-stub"
        record.write_text(f"Target: {platform.machine()}-unknown-linux-gnu. Flags: -I/elsewhere/include -include rte_config.h "
                          f"-march=stub -mrtm -Inative\nHeader digest: {self.HEADER_DIGEST}\nOutput: o\n")
        configure = self.dir / "configure"
        configure.write_text("#!/bin/sh\nfor module in isa-l isa-l-crypto; do\n"
                             '  [ -f "$module/autogen.sh" ] || { echo "$module is required but was not found" >&2; exit 1; }\n'
                             "done\n")
        stubs = {
            "git": "#!/usr/bin/env bash\n"
                   '[ "$1" != clone ] || { [ -z "$STUB_CLONE_FAILS" ] || exit 1; mkdir -p "${!#}"; '
                   f'install -m 755 {shlex.quote(str(configure))} "${{!#}}/configure"; exit 0; }}\n'
                   '[ "$3" != submodule ] || { tree=$2; shift 6; [ $# -gt 0 ] || set -- dpdk isa-l isa-l-crypto; '
                   'for module; do mkdir -p "$tree/$module"; : > "$tree/$module/autogen.sh"; done; exit 0; }\n'
                   f'[ "$3" != rev-parse ] || {{ case "$2" in */dpdk) echo {commits["DPDK_COMMIT"]} ;; '
                   f'*) echo {commits["SPDK_COMMIT"]} ;; esac; }}\n',
            "make": '#!/usr/bin/env bash\n[ "$1" != install ] || { mkdir -p "$STUB_PREFIX" && cp -a "$STUB_INSTALL"/. "$STUB_PREFIX"/; }\n',
        }
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        scratch = self.dir / "tmp"
        scratch.mkdir()
        install = self.dir / "install"
        env = dict(self.env, SPDK_PKG_CONFIG_PATH=str(install / "lib/pkgconfig"), TMPDIR=str(scratch),
                   STUB_INSTALL=str(staged), STUB_PREFIX=str(install))
        build = ["bash", str(crate / "native/install.sh"), "build", str(install), "--target-arch=stub"]
        step = subprocess.run(build, env=dict(env, STUB_CLONE_FAILS="1"), capture_output=True, text=True, timeout=60)
        self.assertNotEqual(step.returncode, 0)
        self.assertEqual(list(scratch.iterdir()), [], "a failed build leaves no tree")
        step = subprocess.run(build, env=env, capture_output=True, text=True, timeout=60)
        self.assertEqual(step.returncode, 0, step.stderr)
        self.assertEqual(list(scratch.iterdir()), [], "a recorded build leaves no tree")
        inputs = (install / "share/spdk-sys/build-inputs.txt").read_text()
        self.assertIn(f"configure --prefix={install}\nconfigure --target-arch=stub\n", inputs)
        written = record.read_text()
        self.assertIn(f"Source: SPDK {commits['SPDK_COMMIT']} DPDK {commits['DPDK_COMMIT']}\n", written)
        self.assertIn(f"Build inputs: {hashlib.sha256(inputs.encode()).hexdigest()}\n", written)

    def test_the_controlled_build_pins_the_workflow_commits_and_the_documented_options(self):
        """The controlled build's commits are the workflow's native pins, and its configure options and make
        variables are the ones crates/spdk-sys/src/lib.rs documents."""
        script = (ROOT / "crates/spdk-sys/native/install.sh").read_text()
        workflow = WORKFLOW.read_text()
        for name in ("SPDK_COMMIT", "DPDK_COMMIT"):
            pinned = matched(rf"(?m)^{name}=(\w+)$", script).group(1)
            self.assertIn(f"  {name}: {pinned}\n", workflow, name)
        documented = (ROOT / "crates/spdk-sys/src/lib.rs").read_text()
        block = matched(r"//! \./configure (.*?)//! sudo make install", documented, re.S).group(1)
        block = " ".join(" ".join(line.removeprefix("//!").strip().rstrip("\\") for line in block.splitlines()).split())
        configure = matched(r"CONFIGURE=\((.*?)\)\n", script, re.S).group(1).split()
        self.assertEqual(set(configure), {token for token in block.split() if token.startswith("--")} - {"--prefix=/usr/local"})
        variables = matched(r'MAKE_VARIABLES=\((\S+)\s+"DPDK_DRIVERS=([^"]*)"\)', script)
        self.assertIn(f"make {variables.group(1)} DPDK_DRIVERS=\"{variables.group(2)}\"", block)

    def test_the_controlled_build_writes_the_lineage_and_only_from_its_own_record(self):
        """`install.sh record` refuses an install the controlled build did not write, one that measures other than
        the build recorded, or a record whose header digest is other than this install's headers' (regenerate.sh
        rewrites the record first); it rewrites the lineage of the record whose target line is the install's, and
        refuses a record whose target line names other flags, including a flag between the include root and
        `-include`: only the include root is normalized."""
        self.native_install("stub")
        crate = self.dir / "crate"
        self.install_sh_crate(crate)
        record = crate / f"src/generated/installs/{platform.machine()}-unknown-linux-gnu-stub"
        head = (f"Target: {platform.machine()}-unknown-linux-gnu. Flags: -I/elsewhere/include -include rte_config.h "
                f"-march=stub -mrtm -Inative\nHeader digest: {self.HEADER_DIGEST}\nOutput: o\n")
        record.write_text(head + "Source: SPDK old DPDK old\nArchive: " + "9" * 64 + "  libgone.a\n")
        install = self.dir / "install"
        env = dict(self.env, SPDK_PKG_CONFIG_PATH=str(install / "lib/pkgconfig"))

        def run():
            return subprocess.run(["bash", str(crate / "native/install.sh"), "record", str(install)], env=env,
                                  capture_output=True, text=True, timeout=60)

        step = run()
        self.assertEqual(step.returncode, 1)
        self.assertIn("only the controlled build writes a lineage", step.stderr)
        (install / "share/spdk-sys").mkdir(parents=True)
        self.build_inputs(install)
        measured = subprocess.run(["bash", str(crate / "native/install.sh"), "measure", str(install / "lib"),
                                   str(install / "include"), str(self.dir)], capture_output=True, text=True, check=True).stdout
        (install / "share/spdk-sys/build.txt").write_text("Source: SPDK a DPDK b\n" + measured.replace("Compilers: ", "Compilers: x;"))
        step = run()
        self.assertEqual(step.returncode, 1)
        self.assertIn("measures other than its controlled build", step.stderr)
        (install / "share/spdk-sys/build.txt").write_text("Source: SPDK a DPDK b\n" + measured)
        record.write_text(head.replace(self.HEADER_DIGEST, "1" * 64) + "Source: SPDK old DPDK old\n")
        step = run()
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn(f"records headers with digest {'1' * 64}, and this install's headers digest {self.HEADER_DIGEST}; "
                      "run regenerate.sh against this install, then install.sh record", step.stderr)
        self.assertIn("Source: SPDK old DPDK old\n", record.read_text(), "a refused record keeps its lineage")
        record.write_text(head + "Source: SPDK old DPDK old\nArchive: " + "9" * 64 + "  libgone.a\n")
        step = run()
        self.assertEqual(step.returncode, 0, step.stderr)
        written = record.read_text()
        self.assertEqual(written, head + "Source: SPDK a DPDK b\n" + measured)
        digest = hashlib.sha256((install / "lib/librte_eal.a").read_bytes()).hexdigest()
        self.assertIn(f"Archive: {digest}  librte_eal.a\n", written)
        self.assertNotIn("libgone.a", written, "the lineage is rewritten, not appended")
        record.write_text(head.replace("-march=stub", "-march=other"))
        step = run()
        self.assertEqual(step.returncode, 1)
        self.assertIn("-march=other -mrtm -Inative`, not this install's", step.stderr)
        record.write_text(head.replace("-I/elsewhere/include -include", "-I/elsewhere/include -DNDEBUG -include"))
        step = run()
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("-DNDEBUG -include rte_config.h -march=stub -mrtm -Inative`, not this install's", step.stderr)

    def measure(self, env=None):
        """Run `install.sh measure` over the stub install into this test's directory and return the step."""
        install = self.dir / "install"
        return subprocess.run(["bash", str(ROOT / "crates/spdk-sys/native/install.sh"), "measure", str(install / "lib"),
                               str(install / "include"), str(self.dir)], env=env, capture_output=True, text=True,
                              timeout=60)

    def test_measure_lists_every_archive_once_in_byte_order_with_its_digest(self):
        """`measure` hashes the archives in several background slices, and under a collating locale its `Archive` lines
        still name every archive once, in byte order, with that archive's sha256, and native-archives.txt holds the
        libspdk_ lines and then the librte_ lines in the same order."""
        spdk = ["libspdk_nvme.a", "libspdk_ut_mock.a", "libspdk_util.a", "libspdk_Log.a", "libspdk_env_dpdk.a"]
        rte = ["librte_eal.a", "librte_ring.a", "librte_Bus_pci.a"]
        self.native_install("stub", archives=(*spdk, *rte, "libisal.a", "libisal_crypto.a"))
        lib = self.dir / "install" / "lib"
        for index, archive in enumerate(sorted(lib.glob("*.a"))):
            (self.dir / "stamp.c").write_text(f"int stamp_{index};\n")
            subprocess.run(["cc", "-c", str(self.dir / "stamp.c"), "-o", str(self.dir / "stamp.o")], check=True)
            subprocess.run(["ar", "r", str(archive), str(self.dir / "stamp.o")], check=True, capture_output=True)
        step = self.measure(dict(os.environ, LC_ALL="en_US.UTF-8"))
        self.assertEqual(step.returncode, 0, step.stderr)
        digest = {path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in lib.glob("*.a")}
        self.assertEqual(len(set(digest.values())), len(digest), "every archive has its own bytes")
        names = sorted(digest, key=str.encode)
        self.assertEqual([line for line in step.stdout.splitlines() if line.startswith("Archive: ")],
                         [f"Archive: {digest[name]}  {name}" for name in names])
        self.assertEqual((self.dir / "native-archives.txt").read_text(),
                         "".join(f"{digest[name]}  {name}\n" for name in sorted(spdk, key=str.encode) + sorted(rte, key=str.encode)))
        self.assertRegex(step.stdout, r"\nCompilers: (GCC|clang)[^\n]*\nConfigure: [0-9a-f]{64}\n")

    def test_measure_digests_build_inputs_naming_every_input_and_marks_others_stale(self):
        """`measure` names a build-inputs.txt `stale` unless every configure option and make variable install.sh names
        is one of its whole lines, digests one that names them all, and names an absent one `unrecorded`."""
        self.native_install("stub")
        install = self.dir / "install"
        self.build_inputs(install)
        inputs = install / "share/spdk-sys/build-inputs.txt"
        whole = inputs.read_text()
        option = whole.splitlines()[0]
        for text, expected in ((whole, None), (whole.rstrip("\n"), None), ("extra\n\n" + whole, None),
                               (whole.replace(f"{option}\n", ""), "stale"),
                               (whole.replace(f"{option}\n", f"{option} \n"), "stale"),
                               (whole.replace("\n", "\r\n"), "stale")):
            with self.subTest(text=text[:40]):
                inputs.write_bytes(text.encode())
                step = self.measure()
                self.assertEqual(step.returncode, 0, step.stderr)
                value = expected or hashlib.sha256(text.encode()).hexdigest()
                self.assertIn(f"\nBuild inputs: {value}\n", step.stdout)
        inputs.unlink()
        self.assertIn("\nBuild inputs: unrecorded\n", self.measure().stdout)

    def qualified_lane(self, lane, run, exit_code=0):
        """Run the qualified test lane LANE over a stub target whose selected run prints `run`, then credit its evidence.

        `run` is formatted with the target's `header`, the `filtered` count of a run by exact ID, the selection's
        `outcomes` and every row's sample `lines`.
        """
        declared = json.loads((ROOT / "scripts/test-inventory.json").read_text())["qualified"][lane]
        selection = [test for row in declared["rows"] for test in row["tests"]]
        header = select_fixture.QUALIFIED_HEADERS[lane]
        ignores = select_fixture.QUALIFIED_IGNORED[lane]
        names = [*(selection if not declared["ignored"] else []), "filler::an_unselected_case", *ignores]

        def listing(listed):
            return "\n".join([header, *(f"{name}: test" for name in listed), "", f"{len(listed)} tests, 0 benchmarks", ""])

        self.native_install("x86-64-v2")
        lines = "".join(f"{line}\n" for row in declared["rows"] for line in select_fixture.ROW_LINES[row["id"]])
        outcomes = "".join(f"test {name} ... ok\n" for name in selection)
        stubs = {"list": listing(names), "ignored": listing(ignores),
                 "run": run.format(header=header, filtered=len(names) - len(selection), outcomes=outcomes, lines=lines,
                                   passed=len(selection))}
        for name, text in stubs.items():
            (self.dir / f"stub-{name}.txt").write_text(text)
        calls = self.dir / "cargo-calls.txt"
        calls.unlink(missing_ok=True)
        env = dict(self.env, STUB_LIST=str(self.dir / "stub-list.txt"), STUB_IGNORED=str(self.dir / "stub-ignored.txt"),
                   STUB_RUN=str(self.dir / "stub-run.txt"), STUB_RUN_EXIT=str(exit_code), STUB_ENV=str(calls),
                   STUB_ENV_DUMP=str(self.dir / "cargo-env.txt"))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", lane], cwd=ROOT, env=env, capture_output=True,
                              text=True, timeout=120)
        evidence = self.dir / "evidence"
        credit = subprocess.run([sys.executable, "scripts/verify-receipts.py", "credit", "--job", lane,
                                 "--evidence", str(evidence)], cwd=ROOT, env=env, capture_output=True, text=True,
                                timeout=120)
        return step, json.loads(credit.stdout), calls.read_text().splitlines(), selection

    PASSED = ("{header}\n\nrunning {passed} tests\n{lines}{outcomes}\n"
              "test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n")

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_each_qualified_lane_credits_only_its_rows_passed_by_exact_id(self):
        expected = {
            "long-run": ("--test sim_worker -- --ignored --nocapture --exact", "Long-run gate",
                         ["long-run-gate-passes-every-check-within-its-bounds",
                          "long-run-scaled-seeds-and-geometries-pass-on-one-engine-each",
                          "warm-cycle-histories-pass-on-seeds-1-to-16-as-unpowered-discovery",
                          "publishing-restart-cycles-load-the-published-cut-plus-the-suffix",
                          "roll-cycles-restart-at-e-plus-one-with-every-acknowledged-mutation",
                          "fleet-runs-pass-on-roots-1-to-16",
                          "slot-reuse-cycles-pass-on-seeds-1-to-16-as-unpowered-discovery",
                          "handoff-cycles-hold-every-acknowledged-mutation-across-both-hosts"]),
            "campaigns": ("--test sim_worker -- --nocapture --exact", "Worker campaigns",
                          ["worker-campaigns-replay-bundles-and-trees-in-fresh-processes",
                           "lane-credit-derives-the-selection-verdict-from-the-raw-run",
                           "fleet-pinned-runs-report-one-digest-in-fresh-processes"]),
            "search": ("--lib -- --nocapture --exact", "ServeCore search, pull-request bound",
                       ["serve-search-exhausts-its-pull-request-bound"]),
            "search-nightly": ("--lib -- --ignored --nocapture --exact", "ServeCore search, nightly bounds",
                               ["serve-search-exhausts-its-nightly-bound",
                                "serve-search-exhausts-its-prefinal-ack-bound",
                                "serve-search-exhausts-its-completed-held-bound",
                                "serve-search-due-get-stages-within-k-under-reply-pressure",
                                "fleet-alarm-sets-match-on-root-1-of-every-scenario",
                                "fleet-volume-scenarios-pass-on-their-second-root-and-every-replacement-crash-cell",
                                "fleet-zone-repair-and-host-scenarios-pass-on-their-second-root",
                                "fleet-restart-host-loss-and-replay-checks-pass-on-their-scheduled-roots",
                                "fleet-declared-holds-leave-the-self-suspicion-count-and-brake-nominations-at-three"]),
        }
        for lane, (command, title, obligations) in expected.items():
            with self.subTest(lane=lane):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                (self.dir / "summary.md").unlink(missing_ok=True)
                step, credit, calls, selection = self.qualified_lane(lane, self.PASSED)
                self.assertEqual(step.returncode, 0, step.stderr)
                self.assertEqual((credit["code"], credit["refusals"], credit["executions"]), (0, [], len(selection)), credit)
                self.assertEqual(credit["obligations"], obligations)
                run = [call for call in calls if " --exact " in call]
                self.assertEqual(len(run), 1, calls)
                self.assertTrue(run[0].endswith(f"+1.99.0 test -p kestrike {command} {' '.join(selection)}"), run)
                self.assertTrue(all(call.startswith("encoded unset ") for call in calls), calls)
                dumped = (self.dir / "cargo-env.txt").read_text().splitlines()
                self.assertIn("CARGO_PROFILE_DEV_OPT_LEVEL=1", dumped)
                self.assertIn("CARGO_PROFILE_DEV_DEBUG=line-tables-only", dumped)
                evidence = self.dir / "evidence"
                self.assertIn("SPDK 25.5.1 at spdk-commit", (evidence / "pins.txt").read_text())
                self.assertIn(f"{command} {selection[0]}", (evidence / "replay.txt").read_text())
                receipt = json.loads((evidence / "receipt.json").read_text())
                self.assertEqual((receipt["completion"], receipt["executed"], receipt["selection"]["cfg"], receipt["selection"]["module"]),
                                 ("completed", sorted(selection), "qualified", lane))
                summary = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", lane], cwd=ROOT, env=self.env,
                                         capture_output=True, text=True)
                self.assertEqual(summary.returncode, 0, summary.stderr)
                text = (self.dir / "summary.md").read_text()
                self.assertIn(f"### {title}: selection credited", text)
                side = "among the ignored cases of" if lane in ("long-run", "search-nightly") else "in"
                self.assertIn(f"- {len(selection)} of {len(selection)} selected cases executed by exact ID {side} ", text)
                for row in json.loads((evidence / "report.json").read_text())["rows"]:
                    self.assertIn(f"- row {row['id']} ({row['kind']}): credited", text)
                if lane == "long-run":
                    self.assertIn("- long-run: marks: device_commands 3/4, device_growth 0/0", text)

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_a_qualified_lane_refuses_a_zero_selection_an_interruption_a_missing_summary_and_a_blocked_row(self):
        zero = ("{header}\n\nrunning 0 tests\n\n"
                "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 3 filtered out; finished in 0.00s\n")
        cut = "{header}\n\nrunning 1 test\nlong-run: churn: seed 10\n"
        failed = ("{header}\n\nrunning 3 tests\n{lines}test long_run::the_long_run_gate_passes ... FAILED\n"
                  "test scaled::every_seed_passes_on_one_engine_each ... ok\n"
                  "test scaled::every_larger_geometry_passes_on_one_engine_each ... ok\n\n"
                  "test result: FAILED. 2 passed; 1 failed; 0 ignored; 0 measured; {filtered} filtered out; finished in 0.00s\n")
        unwitnessed = self.PASSED.replace("{lines}", "")
        for name, lane, run, exit_code, codes in (
            ("zero selection", "long-run", zero, 0, {"selection-refused", "zero-executions", "missing-result"}),
            ("interruption", "long-run", cut, 124, {"timeout", "zero-executions", "missing-result"}),
            ("missing summary", "long-run", cut, 0, {"selection-refused", "zero-executions", "missing-result"}),
            ("failed case", "long-run", failed, 101, {"selection-refused", "raw-failed", "missing-result"}),
            ("missing witnesses", "campaigns", unwitnessed, 0, {"selection-refused"}),
            ("capped search", "search", self.PASSED.replace("{lines}", "serve-search-shallow: Incomplete Totals {{ alphabet: 12, depth: 5 }}\n"),
             0, {"selection-refused"}),
        ):
            with self.subTest(case=name):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                (self.dir / "summary.md").unlink(missing_ok=True)
                step, credit, _, _ = self.qualified_lane(lane, run, exit_code)
                self.assertNotEqual(step.returncode, 0, step.stdout)
                self.assertEqual(credit["code"], 1, credit)
                self.assertEqual({refusal["code"] for refusal in credit["refusals"]}, codes, credit)
                report = json.loads((self.dir / "evidence" / "report.json").read_text())
                self.assertFalse(report["credited"], report)
                if name in ("missing witnesses", "capped search"):
                    self.assertIn("blocked rows: ", report["reason"])
                    subprocess.run(["bash", "scripts/rust-lane.sh", "summary", lane], cwd=ROOT, env=self.env, check=True,
                                   capture_output=True)
                    text = (self.dir / "summary.md").read_text()
                    blocked = [row for row in report["rows"] if not row["credited"]]
                    self.assertTrue(blocked, report)
                    for row in blocked:
                        self.assertIn(f"- row {row['id']} ({row['kind']}): blocked: {'; '.join(row['reasons'])}", text)

    SPDK_HEADER = "     Running unittests src/lib.rs (/tmp/asan/x86_64-unknown-linux-gnu/debug/deps/spdk_sys-b25a6d8b23b3044e)"
    CACHE_HEADER = "     Running unittests src/lib.rs (/tmp/asan/x86_64-unknown-linux-gnu/debug/deps/kestrike-9182b89a273caa7d)"

    def symbolizer_stub(self, usable=True, directory=None):
        """A stub `llvm-symbolizer` in `directory` (this test's bin by default) whose `--version` reports the pinned
        LLVM or, when not `usable`, fails."""
        directory = directory or self.dir / "bin"
        report = "printf 'LLVM (http://llvm.org/):\\n  LLVM version 22.1.8\\n'" if usable else "echo 'stub: unusable' >&2; exit 1"
        (directory / "llvm-symbolizer").write_text(f"#!/usr/bin/env bash\n[ \"$*\" != --version ] || {{ {report}; exit 0; }}\nexit 1\n")
        (directory / "llvm-symbolizer").chmod(0o755)

    def asan_lane(self, exit_code=0, sanitizer=True, controls=None, runtime=True, failed=(), envelope=True, symbolizer=True,
                  instrumented=None):
        """Run the ASan lane over a stub install (its archives uninstrumented when `instrumented` is False) and stub
        cargo whose listings hold the shim `controls` (every required one by default) beside a witness of each
        required kestrike module and every required kestrike test, under a stub `llvm-symbolizer` that reports the pinned LLVM or, without
        `symbolizer`, fails its version query, then credit its evidence; without `envelope`,
        scripts/qualified-envelope.py refuses."""
        inventory = json.loads((ROOT / "scripts/test-inventory.json").read_text())
        registry = json.loads((ROOT / "scripts/test-registry.json").read_text())
        asan = inventory["asan"]
        controls = asan["required"]["spdk_sys"]["tests"] if controls is None else list(controls)
        spdk = [*controls, "registry_tests::a_registry_probe"]
        witnesses = [f"{module}::a_sanitized_witness" for module in asan["required"]["kestrike"]["modules"]]
        witnesses += asan["required"]["kestrike"]["tests"]
        ignored = sorted(row["id"] for row in registry["rows"] if row["cfg"] in ("ordinary", "asan") and row["target"] == "kestrike")

        def listing(sections):
            text = ""
            for header, names in sections:
                text += "\n".join([header, *(f"{name}: test" for name in names), "", f"{len(names)} tests, 0 benchmarks", ""])
            return text

        def run(sections):
            text = ""
            for header, names, skipped in sections:
                lines = [f"test {name} ... {'FAILED' if name in failed else 'ok'}" for name in names]
                lines += [f"test {name} ... ignored, needs hardware" for name in skipped]
                failures = len(set(names) & set(failed))
                text += (f"{header}\n\nrunning {len(names) + len(skipped)} tests\n" + "\n".join(lines)
                         + f"\n\ntest result: {'ok' if not failures else 'FAILED'}. {len(names) - failures} passed; {failures} failed; "
                         f"{len(skipped)} ignored; 0 measured; 0 filtered out; finished in 0.53s\n")
            return text

        self.native_install("native", sanitizer=sanitizer, instrumented=instrumented)
        sysroot = self.dir / "sysroot"
        archive = sysroot / "lib/rustlib/x86_64-unknown-linux-gnu/lib/librustc-nightly_rt.asan.a"
        if runtime:
            archive.parent.mkdir(parents=True)
            archive.write_bytes(b"!<arch>\n")
        stubs = {
            "list": listing([(self.SPDK_HEADER, spdk), (self.CACHE_HEADER, [*witnesses, *ignored])]),
            "ignored": listing([(self.SPDK_HEADER, []), (self.CACHE_HEADER, ignored)]),
            "run": run([(self.SPDK_HEADER, spdk, []), (self.CACHE_HEADER, witnesses, ignored)]),
        }
        for name, text in stubs.items():
            (self.dir / f"stub-{name}.txt").write_text(text)
        self.symbolizer_stub(symbolizer)
        calls = self.dir / "cargo-calls.txt"
        env = dict(self.env, STUB_LIST=str(self.dir / "stub-list.txt"), STUB_IGNORED=str(self.dir / "stub-ignored.txt"),
                   STUB_RUN=str(self.dir / "stub-run.txt"), STUB_RUN_EXIT=str(exit_code), STUB_ENV=str(calls),
                   STUB_ENV_DUMP=str(self.dir / "cargo-env.txt"), STUB_SYSROOT=str(sysroot), GITHUB_RUN_ATTEMPT="3", GITHUB_RUN_ID="70")
        if not envelope:
            refusing = self.dir / "refusing-python"
            refusing.mkdir(exist_ok=True)
            (refusing / "python3").write_text(
                '#!/usr/bin/env bash\ncase "$1" in\n'
                '  *qualified-envelope.py) echo "qualified-envelope: a stub refusal" >&2; exit 1 ;;\nesac\n'
                f'exec {sys.executable} "$@"\n')
            (refusing / "python3").chmod(0o755)
            env["PATH"] = f"{refusing}:{env['PATH']}"
        lane = subprocess.run(["bash", "scripts/rust-lane.sh", "asan"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        evidence = self.dir / "evidence"
        credit = subprocess.run([sys.executable, "scripts/verify-receipts.py", "credit", "--job", "asan", "--evidence", str(evidence)],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        return lane, json.loads(credit.stdout), calls.read_text().splitlines() if calls.exists() else []

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_the_asan_lane_credits_the_qualified_domain_from_its_envelope_and_controls(self):
        lane, credit, calls = self.asan_lane()
        self.assertEqual(lane.returncode, 0, lane.stderr)
        self.assertEqual((credit["code"], credit["refusals"], credit["obligations"]),
                         (0, [], ["mc-log-capture-lifetime", "dpdk-chain-judges-refuse-changed-custody"]), credit)
        evidence = self.dir / "evidence"
        receipt = json.loads((evidence / "receipt.json").read_text())
        envelope = receipt["qualified"]
        self.assertEqual((envelope["domain"], envelope["attempt"], envelope["run"], envelope["sanitizer"], envelope["target"]),
                         ("asan", "3", "70", "address", "x86_64-unknown-linux-gnu"))
        self.assertEqual(envelope["install"], "crates/spdk-sys/src/generated/installs/x86_64-unknown-linux-gnu-native-asan")
        record = (ROOT / envelope["install"]).read_text()
        self.assertIn(f"Header digest: {envelope['header_digest']}\n", record)
        output = matched(r"^Output: ([0-9a-f]{16})$", record, re.M).group(1)
        self.assertEqual(envelope["generated"], f"crates/spdk-sys/src/generated/outputs/{output}")
        bindings = (ROOT / envelope["generated"] / "bindings.rs").read_text()
        self.assertIn(f"// Generator digest: {envelope['generator_digest']}\n", bindings)
        self.assertIn(f"// {envelope['generator']}\n", bindings)
        self.assertRegex(envelope["native"]["compilers"], r"^(GCC|clang)")
        self.assertEqual(envelope["runtime"]["sha256"], hashlib.sha256(b"!<arch>\n").hexdigest())
        self.assertEqual((envelope["runtime"]["rustc"], envelope["runtime"]["llvm"]), ("rustc nightly-2026-07-27 (stub)", "22.1.8"))
        self.assertEqual(envelope["deadlines"]["build_minutes"] * 60, 15 * 60)
        required_count = len(json.loads((ROOT / "scripts/test-inventory.json").read_text())["asan"]["required"]["kestrike"]["tests"])
        self.assertEqual(receipt["bounds"]["targets"]["kestrike"]["witnesses"]["executed_modules"],
                         {"bind": 1, "index": 1, "native": 1 + required_count})
        self.assertEqual((receipt["completion"], receipt["selection"]["cfg"], receipt["executions"]), ("completed", "asan", 6 + required_count))
        self.assertIn("qualified.json", receipt["inputs"])
        runs = [call for call in calls if " --no-fail-fast" in call]
        self.assertEqual(len(runs), 1, calls)
        self.assertTrue(runs[0].endswith("+nightly-2026-07-27 test -Zbuild-std --target x86_64-unknown-linux-gnu -p spdk-sys -p kestrike --lib --no-fail-fast"), runs)
        self.assertTrue(all(call.startswith("encoded unset ") for call in calls), calls)
        dumped = env_dump(self.dir / "cargo-env.txt")
        self.assertEqual(dumped.get("RUSTFLAGS"), "-Zsanitizer=address -Cforce-frame-pointers=yes")
        self.assertEqual(dumped.get("ASAN_OPTIONS"), "detect_leaks=0")
        self.assertEqual(dumped.get("CARGO_PROFILE_DEV_OPT_LEVEL"), "1")
        self.assertIn("RUSTFLAGS=-Zsanitizer=address -Cforce-frame-pointers=yes; ASAN_OPTIONS=detect_leaks=0", (evidence / "pins.txt").read_text())
        self.assertIn(f"- llvm-symbolizer {self.dir / 'bin' / 'llvm-symbolizer'}; LLVM (http://llvm.org/): LLVM version 22.1.8\n",
                      (evidence / "pins.txt").read_text())
        self.assertIn("CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only SPDK_PKG_CONFIG_PATH=", (evidence / "replay.txt").read_text())
        self.assertIn("ASAN_OPTIONS=detect_leaks=0 cargo +nightly-2026-07-27 test -Zbuild-std", (evidence / "replay.txt").read_text())
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "asan"], cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        for line in ("### Address-sanitized library tests: selection credited",
                     f"- kestrike: {3 + required_count} executed, {receipt['bounds']['targets']['kestrike']['observed_ignored']} ignored",
                     f"attributed per module: bind 1, index 1, native {1 + required_count}",
                     "- spdk_sys: 3 executed, 0 ignored; controls `shim_tests::a_one_byte_header_read_is_reported_at_the_shim_frame`",
                     "- attempt 3; target x86_64-unknown-linux-gnu; sanitizer address",
                     "- leak detection off"):
            self.assertIn(line, summary)

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_the_asan_lane_refuses_an_unsanitized_install_a_missing_runtime_a_refused_envelope_a_missing_control_and_a_cut_run(self):
        kwargs: Dict[str, Any]
        for name, kwargs, failure, codes in (
            ("unsanitized install", dict(sanitizer=False), "links no -lasan",
             {"tool-failure", "missing-provenance", "zero-executions", "unqualified", "missing-result"}),
            ("missing runtime", dict(runtime=False), "no address sanitizer runtime",
             {"tool-failure", "missing-provenance", "zero-executions", "unqualified", "missing-result"}),
            ("unusable symbolizer", dict(symbolizer=False), "llvm-symbolizer --version failed",
             {"tool-failure", "missing-provenance", "zero-executions", "unqualified", "missing-result"}),
            ("uninstrumented archives", dict(instrumented=False), "references no __asan_init",
             {"tool-failure", "missing-provenance", "zero-executions", "unqualified", "missing-result"}),
            ("refused envelope", dict(envelope=False), "the qualified envelope was refused",
             {"tool-failure", "zero-executions", "unqualified", "missing-result"}),
            ("missing control", dict(controls=["shim_tests::the_golden_header_checksums_to_its_published_value"]),
             "select-tests.py listing", {"tool-failure", "zero-executions", "unqualified", "missing-result"}),
            ("cut run", dict(exit_code=143), "run", {"timeout"}),
            ("failed control", dict(exit_code=101, failed=["shim_tests::a_one_byte_header_read_is_reported_at_the_shim_frame"]),
             "run", {"selection-refused", "raw-failed", "unqualified", "missing-result"}),
        ):
            with self.subTest(case=name):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                shutil.rmtree(self.dir / "sysroot", ignore_errors=True)
                for stale in self.dir.glob("cargo-*.txt"):
                    stale.unlink()
                lane, credit, _ = self.asan_lane(**kwargs)
                self.assertNotEqual(lane.returncode, 0, lane.stdout)
                self.assertEqual(credit["code"], 1, credit)
                self.assertEqual({refusal["code"] for refusal in credit["refusals"]}, codes, credit)
                evidence = self.dir / "evidence"
                if (evidence / "failure.txt").exists():
                    self.assertIn(failure, (evidence / "failure.txt").read_text())
                if name in ("unsanitized install", "missing runtime", "unusable symbolizer", "uninstrumented archives", "refused envelope"):
                    self.assertFalse((evidence / "list.txt").exists(), "the refusal came before any build")
                if name == "refused envelope":
                    self.assertIn(failure, (evidence / "failure.txt").read_text())
                    self.assertFalse((evidence / "qualified.json").exists(), "a refused envelope leaves no qualified.json")
                    self.assertIsNone(json.loads((evidence / "receipt.json").read_text())["qualified"])

    QEMU_MEASURED = {"domain": "qemu", "date": "2026-10-16",
                     "host": {"machine": platform.machine(), "runners": ["kestrike-heavy-1", "kestrike-heavy-2"], "accel": "tcg"},
                     "guest": {"cpus": 2, "memory_mib": 2048, "backing_mib": 64}, "cpus": 4, "memory_mib": 12288, "handshake_seconds": 40, "run_seconds": 30, "build_peak_rss_mib": 3500, "peak_rss_mib": 3000}

    def guest_inputs(self, mode="pass", artifact_changes=None, lines=None, accel="tcg"):
        """Provision the guest lane's inputs under this test's directory: the fake QEMU of test-guest-binder.py
        playing `mode`, a kernel and initrd, an artifact reference naming the committed portable install record, and
        the inputs file naming `accel` (appended to `lines` that name none); returns its path."""
        guest = load("test_guest_binder", ROOT / "scripts/test-guest-binder.py")
        envelope = load("qualified_envelope", ROOT / "scripts/qualified-envelope.py")
        qemu = self.dir / "qemu-system-x86_64"
        qemu.write_text(guest.QEMU)
        qemu.chmod(0o755)
        (self.dir / "bzImage").write_bytes(b"bzImage")
        # A compressed base, as dracut writes one, whose length leaves the appended archive off a 4-byte boundary.
        base = gzip.compress(b"base initramfs", mtime=0)
        self.assertNotEqual(len(base) % 4, 0)
        (self.dir / "initrd.img").write_bytes(base)
        record = envelope.INSTALLS / "x86_64-unknown-linux-gnu-x86-64-v2"
        found = envelope.recorded(record, envelope.output_bindings(record))
        reference = {"target": found["target"], "rustflags": "-Ctarget-cpu=x86-64-v2", "generated": "x86_64-unknown-linux-gnu-x86-64-v2",
                     "header_digest": found["header_digest"], "generator_digest": found["generator_digest"],
                     "archives": self.archives_digest(), "install": str(self.dir / "install"), "source": "ahrav/kestrike#664 build 12"}
        reference.update(artifact_changes or {})
        (self.dir / "artifact.json").write_text(json.dumps(reference))
        inputs = self.dir / "guest-inputs.env"
        if lines is None:
            lines = [
                "# the platform owner's guest inputs",
                f"KESTRIKE_GUEST_QEMU={qemu}", f"KESTRIKE_GUEST_KERNEL={self.dir / 'bzImage'}",
                f"KESTRIKE_GUEST_INITRD={self.dir / 'initrd.img'}", f"KESTRIKE_GUEST_ARTIFACT={self.dir / 'artifact.json'}",
            ]
        if not any(line.startswith("KESTRIKE_GUEST_ACCEL=") for line in lines):
            lines = [*lines, f"KESTRIKE_GUEST_ACCEL={accel}"]
        inputs.write_text("\n".join(lines) + "\n")
        state = self.dir / "fake-state"
        state.mkdir(exist_ok=True)
        self.env.update(KESTRIKE_GUEST_INPUTS=str(inputs), FAKE_STATE=str(state), FAKE_GUEST=mode, FAKE_TEST=guest.TEST)
        return inputs

    QEMU_MEASUREMENT = ROOT / "verification/qemu/measurement.json"

    def record_measurement(self):
        """Leave `self.measured` the runner measurement the guest lane reads: the one the CI owner committed when
        there is one, else this stub, written for this test alone."""
        if self.QEMU_MEASUREMENT.exists():
            self.measured = json.loads(self.QEMU_MEASUREMENT.read_text())
            return
        self.measured = self.QEMU_MEASURED
        self.QEMU_MEASUREMENT.parent.mkdir(exist_ok=True)
        self.QEMU_MEASUREMENT.write_text(json.dumps(self.QEMU_MEASURED))
        self.wrote_measurement = True
        self.addCleanup(self.remove_measurement)

    def lane_minutes(self):
        """The guest lane's handshake and run deadlines in minutes, as rust-lane.sh declares them."""
        lane = (ROOT / "scripts/rust-lane.sh").read_text()
        return tuple(int(lane.partition(f"QEMU_{name}_MINUTES=")[2].split()[0]) for name in ("HANDSHAKE", "RUN"))

    def remove_measurement(self):
        """Remove the stub measurement `record_measurement` wrote, leaving any other measurement in place, including
        one written over the stub since."""
        if not getattr(self, "wrote_measurement", False):
            return
        self.wrote_measurement = False
        with contextlib.suppress(FileNotFoundError):
            if self.QEMU_MEASUREMENT.read_text() == json.dumps(self.QEMU_MEASURED):
                self.QEMU_MEASUREMENT.unlink()
        with contextlib.suppress(OSError):
            self.QEMU_MEASUREMENT.parent.rmdir()

    def test_the_guest_lanes_deadlines_lie_within_the_harness_bounds(self):
        """`guest-binder.py` rejects a handshake or run deadline outside `BOUNDS` before the guest starts, so the
        lane's minutes must fit them, with the handshake no longer than the run; an activation that measures
        a run over 360 seconds needs the harness bound moved first."""
        harness = load("guest_binder", ROOT / "scripts/guest-binder.py")
        handshake, run = self.lane_minutes()
        for name, minutes in (("handshake_seconds", handshake), ("deadline_seconds", run)):
            low, high = harness.BOUNDS[name]
            self.assertTrue(low <= minutes * 60 <= high, f"{name}: {minutes} minutes lies outside {low}..{high} seconds")
        self.assertLessEqual(handshake, run)

    def test_the_guest_lane_fixture_keeps_a_measurement_it_did_not_write(self):
        """The CI owner's measurement at the lane's path survives the fixture's cleanup, committed or not."""
        if self.QEMU_MEASUREMENT.exists():
            self.skipTest("a qemu measurement is already in the checkout; this test writes its own stand-in")
        owner = '{"domain": "qemu", "written by": "the CI owner"}'
        self.QEMU_MEASUREMENT.parent.mkdir(exist_ok=True)
        self.QEMU_MEASUREMENT.write_text(owner)

        def restore():
            with contextlib.suppress(FileNotFoundError):
                self.QEMU_MEASUREMENT.unlink()
            with contextlib.suppress(OSError):
                self.QEMU_MEASUREMENT.parent.rmdir()

        self.addCleanup(restore)
        self.remove_measurement()
        self.assertTrue(self.QEMU_MEASUREMENT.is_file(), "the fixture deleted a measurement it did not write")
        self.assertEqual(self.QEMU_MEASUREMENT.read_text(), owner)
        self.QEMU_MEASUREMENT.unlink()
        self.record_measurement()
        self.QEMU_MEASUREMENT.write_text(owner)
        self.remove_measurement()
        self.assertTrue(self.QEMU_MEASUREMENT.is_file(), "the fixture deleted a measurement written over its stub")
        self.assertEqual(self.QEMU_MEASUREMENT.read_text(), owner)

    def archives_digest(self):
        """The archives digest native preflight computes for this test's stub install."""
        listing = subprocess.run(["bash", "-c", "export LC_ALL=C; sha256sum libspdk_*.a librte_*.a"], cwd=self.dir / "install" / "lib",
                                 capture_output=True, check=True).stdout
        return hashlib.sha256(listing).hexdigest()

    def qemu_lane(self, mode="pass", measured=True, absent=False, needs_guest=True, **inputs):
        """Run the guest lane over the stub install, a stub cargo whose host listing holds the guest case among
        the ordinary ignores, and the fake QEMU playing `mode`; then credit its evidence."""
        registry = json.loads((ROOT / "scripts/test-registry.json").read_text())
        inventory = json.loads((ROOT / "scripts/test-inventory.json").read_text())
        guest = inventory["qemu"]["tests"]
        ignored = sorted(row["id"] for row in registry["rows"] if row["cfg"] == "ordinary" and row["target"] == "kestrike")
        header = "     Running unittests src/lib.rs (target/debug/deps/kestrike-0123abcd)"
        # The fake guest reports 2470 filtered out, so the host lists 2471 tests.
        names = [f"storage::filler_tests::case_{index}" for index in range(2471 - len(ignored))] + ignored

        def listing(listed):
            return "\n".join([header, *(f"{name}: test" for name in listed), "", f"{len(listed)} tests, 0 benchmarks", ""])

        self.native_install("x86-64-v2")
        if measured:
            self.record_measurement()
        self.accel = self.measured["host"]["accel"] if measured else "tcg"
        if needs_guest and self.accel == "kvm" and not os.access("/dev/kvm", os.R_OK | os.W_OK):
            self.skipTest("the committed measurement was taken under kvm and this host has no read-write /dev/kvm")
        inputs_file = self.guest_inputs(mode, accel=self.accel, **inputs)
        if absent:
            inputs_file.unlink()
        (self.dir / "stub-list.txt").write_text(listing(names))
        (self.dir / "stub-ignored.txt").write_text(listing(ignored))
        executable = self.dir / "target" / "kestrike-0123abcd"
        executable.parent.mkdir(exist_ok=True)
        executable.write_bytes(b"\x7fELF the library test executable")
        artifact = {"reason": "compiler-artifact", "target": {"name": "kestrike"}, "profile": {"test": True}, "executable": str(executable)}
        (self.dir / "stub-build.txt").write_text("\n".join([json.dumps({"reason": "build-script-executed"}), json.dumps(artifact),
                                                             json.dumps({"reason": "build-finished", "success": True})]) + "\n")
        calls = self.dir / "cargo-calls.txt"
        env = dict(self.env, STUB_LIST=str(self.dir / "stub-list.txt"), STUB_IGNORED=str(self.dir / "stub-ignored.txt"),
                   STUB_BUILD=str(self.dir / "stub-build.txt"), STUB_ENV=str(calls), GITHUB_RUN_ATTEMPT="3", GITHUB_RUN_ID="70",
                   RUNNER_NAME=self.QEMU_MEASURED["host"]["runners"][0] if not measured else self.measured["host"]["runners"][0])
        lane = subprocess.run(["bash", "scripts/rust-lane.sh", "qemu"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=180)
        evidence = self.dir / "evidence"
        credit = subprocess.run([sys.executable, "scripts/verify-receipts.py", "credit", "--job", "qemu", "--evidence", str(evidence)],
                                cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        return lane, json.loads(credit.stdout), guest

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_the_qemu_lane_credits_the_guest_domain_from_the_harness_record_and_the_envelope(self):
        lane, credit, guest = self.qemu_lane()
        self.assertEqual(lane.returncode, 0, lane.stderr)
        self.assertEqual((credit["code"], credit["refusals"], credit["obligations"], credit["executions"]), (0, [], [record["id"] for record in json.loads((ROOT / "verification/obligations.json").read_text())["records"] if record["job"] == "qemu"], 1), credit)
        evidence = self.dir / "evidence"
        receipt = json.loads((evidence / "receipt.json").read_text())
        self.assertEqual((receipt["completion"], receipt["selection"]["cfg"], receipt["executed"]), ("completed", "qemu", guest))
        envelope, record = receipt["qualified"], receipt["guest"]
        self.assertEqual((envelope["domain"], envelope["attempt"], envelope["run"], envelope["host"]["accel"]), ("qemu", "3", "70", self.accel))
        self.assertEqual(envelope["artifact"]["generated"], "x86_64-unknown-linux-gnu-x86-64-v2")
        self.assertEqual(envelope["install"], str(ROOT / "crates/spdk-sys/src/generated/installs/x86_64-unknown-linux-gnu-x86-64-v2"))
        qualified = load("qualified_envelope", ROOT / "scripts/qualified-envelope.py")
        install = qualified.INSTALLS / "x86_64-unknown-linux-gnu-x86-64-v2"
        self.assertEqual(envelope["generated"], str(qualified.output_bindings(install).parent))
        self.assertEqual(envelope["host"]["kernel"], platform.release())
        self.assertEqual(envelope["inputs"]["sha256"], hashlib.sha256((self.dir / "guest-inputs.env").read_bytes()).hexdigest())
        self.assertEqual((record["outcome"], record["run_attempt"], record["reports"][0], record["reports"][-1]), ("qualified pass", "3", "default refused", "namespace " + json.loads((ROOT / "scripts/test-inventory.json").read_text())["qemu"]["namespace_cases"][-1]["id"] + " passed"))
        self.assertTrue(record["cleanup"]["backing_removed"])
        self.assertEqual(json.loads((evidence / "guest.json").read_text()), record)
        run = (evidence / "run.txt").read_text()
        executable = self.dir / "target" / "kestrike-0123abcd"
        self.assertTrue(run.startswith(f"     Running unittests src/lib.rs ({executable})\n"), run[:160])
        # The guest ran the provisioned initrd with the lane's executable appended at the init's path. The kernel's
        # initramfs unpacker skips NULs after a compressed member and reads a newc header only at a 4-byte offset.
        combined = (evidence / "guest-initrd.img").read_bytes()
        base = (self.dir / "initrd.img").read_bytes()
        self.assertTrue(combined.startswith(base))
        appended = combined[len(base):]
        start = len(base) + len(appended) - len(appended.lstrip(b"\0"))
        self.assertEqual((start % 4, combined[start:start + 6]), (0, b"070701"), "the appended archive is off a 4-byte boundary")
        listed = subprocess.run(["cpio", "-itv", "--numeric-uid-gid", "--quiet"], input=combined[start:],
                                capture_output=True, check=True).stdout.decode().splitlines()
        entries = {line.split()[-1]: tuple(line.split()[2:4]) for line in listed}
        self.assertIn("usr/lib/kestrike/kestrike-tests", entries)
        self.assertEqual(set(entries.values()), {("0", "0")}, f"the appended entries are root's in the guest: {listed}")
        self.assertEqual(envelope["executable"]["sha256"], hashlib.sha256(executable.read_bytes()).hexdigest())
        self.assertEqual(envelope["initrd"]["sha256"], hashlib.sha256(combined).hexdigest())
        self.assertEqual(record["inputs"]["initrd"]["sha256"], envelope["initrd"]["sha256"])
        self.assertEqual(envelope["host"]["runner"], self.measured["host"]["runners"][0])
        self.assertIn("- RUSTFLAGS=-Ctarget-cpu=x86-64-v2", (evidence / "pins.txt").read_text())
        # Under --nocapture the case's reports follow its name and its outcome stands alone.
        self.assertIn(f"test {guest[0]} ... guest-binder: default refused\n", run)
        self.assertEqual(receipt["executed"], guest)
        handshake, run_minutes = self.lane_minutes()
        self.assertIn(f"--accel {self.accel} --memory-mib 2048 --cpus 2 --backing-mib 64 --handshake-seconds {handshake * 60} --deadline-seconds {run_minutes * 60}",
                      (evidence / "replay.txt").read_text())
        self.assertIn(f"--initrd {evidence / 'guest-initrd.img'}", (evidence / "replay.txt").read_text())
        self.assertIn("- guest inputs ", (evidence / "pins.txt").read_text())
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "qemu"], cwd=ROOT, env=self.env, capture_output=True, text=True)
        self.assertEqual(step.returncode, 0, step.stderr)
        summary = (self.dir / "summary.md").read_text()
        qemu = json.loads((ROOT / "scripts/test-inventory.json").read_text())["qemu"]
        for line in ("### Guest binder in a disposable QEMU guest: selection credited",
                     f"- 1 of 1 guest cases executed by exact ID among the ignored cases of kestrike, 2470 filtered out; `{guest[0]}`",
                     "- guest outcome qualified pass; reports ['default refused', 'controller 0000:00:04.0",
                     "- identity: volume vol-0123456789abcdef0, instance i-0123456789abcdef0, model QEMU NVMe Ctrl, pci 1b36:0010; QEMU emulator version 9.2.0 (fake)",
                     "- attempt 3; artifact x86_64-unknown-linux-gnu-x86-64-v2 target x86_64-unknown-linux-gnu",
                     f"- deadlines: handshake {handshake}m, at least 4 times the measured {self.measured['handshake_seconds']} s; "
                     f"run {run_minutes}m, at least 10 times the measured {self.measured['run_seconds']} s plus the namespace members' "
                     f"{sum(case['deadline_seconds'] + qemu['member_drain_seconds'] for case in qemu['namespace_cases'])} s"):
            self.assertIn(line, summary)

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_the_qemu_lane_refuses_missing_inputs_an_unmeasured_runner_a_foreign_artifact_and_each_failed_guest(self):
        cases = (
            ("no inputs file", dict(absent=True), "is missing; the platform owner provisions it", None),
            ("empty inputs file", dict(lines=[]), "sets no KESTRIKE_GUEST_QEMU", None),
            ("unmeasured runner", dict(measured=False), "unreadable measurement", None),
            ("foreign artifact", dict(artifact_changes={"header_digest": "f" * 64}), "artifact's header_digest", None),
            ("unknown input", dict(lines=["KESTRIKE_GUEST_QEMU=/bin/true", "KESTRIKE_GUEST_BOGUS=1"]), "unknown input BOGUS", None),
            ("repeated input", dict(lines=["KESTRIKE_GUEST_QEMU=/bin/true", "KESTRIKE_GUEST_QEMU=/bin/false"]), "sets KESTRIKE_GUEST_QEMU twice", None),
            ("carriage return", dict(lines=["KESTRIKE_GUEST_QEMU=/bin/true\r"]), "holds a carriage return", None),
            ("foreign install record", dict(artifact_changes={"generated": "x86_64-unknown-linux-gnu-native"}), "not the install record its reference names", None),
            ("foreign archives", dict(artifact_changes={"archives": "b" * 64}), "not the archives its reference names", None),
            ("case failed", dict(mode="unbound"), None, {"selection-refused", "raw-failed", "unqualified", "missing-result"}),
            ("missed release", dict(mode="unreleased"), None, {"selection-refused", "unqualified"}),
            ("guest crashed", dict(mode="crash"), None, {"selection-refused", "zero-executions", "unqualified", "missing-result"}),
            ("rejected input", dict(lines=["KESTRIKE_GUEST_QEMU=/etc/hostname", f"KESTRIKE_GUEST_KERNEL={self.dir / 'bzImage'}",
                                           f"KESTRIKE_GUEST_INITRD={self.dir / 'initrd.img'}",
                                           f"KESTRIKE_GUEST_ARTIFACT={self.dir / 'artifact.json'}"]),
             None, {"unbound-input", "selection-refused", "zero-executions", "unqualified", "missing-result"}),
        )
        kwargs: Dict[str, Any]
        for name, kwargs, failure, codes in cases:
            with self.subTest(case=name):
                self.remove_measurement()
                if name == "unmeasured runner" and self.QEMU_MEASUREMENT.exists():
                    self.skipTest("a qemu measurement is in the checkout; the unmeasured case needs its path empty")
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                lane, credit, _ = self.qemu_lane(needs_guest=name in ("case failed", "missed release", "guest crashed"), **kwargs)
                self.assertNotEqual(lane.returncode, 0, lane.stdout)
                self.assertEqual(credit["code"], 1, credit)
                if failure is not None:
                    self.assertIn(failure, (self.dir / "evidence" / "failure.txt").read_text())
                if name not in ("unmeasured runner", "foreign artifact") and failure is not None:
                    self.assertFalse((self.dir / "evidence" / "list.txt").exists(), "the refusal came before any build")
                if name in ("unmeasured runner", "foreign artifact"):
                    self.assertFalse((self.dir / "evidence" / "guest.txt").exists(), "the refusal came before the guest ran")
                if codes is not None:
                    self.assertEqual({refusal["code"] for refusal in credit["refusals"]}, codes, credit)
                if name == "rejected input":
                    self.assertIn("rejected input: --qemu /etc/hostname is not an executable file", (self.dir / "evidence" / "guest.txt").read_text())
                    self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "2\n")

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_cancelled_asan_step_leaves_no_process(self):
        self.native_install("native", sanitizer=True)
        archive = self.dir / "sysroot/lib/rustlib/x86_64-unknown-linux-gnu/lib/librustc-nightly_rt.asan.a"
        archive.parent.mkdir(parents=True)
        archive.write_bytes(b"!<arch>\n")
        self.symbolizer_stub()
        self.env["STUB_SYSROOT"] = str(self.dir / "sysroot")
        self.assertEqual(self.cancel("asan", self.commands["asan"]), [])
        self.assertIn("RUSTFLAGS=-Zsanitizer=address -Cforce-frame-pointers=yes", self.pins_written())

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_cancelled_qemu_step_leaves_no_process(self):
        """The guest lane's host listing is its first long command; the stub cargo holds it until the step is cancelled."""
        self.native_install("x86-64-v2")
        self.guest_inputs()
        self.record_measurement()
        self.assertEqual(self.cancel("qemu", self.commands["qemu"]), [])
        self.assertIn("- RUSTFLAGS=-Ctarget-cpu=x86-64-v2", self.pins_written())

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_a_cancelled_qualified_step_leaves_no_process_and_keeps_its_first_artifacts(self):
        for lane in ("long-run", "campaigns", "search", "search-nightly"):
            with self.subTest(lane=lane):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                shutil.rmtree(self.dir / "install", ignore_errors=True)
                self.pids.unlink(missing_ok=True)
                self.native_install("x86-64-v2")
                self.assertEqual(self.cancel(lane, self.commands[lane]), [])
                self.assertIn("SPDK 25.5.1 at spdk-commit", self.pins_written())
                credit = subprocess.run([sys.executable, "scripts/verify-receipts.py", "credit", "--job", lane,
                                         "--evidence", str(self.dir / "evidence")], cwd=ROOT, env=self.env,
                                        capture_output=True, text=True, timeout=120)
                self.assertIn("timeout", {refusal["code"] for refusal in json.loads(credit.stdout)["refusals"]}, credit.stdout)

    @unittest.skipUnless(platform.machine() == "x86_64", "the stub install records x86_64 flags")
    def test_preflight_lists_the_archives_in_byte_order_under_a_collating_locale(self):
        spdk = ["libspdk_nvme.a", "libspdk_ut_mock.a", "libspdk_util.a"]
        rte = ["librte_eal.a"]
        self.native_install("x86-64-v2", archives=(*spdk, *rte))
        collating = "en_US.UTF-8"
        expanded = subprocess.run(["bash", "-c", "printf '%s\\n' libspdk_*.a"], cwd=self.dir / "install" / "lib",
                                  env=dict(os.environ, LC_ALL=collating), capture_output=True, text=True, check=True)
        if expanded.stdout.split() == sorted(spdk):
            self.skipTest(f"{collating} is unavailable or collates libspdk_ut_mock.a and libspdk_util.a in byte order")
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "preflight"], cwd=ROOT,
                              env=dict(self.env, STUB_EXIT="0", LC_ALL=collating),
                              capture_output=True, text=True, timeout=120)
        listing = (self.dir / "evidence" / "native-archives.txt").read_text()
        self.assertEqual([line.split()[1] for line in listing.splitlines()], sorted(spdk) + sorted(rte), step.stderr)

    def test_cancelled_loom_step_leaves_no_process(self):
        evidence = self.dir / "evidence"
        evidence.mkdir()
        (evidence / "exit.txt").write_text("0\n")
        self.assertEqual(self.cancel("loom", self.commands["loom"]), [])
        self.assertIn("- loom v0.7.2", self.pins_written())

    def test_a_step_whose_command_returns_124_records_the_exit(self):
        # `deadline` returns 124 when its timer wins; the stub returns it directly.
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "loom", "credit_model"],
            cwd=ROOT, env=dict(self.env, STUB_EXIT="124"), capture_output=True, text=True, timeout=60,
        )
        self.assertEqual(step.returncode, 1, step.stderr)
        evidence = self.dir / "evidence"
        self.assertIn("list failed", (evidence / "failure.txt").read_text())
        self.assertEqual((evidence / "exit.txt").read_text(), "124\n")

    def test_cancelled_miri_step_leaves_no_process(self):
        self.assertEqual(self.cancel("miri", self.commands["miri"]), [])
        self.assertIn("miri 0.1.0 (stub); MIRIFLAGS=-Zmiri-seed=0 -Zmiri-permissive-provenance", self.pins_written())

    def test_a_failing_miri_id_leaves_its_failure_raw_output_and_replay(self):
        select = load("select_tests", ROOT / "scripts/select-tests.py")
        inventory = select.load_inventory(select.INVENTORY)["miri"]
        header = "     Running unittests src/lib.rs (/tmp/miri/debug/deps/kestrike-2d37337a438c04e5)"

        def listing(names):
            return "\n".join([header, *(f"{name}: test" for name in names), "", f"{len(names)} tests, 0 benchmarks", ""])

        failing = inventory["tests"][0]
        run = [header, f"running {len(inventory['tests'])} tests"]
        run += [f"test {name} ... {'FAILED' if name == failing else 'ok'}" for name in inventory["tests"]]
        run += ["", f"test result: FAILED. {len(inventory['tests']) - 1} passed; 1 failed; 0 ignored; 0 measured; "
                f"{len(inventory['ignored'])} filtered out; finished in 51.86s", ""]
        files = {"STUB_LIST": listing(inventory["tests"] + inventory["ignored"]), "STUB_IGNORED": listing(inventory["ignored"]),
                 "STUB_RUN": "\n".join(run)}
        ambient = {
            "MIRIFLAGS": "-Zmiri-disable-stacked-borrows", "MIRI_SYSROOT": "/elsewhere", "RUSTFLAGS": "--cfg x",
            "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fx", "CARGO_BUILD_RUSTFLAGS": "--cfg x",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg x", "RUSTC_WRAPPER": "sccache",
            "RUSTC_WORKSPACE_WRAPPER": "sccache", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "false",
            "CARGO_BUILD_JOBS": "4", "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu",
        }
        env = dict(self.env, **ambient, STUB_RUN_EXIT="101", RUNNER_TEMP=str(self.dir), STUB_ENV=str(self.dir / "cargo-env.txt"))
        for name, text in files.items():
            (self.dir / name).write_text(text)
            env[name] = str(self.dir / name)
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "miri"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(step.returncode, 1, step.stderr)
        evidence = self.dir / "evidence"
        recorded = (evidence / "miri-env.txt").read_text().splitlines()
        self.assertEqual(recorded[:2], ["CARGO_ENCODED_RUSTFLAGS=", "MIRIFLAGS=-Zmiri-seed=0 -Zmiri-permissive-provenance"])
        self.assertRegex(recorded[2], rf"^MIRI_SYSROOT={re.escape(str(self.dir))}/miri-sysroot\.\w+$")
        self.assertEqual(len(recorded), 3, recorded)
        # An empty CARGO_ENCODED_RUSTFLAGS overrides config-file rustflags with an empty flag list.
        miri_calls = [line for line in (self.dir / "cargo-env.txt").read_text().splitlines() if " miri " in f" {line} "]
        self.assertEqual(len(miri_calls), 5, miri_calls)
        for call in miri_calls:
            self.assertTrue(call.startswith("encoded=[] "), call)
        self.assertIn("failed", (evidence / "failure.txt").read_text())
        self.assertIn(f"test {failing} ... FAILED", (evidence / "run.txt").read_text())
        self.assertEqual((evidence / "exit.txt").read_text(), "101\n")
        try:
            report = json.loads((evidence / "report.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the miri lane wrote no readable report.json: {error}")
        self.assertEqual(report["verdict"], "execution mismatch", report)
        replay = (evidence / "replay.txt").read_text().splitlines()
        self.assertEqual(len(replay), len(inventory["tests"]) + 1)
        self.assertTrue(replay[0].endswith(f"--exact {' '.join(inventory['tests'])} --test-threads=1"), replay[0])
        # The empty CARGO_ENCODED_RUSTFLAGS outranks RUSTFLAGS, CARGO_BUILD_RUSTFLAGS, target-scoped
        # rustflags and config files, so a replay from any shell compiles with the lane's flags.
        for line in replay:
            self.assertTrue(line.startswith('CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="-Zmiri-seed=0 -Zmiri-permissive-provenance" cargo +nightly-2026-07-27 miri test '), line)
        self.assertIn(
            f'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="-Zmiri-seed=0 -Zmiri-permissive-provenance" cargo +nightly-2026-07-27 miri test -p kestrike '
            f"--lib -- --exact {failing} --test-threads=1",
            replay,
        )

    def test_a_miri_control_credits_only_its_declared_diagnostic_on_a_failing_exit(self):
        select = load("select_tests", ROOT / "scripts/select-tests.py")
        inventory = select.load_inventory(select.INVENTORY)["miri"]
        header = "     Running unittests src/lib.rs (/tmp/miri/debug/deps/kestrike-2d37337a438c04e5)"
        controls = [control["test"] for control in inventory["controls"]]

        def listing(names):
            return "\n".join([header, *(f"{name}: test" for name in names), "", f"{len(names)} tests, 0 benchmarks", ""])

        run = [header, f"running {len(inventory['tests'])} tests"]
        run += [f"test {name} ... ok" for name in inventory["tests"]]
        run += ["", f"test result: ok. {len(inventory['tests'])} passed; 0 failed; 0 ignored; 0 measured; "
                f"{len(inventory['ignored']) + len(controls)} filtered out; finished in 51.86s", ""]
        # The stub answers every control with one text, so the passing text names every declared diagnostic.
        diagnostics = [control["diagnostic"] for control in inventory["controls"]]
        named = "; ".join(diagnostics)
        for text, exit_code, passes in (
            (f"error: Undefined Behavior: {named}", 1, True),
            ("test result: ok. 1 passed; 0 failed", 0, False),
            ("error: Undefined Behavior: an unrelated use after free", 1, False),
            (f"error: Undefined Behavior: {named}\n"
             "deadline: cargo passed 10m; stopping it", 124, False),
        ):
            with self.subTest(text=text, exit_code=exit_code):
                files = {"STUB_LIST": listing(inventory["tests"] + inventory["ignored"] + controls),
                         "STUB_IGNORED": listing(inventory["ignored"]), "STUB_RUN": "\n".join(run), "STUB_CONTROL": text}
                env = dict(self.env, RUNNER_TEMP=str(self.dir), STUB_CONTROL_EXIT=str(exit_code))
                for name, content in files.items():
                    (self.dir / name).write_text(content)
                    env[name] = str(self.dir / name)
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "miri"], cwd=ROOT, env=env, capture_output=True,
                                      text=True, timeout=120)
                evidence = self.dir / "evidence"
                self.assertEqual(step.returncode, 0 if passes else 1, step.stderr)
                self.assertEqual((evidence / "control-1.txt").read_text().strip(), text)
                # A failing control stops the step at the first control.
                ran = controls if passes else controls[:1]
                rows = "".join(f"{control}\t{exit_code}\t{'found' if diagnostic in text else 'absent'}\n"
                               for control, diagnostic in zip(ran, diagnostics))
                self.assertEqual((evidence / "controls.txt").read_text(), rows)
                if not passes:
                    self.assertIn(f"the Miri control {controls[0]} exited {exit_code}", (evidence / "failure.txt").read_text())
                # A control the deadline stopped leaves the lane's exit record at 124, as a stopped step does, so the
                # receipt reads a timeout; any other control outcome keeps the judged corpus's exit.
                self.assertEqual((evidence / "exit.txt").read_text().strip(), "124" if exit_code == 124 else "0")
                replay = (evidence / "replay.txt").read_text().splitlines()
                self.assertTrue(replay[-1].endswith(f"--exact {ran[-1]} --test-threads=1"), replay[-1])

    def test_cancelled_sweep_step_leaves_no_process(self):
        self.assertEqual(self.cancel("sweep", self.commands["sweep"]), [])
        self.assertIn("MIRIFLAGS=-Zmiri-many-seeds=0..64 -Zmiri-permissive-provenance -Zthreads=1", self.pins_written())

    def test_a_failing_sweep_seed_leaves_its_one_seed_replay(self):
        select = load("select_tests", ROOT / "scripts/select-tests.py")
        inventory = select.load_inventory(select.INVENTORY)
        ignored, kernels = inventory["miri"]["ignored"], inventory["miri_sweep"]["tests"]
        header = "     Running unittests src/lib.rs (/tmp/miri/debug/deps/kestrike-2d37337a438c04e5)"

        def listing(names):
            return "\n".join([header, *(f"{name}: test" for name in names), "", f"{len(names)} tests, 0 benchmarks", ""])

        run = [header, "Trying seed: 0", "", f"running {len(kernels)} tests", *(f"test {name} ... ok" for name in kernels), "",
               f"test result: ok. {len(kernels)} passed; 0 failed; 0 ignored; 0 measured; {len(ignored)} filtered out; finished in 0.7s",
               "", "Trying seed: 1", "", f"running {len(kernels)} tests", f"test {kernels[0]} ... FAILED", "FAILING SEED: 1", ""]
        env = dict(self.env, STUB_RUN_EXIT="101", RUNNER_TEMP=str(self.dir))
        for name, text in {"STUB_LIST": listing(kernels + ignored), "STUB_IGNORED": listing(ignored), "STUB_RUN": "\n".join(run)}.items():
            (self.dir / name).write_text(text)
            env[name] = str(self.dir / name)
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "sweep"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(step.returncode, 1, step.stderr)
        evidence = self.dir / "evidence"
        self.assertTrue((evidence / "failure.txt").exists(), step.stderr)
        replay = (evidence / "replay.txt").read_text().splitlines()
        exact = f"cargo +nightly-2026-07-27 miri test -p kestrike --lib -- --exact {' '.join(kernels)} --test-threads=1"
        self.assertEqual(replay, [
            f'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="-Zmiri-many-seeds=0..64 -Zmiri-permissive-provenance -Zthreads=1" {exact}',
            f'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="-Zmiri-seed=1 -Zmiri-permissive-provenance" {exact}',
        ])
        try:
            report = json.loads((evidence / "report.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the sweep wrote no readable report.json: {error}")
        self.assertEqual(report["reason"], "seed 1 failed", report)

    def test_cancelled_rc11_step_leaves_no_process(self):
        libdir = self.dir / "herdlib"
        libdir.mkdir()
        for name in ("rc11.cat", "stdlib.cat"):
            (libdir / name).write_text("let x = 0\n")
        stub = self.dir / "bin" / "herd7"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            'case "$1" in -version) echo "7.58, Rev: stub"; exit 0 ;; -libdir) echo "$HERD_LIBDIR"; exit 0 ;; esac\n'
            'echo "$$" >> "$STUB_PIDS"\n'
            "trap 'sleep 1; exit 143' TERM\n"
            "while :; do sleep 0.1; done\n"
        )
        stub.chmod(0o755)
        self.env["HERD_LIBDIR"] = str(libdir)
        self.assertEqual(self.cancel("rc11", self.commands["rc11"]), [])
        exit_file = self.dir / "evidence" / "exit.txt"
        self.assertEqual(exit_file.read_text(), "143\n")
        self.assertIn("- herd7 7.58, Rev: stub; sha256 ", (self.dir / "evidence" / "pins.txt").read_text())

    def genmc_toolchain(self, key=None):
        """Cache a provisioned-looking GenMC toolchain under this test's HOME and return its declaration and binary."""
        import hashlib

        def digest(path):
            return hashlib.sha256(Path(path).read_bytes()).hexdigest()

        recipe = ROOT / "verification/genmc/provision.sh"
        patches = sorted((ROOT / "verification/genmc/patches").glob("*.patch"))
        listing = "".join(f"{digest(path)}  {path.relative_to(ROOT)}\n" for path in [recipe, *patches])
        key = key or hashlib.sha256(f"nightly-2026-07-27\n{listing}".encode()).hexdigest()[:16]
        home = self.dir / "home"
        prefix = home / ".cache/kestrike-genmc" / key
        (prefix / "build/bin").mkdir(parents=True)
        binary = prefix / "build/bin/genmc"
        binary.write_text("#!/usr/bin/env bash\nexit 0\n")
        binary.chmod(0o755)
        std = prefix / "genmc-std"
        (std / "src").mkdir(parents=True)
        (std / "src/lib.rs").write_text("pub use std::*;\n")
        tree = hashlib.sha256(f"src/lib.rs\0{digest(std / 'src/lib.rs')}\n".encode()).hexdigest()
        library = prefix / "lib64/libLLVM.so.22.1"
        library.parent.mkdir()
        library.write_bytes(b"libLLVM\n")
        sysroot = self.dir / "rust/toolchains/nightly-2026-07-27-x86_64-unknown-linux-gnu"
        rustc = genmc_fixture.write_rustc(sysroot)
        try:
            expected = json.loads((ROOT / "verification/genmc/expected.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the GenMC declaration is unreadable: {error}")
        (prefix / "identity.json").write_text(json.dumps({
            "upstream": expected["upstream"], "llvm": expected["llvm"], "clang": "clang version 22.1.8",
            "rustc": dict(expected["rustc"], name="nightly-2026-07-27", toolchain=str(sysroot), sha256=digest(rustc)),
            "cxx": "g++ (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7)",
            "patches": {path.name: digest(path) for path in patches}, "recipe": digest(recipe),
            "binary": {"path": str(binary), "sha256": digest(binary)}, "genmc_std": {"path": str(std), "tree": tree},
            "libllvm": {"path": str(library), "sha256": digest(library)},
        }))
        self.env["HOME"] = str(home)
        self.env["GENMC_PROFILE"] = "pr"
        self.env["STUB_LDD_LIBLLVM"] = str(library)
        self.rustc = rustc
        return expected, binary, digest

    @contextlib.contextmanager
    def genmc_std_link(self):
        """Restore the checkout's genmc-std link after a lane run relinks it."""
        link = ROOT / "verification/genmc/packages/genmc-std"
        original = os.readlink(link) if link.is_symlink() else None
        try:
            yield
        finally:
            link.unlink(missing_ok=True)
            if original:
                link.symlink_to(original)

    def test_cancelled_genmc_step_leaves_no_process(self):
        expected, binary, digest = self.genmc_toolchain()
        with self.genmc_std_link():
            self.assertEqual(self.cancel("genmc", self.commands["genmc"]), [])
        self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "143\n")
        self.assertIn(f"- GenMC {expected['upstream']}; genmc sha256 {digest(binary)}", (self.dir / "evidence" / "pins.txt").read_text())

    def kani_toolchain(self):
        """Cache a provisioned-looking Kani under this test's HOME."""
        root = self.dir / "home/.cache/kestrike-kani/0.68.0"
        (root / "bin").mkdir(parents=True)
        (root / "bin/cargo-kani").write_text("#!/usr/bin/env bash\necho 'Kani Rust Verifier 0.68.0 (cargo plugin)'\n")
        (root / "bin/cargo-kani").chmod(0o755)
        bundle = root / "home/kani-0.68.0"
        (bundle / "bin").mkdir(parents=True)
        for name in ("kani-compiler", "kani-driver", "cbmc"):
            (bundle / "bin" / name).write_text(f"{name}\n")
        (bundle / "rust-toolchain-version").write_text("nightly-2026-08-21-x86_64-unknown-linux-gnu")
        toolchain = self.dir / "home/.rustup/toolchains/nightly-2026-08-21-x86_64-unknown-linux-gnu"
        (toolchain / "bin").mkdir(parents=True)
        (toolchain / "bin/cargo").write_text("#!/usr/bin/env bash\n")
        (toolchain / "bin/cargo").chmod(0o755)
        (bundle / "toolchain").symlink_to(toolchain)
        (root / "home/complete").write_text("")
        self.env.update(HOME=str(self.dir / "home"), KANI="0.68.0", KANI_PROFILE="pr")

    def test_cancelled_kani_step_leaves_no_process(self):
        self.kani_toolchain()
        try:
            self.assertEqual(self.cancel("kani", self.commands["kani"]), [])
        finally:
            (ROOT / "crates/kestrike/kani-list.json").unlink(missing_ok=True)
        self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "143\n")
        self.assertIn("- Kani Rust Verifier 0.68.0 (cargo plugin); cargo-kani sha256 ", (self.dir / "evidence" / "pins.txt").read_text())
        try:
            self.assertEqual(json.loads((self.dir / "evidence" / "cargo-config.json").read_text()), {})
        except (OSError, ValueError) as error:
            self.fail(f"the lane recorded no readable cargo configuration: {error}")

    def test_a_kani_setup_that_stopped_after_extracting_its_bundle_is_run_again(self):
        """The bundle's `rust-toolchain-version` lands before setup installs and links the toolchain."""
        root = self.dir / "home/.cache/kestrike-kani/0.68.0"
        for broken in ("complete", "toolchain"):
            with self.subTest(missing=broken):
                self.kani_toolchain()
                log = self.dir / "cargo-kani.log"
                log.unlink(missing_ok=True)
                (root / "bin/cargo-kani").write_text(
                    f"#!/usr/bin/env bash\necho \"$*\" >> {shlex.quote(str(log))}\necho 'Kani Rust Verifier 0.68.0 (cargo plugin)'\n")
                if broken == "complete":
                    (root / "home/complete").unlink()
                else:
                    shutil.rmtree(self.dir / "home/.rustup")
                self.assertTrue((root / "home/kani-0.68.0/rust-toolchain-version").is_file())
                (self.dir / "run").write_text("installed\n")
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", "pr"], cwd=ROOT, env=dict(self.env, STUB_RUN=str(self.dir / "run")),
                                      capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn("setup", log.read_text().splitlines(), "the incomplete install was reused")
                self.assertFalse((root / "home/kani-0.68.0/bin/cbmc").exists(), "the incomplete bundle survived the new setup")
                shutil.rmtree(root)
                shutil.rmtree(self.dir / "home/.rustup", ignore_errors=True)

    def test_the_kani_step_budget_holds_a_cold_provision_the_listing_and_the_scheduled_run(self):
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        # The lane is its setup, which provisions, and its own body, which lists and runs.
        lane = "".join(script.split(f"\n{function}() {{", 1)[1].split("\n}\n", 1)[0] for function in ("kani_setup", "kani"))
        nested = [int(m) for m in re.findall(r"deadline (\d+)m ", lane)]
        nested.append(int(matched(r'KANI_TOTAL:-(\d+)m\}"\n  fi', lane).group(1)))
        self.assertEqual(len(nested), 3, nested)
        budgets = [int(m) for m in re.findall(r"--kill-after=\d+s (\d+)m", workflow_jobs(WORKFLOW.read_text())["kani"])]
        self.assertGreaterEqual(budgets[1] - sum(nested), 5, (budgets, nested))

    def test_the_miri_step_budget_holds_the_setup_the_listings_the_corpus_and_the_controls(self):
        """The Miri step's `timeout` holds every deadline the lane may spend in sequence: the interpreter's setup,
        the two listings, the judged corpus and one control run per inventory control, with the same margin the
        Kani step keeps."""
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        setup = [int(m) for m in re.findall(r"deadline (\d+)m ", script.split("\ninterpreter() {", 1)[1].split("\n}\n", 1)[0])]
        lane = script.split("\nmiri() {", 1)[1].split("\n}\n", 1)[0]
        listing = int(matched(r'LIST=\(deadline (\d+)m ', lane).group(1))
        judged = int(matched(r"judge (\d+)m --cfg miri", lane).group(1))
        control = int(matched(r"deadline (\d+)m ", script.split("\nmiri_controls() {", 1)[1].split("\n}\n", 1)[0]).group(1))
        controls = len(json.loads((ROOT / "scripts/test-inventory.json").read_text())["miri"]["controls"])
        nested = [*setup, listing, listing, judged, *([control] * controls)]
        self.assertEqual(len(setup), 1, nested)
        self.assertGreaterEqual(controls, 1, nested)
        budgets = [int(m) for m in re.findall(r"--kill-after=\d+s (\d+)m", workflow_jobs(WORKFLOW.read_text())["miri"])]
        self.assertGreaterEqual(budgets[1] - sum(nested), 5, (budgets, nested))

    def test_the_contract_step_fails_a_run_that_selects_no_case(self):
        """A run whose filter selects no case exits 0, so the lane's guard on the contract case's passing line is
        what fails it; the guard passes the run that prints that line."""
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        guard = matched(r'^  grep -qxF "test \$CONTRACT_CASE \.\.\. ok".*\n.*\n', script, re.M,
                        "the workspace lane guards the contract case's passing line")
        case = re.findall(r"^CONTRACT_CASE=(\S+)$", script, re.M)[0]
        empty = "\nrunning 0 tests\n\ntest result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 41 filtered out\n"
        for name, text, code in (("no case", empty, 1), ("failed", f"test {case} ... FAILED\n", 1),
                                 ("passed", f"test {case} ... ok\n", 0)):
            with self.subTest(name), tempfile.TemporaryDirectory() as evidence:
                Path(evidence, "contract.txt").write_text(text)
                program = f'fail() {{ echo "$1" >&2; exit 1; }}\nCONTRACT_CASE={case}\nEVIDENCE={evidence}\n{guard.group(0)}'
                ran = subprocess.run(["bash", "-c", program], capture_output=True, text=True, timeout=30, check=False)
                self.assertEqual(ran.returncode, code, ran.stderr)

    def test_the_workspace_step_budget_holds_the_lints_the_listings_the_suite_the_census_and_the_contract(self):
        """The workspace step's `timeout` holds every deadline the lane may spend in sequence, with the margin the
        Kani and Miri steps keep, so an overrun stops at the step's own deadline and names that step. The protocol
        contract case runs last, under its own cfg and target directory, and the lane requires its passing line."""
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        lane = script.split("\nworkspace() {", 1)[1].split("\n}\n", 1)[0]
        steps = [int(m) for m in re.findall(r"step \S+ deadline (\d+)m ", lane)]
        listings = [int(m) for m in re.findall(r"LIST=\(deadline (\d+)m ", lane)]
        judged = [int(m) for m in re.findall(r"judge (\d+)m --cfg ordinary", lane)]
        self.assertEqual((len(listings), len(judged)), (1, 1), lane)
        nested = [*steps, *listings, *listings, *judged]
        self.assertEqual(len(steps), 5, nested)
        self.assertRegex(lane, r"judge \d+m --cfg ordinary\n(?:  #[^\n]*\n)*  step census ", "the census self-test runs after the suite's evidence is written")
        contract = lane.split("  step contract ", 1)[1]
        self.assertIn('RUSTFLAGS="--cfg protocol_contract"', contract)
        self.assertIn('CARGO_TARGET_DIR="$CARGO_TARGET_DIR-contract"', contract)
        self.assertIn('-- --exact "$CONTRACT_CASE"', contract)
        self.assertIn('grep -qxF "test $CONTRACT_CASE ... ok" "$EVIDENCE/contract.txt"', contract)
        cases = re.findall(r"^CONTRACT_CASE=(\S+)$", script, re.M)
        self.assertEqual(len(cases), 1, cases)
        self.assertIn(f'"{cases[0]}"', (ROOT / "crates/kestrike/src/worker_contract.rs").read_text())
        budgets = [int(m) for m in re.findall(r"--kill-after=\d+s (\d+)m", workflow_jobs(WORKFLOW.read_text())["workspace"])]
        self.assertGreaterEqual(budgets[1] - sum(nested), 5, (budgets, nested))

    def test_the_quint_step_budget_holds_a_cold_tool_install_and_the_run(self):
        """The Quint step's `timeout` holds every deadline the lane may spend in sequence: one fetch per declared
        archive, the `npm ci` and the run, with the margin the Kani, Miri and workspace steps keep. The run deadline
        outlasts the longest deadline a case declares, so a slow case stops at its own deadline, which names it."""
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        install = script.split("\nquint_install() {", 1)[1].split("\n}\n", 1)[0]
        archives = re.findall(r'\("\w+", "[\w.]+"\)', install)
        fetch = [int(m) for m in re.findall(r"step fetch deadline (\d+)m ", install)]
        npm = [int(m) for m in re.findall(r"step npm deadline (\d+)m ", install)]
        run = [int(m) for m in re.findall(r"\n  deadline (\d+)m ", script.split("\nquint() {", 1)[1].split("\n}\n", 1)[0])]
        self.assertEqual((len(archives), len(fetch), len(npm), len(run)), (4, 1, 1, 1), (archives, fetch, npm, run))
        nested = [*fetch * len(archives), *npm, *run]
        budgets = [int(m) for m in re.findall(r"--kill-after=\d+s (\d+)m", workflow_jobs(WORKFLOW.read_text())[RUNNERS["quint"]])]
        self.assertGreaterEqual(budgets[1] - sum(nested), 5, (budgets, nested))
        check = load("judge_quint", ROOT / "scripts/judge-quint.py").runner()
        self.assertGreater(run[0] * 60, max(case.deadline or check.CASE_SECONDS for case in check.cases()))

    def test_a_cold_kani_provision_builds_cargo_kani_without_ambient_overrides(self):
        self.kani_toolchain()
        root = self.dir / "home/.cache/kestrike-kani/0.68.0"
        (root / "home/complete").unlink()
        (self.dir / "run").write_text("installed\n")
        ambient = {"RUSTFLAGS": "--cfg x", "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fx", "RUSTC_WRAPPER": "sccache",
                   "CARGO_PROFILE_RELEASE_OPT_LEVEL": "0", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg x"}
        env = dict(self.env, **ambient, STUB_RUN=str(self.dir / "run"), STUB_ENV_DUMP=str(self.dir / "cargo-env-dump.txt"))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", "pr"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(step.returncode, 1, step.stderr)
        received = env_dump(self.dir / "cargo-env-dump.txt")
        self.assertEqual({name: value for name, value in received.items() if name in ambient}, {})

    def test_the_kani_run_keeps_to_the_per_job_worker_bound(self):
        """The workflow bounds every lane at CARGO_BUILD_JOBS workers; the Kani run defaults to two workers for the pr
        profile and three for the scheduled one, or to the bound where it is lower, takes an explicit KANI_JOBS within
        the bound, and runs with two malloc arenas."""
        self.kani_toolchain()
        # Run the real wrapper and judge against one batch per profile in an isolated tree.
        fixture = self.dir / "worker-fixture"
        (fixture / "scripts").mkdir(parents=True)
        for script in ("rust-lane.sh", "judge-kani.py", "judge-genmc.py", "judge-rc11.py", "judge-verus.py"):
            shutil.copyfile(ROOT / "scripts" / script, fixture / "scripts" / script)
        (fixture / "crates/kestrike").mkdir(parents=True)
        (fixture / "Cargo.lock").write_text("")
        cbmc = json.loads((ROOT / "verification/kani/expected.json").read_text())["cbmc"]
        pr_case, scheduled_case = "fixture::pr_work", "fixture::scheduled_work"
        harnesses = {pr_case: 1, scheduled_case: 1}
        for path, data in (
            ("kani/expected.json", {"kani": self.env["KANI"], "package": "kestrike", "cbmc": cbmc, "sources": [],
                                    "singles": harnesses, "families": {}, "compared": list(harnesses),
                                    "argument_only": {}, "pr": [pr_case], "batch_budget": {"pr": 2, "scheduled": 2}}),
            ("verus/expected.json", {"tests": []}),
            ("verus/inventory.json", {"rows": []}),
        ):
            file = fixture / "verification" / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.write_text(json.dumps(data))
        listing = fixture / "crates/kestrike/kani-list.json"
        run = self.dir / "run"
        run.write_text("stub Kani output\n")
        evidence = self.dir / "evidence"
        dump = self.dir / "kani-env-dump.txt"
        ambient = {name: value for name, value in self.env.items() if name not in ("CARGO_BUILD_JOBS", "KANI_JOBS")}
        ambient.update(RUNNER_TEMP=str(self.dir), STUB_RUN=str(run))
        for profile, env, jobs in (("pr", {"CARGO_BUILD_JOBS": "4"}, "2"), ("pr", {}, "2"), ("pr", {"CARGO_BUILD_JOBS": "2"}, "2"),
                                   ("pr", {"CARGO_BUILD_JOBS": "4", "KANI_JOBS": "4"}, "4"), ("pr", {"CARGO_BUILD_JOBS": "4", "KANI_JOBS": "3"}, "3"),
                                   ("pr", {"MALLOC_ARENA_MAX": "8"}, "2"), ("scheduled", {"CARGO_BUILD_JOBS": "4"}, "3"), ("scheduled", {}, "3"),
                                   ("scheduled", {"CARGO_BUILD_JOBS": "2"}, "2"), ("scheduled", {"CARGO_BUILD_JOBS": "4", "KANI_JOBS": "4"}, "4"),
                                   ("scheduled", {"CARGO_BUILD_JOBS": "4", "KANI_JOBS": "2"}, "2")):
            with self.subTest(profile=profile, env=env):
                listing.write_text(json.dumps({"standard-harnesses": {"src/lib.rs": sorted(harnesses)}}))
                dump.unlink(missing_ok=True)
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", profile], cwd=fixture,
                                      env=dict(ambient, **env, STUB_ENV_DUMP=str(dump)),
                                      capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertEqual((evidence / "kani.txt").read_text(), "stub Kani output\n")
                record = json.loads((evidence / "kani-run.json").read_text())
                self.assertTrue(record["complete"], record)
                self.assertEqual(record["count"], 1)
                expected = [pr_case] if profile == "pr" else [pr_case, scheduled_case]
                self.assertEqual(record["runs"][0]["harnesses"], expected)
                argv = (evidence / "kani.argv").read_text().splitlines()
                self.assertEqual(argv[argv.index("-j") + 1], jobs, argv)
                self.assertEqual(env_dump(dump).get("MALLOC_ARENA_MAX"), "2")
                self.assertEqual(argv[argv.index("--target-dir") + 2:], ["-Z", "unstable-options", "--cbmc-args", *cbmc], argv)
        for env, reason in (
            ({"CARGO_BUILD_JOBS": "4", "KANI_JOBS": "8"}, "KANI_JOBS=8 exceeds the per-job worker bound CARGO_BUILD_JOBS=4"),
            ({"KANI_JOBS": "1"}, "the Kani judge credits only a run of 2 or more workers"),
            ({"CARGO_BUILD_JOBS": "1"}, "the Kani judge credits only a run of 2 or more workers"),
        ):
            with self.subTest(env=env):
                step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", "pr"], cwd=fixture,
                                      env=dict(ambient, **env), capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                self.assertIn(reason, (evidence / "failure.txt").read_text())
                self.assertEqual(list(evidence.glob("kani*.argv")), [], "a refused worker count recorded a batch")

    def kani_batches(self, profile, **env):
        """Run the Kani lane for `profile` with a stub `cargo` whose Kani run prints a complete terse run of the
        harnesses its argv names, fails STUB_FAIL's harness and hangs at STUB_HANG's; returns the step, the harness
        lists in the order the lane ran them and the judge's report."""
        self.kani_toolchain()
        root = self.dir / "home/.cache/kestrike-kani/0.68.0"
        (root / "bin/cargo-kani").write_text("#!/usr/bin/env bash\necho 'Kani Rust Verifier 0.68.0 (cargo plugin)'\necho 'CBMC 6.11.0'\n")
        stub = self.dir / "kani-bin"
        stub.mkdir(exist_ok=True)
        (stub / "cargo").write_text(KANI_STUB)
        (stub / "cargo").chmod(0o755)
        log = self.dir / "kani-runs.txt"
        log.unlink(missing_ok=True)
        # The lane copies the workspace lock file, which a fresh clone lacks; a planted one is removed afterwards.
        lock = ROOT / "Cargo.lock"
        planted = not lock.exists()
        if planted:
            lock.write_text('[[package]]\nname = "kestrike"\nversion = "0.1.0"\n')
        try:
            step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", profile], cwd=ROOT,
                                  env=dict(self.env, PATH=f"{stub}:{self.env['PATH']}", RUNNER_TEMP=str(self.dir), STUB_ROOT=str(ROOT),
                                           STUB_KANI_LOG=str(log), **env),
                                  capture_output=True, text=True, timeout=300, check=False)
        finally:
            (ROOT / "crates/kestrike/kani-list.json").unlink(missing_ok=True)
            if planted:
                lock.unlink(missing_ok=True)
        ran = [line.split(" ") for line in log.read_text().splitlines()] if log.exists() else []
        self.assertTrue((self.dir / "evidence" / "report.json").exists(), step.stderr)
        return step, ran, json.loads((self.dir / "evidence" / "report.json").read_text())

    @staticmethod
    def tree_changed():
        """Whether a tracked file of the checkout differs from HEAD, which the Kani judge refuses a run for."""
        return bool(subprocess.run(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"], capture_output=True, text=True,
                                   check=True).stdout.strip())

    def assert_credited_unless_changed(self, step, report):
        """A run on a tree whose tracked files match HEAD credits; on a changed tree the judge refuses it for that alone."""
        if self.tree_changed():
            self.assertIn("records a tree whose tracked files differed", report["reason"], report)
        else:
            self.assertEqual((step.returncode, report["code"]), (0, 0), (step.stderr, report))

    def test_the_kani_lane_runs_each_batch_in_order_in_its_own_process_and_records_it(self):
        """The lane runs the declared batches in order, one `cargo kani` each with the profile's argument array and the
        batch's harnesses, writes kani-N files for a profile of several batches and kani.KIND for one, and records
        each batch in kani-run.json; a batch that fails does not stop the batches after it."""
        judge = load("judge_kani", ROOT / "scripts/judge-kani.py")
        expected = judge.declaration()
        for profile in ("pr", "scheduled"):
            with self.subTest(profile=profile):
                planned = judge.batches(expected, profile)
                shutil.rmtree(self.dir / "home", ignore_errors=True)
                step, ran, report = self.kani_batches(profile)
                self.assertEqual(ran, planned)
                evidence = self.dir / "evidence"
                present = sorted(path.name for path in evidence.iterdir() if judge.BATCH_FILE.fullmatch(path.name))
                self.assertEqual(present, sorted(name for files in judge.batch_files(len(planned)) for name in files.values()))
                run = json.loads((evidence / judge.RUN_RECORD).read_text())
                self.assertEqual(([entry["harnesses"] for entry in run["runs"]], run["count"], run["complete"], run["timeout"]),
                                 (planned, len(planned), True, None))
                lane = (ROOT / "scripts/rust-lane.sh").read_text().split("\nkani() {", 1)[1].split("\n}\n", 1)[0]
                minutes = [int(m) for m in re.findall(r'KANI_TOTAL="\$\{KANI_TOTAL:-(\d+)m\}"', lane)]
                self.assertEqual((run["workers"], run["total"]), (2 if profile == "pr" else 3, 60 * minutes[0 if profile == "pr" else 1]))
                for entry, files in zip(run["runs"], judge.batch_files(len(planned))):
                    self.assertEqual(entry["digests"], {kind: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for kind, name in files.items()})
                    self.assertLessEqual(entry["start"], entry["end"])
                self.assert_credited_unless_changed(step, report)
        planned = judge.batches(expected, "scheduled")
        shutil.rmtree(self.dir / "home", ignore_errors=True)
        step, ran, report = self.kani_batches("scheduled", STUB_FAIL=planned[0][0])
        self.assertEqual(ran, planned, "a failed batch stopped the batches after it")
        self.assertEqual((step.returncode, report["harnesses"]), (1, {}), report)
        if not self.tree_changed():
            self.assertEqual(report["code"], 1, report)
            self.assertIn(f"(batch 1 of {len(planned)})", report["reason"])
        self.assertTrue(json.loads((self.dir / "evidence" / judge.RUN_RECORD).read_text())["complete"])

    def test_a_kani_total_that_runs_out_in_a_later_batch_credits_nothing_and_leaves_no_process(self):
        """The total is shared: a batch cut off by it, with the batches after it, reads as a timeout, no child of the
        run survives, and nothing of an earlier run with more batches or its credit stays in the evidence."""
        judge = load("judge_kani", ROOT / "scripts/judge-kani.py")
        planned = judge.batches(judge.declaration(), "scheduled")
        evidence = self.dir / "evidence"
        evidence.mkdir()
        earlier = [f"kani-{index}.{kind}" for index in range(1, len(planned) + 3) for kind in ("argv", "txt", "exit")]
        (evidence / "kani-target").mkdir()
        (evidence / "kani-baseline.md").write_text("kept\n")
        for name in (*earlier, "kani.argv", "kani-run.json", "report.json", "receipt.json", "credit.json", "exit.txt", "failure.txt"):
            (evidence / name).write_text('{"credited": true, "code": 0}\n' if name.endswith(".json") else "0\n")
        step, ran, report = self.kani_batches("scheduled", STUB_HANG=planned[1][0], KANI_TOTAL="6s")
        self.assertEqual(ran, planned[:2])
        self.assertEqual(tracked(self.marker), [], "a child of the timed-out batch survived")
        self.assertEqual((step.returncode, report["credited"], report["harnesses"]), (1, False, {}), report)
        if self.tree_changed():
            self.assertIn("records a tree whose tracked files differed", report["reason"], report)
        else:
            self.assertEqual(report["code"], 3, report)
            self.assertIn("interrupted (exit 124)", report["reason"])
        # The total is shared: batch 2 was given what batch 1 left of it.
        given = int(matched(r"deadline: cargo passed (\d+); stopping it", (evidence / "kani-2.txt").read_text()).group(1))
        self.assertLess(given, 6)
        present = sorted(path.name for path in evidence.iterdir() if judge.BATCH_FILE.fullmatch(path.name))
        self.assertEqual(present, sorted(f"kani-{index}.{kind}" for index in (1, 2) for kind in ("argv", "txt", "exit")))
        self.assertEqual((evidence / "kani-2.exit").read_text(), "124\n")
        run = json.loads((evidence / judge.RUN_RECORD).read_text())
        self.assertEqual((len(run["runs"]), run["timeout"], run["complete"]), (2, 2, False))
        self.assertFalse((evidence / "credit.json").exists(), "an earlier credit stayed beside the timed-out run")
        self.assertTrue((evidence / "kani-target").is_dir() and (evidence / "kani-baseline.md").is_file(), "the cleanup removed a file of no batch")
        self.assertFalse(json.loads((evidence / "receipt.json").read_text())["selection"]["credited"])

    def test_the_kani_run_record_holds_each_batch_as_its_child_exits(self):
        """While batch 2 runs, the record holds batch 1 alone with the digests of its files and is not complete; a
        stop of the lane then leaves exit 143, no child and no credit."""
        judge = load("judge_kani", ROOT / "scripts/judge-kani.py")
        planned = judge.batches(judge.declaration(), "scheduled")
        self.kani_toolchain()
        root = self.dir / "home/.cache/kestrike-kani/0.68.0"
        (root / "bin/cargo-kani").write_text("#!/usr/bin/env bash\necho 'Kani Rust Verifier 0.68.0 (cargo plugin)'\necho 'CBMC 6.11.0'\n")
        stub = self.dir / "kani-bin"
        stub.mkdir()
        (stub / "cargo").write_text(KANI_STUB)
        (stub / "cargo").chmod(0o755)
        evidence = self.dir / "evidence"
        lane = subprocess.Popen(["bash", "scripts/rust-lane.sh", "kani", "scheduled"], cwd=ROOT, start_new_session=True,
                                env=dict(self.env, PATH=f"{stub}:{self.env['PATH']}", RUNNER_TEMP=str(self.dir), STUB_ROOT=str(ROOT),
                                         STUB_KANI_LOG=str(self.dir / "kani-runs.txt"), STUB_HANG=planned[1][0]),
                                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            deadline = time.monotonic() + 120
            while not (self.pids.exists() and self.pids.read_text().strip()):
                self.assertIsNone(lane.poll(), "the lane exited before batch 2 started")
                self.assertLess(time.monotonic(), deadline, "batch 2 never started")
                time.sleep(0.05)
            run = json.loads((evidence / judge.RUN_RECORD).read_text())
            self.assertEqual(([entry["index"] for entry in run["runs"]], run["complete"], run["timeout"]), ([1], False, None))
            files = judge.batch_files(len(planned))[0]
            self.assertEqual(run["runs"][0]["digests"], {kind: hashlib.sha256((evidence / name).read_bytes()).hexdigest() for kind, name in files.items()})
            self.assertEqual(run["runs"][0]["harnesses"], planned[0])
            os.killpg(lane.pid, signal.SIGTERM)
            self.assertTrue(wait_exit(lane, 60), "the lane did not stop")
        finally:
            (ROOT / "crates/kestrike/kani-list.json").unlink(missing_ok=True)
            if lane.poll() is None:
                lane.kill()
                lane.wait()
        self.assertEqual((evidence / "exit.txt").read_text(), "143\n")
        self.assertEqual(tracked(self.marker), [], "a child of the stopped batch survived")
        self.assertFalse((evidence / "credit.json").exists() or (evidence / "report.json").exists())

    def test_a_stop_while_a_finished_batch_drains_leaves_no_process(self):
        """A batch's leader may exit and leave a process of its group that ignores TERM, which the lane drains for up
        to 30 seconds. A stop of the lane in that time, by the runner's SIGINT or by TERM, leaves exit 143 and no
        process of the batch before the runner's next signal."""
        judge = load("judge_kani", ROOT / "scripts/judge-kani.py")
        planned = judge.batches(judge.declaration(), "scheduled")
        stub = self.dir / "kani-bin"
        stub.mkdir()
        (stub / "cargo").write_text(KANI_STUB)
        (stub / "cargo").chmod(0o755)
        evidence = self.dir / "evidence"
        for stop in (signal.SIGINT, signal.SIGTERM):
            with self.subTest(stop=stop.name):
                shutil.rmtree(self.dir / "home", ignore_errors=True)
                shutil.rmtree(evidence, ignore_errors=True)
                self.pids.unlink(missing_ok=True)
                self.kani_toolchain()
                root = self.dir / "home/.cache/kestrike-kani/0.68.0"
                (root / "bin/cargo-kani").write_text("#!/usr/bin/env bash\necho 'Kani Rust Verifier 0.68.0 (cargo plugin)'\necho 'CBMC 6.11.0'\n")
                lane = subprocess.Popen(["bash", "scripts/rust-lane.sh", "kani", "scheduled"], cwd=ROOT, start_new_session=True,
                                        env=dict(self.env, PATH=f"{stub}:{self.env['PATH']}", RUNNER_TEMP=str(self.dir), STUB_ROOT=str(ROOT),
                                                 STUB_KANI_LOG=str(self.dir / "kani-runs.txt"), STUB_LINGER=planned[0][0]),
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, preexec_fn=default_sigint)
                try:
                    deadline = time.monotonic() + 120
                    while not (self.pids.exists() and self.pids.read_text().strip()):
                        self.assertIsNone(lane.poll(), "the lane exited before batch 1 left its process")
                        self.assertLess(time.monotonic(), deadline, "batch 1 never left its process")
                        time.sleep(0.05)
                    left = int(self.pids.read_text().split()[0])
                    leader = os.getpgid(left)
                    # The leader's pid disappears once the lane reaps the leader.
                    while True:
                        try:
                            os.kill(leader, 0)
                        except ProcessLookupError:
                            break
                        self.assertLess(time.monotonic(), deadline, "batch 1's leader never exited")
                        time.sleep(0.05)
                    self.assertFalse((evidence / "kani-1.exit").exists(), "the drain ended before the stop")
                    self.assertEqual([pid for pid, _ in tracked(self.marker) if pid == left], [left], "the process left the group before the stop")
                    os.kill(lane.pid, stop)
                    stopped = time.monotonic()
                    self.assertTrue(wait_exit(lane, SIGINT_GRACE), "the lane did not stop before the runner's next signal")
                    self.assertEqual((evidence / "exit.txt").read_text(), "143\n")
                    # On a loaded host the lane can exit while the process it killed still shows in /proc, running with
                    # KILL pending; the process has until the runner's next signal to leave.
                    while tracked(self.marker) and time.monotonic() < stopped + SIGINT_GRACE:
                        time.sleep(0.01)
                    self.assertEqual(tracked(self.marker), [], "a process of the draining batch survived the stop")
                    self.assertFalse((evidence / "kani-1.exit").exists() or (evidence / "report.json").exists())
                finally:
                    # Whatever the subtest found, the next one starts with no lane and no process of this one.
                    (ROOT / "crates/kestrike/kani-list.json").unlink(missing_ok=True)
                    if lane.poll() is None:
                        lane.kill()
                        lane.wait()
                    self.kill_tracked()

    def test_a_stop_between_a_leader_s_reap_and_its_drain_kills_the_group_at_once(self):
        """`deadline` reaps a batch's leader with `wait -n` and then drains its group; a stop right after the reap finds
        no process at the leader's ID and kills what remains of the group at once, as a stop during the drain does,
        without waiting out a grace for an exit already reaped."""
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        bodies = "".join(f"{name}() {{{script.split(f'{chr(10)}{name}() {{', 1)[1].split(chr(10) + '}' + chr(10), 1)[0]}\n}}\n"
                         for name in ("stop_group", "on_signal"))
        # The script's `wait` stands for deadline's `wait -n`, and its TERM arrives right after that reap. The script
        # records the time it sends the TERM, so the stop is timed from the signal, whatever the shell took to start.
        window = (f"EVIDENCE={shlex.quote(str(self.dir))}\nCHILD= TIMER=\n{bodies}trap on_signal TERM INT\n"
                  "setsid bash -c \"trap '' TERM; sleep 60 &\" &\nCHILD=$!\nwait \"$CHILD\" || true\n"
                  "date +%s.%N > \"$EVIDENCE/sent\"\nkill -TERM $$\nsleep 60\n")
        ran = subprocess.run(["bash", "-c", window], env=self.env, capture_output=True, text=True, timeout=90, check=False)
        ended = time.time()
        self.assertEqual(ran.returncode, 143, ran.stderr)
        sent = float((self.dir / "sent").read_text())
        while tracked(self.marker) and time.time() < sent + SIGINT_GRACE:
            time.sleep(0.01)
        self.assertEqual((self.dir / "exit.txt").read_text(), "143\n")
        self.assertEqual(tracked(self.marker), [], "the group's member survived the stop")
        self.assertLess(ended - sent, SIGINT_GRACE, "the stop waited for a leader already reaped")

    def test_a_kani_deadline_is_a_positive_base_10_count(self):
        script = (ROOT / "scripts/rust-lane.sh").read_text()
        body = script.split("\nseconds_of() {", 1)[1].split("\n}\n", 1)[0]
        for given, seconds in (("45", "45"), ("6s", "6"), ("30m", "1800"), ("210m", "12600"), ("3h", "10800"), ("010m", "600"),
                               ("08m", "480"), ("0", None), ("0m", None), ("1.5m", None), ("10d", None), ("1234567", None), ("", None)):
            with self.subTest(given=given):
                ran = subprocess.run(["bash", "-c", f"seconds_of() {{{body}\n}}\nseconds_of \"$1\"", "-", given], capture_output=True, text=True, check=False)
                self.assertEqual((ran.returncode == 0, ran.stdout.strip() or None), (seconds is not None, seconds))

    def test_the_comparison_lane_records_both_arms_and_hands_them_to_the_judge(self):
        """`kani-compare` runs its harnesses once without the declaration's CBMC arguments and once under them and records
        each command, so the judge compares two runs it can tell apart; the stub writes no export, so the judge refuses."""
        self.kani_toolchain()
        (self.dir / "run").write_text("compared\n")
        declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
        names, evidence = declared["compared"][:2], self.dir / "evidence"
        ambient = {name: value for name, value in self.env.items() if name not in ("CARGO_BUILD_JOBS", "KANI_JOBS")}
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani-compare", *names], cwd=ROOT,
                              env=dict(ambient, CARGO_BUILD_JOBS="4", RUNNER_TEMP=str(self.dir), STUB_RUN=str(self.dir / "run")),
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(step.returncode, 1, step.stderr)
        without = (evidence / "compare-without.argv").read_text().splitlines()
        under = (evidence / "compare-with.argv").read_text().splitlines()
        head = ["cargo", "kani", "-p", "kestrike", "--exact", "--harness", names[0], "--harness", names[1], "-j", "2", "--output-format", "terse",
                "--target-dir", str(self.dir / "kani-target"), "-Z", "unstable-options", "--export-json"]
        self.assertEqual(without, [*head, str(evidence / "compare-without.json")])
        self.assertEqual(under, [*head, str(evidence / "compare-with.json"), "--cbmc-args", *declared["cbmc"]])
        self.assertEqual([(evidence / f"compare-{arm}.exit").read_text() for arm in ("without", "with")], ["0\n", "0\n"])
        self.assertEqual((evidence / "exit.txt").read_text(), "2\n")
        failure = (evidence / "failure.txt").read_text()
        self.assertIn("the comparison refused", failure)
        self.assertIn("compare-without.json", failure)
        (evidence / "failure.txt").unlink()
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani-compare"], cwd=ROOT, env=dict(ambient, RUNNER_TEMP=str(self.dir), STUB_RUN=str(self.dir / "run")),
                              capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("usage: rust-lane.sh kani-compare HARNESS...", (evidence / "failure.txt").read_text())

    def test_the_kani_lane_clears_every_target_scoped_cargo_override(self):
        self.kani_toolchain()
        ambient = {
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg x", "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/elsewhere/ld",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUNNER": "/elsewhere/run", "CARGO_TARGET_DIR": "/elsewhere/target",
            "RUSTFLAGS": "--cfg x", "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fx", "CARGO_BUILD_RUSTFLAGS": "--cfg x",
            "CARGO_BUILD_TARGET": "aarch64-unknown-linux-gnu", "RUSTC_WRAPPER": "sccache", "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "false",
            "CARGO_ALIAS_KANI": "run --bin fake",
        }
        (self.dir / "run").write_text("listed\n")
        env = dict(self.env, **ambient, RUNNER_TEMP=str(self.dir), STUB_RUN=str(self.dir / "run"), STUB_ENV_DUMP=str(self.dir / "cargo-env-dump.txt"))
        try:
            step = subprocess.run(["bash", "scripts/rust-lane.sh", "kani", "pr"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)
        finally:
            (ROOT / "crates/kestrike/kani-list.json").unlink(missing_ok=True)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertNotIn("survived clearing", step.stderr)
        received = env_dump(self.dir / "cargo-env-dump.txt")
        self.assertEqual(received.get("CARGO_TARGET_DIR"), f"{self.dir}/kani-target")
        survived = {name: value for name, value in received.items()
                    if name != "CARGO_TARGET_DIR" and (name in ambient or name.startswith(("RUSTC", "CARGO_TARGET_", "CARGO_PROFILE_", "CARGO_BUILD_RUSTC", "CARGO_ALIAS_")))}
        self.assertEqual(survived, {})

    def test_a_cache_keyed_without_patch_names_is_provisioned_afresh(self):
        import hashlib

        recipe = ROOT / "verification/genmc/provision.sh"
        patches = sorted((ROOT / "verification/genmc/patches").glob("*.patch"))
        contents_only = hashlib.sha256(b"nightly-2026-07-27\n" + b"".join(p.read_bytes() for p in [recipe, *patches])).hexdigest()[:16]
        self.genmc_toolchain(key=contents_only)
        (self.dir / "run").write_text("    Checking kernels v0.0.0\n")
        env = dict(self.env, STUB_RUN=str(self.dir / "run"))
        with self.genmc_std_link():
            step = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("provision failed", (self.dir / "evidence" / "failure.txt").read_text())

    def test_a_narrower_genmc_profile_leaves_no_output_of_a_wider_one(self):
        self.genmc_toolchain()
        evidence = self.dir / "evidence"
        evidence.mkdir(exist_ok=True)
        for name in ("genmc-grace2-seq.txt", "genmc-grace2-seq.exit", "genmc-grace2-weakpin.dot"):
            (evidence / name).write_text("stale\n")
        (self.dir / "run").write_text("    Checking kernels v0.0.0\n")
        with self.genmc_std_link():
            subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr"], cwd=ROOT, env=dict(self.env, STUB_RUN=str(self.dir / "run")),
                           capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(sorted(path.name for path in evidence.glob("genmc-grace2-*")), [])
        self.assertNotIn("outside the pr profile", (evidence / "report.json").read_text())

    def test_a_genmc_case_list_runs_only_its_cases_and_leaves_no_receipt(self):
        self.genmc_toolchain()
        evidence = self.dir / "evidence"
        (self.dir / "run").write_text("    Checking genmc-kernels v0.0.0\n")
        env = dict(self.env, STUB_RUN=str(self.dir / "run"))
        with self.genmc_std_link():
            listed = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr", "sb_sc", "join-production"], cwd=ROOT, env=env,
                                    capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(listed.returncode, 0, listed.stderr)
        self.assertEqual(sorted(path.name for path in evidence.glob("genmc-*.argv")), ["genmc-join-production.argv", "genmc-sb_sc.argv"])
        weaken = load("weaken_orderings", ROOT / "scripts/weaken-orderings.py")
        for case in ("sb_sc", "join-production"):
            log = evidence / f"check-{case}.txt"
            self.assertTrue(log.is_file() and weaken.REBUILT["genmc"].search(log.read_text()), f"{case} leaves the rebuild evidence run reads")
        for name in ("receipt.json", "report.json", "credit.json", "exit.txt"):
            self.assertFalse((evidence / name).exists(), name)
        packages = ROOT / "verification/genmc/packages"
        refusals = ((("grace2-seq",), "grace2-seq is no GenMC case of the pr profile"),
                    (("join-production\nzzz",), "join-production\nzzz is no GenMC case of the pr profile"),
                    (("join-production\n../escape",), "join-production\n../escape is no GenMC case"),
                    ((" join-production",), " join-production is no GenMC case of the pr profile"),
                    (("join-production", "join-production"), "join-production is named more than once"))
        for index, (arguments, text) in enumerate(refusals):
            fresh = self.dir / f"refused-{index}"
            before = {argument: (packages / f"run-{argument}").exists() for argument in arguments}
            with self.subTest(arguments=arguments), self.genmc_std_link():
                refused = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr", "sb_sc", *arguments], cwd=ROOT,
                                         env=dict(env, EVIDENCE=str(fresh)), capture_output=True, text=True, timeout=120, check=False)
                self.assertEqual(refused.returncode, 1)
                self.assertIn(text, (fresh / "failure.txt").read_text())
                self.assertEqual({argument: (packages / f"run-{argument}").exists() for argument in arguments}, before)
                self.assertEqual(sorted(path.name for path in fresh.glob("check-*")) + sorted(path.name for path in fresh.glob("genmc-*")), [])
        for config in ({"build": {"target-dir": str(self.dir / "elsewhere")}}, {"build": {"build-dir": str(self.dir / "elsewhere")}}):
            for arguments in (("sb_sc",), ()):
                shaped = self.dir / f"shaped-{len(arguments)}-{next(iter(config['build']))}"
                with self.subTest(config=config, arguments=arguments), self.genmc_std_link():
                    refused = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr", *arguments], cwd=ROOT,
                                             env=dict(env, EVIDENCE=str(shaped), STUB_CARGO_CONFIG=json.dumps(config)),
                                             capture_output=True, text=True, timeout=120, check=False)
                    self.assertEqual(refused.returncode, 1)
                    self.assertIn(f"build.{next(iter(config['build']))}", (shaped / "config.txt").read_text())
                    self.assertEqual(sorted(path.name for path in shaped.glob("check-*")), [])
                    self.assertFalse((self.dir / "elsewhere").exists())
        full = self.dir / "full"
        with self.genmc_std_link():
            subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr"], cwd=ROOT, env=dict(env, EVIDENCE=str(full)), capture_output=True,
                           text=True, timeout=120, check=False)
        profile = subprocess.run([sys.executable, "scripts/judge-genmc.py", "cases", "--profile", "pr"], cwd=ROOT, capture_output=True,
                                 text=True, check=True).stdout.split()
        self.assertEqual(sorted(path.name.removesuffix(".argv").removeprefix("genmc-") for path in full.glob("genmc-*.argv")), sorted(profile))
        self.assertTrue((full / "receipt.json").is_file(), "a full-profile run writes its receipt")
        self.assertTrue((full / "exit.txt").is_file(), "a full-profile run records the judgment's exit")
        # A full-profile judgment covers the case outputs it read, so a case-list run that replaces them removes it.
        (full / "credit.json").write_text(json.dumps({"refusals": []}))
        (self.dir / "summary.md").unlink(missing_ok=True)
        with self.genmc_std_link():
            partial = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr", "sb_sc"], cwd=ROOT, env=dict(env, EVIDENCE=str(full)),
                                     capture_output=True, text=True, timeout=120, check=False)
        self.assertEqual(partial.returncode, 0, partial.stderr)
        self.assertEqual(sorted(path.name for path in full.glob("genmc-*.argv")), ["genmc-sb_sc.argv"])
        for name in ("receipt.json", "report.json", "credit.json", "exit.txt"):
            self.assertFalse((full / name).exists(), f"a case-list run keeps the {name} of an earlier full-profile run")
        subprocess.run(["bash", "scripts/rust-lane.sh", "summary", "genmc", "pr"], cwd=ROOT, env=dict(env, EVIDENCE=str(full)),
                       capture_output=True, text=True, timeout=120, check=True)
        self.assertIn("### GenMC pr profile: red", (self.dir / "summary.md").read_text())

    def test_the_genmc_lane_builds_its_cases_under_the_pinned_compiler_only(self):
        self.genmc_toolchain()
        ambient = {
            "RUSTC": "/elsewhere/rustc", "RUSTC_WRAPPER": "sccache", "RUSTC_WORKSPACE_WRAPPER": "sccache",
            "CARGO_BUILD_RUSTC": "/elsewhere/rustc", "CARGO_BUILD_RUSTC_WRAPPER": "sccache",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER": "sccache", "CARGO_BUILD_TARGET": "aarch64-unknown-linux-gnu",
            "RUSTFLAGS": "--cfg x", "CARGO_ENCODED_RUSTFLAGS": "--cfg\x1fx", "CARGO_BUILD_RUSTFLAGS": "--cfg x",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS": "--cfg x",
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER": "/elsewhere/ld", "CARGO_TARGET_DIR": "/elsewhere/target",
            "CARGO_PROFILE_DEV_DEBUG_ASSERTIONS": "false",
        }
        (self.dir / "run").write_text("    Checking kernels v0.0.0\n")
        env = dict(self.env, **ambient, CARGO_BUILD_JOBS="4", STUB_RUN=str(self.dir / "run"), STUB_ENV_DUMP=str(self.dir / "cargo-env-dump.txt"))
        with self.genmc_std_link():
            step = subprocess.run(["bash", "scripts/rust-lane.sh", "genmc", "pr"], cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the GenMC judgment refused", (self.dir / "evidence" / "failure.txt").read_text())
        received = env_dump(self.dir / "cargo-env-dump.txt")
        pinned = {"RUSTUP_TOOLCHAIN": "nightly-2026-07-27", "RUSTC": str(self.rustc),
                  "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": "", "CARGO_BUILD_JOBS": "4"}
        survived = {name: value for name, value in received.items()
                    if name not in pinned and (name in ambient or name.startswith(("RUSTC", "CARGO_TARGET_", "CARGO_PROFILE_", "CARGO_BUILD_RUSTC")))}
        self.assertEqual(survived, {})
        self.assertEqual({name: received.get(name) for name in pinned}, pinned)
        evidence = self.dir / "evidence"
        try:
            self.assertEqual(json.loads((evidence / "cargo-config.json").read_text()), {})
        except (OSError, ValueError) as error:
            self.fail(f"the lane recorded no readable cargo configuration: {error}")
        for name in ("sb_sc", "wrap_falsifier"):
            self.assertEqual((evidence / f"genmc-{name}.env").read_text().splitlines(), [
                f"CASE={name}", "RUSTUP_TOOLCHAIN=nightly-2026-07-27", f"RUSTC={pinned['RUSTC']}", "RUSTC_WRAPPER=", "RUSTC_WORKSPACE_WRAPPER=",
            ])

    def test_each_recorded_rc11_command_is_the_command_herd7_received(self):
        libdir, received = self.dir / "herdlib", self.dir / "received"
        libdir.mkdir()
        received.mkdir()
        for name in ("rc11.cat", "stdlib.cat"):
            (libdir / name).write_text("let x = 0\n")
        stub = self.dir / "bin" / "herd7"
        stub.write_text(
            "#!/usr/bin/env bash\n"
            'case "$1" in -version) echo "7.58, Rev: stub"; exit 0 ;; -libdir) echo "$HERD_LIBDIR"; exit 0 ;; esac\n'
            'printf \'%s\\n\' "$0" "$@" > "$STUB_RECEIVED/$(basename "${@: -1}" .litmus).argv"\n'
        )
        stub.chmod(0o755)
        step = subprocess.run(
            ["bash", "scripts/rust-lane.sh", "rc11"], cwd=ROOT, capture_output=True, text=True, timeout=60,
            env=dict(self.env, HERD_LIBDIR=str(libdir), STUB_RECEIVED=str(received)),
        )
        self.assertEqual(step.returncode, 1, step.stderr)
        tests = sorted(path.stem for path in (ROOT / "verification/rc11/litmus").glob("*.litmus"))
        self.assertEqual(len(tests), len(json.loads((ROOT / "verification/rc11/expected.json").read_text())["tests"]))
        self.assertEqual(sorted(path.stem for path in received.glob("*.argv")), tests)
        for name in tests:
            with self.subTest(test=name):
                recorded = (self.dir / "evidence" / f"herd-{name}.argv").read_text().splitlines()
                self.assertEqual(recorded, (received / f"{name}.argv").read_text().splitlines())
                self.assertEqual(recorded[1:5], ["-model", "rc11.cat", "-speedcheck", "false"])

    def test_cancelled_fuzz_step_leaves_no_process(self):
        for lane in ("fuzz", "fuzz-smoke"):
            with self.subTest(lane=lane):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                self.pids.unlink(missing_ok=True)
                self.assertEqual(self.cancel(lane, self.commands[lane]), [])
                self.assertIn("cargo-fuzz 0.13.2", self.pins_written())

    def campaign_fuzz(self, build_exit=0, worker_exit=0, fuzz_exit=0, frame_runs: Optional[int] = 1000, frame_exit=0, worker_script=None, **env):
        """Run the fuzz lane past the frame smoke into `campaign_fuzz` with a stubbed instrumented worker.

        The cargo stub records the environment of the instrumented build and exits `build_exit`; the
        stubbed worker it names writes one seed and exits `worker_exit` on `--seeds`, and exits
        `fuzz_exit` on `--fuzz` with no output, unless `worker_script` replaces it. The frame run reports
        `frame_runs` runs and exits `frame_exit`; when `STUB_FRAME_ARGS` names a file, the stub writes the
        frame run's arguments there, one per line. Return the step and the build's recorded environment.
        """
        seeds = len(subprocess.run(["git", "-C", "crates/kestrike/fuzz", "ls-files", "corpus/frame"], cwd=ROOT,
                                   capture_output=True, text=True, check=True).stdout.splitlines())
        (self.dir / "run").write_text(f"INFO: seed corpus: files: {seeds} min: 1b max: 1b\nDone {frame_runs or seeds + 1} runs in 61 second(s)\n")
        worker = self.dir / "bin" / "sim_worker"
        worker.write_text(worker_script or (
            "#!/usr/bin/env bash\n"
            f'case "$1" in\n  --seeds) touch "$3/upload.input"; exit {worker_exit} ;;\n  --fuzz) exit {fuzz_exit} ;;\nesac\nexit 0\n'
        ))
        worker.chmod(0o755)
        build = {"reason": "compiler-artifact", "target": {"name": "sim_worker"}, "executable": str(worker)}
        (self.dir / "bin" / "cargo").write_text(
            "#!/usr/bin/env bash\n"
            'case " $* " in\n'
            '  *" fuzz --version "*) echo "cargo-fuzz $CARGO_FUZZ"; exit 0 ;;\n'
            '  *" --test sim_worker "*)\n'
            '    if [ -n "${CARGO_ENCODED_RUSTFLAGS+set}" ]; then echo "encoded=[$CARGO_ENCODED_RUSTFLAGS] RUSTFLAGS=[$RUSTFLAGS]"; '
            'else echo "encoded unset RUSTFLAGS=[$RUSTFLAGS]"; fi > "$STUB_BUILD_ENV"\n'
            f"    echo '{json.dumps(build)}'; exit {build_exit} ;;\n"
            '  *" fuzz run "*" frame "*) [ -z "${STUB_FRAME_ARGS:-}" ] || printf \'%s\\n\' "$@" > "$STUB_FRAME_ARGS"; '
            f'cat "$STUB_RUN"; exit {frame_exit} ;;\n'
            '  *) cat "$STUB_RUN"; exit 0 ;;\n'
            "esac\n"
        )
        (self.dir / "bin" / "nm").write_text("#!/usr/bin/env bash\nprintf '0000 T __asan_init\\n0000 T LLVMFuzzerRunDriver\\n'\n")
        (self.dir / "bin" / "nm").chmod(0o755)
        recorded = self.dir / "campaign-build-env.txt"
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "fuzz"], cwd=ROOT, capture_output=True, text=True, timeout=120, check=False,
                              env=dict(self.env, **env, STUB_RUN=str(self.dir / "run"), STUB_BUILD_ENV=str(recorded)))
        return step, recorded.read_text() if recorded.exists() else ""

    def test_a_worker_target_credits_only_with_a_generated_pass(self):
        """Each worker target's timed run must report a positive non-seed pass count; seed passes and executions
        past the seeds earn nothing."""
        def line(target, *checkpoint):
            head = f"fuzz: {target} executed=500 pass=300 unsuccessful=0 invalid=200 incomplete=0 unsupported=0 failure=0"
            return " ".join([head, *checkpoint])

        whole = {"campaign": line("campaign", "nonseed_pass=3"), "record": line("record", "nonseed_pass=7"),
                 "wire": line("wire", "nonseed_pass=9")}
        cases = (
            ("every target passes a generated input", {}, None),
            ("a campaign without a generated pass", {"campaign": line("campaign", "nonseed_pass=0")},
             "the campaign run earned no credit: no generated input passed the oracle"),
            ("a parser without a generated pass", {"record": line("record", "nonseed_pass=0")},
             "the record run earned no credit: no generated input passed the oracle"),
            ("a counts line without the checkpoint", {"wire": line("wire")},
             "the wire run earned no credit: no generated input passed the oracle"),
        )
        for name, lines, failure in cases:
            with self.subTest(name):
                shutil.rmtree(self.dir / "evidence", ignore_errors=True)
                plan = {"seeds": {}, "lines": {**whole, **lines}}
                step, _ = self.campaign_fuzz(worker_script=FUZZ_WORKER, STUB_FUZZ_PLAN=json.dumps(plan))
                evidence = self.dir / "evidence"
                if failure is None:
                    self.assertEqual(step.returncode, 0, step.stdout + step.stderr)
                    recorded = json.loads((evidence / "fuzz.json").read_text())
                    self.assertEqual(recorded["campaign"]["nonseed_pass"], 3)
                    self.assertEqual(recorded["parsers"]["record"]["nonseed_pass"], 7)
                else:
                    self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
                    self.assertEqual((evidence / "failure.txt").read_text(), failure + "\n")

    def test_the_frame_run_passes_the_tracked_dictionary_and_its_nonzero_exit_fails_the_lane(self):
        """The lane names the fuzz directory relative to the checkout, so the frame run's `-dict` must name
        the tracked dictionary by an absolute path that resolves to it, after the `--` that hands it to libFuzzer.
        libFuzzer exits 1 for a dictionary it cannot read or parse, so the lane must fail on the frame run's
        nonzero exit, with passing seed and run counts, before the campaign build starts."""
        args = self.dir / "frame-args.txt"
        step, recorded = self.campaign_fuzz(frame_exit=1, STUB_FRAME_ARGS=str(args))
        self.assertTrue(args.exists(), step.stdout + step.stderr)
        lines = args.read_text().splitlines()
        dicts = [(at, arg.removeprefix("-dict=")) for at, arg in enumerate(lines) if arg.startswith("-dict=")]
        self.assertEqual(len(dicts), 1, dicts)
        at, path = dicts[0]
        self.assertIn("--", lines)
        self.assertGreater(at, lines.index("--"), lines)
        self.assertTrue(os.path.isabs(path), path)
        self.assertTrue(os.path.exists(path), path)
        self.assertTrue(os.path.samefile(path, ROOT / "crates/kestrike/fuzz/frame.dict"), path)
        evidence = self.dir / "evidence"
        self.assertEqual(step.returncode, 1, step.stdout + step.stderr)
        self.assertEqual((evidence / "exit.txt").read_text(), "1\n")
        self.assertEqual((evidence / "failure.txt").read_text(), "the fuzz run exited 1; crash inputs are in artifacts/\n")
        self.assertEqual(recorded, "", "the campaign build never starts")

    def test_a_frame_run_with_no_input_past_its_seeds_fails_the_lane(self):
        step, recorded = self.campaign_fuzz(frame_runs=None)
        self.assertNotEqual(step.returncode, 0, step.stdout)
        self.assertIn("the run executed no input past its", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertEqual(recorded, "", "the campaign build never starts")

    def test_the_instrumented_worker_builds_without_ambient_encoded_rustflags(self):
        """Cargo reads CARGO_ENCODED_RUSTFLAGS before RUSTFLAGS, so an ambient value would replace the
        sanitizer and coverage flags the campaign build sets."""
        step, recorded = self.campaign_fuzz(worker_exit=1, CARGO_ENCODED_RUSTFLAGS="--cfg\x1fx")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the worker wrote no campaign seeds", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertTrue(recorded, "the instrumented build never ran")
        self.assertTrue(recorded.startswith("encoded unset RUSTFLAGS=[-Zsanitizer=address "), recorded)

    def test_an_interrupted_campaign_step_records_its_exit(self):
        """The frame run records exit 0 before the campaign; a campaign step that passes its deadline must
        record 124 so the receipt reads a timeout, not a tool failure."""
        for name, kwargs, failure in (("build", {"build_exit": 124}, "the instrumented worker build exited 124"),
                                      ("seeds", {"worker_exit": 124}, "the worker wrote no campaign seeds")):
            with self.subTest(step=name):
                step, _ = self.campaign_fuzz(**kwargs)
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn(failure, (self.dir / "evidence" / "failure.txt").read_text())
                self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "124\n")

    def test_a_seed_pass_without_a_counts_line_fails_with_its_exit_code(self):
        """A worker that exits before its counts line, refused or killed, leaves nothing for `grep` to
        match; the lane's failure still names the seed pass and its exit code."""
        step, _ = self.campaign_fuzz(fuzz_exit=2)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the campaign seed pass exited 2 without passing all 1 seeds", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertEqual((self.dir / "evidence" / "exit.txt").read_text(), "2\n")

    def verus_cache(self):
        """Stub the Verus release fetch under this test's HOME and return the release's cache directory and the fetch log."""
        pinned = json.loads((ROOT / "verification/verus/expected.json").read_text())["verus"]
        home = self.dir / "home"
        launcher = self.dir / "verus-launcher"
        launcher.write_text(
            "#!/usr/bin/env bash\nmkdir -p target/verus\n"
            "printf 'target/verus/kestrike_verus.d: src/lib.rs\\n' > target/verus/kestrike_verus.d\n"
            "echo 'verification results:: 19 verified, 0 errors'\n"
        )
        launcher.chmod(0o755)
        stubs = {
            "curl": '#!/usr/bin/env bash\necho fetch >> "$STUB_FETCHES"\n[ -z "${STUB_CURL_EXIT:-}" ] || exit "$STUB_CURL_EXIT"\n'
                    'while [ "$1" != -o ]; do shift; done\necho archive > "$2"\n',
            "sha256sum": f'#!/usr/bin/env bash\ncase "${{1:-}}" in *verus.zip) echo "{pinned["archive"]["sha256"]}  $1" ;; '
                         f'*) exec {shutil.which("sha256sum")} "$@" ;; esac\n',
            "unzip": '#!/usr/bin/env bash\nwhile [ "$1" != -d ]; do shift; done\nmkdir -p "$2/verus-x86-linux"\n'
                     'cp "$STUB_LAUNCHER" "$2/verus-x86-linux/verus"\nexit "${STUB_UNZIP_EXIT:-0}"\n',
            "rustup": "#!/usr/bin/env bash\nexit 0\n",
        }
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        fetches = self.dir / "fetches"
        self.env.update(HOME=str(home), STUB_FETCHES=str(fetches), STUB_LAUNCHER=str(launcher))
        return home / ".cache/kestrike-verus" / pinned["version"], fetches

    def verus_lane(self, **env):
        return subprocess.run(["bash", "scripts/rust-lane.sh", "verus"], cwd=ROOT, env=dict(self.env, **env),
                              capture_output=True, text=True, timeout=120, check=False)

    def test_an_interrupted_verus_extraction_is_fetched_afresh(self):
        prefix, fetches = self.verus_cache()
        for attempt in (1, 2):
            with self.subTest(attempt=attempt):
                step = self.verus_lane(STUB_UNZIP_EXIT="1")
                self.assertEqual(step.returncode, 1, step.stderr)
                self.assertIn("unpack failed", (self.dir / "evidence" / "failure.txt").read_text())
                self.assertEqual(fetches.read_text().splitlines(), ["fetch"] * attempt)
        self.assertFalse(prefix.exists(), "a partial extraction was published as the cached release")

    def test_a_cached_verus_install_off_its_declared_tree_is_fetched_afresh(self):
        prefix, fetches = self.verus_cache()
        (prefix / "verus-x86-linux").mkdir(parents=True)
        shutil.copy(self.env["STUB_LAUNCHER"], prefix / "verus-x86-linux/verus")
        step = self.verus_lane(STUB_CURL_EXIT="22")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertEqual(fetches.read_text().splitlines() if fetches.exists() else [], ["fetch"])
        self.assertIn("fetch failed", (self.dir / "evidence" / "failure.txt").read_text())

    def test_the_verus_lane_stops_before_running_a_refused_or_empty_command(self):
        """The declaration check runs before the identity step, whose refusal reinstalls the cached release, so a
        refused declaration fails the lane with its own reason, keeps the cached release and runs no identity step."""
        prefix, fetches = self.verus_cache()
        (prefix / "verus-x86-linux").mkdir(parents=True)
        identities = self.dir / "identities"
        python = self.dir / "bin" / "python3"
        python.write_text(
            '#!/usr/bin/env bash\ncase "$1 $2" in\n'
            '  "scripts/judge-verus.py identity") echo identity >> "$STUB_IDENTITIES"; exit 2 ;;\n'
            '  "scripts/judge-verus.py command") printf "%s" "$STUB_DECL_OUTPUT"; printf "%s" "$STUB_DECL_ERROR" >&2\n'
            '    exit "$STUB_DECL_EXIT" ;;\n'
            f'esac\nexec {shutil.which("python3")} "$@"\n'
        )
        python.chmod(0o755)
        evidence = self.dir / "evidence"
        for code, output, error, reason in ((2, "verus\n", "judge-verus: a reason\n", "declaration was refused: judge-verus: a reason"),
                                            (2, "verus\n", "judge-verus: first\njudge-verus: last\n",
                                             "declaration was refused: judge-verus: last\n"),
                                            (2, "verus\n", "", "declaration was refused"), (0, "", "", "has no executable"),
                                            (0, "\n--no-cheating\n", "", "has no executable")):
            with self.subTest(code=code, output=output, error=error):
                (evidence / "failure.txt").unlink(missing_ok=True)
                step = self.verus_lane(STUB_DECL_EXIT=str(code), STUB_DECL_OUTPUT=output, STUB_DECL_ERROR=error, STUB_EXIT="0",
                                       STUB_IDENTITIES=str(identities))
                self.assertNotEqual(step.returncode, 0)
                failure = (evidence / "failure.txt").read_text()
                self.assertIn(reason, failure)
                self.assertNotIn("first", failure)
                self.assertFalse(identities.exists(), "the identity step ran before the declaration check")
                self.assertFalse(fetches.exists(), "a refused declaration reinstalled the cached release")
                self.assertTrue((prefix / "verus-x86-linux").is_dir())
                self.assertFalse((evidence / "verus.txt").exists())
                self.assertFalse((evidence / "verus.exit").exists())

    def test_the_verus_lane_records_the_dep_info_of_this_checks_library_artifact(self):
        import hashlib

        prefix, _ = self.verus_cache()
        (prefix / "verus-x86-linux").mkdir(parents=True)
        shutil.copy(self.env["STUB_LAUNCHER"], prefix / "verus-x86-linux/verus")
        python = self.dir / "bin" / "python3"
        python.write_text(
            '#!/usr/bin/env bash\n[ "${1:-} ${2:-}" != "scripts/judge-verus.py identity" ] || exit 0\n'
            f'exec {shutil.which("python3")} "$@"\n'
        )
        python.chmod(0o755)
        cpu = host_cpu(Path("/proc/cpuinfo").read_text())
        deps = self.dir / "home/.cache/kestrike-target" / hashlib.sha256(f"{cpu} 1.99.0".encode()).hexdigest()[:16] / "debug/deps"
        deps.mkdir(parents=True)
        (deps / "kestrike-0000000000000001.d").write_text("library check: crates/kestrike/src/lib.rs\n")
        decoy = deps / "kestrike-0000000000000002.d"
        decoy.write_text("test harness: crates/kestrike/src/lib.rs\n")
        os.utime(decoy, (time.time() + 60, time.time() + 60))
        messages = [
            {"reason": "compiler-artifact", "target": {"name": "libc", "kind": ["lib"]}, "profile": {"test": False},
             "filenames": [str(deps / "liblibc-0000000000000003.rmeta")], "fresh": True},
            {"reason": "compiler-artifact", "target": {"name": "kestrike", "kind": ["lib"]}, "profile": {"test": False},
             "filenames": [str(deps / "libkestrike-0000000000000001.rmeta")], "fresh": True},
            {"reason": "build-finished", "success": True},
        ]
        run = self.dir / "run"
        run.write_text("".join(f"{json.dumps(message)}\n" for message in messages) + "    Finished `dev` profile\n")
        step = self.verus_lane(STUB_RUN=str(run))
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("the Verus judgment refused", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertEqual((self.dir / "evidence" / "cargo.d").read_text(), "library check: crates/kestrike/src/lib.rs\n")

    def tlc_install(self, edit, token="lane-token"):
        """Run `rust-lane.sh tlctools` from a copy of the lane whose TLC declaration `edit` changes, with stub
        fetches that write each archive's file name as its bytes, and return the step, the cache entry and each
        fetch's arguments with the header files it read."""
        import hashlib

        root = self.dir / "root"
        (root / "scripts").mkdir(parents=True)
        (root / "verification/tlc").mkdir(parents=True)
        shutil.copy(ROOT / "scripts/rust-lane.sh", root / "scripts/rust-lane.sh")
        declared = json.loads((ROOT / "verification/tlc/expected.json").read_text())
        for tool, name in (("java", "jdk.tar.gz"), ("jar", "tla2tools.jar")):
            declared[tool]["sha256"] = hashlib.sha256(f"{name}\n".encode()).hexdigest()
        edit(declared)
        (root / "verification/tlc/expected.json").write_text(json.dumps(declared))
        fetches = self.dir / "fetches.json"
        stubs = {
            "curl": "#!/usr/bin/env python3\nimport json, os, sys\nargs = sys.argv[1:]\n"
                    "headers = [open(arg[1:]).read() for arg in args if arg.startswith('@')]\n"
                    "with open(os.environ['STUB_FETCHES'], 'a') as log:\n"
                    "    log.write(json.dumps({'argv': args, 'headers': headers}) + '\\n')\n"
                    "out = args[args.index('-o') + 1]\nopen(out, 'w').write(os.path.basename(out) + '\\n')\n",
            "tar": "#!/usr/bin/env bash\nexit 0\n",
        }
        for name, text in stubs.items():
            (self.dir / "bin" / name).write_text(text)
            (self.dir / "bin" / name).chmod(0o755)
        home = self.dir / "home"
        env = {key: value for key, value in self.env.items() if key != "GH_TOKEN"}
        env.update(HOME=str(home), STUB_FETCHES=str(fetches), **({"GH_TOKEN": token} if token else {}))
        step = subprocess.run(["bash", "scripts/rust-lane.sh", "tlctools"], cwd=root, env=env,
                              capture_output=True, text=True, timeout=60, check=False)
        entry = home / ".cache/kestrike-tlc" / f"{declared['java']['sha256'][:16]}-{declared['jar']['sha256'][:16]}"
        calls = [json.loads(line) for line in fetches.read_text().splitlines()] if fetches.exists() else []
        return step, entry, calls

    def test_a_tlc_install_matching_its_declared_digests_is_cached(self):
        step, entry, calls = self.tlc_install(lambda declared: None)
        self.assertEqual(step.returncode, 0, step.stderr)
        self.assertEqual((entry / "tla2tools.jar").read_text(), "tla2tools.jar\n")
        self.assertEqual(sorted(path.name for path in entry.iterdir()), ["jdk", "tla2tools.jar"])

    def test_the_tlc_jar_fetch_reads_its_token_from_a_header_file_and_the_jdk_fetch_sends_none(self):
        step, _, calls = self.tlc_install(lambda declared: None)
        self.assertEqual(step.returncode, 0, step.stderr)
        by_output = {Path(call["argv"][call["argv"].index("-o") + 1]).name: call for call in calls}
        self.assertEqual(sorted(by_output), ["jdk.tar.gz", "tla2tools.jar"])
        self.assertEqual(by_output["tla2tools.jar"]["headers"], ["Authorization: Bearer lane-token\n"])
        self.assertEqual(by_output["jdk.tar.gz"]["headers"], [])
        for call in calls:
            self.assertNotIn("lane-token", " ".join(call["argv"]))

    def test_a_tlc_install_without_a_token_refuses_the_jar_fetch(self):
        step, entry, calls = self.tlc_install(lambda declared: None, token="")
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("GH_TOKEN", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertEqual(calls, [])
        self.assertFalse(entry.exists())

    def test_a_malformed_tlc_digest_refuses_the_install(self):
        def truncate(declared):
            declared["java"]["sha256"] = declared["java"]["sha256"][:63]

        step, entry, _ = self.tlc_install(truncate)
        self.assertEqual(step.returncode, 1, step.stderr)
        self.assertIn("a TLC tool archive differs from its declared digest", (self.dir / "evidence" / "failure.txt").read_text())
        self.assertFalse(entry.exists(), "an unverified JDK was published as the cached install")

    def pins_written(self):
        """Return the lane's `pins.txt`, written before its long command starts, after checking the interruption record."""
        exit_file = self.dir / "evidence" / "exit.txt"
        self.assertTrue(exit_file.exists(), "the interrupted lane recorded no exit.txt")
        self.assertEqual(exit_file.read_text(), "143\n")
        pins = self.dir / "evidence" / "pins.txt"
        self.assertTrue(pins.exists(), "the lane wrote no pins.txt before its long command")
        text = pins.read_text()
        self.assertIn("rustc 1.99.0", text)
        return text


class EventPolicy(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.jobs = workflow_jobs(WORKFLOW.read_text()) | workflow_jobs(HARDWARE_WORKFLOW.read_text())
        cls.verify = load("verify_receipts", ROOT / "scripts/verify-receipts.py")
        cls.FAST, cls.HEAVY, cls.PENDING = set(cls.verify.FAST_JOBS), set(cls.verify.HEAVY_JOBS), set(cls.verify.PENDING_JOBS)

    def statuses(self, event):
        selected = self.verify.selected_jobs(event)
        return {name: {"result": "success" if name in selected else "skipped"}
                for name in self.FAST | self.HEAVY | self.PENDING}

    def gate(self, event, statuses, action="", raw_results=None):
        return subprocess.run(
            [sys.executable, str(ROOT / "scripts/verify-receipts.py"), "gate", "--event", event, "--action", action],
            text=True, capture_output=True,
            env=dict(os.environ, RESULTS=json.dumps(statuses) if raw_results is None else raw_results),
        )

    def test_the_event_matrix_selects_fast_jobs_always_and_heavy_jobs_on_schedule_and_dispatch(self):
        for event, job, result in (
            ("pull_request", "workspace", "success"), ("pull_request", "comment-policy", "success"),
            ("pull_request", "loom", "skipped"), ("push", "barriers", "skipped"), ("push", "kani", "skipped"),
            ("schedule", "rc11", "success"), ("schedule", "loom", "success"), ("workflow_dispatch", "fuzz", "success"),
        ):
            with self.subTest(event=event, job=job):
                self.assertEqual(self.statuses(event)[job]["result"], result)

    def test_jobs_use_the_runner_pool_without_a_shared_job_lock(self):
        for name, body in workflow_jobs(WORKFLOW.read_text()).items():
            with self.subTest(job=name):
                self.assertNotRegex(body, r"(?m)^    concurrency:")
        workflow = WORKFLOW.read_text().partition("\njobs:\n")[0]
        self.assertNotIn("kestrike-singlehost", workflow)
        self.assertIn("${{ github.workflow }}-${{ github.event_name }}-${{", workflow)
        self.assertIn("github.event.pull_request.number || github.ref }}", workflow)
        self.assertIn("cancel-in-progress: ${{ github.event_name == 'pull_request' }}", workflow)
        # The hardware workflow's group belongs to the admitted job alone: a run the gate refuses, after a failed
        # workspace, a re-run of other jobs or a cancellation, never enters it, so it displaces no pending admitted run.
        self.assertNotIn("concurrency:", HARDWARE_WORKFLOW.read_text().partition("\njobs:\n")[0])
        hardware_jobs = workflow_jobs(HARDWARE_WORKFLOW.read_text())
        self.assertNotRegex(hardware_jobs["gate"], r"(?m)^    concurrency:")
        self.assertIn("    if: needs.gate.outputs.admitted == 'true'\n", hardware_jobs["hardware"])
        self.assertIn("    concurrency:\n      group: ${{ github.workflow }}-${{ matrix.arch }}-${{ github.event.workflow_run.head_branch }}\n"
                      "      cancel-in-progress: false\n", hardware_jobs["hardware"],
                      "an admitted hardware run holds back only the next one of its architecture on its branch")

    def test_gate_uses_all_named_dependencies_and_preserves_quarantine_exclusion(self):
        gate = self.jobs["rust-gate"]
        dependencies = matched(r"needs: \[([^\]]+)\]", gate).group(1).split(", ")
        self.assertEqual(set(dependencies), self.FAST | self.HEAVY | self.PENDING)
        self.assertEqual(len(dependencies), len(self.FAST | self.HEAVY | self.PENDING))
        self.assertNotIn("quarantine", dependencies)
        self.assertEqual(re.findall(r"(?m)^    if: (.+)$", gate), ["always() && (github.event_name != 'pull_request' || !cancelled())"])
        self.assertIn("RESULTS: ${{ toJSON(needs) }}", gate)
        self.assertIn('--event "${{ github.event_name }}"\n          --action "${{ github.event.action }}"', gate)

    def test_the_gate_refuses_a_fork_before_reading_the_checkout(self):
        """A fork pull request checks nothing out, so the gate fails before any step reads the workspace, and the
        step that runs verify-receipts.py from the checkout carries the same-repository guard."""
        gate = self.jobs["rust-gate"]
        refusal = gate.index("github.event.pull_request.head.repo.full_name != github.repository")
        checkout = gate.index("uses: actions/checkout@")
        self.assertLess(refusal, checkout, "the fork refusal precedes the checkout")
        self.assertIn("run: exit 1", gate[refusal:checkout])
        start = gate.index("- name: Every selected Rust lane succeeded")
        step = gate[start:gate.index("- name:", start + 1)]
        self.assertIn("github.event.pull_request.head.repo.full_name == github.repository", step)
        self.assertIn("python3 scripts/verify-receipts.py gate", step)

    def test_selected_lanes_must_succeed_for_each_event(self):
        events = [("pull_request", action) for action in ("opened", "synchronize", "reopened")]
        events += [(event, "") for event in ("push", "schedule", "workflow_dispatch")]
        advisory = set(self.verify.ADVISORY_JOBS)
        for event, action in events:
            statuses = self.statuses(event)
            with self.subTest(event=event, action=action):
                self.assertEqual(self.gate(event, statuses, action).returncode, 0)
            for name, status in statuses.items():
                for result in {"success", "skipped", "failure", "cancelled"} - {status["result"]}:
                    changed = {**statuses, name: {"result": result}}
                    passes = name in advisory and status["result"] == "success" and result != "skipped"
                    with self.subTest(event=event, action=action, lane=name, result=result):
                        self.assertEqual(self.gate(event, changed, action).returncode == 0, passes)

    def test_an_advisory_lane_that_failed_leaves_the_heavy_gate_green_and_a_ran_one_on_a_push_red(self):
        for event in ("schedule", "workflow_dispatch"):
            for result in ("failure", "cancelled"):
                with self.subTest(event=event, result=result):
                    gate = self.gate(event, {**self.statuses(event), "asan": {"result": result}})
                    self.assertEqual(gate.returncode, 0, gate.stdout)
            with self.subTest(event=event, result="skipped"):
                self.assertNotEqual(self.gate(event, {**self.statuses(event), "asan": {"result": "skipped"}}).returncode, 0)
        for event, action in (("pull_request", "opened"), ("push", "")):
            with self.subTest(event=event):
                self.assertNotEqual(self.gate(event, {**self.statuses(event), "asan": {"result": "success"}}, action).returncode, 0)

    def test_gate_rejects_missing_extra_or_invalid_events(self):
        for event, action in (("pull_request", "closed"), ("pull_request", "edited"),
                              ("pull_request", ""), ("merge_group", ""), ("", "")):
            with self.subTest(event=event, action=action):
                self.assertNotEqual(self.gate(event, self.statuses("push"), action).returncode, 0)
        for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
            statuses = self.statuses(event)
            action = "opened" if event == "pull_request" else ""
            for name in statuses:
                with self.subTest(event=event, missing=name):
                    self.assertNotEqual(self.gate(event, {k: v for k, v in statuses.items() if k != name}, action).returncode, 0)
            self.assertNotEqual(self.gate(event, {**statuses, "unexpected": {"result": "success"}}, action).returncode, 0)
        self.assertNotEqual(self.gate("push", {}, raw_results="not json").returncode, 0)

    def test_fast_dependencies_precede_heavy_lanes(self):
        dependencies = {
            "comment-policy": [], "lane-script": [], "rust-format": [],
            "rc11": ["[comment-policy, lane-script, rust-format]"],
            "preflight": [], "workspace": ["preflight"],
            "campaigns": ["[preflight, workspace]"], "search": ["[preflight, workspace]"], "fuzz-smoke": ["preflight"],
        }
        for name, expected in dependencies.items():
            with self.subTest(lane=name):
                self.assertEqual(re.findall(r"(?m)^    needs: (.+)$", self.jobs[name]), expected)
        condition = "if: >-\n      github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch'"
        for name in self.HEAVY | {"quarantine", "fis-controller"}:
            with self.subTest(lane=name):
                self.assertIn(condition, self.jobs[RUNNERS.get(name, name)])
        self.assertIn("needs: workspace", self.jobs["fis-controller"])
        # A pending job keeps the schedule and dispatch condition behind a `false &&`; enabling it replaces the
        # `if:` with the heavy jobs' condition above (the `false &&` and its parentheses go) beside its move from
        # PENDING_JOBS to HEAVY_JOBS.
        pending = "if: >-\n      false &&\n      (github.event_name == 'schedule' ||\n      github.event_name == 'workflow_dispatch')"
        for name in self.PENDING:
            with self.subTest(lane=name):
                if name == "barriers":
                    self.assertIn("if: >-\n      false && (github.event_name != 'pull_request' ||", self.jobs[name])
                    self.assertIn("needs: [comment-policy, lane-script, rust-format]", self.jobs[name])
                else:
                    self.assertIn(pending, self.jobs[name])
                    self.assertIn("needs: [preflight, workspace]", self.jobs[name])
                self.assertNotIn(name, self.verify.selected_jobs("schedule"))
        triggers = HARDWARE_WORKFLOW.read_text().partition("\npermissions:")[0]
        self.assertIn("on:\n  workflow_run:\n    workflows: [agent-checks]\n    types: [completed]\n", triggers,
                      "the hardware workflow starts from a completed agent-checks run")
        self.assertNotIn("pull_request", triggers)
        gate = self.jobs["gate"]
        self.assertIn("(github.event.workflow_run.event == 'schedule' ||\n      github.event.workflow_run.event == 'workflow_dispatch') &&\n"
                      "      github.event.workflow_run.conclusion != 'cancelled'",
                      gate, "a nightly or manual run admits the lane; a pull request, a push or a cancelled run never does")
        self.assertIn("RUN_ATTEMPT: ${{ github.event.workflow_run.run_attempt }}", gate)
        # The gate's admission rule runs against synthetic job lists. A re-run of a failed workspace leaves preflight
        # at the earlier attempt, and workspace needs preflight, so the workspace alone names the attempt.
        script = textwrap.dedent(gate.split("python3 - <<'PY'\n", 1)[1].split("\n          PY\n", 1)[0])
        # FIS admission uses the fis-controller attempt because the controller suite depends on the workspace: a
        # successful fis-controller re-run admits the FIS campaign, and hardware admission uses the workspace attempt.
        # Hardware and FIS admission require comment-policy success, which may come from an earlier attempt.
        policy = {"comment-policy": ("success", 1)}
        for jobs, attempt, admitted in (
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 1), "fis-controller": ("success", 1)}, 1, "true true"),
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 2), "fis-controller": ("success", 2)}, 2, "true true"),
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 1), "fis-controller": ("success", 2)}, 2, "false true"),
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 1), "fis-controller": ("failure", 1)}, 1, "true false"),
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 1)}, 1, "true false"),
            ({**policy, "preflight": ("success", 1), "workspace": ("success", 1), "fis-controller": ("success", 1)}, 2, "false false"),
            ({**policy, "preflight": ("success", 1), "workspace": ("failure", 1), "fis-controller": ("success", 1)}, 1, "false false"),
            ({**policy, "preflight": ("failure", 1), "workspace": ("skipped", 1)}, 1, "false false"),
            ({**policy, "preflight": ("success", 1)}, 1, "false false"),
            ({"comment-policy": ("failure", 1), "preflight": ("success", 1), "workspace": ("success", 1),
              "fis-controller": ("success", 1)}, 1, "false false"),
            ({"preflight": ("success", 1), "workspace": ("success", 1), "fis-controller": ("success", 1)}, 1, "false false"),
            ({}, 1, "false false"),
        ):
            with self.subTest(jobs=jobs, attempt=attempt), tempfile.TemporaryDirectory() as directory:
                (Path(directory) / "jobs.json").write_text(json.dumps({"jobs": [
                    {"name": name, "conclusion": conclusion, "run_attempt": ran} for name, (conclusion, ran) in jobs.items()]}))
                done = subprocess.run([sys.executable, "-c", script], cwd=directory, text=True, capture_output=True,
                                      env=dict(os.environ, RUN_ATTEMPT=str(attempt)))
                self.assertEqual((done.returncode, done.stdout.strip()), (0, admitted), done.stderr)
        self.assertIn("    needs: gate\n    if: needs.gate.outputs.admitted == 'true'\n", self.jobs["hardware"])
        self.assertIn("ref: ${{ github.event.workflow_run.head_sha }}", self.jobs["hardware"],
                      "the lane checks out the revision the admitted run judged")
        # The FIS job runs on its own registration once the run's controller suite passed in the completed attempt;
        # the campaign's custody check guards the host it lands on, so the job waits on the gate alone.
        self.assertIn("    needs: gate\n", self.jobs["fis"])
        self.assertIn("    if: needs.gate.outputs.fis-admitted == 'true'\n", self.jobs["fis"])
        self.assertIn("fis-admitted: ${{ steps.jobs.outputs.fis-admitted }}", gate)
        self.assertNotIn("needs.hardware", self.jobs["fis"], "a hardware host offline elsewhere holds back no FIS result")
        self.assertIn("ref: ${{ github.event.workflow_run.head_sha }}", self.jobs["fis"],
                      "the campaign checks out the revision the admitted run judged")
        self.assertIn('re.search(r"(?m)^  fis\\) ", lane) is not None and re.search(r"(?m)^  fis:$", text) is None',
                      self.jobs["fis"], "a revision from before the fis lane has nothing to run")
        self.assertEqual(self.jobs["fis"].count("if: steps.revision.outputs.split == 'true'"), 2)
        self.assertIn("if: always() && steps.revision.outputs.split == 'true'", self.jobs["fis"])
        for name in self.HEAVY:
            with self.subTest(lane=name):
                self.assertRegex(self.jobs[RUNNERS.get(name, name)], r"needs: (?:workspace|\[preflight, workspace\])")
        self.assertIn("needs: preflight", self.jobs["quarantine"])
        self.assertNotIn("needs: [preflight, workspace]", self.jobs["hardware"], "the gate job carries the ordering")
        hardware = load("hardware_lane", ROOT / "scripts/hardware-lane.py")
        manifest = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())
        grace = max(case["grace"] for profile in manifest["profiles"].values()
                    for role in profile["roles"].values() for case in role["cases"])
        kill_after, budget = map(int, matched(r"--kill-after=(\d+)s (\d+)m\s+bash scripts/rust-lane\.sh hardware",
                                                self.jobs["hardware"]).groups())
        self.assertGreaterEqual(kill_after, grace + hardware.STOP_SECONDS + hardware.CONTROLLER_SECONDS + 20,
                                "timeout's kill-after outlasts the longest close path: the grace, the stop window, "
                                "the controller window and stop_group's two waits")
        self.assertLessEqual(budget + kill_after / 60, int(matched(r"timeout-minutes: (\d+)", self.jobs["hardware"])[1]))
        self.assertIn("needs: [preflight, workspace]", self.jobs["loom"])
        self.assertIn("fromJSON(needs.preflight.outputs.loom-modules)", self.jobs["loom"])
        self.assertIn("      max-parallel: 2\n", self.jobs["loom"])
        for name in ("genmc", "kani"):
            self.assertIn("github.event_name == 'schedule' && 'scheduled' || 'pr'", self.jobs[name])

    def test_gate_fails_closed_on_malformed_results(self):
        for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
            action = "opened" if event == "pull_request" else ""
            statuses = self.statuses(event)
            for raw in ("", "{", "null", "[]", '"success"'):
                with self.subTest(event=event, raw=raw):
                    self.assertNotEqual(self.gate(event, statuses, action, raw_results=raw).returncode, 0)
            for name in statuses:
                for invalid in ({}, None, "success", {"result": None}, {"result": "unknown"}):
                    with self.subTest(event=event, lane=name, invalid=invalid):
                        self.assertNotEqual(self.gate(event, {**statuses, name: invalid}, action).returncode, 0)

    def test_runner_labels_route_short_build_and_heavy_jobs_for_each_event(self):
        allowed_nodes = (ast.Expression, ast.BoolOp, ast.And, ast.Or, ast.Compare,
                         ast.Eq, ast.Name, ast.Load, ast.Constant)
        for name, body in self.jobs.items():
            if name in AARCH64 or name in DEDICATED:
                self.assertIn(f"    runs-on: {(AARCH64 | DEDICATED)[name]}\n", body)
                continue
            if name in HOSTED:
                self.assertIn("    runs-on: ubuntu-24.04\n", body)
                continue
            selector = matched(r'(?m)^    runs-on: \[self-hosted, linux, x64, (.+)\]$', body).group(1)
            for event in ("pull_request", "push", "schedule", "workflow_dispatch"):
                with self.subTest(lane=name, event=event):
                    if selector.startswith('"${{ '):
                        self.assertTrue(selector.endswith(' }}"'))
                        expression = selector.removeprefix('"${{ ').removesuffix(' }}"')
                        expression = expression.replace("github.event_name", "event")
                        expression = expression.replace("&&", "and").replace("||", "or")
                        tree = ast.parse(expression, mode="eval")
                        self.assertTrue(all(isinstance(node, allowed_nodes) for node in ast.walk(tree)))
                        self.assertTrue(all(node.id == "event" for node in ast.walk(tree) if isinstance(node, ast.Name)))
                        label = eval(compile(tree, "<runner-label>", "eval"), {"__builtins__": {}}, {"event": event})
                    else:
                        label = selector
                    expected = "kestrike-ci-heavy"
                    if event in {"pull_request", "push"} and name in {"preflight", "workspace", "campaigns", "search",
                                                                        "fuzz-smoke"}:
                        expected = "kestrike-vm-build"
                    self.assertEqual(label, expected)
        review = (ROOT / ".github/workflows/claude-code-review.yml").read_text()
        self.assertIn("runs-on: ubuntu-24.04\n", review)
        self.assertNotRegex(review, r"kestrike-(?:ci|vm)")

    def test_nightly_verus_preserves_proof_deadlines_and_evidence(self):
        body = self.jobs["verus"]
        self.assertIn("needs: workspace", body)
        self.assertIn("timeout-minutes: 60", body)
        self.assertEqual(re.findall(r"scripts/rust-lane\.sh ([\w-]+)", body), ["toolchains", "verus", "summary"])
        self.assertEqual(re.findall(r"--kill-after=(\d+)s (\d+)m", body), [("60", "10"), ("60", "40")])
        self.assertIn("python3 scripts/verify-receipts.py credit --job verus", body)
        self.assertIn("--receipt evidence/receipt.json --evidence evidence", body)
        self.assertEqual(body.count("if: always()"), 3)
        self.assertIn("evidence-verus-${{ github.run_id", body)
        self.assertIn("if-no-files-found: error", body)
        self.assertNotIn("continue-on-error", body)

    def test_early_format_uses_only_pinned_stable_and_remains_bounded(self):
        job = self.jobs["rust-format"]
        self.assertIn("timeout-minutes: 12", job)
        self.assertIn('rustup toolchain install "$STABLE" --profile minimal --component rustfmt', job)
        self.assertIn("git ls-files -z '*.rs' > \"$RUNNER_TEMP/rust-files\"", job)
        self.assertIn('test -s "$RUNNER_TEMP/rust-files"', job)
        self.assertIn('xargs -0 -a "$RUNNER_TEMP/rust-files" \\\n            rustup run "$STABLE" rustfmt --check', job)
        self.assertNotIn("cargo", job)
        self.assertEqual(job.count("exec timeout --kill-after=30s 5m"), 2)
        self.assertNotIn("$NIGHTLY", job)
        self.assertNotIn("rust-lane.sh toolchains", job)
        self.assertIn("persist-credentials: false", job)

    def test_closed_signal_matches_pr_group_without_running_a_job_or_gate(self):
        text = (ROOT / ".github/workflows/agent-checks-cancel-closed.yml").read_text()
        header, jobs = text.split("\njobs:\n", 1)
        self.assertIn("on:\n  pull_request:\n    types: [closed]", header)
        for trigger in ("pull_request_target:", "push:", "schedule:", "workflow_dispatch:"):
            self.assertNotIn(trigger, header)
        self.assertIn("permissions: {}", header)
        self.assertIn("group: agent-checks-pull_request-${{ github.event.pull_request.number }}", header)
        self.assertIn("cancel-in-progress: true", header)
        self.assertRegex(WORKFLOW.read_text(), r"^name: agent-checks\n")
        self.assertEqual(re.findall(r"(?m)^  ([\w-]+):", jobs), ["agent-checks-close-signal"])
        self.assertIn("if: github.event.action != 'closed'", jobs)
        self.assertIn("runs-on: ubuntu-latest", jobs)
        self.assertIn('      - run: ":"', jobs)
        for forbidden in ("uses:", "secrets.", "self-hosted", "rust-gate:", "    concurrency:", "    permissions:"):
            self.assertNotIn(forbidden, text)
        self.assertNotIn("closed", WORKFLOW.read_text().split("\njobs:\n", 1)[0])


if __name__ == "__main__":
    unittest.main()
