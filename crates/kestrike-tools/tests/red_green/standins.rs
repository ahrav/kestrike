//! The stand-ins the real runner starts in a leg: a test executable and a `cargo`, each Python text
//! that reads the leg's plan, and a stub runner that wraps the real runner. The test executable lists the test only when the carried
//! `table_tests.rs` is in its working directory; by default an attempt passes when `fix.marker` is there
//! and fails with the expected text otherwise, and a `plan.json` entry for the leg, named by the worktree
//! directory, sets another outcome.

use super::support::{EXPECT, FAILED, PASSED};

const EXECUTABLE: &str = r#"#!/usr/bin/env python3
import json, os, signal, subprocess, sys, time
from pathlib import Path
state = Path(os.environ["FAKE_STATE"])
tree = Path.cwd()
leg = json.loads((state / "plan.json").read_text()).get(tree.name, {})
test = sys.argv[sys.argv.index("--exact") + 1]
(state / f"{tree.name}.pid").write_text(str(os.getppid()))
if "--list" in sys.argv:
    files = {}
    for directory, _, names in os.walk(tree):
        for name in names:
            if name != ".git":
                path = Path(directory, name)
                files[str(path.relative_to(tree))] = path.read_text(errors="surrogateescape")
    (state / f"{tree.name}-tree.json").write_text(json.dumps(files))
    listed = (tree / "table_tests.rs").exists() and "--ignored" not in sys.argv
    print(f"{test}: test" if listed else "")
    sys.exit(0)
outcome = leg.get("attempt") or ("pass" if (tree / "fix.marker").exists() else "fail")
print("running 1 test", flush=True)
if outcome in ("hang", "stubborn"):
    if outcome == "stubborn":
        signal.signal(signal.SIGTERM, signal.SIG_IGN)
    (state / "supervised.pid").write_text(str(os.getpid()))
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    (state / "grandchild.pid.new").write_text(str(child.pid))
    (state / "grandchild.pid.new").rename(state / "grandchild.pid")
    time.sleep(600)
if outcome == "crash":
    os.kill(os.getpid(), signal.SIGSEGV)
if outcome.endswith("-receipt"):
    receipt = Path(os.readlink("/proc/self/fd/1")).parents[1] / "receipt.json"
    if outcome == "block-receipt":
        receipt.mkdir()
    elif outcome == "file-receipt":
        receipt.write_text("planted\n")
    else:
        receipt.symlink_to(state / "planted.txt")
    outcome = "pass"
if outcome == "pass":
    print(f"test {test} ... ok\n\nPASSED_LINE")
    sys.exit(0)
if outcome == "stderr-text":
    print(f"thread '{test}' (4242) panicked at stderr_fixture.rs:1:1:\nEXPECT_PLAIN", file=sys.stderr)
text = {"other-text": "assertion failed: the counters moved",
        "stderr-text": "assertion failed: the counters moved",
        "should-panic": "note: panic did not contain expected string\n      panic message: \"the counters moved\"\n"
                        " expected substring: \"zzz\"",
        "non-string": "Box<dyn Any>\nnote: expected panic with string value,\n found non-string value: "
                      "`TypeId(0x1)`\n     expected substring: \"zzz\"",
        "test-message": "test fixture lost a completion",
        "adjacent": "first payload line\nsecond payload line",
        "split": "first payload line\nnote: run with the payload split\nsecond payload line",
        "no-panic": "note: test did not panic as expected at table_tests.rs:9:5"}.get(outcome, EXPECT_TEXT)
kind = " - should panic" if outcome in ("should-panic", "non-string", "no-panic") else ""
print(f"test {test}{kind} ... FAILED\n\nfailures:\n\n---- {test} stdout ----\n\n"
      f"thread '{test}' (4242) panicked at table_tests.rs:9:5:\n{text}\n"
      "note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace\n"
      "note: Some details are omitted, run with `RUST_BACKTRACE=full` for a verbose backtrace.\n"
      "stack backtrace:\n   0: table_tests::frame\n             at ./table_tests.rs:9:5\n\n"
      f"\nfailures:\n    {test}\n\nFAILED_LINE")
sys.exit(101)
"#;

pub const CARGO: &str = r#"#!/usr/bin/env python3
import fcntl, json, os, subprocess, sys, time
from pathlib import Path
state = Path(os.environ["FAKE_STATE"])
tree = Path.cwd()
leg = json.loads((state / "plan.json").read_text()).get(tree.name, {})
if sys.argv[1:] == ["-V"]:
    print("cargo 1.99.0 (5f94df478 2026-08-27)")
    sys.exit(0)
if sys.argv[1:2] == ["metadata"]:
    print(json.dumps({"packages": [
        {"name": name, "version": "0.1.0", "manifest_path": str(tree / "Cargo.toml")}
        for name in ("kestrike", "fixture-pkg")
    ]}))
    sys.exit(leg.get("metadata_exit", 0))
(state / f"{tree.name}.pid").write_text(str(os.getppid()))
with open(Path(os.environ["CARGO_TARGET_DIR"]) / "red-green.lock", "a") as probe:
    try:
        fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held = False
    except BlockingIOError:
        held = True
with (state / "builds.txt").open("a") as out:
    out.write(json.dumps({"leg": tree.name, "argv": sys.argv[1:], "lock_held": held, "stdin": sys.stdin.read(),
                          "target_dir": os.environ.get("CARGO_TARGET_DIR"),
                          "build_dir": os.environ.get("CARGO_BUILD_BUILD_DIR")}) + "\n")
if leg.get("replace"):
    Path(leg["replace"]).write_text("import sys\nprint('Traceback (most recent call last): replaced')\nsys.exit(1)\n")
if leg.get("build_hang"):
    (state / "supervised.pid").write_text(str(os.getpid()))
    child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
    (state / "grandchild.pid.new").write_text(str(child.pid))
    (state / "grandchild.pid.new").rename(state / "grandchild.pid")
    time.sleep(600)
if leg.get("build_exit"):
    print("error: could not compile", file=sys.stderr)
    sys.exit(leg["build_exit"])
target = ({"name": sys.argv[sys.argv.index("--test") + 1], "kind": ["test"]} if "--test" in sys.argv
          else {"name": "kestrike", "kind": ["lib"]})
print(json.dumps({"reason": "compiler-artifact", "target": target,
                  "profile": {"test": True}, "executable": str(state / "kestrike")}))
"#;

/// The stub runner loads the real runner at `REAL` and, by the leg's `stub` mode, stops at once or runs
/// the real runner and changes what it printed or left: no verdict, no announcement, no stderr file,
/// an announcement of the base leg's artifact, or, in the mode `fifo`, the artifact moved aside and a
/// named pipe in its place that [`FEEDER`] fills once the runner has exited.
const STUB_RUNNER: &str = r#"import importlib.util, json, os, subprocess, sys
from pathlib import Path
FEEDER = FEEDER_TEXT
spec = importlib.util.spec_from_file_location("real_runner", REAL)
real = importlib.util.module_from_spec(spec)
spec.loader.exec_module(real)
globals().update({name: value for name, value in vars(real).items() if not name.startswith("__")})
if __name__ == "__main__":
    plan = json.loads((Path(os.environ["FAKE_STATE"]) / "plan.json").read_text())
    mode = plan.get(Path.cwd().name, {}).get("stub", "stop")
    if mode == "stop":
        print("Traceback (most recent call last): the runner stopped")
        sys.exit(1)
    done = subprocess.run([sys.executable, REAL, *sys.argv[1:]], capture_output=True, text=True)
    out, err = done.stdout, done.stderr
    own = Path([line for line in err.splitlines() if line.startswith("artifact: ")][-1].split(": ", 1)[1])
    if mode == "no-verdict":
        out = ""
    if mode == "no-artifact":
        err = "".join(line for line in err.splitlines(True) if not line.startswith("artifact: "))
    if mode == "no-stderr":
        own.with_name("attempt-1.stderr").unlink()
    if mode == "other-leg":
        [base] = own.parent.parent.glob("*-base")
        err += f"artifact: {base / 'artifact.json'}\n"
    if mode == "fifo":
        held = own.with_name("artifact.held")
        own.rename(held)
        os.mkfifo(own)
        marker = Path(os.environ["FAKE_STATE"]) / f"{Path.cwd().name}-fed"
        subprocess.Popen([sys.executable, "-c", FEEDER, str(own), str(held), str(os.getppid()), str(marker)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    sys.stdout.write(out)
    sys.stderr.write(err)
    sys.exit(done.returncode)
"#;

/// The feeder takes the named pipe, the artifact's bytes beside it, the tool's process ID and a marker
/// path. Once the tool has opened the pipe to read the artifact, it sends the tool SIGTERM and creates
/// `MARKER.sent`, then writes the bytes, closes the pipe and creates `MARKER.written`; a write the tool
/// no longer reads fails and leaves no `MARKER.written`.
const FEEDER: &str = r#"
import errno, os, signal, sys, time
fifo, held, tool, marker = sys.argv[1:]
data = open(held, "rb").read()
deadline = time.monotonic() + 60
while True:
    try:
        fd = os.open(fifo, os.O_WRONLY | os.O_NONBLOCK)
        break
    except OSError as error:
        if error.errno != errno.ENXIO or time.monotonic() > deadline:
            raise
        time.sleep(0.01)
os.kill(int(tool), signal.SIGTERM)
open(marker + ".sent", "w").close()
time.sleep(0.2)
os.set_blocking(fd, True)
view = memoryview(data)
while view:
    view = view[os.write(fd, view):]
os.close(fd)
open(marker + ".written", "w").close()
"#;

/// `executable` is the test executable's text, with the result lines and the expected text set in.
pub fn executable() -> String {
    EXECUTABLE
        .replace("PASSED_LINE", PASSED)
        .replace("FAILED_LINE", FAILED)
        .replace("EXPECT_TEXT", &format!("'{EXPECT}'"))
        .replace("EXPECT_PLAIN", EXPECT)
}

/// `stub_runner` is the stub runner's text, loading the real runner at `real`.
pub fn stub_runner(real: &std::path::Path) -> String {
    STUB_RUNNER
        .replace("FEEDER_TEXT", &format!("{FEEDER:?}"))
        .replace("REAL", &format!("'{}'", real.display()))
}
