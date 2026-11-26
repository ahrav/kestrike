#!/usr/bin/env python3
"""Check the patched GenMC checker's identity and credit its runs only from complete, matching results.

Usage:
  judge-genmc.py options
  judge-genmc.py identity --toolchain PREFIX --evidence DIR
  judge-genmc.py cases --profile pr|scheduled
  judge-genmc.py config --evidence DIR
  judge-genmc.py judge --profile pr|scheduled --evidence DIR [--revision SHA]

The declaration is the committed `verification/genmc/expected.json`: the
upstream GenMC commit, the LLVM version, the rustc release, commit and LLVM
version, the options every run passes, the standalone package, per case
whether it must complete positively or report one violation at one of its
named checks,
and two profiles. A `pr` run judges the `pr` cases; a `scheduled` run judges
those and the `scheduled` cases, the two-reader grace domain. `options` and
`cases` print the options and a profile's cases one per line for the lane.

`identity` reads `PREFIX/identity.json`, which `verification/genmc/provision.sh`
writes, and refuses a toolchain whose upstream commit, LLVM or rustc differs
from the declaration, whose recorded patch or recipe digests differ from the
committed `verification/genmc/patches/*.patch` and `provision.sh`, or whose
genmc binary, the shared libLLVM it loads, the toolchain's rustc binary, or
the shipped `genmc-std` tree changed since it was built; the rustc at the
recorded toolchain path must also report the declared release, commit and
LLVM version to `-vV`. The libLLVM check asks the loader (`ldd`) which
copy the binary binds under the lane's environment and requires it to be the
recorded path with the recorded digest. It copies the identity into the
evidence directory and writes `pins.txt`.

`config` checks `DIR/cargo-config.json` against the same rules as `judge`.
It writes no files and exits 0 on success or 2 with the refusal on stderr.

`judge` repeats the identity check on the evidence directory's copy of the
identity and refuses a recorded `cargo-config.json` (the merged cargo file
configuration under the package) whose `build`, `profile`, `target`,
`unstable`, `patch` or `source` entries or `CASE`, `RUST*` or `CARGO*`
`[env]` entries shape the build. It admits one `target` table: the one in
the repository's `.cargo/config.toml`, which adds `-C target-feature=+lse` as
`rustflags` and `rustdocflags` for aarch64 and nothing else; GenMC's own
build of the kernels sets `RUSTFLAGS`, which replaces that table's flags for
the bitcode it checks. It reads, per
case of its profile, `genmc-<case>.argv` (the command, one argument per
line), `genmc-<case>.env`
(the case, the rustup toolchain, the toolchain's rustc as `RUSTC` and empty
`RUSTC_WRAPPER` and `RUSTC_WORKSPACE_WRAPPER`),
`genmc-<case>.txt` (its output) and `genmc-<case>.exit`, and for a case that
declares intrinsics `genmc-<case>.intrinsics`, the intrinsics called in the
bitcode GenMC linked for the case, which must equal the declared set. The
command must be the identified genmc with exactly the declared options, the
case's own `--dump-error-graph` file and the manifest of the case's own copy
of the package beside it, both compared after resolving symlinks and the
evidence directory's own spelling.
The output must show a completed compilation and transformation. A positive
needs exit 0, one `*** Verification complete.`, `No errors were detected.`,
a complete-execution count above zero and no blocked executions, since a
blocked execution is one the search pruned. A violation needs exit 42, one
`Error: Safety violation!`, exactly one `ERROR file:line` event at the line
of a `check!` invocation that carries one of the declared messages,
`*** Verification unsuccesful.`, no `*** Verification complete.` or `No
errors were detected.` line, and a graph whose events are the ones the run
printed, thread ends and blocked joins aside, which the dumped graph draws
for some threads only, and whose one ERROR node is the reported event, so a graph copied from
another run is refused. Exit 42 without the matching event earns
nothing, and a positive never comes from exit 42. An interrupted run (124,
130, 143) is a timeout; an unsupported intrinsic, an unevaluable constant, an
LLVM or interpreter abort, or a missing, repeated or extra line is a tool
failure. GenMC runs here without exploration bounds or loop unrolling
options, so its counts are complete searches. Outputs for cases outside the
profile are refused, so a PR run never stands in for the scheduled domain.
Each case names the RC11 litmus tests that encode its strength: a positive's
must all be declared `Never` and a violation's all `Sometimes`, so the GenMC
and herd7 declarations agree.

Before any case is adjudicated, `judge` checks the declaration's
`bindings`: each entry names one operation on its production side, its
kernel side or both, a production operation a kernel copies, a sequence or
bucket access its stand-ins assume, or a kernel order a stand-in requires,
by kind, operands and success and failure orderings, and per side its file,
nested scope, callee and the entries or text it must precede or follow
there. The operation must occur exactly once in its scope on each side and
match the entry, and every ordering of each kernel strength the
declaration's `strengths` names must be bound. A mismatch refuses as
correspondence drift, its own verdict, before the judge reads any case
result, so positive, violation and redundant control outcomes are
adjudicated only over a kernel whose bindings all resolve.

`judge` writes `report.json` and a receipt for `verify-receipts.py credit
--receipt`, binding the digests of every input the judgment read: the
evidence, the declaration, the recipe and patches, the kernel package with
the production sources it includes, and the production sources the
declaration's `transcribed` list names, whose orderings a kernel copies
rather than includes. `derive` is the same judgment without the writes;
`credit` calls it to require an imported receipt to equal the one its
evidence derives. Exit 0 credits, 1 is an outcome mismatch, 2 is a tool
failure or correspondence drift, 3 is an interrupted run. An argument error
exits 2 without a report, and so does an input the receipt cannot hash or
read. A report or receipt the judge cannot write also exits 2. The receipt
records `pins.txt` as UTF-8, with a replacement character for each
undecodable byte.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from collections import namedtuple
from functools import cache, partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "verification/genmc/expected.json"
RECIPE = ROOT / "verification/genmc/provision.sh"
PATCHES = ROOT / "verification/genmc/patches"
LITMUS = ROOT / "verification/rc11/expected.json"


def load_rc11():
    spec = importlib.util.spec_from_file_location("judge_rc11", ROOT / "scripts/judge-rc11.py")
    if spec is None or spec.loader is None:
        raise SystemExit("judge-genmc: scripts/judge-rc11.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rc11 = load_rc11()
Refusal, sha256, read_json, single = rc11.Refusal, rc11.sha256, rc11.read_json, rc11.single
CREDITED, MISMATCH, TOOL_FAILURE, INCOMPLETE = rc11.CREDITED, rc11.MISMATCH, rc11.TOOL_FAILURE, rc11.INCOMPLETE
VERDICTS = rc11.VERDICTS
ABORTS = re.compile(
    r"does not support intrinsic|Constant unimplemented|LLVM ERROR|Assertion `|Aborted|Segmentation fault"
    r"|terminate called|internal error|unsupported",
    re.I,
)
ERROR_EVENT = re.compile(r"^\((\d+), (\d+)\): ERROR (\S+):(\d+)$")
# A thread's end and a blocked join are left out of both event sets: the
# dumped error graph draws a thread's end only for some threads, and a
# blocked join never.
GRAPH_EVENT = re.compile(r'^\s*"\((\d+), (\d+)\)" \[label=(?!<THREAD_END|<BLOCK)', re.M)
GRAPH_ERROR = re.compile(r'^\s*"\((\d+), (\d+)\)" \[label=<ERROR <FONT COLOR="gray"> (\S+):(\d+)</FONT>>', re.M)
TEXT_EVENT = re.compile(r"^\s*\((\d+), (\d+)\): (?!THREAD_END|BLOCK)", re.M)
INCLUDED = re.compile(r'^\s*#\[path = "([^"]+)"\]', re.M)


# The same digest as verification/genmc/provision.sh's tree(), which records it.
def tree(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in Path(root).rglob("*") if p.is_file() and "target" not in p.relative_to(root).parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + sha256(path).encode() + b"\n")
    return digest.hexdigest()


# The recorded path stays intact while LD_LIBRARY_PATH or the loader cache
# binds the binary to another copy, so admission asks the loader.
# The same fields provision.sh records from `rustc -vV`, read from the binary
# the lane is about to run.
def rustc_identity(compiler):
    try:
        output = subprocess.run([str(compiler), "-vV"], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refusal(TOOL_FAILURE, f"rustc -vV failed for {compiler}: {error}") from error
    fields = dict(line.split(": ", 1) for line in output.splitlines() if ": " in line)
    return {"release": fields.get("release"), "commit": fields.get("commit-hash"), "llvm": fields.get("LLVM version")}


def loaded_llvm(binary):
    try:
        listing = subprocess.run(["ldd", str(binary)], capture_output=True, text=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refusal(TOOL_FAILURE, f"ldd cannot list what {binary} loads: {error}") from error
    for line in listing.splitlines():
        name, _, target = line.strip().partition(" => ")
        if name.startswith("libLLVM") and target.rsplit(" (", 1)[0]:
            return Path(target.rsplit(" (", 1)[0]).resolve()
    raise Refusal(TOOL_FAILURE, f"{binary} loads no libLLVM")


def check_identity(expected, record):
    """Refuse a recorded toolchain identity that differs from the declaration or whose files changed since the recipe built them."""
    if record.get("upstream") != expected["upstream"]:
        raise Refusal(TOOL_FAILURE, f"the toolchain builds GenMC {record.get('upstream')}, declared {expected['upstream']}")
    if record.get("llvm") != expected["llvm"]:
        raise Refusal(TOOL_FAILURE, f"the toolchain links LLVM {record.get('llvm')}, declared {expected['llvm']}")
    rustc = {key: (record.get("rustc") or {}).get(key) for key in expected["rustc"]}
    if rustc != expected["rustc"]:
        raise Refusal(TOOL_FAILURE, f"the toolchain's rustc {rustc} differs from the declared {expected['rustc']}")
    if not all(isinstance(record["rustc"].get(key), str) for key in ("name", "toolchain")):
        raise Refusal(TOOL_FAILURE, "the toolchain's rustc names no rustup toolchain")
    compiler = Path(record["rustc"]["toolchain"]) / "bin/rustc"
    if not compiler.is_file() or sha256(compiler) != record["rustc"].get("sha256"):
        raise Refusal(TOOL_FAILURE, "the rustc binary changed since the recipe recorded it")
    reported = rustc_identity(compiler)
    if reported != expected["rustc"]:
        raise Refusal(TOOL_FAILURE, f"rustc now reports {reported}, declared {expected['rustc']}")
    if not isinstance(record.get("cxx"), str) or not record["cxx"]:
        raise Refusal(TOOL_FAILURE, "the toolchain records no C++ compiler")
    patches = {path.name: sha256(path) for path in sorted(PATCHES.glob("*.patch"))}
    if record.get("patches") != patches:
        raise Refusal(TOOL_FAILURE, "the toolchain was built with patches other than the committed ones")
    if record.get("recipe") != sha256(RECIPE):
        raise Refusal(TOOL_FAILURE, "the toolchain was built by another revision of provision.sh")
    binary = record.get("binary") or {}
    if not Path(binary.get("path", "")).is_file() or sha256(binary["path"]) != binary.get("sha256"):
        raise Refusal(TOOL_FAILURE, "the genmc binary changed since the recipe built it")
    library = record.get("libllvm") or {}
    if not Path(library.get("path", "")).is_file() or sha256(library["path"]) != library.get("sha256"):
        raise Refusal(TOOL_FAILURE, "the libLLVM genmc loads changed since the recipe built it")
    loaded = loaded_llvm(binary["path"])
    if loaded != Path(library["path"]).resolve():
        raise Refusal(TOOL_FAILURE, f"genmc now loads {loaded}, recorded {library['path']}")
    std = record.get("genmc_std") or {}
    if not Path(std.get("path", "")).is_dir() or tree(std["path"]) != std.get("tree"):
        raise Refusal(TOOL_FAILURE, "the shipped genmc-std changed since the recipe built it")


def identity(args):
    expected = read_json(EXPECTED)
    record = read_json(Path(args.toolchain) / "identity.json")
    check_identity(expected, record)
    binary, library, std = record["binary"], record["libllvm"], record["genmc_std"]
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    lines = [
        f"- GenMC {record['upstream']}; genmc sha256 {binary['sha256']}; built by {record['cxx']}",
        f"- recipe sha256 {record['recipe']}; genmc-std tree {std['tree']}",
        *(f"- patch {name} sha256 {digest}" for name, digest in record["patches"].items()),
        f"- LLVM {record['llvm']}; {library['path']} sha256 {library['sha256']}; {record['clang']}",
        f"- rustc {record['rustc']['release']} {record['rustc']['commit']} (LLVM {record['rustc']['llvm']})",
    ]
    (evidence / "pins.txt").write_text("\n".join(lines) + "\n")
    print(json.dumps({"identity": str(evidence / "identity.json")}))
    return CREDITED


# Configuration tables and `[env]` entries that select the compiler, its flags,
# the target, the profile, the dependency sources or the case built.
SHAPING_TABLES = ("profile", "target", "unstable", "patch", "source")
SHAPING_BUILD_KEYS = ("rustc", "rustc-wrapper", "rustc-workspace-wrapper", "target", "target-dir", "build-dir", "rustflags",
                      "rustdocflags")
SHAPING_ENV_PREFIXES = ("CASE", "RUST", "CARGO")
# The one `target` table the configuration may hold: the repository's
# `.cargo/config.toml`, which enables LSE atomics for aarch64 builds.
LSE_FLAGS = ["-C", "target-feature=+lse"]
ADMITTED_TARGET = {'cfg(target_arch = "aarch64")': {"rustflags": LSE_FLAGS, "rustdocflags": LSE_FLAGS}}


def check_config(evidence):
    """Refuse a recorded cargo configuration with an entry that shapes the kernels' build.

    A `target` table whose parsed value equals `ADMITTED_TARGET` is the one exception; every other `target`
    value, and every other shaping entry beside the admitted table, is still refused.
    """
    path = evidence / "cargo-config.json"
    if not path.is_file():
        raise Refusal(TOOL_FAILURE, "the lane left no recorded cargo configuration")
    try:
        config = json.loads(path.read_text(encoding="utf-8"))
    except RecursionError as error:
        raise Refusal(TOOL_FAILURE, f"malformed evidence: {error!r}") from error
    except ValueError as error:
        raise Refusal(TOOL_FAILURE, f"the recorded cargo configuration is unreadable: {error}") from error
    if not isinstance(config, dict):
        raise Refusal(TOOL_FAILURE, "the recorded cargo configuration is not a table")
    for key in ("build", "env"):
        if key in config and not isinstance(config[key], dict):
            raise Refusal(TOOL_FAILURE, f"malformed evidence: the recorded cargo configuration's {key} is not a table")
    entries = [table for table in SHAPING_TABLES
               if table in config and not (table == "target" and config[table] == ADMITTED_TARGET)]
    entries += [f"build.{key}" for key in SHAPING_BUILD_KEYS if key in (config.get("build") or {})]
    entries += [f"env.{name}" for name in sorted(config.get("env") or {}) if name.startswith(SHAPING_ENV_PREFIXES)]
    if entries:
        raise Refusal(TOOL_FAILURE, f"the cargo configuration sets {', '.join(entries)}")


def check_line(declared, message):
    """Return the line of the `check!` invocation that carries `message`, where its error is reported."""
    source = (ROOT / read_json(EXPECTED)["package"] / declared["file"]).read_text(encoding="utf-8").splitlines()
    lines = [number for number, text in enumerate(source, 1) if f'c"{message}"' in text]
    if len(lines) != 1:
        raise Refusal(TOOL_FAILURE, f"the check {message!r} appears {len(lines)} times in {declared['file']}")
    starts = [number for number in range(lines[0], 0, -1) if "check!(" in source[number - 1]]
    if not starts:
        raise Refusal(TOOL_FAILURE, f"the message {message!r} sits in no check! invocation")
    return starts[0]


def check_graph(name, text, graph, event, where):
    """Refuse a graph other than the one this run reported: its events must be the reported graph's, its one ERROR node the reported event."""
    if not graph.is_file() or graph.stat().st_size == 0:
        raise Refusal(TOOL_FAILURE, f"{name} left no error graph")
    dot = graph.read_text(encoding="utf-8", errors="replace")
    errors = GRAPH_ERROR.findall(dot)
    if errors != [(*event, where[0], str(where[1]))]:
        raise Refusal(TOOL_FAILURE, f"{name}'s graph marks errors {errors}, the run reported {event} at {where[0]}:{where[1]}")
    if set(GRAPH_EVENT.findall(dot)) != set(TEXT_EVENT.findall(text.partition("Error: Safety violation!")[2])):
        raise Refusal(TOOL_FAILURE, f"{name}'s graph holds other events than the run reported")


def check_command(name, expected, record, argv, env, evidence):
    graph, manifest = (evidence / f"genmc-{name}.dot").resolve(), ROOT / Path(expected["package"]).parent / f"run-{name}" / "Cargo.toml"
    option = "--dump-error-graph="
    if (
        len(argv) < 2 or argv[:-2] != [record["binary"]["path"], *expected["options"]]
        or not argv[-2].startswith(option) or Path(argv[-2].removeprefix(option)).resolve() != graph
        or Path(argv[-1]).resolve() != manifest
    ):
        raise Refusal(TOOL_FAILURE, f"{name} ran {argv}, not genmc {' '.join(expected['options'])} {option}{graph} {manifest}")
    pinned = {"CASE": name, "RUSTUP_TOOLCHAIN": record["rustc"]["name"], "RUSTC": f"{record['rustc']['toolchain']}/bin/rustc",
              "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}
    if env != pinned:
        raise Refusal(TOOL_FAILURE, f"{name} ran with {env}, not {pinned}")


def judge_case(name, declared, text, exit_code, graph, intrinsics):
    """Return the result of one complete case run that matches its declaration."""
    if exit_code in rc11.INTERRUPTED:
        raise Refusal(INCOMPLETE, f"{name} was interrupted (exit {exit_code})", "timeout")
    if "intrinsics" in declared and intrinsics != sorted(declared["intrinsics"]):
        raise Refusal(TOOL_FAILURE, f"{name}'s bitcode calls {intrinsics}, declared {sorted(declared['intrinsics'])}")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    aborts = [line for line in lines if ABORTS.search(line)]
    if aborts:
        raise Refusal(TOOL_FAILURE, f"{name} aborted: {aborts[0]!r}")
    single(lines, r"^\*\*\* Compilation complete\.$", name, "compilation")
    single(lines, r"^\*\*\* Transformation complete\.$", name, "transformation")
    executions = int(single(lines, r"^Number of complete executions explored: (\d+)$", name, "execution count").group(1))
    errors = [match for match in map(ERROR_EVENT.match, lines) if match]
    if declared["expect"] == "positive":
        if exit_code != 0:
            raise Refusal(MISMATCH if exit_code == 42 else TOOL_FAILURE, f"{name} exited {exit_code}, declared positive")
        single(lines, r"^\*\*\* Verification complete\.$", name, "Verification complete")
        single(lines, r"^No errors were detected\.$", name, "No errors")
        if errors or any(line.startswith("Error:") for line in lines):
            raise Refusal(TOOL_FAILURE, f"{name} reports an error beside exit 0")
        if executions == 0:
            raise Refusal(MISMATCH, f"{name} explored no complete execution")
        blocked = [line for line in lines if line.startswith("Number of blocked executions seen:")]
        if blocked:
            raise Refusal(MISMATCH, f"{name} pruned executions: {blocked[0]!r}")
        return {"result": "positive", "executions": executions}
    if exit_code != 42:
        raise Refusal(MISMATCH if exit_code == 0 else TOOL_FAILURE, f"{name} exited {exit_code}, declared a violation")
    single(lines, r"^Error: Safety violation!$", name, "Safety violation")
    single(lines, r"^\*\*\* Verification unsuccesful\.$", name, "Verification unsuccesful")
    for pattern, what in ((r"^\*\*\* Verification complete\.$", "Verification complete"), (r"^No errors were detected\.$", "No errors")):
        successes = [line for line in lines if re.match(pattern, line)]
        if successes:
            raise Refusal(TOOL_FAILURE, f"{name} prints {len(successes)} {what} lines beside a violation")
    if len(errors) != 1:
        raise Refusal(TOOL_FAILURE, f"{name} reports {len(errors)} ERROR events")
    event, where = errors[0].group(1, 2), (errors[0].group(3), int(errors[0].group(4)))
    wanted = [(Path(declared["file"]).name, check_line(declared, message)) for message in declared["checks"]]
    if where not in wanted:
        accepted = ", ".join(f"{file}:{line}" for file, line in wanted)
        raise Refusal(MISMATCH, f"{name} failed at {where[0]}:{where[1]}, declared {accepted}")
    check_graph(name, text, graph, event, where)
    return {"result": "violation", "at": f"{where[0]}:{where[1]}", "executions": executions}


def profile_cases(expected, profile):
    """Return the cases a run of `profile` judges: the PR cases, and for another profile also its own."""
    if profile not in expected["profiles"]:
        raise Refusal(TOOL_FAILURE, f"profile {profile!r} is not declared")
    return sorted(set(expected["profiles"]["pr"]) | set(expected["profiles"][profile]))


def check_correspondence(expected):
    """Refuse a declaration whose cases disagree with the RC11 litmus tests they name.

    Every case names its litmus tests, an empty list when no test encodes
    it. A positive case's tests must all be declared `Never` and a
    violation's all `Sometimes`, so a GenMC result that disagrees with
    herd7 fails one of the two judges.
    """
    declared = read_json(LITMUS)["tests"]
    for name, case in sorted(expected["cases"].items()):
        if not isinstance(case.get("litmus"), list):
            raise Refusal(TOOL_FAILURE, f"{name} names no litmus list")
        outcomes = [declared.get(test, {}).get("outcome") for test in case["litmus"]]
        if None in outcomes:
            raise Refusal(TOOL_FAILURE, f"{name} names an undeclared litmus test among {case['litmus']}")
        wanted = "Never" if case["expect"] == "positive" else "Sometimes"
        agree = all(outcome == wanted for outcome in outcomes)
        if not agree:
            raise Refusal(TOOL_FAILURE, f"{name} is declared {case['expect']} and its litmus tests {case['litmus']} are {outcomes}")


DRIFT = "correspondence drift"


class Drift(Refusal):
    """A kernel's transcription disagrees with the production operation a binding entry names.

    Drift is its own result class: it refuses before any case is
    adjudicated, so every GenMC outcome the judge reads, positive,
    violation or redundant control, comes from a kernel whose bindings all
    resolve.
    """

    def __init__(self, drift):
        super().__init__(TOOL_FAILURE, f"{DRIFT}: " + "; ".join(drift), DRIFT)


KINDS = {
    "load": lambda method: method == "load",
    "store": lambda method: method == "store",
    "rmw": lambda method: method == "swap" or method.startswith("fetch_"),
    "cas": lambda method: method in ("compare_exchange", "compare_exchange_weak", "fetch_update", "try_update"),
    "fence": lambda method: method in ("fence", "$fence", "fence_release"),
    "call": lambda method: True,
}
ORDERING = re.compile(r"^(?:\w+::)*Ordering::(\w+)$")
STRENGTH = re.compile(r"^S::(\w+)$")
Located = namedtuple("Located", "scope offset operands orderings constants")
LEXEME_TEXT = {"comment": " ", "unclosed": " ", "string": '""', "char": "''"}


def code(text):
    """`text` with each comment, a nested block comment whole, as one space, each string literal as `""` after any
    `b` or `c` prefix and each char literal as `''`, so a delimiter inside a literal never closes a scope or an
    argument list. A lifetime stays in the code, and a block comment that never closes runs to the end of `text`."""
    pieces, index = [], 0
    for kind, start, end in rc11.rust_lexemes(text):
        pieces += [text[index:start], LEXEME_TEXT[kind]]
        index = end
    pieces.append(text[index:])
    return "".join(pieces)


def normalized(text):
    """`code(text)` with whitespace kept only between two identifier characters, one space wide."""
    text = re.sub(r"\s+", " ", code(text))
    return re.sub(r" ?([^\w ]) ?", r"\1", text).strip()


def bodies(text, header):
    """The `{...}` bodies of the items in `text` whose header is `header`; a header ending in `;` has none."""
    found = []
    for match in re.finditer(r"(?<![\w.])" + re.escape(header) + r"(?!\w)", text):
        index = match.end()
        while index < len(text) and text[index] not in "{;":
            index += 1
        if index == len(text) or text[index] == ";":
            continue
        depth = 0
        for end in range(index, len(text)):
            depth += {"{": 1, "}": -1}.get(text[end], 0)
            if depth == 0:
                found.append(text[index:end + 1])
                break
    return found


def arguments(text, start):
    """The top-level comma-separated arguments of the call whose `(` is at `start`, or None if it never closes."""
    depth, args, begun = 0, [], start + 1
    for index in range(start, len(text)):
        if text[index] in "([{":
            depth += 1
        elif text[index] in ")]}":
            depth -= 1
            if depth == 0:
                args.append(text[begun:index])
                return [arg for arg in args if arg]
        elif text[index] == "," and depth == 1:
            args.append(text[begun:index])
            begun = index + 1
    return None


def strengths(declared, source):
    """The pair (each declared kernel file's strength orderings by constant name, a drift line per declared impl
    that the file holds other than exactly once). `source(path)` returns the file's normalized text."""
    found, drift = {}, []
    for strength in declared.get("strengths", []):
        path = str(Path(declared["package"]) / strength["file"])
        blocks = bodies(source(path), normalized(strength["impl"]))
        if len(blocks) != 1:
            drift.append(f"{strength['file']} declares {strength['impl']} {len(blocks)} times")
            continue
        found[path] = dict(re.findall(r"const (\w+):Ordering=Ordering::(\w+);", blocks[0]))
    return found, drift


def locate(entry, side, site, source, strength):
    """Find `site`'s operation in its scope: (None, Located) or (a drift, None).

    `source(path)` returns the file's normalized text. The scope must hold
    the callee exactly `among` times and exactly `matching` of those
    occurrences must carry the bound operands, one each by default; the
    site is the first matching occurrence.
    """
    where = " > ".join(site["scope"]) or "the file"
    scopes = [source(site["file"])]
    for header in site["scope"]:
        scopes = [body for scope in scopes for body in bodies(scope, normalized(header))]
    if len(scopes) != 1:
        return f"{entry['id']}: the {side} scope {where} in {site['file']} appears {len(scopes)} times", None
    scope, call, bound = scopes[0], normalized(site["call"]), [normalized(text) for text in site.get("operands") or entry["operands"]]
    found = [match.end() - 1 for match in re.finditer(r"(?<![\w.$])" + re.escape(call) + r"(?:::<[^>]*>)?\(", scope)]
    if len(found) != site.get("among", 1):
        return f"{entry['id']}: the {side} {site['call']} appears {len(found)} times in {where}", None
    candidates = []
    for offset in found:
        operands, orderings, constants = [], [], set()
        for arg in arguments(scope, offset) or []:
            ordering, constant = ORDERING.match(arg), STRENGTH.match(arg)
            if ordering:
                orderings.append(ordering.group(1))
            elif constant and side == "kernel":
                if strength is None or constant.group(1) not in strength:
                    return f"{entry['id']}: the kernel names {arg}, which no declared strength of {site['file']} defines", None
                orderings.append(strength[constant.group(1)])
                constants.add(constant.group(1))
            else:
                operands.append(arg)
        candidates.append(Located(scope, offset, operands, orderings, constants))
    matching = [located for located in candidates if located.operands == bound]
    if len(matching) != site.get("matching", 1):
        found_operands = [located.operands for located in candidates]
        return f"{entry['id']}: the {side} {site['call']} operands are {found_operands}, bound {bound}", None
    return None, matching[0]


def transcription_drift(declared, read):
    """Where a kernel transcription and the production operation its binding entry names disagree.

    Each entry of the declaration's `bindings` names one operation by
    kind, success and failure orderings and operands, and per side the
    file, the nested scope, the callee that is the location identity, the
    side's own operand spelling when it differs, and the entries or text
    it must precede or follow in that scope. An entry has a production
    side, a kernel side or both. Kind and orderings are shared; each side
    matches the operands it names. An anchor that is an entry id names
    that entry's operation on the same side, which must sit in the same
    scope; any other anchor is source text that occurs once in the scope.
    A side's operation must occur exactly once in its scope, so an
    operation removed, duplicated, moved out of its scope or moved across
    one of its anchors drifts, and matching text in another scope earns no
    credit. Kernel orderings spelled `S::X`
    resolve through the strength the declaration's `strengths` names for
    the site's file, every constant of which some entry must bind.
    `read(path)` returns a file's text; kernel paths are relative to the
    package. Each file is read once per call, with its comments removed
    and its string literals emptied, so a copy of an operation in either
    earns no credit.
    """
    package = Path(declared["package"])
    bindings = declared.get("bindings", [])
    ids = {entry["id"] for entry in bindings}
    source = cache(lambda path: normalized(read(path)))
    declared_strengths, drift = strengths(declared, source)
    sites, bound = {}, {path: set() for path in declared_strengths}
    for entry in bindings:
        if entry["kind"] not in KINDS:
            drift.append(f"{entry['id']}: unknown kind {entry['kind']!r}")
            continue
        for side in ("production", "kernel"):
            site = entry.get(side)
            if site is None:
                continue
            if side == "production" and site["file"] not in declared["transcribed"]:
                drift.append(f"{entry['id']}: {site['file']} is not among the transcribed files")
                continue
            if side == "kernel":
                site = dict(site, file=str(package / site["file"]))
            method = site["call"].rsplit(".", 1)[-1].rsplit("::", 1)[-1]
            if not KINDS[entry["kind"]](method):
                drift.append(f"{entry['id']}: the {side} {site['call']} is no {entry['kind']}")
                continue
            problem, found = locate(entry, side, site, source, declared_strengths.get(site["file"]))
            if problem:
                drift.append(problem)
                continue
            if found.constants:
                bound[site["file"]] |= found.constants
            sites[(entry["id"], side)] = (site, found)
            if found.orderings != entry["orderings"]:
                drift.append(f"{entry['id']}: the {side} orderings are {found.orderings}, bound {entry['orderings']}")
    for (name, side), (site, found) in sorted(sites.items()):
        for relation in ("before", "after"):
            for anchor in site.get(relation, []):
                if anchor in ids:
                    other = sites.get((anchor, side))
                    if other is None:
                        drift.append(f"{name}: the {side} anchor entry {anchor} was not located")
                        continue
                    if (other[0]["file"], other[0]["scope"]) != (site["file"], site["scope"]):
                        drift.append(f"{name}: the {side} anchor entry {anchor} sits in another scope")
                        continue
                    places = [other[1].offset]
                else:
                    places = [match.start() for match in re.finditer(re.escape(normalized(anchor)), found.scope)]
                if len(places) != 1:
                    drift.append(f"{name}: the {side} anchor {anchor!r} appears {len(places)} times in its scope")
                elif (found.offset < places[0]) != (relation == "before"):
                    drift.append(f"{name}: the {side} operation no longer comes {relation} {anchor!r}")
    for path, names in sorted(bound.items()):
        for constant in sorted(set(declared_strengths[path]) - names):
            drift.append(f"{path} transcribes {constant} in its strength and no binding entry binds it")
    return drift


def read_source(path):
    return (ROOT / path).read_text(encoding="utf-8")


def check_transcription(expected):
    drift = transcription_drift(expected, read_source)
    if drift:
        raise Drift(drift)


def judge(evidence, expected, record, profile):
    check_transcription(expected)
    check_correspondence(expected)
    check_identity(expected, record)
    check_config(evidence)
    names = profile_cases(expected, profile)
    outputs = sorted(path.stem.removeprefix("genmc-") for path in evidence.glob("genmc-*.txt"))
    extra = sorted(set(outputs) - set(names))
    if extra:
        raise Refusal(TOOL_FAILURE, f"outputs for cases outside the {profile} profile {extra}")
    results = {}
    for name in names:
        declared = expected["cases"][name]
        paths = {kind: evidence / f"genmc-{name}.{kind}" for kind in ("argv", "env", "txt", "exit")}
        if not all(path.exists() for path in paths.values()):
            raise Refusal(TOOL_FAILURE, f"{name} has no recorded run")
        env = dict(line.split("=", 1) for line in paths["env"].read_text().splitlines() if "=" in line)
        check_command(name, expected, record, paths["argv"].read_text().splitlines(), env, evidence)
        try:
            exit_code = int(paths["exit"].read_text().strip())
        except ValueError as error:
            raise Refusal(TOOL_FAILURE, f"{name} records no exit code: {error}") from error
        text = paths["txt"].read_text(encoding="utf-8", errors="replace")
        called = evidence / f"genmc-{name}.intrinsics"
        intrinsics = sorted(set(called.read_text().split())) if called.exists() else []
        results[name] = judge_case(name, declared, text, exit_code, evidence / f"genmc-{name}.dot", intrinsics)
    return results


def package_sources(package):
    """Return the files a case build compiles: the package's own, `target` build state aside, then the sources
    outside it that its `#[path]` attributes include."""
    files = sorted(p for p in package.rglob("*") if p.is_file() and "target" not in p.relative_to(package).parts)
    included = {
        (path.parent / target).resolve()
        for path in files if path.suffix == ".rs"
        for target in INCLUDED.findall(path.read_text(encoding="utf-8"))
    }
    return [*files, *sorted(included - set(files))]


def declared_sources(declared):
    """Return the sources a judgment of `declared` speaks for: the package's and its included production files, then
    the production files whose orderings a kernel transcribes, each once, so evidence outlives none of them
    unnoticed."""
    sources = [*package_sources(ROOT / declared["package"]), *(ROOT / path for path in declared["transcribed"])]
    return list(dict.fromkeys(path.resolve() for path in sources))


def inputs(evidence):
    declared = read_json(EXPECTED)
    names = ["identity.json", "pins.txt", "report.json", "cargo-config.json", *(path.name for path in sorted(evidence.glob("genmc-*")))]
    digests = {name: sha256(evidence / name) for name in names if (evidence / name).is_file()}
    committed = [
        ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json", ROOT / "verification/obligations.json",
        EXPECTED, LITMUS, RECIPE, *sorted(PATCHES.glob("*.patch")), *declared_sources(declared),
    ]
    for path in committed:
        digests[str(path.relative_to(ROOT))] = sha256(path)
    return digests


def receipt(evidence, revision, profile, completion, code, reason, results):
    pins = evidence / "pins.txt"
    return {
        "job": "genmc", "module": profile, "lane": f"genmc {profile}", "revision": revision,
        "inputs": inputs(evidence),
        "tool": {"name": "genmc", "provenance": pins.read_bytes().decode("utf-8", errors="replace").strip().splitlines() if pins.exists() else []},
        "assumptions": [
            "finite RC11 exploration of the standalone cases under GenMC's experimental Rust frontend",
            "no exploration bound and no loop unrolling option; loops run as compiled",
        ],
        "bounds": {"options": read_json(EXPECTED)["options"], "cases": results},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": sum(max(result["executions"], 1) for result in results.values()) if code == CREDITED else 0,
        "executed": sorted(results) if code == CREDITED else [], "failed": [],
        "replay": f"bash scripts/rust-lane.sh genmc {profile}",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def derive(evidence, revision, profile):
    """Judge the evidence directory for `profile` and return the report and the receipt it supports, writing neither."""
    code, reason, results, completion, verdict = CREDITED, None, {}, "completed", VERDICTS[CREDITED]
    try:
        results = judge(evidence, read_json(EXPECTED), read_json(evidence / "identity.json"), profile)
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
        verdict = DRIFT if isinstance(refusal, Drift) else VERDICTS[code]
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, RecursionError) as error:
        code, reason, completion = TOOL_FAILURE, f"malformed evidence: {error!r}", "tool failure"
        verdict = VERDICTS[code]
    except OSError as error:
        code, reason, completion = TOOL_FAILURE, f"the judgment cannot read an input: {error}", "tool failure"
        verdict = VERDICTS[code]
    report = {"code": code, "verdict": verdict, "credited": code == CREDITED, "reason": reason,
              "profile": profile, "cases": results}
    return report, receipt(evidence, revision, profile, completion, code, reason, results)


def run_judge(args):
    evidence = Path(args.evidence)
    report, derived = derive(evidence, args.revision or rc11.git_revision(), args.profile)
    (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    derived["inputs"]["report.json"] = sha256(evidence / "report.json")
    (evidence / "receipt.json").write_text(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"judge-genmc: {report['reason']}", file=sys.stderr)
    return report["code"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check the GenMC toolchain identity and judge its case runs.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["options", "cases", "identity", "config", "judge"])
    parser.add_argument("--profile")
    parser.add_argument("--toolchain")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    try:
        if args.command == "options":
            print("\n".join(read_json(EXPECTED)["options"]))
            return CREDITED
        if args.command == "cases":
            print("\n".join(profile_cases(read_json(EXPECTED), args.profile)))
            return CREDITED
        if args.command == "judge" and not args.profile:
            parser.error("judge needs --profile")
        if not args.evidence:
            parser.error(f"{args.command} needs --evidence")
        if args.command == "identity":
            if not args.toolchain:
                parser.error("identity needs --toolchain")
            return identity(args)
        if args.command == "config":
            check_config(Path(args.evidence))
            return CREDITED
        return run_judge(args)
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-genmc: {error}", file=sys.stderr)
        return TOOL_FAILURE


if __name__ == "__main__":
    sys.exit(main())
