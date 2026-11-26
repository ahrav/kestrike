#!/usr/bin/env python3
"""Pin the Kani installation and credit each declared harness only from a complete verification.

Usage:
  judge-kani.py cases --profile NAME
  judge-kani.py batches --profile NAME
  judge-kani.py arguments
  judge-kani.py identity --kani-home DIR --cargo-kani PATH --evidence DIR
  judge-kani.py judge --profile NAME --evidence DIR [--revision SHA]
  judge-kani.py record begin --profile NAME --evidence DIR --workers N [--cap N] --total SECONDS
  judge-kani.py inventory --evidence DIR
  judge-kani.py record remaining --evidence DIR
  judge-kani.py record batch --evidence DIR --index N --start SECONDS
  judge-kani.py record timeout --evidence DIR --index N
  judge-kani.py record complete --evidence DIR
  judge-kani.py compare --evidence DIR
  judge-kani.py bands

The declaration is the committed `verification/kani/expected.json`: the Kani
version, the package, the source files that hold the harnesses, each single
harness's cover count, the `unreachable` map of nonzero unreachable-check
counts by harness name, the `cbmc` list of arguments the run passes through to
CBMC, and per band family its check function, module, cover
count, bands of chunk lengths, the gaps between them and the Verus items that
close those gaps: a family's `closed_by` names verified items of
`verification/verus/expected.json` whose contracts hold at every chunk
length, or `kani:FAMILY` for a family whose bands tile every chunk length,
and its `trusts` names the trusted rows of `verification/verus/inventory.json`
whose quoted text those items transcribe. A gap whose family's `closed_by`
is empty becomes an `unproved:` assumption in every receipt. Loading the declaration refuses a
harness, single or band, whose cover count is not an integer of at least 1,
and an `unreachable` pin that names no declared harness or holds no positive
integer count; an unpinned harness declares 0 unreachable checks. The `cbmc`
list is `--max-field-sensitivity-array-size` and the size `COMPARED` records
for the declared Kani release: CBMC
keeps the elements of an array of at most that many elements as separate
values, 64 by default. The argument reaches every harness and disables no
check. It changes how CBMC represents an array whose length lies between 64
and the size, so its symbolic execution can decide a loop exit it otherwise
leaves to the solver and then states no unwinding assertion for that loop: a
harness's check total can fall while its property assertions, covers and
unreachable count stay. That holds for the Kani releases `COMPARED` names, each
with the CBMC it bundles and the size it records, under which every harness
that verifies with the argument omitted ran with that size and without the
argument and met the equality of `compare`. The declaration's `compared` list
names those harnesses, and its `argument_only` map gives each harness that
verifies only with the argument the figures of the run without it that ran
out of memory or time: the census admission proofs over two and three
entries. Loading refuses a declared harness that is in neither or in both,
with the lane command that compares a new harness; `compare` and
`arguments` alone load the declaration without that refusal, so the
comparison runs for a harness no list names yet. Loading
refuses a `cbmc` list beside any other declared Kani version and every `cbmc`
list other than the argument with the recorded size, and the judge
refuses a run whose output names another CBMC version. The declaration is the
one list of bands: `bands` writes each family's `bands!` invocation into the
`*_kani_bands.rs` file its module includes and writes only those files;
`scripts/test-judge-kani.py` fails while a `*_kani_bands.rs` file under
`crates/kestrike/src` differs from that rendering, no family renders it,
or a rendered file is missing. The `pr` profile's harnesses run on
manual dispatch; the `scheduled` profile runs every harness nightly, the `pr`
ones included.
The `batch_budget` map gives each profile its batch budget, and the `weights`
map a weight to each harness that declares one; every other harness weighs
1. A profile runs as batches cut from its sorted harnesses (`profile_cases`)
in order: a batch takes harnesses while their summed weight stays within the
budget, so a harness that weighs the budget runs alone, and each batch is one
`cargo kani` process, which releases what `kani-driver` held for the batch
when it exits. A harness weighs the `scheduled` budget when its CBMC process
reaches 2 GiB resident or its CBMC result reaches 1 GB of JSON
(`docs/agents/ci.md` gives the command for each). The judge reads Kani's
terse output, which names neither size, so the weights rest on the
declaration's review and on those measurements; a heavy harness left at
weight 1 shows as a memory-high event or a kill in its batch when the
changed profile runs under the runner's limits. Loading refuses a map that
lacks a profile or names another, a budget or weight that is not a positive
integer, a weight for a name that is no declared harness, and a weight above
the budget of a profile that runs the harness. A profile whose budget holds
its harnesses' summed weight runs as one batch.
`cases` prints the profile's harnesses one per line, `batches` prints one
line a batch for the lane, its harnesses separated by single spaces, and
`arguments` the declared CBMC arguments one per line.

`record` writes the lane's run record, `kani-run.json`, as the run proceeds,
taking every time on one monotonic clock read at `begin`: `begin` writes a new
invocation id, the profile, the checked-out revision, whether every tracked
file showed its commit's bytes (none changed in the working tree or index and
no assume-unchanged or skip-worktree flag set), the sha256 of the workspace
`Cargo.lock`, the worker count of at least 2, the worker bound (`--cap`, the
runner's `CARGO_BUILD_JOBS`, or null), the positive total in seconds and the
declared batch count; `remaining` prints the whole seconds the total leaves
and the seconds since `begin`; `batch` adds, as a batch's child exits, its
number, which must follow the last recorded one, the harnesses its recorded
command names in order, the sha256 of its command, output and exit code
files, the revision, tree state and lock digest at that sample, and its start
and end in seconds from `begin`; `timeout` records the batch at which the
total ran out; `complete` marks the run complete only when every declared
batch is recorded in order and no timeout is recorded. A malformed option or
record refuses with exit 2 and leaves the record as it was. These samples show
the tree's state at each sample, not between them; the receipt binds the
bytes of every source at judgment. `begin` first refreshes the stat data of
the checkout's index under its lock, so a later sample hashes only the
tracked files whose stat data changed; the samples read the index without
its lock.

`compare` reads the two runs `scripts/rust-lane.sh kani-compare` records in
the evidence directory: `compare-without.argv` and `compare-with.argv`, each
run's exit code beside it, and the `cargo kani --export-json` file each argv
names, `compare-without.json` and `compare-with.json`. The two argv name the
same declared harnesses and differ only in the export file and in the
`--cbmc-args` tail, which the first lacks and the second ends with; both
runs exit 0 and hold exactly those harnesses, under the declared Kani
release and the CBMC `COMPARED` records. A harness meets
the equality when both runs verify, every check the run under the arguments
reports appears in the run without them with the same function, category,
description, file, line, column and status, each check only the run without
them reports is an unwinding assertion that succeeded, and the covers with
their statuses and the count of unreachable checks are the same. It prints
the harnesses that differ with what differs and the harnesses that drop
unwinding assertions. Exit 0 means every harness meets the equality, 1 that
one does not, 2 a record it cannot compare.

`identity` writes `identity.json` into the evidence directory: the version
`cargo kani --version` prints, the toolchain Kani compiles with, the sha256
of `cargo-kani`, and the digest of the whole bundle tree under the Kani home
(the verifier programs, libraries, library sources and the `toolchain` link,
in the Verus judge's manifest form) and of the toolchain tree behind that
link. It also writes `pins.txt`, the identity's provenance lines. A version
that differs from the declaration is a drift the judgment refuses, and so is
a recorded version whose `CBMC` lines are other than one line naming the CBMC
that `COMPARED` records for the declared Kani release; a bundle or toolchain
that changed since the identity was taken is refused.

`judge` reads `identity.json`, `cargo-config.json` (the merged cargo file
configuration the lane recorded beside the package), `kani-list.json` (the
harnesses `cargo kani list --format json` found in the package),
`kani-run.json`, and each batch's command (one argument per line), output and
exit code: `kani.argv`, `kani.txt` and `kani.exit` for a profile of one
batch, `kani-N.argv`, `kani-N.txt` and `kani-N.exit` for batch N of a profile
of several. The run record must name an invocation, the judged profile and
revision, a tree that matched that revision at the start and at every batch's
exit, the evidence's `Cargo.lock` at each of those samples, the declared
batch count, a worker count within the recorded bound, and its batches
numbered 1 to the count in order, each with the declared harness list and the
digests of its files as they are; each batch file is read once, and the bytes
whose digest matches are the bytes judged. A batch whose recorded exit is
124, 130 or 143, or a recorded timeout, makes the run a timeout; otherwise the record must be marked
complete, and the evidence must hold exactly the declared batch files, in one
form. Each batch is then judged alone by the rules below, with its harness
list as the profile's: one refused batch refuses the profile, its reason
names the batch, and the refusal credits no harness. Cargo shapes Kani's build from its configuration files as well
as its environment, and Kani forces `-C overflow-checks=on` and takes debug
assertions from the cargo profile, so the recorded configuration is refused under the GenMC judge's rule: a
`profile`, `target`, `unstable`, `patch` or `source` table, a `build` key that
names the compiler, a wrapper, flags, the target, the target directory or the build directory, or a
`CASE*`, `RUST*` or `CARGO*` `[env]` entry, with the GenMC judge's one
allowance: a `target` table equal to the repository's `.cargo/config.toml`
table, which adds `-C target-feature=+lse` as `rustflags` and `rustdocflags`
for aarch64 and nothing else. The judge also refuses an
`alias.kani` or `KANI*` `[env]` entry, which redirects `cargo kani` from the
identified bundle. Every tracked `.rs` file of the
compiled packages is read as UTF-8 with each CRLF as LF, and a file whose text
holds `kani` is matched with its comments blanked: a `kani::` path must
continue with `proof`, `any`, `assume`, `cover` or `unwind`, which also
refuses brace and glob imports, and it may appear only in a declared source.
In every file whose text holds `kani`, the judge refuses a whole-word
`kanitool`, the attribute namespace Kani's macros expand to; an `extern crate`
of `kani`, `r#kani` or another crate whose name starts with `kani`; any
`kani as NAME` text; and an opening `#!`, after any byte-order mark, other
than `#![`. rustc drops such a first line as a shebang, except that it reads
`#!`, then whitespace or non-doc comments, then `[` as an inner attribute; the
judge refuses those forms too. The judge also refuses a raw string that the comment
lexer opens directly after a quote, a `#` or a non-ASCII character, with or
without a `b` or `c` prefix: rustc can read that `r` as the end of the token
before it, a literal's suffix or the name of a raw identifier or lifetime, and
then reads the text that follows as other tokens than the comment lexer does.
The checks match source text, with Rust's whitespace between tokens, so the
same spelling inside a string literal, or a cast of a local named `kani`, also
refuses. The rule reads only that text: a `cfg(not(kani))` or `cfg!(kani)`
swap, a macro that takes the crate name as an argument and builds the path, an
admitted item re-exported from a declared source and used in another file, a
local item or import named `kani`, a local macro named `assert` or `panic`,
and a source included under another extension or from
outside the two packages reach Kani without a refused spelling, so the rule
leaves them unchecked. The listed
harnesses must equal the declared ones, so a harness that is added, renamed or
dropped fails the judgment. The workspace manifest and the manifests of both
compiled packages may name Kani
only on a line that holds `cfg(kani)`: `cargo kani` reads verification flags
from the `workspace.metadata.kani`, `package.metadata.kani` and top-level
`kani` tables, so the parsed manifests must hold none of them, and a host with
no TOML parser refuses. The parsed dependency tables, at top level, under
`workspace` and under each `target`, and the `patch` tables must hold no entry
whose name or `package` starts with `kani` in any letter case: Cargo binds the
crate to the entry's name, so a source could spell Kani's crate under another
name. The command must be `cargo kani -p PACKAGE
--exact`, a `--harness NAME` for each harness of the batch in the order
`batches` prints, `-j N` for N of 2 or more written in 1 to 6 digits and equal
to the record's worker count, `--output-format terse`, a `--target-dir DIR`,
`-Z unstable-options` and `--cbmc-args` with the declared `cbmc` list,
exactly, so every default check stays enabled: memory-safety (pointer),
arithmetic overflow, undefined-function and unwinding checks, alongside
assertions, covers and the assertion reachability checks. Those mark an
assertion or a compiler-inserted check (index bounds, arithmetic overflow,
division or remainder by zero, and the alignment, null-pointer and
enum-discriminant safety checks) that no execution reaches, which produces the `(N unreachable)` count; an
unreachable `panic!`, `unwrap`, `expect` or `unreachable!` leaves the count
unchanged. The count totals a harness's checks and names no site.
With `-j N`, Kani prints `Thread T: Checking harness NAME...` when thread T
starts a harness and `Thread T:` before that harness's result.
A harness credits only from one start and one result: a summary of zero failed
checks out of a nonzero count, with no undetermined checks, whose
`(N unreachable)` suffix, 0 when absent, equals the declared count and is
below the total, one cover
summary with its declared number of cover properties all satisfied and no
status suffix, `VERIFICATION:- SUCCESSFUL`, and a `Verification Time:` line,
which ends the harness's result. A credited result holds those four lines
after its `VERIFICATION RESULT:` line and no other line; the
output must hold exactly one `Complete - N successfully verified harnesses, 0
failures, N total.` line for the profile's N harnesses, and the run must exit
0. After the first harness starts, a credited run holds only harness starts
and results, then ends with `Manual Harness Summary:` and that `Complete`
line; the text
ahead of the first start is Kani's version lines and cargo's build output,
which the judge reads only for `Kani Rust Verifier`, `CBMC` and `Complete`
lines: it must hold one `Kani Rust Verifier` line, the first line the
identified `cargo kani --version` printed. An exit of 124,
130 or 143 is a timeout. A failed or undetermined check, an
unreachable count or a cover summary other than the declared one, or a missing
or repeated cover summary is an outcome mismatch. A zero-check summary, a
summary whose every check is unreachable, another nonzero
exit from a run whose harnesses all credit, an undeclared profile, a missing
run record or exit code, an output whose `CBMC` lines ahead of the first
harness start are other than one line naming the CBMC that `COMPARED` records
for the declared Kani release, a
started or reported harness set other than the
profile's, a result on a thread with no started harness, a repeated start or
result, a missing or repeated check summary or `VERIFICATION:- SUCCESSFUL`
line, a check or cover summary whose numbers are malformed, longer than the
judge reads or larger in sum than its total, a missing or malformed
`Verification Time:` line, a result that passes every check above and holds
a line beside those five, another line after the first harness start than a
start, a result, `Manual Harness Summary:` and the `Complete` line, and a
missing, repeated or conflicting `Complete`
line is a tool failure. A manifest, configuration, harness-listing,
source-surface or unreadable-input refusal is a tool failure too, and so is
evidence JSON of another shape than the judge reads or nested past the
parser's depth.

`judge` writes `report.json` and a receipt for `verify-receipts.py credit
--receipt`, naming the profile as its module and binding the digests of every
input the judgment read, the run record and every batch file present
included. Exit 0 credits, 1 is an outcome mismatch, 2 is a
tool failure or drift, 3 is an interrupted run. When two conditions hold for
one harness, the first check in `judge_harness` decides the code. An argument
error, a declaration the loader refuses, an evidence file that exists but
cannot be read, and an input a credited receipt cannot hash exit 2 without
writing a new report; otherwise a refused judgment's receipt binds each
committed input it can read.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import os
import re
import subprocess
import sys
import time
import uuid
from collections import Counter
from functools import partial
from itertools import takewhile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "verification/kani/expected.json"
VERUS = ROOT / "verification/verus/expected.json"
INVENTORY = ROOT / "verification/verus/inventory.json"
BINARIES = ("bin/cargo-kani", "bin/kani-compiler", "bin/kani-driver", "bin/cbmc")
MANIFESTS = (ROOT / "Cargo.toml", ROOT / "crates/kestrike/Cargo.toml", ROOT / "crates/spdk-sys/Cargo.toml")
# The local packages `cargo kani -p kestrike` compiles: the package and its path dependency.
COMPILED = (ROOT / "crates/kestrike", ROOT / "crates/spdk-sys")
KANI_TABLES = (("workspace", "metadata", "kani"), ("package", "metadata", "kani"), ("kani",))
DEPENDENCY_TABLES = ("dependencies", "dev-dependencies", "dev_dependencies", "build-dependencies", "build_dependencies")
# Admitting a stub or contract requires both an `ADMITTED` entry and `-Z stubbing` or `-Z function-contracts` in the
# command shape.
ADMITTED = ("proof", "any", "assume", "cover", "unwind")
# The one CBMC argument a declaration may pass through `--cbmc-args`.
FIELD_SENSITIVITY = "--max-field-sensitivity-array-size"
# Each entry maps a Kani release to the CBMC version the release bundles and the `FIELD_SENSITIVITY` size tested.
# The comparison is the two exported runs of `rust-lane.sh kani-compare` on that release, one with the recorded size
# and one with the argument omitted, of every harness the declaration lists in `compared`, which `compare` accepts. A new Kani release or
# `FIELD_SENSITIVITY` size is recorded here and in the declaration first, since `compare` reads both; the record
# stays only when `compare` accepts both runs of every compared harness. A change that adds a harness runs it both
# ways and lists it in `compared`, or in `argument_only` with the figures of the run without the argument that ran
# out of memory or time.
COMPARED = {"0.68.0": ("6.11.0", "128")}
# Rust reads U+200E and U+200F as whitespace between tokens; Python's `\s` holds every other Rust whitespace.
GAP = r"[\s\u200e\u200f]"
KANI_PATH = re.compile(rf"\bkani{GAP}*::{GAP}*(\w+|.)", re.S)
KANI_ALIAS = re.compile(rf"\bkani{GAP}+as{GAP}+\w")
KANI_CRATE = re.compile(rf"\bextern{GAP}+crate{GAP}+((?:r#)?kani\w*)")
KANITOOL = re.compile(r"\bkanitool\b")
# rustc can consume an apparent raw-string `r` as the end of the token before it: a literal's suffix, the name of a
# raw identifier or lifetime, or, in the 2015 and 2018 editions, an identifier that a non-ASCII character continues.
GLUED_RAW = re.compile(r"""r(?=#*")(?:(?<=["'#\u0080-\U0010ffff]r)|(?<=["'#\u0080-\U0010ffff][bc]r))""")
# At most 18 ASCII digits, so every count the judge reads converts to an integer.
COUNT = r"([0-9]{1,18})"
NONZERO = r"([1-9][0-9]{0,17})"
STATUS = rf"(?: \((?:{NONZERO} undetermined|{NONZERO} unreachable|{NONZERO} undetermined,{NONZERO} unreachable)\))?"
# The lane's run record, which it writes as its batches run.
RUN_RECORD = "kani-run.json"
# The three files each batch writes: its command, one argument per line, its output and its exit code.
KINDS = ("argv", "txt", "exit")
# Every file name of either batch form, and any other name that spells a batch file of the form `kani-STEM.KIND`.
BATCH_FILE = re.compile(r"kani(?:-.*)?\.(?:argv|txt|exit)")


def toml_parser():
    """Return the first importable TOML parser: `tomllib` (Python 3.11+), `tomli`, or the `tomli` pip vendors."""
    for name in ("tomllib", "tomli", "pip._vendor.tomli"):
        try:
            return importlib.import_module(name)
        except ImportError:
            continue
    return None


TOML = toml_parser()


def load_judge(name):
    spec = importlib.util.spec_from_file_location(f"judge_{name}", ROOT / f"scripts/judge-{name}.py")
    if spec is None or spec.loader is None:
        raise SystemExit(f"judge-kani: scripts/judge-{name}.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


genmc = load_judge("genmc")
rc11, check_config = genmc.rc11, genmc.check_config
verus = load_judge("verus")
install_digest, code_text = verus.install_digest, verus.code_text
Refusal, sha256, read_json, single = rc11.Refusal, rc11.sha256, rc11.read_json, rc11.single
CREDITED, MISMATCH, TOOL_FAILURE, INCOMPLETE = rc11.CREDITED, rc11.MISMATCH, rc11.TOOL_FAILURE, rc11.INCOMPLETE
VERDICTS, INTERRUPTED = rc11.VERDICTS, rc11.INTERRUPTED


def declaration(path=EXPECTED, comparison=True):
    """Return the declaration with each band family expanded into its harnesses.

    A family names its module, its cover count, its bands of chunk lengths in
    units of 4096 bytes and the gaps between them; band `lo..hi` is the
    harness `MODULE::FAMILY_units_LO_HI`. The `pr` profile is the listed
    harnesses, and the `scheduled` profile is every other one. `comparison`
    is false only for `compare` and `arguments`, which the comparison lane
    runs for a harness before a list names it.
    """
    declared = read_json(path)
    if verus.source_names(declared) is None:
        raise Refusal(TOOL_FAILURE, "the declaration's sources must be a list of repository paths")
    harnesses = {name: {"covers": covers} for name, covers in declared["singles"].items()}
    for family, spec in declared["families"].items():
        for lo, hi in spec["bands"]:
            harnesses[f"{spec['module']}::{family}_units_{lo}_{hi}"] = {"covers": spec["covers"], "family": family, "units": [lo, hi]}
    if len(harnesses) != len(declared["singles"]) + sum(len(spec["bands"]) for spec in declared["families"].values()):
        raise Refusal(TOOL_FAILURE, "the declaration names a harness twice")
    uncovered = sorted(name for name, harness in harnesses.items() if type(harness["covers"]) is not int or harness["covers"] < 1)
    if uncovered:
        raise Refusal(TOOL_FAILURE, f"{uncovered[0]} declares {harnesses[uncovered[0]]['covers']!r} covers; every harness needs at least 1")
    pins = declared.get("unreachable", {})
    if not isinstance(pins, dict):
        raise Refusal(TOOL_FAILURE, "the unreachable pins must map harness names to counts")
    for name, count in sorted(pins.items()):
        if name not in harnesses:
            raise Refusal(TOOL_FAILURE, f"the unreachable pin {name} names no declared harness")
        if type(count) is not int or count < 1:
            raise Refusal(TOOL_FAILURE, f"the unreachable pin {name} is {count!r}; a pin is a positive count")
    for name, harness in harnesses.items():
        harness["unreachable"] = pins.get(name, 0)
    if declared.get("kani") not in COMPARED:
        raise Refusal(TOOL_FAILURE, f"the declaration's cbmc arguments were compared with and without under Kani {', '.join(COMPARED)}, "
                                    f"not {declared.get('kani')!r}; an upgrade repeats that comparison before it keeps them")
    size = COMPARED[declared["kani"]][1]
    if declared.get("cbmc") != [FIELD_SENSITIVITY, size]:
        raise Refusal(TOOL_FAILURE, f"the declaration's cbmc arguments must be {FIELD_SENSITIVITY} {size}, the list compared with and without "
                                    f"under Kani {declared['kani']}; another size repeats that comparison before the declaration names it")
    if comparison:
        check_comparison(declared, harnesses)
    verified = set(read_json(VERUS)["tests"])
    gapless = {f"kani:{family}" for family, spec in declared["families"].items() if not spec["gaps"]}
    trusted = {row["item"].split(": ")[0] for row in read_json(INVENTORY)["rows"] if row["class"] == "trusted"}
    closures, trusts = {}, {}
    for family, spec in declared["families"].items():
        if not spec["gaps"]:
            continue
        closures[family], trusts[family] = spec.get("closed_by", []), spec.get("trusts", [])
        unverified = sorted(set(closures[family]) - verified - gapless)
        if unverified:
            raise Refusal(TOOL_FAILURE, f"{family}'s gaps rest on {unverified[0]}, which neither the Verus declaration verifies nor a gapless family proves")
        untrusted = sorted(set(trusts[family]) - trusted)
        if untrusted:
            raise Refusal(TOOL_FAILURE, f"{family}'s gaps trust {untrusted[0]}, which no trusted inventory row names")
    pr = sorted(declared["pr"])
    profiles = {"pr": pr, "scheduled": sorted(set(harnesses) - set(pr))}
    counts = declared.get("batch_budget")
    if not isinstance(counts, dict) or sorted(counts) != sorted(profiles):
        raise Refusal(TOOL_FAILURE, f"the declaration's batch_budget must map each profile, {', '.join(sorted(profiles))}, to its batch budget")
    for name, size in sorted(counts.items()):
        if type(size) is not int or size < 1:
            raise Refusal(TOOL_FAILURE, f"the {name} profile's batch budget is {size!r}; a batch budget is a positive count")
    weights = declared.get("weights", {})
    if not isinstance(weights, dict):
        raise Refusal(TOOL_FAILURE, "the declaration's weights must map harness names to weights")
    cases = {name: sorted(set(pr) | set(members)) for name, members in profiles.items()}
    for name, weight in sorted(weights.items()):
        if name not in harnesses:
            raise Refusal(TOOL_FAILURE, f"the weight of {name} names no declared harness")
        if type(weight) is not int or weight < 1:
            raise Refusal(TOOL_FAILURE, f"the weight of {name} is {weight!r}; a weight is a positive count")
        over = sorted(profile for profile, members in cases.items() if name in members and weight > counts[profile])
        if over:
            raise Refusal(TOOL_FAILURE, f"the weight {weight} of {name} passes the {over[0]} profile's batch budget of {counts[over[0]]}")
    return {
        **declared, "harnesses": dict(sorted(harnesses.items())),
        "gaps": {family: spec["gaps"] for family, spec in declared["families"].items() if spec["gaps"]},
        "closures": closures, "trusts": trusts, "profiles": profiles,
    }


def check_comparison(declared, harnesses):
    """Refuse a declaration whose harnesses are not each in exactly one of `compared` and `argument_only`.

    `compared` lists the harnesses whose runs with and without the `cbmc` arguments `compare` accepted, and
    `argument_only` maps each harness that verifies only with them to the figures of the run without them that ran
    out of memory or time.
    """
    compared, only = declared.get("compared"), declared.get("argument_only")
    if not isinstance(compared, list) or not all(isinstance(name, str) for name in compared) or len(set(compared)) != len(compared):
        raise Refusal(TOOL_FAILURE, "the declaration's compared list must hold harness names, each once")
    if not isinstance(only, dict) or not all(isinstance(reason, str) and reason.strip() for reason in only.values()):
        raise Refusal(TOOL_FAILURE, "the declaration's argument_only map must give each harness the figures of its run without the cbmc arguments")
    listed = set(compared) | set(only)
    unknown, both, neither = sorted(listed - set(harnesses)), sorted(set(compared) & set(only)), sorted(set(harnesses) - listed)
    if unknown:
        raise Refusal(TOOL_FAILURE, f"{unknown[0]} is listed in compared or argument_only and names no declared harness")
    if both:
        raise Refusal(TOOL_FAILURE, f"{both[0]} is listed in both compared and argument_only; a harness is in exactly one")
    if neither:
        run = f"cargo kani -p {declared['package']} --exact --harness {neither[0]} ... -Z unstable-options --export-json"
        raise Refusal(TOOL_FAILURE, f"{neither[0]} is in neither compared nor argument_only: run `bash scripts/rust-lane.sh kani-compare {neither[0]}`, "
                                    f"which runs `{run} compare-without.json`, then `{run} compare-with.json --cbmc-args {' '.join(declared['cbmc'])}`, "
                                    "and has `judge-kani.py compare` compare the two runs; then list the harness in compared, or in argument_only "
                                    "only with the figures of a run without the arguments that ran out of memory or time")


BANDS_HEADER = (
    "// Generated by `python3 scripts/judge-kani.py bands` from verification/kani/expected.json:\n"
    "// one Kani proof per declared band. Edit the declaration and regenerate.\n"
)


def module_source(module):
    """Return the source file that holds the `verification` module `module`."""
    return ROOT / "crates/kestrike/src" / (module.removesuffix("::verification").replace("::", "/") + ".rs")


def band_file(module):
    """Return the file the `verification` module `module` includes its band proofs from."""
    source = module_source(module)
    return source.with_name(f"{source.stem}_kani_bands.rs")


def band_sources(declared):
    """Render each family's `bands!` invocation from the declaration, keyed by the file that holds it.

    A family's harness `FAMILY_units_LO_HI` runs its `check` function over chunk lengths `LO..HI`,
    so the declaration alone names every band proof.
    """
    files = {}
    for family, spec in declared["families"].items():
        lines = ["bands! {", f"    {spec['check']}:"]
        lines += [f"    {family}_units_{lo}_{hi} => ({lo}, {hi})," for lo, hi in spec["bands"]]
        files.setdefault(band_file(spec["module"]), []).append("\n".join(lines) + "\n}\n")
    return {path: BANDS_HEADER + "\n".join(blocks) for path, blocks in files.items()}


def committed_band_sources():
    """Return every committed `*_kani_bands.rs` file under the crate's sources."""
    return set((ROOT / "crates/kestrike/src").rglob("*_kani_bands.rs"))


def stale_band_sources(declared):
    """Return the band files whose committed text differs from the declaration's rendering.

    A committed band file the declaration no longer renders is stale too: its module would keep
    including proofs the declaration dropped. Deleting it, and the `include!` that names it, is the
    author's edit; `bands` writes only the files it renders.
    """
    rendered = band_sources(declared)
    return sorted(str(path.relative_to(ROOT)) for path in committed_band_sources() | set(rendered)
                  if path not in rendered or not path.is_file() or path.read_text() != rendered[path])


def profile_cases(expected, profile):
    """Return the harnesses a run of `profile` judges: the PR harnesses, and for another profile also its own."""
    if profile not in expected["profiles"]:
        raise Refusal(TOOL_FAILURE, f"profile {profile!r} is not declared")
    return sorted(set(expected["profiles"]["pr"]) | set(expected["profiles"][profile]))


def batches(expected, profile):
    """Return the batches a run of `profile` runs in order, cut from `profile_cases` in its order.

    Each harness weighs its declared weight, 1 when it declares none. A batch takes the next harnesses while their
    summed weight stays within the profile's batch budget and closes before a harness that would pass it, so a
    harness that weighs the budget runs alone. The lane runs these batches and the judge refuses any other cut.
    """
    names = profile_cases(expected, profile)
    budget, weights = expected["batch_budget"][profile], expected.get("weights", {})
    cut, load = [], 0
    for name in names:
        weight = weights.get(name, 1)
        if not cut or load + weight > budget:
            cut.append([])
            load = 0
        cut[-1].append(name)
        load += weight
    return cut


def batch_files(count):
    """Return the file names of each of `count` batches, keyed by kind: `kani.KIND` for a profile of one batch,
    `kani-N.KIND` for batch N of a profile of several."""
    stems = ["kani"] if count == 1 else [f"kani-{index}" for index in range(1, count + 1)]
    return [{kind: f"{stem}.{kind}" for kind in KINDS} for stem in stems]


def evidence_files(expected, profile):
    """Return the evidence files a credited run of `profile` writes beside the common ones: the run record and
    each batch's files, in batch order."""
    return [RUN_RECORD, *(name for files in batch_files(len(batches(expected, profile))) for name in files.values())]


def bundle(kani_home, version):
    return Path(kani_home) / f"kani-{version}"


def identity(args):
    expected = declaration()
    home = bundle(args.kani_home, expected["kani"])
    reported = subprocess.run([args.cargo_kani, "kani", "--version"], capture_output=True, text=True, check=False).stdout
    toolchain = home / "rust-toolchain-version"
    if not toolchain.is_file():
        raise Refusal(TOOL_FAILURE, f"{home} holds no Kani {expected['kani']} bundle")
    for name in BINARIES[1:]:
        if not (home / name).is_file():
            raise Refusal(TOOL_FAILURE, f"{home} holds no {name}")
    compiler = (home / "toolchain").resolve()
    if not (home / "toolchain").is_symlink() or not compiler.is_dir():
        raise Refusal(TOOL_FAILURE, f"{home}/toolchain is no link to an installed toolchain")
    # The bundle tree is `cargo kani setup`'s extracted release: the verifier
    # programs, the kani libraries the harnesses compile against, the library
    # sources it verifies with, and the `toolchain` link, recorded by target.
    # The tree behind the link is the compiler `kani-compiler` loads, recorded
    # by its resolved path and digest.
    record = {
        "version": reported.strip(),
        "toolchain": toolchain.read_text().strip(),
        "cargo_kani": {"path": args.cargo_kani, "sha256": sha256(args.cargo_kani)},
        "bundle": {"path": str(home), **install_digest(home)},
        "compiler": {"path": str(compiler), **install_digest(compiler)},
    }
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    lines = [
        f"- {record['version'].splitlines()[0] if record['version'] else 'Kani'}; cargo-kani sha256 {record['cargo_kani']['sha256']}",
        f"- toolchain {record['toolchain']}",
        f"- bundle tree sha256 {record['bundle']['sha256']} over {record['bundle']['files']} files at {home}",
        f"- toolchain tree sha256 {record['compiler']['sha256']} over {record['compiler']['files']} files at {compiler}",
    ]
    (evidence / "pins.txt").write_text("\n".join(lines) + "\n")
    print(json.dumps({"identity": str(evidence / "identity.json")}))
    return CREDITED


def cbmc_versions(lines):
    """The versions the `CBMC VERSION` lines among `lines` name, in order."""
    return [line.removeprefix("CBMC ") for line in (raw.strip() for raw in lines) if line.startswith("CBMC ")]


def check_identity(expected, record):
    if not record.get("version", "").startswith(f"Kani Rust Verifier {expected['kani']} "):
        raise Refusal(TOOL_FAILURE, f"Kani reports {record.get('version')!r}, declared {expected['kani']}")
    tool = record.get("cargo_kani") or {}
    if not Path(tool.get("path", "")).is_file() or sha256(tool["path"]) != tool.get("sha256"):
        raise Refusal(TOOL_FAILURE, "cargo-kani changed since the identity was taken")
    bundle = record.get("bundle") or {}
    home = Path(bundle.get("path", ""))
    if not home.is_dir() or install_digest(home)["sha256"] != bundle.get("sha256"):
        raise Refusal(TOOL_FAILURE, f"the Kani bundle at {home} changed since the identity was taken")
    compiler = record.get("compiler") or {}
    installed = Path(compiler.get("path", ""))
    if (home / "toolchain").resolve() != installed or not installed.is_dir() or install_digest(installed)["sha256"] != compiler.get("sha256"):
        raise Refusal(TOOL_FAILURE, f"the toolchain behind {home}/toolchain changed since the identity was taken")
    # `cargo kani --version` prints the CBMC the identified Kani runs; the digests above bind that executable and its bundle.
    cbmc, bundled = cbmc_versions(record["version"].splitlines()), COMPARED[expected["kani"]][0]
    if cbmc != [bundled]:
        raise Refusal(TOOL_FAILURE, f"the identified Kani reports CBMC {cbmc}; the cbmc arguments were compared under Kani {expected['kani']} "
                                    f"with CBMC {bundled}")


def check_manifests(manifests=MANIFESTS):
    """Refuse a manifest that configures Kani: `cargo kani` reads `flags` and `unstable` from its Kani tables.

    Kani 0.68.0 reads the `workspace.metadata.kani`, `package.metadata.kani`
    and top-level `kani` tables. A quoted key can spell `kani` with escapes,
    so the parsed manifest must hold none of those tables, and a manifest is
    refused when no TOML parser is importable or it does not parse. Outside a
    `#` comment, a line may name Kani only when it also holds `cfg(kani)`; the
    parsed-table check still refuses a Kani table such a line opens, and the
    parsed dependency check refuses a dependency such a line declares.
    """
    if TOML is None:
        raise Refusal(TOOL_FAILURE, "no TOML parser (tomllib, tomli or pip's vendored tomli) can check the manifests for Kani configuration")
    for path in manifests:
        text = verus_call(verus.utf8_text, path)
        for number, line in enumerate(text.splitlines(), 1):
            code = line.split("#", 1)[0]
            if "kani" in code.lower() and "cfg(kani)" not in code:
                raise Refusal(TOOL_FAILURE, f"{Path(path).name}:{number} configures Kani: {code.strip()!r}")
        try:
            parsed = TOML.loads(text)
        except ValueError as error:
            raise Refusal(TOOL_FAILURE, f"{Path(path).name} does not parse: {error}") from error
        for keys in KANI_TABLES:
            table = parsed
            for key in keys:
                table = table.get(key) if isinstance(table, dict) else None
            if table is not None:
                raise Refusal(TOOL_FAILURE, f"{Path(path).name} configures Kani in {'.'.join(keys)}")
        if renamed := kani_dependency(parsed):
            raise Refusal(TOOL_FAILURE, f"{Path(path).name} configures Kani in {renamed}: a dependency whose name or package starts with kani "
                                        "gives a crate a name the source rule reads as another crate")


def kani_dependency(parsed):
    """Return `TABLE.NAME` for the first dependency whose name or `package` starts with `kani` in any letter case, or None.

    The dependency tables are the top-level ones, those under `workspace` and each `target`, and each `patch`
    source. Cargo binds a dependency's crate name to its key, so `k = { package = "kani" }` lets a source spell
    Kani's crate `k::`, and a key named `kani` on another package lets it spell that package `kani::`.
    """
    def table(value):
        return value if isinstance(value, dict) else {}

    holders = [((), parsed), (("workspace",), table(parsed.get("workspace")))]
    holders += [(("target", name), table(spec)) for name, spec in table(parsed.get("target")).items()]
    tables = [((*scope, kind), table(holder.get(kind))) for scope, holder in holders for kind in DEPENDENCY_TABLES]
    tables += [(("patch", source), table(entries)) for source, entries in table(parsed.get("patch")).items()]
    for scope, entries in tables:
        for name, spec in entries.items():
            package = spec.get("package", name) if isinstance(spec, dict) else name
            if any(str(text).lower().startswith("kani") for text in (name, package)):
                return ".".join((*scope, name))
    return None


def check_inventory(expected, listing):
    """Refuse a package whose harnesses differ from the declared ones."""
    found = sorted(name for names in (listing.get("standard-harnesses") or {}).values() for name in names)
    declared = sorted(expected["harnesses"])
    if found != declared:
        missing, extra = sorted(set(declared) - set(found)), sorted(set(found) - set(declared))
        raise Refusal(TOOL_FAILURE, f"the package's harnesses differ from the declaration: missing {missing}, undeclared {extra}")


def expected_command(expected, names, argv):
    """Return the worker count of a batch's one terse, parallel `cargo kani` run over `names`, refusing any other command."""
    head = ["cargo", "kani", "-p", expected["package"], "--exact"]
    for name in names:
        head += ["--harness", name]
    jobs = argv[len(head) + 1] if len(argv) > len(head) + 1 else ""
    shape = [*head, "-j", jobs, "--output-format", "terse", "--target-dir"]
    tail = ["-Z", "unstable-options", "--cbmc-args", *expected["cbmc"]]
    if argv[:len(shape)] != shape or argv[len(shape) + 1:] != tail or not re.fullmatch(r"[0-9]{1,6}", jobs) or int(jobs) < 2:
        raise Refusal(TOOL_FAILURE, f"the lane ran {argv[:8]}..., not cargo kani -p {expected['package']} --exact with the batch's {len(names)} harnesses, -j N for N of 2 or more, --output-format terse, --target-dir DIR, -Z unstable-options and --cbmc-args {' '.join(expected['cbmc'])}")
    return int(jobs)


START = re.compile(r"^Thread (\d+): Checking harness (\S+)\.\.\.$")
RESULT = re.compile(r"^Thread (\d+):$")


def blocks(text):
    """Return each harness's result lines, keyed by name, the started names, and in order each line after
    the first start that is neither a start, a result opening nor part of a result, from Kani's terse parallel output."""
    running, found, starts, unclaimed = {}, {}, {}, []
    current = None
    for line in (raw.strip() for raw in text.splitlines()):
        start, result = START.match(line), RESULT.match(line)
        if start:
            thread, name = start.groups()
            starts[name] = starts.get(name, 0) + 1
            running[thread], current = name, None
        elif result:
            name = running.pop(result.group(1), None)
            if name is None:
                raise Refusal(TOOL_FAILURE, f"thread {result.group(1)} reports a result for no started harness")
            if name in found:
                raise Refusal(TOOL_FAILURE, f"{name} reports two results")
            found[name], current = [], name
        elif current is not None and line:
            found[current].append(line)
            if line.startswith("Verification Time:"):
                current = None
        elif line and starts:
            unclaimed.append(line)
    repeated = sorted(name for name, count in starts.items() if count > 1)
    if repeated:
        raise Refusal(TOOL_FAILURE, f"harnesses {repeated} start more than once")
    return found, set(starts), unclaimed


def summaries(lines, label, name, what):
    """Return each `** A of B LABEL` line of one result as (A, B, undetermined, unreachable).

    A line in the single-spaced `** A of B LABEL` shape that does not parse whole, or whose counts sum past its
    total, refuses as a tool failure.
    """
    records = []
    for line in lines:
        if not re.match(rf"\*\* \S+ of \S+ {label}", line):
            continue
        match = re.fullmatch(rf"\*\* {COUNT} of {COUNT} {label}{STATUS}", line)
        if match is None:
            raise Refusal(TOOL_FAILURE, f"{name} prints a malformed {what} line: {line[:80]!r}")
        first, total, undetermined, unreachable, both_undetermined, both_unreachable = (int(group or 0) for group in match.groups())
        record = (first, total, undetermined + both_undetermined, unreachable + both_unreachable)
        if record[0] + record[2] + record[3] > total:
            raise Refusal(TOOL_FAILURE, f"{name} prints a {what} line whose counts exceed its total: {line[:80]!r}")
        records.append(record)
    return records


def judge_harness(name, declared, lines):
    """Return the counts of one complete verification that matches its declaration."""
    checks = summaries(lines, "failed", name, "check summary")
    if len(checks) != 1:
        raise Refusal(TOOL_FAILURE, f"{name} prints {len(checks)} check summary lines")
    failed, total, undetermined, unreachable = checks[0]
    if failed:
        raise Refusal(MISMATCH, f"{name} fails {failed} of {total} checks")
    if total == 0:
        raise Refusal(TOOL_FAILURE, f"{name} checked no property")
    if undetermined:
        raise Refusal(MISMATCH, f"{name} leaves {undetermined} of {total} checks undetermined")
    if unreachable == total:
        raise Refusal(TOOL_FAILURE, f"{name} reaches none of its {total} checks")
    covers = summaries(lines, "cover properties satisfied", name, "cover summary")
    wanted = declared["covers"]
    if len(covers) != 1 or covers[0] != (wanted, wanted, 0, 0):
        satisfied = covers[0] if len(covers) == 1 else (0, 0, 0, 0)
        status = f" ({satisfied[2]} undetermined, {satisfied[3]} unreachable)" if any(satisfied[2:]) else ""
        raise Refusal(MISMATCH, f"{name} satisfies {satisfied[0]} of {satisfied[1]} covers{status}, declared {wanted}")
    single(lines, r"^VERIFICATION:- SUCCESSFUL$", name, "VERIFICATION:- SUCCESSFUL")
    seconds = single(lines, r"^Verification Time: ([0-9]{1,12}(?:\.[0-9]{1,30})?)s$", name, "Verification Time").group(1)
    if unreachable != declared["unreachable"]:
        raise Refusal(MISMATCH, f"{name} reports {unreachable} unreachable checks, declared {declared['unreachable']}")
    # The checks above matched one check summary, one cover summary, one verdict and one time line.
    if len(lines) != 5 or lines[0] != "VERIFICATION RESULT:":
        raise Refusal(TOOL_FAILURE, f"{name} prints {len(lines)} result lines; a credited result is exactly VERIFICATION RESULT:, "
                                    "its check summary, its cover summary, VERIFICATION:- SUCCESSFUL and Verification Time")
    return {"checks": total, "unreachable": unreachable, "covers": wanted, "seconds": float(seconds)}


def check_surface(expected):
    """Refuse a Kani name outside `ADMITTED`, a `kani::` path outside the declared sources, and the crate's other spellings.

    Every listed `.rs` file is read as UTF-8 with each CRLF as LF. A file whose text holds `kani` has its
    comments blanked and is matched; a file without it holds no match, because blanking only removes text.
    A `kani::` path in a file outside the declared sources is refused, and in a declared source it must
    continue with an admitted name, which refuses brace and glob imports. A whole-word `kanitool`, an
    `extern crate` of a crate whose name starts with `kani`, any `kani as NAME` text and a first line that
    opens with `#!` other than `#![`, which rustc can drop as a shebang, are refused in every file. A raw
    string that the comment lexer opens directly after a quote, a `#` or a non-ASCII character is refused
    too: rustc can read its `r` as the end of the token before it, and the blanked text would then differ
    from the code rustc compiles. Each refusal names the file and line.
    """
    declared = {ROOT / name for name in expected["sources"]}
    for path in compiled_sources():
        if path.suffix != ".rs":
            continue
        raw = verus_call(verus.source_text, path)
        if "kani" not in raw:
            continue
        source = path.relative_to(ROOT)
        opening = raw.removeprefix("\ufeff")
        if opening.startswith("#!") and not opening.startswith("#!["):
            raise Refusal(TOOL_FAILURE, f"{source}:1 starts with a `#!` line other than `#![`, which rustc can drop as a shebang while the comment lexer reads it as code")
        # `GLUED_RAW.search(raw)` checks every offset, so a miss rules out a match at any lexeme start.
        if GLUED_RAW.search(raw):
            for _, begin, _ in rc11.rust_lexemes(raw):
                if glued := GLUED_RAW.match(raw, begin):
                    raise Refusal(TOOL_FAILURE, f"{located(source, raw, glued)} opens a raw string directly after a quote, `#` or non-ASCII character, "
                                                "where rustc can read the `r` as the end of the token before it and the comment lexer reads a raw string")
        text = verus_call(code_text, raw, source)
        if tool := KANITOOL.search(text):
            raise Refusal(TOOL_FAILURE, f"{located(source, text, tool)} spells kanitool, the attribute namespace Kani's macros expand to, "
                                        "which reaches Kani without an admitted kani:: name")
        if crate := KANI_CRATE.search(text):
            raise Refusal(TOOL_FAILURE, f"{located(source, text, crate)} declares extern crate {crate.group(1)}, which can import Kani's macros without a kani:: path")
        if alias := KANI_ALIAS.search(text):
            raise Refusal(TOOL_FAILURE, f"{located(source, text, alias)} spells `kani as NAME`, which imports the crate under another name")
        for match in KANI_PATH.finditer(text):
            if path not in declared:
                raise Refusal(TOOL_FAILURE, f"{located(source, text, match)} uses kani:: outside the declared sources")
            if match.group(1) not in ADMITTED:
                raise Refusal(TOOL_FAILURE, f"{located(source, text, match)} uses kani::{match.group(1)}, outside the admitted {', '.join(ADMITTED)}")


def verus_call(function, *args):
    """Call a Verus judge helper and re-raise its refusal as this judge's `Refusal`; each judge loads its own copy of the class."""
    try:
        return function(*args)
    except verus.Refusal as refusal:
        raise Refusal(refusal.code, str(refusal)) from refusal


def located(source, text, match):
    """Return `source:LINE` for the line where `match` starts; blanked comments keep their newlines, so lines index the source."""
    return f"{source}:{text.count(chr(10), 0, match.start()) + 1}"


def check_kani_config(evidence):
    """Refuse a recorded cargo configuration that redirects `cargo kani` away from the identified bundle.

    Cargo runs a user alias ahead of an external subcommand of the same name
    (rust-lang/cargo#10049), so `cargo kani` with `alias.kani` runs the
    aliased command, with the hashed `cargo-kani` idle. An `env.KANI_*` entry
    reaches the `cargo-kani` and `kani-driver` processes Cargo launches, and
    `KANI_HOME` selects the bundle they run, so it would bypass the identity
    the lane took directly.
    """
    config = read_json(evidence / "cargo-config.json")
    if not isinstance(config, dict):
        return
    alias = config.get("alias", {})
    if not isinstance(alias, dict):
        raise Refusal(TOOL_FAILURE, f"malformed evidence: the cargo configuration's alias is {type(alias).__name__}, where Cargo records a table")
    if "kani" in alias:
        raise Refusal(TOOL_FAILURE, f"the cargo configuration sets alias.kani = {alias['kani']!r}, which runs in place of cargo-kani")
    for name in sorted(config.get("env") or {}):
        if name.startswith("KANI"):
            raise Refusal(TOOL_FAILURE, f"the cargo configuration sets env.{name}, which redirects the Cargo-launched Kani processes")


def check_bound(evidence):
    """Refuse evidence that lacks `pins.txt` or `Cargo.lock`, or whose pins are not UTF-8.

    The judgment reads neither file, and a credited receipt binds the digest of each and states the
    pins as its tool provenance, so each must be a regular file and the pins must decode exactly.
    """
    for name in ("pins.txt", "Cargo.lock"):
        if not (evidence / name).is_file():
            raise Refusal(TOOL_FAILURE, f"the evidence holds no regular file {name}, which a credited receipt binds")
    try:
        (evidence / "pins.txt").read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(TOOL_FAILURE, f"pins.txt is not UTF-8: {error}") from error


def judge(evidence, expected, record, profile, revision):
    """Return the results of every harness of `profile`, judged batch by batch, or raise the first refusal."""
    check_identity(expected, record)
    check_bound(evidence)
    check_manifests()
    check_surface(expected)
    check_config(evidence)
    check_kani_config(evidence)
    check_inventory(expected, read_json(evidence / "kani-list.json"))
    planned = batches(expected, profile)
    files = batch_files(len(planned))
    run = check_run(evidence, profile, len(planned))
    check_provenance(evidence, run, revision)
    # An exit file counts as an interrupt only when the record binds it to its batch.
    for number, entry in enumerate(run["runs"], 1):
        path = evidence / files[number - 1]["exit"]
        if path.is_file() and entry["digests"].get("exit") == sha256(path) and (code := exit_code(path)) in INTERRUPTED:
            raise Refusal(INCOMPLETE, f"the {profile} run was interrupted (exit {code}){located_batch(number, len(files))}", "timeout")
    if run["timeout"] is not None:
        raise Refusal(INCOMPLETE, f"the {profile} run's total of {run['total']} s ran out at batch {run['timeout']} of {len(files)}", "timeout")
    if run["complete"] is not True:
        raise Refusal(TOOL_FAILURE, f"the {profile} run record is not marked complete: the lane stopped before its last batch exited")
    check_batch_files(evidence, profile, files)
    results = {}
    for number, names in enumerate(planned, 1):
        try:
            results.update(judge_batch(evidence, expected, record, names, files[number - 1], run["runs"][number - 1], run["workers"]))
        except Refusal as refusal:
            raise Refusal(refusal.code, f"{str(refusal).rstrip('.')}{located_batch(number, len(files))}", refusal.completion) from refusal
    return results


def located_batch(number, count):
    """Return the suffix that names batch `number` in a refusal of a profile of `count` batches, or nothing for one batch."""
    return "" if count == 1 else f" (batch {number} of {count})"


def exit_code(path):
    try:
        return int(path.read_text().strip())
    except ValueError as error:
        raise Refusal(TOOL_FAILURE, f"the run records no exit code in {path.name}: {error}") from error


def counted(value, least=1):
    """Whether `value` is an integer, not a boolean, of at least `least`."""
    return type(value) is int and value >= least


def instant(value):
    """Whether `value` is a finite, non-negative number of seconds, not a boolean."""
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def check_run(evidence, profile, count):
    """Refuse a run record of another shape than the lane writes for this judgment: an invocation, the judged
    profile, its declared batch count, a worker count of at least 2 within the recorded worker bound, a positive
    total, a timeout that names the batch after the last recorded one or the last itself, and one entry a recorded
    batch, numbered from 1 in order, each with its harness list, the digests of its files and its start and end in
    seconds; a record marked complete holds every batch and no timeout."""
    path = evidence / RUN_RECORD
    if not path.is_file():
        raise Refusal(TOOL_FAILURE, f"the evidence holds no run record {RUN_RECORD}")
    run = read_json(path)
    if not isinstance(run, dict) or not isinstance(run.get("invocation"), str) or not run["invocation"]:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} names no invocation")
    if run.get("profile") != profile:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records a run of the {run.get('profile')!r} profile, not {profile!r}")
    if not counted(run.get("count")) or run["count"] != count:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records {run.get('count')!r} batches; the {profile} profile declares {count}")
    if not counted(run.get("workers"), 2):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records workers {run.get('workers')!r}, where the lane records a count of at least 2")
    if not counted(run.get("total")):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records total {run.get('total')!r}, where the lane records a positive count of seconds")
    if run.get("cap") is not None and (not counted(run["cap"]) or run["cap"] < run["workers"]):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records the worker bound {run['cap']!r} beside {run['workers']} workers")
    runs = run.get("runs")
    if not isinstance(runs, list) or not all(isinstance(entry, dict) for entry in runs):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records no list of batches")
    indices = [entry.get("index") for entry in runs]
    if len(runs) > count or any(type(index) is not int or index != at for at, index in enumerate(indices, 1)):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records the batches {indices}, where the lane records 1 to at most {count} in order")
    for entry in runs:
        if not isinstance(entry.get("harnesses"), list) or not isinstance(entry.get("digests"), dict):
            raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records batch {entry['index']} without its harness list and file digests")
        if not (instant(entry.get("start")) and instant(entry.get("end")) and entry["start"] <= entry["end"]):
            raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records batch {entry['index']} from {entry.get('start')!r} to {entry.get('end')!r} s")
    timeout = run.get("timeout")
    if timeout is not None and (type(timeout) is not int or timeout not in (len(runs), len(runs) + 1) or not 1 <= timeout <= count):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records the timeout {timeout!r}, where the lane records the last or the next batch of {len(runs)}")
    if run.get("complete") is True and (len(runs) != count or timeout is not None):
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} is marked complete without its {count} batches or beside a timeout")
    return run


def check_provenance(evidence, run, revision):
    """Refuse a run record whose run, or any batch of it, ran at another revision than the judged one, on a tree that
    did not match it at each of the record's samples, or against another workspace lock file than the evidence's."""
    lock = sha256(evidence / "Cargo.lock")
    if run.get("revision") != revision:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records revision {run.get('revision')!r}, not the judged {revision!r}")
    if run.get("clean") is not True:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records a tree whose tracked files differed from revision {revision}")
    if run.get("lock") != lock:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records another Cargo.lock than the evidence's")
    for entry in run["runs"]:
        if entry.get("revision") != revision or entry.get("clean") is not True:
            raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records batch {entry['index']} at revision {entry.get('revision')!r} on a "
                                        f"{'clean' if entry.get('clean') is True else 'changed'} tree; the run began at {revision} on a clean tree")
        if entry.get("lock") != lock:
            raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records batch {entry['index']} against another Cargo.lock than the evidence's")


def check_batch_files(evidence, profile, files):
    """Refuse an evidence directory whose batch files are other than the declared ones, in their one form."""
    declared = {name for batch in files for name in batch.values()}
    present = {path.name for path in evidence.iterdir() if BATCH_FILE.fullmatch(path.name)}
    if present != declared:
        missing, stray = sorted(declared - present), sorted(present - declared)
        if not present & declared:
            raise Refusal(TOOL_FAILURE, f"the {profile} profile has no recorded run; stray {stray}")
        raise Refusal(TOOL_FAILURE, f"the {profile} run's batch files differ from its {len(files)} declared batches: missing {missing}, stray {stray}")


def judge_batch(evidence, expected, record, names, files, entry, workers):
    """Return the results of one batch's harnesses from its own command, output and exit code, each read once: the
    bytes whose digest matches the run record's entry are the bytes judged."""
    read = {kind: (evidence / name).read_bytes() for kind, name in files.items()}
    if any(entry["digests"].get(kind) != hashlib.sha256(data).hexdigest() for kind, data in read.items()):
        raise Refusal(TOOL_FAILURE, f"the files of {files['txt'].removesuffix('.txt')} differ from the digests {RUN_RECORD} records for its batch")
    try:
        argv = read["argv"].decode("utf-8").replace("\r\n", "\n").splitlines()
    except UnicodeDecodeError as error:
        raise Refusal(TOOL_FAILURE, f"{files['argv']} is not UTF-8: {error}") from error
    jobs = expected_command(expected, names, argv)
    if jobs != workers:
        raise Refusal(TOOL_FAILURE, f"the batch ran -j {jobs}; {RUN_RECORD} records {workers} workers")
    if entry["harnesses"] != names:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} records another harness list for the batch than the declaration's")
    try:
        code = int(read["exit"].decode("ascii").strip())
    except (UnicodeDecodeError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"the run records no exit code in {files['exit']}: {error}") from error
    text = read["txt"].decode("utf-8", errors="replace")
    # A harness whose CBMC process fails prints `CBMC` lines inside its result, which `judge_harness` refuses by name.
    header = list(takewhile(lambda line: not START.match(line.strip()), text.splitlines()))
    identified = record["version"].splitlines()[0]
    kani = [line.strip() for line in header if line.strip().startswith("Kani Rust Verifier")]
    if kani != [identified]:
        raise Refusal(TOOL_FAILURE, f"the run reports Kani {kani}; the identified Kani is {identified!r}")
    cbmc = cbmc_versions(header)
    bundled = COMPARED[expected["kani"]][0]
    if cbmc != [bundled]:
        raise Refusal(TOOL_FAILURE, f"the run reports CBMC {cbmc}; the cbmc arguments were compared under Kani {expected['kani']} "
                                    f"with CBMC {bundled}")
    found, started, unclaimed = blocks(text)
    if started != set(names) or set(found) != set(names):
        missing = sorted(set(names) - set(found))
        raise Refusal(TOOL_FAILURE, f"the run checked {len(started)} and reported {len(found)} of the batch's {len(names)} harnesses; no result for {missing[:3]}")
    results = {name: judge_harness(name, expected["harnesses"][name], found[name]) for name in names}
    count = len(names)
    complete = [line for line in (raw.strip() for raw in text.splitlines()) if re.match(r"Complete\s*-", line)]
    if complete != [f"Complete - {count} successfully verified harnesses, 0 failures, {count} total."]:
        raise Refusal(TOOL_FAILURE, f"the run prints {len(complete)} Complete lines, {complete[:2]}; one for the batch's {count} harnesses credits")
    if code != 0:
        raise Refusal(TOOL_FAILURE, f"the run exited {code}")
    trailer = [line for line in (raw.strip() for raw in text.splitlines()) if line][-2:]
    if unclaimed != ["Manual Harness Summary:", *complete] or trailer != unclaimed:
        raise Refusal(TOOL_FAILURE, f"the run prints {len(unclaimed)} lines outside its harness results, {[line[:80] for line in unclaimed[:3]]}; "
                                    "a credited run prints its harness starts and results, then ends with Manual Harness Summary: and its Complete line")
    return results


def refresh_index():
    """Refresh the stat data of the checkout's index once, before the run's first sample. Git compares by content
    every entry whose stat data differs from the file's or whose file is no older than the index; the refresh hashes
    those files once and writes the index anew with the matching stat data, so each later sample hashes only the
    files whose stat data changed since and the files written in the second of the refresh. Git from 2.36 writes the
    index also when every entry's stat data already matched; an older git leaves such an index, and the samples then
    compare as before. The refresh changes no entry's mode, object, stage or flag.

    Git's stat data includes the inode change time in whole seconds, which an edit sets and no caller can set back,
    so after the refresh an edit made in a later second than the file's last inode change shows as a change, a
    same-size edit whose modification time is set back included. A checkout whose git skips that time
    (`core.trustctime` false or `core.checkStat` minimal) gets no refresh, and its samples compare as before.
    `update-index` holds the checkout's `index.lock` while it hashes, and a git command that writes the index in that
    time fails. A refresh that finds the lock held hashes the same files, writes nothing and exits without waiting
    for the lock, and the samples then compare as before."""
    def config(*args):
        return subprocess.run(["git", "-C", str(ROOT), "config", *args], capture_output=True, text=True, check=False).stdout.strip()
    if config("--type=bool", "--get", "core.trustctime") == "false" or config("--get", "core.checkStat").lower() == "minimal":
        return
    subprocess.run(["git", "-C", str(ROOT), "update-index", "-q", "--refresh"], capture_output=True, check=False)


def tree_state():
    """Return the checked-out revision and whether every tracked file shows its commit's bytes: none differs in the
    working tree or the index, and no assume-unchanged or skip-worktree flag hides one from that comparison. Git's
    output stays bytes, so a path in any encoding compares by its bytes, and the status names HEAD's object, which is
    the revision."""
    def git(*args):
        return subprocess.run(["git", "--no-optional-locks", "-C", str(ROOT), *args], capture_output=True, check=False)
    status, flags = git("status", "--porcelain=v2", "--branch", "--no-ahead-behind", "--untracked-files=no"), git("ls-files", "-v", "-z")
    lines = status.stdout.splitlines()
    head = [line.split(b" ")[2].decode("ascii", errors="replace") for line in lines if line.startswith(b"# branch.oid ")]
    revision = head[0] if status.returncode == 0 and head and head[0] != "(initial)" else rc11.git_revision()
    # `ls-files -v` tags an entry H when git compares it and with another letter when a flag hides it.
    hidden = any(entry and entry[:1] != b"H" for entry in flags.stdout.split(b"\0"))
    unchanged = status.returncode == 0 and len(head) == 1 and all(line.startswith(b"# ") for line in lines)
    return revision, unchanged and flags.returncode == 0 and not hidden


def lock_digest():
    """Return the sha256 of the workspace lock file every batch resolves against, or None when there is none."""
    path = ROOT / "Cargo.lock"
    return sha256(path) if path.is_file() else None


def write_run(evidence, run):
    """Replace the run record whole, so a reader sees the record before or after one step."""
    path = evidence / RUN_RECORD
    staged = path.with_name(f"{RUN_RECORD}.tmp")
    staged.write_text(json.dumps(run, indent=2, sort_keys=True) + "\n")
    os.replace(staged, path)


def number(value, name, kind: type = int, least=0):
    """Return option `name` converted by `kind`, refusing a missing, malformed or smaller value."""
    try:
        converted = kind(value)
    except (TypeError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"record needs {name} as a number: {value!r}") from error
    if not (math.isfinite(converted) and converted >= least):
        raise Refusal(TOOL_FAILURE, f"record needs {name} of at least {least}: {value!r}")
    return converted


def record_run(args):
    """Write the lane's run record: `begin` before the first batch, `remaining` to print the whole seconds the total leaves and the seconds since `begin`,
    `batch` as each batch's child exits, `timeout` when the total runs out at a batch, and `complete` after the
    last batch's child exits inside the total. Every time is taken on one monotonic clock from `begin`."""
    evidence = Path(args.evidence)
    if args.action == "begin":
        workers, total = number(args.workers, "--workers", least=2), number(args.total, "--total", least=1)
        cap = number(args.cap, "--cap", least=1) if args.cap else None
        count = len(batches(declaration(), args.profile))
        refresh_index()
        revision, clean = tree_state()
        write_run(evidence, {
            "invocation": uuid.uuid4().hex, "profile": args.profile, "revision": revision, "clean": clean, "lock": lock_digest(),
            "workers": workers, "cap": cap, "total": total, "started": time.time(), "clock": time.monotonic(),
            "count": count, "runs": [], "timeout": None, "complete": False,
        })
        return CREDITED
    run = read_json(evidence / RUN_RECORD)
    if not isinstance(run, dict) or not counted(run.get("count")) or not isinstance(run.get("runs"), list) or type(run.get("clock")) is not float:
        raise Refusal(TOOL_FAILURE, f"{RUN_RECORD} is not a run record the lane began")
    elapsed = time.monotonic() - run["clock"]
    if args.action == "remaining":
        print(max(0, int(run["total"] - elapsed)), f"{elapsed:.3f}")
        return CREDITED
    index = number(args.index, "--index", least=1) if args.action in ("batch", "timeout") else 0
    if args.action in ("batch", "timeout"):
        recorded = len(run["runs"])
        follows = index == recorded + 1 if args.action == "batch" else index in (recorded, recorded + 1)
        if index > run["count"] or not follows:
            raise Refusal(TOOL_FAILURE, f"record {args.action} --index {index} does not follow the {recorded} recorded of {run['count']} batches")
    if args.action == "batch":
        files = batch_files(run["count"])[index - 1]
        argv = verus_call(verus.utf8_text, evidence / files["argv"]).splitlines() if (evidence / files["argv"]).is_file() else []
        revision, clean = tree_state()
        run["runs"].append({
            "index": index, "harnesses": [argv[at + 1] for at in range(len(argv) - 1) if argv[at] == "--harness"],
            "digests": {kind: sha256(evidence / name) if (evidence / name).is_file() else None for kind, name in files.items()},
            "revision": revision, "clean": clean, "lock": lock_digest(),
            "start": round(number(args.start, "--start", float), 3), "end": round(elapsed, 3),
        })
    elif args.action == "timeout":
        run["timeout"] = index
    else:
        indices = [entry["index"] for entry in run["runs"]]
        run["complete"] = indices == list(range(1, run["count"] + 1)) and run["timeout"] is None
    write_run(evidence, run)
    return CREDITED


def compiled_sources():
    """Return the manifests and every tracked file of the local packages a build of `kestrike` compiles."""
    try:
        listed = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z", "--", *(str(root) for root in COMPILED)],
                                capture_output=True, check=True).stdout
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refusal(TOOL_FAILURE, f"git ls-files cannot list the compiled packages: {error}") from error
    try:
        names = listed.decode().split("\0")
    except UnicodeDecodeError as error:
        raise Refusal(TOOL_FAILURE, f"git ls-files lists a compiled path that is not UTF-8: {error}") from error
    return [*MANIFESTS, *sorted(ROOT / name for name in names if name)]


def committed():
    """Return the committed files a judgment depends on: the declaration, the Verus declaration and inventory
    its gap closures are checked against, the manifests and every tracked file of the local packages the
    harness build compiles, so a receipt binds each source a proof read."""
    return [EXPECTED, VERUS, INVENTORY, *compiled_sources()]


def inputs(evidence, credited=True):
    """Return the digests a receipt binds. A credited receipt binds every input; a refusal binds each one it can read."""
    names = ["identity.json", "pins.txt", "report.json", "cargo-config.json", "kani-list.json", RUN_RECORD, "Cargo.lock"]
    names += sorted(path.name for path in evidence.iterdir() if BATCH_FILE.fullmatch(path.name)) if evidence.is_dir() else []
    digests = {name: sha256(evidence / name) for name in names if (evidence / name).is_file()}
    try:
        files = committed()
    except Refusal:
        if credited:
            raise
        files = [EXPECTED, VERUS, INVENTORY, *MANIFESTS]
    for path in [ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json", ROOT / "verification/obligations.json", *files]:
        try:
            digests[str(path.relative_to(ROOT))] = sha256(path)
        except OSError:
            if credited:
                raise
    return digests


def receipt(evidence, revision, profile, completion, code, reason, results):
    pins, expected = evidence / "pins.txt", declaration()
    return {
        "job": "kani", "module": profile, "lane": f"kani {profile}", "revision": revision,
        "inputs": inputs(evidence, code == CREDITED),
        "tool": {"name": "kani", "provenance": pins.read_bytes().decode("utf-8", errors="replace").strip().splitlines() if pins.is_file() else []},
        "assumptions": [
            "bit-precise bounded proofs of the harnesses' stated domains only",
            "default Kani checks: assertions, arithmetic overflow, pointers, unwinding and covers",
            *(f"unproved: {limit}" for limit in expected.get("limits", {}).values()),
            *gap_assumptions(expected),
        ],
        "bounds": {"harnesses": results},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": sum(result["checks"] for result in results.values()) if code == CREDITED else 0,
        "executed": sorted(results) if code == CREDITED else [], "failed": [],
        "replay": f"bash scripts/rust-lane.sh kani {profile}",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def gap_assumptions(expected):
    """Return each family's gaps as the receipt states them: the Verus items that close them, or unproved."""
    stated = []
    for family, gaps in expected["gaps"].items():
        lengths = ", ".join(f"{lo}..{hi}" for lo, hi in gaps)
        items, trusts = expected["closures"][family], expected["trusts"][family]
        trusting = f"; trusts {', '.join(trusts)}" if trusts else ""
        stated.append(f"closed: {family} at chunk lengths {lengths} units rests on {', '.join(items)}{trusting}" if items
                      else f"unproved: {family} at chunk lengths {lengths} units")
    return stated


def derive(evidence, revision, profile):
    """Judge the evidence directory for `profile` and return the report and the receipt it supports, writing neither."""
    code, reason, results, completion = CREDITED, None, {}, "completed"
    try:
        results = judge(evidence, declaration(), read_json(evidence / "identity.json"), profile, revision)
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, RecursionError) as error:
        code, reason, completion = TOOL_FAILURE, f"malformed evidence: {error!r}", "tool failure"
    except OSError as error:
        code, reason, completion = TOOL_FAILURE, f"the judgment cannot read an input: {error}", "tool failure"
    report = {"code": code, "verdict": VERDICTS[code], "credited": code == CREDITED, "reason": reason,
              "profile": profile, "harnesses": results}
    return report, receipt(evidence, revision, profile, completion, code, reason, results)


def run_judge(args):
    evidence = Path(args.evidence)
    report, derived = derive(evidence, args.revision or rc11.git_revision(), args.profile)
    (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    derived["inputs"]["report.json"] = sha256(evidence / "report.json")
    (evidence / "receipt.json").write_text(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"judge-kani: {report['reason']}", file=sys.stderr)
    return report["code"]


def exported(path, expected):
    """Return each harness's checks of a `cargo kani --export-json` file as a multiset of (function, category,
    description, file, line, column, status), with the harness's own status.

    Refuses a file of another shape, of another Kani release than the declared one or of another CBMC than `COMPARED`
    records for it, and a file that holds an undeclared harness or none.
    """
    data = read_json(path)
    try:
        kani, cbmc = data["metadata"]["kani_version"], data["tools"]["cbmc"]
        harnesses = {}
        for result in data["verification_results"]["results"]:
            checks = Counter()
            for check in result["checks"]:
                place = check.get("location") or {}
                checks[(check["function"], check["category"], check["description"], place.get("file"), place.get("line"), place.get("column"),
                        check["status"])] += 1
            if result["harness_id"] in harnesses:
                raise Refusal(TOOL_FAILURE, f"{path} reports {result['harness_id']} twice")
            harnesses[result["harness_id"]] = (result["status"], checks)
    except (KeyError, TypeError, AttributeError) as error:
        raise Refusal(TOOL_FAILURE, f"{path} is no `cargo kani --export-json` file: {error!r}") from error
    bundled = COMPARED[expected["kani"]][0]
    if kani != expected["kani"] or not isinstance(cbmc, str) or cbmc.split()[:1] != [bundled]:
        raise Refusal(TOOL_FAILURE, f"{path} is a run of Kani {kani!r} with CBMC {cbmc!r}; the declaration compares under Kani {expected['kani']} with CBMC {bundled}")
    undeclared = sorted(set(harnesses) - set(expected["harnesses"]))
    if undeclared or not harnesses:
        raise Refusal(TOOL_FAILURE, f"{path} holds {undeclared[0] if undeclared else 'no harness'}, where a comparison holds declared harnesses")
    return harnesses


def compare_harness(without, under):
    """Return what keeps one harness's two runs from the comparison's equality, an empty list when it holds.

    The equality: both runs verify; every check the run under the `cbmc` arguments reports, the run without them
    reports with the same function, category, description, place and status; each check only the run without them
    reports is an unwinding assertion that succeeded; the covers with their statuses and the count of unreachable
    checks are the same.
    """
    (status_without, checks_without), (status_under, checks_under) = without, under
    found = []
    if (status_without, status_under) != ("Success", "Success"):
        found.append(f"the runs end {status_without} without the arguments and {status_under} under them")
    added = checks_under - checks_without
    if added:
        found.append(f"{sum(added.values())} checks under the arguments are absent or of another status without them, first {min(added, key=str)}")
    dropped = [key for key in (checks_without - checks_under) if (key[1], key[6]) != ("unwind", "Success")]
    if dropped:
        found.append(f"{len(dropped)} checks other than successful unwinding assertions are missing under the arguments, first {min(dropped, key=str)}")
    covers = [Counter({key: count for key, count in checks.items() if key[1] == "cover"}) for checks in (checks_without, checks_under)]
    if covers[0] != covers[1]:
        found.append("the covers or their statuses differ")
    unreachable = [sum(count for key, count in checks.items() if key[6] == "Unreachable") for checks in (checks_without, checks_under)]
    if unreachable[0] != unreachable[1]:
        found.append(f"{unreachable[0]} checks are unreachable without the arguments and {unreachable[1]} under them")
    return found


def compared_runs(evidence, expected):
    """Return the harness names and the two export paths of a recorded comparison, refusing a record whose two argv
    are not the lane's comparison of the same declared harnesses without and under the `cbmc` arguments."""
    arms = {}
    for arm in ("without", "with"):
        argv = verus_call(verus.utf8_text, evidence / f"compare-{arm}.argv").splitlines()
        head = ["cargo", "kani", "-p", expected["package"], "--exact"]
        names = []
        while argv[len(head):len(head) + 1] == ["--harness"] and len(argv) > len(head) + 1:
            names.append(argv[len(head) + 1])
            head += argv[len(head):len(head) + 2]
        export = evidence / f"compare-{arm}.json"
        jobs = argv[len(head) + 1] if len(argv) > len(head) + 1 else ""
        shape = [*head, "-j", jobs, "--output-format", "terse", "--target-dir"]
        # The lane writes the export path under EVIDENCE as it was given, so the path is compared as a path.
        ahead, named, tail = argv[len(shape) + 1:len(shape) + 4], argv[len(shape) + 4:len(shape) + 5], argv[len(shape) + 5:]
        if (not names or argv[:len(shape)] != shape or ahead != ["-Z", "unstable-options", "--export-json"] or [Path(path) for path in named] != [export]
                or tail != (["--cbmc-args", *expected["cbmc"]] if arm == "with" else []) or not re.fullmatch(r"[0-9]{1,6}", jobs)):
            raise Refusal(TOOL_FAILURE, f"compare-{arm}.argv is {argv[:6]}...{argv[-4:]}, not cargo kani -p {expected['package']} --exact with its "
                                        f"harnesses, -j N, --output-format terse, --target-dir DIR, -Z unstable-options, --export-json {export}"
                                        + (f" and --cbmc-args {' '.join(expected['cbmc'])}" if arm == "with" else " and nothing after it"))
        try:
            code = int((evidence / f"compare-{arm}.exit").read_text().strip())
        except (OSError, ValueError) as error:
            raise Refusal(TOOL_FAILURE, f"the run {arm} the cbmc arguments records no exit code: {error}") from error
        if code != 0:
            raise Refusal(TOOL_FAILURE, f"the run {arm} the cbmc arguments exited {code}; a harness that runs out of memory or time without them "
                                        "is listed in argument_only with that run's figures, and no other failed run is compared")
        arms[arm] = (names, export)
    if arms["without"][0] != arms["with"][0]:
        raise Refusal(TOOL_FAILURE, "the two recorded runs name different harnesses")
    return arms["without"][0], arms["without"][1], arms["with"][1]


def compare(args):
    """Compare the two runs of a recorded comparison, one without the `cbmc` arguments and one under them.

    Prints a report and returns 0 when every harness meets the equality of `compare_harness`, 1 when one does not,
    and refuses a record `compared_runs` or `exported` refuses and exports that hold other harnesses than the argv.
    """
    expected = declaration(comparison=False)
    names, without_path, under_path = compared_runs(Path(args.evidence), expected)
    without, under = exported(without_path, expected), exported(under_path, expected)
    if set(without) != set(names) or set(under) != set(names):
        raise Refusal(TOOL_FAILURE, f"the exports hold other harnesses than the {len(names)} the recorded runs name, "
                                    f"{sorted((set(without) | set(under)) ^ set(names))[:3]}")
    differing = {name: found for name in sorted(without) if (found := compare_harness(without[name], under[name]))}
    fewer = {name: sum((without[name][1] - under[name][1]).values()) for name in sorted(without) if without[name][1] != under[name][1] and name not in differing}
    print(json.dumps({"harnesses": len(without), "checks": sum(sum(checks.values()) for _, checks in without.values()), "equal": len(without) - len(differing),
                      "unwinding_assertions_dropped": fewer, "differing": differing}, indent=2, sort_keys=True))
    return MISMATCH if differing else CREDITED


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Check the Kani installation and judge its harness runs.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["cases", "batches", "arguments", "identity", "inventory", "judge", "record", "compare", "bands"])
    parser.add_argument("action", nargs="?", choices=["begin", "remaining", "batch", "timeout", "complete"])
    parser.add_argument("--profile")
    parser.add_argument("--kani-home")
    parser.add_argument("--cargo-kani")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    parser.add_argument("--workers")
    parser.add_argument("--cap")
    parser.add_argument("--total")
    parser.add_argument("--index")
    parser.add_argument("--start")
    args = parser.parse_args(argv)
    try:
        if args.command == "cases":
            print("\n".join(profile_cases(declaration(), args.profile)))
            return CREDITED
        if args.command == "batches":
            print("\n".join(" ".join(batch) for batch in batches(declaration(), args.profile)))
            return CREDITED
        if args.command == "arguments":
            # The comparison lane reads the arguments for a harness no list names yet; `cases` holds the list check for the profiles.
            print("\n".join(declaration(comparison=False)["cbmc"]))
            return CREDITED
        if args.command == "bands":
            for path, text in band_sources(read_json(EXPECTED)).items():
                path.write_text(text)
            return CREDITED
        if not args.evidence:
            parser.error(f"{args.command} needs --evidence")
        if args.command == "compare":
            return compare(args)
        if args.command == "identity":
            if not args.kani_home or not args.cargo_kani:
                parser.error("identity needs --kani-home and --cargo-kani")
            return identity(args)
        if args.command == "inventory":
            check_inventory(declaration(), read_json(Path(args.evidence) / "kani-list.json"))
            return CREDITED
        if args.command == "record":
            if not args.action or args.action == "begin" and not args.profile:
                parser.error("record needs begin --profile NAME, batch, timeout or complete")
            if args.action in ("batch", "timeout") and not args.index or args.action == "batch" and not args.start:
                parser.error(f"record {args.action} needs --index{' and --start' if args.action == 'batch' else ''}")
            return record_run(args)
        if not args.profile:
            parser.error("judge needs --profile")
        return run_judge(args)
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-kani: {error}", file=sys.stderr)
        return TOOL_FAILURE


if __name__ == "__main__":
    sys.exit(main())
