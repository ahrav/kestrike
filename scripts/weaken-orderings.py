#!/usr/bin/env python3
"""Check the ordering catalog in verification/orderings/expected.json against the scoped production files, and run each
row's weakening against its model tests in a copy of the checkout.

Usage:
  weaken-orderings.py check
  weaken-orderings.py run --work DIR [--row ID]...

The catalog names the scoped `files`, the production files the GenMC kernel
package compiles by `#[path]`, and holds one row per site and step. A site
is one `Ordering` stronger than `Relaxed`, or one fence call, in a file's
production text: its text with each test-only element blanked, as
`blanked` in `scripts/classify-atomics.py` returns it. An element ends at
the close of its first `{...}` block at the latest, and the text of an
element that continues past that block is read as production text. A
scoped file holds no element that `analyzed` there lists as cut: each
test-only element ends at the same offset under every reading that applies
where it stands, at no `,` that may lie among its own generic arguments or
closure parameters, and, unless it is an item or a statement, outside
every macro's tokens. Sites are matched outside comments and literals. A
fence call is a call of a path, a leading `::` included, whose last
segment holds `fence`, declarations and definitions
aside. A hook of `HOOKS` mentioned as `S::NAME` is excluded by name while
the file holds at least one definition of it with a body and every such
body is empty; the rule reads only that file. An ordering passed directly
to a fence call belongs to the fence; an ordering nested deeper in the
fence's arguments is a site of its own. A scoped file's production text
spells each ordering variant as part of an `Ordering::` path and names
each fence path only in a path call whose callee the matcher delimits
whole, a macro fragment, or a forwarder invocation
`name!(<type>, std::sync::atomic::fence);`. Each `$fence` call sits in
the body of a `macro_rules!` that is one arm
`($name:ty, $fence:path) => {..}`. That macro's production invocations, at
least one, all pass `std::sync::atomic::fence`, lie among no other macro's
tokens and follow the definition with only blank text between, so each
invocation expands that arm; no other macro receives the std fence. This
binds each forwarder's source text to the std fence; the type argument
stays free.

A step is one level of weakening: `SeqCst` goes to `Acquire` for a `load`,
`Release` for a `store` and `AcqRel` for an `rmw`; `AcqRel` goes to
`Acquire` and to `Release`, so its site takes two rows; `Release` and
`Acquire` go to `Relaxed`; a `fence` row deletes the call and a `;`
directly after it. The matcher reads the `op` of an ordering from the
atomic method, called as `receiver.method(...)`, whose argument it is. A
compare-exchange's success ordering is an `rmw` and its failure ordering a
`load`, and `fetch_update`'s set and fetch orderings are an `rmw` and a
`load`, each read by argument position while no earlier argument holds
`<` or `>` outside brackets. The `op` of a strength constant, a
`const NAME: Ordering` item, comes from each `S::NAME` mention in its
file's scanned production text: the mentions must all sit in atomic calls
of one op. A constant with no such mention takes its op from `EXTERNAL`,
a pin kept by hand and keyed by the defining file and the constant's
name: `RELOAD` of `storage/credit.rs` reaches `record_credits` in
`storage/lease.rs` as `S::RELOAD`, and both of its `credit::credits` calls
load with it. Any other constant with no mention is unread. The row's
`op` must agree with the one the matcher reads.

A row holds `id`, `path`, `find`, text that occurs exactly once in the
file's production text and holds exactly one site, `replace`, the `find`
after one step, and `op` (`load`, `store`, `rmw` or `fence`). It may hold
a GenMC `binding` and a `twin` list. Each twin entry names a `lane`
(`loom`, `genmc` or `rc11`), a `test` and `steps`, the positive number of
steps by which that existing control weakens the same site; only a
one-step twin predicts the row's own result. A row holds exactly one
disposition:

- `kill`: a nonempty list with at most one entry per lane, each `lane`
  (`loom` or `genmc`), `tests` and `failure`, recording that the named
  tests failed with `failure` under the row's plant;
- `survives`: `reason` and `passed`, a list of `lane` and `tests` entries
  that passed under the plant, empty when no model run decides the site;
- `unrun`: `needs`, a list of `lane`, `tests` and `failure` entries naming
  the runs that decide the row and a failure each would count as a kill,
  or an empty list beside a `reason` that states why no model run decides
  the site.

The rows whose sites no model run decides are those of `UNMODELED`, a pin
kept by hand and keyed by row id. Only they may hold an empty `passed` or
`needs`; every other row names at least one run.

A `kill` or `survives` row records the `revision`, the 40-hex-digit
commit, of the run that set it. A row without a binding names its
enclosing item in `scope`, given as a binding's `scope` is: the nested
item headers, an `impl` header for a strength constant. An item's body is
the first `{` block after its header, and a `;` before that brace ends the
search, so a header whose signature holds a `;`, such as `[W; N]`, is
named through its return type. A bound row's enclosing item is its
binding's production scope, and its `find` holds the binding's call. The
binding guard of `scripts/judge-genmc.py` holds that call to its scope.

A loom test's model source is the module file its path reaches from
`crates/kestrike/src/mod.rs`: each module the path names is loaded by
its parent's declaration, a `#[path]` one or a bare `mod name;`, read as
the scope rule below reads declarations, and the last file reached
declares the remaining module inline. A module that its parent declares
more than once, inline or by two files, has no model source. A GenMC
case's kernel file is the one file of the kernel package named
`<family>_kernel.rs`, the family being the leading lowercase letters of the
case name; `check` and `run` find it by the same rule.

An included file is classified by the declarations that load it and by
the standing of each module file that holds one, read up to the crate
root: `mod.rs`, `lib.rs` and `main.rs` of `crates/kestrike/src`, which
stand as production. A bare `mod name;` loads `name.rs` or `name/mod.rs`
from the directory its module file's declarations load from: the crate's
source directory for a root, `D` for `D/mod.rs`, `D` for the sibling
`D.rs` that a bare `mod D;` loads, and its own directory for a file a path
attribute loads. A `#[path = "..."]` on a `mod` item loads that path from
the module file's own directory. Inside inline `mod` blocks both load from
the declaring directory extended by the blocks' names. A module file's
standing is the standing its own declarations give it, and only a module
file with standing gives one: a live declaration passes its module file's
standing on, a declaration inside a test-only item of a production module
file excludes, and an excluded module file excludes. A path attribute
counts in a root, in a module file whose bare declarations load from the
included file's directory, and nowhere else: a declaration from another
crate source is refused. The crate sources searched for path attributes
are those whose committed text holds one. The file is production when a
chain of live declarations from a root loads it, and excluded when every
chain that loads it passes a test-only item. Among the tokens of a macro,
a `macro_rules!` definition or an invocation, a path attribute or a `mod`
keyword loads nothing. A module name may be a raw identifier.

`check` refuses, each by name:

- `unrowed site`: a site that no accepted row's `find` holds; `site rows`:
  a site whose rows are not one per step;
- `find`: a `find` that does not occur exactly once in its file's
  production text, or that holds other than one site;
- `step`: a `replace` that is not its `find` after one step for its `op`,
  an `op` the matcher reads otherwise, or a rowed site whose `op` the
  matcher cannot read;
- `spelling`: in a scoped file's production text, an ordering variant
  outside an `Ordering::` path, a test-only element that `analyzed` lists
  as cut, a glob import of `Ordering`'s variants, an
  `Ordering as` rename, a fence path named outside a call, a fence called
  as a method, a fence callee the matcher cannot delimit, a `$fence` call
  outside a `macro_rules!` body, a macro holding a `$fence` call that is
  never invoked, is invoked among another macro's tokens, whose
  invocations pass another fence, that is not one arm
  `($name:ty, $fence:path) => {..}` or that an invocation does not
  directly follow, or a macro that receives `std::sync::atomic::fence`
  and holds no `$fence` call;
- `scope file`: a production file the kernel package includes by `#[path]`
  that `files` lacks, a listed file the package does not include as
  production, a listed file that cannot be read, a file the package
  includes from outside the repository, an included file that no module
  file declares through declarations that reach the crate root or that
  only a path attribute outside its module files and the crate root
  declares, a module file that cannot be read, a module file holding
  a path attribute the scope rule cannot read, or a path attribute or a
  `mod` keyword among a macro's tokens, a live path attribute of a
  package source that the shared include scanner misses or a match of
  that scanner outside live code, an include path holding an escape, an
  include inside the package that is no Rust source the scan reads, the
  name `include` in a package source's code, or a scoped file whose
  production text names `include` or holds a path attribute or a `mod`
  keyword, whether it declares a file or opens an inline module (the raw
  identifier `r#mod` is a name); the
  report lists the files declared only in test-only items under
  `excluded`;
- `reference`: a `binding` absent from `verification/genmc/expected.json`,
  bound in another file, holding no call or scope, or whose call the row's
  `find` lacks; a twin list that is no list of entries, a twin whose `test`
  is no twin of its `lane` (a loom control of a loom record of
  `verification/obligations.json`, a GenMC violation case, a `Sometimes`
  litmus test) or whose `steps` is no positive integer, or a lane named
  twice; an entry test that its lane does not hold as positive (for `loom`
  a test a loom record lists under `tests` and no loom record lists under
  `controls`, for `genmc` a `positive` GenMC case); a loom test whose
  model source cannot be read; a loom `failure` that some model source of
  its tests holds in no message literal of an assertion, a panic or an
  `expect`, as the whole literal, its text before the first `{`, or the
  text after one of its `: ` separators, or that more than one message
  literal of one model source holds; or a GenMC `failure` that is not
  the text of exactly one `c"..."` literal that is the last argument of a
  `check!` call in the kernel file of its case's family, or whose family has
  no kernel file;
- `disposition`: a row with no disposition, more than one, or a malformed
  one: a `kill` that is no nonempty list, a `survives` or `unrun` that is
  no object, a missing or blank field such as a `survives` row with an
  empty reason, a lane other than `loom` or `genmc`, `kill` entries
  naming a lane twice, or an empty `passed` or `needs` on a row outside
  `UNMODELED`;
- `enclosing item`: a row without a binding and without a `scope`, or a
  row whose enclosing item resolves to other than one body, whose body
  lacks the row's `find`, or whose site lies in an `fn` or `impl` nested in
  that body;
- `revision`: a `kill` or `survives` row whose `revision` is no string of
  exactly 40 lowercase hex digits;
- `row`: a malformed row: no object, a missing `id`, `path`, `op`, `find`
  or `replace`, a blank or repeated `id`, a `path` outside `files`, an `op`
  outside the four, a key outside the row's fields, both a `binding` and a
  `scope`, or an `id`, `path`, `find`, `replace`, `binding` or `scope`
  value of the wrong type.

The rows of a listed file that is not read are not matched; the file's
own refusal names it. `check` prints one JSON report with the refusals,
each row's disposition (null for a row with none or more than one), the
unrun rows, the site count, the excluded files and `credited`, true
exactly when `check` refuses nothing and no row is unrun. Exit 0 is a
catalog without refusals, unrun rows included; 1 is a refusal; 2 is a
catalog, declaration, package or helper script that cannot be read,
reported as `{"error": ...}` on standard output. A usage error exits 2
with argparse's usage text on standard error and no report, and `--help`
prints the help text and exits 0.

A passing check shows that each cataloged text is unchanged and that each
site has its rows. The test outcomes live in each row's disposition: the
report maps each row to its disposition and lists the unrun rows. An
entry's `failure` is held to the model source or the kernel file of its
tests, a file that other tests share; the run that sets the disposition
shows which of those tests fails with it. An entry's tests are held to the
positive tests of its lane; that they reach the row's site and ran under
its plant is the claim of the run recorded in the row's `revision`.
Several weakenings keep every row's text and pass: two consumers of one op
that exchange their strength constants, or a consumer edit that leaves its
constant another `S::NAME` mention of the same op; an edit to the consumer
outside the scoped files of a constant `EXTERNAL` pins; any caller
choosing another strength; an ordering taken from a constant defined
outside the scoped files; a word forwarder that ignores the ordering it is
passed; a forwarder invocation on another type beside a hand-written impl
for the production word; a path `std::sync::atomic::fence` that a local
`mod std` resolves elsewhere; and a cataloged statement kept in its item
while a dead branch, a
non-test `cfg`, the text of a test-only element after its first `{...}`
block, or an unreached path holds it and a weaker access does the live
work. Such text follows any first block that does not end its element:
for example the `else` of a test-only `if`, the rest of a `const` or `let`
initializer, the later arguments of a call that holds a closure body or a
struct literal, a method call on a block, a body after a struct pattern,
or an item body after a braced const argument in its header. The
predicates read as test-only are `cfg(test)` and `cfg(all(test, ...))`;
any other `cfg` is read as production text, on a module declaration as on
a site, and an inner `#![cfg(test)]` of a module file is read as
production text too. The scope rule reads `mod.rs`, `lib.rs` and
`main.rs` of the crate's source directory as the crate root; how those
files include one another is outside it. A constant left with no in-file
mention and no `EXTERNAL` pin is refused.

`run` is an operator command. It needs the workflow's `STABLE` toolchain
and, for its Cargo configuration read, the `NIGHTLY` toolchain. It refuses
a `DIR` inside the checkout, a `DIR` that cannot be listed (a regular file
among them), is not empty or cannot hold the copy, and a checkout whose
judging scripts (`weaken-orderings.py`, `classify-atomics.py`,
`judge-genmc.py`, `judge-rc11.py`) differ from `HEAD`, so the report's
revision names the code that judged it. It copies the checkout's `HEAD` to
`DIR/copy` with `git archive`, prints that revision on standard error,
since uncommitted changes stay out of the copy, and refuses a copy whose
catalog `check` refuses, with the crate sources walked in the copy, or
whose workflow names no `STABLE`, `NIGHTLY` or `LOOM` pin, bare or in
matched quotes. It refuses a planted file whose bytes a text restore cannot
reproduce, such as CR LF line endings. It reads the merged Cargo
configuration with `cargo +NIGHTLY config get` in the copy, and in the
kernel package when a GenMC case is selected, and refuses an entry the
GenMC judge's `check_config` refuses, a `LOOM_*` environment entry when a
loom test is selected, or a read that fails, quoting Cargo's last lines.
When a GenMC case is selected it refuses a copy whose declaration the
copy's GenMC judge refuses on the unweakened sources:
`check_transcription`, a binding whose kernel or production operation
drifted, or `check_correspondence`, a case that disagrees with the litmus
tests it names. A plant then differs from the judged sources in its one
site.
A run with a loom test refuses a copy that resolves a loom version other
than the `LOOM` pin or whose resolution fails. It writes its copy, build
outputs, evidence, `progress.json` and `report.json` under `DIR`; the
toolchains, the GenMC checker the lane builds under
`~/.cache/kestrike-genmc` and Cargo's registry caches are its only writes
elsewhere. Each output is a new file whose name carries a serial number
and, for a planted run, the row's catalog position, never its id. The
selected rows are every row, or each `--row`. A row's entries are its
`kill` entries, its `survives` passed entries or its `unrun` needs; a row
with none is `skipped`, with the row's reason, which agrees with a
`survives` row that no model runs.

First the baseline: each test the selected rows name runs once on the
unweakened copy, and each must give `survived`, or the run stops with exit
3 and no row result, and must leave every scoped file a regular file with
the unweakened copy's digest, or the run stops with exit 4. Then, per row,
`run` writes the plant, the row's
`replace` at its one `find` in the production text, as a new file created
exclusively beside the scoped file, with its mode and a later modification
time, runs each test the row's entries name once and judges that run for
each entry, then checks that the planted file still holds the plant,
writes the unweakened file back the same way, and stops with exit 4 when
the plant had changed, the unweakened file cannot be written back, or any
scoped file is then a symbolic link, no regular file, unreadable or one
whose digest differs from the unweakened copy's. A plant a test removed,
replaced or made unreadable is written back with the unweakened file's
mode. The restore also runs when a
test raises or the run is interrupted by SIGINT, SIGTERM or SIGHUP (each
one the invoking shell did not ignore), and it runs with those signals
blocked. From before a row's plant is written until its restore has been
checked, and while a baseline test runs, a handled signal is recorded: it
ends the running test's wait and starts no further test of the row, and
the run unwinds as KeyboardInterrupt once that test's process group has
ended, through the restore. Each test runs in its own session; when it
ends, times out or is interrupted, its process group gets SIGTERM, then
SIGKILL once the leader has exited, a further signal arrives or 45 seconds
pass, which outlasts the lane's own 30-second grace.

- A loom test runs as `cargo +STABLE test -p kestrike --lib --release
  TEST -- --exact` in the copy, with the workflow's toolchain pins; every
  `LOOM_*` variable and every compiler, wrapper, flag, target, runner,
  profile and output-directory variable (`RUSTC*`, `RUSTFLAGS`,
  `RUSTDOCFLAGS`, `CARGO_ENCODED_*FLAGS`, `CARGO_BUILD_*` but
  `CARGO_BUILD_JOBS`, `CARGO_TARGET_*`, `CARGO_PROFILE_*`) cleared;
  `RUSTFLAGS="--cfg loom"`, `CARGO_TARGET_DIR` and `CARGO_BUILD_BUILD_DIR`
  under `DIR`, plain Cargo status lines and a 60-minute deadline.
  `killed`: the test failed and a panic in its output reports the location
  of the one assertion, panic or `expect` whose message literal holds the
  entry's `failure`, the line of its macro or method name in the test's
  model source, with the failure in its first message line. `survived`:
  `test result: ok. 1 passed; 0 failed; 0 ignored`, so a filter that
  matches no test, or an ignored test, gives `no verdict`. A planted row's
  results count once `cargo` reports compiling `kestrike` under the
  plant; the row's later tests reuse that build. A loom result records no
  search bound: with every `LOOM_*` variable cleared and refused, the bound
  is the one the test's model source sets at `revision`.
- A GenMC entry runs `bash scripts/rust-lane.sh genmc PROFILE CASE...` in
  the copy, with each case once, `EVIDENCE` under `DIR` and plain Cargo
  status lines, under 20 minutes per case plus 45, the sum of the lane's
  own deadlines and 5 minutes; the profile is `pr` when it holds every
  case, else `scheduled`. `run` judges each case's raw output with the
  copy's `scripts/judge-genmc.py`: its `check_config` and `check_command`
  first, with the identity record's fields checked for shape, then
  `judge_case`. `survived`: `judge_case` accepts the case's positive
  declaration. `killed`: it accepts that declaration as a violation that
  names the case family's kernel file and the entry's `failure` as its one
  `check!`. A planted case counts once the lane's `cargo check` of the case
  compiled the kernel package.
- Anything else is `no verdict`, with its reason: a timeout, missing
  rebuild evidence, another failure text or assertion, an ignored or
  absent test, a build failure, a crashed test, or a lane output the
  judge refuses.

`progress.json` holds the report so far, rewritten whole before the
baseline, after each baseline test, after each loom test and GenMC batch
of a planted row and after each row, with `active`, the row or `baseline` in progress, or null
between them; a planted row in progress holds no `agrees`. It is the
record of a run that stops after its configuration checks. `report.json`
holds `revision`, the copy's; `pins`, the toolchain pins with the `rustc`
version, the host architecture, the CPU count, `CARGO_BUILD_JOBS`, the
loom version the copy resolved (`loom resolved`) and the digest of the
workspace lock file that resolution wrote in the copy (`Cargo.lock
sha256`, null when it wrote none); `baseline` and, per row
under `rows`, the plant, `expected`, `results`, `seconds` and `agrees`, or
for a skipped row `result` and `reason`; `mismatched`; `no verdict`, the
rows with a test that no entry judged `killed` or `survived`; and the
run's `seconds`, from the command's start to its last row. Each result
holds the command (for a loom test with its `RUSTFLAGS`), `exit` (a GenMC
case's own, an integer or null, with the lane's as `lane_exit`), its
`seconds` (for a GenMC case, the whole lane run's), the output's path and
sha256 digest, shared by the results of one run, and the result with its
reason, and for a GenMC case the `executions` its accepted judgment
counted. A `kill` row agrees when every result is `killed`, a `survives`
row when every result is `survived`; an `unrun` row always agrees. Both
JSON files get the mode a plain create gets under the umask.

Exit 0: a completed run whose every row agrees; 1: a completed run with a
row that does not, named under `mismatched`, or an unhandled error, shown
by a traceback and no `report.json`; 2: a refused work directory,
checkout, catalog, configuration, GenMC declaration, pin or file, a
`--row` that names no row, or a usage error; 3: a red baseline; 4: a
baseline test that left a scoped file changed, a changed plant, a failed
restore or a restore that left a scoped file changed. A completed run writes `report.json` and
prints its path, `mismatched` and `no verdict` as one JSON line. Exits 2,
3 and 4 print `weaken-orderings:` and the reason on standard error, for
exit 3 the baseline results as indented JSON. A handled signal before the
report is written restores the plant and unwinds as KeyboardInterrupt,
with a traceback and no `report.json`; CPython then ends the process by
SIGINT, whichever signal arrived. Obligation credit comes from lane
receipts alone, and `run`'s outputs are the files under `DIR`.
"""

import argparse
import contextlib
import functools
import hashlib
import importlib.util
import json
import os
import re
import shlex
import signal
import stat
import subprocess
import sys
import tempfile
import time
from collections import namedtuple
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CATALOG = "verification/orderings/expected.json"
GENMC = "verification/genmc/expected.json"
RC11 = "verification/rc11/expected.json"
OBLIGATIONS = "verification/obligations.json"
CRATE = "crates/kestrike/src"
HOOKS = ("fence_park", "fence_clear", "fence_pin", "fence_retire", "fence_certify")
EXTERNAL = {("crates/kestrike/src/storage/credit.rs", "RELOAD"): "load"}
UNMODELED = ("word-install", "fill-depart-held", "sequence-begin-store", "sequence-commit")
OPS = ("load", "store", "rmw", "fence")
STEPS = {"SeqCst": {"load": ["Acquire"], "store": ["Release"], "rmw": ["AcqRel"]}, "AcqRel": {"rmw": ["Acquire", "Release"]},
         "Release": {"store": ["Relaxed"], "rmw": ["Relaxed"]}, "Acquire": {"load": ["Relaxed"], "rmw": ["Relaxed"]}}
DISPOSITIONS = ("kill", "survives", "unrun")
ROW_KEYS = {"id", "path", "find", "replace", "op", "binding", "scope", "twin", "revision", *DISPOSITIONS}
ORDERING = re.compile(r"\bOrdering\s*::\s*(SeqCst|AcqRel|Acquire|Release)\b")
SPELLING = re.compile(r"\bOrdering\s*(?:::\s*\*|as\b)")
VARIANT = re.compile(r"\b(?:SeqCst|AcqRel|Acquire|Release)\b")
FENCE = re.compile(r"\$?\b\w*fence\w*\b")
FENCE_PATH = re.compile(r"(?:::\s*)?(?:(?:<(?:[^<>]|<[^<>]*>)*>|\w+)\s*::\s*)*\$?\w*$")
FORWARDER = re.compile(r"\b(\w+)\s*!\s*\(\s*[\w:<>]+\s*,\s*std\s*::\s*sync\s*::\s*atomic\s*::\s*$")
PATH_ATTRIBUTE = re.compile(r"#\s*!?\s*\[\s*(?:path\b|cfg_attr\s*\([^\]]*\bpath\s*=)")
SOURCED = re.compile(r"\binclude\b|(?<!#)\bmod\b|" + PATH_ATTRIBUTE.pattern)
DECLARED = re.compile(r'#\s*\[\s*path\s*=\s*"(?P<path>[^"]*)"\s*\]\s*(?:#\s*\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?P<mod>mod)\s+(?:r#)?(?P<name>\w+)\s*;')
ARM = re.compile(r"\s*\(\s*\$\w+\s*:\s*ty\s*,\s*\$fence\s*:\s*path\s*\)\s*=>\s*\{")
MACRO = re.compile(r"(?:\bmacro_rules\s*!\s*(?:r#)?\w+|\b\w+\s*!)\s*[(\[{]")
DIAGNOSTIC = re.compile(r"(?:\b(?:assert|assert_eq|assert_ne|debug_assert|debug_assert_eq|debug_assert_ne|panic|unreachable)!|\.\s*expect)\s*$")
CONSTANT = re.compile(r"\bconst\s+(\w+)\s*:\s*Ordering\s*=\s*$")
REVISION = re.compile(r"[0-9a-f]{40}")
UNREAD = "unread"
MALFORMED = (TypeError, KeyError, AttributeError, ValueError)
Site = namedtuple("Site", "start end ordering op open", defaults=(None,))


def load(script, root=ROOT):
    sys.dont_write_bytecode = True
    try:
        spec = importlib.util.spec_from_file_location(script.replace("-", "_"), root / f"scripts/{script}.py")
        if spec is None or spec.loader is None:
            raise ImportError(f"scripts/{script}.py has no loader")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except (OSError, ImportError, SyntaxError) as error:
        print(json.dumps({"error": f"scripts/{script}.py cannot be loaded: {error}"}, indent=2))
        raise SystemExit(2) from error
    return module


atomics = load("classify-atomics")
scanned_text = functools.cache(atomics.code)
genmc = load("judge-genmc")
read_repo = genmc.read_source


def read_or_none(read, path):
    try:
        return read(path)
    except (OSError, ValueError):
        return None


def unique(pairs):
    """A JSON object of `pairs`, refusing a key it repeats."""
    keys = [key for key, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError(f"an object repeats a key among {keys}")
    return dict(pairs)


def call_end(text, start):
    """The offset past the bracket that closes the one at `start`."""
    depth = 0
    for index in range(start, len(text)):
        depth += (text[index] in "([{") - (text[index] in ")]}")
        if depth == 0:
            return index + 1
    return len(text)


def opener(scanned, offset):
    """The offset of the innermost bracket open at `offset`, or -1."""
    depth = 0
    for index in range(offset - 1, -1, -1):
        char = scanned[index]
        if char in ")]}":
            depth += 1
        elif char in "([{":
            if not depth:
                return index
            depth -= 1
    return -1


def body_open(text, index):
    """The offset of the `{` that opens the body of an item whose header continues at `index`, or -1 when a `;`
    outside brackets ends it as a declaration."""
    depth = 0
    for position in range(index, len(text)):
        char = text[position]
        if char in "([":
            depth += 1
        elif char in ")]":
            depth -= 1
        elif not depth and char == "{":
            return position
        elif not depth and char == ";":
            return -1
    return -1


def call_op(scanned, offset):
    """The op of the call argument at `offset`, read from the atomic method whose argument it is, or UNREAD."""
    index = opener(scanned, offset)
    if index < 0 or scanned[index] != "(":
        return UNREAD
    depth, commas, generic = 0, 0, False
    for char in scanned[index + 1:offset]:
        if char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif not depth:
            commas += char == ","
            generic = generic or char in "<>"
    method = re.search(r"\.\s*(\w+)\s*(?:::<[^>]*>)?\s*$", scanned[max(0, index - 200):index])
    name = method.group(1) if method else ""
    if name in ("load", "store"):
        return name
    if name == "swap" or (name.startswith("fetch_") and name != "fetch_update"):
        return "rmw"
    if generic:
        return UNREAD
    if name in ("compare_exchange", "compare_exchange_weak"):
        return {2: "rmw", 3: "load"}.get(commas, UNREAD)
    if name == "fetch_update":
        return {0: "rmw", 1: "load"}.get(commas, UNREAD)
    return UNREAD


def empty_hooks(scanned):
    """The hooks of HOOKS that `scanned` defines with at least one body, each body empty."""
    empty = set()
    for name in HOOKS:
        bodies = []
        for definition in re.finditer(rf"\bfn\s+{name}\b", scanned):
            brace = body_open(scanned, definition.end())
            if brace >= 0:
                bodies.append(scanned[brace + 1:(atomics.closing(scanned, brace) or len(scanned)) - 1])
        if bodies and not any(body.strip() for body in bodies):
            empty.add(name)
    return empty


def fence_calls(scanned):
    """(each fence call site of `scanned`, (offset, why) for each fence named outside a delimited path call, the
    name of the macro each forwarder invocation that passes `std::sync::atomic::fence` invokes)."""
    found, stray, forwards = [], [], []
    empty = empty_hooks(scanned)
    for match in FENCE.finditer(scanned):
        before, after = scanned[max(0, match.start() - 200):match.start()], scanned[match.end():match.end() + 200]
        if re.search(r"\bfn\s+$", before) or (match.group().startswith("$") and re.match(r"\s*:", after)):
            continue
        if match.group() in empty and re.search(r"\bS\s*::\s*$", before):
            continue
        call = re.match(r"\s*\(", after)
        if not call:
            forwarder = FORWARDER.search(before)
            if match.group() == "fence" and forwarder and re.match(r"\s*\)\s*;", after):
                forwards.append(forwarder.group(1))
            else:
                stray.append((match.start(), "a fence path named outside a call"))
            continue
        path = FENCE_PATH.search(before)
        path = path.group() if path else ""
        prefix = before[:len(before) - len(path)]
        if re.search(r"\.\s*$", prefix):
            stray.append((match.start(), "a fence called as a method"))
            continue
        if prefix[-1:] in ("$", ">", ":") or re.search(r"\w$", prefix):
            stray.append((match.start(), "a fence callee the matcher cannot delimit"))
            continue
        opening = match.end() + call.end() - 1
        end = call_end(scanned, opening)
        found.append(Site(match.start() - len(path), end + (scanned[end:end + 1] == ";"), None, "fence", opening))
    return found, stray, forwards


def forwarder_defects(scanned, fences, forwards):
    """What breaks the tie between each `$fence` call, the `macro_rules!` whose body holds it, and that macro's
    production invocations: each passes `std::sync::atomic::fence`, none lies among another macro's tokens, the body
    is one arm `($name:ty, $fence:path) => {..}`, and the invocations follow the definition with nothing between."""
    spans = [(match.group(1), match.end() - 1, atomics.closing(scanned, match.end() - 1) or len(scanned))
             for match in re.finditer(r"\bmacro_rules!\s*(?:r#)?(\w+)\s*\{", scanned)]
    owners, defects = set(), []
    for site in fences:
        if scanned[site.start] != "$":
            continue
        owner = next((span for span in spans if span[1] < site.start < span[2]), None)
        if owner is None:
            defects.append(f"line {line_of(scanned, site.start)}: a $fence call lies in no macro_rules! body")
        else:
            owners.add(owner)
    for name in sorted(set(forwards) - {name for name, _, _ in owners}):
        defects.append(f"{name}! receives std::sync::atomic::fence and holds no $fence call")
    groups = [(match.end() - 1, call_end(scanned, match.end() - 1)) for match in MACRO.finditer(scanned)]
    for name, low, high in sorted(owners):
        invoked = [(match.start(), match.end() - 1) for match in re.finditer(rf"\b{re.escape(name)}\s*!\s*[(\[{{]", scanned)]
        if any(first < offset < last for offset, _ in invoked for first, last in groups):
            defects.append(f"{name}! is invoked among another macro's tokens, which the matcher cannot expand")
        if not invoked or forwards.count(name) != len(invoked):
            defects.append(f"{name}! holds a $fence call, and {forwards.count(name)} of its {len(invoked)} production invocations "
                           "pass std::sync::atomic::fence")
        arm = ARM.match(scanned, low + 1)
        cursor = high if arm and re.fullmatch(r"\s*;?\s*", scanned[atomics.closing(scanned, arm.end() - 1) or low:high - 1]) else None
        for offset, opening in invoked:
            if cursor is not None:
                end = call_end(scanned, opening)
                cursor = None if offset < cursor or scanned[cursor:offset].strip() else end + (scanned[end:end + 1] == ";")
        if cursor is None:
            defects.append(f"{name}! is not one arm ($name:ty, $fence:path) => {{..}} that its production invocations directly follow")
    return defects


def sites(scanned, fences=None, external=None):
    """Each site of `scanned` in order, given its fence call sites (found when None) and the op of each strength
    constant whose consumer lies outside the file."""
    fences = fence_calls(scanned)[0] if fences is None else fences
    found = list(fences)
    for match in ORDERING.finditer(scanned):
        if any(site.start <= match.start() < site.end and opener(scanned, match.start()) == site.open for site in fences):
            continue
        constant = CONSTANT.search(scanned[scanned.rfind("\n", 0, match.start()) + 1:match.start()])
        if constant:
            name = constant.group(1)
            ops = {call_op(scanned, use.start()) for use in re.finditer(rf"\bS\s*::\s*{name}\b", scanned)}
            op = (ops.pop() if len(ops) == 1 else UNREAD) if ops else (external or {}).get(name, UNREAD)
        else:
            op = call_op(scanned, match.start())
        found.append(Site(match.start(), match.end(), match.group(1), op))
    return sorted(found, key=lambda site: site.start)


def line_of(text, offset):
    return text.count("\n", 0, offset) + 1


def module_source(test, read):
    """The text of the module file `module_file` reaches for loom test `test`, or None."""
    return (module_file(test, read) or (None, None))[1]


@functools.cache
def module_file(test, read):
    """(the repository path, the text) of the module file that holds loom test `test`, read down from the crate's
    `mod.rs` as rustc loads it: each module the path names is loaded by a declaration that `loads` reads in its parent,
    a `#[path]` one or a bare `mod name;`, and the last file reached declares the remaining module inline. None when a
    declaration or the file it loads is missing, or when a parent declares one module more than once, inline or by two
    files, which only a `cfg` this lookup does not evaluate tells apart."""
    names, home = test.split("::")[:-1], Path(CRATE)
    path = home / "mod.rs"
    text = read_or_none(read, str(path))
    while text is not None and names:
        bare, attributed = loads(path, home, text, scanned_text(text), lambda *_: None)
        paths = [Path(target) for target, declared in attributed.items() if names[0] in declared]
        inline = re.search(rf"\bmod\s+(?:r#)?{re.escape(names[0])}\s*\{{", scanned_text(text)) is not None
        if len(paths) + (str(home / f"{names[0]}.rs") in bare) + inline != 1:
            return None
        if inline:
            break
        files = paths or [home / f"{names[0]}.rs", home / names[0] / "mod.rs"]
        path = next((file for file in files if read_or_none(read, str(file)) is not None), files[0])
        text, home, names = read_or_none(read, str(path)), path.parent if paths or path.name == "mod.rs" else path.with_suffix(""), names[1:]
    return None if text is None else (str(path), text)


def diagnostics(text):
    """The contents of the string literals of `text` passed to an assertion, a panic or an `expect`."""
    return [content for content, _ in diagnostic_sites(text)]


def diagnostic_sites(text):
    """(content, line) of each string literal of `text` passed to an assertion, a panic or an `expect`, the line being
    that of the macro or method name, where a panic it raises reports its location."""
    code = atomics.code(text)
    found = []
    for kind, start, end in genmc.rc11.rust_lexemes(text):
        index = opener(code, start) if kind == "string" else -1
        window = max(0, index - 40)
        named = DIAGNOSTIC.search(code[window:index]) if index >= 0 else None
        if named:
            lexeme, name = text[start:end], named.group()
            macro = window + named.start() + len(name) - len(name.lstrip(". \t\n"))
            found.append((lexeme[lexeme.index('"') + 1:lexeme.rindex('"')], line_of(text, macro)))
    return found


def loom_site(test, failure, read):
    """(path, line) of the one assertion, panic or `expect` in `test`'s model source whose message literal holds
    `failure`, or None."""
    found = module_file(test, read)
    if found is None:
        return None
    lines = [line for content, line in diagnostic_sites(found[1]) if failure in content]
    return (found[0], lines[0]) if len(lines) == 1 else None


def c_literals(text):
    """The contents of the `c"..."` literals of `text` that are the last argument of a `check!` call, its message."""
    code = atomics.code(text)
    return [text[start + 1:end - 1] for kind, start, end in genmc.rc11.rust_lexemes(text)
            if kind == "string" and text[start] == '"' and start and text[start - 1] == "c"
            and not (start > 1 and (text[start - 2].isalnum() or text[start - 2] == "_"))
            and (index := opener(code, start)) >= 0 and re.search(r"\bcheck\s*!\s*$", code[max(0, index - 40):index])
            and re.match(r"\s*,?\s*\)", code[end:])]


def references(declared, litmus, records, root):
    """The tests a disposition entry may name, the twins a row may cite by lane, the bindings, and the kernel texts."""
    loom = [record for record in records["records"] if record.get("job") == "loom"]
    controls = {control["test"] for record in loom for control in record.get("controls", [])}
    positive = {"loom": {test for record in loom for test in record["tests"]} - controls,
                "genmc": {name for name, case in declared["cases"].items() if case["expect"] == "positive"}}
    twins = {"loom": controls,
             "genmc": {name for name, case in declared["cases"].items() if case["expect"] == "violation"},
             "rc11": {name for name, test in litmus["tests"].items() if test["outcome"] == "Sometimes"}}
    bindings = {entry["id"]: entry for entry in declared["bindings"]}
    package = root / declared["package"]
    return positive, twins, bindings, kernel_texts(package)


def kernel_texts(package):
    """The text of each Rust source of the kernel package, keyed by its path relative to `package`, build outputs aside."""
    return {str(path.relative_to(package)): path.read_text(encoding="utf-8") for path in package.rglob("*.rs")
            if path.is_file() and "target" not in path.relative_to(package).parts}


def include_defects(package, kernels):
    """What makes a kernel source's `#[path]` includes differ from what the shared include scanner reads."""
    defects = []
    for path, text in sorted(kernels.items()):
        code = atomics.code(text)
        live = {match.start() for match in PATH_ATTRIBUTE.finditer(code)}
        read = {match.start() + match.group().index("#"): match.group(1) for match in genmc.INCLUDED.finditer(text)}
        where = f"{package.name}/{path}"
        for match in re.finditer(r"\binclude\b", code):
            defects.append(f"{where}:{line_of(text, match.start())}: an include! macro, whose source the scope rule does not read")
        for offset in sorted(live - set(read)):
            defects.append(f"{where}:{line_of(text, offset)}: a path attribute the include scanner misses")
        for offset in sorted(set(read) - live):
            defects.append(f"{where}:{line_of(text, offset)}: the include scanner reads a path attribute outside live code")
        for offset, target in sorted(read.items()):
            resolved = ((package / path).parent / target).resolve()
            if "\\" in target:
                defects.append(f"{where}:{line_of(text, offset)}: the include path {target!r} holds an escape")
            elif resolved.is_relative_to(package.resolve()) and str(resolved.relative_to(package.resolve())) not in kernels:
                defects.append(f"{where}:{line_of(text, offset)}: the include {target!r} is no Rust source of the package the scan reads")
    return defects


def loads(module, child, text, scanned, refuse):
    """(the files the live bare `mod name;` declarations of `module` in `text` load from `child`, the directory its
    declarations load from, each file its live path attributes load with the names they declare it under, a name
    inside inline modules prefixed by theirs), relative to the root; `scanned` is `text` with comments and literals
    blanked. Among a macro's tokens a path attribute or a `mod` keyword is refused and loads nothing: a definition's
    body declares only where it is invoked, and an invocation may drop its tokens or turn them into a declaration."""
    for match in MACRO.finditer(scanned):
        end = call_end(scanned, match.end() - 1)
        tokens = scanned[match.end():end]
        if re.search(r"(?<!#)\bmod\b", tokens) or PATH_ATTRIBUTE.search(tokens):
            refuse("scope file", f"{module}:{line_of(scanned, match.start())}: a module declaration inside a macro's tokens, which the "
                                 "scope rule cannot read")
        scanned = scanned[:match.end()] + re.sub(r"[^\n]", " ", tokens) + scanned[end:]
    inline = [(match.group(1), match.end() - 1, call_end(scanned, match.end() - 1))
              for match in re.finditer(r"\bmod\s+(?:r#)?(\w+)\s*\{", scanned)]

    def enclosing(offset):
        return [name for name, low, high in inline if low < offset < high]
    bare, attributed, marked = set(), {}, set()
    for match in DECLARED.finditer(text):
        if scanned[match.start()] != "#":
            continue
        marked.add(match.start("mod"))
        inside = enclosing(match.start())
        if "\\" in match.group("path"):
            refuse("scope file", f"{module}:{line_of(text, match.start())}: the path attribute holds an escape the scope rule cannot read")
        else:
            target = os.path.normpath((child.joinpath(*inside) if inside else module.parent) / match.group("path"))
            attributed.setdefault(target, set()).add("::".join([*inside, match.group("name")]))
    if len(PATH_ATTRIBUTE.findall(scanned)) != len(marked):
        refuse("scope file", f"{module} holds a path attribute the scope rule cannot read")
    for match in re.finditer(r"\bmod\s+(?:r#)?(\w+)\s*;", scanned):
        if match.start() not in marked:
            home = child.joinpath(*enclosing(match.start()))
            bare |= {str(home / f"{match.group(1)}.rs"), str(home / match.group(1) / "mod.rs")}
    return bare, attributed


def path_holders(tree):
    """The crate sources under `tree` whose text holds a path attribute; a source that cannot be read holds none."""
    return [path.relative_to(tree) for path in sorted((tree / CRATE).rglob("*.rs"))
            if path.is_file() and PATH_ATTRIBUTE.search(read_or_none(lambda name: name.read_text(encoding="utf-8"), path) or "")]


def scope_files(package, root, read, refuse, tree=ROOT):
    """The (production, excluded) files outside `package` that it includes by `#[path]`, relative to `root`.

    The package is walked on disk under `root`. The path holders are the crate sources whose committed text holds a
    path attribute; each holder and each module file is read through `read`.
    """
    crate, ranks = Path(CRATE), ("production", "elsewhere", "excluded", "unreadable", None)
    roots = [crate / name for name in ("mod.rs", "lib.rs", "main.rs")]
    included, excluded, messages, texts, parsed, places = [], [], set(), {}, {}, {}

    def once(name, message):
        if message not in messages:
            messages.add(message)
            refuse(name, message)

    def source(module):
        """The text of `module`, None when it is absent, or the error that kept it from being read."""
        if module not in texts:
            try:
                texts[module] = read(str(module))
            except (OSError, ValueError) as error:
                texts[module] = None if isinstance(error, FileNotFoundError) else error
        return texts[module]

    def parse(module, child, live):
        """`loads` of `module`, its bare declarations loading from `child`: of its live declarations, or of all of them."""
        if (module, child, live) not in parsed:
            text, scanned = atomics.blanked(texts[module]) if live else (texts[module], atomics.code(texts[module]))
            parsed[module, child, live] = loads(module, child, text, scanned, once)
        return parsed[module, child, live]

    def best(states):
        return next(state for state in ranks if state in states or state is None)

    def place(file):
        """The standing a bare declaration gives crate source `file` and the standing a path attribute gives it: each
        `production`, `elsewhere` for a declarer whose place the rule does not read, `excluded`, `unreadable` or None."""
        if file not in places:
            places[file] = (None, None)
            places[file] = ("production", "production") if file in roots else declared(file)[:2]
        return places[file]

    def declared(file):
        """`place` of `file`, and the module files whose bare declarations load from its directory."""
        directory = file.parent.parent if file.name == "mod.rs" else file.parent
        named = [] if crate not in (directory, *directory.parents) else roots if directory == crate \
            else [directory / "mod.rs", directory.with_suffix(".rs")]
        names = pathed | {Path(match.group("path")).name for module in named if isinstance(source(module), str)
                          for match in DECLARED.finditer(texts[module])}
        modules = named + sorted(directory / name for name in names if name != "mod.rs" and directory / name not in (file, *named))
        found = (set(), set())
        for module in modules + [module for module in (*roots, *holders) if module not in modules]:
            text, home = source(module), module in modules
            if isinstance(text, Exception) and home:
                once("scope file", f"{module} cannot be read to classify {file}: {text}")
                found[0].add("unreadable")
            if not isinstance(text, str) or not (home or module in roots or file.name in text):
                continue
            child = directory if home else module.parent if module.name in ("mod.rs", "lib.rs", "main.rs") else module.parent / module.stem
            anywhere = parse(module, child, False)
            for attribute in (0, 1):
                if str(file) not in anywhere[attribute]:
                    continue
                if not home and module not in roots:
                    standing = "elsewhere"
                elif attribute or module in roots or module.name == "mod.rs":
                    standing = best(place(module))
                else:
                    standing = place(module)[module != directory.with_suffix(".rs")]
                tested = standing == "production" and str(file) not in parse(module, child, True)[attribute]
                found[attribute].add("excluded" if tested else standing)
        return best(found[0]), best(found[1]), [str(module) for module in modules]

    holders = [holder for holder in path_holders(tree) if isinstance(source(holder), str)]
    pathed = {Path(match.group("path")).name for holder in holders for match in DECLARED.finditer(texts[holder])}
    for path in genmc.package_sources(package):
        resolved = path.resolve()
        if resolved.is_relative_to(package.resolve()):
            continue
        if not resolved.is_relative_to(root.resolve()):
            once("scope file", f"the kernel package includes {path}, outside the repository")
            continue
        relative = resolved.relative_to(root.resolve())
        bare, attributed, searched = declared(relative)
        state = best({bare, attributed})
        if state == "production":
            included.append(str(relative))
        elif state == "elsewhere":
            once("scope file", f"{relative} is declared only by a path attribute outside its module files and the crate root, in a "
                               "file whose place in the crate the scope rule does not read")
        elif state == "excluded":
            excluded.append(str(relative))
        elif state is None:
            once("scope file", f"the kernel package includes {relative} and no module file declares it through declarations "
                               f"that reach the crate root; searched {searched} and the crate's path attributes")
    return included, excluded


def scan(path, text):
    """(production text, normalized production text, its sites, its spelling defects) for scoped file `path`."""
    production, scanned, cut = atomics.analyzed(text)
    defects = [f"{path}:{line_of(text, match.start())}: {match.group()} hides the sites it names from the matcher"
               for match in SPELLING.finditer(scanned)]
    named = {match.start(1) for match in ORDERING.finditer(scanned)}
    defects += [f"{path}:{line_of(text, match.start())}: {match.group()} outside an Ordering:: path hides its site from the matcher"
                for match in VARIANT.finditer(scanned) if match.start() not in named]
    defects += [f"{path}:{line_of(text, offset)}: a test-only element whose end the matcher reads more than one way; parenthesize "
                "its `<`, `>` or `|`, or move it into a test-only block or module" for offset in cut]
    fences, stray, forwards = fence_calls(scanned)
    defects += [f"{path}:{line_of(text, offset)}: {why} hides the sites it names from the matcher" for offset, why in stray]
    defects += [f"{path}: {defect}" for defect in forwarder_defects(scanned, fences, forwards)]
    external = {name: op for (file, name), op in EXTERNAL.items() if file == path}
    return production, genmc.normalized(production), {site: [] for site in sites(scanned, fences, external)}, defects


def check(read=read_repo, root=ROOT, tree=ROOT):
    """Return (report, exit code) for the catalog `read` returns, with the kernel package walked under `root` and the
    crate sources that can declare an included file found under `tree`."""
    try:
        catalog, declared, litmus, records = (json.loads(read(path), object_pairs_hook=unique)
                                              for path in (CATALOG, GENMC, RC11, OBLIGATIONS))
        files, rows = catalog["files"], catalog["rows"]
        if not isinstance(files, list) or not all(isinstance(path, str) for path in files) \
                or len(set(files)) != len(files) or not isinstance(rows, list):
            raise ValueError("files is no list of distinct paths, or rows is no list")
        positive, twins, bindings, kernels = references(declared, litmus, records, root)
    except (OSError, RuntimeError, *MALFORMED) as error:
        return {"error": f"unreadable catalog or declaration: {error}"}, 2
    refusals = []

    def refuse(name, message):
        refusals.append({"refusal": name, "message": message})

    try:
        package = root / declared["package"]
        for defect in include_defects(package, kernels):
            refuse("scope file", defect)
        included, excluded = scope_files(package, root, read, refuse, tree)
    except (OSError, RuntimeError, ValueError) as error:
        return {"error": f"unreadable kernel package: {error}"}, 2
    for path in sorted(set(included) - set(files)):
        refuse("scope file", f"{path} is a production file the kernel package includes and files lacks")
    for path in sorted(set(files) - set(included)):
        refuse("scope file", f"{path} is listed and the kernel package includes no production file there")

    texts, normal, found = {}, {}, {}
    for path in files:
        if path not in included:
            continue
        text = read_or_none(read, path)
        if text is None:
            refuse("scope file", f"{path} cannot be read")
            continue
        texts[path], normal[path], found[path], defects = scan(path, text)
        for defect in defects:
            refuse("spelling", defect)
        for match in SOURCED.finditer(atomics.code(texts[path])):
            refuse("scope file", f"{path}:{line_of(text, match.start())}: {' '.join(match.group().split())} can load source that the "
                                 "catalog does not scope")

    ids, dispositions = set(), {}
    for row in rows:
        defect = row_defect(row, ids, files)
        if defect:
            refuse("row", f"row {row.get('id') if isinstance(row, dict) else row!r} is malformed: {defect}")
            continue
        name = row["id"]
        ids.add(name)
        held = [key for key in DISPOSITIONS if key in row]
        dispositions[name] = held[0] if len(held) == 1 else None
        try:
            if row["path"] in texts:
                production = texts[row["path"]]
                site = match_row(row, production, found[row["path"]], refuse)
                binding = bindings.get(row.get("binding"), {}).get("production", {}) if "binding" in row else {}
                scope = binding.get("scope") if "binding" in row else row.get("scope")
                if site and ("binding" not in row or (isinstance(scope, list) and scope)):
                    check_enclosing(row, refuse, normal[row["path"]], scope, site.start - production.find(row["find"]))
            check_disposition(row, held, refuse, positive, kernels, read)
            check_references(row, refuse, bindings, twins)
        except MALFORMED as error:
            refuse("row", f"row {name!r} is malformed: {type(error).__name__}: {error}")

    for path, entries in found.items():
        for site, targets in entries.items():
            token = texts[path][site.start:site.end]
            where = f"{path}:{line_of(texts[path], site.start)}"
            if not targets:
                refuse("unrowed site", f"{where}: {token} lies in no row's find")
                continue
            steps = ["delete"] if site.ordering is None else sorted(STEPS[site.ordering][site.op])
            if sorted(targets) != steps:
                refuse("site rows", f"{where}: {token} has rows to {sorted(targets)}, its steps are {steps}")

    unrun = sorted(name for name, disposition in dispositions.items() if disposition == "unrun")
    report = {"refusals": refusals, "rows": dispositions, "unrun": unrun, "sites": sum(map(len, found.values())),
              "excluded": sorted(excluded), "credited": not refusals and not unrun}
    return report, 1 if refusals else 0


def row_defect(row, ids, files):
    """What makes `row` malformed, or None."""
    if not isinstance(row, dict):
        return "it is no object"
    missing = [key for key in ("id", "path", "op", "find", "replace") if key not in row]
    if missing:
        return f"it lacks {missing}"
    unknown = sorted(set(row) - ROW_KEYS)
    if unknown:
        return f"it holds the unknown keys {unknown}"
    if not all(isinstance(row[key], str) for key in ("id", "path", "op", "find", "replace")) \
            or not isinstance(row.get("binding", ""), str) \
            or not (isinstance(row.get("scope", []), list) and all(isinstance(header, str) for header in row.get("scope", []))):
        return "a field has the wrong type"
    if not row["id"].strip():
        return "its id is blank"
    if row["id"] in ids:
        return "its id is repeated"
    if row["path"] not in files:
        return "it names an unlisted path"
    if row["op"] not in OPS:
        return f"its op {row['op']!r} is none of {list(OPS)}"
    if "binding" in row and "scope" in row:
        return "it holds both a binding and a scope"
    return None


def match_row(row, production, entries, refuse):
    """Record the row against the one site its `find` holds and return that site, or refuse it and return None."""
    name, find, replace = row["id"], row["find"], row["replace"]
    count = production.count(find)
    if count != 1:
        refuse("find", f"{name}: its find occurs {count} times in {row['path']}")
        return None
    start = production.find(find)
    held = [site for site in entries if start <= site.start and site.end <= start + len(find)]
    if len(held) != 1:
        refuse("find", f"{name}: its find holds {len(held)} sites")
        return None
    site = held[0]
    low, high = site.start - start, site.end - start
    if site.op == UNREAD:
        refuse("step", f"{name}: the matcher reads no op for its site")
        return None
    if site.op != row["op"]:
        refuse("step", f"{name}: its site is a {site.op}, the row says {row['op']}")
        return None
    if site.ordering is None:
        target = "delete" if replace == find[:low] + find[high:] else None
    else:
        steps = STEPS[site.ordering].get(row["op"], [])
        target = next((step for step in steps if replace == find[:low] + f"Ordering::{step}" + find[high:]), None)
    if target is None:
        refuse("step", f"{name}: its replace is not its find after one {row['op']} step")
        return None
    entries[site].append(target)
    return site


def disposition_entries(kind, value):
    """The entries of a well-formed disposition of `kind`, or None."""
    if kind == "survives":
        if not isinstance(value, dict):
            return None
        reason, passed = value.get("reason"), value.get("passed")
        if isinstance(reason, str) and reason.strip() and isinstance(passed, list) \
                and all(entry_fields(entry, failure=False) for entry in passed):
            return passed
        return None
    if kind == "kill":
        entries, reason = value, None
    elif isinstance(value, dict):
        entries, reason = value.get("needs"), value.get("reason")
    else:
        return None
    if not isinstance(entries, list) or not all(entry_fields(entry, failure=True) for entry in entries):
        return None
    if not entries and not (isinstance(reason, str) and reason.strip()):
        return None
    if kind == "kill" and len({entry["lane"] for entry in entries}) != len(entries):
        return None
    return entries


def entry_fields(entry, failure):
    """Whether `entry` names a model lane and a nonempty list of tests, and, when `failure`, a nonblank failure."""
    return isinstance(entry, dict) and entry.get("lane") in ("loom", "genmc") and isinstance(entry.get("tests"), list) \
        and bool(entry["tests"]) and all(isinstance(test, str) for test in entry["tests"]) \
        and (not failure or (isinstance(entry.get("failure"), str) and bool(entry["failure"].strip())))


def is_loom_failure(failure, text):
    """Whether `failure` is a message literal of `text`, its text before the first `{`, or the text after one of its
    `: ` separators."""
    for content in diagnostics(text):
        head = content.split("{", 1)[0].rstrip(" :")
        parts = head.split(": ")
        if failure in (content, head, *(": ".join(parts[index:]) for index in range(1, len(parts)))):
            return True
    return False


def family_kernel(case, kernels):
    """(the package-relative path, the text) of the one kernel file of `case`'s family, or None when the package holds
    none or several: `src/join_kernel.rs` for `join-production`."""
    family = re.sub(r"[^a-z].*", "", case, flags=re.S)
    found = [(path, text) for path, text in kernels.items() if Path(path).stem == f"{family}_kernel"]
    return found[0] if len(found) == 1 else None


def check_disposition(row, held, refuse, positive, kernels, read):
    name = row["id"]
    if len(held) != 1:
        refuse("disposition", f"{name}: it holds {len(held)} dispositions {held}")
        return
    entries = disposition_entries(held[0], row[held[0]])
    if entries is None:
        refuse("disposition", f"{name}: its {held[0]} disposition lacks a field, holds an empty one or has the wrong shape")
        return
    if not entries and name not in UNMODELED:
        refuse("disposition", f"{name}: its {held[0]} disposition names no run, and the row is outside {list(UNMODELED)}")
    revision = row.get("revision")
    if held[0] != "unrun" and not (isinstance(revision, str) and REVISION.fullmatch(revision)):
        refuse("revision", f"{name}: its {held[0]} disposition records no revision")
    for entry in entries:
        tests = []
        for test in entry["tests"]:
            if test in positive[entry["lane"]]:
                tests.append(test)
            else:
                refuse("reference", f"{name}: {test} is no positive {entry['lane']} test")
        if held[0] == "survives":
            continue
        sources = []
        for test in tests:
            text = module_source(test, read) if entry["lane"] == "loom" else (family_kernel(test, kernels) or (None, None))[1]
            if text is None:
                refuse("reference", f"{name}: no model source of {test} can be read" if entry["lane"] == "loom"
                       else f"{name}: {test} has no kernel file of its family")
            elif text not in sources:
                sources.append(text)
        if entry["lane"] == "loom" and not all(is_loom_failure(entry["failure"], text) for text in sources):
            refuse("reference", f"{name}: the failure {entry['failure']!r} is no message literal of a model source of its tests")
        elif entry["lane"] == "loom" and any(sum(entry["failure"] in content for content in diagnostics(text)) > 1 for text in sources):
            refuse("reference", f"{name}: the failure {entry['failure']!r} lies in more than one message literal of a model source of its "
                   "tests, so a panic holding it names no one assertion")
        if entry["lane"] == "genmc" and not all(c_literals(text).count(entry["failure"]) == 1 for text in sources):
            refuse("reference", f"{name}: the failure {entry['failure']!r} is no one check! message of its cases' kernel file")


def check_references(row, refuse, bindings, twins):
    name, binding, twin = row["id"], row.get("binding"), row.get("twin", [])
    if binding is not None:
        production = bindings.get(binding, {}).get("production", {})
        call, scope = production.get("call"), production.get("scope")
        if production.get("file") != row["path"]:
            refuse("reference", f"{name}: binding {binding!r} binds no operation in {row['path']}")
        elif not (isinstance(call, str) and call.strip() and isinstance(scope, list) and all(isinstance(header, str) for header in scope)):
            refuse("reference", f"{name}: binding {binding!r} holds no call or scope")
        elif genmc.normalized(call) not in genmc.normalized(row["find"]):
            refuse("reference", f"{name}: binding {binding!r} binds {call!r}, which its find lacks")
    if not isinstance(twin, list) or not all(isinstance(entry, dict) for entry in twin):
        refuse("reference", f"{name}: its twin is no list of lane entries")
        return
    lanes = [entry.get("lane") for entry in twin]
    if not all(isinstance(lane, str) for lane in lanes):
        refuse("reference", f"{name}: a twin names no lane")
        return
    if len(set(lanes)) != len(lanes):
        refuse("reference", f"{name}: its twins name a lane twice")
    for entry in twin:
        steps, test = entry.get("steps"), entry.get("test")
        if not isinstance(test, str) or test not in twins.get(entry["lane"], ()) \
                or not isinstance(steps, int) or isinstance(steps, bool) or steps < 1:
            refuse("reference", f"{name}: twin {entry!r} is no {entry['lane']} twin with its steps")


def nested(body, position):
    """Whether `position` of `body` lies in the body of an `fn` or `impl` nested in it."""
    for item in re.finditer(r"\b(?:fn|impl)\b", body):
        brace = body_open(body, item.end())
        if brace >= 0 and brace < position < (atomics.closing(body, brace) or len(body)):
            return True
    return False


def check_enclosing(row, refuse, normal, scope, offset):
    """Refuse `row` unless `scope`, its enclosing item's headers, resolves in `normal`, its file's normalized
    production text, to one body that holds its `find`, with its site, `offset` characters into the find, outside
    every nested `fn` or `impl`."""
    name = row["id"]
    if not isinstance(scope, list) or not scope:
        refuse("enclosing item", f"{name}: it names no enclosing item")
        return
    bodies = [normal]
    for header in scope:
        bodies = [body for text in bodies for body in genmc.bodies(text, genmc.normalized(header))]
    start = bodies[0].find(genmc.normalized(row["find"])) if len(bodies) == 1 else -1
    if start < 0:
        refuse("enclosing item", f"{name}: {' > '.join(scope)} resolves to {len(bodies)} bodies, or its body lacks the find")
    elif nested(bodies[0], start + len(genmc.normalized(row["find"][:offset]))):
        refuse("enclosing item", f"{name}: its site lies in an item nested in {' > '.join(scope)}")


LOOM_DEADLINE = 3600
# `genmc` in scripts/rust-lane.sh runs a case's `cargo check` under `deadline 5m` and its checker under `deadline 15m`,
# and provisions the checker under `deadline 40m`. A lane call's outer deadline is the sum over its cases, plus 5
# minutes for the lane's other steps.
GENMC_DEADLINE = (5 + 15) * 60
GENMC_SETUP = (40 + 5) * 60
# The lane's `stop_group` gives a stopped session 30 seconds before SIGKILL; the outer grace outlasts it.
STOP_GRACE = 45
# POLL caps the sleep between checks for child exit and recorded signals.
POLL = 0.05
PINS = ("STABLE", "NIGHTLY", "LOOM", "HERDTOOLS7", "LLVM", "KANI", "CARGO_FUZZ")
REQUIRED_PINS = ("STABLE", "NIGHTLY", "LOOM")
PIN_LINE = re.compile(r"""^  ([A-Z0-9_]+): (?:"([^"\n]*)"|'([^'\n]*)'|([^\s"'#]+))[ \t]*(?:#.*)?$""", re.M)
# Plain, unsilenced Cargo status lines carry the `Compiling` and `Checking` lines that `REBUILT` reads.
TERM = {"CARGO_TERM_COLOR": "never", "CARGO_TERM_QUIET": "false"}
# The environment forms of a compiler, wrapper, target, runner, flag, profile or output-directory override, which the
# loom tests build without; `CARGO_BUILD_JOBS` stays.
SHAPING_ENV = re.compile(r"^(?:RUSTC|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_RUSTFLAGS|"
                         r"CARGO_ENCODED_RUSTDOCFLAGS|CARGO_BUILD_(?!JOBS$)\w+|CARGO_TARGET_\w+|CARGO_PROFILE_\w+|LOOM_\w+)$")
LOOM_PASS = re.compile(r"^test result: ok\. 1 passed; 0 failed; 0 ignored;", re.M)
LOOM_FAIL = re.compile(r"^test result: FAILED\. 0 passed; 1 failed; 0 ignored;", re.M)
LOOM_IGNORED = re.compile(r"^test result: ok\. 0 passed; 0 failed; 1 ignored;", re.M)
LOOM_ABSENT = re.compile(r"^test result: ok\. 0 passed; 0 failed; 0 ignored;", re.M)
LOOM_RUNNING = re.compile(r"^running \d+ tests?$", re.M)
PANIC = re.compile(r"^thread '[^']*'(?: \(\d+\))? panicked at ([^\n]*?):(\d+):\d+:\n(.*)$", re.M)
REBUILT = {"loom": re.compile(r"^\s*Compiling kestrike v", re.M), "genmc": re.compile(r"^\s*(?:Checking|Compiling) genmc-kernels v", re.M)}
DECIDED = ("killed", "survived")
SIGNALS = (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
# During a hold, HELD stores handled signal numbers in delivery order. When HELD is None, `interrupted` raises
# KeyboardInterrupt.
HELD = None


class Stop(Exception):
    """A run that ends before its row results count, with `code` as its exit and the reason on standard error."""

    def __init__(self, code, reason):
        super().__init__(reason)
        self.code = code


def interrupted(number, frame):
    """Record a handled signal while a hold is set, else raise KeyboardInterrupt for it."""
    if HELD is not None:
        HELD.append(number)
        return
    raise KeyboardInterrupt(f"signal {number}")


@contextlib.contextmanager
def holding():
    """Hold the handled signals for the block and yield the list `interrupted` records them in, so the block's own steps
    decide where a signal takes effect. Inside another hold, yield that hold's list and leave the release to it. The
    release raises KeyboardInterrupt for a recorded signal unless one is already unwinding."""
    global HELD
    if HELD is not None:
        yield HELD
        return
    deliveries = HELD = []
    try:
        yield deliveries
    finally:
        HELD = None
        if deliveries and not isinstance(sys.exc_info()[1], KeyboardInterrupt):
            raise KeyboardInterrupt(f"signal {deliveries[0]}")


def workflow_pins(copy):
    """The toolchain pins of the workflow's top-level `env` block in `copy`, bare or in matched quotes; a missing or empty
    STABLE, NIGHTLY or LOOM pin stops the run."""
    text = (copy / ".github/workflows/agent-checks.yml").read_text(encoding="utf-8").split("\njobs:", 1)[0]
    pins = {match.group(1): next(value for value in match.groups()[1:] if value is not None) for match in PIN_LINE.finditer(text)}
    missing = [name for name in REQUIRED_PINS if not pins.get(name)]
    if missing:
        raise Stop(2, f"the workflow's env block names no {', '.join(missing)} pin")
    return {name: pins[name] for name in PINS if name in pins}


def lane_env(work, pins):
    """The loom lane's environment: the pins, every name `SHAPING_ENV` matches cleared, `--cfg loom`, the target and
    build directories under `work` and plain Cargo status lines."""
    env = {name: value for name, value in os.environ.items() if not SHAPING_ENV.match(name)}
    target = str(work / "target-loom")
    return dict(env, **pins, **TERM, RUSTFLAGS="--cfg loom", CARGO_TARGET_DIR=target, CARGO_BUILD_BUILD_DIR=target)


def stop_group(child, grace=STOP_GRACE, deliveries=(), spent=0):
    """End `child`'s process group: SIGTERM, so a lane stops the sessions it started, then SIGKILL to every member left
    once the leader has exited, `grace` seconds have passed, `deliveries` holds more signals than the `spent` ones that
    ended the caller's wait, or a raising handler cut the wait short."""
    try:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGTERM)
        ends = time.monotonic() + grace
        while child.poll() is None and len(deliveries) <= spent and time.monotonic() < ends:
            time.sleep(POLL)
    finally:
        with contextlib.suppress(ProcessLookupError):
            os.killpg(child.pid, signal.SIGKILL)
        child.wait()


def execute(command, cwd, env, deadline, output):
    """Run `command` in its own session under `deadline` seconds into `output`, a new file, and end its process group;
    return (exit or None on timeout, seconds). The handled signals are held from before the child starts until its group
    has ended: a recorded one ends the wait, a further one ends the stop's grace, and KeyboardInterrupt follows the
    stop. A signal recorded before the call starts no child."""
    started = time.monotonic()
    with open(output, "xb") as sink, holding() as deliveries:
        if deliveries:
            raise KeyboardInterrupt(f"signal {deliveries[0]}")
        child = subprocess.Popen(command, cwd=cwd, env=env, stdout=sink, stderr=subprocess.STDOUT, start_new_session=True)
        code, spent, pause = None, 0, 0.0005
        try:
            while True:
                code, spent = child.poll(), min(len(deliveries), 1)
                if code is not None or spent or time.monotonic() - started >= deadline:
                    break
                time.sleep(pause)
                pause = min(pause * 2, POLL)
        finally:
            stop_group(child, deliveries=deliveries, spent=spent)
        if deliveries:
            raise KeyboardInterrupt(f"signal {deliveries[0]}")
    return code, round(time.monotonic() - started, 1)


def loom_result(text, code, failure, rebuilt, site=None):
    """(result, reason) of one loom test run: `killed` for a panic at `site`, the (path, line) of the one assertion whose
    message literal holds `failure`, with `failure` in its first message line; `survived` for exactly one executed test
    that passed; `no verdict` otherwise. A planted run counts only once the crate rebuilt under the plant."""
    if code is None:
        return "no verdict", "timeout"
    if not rebuilt:
        return "no verdict", "no evidence that kestrike rebuilt"
    if code == 0 and LOOM_PASS.search(text):
        return "survived", "one executed test passed"
    if code != 0 and LOOM_FAIL.search(text):
        if failure and site and any(failure in message and (path, int(line)) == site for path, line, message in PANIC.findall(text)):
            return "killed", f"failed with {failure!r} at {site[0]}:{site[1]}"
        return "no verdict", "failed with another text or at another assertion"
    if LOOM_IGNORED.search(text):
        return "no verdict", "the test is ignored"
    if LOOM_ABSENT.search(text):
        return "no verdict", "the test is absent: no test matched its name"
    if not LOOM_RUNNING.search(text):
        return "no verdict", "a build failure"
    return "no verdict", "the test crashed: its run ended without a summary"


def case_exit(evidence, case):
    """The exit GenMC gave `case`, as the lane recorded it, or None."""
    try:
        return int((evidence / f"genmc-{case}.exit").read_text().strip())
    except (OSError, ValueError):
        return None


def identity_record(evidence):
    """The lane's identity record, with the fields `check_command` reads checked for their shape."""
    record = json.loads((evidence / "identity.json").read_text())
    if not (isinstance(record, dict) and isinstance(record.get("binary"), dict) and isinstance(record["binary"].get("path"), str)
            and isinstance(record.get("rustc"), dict) and all(isinstance(record["rustc"].get(key), str) for key in ("name", "toolchain"))):
        raise ValueError("the identity record lacks a binary path or a rustc name and toolchain")
    return record


def genmc_result(judge, declared, case, failure, evidence, planted, kernel, code):
    """(result, reason, executions) of one GenMC case from its raw lane output and `code`, its recorded exit: `survived`
    when `judge_case` accepts the case's positive declaration, `killed` when it accepts a violation at the `check!` that
    carries `failure` in `kernel`, the case family's kernel file, `no verdict` otherwise."""
    paths = {kind: evidence / f"genmc-{case}.{kind}" for kind in ("txt", "exit", "argv", "env")}
    if not all(path.is_file() for path in paths.values()) or not (evidence / "identity.json").is_file():
        return "no verdict", "the lane left no output", None
    try:
        judge.check_config(evidence)
        env = dict(line.split("=", 1) for line in paths["env"].read_text().splitlines() if "=" in line)
        judge.check_command(case, declared, identity_record(evidence), paths["argv"].read_text().splitlines(), env, evidence)
    except (judge.Refusal, OSError, ValueError, KeyError) as refusal:
        return "no verdict", f"the lane's build or command is not the declared one: {refusal}", None
    check_log = evidence / f"check-{case}.txt"
    if planted and not (check_log.is_file() and REBUILT["genmc"].search(check_log.read_text(encoding="utf-8", errors="replace"))):
        return "no verdict", "no evidence that the kernel rebuilt", None
    if code is None:
        return "no verdict", "no exit code", None
    text = paths["txt"].read_text(encoding="utf-8", errors="replace")
    called = evidence / f"genmc-{case}.intrinsics"
    intrinsics = sorted(set(called.read_text().split())) if called.is_file() else []
    graph = evidence / f"genmc-{case}.dot"
    attempts = [("survived", declared["cases"][case])]
    if failure and kernel:
        attempts.append(("killed", dict(declared["cases"][case], expect="violation", file=kernel, checks=[failure])))
    reasons = []
    for result, declaration in attempts:
        try:
            judged = judge.judge_case(case, declaration, text, code, graph, intrinsics)
            return result, f"judge_case accepts the {declaration['expect']} declaration", judged["executions"]
        except (judge.Refusal, OSError) as refusal:
            reasons.append(str(refusal))
    return "no verdict", "; ".join(reasons), None


def staged_write(path, text, mode, mtime_ns=None):
    """Replace `path` with a new regular file holding `text`, created exclusively beside it, with `mode` and, when given,
    `mtime_ns` set through its descriptor, so a reader sees the previous or the new text whole."""
    descriptor, staged = tempfile.mkstemp(dir=path.parent, prefix=f".{path.name}.", suffix=".weaken")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="") as sink:
            sink.write(text)
            sink.flush()
            os.fchmod(sink.fileno(), mode)
            if mtime_ns is not None:
                os.utime(sink.fileno(), ns=(mtime_ns, mtime_ns))
        os.replace(staged, path)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(staged)
        raise


def fresh_write(path, text, previous=None):
    """Replace `path` with a new file holding `text`, with the mode of `previous`, `path`'s own status unless given, and
    a modification time later than that status's."""
    previous = previous or path.stat()
    staged_write(path, text, stat.S_IMODE(previous.st_mode), max(time.time_ns(), previous.st_mtime_ns + 1))


def regular_digest(path):
    """The sha256 of `path` when it is a regular file, no symbolic link, that can be read, else None."""
    try:
        return None if path.is_symlink() or not path.is_file() else genmc.sha256(path)
    except OSError:
        return None


def save(path, data):
    """Write `data` as JSON to `path` as a new file with the mode a plain create gets under the umask."""
    umask = os.umask(0)
    os.umask(umask)
    staged_write(path, json.dumps(data, indent=2) + "\n", 0o666 & ~umask)


WANTED = {"kill": "killed", "survives": "survived", "unrun": None}


def row_entries(row):
    """(the lane entries a run of `row` executes, the result each must give, or None when no result is decided), for a
    row `check` accepts."""
    kind = next(key for key in DISPOSITIONS if key in row)
    entries = disposition_entries(kind, row[kind])
    if entries is None:
        raise ValueError(f"{row['id']}: its {kind} disposition is malformed")
    return entries, WANTED[kind]


def undecided(results):
    """Whether some (lane, test) of `results` has no `killed` or `survived` result among them."""
    outcomes = {}
    for result in results:
        outcomes.setdefault((result["lane"], result["test"]), set()).add(result["result"])
    return any(not outcome & set(DECIDED) for outcome in outcomes.values())


class Runner:
    """One `run`: the copy under `work`, its pins and the raw output of every test it runs."""

    def __init__(self, work):
        self.work, self.copy, self.evidence = work, work / "copy", work / "evidence"
        revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        with subprocess.Popen(["git", "-C", str(ROOT), "archive", revision], stdout=subprocess.PIPE) as archive:
            extracted = subprocess.run(["tar", "-x", "-C", str(self.copy)], stdin=archive.stdout, check=False)
        if archive.returncode or extracted.returncode:
            raise subprocess.CalledProcessError(archive.returncode or extracted.returncode, "git archive | tar -x")
        self.revision, self.pins = revision, workflow_pins(self.copy)
        # Each output's serial number keeps its path apart from every other output of the run.
        self.serial = 0
        # The row whose plant the loom build holds: a row's first loom test rebuilds the crate, and its later tests
        # reuse that build.
        self.rebuilt = None

    def read(self, path):
        return (self.copy / path).read_text(encoding="utf-8")

    def prepare(self):
        """Load the copy's GenMC judge, declaration and kernel texts, once `check` has accepted the copy."""
        self.judge, self.declared = load("judge-genmc", self.copy), json.loads((self.copy / GENMC).read_text())
        self.kernels = kernel_texts(self.copy / self.declared["package"])

    def output(self, label, name):
        self.serial += 1
        return self.evidence / f"{self.serial:03d}-{label}-{name}"

    def check_configs(self, lanes):
        """Stop the run when the merged Cargo configuration that a selected lane builds under holds an entry that shapes a
        build, as the lane's judge reads one: the copy's for both lanes, the kernel package's for GenMC. A loom selection
        also stops on a `LOOM_*` environment entry."""
        probes = [("copy", self.copy)] + ([("kernels", self.copy / self.declared["package"])] if "genmc" in lanes else [])
        for name, directory in probes:
            recorded = self.output("config", name)
            recorded.mkdir()
            command = ["cargo", f"+{self.pins['NIGHTLY']}", "-Zunstable-options", "config", "get", "--format", "json"]
            with open(recorded / "cargo-config.json", "xb") as sink:
                done = subprocess.run(command, cwd=directory, env=lane_env(self.work, self.pins), stdout=sink, stderr=subprocess.PIPE,
                                      check=False)
            if done.returncode:
                tail = " | ".join(done.stderr.decode("utf-8", "replace").strip().splitlines()[-3:])
                raise Stop(2, f"{shlex.join(command)} in {directory} exited {done.returncode}: {tail}")
            try:
                self.judge.check_config(recorded)
                loom = sorted(entry for entry in json.loads((recorded / "cargo-config.json").read_text()).get("env") or {}
                              if entry.startswith("LOOM_")) if "loom" in lanes else []
            except (self.judge.Refusal, ValueError, AttributeError, TypeError) as refusal:
                raise Stop(2, f"the Cargo configuration of {directory} shapes the build: {refusal}") from refusal
            if loom:
                raise Stop(2, f"the Cargo configuration of {directory} sets {', '.join(f'env.{entry}' for entry in loom)}")

    def check_declaration(self):
        """Stop the run when the copy's GenMC judge refuses the declaration against the unweakened copy: a binding whose
        kernel or production operation drifted, or a case that disagrees with the litmus tests it names. A plant then
        differs from the judged sources in its one site."""
        try:
            self.judge.check_transcription(self.declared)
            self.judge.check_correspondence(self.declared)
        except (self.judge.Refusal, OSError, *MALFORMED) as refusal:
            raise Stop(2, f"the copy's GenMC judge refuses its declaration: {refusal}") from refusal

    def loom(self, test, failure, row, runs):
        """The result of loom test `test` judged for `failure`, running it once per plant into `runs`."""
        if ("loom", test) not in runs:
            output = self.output(row or "baseline", f"loom-{test.replace('::', '.')}.txt")
            env = lane_env(self.work, self.pins)
            command = ["cargo", f"+{self.pins['STABLE']}", "test", "-p", "kestrike", "--lib", "--release", test, "--", "--exact"]
            code, seconds = execute(command, self.copy, env, LOOM_DEADLINE, output)
            text = output.read_text(encoding="utf-8", errors="replace")
            if row is not None and REBUILT["loom"].search(text):
                self.rebuilt = row
            runs[("loom", test)] = {"command": f'RUSTFLAGS="{env["RUSTFLAGS"]}" {shlex.join(command)}', "exit": code, "seconds": seconds,
                                    "output": str(output), "digest": genmc.sha256(output), "text": text}
        run = runs[("loom", test)]
        site = loom_site(test, failure, self.read) if failure else None
        result, reason = loom_result(run["text"], run["exit"], failure, row is None or self.rebuilt == row, site)
        return {"lane": "loom", "test": test, **{key: value for key, value in run.items() if key != "text"}, "result": result,
                "reason": reason}

    def genmc(self, cases, failure, row, runs):
        """The results of GenMC `cases` judged for `failure`, running each case once per plant into `runs`."""
        fresh = [case for case in dict.fromkeys(cases) if ("genmc", case) not in runs]
        if fresh:
            evidence = self.output(row or "baseline", "genmc")
            profile = "pr" if set(fresh) <= set(self.declared["profiles"]["pr"]) else "scheduled"
            command = ["bash", "scripts/rust-lane.sh", "genmc", profile, *fresh]
            env = dict(os.environ, **self.pins, **TERM, EVIDENCE=str(evidence), GITHUB_STEP_SUMMARY=str(evidence / "summary.md"))
            evidence.mkdir()
            code, seconds = execute(command, self.copy, env, GENMC_DEADLINE * len(fresh) + GENMC_SETUP, evidence / "lane.txt")
            for case in fresh:
                output = evidence / f"genmc-{case}.txt"
                runs[("genmc", case)] = {"command": shlex.join(command), "exit": case_exit(evidence, case), "lane_exit": code,
                                         "seconds": seconds, "output": str(output),
                                         "digest": genmc.sha256(output) if output.is_file() else None, "evidence": evidence}
        results = []
        for case in cases:
            run = runs[("genmc", case)]
            if run["lane_exit"] is None:
                result, reason, executions = "no verdict", "the lane passed its deadline", None
            else:
                kernel = (family_kernel(case, self.kernels) or (None, None))[0]
                result, reason, executions = genmc_result(self.judge, self.declared, case, failure, run["evidence"], row is not None, kernel,
                                                          run["exit"])
            results.append({"lane": "genmc", "test": case, **{key: value for key, value in run.items() if key != "evidence"},
                            "result": result, "reason": reason, "executions": executions})
        return results

    def each(self, entry, row, runs):
        """The results of one lane entry, a list per loom test and one list for a GenMC batch, each yielded once it is
        judged: on the unweakened copy when `row` is None, else under the plant of the row that `row` labels. `runs`
        holds each test's run under the same plant, so a test two entries name runs once."""
        if entry["lane"] == "loom":
            for test in entry["tests"]:
                yield [self.loom(test, entry.get("failure"), row, runs)]
        else:
            yield self.genmc(entry["tests"], entry.get("failure"), row, runs)


def run(work, selected):
    """Run the baseline, then each selected row's plant, and return the report and exit code."""
    started = time.monotonic()
    runner = Runner(work)
    print(f"weaken-orderings: running the committed revision {runner.revision}; uncommitted changes are not in the copy", file=sys.stderr)
    report, code = check(runner.read, runner.copy, runner.copy)
    if code:
        raise Stop(2, f"check refuses the copy's catalog: {report.get('refusals') or report.get('error')}")
    runner.prepare()
    catalog = json.loads(runner.read(CATALOG))
    rows = [row for row in catalog["rows"] if not selected or row["id"] in selected]
    if selected and len(rows) != len(set(selected)):
        raise Stop(2, f"no catalog row named {sorted(set(selected) - {row['id'] for row in rows})}")
    # A row's evidence carries its catalog position, so no row id becomes a path component.
    labels = {row["id"]: f"row{index:02d}" for index, row in enumerate(catalog["rows"])}
    originals = {path: runner.read(path) for path in catalog["files"]}
    digests = {path: genmc.sha256(runner.copy / path) for path in catalog["files"]}
    planted_paths = sorted({row["path"] for row in rows if row_entries(row)[0]})
    unfaithful = [path for path in planted_paths if (runner.copy / path).read_bytes() != originals[path].encode("utf-8")]
    if unfaithful:
        raise Stop(2, f"the scoped files {unfaithful} hold line endings a text restore cannot reproduce byte for byte")
    baseline = sorted({(entry["lane"], test) for row in rows for entry in row_entries(row)[0] for test in entry["tests"]})
    lanes = {lane for lane, _ in baseline}
    if lanes:
        runner.check_configs(lanes)
    if "genmc" in lanes:
        runner.check_declaration()
    output = {"revision": runner.revision, "pins": dict(runner.pins), "baseline": [], "rows": {}}
    tree = subprocess.run(["cargo", f"+{runner.pins['STABLE']}", "tree", "-p", "kestrike", "-i", "loom", "--target", "all", "--depth", "0",
                           "--prefix", "none"], cwd=runner.copy, env=lane_env(work, runner.pins), capture_output=True, text=True, check=False)
    words = tree.stdout.split()
    output["pins"]["loom resolved"] = words[1] if tree.returncode == 0 and len(words) > 1 else "unresolved"
    if "loom" in lanes and output["pins"]["loom resolved"] != f"v{runner.pins['LOOM']}":
        raise Stop(2, f"the copy resolves loom {output['pins']['loom resolved']}, and the LOOM pin is v{runner.pins['LOOM']}")
    # The workspace lock file is ignored, so that resolution wrote the one the copy's builds use.
    output["pins"]["Cargo.lock sha256"] = regular_digest(runner.copy / "Cargo.lock")
    output["pins"]["rustc"] = subprocess.run(["rustc", f"+{runner.pins['STABLE']}", "--version"], capture_output=True, text=True,
                                             check=False).stdout.strip()
    output["pins"]["host"] = os.uname().machine
    output["pins"]["cpus"] = os.cpu_count()
    output["pins"]["CARGO_BUILD_JOBS"] = os.environ.get("CARGO_BUILD_JOBS")

    def checkpoint(active):
        save(work / "progress.json", dict(output, active=active, seconds=round(time.monotonic() - started, 1)))

    checkpoint("baseline")

    def drifted():
        """The scoped files that are no regular, readable file holding the unweakened copy's bytes."""
        return sorted(name for name in catalog["files"] if regular_digest(runner.copy / name) != digests[name])

    baseline_runs = {}
    for lane, test in baseline:
        for results in runner.each({"lane": lane, "tests": [test]}, None, baseline_runs):
            output["baseline"] += results
            drift = drifted()
            if drift or any(result["result"] != "survived" for result in results):
                output["seconds"] = round(time.monotonic() - started, 1)
                checkpoint(None)
                if drift:
                    raise Stop(4, f"the scoped files {drift} differ from the unweakened copy after the baseline test {test}")
                raise Stop(3, json.dumps(output, indent=2))
            checkpoint("baseline")
    checkpoint(None)

    @contextlib.contextmanager
    def planted(row):
        """Hold `row`'s plant in the copy, then check that it stayed in place, write the unweakened file back and compare
        every scoped file's digest."""
        text, path = originals[row["path"]], runner.copy / row["path"]
        production = atomics.blanked(text)[0]
        if production.count(row["find"]) != 1:
            raise Stop(2, f"{row['id']}: its find does not occur once in {row['path']}'s production text")
        at = production.find(row["find"])
        plant = text[:at] + row["replace"] + text[at + len(row["find"]):]
        unweakened = path.stat()
        try:
            fresh_write(path, plant)
            yield
        finally:
            blocked = signal.pthread_sigmask(signal.SIG_BLOCK, set(SIGNALS))
            try:
                moved = regular_digest(path) != hashlib.sha256(plant.encode("utf-8")).hexdigest()
                try:
                    fresh_write(path, text, unweakened if moved else None)
                except OSError as error:
                    raise Stop(4, f"the unweakened {row['path']} cannot be written back after {row['id']}'s tests: {error}") from error
                drift = drifted()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, blocked)
            if moved:
                raise Stop(4, f"the plant of {row['path']} changed while {row['id']}'s tests ran")
            if drift:
                raise Stop(4, f"the scoped files {drift} differ from the unweakened copy after a restore")

    mismatched = []
    for row in rows:
        planted_entries, wanted = row_entries(row)
        record = {"plant": {"path": row["path"], "find": row["find"], "replace": row["replace"]}, "expected": wanted, "results": []}
        output["rows"][row["id"]] = record
        if not planted_entries:
            record.update(result="skipped", reason=row.get("unrun", {}).get("reason") or row.get("survives", {}).get("reason"), agrees=True)
            checkpoint(None)
            continue
        checkpoint(row["id"])
        row_started, runs = time.monotonic(), {}
        with holding(), planted(row):
            for entry in planted_entries:
                for results in runner.each(entry, labels[row["id"]], runs):
                    record["results"] += results
                    checkpoint(row["id"])
        record["seconds"] = round(time.monotonic() - row_started, 1)
        record["agrees"] = wanted is None or all(result["result"] == wanted for result in record["results"])
        if not record["agrees"]:
            mismatched.append(row["id"])
        checkpoint(None)
    output["seconds"] = round(time.monotonic() - started, 1)
    output["mismatched"] = mismatched
    output["no verdict"] = [name for name, record in output["rows"].items() if undecided(record["results"])]
    return output, 1 if mismatched else 0


def run_command(args):
    work = Path(args.work).resolve()
    scripts = [f"scripts/{name}.py" for name in ("weaken-orderings", "classify-atomics", "judge-genmc", "judge-rc11")]
    try:
        if work.is_relative_to(ROOT):
            raise Stop(2, f"the work directory {work} lies inside the checkout {ROOT}")
        try:
            populated = work.exists() and any(work.iterdir())
        except OSError as error:
            raise Stop(2, f"the work directory {work} cannot be listed: {error}") from error
        if populated:
            raise Stop(2, f"the work directory {work} is not empty")
        if subprocess.run(["git", "-C", str(ROOT), "diff", "--quiet", "HEAD", "--", *scripts], check=False).returncode:
            raise Stop(2, f"{scripts} differ from HEAD, so the report's revision would not name the code that judged it")
        try:
            (work / "copy").mkdir(parents=True)
            (work / "evidence").mkdir()
        except OSError as error:
            raise Stop(2, f"the work directory {work} cannot hold the copy: {error}") from error
        for number in SIGNALS:
            if signal.getsignal(number) != signal.SIG_IGN:
                signal.signal(number, interrupted)
        report, code = run(work, args.row)
    except Stop as stop:
        print(f"weaken-orderings: {stop}", file=sys.stderr)
        return stop.code
    save(work / "report.json", report)
    print(json.dumps({"report": str(work / "report.json"), "mismatched": report["mismatched"], "no verdict": report["no verdict"]}))
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("check")
    runs = commands.add_parser("run")
    runs.add_argument("--work", required=True)
    runs.add_argument("--row", action="append", default=[])
    args = parser.parse_args(argv)
    if args.command == "run":
        return run_command(args)
    report, code = check()
    print(json.dumps(report, indent=2))
    return code


if __name__ == "__main__":
    sys.exit(main())
