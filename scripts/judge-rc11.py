#!/usr/bin/env python3
"""Pin the herd7 RC11 installation and credit litmus outcomes only when each matches its declaration.

Usage:
  judge-rc11.py options
  judge-rc11.py identity --herd7 PATH --libdir DIR --evidence DIR
  judge-rc11.py judge --evidence DIR [--revision SHA]

The declaration is the committed `verification/rc11/expected.json`: the herd7
version, the semantic options every run passes, the sha256 of each file in
the model's transitive closure under herd7's library directory, and per
litmus test the result header, the condition text and the `Sometimes` or
`Never` outcome; a base declares `base` true, a variant names its base in
`drops_from`, and a `Never` variant gives its `redundant` reason and may
name a `joint` variant. The tests are the committed
`verification/rc11/litmus/*.litmus`.
`options` prints the semantic options one per line for the lane.

A test that declares `base` is a base, and a test that names a base in
`drops_from` is a variant of it. A program is a litmus file's initial state,
threads and condition; the name line and the comments before the initial
state lie outside it. `judge` reads a program only in this shape, which is
narrower than what herd7 accepts:

- a `C NAME` first line;
- unnested `(* ... *)` comments before the initial state, holding no brace
  and no later line that opens with `KEY=`, since herd7 reads a brace there
  as the initial state and such a line as a test option;
- no `(*` or `*)` anywhere after those comments, even as C code, and no
  `/*`, `*/` or `//`;
- the initial state on one `{ NAME = INTEGER; ... }` line;
- each thread as a `Pn(...) {` line, one straight-line statement per line
  and a `}` line, where a statement ends in its one `;`, holds no brace and
  opens with no control keyword;
- one final `exists`, `~exists` or `forall` line with no `<<` trailer, so
  no `filter` line narrows the executions herd7 checks and no `locations`
  line stands between the threads and the condition.

A fence is an `atomic_thread_fence(ORDER);` statement alone on its line,
named by its thread and its statement position in that thread's body. No
fence form repeats within a run of adjacent fence lines, so each set of
removed fences has one set of positions. Programs compare line by line after
whitespace is compacted to one space between two word characters or two
operator characters, so a reordered or renamed program is another program.

Before it reads any herd7 output, `judge` derives each relation from the
committed litmus text and refuses a defective declaration as one tool
failure. It first checks the test set and each test's name and fields, and
when any is wrong it names those defects alone: an empty or malformed test
set; a name that does not start with an ASCII word character and continue
with word characters, `.`, `+` and `-`, which keeps every litmus path inside
the litmus directory; a missing `header`, `condition` or `outcome`; a
present `header`, `condition`, `outcome`, `drops_from`, `joint` or
`redundant` that is no nonempty string; a present `base` that is not `true`;
and an outcome other than `Sometimes` or `Never`. Otherwise it names every
defect the remaining checks find:

- a test whose litmus file cannot be read or decoded, or whose text lies
  outside the shape above;
- a `drops_from` that names no declared base;
- a variant whose declared condition differs from its base's, or whose
  program is not its base's with one or more fence lines removed;
- a base whose declared outcome is not `Never`: every outcome of a base is
  an outcome of each variant, so a `Sometimes` variant is evidence about
  the dropped fences only under a `Never` base;
- a fence of a base that no variant drops alone;
- a base with no `Sometimes` variant: a matching `Sometimes` result for a
  variant witnesses that the condition is reachable once fences are
  dropped, which `Never` results alone cannot show. A base with no variant
  fails this check, and the one before it for each fence it holds, so
  deleting the last variant of a declared base is refused;
- a `Never` variant with no `redundant` reason, or whose `joint` names no
  `Sometimes` variant of the same base whose dropped fences include its
  own;
- a `joint` or `redundant` on a test that is no `Never` variant;
- a test without `drops_from` whose program is another declared test's
  with fence lines removed, under the same condition. Removing a declared
  variant's `drops_from` together with its base's `base` is thereby
  refused.

`identity` writes `identity.json` into the evidence directory: the version
herd7 prints, the sha256 of the herd7 executable, its library directory, the
closure it resolves by following `include` lines from the model plus
`stdlib.cat`, and each test file's sha256. It also writes `pins.txt`, the
identity's provenance lines. herd7 finds a model file in its working
directory or under `HERDLIB` before its library directory, so `identity`
refuses a set `HERDLIB` and a closure file in the working directory. A
version, closure member or file digest that differs from the declaration is
a drift the judgment refuses; the binary's digest is recorded, and credit
rests on the version and the pinned closure.

`judge` reads `identity.json` and, per declared test, `herd-<test>.argv` (the
command the lane ran, one argument per line), `herd-<test>.txt` (its stdout
and stderr) and `herd-<test>.exit` (its exit code). The command must be the
herd7 the identity names with exactly the declared options, then `-show prop
-o DIR`, which only writes witness graphs, then the test's committed litmus
file. It credits a test
only from one normal completed result: exit 0; exactly one `Test NAME
Allowed` header; a `States` count, an `Ok` or `No` verdict, `Witnesses` with
positive and negative counts, the declared condition, one `Observation` line
naming the test and one `Hash=` line. `Sometimes` needs `Ok` with positive and
negative counts above zero; `Never` needs `No` with zero positives over a
nonempty checked domain. Refused: a missing or extra test; an exit of 124,
130 or 143 (interrupted); another nonzero exit; a `Warning` line or a `Loop`
verdict (cut off by the unrolling bound); a missing or repeated line; a
command other than the declared one, `-through`, `-skipcheck` and
`-skipchecks` included; an outcome or header that differs from the
declaration; a zero count where one is required; and identity drift.

`judge` writes `report.json` and `receipt.json`, the receipt in the form
`verify-receipts.py credit --receipt` imports: completion `completed`,
`timeout` for an interrupted run, `exhausted` for a cut-off or warned one and
`tool failure` otherwise, the selection verdict, every judged test executed,
and digests of every input the judgment read and of the committed inventory,
registry and obligation catalog the credit binds. Exit 0 credits, 1 is an outcome
mismatch, 2 is a tool failure or drift, 3 is an incomplete run. Evidence JSON
of another shape than the judge reads, or nested past the parser's depth, is
a tool failure. An argument error exits 2 without a report, and so does an
input the judgment or the receipt cannot read. A report or receipt the judge
cannot write also exits 2. The receipt records `pins.txt` as UTF-8, with a
replacement character for each undecodable byte.
"""

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from collections import namedtuple
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
EXPECTED = ROOT / "verification/rc11/expected.json"
LITMUS = ROOT / "verification/rc11/litmus"
CREDITED, MISMATCH, TOOL_FAILURE, INCOMPLETE = 0, 1, 2, 3
VERDICTS = {CREDITED: "credited", MISMATCH: "outcome mismatch", TOOL_FAILURE: "tool failure", INCOMPLETE: "incomplete"}
INTERRUPTED = (124, 130, 143)
WIDENING = ("-through", "-skipcheck", "-skipchecks")
INCLUDE = re.compile(r'^\s*include\s+"([^"]+)"', re.M)
FENCE = re.compile(r"atomic_thread_fence\(\w+\);")
NAME_LINE = re.compile(r"C [\w.+-]+", re.A)
TEST_NAME = re.compile(r"\w[\w.+-]*", re.A)
STATE = re.compile(r"\{(?:[A-Za-z_]\w*=(?: ?-)?\d+;)*\}", re.A)
THREAD = re.compile(r"(P\d+)\([^(){}/]*\)\{")
STATEMENT = re.compile(r"[^;{}]*;")
CONTROL = re.compile(r"(?:if|else|while|for|do|switch|goto)\b")
CONDITION = re.compile(r"(?:~?exists|forall)\b")
OUTCOMES = ("Sometimes", "Never")
OPERATOR = frozenset("+-*/%&|<>=!^~.:?")
INFO_KEY = re.compile(r"[A-Za-z][\w/.-]*[ \t\r]*=", re.A)
Program = namedtuple("Program", "state threads condition")
Thread = namedtuple("Thread", "name header body")


class Unreadable(ValueError):
    """Litmus text outside the shape `program` reads; the message names the rule it breaks."""


class Refusal(Exception):
    def __init__(self, code, reason, completion=None):
        super().__init__(reason)
        self.code = code
        self.completion = completion or {INCOMPLETE: "exhausted", TOOL_FAILURE: "tool failure"}.get(code, "completed")


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"unreadable {path}: {error}") from error


# Each search resumes after the previous lexeme, so a comment marker inside a literal and a quote inside a comment
# stay part of their lexeme. A char literal match spans its whole `\xNN` or `\u{...}` escape and its closing quote.
# A lifetime such as `'r` or `'r#r` and a raw identifier such as `r#r` match as one lexeme, so the `"` after either
# opens a cooked string. The two lookbehinds open a raw string at an `r` that begins a token or follows a `b` or `c`
# that does, so the `r` ending an identifier such as `bar` stays code. Every alternative starts with a fixed
# character outside any capturing group, which lets the search skip directly to the next candidate character.
RUST_LEXEME = re.compile(
    r'//[^\n]*|/\*'
    r'|r(?=#*")(?<![^\Wbc]r)(?<!\w[bc]r)(#*)".*?"\1|r(?<!\wr)#\w+|"(?:\\.|[^"\\])*"'
    r"|'(?:\\x[0-9A-Fa-f]{2}|\\u\{[0-9A-Fa-f][0-9A-Fa-f_]*\}|\\.|[^\\'\n])'"
    r"|'(?!\d)(?:r#)?\w+\b(?!')",
    re.S,
)
BLOCK_EDGE = re.compile(r"/\*|\*/")


def rust_lexemes(text):
    """Yield `(kind, start, end)` for each comment, string and char literal of Rust source `text`, in order.

    `kind` is `comment`, `string`, `char` or `unclosed`. Block comments nest as rustc nests them, and a block comment
    that never closes is `unclosed` and ends at the end of `text`. A lifetime or raw identifier is consumed as code
    and yields nothing. A string's span starts at its `r` or quote, so a `b` or `c` prefix stays in the code.
    """
    start = 0
    while match := RUST_LEXEME.search(text, start):
        lexeme, start = match.group(), match.end()
        if lexeme == "/*":
            depth = 1
            while depth and (edge := BLOCK_EDGE.search(text, start)):
                depth += 1 if edge.group() == "/*" else -1
                start = edge.end()
            kind, start = ("comment", start) if depth == 0 else ("unclosed", len(text))
        elif lexeme[0] == "/":
            kind = "comment"
        elif lexeme[-1] in '"#':
            kind = "string"
        elif lexeme[-1] == "'":
            kind = "char"
        else:
            continue
        yield kind, match.start(), start


def litmus_digests():
    return {path.stem: sha256(path) for path in sorted(LITMUS.glob("*.litmus"))}


def closure(libdir, model):
    """Return the sha256 of the model, every file it includes transitively, and stdlib.cat."""
    found, pending = {}, [model, "stdlib.cat"]
    while pending:
        name = pending.pop()
        if name in found:
            continue
        path = Path(libdir) / name
        if not path.is_file():
            raise Refusal(TOOL_FAILURE, f"the model closure names {name}, absent from {libdir}")
        found[name] = sha256(path)
        pending += INCLUDE.findall(path.read_text(encoding="utf-8", errors="replace"))
    return dict(sorted(found.items()))


def identity(args):
    expected = read_json(EXPECTED)
    if os.environ.get("HERDLIB"):
        raise Refusal(TOOL_FAILURE, "HERDLIB is set, so herd7 could load a model file outside its library directory")
    record = {
        "version": subprocess.run([args.herd7, "-version"], capture_output=True, text=True, check=False).stdout.strip(),
        "binary": {"path": args.herd7, "sha256": sha256(args.herd7)},
        "libdir": args.libdir,
        "closure": closure(args.libdir, expected["model"]),
        "tests": litmus_digests(),
    }
    shadowing = sorted(name for name in record["closure"] if Path(name).exists())
    if shadowing:
        raise Refusal(TOOL_FAILURE, f"the working directory holds closure files {shadowing}, which herd7 would load first")
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (evidence / "pins.txt").write_text(pins(record))
    print(json.dumps({"identity": str(evidence / "identity.json")}))
    return CREDITED


def pins(record):
    lines = [f"- herd7 {record['version']}; sha256 {record['binary']['sha256']}",
             f"- library {record['libdir']}"]
    lines += [f"- {name} sha256 {digest}" for name, digest in record["closure"].items()]
    return "\n".join(lines) + "\n"


def check_identity(expected, record):
    if not record.get("version", "").startswith(expected["herd7"] + ","):
        raise Refusal(TOOL_FAILURE, f"herd7 reports {record.get('version')!r}, declared {expected['herd7']}")
    if any(option in WIDENING for option in expected["options"]):
        raise Refusal(TOOL_FAILURE, f"the declared options {expected['options']} widen or skip checks")
    if record.get("closure") != expected["closure"]:
        raise Refusal(TOOL_FAILURE, f"the model closure {record.get('closure')} differs from the declared {expected['closure']}")
    tests = litmus_digests()
    if record.get("tests") != tests:
        raise Refusal(TOOL_FAILURE, "the litmus files changed since the identity was taken")
    if set(tests) != set(expected["tests"]):
        raise Refusal(TOOL_FAILURE, f"the litmus files {sorted(tests)} differ from the declared tests {sorted(expected['tests'])}")


def single(lines, pattern, name, what):
    found = [match for match in map(re.compile(pattern).match, lines) if match]
    if len(found) != 1:
        raise Refusal(TOOL_FAILURE, f"{name} prints {len(found)} {what} lines")
    return found[0]


def check_command(name, expected, record, argv):
    """Refuse a command other than the identified herd7 with the declared options, the graph display options and the test's committed file."""
    tail = argv[1 + len(expected["options"]):]
    if (
        len(argv) < 2 or argv[0] != record["binary"]["path"]
        or argv[1:1 + len(expected["options"])] != expected["options"]
        or len(tail) != 5 or tail[:3] != ["-show", "prop", "-o"]
        or Path(tail[4]).resolve() != (LITMUS / f"{name}.litmus").resolve()
    ):
        raise Refusal(TOOL_FAILURE, f"{name} ran {argv}, not herd7 {' '.join(expected['options'])} -show prop -o DIR {name}.litmus")


def judge_test(name, declared, text, exit_code):
    """Return the counts of one normal completed result that matches its declaration."""
    if exit_code in INTERRUPTED:
        raise Refusal(INCOMPLETE, f"{name} was interrupted (exit {exit_code})", "timeout")
    if exit_code != 0:
        raise Refusal(TOOL_FAILURE, f"{name} exited {exit_code}")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    warnings = [line for line in lines if line.startswith("Warning")]
    if warnings:
        raise Refusal(INCOMPLETE, f"{name} warns {warnings[0]!r}")
    header = single(lines, rf"^Test {re.escape(name)} (\w+)$", name, "Test")
    states = int(single(lines, r"^States (\d+)$", name, "States").group(1))
    looped, verdict = single(lines, r"^(Loop )?(Ok|No)$", name, "verdict").groups()
    single(lines, r"^Witnesses$", name, "Witnesses")
    positive, negative = map(int, single(lines, r"^Positive: (\d+) Negative: (\d+)$", name, "witness count").groups())
    condition = single(lines, r"^Condition (.+)$", name, "Condition").group(1)
    observation = single(lines, rf"^Observation {re.escape(name)} (\w+) (\d+) (\d+)$", name, "Observation")
    single(lines, r"^Hash=[0-9a-f]+$", name, "Hash")
    if looped:
        raise Refusal(INCOMPLETE, f"{name} reports Loop {verdict}: the unrolling bound cut the exploration")
    if header.group(1) != declared["header"]:
        raise Refusal(MISMATCH, f"{name} answers {header.group(1)}, declared {declared['header']}")
    if condition != declared["condition"]:
        raise Refusal(TOOL_FAILURE, f"{name} checks {condition!r}, declared {declared['condition']!r}")
    outcome = observation.group(1)
    if (int(observation.group(2)), int(observation.group(3))) != (positive, negative):
        raise Refusal(TOOL_FAILURE, f"{name} observation counts differ from its witnesses")
    if outcome != declared["outcome"]:
        raise Refusal(MISMATCH, f"{name} is {outcome}, declared {declared['outcome']}")
    if outcome == "Sometimes" and not (verdict == "Ok" and positive > 0 and negative > 0):
        raise Refusal(MISMATCH, f"{name} Sometimes needs Ok with both counts above zero, not {verdict} {positive} {negative}")
    if outcome == "Never" and not (verdict == "No" and positive == 0 and negative > 0 and states > 0):
        raise Refusal(MISMATCH, f"{name} Never needs No with zero positives over a nonempty domain, not {verdict} {positive} {negative}")
    return {"outcome": outcome, "positive": positive, "negative": negative, "states": states}


def compact(line):
    """`line` with its whitespace runs removed, except one space between two word characters or two operator
    characters, so compaction never joins two tokens into one."""
    out = ""
    for token in line.split():
        if out and ((re.match(r"\w", out[-1]) and re.match(r"\w", token[0])) or (out[-1] in OPERATOR and token[0] in OPERATOR)):
            out += " "
        out += token
    return out


def skip_space(text, at):
    """The index of the first non-whitespace character of `text` at or after `at`, or its length."""
    while at < len(text) and text[at].isspace():
        at += 1
    return at


def program(text):
    """The `Program` of litmus `text`, each line compacted; raises `Unreadable` naming the first rule `text` breaks.

    The rules are the read shape the module documentation states: the `C NAME` line, the leading comments, the
    initial state, the threads and their statements, the fences, and the one final condition line.
    """
    first, _, rest = text.partition("\n")
    if not NAME_LINE.fullmatch(first):
        raise Unreadable("its first line is no `C NAME` line")
    at = skip_space(rest, 0)
    while rest.startswith("(*", at):
        close = rest.find("*)", at + 2)
        if close < 0 or "(*" in rest[at + 2:close]:
            raise Unreadable("a comment before its initial state is unclosed or nested")
        comment = rest[at + 2:close]
        if "{" in comment or "}" in comment or any(INFO_KEY.match(line) for line in comment.split("\n")[1:]):
            raise Unreadable("a comment before its initial state holds a brace or a line that opens with `KEY=`")
        at = skip_space(rest, close + 2)
    rest = rest[at:]
    if "(*" in rest or "*)" in rest:
        raise Unreadable("a `(*` or `*)` stands outside the comments before its initial state")
    raw = [line.strip() for line in rest.splitlines() if line.strip()]
    if any(mark in line for line in raw for mark in ("/*", "*/", "//")):
        raise Unreadable("it holds a C comment")
    lines = [compact(line) for line in raw]
    if not lines or not STATE.fullmatch(lines[0]):
        raise Unreadable("its initial state is no single `{ NAME = INTEGER; ... }` line")
    threads, index = [], 1
    while index < len(lines) and (header := THREAD.fullmatch(lines[index])):
        name = header.group(1)
        close = next((at for at in range(index + 1, len(lines)) if lines[at] == "}"), None)
        if close is None:
            raise Unreadable(f"thread {name} has no closing `}}` line")
        body = tuple(lines[index + 1:close])
        run = []
        for line in (*body, ""):
            if "atomic_thread_fence" in line and not FENCE.fullmatch(line):
                raise Unreadable(f"thread {name} holds a fence that shares its line")
            if line and (not STATEMENT.fullmatch(line) or CONTROL.match(line)):
                raise Unreadable(f"thread {name} holds {line!r}, which is no single straight-line statement")
            if FENCE.fullmatch(line):
                run.append(line)
                continue
            if len(set(run)) != len(run):
                raise Unreadable(f"thread {name} holds the same fence twice among adjacent fence lines")
            run = []
        threads.append(Thread(name, lines[index], body))
        index = close + 1
    if index == len(lines):
        raise Unreadable("it has no condition line")
    if index != len(lines) - 1 or not CONDITION.match(lines[index]):
        raise Unreadable(f"{lines[index]!r} is neither a thread header nor its one final `exists`, `~exists` or `forall` line")
    if "<<" in lines[index]:
        raise Unreadable("its condition line holds a `<<` trailer")
    return Program(lines[0], tuple(threads), lines[index])


def dropped(base, variant):
    """The fences of program `base`, as (thread, position), whose removal gives program `variant`.

    The result is a nonempty set, or None when the two programs are equal or differ by anything other than fence
    lines. A position counts statements from 1 in the base thread's body.
    """
    if base.state != variant.state or base.condition != variant.condition or len(base.threads) != len(variant.threads):
        return None
    fences = set()
    for index, thread in enumerate(base.threads):
        kept = variant.threads[index]
        if thread.header != kept.header:
            return None
        at = 0
        for position, line in enumerate(thread.body, 1):
            if at < len(kept.body) and kept.body[at] == line:
                at += 1
            elif FENCE.fullmatch(line):
                fences.add((thread.name, position))
            else:
                return None
        if at != len(kept.body):
            return None
    return frozenset(fences) or None


def fence_lines(parsed):
    """The fences of program `parsed` as (thread, position), the identity `dropped` reports."""
    return {(thread.name, position) for thread in parsed.threads
            for position, line in enumerate(thread.body, 1) if FENCE.fullmatch(line)}


def field_defects(name, declared):
    """The defects of one declared test's name and fields."""
    if not TEST_NAME.fullmatch(name):
        return [f"{name!r} is no test name: an ASCII word character, then word characters, `.`, `+` and `-`"]
    defects = [f"{name} declares no {key}" for key in ("header", "condition", "outcome") if key not in declared]
    malformed = [key for key in ("header", "condition", "outcome", "drops_from", "joint", "redundant")
                 if key in declared and not (isinstance(declared[key], str) and declared[key].strip())]
    defects += [f"{name} declares a {key} that is no nonempty string" for key in malformed]
    if "outcome" in declared and "outcome" not in malformed and declared["outcome"] not in OUTCOMES:
        defects.append(f"{name} declares outcome {declared['outcome']!r}, not Sometimes or Never")
    if "base" in declared and declared["base"] is not True:
        defects.append(f"{name} declares a base that is not true")
    return defects


def relation_defects(expected, read):
    """The relation defects of the declaration's tests, where `read(name)` returns a test's litmus text.

    A malformed or empty test set, or any name or field defect, is returned alone and stops the later checks for
    the whole declaration; otherwise every defect the program and relation checks find is returned together.
    """
    tests = expected.get("tests") if isinstance(expected, dict) else None
    if not isinstance(tests, dict) or not all(isinstance(declared, dict) for declared in tests.values()):
        return ["the declaration's tests are no object of test objects"]
    if not tests:
        return ["the declaration declares no tests"]
    defects = [defect for name, declared in tests.items() for defect in field_defects(name, declared)]
    if defects:
        return defects
    programs = {}
    for name in tests:
        try:
            programs[name] = program(read(name))
        except (OSError, ValueError) as error:
            defects.append(f"{name} has no readable litmus program: {error}")
    variants = {}
    for name, declared in tests.items():
        base = declared.get("drops_from")
        if base is None or name not in programs:
            continue
        if base not in tests:
            defects.append(f"{name} drops_from {base!r}, which is no declared test")
            continue
        if "base" not in tests[base]:
            defects.append(f"{name} drops_from {base}, which declares no base")
            continue
        if base not in programs:
            continue
        if declared["condition"] != tests[base]["condition"]:
            defects.append(f"{name} declares another condition than its base {base}")
            continue
        fences = dropped(programs[base], programs[name])
        if fences is None:
            defects.append(f"{name} is not {base} with fence lines removed")
            continue
        variants.setdefault(base, {})[name] = fences
    for base in sorted(name for name in programs if "base" in tests[name]):
        found = variants.get(base, {})
        if tests[base]["outcome"] != "Never":
            defects.append(f"{base} is a base declared {tests[base]['outcome']}, not Never")
        alone = {fence for drop in found.values() if len(drop) == 1 for fence in drop}
        for thread, position in sorted(fence_lines(programs[base]) - alone):
            defects.append(f"no variant of {base} drops its {thread} fence at statement {position} alone")
        if all(tests[name]["outcome"] != "Sometimes" for name in found):
            defects.append(f"{base} has no Sometimes variant")
        for name, drop in sorted(found.items()):
            if tests[name]["outcome"] != "Never":
                continue
            if "redundant" not in tests[name]:
                defects.append(f"{name} is a Never variant with no redundant reason")
            joint = tests[name].get("joint")
            if joint is not None and not (joint in found and tests[joint]["outcome"] == "Sometimes" and drop <= found[joint]):
                defects.append(f"{name} names joint {joint!r}, which is no Sometimes variant of {base} dropping its fences")
    linked = {name for found in variants.values() for name in found}
    for name, declared in sorted(tests.items()):
        stray = sorted(key for key in ("joint", "redundant") if key in declared)
        unlinked = declared.get("drops_from") is None
        sometimes_variant = name in linked and declared["outcome"] != "Never"
        if stray and (unlinked or sometimes_variant):
            defects.append(f"{name} declares {' and '.join(stray)}, which only a Never variant carries")
    for name, declared in sorted(tests.items()):
        if declared.get("drops_from") is not None or name not in programs:
            continue
        other = next((other for other in sorted(programs) if other != name and tests[other]["condition"] == declared["condition"]
                      and dropped(programs[other], programs[name])), None)
        if other is not None:
            defects.append(f"{name} is {other} with fence lines removed and names no drops_from")
    return defects


def read_litmus(name):
    return (LITMUS / f"{name}.litmus").read_text(encoding="utf-8")


def judge(evidence, expected):
    defects = relation_defects(expected, read_litmus)
    if defects:
        raise Refusal(TOOL_FAILURE, "relation defect: " + "; ".join(defects))
    record = read_json(evidence / "identity.json")
    check_identity(expected, record)
    results = {}
    outputs = sorted(path.stem.removeprefix("herd-") for path in evidence.glob("herd-*.txt"))
    extra = sorted(set(outputs) - set(expected["tests"]))
    if extra:
        raise Refusal(TOOL_FAILURE, f"outputs for undeclared tests {extra}")
    for name, declared in sorted(expected["tests"].items()):
        text_path, exit_path, argv_path = (evidence / f"herd-{name}.{kind}" for kind in ("txt", "exit", "argv"))
        if not text_path.exists() or not exit_path.exists() or not argv_path.exists():
            raise Refusal(TOOL_FAILURE, f"{name} has no recorded run")
        check_command(name, expected, record, argv_path.read_text().splitlines())
        try:
            exit_code = int(exit_path.read_text().strip())
        except ValueError as error:
            raise Refusal(TOOL_FAILURE, f"{name} records no exit code: {error}") from error
        results[name] = judge_test(name, declared, text_path.read_text(encoding="utf-8", errors="replace"), exit_code)
    return results


def inputs(evidence):
    names = ["identity.json", "pins.txt", "report.json", *(path.name for path in sorted(evidence.glob("herd-*")))]
    digests = {name: sha256(evidence / name) for name in names if (evidence / name).is_file()}
    committed = (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json", ROOT / "verification/obligations.json")
    for path in (*committed, EXPECTED, *sorted(LITMUS.glob("*.litmus"))):
        digests[str(path.relative_to(ROOT))] = sha256(path)
    return digests


def receipt(evidence, revision, completion, code, reason, results, expected):
    pins_path = evidence / "pins.txt"
    return {
        "job": "rc11", "module": None, "lane": "rc11", "revision": revision,
        "inputs": inputs(evidence),
        "tool": {"name": "herd7", "provenance": pins_path.read_bytes().decode("utf-8", errors="replace").strip().splitlines() if pins_path.exists() else []},
        "assumptions": [
            "finite C11/RC11 litmus evidence for the inventoried encodings only",
            "the Rust translation, compiler and hardware obligations stay separate",
        ],
        "bounds": {"options": expected.get("options") if isinstance(expected, dict) else None, "tests": results},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": len(results) if code == CREDITED else 0,
        "executed": sorted(results) if code == CREDITED else [], "failed": [],
        "replay": "bash scripts/rust-lane.sh rc11",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def git_revision():
    result = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=False)
    return result.stdout.strip() or None


def derive(evidence, revision):
    """Judge the evidence directory and return the report and the receipt it supports, writing neither."""
    code, reason, results, expected, completion = CREDITED, None, {}, None, "completed"
    try:
        expected = read_json(EXPECTED)
        results = judge(evidence, expected)
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, RecursionError) as error:
        code, reason, completion = TOOL_FAILURE, f"malformed evidence: {error!r}", "tool failure"
    report = {"code": code, "verdict": VERDICTS[code], "credited": code == CREDITED, "reason": reason, "tests": results}
    return report, receipt(evidence, revision, completion, code, reason, results, expected)


def run_judge(args):
    evidence = Path(args.evidence)
    report, derived = derive(evidence, args.revision or git_revision())
    (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    derived["inputs"]["report.json"] = sha256(evidence / "report.json")
    (evidence / "receipt.json").write_text(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    code, reason = report["code"], report["reason"]
    if reason:
        print(f"judge-rc11: {reason}", file=sys.stderr)
    return code


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pin the herd7 RC11 installation and judge litmus outcomes.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["options", "identity", "judge"])
    parser.add_argument("--herd7")
    parser.add_argument("--libdir")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    if args.command == "options":
        try:
            print("\n".join(read_json(EXPECTED)["options"]))
        except (Refusal, KeyError) as error:
            print(f"judge-rc11: {error}", file=sys.stderr)
            return TOOL_FAILURE
        return CREDITED
    if not args.evidence:
        parser.error(f"{args.command} needs --evidence")
    if args.command == "identity":
        if not args.herd7 or not args.libdir:
            parser.error("identity needs --herd7 and --libdir")
        try:
            return identity(args)
        except (Refusal, OSError) as error:
            print(f"judge-rc11: {error}", file=sys.stderr)
            return TOOL_FAILURE
    try:
        return run_judge(args)
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-rc11: {error}", file=sys.stderr)
        return TOOL_FAILURE


if __name__ == "__main__":
    sys.exit(main())
