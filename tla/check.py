#!/usr/bin/env python3
"""Check finite models, reachable scenarios, and named fault-injection outcomes.

Each case's result in `results.json` records the digests of the `sany.log` and
`tlc.log` it leaves under its output directory. `outcomes`, `parsed`, `uncovered`,
`state_counts` and `steps` read those logs here and in `scripts/judge-tlc.py`, which
rederives each result from them. `listed` reads the sections and span lines of a
log's last complete coverage report for the judge's report of unreached spans.

A kill case is a mutation case whose outcome is an invariant or action-property
violation. It counts as a kill under three rules: a passing baseline checks
its killing property, its mutation lies outside the definitions that property
references, and its counterexample takes a step of an action that reaches the
mutated definition. `kill_basis` reads the target module by top-level
definition, refuses a kill case whose text the rules cannot read, and returns
the mutated definition, the property's references and those actions; its
docstring lists its refusals. The runner and the judge check the step; the
judge checks the baseline and the references. `checked` and `safety` read the
invariant and property names of a generated configuration and the conjuncts
of a module's `Safety`, which the judge compares with
`verification/tlc/expected.json`.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
from datetime import datetime, timezone
import functools
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
from types import MappingProxyType
import zipfile


PROFILES = {"pr": ("pr",), "scheduled": ("pr", "scheduled")}


@dataclass
class Case:
    """One TLC run and the only outcome that passes it.

    `base` is the configuration file the case's configuration is generated
    from, and `module` is the root module TLC checks. `coverage` names the
    actions a passing positive run must execute. `target` is the module a
    `mutation` edits in the case's copy. `liveness` checks the
    configuration's temporal properties once, on the complete state graph
    (`-lncheck final`), and needs a configuration without symmetry. `tier`
    places the case by its measured cost: `PROFILES` runs a `pr` case in both
    profiles and a `scheduled` one only in the scheduled profile.
    """

    name: str
    base: str
    module: str
    target: str
    coverage: tuple[str, ...]
    settings: dict[str, str] = field(default_factory=dict)
    spec: str = "Spec"
    invariant: str | None = None
    extra: str = ""
    symmetry: bool = False
    expected: str = "Model checking completed. No error has been found."
    mutation: tuple[str, str] | None = None
    liveness: bool = False
    tier: str = "pr"


def violation(invariant):
    return f"Error: Invariant {invariant} is violated."


# TLC's exit status for each outcome a case can declare: a completed check, a
# deadlock, a safety violation (invariant or action property) and a liveness
# violation. A run that reports its outcome and then fails exits otherwise.
EXIT_STATUS = (("Model checking completed.", 0), ("Error: Deadlock reached.", 11), ("Error: Invariant", 12),
               ("Error: Action property", 13), ("Error: Temporal property", 13))


def exit_status(expected):
    """Return the exit status TLC reports for a run whose outcome is `expected`."""
    return next(status for prefix, status in EXIT_STATUS if expected.startswith(prefix))


def completes(case):
    """Whether `case` declares a finished check without a violation, a safety or a liveness check alike."""
    return exit_status(case.expected) == 0


# `str.splitlines` ends a line at each of these code points.
LINE_BREAKS = "\n\r\x0b\x0c\x1c\x1d\x1e\x85\u2028\u2029"
# TLC opens its completion report with "Model checking completed." and each violation, run failure and trace
# heading with "Error: ".
TERMINAL_TEXT = tuple(re.compile(re.escape(head) + f"[^{LINE_BREAKS}]*")
                      for head in ("Model checking completed.", "Error: "))
# TLC prints one of these whole lines between a violation and the states of its trace.
TRACE_HEADINGS = frozenset({"Error: The behavior up to this point is:",
                            "Error: The following behavior constitutes a counter-example:"})


def outcomes(tlc_log):
    """Every terminal line the log reports, in order: each line `TERMINAL_TEXT` opens except the `TRACE_HEADINGS`,
    so a failure TLC reports beside a declared outcome is an outcome of its own. A run that completed reports
    exactly one, its outcome. A line starts at the log's first character or after one of `LINE_BREAKS` and ends
    before the next one, as `str.splitlines` cuts it."""
    found = sorted((match.start(), match[0]) for pattern in TERMINAL_TEXT for match in pattern.finditer(tlc_log))
    return [line for start, line in found
            if (start == 0 or tlc_log[start - 1] in LINE_BREAKS) and line not in TRACE_HEADINGS]


def parsed(case, sany_log):
    """Whether SANY's output reports no error and the semantic processing of the case's root module."""
    return ("*** Errors:" not in sany_log and "Fatal errors" not in sany_log
            and f"Semantic processing of module {case.module}" in sany_log.splitlines())


# A coverage line opens a line with `<`, an action and ` line`, runs to the first `>`, on that line or a later
# one, and ends its line with `: distinct:generated`, the distinct states the action found and the states it
# generated. `COVERAGE` consumes only `\n<`, so `finditer` also matches a coverage line inside another's span.
COVERAGE = re.compile(r"\n<(?=(\w+) line[^>]+>: (\d+):(\d+)$)", re.M)


def uncovered(case, tlc_log):
    """The actions of `case.coverage` a passing run's log reports no generated state for: the second count of each
    action's last coverage line decides, and an action without one is uncovered. An action's name is a run of word
    characters."""
    generated = {match[1]: match[3] for match in COVERAGE.finditer("\n" + tlc_log)}
    return [action for action in case.coverage if int(generated.get(action, "0")) == 0]


REPORT_OPENS = "The coverage statistics at "
LOCATION = (r"line (?P<first>\d+), col (?P<start>\d+) to line (?P<last>\d+), col (?P<end>\d+)"
            r" of module (?P<module>\w+)")
HEADER = re.compile(rf"<(?P<operator>\w+) {LOCATION}(?: \((?P<located>\d+ \d+ \d+ \d+)\))?>(?:: \d+(?::(?P<generated>\d+))?)?")
SPAN = re.compile(rf"  (?P<depth>\|*){LOCATION}: (?P<count>\d+)(?::\d+)?")


@dataclass
class Section:
    """One section of a coverage report: a header with two counts, other than `Init`, and its span lines.

    `name` is the header's operator, followed by its parenthesized location when the header carries one. `ran` is
    whether the header's second count, the states generated, is positive. Each span is `(depth, location, count)`
    in log order: `depth` is the number of `|` that nest the line under the lines above it, `location` is
    `(module, (line, col), (line, col))`, and `count` is the line's first count.
    """

    name: str
    ran: bool
    spans: list


def listed(tlc_log):
    """The sections of the log's last complete coverage report, in log order.

    A report opens with a line that starts with `REPORT_OPENS` and is complete when a line `End of statistics.` or
    a line that starts with `End of statistics (` ends it; a report that the next opening line or the end of the
    log reaches first is cut short and ignored. Inside a complete report every line is a header, `<Op location>` with
    no count, one, or two, and an optional parenthesized location after the module, or a span line, two spaces,
    `|` per nesting level, a location and a count with an optional second count. Lines are cut at `\\n`. Raises
    ValueError, naming the condition, for a line of another form inside the last complete report, a span line
    before the report's first header, a log without a complete report, and a last complete report without a
    section.
    """
    pending, last = None, None
    for line in tlc_log.split("\n"):
        if line.startswith(REPORT_OPENS):
            pending = []
        elif pending is None:
            continue
        elif line == "End of statistics." or line.startswith("End of statistics ("):
            pending, last = None, pending
        else:
            pending.append(line)
    if last is None:
        raise ValueError("tlc.log has no complete coverage report")
    report = []
    for line in last:
        if header := HEADER.fullmatch(line):
            is_section = header["generated"] is not None and header["operator"] != "Init"
            name = header["operator"] + (f" ({header['located']})" if header["located"] else "")
            report.append(Section(name, int(header["generated"]) > 0, []) if is_section else None)
        elif span := SPAN.fullmatch(line):
            if not report:
                raise ValueError(f"tlc.log's coverage report holds a span line before its first header: {line!r}")
            if report[-1] is not None:
                location = (span["module"], (int(span["first"]), int(span["start"])), (int(span["last"]), int(span["end"])))
                report[-1].spans.append((len(span["depth"]), location, int(span["count"])))
        else:
            raise ValueError(f"tlc.log's coverage report holds a line that is neither a header nor a span line: {line!r}")
    sections = [section for section in report if section is not None]
    if not sections:
        raise ValueError("tlc.log's last complete coverage report has no section")
    return sections


GENERATED = " states generated, "
DISTINCT = re.compile(r"(\d+) distinct states found")


def state_counts(tlc_log):
    """The last generated and distinct state counts the log reports, as strings, or None.

    A report is a run of decimal digits, `GENERATED`, a second run and ` distinct states found`. Two reports
    share no character, so the last report is the last `GENERATED` with both runs around it.
    """
    end = len(tlc_log)
    while (at := tlc_log.rfind(GENERATED, 0, end)) >= 0:
        start = at
        while start and tlc_log[start - 1].isdecimal():
            start -= 1
        distinct = DISTINCT.match(tlc_log, at + len(GENERATED))
        if start < at and distinct:
            return [tlc_log[start:at], distinct[1]]
        end = at + len(GENERATED) - 1
    return None


STEP = re.compile(r"State \d+: <(\w+)(?:\(.*\))? line \d+, col \d+ to line \d+, col \d+ of module \w+>")


def steps(tlc_log):
    """The actions the counterexample's steps take, in order, one per state line `STEP` matches whole. Lines are
    cut at `\\n`; the initial state names no action."""
    return [match[1] for line in tlc_log.split("\n") if (match := STEP.fullmatch(line))]


def takes_step(tlc_log, actions):
    """Whether the counterexample of `tlc_log` takes a step of one of `actions`; an empty `actions` never holds."""
    return bool(set(steps(tlc_log)) & set(actions))


# Each keyword starts a configuration statement and ends the preceding one.
CONFIG_KEYWORDS = frozenset({"CONSTANT", "CONSTANTS", "INIT", "NEXT", "SPECIFICATION", "INVARIANT", "INVARIANTS",
                             "PROPERTY", "PROPERTIES", "SYMMETRY", "VIEW", "CONSTRAINT", "CONSTRAINTS",
                             "ACTION_CONSTRAINT", "ACTION_CONSTRAINTS", "CHECK_DEADLOCK", "POSTCONDITION",
                             "POSTCONDITIONS", "ALIAS", "_PERIODIC", "_RL_REWARD", "_POSSIBLE"})
CHECKED = {"INVARIANT": "invariants", "INVARIANTS": "invariants", "PROPERTY": "properties", "PROPERTIES": "properties"}
WORD = re.compile(r'\s+|"(?:\\[\s\S]|[^"\\])*"|<-|\w+|[^\s\w"]')


def words(config):
    """The words of a configuration's text with comments removed, cut as TLC's lexer cuts them: a string literal
    with its backslash escapes, `<-`, a run of word characters, or one other character. An unterminated string
    raises ValueError."""
    text, found, at = uncommented(config), [], 0
    while at < len(text):
        match = WORD.match(text, at)
        if not match:
            raise ValueError(f"configuration text {text[at:at + 20]!r} opens a string it does not close")
        if not match[0].isspace():
            found.append(match[0])
        at = match.end()
    return found


def statements(config):
    """The statements of a TLC configuration in order, each its keyword and the words up to the next keyword, with
    comments removed."""
    found, previous = [], None
    for word in words(config):
        if word in CONFIG_KEYWORDS and previous in ("=", "<-"):
            raise ValueError(f"configuration keyword {word} stands where {previous} needs a value")
        previous = word
        if word in CONFIG_KEYWORDS:
            found.append((word, []))
        elif found:
            found[-1][1].append(word)
        else:
            raise ValueError(f"configuration text {word!r} precedes every keyword")
    return found


def checked(config):
    """The invariant and property names a configuration checks, each list in the configuration's order."""
    found = {"invariants": [], "properties": []}
    for keyword, operands in statements(config):
        if keyword in CHECKED:
            found[CHECKED[keyword]].extend(operands)
    return found


def unchecked(config):
    """The statements of a configuration other than its invariant and property statements."""
    return [statement for statement in statements(config) if statement[0] not in CHECKED]


OPENER = re.compile(r'\(\*|\\\*|"(?:\\[\s\S]|[^"\\])*"?')
NESTING = re.compile(r"\(\*|\*\)")
NOT_NEWLINE = re.compile(r"[^\n]")


def uncommented(text):
    """`text` with each TLA+ comment, `\\*` to the end of its line and nested `(* *)`, blanked to spaces and line
    breaks kept, so every offset keeps its line and column. A string literal holds no comment."""
    out, depth, at = [], 0, 0
    while at < len(text):
        if depth:
            match = NESTING.search(text, at)
            end = match.end() if match else len(text)
            out.append(NOT_NEWLINE.sub(" ", text[at:end]))
            if match:
                depth += 1 if match[0] == "(*" else -1
            at = end
            continue
        match = OPENER.search(text, at)
        if not match:
            out.append(text[at:])
            break
        out.append(text[at:match.start()])
        if match[0] == "(*":
            out.append("  ")
            depth, at = 1, match.end()
        elif match[0] == "\\*":
            end = text.find("\n", match.start())
            at = len(text) if end < 0 else end
            out.append(" " * (at - match.start()))
        else:
            out.append(match[0])
            at = match.end()
    return "".join(out)


def unquoted(text):
    """`text` with the contents of each string literal blanked to spaces, quotes and line breaks kept, so every offset
    keeps its place; a backslash escapes the character after it. `text` holds no comment."""
    if '"' not in text:
        return text
    return STRING.sub(lambda match: re.sub(r"[^\n]", " ", match[0][1:-1]).join('""'), text)


DEFINITION = re.compile(r"([A-Za-z_]\w*)(?:\s*\([^)]*\))?\s*==")
MODULE_LINE = re.compile(r"-{4,}|(?:EXTENDS|CONSTANTS?|VARIABLES?|ASSUME|RECURSIVE)\b")
MODULE_HEADER = re.compile(r"-{4,}[ \t]*MODULE[ \t]+\w+[ \t]*-{4,}")
MODULE_END = re.compile(r"={4,}")
LINE_OPEN = re.compile(r"(?m)^\S")
IDENTIFIER = re.compile(r"(?<!\w)[A-Za-z_]\w*")
STRING = re.compile(r'"(?:\\[\s\S]|[^"\\])*"')
# A `LET` opens local definitions and its `IN` closes them; every `==` outside them opens a definition.
LOCAL = re.compile(r"(?<!\w)(?:LET|IN)(?!\w)|==")
INSTANCE = re.compile(r"(?<!\w)INSTANCE(?!\w)")


@functools.lru_cache(maxsize=128)
def definitions(module):
    """The top-level definitions of a module's text, by name, each the offsets of its span and its body with
    comments removed, as a read-only mapping that calls with equal text share. The module runs from its header,
    the first line that opens at column 0, to its end, the first run of four or more `=` after the header and
    outside string literals; SANY ignores text outside a module, so text there is refused. A definition opens a
    line with its name, an optional parameter list and `==`, all inside its span and outside string literals, and
    runs to the next line that opens with a character other than white space, after comments are removed, or to the
    module's end; its body follows its `==`. Every other such line opens with a separator or a module keyword that
    `MODULE_LINE` names, and a line that opens with one is a module line whatever follows it. Text before
    the first such line, a first such line other than the header, a module without an end, text after the end, a
    line of another form, a name defined twice, and a span whose `LET` and `IN` outside string literals do not
    pair or that holds an `==` outside a `LET`, which would fold a second definition into the one above it, raise
    ValueError."""
    text = uncommented(module)
    plain = unquoted(text)
    first = LINE_OPEN.search(text)
    lead = first.start() if first else len(text)
    if text[:lead].strip():
        raise ValueError(f"module text {text[:lead].split()[0]!r} precedes its first line at column 0")
    opening = MODULE_HEADER.match(text, lead)
    if not opening:
        line = text[lead:].split("\n", 1)[0]
        raise ValueError(f"module line {line!r} precedes the module header")
    close = MODULE_END.search(plain, opening.end())
    if not close:
        raise ValueError("the module has no end")
    if text[close.end():].strip():
        raise ValueError(f"module text {text[close.end():].split()[0]!r} follows the end of its module")
    opens = [match.start() for match in LINE_OPEN.finditer(text, 0, close.start())] + [close.start()]
    found = {}
    for start, end in zip(opens, opens[1:]):
        line = text[start:end].splitlines()[0]
        module_line = MODULE_LINE.match(plain, start, end)
        definition = None if module_line else DEFINITION.match(plain, start, end)
        header = definition or module_line
        if not header:
            raise ValueError(f"module line {line!r} opens no definition the reader knows")
        if definition:
            if definition[1] in found:
                raise ValueError(f"the module defines {definition[1]} twice")
            found[definition[1]] = (start, end, text[definition.end():end])
        depth = 0
        for word in LOCAL.findall(plain, header.end(), end):
            depth += {"LET": 1, "IN": -1}.get(word, 0)
            if depth < 0:
                raise ValueError(f"the span of module line {line!r} closes a LET it does not open")
            if word == "==" and depth == 0:
                raise ValueError(f"the span of module line {line!r} holds a definition outside a LET")
        if depth:
            raise ValueError(f"the span of module line {line!r} leaves a LET open")
    return MappingProxyType(found)


def reached(found, root):
    """The definitions `root` reaches in `found`, itself included: each name of a reached body, as `names` reads
    them, that names a definition, followed through other definitions. Names are matched without scope, so a local
    binding that repeats a definition's name also counts."""
    seen, pending = set(), [root]
    while pending:
        name = pending.pop()
        if name in found and name not in seen:
            seen.add(name)
            pending.extend(names(found[name][2]))
    return seen


def names(text):
    """Each whole identifier of `text`, and each part of one that follows an underscore, so the subscript of
    `[A]_vars`, `<<A>>_vars`, `WF_vars(A)` and `SF_vars(A)` also names `vars`."""
    found = []
    for token in IDENTIFIER.findall(text):
        found.append(token)
        if "_" in token:
            found.extend(token[at + 1:] for at, char in enumerate(token[:-1]) if char == "_")
    return found


def safety(module):
    """The conjuncts of a module's `Safety` definition in order, or None when it defines none. The body is one
    conjunction, on one line or bulleted with `/\\`, and each conjunct is a bare definition name."""
    found = definitions(module)
    if "Safety" not in found:
        return None
    parts = [part.strip() for part in found["Safety"][2].split("/\\")]
    parts = parts[1:] if not parts[0] else parts
    for part in parts:
        if not re.fullmatch(r"[A-Za-z_]\w*", part):
            raise ValueError(f"Safety conjunct {part!r} is not a bare definition name")
    return parts


KILLS = re.compile(r"Error: (?:Invariant|Action property) (\w+) is violated\.")


def killing(case):
    """The killing property of a mutation case whose outcome is an invariant or action-property violation, else None.
    A mutation case whose outcome opens as such a violation but is not one `KILLS` reads, such as a violation by the
    initial state, raises ValueError."""
    if not case.mutation:
        return None
    if match := KILLS.fullmatch(case.expected):
        return match[1]
    if case.expected.startswith(("Error: Invariant ", "Error: Action property ")):
        raise ValueError(f"{case.name}: the kill rules read no violated property in the outcome {case.expected!r}")
    return None


def module_lines(module, found):
    """The text of `module`, comments removed, outside every span of its definitions `found`, in order: the header,
    the module lines such as `VARIABLES` and `ASSUME`, and the end."""
    text, kept, at = uncommented(module), [], 0
    for first, last, _ in sorted(found.values()):
        kept.append(text[at:first])
        at = last
    return "".join(kept) + text[at:]


def read_definitions(case, module, text):
    """The definitions of `text`, the module named `module`; a refusal of the reader names the case and the module."""
    try:
        return definitions(text)
    except ValueError as error:
        raise ValueError(f"{case.name}: {module}: {error}") from error


def kill_basis(case, source):
    """The text a kill of `case` stands on: the definition of `case.target` its mutation anchor lies in, the
    definitions its killing property reaches, and the actions that reach the mutated definition.

    An action is a definition the body of `Next` names, other than `Next` and `Spec`, that reaches the mutated
    definition. TLC labels each counterexample step with the innermost definition its action expands to: a
    definition that `Next` names and whose body is a disjunction of other actions gives its steps the inner names,
    and a disjunct of `Next` that is not an operator application, such as `Mismatch /\\ URetry("RETRY2")`, keeps the
    label `Next`. A label `Next`'s body does not name counts for no action, and `Next` and `Spec` are never
    actions, so a kill whose mutated steps all carry such labels fails the step rule.

    The references, the `Init` refusal and the actions follow the target's definitions, the root module's
    definitions and each `C <- Op` substitution of the generated configuration, read as `C` naming `Op`.

    Raises ValueError when the case's specification is other than the target's `Spec == Init /\\ [][Next]_vars`,
    when its generated configuration assigns or substitutes a definition of the target in a `CONSTANT` statement,
    as `D = v`, `D(a) = v` or `D <- Op`, when the target or the mutated target instantiates a module, when the
    anchor occurs other than once in the target, spans two definitions or none, or reaches text outside its one
    definition, when the mutation changes a definition other than the anchor's or any module text outside the
    definitions, when `Init` reaches the mutated definition, or when the target does not
    define the killing property or `Next`. It also raises what its readers raise: `killing` on an outcome the
    rules cannot read, `definitions` on a layout of the target, the mutated target or the root module it does not
    read, and `configuration` on a configuration it refuses. An empty action set is returned as it is; the judge
    and the runner refuse it.
    """
    prop, module, anchor = killing(case), (source / case.target).read_text(), case.mutation[0]
    found = read_definitions(case, case.target, module)
    for name in (prop, "Next"):
        if name not in found:
            raise ValueError(f"{case.name}: {case.target} does not define {name}")
    if case.spec != "Spec" or "".join(found.get("Spec", (0, 0, ""))[2].split()) != "Init/\\[][Next]_vars":
        raise ValueError(f"{case.name}: the specification {case.spec} is not Init /\\ [][Next]_vars of {case.target}")
    if any("INSTANCE" in text and INSTANCE.search(unquoted(uncommented(text)))
           for text in (module, module.replace(anchor, case.mutation[1]))):
        raise ValueError(f"{case.name}: {case.target} instantiates a module, whose substitutions the kill rules do not follow")
    config = statements(configuration(case, source))
    # The `""` placeholder holds a string value's position, so the name after it opens the next binding.
    assigned = " ".join('""' if word.startswith('"') else word
                        for keyword, operands in config if keyword in ("CONSTANT", "CONSTANTS") for word in operands)
    heads = re.finditer(r"([A-Za-z_]\w*)\s*(?:\([^()]*\)\s*)?(<-|=)\s*(?:\[\s*\w+\s*\]\s*)?(\w*)", assigned)
    bindings = [(match[1], match[2], match[3]) for match in heads]
    overridden = sorted({name for name, _, _ in bindings} & set(found))
    if overridden:
        raise ValueError(f"{case.name}: the configuration overrides {overridden}, which {case.target} defines")
    root = f"{case.module}.tla"
    graph = dict(read_definitions(case, root, (source / root).read_text())) if root != case.target else {}
    graph.update(found)
    graph.update((name, (0, 0, value)) for name, arrow, value in bindings if arrow == "<-")
    if module.count(anchor) != 1:
        raise ValueError(f"{case.name}: the mutation anchor occurs {module.count(anchor)} times in {case.target}")
    start = module.find(anchor)
    hit = [name for name, (first, last, _) in found.items() if first < start + len(anchor) and start < last]
    if len(hit) != 1:
        raise ValueError(f"{case.name}: the mutation anchor spans the definitions {hit} of {case.target}")
    if not found[hit[0]][0] <= start < start + len(anchor) <= found[hit[0]][1]:
        raise ValueError(f"{case.name}: the mutation anchor reaches module text of {case.target} outside {hit[0]}")
    mutated = module.replace(anchor, case.mutation[1])
    edited = read_definitions(case, f"the mutated {case.target}", mutated)
    if set(edited) != set(found) or any(edited[name][2] != found[name][2] for name in found if name != hit[0]):
        raise ValueError(f"{case.name}: the mutation changes definitions of {case.target} other than {hit[0]}")
    if module_lines(mutated, edited) != module_lines(module, found):
        raise ValueError(f"{case.name}: the mutation changes module text of {case.target} outside its definitions")
    if hit[0] in reached(graph, "Init"):
        raise ValueError(f"{case.name}: the mutation edits {hit[0]}, which Init reaches")
    named = (set(names(found["Next"][2])) & set(found)) - {"Next", "Spec"}
    actions = sorted(name for name in named if hit[0] in reached(graph, name))
    return {"definition": hit[0], "references": reached(graph, prop), "actions": actions}


def cases():
    yield from lifecycle_cases()
    yield from identity_cases()
    yield from recovery_cases()


PUT_ACTIONS = ("CBegin", "CAuthority", "CPrepare", "CReady", "CSupply", "CSend", "CNicReturn",
               "CAck", "CResult", "CClose", "OBegin", "OPrepare", "OData", "OSubmit", "OPublish",
               "DTerminal", "Done")
ENDING_ACTIONS = ("CCancel", "CExpire", "CError", "CAbandon", "OFail", "OTimeout", "ODrain")
READ_ACTIONS = ("RAdmit", "RIssue", "RTerminal", "RChunk", "RDone")


def lifecycle(name, settings=None, also=(), coverage=PUT_ACTIONS + ENDING_ACTIONS, **fields):
    """A case of the PUT, fill and read lifecycle model that must also cover the actions `also` names."""
    return Case(name, base="Lifecycle.cfg", settings=settings or {}, module="LifecycleMC",
                target="Lifecycle.tla", coverage=coverage + also, **fields)


def lifecycle_cases():
    three = {"Ranges": "{0, 1, 2}", "Cover": "EachRange", "Conflicts": "TRUE"}
    zero = {"Frags": "{}", "Ranges": "{0}", "Get": "TRUE"}
    revocation = {"Successor": "TRUE"}
    loss = {"Loss": "TRUE", "Stops": "TRUE", "Unproven": "TRUE"}
    read = {"Get": "TRUE", "Successor": "TRUE"}
    expiry = {"Expiry": "TRUE"}
    yield lifecycle("put")
    yield lifecycle("put-three-ranges", three, also=("NConflict",))
    yield lifecycle("put-zero-bytes", zero, coverage=("CBegin", "CPrepare", "CReady", "CResult",
                                                     "OPublish", "OSubmit", "DTerminal", "Done")
                    + READ_ACTIONS)
    yield lifecycle("put-revocation", revocation, also=("OInvalidate", "SBegin", "SFail", "SPublish"))
    yield lifecycle("put-loss-and-stop", loss, also=("OLose", "DStop"))
    yield lifecycle("put-and-get", read, also=READ_ACTIONS + ("SPublish",))
    yield lifecycle("put-result-expiry", expiry, also=("OExpire",))
    for case, settings in (
        ("NoPublication", {}), ("NoFailure", {}), ("NoUnknownPublication", {}),
        ("NoPublishedAfterCancel", {}), ("NoFullReceiptWithHeldWrite", {}), ("NoConflict", three),
        ("NoLateOldWrite", revocation), ("NoSuccessorPublication", revocation),
        ("NoCancelWithTwoReads", read), ("NoCompleteRead", read), ("NoReadBesideUpload", read),
        ("NoLossAfterSubmit", loss), ("NoHeldStop", loss), ("NoHeldUnknown", {}),
        ("NoPublication-zero-bytes", {**zero, "Get": "FALSE"}),
    ):
        name = case.removesuffix("-zero-bytes")
        yield lifecycle(case, settings, extra=f"INVARIANT {name}\n", expected=violation(name))
    drain = {"Get": "TRUE", "Stops": "TRUE"}
    patient = {"Deadlines": "FALSE", "WriteFaults": "FALSE"}
    yield lifecycle("live-drain", drain, also=READ_ACTIONS + ("DStop",), spec="FairSpec", liveness=True,
                    extra="PROPERTIES Decides Drains ReadDrains Releases\n")
    yield lifecycle("live-publish", patient, spec="FairSpec", liveness=True,
                    extra="PROPERTY Publishes\n", coverage=PUT_ACTIONS)
    for name, settings, spec, prop in (
        ("stalled-supplier", patient, "StalledSpec", "Publishes"),
        ("result-expiry", {**patient, "Expiry": "TRUE"}, "FairSpec", "Publishes"),
        ("retained-unknown", {"Expiry": "TRUE"}, "NoAbandonSpec", "Releases"),
        ("unproven-stop", {"Stops": "TRUE", "Unproven": "TRUE"}, "FairSpec", "Drains"),
    ):
        yield lifecycle(name, settings, spec=spec, liveness=True, extra=f"PROPERTY {prop}\n",
                        expected=f"Error: Temporal property {prop} was violated.")
    for name, settings, invariant, old, new in (
        ("publish-missing-range", {}, "PublishedComplete",
         'Complete == \\A w \\in Ranges : ws[1][w] = "written"', 'Complete == ws[1][0] = "written"'),
        ("duplicate-credit", {}, "PublishedComplete",
         "ELSE /\\ o.data[m.i] # m.v /\\ ~o.conflict /\\ o' = [o EXCEPT !.conflict = TRUE]",
         "ELSE /\\ o' = [o EXCEPT !.credit[m.i] = 2]"),
        ("later-copy-replaces-bytes", three, "PublishedClientBytes",
         "ELSE /\\ o.data[m.i] # m.v /\\ ~o.conflict /\\ o' = [o EXCEPT !.conflict = TRUE]",
         "ELSE /\\ o.data[m.i] # m.v /\\ ~o.conflict /\\ o' = [o EXCEPT !.data[m.i] = m.v]"),
        ("publish-revoked", revocation, "PublishedComplete",
         "/\\ o.stage = \"ready\" /\\ Complete /\\ ~o.conflict /\\ ~o.revoked /\\ ~o.lost",
         "/\\ o.stage = \"ready\" /\\ Complete /\\ ~o.conflict /\\ ~o.lost"),
        ("unverified-chunk", read, "ChunksVerified",
         "/\\ r.phase = \"reading\" /\\ (r.chunks + 1) \\in r.done",
         "/\\ r.phase = \"reading\" /\\ r.chunks < Chunks"),
        ("chunk-after-done", read, "OneDone",
         "/\\ r.phase = \"reading\" /\\ (r.chunks + 1) \\in r.done",
         "/\\ r.phase # \"idle\" /\\ (r.chunks + 1) \\in r.done"),
        ("receipt-as-publication", {}, "PublishedNeedsResult",
         '!.phase = IF base = N THEN "received" ELSE @])',
         '!.phase = IF base = N THEN "received" ELSE @, !.outcome = IF base = N THEN "Published" ELSE @])'),
        ("unknown-as-failure", {}, "FailedMeansUnpublished",
         '!.outcome = IF c.handed THEN "Unknown" ELSE "NotStarted"',
         '!.outcome = IF c.handed THEN "Failed" ELSE "NotStarted"'),
        ("early-source-reuse", {}, "SourceCustody",
         "/\\ ~Retained(u, i) /\\ i \\notin u.nic THEN", "/\\ ~Retained(u, i) THEN"),
        ("data-after-end", {}, "NoDataAfterEnd",
         "/\\ ~Retained(u, i) /\\ i \\notin u.nic THEN", "/\\ ~(i > u.base) /\\ i \\notin u.nic THEN"),
        ("early-write-release", {}, "WriteCustody",
         '/\\ o.stage = "draining" /\\ Writing(1) = {}', '/\\ o.stage = "draining"'),
        ("late-write-ends-successor", revocation, "SuccessorIsolated",
         "/\\ dev' = dev \\ {x} /\\ ws' = [ws EXCEPT ![x.s][x.w] = res]",
         "/\\ dev' = (dev \\ {x}) \\ {[s |-> 2, w |-> x.w]}\n"
         "        /\\ ws' = [ws EXCEPT ![x.s][x.w] = res, ![2][x.w] = IF o.succ # \"none\" THEN res ELSE @]"),
    ):
        yield lifecycle(name, settings, invariant=invariant, mutation=(old, new),
                        expected=violation(invariant))
    yield lifecycle("result-after-close", {}, expected="Error: Action property ClosedIsFinal is violated.",
                    mutation=('/\\ ~c.closed /\\ [t |-> "RESULT"] \\in net', '/\\ [t |-> "RESULT"] \\in net'))
    yield lifecycle("untyped-read-version", read, invariant="TypeOK", expected=violation("TypeOK"),
                    mutation=('!.phase = "reading", !.ver = store.s]', '!.phase = "reading", !.ver = store.s + 7]'))


IDENTITY_ACTIONS = ("Admit", "Refuse", "End", "Unbind", "Release", "WrongOp", "Replay", "UnknownAnswer", "Tick",
                    "Replace", "UBegin", "URetry", "UReply", "UExpire", "UAbandon", "Stray",
                    "CAdmit", "CHand", "CReturn", "CReturnStale", "CClose", "CAttach")


def identity(name, settings=None, coverage=IDENTITY_ACTIONS, **fields):
    """A case of the request identity and replay model."""
    return Case(name, base="Identity.cfg", settings=settings or {}, module="IdentityMC",
                target="Identity.tla", coverage=coverage, **fields)


def identity_cases():
    """Owner identity cases run without client leases; board cases run with one epoch and no retries."""
    owner = {"Leases": "0", "Cores": "{1}"}
    board = {"Upload": "FALSE", "Epochs": "{1}", "Gens": "{1, 2, 3, 4}", "Linger": "0", "Table": "2"}
    one = {**owner, "Epochs": "{1}"}
    peers = {**one, "Peers": "{1, 2}", "Slots": "{1, 2}", "Share": "1"}
    two_peers = {**one, "Peers": "{1, 2}", "Table": "1", "Share": "1", "Linger": "0"}
    slots = {**one, "Slots": "{1, 2}", "Linger": "0"}
    share_one = {**slots, "Share": "1"}
    gens = {**one, "Gens": "{1, 2, 3}", "Linger": "0"}
    mismatch = {**one, "Mismatch": "TRUE"}
    stale = {**gens, "StaleData": "TRUE"}
    owner_actions = tuple(a for a in IDENTITY_ACTIONS if not a.startswith("C")) + ("Done",)
    single = tuple(a for a in owner_actions if a != "Replace")
    brief = tuple(a for a in single if a != "Replay")
    board_actions = ("Admit", "End", "Release", "Tick", "CAdmit", "CHand", "CReturn", "CReturnStale", "CClose", "CAttach", "Done")
    yield identity("identity", owner, coverage=owner_actions)
    yield identity("identity-two-peers", two_peers, coverage=brief)
    yield identity("identity-two-slots", slots, coverage=brief)
    yield identity("identity-share-of-one", share_one, coverage=brief)
    yield identity("identity-three-generations", gens, coverage=brief)
    yield identity("identity-mismatch", mismatch, coverage=single + ("Conflict",))
    yield identity("identity-stale-data", stale, coverage=brief + ("Stale",))
    yield identity("identity-board", board, coverage=board_actions)
    caps = {**one, "Peers": "{1, 2}", "Linger": "0", "PutCap": "1", "PeerPutCap": "1"}
    headroom = "INVARIANT Headroom\n"
    yield identity("identity-put-caps", caps, coverage=brief, extra=headroom)
    yield identity("identity-put-cap-at-table", {**caps, "PutCap": "2"}, coverage=(),
                   extra="INVARIANT Headroom\n", expected=violation("Headroom"))
    share_caps = {**slots, "PutCap": "1", "PeerPutCap": "1"}
    peer_caps = {**slots, "Table": "3", "PutCap": "2", "PeerPutCap": "1"}
    yield identity("identity-peer-put-cap", peer_caps, coverage=brief, extra=headroom)
    yield identity("identity-peer-put-cap-at-share", {**peer_caps, "PeerPutCap": "2"}, coverage=(),
                   extra="INVARIANT Headroom\n", expected=violation("Headroom"))
    cap_room = {**slots, "Upload": "FALSE", "Slots": "{1, 2, 3}", "Share": "3", "Table": "3", "PutCap": "3", "PeerPutCap": "1"}
    yield identity("identity-cap-without-pressure", cap_room, coverage=(), extra="INVARIANT IdNoSharedPressure\n")
    for case, settings in (
        ("IdNoRefusal", owner), ("IdNoWrongOperation", owner), ("IdNoConflict", mismatch), ("IdNoUnknownAnswer", owner),
        ("IdNoReplay", owner), ("IdNoExpiredRetry", owner), ("IdNoResolvedUnknown", owner), ("IdNoRetainedUnknown", owner),
        ("IdNoSharedPressure", peers), ("IdNoReplacementDrain", owner), ("IdNoStaleData", stale),
        ("IdNoStaleRelease", owner), ("IdNoUnbound", owner), ("IdNoUnboundPut", owner), ("IdNoReuseBesideUnbound", gens),
        ("IdNoCappedPut", caps), ("IdNoPeerCappedPut", peer_caps), ("IdNoReservedGet", share_caps),
        ("IdNoOrphan", board), ("IdNoOldLeaseReturn", board),
    ):
        yield identity(case, settings, coverage=(), extra=f"INVARIANT {case}\n", expected=violation(case))
    for name, settings, invariant, old, new in (
        ("admit-without-wire-id", owner, "OneAdmission",
         "Fresh(p, s, g) == g > wire[p][s].mark /\\ wire[p][s].active = 0 /\\ g < Limit",
         "Fresh(p, s, g) == wire[p][s].active = 0 /\\ g < Limit"),
        ("admit-busy-slot", owner, "OneBindingPerHandle",
         "Fresh(p, s, g) == g > wire[p][s].mark /\\ wire[p][s].active = 0 /\\ g < Limit",
         "Fresh(p, s, g) == g > wire[p][s].mark /\\ g < Limit"),
        ("admit-over-put-cap", caps, "PutCaps",
         'Admissible(p, op) == Room(p) /\\ (op = "GET" \\/ (Cardinality(LivePuts) < PutCap /\\ Cardinality(HeldPuts(p)) < PeerPutCap))',
         'Admissible(p, op) == Room(p) /\\ (op = "GET" \\/ (Cardinality(LivePuts) <= PutCap /\\ Cardinality(HeldPuts(p)) < PeerPutCap))'),
        ("admit-over-peer-put-cap", peer_caps, "PutCaps",
         'Admissible(p, op) == Room(p) /\\ (op = "GET" \\/ (Cardinality(LivePuts) < PutCap /\\ Cardinality(HeldPuts(p)) < PeerPutCap))',
         'Admissible(p, op) == Room(p) /\\ (op = "GET" \\/ (Cardinality(LivePuts) < PutCap /\\ Cardinality(HeldPuts(p)) <= PeerPutCap))'),
        ("replay-without-watermark", owner, "ResultHasAdmission",
         '    /\\ Answers(f, w) /\\ f.kind = "RETRY" /\\ At(w, f.gen) /\\ Current(w, f.peer) /\\ counts.replays < 1\n',
         '    /\\ Answers(f, w) /\\ f.kind = "RETRY" /\\ Current(w, f.peer) /\\ counts.replays < 1\n'),
        ("replay-without-epoch", owner, "ResultHasAdmission",
         '    /\\ f.kind \\in {"RETRY", "RETRY2"} /\\ f.op = "PUT" /\\ f.epoch = epoch[f.peer]\n',
         '    /\\ f.kind \\in {"RETRY", "RETRY2"} /\\ f.op = "PUT"\n'),
        ("result-after-replacement", owner, "ResultHasAdmission",
         "        IF wire[p][s].mark = 0\n", "        IF FALSE\n"),
        ("admit-over-share", share_one, "Capacity",
         "Room(p) == Cardinality(Held(p)) < Share /\\ Cardinality(Live) < Table",
         "Room(p) == Cardinality(Live) < Table"),
        ("release-without-table-generation", owner, "ExactRelease",
         "    /\\ IF tg = tgen[h]\n", "    /\\ IF tg <= tgen[h]\n"),
        ("release-without-handle", slots, "ExactBinding",
         "    /\\ (wire[p][s].active = h \\/ (table[h].unbound /\\ table[h].peer = p)) /\\ table[h].ended /\\ tg <= tgen[h]\n",
         "    /\\ (wire[p][s].active # 0 \\/ (table[h].unbound /\\ table[h].peer = p)) /\\ table[h].ended /\\ tg <= tgen[h]\n"),
        ("release-clears-successor", gens, "OneBindingPerHandle",
         "            /\\ wire' = [wire EXCEPT ![p][s].active = IF @ = h THEN 0 ELSE @]\n",
         "            /\\ wire' = [wire EXCEPT ![p][s].active = 0]\n"),
        ("unbind-without-mark", owner, "OneBindingPerHandle",
         "        /\\ table' = [table EXCEPT ![h].unbound = TRUE]\n",
         "        /\\ UNCHANGED table\n"),
        ("reply-without-peer", two_peers, "PublishedNeedsResult",
         "/\\ f.peer = upload.peer /\\ f.slot = upload.slot /\\ f.gen = upload.gen /\\ f.epoch = upload.epoch",
         "/\\ f.slot = upload.slot /\\ f.gen = upload.gen /\\ f.epoch = upload.epoch"),
        ("replay-after-expiry", owner, "NoExpiredReplay",
         "Current(w, p) == w.row # NoRow /\\ w.row.epoch = epoch[p] /\\ w.row.expires > clock",
         "Current(w, p) == w.row # NoRow /\\ w.row.epoch = epoch[p]"),
        ("reply-without-epoch", owner, "PublishedNeedsResult",
         "/\\ f.peer = upload.peer /\\ f.slot = upload.slot /\\ f.gen = upload.gen /\\ f.epoch = upload.epoch",
         "/\\ f.peer = upload.peer /\\ f.slot = upload.slot /\\ f.gen = upload.gen"),
        ("replay-across-operations", owner, "NoCrossedReplay",
         "/\\ ~(At(w, f.gen) /\\ Other(w, f.op)) /\\ ~(At(w, f.gen) /\\ w.active # 0 /\\ ~table[w.active].ended)",
         "/\\ ~(At(w, f.gen) /\\ w.active # 0 /\\ ~table[w.active].ended)"),
        ("reply-without-generation", gens, "PublishedNeedsResult",
         "/\\ f.peer = upload.peer /\\ f.slot = upload.slot /\\ f.gen = upload.gen /\\ f.epoch = upload.epoch",
         "/\\ f.peer = upload.peer /\\ f.slot = upload.slot /\\ f.epoch = upload.epoch"),
        ("lease-without-core", board, "OrphanConservation",
         "Credits(h) == leases[h].open /\\ leases[h].score = board.core /\\ leases[h].sgen = leases[h].gen",
         "Credits(h) == leases[h].open /\\ leases[h].sgen = leases[h].gen"),
        ("lease-without-generation", board, "OrphanConservation",
         "Credits(h) == leases[h].open /\\ leases[h].score = board.core /\\ leases[h].sgen = leases[h].gen",
         "Credits(h) == leases[h].open /\\ leases[h].score = board.core"),
    ):
        yield identity(name, settings, coverage=(), invariant=invariant, mutation=(old, new),
                       expected=violation(invariant))


RECOVERY_ACTIONS = ("Fill", "Exhaust", "Land", "Publish", "RequestExclude", "Exclude", "Ack",
                    "Observe", "Lose", "Unprotect", "LiveInvalidate", "FreshAck", "Crash",
                    "OldLand", "OldDrop", "Replay", "Recover", "Reuse", "Finished")


def recovery(name, settings=None, coverage=RECOVERY_ACTIONS, **fields):
    """A case of the recovery model."""
    return Case(name, base="Recovery.cfg", settings=settings or {}, module="RecoveryMC",
                target="Recovery.tla", coverage=coverage, **fields)


def recovery_cases():
    """Positive cases per configuration, witnesses of the terminals and of the states the invariants constrain,
    and one mutation per invariant."""
    replacement = {"Replacement": "TRUE"}
    yield recovery("recovery")
    yield recovery("recovery-replacement", replacement)
    yield recovery("recovery-fence", {"Fence": "TRUE"}, coverage=RECOVERY_ACTIONS + ("PersistFence",))
    yield recovery("recovery-two-invalidations", {"Cursors": "{0, 1, 2}"})
    for case, settings in (
        ("NoRecovered", {}), ("NoWithheld", {}), ("NoExhausted", {}), ("NoVisibleSuccessor", replacement),
        ("NoObservedExclusion", {}), ("NoLostAcknowledgment", {}), ("NoLiveBinding", {}),
        ("NoRecoveryPastFloor", {}), ("NoWithheldBelowFloor", {}), ("NoInvalidationWithheld", {}),
        ("NoReuse", {}), ("NoFullIssue", {}), ("NoRecoveredFill", {}), ("NoLateLanding", {}),
        ("NoReuseBesideOldWork", {}), ("NoExclusionAcrossCrash", {}), ("NoLiveInvalidation", {}),
        ("NoReleasedProtection", {}), ("NoRecoveredExhaustion", {}), ("NoReplayAboveFloor", {}),
    ):
        yield recovery(case, settings, coverage=(), extra=f"INVARIANT {case}\n", expected=violation(case))
    for name, settings, invariant, old, new in (
        ("successor-before-exclusion", replacement, "XBeforeV",
         "q.l = r.l => Replacement /\\ q \\in excl", "q.l = r.l => Replacement"),
        ("ack-before-exclusion", {}, "AckAfterX",
         "    /\\ r \\in excl\n    /\\ obs' = [obs EXCEPT ![r] = \"emitted\"]",
         "    /\\ obs' = [obs EXCEPT ![r] = \"emitted\"]"),
        ("publish-without-evidence", {}, "AdmissionNeedsEvidence",
         "    /\\ r \\notin per.roots\n    /\\ Durable(r)\n", "    /\\ r \\notin per.roots\n"),
        ("recover-below-floor", {}, "RecoveredNeedsReplay",
         "IF Covered /\\ Cardinality(Eligible(l)) = 1", "IF Cardinality(Eligible(l)) = 1"),
        ("recover-unpublished", {}, "AdmitAuthorized",
         "{r \\in Admissible : /\\ r.l = l", "{r \\in Rec \\ excl : /\\ r.l = l"),
        ("recover-invalidated", {}, "ServeFresh",
         "/\\ \\A e \\in fresh.feed : e.r = r => e.at > vol.replayed}", "/\\ TRUE}"),
        ("recover-unobserved-invalidated", {}, "ReplayHonored",
         "/\\ \\A e \\in fresh.feed : e.r = r => e.at > vol.replayed}",
         "/\\ \\A e \\in fresh.feed : e.r = r => e.at > vol.replayed \\/ e.at > fresh.floor}"),
        ("feed-trims-acknowledged", {}, "ServeFresh",
         "    /\\ fresh' = [fresh EXCEPT !.floor = c]",
         "    /\\ fresh' = [fresh EXCEPT !.floor = c, !.feed = {e \\in @ : e.at > c}]"),
        ("reuse-admissible-extent", {}, "ReuseTwoProofs",
         "Free(u) == /\\ \\A r \\in Admissible : ~Holds(u, r)", "Free(u) == /\\ TRUE"),
        ("issuer-forgets-at-crash", {}, "GenerationNeverReissued",
         "    /\\ done' = \"crashed\"\n    /\\ UNCHANGED <<per, ",
         "    /\\ done' = \"crashed\"\n    /\\ per' = [per EXCEPT !.next = 0]\n    /\\ UNCHANGED <<"),
        ("late-write-relabelled", {}, "LateWorkKeepsIdentity",
         "!.media[w.u] = w.r]\n    /\\ old' = [q",
         "!.media[w.u] = [w.r EXCEPT !.l = CHOOSE l \\in Labels : l # w.r.l]]\n    /\\ old' = [q"),
        ("reuse-beside-old-work", {}, "UnknownIneligible",
         "/\\ \\A w \\in Outstanding : w.u # u", "/\\ \\A w \\in vol.queue : w.u # u"),
        ("fill-beside-old-work", {}, "UnknownIneligible",
         "    /\\ per.next + 1 \\in Gens\n    /\\ Free(u)\n",
         "    /\\ per.next + 1 \\in Gens\n"
         "    /\\ \\A r \\in Admissible : ~Holds(u, r)\n"
         "    /\\ \\A k \\in Labels : vol.index[k] # 0 => ~Holds(u, Bound(k))\n"
         "    /\\ u \\notin prot\n"
         "    /\\ \\A w \\in vol.queue : w.u # u\n"),
        ("crash-clears-exclusions", {}, "ExcludedStayOut",
         "    /\\ UNCHANGED <<per, obs, excl, fresh, prot, issued>>",
         "    /\\ excl' = {}\n    /\\ UNCHANGED <<per, obs, fresh, prot, issued>>"),
        ("live-invalidation-excludes", {}, "LiveAckIsNotExclusion",
         "    /\\ UNCHANGED <<per, old, obs, excl, prot, done>>",
         "    /\\ excl' = excl \\cup {Bound(l)}\n    /\\ UNCHANGED <<per, old, obs, prot, done>>"),
        ("live-invalidation-clears-other", {}, "LiveBindingFresh",
         "    /\\ vol' = [vol EXCEPT !.index[l] = 0]\n    /\\ fresh' = [fresh EXCEPT !.feed",
         "    /\\ vol' = [vol EXCEPT !.index[CHOOSE k \\in Labels : k # l] = 0]\n    /\\ fresh' = [fresh EXCEPT !.feed"),
        ("exhaust-early", {}, "ExhaustionIsTyped",
         "    /\\ per.next = Last\n    /\\ done' = \"Exhausted\"", "    /\\ done' = \"Exhausted\""),
        ("reuse-protected-extent", {}, "ProtectedUntilObserved",
         "           /\\ u \\notin prot\n", ""),
    ):
        yield recovery(name, settings, coverage=(), invariant=invariant, mutation=(old, new),
                       expected=violation(invariant))


# Statements that prune or merge the explored states, or override the deadlock check.
PRUNING = frozenset({"CONSTRAINT", "CONSTRAINTS", "ACTION_CONSTRAINT", "ACTION_CONSTRAINTS", "VIEW", "CHECK_DEADLOCK"})


def configuration(case, source):
    text = (source / case.base).read_text()
    for name, value in case.settings.items():
        text, count = re.subn(rf"(?m)^(\s*{name}\s*(?:=|<-)\s*).*$",
                              lambda match: match[1] + value, text)
        if count != 1:
            raise ValueError(f"{case.name}: expected one setting for {name}, got {count}")
    if not case.symmetry:
        text = re.sub(r"(?m)^SYMMETRY .*\n", "", text)
    elif case.liveness:
        raise ValueError(f"{case.name}: a liveness check under symmetry can miss a violating cycle")
    text = text.replace("SPECIFICATION Spec", f"SPECIFICATION {case.spec}")
    if case.invariant:
        invariants = "TypeOK" + (f" {case.invariant}" if case.invariant != "TypeOK" else "")
        text = re.sub(r"INVARIANTS\s+.*", f"INVARIANTS {invariants}\n", text, flags=re.S)
    text += case.extra
    try:
        found = statements(text)
    except ValueError as error:
        raise ValueError(f"{case.name}: the configuration from {case.base}: {error}") from error
    keywords = {keyword for keyword, _ in found}
    if pruning := sorted(keywords & PRUNING):
        raise ValueError(f"{case.name}: search pruning, a view or a deadlock override is not allowed: {pruning}")
    if "SYMMETRY" in keywords and not case.symmetry:
        raise ValueError(f"{case.name}: the configuration holds a SYMMETRY statement the case does not declare")
    selectors = [" ".join([keyword, *operands]) for keyword, operands in found if keyword in ("SPECIFICATION", "INIT", "NEXT")]
    if selectors != [f"SPECIFICATION {case.spec}"]:
        raise ValueError(f"{case.name}: the configuration selects {selectors}, not SPECIFICATION {case.spec} alone")
    return text


def run_case(case, source, output, jar, workers):
    directory = output / case.name
    directory.mkdir()
    for module in source.glob("*.tla"):
        shutil.copy2(module, directory / module.name)
    if case.mutation:
        path = directory / case.target
        text = path.read_text()
        old, new = case.mutation
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        path.write_text(text.replace(old, new))
    actions = kill_basis(case, source)["actions"] if killing(case) else None
    if actions == []:
        raise ValueError(f"{case.name}: no action of Next reaches the definition the mutation edits")
    (directory / "model.cfg").write_text(configuration(case, source))
    command = ["java", "-Xmx4g", "-XX:+UseParallelGC", "-cp", str(jar)]
    sany = subprocess.run(command + ["tla2sany.SANY", f"{case.module}.tla"],
                          cwd=directory, text=True, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT)
    (directory / "sany.log").write_text(sany.stdout)
    if sany.returncode or not parsed(case, sany.stdout):
        raise RuntimeError(f"{case.name}: SANY failed; see {directory / 'sany.log'}")
    command += ["tlc2.TLC", "-workers", str(workers), "-fp", "0", "-seed", "1",
                "-coverage", "1", *(["-lncheck", "final"] if case.liveness else []),
                "-config", "model.cfg", f"{case.module}.tla"]
    started = time.monotonic()
    print(f"RUN  {case.name}", flush=True)
    with (directory / "tlc.log").open("w") as log_file:
        completed = subprocess.run(command, cwd=directory, stdout=log_file,
                                   stderr=subprocess.STDOUT)
    log = (directory / "tlc.log").read_text()
    if outcomes(log) != [case.expected] or completed.returncode != exit_status(case.expected):
        raise RuntimeError(f"{case.name}: unexpected TLC outcome or exit {completed.returncode}; see {directory / 'tlc.log'}")
    if completed.returncode == 0 and (missing := uncovered(case, log)):
        raise RuntimeError(f"{case.name}: no coverage for {missing[0]}")
    if actions is not None and not takes_step(log, actions):
        raise RuntimeError(f"{case.name}: the counterexample takes no step of {actions}; see {directory / 'tlc.log'}")
    elapsed = round(time.monotonic() - started, 2)
    print(f"PASS {case.name} ({elapsed}s)", flush=True)
    return {"case": case.name, "tier": case.tier, "expected": case.expected,
            "returncode": completed.returncode, "coverage": list(case.coverage),
            "liveness": case.liveness,
            "seconds": elapsed, "command": command,
            "states": state_counts(log),
            "inputs": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                       for name in [*(p.name for p in sorted(source.glob("*.tla"))), "model.cfg"]},
            "logs": {name: hashlib.sha256((directory / name).read_bytes()).hexdigest()
                     for name in ("sany.log", "tlc.log")}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--jar", type=Path, default=os.environ.get("TLA_TOOLS_JAR"))
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--case", action="append", dest="selected")
    parser.add_argument("--tier", choices=sorted(PROFILES),
                        help="Run only the cases of one profile; scheduled includes every pr case")
    parser.add_argument("--output", type=Path, help="A new directory for inputs, logs, and results")
    args = parser.parse_args()
    if args.jar is None or not args.jar.is_file():
        parser.error("provide --jar or TLA_TOOLS_JAR pointing to tla2tools.jar")
    if args.workers < 1:
        parser.error("--workers must be positive")
    selected = list(cases())
    if args.selected:
        unknown = set(args.selected) - {case.name for case in selected}
        if unknown:
            parser.error(f"unknown cases: {sorted(unknown)}")
        selected = [case for case in selected if case.name in args.selected]
    if args.tier:
        selected = [case for case in selected if case.tier in PROFILES[args.tier]]
    output = args.output or Path(tempfile.mkdtemp(prefix="kestrike-tlc-"))
    if args.output:
        output.mkdir(parents=True, exist_ok=False)
    output = output.resolve()
    source = Path(__file__).resolve().parent
    jar = args.jar.resolve()
    print(f"Evidence: {output}", flush=True)
    with zipfile.ZipFile(jar) as archive:
        manifest = archive.read("META-INF/MANIFEST.MF").decode()
    runtime = subprocess.run(["java", "-version"], text=True, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, check=True).stdout
    record = {"date": datetime.now(timezone.utc).isoformat(),
              "jar_sha256": hashlib.sha256(jar.read_bytes()).hexdigest(),
              "jar_manifest": manifest, "runtime": runtime, "results": []}
    try:
        for case in selected:
            record["results"].append(run_case(case, source, output, jar, args.workers))
    finally:
        (output / "results.json").write_text(json.dumps(record, indent=2) + "\n")
    print(f"All {len(selected)} expected outcomes verified.", flush=True)


if __name__ == "__main__":
    main()
