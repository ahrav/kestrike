#!/usr/bin/env python3
"""Check that each action of an enrolled TLA+ model names its code site or a declared abstraction.

Usage:
  model-links.py check [--root DIR]

The registry is `verification/models/links.json` under the tree root, which defaults to this repository. Its `models`
list enrolls each model by repository path with the row kinds it enrolls; `action` is the one kind. Its `rows` list
maps one item of one enrolled model per row, keyed by `model`, `kind` and `name`. A row holds either `anchors`, a
non-empty list of `{path, quote, digest?}`, or `abstraction`, the stated reason the action has no code site, and a
`note` with the reviewer's reasoning.

`check` refuses, with exit 2 and one line per breach naming the row or the action:
- an enrolled model whose path is other than `tla/<file>`, the directory `tla/check.py` reads its models from, or
  that resolves outside the tree root, and a model that defines no `Next`;
- an action set that differs from the union of `Case.coverage` over the cases of `tla/check.py` whose `target` is
  the model and that are expected to complete. The action set is every name the model defines at column 0 with `==`,
  read by the runner's `definitions`, that the body of `Next` names once comments, string literals and the bound
  part of each `\\E` or `\\A` quantifier are removed, `Next` itself excluded. A bound runs from the quantifier
  through the first `:` outside `()`, `[]`, `{}` and `<<>>`, and a bound that reaches the end of `Next` first is
  refused;
- a disjunct of that body, a piece between two disjunction operators (`\\/`, `\\lor` or `∨`), that holds more than
  brackets and either names no definition or takes a step of its own with a prime or `UNCHANGED`. A `\\/` inside a
  guard also splits, so such a guard belongs in a named definition. A disjunct that names a definition and takes
  no step of its own passes whatever its branches, so a definition named only as a guard enters the action set;
  the TLC lane's coverage rule (`uncovered` in `tla/check.py`) then fails its completing cases, which report no
  step of that name;
- an action without a row, a row for a name that is no action, a model that is not enrolled or a kind the model does
  not enroll, two rows for one name, and a row with both or neither of an anchor list and an abstraction text;
- an anchor whose path is other than a tree-relative path spelled without `.`, `..` or empty parts, or is no file of
  the tree, or whose quote occurs other than once in it. A path ending in `.rs` is a Rust file, read as rustc reads
  it, with each CRLF as LF, and counted with its comments blanked by `code_text` of `scripts/judge-verus.py`, so a
  quote that occurs only in a comment is absent and a doc comment that repeats a header is not a second place. An
  occurrence in a Rust file that lies wholly inside one string or character literal, after the literal's first
  character, is not counted either (`masked_literals` of the same judge blanks that text), so a quote found only
  in a message string is absent and a string that repeats a header is not a second place. An occurrence that holds
  a literal's first character, as a quoted whole literal does, or any code beside a literal is counted;
- a digest on an anchor whose path names no `.rs` file;
- a digest on a quote that is followed by no item body of its own. A digested quote ends before its item's body
  `{`: its own braces balance, as a match-arm pattern's do, and it closes no brace or bracket it did not open, and
  ends with no closed block. Bracket depth counts `(` and `[` from the quote's first character. The check refuses a
  breach of those rules; a `;` or `}` at bracket depth zero, a second match-arm `=>`, or a `)` or `]` the quote did
  not open between the quote and the first `{` after it; a first `{` inside brackets; no `{` at all; braces that
  never balance; and a span whose closing brace is followed by `=>`, as a braced pattern or guard is, or by `else`,
  `.` or `?`, which continue the expression;
- a digest other than the item digest, printed beside the row and the anchor. The item is the comment-blanked text
  from the quote's first character through the brace that closes the first `{` after the quote, with braces inside
  string and character literals skipped (`masked_literals` of the same judge) and each run of white space collapsed
  to one space. Its digest is the SHA-256 of that text's UTF-8 bytes. A move of the item inside its file, an edit
  inside a comment and a change to the white space between tokens already apart keep the digest. White space or a
  comment between two tokens that touched, and a formatter re-wrap that adds or removes a token such as a trailing
  comma, change it. White space inside the quoted text is matched exactly, so a re-wrap there makes the quote
  absent, and runs of white space inside string literals collapse as well. Text before the quote, such as an
  attribute or an earlier match arm's guard, and the bodies of the functions the item calls lie outside the digest.
  The span rule reads text, not Rust syntax: angle brackets are not counted, so a brace in a const generic argument
  before the body opens the span early; an expression that continues after a block with an operator such as `as`
  or `+` ends the span at that block; and an enum variant quote followed by a struct variant spans into it.
These end the check with exit 2 and one line: a registry that cannot be read or does not match this shape; a registry
that does not enroll `tla/Lifecycle.tla` for action rows; a model or an anchor's file that cannot be read, or not as
UTF-8; a Rust file with a block comment that never closes; a failed load of the runner or the judge; and a runner or
judge whose functions raise or exit. Model and anchor paths must resolve inside the tree root. The registry,
`tla/check.py` and `scripts/judge-verus.py` are trusted inputs, read and executed at their fixed paths under the
root, and the judge loads `scripts/judge-rc11.py` beside its own resolved file. The check uses no network, tool,
evidence directory or clock.

A pass shows that at the checked tree every action of every enrolled model has one row, every quote names one place,
every digest equals the one recorded in its row and each action set equals the runner's coverage. That is a reviewed
mapping only when the person who recorded each digest read the item and the row. A digest can be pasted without
reading the item, and no check enforces the reading. Whether a pairing is right and whether a model matches or
refines the code stay outside the check, which validates no trace. No performance threshold applies beyond the
time limit of the job that runs the check.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path, PurePosixPath

REGISTRY = "verification/models/links.json"
KINDS = ("action",)
REQUIRED = ("tla/Lifecycle.tla",)
QUANTIFIER = re.compile(r"\\[EA]\b")
DISJUNCT = re.compile(r"\\/|\\lor\b|∨")
STEP = re.compile(r"'|\bUNCHANGED\b")
STRUCTURE = " \t\n()[]"
STRING = re.compile(r'"(?:\\.|[^"\\])*"')
DEPTH = {"(": 1, "[": 1, ")": -1, "]": -1}
BRACES = {"{": 1, "}": -1}


class Refusal(Exception):
    """A breach that ends the check before every rule ran: an unreadable input or a failed load."""


def load(root, relative, name):
    """Load the Python file `relative` of the tree as module `name`, refusing a file that is absent or fails."""
    path = root / relative
    try:
        spec = importlib.util.spec_from_file_location(name, path)
        if spec is None or spec.loader is None:
            raise ImportError("no module loader takes the path")
        module = importlib.util.module_from_spec(spec)
        sys.modules[name] = module
        spec.loader.exec_module(module)
    except (Exception, SystemExit) as error:
        raise Refusal(f"{relative} cannot be loaded: {error}") from error
    return module


def unique(pairs):
    names = [name for name, _ in pairs]
    if len(set(names)) != len(names):
        raise ValueError(f"an object repeats {sorted({name for name in names if names.count(name) > 1})}")
    return dict(pairs)


def shaped(value, keys, required, where):
    """`value` when it is an object whose members are among `keys` and include `required`."""
    if not isinstance(value, dict) or not set(required) <= set(value) or not set(value) <= set(keys):
        raise Refusal(f"{REGISTRY}: {where} is not an object with {sorted(required)} among {sorted(keys)}")
    return value


def text_field(value, key, where):
    if not isinstance(value.get(key), str) or not value[key].strip():
        raise Refusal(f"{REGISTRY}: {where} has no {key} text")
    return value[key]


def registry(root):
    """The registry's enrolled models, by path to their kinds, and its rows, refusing any other shape."""
    try:
        data = json.loads((root / REGISTRY).read_text(encoding="utf-8"), object_pairs_hook=unique)
    except (OSError, ValueError, RecursionError) as error:
        raise Refusal(f"unreadable {REGISTRY}: {error}") from error
    shaped(data, ("models", "rows"), ("models", "rows"), "the registry")
    if not isinstance(data["models"], list) or not isinstance(data["rows"], list):
        raise Refusal(f"{REGISTRY}: models and rows are not lists")
    models = {}
    for at, model in enumerate(data["models"]):
        shaped(model, ("path", "kinds"), ("path", "kinds"), f"model {at}")
        kinds = model["kinds"]
        if (not isinstance(kinds, list) or not kinds or not all(kind in KINDS for kind in kinds)
                or len(set(kinds)) != len(kinds)):
            raise Refusal(f"{REGISTRY}: model {at} kinds are not a list of distinct {list(KINDS)}")
        if text_field(model, "path", f"model {at}") in models:
            raise Refusal(f"{REGISTRY}: model {model['path']} is enrolled twice")
        models[model["path"]] = kinds
    for model in REQUIRED:
        if "action" not in models.get(model, ()):
            raise Refusal(f"{REGISTRY}: {model} is not enrolled for action rows")
    for at, row in enumerate(data["rows"]):
        shaped(row, ("model", "kind", "name", "anchors", "abstraction", "note"), ("model", "kind", "name", "note"),
               f"row {at}")
        for key in ("model", "kind", "name", "note"):
            text_field(row, key, f"row {at}")
        label = f"row {at} ({row['model']} {row['kind']} {row['name']})"
        if "abstraction" in row:
            text_field(row, "abstraction", label)
        if "anchors" in row:
            if not isinstance(row["anchors"], list) or not row["anchors"]:
                raise Refusal(f"{REGISTRY}: {label} anchors are not a non-empty list")
            for number, anchor in enumerate(row["anchors"]):
                where = f"{label} anchor {number}"
                shaped(anchor, ("path", "quote", "digest"), ("path", "quote"), where)
                text_field(anchor, "path", where)
                text_field(anchor, "quote", where)
                if "digest" in anchor and not (isinstance(anchor["digest"], str)
                                               and re.fullmatch(r"[0-9a-f]{64}", anchor["digest"])):
                    raise Refusal(f"{REGISTRY}: {where} digest is not 64 lowercase hex digits")
    return models, data["rows"]


def unbound(body):
    """`body` with the bound part of each quantifier removed: from `\\E` or `\\A` through the first `:` outside
    brackets, braces and `<<>>`, or None when a bound reaches the end of `body` first. A quantifier inside a bound
    goes with that bound."""
    pieces, at = [], 0
    for match in QUANTIFIER.finditer(body):
        if match.start() < at:
            continue
        depth, end = 0, match.end()
        while end < len(body) and (depth > 0 or body[end] != ":"):
            pair = body[end:end + 2]
            if pair in ("<<", ">>"):
                depth += 1 if pair == "<<" else -1
                end += 2
                continue
            depth += DEPTH.get(body[end], 0) + BRACES.get(body[end], 0)
            end += 1
        if end == len(body):
            return None
        pieces.append(body[at:match.start()])
        at = end + 1
    return " ".join([*pieces, body[at:]])


def actions(runner, text):
    """The body of the module's `Next` with comments and string literals removed, its column-0 definitions other than
    `Next`, and the runner's identifier pattern; None when the module defines no `Next`."""
    try:
        found = runner.definitions(text)
        identifier = runner.IDENTIFIER
    except (Exception, SystemExit) as error:
        raise Refusal(f"the definition reader of tla/check.py refuses the model: {error}") from error
    if "Next" not in found:
        return None
    return STRING.sub(" ", found["Next"][2]), set(found) - {"Next"}, identifier


def disjuncts(body, defined, identifier):
    """The names of `defined` that `body` names once its quantifier bounds are removed, and the disjuncts that are
    no named action; None when a bound never ends."""
    body = unbound(body)
    if body is None:
        return None
    unnamed = [" ".join(piece.split()) for piece in DISJUNCT.split(body)
               if piece.strip(STRUCTURE) and (STEP.search(piece) or not set(identifier.findall(piece)) & defined)]
    return set(identifier.findall(body)) & defined, unnamed


def coverage(runner, name):
    """The union of `coverage` over the runner's cases of target `name` that are expected to complete."""
    try:
        return {action for case in runner.cases() if case.target == name and runner.exit_status(case.expected) == 0
                for action in case.coverage}
    except (Exception, SystemExit) as error:
        raise Refusal(f"tla/check.py cannot list its cases: {error}") from error


def item(code, masked, start, end):
    """The item text from offset `start` of comment-blanked `code` through the brace that closes the first `{` at or
    after offset `end`, where the quote ends, or the reason it has no body of its own. `masked` is `code` with its
    literals blanked, offset for offset. Bracket depth counts `(` and `[` from `start`, so the quote's own
    brackets count; the quote's own braces must balance."""
    braces = depth = 0
    for char in masked[start:end]:
        braces += BRACES.get(char, 0)
        depth += DEPTH.get(char, 0)
        if braces < 0 or depth < 0:
            return None, "the quote closes a brace or bracket it does not open"
    if braces:
        return None, "the braces inside the quote do not balance"
    if masked[start:end].rstrip().endswith("}"):
        return None, "the quote ends with a closed block"
    for at in range(end, len(masked)):
        char = masked[at]
        if char == "{":
            if depth > 0:
                return None, "the first '{' after the quote lies inside brackets"
            break
        depth += DEPTH.get(char, 0)
        if depth < 0:
            return None, f"a {char!r} after the quote closes a bracket the quote does not open"
        if depth == 0 and char in ";}":
            return None, f"a {char!r} at bracket depth zero lies between the quote and the first '{{'"
    else:
        return None, "no '{' follows the quote"
    if masked.count("=>", start, at) > 1:
        return None, "a second match arm lies between the quote and the first '{'"
    braces = 0
    for close in range(at, len(masked)):
        braces += BRACES.get(masked[close], 0)
        if braces == 0:
            after = masked[close + 1:].lstrip()
            if after.startswith("=>"):
                return None, "the span closes inside a match pattern or guard, before its '=>'"
            if after.startswith((".", "?")) or re.match(r"else\b", after):
                return None, "the expression continues after the span's closing brace"
            return re.sub(r"\s+", " ", code[start:close + 1]), None
    return None, "the braces after the quote never balance"


def check_anchor(root, judge, where, anchor, refusals):
    cited = PurePosixPath(anchor["path"])
    if cited.is_absolute() or cited.as_posix() != anchor["path"] or ".." in cited.parts:
        refusals.append(f"{where}: {anchor['path']} is no tree-relative path spelled without '.', '..' or empty parts")
        return
    path = root / anchor["path"]
    try:
        path = path.resolve()
        inside = path.is_relative_to(root) and path.is_file()
    except (OSError, ValueError, RuntimeError):
        inside = False
    if not inside:
        refusals.append(f"{where}: {anchor['path']} is no file of the tree")
        return
    rust = anchor["path"].endswith(".rs")
    try:
        code = judge.code_text(judge.source_text(path), anchor["path"]) if rust else path.read_text(encoding="utf-8")
    except Exception as error:
        raise Refusal(f"{where}: {anchor['path']} cannot be read: {error}") from error
    try:
        masked = judge.masked_literals(code) if rust else code
    except Exception as error:
        raise Refusal(f"{where}: the literals of {anchor['path']} cannot be masked: {error}") from error
    quote = anchor["quote"]
    places, at = [], code.find(quote)
    while at >= 0:
        if masked[at:at + len(quote)].strip():
            places.append(at)
        at = code.find(quote, at + 1)
    if len(places) != 1:
        refusals.append(f"{where}: the quote {quote!r} occurs {len(places)} times in {anchor['path']}")
        return
    if "digest" not in anchor:
        return
    if not rust:
        refusals.append(f"{where}: a digest needs a Rust item, and {anchor['path']} is no Rust file")
        return
    start = places[0]
    body, reason = item(code, masked, start, start + len(quote))
    if body is None:
        refusals.append(f"{where}: the quote {quote!r} carries a digest but has no item body: {reason}")
    elif (current := hashlib.sha256(body.encode("utf-8")).hexdigest()) != anchor["digest"]:
        refusals.append(f"{where}: the item at {anchor['path']} {quote!r} changed; read it and the row, then record "
                        f"its current digest {current}")


def check(root):
    """Every refusal of the tree at `root`, in registry order; an empty list is a pass."""
    models, rows = registry(root)
    runner = load(root, "tla/check.py", "model_links_runner")
    judge = load(root, "scripts/judge-verus.py", "model_links_judge")
    refusals, named = [], {}
    for model in models:
        try:
            inside = model == f"tla/{Path(model).name}" and (root / model).resolve().is_relative_to(root)
        except (OSError, ValueError, RuntimeError):
            inside = False
        if not inside:
            refusals.append(f"{model}: an enrolled model must be named tla/<file> and lie in tla/ of the tree, where "
                            "tla/check.py reads its models")
            continue
        try:
            text = (root / model).read_text(encoding="utf-8")
        except (OSError, ValueError) as error:
            raise Refusal(f"{model} cannot be read: {error}") from error
        read = actions(runner, text)
        if read is None:
            refusals.append(f"{model}: the model defines no Next")
            continue
        split = disjuncts(*read)
        if split is None:
            refusals.append(f"{model}: a quantifier bound in Next reaches the end of Next without its ':'")
            continue
        defined, unnamed = split
        for piece in unnamed:
            refusals.append(f"{model}: the disjunct {piece!r} of Next names no definition or takes a step of its own")
        covered = coverage(runner, Path(model).name)
        for name in sorted(defined - covered):
            refusals.append(f"{model}: action {name} of Next is in no completing case's coverage in tla/check.py")
        for name in sorted(covered - defined):
            refusals.append(f"{model}: coverage name {name} in tla/check.py is no action of Next")
        named[model] = {"action": defined}
    seen = {}
    for row in rows:
        where = f"{row['model']} {row['kind']} {row['name']}"
        if row["model"] not in models:
            refusals.append(f"{where}: the row's model is not enrolled")
            continue
        if row["kind"] not in models[row["model"]]:
            refusals.append(f"{where}: {row['model']} does not enroll {row['kind']} rows")
            continue
        if row["model"] in named and row["name"] not in named[row["model"]][row["kind"]]:
            refusals.append(f"{where}: the row names no {row['kind']} of {row['model']}")
        key = (row["model"], row["kind"], row["name"])
        seen[key] = seen.get(key, 0) + 1
        if seen[key] == 2:
            refusals.append(f"{where}: two rows name this {row['kind']}")
        if bool(row.get("anchors")) == ("abstraction" in row):
            refusals.append(f"{where}: the row holds {'both' if 'abstraction' in row else 'neither'} of an anchor "
                            "and an abstraction text")
        for number, anchor in enumerate(row.get("anchors", [])):
            check_anchor(root, judge, f"{where} anchor {number}", anchor, refusals)
    for model, kinds in sorted(named.items()):
        for kind, names in sorted(kinds.items()):
            for name in sorted(names):
                if (model, kind, name) not in seen:
                    refusals.append(f"{model} {kind} {name}: the {kind} has no row")
    return refusals


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)
    run = commands.add_parser("check", help="check the registry against the models, the runner and the code")
    run.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    try:
        refusals = check(args.root.resolve())
    except Refusal as error:
        print(f"model-links: {error}", file=sys.stderr)
        return 2
    except (Exception, SystemExit) as error:
        print(f"model-links: the check stopped on {type(error).__name__}: {error}", file=sys.stderr)
        return 2
    for refusal in refusals:
        print(f"model-links: {refusal}", file=sys.stderr)
    if refusals:
        return 2
    print(f"model-links: {REGISTRY} maps every action of its enrolled models")
    return 0


if __name__ == "__main__":
    sys.exit(main())
