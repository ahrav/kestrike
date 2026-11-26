#!/usr/bin/env python3
"""Validate the atomic-site census in verification/atomics/census.json.

Usage:
  classify-atomics.py check [--census FILE]

The census gives each atomic surface in `SURFACES` exactly one
disposition, with source evidence:

- `covered`: an existing check the census names in `checks` and a witness
  of a fault or state that check drives. The witness names one of the
  checks, a test that check runs, and `observes`, text the test's own body
  holds outside its comments. The test's body names one of the surface's
  writer fns or an operation's method.
- `serialized`: an `exclusion`, an `argument` and the writer chain the
  exclusion guards. The
  exclusion names its `fn` and source text inside that fn that takes a
  lock (`try_lock(` or `.lock(`) into `let <guard> =`, a named guard whose
  statement ends in `?` or calls `unwrap` or `expect`, so a refused
  acquisition leaves the fn; the locked region
  runs from the `;` that ends that statement, so a handler of a refused
  acquisition lies outside it, to the guard's `release()` or
  `drop(<guard>)`, or to the end of the block that binds the guard, and
  any other use of the guard inside the region refuses. A closure or
  async body inside the region lies outside it, since its run may follow
  the guard's release. The text names
  none of the surface's operations.
  `words` names the structs or statics that hold the surface's atomics.
  The check reads each atomic field from its declaration and scans every
  production file the field's visibility reaches, private to its file and
  its module's descendants, `pub(super)` to its parent module's tree,
  `pub(crate)` or `pub` to the crate,
  for a store, swap, fetch, compare-exchange, `as_ptr`, `get_mut` or
  `into_inner` on it, a `&` borrow of it, or a struct expression or
  pattern that names a listed struct, path-qualified or not. A `Self { .. }`
  constructor inside the struct's impl lies outside the scan, so the
  surface's `argument` states when that initialization runs. Every operation that writes lies in one of
  those writes. Every write lies in a listed writer or in the locked
  region, apart from a write `foreign` lists by file, fn, word and
  receiver, which belongs to another struct's field of the same name; a
  `foreign` entry that matches no write refuses. Every listed writer other than the
  root is called at least once in the files its own visibility reaches,
  and each call lies in a listed writer or in the locked region. A
  writer reached `via` an accessor is checked at each accessor call: a
  call chained to the writer must be guarded, a call chained to another
  `via` writer or to a method `reads` declares whose every definition
  touches the words only by `load` and calls no method on `self` passes,
  and any other use of the
  accessor refuses. Every listed writer writes a word or calls a writer.
- `needs-kernel`: the exact `obligation`, its missing observation, its
  actor and its fault. The check reports it and credits it as nothing.

Every surface also names its production `path`, the `operations` it
classifies, each held by that path's code outside comments and literals,
and its `writers`. Each writer cites `evidence`, source text in
its own `path` or the surface's, comments included. A surface that claims
`"writers_at_once": "one"` must be serialized as above, so a writer count
taken from what a counter is for, from the write itself or from a lock
elsewhere refuses. A covered witness's `observes` holds an assertion
outside comments, so a commented-out assertion witnesses nothing.

A check is an obligation id from verification/obligations.json or a test
the catalog or scripts/test-inventory.json names. Source text matches after
each run of whitespace becomes one space, in the production source: every
element under `#[cfg(test)]` or `#[cfg(all(test, ...))]` is blanked first,
the attribute and the element's end found outside comments and literals. An
item such as a fn or impl ends at its first block or its `;`. Any other
element ends at its first block, its `;` or its `,` outside brackets, or
before the bracket that closes its list, and a generic or closure
parameter before its list's `>` or `|`. What an element is follows from
the text before its attributes: directly after `{`, `}`, `;` or the start
of the file it is an item, a statement or the first element of a braced
list; anywhere else it is a list element, and a parameter only where its
list's `<` or `|` precedes it. Evidence, an operation, a call or a
declaration in the text of an element after its first block counts as
production source. An element whose end is read more than one way, among
them an element that ends at a `,` its own generic arguments or closure
parameters may hold and an element among a macro's tokens that is no item
or statement, is blanked up to its earliest end, and the check refuses it
as `cut-element`, with its file and line, in every source it reads.
The write and call scans also blank comments and literal contents, and a
glob reaches no `*_tests.rs`, `*_bench.rs` or `*_model.rs` file.

`check` prints one JSON report with the refusals, each surface's
disposition, the needs-kernel obligations under `reported`, and `credited`,
true only when nothing is refused or reported. Exit 0 is a
census without refusals, 1 is a refusal, 2 is a census, catalog or
inventory that cannot be read.
"""

import argparse
import importlib.util
import json
import re
import sys
from functools import cache
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CENSUS = ROOT / "verification/atomics/census.json"
CATALOG = ROOT / "verification/obligations.json"
INVENTORY = ROOT / "scripts/test-inventory.json"
SURFACES = (
    "bind/wc job dispenser",
    "native/containment exchange",
    "native/ena callback flag",
    "native/env once-election",
    "native/registration issuance counter",
    "net/serving signal word",
    "net/client shard route binding",
    "storage/gate word",
    "storage/cache one-shot cutoff",
    "storage/closing cursor",
    "storage/maintain cursor",
    "storage/expire advisory bound",
    "storage/finalize exclusive owner",
    "storage/evict serialized writer",
    "storage/volume/attach election",
    "storage/journal durable prefix",
    "storage/coverage epoch word",
    "storage/coverage positions",
    "storage/journal parked marker",
    "storage/record generation column",
    "storage/readiness word",
)
DISPOSITIONS = ("covered", "serialized", "needs-kernel")
WITNESS_KINDS = ("fault", "state")
COMMON = {"store", "load", "swap", "fetch_add", "cast", "into", "unwrap", "storage", "state", "tables", "live", "len"}
LOCKS = ("try_lock(", ".lock(")
WRITES = r"store|swap|fetch_[a-z_]+|compare_exchange[a-z_]*|as_ptr|get_mut|into_inner"
FN = re.compile(r'^[ \t]*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+)?(?:unsafe\s+)?(?:extern\s+"C"\s+)?fn\s+(\w+)', re.M)
TEST_ITEM = re.compile(r"#\[cfg\((?:test|all\(test\b[^\]]*)\)\]")
RUN = re.compile(r"(?:#\s*\[(?:[^\[\]]|\[[^\[\]]*\])*\]\s*)*" + TEST_ITEM.pattern)
UNION = r"union(?=\s+(?!(?:as|if)\b)[A-Za-z_])"
QUALIFIERS = r"(?:pub(?:\([^)]*\))?\s+)?(?:(?:const|unsafe|async|extern(?:\s+\"[^\"]*\")?)\s+)*"
ITEM = re.compile(r"\s*(?:#\[[^\]]*\]\s*)*" + QUALIFIERS + rf"(?:fn|impl|struct|enum|{UNION}|trait|type|mod|const|static|use)\b")
MACRO = re.compile(r"(?:\bmacro_rules\s*!\s*(?:r#)?\w+|\w\s*!)\s*$")
PROVEN = re.compile(r"\s*(?:#\[[^\[\]]*\]\s*)*(?:" + QUALIFIERS
                    + rf"(?:fn\s+\w|{UNION}|static(?=\s+(?!move\b)[A-Za-z_])|(?:impl|struct|enum|trait|type|mod|use)\b)"
                    r"|(?:let|if|match|while|for|loop|return)\b)")


def load(script):
    """Return scripts/`script`.py loaded as a module."""
    spec = importlib.util.spec_from_file_location(script.replace("-", "_"), ROOT / f"scripts/{script}.py")
    if spec is None or spec.loader is None:
        raise OSError(f"scripts/{script}.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rc11 = load("judge-rc11")


def receipts():
    """Return scripts/verify-receipts.py loaded as a module, for its `control_text` test-body reader."""
    return load("verify-receipts")


BRACE = re.compile(r"[{}]")


def closing(text, start):
    """Return the offset just past the brace that closes the block opening at `start`, or None. Braces are counted
    from `start`, and a `start` that holds no brace closes at once, just past itself."""
    if start < len(text) and text[start] not in "{}":
        return start + 1
    depth = 0
    for brace in BRACE.finditer(text, start):
        depth += 1 if brace.group() == "{" else -1
        if depth == 0:
            return brace.end()
    return None


def blank(text):
    """Return `text` with every character other than a newline replaced by a space."""
    return "\n".join(" " * len(line) for line in text.split("\n"))


def item_end(text, start, closer=None):
    """Return the end of the item or statement starting at `start`: its block, or its `;` outside brackets, or
    for a field, variant, argument or arm, its `,` outside brackets. An item keyword after the attributes and
    visibility, such as `fn` or `impl`, runs past the commas of its generics to its block or `;`. A closing
    bracket or brace that the item never opened belongs to the enclosing list or block, so a last element
    without a trailing comma ends before it. Inside a generic or closure parameter list, `closer` names the
    list's closing `>` or `|`, and the element ends at its `,` or before that closer. A `closer` of `,` reads an
    element of any other list, which ends at its `,` whatever word starts it."""
    item, tracked = closer is None and ITEM.match(text, start) is not None, closer in (">", "|")
    parens = angle = 0
    for index in range(start, len(text)):
        char = text[index]
        if char in "([":
            parens += 1
        elif (char in ")]" and parens == 0) or char == "}":
            return index
        elif char in ")]":
            parens -= 1
        elif tracked and parens == 0 and char == "<":
            angle += 1
        elif tracked and parens == 0 and char == ">" and text[index - 1:index] not in ("-", "="):
            if angle == 0 and closer == ">":
                return index
            angle = max(angle - 1, 0)
        elif closer == "|" and parens == 0 and angle == 0 and char == "|":
            return index
        elif char == "{":
            return closing(text, index)
        elif parens == 0 and angle == 0 and (char == ";" or (char == "," and not item)):
            return index + 1
    return None


def readings(text, start):
    """Return the closers `item_end` reads under for the test-only element at `start`, from the text before its
    attributes.

    Directly after `{`, `}`, `;` or the start of `text` the element is an item, a statement or the first element of
    a braced list. No parameter list is open there, so it is read once, as an item or statement. Anywhere else it is
    an element of a list: it is read to its `,`, as a generic parameter when a `<` lies outside brackets between it
    and the bracket or `;` its list follows, and as a closure parameter when a `|` lies there, since a parameter
    list's own opener lies in that stretch."""
    depth, direct, openers = 0, True, set()
    for index in range(start - 1, -2, -1):
        char = text[index] if index >= 0 else ";"
        if char in ")]}":
            if direct and not depth and char == "}":
                return (None,)
            depth += 1
        elif char in "([{":
            if not depth:
                if direct and char == "{":
                    return (None,)
                break
            depth -= 1
            direct = direct and (depth > 0 or (char == "[" and re.search(r"#\s*!?\s*$", text[max(0, index - 8):index]) is not None))
        elif depth or char.isspace() or (direct and char in "#!"):
            continue
        elif char == ";":
            if direct:
                return (None,)
            break
        else:
            direct = False
            openers.update(char if char in "<|" else "")
    return (",", *(closer for opener, closer in (("<", ">"), ("|", "|")) if opener in openers))


def macro_spans(text):
    """Return the (opening bracket, closing bracket) offsets of the tokens of each macro definition and invocation
    of `text`, a file's code with comments and literals blanked: each bracket pair that follows `name!` or
    `macro_rules! name`."""
    spans, stack = [], []
    for bracket in re.finditer(r"[()\[\]{}]", text):
        if bracket.group() in "([{":
            stack.append(bracket.start() if MACRO.search(text, max(0, bracket.start() - 80), bracket.start()) else None)
        elif stack and (opened := stack.pop()) is not None:
            spans.append((opened, bracket.start()))
    return spans


def own_comma(text, start, end, proven):
    """Return whether the element of `text` from `start` to `end` ends at a `,` that a comma among its own generic
    arguments or closure parameters may be: any `,` that ends a statement `PROVEN` matches, and otherwise one a `<`
    of the element is still open at, or one after a `|` that follows the element's last `=>`."""
    tail = max(start, text.rfind("=>", start, end) + 2)
    return text[end - 1] == "," and (proven or (item_end(text, tail, ">") or len(text)) > end or item_end(text, tail, "|") != end)


def analyzed(text):
    """Return `(production, scanned, cut)` for `text`.

    `production` is `text` with each test-only element blanked from the first outer attribute of the run that holds
    its `cfg` attribute, offsets kept, and `scanned` is `production` with comments and literal contents also
    blanked, as `code` returns it. Attributes and element ends are found in the scanned text, so attribute text
    inside a comment blanks nothing and a brace inside a literal ends no element. Each blanked element starts and
    ends outside any comment or literal, so blanking it in both texts keeps `scanned` equal to `code(production)`.

    An element `PROVEN` matches starts with a word no parameter starts with: an item keyword followed as an item
    follows it (`fn` and `union` by a name, `static` by a name other than `move`), or `let`, `if`, `match`, `while`,
    `for`, `loop` or `return`. It is read once, as an item or statement; `union` followed by `as` or `if`, or by no
    name, is an identifier. Any other element is read under the closers `readings` selects, or under every closer
    among the tokens of a macro, whose expansion decides what the element is. The element ends at the earliest
    end, so the code after it stays in the production text.

    `cut` holds the offset of the first attribute of each element whose end may lie before its true end, leaving the
    rest of it in the production text: an element among a macro's tokens that `PROVEN` does not match, an element
    whose readings end at different offsets, a reading without an end included, and an element that ends at a `,`
    which a comma among its own generic arguments or closure parameters may be. An attribute inside an element
    already blanked is skipped. Every run ends in a `#[cfg(` attribute, so a text without one holds no run."""
    masked, spans, cut, covered, macros = code(text), [], [], 0, None
    for attribute in RUN.finditer(masked) if "#[cfg(" in masked else ():
        start, proven = attribute.end(), PROVEN.match(masked, attribute.end()) is not None
        macros = macro_spans(masked) if macros is None and not proven else macros
        inside = not proven and any(low < start < high for low, high in macros or ())
        closers = (None,) if proven else (None, ",", ">", "|") if inside else readings(masked, start)
        ends = {item_end(masked, start, closer) for closer in closers}
        end = min((found for found in ends if found is not None), default=None)
        if attribute.start() >= covered:
            covered = end or covered
            if inside or len(ends) > 1 or (end is not None and own_comma(masked, start, end, proven)):
                cut.append(attribute.start())
        if end is not None:
            spans.append((attribute.start(), end))
    if spans:
        text, masked = (spliced(s, spans) for s in (text, masked))
    return text, masked, cut


def spliced(text, spans):
    """Return `text` with every character other than a newline inside one of the `(start, end)` spans replaced by a
    space, offsets kept. The spans may nest or overlap, so each run of overlapping spans blanks once."""
    pieces, at = [], 0
    for start, end in sorted(spans):
        if end <= at:
            continue
        start = max(start, at)
        pieces += [text[at:start], blank(text[start:end])]
        at = end
    return "".join([*pieces, text[at:]])


def blanked(text):
    """Return `(production, scanned)` of `analyzed(text)`."""
    return analyzed(text)[:2]


def code(text):
    """Return `text` with each comment, string literal and char literal blanked, newlines and offsets kept, so a
    brace, a call or a word inside them matches nothing. A literal's `b` or `c` prefix stays, and a block comment
    that never closes blanks the rest of `text`."""
    pieces, index = [], 0
    for _, start, end in rc11.rust_lexemes(text):
        pieces += [text[index:start], blank(text[start:end])]
        index = end
    return "".join([*pieces, text[index:]])


def enclosing_fns(text):
    """Return (start, body, end, name) for each fn with a body in `text`; `body` is its opening brace."""
    spans = []
    for item in FN.finditer(text):
        brace, semicolon = text.find("{", item.end()), text.find(";", item.end())
        if brace < 0 or 0 <= semicolon < brace:
            continue
        end = closing(text, brace)
        if end is not None:
            spans.append((item.start(), brace, end, item.group(1)))
    return spans


def innermost(spans, offset):
    """Return the last span of `spans` that contains `offset`, the innermost fn in source order, or None."""
    inner = [span for span in spans if span[0] <= offset < span[2]]
    return inner[-1] if inner else None


def whole_assertion(text):
    """Return whether `text` holds an `assert…!(` call with arguments whose parenthesis closes inside `text`."""
    for start in re.finditer(r"\bassert\w*!\s*\(", text):
        depth = 0
        for index in range(start.end() - 1, len(text)):
            depth += {"(": 1, ")": -1}.get(text[index], 0)
            if depth == 0:
                if text[start.end():index].strip():
                    return True
                break
    return False


def flat(text):
    return re.sub(r"\s+", " ", text).strip()


def loose(text):
    """Return a pattern matching `text` with any whitespace between its tokens."""
    return r"\s*".join(re.escape(token) for token in text.split())


def inventory_tests(value):
    """Yield every test name a `tests` or `controls` list in the inventory holds."""
    if isinstance(value, dict):
        for key, inner in value.items():
            if key in ("tests", "controls") and isinstance(inner, list):
                for item in inner:
                    name = item.get("test") if isinstance(item, dict) else item
                    if isinstance(name, str):
                        yield name
            else:
                yield from inventory_tests(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from inventory_tests(inner)


class Census:
    def __init__(self, catalog, inventory, control_text):
        self.jobs = {r["id"]: r["job"] for r in catalog["records"]}
        self.runs = {r["id"]: {*r["tests"], *(c["test"] for c in r["controls"])} for r in catalog["records"]}
        self.tests = set(inventory_tests(inventory)).union(*self.runs.values())
        self.control_text = control_text
        self.seen = set()

    @staticmethod
    @cache
    def read(path):
        """Return `analyzed` of the source at `path`, or `(None, None, [])` when it cannot be read."""
        try:
            return analyzed((ROOT / path).read_text(encoding="utf-8"))
        except (OSError, TypeError):
            return None, None, []

    def load(self, path):
        """Return `read(path)` and note `path` among the sources this judge reads."""
        self.seen.add(path)
        return Census.read(path)

    def text(self, path):
        return self.load(path)[0]

    def code(self, path):
        return self.load(path)[1]

    def scanned(self, path):
        """Return the scanned text of a file the census already read; a file it could not read scans as empty."""
        return self.code(path) or ""

    @cache
    def spans(self, path):
        return enclosing_fns(self.code(path))

    def holds(self, path, text, scanned=False):
        """Return whether `path` holds `text`: in its code when `scanned`, else in its production text, comments
        included."""
        source = self.code(path) if scanned else self.text(path)
        return isinstance(text, str) and bool(text.strip()) and source is not None and flat(text) in flat(source)

    def resolves(self, check):
        return check in self.runs or check in self.tests

    def witness_text(self, check, test):
        """Return the witness test's body when the check runs it, else None."""
        if check in self.runs:
            return self.control_text(test, self.jobs[check]) if test in self.runs[check] else None
        return self.control_text(test) if test == check else None

    @staticmethod
    def expand(files):
        return Census.globbed(tuple(files))

    @staticmethod
    @cache
    def globbed(files):
        """Return `files` with each glob replaced by the production files it matches; a test, bench or model
        file is test-only."""
        names = []
        for entry in files:
            if "*" not in entry:
                names.append(entry)
                continue
            names.extend(str(found.relative_to(ROOT)) for found in sorted(ROOT.glob(entry))
                         if not re.search(r"_(?:tests|bench|model)\.rs$", found.name))
        return names

    def sites(self, pattern, files, needles=None):
        """Yield (file, enclosing fn span, offset) for each match of `pattern` in `files` outside a fn header;
        a glob among `files` names the production files it matches. Every file is read, so the census reads the
        same sources. When `needles` is given, every match of `pattern` holds one of its strings, so a file
        whose scanned text holds none of them yields nothing and is not scanned."""
        for name in self.expand(files):
            text = self.code(name)
            if text is None:
                raise FileNotFoundError(name)
            if needles is not None and not any(needle in text for needle in needles):
                continue
            for found in re.finditer(pattern, text):
                if re.search(r"\bfn\s+$", text[max(0, found.start() - 16):found.start()]):
                    continue
                yield name, innermost(self.spans(name), found.start()), found.start()

    def judge(self, census):
        refusals, verdicts, reported = [], {}, []

        def refuse(code, surface, reason):
            refusals.append({"code": code, "surface": surface, "reason": reason})

        surfaces = census.get("surfaces") if isinstance(census, dict) else None
        if not isinstance(surfaces, list):
            refuse("malformed-census", None, "the census needs a list of surfaces")
            return refusals, verdicts, reported
        named = [s.get("surface") if isinstance(s, dict) else None for s in surfaces]
        for name in SURFACES:
            if name not in named:
                refuse("omitted-surface", name, "the census gives this surface no disposition")
        for site in surfaces:
            name = site.get("surface") if isinstance(site, dict) else None
            if name not in SURFACES:
                refuse("unknown-surface", name, f"the census names a surface outside the {len(SURFACES)} in SURFACES")
                continue
            if name in verdicts:
                refuse("duplicate-surface", name, "the surface has more than one disposition")
                continue
            verdicts[name] = site.get("disposition")
            self.judge_site(site, name, lambda code, reason, name=name: refuse(code, name, reason), reported)
        for path in sorted(self.seen, key=str):
            production, _, cut = self.load(path)
            for offset in cut:
                refuse("cut-element", None, f"{path}:{(production or '').count(chr(10), 0, offset) + 1}: a test-only element whose end is "
                                            "read more than one way; parenthesize its `<`, `>` or `|`, or move it into a test-only block or module")
        return refusals, verdicts, reported

    def judge_site(self, site, name, refuse, reported):
        path = site.get("path")
        if self.text(path) is None:
            refuse("missing-source", f"path {path!r} names no source file")
            return
        operations = [op for op in site.get("operations") or [] if isinstance(op, str)]
        if not operations:
            refuse("missing-operation", "the surface names no atomic operation")
        for operation in operations:
            if not self.holds(path, operation, scanned=True):
                refuse("missing-operation", f"{path} holds no {operation!r}")
        writers = [w for w in site.get("writers") or [] if isinstance(w, dict)]
        if not writers:
            refuse("missing-writer", "the surface names no writer")
        for writer in writers:
            where = writer.get("path", path)
            if not all(isinstance(writer.get(k), str) and writer[k] for k in ("fn", "actor")):
                refuse("missing-writer", "each writer needs a fn and an actor")
            elif not self.holds(where, writer.get("evidence")):
                refuse("unsupported-writer", f"writer {writer['fn']} cites {writer.get('evidence')!r}, which {where} does not hold")
        for check in site.get("checks") if isinstance(site.get("checks"), list) else []:
            if not self.resolves(check):
                refuse("dangling-check", f"{check} is neither an obligation record nor an inventory test")
        if site.get("writers_at_once") not in ("one", "many"):
            refuse("missing-thread-count", "writers_at_once must be one or many")
        disposition = site.get("disposition")
        if site.get("writers_at_once") == "one" and disposition != "serialized":
            refuse("inferred-thread-count", "one writer at a time holds only for a serialized surface")
        if disposition not in DISPOSITIONS:
            refuse("unknown-disposition", f"disposition {disposition!r} is not one of {list(DISPOSITIONS)}")
        elif disposition == "covered":
            self.judge_covered(site, refuse)
        elif disposition == "serialized":
            if site.get("writers_at_once") != "one":
                refuse("unserialized", "a serialized surface admits one writer at a time")
            if not site.get("argument"):
                refuse("missing-argument", "a serialized surface needs its writer and ownership argument")
            self.judge_serialized(site, path, operations, writers, refuse)
        else:
            obligation = site.get("obligation")
            if not isinstance(obligation, dict) or not all(
                isinstance(obligation.get(k), str) and obligation[k].strip() for k in ("observation", "actor", "fault")
            ):
                refuse("missing-obligation", "a needs-kernel surface names its observation, actor and fault")
            else:
                reported.append({"surface": name, **{k: obligation[k] for k in ("observation", "actor", "fault")}})

    def visible(self, path, header):
        """Return the production files a declaration in `path` with item header `header` reaches: its file and its
        module's descendants when private, its parent module's tree for `pub(super)`, the crate for `pub(crate)`
        or `pub`."""
        crate = re.match(r"crates/[^/]+/src/", path)
        if crate is None:
            return [path]
        module = Path(path)
        tree = module.parent if module.stem in ("mod", "lib", "main") else module.with_suffix("")
        if not re.match(r"\s*pub\b", header):
            return [path, *(f for f in self.expand([str(tree / "**/*.rs")]) if f != path)]
        if re.match(r"\s*pub\s*\(\s*super\s*\)", header):
            return self.expand([str(tree.parent / "**/*.rs")])
        return self.expand([crate.group(0) + "**/*.rs"])

    def atomics(self, words, refuse):
        """Return {field: files it reaches} for the atomics `words` declares, refusing a declaration it cannot read."""
        fields = {}
        for word in words:
            path, name = word.get("path"), word.get("struct") or word.get("static")
            source = self.code(path) if isinstance(path, str) else None
            if source is None or not isinstance(name, str):
                refuse("missing-source", f"words entry {word!r} names no readable declaration")
                continue
            if "static" in word:
                found = re.search(rf"^([ \t]*(?:pub(?:\([^)]*\))?\s+)?)static\s+{re.escape(name)}\s*:\s*(?:[\w:]*::)?Atomic\w+", source, re.M)
                if found is None:
                    refuse("missing-source", f"{path} declares no atomic static {name}")
                else:
                    fields[name] = self.visible(path, found.group(1))
                continue
            found = re.search(rf"^[ \t]*(?:pub(?:\([^)]*\))?\s+)?struct\s+{re.escape(name)}\b[^{{;]*\{{", source, re.M)
            end = None if found is None else closing(source, found.end() - 1)
            if found is None or end is None:
                refuse("missing-source", f"{path} declares no struct {name}")
                continue
            body = source[found.end():end - 1]
            declared = re.findall(r"^([ \t]*(?:pub(?:\([^)]*\))?\s+)?)(\w+)\s*:\s*(?:[\w:]*::)?Atomic\w+", body, re.M)
            if not declared:
                refuse("missing-source", f"struct {name} in {path} holds no atomic field")
            for header, field in declared:
                fields.setdefault(field, []).extend(f for f in self.visible(path, header) if f not in fields.get(field, []))
        return fields

    def judge_serialized(self, site, path, operations, writers, refuse):
        exclusion = site.get("exclusion")
        text = exclusion.get("text") if isinstance(exclusion, dict) else None
        if not isinstance(text, str) or not text.strip() or any(flat(op) in flat(text) for op in operations):
            refuse("inferred-thread-count", "a serialized surface needs an exclusion apart from its own operations")
            return
        where = exclusion.get("path", path)
        source = self.code(where)
        lock = None if source is None else re.search(loose(text), source)
        span = None if lock is None else innermost(self.spans(where), lock.start())
        guard = re.search(r"\blet\s+(?:mut\s+)?(\w+)\s*=", text)
        if (guard is None or guard.group(1) == "_" or lock is None or source is None or span is None
                or not any(kind in text for kind in LOCKS) or span[3] != exclusion.get("fn")):
            refuse("inferred-thread-count",
                   f"the exclusion must take a lock into a named guard inside fn {exclusion.get('fn')!r} of {where}; "
                   "a counter's purpose, its own write or a lock elsewhere admits no writer count")
            return
        region = self.region(source, lock, span, guard.group(1), refuse)
        binding = source[lock.end():region[0]]
        if not re.search(r"\?\s*;\s*$|\.\s*(?:unwrap|expect)\s*\(", binding):
            refuse("inferred-thread-count",
                   f"the statement that binds {guard.group(1)} keeps a refused acquisition; it needs `?`, `unwrap` or `expect`")
            return
        deferred = self.deferred(source, *region)
        root = (where, span[3])
        listed = {(w.get("path", path), w["fn"]): w for w in writers if isinstance(w.get("fn"), str)}
        listed.pop(root, None)

        def guarded(file, enclosing, offset):
            if enclosing is None:
                return False
            if (file, enclosing[3]) == root:
                return region[0] <= offset < region[1] and not any(start <= offset < end for start, end in deferred)
            return (file, enclosing[3]) in listed

        words = site.get("words")
        if not isinstance(words, list) or not words or not all(isinstance(w, dict) for w in words):
            refuse("missing-words", "a serialized surface names the structs or statics that hold its words")
            return
        fields = self.atomics(words, refuse)
        if not fields:
            return
        foreign = {(f.get("path"), f.get("fn"), f.get("word"), f.get("receiver")) for f in site.get("foreign", []) if isinstance(f, dict)}
        used, active, writes = set(), set(), []
        statics = {w["static"] for w in words if isinstance(w.get("static"), str)}
        structs = "|".join(re.escape(w["struct"]) for w in words if isinstance(w.get("struct"), str))
        for field, files in fields.items():
            receiver = r"(?<![\w])" if field in statics else r"\.\s*"
            pattern = (rf"{receiver}{field}\s*\.\s*(?:{WRITES})\s*\(|(?<!&)&(?!&)\s*(?:mut\s+)?(?:\w+\s*\.\s*)+{field}\b(?!\s*[.(\[])"
                       + (rf"|(?<![\w])(?:{structs})\s*\{{" if structs else ""))
            needles = (field, *(w["struct"] for w in words if isinstance(w.get("struct"), str))) if re.fullmatch(r"\w+", field) else None
            for file, enclosing, offset in self.sites(pattern, files, needles):
                if structs and re.match(rf"(?:{structs})\b", self.scanned(file)[offset:]) and \
                        re.search(r"(?:\b(?:struct|impl(?:<[^>]*>)?|for)\s+|&\s*(?:'\w+\s+)?|->\s*|(?<!:):\s*)$", self.scanned(file)[max(0, offset - 40):offset]):
                    continue
                key = next((f for f in foreign if f[:3] == (file, enclosing and enclosing[3], field) and isinstance(f[3], str)
                            and self.receives(file, offset, f[3], field)), None)
                if key:
                    used.add(key)
                    continue
                writes.append((file, offset))
                if not guarded(file, enclosing, offset):
                    refuse("unlisted-writer", f"a write of {field} in {file}, fn {enclosing and enclosing[3]}, lies outside the guarded writers")
                elif enclosing:
                    active.add((file, enclosing[3]))
        for stale in sorted(foreign - used, key=str):
            refuse("stale-foreign", f"foreign entry {stale} matches no write")
        for operation in operations:
            if not re.search(rf"\.\s*(?:{WRITES})\s*\(", operation):
                continue
            found = re.search(loose(operation), self.scanned(path))
            if found is None or not any(file == path and found.start() <= offset < found.end() for file, offset in writes):
                refuse("uncovered-operation", f"{operation!r} writes no word the census reads from its declarations")
        self.via_writers = {w["fn"] for w in listed.values() if w.get("via")}
        for (file, name), writer in listed.items():
            for caller in self.callers(file, name, writer, site.get("reads", []), fields, refuse):
                if not guarded(*caller):
                    refuse("unguarded-caller", f"{caller[0]}, fn {caller[1] and caller[1][3]}, reaches {name} outside the guarded writers")
                elif caller[1]:
                    active.add((caller[0], caller[1][3]))
        for writer in sorted(set(listed) - active, key=str):
            refuse("writer-without-write", f"listed writer {writer[1]} in {writer[0]} neither writes the surface nor calls a writer")

    def receives(self, file, offset, receiver, field):
        """Return whether the write at `offset` is `receiver.field` itself, the receiver's text ending at the field."""
        window = max(0, offset - 80)
        return any(found.start() <= offset - window + 1 and offset - window < found.end()
                   for found in re.finditer(loose(receiver) + rf"\s*\.\s*{field}\b", self.scanned(file)[window:offset + 80]))

    @staticmethod
    def region(source, lock, span, guard, refuse):
        """Return the locked region: from the end of the statement that binds the guard to the guard's release
        or drop, or to the end of the block that binds the guard; any other use of the guard there refuses,
        since it could move the lock away. The statement's own tail, such as a `map_err` handler of a refused
        acquisition, runs without the lock and lies outside the region; a binding with no `;` before its
        block ends leaves the region empty."""
        depth, start = 0, span[2]
        for index in range(lock.end(), span[2]):
            char = source[index]
            depth += {"(": 1, "[": 1, "{": 1, ")": -1, "]": -1, "}": -1}.get(char, 0)
            if depth < 0:
                break
            if char == ";" and depth == 0:
                start = index + 1
                break
        depth, block = 0, span[2]
        for index in range(start, span[2]):
            depth += {"{": 1, "}": -1}.get(source[index], 0)
            if depth < 0:
                block = index
                break
        ending = re.compile(rf"\b{guard}\s*\.\s*release\s*\(|\bdrop\s*\(\s*{guard}\s*\)").search(source, start, block)
        end = ending.start() if ending else block
        if re.search(rf"\b{guard}\b", source[start:end]):
            refuse("moved-guard", f"the guard {guard} is used inside its locked region beyond its release")
        return start, end

    @staticmethod
    def deferred(source, start, end):
        """Return the spans of closure and async bodies between `start` and `end`. A write or call there may run
        after the guard's release, so the locked region excludes it. A closure head `|..|` counts where an
        expression starts: after `(`, `,`, `=`, `=>`, `;`, `{`, `&` or `return`, so `a || b` and an or-pattern are
        none. A block body ends at its closing brace; an expression body runs past any block it holds and ends at a
        `;` or `,` outside brackets or at a bracket or brace that closes its enclosing expression."""
        spans = []
        head = re.compile(r"(?:(?<=[(,;{&])|(?<=[^=<>!]=)|(?<==>)|(?<=\breturn))\s*(?:move\s+)?\|[^|\n]*\|(?:\s*->[^{]*)?"
                          r"|\basync\b(?:\s*move\b)?")
        for found in head.finditer(source, start, end):
            at = found.end()
            while at < end and source[at].isspace():
                at += 1
            if at < end and source[at] == "{":
                spans.append((at, min(closing(source, at) or end, end)))
                continue
            depth, stop, index = 0, end, at
            while index < end:
                char = source[index]
                if char == "{" and depth == 0:
                    index = closing(source, index) or end
                    continue
                if char in "([":
                    depth += 1
                elif char in ")]":
                    depth -= 1
                if depth < 0 or (depth == 0 and char in ";,}"):
                    stop = index
                    break
                index += 1
            spans.append((at, stop))
        return spans

    @cache
    def definition(self, file, name):
        """Return the item header of fn `name` in `file`, its visibility prefix included, or None. A header holds
        `name` itself, so a source that does not hold it is not scanned."""
        source = self.code(file)
        found = None if source is None or isinstance(name, str) and name not in source else re.search(rf"^([ \t]*(?:pub(?:\([^)]*\))?\s+)?)(?:const\s+)?(?:unsafe\s+)?fn\s+{re.escape(name)}\b", source, re.M)
        return None if found is None else found.group(1)

    def callers(self, file, name, writer, reads, fields, refuse):
        """Yield (file, enclosing span, offset) for each call or path reference of the listed writer `name`; a
        writer reached `via` an accessor yields each accessor call chained to it and refuses an untracked use."""
        header = self.definition(file, name)
        if header is None:
            refuse("missing-writer", f"{file} defines no fn {name}")
            return
        accessor = writer.get("via")
        if accessor is None:
            calls = list(self.sites(rf"(?<![\w]){re.escape(name)}\s*\(|(?:::|\.)\s*{re.escape(name)}\b(?!\s*[(.\w\[])",
                                    self.visible(file, header), (name,)))
            if not calls:
                refuse("unreached-writer", f"no call of writer {name} appears where it is visible")
            yield from calls
            return
        reached, seen = False, set()
        for target in self.accessors(accessor):
            for site, enclosing, offset in self.sites(rf"\b{re.escape(accessor)}\s*\(", self.visible(*target), (accessor,)):
                if (site, offset) in seen or enclosing and enclosing[3] == accessor:
                    continue
                seen.add((site, offset))
                text = self.scanned(site)
                depth, index = 0, text.find("(", offset)
                for index in range(index, len(text)):
                    depth += {"(": 1, ")": -1}.get(text[index], 0)
                    if depth == 0:
                        break
                method = re.match(r"\s*\.\s*(\w+)\s*\(", text[index + 1:])
                if method and method.group(1) == name:
                    reached = True
                    yield site, enclosing, offset
                elif not (method and (method.group(1) in self.via_writers or self.reads_only(method.group(1), reads, fields))):
                    refuse("untracked-access", f"{site}, fn {enclosing and enclosing[3]}, uses {accessor} beyond a declared read")
        if not reached:
            refuse("unreached-writer", f"no call of writer {name} through {accessor} appears")

    def reads_only(self, method, reads, fields):
        """Return whether `method` is a declared read whose every definition touches the words only by `load`."""
        if method not in reads:
            return False
        bodies = [self.scanned(f)[start:end] for f, _ in self.accessors(method) for start, _, end, n in self.spans(f) if n == method]
        touch = rf"\b(?:{'|'.join(map(re.escape, fields))})\b(?!\s*\.\s*load\s*\()"
        return bool(bodies) and not any(re.search(touch, body) or re.search(r"\bself\s*\.\s*\w+\s*\(", body) for body in bodies)

    @cache
    def accessors(self, name):
        """Return (file, header) for each production definition of fn `name` in the crate."""
        return [(file, header) for file in self.expand(["crates/kestrike/src/**/*.rs"])
                if (header := self.definition(file, name)) is not None]

    @staticmethod
    def names(site):
        """Return the identifiers that tie a witness to its surface: each writer's fn and each operation's names."""
        names = {w["fn"].split("::")[-1] for w in site.get("writers", []) if isinstance(w, dict) and isinstance(w.get("fn"), str)}
        for operation in site.get("operations", []):
            names.update(re.findall(r"\.\s*([a-z_]\w{3,})\b", str(operation)))
        return names - COMMON

    def judge_covered(self, site, refuse):
        checks = site.get("checks")
        if not isinstance(checks, list) or not checks:
            refuse("missing-check", "a covered surface names its checks")
            return
        witness = site.get("witness")
        if not isinstance(witness, dict) or witness.get("kind") not in WITNESS_KINDS:
            refuse("missing-witness", "a covered surface needs a fault or state witness")
            return
        check, test = witness.get("check"), witness.get("test")
        if check not in checks:
            refuse("irrelevant-witness", f"the witness check {check!r} is not among the surface's checks")
            return
        if not self.resolves(check):
            return
        body = self.witness_text(check, test)
        observes = witness.get("observes")
        if body is None:
            refuse("irrelevant-witness", f"{check} runs no test {test!r}")
        elif not body or not isinstance(observes, str) or flat(observes) not in flat(body) \
                or flat(code(observes)) not in flat(code(body)) or not whole_assertion(code(observes)):
            refuse("irrelevant-witness", f"{test} asserts no {observes!r}")
        elif not any(re.search(rf"\b{re.escape(name)}\b", body) for name in self.names(site)):
            refuse("irrelevant-witness", f"{test} names none of the surface's writers or operations")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Validate the atomic-site census.")
    parser.add_argument("command", choices=["check"])
    parser.add_argument("--census", type=Path, default=CENSUS)
    args = parser.parse_args(argv)
    try:
        census = json.loads(args.census.read_text(encoding="utf-8"))
        catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
        inventory = json.loads(INVENTORY.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        print(json.dumps({"command": "check", "error": str(error)}))
        return 2
    refusals, verdicts, reported = Census(catalog, inventory, receipts().control_text).judge(census)
    print(json.dumps({"command": "check", "refusals": refusals, "dispositions": verdicts,
                      "reported": reported, "credited": not refusals and not reported}, indent=1))
    return 1 if refusals else 0


if __name__ == "__main__":
    sys.exit(main())
