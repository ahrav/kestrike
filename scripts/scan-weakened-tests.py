#!/usr/bin/env python3
"""Report the changes between two commits that weaken a Rust test or its budget.

Usage:
  scan-weakened-tests.py --base REV [--head REV]

The head defaults to `HEAD`. The scanner reads Git commits and blobs only, so
the working tree, the index and the worktree list never change its report and
stay as they were. It compares each changed file's blob at the head with its
blob at the merge base of the base and the head, so the report holds what the
commits of `base..head` changed and a change made only on the base side is no
finding. It sorts each match into one of five classes:

- `ignore-existing` blocks: a fn of the base file that carries no plain
  `#[ignore..]` carries at the head an ignore attribute, `#[ignore..]` or
  `#[cfg_attr(.., ignore..)]`, whose text the base fn lacks, so a conditional
  ignore widened to a plain one and one whose condition changes in any way
  both count. The texts compare with whitespace and each `ignore = ".."` reason
  dropped, so a reason or a line wrap changes nothing; a fn the base already
  ignores plainly reports nothing.
  The ignore attribute is the hook's `IGNORE` expression and its fn the first
  `FUNCTION` match after it, both from `scripts/pre-push-checks.py`, matched in
  text with comments, nested ones included, and literal contents blanked by
  `code` from `scripts/classify-atomics.py`. Fns match by the names of their
  enclosing inline modules, a `{}` for each other enclosing brace block, and
  their own name without an `r#` prefix; same-named fns of one scope pair in
  order.
- `budget-lowered` blocks: a declared test budget decreases. In
  `scripts/test-inventory.json` these are `seeds`, `seconds` and `executions`,
  `miri_sweep.seeds` among them, and each `depth: N`, `actions N` and
  `cycles N` inside a `bound` or `member` text, counts in one text pairing by
  word in order. A count there is the digits followed by whitespace, `:`, `,`,
  `;`, `$`, `)` or the end of the text; a count followed by anything else names
  no count. A `seeds`, `seconds` or `executions` field or a count of a `bound`
  or `member` text that leaves an object that remains reads as `absent`. A list
  item that holds an `id` matches by that `id` and any other item by position,
  so reordered rows pair by `id`. In Rust source these are
  `preemption_bound = Some(N)`, `max_branches = N`, and a `const` whose name
  ends in `SEEDS`, `ROOTS` or `PREEMPTION_BOUND`, compared by its integer value
  or by the length of its integer array type, each only where N is a whole
  decimal literal that whitespace and same-line block comments alone separate
  from its `)`, `;`, `,` or `]`. A `preemption_bound = Some(NAME)` reads the
  integer that the file's `const NAME` declares, at the base for a removed line
  and at the head for an added one, where every declaration of that name in
  the file gives one such literal. A `preemption_bound` set from a fn
  parameter, from a `const` of another file or from any other expression
  matches none of them, and neither does a `max_branches` set from a name.
- `timeout-raised` reports: `timeout-minutes: N`, `deadline Nm` or
  `timeout .. Nm` rises in `.github/workflows/agent-checks.yml` or
  `scripts/rust-lane.sh`, or an inventory `deadline_seconds` or
  `member_drain_seconds` rises.
- `assertions-removed` reports: the diff of a Rust file, a deleted one
  included, removes more lines holding `assert*!` than it adds.
- `ignore-new` reports: a fn whose module path and name the base file lacks
  arrives ignored. A renamed ignored test reads as one.

A Rust or workflow budget is a line pattern. One hunk of the Myers diff pairs a
removed line and an added line when the text up to the end of the pattern's
match is equal on both lines after each run of digits and underscores is
replaced; several lines with one such text pair in order. A raised Rust
budget, a lowered timeout, and an added or removed line with no pair are no
line finding, and an added or removed inventory row is no inventory finding.
The patterns are text matches: a weakening they do not match is not reported,
and the report claims nothing about it.

Each finding prints one line on stdout, `EFFECT CLASS:PATH NAME: OLD -> NEW`,
and the whole report is appended to the file `GITHUB_STEP_SUMMARY` names when
it is set. `CLASS:PATH` is the finding's key. A commit-message line
`Weakens-Test: KEY: REASON` in `base..head`, with a reason that holds a
non-whitespace character, acknowledges every blocking finding under that key;
the report lists each with the reason. A line belongs to the longest key it
starts with. An empty range prints nothing.

Exit 0 passes, 1 is a blocking finding without an acknowledgement, 2 is a Git
failure, a sibling script that cannot be loaded, an unreadable base or head, a
base and head that share no history, a present test inventory that is empty,
not a regular file, unreadable, not JSON, nested past the recursion limit,
holds a key or `id` that could name another path or holds values that share a
path, a changed path name or a scanned blob, diff or commit message that is not
UTF-8, a changed Rust path that holds a newline, or an unwritable step summary.
A report character the output encoding lacks prints escaped.
"""

import argparse
import bisect
import importlib.util
import io
import json
import os
import re
import subprocess
import sys
from collections import deque
from pathlib import Path


def _load(name):
    """Load the sibling script `name` as a module; exit 2 when it cannot be loaded."""
    path = Path(__file__).with_name(name)
    try:
        spec = importlib.util.spec_from_file_location(path.stem.replace("-", "_"), path)
        if spec is None or spec.loader is None:
            raise ImportError("no loader for the path")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
    except Exception as error:
        print(f"scan-weakened-tests: {name} cannot be loaded: {error}", file=sys.stderr)
        raise SystemExit(2) from error
    return module


# The scan leaves the checkout as it was, so loading the siblings writes no bytecode cache beside them.
sys.dont_write_bytecode = True
hook = _load("pre-push-checks.py")
atomics = _load("classify-atomics.py")
BLOCKING = ("ignore-existing", "budget-lowered")
INVENTORY = "scripts/test-inventory.json"
TIMEOUT_FILES = (".github/workflows/agent-checks.yml", "scripts/rust-lane.sh")
NUMBER = r"(?P<value>\d[\d_]*)"
# Whitespace and same-line block comments may sit between a literal and its terminator.
TRIVIA = r"(?:\s|/\*.*?\*/)*"
INTEGER_TYPE = r"[iu](?:8|16|32|64|128|size)"
RUST_BUDGETS = (
    re.compile(rf"\b(?P<name>preemption_bound)\s*=\s*Some\(\s*{NUMBER}{TRIVIA}\)"),
    re.compile(rf"\b(?P<name>max_branches)\s*=\s*{NUMBER}(?={TRIVIA}[;,])"),
    re.compile(rf"\bconst\s+(?P<name>\w*(?:SEEDS|ROOTS|PREEMPTION_BOUND))\s*:\s*"
               rf"(?:{INTEGER_TYPE}\s*=\s*|\[\s*{INTEGER_TYPE}\s*;\s*){NUMBER}(?={TRIVIA}[;\]])"),
)
CONSTANT = re.compile(rf"\bconst\s+(?P<name>\w+)\s*:(?:\s*{INTEGER_TYPE}\s*=\s*{NUMBER}(?={TRIVIA};))?")
NAMED_BOUND = re.compile(r"(?P<site>\bpreemption_bound\s*=\s*Some\(\s*)(?P<name>[A-Za-z_]\w*)(?=\s*\))")
REASON = re.compile(r'\bignore\s*=\s*"(?:\\.|[^"\\])*"')
TIMEOUTS = (
    re.compile(rf"\b(?P<name>timeout-minutes):\s*{NUMBER}"),
    re.compile(rf"\b(?P<name>deadline)\s+{NUMBER}m\b"),
    re.compile(rf"\b(?P<name>timeout)\b.*?\s{NUMBER}m\b"),
)
INVENTORY_BUDGETS = ("seeds", "seconds", "executions")
INVENTORY_TEXTS = ("bound", "member")
INVENTORY_TEXT_BUDGET = re.compile(r"\b(?P<name>depth:|actions|cycles) (?P<value>\d+)(?=[\s:,;$)]|\Z)")
INVENTORY_TIMEOUTS = ("deadline_seconds", "member_drain_seconds")
ASSERT = re.compile(r"\bassert\w*!")
DIGITS = re.compile(r"\d[\d_]*")
HUNK = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")
# Batching pathspecs reduces the risk of exceeding the operating system's argument-size limit.
DIFF_BATCH = 256
ALIASING = re.compile(r"[.\[\]]")
SCOPE = re.compile(r"\bmod\s+(?:r#)?(?P<module>\w+)\s*\{|[{}]")


def resolve(rev):
    return hook.git("rev-parse", "--verify", "--end-of-options", f"{rev}^{{commit}}").strip()


def git_text(*args):
    """Return the stdout of `git args` decoded as strict UTF-8, its lines ending at LF only.

    Without GIT_ICASE_PATHSPECS or GIT_GLOB_PATHSPECS a pathspec names one path, and without GIT_DIFF_OPTS a
    diff keeps -U0. Output that is not UTF-8 raises `GitError` naming the command.
    """
    label = "git " + " ".join(os.fsdecode(arg) for arg in args)
    result = subprocess.run(("git", *args), capture_output=True, env={
        k: v for k, v in os.environ.items()
        if k not in ("GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS", "GIT_DIFF_OPTS")})
    if result.returncode != 0:
        raise hook.GitError(f"{label}: {result.stderr.decode(errors='replace').strip()}")
    try:
        return result.stdout.decode()
    except UnicodeDecodeError as error:
        raise hook.GitError(f"{label}: {error}") from error


def patch(base, head, paths):
    """Return the zero-context diff of paths between base and head, one `diff --git` section per change."""
    # The pathspec is UTF-8 bytes, so a non-ASCII path names itself under any locale. The Myers algorithm and
    # the indent heuristic are fixed, so `diff.algorithm` and `diff.indentHeuristic` cannot regroup the
    # removed and added lines.
    # Fixed prefixes let `path_hunks` compare unquoted headers with its expected `diff --git a/{path} b/{path}` form.
    return git_text("--no-literal-pathspecs", "-c", "core.quotePath=false", "diff", "--no-relative",
                    "--no-renames", "--no-color", "--no-ext-diff", "--no-textconv", "--text",
                    "--diff-algorithm=myers", "--indent-heuristic", "-U0", "--inter-hunk-context=0",
                    "--src-prefix=a/", "--dst-prefix=b/", base, head, "--",
                    *(f":(top,literal){path}".encode() for path in paths))


def hunks(lines):
    """Yield each hunk of one path's diff lines as (removed lines, added (line number, text) pairs)."""
    removed, added, number = [], [], None
    for line in lines:
        found = HUNK.match(line)
        if found:
            if removed or added:
                yield removed, added
            removed, added, number = [], [], int(found.group(1))
        elif number is not None and line.startswith("-"):
            removed.append(line[1:])
        elif number is not None and line.startswith("+"):
            added.append((number, line[1:]))
            number += 1
    if removed or added:
        yield removed, added


def path_hunks(base, head, paths):
    """Map each of paths, in the order Git lists changed paths, to the hunks of its diff.

    One diff reads up to `DIFF_BATCH` paths. Its sections are assigned in order only when every `diff --git`
    header names the expected path unquoted. Any other batch holds a name Git quotes or a path that prints
    two sections because it changes between a file and a link, and each of its paths gets its own diff.
    """
    found = {}
    for start in range(0, len(paths), DIFF_BATCH):
        batch = paths[start:start + DIFF_BATCH]
        headers, sections = [], []
        for line in patch(base, head, batch).split("\n"):
            if line.startswith("diff --git "):
                headers.append(line)
                sections.append([])
            elif sections:
                sections[-1].append(line)
        if headers != [f"diff --git a/{path} b/{path}" for path in batch]:
            sections = [patch(base, head, [path]).split("\n") for path in batch]
        found.update((path, list(hunks(lines))) for path, lines in zip(batch, sections))
    return found


def keyed(pattern, text):
    """Yield each match of pattern in text with its pairing key: the text through the match, digits replaced."""
    for match in pattern.finditer(text):
        yield DIGITS.sub("#", text[:match.end()]), match


def integer(match):
    return int(match.group("value").replace("_", ""))


def paired(old, new):
    """Pair each new (key, item) with the earliest unpaired old item of its key, in order.

    Return the (old item, new item) pairs and the (key, old item) entries left unpaired.
    """
    queues = {}
    for key, item in old:
        queues.setdefault(key, deque()).append(item)
    pairs = [(queues[key].popleft(), item) for key, item in new if queues.get(key)]
    return pairs, [(key, item) for key, queue in queues.items() for item in queue]


def line_changes(changes, patterns):
    """Return (name, old, new) for each budget line of the hunks that pairs with a removed line."""
    found = []
    for removed, added in changes:
        for pattern in patterns:
            pairs, _ = paired(((key, match) for text in removed for key, match in keyed(pattern, text)),
                              ((key, (number, match)) for number, text in added
                               for key, match in keyed(pattern, text)))
            found += [(f"{match.group('name')} at line {number}", integer(before), integer(match))
                      for before, (number, match) in pairs]
    return found


def constants(text):
    """Map each `const` name of text to its integer literal, where every declaration of the name gives one.

    Declarations are read with comments and literal contents blanked, so a commented-out one declares nothing.
    """
    values = {}
    for match in CONSTANT.finditer(atomics.code(text)):
        values.setdefault(match.group("name"), set()).add(match.group("value"))
    return {name: found.pop() for name, found in values.items() if len(found) == 1 and None not in found}


def named_bounds(changes, old, new):
    """Return the hunks with each `preemption_bound = Some(NAME)` holding the integer its file declares for NAME.

    A removed line reads the `constants` of the base text `old` and an added line those of the head text `new`.
    A name with no such integer stays as written and matches no budget pattern.
    """
    if not any(NAMED_BOUND.search(text) for removed, added in changes for text in (*removed, *(t for _, t in added))):
        return changes
    before, after = constants(old), constants(new)

    def valued(text, values):
        return NAMED_BOUND.sub(lambda m: m.group("site") + values.get(m.group("name"), m.group("name")), text)

    return [([valued(text, before) for text in removed], [(number, valued(text, after)) for number, text in added])
            for removed, added in changes]


def declarations(text):
    """Map each fn name of text to one ignore-attribute list per declaration of that name, in order.

    A name is `scope::name`, the scopes being the enclosing inline modules and a `{}` for each other
    enclosing brace block. Matches run over text with comments and literal contents blanked, offsets kept,
    so a word or an attribute inside them names no fn and ignores none. Each attribute belongs to the first
    fn after it.
    """
    view = atomics.code(text)
    scopes, path, functions = SCOPE.finditer(view), "", []
    # One entry per open brace: a module's name, or `{}` for any other block, so a method or a nested fn
    # never shares the name of a fn at module level.
    stack, scope = [], next(scopes, None)
    for match in hook.FUNCTION.finditer(view):
        while scope and scope.end() <= match.start():
            if scope.group() != "}":
                stack.append(scope.group("module") or "{}")
            elif stack:
                stack.pop()
            path, scope = "::".join(stack), next(scopes, None)
        name = match.group().split()[-1].removeprefix("r#")
        functions.append((match.end(), f"{path}::{name}" if path else name, []))
    ends = [end for end, _, _ in functions]
    for attribute in hook.IGNORE.finditer(view):
        index = bisect.bisect_right(ends, attribute.end())
        if index < len(functions):
            functions[index][2].append(" ".join(text[attribute.start():attribute.end()].split()))
    found = {}
    for _, name, attributes in functions:
        found.setdefault(name, []).append(attributes)
    return found


def plain(attributes):
    return sum(1 for attribute in attributes if attribute.startswith("#[ignore"))


def conditions(attributes):
    """Return the set of the attribute texts with each ignore reason and all whitespace dropped."""
    return {"".join(REASON.sub("ignore", attribute).split()) for attribute in attributes}


def budget(value):
    """Tell whether an inventory value is an integer count; a JSON boolean is not one."""
    return isinstance(value, int) and not isinstance(value, bool)


def flatten(node, path, leaves, owners):
    """Record each scalar of an inventory document under its path, and each object's path in owners.

    A list item that holds a string `id` takes that `id` in its path, any other item its position. A key or
    `id` holding `.`, `[` or `]`, an `id` of digits only, and two scalars that render to one path could each
    stand for another path, so they raise `GitError`.
    """
    if isinstance(node, dict):
        owners.add(path)
        for key, value in node.items():
            if ALIASING.search(key):
                raise hook.GitError(f"{INVENTORY}: the key {key!r} under {path or 'the root'} could name another path")
            flatten(value, f"{path}.{key}" if path else key, leaves, owners)
    elif isinstance(node, list):
        for index, value in enumerate(node):
            item = value.get("id") if isinstance(value, dict) else None
            if isinstance(item, str) and (ALIASING.search(item) or item.isdigit()):
                raise hook.GitError(f"{INVENTORY}: the id {item!r} under {path} could name another path")
            flatten(value, f"{path}[{item if isinstance(item, str) else index}]", leaves, owners)
    elif path in leaves:
        raise hook.GitError(f"{INVENTORY}: two values share the path {path}")
    else:
        leaves[path] = node


def inventory_changes(old_text, new_text):
    """Return (class, name, old, new) for each inventory budget that fell or went absent and timeout that rose."""
    documents = []
    for text in (old_text, new_text):
        leaves, owners = {}, set()
        if text:
            try:
                flatten(json.loads(text), "", leaves, owners)
            except (ValueError, RecursionError) as error:
                raise hook.GitError(f"{INVENTORY}: {error}") from error
        documents.append((leaves, owners))
    (old, _), (new, kept) = documents
    found = []
    for path, before in old.items():
        owner, _, field = path.rpartition(".")
        after, dropped = new.get(path), path not in new and owner in kept
        numbers = budget(before) and budget(after)
        if field in INVENTORY_BUDGETS and budget(before) and dropped:
            found.append(("budget-lowered", path, before, "absent"))
        elif field in INVENTORY_BUDGETS and numbers and after < before:
            found.append(("budget-lowered", path, before, after))
        elif field in INVENTORY_TIMEOUTS and numbers and after > before:
            found.append(("timeout-raised", path, before, after))
        elif field in INVENTORY_TEXTS and isinstance(before, str) and (isinstance(after, str) or dropped):
            pairs, unpaired = paired(
                ((match.group("name"), match) for match in INVENTORY_TEXT_BUDGET.finditer(before)),
                ((match.group("name"), match) for match in INVENTORY_TEXT_BUDGET.finditer(after or "")))
            found += [("budget-lowered", f"{path} {match.group('name').rstrip(':')}", integer(earlier),
                       integer(match)) for earlier, match in pairs if integer(match) < integer(earlier)]
            found += [("budget-lowered", f"{path} {name.rstrip(':')}", integer(earlier), "absent")
                      for name, earlier in unpaired]
    return found


def inventory_text(rev):
    """Return the inventory text at rev, or "" where rev's tree holds no inventory.

    A present inventory that is not a regular file, is empty or cannot be read raises `GitError`.
    """
    entry = git_text("ls-tree", "-z", "--full-tree", rev, "--", INVENTORY)
    if not entry:
        return ""
    if entry.split()[0] not in ("100644", "100755"):
        raise hook.GitError(f"{INVENTORY} at {rev[:12]} is not a file")
    (text,) = hook.blob_texts([f"{rev}:{INVENTORY}"], errors="strict")
    if not text:
        raise hook.GitError(f"{INVENTORY} at {rev[:12]} is empty or unreadable")
    return text


def findings(base, head):
    """Return (class, path, name, old, new) for every match of the classes in the header."""
    paths = [p for p in hook.git("diff", "--no-relative", "--no-renames", "--name-only", "-z", base, head)
             .split("\0") if p]
    rust = [p for p in paths if p.endswith(".rs")]
    if any("\n" in p for p in rust):
        raise hook.GitError("a changed Rust path holds a newline, which the blob reader cannot name")
    texts = hook.blob_texts([f"{commit}:{path}" for path in rust for commit in (base, head)],
                            errors="strict") if rust else []
    diffs = path_hunks(base, head, [p for p in paths if p.endswith(".rs") or p in TIMEOUT_FILES])
    found = []
    for path, old, new in zip(rust, texts[::2], texts[1::2]):
        after = declarations(new) if "ignore" in new else {}
        before = declarations(old) if any(any(each) for each in after.values()) else {}
        for name, heads in after.items():
            bases = before.get(name, [])
            for index, attributes in enumerate(heads):
                if index >= len(bases):
                    if attributes:
                        found.append(("ignore-new", path, name, "absent", "; ".join(attributes)))
                elif not plain(bases[index]) and not conditions(attributes) <= conditions(bases[index]):
                    found.append(("ignore-existing", path, name, "; ".join(bases[index]) or "not ignored",
                                  "; ".join(attributes)))
        changes = diffs[path]
        found += [("budget-lowered", path, name, old_value, new_value)
                  for name, old_value, new_value in line_changes(named_bounds(changes, old, new), RUST_BUDGETS)
                  if new_value < old_value]
        asserts_removed = sum(1 for lines, _ in changes for text in lines if ASSERT.search(text))
        asserts_added = sum(1 for _, lines in changes for _, text in lines if ASSERT.search(text))
        if asserts_removed > asserts_added:
            found.append(("assertions-removed", path, "assert lines", f"{asserts_removed} removed",
                          f"{asserts_added} added"))
    for path in (p for p in TIMEOUT_FILES if p in paths):
        found += [("timeout-raised", path, name, old_value, new_value)
                  for name, old_value, new_value in line_changes(diffs[path], TIMEOUTS)
                  if new_value > old_value]
    if INVENTORY in paths:
        found += [(kind, INVENTORY, *rest) for kind, *rest in inventory_changes(inventory_text(base),
                                                                                  inventory_text(head))]
    return found


def acknowledgements(base, head, keys):
    """Return the reason of the first `Weakens-Test: KEY: REASON` line in base..head for each key.

    A line belongs to the longest key whose prefix it starts with, so it acknowledges one key at most.
    """
    if not keys:
        return {}
    prefixes, reasons = {f"Weakens-Test: {key}: ": key for key in keys}, {}
    for line in git_text("log", "--encoding=UTF-8", "--format=%B", f"{base}..{head}").split("\n"):
        if not line.startswith("Weakens-Test: "):
            continue
        matches = [prefix for prefix in prefixes if line.startswith(prefix)]
        if matches:
            prefix = max(matches, key=len)
            reason = line[len(prefix):].strip()
            if reason:
                reasons.setdefault(prefixes[prefix], reason)
    return reasons


def main(argv):
    parser = argparse.ArgumentParser(description="Report changes that weaken a Rust test or its budget.")
    parser.add_argument("--base", required=True)
    parser.add_argument("--head", default="HEAD")
    args = parser.parse_args(argv)
    try:
        base, head = resolve(args.base), resolve(args.head)
        if hook.git("rev-list", "--count", f"{base}..{head}").strip() == "0":
            return 0
        # Comparing `head` with the merge base isolates the net changes on the `head` side of the divergence.
        fork = hook.merge_base(base, head)
        if fork is None:
            raise hook.GitError(f"{base[:12]} and {head[:12]} share no history")
        base = fork
        found = [(f"{kind}:{path}", kind in BLOCKING, name, old, new) for kind, path, name, old, new
                 in findings(base, head)]
        reasons = acknowledgements(base, head, {key for key, blocking, *_ in found if blocking})
    except (hook.GitError, ValueError, OSError) as error:
        print(f"scan-weakened-tests: {error}", file=sys.stderr)
        return 2
    report, unacknowledged = [], []
    for key, blocking, name, old, new in found:
        line = f"{key} {name}: {old} -> {new}"
        if not blocking:
            report.append(f"reports {line}")
        elif key in reasons:
            report.append(f"acknowledged {line} (Weakens-Test: {reasons[key]})")
        else:
            report.append(f"blocks {line}")
            if key not in unacknowledged:
                unacknowledged.append(key)
    if report:
        text = "".join(f"{line}\n" for line in report)
        # A character the output encoding lacks prints escaped, so the exit code depends on the findings only.
        stdout = io.TextIOWrapper(sys.stdout.buffer, encoding=sys.stdout.encoding, errors="backslashreplace",
                                  write_through=True)
        stdout.write(text)
        stdout.detach()
        summary = os.environ.get("GITHUB_STEP_SUMMARY")
        if summary:
            try:
                with Path(summary).open("a", encoding="utf-8", errors="backslashreplace") as stream:
                    stream.write(f"Weakened-test scan of {base[:12]}..{head[:12]}:\n\n```text\n{text}```\n")
            except OSError as error:
                print(f"scan-weakened-tests: step summary: {error}", file=sys.stderr)
                return 2
    for key in unacknowledged:
        print(f"scan-weakened-tests: {key} blocks; acknowledge it with a commit-message line "
              f"in {base[:12]}..{head[:12]}: Weakens-Test: {key}: <reason>", file=sys.stderr)
    return 1 if unacknowledged else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
