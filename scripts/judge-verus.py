#!/usr/bin/env python3
"""Credit declared items from a complete, whole-package run of the pinned Verus.

Usage:
  python3 scripts/judge-verus.py command
  python3 scripts/judge-verus.py identity --verus PATH --evidence DIR
  python3 scripts/judge-verus.py judge --evidence DIR [--revision SHA]
  python3 scripts/judge-verus.py reconcile

`verification/verus/expected.json` declares the tool pins, command, verified
count, production sources and items eligible for credit. `command`,
`identity`, `judge` and `reconcile` check the declaration: a JSON object whose
`verus` pins are strings, whose `tests` is a map, whose `sources` is a list of
paths and whose `verified` is a positive integer. Its `command` is a list of
UTF-8 strings that starts with `verus`, holds `--no-cheating` and has no
argument with a NUL or line break. Each other argument that starts with `-` is
the flag `--compile` or one of `--crate-type`, `--crate-name`, `--edition`,
`--emit` and `--out-dir` with its value after `=` or in the next argument. A
value never starts with `-`, so Verus reads `--no-cheating` as a flag, and the
one remaining argument is the operand `src/lib.rs`. Any other option, such as
`--verify-module`, `--no-verify` or `--log-dir`, refuses the declaration.
`command` prints one argument per line to standard output and exits 0; for a
refused declaration it prints the reason to standard error, nothing to
standard output, and exits 2. The lane runs `command` before `identity`, so a
refused declaration fails before an `identity` refusal reinstalls the cached
release.
`identity` hashes the install tree before running its programs. A matching
digest allows the version checks; the recorded Verus release, commit,
platform, toolchain, Z3 version and `VERUS_Z3_PATH` must identify the pinned
tools and the bundled solver. `identity` exits 0 for the pinned install and 2
otherwise.

`reconcile` checks the trust inventory against the current sources and exits 0
when it matches or 2 otherwise. In `inventory.json`, each audited source has
one reviewed digest and at least one row naming it. Rows hold string `item`,
`class` and `source` fields and an optional string `text`, and classify items
as verified, trusted, excluded or tested. The scan covers the package Rust
sources and declared production sources, read as UTF-8 with each CRLF read as
LF and comments blanked; a block comment that never closes refuses its file. A
strict form is a detected spelling of `admit`, `assume`, `external_body`,
`assume_specification`, `assume_termination`,
`externals_available_without_declaration`, `axiom fn` or
`external_fn_specification`, the names strict mode rejects in the forms that
grant an assumption. A strict form fails even inside a trusted quote, which
includes a `deny` attribute naming one of them. Each remaining escape must fit
within a trusted quote with one non-overlapping match in its source.

The package root holds only attributes and `pub mod NAME;` declarations, each
name declared once. A root attribute holds no character literal or bracket
outside a string, and a crate attribute names no `path`, `cfg` or `cfg_attr`.
A module's one `#[path = "..."]` attribute selects its file; a module without
one resolves to `NAME.rs` or `NAME/mod.rs` beside the root, and a module with
both files refuses the root. A module attribute that names `path`, `cfg` or
`cfg_attr` in any other form refuses the root. For each credited
`module::name`, the module's file must be a scanned source whose
comment-blanked text holds `fn`, whitespace, the identifier `name` and then
`(` or `<`. This establishes a text match: a string literal or a nested module
in that file can satisfy it, and it does not show that Verus checked the
function. The verified count applies to the package.

`judge` requires a matching identity, a passing inventory check and a
`verus.argv` whose bytes are the declared command, one argument and a line
feed each. `verus.argv`, `tree.txt` and `pins.txt` must be UTF-8. Verus must
exit 0 and print one results line with the declared count, written in ASCII
digits, and zero errors. A malformed results line fails verification first;
otherwise a line starting with `error` fails verification and stays the reason
when the run also prints several well-formed results lines. The prerequisites
parsed from `verus.d` must include the package root, and those of `verus.d`
and `cargo.d` must include every declared production source. Every `.rs` path
parsed from `verus.d` must belong to the scan. The judge rejects a line in the
ordinary build's `tree.txt` that starts with `vstd` or with `verus_` plus one
or more word characters when a space follows the name.

After deriving a verdict and its receipt, `judge` writes `report.json` and
`receipt.json` in the evidence directory. The receipt lists all declared items
for credit and zero executions for a refusal. A refusal receipt binds each
readable input file inside the repository. Reported verdicts return 0 for
credit, 1 for verification failure and 2 for tool failure or drift. After the
declaration, identity and command checks pass, a recorded verifier exit of
124, 130 or 143 returns 3. An identity record nested past the parser's depth
is a tool failure. An input the receipt cannot hash or read returns 2 without
a report, and a report or receipt the judge cannot write returns 2.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = ROOT / "verification/verus"
EXPECTED = PACKAGE / "expected.json"
INVENTORY = PACKAGE / "inventory.json"
# A `#[path]` attribute names a production file outside the package, so it resolves from the committed package
# source directory even when a copy of the package sources is checked.
DECLARED_SRC = PACKAGE / "src"


def load_rc11():
    spec = importlib.util.spec_from_file_location("judge_rc11", ROOT / "scripts/judge-rc11.py")
    if spec is None or spec.loader is None:
        raise SystemExit("judge-verus: scripts/judge-rc11.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


rc11 = load_rc11()
Refusal, sha256, read_json, git_revision = rc11.Refusal, rc11.sha256, rc11.read_json, rc11.git_revision
INTERRUPTED = rc11.INTERRUPTED
CREDITED, FAILED, TOOL_FAILURE, INCOMPLETE = rc11.CREDITED, rc11.MISMATCH, rc11.TOOL_FAILURE, rc11.INCOMPLETE
VERDICTS = {CREDITED: "credited", FAILED: "verification failure", TOOL_FAILURE: "tool failure", INCOMPLETE: "incomplete"}
ESCAPES = re.compile(
    r"\b(admit|assume|assume_termination|external_body|exec_spec_unverified)\s*[!(\[\])]|\bassume_specification\b"
    r"|\bverifier\s*(?:::|\()\s*external|\bverus_verify\s*\(\s*external|\baxiom\s+fn\b"
    r"|\binline_air_stmt\b|\bexternals_available_without_declaration\b|\bnot\s*\(\s*verus_keep_ghost\b"
)
# `STRICT_FORM` classifies the full identifier starting at an `ESCAPES` match. Its optional prefix covers each
# `ESCAPES` alternative that begins before the form name.
STRICT_FORM = re.compile(
    r"(?:(?:verifier\s*(?:::|\()|verus_verify\s*\()\s*)?"
    r"(?:admit|assume|external_body|assume_specification|assume_termination|externals_available_without_declaration"
    r"|axiom\s+fn|external_fn_specification)\b"
)
RESULTS = re.compile(r"^verification results:: (\d+) verified, (\d+) errors$")
# The package root is read with its literals masked, so a bracket or keyword inside a literal ends no item.
ROOT_ITEM = re.compile(r"\s*(?:(#!?\[[^\[\]]*\])|pub\s+mod\s+(\w+)\s*;)")
CONDITION = re.compile(r"\b(?:path|cfg|cfg_attr)\b")
# Verus treats the argument after a bare value-taking option as its value, even when that argument looks like a flag,
# so the declaration may use only these options, and `True` marks one that takes a value.
OPTIONS = {"--crate-type": True, "--crate-name": True, "--edition": True, "--emit": True, "--out-dir": True,
           "--compile": False, "--no-cheating": False}
PINS = ("install", "version", "commit", "toolchain", "platform", "z3")


def code_text(text, path):
    """Return `text` with every comment blanked to spaces, keeping newlines, so offsets and line numbers still index the source.

    A block comment that never closes refuses `path`, so no unread tail of the file reaches a check.
    """
    pieces, start = [], 0
    for kind, begin, end in rc11.rust_lexemes(text):
        if kind == "unclosed":
            number = text.count("\n", 0, begin) + 1
            raise Refusal(TOOL_FAILURE, f"{path}:{number} opens a block comment that never closes")
        if kind == "comment":
            pieces += [text[start:begin], re.sub(r"[^\n]", " ", text[begin:end])]
            start = end
    return "".join([*pieces, text[start:]])


def masked_literals(code):
    """Return comment-blanked `code` with each string and char literal blanked after its first character."""
    pieces, start = [], 0
    for _, begin, end in rc11.rust_lexemes(code):
        pieces += [code[start:begin + 1], re.sub(r"[^\n]", " ", code[begin + 1:end])]
        start = end
    return "".join([*pieces, code[start:]])


def utf8_text(path):
    """Return a file's bytes decoded as UTF-8, refusing the file when they are not."""
    try:
        return Path(path).read_bytes().decode("utf-8")
    except UnicodeDecodeError as error:
        raise Refusal(TOOL_FAILURE, f"{path} is not UTF-8: {error}") from error


def source_text(path):
    """Return a Rust source's text with each CRLF read as LF, as rustc reads it; a lone carriage return stays text."""
    return utf8_text(path).replace("\r\n", "\n")


def package_sources():
    return sorted((PACKAGE / "src").rglob("*.rs"))


def source_names(expected):
    """Return the declaration's production source names, or None when `sources` is not a list of paths."""
    names = expected.get("sources") if isinstance(expected, dict) else None
    return names if isinstance(names, list) and all(isinstance(name, str) and "\0" not in name for name in names) else None


def scanned_sources(expected):
    """Return the files the escape scan reads and the receipt binds: every package source and each declared production source.

    A declaration without a list of source paths earns no credit, and its scan holds the package sources alone.
    """
    return [*package_sources(), *(ROOT / name for name in sorted(source_names(expected) or []))]


def committed():
    """Return the committed files a verdict depends on: the declaration, the inventory and the scanned sources."""
    return [EXPECTED, INVENTORY, *scanned_sources(read_json(EXPECTED))]


def load_inventory():
    """Return the trust inventory: `sources` maps each audited file to its one digest, and each of `rows` names its source."""
    return read_json(INVENTORY)


def checked_inventory():
    """Return the trust inventory after refusing a shape other than a digest map and rows of string fields."""
    inventory = load_inventory()
    digests, rows = (inventory.get("sources"), inventory.get("rows")) if isinstance(inventory, dict) else (None, None)
    if not isinstance(digests, dict) or not all(isinstance(digest, str) for digest in digests.values()) \
            or not isinstance(rows, list):
        raise Refusal(TOOL_FAILURE, "the inventory needs a sources map of digests and a rows list")
    for row in rows:
        if not isinstance(row, dict) or not all(isinstance(row.get(key), str) for key in ("item", "class", "source")) \
                or not isinstance(row.get("text", ""), str):
            raise Refusal(TOOL_FAILURE, f"inventory row {row!r} needs string item, class and source fields and a string text")
    return inventory


def source_digests():
    """Return each inventoried source's digest, which the trust inventory alone declares."""
    return dict(checked_inventory()["sources"])


def install_digest(root):
    """Return the digest of a manifest of every entry under `root` and its file count.

    The manifest lists each file's executable bit and content digest and each link's target, so
    it covers the launcher, `rust_verify`, the macro libraries, vstd and the solver alike.
    """
    root = Path(root)
    paths = sorted(path for path in root.rglob("*") if path.is_symlink() or not path.is_dir())
    files = [path for path in paths if not path.is_symlink()]
    with ThreadPoolExecutor(max_workers=8) as pool:
        digests = dict(zip(files, pool.map(sha256, files)))
    lines = [
        f"link {os.readlink(path)} {path.relative_to(root)}" if path.is_symlink()
        else f"{'x' if path.stat().st_mode & 0o111 else '-'} {digests[path]} {path.relative_to(root)}"
        for path in paths
    ]
    return {"sha256": hashlib.sha256("".join(f"{line}\n" for line in lines).encode()).hexdigest(), "files": len(files)}


def identity(args):
    """Record the installation's identity, then refuse unless it is the declared one.

    The install tree is digested first, and its programs run only when that digest is the declared
    one. `VERUS_Z3_PATH` selects the solver the launcher hands to the verifier, so the record keeps
    it beside the solver it identifies.
    """
    expected, verus = read_json(EXPECTED), Path(args.verus)
    check_declaration(expected)
    install = install_digest(verus.parent)
    record = {"binary": {"path": str(verus)}, "install": install, "z3_path": os.environ.get("VERUS_Z3_PATH")}
    if install["sha256"] == expected["verus"]["install"]:
        version = subprocess.run([str(verus), "--version"], capture_output=True, text=True, check=False).stdout
        fields = dict(re.findall(r"^\s*(\w+): (.+)$", version, re.M))
        z3 = subprocess.run([str(verus.parent / "z3"), "--version"], capture_output=True, text=True, check=False).stdout.strip()
        record.update(
            version=fields.get("Version"), platform=fields.get("Platform"), z3=z3,
            toolchain=(fields.get("Toolchain") or "").split(" ")[0],
            commit=read_json(verus.parent / "version.json")["verus"].get("commit"),
        )
    evidence = Path(args.evidence)
    evidence.mkdir(parents=True, exist_ok=True)
    (evidence / "identity.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    (evidence / "pins.txt").write_text(
        f"- verus {record.get('version')} at {record.get('commit')}; {record.get('platform')}; toolchain {record.get('toolchain')}\n"
        f"- {record.get('z3')} at {record['z3_path']}\n"
        f"- install tree sha256 {install['sha256']} over {install['files']} files\n"
    )
    check_identity(expected, record)
    print(json.dumps({"identity": str(evidence / "identity.json")}))
    return CREDITED


def check_identity(expected, record):
    pinned = expected["verus"]
    if not isinstance(record, dict):
        raise Refusal(TOOL_FAILURE, "the identity record must be a JSON object")
    install, binary, z3 = record.get("install"), record.get("binary"), record.get("z3")
    if not isinstance(install, dict) or install.get("sha256") != pinned["install"]:
        raise Refusal(TOOL_FAILURE, f"the Verus install tree differs from the declared sha256 {pinned['install']}")
    for key in ("version", "commit", "toolchain", "platform"):
        if record.get(key) != pinned[key]:
            raise Refusal(TOOL_FAILURE, f"verus {key} {record.get(key)!r}, declared {pinned[key]!r}")
    if not isinstance(z3, str) or not z3.startswith(f"Z3 version {pinned['z3']} "):
        raise Refusal(TOOL_FAILURE, f"the solver reports {z3!r}, declared Z3 {pinned['z3']}")
    path = binary.get("path") if isinstance(binary, dict) else None
    if not isinstance(path, str) or not path:
        raise Refusal(TOOL_FAILURE, "the identity record names no verifier path")
    if not Path(path).is_absolute():
        raise Refusal(TOOL_FAILURE, f"the verifier path {path!r} is not absolute, so its solver would resolve from PATH")
    solver = str(Path(path).parent / "z3")
    if record.get("z3_path") != solver:
        raise Refusal(TOOL_FAILURE, f"the verifier's solver path VERUS_Z3_PATH={record.get('z3_path')!r} is not the identified solver {solver}")


def dep_paths(path, base):
    """Return the source paths a rustc dep-info file lists, resolved against the directory rustc ran in."""
    text = Path(path).read_text(encoding="utf-8", errors="replace")
    names = set()
    for line in text.splitlines():
        if ":" in line and not line.startswith("#"):
            names.update(part for part in line.split(":", 1)[1].split() if part.endswith(".rs"))
    return {(base / name).resolve() for name in names}


def module_files(sources):
    """Map each `pub mod` of the package root to the resolved file it compiles from.

    The root holds only attributes and `pub mod NAME;` declarations, so every module the map reads is
    a root module and no attribute text can hide one. A module attribute the map cannot resolve to
    one file refuses the root instead of falling back to a default file.
    """
    src = PACKAGE / "src"
    root = (src / "lib.rs").resolve()
    if root not in sources:
        raise Refusal(TOOL_FAILURE, f"the package root {root} is outside the scanned sources")
    code = sources[root]
    masked = masked_literals(code)
    position, attributes, modules = 0, [], {}
    while item := ROOT_ITEM.match(masked, position):
        position = item.end()
        if item[1]:
            start, end = item.start(1) + (3 if item[1].startswith("#!") else 2), item.end(1) - 1
            text, shape = code[start:end], masked[start:end]
            if "'" in shape or (item[1].startswith("#!") and CONDITION.search(shape)):
                raise Refusal(TOOL_FAILURE, f"the package root carries an attribute the module map cannot resolve: {code[item.start(1):item.end(1)]}")
            attributes += [] if item[1].startswith("#!") else [(text, shape)]
            continue
        name, paths = item[2], []
        for text, shape in attributes:
            if plain := re.fullmatch(r'\s*path\s*=\s*"([^"\\\n]+)"\s*', text):
                paths.append(plain[1])
            elif CONDITION.search(shape):
                raise Refusal(TOOL_FAILURE, f"module {name} carries an attribute the module map cannot resolve: #[{text}]")
        if len(paths) > 1 or name in modules:
            raise Refusal(TOOL_FAILURE, f"the package root maps module {name} to more than one file")
        attributes = []
        try:
            candidates = [(DECLARED_SRC / paths[0]).resolve()] if paths else \
                [(src / f"{name}.rs").resolve(), (src / name / "mod.rs").resolve()]
        except (OSError, RuntimeError, ValueError) as error:
            raise Refusal(TOOL_FAILURE, f"module {name} names a path that does not resolve: {error}") from error
        present = [path for path in candidates if path in sources]
        if len(present) > 1:
            raise Refusal(TOOL_FAILURE, f"module {name} has both {present[0]} and {present[1]}")
        modules[name] = (present or candidates)[0]
    rest = masked[position:]
    number = code.count("\n", 0, position + len(rest) - len(rest.lstrip())) + 1
    if rest.strip():
        raise Refusal(TOOL_FAILURE, f"{root}:{number} holds an item other than an attribute or a `pub mod` declaration")
    if attributes:
        raise Refusal(TOOL_FAILURE, f"{root} ends with an attribute that no `pub mod` declaration follows")
    return modules


def check_items(expected, sources):
    """Resolve credited names against the comment-blanked files of the escape scan."""
    modules = module_files(sources)
    for item in expected["tests"]:
        module, _, function = item.partition("::")
        if module not in modules:
            raise Refusal(TOOL_FAILURE, f"{item} names missing public module {module}")
        path = modules[module]
        if path not in sources:
            raise Refusal(TOOL_FAILURE, f"{item} names {path}, outside the scanned sources")
        if not function.isidentifier() or not re.search(rf"\bfn\s+{re.escape(function)}\s*[<(]", sources[path]):
            raise Refusal(TOOL_FAILURE, f"{path} declares no function for {item}")


def check_declaration(expected):
    """Validate the declaration's shape before any consumer uses it.

    The command starts with `verus`, which the lane resolves to the identified install, and each
    argument survives the one-argument-per-line record that the lane writes and the judge compares.
    Every option is listed in `OPTIONS` and every value follows its option, so `--no-cheating` is
    read as a flag and `src/lib.rs` is the one operand.
    """
    if not isinstance(expected, dict):
        raise Refusal(TOOL_FAILURE, "the declaration must be a JSON object")
    pins = expected.get("verus")
    if not isinstance(pins, dict) or not all(isinstance(pins.get(key), str) for key in PINS):
        raise Refusal(TOOL_FAILURE, f"the declared Verus pins must give {', '.join(PINS)} as strings")
    argv = expected.get("command")
    if not isinstance(argv, list) or not all(isinstance(arg, str) for arg in argv) or "--no-cheating" not in argv:
        raise Refusal(TOOL_FAILURE, "the declared Verus command requires an argument list including --no-cheating")
    if argv[0] != "verus":
        raise Refusal(TOOL_FAILURE, f"the declared Verus command runs {argv[0]!r}, not verus")
    for arg in argv:
        if "\0" in arg or "".join(arg.splitlines()) != arg:
            raise Refusal(TOOL_FAILURE, f"the declared Verus argument {arg!r} holds a NUL or a line break")
        try:
            arg.encode("utf-8")
        except UnicodeEncodeError as error:
            raise Refusal(TOOL_FAILURE, f"the declared Verus argument {arg!r} is not valid UTF-8") from error
    operands, rest = [], iter(argv[1:])
    for arg in rest:
        if not arg.startswith("-"):
            operands.append(arg)
            continue
        name, attached = arg.split("=", 1)[0], "=" in arg
        if name not in OPTIONS or (attached and not OPTIONS[name]):
            raise Refusal(TOOL_FAILURE, f"the declared Verus command passes {arg!r}, which is not a listed option")
        if OPTIONS[name] and not attached:
            value = next(rest, None)
            if value is None:
                raise Refusal(TOOL_FAILURE, f"the declared Verus option {arg} has no value")
            if value.startswith("-"):
                raise Refusal(TOOL_FAILURE, f"the declared Verus option {arg} takes {value!r} as its value")
    if operands != ["src/lib.rs"]:
        raise Refusal(TOOL_FAILURE, "the declared Verus command must compile the package root src/lib.rs as its one source")
    if not isinstance(expected.get("tests"), dict):
        raise Refusal(TOOL_FAILURE, "the declared tests must map item names to claims")
    if source_names(expected) is None:
        raise Refusal(TOOL_FAILURE, "the declared sources must be a list of paths")
    if type(expected.get("verified")) is not int or expected["verified"] < 1:
        raise Refusal(TOOL_FAILURE, "the declared verified count must be a positive integer")


def check_inventory(expected):
    """Check the declaration, reviewed sources, trust quotes and credited function names.

    A trusted quote must occur once in its source, so it names one item; an escape that is not a
    strict form is exempt only inside the span of such a quote, and a strict form is refused there
    too. The scan reads code with comments blanked, so whitespace, newlines and comments between an
    escape's tokens still match.
    """
    check_declaration(expected)
    spans, inventory = {}, checked_inventory()
    digests, rows = inventory["sources"], inventory["rows"]
    undigested = sorted(set(expected["sources"]) - set(digests))
    if undigested:
        raise Refusal(TOOL_FAILURE, f"the declaration declares {undigested[0]}, which the inventory does not digest")
    named = {row.get("source") for row in rows}
    orphaned = sorted(set(digests) - named)
    if orphaned:
        raise Refusal(TOOL_FAILURE, f"the inventory digests {orphaned[0]}, which no row names")
    for name, digest in sorted(digests.items()):
        source = ROOT / name
        if not source.is_file() or sha256(source) != digest:
            raise Refusal(TOOL_FAILURE, f"inventory source {name} changed since its digest was reviewed")
    for row in rows:
        source = ROOT / row["source"]
        if row["class"] not in ("verified", "trusted", "excluded", "tested"):
            raise Refusal(TOOL_FAILURE, f"inventory row {row['item']} has class {row['class']!r}")
        if row["source"] not in digests:
            raise Refusal(TOOL_FAILURE, f"inventory row {row['item']} names {row['source']}, which the inventory does not digest")
        if row["class"] == "trusted":
            text, body = row.get("text"), source_text(source)
            count = body.count(text) if text else 0
            if count == 0:
                raise Refusal(TOOL_FAILURE, f"trusted row {row['item']} quotes text absent from {row['source']}")
            if count > 1:
                raise Refusal(TOOL_FAILURE, f"trusted row {row['item']} quotes text that occurs {count} times in {row['source']}, so it names no one item")
            start = body.index(text)
            spans.setdefault(source.resolve(), []).append((start, start + len(text)))
    sources = {}
    for path in scanned_sources(expected):
        text, resolved = source_text(path), path.resolve()
        code = sources[resolved] = code_text(text, path)
        for match in ESCAPES.finditer(code):
            quoted = any(start <= match.start() and match.end() <= end for start, end in spans.get(resolved, []))
            if quoted and not STRICT_FORM.match(code, match.start()):
                continue
            number = text.count("\n", 0, match.start()) + 1
            line = text.split("\n")[number - 1].strip()
            if quoted:
                raise Refusal(TOOL_FAILURE, f"{path}:{number} matches a form strict mode rejects, which no trusted row may exempt: {line}")
            raise Refusal(TOOL_FAILURE, f"{path}:{number} escapes verification outside the trust inventory: {line}")
    check_items(expected, sources)


def judge(evidence, expected, record):
    check_declaration(expected)
    check_identity(expected, record)
    recorded = utf8_text(evidence / "verus.argv")
    if recorded != "".join(f"{arg}\n" for arg in expected["command"]):
        raise Refusal(TOOL_FAILURE, f"the lane ran {recorded!r}, declared {expected['command']}")
    try:
        exit_code = int((evidence / "verus.exit").read_text().strip())
    except (OSError, ValueError) as error:
        raise Refusal(TOOL_FAILURE, f"the run records no exit code: {error}") from error
    if exit_code in INTERRUPTED:
        raise Refusal(INCOMPLETE, f"the run was interrupted (exit {exit_code})", "timeout")
    lines = [line.strip() for line in (evidence / "verus.txt").read_text(encoding="utf-8", errors="replace").splitlines()]
    errors = [line for line in lines if line.startswith("error")]
    results = [RESULTS.match(line) for line in lines if line.startswith("verification results")]
    if any(match is None for match in results):
        raise Refusal(FAILED, "the run prints a malformed verification results line")
    if exit_code != 0 or errors or any(match.group(2) != "0" for match in results if match):
        raise Refusal(FAILED, f"the run exited {exit_code}: {(errors or [None])[0]}")
    if len(results) > 1:
        raise Refusal(FAILED, f"the run prints {len(results)} verification results lines, expected one")
    result = results[0] if results else None
    count = (result.group(1).lstrip("0") or "0") if result else "0"
    if result is None or count != str(expected["verified"]):
        raise Refusal(FAILED, f"the package reports {count} verified items, declared {expected['verified']}")
    digests = source_digests()
    for source in sorted(expected["sources"]):
        if digests.get(source) != sha256(ROOT / source):
            raise Refusal(TOOL_FAILURE, f"{source} differs from its inventoried digest")
    listed = {name: dep_paths(evidence / name, base) for name, base in (("verus.d", PACKAGE), ("cargo.d", ROOT))}
    if (PACKAGE / "src/lib.rs").resolve() not in listed["verus.d"]:
        raise Refusal(TOOL_FAILURE, "verus.d does not list the package root src/lib.rs, so Verus compiled another crate")
    for name, paths in listed.items():
        for source in sorted(expected["sources"]):
            if (ROOT / source).resolve() not in paths:
                raise Refusal(TOOL_FAILURE, f"{name} does not list {source}, so that build compiled another file")
    outside = sorted(str(path) for path in listed["verus.d"] - {path.resolve() for path in scanned_sources(expected)})
    if outside:
        raise Refusal(TOOL_FAILURE, f"verus.d lists {outside[0]}, outside the scanned sources the trust inventory covers")
    crates = [line for line in utf8_text(evidence / "tree.txt").splitlines() if re.match(r"(vstd|verus_\w+) ", line)]
    if crates:
        raise Refusal(TOOL_FAILURE, f"the ordinary kestrike build depends on {crates[0]}")
    utf8_text(evidence / "pins.txt")
    check_inventory(expected)
    return {"verified": expected["verified"], "items": sorted(expected["tests"])}


def inputs(evidence, credited=True):
    """Return the digests a receipt binds. A refusal binds each readable input file inside the repository."""
    names = ["identity.json", "pins.txt", "report.json", "verus.argv", "verus.txt", "verus.exit", "verus.d", "cargo.d", "tree.txt"]
    digests = {name: sha256(evidence / name) for name in names if (evidence / name).is_file()}
    try:
        files = committed()
    except Refusal:
        if credited:
            raise
        files = [EXPECTED, INVENTORY]
    for path in (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json", ROOT / "verification/obligations.json", *files):
        try:
            name = str(path.relative_to(ROOT))
            if credited or path.resolve().is_relative_to(ROOT):
                digests[name] = sha256(path)
        except (OSError, ValueError):
            if credited:
                raise
    return digests


def receipt(evidence, revision, completion, code, reason, results, expected):
    pins_path = evidence / "pins.txt"
    executed = results.get("items", []) if code == CREDITED else []
    return {
        "job": "verus", "module": None, "lane": "verus", "revision": revision,
        "inputs": inputs(evidence, code == CREDITED),
        "tool": {"name": "verus", "provenance": pins_path.read_text(encoding="utf-8", errors="replace").strip().splitlines()
                 if pins_path.exists() else []},
        "assumptions": [
            "the written contracts of the included production cores; callers outside the package are not verified",
            "trusted rows of the inventory: the verifier, the solver and vstd's specifications of the standard operations",
        ],
        "bounds": {"command": expected.get("command") if isinstance(expected, dict) else None, "verified": results.get("verified")},
        "completion": completion, "violation": None, "detail": reason,
        "selection": {"credited": code == CREDITED, "reason": reason},
        "executions": len(executed), "executed": executed, "failed": [],
        "replay": "bash scripts/rust-lane.sh verus",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def derive(evidence, revision):
    """Judge the evidence directory and return the report and the receipt it supports, writing neither."""
    code, reason, results, expected, completion = CREDITED, None, {}, None, "completed"
    try:
        expected = read_json(EXPECTED)
        results = judge(evidence, expected, read_json(evidence / "identity.json"))
    except (OSError, KeyError) as error:
        refusal = Refusal(TOOL_FAILURE, f"unreadable evidence: {error}")
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except RecursionError as error:
        refusal = Refusal(TOOL_FAILURE, f"malformed evidence: {error!r}")
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    except Refusal as refusal:
        code, reason, completion = refusal.code, str(refusal), refusal.completion
    report = {"code": code, "verdict": VERDICTS[code], "credited": code == CREDITED, "reason": reason, "results": results}
    return report, receipt(evidence, revision, completion, code, reason, results, expected)


def run_judge(args):
    evidence = Path(args.evidence)
    report, derived = derive(evidence, args.revision or git_revision())
    (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    derived["inputs"]["report.json"] = sha256(evidence / "report.json")
    (evidence / "receipt.json").write_text(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    print(json.dumps(report, sort_keys=True))
    if report["reason"]:
        print(f"judge-verus: {report['reason']}", file=sys.stderr)
    return report["code"]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Pin the Verus installation and judge the verification package run.",
        formatter_class=partial(argparse.HelpFormatter, width=78),
    )
    parser.add_argument("command", choices=["command", "identity", "judge", "reconcile"])
    parser.add_argument("--verus")
    parser.add_argument("--evidence")
    parser.add_argument("--revision")
    args = parser.parse_args(argv)
    if args.command == "command":
        try:
            expected = read_json(EXPECTED)
            check_declaration(expected)
            print("\n".join(expected["command"]))
        except Refusal as error:
            print(f"judge-verus: {error}", file=sys.stderr)
            return TOOL_FAILURE
        return CREDITED
    if args.command == "reconcile":
        try:
            check_inventory(read_json(EXPECTED))
        except (Refusal, OSError, KeyError) as error:
            print(f"judge-verus: {error}", file=sys.stderr)
            return TOOL_FAILURE
        print("judge-verus: the trust inventory matches its sources")
        return CREDITED
    if not args.evidence:
        parser.error(f"{args.command} needs --evidence")
    if args.command == "identity":
        if not args.verus:
            parser.error("identity needs --verus")
        try:
            return identity(args)
        except (Refusal, OSError, KeyError) as error:
            print(f"judge-verus: {error}", file=sys.stderr)
            return TOOL_FAILURE
    try:
        return run_judge(args)
    except (Refusal, OSError, KeyError) as error:
        print(f"judge-verus: {error}", file=sys.stderr)
        return TOOL_FAILURE


if __name__ == "__main__":
    sys.exit(main())
