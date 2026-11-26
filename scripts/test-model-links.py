#!/usr/bin/env python3
"""Exercise `model-links.py check` over sandbox copies of the tree: the committed tree passes, each planted breach
fails through the rule it breaks with exit 2 and its refusal text, each planted change the rules accept passes, and
each unreadable or malformed input ends the check with exit 2 and one line."""

import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/model-links.py"
REGISTRY = "verification/models/links.json"
MODEL = "tla/Lifecycle.tla"
PLANTED = "crates/planted/item.rs"
# The digest's span must end at the brace that closes `fn braces`, skipping the braces of its comment and literals,
# and the quote count must skip the doc comment that repeats its header. `BRACES` is that span with comments blanked
# and white space collapsed.
ITEM = """/// fn braces(x: u8) -> &'static str {
fn braces(x: u8) -> &'static str {
    // a } in a comment
    let close = '}';
    let open = "{";
    if x > 0 { open } else { "end" }
}

fn other() {}
"""
BRACES = """fn braces(x: u8) -> &'static str { let close = '}'; let open = "{"; if x > 0 { open } else { "end" } }"""


def sha256(text):
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def run(root):
    result = subprocess.run([sys.executable, str(CHECK), "check", "--root", str(root)],
                            capture_output=True, text=True, check=False, timeout=120)
    return result.returncode, [line.removeprefix("model-links: ") for line in result.stderr.splitlines()]


class ModelLinks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        result = run(ROOT)
        if result != (0, []):
            raise AssertionError(f"the committed tree fails the check, so every sandbox copy fails too: {result}")

    def setUp(self):
        self.sandbox()

    def sandbox(self):
        """Copy the files the check reads into a new tree root: the registry, the runner, the enrolled models, the
        cited files and both judges, since `scripts/judge-verus.py` loads `scripts/judge-rc11.py` beside it."""
        self.root = Path(tempfile.mkdtemp(prefix="model-links-"))
        self.addCleanup(shutil.rmtree, self.root)
        try:
            registry = json.loads((ROOT / REGISTRY).read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the committed {REGISTRY} cannot be read: {error}")
        paths = {REGISTRY, "tla/check.py", "scripts/judge-verus.py", "scripts/judge-rc11.py"}
        paths |= {model["path"] for model in registry["models"]}
        paths |= {anchor["path"] for row in registry["rows"] for anchor in row.get("anchors", [])}
        for path in paths:
            if not (self.root / path).resolve().is_relative_to(self.root.resolve()):
                self.fail(f"{REGISTRY} names {path}, which leaves the sandbox")
            (self.root / path).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(ROOT / path, self.root / path)

    def run_check(self, root=None):
        return run(root or self.root)

    def refused(self, *expected):
        """Assert that the check exits 2 with exactly the refusals `expected`."""
        self.assertEqual(self.run_check(), (2, list(expected)))

    def passes(self):
        self.assertEqual(self.run_check(), (0, []))

    def edit(self, path, old, new):
        text = (self.root / path).read_text(encoding="utf-8")
        self.assertEqual(text.count(old), 1, f"{old!r} in {path}")
        (self.root / path).write_text(text.replace(old, new), encoding="utf-8")

    def registry(self):
        try:
            return json.loads((self.root / REGISTRY).read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the sandbox {REGISTRY} cannot be read: {error}")

    def write_registry(self, data):
        (self.root / REGISTRY).write_text(json.dumps(data))

    def row(self, data, name):
        return next(row for row in data["rows"] if row["model"] == MODEL and row["name"] == name)

    def index(self, name):
        """The position of `name`'s row in the sandbox registry, as a shape refusal names it."""
        return next(at for at, row in enumerate(self.registry()["rows"])
                    if row["model"] == MODEL and row["name"] == name)

    def change_row(self, name, change):
        data = self.registry()
        change(data, self.row(data, name))
        self.write_registry(data)

    def plant_item(self, text=ITEM, quote="fn braces(", digest=None, path=PLANTED):
        """Write `text` as a file of the tree, add an anchor on it to `CAbandon`'s row and return the anchor's name
        in a refusal."""
        (self.root / path).parent.mkdir(parents=True, exist_ok=True)
        (self.root / path).write_text(text)
        return self.add_anchor(path, quote, digest)

    def add_anchor(self, path, quote, digest=None):
        """Add an anchor to `CAbandon`'s row and return the anchor's name in a refusal."""
        data = self.registry()
        anchors = self.row(data, "CAbandon")["anchors"]
        anchors.append({"path": path, "quote": quote, **({} if digest is None else {"digest": digest})})
        self.write_registry(data)
        return f"{MODEL} action CAbandon anchor {len(anchors) - 1}"

    def test_sandbox_passes(self):
        self.passes()

    def test_new_next_disjunct_without_a_row(self):
        self.edit(MODEL, "    \\/ Done\n\nSpec ==", "    \\/ Done \\/ Fresh\n\nSpec ==")
        self.edit(MODEL, "Done == (Finished", "Fresh == UNCHANGED vars\nDone == (Finished")
        self.edit("tla/check.py", '"DTerminal", "Done")\nENDING', '"DTerminal", "Done", "Fresh")\nENDING')
        self.refused(f"{MODEL} action Fresh: the action has no row")

    def test_quantifier_bounds_and_strings_name_no_action(self):
        self.edit(MODEL, "    \\/ Done\n\nSpec ==",
                  '    \\/ \\E k \\in {j \\in Lim : j < Cap} : Done\n'
                  '    \\/ \\A k \\in All,\n           m \\in All : \\E n \\in All : Done\n'
                  '    \\/ \\E k \\in {j \\in Lim : \\E q \\in All : q < Cap} : Done\n'
                  '    \\/ \\E t \\in [a : Lim] : Done\n'
                  '    \\/ \\E k \\in DOMAIN <<CHOOSE x \\in All : x < Cap>> : Done\n'
                  '    \\/ \\E k \\in (CHOOSE s \\in {All, Lim} : Cap \\notin s) : Done\n'
                  '    \\/ (Done /\\ "Held" # "x")\n\nSpec ==')
        self.edit(MODEL, "Done == (Finished", "Lim == {1}\nCap == 2\nAll == {1}\nDone == (Finished")
        self.passes()

    def test_next_disjunct_that_names_no_definition(self):
        steps = (
            ("\\/ (stop' = stop /\\ UNCHANGED <<c, o>>)", "(stop' = stop /\\ UNCHANGED <<c, o>>)"),
            ("\\/ LET k == 1 IN stop' = stop /\\ UNCHANGED <<c, o>>", "LET k == 1 IN stop' = stop /\\ UNCHANGED <<c, o>>"),
            ("\\/ (1 = 1)", "(1 = 1)"),
            ("\\lor (Done /\\ UNCHANGED <<c, o>>)", "(Done /\\ UNCHANGED <<c, o>>)"),
            ("∨ (ENABLED Done /\\ stop' = stop)", "(ENABLED Done /\\ stop' = stop)"),
            ("\\/ \\E k \\in Credited : (k = k)", "(k = k)"),
        )
        for step, piece in steps:
            with self.subTest(step=step):
                self.sandbox()
                self.edit(MODEL, "    \\/ Done\n\nSpec ==", f"    \\/ Done\n    {step}\n\nSpec ==")
                self.refused(f"{MODEL}: the disjunct {piece!r} of Next names no definition or takes a step of its own")

    def test_quantifier_bound_that_never_ends(self):
        self.edit(MODEL, "    \\/ Done\n\nSpec ==", "    \\/ Done\n    \\/ \\E k \\in {1\n\nSpec ==")
        self.refused(f"{MODEL}: a quantifier bound in Next reaches the end of Next without its ':'")

    def test_action_removed_from_next_keeps_its_definition(self):
        self.edit(MODEL, "\\/ CExpire \\/ CAbandon \\/ CClose", "\\/ CExpire \\/ CClose")
        self.refused(f"{MODEL}: coverage name CAbandon in tla/check.py is no action of Next",
                     f"{MODEL} action CAbandon: the row names no action of {MODEL}")

    def test_two_rows_for_one_action(self):
        data = self.registry()
        data["rows"].append(dict(self.row(data, "CBegin")))
        self.write_registry(data)
        self.refused(f"{MODEL} action CBegin: two rows name this action")

    def test_row_without_anchor_or_abstraction(self):
        self.change_row("CBegin", lambda data, row: row.pop("anchors"))
        self.refused(f"{MODEL} action CBegin: the row holds neither of an anchor and an abstraction text")

    def test_row_with_anchor_and_abstraction(self):
        self.change_row("CBegin", lambda data, row: row.update(abstraction="no code site"))
        self.refused(f"{MODEL} action CBegin: the row holds both of an anchor and an abstraction text")

    def test_row_for_an_unknown_action(self):
        self.change_row("Done", lambda data, row: data["rows"].append({**row, "name": "Bogus"}))
        self.refused(f"{MODEL} action Bogus: the row names no action of {MODEL}")

    def test_row_of_a_model_that_is_not_enrolled(self):
        for model in ("tla/NotEnrolled.tla", "tla//Lifecycle.tla", "./tla/Lifecycle.tla"):
            with self.subTest(model=model):
                self.sandbox()
                self.change_row("Done", lambda data, row, model=model: data["rows"].append(
                    {**row, "model": model, "name": "Planted"}))
                self.refused(f"{model} action Planted: the row's model is not enrolled")

    def test_rows_are_matched_to_actions_of_their_own_model(self):
        """A row moved to another enrolled model is refused there, though a third model defines its action, and its
        own model then misses the action."""
        data = self.registry()
        row = next(row for row in data["rows"] if row["model"] == "tla/Identity.tla" and row["name"] == "Done")
        row["model"] = "tla/Recovery.tla"
        self.write_registry(data)
        self.refused("tla/Recovery.tla action Done: the row names no action of tla/Recovery.tla",
                     "tla/Identity.tla action Done: the action has no row")

    def test_row_of_a_kind_the_model_does_not_enroll(self):
        self.change_row("Done", lambda data, row: data["rows"].append({**row, "kind": "no-such-kind", "name": "c"}))
        self.refused(f"{MODEL} no-such-kind c: {MODEL} does not enroll no-such-kind rows")

    def test_model_outside_tla(self):
        outside = Path(tempfile.mkdtemp(prefix="model-links-outside-"))
        self.addCleanup(shutil.rmtree, outside)
        (outside / "Lifecycle.tla").write_text((self.root / MODEL).read_text())
        (self.root / MODEL).unlink()
        (self.root / MODEL).symlink_to(outside / "Lifecycle.tla")
        self.refused(f"{MODEL}: an enrolled model must be named tla/<file> and lie in tla/ of the tree, where "
                     "tla/check.py reads its models")
        for model in ("docs/X.tla", "./tla/Lifecycle.tla", "tla//Lifecycle.tla", "tla/../tla/Lifecycle.tla"):
            with self.subTest(model=model):
                self.sandbox()
                self.change_row("Done", lambda data, row, model=model: data["models"].append(
                    {"path": model, "kinds": ["action"]}))
                self.refused(f"{model}: an enrolled model must be named tla/<file> and lie in tla/ of the tree, where "
                             "tla/check.py reads its models")

    def test_runner_coverage_that_omits_an_action(self):
        self.edit("tla/check.py", '"CSend", "CNicReturn",', '"CSend",')
        self.refused(f"{MODEL}: action CNicReturn of Next is in no completing case's coverage in tla/check.py")

    def test_runner_coverage_that_names_no_action(self):
        self.edit("tla/check.py", '"RChunk", "RDone")', '"RChunk", "RDone", "Ghost")')
        self.refused(f"{MODEL}: coverage name Ghost in tla/check.py is no action of Next")

    def test_coverage_of_a_violation_case_is_outside_the_union(self):
        self.edit("tla/check.py", '    yield lifecycle("put")\n',
                  '    yield lifecycle("put")\n    yield lifecycle("ghost", coverage=("Ghost",), '
                  'extra="INVARIANT NoPublication\\n", expected=violation("NoPublication"))\n')
        self.passes()

    def test_absent_quote(self):
        where = self.plant_item(quote="fn braced(")
        self.refused(f"{where}: the quote 'fn braced(' occurs 0 times in {PLANTED}")

    def test_repeated_quote(self):
        where = self.plant_item(text=ITEM + "fn braces(y: u8) {}\n")
        self.refused(f"{where}: the quote 'fn braces(' occurs 2 times in {PLANTED}")

    def test_self_overlapping_quote(self):
        where = self.plant_item(text="fn aaa() {}\n", quote="aa")
        self.refused(f"{where}: the quote 'aa' occurs 2 times in {PLANTED}")

    def test_quote_only_in_a_comment(self):
        where = self.plant_item(text="// fn only_here() {}\nfn other() {}\n", quote="fn only_here()")
        self.refused(f"{where}: the quote 'fn only_here()' occurs 0 times in {PLANTED}")

    def test_quote_only_inside_a_literal(self):
        """Text inside a string or character literal names no code, so a quote found only there is absent, with or
        without a digest: the last case's digest is the span the item rule reads from inside the string pattern."""
        arm = 'fn real(s: &str) -> u8 {\n    match s {\n        "fn fake(" => { 1 }\n        _ => 0,\n    }\n}\n'
        cases = (
            ('fn real() { println!("fn fake("); }\n', "fn fake(", None),
            ('fn real() { println!("  fn fake("); }\n', " fn fake(", None),
            ('fn real() { println!(r#"fn fake("#); }\n', "fn fake(", None),
            ('fn real() -> &\'static [u8] { b"fn fake(" }\n', "fn fake(", None),
            ("fn real() -> char { 'Q' }\n", "Q", None),
            (arm, "fn fake(", sha256('fn fake(" => { 1 }')),
        )
        for text, quote, digest in cases:
            with self.subTest(text=text):
                self.sandbox()
                where = self.plant_item(text=text, quote=quote, digest=digest)
                self.refused(f"{where}: the quote {quote!r} occurs 0 times in {PLANTED}")

    def test_literal_that_repeats_a_quote_is_no_second_place(self):
        """The quote's one place is its occurrence in code, and the digest spans the item there, although the
        literal that repeats the quote comes first in the file."""
        self.plant_item(text='fn real() { println!("fn fake("); }\nfn fake() -> u8 { 1 }\n', quote="fn fake(",
                        digest=sha256("fn fake() -> u8 { 1 }"))
        self.passes()

    def test_lone_carriage_return_stays_inside_a_line_comment(self):
        where = self.plant_item(text="", quote="fn only_here()")
        (self.root / PLANTED).write_bytes(b"// retired \rfn only_here() {}\nfn other() {}\n")
        self.refused(f"{where}: the quote 'fn only_here()' occurs 0 times in {PLANTED}")
        self.sandbox()
        self.plant_item(text="", digest=sha256(BRACES))
        self.add_anchor(PLANTED, "let close = '}';\n    let open")
        (self.root / PLANTED).write_bytes(ITEM.replace("\n", "\r\n").encode("utf-8"))
        self.passes()

    def test_rust_handling_follows_the_cited_path(self):
        target = Path(PLANTED).with_suffix(".inc")
        (self.root / target).parent.mkdir(parents=True, exist_ok=True)
        (self.root / target).write_text("// fn only_here() {}\nfn real(x: u8) -> u8 { x }\n")
        (self.root / "crates/planted/link.rs").symlink_to(target.name)
        where = self.add_anchor("crates/planted/link.rs", "fn only_here()")
        self.add_anchor("crates/planted/link.rs", "fn real(", sha256("fn real(x: u8) -> u8 { x }"))
        self.refused(f"{where}: the quote 'fn only_here()' occurs 0 times in crates/planted/link.rs")

    def test_anchor_outside_the_tree(self):
        outside = Path(tempfile.mkdtemp(prefix="model-links-outside-"))
        self.addCleanup(shutil.rmtree, outside)
        (outside / "item.rs").write_text(ITEM)
        (self.root / "crates").mkdir(exist_ok=True)
        (self.root / "crates/link.rs").symlink_to(outside / "item.rs")
        (self.root / "crates/loop.rs").symlink_to("loop2.rs")
        (self.root / "crates/loop2.rs").symlink_to("loop.rs")
        for path in ("crates/link.rs", "crates/\u0000.rs", "crates/absent.rs", "crates/loop.rs"):
            with self.subTest(path=path):
                data = self.registry()
                self.row(data, "CAbandon")["anchors"][0]["path"] = path
                self.write_registry(data)
                self.refused(f"{MODEL} action CAbandon anchor 0: {path} is no file of the tree")

    def test_rows_that_share_a_quote_and_an_undigested_anchor_before_a_digested_one(self):
        """Each row's anchors are checked in turn: an anchor without a digest is checked for its quote only, a
        digested anchor after it in the same row is still checked, and every row that quotes one place is
        refused when the quote goes."""
        other = self.plant_item()
        data = self.registry()
        anchors = self.row(data, "CClose")["anchors"]
        anchors.insert(0, {"path": PLANTED, "quote": "fn braces("})
        anchors.append({"path": PLANTED, "quote": "fn braces(", "digest": sha256(BRACES)})
        self.write_registry(data)
        first, digested = f"{MODEL} action CClose anchor 0", f"{MODEL} action CClose anchor {len(anchors) - 1}"
        self.passes()
        (self.root / PLANTED).write_text(ITEM.replace("x > 0", "x > 1"))
        self.refused(f"{digested}: the item at {PLANTED} 'fn braces(' changed; read it and the row, then record its "
                     f"current digest {sha256(BRACES.replace('x > 0', 'x > 1'))}")
        (self.root / PLANTED).write_text(ITEM.replace("fn braces(", "fn renamed("))
        self.refused(f"{other}: the quote 'fn braces(' occurs 0 times in {PLANTED}",
                     f"{first}: the quote 'fn braces(' occurs 0 times in {PLANTED}",
                     f"{digested}: the quote 'fn braces(' occurs 0 times in {PLANTED}")

    def test_anchor_path_spelling(self):
        self.plant_item(text="// fn only_here() {}\nfn other() {}\n", quote="fn only_here()")
        for path in ("../outside.rs", "/etc/hosts", "./" + PLANTED, PLANTED.replace("/", "//", 1), PLANTED + "/",
                     "crates/planted/../planted/item.rs"):
            with self.subTest(path=path):
                data = self.registry()
                self.row(data, "CAbandon")["anchors"][-1]["path"] = path
                self.write_registry(data)
                index = len(self.row(data, "CAbandon")["anchors"]) - 1
                self.refused(f"{MODEL} action CAbandon anchor {index}: {path} is no tree-relative path spelled without "
                             "'.', '..' or empty parts")

    def test_digest_covers_the_item_with_braces_in_literals(self):
        self.plant_item(digest=sha256(BRACES))
        self.passes()

    def test_digest_counts_bracket_depth(self):
        self.plant_item(text="fn arr(x: [u8; 4]) -> u8 { x[0] }\n", quote="fn arr(",
                        digest=sha256("fn arr(x: [u8; 4]) -> u8 { x[0] }"))
        self.passes()

    def test_digest_spans_written_by_hand(self):
        """Bracket depth starts at the quote's first character, so the return type's `;` lies at depth one; a quote
        with balanced braces of its own spans the arm body through the brace that closes it."""
        text = ("fn ret(x: u8) -> [u8; 4] { [x; 4] }\n"
                "fn pick(r: R) -> u8 {\n    match r {\n        R::Same { a, b } => {\n            a + b\n        }\n"
                "        R::Other => 0,\n    }\n}\n")
        self.plant_item(text=text, quote="fn ret(", digest=sha256("fn ret(x: u8) -> [u8; 4] { [x; 4] }"))
        self.add_anchor(PLANTED, "R::Same { a, b } =>", sha256("R::Same { a, b } => { a + b }"))
        self.passes()

    def test_every_anchor_of_a_file_is_checked(self):
        self.plant_item(digest=sha256(BRACES))
        where = self.add_anchor(PLANTED, "fn other(", "0" * 64)
        self.refused(f"{where}: the item at {PLANTED} 'fn other(' changed; read it and the row, then record its "
                     f"current digest {sha256('fn other() {}')}")

    def test_comment_whitespace_and_move_keep_the_digest(self):
        texts = (
            ITEM.replace("// a } in a comment", "/* another { comment */"),
            ITEM.replace('    let open = "{";\n', '        let open\n            = "{";\n\n'),
            "fn other() {}\n\n" + ITEM.replace("\nfn other() {}\n", ""),
        )
        for text in texts:
            with self.subTest(text=text):
                self.sandbox()
                self.plant_item(text=text, digest=sha256(BRACES))
                self.passes()

    def test_edited_item_body_prints_the_current_digest(self):
        where = self.plant_item(text=ITEM.replace("x > 0", "x > 1"), digest=sha256(BRACES))
        current = sha256(BRACES.replace("x > 0", "x > 1"))
        self.refused(f"{where}: the item at {PLANTED} 'fn braces(' changed; read it and the row, then record its "
                     f"current digest {current}")

    def test_digest_needs_an_item_body(self):
        cases = (
            ("fn decl(x: [u8; 4]) -> u8;\nfn after() {}\n", "fn decl(",
             "a ';' at bracket depth zero lies between the quote and the first '{'"),
            ("enum E { A, B }\nfn after() {}\n", "A,",
             "a '}' at bracket depth zero lies between the quote and the first '{'"),
            ("fn open() { {\n", "fn open(", "the braces after the quote never balance"),
            ("fn opened(x: u8) {\n    { x };\n}\n", "fn opened(x: u8) {", "the braces inside the quote do not balance"),
            ("fn arr(x: [u8; { 4 }]) -> u8 { x[0] }\n", "fn arr(",
             "the first '{' after the quote lies inside brackets"),
            ("fn f(c: bool) -> u8 {\n    if c { 1 } else if c {\n        { 2 };\n        3\n    } else { 4 }\n}\n",
             "} else if c {", "the quote closes a brace or bracket it does not open"),
            ("fn g(x: u8) -> u8 { x }\nfn h(x: u8) -> u8 { g(x) + (1) }\n", "x) + (",
             "the quote closes a brace or bracket it does not open"),
            ("fn k(x: u8) -> u8 { m(x)) { 1 } }\n", "fn k(x: u8) -> u8 { m(",
             "the braces inside the quote do not balance"),
            ("fn first() {}\nfn second() { body() }\n", "fn first() {}", "the quote ends with a closed block"),
            ("fn p(v: Option<u8>) {\n    match v {\n        Some(n) if { n > 0 } => { save(n); }\n        _ => {}\n"
             "    }\n}\n", "Some(n) if", "the span closes inside a match pattern or guard, before its '=>'"),
            ("fn q(v: Option<u8>) {\n    match v {\n        Some(n) if n == S { a: 1 }.a => { save(n); }\n"
             "        _ => {}\n    }\n}\n", "Some(n) if n == S",
             "the expression continues after the span's closing brace"),
            ("fn r(v: Option<u8>, c: bool) -> u8 {\n    match v {\n        Some(_) => if c { 1 } else { 2 },\n"
             "        None => 0,\n    }\n}\n", "Some(_) =>", "the expression continues after the span's closing brace"),
            ("fn s(v: Option<u8>) {\n    match v {\n        Some(_) => Frame { kind: 1 }?.send(0),\n        None => (),\n"
             "    }\n}\n", "Some(_) =>", "the expression continues after the span's closing brace"),
            ("fn t(v: u8) {\n    match v {\n        0 => call(),\n        _ => { work() }\n    }\n}\n", "0 =>",
             "a second match arm lies between the quote and the first '{'"),
            ("fn other() {}\nfn tail(x: u8) -> u8\n", "fn tail(", "no '{' follows the quote"),
            ("fn u(flag: bool) -> u8 { if (flagged) { 1 } else { 2 } }\n", "flagged",
             "a ')' after the quote closes a bracket the quote does not open"),
        )
        for text, quote, reason in cases:
            with self.subTest(quote=quote):
                self.sandbox()
                where = self.plant_item(text=text, quote=quote, digest="0" * 64)
                self.refused(f"{where}: the quote {quote!r} carries a digest but has no item body: {reason}")

    def test_digest_needs_a_rust_file(self):
        where = self.plant_item(text="Fresh == {1}\n", quote="Fresh ==", digest="0" * 64, path="tla/Planted.txt")
        self.refused(f"{where}: a digest needs a Rust item, and tla/Planted.txt is no Rust file")

    def test_empty_anchor_list(self):
        for name in ("CAbandon", "Done"):
            with self.subTest(name=name):
                self.sandbox()
                self.change_row(name, lambda data, row: row.update(anchors=[]))
                self.refused(f"{REGISTRY}: row {self.index(name)} ({MODEL} action {name}) anchors are not a non-empty "
                             "list")

    def test_registry_that_drops_the_lifecycle_enrollment(self):
        for models in ([], [{"path": "tla/Identity.tla", "kinds": ["action"]}]):
            with self.subTest(models=models):
                self.write_registry({"models": models, "rows": []})
                self.refused(f"{REGISTRY}: {MODEL} is not enrolled for action rows")

    def test_cyclic_root(self):
        (self.root / "cycle").symlink_to("cycle2")
        (self.root / "cycle2").symlink_to("cycle")
        code, lines = self.run_check(self.root / "cycle")
        self.assertEqual((code, len(lines)), (2, 1), lines)

    def test_fails_closed(self):
        def label(name):
            return f"{REGISTRY}: row {self.index(name)} ({MODEL} action {name})"

        def first_anchor(name, change):
            self.change_row(name, lambda data, row: change(row["anchors"][0]))

        def unreadable_item():
            self.plant_item(quote="fn x(")
            (self.root / PLANTED).write_bytes(b"\xff")

        def repeated(data):
            text = json.dumps(data)
            return text.replace('{"models": [', '{"models": [], "models": [', 1)

        def twice(data):
            data["models"].append(data["models"][0])
            return data

        def nested_kinds(data):
            data["models"][0]["kinds"] = [["action"]]
            return data

        cases = (
            (lambda: (self.root / REGISTRY).write_text("{not json"), f"unreadable {REGISTRY}"),
            (lambda: (self.root / REGISTRY).write_text("[" * 100000 + "]" * 100000), f"unreadable {REGISTRY}"),
            (lambda: (self.root / REGISTRY).unlink(), f"unreadable {REGISTRY}"),
            (lambda: self.write_registry({"models": [], "rows": {}}), f"{REGISTRY}: models and rows are not lists"),
            (lambda: (self.root / REGISTRY).write_text(repeated(self.registry())),
             f"unreadable {REGISTRY}: an object repeats ['models']"),
            (lambda: first_anchor("CAbandon", lambda at: at.update(hash=at.pop("digest"))),
             f"{label('CAbandon')} anchor 0 is not an object with ['path', 'quote']"),
            (lambda: self.change_row("CBegin", lambda data, row: row.pop("note")),
             f"{REGISTRY}: row {self.index('CBegin')} is not an object with ['kind', 'model', 'name', 'note']"),
            (lambda: self.change_row("Done", lambda data, row: row.update(abstraction="  ")),
             f"{label('Done')} has no abstraction text"),
            (lambda: first_anchor("CAbandon", lambda at: at.update(digest=10 ** 63)),
             f"{label('CAbandon')} anchor 0 digest is not 64 lowercase hex digits"),
            (lambda: first_anchor("CAbandon", lambda at: at.update(digest="0" * 63 + "G")),
             f"{label('CAbandon')} anchor 0 digest is not 64 lowercase hex digits"),
            (lambda: self.write_registry(twice(self.registry())), f"{REGISTRY}: model {MODEL} is enrolled twice"),
            (lambda: self.write_registry(nested_kinds(self.registry())), f"{REGISTRY}: model 0 kinds are not"),
            (lambda: (self.root / MODEL).write_bytes(b"\xff\xfe"), f"{MODEL} cannot be read"),
            (lambda: (self.root / "tla/check.py").write_text("def cases(:\n"), "tla/check.py cannot be loaded"),
            (lambda: (self.root / "tla/check.py").write_text("x = 1\n"), "the definition reader of tla/check.py"),
            (lambda: self.edit("tla/check.py", "def cases():\n", "def cases():\n    raise RuntimeError('planted')\n"),
             "tla/check.py cannot list its cases: planted"),
            (lambda: self.edit("tla/check.py", "def cases():\n", "def cases():\n    raise SystemExit(0)\n"),
             "tla/check.py cannot list its cases: 0"),
            (lambda: self.edit("tla/check.py", "    text = uncommented(module)\n",
                               "    raise SystemExit\n    text = uncommented(module)\n"),
             "the definition reader of tla/check.py refuses the model"),
            (lambda: self.edit(MODEL, "\nNext ==\n", "\nStep ==\n"), f"{MODEL}: the model defines no Next"),
            (lambda: self.plant_item(text="fn x() {}\n/* open\n", quote="fn x("),
             f"{MODEL} action CAbandon anchor 1: {PLANTED} cannot be read: {PLANTED}:2 opens a block comment"),
            (unreadable_item, f"{MODEL} action CAbandon anchor 1: {PLANTED} cannot be read"),
            (lambda: self.edit("scripts/judge-verus.py", "def source_text(path):\n",
                               "def source_text(path):\n    raise SystemExit(0)\n"),
             "the check stopped on SystemExit: 0"),
            (lambda: (self.root / "scripts/judge-verus.py").write_text("def x(:\n"),
             "scripts/judge-verus.py cannot be loaded"),
        )
        for plant, refusal in cases:
            with self.subTest(refusal=refusal):
                self.sandbox()
                plant()
                code, lines = self.run_check()
                self.assertEqual((code, len(lines)), (2, 1), lines)
                self.assertTrue(lines[0].startswith(refusal), lines[0])


if __name__ == "__main__":
    unittest.main()
