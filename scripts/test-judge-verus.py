#!/usr/bin/env python3
"""Check that judge-verus.py credits only a complete, unscoped run of the pinned Verus over the declared production sources.

Each test builds an evidence directory as the lane writes it, runs the judge,
then breaks one property and checks the refusal names it.
"""

import contextlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-verus.py"
spec = importlib.util.spec_from_file_location("judge_verus", SCRIPT)
assert spec is not None and spec.loader is not None
judge = importlib.util.module_from_spec(spec)
spec.loader.exec_module(judge)
try:
    EXPECTED = json.loads(judge.EXPECTED.read_text())
    COMMITTED = json.loads(judge.INVENTORY.read_text())
except (OSError, ValueError) as error:
    raise SystemExit(f"test-judge-verus: unreadable declaration or inventory: {error}") from error


def reviewed(rows):
    """Return an inventory over `rows` whose digests are the current ones, as a reviewer records them."""
    return {"sources": {row["source"]: judge.sha256(judge.ROOT / row["source"]) for row in rows}, "rows": rows}


class JudgeVerus(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-verus-")
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name) / "evidence"
        self.evidence.mkdir()
        pinned = EXPECTED["verus"]
        self.identity = {
            "version": pinned["version"], "commit": pinned["commit"], "platform": pinned["platform"],
            "toolchain": pinned["toolchain"], "z3": f"Z3 version {pinned['z3']} - 64 bit", "z3_path": "/v/z3",
            "binary": {"path": "/v/verus"}, "install": {"sha256": pinned["install"], "files": 1},
        }
        # The judge's own checks run over a reviewed copy of the inventory; `reconcile` checks the committed digests.
        patcher = mock.patch.object(judge, "load_inventory", lambda: reviewed(COMMITTED["rows"]))
        patcher.start()
        self.addCleanup(patcher.stop)
        sources = " ".join(str(ROOT / name) for name in EXPECTED["sources"])
        self.files = {
            "verus.argv": "\n".join(EXPECTED["command"]) + "\n",
            "verus.txt": f"verification results:: {EXPECTED['verified']} verified, 0 errors\n    Finished `dev` profile\n",
            "verus.exit": "0\n",
            "verus.d": f"/t/kestrike_verus.d: src/lib.rs {sources}\n",
            "cargo.d": f"/t/kestrike.d: crates/kestrike/src/lib.rs {sources}\n",
            "tree.txt": "kestrike v0.1.0\nlibc v0.2.189\n",
            "pins.txt": "- verus\n",
        }

    def run_judge(self):
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        for name, text in self.files.items():
            if isinstance(text, bytes):
                (self.evidence / name).write_bytes(text)
            else:
                (self.evidence / name).write_text(text)
        with contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            code = judge.main(["judge", "--evidence", str(self.evidence), "--revision", "0" * 40])
        return code, json.loads(stdout.getvalue())

    def refused(self, code, fragment):
        exit_code, report = self.run_judge()
        self.assertEqual(exit_code, code, report)
        self.assertIn(fragment, report["reason"])
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(receipt["executions"], 0)
        self.assertFalse(receipt["selection"]["credited"])
        return receipt

    def test_a_complete_run_credits_every_declared_item(self):
        exit_code, report = self.run_judge()
        self.assertEqual(exit_code, 0, report)
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual(receipt["completion"], "completed")
        self.assertEqual(receipt["executed"], sorted(EXPECTED["tests"]))
        package = sorted(str(path.relative_to(ROOT)) for path in (ROOT / "verification/verus/src").rglob("*.rs"))
        for name in ("verification/verus/expected.json", "verification/verus/inventory.json", *package, *EXPECTED["sources"]):
            self.assertIn(name, receipt["inputs"])

    def test_identity_drift_is_a_tool_failure(self):
        for key, value, fragment in (("version", "0.0", "declared"), ("commit", "f" * 40, "declared"),
                                     ("toolchain", "1.0.0", "declared"), ("z3", "Z3 version 4.8.0 - 64 bit", "declared"),
                                     ("install", {"sha256": "0" * 64, "files": 1}, "install tree"),
                                     ("z3_path", "/elsewhere/z3", "solver path"), ("z3_path", None, "solver path")):
            with self.subTest(key=key, value=value):
                saved = self.identity[key]
                self.identity[key] = value
                self.refused(2, fragment)
                self.identity[key] = saved

    def fake_install(self):
        """Write an install whose launcher and solver report the declared versions, and return its launcher."""
        pinned = EXPECTED["verus"]
        root = Path(self.temp.name) / "install" / "verus-x86-linux"
        root.mkdir(parents=True)
        (root / "verus").write_text(
            "#!/bin/sh\nprintf 'Verus\\n  Version: %s\\n  Platform: %s\\n  Toolchain: %s (overridden)\\n' "
            f"{pinned['version']} {pinned['platform']} {pinned['toolchain']}\n"
        )
        (root / "z3").write_text(f"#!/bin/sh\necho 'Z3 version {pinned['z3']} - 64 bit'\n")
        for name in ("verus", "z3"):
            (root / name).chmod(0o755)
        for name in ("rust_verify", "libvstd.rlib", "vstd.vir", "libverus_builtin_macros.so"):
            (root / name).write_text(f"{name}\n")
        (root / "version.json").write_text(json.dumps({"verus": {"commit": pinned["commit"]}}))
        return root / "verus"

    def identify(self, verus, solver):
        environment = {key: value for key, value in os.environ.items() if key != "VERUS_Z3_PATH"}
        if solver is not None:
            environment["VERUS_Z3_PATH"] = str(solver)
        with mock.patch.dict(os.environ, environment, clear=True), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            code = judge.main(["identity", "--verus", str(verus), "--evidence", str(self.evidence)])
        return code, json.loads((self.evidence / "identity.json").read_text())

    def test_identity_binds_every_installed_file_and_the_solver_the_verifier_uses(self):
        verus = self.fake_install()
        code, record = self.identify(verus, verus.parent / "z3")
        self.assertEqual(code, 2, "an install off the declared tree must refuse, so the lane reinstalls")
        self.assertNotIn("version", record, "a program of an undeclared install ran")
        declared = dict(EXPECTED, verus=dict(EXPECTED["verus"], install=record["install"]["sha256"]))
        expected = Path(self.temp.name) / "expected.json"
        expected.write_text(json.dumps(declared))
        with mock.patch.object(judge, "EXPECTED", expected):
            code, record = self.identify(verus, verus.parent / "z3")
            self.assertEqual(code, 0, record)
            judge.check_identity(declared, record)
            (verus.parent / "rust_verify").write_text("another verifier\n")
            code, tampered = self.identify(verus, verus.parent / "z3")
            self.assertEqual(code, 2)
            with self.assertRaisesRegex(judge.Refusal, "install tree"):
                judge.check_identity(declared, tampered)
            (verus.parent / "rust_verify").write_text("rust_verify\n")
            for solver in (Path("/elsewhere/z3"), None):
                with self.subTest(solver=solver):
                    code, redirected = self.identify(verus, solver)
                    self.assertEqual(code, 2)
                    with self.assertRaisesRegex(judge.Refusal, "solver path"):
                        judge.check_identity(declared, redirected)

    def test_a_scoped_or_other_command_is_refused(self):
        for separator in ("\x0c", "\r\n"):
            with self.subTest(separator=separator):
                self.files["verus.argv"] = separator.join(EXPECTED["command"]) + "\n"
                self.refused(2, "the lane ran")
        self.files["verus.argv"] = "\n".join(EXPECTED["command"]) + "\n"
        for name in ("verus.argv", "tree.txt", "pins.txt"):
            with self.subTest(name=name):
                saved = self.files[name]
                self.files[name] = saved.encode() + b"\xff\n"
                self.refused(2, f"{name} is not UTF-8")
                self.files[name] = saved
        saved = self.files["verus.d"]
        self.files["verus.d"] = saved.replace(" src/lib.rs ", " ")
        self.refused(2, "verus.d does not list the package root")
        self.files["verus.d"] = saved
        self.files["verus.argv"] = "\n".join([*EXPECTED["command"], "--", "--verify-only-module", "summary"]) + "\n"
        self.refused(2, "declared")
        argv = [arg for arg in EXPECTED["command"] if arg != "--no-cheating"]
        self.files["verus.argv"] = "\n".join(argv) + "\n"
        self.refused(2, "the lane ran")
        with self.assertRaisesRegex(judge.Refusal, "--no-cheating"):
            judge.check_inventory(dict(EXPECTED, command=argv))

    def test_a_failed_interrupted_or_short_run_earns_no_credit(self):
        self.files["verus.exit"] = "124\n"
        self.assertEqual(self.refused(3, "interrupted")["completion"], "timeout")
        self.files["verus.exit"] = "1\n"
        self.refused(1, "exited 1")
        strict_error = "error: assume/admit not allowed with --no-cheating"
        self.files["verus.txt"] = strict_error + "\n"
        self.refused(1, strict_error)
        line = f"verification results:: {EXPECTED['verified']} verified, 0 errors\n"
        self.files["verus.txt"] = strict_error + "\n" + line * 2
        self.refused(1, strict_error)
        self.files["verus.exit"] = "0\n"
        self.files["verus.txt"] = f"verification results:: {EXPECTED['verified']} verified, 0 errors\n" * 2
        self.refused(1, "2 verification results lines")
        self.files["verus.txt"] = strict_error + f"\nverification results:: {EXPECTED['verified']} verified, 0 errors\n"
        self.refused(1, strict_error)
        self.files["verus.txt"] = "error: postcondition not satisfied\nverification results:: 25 verified, 1 errors\n"
        self.refused(1, "postcondition")
        self.files["verus.txt"] = f"verification results:: {EXPECTED['verified'] - 1} verified, 0 errors\n"
        self.refused(1, "declared")
        arabic = str(EXPECTED["verified"]).translate(str.maketrans("0123456789", "\u0660\u0661\u0662\u0663\u0664\u0665\u0666\u0667\u0668\u0669"))
        for token in (arabic, "9" * 5000):
            with self.subTest(token=token[:8]):
                self.files["verus.txt"] = f"verification results:: {token} verified, 0 errors\n"
                self.refused(1, "declared")
        self.files["verus.txt"] = f"verification results:: 0{EXPECTED['verified']} verified, 0 errors\n"
        self.assertEqual(self.run_judge()[0], 0)
        self.files["verus.txt"] = "    Finished `dev` profile\n"
        self.refused(1, "reports 0 verified")
        self.files["verus.txt"] = "verification results:: many verified, 0 errors\n"
        self.refused(1, "malformed verification results line")
        for code in ("130", "143"):
            self.files["verus.exit"] = code + "\n"
            self.refused(3, "interrupted")

    def test_missing_evidence_is_a_tool_failure(self):
        del self.files["verus.d"]
        receipt = self.refused(2, "unreadable evidence")
        self.assertEqual(receipt["completion"], "tool failure")

    def test_either_build_compiling_another_file_or_a_verus_dependency_is_refused(self):
        source = str(ROOT / next(iter(EXPECTED["sources"])))
        for name in ("verus.d", "cargo.d"):
            with self.subTest(name=name):
                saved = self.files[name]
                self.files[name] = saved.replace(source, "/copy/summary.rs")
                self.refused(2, f"{name} does not list")
                self.files[name] = saved
        self.files["tree.txt"] += "vstd v0.0.0\n"
        self.refused(2, "depends on vstd")

    def test_a_verifier_source_outside_the_scanned_and_inventoried_files_is_refused(self):
        for extra in ("src/proof/helpers.rs", str(ROOT / "crates/kestrike/src/storage/extent/bitmap.rs")):
            with self.subTest(extra=extra):
                saved = self.files["verus.d"]
                self.files["verus.d"] = saved.replace(" src/lib.rs ", f" src/lib.rs {extra} ")
                self.refused(2, "outside the scanned sources")
                self.files["verus.d"] = saved

    def sandbox(self):
        """Point the judge at a copy of the package and inventory, and return the copy's root and rows."""
        package = Path(self.temp.name) / "package"
        shutil.copytree(judge.PACKAGE / "src", package / "src")
        original = (judge.PACKAGE, judge.INVENTORY)
        self.addCleanup(lambda: setattr(judge, "PACKAGE", original[0]) or setattr(judge, "INVENTORY", original[1]))
        setattr(judge, "PACKAGE", package)
        setattr(judge, "INVENTORY", package / "inventory.json")
        patcher = mock.patch.object(judge, "load_inventory", lambda: json.loads(judge.INVENTORY.read_text()))
        patcher.start()
        self.addCleanup(patcher.stop)
        rows = [dict(row) for row in COMMITTED["rows"]]
        self.save(rows)
        return package, rows

    def save(self, rows, **digests):
        """Write the sandbox inventory over `rows` at their current digests, with each source in `digests` overridden."""
        inventory = reviewed(rows)
        inventory["sources"].update(digests)
        judge.INVENTORY.write_text(json.dumps(inventory))

    def test_every_escape_form_outside_a_trusted_row_is_refused_in_the_package_and_the_production_source(self):
        package, rows = self.sandbox()
        production = package / "summary.rs"
        shutil.copy(ROOT / EXPECTED["sources"][0], production)
        declared = dict(EXPECTED, sources=[str(production)],
                        tests={k: v for k, v in EXPECTED["tests"].items() if k.startswith(("owners::", "proof::"))})
        rows.append({"item": "the copied production source", "class": "excluded", "source": str(production)})
        self.save(rows)
        judge.check_inventory(declared)
        forms = [
            "proof fn hole() ensures false { admit(); }", "proof fn hole() ensures false { assume(false); }",
            "#[verifier::external_body]", "#[verifier(external_body)]", "#[verifier(external)]",
            "#[cfg_attr(verus_keep_ghost, verus_verify(external_body))]", "#[verifier::external_fn_specification]",
            "pub assume_specification [ core::mem::swap ];", "axiom fn hole();",
            "#[verifier::externals_available_without_declaration]", "#[verifier::assume(externals_available_without_declaration)]",
            "inline_air_stmt(x);",
            "proof fn hole() ensures false { assume /* reason */ (false); }",
            "proof fn hole() ensures false { assume\n(false); }",
            "#[verifier::\nexternal_body]",
            "#[cfg(not(verus_keep_ghost))]", "#[cfg(not( verus_keep_ghost ))]", "#[cfg(all(unix, not(verus_keep_ghost)))]",
        ]
        allowed_quotes = ("#[verifier(external)]", "#[verifier::external]")
        nested = package / "src/proof/helpers.rs"
        nested.parent.mkdir()
        nested.write_text("")
        for target in (package / "src/proof.rs", nested, production):
            original = target.read_text()
            for form in forms:
                with self.subTest(target=target.name, form=form):
                    target.write_text(original + "\n" + form + "\n")
                    self.save(rows)
                    with self.assertRaisesRegex(judge.Refusal, "escapes verification"):
                        judge.check_inventory(declared)
            for quote in ("admit();", "assume(false);", "#[verifier::external_body]",
                          "pub assume_specification [ core::mem::swap ];", "#[verifier::assume_termination]",
                          "#[verifier::externals_available_without_declaration]", "axiom fn hole();",
                          "#[verifier::external_fn_specification]", "#[verifier(external_body)]",
                          "#[cfg_attr(verus_keep_ghost, verus_verify(external_body))]",
                          "#[verifier::assume(externals_available_without_declaration)]",
                          "#[verifier:: /* reason */ external_body]", "#[verifier::\nexternal_body]", "#[verifier (external_body)]",
                          "#[cfg_attr(verus_keep_ghost, verus_verify( external_body ))]", "axiom\nfn hole();",
                          "axiom /* reason */ fn hole();", "#[verifier::deny(externals_available_without_declaration)]",
                          "#[cfg_attr(verus_keep_ghost, verus_verify (external_body))]", *allowed_quotes):
                with self.subTest(target=target.name, quote=quote):
                    target.write_text(original + "\n" + quote + "\n")
                    self.save([*rows, {"item": "quoted escape", "class": "trusted", "source": str(target), "text": quote}])
                    if quote in allowed_quotes:
                        judge.check_inventory(declared)
                    else:
                        with self.assertRaisesRegex(judge.Refusal, "strict mode"):
                            judge.check_inventory(declared)
            target.write_text(original)
            self.save(rows)

    def test_a_trusted_quote_exempts_only_its_one_occurrence_and_comments_are_not_code(self):
        package, rows = self.sandbox()
        target = package / "src/proof.rs"
        original = target.read_text()
        escape = "#[verifier(external)]\n"

        def trust(source, text):
            target.write_text(original + source)
            row = {"item": "quoted escape", "class": "trusted", "source": str(target), "text": text}
            self.save([*rows, row])

        twice = f"\n{escape}proof fn first() {{}}\n{escape}proof fn second() {{}}\n"
        trust(twice, escape.strip())
        with self.assertRaisesRegex(judge.Refusal, "occurs 2 times"):
            judge.check_inventory(EXPECTED)
        trust(twice, f"{escape}proof fn first() {{}}")
        with self.assertRaisesRegex(judge.Refusal, r"proof\.rs:\d+ escapes verification"):
            judge.check_inventory(EXPECTED)
        trust(f"\n{escape}proof fn first() {{}}\n", f"{escape}proof fn first() {{}}")
        judge.check_inventory(EXPECTED)
        self.save(rows)
        for comment in ("// a caller would otherwise need assume(false)\n", "/* never admit() here */\n",
                        '/// `#[verifier::external_body]` stays out of this file\n'):
            with self.subTest(comment=comment):
                target.write_text(original + "\n" + comment)
                judge.check_inventory(EXPECTED)
        target.write_text(original + "\n/* outer /* inner */ assume(false); */\n")
        judge.check_inventory(EXPECTED)
        target.write_text(original + "\n/* outer /* inner */ still outer */\nproof fn hole() { assume(false); }\n/* later */\n")
        with self.assertRaisesRegex(judge.Refusal, "escapes verification outside the trust inventory"):
            judge.check_inventory(EXPECTED)
        # rustc reads `'r` or `'r#r` as a lifetime and `r#r` as a raw identifier, and the cooked string after either as
        # one literal, so the comment markers inside that string are literal text and `#[verifier::external]` below is
        # code the scan must refuse.
        for lifetime in ("'r", "'r#x", "'br", "'r#r", "'r#br", "r#r", "r#br", "r#cr"):
            with self.subTest(lifetime=lifetime):
                target.write_text(original + "\nmacro_rules! ignored { ($($t:tt)*) => {} }\n"
                                  f'ignored!({lifetime}"x\\"/* /* */");\n#[verifier::external]\nfn unchecked() {{}}\n// */\n')
                with self.assertRaisesRegex(judge.Refusal, "escapes verification outside the trust inventory"):
                    judge.check_inventory(EXPECTED)
        # Raw literals treat backslashes as data. A quote followed by the opening delimiter's `#` count closes the
        # literal, so the later `"/*"` is a string and the scanner must recognize `#[verifier::external]` as code.
        for raw in ('r"\\"', 'br"\\"', 'cr"\\"', 'br#"\\"#'):
            with self.subTest(raw=raw):
                target.write_text(original + f'\nconst B: &[u8] = {raw}; const S: &str = "/*";\n#[verifier::external]\nfn f() {{}}\n// */\n')
                with self.assertRaisesRegex(judge.Refusal, "escapes verification outside the trust inventory"):
                    judge.check_inventory(EXPECTED)
        target.write_text(original + "\n/* opened\nproof fn hole() { assume(false); }\n")
        with self.assertRaisesRegex(judge.Refusal, r"proof\.rs:\d+ opens a block comment that never closes"):
            judge.check_inventory(EXPECTED)
        for literal in ("'\\x41'", "'\\u{41}'", "'\\u{0_0_0_0_4_1}'", "b'\\x41'"):
            with self.subTest(literal=literal):
                target.write_text(original + f"\nconst C: [char; 2] = [{literal},'\"'];\nconst S: &str = \"/*\";\n#[verifier::external]\nfn f() {{}}\n")
                with self.assertRaisesRegex(judge.Refusal, "escapes verification outside the trust inventory"):
                    judge.check_inventory(EXPECTED)
                target.write_text(original + f"\nconst C: [char; 2] = [{literal},'\"'];\n/* fn ghost() {{}} */\nconst S: &str = \"x\";\n")
                with self.assertRaisesRegex(judge.Refusal, r"proof\.rs declares no function for proof::ghost"):
                    judge.check_inventory(dict(EXPECTED, tests={**EXPECTED["tests"], "proof::ghost": "claim"}))
        target.write_bytes(original.encode() + b"\n// retired \rproof fn ghost() {}\n")
        with self.assertRaisesRegex(judge.Refusal, r"proof\.rs declares no function for proof::ghost"):
            judge.check_inventory(dict(EXPECTED, tests={**EXPECTED["tests"], "proof::ghost": "claim"}))
        target.write_bytes(original.encode() + b"\n// retired \r\nproof fn ghost() {}\n")
        judge.check_inventory(dict(EXPECTED, tests={**EXPECTED["tests"], "proof::ghost": "claim"}))
        target.write_bytes(original.encode() + b'\n// note \r"\nconst S: &str = "/*";\n#[verifier::external]\nfn f() {}\n// */\n')
        with self.assertRaisesRegex(judge.Refusal, "escapes verification outside the trust inventory"):
            judge.check_inventory(EXPECTED)
        target.write_text(original + '\nproof fn hole() { let s = "/*"; assume(false); let t = "*/"; }\n')
        with self.assertRaisesRegex(judge.Refusal, "escapes verification"):
            judge.check_inventory(EXPECTED)
        target.write_text(original + '\nproof fn hole() { let s = r"\\"; let t = "/*"; assume(false); let u = "*/"; }\n')
        with self.assertRaisesRegex(judge.Refusal, "escapes verification"):
            judge.check_inventory(EXPECTED)

    def test_a_stale_unquoted_or_unclassed_inventory_row_is_refused(self):
        package, rows = self.sandbox()
        declared = {**EXPECTED, "sources": [*EXPECTED["sources"], "crates/kestrike/src/lib.rs"]}
        with self.assertRaisesRegex(judge.Refusal, "declares crates/kestrike/src/lib.rs, which the inventory does not digest"):
            judge.check_inventory(declared)
        trusted = next(row for row in rows if row["class"] == "trusted")
        for change, fragment in (({"text": "text absent from the source"}, "quotes text absent"),
                                 ({"text": ""}, "quotes text absent"),
                                 ({"class": "assumed"}, "has class")):
            with self.subTest(change=change):
                saved = dict(trusted)
                trusted.update(change)
                self.save(rows)
                with self.assertRaisesRegex(judge.Refusal, fragment):
                    judge.check_inventory(EXPECTED)
                trusted.clear()
                trusted.update(saved)
        self.save(rows, **{trusted["source"]: "0" * 64})
        with self.assertRaisesRegex(judge.Refusal, f"inventory source {trusted['source']} changed since its digest was reviewed"):
            judge.check_inventory(EXPECTED)
        inventory = reviewed(rows)
        inventory["sources"]["crates/kestrike/src/lib.rs"] = judge.sha256(ROOT / "crates/kestrike/src/lib.rs")
        judge.INVENTORY.write_text(json.dumps(inventory))
        with self.assertRaisesRegex(judge.Refusal, "digests crates/kestrike/src/lib.rs, which no row names"):
            judge.check_inventory(EXPECTED)
        inventory = reviewed(rows)
        inventory["rows"].append({"item": "undigested row", "class": "excluded", "source": "crates/kestrike/src/lib.rs"})
        judge.INVENTORY.write_text(json.dumps(inventory))
        with self.assertRaisesRegex(judge.Refusal, "undigested row names crates/kestrike/src/lib.rs, which the inventory does not digest"):
            judge.check_inventory(EXPECTED)

    def test_each_credited_item_names_a_function_in_its_scanned_module(self):
        for item, fragment in (("arithmetic::absent", r"arithmetic\.rs"),
                               ("arithmetic::extent_count", r"arithmetic\.rs"),
                               ("arithmetic", r"arithmetic\.rs declares no function for arithmetic$"),
                               ("arithmetic::", r"arithmetic\.rs declares no function for arithmetic::$"),
                               ("absent::extent_counts", "module absent")):
            with self.subTest(item=item), self.assertRaisesRegex(judge.Refusal, fragment):
                judge.check_inventory(dict(EXPECTED, tests={item: "claim"}))
        source = "crates/kestrike/src/storage/record/arithmetic.rs"
        declared = dict(EXPECTED, tests={"arithmetic::extent_counts": "claim"},
                        sources=[s for s in EXPECTED["sources"] if s != source])
        with self.assertRaisesRegex(judge.Refusal, r"arithmetic\.rs.*scanned"):
            judge.check_inventory(declared)
        package, _ = self.sandbox()
        lib = package / "src/lib.rs"
        attributes = '#[allow(\n    dead_code,\n)]\n#[doc = "See [extent_counts]."]\n'
        lib.write_text(lib.read_text().replace("pub mod arithmetic;", attributes + "pub mod arithmetic;"))
        judge.check_inventory(EXPECTED)
        proof = package / "src/proof.rs"
        proof.write_text(proof.read_text() + "\n/* outer /* inner */ fn commented_only() {} */\n")
        with self.assertRaisesRegex(judge.Refusal, r"proof\.rs.*proof::commented_only"):
            judge.check_inventory(dict(EXPECTED, tests={**EXPECTED["tests"], "proof::commented_only": "claim"}))

    def test_a_credited_name_is_a_whole_function_name(self):
        package, _ = self.sandbox()
        proof = package / "src/proof.rs"
        # `width` is followed by `<` but declares no function, and the probe's signature text opens a `(` after `-> `.
        proof.write_text(proof.read_text() + "\nproof fn renamed\u0301() {}\nproof fn spaced\u00b7x() {}\n"
                         "proof fn probe(width: u64) -> (bool) { width < 1 }\nproof fn generic /* c */ <T>(value: T) {}\n")
        for item in ("proof::renamed", "proof::spaced", "proof::width", "proof::probe(width: u64) -> "):
            with self.subTest(item=item), self.assertRaisesRegex(judge.Refusal, rf"proof\.rs declares no function for {re.escape(item)}$"):
                judge.check_inventory(dict(EXPECTED, tests={item: "claim"}))
        judge.check_inventory(dict(EXPECTED, tests={"proof::renamed\u0301": "claim", "proof::spaced\u00b7x": "claim",
                                                    "proof::probe": "claim", "proof::generic": "claim"}))

    def test_the_package_root_maps_each_module_to_one_file(self):
        package, _ = self.sandbox()
        lib, proof = package / "src/lib.rs", package / "src/proof.rs"
        root, body = lib.read_text(), proof.read_text()
        arithmetic = '#[path = "../../../crates/kestrike/src/storage/record/arithmetic.rs"]\npub mod arithmetic;'
        self.assertIn(arithmetic, root)
        path = arithmetic.split("\n")[0]
        for change, fragment in (
                (arithmetic.replace('= "', '= r"'), "module arithmetic carries an attribute"),
                (arithmetic.replace(path, f"#[cfg_attr(all(), path = {path[9:-1]})]"), "module arithmetic carries an attribute"),
                (path + "\n#[cfg_attr(all(), doc = concat![\"a\"])]\npub mod arithmetic;", "holds an item other than"),
                (arithmetic + "\n#[cfg(any())]\npub mod arithmetic;", "module arithmetic carries an attribute"),
                (arithmetic + "\n#[path = \"model.rs\"]\npub mod arithmetic;", "maps module arithmetic to more than one file"),
                (arithmetic + "\npub mod outer {\n    pub mod proof;\n}", "holds an item other than"),
                (arithmetic + "\nuse crate::proof::handoff;", "holds an item other than"),
                (path.replace("record/arithmetic", "record/arith\0metic") + "\npub mod arithmetic;", "does not resolve"),
                ("#[doc = '\"']\n" + arithmetic, "carries an attribute the module map cannot resolve"),
                ("#[doc = '\"']\npub mod extra;\n#[doc = '\"']\n" + arithmetic, "carries an attribute the module map cannot resolve"),
                ("#[doc = " + 'r"a" ' * 40 + "\n" + arithmetic, "holds an item other than"),
                (arithmetic + '\n#[path = "model.rs"]\n#[path = "owners.rs"]\npub mod extra;', "maps module extra to more than one file"),
                ("#![cfg(any())]\n" + arithmetic, r"cannot resolve: #!\[cfg\(any\(\)\)\]"),
                ("#![cfg_attr(all(), cfg(any()))]\n" + arithmetic, "carries an attribute the module map cannot resolve")):
            with self.subTest(change=change):
                lib.write_text(root.replace(arithmetic, change))
                with self.assertRaisesRegex(judge.Refusal, fragment):
                    judge.check_inventory(EXPECTED)
        lib.write_text(root + "\n#[allow(unused)]\n")
        with self.assertRaisesRegex(judge.Refusal, "ends with an attribute that no `pub mod` declaration follows"):
            judge.check_inventory(EXPECTED)
        lib.write_text(root.replace("pub mod proof;", '#[doc = r#"#[path = "model.rs"]"#]\npub mod proof;'))
        judge.check_inventory(EXPECTED)
        lib.write_text('#![allow(unused)]\n#![doc = "cfg and path stay inside this string"]\n' + root)
        judge.check_inventory(EXPECTED)
        lib.write_text(root)
        (package / "src/proof").mkdir()
        proof.rename(package / "src/proof/mod.rs")
        judge.check_inventory(EXPECTED)
        proof.write_text(body)
        with self.assertRaisesRegex(judge.Refusal, "module proof has both"):
            judge.check_inventory(EXPECTED)

    def test_a_source_or_trusted_file_outside_utf8_is_refused(self):
        package, rows = self.sandbox()
        proof = package / "src/proof.rs"
        proof.write_bytes(proof.read_bytes() + b'\nconst E: &str = "\xe9";\n')
        with self.assertRaisesRegex(judge.Refusal, r"proof\.rs is not UTF-8"):
            judge.check_inventory(EXPECTED)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(judge.main(["reconcile"]), 2)
        self.assertIn("proof.rs is not UTF-8", stderr.getvalue())
        self.assertEqual(self.refused(2, "not UTF-8")["completion"], "tool failure")
        proof.write_bytes(proof.read_bytes().replace(b'\nconst E: &str = "\xe9";\n', b""))
        judge.check_inventory(EXPECTED)
        outside = package / "trusted.rs"
        outside.write_bytes(b"#[verifier::external]\n\xff\n")
        self.save([*rows, {"item": "quoted escape", "class": "trusted", "source": str(outside), "text": "#[verifier::external]"}])
        with self.assertRaisesRegex(judge.Refusal, r"trusted\.rs is not UTF-8"):
            judge.check_inventory(EXPECTED)

    def test_a_missing_package_root_is_refused_by_name(self):
        package, _ = self.sandbox()
        (package / "src/lib.rs").unlink()
        with self.assertRaisesRegex(judge.Refusal, r"the package root .*lib\.rs is outside the scanned sources"):
            judge.check_inventory(EXPECTED)

    def test_declaration_fields_have_the_types_used_to_credit_items(self):
        command = EXPECTED["command"]
        for field, value, reason in (
                ("command", None, "argument list"), ("command", "--no-cheating", "argument list"),
                ("command", [*command, 7], "argument list"), ("command", ["", *command[1:]], "runs ''"),
                ("command", ["/elsewhere/verus", *command[1:]], "not verus"),
                ("command", ["VERUS_Z3_PATH=/elsewhere/z3", *command], "not verus"),
                *(("command", [*command[:-1], f"--log-dir{mark}x", command[-1]], "NUL or a line break")
                  for mark in ("\0", "\n", "\r", "\x0b", "\x85", "\u2028")),
                ("tests", None, "map item names"), ("tests", sorted(EXPECTED["tests"]), "map item names"),
                ("sources", None, "list of paths"), ("sources", [*EXPECTED["sources"], 7], "list of paths"),
                ("verified", str(EXPECTED["verified"]), "positive integer"), ("verified", -1, "positive integer"),
                ("verified", True, "positive integer"), ("verified", 0, "positive integer"),
                *(("command", [*command[:-1], *flag, command[-1]], f"passes '{flag[0]}', which is not a listed option")
                  for flag in (["--verify-module", "summary"], ["--verify-module=summary"], ["--verify-only-module", "summary"],
                               ["--verify-only-module=summary"], ["--verify-root"], ["--verify-function", "f"],
                               ["--verify-function=f"], ["--no-verify"], ["--no-lifetime"], ["--no-trait-conflicts"])),
                *(("command", [*command[:-1], f"--log-dir={mark}", command[-1]], "not valid UTF-8") for mark in ("\ud800", "\udc80")),
                ("command", [*command[:-1], "src/main.rs"], "package root src/lib.rs"),
                ("command", [*command, "src/other.rs"], "package root src/lib.rs"),
                ("command", [*command[:-1], "extra", command[-1]], "package root src/lib.rs"),
                # Verus reads the argument after a value-taking option as that option's value, so `--no-cheating`
                # in that position leaves strict mode off.
                ("command", [*command[:-2], "--log-dir", "--no-cheating", command[-1]], "'--log-dir', which is not a listed option"),
                ("command", [arg for arg in command if arg != "target/verus"][:-1] + ["target/verus", command[-1]],
                 "option --out-dir takes '--no-cheating' as its value"),
                ("command", [*command, "--out-dir"], "option --out-dir has no value"),
                ("command", [*command[:-1], "--compile=yes", command[-1]], "'--compile=yes', which is not a listed option"),
                ("command", [*command[:-1], "--", command[-1]], "'--', which is not a listed option"),
                ("command", [*command[:-1], "-v", command[-1]], "'-v', which is not a listed option"),
                ("verus", None, "pins must give"), ("verus", dict(EXPECTED["verus"], install=None), "pins must give")):
            with self.subTest(field=field, value=value), self.assertRaisesRegex(judge.Refusal, reason):
                judge.check_inventory({**EXPECTED, field: value})
        with self.assertRaisesRegex(judge.Refusal, "JSON object"):
            judge.check_inventory([EXPECTED])
        read = judge.read_json
        self.files["verus.txt"] = "verification results:: 0 verified, 0 errors\n"
        for declared, reason in ((dict(EXPECTED, command="--no-cheating"), "argument list"), ([EXPECTED], "JSON object"),
                                 (dict(EXPECTED, sources=None), "list of paths"), (dict(EXPECTED, verified=0), "positive integer"),
                                 (dict(EXPECTED, command=[*EXPECTED["command"][:-1], "--log-dir=\ud800", "src/lib.rs"]), "UTF-8"),
                                 (dict(EXPECTED, verus=None), "pins must give")):
            def reader(path, declared=declared):
                return declared if path == judge.EXPECTED else read(path)

            with self.subTest(reason=reason), mock.patch.object(judge, "read_json", reader):
                for step in ("command", "reconcile"):
                    with contextlib.redirect_stdout(io.StringIO()) as output, contextlib.redirect_stderr(io.StringIO()) as error:
                        self.assertEqual(judge.main([step]), 2)
                    self.assertEqual(output.getvalue(), "")
                    self.assertIn(reason, error.getvalue())
                self.assertEqual(self.refused(2, reason)["completion"], "tool failure")
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(judge.main(["identity", "--verus", "/absent/verus", "--evidence", str(self.evidence)]), 2)
                self.assertIn(reason, error.getvalue())

    def test_a_refused_receipt_binds_only_readable_repository_inputs(self):
        outside = Path(self.temp.name) / "outside.rs"
        outside.write_text("fn outside() {}\n")
        declaration = Path(self.temp.name) / "expected.json"
        for text, reason in (("{", "unreadable"), (json.dumps(dict(EXPECTED, sources=[*EXPECTED["sources"], "crates/absent.rs"])), "unreadable evidence"),
                             (json.dumps(dict(EXPECTED, sources=[*EXPECTED["sources"], str(outside)])), "differs from its inventoried digest")):
            with self.subTest(reason=reason), mock.patch.object(judge, "EXPECTED", declaration):
                declaration.write_text(text)
                receipt = self.refused(2, reason)
                self.assertEqual(receipt["completion"], "tool failure")
                self.assertNotIn("crates/absent.rs", receipt["inputs"])
                self.assertIn("verification/verus/inventory.json", receipt["inputs"])

    def test_a_malformed_identity_record_or_inventory_is_refused(self):
        recorded = self.identity
        assert isinstance(recorded, dict)
        for binary in ({"path": 7}, {"path": ""}, {}, None):
            with self.subTest(binary=binary):
                self.identity = dict(recorded, binary=binary, z3_path="z3")
                self.refused(2, "the identity record names no verifier path")
        for path in ("verus", "bin/verus"):
            with self.subTest(path=path):
                self.identity = dict(recorded, binary={"path": path}, z3_path=str(Path(path).parent / "z3"))
                self.refused(2, "is not absolute")
        self.identity = []
        self.assertEqual(self.refused(2, "identity record must be a JSON object")["completion"], "tool failure")
        self.identity = None
        package, rows = self.sandbox()
        for inventory, fragment in (([], "sources map of digests"), ({"sources": {}, "rows": ["row"]}, "needs string item"),
                                    (dict(reviewed(rows), rows=[*rows, {"item": "x", "class": "trusted", "source": rows[0]["source"], "text": 7}]),
                                     "needs string item")):
            with self.subTest(inventory=str(inventory)[:40]):
                judge.INVENTORY.write_text(json.dumps(inventory))
                with self.assertRaisesRegex(judge.Refusal, fragment):
                    judge.check_inventory(EXPECTED)
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as error:
                    self.assertEqual(judge.main(["reconcile"]), 2)
                self.assertIn(fragment, error.getvalue())

    def test_reconcile_checks_only_the_committed_inventory(self):
        package, rows = self.sandbox()
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(judge.main(["reconcile"]), 0)
        self.save(rows, **{rows[0]["source"]: "0" * 64})
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(judge.main(["reconcile"]), 2)
        self.assertIn(f"inventory source {rows[0]['source']} changed since its digest was reviewed", stderr.getvalue())

    def test_a_tested_source_off_its_inventoried_digest_earns_no_credit(self):
        package, rows = self.sandbox()
        source = "crates/kestrike/src/storage/device/table_tests.rs"
        tested = next(row for row in rows if row["source"] == source)
        self.assertEqual(tested["class"], "tested")
        self.save(rows, **{source: "0" * 64})
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        for name, text in self.files.items():
            (self.evidence / name).write_text(text)
        with self.assertRaisesRegex(judge.Refusal, f"inventory source {source} changed since its digest was reviewed"):
            judge.judge(self.evidence, EXPECTED, self.identity)

    def test_a_production_source_off_its_inventoried_digest_earns_no_credit(self):
        package, rows = self.sandbox()
        source = EXPECTED["sources"][0]
        self.save(rows, **{source: "0" * 64})
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        for name, text in self.files.items():
            (self.evidence / name).write_text(text)
        with self.assertRaisesRegex(judge.Refusal, "differs from its inventoried digest"):
            judge.judge(self.evidence, EXPECTED, self.identity)

    def cli(self):
        """Run the judge's command over the evidence as it stands and return its exit code and stderr."""
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()) as stderr:
            code = judge.main(["judge", "--evidence", str(self.evidence), "--revision", "0" * 40])
        return code, stderr.getvalue()

    def test_a_receipt_input_or_report_the_judge_cannot_use_exits_2_without_a_report(self):
        pins, argv, report, receipt = (self.evidence / name for name in ("pins.txt", "verus.argv", "report.json", "receipt.json"))
        plants = (
            ("a pins directory", lambda: (pins.unlink(), pins.mkdir()), pins.rmdir),
            ("an unreadable command record", lambda: argv.chmod(0), lambda: argv.chmod(0o644)),
            ("a report directory", report.mkdir, report.rmdir),
        )
        for name, plant, restore in plants:
            with self.subTest(plant=name):
                if name == "an unreadable command record" and os.geteuid() == 0:
                    self.skipTest("root reads a file of any mode")
                exit_code, credited = self.run_judge()
                self.assertEqual(exit_code, 0, credited)
                report.unlink()
                receipt.unlink()
                plant()
                try:
                    code, stderr = self.cli()
                finally:
                    restore()
                self.assertEqual(code, 2, stderr)
                self.assertTrue(stderr.startswith("judge-verus: "), stderr)
                self.assertFalse(report.exists() or receipt.exists())

    def test_an_identity_nested_past_the_parser_is_refused_with_a_report(self):
        exit_code, credited = self.run_judge()
        self.assertEqual(exit_code, 0, credited)
        (self.evidence / "identity.json").write_text("[" * 100_000)
        code, stderr = self.cli()
        report = json.loads((self.evidence / "report.json").read_text())
        receipt = json.loads((self.evidence / "receipt.json").read_text())
        self.assertEqual((code, report["code"], receipt["executions"]), (2, 2, 0), stderr)
        self.assertIn("malformed evidence: RecursionError", report["reason"])


if __name__ == "__main__":
    unittest.main()
