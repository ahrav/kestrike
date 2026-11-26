#!/usr/bin/env python3
"""Check that weaken-orderings.py check accepts the committed catalog and refuses each defect by name, and that run
judges each row's plant by the documented rules.

Each refusal test plants a defect in the catalog, a scoped source, a model
source or the kernel package, through the reader and package root `check`
takes, and asserts the refusal that names it, so each documented refusal
has a test that fails when its check is removed. The other `check` tests
check that the committed catalog and correct variants pass with the documented
report, that the command and `main` print the report and return its exit
code, that an unreadable input exits 2, that a symlink loop in the kernel
package exits 2 or is refused, how the matcher reads sites and ops, and
that `CLAUSES`, which maps each refusal name the script's header lists to
tests that plant it, covers the header and names tests that assert that
refusal.

`RunCommand` drives the `run` command line over a disposable clone, with a
stub `cargo` and `rustc` on PATH and a stub GenMC lane that writes planted
case output, and asserts each verdict, refusal, exit, report field and the
restore of every plant. `Verdicts` checks the process handling and the loom
and GenMC result rules directly, the GenMC ones through the real
`judge_case`. Neither runs a model.
"""

import contextlib
import copy
import hashlib
import importlib.util
import inspect
import io
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/weaken-orderings.py"
SPEC = importlib.util.spec_from_file_location("weaken_orderings", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("test-weaken-orderings: scripts/weaken-orderings.py cannot be loaded")
WEAKEN = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(WEAKEN)
try:
    CATALOG = json.loads((ROOT / WEAKEN.CATALOG).read_text())
    CATALOG_PACKAGE = json.loads((ROOT / WEAKEN.GENMC).read_text())["package"]
except (OSError, ValueError, KeyError) as error:
    raise SystemExit(f"test-weaken-orderings: unreadable catalog or declaration: {error}") from error
GENMC_FIXTURE = WEAKEN.load("test-judge-genmc")
FILL = "crates/kestrike/src/storage/fill.rs"
GRACE = "crates/kestrike/src/storage/grace.rs"
CREDIT = "crates/kestrike/src/storage/credit.rs"
STORAGE = "crates/kestrike/src/storage/mod.rs"
FILL_MODEL = "storage::fill_model::"
REVISION = "0" * 40
ANCHOR = "pub(crate) fn observe<W: FillWord>"
UNPIN = "pub(crate) fn unpin<W: EraWord>(record: &W) {"
CONTROL = FILL_MODEL + "negative_control_a_relaxed_departure_loses_the_owners_last_write"
# Each disposition fixture names one or more positive tests and quotes a failure from the corresponding model or kernel source.
DEPARTED = {"lane": "loom", "tests": [FILL_MODEL + "two_owners_on_one_key_and_a_servicer",
                                      FILL_MODEL + "three_participants_over_two_keys_reach_the_serial_maximum"],
            "failure": "a departed record whose owner had not ended"}
FOLLOWER = {"lane": "genmc", "tests": ["join-production"], "failure": "a follower saw the departure without its terminal"}
FREED = {"lane": "genmc", "tests": ["join-production"], "failure": "a follower's record was freed or reissued under it"}
CUTOFF = {"lane": "genmc", "tests": ["cutoff-pinfirst"],
          "failure": "protection violated: a scan after the close missed an admitted interval's live pin"}
TERMINAL = {"lane": "genmc", "tests": ["terminal-own"],
            "failure": "a copy of the terminal removal's bare store was accepted under the old sequence"}
TORN = {"lane": "loom", "tests": ["index::scan_model::readers_return_no_copy_or_a_copy_of_one_stable_state_across_an_insert"],
        "failure": "torn copy of"}
CLAUSES = {
    "unrowed site": ["test_a_new_acquire_load_without_a_row_is_refused_by_file_and_token", "test_a_new_fence_without_a_row_is_refused",
                     "test_a_site_after_a_test_only_element_is_a_site",
                     "test_an_ordering_nested_in_a_fence_named_call_is_its_own_site", "test_a_hook_with_a_body_is_a_fence_site"],
    "site rows": ["test_a_site_in_two_rows_is_refused", "test_an_acqrel_site_needs_a_row_to_acquire_and_a_row_to_release"],
    "find": ["test_a_cataloged_release_weakened_in_the_source_is_refused_by_row", "test_an_emptied_fill_forwarder_is_refused",
             "test_a_find_that_occurs_twice_is_refused", "test_an_empty_scoped_file_refuses_each_of_its_rows",
             "test_a_find_that_holds_two_sites_is_refused", "test_a_find_whose_site_moved_to_a_comment_holds_no_site",
             "test_an_ordering_nested_in_a_fence_named_call_is_its_own_site"],
    "step": ["test_a_replace_that_weakens_seqcst_to_relaxed_is_refused", "test_an_op_the_matcher_reads_otherwise_is_refused",
             "test_a_site_whose_op_the_matcher_cannot_read_is_refused", "test_a_fence_row_that_keeps_the_call_is_refused",
             "test_a_rooted_fence_row_deletes_the_whole_path", "test_a_strength_constant_takes_its_op_from_the_code",
             "test_a_strength_constant_passed_to_two_ops_is_unread"],
    "spelling": ["test_a_hidden_spelling_of_an_ordering_is_refused", "test_a_forwarder_that_passes_another_fence_is_refused",
                 "test_a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused",
                 "test_a_test_only_element_the_matcher_cuts_is_refused"],
    "scope file": ["test_a_production_file_the_package_includes_and_files_lacks_is_refused",
                   "test_a_listed_file_the_package_does_not_include_is_refused", "test_an_unreadable_scope_file_is_refused",
                   "test_a_module_declaration_inside_a_macro_is_refused", "test_a_module_declared_by_a_raw_identifier_loads_its_file",
                   "test_a_declaration_in_an_inline_module_loads_from_that_modules_directory",
                   "test_an_include_macro_in_a_package_source_is_refused",
                   "test_a_file_declared_only_from_another_directory_is_refused",
                   "test_an_included_file_is_classified_through_its_chain_to_the_crate_root",
                   "test_a_scoped_file_that_loads_other_source_is_refused",
                   "test_an_include_outside_the_repository_is_refused", "test_a_parent_that_declares_a_file_by_path_makes_it_production",
                   "test_a_path_attribute_the_include_scanner_misses_is_refused", "test_a_directory_module_is_classified_by_its_parent",
                   "test_an_include_no_module_file_declares_is_refused", "test_a_crate_root_or_another_directory_declares_an_include"],
    "reference": ["test_an_unknown_binding_is_refused", "test_a_binding_of_another_file_is_refused",
                  "test_a_binding_of_another_operation_in_the_same_file_is_refused",
                  "test_a_twin_that_is_no_control_is_refused", "test_two_twins_in_one_lane_are_refused",
                  "test_a_kill_row_naming_a_loom_control_is_refused", "test_an_entry_naming_a_violation_case_or_a_control_is_refused",
                  "test_a_control_also_listed_under_tests_is_no_positive_test", "test_a_refused_path_or_test_is_never_read",
                  "test_a_loom_failure_in_no_string_literal_is_refused", "test_a_loom_failure_only_an_attribute_holds_is_refused",
                  "test_a_loom_failure_two_message_literals_hold_is_refused",
                  "test_a_loom_failure_another_message_literal_extends_is_refused",
                  "test_a_loom_test_whose_model_source_cannot_be_read_is_refused",
                  "test_a_genmc_failure_that_is_no_one_check_message_is_refused",
                  "test_a_genmc_failure_spelled_c_only_in_a_comment_is_refused"],
    "disposition": ["test_a_row_with_two_dispositions_or_none_is_refused", "test_a_survives_row_with_an_empty_reason_is_refused",
                    "test_a_disposition_entry_without_its_fields_is_refused",
                    "test_a_disposition_that_names_no_run_is_refused_outside_the_unmodeled_rows"],
    "enclosing item": ["test_a_find_moved_out_of_its_enclosing_item_is_refused", "test_a_scope_that_resolves_to_two_bodies_is_refused",
                       "test_a_row_without_an_enclosing_item_is_refused", "test_a_find_moved_into_a_nested_item_is_refused",
                       "test_a_binding_of_another_operation_in_the_same_file_is_refused"],
    "revision": ["test_a_decided_row_without_a_revision_is_refused"],
    "row": ["test_a_repeated_row_id_is_refused", "test_a_malformed_row_is_refused_by_name"],
}


def reader(overrides):
    """A reader that returns each override by path, raises one that is an exception, and reads the committed file
    otherwise."""
    def read(path):
        if path not in overrides:
            return WEAKEN.read_repo(path)
        if isinstance(overrides[path], Exception):
            raise overrides[path]
        return overrides[path]
    return read


def source(path, old, new):
    text = WEAKEN.read_repo(path)
    if text.count(old) != 1:
        raise AssertionError(f"{old!r} occurs {text.count(old)} times in {path}")
    return text.replace(old, new)


def catalog_with(change):
    planted = copy.deepcopy(CATALOG)
    change(planted)
    return json.dumps(planted)


def row(catalog, name):
    return next(entry for entry in catalog["rows"] if entry["id"] == name)


def decided(catalog, name, kind, value):
    """Set row `name`'s disposition, whichever it holds, to `kind` with `value` and a revision."""
    planted = row(catalog, name)
    for key in WEAKEN.DISPOSITIONS:
        planted.pop(key, None)
    planted["revision"] = REVISION
    planted[kind] = copy.deepcopy(value)


def needing(catalog, name, needs):
    """Set row `name`'s disposition, whichever it holds, to `unrun` with `needs`."""
    planted = row(catalog, name)
    for key in (*WEAKEN.DISPOSITIONS, "revision"):
        planted.pop(key, None)
    planted["unrun"] = {"needs": copy.deepcopy(needs)}


def survived(catalog):
    """Set every row to `survives`, with the tests of its `needs` as `passed`: none for a row of `UNMODELED`."""
    for entry in catalog["rows"]:
        passed = [{"lane": need["lane"], "tests": need["tests"]} for need in entry["unrun"]["needs"]]
        decided(catalog, entry["id"], "survives", {"reason": "planted", "passed": passed})


def planted_row(**fields):
    """An unrun row for FILL beside the committed rows, with `fields` over its defaults."""
    return {"id": "planted", "path": FILL, "op": "fence", "scope": ["fn extra"], "unrun": {"needs": [DEPARTED]}, **fields}


class Check(unittest.TestCase):
    def refused(self, refusal, text, read, root=ROOT):
        report, code = WEAKEN.check(read, root)
        self.assertEqual(code, 1, report)
        self.assertIs(report.get("credited"), False)
        messages = [entry["message"] for entry in report["refusals"] if entry["refusal"] == refusal]
        self.assertTrue(any(text in message for message in messages), report["refusals"])

    def with_catalog(self, change):
        return reader({WEAKEN.CATALOG: catalog_with(change)})

    def with_source(self, path, old, new):
        return reader({path: source(path, old, new)})

    def test_the_committed_catalog_holds_29_unrun_rows_and_credits_nothing(self):
        report, code = WEAKEN.check()
        self.assertEqual((code, report["refusals"]), (0, []))
        self.assertEqual(len(report["rows"]), 29)
        self.assertEqual(set(report["rows"].values()), {"unrun"})
        self.assertEqual(sorted(report["rows"]), report["unrun"])
        self.assertEqual(report["sites"], 29)
        self.assertIs(report["credited"], False)
        self.assertEqual(report["excluded"], ["crates/kestrike/src/storage/credit_steps.rs"])
        steps = {name: [twin["steps"] for twin in row(CATALOG, name)["twin"]] for name in ("grace-bump", "grace-start")}
        self.assertEqual(steps, {"grace-bump": [3, 3], "grace-start": [2, 2]})
        self.assertEqual({entry["id"] for entry in CATALOG["rows"] if not entry["unrun"]["needs"]}, set(WEAKEN.UNMODELED))
        self.assertEqual(len(WEAKEN.UNMODELED), 4)
        for name in WEAKEN.UNMODELED:
            self.assertTrue(row(CATALOG, name)["unrun"]["reason"].strip(), name)

    def test_a_catalog_with_every_row_decided_and_none_refused_credits(self):
        report, code = WEAKEN.check(self.with_catalog(survived))
        self.assertEqual((code, report["refusals"], report["unrun"], report["credited"]), (0, [], [], True))

        def refused_one(catalog):
            survived(catalog)
            row(catalog, "grace-visit")["revision"] = "planted"
        report, code = WEAKEN.check(self.with_catalog(refused_one))
        self.assertEqual((code, report["unrun"], report["credited"]), (1, [], False))

    def test_a_kill_and_a_survivor_with_passed_tests_are_accepted(self):
        def change(catalog):
            survived(catalog)
            decided(catalog, "fill-observe", "kill", [DEPARTED, FOLLOWER])
            decided(catalog, "row-observers", "kill", [FREED])
            decided(catalog, "fill-depart-release", "survives",
                    {"reason": "planted", "passed": [{"lane": "loom", "tests": DEPARTED["tests"]}, {"lane": "genmc", "tests": ["join-production"]}]})
        report, code = WEAKEN.check(self.with_catalog(change))
        self.assertEqual((code, report["refusals"], report["unrun"], report["credited"]), (0, [], [], True))
        self.assertEqual([report["rows"][name] for name in ("fill-observe", "row-observers", "fill-depart-release")],
                         ["kill", "kill", "survives"])

    def test_the_command_prints_the_report_and_writes_nothing(self):
        def status(*args):
            return subprocess.run(["git", "--no-optional-locks", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=all", *args],
                                  capture_output=True, text=True, check=True).stdout

        def snapshot():
            return status(), status("--ignored", "--", "scripts", "verification", "evidence")
        before = snapshot()
        with tempfile.TemporaryDirectory() as work:
            run = subprocess.run([sys.executable, str(SCRIPT), "check"], cwd=work, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(run.stdout), WEAKEN.check()[0])
            self.assertEqual(list(Path(work).iterdir()), [])
        self.assertEqual(snapshot(), before)

    def test_main_prints_only_the_report_and_returns_its_exit_code(self):
        for report, code in (({"refusals": [{"refusal": "find", "message": "planted"}], "credited": False}, 1),
                             ({"error": "unreadable catalog or declaration: planted"}, 2)):
            with self.subTest(code=code):
                out = io.StringIO()
                with mock.patch.object(WEAKEN, "check", return_value=(report, code)), contextlib.redirect_stdout(out):
                    self.assertEqual(WEAKEN.main(["check"]), code)
                self.assertEqual(json.loads(out.getvalue()), report)

    def test_a_helper_that_cannot_load_or_a_usage_error_exits_2(self):
        with tempfile.TemporaryDirectory() as work:
            (Path(work) / "scripts").mkdir()
            shutil.copy(SCRIPT, Path(work) / "scripts")
            run = subprocess.run([sys.executable, str(Path(work) / "scripts" / SCRIPT.name), "check"],
                                 cwd=work, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 2, run.stderr)
            self.assertIn("classify-atomics.py cannot be loaded", json.loads(run.stdout)["error"])
        run = subprocess.run([sys.executable, str(SCRIPT), "bogus"], capture_output=True, text=True, check=False)
        self.assertEqual((run.returncode, run.stdout), (2, ""))
        self.assertIn("usage:", run.stderr)
        run = subprocess.run([sys.executable, str(SCRIPT), "--help"], capture_output=True, text=True, check=False)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("`check` refuses, each by name:", run.stdout)

    def test_a_new_acquire_load_without_a_row_is_refused_by_file_and_token(self):
        read = self.with_source(FILL, ANCHOR, "pub(crate) fn peek(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n\n" + ANCHOR)
        self.refused("unrowed site", f"{FILL}:", read)
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", read)
        trailing = "pub(crate) fn peek(state: &AtomicU64, #[cfg(test)] probe: u8) -> u64 {\n    state.load(Ordering::Acquire)\n}\n\n"
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", self.with_source(FILL, ANCHOR, trailing + ANCHOR))
        generic = "pub(crate) fn peek<A, #[cfg(test)] B>(state: &AtomicU64) -> u64 {\n    state.load(Ordering::Acquire)\n}\n\n"
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", self.with_source(FILL, ANCHOR, generic + ANCHOR))

    def test_the_command_exits_1_and_prints_the_refusing_report(self):
        with tempfile.TemporaryDirectory() as work:
            shutil.copytree(ROOT / "scripts", Path(work) / "scripts", ignore=shutil.ignore_patterns("__pycache__"))
            shutil.copytree(ROOT / "verification", Path(work) / "verification", ignore=shutil.ignore_patterns("target"))
            run = subprocess.run([sys.executable, str(Path(work) / "scripts" / SCRIPT.name), "check"],
                                 cwd=work, capture_output=True, text=True, check=False)
            self.assertEqual(run.returncode, 1, run.stderr)
            report = json.loads(run.stdout)
            self.assertIs(report["credited"], False)
            self.assertIn({"refusal": "scope file", "message": f"{FILL} is listed and the kernel package includes no production file there"},
                          report["refusals"])

    def test_a_refused_path_or_test_is_never_read(self):
        spied = []
        slot, spy = "crates/kestrike/src/storage/slot.rs", "storage::spy_model::a_test"
        planted = catalog_with(lambda catalog: (catalog["files"].append(slot),
                                                needing(catalog, "fill-observe", [dict(DEPARTED, tests=[spy])])))

        def read(path):
            spied.append(path)
            return planted if path == WEAKEN.CATALOG else WEAKEN.read_repo(path)
        self.refused("reference", f"{spy} is no positive loom test", read)
        self.assertNotIn(slot, spied)
        self.assertFalse([path for path in spied if "spy_model" in path], spied)

    def test_a_new_fence_without_a_row_is_refused(self):
        for call in ("std::sync::atomic::fence(Ordering::SeqCst);", "std::sync::atomic::compiler_fence(Ordering::Release);",
                     "::std::sync::atomic::fence(Ordering::SeqCst);",
                     "<W as FillWord>::acquire_fence();", "<W as Into<u8>>::acquire_fence();", "W::fence_clear();"):
            with self.subTest(call=call):
                read = self.with_source(FILL, ANCHOR, f"fn extra<W: FillWord>() {{\n    {call}\n}}\n\n" + ANCHOR)
                self.refused("unrowed site", f"{call} lies in no row's find", read)

    def test_a_rooted_fence_row_deletes_the_whole_path(self):
        call = "::std::sync::atomic::fence(Ordering::SeqCst);"
        text = source(FILL, ANCHOR, f"fn extra() {{\n    {call}\n}}\n\n" + ANCHOR)

        def planted(replace):
            return reader({FILL: text, WEAKEN.CATALOG: catalog_with(lambda catalog: catalog["rows"].append(
                planted_row(find=call, replace=replace)))})
        report, code = WEAKEN.check(planted(""))
        self.assertEqual((code, report["refusals"]), (0, []))
        self.refused("step", "planted: its replace is not its find after one fence step", planted("::"))

    def test_an_ordering_inside_a_comment_or_a_test_item_is_no_site(self):
        read = self.with_source(FILL, ANCHOR, "// state.load(Ordering::Acquire)\n#[cfg(test)]\nfn peek(state: &AtomicU64) -> u64 {\n"
                                "    state.load(Ordering::Acquire)\n}\n\n" + ANCHOR)
        self.assertEqual(WEAKEN.check(read)[0]["refusals"], [])

    def test_a_site_after_a_test_only_element_is_a_site(self):
        load = "state.load(Ordering::Acquire)"
        plants = {
            "a generic parameter after a braced const argument":
                f"pub(crate) trait Planted<T: Bound<{{ true }}>, #[cfg(test)] U> {{\n    fn peek(state: &AtomicU64) -> u64 {{\n        {load}\n    }}\n}}\n",
            "an arm after an arm that holds `||`":
                f"fn ready(state: &AtomicU64, a: bool, b: bool, n: u64) -> bool {{\n    match n {{\n        0 => a || b,\n        #[cfg(test)]\n"
                f"        1 => n < 2,\n        _ => {load} == n,\n    }}\n}}\n",
            "a field after a field that holds `||`":
                f"fn probe(state: &AtomicU64) -> S {{\n    S {{ a: x || y, #[cfg(test)] probe: n < 2, live: {load} }}\n}}\n",
        }
        for label, text in plants.items():
            with self.subTest(label=label):
                self.refused("unrowed site", "Ordering::Acquire lies in no row's find", self.with_source(FILL, ANCHOR, text + "\n" + ANCHOR))

    def test_an_ordering_nested_in_a_fence_named_call_is_its_own_site(self):
        call = "record_fence_epoch(state.load(Ordering::Acquire));"
        text = source(FILL, ANCHOR, f"fn extra(state: &AtomicU64) {{\n    {call}\n}}\n\n" + ANCHOR)
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", reader({FILL: text}))
        whole = catalog_with(lambda catalog: catalog["rows"].append(planted_row(find=call, replace="")))
        self.refused("find", "planted: its find holds 2 sites", reader({FILL: text, WEAKEN.CATALOG: whole}))
        computed = "std::sync::atomic::fence(order_of(state.load(Ordering::Acquire)));"
        read = self.with_source(FILL, ANCHOR, f"fn extra(state: &AtomicU64) {{\n    {computed}\n}}\n\n" + ANCHOR)
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", read)

    def test_a_hook_with_a_body_is_a_fence_site(self):
        body = "    fn fence_pin() {\n        std::sync::atomic::fence(Ordering::SeqCst);\n    }"
        fence = "std::sync::atomic::fence(Ordering::SeqCst);"
        plants = (("a default with a body", source(GRACE, "    fn fence_pin() {}", body), ["fn fence_pin"]),
                  ("a production override", source(GRACE, "impl Strength for Sequential {", "impl Strength for Sequential {\n" + body),
                   ["impl Strength for Sequential", "fn fence_pin"]))
        for label, text, scope in plants:
            with self.subTest(label=label):
                rowed = catalog_with(lambda catalog, scope=scope: catalog["rows"].append(
                    planted_row(path=GRACE, find=fence, replace="", scope=scope)))
                self.refused("unrowed site", "S::fence_pin(); lies in no row's find", reader({GRACE: text, WEAKEN.CATALOG: rowed}))
        for label, definition in (("no definition", ""), ("a declaration", "trait Hooks {\n    fn fence_pin();\n}\n")):
            with self.subTest(label=label):
                read = self.with_source(FILL, ANCHOR, f"{definition}fn extra<S: Strength>() {{\n    S::fence_pin();\n}}\n\n" + ANCHOR)
                self.refused("unrowed site", "S::fence_pin(); lies in no row's find", read)

    def test_a_hidden_spelling_of_an_ordering_is_refused(self):
        for spelling in ("use std::sync::atomic::Ordering::{Acquire};", "use std::sync::atomic::Ordering::*;",
                         "use std::sync::atomic::Ordering as O;", "type O = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::Acquire) }",
                         "type O<'a> = Ordering;\nfn peek(s: &AtomicU64) -> u64 { s.load(O::SeqCst) }",
                         "fn peek(s: &AtomicU64) -> u64 { s.load(<Ordering>::Acquire) }",
                         "fn peek(s: &AtomicU64) -> u64 { s.load(<std::sync::atomic::Ordering>::Acquire) }",
                         "fn peek(s: &AtomicU64) -> u64 { s.load(Ordering::r#Acquire) }",
                         "macro_rules! o { ($t:ident) => { $t::SeqCst }; }",
                         "fn peek<W: FillWord>() { let f = W::acquire_fence; f(); }", "fn peek<W: FillWord>() { (W::acquire_fence)(); }",
                         "fn peek() { std::convert::identity(std::sync::atomic::fence); }",
                         "fn peek(order: Ordering) { apply(order, std::sync::atomic::fence); }",
                         "fn peek(word: &W) { word.acquire_fence(); }",
                         "fn peek() { $crate::x::settle_fence(); }", "fn peek<W>() { <W as Foo<Bar<Baz>>>::acquire_fence(); }"):
            with self.subTest(spelling=spelling):
                self.refused("spelling", "hides", self.with_source(FILL, ANCHOR, spelling + "\n" + ANCHOR))

    def test_a_forwarder_that_passes_another_fence_is_refused(self):
        invocation = "forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);"
        swapped = "forward_fill_word!(std::sync::atomic::AtomicU64, settle);"
        plants = (
            ("another function", swapped, "forward_fill_word! holds a $fence call, and 0 of its 1 production invocations"),
            ("a hand-written impl", "impl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}",
             "forward_fill_word! holds a $fence call, and 0 of its 0 production invocations"),
            ("a decoy macro", swapped + "\nstringify!(u8, std::sync::atomic::fence);",
             "stringify! receives std::sync::atomic::fence and holds no $fence call"),
            ("a decoy macro beside the swap", swapped + "\nstringify!(u8, std::sync::atomic::fence);",
             "forward_fill_word! holds a $fence call, and 0 of its 1 production invocations"),
            ("a $fence call outside a macro", invocation + "\nfn stray() {\n    $fence(Ordering::Acquire);\n}",
             "a $fence call lies in no macro_rules! body"),
            ("a bracket invocation beside the canonical one", invocation + "\nforward_fill_word![std::sync::atomic::AtomicU32, settle];",
             "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations"),
            ("a brace invocation beside the canonical one", invocation + "\nforward_fill_word! {std::sync::atomic::AtomicU32, settle}",
             "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations"),
            ("a spaced-bang invocation beside the canonical one", invocation + "\nforward_fill_word ! (std::sync::atomic::AtomicU32, settle);",
             "forward_fill_word! holds a $fence call, and 1 of its 2 production invocations"),
            ("the canonical invocation in an arm of another macro",
             "impl FillWord for std::sync::atomic::AtomicU64 {\n    fn acquire_fence() {}\n}\n"
             f"macro_rules! spare {{\n    (unused) => {{\n        {invocation}\n    }};\n    () => {{}};\n}}\nspare!();",
             "forward_fill_word! is invoked among another macro's tokens"),
        )
        for label, new, message in plants:
            with self.subTest(label=label):
                self.refused("spelling", f"{FILL}: ", self.with_source(FILL, invocation, new))
                self.refused("spelling", message, self.with_source(FILL, invocation, new))
        fill = WEAKEN.read_repo(FILL)
        forwarder = fill[fill.index("macro_rules! forward_fill_word {"):fill.index(invocation) + len(invocation)]
        for name in ("spare", "r#spare"):
            with self.subTest(label=f"the definition and its invocation in an arm of macro {name}"):
                arm = (f"impl FillWord for std::sync::atomic::AtomicU64 {{\n    fn acquire_fence() {{}}\n}}\n"
                       f"macro_rules! {name} {{\n    (unused) => {{\n{forwarder}\n    }};\n    () => {{}};\n}}\nspare!();")
                self.refused("spelling", "spare! holds a $fence call, and 0 of its 1 production invocations", reader({FILL: fill.replace(forwarder, arm)}))

    def test_a_forwarder_that_is_not_one_arm_its_invocations_directly_follow_is_refused(self):
        # Each plant leaves the cataloged `$fence` call in text that the production invocation does not expand, or
        # binds `$fence` to an argument other than the std fence, while the invocation still passes
        # `std::sync::atomic::fence`.
        header = "macro_rules! forward_fill_word {\n    ($atomic:ty, $fence:path) => {\n        impl FillWord for $atomic {"
        footer = "        }\n    };\n}\n\nforward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);"
        invocation = "forward_fill_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);"
        fence = "            #[inline(always)]\n            fn acquire_fence() {\n                $fence(Ordering::Acquire);\n            }\n\n"
        spare = "macro_rules{bang} {name} {open}\n    ($atomic:ty, $fence:path) => {{\n        impl Spare for $atomic {{}}\n    }};\n{close}\n"
        fill = WEAKEN.read_repo(FILL)
        for anchor in (header, footer, invocation, fence):
            self.assertEqual(fill.count(anchor), 1, anchor)
        plants = {
            "swapped parameters": [(header, header.replace("($atomic:ty, $fence:path)", "($fence:path, $_unused:path)")
                                    .replace("for $atomic", "for std::sync::atomic::AtomicU64")),
                                   (invocation, "fn noop<T>(_: T) {}\nforward_fill_word!(noop, std::sync::atomic::fence);")],
            "the fence in a second arm that no invocation matches":
                [(fence, ""), (footer, footer.replace("    };\n}", "    };\n    (unused, $fence:path) => {\n        fn acquire_fence() {\n"
                                                      "            $fence(Ordering::Acquire);\n        }\n    };\n}"))],
            "a catch-all arm before the arm": [(header, header.replace("    ($atomic", "    ($atomic:ty, $($rest:tt)*) => {};\n    ($atomic"))],
            "a literal arm before the arm":
                [(header, header.replace("    ($atomic", "    (std::sync::atomic::AtomicU64, $other:path) => {};\n    ($atomic"))],
            "an arm after the arm": [(footer, footer.replace("    };\n}", "    };\n    () => {};\n}"))],
            "a third parameter": [(header, header.replace("$fence:path)", "$fence:path, $spare:path)"))],
        }
        for label, (bang, name, open_, close) in (("a second definition", ("!", "forward_fill_word", "{", "}")),
                                                    ("a second definition with a spaced bang", (" !", "forward_fill_word", "{", "}")),
                                                    ("a second definition in parentheses", ("!", "forward_fill_word", "(", ");")),
                                                    ("a second definition named by a raw identifier", ("!", "r#forward_fill_word", "{", "}"))):
            plants[label] = [(invocation, spare.format(bang=bang, name=name, open=open_, close=close) + invocation)]
        definition = fill[fill.index("macro_rules! forward_fill_word {"):fill.index(invocation)]
        plants["the definition after its invocation"] = [(definition, ""), (invocation, invocation + "\n\n" + definition.rstrip())]
        plants["the definition in an inline module"] = [(definition, "mod forwarders {\n" + definition + "}\n\n")]
        plants["an invocation through a path"] = [(invocation, invocation.replace("forward_fill_word!", "forwarders::forward_fill_word!"))]
        plants["an item between the definition and its invocation"] = [(invocation, "const SPARE: u8 = 0;\n" + invocation)]
        for label, edits in plants.items():
            with self.subTest(label=label):
                text = fill
                for old, new in edits:
                    text = text.replace(old, new)
                self.assertNotEqual(text, fill)
                self.refused("spelling", f"{FILL}: forward_fill_word! is not one arm ($name:ty, $fence:path) => {{..}} that its "
                                         "production invocations directly follow", reader({FILL: text}))
        sequence = "crates/kestrike/src/index/sequence.rs"
        split = source(sequence, "macro_rules! forward_seq_word {\n", "macro_rules! forward_seq_word {\n    () => {};\n")
        self.refused("spelling", f"{sequence}: forward_seq_word! is not one arm", reader({sequence: split}))
        accepted = {
            "another name for the type parameter": fill.replace("$atomic", "$word"),
            "the arm without its `;`": fill.replace(footer, footer.replace("    };\n}", "    }\n}")),
            "a comment before the arm and a reflowed header":
                fill.replace(header, header.replace("    ($atomic:ty, $fence:path) =>", "    // The arm.\n    (\n        $atomic:ty,\n        $fence:path\n    ) =>")),
            "a second invocation after a comment":
                fill.replace(invocation, invocation + "\n// Another word.\nforward_fill_word!(std::sync::atomic::AtomicUsize, std::sync::atomic::fence);"),
        }
        for label, text in accepted.items():
            with self.subTest(label=label):
                self.assertNotEqual(text, fill)
                report, code = WEAKEN.check(reader({FILL: text}))
                self.assertEqual((code, report["refusals"], report["sites"]), (0, [], 29))

    def test_a_test_only_element_the_matcher_cuts_is_refused(self):
        visit = "    const VISIT: Ordering = Ordering::SeqCst;\n"
        weak = "    #[cfg(not(test))]\n    const VISIT: Ordering = Ordering::Relaxed;\n"
        nested = "        const VISIT: Ordering = Ordering::SeqCst;\n        VISIT\n"
        store = "    record.store(INACTIVE, Ordering::Release);\n}"
        relaxed = "    record.store(INACTIVE, Ordering::Relaxed);\n}"
        load = "    decode(state.load(Ordering::Acquire), next_serial)\n}"
        plants = {
            "an arm with an or-pattern after an arm with an or-pattern":
                (FILL, ANCHOR, "fn extra(n: u8) -> u8 {\n    match n {\n        2 | 3 => 2,\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n"
                               "    }\n}\n\n" + ANCHOR),
            "a statement cut at a comma among its own generic arguments":
                (GRACE, store, "    #[cfg(test)]\n    pick::<u8, u8>({ record.store(INACTIVE, Ordering::Release); 1 });\n" + relaxed),
            "an assignment cut at a comma among its own closure parameters":
                (GRACE, store, "    #[cfg(test)]\n    hook = |a, b| { record.store(INACTIVE, Ordering::Release); };\n" + relaxed),
            "a fn-pointer field cut at a comma among its own generic arguments":
                (GRACE, store, "    struct _S(#[cfg(test)] fn() -> W<u8, { record.store(INACTIVE, Ordering::Release); 1 }>, u8);\n" + relaxed),
            "a first arm cut at a comma among its own generic arguments":
                (FILL, load, "    match next_serial {\n        #[cfg(test)]\n        0 => pick::<u8, u8>(decode(state.load(Ordering::Acquire), next_serial)),\n"
                             "        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}"),
            "a parameter among a macro's tokens":
                (FILL, ANCHOR, "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) { state.load(Ordering::Relaxed); });\n\n" + ANCHOR),
            "a generic parameter": (FILL, ANCHOR, "fn extra<A, #[cfg(test)] B>(a: A) -> A {\n    a\n}\n\n" + ANCHOR),
            "a statement cut at the comma of its closure parameters":
                (FILL, ANCHOR, "fn extra() {\n    #[cfg(test)]\n    let sum = |a, b| a + b;\n}\n\n" + ANCHOR),
            "a tuple element cut at the comma of its generic arguments":
                (GRACE, "    record.store(INACTIVE, Ordering::Release);\n}",
                 "    let _ = (a | b, #[cfg(test)] if pick::<u8, u8>() { record.store(INACTIVE, Ordering::Release); 1 } else { 2 });\n"
                 "    record.store(INACTIVE, Ordering::Relaxed);\n}"),
        }
        for label, (path, old, new) in plants.items():
            with self.subTest(label=label):
                self.refused("spelling", "a test-only element whose end the matcher reads more than one way", self.with_source(path, old, new))
        self.refused("unrowed site", "Ordering::Acquire lies in no row's find", self.with_source(
            FILL, ANCHOR, "with_probe!(; #[cfg(test)] B> fn extra(state: &AtomicU64) { state.load(Ordering::Acquire); });\n\n" + ANCHOR))
        # A test-only element in item, statement or first-arm position is blanked whole, so text it alone holds is gone.
        compared = weak + "    #[cfg(test)]\n    const VISIT: Ordering = if 1 > 0 {\n" + nested + "    } else {\n        Ordering::Relaxed\n    };\n"
        arm = ("    match next_serial {\n        #[cfg(test)]\n        0 | 1 => decode(state.load(Ordering::Acquire), next_serial),\n"
               "        _ => decode(state.load(Ordering::Relaxed), next_serial),\n    }\n}")
        whole = weak + "    #[cfg(test)]\n    const VISIT: Ordering = Ordering::SeqCst;\n"
        for label, (path, old, new, row) in {"a const whose initializer holds a comparison": (GRACE, visit, compared, "grace-visit"),
                                             "an or-pattern first arm that holds a row's find": (FILL, load, arm, "fill-observe"),
                                             "a const": (GRACE, visit, whole, "grace-visit")}.items():
            with self.subTest(label=label):
                self.refused("find", f"{row}: its find occurs 0 times", self.with_source(path, old, new))
                report = WEAKEN.check(self.with_source(path, old, new))[0]
                self.assertEqual([entry for entry in report["refusals"] if entry["refusal"] == "spelling"], [])
        first = "fn extra(n: u8) -> u8 {\n    match n {\n        #[cfg(test)]\n        0 | 1 => 1,\n        _ => 0,\n    }\n}\n\n"
        report, code = WEAKEN.check(self.with_source(FILL, ANCHOR, first + ANCHOR))
        self.assertEqual((code, report["refusals"]), (0, []))
        inner = "#[cfg(test)]\nmod probes {\n    #[cfg(all(test, loom))]\n    const ROOM: usize = 1 << 12;\n}\n\n"
        report, code = WEAKEN.check(self.with_source(FILL, ANCHOR, inner + ANCHOR))
        self.assertEqual((code, report["refusals"]), (0, []))
        for label, whole in (("an extern fn with a comma in its generics", '#[cfg(test)]\nextern "C" fn probe<A, B>() {}\n\n'),
                             ("an extern fn with no ABI", "#[cfg(test)]\nextern fn probe<A, B>() {}\n\n")):
            with self.subTest(label=label):
                report, code = WEAKEN.check(self.with_source(FILL, ANCHOR, whole + ANCHOR))
                self.assertEqual((code, report["refusals"]), (0, []))

    def test_the_text_of_a_test_only_element_after_its_first_block_is_a_stated_limit(self):
        # Each plant weakens the production store and keeps the cataloged text after the first block of a test-only
        # element. The header lists this among the weakenings that pass; a change to where an element ends revisits it.
        store = "    record.store(INACTIVE, Ordering::Release);\n}"
        weak = "    record.store(INACTIVE, Ordering::Relaxed);\n}"
        for label, kept in (("the else of an if", "let _ = if skip() { 0 } else { record.store(INACTIVE, Ordering::Release); 1 };"),
                            ("a loop body after a struct pattern", "for Probe { n } in probes() { record.store(INACTIVE, Ordering::Release); }")):
            with self.subTest(label=label):
                report, code = WEAKEN.check(self.with_source(GRACE, store, f"    #[cfg(test)]\n    {kept}\n{weak}"))
                self.assertEqual((code, report["refusals"]), (0, []))

    def test_an_ordering_type_in_a_type_position_is_no_spelling(self):
        read = self.with_source(FILL, ANCHOR, "fn pick(_: Option<Ordering>) -> Option<Ordering> {\n    None\n}\n\n" + ANCHOR)
        self.assertEqual(WEAKEN.check(read)[0]["refusals"], [])

    def test_a_path_call_compare_exchange_ordering_is_no_read_op(self):
        scanned = "AtomicU64::compare_exchange(&s, 0, 1, Ordering::SeqCst, Ordering::Acquire)"
        self.assertEqual({site.op for site in WEAKEN.sites(scanned)}, {WEAKEN.UNREAD})

    def test_a_cataloged_release_weakened_in_the_source_is_refused_by_row(self):
        read = self.with_source(GRACE, "record.store(INACTIVE, Ordering::Release);", "record.store(INACTIVE, Ordering::Relaxed);")
        self.refused("find", "grace-unpin: its find occurs 0 times", read)

    def test_an_emptied_fill_forwarder_is_refused(self):
        self.refused("find", "fill-forward-fence: its find occurs 0 times", self.with_source(FILL, "$fence(Ordering::Acquire);", ""))

    def test_a_find_that_occurs_twice_is_refused(self):
        read = self.with_source(GRACE, UNPIN, "fn spare<W: EraWord>(record: &W) {\n    // record.store(INACTIVE, Ordering::Release);\n}\n\n" + UNPIN)
        self.refused("find", "grace-unpin: its find occurs 2 times", read)

    def test_a_find_whose_site_moved_to_a_comment_holds_no_site(self):
        read = self.with_source(GRACE, "    record.store(INACTIVE, Ordering::Release);\n}",
                                "    // record.store(INACTIVE, Ordering::Release);\n    record.store(INACTIVE, Ordering::Relaxed);\n}")
        self.refused("find", "grace-unpin: its find holds 0 sites", read)

    def test_a_find_that_holds_two_sites_is_refused(self):
        def change(catalog):
            planted = row(catalog, "grace-start")
            planted["find"] = "const START: Ordering = Ordering::SeqCst;\n    const VISIT: Ordering = Ordering::SeqCst;"
            planted["replace"] = "const START: Ordering = Ordering::Acquire;\n    const VISIT: Ordering = Ordering::SeqCst;"
        self.refused("find", "grace-start: its find holds 2 sites", self.with_catalog(change))

    def test_a_replace_that_weakens_seqcst_to_relaxed_is_refused(self):
        def change(catalog):
            row(catalog, "grace-visit")["replace"] = "const VISIT: Ordering = Ordering::Relaxed;"
        self.refused("step", "grace-visit: its replace is not its find after one load step", self.with_catalog(change))

        def beyond(catalog):
            planted = row(catalog, "grace-unpin")
            planted["replace"] = planted["replace"].replace("INACTIVE", "0")
        self.refused("step", "grace-unpin: its replace is not its find after one store step", self.with_catalog(beyond))

    def test_an_op_the_matcher_reads_otherwise_is_refused(self):
        def change(catalog):
            planted = row(catalog, "grace-pin-store")
            planted["op"], planted["replace"] = "load", "const PIN_STORE: Ordering = Ordering::Acquire;"
        self.refused("step", "grace-pin-store: its site is a store, the row says load", self.with_catalog(change))

    def test_the_matcher_reads_each_compare_exchange_ordering_by_position(self):
        scanned = "s.compare_exchange(0,1,Ordering::Release,Ordering::Acquire)"
        self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites(scanned)], [("Release", "rmw"), ("Acquire", "load")])
        scanned = "s.fetch_update(Ordering::SeqCst, Ordering::SeqCst, f)"
        self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites(scanned)], [("SeqCst", "rmw"), ("SeqCst", "load")])
        scanned = "s.compare_exchange(word, word | BIT, Ordering::SeqCst, Ordering::Acquire)"
        self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites(scanned)], [("SeqCst", "rmw"), ("Acquire", "load")])
        scanned = "s.compare_exchange_weak(0, 1, Ordering::SeqCst, Ordering::Acquire)"
        self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites(scanned)], [("SeqCst", "rmw"), ("Acquire", "load")])
        self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites("s.swap(1, Ordering::AcqRel)")], [("AcqRel", "rmw")])

    def test_an_earlier_operand_with_angle_brackets_leaves_a_compare_exchange_ordering_unread(self):
        for method in ("compare_exchange", "compare_exchange_weak"):
            for operand in ("pack::<A, B>(x)", "a < b"):
                with self.subTest(method=method, operand=operand):
                    scanned = f"s.{method}({operand}, 1, Ordering::SeqCst, Ordering::Acquire)"
                    self.assertEqual([(site.ordering, site.op) for site in WEAKEN.sites(scanned)],
                                     [("SeqCst", WEAKEN.UNREAD), ("Acquire", WEAKEN.UNREAD)])

    def test_a_site_whose_op_the_matcher_cannot_read_is_refused(self):
        old = "map.fetch_or(bits, Ordering::SeqCst);"
        new = "let order = Ordering::SeqCst;\n    map.fetch_or(bits, order);"

        def change(catalog):
            planted = row(catalog, "credit-reset-flag")
            planted["find"], planted["replace"] = "let order = Ordering::SeqCst;", "let order = Ordering::AcqRel;"
        read = reader({CREDIT: source(CREDIT, old, new), WEAKEN.CATALOG: catalog_with(change)})
        self.refused("step", "credit-reset-flag: the matcher reads no op for its site", read)

    def test_a_strength_constant_takes_its_op_from_the_code(self):
        for op, step in (("store", "Release"), ("rmw", "AcqRel")):
            def change(catalog, op=op, step=step):
                planted = row(catalog, "credit-reload")
                planted["op"], planted["replace"] = op, f"const RELOAD: Ordering = Ordering::{step};"
            with self.subTest(op=op):
                self.refused("step", f"credit-reload: its site is a load, the row says {op}", self.with_catalog(change))
        with mock.patch.dict(WEAKEN.EXTERNAL, clear=True):
            self.refused("step", "credit-reload: the matcher reads no op for its site", WEAKEN.read_repo)

    def test_a_strength_constant_passed_to_two_ops_is_unread(self):
        for path in ("S::VISIT", "S :: VISIT"):
            with self.subTest(path=path):
                read = self.with_source(GRACE, UNPIN, f"fn spare<W: EraWord, S: Strength>(record: &W) {{\n    record.store(0, {path});\n}}\n\n" + UNPIN)
                self.refused("step", "grace-visit: the matcher reads no op for its site", read)

    def test_a_fence_row_that_keeps_the_call_is_refused(self):
        def change(catalog):
            row(catalog, "fill-forward-fence")["replace"] = "$fence(Ordering::Relaxed);"
        self.refused("step", "fill-forward-fence: its replace is not its find after one fence step", self.with_catalog(change))

    def test_a_site_in_two_rows_is_refused(self):
        def change(catalog):
            catalog["rows"].append(dict(row(catalog, "grace-visit"), id="grace-visit-again"))
        lines = WEAKEN.read_repo(GRACE).split("\n")
        line = next(number for number, text in enumerate(lines, 1) if row(CATALOG, "grace-visit")["find"] in text)
        self.refused("site rows", f"{GRACE}:{line}: Ordering::SeqCst has rows to ['Acquire', 'Acquire']", self.with_catalog(change))

    def test_an_acqrel_site_needs_a_row_to_acquire_and_a_row_to_release(self):
        new = "map.fetch_or(bits, Ordering::AcqRel);"
        credit = source(CREDIT, "map.fetch_or(bits, Ordering::SeqCst);", new)

        def one(catalog):
            planted = row(catalog, "credit-reset-flag")
            planted["find"], planted["replace"] = new, new.replace("AcqRel", "Acquire")

        def two(catalog):
            one(catalog)
            catalog["rows"].append(dict(row(catalog, "credit-reset-flag"), id="credit-reset-release", replace=new.replace("AcqRel", "Release")))

        def same(catalog):
            one(catalog)
            catalog["rows"].append(dict(row(catalog, "credit-reset-flag"), id="credit-reset-again"))

        def planted(change):
            return reader({CREDIT: credit, WEAKEN.CATALOG: catalog_with(change)})
        self.refused("site rows", "Ordering::AcqRel has rows to ['Acquire'], its steps are ['Acquire', 'Release']", planted(one))
        self.refused("site rows", "has rows to ['Acquire', 'Acquire']", planted(same))
        report, code = WEAKEN.check(planted(two))
        self.assertEqual((code, report["refusals"]), (0, []))

    def planted_package(self, work, extra, text=None):
        """A copy of the kernel package under `work` with one more source: `text`, with `{up}` the path from the
        source to the repository root, or one that includes each of `extra` by `#[path]`."""
        package = Path(work) / CATALOG_PACKAGE
        shutil.copytree(ROOT / CATALOG_PACKAGE, package, ignore=shutil.ignore_patterns("target"))
        up = "../" * len(Path(CATALOG_PACKAGE, "src").parts)
        if text is None:
            text = "".join(f'#[path = "{{up}}{path}"]\nmod m{index};\n' for index, path in enumerate(extra))
        (package / "src/planted.rs").write_text(text.replace("{up}", up))
        return Path(work)

    def test_a_production_file_the_package_includes_and_files_lacks_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, ["crates/kestrike/src/storage/slot.rs"])
            self.refused("scope file", "crates/kestrike/src/storage/slot.rs is a production file", WEAKEN.read_repo, root)

    def test_an_include_macro_in_a_package_source_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [], 'include!("{up}crates/kestrike/src/storage/slot.rs");\n')
            self.refused("scope file", "an include! macro, whose source the scope rule does not read", WEAKEN.read_repo, root)
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [], 'use std::include as inc;\ninc!("{up}crates/kestrike/src/storage/slot.rs");\n')
            self.refused("scope file", "an include! macro, whose source the scope rule does not read", WEAKEN.read_repo, root)

    def test_a_model_support_file_the_package_includes_is_excluded(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, ["crates/kestrike/src/storage/credit_model.rs", CREDIT])
            report, code = WEAKEN.check(WEAKEN.read_repo, root)
            excluded = ["crates/kestrike/src/storage/credit_model.rs", "crates/kestrike/src/storage/credit_steps.rs"]
            self.assertEqual((code, report["excluded"]), (0, excluded), report["refusals"])

    def test_a_commented_declaration_declares_nothing(self):
        planted = '// mod credit_steps;\n// #[path = "credit_steps.rs"]\nconst _DECLARED: &str = "mod credit_steps;";\nmod credit;\n'
        report, code = WEAKEN.check(reader({STORAGE: source(STORAGE, "\nmod credit;\n", "\n" + planted)}))
        self.assertEqual((code, report["excluded"]), (0, ["crates/kestrike/src/storage/credit_steps.rs"]), report["refusals"])

    def test_a_module_declaration_inside_a_macro_is_refused(self):
        moved = source(STORAGE, "\nmod fill;\n", '\n#[path = "fill_v2.rs"]\nmod fill;\n')
        committed = WEAKEN.read_repo(STORAGE)
        plants = {
            "an unexpanded definition beside a redirected module": moved + "macro_rules! decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            "a definition in parentheses": moved + "macro_rules! decoy (\n    () => {\n        mod fill;\n    };\n);\n",
            "a definition named by a raw identifier": moved + "macro_rules! r#decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            "a definition with a spaced bang": moved + "macro_rules ! decoy {\n    () => {\n        mod fill;\n    };\n}\n",
            "an invocation that drops its tokens": moved + "ignore! {\n    mod fill;\n}\n",
            "an invocation in parentheses": moved + "const _DECOY: &str = stringify!(mod fill;);\n",
            "an invoked definition beside a test-only declaration":
                committed + "macro_rules! live {\n    () => {\n        #[cfg(not(test))]\n        mod credit_steps;\n    };\n}\nlive!();\n",
            "a path attribute in a definition":
                committed + 'macro_rules! live {\n    () => {\n        #[path = "credit_steps.rs"]\n        mod steps_live;\n    };\n}\nlive!();\n',
            "a module named by a fragment":
                committed + "macro_rules! declare {\n    ($name:ident) => {\n        mod $name;\n    };\n}\ndeclare!(credit_steps);\n",
            "a module whose `;` the macro supplies": committed + "#[cfg(not(all(test, loom)))]\ndeclare!(mod credit_steps);\n",
            "a module a macro declares from an inline block":
                committed + "macro_rules! child {\n    ($kw:tt $name:ident $body:tt) => {\n        $kw $name;\n    };\n}\nchild!(mod credit_steps {});\n",
            "an inline module in a definition": committed + "macro_rules! plain {\n    () => {\n        mod inner {}\n    };\n}\nplain!();\n",
        }
        for label, text in plants.items():
            with self.subTest(label=label):
                self.refused("scope file", "a module declaration inside a macro's tokens, which the scope rule cannot read", reader({STORAGE: text}))
        plain = committed + "macro_rules! plain {\n    () => {\n        fn helper() {}\n    };\n}\nplain!();\n"
        report, code = WEAKEN.check(reader({STORAGE: plain}))
        self.assertEqual((code, report["refusals"]), (0, []))

    def test_a_declaration_in_an_inline_module_loads_from_that_modules_directory(self):
        moved = source(STORAGE, "\nmod fill;\n", '\n#[path = "fill_v2.rs"]\nmod fill;\n')
        self.refused("scope file", f"the kernel package includes {FILL} and no module file declares it",
                     reader({STORAGE: moved + "mod inner {\n    mod fill;\n}\n"}))
        committed = WEAKEN.read_repo(STORAGE)
        steps = "crates/kestrike/src/storage/credit_steps.rs"
        for label, nested in (("a nested declaration", "mod nested {\n    mod credit_steps;\n}\n"),
                              ("a nested path attribute", 'mod nested {\n    #[path = "credit_steps.rs"]\n    mod steps;\n}\n')):
            with self.subTest(label=label):
                report, code = WEAKEN.check(reader({STORAGE: committed + nested}))
                self.assertEqual((code, report["refusals"], report["excluded"]), (0, [], [steps]))
        climbing = 'mod nested {\n    mod deeper {\n        #[path = "../../credit_steps.rs"]\n        mod steps;\n    }\n}\n'
        self.refused("scope file", f"{steps} is a production file the kernel package includes and files lacks", reader({STORAGE: committed + climbing}))

    def test_a_module_declared_by_a_raw_identifier_loads_its_file(self):
        steps = "crates/kestrike/src/storage/credit_steps.rs"
        committed = WEAKEN.read_repo(STORAGE)
        for label, declaration in (("a declaration", "mod r#credit_steps;"), ("a path attribute", '#[path = "credit_steps.rs"]\nmod r#steps;'),
                                   ("an inline module", "mod r#storage {\n    #[path = \"../credit_steps.rs\"]\n    mod steps;\n}")):
            with self.subTest(label=label):
                read = reader({STORAGE: committed + f"#[cfg(not(test))]\n{declaration}\n"})
                self.refused("scope file", f"{steps} is a production file the kernel package includes and files lacks", read)
        report, code = WEAKEN.check(reader({STORAGE: source(STORAGE, "\nmod fill;\n", "\nmod r#fill;\n")}))
        self.assertEqual((code, report["refusals"]), (0, []))
        self.refused("scope file", "a module declaration inside a macro's tokens, which the scope rule cannot read",
                     reader({STORAGE: committed + "ignore! {\n    mod r#credit_steps;\n}\n"}))

    def test_a_parent_that_declares_a_file_by_path_makes_it_production(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, ["crates/kestrike/src/storage/slot.rs"])
            read = reader({STORAGE: source(STORAGE, "\nmod slot;\n", '\n#[path = "slot.rs"]\nmod slot_file;\n')})
            self.refused("scope file", "crates/kestrike/src/storage/slot.rs is a production file", read, root)

    def test_a_directory_module_is_classified_by_its_parent(self):
        include = "crates/kestrike/src/storage/planted/mod.rs"
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [include])
            read = reader({STORAGE: source(STORAGE, "\nmod slot;\n", "\nmod slot;\nmod planted;\n")})
            self.refused("scope file", f"{include} is a production file the kernel package includes and files lacks", read, root)
            read = reader({STORAGE: source(STORAGE, "\nmod slot;\n", "\nmod slot;\n#[cfg(test)]\nmod planted;\n")})
            report, code = WEAKEN.check(read, root)
            self.assertEqual(code, 0, report["refusals"])
            self.assertIn(include, report["excluded"])

    def test_a_crate_root_or_another_directory_declares_an_include(self):
        lib = "crates/kestrike/src/lib.rs"
        include = "crates/kestrike/src/planted.rs"
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [include])
            read = reader({lib: WEAKEN.read_repo(lib) + "\nmod planted;\n"})
            self.refused("scope file", f"{include} is a production file the kernel package includes and files lacks", read, root)
        steps = "crates/kestrike/src/storage/credit_steps.rs"
        read = reader({lib: WEAKEN.read_repo(lib) + '\n#[path = "storage/credit_steps.rs"]\nmod steps;\n'})
        self.refused("scope file", f"{steps} is a production file the kernel package includes and files lacks", read)
        read = reader({STORAGE: WEAKEN.read_repo(STORAGE) + '\n#[path = r"credit_steps.rs"]\nmod steps;\n'})
        self.refused("scope file", f"{STORAGE} holds a path attribute the scope rule cannot read", read)
        read = reader({STORAGE: WEAKEN.read_repo(STORAGE) + '\n#[path = "credit\\x5fsteps.rs"]\nmod steps;\n'})
        self.refused("scope file", "the path attribute holds an escape the scope rule cannot read", read)

    def test_a_file_declared_only_from_another_directory_is_refused(self):
        holder = "crates/kestrike/src/failover/reconcile_tests.rs"
        moved = source(STORAGE, "\nmod fill;\n", '\n#[path = "fill_v2.rs"]\nmod fill;\n')
        read = reader({STORAGE: moved, holder: WEAKEN.read_repo(holder) + '\n#[path = "../storage/fill.rs"]\nmod decoy;\n'})
        self.refused("scope file", f"{FILL} is declared only by a path attribute outside its module files and the crate root", read)

    def test_an_included_file_is_classified_through_its_chain_to_the_crate_root(self):
        tree = "crates/kestrike/src/mod.rs"
        steps = "crates/kestrike/src/storage/credit_steps.rs"
        storage = [path for path in CATALOG["files"] if "/storage/" in path]
        moved = source(STORAGE, "\nmod fill;\n", '\n#[path = "fill_v2.rs"]\nmod fill;\n')
        undeclared = f"the kernel package includes {FILL} and no module file declares it"
        self.refused("scope file", undeclared, reader({STORAGE: moved, "crates/kestrike/src/storage/lib.rs": "mod fill;\n"}))
        redirected = source(tree, "pub mod storage;", '#[path = "storage_v2/mod.rs"]\npub mod storage;')
        for label, extra in (("a redirected directory", {}), ("a declaration beside the source directory", {"crates/kestrike/src.rs": "mod storage;\n"})):
            with self.subTest(label=label):
                report, code = WEAKEN.check(reader({tree: redirected, **extra}))
                messages = [entry["message"] for entry in report["refusals"] if entry["refusal"] == "scope file"]
                self.assertEqual(code, 1, report)
                for path in (*storage, steps):
                    self.assertIn(f"the kernel package includes {path} and no module file declares it", " ".join(messages))
                self.assertFalse([message for message in messages if "index/sequence.rs" in message], messages)
                self.assertEqual(report["excluded"], [])
        report, code = WEAKEN.check(reader({tree: source(tree, "pub mod storage;", "#[cfg(test)]\npub mod storage;")}))
        self.assertEqual((code, report["excluded"]), (1, sorted([*storage, steps])), report["refusals"])
        self.refused("scope file", f"{FILL} is listed and the kernel package includes no production file there",
                     reader({tree: source(tree, "pub mod storage;", "#[cfg(test)]\npub mod storage;")}))
        sibling = "crates/kestrike/src/storage.rs"
        by_path = source(tree, "pub mod storage;", '#[path = "storage.rs"]\npub mod storage;')
        self.refused("scope file", undeclared, reader({tree: by_path, sibling: WEAKEN.read_repo(STORAGE)}))
        report, code = WEAKEN.check(reader({tree: by_path, sibling: '#[path = "storage/fill.rs"]\nmod fill;\n'}))
        self.assertFalse([entry for entry in report["refusals"] if entry["message"].startswith((f"the kernel package includes {FILL} ", FILL))],
                         report["refusals"])
        report, code = WEAKEN.check(reader({tree: source(tree, "pub mod storage;", '#[path = "storage/mod.rs"]\npub mod storage;')}))
        self.assertEqual((code, report["refusals"], report["sites"], report["excluded"]), (0, [], 29, [steps]))
        lacks = f"{steps} is a production file the kernel package includes and files lacks"
        committed = WEAKEN.read_repo(STORAGE)
        self.refused("scope file", lacks, reader({STORAGE: committed + '#[path = "via.rs"]\nmod via;\n',
                                                  "crates/kestrike/src/storage/via.rs": "mod credit_steps;\n"}))
        self.refused("scope file", lacks, reader({tree: WEAKEN.read_repo(tree) + '\n#[path = "storage/credit_steps.rs"]\nmod steps;\n'}))
        before = source(STORAGE, "#[cfg(all(test, loom))]\nmod credit_steps;", '#[path = "credit_steps.rs"]\n#[cfg(all(test, loom))]\nmod credit_steps;')
        report, code = WEAKEN.check(reader({STORAGE: before}))
        self.assertEqual((code, report["refusals"], report["excluded"]), (0, [], [steps]))
        extra = "crates/kestrike/src/storage/helpers/extra.rs"
        helpers = {"crates/kestrike/src/storage/helpers/mod.rs": "mod extra;\n"}
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [extra])
            report, code = WEAKEN.check(reader({STORAGE: committed + "#[cfg(test)]\nmod helpers;\n", **helpers}), root)
            self.assertEqual((code, report["refusals"]), (0, []))
            self.assertIn(extra, report["excluded"])
            self.refused("scope file", f"{extra} is a production file the kernel package includes and files lacks",
                         reader({STORAGE: committed + "mod helpers;\n", **helpers}), root)
            self.refused("scope file", f"the kernel package includes {extra} and no module file declares it", reader(helpers), root)

    def test_a_scoped_file_that_loads_other_source_is_refused(self):
        for label, loaded in (("an include! macro", 'include!("fill_peek.rs");'), ("a child module", "mod extra;"),
                              ("a child module named by a raw identifier", "mod r#extra;"),
                              ("a renamed include macro", 'use std::include as inc;\ninc!("fill_peek.rs");'),
                              ("an include macro renamed from its raw identifier", 'use std::r#include as inc;\ninc!("fill_peek.rs");'),
                              ("a child module a macro names by a fragment",
                               "macro_rules! child {\n    ($name:ident) => {\n        mod $name;\n    };\n}\nchild!(extra);"),
                              ("a child module whose `;` a macro supplies", "declare!(mod extra);"),
                              ("a child module a macro declares from an inline block", "child!(mod extra {});"),
                              ("an inline module", "mod extra {}"),
                              ("a module by path", '#[path = "fill_extra.rs"]\nmod extra;')):
            with self.subTest(label=label):
                self.refused("scope file", f"{FILL}:", self.with_source(FILL, ANCHOR, f"{loaded}\n\n" + ANCHOR))
                self.refused("scope file", "can load source that the catalog does not scope", self.with_source(FILL, ANCHOR, f"{loaded}\n\n" + ANCHOR))
        for label, kept in (("a test-only child module", "#[cfg(test)]\nmod fill_probes;"), ("a fn named by the raw identifier mod", "fn r#mod() {}"),
                            ("a test-only module declared by path before its test attribute", '#[path = "probes.rs"]\n#[cfg(test)]\nmod fill_probes;')):
            with self.subTest(label=label):
                report, code = WEAKEN.check(self.with_source(FILL, ANCHOR, f"{kept}\n\n" + ANCHOR))
                self.assertEqual((code, report["refusals"]), (0, []))

    def test_an_include_no_module_file_declares_is_refused(self):
        include = "crates/kestrike/src/storage/undeclared.rs"
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [include])
            self.refused("scope file", f"the kernel package includes {include} and no module file declares it", WEAKEN.read_repo, root)
            self.refused("scope file", f"{STORAGE} cannot be read to classify {include}",
                         reader({STORAGE: PermissionError(STORAGE)}), root)
        extra = "crates/kestrike/src/storage/extra.rs"
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [extra])
            read = reader({STORAGE: WEAKEN.read_repo(STORAGE) + '\n#[cfg(test)]\n#[path = "tests/extra.rs"]\nmod extra;\n'})
            self.refused("scope file", f"the kernel package includes {extra} and no module file declares it", read, root)
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, ["undeclared.rs"])
            self.refused("scope file", "the kernel package includes undeclared.rs and no module file declares it", WEAKEN.read_repo, root)

    def test_a_path_attribute_the_include_scanner_misses_is_refused(self):
        slot = "{up}crates/kestrike/src/storage/slot.rs"
        plants = (
            ("a raw string", f'#[path = r"{slot}"]\nmod m0;\n', "kernels/src/planted.rs:1: a path attribute the include scanner misses"),
            ("other spacing", f'#[path  =  "{slot}"]\nmod m0;\n', "kernels/src/planted.rs:1: a path attribute the include scanner misses"),
            ("a conditional attribute", f'#[cfg_attr(kernel = "x", path = "{slot}")]\nmod m0;\n',
             "kernels/src/planted.rs:1: a path attribute the include scanner misses"),
            ("a commented include beside a missed one",
             f'/*\n#[path = "{{up}}{CREDIT}"]\n*/\n#[path = r"{slot}"]\nmod m0;\n',
             "kernels/src/planted.rs:2: the include scanner reads a path attribute outside live code"),
            ("an escaped include", '#[path = "{up}crates/kestrike/src/storage/sl\\x6ft.rs"]\nmod m0;\n',
             "kernels/src/planted.rs:1: the include path"),
        )
        for label, text, message in plants:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as work:
                root = self.planted_package(work, [], text)
                self.refused("scope file", message, WEAKEN.read_repo, root)
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [], '#[path = "extra.inc"]\nmod extra;\n')
            (root / CATALOG_PACKAGE / "src/extra.inc").write_text(f'#[path = "../{"../" * 5}crates/kestrike/src/storage/slot.rs"]\nmod m0;\n')
            self.refused("scope file", "the include 'extra.inc' is no Rust source of the package the scan reads", WEAKEN.read_repo, root)

    def test_a_directory_named_like_a_source_is_skipped(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [], "")
            (root / CATALOG_PACKAGE / "src/spare.rs").mkdir()
            report, code = WEAKEN.check(WEAKEN.read_repo, root)
            self.assertEqual((code, report["refusals"]), (0, []))

    def test_a_listed_file_the_package_does_not_include_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [])
            read = self.with_catalog(lambda catalog: catalog["files"].append("crates/kestrike/src/storage/slot.rs"))
            self.refused("scope file", "slot.rs is listed and the kernel package includes no production file", read, root)

    def test_an_include_outside_the_repository_is_refused(self):
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, ["../outside.rs"])
            self.refused("scope file", "outside the repository", WEAKEN.read_repo, root)

    def test_an_unreadable_scope_file_is_refused(self):
        self.refused("scope file", f"{FILL} cannot be read", reader({FILL: OSError(FILL)}))
        report = WEAKEN.check(reader({FILL: OSError(FILL)}))[0]
        self.assertEqual([entry for entry in report["refusals"] if entry["refusal"] == "row"], [])
        self.assertEqual(report["rows"]["fill-observe"], "unrun")

    def test_an_empty_scoped_file_refuses_each_of_its_rows(self):
        report, code = WEAKEN.check(reader({FILL: ""}))
        self.assertEqual(code, 1, report)
        refused = {entry["message"].split(":")[0] for entry in report["refusals"] if entry["refusal"] == "find"}
        self.assertEqual(refused, {entry["id"] for entry in CATALOG["rows"] if entry["path"] == FILL})
        self.refused("find", f"fill-observe: its find occurs 0 times in {FILL}", reader({FILL: ""}))

    def test_an_unknown_binding_is_refused(self):
        def change(catalog):
            row(catalog, "row-detach")["binding"] = "join-detach-acquire"
        self.refused("reference", "row-detach: binding 'join-detach-acquire' binds no operation", self.with_catalog(change))

    def test_a_binding_of_another_file_is_refused(self):
        def change(catalog):
            row(catalog, "row-detach")["binding"] = "publication-install"
        self.refused("reference", "row-detach: binding 'publication-install' binds no operation", self.with_catalog(change))

    def test_a_binding_of_another_operation_in_the_same_file_is_refused(self):
        def detach(catalog):
            row(catalog, "row-detach")["binding"] = "join-observers-acquire"
        self.refused("reference", "row-detach: binding 'join-observers-acquire' binds 'self.observers.load', which its find lacks",
                     self.with_catalog(detach))

        def stable(catalog):
            row(catalog, "sequence-read-stable")["binding"] = "sequence-second-load"
        self.refused("enclosing item", "sequence-read-stable: fn still resolves to 1 bodies, or its body lacks the find", self.with_catalog(stable))
        declaration = json.loads(WEAKEN.read_repo(WEAKEN.GENMC))
        for field in ("call", "scope"):
            with self.subTest(field=field):
                planted = copy.deepcopy(declaration)
                next(entry for entry in planted["bindings"] if entry["id"] == "join-detach-release")["production"].pop(field)
                self.refused("reference", "row-detach: binding 'join-detach-release' holds no call or scope",
                             reader({WEAKEN.GENMC: json.dumps(planted)}))

    def test_a_twin_that_is_no_control_is_refused(self):
        plants = {
            "a positive GenMC case": lambda twin: twin[1].update(test="join-production"),
            "a Never litmus test": lambda twin: twin[2].update(test="F0-fill-terminal-production"),
            "a positive loom test": lambda twin: twin[0].update(test=FILL_MODEL + "two_owners_on_one_key_and_a_servicer"),
            "a loom control under the genmc lane": lambda twin: twin[1].update(test=twin[0]["test"]),
            "no steps": lambda twin: twin[0].pop("steps"),
            "zero steps": lambda twin: twin[0].update(steps=0),
            "boolean steps": lambda twin: twin[0].update(steps=True),
            "a list for a test": lambda twin: twin[0].update(test=[twin[0]["test"]]),
        }
        for label, plant in plants.items():
            with self.subTest(label=label):
                read = self.with_catalog(lambda catalog, plant=plant: plant(row(catalog, "fill-depart-release")["twin"]))
                self.refused("reference", "fill-depart-release: twin", read)
                self.assertFalse([entry for entry in WEAKEN.check(read)[0]["refusals"] if entry["refusal"] == "unrowed site"])
        read = self.with_catalog(lambda catalog: row(catalog, "fill-depart-release")["twin"][0].update(lane=["loom"]))
        self.refused("reference", "fill-depart-release: a twin names no lane", read)
        for twin in (None, "join-relaxeddepart", {"lane": "loom"}):
            with self.subTest(twin=twin):
                read = self.with_catalog(lambda catalog, twin=twin: row(catalog, "fill-depart-release").update(twin=twin))
                self.refused("reference", "fill-depart-release: its twin is no list of lane entries", read)

    def test_two_twins_in_one_lane_are_refused(self):
        def change(catalog):
            planted = row(catalog, "grace-bump")
            planted["twin"].append(dict(planted["twin"][0], test="grace2-bumprelaxed"))
        self.refused("reference", "grace-bump: its twins name a lane twice", self.with_catalog(change))

    def test_a_kill_row_naming_a_loom_control_is_refused(self):
        def change(catalog):
            decided(catalog, "fill-depart-release", "kill", [dict(DEPARTED, tests=[CONTROL])])
        self.refused("reference", f"{CONTROL} is no positive loom test", self.with_catalog(change))

    def test_an_entry_naming_a_violation_case_or_a_control_is_refused(self):
        def needs(catalog):
            needing(catalog, "row-detach", [dict(FREED, tests=["join-earlydetach"])])

        def kill(catalog):
            decided(catalog, "row-detach", "kill", [dict(FREED, tests=["join-earlydetach"])])

        def passed(catalog):
            decided(catalog, "row-detach", "survives", {"reason": "planted", "passed": [{"lane": "loom", "tests": [CONTROL]}]})
        self.refused("reference", "join-earlydetach is no positive genmc test", self.with_catalog(needs))
        self.refused("reference", "join-earlydetach is no positive genmc test", self.with_catalog(kill))
        self.refused("reference", f"{CONTROL} is no positive loom test", self.with_catalog(passed))

    def test_a_control_also_listed_under_tests_is_no_positive_test(self):
        records = json.loads(WEAKEN.read_repo(WEAKEN.OBLIGATIONS))
        record = next(entry for entry in records["records"] if CONTROL in [control["test"] for control in entry.get("controls", [])])
        record["tests"].append(CONTROL)
        for kind, value in (("kill", [dict(DEPARTED, tests=[CONTROL])]),
                            ("survives", {"reason": "planted", "passed": [{"lane": "loom", "tests": [CONTROL]}]})):
            with self.subTest(kind=kind):
                read = reader({WEAKEN.OBLIGATIONS: json.dumps(records),
                               WEAKEN.CATALOG: catalog_with(lambda catalog, kind=kind, value=value: decided(catalog, "fill-observe", kind, value))})
                self.refused("reference", f"{CONTROL} is no positive loom test", read)

    def test_a_loom_failure_in_no_string_literal_is_refused(self):
        scan = "index::scan_model::readers_never_copy_a_pending_pair_across_its_cancel"
        run = [FILL_MODEL + "two_owners_on_one_key_and_a_servicer_observing_the_run"]
        plants = {
            "absent": ("unrun", "a record departed twice", run),
            "a kill row": ("kill", "a record departed twice", run),
            "code text, not a literal": ("unrun", "fill::depart", run),
            "in one model file of two": ("unrun", "a departed record whose owner had not ended", run + [scan]),
            "a substring of a literal": ("unrun", "a", run),
            "the leading part of a message": ("unrun", "protection violated", run),
        }
        for label, (kind, failure, tests) in plants.items():
            def change(catalog, kind=kind, failure=failure, tests=tests):
                entry = {"lane": "loom", "tests": tests, "failure": failure}
                if kind == "kill":
                    decided(catalog, "fill-run-fence", "kill", [entry])
                else:
                    needing(catalog, "fill-run-fence", [entry])
            with self.subTest(label=label):
                self.refused("reference", f"fill-run-fence: the failure {failure!r} is no message literal", self.with_catalog(change))

    def test_an_empty_included_file_refuses_each_of_its_rows(self):
        names = [entry["id"] for entry in CATALOG["rows"] if entry["path"] == FILL]
        self.assertTrue(names)
        self.refused("find", f"{names[0]}: its find occurs 0 times in {FILL}", reader({FILL: ""}))
        report, code = WEAKEN.check(reader({FILL: ""}))
        self.assertEqual(code, 1, report)
        refused = [entry["message"] for entry in report["refusals"] if entry["refusal"] == "find"]
        for name in names:
            self.assertIn(f"{name}: its find occurs 0 times in {FILL}", refused)

    def test_a_loom_failure_two_message_literals_hold_is_refused(self):
        model = "crates/kestrike/src/storage/grace_model.rs"
        self.assertEqual(WEAKEN.diagnostics(WEAKEN.read_repo(model)).count("protection violated: anchor released twice"), 2)
        entry = {"lane": "loom", "tests": ["storage::grace_model::pinned_readers_never_observe_a_released_anchor_or_a_reused_slot"],
                 "failure": "anchor released twice"}
        self.refused("reference", "grace-unpin: the failure 'anchor released twice' lies in more than one message literal",
                     self.with_catalog(lambda catalog: needing(catalog, "grace-unpin", [entry])))

    def test_a_loom_failure_another_message_literal_extends_is_refused(self):
        model = "crates/kestrike/src/storage/grace_model.rs"
        anchor = '"protection violated: anchor released under a pinned reader"'
        extended = source(model, anchor, anchor + ");\n        assert!(false, \"protection violated: anchor released under a pinned reader twice\"")
        self.assertEqual(sum("anchor released under a pinned reader" in content for content in WEAKEN.diagnostics(extended)), 2)
        entry = {"lane": "loom", "tests": ["storage::grace_model::pinned_readers_never_observe_a_released_anchor_or_a_reused_slot"],
                 "failure": "anchor released under a pinned reader"}
        planted = catalog_with(lambda catalog: needing(catalog, "grace-unpin", [entry]))
        self.refused("reference", "grace-unpin: the failure 'anchor released under a pinned reader' lies in more than one message literal",
                     reader({model: extended, WEAKEN.CATALOG: planted}))

    def test_a_loom_failure_only_an_attribute_holds_is_refused(self):
        self.assertIn('#[should_panic(expected = "torn copy of B")]', WEAKEN.read_repo("crates/kestrike/src/index/scan_model.rs"))
        for failure in ("torn copy of B", "A"):
            with self.subTest(failure=failure):
                read = self.with_catalog(lambda catalog, failure=failure: needing(catalog, "sequence-begin-fence", [dict(TORN, failure=failure)]))
                self.refused("reference", f"sequence-begin-fence: the failure {failure!r} is no message literal", read)
        model = "crates/kestrike/src/storage/fill_model.rs"
        text = WEAKEN.read_repo(model)
        self.assertIn('#[should_panic(expected = "a departed record whose owner had not ended")]', text)
        bare = text.replace('#[should_panic(expected = "a departed record whose owner had not ended")]', "#[should_panic]")
        planted = catalog_with(lambda catalog: needing(catalog, "fill-observe", [DEPARTED]))
        report = WEAKEN.check(reader({model: bare, WEAKEN.CATALOG: planted}))[0]
        self.assertEqual([entry for entry in report["refusals"] if entry["refusal"] == "reference"], [])

    def test_a_loom_test_whose_model_source_cannot_be_read_is_refused(self):
        model = "crates/kestrike/src/storage/fill_model.rs"
        planted = catalog_with(lambda catalog: needing(catalog, "fill-observe", [DEPARTED]))
        self.refused("reference", f"fill-observe: no model source of {DEPARTED['tests'][0]} can be read",
                     reader({model: OSError(model), WEAKEN.CATALOG: planted}))

    def test_a_loom_model_source_follows_inline_and_path_declared_modules(self):
        cases = {"storage::readiness::authority_model::withdrawal_and_serving_publication_preserve_both_word_fields":
                 "crates/kestrike/src/storage/readiness.rs",
                 "net::client::route::route_model::a_read_racing_a_rebind_takes_one_binding_whole":
                 "crates/kestrike/src/net/client/route_model.rs",
                 FILL_MODEL + "two_owners_on_one_key_and_a_servicer": "crates/kestrike/src/storage/fill_model.rs"}
        for test, path in cases.items():
            with self.subTest(test=test):
                self.assertEqual(WEAKEN.module_source(test, WEAKEN.read_repo), WEAKEN.read_repo(path))
        self.assertIsNone(WEAKEN.module_source("undeclared::a_test", WEAKEN.read_repo))
        readiness = "crates/kestrike/src/storage/readiness.rs"
        decoyed = '/*\n#[path = "decoy.rs"]\nmod authority_model;\n*/\n' + WEAKEN.read_repo(readiness)
        test = next(iter(cases))
        self.assertEqual(WEAKEN.module_source(test, reader({readiness: decoyed})), decoyed)
        # A module file is the one its parent's declaration loads; a file that only the path convention names is none.
        live, test = "crates/kestrike/src/storage/fill_model_v2.rs", FILL_MODEL + "two_owners_on_one_key_and_a_servicer"
        moved = reader({STORAGE: source(STORAGE, "\nmod fill_model;\n", '\n#[path = "fill_model_v2.rs"]\nmod fill_model;\n'), live: "// The live model.\n"})
        self.assertEqual(WEAKEN.module_source(test, moved), "// The live model.\n")
        self.refused("reference", "is no message literal of a model source of its tests", moved)
        dropped = reader({STORAGE: source(STORAGE, "\nmod fill_model;\n", "\n")})
        self.assertIsNone(WEAKEN.module_source(test, dropped))
        stale = "crates/kestrike/src/storage/fill_model_stale.rs"
        for label, decoy in (("among a macro's tokens", 'macro_rules! decoy {\n    () => {\n#[path = "fill_model_stale.rs"]\nmod fill_model;\n    };\n}\n'),
                             ("in a comment", '/*\n#[path = "fill_model_stale.rs"]\nmod fill_model;\n*/\n')):
            with self.subTest(label=f"a path declaration {label}"):
                live = '#[cfg(all(test, loom))]\n#[path = "fill_model_stale.rs"]\nmod stale_model;\n'
                decoyed = reader({STORAGE: decoy + WEAKEN.read_repo(STORAGE) + live, stale: "// A stale model.\n"})
                self.assertEqual(WEAKEN.module_source(test, decoyed), WEAKEN.read_repo("crates/kestrike/src/storage/fill_model.rs"))
        unexpanded = reader({STORAGE: source(STORAGE, "\nmod fill_model;\n", "\nmacro_rules! decoy {\n    () => {\n        mod fill_model;\n    };\n}\n")})
        self.assertIsNone(WEAKEN.module_source(test, unexpanded))
        # Two declarations that load different files leave the choice to a `cfg` the lookup does not evaluate.
        twice = '#[cfg(all(test, loom, any()))]\n#[path = "fill_model_stale.rs"]\nmod fill_model;\n#[cfg(all(test, loom))]\nmod fill_model;'
        doubled = reader({STORAGE: source(STORAGE, "#[cfg(all(test, loom))]\nmod fill_model;", twice), stale: "// A stale model.\n"})
        self.assertIsNone(WEAKEN.module_source(test, doubled))
        self.refused("reference", f"no model source of {test} can be read", doubled)
        beside = '#[cfg(any())]\n#[path = "authority_model_stale.rs"]\nmod authority_model;\n' + WEAKEN.read_repo(readiness)
        inline = reader({readiness: beside, "crates/kestrike/src/storage/authority_model_stale.rs": "// A stale model.\n"})
        self.assertIsNone(WEAKEN.module_source(next(iter(cases)), inline))

    def test_a_genmc_failure_that_is_no_one_check_message_is_refused(self):
        plants = {
            "a substring": ("row-observers", FREED, "a follower's record was freed"),
            "another family's message": ("row-observers", FREED, "pin refused"),
            "another family's message again": ("row-observers", FREED, "a record holding credits is flagged"),
            "a message its kernel holds twice": ("grace-era-load", CUTOFF, "pin refused"),
            "a plain string": ("sequence-terminate-store", TERMINAL, "own"),
        }
        for label, (name, entry, failure) in plants.items():
            with self.subTest(label=label):
                read = self.with_catalog(lambda catalog, name=name, entry=entry, failure=failure: needing(
                    catalog, name, [dict(entry, failure=failure)]))
                self.refused("reference", f"{name}: the failure {failure!r} is no one check! message of its cases' kernel file", read)
        read = self.with_catalog(lambda catalog: needing(catalog, "row-observers", [dict(FREED, tests=["sb_sc"])]))
        self.refused("reference", "row-observers: sb_sc has no kernel file of its family", read)

    def test_a_genmc_failure_spelled_c_only_in_a_comment_is_refused(self):
        literal = 'c"a follower\'s record was freed or reissued under it"'
        planted = reader({WEAKEN.CATALOG: catalog_with(lambda catalog: needing(catalog, "row-observers", [FREED]))})
        call = f"check!(false, {literal})"
        for label, new, refused in (("a comment", f"check!(false, {literal[1:]} /* {literal} */)", True),
                                    ("the literal outside check!", f"check!(false, {literal[1:]}); let _stale = ({literal})", True),
                                    ("the literal in the condition", f'check!({literal}.is_empty(), c"another message")', True),
                                    ("a plain duplicate beside it", f"check!(false, {literal}); let _plain = ({literal[1:]})", False)):
            with self.subTest(label=label), tempfile.TemporaryDirectory() as work:
                root = self.planted_package(work, [], "")
                path = root / CATALOG_PACKAGE / "src/join_kernel.rs"
                text = path.read_text()
                self.assertEqual(text.count(call), 1)
                path.write_text(text.replace(call, new))
                if refused:
                    self.refused("reference", f"row-observers: the failure {FREED['failure']!r} is no one check! message", planted, root)
                else:
                    report = WEAKEN.check(planted, root)[0]
                    self.assertEqual([entry for entry in report["refusals"] if entry["refusal"] == "reference"], [])

    def test_a_survives_row_with_an_empty_reason_is_refused(self):
        def change(catalog):
            decided(catalog, "fill-depart-held", "survives", {"reason": " ", "passed": []})
        self.refused("disposition", "fill-depart-held: its survives disposition lacks a field", self.with_catalog(change))

    def test_a_survives_row_with_a_reason_and_its_revision_is_accepted(self):
        def change(catalog):
            decided(catalog, "fill-depart-held", "survives", {"reason": "no model calls depart_held", "passed": []})
        report, code = WEAKEN.check(self.with_catalog(change))
        self.assertEqual((code, report["rows"]["fill-depart-held"]), (0, "survives"))

    def test_a_disposition_that_names_no_run_is_refused_outside_the_unmodeled_rows(self):
        def every(catalog):
            for entry in catalog["rows"]:
                decided(catalog, entry["id"], "survives", {"reason": "planted", "passed": []})
        report, code = WEAKEN.check(self.with_catalog(every))
        refused = sorted(entry["message"].split(":")[0] for entry in report["refusals"])
        self.assertEqual((code, report["credited"]), (1, False))
        self.assertEqual({entry["refusal"] for entry in report["refusals"]}, {"disposition"})
        self.assertEqual(refused, sorted({entry["id"] for entry in CATALOG["rows"]} - set(WEAKEN.UNMODELED)))
        self.refused("disposition", "grace-visit: its survives disposition names no run",
                     self.with_catalog(lambda catalog: decided(catalog, "grace-visit", "survives", {"reason": "planted", "passed": []})))

        def unrun(catalog):
            row(catalog, "grace-visit")["unrun"] = {"needs": [], "reason": "planted"}
        self.refused("disposition", "grace-visit: its unrun disposition names no run", self.with_catalog(unrun))
        report, code = WEAKEN.check(self.with_catalog(lambda catalog: needing(catalog, "fill-depart-held", [DEPARTED])))
        self.assertEqual((code, report["refusals"]), (0, []))

    def test_a_row_with_two_dispositions_or_none_is_refused(self):
        def two(catalog):
            needing(catalog, "grace-visit", [CUTOFF])
            row(catalog, "grace-visit")["survives"] = {"reason": "planted", "passed": []}

        def none(catalog):
            for key in WEAKEN.DISPOSITIONS:
                row(catalog, "grace-visit").pop(key, None)
        for change, count in ((two, 2), (none, 0)):
            with self.subTest(count=count):
                self.refused("disposition", f"grace-visit: it holds {count} dispositions", self.with_catalog(change))
                report = WEAKEN.check(self.with_catalog(change))[0]
                self.assertIsNone(report["rows"]["grace-visit"])
                self.assertNotIn("grace-visit", report["unrun"])

    def test_a_disposition_entry_without_its_fields_is_refused(self):
        without_failure = [{key: value for key, value in entry.items() if key != "failure"} for entry in (DEPARTED, FOLLOWER)]
        plants = {
            "unrun without needs or a reason": ("unrun", {"needs": []}),
            "unrun without needs beside a blank reason": ("unrun", {"needs": [], "reason": " "}),
            "unrun that is a list": ("unrun", [DEPARTED]),
            "unrun that is a string": ("unrun", "planted"),
            "a needs entry without a failure": ("unrun", {"needs": without_failure}),
            "a needs entry with a blank failure": ("unrun", {"needs": [dict(DEPARTED, failure=" ")]}),
            "a needs entry with a numeric failure": ("unrun", {"needs": [dict(DEPARTED, failure=7)]}),
            "a needs entry with no tests": ("unrun", {"needs": [dict(DEPARTED, tests=[])]}),
            "an empty kill": ("kill", []),
            "a kill that is an object": ("kill", {"needs": [DEPARTED]}),
            "a kill entry without a failure": ("kill", without_failure),
            "two kill entries in one lane": ("kill", [DEPARTED, DEPARTED]),
            "a survives that is a list": ("survives", [{"lane": "loom", "tests": DEPARTED["tests"]}]),
            "a passed entry without tests": ("survives", {"reason": "planted", "passed": [{"lane": "loom"}]}),
            "a passed entry in another lane": ("survives", {"reason": "planted", "passed": [{"lane": "rc11", "tests": ["F0"]}]}),
        }
        for label, (kind, value) in plants.items():
            def change(catalog, kind=kind, value=value):
                decided(catalog, "fill-observe", kind, value)
                if kind == "unrun":
                    row(catalog, "fill-observe").pop("revision")
            with self.subTest(label=label):
                self.refused("disposition", f"fill-observe: its {kind} disposition lacks a field", self.with_catalog(change))

    def test_a_decided_row_without_a_revision_is_refused(self):
        for kind, value in (("kill", [DEPARTED, FOLLOWER]), ("survives", {"reason": "planted", "passed": [{"lane": "loom", "tests": DEPARTED["tests"]}]})):
            for label, revision in (("none", None), ("a number", int("1" * 40)), ("a trailing newline", REVISION + "\n"),
                                    ("upper case", "A" * 40)):
                def change(catalog, kind=kind, value=value, revision=revision):
                    decided(catalog, "fill-observe", kind, value)
                    if revision is None:
                        del row(catalog, "fill-observe")["revision"]
                    else:
                        row(catalog, "fill-observe")["revision"] = revision
                with self.subTest(kind=kind, label=label):
                    self.refused("revision", f"fill-observe: its {kind} disposition records no revision", self.with_catalog(change))

    def test_a_find_moved_out_of_its_enclosing_item_is_refused(self):
        moved = source(GRACE, "    record.store(INACTIVE, Ordering::Release);\n}",
                       "    clear(record);\n}\n\nfn clear<W: EraWord>(record: &W) {\n    record.store(INACTIVE, Ordering::Release);\n}")
        self.refused("enclosing item", "grace-unpin: fn unpin resolves to 1 bodies, or its body lacks the find", reader({GRACE: moved}))
        unbound = catalog_with(lambda catalog: row(catalog, "grace-unpin").update(binding=None))
        self.refused("row", "row 'grace-unpin' is malformed: a field has the wrong type", reader({GRACE: moved, WEAKEN.CATALOG: unbound}))

    def test_a_find_moved_into_a_nested_item_is_refused(self):
        live = "    record.store(INACTIVE, Ordering::Relaxed);\n}"
        plants = {
            "a nested fn": "    fn clear<W: EraWord>(record: &W) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n",
            "a nested fn with an array parameter": "    fn clear<W: EraWord>(record: &W, _: [u8; 0]) {\n        record.store(INACTIVE, Ordering::Release);\n    }\n",
            "a nested impl": "    impl Spare {\n        const _: () = record.store(INACTIVE, Ordering::Release);\n    }\n",
        }
        for label, helper in plants.items():
            with self.subTest(label=label):
                nested = source(GRACE, "    record.store(INACTIVE, Ordering::Release);\n}", helper + live)
                self.refused("enclosing item", "grace-unpin: its site lies in an item nested in fn unpin", reader({GRACE: nested}))
        nested = source(GRACE, "    record.store(INACTIVE, Ordering::Release);\n}", plants["a nested fn"] + live)
        find = "(record: &W) {\n        record.store(INACTIVE, Ordering::Release);"

        def header(catalog):
            planted = row(catalog, "grace-unpin")
            planted["find"], planted["replace"] = find, find.replace("Release", "Relaxed")
        self.refused("enclosing item", "grace-unpin: its site lies in an item nested in fn unpin",
                     reader({GRACE: nested, WEAKEN.CATALOG: catalog_with(header)}))

    def test_a_scope_that_resolves_to_two_bodies_is_refused(self):
        read = self.with_source(GRACE, "    record.store(INACTIVE, Ordering::Release);\n}",
                                "    record.store(INACTIVE, Ordering::Release);\n}\n\nmod spare {\n    fn unpin() {}\n}")
        self.refused("enclosing item", "grace-unpin: fn unpin resolves to 2 bodies", read)

    def test_a_row_without_an_enclosing_item_is_refused(self):
        def change(catalog):
            del row(catalog, "grace-visit")["scope"]
        self.refused("enclosing item", "grace-visit: it names no enclosing item", self.with_catalog(change))

    def test_a_repeated_row_id_is_refused(self):
        def change(catalog):
            catalog["rows"].append(copy.deepcopy(row(catalog, "grace-visit")))
        self.refused("row", "row 'grace-visit' is malformed: its id is repeated", self.with_catalog(change))

    def test_a_malformed_row_is_refused_by_name(self):
        plants = {
            "an unlisted path": (lambda entry: entry.update(path="crates/kestrike/src/storage/slot.rs"), "'grace-visit'", "it names an unlisted path"),
            "an unhashable path": (lambda entry: entry.update(path=[1]), "'grace-visit'", "a field has the wrong type"),
            "an unhashable binding": (lambda entry: entry.update(binding=["x"]), "'grace-visit'", "a field has the wrong type"),
            "a scope of numbers": (lambda entry: entry.update(scope=[1]), "'grace-visit'", "a field has the wrong type"),
            "a scope that is a string": (lambda entry: entry.update(scope="fn unpin"), "'grace-visit'", "a field has the wrong type"),
            "an unknown op": (lambda entry: entry.update(op="swap"), "'grace-visit'", "its op 'swap'"),
            "a numeric id": (lambda entry: entry.update(id=7), "7", "a field has the wrong type"),
            "a numeric find": (lambda entry: entry.update(find=7), "'grace-visit'", "a field has the wrong type"),
            "a blank id": (lambda entry: entry.update(id=""), "''", "its id is blank"),
            "a whitespace id": (lambda entry: entry.update(id="  "), "'  '", "its id is blank"),
            "no id": (lambda entry: entry.pop("id"), "None", "it lacks ['id']"),
            "no find": (lambda entry: entry.pop("find"), "'grace-visit'", "it lacks ['find']"),
            "no replace": (lambda entry: entry.pop("replace"), "'grace-visit'", "it lacks ['replace']"),
            "no path": (lambda entry: entry.pop("path"), "'grace-visit'", "it lacks ['path']"),
            "no op": (lambda entry: entry.pop("op"), "'grace-visit'", "it lacks ['op']"),
            "a numeric op": (lambda entry: entry.update(op=1), "'grace-visit'", "a field has the wrong type"),
            "a numeric replace": (lambda entry: entry.update(replace=1), "'grace-visit'", "a field has the wrong type"),
            "a binding beside a scope": (lambda entry: entry.update(binding="join-detach-release"), "'grace-visit'",
                                         "it holds both a binding and a scope"),
            "a misspelled key": (lambda entry: entry.update(twins=[]), "'grace-visit'", "it holds the unknown keys ['twins']"),
        }
        for label, (plant, shown, defect) in plants.items():
            with self.subTest(label=label):
                read = self.with_catalog(lambda catalog, plant=plant: plant(row(catalog, "grace-visit")))
                self.refused("row", f"row {shown} is malformed: {defect}", read)
        read = self.with_catalog(lambda catalog: catalog["rows"].append("grace-visit"))
        self.refused("row", "row 'grace-visit' is malformed: it is no object", read)

    def test_an_unreadable_catalog_exits_2(self):
        files = list(CATALOG["files"])
        texts = {
            "truncated": "{",
            "files that are a number": json.dumps({"files": 5, "rows": []}),
            "files that are an object": json.dumps({"files": dict.fromkeys(files, True), "rows": []}),
            "a repeated file": json.dumps({"files": files + files[:1], "rows": []}),
            "a numeric file": json.dumps({"files": files + [7], "rows": []}),
            "rows that are an object": json.dumps({"files": files, "rows": {}}),
            "a repeated key": json.dumps(CATALOG).replace('"find": ', '"find": "stale", "find": ', 1),
            "deep nesting": "[" * 100000 + "]" * 100000,
        }
        for label, text in texts.items():
            with self.subTest(label=label):
                report, code = WEAKEN.check(reader({WEAKEN.CATALOG: text}))
                self.assertEqual(code, 2, report)
                self.assertIn("unreadable catalog", report["error"])
        report, code = WEAKEN.check(reader({WEAKEN.GENMC: "[" * 100000}))
        self.assertEqual(code, 2, report)
        for error in (OSError("planted"), RuntimeError("planted"), ValueError("planted")):
            with self.subTest(error=type(error).__name__), mock.patch.object(WEAKEN.genmc, "package_sources", side_effect=error):
                report, code = WEAKEN.check()
                self.assertEqual((code, report), (2, {"error": "unreadable kernel package: planted"}))

    def test_a_symlink_loop_in_the_kernel_package_is_never_accepted(self):
        # `Path.resolve` raises on a symlink loop before Python 3.13 and returns the path unresolved from 3.13 on, so
        # the loop is an unreadable package on the older interpreters and an include the scan does not read on the newer.
        with tempfile.TemporaryDirectory() as work:
            root = self.planted_package(work, [], '#[path = "loop.rs"]\nmod looped;\n')
            (root / CATALOG_PACKAGE / "src/loop.rs").symlink_to("loop.rs")
            report, code = WEAKEN.check(WEAKEN.read_repo, root)
        if code == 2:
            self.assertIn("unreadable kernel package", report["error"])
        else:
            self.assertEqual(code, 1, report)
            refused = [entry["message"] for entry in report["refusals"] if entry["refusal"] == "scope file"]
            self.assertTrue(any("the include 'loop.rs' is no Rust source of the package the scan reads" in message
                                for message in refused), report)

    def test_every_documented_refusal_names_the_tests_that_plant_it(self):
        header = (WEAKEN.__doc__ or "").split("`check` refuses, each by name:")[1].split("`check` prints")[0]
        documented = set(re.findall(r"^- `([a-z ]+)`:", header, re.M)) | set(re.findall(r"; `([a-z ]+)`:", header))
        self.assertEqual(documented, set(CLAUSES))
        for refusal, tests in CLAUSES.items():
            for test in tests:
                method = getattr(self, test, None)
                if not callable(method):
                    self.fail(f"{test} names no test")
                self.assertIn(f'self.refused("{refusal}"', inspect.getsource(method), test)


STUB_CARGO = r"""#!/usr/bin/env python3
import hashlib, json, os, re, sys
from pathlib import Path
args = sys.argv[1:]
shaping = re.compile(r"^(RUSTC\w*|RUSTFLAGS|RUSTDOCFLAGS|CARGO_ENCODED_\w+|CARGO_BUILD_\w+|CARGO_TARGET_\w+|CARGO_PROFILE_\w+|LOOM_\w+)$")
with open(os.environ["STUB_PLAN"] + ".env", "a") as seen_env:
    seen_env.write(json.dumps({"args": args, "cwd": os.getcwd(), "env": {name: value for name, value in os.environ.items() if shaping.match(name)}}) + "\n")
if "tree" in args:
    if os.environ.get("STUB_TREE_EXIT", "0") == "0":
        Path("Cargo.lock").write_text("stub lock\n")
    print(os.environ.get("STUB_LOOM", f"loom v{os.environ.get('LOOM')}") if args[args.index("-i") + 1] == "loom" else "")
    sys.exit(int(os.environ.get("STUB_TREE_EXIT", "0")))
if "config" in args:
    kernels = os.getcwd().endswith("verification/genmc/packages/kernels")
    print(os.environ.get("STUB_CONFIG_KERNELS" if kernels else "STUB_CONFIG", "{}"))
    print(os.environ.get("STUB_CONFIG_ERR", ""), file=sys.stderr)
    sys.exit(int(os.environ.get("STUB_CONFIG_EXIT", "0")))
test = args[args.index("--release") + 1]
files = json.loads(Path("verification/orderings/expected.json").read_text())["files"]
state = hashlib.sha256(b"".join(Path(name).read_bytes() for name in files)).hexdigest()
plan = json.loads(Path(os.environ["STUB_PLAN"]).read_text())
seen = Path(os.environ["STUB_PLAN"] + ".seen")
if not seen.exists():
    seen.write_text(state)
first = seen.read_text()
mode = plan.get(test, {}).get("clean" if state == first else "planted", "pass")
log = Path(os.environ["STUB_PLAN"] + ".log")
log.write_text((log.read_text() if log.exists() else "") + f"{test} {'clean' if state == first else 'planted'} {os.environ.get('RUSTFLAGS')} "
               f"{os.environ.get('CARGO_TARGET_DIR')} {sorted(name for name in os.environ if name.startswith('LOOM_'))} "
               f"{os.environ.get('CARGO_ENCODED_RUSTFLAGS')} {os.environ.get('CARGO_TERM_COLOR')}/{os.environ.get('CARGO_TERM_QUIET')} "
               f"{hashlib.sha256(Path(files[3]).read_bytes()).hexdigest()}\n")
if mode.startswith("sleep"):
    import signal, time
    signal.signal(signal.SIGTERM, lambda *_: (Path(os.environ["STUB_PLAN"] + ".stopped").write_text("1"), sys.exit(143)))
    Path(os.environ["STUB_PLAN"] + ".sleeping").write_text("1")
    time.sleep(60)
if mode in ("drift", "drift-own"):
    with open(files[0] if mode == "drift" else files[3], "a") as scoped:
        scoped.write("// drift\n")
    mode = "pass"
if mode == "link":
    twin = Path(files[0] + ".twin")
    twin.write_bytes(Path(files[0]).read_bytes())
    Path(files[0]).unlink()
    Path(files[0]).symlink_to(twin.name)
    mode = "pass"
if mode in ("gone", "dangling", "loop", "dir-own", "gone-other", "dir-other"):
    target = Path(files[0] if mode.endswith("-other") else files[3])
    target.unlink()
    if mode in ("dangling", "loop"):
        target.symlink_to("absent" if mode == "dangling" else target.name)
    if mode.startswith("dir"):
        target.mkdir()
    mode = "pass"
if mode in ("unreadable", "unreadable-other"):
    os.chmod(files[0] if mode.endswith("-other") else files[3], 0)
    mode = "pass"
if mode != "norebuild":
    print("   Compiling kestrike v0.1.0 (copy)")
if mode == "build":
    print("error[E0308]: mismatched types")
    sys.exit(101)
if mode == "crash":
    print("running 1 test")
    sys.exit(101)
print("running 1 test" if mode not in ("none",) else "running 0 tests")
if mode in ("pass", "norebuild"):
    print(f"test {test} ... ok\n\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out")
elif mode == "none":
    print("test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 10 filtered out")
elif mode == "ignored":
    print(f"test {test} ... ignored\n\ntest result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out")
else:
    at = plan.get(test, {}).get("at", "model.rs:1")
    print(f"test {test} ... FAILED\nthread '{test}' panicked at {at}:21:\n{mode[len('fail:'):]}\n"
          "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out")
    sys.exit(101)
"""
STUB_RUSTC = """#!/bin/sh
echo "rustc $1-stub"
"""
STUB_LANE = r"""#!/usr/bin/env python3
import hashlib, importlib.util, json, os, sys
from pathlib import Path
def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module
weaken = load("weaken", "scripts/weaken-orderings.py")
fixture, judge = weaken.load("test-judge-genmc", Path.cwd()), weaken.load("judge-genmc", Path.cwd())
profile, cases = sys.argv[2], sys.argv[3:]
evidence = Path(os.environ["EVIDENCE"])
evidence.mkdir(parents=True, exist_ok=True)
files = json.loads(Path("verification/orderings/expected.json").read_text())["files"]
state = hashlib.sha256(b"".join(Path(name).read_bytes() for name in files)).hexdigest()
plan = json.loads(Path(os.environ["STUB_PLAN"]).read_text())
seen = Path(os.environ["STUB_PLAN"] + ".seen")
if not seen.exists():
    seen.write_text(state)
phase = "clean" if state == seen.read_text() else "planted"
with open(os.environ["STUB_PLAN"] + ".lane", "a") as log:
    log.write(f"{phase} {evidence} {os.environ.get('CARGO_TERM_COLOR')}/{os.environ.get('CARGO_TERM_QUIET')} {' '.join(sys.argv[1:])}\n")
record = {"binary": {"path": "/genmc/build/bin/genmc"}, "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}
(evidence / "identity.json").write_text(json.dumps(record))
(evidence / "cargo-config.json").write_text("{}")
declared = json.loads(Path("verification/genmc/expected.json").read_text())
kernels = weaken.kernel_texts(Path(declared["package"]))
for case in cases:
    mode = plan.get(case, {}).get(phase, "positive")
    if mode == "abort":
        (evidence / f"check-{case}.txt").write_text("error: could not compile `genmc-kernels`\n")
        sys.exit(1)
    manifest = Path.cwd() / Path(declared["package"]).parent / f"run-{case}" / "Cargo.toml"
    argv = [record["binary"]["path"], *declared["options"], f"--dump-error-graph={evidence / f'genmc-{case}.dot'}", str(manifest)]
    (evidence / f"genmc-{case}.argv").write_text("\n".join(argv) + "\n")
    (evidence / f"genmc-{case}.env").write_text(f"CASE={case}\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC=/toolchain/bin/rustc\n"
                                                 "RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n")
    (evidence / f"check-{case}.txt").write_text("" if mode == "norebuild" else "    Checking genmc-kernels v0.0.0\n")
    if mode.startswith("violation:"):
        file = weaken.family_kernel(case, kernels)[0]
        text, code = fixture.violation(line=judge.check_line({"file": file}, mode[len("violation:"):]), file=Path(file).name), 42
    else:
        text, code = fixture.positive(executions=5 if phase == "clean" else 3), 0
    (evidence / f"genmc-{case}.txt").write_text(text)
    (evidence / f"genmc-{case}.exit").write_text("x\n" if mode == "badexit" else f"{code}\n")
    (evidence / f"genmc-{case}.dot").write_text(fixture.graph_of(text))
"""
JOIN_ROW = "row-detach"
JOIN_FREED = "a follower's record was freed or reissued under it"
RUN_FENCE = "fill-run-fence"
RUN_FAILURE = "a departed record whose owner had not ended"
RUN_TESTS = [FILL_MODEL + "two_owners_on_one_key_and_a_servicer_observing_the_run", FILL_MODEL + "three_participants_over_two_keys_observing_the_run"]
RUN_SITE = WEAKEN.loom_site(RUN_TESTS[0], RUN_FAILURE, WEAKEN.read_repo)
RUN_AT = f"{RUN_SITE[0]}:{RUN_SITE[1]}" if RUN_SITE else "unresolved"
DEPART_ROW = "fill-depart-release"
DEPART_TESTS = [FILL_MODEL + "two_owners_on_one_key_and_a_servicer", FILL_MODEL + "three_participants_over_two_keys_reach_the_serial_maximum",
                *RUN_TESTS]
CREDIT_ROW = "credit-add"
CREDIT_CASES = ["credit-seq-empty", "credit-seq-pool1", "credit-seq-stale", "credit-seq-two"]
CREDIT_FLAGGED = "a record holding credits is flagged"
GRACE_ROW = "grace-pin-store"
ANCHOR_RELEASED = "protection violated: anchor released under a pinned reader"
RETAIN = "protection violated: a pinned reader's retain refused"
# The entries each run test pins in its fixture catalog, so the run tests hold whatever the committed rows decide.
SEEDED = {
    RUN_FENCE: [{"lane": "loom", "tests": RUN_TESTS, "failure": RUN_FAILURE}],
    DEPART_ROW: [{"lane": "loom", "tests": DEPART_TESTS, "failure": RUN_FAILURE}],
    JOIN_ROW: [{"lane": "genmc", "tests": ["join-production"], "failure": JOIN_FREED}],
    CREDIT_ROW: [{"lane": "genmc", "tests": CREDIT_CASES, "failure": CREDIT_FLAGGED}],
    GRACE_ROW: [{"lane": "genmc", "tests": ["grace1-seq"], "failure": ANCHOR_RELEASED}, {"lane": "genmc", "tests": ["grace1-seq"], "failure": RETAIN},
                dict(CUTOFF)],
}


# Runs the script at argv[2] with the arguments after it, and sends the process one handled signal at the point argv[1]
# names: `restore`, as an interrupted row's restore begins, or `between`, as a planted row's first result is recorded.
INJECTING = r"""
import importlib.util, os, signal, sys, time
from pathlib import Path
spec = importlib.util.spec_from_file_location("weaken_orderings", sys.argv[2])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
fired = []

def deliver(number):
    fired.append(True)
    os.kill(os.getpid(), number)
    for _ in range(20):
        time.sleep(0.01)

mask, save = signal.pthread_sigmask, module.save

def masking(how, numbers):
    if sys.argv[1] == "restore" and how == signal.SIG_BLOCK and not fired and Path(os.environ["STUB_PLAN"] + ".stopped").exists():
        deliver(signal.SIGHUP)
    return mask(how, numbers)

def saving(path, data):
    if sys.argv[1] == "between" and not fired and any(len(row["results"]) == 1 and row["expected"] is None and "agrees" not in row
                                                      for row in data.get("rows", {}).values()):
        deliver(signal.SIGTERM)
    return save(path, data)

signal.pthread_sigmask, module.save = masking, saving
sys.exit(module.main(sys.argv[3:]))
"""


def process_running(pid):
    """Whether `pid` names a live process that is no zombie."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().split(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return False


def default_signals():
    """Give a child process the default action for the signals `run` handles."""
    for number in WEAKEN.SIGNALS:
        signal.signal(number, signal.SIG_DFL)


def write_case(evidence, case, text, code, check=True, record=None, config=None, argv=None, intrinsics=None):
    """Write one GenMC case's lane evidence into `evidence`, as the lane's case loop does."""
    declared = json.loads((ROOT / WEAKEN.GENMC).read_text())
    (evidence / f"genmc-{case}.txt").write_text(text)
    (evidence / f"genmc-{case}.exit").write_text(f"{code}\n")
    (evidence / f"genmc-{case}.dot").write_text(GENMC_FIXTURE.graph_of(text))
    (evidence / f"check-{case}.txt").write_text("    Checking genmc-kernels v0.0.0\n" if check else "")
    if intrinsics is not None:
        (evidence / f"genmc-{case}.intrinsics").write_text("\n".join(intrinsics) + "\n")
    record = record if record is not None else {"binary": {"path": "/genmc/build/bin/genmc"},
                                                 "rustc": {"name": "nightly-2026-07-27", "toolchain": "/toolchain"}}
    (evidence / "identity.json").write_text(json.dumps(record))
    (evidence / "cargo-config.json").write_text(json.dumps(config if config is not None else {}))
    manifest = ROOT / Path(declared["package"]).parent / f"run-{case}" / "Cargo.toml"
    argv = argv or ["/genmc/build/bin/genmc", *declared["options"], f"--dump-error-graph={evidence / f'genmc-{case}.dot'}", str(manifest)]
    (evidence / f"genmc-{case}.argv").write_text("\n".join(argv) + "\n")
    (evidence / f"genmc-{case}.env").write_text(f"CASE={case}\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC=/toolchain/bin/rustc\n"
                                                 "RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n")
    return declared


class RunCommand(unittest.TestCase):
    """`run` over a disposable clone of the checkout with this working tree's tracked changes and untracked files
    committed into it, the run rows' entries pinned by `SEEDED`, a stub `cargo` and `rustc` on PATH and a stub GenMC
    lane; expected bytes come from the clone. `base` is the resolved temporary directory, the form in which `run`
    reports each path under its work directory."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="weaken-run-")
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.repo = self.base / "repo"
        subprocess.run(["git", "clone", "-q", "--shared", str(ROOT), str(self.repo)], check=True)
        listed = [subprocess.run(["git", "-C", str(ROOT), *command], capture_output=True, text=True, check=True).stdout.split("\0")
                  for command in (("diff", "--name-only", "-z", "HEAD"), ("ls-files", "-z", "--others", "--exclude-standard"))]
        for name in filter(None, listed[0] + listed[1]):
            source_path, target = ROOT / name, self.repo / name
            if source_path.is_file():
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source_path, target)
            else:
                target.unlink(missing_ok=True)
        (self.base / "bin").mkdir()
        for name, text in (("cargo", STUB_CARGO), ("rustc", STUB_RUSTC)):
            (self.base / "bin" / name).write_text(text)
            (self.base / "bin" / name).chmod(0o755)
        (self.base / "stub_lane.py").write_text(STUB_LANE)
        (self.repo / "scripts/rust-lane.sh").write_text(f'exec python3 {self.base / "stub_lane.py"} "$@"\n')
        self.plan = self.base / "plan.json"
        self.plan.write_text("{}")
        self.catalog = json.loads((self.repo / WEAKEN.CATALOG).read_text())

    def commit(self, change=None):
        planted = copy.deepcopy(self.catalog)
        for name, entries in SEEDED.items():
            needing(planted, name, entries)
        if change:
            change(planted)
        (self.repo / WEAKEN.CATALOG).write_text(json.dumps(planted))
        subprocess.run(["git", "-C", str(self.repo), "add", "-A"], check=True)
        subprocess.run(["git", "-C", str(self.repo), "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false",
                        "-c", "core.hooksPath=/dev/null", "commit", "-qm", "planted", "--allow-empty"], check=True)
        return subprocess.run(["git", "-C", str(self.repo), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()

    def command(self, rows, work, plan, env):
        self.plan.write_text(json.dumps(plan or {}))
        for suffix in (".seen", ".log", ".lane", ".env", ".sleeping", ".stopped"):
            Path(str(self.plan) + suffix).unlink(missing_ok=True)
        merged = dict(os.environ, PATH=f"{self.base / 'bin'}:{os.environ['PATH']}", STUB_PLAN=str(self.plan), LOOM_MAX_PREEMPTIONS="9",
                      CARGO_ENCODED_RUSTFLAGS="--cfg\x1fx", CARGO_TERM_COLOR="always", CARGO_TERM_QUIET="true", **(env or {}))
        merged = {name: value for name, value in merged.items() if value is not None}
        command = [sys.executable, str(self.repo / "scripts/weaken-orderings.py"), "run", "--work", str(work), *(f"--row={name}" for name in rows)]
        return command, merged

    def run_rows(self, *rows, work=None, plan=None, env=None, umask=None):
        work = work or self.base / "work"
        command, env = self.command(rows, work, plan, env)
        result = subprocess.run(command, env=env, capture_output=True, text=True, check=False,
                                preexec_fn=None if umask is None else (lambda: os.umask(umask)))
        report = json.loads((Path(work) / "report.json").read_text()) if (Path(work) / "report.json").is_file() else {}
        return result, report

    def start_rows(self, *rows, work, plan=None, inject=None):
        command, env = self.command(rows, work, plan, None)
        if inject:
            command = [command[0], "-c", INJECTING, inject, *command[1:]]
        child = subprocess.Popen(command, env=env, preexec_fn=default_signals)
        self.addCleanup(lambda: child.poll() is not None or (child.kill(), child.wait()))
        return child

    def wait_for(self, suffix):
        marker = Path(str(self.plan) + suffix)
        for _ in range(600):
            if marker.exists():
                return
            time.sleep(0.1)
        self.fail(f"no {suffix} marker")

    def results(self, report, name):
        return [result["result"] for result in report["rows"][name]["results"]]

    def lines(self, suffix):
        path = Path(str(self.plan) + suffix)
        return path.read_text().splitlines() if path.is_file() else []

    def stub_calls(self):
        return [json.loads(line) for line in self.lines(".env")]

    def test_a_work_directory_inside_the_checkout_or_unusable_is_refused(self):
        self.commit()
        status = ["git", "-C", str(self.repo), "status", "--porcelain", "--ignored", "--untracked-files=all"]
        before = subprocess.run(status, capture_output=True, text=True, check=True).stdout
        (self.base / "link").symlink_to(self.repo)
        for work in (self.repo / "work", f"{self.base}/elsewhere/../repo/work", self.base / "link/work"):
            inside, _ = self.run_rows(RUN_FENCE, work=work)
            self.assertEqual(inside.returncode, 2)
            self.assertIn("lies inside the checkout", inside.stderr)
        self.assertEqual(subprocess.run(status, capture_output=True, text=True, check=True).stdout, before)
        full = self.base / "full"
        full.mkdir()
        (full / "x").write_text("x")
        plain = self.base / "plain"
        plain.write_text("x")
        for work, text in ((full, "is not empty"), (plain, f"the work directory {plain} cannot be listed"),
                           (plain / "sub", f"the work directory {plain / 'sub'} cannot hold the copy")):
            with self.subTest(work=work):
                refused, report = self.run_rows(RUN_FENCE, work=work)
                self.assertEqual(refused.returncode, 2)
                self.assertIn(text, refused.stderr)
                self.assertNotIn("Traceback", refused.stderr)
                self.assertEqual((report, self.stub_calls()), ({}, []))
        self.assertFalse((self.repo / "work").exists())

    def test_the_run_tests_hold_under_a_temporary_directory_behind_a_symbolic_link(self):
        # `run` resolves its work directory, so the fixture expects resolved paths in the report and the build environment.
        (self.base / "real").mkdir()
        (self.base / "alias").symlink_to("real")
        nested = unittest.TestResult()
        with mock.patch.object(tempfile, "tempdir", str(self.base / "alias")):
            RunCommand("test_the_named_failure_kills_and_the_checkout_is_unchanged").run(nested)
        self.assertEqual(nested.testsRun, 1)
        self.assertFalse(nested.failures + nested.errors, "\n".join(text for _, text in nested.failures + nested.errors))

    def test_a_run_whose_judging_scripts_differ_from_head_is_refused(self):
        self.commit()
        for name in ("weaken-orderings", "classify-atomics", "judge-genmc", "judge-rc11"):
            with self.subTest(script=name):
                path = self.repo / f"scripts/{name}.py"
                original = path.read_text()
                path.write_text(original + "\n")
                try:
                    result, report = self.run_rows(RUN_FENCE, work=self.base / f"dirty-{name}")
                finally:
                    path.write_text(original)
                self.assertEqual(result.returncode, 2)
                self.assertIn("differ from HEAD", result.stderr)
                self.assertEqual((report, self.lines(".log")), ({}, []))

    def test_the_named_failure_kills_and_the_checkout_is_unchanged(self):
        self.assertIsNotNone(RUN_SITE)
        revision = self.commit()
        status = ["git", "-C", str(self.repo), "status", "--porcelain", "--ignored", "--untracked-files=all"]
        before = subprocess.run(status, capture_output=True, text=True, check=True).stdout
        plan = {test: {"planted": f"fail:{RUN_FAILURE}", "at": RUN_AT} for test in RUN_TESTS}
        result, report = self.run_rows(RUN_FENCE, plan=plan, env={"CARGO_BUILD_JOBS": "3"})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"running the committed revision {revision}", result.stderr)
        self.assertEqual(self.results(report, RUN_FENCE), ["killed"] * len(RUN_TESTS))
        self.assertEqual(subprocess.run(status, capture_output=True, text=True, check=True).stdout, before)
        self.assertEqual(report["revision"], revision)
        pins = WEAKEN.workflow_pins(self.repo)
        self.assertEqual((report["pins"]["STABLE"], report["pins"]["NIGHTLY"], report["pins"]["loom resolved"], report["pins"]["rustc"]),
                         (pins["STABLE"], pins["NIGHTLY"], f"v{pins['LOOM']}", f"rustc +{pins['STABLE']}-stub"))
        self.assertEqual((report["pins"]["host"], report["pins"]["cpus"], report["pins"]["CARGO_BUILD_JOBS"]), (os.uname().machine, os.cpu_count(), "3"))
        self.assertEqual((self.base / "work/copy/Cargo.lock").read_text(), "stub lock\n")
        self.assertEqual(report["pins"]["Cargo.lock sha256"], hashlib.sha256(b"stub lock\n").hexdigest())
        self.assertEqual([entry["exit"] for entry in report["baseline"]], [0] * len(RUN_TESTS))
        self.assertEqual([entry["exit"] for entry in report["rows"][RUN_FENCE]["results"]], [101] * len(RUN_TESTS))
        fence = row(self.catalog, RUN_FENCE)
        self.assertEqual(report["rows"][RUN_FENCE]["plant"], {"path": fence["path"], "find": fence["find"], "replace": fence["replace"]})
        self.assertIsNone(report["rows"][RUN_FENCE]["expected"])
        self.assertGreaterEqual(report["seconds"], report["rows"][RUN_FENCE]["seconds"])
        label = f"row{[entry['id'] for entry in self.catalog['rows']].index(RUN_FENCE):02d}"
        outputs = set()
        for entry in report["baseline"] + report["rows"][RUN_FENCE]["results"]:
            self.assertEqual(entry["command"], f'RUSTFLAGS="--cfg loom" cargo +{pins["STABLE"]} test -p kestrike --lib --release '
                                               f'{entry["test"]} -- --exact')
            self.assertEqual(entry["digest"], hashlib.sha256(Path(entry["output"]).read_bytes()).hexdigest())
            self.assertTrue(Path(entry["output"]).is_relative_to(self.base / "work/evidence"), entry)
            self.assertIsInstance(entry["seconds"], float)
            outputs.add(entry["output"])
        self.assertEqual(len(outputs), 2 * len(RUN_TESTS))
        self.assertTrue(all(f"-{label}-" in output for output in (entry["output"] for entry in report["rows"][RUN_FENCE]["results"])))
        log = self.lines(".log")
        self.assertTrue(all(" --cfg loom " in line and f"{self.base / 'work'}/target-loom" in line and " [] None never/false " in line
                            for line in log), log)
        original = (self.repo / fence["path"]).read_text()
        planted = original.replace(fence["find"], fence["replace"])
        self.assertEqual(original.count(fence["find"]), 1)
        self.assertEqual({line.split()[-1] for line in log if " planted " in line}, {hashlib.sha256(planted.encode()).hexdigest()})
        for path in CATALOG["files"]:
            self.assertEqual((self.base / "work/copy" / path).read_bytes(), (self.repo / path).read_bytes(), path)
        self.assertEqual(list((self.base / "work/copy").rglob("*.weaken")), [])

    def test_a_named_failure_at_another_assertion_is_no_verdict(self):
        self.commit()
        plan = {test: {"planted": f"fail:protection violated: {RUN_FAILURE}", "at": f"{RUN_SITE[0]}:{RUN_SITE[1] + 40}"} for test in RUN_TESTS}
        result, report = self.run_rows(RUN_FENCE, plan=plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        first = report["rows"][RUN_FENCE]["results"][0]
        self.assertEqual((first["result"], first["reason"]), ("no verdict", "failed with another text or at another assertion"))

    def test_the_loom_build_runs_without_the_operators_build_overrides(self):
        self.commit()
        ambient = {"RUSTC_WRAPPER": "sccache", "RUSTC": "/elsewhere/rustc", "CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS": "false",
                   "CARGO_TARGET_AARCH64_UNKNOWN_LINUX_GNU_RUNNER": "/elsewhere/run", "CARGO_BUILD_TARGET": "x86_64-unknown-linux-gnu",
                   "CARGO_BUILD_BUILD_DIR": str(self.base / "elsewhere"), "RUSTDOCFLAGS": "--cfg x", "CARGO_BUILD_JOBS": None}
        result, report = self.run_rows(RUN_FENCE, env=ambient)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(report["pins"]["CARGO_BUILD_JOBS"])
        target = str(self.base / "work/target-loom")
        for call in self.stub_calls():
            self.assertEqual(call["env"], {"RUSTFLAGS": "--cfg loom", "CARGO_TARGET_DIR": target, "CARGO_BUILD_BUILD_DIR": target}, call)

    def test_a_pass_under_the_plant_survives(self):
        self.commit()
        result, report = self.run_rows(RUN_FENCE)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.results(report, RUN_FENCE), ["survived"] * len(RUN_TESTS))
        self.assertEqual((report["mismatched"], report["no verdict"]), ([], []))

    def test_every_other_outcome_is_no_verdict(self):
        self.commit()
        reasons = {"build": "a build failure", "fail:another assertion": "failed with another text or at another assertion",
                   "none": "the test is absent: no test matched its name", "ignored": "the test is ignored",
                   "norebuild": "no evidence that kestrike rebuilt", "crash": "the test crashed: its run ended without a summary"}
        for mode, reason in reasons.items():
            with self.subTest(mode=mode):
                work = self.base / f"work-{mode.replace(':', '-').replace(' ', '-')}"
                result, report = self.run_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"planted": mode, "at": RUN_AT}})
                self.assertEqual(result.returncode, 0, result.stderr)
                first = report["rows"][RUN_FENCE]["results"][0]
                self.assertEqual((first["result"], first["reason"]), ("no verdict", reason))
                self.assertEqual(report["no verdict"], [RUN_FENCE])
                self.assertIn('"no verdict": ["fill-run-fence"]', result.stdout)

    def test_a_red_baseline_stops_the_run_with_no_row_result(self):
        self.commit()
        for mode in (f"fail:{RUN_FAILURE}", "none", "ignored"):
            with self.subTest(mode=mode):
                work = self.base / f"red-{mode.split(':')[0]}"
                result, report = self.run_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"clean": mode}})
                self.assertEqual(result.returncode, 3, result.stderr)
                self.assertEqual(report, {})
                self.assertIn('"rows": {}', result.stderr)
                self.assertEqual(json.loads((work / "progress.json").read_text())["rows"], {})

    def test_a_red_test_of_a_later_row_stops_the_run_before_any_plant(self):
        self.commit()
        work = self.base / "red-later"
        result, report = self.run_rows(RUN_FENCE, JOIN_ROW, work=work, plan={"join-production": {"clean": f"violation:{JOIN_FREED}"}})
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(report, {})
        lanes, log = self.lines(".lane"), self.lines(".log")
        self.assertEqual([line.split()[0] for line in lanes], ["clean"])
        self.assertFalse(any(" planted " in line for line in log), log)

    def test_a_result_that_differs_from_a_decided_row_fails_and_names_it(self):
        def decide(catalog):
            decided(catalog, RUN_FENCE, "kill", SEEDED[RUN_FENCE])
        self.commit(decide)
        result, report = self.run_rows(RUN_FENCE)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(report["mismatched"], [RUN_FENCE])
        self.assertIs(report["rows"][RUN_FENCE]["agrees"], False)
        self.assertEqual(report["rows"][RUN_FENCE]["expected"], "killed")

    def test_a_kill_row_agrees_only_when_every_test_is_killed(self):
        def decide(catalog):
            decided(catalog, RUN_FENCE, "kill", SEEDED[RUN_FENCE])
        self.commit(decide)
        killed = {"planted": f"fail:{RUN_FAILURE}", "at": RUN_AT}
        result, report = self.run_rows(RUN_FENCE, plan={RUN_TESTS[0]: killed})
        self.assertEqual((result.returncode, report["mismatched"]), (1, [RUN_FENCE]), result.stderr)
        result, report = self.run_rows(RUN_FENCE, work=self.base / "built", plan={RUN_TESTS[0]: killed, RUN_TESTS[1]: {"planted": "build"}})
        self.assertEqual((result.returncode, report["mismatched"], report["no verdict"]), (1, [RUN_FENCE], [RUN_FENCE]), result.stderr)
        result, report = self.run_rows(RUN_FENCE, work=self.base / "killed", plan=dict.fromkeys(RUN_TESTS, killed))
        self.assertEqual((result.returncode, report["mismatched"]), (0, []), result.stderr)
        self.assertEqual(self.results(report, RUN_FENCE), ["killed"] * len(RUN_TESTS))
        self.assertIs(report["rows"][RUN_FENCE]["agrees"], True)

    def test_a_survives_row_agrees_only_when_its_tests_pass(self):
        def decide(catalog):
            decided(catalog, RUN_FENCE, "survives", {"reason": "planted", "passed": [{"lane": "loom", "tests": RUN_TESTS}]})
        self.commit(decide)
        result, report = self.run_rows(RUN_FENCE)
        self.assertEqual((result.returncode, report["mismatched"]), (0, []), result.stderr)
        result, report = self.run_rows(RUN_FENCE, work=self.base / "killed", plan={RUN_TESTS[0]: {"planted": f"fail:{RUN_FAILURE}"}})
        self.assertEqual((result.returncode, report["mismatched"]), (1, [RUN_FENCE]), result.stderr)

    def test_a_later_row_needs_its_own_rebuild(self):
        rows = [entry["id"] for entry in self.catalog["rows"]]
        self.assertLess(rows.index(DEPART_ROW), rows.index(RUN_FENCE))
        self.assertNotIn(DEPART_TESTS[0], RUN_TESTS)
        self.commit()
        plan = {test: {"planted": "norebuild"} for test in RUN_TESTS}
        result, report = self.run_rows(RUN_FENCE, DEPART_ROW, plan=plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.results(report, DEPART_ROW), ["survived"] * len(DEPART_TESTS))
        self.assertEqual(set(self.results(report, RUN_FENCE)), {"no verdict"})

    def test_a_changed_scoped_file_stops_the_run_with_exit_4(self):
        self.commit()
        self.assertNotEqual(CATALOG["files"][0], row(self.catalog, RUN_FENCE)["path"])
        self.assertEqual(CATALOG["files"][3], row(self.catalog, RUN_FENCE)["path"])
        differ = f"the scoped files ['{CATALOG['files'][0]}'] differ from the unweakened copy"
        # A privileged user reads a file of mode 0, so that mode changes nothing for it.
        unreadable = [("unreadable-other", differ)] if os.geteuid() else []
        for mode, text in (("drift", differ), ("link", differ), ("gone-other", differ), ("dir-other", differ), *unreadable,
                           ("drift-own", f"the plant of {CATALOG['files'][3]} changed"),
                           ("dir-own", f"the unweakened {CATALOG['files'][3]} cannot be written back")):
            with self.subTest(mode=mode):
                work = self.base / f"changed-{mode}"
                result, report = self.run_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"planted": mode}})
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn(text, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual(report, {})
                self.assertEqual(json.loads((work / "progress.json").read_text())["active"], RUN_FENCE)

    def test_a_baseline_test_that_changes_a_scoped_file_stops_the_run_with_exit_4(self):
        self.commit()
        changed = CATALOG["files"][0]
        ran = sorted(RUN_TESTS)[:sorted(RUN_TESTS).index(RUN_TESTS[0]) + 1]
        for mode in ("drift", "gone-other"):
            with self.subTest(mode=mode):
                work = self.base / f"baseline-{mode}"
                result, report = self.run_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"clean": mode}})
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn(f"the scoped files ['{changed}'] differ from the unweakened copy after the baseline test {RUN_TESTS[0]}",
                              result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual([line.split()[:2] for line in self.lines(".log")], [[test, "clean"] for test in ran])
                progress = json.loads((work / "progress.json").read_text())
                self.assertEqual(([entry["test"] for entry in progress["baseline"]], progress["rows"], report), (ran, {}, {}))

    def test_a_planted_file_a_test_removed_or_replaced_with_an_unreadable_link_is_written_back_with_exit_4(self):
        self.commit()
        name = row(self.catalog, RUN_FENCE)["path"]
        self.assertEqual(CATALOG["files"][3], name)
        for mode in ("gone", "dangling", "loop", *(["unreadable"] if os.geteuid() else [])):
            with self.subTest(mode=mode):
                work = self.base / f"replaced-{mode}"
                result, report = self.run_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"planted": mode}})
                self.assertEqual(result.returncode, 4, result.stderr)
                self.assertIn(f"the plant of {name} changed", result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                restored = work / "copy" / name
                self.assertFalse(restored.is_symlink())
                self.assertEqual(restored.read_bytes(), (self.repo / name).read_bytes())
                self.assertEqual(restored.stat().st_mode, (work / "copy" / CATALOG["files"][0]).stat().st_mode)
                self.assertEqual(report, {})

    def test_a_genmc_declaration_the_copys_judge_refuses_stops_a_run_that_selects_a_case(self):
        declaration = self.repo / WEAKEN.GENMC
        committed = json.loads(declaration.read_text())

        def drifted(declared):
            next(entry for entry in declared["bindings"] if entry["id"] == "claim-load")["orderings"] = ["Acquire"]

        def disagreeing(declared):
            declared["cases"]["credit-seq-empty"]["litmus"] = ["L0-no-fences"]

        for change, text in ((drifted, "correspondence drift: claim-load"), (disagreeing, "credit-seq-empty is declared positive")):
            with self.subTest(change=change.__name__):
                planted = copy.deepcopy(committed)
                change(planted)
                declaration.write_text(json.dumps(planted))
                self.commit()
                result, report = self.run_rows(CREDIT_ROW, work=self.base / change.__name__)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(text, result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertEqual((report, self.lines(".lane")), ({}, []))
        loom, report = self.run_rows(RUN_FENCE, work=self.base / "loom-only")
        self.assertEqual((loom.returncode, set(self.results(report, RUN_FENCE))), (0, {"survived"}), loom.stderr)

    def test_a_planted_file_a_text_restore_cannot_reproduce_is_refused(self):
        credit = self.repo / CATALOG["files"][0]
        credit.write_bytes(credit.read_bytes().replace(b"\n", b"\r\n"))
        self.commit()
        result, report = self.run_rows(CREDIT_ROW)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(f"the scoped files ['{CATALOG['files'][0]}'] hold line endings", result.stderr)
        self.assertEqual((report, self.lines(".lane")), ({}, []))

    def test_an_interrupted_run_restores_the_plant_and_keeps_the_finished_results(self):
        self.commit()
        for number in (signal.SIGTERM, signal.SIGHUP):
            with self.subTest(signal=number):
                work = self.base / f"interrupted-{number}"
                child = self.start_rows(CREDIT_ROW, RUN_FENCE, work=work, plan={RUN_TESTS[1]: {"planted": "sleep"}})
                self.wait_for(".sleeping")
                started = time.monotonic()
                child.send_signal(number)
                child.wait(timeout=120)
                self.assertLess(time.monotonic() - started, 50)
                self.assertEqual(child.returncode, -signal.SIGINT)
                self.assertTrue(Path(str(self.plan) + ".stopped").exists(), "the sleeping test received SIGTERM")
                self.assertFalse((work / "report.json").exists())
                progress = json.loads((work / "progress.json").read_text())
                self.assertEqual(progress["active"], RUN_FENCE)
                self.assertEqual(self.results(progress, CREDIT_ROW), ["survived"] * 4)
                self.assertEqual([result["test"] for result in progress["rows"][RUN_FENCE]["results"]], RUN_TESTS[:1])
                self.assertNotIn("agrees", progress["rows"][RUN_FENCE])
                for path in CATALOG["files"]:
                    self.assertEqual((work / "copy" / path).read_bytes(), (self.repo / path).read_bytes(), path)
                self.assertEqual(list((work / "copy").rglob("*.weaken")), [])

    def test_a_second_signal_as_the_restore_begins_still_restores_the_plant(self):
        self.commit()
        work = self.base / "restore-entry"
        child = self.start_rows(RUN_FENCE, work=work, plan={RUN_TESTS[1]: {"planted": "sleep"}}, inject="restore")
        self.wait_for(".sleeping")
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=120)
        self.assertEqual(child.returncode, -signal.SIGINT)
        self.assertTrue(Path(str(self.plan) + ".stopped").exists(), "the sleeping test received SIGTERM")
        self.assertFalse((work / "report.json").exists())
        for path in CATALOG["files"]:
            self.assertEqual((work / "copy" / path).read_bytes(), (self.repo / path).read_bytes(), path)
        self.assertEqual(list((work / "copy").rglob("*.weaken")), [])

    def test_a_signal_between_a_rows_tests_starts_no_further_test_and_restores_the_plant(self):
        self.commit()
        work = self.base / "between"
        child = self.start_rows(RUN_FENCE, work=work, inject="between")
        child.wait(timeout=120)
        self.assertEqual(child.returncode, -signal.SIGINT)
        self.assertEqual([line.split()[:2] for line in self.lines(".log") if line.split()[1] == "planted"], [[RUN_TESTS[0], "planted"]])
        self.assertFalse((work / "report.json").exists())
        for path in CATALOG["files"]:
            self.assertEqual((work / "copy" / path).read_bytes(), (self.repo / path).read_bytes(), path)

    def test_progress_records_each_finished_baseline_test_and_skipped_row(self):
        self.commit()
        self.assertLess(RUN_TESTS[1], RUN_TESTS[0])
        work = self.base / "baseline-progress"
        child = self.start_rows(RUN_FENCE, work=work, plan={RUN_TESTS[0]: {"clean": "sleep"}})
        self.wait_for(".sleeping")
        progress = json.loads((work / "progress.json").read_text())
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=120)
        self.assertEqual((progress["active"], [result["test"] for result in progress["baseline"]]), ("baseline", RUN_TESTS[1:]))
        result, report = self.run_rows("word-install", work=self.base / "skipped")
        self.assertEqual(result.returncode, 0, result.stderr)
        progress = json.loads((self.base / "skipped/progress.json").read_text())
        self.assertEqual((progress["active"], progress["rows"]["word-install"]["result"]), (None, "skipped"))

    def test_report_files_take_the_umask_mode(self):
        self.commit()
        for umask, mode in ((0o022, 0o644), (0o077, 0o600)):
            with self.subTest(umask=oct(umask)):
                work = self.base / f"umask-{umask:o}"
                result, _ = self.run_rows(RUN_FENCE, work=work, umask=umask)
                self.assertEqual(result.returncode, 0, result.stderr)
                for name in ("report.json", "progress.json"):
                    self.assertEqual((work / name).stat().st_mode & 0o777, mode, name)

    def test_a_genmc_row_runs_the_case_list_lane_and_judges_each_case(self):
        self.commit()
        result, report = self.run_rows(JOIN_ROW, plan={"join-production": {"planted": f"violation:{JOIN_FREED}"}})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.results(report, JOIN_ROW), ["killed"])
        entry = report["rows"][JOIN_ROW]["results"][0]
        self.assertEqual((entry["command"], entry["exit"], entry["lane_exit"]), ("bash scripts/rust-lane.sh genmc pr join-production", 42, 0))
        self.assertEqual(entry["digest"], hashlib.sha256(Path(entry["output"]).read_bytes()).hexdigest())
        self.assertEqual(Path(entry["output"]).name, "genmc-join-production.txt")
        self.assertEqual((entry["executions"], report["baseline"][0]["executions"]), (0, 5))
        lanes = self.lines(".lane")
        self.assertEqual([line.split()[0] for line in lanes], ["clean", "planted"])
        self.assertEqual(Path(entry["output"]).parent, Path(lanes[1].split()[1]))
        self.assertTrue(all(line.split()[1].startswith(str(self.base / "work") + "/") and line.split()[2] == "never/false" for line in lanes),
                        lanes)
        result, report = self.run_rows(JOIN_ROW, work=self.base / "survived")
        self.assertEqual(self.results(report, JOIN_ROW), ["survived"])
        self.assertEqual((report["rows"][JOIN_ROW]["results"][0]["exit"], report["rows"][JOIN_ROW]["results"][0]["executions"]), (0, 3))
        for mode, reason in (("norebuild", "no evidence that the kernel rebuilt"), ("abort", "the lane left no output"), ("badexit", "no exit code")):
            with self.subTest(mode=mode):
                result, report = self.run_rows(JOIN_ROW, work=self.base / f"lane-{mode}", plan={"join-production": {"planted": mode}})
                self.assertEqual(result.returncode, 0, result.stderr)
                entry = report["rows"][JOIN_ROW]["results"][0]
                self.assertEqual((entry["result"], entry["reason"], entry["executions"]), ("no verdict", reason, None))
                if mode == "abort":
                    self.assertEqual((entry["exit"], entry["lane_exit"], entry["digest"]), (None, 1, None))
        result, _ = self.run_rows(JOIN_ROW, work=self.base / "red", plan={"join-production": {"clean": f"violation:{JOIN_FREED}"}})
        self.assertEqual(result.returncode, 3, result.stderr)

    def test_a_multi_case_entry_judges_each_case_by_its_own_output(self):
        self.commit()
        plan = {case: {"planted": f"violation:{CREDIT_FLAGGED}"} for case in CREDIT_CASES if case != "credit-seq-empty"}
        plan["grace1-seq"] = {"planted": f"violation:{RETAIN}"}
        result, report = self.run_rows(CREDIT_ROW, GRACE_ROW, plan=plan)
        self.assertEqual(result.returncode, 0, result.stderr)
        credit = {entry["test"]: (entry["result"], entry["exit"]) for entry in report["rows"][CREDIT_ROW]["results"]}
        self.assertEqual(credit, {case: ("survived", 0) if case == "credit-seq-empty" else ("killed", 42) for case in CREDIT_CASES})
        for entry in report["rows"][CREDIT_ROW]["results"]:
            self.assertEqual(Path(entry["output"]).name, f"genmc-{entry['test']}.txt")
            self.assertEqual(entry["digest"], hashlib.sha256(Path(entry["output"]).read_bytes()).hexdigest())
        grace = [(entry["test"], entry["result"]) for entry in report["rows"][GRACE_ROW]["results"]]
        self.assertEqual(grace, [("grace1-seq", "no verdict"), ("grace1-seq", "killed"), ("cutoff-pinfirst", "survived")])
        self.assertEqual(len({entry["output"] for entry in report["rows"][GRACE_ROW]["results"][:2]}), 1)
        self.assertEqual(report["no verdict"], [])
        planted = [line.split()[3:] for line in self.lines(".lane") if line.startswith("planted ")]
        self.assertEqual(planted, [["genmc", "pr", *CREDIT_CASES], ["genmc", "pr", "grace1-seq"], ["genmc", "pr", "cutoff-pinfirst"]])

    def test_a_test_a_row_names_twice_runs_once(self):
        def twice(catalog):
            needing(catalog, RUN_FENCE, [{"lane": "loom", "tests": [RUN_TESTS[0], RUN_TESTS[0]], "failure": RUN_FAILURE}])
            needing(catalog, JOIN_ROW, [{"lane": "genmc", "tests": ["join-production", "join-production"], "failure": JOIN_FREED}] * 2)
        self.commit(twice)
        result, report = self.run_rows(RUN_FENCE, JOIN_ROW)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(len([line for line in self.lines(".log") if " planted " in line]), 1)
        self.assertEqual([line.split()[3:] for line in self.lines(".lane") if line.startswith("planted ")], [["genmc", "pr", "join-production"]])
        for name, count in ((RUN_FENCE, 2), (JOIN_ROW, 4)):
            entries = report["rows"][name]["results"]
            self.assertEqual((len(entries), len({entry["output"] for entry in entries})), (count, 1), entries)
            self.assertEqual({entry["digest"] for entry in entries}, {hashlib.sha256(Path(entries[0]["output"]).read_bytes()).hexdigest()})

    def test_a_row_id_never_names_an_output_path(self):
        def rename(catalog):
            row(catalog, RUN_FENCE)["id"] = "baseline"
            row(catalog, JOIN_ROW)["id"] = "../../escape"
        self.commit(rename)
        work = self.base / "ids"
        result, report = self.run_rows("baseline", "../../escape", work=work)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(report["rows"]), ["../../escape", "baseline"])
        outputs = [entry["output"] for entry in report["baseline"] + [result for record in report["rows"].values() for result in record["results"]]]
        self.assertEqual(len(set(outputs)), len(outputs))
        self.assertTrue(all(Path(output).resolve().is_relative_to((work / "evidence").resolve()) for output in outputs), outputs)
        self.assertEqual([path.name for path in self.base.iterdir() if path.name.startswith("escape")], [])

    def test_a_row_no_model_runs_is_skipped_and_agrees(self):
        def decide(catalog):
            decided(catalog, "word-install", "survives", {"reason": "no model runs the site", "passed": []})
        self.commit(decide)
        result, report = self.run_rows("word-install")
        self.assertEqual(result.returncode, 0, result.stderr)
        skipped = report["rows"]["word-install"]
        self.assertEqual((skipped["result"], skipped["reason"], skipped["agrees"]), ("skipped", "no model runs the site", True))
        self.assertEqual(report["baseline"], [])
        self.assertEqual([call["args"][1] for call in self.stub_calls()], ["tree"])

    def test_a_run_without_rows_selects_every_row(self):
        self.commit()
        result, report = self.run_rows()
        self.assertIn(result.returncode, (0, 1), result.stderr)
        self.assertEqual(list(report["rows"]), [entry["id"] for entry in self.catalog["rows"]])

    def test_an_unknown_row_stops_the_run(self):
        self.commit()
        work = self.base / "unknown"
        result, report = self.run_rows(RUN_FENCE, "no-such-row", work=work)
        self.assertEqual(result.returncode, 2)
        self.assertIn("no catalog row named ['no-such-row']", result.stderr)
        self.assertEqual((report, self.lines(".log")), ({}, []))

    def test_a_refused_catalog_or_declaration_stops_the_run(self):
        self.commit(lambda catalog: row(catalog, "grace-visit").update(replace="const VISIT: Ordering = Ordering::Relaxed;"))
        result, _ = self.run_rows("grace-visit")
        self.assertEqual(result.returncode, 2)
        self.assertIn("check refuses the copy's catalog", result.stderr)
        declaration = self.repo / WEAKEN.GENMC
        declared = json.loads(declaration.read_text())
        declaration.write_text(json.dumps(dict(declared, package=None)))
        self.commit()
        result, _ = self.run_rows(RUN_FENCE, work=self.base / "package")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("check refuses the copy's catalog", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_a_stray_source_in_the_invoking_checkout_leaves_the_copy_s_check_alone(self):
        self.commit()
        stray = self.repo / WEAKEN.CRATE / "stray.rs"
        stray.write_text('#[path = concat!("storage/", "fill.rs")] mod fill;\n')
        report, code = WEAKEN.check(lambda path: (self.repo / path).read_text(encoding="utf-8"), self.repo, self.repo)
        self.assertEqual(code, 1, report)
        self.assertIn(f"{WEAKEN.CRATE}/stray.rs holds a path attribute the scope rule cannot read",
                      [entry["message"] for entry in report["refusals"]])
        result, _ = self.run_rows(RUN_FENCE)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_shaping_cargo_configuration_or_another_loom_stops_the_run(self):
        self.commit()
        refusals = ((RUN_FENCE, {"STUB_CONFIG": json.dumps({"env": {"LOOM_MAX_PREEMPTIONS": "1"}})}, "env.LOOM_MAX_PREEMPTIONS"),
                    (RUN_FENCE, {"STUB_CONFIG": json.dumps({"build": {"target-dir": str(self.base / "elsewhere")}})}, "build.target-dir"),
                    (RUN_FENCE, {"STUB_CONFIG": json.dumps({"build": {"build-dir": str(self.base / "elsewhere")}})}, "build.build-dir"),
                    (JOIN_ROW, {"STUB_CONFIG_KERNELS": json.dumps({"build": {"target-dir": str(self.base / "elsewhere")}})}, "build.target-dir"),
                    (RUN_FENCE, {"STUB_CONFIG_EXIT": "101", "STUB_CONFIG_ERR": "error: unknown -Z flag"}, "exited 101: error: unknown -Z flag"),
                    (RUN_FENCE, {"STUB_LOOM": "loom v0.7.3"}, "the copy resolves loom v0.7.3"),
                    (RUN_FENCE, {"STUB_TREE_EXIT": "101"}, "the copy resolves loom unresolved"))
        for index, (name, env, text) in enumerate(refusals):
            with self.subTest(text=text, row=name):
                result, report = self.run_rows(name, work=self.base / f"config-{index}", env=env)
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(text, result.stderr)
                self.assertEqual((report, self.lines(".log"), self.lines(".lane")), ({}, [], []))
        result, report = self.run_rows(JOIN_ROW, work=self.base / "genmc-only", env={"STUB_LOOM": "loom v0.7.3",
                                                                                      "STUB_CONFIG": json.dumps({"env": {"LOOM_X": "1"}})})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(report["pins"]["loom resolved"], "v0.7.3")
        result, _ = self.run_rows(RUN_FENCE, work=self.base / "loom-only", env={"STUB_CONFIG_KERNELS": json.dumps({"build": {"target-dir": "/x"}})})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(any(call["cwd"].endswith("kernels") for call in self.stub_calls()))


class Verdicts(unittest.TestCase):
    """The process handling and the loom and GenMC result rules over planted output."""

    def test_an_interrupted_command_leaves_no_process_behind(self):
        marker = Path(tempfile.mkdtemp(prefix="weaken-execute-"))
        self.addCleanup(shutil.rmtree, marker)
        script = ("import signal, subprocess, sys, time\n"
                  f"sys.path.insert(0, {str(SCRIPT.parent)!r})\n"
                  "import importlib.util\n"
                  f"spec = importlib.util.spec_from_file_location('w', {str(SCRIPT)!r})\n"
                  "w = importlib.util.module_from_spec(spec); spec.loader.exec_module(w)\n"
                  "signal.signal(signal.SIGTERM, lambda *a: (_ for _ in ()).throw(KeyboardInterrupt()))\n"
                  f"w.execute(['sh', '-c', 'echo $$ > {marker}/pid; exec sleep 60'], '.', None, 120, {str(marker / 'out')!r})\n")
        child = subprocess.Popen([sys.executable, "-c", script])
        for _ in range(100):
            if (marker / "pid").is_file() and (marker / "pid").read_text().strip():
                break
            time.sleep(0.1)
        pid = int((marker / "pid").read_text())
        child.send_signal(signal.SIGTERM)
        child.wait(timeout=30)
        time.sleep(0.5)
        self.assertFalse(process_running(pid))

    def group(self, marker, leader_ignores_term):
        """A command whose leader writes `ready` once its same-group worker, which ignores SIGTERM, has written its pid."""
        trap = "trap '' TERM; " if leader_ignores_term else ""
        return ["sh", "-c", f"{trap}sh -c 'trap \"\" TERM; echo $$ > {marker}/worker; exec sleep 120' & "
                            f"while [ ! -s {marker}/worker ]; do sleep 0.05; done; echo $$ > {marker}/leader; exec sleep 120"]

    def reap_later(self, marker):
        def stop():
            for name in ("worker", "leader"):
                path = marker / name
                if path.is_file() and process_running(int(path.read_text())):
                    os.kill(int(path.read_text()), signal.SIGKILL)
        self.addCleanup(stop)

    def test_a_deadline_ends_the_whole_process_group(self):
        marker = Path(tempfile.mkdtemp(prefix="weaken-deadline-"))
        self.addCleanup(shutil.rmtree, marker)
        self.reap_later(marker)
        code, seconds = WEAKEN.execute(self.group(marker, False), ".", None, 2, marker / "out")
        self.assertTrue((marker / "leader").is_file())
        self.assertIsNone(code)
        self.assertLess(seconds, 30)
        time.sleep(0.2)
        self.assertFalse(process_running(int((marker / "worker").read_text())))
        self.assertEqual(WEAKEN.loom_result("", code, RUN_FAILURE, True), ("no verdict", "timeout"))

    def test_a_second_signal_during_the_grace_still_kills_the_group(self):
        marker = Path(tempfile.mkdtemp(prefix="weaken-grace-"))
        self.addCleanup(shutil.rmtree, marker)
        self.reap_later(marker)
        child = subprocess.Popen(self.group(marker, True), start_new_session=True)
        for _ in range(200):
            if (marker / "leader").is_file():
                break
            time.sleep(0.05)
        previous = signal.signal(signal.SIGTERM, WEAKEN.interrupted)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        timer = threading.Timer(0.5, os.kill, (os.getpid(), signal.SIGTERM))
        timer.start()
        self.addCleanup(timer.cancel)
        started = time.monotonic()
        with self.assertRaises(KeyboardInterrupt):
            WEAKEN.stop_group(child, grace=30)
        self.assertLess(time.monotonic() - started, 20)
        time.sleep(0.2)
        self.assertIsNotNone(child.returncode)
        self.assertFalse(process_running(int((marker / "worker").read_text())))

    def test_a_signal_while_a_child_starts_stops_that_child(self):
        started = []
        real = subprocess.Popen

        def spawn(*args, **kwargs):
            child = real(*args, **kwargs)
            started.append(child.pid)
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(100):
                time.sleep(0.01)
            return child
        previous = signal.signal(signal.SIGTERM, WEAKEN.interrupted)
        self.addCleanup(signal.signal, signal.SIGTERM, previous)
        output = Path(tempfile.mkdtemp(prefix="weaken-spawn-")) / "out"
        self.addCleanup(shutil.rmtree, output.parent)
        with mock.patch.object(WEAKEN.subprocess, "Popen", spawn), self.assertRaises(KeyboardInterrupt):
            WEAKEN.execute(["sleep", "60"], ".", None, 120, output)
        self.assertIsNone(WEAKEN.HELD)
        self.assertFalse(process_running(started[0]))

    def test_a_signal_after_the_stop_is_raised_and_the_hold_is_released(self):
        """A signal recorded after a test's group has ended still raises from `execute`, and the released hold leaves
        the next handled signal raising at once; a command that cannot start releases the hold too."""
        real = WEAKEN.stop_group

        def stop(child, *args, **kwargs):
            real(child, *args, **kwargs)
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.01)
        self.addCleanup(signal.signal, signal.SIGTERM, signal.signal(signal.SIGTERM, WEAKEN.interrupted))
        directory = Path(tempfile.mkdtemp(prefix="weaken-release-"))
        self.addCleanup(shutil.rmtree, directory)
        with mock.patch.object(WEAKEN, "stop_group", stop), self.assertRaises(KeyboardInterrupt):
            WEAKEN.execute(["true"], ".", None, 120, directory / "out")
        self.assertIsNone(WEAKEN.HELD)
        with self.assertRaises(KeyboardInterrupt):
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(100):
                time.sleep(0.01)
        with self.assertRaises(FileNotFoundError):
            WEAKEN.execute([str(directory / "absent")], ".", None, 120, directory / "absent.out")
        self.assertIsNone(WEAKEN.HELD)

    def test_a_hold_records_signals_and_raises_one_at_its_release(self):
        self.addCleanup(signal.signal, signal.SIGTERM, signal.signal(signal.SIGTERM, WEAKEN.interrupted))

        def deliver():
            os.kill(os.getpid(), signal.SIGTERM)
            for _ in range(20):
                time.sleep(0.01)
        with WEAKEN.holding() as quiet:
            pass
        self.assertEqual((quiet, WEAKEN.HELD), ([], None))
        reached = []
        with self.assertRaises(KeyboardInterrupt) as raised:
            with WEAKEN.holding() as outer:
                with WEAKEN.holding() as inner:
                    deliver()
                self.assertIs(inner, outer)
                self.assertIs(WEAKEN.HELD, outer)
                deliver()
                reached.append(list(outer))
                raise ValueError("the block's own failure")
        self.assertEqual(reached, [[signal.SIGTERM, signal.SIGTERM]])
        self.assertIsInstance(raised.exception.__context__, ValueError)
        self.assertIsNone(WEAKEN.HELD)
        first = KeyboardInterrupt("the block's own interrupt")
        with self.assertRaises(KeyboardInterrupt) as raised:
            with WEAKEN.holding():
                deliver()
                raise first
        self.assertIs(raised.exception, first)

    def test_a_further_signal_ends_the_grace_and_the_one_that_ended_the_wait_keeps_it(self):
        """With a leader that ignores SIGTERM and a 6-second grace: the signal that ends the wait keeps the grace; a
        second one ends it, whether both arrive before the wait reads them or the second arrives during the grace; and
        after a deadline the first signal ends it."""
        real_stop, real_popen = WEAKEN.stop_group, subprocess.Popen
        for number in (signal.SIGINT, signal.SIGHUP):
            self.addCleanup(signal.signal, number, signal.signal(number, WEAKEN.interrupted))
        for name, at_once, later, deadline, least, most in (("one", [signal.SIGINT], None, 120, 6, 12),
                                                            ("two at once", [signal.SIGINT, signal.SIGHUP], None, 120, 0, 4),
                                                            ("a second later", [signal.SIGINT], signal.SIGHUP, 120, 0, 5),
                                                            ("one after a deadline", [], signal.SIGHUP, 1, 0, 5)):
            with self.subTest(name=name):
                marker = Path(tempfile.mkdtemp(prefix="weaken-further-"))
                self.addCleanup(shutil.rmtree, marker)
                self.reap_later(marker)
                sent = []

                def spawn(*args, **kwargs):
                    child = real_popen(*args, **kwargs)
                    for _ in range(200):
                        if (marker / "leader").is_file():
                            break
                        time.sleep(0.05)
                    for number in at_once:
                        os.kill(os.getpid(), number)
                        for _ in range(10):
                            time.sleep(0.01)
                    sent.append(time.monotonic())
                    return child

                def stop(child, *args, **kwargs):
                    if later is not None:
                        timer = threading.Timer(1, os.kill, (os.getpid(), later))
                        timer.start()
                        self.addCleanup(timer.cancel)
                    return real_stop(child, *args, **dict(kwargs, grace=6))
                with mock.patch.object(WEAKEN.subprocess, "Popen", spawn), mock.patch.object(WEAKEN, "stop_group", stop), \
                        self.assertRaises(KeyboardInterrupt):
                    WEAKEN.execute(self.group(marker, True), ".", None, deadline, marker / "out")
                took = time.monotonic() - sent[0]
                self.assertTrue(least <= took < most, took)
                time.sleep(0.2)
                self.assertFalse(process_running(int((marker / "worker").read_text())))
                self.assertIsNone(WEAKEN.HELD)

    def test_a_signal_during_the_stop_still_ends_the_whole_group(self):
        """A handled signal that lands as the stop begins, after a deadline or after an interrupt, or just before the
        stop's SIGKILL, leaves no member of the group running: the worker ignores SIGTERM, so only the SIGKILL ends it."""
        real_stop, real_killpg = WEAKEN.stop_group, os.killpg
        for number in (signal.SIGTERM, signal.SIGINT):
            self.addCleanup(signal.signal, number, signal.signal(number, WEAKEN.interrupted))
        for at, first in (("stop", None), ("stop", signal.SIGINT), ("kill", None)):
            with self.subTest(at=at, first=first):
                marker = Path(tempfile.mkdtemp(prefix="weaken-stop-"))
                self.addCleanup(shutil.rmtree, marker)
                self.reap_later(marker)
                fired = []

                def deliver():
                    fired.append(True)
                    os.kill(os.getpid(), signal.SIGTERM)
                    for _ in range(20):
                        time.sleep(0.01)

                def stop(child, *args, **kwargs):
                    if at == "stop":
                        deliver()
                    return real_stop(child, *args, **kwargs)

                def killpg(pid, number):
                    if at == "kill" and number == signal.SIGKILL and not fired:
                        deliver()
                    return real_killpg(pid, number)
                if first is not None:
                    timer = threading.Timer(1.5, os.kill, (os.getpid(), first))
                    timer.start()
                    self.addCleanup(timer.cancel)
                started = time.monotonic()
                with mock.patch.object(WEAKEN, "stop_group", stop), mock.patch.object(os, "killpg", killpg), \
                        self.assertRaises(KeyboardInterrupt):
                    WEAKEN.execute(self.group(marker, False), ".", None, 120 if first else 3, marker / "out")
                self.assertTrue(fired)
                self.assertLess(time.monotonic() - started, 20)
                time.sleep(0.2)
                self.assertFalse(process_running(int((marker / "worker").read_text())))

    def test_an_output_name_already_taken_is_refused_before_the_child_starts(self):
        directory = Path(tempfile.mkdtemp(prefix="weaken-taken-"))
        self.addCleanup(shutil.rmtree, directory)
        outside = directory / "outside"
        outside.write_text("kept")
        (directory / "out").symlink_to(outside)
        with self.assertRaises(FileExistsError):
            WEAKEN.execute(["sh", "-c", f"touch {directory}/ran"], ".", None, 10, directory / "out")
        self.assertEqual((outside.read_text(), (directory / "ran").exists()), ("kept", False))

    def test_a_fresh_write_is_a_new_later_file_and_follows_no_link(self):
        directory = Path(tempfile.mkdtemp(prefix="weaken-fresh-"))
        self.addCleanup(shutil.rmtree, directory)
        target, outside = directory / "f.rs", directory / "outside"
        target.write_text("a")
        target.chmod(0o640)
        outside.write_text("kept")
        (directory / "f.rs.weaken").symlink_to(outside)
        future = time.time_ns() + 10_000_000_000
        os.utime(target, ns=(future, future))
        inode = target.stat().st_ino
        WEAKEN.fresh_write(target, "b")
        self.assertEqual(target.read_text(), "b")
        self.assertNotEqual(target.stat().st_ino, inode)
        self.assertFalse(target.is_symlink())
        self.assertEqual(target.stat().st_mode & 0o777, 0o640)
        self.assertGreater(target.stat().st_mtime_ns, future)
        self.assertEqual(outside.read_text(), "kept")
        self.assertEqual(sorted(path.name for path in directory.iterdir()), ["f.rs", "f.rs.weaken", "outside"])
        linked = directory / "g.rs"
        linked.symlink_to(outside)
        WEAKEN.fresh_write(linked, "c")
        self.assertEqual((linked.is_symlink(), linked.read_text(), outside.read_text()), (False, "c", "kept"))

    def test_workflow_pins_read_quoted_and_commented_values_and_need_the_toolchain_pins(self):
        copy_root = Path(tempfile.mkdtemp(prefix="weaken-pins-"))
        self.addCleanup(shutil.rmtree, copy_root)
        workflow = copy_root / ".github/workflows/agent-checks.yml"
        workflow.parent.mkdir(parents=True)
        workflow.write_text("env:\n  STABLE: \"1.99.0\" # pinned\n  NIGHTLY: nightly-2026-07-27\n  LOOM: '0.7.2' # quoted\n\njobs:\n  x: {}\n")
        self.assertEqual(WEAKEN.workflow_pins(copy_root), {"STABLE": "1.99.0", "NIGHTLY": "nightly-2026-07-27", "LOOM": "0.7.2"})
        for text, missing in (('env:\n  NIGHTLY: nightly-2026-07-27\n  LOOM: "0.7.2"\n\njobs:\n', "STABLE"),
                              ('env:\n  STABLE: ""\n  NIGHTLY: n\n  LOOM: "0.7.2"\n\njobs:\n', "STABLE"),
                              ("env:\n  STABLE: 1.99.0\n  NIGHTLY: n\n  LOOM: '0.7.2\n\njobs:\n", "LOOM")):
            with self.subTest(missing=missing, text=text):
                workflow.write_text(text)
                with self.assertRaises(WEAKEN.Stop) as stop:
                    WEAKEN.workflow_pins(copy_root)
                self.assertEqual(stop.exception.code, 2)
                self.assertIn(f"names no {missing} pin", str(stop.exception))

    def test_each_cataloged_genmc_failure_lies_in_its_case_family_kernel(self):
        kernels = WEAKEN.kernel_texts(ROOT / CATALOG_PACKAGE)
        for entry in (entry for name in (item["id"] for item in CATALOG["rows"]) for entry in WEAKEN.row_entries(row(CATALOG, name))[0]
                      if entry["lane"] == "genmc" and entry.get("failure")):
            for case in entry["tests"]:
                path, text = WEAKEN.family_kernel(case, kernels)
                self.assertEqual((ROOT / CATALOG_PACKAGE / path).read_text(), text)
                self.assertIn(f'c"{entry["failure"]}"', text, case)
        self.assertEqual(WEAKEN.family_kernel("grace1-seq", {"src/nested/grace_kernel.rs": "t"}), ("src/nested/grace_kernel.rs", "t"))
        self.assertIsNone(WEAKEN.family_kernel("grace1-seq", {"src/grace_kernel.rs": "t", "src/nested/grace_kernel.rs": "u"}))

    def test_a_genmc_lane_past_its_deadline_gives_no_verdict_for_every_case(self):
        work = Path(tempfile.mkdtemp(prefix="weaken-lane-deadline-"))
        self.addCleanup(shutil.rmtree, work)
        runner = WEAKEN.Runner.__new__(WEAKEN.Runner)
        runner.work, runner.copy, runner.evidence, runner.serial, runner.rebuilt = work, ROOT, work / "evidence", 0, None
        runner.pins, runner.judge = {"STABLE": "1.99.0", "NIGHTLY": "nightly-2026-07-27", "LOOM": "0.7.2"}, WEAKEN.genmc
        runner.declared = json.loads((ROOT / WEAKEN.GENMC).read_text())
        runner.kernels = WEAKEN.kernel_texts(ROOT / CATALOG_PACKAGE)
        runner.evidence.mkdir()

        def expired(command, cwd, env, deadline, output):
            Path(output).write_text("")
            write_case(Path(env["EVIDENCE"]), "join-production", GENMC_FIXTURE.positive(), 0)
            return None, 1.0
        with mock.patch.object(WEAKEN, "execute", expired):
            results = runner.genmc(["join-production", "credit-seq-empty"], None, "row00", {})
        self.assertEqual([(result["lane_exit"], result["result"], result["reason"]) for result in results],
                         [(None, "no verdict", "the lane passed its deadline")] * 2)
        self.assertEqual(results[0]["exit"], 0)

    def genmc(self, text, code, case="join-production", failure="a follower saw the departure without its terminal", check=True,
              config=None, argv=None, kernel: "str | None" = "src/join_kernel.rs", declared_intrinsics=None, intrinsics=None, record=None):
        evidence = Path(tempfile.mkdtemp(prefix="weaken-genmc-"))
        self.addCleanup(shutil.rmtree, evidence)
        declared = write_case(evidence, case, text, code, check=check, record=record, config=config, argv=argv, intrinsics=intrinsics)
        if declared_intrinsics is not None:
            declared["cases"][case]["intrinsics"] = declared_intrinsics
        return WEAKEN.genmc_result(WEAKEN.genmc, declared, case, failure, evidence, True, kernel, WEAKEN.case_exit(evidence, case))[0]

    def violation_at(self, message):
        declared = {"file": "src/join_kernel.rs"}
        line = WEAKEN.genmc.check_line(declared, message)
        return GENMC_FIXTURE.violation(line=line, file="join_kernel.rs", case="join-relaxeddepart")

    def test_genmc_verdicts_come_from_judge_case(self):
        self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 0), "survived")
        self.assertEqual(self.genmc(self.violation_at("a follower saw the departure without its terminal"), 42), "killed")
        self.assertEqual(self.genmc(self.violation_at("a follower's record was freed or reissued under it"), 42), "no verdict")
        self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 124), "no verdict")
        self.assertEqual(self.genmc("LLVM ERROR: unsupported intrinsic\n" + GENMC_FIXTURE.positive(), 0), "no verdict")
        self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 0, check=False), "no verdict")
        self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 0, config={"build": {"rustflags": ["--cfg", "x"]}}), "no verdict")
        self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 0, argv=["/elsewhere/genmc", "x"]), "no verdict")
        for record in ({"binary": None, "rustc": {"name": "n", "toolchain": "/t"}}, ["not", "an", "object"], {"binary": {"path": "/g"}}):
            with self.subTest(record=record):
                self.assertEqual(self.genmc(GENMC_FIXTURE.positive(), 0, record=record), "no verdict")

    def test_a_genmc_kill_keeps_the_case_declaration_and_needs_its_kernel(self):
        named = self.violation_at("a follower saw the departure without its terminal")
        pin = ["llvm.umin.i64"]
        self.assertEqual(self.genmc(named, 42, declared_intrinsics=pin, intrinsics=pin), "killed")
        self.assertEqual(self.genmc(named, 42, declared_intrinsics=pin, intrinsics=[]), "no verdict")
        self.assertEqual(self.genmc(named, 42, kernel=None), "no verdict")
        self.assertEqual(self.genmc(named, 42, kernel="src/absent_kernel.rs"), "no verdict")

    def test_a_loom_kill_needs_the_named_assertion_at_its_location(self):
        failed = ("   Compiling kestrike v0.1.0\nrunning 1 test\ntest t ... FAILED\nthread 't' (12) panicked at {}:21:\n{}\n"
                  "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out\n")
        named = "protection violated: a departed record whose owner had not ended"
        site = ("crates/kestrike/src/storage/fill_model.rs", 333)
        self.assertEqual(WEAKEN.loom_result(failed.format("crates/kestrike/src/storage/fill_model.rs:333", named), 101, RUN_FAILURE, True, site)[0],
                         "killed")
        for location, message in (("crates/kestrike/src/storage/fill_model.rs:340", named), ("crates/kestrike/src/storage/fill.rs:333", named),
                                  ("crates/kestrike/src/storage/fill_model.rs:333", "another assertion")):
            with self.subTest(location=location, message=message):
                self.assertEqual(WEAKEN.loom_result(failed.format(location, message), 101, RUN_FAILURE, True, site)[0], "no verdict")
        self.assertEqual(WEAKEN.loom_result(failed.format("crates/kestrike/src/storage/fill_model.rs:333", named), 101, RUN_FAILURE, True)[0],
                         "no verdict")
        self.assertEqual(RUN_SITE, site)


if __name__ == "__main__":
    unittest.main()
