#!/usr/bin/env python3
"""Self-test of scripts/classify-atomics.py: the committed census validates,
and each planted census or source defect refuses with its own code."""

import copy
import functools
import importlib.util
import json
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts/classify-atomics.py"
spec = importlib.util.spec_from_file_location("classify_atomics", SCRIPT)
if spec is None or spec.loader is None:
    raise ImportError(f"{SCRIPT} cannot be loaded")
classify = importlib.util.module_from_spec(spec)
spec.loader.exec_module(classify)


def committed(path):
    """Return the committed JSON at `path`; an unreadable file stops the self-test with its name."""
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise SystemExit(f"{path.relative_to(ROOT)} cannot be read: {error}") from error


CENSUS = committed(classify.CENSUS)
CATALOG = committed(classify.CATALOG)
INVENTORY = committed(classify.INVENTORY)
CONTROL_TEXT = classify.receipts().control_text
STORAGE = "crates/kestrike/src/storage/"
CLOSING, EVICT, MAINTAIN = "storage/closing cursor", "storage/evict serialized writer", "storage/maintain cursor"


class Planted(classify.Census):
    """A census judge over the committed sources with `edits` applied to the raw source before its test-only
    items are blanked: each path maps to one `(old, new)` replacement or a list of them, and each `old`
    occurs exactly once in that file."""

    def __init__(self, edits):
        super().__init__(CATALOG, INVENTORY, CONTROL_TEXT)
        self.edits = edits

    @functools.cache
    def edited(self, path):
        """Return `classify.analyzed` of the raw source at `path` with its planted edits applied."""
        source = (ROOT / path).read_text(encoding="utf-8")
        edits = self.edits[path]
        for old, new in edits if isinstance(edits, list) else [edits]:
            if source.count(old) != 1:
                raise AssertionError(f"the planted edit's anchor {old!r} is not unique in {path}")
            source = source.replace(old, new)
        return classify.analyzed(source)

    def load(self, path):
        self.seen.add(path)
        return self.edited(path) if path in self.edits else classify.Census.read(path)

    def spans(self, path):
        return super().spans(path) if path in self.edits else COMMITTED.spans(path)

    def definition(self, file, name):
        return super().definition(file, name) if file in self.edits else COMMITTED.definition(file, name)


COMMITTED = classify.Census(CATALOG, INVENTORY, CONTROL_TEXT)


def site(census, name):
    return next(s for s in census["surfaces"] if s["surface"] == name)


def codes(census, edits=None):
    judge = Planted(edits or {})
    refusals, _, _ = judge.judge(census)
    return {(r["code"], r["surface"]) for r in refusals}


def planted(name, change):
    census = copy.deepcopy(CENSUS)
    change(site(census, name))
    return census


class CensusTests(unittest.TestCase):
    def test_the_committed_census_gives_every_surface_one_disposition(self):
        refusals, dispositions, reported = Planted({}).judge(CENSUS)
        self.assertEqual(refusals, [])
        self.assertEqual(sorted(dispositions), sorted(classify.SURFACES))
        self.assertEqual([r["surface"] for r in reported],
                         [s["surface"] for s in CENSUS["surfaces"] if s["disposition"] == "needs-kernel"])

    def test_sites_parse_function_spans_only_for_body_matches(self):
        judge = classify.Census(CATALOG, INVENTORY, CONTROL_TEXT)
        source = "fn target() { target(); }"
        span = (0, source.index("{"), len(source), "target")
        with mock.patch.object(judge, "expand", return_value=["source.rs"]), \
                mock.patch.object(judge, "code", return_value=source), \
                mock.patch.object(judge, "spans", return_value=[span]) as spans:
            self.assertEqual(list(judge.sites(r"absent", [])), [])
            self.assertEqual(list(judge.sites(r"target(?=\(\) \{)", [])), [])
            spans.assert_not_called()
            self.assertEqual(list(judge.sites(r"target", [])), [("source.rs", span, source.rindex("target"))])
            spans.assert_called_once_with("source.rs")
        with mock.patch.object(judge, "expand", return_value=["missing.rs"]), \
                mock.patch.object(judge, "code", return_value=None):
            with self.assertRaises(FileNotFoundError):
                list(judge.sites(r"absent", []))

    def test_the_check_command_reports_needs_kernel_surfaces_without_credit(self):
        run = subprocess.run([sys.executable, str(SCRIPT), "check"], capture_output=True, text=True, check=False)
        try:
            report = json.loads(run.stdout)
        except ValueError:
            self.fail(f"check printed no JSON report: {run.stdout!r} {run.stderr!r}")
        self.assertEqual((run.returncode, report["refusals"]), (0, []))
        self.assertEqual(report["credited"], not report["reported"])

    def test_an_omitted_surface_refuses(self):
        census = copy.deepcopy(CENSUS)
        census["surfaces"] = [s for s in census["surfaces"] if s["surface"] != CLOSING]
        self.assertEqual(codes(census), {("omitted-surface", CLOSING)})

    def test_a_thread_count_taken_from_the_counters_purpose_refuses(self):
        name = "native/registration issuance counter"
        census = planted(name, lambda s: s.update(writers_at_once="one"))
        self.assertEqual(codes(census), {("inferred-thread-count", name)})

    def test_a_covered_surface_without_a_witness_refuses(self):
        name = "storage/cache one-shot cutoff"
        self.assertEqual(codes(planted(name, lambda s: s.pop("witness"))), {("missing-witness", name)})

    def test_a_dangling_check_reference_refuses(self):
        census = planted(MAINTAIN, lambda s: s["checks"].append("storage::maintain_tests::a_test_nobody_wrote"))
        self.assertEqual(codes(census), {("dangling-check", MAINTAIN)})

    def test_a_witness_its_test_does_not_assert_refuses(self):
        name = "storage/volume/attach election"
        for observes in ("Some(AttachError::Detached)", "let", "assert", "assert!(", "assert_eq!(", "assert_eq!(volume"):
            with self.subTest(observes=observes):
                census = planted(name, lambda s, o=observes: s["witness"].update(observes=o))
                self.assertEqual(codes(census), {("irrelevant-witness", name)})

    def test_a_witness_that_names_nothing_of_its_surface_refuses(self):
        name = "storage/volume/attach election"
        for other in ("storage/gate word", "storage/expire advisory bound", "storage/finalize exclusive owner"):
            with self.subTest(other=other):
                borrowed = site(CENSUS, other)
                census = planted(name, lambda s, b=borrowed: s.update(checks=list(b["checks"]), witness=copy.deepcopy(b["witness"])))
                self.assertEqual(codes(census), {("irrelevant-witness", name)})

    def test_a_witness_from_a_record_that_does_not_run_its_test_refuses(self):
        name = "storage/gate word"
        census = planted(name, lambda s: s["witness"].update(check="mc-certificate-handoff"))
        self.assertEqual(codes(census), {("irrelevant-witness", name)})

    def test_a_commented_out_witness_assertion_refuses(self):
        name = "native/env once-election"
        witness = site(CENSUS, name)["witness"]
        observes = witness["observes"]
        for label, comment, quoted in (("line", f"// {observes}", observes), ("block", f"/* {observes} */", observes),
                                       ("quoted as a comment", f"// {observes}", f"// {observes}")):
            with self.subTest(label=label):
                def control_text(test, job=None, c=comment):
                    body = CONTROL_TEXT(test, job)
                    if test != witness["test"]:
                        return body
                    if body.count(observes) != 1:
                        raise AssertionError(f"the witness {observes!r} is not unique in {test}")
                    return body.replace(observes, c)
                judge = Planted({})
                judge.control_text = control_text
                census = planted(name, lambda s, q=quoted: s["witness"].update(observes=q))
                self.assertEqual({(r["code"], r["surface"]) for r in judge.judge(census)[0]}, {("irrelevant-witness", name)})

    def test_writer_evidence_only_test_code_holds_refuses(self):
        cases = (("storage/cache one-shot cutoff", "fn close(flag: &AtomicBool) {"),
                 ("native/ena callback flag", "pub(crate) fn request_reset(&self) {"),
                 ("bind/wc job dispenser", "jobs.pop()"),
                 ("storage/gate word", "self.0.store(value, order);"))
        for name, evidence in cases:
            with self.subTest(name=name):
                census = planted(name, lambda s, e=evidence: s["writers"][0].update(evidence=e))
                self.assertEqual(codes(census), {("unsupported-writer", name)})

    def test_a_needs_kernel_surface_without_its_fault_refuses(self):
        name = "native/registration issuance counter"
        census = planted(name, lambda s: s["obligation"].pop("fault"))
        self.assertEqual(codes(census), {("missing-obligation", name)})

    def test_an_exclusion_that_is_the_write_itself_or_holds_an_operation_refuses(self):
        def own_write(s):
            s["exclusion"] = {"fn": "advance", "text": "self.close.stage.store(next.encode(), Ordering::Relaxed);"}

        def lock_holding_an_operation(s):
            s["operations"].append("self .close .gate .try_lock()")
        for change in (own_write, lock_holding_an_operation):
            with self.subTest(change=change.__name__):
                self.assertEqual(codes(planted(CLOSING, change)), {("inferred-thread-count", CLOSING)})

    def test_lock_text_outside_the_named_fn_refuses(self):
        census = planted(CLOSING, lambda s: s["exclusion"].update(fn="advance"))
        self.assertEqual(codes(census), {("inferred-thread-count", CLOSING)})

    def test_a_binding_that_drops_the_guard_or_keeps_a_refused_acquisition_refuses(self):
        """`let _ =` drops the guard at its own statement, and a binding without `?`, `unwrap` or `expect` runs the
        region on a refused acquisition too; neither excludes a second writer."""
        lock = "        let guard = self.maintain.gate.try_lock()"
        release = "        guard.release();\n"
        cases = (("a wildcard binding", {STORAGE + "maintain.rs": [(lock, lock.replace("guard", "_")), (release, "")]},
                  lambda s: s["exclusion"].update(text="let _ = self.maintain.gate.try_lock()")),
                 ("a binding that keeps the Err", {STORAGE + "maintain.rs": [("        })?;\n        let cursor = &self.maintain;",
                                                                               "        });\n        let cursor = &self.maintain;"), (release, "")]},
                  lambda s: None))
        for label, edits, change in cases:
            with self.subTest(label=label):
                self.assertEqual({c for c in codes(planted(MAINTAIN, change), edits) if c[1] == MAINTAIN}, {("inferred-thread-count", MAINTAIN)})

    def test_a_lock_that_reaches_none_of_the_writers_refuses(self):
        def elsewhere(s):
            s["exclusion"] = {"fn": "maintain_open", "path": STORAGE + "maintain.rs", "text": "let guard = self.maintain.gate.try_lock()"}
        self.assertEqual(codes(planted(CLOSING, elsewhere)), {("unguarded-caller", CLOSING)})

    def test_a_counter_with_concurrent_callers_cannot_be_serialized_under_a_borrowed_lock(self):
        name = "native/registration issuance counter"

        def serialized(s):
            s.update(writers_at_once="one", disposition="serialized", words=[{"static": "NEXT_REGISTRATION", "path": s["path"]}],
                     exclusion={"fn": "maintain_open", "path": STORAGE + "maintain.rs", "text": "let guard = self.maintain.gate.try_lock()"})
            s["writers"][0]["fn"] = "next"
        self.assertEqual(codes(planted(name, serialized)), {("unguarded-caller", name)})

    def test_an_omitted_writer_or_caller_refuses(self):
        for omitted, code in (("status", "unlisted-writer"), ("sweep_volume", "unguarded-caller")):
            with self.subTest(omitted=omitted):
                census = planted(CLOSING, lambda s, o=omitted: s.update(writers=[w for w in s["writers"] if w["fn"] != o]))
                self.assertEqual(codes(census), {(code, CLOSING)})

    def test_a_listed_writer_that_neither_writes_nor_calls_a_writer_refuses(self):
        census = planted(CLOSING, lambda s: s["writers"].append({"fn": "examined", "actor": "any", "evidence": "fn examined(&self) -> usize {"}))
        self.assertEqual(codes(census), {("writer-without-write", CLOSING)})

    def test_a_listed_writer_nothing_calls_refuses(self):
        edits = {STORAGE + "closing.rs": ("self.status(budget, report)?;", "status_of(budget, report)?;")}
        self.assertEqual(codes(CENSUS, edits), {("unreached-writer", CLOSING)})

    def test_a_census_without_its_words_or_over_missing_source_refuses(self):
        for change, code in ((lambda s: s.pop("words"), "missing-words"),
                             (lambda s: s.update(words=["PendingMark"]), "missing-words"),
                             (lambda s: s.update(words=[{"struct": "PendingMark", "path": STORAGE + "gone.rs"}]), "missing-source"),
                             (lambda s: s.update(words=[{"struct": "Gone", "path": STORAGE + "policy.rs"}]), "missing-source")):
            with self.subTest(code=code):
                self.assertIn((code, EVICT), codes(planted(EVICT, change)))

    def test_an_omitted_struct_leaves_its_writes_uncovered(self):
        census = planted(CLOSING, lambda s: s.update(words=[w for w in s["words"] if w["struct"] != "PassCount"]))
        self.assertEqual(codes(census), {("uncovered-operation", CLOSING), ("writer-without-write", CLOSING)})

    def test_a_stale_foreign_write_refuses(self):
        census = planted(EVICT, lambda s: s["foreign"].append({"path": STORAGE + "evict.rs", "fn": "commit", "word": "slot", "reason": "x"}))
        self.assertEqual(codes(census), {("stale-foreign", EVICT)})

    def test_planted_source_defects_refuse(self):
        rogue = "\nfn rogue(live: &Pool) {\n    live.pending_mark().slot.store(0, Ordering::Relaxed);\n}\n"
        alias = "\nfn rogue(live: &Pool) {\n    let mark = live.pending_mark();\n    mark.set(0, 0);\n}\n"
        cases = (
            ("an ungated write through the accessor", EVICT, {STORAGE + "expire.rs": ("\nfn prefetch_after_choice(", rogue + "\nfn prefetch_after_choice(")},
             {("unlisted-writer", EVICT), ("untracked-access", EVICT)}),
            ("an alias of the accessor", EVICT, {STORAGE + "expire.rs": ("\nfn prefetch_after_choice(", alias + "\nfn prefetch_after_choice(")},
             {("untracked-access", EVICT)}),
            ("a path reference to a step", EVICT, {STORAGE + "reserve.rs": ("    pub fn close(&self) {", "    pub fn close(&self) {\n        let _ = Self::evict_step;")},
             {("unguarded-caller", EVICT)}),
            ("a new method reached through the accessor", EVICT,
             {STORAGE + "evict.rs": ("impl PendingMark {", "impl PendingMark {\n    pub(crate) fn clear(&self) {\n        let _ = self.take();\n    }"),
              STORAGE + "expire.rs": ("\nfn prefetch_after_choice(", "\nfn rogue(live: &Pool) {\n    live.pending_mark().clear();\n}\n\nfn prefetch_after_choice(")},
             {("untracked-access", EVICT)}),
            ("a conversion of the accessor", EVICT,
             {STORAGE + "expire.rs": ("\nfn prefetch_after_choice(", "\nfn rogue(live: &Pool) {\n    let mark: &PendingMark = live.pending_mark().into();\n}\n\nfn prefetch_after_choice(")},
             {("untracked-access", EVICT)}),
            *((f"a write by {form}", EVICT,
               {STORAGE + "expire.rs": ("\nfn prefetch_after_choice(", f"\nfn rogue(mark: &PendingMark) {{\n    {form};\n}}\n\nfn prefetch_after_choice(")},
               {("unlisted-writer", EVICT)})
              for form in ("unsafe { mark.slot.as_ptr().write(0) }", "let _ = mark.slot.get_mut()", "let _ = mark.slot.into_inner()",
                           "let PendingMark { incarnation, .. } = mark", "let _ = &mut mark.incarnation",
                           "let _ = super::policy::PendingMark { slot: AtomicU64::new(0), incarnation: AtomicU32::new(0) }")),
            ("a declared read whose body writes", EVICT,
             {STORAGE + "evict.rs": ("        self.slot.load(Ordering::Relaxed) != MARK_NONE", "        self.slot.store(MARK_NONE, Ordering::Relaxed);\n        false")},
             {("untracked-access", EVICT), ("unlisted-writer", EVICT)}),
            ("a same-line write of a word a foreign entry excuses nearby", MAINTAIN,
             {STORAGE + "closing.rs": ("            self.close.stage.store(next.encode(), Ordering::Relaxed);",
                                       "            self.maintain.stage.store(0, Ordering::Relaxed); self.close.stage.store(next.encode(), Ordering::Relaxed);")},
             {("unlisted-writer", MAINTAIN)}),
            ("a guard moved inside its region", MAINTAIN,
             {STORAGE + "maintain.rs": ("        let cursor = &self.maintain;\n", "        let held = guard;\n        let cursor = &self.maintain;\n")},
             {("moved-guard", MAINTAIN)}),
            ("a guard whose block ends early", MAINTAIN,
             {STORAGE + "maintain.rs": [("        let guard = self.maintain.gate.try_lock()", "        { let guard = self.maintain.gate.try_lock()"),
                                        ("        })?;\n        let cursor = &self.maintain;", "        })?; }\n        let cursor = &self.maintain;")]},
             {("unlisted-writer", MAINTAIN), ("unguarded-caller", MAINTAIN)}),
            ("a write after the guard's release", CLOSING, {STORAGE + "closing.rs": ("        guard.release();\n        Ok(report)",
                                                                                     "        guard.release();\n        self.close.stage.store(0, Ordering::Relaxed);\n        Ok(report)")},
             {("unlisted-writer", CLOSING)}),
            ("a write before the lock", CLOSING, {STORAGE + "closing.rs": ("        let guard = self\n            .close",
                                                                            "        self.close.stage.store(0, Ordering::Relaxed);\n        let guard = self\n            .close")},
             {("unlisted-writer", CLOSING)}),
            *((f"a write in the handler of a refused lock in {stage}", name,
               {STORAGE + file: (f"GateError::Contended => {error}::Contended,",
                                 f"GateError::Contended => {{\n                self.{stage}.stage.store(0, Ordering::Relaxed);\n"
                                 f"                {error}::Contended\n            }}")},
               {("unlisted-writer", name)})
              for name, file, stage, error in ((MAINTAIN, "maintain.rs", "maintain", "MaintainError"),
                                               (CLOSING, "closing.rs", "close", "CloseError"))),
            ("a write after a comment that names a test-only attribute", MAINTAIN,
             {STORAGE + "maintain.rs": ("        let guard = self.maintain.gate.try_lock()",
                                        "        // The #[cfg(test)] interpose observes the stage this resets\n"
                                        "        self.maintain.stage.store(0, Ordering::Relaxed);\n"
                                        "        let guard = self.maintain.gate.try_lock()")},
             {("unlisted-writer", MAINTAIN)}),
            ("a test-only helper whose literal holds a closing brace", EVICT,
             {STORAGE + "expire.rs": ("\nfn prefetch_after_choice(",
                                      "\n#[cfg(test)]\nfn rogue(mark: &PendingMark) {\n    let _ = \"}\";\n"
                                      "    mark.slot.store(0, Ordering::Relaxed);\n}\n\nfn prefetch_after_choice(")},
             set()),
            ("a new caller of a step outside the stages", EVICT,
             {STORAGE + "reserve.rs": ("    pub fn close(&self) {", "    pub fn close(&self) {\n        let _ = self.expire_step(&mut WorkBudget::new(1));")},
             {("unguarded-caller", EVICT)}),
        )
        for label, name, edits, expected in cases:
            with self.subTest(label=label):
                self.assertEqual({c for c in codes(CENSUS, edits) if c[1] == name}, expected)

    def test_an_operation_only_a_comment_or_literal_holds_refuses(self):
        name = "native/ena callback flag"
        operation = "self.reset.load(Ordering::Acquire) && self.reset.swap(false, Ordering::AcqRel);"
        for label, replacement in (("comment", f"// {operation}\n            self.reset.load(Ordering::Acquire);"),
                                   ("literal", f'{{ let _ = "{operation}"; self.reset.load(Ordering::Acquire) }};')):
            with self.subTest(label=label):
                edits = {"crates/kestrike/src/native/ena.rs": (operation, replacement)}
                self.assertEqual({c for c in codes(CENSUS, edits) if c[1] == name}, {("missing-operation", name)})

    def test_a_test_only_last_element_without_a_trailing_comma_blanks_only_itself(self):
        # A test-only item that ran past its list's closing bracket would blank the production code after it.
        live = "state.load(Ordering::Acquire)"
        cases = (
            ("a last parameter", f"fn peek(state: &AtomicU64, #[cfg(test)] probe: u8) -> u64 {{\n    {live}\n}}\n", "#[cfg(test)] probe: u8"),
            ("a last field", f"struct S {{\n    a: u8,\n    #[cfg(test)]\n    b: u8\n}}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)]\n    b: u8\n"),
            ("a last struct-literal field", f"fn peek(state: &AtomicU64) -> S {{\n    S {{ a: 1, #[cfg(test)] b: 2 }};\n    {live}\n}}\n",
             "#[cfg(test)] b: 2 "),
            ("a parameter with a trailing comma", f"fn peek(#[cfg(test)] probe: u8, state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)] probe: u8,"),
            ("a last type parameter", f"fn peek<A, #[cfg(test)] B>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] B"),
            ("a last const parameter", f"fn peek<#[cfg(test)] const N: usize>(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)] const N: usize"),
            ("a const parameter with a trailing comma",
             f"fn peek<#[cfg(test)] const N: usize, T>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] const N: usize,"),
            ("a last closure parameter", f"fn peek(state: &AtomicU64) -> u64 {{\n    let f = |a: u8, #[cfg(test)] b: u8| {live};\n    f(0)\n}}\n",
             "#[cfg(test)] b: u8"),
            ("a test-only statement holding a comparison", f"fn peek(state: &AtomicU64) -> u64 {{\n    #[cfg(test)]\n    let x = a > b;\n    {live}\n}}\n",
             "#[cfg(test)]\n    let x = a > b;"),
            ("a test-only statement after a block whose header holds an operator",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    if a || b {{ return 0; }}\n    #[cfg(test)] let fits = used < limit;\n    {live}\n}}\n",
             "#[cfg(test)] let fits = used < limit;"),
            ("a last type parameter after a braced const default",
             f"fn peek<const N: usize = {{ 3 }}, #[cfg(test)] B>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] B"),
            ("a last type parameter after a braced const argument",
             f"fn peek<T: Bound<{{ true }}>, #[cfg(test)] B>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] B"),
            ("a last type parameter after a braced second const argument",
             f"fn peek<T: Pair<0, {{ 1 }}>, #[cfg(test)] B>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] B"),
            ("a type parameter behind an attribute that holds brackets",
             f"fn peek<A, #[cfg(test)] #[cfg_attr(any(), a([] if))] T>(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)] #[cfg_attr(any(), a([] if))] T"),
            ("a closure parameter after a braced const argument",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    let f = |a: W<{{ 1 }}>, #[cfg(test)] b: u8| {live};\n    f(0)\n}}\n",
             "#[cfg(test)] b: u8"),
            ("a closure parameter after a struct pattern",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    let f = |S {{ x }}, #[cfg(test)] b: u8| {live};\n    f(s)\n}}\n",
             "#[cfg(test)] b: u8"),
            ("an arm after an arm that holds `||`",
             f"fn peek(state: &AtomicU64) -> bool {{\n    match n {{\n        0 => a || b,\n        #[cfg(test)]\n        1 => n < 2,\n"
             f"        _ => {live} == n,\n    }}\n}}\n", "#[cfg(test)]\n        1 => n < 2,"),
            ("an arm after an arm that holds a shift",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    match n {{\n        0 => mask << 1,\n        #[cfg(test)]\n        1 => n < 2,\n"
             f"        _ => {live},\n    }}\n}}\n", "#[cfg(test)]\n        1 => n < 2,"),
            ("an arm before an arm that holds `>` and `|`",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    match n {{\n        0 => a || b,\n        #[cfg(test)]\n        1 => n < 2,\n"
             f"        _ => q > {live} | m,\n    }}\n}}\n", "#[cfg(test)]\n        1 => n < 2,"),
            ("a field after a field that holds `||`",
             f"fn peek(state: &AtomicU64) -> S {{ S {{ a: x || y, #[cfg(test)] probe: n < 2, live: {live} }} }}\n",
             "#[cfg(test)] probe: n < 2,"),
            ("a field after a field that holds `<`",
             f"fn peek(state: &AtomicU64) -> S {{ S {{ a: x < y, #[cfg(test)] d: p < q, e: {live} }} }}\n", "#[cfg(test)] d: p < q,"),
            ("a fn-pointer tuple field", f"struct S(#[cfg(test)] fn(u8) -> u8, AtomicU64);\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)] fn(u8) -> u8,"),
            ("a closure parameter named union",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    let f = |a: u8, #[cfg(test)] union: u8| {live};\n    f(0)\n}}\n",
             "#[cfg(test)] union: u8"),
            ("a type parameter named union", f"fn peek<A, #[cfg(test)] union>(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)] union"),
            ("a field named union that holds `<`",
             f"fn peek(state: &AtomicU64) -> S {{ S {{ a: 1, #[cfg(test)] union: p < q, live: {live} }} }}\n", "#[cfg(test)] union: p < q,"),
            ("an arm that binds union under a guard",
             f"fn peek(state: &AtomicU64) -> bool {{ match n {{ #[cfg(test)] union if c < 2 => true, _ => {live} == n, }} }}\n",
             "#[cfg(test)] union if c < 2 => true,"),
            ("an arm that binds union under a guard with a qualified path",
             f"fn peek(state: &AtomicU64) -> bool {{ match n {{ #[cfg(test)] union if <u64>::MAX < n => true, _ => {live} == n, }} }}\n",
             "#[cfg(test)] union if <u64>::MAX < n => true,"),
            ("an argument that casts union", f"fn peek(state: &AtomicU64) -> u64 {{ call(#[cfg(test)] union as u64 < 3, {live}) }}\n",
             "#[cfg(test)] union as u64 < 3,"),
            ("a test-only union with a comma in its generics",
             f"#[cfg(test)]\nunion Raw<A, B> {{ a: A, b: B }}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)]\nunion Raw<A, B> { a: A, b: B }"),
            ("a test-only union with a comma in its where clause",
             f"#[cfg(test)]\npub(crate) union Raw<A>\nwhere\n    A: Copy,\n{{ a: A, b: u8 }}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)]\npub(crate) union Raw<A>\nwhere\n    A: Copy,\n{ a: A, b: u8 }"),
            ("a test-only impl with a comma in its where clause",
             f"#[cfg(test)]\nimpl<W, const TAKE: bool> GateWord for WeakGate<W, TAKE>\nwhere\n    W: GateWord,\n{{\n"
             f"    fn store(&self) {{ self.0.store(1, Ordering::SeqCst) }}\n}}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)]\nimpl<W, const TAKE: bool> GateWord for WeakGate<W, TAKE>\nwhere\n    W: GateWord,\n{\n"
             "    fn store(&self) { self.0.store(1, Ordering::SeqCst) }\n}"),
            ("a test-only if statement whose condition holds `||`",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    #[cfg(test)]\n    if a || b {{ X.store(1, Ordering::SeqCst); }}\n    {live}\n}}\n",
             "#[cfg(test)]\n    if a || b { X.store(1, Ordering::SeqCst); }"),
            ("a test-only extern fn with a comma in its generics",
             f'#[cfg(test)]\nextern "C" fn probe<A, B>() {{ X.store(1, Ordering::SeqCst); }}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n',
             '#[cfg(test)]\nextern "C" fn probe<A, B>() { X.store(1, Ordering::SeqCst); }'),
            ("a test-only extern fn with no ABI and a comma in its generics",
             f"#[cfg(test)]\nunsafe extern fn probe<A, B>() {{ X.store(1, Ordering::SeqCst); }}\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg(test)]\nunsafe extern fn probe<A, B>() { X.store(1, Ordering::SeqCst); }"),
            ("an extern fn-pointer tuple field",
             f'struct S(#[cfg(test)] extern "C" fn(u8) -> u8, AtomicU64);\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n',
             '#[cfg(test)] extern "C" fn(u8) -> u8,'),
            ("a first arm with an or-pattern",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    match n {{\n        #[cfg(test)]\n        A | B => 1,\n        _ => {live},\n    }}\n}}\n",
             "#[cfg(test)]\n        A | B => 1,"),
            ("an arm with an or-pattern after arms that hold no `<` or `|`",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    match n {{\n        C {{ d }} => 2 + d,\n        #[cfg(test)]\n        A | B => 1,\n"
             f"        _ => {live},\n    }}\n}}\n", "#[cfg(test)]\n        A | B => 1,"),
            ("a const whose initializer holds a comparison",
             f"#[cfg(test)]\nconst BIG: bool = A > B;\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n", "#[cfg(test)]\nconst BIG: bool = A > B;"),
            ("a const that holds a comparison after an inner attribute",
             f"mod m {{\n    #![allow(unused)]\n    #[cfg(test)]\n    const BIG: Pair<u8, bool> = Pair(0, A > B);\n"
             f"    fn peek(state: &AtomicU64) -> u64 {{ {live} }}\n}}\n", "#[cfg(test)]\n    const BIG: Pair<u8, bool> = Pair(0, A > B);"),
            ("an arm cut at its `>` after an arm that holds `<`",
             f"fn peek(state: &AtomicU64) -> u64 {{\n    match n {{\n        0 if a < b => 1,\n        #[cfg(test)]\n        1 => c > d,\n"
             f"        _ => {live},\n    }}\n}}\n", "#[cfg(test)]\n        1 => c "),
            ("a type parameter after an attribute that holds braces",
             f"fn peek<A, #[cfg_attr(any(), a({{}} if))] #[cfg(test)] T>(state: &AtomicU64) -> u64 {{ {live} }}\n",
             "#[cfg_attr(any(), a({} if))] #[cfg(test)] T"),
            ("a module with its path attribute before its test attribute",
             f'#[path = "probe.rs"]\n#[cfg(test)]\nmod probe;\nmod live;\nfn peek(state: &AtomicU64) -> u64 {{ {live} }}\n',
             '#[path = "probe.rs"]\n#[cfg(test)]\nmod probe;'),
            ("a type parameter whose list a macro's definition opens",
             f"macro_rules! complete {{\n    ($($tail:tt)*) => {{ fn peek< $($tail)* }};\n}}\n"
             f"complete! {{ #[cfg(test)] T>(state: &AtomicU64) -> u64 {{ {live} }} }}\n", "#[cfg(test)] T"),
            ("a type parameter after a `;` among a macro's tokens",
             f"with_probe!(; #[cfg(test)] B> fn peek(state: &AtomicU64) -> u64 {{ {live} }});\n", "#[cfg(test)] B"),
        )
        for label, source, blanked in cases:
            with self.subTest(label=label):
                self.assertEqual(source.count(blanked), 1)
                expected = source.replace(blanked, "".join(c if c == "\n" else " " for c in blanked))
                self.assertEqual(classify.blanked(source)[0], expected)

    def test_evidence_only_a_test_only_element_holds_refuses(self):
        # Each decoy keeps the surface's exact operation in a test-only element beside the weakened live operation.
        name, ena = "native/ena callback flag", "crates/kestrike/src/native/ena.rs"
        operation = "self.reset.load(Ordering::Acquire) && self.reset.swap(false, Ordering::AcqRel);"
        anchor = "\npub(crate) fn reset_due"
        whole = {
            "a const whose initializer holds a comparison": f"#[cfg(test)]\nconst _T: bool = 1 > 0 && {{ {operation} true }};\n",
            "a const after an inner attribute":
                f"mod decoy {{\n    #![allow(unused)]\n    #[cfg(test)]\n    const _T: Pair<u8, bool> = Pair(0, {{ {operation} true }});\n}}\n",
            "an arm after arms that hold no `<` or `|`":
                f"fn decoy(n: u8) -> bool {{\n    match n {{\n        0 => false,\n        #[cfg(test)]\n        1 => 1 > 0 && {{ {operation} true }},\n"
                "        _ => false,\n    }\n}\n",
        }
        cut = {
            "a fn-pointer field cut at a comma among its own generic arguments": f"struct _S(\n    #[cfg(test)] fn() -> W<u8, {{ {operation} 0 }}>,\n    u8,\n);\n",
            "an arm after a guard that holds `<`":
                f"fn decoy(n: u8) -> bool {{\n    match n {{\n        x if x < 2 => false,\n        #[cfg(test)]\n        2 => n > 0 && {{ {operation} true }},\n"
                "        _ => true,\n    }\n}\n",
            "an or-pattern arm after an or-pattern arm":
                f"fn decoy(n: u8) {{\n    match n {{\n        0 | 1 => (),\n        #[cfg(test)]\n        4 | 5 => {{ {operation} }}\n        _ => {{}}\n    }}\n}}\n",
        }

        def judged(path, old, decoy, weakened=True):
            edits = {path: (old, "\n" + decoy + old)}
            if weakened:
                edits = {ena: [(operation, operation.replace("AcqRel", "Relaxed")), (anchor, "\n" + decoy + anchor)]}
            return Planted(edits).judge(CENSUS)[0]
        for label, decoy in whole.items():
            with self.subTest(label=label):
                self.assertEqual({(r["code"], r["surface"]) for r in judged(ena, anchor, decoy)}, {("missing-operation", name)})
        first = (ROOT / ena).read_text(encoding="utf-8").split(anchor)[0].count("\n") + 2
        for label, decoy in cut.items():
            with self.subTest(label=label):
                reasons = [r["reason"] for r in judged(ena, anchor, decoy) if (r["code"], r["surface"]) == ("cut-element", None)]
                line = first + decoy[:decoy.index("#[cfg(test)]")].count("\n")
                self.assertEqual(len(reasons), 1, reasons)
                self.assertTrue(reasons[0].startswith(f"{ena}:{line}: a test-only element whose end is read more than one way"), reasons)
        tick = STORAGE + "volume/tick.rs"
        reasons = [r["reason"] for r in judged(tick, "\n    fn apply_read(", "    fn decoy(n: u8) -> u8 {\n        match n {\n            0 | 1 => 0,\n"
                                              "            #[cfg(test)]\n            4 | 5 => 1,\n            _ => 2,\n        }\n    }\n", weakened=False)
                   if r["code"] == "cut-element"]
        self.assertEqual(len(reasons), 1, reasons)
        self.assertTrue(reasons[0].startswith(f"{tick}:"), reasons)
        for name in ("decoy", "r#decoy"):
            with self.subTest(label=f"a field among the tokens of macro {name}"):
                source = f"macro_rules! {name} {{\n    () => {{\n        struct S {{ a: u8, #[cfg(test)] b: u8 }}\n    }};\n}}\n"
                self.assertEqual(classify.analyzed(source)[2], [source.index("#[cfg(test)]")])
        limit = f"#[cfg(test)]\nconst _T: bool = if F {{ false }} else {{ {operation} true }};\n"
        self.assertEqual(judged(ena, anchor, limit), [])

    def test_the_scanned_text_blanks_each_literal_and_comment_whole_and_keeps_the_code_around_it(self):
        # An incorrect literal or comment boundary can make census scans miss a live write or count a commented-out write.
        write = "word.store(1, Ordering::Relaxed);"
        cases = (
            ("a `\\x` char escape", f"let _ = ['\\x41','\"']; let _ = \"/*\";\n{write}\n// */\n", ("'\\x41'", "'\"'", '"/*"', "// */")),
            ("a `\\u` char escape", f"let _ = ['\\u{{0_41}}','\"']; let _ = \"/*\";\n{write}\n// */\n", ("'\\u{0_41}'", "'\"'", '"/*"', "// */")),
            ("a lifetime before a string", f"m!('r\"x\\\"/* /* */\");\n{write}\n", ('"x\\"/* /* */"',)),
            ("a nested block comment", f"/* a /* b */ word.swap(0); c */ {write}\n", ("/* a /* b */ word.swap(0); c */",)),
            ("an unclosed block comment", f"{write}\n/* open\nword.swap(0);\n", ("/* open\nword.swap(0);\n",)),
        )
        for label, source, spans in cases:
            with self.subTest(label=label):
                expected = source
                for span in spans:
                    self.assertEqual(expected.count(span), 1)
                    expected = expected.replace(span, "".join(c if c == "\n" else " " for c in span))
                self.assertIn(write, expected)
                self.assertEqual(classify.code(source), expected)

    def test_a_private_word_is_visible_to_the_declaring_modules_descendants(self):
        judge = Planted({})
        storage = "crates/kestrike/src/storage/"
        self.assertEqual(judge.visible(storage + "closing.rs", "    "), [storage + "closing.rs"])
        volume = judge.visible(storage + "volume/mod.rs", "    ")
        self.assertIn(storage + "volume/mod.rs", volume)
        self.assertIn(storage + "volume/attach.rs", volume)
        self.assertNotIn(storage + "closing.rs", volume)
        device = judge.visible(storage + "device/mod.rs", "    ")
        self.assertIn(storage + "device/spdk/mod.rs", device)
        self.assertTrue(all(f.startswith(storage + "device/") for f in device), device)
        self.assertIn(storage + "closing.rs", judge.visible(storage + "volume/mod.rs", "    pub(super) "))
        self.assertNotIn("crates/kestrike/src/native/env.rs", judge.visible(storage + "volume/mod.rs", "    pub(super) "))

    def test_a_write_deferred_by_a_closure_in_the_locked_region_refuses(self):
        anchor = "        saturating_add(&cursor.evicted, report.evicted);\n"
        for label, closure in (("closure", "        let delayed = || cursor.stage.store(0, Ordering::Relaxed);\n"),
                               ("move closure", "        let delayed = move || { cursor.stage.store(0, Ordering::Relaxed); };\n"),
                               ("async block", "        let delayed = async { cursor.stage.store(0, Ordering::Relaxed); };\n"),
                               ("borrowed closure", "        let delayed = &|| cursor.stage.store(0, Ordering::Relaxed);\n"),
                               ("closure whose body is a keyword block",
                                "        let delayed = || if report.evicted > 0 { cursor.stage.store(0, Ordering::Relaxed) };\n"),
                               ("closure argument whose body is a match",
                                "        take(|| match report.evicted { 0 => (), _ => cursor.stage.store(0, Ordering::Relaxed) });\n")):
            with self.subTest(label=label):
                edits = {STORAGE + "maintain.rs": (anchor, closure + anchor)}
                self.assertEqual({c for c in codes(CENSUS, edits) if c[1] == MAINTAIN}, {("unlisted-writer", MAINTAIN)})

    def test_a_disjunction_in_the_locked_region_is_no_closure(self):
        """`a || b { write }` is an `if` condition, so the write in its block stays guarded."""
        anchor = "        saturating_add(&cursor.evicted, report.evicted);\n"
        guarded = "        if done || report.more_work { cursor.stage.store(0, Ordering::Relaxed); }\n"
        edits = {STORAGE + "maintain.rs": (anchor, guarded + anchor)}
        self.assertEqual({c for c in codes(CENSUS, edits) if c[1] == MAINTAIN}, set())

    def test_each_shape_rule_refuses(self):
        name = "storage/volume/attach election"
        cases = (
            (lambda s: s.update(surface="storage/elsewhere"), {("unknown-surface", "storage/elsewhere"), ("omitted-surface", name)}),
            (lambda s: s.update(writers_at_once="few"), {("missing-thread-count", name)}),
            (lambda s: s.update(disposition="trusted"), {("unknown-disposition", name)}),
            (lambda s: s.update(checks=[]), {("missing-check", name)}),
            (lambda s: s.update(checks=None), {("missing-check", name)}),
            (lambda s: s.update(writers=[]), {("missing-writer", name), ("irrelevant-witness", name)}),
            (lambda s: s.update(operations=["storage.attached().fetch_or(true)"]), {("missing-operation", name)}),
        )
        for change, expected in cases:
            with self.subTest(expected=expected):
                self.assertEqual(codes(planted(name, change)), expected)
        census = copy.deepcopy(CENSUS)
        census["surfaces"].append(copy.deepcopy(site(census, name)))
        self.assertEqual(codes(census), {("duplicate-surface", name)})
        self.assertEqual(codes({"surfaces": None}), {("malformed-census", None)})
        for change, code in ((lambda s: s.update(writers_at_once="many"), "unserialized"), (lambda s: s.pop("argument"), "missing-argument")):
            with self.subTest(code=code):
                self.assertIn((code, CLOSING), codes(planted(CLOSING, change)))


if __name__ == "__main__":
    unittest.main()
