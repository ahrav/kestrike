#!/usr/bin/env python3
"""Exercise verify-receipts.py on the committed catalog and on seeded lane evidence."""

import contextlib
import atexit
import copy
import functools
import types
import dataclasses
import importlib.util
import io
import hashlib
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
SCRIPT = ROOT / "scripts/verify-receipts.py"
SELECT = ROOT / "scripts/select-tests.py"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


os.environ.pop("GITHUB_STEP_SUMMARY", None)
verify = load("verify_receipts", SCRIPT)
read_json = verify.read_json
select = load("select_tests", SELECT)
rc11_fixture = load("test_judge_rc11", ROOT / "scripts/test-judge-rc11.py")
RC11 = rc11_fixture.EXPECTED
genmc_fixture = load("test_judge_genmc", ROOT / "scripts/test-judge-genmc.py")
GENMC = genmc_fixture.EXPECTED
try:
    CATALOG = json.loads(verify.CATALOG.read_text())
except (OSError, ValueError) as error:
    raise SystemExit(f"test-verify-receipts: unreadable catalog: {error}") from error
ORACLE_RECORD = next(i for i, record in enumerate(CATALOG["records"]) if record["id"] == "oracle-verdict-credits-only-activated-pass")
INVENTORY = select.load_inventory(select.INVENTORY)
WORKFLOW = verify.WORKFLOW.read_text()
JOBS = verify.workflow_jobs(WORKFLOW)
REVISION = "0123456789abcdef0123456789abcdef01234567"
# A fuzz lane record with the frame run, the campaign run and both parser runs finished.
COMPLETED_FUZZ = {
    "seeds": 22, "runs": 184733, "seconds": 61,
    "campaign": {"seeds": 4, "runs": 5832, "seconds": 121, "nonseed_pass": 63},
    "parsers": {name: {"seeds": 9, "runs": 40383, "seconds": 61, "nonseed_pass": 900} for name in ("record", "wire")},
}
FUZZ_ROWS = select.load_inventory(select.INVENTORY)["qualified"]["fuzz"]["rows"]
HEADER = "     Running unittests src/lib.rs (target/debug/deps/kestrike-b42c7cc1393e6040)"
WORKER_HEADER = "     Running src/worker.rs (target/debug/deps/sim_worker-406c4a569d4203d8)"
SOAK_HEADER = "     Running tests/soak_cli.rs (target/debug/deps/soak_cli-5b1f0c7d2a9e4c36)"
WORKSPACE_NAMED = {test for record in CATALOG["records"] if record["job"] == "workspace"
                   for test in [*record["tests"], *(control["test"] for control in record["controls"])]}
# The required targets that hold a test a workspace record names.
WORKSPACE_TARGETS = tuple(target for target, required in INVENTORY["ordinary"]["kestrike"]["required"].items()
                          if WORKSPACE_NAMED & set(required["tests"]))
LOOM_HEADER = "     Running unittests src/lib.rs (/tmp/loom-target/release/deps/kestrike-9b91aa9cade47514)"
UNRELATED_ASAN = ["storage::writable_tests::with_reads_holding_every_read_slot_a_fill_still_publishes"]
PUT_FAMILIES = {
    "put-authority-then-ready-before-input", "put-source-custody-until-receipt-and-device-return",
    "put-full-receipt-is-not-publication", "put-then-get-exact-bytes", "put-duplicate-receipt-adds-no-credit",
    "put-replay-and-unknown-outcome", "put-cancel-and-invalidation-keep-custody",
    "mixed-get-and-put-progress-holds-every-bound",
}


def listing(names, header):
    return "\n".join([header, *(f"{name}: test" for name in names), "", f"{len(names)} tests, 0 benchmarks"]) + "\n"


def summary(passed, failed, ignored, filtered=0):
    return (
        f"test result: {'ok' if failed == 0 else 'FAILED'}. {passed} passed; {failed} failed; "
        f"{ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.79s"
    )


def module_witnesses(target="kestrike", crate="kestrike"):
    required = INVENTORY["ordinary"][crate]["required"][target]
    names = list(required["tests"])
    for module in required["modules"]:
        if not any(name.startswith(module + "::") for name in names):
            names.append(f"{module}::a_module_witness")
    return names


def with_timeout(workflow, job, minutes):
    """Return the workflow with the job's own `timeout-minutes` set to `minutes`."""
    edited, count = re.subn(
        rf"(\n  {re.escape(job)}:\n(?:    .*\n)*?    timeout-minutes: )\d+\n", rf"\g<1>{minutes}\n", workflow, count=1,
    )
    if count != 1:
        raise AssertionError(f"job {job} has no timeout-minutes line")
    return edited


REFERENCE = r"(?:(?:P-[EN]|EBS4-E|S3-D|EX-SA|CG-SA|CG-FC|PR-TEN|PR-CLI|PR-RST|PR-PERF)-\d+|P-CHC-[EN]\d+|P-CWC-[EN]\d+|P-DF-[EN]\d+|P-CO-[EN]\d+|P-CP-(?:[EN]\d+|N2a)|ebs-cache-[ne]-\d+(?:, ebs-cache-[ne]-\d+)*|T\d+)"
# A property names the issue or pull request that states it: a kestrike issue as `#N`, or one in the blotter
# tracker as `blotter issue N` or `blotter pull request N`.
SOURCE = r"(?:#\d+|blotter (?:issue|pull request) \d+)"
PROPERTY_GRAMMAR = (rf"^{SOURCE} (?:{REFERENCE}|[a-z][a-z0-9]*(?:-[a-z0-9]+)+)"
                    rf"(?:; (?:{SOURCE} )?(?:{REFERENCE}|[A-Z]+[a-z]+(?:[A-Z]+[a-z]*)+))*$")


class VerifyReceipts(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-receipts-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def test_quint_credit_withholds_only_records_requiring_a_blocked_case(self):
        fixture_module = load("quint_gate_fixture", ROOT / "scripts/test-judge-quint.py")
        fixture = fixture_module.JudgeQuint()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        self.assertTrue(fixture.judge()["credited"])
        code, report = self.run_script("credit", "--job", "quint", "--receipt", str(fixture.evidence / "receipt.json"),
                                      "--evidence", str(fixture.evidence), "--revision", "0" * 40)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(set(report["blocked"]), {"detect-fixed-incident-progress", "detect-declared-progress", "preserve-p4-retention-proposed"})
        self.assertEqual(report["blocked"]["detect-fixed-incident-progress"], {"detect-progress": "AQ-15", "detect-broken-progress": "AQ-15"})
        self.assertEqual(report["blocked"]["detect-declared-progress"],
                         {"detect-declared-progress": "AQ-15", "detect-broken-declared-progress": "AQ-15"})
        self.assertNotIn("detect-fixed-incident-progress", report["obligations"])
        self.assertNotIn("detect-declared-progress", report["obligations"])
        expected = {row["id"] for row in CATALOG["records"] if row["job"] == "quint"} - set(report["blocked"])
        self.assertEqual(set(report["obligations"]), expected)

    def quint_credit(self, evidence, ci):
        """Run `credit --job quint --receipt --read-only` in-process on `evidence` under the run identity `ci`, with the
        catalog admission and the census, which this evidence does not reach, left out; return (code, report)."""
        kept = {key: value for key, value in os.environ.items() if key not in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT")}
        with mock.patch.dict(os.environ, {**kept, **ci}, clear=True), mock.patch.object(verify, "admit", return_value=[]), \
                mock.patch.object(verify, "census_judgment", return_value=([], [])), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            code = verify.main(["credit", "--job", "quint", "--receipt", str(evidence / "receipt.json"),
                                "--evidence", str(evidence), "--revision", REVISION, "--read-only"])
        try:
            return code, json.loads(stdout.getvalue())
        except ValueError:
            self.fail(f"no JSON report: {stdout.getvalue()!r}")

    def test_quint_credit_rederives_a_join_from_both_shard_artifacts_under_the_producing_run(self):
        """A join's receipt binds `report.json`, `pins.txt` and `quint-shards.json` and none of a single run's files, so
        credit requires the sharded evidence list of it. The judge takes the run and attempt it requires of the
        shards from the environment, so the join re-derives at any path, and only from a directory that holds both
        shard artifacts under `shards/`, under the producing run's identity."""
        fixture = load("quint_gate_fixture", ROOT / "scripts/test-judge-quint.py")
        judge, ci = fixture.judge_quint, {"GITHUB_RUN_ID": "42", "GITHUB_RUN_ATTEMPT": "3"}
        root = self.dir.resolve()
        produced = root / "produced"
        (produced / "shards").mkdir(parents=True)
        for index in judge.SHARDS:
            fixture.shard_artifact(root / str(index), produced / "shards" / f"quint-shard-{index}-42-3", index,
                                   list(judge.shard_cases(fixture.CASES, index)), ci, REVISION)
        with mock.patch.dict(os.environ, ci), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(judge.main(["judge", "--evidence", str(produced), "--revision", REVISION]), 0)
        join = root / "join"
        produced.rename(join)

        def files():
            return {str(path.relative_to(join)): path.read_bytes() for path in sorted(join.rglob("*")) if path.is_file()}

        before = files()
        code, report = self.quint_credit(join, ci)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(set(report["obligations"]),
                         {row["id"] for row in CATALOG["records"] if row["job"] == "quint"} - set(report["blocked"]))
        self.assertEqual(files(), before, "a read-only credit writes nothing")
        receipts = root / "receipts"
        receipts.mkdir()
        for name in ("report.json", "receipt.json", "pins.txt", "quint-shards.json"):
            shutil.copy(join / name, receipts / name)
        for evidence, identity in ((join, {}), (join, {**ci, "GITHUB_RUN_ATTEMPT": "4"}), (receipts, ci)):
            with self.subTest(evidence=evidence.name, identity=identity):
                code, report = self.quint_credit(evidence, identity)
                self.assertEqual((code, report["credited"], self.codes(report)), (1, False, ["unbound-input"]), report)
        (join / "quint-shards.json").write_text("{}\n")
        code, report = self.quint_credit(join, ci)
        self.assertEqual((code, self.codes(report)), (1, ["unbound-input"]), report)
        self.assertIn("quint-shards.json changed since the receipt or is missing", [r["reason"] for r in report["refusals"]])

    def test_quint_blocks_refuses_undeclared_cases_and_empty_gates(self):
        for blocked in ({"absent": "AQ-15"}, {"detect-progress": ""}):
            manifest = self.dir / "expected.json"
            manifest.write_text(json.dumps({**read_json(verify.CHECKER_JOBS["quint"]), "blocked": blocked}))
            with mock.patch.dict(verify.CHECKER_JOBS, {"quint": manifest}):
                with self.assertRaisesRegex(verify.Crash, "undeclared case or empty gate"):
                    verify.quint_blocks(CATALOG)

    def test_blocked_summary_names_each_case_and_external_gate(self):
        self.assertEqual(verify.blocked_lines({"record": {"case": "AQ-15"}}), ["- record: case withheld at AQ-15; no credit"])

    def run_script(self, *args, env=None):
        result = subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False, env=env)
        try:
            return result.returncode, json.loads(result.stdout)
        except ValueError:
            self.fail(f"no JSON report: {result.stdout!r} {result.stderr!r}")

    def evidence(self, name, runnable, ignored, failed=(), exit_code=0, header=HEADER, cfg_args=("--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike"), extra_output="", more_targets=()):
        """Write a lane's evidence: one target section from the arguments, then one per `(header, runnable, ignored)` in `more_targets`."""
        evidence = self.dir / name
        evidence.mkdir()
        sections = [(header, runnable, ignored, extra_output), *((h, names, skipped, "") for h, names, skipped in more_targets)]
        (evidence / "list.txt").write_text("".join(listing(names + skipped, h) for h, names, skipped, _ in sections))
        (evidence / "ignored.txt").write_text("".join(listing(skipped, h) for h, _, skipped, _ in sections))
        run = ""
        for h, names, skipped, trailer in sections:
            lines = [f"test {n} ... {'FAILED' if n in failed else 'ok'}" for n in names]
            lines += [f"test {n} ... ignored, needs hardware" for n in skipped]
            failures = len(set(names) & set(failed))
            run += f"{h}\n" + "\n".join(lines) + f"\n{trailer}{summary(len(names) - failures, failures, len(skipped), 1484 if 'loom' in h else 0)}\n"
        (evidence / "run.txt").write_text(run)
        (evidence / "exit.txt").write_text(f"{exit_code}\n")
        (evidence / "pins.txt").write_text("- rustc 1.99.0 (b940084d7 2026-09-28)\n")
        common = [*cfg_args, "--list", str(evidence / "list.txt"), "--ignored", str(evidence / "ignored.txt")]
        with (evidence / "selection.json").open("w") as out:
            subprocess.run([sys.executable, str(SELECT), "listing", *common], stdout=out, stderr=subprocess.DEVNULL, check=False)
        with (evidence / "report.json").open("w") as out:
            subprocess.run(
                [sys.executable, str(SELECT), "run", *common, "--output", str(evidence / "run.txt"), "--exit", str(exit_code)],
                stdout=out, stderr=subprocess.DEVNULL, check=False,
            )
        return evidence

    def workspace_evidence(self, name="workspace", **kwargs):
        """The workspace lane's evidence as `--cfg ordinary` judges its whole-workspace listing: every declared target
        of every crate, a required target with its witnesses and every other with one test, each with its declared
        ignores, `kestrike` first."""
        headers = {"kestrike": HEADER, "sim_worker": WORKER_HEADER, "soak_cli": SOAK_HEADER}
        self.assertLessEqual(set(WORKSPACE_TARGETS), set(headers), "a workspace record names a test of a target the fixture lists as generic")
        sections = []
        for crate, declared in INVENTORY["ordinary"].items():
            for target in declared["targets"]:
                header = headers.get(target) or (f"   Doc-tests {target.removeprefix('doc:')}" if target.startswith("doc:") else
                                                 f"     Running unittests src/lib.rs (target/debug/deps/{target}-0123456789abcdef)")
                runnable = module_witnesses(target, crate) if target in declared.get("required", {}) else ["tests::a_listed_test"]
                sections.append((target, (header, runnable, declared["ignored"].get(target, []))))
        sections.sort(key=lambda section: section[0] != "kestrike")
        (header, runnable, ignored), *more = (section for _, section in sections)
        return self.evidence(name, runnable, ignored, header=header, cfg_args=("--cfg", "ordinary"), more_targets=tuple(more), **kwargs)

    def loom_evidence(self, module, name=None, **kwargs):
        declared = INVENTORY["loom"][module]
        runnable = [t for t in declared["tests"] if t not in declared["ignored"]]
        return self.evidence(
            name or module, runnable, declared["ignored"], header=LOOM_HEADER,
            cfg_args=("--cfg", "loom", "--module", module), **kwargs,
        )

    def credit(self, evidence, job, module=None, **changes):
        code, report = self.run_script("receipt", "--job", job, *(["--module", module] if module else []), "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 0, report)
        receipt = self.receipt_of(evidence)
        receipt.update(changes)
        path = evidence / "judged.json"
        path.write_text(json.dumps(receipt))
        return self.run_script("credit", "--job", job, *(["--module", module] if module else []), "--evidence", str(evidence), "--revision", REVISION, "--receipt", str(path))

    def codes(self, report):
        return sorted({r["code"] for r in report["refusals"]})

    def receipt_of(self, evidence):
        try:
            return json.loads((evidence / "receipt.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"no receipt in {evidence}: {error}")

    def test_the_committed_catalog_is_admitted_and_covers_every_lane(self):
        self.assertEqual(verify.admit(CATALOG, INVENTORY, JOBS), [])
        code, report = self.run_script("admit")
        self.assertEqual((code, report["refusals"], report["records"]), (0, [], len(CATALOG["records"])))
        census, needs_kernel = verify.census_judgment(CATALOG, INVENTORY)
        self.assertEqual((census, report["census_needs_kernel"]), ([], needs_kernel))
        self.assertTrue(needs_kernel, "the census reports its needs-kernel obligations beside admission")
        intake, opened = verify.intake_judgment(CATALOG, verify.INTAKE)
        self.assertEqual((intake, {key: report[key] for key in opened}), ([], opened))
        ratchet, listed = verify.ratchet_judgment(CATALOG, verify.CONTROL_LESS)
        self.assertEqual((ratchet, report["control_less"]), ([], listed))
        self.assertEqual(listed, sum(not record["controls"] and "no_control" not in record for record in CATALOG["records"]))

        jobs = {r["job"] for r in CATALOG["records"]}
        self.assertEqual(jobs, {"workspace", "campaigns", "search", "fuzz-smoke", "long-run", "search-nightly", "loom", "miri", "sweep",
                                "rc11", "verus", "genmc", "kani", "tlc", "quint", "fuzz", "isa-x86-64", "isa-aarch64", "asan", "qemu",
                                *verify.TAG_COMPARE})
        self.assertEqual({job for job in JOBS if JOBS[job]["credit"]} - jobs, set(verify.ENVELOPED) - jobs)
        self.assertEqual({r["module"] for r in CATALOG["records"] if r["job"] == "loom"}, set(INVENTORY["loom"]))
        self.assertLessEqual(PUT_FAMILIES, {r["id"] for r in CATALOG["records"]})
        for record in CATALOG["records"]:
            self.assertRegex(record["property"], PROPERTY_GRAMMAR)
            for control in record["controls"]:
                self.assertIn(control["violation"], verify.control_text(control["test"], record["job"]), control["test"])
        self.assertEqual(CATALOG["baseline"], INVENTORY["baseline"])

    def test_the_property_grammar_admits_numbered_rules_and_named_invariants(self):
        for good in ("#175 P-CHC-N2; P-CHC-N3", "#175 P-CHC-E1",
                     "blotter issue 1278 T3; T21", "blotter issue 1166 P-N-326; blotter issue 1278 T23; RouteMonotonic", "#8 P-E-122", "#61 isa-required-entry",
                     "blotter issue 1278 EX-SA-1; CG-SA-1; PR-TEN-4; NoWriteBeforeFB", "blotter issue 1278 T5; FBAfterOwnBump; NoPredecessorEffectAfterFB",
                     "blotter issue 1278 T13; T21; T23; PR-CLI-1", "blotter issue 1278 T23; PR-CLI-2; PR-CLI-5; CG-FC-1; RouteMonotonic",
                     "blotter issue 1278 T18; T19; T24; PR-RST-3; PR-RST-4; PR-PERF-1; SlotNotOverwrittenWhileNamed; PossNamedCoversStore; RootNamedByStore; SelfValidatingRead",
                     "#182 P-CWC-N1; P-CWC-N2; P-CWC-N3; P-CWC-N4", "#221 P-DF-N2", "#221 P-DF-E20; P-DF-N10",
                     "#206 P-CO-N12", "#206 P-CO-N12; P-CO-E1",
                     "#238 P-CP-N1; P-CP-N2a; P-CP-E9"):
            self.assertRegex(good, PROPERTY_GRAMMAR)
        for bad in ("blotter issue 1278 t3", "blotter issue 1278 T", "blotter issue 1278 T3;T21", "blotter issue 1278 T3; routeMonotonic", "blotter issue 1278 T3; Route", "blotter issue 1278 RouteMonotonic",
                    "blotter issue 1278 T3; FB", "#175 P-CHC-N", "#175 P-CHC-E-1", "#175 P-CHC-X2", "#182 P-CWC-N", "#182 P-CWC-1",
                    "#221 P-DF-N", "#221 P-DF-2", "#221 P-DF-N-2",
                    "#206 P-CO-N", "#206 P-CO-E-1", "#206 P-CO-X2", "#206 P-CO-12",
                    "#238 P-CP-N", "#238 P-CP-N1 to P-CP-N15", "#238 P-CP-N2b", "#238 P-CP-X1",
                    "#238 P-CP-E9a", "#238 P-CP-N1; P-CP-N15a"):
            self.assertNotRegex(bad, PROPERTY_GRAMMAR)

    def test_a_census_refusal_refuses_admission_under_the_census_code(self):
        catalog = copy.deepcopy(CATALOG)
        catalog["records"] = [r for r in catalog["records"] if r["id"] != "mc-gate-contention"]
        census, _ = verify.census_judgment(catalog, INVENTORY)
        self.assertEqual({(r["code"], r["record"]) for r in census}, {("census", "storage/gate word")})
        self.assertIn("dangling-check", census[0]["reason"])

    def test_module_spans_follow_source_content_and_keep_nested_functions_out(self):
        source = "fn witness() {}\nmod nested {\nfn witness() {}\n}\n"
        for _ in range(2):
            self.assertEqual(list(verify.direct_items(source, "witness")), ["fn witness() {}"])
        moved = "mod outer {\n" + source + "}\n"
        self.assertEqual(list(verify.direct_items(moved, "witness")), [])
        self.assertIsInstance(verify.module_spans(source), tuple)

    def test_indexed_fn_headers_and_brace_spans_match_the_regex_and_depth_count(self):
        """`fn_matches` yields what `re.finditer` yields for each fn header, and `fn_spans` ends each item where a
        depth count from its opening brace returns to zero, on stacked attributes, a name that prefixes another,
        two candidate line starts for one fn, a stray close, an unclosed item and a name the index cannot hold; and
        `direct_tests` keeps the items whose own `fn_header` attribute lines hold `#[test]`."""
        source = ("#[test]\n#[ignore]\nfn foo() { if x { y } }\nfn foo_bar() {}\n}\npub fn foo() {}\n"
                  "#[cfg(test)]\n    #[test]\n  pub(crate) async fn\n  foo() { { }\nfn foo() {\n")
        code = verify.masked(source)

        def depth_spans(header):
            found = []
            for item in re.finditer(header, code, re.M):
                start, depth = code.find("{", item.end()), 0
                for index in range(max(start, 0), len(code) if start >= 0 else 0):
                    depth += {"{": 1, "}": -1}.get(code[index], 0)
                    if depth == 0:
                        found.append((item.start(), index + 1))
                        break
            return found

        for name in ("foo", "foo_bar", "fo", "bar", "x.y"):
            header = verify.fn_header(name)
            with self.subTest(name=name):
                self.assertEqual(list(verify.fn_matches(name, code)),
                                 [found.span() for found in re.finditer(header, code, re.M)])
                self.assertEqual(list(verify.fn_spans(source, name)), depth_spans(header))
                self.assertEqual(list(verify.fn_spans(source, name)), list(verify.spans(source, header)))
                self.assertEqual(list(verify.direct_tests(source, name)),
                                 [item for item in verify.direct_items(source, name)
                                  if re.search(r"^[ \t]*#\[test\]$", re.match(header, item, re.M).group(1), re.M)])
        self.assertEqual(len(list(verify.fn_spans(source, "foo"))), 2)

    def test_a_path_attribute_moves_a_test_module_into_its_file(self):
        source, inline = verify.module_file("native::env::init_tests::concurrent_entrants_elect_one_native_initializer", "kestrike")
        self.assertIn("fn concurrent_entrants_elect_one_native_initializer()", source)
        self.assertEqual(inline, ())

    def test_a_mod_rs_module_and_plain_mod_declarations_lead_to_their_files(self):
        for test in [
            "failover::zone_loop::tests::actuate::two_loops_racing_at_the_census_designate_one_host",
            "failover::report::status::tests::status_fields_and_fixtures",
            "failover::zone_loop::tests::tick::each_tick_builds_its_part_from_its_own_survey_rows",
        ]:
            source, inline = verify.module_file(test, "kestrike")
            self.assertIn(f"fn {test.rsplit('::', 1)[-1]}()", source, test)
            self.assertEqual(inline, (), test)
            self.assertTrue(verify.declares_test(test, "kestrike"), test)
        self.assertFalse(verify.declares_test("failover::zone_loop::tests::actuate::no_such_case", "kestrike"))
        self.assertFalse(verify.declares_test("failover::report::status::tests::no_such_case", "kestrike"))
        self.assertFalse(verify.declares_test("failover::zone_loop::tests::tick::no_such_case", "kestrike"))
        self.assertFalse(verify.declares_test("tree::failover::report::status::tests::status_fields_and_fixtures", "kestrike"),
                         "the crate root's `#[cfg(any())] mod tree;`, which no build compiles")

    def test_a_witness_resolves_only_through_declarations_from_the_crate_root(self):
        def test_fn(name="witness", body=""):
            return "#[test]\nfn " + name + "() {" + body + "}\n"
        layout = {
            "lib.rs": (
                "mod declared;\nmod sibling {\n    mod hidden;\n}\n"
                "const TEXT: &str = r\"\nmod quoted;\n\";\n"
                "/*\nmod commented;\n*/\n"
                "mod outer {\n    #[path = \"moved.rs\"]\n    mod inner;\n}\n"
                "#[path = \"gone.rs\"]\nmod gone;\nmod absent;\n"
                "#[path = \"real.rs\"]\nmod mapped;\n"
                "#[cfg_attr(test, path = \"real.rs\")]\nmod conditional;\n"
                "#[cfg(test)] mod braced {\n    const OPEN: &str = \"{\";\n" + test_fn() + "}\n"
                "#[cfg(a)]\nmod alternative {}\n#[cfg(not(a))]\nmod alternative {\n" + test_fn() + "}\n"
                "#[cfg(any())]\n#[path = \"real.rs\"]\nmod disabled;\n"
                "#[cfg(any())]\nmod skipped;\n"
                "#[cfg( any ( ) )]\nmod unbuilt {\n" + test_fn() + "}\n"
                "#[cfg(not(any()))]\nmod enabled {\n" + test_fn() + "}\n"
                "#[cfg(test)] // not #[cfg(any())]\nmod remarked {\n" + test_fn() + "}\n"
                "mod control {\n    mod nested {\n" + test_fn("probe", " \"planted\"; ") + "    }\n"
                + test_fn("probe") + "}\n"
                "#[cfg(a)]\nmod twin {\n" + test_fn("probe", " \"planted\"; ") + "}\n"
                "#[cfg(not(a))]\nmod twin {\n" + test_fn("probe") + "}\n"
                "#[cfg(a)]\nmod reached;\n#[cfg(not(a))]\npub(crate) mod reached;\n"
                "mod deep;\n"
                "#[cfg(a)]\nmod rerouted {\n" + test_fn("probe", " \"planted\"; ") + "}\n"
                "#[cfg_attr(not(a), path = \"unseen.rs\")]\nmod rerouted;\n"
                "#[cfg(a)]\nmod wrapped {\n" + test_fn("probe", " \"planted\"; ") + "}\n"
                "#[cfg_attr(\n    not(a),\n    path = \"unseen.rs\"\n)]\nmod wrapped;\n"
                "#[cfg_attr(\n    test,\n    path = \"real.rs\"\n)]\nmod lone;\n"
                "#[cfg(\n    any()\n)]\nmod never {\n" + test_fn() + "}\n"
                "#[path =\n    \"real.rs\"]\nmod folded;\n"
                "#[cfg_attr(\n    not(test),\n    expect(dead_code, reason = \"the path [of] least ] resistance\")\n)]\n"
                "pub(crate) mod linted;\n"
                "#[cfg(test)]\n// #[path = \"real.rs\"]\nmod noted;\n"
                "/*\ninclude!(\"removed.rs\");\ninclude!(\"remarked.rs\");\n*/\n"
                + test_fn("at_root")
            ),
            "declared.rs": "mod inner {\n" + test_fn() + "}\n",
            "orphan/mod.rs": test_fn(),
            "orphan.rs": test_fn(),
            "hidden.rs": test_fn(),
            "sibling/hidden.rs": test_fn("hidden_witness"),
            "quoted.rs": test_fn(),
            "commented.rs": test_fn(),
            "moved.rs": test_fn("decoy"),
            "outer/moved.rs": test_fn("moved_witness"),
            "mapped.rs": test_fn("conventional"),
            "conditional.rs": test_fn("conventional_twin"),
            "skipped.rs": test_fn(),
            "real.rs": test_fn("mapped_witness"),
            "reached.rs": test_fn("probe", " \"kept\"; "),
            "unseen.rs": test_fn("probe"),
            # A module file, where no `include!` is expanded: one twin holds the fn and the other includes it.
            "deep.rs": (
                "#[cfg(a)]\nmod spliced {\n" + test_fn("probe", " \"planted\"; ") + "}\n"
                "#[cfg(not(a))]\nmod spliced {\n    include!(\"unseen.rs\");\n}\n"
            ),
            "lone.rs": test_fn("conventional_lone"),
            "linted.rs": test_fn("probe", " \"linted\"; "),
            "noted.rs": test_fn("live"),
            "remarked.rs": test_fn("at_remarked_root"),
        }
        # A second crate whose root is `main.rs`; it declares `control::probe` as the first crate does.
        binary = test_fn("at_main") + "mod control {\n" + test_fn("probe", " \"second\"; ") + "}\n"
        # A package with a library and a binary: each root is a crate, and both declare `shared`.
        both = {
            "lib.rs": "mod shared;\n",
            "main.rs": "mod shared;\nmod launcher {\n    mod tests {\n" + test_fn("in_binary") + "    }\n}\n",
            "shared.rs": test_fn("probe", " \"shared\"; "),
        }
        with tempfile.TemporaryDirectory(prefix="kestrike-tree-") as root:
            source = Path(root) / "crates" / "tree" / "src"
            for name, text in layout.items():
                (source / name).parent.mkdir(parents=True, exist_ok=True)
                (source / name).write_text(text, encoding="utf-8")
            (Path(root) / "crates" / "binary" / "src").mkdir(parents=True)
            (Path(root) / "crates" / "binary" / "src" / "main.rs").write_text(binary, encoding="utf-8")
            (Path(root) / "crates" / "both" / "src").mkdir(parents=True)
            for name, text in both.items():
                (Path(root) / "crates" / "both" / "src" / name).write_text(text, encoding="utf-8")
            patched = mock.patch.object(verify, "ROOT", Path(root))
            patched.start()
            caches = (verify.module_scopes, verify.declares_test, verify.control_text)
            for cached in caches:
                cached.cache_clear()
            try:
                for declared in ("declared::inner::witness", "sibling::hidden::hidden_witness",
                                 "outer::inner::moved_witness", "mapped::mapped_witness", "braced::witness",
                                 "alternative::witness", "enabled::witness", "remarked::witness", "at_root",
                                 "folded::mapped_witness", "linted::probe", "noted::live"):
                    self.assertTrue(verify.declares_test(declared, "tree"), declared)
                for orphan in ("orphan::witness", "hidden::witness", "quoted::witness", "commented::witness",
                               "sibling::hidden::witness", "outer::inner::decoy", "mapped::conventional",
                               "gone::witness", "absent::witness", "at_root_missing",
                               "conditional::conventional_twin", "conditional::mapped_witness",
                               "disabled::mapped_witness", "skipped::witness", "unbuilt::witness",
                               "at_remarked_root", "lone::conventional_lone", "lone::mapped_witness",
                               "never::witness", "noted::mapped_witness"):
                    self.assertFalse(verify.declares_test(orphan, "tree"), orphan)
                self.assertNotIn("planted", verify.control_text("control::probe", None, "tree"))
                self.assertIn("fn probe()", verify.control_text("control::probe", None, "tree"))
                self.assertEqual(verify.control_text("orphan::witness", None, "tree"), "")
                self.assertTrue(verify.declares_test("at_main", "binary"), "a crate rooted at main.rs")
                self.assertFalse(verify.declares_test("at_main", "tree"))
                self.assertIn("second", verify.control_text("control::probe", None, "binary"))
                self.assertEqual(verify.control_text("control::probe"), "", "a control two crates declare, no crate named")
                self.assertEqual(verify.control_text("twin::probe", None, "tree"), "",
                                 "two definitions that differ, under exclusive cfg predicates")
                self.assertIn("kept", verify.control_text("reached::probe", None, "tree"),
                              "one file that two declarations reach")
                self.assertEqual(verify.control_text("deep::spliced::probe", None, "tree"), "",
                                 "a reached scope with no direct fn, which includes its definition")
                self.assertEqual(verify.control_text("rerouted::probe", None, "tree"), "",
                                 "a declaration whose path override the reader cannot follow")
                self.assertEqual(verify.control_text("wrapped::probe", None, "tree"), "",
                                 "the same override wrapped across lines")
                self.assertIn("linted", verify.control_text("linted::probe", None, "tree"),
                              "a wrapped attribute that names no path override")
                self.assertTrue(verify.declares_test("launcher::tests::in_binary", "both"),
                                "the binary root of a package with a library")
                self.assertTrue(verify.declares_test("shared::probe", "both"))
                self.assertIn("shared", verify.control_text("shared::probe", None, "both"),
                              "one file that both roots declare")
            finally:
                patched.stop()
                for cached in caches:
                    cached.cache_clear()

    def test_every_declared_litmus_test_is_named_by_an_rc11_record(self):
        named = {test for record in CATALOG["records"] if record["job"] == "rc11" for test in record["tests"]}
        self.assertEqual(sorted(set(RC11["tests"]) - named), [])

    def admit(self, edit, catalog=None, jobs=None):
        catalog = copy.deepcopy(catalog or CATALOG)
        edit(catalog)
        return verify.admit(catalog, INVENTORY, jobs or JOBS)

    def test_a_nonexistent_test_id_is_refused(self):
        refusals = self.admit(lambda c: c["records"][1]["tests"].append("storage::device::table_tests::a_test_nobody_wrote"))
        self.assertEqual([r["code"] for r in refusals], ["nonexistent-test"])
        self.assertIn("a_test_nobody_wrote", refusals[0]["reason"])
        refusals = self.admit(lambda c: c["records"][1]["controls"].append({"test": "storage::device::table_tests::no_such_control", "violation": "refusal"}))
        self.assertEqual([r["code"] for r in refusals], ["nonexistent-test"])
        self.assertIn("no_such_control", refusals[0]["reason"])
        loom = next(i for i, r in enumerate(CATALOG["records"]) if r.get("module") == "credit_model")
        refusals = self.admit(lambda c: c["records"][loom]["tests"].append("storage::credit_model::missing"))
        self.assertEqual([r["code"] for r in refusals], ["nonexistent-test"])
        refusals = self.admit(lambda c: c["records"][loom].update(module="other_model"))
        self.assertIn("nonexistent-test", [r["code"] for r in refusals])

    def test_a_catalog_test_absent_from_the_sources_is_refused_through_the_derived_inventory(self):
        """`admit` reads the inventory declared from the catalog it judges, so a catalog test the inventory
        derives is admitted only when the crate sources hold a `#[test]` fn under its module path; a sim_worker
        test the inventory lists itself needs no source item."""
        committed = json.loads(select.read(select.INVENTORY))
        registry = select.load_registry(select.REGISTRY, committed["baseline"])
        catalog = copy.deepcopy(CATALOG)
        bogus = [
            "storage::device::table_tests::a_test_nobody_wrote",
            "storage::device::geometry::new",
            "storage::reserve::nowhere::same_size_extents_of_different_owners_return_only_their_own_units",
            "timestamp::verification::round_trips_through_bytes",
            "storage::device::geometry::device_ranges_refuse_each_fault_distinctly",
            "storage::reserve::same_size_extents_of_different_owners_return_only_their_own_units",
            "timestamp::tests::round_trips_through_bytes",
        ]
        catalog["records"][1]["tests"] += [*bogus, "histories::each_history_replays_in_a_fresh_process"]
        refusals = verify.admit(catalog, select.declare(committed, registry, catalog), JOBS)
        self.assertEqual([r["code"] for r in refusals], ["nonexistent-test"] * len(bogus))
        for test, refusal in zip(bogus, refusals):
            self.assertIn(test, refusal["reason"])
            self.assertIn("sources", refusal["reason"])

    def test_a_registry_ignored_required_test_is_refused(self):
        """A catalog that cites a registry-ignored test is refused by name through the inventory declared from
        that same catalog, the path the `admit` command takes."""
        committed = json.loads(select.read(select.INVENTORY))
        registry = select.load_registry(select.REGISTRY, committed["baseline"])
        catalog = copy.deepcopy(CATALOG)
        catalog["records"][1]["tests"].append("storage::churn_tests::churn_replay")
        refusals = verify.admit(catalog, select.declare(committed, registry, catalog), JOBS)
        self.assertEqual([(r["code"], r["record"]) for r in refusals], [("ignored-required-test", CATALOG["records"][1]["id"])])
        inventory = copy.deepcopy(INVENTORY)
        inventory["loom"]["credit_model"]["ignored"].append("storage::credit_model::dropping_the_return_fence_hides_a_credit")
        refusals = verify.admit(copy.deepcopy(CATALOG), inventory, JOBS)
        self.assertEqual([r["code"] for r in refusals], ["ignored-required-test"])

    def test_a_missing_workflow_job_is_refused(self):
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].update(job="creusot"))
        self.assertEqual([r["code"] for r in refusals], ["missing-job"])
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].update(job="rust-gate"))
        self.assertEqual([r["code"] for r in refusals], ["missing-job"])
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].update(job="quarantine"))
        self.assertEqual([r["code"] for r in refusals], ["gate-structure"])
        self.assertIn("outside rust-gate's needs", refusals[0]["reason"])
        for job in ("comment-policy", "lane-script", "rust-format"):
            with self.subTest(job=job):
                refusals = self.admit(lambda c, job=job: c["records"][ORACLE_RECORD].update(job=job))
                self.assertTrue(refusals)
                self.assertEqual({r["code"] for r in refusals}, {"gate-structure"})
                self.assertTrue(any("lacks an evidence upload" in r["reason"] for r in refusals))
                self.assertTrue(any("lacks a verify-receipts.py credit step" in r["reason"] for r in refusals))

    def test_missing_violation_text_is_refused(self):
        with_controls = next(i for i, r in enumerate(CATALOG["records"]) if r["controls"])
        refusals = self.admit(lambda c: c["records"][with_controls]["controls"][0].update(violation=""))
        self.assertEqual([r["code"] for r in refusals], ["missing-violation"])
        refusals = self.admit(lambda c: c["records"][with_controls]["controls"][0].update(violation="a message no control asserts"))
        self.assertEqual([r["code"] for r in refusals], ["missing-violation"])
        refusals = self.admit(lambda c: c["records"][with_controls]["controls"][0].update(violation=None))
        self.assertEqual([r["code"] for r in refusals], ["missing-violation"])

    def test_a_quint_control_binds_to_the_property_its_case_checks(self):
        self.assertEqual(verify.control_text("mutant-reuse-epoch", "quint"), "violation distinctEpochs")
        record = next(i for i, r in enumerate(CATALOG["records"]) if r["id"] == "q1-handshake-identity-safety")

        for violation in ("violation agreement", "violation"):
            with self.subTest(violation=violation):
                def mislabel(catalog, violation=violation):
                    catalog["records"][record]["controls"][0] = {"test": "mutant-reuse-epoch", "violation": violation}

                refusals = self.admit(mislabel)
                self.assertEqual([r["code"] for r in refusals], ["missing-violation"])
                self.assertIn("mutant-reuse-epoch", refusals[0]["reason"])

    def test_a_quint_runner_that_fails_to_load_is_a_crash_with_a_report(self):
        """A Quint control's text comes from the runner's cases, so a runner the judge cannot load leaves admission
        without a verdict: `control_text` raises `Crash`, and `admit` reports the crash under its own code. The control
        is a declared case no record cites, so its text is read from the runner and from no earlier read. A pass that
        loaded the committed runner first keeps none of its cases once it ends, whether it returns or crashes."""
        quint = {**CATALOG, "records": [r for r in CATALOG["records"] if r["job"] == "quint" and r["controls"]]}
        verify.admit(quint, INVENTORY, JOBS)
        self.assertIsNone(verify.PASS_CASES)
        judge = verify.load_script("judge_quint", verify.CHECKER_JUDGES["quint"])
        cited = {control["test"] for record in CATALOG["records"] for control in record["controls"]}
        uncited = next(name for name in read_json(verify.CHECKER_JOBS["quint"])["tests"] if name not in cited)
        record = next(i for i, r in enumerate(CATALOG["records"]) if r["id"] == "q1-handshake-identity-safety")
        catalog = copy.deepcopy(CATALOG)
        catalog["records"][record]["controls"][0] = {"test": uncited, "violation": "violation"}
        models = self.dir / "quint"
        models.mkdir()

        def load_script(name, path, load_script=verify.load_script):
            return judge if name == "judge_quint" else load_script(name, path)

        with mock.patch.object(judge, "MODELS", models), mock.patch.object(verify, "load_script", load_script), \
                mock.patch.dict(sys.modules):
            for error in ("FileNotFoundError('no family module')", "ValueError('no such action')",
                          "KeyError('no such mutant')"):
                (models / "check.py").write_text(f"raise {error}\n")
                with self.subTest(error=error), self.assertRaisesRegex(
                        verify.Crash, rf"check\.py fails to load: {re.escape(error)}"):
                    verify.control_text(uncited, "quint")
            code, report = self.main_with_catalog(catalog, "admit")
        self.assertIsNone(verify.PASS_CASES)
        self.assertEqual((code, report["code"], report["credited"]), (verify.CRASHED, verify.CRASHED, False), report)
        self.assertIn("check.py fails to load: KeyError('no such mutant')", report["crash"])

    def test_a_tlc_runner_that_fails_to_load_is_a_crash_with_a_report(self):
        """A TLC control's text comes from the runner's cases, so a runner the judge cannot load leaves admission
        without a verdict: `control_text` raises `Crash`, and `admit` reports the crash under its own code. The control
        is a declared case no record cites, so its text is read from the runner and from no earlier read. A pass that
        loaded the committed runner first keeps none of its cases once it ends, whether it returns or crashes."""
        tlc = {**CATALOG, "records": [r for r in CATALOG["records"] if r["job"] == "tlc" and r["controls"]]}
        verify.admit(tlc, INVENTORY, JOBS)
        self.assertIsNone(verify.PASS_CASES)
        judge = verify.load_script("judge_tlc", verify.CHECKER_JUDGES["tlc"])
        cited = {control["test"] for record in CATALOG["records"] for control in record["controls"]}
        record = next(i for i, r in enumerate(CATALOG["records"]) if r["job"] == "tlc")
        profile = read_json(verify.CHECKER_JOBS["tlc"])["profiles"][CATALOG["records"][record]["module"]]
        uncited = next(name for name in profile if name not in cited)
        catalog = copy.deepcopy(CATALOG)
        catalog["records"][record]["controls"][0] = {"test": uncited, "violation": "violation"}
        models = self.dir / "tla"
        models.mkdir()

        def load_script(name, path, load_script=verify.load_script):
            return judge if name == "judge_tlc" else load_script(name, path)

        with mock.patch.object(judge, "MODELS", models), mock.patch.object(verify, "load_script", load_script), \
                mock.patch.dict(sys.modules):
            for error in ("NameError('no such name')", "ImportError('no such module')", "RuntimeError('no runner')"):
                (models / "check.py").write_text(f"raise {error}\n")
                with self.subTest(error=error), self.assertRaisesRegex(
                        verify.Crash, rf"check\.py fails to load: {re.escape(error)}"):
                    verify.control_text(uncited, "tlc")
            code, report = self.main_with_catalog(catalog, "admit")
        self.assertIsNone(verify.PASS_CASES)
        self.assertEqual((code, report["code"], report["credited"]), (verify.CRASHED, verify.CRASHED, False), report)
        self.assertIn("check.py fails to load: RuntimeError('no runner')", report["crash"])

    def test_a_judge_refusal_of_cases_or_inputs_is_a_crash(self):
        """`credit` reads each profiled judge's cases and each checker judge's inputs, and `aggregate` reads the GenMC
        profile's cases for its lane domains. A judge that refuses them, as a TLC registry the runner's cases contradict,
        a failed `git ls-files` or a GenMC declaration without the event's profile does, raises `Crash`, which `main`
        reports as a JSON crash report, where the judge's own `Refusal` would leave `main` uncaught."""
        for job, name, read in (("tlc", "profile_cases", lambda: verify.credited_modules("tlc", "pr")),
                                ("genmc", "profile_cases", lambda: verify.credited_modules("genmc", "pr")),
                                ("genmc", "profile_cases", lambda: verify.lane_domains("schedule", INVENTORY)),
                                ("kani", "declaration", lambda: verify.credited_modules("kani", "pr")),
                                ("tlc", "model_files", lambda: verify.checker_inputs("tlc")),
                                ("quint", "model_files", lambda: verify.checker_inputs("quint")),
                                ("kani", "committed", lambda: verify.checker_inputs("kani")),
                                ("verus", "committed", lambda: verify.checker_inputs("verus")),
                                ("genmc", "declared_sources", lambda: verify.checker_inputs("genmc"))):
            judge = verify.load_script(f"judge_{job}", verify.CHECKER_JUDGES[job])

            def refuse(*_, judge=judge):
                raise judge.Refusal(judge.TOOL_FAILURE, "the judge refuses its inputs")

            def load_script(module, path, judge=judge, job=job, load_script=verify.load_script):
                return judge if module == f"judge_{job}" else load_script(module, path)

            with self.subTest(job=job, name=name), mock.patch.object(judge, name, refuse), \
                    mock.patch.object(verify, "load_script", load_script), mock.patch.dict(sys.modules), \
                    self.assertRaisesRegex(verify.Crash, "the judge refuses its inputs"):
                read()

    def test_violation_text_binds_to_the_named_control_not_its_module(self):
        control = "storage::lookup_model::negative_control_releasing_the_anchor_at_removal_fails"
        self.assertIn("witness violated", verify.source_of(control))
        text = verify.control_text(control)
        self.assertIn('should_panic(expected = "protection violated")', text)
        self.assertNotIn("witness violated", text)
        lookup = next(i for i, r in enumerate(CATALOG["records"]) if r.get("module") == "lookup_model")

        def mislabel(catalog):
            catalog["records"][lookup]["controls"] = [{"test": control, "violation": "witness violated"}]

        refusals = self.admit(mislabel)
        self.assertEqual([r["code"] for r in refusals], ["missing-violation"])
        self.assertIn(control, refusals[0]["reason"])
        body_control = "oracle::history_tests::a_golden_with_zero_activations_of_its_declared_obligation_fails"
        self.assertIn("!verdict.satisfies", verify.control_text(body_control))
        self.assertEqual(verify.control_text("storage::lookup_model::no_such_fn"), "")

    def test_a_missing_independent_reference_is_refused(self):
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].update(reference=" "))
        self.assertEqual([r["code"] for r in refusals], ["missing-reference"])
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].pop("reference"))
        self.assertEqual([r["code"] for r in refusals], ["malformed-record"])

    def test_shape_duplicate_and_baseline_refusals(self):
        refusals = self.admit(lambda c: c["records"].append(copy.deepcopy(c["records"][ORACLE_RECORD])))
        self.assertEqual([r["code"] for r in refusals], ["duplicate-record"])
        refusals = self.admit(lambda c: c.update(baseline="8677e862"))
        self.assertEqual([r["code"] for r in refusals], ["baseline-mismatch"])
        refusals = self.admit(lambda c: c["records"][1].update(tests=[], controls=[]))
        self.assertEqual([r["code"] for r in refusals], ["malformed-record"])
        # A malformed field reaches admission through the inventory declared from the same catalog.
        committed = json.loads(select.read(select.INVENTORY))
        registry = select.load_registry(select.REGISTRY, committed["baseline"])
        for field, value in (("tests", None), ("tests", 7), ("controls", None), ("controls", [{"violation": "x"}])):
            malformed = copy.deepcopy(CATALOG)
            malformed["records"][1][field] = value
            refusals = verify.admit(malformed, select.declare(committed, registry, malformed), JOBS)
            self.assertEqual([r["code"] for r in refusals], ["malformed-record"], (field, value))
        refusals = self.admit(lambda c: c["records"].append("not a record"))
        self.assertEqual([r["code"] for r in refusals], ["malformed-record"])
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].pop("job"))
        self.assertEqual([r["code"] for r in refusals], ["malformed-record"])
        refusals = self.admit(lambda c: c["records"][ORACLE_RECORD].update(job=["workspace"]))
        self.assertEqual([r["code"] for r in refusals], ["malformed-record"])
        jobless = copy.deepcopy(CATALOG)
        jobless["records"][ORACLE_RECORD].pop("job")
        code, report = self.credit_with_catalog(jobless, self.workspace_evidence(), "--job", "workspace")
        self.assertEqual((code, self.codes(report)), (1, ["malformed-record"]), report)

    def test_the_gate_needs_every_required_job_with_strict_unconditional_uploads(self):
        self.assertEqual(
            JOBS["rust-gate"]["needs"],
            ["comment-policy", "lane-script", "rust-format", "preflight", "workspace", "rc11", "barriers", "campaigns", "search",
             "fuzz-smoke", "long-run", "search-nightly", "verus", "loom", "miri", "sweep", "genmc", "kani", "tlc", "quint", "fuzz", "asan", "qemu",
             "isa-x86-64", "isa-aarch64", "tag-compare-x86-64", "tag-compare-aarch64"],
        )
        for job in ("workspace", "campaigns", "search", "fuzz-smoke", "long-run", "search-nightly", "loom", "fuzz"):
            self.assertTrue(JOBS[job]["upload"], job)
            self.assertTrue(JOBS[job]["credit"], job)
            self.assertGreaterEqual(JOBS[job]["timeout"], JOBS[job]["budget"] + verify.MARGIN_MINUTES, job)
            steps = JOBS[job]["steps"]
            credit = steps.index(next(s for s in steps if s["credit"]))
            self.assertTrue(steps[credit]["always"], f"{job} needs an unconditional credit step")
            self.assertTrue(any(s["upload"] for s in steps[credit + 1:]), f"{job} must upload after the credit step")
        self.assertRegex(WORKFLOW, r"verify-receipts\.py credit --job workspace")
        self.assertRegex(WORKFLOW, r"verify-receipts\.py credit --job loom\s+--module")
        self.assertRegex(WORKFLOW, r"verify-receipts\.py credit --job fuzz")
        self.assertRegex(WORKFLOW, r"verify-receipts\.py credit --job long-run --evidence evidence")
        self.assertIn("python3 scripts/verify-receipts.py admit", WORKFLOW)
        self.assertIn("python3 scripts/run-receipt-selftests.py", WORKFLOW)
        self.assertIn("python3 scripts/test-run-receipt-selftests.py", WORKFLOW)
        self.assertIn("      - name: Script self-checks\n", WORKFLOW)
        job = re.split(r"(?m)^  (?=\S)", WORKFLOW.split("\n  comment-policy:\n", 1)[-1], maxsplit=1)[0]
        self_checks = job.split("      - name: Script self-checks\n", 1)[-1].split("      - name: ", 1)[0]
        self.assertNotRegex(self_checks, r"(?m)^ {8}(?:if|shell):")
        self.assertNotIn("continue-on-error", job)
        self.assertIn("        run: |\n", self_checks)
        for command in ("python3 scripts/test-weaken-orderings.py", "python3 scripts/weaken-orderings.py check"):
            self.assertIn(f"\n          {command}\n", self_checks.split("        run: |\n", 1)[-1])
        self.assertIn("python3 scripts/test-hardware-lane.py --ci", WORKFLOW)
        self.assertIn("fetch-depth: 0", WORKFLOW.split("  lane-script:")[0])

    def test_a_job_outside_the_gate_or_without_a_strict_upload_is_refused(self):
        jobs = copy.deepcopy(JOBS)
        jobs["rust-gate"]["needs"].remove("fuzz")
        refusals = self.admit(lambda c: None, jobs=jobs)
        self.assertEqual({r["code"] for r in refusals}, {"gate-structure"})
        self.assertTrue(all(r["record"] in {x["id"] for x in CATALOG["records"] if x["job"] == "fuzz"} for r in refusals))
        for broken in (
            WORKFLOW.replace("          if-no-files-found: error\n", ""),
            re.sub(r"      - name: Evidence\n        if: always\(\)\n", "      - name: Evidence\n", WORKFLOW),
            re.sub(r"      - name: Obligation receipt and credit\n        if: always\(\)\n", "      - name: Obligation receipt and credit\n", WORKFLOW),
            WORKFLOW.replace("verify-receipts.py credit --job fuzz", "verify-receipts.py receipt --job fuzz"),
        ):
            refusals = self.admit(lambda c: None, jobs=verify.workflow_jobs(broken))
            self.assertIn("gate-structure", {r["code"] for r in refusals}, broken[:40])

    def test_a_qualified_job_without_its_credit_step_or_absent_from_the_workflow_is_refused(self):
        jobs = copy.deepcopy(JOBS)
        jobs["asan"].update(credit=False, upload=False, timeout=1)
        refusals = self.admit(lambda c: None, jobs=jobs)
        records = [r["id"] for r in CATALOG["records"] if r["job"] == "asan"]
        self.assertEqual({(r["code"], r["record"]) for r in refusals},
                         {("gate-structure", "asan"), *(("gate-structure", record) for record in records)})
        reasons = " ".join(r["reason"] for r in refusals)
        for gap in ("needs timeout-minutes at least", "lacks an evidence upload", "lacks a verify-receipts.py credit step"):
            self.assertIn(gap, reasons)
        jobs = copy.deepcopy(JOBS)
        del jobs["asan"]
        refusals = self.admit(lambda c: None, jobs=jobs)
        self.assertEqual(sorted((r["code"], r["record"]) for r in refusals),
                         sorted([("missing-job", "asan"), *(("missing-job", record) for record in records)]))

    def test_the_timeout_refusal_follows_the_step_budget_not_the_committed_value(self):
        floor = JOBS["workspace"]["budget"] + verify.MARGIN_MINUTES
        for workflow in (WORKFLOW, with_timeout(WORKFLOW, "workspace", floor + 10)):
            self.assertEqual(self.admit(lambda c: None, jobs=verify.workflow_jobs(workflow)), [])
            broken = with_timeout(workflow, "workspace", floor - 1)
            refusals = self.admit(lambda c: None, jobs=verify.workflow_jobs(broken))
            self.assertEqual({r["code"] for r in refusals}, {"gate-structure"})
            self.assertTrue(all(f"at least {floor}" in r["reason"] for r in refusals), refusals)

    def test_a_completed_positive_receipt_credits_every_workspace_record(self):
        evidence = self.workspace_evidence()
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(set(report["obligations"]), {r["id"] for r in CATALOG["records"] if r["job"] == "workspace"})
        self.assertEqual(json.loads((evidence / "credit.json").read_text())["refusals"], [])
        receipt = self.receipt_of(evidence)
        self.assertEqual(receipt["revision"], REVISION)
        self.assertEqual(receipt["completion"], "completed")
        self.assertEqual(receipt["executions"], len(receipt["executed"]))
        self.assertLessEqual({name for target in WORKSPACE_TARGETS for name in module_witnesses(target)}, set(receipt["executed"]))
        self.assertLessEqual({"list.txt", "run.txt", "report.json", "scripts/test-inventory.json", "verification/obligations.json"}, set(receipt["inputs"]))
        self.assertEqual(receipt["tool"], {"name": "cargo test", "provenance": ["- rustc 1.99.0 (b940084d7 2026-09-28)"]})
        self.assertEqual(receipt["replay"], "bash scripts/rust-lane.sh workspace")
        self.assertEqual(receipt["bounds"]["exit"], 0)
        self.assertIn("GITHUB_RUN_ID", receipt["ci"])

    def test_a_completed_loom_receipt_credits_its_module(self):
        evidence = self.loom_evidence("credit_model")
        code, report = self.run_script("credit", "--job", "loom", "--module", "credit_model", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"]
                                                 if r["job"] == "loom" and r.get("module") == "credit_model"])
        self.assertIn("credit-fences-conserve-and-flag-credits", report["obligations"])
        receipt = self.receipt_of(evidence)
        self.assertIn("release profile: debug assertions disabled", receipt["assumptions"])
        self.assertEqual(receipt["executions"], len(INVENTORY["loom"]["credit_model"]["tests"]))
        code, report = self.run_script("credit", "--job", "loom", "--module", "grace_model", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertIn("missing-result", self.codes(report))

    SPDK_HEADER = "     Running unittests src/lib.rs (/tmp/asan-target/x86_64-unknown-linux-gnu/debug/deps/spdk_sys-b25a6d8b23b3044e)"
    ASAN_HEADER = "     Running unittests src/lib.rs (/tmp/asan-target/x86_64-unknown-linux-gnu/debug/deps/kestrike-9182b89a273caa7d)"
    ENVELOPE = {
        "domain": "asan", "attempt": "1", "run": "7", "target": "x86_64-unknown-linux-gnu",
        "rustflags": "-Zsanitizer=address -Cforce-frame-pointers=yes", "sanitizer": "address",
        "install": "crates/spdk-sys/src/generated/installs/x86_64-unknown-linux-gnu-native-asan",
        "generated": "crates/spdk-sys/src/generated/outputs/cebb931293040bd0",
        "header_digest": "1" * 64, "generator_digest": "2" * 64, "generator": "bindgen 0.73.2, clang version 15.0.7, rustfmt 1.10.0-stable",
        "native": {"compilers": "GCC: (GNU) 11.5.0", "configure": "3" * 64, "archives": "4" * 64, "lineage": "unrecorded"},
        "runtime": {"archive": "/toolchain/lib/librustc-nightly_rt.asan.a", "sha256": "5" * 64, "rustc": "rustc 1.99.0-nightly", "llvm": "22.1.8"},
        "deadlines": {"build_minutes": 15, "run_minutes": 20, "build_factor": 4, "run_factor": 10},
        "measured": {"domain": "asan", "date": "2026-10-16", "host": "stub", "build_seconds": 175, "run_seconds": 61,
                     "build_peak_rss_mib": 3468, "peak_rss_mib": 8815, "cpus": 4, "memory_mib": 12288},
    }

    def asan_evidence(self, name="asan", envelope=ENVELOPE, controls=None, modules=None, chain_tests=None, **kwargs):
        """The ASan lane's evidence: the `spdk_sys` target with its shim controls and the `kestrike` target with
        a witness of each required module and its declared ignores, plus the qualified envelope."""
        asan = INVENTORY["asan"]
        controls = list(asan["required"]["spdk_sys"]["tests"]) if controls is None else list(controls)
        witnesses = [f"{module}::a_sanitized_witness" for module in (asan["required"]["kestrike"]["modules"] if modules is None else modules)]
        witnesses += list(asan["required"]["kestrike"]["tests"] if chain_tests is None else chain_tests)
        ignored = asan["ignored"]["kestrike"]
        cache = (self.ASAN_HEADER, witnesses + UNRELATED_ASAN, ignored)
        evidence = self.evidence(name, controls + ["registry_tests::a_registry_probe"], [], header=self.SPDK_HEADER,
                                 cfg_args=("--cfg", "asan"), more_targets=(cache,), **kwargs)
        if envelope is not None:
            (evidence / "qualified.json").write_text(json.dumps(envelope))
        return evidence

    def test_a_completed_asan_receipt_credits_the_qualified_domain(self):
        evidence = self.asan_evidence()
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION,
                                       env={**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"})
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "asan"],
                         "the qualified domain credits its records")
        receipt = self.receipt_of(evidence)
        self.assertEqual((receipt["completion"], receipt["selection"]["cfg"], receipt["lane"]), ("completed", "asan", "asan"))
        self.assertEqual(receipt["qualified"], self.ENVELOPE)
        self.assertIn("qualified.json", receipt["inputs"])
        self.assertEqual(receipt["tool"]["name"], "cargo test -Zbuild-std -Zsanitizer=address")
        native = 1 + len(INVENTORY["asan"]["required"]["kestrike"]["tests"])
        self.assertEqual(receipt["bounds"]["targets"]["kestrike"]["witnesses"]["executed_modules"],
                         {"bind": 1, "index": 1, "native": native})
        self.assertEqual(receipt["replay"], "bash scripts/rust-lane.sh asan")
        self.assertTrue(any("leak detection is off" in line for line in receipt["assumptions"]))

    def test_each_native_chain_judge_binds_qualified_receipt_credit_to_its_own_result(self):
        required = INVENTORY["asan"]["required"]["kestrike"]["tests"]
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        for at, test in enumerate(required):
            for fault, kwargs in (
                ("missing", {"chain_tests": [name for name in required if name != test]}),
                ("failed", {"failed": [test], "exit_code": 101}),
            ):
                with self.subTest(test=test, fault=fault):
                    evidence = self.asan_evidence(name=f"asan-chain-{at}-{fault}", **kwargs)
                    code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence),
                                                   "--revision", REVISION, env=env)
                    self.assertEqual(code, 1, report)
                    self.assertFalse(report["credited"])
                    self.assertTrue(any(test in refusal["reason"] for refusal in report["refusals"]), report)
                    self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "asan"])

    def test_an_asan_receipt_short_of_its_qualification_is_refused(self):
        cases = {
            "no envelope": (dict(envelope=None), "unqualified", "no qualified envelope"),
            "wrong domain": (dict(envelope={**self.ENVELOPE, "domain": "qemu"}), "unqualified", "names domain 'qemu'"),
            "missing attempt": (dict(envelope={**self.ENVELOPE, "attempt": ""}), "unqualified", "names no run attempt"),
            "another attempt": (dict(envelope={**self.ENVELOPE, "attempt": "2"}), "unqualified", "names attempt '2', the run is attempt '1'"),
            "missing run": (dict(envelope={**self.ENVELOPE, "run": ""}), "unqualified", "names no run"),
            "another run": (dict(envelope={**self.ENVELOPE, "run": "6"}), "unqualified", "names run '6', the receipt is of run '7'"),
            "unsanitized": (dict(envelope={**self.ENVELOPE, "sanitizer": "none"}), "unqualified", "sanitizer 'none'"),
            "missing digest": (dict(envelope={k: v for k, v in self.ENVELOPE.items() if k != "header_digest"}), "unqualified", "lacks ['header_digest']"),
            "missing runtime": (dict(envelope={**self.ENVELOPE, "runtime": None}), "unqualified", "lacks ['runtime']"),
            "runtime without digest": (dict(envelope={**self.ENVELOPE, "runtime": {**self.ENVELOPE["runtime"], "sha256": ""}}), "unqualified", "runtime lacks ['sha256']"),
            "foreign measurement": (dict(envelope={**self.ENVELOPE, "measured": {**self.ENVELOPE["measured"], "domain": "qemu"}}), "unqualified", "measurement is of domain 'qemu'"),
            "short deadline": (dict(envelope={**self.ENVELOPE, "deadlines": {**self.ENVELOPE["deadlines"], "run_minutes": 5}}), "unqualified", "run deadline 5m is below 10 times the measured 61 s"),
            "peak over memory": (dict(envelope={**self.ENVELOPE, "measured": {**self.ENVELOPE["measured"], "peak_rss_mib": 20000}}), "unqualified", "exceeds the measured memory"),
            "missing control": (dict(controls=INVENTORY["asan"]["required"]["spdk_sys"]["tests"][:1]), "selection-refused", "omits required controls"),
            "failed control": (dict(failed=INVENTORY["asan"]["required"]["spdk_sys"]["tests"][:1], exit_code=101), "missing-result", "has no ok outcome"),
            "unattributed module": (dict(modules=["bind", "native"]), "selection-refused", "lists no runnable test of required modules ['index']"),
        }
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        for name, (kwargs, code, reason) in cases.items():
            with self.subTest(case=name):
                evidence = self.asan_evidence(name=f"asan-{name.replace(' ', '-')}", **kwargs)
                result, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
                self.assertEqual(result, 1, report)
                self.assertIn(code, self.codes(report))
                self.assertTrue(any(reason in r["reason"] for r in report["refusals"] if r["code"] == code), report)
        with self.subTest(case="stale revision"):
            evidence = self.asan_evidence(name="asan-stale")
            result, report = self.credit(evidence, "asan", revision="f" * 40)
            self.assertEqual((result, "unbound-revision" in self.codes(report)), (1, True), report)

    def test_a_qualified_envelope_with_a_per_module_attribution_of_zero_is_refused_at_credit(self):
        evidence = self.asan_evidence()
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        code, report = self.run_script("receipt", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual(code, 0, report)
        receipt = self.receipt_of(evidence)
        receipt["bounds"]["targets"]["kestrike"]["witnesses"]["executed_modules"]["index"] = 0
        judged = evidence / "judged.json"
        judged.write_text(json.dumps(receipt))
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, "--receipt", str(judged), env=env)
        self.assertEqual(code, 1, report)
        self.assertEqual(self.codes(report), ["unbound-input", "unqualified"])
        gaps = verify.qualification_gaps("asan", receipt, INVENTORY)
        self.assertEqual(gaps, [("unqualified", "kestrike attributes no executed test to the required modules ['index']")])

    def test_an_envelope_the_producer_would_refuse_is_unqualified_at_credit(self):
        evidence = self.asan_evidence(name="asan-weakened")
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        code, report = self.run_script("receipt", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual(code, 0, report)
        receipt = self.receipt_of(evidence)
        self.assertEqual(verify.qualification_gaps("asan", receipt, INVENTORY), [])
        measured, deadlines = self.ENVELOPE["measured"], self.ENVELOPE["deadlines"]
        cases = {
            "measurement not a record": ({"measured": "x"}, "the measurement is not a record"),
            "deadlines not a record": ({"deadlines": "y"}, "the deadlines are not a record"),
            "weakened factor": ({"deadlines": {**deadlines, "build_factor": 1, "build_minutes": 3}}, "the build factor 1 is not the lane's factor 4"),
            "zero figure": ({"measured": {**measured, "build_seconds": 0}}, "the measurement records build_seconds as 0; a positive number is required"),
            "boolean peak": ({"measured": {**measured, "peak_rss_mib": True}}, "the measurement records peak_rss_mib as True; a positive number is required"),
            "build peak over memory": ({"measured": {**measured, "build_peak_rss_mib": 20000}}, "the measured build peak 20000 MiB exceeds the measured memory 12288 MiB"),
            "measurement without its build peak": ({"measured": {k: v for k, v in measured.items() if k != "build_peak_rss_mib"}}, "the measurement lacks ['build_peak_rss_mib']"),
            "measurement without its host": ({"measured": {k: v for k, v in measured.items() if k != "host"}}, "the measurement lacks ['host']"),
            "non-positive deadline": ({"deadlines": {**deadlines, "run_minutes": -1}}, "the run deadline -1m is no positive bound"),
            "native without digests": ({"native": {"compilers": "GCC"}}, "the envelope's native lacks ['configure', 'archives', 'lineage']"),
            "native not a record": ({"native": "GCC"}, "the envelope's native lacks ['compilers', 'configure', 'archives', 'lineage']"),
            "stale lineage": ({"native": {**self.ENVELOPE["native"], "lineage": "e" * 64}}, f"the envelope's lineage {'e' * 64} is "
                              f"not unrecorded, the identity of the committed {self.ENVELOPE['install']}; the record is stale"),
            "install of another checkout's directory outside installs": ({"install": "/srv/checkout/crates/spdk-sys/src/generated/x86_64-unknown-linux-gnu-native-asan"},
                "the envelope names install '/srv/checkout/crates/spdk-sys/src/generated/x86_64-unknown-linux-gnu-native-asan', no committed record "
                "under crates/spdk-sys/src/generated/installs"),
            "foreign install": ({"install": "/etc/passwd"}, "the envelope names install '/etc/passwd', no committed record "
                                "under crates/spdk-sys/src/generated/installs"),
        }
        for name, (change, reason) in cases.items():
            with self.subTest(case=name):
                gaps = verify.qualification_gaps("asan", {**receipt, "qualified": {**receipt["qualified"], **change}}, INVENTORY)
                self.assertIn(("unqualified", reason), gaps)
        with self.subTest(case="credit"):
            evidence = self.asan_evidence(name="asan-unrecorded", envelope={**self.ENVELOPE, "measured": "x", "deadlines": "y"})
            code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
            self.assertEqual(code, 1, report)
            self.assertEqual(self.codes(report), ["unqualified"], report)

    def test_a_lineage_bearing_record_credits_only_its_own_digest(self):
        """An envelope credits against the committed record's identity: its sha256 once the record carries the
        controlled build's lineage, so an `unrecorded` envelope is then stale."""
        # A copy of the committed record under a scratch root keeps the checkout untouched while the test
        # appends a lineage to it.
        install = self.dir / self.ENVELOPE["install"]
        install.parent.mkdir(parents=True)
        original = (ROOT / self.ENVELOPE["install"]).read_bytes()
        install.write_bytes(original)
        with mock.patch.object(verify, "ROOT", self.dir):
            self.assertEqual(verify.lineage_gaps(self.ENVELOPE), [])
            another_checkout = {**self.ENVELOPE, "install": f"/srv/another-checkout/{self.ENVELOPE['install']}"}
            self.assertEqual(verify.lineage_gaps(another_checkout), [], "a producer's absolute install path is read in the judging checkout")
            install.write_bytes(original + f"Source: SPDK a DPDK b\nArchive: {'a' * 64}  librte_eal.a\n".encode())
            digest = hashlib.sha256(install.read_bytes()).hexdigest()
            recorded = {**self.ENVELOPE, "native": {**self.ENVELOPE["native"], "lineage": digest}}
            self.assertEqual(verify.lineage_gaps(recorded), [])
            self.assertEqual(verify.lineage_gaps(self.ENVELOPE),
                             [f"the envelope's lineage unrecorded is not {digest}, the identity of the committed "
                              f"{self.ENVELOPE['install']}; the record is stale"])

    def test_an_unreadable_envelope_is_unqualified_and_the_receipt_is_written(self):
        evidence = self.asan_evidence(name="asan-unreadable", envelope=None)
        (evidence / "qualified.json").write_text("")
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual(code, 1, report)
        self.assertEqual(self.codes(report), ["unqualified"], report)
        self.assertTrue(any("no readable qualified.json" in r["reason"] for r in report["refusals"]), report)
        self.assertIsNone(self.receipt_of(evidence)["qualified"])

    def test_a_catalog_record_naming_the_asan_lane_is_admitted_against_its_required_controls(self):
        control = INVENTORY["asan"]["required"]["spdk_sys"]["tests"][0]
        record = {"id": "a-sanitized-record", "property": "blotter issue 758 P-E-999", "transition": "x", "invariant": "y", "job": "asan",
                  "tests": [], "controls": [{"test": control, "violation": "heap-buffer-overflow"}], "reference": "z"}
        self.assertEqual(self.admit(lambda c: c["records"].append(record)), [])
        unknown = {**record, "controls": [{"test": "shim_tests::an_unlisted_control", "violation": "x"}]}
        refusals = self.admit(lambda c: c["records"].append(unknown))
        self.assertEqual([(r["code"], r["record"]) for r in refusals], [("nonexistent-test", "a-sanitized-record")])

    def test_an_asan_run_that_timed_out_was_skipped_or_executed_nothing_is_refused(self):
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        evidence = self.asan_evidence(name="asan-timeout", exit_code=143)
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual((code, "timeout" in self.codes(report)), (1, True), report)
        skipped = self.dir / "asan-skipped"
        skipped.mkdir()
        (skipped / "qualified.json").write_text(json.dumps(self.ENVELOPE))
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(skipped), "--revision", REVISION, env=env)
        self.assertEqual(code, 1, report)
        self.assertLessEqual({"skipped", "zero-executions", "missing-result"}, set(self.codes(report)))
        cancelled = self.asan_evidence(name="asan-cancelled", extra_output="##[error]The operation was canceled.\n")
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(cancelled), "--revision", REVISION, env=env)
        self.assertEqual((code, "timeout" in self.codes(report)), (1, True), report)
        empty = self.asan_evidence(name="asan-empty")
        (empty / "run.txt").write_text(f"{self.SPDK_HEADER}\n{summary(0, 0, 0)}\n{self.ASAN_HEADER}\n{summary(0, 0, 0)}\n")
        for stale in ("report.json", "selection.json"):
            (empty / stale).unlink()
        code, report = self.run_script("credit", "--job", "asan", "--evidence", str(empty), "--revision", REVISION, env=env)
        self.assertEqual(code, 1, report)
        self.assertIn("zero-executions", self.codes(report))

    GUEST_HEADER = "     Running unittests src/lib.rs (guest/kestrike-0123456789abcdef)"
    GUEST_TEST = INVENTORY["qemu"]["tests"][0]
    QEMU_ENVELOPE = {
        "domain": "qemu", "attempt": "1", "run": "7", "target": "x86_64-unknown-linux-gnu", "rustflags": "-Ctarget-cpu=x86-64-v2",
        "install": "crates/spdk-sys/src/generated/installs/x86_64-unknown-linux-gnu-x86-64-v2",
        "generated": "crates/spdk-sys/src/generated/outputs/cebb931293040bd0",
        "header_digest": "1" * 64, "generator_digest": "2" * 64, "generator": "bindgen 0.73.2, clang version 15.0.7, rustfmt 1.10.0-stable",
        "native": {"compilers": "GCC: (GNU) 11.5.0", "configure": "3" * 64, "archives": "4" * 64, "lineage": "unrecorded"},
        "artifact": {"target": "x86_64-unknown-linux-gnu", "rustflags": "-Ctarget-cpu=x86-64-v2", "generated": "x86_64-unknown-linux-gnu-x86-64-v2",
                     "header_digest": "1" * 64, "generator_digest": "2" * 64, "archives": "4" * 64, "install": "/opt/spdk-v25.05.1-x86-64-v2",
                     "source": "ahrav/kestrike#664 build 12"},
        "guest": {"cpus": 2, "memory_mib": 2048, "backing_mib": 64},
        "host": {"kernel": "6.12.0", "machine": "x86_64", "runner": "kestrike-heavy-1", "accel": "kvm"},
        "inputs": {"path": "/etc/kestrike/guest-inputs.env", "sha256": "6" * 64},
        "executable": {"path": "/cache/target/debug/deps/kestrike-0123abcd", "sha256": "8" * 64},
        "initrd": {"path": "evidence/guest-initrd.img", "sha256": "7" * 64},
        "deadlines": {"handshake_minutes": 5, "run_minutes": 15, "handshake_factor": 4, "run_factor": 10},
        "measured": {"domain": "qemu", "handshake_seconds": 40, "run_seconds": 30, "build_peak_rss_mib": 3500, "peak_rss_mib": 3000, "cpus": 4, "memory_mib": 12288,
                     "guest": {"cpus": 2, "memory_mib": 2048, "backing_mib": 64},
                     "host": {"machine": "x86_64", "runners": ["kestrike-heavy-1", "kestrike-heavy-2"], "accel": "kvm"}, "date": "2026-10-16"},
    }
    GUEST = {
        "test_id": GUEST_TEST, "outcome": "qualified pass", "exit": 0, "reason": None, "run_id": "7", "run_attempt": "1",
        "identity": {"volume": "vol-0123456789abcdef0", "instance": "i-0123456789abcdef0", "model": "QEMU NVMe Ctrl", "pci": "1b36:0010"},
        "inputs": {name: {"path": f"/var/lib/kestrike/guest/{name}", "sha256": "7" * 64} for name in ("qemu", "kernel", "initrd")},
        "qemu_version": "QEMU emulator version 9.2.0", "ready": "kernel=6.12.0 modules=vfio-pci,nvme iommu=intel",
        "reports": ["default refused", "controller 0000:00:04.0 model \"QEMU NVMe Ctrl\" pci 1b36:0010 namespace nvme0n1 group 3", "substituted file refused", "other block node refused", "holder refused", "claimed", "bound", "released", "namespace tools ready", *[f"namespace {case['id']} passed" for case in INVENTORY["qemu"]["namespace_cases"]]],
        "summary": ["running 1 test", "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.10s"],
        "argv": ["/usr/bin/qemu-system-x86_64", "-machine", "q35,accel=kvm,kernel-irqchip=split", "-device", "intel-iommu,intremap=on,caching-mode=on",
                 "-append", "console=ttyS0 intel_iommu=on iommu=nopt panic=-1"],
        "bounds": {"memory_mib": 2048, "cpus": 2, "backing_mib": 64, "handshake_seconds": 300, "deadline_seconds": 900, "accel": "kvm"},
        "backing": {"path": "/tmp/guest-binder-x/volume.raw", "bytes": 64 << 20}, "cleanup": {"backing_removed": True, "qemu_reaped": True},
        "guest_exit": 0, "qemu_exit": 0, "seconds": 95.1, "reports_overflow": False,
    }

    def qemu_evidence(self, name="qemu", envelope=QEMU_ENVELOPE, guest=GUEST, **kwargs):
        """The guest lane's evidence: the host listing of `kestrike` with its declared ignores, the guest console
        as the run of the one exact ID, the qualified envelope and the harness record."""
        ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        listed = [*UNRELATED_ASAN, *module_witnesses()]
        evidence = self.dir / name
        evidence.mkdir()
        (evidence / "list.txt").write_text(listing(listed + ignored, self.GUEST_HEADER))
        (evidence / "ignored.txt").write_text(listing(ignored, self.GUEST_HEADER))
        filtered = len(listed) + len(ignored) - 1
        exit_code = kwargs.get("exit_code", 0)
        # The console as libtest prints it under --nocapture: the case named before its reports, its outcome alone.
        padding = [f"padding {index}" for index in range(kwargs.get("padding", 0))]
        reports = "".join(f"guest-binder: {report}\n" for report in [*self.GUEST["reports"], *padding])
        run = kwargs.get("run", f"{self.GUEST_HEADER}\n[    0.000000] Linux version 6.12.0\nguest-binder: ready kernel=6.12.0\nrunning 1 test\n"
                                f"test {self.GUEST_TEST} ... {reports}ok\n\n"
                                f"{summary(1, 0, 0, filtered)}\nguest-binder: exit 0\n")
        (evidence / "run.txt").write_text(run)
        (evidence / "exit.txt").write_text(f"{exit_code}\n")
        (evidence / "pins.txt").write_text("- rustc 1.99.0 (b940084d7 2026-09-28)\n- guest inputs /etc/kestrike/guest-inputs.env\n")
        common = ["--cfg", "qemu", "--list", str(evidence / "list.txt"), "--ignored", str(evidence / "ignored.txt")]
        with (evidence / "selection.json").open("w") as out:
            subprocess.run([sys.executable, str(SELECT), "listing", *common], stdout=out, stderr=subprocess.DEVNULL, check=False)
        with (evidence / "report.json").open("w") as out:
            subprocess.run([sys.executable, str(SELECT), "run", *common, "--output", str(evidence / "run.txt"), "--exit", str(exit_code)],
                           stdout=out, stderr=subprocess.DEVNULL, check=False)
        if envelope is not None:
            (evidence / "qualified.json").write_text(json.dumps(envelope))
        if guest is not None:
            (evidence / "guest.json").write_text(json.dumps(guest))
        return evidence

    def test_a_completed_qemu_receipt_credits_the_guest_domain(self):
        evidence = self.qemu_evidence()
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual((code, report["refusals"], report["obligations"]), (0, [], [record["id"] for record in CATALOG["records"] if record["job"] == "qemu"]), report)
        receipt = self.receipt_of(evidence)
        self.assertEqual((receipt["completion"], receipt["selection"]["cfg"], receipt["executions"], receipt["executed"]),
                         ("completed", "qemu", 1, [self.GUEST_TEST]))
        self.assertEqual((receipt["qualified"], receipt["guest"]), (self.QEMU_ENVELOPE, self.GUEST))
        self.assertLessEqual({"qualified.json", "guest.json", "run.txt"}, set(receipt["inputs"]))
        self.assertEqual((receipt["tool"]["name"], receipt["replay"]), ("scripts/guest-binder.py", "bash scripts/rust-lane.sh qemu"))
        other = self.qemu_evidence(name="qemu-second-registration",
                                   envelope={**self.QEMU_ENVELOPE, "host": {**self.QEMU_ENVELOPE["host"], "runner": "kestrike-heavy-2"}})
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(other), "--revision", REVISION, env=env)
        self.assertEqual((code, report["refusals"]), (0, []), report)

    def test_namespace_console_and_record_must_agree(self):
        evidence = self.qemu_evidence(name="namespace-console")
        run = evidence / "run.txt"
        run.write_text("\n".join(line for line in run.read_text().splitlines() if "guest-binder: namespace bind::" not in line))
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION,
                                       env={**os.environ, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"})
        self.assertEqual(code, 1, report)
        self.assertTrue(any("guest console reports differ from the guest record" in refusal["reason"] for refusal in report["refusals"]))

    def test_a_console_that_lacks_a_recorded_binder_witness_refuses_the_receipt(self):
        """The record's reports credit only as the console prints them: with the console's `default refused`
        report replaced by another report and the record unchanged, the receipt is refused."""
        evidence = self.qemu_evidence(name="console-without-a-witness")
        run = evidence / "run.txt"
        console = run.read_text()
        self.assertIn("guest-binder: default refused\n", console)
        run.write_text(console.replace("guest-binder: default refused\n", "guest-binder: default admitted\n"))
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION,
                                       env={**os.environ, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"})
        self.assertEqual((code, [(refusal["code"], refusal["reason"]) for refusal in report["refusals"]]),
                         (1, [("unqualified", "guest console reports differ from the guest record")]), report)

    def test_namespace_receipts_require_every_exact_result_once(self):
        reports = self.GUEST["reports"]
        member = next(report for report in reports if report.startswith("namespace bind::"))
        for name, changed in {
            "missing": [report for report in reports if report != member],
            "substituted": [report.replace(member, "namespace bind::network_tests::substituted passed") for report in reports],
            "duplicate": [*reports, member],
            "failed": [report.replace(member, member.replace(" passed", " failed")) for report in reports],
            "timeout": [report.replace(member, member.replace(" passed", " timed-out")) for report in reports],
            "tools": [report for report in reports if report != "namespace tools ready"],
        }.items():
            with self.subTest(name=name):
                evidence = self.qemu_evidence(name="namespace-" + name, guest={**self.GUEST, "reports": changed})
                code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION,
                                               env={**os.environ, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"})
                self.assertEqual(code, 1, report)
                self.assertTrue(any("namespace witnesses differ" in refusal["reason"] for refusal in report["refusals"]))

    def test_a_console_past_the_report_bound_refuses_a_record_that_states_no_overflow(self):
        """The harness judges its witnesses over the reports its record keeps, the first `REPORT_BOUND`, so
        the verifier counts the console's reports itself: with exactly the bound the receipt credits, and with
        one report past it the receipt is refused although the record's `reports_overflow` is `False`."""
        bound = verify.load_script("guest_binder", ROOT / "scripts/guest-binder.py").REPORT_BOUND
        held = len(self.GUEST["reports"])
        env = {**os.environ, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        kept = {**self.GUEST, "reports": [*self.GUEST["reports"], *(f"padding {index}" for index in range(bound - held))]}
        self.assertEqual(len(kept["reports"]), bound)
        evidence = self.qemu_evidence(name="console-at-bound", padding=bound - held, guest=kept)
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        evidence = self.qemu_evidence(name="console-past-bound", padding=bound - held + 1, guest=kept)
        code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=env)
        self.assertEqual(code, 1, report)
        self.assertEqual([(refusal["code"], refusal["reason"]) for refusal in report["refusals"]],
                         [("unqualified", f"guest console: the report count exceeded its bound of {bound}")], report)

    def test_a_console_log_at_its_bound_refuses_a_record_that_states_a_qualified_pass(self):
        """The harness logs at most `CONSOLE_BYTES` characters of the console, and the witness and report checks
        read that log. One character under the bound the receipt credits. At the bound the log can be cut, so
        the receipt is refused although its record states a qualified pass and no truncation."""
        bound = verify.load_script("guest_binder", ROOT / "scripts/guest-binder.py").CONSOLE_BYTES
        env = {**os.environ, "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1"}
        for name, length, refusals in (
            ("log-under-bound", bound - 1, []),
            ("log-at-bound", bound, [("unqualified", f"guest console: the log reached its bound of {bound} characters")]),
        ):
            with self.subTest(name=name):
                evidence = self.qemu_evidence(name=name)
                run = evidence / "run.txt"
                header, console = run.read_text().split("\n", 1)
                console += "x" * (length - len(console) - 1) + "\n"
                self.assertEqual(len(console), length)
                run.write_text(f"{header}\n{console}")
                code, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=env)
                self.assertEqual((code, [(refusal["code"], refusal["reason"]) for refusal in report["refusals"]]),
                                 (1 if refusals else 0, refusals), report)

    def test_a_qemu_receipt_short_of_its_guest_witnesses_or_artifact_is_refused(self):
        guest = self.GUEST
        cases = {
            "no guest record": (dict(guest=None), "unqualified", "no guest record"),
            "failed case": (dict(guest={**guest, "outcome": "case failed", "reason": "x"}), "unqualified", "ended 'case failed'"),
            "report overflow": (dict(guest={**guest, "reports_overflow": True}), "unqualified", "guest report count exceeded its bound"),
            "unstated report overflow": (dict(guest={k: v for k, v in guest.items() if k != "reports_overflow"}), "unqualified", "states no report overflow flag: None"),
            "report overflow stated as zero": (dict(guest={**guest, "reports_overflow": 0}), "unqualified", "states no report overflow flag: 0"),
            "truncated console": (dict(guest={**guest, "console_truncated": True}), "unqualified", "the guest console passed its log's bound"),
            "another attempt": (dict(guest={**guest, "run_attempt": "2"}), "unqualified", "names attempt '2'"),
            "another run": (dict(guest={**guest, "run_id": "6"}), "unqualified", "the guest record names run '6', the receipt is of run '7'"),
            "no run id": (dict(guest={k: v for k, v in guest.items() if k != "run_id"}), "unqualified", "the guest record names run None"),
            "missing release": (dict(guest={**guest, "reports": [r for r in guest["reports"] if r != "released"]}), "unqualified", "lack the ordered witnesses"),
            "missing block node refusal": (dict(guest={**guest, "reports": [r for r in guest["reports"] if r != "other block node refused"]}), "unqualified", "lack the ordered witnesses"),
            "reports out of order": (dict(guest={**guest, "reports": [r for r in guest["reports"] if r != "claimed"] + ["claimed"]}), "unqualified", "lack the ordered witnesses"),
            "no IOMMU group": (dict(guest={**guest, "reports": [r for r in guest["reports"] if not r.startswith("controller ")]}), "unqualified", "name no controller with its IOMMU group"),
            "no IOMMU settings": (dict(guest={**guest, "argv": ["/usr/bin/qemu-system-x86_64", "-machine", "q35"]}), "unqualified", "without the IOMMU settings"),
            "undigested input": (dict(guest={**guest, "inputs": {**guest["inputs"], "initrd": {"path": "/x"}}}), "unqualified", "inputs ['initrd'] carry no digest"),
            "backing left": (dict(guest={**guest, "cleanup": {"backing_removed": False, "qemu_reaped": True}}), "unqualified", "left behind"),
            "no identity": (dict(guest={**guest, "identity": {"volume": "v"}}), "unqualified", "identity lacks"),
            "missing artifact": (dict(envelope={k: v for k, v in self.QEMU_ENVELOPE.items() if k != "artifact"}), "unqualified", "lacks ['artifact']"),
            "artifact without digest": (dict(envelope={**self.QEMU_ENVELOPE, "artifact": {**self.QEMU_ENVELOPE["artifact"], "header_digest": ""}}), "unqualified", "artifact lacks ['header_digest']"),
            "wrong domain": (dict(envelope={**self.QEMU_ENVELOPE, "domain": "asan"}), "unqualified", "names domain 'asan'"),
            "short handshake": (dict(envelope={**self.QEMU_ENVELOPE, "deadlines": {**self.QEMU_ENVELOPE["deadlines"], "handshake_minutes": 1}}), "unqualified", "handshake deadline 1m is below 4 times"),
            "handshake dropped": (dict(envelope={**self.QEMU_ENVELOPE, "deadlines": {"run_minutes": 15, "run_factor": 10}}), "unqualified", "the handshake deadline Nonem is no positive bound"),
            "hollow host": (dict(envelope={**self.QEMU_ENVELOPE, "host": {**self.QEMU_ENVELOPE["host"], "accel": ""}}), "unqualified", "host lacks ['accel']"),
            "unmeasured runner": (dict(envelope={**self.QEMU_ENVELOPE, "host": {**self.QEMU_ENVELOPE["host"], "runner": "kestrike-heavy-3"}}), "unqualified", "taken on runners ['kestrike-heavy-1', 'kestrike-heavy-2'], this run is on 'kestrike-heavy-3'"),
            "unmeasured accelerator": (dict(envelope={**self.QEMU_ENVELOPE, "host": {**self.QEMU_ENVELOPE["host"], "accel": "tcg"}}), "unqualified", "taken under accelerator 'kvm', this run is under 'tcg'"),
            "single measured runner": (dict(envelope={**self.QEMU_ENVELOPE, "measured": {**self.QEMU_ENVELOPE["measured"], "host": {"machine": "x86_64", "runner": "kestrike-heavy-1", "accel": "kvm"}}}), "unqualified", "needs a record of its machine, its runner registrations and its accelerator"),
            "another initrd": (dict(guest={**guest, "inputs": {**guest["inputs"], "initrd": {"path": "/x", "sha256": "9" * 64}}}), "unqualified", "not the one the lane built"),
            "no executable": (dict(envelope={k: v for k, v in self.QEMU_ENVELOPE.items() if k != "executable"}), "unqualified", "lacks ['executable']"),
            "no modules fact": (dict(guest={**guest, "ready": "kernel=6.12.0 iommu=intel"}), "unqualified", "state no ['modules']"),
            "malformed identity": (dict(guest={**guest, "identity": ["volume"]}), "unqualified", "identity lacks"),
            "undigested inputs file": (dict(envelope={**self.QEMU_ENVELOPE, "inputs": {"path": "/x"}}), "unqualified", "inputs lacks ['sha256']"),
            "half IOMMU": (dict(guest={**guest, "argv": [w for w in guest["argv"] if "intel_iommu=on" not in w]}), "unqualified", "without the IOMMU settings"),
            "no ready": (dict(guest={**guest, "ready": None}), "unqualified", "state no ['kernel', 'modules', 'iommu']"),
            "no QEMU version": (dict(guest={**guest, "qemu_version": ""}), "unqualified", "lacks qemu_version"),
            "short bounds": (dict(guest={**guest, "bounds": {"memory_mib": 2048}}), "unqualified", "bounds lack"),
            "guest under another accelerator": (dict(guest={**guest, "bounds": {**guest["bounds"], "accel": "tcg"}}), "unqualified", "the guest ran under accelerator 'tcg', the envelope names 'kvm'"),
            "no backing bytes": (dict(guest={**guest, "backing": {"path": "/x"}}), "unqualified", "unrecorded or was left behind"),
            "no envelope": (dict(envelope=None), "unqualified", "no qualified envelope"),
            "cut run": (dict(run=f"{self.GUEST_HEADER}\nguest-binder: ready\nrunning 1 test\n", exit_code=124), "timeout", "produced no summary"),
            "cancelled": (dict(run=f"{self.GUEST_HEADER}\nguest-binder: ready\nrunning 1 test\n##[error]The operation was canceled.\n", exit_code=143), "timeout", "cancel or timeout marker"),
        }
        for key, value in (("cpus", 3), ("memory_mib", 4096), ("backing_mib", 128)):
            cases[f"unmeasured envelope {key}"] = (
                dict(envelope={**self.QEMU_ENVELOPE, "guest": {**self.QEMU_ENVELOPE["guest"], key: value}}),
                "unqualified", f"guest {key} {value} differs from measured")
            cases[f"unmeasured guest {key}"] = (
                dict(guest={**guest, "bounds": {**guest["bounds"], key: value}}),
                "unqualified", f"guest {key} {value} differs from measured")
        cases["missing measured guest resources"] = (
            dict(envelope={**self.QEMU_ENVELOPE, "measured": {k: v for k, v in self.QEMU_ENVELOPE["measured"].items() if k != "guest"}}),
            "unqualified", "positive integer guest")
        cases["missing envelope guest resources"] = (
            dict(envelope={k: v for k, v in self.QEMU_ENVELOPE.items() if k != "guest"}),
            "unqualified", "guest resources are missing")
        env = {**os.environ, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "7"}
        for name, (kwargs, code, reason) in cases.items():
            with self.subTest(case=name):
                evidence = self.qemu_evidence(name=f"qemu-{name.replace(' ', '-')}", **kwargs)
                result, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=env)
                self.assertEqual(result, 1, report)
                self.assertIn(code, self.codes(report))
                self.assertTrue(any(reason in r["reason"] for r in report["refusals"] if r["code"] == code), report)
        with self.subTest(case="stale revision"):
            evidence = self.qemu_evidence(name="qemu-stale")
            result, report = self.credit(evidence, "qemu", revision="f" * 40)
            self.assertEqual((result, "unbound-revision" in self.codes(report)), (1, True), report)
        for name, ci in (("local run", {}), ("no run id", {"GITHUB_RUN_ATTEMPT": "1"}), ("no attempt", {"GITHUB_RUN_ID": "7"})):
            with self.subTest(case=name):
                evidence = self.qemu_evidence(name=f"qemu-ci-{name.replace(' ', '-')}")
                local = {**{k: v for k, v in os.environ.items() if not k.startswith("GITHUB_")}, **ci}
                result, report = self.run_script("credit", "--job", "qemu", "--evidence", str(evidence), "--revision", REVISION, env=local)
                self.assertEqual(result, 1, report)
                self.assertTrue(any("the guest domain credits a CI run alone" in r["reason"] for r in report["refusals"]), report)
        with self.subTest(case="skipped"):
            skipped = self.dir / "qemu-skipped"
            skipped.mkdir()
            result, report = self.run_script("credit", "--job", "qemu", "--evidence", str(skipped), "--revision", REVISION, env=env)
            self.assertEqual(result, 1, report)
            self.assertLessEqual({"skipped", "zero-executions", "unqualified", "missing-result"}, set(self.codes(report)))
        with self.subTest(case="empty run"):
            empty = self.qemu_evidence(name="qemu-empty", run=f"{self.GUEST_HEADER}\nrunning 0 tests\n\n{summary(0, 0, 0, 10)}\n")
            result, report = self.run_script("credit", "--job", "qemu", "--evidence", str(empty), "--revision", REVISION, env=env)
            self.assertEqual(result, 1, report)
            self.assertLessEqual({"selection-refused", "zero-executions", "missing-result"}, set(self.codes(report)))

    def miri_evidence(self, name="miri", failed=(), filtered=None):
        declared = INVENTORY["miri"]
        evidence = self.dir / name
        evidence.mkdir()
        header = "     Running unittests src/lib.rs (/tmp/miri-target/miri/x86_64-unknown-linux-gnu/debug/deps/kestrike-2d37337a438c04e5)"
        (evidence / "list.txt").write_text(listing(declared["tests"] + declared["ignored"], header))
        (evidence / "ignored.txt").write_text(listing(declared["ignored"], header))
        lines = [f"test {n} ... {'FAILED' if n in failed else 'ok'}" for n in declared["tests"]]
        passed = len(declared["tests"]) - len(failed)
        filtered = len(declared["ignored"]) if filtered is None else filtered
        (evidence / "run.txt").write_text(f"{header}\n" + "\n".join(lines) + f"\n{summary(passed, len(failed), 0, filtered)}\n")
        (evidence / "exit.txt").write_text(f"{101 if failed else 0}\n")
        (evidence / "pins.txt").write_text("- miri 0.1.0 (dc3f85158a 2026-07-26); MIRIFLAGS=-Zmiri-seed=0 -Zmiri-permissive-provenance\n")
        (evidence / "controls.txt").write_text("".join(f"{c['test']}\t1\tfound\n" for c in declared["controls"]))
        common = ["--cfg", "miri", "--list", str(evidence / "list.txt"), "--ignored", str(evidence / "ignored.txt")]
        with (evidence / "report.json").open("w") as out:
            subprocess.run([sys.executable, str(SELECT), "run", *common, "--output", str(evidence / "run.txt"),
                            "--exit", (evidence / "exit.txt").read_text().strip()], stdout=out, stderr=subprocess.DEVNULL, check=False)
        return evidence

    def test_a_completed_miri_receipt_credits_the_ownership_records(self):
        evidence = self.miri_evidence()
        code, report = self.run_script("credit", "--job", "miri", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "miri"])
        receipt = self.receipt_of(evidence)
        self.assertEqual((receipt["tool"]["name"], receipt["executions"]), ("cargo miri test", len(INVENTORY["miri"]["tests"])))
        self.assertIn("default Stacked Borrows and detectors, seed 0, one test thread", receipt["assumptions"])
        self.assertIn("one sampled schedule; weak-memory emulation is bounded and incomplete", receipt["assumptions"])
        self.assertIn("integer-to-pointer casts accepted without warning; strict provenance unestablished", receipt["assumptions"])
        failed = self.miri_evidence("miri-failed", failed=INVENTORY["miri"]["tests"][:1])
        code, report = self.run_script("credit", "--job", "miri", "--evidence", str(failed), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertLessEqual({"selection-refused", "raw-failed", "missing-result"}, set(self.codes(report)))
        refusals = self.admit(lambda c: next(r for r in c["records"] if r["job"] == "miri")["tests"].append(INVENTORY["miri"]["ignored"][0]))
        self.assertEqual([r["code"] for r in refusals], ["ignored-required-test"])

    def sweep_evidence(self, name="sweep"):
        """The sweep lane's evidence: every kernel run `ok` in one block per seed."""
        declared, sweep = INVENTORY["miri"], INVENTORY["miri_sweep"]
        evidence = self.dir / name
        evidence.mkdir()
        header = "     Running unittests src/lib.rs (/tmp/miri-target/miri/x86_64-unknown-linux-gnu/debug/deps/kestrike-2d37337a438c04e5)"
        names = sweep["tests"] + declared["ignored"]
        (evidence / "list.txt").write_text(listing(names, header))
        (evidence / "ignored.txt").write_text(listing(declared["ignored"], header))
        blocks = [header]
        for seed in range(sweep["seeds"]):
            blocks += [f"Trying seed: {seed}", "", f"running {len(sweep['tests'])} tests"]
            blocks += [f"test {name} ... ok" for name in sweep["tests"]]
            blocks += ["", summary(len(sweep["tests"]), 0, 0, len(declared["ignored"])), ""]
        (evidence / "run.txt").write_text("\n".join(blocks) + "\n")
        (evidence / "exit.txt").write_text("0\n")
        (evidence / "pins.txt").write_text("- miri 0.1.0 (dc3f85158a 2026-07-26); MIRIFLAGS=-Zmiri-many-seeds=0..64\n")
        common = ["--cfg", "miri-sweep", "--list", str(evidence / "list.txt"), "--ignored", str(evidence / "ignored.txt")]
        with (evidence / "report.json").open("w") as out:
            subprocess.run([sys.executable, str(SELECT), "run", *common, "--output", str(evidence / "run.txt"), "--exit", "0"],
                           stdout=out, stderr=subprocess.DEVNULL, check=False)
        return evidence

    def test_a_completed_sweep_receipt_credits_every_kernel_over_every_seed(self):
        sweep = INVENTORY["miri_sweep"]
        evidence = self.sweep_evidence()
        code, report = self.run_script("credit", "--job", "sweep", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["executions"], len(sweep["tests"]) * sweep["seeds"])
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "sweep"])
        assumptions = self.receipt_of(evidence)["assumptions"]
        self.assertIn("SC-fence weakening evidence belongs to the RC11 lanes", assumptions)
        self.assertIn("removing the sequence bracket's Release fence went undetected over all 64 seeds", assumptions)

    def rc11_evidence(self, outputs=None):
        """Write synthetic herd7 evidence for every declared test and judge it as the lane does."""
        evidence = self.dir / "rc11"
        evidence.mkdir(exist_ok=True)
        litmus = sorted((ROOT / "verification/rc11/litmus").glob("*.litmus"))
        identity = {
            "version": "7.58, Rev: exported", "binary": {"path": "/bin/herd7", "sha256": "0" * 64},
            "libdir": "/lib/herd", "closure": dict(RC11["closure"]), "tests": {path.stem: verify.sha256(path) for path in litmus},
        }
        (evidence / "identity.json").write_text(json.dumps(identity))
        (evidence / "pins.txt").write_text("- herd7 7.58, Rev: exported; sha256 " + "0" * 64 + "\n")
        for name, declared in RC11["tests"].items():
            (evidence / f"herd-{name}.txt").write_text((outputs or {}).get(name, rc11_fixture.output(name, declared)))
            (evidence / f"herd-{name}.exit").write_text("0\n")
            argv = ["/bin/herd7", *RC11["options"], "-show", "prop", "-o", "/e/graphs", str(ROOT / "verification/rc11/litmus" / f"{name}.litmus")]
            (evidence / f"herd-{name}.argv").write_text("\n".join(argv) + "\n")
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/judge-rc11.py"), "judge", "--evidence", str(evidence), "--revision", REVISION],
            capture_output=True, text=True, check=False,
        )
        return evidence

    def rc11_credit(self, evidence):
        return self.run_script("credit", "--job", "rc11", "--receipt", str(evidence / "receipt.json"), "--evidence", str(evidence), "--revision", REVISION)

    def test_an_imported_rc11_receipt_credits_only_when_its_evidence_derives_it(self):
        evidence = self.rc11_evidence()
        code, report = self.rc11_credit(evidence)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "rc11"])
        self.assertEqual(report["executions"], len(RC11["tests"]))
        receipt = json.loads((evidence / "receipt.json").read_text())
        declared = ["verification/rc11/expected.json", *(f"verification/rc11/litmus/{name}.litmus" for name in sorted(RC11["tests"]))]
        self.assertLessEqual(set(declared), set(receipt["inputs"]))
        unbound = {name: digest for name, digest in receipt["inputs"].items() if name not in declared}
        (evidence / "receipt.json").write_text(json.dumps(dict(receipt, inputs=unbound)))
        code, report = self.rc11_credit(evidence)
        self.assertEqual(code, 1, report)
        reasons = [r["reason"] for r in report["refusals"] if r["code"] == "unbound-input"]
        self.assertEqual(reasons[-len(declared):], [f"the receipt binds no digest for {name}" for name in declared])
        (evidence / "receipt.json").write_text(json.dumps(receipt))
        (evidence / "identity.json").write_text('{"closure": {}}\n')
        code, report = self.rc11_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn("unbound-input", self.codes(report))
        never = "L1-both-fences"
        evidence = self.rc11_evidence({never: rc11_fixture.output(never, RC11["tests"][never], positive=1, verdict="Ok")})
        self.assertFalse(json.loads((evidence / "report.json").read_text())["credited"])
        forged = json.loads((evidence / "receipt.json").read_text())
        forged.update(detail=None, selection={"credited": True, "reason": None}, executions=len(RC11["tests"]), executed=sorted(RC11["tests"]))
        (evidence / "receipt.json").write_text(json.dumps(forged))
        code, report = self.rc11_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn(
            {"code": "unbound-input", "record": None, "reason": "the imported receipt differs from the receipt derived from the evidence"},
            report["refusals"],
        )

    def test_a_miri_receipt_credits_the_detector_record_only_with_its_bound_control_outcomes(self):
        """`controls.txt`, one line per inventory control with its exit and whether its diagnostic appeared, is a
        bound input of a completed miri receipt; the lane credits only when every inventory control has a line
        with a failing exit outside the interrupted codes and the diagnostic found, so evidence missing the file
        or holding a passing, timed-out or diagnostic-free control run is refused."""
        control = INVENTORY["miri"]["controls"][0]["test"]
        evidence = self.miri_evidence("miri-no-controls")
        (evidence / "controls.txt").unlink()
        code, report = self.run_script("credit", "--job", "miri", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertLessEqual({"unbound-input", "missing-result"}, set(self.codes(report)))
        self.assertIn(f"control {control} has no recorded failing run", [r["reason"] for r in report["refusals"]])
        for name, line in (("passed", f"{control}\t0\tfound"), ("timed-out", f"{control}\t124\tfound"),
                           ("quiet", f"{control}\t1\tabsent"), ("other", f"storage::other::control\t1\tfound")):
            with self.subTest(outcome=name):
                evidence = self.miri_evidence(f"miri-control-{name}")
                (evidence / "controls.txt").write_text(line + "\n")
                code, report = self.run_script("credit", "--job", "miri", "--evidence", str(evidence), "--revision", REVISION)
                self.assertEqual(code, 1, report)
                self.assertEqual(self.codes(report), ["missing-result"], report)
                # The one line leaves every declared control without its recorded run.
                self.assertEqual([r["record"] for r in report["refusals"]], [None] * len(INVENTORY["miri"]["controls"]))
        evidence = self.miri_evidence("miri-controls-bound")
        code, report = self.run_script("credit", "--job", "miri", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        receipt = self.receipt_of(evidence)
        self.assertEqual(receipt["controls"], [{"test": c["test"], "exit": 1, "diagnostic": True}
                                               for c in INVENTORY["miri"]["controls"]])
        self.assertIn("controls.txt", receipt["inputs"])

    def test_native_evidence_that_passes_the_miri_ids_does_not_credit_the_miri_job(self):
        ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        runnable = sorted(set(module_witnesses()) | set(INVENTORY["miri"]["tests"]))
        native = self.evidence("native", runnable, ignored)
        self.assertTrue(json.loads((native / "report.json").read_text())["credited"])
        code, report = self.run_script("credit", "--job", "miri", "--evidence", str(native), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertIn("raw-selection-mismatch", self.codes(report))
        self.assertTrue(any(r["code"] == "raw-selection-mismatch" and "'cfg'" in r["reason"] for r in report["refusals"]), report)
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(native), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertFalse(any("'cfg'" in r["reason"] for r in report["refusals"] if r["code"] == "raw-selection-mismatch"), report)

    def genmc_evidence(self, outputs=None, profile="pr"):
        """Write synthetic GenMC evidence for every case of `profile` and judge it as the lane does."""
        evidence = self.dir / "genmc"
        evidence.mkdir(exist_ok=True)
        binary, library, std = self.dir / "genmc-bin/genmc", self.dir / "genmc-lib/libLLVM.so.22.1", self.dir / "genmc-std"
        for path, text in ((binary, "genmc\n"), (library, "libLLVM\n"), (std / "src/lib.rs", "pub use std::*;\n")):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
        sysroot = self.dir / "rust/toolchains/nightly-2026-07-27-x86_64-unknown-linux-gnu"
        rustc = genmc_fixture.write_rustc(sysroot)
        identity = {
            "upstream": GENMC["upstream"], "llvm": GENMC["llvm"], "clang": "clang version 22.1.8",
            "rustc": dict(GENMC["rustc"], name="nightly-2026-07-27", toolchain=str(sysroot), sha256=verify.sha256(rustc)),
            "cxx": "g++ (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7)",
            "patches": {path.name: verify.sha256(path) for path in sorted((ROOT / "verification/genmc/patches").glob("*.patch"))},
            "recipe": verify.sha256(ROOT / "verification/genmc/provision.sh"),
            "binary": {"path": str(binary), "sha256": verify.sha256(binary)},
            "libllvm": {"path": str(library), "sha256": verify.sha256(library)},
            "genmc_std": {"path": str(std), "tree": genmc_fixture.tree(std)},
        }
        (evidence / "identity.json").write_text(json.dumps(identity))
        (evidence / "pins.txt").write_text(f"- GenMC {GENMC['upstream']}; genmc sha256 {verify.sha256(binary)}\n")
        (evidence / "cargo-config.json").write_text("{}\n")
        for name in genmc_fixture.profile(profile):
            declared = GENMC["cases"][name]
            positive = declared["expect"] == "positive"
            default = genmc_fixture.positive() if positive else genmc_fixture.violation(case=name)
            (evidence / f"genmc-{name}.txt").write_text((outputs or {}).get(name, default))
            (evidence / f"genmc-{name}.exit").write_text("0\n" if positive else "42\n")
            argv = [str(binary), *GENMC["options"], f"--dump-error-graph={evidence / f'genmc-{name}.dot'}",
                    str(ROOT / Path(GENMC["package"]).parent / f"run-{name}" / "Cargo.toml")]
            (evidence / f"genmc-{name}.argv").write_text("\n".join(argv) + "\n")
            (evidence / f"genmc-{name}.env").write_text(
                f"CASE={name}\nRUSTUP_TOOLCHAIN=nightly-2026-07-27\nRUSTC={identity['rustc']['toolchain']}/bin/rustc\n"
                "RUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n"
            )
            if "intrinsics" in declared:
                (evidence / f"genmc-{name}.intrinsics").write_text("\n".join(declared["intrinsics"]) + "\n")
            if not positive:
                (evidence / f"genmc-{name}.dot").write_text(genmc_fixture.graph_of((evidence / f"genmc-{name}.txt").read_text()))
        stub = self.dir / "genmc-bin/ldd"
        stub.write_text("#!/usr/bin/env bash\nprintf '\\tlibLLVM.so.22.1 => %s (0x00007f00)\\n' \"$STUB_LDD_LIBLLVM\"\n")
        stub.chmod(0o755)
        self.genmc_env = dict(os.environ, PATH=f"{stub.parent}:{os.environ['PATH']}", STUB_LDD_LIBLLVM=str(library))
        subprocess.run(
            [sys.executable, str(ROOT / "scripts/judge-genmc.py"), "judge", "--profile", profile, "--evidence", str(evidence), "--revision", REVISION],
            capture_output=True, text=True, check=False, env=self.genmc_env,
        )
        return evidence

    def genmc_credit(self, evidence, profile="pr", receipt="receipt.json"):
        return self.run_script("credit", "--job", "genmc", "--module", profile, "--receipt", str(evidence / receipt), "--evidence", str(evidence),
                               "--revision", REVISION, env=self.genmc_env)

    def test_an_imported_genmc_receipt_credits_only_when_its_evidence_derives_it(self):
        evidence = self.genmc_evidence()
        code, report = self.genmc_credit(evidence)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(report["obligations"], [r["id"] for r in CATALOG["records"] if r["job"] == "genmc" and r["module"] == "pr"])
        self.assertEqual(report["executions"], sum(3 if GENMC["cases"][name]["expect"] == "positive" else 1 for name in GENMC["profiles"]["pr"]))
        receipt = json.loads((evidence / "receipt.json").read_text())
        relabelled = dict(receipt, module="scheduled", lane="genmc scheduled", replay="bash scripts/rust-lane.sh genmc scheduled")
        (evidence / "relabelled.json").write_text(json.dumps(relabelled))
        code, report = self.genmc_credit(evidence, "scheduled", "relabelled.json")
        self.assertEqual(code, 1, report)
        self.assertIn("the imported receipt differs from the receipt derived from the evidence", json.dumps(report))
        swapped = json.loads((evidence / "report.json").read_text())
        (evidence / "report.json").write_text(json.dumps(dict(swapped, profile="scheduled")))
        (evidence / "swapped.json").write_text(json.dumps(dict(receipt, inputs=dict(receipt["inputs"], **{"report.json": verify.sha256(evidence / "report.json")}))))
        code, report = self.genmc_credit(evidence, receipt="swapped.json")
        self.assertEqual(code, 1, report)
        self.assertIn("report.json differs from the report derived from the evidence", json.dumps(report))
        (evidence / "report.json").write_text(json.dumps(swapped, indent=2, sort_keys=True) + "\n")
        refusals = self.admit(lambda c: next(r for r in c["records"] if r["job"] == "genmc" and r["module"] == "pr")["tests"].append("grace2-seq"))
        self.assertEqual([r["code"] for r in refusals], ["nonexistent-test"])
        receipt = json.loads((evidence / "receipt.json").read_text())
        package = ROOT / GENMC["package"]
        declared = list(dict.fromkeys([
            "verification/genmc/expected.json", "verification/genmc/provision.sh",
            *sorted(str(p.relative_to(ROOT)) for p in (ROOT / "verification/genmc/patches").glob("*.patch")),
            *sorted(str(p.relative_to(ROOT)) for p in package.rglob("*") if p.is_file() and "target" not in p.relative_to(package).parts),
            "crates/kestrike/src/index/sequence.rs",
            *(f"crates/kestrike/src/storage/{module}.rs" for module in ("credit", "fill", "grace", "row", "word")),
            *GENMC["transcribed"],
        ]))
        self.assertIn("verification/genmc/packages/kernels/src/qualification.rs", declared)
        self.assertIn("crates/kestrike/src/index/sequence.rs", declared)
        self.assertLessEqual(set(declared), set(receipt["inputs"]))
        unbound = {name: digest for name, digest in receipt["inputs"].items() if name not in declared}
        (evidence / "receipt.json").write_text(json.dumps(dict(receipt, inputs=unbound)))
        code, report = self.genmc_credit(evidence)
        self.assertEqual(code, 1, report)
        reasons = [r["reason"] for r in report["refusals"] if r["code"] == "unbound-input"]
        self.assertEqual(reasons[-len(declared):], [f"the receipt binds no digest for {name}" for name in declared])
        stale = dict(receipt, inputs=dict(receipt["inputs"], **{"crates/kestrike/src/storage/grace.rs": "0" * 64}))
        (evidence / "receipt.json").write_text(json.dumps(stale))
        code, report = self.genmc_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn("crates/kestrike/src/storage/grace.rs changed since the receipt or is missing",
                      [r["reason"] for r in report["refusals"]])
        stale = dict(receipt, inputs=dict(receipt["inputs"], **{"crates/kestrike/src/index/sequence.rs": "0" * 64}))
        (evidence / "receipt.json").write_text(json.dumps(stale))
        code, report = self.genmc_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn("crates/kestrike/src/index/sequence.rs changed since the receipt or is missing",
                      [r["reason"] for r in report["refusals"]])
        (evidence / "receipt.json").write_text(json.dumps(receipt))
        (evidence / "identity.json").write_text('{"binary": {}}\n')
        code, report = self.genmc_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn("unbound-input", self.codes(report))
        evidence = self.genmc_evidence({"sb_relaxed": genmc_fixture.positive()})
        self.assertFalse(json.loads((evidence / "report.json").read_text())["credited"])
        forged = json.loads((evidence / "receipt.json").read_text())
        forged.update(detail=None, selection={"credited": True, "reason": None}, executions=1, executed=GENMC["profiles"]["pr"])
        (evidence / "receipt.json").write_text(json.dumps(forged))
        code, report = self.genmc_credit(evidence)
        self.assertEqual(code, 1, report)
        self.assertIn(
            {"code": "unbound-input", "record": None, "reason": "the imported receipt differs from the receipt derived from the evidence"},
            report["refusals"],
        )

    def test_a_kani_receipt_binds_the_root_manifest_as_a_repository_input(self):
        self.assertIn("Cargo.lock", verify.LANE_EVIDENCE["kani"], "a completed Kani receipt must bind the lock file its build resolved")
        inputs = verify.checker_inputs("kani")
        for name in ("Cargo.toml", "crates/kestrike/src/storage/layout.rs", "crates/spdk-sys/src/lib.rs",
                     "verification/verus/expected.json", "verification/verus/inventory.json"):
            self.assertIn(ROOT / name, inputs)
        receipt = {"job": "kani", "module": "pr", "revision": REVISION, "completion": "completed",
                   "inputs": {"Cargo.toml": verify.sha256(ROOT / "Cargo.toml")}, "selection": {"credited": True}}
        def reasons():
            return [r["reason"] for r in verify.credit(CATALOG, receipt, "kani", "pr", REVISION, str(self.dir), INVENTORY)[1]]
        self.assertNotIn("Cargo.toml changed since the receipt or is missing", reasons())
        receipt["inputs"]["Cargo.toml"] = "0" * 64
        self.assertIn("Cargo.toml changed since the receipt or is missing", reasons())

    def test_a_kani_receipt_that_lacks_one_batchs_digest_reads_as_an_unbound_input(self):
        """A completed Kani receipt binds the run record and every file of every declared batch; one batch's output
        left unbound refuses the receipt as an unbound input."""
        judge = verify.load_script("judge_kani", ROOT / "scripts/judge-kani.py")
        expected = judge.declaration()
        files = judge.evidence_files(expected, "scheduled")
        self.assertGreater(len(judge.batches(expected, "scheduled")), 1)
        self.assertEqual(set(verify.lane_evidence("kani", "scheduled")), {*verify.LANE_EVIDENCE["kani"], *files})
        self.assertEqual(set(verify.lane_evidence("kani", "pr")), {*verify.LANE_EVIDENCE["kani"], *judge.evidence_files(expected, "pr")})
        for name in files:
            (self.dir / name).write_text(f"{name}\n")
        receipt = {"job": "kani", "module": "scheduled", "revision": REVISION, "completion": "completed",
                   "inputs": {name: verify.sha256(self.dir / name) for name in files}, "selection": {"credited": True}}

        def reasons():
            return [r["reason"] for r in verify.credit(CATALOG, receipt, "kani", "scheduled", REVISION, str(self.dir), INVENTORY)[1]
                    if r["code"] == "unbound-input"]
        self.assertFalse([reason for reason in reasons() if any(name in reason for name in files)], reasons())
        del receipt["inputs"]["kani-2.txt"]
        self.assertIn("the receipt binds no digest for kani-2.txt", reasons())

    def test_an_imported_kani_receipt_of_several_batches_credits_only_when_every_batch_derives_it(self):
        """The workflow's import path: a judged scheduled run of several batches credits the pr and scheduled records,
        and a credited receipt kept over a later batch that fails, its record's digests rewritten to match, is refused
        as differing from the receipt the evidence derives."""
        fixture = load("kani_judge_fixture", ROOT / "scripts/test-judge-kani.py")
        case = fixture.JudgeKani("test_complete_runs_credit_the_profile")
        case.setUp()
        self.addCleanup(case.temp.cleanup)
        case.identify()
        case.write_runs("scheduled")
        case.write_record("scheduled", revision=REVISION)
        evidence = case.evidence

        def judged():
            return subprocess.run([sys.executable, str(ROOT / "scripts/judge-kani.py"), "judge", "--profile", "scheduled", "--evidence",
                                   str(evidence), "--revision", REVISION], capture_output=True, text=True, check=False).returncode
        self.assertEqual(judged(), 0)
        code, report = self.run_script("credit", "--job", "kani", "--module", "scheduled", "--receipt", str(evidence / "receipt.json"),
                                       "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        kani = {r["id"] for r in CATALOG["records"] if r["job"] == "kani"}
        self.assertEqual(set(report["obligations"]), kani)
        credited = (evidence / "receipt.json").read_text()
        planned = fixture.judge_kani.batches(fixture.EXPECTED, "scheduled")
        last = len(planned)
        name = planned[-1][0]
        failing = [line.replace(" ** 0 of", " ** 1 of", 1).replace("SUCCESSFUL", "FAILED") for line in fixture.verified(name)]
        (evidence / f"kani-{last}.txt").write_text(fixture.run_text(planned[-1], {name: failing}))
        case.write_record("scheduled", revision=REVISION)
        self.assertEqual(judged(), 1)
        (evidence / "forged.json").write_text(credited)
        code, report = self.run_script("credit", "--job", "kani", "--module", "scheduled", "--receipt", str(evidence / "forged.json"),
                                       "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertIn({"code": "unbound-input", "record": None, "reason": "the imported receipt differs from the receipt derived from the evidence"},
                      report["refusals"])

    def test_a_quint_receipt_binds_the_sources_its_replays_compile(self):
        inputs = verify.checker_inputs("quint")
        for name in ("quint/keyops.qnt", "Cargo.toml", "crates/kestrike/src/storage/publish.rs",
                     "crates/kestrike/src/sim/round.rs", "crates/spdk-sys/src/lib.rs"):
            self.assertIn(ROOT / name, inputs)
        source = "crates/kestrike/src/storage/publish.rs"
        receipt = {"job": "quint", "module": None, "revision": REVISION, "completion": "completed", "inputs": {},
                   "selection": {"credited": True}}
        def reasons():
            return [r["reason"] for r in verify.credit(CATALOG, receipt, "quint", None, REVISION, str(self.dir), INVENTORY)[1]]
        self.assertIn(f"the receipt binds no digest for {source}", reasons())
        receipt["inputs"][source] = verify.sha256(ROOT / source)
        self.assertNotIn(f"{source} changed since the receipt or is missing", reasons())
        receipt["inputs"][source] = "0" * 64
        self.assertIn(f"{source} changed since the receipt or is missing", reasons())

    def test_a_scheduled_kani_receipt_credits_the_pr_records_and_a_pr_receipt_its_own(self):
        self.assertEqual(verify.credited_modules("kani", "scheduled"), {"pr", "scheduled"})
        self.assertEqual(verify.credited_modules("kani", "pr"), {"pr"})
        self.assertEqual(verify.credited_modules("verus", None), {None})

    def test_a_scheduled_tlc_receipt_credits_the_pr_records_and_a_pr_receipt_its_own(self):
        self.assertEqual(verify.credited_modules("tlc", "scheduled"), {"scheduled"})
        self.assertEqual(verify.credited_modules("tlc", "pr"), {"pr"})

    def test_a_scheduled_genmc_receipt_credits_every_record_its_run_judges(self):
        evidence = self.genmc_evidence(profile="scheduled")
        code, report = self.genmc_credit(evidence, "scheduled")
        self.assertEqual((code, report["refusals"]), (0, []), report)
        genmc = [r for r in CATALOG["records"] if r["job"] == "genmc"]
        self.assertEqual({r["module"] for r in genmc}, {"pr", "scheduled"})
        self.assertEqual(report["obligations"], [r["id"] for r in genmc])
        receipt = json.loads((evidence / "receipt.json").read_text())
        record = next(r for r in genmc if r["module"] == "pr" and r["tests"])
        missing = dict(receipt, executed=[name for name in receipt["executed"] if name != record["tests"][0]])
        records, refusals = verify.credit(CATALOG, missing, "genmc", "scheduled", REVISION, evidence, INVENTORY)
        self.assertEqual([r["id"] for r in records], [r["id"] for r in genmc])
        self.assertIn({"code": "missing-result", "record": record["id"], "reason": f"{record['tests'][0]} has no ok outcome"}, refusals)

    def test_a_receipt_without_the_binary_scan_leaves_the_chaos_record_uncredited(self):
        evidence = self.workspace_evidence()
        scan = "chaos::no_binary_holds_a_chaos_point"
        record = "chaos-points-are-cataloged-seeded-and-absent-outside-test-builds"
        executed = [name for target in WORKSPACE_TARGETS for name in module_witnesses(target)]
        self.assertIn(scan, executed)
        result, report = self.credit(evidence, "workspace", executed=[name for name in executed if name != scan])
        self.assertEqual(result, 1, report)
        self.assertEqual({r["record"] for r in report["refusals"] if r["code"] == "missing-result"}, {record}, report)

    def test_each_receipt_refusal_blocks_credit(self):
        evidence = self.workspace_evidence()
        control = CATALOG["records"][ORACLE_RECORD]["controls"][0]["test"]
        for changes, code in (
            ({"executed": [n for n in module_witnesses() if n != control]}, "missing-result"),
            ({"executions": 0}, "zero-executions"),
            ({"failed": [control]}, "raw-failed"),
            ({"completion": "timeout", "detail": "the run exited 124"}, "timeout"),
            ({"completion": "exhausted", "detail": "state limit"}, "exhausted"),
            ({"completion": "unsupported", "detail": "unsupported semantics"}, "unsupported"),
            ({"completion": "skipped"}, "skipped"),
            ({"completion": "tool failure", "detail": "inventory unreadable"}, "tool-failure"),
            ({"completion": "correspondence drift", "detail": "a binding moved"}, "correspondence-drift"),
            ({"completion": "violation", "violation": "another text"}, "wrong-violation"),
            ({"completion": None}, "tool-failure"),
            ({"revision": "f" * 40}, "unbound-revision"),
            ({"inputs": {"run.txt": "0" * 64}}, "unbound-input"),
            ({"selection": {"credited": False, "reason": "kestrike executed 2 of 3 runnable tests"}}, "selection-refused"),
        ):
            result, report = self.credit(evidence, "workspace", **changes)
            self.assertEqual(result, 1, (changes, report))
            self.assertIn(code, self.codes(report), (changes, report))
        result, report = self.credit(evidence, "workspace")
        self.assertEqual((result, report["refusals"]), (0, []), report)

    def main_with_catalog(self, catalog, *argv):
        """Run the script's `main` in-process against `catalog` written under the test directory; return (code, report)."""
        path = self.dir / "obligations.json"
        path.write_text(json.dumps(catalog))
        with mock.patch.object(verify, "CATALOG", path), contextlib.redirect_stdout(io.StringIO()) as stdout, \
                contextlib.redirect_stderr(io.StringIO()):
            code = verify.main(list(argv))
        try:
            return code, json.loads(stdout.getvalue())
        except ValueError:
            self.fail(f"no JSON report: {stdout.getvalue()!r}")

    def credit_with_catalog(self, catalog, evidence, *args):
        """Run `credit` in-process against `catalog` written beside the evidence; return (code, report)."""
        return self.main_with_catalog(catalog, "credit", *args, "--evidence", str(evidence), "--revision", REVISION)

    def test_admit_reports_a_malformed_record_instead_of_crashing_in_the_census(self):
        # `admit` reports every malformed record and goes on, so one run judges the three of the third catalog.
        first, unhashable = CATALOG["records"][0]["id"], [["x"], {"x": 1}]
        for edit, malformed in (
            (lambda c: c["records"][0].pop("job"), [first]),
            (lambda c: c["records"][0].pop("controls"), [first]),
            (lambda c: c["records"].extend(["not a record", *({**c["records"][0], "id": value} for value in unhashable)]),
             [len(CATALOG["records"]), *unhashable]),
        ):
            catalog = copy.deepcopy(CATALOG)
            edit(catalog)
            code, report = self.main_with_catalog(catalog, "admit")
            self.assertEqual((code, report.get("crash")), (1, None), report)
            self.assertEqual([r["record"] for r in report["refusals"] if r["code"] == "malformed-record"], malformed, report)

    def admit_with_list(self, catalog, listed):
        """Run `admit` in-process against `catalog` and a scratch control-less list of `listed`; return (code, report)."""
        path = self.dir / "control-less.json"
        path.write_text(json.dumps(sorted(listed)))
        with mock.patch.object(verify, "CONTROL_LESS", path):
            return self.main_with_catalog(catalog, "admit")

    def control_less_twin(self, name, **changes):
        """Return a copy of the committed catalog's first record that names a test, under the id `name`, without its
        controls or `no_control` reason and with `changes` applied."""
        template = copy.deepcopy(next(record for record in CATALOG["records"] if record["tests"]))
        template.pop("no_control", None)
        return {**template, "id": name, "controls": [], **changes}

    def test_a_control_less_twin_needs_no_entry_on_the_list(self):
        path = self.dir / "control-less.json"
        path.write_text("[]\n")
        with mock.patch.object(verify, "CONTROL_LESS", path):
            twin = self.control_less_twin("a-fresh-record")
        self.assertIsNone(verify.check_shape(twin))
        self.assertEqual((twin["id"], twin["controls"], "no_control" in twin), ("a-fresh-record", [], False))

    def test_admit_admits_a_new_control_less_record_whose_no_control_states_a_reason(self):
        listed = json.loads(verify.CONTROL_LESS.read_text())
        reasoned = self.control_less_twin("a-fresh-record-with-a-reason", no_control="its property has no violating input")
        self.assertIsNone(verify.check_shape(reasoned))
        code, report = self.admit_with_list({**CATALOG, "records": [*CATALOG["records"], reasoned]}, listed)
        self.assertEqual((code, report["refusals"], report["records"], report["control_less"]),
                         (0, [], len(CATALOG["records"]) + 1, len(listed)), report)

    def test_admit_gives_a_malformed_record_only_its_own_refusal_on_or_off_the_list(self):
        listed = json.loads(verify.CONTROL_LESS.read_text())
        malformed = self.control_less_twin("a-fresh-malformed-record")
        del malformed["transition"]
        bare = self.control_less_twin("a-fresh-record-without-a-reason")
        for entries in (listed, [*listed, malformed["id"]]):
            with self.subTest(listed=malformed["id"] in entries):
                code, report = self.admit_with_list({**CATALOG, "records": [*CATALOG["records"], malformed, bare]}, entries)
                self.assertEqual((code, report.get("crash")), (verify.REFUSED, None), report)
                self.assertEqual(sorted((r["code"], r["record"]) for r in report["refusals"]),
                                 [("control-ratchet", bare["id"]), ("malformed-record", malformed["id"])], report)

    def test_credit_refuses_an_inadmissible_catalog(self):
        evidence = self.workspace_evidence()
        catalog = copy.deepcopy(CATALOG)
        catalog["records"].append(copy.deepcopy(catalog["records"][0]))
        catalog["records"][1]["reference"] = " "
        code, report = self.credit_with_catalog(catalog, evidence, "--job", "workspace")
        self.assertEqual(code, 1, report)
        self.assertEqual(self.codes(report), ["duplicate-record", "missing-reference"])
        self.assertEqual(json.loads((evidence / "credit.json").read_text())["refusals"], report["refusals"])
        malformed = copy.deepcopy(CATALOG)
        malformed["records"].append("not a record")
        (evidence / "credit.json").unlink()
        code, report = self.credit_with_catalog(malformed, evidence, "--job", "workspace")
        self.assertEqual((code, self.codes(report), report["obligations"]), (1, ["malformed-record"], []), report)
        self.assertEqual(json.loads((evidence / "credit.json").read_text())["refusals"], report["refusals"])

    def test_credit_refuses_a_catalog_the_census_refuses(self):
        """A census refusal is an admission refusal at credit too, so a lane run outside the gate's dependency
        order credits nothing against a census with a dangling check."""
        evidence = self.workspace_evidence()
        catalog = copy.deepcopy(CATALOG)
        catalog["records"] = [r for r in catalog["records"] if r["id"] != "mc-gate-contention"]
        code, report = self.credit_with_catalog(catalog, evidence, "--job", "workspace")
        self.assertEqual((code, self.codes(report), report["obligations"]), (1, ["census"], []), report)
        self.assertIn("dangling-check", report["refusals"][0]["reason"])

    def test_a_lane_no_record_names_is_refused_at_credit(self):
        evidence = self.workspace_evidence()
        code, report = self.run_script("credit", "--job", "workspacex", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["obligations"]), (1, []), report)
        self.assertIn("uncovered-lane", self.codes(report))
        loom = self.loom_evidence("credit_model")
        code, report = self.run_script("credit", "--job", "loom", "--module", "no_such_model", "--evidence", str(loom), "--revision", REVISION)
        self.assertEqual((code, report["obligations"]), (1, []), report)
        self.assertIn("uncovered-lane", self.codes(report))

    def tag_compare_evidence(self, name, decision, control, built=REVISION, callers_ran=True):
        """A tag comparison lane's evidence over two recorded AArch64 extents, built at `built` and judged at
        `REVISION` into its report and receipt, with the declared callers' run recorded when `callers_ran`."""
        evidence = self.dir / name
        evidence.mkdir()
        fixtures = ROOT / "verification/tag-compare/fixtures"
        # The unfolded extent comes from a reproduction crate; its callees take the declared callers' names.
        sites = {site: {"address": "0x0", "size": 4, "disassembly": (fixtures / f"{listing}.txt").read_text()
                        .replace("tcx::", "kestrike::net::tag_compare_tests::")}
                 for site, listing in (("tag-decision", decision), ("early-return-control", control))}
        (evidence / "extents.json").write_text(json.dumps({"machine": "aarch64", "sha256": "d" * 64, "sites": sites}))
        (evidence / "identity.json").write_text(json.dumps({
            "revision": built, "ci": {"GITHUB_RUN_ID": "7"}, "executable": "kestrike", "sha256": "d" * 64,
            "profile": "release", "cargo_profile": {"opt_level": "3", "debug_assertions": False}, "lto": "false",
            "profile_env": {"CARGO_PROFILE_RELEASE_LTO": "false"}, "rustflags": "-C symbol-mangling-version=v0",
            "target_features": ["neon"], "native_build": ["- pin"]}))
        (evidence / "pins.txt").write_text("- pin\n")
        if callers_ran:
            callers = read_json(verify.CHECKER_JOBS["tag-compare-aarch64"])["callers"]
            (evidence / "callers.txt").write_text("".join(f"test {name} ... ok\n" for name in callers)
                                                  + f"\ntest result: ok. {len(callers)} passed; 0 failed; 0 ignored; 0 measured\n")
            (evidence / "exit.txt").write_text("0\n")
        subprocess.run([sys.executable, str(ROOT / "scripts/scan-tag-compare.py"), "judge", "--evidence", str(evidence),
                        "--revision", REVISION], capture_output=True, check=False)
        return evidence

    def test_a_tag_compare_receipt_credits_its_own_architecture_only_with_the_control_flagged(self):
        evidence = self.tag_compare_evidence("tag", "aarch64-decision", "aarch64-early-return")
        credit = ("credit", "--receipt", str(evidence / "receipt.json"), "--evidence", str(evidence), "--revision", REVISION)
        code, report = self.run_script(*credit, "--job", "tag-compare-aarch64")
        self.assertEqual((code, report["obligations"], report["refusals"]), (0, ["tag-compare-control-flow-aarch64"], []))
        code, report = self.run_script(*credit, "--job", "tag-compare-x86-64")
        self.assertEqual(code, 1)
        self.assertIn("unbound-lane", self.codes(report))
        unflagged = self.tag_compare_evidence("unflagged", "aarch64-decision", "aarch64-decision")
        code, report = self.run_script("credit", "--receipt", str(unflagged / "receipt.json"), "--evidence", str(unflagged),
                                       "--revision", REVISION, "--job", "tag-compare-aarch64")
        self.assertEqual(code, 1)
        self.assertIn("selection-refused", self.codes(report))
        unfolded = self.tag_compare_evidence("unfolded", "aarch64-unfolded", "aarch64-early-return")
        code, report = self.run_script("credit", "--receipt", str(unfolded / "receipt.json"), "--evidence", str(unfolded),
                                       "--revision", REVISION, "--job", "tag-compare-aarch64")
        self.assertEqual(code, 1)
        self.assertIn("selection-refused", self.codes(report))
        stale = self.tag_compare_evidence("stale", "aarch64-decision", "aarch64-early-return", built="0" * 40)
        code, report = self.run_script("credit", "--receipt", str(stale / "receipt.json"), "--evidence", str(stale),
                                       "--revision", REVISION, "--job", "tag-compare-aarch64")
        self.assertEqual((code, report["obligations"]), (1, ["tag-compare-control-flow-aarch64"]))
        self.assertIn("tool-failure", self.codes(report))
        unrun = self.tag_compare_evidence("unrun", "aarch64-decision", "aarch64-early-return", callers_ran=False)
        code, report = self.run_script("credit", "--receipt", str(unrun / "receipt.json"), "--evidence", str(unrun),
                                       "--revision", REVISION, "--job", "tag-compare-aarch64")
        self.assertEqual(code, 1)
        self.assertIn("tool-failure", self.codes(report))
        self.assertIn("no recorded callers' run", json.dumps(report["refusals"]))

    def test_an_empty_catalog_or_a_lane_without_records_is_refused(self):
        refusals = self.admit(lambda c: c.update(records=[]))
        self.assertEqual({r["code"] for r in refusals}, {"uncovered-lane"})
        uncovered = {r["record"] for r in refusals}
        self.assertEqual(uncovered, {"workspace", "campaigns", "search", "fuzz-smoke", "search-nightly", "long-run", "miri", "sweep", "rc11", "verus", "genmc pr", "genmc scheduled", "kani pr", "kani scheduled", "tlc pr", "quint", "fuzz", "isa-x86-64", "isa-aarch64", *verify.TAG_COMPARE, *(f"loom {module}" for module in INVENTORY["loom"])})
        refusals = self.admit(lambda c: c["records"].__delitem__(slice(0, len(c["records"]), 1)) or c["records"].extend(r for r in CATALOG["records"] if r["job"] != "fuzz"))
        self.assertEqual([(r["code"], r["record"]) for r in refusals], [("uncovered-lane", "fuzz")])
        refusals = self.admit(lambda c: c["records"].__delitem__(slice(0, len(c["records"]), 1)) or c["records"].extend(r for r in CATALOG["records"] if r.get("module") != "grace_model"))
        self.assertEqual([(r["code"], r["record"]) for r in refusals], [("uncovered-lane", "loom grace_model")])
        evidence = self.workspace_evidence()
        code, report = self.credit_with_catalog({"baseline": CATALOG["baseline"], "records": []}, evidence, "--job", "workspace")
        self.assertEqual((code, report["obligations"]), (1, []), report)
        self.assertIn("uncovered-lane", self.codes(report))

    def test_the_self_checks_leave_the_step_summary_alone(self):
        summary = self.dir / "summary.md"
        result = subprocess.run(
            [sys.executable, __file__, "VerifyReceipts.test_a_completed_positive_receipt_credits_every_workspace_record"],
            capture_output=True, text=True, check=False, env=dict(os.environ, GITHUB_STEP_SUMMARY=str(summary)),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(summary.exists(), summary.read_text() if summary.exists() else "")

    def test_read_only_credit_judges_an_imported_receipt_and_writes_nothing(self):
        evidence = self.workspace_evidence()
        code, _ = self.run_script("receipt", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 0)
        before = sorted(p.name for p in evidence.iterdir())
        summary = self.dir / "summary.md"
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(evidence), "--revision",
                                       REVISION, "--receipt", str(evidence / "receipt.json"), "--read-only",
                                       env=dict(os.environ, GITHUB_STEP_SUMMARY=str(summary)))
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertEqual(set(report["obligations"]), {r["id"] for r in CATALOG["records"] if r["job"] == "workspace"})
        self.assertEqual(sorted(p.name for p in evidence.iterdir()), before)
        self.assertNotIn("credit.json", before)
        self.assertFalse(summary.exists())
        result = subprocess.run([sys.executable, str(SCRIPT), "credit", "--job", "workspace", "--evidence",
                                 str(evidence), "--revision", REVISION, "--read-only"],
                                capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("--read-only judges an imported receipt", result.stderr)

    def test_credit_appends_its_verdict_to_the_step_summary(self):
        evidence = self.workspace_evidence()
        summary = self.dir / "summary.md"
        env = dict(os.environ, GITHUB_STEP_SUMMARY=str(summary))
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION],
            capture_output=True, text=True, check=False, env=env,
        )
        self.assertEqual(result.returncode, 0, result.stdout)
        count = len([r for r in CATALOG["records"] if r["job"] == "workspace"])
        self.assertEqual(summary.read_text(), f"- obligations for workspace: credited {count}\n")
        (evidence / "pins.txt").unlink()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION],
            capture_output=True, text=True, check=False, env=env,
        )
        self.assertEqual(result.returncode, 1, result.stdout)
        self.assertEqual(summary.read_text().splitlines()[-1], f"- obligations for workspace: refused missing-provenance unbound-input; {count} judged")

    def test_a_receipt_without_tool_provenance_is_refused(self):
        evidence = self.workspace_evidence()
        for tool in ({"name": "cargo test", "provenance": []}, {"name": "cargo test"}, None):
            result, report = self.credit(evidence, "workspace", tool=tool)
            self.assertEqual(result, 1, (tool, report))
            self.assertEqual(self.codes(report), ["missing-provenance", "unbound-input"], (tool, report))
        result, report = self.credit(evidence, "workspace", tool={"name": "cargo test", "provenance": ["- rustc 1.98.0 (claimed, unpinned)"]})
        self.assertEqual((result, self.codes(report)), (1, ["missing-provenance", "unbound-input"]), report)
        (evidence / "pins.txt").unlink()
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, sorted(set(self.codes(report)))), (1, ["missing-provenance", "unbound-input"]), report)
        self.assertEqual(self.receipt_of(evidence)["tool"]["provenance"], [])

    def test_a_receipt_that_omits_an_input_digest_is_refused(self):
        evidence = self.workspace_evidence()
        code, report = self.run_script("receipt", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 0, report)
        bound = self.receipt_of(evidence)["inputs"]
        for dropped in (set(bound), {"verification/obligations.json"}, {"scripts/test-registry.json"}, {"run.txt"}, {"report.json"}, {"pins.txt"}):
            result, report = self.credit(evidence, "workspace", inputs={k: v for k, v in bound.items() if k not in dropped})
            self.assertEqual(result, 1, (dropped, report))
            self.assertIn("unbound-input", self.codes(report), (dropped, report))
        fuzz = self.dir / "fuzz"
        fuzz.mkdir()
        (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
        code, report = self.run_script("receipt", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual(code, 0, report)
        receipt = self.receipt_of(fuzz)
        for edit in (lambda r: r.pop("inputs"), lambda r: r["inputs"].pop("fuzz.json")):
            judged = copy.deepcopy(receipt)
            edit(judged)
            (fuzz / "judged.json").write_text(json.dumps(judged))
            code, report = self.run_script(
                "credit", "--job", "fuzz", "--evidence", str(self.dir / "elsewhere"), "--revision", REVISION, "--receipt", str(fuzz / "judged.json"),
            )
            self.assertEqual(code, 1, report)
            self.assertIn("unbound-input", self.codes(report), report)
            self.assertEqual(report["obligations"], ["frame-parse-never-panics-and-reencodes"])

    def test_an_imported_cargo_receipt_is_rederived_from_its_evidence(self):
        evidence = self.workspace_evidence()
        code, report = self.run_script("receipt", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 0, report)
        claimed = self.receipt_of(evidence)
        (evidence / "run.txt").write_text("not cargo output\n")
        (evidence / "report.json").write_text('{"code": 4, "credited": false, "reason": "kestrike failed 1 tests", "targets": {}}')
        claimed["inputs"]["run.txt"] = verify.sha256(evidence / "run.txt")
        claimed["inputs"]["report.json"] = verify.sha256(evidence / "report.json")
        path = evidence / "claimed.json"
        path.write_text(json.dumps(claimed))
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION, "--receipt", str(path))
        self.assertEqual(code, 1, report)
        self.assertIn("unbound-input", self.codes(report))
        self.assertTrue(any("differs from the receipt derived" in r["reason"] for r in report["refusals"]), report)
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual(code, 1, report)
        self.assertIn("selection-refused", self.codes(report))
        honest = self.workspace_evidence("honest")
        code, report = self.run_script("receipt", "--job", "workspace", "--evidence", str(honest), "--revision", REVISION)
        self.assertEqual(code, 0, report)
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(honest), "--revision", REVISION, "--receipt", str(honest / "receipt.json"))
        self.assertEqual((code, report["refusals"]), (0, []), report)

    def test_a_receipt_judged_under_another_lane_is_refused(self):
        workspace = self.workspace_evidence()
        loom = self.loom_evidence("credit_model")
        for evidence, args in ((workspace, ["--job", "workspace"]), (loom, ["--job", "loom", "--module", "credit_model"])):
            code, report = self.run_script("receipt", *args, "--evidence", str(evidence), "--revision", REVISION)
            self.assertEqual(code, 0, report)
        for evidence, args in (
            (workspace, ["--job", "fuzz"]),
            (workspace, ["--job", "loom", "--module", "credit_model"]),
            (loom, ["--job", "loom", "--module", "grace_model"]),
            (loom, ["--job", "workspace"]),
        ):
            code, report = self.run_script(
                "credit", *args, "--evidence", str(evidence), "--revision", REVISION, "--receipt", str(evidence / "receipt.json"),
            )
            self.assertEqual(code, 1, (args, report))
            self.assertIn("unbound-lane", self.codes(report), (args, report))
        code, report = self.run_script(
            "credit", "--job", "loom", "--module", "credit_model", "--evidence", str(loom), "--revision", REVISION, "--receipt", str(loom / "receipt.json"),
        )
        self.assertEqual((code, report["refusals"]), (0, []), report)

    def test_a_timeout_a_skip_a_tool_failure_and_a_raw_failed_line_refuse_from_the_evidence(self):
        control = CATALOG["records"][ORACLE_RECORD]["controls"][0]["test"]
        timed_out = self.workspace_evidence("timeout", exit_code=124)
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(timed_out), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        self.assertIn("timeout", self.codes(report))
        cancelled = self.workspace_evidence("cancelled", extra_output="##[error]The operation was canceled.\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(cancelled), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        skipped = self.dir / "skipped"
        skipped.mkdir()
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(skipped), "--revision", REVISION)
        self.assertEqual((code, report["completion"], self.codes(report)), (1, "skipped", ["missing-provenance", "missing-result", "skipped", "zero-executions"]), report)
        failed_setup = self.dir / "setup"
        failed_setup.mkdir()
        (failed_setup / "failure.txt").write_text("check failed; see check.txt in the evidence\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(failed_setup), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        self.assertIn("tool-failure", self.codes(report))
        self.assertIn("failure.txt", self.receipt_of(failed_setup)["inputs"])
        (failed_setup / "failure.txt").write_text("another failure\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(failed_setup), "--revision", REVISION, "--receipt", str(failed_setup / "receipt.json"))
        self.assertIn("unbound-input", self.codes(report))
        (failed_setup / "exit.txt").write_text("124\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(failed_setup), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        self.assertEqual(self.receipt_of(failed_setup)["detail"], "another failure")
        summary_failed = self.workspace_evidence("summary-failed")
        (summary_failed / "failure.txt").write_text("rust-lane.sh failed at line 300: python3 - ...\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(summary_failed), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        self.assertEqual(self.codes(report), ["tool-failure"])
        self.assertIn("line 300", self.receipt_of(summary_failed)["detail"])
        failing = self.workspace_evidence("failed", failed=(control,), exit_code=101)
        (failing / "failure.txt").write_text("rust-lane.sh failed at line 146: python3 scripts/select-tests.py run --cfg ordinary\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(failing), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "completed"), report)
        self.assertLessEqual({"raw-failed", "selection-refused"}, set(self.codes(report)))
        self.assertNotIn("tool-failure", self.codes(report))
        self.assertIn("failed 1 tests", next(r["reason"] for r in report["refusals"] if r["code"] == "selection-refused"))
        unreadable = self.workspace_evidence("unreadable")
        (unreadable / "report.json").write_text('{"code": 2, "credited": false, "reason": "unreadable inventory", "targets": {}}')
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(unreadable), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        self.assertNotIn("missing-result", self.codes(report))
        malformed = self.workspace_evidence("malformed")
        (malformed / "run.txt").write_text(f"{HEADER}\ntest result: ok. 2 passed; 0 failed\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(malformed), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        killed = self.workspace_evidence("killed-malformed", exit_code=124)
        (killed / "run.txt").write_text(f"{HEADER}\ntest result: ok. 2 passed; 0 failed\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(killed), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        (killed / "exit.txt").unlink()
        (killed / "report.json").unlink()
        (killed / "run.txt").write_text(f"{HEADER}\ntest a::b ... ok\n##[error]The operation was canceled.\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(killed), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        unjudged = self.workspace_evidence("unjudged")
        (unjudged / "report.json").unlink()
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(unjudged), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)

    def test_an_interrupted_lane_is_a_timeout_and_a_failed_fuzz_setup_is_a_tool_failure(self):
        interrupted = self.workspace_evidence("interrupted", exit_code=143)
        (interrupted / "run.txt").write_text(f"{HEADER}\ntest a::b ... ok\n")
        (interrupted / "report.json").unlink()
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(interrupted), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        self.assertIn("timeout", self.codes(report))
        self.assertEqual(self.receipt_of(interrupted)["bounds"]["exit"], 143)
        early = self.dir / "early"
        early.mkdir()
        (early / "exit.txt").write_text("143\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(early), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        (early / "exit.txt").write_text("130\n")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(early), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)
        fuzz_setup = self.dir / "fuzz-setup"
        fuzz_setup.mkdir()
        (fuzz_setup / "failure.txt").write_text("toolchains failed; see toolchains.txt in the evidence\n")
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz_setup), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        self.assertIn("tool-failure", self.codes(report))
        (fuzz_setup / "exit.txt").write_text("143\n")
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz_setup), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "timeout"), report)

    def test_a_defect_receipt_credits_only_its_named_violation(self):
        catalog = {"baseline": CATALOG["baseline"], "records": [{
            "id": "grace-control", "property": "#8 P-E-122", "transition": "t", "invariant": "i", "job": "loom",
            "module": "grace_model", "tests": [],
            "controls": [{"test": "storage::grace_model::negative_control_an_uncharged_busy_attempt_fails", "violation": "protection violated"}],
            "reference": "r",
        }]}
        receipt = {
            "job": "loom", "module": "grace_model", "revision": REVISION, "inputs": verify.committed_inputs(),
            "tool": {"name": "loom", "provenance": ["- loom v0.7.2"]},
            "completion": "violation", "violation": "protection violated",
            "selection": {"credited": True, "cfg": "loom"}, "executions": 1, "executed": [], "failed": [],
        }
        records, refusals = verify.credit(catalog, receipt, "loom", "grace_model", REVISION, self.dir, INVENTORY)
        self.assertEqual(([r["id"] for r in records], refusals), (["grace-control"], []))
        receipt["violation"] = "a park lost its bit"
        _, refusals = verify.credit(catalog, receipt, "loom", "grace_model", REVISION, self.dir, INVENTORY)
        self.assertEqual([r["code"] for r in refusals], ["wrong-violation"])
        receipt.update(completion="tool failure", detail="the checker could not parse the model")
        _, refusals = verify.credit(catalog, receipt, "loom", "grace_model", REVISION, self.dir, INVENTORY)
        self.assertEqual([r["code"] for r in refusals], ["tool-failure", "missing-result"])
        receipt.update(completion="completed", executions=0)
        _, refusals = verify.credit(catalog, receipt, "loom", "grace_model", REVISION, self.dir, INVENTORY)
        self.assertEqual({r["code"] for r in refusals}, {"zero-executions", "missing-result", "unbound-input", "selection-refused"})
        receipt.update(completion="violation", executions=1, violation="protection violated")
        catalog["records"][0]["tests"] = ["storage::grace_model::pinned_readers_never_observe_a_released_anchor_or_a_reused_slot"]
        _, refusals = verify.credit(catalog, receipt, "loom", "grace_model", REVISION, self.dir, INVENTORY)
        self.assertEqual([r["code"] for r in refusals], ["missing-result", "wrong-violation"])

    def test_a_campaign_failure_is_a_violation_named_by_its_retained_files(self):
        """The campaign run leaves a failure's files in campaign-artifacts/; the wrong-byte control's
        intentional crash in campaign-control/ is not a violation."""
        fuzz = self.dir / "fuzz"
        (fuzz / "campaign-artifacts").mkdir(parents=True)
        (fuzz / "campaign-control").mkdir()
        (fuzz / "fuzz.json").write_text('{"seeds": 22, "runs": 184733, "seconds": 61}')
        (fuzz / "campaign-control" / "first-failure.input").write_bytes(b"planted")
        failure = "the campaign fuzz run exited 77; its first failure is in campaign-artifacts/"
        self.assertEqual(verify.fuzz_completion(fuzz, failure, 77, FUZZ_ROWS), ("tool failure", failure))
        for name in ("first-failure.input", "first-failure.claim", "crash-0f"):
            (fuzz / "campaign-artifacts" / name).write_bytes(b"x")
        self.assertEqual(
            verify.fuzz_completion(fuzz, failure, 77, FUZZ_ROWS),
            ("violation", "crash inputs ['crash-0f', 'first-failure.claim', 'first-failure.input']"),
        )
        (fuzz / "artifacts").mkdir()
        (fuzz / "artifacts" / "crash-aa").write_bytes(b"x")
        self.assertEqual(
            verify.fuzz_completion(fuzz, failure, 77, FUZZ_ROWS),
            ("violation", "crash inputs ['crash-aa', 'crash-0f', 'first-failure.claim', 'first-failure.input']"),
        )

    def test_a_slow_unit_is_a_timing_note_and_leaves_a_passing_run_completed(self):
        """libFuzzer writes an input past -report_slow_units as slow-unit-<sha> under -artifact_prefix and
        keeps running; the lane exits 0 and the receipt stays completed."""
        fuzz = self.dir / "fuzz"
        (fuzz / "campaign-artifacts").mkdir(parents=True)
        (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
        (fuzz / "campaign-artifacts" / "slow-unit-0f").write_bytes(b"x")
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("completed", None))
        (fuzz / "campaign-artifacts" / "crash-0a").write_bytes(b"x")
        self.assertEqual(verify.fuzz_completion(fuzz, None, 77, FUZZ_ROWS), ("violation", "crash inputs ['crash-0a']"))

    def test_a_fuzz_run_without_its_campaign_record_did_not_finish(self):
        """The frame run records its executions before the campaign runs, so a run that ends between
        them has runs and no campaign record; it completed nothing."""
        fuzz = self.dir / "fuzz"
        fuzz.mkdir()
        (fuzz / "fuzz.json").write_text('{"seeds": 22, "runs": 184733, "seconds": 61}')
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("tool failure", "the campaign run did not finish"))
        (fuzz / "fuzz.json").write_text(
            '{"seeds": 22, "runs": 184733, "seconds": 61, "campaign": {"seeds": 4, "runs": 5832, "seconds": 121}}'
        )
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("tool failure", "the parser runs did not finish"))
        parser = '{"seeds": 22, "runs": 40383, "seconds": 61}'
        (fuzz / "fuzz.json").write_text(
            '{"seeds": 22, "runs": 184733, "seconds": 61, "campaign": {"seeds": 4, "runs": 5832, "seconds": 121}, '
            f'"parsers": {{"record": {parser}}}}}'
        )
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("tool failure", "the parser runs did not finish"))
        (fuzz / "fuzz.json").write_text(
            '{"seeds": 22, "runs": 184733, "seconds": 61, "campaign": {"seeds": 4, "runs": 5832, "seconds": 121}, '
            f'"parsers": {{"record": {parser}, "wire": {parser}}}}}'
        )
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS),
                         ("tool failure", "unmet fuzz checkpoints: no generated input passed the oracle for campaign"
                          " | no generated input passed the oracle for record"
                          " | no generated input passed the oracle for wire"))
        (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("completed", None))

    def test_a_zero_input_fuzz_target_blocks_its_row_and_the_lane(self):
        """A target that ran its seeds and libFuzzer's empty input and nothing past them earns no credit, and
        the completion names each blocked row; the smoke lane judges its own rows."""
        fuzz = self.dir / "fuzz"
        fuzz.mkdir()
        for lane in ("fuzz", "fuzz-smoke"):
            rows = select.load_inventory(select.INVENTORY)["qualified"][lane]["rows"]
            names = {row["target"]: row["id"] for row in rows}
            for target, edit in (("frame", lambda r: r.update(runs=r["seeds"] + 1)),
                                 ("campaign", lambda r: r["campaign"].update(runs=0)),
                                 ("wire", lambda r: r["parsers"]["wire"].update(runs=r["parsers"]["wire"]["seeds"]))):
                with self.subTest(lane=lane, target=target):
                    record = copy.deepcopy(COMPLETED_FUZZ)
                    edit(record)
                    (fuzz / "fuzz.json").write_text(json.dumps(record))
                    completion, detail = verify.fuzz_completion(fuzz, None, 0, rows)
                    self.assertEqual(completion, "tool failure")
                    self.assertEqual(detail, f"blocked fuzz rows: {names[target]} ran 0 inputs past its seeds, declared at least 1")
            (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
            self.assertEqual(verify.fuzz_completion(fuzz, None, 0, rows), ("completed", None))
        record = copy.deepcopy(COMPLETED_FUZZ)
        record["campaign"]["runs"] = 0
        (fuzz / "fuzz.json").write_text(json.dumps(record))
        (fuzz / "pins.txt").write_text("- cargo-fuzz 0.13.2; host Linux\n")
        code, report = self.run_script("credit", "--job", "fuzz-smoke", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, report["completion"], self.codes(report)), (1, "tool failure", ["tool-failure"]), report)
        self.assertEqual(report["obligations"], ["fuzz-smoke-runs-every-target-past-its-seeds"])

    def test_a_worker_target_without_a_generated_pass_blocks_the_lane(self):
        """The record carries each worker target's checkpoint count, and the completion judges it itself: the
        campaign and each parser need a positive count of generated passes; a record lacking one earned no credit
        whatever its executions."""
        fuzz = self.dir / "fuzz"
        fuzz.mkdir()
        cases = (
            ("the campaign at zero", lambda r: r["campaign"].update(nonseed_pass=0), "campaign"),
            ("the campaign count missing", lambda r: r["campaign"].pop("nonseed_pass"), "campaign"),
            ("a parser at zero", lambda r: r["parsers"]["wire"].update(nonseed_pass=0), "wire"),
            ("a parser count missing", lambda r: r["parsers"]["record"].pop("nonseed_pass"), "record"),
            ("a campaign count that is true", lambda r: r["campaign"].update(nonseed_pass=True), "campaign"),
            ("a parser count that is true", lambda r: r["parsers"]["wire"].update(nonseed_pass=True), "wire"),
        )
        for name, edit, target in cases:
            with self.subTest(name):
                record = copy.deepcopy(COMPLETED_FUZZ)
                edit(record)
                (fuzz / "fuzz.json").write_text(json.dumps(record))
                self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS),
                                 ("tool failure", f"unmet fuzz checkpoints: no generated input passed the oracle for {target}"))
        record = copy.deepcopy(COMPLETED_FUZZ)
        record["campaign"]["nonseed_pass"] = 0
        record["parsers"]["record"]["nonseed_pass"] = 0
        (fuzz / "fuzz.json").write_text(json.dumps(record))
        self.assertEqual(
            verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS),
            ("tool failure", "unmet fuzz checkpoints: no generated input passed the oracle for campaign"
             " | no generated input passed the oracle for record"),
        )
        (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
        self.assertEqual(verify.fuzz_completion(fuzz, None, 0, FUZZ_ROWS), ("completed", None))

    def test_a_parser_failure_is_a_violation_named_by_its_retained_files(self):
        """A parser target's failure leaves its files in TARGET-artifacts/, which the completion scans."""
        fuzz = self.dir / "fuzz"
        for target in ("record", "wire"):
            (fuzz / f"{target}-artifacts").mkdir(parents=True)
        (fuzz / "wire-artifacts" / "first-failure.input").write_bytes(b"x")
        failure = "the wire fuzz run exited 77; its first failure is in wire-artifacts/"
        self.assertEqual(
            verify.fuzz_completion(fuzz, failure, 77, FUZZ_ROWS), ("violation", "crash inputs ['first-failure.input']")
        )

    def test_the_fuzz_lane_credits_a_nonzero_run_count_without_crash_inputs(self):
        fuzz = self.dir / "fuzz"
        fuzz.mkdir()
        (fuzz / "fuzz.json").write_text(json.dumps(COMPLETED_FUZZ))
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, self.codes(report)), (1, ["missing-provenance", "unbound-input"]), report)
        (fuzz / "pins.txt").write_text("- cargo-fuzz 0.13.2; host Linux\n")
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, report["refusals"], report["executions"]), (0, [], 184733), report)
        self.assertEqual(report["obligations"], ["frame-parse-never-panics-and-reencodes"])
        (fuzz / "fuzz.json").write_text('{"seeds": 22}')
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "tool failure"), report)
        (fuzz / "exit.txt").write_text("124\n")
        (fuzz / "failure.txt").write_text("the fuzz run exited 124; crash inputs are in artifacts/\n")
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, report["completion"], self.codes(report)), (1, "timeout", ["timeout", "zero-executions"]), report)
        (fuzz / "exit.txt").unlink()
        (fuzz / "failure.txt").unlink()
        (fuzz / "fuzz.json").write_text(json.dumps({**COMPLETED_FUZZ, "runs": 0}))
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, self.codes(report)), (1, ["tool-failure", "zero-executions"]), report)
        (fuzz / "fuzz.json").write_text('{"seeds": 22, "runs": 9, "seconds": 61}')
        (fuzz / "artifacts").mkdir()
        (fuzz / "artifacts" / "crash-0a").write_bytes(b"\x00")
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(fuzz), "--revision", REVISION)
        self.assertEqual((code, report["completion"], self.codes(report)), (1, "violation", ["wrong-violation"]), report)
        empty = self.dir / "fuzz-skipped"
        empty.mkdir()
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(empty), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (1, "skipped"), report)

    def test_an_unreadable_receipt_or_a_bad_argument_is_a_crash_or_usage_error(self):
        broken = self.dir / "broken.json"
        broken.write_text("{")
        code, report = self.run_script("credit", "--job", "workspace", "--evidence", str(self.dir), "--revision", REVISION, "--receipt", str(broken))
        self.assertEqual((code, report["credited"]), (2, False), report)
        self.assertIn("crash", report)
        receipt = self.dir / "checker.json"
        receipt.write_text(json.dumps({
            "job": "fuzz", "revision": REVISION, "inputs": verify.committed_inputs(),
            "tool": {"name": "checker", "provenance": ["- checker 1.0"]},
            "completion": "exhausted", "detail": "state limit", "executions": 0,
        }))
        code, report = self.run_script("credit", "--job", "fuzz", "--evidence", str(self.dir / "absent"), "--revision", REVISION, "--receipt", str(receipt))
        self.assertEqual((code, self.codes(report)), (1, ["exhausted", "unbound-input", "zero-executions"]), report)
        self.assertTrue((self.dir / "absent" / "credit.json").exists())
        result = subprocess.run([sys.executable, str(SCRIPT), "credit", "--job", "loom", "--evidence", str(self.dir)], capture_output=True, text=True, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("needs --module", result.stderr)

    def test_the_receipt_command_writes_the_receipt_and_judges_nothing(self):
        evidence = self.workspace_evidence("receipt-only", exit_code=124)
        code, report = self.run_script("receipt", "--job", "workspace", "--evidence", str(evidence), "--revision", REVISION)
        self.assertEqual((code, report["completion"]), (0, "timeout"), report)
        self.assertTrue((evidence / "receipt.json").exists())
        with mock.patch.object(verify, "admit", side_effect=AssertionError("receipt must not admit")), \
                mock.patch.object(verify, "census_judgment", side_effect=AssertionError("receipt must not judge the census")), \
                contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(verify.main(["receipt", "--job", "workspace", "--evidence", str(evidence),
                                          "--revision", REVISION]), 0)



# The identity the workflow passes the aggregate: the checked-out revision, the run and its attempt.
RUN = "7"
IDENTITY = ("--revision", REVISION, "--run", RUN, "--run-attempt", "1")


def expected(attempt="1"):
    return {"revision": REVISION, "run": RUN, "attempt": attempt}


select_fixture = load("test_select_tests", ROOT / "scripts/test-select-tests.py")
REJUDGED_LANE = "search-nightly"
MEMBER_LINE = "fleet: scheduled zone loss root 2: pass"
WITNESS_LINE = next(line for line in select_fixture.ROW_LINES["fleet-scheduled-roots"]
                    if line.startswith("fleet: scheduled zone: "))


def qualified_evidence(evidence, lane, ran=None, drop=None):
    """Write qualified test lane `lane`'s evidence into the new directory `evidence`: its listings, a run that
    executes `ran` (the lane's selection by default) with every row's lines, its exit code, its pins and the report
    `select-tests.py run` writes for them. `drop` then removes that line from `run.txt`, so the report is stale
    against the run beside it. Return the report."""
    evidence.mkdir()
    header = select_fixture.QUALIFIED_HEADERS[lane]
    selection = select.selection_of(INVENTORY["qualified"][lane])
    ran = selection if ran is None else list(ran)
    lines = [line for row in INVENTORY["qualified"][lane]["rows"] for line in select_fixture.ROW_LINES[row["id"]]]
    filtered = len(select_fixture.QUALIFIED_LISTED[lane]) - len(ran)
    run = (f"{header}\n\nrunning {len(ran)} tests\n" + "".join(f"{line}\n" for line in lines)
           + f"{select_fixture.outcomes(ran)}\n{summary(len(ran), 0, 0, filtered)}\n")
    (evidence / "list.txt").write_text(select_fixture.listing(select_fixture.QUALIFIED_LISTED[lane], header))
    (evidence / "ignored.txt").write_text(select_fixture.listing(select_fixture.QUALIFIED_IGNORED[lane], header))
    (evidence / "run.txt").write_text(run)
    (evidence / "exit.txt").write_text("0\n")
    (evidence / "pins.txt").write_text("- rustc 1.99.0 (b940084d7 2026-09-28)\n")
    common = ["--cfg", "qualified", "--module", lane, "--list", str(evidence / "list.txt"), "--ignored", str(evidence / "ignored.txt")]
    report, _ = select.verdict(["run", *common, "--output", str(evidence / "run.txt"), "--exit", "0"])
    (evidence / "report.json").write_text(json.dumps(report, sort_keys=True) + "\n")
    if drop is not None:
        if f"{drop}\n" not in run:
            raise AssertionError(f"the {lane} run prints no line {drop!r}")
        (evidence / "run.txt").write_text(run.replace(f"{drop}\n", ""))
    return report


COMPLETE = Path(tempfile.mkdtemp(prefix="kestrike-complete-"))
atexit.register(shutil.rmtree, COMPLETE, ignore_errors=True)


def complete_evidence(job, module=None):
    """Return a directory of evidence that credits lane `job` (and Loom `module`), written once a process by the
    `VerifyReceipts` builders, which run `select-tests.py` on it as the lane does."""
    return built_evidence(job, module)


@functools.cache
def built_evidence(job, module):
    builder = VerifyReceipts("test_the_committed_catalog_is_admitted_and_covers_every_lane")
    builder.dir = COMPLETE
    name = f"{job}-{module}" if module else job
    build = {"workspace": lambda: builder.workspace_evidence(name), "loom": lambda: builder.loom_evidence(module, name=name),
             "miri": lambda: builder.miri_evidence(name), "sweep": lambda: builder.sweep_evidence(name),
             "asan": lambda: builder.asan_evidence(name), "qemu": lambda: builder.qemu_evidence(name)}[job]
    return build()


def lane_receipt(job, module, evidence):
    """The receipt `verify-receipts.py receipt` writes for `evidence` under run 7, attempt 1."""
    with mock.patch.dict(os.environ, {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1"}):
        return verify.build_receipt(select, job, module, evidence, REVISION)


class QualifiedRejudge(unittest.TestCase):
    """Credit of a qualified test lane judges its bound listings, run and exit code again and refuses a saved positive
    report or receipt that disagrees, on the direct path, the import path and aggregation."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-rejudge-")
        self.addCleanup(self.temp.cleanup)

    def evidence(self, drop=None, lane=REJUDGED_LANE):
        """Write a passing run of `lane` with its report into a lanes directory of its own, then remove the line
        `drop` from `run.txt`, so the report that says credited is stale against the run beside it."""
        evidence = Path(tempfile.mkdtemp(dir=self.temp.name)) / f"evidence-{lane}-{RUN}-1"
        report = qualified_evidence(evidence, lane, drop=drop)
        self.assertTrue(report["credited"], report)
        return evidence

    def main(self, *argv):
        """Run the script in-process under run 7, attempt 1, with the catalog admission and the census, which this
        evidence does not reach, left out; return (code, report)."""
        ci = {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1"}
        with mock.patch.dict(os.environ, ci), mock.patch.object(verify, "admit", return_value=[]), \
                mock.patch.object(verify, "census_judgment", return_value=([], [])), \
                contextlib.redirect_stdout(io.StringIO()) as stdout, contextlib.redirect_stderr(io.StringIO()):
            code = verify.main([*argv, "--job", REJUDGED_LANE, "--revision", REVISION])
        try:
            return code, json.loads(stdout.getvalue())
        except ValueError:
            self.fail(f"no JSON report: {stdout.getvalue()!r}")

    def credit(self, evidence, *extra):
        return self.main("credit", "--evidence", str(evidence), *extra)

    def imported(self, evidence):
        """Write the lane's receipt, then credit it as an imported receipt, read-only."""
        code, report = self.main("receipt", "--evidence", str(evidence))
        self.assertEqual(code, 0, report)
        return self.credit(evidence, "--receipt", str(evidence / "receipt.json"), "--read-only")

    def aggregated(self, evidence):
        _, entries, _ = verify.aggregate(evidence.parent, "schedule", expected(), INVENTORY)
        return {entry["lane"]: entry for entry in entries}[REJUDGED_LANE]

    def codes(self, report):
        return sorted({refusal["code"] for refusal in report["refusals"]})

    STALE = (("a missing member", MEMBER_LINE, "skipped members ['zone loss root 2']"),
             ("a missing witness", WITNESS_LINE, f"missing witness '^{WITNESS_LINE}$'"))

    def test_the_honest_run_credits_on_each_path(self):
        evidence = self.evidence()
        code, report = self.credit(evidence)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        code, report = self.imported(evidence)
        self.assertEqual((code, report["refusals"]), (0, []), report)
        self.assertTrue(self.aggregated(evidence)["complete"], self.aggregated(evidence))

    def test_a_saved_refusal_stays_refused_and_saved_credit_refusals_are_left_unread(self):
        """A `report.json` that refused keeps the lane refused though its run judged again credits it, and
        aggregation judges the lane from its evidence, so a saved `credit.json` neither refuses nor credits it."""
        evidence = self.evidence()
        saved = json.loads((evidence / "report.json").read_text())
        (evidence / "report.json").write_text(json.dumps({**saved, "code": 4, "credited": False, "reason": "stale refusal"}))
        code, report = self.credit(evidence)
        self.assertEqual((code, self.codes(report)), (1, ["selection-refused"]), report)
        self.assertEqual(report["refusals"][0]["reason"], "stale refusal")
        self.assertFalse(self.aggregated(evidence)["complete"])
        (evidence / "report.json").write_text(json.dumps(saved))
        self.assertEqual(self.credit(evidence)[0], 0)
        (evidence / "credit.json").write_text(json.dumps({"refusals": [{"code": "selection-refused", "reason": "x"}]}))
        self.assertTrue(self.aggregated(evidence)["complete"], self.aggregated(evidence))

    def test_aggregation_leaves_an_unreadable_credit_file_unread_and_keeps_a_lane_read_failure_local(self):
        """A selection lane's `credit.json` is left unread, so an unreadable one changes nothing; a lane whose raw
        evidence cannot be read is that lane's `unbound-input`, and the aggregate judges the other lanes."""
        evidence = self.evidence()
        self.assertEqual(self.credit(evidence)[0], 0)
        (evidence / "credit.json").write_text("{")
        self.assertTrue(self.aggregated(evidence)["complete"], self.aggregated(evidence))
        (evidence / "report.json").write_text("{")
        entry = self.aggregated(evidence)
        self.assertEqual((entry["complete"], entry["reason"]), (False, "credit refused: ['unbound-input']"), entry)

    def test_a_saved_report_whose_targets_are_malformed_is_the_lanes_own_refusal(self):
        """A saved report of a tool failure is the receipt's basis as written. A `targets` field that is no object
        of objects reads as holding no count, so the receipt step and direct credit end in their JSON report, and
        aggregation refuses that lane and judges the others."""
        for targets in ([], "kestrike", {"kestrike": []}):
            with self.subTest(targets=targets):
                evidence = self.evidence()
                self.assertEqual(self.credit(evidence)[0], 0)
                (evidence / "report.json").write_text(json.dumps({"code": 2, "targets": targets}))
                entry = self.aggregated(evidence)
                self.assertFalse(entry["complete"], entry)
                self.assertIn("unbound-input", entry["reason"])
                code, report = self.credit(evidence)
                self.assertEqual((code, report["executions"]), (1, 0), report)
                self.assertIn("tool-failure", self.codes(report))

    def test_a_saved_report_whose_targets_are_malformed_is_the_asan_lanes_own_refusal(self):
        """The ASan envelope reads each required target's witnesses from the receipt's bounds, which a saved report
        of a tool failure supplies as written. A target, its witnesses or its executed modules in another shape
        than an object attributes no executed test, so aggregation refuses the ASan lane, direct credit and import
        end in their JSON report, and the other lanes are judged."""
        shapes = ("kestrike", {"spdk_sys": "x"}, {"kestrike": {"witnesses": "x"}},
                  {"kestrike": {"witnesses": {"executed_modules": "x"}}})
        for targets in shapes:
            with self.subTest(targets=targets):
                lanes = Path(tempfile.mkdtemp(dir=self.temp.name))
                evidence = lanes / f"evidence-asan-{RUN}-1"
                shutil.copytree(complete_evidence("asan"), evidence)
                (evidence / "receipt.json").write_text(json.dumps(lane_receipt("asan", None, evidence)))
                (evidence / "report.json").write_text(json.dumps({"code": 2, "targets": targets}))
                _, entries, _ = verify.aggregate(lanes, "schedule", expected(), INVENTORY)
                entry = next(entry for entry in entries if entry.get("artifact") == evidence.name)
                self.assertFalse(entry["complete"], entry)
                self.assertIn("unbound-input", entry["reason"])
                argv = ["credit", "--job", "asan", "--evidence", str(evidence), "--revision", REVISION]
                ci = {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1"}
                with mock.patch.dict(os.environ, ci), mock.patch.object(verify, "admit", return_value=[]), \
                        mock.patch.object(verify, "census_judgment", return_value=([], [])), \
                        contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()):
                    verify.main(argv)
                    verify.main([*argv, "--receipt", str(evidence / "receipt.json"), "--read-only"])
                try:
                    reports = [json.loads(line) for line in out.getvalue().splitlines()]
                except ValueError:
                    self.fail(f"no JSON report: {out.getvalue()!r}")
                self.assertEqual(len(reports), 2, reports)
                for report in reports:
                    self.assertIn("tool-failure", self.codes(report), report)

    def test_a_saved_positive_report_that_differs_in_one_verdict_field_is_refused(self):
        """The honest run credits, so each edited field of the saved credited report differs from the judgment
        alone, and the receipt's execution count is the judgment's."""
        honest = self.evidence()
        code, report = self.credit(honest)
        self.assertEqual((code, report["executions"]), (0, len(select.selection_of(INVENTORY["qualified"][REJUDGED_LANE]))), report)
        edits = {"rows": lambda r: r["rows"][0].update(id="another-row"), "module": lambda r: r.update(module="search"),
                 "targets": lambda r: next(iter(r["targets"].values())).update(executed=1000)}
        for field, edit in edits.items():
            with self.subTest(field=field):
                evidence = self.evidence()
                saved = json.loads((evidence / "report.json").read_text())
                edit(saved)
                (evidence / "report.json").write_text(json.dumps(saved))
                code, report = self.credit(evidence)
                self.assertEqual((code, self.codes(report)), (1, ["raw-selection-mismatch"]), report)
                self.assertIn(f"in ['{field}']", report["refusals"][0]["reason"])
                self.assertEqual(report["executions"], len(select.selection_of(INVENTORY["qualified"][REJUDGED_LANE])))
                code, report = self.credit(evidence, "--receipt", str(evidence / "receipt.json"), "--read-only")
                self.assertEqual(self.codes(report), ["raw-selection-mismatch"], report)
                self.assertIn("raw-selection-mismatch", self.aggregated(evidence)["reason"])

    def test_an_option_like_loom_module_is_the_lanes_own_refusal(self):
        """A receipt's module reaches the selection judge as one `--module=` token, so a module that reads as an
        option is judged as a module name, which the inventory lacks, and the other lanes are still judged."""
        self.assertEqual(verify.selection_args("loom", "--help"), ["--cfg=loom", "--module=--help"])
        evidence = self.evidence()
        self.assertEqual(self.credit(evidence)[0], 0)
        loom = evidence.parent / f"evidence-loom-credit_model-{RUN}-1"
        shutil.copytree(complete_evidence("loom", "credit_model"), loom)
        receipt = {**lane_receipt("loom", "credit_model", loom), "module": "--help"}
        (loom / "receipt.json").write_text(json.dumps(receipt))
        _, entries, _ = verify.aggregate(evidence.parent, "schedule", expected(), INVENTORY)
        self.assertIn("a receipt for loom --help", {entry["lane"]: entry for entry in entries}["loom --help"]["reason"])
        self.assertTrue(self.aggregated(evidence)["complete"])

    def test_a_missing_or_malformed_raw_input_is_unbound(self):
        cases = (("no listing", lambda e: (e / "list.txt").unlink(), "the lane holds no list.txt"),
                 ("no ignored listing", lambda e: (e / "ignored.txt").unlink(), "the lane holds no ignored.txt"),
                 ("no exit code", lambda e: (e / "exit.txt").unlink(), "the lane holds no exit.txt"),
                 ("a malformed exit code", lambda e: (e / "exit.txt").write_text("zero\n"), "exit.txt holds 'zero'"))
        for name, edit, reason in cases:
            with self.subTest(name):
                evidence = self.evidence()
                edit(evidence)
                code, report = self.credit(evidence)
                self.assertEqual(code, 1, report)
                self.assertTrue(any(refusal["code"] == "unbound-input" and reason in refusal["reason"]
                                    for refusal in report["refusals"]), report)

    def test_a_stale_credited_report_beside_a_run_short_of_its_row_is_refused_on_the_direct_path(self):
        for name, drop, reason in self.STALE:
            with self.subTest(name):
                evidence = self.evidence(drop)
                code, report = self.credit(evidence)
                self.assertEqual((code, self.codes(report)), (1, ["raw-selection-mismatch"]), report)
                self.assertTrue(any(reason in refusal["reason"] for refusal in report["refusals"]), report)

    def test_a_stale_credited_report_beside_a_run_short_of_its_row_is_refused_on_import(self):
        for name, drop, reason in self.STALE:
            with self.subTest(name):
                evidence = self.evidence(drop)
                code, report = self.imported(evidence)
                self.assertEqual((code, self.codes(report)), (1, ["raw-selection-mismatch"]), report)
                self.assertTrue(any(reason in refusal["reason"] for refusal in report["refusals"]), report)

    def test_a_stale_credited_report_of_each_selection_lane_is_refused_on_each_path(self):
        """A lane whose saved report says credited while the exit code beside it is a failing one is refused on the
        direct path, on import and at aggregation: the run judged again is an execution mismatch."""
        for job, module in (("workspace", None), ("loom", "credit_model"), ("miri", None), ("sweep", None), ("asan", None),
                            ("qemu", None)):
            with self.subTest(job=job):
                lanes = Path(tempfile.mkdtemp(dir=self.temp.name))
                evidence = lanes / f"evidence-{job}-{RUN}-1"
                shutil.copytree(complete_evidence(job, module), evidence)
                (evidence / "exit.txt").write_text("1\n")
                argv = ["--job", job, *(["--module", module] if module else []), "--evidence", str(evidence), "--revision", REVISION]
                ci = {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1"}
                with mock.patch.dict(os.environ, ci), mock.patch.object(verify, "admit", return_value=[]), \
                        mock.patch.object(verify, "census_judgment", return_value=([], [])), \
                        contextlib.redirect_stdout(io.StringIO()) as direct, contextlib.redirect_stderr(io.StringIO()):
                    verify.main(["credit", *argv])
                    verify.main(["credit", *argv, "--receipt", str(evidence / "receipt.json"), "--read-only"])
                reports = [json.loads(line) for line in direct.getvalue().splitlines()]
                for path, report in zip(("direct", "import"), reports):
                    self.assertIn("raw-selection-mismatch", self.codes(report), (path, report))
                (evidence / "credit.json").write_text(json.dumps({"refusals": []}))
                _, entries, _ = verify.aggregate(lanes, "schedule", expected(), INVENTORY)
                entry = next(entry for entry in entries if entry.get("artifact") == evidence.name)
                self.assertIn("raw-selection-mismatch", entry["reason"] or "", entry)

    def test_a_stale_credited_report_beside_a_run_short_of_its_row_is_refused_at_aggregation(self):
        """The lane's saved `credit.json` holds no refusal, as a credit step that judged the run before the line was
        lost writes; aggregation judges the run again and refuses the lane."""
        for name, drop, _ in self.STALE:
            with self.subTest(name):
                evidence = self.evidence(drop)
                self.assertEqual(self.main("receipt", "--evidence", str(evidence))[0], 0)
                (evidence / "credit.json").write_text(json.dumps({"refusals": []}))
                entry = self.aggregated(evidence)
                self.assertEqual((entry["complete"], entry["reason"]), (False, "credit refused: ['raw-selection-mismatch']"), entry)


class Aggregate(unittest.TestCase):
    """The aggregate gate over downloaded lane evidence."""

    INVENTORY = select.load_inventory(select.INVENTORY)

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.lanes = Path(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def lane(self, name, job, module=None, executed=(), executions=None, completion="completed", refusals=(), attempt="1", drop=None,
             edit=None):
        """Write a lane's receipt and its `credit.json` with `refusals`. A lane whose report a selection judge writes
        holds complete evidence, a qualified test lane's a run of `executed` and `drop` removed from its run after
        its report is written, and every other's the evidence `complete_evidence` writes, which `edit` then changes;
        the tool derives its receipt, whose `executions`, `completion` and `attempt` the arguments then replace,
        and its `executed` too where they differ."""
        path = self.lanes / name
        if verify.selection_args(job, module) is not None:
            if job in verify.QUALIFIED:
                qualified_evidence(path, job, ran=executed, drop=drop)
            else:
                shutil.copytree(complete_evidence(job, module), path)
                if edit is not None:
                    edit(path)
            receipt = lane_receipt(job, module, path)
            receipt["completion"] = completion
            receipt["ci"]["GITHUB_RUN_ATTEMPT"] = attempt
            if executions is not None:
                receipt["executions"] = executions
            if job not in verify.QUALIFIED and executed and sorted(executed) != receipt["executed"]:
                receipt["executed"] = sorted(executed)
            (path / "receipt.json").write_text(json.dumps(receipt))
            (path / "credit.json").write_text(json.dumps({"refusals": list(refusals)}))
            return
        path.mkdir()
        receipt = {"job": job, "module": module, "completion": completion, "executed": sorted(executed),
                   "executions": len(executed) if executions is None else executions, "revision": REVISION,
                   "ci": {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": attempt}}
        (path / "receipt.json").write_text(json.dumps(receipt))
        (path / "credit.json").write_text(json.dumps({"refusals": list(refusals)}))

    def activate(self, jobs, tier):
        name = "FAST_JOBS" if tier == "fast" else "HEAVY_JOBS"
        patch = mock.patch.object(verify, name, (*getattr(verify, name), *jobs))
        patch.start()
        self.addCleanup(patch.stop)
        pending = mock.patch.object(verify, "PENDING_JOBS", {key: reason for key, reason in verify.PENDING_JOBS.items() if key not in jobs})
        pending.start()
        self.addCleanup(pending.stop)

    def barriers(self, credited=True):
        path = self.lanes / "evidence-barriers-7-1"
        path.mkdir()
        sites = [{"site": site["site"], "verdict": "pass" if credited or index else "fail"}
                 for index, site in enumerate(read_json(ROOT / "verification/barriers/expected.json")["sites"])]
        ci = {"GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "barriers"}
        identity = {"revision": REVISION, "ci": dict(ci)}
        (path / "report.json").write_text(json.dumps({"credited": credited, "sites": sites, "ci": dict(ci), "identity": identity}))
        (path / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")

    def fast(self, rc11=None):
        self.lane("evidence-workspace-7-1", "workspace")
        self.lane("evidence-rc11-7-1", "rc11", executed=rc11 or read_json(verify.CHECKER_JOBS["rc11"])["tests"])
        if "barriers" in verify.FAST_JOBS:
            self.barriers()
        for lane in ("campaigns", "search"):
            self.lane(f"evidence-{lane}-7-1", lane, executed=select.selection_of(self.INVENTORY["qualified"][lane]))
        self.lane("evidence-fuzz-smoke-7-1", "fuzz-smoke", executed=["x"])

    def heavy(self, profile):
        inventory = self.INVENTORY
        sweep = inventory["miri_sweep"]
        for lane in ("long-run", "search-nightly", "isa-x86-64", "isa-aarch64"):
            if lane not in verify.HEAVY_JOBS:
                continue
            self.lane(f"evidence-{lane}-7-1", lane, executed=select.selection_of(inventory["qualified"][lane]))
        self.lane("evidence-miri-7-1", "miri")
        self.lane("evidence-sweep-7-1", "sweep")
        for module in inventory["loom"]:
            self.lane(f"evidence-loom-{module}-7-1", "loom", module)
        profiles = read_json(verify.CHECKER_JOBS["genmc"])["profiles"]
        cases = profiles["pr"] + (profiles["scheduled"] if profile == "scheduled" else [])
        self.lane("evidence-genmc-7-1", "genmc", profile, executed=cases)
        for job in ("fuzz", "verus"):
            self.lane(f"evidence-{job}-7-1", job, executed=["x"])
        self.lane("evidence-asan-7-1", "asan")
        for job in ("kani", "tlc"):
            self.lane(f"evidence-{job}-7-1", job, profile, executed=["x"])
        self.lane("evidence-quint-7-1", "quint", executed=sorted(set(read_json(verify.CHECKER_JOBS["quint"])["tests"]) - set(read_json(verify.CHECKER_JOBS["quint"]).get("blocked", {}))))
        if "qemu" in verify.HEAVY_JOBS:
            self.lane("evidence-qemu-7-1", "qemu")

    def verdict(self, event="pull_request", attempt="1"):
        complete, entries, other = verify.aggregate(self.lanes, event, expected(attempt), self.INVENTORY)
        return complete, {entry["lane"]: entry for entry in entries}, other

    def test_quint_aggregation_accepts_the_unblocked_domain_and_reports_the_gate(self):
        self.fast()
        self.heavy("scheduled")
        complete, entries, _ = self.verdict("schedule")
        self.assertTrue(complete, entries)
        self.assertTrue(entries["quint"]["complete"])
        self.assertEqual(set(entries["quint"]["blocked"]),
                         {"detect-fixed-incident-progress", "detect-declared-progress", "preserve-p4-retention-proposed"})

    def test_a_complete_pull_request_run_reports_each_lanes_executed_domain(self):
        self.fast()
        complete, lanes, _ = self.verdict()
        self.assertTrue(complete, lanes)
        self.assertEqual(set(lanes), {"workspace", "rc11", "campaigns", "search", "fuzz-smoke", *verify.PENDING_JOBS})
        self.assertEqual(lanes["campaigns"]["executed"], len(select.selection_of(self.INVENTORY["qualified"]["campaigns"])))
        self.assertTrue(lanes["barriers"]["pending"])
        self.assertFalse(lanes["barriers"]["complete"])
        self.assertNotIn("executions", lanes["barriers"])
        self.assertEqual(lanes["rc11"]["executed"], len(read_json(verify.CHECKER_JOBS["rc11"])["tests"]))

    def test_a_complete_scheduled_run_credits_every_domain_and_the_two_reader_cases(self):
        self.fast()
        self.heavy("scheduled")
        complete, lanes, _ = self.verdict("schedule")
        self.assertTrue(complete, {name: entry["reason"] for name, entry in lanes.items() if entry["reason"]})
        sweep = INVENTORY["miri_sweep"]
        self.assertEqual(lanes["sweep"]["executions"], sweep["seeds"] * len(sweep["tests"]))
        self.assertEqual(lanes["miri"]["executed"], len(INVENTORY["miri"]["tests"]))
        self.assertEqual({name for name in lanes if name.startswith("loom ")}, {f"loom {module}" for module in INVENTORY["loom"]})
        self.assertIn("genmc scheduled", lanes)
        long_run = len(select.selection_of(INVENTORY["qualified"]["long-run"]))
        self.assertEqual((lanes["long-run"]["executions"], lanes["long-run"]["executed"]), (long_run, long_run))
        nightly = len(select.selection_of(INVENTORY["qualified"]["search-nightly"]))
        self.assertEqual((lanes["search-nightly"]["executions"], lanes["search-nightly"]["executed"]), (nightly, nightly))

    def test_a_pull_request_lane_that_did_not_run_or_ran_short_leaves_the_gate_incomplete(self):
        selection = select.selection_of(self.INVENTORY["qualified"]["campaigns"])
        for event in ("pull_request", "push", "schedule"):
            for name, receipt, reason in (
                ("missing artifact", None, "no receipt"),
                ("skipped selection", dict(executed=selection[1:]), "'selection-refused'"),
                ("repeated run", dict(executed=selection, executions=len(selection) + 1), "credit refused: ['unbound-input']"),
                ("blocked row", dict(executed=selection, drop=select_fixture.ROW_LINES["fleet-replay"][-1]),
                 "credit refused: ['raw-selection-mismatch']"),
            ):
                with self.subTest(event=event, case=name):
                    for path in list(self.lanes.iterdir()):
                        shutil.rmtree(path)
                    self.fast()
                    if event == "schedule":
                        self.heavy("scheduled")
                    shutil.rmtree(self.lanes / "evidence-campaigns-7-1")
                    if receipt is not None:
                        self.lane("evidence-campaigns-7-1", "campaigns", **receipt)
                    complete, lanes, _ = self.verdict(event)
                    self.assertFalse(complete)
                    self.assertIn(reason, lanes["campaigns"]["reason"])

    def test_the_long_run_lane_credits_its_cases_executed_once_on_heavy_events_only(self):
        gate = select.selection_of(self.INVENTORY["qualified"]["long-run"])
        cases = {
            "zero selection": (dict(executed=(), executions=0), "'selection-refused', 'zero-executions'"),
            "a repeated run": (dict(executed=gate, executions=len(gate) + 1), "credit refused: ['unbound-input']"),
            "another case": (dict(executed=["long_run::another"]), "'selection-refused'"),
            "interrupted": (dict(executed=gate, completion="timeout"), "completion timeout"),
            "refused selection": (dict(executed=gate, drop=select_fixture.ROW_LINES["long-run-gate"][0]),
                                  "credit refused: ['raw-selection-mismatch']"),
        }
        for event in ("schedule", "workflow_dispatch"):
            for name, (receipt, reason) in cases.items():
                with self.subTest(event=event, case=name):
                    for path in list(self.lanes.iterdir()):
                        shutil.rmtree(path)
                    self.fast()
                    self.heavy("scheduled" if event == "schedule" else "pr")
                    shutil.rmtree(self.lanes / "evidence-long-run-7-1")
                    self.lane("evidence-long-run-7-1", "long-run", **receipt)
                    complete, lanes, _ = self.verdict(event)
                    self.assertFalse(complete)
                    self.assertIn(reason, lanes["long-run"]["reason"])
            with self.subTest(event=event, case="missing artifact"):
                shutil.rmtree(self.lanes / "evidence-long-run-7-1")
                complete, lanes, _ = self.verdict(event)
                self.assertFalse(complete)
                self.assertIn("no receipt", lanes["long-run"]["reason"])
        for event in ("pull_request", "push"):
            with self.subTest(event=event):
                for path in list(self.lanes.iterdir()):
                    shutil.rmtree(path)
                self.fast()
                complete, lanes, _ = self.verdict(event)
                self.assertTrue(complete, lanes)
                self.assertNotIn("long-run", lanes)
                self.lane("evidence-long-run-7-1", "long-run", executed=gate)
                self.lane("evidence-search-nightly-7-1", "search-nightly",
                          executed=select.selection_of(self.INVENTORY["qualified"]["search-nightly"]))
                complete, lanes, _ = self.verdict(event)
                self.assertFalse(complete)
                self.assertIn("does not select", lanes["long-run"]["reason"])
                self.assertIn("does not select", lanes["search-nightly"]["reason"])

    def test_a_dispatched_run_needs_the_pr_profile_and_refuses_two_reader_cases(self):
        self.fast()
        self.heavy("scheduled")
        complete, lanes, _ = self.verdict("workflow_dispatch")
        self.assertFalse(complete)
        self.assertIn("does not select", lanes["genmc scheduled"]["reason"])
        self.assertIn("no receipt", lanes["genmc pr"]["reason"])

    def test_a_pr_genmc_receipt_with_a_two_reader_case_is_outside_its_domain(self):
        self.fast()
        self.heavy("pr")
        profiles = read_json(verify.CHECKER_JOBS["genmc"])["profiles"]
        receipt = self.lanes / "evidence-genmc-7-1" / "receipt.json"
        data = json.loads(receipt.read_text())
        data["executed"] = sorted(profiles["pr"][1:] + profiles["scheduled"][:1])
        receipt.write_text(json.dumps(data))
        complete, lanes, _ = self.verdict("workflow_dispatch")
        self.assertFalse(complete)
        self.assertIn("outside the domain", lanes["genmc pr"]["reason"])

    def test_each_incomplete_lane_leaves_the_gate_unsuccessful(self):
        tests = sorted(read_json(verify.CHECKER_JOBS["rc11"])["tests"])
        cases = {
            "skipped prerequisite": (lambda: None, "no receipt"),
            "zero execution": (lambda: self.lane("evidence-rc11-7-1", "rc11", executed=tests, executions=0), "zero executions"),
            "refused credit": (lambda: self.lane("evidence-rc11-7-1", "rc11", executed=tests,
                                                 refusals=[{"code": "raw-failed", "reason": "x"}]), "credit refused"),
            "checker cutoff": (lambda: self.lane("evidence-rc11-7-1", "rc11", executed=tests, completion="exhausted"), "completion exhausted"),
            "canceled process group": (lambda: self.lane("evidence-rc11-7-1", "rc11", executed=tests, completion="timeout"), "completion timeout"),
            "count-matched wrong domain": (lambda: self.lane("evidence-rc11-7-1", "rc11", executed=tests[1:] + ["another"]), "outside the domain"),
        }
        for name, (make, reason) in cases.items():
            with self.subTest(case=name):
                for path in self.lanes.iterdir():
                    for item in path.iterdir():
                        item.unlink()
                    path.rmdir()
                self.lane("evidence-workspace-7-1", "workspace", executed=["a"], executions=1)
                make()
                complete, lanes, _ = self.verdict()
                self.assertFalse(complete)
                self.assertIn(reason, lanes["rc11"]["reason"])

    def test_a_partial_seed_range_and_a_missing_artifact_are_incomplete(self):
        """A sweep whose run lost its last seed block beside the report that judged the whole range is refused."""
        self.fast()
        self.heavy("scheduled")
        shutil.rmtree(self.lanes / "evidence-sweep-7-1")
        last = f"Trying seed: {INVENTORY['miri_sweep']['seeds'] - 1}\n"

        def cut(path):
            run = (path / "run.txt").read_text()
            (path / "run.txt").write_text(run[:run.index(last)])

        self.lane("evidence-sweep-7-1", "sweep", edit=cut)
        for item in (self.lanes / "evidence-loom-fill_model-7-1").iterdir():
            item.unlink()
        complete, lanes, _ = self.verdict("schedule")
        self.assertFalse(complete)
        self.assertIn("'raw-selection-mismatch'", lanes["sweep"]["reason"])
        self.assertIn("no receipt", lanes["loom fill_model"]["reason"])

    def test_a_declared_loom_ignore_leaves_the_module_domain(self):
        """The module's domain is its declared tests less its declared ignores; the lane's credit, judged from its
        evidence against the committed inventory, is the selection judge's."""
        inventory = copy.deepcopy(self.INVENTORY)
        declared = inventory["loom"]["fill_model"]
        declared["ignored"] = declared["tests"][:1]
        domain, count = verify.lane_domains("schedule", inventory)[("loom", "fill_model")]
        self.assertEqual((domain, count), (set(declared["tests"][1:]), None))

    def test_an_uncredited_barrier_scan_is_incomplete(self):
        self.activate(("barriers",), "fast")
        self.lane("evidence-workspace-7-1", "workspace", executed=["a"], executions=1)
        self.lane("evidence-rc11-7-1", "rc11", executed=read_json(verify.CHECKER_JOBS["rc11"])["tests"])
        self.barriers(credited=False)
        complete, lanes, _ = self.verdict()
        self.assertFalse(complete)
        self.assertIn("credit refused", lanes["barriers"]["reason"])

    def test_a_lane_credits_only_under_the_complete_expected_identity(self):
        self.activate(("barriers",), "fast")

        def edit(path, change):
            data = json.loads(path.read_text())
            change(data)
            path.write_text(json.dumps(data))

        receipt = self.lanes / "evidence-rc11-7-1" / "receipt.json"
        report = self.lanes / "evidence-barriers-7-1" / "report.json"
        identity = self.lanes / "evidence-barriers-7-1" / "identity.json"
        for name, path, change, lane, reason in (
            ("no revision", receipt, lambda data: data.pop("revision"), "rc11",
             f"records revision None, not the expected {REVISION!r}"),
            ("another revision", receipt, lambda data: data.update(revision="b" * 40), "rc11",
             f"records revision {'b' * 40!r}, not the expected {REVISION!r}"),
            ("no run", receipt, lambda data: data["ci"].pop("GITHUB_RUN_ID"), "rc11", "records run None, not the expected '7'"),
            ("another run", receipt, lambda data: data["ci"].update(GITHUB_RUN_ID="8"), "rc11",
             "records run '8', not the expected '7'"),
            ("no attempt", receipt, lambda data: data["ci"].pop("GITHUB_RUN_ATTEMPT"), "rc11",
             "records attempt None, not the expected '1'"),
            ("a barrier report without its revision", report, lambda data: data.pop("identity"), "barriers",
             f"records revision None, not the expected {REVISION!r}"),
            ("a barrier report whose build identity names another run", report,
             lambda data: data["identity"]["ci"].update(GITHUB_RUN_ID="8"), "barriers", "records run '8', not the expected '7'"),
            ("a barrier report whose scan names another run than its build identity", report,
             lambda data: data["ci"].update(GITHUB_RUN_ID="8"), "barriers", "credit refused: ['identity']"),
            ("a barrier identity file naming another revision than the report embeds", identity,
             lambda data: data.update(revision="b" * 40), "barriers", "credit refused: ['identity']"),
            ("a barrier identity file naming another run than the report embeds", identity,
             lambda data: data["ci"].update(GITHUB_RUN_ID="8"), "barriers", "credit refused: ['identity']"),
            ("a barrier identity file with a build field the report does not embed", identity,
             lambda data: data.update(lto="fat"), "barriers", "credit refused: ['identity']"),
        ):
            with self.subTest(name):
                shutil.rmtree(self.lanes)
                self.lanes.mkdir()
                self.fast()
                complete, lanes, _ = self.verdict()
                self.assertTrue(complete, lanes)
                edit(path, change)
                complete, lanes, other = self.verdict()
                self.assertFalse(complete)
                self.assertEqual(other, [])
                self.assertIn(reason, lanes[lane]["reason"])
        for name, damage in (("a barrier report without its identity file", Path.unlink),
                             ("a barrier report beside an unreadable identity file", lambda path: path.write_text("{"))):
            with self.subTest(name):
                shutil.rmtree(self.lanes)
                self.lanes.mkdir()
                self.fast()
                damage(identity)
                complete, lanes, other = self.verdict()
                self.assertFalse(complete)
                self.assertEqual(other, [])
                self.assertIn("credit refused: ['identity']", lanes["barriers"]["reason"])
        with self.subTest("an advisory lane of another run"):
            shutil.rmtree(self.lanes)
            self.lanes.mkdir()
            self.fast()
            self.heavy("scheduled")
            edit(self.lanes / "evidence-asan-7-1" / "receipt.json", lambda data: data["ci"].update(GITHUB_RUN_ID="8"))
            complete, lanes, _ = self.verdict("schedule")
            self.assertTrue(complete, lanes)
            self.assertEqual((lanes["asan"]["complete"], lanes["asan"]["advisory"]), (False, True))
            self.assertIn("records run '8'", lanes["asan"]["reason"])
        for missing in ("--revision", "--run", "--run-attempt"):
            with self.subTest(f"no {missing}"):
                argv = list(IDENTITY)
                del argv[argv.index(missing):argv.index(missing) + 2]
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err), self.assertRaises(SystemExit) as stop:
                    verify.main(["aggregate", "--lanes", str(self.lanes), "--event", "pull_request", *argv])
                self.assertEqual(stop.exception.code, 2)
                self.assertEqual(out.getvalue(), "", "a usage error prints no credit report")
                self.assertIn("aggregate needs the expected --revision, --run and --run-attempt", err.getvalue())
        with self.assertRaises(ValueError):
            verify.aggregate(self.lanes, "pull_request", {"revision": "", "run": RUN, "attempt": "1"}, self.INVENTORY)

    def test_a_rerun_reads_only_its_own_attempt_and_keeps_the_first_failure(self):
        self.fast()
        self.lane("evidence-workspace-7-2", "workspace", executed=["a"], executions=1, attempt="2")
        complete, lanes, other = self.verdict(attempt="1")
        self.assertTrue(complete)
        self.assertEqual(other, [{"lane": "evidence-workspace-7-2", "attempt": "2"}])
        complete, lanes, other = self.verdict(attempt="2")
        self.assertFalse(complete)
        self.assertIn("no receipt", lanes["rc11"]["reason"])
        self.assertIn("no receipt", lanes["campaigns"]["reason"])
        self.assertEqual(len(other), 5)

    def test_a_scheduled_run_refuses_a_pr_profile_genmc_receipt(self):
        self.fast()
        self.heavy("pr")
        complete, lanes, _ = self.verdict("schedule")
        self.assertFalse(complete)
        self.assertIn("does not select", lanes["genmc pr"]["reason"])
        self.assertIn("no receipt", lanes["genmc scheduled"]["reason"])

    def test_a_barrier_report_short_of_the_declared_sites_is_incomplete(self):
        self.activate(("barriers",), "fast")
        self.fast()
        report = self.lanes / "evidence-barriers-7-1" / "report.json"
        data = json.loads(report.read_text())
        dropped = data["sites"][-1]["site"]
        data["sites"] = data["sites"][:-1]
        report.write_text(json.dumps(data))
        complete, lanes, _ = self.verdict()
        self.assertFalse(complete)
        self.assertIn(f"missing [{dropped!r}]", lanes["barriers"]["reason"])

    def test_an_artifact_without_its_receipt_is_told_apart_from_a_lane_that_never_ran(self):
        self.fast()
        for item in (self.lanes / "evidence-rc11-7-1").iterdir():
            item.unlink()
        (self.lanes / "evidence-preflight-7-1").mkdir()
        complete, lanes, _ = self.verdict()
        self.assertFalse(complete)
        self.assertIn("evidence-rc11-7-1 holds no receipt", lanes["rc11"]["reason"])
        self.assertNotIn("preflight", lanes)

    def test_a_truncated_receipt_is_a_crash_with_a_report(self):
        self.fast()
        (self.lanes / "evidence-rc11-7-1" / "receipt.json").write_text("{")
        out = io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO()):
            code = verify.main(["aggregate", "--lanes", str(self.lanes), "--event", "pull_request", *IDENTITY])
        self.assertEqual(code, verify.CRASHED)
        self.assertEqual(json.loads(out.getvalue())["code"], verify.CRASHED)

    def test_a_wrong_shape_receipt_is_its_own_lanes_incomplete_entry(self):
        """A saved receipt that parses and is no receipt, as a whole or in its `ci`, `job`, `module` or `executed`,
        leaves its own lane incomplete; the aggregate returns and judges the other lanes. A null module is a
        receipt's own shape."""
        self.fast()
        path = self.lanes / "evidence-workspace-7-1" / "receipt.json"
        saved = verify.read_json(path)
        for field in (None, "ci", "job", "module", "executed"):
            for value in (None, [], "x", 7, {"a": []}, {"a": "x"}, [[]], True):
                if field == "module" and value is None:
                    continue
                with self.subTest(field=field, value=value):
                    path.write_text(json.dumps(value if field is None else {**saved, field: value}))
                    complete, lanes, _ = self.verdict()
                    self.assertFalse(complete)
                    self.assertFalse(lanes["workspace"]["complete"], lanes["workspace"])
                    self.assertEqual([lanes[lane]["reason"] for lane in ("rc11", "campaigns", "search")], [None] * 3)
        for value in ([], "x", 7, True):
            with self.subTest(document=value):
                path.write_text(json.dumps(value))
                self.assertIn("evidence-workspace-7-1 holds no receipt", self.verdict()[1]["workspace"]["reason"])

    def test_a_saved_credit_that_holds_no_list_of_refusals_is_its_lanes_missing_result(self):
        """A lane whose credit aggregation reads from `credit.json` is complete only on a `refusals` list that is
        empty. A document of another shape, an empty mapping in the list's place included, is that lane's
        `missing-result`, and the other lanes are judged."""
        self.fast()
        path = self.lanes / "evidence-rc11-7-1" / "credit.json"
        self.assertTrue(self.verdict()[1]["rc11"]["complete"])
        shapes = ({"refusals": {}}, {"refusals": None}, {"refusals": "x"}, {"refusals": [7]}, {"refusals": [{"reason": "x"}]},
                  {"refusals": [{"code": 7}]}, {"refusals": [{"code": []}]}, {}, [], [1], "x", 7, None, True)
        for value in shapes:
            with self.subTest(value=value):
                path.write_text(json.dumps(value))
                complete, lanes, _ = self.verdict()
                self.assertFalse(complete)
                self.assertEqual(lanes["rc11"]["reason"], "credit refused: ['missing-result']", lanes["rc11"])
                self.assertEqual([lanes[lane]["reason"] for lane in ("workspace", "campaigns", "search")], [None] * 3)
        path.write_text(json.dumps({"refusals": [{"code": "raw-failed", "reason": "x"}]}))
        self.assertEqual(self.verdict()[1]["rc11"]["reason"], "credit refused: ['raw-failed']")

    def test_an_advisory_lane_reports_its_gap_without_holding_the_gate(self):
        def repeated():
            self.lane("evidence-asan-7-1-again", "asan", executed=["x"])

        def refused():
            shutil.rmtree(self.lanes / "evidence-asan-7-1")
            self.lane("evidence-asan-7-1", "asan", edit=lambda path: (path / "qualified.json").write_text("{}"))

        def absent():
            shutil.rmtree(self.lanes / "evidence-asan-7-1")

        def truncated():
            (self.lanes / "evidence-asan-7-1" / "report.json").write_text("{")

        for name, edit, reason in (("repeated", repeated, "2 receipts"), ("refused", refused, "'unqualified'"),
                                   ("absent", absent, "no receipt"), ("truncated report", truncated, "'unbound-input'")):
            with self.subTest(case=name):
                shutil.rmtree(self.lanes)
                self.lanes.mkdir()
                self.fast()
                self.heavy("scheduled")
                edit()
                complete, lanes, _ = self.verdict("schedule")
                self.assertTrue(complete, lanes)
                self.assertEqual((lanes["asan"]["complete"], lanes["asan"]["advisory"]), (False, True))
                self.assertIn(reason, lanes["asan"]["reason"])
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = verify.main(["aggregate", "--lanes", str(self.lanes), "--event", "schedule", *IDENTITY])
                self.assertEqual((code, json.loads(out.getvalue())["refusals"]), (verify.ADMITTED, []))
                self.assertIn("- asan: advisory, incomplete, ", err.getvalue())
        self.assertEqual(verify.ADVISORY_JOBS, ("asan",))
        self.assertTrue(set(verify.ADVISORY_JOBS) <= set(verify.HEAVY_JOBS))

    def test_the_guest_receipt_follows_the_qemu_jobs_state(self):
        """Pending, a guest receipt lies outside every event's selection; heavy, the schedule selects the guest
        domain's exact ID and credits it from one receipt."""
        self.fast()
        self.heavy("scheduled")
        self.assertIn("qemu", (*verify.PENDING_JOBS, *verify.HEAVY_JOBS))
        if "qemu" in verify.PENDING_JOBS:
            self.lane("evidence-qemu-7-1", "qemu", executed=self.INVENTORY["qemu"]["tests"])
            complete, lanes, _ = self.verdict("schedule")
            self.assertFalse(complete)
            self.assertIn("which the schedule event does not select", lanes["qemu"]["reason"])
            self.assertNotIn("qemu", verify.selected_jobs("schedule"))
            return
        complete, lanes, _ = self.verdict("schedule")
        self.assertTrue(complete, lanes)
        self.assertEqual((lanes["qemu"]["executed"], lanes["qemu"]["executions"]), (len(self.INVENTORY["qemu"]["tests"]), 1))
        self.assertIn("qemu", verify.selected_jobs("schedule"))
        self.assertNotIn("qemu", verify.selected_jobs("pull_request"))

    def test_the_architecture_lanes_are_heavy_and_need_exactly_their_rows_on_heavy_events(self):
        """The architecture qualification lanes run on schedule and manual events and are skipped on pull-request
        and push events; a scheduled or manual aggregate needs each lane's receipt of exactly its rows."""
        self.activate(("isa-aarch64",), "heavy")
        for lane in ("isa-x86-64", "isa-aarch64"):
            self.assertIn(lane, verify.HEAVY_JOBS)
            for event, selected in verify.EVENT_HEAVY.items():
                with self.subTest(lane=lane, event=event):
                    self.assertEqual(lane in verify.selected_jobs(event), selected)
                    self.assertEqual(any(job == lane for job, _ in verify.lane_domains(event, self.INVENTORY)), selected)
        rows = select.selection_of(self.INVENTORY["qualified"]["isa-x86-64"])
        for event, profile in (("schedule", "scheduled"), ("workflow_dispatch", "pr")):
            with self.subTest(event=event):
                shutil.rmtree(self.lanes)
                self.lanes.mkdir()
                self.fast()
                self.heavy(profile)
                shutil.rmtree(self.lanes / "evidence-isa-aarch64-7-1")
                shutil.rmtree(self.lanes / "evidence-isa-x86-64-7-1")
                self.lane("evidence-isa-x86-64-7-1", "isa-x86-64", executed=rows[1:])
                complete, lanes, _ = self.verdict(event)
                self.assertFalse(complete)
                self.assertIn("no receipt: the lane did not run", lanes["isa-aarch64"]["reason"])
                self.assertIn("'selection-refused'", lanes["isa-x86-64"]["reason"])

    def test_a_pending_lane_receipt_lies_outside_every_events_selection(self):
        """A disabled lane is visible but never credited; even a passing receipt is outside the selected domain."""
        self.assertEqual(set(verify.PENDING_JOBS), {"barriers", "isa-aarch64", *verify.TAG_COMPARE})
        for event in verify.EVENT_HEAVY:
            with self.subTest(event=event):
                self.assertTrue(set(verify.PENDING_JOBS).isdisjoint(verify.selected_jobs(event)))
                self.assertTrue(set(verify.PENDING_JOBS).isdisjoint(job for job, _ in verify.lane_domains(event, self.INVENTORY)))
        self.fast()
        self.heavy("scheduled")
        complete, lanes, _ = self.verdict("schedule")
        self.assertTrue(complete, lanes)
        for lane in verify.PENDING_JOBS:
            self.lane(f"evidence-{lane}-7-1", lane, executed=["unexpected"])
        complete, lanes, _ = self.verdict("schedule")
        self.assertFalse(complete)
        for lane in verify.PENDING_JOBS:
            self.assertIn("which the schedule event does not select", lanes[lane]["reason"])

    def test_a_pending_barrier_scan_report_is_unselected_evidence(self):
        """The barrier lane uploads a scan report in place of a receipt; while the lane is pending, that report is refused as unselected evidence."""
        self.fast()
        self.heavy("scheduled")
        complete, lanes, _ = self.verdict("schedule")
        self.assertTrue(complete, lanes)
        self.barriers()
        complete, lanes, _ = self.verdict("schedule")
        self.assertFalse(complete)
        self.assertIn("which the schedule event does not select", lanes["barriers"]["reason"])

    def test_pending_coverage_is_named_without_receipt_or_credit_on_every_event(self):
        for event in verify.EVENT_HEAVY:
            with self.subTest(event=event):
                shutil.rmtree(self.lanes)
                self.lanes.mkdir()
                self.fast()
                if verify.EVENT_HEAVY[event]:
                    self.heavy("scheduled" if event == "schedule" else "pr")
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = verify.main(["aggregate", "--lanes", str(self.lanes), "--event", event, *IDENTITY])
                report = json.loads(out.getvalue())
                self.assertEqual((code, report["refusals"]), (verify.ADMITTED, []))
                pending = {entry["lane"]: entry for entry in report["lanes"] if entry.get("pending")}
                self.assertEqual(set(pending), set(verify.PENDING_JOBS))
                for job, reason in verify.PENDING_JOBS.items():
                    self.assertEqual(pending[job], {"lane": job, "complete": False, "pending": True, "reason": reason})
                    self.assertIn(f"- {job}: pending, no coverage credit, {reason}", err.getvalue())

    def test_an_activated_tag_comparison_lane_joins_the_heavy_aggregate_with_its_declared_sites(self):
        """Activation moves the tag comparison jobs to `HEAVY_JOBS`; the heavy events then select both lanes and
        the aggregate requires each to credit exactly the declaration's sites."""
        heavy = (*verify.HEAVY_JOBS, *verify.TAG_COMPARE)
        pending = {job: reason for job, reason in verify.PENDING_JOBS.items() if job not in verify.TAG_COMPARE}
        with mock.patch.object(verify, "HEAVY_JOBS", heavy), mock.patch.object(verify, "PENDING_JOBS", pending):
            self.assertTrue(set(verify.TAG_COMPARE).isdisjoint(job for job, _ in verify.lane_domains("pull_request", self.INVENTORY)))
            domains = verify.lane_domains("schedule", self.INVENTORY)
            for job in verify.TAG_COMPARE:
                self.assertEqual(domains[(job, None)], (set(read_json(verify.CHECKER_JOBS[job])["tests"]), None))
            self.fast()
            self.heavy("scheduled")
            self.lane("evidence-tag-compare-x86-64-7-1", "tag-compare-x86-64", executed=["tag-decision"])
            complete, lanes, _ = self.verdict("schedule")
            self.assertFalse(complete)
            self.assertIn("missing ['early-return-control']", lanes["tag-compare-x86-64"]["reason"])
            self.assertIn("no receipt", lanes["tag-compare-aarch64"]["reason"])

    def test_the_verifiers_domain_tables_match_the_harness_and_the_envelope_producer(self):
        guest = load("guest_binder", ROOT / "scripts/guest-binder.py")
        producer = load("qualified_envelope", ROOT / "scripts/qualified-envelope.py")
        self.assertEqual(verify.GUEST_REPORTS, guest.REPORTS)
        self.assertEqual(verify.GUEST_PASS, guest.OUTCOMES[guest.PASSED])
        self.assertEqual(verify.ENVELOPED["qemu"]["artifact"], producer.ARTIFACT_FIELDS)
        self.assertEqual(set(verify.ENVELOPED), set(producer.DEADLINES))

    def test_an_advisory_receipt_on_a_pull_request_is_incomplete(self):
        self.fast()
        self.lane("evidence-asan-7-1", "asan", executed=["x"])
        complete, lanes, _ = self.verdict()
        self.assertFalse(complete)
        self.assertIn("which the pull_request event does not select", lanes["asan"]["reason"])

    def test_a_repeated_receipt_is_incomplete(self):
        self.fast()
        self.lane("evidence-workspace-copy", "workspace", executed=["a"], executions=1)
        complete, lanes, _ = self.verdict()
        self.assertFalse(complete)
        self.assertIn("2 receipts", lanes["workspace"]["reason"])



class Intake(unittest.TestCase):
    """The intake register's checks inside `admit`, each fed a scratch register of fixed rows the test writes."""

    ORIGINAL_ESCAPES = (
        "dsw-109 dsw-1094 dsw-1114 dsw-1162 dsw-122 dsw-18 dsw-190 dsw-195 dsw-21 dsw-23 dsw-239 dsw-25 dsw-28 dsw-32 "
        "dsw-4 dsw-5 dsw-52 dsw-548 dsw-55 dsw-7 ivk-1034 ivk-1489 ivk-1649 ivk-1768 ivk-1795 ivk-1801 ivk-1806 "
        "ivk-1865 ivk-1900 ivk-1920 ivk-1921 ivk-1974 ivk-2021 ivk-2124 ivk-2170 ivk-2229 ivk-2261 ivk-2310 ivk-2314 "
        "ivk-2317 ivk-2330 ivk-2350 ivk-2352 ivk-2354 ivk-2368 ivk-2371 ivk-2376").split()
    ORIGINAL_PAIRS = {"dsw-4": "ivk-1034", "dsw-18": "ivk-1649", "dsw-52": "ivk-1865", "dsw-1162": "ivk-1974"}
    RECORD = "warm-activation-commits-allocation-before-fills"
    RULE = "a retained entry outside every damage set was lost on host loss"
    REGRESSION = {"path": "crates/kestrike/src/bind/identity_tests.rs",
                  "tests": ["bind::identity_tests::an_entry_behind_a_link_that_a_mount_shows_is_refused_as_unreadable"]}
    BUILD = "a62ea077e0a0c6a03d49146209193c5549d82119c3ac47e00afe49197dadf2f8"
    SWEEP = f"one sweep of upload on the unfixed build, archive build {BUILD}, runs 0..499"
    CATCH = {"history": "ss1-get-beside-an-open-share", "rule": "an eligible peer's GET starved behind a saturated share",
             "tally": {"build": BUILD, "runs": 500, "ended": {"violation": 500, "pass": 0}, "missed": 0,
                       "controls": [{"name": "a control", "runs": 500, "missed": 0}]}}
    CAUSES = {"workload": ("steps", "sweep"), "environment": ("gap", "standing_check"),
              "ordering": ("constraint", "sweep"), "property": ("unjudged", "sweep")}
    CATCH_FIELDS = ("history", "rule", "tally")
    ROWS = {
        "open": {"id": "open", "kind": "escape", "class": "correctness bug",
                 "site": {"path": "crates/kestrike/src/bind/identity.rs", "function": "Host::shown"},
                 "property": {"text": "the record's invariant", "place": "obligation", "pointer": RECORD},
                 "fix": {"state": "not-delivered"}},
        "ruled": {"id": "ruled", "kind": "escape", "class": "safety bug",
                  "site": {"path": "crates/kestrike/src/storage/publication.rs", "function": "the fill's commit"},
                  "property": {"text": RULE, "place": "rule", "pointer": "array ORACLE of narrate/rules.rs"},
                  "fix": {"state": "not-delivered"}},
        "excluded": {"id": "excluded", "kind": "escape", "class": "correctness bug",
                     "site": {"path": "crates/kestrike/src/bind/identity.rs", "function": "Host::covered"},
                     "property": {"text": "a cover is refused", "place": "documentation", "pointer": "bind/mod.rs"},
                     "fix": {"state": "merged", "pull_request": 1752, "regression": REGRESSION},
                     "cause": "environment", "evidence": {"gap": "no host procfs", "standing_check": "none"},
                     "exclusion": "gap"},
        "change": {"id": "change", "kind": "contract-change", "pull_request": 1894,
                   "property_action": {"action": "added", "place": "obligation", "reference": RECORD}},
        "dispute": {"id": "dispute", "kind": "disagreement", "sources": ["source one", "source two"]},
    }
    EXCLUSION = {"id": "gap", "reason": "the environment lacks the host", "covers": ["excluded"]}

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="kestrike-intake-")
        self.addCleanup(temp.cleanup)
        self.register = Path(temp.name) / "intake"
        (self.register / "exclusions").mkdir(parents=True)
        self.reset()

    def reset(self):
        """Writes the fixture rows and the exclusion file afresh."""
        for name, row in self.ROWS.items():
            self.put(name, row)
        self.put("gap", self.EXCLUSION, "exclusions")

    def put(self, name, value, under=""):
        (self.register / under / f"{name}.json").write_text(value if isinstance(value, str) else json.dumps(value))

    def edited(self, name, edit, under=""):
        """Writes the fixture row `name` with `edit` applied into a fresh copy of the fixtures and judges them."""
        self.reset()
        row = copy.deepcopy(self.EXCLUSION if under else self.ROWS[name])
        edit(row)
        self.put(name, row, under)
        return self.judge()

    def judge(self):
        return verify.intake_judgment(CATALOG, self.register)

    def admit_report(self, register):
        """Runs `admit` against the register `register`, with catalog admission, the census and the control ratchet
        stubbed, and returns its exit code and its JSON report."""
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for patch in (mock.patch.object(verify, "INTAKE", register), mock.patch.object(verify, "admit", return_value=[]),
                          mock.patch.object(verify, "census_judgment", return_value=([], [])),
                          mock.patch.object(verify, "ratchet_judgment", return_value=([], 0)),
                          contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO())):
                stack.enter_context(patch)
            code = verify.main(["admit"])
        return code, json.loads(out.getvalue())

    def scratch(self, files):
        """Writes `files`, relative paths to texts or bytes, under a fresh directory beside the register and returns it."""
        root = Path(tempfile.mkdtemp(dir=self.register.parent))
        for name, text in files.items():
            (root / name).parent.mkdir(parents=True, exist_ok=True)
            (root / name).write_bytes(text if isinstance(text, bytes) else text.encode())
        return root

    def cleared(self, *indexes):
        """Clears the cached `indexes` now and when the test ends."""
        for index in indexes:
            index.cache_clear()
            self.addCleanup(index.cache_clear)

    def caught(self, **changes):
        """Return an edit that gives a row cause `workload`, its evidence, and the fixed catch with `changes`."""
        return lambda row: row.update(cause="workload", evidence={"steps": "s", "sweep": self.SWEEP},
                                      catch={**copy.deepcopy(self.CATCH), **changes})

    def paired(self, control):
        """Return the tally of a catch that names `control`: the fixed catch's history and `control`, each counted."""
        counted = {"runs": 500, "missed": 0}
        return {"build": self.BUILD, "history": {"name": self.CATCH["history"], **counted},
                "controls": [{"name": control, **counted}]}

    def assertRefused(self, judgment, record, fragment):
        refusals, _ = judgment
        self.assertTrue(refusals, f"admitted where {record} should be refused for {fragment!r}")
        self.assertEqual({r["code"] for r in refusals}, {"intake"}, refusals)
        self.assertTrue(any(r["record"] == record and fragment in r["reason"] for r in refusals), refusals)

    def assertAdmitted(self, judgment):
        self.assertEqual(judgment[0], [])
        return judgment[1]

    def test_the_committed_register_is_admitted_and_prints_its_open_rows(self):
        opened = self.assertAdmitted(verify.intake_judgment(CATALOG, verify.INTAKE))
        rows = {path.stem: json.loads(path.read_text()) for path in sorted(verify.INTAKE.glob("*.json"))}
        exclusions = [json.loads(path.read_text()) for path in sorted((verify.INTAKE / "exclusions").glob("*.json"))]
        kinds = {kind: sum(row["kind"] == kind for row in rows.values()) for kind in verify.INTAKE_KINDS}
        self.assertEqual(opened["intake"], {**kinds, "exclusion": len(exclusions)})
        self.assertEqual([row["id"] for row in opened["open_escapes"]],
                         [name for name, row in rows.items() if row["kind"] == "escape" and not {"catch", "exclusion"} & set(row)])
        self.assertEqual(opened["open_disagreements"], [{"id": name, "sources": row["sources"]} for name, row in rows.items()
                                                        if row["kind"] == "disagreement" and "holds" not in row])
        self.assertEqual(opened["open_exclusions"], [{"id": e["id"], "covers": len(set(e["covers"]))}
                                                     for e in exclusions if "approval" not in e])
        caused = ["catch or exclusion"]
        self.assertEqual({row["id"]: row["lacks"] for row in opened["open_escapes"]},
                         dict.fromkeys(("dsw-1114", "dsw-122"), caused))
        self.assertEqual({e["id"]: e["covers"] for e in opened["open_exclusions"]},
                         {"bind-and-failover": 29, "panic-during-unwinding": 4, "slot-load-size": 1,
                          "volume-close-after-cancel": 1})
        escapes = {name for name, row in rows.items() if row["kind"] == "escape"}
        self.assertLessEqual(set(self.ORIGINAL_ESCAPES), escapes)
        for name, kind in (("contract-change-1758", "contract-change"), ("contract-change-1894", "contract-change"),
                           ("disagreement-fill-after-close", "disagreement"), ("disagreement-first-pass-fills", "disagreement"),
                           ("disagreement-root-slot-layout", "disagreement"), ("disagreement-waiting-pass-quota", "disagreement")):
            self.assertEqual(rows.get(name, {}).get("kind"), kind, name)
        for name, mate in self.ORIGINAL_PAIRS.items():
            with self.subTest(pair=name):
                self.assertEqual((rows[name].get("pair"), rows[mate].get("pair")), (mate, name))
        for name, row in rows.items():
            if "pair" in row:
                with self.subTest(paired=name):
                    self.assertNotEqual(row["pair"], name)
                    self.assertIn(row["pair"], escapes)
                    self.assertEqual(rows[row["pair"]].get("pair"), name)

    def test_the_fixture_register_is_admitted_with_its_open_rows(self):
        opened = self.assertAdmitted(self.judge())
        self.assertEqual(opened["intake"], {"escape": 3, "incident": 0, "contract-change": 1, "disagreement": 1, "exclusion": 1})
        self.assertEqual(opened["open_escapes"], [{"id": "open", "lacks": ["cause", "evidence", "catch or exclusion"]},
                                                  {"id": "ruled", "lacks": ["cause", "evidence", "catch or exclusion"]}])
        self.assertEqual(opened["open_disagreements"], [{"id": "dispute", "sources": ["source one", "source two"]}])
        self.assertEqual(opened["open_exclusions"], [{"id": "gap", "covers": 1}])
        try:
            descriptors = len(os.listdir("/proc/self/fd"))
            self.judge()
            self.assertEqual(len(os.listdir("/proc/self/fd")), descriptors)
        except OSError as error:
            self.skipTest(f"this host lists no descriptors: {error}")

    def test_a_tlc_configuration_that_is_a_link_out_of_the_models_is_unreadable(self):
        outside = self.scratch({"Lifecycle.cfg": (verify.ROOT / "tla/Lifecycle.cfg").read_text()})
        root = self.scratch({"tla/Lifecycle.tla": (verify.ROOT / "tla/Lifecycle.tla").read_text()})
        bases = {case.base for case in verify.model_runner("tla").cases() if case.target == "Lifecycle.tla"}
        self.assertIn("Lifecycle.cfg", bases)
        for base in bases:
            (root / "tla" / base).symlink_to(outside / "Lifecycle.cfg")
        self.cleared(verify.model_properties, verify.bounded_text)
        with mock.patch.object(verify, "ROOT", root):
            gap = verify.model_gap("tla/Lifecycle.tla", "TypeOK")
        self.assertRegex(gap, r"^model 'tla/Lifecycle.tla' cannot be read: .*\.cfg cannot be read: it resolves outside")

    def test_a_file_that_is_no_object_or_has_another_id_or_kind_is_refused(self):
        deep = json.dumps(self.ROWS["open"])[:-1] + ', "note": ' + "[" * 100_000 + "]" * 100_000 + "}"
        for value, fragment in (("{", "is no JSON object"), ("[]", "is no JSON object"), ("", "is no JSON object"),
                                (" \n", "is no JSON object"), (deep, "is no JSON object")):
            with self.subTest(value=value[:40]):
                self.put("open", value)
                self.assertRefused(self.judge(), "open", fragment)
        (self.register / "open.json").write_bytes(json.dumps(self.ROWS["open"]).encode().replace(b"Host::shown", b"Host::\xff"))
        self.assertRefused(self.judge(), "open", "is no JSON object")
        self.assertRefused(self.edited("open", lambda row: row.update(id="other")), "open", "differs from its file name")
        self.assertEqual(verify.INTAKE_KINDS, ("escape", "incident", "contract-change", "disagreement"))
        for kind in ("outage", "exclusion", "Escape", ["escape"]):
            with self.subTest(kind=kind):
                self.assertRefused(self.edited("open", lambda row, kind=kind: row.update(kind=kind)), "open",
                                   f"kind {kind!r} is none of")
        self.assertRefused(self.edited("open", lambda row: row.pop("kind")), "open", "kind None is none of")
        self.assertRefused(self.edited("dispute", lambda row: row.pop("kind")), "dispute", "kind None is none of")

    def test_a_file_that_repeats_a_member_or_holds_a_non_json_constant_is_refused(self):
        text = json.dumps(self.ROWS["open"])
        for value, fragment in (
            (text[:-1] + ', "id": "open"}', "repeats the member 'id'"),
            (text.replace('"state": "not-delivered"', '"state": "merged", "state": "not-delivered"'), "repeats the member 'state'"),
            (text[:-1] + ', "tally": NaN}', "holds NaN"),
            (text[:-1] + ', "tally": -Infinity}', "holds -Infinity"),
            (text[:-1] + ', "tally": 1e999}', "holds 1e999, which is no finite number"),
            (text[:-1] + ', "tally": -1e999}', "holds -1e999, which is no finite number"),
        ):
            with self.subTest(fragment=fragment):
                self.put("open", value)
                self.assertRefused(self.judge(), "open", fragment)
        self.put("gap", json.dumps(self.EXCLUSION)[:-1] + ', "reason": "r"}', "exclusions")
        self.assertRefused(self.judge(), "exclusions/gap", "repeats the member 'reason'")
        self.put("gap", self.EXCLUSION, "exclusions")
        self.put("open", text.replace('"not-delivered"', '"NaN"'))
        self.assertRefused(self.judge(), "open", "fix needs a state among")

    def test_a_file_outside_the_rows_and_the_exclusions_is_refused(self):
        (self.register / "old").mkdir()
        self.put("open", self.ROWS["open"], "old")
        (self.register / "exclusions" / "deeper").mkdir()
        self.put("stray", self.ROWS["open"], "exclusions/deeper")
        (self.register / "stray.JSON").write_text(json.dumps(self.ROWS["open"]))
        (self.register / "notes.md").write_text("notes\n")
        (self.register / ".json").write_text(json.dumps({**self.ROWS["open"], "id": ""}))
        refusals, opened = self.judge()
        self.assertEqual(sorted(r["record"] for r in refusals if "is no row or exclusion" in r["reason"]),
                         [".json", "exclusions/deeper", "notes.md", "old", "stray.JSON"])
        self.assertEqual(len(refusals), 5, refusals)
        self.assertEqual(opened["open_exclusions"], [{"id": "gap", "covers": 1}])
        self.assertEqual(opened["intake"], {"escape": 3, "incident": 0, "contract-change": 1, "disagreement": 1, "exclusion": 1})

    def test_a_link_or_a_special_file_in_the_register_is_refused(self):
        outside = Path(tempfile.mkdtemp(dir=self.register.parent))
        (outside / "linked.json").write_text(json.dumps({**self.ROWS["open"], "id": "linked"}))
        (self.register / "linked.json").symlink_to(outside / "linked.json")
        refusals, opened = self.judge()
        self.assertIn({"code": "intake", "record": "linked.json", "reason": "is a link; the register holds regular files"}, refusals)
        self.assertNotIn("linked", [row["id"] for row in opened["open_escapes"]])
        (self.register / "linked.json").unlink()
        shutil.move(str(self.register / "exclusions"), str(outside / "exclusions"))
        (self.register / "exclusions").symlink_to(outside / "exclusions", target_is_directory=True)
        self.assertRefused(self.judge(), "exclusions", "is a link")
        (self.register / "exclusions").unlink()
        shutil.move(str(outside / "exclusions"), str(self.register / "exclusions"))
        os.mkfifo(self.register / "pipe.json")
        self.assertRefused(self.judge(), "pipe.json", "is no row or exclusion of the register")

    def test_a_register_that_is_missing_or_cannot_be_listed_is_refused(self):
        self.assertRefused(verify.intake_judgment(CATALOG, self.register.parent / "absent"), ".", "cannot be listed")
        self.assertRefused(verify.intake_judgment(CATALOG, self.register / "open.json"), ".", "cannot be listed")
        shutil.rmtree(self.register / "exclusions")
        self.assertRefused(self.judge(), "excluded", "names no file under verification/intake/exclusions/")
        (self.register / "excluded.json").unlink()
        self.assertEqual(self.assertAdmitted(self.judge())["open_exclusions"], [])
        (self.register / "exclusions").mkdir()
        self.put("excluded", self.ROWS["excluded"])
        listed = os.scandir
        for directory, record in ((self.register / "exclusions", "exclusions"), (self.register, ".")):
            def unlistable(descriptor, inode=directory.stat().st_ino):
                try:
                    named = isinstance(descriptor, int) and os.fstat(descriptor).st_ino == inode
                except OSError:
                    named = False
                if named:
                    raise PermissionError(13, "Permission denied")
                return listed(descriptor)
            with self.subTest(record=record), mock.patch.object(verify.os, "scandir", side_effect=unlistable):
                refusals, opened = self.judge()
                self.assertIn({"code": "intake", "record": record,
                               "reason": "the register directory cannot be listed: [Errno 13] Permission denied"}, refusals)
                self.assertEqual(opened["open_exclusions"], [])
        opening = os.open

        def unopenable(path, *args, **kwargs):
            if path == "exclusions" and kwargs.get("dir_fd") is not None:
                raise PermissionError(13, "Permission denied")
            return opening(path, *args, **kwargs)
        with mock.patch.object(verify.os, "open", side_effect=unopenable):
            refusals, opened = self.judge()
        self.assertEqual([r["record"] for r in refusals], ["exclusions", "excluded"], refusals)
        self.assertIn("the register directory cannot be listed", refusals[0]["reason"])
        self.assertEqual(opened["open_exclusions"], [])
        linked = self.register.parent / "linked-register"
        linked.symlink_to(self.register, target_is_directory=True)
        refusals, opened = verify.intake_judgment(CATALOG, linked)
        self.assertEqual(refusals, [{"code": "intake", "record": ".", "reason": "is a link; the register holds regular files"}])
        self.assertEqual((opened["intake"]["escape"], opened["open_escapes"]), (0, []))

    def test_an_entry_whose_type_cannot_be_read_is_refused_and_the_judgment_goes_on(self):
        self.put("dispute", {**self.ROWS["dispute"], "sources": ["one"]})
        read = os.stat

        def failing(path, *args, **kwargs):
            if path in ("open.json", "gap.json") and kwargs.get("dir_fd") is not None:
                raise PermissionError(13, "Permission denied")
            return read(path, *args, **kwargs)
        with mock.patch.object(verify.os, "stat", side_effect=failing):
            refusals, _ = self.judge()
        self.assertIn({"code": "intake", "record": "open.json", "reason": "cannot be read: [Errno 13] Permission denied"}, refusals)
        self.assertIn({"code": "intake", "record": "exclusions/gap.json", "reason": "cannot be read: [Errno 13] Permission denied"},
                      refusals)
        self.assertIn({"code": "intake", "record": "dispute", "reason": "sources needs two citations"}, refusals)

    def test_a_register_file_over_its_byte_bound_is_refused(self):
        self.assertEqual((verify.REGISTER_BYTES, verify.SOURCE_BYTES), (1 << 20, 8 << 20))
        room = verify.REGISTER_BYTES - len(json.dumps({**self.ROWS["open"], "note": ""}))
        self.put("open", json.dumps({**self.ROWS["open"], "note": "n" * room}))
        self.assertEqual((self.register / "open.json").stat().st_size, verify.REGISTER_BYTES)
        self.assertAdmitted(self.judge())
        self.put("open", json.dumps({**self.ROWS["open"], "note": "n" * (room + 1)}))
        self.assertRefused(self.judge(), "open", f"it holds more than {verify.REGISTER_BYTES} bytes")
        self.put("open", json.dumps({**self.ROWS["open"], "note": "n" * verify.REGISTER_BYTES}))
        self.assertRefused(self.judge(), "open", f"it holds more than {verify.REGISTER_BYTES} bytes")
        scratch = self.scratch({"narrate/rules.rs": self.RULES + "//" + "x" * verify.SOURCE_BYTES + "\n"})
        self.cleared(verify.rule_texts)
        with mock.patch.object(verify, "WORLD_TESTS", scratch), \
                self.assertRaisesRegex(verify.Crash, f"it holds more than {verify.SOURCE_BYTES} bytes"):
            verify.rule_texts()

    def test_an_escape_without_a_required_field_or_its_agreed_property_is_refused(self):
        for field in ("class", "property", "site", "fix"):
            with self.subTest(field=field):
                self.assertRefused(self.edited("open", lambda row: row.pop(field)), "open", f"lacks {field}")
        for name, edit, fragment in (
            ("open", lambda row: row.update({"class": "minor bug"}), "class 'minor bug' is none of"),
            ("open", lambda row: row["property"].pop("place"), "property needs its text, a pointer and a place"),
            ("open", lambda row: row["property"].update(place="hearsay"), "property needs its text, a pointer and a place"),
            ("open", lambda row: row["property"].update(pointer=" "), "property needs its text, a pointer and a place"),
            ("excluded", lambda row: row["property"].pop("text"), "property needs its text, a pointer and a place"),
            ("excluded", lambda row: row["property"].update(text=" "), "property needs its text, a pointer and a place"),
            ("open", lambda row: row["site"].pop("function"), "site needs a path and a function"),
            ("open", lambda row: row["site"].update(function=" "), "site needs a path and a function"),
            ("excluded", lambda row: row["site"].update(function=""), "site needs a path and a function"),
            ("open", lambda row: row["site"].pop("path"), "site needs a path and a function"),
            ("open", lambda row: row.update(site="crates/kestrike/src/bind/identity.rs"), "site needs a path and a function"),
            ("open", lambda row: row["site"].update(path="crates/kestrike/src/bind/gone.rs"),
             "site.path 'crates/kestrike/src/bind/gone.rs' is no file of the repository"),
            ("open", lambda row: row["site"].update(path="crates/kestrike/src/bind"),
             "site.path 'crates/kestrike/src/bind' is no file of the repository"),
        ):
            with self.subTest(fragment=fragment, name=name):
                self.assertRefused(self.edited(name, edit), name, fragment)
        self.assertAdmitted(self.edited("excluded", lambda row: row["site"].update(path="crates/kestrike/src/bind/gone.rs")))

    def test_a_property_absent_from_its_place_is_refused(self):
        self.assertRefused(self.edited("open", lambda row: row["property"].update(pointer="no-such-record")),
                           "open", "'no-such-record' is no record id of verification/obligations.json")
        self.assertRefused(self.edited("ruled", lambda row: row["property"].update(text="a fill admitted at last")),
                           "ruled", "'a fill admitted at last' is no rule text")
        model = {"place": "model", "model": "tla/Lifecycle.tla"}
        self.assertRefused(self.edited("open", lambda row: row["property"].update(model, pointer="Next")),
                           "open", "'Next' is no invariant of the model 'tla/Lifecycle.tla'")
        self.assertAdmitted(self.edited("open", lambda row: row["property"].update(model, pointer="TypeOK")))
        quint = {"place": "model", "model": "quint/suffix.qnt"}
        self.assertRefused(self.edited("open", lambda row: row["property"].update(quint, pointer="Retains")),
                           "open", "'Retains' is no invariant of the model 'quint/suffix.qnt'")
        self.assertAdmitted(self.edited("open", lambda row: row["property"].update(quint, pointer="Retained")))

    def test_a_fix_outside_its_states_without_its_pull_request_or_with_an_absent_regression_is_refused(self):
        identity = "crates/kestrike/src/bind/identity_tests.rs"
        for edit, fragment in (
            (lambda row: row["fix"].update(state="probably merged"), "fix needs a state among merged, not-delivered"),
            (lambda row: row["fix"].pop("pull_request"), "a merged fix names its pull request by number"),
            (lambda row: row["fix"].update(pull_request="blotter pull request 1752"), "a merged fix names its pull request by number"),
            (lambda row: row["fix"].update(pull_request=0), "a merged fix names its pull request by number"),
            (lambda row: row["fix"].update(pull_request=-1752), "a merged fix names its pull request by number"),
            (lambda row: row["fix"].update(pull_request=True), "a merged fix names its pull request by number"),
            (lambda row: row["fix"].update(pull_request=1752.0), "a merged fix names its pull request by number"),
            (lambda row: row["fix"]["regression"]["tests"].append("bind::identity_tests::no_such_test"),
             f"fix.regression '{identity}' declares no #[test] fn 'bind::identity_tests::no_such_test'"),
            (lambda row: row["fix"]["regression"].update(tests=[
                "bind::eni_tests::an_entry_behind_a_link_that_a_mount_shows_is_refused_as_unreadable"]), "declares no #[test] fn"),
            (lambda row: row["fix"]["regression"].update(tests=["bind::identity_tests::refuses_open_character_node"]),
             "declares no #[test] fn 'bind::identity_tests::refuses_open_character_node'"),
            (lambda row: row["fix"]["regression"].update(path="crates/kestrike/src/bind/eni_tests.rs"), "declares no #[test] fn"),
            (lambda row: row["fix"]["regression"].update(path="crates/kestrike/src/bind/gone_tests.rs"), "is no Rust source of a crate"),
            (lambda row: row["fix"]["regression"].update(path="verification/obligations.json"), "is no Rust source of a crate"),
            (lambda row: row["fix"]["regression"].update(tests=[]), "fix.regression needs a path and its tests"),
            (lambda row: row["fix"]["regression"].update(tests=["bind identity tests"]), "is no test ID"),
            (lambda row: row["fix"]["regression"].update(tests=["bind::" + "a" * 300]), "is no test ID"),
            (lambda row: row["fix"]["regression"].update(tests=[["bind::identity_tests::x"]]), "is no test ID"),
        ):
            with self.subTest(fragment=fragment):
                self.assertRefused(self.edited("excluded", edit), "excluded", fragment)

    def test_a_regression_outside_the_repository_is_refused(self):
        inside = "crates/kestrike/src/bind/identity_tests.rs"
        for path in ("a" * 300, "/usr/bin/ls", f"../{verify.ROOT.name}/{inside}", str(verify.ROOT / inside)):
            with self.subTest(path=path):
                self.assertRefused(self.edited("excluded", lambda row: row["fix"]["regression"].update(path=path)),
                                   "excluded", "is no Rust source of a crate")
        root = Path(tempfile.mkdtemp(dir=self.register.parent))
        (root / "crates/kestrike/src/bind").mkdir(parents=True)
        (root / "crates/kestrike/Cargo.toml").write_text('[package]\nname = "kestrike"\n')
        (root / "crates/kestrike/src/bind/linked_tests.rs").symlink_to(verify.ROOT / inside)
        with mock.patch.object(verify, "ROOT", root):
            self.assertIsNone(verify.regression_target("crates/kestrike/src/bind/linked_tests.rs"))

    def test_a_regression_under_a_directory_that_is_no_workspace_package_is_refused(self):
        workspace = (verify.ROOT / "Cargo.toml").read_text().split("\n[", 2)[0]
        self.assertIn('members = ["crates/*"]', workspace)
        self.assertNotIn("exclude", workspace)
        paths = ("crates/loose/src/lib.rs", "crates/loose/tests/flat.rs")
        root = self.scratch(dict.fromkeys(paths, "#[test]\nfn planted() {}\n"))
        manifest = root / "crates/loose/Cargo.toml"
        with mock.patch.object(verify, "ROOT", root):
            for make in (lambda: None, manifest.mkdir):
                make()
                for path in paths:
                    with self.subTest(path=path, manifest=manifest.exists()):
                        self.assertIsNone(verify.regression_target(path))
                        self.assertEqual(
                            verify.fix_gaps({"state": "not-delivered", "regression": {"path": path, "tests": ["planted"]}}),
                            [f"fix.regression {path!r} is no Rust source of a crate's src or tests"])
            manifest.rmdir()
            manifest.write_text('[package]\nname = "loose"\n')
            for path in paths:
                with self.subTest(path=path, manifest="file"):
                    self.assertIsNone(verify.regression_gap(verify.regression_target(path), "planted"))
        verify.crate_source.cache_clear()
        verify.bounded_text.cache_clear()

    def test_a_cause_outside_the_four_words_or_without_an_evidence_key_is_refused(self):
        self.assertEqual(verify.CAUSE_EVIDENCE, self.CAUSES)
        self.assertRefused(self.edited("excluded", lambda row: row.update(cause="chance")), "excluded", "cause 'chance' is none of")
        self.assertRefused(self.edited("excluded", lambda row: row.pop("evidence")), "excluded", "cause environment lacks evidence key gap")
        self.assertRefused(self.edited("excluded", lambda row: row.update(evidence="no host procfs; no standing check")),
                           "excluded", "cause environment lacks evidence key gap")
        for word in ("Workload", " workload", "WORKLOAD", "workload "):
            with self.subTest(word=word):
                self.assertRefused(self.edited("open", lambda row, word=word: row.update(
                    cause=word, evidence={"steps": "s", "sweep": "w"})), "open", f"cause {word!r} is none of")
        refusals, opened = self.edited("open", lambda row: row.update(cause="workload", evidence={"steps": "s"}))
        self.assertIn({"code": "intake", "record": "open", "reason": "cause workload lacks evidence key sweep"}, refusals)
        self.assertIn({"id": "open", "lacks": ["evidence", "catch or exclusion"]}, opened["open_escapes"])
        for cause, keys in self.CAUSES.items():
            evidence = dict.fromkeys(keys, self.SWEEP)
            with self.subTest(cause=cause):
                opened = self.assertAdmitted(self.edited("open", lambda row: row.update(cause=cause, evidence=evidence)))
                self.assertIn({"id": "open", "lacks": ["catch or exclusion"]}, opened["open_escapes"])
            for key in keys:
                with self.subTest(cause=cause, key=key):
                    for kept in ({k: v for k, v in evidence.items() if k != key}, {**evidence, key: " "},
                                 {**evidence, key: [self.SWEEP]}, {**evidence, key: {"run": self.SWEEP}}):
                        self.assertRefused(self.edited("open", lambda row: row.update(cause=cause, evidence=kept)),
                                           "open", f"cause {cause} lacks evidence key {key}")
            for other, theirs in self.CAUSES.items():
                for key in set(keys) - set(theirs):
                    with self.subTest(cause=cause, keys_of=other):
                        borrowed = dict.fromkeys(theirs, self.SWEEP)
                        self.assertRefused(self.edited("open", lambda row, cause=cause, borrowed=borrowed: row.update(
                            cause=cause, evidence=borrowed)), "open", f"cause {cause} lacks evidence key {key}")

    def test_a_sweep_without_its_archive_digest_is_refused(self):
        for cause, keys in self.CAUSES.items():
            evidence = dict.fromkeys(keys, "a run a reviewer can read")
            if "sweep" not in keys:
                with self.subTest(cause=cause):
                    self.assertAdmitted(self.edited("open", lambda row: row.update(cause=cause, evidence=evidence)))
                continue
            for sweep in ("one sweep of upload on the unfixed build", self.SWEEP.replace(self.BUILD, self.BUILD[:-1]),
                          self.SWEEP.replace(self.BUILD, self.BUILD + "0"), self.SWEEP.replace(self.BUILD, self.BUILD.upper()),
                          self.SWEEP.replace(self.BUILD, "g" + self.BUILD[1:])):
                with self.subTest(cause=cause, sweep=sweep):
                    refusals, opened = self.edited("open", lambda row: row.update(cause=cause, evidence={**evidence, "sweep": sweep}))
                    self.assertEqual([r["reason"] for r in refusals],
                                     ["evidence.sweep names no archive digest of 64 hexadecimal characters"])
                    self.assertIn({"id": "open", "lacks": ["evidence", "catch or exclusion"]}, opened["open_escapes"])
            with self.subTest(cause=cause, sweep="digest"):
                self.assertAdmitted(self.edited("open", lambda row: row.update(
                    cause=cause, evidence={**evidence, "sweep": f"archive of head 424e30371 (build {self.BUILD}, dirty false)"})))

    def test_a_tally_without_its_build_digest_or_with_a_missed_run_is_refused(self):
        tally = self.CATCH["tally"]
        for build in ("unfixed", self.BUILD[:-1], self.BUILD + "0", self.BUILD.upper(), f" {self.BUILD}", 5, None, [self.BUILD]):
            with self.subTest(build=build):
                refusals, _ = self.edited("open", self.caught(tally={**tally, "build": build}))
                self.assertEqual([r["reason"] for r in refusals],
                                 ["catch.tally lacks its build digest: build holds 64 hexadecimal characters"])
        self.assertRefused(self.edited("open", self.caught(tally={k: v for k, v in tally.items() if k != "build"})), "open",
                           "catch.tally lacks its build digest")
        self.assertRefused(self.edited("open", self.caught(tally={"history": {"build": self.BUILD}, "missed": 0, "runs": 5})),
                           "open", "catch.tally lacks its build digest")
        for missed in (1, 500, -1, "0", "1", True, False, 0.0, 1.5, None, [0], {"count": 0}):
            for holder in ({**tally, "missed": missed}, {**tally, "history": {"runs": 500, "missed": missed}},
                           {**tally, "controls": [{"missed": 0}, {"missed": missed}]},
                           {**tally, "controls": [[{"parts": {"missed": missed}}]]}):
                with self.subTest(missed=missed, holder=holder):
                    refusals, _ = self.edited("open", self.caught(tally=holder))
                    self.assertEqual([r["reason"] for r in refusals],
                                     [f"catch.tally holds missed {missed!r}: each missed count of a catch is 0"])
        refusals, _ = self.edited("open", self.caught(tally={**tally, "missed": 2, "history": {"missed": 3}}))
        self.assertEqual(sorted(r["reason"] for r in refusals),
                         ["catch.tally holds missed 2: each missed count of a catch is 0",
                          "catch.tally holds missed 3: each missed count of a catch is 0"])
        for admitted in ({"build": self.BUILD, "runs": 1, "missed": 0}, {**tally, "runs": "0..57367"}, {**tally, "runs": "7..7"},
                         {"build": self.BUILD, "history": {"runs": 128962, "missed": 0}, "controls": [{"runs": 129280, "missed": 0}]},
                         {**tally, "history": {"missed": 0}, "controls": [{"missed": 0}, {"missed": 0}]},
                         {**tally, "missed_by": "none", "notes": ["missed", "runs"]}):
            with self.subTest(admitted=admitted):
                self.assertAdmitted(self.edited("open", self.caught(tally=admitted)))
        unmissed, unrun = "catch.tally holds no missed count", "catch.tally records no run: each runs is a positive integer or first..last"
        for refused, reasons in (
            ({"build": self.BUILD}, [unmissed, unrun]),
            ({"build": self.BUILD, "runs": 500, "missed_by": "none"}, [unmissed]),
            ({"build": self.BUILD, "missed": 0, "ran": 500}, [unrun]),
            ({"build": self.BUILD, "histories": {"ran": 0, "runs": 0, "caught": 0, "missed": 0}}, [unrun]),
            ({**tally, "controls": [{"runs": 0, "missed": 0}]}, [unrun]),
            *(({**tally, "runs": runs}, [unrun]) for runs in (
                0, -1, True, 500.0, None, "", "500", "5..4", "0..", "..5", "0...5", "0..5 ", "a..b", "\u0660..\u0669",
                "0.." + "9" * 19, [500], {"first": 0, "last": 5})),
        ):
            with self.subTest(refused=refused):
                refusals, _ = self.edited("open", self.caught(tally=refused))
                self.assertEqual([r["reason"] for r in refusals], reasons)
        deep = tally
        for _ in range(400):
            deep = {"inner": [deep]}
        self.assertRefused(self.edited("open", self.caught(tally={**tally, "nested": deep, "deepest": {"missed": 7}})), "open",
                           "catch.tally holds missed 7")

    def test_evidence_a_catch_or_an_exclusion_without_a_cause_is_refused(self):
        refusals, opened = self.edited("open", lambda row: row.update(evidence=None))
        self.assertIn({"code": "intake", "record": "open", "reason": "holds evidence and no cause"}, refusals)
        self.assertIn({"id": "open", "lacks": ["cause", "evidence", "catch or exclusion"]}, opened["open_escapes"])
        self.assertRefused(self.edited("open", lambda row: row.update(catch=self.CATCH)), "open", "holds catch and no cause")
        self.assertRefused(self.edited("excluded", lambda row: [row.pop("cause"), row.pop("evidence")]), "excluded",
                           "holds exclusion and no cause")

    def test_a_catch_is_admitted_with_its_three_fields_and_a_quoted_history_and_rule(self):
        self.assertEqual(verify.CATCH_FIELDS, self.CATCH_FIELDS)
        opened = self.assertAdmitted(self.edited("open", self.caught()))
        self.assertNotIn("open", [row["id"] for row in opened["open_escapes"]])
        for field in self.CATCH_FIELDS:
            with self.subTest(field=field):
                self.assertRefused(self.edited("open", lambda row: [self.caught()(row), row["catch"].pop(field)]),
                                   "open", f"catch lacks {field}")
        self.assertRefused(self.edited("open", self.caught(history="ss1-no-such-history")), "open",
                           "catch.history 'ss1-no-such-history' is no quoted history name in the history sources")
        for part in (self.CATCH["history"][:-1], self.CATCH["history"][1:], self.CATCH["history"] + " "):
            with self.subTest(part=part):
                self.assertRefused(self.edited("open", self.caught(history=part)), "open",
                                   f"catch.history {part!r} is no quoted history name in the history sources")
        self.assertRefused(self.edited("open", self.caught(rule="a GET starved")), "open", "catch.rule 'a GET starved' is no rule text")
        control, other = "ss1-open-share-peer-late", "ss2-three-commands-peer-read-altered"
        paired = self.paired(control)
        bound = lambda **parts: self.edited("open", self.caught(control=control, tally={**paired, **parts}))
        self.assertNotIn("open", [row["id"] for row in self.assertAdmitted(bound())["open_escapes"]])
        for field in ("history", "control"):
            with self.subTest(unnamed=field):
                self.assertRefused(self.edited("open", self.caught(control=control)), "open",
                                   f"catch.tally holds no entry named for catch.{field}")
        counted = {"runs": 500, "missed": 0}
        for part in ({"name": other, **counted}, {"name": self.CATCH["history"], "runs": 500},
                     {"name": self.CATCH["history"], "missed": 0}, self.CATCH["history"], None):
            with self.subTest(history=part):
                self.assertRefused(bound(history=part), "open", "catch.tally holds no entry named for catch.history")
        for part in ([{"name": other, **counted}], [{"name": control, "runs": 500}, {"name": other, **counted}],
                     [{"name": control, "missed": 0}, {"name": other, **counted}], [control], {"name": control, **counted}, None):
            with self.subTest(controls=part):
                self.assertRefused(bound(controls=part), "open", "catch.tally holds no entry named for catch.control")
        self.assertAdmitted(bound(controls=[{"name": other, **counted}, *paired["controls"]]))
        self.assertRefused(self.edited("open", self.caught(control=self.CATCH["history"])), "open",
                           f"catch.control {self.CATCH['history']!r} repeats catch.history")
        for control in ("ss1-no-such-control", "", ["x"]):
            with self.subTest(control=control):
                self.assertRefused(self.edited("open", self.caught(control=control)), "open",
                                   f"catch.control {control!r} is no quoted history name in the history sources")
        misread = self.caught(history="ss2-three-commands-peer-read-altered", rule="a complete read returned bytes other than the label's content")
        self.assertNotIn("open", [row["id"] for row in self.assertAdmitted(self.edited("open", misread))["open_escapes"]])
        self.assertRefused(self.edited("open", self.caught(tally={})), "open", "catch.tally is empty")
        self.assertRefused(self.edited("open", lambda row: [self.caught()(row), row.update(catch="history")]), "open", "catch lacks history")

    def test_a_catch_s_further_histories_are_judged_as_its_first(self):
        other = "ss2-three-commands-peer-read-altered"
        entry = {"history": other, "site": "Host::other", "tally": copy.deepcopy(self.CATCH["tally"])}
        also = lambda *entries, **changes: self.edited("open", self.caught(also=list(entries), **changes))
        shown = {"site": "Host::shown"}
        opened = self.assertAdmitted(also(entry, **shown))
        self.assertNotIn("open", [row["id"] for row in opened["open_escapes"]])
        self.assertRefused(also(entry), "open", "catch lacks site: a catch with further histories names its own site")
        for value in ([], {}, "history", None):
            with self.subTest(also=value):
                self.assertRefused(self.edited("open", self.caught(also=value, **shown)), "open", "catch.also is no nonempty list")
        also = lambda *entries, **changes: self.edited("open", self.caught(also=list(entries), **{**shown, **changes}))
        self.assertRefused(also(entry, other), "open", "catch.also[1] is no object")
        for field in ("history", "site", "tally"):
            with self.subTest(lacks=field):
                self.assertRefused(also({name: value for name, value in entry.items() if name != field}), "open",
                                   f"catch.also[0] lacks {field}")
        for history in ("ss1-no-such-history", "", ["x"], None):
            with self.subTest(history=history):
                self.assertRefused(also({**entry, "history": history}), "open",
                                   f"catch.also[0].history {history!r} is no quoted history name in the history sources")
        self.assertRefused(also({**entry, "history": self.CATCH["history"]}), "open",
                           f"catch.also[0].history {self.CATCH['history']!r} repeats a history of the catch")
        self.assertRefused(also(entry, entry), "open", f"catch.also[1].history {other!r} repeats a history of the catch")
        control = "ss1-open-share-peer-late"
        self.assertAdmitted(also(entry, control=control, tally=self.paired(control)))
        self.assertRefused(also({**entry, "history": control}, control=control, tally=self.paired(control)), "open",
                           f"catch.also[0].history {control!r} repeats a history of the catch")
        for site in ("", " ", None, ["Host::other"]):
            with self.subTest(site=site):
                self.assertRefused(also({**entry, "site": site}), "open", "catch.also[0].site is no nonblank text")
                self.assertRefused(also(entry, site=site), "open", "catch.site is no nonblank text")
        self.assertRefused(also({**entry, "tally": None}), "open", "catch.also[0].tally is no object")
        self.assertRefused(also({**entry, "tally": {}}), "open", "catch.also[0].tally is empty")
        self.assertRefused(also(entry, {**entry, "history": "ss1-get-beside-a-drained-share", "tally": {"build": self.BUILD, "runs": 500}}),
                           "open", "catch.also[1].tally holds no missed count")
        self.assertRefused(also({**entry, "tally": {**entry["tally"], "missed": 1}}), "open",
                           "catch.also[0].tally holds missed 1: each missed count of a catch is 0")
        self.assertRefused(also({**entry, "tally": {**entry["tally"], "build": "unfixed"}}), "open",
                           "catch.also[0].tally lacks its build digest")
        self.assertRefused(also({**entry, "tally": {"build": self.BUILD, "missed": 0}}), "open", "catch.also[0].tally records no run")

    def test_an_exclusion_naming_no_file_or_not_covering_its_row_is_refused(self):
        self.assertRefused(self.edited("excluded", lambda row: row.update(exclusion="no-such-exclusion")), "excluded",
                           "exclusion 'no-such-exclusion' names no file under verification/intake/exclusions/")
        self.assertRefused(self.edited("gap", lambda e: e["covers"].remove("excluded"), "exclusions"),
                           "excluded", "exclusion gap does not cover excluded")
        for edit, fragment in (
            (lambda e: e["covers"].append("open"), "covers 'open', which is no escape row naming gap"),
            (lambda e: e["covers"].append("dispute"), "covers 'dispute', which is no escape row naming gap"),
            (lambda e: e["covers"].append("excluded"), "covers 'excluded' more than once"),
            (lambda e: e["covers"].append({"id": "excluded"}), "which is no escape row naming gap"),
            (lambda e: e.pop("reason"), "lacks reason"),
            (lambda e: e.update(covers=[]), "covers needs the escape ids it excludes"),
            (lambda e: e.update(covers=5), "covers needs the escape ids it excludes"),
            (lambda e: e.update(id="bind"), "differs from its file name"),
            (lambda e: e.update(approval=""), "approval, when present, cites the owner's approval"),
        ):
            with self.subTest(fragment=fragment):
                self.assertRefused(self.edited("gap", edit, "exclusions"), "exclusions/gap", fragment)
        _, opened = self.edited("gap", lambda e: e["covers"].append("excluded"), "exclusions")
        self.assertEqual(opened["open_exclusions"], [{"id": "gap", "covers": 1}])
        self.reset()
        self.put("dispute", {**self.ROWS["dispute"], "exclusion": "gap"})
        self.put("gap", {**self.EXCLUSION, "covers": ["excluded", "dispute"]}, "exclusions")
        self.assertRefused(self.judge(), "exclusions/gap", "covers 'dispute', which is no escape row naming gap")
        self.reset()
        self.put("gap", "[]", "exclusions")
        self.assertRefused(self.judge(), "exclusions/gap", "is no JSON object")

    def test_an_approved_exclusion_leaves_the_open_list(self):
        opened = self.assertAdmitted(self.edited("gap", lambda e: e.update(approval="the owner's comment of #317"), "exclusions"))
        self.assertEqual(opened["open_exclusions"], [])
        self.assertEqual(opened["intake"]["exclusion"], 1)

    def test_a_property_action_without_its_form_or_with_an_absent_reference_is_refused(self):
        self.assertRefused(self.edited("change", lambda row: row.pop("property_action")), "change", "lacks property_action")
        for change, fragment in (
            ({"reference": self.RECORD[:-1]}, "is no record id of verification/obligations.json"),
            ({"place": "rule", "reference": "a fill admitted at last"}, "is no rule text of narrate/rules.rs"),
            ({"place": "model", "model": "quint/suffix.qnt", "reference": "Retains"}, "is no invariant of the model 'quint/suffix.qnt'"),
            ({"place": "model", "model": "verification/obligations.json", "reference": "Retained"}, "is no file under tla/ or quint/"),
            ({"place": "model", "model": "quint/../quint/suffix.qnt", "reference": "Retained"}, "is no file under tla/ or quint/"),
            ({"place": "model", "model": "quint/absent.qnt", "reference": "Retained"}, "is no file under tla/ or quint/"),
            ({"place": "model", "reference": "Retained"}, "model None is no file under tla/ or quint/"),
            ({"place": "catalog"}, "property_action is neither none with a reason nor added"),
            ({"place": "spec", "reference": "#297 R20"}, "property_action is neither none with a reason nor added"),
            ({"place": "documentation", "reference": "storage/writable.rs"}, "property_action is neither none with a reason nor added"),
            ({"place": "pull-request", "reference": "blotter pull request 1894"}, "property_action is neither none with a reason nor added"),
            ({"action": "removed"}, "property_action is neither none with a reason nor added"),
            ({"reference": " "}, "property_action is neither none with a reason nor added"),
            ({"action": "none", "reason": ""}, "property_action none needs a reason"),
        ):
            with self.subTest(change=change):
                self.assertRefused(self.edited("change", lambda row: row["property_action"].update(change)), "change", fragment)
        for change in ({"place": "model", "model": "quint/suffix.qnt", "reference": "Retained"},
                       {"place": "model", "model": "quint/suffix.qnt", "reference": "safety"},
                       {"place": "model", "model": "quint/capture.qnt", "reference": "LoadRetains"},
                       {"place": "model", "model": "quint/board.qnt", "reference": "OrphanConservation"},
                       {"place": "model", "model": "quint/grace.qnt", "reference": "Protected"},
                       {"place": "model", "model": "tla/Lifecycle.tla", "reference": "TypeOK"},
                       {"place": "model", "model": "tla/Identity.tla", "reference": "PutCaps"},
                       {"place": "model", "model": "tla/Identity.tla", "reference": "Headroom"},
                       {"place": "model", "model": "tla/Lifecycle.tla", "reference": "Publishes"},
                       {"place": "model", "model": "tla/IdentityMC.tla", "reference": "IdNoSharedPressure"},
                       {"place": "model", "model": "quint/loss.qnt", "reference": "safety"},
                       {"place": "model", "model": "quint/loss.qnt", "reference": "HostLossCreatesNothing"},
                       {"place": "model", "model": "quint/joins.qnt", "reference": "AcksAgree"},
                       {"place": "model", "model": "quint/joins.qnt", "reference": "ReachableHistoryIntact"},
                       {"place": "model", "model": "quint/session.qnt", "reference": "safety"},
                       {"place": "rule", "reference": "a fill admitted after the cache closed"},
                       {"action": "none", "reason": "the invariant already stated the clause"}):
            with self.subTest(change=change):
                self.assertAdmitted(self.edited("change", lambda row: row["property_action"].update(change)))

    def test_a_model_reference_is_a_property_a_passing_case_checks_for_that_model(self):
        for model, reference in (("tla/Lifecycle.tla", "Next"), ("tla/Identity.tla", "IdNoCappedPut"),
                                 ("quint/suffix.qnt", "init"), ("quint/suffix.qnt", "fits"), ("quint/suffix.qnt", "prior"),
                                 ("quint/suffix.qnt", "KEYS"), ("quint/suffix.qnt", "owned"),
                                 ("quint/suffix.qnt", "witnessRecovered"), ("tla/Identity.tla", "IdNoSharedPressure"),
                                 ("quint/loss.qnt", "runSafety"), ("quint/loss.qnt", "rootSafety"),
                                 ("quint/joins.qnt", "LiveAgrees"), ("quint/joins.qnt", "CutIsCapture"),
                                 ("quint/session.qnt", "unreached")):
            with self.subTest(model=model, reference=reference):
                self.assertRefused(self.edited("change", lambda row: row["property_action"].update(
                    place="model", model=model, reference=reference)), "change", f"{reference!r} is no invariant of the model")

    def judged_model(self, model, reference):
        """Judges the contract change with `reference` added in the model file `model`."""
        return self.edited("change", lambda row: row["property_action"].update(place="model", model=model, reference=reference))

    def stubbed_runner(self, root, edit):
        """Returns a patch of the `root` runner whose cases are the real ones passed through `edit`, with the
        property index cleared."""
        runner = verify.model_runner(root)
        stub = types.SimpleNamespace(**{name: getattr(runner, name) for name in dir(runner) if not name.startswith("__")})
        stub.cases = lambda: [changed for case in runner.cases() if (changed := edit(case)) is not None]
        self.cleared(verify.model_properties)
        return mock.patch.object(verify, "model_runner", lambda name: stub if name == root else runner)

    def test_each_filter_of_the_model_lookup_refuses_alone(self):
        self.cleared(verify.model_properties)
        quint, tla = ("quint/suffix.qnt", "Retained"), ("tla/Lifecycle.tla", "TypeOK")
        self.assertAdmitted(self.judged_model(*quint))
        self.assertAdmitted(self.judged_model(*tla))
        violated = lambda case: dataclasses.replace(case, expected="violation", depth=None) if case.family == "suffix" else case
        for root, model, edit in (
            ("quint", quint, violated),
            ("quint", quint, lambda case: dataclasses.replace(case, family="other") if case.family == "suffix" else case),
            ("quint", quint, lambda case: dataclasses.replace(case, mutations=[("x", "y")]) if case.family == "suffix" else case),
            ("tla", tla, lambda case: dataclasses.replace(case, expected="Error: Invariant TypeOK is violated.")),
            ("tla", tla, lambda case: dataclasses.replace(case, target="Other.tla", module="Other")),
            ("tla", tla, lambda case: dataclasses.replace(case, mutation=("TypeOK", "TypeOK"))),
            ("tla", tla, lambda case: dataclasses.replace(case, extra=case.extra + "CONSTANT TypeOK <- Other\n")),
            ("tla", tla, lambda case: dataclasses.replace(case, extra=case.extra + "CONSTANTS TypeOK <- Other\n")),
            ("tla", ("tla/Identity.tla", "PutCaps"),
             lambda case: dataclasses.replace(case, extra=case.extra + "CONSTANT PutCaps <- Other\n")),
        ):
            with self.subTest(root=root, edit=edit), self.stubbed_runner(root, edit):
                self.assertRefused(self.judged_model(*model), "change", f"{model[1]!r} is no invariant of the model")
        self.cleared(verify.model_properties)
        self.assertAdmitted(self.judged_model("tla/Identity.tla", "PutCaps"))
        def simulated(case):
            return case if case.family != "session" or case.command == "simulate" else None
        with self.stubbed_runner("quint", simulated):
            self.assertEqual([case.command for case in verify.model_runner("quint").cases() if case.family == "session"], ["simulate"])
            self.assertAdmitted(self.judged_model("quint/session.qnt", "safety"))
        with self.stubbed_runner("tla", lambda case: case):
            runner = verify.model_runner("tla")
            checked = runner.checked
            runner.checked = lambda config: {kind: [name for name in names if name != "Safety"]
                                             for kind, names in checked(config).items()}
            self.assertRefused(self.judged_model("tla/Identity.tla", "PutCaps"), "change", "'PutCaps' is no invariant of the model")

    def test_a_runner_that_cannot_load_or_list_its_cases_is_a_crash(self):
        def failing():
            raise ValueError("no cases")
        with self.stubbed_runner("quint", lambda case: case):
            verify.model_runner("quint").cases = failing
            with self.assertRaisesRegex(verify.Crash, "quint/check.py cannot list the properties of suffix.qnt: no cases"):
                self.judged_model("quint/suffix.qnt", "Retained")
        self.cleared(verify.model_runner, verify.model_properties)
        with mock.patch.object(verify, "load_script", side_effect=SyntaxError("broken")):
            with self.assertRaisesRegex(verify.Crash, "tla/check.py cannot be loaded: broken"):
                self.judged_model("tla/Lifecycle.tla", "TypeOK")

    def test_a_model_that_is_nested_or_no_utf8_text_is_refused(self):
        root = self.scratch({"quint/bad.qnt": b"\xff\xfe", "quint/nested/suffix.qnt": (verify.ROOT / "quint/suffix.qnt").read_text(),
                             "quint/suffix.qnt": b"", "tla/Lifecycle.tla": b""})
        (root / "quint/linked.qnt").symlink_to(root / "quint/nested/suffix.qnt")
        self.cleared(verify.model_properties, verify.bounded_text)
        with mock.patch.object(verify, "ROOT", root):
            self.assertIn("cannot be read", verify.model_gap("quint/bad.qnt", "safety"))
            for model in ("quint/nested/suffix.qnt", "quint/linked.qnt", "quint/bad.tla", "tla/Lifecycle.qnt"):
                with self.subTest(model=model):
                    self.assertIn("is no file under tla/ or quint/ that its runner reads", verify.model_gap(model, "Retained"))

    def test_a_quint_definition_counts_only_in_code_and_a_block_conjunction_is_followed(self):
        source = ("module m {\n  val safety = and {\n    first,\n    second,\n  }\n  /*\n  val safety = hidden\n  */\n"
                  "  // val first = commented\n  val first = third and (x or y) and Q::r\n  val second = a or b\n"
                  "  val third = \"// not a comment\" == s\n}\n")
        code = verify.quint_code(source)
        self.assertNotIn("hidden", code)
        self.assertIn('"// not a comment"', code)
        self.assertEqual(verify.quint_reached(code, "", "safety"), {"safety", "first", "second", "third"})
        self.assertEqual(verify.quint_reached(code, "  val wrap = safety and extraOnly\n", "wrap"),
                         {"wrap", "safety", "first", "second", "third", "extraOnly"})
        self.assertEqual(verify.quint_conjuncts("a and b or c"), [])
        self.assertEqual(verify.quint_conjuncts("if (c) a else b and d"), [])
        for body in ("a and f(x and y and z) and b", "a and (x) and b", "a and xs[i and j and k] and b",
                     "a and r{p and q and s} and b", "(x) and a and b", "and { a, f(x, y, z), b }", "and { a, xs[y, z], {y, z}, b }"):
            with self.subTest(body=body):
                self.assertEqual(verify.quint_conjuncts(body), ["a", "b"])
        for body in ("a and (b) or c", "a and xs[0] or c", "a and r{p} or c", "a and f(x) implies c"):
            with self.subTest(body=body):
                self.assertEqual(verify.quint_conjuncts(body), [])

    def test_a_quint_definition_inside_a_comment_of_the_model_is_no_property(self):
        model = (verify.ROOT / "quint/suffix.qnt").read_text()
        body, closed = model.rstrip().rsplit("\n", 1)
        self.assertEqual(closed, "}")
        root = self.scratch({"quint/suffix.qnt": f"{body}\n  /*\n  val safety = Hidden\n  val Hidden = true\n  */\n}}\n"})
        self.cleared(verify.model_properties, verify.bounded_text)
        with mock.patch.object(verify, "ROOT", root):
            self.assertIsNone(verify.model_gap("quint/suffix.qnt", "safety"))
            self.assertIsNone(verify.model_gap("quint/suffix.qnt", "Retained"))
            self.assertEqual(verify.model_gap("quint/suffix.qnt", "Hidden"),
                             "'Hidden' is no invariant of the model 'quint/suffix.qnt'")

    def test_an_incident_is_admitted_only_with_its_property_action(self):
        incident = {"id": "incident-1", "kind": "incident", "issue": 1}
        self.put("incident-1", incident)
        self.assertRefused(self.judge(), "incident-1", "lacks property_action")
        self.put("incident-1", {**incident, "property_action": {"action": "none", "reason": "the issue names no property"}})
        self.assertEqual(self.assertAdmitted(self.judge())["intake"]["incident"], 1)

    def test_a_disagreement_with_holds_and_no_corrected_or_without_both_sources_is_refused(self):
        for edit, fragment in (
            (lambda row: row.update(holds="source one"), "holds and no corrected pull request by number"),
            (lambda row: row.update(holds="source one", corrected=0), "holds and no corrected pull request by number"),
            (lambda row: row.update(holds="source one", corrected=-2200), "holds and no corrected pull request by number"),
            (lambda row: row.update(holds="source one", corrected=True), "holds and no corrected pull request by number"),
            (lambda row: row.update(holds="source one", corrected="blotter pull request 2200"), "holds and no corrected pull request by number"),
            (lambda row: row["sources"].pop(), "sources needs two citations"),
            (lambda row: row.pop("sources"), "sources needs two citations"),
            (lambda row: row["sources"].__setitem__(1, " "), "sources needs two citations"),
            (lambda row: row["sources"].append("source three"), "sources needs two citations"),
            (lambda row: row["sources"].__setitem__(1, " source one "), "sources needs two citations"),
            (lambda row: row.update(corrected=2200), "holds corrected and no holds"),
        ):
            with self.subTest(fragment=fragment):
                self.assertRefused(self.edited("dispute", edit), "dispute", fragment)
        opened = self.assertAdmitted(self.edited("dispute", lambda row: row.update(holds="source one", corrected=2200)))
        self.assertEqual(opened["open_disagreements"], [])

    def test_a_refused_disagreement_lists_as_open_without_its_sources(self):
        refusals, opened = self.edited("dispute", lambda row: row.update(sources=[[["deep"]], {"a": 1}]))
        self.assertIn({"code": "intake", "record": "dispute", "reason": "sources needs two citations"}, refusals)
        self.assertEqual(opened["open_disagreements"], [{"id": "dispute", "sources": []}])

    def test_a_field_of_the_wrong_type_is_refused_and_not_a_crash(self):
        self.assertRefused(self.edited("open", lambda row: row.update(cause=["workload"])), "open", "cause ['workload'] is none of")
        self.assertRefused(self.edited("open", self.caught(history=["x"])), "open", "catch.history ['x'] is no quoted history name")
        self.assertRefused(self.edited("open", self.caught(history="")), "open", "catch.history '' is no quoted history name")
        self.assertRefused(self.edited("open", self.caught(rule={})), "open", "catch.rule {} is no rule text")
        self.assertRefused(self.edited("open", self.caught(tally=None)), "open", "catch.tally is no object")
        self.assertRefused(self.edited("open", lambda row: row["property"].update(place="model", model=["tla"], pointer="TypeOK")),
                           "open", "is no file under tla/ or quint/")
        self.assertRefused(self.edited("excluded", lambda row: row["fix"]["regression"].update(path={"p": 1})),
                           "excluded", "is no Rust source of a crate")
        self.assertRefused(self.edited("gap", lambda e: e.update(covers=5), "exclusions"),
                           "excluded", "exclusion gap does not cover excluded")
        for edit, fragment in ((lambda row: row.update(holds=None, corrected=None), "holds, when present, states the owner's answer"),
                               (lambda row: row.update(holds=None, corrected=None), "holds and no corrected pull request by number")):
            self.assertRefused(self.edited("dispute", edit), "dispute", fragment)

    def test_a_guarded_field_of_the_wrong_type_is_refused_and_every_agreed_place_admits_an_open_row(self):
        for name, edit, fragment in (
            ("open", lambda row: row.update(property="the record's invariant"), "property needs its text, a pointer and a place"),
            ("open", lambda row: row.update(fix="not-delivered"), "fix needs a state among"),
            ("excluded", lambda row: row["fix"].update(regression="identity_tests"), "fix.regression needs a path and its tests"),
            ("excluded", lambda row: row.update(exclusion=["gap"]), "exclusion ['gap'] names no file"),
            ("open", lambda row: [row.update(fix="merged"), row["site"].pop("path")], "site needs a path and a function"),
        ):
            with self.subTest(fragment=fragment):
                self.assertRefused(self.edited(name, edit), name, fragment)
        self.assertEqual(verify.AGREED_PLACES, ("obligation", "rule", "spec", "documentation", "model", "pull-request"))
        for place in ("spec", "pull-request"):
            with self.subTest(place=place):
                self.assertAdmitted(self.edited("open", lambda row: row["property"].update(place=place, pointer="#297 R3")))

    def test_a_shape_invalid_catalog_record_resolves_no_reference(self):
        catalog = copy.deepcopy(CATALOG)
        record = next(r for r in catalog["records"] if r["id"] == self.RECORD)
        del record["reference"]
        refusals, _ = verify.intake_judgment(catalog, self.register)
        fragment = f"{self.RECORD!r} is no record id of verification/obligations.json"
        self.assertIn({"code": "intake", "record": "open", "reason": f"property {fragment}"}, refusals)
        self.assertIn({"code": "intake", "record": "change", "reason": f"property_action added {fragment}"}, refusals)

    def test_the_catalog_is_read_strictly(self):
        scratch = self.scratch({"repeated.json": '{"baseline": "a", "baseline": "b", "records": []}',
                                "nan.json": '{"baseline": NaN, "records": []}'})
        for name, fragment in (("repeated.json", "repeats the member 'baseline'"), ("nan.json", "holds NaN")):
            with self.subTest(name=name), mock.patch.object(verify, "CATALOG", scratch / name):
                with self.assertRaisesRegex(verify.Crash, fragment):
                    verify.read_catalog()

    def test_a_history_resolves_in_either_source_and_only_by_a_history_name(self):
        sources = [verify.WORLD_TESTS / "histories.rs", *(verify.WORLD_TESTS / "histories").rglob("*.rs")]
        declared = sum(int(n) for path in sources for n in re.findall(r"\[History; (\d+)\]", path.read_text()))
        self.assertEqual(len(verify.history_names()), declared)
        for history in ("h1-get-stale", "cr1-get-cancelled-on-a-held-read", "de1-publish-at-deadline"):
            with self.subTest(history=history):
                self.assertAdmitted(self.edited("open", self.caught(history=history)))
        for history in (self.CATCH["rule"], "A holds no GET", "a-get"):
            with self.subTest(history=history):
                self.assertRefused(self.edited("open", self.caught(history=history)), "open",
                                   "is no quoted history name in the history sources")

    RULES = (
        'const ORACLE: &[&str] = &[\n    "a rule // with a slash",\n    // "a commented rule",\n'
        '    /* "a blocked rule", /* nested */ "a nested rule", */\n    r"a raw rule",\n    "a last rule",\n];\n'
        'const RETIRED: &[&str] = &["a retired rule"];\nconst P: &str = r"\\";\n// "a rule after a raw string"\n'
        'const INLINE: &[&str] = &["an inline rule"];\n'
        'pub(crate) fn scoped() -> impl Iterator<Item = (&\'static str, &\'static str)> {\n'
        '    scope("oracle", ORACLE).chain(scope("inline", INLINE))\n}\n')
    HISTORIES = (
        'mod family;\nfn history(name: &\'static str) -> History { todo!() }\n'
        'const H: [History; 2] = [history("h-live"), /* history("h-blocked") /* x */ history("h-nested") */\n'
        '    history("h-after-char-\'"),\n];\nconst Q: char = \'"\';\n'
        'const UNCHAINED: [History; 1] = [history("h-unchained")];\n// history("h-commented")\n'
        'pub(crate) fn every() -> impl Iterator<Item = &\'static History> {\n    H\n        .iter()\n        .chain(scenarios())\n}\n'
        'fn scenarios() -> impl Iterator<Item = &\'static History> {\n    family::FAMILY.iter()\n}\n')

    def test_a_rule_or_history_counts_only_in_code_and_in_the_arrays_the_narrator_and_every_chain(self):
        scratch = self.scratch({"narrate/rules.rs": self.RULES, "histories.rs": self.HISTORIES,
                                "histories/family.rs": 'const FAMILY: [History; 1] = [history("h-family")];\n'})
        self.cleared(verify.rule_texts, verify.history_names)
        with mock.patch.object(verify, "WORLD_TESTS", scratch):
            self.assertEqual(verify.rule_texts(), {"a rule // with a slash", "a raw rule", "a last rule", "an inline rule"})
            self.assertEqual(verify.history_names(), {"h-live", "h-after-char-'", "h-family"})
        for name, text, fragment in (
            ("histories/family.rs", None, "cannot be read"),
            ("histories.rs", self.HISTORIES.replace("mod family;", ""), "whose module it does not declare"),
            ("histories/family.rs", "/* const FAMILY: [History; 1] = [];\n", "opens a block comment that never closes"),
            ("histories/family.rs", "const FAMILY: &[History] = &[];\n", "chains FAMILY, which family.rs declares as no"),
        ):
            with self.subTest(fragment=fragment):
                broken = self.scratch({"narrate/rules.rs": self.RULES, "histories.rs": self.HISTORIES,
                                       "histories/family.rs": 'const FAMILY: [History; 1] = [history("h-family")];\n'})
                if text is None:
                    (broken / name).unlink()
                    os.mkfifo(broken / name)
                else:
                    (broken / name).write_text(text)
                verify.history_names.cache_clear()
                with mock.patch.object(verify, "WORLD_TESTS", broken), self.assertRaisesRegex(verify.Crash, fragment):
                    verify.history_names()

    def test_an_indexed_source_that_leaves_its_directory_or_is_no_regular_file_is_a_crash(self):
        outside = self.scratch({"rules.rs": self.RULES})
        for make in (lambda path: path.symlink_to(outside / "rules.rs"), os.mkfifo):
            scratch = self.scratch({})
            (scratch / "narrate").mkdir()
            make(scratch / "narrate/rules.rs")
            self.cleared(verify.rule_texts)
            with self.subTest(make=make), mock.patch.object(verify, "WORLD_TESTS", scratch):
                with self.assertRaisesRegex(verify.Crash, "narrate/rules.rs cannot be read"):
                    verify.rule_texts()

    def test_a_regression_resolves_through_the_module_declarations_of_its_target(self):
        for path, test in (
            ("crates/kestrike/src/failover/zone_loop_tests/config.rs",
             "failover::zone_loop::tests::config::the_default_configuration_validates"),
            ("crates/campaign-monitor/src/signals_tests.rs",
             "signals::tests::an_unresolved_failure_group_is_new_when_the_newest_earlier_sample_lacks_its_identity"),
            ("crates/kestrike/tests/inspect_cli.rs", "a_non_utf8_image_path_is_read_unchanged_and_verifies"),
        ):
            with self.subTest(test=test):
                self.assertAdmitted(self.edited("excluded", lambda row: row["fix"].update(
                    regression={"path": path, "tests": [test]})))
        for path, test in (
            ("crates/kestrike/src/failover/zone_loop_tests/config.rs",
             "failover::zone_loop_tests::config::the_default_configuration_validates"),
            ("crates/campaign-monitor/src/signals_tests.rs",
             "signals_tests::an_unresolved_failure_group_is_new_when_the_newest_earlier_sample_lacks_its_identity"),
            ("crates/kestrike/tests/inspect_cli.rs", "inspect_cli::a_non_utf8_image_path_is_read_unchanged_and_verifies"),
            (self.REGRESSION["path"], "tree::" + self.REGRESSION["tests"][0]),
        ):
            with self.subTest(alias=test):
                self.assertRefused(self.edited("excluded", lambda row: row["fix"].update(
                    regression={"path": path, "tests": [test]})), "excluded", f"declares no #[test] fn {test!r}")

    def test_a_regression_counts_only_a_declared_test_fn_in_code(self):
        root = self.scratch({
            "crates/demo/Cargo.toml": '[package]\nname = "demo"\n',
            "crates/demo/src/lib.rs": '#[cfg(test)]\nmod a;\n// mod gone;\nmod b {\n    #[cfg(test)]\n    mod c;\n'
                                      '    const B: (&str, char) = ("}", \'}\');\n    #[test]\n    fn inner() {}\n    include!("inc.rs");\n}\n'
                                      '#[test]\nfn after() {}\nmod cycle;\n#[path = "renamed.rs"]\nmod moved;\n'
                                      '#[cfg(any())]\n#[path = "a.rs"]\nmod off;\n'
                                      '#[cfg(false)]\nmod never {\n    #[test]\n    fn unbuilt() {}\n}\n'
                                      '#[cfg(any())]\n#[test]\nfn disabled() {}\n',
            "crates/demo/src/a.rs": '/* #[test]\nfn blocked() {} */\n#[cfg_attr(\n    miri,\n    ignore\n)]\n#[test]\n'
                                    'fn wrapped() {}\nconst S: &str = "#[test] fn quoted() {}";\nfn plain() {}\n'
                                    '/*\n#[test]\nfn blocked_lines() {}\n*/\nconst T: &str = "\n#[test]\nfn quoted_lines() {}\n";\n'
                                    '#[cfg(test)]\nfn helper() {}\n'
                                    '#[test]\n// a line comment\n\n/// a doc comment\nfn commented() {}\n',
            "crates/demo/src/gone.rs": "#[test]\nfn undeclared() {}\n",
            "crates/demo/src/b/c.rs": "#[test]\nfn nested() {}\n",
            "crates/demo/src/open.rs": "/* never closed\n",
            "crates/demo/src/main.rs": "mod cli;\n",
            "crates/demo/src/cli.rs": "#[test]\nfn parses() {}\n",
            "crates/demo/src/inc.rs": "mod d;\n",
            "crates/demo/src/b/d.rs": "#[test]\nfn included() {}\n",
            "crates/demo/src/d.rs": "#[test]\nfn included() {}\n",
            "crates/demo/src/cycle.rs": 'include!("cycle.rs");\n#[test]\nfn turns() {}\n',
            "crates/demo/src/renamed.rs": "#[test]\nfn relocated() {}\n",
            "crates/demo/tests/flat.rs": '#[path = "flat/part.rs"]\nmod part;\n',
            "crates/demo/tests/flat/part.rs": "#[test]\nfn split() {}\n",
            "crates/demo/tests/deep/main.rs": "mod part;\n",
            "crates/demo/tests/deep/part.rs": "#[test]\nfn held() {}\n",
            "crates/demo/tests/lone/part.rs": "#[test]\nfn rootless() {}\n",
            "crates/demo/benches/bench.rs": "#[test]\nfn measured() {}\n",
            "crates/demo/src/notes.md": "#[test]\nfn noted() {}\n",
            "crates/demo/build.rs": "#[test]\nfn built() {}\n",
            "crates/loose.rs": "#[test]\nfn loose() {}\n",
            "tools/demo/src/lib.rs": "#[test]\nfn tooled() {}\n",
        })
        with mock.patch.object(verify, "ROOT", root):
            def gap(path, test):
                return verify.regression_gap(verify.regression_target(path), test)
            self.assertIsNone(gap("crates/demo/src/a.rs", "a::wrapped"))
            self.assertIsNone(gap("crates/demo/src/a.rs", "a::commented"))
            self.assertIsNone(gap("crates/demo/src/b/c.rs", "b::c::nested"))
            self.assertIsNone(gap("crates/demo/src/lib.rs", "b::inner"))
            self.assertIsNone(gap("crates/demo/src/lib.rs", "after"))
            self.assertIsNone(gap("crates/demo/src/cli.rs", "cli::parses"))
            self.assertIsNone(gap("crates/demo/src/b/d.rs", "b::d::included"))
            self.assertIsNone(gap("crates/demo/src/cycle.rs", "cycle::turns"))
            self.assertIsNone(gap("crates/demo/src/renamed.rs", "moved::relocated"))
            self.assertIsNone(gap("crates/demo/tests/flat/part.rs", "part::split"))
            self.assertIsNone(gap("crates/demo/tests/deep/part.rs", "part::held"))
            for path in ("crates/demo/benches/bench.rs", "crates/demo/src/notes.md", "crates/demo/build.rs", "crates/loose.rs",
                         "tools/demo/src/lib.rs", "crates/demo/src", "crates/demo/src/absent.rs",
                         "crates/demo/tests/lone/part.rs"):
                with self.subTest(path=path):
                    self.assertIsNone(verify.regression_target(path))
            for path, test in (("crates/demo/src/a.rs", "a::blocked"), ("crates/demo/src/a.rs", "a::quoted"),
                               ("crates/demo/src/a.rs", "a::plain"), ("crates/demo/src/gone.rs", "gone::undeclared"),
                               ("crates/demo/src/b/c.rs", "c::nested"), ("crates/demo/src/a.rs", "a::blocked_lines"),
                               ("crates/demo/src/a.rs", "a::quoted_lines"), ("crates/demo/src/a.rs", "a::helper"),
                               ("crates/demo/src/lib.rs", "inner"), ("crates/demo/src/lib.rs", "b::after"),
                               ("crates/demo/src/d.rs", "d::included"), ("crates/demo/src/cycle.rs", "cycle::inner::turns"),
                               ("crates/demo/src/renamed.rs", "renamed::relocated"),
                               ("crates/demo/src/a.rs", "off::wrapped"), ("crates/demo/src/lib.rs", "never::unbuilt"),
                               ("crates/demo/src/lib.rs", "disabled"),
                               ("crates/demo/tests/flat/part.rs", "flat::part::split"),
                               ("crates/demo/tests/flat/part.rs", "split")):
                with self.subTest(test=test):
                    self.assertEqual(gap(path, test), f"fix.regression {path!r} declares no #[test] fn {test!r}")
            (root / "crates/demo/src/lib.rs").write_text("mod open;\n")
            verify.crate_source.cache_clear()
            verify.bounded_text.cache_clear()
            self.assertIn("opens a block comment that never closes", gap("crates/demo/src/open.rs", "open::x"))
        verify.crate_source.cache_clear()
        verify.bounded_text.cache_clear()

    def test_a_regression_list_is_checked_once_per_path_and_refuses_a_repeated_test(self):
        test = self.REGRESSION["tests"][0]
        refusals, _ = self.edited("excluded", lambda row: row["fix"]["regression"].update(tests=[test, test]))
        self.assertEqual([r["reason"] for r in refusals], [f"fix.regression lists the test {test!r} more than once"])
        refusals, _ = self.edited("excluded", lambda row: row["fix"]["regression"].update(path="/etc/passwd", tests=["a::b", "a::c"]))
        self.assertEqual([r["reason"] for r in refusals],
                         ["fix.regression '/etc/passwd' is no Rust source of a crate's src or tests"])

    def test_a_merged_site_is_still_a_path_relative_to_the_checkout(self):
        for path in ("/usr/bin/ls", "../outside.rs"):
            with self.subTest(path=path):
                self.assertRefused(self.edited("excluded", lambda row: row["site"].update(path=path)), "excluded",
                                   "the path relative to the checkout")

    def test_admit_refuses_an_intake_row_with_code_intake(self):
        self.put("open", "[]")
        self.put("dispute", {**self.ROWS["dispute"], "sources": [[[["deep"]]], "one"]})
        code, report = self.admit_report(self.register)
        self.assertEqual((code, report["credited"]), (verify.REFUSED, False), report)
        self.assertEqual({r["code"] for r in report["refusals"]}, {"intake"})
        self.assertIn("intake", verify.REFUSALS)
        self.assertEqual((report["command"], report["records"], report["census_needs_kernel"]),
                         ("admit", len(CATALOG["records"]), []))
        self.assertIn({"code": "intake", "record": "open", "reason": "open.json is no JSON object"}, report["refusals"])
        self.assertIn({"code": "intake", "record": "dispute", "reason": "sources needs two citations"}, report["refusals"])
        self.assertEqual(report["open_disagreements"], [{"id": "dispute", "sources": []}])
        self.assertEqual(report["intake"]["escape"], 2)

    def test_admit_refuses_an_absent_register(self):
        code, report = self.admit_report(self.register.parent / "absent")
        self.assertEqual((code, report["credited"]), (verify.REFUSED, False), report)
        self.assertEqual([r["record"] for r in report["refusals"]], ["."], report)

    REVIEW_RULES = (
        "An intake row's `evidence` supports its `cause` with a run or a file a reviewer can read",
        "A cause without that evidence is unverified",
        "A pull request that fixes an escape, changing the code its row's `site` names, sets that row's `fix`",
        "A reviewer reports such a pull request that leaves the row unchanged",
        "A pull request is a contract change when it changes an `invariant` of `verification/obligations.json`, a rule text of "
        "`crates/kestrike/src/net/world_tests/narrate/rules.rs`, a model under `tla/` or `quint/`, or an item a row of "
        "`verification/models/links.json` cites",
        "It adds its `contract-change` row with `property_action`",
        "A reviewer reports a contract change without its row",
    )

    def test_the_guide_states_the_review_rules_and_every_word_admit_reads_and_review_md_points_at_it(self):
        self.assertIn("(docs/agents/ci.md#intake)", (verify.ROOT / "REVIEW.md").read_text())
        guide = (verify.ROOT / "docs/agents/ci.md").read_text()
        self.assertEqual(guide.count("\n### Intake\n"), 1)
        section = " ".join(guide.split("\n### Intake\n", 1)[1].split("\n## ", 1)[0].split())
        for rule in self.REVIEW_RULES:
            with self.subTest(rule=rule):
                self.assertIn(rule, section)
        words = [*verify.INTAKE_KINDS, *verify.ESCAPE_CLASSES, *verify.AGREED_PLACES, *verify.CAUSE_EVIDENCE,
                 *(key for keys in verify.CAUSE_EVIDENCE.values() for key in keys), *verify.CATCH_FIELDS,
                 *verify.FIX_STATES, *verify.ACTION_PLACES, "id", "kind", "class", "property", "site", "fix", "pair",
                 "cause", "evidence", "catch", "exclusion", "property_action", "sources", "holds", "corrected",
                 "reason", "covers", "approval", "added", "none", "reference", "pull_request", "fix.regression",
                 "catch.also"]
        for word in words:
            with self.subTest(word=word):
                self.assertIn(f"`{word}`", section)
        for cause, (first, second) in verify.CAUSE_EVIDENCE.items():
            with self.subTest(cause=cause):
                self.assertIn(f"`{first}` and `{second}`", section)

    def test_the_simulation_guide_counts_every_model_directory_admit_resolves_as_an_agreed_place(self):
        guide = " ".join((verify.ROOT / "docs/agents/simulation.md").read_text().split())
        roots = " or ".join(f"`{root}/`" for root in verify.MODEL_SUFFIXES)
        self.assertEqual(roots, "`tla/` or `quint/`")
        self.assertIn(f"5. An invariant of a model under {roots}.", guide.split("## An agreed property", 1)[1].split(" ## ", 1)[0])
        self.assertIn(f"5. When a model under {roots} covers the property, its model case passes.",
                      guide.split("## Prove a bug", 1)[1].split(" ## ", 1)[0])


class ControlRatchet(unittest.TestCase):
    """The control ratchet inside `admit`, each case fed a synthetic catalog of two listed records and a controlled
    one, and a scratch list."""

    LISTED = ("legacy-a", "legacy-b")

    @staticmethod
    def record(name, controls=()):
        return {"id": name, "property": "p", "transition": "t", "invariant": "i", "job": "workspace", "tests": ["a_test"],
                "controls": list(controls), "reference": "r"}

    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="kestrike-ratchet-")
        self.addCleanup(temp.cleanup)
        self.list = Path(temp.name) / "control-less.json"
        self.controlled = self.record("controlled", [{"test": "a_control", "violation": "v"}])
        self.catalog = {"records": [*(self.record(name) for name in self.LISTED), self.controlled]}
        self.new = self.record("a-new-record-without-a-control")

    def judge(self, listed=None, added=()):
        self.list.write_text(json.dumps(sorted(self.LISTED if listed is None else listed), indent=2) + "\n")
        return verify.ratchet_judgment({"records": [*self.catalog["records"], *added]}, self.list)

    def assertRefused(self, judgment, record, fragment):
        refusals, _ = judgment
        self.assertEqual({r["code"] for r in refusals}, {"control-ratchet"}, refusals)
        self.assertIn("control-ratchet", verify.REFUSALS)
        self.assertEqual([(r["record"], fragment in r["reason"]) for r in refusals], [(record, True)], refusals)

    def test_a_new_control_less_record_off_the_list_without_a_reason_is_refused(self):
        self.assertRefused(self.judge(added=[self.new]), self.new["id"], "add a control, or record the reason")

    def test_the_same_record_with_a_no_control_reason_is_admitted(self):
        self.assertEqual(self.judge(added=[{**self.new, "no_control": "its property has no violating input"}]),
                         ([], len(self.LISTED)))

    def test_a_listed_record_is_admitted(self):
        self.assertEqual(self.judge([*self.LISTED, self.new["id"]], added=[self.new]), ([], len(self.LISTED) + 1))

    def test_an_empty_list_admits_reasoned_records_and_refuses_an_unreasoned_one(self):
        self.catalog = {"records": [*({**self.record(name), "no_control": "a reason"} for name in self.LISTED), self.controlled]}
        self.assertEqual(self.judge([]), ([], 0))
        judgment = self.judge([], added=[self.new])
        self.assertRefused(judgment, self.new["id"], "add a control, or record the reason")
        self.assertEqual(judgment[1], 0)

    def test_a_list_entry_whose_record_has_a_control_is_refused(self):
        self.assertRefused(self.judge([*self.LISTED, self.controlled["id"]]), self.controlled["id"],
                           "the record has a control: remove its entry from")

    def test_a_list_entry_without_a_record_or_with_a_reason_is_refused(self):
        self.assertRefused(self.judge([*self.LISTED, "no-such-record"]), "no-such-record", "names no catalog record")
        reasoned = {**self.new, "no_control": "its property has no violating input"}
        self.assertRefused(self.judge([*self.LISTED, reasoned["id"]], added=[reasoned]), reasoned["id"],
                           "carries a no_control reason: remove its entry from")

    def test_a_malformed_record_carries_only_the_records_refusal_on_or_off_the_list(self):
        malformed = {key: value for key, value in self.new.items() if key != "transition"}
        self.assertIsNotNone(verify.check_shape(malformed))
        self.assertEqual(self.judge([*self.LISTED, malformed["id"]], added=[malformed]), ([], len(self.LISTED) + 1))
        self.assertEqual(self.judge(added=[malformed]), ([], len(self.LISTED)))

    def test_a_record_with_a_non_text_id_carries_only_the_records_refusal(self):
        for name in ([], {}):
            with self.subTest(id=name):
                self.assertEqual(self.judge(added=[{**self.new, "id": name}]), ([], len(self.LISTED)))

    def test_a_listed_record_with_a_blank_reason_is_told_only_to_state_one(self):
        for blank in (" ", True, None):
            with self.subTest(no_control=blank):
                record = {**self.new, "no_control": blank}
                self.assertRefused(self.judge([*self.LISTED, record["id"]], added=[record]), record["id"], "must state the reason")

    def test_a_blank_reason_or_a_reason_beside_a_control_is_refused(self):
        for blank in (" ", True, None):
            with self.subTest(no_control=blank):
                self.assertRefused(self.judge(added=[{**self.new, "no_control": blank}]), self.new["id"], "must state the reason")
        for reason in ("a reason", " ", True, None):
            with self.subTest(beside=reason):
                beside = {**self.controlled, "id": "a-controlled-copy", "no_control": reason}
                self.assertRefused(self.judge(added=[beside]), beside["id"], "the record has a control: remove its no_control member")

    def test_an_unsorted_or_repeating_list_is_refused(self):
        for listed in ([self.LISTED[0], *self.LISTED], list(reversed(self.LISTED))):
            self.list.write_text(json.dumps(listed))
            self.assertRefused(verify.ratchet_judgment(self.catalog, self.list), None, "sorted list of distinct")
        for listed in ({"ids": list(self.LISTED)}, [*self.LISTED, 7]):
            self.list.write_text(json.dumps(listed))
            self.assertEqual(verify.ratchet_judgment(self.catalog, self.list),
                             ([{"code": "control-ratchet", "record": None, "reason": "control-less.json is no list of record ids"}], 0))

    def admit(self):
        catalog = self.list.with_name("obligations.json")
        catalog.write_text(json.dumps(self.catalog))
        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            for patch in (mock.patch.object(verify, "CONTROL_LESS", self.list), mock.patch.object(verify, "CATALOG", catalog),
                          mock.patch.object(verify, "admit", return_value=[]),
                          mock.patch.object(verify, "census_judgment", return_value=([], [])),
                          mock.patch.object(verify, "intake_judgment", return_value=([], {})),
                          contextlib.redirect_stdout(out), contextlib.redirect_stderr(io.StringIO())):
                stack.enter_context(patch)
            code = verify.main(["admit"])
        return code, json.loads(out.getvalue())

    def test_admit_refuses_with_code_control_ratchet_and_prints_the_lists_length(self):
        self.list.write_text(json.dumps(self.LISTED[1:]))
        code, report = self.admit()
        self.assertEqual((code, report["credited"], report["control_less"]), (verify.REFUSED, False, len(self.LISTED) - 1), report)
        self.assertEqual([(r["code"], r["record"]) for r in report["refusals"]], [("control-ratchet", self.LISTED[0])])

    def test_admit_crashes_on_a_missing_or_unparsable_list(self):
        for name, contents in (("a missing list", None), ("conflict markers", "<<<<<<< HEAD\n[]\n=======\n[]\n>>>>>>> x\n")):
            with self.subTest(name):
                self.list.unlink(missing_ok=True)
                if contents is not None:
                    self.list.write_text(contents)
                code, report = self.admit()
                self.assertEqual((code, report["credited"]), (verify.CRASHED, False), report)
                self.assertIn(f"unreadable {self.list}", report["crash"])


if __name__ == "__main__":
    unittest.main()
