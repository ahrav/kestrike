#!/usr/bin/env python3
"""Exercise Git hooks in disposable repositories without changing this checkout."""

import ast
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
ZERO = "0" * 40
DELETION = f"(delete) {ZERO} refs/heads/gone {'1' * 40}\n"

# Each stub records its run in $STUB_LOG and exits with the status its
# STUB_<NAME> variable names, so a test can fail one check and see which ran.
STUB = """import os, sys
name = os.path.basename(sys.argv[0])
with open(os.environ["STUB_LOG"], "a") as log:
    log.write(" ".join([name, *sys.argv[1:]]) + "\\n")
sys.exit(int(os.environ.get("STUB_" + name.replace("-", "_").replace(".py", "").upper(), "0")))
"""


def hook_module():
    """Load scripts/pre-push-checks.py as a module once, writing no bytecode beside it."""
    if "pre_push_checks" not in sys.modules:
        spec = importlib.util.spec_from_file_location("pre_push_checks", ROOT / "scripts/pre-push-checks.py")
        if spec is None or spec.loader is None:
            raise ImportError("scripts/pre-push-checks.py cannot be loaded")
        module = importlib.util.module_from_spec(spec)
        writes, sys.dont_write_bytecode = sys.dont_write_bytecode, True
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = writes
        sys.modules["pre_push_checks"] = module
    return sys.modules["pre_push_checks"]

class AgentHooks(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-hooks-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name)
        self.env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1",
            GIT_CONFIG_GLOBAL=str(self.repo / "global-config"),
        )
        self.run_command("git", "init", "-q", check=True)

    def run_command(self, *args, check=False, input=""):
        return subprocess.run(
            args, cwd=self.repo, env=self.env, text=True,
            input=input, capture_output=True, check=check,
        )

    def test_pre_push_preserves_global_guard_arguments_input_and_failure(self):
        hooks = self.repo / "shared hooks"
        hooks.mkdir()
        guard = hooks / "pre-push"
        guard.write_text('#!/bin/sh\nprintf "%s\\n" "$@"\ncat\nexit 37\n')
        guard.chmod(0o755)
        for mode in ("direct", "include", "includeIf"):
            with self.subTest(mode=mode):
                config = self.repo / "global-config"
                config.write_text("")
                if mode == "direct":
                    self.run_command("git", "config", "--global", "core.hooksPath", str(hooks), check=True)
                else:
                    included = self.repo / "included-config"
                    self.run_command("git", "config", "--file", str(included), "core.hooksPath", str(hooks), check=True)
                    key = "include.path" if mode == "include" else f"includeIf.gitdir:{self.repo}/.path"
                    self.run_command("git", "config", "--global", key, str(included), check=True)
                result = self.run_command(
                    "bash", str(ROOT / ".githooks/pre-push"), "origin", "remote-url",
                    input=DELETION,
                )
                self.assertEqual(result.returncode, 37)
                self.assertEqual(result.stdout, "origin\nremote-url\n" + DELETION)

    def test_pre_push_without_global_hook_path_passes(self):
        result = self.run_command("bash", str(ROOT / ".githooks/pre-push"))
        self.assertEqual(result.returncode, 0)

    def test_pre_push_honors_explicitly_disabled_global_hooks(self):
        for value in ("/dev/null", ""):
            with self.subTest(hooks_path=value):
                self.run_command("git", "config", "--global", "core.hooksPath", value, check=True)
                result = self.run_command("bash", str(ROOT / ".githooks/pre-push"))
                self.assertEqual(result.returncode, 0)

    def test_pre_push_missing_configured_guard_fails(self):
        self.run_command("git", "config", "--global", "core.hooksPath", str(self.repo / "missing"), check=True)
        result = self.run_command("bash", str(ROOT / ".githooks/pre-push"))
        self.assertNotEqual(result.returncode, 0)

    def test_pre_push_self_delegation_fails(self):
        self.run_command("git", "config", "--global", "core.hooksPath", str(ROOT / ".githooks"), check=True)
        result = self.run_command("bash", str(ROOT / ".githooks/pre-push"))
        self.assertEqual(result.returncode, 2)


class PrePushChecks(unittest.TestCase):
    """The pre-push hook runs the checks the pushed commits need, on their content."""

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-pre-push-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.log = Path(self.temp.name) / "stub.log"
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITHUB_"))}
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(Path(self.temp.name) / "global"),
            GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
            STUB_LOG=str(self.log),
        )
        self.git("init", "-q", "-b", "main")
        files = {f"scripts/{name}": STUB for name in
                 ("test-select-tests.py", "verify-receipts.py", "judge-verus.py")}
        files["verification/verus/inventory.json"] = '{"sources": {"crates/v.rs": "d"}}'
        files["crates/v.rs"] = "v\n"
        files["crates/plain.rs"] = "p\n"
        files["scripts/test-inventory.json"] = "{}"
        self.base = self.commit(files)
        self.git("update-ref", "refs/remotes/origin/main", self.base)

    def git(self, *args):
        return subprocess.run(("git", *args), cwd=self.repo, env=self.env, text=True,
                              capture_output=True, check=True).stdout.strip()

    def commit(self, files, message="change"):
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            self.git("add", "--", name)
        self.git("commit", "-q", "-m", message)
        return self.git("rev-parse", "HEAD")

    def push(self, local, remote=ZERO, *more, cwd=None, **status):
        env = dict(self.env, **{f"STUB_{k.upper()}": str(v) for k, v in status.items()})
        lines = [(local, remote), *zip(more[::2], more[1::2])]
        return subprocess.run(
            ("bash", str(ROOT / ".githooks/pre-push"), "origin", "url"), cwd=cwd or self.repo, env=env,
            text=True, capture_output=True,
            input="".join(f"refs/heads/x {a} refs/heads/x {b}\n" for a, b in lines),
        )

    def ran(self):
        return self.log.read_text().splitlines() if self.log.exists() else []

    def test_an_inventory_change_runs_selection_checks_and_a_failure_blocks(self):
        head = self.commit({"scripts/test-inventory.json": '{"rows": []}'})
        result = self.push(head, self.base, test_select_tests=3)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])
        self.assertIn("failed: python3 scripts/test-select-tests.py", result.stderr)

    def test_an_intake_row_change_runs_selection_checks(self):
        for path in ("verification/intake/dsw-4.json", "verification/intake/exclusions/old/notes.md",
                     "verification/intake/old\nrow.md"):
            with self.subTest(path=path):
                self.log.unlink(missing_ok=True)
                self.git("checkout", "-q", "--detach", self.base)
                head = self.commit({path: "{}\n"})
                self.assertEqual(self.push(head, self.base).returncode, 0)
                self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])
        self.log.unlink(missing_ok=True)
        self.git("checkout", "-q", "--detach", self.base)
        head = self.commit({"verification/intake-old/dsw-4.json": "{}\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), [])

    def test_a_verus_source_change_runs_reconciliation(self):
        head = self.commit({"crates/v.rs": "edited\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["judge-verus.py reconcile"])

    def test_an_unrelated_change_runs_no_check(self):
        head = self.commit({"crates/plain.rs": "edited\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), [])

    def test_a_new_branch_compares_against_origin_main(self):
        head = self.commit({"crates/v.rs": "edited\n"})
        self.assertEqual(self.push(head).returncode, 0)
        self.assertEqual(self.ran(), ["judge-verus.py reconcile"])

    def test_a_new_branch_without_origin_main_runs_every_check(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        head = self.commit({"crates/plain.rs": "edited\n"})
        self.assertEqual(self.push(head).returncode, 0)
        self.assertEqual(self.ran(), [
            "test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile",
        ])

    def links(self):
        """Commit a model links registry that enrolls `tla/M.tla` and cites `crates/cited.rs`, with the check and
        its self-test as stubs, and return the commit."""
        registry = {"models": [{"path": "tla/M.tla", "kinds": ["action"]}],
                    "rows": [{"model": "tla/M.tla", "kind": "action", "name": "A", "note": "n",
                              "anchors": [{"path": "crates/cited.rs", "quote": "fn a("}]},
                             {"model": "tla/M.tla", "kind": "action", "name": "B", "note": "n",
                              "abstraction": "no code site"}]}
        return self.commit({
            "verification/models/links.json": json.dumps(registry), "tla/M.tla": "m\n",
            "tla/Other.tla": "o\n", "crates/cited.rs": "fn a() {}\n",
            "scripts/model-links.py": STUB, "scripts/test-model-links.py": STUB,
        })

    def test_a_cited_file_change_runs_the_links_check_and_a_failure_blocks(self):
        base = self.links()
        head = self.commit({"crates/cited.rs": "fn a() { 1; }\n"})
        result = self.push(head, base, model_links=2)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), ["model-links.py check"])
        self.assertIn("failed: python3 scripts/model-links.py check", result.stderr)

    def test_each_links_input_runs_its_checks(self):
        selection = ["test-select-tests.py", "verify-receipts.py admit"]
        check, both = ["model-links.py check"], ["model-links.py check", "test-model-links.py"]
        base = self.links()
        for path, expected in (
            ("verification/models/links.json", check),
            ("tla/M.tla", check),
            ("tla/Other.tla", []),
            ("crates/plain.rs", []),
            ("scripts/model-links.py", both),
            ("scripts/test-model-links.py", both),
            ("tla/check.py", [*selection, *both]),
            ("scripts/judge-verus.py", [*selection, *both]),
            ("scripts/judge-rc11.py", [*selection, *both]),
        ):
            with self.subTest(path=path):
                self.log.unlink(missing_ok=True)
                self.git("checkout", "-q", "--detach", base)
                text = (self.repo / path).read_text() if (self.repo / path).exists() else ""
                head = self.commit({path: text + "\n"})
                self.assertEqual(self.push(head, base).returncode, 0)
                self.assertEqual(self.ran(), expected)

    def test_an_unreadable_links_registry_runs_the_links_check(self):
        base = self.links()
        for content in ("not json", "[]", '{"models": [{}], "rows": []}'):
            with self.subTest(content=content):
                self.log.unlink(missing_ok=True)
                self.git("checkout", "-q", "--detach", base)
                self.commit({"verification/models/links.json": content})
                head = self.commit({"crates/plain.rs": "edited\n"})
                self.assertEqual(self.push(head, self.git("rev-parse", "HEAD~1")).returncode, 0)
                self.assertEqual(self.ran(), ["model-links.py check"])

    def test_a_script_change_under_an_unreadable_links_registry_runs_the_self_test(self):
        self.links()
        base = self.commit({"verification/models/links.json": "not json"})
        head = self.commit({"scripts/model-links.py": STUB + "\n"})
        self.assertEqual(self.push(head, base).returncode, 0)
        self.assertEqual(self.ran(), ["model-links.py check", "test-model-links.py"])

    def test_a_push_that_removes_the_links_registry_runs_the_links_check_of_a_tip_that_keeps_it(self):
        registry, check = "verification/models/links.json", ["model-links.py check"]
        base = self.links()
        for label, removal, expected in (
            ("deleted", ("rm", "-q", "--", registry), check),
            ("renamed", ("mv", registry, "verification/models/old.json"), check),
            ("deleted with the check", ("rm", "-q", "--", registry, "scripts/model-links.py",
                                        "scripts/test-model-links.py"), []),
        ):
            with self.subTest(registry=label):
                self.log.unlink(missing_ok=True)
                self.git("checkout", "-q", "--detach", base)
                self.git(*removal)
                self.git("commit", "-q", "-m", "remove")
                self.assertEqual(self.push(self.git("rev-parse", "HEAD"), base).returncode, 0)
                self.assertEqual(self.ran(), expected)

    def test_a_new_branch_without_origin_main_runs_the_links_checks_of_a_tip_with_a_registry(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.assertEqual(self.push(self.links()).returncode, 0)
        self.assertEqual(self.ran(), [
            "test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile",
            "model-links.py check", "test-model-links.py",
        ])

    def test_a_new_branch_without_origin_main_runs_the_links_checks_of_a_tip_that_keeps_only_the_check(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.links()
        self.git("rm", "-q", "--", "verification/models/links.json")
        self.git("commit", "-q", "-m", "remove")
        self.assertEqual(self.push(self.git("rev-parse", "HEAD")).returncode, 0)
        self.assertEqual(self.ran(), [
            "test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile",
            "model-links.py check", "test-model-links.py",
        ])

    CONTRACT_CHECK = ("validate_contract.py chaos/ledger.json --root . --project chaos/project.yaml "
                      "--receipts chaos/receipts --check-claim chaos/READINESS.md")
    REFUSED = "holds what may be an AWS account number"
    CONTROLS = "crates/campaign-supervisor/src/campaign/calibration/controls.rs"

    def contract(self):
        """Commit a chaos contract with the validator and the judges' test as stubs, and return the commit."""
        return self.commit({
            "chaos/ledger.json": "{}\n", "chaos/READINESS.md": "r\n", "chaos/tools/validate_contract.py": STUB,
            "chaos/tests/test_judges.py": STUB, "chaos/harness/run_scenario.py": "h\n",
            "chaos/judges/core/common.py": "j\n", "chaos/receipts/run/row.json": "{}\n",
            "chaos/runs/run/run.json": "{}\n", "chaos/project.yaml": "p\n", "chaos/approval-policy.md": "a\n",
            "chaos/survey.md": "s\n",
        })

    def link(self, name, target):
        """Commit name as a link to target, replacing what stood there, and return the commit."""
        path = self.repo / name
        if path.is_dir() and not path.is_symlink():
            self.git("rm", "-rq", "--", name)
        elif path.exists() or path.is_symlink():
            self.git("rm", "-q", "--", name)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.symlink_to(target)
        self.git("add", "--", name)
        self.git("commit", "-q", "-m", "link")
        return self.git("rev-parse", "HEAD")

    def test_each_contract_input_selects_its_checks(self):
        contract = hook_module().CONTRACT_CHECK
        judges = (("python3", "-I", "chaos/tests/test_judges.py"),)
        both = contract + judges
        for path, expected in (
            ("chaos/READINESS.md", contract),
            ("chaos/harness/run_scenario.py", both),
            ("chaos/judges/core/common.py", both),
            ("chaos/tests/test_judges.py", both),
            ("chaos/tests/runs/fixture/run.json", both),
            ("chaos/tools/validate_contract.py", both),
            ("chaos/receipts/run/row.json", both),
            ("chaos/ledger.json", both),
            ("chaos/project.yaml", both),
            ("chaos/approval-policy.md", both),
            ("chaos/judges", both),
            ("chaos/harness", both),
            ("chaos", contract),
            ("chaos/ledger.json.old", contract),
            ("chaos/project.yaml.example", contract),
            ("chaos/approval-policy.md.bak", contract),
            ("chaos/survey.md", contract),
            ("chaos/runs/run/run.json", contract),
            ("crates/plain.rs", ()),
            (self.CONTROLS, judges),
            (self.CONTROLS.replace("controls.rs", "controls_tests.rs"), ()),
        ):
            with self.subTest(path=path):
                self.assertEqual(tuple(hook_module().checks_for([path], set(), set())), expected)
        self.assertEqual(hook_module().checks_for([self.CONTROLS], set(), set(), judges_held=False), [])
        self.assertEqual(contract, (("python3", "-I", "chaos/tools/validate_contract.py", "chaos/ledger.json",
                                     "--root", ".", "--project", "chaos/project.yaml", "--receipts",
                                     "chaos/receipts", "--check-claim", "chaos/READINESS.md"),))

    def test_a_chaos_change_runs_the_contract_check(self):
        # The validator imports a module that a file beside it and a directory on PYTHONPATH both
        # shadow with one that exits nonzero, so the check passes only on the interpreter's own module.
        # That directory also shadows a module of the hook's own script with one that exits 0, so the
        # check runs at all only when the hook starts its script on the interpreter's own modules.
        self.contract()
        base = self.commit({"chaos/tools/validate_contract.py": "import colorsys\n" + STUB,
                            "chaos/tools/colorsys.py": "raise SystemExit(5)\n"})
        (Path(self.temp.name) / "colorsys.py").write_text("raise SystemExit(6)\n")
        (Path(self.temp.name) / "json.py").write_text("raise SystemExit(0)\n")
        self.env["PYTHONPATH"] = self.temp.name
        head = self.commit({"chaos/READINESS.md": "r\n\n"})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), [self.CONTRACT_CHECK])

    def test_a_change_to_the_calibration_controls_runs_the_judges_test_of_a_tip_that_holds_it(self):
        base = self.contract()
        held = self.commit({self.CONTROLS: "depth, n and k\n"})
        self.git("checkout", "-q", "--detach", base)
        self.git("rm", "-q", "--", "chaos/tests/test_judges.py")
        self.git("commit", "-q", "-m", "remove")
        start = self.git("rev-parse", "HEAD")
        lacking = self.commit({self.CONTROLS: "depth, n and k\n"})
        result = self.push(held, base, lacking, start)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), ["test_judges.py"])

    def test_each_rust_source_beside_the_controls_runs_the_judges_test_of_a_tip_that_holds_it(self):
        hook, crate = hook_module(), "crates/campaign-supervisor/src"
        for path, held in ((f"{crate}/campaign/seeds/required.rs", list(hook.JUDGES_TEST)),
                           (f"{crate}/campaign/seeds.rs", list(hook.JUDGES_TEST)),
                           (f"{crate}/protocol/summary.rs", list(hook.JUDGES_TEST)),
                           (f"{crate}/campaign/seeds/pen.rs", [])):
            with self.subTest(path=path):
                self.assertEqual(hook.checks_for([path], set(), set()), held)
                self.assertEqual(hook.checks_for([path], set(), set(), judges_held=False), [])

    def test_a_chaos_change_at_a_tip_that_holds_the_receipt_replay_runs_it_and_its_failure_blocks(self):
        # A module beside the replay shadows its import and exits 0, so the replay fails the push
        # only when it runs on the interpreter's own module.
        base = self.commit({**dict.fromkeys(("chaos/ledger.json", "chaos/READINESS.md"), "r\n"),
                            "chaos/tools/validate_contract.py": STUB, "scripts/colorsys.py": "raise SystemExit(0)\n",
                            "scripts/chaos-receipt-replay.py": "import colorsys\n" + STUB})
        head = self.commit({"chaos/READINESS.md": "r\n\n"})
        result = self.push(head, base, chaos_receipt_replay=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), [self.CONTRACT_CHECK, "chaos-receipt-replay.py"])
        self.assertEqual(hook_module().REPLAY_CHECK, (("python3", "-I", "scripts/chaos-receipt-replay.py"),))
        self.assertEqual(hook_module().checks_for([hook_module().REPLAY], set(), set(), replay_held=True),
                         list(hook_module().REPLAY_CHECK))
        # A tip cut before the replay existed runs none. A push that removes the script runs it, and
        # the run fails for the missing file.
        self.assertEqual(hook_module().checks_for(["chaos/READINESS.md"], set(), set(), replay_held=False),
                         list(hook_module().CONTRACT_CHECK))
        self.git("rm", "-q", "--", "scripts/chaos-receipt-replay.py")
        self.git("commit", "-q", "-m", "remove")
        result = self.push(self.git("rev-parse", "HEAD"), head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed: python3 -I scripts/chaos-receipt-replay.py", result.stderr)

    def test_a_game_day_judge_input_runs_its_self_test_at_a_tip_that_holds_it(self):
        hook = hook_module()
        self.assertEqual(hook.GAMEDAY_TEST, (("python3", "-I", "scripts/test-gameday-judge.py"),))
        inputs = ("scripts/readiness.py", "scripts/fis-profiles.json", "verification/readiness/gamedays.json",
                  "verification/readiness/failover.json", "scripts/gameday-fixtures/held/package.json",
                  "scripts/measurement-frame.py", "scripts/acceptance.py", "scripts/hit-gate.py")
        for path in ("scripts/gameday-judge.py", "scripts/test-gameday-judge.py", *inputs):
            with self.subTest(path=path):
                # The host stop controller's self-test reads most of these paths too; its rule is tested on its own.
                self.assertEqual(hook.checks_for([path], set(), set(), host_stop_held=False),
                                 list(hook.GAMEDAY_TEST))
        # A tip cut before the self-test existed runs it for none of the judge's inputs; a change to
        # the judge or its self-test runs it there too, so a push that removes it fails.
        for path in inputs:
            with self.subTest(path=path, held=False):
                self.assertEqual(hook.checks_for([path], set(), set(), gameday_held=False, host_stop_held=False), [])
        self.assertEqual(hook.checks_for(["scripts/test-gameday-judge.py"], set(), set(), gameday_held=False),
                         list(hook.GAMEDAY_TEST))
        # Each file the judge's FLEET_BOUNDS names runs both self-tests beside the checks a Rust change selects.
        judge = ast.parse((ROOT / "scripts/gameday-judge.py").read_text(encoding="utf-8"))
        bounds = [ast.literal_eval(node.value) for node in judge.body if isinstance(node, ast.Assign)
                  and [getattr(target, "id", None) for target in node.targets] == ["FLEET_BOUNDS"]]
        self.assertEqual(len(bounds), 1)
        for path in sorted({rel for rel, _ in bounds[0].values()}):
            with self.subTest(fleet_bound=path):
                for test, held in ((hook.GAMEDAY_TEST[0], "gameday_held"), (hook.HOST_STOP_TEST[0], "host_stop_held")):
                    self.assertIn(test, hook.checks_for([path], set(), set()))
                    self.assertNotIn(test, hook.checks_for([path], set(), set(), **{held: False}))
        tree = ast.parse((ROOT / "scripts/readiness.py").read_text(encoding="utf-8"))
        owning = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
                  and [getattr(target, "id", None) for target in node.targets] == ["OWNING"]]
        self.assertEqual(len(owning), 1)
        self.assertGreaterEqual(len(owning[0]), 9)
        self.assertEqual({f"scripts/{name}" for name in owning[0]} & set(hook.GAMEDAY_OWN),
                         {"scripts/gameday-judge.py"})
        for name in owning[0]:
            with self.subTest(readiness_hashes=name):
                self.assertIn(hook.GAMEDAY_TEST[0], hook.checks_for([f"scripts/{name}"], set(), set()))
                unheld = hook.checks_for([f"scripts/{name}"], set(), set(), gameday_held=False)
                if f"scripts/{name}" in hook.GAMEDAY_OWN:
                    self.assertIn(hook.GAMEDAY_TEST[0], unheld)
                else:
                    self.assertNotIn(hook.GAMEDAY_TEST[0], unheld)

    def test_a_game_day_input_push_runs_the_isolated_self_test_and_its_failure_blocks(self):
        gameday = "test-gameday-judge.py"
        head = self.commit({"verification/readiness/gamedays.json": "{}\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertNotIn(gameday, self.ran())
        # A module beside the self-test shadows its import and exits 0, so the self-test fails the
        # push only when it runs on the interpreter's own module.
        held = self.commit({"scripts/colorsys.py": "raise SystemExit(0)\n",
                            "scripts/test-gameday-judge.py": "import colorsys\n" + STUB})
        tip = self.commit({"verification/readiness/gamedays.json": "{}\n\n"})
        for remote in (held, ZERO):
            with self.subTest(base="none" if remote == ZERO else "held"):
                self.log.unlink(missing_ok=True)
                if remote == ZERO:
                    self.git("update-ref", "-d", "refs/remotes/origin/main")
                result = self.push(tip, remote, test_gameday_judge=1)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(gameday, self.ran())
                self.assertIn("failed: python3 -I scripts/test-gameday-judge.py", result.stderr)
                self.assertEqual("no comparison base" in result.stderr, remote == ZERO)
        self.git("rm", "-q", "--", "scripts/test-gameday-judge.py")
        self.git("commit", "-q", "-m", "remove")
        result = self.push(self.git("rev-parse", "HEAD"), tip)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed: python3 -I scripts/test-gameday-judge.py", result.stderr)

    def test_a_host_stop_controller_input_runs_its_self_test_at_a_tip_that_holds_it(self):
        hook = hook_module()
        self.assertEqual(hook.HOST_STOP_TEST, (("python3", "-I", "scripts/test-host-stop-controller.py"),))
        inputs = ("scripts/host-stop-controller.py", "scripts/test-host-stop-controller.py",
                  "scripts/host-stop-fixtures/operator.json", "scripts/host-stop-fixtures/snapshot/shards.jsonl",
                  "scripts/gameday-fixtures/held/package.json", "scripts/gameday-judge.py", "scripts/readiness.py",
                  "scripts/acceptance.py", "scripts/fis-controller.py", "scripts/hardware-lane.py",
                  "scripts/reproduce-test.py", "scripts/select-tests.py", "scripts/sizing-worksheet.py",
                  "scripts/recovery-packages.py", "scripts/measurement-frame.py", "scripts/hit-gate.py",
                  "scripts/verify-receipts.py", "scripts/fis-profiles.json", "verification/readiness/gamedays.json")
        for path in inputs:
            with self.subTest(path=path):
                self.assertIn(hook.HOST_STOP_TEST[0], hook.checks_for([path], set(), set()))
        # A tip cut before the self-test existed runs it for no input but the controller and its self-test, so a
        # push that removes the self-test fails on the missing file.
        for path in inputs[2:]:
            with self.subTest(path=path, held=False):
                self.assertNotIn(hook.HOST_STOP_TEST[0], hook.checks_for([path], set(), set(), host_stop_held=False))
        for path in inputs[:2]:
            with self.subTest(path=path, held=False):
                self.assertEqual(hook.checks_for([path], set(), set(), host_stop_held=False),
                                 list(hook.HOST_STOP_TEST))
        for path in ("verification/readiness/failover.json", "scripts/test-fis-controller.py",
                     "scripts/host-stop-controller.md", "docs/agents/ci.md"):
            with self.subTest(path=path, unrelated=True):
                self.assertNotIn(hook.HOST_STOP_TEST[0], hook.checks_for([path], set(), set()))
        self.assertEqual(hook.checks_for(["scripts/host-stop-controller.py"], set(), set()), list(hook.HOST_STOP_TEST))
        # The run order holds the self-test, so sorting the selected commands never fails on it.
        self.assertIn(hook.HOST_STOP_TEST[0], hook.ORDER)

    def test_an_unrelated_push_asks_git_nothing_about_the_host_stop_self_test(self):
        held = self.commit({"scripts/test-host-stop-controller.py": STUB})
        head = self.commit({"docs/notes.md": "n\n"})
        trace = Path(self.temp.name) / "trace.log"
        self.env["GIT_TRACE"] = str(trace)
        self.assertEqual(self.push(head, held).returncode, 0)
        del self.env["GIT_TRACE"]
        lookups = [line for line in trace.read_text().splitlines() if "cat-file" in line]
        self.assertTrue(lookups, "the trace records the hook's other lookups")
        self.assertFalse([line for line in lookups if "test-host-stop-controller.py" in line], lookups)
        self.assertNotIn("test-host-stop-controller.py", self.ran())

    def test_the_hook_runs_the_host_stop_self_test_only_at_a_tip_that_holds_it(self):
        # A tip without the self-test: a change to a file it loads runs nothing of it.
        head = self.commit({"scripts/fis-profiles.json": "{}\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertNotIn("test-host-stop-controller.py", self.ran())
        # A tip that holds it: the same change runs it, and a failure blocks the push.
        held = self.commit({"scripts/test-host-stop-controller.py": STUB})
        self.log.unlink(missing_ok=True)
        head = self.commit({"scripts/fis-profiles.json": '{"x": 1}\n'})
        self.assertEqual(self.push(head, held).returncode, 0)
        self.assertEqual(self.ran(), ["test-host-stop-controller.py"])
        self.log.unlink(missing_ok=True)
        result = self.push(head, held, test_host_stop_controller=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed: python3 -I scripts/test-host-stop-controller.py", result.stderr)
        # A new ref with no comparison base runs it at a tip that holds it.
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        self.log.unlink(missing_ok=True)
        self.assertEqual(self.push(head).returncode, 0)
        self.assertIn("test-host-stop-controller.py", self.ran())

    def test_a_failing_contract_check_or_judges_test_fails_the_push(self):
        # A module beside the judges' test shadows its import and exits 0, so the test fails the
        # push only when it runs on the interpreter's own module.
        base = self.contract()
        head = self.commit({"chaos/judges/core/common.py": "edited\n", "chaos/tests/colorsys.py": "raise SystemExit(0)\n",
                            "chaos/tests/test_judges.py": "import colorsys\n" + STUB})
        result = self.push(head, base, validate_contract=1, test_judges=1)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), [self.CONTRACT_CHECK, "test_judges.py"])
        for failed in ("python3 -I chaos/tools/validate_contract.py", "python3 -I chaos/tests/test_judges.py"):
            self.assertIn(f"failed: {failed}", result.stderr)

    def test_the_account_number_match_reads_each_decoded_key_string_and_integer(self):
        hook = hook_module()
        digest = "ab" + "123456789012" + "cd" * 25
        for text, refused in (
            ('{"arn": "arn:aws:sts::123456789012:assumed-role/r"}', True),
            ('{"output": "account 1234-5678-9012"}', True),
            ('{"account": 123456789012}', True),
            ('{"account": -123456789012}', True),
            ('{"123456789012": "key"}', True),
            ('{"bucket": "assets-123456789012-us-east-1"}', True),
            (json.dumps({"output": "line\n123456789012"}), True),
            (json.dumps({"output": "cell\t1234-5678-9012"}), True),
            ('{"output": "x\\u0020123456789012"}', True),
            ('{"nested": [[{"deep": "123456789012"}]]}', True),
            (f'{{"judge": "{digest}", "runs": [12345678901, 1234567890123]}}', False),
            ('{"head": "123456789012cdcd", "tail": "abab123456789012"}', False),
            ('{"before": "x1234-5678-9012", "after": "1234-5678-9012y"}', False),
            ('{"card": "1234-5678-9012-3456", "lead": "0-1234-5678-9012"}', False),
            ('{"b": 0.000244140625}', False),
            ('{"output": "x\\u0041123456789012"}', False),
            ('{"output": "x\\\\n123456789012"}', False),
        ):
            with self.subTest(text=text):
                values = hook.record_values(text)
                self.assertEqual(any(hook.ACCOUNT_NUMBER.search(v) for v in values), refused, values)
        for text in ("not json: account 123456789012", '{"a": "\\n123456789012"', "\ufeff{}", "[" * 100000):
            with self.subTest(text=text[:40]):
                self.assertIsNone(hook.record_values(text))

    def test_a_chaos_record_with_an_account_number_fails_the_push(self):
        base = self.contract()
        refused = {
            "chaos/receipts/run/row.json": '{"arn": "arn:aws:sts::123456789012:assumed-role/r"}',
            "chaos/receipts/run/a\nb.json": '{"account": 123456789012}',
            "chaos/runs/run/run.json": json.dumps({"error": "denied\n1234-5678-9012"}),
            "chaos/tests/runs/fixture/run.json": '{"bucket": "assets-123456789012-us-east-1"}',
            "chaos/tests/receipts/fixture/row.json": '{"detail": "role 123456789012 refused"}',
        }
        unread = {
            "chaos/receipts/run/clean.json": '{"b": 0.000244140625}',
            "chaos/runs/run/history.jsonl": '{"history": 123456789012}',
            "chaos/runs/run/sweep-status.json": '{"status": 123456789012}',
            "chaos/tests/runs/fixture/history.jsonl": '{"fixture": 123456789012}',
        }
        head = self.commit({**refused, **unread})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), [self.CONTRACT_CHECK, "test_judges.py"])
        for path in refused:
            shown = path if path.isprintable() else repr(path)
            self.assertEqual(result.stderr.count(f"failed: {shown} at {head[:12]} {self.REFUSED}"), 1, path)
        for path in unread:
            self.assertNotIn(f"{path} at", result.stderr)

    def test_a_link_under_chaos_fails_the_push(self):
        base = self.contract()
        self.commit({"chaos/elsewhere/row.json": '{"account": 123456789012}', "chaos/copy.md": "r\n"})
        self.link("chaos/receipts", "elsewhere")
        head = self.link("chaos/READINESS.md", "copy.md")
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/receipts at {head[:12]} is a link or a submodule", result.stderr)
        self.assertIn(f"failed: chaos/READINESS.md at {head[:12]} is a link or a submodule", result.stderr)

    def test_the_guard_reads_the_original_objects_past_a_replacement(self):
        base = self.contract()
        head = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        original = self.git("rev-parse", f"{head}:chaos/runs/run/run.json")
        clean = subprocess.run(("git", "hash-object", "-w", "--stdin"), cwd=self.repo, env=self.env, text=True,
                               input="{}\n", capture_output=True, check=True).stdout.strip()
        self.git("replace", original, clean)
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {head[:12]} {self.REFUSED}", result.stderr)

    def test_a_pushed_commit_with_an_account_number_fails_a_push_whose_tip_removed_it(self):
        base = self.contract()
        linked = self.link("chaos/runs/linked/run.json", "123456789012")
        test_receipt = "chaos/tests/receipts/fixture/row.json"
        leaked = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}',
                              test_receipt: '{"role": 123456789012}'})
        self.git("rm", "-q", "--", "chaos/runs/linked/run.json", test_receipt)
        head = self.commit({"chaos/runs/run/run.json": "{}\n"})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), [])
        for path in ("chaos/runs/run/run.json", test_receipt):
            self.assertIn(f"failed: {path} at {leaked[:12]} {self.REFUSED}", result.stderr)
        self.assertEqual(result.stderr.count("failed: chaos/runs/linked/run.json at"), 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/linked/run.json at {linked[:12]} is a chaos record that is not a "
                      "regular file", result.stderr)

    def test_a_link_or_a_submodule_at_the_chaos_root_fails_a_push_with_a_base(self):
        self.commit({"elsewhere/runs/run/run.json": '{"account": 123456789012}'})
        linked = self.link("chaos", "elsewhere")
        self.git("checkout", "-q", "--detach", self.base)
        self.git("config", "diff.ignoreSubmodules", "all")
        self.git("update-index", "--add", "--cacheinfo", f"160000,{self.base},chaos")
        self.git("commit", "-q", "-m", "submodule")
        submodule = self.git("rev-parse", "HEAD")
        result = self.push(linked, self.base, submodule, self.base)
        self.assertEqual(result.returncode, 1, result.stderr)
        for head in (linked, submodule):
            self.assertIn(f"failed: chaos at {head[:12]} is a link or a submodule", result.stderr)

    def test_a_merged_side_branch_with_an_account_number_fails_the_push(self):
        base = self.contract()
        leaked = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        self.commit({"chaos/runs/run/run.json": "{}\n"})
        side = self.git("rev-parse", "HEAD")
        self.git("checkout", "-q", "--detach", base)
        self.commit({"chaos/survey.md": "main line\n"})
        self.git("merge", "-q", "--no-ff", "-m", "merge", side)
        head = self.git("rev-parse", "HEAD")
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {leaked[:12]} {self.REFUSED}", result.stderr)

    def test_the_history_guard_skips_the_records_of_commits_the_destination_holds(self):
        # Both `new` and `merged` have `held` as an ancestor. Because `origin/team/topic` points to
        # `held`, the guard skips the refused record in its parent for both updates.
        start = self.contract()
        self.git("update-ref", "refs/remotes/origin/main", start)
        self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        held = self.commit({"chaos/runs/run/run.json": "{}\n"})
        self.git("update-ref", "refs/remotes/origin/team/topic", held)
        new = self.commit({"crates/plain.rs": "a new branch\n"})
        self.git("checkout", "-q", "--detach", start)
        old = self.commit({"crates/other.rs": "an older branch\n"})
        self.git("merge", "-q", "--no-ff", "-m", "merge", held)
        merged = self.git("rev-parse", "HEAD")
        result = self.push(new, ZERO, merged, old)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), [])

    def test_the_destination_refs_come_only_from_a_remote_name_without_a_glob(self):
        hook = hook_module()
        for name, expected in (
            ("origin", ("--remotes=origin",)),
            ("group/fork", ("--remotes=group/fork",)),
            # A branch `fork/x` of the remote `team` has the ref name of the branch `x` of `team/fork`.
            ("team/fork", ()),
            ("", ()),
            ("*", ()),
            ("orig?n", ()),
            ("[o]rigin", ()),
            ("o\\rigin", ()),
        ):
            with self.subTest(name=name):
                self.assertEqual(hook.destination_refs(name, ["origin", "team/fork", "team", "teammate"]), expected)
        # The refs of a remote whose name extends the destination's lie under the destination's own.
        self.assertEqual(hook.destination_refs("team", ["team/fork", "team", "teammate", "team/fork/deep"]),
                         ("--exclude=team/fork/*", "--exclude=team/fork/deep/*", "--remotes=team"))

    def test_a_new_ref_reads_the_records_of_commits_only_another_remote_holds(self):
        # Besides `other`, a remote named `origin/fork` holds the commit, and its refs lie under `origin`'s.
        self.contract()
        leaked = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        self.git("update-ref", "refs/remotes/other/x", leaked)
        self.git("update-ref", "refs/remotes/origin/fork/x", leaked)
        self.git("config", "remote.origin/fork.url", "elsewhere")
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        head = self.commit({"chaos/runs/run/run.json": "{}\n"})
        result = self.push(head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {leaked[:12]} {self.REFUSED}", result.stderr)

    def test_the_history_guard_reads_pathspecs_whatever_mode_the_push_set(self):
        base = self.contract()
        leaked = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        head = self.commit({"chaos/runs/run/run.json": "{}\n"})
        # Git refuses the literal mode beside any other, so only a hook that clears every mode reads the record.
        self.env.update(GIT_LITERAL_PATHSPECS="1", GIT_GLOB_PATHSPECS="1", GIT_ICASE_PATHSPECS="1")
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {leaked[:12]} {self.REFUSED}", result.stderr)

    def test_a_chaos_record_that_is_not_json_or_cannot_be_read_fails(self):
        base = self.contract()
        head = self.commit({"chaos/runs/run/run.json": '{"a": "\\n123456789012"'})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {head[:12]} is a chaos record that is not JSON",
                      result.stderr)
        program = ("import importlib.util, sys\n"
                   "spec = importlib.util.spec_from_file_location('hook', sys.argv[1])\n"
                   "hook = importlib.util.module_from_spec(spec)\n"
                   "spec.loader.exec_module(hook)\n"
                   "print(hook.account_numbers([(sys.argv[2], 'chaos/runs/run/run.json', '0' * 40)]))\n")
        read = subprocess.run((sys.executable, "-B", "-c", program, str(ROOT / "scripts/pre-push-checks.py"), head),
                              cwd=self.repo, env=self.env, text=True, capture_output=True, timeout=120)
        self.assertEqual(read.stdout, f"['chaos/runs/run/run.json at {head[:12]} is a chaos record Git could not "
                                      "read']\n", read.stderr)

    def test_a_chaos_change_reads_every_record_of_the_tip_from_any_directory(self):
        self.contract()
        base = self.commit({"chaos/runs/old/run.json": '{"account": 123456789012}'})
        head = self.commit({"chaos/survey.md": "edited\n"})
        result = self.push(head, base, cwd=self.repo / "crates")
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(self.ran(), [self.CONTRACT_CHECK])
        self.assertIn(f"failed: chaos/runs/old/run.json at {head[:12]} {self.REFUSED}", result.stderr)

    def test_a_push_that_changes_nothing_under_chaos_reads_no_chaos_record(self):
        base = self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}'})
        head = self.commit({"crates/plain.rs": "edited\n"})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), [])

    def test_a_new_branch_without_origin_main_runs_the_contract_checks_its_tip_holds(self):
        every = ["test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile"]
        base = self.contract()
        tips, expected = [base], [*every, self.CONTRACT_CHECK, "test_judges.py"]
        for removed, checks in (("chaos/tests/test_judges.py", [self.CONTRACT_CHECK]),
                                ("chaos/ledger.json", ["test_judges.py"])):
            self.git("checkout", "-q", "--detach", base)
            self.git("rm", "-q", "--", removed)
            self.git("commit", "-q", "-m", "remove")
            tips.append(self.git("rev-parse", "HEAD"))
            expected += [*every, *checks]
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        result = self.push(tips[0], ZERO, tips[1], ZERO, tips[2], ZERO)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), expected)

    def test_a_new_branch_without_origin_main_guards_the_chaos_records_of_its_tip(self):
        self.contract()
        self.git("rm", "-q", "--", "chaos/ledger.json")
        self.commit({"chaos/runs/run/run.json": '{"account": 123456789012}', "chaos/elsewhere.json": "{}\n"})
        head = self.link("chaos/runs/linked/run.json", "../../elsewhere.json")
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        result = self.push(head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: chaos/runs/run/run.json at {head[:12]} {self.REFUSED}", result.stderr)
        self.assertIn(f"failed: chaos/runs/linked/run.json at {head[:12]} is a link or a submodule", result.stderr)

    def test_checks_run_on_the_pushed_commit_not_the_working_tree(self):
        head = self.commit({"scripts/test-inventory.json": '{"rows": []}',
                            "scripts/verify-receipts.py": "import sys\nsys.exit(4)\n"})
        (self.repo / "scripts/verify-receipts.py").write_text(STUB)
        result = self.push(head, self.base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("failed: python3 scripts/verify-receipts.py admit", result.stderr)
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)

    def test_a_signal_during_worktree_creation_leaves_no_worktree(self):
        real_git = shutil.which("git")
        binaries = Path(self.temp.name) / "bin"
        binaries.mkdir()
        wrapper = binaries / "git"
        wrapper.write_text(
            "#!/bin/sh\n"
            'if [ "$1" = worktree ] && [ "$2" = add ]; then shift 2; set -- worktree add --lock "$@"; fi\n'
            f'"{real_git}" "$@"\n'
            'status=$?\n'
            'if [ "$1" = worktree ] && [ "$2" = add ]; then kill -TERM "$PPID"; fi\n'
            'exit "$status"\n'
        )
        wrapper.chmod(0o755)
        self.env["PATH"] = f"{binaries}{os.pathsep}{self.env['PATH']}"
        head = self.commit({"scripts/test-inventory.json": '{"rows": []}'})
        result = self.push(head, self.base)
        self.assertEqual(result.returncode, 128 + signal.SIGTERM, result.stderr)
        self.assertEqual(self.ran(), [])
        self.assertEqual(self.git("worktree", "list", "--porcelain").count("worktree "), 1)

    def test_the_diff_starts_at_the_remote_commit(self):
        first = self.commit({"scripts/test-inventory.json": '{"rows": []}'})
        head = self.commit({"crates/plain.rs": "edited\n"})
        self.assertEqual(self.push(head, first).returncode, 0)
        self.assertEqual(self.ran(), [])

    def test_the_diff_covers_every_pushed_commit_not_only_the_tip(self):
        self.commit({"scripts/test-inventory.json": '{"rows": []}'})
        head = self.commit({"crates/plain.rs": "edited\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_an_unknown_remote_commit_compares_against_origin_main(self):
        head = self.commit({"crates/v.rs": "edited\n"})
        self.assertEqual(self.push(head, "2" * 40).returncode, 0)
        self.assertEqual(self.ran(), ["judge-verus.py reconcile"])

    def test_an_ignore_attribute_change_runs_selection_checks(self):
        head = self.commit({"crates/plain.rs": '#[ignore = "slow"]\nfn t() {}\n'})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_a_judge_script_change_runs_selection_checks(self):
        head = self.commit({"scripts/judge-kani.py": "x = 1\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_each_admission_input_runs_its_checks(self):
        selection = ["test-select-tests.py", "verify-receipts.py admit"]
        for path, content, expected in (
            ("scripts/classify-atomics.py", "x = 1\n", selection),
            ("tla/check.py", "x = 1\n", selection),
            ("quint/check.py", "x = 1\n", selection),
            ("verification/atomics/census.json", '{"surfaces": []}', selection),
            ("verification/control-less.json", "[]\n", selection),
            ("verification/verus/inventory.json", '{"sources": {"crates/v.rs": "e"}}',
             [*selection, "judge-verus.py reconcile"]),
        ):
            with self.subTest(path=path):
                self.log.unlink(missing_ok=True)
                self.git("checkout", "-q", "--detach", self.base)
                head = self.commit({path: content})
                self.assertEqual(self.push(head, self.base).returncode, 0)
                self.assertEqual(self.ran(), expected)

    def test_renaming_an_ignored_test_runs_selection_checks(self):
        ignored = self.commit({"crates/plain.rs": '#[test]\n#[ignore = "slow"]\nfn churn() {}\n'})
        head = self.commit({"crates/plain.rs": '#[test]\n#[ignore = "slow"]\nfn churn_renamed() {}\n'})
        self.assertEqual(self.push(head, ignored).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_renaming_an_ignored_test_behind_another_attribute_runs_selection_checks(self):
        attributes = '#[ignore = "slow"]\n#[should_panic(expected = "fn sentinel")]\n'
        ignored = self.commit({"crates/plain.rs": f"{attributes}fn churn() {{}}\n"})
        head = self.commit({"crates/plain.rs": f"{attributes}fn churn_renamed() {{}}\n"})
        self.assertEqual(self.push(head, ignored).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_deleting_a_file_with_an_ignored_test_runs_selection_checks(self):
        ignored = self.commit({"crates/plain.rs": '#[ignore = "slow"]\nfn churn() {}\n'})
        self.git("rm", "-q", "crates/plain.rs")
        self.git("commit", "-q", "-m", "delete")
        head = self.git("rev-parse", "HEAD")
        self.assertEqual(self.push(head, ignored).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_an_edit_beside_an_ignored_test_runs_no_check(self):
        ignored = self.commit({"crates/plain.rs": '#[ignore = "slow"]\nfn churn() {}\n'})
        head = self.commit({"crates/plain.rs": 'fn helper() {}\n\n#[ignore = "slow"]\nfn churn() { helper() }\n'})
        self.assertEqual(self.push(head, ignored).returncode, 0)
        self.assertEqual(self.ran(), [])

    def test_a_malformed_verus_inventory_runs_reconciliation(self):
        head = self.commit({"verification/verus/inventory.json": "not json",
                            "crates/plain.rs": "edited\n"})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), [
            "test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile",
        ])
        self.log.unlink()
        self.git("checkout", "-q", "-b", "other", self.base)
        self.commit({"verification/verus/inventory.json": "[]"})
        later = self.commit({"crates/plain.rs": "again\n"})
        self.assertEqual(self.push(later, self.git("rev-parse", "HEAD~1")).returncode, 0)
        self.assertEqual(self.ran(), ["judge-verus.py reconcile"])

    def test_every_pushed_ref_is_checked_once_per_commit(self):
        plain = self.commit({"crates/plain.rs": "edited\n"})
        head = self.commit({"crates/v.rs": "edited\n"})
        result = self.push(plain, self.base, head, plain, head, plain)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), ["judge-verus.py reconcile"])

    def test_one_commit_pushed_to_two_refs_runs_the_union_of_their_checks(self):
        head = self.commit({"scripts/test-inventory.json": '{"rows": []}'})
        result = self.push(head, head, head, self.base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_a_miri_ignore_change_runs_selection_checks(self):
        head = self.commit({"crates/plain.rs": '#[cfg_attr(miri, ignore = "slow")]\nfn t() {}\n'})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_a_nested_predicate_ignore_change_runs_selection_checks(self):
        head = self.commit({"crates/plain.rs": '#[cfg_attr(not(miri), ignore = "slow")]\nfn t() {}\n'})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_a_multiline_miri_ignore_change_runs_selection_checks(self):
        head = self.commit({"crates/plain.rs": '#[cfg_attr(\n    miri,\n    ignore = "slow"\n)]\nfn t() {}\n'})
        self.assertEqual(self.push(head, self.base).returncode, 0)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def ignore_an_existing_test(self, message="change"):
        existing = self.commit({"crates/plain.rs": "#[test]\nfn churn() {}\n"})
        return existing, self.commit({"crates/plain.rs": '#[test]\n#[ignore = "slow"]\nfn churn() {}\n'}, message)

    def test_an_existing_test_that_gains_an_ignore_fails_the_push_and_the_checks_still_run(self):
        existing, head = self.ignore_an_existing_test()
        result = self.push(head, existing)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('blocks ignore-existing:crates/plain.rs churn: not ignored -> #[ignore = "slow"]',
                      result.stderr)
        self.assertIn(f"failed: scripts/tool.sh scan-weakened-tests --base {existing} --head {head}", result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])
        self.assertLess(result.stderr.index("tool.sh scan-weakened-tests --base"),
                        result.stderr.index(f"pre-push: {head[:12]}: python3 scripts/test-select-tests.py"))

    def test_a_blocking_finding_on_the_second_ref_line_fails_the_push(self):
        existing, head = self.ignore_an_existing_test()
        result = self.push(head, self.base, head, existing)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn('reports ignore-new:crates/plain.rs churn: absent -> #[ignore = "slow"]', result.stderr)
        self.assertIn("blocks ignore-existing:crates/plain.rs churn", result.stderr)
        self.assertIn(f"failed: scripts/tool.sh scan-weakened-tests --base {existing} --head {head}", result.stderr)
        self.assertNotIn(f"failed: scripts/tool.sh scan-weakened-tests --base {self.base}", result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_the_pushed_tip_and_not_the_checkout_is_scanned(self):
        existing, head = self.ignore_an_existing_test()
        self.commit({"crates/plain.rs": "#[test]\nfn churn() {}\n"},
                    "Restore churn\n\nWeakens-Test: ignore-existing:crates/plain.rs: written after the pushed tip")
        result = self.push(head, existing)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("blocks ignore-existing:crates/plain.rs churn", result.stderr)

    def test_a_lowered_budget_alone_fails_the_push_with_no_worktree_check(self):
        budget = self.commit({"crates/plain.rs": "const SEEDS: u64 = 12;\n"})
        head = self.commit({"crates/plain.rs": "const SEEDS: u64 = 11;\n"})
        result = self.push(head, budget)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("blocks budget-lowered:crates/plain.rs SEEDS at line 1: 12 -> 11", result.stderr)
        self.assertIn(f"failed: scripts/tool.sh scan-weakened-tests --base {budget} --head {head}", result.stderr)
        self.assertEqual(self.ran(), [])

    def test_an_inherited_step_summary_is_left_alone(self):
        summary = Path(self.temp.name) / "summary.md"
        summary.write_text("earlier step\n")
        with mock.patch.dict(os.environ, GITHUB_STEP_SUMMARY=str(summary)):
            self.setUp()
        existing, head = self.ignore_an_existing_test()
        result = self.push(head, existing)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn("blocks ignore-existing:crates/plain.rs churn", result.stderr)
        self.assertEqual(summary.read_text(), "earlier step\n")

    def test_ignores_with_no_fn_after_them_select_the_checks_when_their_suffix_changes(self):
        base = self.commit({"crates/plain.rs": "#[ignore]\n#[ignore]\nconst N: u8 = 1;\n"})
        head = self.commit({"crates/plain.rs": "#[ignore]\n#[ignore]\nconst N: u8 = 2;\n"})
        result = self.push(head, base)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_the_ignore_spans_reuse_a_search_that_still_holds(self):
        program = ("import importlib.util, sys\n"
                   "spec = importlib.util.spec_from_file_location('hook', sys.argv[1])\n"
                   "hook = importlib.util.module_from_spec(spec)\n"
                   "spec.loader.exec_module(hook)\n"
                   "spans = hook.ignored_tests('#[ignore]\\n' * 3000 + 'struct S;\\nfn f() {}\\n')\n"
                   "print(len(spans), all(span.endswith('fn f') for span in spans))\n")
        result = subprocess.run((sys.executable, "-B", "-c", program, str(ROOT / "scripts/pre-push-checks.py")),
                                text=True, capture_output=True, timeout=120)
        self.assertEqual(result.stdout, "3000 True\n", result.stderr)

    def test_an_unreadable_origin_main_fails_the_push_with_a_git_error(self):
        head = self.commit({"crates/plain.rs": "edited\n"})
        ref = self.repo / ".git/refs/remotes/origin/main"
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        ref.parent.mkdir(parents=True, exist_ok=True)
        ref.write_text("1" * 40 + "\n")
        result = self.push(head)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("pre-push: git merge-base origin/main", result.stderr)
        self.assertNotIn("weakened-test scan skipped", result.stderr)

    def test_a_non_ascii_verus_source_selects_reconciliation_under_a_non_utf8_locale(self):
        source = "crates/caf\u00e9.rs"
        base = self.commit({"verification/verus/inventory.json": json.dumps({"sources": {source: "d"}}, ensure_ascii=False),
                            source: "v\n"})
        head = self.commit({source: "edited\n"})
        locales = [{"LC_ALL": "C", "PYTHONCOERCECLOCALE": "0"}]
        try:
            installed = subprocess.run(("locale", "-a"), capture_output=True, text=True).stdout.split()
        except OSError:
            installed = []
        locales += [{"LC_ALL": name} for name in ("en_US.iso88591", "en_US.ISO-8859-1") if name in installed][:1]
        plain = dict(self.env)
        for env in locales:
            with self.subTest(locale=env["LC_ALL"]):
                self.env = dict(plain, **env, PYTHONUTF8="0")
                result = self.push(head, base)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(self.ran(), ["judge-verus.py reconcile"])
                self.log.unlink(missing_ok=True)

    def test_a_scan_that_fails_for_another_reason_fails_the_push(self):
        head = self.commit({"scripts/test-inventory.json": "not json"})
        result = self.push(head, self.base)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertIn(f"failed: scripts/tool.sh scan-weakened-tests --base {self.base} --head {head}", result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_an_acknowledged_ignore_of_an_existing_test_passes_the_push(self):
        existing, head = self.ignore_an_existing_test(
            "Ignore churn\n\nWeakens-Test: ignore-existing:crates/plain.rs: needs a cgroup scope")
        result = self.push(head, existing)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("acknowledged ignore-existing:crates/plain.rs churn", result.stderr)
        self.assertEqual(self.ran(), ["test-select-tests.py", "verify-receipts.py admit"])

    def test_a_ref_without_a_comparison_base_prints_the_skipped_scan_and_runs_every_check(self):
        self.git("update-ref", "-d", "refs/remotes/origin/main")
        _, head = self.ignore_an_existing_test()
        result = self.push(head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"pre-push: {head[:12]}: no comparison base; weakened-test scan skipped", result.stderr)
        self.assertEqual(self.ran(), [
            "test-select-tests.py", "verify-receipts.py admit", "judge-verus.py reconcile",
        ])

    def test_a_deletion_runs_no_check(self):
        result = subprocess.run(("bash", str(ROOT / ".githooks/pre-push")), cwd=self.repo,
                                env=self.env, text=True, capture_output=True, input=DELETION)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.ran(), [])

    def test_a_malformed_ref_line_fails(self):
        result = subprocess.run(("bash", str(ROOT / ".githooks/pre-push")), cwd=self.repo,
                                env=self.env, text=True, capture_output=True, input="ref-update\n")
        self.assertEqual(result.returncode, 2)


if __name__ == "__main__":
    unittest.main()
