#!/usr/bin/env python3
"""Exercise the weakened-test scanner over disposable Git repositories, and pin the CI step that runs it."""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCANNER = Path(__file__).with_name("scan-weakened-tests.py")
WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/agent-checks.yml"
INVENTORY = "scripts/test-inventory.json"
TEST = "#[test]\nfn {name}() {{\n    assert!(true);\n}}\n"
ROWS = [{"id": "a", "seeds": 12, "bound": "^a: depth: 6 actions 40$"}, {"id": "b", "seeds": 4},
        {"id": "f", "seconds": 10, "executions": 3, "member": "^f: cycles 9$", "deadline_seconds": 30}]


def inventory(rows, drain=10):
    return json.dumps({"miri_sweep": {"seeds": 64}, "qemu": {"member_drain_seconds": drain},
                       "qualified": {"lane": {"rows": rows}}}, indent=2) + "\n"


class ScanWeakenedTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-scan-")
        self.addCleanup(self.temp.cleanup)
        self.repo = Path(self.temp.name) / "repo"
        self.repo.mkdir()
        self.env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GITHUB_"))}
        self.env.update(
            GIT_CONFIG_NOSYSTEM="1", GIT_CONFIG_GLOBAL=str(Path(self.temp.name) / "global"),
            GIT_AUTHOR_NAME="t", GIT_AUTHOR_EMAIL="t@example.com",
            GIT_COMMITTER_NAME="t", GIT_COMMITTER_EMAIL="t@example.com",
        )
        self.git("init", "-q", "-b", "main")
        self.base = self.commit({
            "src/a_tests.rs": TEST.format(name="first") + TEST.format(name="second"),
            "src/model.rs": "    builder.preemption_bound = Some(3);\n    builder.max_branches = 10_000;\n"
                            "const SEEDS: u64 = 48;\nconst ROOTS: [u64; 3] = [1, 2, 3];\n"
                            'const MOD_ROOTS: [&str; 4] = ["a", "b", "c", "d"];\n'
                            "const CASE_SEEDS: usize = 9;\nconst S19_ROOTS: [u32; 3] = [\n"
                            "const PREEMPTION_BOUND: usize = 9;\n"
                            "    builder.preemption_bound = Some(PREEMPTION_BOUND);\n",
            "src/ignored_tests.rs": '#[ignore = "slow"]\n' + TEST.format(name="old_name"),
            "src/gone_tests.rs": TEST.format(name="gone"),
            INVENTORY: inventory(ROWS),
            ".github/workflows/agent-checks.yml": "    timeout-minutes: 15\n"
                                                  "    run: exec timeout --kill-after=30s 5m make\n",
            "scripts/rust-lane.sh": "  step check deadline 25m cargo check\n",
        })

    def git(self, *args):
        return subprocess.run(("git", *args), cwd=self.repo, env=self.env, text=True,
                              capture_output=True, check=True).stdout.strip()

    def commit(self, files, message="change", deleted=()):
        for name, content in files.items():
            path = self.repo / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            self.git("add", "--", name)
        for name in deleted:
            self.git("rm", "-q", "--", name)
        self.git("commit", "-q", "--allow-empty", "--cleanup=verbatim", "-m", message)
        return self.git("rev-parse", "HEAD")

    def edit(self, path, old, new):
        return (self.repo / path).read_text().replace(old, new)

    def scan(self, *args, env=None, cwd=None):
        return subprocess.run((sys.executable, str(SCANNER), *args), cwd=cwd or self.repo,
                              env=dict(self.env, **(env or {})), text=True, capture_output=True)

    def scan_head(self, head=None):
        return self.scan("--base", self.base, *(("--head", head) if head else ()))

    def assert_blocks(self, result, line):
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(f"blocks {line}\n", result.stdout)

    def test_an_existing_test_that_gains_an_ignore_blocks(self):
        for attribute in ('#[ignore = "slow"]', "#[cfg_attr(miri, ignore)]"):
            with self.subTest(attribute=attribute):
                head = self.commit({"src/a_tests.rs": self.edit(
                    "src/a_tests.rs", "#[test]\nfn second", f"#[test]\n{attribute}\nfn second")})
                self.assert_blocks(self.scan_head(head),
                                   f"ignore-existing:src/a_tests.rs second: not ignored -> {attribute}")
                self.git("reset", "-q", "--hard", self.base)

    def test_a_lowered_inventory_budget_blocks_by_row_id_while_rows_reorder(self):
        head = self.commit({INVENTORY: inventory([dict(ROWS[1], seeds=3), ROWS[2], ROWS[0]])})
        result = self.scan_head(head)
        self.assert_blocks(result, f"budget-lowered:{INVENTORY} qualified.lane.rows[b].seeds: 4 -> 3")
        self.assertEqual(result.stdout.count("\n"), 1, result.stdout)

    def test_a_reorder_with_no_value_change_is_no_finding(self):
        head = self.commit({INVENTORY: inventory(ROWS[::-1])})
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_a_lowered_count_in_a_bound_text_or_the_miri_sweep_blocks(self):
        for text, line in (
            (inventory([dict(ROWS[0], bound="^a: depth: 5 actions 40$"), *ROWS[1:]]),
             "qualified.lane.rows[a].bound depth: 6 -> 5"),
            (inventory([dict(ROWS[0], bound="^a: depth: 6 actions 39$"), *ROWS[1:]]),
             "qualified.lane.rows[a].bound actions: 40 -> 39"),
            (inventory([*ROWS[:2], dict(ROWS[2], member="^f: cycles 8$")]),
             "qualified.lane.rows[f].member cycles: 9 -> 8"),
            (inventory([*ROWS[:2], dict(ROWS[2], seconds=9)]), "qualified.lane.rows[f].seconds: 10 -> 9"),
            (inventory([*ROWS[:2], dict(ROWS[2], executions=2)]), "qualified.lane.rows[f].executions: 3 -> 2"),
            (inventory([{k: v for k, v in ROWS[0].items() if k != "seeds"}, *ROWS[1:]]),
             "qualified.lane.rows[a].seeds: 12 -> absent"),
            (inventory(ROWS).replace('"seeds": 64', '"seeds": 32'), "miri_sweep.seeds: 64 -> 32"),
        ):
            with self.subTest(line=line):
                head = self.commit({INVENTORY: text})
                self.assert_blocks(self.scan_head(head), f"budget-lowered:{INVENTORY} {line}")
                self.git("reset", "-q", "--hard", self.base)

    def test_each_lowered_rust_budget_blocks(self):
        for old, new, line in (
            ("Some(3)", "Some(2)", "preemption_bound at line 1: 3 -> 2"),
            ("10_000;", "9_999;", "max_branches at line 2: 10000 -> 9999"),
            ("SEEDS: u64 = 48", "SEEDS: u64 = 47", "SEEDS at line 3: 48 -> 47"),
            ("[u64; 3] = [1, 2, 3]", "[u64; 2] = [1, 2]", "ROOTS at line 4: 3 -> 2"),
            ("CASE_SEEDS: usize = 9", "CASE_SEEDS: usize = 8", "CASE_SEEDS at line 6: 9 -> 8"),
            ("[u32; 3] = [\n", "[u32; 2] = [\n", "S19_ROOTS at line 7: 3 -> 2"),
            ("PREEMPTION_BOUND: usize = 9", "PREEMPTION_BOUND: usize = 8", "PREEMPTION_BOUND at line 8: 9 -> 8"),
            ("Some(PREEMPTION_BOUND)", "Some(8)", "preemption_bound at line 9: 9 -> 8"),
            ("Some(3);\n", "Some(LOW);\nconst LOW: usize = 1;\n", "preemption_bound at line 1: 3 -> 1"),
            ("const PREEMPTION_BOUND: usize = 9;\n    builder.preemption_bound = Some(PREEMPTION_BOUND);",
             "    builder.preemption_bound = Some(8);", "preemption_bound at line 8: 9 -> 8"),
        ):
            with self.subTest(old=old):
                head = self.commit({"src/model.rs": self.edit("src/model.rs", old, new)})
                self.assert_blocks(self.scan_head(head), f"budget-lowered:src/model.rs {line}")
                self.git("reset", "-q", "--hard", self.base)

    def test_a_raised_budget_a_new_row_and_a_shortened_string_array_pass(self):
        flag = self.commit({INVENTORY: inventory([*ROWS, {"id": "d", "seeds": True}])})
        head = self.commit({
            "src/model.rs": self.edit("src/model.rs", "Some(3)", "Some(4)").replace(
                '[&str; 4] = ["a", "b", "c", "d"]', '[&str; 3] = ["a", "b", "c"]'),
            INVENTORY: inventory([dict(ROWS[0], seeds=13, bound="^a: depth: 7 actions 40$"),
                                  dict(ROWS[2], deadline_seconds=20), {"id": "c", "seeds": 1}, {"id": "d"}]),
            "src/a_tests.rs": self.edit("src/a_tests.rs", "assert!(true);\n}\n#[test]\nfn second",
                                        "assert_eq!(1, 1);\n}\n#[test]\nfn second"),
        })
        result = self.scan("--base", flag, "--head", head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_lines_with_one_pairing_text_pair_in_order(self):
        self.commit({"src/model.rs": "    a.preemption_bound = Some(1);\n    b.preemption_bound = Some(3);\n"
                                     "    b.preemption_bound = Some(5);\n",
                     INVENTORY: inventory([dict(ROWS[0], bound="^a: depth: 3 depth: 5$"), *ROWS[1:]])})
        head = self.commit({"src/model.rs": "    b.preemption_bound = Some(4);\n    b.preemption_bound = Some(4);\n",
                            INVENTORY: inventory([dict(ROWS[0], bound="^a: depth: 6 depth: 4$"), *ROWS[1:]])})
        result = self.scan("--base", f"{head}^", "--head", head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(result.stdout, "blocks budget-lowered:src/model.rs preemption_bound at line 2: 5 -> 4\n"
                                        f"blocks budget-lowered:{INVENTORY} qualified.lane.rows[a].bound depth: 5 -> 4\n")

    def test_hunks_pair_only_within_themselves(self):
        self.commit({"src/model.rs": "    b.max_branches = 1;\nx\n    b.max_branches = 3;\n"})
        head = self.commit({"src/model.rs": "x\n    b.max_branches = 2;\n"})
        self.git("config", "diff.interHunkContext", "1")
        self.assert_blocks(self.scan("--base", f"{head}^", "--head", head, env={"GIT_DIFF_OPTS": "--unified=3"}),
                           "budget-lowered:src/model.rs max_branches at line 2: 3 -> 2")

    def test_a_path_with_glob_characters_reads_its_own_hunks(self):
        self.commit({"src/[ab].rs": "    b.max_branches = 10;\n", "src/a.rs": "    b.max_branches = 10;\n",
                     "src/A.rs": "    b.max_branches = 10;\n"})
        head = self.commit({"src/a.rs": "    b.max_branches = 9;\n", "src/[ab].rs": "    b.max_branches = 10;\n// x\n",
                            "src/A.rs": "    b.max_branches = 10;\n// x\n"})
        result = self.scan("--base", f"{head}^", "--head", head, env={"GIT_ICASE_PATHSPECS": "1"})
        self.assertEqual(result.stdout, "blocks budget-lowered:src/a.rs max_branches at line 1: 10 -> 9\n")

    def test_a_renamed_ignored_test_reports_as_new(self):
        head = self.commit({"src/ignored_tests.rs": self.edit("src/ignored_tests.rs", "old_name", "new_name")})
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout,
                         'reports ignore-new:src/ignored_tests.rs new_name: absent -> #[ignore = "slow"]\n')

    def test_each_report_class_prints_its_line_and_passes(self):
        head = self.commit({
            ".github/workflows/agent-checks.yml": "    timeout-minutes: 20\n",
            "scripts/rust-lane.sh": "  step check deadline 30m cargo check\n",
            INVENTORY: inventory(ROWS, drain=11),
            "src/new_tests.rs": "#[ignore]\n" + TEST.format(name="arrives"),
            "src/a_tests.rs": self.edit("src/a_tests.rs", "    assert!(true);\n}\n#[test]\nfn second",
                                        "}\n#[test]\nfn second"),
        }, deleted=("src/gone_tests.rs",))
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(sorted(result.stdout.splitlines()), [
            "reports assertions-removed:src/a_tests.rs assert lines: 1 removed -> 0 added",
            "reports assertions-removed:src/gone_tests.rs assert lines: 1 removed -> 0 added",
            "reports ignore-new:src/new_tests.rs arrives: absent -> #[ignore]",
            "reports timeout-raised:.github/workflows/agent-checks.yml timeout-minutes at line 1: 15 -> 20",
            "reports timeout-raised:scripts/rust-lane.sh deadline at line 1: 25 -> 30",
            f"reports timeout-raised:{INVENTORY} qemu.member_drain_seconds: 10 -> 11",
        ])

    def ignore_second(self, message):
        return self.commit({"src/a_tests.rs": self.edit(
            "src/a_tests.rs", "#[test]\nfn second", "#[test]\n#[ignore]\nfn second")}, message)

    def test_only_the_exact_key_with_a_reason_in_the_range_acknowledges(self):
        key = "ignore-existing:src/a_tests.rs"
        outside = self.commit({}, f"Weakens-Test: {key}: an earlier reason")
        for message, code in (
            (f"subject\n\nWeakens-Test: {key}: needs a cgroup scope", 0),
            (f"subject\n\nWeakens-Test: {key}: ", 1),
            (f"subject\n\nWeakens-Test: {key}:    \t", 1),
            (f"subject\n\nWeakens-Test: {key}x: needs a cgroup scope", 1),
            ("subject\n\nWeakens-Test: budget-lowered:src/a_tests.rs: needs a cgroup scope", 1),
            ("subject\n\nWeakens-Test: ignore-existing:src: needs a cgroup scope", 1),
            (f"subject\n\n> Weakens-Test: {key}: quoted from another commit", 1),
            ("subject", 1),
        ):
            with self.subTest(message=message):
                head = self.ignore_second(message)
                result = self.scan("--base", outside, "--head", head)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                if code:
                    self.assertIn(f"Weakens-Test: {key}: <reason>", result.stderr)
                else:
                    self.assertEqual(result.stdout, f"acknowledged {key} second: not ignored -> #[ignore]"
                                                    " (Weakens-Test: needs a cgroup scope)\n")
                self.git("reset", "-q", "--hard", outside)

    def test_one_line_acknowledges_every_finding_of_its_class_in_its_file(self):
        key = "ignore-existing:src/a_tests.rs"
        self.commit({"src/a_tests.rs": "#[test]\n#[ignore]\nfn first() {}\n#[test]\n#[ignore]\nfn second() {}\n"},
                    f"ignore both\n\nWeakens-Test: {key}: both need root")
        head = self.commit({"src/model.rs": "// unrelated\n"})
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"acknowledged {key} first: not ignored -> #[ignore] (Weakens-Test: both need root)\n",
                      result.stdout)
        self.assertIn(f"acknowledged {key} second: not ignored -> #[ignore] (Weakens-Test: both need root)\n",
                      result.stdout)

    def test_an_unreadable_base_exits_two_and_an_empty_range_prints_nothing(self):
        self.assertEqual(self.scan("--base", "f" * 40).returncode, 2)
        self.assertEqual(self.scan("--base", "no-such-ref").returncode, 2)
        empty = self.scan("--base", self.base)
        self.assertEqual((empty.returncode, empty.stdout, empty.stderr), (0, "", ""))
        raised = self.commit({"src/model.rs": self.edit("src/model.rs", "Some(3)", "Some(4)")})
        behind = self.scan("--base", raised, "--head", self.base)
        self.assertEqual((behind.returncode, behind.stdout, behind.stderr), (0, "", ""))

    def test_a_budget_line_after_a_form_feed_or_a_carriage_return_is_read(self):
        for separator in ("\x0c", "\r"):
            with self.subTest(separator=separator):
                (self.repo / "src/model.rs").write_bytes(f"x{separator}const SEEDS: u64 = 48;\n".encode())
                self.git("commit", "-q", "-am", "budget")
                (self.repo / "src/model.rs").write_bytes(f"x{separator}const SEEDS: u64 = 2;\n".encode())
                self.git("commit", "-q", "-am", "lowered")
                self.assert_blocks(self.scan("--base", "HEAD^"), "budget-lowered:src/model.rs SEEDS at line 1: 48 -> 2")

    def test_a_rust_path_holding_a_newline_exits_two(self):
        self.ignore_second("change")
        self.commit({"src/a\nb.rs": "fn x() {}\n"})
        result = self.scan("--base", self.base)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("newline", result.stderr)

    def test_text_that_is_not_utf8_exits_two(self):
        self.ignore_second("change")
        (self.repo / "src/model.rs").write_bytes(b"// \xff\n")
        self.git("commit", "-q", "-am", "binary byte")
        result = self.scan("--base", self.base)
        self.assertEqual(result.returncode, 2)
        self.assertIn("src/model.rs", result.stderr)

    def test_a_byte_that_is_not_utf8_outside_the_diff_exits_two(self):
        self.commit({"src/b.rs": "x\n"})
        (self.repo / "src/b.rs").write_bytes(b"x\n// \xff\n")
        self.git("commit", "-q", "-am", "unchanged byte")
        rust = self.git("rev-parse", "HEAD")
        (self.repo / "src/b.rs").write_bytes(b"y\n// \xff\n")
        self.git("commit", "-q", "-am", "edit beside the byte")
        result = self.scan("--base", rust, "--head", "HEAD")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(result.stderr.startswith("scan-weakened-tests: ") and "src/b.rs" in result.stderr,
                        result.stderr)
        document = inventory([dict(ROWS[0], note="cafe"), *ROWS[1:]])
        self.commit({INVENTORY: document})
        before = self.git("rev-parse", "HEAD")
        (self.repo / INVENTORY).write_bytes(document.replace('"seeds": 12', '"seeds": 11').encode()
                                            .replace(b'"cafe"', b'"caf\xe9"'))
        self.git("commit", "-q", "-am", "latin-1 note")
        result = self.scan("--base", before, "--head", "HEAD")
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn(INVENTORY, result.stderr)

    def test_a_scan_from_a_subdirectory_reports_the_line_patterns(self):
        head = self.commit({"src/model.rs": self.edit("src/model.rs", "Some(3)", "Some(2)")})
        self.git("config", "diff.relative", "true")
        root = self.scan_head(head)
        nested = self.scan("--base", self.base, cwd=self.repo / "scripts", env={"GIT_LITERAL_PATHSPECS": "1"})
        self.assertIn("blocks budget-lowered:src/model.rs preemption_bound at line 1: 3 -> 2\n", root.stdout)
        self.assertEqual((nested.returncode, nested.stdout), (root.returncode, root.stdout))

    def test_the_report_reads_commits_only_and_leaves_the_checkout_as_it_was(self):
        self.commit({"src/model.rs": self.edit("src/model.rs", "Some(3)", "Some(2)"),
                     ".github/workflows/agent-checks.yml": "    timeout-minutes: 20\n"})
        head = self.ignore_second("change")
        clean = self.scan_head(head)
        (self.repo / "src/a_tests.rs").write_text(TEST.format(name="first"))
        (self.repo / "src/model.rs").write_text("    builder.preemption_bound = Some(1);\n")
        self.git("add", "src/model.rs")
        (self.repo / ".gitattributes").write_text("*.rs -diff\n*.yml diff=rewrite\n")
        self.git("config", "diff.rewrite.textconv", "sed s/timeout/hidden/")
        before = [self.git("status", "--porcelain"), self.git("diff", "--cached"),
                  self.git("worktree", "list", "--porcelain"), (self.repo / "src/a_tests.rs").read_text()]
        changed = self.scan_head()
        after = [self.git("status", "--porcelain"), self.git("diff", "--cached"),
                 self.git("worktree", "list", "--porcelain"), (self.repo / "src/a_tests.rs").read_text()]
        self.assertEqual(clean.returncode, 1)
        self.assertIn("blocks budget-lowered:src/model.rs preemption_bound at line 1: 3 -> 2\n", clean.stdout)
        self.assertIn("reports timeout-raised:.github/workflows/agent-checks.yml timeout-minutes at line 1: 15 -> 20\n",
                      clean.stdout)
        self.assertEqual((changed.returncode, changed.stdout), (clean.returncode, clean.stdout))
        self.assertEqual(after, before)

    def test_the_report_is_appended_to_the_step_summary(self):
        self.ignore_second("change")
        summary = Path(self.temp.name) / "summary.md"
        summary.write_text("earlier step\n")
        result = self.scan("--base", self.base, env={"GITHUB_STEP_SUMMARY": str(summary)})
        line = "blocks ignore-existing:src/a_tests.rs second: not ignored -> #[ignore]\n"
        self.assertEqual((result.returncode, result.stdout), (1, line), result.stderr)
        text = summary.read_text()
        self.assertTrue(text.startswith("earlier step\n"), text)
        self.assertEqual(text.count(line), 1, text)


    def test_a_budget_written_as_an_expression_or_a_hex_literal_is_no_finding(self):
        head = self.commit({"src/model.rs": self.edit("src/model.rs", "SEEDS: u64 = 48", "SEEDS: u64 = 0x40")
                            .replace("max_branches = 10_000;", "max_branches = 5_000 * 4;")})
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_equal_paired_values_are_no_finding(self):
        head = self.commit({
            "src/model.rs": self.edit("src/model.rs", "[u64; 3] = [1, 2, 3]", "[u64; 3] = [1, 2, 4]"),
            ".github/workflows/agent-checks.yml": "    timeout-minutes: 15 # fifteen\n"
                                                  "    run: exec timeout --kill-after=30s 5m make\n",
        })
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_the_diff_algorithm_setting_leaves_the_pairing_as_it_was(self):
        self.commit({"src/model.rs": "fn f() {\n}\n\nfn f() {\n{\nx();\n b.max_branches = 10;\nfn f() {\n"})
        head = self.commit({"src/model.rs": "fn f() {\n}\n\nfn f() {\n{\nfn f() {\nx();\n b.max_branches = 9;\n"
                                            "fn f() {\n{\n"})
        self.git("config", "diff.algorithm", "histogram")
        self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                           "budget-lowered:src/model.rs max_branches at line 8: 10 -> 9")

    def test_a_command_timeout_and_a_row_deadline_that_rise_report(self):
        head = self.commit({
            ".github/workflows/agent-checks.yml": "    timeout-minutes: 14\n"
                                                  "    run: exec timeout --kill-after=30s 7m make\n",
            INVENTORY: inventory([*ROWS[:2], dict(ROWS[2], deadline_seconds=31)]),
        })
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "reports timeout-raised:.github/workflows/agent-checks.yml timeout at line 2: 5 -> 7",
            f"reports timeout-raised:{INVENTORY} qualified.lane.rows[f].deadline_seconds: 30 -> 31",
        ])

    def test_a_count_or_a_field_that_leaves_an_object_that_remains_blocks(self):
        for text, line in (
            (inventory([dict(ROWS[0], bound="^a: depth: \\d+ actions 40$"), *ROWS[1:]]),
             "qualified.lane.rows[a].bound depth: 6 -> absent"),
            (inventory([*ROWS[:2], dict(ROWS[2], member="^f:$")]), "qualified.lane.rows[f].member cycles: 9 -> absent"),
            (inventory([*ROWS[:2], {k: v for k, v in ROWS[2].items() if k != "member"}]),
             "qualified.lane.rows[f].member cycles: 9 -> absent"),
            (inventory(ROWS).replace('"seeds": 64', '"options": {"x": 1}'), "miri_sweep.seeds: 64 -> absent"),
            (inventory(ROWS).replace('{\n    "seeds": 64\n  }', "{}"), "miri_sweep.seeds: 64 -> absent"),
        ):
            with self.subTest(line=line):
                head = self.commit({INVENTORY: text})
                self.assert_blocks(self.scan_head(head), f"budget-lowered:{INVENTORY} {line}")
                self.git("reset", "-q", "--hard", self.base)

    def test_a_removed_object_and_a_reworded_text_with_every_count_are_no_finding(self):
        document = json.loads(inventory([dict(ROWS[0], bound="^a(x): depth: 6 actions 40$"), *ROWS[1:]]))
        del document["miri_sweep"]
        head = self.commit({INVENTORY: json.dumps(document)})
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_a_root_level_budget_that_falls_or_goes_absent_blocks(self):
        self.commit({INVENTORY: json.dumps({"baseline": "x", "seeds": 12})})
        for text, line in ((json.dumps({"baseline": "x", "seeds": 11}), "seeds: 12 -> 11"),
                           (json.dumps({"baseline": "x"}), "seeds: 12 -> absent")):
            with self.subTest(line=line):
                head = self.commit({INVENTORY: text})
                self.assert_blocks(self.scan("--base", f"{head}^", "--head", head), f"budget-lowered:{INVENTORY} {line}")
                self.git("reset", "-q", "--hard", "HEAD^")

    def test_an_inventory_that_cannot_be_compared_exits_two(self):
        decoy = json.loads(inventory([dict(ROWS[1], seeds=3), ROWS[0], ROWS[2]]))
        decoy["qualified.lane.rows[b].seeds"] = 4
        for files, deleted, message in (
            ({INVENTORY: json.dumps(decoy)}, (), "the key 'qualified.lane.rows[b].seeds' under the root"),
            ({INVENTORY: inventory([*ROWS, dict(ROWS[1], seeds=3)])}, (), "share the path qualified.lane.rows[b].id"),
            ({INVENTORY: inventory([*ROWS, {"id": "1", "seeds": 2}])}, (), "the id '1'"),
            ({INVENTORY: inventory([*ROWS, {"id": "x.y", "seeds": 2}])}, (), "the id 'x.y'"),
            ({INVENTORY: "[" * 5000 + "]" * 5000}, (), INVENTORY),
            ({INVENTORY: ""}, (), "is empty"),
            ({INVENTORY: "not json"}, (), INVENTORY),
            ({f"{INVENTORY}/x": "{}"}, (INVENTORY,), "is not a file"),
        ):
            with self.subTest(message=message):
                if deleted:
                    self.git("rm", "-q", "--", *deleted)
                head = self.commit(files)
                result = self.scan_head(head)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn(message, result.stderr)
                self.assertTrue(result.stderr.startswith("scan-weakened-tests: "), result.stderr)
                self.git("reset", "-q", "--hard", self.base)

    def test_an_inventory_entry_whose_object_is_missing_exits_two(self):
        self.git("read-tree", self.base)
        self.git("update-index", "--cacheinfo", f"100644,{'1' * 40},{INVENTORY}")
        tree = self.git("write-tree", "--missing-ok")
        head = self.git("commit-tree", tree, "-p", self.base, "-m", "missing")
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertIn("is empty or unreadable", result.stderr)

    def test_a_deleted_inventory_is_no_finding(self):
        head = self.commit({}, deleted=(INVENTORY,))
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_a_test_in_a_sibling_module_is_matched_by_its_module(self):
        helper = "fn helper() {\n    let _ = 1;\n}\n"
        first = "mod a {\n" + helper + '#[ignore = "slow"]\n' + TEST.format(name="same") + "}\nmod b {\n" + helper
        self.commit({"src/mods_tests.rs": first + TEST.format(name="same") + "}\n"})
        head = self.commit({"src/mods_tests.rs": first + "#[ignore]\n" + TEST.format(name="same") + "}\n"})
        result = self.scan("--base", f"{head}^", "--head", head)
        self.assertEqual((result.returncode, result.stdout),
                         (1, "blocks ignore-existing:src/mods_tests.rs b::same: not ignored -> #[ignore]\n"),
                         result.stderr)
        reordered = self.commit({"src/mods_tests.rs": "mod b {\n#[ignore]\n" + TEST.format(name="same") + "}\n"
                                 'mod a {\n#[ignore = "slow"]\n' + TEST.format(name="same") + "}\n"})
        result = self.scan("--base", head, "--head", reordered)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)
        helper = self.commit({"src/mods_tests.rs": "mod c {\n#[ignore]\n" + TEST.format(name="same") + "}\n"})
        result = self.scan("--base", reordered, "--head", helper)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("reports ignore-new:src/mods_tests.rs c::same: absent -> #[ignore]\n", result.stdout)
        self.assertNotIn("ignore-existing", result.stdout)

    def test_a_conditional_ignore_widened_to_a_plain_one_blocks(self):
        miri = "#[cfg_attr(miri, ignore)]"
        self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[test]\nfn second", f"#[test]\n{miri}\nfn second")})
        for attributes, line in (
            ("#[ignore]", f"{miri} -> #[ignore]"),
            (f"{miri}\n#[ignore]", f"{miri} -> {miri}; #[ignore]"),
            (f"#[ignore]\n{miri}", f"{miri} -> #[ignore]; {miri}"),
        ):
            with self.subTest(attributes=attributes):
                head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", miri, attributes)})
                self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                                   f"ignore-existing:src/a_tests.rs second: {line}")
                self.git("reset", "-q", "--hard", "HEAD^")
        reason = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", miri, '#[cfg_attr(miri, ignore = "slow")]')})
        result = self.scan("--base", f"{reason}^", "--head", reason)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)
        narrowed = self.commit({"src/ignored_tests.rs": self.edit("src/ignored_tests.rs", '#[ignore = "slow"]', miri)})
        self.assertEqual(self.scan("--base", f"{narrowed}^", "--head", narrowed).returncode, 0)

    def test_an_ignore_inside_a_literal_or_a_comment_names_no_test(self):
        for decoy, attribute in (
            ('const NOTE: &str = "#[ignore]";\n', "#[ignore]"),
            ("// #[ignore]\n", "#[ignore]"),
            ("/* outer /* inner */ #[ignore] */\n", "#[ignore]"),
            ("const C: [char; 2] = ['\\u{0}', '\"'];\nconst D: bool = matches!('a', '\\x00'|'\"');\n", "#[ignore]"),
            ("", "#[ignore] // this fn hangs on CI"),
            ("", "#[ignore]\n// fn hangs on CI"),
            ("", "#[ignore]\n/* fn hangs */"),
        ):
            with self.subTest(decoy=decoy, attribute=attribute):
                planted = self.commit({"src/a_tests.rs": self.edit(
                    "src/a_tests.rs", "#[test]\nfn second() {\n", f"{decoy}#[test]\nfn second() {{\n"
                    '    assert_eq!("x", "x");\n')})
                control = self.scan("--base", f"{planted}^", "--head", planted)
                self.assertEqual((control.returncode, control.stdout), (0, ""), control.stderr)
                head = self.commit({"src/a_tests.rs": self.edit(
                    "src/a_tests.rs", "#[test]\nfn second", f"#[test]\n{attribute}\nfn second")})
                result = self.scan("--base", planted, "--head", head)
                self.assertEqual((result.returncode, result.stdout),
                                 (1, "blocks ignore-existing:src/a_tests.rs second: not ignored -> #[ignore]\n"),
                                 result.stderr)
                self.git("reset", "-q", "--hard", self.base)

    def test_many_ignores_with_no_fn_after_them_are_no_finding(self):
        head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "", "") + "#[ignore]\n" * 3000})
        result = subprocess.run((sys.executable, str(SCANNER), "--base", self.base, "--head", head), cwd=self.repo,
                                env=self.env, text=True, capture_output=True, timeout=60)
        self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_a_non_ascii_path_reads_under_a_non_utf8_locale(self):
        path = "src/caf\u00e9_tests.rs"
        self.commit({path: "const SEEDS: u64 = 12;\n" + TEST.format(name="second")})
        head = self.commit({path: "const SEEDS: u64 = 11;\n#[test]\n#[ignore]\nfn second() {\n    assert!(true);\n}\n"})
        locales = [{"LC_ALL": "C", "PYTHONCOERCECLOCALE": "0"}]
        try:
            installed = subprocess.run(("locale", "-a"), capture_output=True, text=True).stdout.split()
        except OSError:
            installed = []
        locales += [{"LC_ALL": name} for name in ("en_US.iso88591", "en_US.ISO-8859-1") if name in installed][:1]
        for env in locales:
            with self.subTest(locale=env["LC_ALL"]):
                result = self.scan("--base", f"{head}^", "--head", head,
                                   env=dict(env, PYTHONUTF8="0", PYTHONIOENCODING="utf-8"))
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(sorted(result.stdout.splitlines()), [
                    f"blocks budget-lowered:{path} SEEDS at line 1: 12 -> 11",
                    f"blocks ignore-existing:{path} second: not ignored -> #[ignore]",
                ])

    def test_the_longest_key_owns_an_acknowledgement_line(self):
        for path in ("src/a.rs", "src/a.rs: b.rs"):
            self.commit({path: TEST.format(name="first")})
        start = self.git("rev-parse", "HEAD")
        long_key, short_key = "ignore-existing:src/a.rs: b.rs", "ignore-existing:src/a.rs"
        for message, code in ((f"x\n\nWeakens-Test: {long_key}: needs root", 1),
                              (f"x\n\nWeakens-Test: {long_key}:  ", 1),
                              (f"x\n\nWeakens-Test: {long_key}: needs root\nWeakens-Test: {short_key}: also", 0)):
            with self.subTest(message=message):
                head = self.commit(dict.fromkeys(("src/a.rs", "src/a.rs: b.rs"), "#[test]\n#[ignore]\nfn first() {}\n"),
                                   message)
                result = self.scan("--base", start, "--head", head)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                if code:
                    self.assertIn(f"blocks {short_key} first: not ignored -> #[ignore]\n", result.stdout)
                self.git("reset", "-q", "--hard", start)

    def test_an_acknowledgement_after_a_line_separator_other_than_lf_is_no_line(self):
        key = "ignore-existing:src/a_tests.rs"
        for separator, code in (("\x0c", 1), ("\r", 1), ("\u2028", 1), ("\r\n", 0)):
            with self.subTest(separator=repr(separator)):
                head = self.ignore_second(f"subject\n\nprose{separator}Weakens-Test: {key}: needs root\n")
                result = self.scan_head(head)
                verdict = "acknowledged" if code == 0 else "blocks"
                self.assertEqual((result.returncode, result.stdout.split(" (")[0]),
                                 (code, f"{verdict} {key} second: not ignored -> #[ignore]" + ("\n" if code else "")),
                                 result.stderr)
                self.git("reset", "-q", "--hard", self.base)

    def test_one_acknowledged_key_leaves_another_blocking(self):
        budget = f"budget-lowered:{INVENTORY}"
        self.commit({INVENTORY: inventory([dict(ROWS[0], seeds=11), *ROWS[1:]])},
                    f"lower\n\nWeakens-Test: {budget}: the row moved to a nightly lane")
        head = self.ignore_second("ignore")
        result = self.scan_head(head)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual(sorted(result.stdout.splitlines()), [
            f"acknowledged {budget} qualified.lane.rows[a].seeds: 12 -> 11 (Weakens-Test: the row moved to a nightly lane)",
            "blocks ignore-existing:src/a_tests.rs second: not ignored -> #[ignore]",
        ])
        self.assertIn("Weakens-Test: ignore-existing:src/a_tests.rs: <reason>", result.stderr)
        self.assertNotIn(f"Weakens-Test: {budget}: <reason>", result.stderr)

    def test_the_head_argument_bounds_the_findings_and_the_acknowledgements(self):
        key = "ignore-existing:src/a_tests.rs"
        tip = self.ignore_second("ignore")
        self.commit({}, f"later\n\nWeakens-Test: {key}: written after the scanned head")
        self.assertEqual(self.scan_head().returncode, 0)
        self.assert_blocks(self.scan_head(tip), f"{key} second: not ignored -> #[ignore]")

    def test_a_range_with_no_blocking_finding_reads_no_commit_message(self):
        trace = Path(self.temp.name) / "trace"
        head = self.commit({".github/workflows/agent-checks.yml": "    timeout-minutes: 20\n"
                                                                  "    run: exec timeout --kill-after=30s 5m make\n"})
        result = self.scan("--base", self.base, "--head", head, env={"GIT_TRACE": str(trace)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("timeout-raised", result.stdout)
        self.assertIn("git diff", trace.read_text())
        self.assertNotIn("git log", trace.read_text())

    def test_an_unreadable_head_or_an_unwritable_summary_exits_two(self):
        result = self.scan("--base", self.base, "--head", "no-such-ref")
        self.assertEqual(result.returncode, 2)
        self.assertRegex(result.stderr, r"^scan-weakened-tests: git rev-parse .*: \S")
        self.ignore_second("change")
        result = self.scan("--base", self.base, env={"GITHUB_STEP_SUMMARY": self.temp.name})
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("scan-weakened-tests: step summary:", result.stderr)

    def test_a_sibling_that_cannot_load_or_a_missing_git_exits_two(self):
        scripts = Path(self.temp.name) / "scripts"
        scripts.mkdir()
        for name in ("scan-weakened-tests.py", "pre-push-checks.py", "classify-atomics.py", "judge-rc11.py"):
            shutil.copy(SCANNER.with_name(name), scripts / name)
        env = {k: v for k, v in self.env.items() if k not in ("PYTHONDONTWRITEBYTECODE", "PYTHONPYCACHEPREFIX")}
        def run(**extra):
            return subprocess.run((sys.executable, str(scripts / "scan-weakened-tests.py"), "--base", self.base),
                                  cwd=self.repo, env=dict(env, **extra), text=True, capture_output=True)
        self.assertEqual(run().returncode, 0)
        self.assertEqual(sorted(p.name for p in scripts.iterdir()),
                         ["classify-atomics.py", "judge-rc11.py", "pre-push-checks.py", "scan-weakened-tests.py"])
        missing = run(PATH=str(scripts))
        self.assertEqual(missing.returncode, 2, missing.stderr)
        self.assertTrue(missing.stderr.startswith("scan-weakened-tests: "), missing.stderr)
        (scripts / "pre-push-checks.py").write_text("def broken(:\n")
        broken = run()
        self.assertEqual(broken.returncode, 2, broken.stderr)
        self.assertTrue(broken.stderr.startswith("scan-weakened-tests: pre-push-checks.py cannot be loaded"),
                        broken.stderr)

    def test_a_comment_before_a_budget_terminator_keeps_the_budget(self):
        self.commit({"src/model.rs": "    b.max_branches = 10 /* cap */;\n    b.preemption_bound = Some(3 /* x */);\n"})
        head = self.commit({"src/model.rs": "    b.max_branches = 9 /* cap */;\n    b.preemption_bound = Some(2 /* x */);\n"})
        result = self.scan("--base", f"{head}^", "--head", head)
        self.assertEqual((result.returncode, sorted(result.stdout.splitlines())), (1, [
            "blocks budget-lowered:src/model.rs max_branches at line 1: 10 -> 9",
            "blocks budget-lowered:src/model.rs preemption_bound at line 2: 3 -> 2",
        ]), result.stderr)

    def test_a_count_that_stops_being_a_literal_reads_as_absent(self):
        for bound, line in (("^a: depth: 6 actions 40?$", "actions: 40 -> absent"),
                            ("^a: depth: 5[0-9] actions 40$", "depth: 6 -> absent")):
            with self.subTest(bound=bound):
                head = self.commit({INVENTORY: inventory([dict(ROWS[0], bound=bound), *ROWS[1:]])})
                result = self.scan_head(head)
                self.assertEqual((result.returncode, result.stdout),
                                 (1, f"blocks budget-lowered:{INVENTORY} qualified.lane.rows[a].bound {line}\n"),
                                 result.stderr)
                self.git("reset", "-q", "--hard", self.base)

    def test_raw_identifiers_name_their_fns_and_modules(self):
        self.commit({"src/raw_tests.rs": "#[test]\n#[ignore]\nfn r#type() {}\n#[test]\nfn r#match() {}\n"
                                         "mod r#kind {\n    fn helper() {}\n}\n"})
        head = self.commit({"src/raw_tests.rs": "#[test]\nfn r#type() {}\n#[test]\n#[ignore]\nfn r#match() {}\n"
                                                "mod r#kind {\n    fn helper() {}\n    #[ignore]\n    fn other() {}\n}\n"})
        result = self.scan("--base", f"{head}^", "--head", head)
        self.assertEqual((result.returncode, sorted(result.stdout.splitlines())), (1, [
            "blocks ignore-existing:src/raw_tests.rs match: not ignored -> #[ignore]",
            "reports ignore-new:src/raw_tests.rs kind::other: absent -> #[ignore]",
        ]), result.stderr)

    def test_a_new_test_named_like_a_method_or_a_nested_fn_is_new(self):
        self.commit({"src/harness_tests.rs": "struct H;\nimpl H {\n    fn drains(&self) {}\n}\n"
                                             "fn outer() {\n    fn inner() {}\n}\n"})
        head = self.commit({"src/harness_tests.rs": self.edit("src/harness_tests.rs", "", "")
                            + "#[test]\n#[ignore]\nfn drains() {}\n#[test]\n#[ignore]\nfn inner() {}\n"})
        result = self.scan("--base", f"{head}^", "--head", head)
        self.assertEqual((result.returncode, sorted(result.stdout.splitlines())), (0, [
            "reports ignore-new:src/harness_tests.rs drains: absent -> #[ignore]",
            "reports ignore-new:src/harness_tests.rs inner: absent -> #[ignore]",
        ]), result.stderr)

    def test_a_plainly_ignored_test_that_gains_another_ignore_is_no_finding(self):
        self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[test]\nfn second", "#[test]\n#[ignore]\nfn second")})
        for added in ("#[cfg_attr(miri, ignore)]", '#[ignore = "slow"]'):
            with self.subTest(added=added):
                head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[ignore]\n", f"#[ignore]\n{added}\n")})
                result = self.scan("--base", f"{head}^", "--head", head)
                self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)
                self.git("reset", "-q", "--hard", "HEAD^")

    def test_a_runnable_twin_of_an_ignored_test_that_gains_an_ignore_blocks(self):
        twins = "#[cfg(miri)]\n#[test]\n#[ignore]\nfn twin() {}\n#[cfg(not(miri))]\n#[test]\n{}fn twin() {{}}\n"
        self.commit({"src/twin_tests.rs": twins.replace("{}fn", "fn").replace("{{}}", "{}")})
        head = self.commit({"src/twin_tests.rs": twins.replace("{}fn", "#[cfg_attr(loom, ignore)]\nfn")
                            .replace("{{}}", "{}")})
        self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                           "ignore-existing:src/twin_tests.rs twin: not ignored -> #[cfg_attr(loom, ignore)]")

    def test_a_second_conditional_ignore_blocks(self):
        miri = "#[cfg_attr(miri, ignore)]"
        self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[test]\nfn second", f"#[test]\n{miri}\nfn second")})
        head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", miri, f"{miri}\n#[cfg_attr(loom, ignore)]")})
        self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                           f"ignore-existing:src/a_tests.rs second: {miri} -> {miri}; #[cfg_attr(loom, ignore)]")

    def test_a_conditional_ignore_whose_condition_changes_blocks(self):
        miri = '#[cfg_attr(miri, ignore = "weak")]'
        self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[test]\nfn second", f"#[test]\n{miri}\nfn second")})
        for predicate in ("not(miri)", "any(miri, unix)", "all(miri, unix)"):
            with self.subTest(predicate=predicate):
                changed = miri.replace("(miri,", f"({predicate},")
                head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", miri, changed)})
                self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                                   f"ignore-existing:src/a_tests.rs second: {miri} -> {changed}")
                self.git("reset", "-q", "--hard", "HEAD^")

    def test_conditional_ignores_that_keep_their_conditions_are_no_finding(self):
        miri, loom = '#[cfg_attr(miri, ignore = "weak")]', "#[cfg_attr(loom, ignore)]"
        self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", "#[test]\nfn second",
                                                 f"#[test]\n{miri}\n{loom}\nfn second")})
        for attributes in (
            '#[cfg_attr(miri, ignore = "a \\"quoted\\" ] reason")]\n' + loom,
            f"#[cfg_attr(miri, ignore)]\n{loom}",
            '#[cfg_attr(\n    miri,\n    ignore = "a reason long enough to wrap the attribute"\n)]\n' + loom,
            f"{loom}\n{miri}",
            miri,
        ):
            with self.subTest(attributes=attributes):
                head = self.commit({"src/a_tests.rs": self.edit("src/a_tests.rs", f"{miri}\n{loom}", attributes)})
                result = self.scan("--base", f"{head}^", "--head", head)
                self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)
                self.git("reset", "-q", "--hard", "HEAD^")

    def test_a_named_bound_that_does_not_fall_or_has_no_one_value_is_no_finding(self):
        site = "    builder.preemption_bound = Some({});\n"
        for old, new in (
            ("Some(PREEMPTION_BOUND)", "Some(9)"),
            ("Some(PREEMPTION_BOUND)", "Some(10)"),
            ("Some(3)", "Some(PREEMPTION_BOUND)"),
            ("Some(3)", "Some(bound)"),
            ("PREEMPTION_BOUND: usize = 9;\n    builder.preemption_bound = Some(PREEMPTION_BOUND)",
             "PREEMPTION_BOUND: usize = 12;\n    builder.preemption_bound = Some(10)"),
        ):
            with self.subTest(old=old, new=new):
                head = self.commit({"src/model.rs": self.edit("src/model.rs", old, new)})
                result = self.scan_head(head)
                self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)
                self.git("reset", "-q", "--hard", self.base)
        for declarations in (
            "const LOW: usize = 9;\nmod m {\n    const LOW: usize = 5;\n}\n",
            "const LOW: usize = 3 * 3;\n",
            "const LOW: usize = 9;\nconst LOW: usize = 3 * 3;\n",
            "// const LOW: usize = 9;\n",
        ):
            with self.subTest(declarations=declarations):
                self.commit({"src/named.rs": declarations + site.format("LOW")})
                head = self.commit({"src/named.rs": declarations + site.format("1")})
                result = self.scan("--base", f"{head}^", "--head", head)
                self.assertEqual((result.returncode, result.stdout), (0, ""), result.stderr)

    def test_an_inventory_that_is_a_link_exits_two(self):
        target = subprocess.run(
            ("git", "hash-object", "-w", "--stdin"), cwd=self.repo, env=self.env, input="{}", text=True,
            capture_output=True, check=True).stdout.strip()
        self.git("update-index", "--cacheinfo", f"120000,{target},{INVENTORY}")
        self.git("commit", "-q", "-m", "link")
        link = self.git("rev-parse", "HEAD")
        for base, head in ((self.base, link), (link, self.commit({INVENTORY: inventory(ROWS)}))):
            with self.subTest(base=base):
                result = self.scan("--base", base, "--head", head)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("is not a file", result.stderr)

    def test_an_inventory_scan_ignores_the_pathspec_environment(self):
        head = self.commit({INVENTORY: inventory([dict(ROWS[1], seeds=3), ROWS[0], ROWS[2]])})
        for name in ("GIT_ICASE_PATHSPECS", "GIT_GLOB_PATHSPECS"):
            with self.subTest(name=name):
                result = self.scan("--base", self.base, "--head", head, cwd=self.repo / "src", env={name: "1"})
                self.assertEqual((result.returncode, result.stdout),
                                 (1, f"blocks budget-lowered:{INVENTORY} qualified.lane.rows[b].seeds: 4 -> 3\n"),
                                 result.stderr)

    def test_a_carriage_return_in_a_path_keeps_the_path(self):
        path = "src/a\rb.rs"
        self.commit({path: "const SEEDS: u64 = 12;\n"})
        head = self.commit({path: "const SEEDS: u64 = 11;\n"})
        result = subprocess.run((sys.executable, str(SCANNER), "--base", f"{head}^", "--head", head), cwd=self.repo,
                                env=self.env, capture_output=True)
        self.assertEqual((result.returncode, result.stdout),
                         (1, f"blocks budget-lowered:{path} SEEDS at line 1: 12 -> 11\n".encode()), result.stderr)

    def test_a_report_the_output_encoding_cannot_spell_prints_escaped(self):
        summary = Path(self.temp.name) / "summary.md"
        summary.write_text("earlier step\n")
        head = self.commit({"src/\u65e5_tests.rs": "#[ignore]\n" + TEST.format(name="arrives")})
        result = subprocess.run((sys.executable, str(SCANNER), "--base", self.base, "--head", head), cwd=self.repo,
                                env=dict(self.env, LC_ALL="C", PYTHONCOERCECLOCALE="0", PYTHONUTF8="0",
                                         GITHUB_STEP_SUMMARY=str(summary)), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"reports ignore-new:src/\\u65e5_tests.rs arrives: absent -> #[ignore]\n")
        self.assertIn("reports ignore-new:src/\u65e5_tests.rs arrives", summary.read_text(encoding="utf-8"))
        self.assertTrue(summary.read_text(encoding="utf-8").startswith("earlier step\n"))
        self.git("reset", "-q", "--hard", self.base)
        surrogate = json.dumps({"qualified": {"lane": {"rows": [{"id": "s\ud800", "deadline_seconds": 5}]}}})
        self.commit({INVENTORY: surrogate})
        raised = self.commit({INVENTORY: surrogate.replace("5}", "6}")})
        result = self.scan("--base", f"{raised}^", "--head", raised, env={"GITHUB_STEP_SUMMARY": str(summary)})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("deadline_seconds: 5 -> 6", result.stdout)

    def test_an_acknowledgement_reads_as_utf8_whatever_the_log_encoding(self):
        key = "ignore-existing:src/a_tests.rs"
        head = self.ignore_second(f"ignore\n\nWeakens-Test: {key}: caf\u00e9 needs root")
        self.git("config", "i18n.logOutputEncoding", "ISO-8859-1")
        result = self.scan_head(head)
        self.assertEqual((result.returncode, result.stdout),
                         (0, f"acknowledged {key} second: not ignored -> #[ignore] (Weakens-Test: caf\u00e9 needs root)\n"),
                         result.stderr)

    def test_the_diff_heuristic_setting_leaves_the_pairing_as_it_was(self):
        self.commit({"src/model.rs": "Z0\n x();\nb\nb\n" + " b.max_branches = 9;\n y();\n" * 3
                                     + "{\n b.max_branches = 10;\nfn f() {\n x();\nZ1\n"})
        head = self.commit({"src/model.rs": " }\n x();\nb\nb\nb\n" + " b.max_branches = 9;\n y();\n" * 4
                                            + " x();\nfn f() {\n\n"})
        self.git("config", "diff.indentHeuristic", "false")
        self.assert_blocks(self.scan("--base", f"{head}^", "--head", head),
                           "budget-lowered:src/model.rs max_branches at line 12: 10 -> 9")

    def test_a_base_past_the_fork_point_charges_the_head_with_its_own_commits_only(self):
        key = "ignore-existing:src/a_tests.rs"
        branch = self.commit({"src/lib.rs": "fn f() {}\n"})
        self.git("reset", "-q", "--hard", self.base)
        # Comparing the head with the merge base keeps base-only strengthening from counting against the head.
        ahead = self.commit({
            "src/model.rs": self.edit("src/model.rs", "SEEDS: u64 = 48", "SEEDS: u64 = 96"),
            "src/ignored_tests.rs": TEST.format(name="old_name"),
            INVENTORY: inventory([dict(ROWS[0], seeds=24), dict(ROWS[1], seconds=5), ROWS[2]]),
        }, f"strengthen\n\nWeakens-Test: {key}: written on the base side")
        result = self.scan("--base", ahead, "--head", branch)
        self.assertEqual((result.returncode, result.stdout, result.stderr), (0, "", ""))
        self.git("reset", "-q", "--hard", branch)
        weakened = self.ignore_second("ignore")
        result = self.scan("--base", ahead, "--head", weakened)
        self.assertEqual((result.returncode, result.stdout),
                         (1, f"blocks {key} second: not ignored -> #[ignore]\n"), result.stderr)
        self.assertIn(f"in {self.base[:12]}..{weakened[:12]}: Weakens-Test: {key}: <reason>", result.stderr)

    def test_a_base_that_shares_no_history_with_the_head_exits_two(self):
        unrelated = self.git("commit-tree", f"{self.base}^{{tree}}", "-m", "unrelated root")
        result = self.scan("--base", unrelated, "--head", self.ignore_second("ignore"))
        self.assertEqual((result.returncode, result.stdout), (2, ""), result.stderr)
        self.assertIn("share no history", result.stderr)

    def test_ci_scans_a_pull_request_from_the_first_parent_of_its_test_merge(self):
        workflow = WORKFLOW.read_text()
        self.assertEqual(workflow.count("scripts/scan-weakened-tests.py"), 1, "one step runs the scanner")
        self.assertIn("          SCAN_BASE: ${{ github.event_name == 'pull_request' && 'HEAD^1' "
                      "|| github.event.before || 'origin/main' }}\n"
                      '        run: python3 scripts/scan-weakened-tests.py --base "$SCAN_BASE"\n', workflow)
        # A base behind the first parent lets another pull request's acknowledgement cover this one's finding.
        key = f"budget-lowered:{INVENTORY}"
        pull = self.commit({INVENTORY: inventory([ROWS[0], dict(ROWS[1], seeds=3), ROWS[2]])})
        self.git("reset", "-q", "--hard", self.base)
        self.commit({INVENTORY: inventory([dict(ROWS[0], seeds=11), *ROWS[1:]])},
                    f"lower a\n\nWeakens-Test: {key}: row a is slow on the runner")
        self.git("merge", "-q", "--no-ff", "-m", "test merge", pull)
        self.assertEqual(self.scan("--base", self.base).returncode, 0)
        result = self.scan("--base", "HEAD^1")
        self.assertEqual((result.returncode, result.stdout),
                         (1, f"blocks {key} qualified.lane.rows[b].seeds: 4 -> 3\n"), result.stderr)

    def test_changed_rust_files_share_one_diff_process_per_batch(self):
        names = [f"src/many/f{index:03}.rs" for index in range(300)]
        (self.repo / "src/many").mkdir()
        for name in names:
            (self.repo / name).write_text("    b.max_branches = 10;\n")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "many files")
        for name in names:
            (self.repo / name).write_text("    b.max_branches = 10;\n// x\n")
        (self.repo / names[-1]).write_text("    b.max_branches = 9;\n")
        self.git("commit", "-q", "-am", "change each file")
        trace = Path(self.temp.name) / "trace"
        result = self.scan("--base", "HEAD^", env={"GIT_TRACE": str(trace)})
        self.assertEqual((result.returncode, result.stdout),
                         (1, f"blocks budget-lowered:{names[-1]} max_branches at line 1: 10 -> 9\n"), result.stderr)
        self.assertEqual(trace.read_text().count("-U0"), 2, "300 changed files read in two diffs")

    def test_a_file_that_becomes_a_link_leaves_each_later_file_its_own_hunks(self):
        self.commit({"src/a.rs": "    b.max_branches = 10;\n", "src/b.rs": "    b.max_branches = 10;\n"})
        target = subprocess.run(
            ("git", "hash-object", "-w", "--stdin"), cwd=self.repo, env=self.env, input="b.rs", text=True,
            capture_output=True, check=True).stdout.strip()
        # A file that becomes a symlink has two diff sections for its path, a deletion and a creation.
        self.git("update-index", "--cacheinfo", f"120000,{target},src/a.rs")
        (self.repo / "src/b.rs").write_text("    b.max_branches = 9;\n")
        self.git("add", "src/b.rs")
        self.git("commit", "-q", "-m", "link")
        result = self.scan("--base", "HEAD^", "--head", "HEAD")
        self.assertEqual((result.returncode, result.stdout),
                         (1, "blocks budget-lowered:src/b.rs max_branches at line 1: 10 -> 9\n"), result.stderr)

if __name__ == "__main__":
    unittest.main()
