#!/usr/bin/env python3
"""Exercise the chaos receipt replay in a scratch copy of the chaos tree without changing this checkout."""

import importlib.util
import json
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]


class ChaosReceiptReplay(unittest.TestCase):
    """The receipt replay runs a run receipt's judge again on its evidence and refuses a receipt that differs from its."""

    def test_a_receipt_passes_until_its_outcome_build_or_out_of_scope_list_is_edited(self):
        temp = tempfile.TemporaryDirectory(prefix="kestrike-replay-")
        self.addCleanup(temp.cleanup)
        tree = Path(temp.name)
        (tree / "chaos").mkdir()
        for name in ("ledger.json", "project.yaml", "judges"):
            source = ROOT / "chaos" / name
            (shutil.copytree if source.is_dir() else shutil.copy)(source, tree / "chaos" / name)
        shutil.copytree(ROOT / "chaos/tests/runs/fixture-upload-live", tree / "chaos/runs/fixture-upload-live")
        # The validity judge holds a run only while its `scenario_row` is the digest of the scenario's row in the
        # tree's ledger. The recorded run names `recorded` for `ks-upload-no-fault` and `chaos/ledger.json` gives
        # `current`, so the copy names `current` and the judge writes the outcome `held`, which the held-receipt
        # case requires. If the ledger row's digest differs from `current`, the judge writes `invalid` and that
        # case fails.
        recorded = "55b2c9cdf9b08a7be0ee2dcecac61ecb817747764a235bc4bfc22fe448d436d5"
        current = "6733940892ad59f1e0cbf5747a891123187c1998b4412c59fe023675d7c61a31"
        run = tree / "chaos/runs/fixture-upload-live/run.json"
        record = json.loads(run.read_text())
        if record["scenario_row"] == recorded:
            record["scenario_row"] = current
            run.write_text(json.dumps(record))
        (tree / "chaos/receipts/fixture-upload-live").mkdir(parents=True)
        receipt = tree / "chaos/receipts/fixture-upload-live/ks-upload-no-fault.json"
        subprocess.run([sys.executable, "-I", "-B", "chaos/judges/core/validity.py", "ks-upload-no-fault", "--evidence",
                        "chaos/runs/fixture-upload-live", "--receipt", str(receipt)], cwd=tree, capture_output=True)
        replay = (sys.executable, str(ROOT / "scripts/chaos-receipt-replay.py"))
        original, project = receipt.read_text(), (tree / "chaos/project.yaml").read_text()

        def rewrite(change):
            data = json.loads(original)
            change(data)
            receipt.write_text(json.dumps(data))

        for case, edit, refused in (
            ("as recorded, at another time by another interpreter",
             lambda: rewrite(lambda data: data["run"].update(judged="2000-01-01T00:00:00Z", interpreter="0")), ()),
            ("outcome edited to broken, detail edited",
             lambda: rewrite(lambda data: data["key"].update(outcome="broken", detail=data["key"]["detail"] + "0")),
             ("differs in key.detail, key.outcome from the receipt",)),
            ("build in capitals, a figure and a note added, the mode removed, out_of_scope empty", lambda: (
                rewrite(lambda data: (data.update(note=1), data["key"].pop("mode"), data["key"].update(
                    figure={"k": 1}, system_build="A" + data["key"]["system_build"][1:]))),
                (tree / "chaos/project.yaml").write_text(project.replace("out_of_scope:", "out_of_scope: []\nx:"))),
             ("not 64 lowercase hexadecimal digits",
              "differs in key.figure, key.mode, key.system_build, note from the receipt", "no out_of_scope list")),
        ):
            with self.subTest(case=case):
                receipt.write_text(original)
                (tree / "chaos/project.yaml").write_text(project)
                edit()
                done = subprocess.run(replay, cwd=tree, capture_output=True, text=True)
                self.assertEqual((done.returncode, len(done.stdout.splitlines())), (1 if refused else 0, len(refused)),
                                 done.stdout)
                for text in refused:
                    self.assertIn(text, done.stdout)
        # A judge that writes no receipt leaves nothing to compare with, which is a refusal.
        spec = importlib.util.spec_from_file_location("chaos_receipt_replay", replay[1])
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        writes, sys.dont_write_bytecode = sys.dont_write_bytecode, True
        try:
            spec.loader.exec_module(module)
        finally:
            sys.dont_write_bytecode = writes
        lines = module.replay(receipt.relative_to(tree), json.loads(original),
                              {"ks-upload-no-fault": "chaos/judges/core/absent.py ks-upload-no-fault"}, tree / "scratch", {})
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("has no receipt of its judge to compare with", lines[0])
        # A judge that writes the stored receipt and exits with the code of another outcome is refused, and
        # so is a broken receipt whose detail lacks the rule text its row expects of a control.
        stub = ("import shutil, sys\n"
                "shutil.copy('stored.json', sys.argv[sys.argv.index('--receipt') + 1])\n"
                "sys.exit(1)\n")
        broken = json.loads(original)
        broken["key"].update(outcome="broken", detail="caught under the rule text")
        for case, stored, rule, refusal in (
            ("exit 1 beside a held receipt", json.loads(original), None, "its judge exits 1 and writes the outcome 'held'"),
            ("broken with the row's rule text", broken, "the rule text", None),
            ("broken without the row's rule text", broken, "another rule", "holds no rule text"),
            ("broken for a row with no control", broken, None, "holds no rule text"),
        ):
            with self.subTest(case=case):
                scratch = Path(tempfile.mkdtemp(dir=tree))
                (scratch / "stored.json").write_text(json.dumps(stored))
                (scratch / "judge.py").write_text(stub)
                with mock.patch.object(subprocess, "run", wraps=subprocess.run) as started:
                    lines = module.replay(receipt.relative_to(tree), stored,
                                          {"ks-upload-no-fault": "judge.py ks-upload-no-fault"}, scratch,
                                          {"ks-upload-no-fault": rule})
                self.assertEqual(started.call_args.kwargs["timeout"], module.JUDGE_WAIT_S)
                self.assertEqual(len(lines), 1 if refusal else 0, lines)
                if refusal:
                    self.assertIn(refusal, lines[0])
        wait = re.search(r"^JUDGE_WAIT_S = (\d+)$", (ROOT / "chaos/harness/run_scenario.py").read_text(), re.MULTILINE)
        if wait is None:
            self.fail("chaos/harness/run_scenario.py states no JUDGE_WAIT_S")
        self.assertEqual(module.JUDGE_WAIT_S, int(wait.group(1)))


if __name__ == "__main__":
    unittest.main()
