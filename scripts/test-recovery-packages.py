#!/usr/bin/env python3
"""Exercise recovery-packages.py's package validation, open items, repeat admission, five independent verdicts, stop
roster, repeat isolation, campaign safety and receipt over the committed manifest and synthetic lane receipts. The
base lines come from `scripts/recovery-package-lines.json`, the fixture the Rust formatters' test pins."""

import copy
import hashlib
import importlib.util
import io
import itertools
import json
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("recovery_packages", ROOT / "scripts/recovery-packages.py")
assert SPEC is not None and SPEC.loader is not None
packages = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(packages)
gate = packages.gate

DOCUMENT = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())
FIXTURE = json.loads((ROOT / "scripts/recovery-package-lines.json").read_text())
REVISION, DIGEST, MAPPINGS = "c" * 40, "d" * 64, "a" * 64
CAPTURED = FIXTURE["persisted"].removeprefix("persisted ").partition(" installed")[0]
RETAINED = (FIXTURE["retained"].removeprefix("retained ").removesuffix(" episode e")
            .replace("authority fixture coverage harness", "authority restart coverage fenced") + " episode {run}")
RESIDUAL = FIXTURE["residual"].removeprefix("residual ")
PERSISTED = FIXTURE["persisted"].removeprefix("persisted ")
INJECTION = {"CR-1": ("controller-reset", FIXTURE["controller-reset"].removeprefix("controller-reset ")),
             "PK-1": ("process-kill", FIXTURE["process-kill"].removeprefix("process-kill "))}
SUMMARY = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.00s"
CUSTODY = ("no repeat binds the host's reservation and a clear custody check at its start, so a direct lane run "
           "establishes no host exclusion")
OPEN_FILLED = {"CR-1": [f"no native class and credit interface: {DOCUMENT['packages']['owner']}",
                        "package CR-1 binds no record of each repeat's restoration outcome", CUSTODY],
               "PK-1": [f"no native class and credit interface: {DOCUMENT['packages']['owner']}",
                        "package PK-1 binds no record of each repeat's restoration outcome or of the deployment "
                        "owner's containment of the killed child's DMA", CUSTODY]}
PASSING = {"safety": "pass", "containment": "inconclusive", "retention": "pass", "progress": "pass",
           "residuals": "pass"}


def campaign_id(package):
    return packages.campaign_id(DIGEST, package, REVISION)


def filled():
    """The committed manifest with every owner input an approved campaign would supply that this judge accepts."""
    document = copy.deepcopy(DOCUMENT)
    for row in document["platforms"].values():
        row["supported"] = True
    for profile in ("cr1-controller-reset", "pk1-process-kill"):
        document["profiles"][profile]["platforms"] = dict.fromkeys(document["platforms"], "runs")
    p = document["packages"]
    p["interface"].update(repeats=2, legs={"authority": "restart", "coverage": "fenced"})
    for package in p["packages"].values():
        package["authority"] = {"approver": "the platform owner", "injection": package["injection"]}
    return document


def relaxed():
    """`filled()` with the profiles' whole-S and SIGKILL witnesses relaxed to their line prefixes, so a repeat that
    breaks one of those rules reaches the package judge's verdict instead of the declared-witness refusal."""
    document = filled()
    for profile, exact, prefix in (("cr1-controller-reset", "observe: retained S 23/23 ", "observe: retained S "),
                                   ("pk1-process-kill", "observe: retained S 23/23 ", "observe: retained S "),
                                   ("pk1-process-kill", "observe: process-kill signal 9 ",
                                    "observe: process-kill signal ")):
        witnesses = document["profiles"][profile]["roles"]["owner"]["cases"][0]["witnesses"]
        witnesses[witnesses.index(exact)] = prefix
    return document


def safety(package, standing=("i-1", "vol-1")):
    return {"tag": {"key": "kestrike-campaign", "value": campaign_id(package)}, "owner": "qualification",
            "budget_usd": 40, "deadline": "2031-01-01T00:00:00Z", "teardown_on_failure": True,
            "preexisting": ["vol-other"], "resources": [], "teardown": [], "standing": list(standing), "residue": []}


class Lane:
    """The lane's judge_profile for receipts the test writes: it credits a receipt that names the required revision
    and records `credited`, so the package judge's own binding rules are what the tests exercise."""

    artifact_name = staticmethod(gate.lane_module().artifact_name)

    def judge_profile(self, platforms, profile_name, profile, receipts, digest, revision):
        section = receipts[0]["hardware"]
        if section.get("revision") != revision:
            return False, [f"the receipts name revision {section.get('revision')}, not {revision}"]
        if not section.get("credited"):
            return False, ["platform row unsupported: x86_64-nitro-ebs"]
        return True, []


class Packages(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="recovery-packages-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)
        self.lane = Lane()
        self.serial = itertools.count()

    def write_run(self, package, repeat, lines=None, *, document=None, credited=True, episode=None, raw=None,
                  order=None, edit=None, stdout_extra=""):
        """One repeat's receipt and its raw artifacts in their own run directory. `lines` overrides printed lines by
        name, an entry of None leaving the line out; `order` reorders the printed names in raw stderr; `raw`
        replaces the stderr artifact; `edit` changes the receipt's case entry and section after they are built."""
        document = document or DOCUMENT
        spec = document["packages"]["packages"][package]
        run = f"{campaign_id(package)}-{package}-r{repeat}"
        label, injection = INJECTION[package]
        printed = {label: injection, "persisted": PERSISTED, "retained": RETAINED, "residual": RESIDUAL, **(lines or {})}
        printed = {name: detail.replace("{run}", run) for name, detail in printed.items() if detail is not None}
        observed = [{"kind": "observed", "name": name, "detail": detail, "ordinal": ordinal}
                    for ordinal, (name, detail) in enumerate(printed.items(), 2)]
        case = document["profiles"][spec["profile"]]["roles"][spec["role"]]["cases"][0]
        directory = self.dir / f"{package}-{repeat}-{next(self.serial)}"
        directory.mkdir()
        stdout = f"running 1 test\ntest {spec['case']} ... ok\n\n{SUMMARY}\n{stdout_extra}"
        names = order or list(printed)
        stderr = "".join(f"observe: {name} {printed[name]}\n" for name in names) if raw is None else raw
        output = stdout.strip() + "\n" + stderr.strip()
        start = {"kind": "start", "episode": run, "ordinal": 1, "profile": spec["profile"], "role": spec["role"],
                 "case": spec["case"]}
        entry = {"id": spec["case"], "observed": observed, "start": start,
                 "mappings": {"volume": "vol-1", "sha256": MAPPINGS}, "mappings_after": MAPPINGS,
                 "summary": [SUMMARY], "restoration": case["restoration"],
                 "witness_counts": {witness: output.count(witness) for witness in case["witnesses"]}}
        section = {"profile": spec["profile"], "role": spec["role"], "episode": episode or run, "revision": REVISION,
                   "credited": credited, "host": {"instance": "i-1"}, "platform": {"row": "x86_64-nitro-ebs"},
                   "toolchain": {"rustc": "1", "cargo": "1"}, "dependencies": ["a 1"], "build_environment": {},
                   "cases": [entry]}
        if edit:
            edit(entry, section)
        (directory / "receipt.json").write_text(json.dumps({"envelope": {"version": 1, "section": "hardware"},
                                                            "hardware": section}))
        stem = directory / self.lane.artifact_name(spec["case"])
        stem.with_name(stem.name + ".stdout").write_text(stdout)
        stem.with_name(stem.name + ".stderr").write_text(stderr)
        return {"repeat": repeat, "receipt": str(directory / "receipt.json")}

    def artifact(self, run, package, kind):
        stem = Path(run["receipt"]).parent / self.lane.artifact_name(DOCUMENT["packages"]["packages"][package]["case"])
        return stem.with_name(f"{stem.name}.{kind}")

    def judge(self, package, runs, *, document=None, **fields):
        campaign = {"campaign": campaign_id(package), "package": package, "revision": REVISION, "runs": runs,
                    "safety": safety(package), **fields}
        return packages.judge(document or DOCUMENT, DIGEST, campaign, self.lane)

    def test_the_committed_packages_validate_and_list_what_keeps_them_uncredited(self):
        found = packages.check(DOCUMENT)
        for item in ("platform row x86_64-nitro-ebs is unsupported", "the package interface declares no repeat count",
                     "package CR-1 declares no injection authority", "package PK-1 declares no injection authority",
                     "package CR-1's profile cr1-controller-reset is pending on platform row x86_64-nitro-ebs",
                     "package PK-1's profile pk1-process-kill is pending on platform row x86_64-nitro-ebs",
                     *OPEN_FILLED["CR-1"], *OPEN_FILLED["PK-1"]):
            self.assertIn(item, found)
        self.assertTrue(any(item.startswith("the package interface declares no qualified authority and coverage legs")
                            for item in found))
        self.assertTrue(any(item.startswith("package PK-1 leg reboot is unrun") for item in found))
        self.assertEqual([item for item in packages.check(filled()) if "unrun" not in item],
                         list(dict.fromkeys([*OPEN_FILLED["CR-1"], *OPEN_FILLED["PK-1"]])))

    def test_a_label_or_recovery_class_off_its_injection_is_refused(self):
        edits = {
            "a kill labeled power loss": ("PK-1", "class", "power-loss"),
            "a kill labeled a reboot": ("PK-1", "class", "reboot"),
            "a controller reset labeled host loss": ("CR-1", "class", "host-loss"),
            "a reset recovered by cold replacement": ("CR-1", "recovery", "volume-loss-control"),
            "a host-loss recovery": ("PK-1", "recovery", "warm-takeover"),
            "an undeclared injection": ("CR-1", "injection", "power-cut"),
            "a case the profile does not run": ("CR-1", "case", "storage::other"),
            "a profile the manifest lacks": ("PK-1", "profile", "absent"),
            "an unhashable profile": ("PK-1", "profile", ["absent"]),
            "an authority of another injection": ("CR-1", "authority", {"approver": "owner", "injection": "sigkill"}),
            "an authority that names no approver": ("PK-1", "authority", {"approved": True}),
        }
        for what, (name, key, value) in edits.items():
            with self.subTest(what):
                document = copy.deepcopy(DOCUMENT)
                document["packages"]["packages"][name][key] = value
                with self.assertRaises(gate.Refusal):
                    packages.check(document)
        for what, edit in {
            "a package also excluded": lambda p: p["excluded"].update({"CR-1": "owner"}),
            "another run identity": lambda p: p["interface"].update(run_identity="{campaign}-{repeat}"),
            "an empty stop roster": lambda p: p["interface"].update(stop=[]),
            "a boolean repeat count": lambda p: p["interface"].update(repeats=True),
            "a repeat count of zero": lambda p: p["interface"].update(repeats=0),
            "a repeat count past 64": lambda p: p["interface"].update(repeats=65),
            "a witness set without the residual line": lambda p: p["interface"].update(witness=["retained"]),
            "legs without coverage": lambda p: p["interface"].update(legs={"authority": "restart"}),
            "the fixture authority as a qualified leg": lambda p: p["interface"].update(
                legs={"authority": "fixture", "coverage": "fenced"}),
            "harness coverage as a qualified leg": lambda p: p["interface"].update(
                legs={"authority": "restart", "coverage": "harness"}),
            "a leg that is no word": lambda p: p["interface"].update(legs={"authority": "re start", "coverage": "x"}),
            "a list injection": lambda p: p["packages"]["CR-1"].update(injection=["controller-disable"]),
            "a credit interface the judge does not bind": lambda p: p.update(credit={"interface": "native"}),
            "a package that is no object": lambda p: p["packages"].update({"CR-1": "controller-reset"}),
            "a package without its profile": lambda p: p["packages"]["PK-1"].pop("profile"),
        }.items():
            with self.subTest(what):
                document = copy.deepcopy(DOCUMENT)
                edit(document["packages"])
                with self.assertRaises(gate.Refusal):
                    packages.check(document)
        for repeats in (1, 64):
            document = copy.deepcopy(DOCUMENT)
            document["packages"]["interface"]["repeats"] = repeats
            packages.check(document)
        document = copy.deepcopy(DOCUMENT)
        document["profiles"]["cr1-controller-reset"]["roles"]["owner"]["cases"][0]["witnesses"].remove(
            "observe: residual ")
        with self.assertRaisesRegex(gate.Refusal, "declares no witness"):
            packages.check(document)

    def test_a_complete_campaign_passes_four_verdicts_and_containment_waits_on_its_restoration_record(self):
        """Every owner input this judge accepts is filled and both repeats bind their evidence, so the only
        blockers are the open items no manifest value clears: the null credit interface and the unobserved
        restoration, which keeps containment inconclusive."""
        for name in ("CR-1", "PK-1"):
            with self.subTest(name):
                document = filled()
                runs = [self.write_run(name, repeat, document=document) for repeat in (1, 2)]
                receipt = self.judge(name, runs, document=document)
                self.assertEqual(receipt["reasons"], [])
                self.assertEqual(receipt["open"], OPEN_FILLED[name])
                self.assertEqual(receipt["verdicts"], PASSING)
                self.assertFalse(receipt["credited"])
                self.assertEqual(receipt["verdict"], "inconclusive")
                m = receipt["repeats"][0]["measurements"]
                self.assertEqual((m["served"], m["eligible"], m["bytes"], m["eligible_bytes"], m["unaffected_bytes"],
                                  m["affected_bytes"], m["first_hit_us"]), (23, 23, 1012, 1012, 1012, 0, 1))
                self.assertEqual(m["residuals"], dict.fromkeys(packages.RESIDUALS, 0))
                self.assertEqual(m["retirement"], {"retired-bytes": 4100, "waste": 257032})
                self.assertEqual(m["persisted"], {"checkpoint": CAPTURED, "slot": 0, "session": 0x300000002,
                                                  "capture": 9, "units": 3, "entries": 24, "installed": 23,
                                                  "omitted": 1})
                self.assertEqual((m["authority"], m["coverage"]), ("restart", "fenced"))
                self.assertEqual((m["session"], m["checkpoint_session"]), (0x300000003, 0x300000002))
                self.assertEqual(receipt["class"], INJECTION[name][0])
                self.assertEqual(receipt["recovery"], "same-host-restart")
                self.assertEqual(receipt["persistence"], document["packages"]["packages"][name]["persistence"])
                self.assertEqual(receipt["authority"], document["packages"]["packages"][name]["authority"])
                self.assertEqual(receipt["identity"]["row"], "x86_64-nitro-ebs")
                self.assertEqual(set(receipt["repeats"][0]["artifacts"]), {"stdout", "stderr"})
                self.assertEqual(receipt["repeats"][0]["artifacts"]["stdout"],
                                 receipt["repeats"][1]["artifacts"]["stdout"],
                                 "honest repeats print the same libtest stdout and share no evidence by it")
                self.assertIn("host-failure", receipt["excluded"])
        self.assertEqual(self.judge("PK-1", [self.write_run("PK-1", 1)])["unrun"],
                         DOCUMENT["packages"]["packages"]["PK-1"]["unrun"])

    def test_the_committed_owner_inputs_leave_a_passing_campaign_inconclusive(self):
        receipt = self.judge("CR-1", [self.write_run("CR-1", 1)])
        self.assertEqual(receipt["verdict"], "inconclusive")
        self.assertFalse(receipt["credited"])
        self.assertEqual(receipt["verdicts"], PASSING)
        for item in ("the package interface declares no repeat count", "package CR-1 declares no injection authority",
                     *OPEN_FILLED["CR-1"]):
            self.assertIn(item, receipt["open"])

    def test_each_open_item_alone_keeps_a_passing_campaign_uncredited(self):
        for what, edit, item in (
            ("no repeat count", lambda p: p["interface"].update(repeats=None),
             "the package interface declares no repeat count"),
            ("no legs", lambda p: p["interface"].update(legs=None),
             "the package interface declares no qualified authority and coverage legs, so a repeat recovered under a "
             "fixture authority and harness-built coverage earns no credit"),
            ("no injection authority", lambda p: p["packages"]["CR-1"].update(authority=None),
             "package CR-1 declares no injection authority"),
        ):
            with self.subTest(what):
                document = filled()
                edit(document["packages"])
                runs = [self.write_run("CR-1", repeat, document=document) for repeat in (1, 2)]
                receipt = self.judge("CR-1", runs, document=document)
                self.assertEqual(receipt["reasons"], [])
                self.assertEqual(sorted(receipt["open"]), sorted([*OPEN_FILLED["CR-1"], item]))
                self.assertEqual(receipt["verdicts"], PASSING)
                self.assertFalse(receipt["credited"])
                self.assertEqual(receipt["verdict"], "inconclusive")

    def test_each_broken_rule_fails_its_own_verdict_by_name(self):
        retained = RETAINED
        cases = {
            "correct misses": ("retention", "fail RetainedSetServed",
                               {"retained": retained.replace("S 23/23 bytes 1012", "S 0/23 bytes 0")}),
            "one member short": ("retention", "fail RetainedSetServed",
                                 {"retained": retained.replace("S 23/23 bytes 1012", "S 22/23 bytes 968")}),
            "an empty S": ("retention", "fail RetainedSetServed", {
                "retained": retained.replace("S 23/23 bytes 1012", "S 0/0 bytes 0")
                .replace("eligible-bytes 1012 unaffected-bytes 1012", "eligible-bytes 0 unaffected-bytes 0")
                .replace("omitted 1 installed 23", "omitted 24 installed 0"),
                "persisted": f"{CAPTURED} installed 0 omitted 24"}),
            "bytes off the unaffected bytes": ("retention", "fail UnaffectedBytesServed",
                                               {"retained": retained.replace("bytes 1012 wrong", "bytes 1000 wrong")}),
            "an affected share that breaks the sum": ("retention", "fail UnaffectedBytesServed",
                                                      {"retained": retained.replace("affected-bytes 0", "affected-bytes 4")}),
            "a load that installed the covered entry it missed": (
                "retention", "fail LoadCounts", {"persisted": f"{CAPTURED} installed 24 omitted 0"}),
            "a load short of S on both lines": ("retention", "fail LoadCounts", {
                "retained": retained.replace("omitted 1 installed 23", "omitted 2 installed 22"),
                "persisted": f"{CAPTURED} installed 22 omitted 2"}),
            "a load omitting past the captured entries": ("retention", "fail LoadCounts", {
                "retained": retained.replace("omitted 1 installed 23", "omitted 2 installed 23"),
                "persisted": f"{CAPTURED} installed 23 omitted 2"}),
            "lines that disagree on the omitted entries": ("retention", "fail LoadCounts",
                                                           {"persisted": f"{CAPTURED} installed 23 omitted 0"}),
            "a wrong read": ("safety", "fail ExactBytes", {"retained": retained.replace("wrong 0", "wrong 1")}),
            "an overlapping fill": ("safety", "fail DisjointAllocation",
                                    {"retained": retained.replace("overlapping 0", "overlapping 1")}),
            "no first warm hit": ("progress", "fail FirstWarmHit",
                                  {"retained": retained.replace("first-hit-us 1 ", "first-hit-us none ")}),
            "no fill at Live": ("progress", "fail FillAtLive", {"retained": retained.replace("reserved 41", "reserved 0")}),
            "a held fill": ("residuals", "fail ResidualsZero", {"residual": RESIDUAL.replace("filling +0", "filling +1")}),
            "a quarantined slot": ("residuals", "fail ResidualsZero",
                                   {"residual": RESIDUAL.replace("quarantined +0", "quarantined +1")}),
            "a slot below its account": ("residuals", "fail ResidualsZero",
                                         {"residual": RESIDUAL.replace("resident-slots +0", "resident-slots -1")}),
            "an enabled controller": ("containment", "fail InjectionObserved",
                                      {"controller-reset": INJECTION["CR-1"][1].replace("cc 0x460000", "cc 0x460001")}),
            "a ready controller": ("containment", "fail InjectionObserved",
                                   {"controller-reset": INJECTION["CR-1"][1].replace("csts 0x0", "csts 0x1")}),
            "another checkpoint persisted": ("containment", "fail PersistenceWitnessed",
                                             {"persisted": PERSISTED.replace("capture 9", "capture 8")}),
        }
        for what, (kind, verdict, lines) in cases.items():
            with self.subTest(what):
                document = relaxed()
                receipt = self.judge("CR-1", [self.write_run("CR-1", 1, lines, document=document)], document=document)
                self.assertEqual(receipt["verdicts"][kind], verdict)
                self.assertEqual({k: v for k, v in receipt["verdicts"].items() if k != kind},
                                 {k: v for k, v in PASSING.items() if k != kind})
                self.assertEqual(receipt["verdict"], "fail")
                self.assertFalse(receipt["credited"])
        document = relaxed()
        run = self.write_run("PK-1", 1, {"process-kill": INJECTION["PK-1"][1].replace("signal 9", "signal 15")},
                             document=document)
        self.assertEqual(self.judge("PK-1", [run], document=document)["verdicts"]["containment"],
                         "fail InjectionObserved", "a SIGTERM is no process kill")
        retired = self.write_run("CR-1", 1, {"residual": RESIDUAL.replace("retired-bytes 4100", "retired-bytes 7")},
                                 document=document)
        self.assertEqual(self.judge("CR-1", [retired], document=document)["verdicts"]["residuals"], "pass",
                         "the retirement counts are recorded and not judged")

    def test_a_served_covered_object_fails_safety_and_leaves_retention_passing(self):
        """The account a coverage copy without the INVALIDATE produces: every object served, the load installed all
        24 and omitted none, and the served bytes count members of S alone."""
        document = filled()
        lines = {"retained": RETAINED.replace("omitted 1 installed 23 covered-miss true",
                                              "omitted 0 installed 24 covered-miss false"),
                 "persisted": f"{CAPTURED} installed 24 omitted 0"}
        receipt = self.judge("CR-1", [self.write_run("CR-1", 1, lines, document=document)], document=document)
        self.assertEqual(receipt["verdicts"], {**PASSING, "safety": "fail CoveredObjectMisses"})

    def test_an_unmeasured_byte_split_leaves_retention_inconclusive_unless_a_member_missed(self):
        document = relaxed()
        unmeasured = RETAINED.replace("unaffected-bytes 1012 affected-bytes 0 damaged-units 0",
                                      "unaffected-bytes unmeasured affected-bytes unmeasured damaged-units 1")
        receipt = self.judge("CR-1", [self.write_run("CR-1", 1, {"retained": unmeasured}, document=document)],
                             document=document)
        self.assertEqual(receipt["verdicts"], {**PASSING, "retention": "inconclusive"})
        self.assertIsNone(receipt["repeats"][0]["measurements"]["affected_bytes"])
        short = unmeasured.replace("S 23/23 bytes 1012", "S 22/23 bytes 968")
        self.assertEqual(self.judge("CR-1", [self.write_run("CR-1", 1, {"retained": short}, document=document)],
                                    document=document)["verdicts"]["retention"], "fail RetainedSetServed")
        half = RETAINED.replace(" affected-bytes 0 ", " affected-bytes unmeasured ")
        receipt = self.judge("CR-1", [self.write_run("CR-1", 1, {"retained": half}, document=document)],
                             document=document)
        self.assertIn("measures one of its unaffected and affected bytes", receipt["repeats"][0]["missing"])

    def test_the_persistence_witness_must_follow_its_injection_in_the_raw_artifact(self):
        document = filled()
        run = self.write_run("CR-1", 1, document=document,
                             order=["persisted", "controller-reset", "retained", "residual"])
        self.assertEqual(self.judge("CR-1", [run], document=document)["verdicts"]["containment"],
                         "fail PersistenceWitnessed")

    def test_the_residual_inventory_must_follow_its_injection_in_the_raw_artifact(self):
        """A residual line printed before the injection inventories the tenure the fault ended, so its zeros fail
        residuals by the order rule while the lines that follow the injection keep their verdicts."""
        document = filled()
        run = self.write_run("CR-1", 1, document=document,
                             order=["residual", "controller-reset", "persisted", "retained"])
        self.assertEqual(self.judge("CR-1", [run], document=document)["verdicts"],
                         {**PASSING, "residuals": "fail ResidualsAfterTheInjection"})
        held = self.write_run("CR-1", 1, {"residual": RESIDUAL.replace("filling +0", "filling +1")}, document=document,
                              order=["residual", "controller-reset", "persisted", "retained"])
        self.assertEqual(self.judge("CR-1", [held], document=document)["verdicts"]["residuals"], "fail ResidualsZero",
                         "a nonzero residual is named first")

    def test_a_restoration_other_than_the_declared_one_fails_containment(self):
        document = filled()
        run = self.write_run("CR-1", 1, document=document, edit=lambda entry, _: entry.update(restoration="none"))
        self.assertEqual(self.judge("CR-1", [run], document=document)["verdicts"]["containment"],
                         "fail RestorationDeclared")

    def test_the_retained_line_decodes_each_field_by_name(self):
        line = ("S 21/23 bytes 924 wrong 2 eligible-bytes 1012 unaffected-bytes 968 affected-bytes 44 damaged-units 3 "
                "omitted 4 installed 20 covered-miss false reserved 17 overlapping 5 first-hit-us 2737 session 0x9 "
                "over checkpoint session 0x8 authority restart coverage fenced episode r1")
        found = {"retained": (line, 0), "residual": (RESIDUAL, 1), "persisted": (PERSISTED, 2),
                 "controller-reset": (INJECTION["CR-1"][1], 3)}
        m = packages.measure(DOCUMENT["packages"]["packages"]["CR-1"], found)
        self.assertEqual({k: m[k] for k in (*packages.COUNTS, "unaffected_bytes", "affected_bytes", "covered_miss",
                                            "first_hit_us", "authority", "coverage", "episode")},
                         {"served": 21, "eligible": 23, "bytes": 924, "wrong": 2, "eligible_bytes": 1012,
                          "damaged_units": 3, "omitted": 4, "installed": 20, "reserved": 17, "overlapping": 5,
                          "unaffected_bytes": 968, "affected_bytes": 44, "covered_miss": False, "first_hit_us": 2737,
                          "authority": "restart", "coverage": "fenced", "episode": "r1"})
        self.assertIsNone(packages.measure(DOCUMENT["packages"]["packages"]["CR-1"], {
            **found, "retained": (line.replace("first-hit-us 2737", "first-hit-us none"), 0)})["first_hit_us"])
        self.assertEqual(m["injection"], {"cc": 0x460000, "csts": 0, "after": CAPTURED})
        killed = packages.measure(DOCUMENT["packages"]["packages"]["PK-1"], {
            "retained": (line, 0), "residual": (RESIDUAL, 1), "persisted": (PERSISTED, 2),
            "process-kill": (INJECTION["PK-1"][1], 3)})
        self.assertEqual(killed["injection"], {"signal": 9, "pid": 7, "after": CAPTURED})

    def test_a_repeat_without_its_lines_or_artifacts_or_binding_is_missing(self):
        observe = "".join(f"observe: {n} {d}\n" for n, d in (
            ("controller-reset", INJECTION["CR-1"][1]), ("persisted", PERSISTED), ("residual", RESIDUAL)))
        retained = RETAINED.replace("{run}", f"{campaign_id('CR-1')}-CR-1-r1")
        one = {"controller-reset": INJECTION["CR-1"][1].replace("entries 24", "entries 2"),
               "retained": (retained.replace("S 23/23 bytes 1012", "S 1/1 bytes 44")
                            .replace("eligible-bytes 1012 unaffected-bytes 1012", "eligible-bytes 44 unaffected-bytes 44")
                            .replace("omitted 1 installed 23", "omitted 1 installed 1")),
               "residual": RESIDUAL,
               "persisted": PERSISTED.replace("entries 24 installed 23", "entries 2 installed 1")}

        def raw_with(*extra):
            return observe + "".join(extra)

        def entry_edit(**fields):
            return lambda entry, _: entry.update(fields)

        cases = {
            "no residual line": ({"residual": None}, {}, "declared witness 'observe: residual '"),
            "a line off its shape": ({"residual": "filling 0"}, {}, "off its shape"),
            "a register past 32 bits": ({"controller-reset": INJECTION["CR-1"][1].replace("0x460000", "0x100000000")},
                                        {}, "off its shape"),
            "a register of 4000 hex digits": ({"controller-reset": INJECTION["CR-1"][1].replace("0x460000",
                                                                                               "0x" + "f" * 4000)},
                                              {}, "off its shape"),
            "a non-ASCII digit": ({"residual": RESIDUAL.replace("filling +0", "filling +\u0661")}, {},
                                  "off its shape"),
            "a line the raw artifact lacks": ({}, {"raw": "observe: unrelated\n"}, "hold 0 of the declared witness"),
            "two residual lines in raw stderr": ({}, {"raw": raw_with(
                "observe: retained " + retained + "\n", "observe: residual " + RESIDUAL + "\n")},
                "holds 2 residual lines"),
            "a raw line other than the receipt's": ({}, {"raw": raw_with(
                "observe: retained " + retained.replace("wrong 0", "wrong 9") + "\n")},
                "not the one the raw stderr artifact holds"),
            "a whole-S witness only inside another line": (one, {"raw": "".join(
                [*(f"observe: {n} {d}\n" for n, d in one.items()), "expected observe: retained S 23/23 members\n"])},
                "the retained line does not carry the declared witness 'observe: retained S 23/23 '"),
            "another lane episode": ({}, {"episode": "other"}, "ran in episode 'other'"),
            "a retained line of another episode": ({"retained": RETAINED.format(run="other")}, {},
                                                   "names episode 'other'"),
            "an uncredited lane receipt": ({}, {"credited": False}, "uncredited: platform row unsupported"),
            "no observer log": ({}, {"edit": entry_edit(start=None)}, "only under an observer log"),
            "a start past the first event": ({}, {"edit": lambda entry, _: entry["start"].update(ordinal=3)},
                                             "the log holds an earlier event of that episode"),
            "a mappings file changed during the case": ({}, {"edit": entry_edit(mappings_after="b" * 64)},
                                                        "another digest at the case's end"),
            "a mappings file unreadable at the end": ({}, {"edit": entry_edit(mappings_after=None)},
                                                      "another digest at the case's end"),
            "no host instance": ({}, {"edit": lambda _, section: section.update(host={})}, "no host instance"),
            "no bound volume": ({}, {"edit": lambda entry, _: entry["mappings"].pop("volume")}, "no bound volume"),
            "a summary the raw artifacts lack": ({}, {"edit": entry_edit(summary=["test result: ok. 2 passed;"])},
                                                 "libtest summary"),
        }
        for what, (lines, options, reason) in cases.items():
            with self.subTest(what):
                document = filled()
                run = self.write_run("CR-1", 1, lines, document=document, **options)
                receipt = self.judge("CR-1", [run], document=document)
                self.assertIn(reason, receipt["repeats"][0].get("missing", ""), receipt["repeats"][0])
                self.assertEqual(receipt["verdicts"], dict.fromkeys(packages.KINDS, "inconclusive"))
                self.assertIn("repeat 1 is missing evidence and the campaign records no stop at it", receipt["reasons"])
                self.assertEqual(receipt["verdict"], "inconclusive")
        for kind in ("stdout", "stderr"):
            with self.subTest(f"no {kind} artifact"):
                document = filled()
                run = self.write_run("CR-1", 1, document=document)
                self.artifact(run, "CR-1", kind).unlink()
                receipt = self.judge("CR-1", [run], document=document)
                self.assertIn(f"raw {kind} artifact", receipt["repeats"][0]["missing"])
        with self.subTest("a witness line on stdout"):
            document = filled()
            run = self.write_run("CR-1", 1, document=document, stdout_extra="observe: residual " + RESIDUAL + "\n")
            self.assertIn("raw stdout artifact holds a residual line",
                          self.judge("CR-1", [run], document=document)["repeats"][0]["missing"])

    def test_each_binding_over_the_lane_refuses_or_fails_alone_by_name(self):
        """Each binding the package judge adds over the lane fails alone: the retained line's sessions and order
        against the injection, a numeric split beside damage, the capture's size, the start event's identity and
        ordinal type, the declared witness counts, repeated JSON keys and numbers outside their source types."""
        retention = {
            "another checkpoint session": {"retained": RETAINED.replace("over checkpoint session 0x300000002",
                                                                     "over checkpoint session 0x300000001")},
            "a recovered session not above the checkpoint's": {
                "retained": RETAINED.replace("session 0x300000003 over", "session 0x300000002 over")},
            "a capture of other than S and the covered entry": {
                "retained": RETAINED.replace("omitted 1 installed 23", "omitted 2 installed 23"),
                "persisted": PERSISTED.replace("entries 24 installed 23 omitted 1", "entries 25 installed 23 omitted 2"),
                "controller-reset": INJECTION["CR-1"][1].replace("entries 24", "entries 25")},
        }
        for what, lines in retention.items():
            with self.subTest(what):
                document = filled()
                receipt = self.judge("CR-1", [self.write_run("CR-1", 1, lines, document=document)], document=document)
                self.assertTrue(receipt["verdicts"]["retention"].startswith("fail "), receipt["verdicts"])
        document = filled()
        run = self.write_run("CR-1", 1, document=document,
                             order=["retained", "controller-reset", "persisted", "residual"])
        self.assertEqual(self.judge("CR-1", [run], document=document)["verdicts"]["retention"],
                         "fail RecoveredFromTheCheckpoint", "the retained line precedes the injection")
        damaged = {"retained": RETAINED.replace("damaged-units 0", "damaged-units 1")}
        self.assertEqual(self.judge("CR-1", [self.write_run("CR-1", 1, damaged, document=document)],
                                    document=document)["verdicts"]["retention"], "inconclusive")
        missing = {
            "a boolean start ordinal": (lambda entry, _: entry["start"].update(ordinal=True), "event True"),
            "a float start ordinal": (lambda entry, _: entry["start"].update(ordinal=1.0), "event 1.0"),
            "a ready event as the start": (lambda entry, _: entry["start"].update(kind="ready"), "names ['ready'"),
            "a start of another episode": (lambda entry, _: entry["start"].update(episode="other"),
                                           "names ['start', 'other'"),
            "a start of another profile": (lambda entry, _: entry["start"].update(profile="fis-read"), "'fis-read'"),
            "a start of another case": (lambda entry, _: entry["start"].update(case="storage::other"),
                                        "'storage::other'], not"),
            "no mappings digest": (lambda entry, _: entry["mappings"].pop("sha256"), "another digest"),
            "a witness count off the raw artifacts":
                (lambda entry, _: entry["witness_counts"].update({"observe: residual ": 2}), "the receipt counts 2"),
            "no receipt event for a raw line":
                (lambda entry, _: entry.update(observed=[e for e in entry["observed"] if e["name"] != "residual"]),
                 "records 0 residual lines"),
        }
        for what, (edit, reason) in missing.items():
            with self.subTest(what):
                receipt = self.judge("CR-1", [self.write_run("CR-1", 1, document=document, edit=edit)],
                                     document=document)
                self.assertIn(reason, receipt["repeats"][0]["missing"], what)
        for what, lines in {
            "a zero-padded count": {"retained": RETAINED.replace("reserved 41", "reserved 041")},
            "a slot past 32 bits": {"persisted": PERSISTED.replace("slot 0", "slot 4294967296")},
            "a residual past i64": {"residual": RESIDUAL.replace("filling +0", "filling +9223372036854775808")},
            "a zero-padded register": {"controller-reset": INJECTION["CR-1"][1].replace("csts 0x0", "csts 0x00")},
            "damaged units past 32 bits": {"retained": RETAINED.replace(
                "unaffected-bytes 1012 affected-bytes 0 damaged-units 0",
                "unaffected-bytes unmeasured affected-bytes unmeasured damaged-units 4294967296")},
        }.items():
            with self.subTest(what):
                receipt = self.judge("CR-1", [self.write_run("CR-1", 1, lines, document=document)], document=document)
                self.assertIn("outside its type or not as the case prints it",
                              receipt["repeats"][0].get("missing", ""), receipt["repeats"][0])
        for what, pid in {"a pid past 32 bits": "pid 4294967296 ", "a zero-padded pid": "pid 07 "}.items():
            with self.subTest(what):
                lines = {"process-kill": INJECTION["PK-1"][1].replace("pid 7 ", pid)}
                receipt = self.judge("PK-1", [self.write_run("PK-1", 1, lines, document=document)], document=document)
                self.assertIn("outside its type or not as the case prints it",
                              receipt["repeats"][0].get("missing", ""), receipt["repeats"][0])
        with self.subTest("a raw retained line without its newline"):
            run = self.write_run("CR-1", 1, document=document,
                                 order=["controller-reset", "persisted", "residual", "retained"])
            stderr = self.artifact(run, "CR-1", "stderr")
            stderr.write_text(stderr.read_text().rstrip("\n"))
            self.assertIn("holds 0 retained lines",
                          self.judge("CR-1", [run], document=document)["repeats"][0]["missing"])
        with self.subTest("a receipt with a repeated key"):
            run = self.write_run("CR-1", 1, document=document)
            text = Path(run["receipt"]).read_text()
            Path(run["receipt"]).write_text(text.replace('{"envelope":', '{"hardware": {}, "envelope":', 1))
            self.assertIn("repeats an object key",
                          self.judge("CR-1", [run], document=document)["repeats"][0]["missing"])

    def test_credit_needs_every_kind_passing_with_no_open_item_or_reason(self):
        kinds = dict.fromkeys(packages.KINDS, "pass")
        self.assertTrue(packages.credit([], [], kinds))
        self.assertFalse(packages.credit(["an open item"], [], kinds))
        self.assertFalse(packages.credit([], ["a reason"], kinds))
        self.assertFalse(packages.credit([], [], {}))
        for kind in packages.KINDS:
            for verdict in ("inconclusive", "fail Rule"):
                self.assertFalse(packages.credit([], [], {**kinds, kind: verdict}), (kind, verdict))

    def test_the_stop_roster_and_repeat_isolation_bind_the_runs(self):
        document = filled()
        first, second = (self.write_run("CR-1", repeat, document=document) for repeat in (1, 2))
        roster = document["packages"]["interface"]["stop"]
        failed = self.write_run("CR-1", 2, document=document, credited=False)
        stopped = self.judge("CR-1", [first, failed], document=document,
                             stopped={"repeat": 2, "reason": roster[0]})
        self.assertEqual(stopped["reasons"], [f"the campaign stopped at repeat 2: {roster[0]}"],
                         "a stop at the missing repeat is the roster's, and a stopped campaign credits nothing")
        self.assertEqual(stopped["verdict"], "inconclusive")
        early = self.judge("CR-1", [first], document=document, stopped={"repeat": 1, "reason": roster[1]})
        self.assertIn("the campaign ran 1 repeats, not the declared 2", early["reasons"])
        self.assertEqual(early["verdicts"], PASSING)
        self.assertFalse(early["credited"], "a campaign stopped after a passing repeat is short of its repeats")
        self.assertIn("the campaign stopped at repeat 1 and ran 2",
                      self.judge("CR-1", [first, second], document=document,
                                 stopped={"repeat": 1, "reason": roster[0]})["reasons"])
        self.assertIn("the stop reason 'tired' is not on the stop roster",
                      self.judge("CR-1", [first, failed], document=document,
                                 stopped={"repeat": 2, "reason": "tired"})["reasons"])
        self.assertIn("the campaign ran 1 repeats, not the declared 2",
                      self.judge("CR-1", [first], document=document)["reasons"])
        self.assertIn("the runs are repeats [2, 1], not 1 to 2 in order, each once",
                      self.judge("CR-1", [second, first], document=document)["reasons"])
        shared = self.judge("CR-1", [first, {**first, "repeat": 2}], document=document)
        self.assertTrue(any("ran in episode" in r.get("missing", "") for r in shared["repeats"]),
                        "a copied receipt names its first repeat's episode, so it is never a second repeat")
        self.assertEqual(self.judge("CR-1", [first, second], document=document)["reasons"], [],
                         "two honest repeats can share their libtest stdout and nothing else")
        twice = self.judge("CR-1", [first, first], document=document)["reasons"]
        self.assertIn("the runs are repeats [1, 1], not 1 to 2 in order, each once", twice)
        self.assertIn("repeat 1 shares a receipt or raw stderr artifact with an earlier repeat", twice)

    def test_admitted_repeats_share_one_build_identity_and_the_declared_legs(self):
        document = filled()
        first = self.write_run("CR-1", 1, document=document)
        other = self.write_run("CR-1", 2, document=document,
                               edit=lambda _, section: section.update(toolchain={"rustc": "2", "cargo": "2"}))
        self.assertIn("repeat 2 ran on another platform row, toolchain, dependency set or build environment than the "
                      "campaign's first admitted repeat",
                      self.judge("CR-1", [first, other], document=document)["reasons"])
        row = self.write_run("CR-1", 2, document=document,
                             edit=lambda _, section: section.update(platform={"row": "aarch64-r8gb-4xlarge-ebs"}))
        self.assertTrue(self.judge("CR-1", [first, row], document=document)["reasons"])
        document["packages"]["interface"]["legs"] = {"authority": "restart", "coverage": "fenced"}
        fixture_legs = {"retained": RETAINED.replace("authority restart coverage fenced",
                                                     "authority fixture coverage harness")}
        runs = [self.write_run("CR-1", repeat, fixture_legs, document=document) for repeat in (1, 2)]
        receipt = self.judge("CR-1", runs, document=document)
        self.assertIn("repeat 1 recovered under authority fixture and coverage harness, not the declared legs restart "
                      "and fenced", receipt["reasons"])
        self.assertFalse(receipt["credited"])
        runs = [self.write_run("CR-1", repeat, document=document) for repeat in (1, 2)]
        self.assertEqual(self.judge("CR-1", runs, document=document)["reasons"], [])
        for field, value in (("dependencies", ["b 2"]), ("build_environment", {"OPT": "3"})):
            other = self.write_run("CR-1", 2, document=document,
                                   edit=lambda _, section, field=field, value=value: section.update({field: value}))
            self.assertIn("repeat 2 ran on another platform row, toolchain, dependency set or build environment than "
                          "the campaign's first admitted repeat",
                          self.judge("CR-1", [runs[0], other], document=document)["reasons"], field)

    def test_the_package_verdict_is_the_worst_over_its_repeats(self):
        document = filled()
        broken = {"residual": RESIDUAL.replace("filling +0", "filling +1")}
        stop = {"repeat": 2, "reason": "a repeat the lane leaves uncredited"}
        for what, makes, stopped, expected in (
            ("fail then pass", [broken, None], None, {**PASSING, "residuals": "fail ResidualsZero"}),
            ("pass then fail", [None, broken], None, {**PASSING, "residuals": "fail ResidualsZero"}),
            ("pass then missing", [None, "missing"], stop, dict.fromkeys(packages.KINDS, "inconclusive")),
            ("fail then missing", [broken, "missing"], stop,
             {**dict.fromkeys(packages.KINDS, "inconclusive"), "residuals": "fail ResidualsZero"}),
        ):
            with self.subTest(what):
                runs = [self.write_run("CR-1", repeat, None if make == "missing" else make, document=document,
                                       credited=make != "missing")
                        for repeat, make in enumerate(makes, 1)]
                receipt = self.judge("CR-1", runs, document=document, **({"stopped": stopped} if stopped else {}))
                self.assertEqual(receipt["verdicts"], expected)
                self.assertFalse(receipt["credited"])
                self.assertEqual(receipt["verdict"], "fail" if "fail" in what else "inconclusive")
        self.assertEqual(packages.worst(["pass", "unscored"]), "inconclusive")
        self.assertEqual(packages.worst([]), "inconclusive")
        self.assertEqual(packages.worst(["fail B", "inconclusive", "fail A"]), "fail A")

    def test_the_campaign_identity_and_safety_manifest_gate_credit(self):
        document = filled()
        runs = [self.write_run("CR-1", repeat, document=document) for repeat in (1, 2)]
        self.assertIn(f"the campaign id is not {campaign_id('CR-1')}, the one campaign of this manifest, package and "
                      "revision", self.judge("CR-1", runs, document=document, campaign="package-0")["reasons"])
        gaps = self.judge("CR-1", runs, document=document, safety=safety("CR-1", ["i-1"]))
        self.assertIn("the admitted runs bind ['vol-1'], which the safety manifest lists neither as creates nor as "
                      "standing", gaps["reasons"])
        self.assertFalse(gaps["credited"])
        residue = self.judge("CR-1", runs, document=document, safety={**safety("CR-1"), "residue": ["vol-9"]})
        self.assertIn("residue verification found ['vol-9']", residue["reasons"])
        touched = self.judge("CR-1", runs, document=document, safety={**safety("CR-1"), "preexisting": ["vol-1"]})
        self.assertTrue(any("touched preexisting resources ['vol-1']" in r for r in touched["reasons"]))
        self.assertIn("the campaign records no safety manifest",
                      self.judge("CR-1", runs, document=document, safety=None)["reasons"])

    def test_malformed_campaigns_are_refused(self):
        run = {"repeat": 1, "receipt": "absent"}
        for what, campaign in {
            "an undeclared package": {"package": "HF-1"},
            "a list package": {"package": ["CR-1"]},
            "a short revision": {"revision": "abc"},
            "a run without its receipt": {"runs": [{"repeat": 1}]},
            "a repeat zero": {"runs": [{"repeat": 0, "receipt": "absent"}]},
            "a repeat past 64": {"runs": [{"repeat": 65, "receipt": "absent"}]},
            "more runs than any repeat count": {"runs": [{"repeat": i, "receipt": str(self.dir / f"absent-{i}")}
                                                         for i in range(1, packages.MAX_REPEATS + 2)]},
            "an unknown key": {"retries": 1},
            "a malformed stop": {"stopped": {"repeat": 1}},
        }.items():
            with self.subTest(what), self.assertRaises(gate.Refusal):
                packages.judge(DOCUMENT, DIGEST, {"campaign": "x", "package": "CR-1", "revision": REVISION,
                                                  "runs": [run], **campaign}, self.lane)

    def test_the_command_writes_the_receipt_and_exits_by_credit(self):
        run = self.write_run("CR-1", 1)
        manifest = ROOT / "scripts/hardware-profiles.json"
        digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
        campaign = self.dir / "campaign.json"
        campaign.write_text(json.dumps({"campaign": packages.campaign_id(digest, "CR-1", REVISION), "package": "CR-1",
                                        "revision": REVISION, "runs": [run], "safety": safety("CR-1")}))
        output = self.dir / "package.json"
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            code = packages.main(["judge", "--campaign", str(campaign), "--output", str(output)])
        self.assertEqual(code, 1)
        receipt = json.loads(output.read_text())
        self.assertEqual((receipt["manifest_sha256"], receipt["campaign_sha256"]),
                         (digest, hashlib.sha256(campaign.read_bytes()).hexdigest()))
        self.assertIn("uncredited", receipt["repeats"][0]["missing"], "the real lane refuses the synthetic receipt")
        campaign.write_text("[")
        err = io.StringIO()
        with redirect_stderr(err):
            self.assertEqual(packages.main(["judge", "--campaign", str(campaign)]), 2)
        self.assertIn("refused", err.getvalue())
        with redirect_stdout(io.StringIO()) as out:
            self.assertEqual(packages.main(["check"]), 0)
        self.assertIn("the package interface declares no repeat count", out.getvalue())


if __name__ == "__main__":
    unittest.main()
