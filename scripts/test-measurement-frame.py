#!/usr/bin/env python3
"""Exercise measurement-frame.py's record checks, field-source column, floor rule, Wilson edge rates, revision log,
policy non-retroactivity and registration, host admission, clock trust, controls, evidence-kind columns, the samples
reader and its use of the hit gate's own judgment, and the comparison judge: seeded blocks, paired log contrasts,
order-statistic bounds, censoring, pilot floors, the fixed horizon, the derived A/A and drift controls, the AWS safety
manifest and authority, the four columns, the sizing hand-off and the result-to-ticket bound verdict, over the
committed records and synthetic campaigns."""

import copy
import hashlib
import importlib.util
import io
import json
import math
import os
import subprocess
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from fractions import Fraction
from pathlib import Path
from statistics import NormalDist
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("measurement_frame", ROOT / "scripts/measurement-frame.py")
assert SPEC is not None and SPEC.loader is not None
mf = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mf)
gate = mf.gate

LANE = gate.lane_module()
DOCUMENT, DIGEST = gate.read_document(gate.MANIFEST, LANE)
QUALIFICATION = DOCUMENT["qualification"]
IDS = gate.obligation_ids(gate.OBLIGATIONS)
RECORDS, LOG = mf.load(mf.RECORDS)
COMMIT, PATCH = "c" * 40, mf.NO_PATCH
CELL = "request-weighted/idle/0"
GIT_SHOW = mf.git_show
CURRENT = {kind: RECORDS[kind][0]["version"] for kind in mf.KINDS}
NEXT = {kind: version + 1 for kind, version in CURRENT.items()}
CONTEXT = {"document": DOCUMENT, "manifest_sha256": DIGEST, "ids": IDS, "lane": LANE}


def encode(document):
    return (json.dumps(document, indent=1) + "\n").encode()


def held(records):
    """The bytes a commit holding `records` holds at each record path, for a mocked `git_show`."""
    return {f"{mf.RECORDS_PATH}/{kind}.json": (mf.RECORDS / f"{kind}.json").read_bytes()
            if records[kind][1] == RECORDS[kind][1] else encode(records[kind][0]) for kind in mf.KINDS}


def holding(records):
    """A patch of `git_show` under which the campaign commit holds `records`."""
    files = held(records)
    return mock.patch.object(mf, "git_show", side_effect=lambda revision, path: files.get(path))


def build(frame=None, statistics=None, policy=None, relog=True):
    """Records from the committed ones with `frame`, `statistics` and `policy` edited in place by the callables given.
    With `relog`, the policy pins the edited frame and statistics and each kind's log keeps the committed entries
    below the edited record's version and ends at its bytes."""
    docs = {kind: copy.deepcopy(RECORDS[kind][0]) for kind in mf.KINDS}
    for kind, edit in (("frame", frame), ("statistics", statistics), ("policy", policy)):
        if edit:
            edit(docs[kind])

    def digest(kind):
        unchanged = docs[kind] == RECORDS[kind][0]
        return RECORDS[kind][1] if unchanged else hashlib.sha256(encode(docs[kind])).hexdigest()

    if relog:
        for kind in ("frame", "statistics"):
            docs["policy"][kind] = {"version": docs[kind]["version"], "sha256": digest(kind)}
    records = {kind: (docs[kind], digest(kind)) for kind in mf.KINDS}
    log = copy.deepcopy(LOG)
    if relog:
        log = {kind: [*(e for e in LOG[kind] if e["version"] < docs[kind]["version"]), mf.pin(records, kind)]
               for kind in mf.KINDS}
    return records, log


def filled():
    """The manifest with a declared protocol and a supported x86_64 row, and records whose frame pins it."""
    document = copy.deepcopy(DOCUMENT)
    document["platforms"]["x86_64-nitro-ebs"]["supported"] = True
    q = document["qualification"]
    q["offered_rate"] = 1000
    q["protocol"] = {"null_blocks": 2, "blocks": 2, "repeats": 1, "requests": 4000, "max_lag_us": 1000,
                     "position_hits": 1000, "max_non_hits": 100, "band_coverage": 0.5,
                     "tolerance_ms": {"p90": 0.05, "p99": 0.2}}
    records, log = build(frame=lambda f: f["hit_gate"].update(qualification_sha256=mf.canonical(q)))
    return document, records, log


OPEN = [
    "the envelope declares no n_max", "the envelope declares no volume_size_bytes", "the envelope declares no iops",
    "the envelope declares no host_sharing", "the envelope declares no platform_row",
    "the envelope declares no cpu_family", "the envelope declares no workload_sha256",
    "the frame names no frozen population manifest",
    "familywise_alpha 0.05 is provisional, so every result is discovery, not powered confirmation",
    "power 0.9 is provisional, so every result is discovery, not powered confirmation",
    "the statistics version declares no horizon block count",
    "the statistics version declares no sample size from the power target",
    "the statistics version declares no plateau bands", "the statistics version declares no calibration drift band",
    "the statistics version declares no comparison strata",
    "the statistics version declares no budget bound", "F declares no accepted percentile",
    "F declares no accepted budget_ms", "the policy declares no fill_band", "the policy declares no fill_window_s",
    "the policy declares no full_load_window_s", "the policy declares no request_deadline_ms",
    "H declares no edge threshold for p50",
    *(f"the request tail declares no edge threshold for {q}" for q in ("p50", "p90", "p99", "p999")),
    "the policy names no readiness-review class list",
    "the policy declares no foreground reservation for the calibration's worker slots",
    "the policy names no campaign authority, budget or host-hour limit",
    *(f"{member} declares no {key}" for member in ("first_safe_hit", "retained_hit_recovery",
                                                   "sustained_fill_readiness", "rto", "request_tail", "origin_demand",
                                                   "goodput", "held_capacity", "peak_ram")
      for key in ("normalization", "boundary", "smallest_effect")),
    "fill_latency declares no normalization", "fill_latency declares no smallest_effect",
    "25 budget rows hold no accepted budget and read unscored",
]


class Records(unittest.TestCase):
    def test_the_committed_records_check_and_list_their_null_inputs_and_provisional_choices(self):
        self.assertCountEqual(mf.check(RECORDS, LOG, QUALIFICATION), OPEN)

    def test_the_committed_files_are_their_logged_revisions(self):
        for kind in mf.KINDS:
            data = (mf.RECORDS / f"{kind}.json").read_bytes()
            self.assertEqual(LOG[kind][-1]["sha256"], hashlib.sha256(data).hexdigest())

    def test_a_field_read_from_a_host_report_count_spans_the_counts_reset_identity(self):
        """The host report's contract gives each count a reset identity, and the count restarts from zero at it. A frame
        field whose producer is such a count measures within that identity: an estimand over a longer span reads one
        value where the count restarted inside the span."""
        report = "crates/kestrike/src/failover/report"
        contract = json.loads((ROOT / report / "contract.json").read_bytes())
        spans = {"tenure": "in the entry's tenure", "writer.boot": "since the writer's boot"}
        self.assertEqual(set(contract["reset_identities"]), set(spans))
        for name, count, symbol in (("capture_abandonment", "entries.captures.abandoned", "pub abandoned"),):
            with self.subTest(name):
                field = RECORDS["frame"][0]["fields"][name]
                self.assertEqual(field["sources"]["hardware"],
                                 {"kind": "producer", "path": f"{report}.rs", "symbol": symbol})
                self.assertTrue(field["estimand"].endswith(spans[contract["resets"][count]]), field["estimand"])

    def test_a_policy_version_that_declares_a_normalization_and_its_unit_checks(self):
        def revise(p):
            p["version"] = NEXT["policy"]
            p["outcomes"]["rto"].update(normalization="per recovered object", unit="s/object")

        records, log = build(policy=revise)
        found = mf.check(records, log, QUALIFICATION)
        self.assertNotIn("rto declares no normalization", found)
        self.assertIn("first_safe_hit declares no normalization", found)

        def rename(p):
            p["version"] = NEXT["policy"]
            p["outcomes"]["rto"]["unit"] = "ms"

        records, log = build(policy=rename)
        with self.assertRaisesRegex(gate.Refusal, "outcome rto's unit 'ms' is not its field's 's'"):
            mf.check(records, log, QUALIFICATION)

    def test_each_null_edge_threshold_is_an_open_item(self):
        def revise(p):
            p["version"] = NEXT["policy"]
            p["request_tail_edge_ms"]["p999"] = 4.0
            p["h"]["edge"]["p50"] = "p90_ms"

        records, log = build(policy=revise)
        found = mf.check(records, log, QUALIFICATION)
        self.assertEqual([item for item in found if "edge threshold" in item],
                         [f"the request tail declares no edge threshold for {q}" for q in ("p50", "p90", "p99")])

    def test_accepting_the_provisional_alpha_takes_a_new_logged_version(self):
        def accept(s):
            s["familywise_alpha"]["status"] = "accepted"

        records, log = build(statistics=accept, relog=False)
        with self.assertRaisesRegex(gate.Refusal,
                                    f"statistics version {CURRENT['statistics']} with SHA-256 .* is not its last "
                                    "logged"):
            mf.check(records, log, QUALIFICATION)

        def revise(s):
            accept(s)
            s["version"] = NEXT["statistics"]

        records, _ = build(statistics=revise)
        log = {**LOG, "statistics": [*LOG["statistics"], mf.pin(records, "statistics")]}
        with self.assertRaisesRegex(gate.Refusal,
                                    f"policy version {CURRENT['policy']} with SHA-256 .* is not its last logged"):
            mf.check(records, log, QUALIFICATION)
        records, log = build(statistics=revise, policy=lambda p: p.update(version=NEXT["policy"]))
        log = {kind: [*LOG[kind], mf.pin(records, kind)] if kind != "frame" else LOG[kind] for kind in mf.KINDS}
        found = mf.check(records, log, QUALIFICATION, prior=LOG)
        self.assertFalse(any(item.startswith("familywise_alpha") for item in found))
        self.assertIn("power 0.9 is provisional, so every result is discovery, not powered confirmation", found)

    def test_a_log_that_rewrites_an_earlier_entry_is_refused_against_the_base_log(self):
        records, log = build(statistics=lambda s: s["familywise_alpha"].update(status="accepted"))
        mf.check(records, log, QUALIFICATION)
        with self.assertRaisesRegex(gate.Refusal, "the statistics revisions rewrite or drop an entry"):
            mf.check(records, log, QUALIFICATION, prior=LOG)
        mf.check(RECORDS, LOG, QUALIFICATION, prior={kind: [] for kind in mf.KINDS})

    def test_the_base_log_is_read_from_the_named_commit(self):
        with self.assertRaisesRegex(gate.Refusal, "names no commit of this repository"):
            mf.prior_log("f" * 40)
        with mock.patch.object(mf, "git_show", return_value=None) as show:
            self.assertIsNone(mf.prior_log("base"))
        show.assert_called_once_with("base", "verification/measurement/revisions.json")
        with mock.patch.object(mf, "git_show", return_value=(mf.RECORDS / "revisions.json").read_bytes()):
            self.assertEqual(mf.prior_log("base"), LOG)
        with mock.patch.object(mf, "git_show", return_value=json.dumps({"frame": [], "policy": []}).encode()), \
                self.assertRaisesRegex(gate.Refusal, "does not list every kind"):
            mf.prior_log("base")

    def test_the_base_log_is_read_by_blob_from_a_real_commit(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()

            def git(*args):
                subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)

            git("init", "-q")
            (root / mf.RECORDS_PATH).mkdir(parents=True)
            (root / mf.RECORDS_PATH / "revisions.json").write_bytes((mf.RECORDS / "revisions.json").read_bytes())
            (root / "big").write_bytes(b"x" * 64)
            git("add", "-A")
            git("-c", "user.name=t", "-c", "user.email=t@t", "commit", "-qm", "base", "--no-verify")
            with mock.patch.object(mf, "ROOT", root):
                self.assertEqual(mf.prior_log("HEAD"), LOG)
                self.assertIsNone(mf.git_show("HEAD", "absent.json"))
                with mock.patch.object(gate, "READ_LIMIT", 10), \
                        self.assertRaisesRegex(gate.Refusal, "big at HEAD exceeds 10 bytes"):
                    mf.git_show("HEAD", "big")
                with self.assertRaisesRegex(gate.Refusal, "is no readable blob"):
                    mf.git_show("HEAD", mf.RECORDS_PATH)
                with self.assertRaisesRegex(gate.Refusal, "names no commit"):
                    mf.git_show("", "big")

    def test_each_malformed_record_is_refused_by_its_own_rule(self):
        def field(name, **values):
            return lambda f: f["fields"][name].update(values)

        def source(name, kind, value):
            return lambda f: f["fields"][name]["sources"].__setitem__(kind, value)

        def producer(path, symbol):
            return source("held_capacity", "hardware", {"kind": "producer", "path": path, "symbol": symbol})

        def handoff(labels):
            return source("capture_duration", "hardware", {"kind": "handoff", "owner": "completion-plan U5",
                                                            "labels": labels, "draft": "d"})

        def drop(member):
            def edit(p):
                p["family"].remove(member)
                p["outcomes"].pop(member)
                for rows in p["budgets"].values():
                    rows.pop(member)
            return edit

        frame_edits = {
            "simulation evidence for a latency": (field("hit_latency", evidence=["hardware", "simulation"], sources={
                "hardware": RECORDS["frame"][0]["fields"]["hit_latency"]["sources"]["hardware"],
                "simulation": {"kind": "campaign", "computation": "ticks"}}), "is a timing in us"),
            "simulation evidence for a rate": (field("goodput", evidence=["hardware", "simulation"], sources={
                "hardware": RECORDS["frame"][0]["fields"]["goodput"]["sources"]["hardware"],
                "simulation": {"kind": "campaign", "computation": "ticks"}}), "is a timing in bytes/s"),
            "a unit outside the closed table": (field("rto", unit="ns"), "unit 'ns' is not one of"),
            "a source per kind missing": (field("certified_cut", evidence=["hardware", "simulation", "store"]),
                                          "does not name one source per evidence kind"),
            "an unresolved producer symbol": (producer("crates/kestrike/src/storage/volume/report.rs",
                                                       "pub no_such_field"), "declares no 'pub no_such_field'"),
            "a producer symbol matched only as a prefix": (producer("scripts/hit-gate.py", "def judge_ru"),
                                                           "declares no 'def judge_ru'"),
            "a producer symbol only in comments and calls": (producer("scripts/hit-gate.py", "judge_profile"),
                                                             "is no declaration or enum variant"),
            **{f"the keyword {keyword} alone as a public field": (
                producer("crates/kestrike/src/storage/volume/report.rs", keyword),
                "is no declaration or enum variant") for keyword in ("pub struct", "pub(crate) fn", "pub enum")},
            "a campaign anchor on a call": (source("rto", "hardware", {"kind": "campaign", "computation": "c",
                                                                       "path": "scripts/hit-gate.py",
                                                                       "symbol": "print"}),
                                            "'print' is no declaration or enum variant"),
            "a campaign anchor on a docstring word": (source("rto", "hardware", {
                "kind": "campaign", "computation": "c", "path": "scripts/hit-gate.py", "symbol": "campaign"}),
                "'campaign' is no declaration or enum variant"),
            "a producer in a tests directory": (producer("crates/kestrike/tests/bind_cli.rs", "fn scratch"),
                                                "is test code"),
            "a producer in a _tests directory": (producer("crates/kestrike/src/net/world_tests/boundary.rs",
                                                          "fn profile"), "is test code"),
            "a producer in a test script": (producer("scripts/test-hit-gate.py", "def filled"), "is test code"),
            "a producer under its own cfg(test) attribute": (producer(
                "crates/kestrike/src/storage/volume/report.rs", "pub(crate) fn refuse_recovery_io"),
                "outside docstrings and test items"),
            "a producer in a test file": (producer("crates/kestrike/src/storage/volume/warm_sim_tests.rs",
                                                   "pub struct TenureA"), "is test code"),
            "a producer in a tests.rs module file": (producer("crates/kestrike/src/failover/report/tests.rs",
                                                              "fn abandoned"), "is test code"),
            "a producer spelled with a trailing dot": (producer(
                "crates/kestrike/src/storage/volume/warm_sim_tests.rs/.", "pub struct TenureA"), "is test code"),
            "a producer inside an inline test module": (producer("crates/kestrike/src/failover/records.rs",
                                                                 "const NAMESPACE"), "outside docstrings and test items"),
            "a handoff label carrying volume identity": (handoff({"volume_id": ["vol-a"]}), "closed label table"),
            "a capitalized identity label": (handoff({"Volume": ["v"]}), "closed label table"),
            "a hyphenated identity label": (handoff({"request-id": ["r"]}), "closed label table"),
            "an identity value under a closed label": (handoff({"state": ["vol-a"]}), "closed label table"),
            "a handoff to another owner": (source("capture_duration", "hardware", {
                "kind": "handoff", "owner": "#1", "labels": {"state": ["published"]}, "draft": "d"}),
                "hands off to another owner"),
            "a ticket without a number": (source("fill_latency", "hardware", {
                "kind": "ticket", "owner": "the fill team", "draft": "d"}), "an owner that is not a #number"),
            "a ticket without draft text": (source("fill_latency", "hardware", {"kind": "ticket", "owner": "#139"}),
                                            "a ticket source names no owner or no draft text"),
            "a campaign source without its computation": (source("rto", "hardware", {"kind": "campaign"}),
                                                          "names no computation"),
            "a retired BIND axis": (lambda f: f["fields"].__setitem__("bind_queue_full", f["fields"]["rto"]),
                                    "retired axes"),
            "a retired term inside a name": (lambda f: f["fields"].__setitem__("queue_bind_full", f["fields"]["rto"]),
                                             "retired axes"),
            "a retired currency-proof axis": (lambda f: f["fields"].__setitem__(
                "per_hit_currency_proof", f["fields"]["rto"]), "retired axes"),
            "a retired tau axis": (lambda f: f["fields"].__setitem__("tau", f["fields"]["rto"]), "retired axes"),
            "an emptied retired list beside a retired axis": (lambda f: (f["retired"].update(names=[], prefixes=[]),
                                                                         f["fields"].__setitem__("bind_x", f["fields"]["rto"])),
                                                              "the retired axes are not"),
            "a retired header key": (lambda f: f["header"].__setitem__("currency_proof", ["hardware"]),
                                     "the header is not"),
            "a missing warm field": (lambda f: f["fields"].pop("interruption_ancestry"),
                                     "fields lack \\['interruption_ancestry'\\]$"),
            "a missing preserved outcome": (lambda f: f["fields"].pop("rto"), "fields lack \\['rto'\\]$"),
            "a missing observed field": (lambda f: f["fields"].pop("request_attempts"), "changes content this script"),
            "a missing device field": (lambda f: (f["fields"].pop("device_read"), f["comparison"]["cells"].pop(
                "device_read")), "changes content this script"),
            "a relabeled timing unit beside simulation evidence": (field("rto", unit="requests", evidence=[
                "hardware", "simulation"], sources={"hardware": RECORDS["frame"][0]["fields"]["rto"]["sources"][
                    "hardware"], "simulation": {"kind": "campaign", "computation": "ticks"}}),
                "changes content this script"),
            "a flipped direction": (field("rto", direction="higher"), "changes content this script"),
            "another estimand": (field("rto", estimand="time to anything"), "changes content this script"),
            "an emptied population": (lambda f: f.update(population={"manifest": None}), "changes content this"),
            "a population that is no object": (lambda f: f.update(population=[]), "the population is no object"),
            "a discipline holding only its identity": (lambda f: f.update(discipline={
                "identity": f["discipline"]["identity"]}), "changes content this script"),
            "a null property row": (lambda f: f["properties"].update({"P-N-341": None}), "changes content this"),
            "a closed-loop tape": (lambda f: f["arrival"].update(tape="closed loop"), "changes content this"),
            "another class meaning": (lambda f: f["classes"]["warm-takeover"].update(meaning="a fresh host"),
                                      "changes content this script"),
            "another evidence definition": (lambda f: f["evidence"].update(model="anything"), "changes content"),
            "a samples reader on fill_latency": (field("fill_latency", samples="hit-gate"),
                                                 "names a samples reader other than"),
            "hit_latency without its samples reader": (lambda f: f["fields"]["hit_latency"].pop("samples"),
                                                       "names a samples reader other than"),
            "a true edge floor": (lambda f: f["floors"].update(edge=True), "the floors are not"),
            "a float floor example": (lambda f: f["floors"]["example"].update(requests=4000.0),
                                      "the floor example is not"),
            "mq-3 inside a name": (lambda f: f["fields"].__setitem__("mq_3_depth", f["fields"]["rto"]),
                                   "retired axes"),
            "an embedded c7": (lambda f: f["fields"].__setitem__("lag_c7", f["fields"]["rto"]), "retired axes"),
            "a CamelCase field name": (lambda f: f["fields"].__setitem__("HitRequiresCurrency", f["fields"]["rto"]),
                                       "is not lower snake case"),
            "a dotted field name": (lambda f: f["fields"].__setitem__("queue.bind_full", f["fields"]["rto"]),
                                    "is not lower snake case"),
            "a seconds field with simulation evidence": (field("rto", evidence=["hardware", "simulation"], sources={
                "hardware": RECORDS["frame"][0]["fields"]["rto"]["sources"]["hardware"],
                "simulation": {"kind": "campaign", "computation": "ticks"}}), "is a timing in s,"),
            "a stage with simulation evidence": (lambda f: f["stages"]["coverage"].update(
                evidence=["hardware", "simulation"], sources={**f["stages"]["coverage"]["sources"],
                                                             "simulation": {"kind": "campaign", "computation": "t"}}),
                "coverage is a timing in s"),
            "a manifest path that is no string": (lambda f: f["population"].update(manifest={"path": 5,
                                                                                            "sha256": "0" * 64}),
                                                  "names no file by a path string"),
            "a workload digest without a manifest": (lambda f: f["envelope"].update(workload_sha256="1" * 64),
                                                     "without a population manifest"),
            "a missing stage": (lambda f: f["stages"].pop("coverage"), "the stages are not"),
            "a missing control": (lambda f: f["controls"].pop("always-miss"), "the controls are not"),
            "another control outcome": (lambda f: f["controls"]["aa"].update(expected="pass"), "the controls are not"),
            "two cold classes": (lambda f: f["classes"]["warm-takeover"].update(cold=True), "the classes are not"),
            "another E_max": (lambda f: f["envelope"].update(e_max=1 << 27), "is not 2\\^28"),
            "a deleted envelope key": (lambda f: f["envelope"].pop("n_max"), "the envelope keys are not"),
            "an off-type envelope value": (lambda f: f["envelope"].update(iops="fast"), "envelope values \\['iops'\\]"),
            "a deleted header key": (lambda f: f["header"].pop("n_max"), "the header is not"),
            "c_page in a cell header kind": (lambda f: f["header"].__setitem__("c_page", ["hardware"]),
                                             "the header is not"),
            "another quantile floor": (lambda f: f["floors"].update(quantile=5), "the floors are not"),
            "p999 relabeled at 99/100 with its example": (lambda f: (f["floors"]["quantiles"].update(p999="99/100"),
                                                                     f["floors"]["example"]["kinds"].update(
                                                                         p999="quantile")), "the quantiles are not"),
            "a floor example reporting p99.9 of 4,000 requests": (lambda f: f["floors"]["example"]["kinds"].update(
                p999="quantile"), "the floor example is not"),
            "a floor example of another request count": (lambda f: f["floors"]["example"].update(requests=400_000),
                                                         "the floor example is not"),
            "another hit-gate qualification": (lambda f: f["hit_gate"].update(qualification_sha256="0" * 64),
                                               "pins another hit gate"),
            "another hit-gate judge": (lambda f: f["hit_gate"].update(judge="scripts/other.py"),
                                       "pins another hit gate"),
            "a run identity without the patch digest": (lambda f: f["discipline"].update(
                identity=["campaign", "commit", "cpu_family"]), "the run identity is not"),
            "a parent without its body digest": (lambda f: f["parent"]["ticket"].pop("body_sha256"),
                                                 "the parent does not pin"),
            "a version of true": (lambda f: f.update(version=True), "frame revisions are not versions 1 to n"),
            "a changed censoring rule": (lambda f: f["arrival"].update(censoring="none"), "the arrival section"),
            "other retained-hit levels": (field("retained_hit_recovery", levels=[50, 90]), "levels are not"),
        }
        policy_edits = {
            "a cold retained-hit budget": (lambda p: p["budgets"]["volume-loss-control"].update(
                retained_hit_recovery=1), "the cold class holds a retained-hit recovery budget"),
            "a cold held-capacity budget": (lambda p: p["budgets"]["volume-loss-control"].update(
                held_capacity=1), "the cold class holds a held-capacity budget"),
            "a cold class with retained hits": (lambda p: p["cold_retained_hits"].update({"volume-loss-control": 1}),
                                                "the cold class's retained hits are not"),
            "a cold class with null retained hits": (lambda p: p["cold_retained_hits"].update(
                {"volume-loss-control": None}), "the cold class's retained hits are not"),
            "an H p99 over 3 ms": (lambda p: p["h"]["nominal"].update(p99_ms=4.0), "H is not R6's"),
            "a large-object row without its p90": (lambda p: p["h"]["large_object"].pop("p90_ms"), "H is not R6's"),
            "a large-object p99 over 5 ms": (lambda p: p["h"]["large_object"].update(p99_ms=8.0), "H is not R6's"),
            "other reported quantiles": (lambda p: p["h"].update(reported=["p50"]), "changes content this script"),
            "other H strata": (lambda p: p["h"].update(strata="none"), "changes content this script"),
            "an edge threshold off the ceilings": (lambda p: p["h"]["edge"].update(p999="p50_ms"),
                                                   "H's edge thresholds"),
            "p90 rated at the p99 ceiling": (lambda p: p["h"]["edge"].update(p90="p99_ms"), "H's edge thresholds"),
            "p99 rated at the p90 ceiling": (lambda p: p["h"]["edge"].update(p99="p90_ms"), "H's edge thresholds"),
            "p90 rated at no ceiling": (lambda p: p["h"]["edge"].update(p90=None), "H's edge thresholds"),
            "a false cold zero": (lambda p: p["cold_retained_hits"].update({"volume-loss-control": False}),
                                  "the cold class's retained hits are not"),
            "a true p90 ceiling": (lambda p: p["h"]["nominal"].update(p90_ms=True), "H is not R6's"),
            "an outcome row without a unit": (lambda p: p["outcomes"]["rto"].pop("unit"), "outcome rto is no row"),
            "an outcome unit off its field": (lambda p: p["outcomes"]["rto"].update(unit="us"),
                                              "outcome rto's unit 'us' is not its field's 's'"),
            "a string outcome effect": (lambda p: p["outcomes"]["rto"].update(smallest_effect="tbd"),
                                        "outcome rto is no row"),
            "a string request-tail threshold": (lambda p: p["request_tail_edge_ms"].update(p999="tbd"),
                                                "request tail's edge thresholds"),
            "an H normalization": (lambda p: p["outcomes"]["hit_latency"].update(normalization="log"),
                                   "H's row holds a normalization"),
            "both H boundaries moved together": (lambda p: (p["h"].update(boundary="to admission"),
                                                            p["outcomes"]["hit_latency"].update(boundary="to admission")),
                                                 "changes content this script"),
            "both F boundaries moved together": (lambda p: (p["f"].update(boundary="to the write"),
                                                            p["outcomes"]["fill_latency"].update(boundary="to the write")),
                                                 "changes content this script"),
            "a family without F": (drop("fill_latency"), "the family is not"),
            "a family without rto": (drop("rto"), "the family is not"),
            "an H boundary off its outcome row": (lambda p: p["h"].update(boundary="to the first byte"),
                                                  "H's boundary differs"),
            "an F boundary off its outcome row": (lambda p: p["f"].update(boundary="to the device write"),
                                                  "F's boundary differs"),
            "an H budget row": (lambda p: p["budgets"]["warm-takeover"].update(hit_latency=3), "H's and F's budget"),
            "a negative budget": (lambda p: p["budgets"]["warm-takeover"].update(rto=-1),
                                  "budget rows \\['warm-takeover.rto'\\] are neither positive nor null"),
            "a placeholder class list": (lambda p: p.update(class_list="tbd"), "the class list is not"),
            "an F percentile over one": (lambda p: p["f"].update(percentile=99), "F is no boundary"),
            "a string F budget": (lambda p: p["f"].update(budget_ms="tbd"), "F is no boundary"),
            "a negative readiness window": (lambda p: p["readiness"].update(fill_window_s=-1),
                                            "the readiness inputs"),
            "other counting tickets": (lambda p: p.update(counted_by=["#139"]), "counts for other tickets"),
        }
        statistics_edits = {
            "a provisional alpha other than 0.05": (lambda s: s["familywise_alpha"].update(value=0.1),
                                                    "provisional familywise_alpha is not 0.05"),
            "an extended horizon": (lambda s: s["horizon"].update(extension=True), "the horizon is not fixed"),
            "a budget bound this judge does not apply": (lambda s: s.update(budget_bound="t-interval"),
                                                         "applies no budget bound"),
            "another bound method": (lambda s: s["bounds"].update(method="Holm"), "the statistics bounds"),
            "another edge interval": (lambda s: s.update(edge_interval="Clopper-Pearson"),
                                      "the statistics edge_interval"),
            "another censoring rule": (lambda s: s.update(censoring="none"), "the statistics censoring"),
            "a null pilot rule": (lambda s: s.update(pilot=None), "are not all text"),
            "a placeholder sample size": (lambda s: s["sample_size"].update(value="tbd"), "no positive count"),
            "another hit-latency protocol": (lambda s: s.update(hit_latency="any"), "the statistics hit_latency"),
            "a one-block horizon": (lambda s: s["horizon"].update(blocks=1), "the horizon is not fixed"),
            "a horizon over a campaign's block limit": (lambda s: s["horizon"].update(blocks=mf.MAX_CELLS + 1),
                                                        "the horizon is not fixed"),
            "a negative plateau band": (lambda s: s.update(plateau_bands={"held_units": -1}), "plateau bands"),
            "a zero drift band": (lambda s: s.update(drift_band=0), "the drift band is not positive"),
            "a true alpha": (lambda s: s["familywise_alpha"].update(value=True), "is no fraction"),
            "an alpha whose per-tail level underflows": (lambda s: s["familywise_alpha"].update(
                value=5e-324, status="accepted"), "underflows to zero"),
            "another pilot rule": (lambda s: s.update(pilot="pilot runs count toward confirmation"),
                                   "change content this script fixes"),
        }
        cases = [*(({"frame": e}, n, m) for n, (e, m) in frame_edits.items()),
                 *(({"policy": e}, n, m) for n, (e, m) in policy_edits.items()),
                 *(({"statistics": e}, n, m) for n, (e, m) in statistics_edits.items())]
        for edits, name, message in cases:
            with self.subTest(name):
                records, log = build(**edits)
                with self.assertRaisesRegex(gate.Refusal, message):
                    mf.check(records, log, QUALIFICATION)

    def test_the_envelope_must_match_the_qualifications_recovery_counts(self):
        q = copy.deepcopy(QUALIFICATION)
        q["recovery"]["n_max"] = 1 << 25
        records, log = build(frame=lambda f: (f["envelope"].update(n_max=1 << 24),
                                              f["hit_gate"].update(qualification_sha256=mf.canonical(q))))
        with self.assertRaisesRegex(gate.Refusal, "n_max and e_max differ"):
            mf.check(records, log, q)

    def test_the_log_and_records_refuse_loose_types(self):
        integer_digest = {**LOG, "policy": [{"version": 1, "sha256": int(LOG["policy"][0]["sha256"], 16)}]}
        with self.assertRaisesRegex(gate.Refusal, "policy revisions are not versions 1 to n"):
            mf.check(RECORDS, integer_digest, QUALIFICATION)
        true_version = {**LOG, "frame": [{"version": True, "sha256": LOG["frame"][0]["sha256"]}]}
        with self.assertRaisesRegex(gate.Refusal, "frame revisions are not versions 1 to n"):
            mf.check(RECORDS, true_version, QUALIFICATION)
        for kind in mf.KINDS:
            with self.subTest(kind):
                records = {**RECORDS, kind: ({**RECORDS[kind][0], "version": True}, RECORDS[kind][1])}
                with self.assertRaisesRegex(gate.Refusal, f"{kind} version True with SHA-256"):
                    mf.check(records, LOG, QUALIFICATION)

    def test_a_policy_pin_off_either_record_is_refused(self):
        for kind in ("frame", "statistics"):
            with self.subTest(kind):
                records, _ = build(policy=lambda p, k=kind: p[k].update(sha256="0" * 64), relog=False)
                log = {**LOG, "policy": [*LOG["policy"][:-1], mf.pin(records, "policy")]}
                with self.assertRaisesRegex(gate.Refusal, f"names another {kind} version"):
                    mf.check(records, log, QUALIFICATION)

    def test_source_anchors_outside_the_repository_loops_fifos_and_docstrings_are_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root, outside = Path(tmp).resolve() / "repo", Path(tmp).resolve() / "outside.rs"
            root.mkdir()
            outside.write_text("pub x: u64,\n")
            (Path(tmp).resolve() / "repo.rs").write_text("pub fn beside_the_repository() {}\n")
            (root / "loop").symlink_to(root / "loop")
            os.mkfifo(root / "pipe.rs")
            (root / "doc.py").write_text('"""A module.\n\ndef ghost(x)\n"""\n\ndef real():\n    pass\n')
            (root / "single.py").write_text("'''A module.\n\ndef ghost(x)\n'''\n\ndef real():\n    pass\n")
            (root / "mixed.py").write_text("r'''A module, \"\"\"quoted.\n\ndef ghost(x)\n'''\n\ndef real():\n    pass\n")
            (root / "escaped.py").write_text('"""An escaped \\""" quote.\n\ndef ghost(x)\n"""\n\ndef real():\n    pass\n')
            (root / "comment.py").write_text('# A """ in a comment.\nNOTE = "\'\'\'"\n\ndef real():\n    pass\n')
            (root / "broken.py").write_text('"""An unterminated string.\n\ndef ghost(x)\n')
            (root / "dead.py").write_text("if False:\n    def ghost():\n        pass\n\n\ndef outer():\n"
                                          "    def inner():\n        pass\n\n\nclass Judge:\n"
                                          "    def decide(self):\n        pass\n\n\nasync def real():\n    pass\n")
            (root / "scoped.rs").write_text("pub(super) fn moved() {}\npub(in crate::storage) fn placed() {}\n")
            (root / "Cargo.toml").write_text("")
            with mock.patch.object(mf, "ROOT", root):
                problems = {name: mf.source_problem({"kind": "producer", "path": path, "symbol": "pub x"})
                            for name, path in (("outside", "../outside.rs"), ("loop", "loop/a.rs"),
                                               ("fifo", "pipe.rs"))}
                docstring = mf.source_problem({"kind": "producer", "path": "doc.py", "symbol": "def ghost"})
                real = mf.source_problem({"kind": "producer", "path": "doc.py", "symbol": "def real"})
                single = [mf.source_problem({"kind": "producer", "path": path, "symbol": symbol})
                          for path in ("single.py", "mixed.py", "escaped.py") for symbol in ("def ghost", "def real")]
                comment = mf.source_problem({"kind": "producer", "path": "comment.py", "symbol": "def real"})
                broken = mf.source_problem({"kind": "producer", "path": "broken.py", "symbol": "def ghost"})
                dead = [mf.source_problem({"kind": "producer", "path": "dead.py", "symbol": symbol})
                        for symbol in ("def ghost", "def inner", "def outer", "class Judge", "def decide", "def real")]
                scoped = [mf.source_problem({"kind": "producer", "path": "scoped.rs", "symbol": symbol})
                          for symbol in ("pub(crate) fn moved", "pub(crate) fn placed", "pub fn placed")]
                private = mf.source_problem({"kind": "producer", "path": "scoped.rs", "symbol": "fn moved"})
        self.assertIn("declares no 'def ghost'", docstring)
        self.assertIsNone(real)
        for ghost, found in (single[:2], single[2:4], single[4:]):
            self.assertIn("declares no 'def ghost'", str(ghost))
            self.assertIsNone(found)
        self.assertIsNone(comment)
        self.assertIn("source broken.py does not parse as Python", str(broken))
        self.assertIn("declares no 'def ghost'", str(dead[0]))
        self.assertIn("declares no 'def inner'", str(dead[1]))
        self.assertEqual(dead[2:], [None, None, None, None])
        self.assertEqual(scoped, [None, None, None])
        self.assertIn("declares no 'fn moved'", private)
        self.assertIn("is outside the repository", problems["outside"])
        self.assertIn("does not resolve", problems["loop"])
        self.assertIn("is not a regular file", problems["fifo"])

    def test_a_producer_inside_a_cfg_test_item_is_refused_and_the_item_after_it_resolves(self):
        source = """\
#[cfg(test)]
impl Report {
    pub fn only_in_tests(&self) {}
}

#[cfg(all(test, feature = "sim"))]
#[allow(dead_code)]
fn helper(
    a: u8,
) -> u8 {
    fn nested() {}
    a
}

pub struct Kept {
    #[cfg(test)]
    pub scratch: u64,
    pub held: u64,
}

#[cfg(test)]
const TABLE: &[u8] = &[
    1,
];

pub fn after() {}

#[cfg(test)]
use std::fmt;

#[cfg(all(unix, test))]
fn second_conjunct() {}

#[cfg(all(feature = "sim", not(loom), test))]
fn last_conjunct() {}

#[cfg(not(test))]
fn production_only() {}

#[cfg(any(test, kani))]
fn either() {}

pub fn real() {}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "item.rs").write_text(source)
            (root / "Cargo.toml").write_text("")
            with mock.patch.object(mf, "ROOT", root):
                found = {symbol: mf.source_problem({"kind": "producer", "path": "item.rs", "symbol": symbol})
                         for symbol in ("pub fn only_in_tests", "fn nested", "pub scratch", "const TABLE",
                                        "fn second_conjunct", "fn last_conjunct", "fn production_only", "fn either",
                                        "pub held", "pub fn after", "pub fn real")}
        for symbol in ("pub fn only_in_tests", "fn nested", "pub scratch", "const TABLE", "fn second_conjunct",
                       "fn last_conjunct"):
            self.assertIn("outside docstrings and test items", str(found[symbol]), symbol)
        for symbol in ("fn production_only", "fn either", "pub held", "pub fn after", "pub fn real"):
            self.assertIsNone(found[symbol], symbol)

    def test_text_that_is_no_rust_declaration_is_refused_and_the_declaration_beside_it_resolves(self):
        source = """\
pub struct Report {
    pub kept: u64, /*
    pub commented: u64,
    */
}
pub const DOC: &str = "
pub fn in_string() {}
";
macro_rules! unused {
    () => {
        pub fn in_macro() {}
    };
}
#[cfg(all(
    test,
    target_os = "linux",
))]
mod tests {
    macro_rules! m {
        ($($x:tt)*) => { $($x)* }
}
    pub fn in_test_module() {}
}
#[test]
pub fn a_test() {}
#[cfg(any(test))]
pub fn any_test() {}
pub fn outer() {
    pub fn in_function_body() {}
}
pub enum Kind {
    Real = core::mem::size_of::<Box<dyn core::ops::Add<u8, Output = u8>>>() as isize,
}
pub struct Output;
pub fn real() {}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "item.rs").write_text(source)
            (root / "Cargo.toml").write_text("")
            (root / "broken.rs").write_text("pub fn real( {\n")
            with mock.patch.object(mf, "ROOT", root):
                found = {symbol: mf.source_problem({"kind": "producer", "path": "item.rs", "symbol": symbol})
                         for symbol in ("pub commented", "pub fn in_string", "pub fn in_macro",
                                        "pub fn in_test_module", "pub fn a_test", "pub fn any_test",
                                        "pub fn in_function_body", "Output", "Report",
                                        "pub kept", "pub const DOC", "pub fn outer", "Real", "pub struct Output",
                                        "pub fn real")}
                campaign = mf.source_problem({"kind": "campaign", "computation": "c", "path": "item.rs",
                                              "symbol": "pub fn in_test_module"})
                broken = mf.source_problem({"kind": "producer", "path": "broken.rs", "symbol": "pub fn real"})
        refused = ("pub commented", "pub fn in_string", "pub fn in_macro", "pub fn in_test_module", "pub fn a_test",
                   "pub fn any_test", "pub fn in_function_body", "Output", "Report")
        for symbol, problem in found.items():
            if symbol in refused:
                self.assertIn(f"item.rs declares no {symbol!r} outside docstrings and test items", str(problem))
            else:
                self.assertIsNone(problem, symbol)
        self.assertIsNone(campaign)
        self.assertIn("source broken.rs: source-anchors: the source does not parse as Rust", str(broken))

    def test_a_producer_in_a_module_its_parent_gates_is_refused(self):
        files = {
            "src/lib.rs": "#[cfg(test)]\nmod fixture;\npub mod live;\nmod deep;\nmod alt;\n"
                          "#[cfg(test)]\nmod gated_tree;\n#[cfg(test)]\nmod shared;\nmod broken;\n"
                          "#[cfg(test)]\nmod support;\npub mod client {\n    pub mod support {}\n}\n",
            "src/support.rs": "pub fn ghost() {}\n",
            "src/orphan.rs": "pub fn ghost() {}\n",
            "src/gone/stray.rs": "pub fn ghost() {}\n",
            "scratch/lib.rs": "pub fn ghost() {}\n",
            "scratch/main.rs": "pub fn ghost() {}\n",
            "src/bin/multi/main.rs": "mod part;\npub fn real() {}\n",
            "src/bin/multi/part.rs": "pub fn real() {}\n",
            "build.rs": "pub fn real() {}\n",
            "Cargo.toml": "",
            "src/deep/stray.rs": "pub fn ghost() {}\n",
            "src/bin/tool.rs": "pub fn real() {}\n",
            "src/main.rs": "#[cfg(test)]\nmod bin_only;\nmod shared;\n",
            "src/bin_only.rs": "pub fn ghost() {}\n",
            "src/shared.rs": "pub fn real() {}\n",
            "src/broken/mod.rs": "mod leaf;\npub fn broken( {\n",
            "src/broken/leaf.rs": "pub fn real() {}\n",
            "src/fixture.rs": "pub fn ghost() {}\n",
            "src/live.rs": "pub fn real() {}\n",
            "src/deep/mod.rs": "#[cfg(all(test, unix))]\nmod inner;\npub mod open;\n",
            "src/deep/inner.rs": "pub fn ghost() {}\n",
            "src/deep/open.rs": "pub fn real() {}\n",
            "src/alt.rs": "#[cfg(test)]\npub(crate) mod child;\n",
            "src/alt/child.rs": "pub fn ghost() {}\n",
            "src/gated_tree/mod.rs": "pub mod leaf;\n",
            "src/gated_tree/leaf.rs": "pub fn ghost() {}\n",
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            for name, content in files.items():
                (root / name).parent.mkdir(parents=True, exist_ok=True)
                (root / name).write_text(content)
            with mock.patch.object(mf, "ROOT", root):
                def problem(path, symbol, kind="producer"):
                    return mf.source_problem({"kind": kind, "path": path, "symbol": symbol,
                                              **({"computation": "c"} if kind == "campaign" else {})})

                gated = {path: problem(path, "pub fn ghost") for path in (
                    "src/fixture.rs", "src/deep/inner.rs", "src/alt/child.rs", "src/gated_tree/leaf.rs",
                    "src/bin_only.rs", "src/support.rs")}
                live = [problem("src/live.rs", "pub fn real"), problem("src/deep/open.rs", "pub fn real"),
                        problem("src/fixture.rs", "pub fn ghost", "campaign"), problem("src/shared.rs", "pub fn real")]
                broken = problem("src/broken/leaf.rs", "pub fn real")
                orphans = [problem("src/orphan.rs", "pub fn ghost"), problem("src/deep/stray.rs", "pub fn ghost"),
                           problem("src/gone/stray.rs", "pub fn ghost"),
                           problem("src/bin/tool.rs", "pub fn real"), problem("src/lib.rs", "pub mod live"),
                           problem("build.rs", "pub fn real"), problem("src/orphan.rs", "pub fn ghost", "campaign"),
                           problem("src/bin/multi/main.rs", "pub fn real"),
                           problem("src/bin/multi/part.rs", "pub fn real")]
                strays = [problem("scratch/lib.rs", "pub fn ghost"), problem("scratch/main.rs", "pub fn ghost")]
        for path, found in gated.items():
            self.assertEqual(found, f"producer {path} is test code")
        self.assertEqual(live, [None, None, None, None])
        self.assertIn("source src/broken/leaf.rs: its parent module src/broken/mod.rs: source-anchors: the source "
                      "does not parse as Rust", broken)
        self.assertEqual(orphans, [
            "source src/orphan.rs: no `mod orphan;` line in src/lib.rs or src/main.rs declares src/orphan.rs",
            "source src/deep/stray.rs: no `mod stray;` line in src/deep/mod.rs declares src/deep/stray.rs",
            "source src/gone/stray.rs: no file above src/gone/stray.rs declares it, and it is no crate root",
            None, None, None, None, None, None])
        self.assertEqual(strays, [
            "source scratch/lib.rs: no `mod lib;` line in scratch/main.rs declares scratch/lib.rs",
            "source scratch/main.rs: no `mod main;` line in scratch/lib.rs declares scratch/main.rs"])

    def test_a_source_that_is_neither_rust_nor_python_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            (root / "notes.md").write_text("class Producer\n")
            (root / "tool.sh").write_text("fn producer\n")
            with mock.patch.object(mf, "ROOT", root):
                found = {path: mf.source_problem({"kind": "producer", "path": path, "symbol": symbol})
                         for path, symbol in (("notes.md", "class Producer"), ("tool.sh", "fn producer"))}
        for path, problem in found.items():
            self.assertEqual(problem, f"source {path} is neither Rust nor Python, the sources this check reads")

    def test_a_rust_source_is_refused_when_the_lister_does_not_run(self):
        mf.rust_declarations.cache_clear()
        self.addCleanup(mf.rust_declarations.cache_clear)
        anchor = {"kind": "producer", "path": "crates/kestrike/src/storage/volume/report.rs",
                  "symbol": "pub held_units"}
        with mock.patch.object(subprocess, "run", side_effect=FileNotFoundError("cargo")):
            problem = mf.source_problem(anchor)
        self.assertIn("--package source-anchors` did not run", problem)
        self.assertIsNone(mf.source_problem(anchor))

    def test_an_over_limit_source_file_is_refused(self):
        with mock.patch.object(gate, "READ_LIMIT", 10):
            problem = mf.source_problem({"kind": "producer", "path": "crates/kestrike/src/failover/report.rs",
                                         "symbol": "pub abandoned"})
        self.assertIn("exceeds 10 bytes", problem)

    def test_a_population_manifest_resolves_to_the_envelopes_workload_digest(self):
        path = "verification/measurement/policy.json"
        data = (ROOT / path).read_bytes()
        sha = hashlib.sha256(data).hexdigest()
        for name, manifest, workload, message in (
                ("matching", {"path": path, "sha256": sha}, sha, None),
                ("off its digest", {"path": path, "sha256": "0" * 64}, "0" * 64, "does not resolve"),
                ("off the workload digest", {"path": path, "sha256": sha}, "1" * 64, "is not the envelope's")):
            with self.subTest(name):
                records, log = build(frame=lambda f, m=manifest, w=workload: (
                    f["population"].update(manifest=m), f["envelope"].update(workload_sha256=w)))
                if message is None:
                    found = mf.check(records, log, QUALIFICATION)
                    self.assertNotIn("the frame names no frozen population manifest", found)
                    self.assertNotIn("the envelope declares no workload_sha256", found)
                else:
                    with self.assertRaisesRegex(gate.Refusal, message):
                        mf.check(records, log, QUALIFICATION)

    def test_a_population_manifest_outside_the_repository_is_refused(self):
        with tempfile.NamedTemporaryFile() as outside:
            outside.write(b"population\n")
            outside.flush()
            sha = hashlib.sha256(b"population\n").hexdigest()
            for path in (outside.name, os.path.relpath(outside.name, ROOT)):
                with self.subTest(path):
                    records, log = build(frame=lambda f, p=path: (
                        f["population"].update(manifest={"path": p, "sha256": sha}),
                        f["envelope"].update(workload_sha256=sha)))
                    with self.assertRaisesRegex(gate.Refusal, "the population manifest .* is outside the repository"):
                        mf.check(records, log, QUALIFICATION)

    def test_each_workload_takes_its_own_ceilings_whatever_its_place_in_the_manifest(self):
        for first in (True, False):
            with self.subTest(tight_first=first):
                q = copy.deepcopy(QUALIFICATION)
                tight = {**q["workloads"]["request-weighted"], "p90_ms": 0.5, "p99_ms": 2.0}
                q["workloads"] = {"tight": tight, **q["workloads"]} if first else {**q["workloads"], "tight": tight}
                records, log = build(frame=lambda f, q=q: f["hit_gate"].update(qualification_sha256=mf.canonical(q)))
                mf.check(records, log, q)
                data = samples_file([2500] * 4000).replace(b'"workload": "request-weighted"', b'"workload": "tight"')
                summary, _ = mf.per_request(data, "tight", RECORDS["policy"][0], q, 2.0)[mf.H]
                self.assertEqual((summary["hits"]["p999"]["threshold_ms"], summary["hits"]["p999"]["exceedances"]),
                                 (2.0, 4000))


class Floors(unittest.TestCase):
    def test_a_4000_request_stratum_reports_p99_and_a_wilson_edge_rate_not_a_p999_quantile(self):
        values = sorted(range(500, 4500))
        summary = mf.summarize(values, 2.0, {"p999": 4000})
        self.assertEqual(summary["p99"], {"kind": "quantile", "value_us": values[3959]})
        p999 = summary["p999"]
        self.assertEqual(p999["kind"], "edge")
        self.assertNotIn("value_us", p999)
        self.assertEqual((p999["exceedances"], p999["rate"], p999["threshold_ms"]), (500, 500 / 4000, 4.0))
        self.assertLess(p999["low"], p999["rate"])
        self.assertGreater(p999["high"], p999["rate"])

    def test_expected_exceedances_decide_the_floor_kind_at_each_boundary(self):
        q = gate.QUANTILES["p999"]
        self.assertEqual([mf.floor_kind(n, q) for n in (999, 1000, 9999, 10_000)],
                         ["beyond the sample", "edge", "edge", "quantile"])
        self.assertEqual(mf.summarize([], 2.0)["p50"], {"kind": "beyond the sample"})

    def test_the_wilson_interval_and_bonferroni_level_are_the_declared_formulas(self):
        low, high = mf.wilson(4, 4000, 1.959963984540054)
        self.assertAlmostEqual(low, 0.000389, places=6)
        self.assertAlmostEqual(high, 0.002569, places=6)
        self.assertEqual(mf.wilson(0, 100, 2.0)[0], 0.0)
        m, tail, z = mf.level(RECORDS["statistics"][0], RECORDS["policy"][0])
        self.assertEqual((m, tail), (11, 0.05 / 22))
        self.assertAlmostEqual(z, 2.8376, places=4)

    def test_an_edge_without_a_declared_threshold_names_the_missing_input(self):
        summary = mf.summarize(list(range(4000)), 2.0, {"p99": 3000})
        self.assertEqual(summary["p999"], {"kind": "edge",
                                           "reason": "the policy declares no edge threshold for this quantile"})

    def test_a_value_at_the_ceiling_is_an_exceedance(self):
        p999 = mf.summarize([700] * 3999 + [3000], 2.0, {"p999": gate.microseconds(3.0)})["p999"]
        self.assertEqual((p999["exceedances"], p999["threshold_ms"]), (1, 3.0))

    def test_the_floors_command_prints_the_4000_request_example(self):
        out = io.StringIO()
        with redirect_stdout(out):
            self.assertEqual(mf.main(["floors", "--requests", "4000"]), 0)
        printed = json.loads(out.getvalue())
        self.assertEqual(printed["kinds"], {"p50": "quantile", "p90": "quantile", "p99": "quantile", "p999": "edge"})
        self.assertEqual((printed["m"], printed["per_tail"]), (11, 0.05 / 22))
        self.assertAlmostEqual(printed["z"], NormalDist().inv_cdf(1 - 0.05 / 22))

    def test_a_small_accepted_alpha_keeps_a_finite_z(self):
        records, log = build(statistics=lambda s: s["familywise_alpha"].update(value=1e-16, status="accepted"))
        mf.check(records, log, QUALIFICATION)
        _, tail, z = mf.level(records["statistics"][0], records["policy"][0])
        self.assertAlmostEqual(z, -NormalDist().inv_cdf(tail))
        self.assertGreater(z, 8)
        with tempfile.TemporaryDirectory() as tmp:
            for kind in mf.KINDS:
                (Path(tmp) / f"{kind}.json").write_bytes(held(records)[f"{mf.RECORDS_PATH}/{kind}.json"])
            (Path(tmp) / "revisions.json").write_text(json.dumps(log))
            out = io.StringIO()
            with redirect_stdout(out):
                self.assertEqual(mf.main(["floors", "--requests", "10", "--records", tmp]), 0)
        self.assertAlmostEqual(json.loads(out.getvalue())["z"], z)

    def test_a_negative_request_count_is_refused_as_itself(self):
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(mf.main(["floors", "--requests", "-1"]), 2)
        self.assertIn("refused: --requests is negative", err.getvalue())


def samples_file(latencies, stratum="hit", workload="request-weighted", source=0, extra=()):
    """A hit-gate samples file of `workload` whose header routes owner 0: one `stratum` sample from `source` per
    latency, then the `extra` [latency, stratum, source] samples."""
    spec = QUALIFICATION["workloads"][workload]
    rows = [(v, stratum, source) for v in latencies] + list(extra)
    header = {"workload": workload, "records": spec["records"], "weights": spec["weights"], "rate": 1000,
              "requests": len(rows), "seed": 7, "previous": "none", "slots": 4, "source": 0, "started_unix_ms": 1}
    lines = [json.dumps(header)] + [json.dumps([10 * i, 10 * i, 10 * i, 10 * i + v, i % 4, s, src])
                                    for i, (v, s, src) in enumerate(rows)]
    return ("\n".join(lines) + "\n").encode()


class Campaign:
    """A campaign under the given records with every structural input in place, written under a temporary
    directory."""

    def __init__(self, directory, records=RECORDS):
        self.dir, self.records = Path(directory), records
        envelope = records["frame"][0]["envelope"]
        header = {"rate": 1000, "locality": "zipf 1.1", "ticks_per_second": 1000, "b_pages": 1, "k_slots": 1,
                  "s_units_per_slot": 1, "n_max": 1, "e_max": envelope["e_max"], "device_model": "nvme",
                  "cpu_family": "Graviton", "objects_measured": 1, "always_miss_saturates": False,
                  "volume_size_bytes": 1, "iops": 1, "host_sharing": "dedicated", "platform_row": "x86_64-nitro-ebs",
                  "workload_sha256": "d" * 64, "c_page": 1}
        self.value = {
            **{kind: mf.pin(records, kind) for kind in mf.KINDS},
            "campaign": mf.campaign_id(records, COMMIT, PATCH),
            "revision": {"commit": COMMIT, "patch_sha256": PATCH},
            "header": header,
            "hosts": [self.host("ref", True), self.host("h1", False)],
            "controls": {name: {"observed": expected, "evidence": self.file(f"control-{name}", b"seen\n")}
                         for name, expected in mf.CONTROLS.items()},
            "cells": [],
        }

    def file(self, name, data):
        path = self.dir / name
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}

    def host(self, name, reference, outcome=b"reference outcomes\n", **extra):
        return {"id": name, "instance": f"i-{name}", "cpu_family": "Graviton", "physical_cores": 16, "jobs": 16,
                "clock": "trusted", "reference": reference, "outcome": self.file(f"outcome-{name}", outcome), **extra}

    def cell(self, field="hit_latency", evidence="hardware", host="h1", data=None, **extra):
        cell = {"class": "warm-takeover", "field": field, "stratum": "idle", "evidence": evidence, "host": host,
                "samples": self.file(f"cell-{len(self.value['cells'])}", data or samples_file([700] * 4000)), **extra}
        self.value["cells"].append(cell)
        return cell

    def report(self, log=LOG, document=DOCUMENT):
        return mf.report(self.records, log, self.value, "f" * 64, document=document, manifest_sha256=DIGEST, ids=IDS,
                         lane=LANE)


def supported():
    document = copy.deepcopy(DOCUMENT)
    document["platforms"]["x86_64-nitro-ebs"]["supported"] = True
    return document


UNBOUND = ["no hit-gate run binds a recovery class, so the cell's class is the campaign's statement",
           "the hit gate's run identity records no platform row or CPU identity, so the cell's are the campaign's "
           "statement"]


def bind(cell, host="i-h1", phase="idle", workload="request-weighted"):
    """A hit-gate result that binds `cell`'s samples to a decided candidate-arm run on client `host`."""
    run = {"run": "r", "workload": workload, "phase": phase, "client": host}
    return {"verdict": "pass", "reasons": []}, {cell["samples"]["sha256"]: run}


def only(receipt):
    (cell,) = receipt["cells"].values()
    return cell


class Report(unittest.TestCase):
    def setUp(self):
        patch = holding(RECORDS)
        patch.start()
        self.addCleanup(patch.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.campaign = Campaign(self.tmp.name)

    def tearDown(self):
        self.tmp.cleanup()

    def test_a_campaign_naming_no_policy_is_exploratory(self):
        for kind in mf.KINDS:
            self.campaign.value.pop(kind)
        receipt = self.campaign.report()
        self.assertEqual(receipt["verdict"], "exploratory")
        self.assertEqual([receipt[kind] for kind in mf.KINDS], [None, None, None])
        self.assertNotIn("cells", receipt)

    def test_every_receipt_names_the_manifest_it_was_read_under(self):
        current = self.campaign.report()
        for kind in mf.KINDS:
            self.campaign.value.pop(kind)
        exploratory = self.campaign.report()
        self.assertEqual((current["verdict"], exploratory["verdict"]), ("inconclusive", "exploratory"))
        self.assertEqual([receipt["manifest_sha256"] for receipt in (current, exploratory)], [DIGEST, DIGEST])

    def test_a_later_policy_never_rejudges_a_campaign_registered_under_an_earlier_one(self):
        def revise(p):
            p["version"] = NEXT["policy"]
            p["readiness"]["fill_window_s"] = 30

        earlier = mf.pin(RECORDS, "policy")
        records, log = build(policy=revise)
        campaign = Campaign(self.tmp.name, records)
        campaign.value["policy"] = earlier
        named = mf.campaign_id(RECORDS, COMMIT, PATCH)
        for stated in (campaign.value["campaign"], None, "measure-0000000000000000"):
            with self.subTest(stated=stated):
                campaign.value.pop("campaign", None)
                if stated:
                    campaign.value["campaign"] = stated
                receipt = campaign.report(log)
                self.assertEqual(receipt["verdict"], "inconclusive")
                self.assertEqual(receipt["reasons"], [
                    f"the campaign id is not {named}, the one its records and revision derive"])
        campaign.value["campaign"] = named
        receipt = campaign.report(log)
        self.assertEqual(receipt["verdict"], "retained")
        self.assertEqual(receipt["manifest_sha256"], DIGEST)
        self.assertFalse({"hosts", "hit_gate", "cells", "outcomes"} & set(receipt))
        (reason,) = receipt["reasons"]
        self.assertIn(f"registered under policy version {CURRENT['policy']}", reason)
        self.assertIn(f"policy version {NEXT['policy']} does not re-judge it", reason)
        self.assertIn("this receipt establishes no verdict for it", reason)
        for claim in ("counted", "stands"):
            self.assertNotIn(claim, reason)
        self.assertEqual(receipt["policy"], earlier)
        self.assertEqual(receipt["records"]["policy"], mf.pin(records, "policy"))
        self.assertEqual((receipt["frame"], receipt["statistics"]), (campaign.value["frame"], campaign.value["statistics"]))
        with mock.patch.object(mf, "git_show", return_value=None):
            receipt = campaign.report(log)
        self.assertEqual(receipt["verdict"], "inconclusive")
        self.assertIn(f"commit {COMMIT} does not hold policy version {CURRENT['policy']}, so nothing shows it preceded "
                      "the runs",
                      receipt["reasons"])

    def test_a_retained_campaign_keeps_the_frame_and_statistics_it_names(self):
        def revise(kind):
            def edit(d):
                d["version"] = NEXT[kind]
                if kind == "statistics":
                    d["horizon"]["blocks"] = 8
                else:
                    d["readiness"]["fill_window_s"] = 30
            return edit

        records, log = build(statistics=revise("statistics"), policy=revise("policy"))
        log = {kind: [*LOG[kind], mf.pin(records, kind)] if kind != "frame" else LOG[kind] for kind in mf.KINDS}
        campaign = Campaign(self.tmp.name, records)
        campaign.value.update({kind: mf.pin(RECORDS, kind) for kind in mf.KINDS})
        campaign.value["campaign"] = mf.campaign_id(RECORDS, COMMIT, PATCH)
        receipt = campaign.report(log)
        self.assertEqual(receipt["verdict"], "retained")
        self.assertEqual([receipt[kind] for kind in mf.KINDS], [mf.pin(RECORDS, kind) for kind in mf.KINDS])
        self.assertNotEqual(receipt["statistics"], receipt["records"]["statistics"])
        mixed = {**RECORDS, "statistics": records["statistics"]}
        campaign.value["statistics"] = mf.pin(records, "statistics")
        campaign.value["campaign"] = mf.campaign_id(mixed, COMMIT, PATCH)
        with holding(mixed), self.assertRaisesRegex(
                gate.Refusal, "the campaign names another frame or statistics version than its policy"):
            campaign.report(log)

    def test_an_unlogged_policy_is_refused(self):
        self.campaign.value["policy"] = {"version": 1, "sha256": "0" * 64}
        with self.assertRaisesRegex(gate.Refusal, "the revision log does not hold"):
            self.campaign.report()

    def test_a_malformed_campaign_is_refused_whatever_policy_it_names(self):
        host = self.campaign.host("h9", False)
        sample = {"path": "s", "sha256": "0" * 64}
        malformed = {
            "campaign": {"campaign": 5}, "revision": {"revision": "abc"}, "cells": {"cells": "x"},
            "header": {"header": []}, "controls": {"controls": []},
            "hosts": {"hosts": [self.campaign.host("a", True), self.campaign.host("a", False)]},
            "policy": {"policy": {"version": True, "sha256": RECORDS["policy"][1]}},
            "hit_gate": {"hit_gate": {"path": 5, "sha256": "0" * 64}},
            **{f"hosts {key}": {"hosts": [{**host, key: value}]} for key, value in (
                ("clock", 7), ("reference", 1), ("instance", None), ("cpu_family", ""))},
            "cells samples": {"cells": [{"class": "c", "field": "f", "stratum": "s", "evidence": "hardware", "host": "h",
                                         "samples": {**sample, "sha256": ["x"]}}]},
            "cells header": {"cells": [{"class": "c", "field": "f", "stratum": "s", "evidence": "simulation",
                                        "host": "h", "samples": sample, "header": {"iops": 1}}]},
            "controls member": {"controls": {"aa": {"observed": 1, "evidence": sample}}},
        }
        earlier = mf.pin(RECORDS, "policy")
        records, log = build(policy=lambda p: (p.update(version=NEXT["policy"]),
                                               p["readiness"].update(fill_window_s=30)))
        for name, edit in malformed.items():
            for policy in (None, earlier, mf.pin(records, "policy")):
                with self.subTest(name, policy=policy and policy["version"]):
                    value = {**{k: v for k, v in self.campaign.value.items() if k != "policy"}, "policy": policy}
                    value.update(edit)
                    key = name.split()[0]
                    with self.assertRaisesRegex(gate.Refusal, f"the campaign's \\['{key}'\\] are off their types"):
                        mf.report(records, log, value, "f" * 64, **CONTEXT)

    def test_host_and_cell_lists_past_their_bounds_are_refused_before_any_evidence_is_read(self):
        for key in ("hosts", "cells"):
            with self.subTest(key), mock.patch.object(mf, "MAX_HOSTS", 2), mock.patch.object(mf, "MAX_CELLS", 2):
                c = Campaign(self.tmp.name)
                if key == "hosts":
                    c.value["hosts"].append(c.host("h2", False))
                else:
                    for _ in range(3):
                        c.cell()
                with mock.patch.object(gate, "read_file", wraps=gate.read_file) as read, \
                        self.assertRaisesRegex(gate.Refusal, f"\\['{key}'\\] are off their types"):
                    c.report()
                self.assertFalse(any("outcome" in str(call.args[1]) or "samples" in str(call.args[1])
                                     for call in read.call_args_list))

    def test_the_current_policy_path_refuses_a_campaign_missing_its_structure(self):
        c = self.campaign
        for name, edit, message in (
                ("an unlogged frame pin", lambda v: v.update(frame=LOG["statistics"][0]),
                 "names frame .* which the revision log does not hold"),
                ("an unlogged statistics pin", lambda v: v.update(statistics=LOG["frame"][0]),
                 "names statistics .* which the revision log does not hold"),
                ("no frame pin", lambda v: v.update(frame=None), "names no frame, statistics or revision"),
                ("no revision", lambda v: v.pop("revision"), "names no frame, statistics or revision"),
                ("a header key missing", lambda v: v["header"].pop("rate"), "the campaign header keys are not"),
                ("a cell without a host", lambda v: v["cells"].append({"class": "x", "field": "y", "stratum": "z",
                                                                        "evidence": "hardware"}), "off their types"),
                ("a host without an instance", lambda v: v["hosts"][1].pop("instance"), "\\['hosts'\\] are off")):
            with self.subTest(name):
                value = copy.deepcopy(c.value)
                edit(value)
                with self.assertRaisesRegex(gate.Refusal, message):
                    mf.report(RECORDS, LOG, value, "f" * 64, **CONTEXT)

    def test_the_campaign_id_is_the_digest_of_the_records_commit_and_patch(self):
        joined = "/".join([RECORDS["frame"][1], RECORDS["statistics"][1], RECORDS["policy"][1], COMMIT, PATCH])
        self.assertEqual(mf.campaign_id(RECORDS, COMMIT, PATCH),
                         "measure-" + hashlib.sha256(joined.encode()).hexdigest()[:16])
        self.assertNotEqual(mf.campaign_id(RECORDS, COMMIT, "f" * 64), mf.campaign_id(RECORDS, COMMIT, PATCH))
        self.campaign.value["campaign"] = "measure-0000000000000000"
        receipt = self.campaign.report()
        self.assertIn(f"the campaign id is not {mf.campaign_id(RECORDS, COMMIT, PATCH)}, the one its records and "
                      "revision derive", receipt["reasons"])

    def test_the_commit_must_hold_the_records_the_campaign_names(self):
        with mock.patch.object(mf, "git_show", side_effect=GIT_SHOW):
            reasons = self.campaign.report()["reasons"]
        self.assertIn(f"revision '{COMMIT}' names no commit of this repository, so nothing shows the records "
                      "preceded the runs", reasons)
        held = {f"{mf.RECORDS_PATH}/{kind}.json": (mf.RECORDS / f"{kind}.json").read_bytes() for kind in mf.KINDS}
        with mock.patch.object(mf, "git_show", side_effect=lambda rev, path: held.get(path)):
            reasons = self.campaign.report()["reasons"]
        self.assertFalse(any("preceded the runs" in r for r in reasons))
        held[f"{mf.RECORDS_PATH}/policy.json"] = b"{}"
        with mock.patch.object(mf, "git_show", side_effect=lambda rev, path: held.get(path)):
            reasons = self.campaign.report()["reasons"]
        self.assertIn(f"commit {COMMIT} does not hold policy version {CURRENT['policy']}, so nothing shows it preceded "
                      "the runs", reasons)

    def test_header_values_off_their_type_or_the_envelope_name_their_key(self):
        header = self.campaign.value["header"]
        header.update(e_max=1 << 27, rate="fast", objects_measured=-1, always_miss_saturates="unknown")
        reasons = self.campaign.report()["reasons"]
        for key in ("rate", "objects_measured", "always_miss_saturates"):
            self.assertIn(f"header {key} {header[key]!r} is off its type", reasons)
        self.assertIn(f"header e_max is not the envelope's {1 << 28}", reasons)

    def test_a_null_header_key_makes_only_the_cells_it_applies_to_inconclusive(self):
        self.campaign.value["header"].update(ticks_per_second=None, iops=None)
        self.campaign.cell(field="origin_demand", evidence="simulation", data=b"x\n")
        self.campaign.cell(field="origin_demand", evidence="hardware", data=b"y\n")
        simulation, hardware = self.campaign.report()["cells"].values()
        self.assertIn("header ticks_per_second is undeclared for simulation evidence", simulation["reasons"])
        self.assertNotIn("header iops is undeclared for simulation evidence", simulation["reasons"])
        self.assertIn("header iops is undeclared for hardware evidence", hardware["reasons"])
        self.assertNotIn("ticks_per_second", hardware["header"])

    def test_hosts_count_only_through_their_cpu_familys_admitted_reference_and_core_bound(self):
        c = self.campaign
        c.value["hosts"] += [c.host("h2", False, outcome=b"other outcomes\n"), c.host("h3", False, jobs=17),
                             c.host("h4", False, jobs=0), c.host("h5", False, physical_cores=None),
                             c.host("x1", True, cpu_family="Xeon")]
        bad = c.host("h6", False)
        bad["outcome"]["sha256"] = "0" * 64
        c.value["hosts"].append(bad)
        for name in ("h1", "h2", "h3", "x1", "nobody"):
            c.cell(host=name, data=samples_file([700 + len(c.value["cells"])] * 10))
        with mock.patch.object(mf, "hit_gate", side_effect=lambda ref, hosts, **rest: (
                {"verdict": "pass", "reasons": []},
                {cell["samples"]["sha256"]: {"run": "r", "workload": "request-weighted", "phase": "idle",
                                             "client": hosts.get(cell["host"], {}).get("instance")}
                 for cell in c.value["cells"]})):
            receipt = c.report(document=supported())
        hosts = receipt["hosts"]
        self.assertEqual({name: h["admitted"] for name, h in hosts.items()},
                         {"ref": True, "h1": True, "h2": False, "h3": False, "h4": False, "h5": False, "x1": False,
                          "h6": False})
        self.assertIn("host h2's outcome digest differs from reference host ref's", hosts["h2"]["reasons"])
        self.assertIn("host h3 runs more jobs than its physical cores", hosts["h3"]["reasons"])
        self.assertIn("host h4 declares no positive jobs and physical_cores", hosts["h4"]["reasons"])
        self.assertIn("host h5 declares no positive jobs and physical_cores", hosts["h5"]["reasons"])
        self.assertIn("host x1's CPU family Xeon is not the header's Graviton", hosts["x1"]["reasons"])
        self.assertIn("is not the file its SHA-256 names", " ".join(hosts["h6"]["reasons"]))
        entries = list(receipt["cells"].values())
        cells = {cell["host"]: entries[i] for i, cell in enumerate(c.value["cells"])}
        self.assertNotIn("host h1 is not admitted", cells["h1"]["reasons"])
        for name in ("h2", "h3", "x1"):
            self.assertIn(f"host {name} is not admitted", cells[name]["reasons"])
        self.assertIn("the cell names an undeclared host 'nobody'", cells["nobody"]["reasons"])

    def test_a_family_with_two_references_or_an_inadmissible_reference_admits_no_host(self):
        c = self.campaign
        c.value["hosts"] = [c.host("ref", True, jobs=17), c.host("h1", False)]
        hosts = c.report()["hosts"]
        self.assertIn("reference host ref is not admitted on its own", hosts["h1"]["reasons"])
        c.value["hosts"] = [c.host("ref", True), c.host("h1", True)]
        hosts = c.report()["hosts"]
        self.assertIn("CPU family Graviton has 2 reference hosts, not one", hosts["h1"]["reasons"])

    def test_an_untrusted_clock_degrades_every_cell_of_its_host(self):
        c = self.campaign
        c.value["hosts"][1]["clock"] = "untrusted"
        c.cell()
        c.cell(field="certified_cut", data=b"cut\n")
        c.cell(field="goodput", data=b"bytes\n")
        cells = list(c.report()["cells"].values())
        self.assertEqual([cell["degraded"] for cell in cells], [True, True, True])
        self.assertIn("host h1's clock is untrusted, so its cells read degraded", cells[2]["reasons"])

    def test_no_control_counts_as_reached_without_a_judge_of_its_evidence(self):
        c = self.campaign
        c.value["controls"].pop("foreground-hog")
        c.value["controls"]["always-miss"]["observed"] = "retention-holds"
        c.value["controls"]["leaked-capacity"]["evidence"]["sha256"] = "0" * 64
        receipt = c.report()
        reasons = [r for r in receipt["reasons"] if "control" in r]
        self.assertEqual(reasons, [
            "control aa is unreached: the campaign declares no contrast",
            "control always-miss observed 'retention-holds', not its declared 'retention-fails'",
            f"control leaked-capacity evidence {c.value['controls']['leaked-capacity']['evidence']['path']!r} is not "
            "the file its SHA-256 names",
            "control foreground-hog is unrun",
            "control advertised-rate reports 'uncredited', but no judge on this revision derives its outcome from its "
            "evidence",
            "control calibration-drift is unreached: the campaign declares no contrast"])
        self.assertEqual(receipt["ranking"], {"withheld": reasons})

    def test_a_hardware_column_never_passes_from_simulation_evidence(self):
        self.campaign.cell(evidence="simulation")
        cell = only(self.campaign.report())
        self.assertEqual(cell, {"verdict": "inconclusive", "reasons": [
            "field hit_latency admits no simulation evidence; a column credits only its own kind"]})

    def test_a_cell_naming_no_frame_field_class_or_kind_is_inconclusive(self):
        for edit in ({"field": "bind_rate"}, {"class": "cold-host-loss"}, {"evidence": "survey"}):
            with self.subTest(**edit):
                self.campaign.value["cells"] = []
                self.campaign.cell(**edit)
                self.assertEqual(only(self.campaign.report())["reasons"],
                                 ["the cell names no frame field, class or evidence kind"])

    def test_a_field_without_a_samples_reader_never_passes_on_admitted_samples(self):
        for field in ("peak_ram", "s_membership", "authority", "fill_latency"):
            with self.subTest(field):
                self.campaign.value["cells"] = []
                cell = self.campaign.cell(field=field)
                with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
                    entry = only(self.campaign.report(document=supported()))
                self.assertEqual(entry["verdict"], "inconclusive")
                self.assertEqual(entry["reasons"], [f"no judge on this revision reads {field} evidence"])
                self.assertNotIn("summary", entry)

    def test_a_hardware_cell_without_a_reader_names_its_platform_row(self):
        self.campaign.cell(field="peak_ram", header={"platform_row": "nope"})
        self.campaign.cell(field="rto", data=b"y\n")
        self.campaign.cell(field="origin_demand", evidence="simulation", data=b"z\n")
        missing, unsupported, simulated = (entry["reasons"] for entry in self.campaign.report()["cells"].values())
        self.assertEqual(missing, ["platform row 'nope' is not in the manifest",
                                   "no judge on this revision reads peak_ram evidence"])
        self.assertEqual(unsupported, ["Inconclusive: platform row unsupported",
                                       "no judge on this revision reads rto evidence"])
        self.assertEqual(simulated, ["no judge on this revision reads origin_demand evidence"])

    def test_distinct_runs_evidence_kinds_and_separator_strings_keep_distinct_identities(self):
        c = self.campaign
        c.cell()
        c.cell(data=samples_file([900] * 4000))
        c.cell(field="origin_demand", evidence="hardware", data=b"a\n")
        c.cell(field="origin_demand", evidence="simulation", data=b"a\n")
        c.cell(stratum="idle/x")
        c.value["cells"][-1]["samples"] = c.value["cells"][0]["samples"]
        receipt = c.report()
        self.assertEqual(len(receipt["cells"]), 5)
        self.assertEqual(sorted(e.get("evidence") for e in receipt["cells"].values()),
                         ["hardware", "hardware", "hardware", "hardware", "simulation"])
        first = c.value["cells"][0]
        self.assertIn(json.dumps([mf.campaign_id(RECORDS, COMMIT, PATCH), COMMIT, PATCH, "Graviton", "warm-takeover",
                                  "hit_latency", "idle", "hardware", "h1", first["samples"]["sha256"], 1]),
                      receipt["cells"])
        c.cell(data=None)
        c.value["cells"][-1]["samples"] = first["samples"]
        receipt = c.report()
        self.assertEqual(len(receipt["cells"]), 5)
        self.assertTrue(any(r.endswith("repeats a run identity") for r in receipt["reasons"]))

    def test_a_bound_samples_cell_still_reads_inconclusive_for_its_unbound_class(self):
        cell = self.campaign.cell()
        reasons = only(self.campaign.report())["reasons"]
        self.assertIn("Inconclusive: platform row unsupported", reasons)
        self.assertIn("the hit gate admitted these samples for no non-null candidate-arm run of a decided cell",
                      reasons)
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            entry = only(self.campaign.report(document=supported()))
        self.assertEqual(entry["reasons"], UNBOUND)
        self.assertEqual(entry["verdict"], "inconclusive")
        self.assertEqual(entry["run"], {"id": "r", "workload": "request-weighted"})
        self.assertIn("summary", entry)

    def test_a_platform_row_outside_the_manifest_is_named_apart_from_an_unsupported_one(self):
        self.campaign.value["header"]["platform_row"] = "riscv-ebs"
        self.campaign.cell()
        reasons = only(self.campaign.report())["reasons"]
        self.assertIn("platform row 'riscv-ebs' is not in the manifest", reasons)
        self.assertNotIn("Inconclusive: platform row unsupported", reasons)

    def test_a_bound_cell_on_another_phase_or_client_names_the_mismatch(self):
        cell = self.campaign.cell()
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell, host="i-ref", phase="publish")):
            reasons = only(self.campaign.report(document=supported()))["reasons"]
        self.assertIn("the cell's stratum idle is not hit-gate run r's phase publish", reasons)
        self.assertIn("host h1 is not hit-gate run r's client instance i-ref", reasons)
        self.campaign.value["cells"][0]["host"] = "nobody"
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            entry = only(self.campaign.report(document=supported()))
        self.assertNotIn("summary", entry)
        self.assertIn("host nobody is not hit-gate run r's client instance i-h1", entry["reasons"])

    def test_a_cell_header_overrides_the_campaign_header_for_its_own_kind(self):
        a = self.campaign.cell(header={"rate": 2000})
        b = self.campaign.cell(data=samples_file([900] * 4000), header={"rate": "fast"})
        entries = list(self.campaign.report()["cells"].values())
        self.assertEqual([e["header"]["rate"] for e in entries], [2000, "fast"])
        self.assertIn("header rate 'fast' is off its type", entries[1]["reasons"])
        self.assertTrue(a and b)

    def test_a_cell_rate_off_the_offered_rate_is_named_on_the_cell(self):
        document, records, log = filled()
        campaign = Campaign(self.tmp.name, records)
        bound = campaign.cell(header={"rate": 2000})
        campaign.cell(field="origin_demand", evidence="simulation", data=b"x\n", header={"rate": 2000})
        campaign.cell(data=samples_file([900] * 4000), header={"rate": 1000})
        with holding(records), mock.patch.object(mf, "hit_gate", return_value=bind(bound)):
            receipt = campaign.report(log, document)
        off, simulated, on = receipt["cells"].values()
        reason = "header rate 2000 is not the qualification's offered rate 1000"
        self.assertEqual((off["header"]["rate"], simulated["header"]["rate"], on["header"]["rate"]), (2000, 2000, 1000))
        self.assertIn("summary", off)
        self.assertIn(reason, off["reasons"])
        self.assertIn(reason, simulated["reasons"])
        self.assertFalse(any("offered rate" in r for r in [*on["reasons"], *receipt["reasons"]]))

    def test_a_cell_cpu_family_off_its_host_and_a_cell_platform_row_are_judged_on_the_cell(self):
        bound = self.campaign.cell(header={"cpu_family": "Xeon", "platform_row": "nope"})
        self.campaign.cell(data=samples_file([900] * 4000))
        with mock.patch.object(mf, "hit_gate", return_value=bind(bound)):
            receipt = self.campaign.report(document=supported())
        off, on = receipt["cells"].values()
        named = ["header cpu_family Xeon is not host h1's Graviton", "platform row 'nope' is not in the manifest"]
        self.assertEqual((off["header"]["cpu_family"], off["header"]["platform_row"]), ("Xeon", "nope"))
        self.assertIn("summary", off)
        self.assertEqual(off["reasons"], [*named, *UNBOUND])
        self.assertFalse(set(named) & set(on["reasons"]))
        self.assertEqual({name: host["admitted"] for name, host in receipt["hosts"].items()}, {"ref": True, "h1": True})
        self.campaign.value["header"]["platform_row"] = "riscv-ebs"
        self.campaign.value["cells"] = []
        self.campaign.cell(header={"platform_row": "x86_64-nitro-ebs"})
        reasons = only(self.campaign.report())["reasons"]
        self.assertIn("Inconclusive: platform row unsupported", reasons)
        self.assertNotIn("platform row 'riscv-ebs' is not in the manifest", reasons)

    def test_a_patched_campaign_binds_no_hit_gate_samples_and_an_unpatched_one_binds_them(self):
        def report(patch, gate=True):
            campaign = Campaign(self.tmp.name)
            campaign.value["revision"]["patch_sha256"] = patch
            campaign.value["campaign"] = mf.campaign_id(RECORDS, COMMIT, patch)
            if gate:
                campaign.value["hit_gate"] = campaign.file("gate", b"{}\n")
            cell = campaign.cell()
            with mock.patch.object(mf, "hit_gate", return_value=bind(cell)), \
                    mock.patch.object(mf, "per_request", wraps=mf.per_request) as reader:
                return campaign.report(document=supported()), reader

        named = ("the hit gate's lane admits only an unmodified tree of the commit, so no gate run is a build of "
                 f"patch {'e' * 64}")
        receipt, reader = report("e" * 64)
        entry = only(receipt)
        self.assertEqual(receipt["hit_gate"]["verdict"], "inconclusive")
        self.assertTrue(any(r.startswith(named) for r in receipt["hit_gate"]["reasons"]), receipt["hit_gate"])
        self.assertFalse({"run", "summary"} & set(entry))
        reader.assert_not_called()
        self.assertIn("e" * 64, next(iter(receipt["cells"])))
        receipt, reader = report(mf.NO_PATCH)
        self.assertFalse(any("patch" in r for r in receipt["hit_gate"]["reasons"]))
        self.assertTrue({"run", "summary"} <= set(only(receipt)))
        reader.assert_called_once()
        self.assertEqual(mf.NO_PATCH, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        receipt, _ = report("e" * 64, gate=False)
        self.assertFalse(any("patch" in r for r in receipt["hit_gate"]["reasons"]))

    def test_a_rate_off_the_offered_rate_and_campaign_labels_are_named(self):
        document, records, log = filled()
        campaign = Campaign(self.tmp.name, records)
        campaign.value["header"]["rate"] = 2000
        with holding(records):
            receipt = campaign.report(log, document)
        self.assertIn("header rate 2000 is not the qualification's offered rate 1000", receipt["reasons"])

    def test_a_null_hardware_key_leaves_simulation_hosts_admitted_and_a_null_e_max_matches_any_envelope(self):
        c = self.campaign
        c.value["header"].update(cpu_family=None, e_max=None)
        c.cell(field="origin_demand", evidence="simulation", data=b"x\n")
        receipt = c.report()
        self.assertEqual({name: h["admitted"] for name, h in receipt["hosts"].items()}, {"ref": True, "h1": True})
        self.assertFalse(any("e_max" in r for r in receipt["reasons"]))
        self.assertIn("header e_max is undeclared for simulation evidence", only(receipt)["reasons"])

    def test_an_off_type_platform_row_reads_inconclusive(self):
        for row in (["x"], {"row": 1}):
            with self.subTest(row=row):
                self.campaign.value["header"]["platform_row"] = row
                self.campaign.value["cells"] = []
                self.campaign.cell()
                receipt = self.campaign.report()
                self.assertIn(f"header platform_row {row!r} is off its type", receipt["reasons"])
                self.assertIn(f"platform row {row!r} is not in the manifest", only(receipt)["reasons"])

    def test_the_4000_request_h_cell_reports_p99_a_wilson_edge_at_the_report_level_and_size_strata(self):
        latencies = [700] * 3990 + [3000] + [3500] * 9
        cell = self.campaign.cell(data=samples_file(latencies))
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            summary = only(self.campaign.report())["summary"]
        self.assertEqual(summary["strata"], {"hit": 4000, "miss": 0, "refused": 0, "error": 0})
        self.assertEqual(summary["hits"]["p99"], {"kind": "quantile", "value_us": 700})
        p999 = summary["hits"]["p999"]
        self.assertEqual((p999["kind"], p999["threshold_ms"], p999["exceedances"]), ("edge", 3.0, 10))
        self.assertAlmostEqual(p999["low"], 0.001048, places=6)
        self.assertAlmostEqual(p999["high"], 0.005951, places=6)
        self.assertEqual(set(summary["sizes"]), {"8192", "15743", "241011", "8076"})
        self.assertEqual(summary["sizes"]["8192"]["requests"], 1000)
        self.assertEqual(summary["sizes"]["8192"]["p99"]["kind"], "quantile")
        self.assertEqual(summary["sizes"]["8192"]["p999"]["kind"], "edge")

    def test_h_pools_only_the_routed_owner_and_counts_residual_owners_apart(self):
        data = samples_file([700] * 4000, extra=[(9000, "hit", 1)] * 6000 + [(9000, "miss", 1)])
        cell = self.campaign.cell(data=data)
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            summary = only(self.campaign.report())["summary"]
        self.assertEqual(summary["hits"]["requests"], 4000)
        self.assertEqual(summary["hits"]["p99"], {"kind": "quantile", "value_us": 700})
        self.assertEqual(summary["residual"], {"hit": 6000, "miss": 1, "refused": 0, "error": 0})

    def test_each_quantile_edge_is_rated_against_its_own_ceiling_of_the_workload(self):
        cell = self.campaign.cell(data=samples_file([1500] * 60, workload="large-object"))
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell, workload="large-object")):
            hits = only(self.campaign.report())["summary"]["hits"]
        self.assertEqual((hits["p90"]["kind"], hits["p90"]["threshold_ms"], hits["p90"]["exceedances"]),
                         ("edge", 1.0, 60))
        self.assertEqual(hits["p999"]["kind"], "beyond the sample")
        cell = self.campaign.cell(data=samples_file([4000] * 4000, workload="large-object"))
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell, workload="large-object")):
            hits = list(self.campaign.report()["cells"].values())[1]["summary"]["hits"]
        self.assertEqual((hits["p999"]["threshold_ms"], hits["p999"]["exceedances"]), (5.0, 0))

    def test_the_request_tail_reports_one_tail_per_outcome_and_leaves_errors_inconclusive(self):
        data = samples_file([500] * 3900, extra=[(800, "miss", 0)] * 99 + [(9, "error", 0)])
        cell = self.campaign.cell(field="request_tail", data=data)
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            entry = only(self.campaign.report())
        tails = entry["summary"]["tails"]
        self.assertEqual(tails["hit"]["p99"], {"kind": "quantile", "value_us": 500})
        self.assertEqual(tails["miss"]["requests"], 99)
        self.assertEqual(tails["miss"]["p50"], {"kind": "quantile", "value_us": 800})
        self.assertIn("the samples format records no timeout or deadline, so 1 error outcomes cannot be censored at "
                      "a deadline", entry["reasons"])

    def test_the_request_tail_counts_routed_and_residual_requests_beside_its_pooled_tails(self):
        data = samples_file([500] * 4000, extra=[(900, "hit", 1)] * 6000)
        cell = self.campaign.cell(field="request_tail", data=data)
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            summary = only(self.campaign.report())["summary"]
        self.assertEqual(summary["tails"]["hit"]["requests"], 10_000)
        self.assertEqual((summary["routed"]["hit"], summary["residual"]["hit"]), (4000, 6000))

    def test_the_request_tail_rates_its_edge_against_a_declared_threshold(self):
        policy = copy.deepcopy(RECORDS["policy"][0])
        data = samples_file([500] * 3995 + [5000] * 5)
        summary, _ = mf.per_request(data, "request-weighted", policy, QUALIFICATION, 2.0)[mf.TAIL]
        self.assertEqual(summary["tails"]["hit"]["p999"]["reason"], "the policy declares no edge threshold for this quantile")
        policy["request_tail_edge_ms"]["p999"] = 4.0
        summary, _ = mf.per_request(data, "request-weighted", policy, QUALIFICATION, 2.0)[mf.TAIL]
        self.assertEqual((summary["tails"]["hit"]["p999"]["threshold_ms"], summary["tails"]["hit"]["p999"]["exceedances"]),
                         (4.0, 5))

    def test_an_h_cell_holding_errors_names_them(self):
        data = samples_file([500] * 3990, extra=[(9, "error", 0)] * 10)
        h, reasons = mf.per_request(data, "request-weighted", RECORDS["policy"][0], QUALIFICATION, 2.0)[mf.H]
        self.assertEqual(h["strata"]["error"], 10)
        self.assertEqual(reasons, ["the samples format records no timeout or deadline, so 10 error outcomes cannot be "
                                   "censored at a deadline"])

    def test_one_bound_file_is_decoded_once_for_both_reader_fields(self):
        cell = self.campaign.cell()
        self.campaign.cell(field="request_tail", data=None)
        self.campaign.value["cells"][1]["samples"] = cell["samples"]
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)), \
                mock.patch.object(mf, "parse_samples", wraps=mf.parse_samples) as parse:
            entries = list(self.campaign.report()["cells"].values())
        self.assertEqual(parse.call_count, 1)
        self.assertEqual([sorted(e["summary"]) for e in entries], [["hits", "residual", "sizes", "strata"],
                                                                   ["residual", "routed", "strata", "tails"]])

    def test_a_malformed_or_oversized_samples_file_reads_inconclusive_without_a_summary(self):
        good = samples_file([700] * 10)
        head, _, body = good.partition(b"\n")
        header = json.loads(head)
        cases = {
            "not samples": (b"[1]\n", "Refusal: the samples header is not"),
            "changed weights": (json.dumps({**header, "weights": [9, 9, 9, 9]}).encode() + b"\n" + body,
                                "Refusal: the samples header is not"),
            "an admission before the send": (head + b"\n" + json.dumps([10, 5, 5, 20, 0, "hit", 0]).encode() + b"\n",
                                             "Refusal: a sample is not"),
            "a boolean source": (head + b"\n" + json.dumps([10, 10, 10, 20, 0, "hit", True]).encode() + b"\n",
                                 "Refusal: a sample is not"),
        }
        for name, (data, reason) in cases.items():
            with self.subTest(name):
                self.campaign.value["cells"] = []
                cell = self.campaign.cell(data=data)
                with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
                    entry = only(self.campaign.report())
                self.assertTrue(any(r.startswith(reason) for r in entry["reasons"]), entry["reasons"])
                self.assertNotIn("summary", entry)
        self.campaign.value["cells"] = []
        cell = self.campaign.cell(data=good)
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)), \
                mock.patch.object(gate, "MAX_REQUESTS", 5), mock.patch.object(gate, "parse", wraps=gate.parse) as parse:
            entry = only(self.campaign.report())
        self.assertTrue(any("another line count" in r for r in entry["reasons"]))
        self.assertFalse(any(call.args[1] in ("a sample", "the samples header") for call in parse.call_args_list))

    def test_raw_evidence_off_its_digest_makes_its_cell_inconclusive(self):
        cell = self.campaign.cell()
        Path(cell["samples"]["path"]).write_bytes(samples_file([701] * 4000))
        with mock.patch.object(mf, "hit_gate", return_value=bind(cell)):
            reasons = only(self.campaign.report())["reasons"]
        self.assertIn("is not the file its SHA-256 names", " ".join(reasons))

    def test_a_hit_gate_file_off_its_digest_names_it(self):
        c = self.campaign
        c.value["hit_gate"] = c.file("hit-gate.json", b"{}")
        Path(c.value["hit_gate"]["path"]).write_bytes(b"[]")
        h = c.report()["hit_gate"]
        self.assertEqual(h["verdict"], "inconclusive")
        self.assertIn("is not the file its SHA-256 names", h["reasons"][0])

    def test_null_budgets_read_unscored_and_h_reads_no_class_verdict(self):
        c = self.campaign
        c.value["hit_gate"] = c.file("hit-gate.json", json.dumps(
            {"campaign": "hit-gate-0", "main": "a" * 40, "candidate": COMMIT, "runs": []}).encode())
        receipt = c.report()
        self.assertEqual(receipt["hit_gate"]["verdict"], "handoff")
        self.assertIn("handoff", receipt["hit_gate"])
        self.assertEqual(set(receipt["hit_gate"]), {"verdict", "reasons", "receipt_sha256", "handoff", "gate"})
        self.assertEqual(receipt["hit_gate"]["gate"]["manifest_sha256"], DIGEST)
        self.assertEqual(receipt["hit_gate"]["gate"]["judge_sha256"],
                         hashlib.sha256((ROOT / "scripts/hit-gate.py").read_bytes()).hexdigest())
        self.assertIn("the campaign's header or controls are unestablished, so the hit gate's verdict decides nothing",
                      receipt["hit_gate"]["reasons"])
        self.assertNotIn("p999", json.dumps(receipt["hit_gate"]))
        outcomes = receipt["outcomes"]
        unscored = sum(v == "unscored" for rows in outcomes.values() for m, v in rows.items() if m != mf.F)
        self.assertIn(f"{unscored} budget rows hold no accepted budget and read unscored", receipt["open"])
        self.assertEqual({outcomes[cls]["hit_latency"] for cls in mf.CLASSES}, {"inconclusive"})
        self.assertEqual(outcomes["warm-takeover"]["fill_latency"], "unscored")
        self.assertEqual(outcomes["warm-takeover"]["rto"], "unscored")
        self.assertEqual(outcomes["volume-loss-control"]["retained_hit_recovery"], "inconclusive")
        self.assertEqual(receipt["verdict"], "handoff")

    def test_a_hit_gate_campaign_of_another_candidate_binds_nothing_and_decides_nothing(self):
        c = self.campaign
        c.value["hit_gate"] = c.file("hit-gate.json", json.dumps({"campaign": "hit-gate-0", "runs": []}).encode())
        for verdict in ("pass", "fail"):
            with self.subTest(verdict):
                judged = {"verdict": verdict, "candidate": "b" * 40, "seed": 1, "reasons": [], "open": [],
                          "cells": {CELL: {"verdict": verdict, "reasons": [],
                                           "runs": [{"id": "r", "samples_sha256": "a" * 64}], "identity": {}}}}
                with mock.patch.object(gate, "judge", return_value=judged):
                    h, bound = mf.hit_gate(c.value["hit_gate"], commit=COMMIT, hosts={}, document=DOCUMENT,
                                           manifest_sha256=DIGEST, ids=IDS, lane=LANE)
                self.assertEqual((h["verdict"], h["reasons"], bound),
                                 ("inconclusive", ["the hit gate judged another candidate than the commit"], {}))


class HitGateBinding(unittest.TestCase):
    """The bound-set derivation over a hit-gate receipt the real judge's shape gives, under a declared protocol."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.document, self.records, self.log = filled()
        self.campaign = Campaign(self.tmp.name, self.records)
        self.campaign.value["hit_gate"] = self.campaign.file("hit-gate.json", b"{}")
        self.plan = gate.schedule(5, ("request-weighted", "idle", 0), self.document["qualification"]["protocol"])
        self.runs = [{"id": f"run-{i}", "samples_sha256": hashlib.sha256(f"run-{i}".encode()).hexdigest()}
                     for i in range(len(self.plan))]

    def tearDown(self):
        self.tmp.cleanup()

    def judged(self, verdict="fail", client="i-h1", handoff=False, cells=None):
        identity = {"toolchain": "t", "owner": {"instance": "i-ref"}, "client": {"instance": client}}
        receipt = {"verdict": verdict, "candidate": COMMIT, "seed": 5, "main": "a" * 40, "campaign": "hit-gate-5",
                   "manifest_sha256": DIGEST, "open": ["an open item"], "reasons": ["a gate reason"],
                   "cells": cells or {CELL: {"verdict": verdict, "reasons": ["a cell reason"], "runs": self.runs,
                                             "identity": identity}}}
        if handoff:
            receipt["handoff"] = {"obligation": "o", "reason": "r"}
        return receipt

    def hit_gate(self, receipt):
        hosts = mf.admit_hosts(self.campaign.value["hosts"], "Graviton")
        with mock.patch.object(gate, "judge", return_value=receipt):
            return mf.hit_gate(self.campaign.value["hit_gate"], commit=COMMIT, hosts=hosts, document=self.document,
                               manifest_sha256=DIGEST, ids=IDS, lane=LANE)

    def test_only_non_null_candidate_arm_runs_of_a_decided_cell_bind(self):
        h, bound = self.hit_gate(self.judged())
        expected = {self.runs[i]["samples_sha256"] for i, (_, _, _, arm, null) in enumerate(self.plan)
                    if arm == "B" and not null}
        self.assertEqual(set(bound), expected)
        self.assertEqual(len(expected), 4)
        self.assertEqual({entry["client"] for entry in bound.values()}, {"i-h1"})
        self.assertEqual((h["verdict"], h["reasons"]), ("fail", []))
        _, bound = self.hit_gate(self.judged(verdict="inconclusive"))
        self.assertEqual(bound, {})

    def test_h_reads_inconclusive_when_its_runs_ran_on_unadmitted_or_untrusted_hosts(self):
        h, _ = self.hit_gate(self.judged(client="i-stranger"))
        self.assertEqual(h["verdict"], "inconclusive")
        self.assertIn(f"hit-gate cell {CELL} role client ran on instance i-stranger, which no admitted campaign host "
                      "names", h["reasons"])
        self.campaign.value["hosts"][1]["clock"] = "untrusted"
        h, _ = self.hit_gate(self.judged(handoff=True))
        self.assertEqual(h["verdict"], "handoff")
        self.assertIn(f"hit-gate cell {CELL}'s client host h1 has an untrusted clock", h["reasons"])

    def test_a_gate_cell_with_a_role_on_an_unadmitted_host_binds_no_cell(self):
        cells = self.judged()["cells"]
        cells[CELL]["identity"] = {**cells[CELL]["identity"], "owner": {"instance": "i-stranger"}}
        h, bound = self.hit_gate(self.judged(cells=cells))
        self.assertEqual(bound, {})
        self.assertEqual((h["verdict"], h["reasons"]), ("inconclusive", [
            f"hit-gate cell {CELL} role owner ran on instance i-stranger, which no admitted campaign host names"]))
        self.campaign.value["hosts"][1]["clock"] = "untrusted"
        h, bound = self.hit_gate(self.judged())
        self.assertEqual(len(bound), 4)
        self.assertEqual(h["reasons"], [f"hit-gate cell {CELL}'s client host h1 has an untrusted clock"])

    def test_a_samples_digest_two_candidate_arm_runs_carry_binds_no_cell(self):
        other = "request-weighted/publish/0"
        plan = gate.schedule(5, ("request-weighted", "publish", 0), self.document["qualification"]["protocol"])
        first = next(i for i, (_, _, _, arm, null) in enumerate(self.plan) if arm == "B" and not null)
        second = next(i for i, (_, _, _, arm, null) in enumerate(plan) if arm == "B" and not null)
        shared = self.runs[first]["samples_sha256"]
        runs = [{"id": f"publish-{i}", "samples_sha256": shared if i == second else
                 hashlib.sha256(f"publish-{i}".encode()).hexdigest()} for i in range(len(plan))]
        cells = self.judged()["cells"]
        cells[other] = {**cells[CELL], "runs": runs}
        named = (f"hit-gate runs {CELL} run-{first} and {other} publish-{second} carry the same samples {shared}, so "
                 "those samples bind no cell")
        for order in (cells, dict(reversed(cells.items()))):
            h, bound = self.hit_gate(self.judged(cells=order))
            self.assertNotIn(shared, bound)
            self.assertEqual(len(bound), 6)
            self.assertEqual((h["verdict"], h["reasons"]), ("inconclusive", [named]))

    def test_a_candidate_arm_digest_any_other_gate_run_carries_binds_no_cell(self):
        other = "request-weighted/publish/0"
        plan = gate.schedule(5, ("request-weighted", "publish", 0), self.document["qualification"]["protocol"])
        first = next(i for i, (_, _, _, arm, null) in enumerate(self.plan) if arm == "B" and not null)
        shared = self.runs[first]["samples_sha256"]
        main = next(i for i, (_, _, _, arm, null) in enumerate(plan) if arm == "A" and not null)
        null = next(i for i, (_, _, _, _, null) in enumerate(plan) if null)
        for label, at, verdict in (("a main-arm run", main, "fail"), ("a null-block run", null, "fail"),
                                   ("a run of an undecided cell", main, "inconclusive")):
            with self.subTest(label):
                runs = [{"id": f"publish-{i}", "samples_sha256": shared if i == at else
                         hashlib.sha256(f"publish-{i}".encode()).hexdigest()} for i in range(len(plan))]
                cells = self.judged()["cells"]
                cells[other] = {**cells[CELL], "verdict": verdict, "runs": runs}
                h, bound = self.hit_gate(self.judged(cells=cells))
                self.assertNotIn(shared, bound)
                self.assertEqual((h["verdict"], h["reasons"]), ("inconclusive", [
                    f"hit-gate runs {CELL} run-{first} and {other} publish-{at} carry the same samples {shared}, so "
                    "those samples bind no cell"]))

    def test_a_cell_on_a_bound_run_reads_its_summary_through_the_real_derivation(self):
        run = next(i for i, (_, _, _, arm, null) in enumerate(self.plan) if arm == "B" and not null)
        cell = self.campaign.cell(data=samples_file([700] * 4000))
        self.runs[run]["samples_sha256"] = cell["samples"]["sha256"]
        with mock.patch.object(gate, "judge", return_value=self.judged()), holding(self.records):
            receipt = self.campaign.report(self.log, self.document)
        entry = only(receipt)
        self.assertEqual(entry["reasons"], UNBOUND)
        self.assertEqual(entry["summary"]["hits"]["requests"], 4000)
        h = receipt["hit_gate"]
        self.assertEqual(h["verdict"], "inconclusive")
        self.assertEqual((h["gate"]["reasons"], h["gate"]["open"], h["gate"]["cells"][CELL]),
                         (["a gate reason"], ["an open item"], {"verdict": "fail", "reasons": ["a cell reason"]}))
        self.assertEqual(receipt["verdict"], "inconclusive")
        with mock.patch.object(gate, "judge", return_value=self.judged()):
            receipt = self.campaign.report(self.log, self.document)
        self.assertNotIn("summary", only(receipt))
        self.assertIn("the campaign's registration or id is unestablished, so the hit gate's samples bind nothing and "
                      "its verdict decides nothing", receipt["hit_gate"]["reasons"])
        null = next(i for i, (_, _, _, _, null) in enumerate(self.plan) if null)
        self.runs[run]["samples_sha256"], self.runs[null]["samples_sha256"] = "0" * 64, cell["samples"]["sha256"]
        with mock.patch.object(gate, "judge", return_value=self.judged()), holding(self.records):
            entry = only(self.campaign.report(self.log, self.document))
        self.assertNotIn("summary", entry)

    def test_a_decided_cell_needs_its_runs_and_its_schedules_run_count(self):
        bare = {CELL: {"verdict": "fail", "reasons": [], "runs": [], "identity": {}}}
        with self.assertRaisesRegex(gate.Refusal, "reads fail with no admitted runs"):
            self.hit_gate(self.judged(cells=bare))
        self.runs.pop()
        with self.assertRaisesRegex(gate.Refusal, "admitted 15 runs, not its schedule's 16"):
            self.hit_gate(self.judged())

    def test_a_declared_host_that_failed_admission_cannot_carry_hs_runs(self):
        self.campaign.value["hosts"][1]["jobs"] = 17
        h, _ = self.hit_gate(self.judged())
        self.assertEqual(h["verdict"], "inconclusive")
        self.assertIn(f"hit-gate cell {CELL} role client ran on instance i-h1, which no admitted campaign host names",
                      h["reasons"])
        self.campaign.value["hosts"][0]["jobs"] = 17
        h, _ = self.hit_gate(self.judged())
        self.assertIn(f"hit-gate cell {CELL} role owner ran on instance i-ref, which no admitted campaign host names",
                      h["reasons"])


class RealHitGate(unittest.TestCase):
    """The bound-set derivation over a receipt the real `gate.judge` writes for a decided cell, through the hit
    gate's own test fixture."""

    def test_the_real_judges_receipt_binds_exactly_its_candidate_arm_runs(self):
        spec = importlib.util.spec_from_file_location("test_hit_gate", ROOT / "scripts/test-hit-gate.py")
        assert spec is not None and spec.loader is not None
        th = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(th)
        fixture = th.Judge("test_a_regressed_candidate_fails_its_cell")
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        campaign = fixture.campaign(b_us=800)
        data = json.dumps(campaign).encode()
        ref = {"path": str(fixture.dir / "campaign.json"), "sha256": hashlib.sha256(data).hexdigest()}
        Path(ref["path"]).write_bytes(data)
        with tempfile.TemporaryDirectory() as tmp:
            c = Campaign(tmp)
            c.value["hosts"] = [c.host("owner", True), {**c.host("client", False), "instance": "i-client"}]
            c.value["hosts"][0]["instance"] = "i-owner"
            hosts = mf.admit_hosts(c.value["hosts"], "Graviton")
            h, bound = mf.hit_gate(ref, commit=th.CANDIDATE, hosts=hosts, document=fixture.document,
                                   manifest_sha256=th.DIGEST, ids=th.IDS, lane=th.Lane())
        q = fixture.q
        plan = gate.schedule(th.SEED, th.CELL, q["protocol"])
        expected = set()
        self.assertEqual(len(plan), len(campaign["runs"]))
        for i, run in enumerate(campaign["runs"]):
            if plan[i][3] == "B" and not plan[i][4]:
                client = json.loads(Path(run["receipts"][1]).read_text())["hardware"]
                path = client["cases"][0]["inputs"]["KESTRIKE_HIT_SAMPLES"]
                expected.add(hashlib.sha256(Path(path).read_bytes()).hexdigest())
        self.assertEqual(h["gate"]["cells"]["request-weighted/idle/0"]["verdict"], "fail")
        self.assertEqual(set(bound), expected)
        self.assertEqual(len(expected), 2 * q["protocol"]["blocks"] * q["protocol"]["repeats"])
        self.assertEqual({entry["client"] for entry in bound.values()}, {"i-client"})
        self.assertEqual(h["reasons"], [])


BASE = "b" * 40
READ = [member for member in mf.FAMILY if member not in mf.READERS]
HORIZON = 12
PASSING_GATE = ({"verdict": "pass", "reasons": [], "gate": {"main": BASE}}, {})
WARM = "warm-takeover"
IDLE = "idle"
TARGET = json.dumps([f"measure-{'0' * 16}", COMMIT, PATCH, "Graviton", WARM, "rto", "recovery", "hardware", "h1",
                     None, 1])
DECIDING = {mf.H: mf.PASS, mf.TAIL: mf.PASS}
AA_DERIVED, DRIFT_DERIVED = (f"control {name} derived {outcome!r} from values the campaign driver declares, which no "
                             "judge on this revision derives from their evidence"
                             for name, outcome in (("aa", "null"), ("calibration-drift", "stable")))


def outcomes(x, cold=False):
    """Every block-read member at value `x`, each level of a member with levels included, without the warm-only
    members when an arm runs the cold class."""
    fields = RECORDS["frame"][0]["fields"]
    return {m: {str(lv): x for lv in fields[m]["levels"]} if "levels" in fields[m] else x for m in READ
            if not (cold and m in mf.WARM_ONLY)}


def noise(kind, arm, i, slot):
    """A value near 100 whose block contrasts take both signs, so every A/A bound covers zero."""
    return 100 * (1 + 0.001 * ((7 * i + 3 * slot) % 5 - 2))


def regressing(kind, arm, i, slot):
    return noise(kind, arm, i, slot) * (1.5 if kind == "held-out" and arm == "B" else 1)


def scored(policy=None, strata=(f"{WARM}/{IDLE}",)):
    """Records whose statistics accept alpha and power and declare a horizon and drift band, and whose policy declares
    every block member's smallest effect, F's percentile, the readiness band and window, a foreground reservation and
    a campaign authority, and whose statistics declare the comparison `strata`, then the `policy` edit."""
    def revise_statistics(s):
        s["version"] = NEXT["statistics"]
        s["familywise_alpha"]["status"] = s["power"]["status"] = "accepted"
        s["horizon"]["blocks"], s["drift_band"], s["comparison_strata"] = HORIZON, 0.1, list(strata)

    def revise_policy(p):
        p["version"] = NEXT["policy"]
        for member in READ:
            p["outcomes"][member]["smallest_effect"] = 10.0
        p["f"]["percentile"] = 0.99
        p["readiness"].update(fill_band=0.1, fill_window_s=1)
        p["foreground_reservation"] = 0.5
        p["campaign_authority"] = {"approver": "owner", "budget_usd": 100, "host_hours": 10}
        if policy:
            policy(p)

    return build(statistics=revise_statistics, policy=revise_policy)


class Comparison(Campaign):
    """A comparison campaign: a contrast, a calibration on host h1, an AWS safety manifest over the hosts and volumes
    and, through `blocks` or `full`, seeded blocks of fresh runs. Its candidate carries `patch`, and a revision
    contrast's baseline is the unpatched commit `baseline`."""

    def __init__(self, directory, records=RECORDS, contrast="revision", baseline=BASE, patch=PATCH):
        super().__init__(directory, records)
        v = self.value
        v["contrast"] = contrast
        v["revision"]["patch_sha256"] = patch
        if contrast == "revision":
            v["baseline"] = {"commit": baseline, "patch_sha256": PATCH}
        v["campaign"] = mf.campaign_id(records, COMMIT, patch, v.get("baseline"))
        v["safety"] = {"tag": {"key": "campaign", "value": v["campaign"]}, "owner": "owner", "budget_usd": 50,
                       "host_hours": 4, "deadline": "2030-01-01T00:00:00Z", "teardown_on_failure": True,
                       "preexisting": [], "resources": [], "teardown": [],
                       "standing": ["i-ref", "i-h1", "vol-h1", "vol-cal"], "residue": []}
        terms = records["frame"][0]["calibration"]
        v["calibration"] = {phase: {"host": "h1", "volumes": ["vol-cal"],
                                    "evidence": self.file(f"calibration-{phase}", phase.encode()),
                                    "values": {term: {"value": value, "uncertainty": 1.0} for term in terms}}
                            for phase, value in (("start", 100.0), ("end", 101.0))}
        v["blocks"], self.runs = [], 0

    def blocks(self, kind, n, value=noise, cls=WARM, posture=IDLE):
        protocol = {"null_blocks": 0, "blocks": n, "repeats": 1}
        plan = gate.schedule(self.value["campaign"], (kind, cls, posture), protocol)
        cold = cls == mf.COLD or self.value["contrast"] == "class"
        for i in range(n):
            order, positions = "".join(p[3] for p in plan[4 * i:4 * i + 4]), []
            for slot, arm in enumerate(order):
                self.runs += 1
                positions.append({"arm": arm, "run": f"run-{self.runs}",
                                  "evidence": self.file(f"run-{self.runs}", f"{self.runs}\n".encode()),
                                  "outcomes": outcomes(value(kind, arm, i, slot), cold)})
            self.value["blocks"].append({"set": kind, "class": cls, "posture": posture, "order": order,
                                         "hosts": ["h1"], "volumes": ["vol-h1"], "positions": positions})

    def full(self, value=noise, cls=WARM):
        for kind, n in (("null", HORIZON), ("pilot", 3), ("held-out", HORIZON)):
            self.blocks(kind, n, value, cls)

    def cite(self, receipt=None):
        """Cite, as the revision contrast's target, a receipt file holding the rto cell TARGET of the warm class."""
        receipt = receipt or cited_receipt()
        data = json.dumps(receipt).encode()
        self.value["target"] = {"receipt": self.file("cited.json", data), "cell": TARGET}
        return data

    def pilot_tolerance(self):
        """The tolerance the pilot's exact arm A values set for rto at the smallest effect 10."""
        values = [v for b in self.value["blocks"] if b["set"] == "pilot"
                  for v in mf.block_contrast(b, "rto", None, "lower")[1]]
        return math.log(1 + 10.0 / mf.median(values))


def cited_receipt():
    """A measurement-frame receipt holding the judged rto cell TARGET of its own campaign."""
    return {"envelope": mf.ENVELOPE, "campaign_sha256": "e" * 64, "campaign": f"measure-{'0' * 16}",
            "cells": {TARGET: {"verdict": "inconclusive"}}}


def fewest(tail):
    """The fewest contrasts whose order bound is bounded at `tail`: the least n with 2^-n <= tail."""
    return next(n for n in range(1, 4097) if Fraction(1, 2 ** n) <= Fraction(tail))


def brute_floor(tail, power, s, tolerance):
    """The pilot floor by a linear search with exact binomial sums: the least n whose rank k leaves fewer than k
    contrasts above the tolerance with probability `power`."""
    q = 1 - NormalDist().cdf(tolerance / s)
    for n in range(1, 4097):
        k = max(k for k in range(n + 1) if sum(math.comb(n, i) for i in range(k)) <= Fraction(tail) * 2 ** n)
        if k and sum(math.comb(n, i) * q ** i * (1 - q) ** (n - i) for i in range(k)) >= power:
            return n
    return None


def entry(section, member="rto", cls=WARM, posture=IDLE):
    return section["bounds"][cls][posture][member]


class Comparisons(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def run_report(self, campaign, records, log, document=None):
        """The report under `records`, a passing hit gate and `document`, by default the manifest with a supported
        platform row."""
        with holding(records), mock.patch.object(mf, "hit_gate", return_value=PASSING_GATE):
            return campaign.report(log, document or supported())

    def scored_campaign(self, value=noise, policy=None, strata=(f"{WARM}/{IDLE}",)):
        records, log = scored(policy, strata)
        campaign = Comparison(self.tmp.name, records)
        campaign.full(value)
        campaign.cite()
        return campaign, records, log

    def assert_withheld(self, receipt, reason):
        """A regressing campaign whose fault `reason` withholds the regression verdict: rto still bounds as a
        regression and the ticket reads INCONCLUSIVE naming the fault."""
        ticket = receipt["comparison"]["ticket"]
        self.assertEqual(ticket["members"][f"{WARM}/{IDLE}/rto"], mf.REGRESSION)
        self.assertEqual(ticket["verdict"], mf.UNDECIDED)
        self.assertIn(reason, ticket["reasons"])

    def test_every_block_member_passes_yet_the_ticket_waits_on_the_request_tail_and_its_unjudged_controls(self):
        campaign, records, log = self.scored_campaign()
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertEqual((section["reasons"], section["calibration"]["reasons"]), ([], []))
        ticket = section["ticket"]
        block_members = {key: v for key, v in ticket["members"].items() if key.startswith(f"{WARM}/{IDLE}/")}
        self.assertEqual(len(block_members), len(READ) + 2)
        self.assertEqual(set(block_members.values()), {mf.PASS})
        self.assertEqual((ticket["members"][mf.H], ticket["members"][mf.TAIL]), (mf.PASS, mf.UNDECIDED))
        self.assertEqual((ticket["verdict"], ticket["merges"]), (mf.UNDECIDED, False))
        self.assertIn("no judge on this revision bounds the request tail between the baseline and the candidate, the "
                      "hit gate bounding hit latency alone", ticket["reasons"])
        self.assertIn(mf.DECLARED, ticket["reasons"])
        rto = entry(section)
        self.assertEqual(rto["blocks"], {"null": HORIZON, "pilot": 3, "held-out": HORIZON})
        self.assertAlmostEqual(rto["tolerance"], campaign.pilot_tolerance())
        self.assertEqual((section["revision"], section["baseline"]),
                         ({"commit": COMMIT, "patch_sha256": PATCH}, {"commit": BASE, "patch_sha256": PATCH}))

    def test_the_bound_verdict_passes_only_when_every_member_passes_under_accepted_statistics(self):
        campaign, records, log = self.scored_campaign()
        section = self.run_report(campaign, records, log)["comparison"]
        statistics, frame = records["statistics"][0], records["frame"][0]
        improved = copy.deepcopy(section["bounds"])
        improved[WARM][IDLE]["rto"]["bound"][1] = -0.01
        target = {"class": WARM, "field": "rto", "stratum": "recovery"}

        def judge(h=PASSING_GATE[0], validity=(), uncredited=(), stats=statistics, bounds=improved, cited=target):
            s = {**section, "bounds": bounds}
            return mf.bound_verdict(s, h=h, validity=list(validity), uncredited=list(uncredited), statistics=stats,
                                    frame=frame, target=cited)

        with mock.patch.object(mf, "reader_verdicts", return_value=(DECIDING, [])):
            passed = judge()
            self.assertEqual((passed["verdict"], passed["merges"], passed["reasons"]), (mf.PASS, True, []))
            self.assertEqual(judge(validity=["a fault"])["verdict"], mf.UNDECIDED)
            self.assertEqual(judge(uncredited=["a declaration"])["verdict"], mf.UNDECIDED)
            self.assertEqual(judge(bounds={})["verdict"], mf.UNDECIDED)
            unimproved = judge(bounds=section["bounds"])
            self.assertEqual(unimproved["verdict"], mf.UNDECIDED)
            self.assertIn(f"the target's rto on {WARM} holds no upper bound below zero, so the candidate shows no "
                          "measured improvement", unimproved["reasons"])
            for name, edit in (("an empty stratum", lambda b: b[WARM].update({IDLE: {}})),
                               ("a missing member", lambda b: b[WARM][IDLE].pop("goodput")),
                               ("a missing level", lambda b: b[WARM][IDLE].pop(f"{mf.RETAINED}/50"))):
                with self.subTest(name):
                    bounds = copy.deepcopy(improved)
                    edit(bounds)
                    found = judge(bounds=bounds)
                    self.assertEqual(found["verdict"], mf.UNDECIDED)
                    self.assertTrue(any(r.startswith(f"{WARM}/{IDLE} holds bounds on") for r in found["reasons"]))
            provisional = copy.deepcopy(statistics)
            provisional["power"]["status"] = "provisional"
            found = judge(stats=provisional)
            self.assertEqual(found["verdict"], mf.UNDECIDED)
            self.assertIn("alpha or power is provisional, so a passing bound is discovery, not powered confirmation",
                          found["reasons"])
        self.assertEqual(judge(h={"verdict": "fail", "gate": {"main": BASE}})["verdict"], mf.REGRESSION)
        self.assertEqual(judge()["verdict"], mf.UNDECIDED)

    def test_h_takes_the_gate_verdict_only_for_an_unpatched_baseline_and_candidate_and_the_tail_takes_none(self):
        baseline, candidate = {"commit": BASE, "patch_sha256": PATCH}, {"commit": COMMIT, "patch_sha256": PATCH}
        tail = ("no judge on this revision bounds the request tail between the baseline and the candidate, the hit "
                "gate bounding hit latency alone")
        for verdict, expected in (("pass", mf.PASS), ("fail", mf.REGRESSION)):
            self.assertEqual(mf.reader_verdicts({"verdict": verdict, "gate": {"main": BASE}}, baseline, candidate),
                             ({mf.H: expected, mf.TAIL: mf.UNDECIDED}, [tail]))
            for role in ("baseline", "candidate"):
                revisions = {"baseline": baseline, "candidate": candidate}
                revisions[role] = {**revisions[role], "patch_sha256": "a" * 64}
                patched = mf.reader_verdicts({"verdict": verdict, "gate": {"main": BASE}}, revisions["baseline"],
                                             revisions["candidate"])
                self.assertEqual(patched, ({mf.H: mf.UNDECIDED, mf.TAIL: mf.UNDECIDED}, [
                    f"the {role} is patched and the hit gate builds only an unmodified tree, so H takes no bound "
                    "verdict", tail]))
        moved = mf.reader_verdicts({"verdict": "pass", "gate": {"main": "a" * 40}}, baseline, candidate)
        self.assertEqual(moved[0][mf.H], mf.UNDECIDED)
        self.assertIn("the hit gate judged another main revision than the baseline, so H takes no bound verdict",
                      moved[1])
        unjudged = mf.reader_verdicts({"verdict": "inconclusive", "reasons": []}, baseline, candidate)
        self.assertEqual(unjudged[1][0], "the hit gate reads inconclusive, so H holds no decided bound")

    def test_a_held_out_regression_past_the_tolerance_is_an_unacceptable_regression(self):
        campaign, records, log = self.scored_campaign(regressing)
        receipt = self.run_report(campaign, records, log)
        ticket = receipt["comparison"]["ticket"]
        self.assertEqual((ticket["verdict"], ticket["merges"]), (mf.REGRESSION, False))
        self.assertEqual(ticket["members"][f"{WARM}/{IDLE}/rto"], mf.REGRESSION)
        self.assertEqual(ticket["members"][f"{WARM}/{IDLE}/goodput"], mf.PASS)
        self.assertEqual(receipt["verdict"], "fail")
        low, _ = entry(receipt["comparison"])["bound"]
        self.assertGreater(low, math.log(1.4))
        receipt = self.run_report(campaign, records, log, DOCUMENT)
        self.assert_withheld(receipt, "Inconclusive: platform row unsupported, so no block bound decides")
        campaign.value["header"]["device_model"] = None
        receipt = self.run_report(campaign, records, log)
        self.assert_withheld(receipt, "header device_model is undeclared for hardware evidence, so no block bound "
                                      "decides")

    def test_a_hit_gate_regression_alone_is_an_unacceptable_regression_under_underived_controls(self):
        """H takes the gate's own verdict: the controls no judge derives withhold PASS from it but never a
        regression, so a failing gate reads UNACCEPTABLE_REGRESSION while every block member passes."""
        campaign, records, log = self.scored_campaign()
        failing = ({"verdict": "fail", "reasons": [], "gate": {"main": BASE}}, {})
        with holding(records), mock.patch.object(mf, "hit_gate", return_value=failing):
            receipt = campaign.report(log, supported())
        ticket = receipt["comparison"]["ticket"]
        self.assertEqual(ticket["members"][mf.H], mf.REGRESSION)
        self.assertEqual((ticket["verdict"], ticket["merges"]), (mf.REGRESSION, False))
        self.assertEqual(receipt["verdict"], "fail")
        patched = "a" * 64
        campaign.value["revision"]["patch_sha256"] = patched
        campaign.value["campaign"] = mf.campaign_id(records, COMMIT, patched, campaign.value["baseline"])
        campaign.value["safety"]["tag"]["value"] = campaign.value["campaign"]
        with holding(records), mock.patch.object(mf, "hit_gate", return_value=failing):
            ticket = campaign.report(log, supported())["comparison"]["ticket"]
        self.assertEqual((ticket["members"][mf.H], ticket["verdict"]), (mf.UNDECIDED, mf.UNDECIDED))
        self.assertIn("the candidate is patched and the hit gate builds only an unmodified tree, so H takes no bound "
                      "verdict", ticket["reasons"])

    def test_a_contrast_of_a_revision_with_itself_withholds_the_regression(self):
        """A baseline that is the campaign's own revision runs one build as both arms, so a bound past the tolerance
        is no revision effect and the ticket reads INCONCLUSIVE naming it. The same commit under another patch digest
        is a second build, whose regression stands."""
        one_build = ("the baseline is the campaign's own revision, so both arms run one build and no bound is a "
                     "revision effect")
        records, log = scored()
        campaign = Comparison(self.tmp.name, records, baseline=COMMIT)
        campaign.full(regressing)
        campaign.cite()
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(receipt["comparison"]["reasons"], [one_build])
        self.assert_withheld(receipt, one_build)
        self.assertEqual(receipt["verdict"], "inconclusive")
        patched = Comparison(self.tmp.name, records, baseline=COMMIT, patch="a" * 64)
        patched.full(regressing)
        patched.cite()
        section = self.run_report(patched, records, log)["comparison"]
        self.assertEqual((section["reasons"], section["ticket"]["verdict"]), ([], mf.REGRESSION))

    def test_the_committed_owner_inputs_leave_every_bound_unscored(self):
        campaign = Comparison(self.tmp.name)
        campaign.full(regressing)
        receipt = self.run_report(campaign, RECORDS, LOG)
        section = receipt["comparison"]
        rto = entry(section)
        self.assertIn("the statistics version declares no horizon block count", rto["reasons"])
        self.assertIn("the statistics version declares no comparison strata, so the per-tail level has no fixed "
                      "family", rto["reasons"])
        self.assertIn("the policy declares no smallest effect for rto, so its bound is unscored", rto["reasons"])
        self.assertIsNone(rto["tolerance"])
        self.assertIn("the policy declares no F percentile, so fill_latency's measured value is undefined",
                      entry(section, mf.F)["reasons"])
        self.assertIn("the policy declares no readiness fill_band, so sustained fill readiness is undefined",
                      entry(section, "sustained_fill_readiness")["reasons"])
        members = section["ticket"]["members"]
        self.assertEqual({v for key, v in members.items() if key != mf.H}, {mf.UNDECIDED})
        self.assertEqual(members[mf.H], mf.PASS)
        self.assertEqual(section["ticket"]["verdict"], mf.UNDECIDED)
        self.assertIn("the policy names no campaign authority, so no budget or host-hour limit approves the campaign",
                      section["reasons"])
        self.assertIn(mf.RESERVATION, section["calibration"]["reasons"])
        self.assertIn("control calibration-drift is unreached: the statistics version declares no drift band",
                      receipt["reasons"])
        self.assertEqual(receipt["verdict"], "inconclusive")

    def test_blocks_take_the_seeded_order_and_a_reordered_incomplete_or_repeated_block_is_missing(self):
        campaign, records, log = self.scored_campaign()
        blocks = campaign.value["blocks"]
        held = [b for b in blocks if b["set"] == "held-out"]
        pilot = [b for b in blocks if b["set"] == "pilot"]
        seeded = held[0]["order"]
        flipped = held[0]["order"] = {"ABBA": "BAAB", "BAAB": "ABBA"}[seeded]
        held[1]["positions"].pop()
        held[2]["positions"][0]["run"] = held[3]["positions"][0]["run"]
        held[4]["hosts"] = ["h9"]
        held[5]["positions"][1]["evidence"]["sha256"] = "0" * 64
        held[6]["positions"][0]["outcomes"][mf.H] = 700
        held[7]["positions"][0]["evidence"] = pilot[0]["positions"][0]["evidence"]
        section = self.run_report(campaign, records, log)["comparison"]
        reasons, name = section["reasons"], f"of {WARM}/{IDLE}"
        self.assertIn(f"held-out block 0 {name} runs {flipped}, not its seeded order {seeded}", reasons)
        self.assertIn(f"held-out block 1 {name} is incomplete: its positions are not one run per slot of its order",
                      reasons)
        repeated = held[2]["positions"][0]["run"]
        for i in (2, 3):
            self.assertIn(f"held-out block {i} {name} carries run {repeated}, which another position also names; a "
                          "stopped run is missing, never retried", reasons)
        self.assertIn(f"held-out block 4 {name} ran on h9, which is no admitted host", reasons)
        self.assertTrue(any(r.startswith(f"held-out block 5 {name} run") and "is not the file its SHA-256 names" in r
                            for r in reasons))
        for block in (f"held-out block 7 {name} run {held[7]['positions'][0]['run']}",
                      f"pilot block 0 {name} run {pilot[0]['positions'][0]['run']}"):
            self.assertIn(f"{block} names evidence another position also names", reasons)
        self.assertIn("block positions name ['hit_latency'], which no block contrast reads", reasons)
        rto = entry(section)
        self.assertEqual((rto["blocks"]["held-out"], rto["blocks"]["pilot"]), (HORIZON - 7, 2))
        self.assertIn(f"{HORIZON - 7} of the fixed horizon's {HORIZON} held-out blocks hold a usable value",
                      rto["reasons"])
        self.assertEqual(section["ticket"]["verdict"], mf.UNDECIDED)

    def test_a_declared_host_that_fails_admission_leaves_its_blocks_missing(self):
        campaign, records, log = self.scored_campaign()
        campaign.value["hosts"][1]["jobs"] = 17
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn(f"held-out block 0 of {WARM}/{IDLE} ran on h1, which is no admitted host", section["reasons"])
        self.assertIn("the calibration's start host h1 is no admitted host", section["calibration"]["reasons"])
        self.assertEqual(entry(section)["blocks"]["held-out"], 0)

    def test_blocks_of_one_class_and_posture_on_two_host_sets_decide_nothing(self):
        campaign, records, log = self.scored_campaign(regressing)
        campaign.value["hosts"].append(campaign.host("h2", False))
        campaign.value["safety"]["standing"].append("i-h2")
        for block in campaign.value["blocks"]:
            if block["set"] == "held-out":
                block["hosts"] = ["h2", "h1"]
        receipt = self.run_report(campaign, records, log)
        self.assertIn(f"{WARM}/{IDLE}'s blocks run on 2 host sets, so its bounds would pool host strata",
                      entry(receipt["comparison"])["reasons"])
        self.assertEqual(receipt["comparison"]["ticket"]["verdict"], mf.UNDECIDED)
        for block in campaign.value["blocks"]:
            block["hosts"] = ["h2", "h1"] if block["set"] == "pilot" else ["h1", "h2"]
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(receipt["comparison"]["ticket"]["verdict"], mf.REGRESSION)

    def test_each_posture_takes_its_own_seeded_blocks_and_bounds(self):
        records, log = scored(strata=(f"{WARM}/{IDLE}", f"{WARM}/scan"))
        campaign = Comparison(self.tmp.name, records)
        campaign.full()
        for kind, n in (("null", HORIZON), ("pilot", 3), ("held-out", HORIZON)):
            campaign.blocks(kind, n, regressing, posture="scan")
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertEqual(section["reasons"], [])
        self.assertEqual(sorted(section["bounds"][WARM]), ["idle", "scan"])
        self.assertEqual(section["ticket"]["members"][f"{WARM}/scan/rto"], mf.REGRESSION)
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.PASS)
        _, tail, _ = mf.level(records["statistics"][0], records["policy"][0])
        self.assertEqual(entry(section)["floor"], fewest(tail / 2))

    def test_the_fixed_horizon_admits_no_extension_and_the_pilot_floor_can_exceed_it(self):
        records, log = scored()
        campaign = Comparison(self.tmp.name, records)
        campaign.full()
        campaign.blocks("held-out", 1, cls="same-host-restart")
        bounds = self.run_report(campaign, records, log)["comparison"]["bounds"]
        self.assertIn(f"same-host-restart/{IDLE} holds 1 held-out blocks, not the fixed horizon's {HORIZON}",
                      bounds["same-host-restart"][IDLE]["rto"]["reasons"])
        campaign = Comparison(self.tmp.name, records)
        campaign.full(regressing)
        campaign.blocks("held-out", 1, regressing)
        campaign.cite()
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn(f"{WARM}/{IDLE} holds {HORIZON + 1} held-out blocks, not the fixed horizon's {HORIZON}",
                      entry(section)["reasons"])
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)

        def spread(kind, arm, i, slot):
            return noise(kind, arm, i, slot) * (1 + (0.3 * (slot + i) if kind == "pilot" and arm == "B" else 0))

        campaign, records, log = self.scored_campaign(spread)
        section = self.run_report(campaign, records, log)["comparison"]
        rto = entry(section)
        pilot = [mf.block_contrast(b, "rto", None, "lower")[0][0] for b in campaign.value["blocks"]
                 if b["set"] == "pilot"]
        tolerance = campaign.pilot_tolerance()
        _, tail, _ = mf.level(records["statistics"][0], records["policy"][0])
        floor = brute_floor(tail, 0.9, mf.stdev(pilot), tolerance)
        self.assertGreater(floor or 0, HORIZON)
        self.assertEqual(rto["floor"], floor)
        self.assertAlmostEqual(rto["tolerance"], tolerance)
        self.assertIn(f"the fixed horizon of {HORIZON} blocks is under the pilot floor of {floor}", rto["reasons"])
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)

    def test_the_pilot_floor_sizes_the_order_bound_it_feeds(self):
        tail = 0.05 / (2 * len(mf.FAMILY))
        self.assertEqual(mf.pilot_floor(tail, 0.9, 1.0, 1.0), 34)
        self.assertEqual(brute_floor(tail, 0.9, 1.0, 1.0), 34)
        for s, tolerance, power in ((0.5, 1.0, 0.9), (2.0, 1.0, 0.8), (1.0, 3.0, 0.99), (1.0, 0.4, 0.9)):
            with self.subTest(s=s, tolerance=tolerance, power=power):
                self.assertEqual(mf.pilot_floor(tail, power, s, tolerance), brute_floor(tail, power, s, tolerance))
        self.assertEqual(mf.pilot_floor(tail, 0.9, 0.0, 1.0), fewest(tail))
        self.assertIsNone(mf.pilot_floor(tail, 0.9, 1.0, 1e-9))

    def test_the_floor_scan_carries_each_horizons_power_and_agrees_with_the_direct_sum(self):
        """The floor scan carries P(Binomial(n, q) < k) from each n to the next at the order rank k; at every n,
        exceedances near one half included, it is the direct sum `sign_power` takes and its ranks are `ranks`."""
        tail = 0.05 / (2 * len(mf.FAMILY)) / 12
        for q in (0.0, 1e-6, 0.1, 0.3, 0.46, 0.4999):
            with self.subTest(q=q):
                scan = list(mf.floor_powers(tail, q, 400))
                self.assertEqual([(n, k) for n, k, _ in scan], list(mf.ranks(tail, 400)))
                for n, k, p in scan:
                    self.assertAlmostEqual(p, mf.sign_power(n, k, q), delta=1e-12)
        scan = list(mf.floor_powers(tail, 0.48, mf.MAX_CELLS))
        self.assertEqual(len(scan), mf.MAX_CELLS)
        for n, k, p in scan[999::1024]:
            self.assertAlmostEqual(p, mf.sign_power(n, k, 0.48), delta=1e-9)
        self.assertIsNone(mf.pilot_floor(tail, 0.9, 1.0, 0.05))

    def test_the_tolerance_follows_the_member_direction_and_refuses_no_finite_value(self):
        self.assertAlmostEqual(mf.tolerance_of(10.0, 100.0, "higher"), 0.1053605156578263)
        self.assertAlmostEqual(mf.tolerance_of(10.0, 100.0, "lower"), math.log(1.1))
        for effect, center, direction in ((100.0, 100.0, "higher"), (150.0, 100.0, "higher"), (1e-320, 1e308, "lower"),
                                          (10.0, 5e-324, "lower")):
            with self.subTest(effect=effect, center=center):
                self.assertIsNone(mf.tolerance_of(effect, center, direction))
        campaign, records, log = self.scored_campaign(policy=lambda p: p["outcomes"]["rto"].update(
            smallest_effect=1e-300))
        rto = entry(self.run_report(campaign, records, log)["comparison"])
        self.assertGreater(rto["tolerance"], 0)
        self.assertIsNone(rto["floor"])
        self.assertIn(f"no horizon up to {mf.MAX_CELLS} blocks reaches the power", rto["reasons"])
        campaign, records, log = self.scored_campaign(policy=lambda p: p["outcomes"]["goodput"].update(
            smallest_effect=500.0))
        goodput = entry(self.run_report(campaign, records, log)["comparison"], "goodput")
        self.assertIsNone(goodput["tolerance"])
        self.assertTrue(any(r.startswith("the smallest effect 500.0 makes no finite positive tolerance")
                            for r in goodput["reasons"]))

    def test_the_order_bound_is_the_binomial_order_statistic_at_the_split_bonferroni_level(self):
        _, tail, _ = mf.level(RECORDS["statistics"][0], RECORDS["policy"][0])
        self.assertEqual(tail, 0.05 / (2 * len(mf.FAMILY)))
        self.assertEqual((fewest(tail), fewest(tail / 3)), (9, 11))
        exact = [(float(v), float(v)) for v in range(1, 9)]
        self.assertEqual(mf.order_bound(exact, tail), [None, None])
        self.assertEqual(mf.order_bound(exact + [(9.0, 9.0)], tail), [1.0, 9.0])
        wide = [(float(v), float(v)) for v in range(1, 41)]
        k = max(k for k in range(41) if sum(math.comb(40, i) for i in range(k)) <= tail * 2 ** 40)
        self.assertEqual(mf.order_bound(wide, tail), [float(k), float(41 - k)])
        self.assertEqual(mf.order_bound(exact + [(9.0, math.inf)], tail), [1.0, None])
        self.assertEqual(mf.order_bound([(-math.inf, 0.5)] + exact, tail), [None, 8.0])
        for level in (tail, tail / 3, 0.25):
            carried = dict(mf.ranks(level, 400))
            for n in (1, 9, 10, 40, 333, 400):
                with self.subTest(n=n, level=level):
                    expected = max(k for k in range(n + 1)
                                   if sum(math.comb(n, i) for i in range(k)) <= Fraction(level) * 2 ** n)
                    self.assertEqual((mf.order_rank(n, level), carried[n]), (expected, expected))
            self.assertEqual(carried, {n: mf.order_rank(n, level) for n in carried})

    def test_the_split_level_sets_each_level_its_own_floor_and_the_strata_share_the_family(self):
        campaign, records, log = self.scored_campaign()
        section = self.run_report(campaign, records, log)["comparison"]
        _, tail, _ = mf.level(records["statistics"][0], records["policy"][0])
        self.assertEqual(entry(section)["floor"], 9)
        for at in (50, 90, 99):
            self.assertEqual(entry(section, f"{mf.RETAINED}/{at}")["floor"], 11)
        self.assertEqual(fewest(tail), 9)
        campaign.blocks("pilot", 3, cls="same-host-restart")
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertEqual(entry(section)["floor"], 9)
        self.assertIn(f"the campaign's strata ['same-host-restart/{IDLE}', '{WARM}/{IDLE}'] are not the declared "
                      f"comparison strata ['{WARM}/{IDLE}']", entry(section)["reasons"])
        self.assertEqual(section["ticket"]["verdict"], mf.UNDECIDED)
        campaign, records, log = self.scored_campaign(regressing, strata=(f"{WARM}/{IDLE}", f"{WARM}/scan"))
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(entry(receipt["comparison"])["floor"], fewest(tail / 2))
        self.assertIn(f"the campaign's strata ['{WARM}/{IDLE}'] are not the declared comparison strata "
                      f"['{WARM}/{IDLE}', '{WARM}/scan']", entry(receipt["comparison"])["reasons"])
        self.assertEqual(receipt["comparison"]["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)
        self.assertEqual(receipt["comparison"]["ticket"]["verdict"], mf.UNDECIDED)

    def test_decide_reads_its_bound_against_the_tolerance_at_both_equalities(self):
        def at(low, high, reasons=()):
            return mf.decide({"bound": [low, high], "tolerance": 0.1, "reasons": list(reasons)})

        self.assertEqual(at(-0.2, 0.1), mf.PASS)
        self.assertEqual(at(0.1, 0.3), mf.UNDECIDED)
        self.assertEqual(at(0.10000001, 0.3), mf.REGRESSION)
        self.assertEqual(at(-0.2, None), mf.UNDECIDED)
        self.assertEqual(at(None, 0.05), mf.PASS)
        self.assertEqual(at(None, 0.3), mf.UNDECIDED)
        self.assertEqual(at(0.5, 0.6, ["a reason"]), mf.UNDECIDED)
        self.assertEqual(mf.decide({"bound": [0.5, 0.6], "tolerance": None, "reasons": []}), mf.UNDECIDED)

    def test_censoring_bounds_only_the_side_its_censoring_keeps(self):
        positions = [{"arm": arm, "outcomes": {"rto": value}} for arm, value in
                     (("A", 10), ("B", {"censored": 20}), ("B", 20), ("A", 10))]
        (low, high), values, censored = mf.block_contrast({"positions": positions}, "rto", None, "lower")
        self.assertEqual((high, values, censored), (math.inf, [10, 10], True))
        self.assertAlmostEqual(low, math.log(2))
        positions[0]["outcomes"]["rto"] = {"censored": 10}
        positions[1]["outcomes"]["rto"] = 20
        (low, high), values, _ = mf.block_contrast({"positions": positions}, "rto", None, "lower")
        self.assertEqual((low, values), (-math.inf, [10]))
        self.assertAlmostEqual(high, math.log(2))
        positions[2]["outcomes"]["rto"] = 0
        self.assertIsNone(mf.block_contrast({"positions": positions}, "rto", None, "lower"))
        goodput = [{"arm": a, "outcomes": {"goodput": v}} for a, v in (("A", 10), ("B", 20), ("B", 20), ("A", 10))]
        (low, high), _, censored = mf.block_contrast({"positions": goodput}, "goodput", None, "higher")
        self.assertAlmostEqual(low, -math.log(2))
        self.assertAlmostEqual(high, -math.log(2))
        self.assertFalse(censored)
        goodput[1]["outcomes"]["goodput"] = {"censored": 20}
        (low, high), _, _ = mf.block_contrast({"positions": goodput}, "goodput", None, "higher")
        self.assertAlmostEqual(low, -math.log(2))
        self.assertEqual(high, math.inf)
        for huge in (10 ** 400, float("inf"), True):
            positions[2]["outcomes"]["rto"] = huge
            self.assertIsNone(mf.block_contrast({"positions": positions}, "rto", None, "lower"))

    def test_censored_values_keep_their_side_through_the_verdict_and_the_pilot(self):
        def timeouts(kind, arm, i, slot):
            value = regressing(kind, arm, i, slot)
            return {"censored": value} if kind == "held-out" and arm == "B" and i < 6 else value

        campaign, records, log = self.scored_campaign(timeouts)
        section = self.run_report(campaign, records, log)["comparison"]
        rto = entry(section)
        self.assertEqual(rto["bound"][1], None)
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.REGRESSION)

        def slow_baseline(kind, arm, i, slot):
            value = noise(kind, arm, i, slot)
            return {"censored": value} if kind == "held-out" and arm == "A" else value

        campaign, records, log = self.scored_campaign(slow_baseline)
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIsNone(entry(section)["bound"][0])
        self.assertNotEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.REGRESSION)

        def censored_pilot(kind, arm, i, slot):
            value = noise(kind, arm, i, slot)
            return {"censored": value * 60} if kind == "pilot" and arm == "A" and slot == 0 else value

        campaign, records, log = self.scored_campaign(censored_pilot)
        rto = entry(self.run_report(campaign, records, log)["comparison"])
        self.assertEqual((rto["tolerance"], rto["floor"]), (None, None))
        self.assertIn("a censored pilot value leaves the tolerance and the floor unsized", rto["reasons"])

    def test_the_aa_control_is_derived_from_the_null_blocks(self):
        campaign, records, log = self.scored_campaign()
        receipt = self.run_report(campaign, records, log)
        self.assertIn(AA_DERIVED, receipt["ranking"]["withheld"])

        def biased(kind, arm, i, slot):
            return regressing(kind, arm, i, slot) * (1.2 if kind == "null" and arm == "B" else 1)

        campaign, records, log = self.scored_campaign(biased)
        receipt = self.run_report(campaign, records, log)
        self.assertIn("control aa derived 'not-null', not its declared 'null'", receipt["reasons"])
        self.assertIn("control aa derived 'not-null', not its declared 'null'", receipt["ranking"]["withheld"])
        self.assert_withheld(receipt, "control aa derived 'not-null', not its declared 'null'")
        records, log = scored()
        campaign = Comparison(self.tmp.name, records)
        campaign.blocks("null", 3)
        receipt = self.run_report(campaign, records, log)
        (reason,) = [r for r in receipt["reasons"] if r.startswith("control aa")]
        self.assertTrue(reason.startswith(
            f"control aa is unreached: the A/A bounds on ['{WARM}/{IDLE}/first_safe_hit'"))

    def test_an_entry_with_held_out_contrasts_and_no_aa_contrast_leaves_the_aa_control_unreached(self):
        campaign, records, log = self.scored_campaign()
        campaign.blocks("held-out", HORIZON, cls="same-host-restart")
        campaign.blocks("pilot", 3, cls="same-host-restart")
        receipt = self.run_report(campaign, records, log)
        (reason,) = [r for r in receipt["reasons"] if r.startswith("control aa")]
        self.assertTrue(reason.startswith("control aa is unreached: the entries ['same-host-restart/idle/"))
        campaign, records, log = self.scored_campaign()
        for block in campaign.value["blocks"]:
            if block["set"] == "null":
                for position in block["positions"]:
                    position["outcomes"].pop("rto")
                    position["outcomes"][mf.RETAINED].pop("50")
        receipt = self.run_report(campaign, records, log)
        (reason,) = [r for r in receipt["reasons"] if r.startswith("control aa")]
        self.assertIn(f"'{WARM}/{IDLE}/rto'", reason)
        self.assertIn(f"'{WARM}/{IDLE}/{mf.RETAINED}/50'", reason)

    def test_the_calibration_drift_control_and_its_independence_from_scored_runs(self):
        campaign, records, log = self.scored_campaign(regressing)
        receipt = self.run_report(campaign, records, log)
        calibration = receipt["comparison"]["calibration"]
        self.assertEqual(set(calibration["terms"]), set(records["frame"][0]["calibration"]))
        self.assertAlmostEqual(calibration["terms"]["volume_iops"]["drift"], 0.01)
        low, high = calibration["terms"]["volume_iops"]["range"]
        self.assertEqual(low, 0.0)
        self.assertAlmostEqual(high, 3 / 99)
        self.assertIn(DRIFT_DERIVED, receipt["ranking"]["withheld"])
        values = campaign.value["calibration"]["end"]["values"]
        values["volume_iops"]["value"] = 150.0
        receipt = self.run_report(campaign, records, log)
        self.assert_withheld(receipt, "control calibration-drift derived 'drifted', not its declared 'stable'")
        values["volume_iops"].update(value=101.0, uncertainty=10.0)
        receipt = self.run_report(campaign, records, log)
        self.assert_withheld(receipt, "control calibration-drift is unreached: the uncertainty of calibration terms "
                                      "['volume_iops'] spans the drift band")
        for start in campaign.value["calibration"]["start"]["values"].values():
            start["uncertainty"] = 0.0
        for end in values.values():
            end.update(value=110.0, uncertainty=0.0)
        receipt = self.run_report(campaign, records, log)
        self.assertIn(DRIFT_DERIVED, receipt["reasons"])
        values.pop("worker_slots")
        campaign.value["calibration"]["start"]["evidence"] = campaign.value["blocks"][0]["positions"][0]["evidence"]
        receipt = self.run_report(campaign, records, log)
        reasons = receipt["comparison"]["calibration"]["reasons"]
        self.assertEqual(reasons, [
            "the calibration's start evidence is a scored position's, so it is not measured apart from scored "
            "elapsed time",
            "calibration term worker_slots lacks a positive start or end value with a non-negative uncertainty"])
        control = f"control calibration-drift is unreached: {'; '.join(reasons)}"
        self.assert_withheld(receipt, control)
        self.assertEqual(sum(r == reasons[1] for r in receipt["comparison"]["ticket"]["reasons"]), 0)

    def test_the_calibration_runs_on_one_admitted_trusted_host_from_two_files(self):
        campaign, records, log = self.scored_campaign(regressing)
        calibration = campaign.value["calibration"]
        calibration["end"]["evidence"] = calibration["start"]["evidence"]
        calibration["end"]["host"] = "ref"
        reasons = self.run_report(campaign, records, log)["comparison"]["calibration"]["reasons"]
        self.assertEqual(reasons, [
            "the calibration's start and end ran on different hosts, so their drift compares nothing",
            "the calibration's start and end name one evidence file, so they are one measurement"])
        calibration["end"]["host"] = "h9"
        reasons = self.run_report(campaign, records, log)["comparison"]["calibration"]["reasons"]
        self.assertIn("the calibration's end host h9 is no admitted host", reasons)
        calibration["end"]["host"] = "h1"
        calibration["end"]["evidence"] = campaign.file("calibration-end", b"end")
        campaign.value["hosts"][1]["clock"] = "untrusted"
        receipt = self.run_report(campaign, records, log)
        self.assertIn("the calibration's start host h1 has an untrusted clock, so its rates are not measured",
                      receipt["comparison"]["calibration"]["reasons"])
        campaign.value["calibration"]["start"]["values"]["volume_iops"]["value"] = 10 ** 400
        receipt = self.run_report(campaign, records, log)
        self.assertIn("calibration term volume_iops lacks a positive start or end value with a non-negative "
                      "uncertainty", receipt["comparison"]["calibration"]["reasons"])
        campaign.value.pop("calibration")
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(receipt["comparison"]["calibration"], {"terms": {}, "reasons": [
            "the campaign holds no calibration"]})

    def test_an_untrusted_clock_degrades_the_clocked_members_of_its_blocks(self):
        records, log = scored(policy=lambda p: p["outcomes"]["held_capacity"].update(
            unit="units/s", normalization="per second of the recovery window"))
        campaign = Comparison(self.tmp.name, records)
        campaign.value["hosts"][1]["clock"] = "untrusted"
        campaign.full()
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertEqual(entry(section)["blocks"]["held-out"], 0)
        self.assertEqual(entry(section, "held_capacity")["blocks"]["held-out"], 0)
        self.assertEqual(entry(section, "origin_demand")["blocks"]["held-out"], HORIZON)

    def test_a_class_contrast_keeps_the_cold_control_as_arm_a_and_takes_no_bound_verdict(self):
        records, log = scored()
        campaign = Comparison(self.tmp.name, records, "class")
        campaign.full(regressing)
        campaign.blocks("held-out", 1, cls=mf.COLD)
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertNotIn("ticket", section)
        self.assertEqual(section["contrast"], "class")
        self.assertIn(f"held-out block 0 of {mf.COLD}/{IDLE} runs the cold control as arm B, which a class contrast "
                      "keeps for a treatment", section["reasons"])
        self.assertGreater(entry(section)["bound"][0], 0)

    def test_the_cold_class_bounds_no_warm_only_member(self):
        records, log = scored(strata=(f"{mf.COLD}/{IDLE}",))
        campaign = Comparison(self.tmp.name, records)
        campaign.full(cls=mf.COLD)
        self.assertFalse({key for block in campaign.value["blocks"] for position in block["positions"]
                          for key in position["outcomes"]} & set(mf.WARM_ONLY))
        section = self.run_report(campaign, records, log)["comparison"]
        cold = {"first_safe_hit", "sustained_fill_readiness", "rto", "origin_demand", "goodput", "peak_ram", mf.F}
        self.assertEqual(set(section["bounds"][mf.COLD][IDLE]), cold)
        self.assertEqual({section["ticket"]["members"][f"{mf.COLD}/{IDLE}/{k}"] for k in cold}, {mf.PASS})
        self.assertEqual(section["reasons"], [])
        warm = mf.member_keys(records["frame"][0], WARM, "revision")
        self.assertEqual(set(warm) - cold, {f"{mf.RETAINED}/50", f"{mf.RETAINED}/90", f"{mf.RETAINED}/99",
                                            "held_capacity"})
        self.assertEqual(set(mf.member_keys(records["frame"][0], WARM, "class")), cold)
        self.assertEqual(mf.outcome(records["policy"][0], mf.COLD, "held_capacity"), "inconclusive")

    def test_a_warm_only_value_on_a_cold_arm_and_an_undeclared_level_are_campaign_reasons(self):
        """A position names only the keys its block's contrast reads: a warm-only member on a block whose arm runs
        the cold class, or a level the field does not declare, is a campaign reason that withholds the verdict."""
        levels = RECORDS["frame"][0]["fields"][mf.RETAINED]["levels"]
        self.assertNotIn(75, levels)
        cases = (("an undeclared level", WARM, "revision",
                  lambda o: o[mf.RETAINED].update({"75": 100.0}), [f"{mf.RETAINED}/75"]),
                 ("a warm-only member on the cold class", mf.COLD, "revision",
                  lambda o: o.update(held_capacity=100.0), ["held_capacity"]),
                 ("a warm-only member in a class contrast", WARM, "class",
                  lambda o: o.update(held_capacity=100.0), ["held_capacity"]))
        for name, cls, contrast, edit, extra in cases:
            with self.subTest(name):
                records, log = scored(strata=(f"{cls}/{IDLE}",))
                campaign = Comparison(self.tmp.name, records, contrast)
                campaign.full(regressing, cls=cls)
                if contrast == "revision":
                    campaign.cite()
                clean = self.run_report(campaign, records, log)["comparison"]
                self.assertEqual(clean["reasons"], [])
                for block in campaign.value["blocks"]:
                    for position in block["positions"]:
                        edit(position["outcomes"])
                section = self.run_report(campaign, records, log)["comparison"]
                self.assertIn(f"block positions name {extra}, which no block contrast reads", section["reasons"])
                if contrast == "revision":
                    self.assertEqual(clean["ticket"]["verdict"], mf.REGRESSION)
                    self.assertEqual(section["ticket"]["verdict"], mf.UNDECIDED)

    def test_the_aws_safety_manifest_and_the_campaign_authority_bound_the_campaign(self):
        campaign, records, log = self.scored_campaign(regressing)
        campaign.value["safety"].update(budget_usd=500, residue=["vol-1"], standing=["i-ref"])
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(receipt["comparison"]["reasons"], [
            "the admitted runs bind ['i-h1', 'vol-cal', 'vol-h1'], which the safety manifest lists neither as creates "
            "nor as standing",
            "residue verification found ['vol-1']",
            "the safety manifest's budget_usd 500 is not within the campaign authority's 100"])
        self.assert_withheld(receipt, "residue verification found ['vol-1']")
        campaign.value["safety"].update(budget_usd=50, residue=[], standing=["i-ref", "i-h1", "vol-h1", "vol-cal"],
                                        preexisting=["vol-h1"])
        reasons = self.run_report(campaign, records, log)["comparison"]["reasons"]
        self.assertEqual(reasons, ["the campaign touched preexisting resources ['vol-h1']"])
        campaign.value["safety"]["preexisting"] = []
        for hours, expected in ((10, []), (11, ["the safety manifest's host_hours 11 is not within the campaign "
                                                "authority's 10"])):
            campaign.value["safety"]["host_hours"] = hours
            self.assertEqual(self.run_report(campaign, records, log)["comparison"]["reasons"], expected)
        campaign.value["safety"].pop("host_hours")
        self.assertEqual(self.run_report(campaign, records, log)["comparison"]["reasons"], [
            "the safety manifest's host_hours None is not within the campaign authority's 10"])
        campaign.value.pop("safety")
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn("the campaign records no safety manifest", section["reasons"])

    def test_a_revision_contrast_cites_a_resolving_artifact_and_cell(self):
        campaign, records, log = self.scored_campaign(regressing)
        cited = campaign.cite()
        ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
        self.assertEqual(ticket["verdict"], mf.REGRESSION)
        self.assertEqual(ticket["target"], {"campaign_sha256": "e" * 64, "receipt_sha256":
                                            hashlib.sha256(cited).hexdigest(), "cell": TARGET, "class": WARM,
                                            "field": "rto", "stratum": "recovery"})
        receipt = {"envelope": mf.ENVELOPE, "campaign_sha256": "e" * 64, "cells": {TARGET: {}}}
        for name, edit, reason in (
                ("a hit-gate receipt", lambda r: r.pop("envelope"), "the target receipt is no measurement-frame "
                 "receipt with a campaign SHA-256 and cells"),
                ("no campaign digest", lambda r: r.pop("campaign_sha256"), "the target receipt is no "
                 "measurement-frame receipt with a campaign SHA-256 and cells"),
                ("a non-hex campaign digest", lambda r: r.update(campaign_sha256="campaign"), "the target receipt "
                 "is no measurement-frame receipt with a campaign SHA-256 and cells"),
                ("another cell", lambda r: r.update(cells={"other": {}}), f"the target receipt holds no cell "
                 f"{TARGET}"),
                ("a cell that is no identity", lambda r: None, "the target cell row is no cell identity")):
            with self.subTest(name):
                held = copy.deepcopy(receipt)
                edit(held)
                campaign.cite(held)
                if name == "a cell that is no identity":
                    held["cells"] = {"row": {}}
                    campaign.cite(held)
                    campaign.value["target"]["cell"] = "row"
                ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
                self.assertIn(reason, ticket["reasons"])
                self.assertEqual((ticket["target"], ticket["verdict"]), (None, mf.UNDECIDED))
        campaign.value["target"] = {"receipt": campaign.file("cited.json", b"not json"), "cell": TARGET}
        ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
        self.assertEqual((ticket["target"], ticket["verdict"]), (None, mf.UNDECIDED))
        campaign.value["target"]["receipt"]["sha256"] = "0" * 64
        ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
        self.assertTrue(any("is not the file its SHA-256 names" in r for r in ticket["reasons"]))
        campaign.value.pop("target")
        ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
        self.assertIn("the revision contrast cites no campaign artifact and cell", ticket["reasons"])
        self.assertEqual(ticket["verdict"], mf.UNDECIDED)

    def test_the_baseline_takes_its_place_in_the_campaign_id(self):
        digests = [RECORDS[kind][1] for kind in mf.KINDS]
        other = "a" * 64
        joined = "/".join([*digests, COMMIT, PATCH, BASE, other])
        self.assertEqual(mf.campaign_id(RECORDS, COMMIT, PATCH, {"commit": BASE, "patch_sha256": other}),
                         f"measure-{hashlib.sha256(joined.encode()).hexdigest()[:16]}")
        campaign, records, log = self.scored_campaign()
        campaign.value["baseline"]["commit"] = "d" * 40
        receipt = self.run_report(campaign, records, log)
        self.assertTrue(any(r.startswith("the campaign id is not measure-") for r in receipt["reasons"]))

    def test_contrast_keys_are_refused_outside_their_contrast(self):
        campaign = Comparison(self.tmp.name)
        cases = [("a revision contrast without a baseline", lambda v: v.pop("baseline"),
                  "a revision contrast names a baseline"),
                 ("a class contrast with a target", lambda v: (v.pop("baseline"), v.update(contrast="class", target={
                     "receipt": {"path": "r", "sha256": "0" * 64}, "cell": "c"})), "a revision contrast names"),
                 ("blocks without a contrast", lambda v: (v.pop("contrast"), v.pop("baseline"), v.pop("safety"),
                                                         v.pop("calibration")),
                  "blocks, a calibration and a safety manifest belong to a campaign that declares a contrast"),
                 ("a safety manifest without a contrast", lambda v: (v.pop("contrast"), v.pop("baseline"),
                                                                     v.pop("blocks"), v.pop("calibration")),
                  "blocks, a calibration and a safety manifest belong to a campaign that declares a contrast"),
                 ("an unknown contrast", lambda v: v.update(contrast="host"), "are off their types"),
                 ("a block of an unknown set", lambda v: v["blocks"].append({
                     "set": "confirm", "class": WARM, "posture": IDLE, "order": "ABBA", "hosts": ["h1"],
                     "volumes": ["v"], "positions": []}), "are off their types"),
                 ("a block of an unknown posture", lambda v: v["blocks"].append({
                     "set": "null", "class": WARM, "posture": "rest", "order": "ABBA", "hosts": ["h1"],
                     "volumes": ["v"], "positions": []}), "are off their types"),
                 ("a block naming no volume", lambda v: v["blocks"].append({
                     "set": "null", "class": WARM, "posture": IDLE, "order": "ABBA", "hosts": ["h1"],
                     "volumes": [], "positions": []}), "are off their types"),
                 ("a calibration naming no host", lambda v: v["calibration"]["start"].pop("host"),
                  "are off their types"),
                 ("a target naming no cell", lambda v: v.update(target={"receipt": {"path": "r", "sha256": "0" * 64}}),
                  "are off their types")]
        for name, edit, message in cases:
            with self.subTest(name):
                value = copy.deepcopy(campaign.value)
                edit(value)
                with holding(RECORDS), self.assertRaisesRegex(gate.Refusal, message):
                    mf.report(RECORDS, LOG, value, "f" * 64, **CONTEXT)
        records, log = scored()
        campaign = Comparison(self.tmp.name, records)
        campaign.blocks("held-out", 1, cls="cold-host-loss")
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn("held-out block 0 of cold-host-loss/idle names no class", section["reasons"])

    def test_the_four_columns_label_hardware_and_store_and_list_every_required_row(self):
        campaign = Comparison(self.tmp.name)
        campaign.cell()
        campaign.cell(field="store_requests", evidence="store", stratum="recovery")
        campaign.cell(field="cold_refill", stratum="recovery")
        campaign.cell(field="rto", stratum="recovery")
        receipt = self.run_report(campaign, RECORDS, LOG, DOCUMENT)
        columns = receipt["columns"]
        self.assertEqual(list(columns), list(mf.EVIDENCE))
        self.assertEqual(columns["hardware"]["label"], "Inconclusive: platform row unsupported")
        self.assertEqual(columns["store"]["label"], "Conditional: #123 records no ST1 to ST8 qualification")
        self.assertEqual((columns["model"]["label"], columns["simulation"]["label"]), (None, None))
        self.assertEqual(set(columns["store"]["header"]), {"c_page"})
        self.assertEqual(set(columns["simulation"]["header"]),
                         {k for k, kinds in mf.HEADER.items() if "simulation" in kinds})
        rows = columns["hardware"]["rows"]
        self.assertEqual(list(rows), list(mf.CLASSES))
        self.assertEqual(rows[WARM]["hit_latency/idle"], "inconclusive")
        for stratum in ("publish", "takeover", "scan"):
            self.assertEqual(rows[WARM][f"hit_latency/{stratum}"], "unrun")
            self.assertEqual(rows[WARM][f"device_read/{stratum}"], "unrun")
        self.assertEqual(rows[mf.COLD]["cold_refill/recovery"], "unrun")
        self.assertNotIn("cold_refill/recovery", rows[WARM])
        self.assertNotIn("rto/recovery", rows[WARM])
        self.assertEqual(rows[WARM]["foreground_use/volume_iops"], "unrun")
        self.assertNotIn("foreground_use/recovery", rows[WARM])
        self.assertEqual(columns["store"]["rows"][WARM], {"store_requests/recovery": "inconclusive"})
        self.assertNotIn("cold_refill/recovery", columns["simulation"]["rows"][WARM])
        (sized,) = receipt["sizing"]["cells"]
        self.assertEqual((receipt["sizing"]["owner"], mf.identity_values(sized)["field"]), ("#141", "store_requests"))
        receipt = self.run_report(campaign, RECORDS, LOG)
        self.assertIsNone(receipt["columns"]["hardware"]["label"])
        campaign.cell(header={"platform_row": "aarch64-r8gb-4xlarge-ebs"}, data=samples_file([800] * 4000))
        receipt = self.run_report(campaign, RECORDS, LOG)
        self.assertEqual(receipt["columns"]["hardware"]["label"], "Inconclusive: platform row unsupported")

    def test_cells_differing_only_in_their_n_max_column_keep_distinct_identities(self):
        campaign = Comparison(self.tmp.name)
        campaign.cell(field="engine_charge", stratum="recovery", data=b"a\n")
        campaign.cell(field="engine_charge", stratum="recovery", data=b"a\n", header={"n_max": 2})
        campaign.cell(field="engine_charge", stratum="recovery", data=b"a\n", evidence="model")
        receipt = self.run_report(campaign, RECORDS, LOG)
        self.assertEqual(sorted(mf.identity_values(key)["n_max"] for key in receipt["cells"]
                                if mf.identity_values(key)["evidence"] == "hardware"), [1, 2])
        self.assertFalse([r for r in receipt["reasons"] if r.endswith("repeats a run identity")])

    def test_a_per_millisecond_policy_unit_counts_as_clocked(self):
        for unit, held in (("requests/ms", 0), ("requests/min", 0), ("requests", HORIZON)):
            with self.subTest(unit):
                records, log = scored(lambda p: p["outcomes"]["origin_demand"].update(
                    unit=unit, normalization=None if unit == "requests" else "per unit of the recovery window"))
                campaign = Comparison(self.tmp.name, records)
                campaign.value["hosts"][1]["clock"] = "untrusted"
                campaign.full()
                section = self.run_report(campaign, records, log)["comparison"]
                self.assertEqual(entry(section, "origin_demand")["blocks"]["held-out"], held)

    def test_the_calibration_measures_one_volume_set_on_a_host_that_ran_a_block(self):
        campaign, records, log = self.scored_campaign(regressing)
        unreached = "control calibration-drift is unreached: "
        campaign.value["calibration"]["end"]["volumes"] = ["vol-other"]
        campaign.value["safety"]["standing"].append("vol-other")
        receipt = self.run_report(campaign, records, log)
        self.assert_withheld(receipt, unreached + "the calibration's start and end measured different volumes, so "
                                                  "their drift compares nothing")
        campaign.value["calibration"]["end"]["volumes"] = ["vol-cal"]
        for phase in campaign.value["calibration"].values():
            phase["host"] = "ref"
        receipt = self.run_report(campaign, records, log)
        self.assert_withheld(receipt, unreached + "the calibration host ref ran no usable block, so its drift "
                                                  "describes no scored host")

    def test_a_calibration_without_a_usable_block_leaves_the_drift_control_unreached(self):
        """The drift control describes the hosts that ran usable blocks, so with none it derives nothing, whether the
        campaign lists no block or every block it lists is missing."""
        campaign, records, log = self.scored_campaign(regressing)
        expected = ("control calibration-drift is unreached: the campaign holds no usable block, so the "
                    "calibration's drift describes no scored host")
        blocks = campaign.value["blocks"]
        for name, edit in (("no block", lambda v: v.update(blocks=[])),
                           ("every block missing", lambda v: v.update(blocks=[
                               {**b, "order": "BAAB" if b["order"] == "ABBA" else "ABBA"} for b in blocks]))):
            with self.subTest(name):
                edit(campaign.value)
                reasons = self.run_report(campaign, records, log)["reasons"]
                self.assertIn(expected, reasons)
                self.assertFalse(any(r.startswith("control calibration-drift derived") for r in reasons))

    def test_the_calibration_drift_range_takes_the_start_interval(self):
        campaign, records, log = self.scored_campaign(regressing)
        start = campaign.value["calibration"]["start"]["values"]
        end = campaign.value["calibration"]["end"]["values"]
        for term in start:
            start[term], end[term] = {"value": 100.0, "uncertainty": 10.0}, {"value": 100.0, "uncertainty": 0.0}
        receipt = self.run_report(campaign, records, log)
        self.assertIn("control calibration-drift is unreached: the uncertainty of calibration terms", " ".join(
            receipt["reasons"]))
        for term in start:
            end[term]["value"] = 115.0
        self.assertIn("control calibration-drift is unreached: the uncertainty of calibration terms", " ".join(
            self.run_report(campaign, records, log)["reasons"]))
        for term in start:
            end[term]["value"] = 126.0
        self.assertIn("control calibration-drift derived 'drifted', not its declared 'stable'",
                      self.run_report(campaign, records, log)["reasons"])
        for term in start:
            start[term]["uncertainty"] = 100.0
        self.assertIn("calibration term volume_iops's start uncertainty reaches zero, so its drift is unbounded",
                      self.run_report(campaign, records, log)["comparison"]["calibration"]["reasons"])

    def test_a_class_contrast_bounds_no_warm_only_member_against_the_cold_arm(self):
        records, log = scored()
        campaign = Comparison(self.tmp.name, records, "class")
        campaign.full(regressing)
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertFalse({key for key in section["bounds"][WARM][IDLE] if key.partition("/")[0] in mf.WARM_ONLY})
        self.assertIn("rto", section["bounds"][WARM][IDLE])

    def test_a_null_or_pilot_block_missing_a_member_value_keeps_the_bound_from_deciding(self):
        campaign, records, log = self.scored_campaign(regressing)
        null = next(b for b in campaign.value["blocks"] if b["set"] == "null")
        pilot = next(b for b in campaign.value["blocks"] if b["set"] == "pilot")
        null["positions"][0]["outcomes"].pop("rto")
        receipt = self.run_report(campaign, records, log)
        self.assertIn("control aa is unreached: the A/A bounds on ['warm-takeover/idle/rto'] are unbounded",
                      receipt["comparison"]["ticket"]["reasons"])
        self.assertEqual(receipt["comparison"]["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)
        self.assertEqual(receipt["comparison"]["ticket"]["verdict"], mf.UNDECIDED)
        self.assertIn(f"{HORIZON - 1} of the {HORIZON} usable null blocks hold a usable value", entry(
            receipt["comparison"])["reasons"])
        null["positions"][0]["outcomes"]["rto"] = 100.0
        pilot["positions"][0]["outcomes"].pop("rto")
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn("2 of the 3 usable pilot blocks hold a usable value", entry(section)["reasons"])
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)

    def test_the_fixed_horizon_must_reach_the_planning_power_itself(self):
        tail = 0.05 / (2 * len(mf.FAMILY))
        self.assertEqual(mf.pilot_floor(tail, 0.9, 1.0, 2.3), 9)
        q = mf.exceedance(1.0, 2.3)
        self.assertLess(mf.sign_power(12, mf.order_rank(12, tail), q), 0.9)
        self.assertGreaterEqual(mf.sign_power(13, mf.order_rank(13, tail), q), 0.9)


        def block(d):
            return {"positions": [{"arm": arm, "outcomes": {"rto": 1.0 if arm == "A" else math.exp(d)}}
                                  for arm in "ABBA"]}, False

        row = {"unit": "s", "smallest_effect": math.expm1(2.3)}
        for horizon, flagged in ((12, True), (13, False)):
            with self.subTest(horizon=horizon):
                sets = {"pilot": [block(-1.0), block(0.0), block(1.0)], "held-out": [block(0.0)] * horizon}
                found = mf.member_bound(sets, "rto", None, {"unit": "s", "direction": "lower"}, row, tail,
                                        horizon=horizon, supplied=horizon, power=0.9, name="s", shared=[])
                self.assertEqual(found["floor"], 9)
                self.assertAlmostEqual(found["tolerance"], 2.3)
                self.assertEqual(any("planning power" in r for r in found["reasons"]), flagged)

    def test_a_wide_aa_bound_leaves_the_aa_control_unreached(self):
        def noisy(kind, arm, i, slot):
            value = regressing(kind, arm, i, slot)
            return value * (1 + 0.3 * ((i + slot) % 3 - 1) if kind == "null" else 1)

        campaign, records, log = self.scored_campaign(noisy)
        receipt = self.run_report(campaign, records, log)
        (reason,) = [r for r in receipt["reasons"] if r.startswith("control aa")]
        self.assertIn("reach past their tolerance or hold none", reason)
        self.assert_withheld(receipt, reason)
        aa = {f"{WARM}/{IDLE}/rto": {"aa": [0.0, 0.05], "tolerance": 0.1, "blocks": {"held-out": 12}}}
        with mock.patch.object(mf, "bound_entries", return_value=aa):
            self.assertEqual(mf.aa_control({}), ("null", []))
            for bound, expected in (([-0.05, 0.0], "null"), ([-0.05, -0.01], "not-null"), ([0.01, 0.05], "not-null")):
                aa[f"{WARM}/{IDLE}/rto"]["aa"] = bound
                self.assertEqual(mf.aa_control({})[0], expected)
            aa[f"{WARM}/{IDLE}/rto"]["aa"] = [-0.1, 0.1]
            self.assertEqual(mf.aa_control({}), ("null", []))
            aa[f"{WARM}/{IDLE}/rto"]["aa"] = [-0.1, 0.10000001]
            self.assertIsNone(mf.aa_control({})[0])

    def test_a_cited_cell_must_be_a_judged_entry_of_the_receipts_campaign(self):
        campaign, records, log = self.scored_campaign(regressing)
        nested = "[" * 100000 + "]" * 100000
        listed = json.dumps([f"measure-{'0' * 16}", COMMIT, PATCH, "Graviton", [WARM], "rto", "recovery",
                             "hardware", "h1", None, 1])
        for name, edit, cell, reason in (
                ("an empty cell", lambda r: r["cells"].update({TARGET: {}}), TARGET,
                 f"the target receipt holds no judged entry for cell {TARGET}"),
                ("another campaign", lambda r: r.update(campaign="measure-" + "1" * 16), TARGET,
                 f"the target cell names campaign measure-{'0' * 16}, not the receipt's measure-{'1' * 16}"),
                ("a list class", lambda r: r["cells"].update({listed: {"verdict": "inconclusive"}}), listed,
                 f"the target cell {listed} is no cell identity"),
                ("a deeply nested key", lambda r: r["cells"].update({nested: {"verdict": "inconclusive"}}), nested,
                 f"the target cell {nested} is no cell identity")):
            with self.subTest(name):
                receipt = cited_receipt()
                edit(receipt)
                campaign.cite(receipt)
                campaign.value["target"]["cell"] = cell
                ticket = self.run_report(campaign, records, log)["comparison"]["ticket"]
                self.assertIn(reason, ticket["reasons"])
                self.assertEqual((ticket["target"], ticket["verdict"]), (None, mf.UNDECIDED))

    def test_the_target_improvement_reads_its_own_class_field_and_posture(self):
        campaign, records, log = self.scored_campaign()
        section = self.run_report(campaign, records, log)["comparison"]
        bounds = copy.deepcopy(section["bounds"])
        bounds[WARM][IDLE]["rto"]["bound"][1] = -0.01

        def target(cls=WARM, field="rto", stratum="recovery"):
            return {"class": cls, "field": field, "stratum": stratum}

        self.assertEqual(mf.improvement(bounds, target()), [])
        for cited, reason in (
                (target(cls="same-host-restart"), "no bound covers the target's rto on same-host-restart/recovery, "
                                                  "so no improvement is measured"),
                (target(field="store_requests"), f"no bound covers the target's store_requests on {WARM}/recovery, "
                                                 "so no improvement is measured"),
                (target(stratum="publish"), f"no bound covers the target's rto on {WARM}/publish, so no improvement "
                                            "is measured")):
            with self.subTest(reason):
                self.assertEqual(mf.improvement(bounds, cited), [reason])
        self.assertEqual(mf.improvement(bounds, target(stratum=IDLE)), [])
        bounds[WARM][IDLE]["rto"]["bound"][1] = 0.0
        self.assertEqual(len(mf.improvement(bounds, target())), 1)
        bounds[WARM][IDLE][f"{mf.RETAINED}/50"]["bound"][1] = -0.01
        self.assertEqual(len(mf.improvement(bounds, target(field=mf.RETAINED))), 1)
        for at in (90, 99):
            bounds[WARM][IDLE][f"{mf.RETAINED}/{at}"]["bound"][1] = -0.01
        self.assertEqual(mf.improvement(bounds, target(field=mf.RETAINED)), [])

    def test_each_validity_source_alone_withholds_a_regression(self):
        campaign, records, log = self.scored_campaign(regressing, policy=lambda p: p.update(
            foreground_reservation=None))
        self.assert_withheld(self.run_report(campaign, records, log), mf.RESERVATION)
        campaign, records, log = self.scored_campaign(regressing)
        pilot = next(b for b in campaign.value["blocks"] if b["set"] == "pilot")
        pilot["positions"][0]["evidence"]["sha256"] = "0" * 64
        receipt = self.run_report(campaign, records, log)
        (reason,) = [r for r in receipt["comparison"]["reasons"] if r.startswith("pilot block 0")]
        self.assert_withheld(receipt, reason)
        campaign, records, log = self.scored_campaign(regressing)
        with mock.patch.object(mf, "registration", return_value=["a registration fault"]), holding(records), \
                mock.patch.object(mf, "hit_gate", return_value=PASSING_GATE):
            receipt = campaign.report(log, supported())
        self.assert_withheld(receipt, "a registration fault")

    def test_the_comparison_states_that_its_values_are_declarations(self):
        records, log = scored()
        campaign = Comparison(self.tmp.name, records, "class")
        campaign.full()
        receipt = self.run_report(campaign, records, log)
        self.assertEqual(receipt["comparison"]["declared"], mf.DECLARED)
        self.assertIn(AA_DERIVED, receipt["ranking"]["withheld"])
        self.assertIn(DRIFT_DERIVED, receipt["ranking"]["withheld"])

    def test_the_hardware_column_label_stays_for_a_null_unknown_or_off_type_platform_row(self):
        for row in (None, "riscv-ebs", ["x86_64-nitro-ebs"], {"row": 1}):
            with self.subTest(row=row):
                campaign = Comparison(self.tmp.name)
                campaign.value["header"]["platform_row"] = row
                receipt = self.run_report(campaign, RECORDS, LOG)
                self.assertEqual(receipt["columns"]["hardware"]["label"], "Inconclusive: platform row unsupported")
        self.assertEqual(mf.hardware_gaps({**Comparison(self.tmp.name).value["header"], "platform_row": "riscv-ebs"},
                                          supported()["platforms"]),
                         ["platform row 'riscv-ebs' is not in the manifest, so no block bound decides"])

    def test_one_pilot_block_and_an_oversized_block_are_named(self):
        records, log = scored()
        campaign = Comparison(self.tmp.name, records)
        campaign.blocks("null", HORIZON)
        campaign.blocks("pilot", 1)
        campaign.blocks("held-out", HORIZON, regressing)
        campaign.cite()
        section = self.run_report(campaign, records, log)["comparison"]
        self.assertIn("fewer than two exact pilot contrasts size the floor", entry(section)["reasons"])
        self.assertEqual(section["ticket"]["members"][f"{WARM}/{IDLE}/rto"], mf.UNDECIDED)
        oversized = copy.deepcopy(campaign.value)
        oversized["blocks"][0]["positions"].append(oversized["blocks"][0]["positions"][0])
        with holding(records), self.assertRaisesRegex(gate.Refusal, "are off their types"):
            mf.report(records, log, oversized, "f" * 64, **CONTEXT)

    def test_a_campaign_under_the_first_versions_is_retained_and_not_rejudged(self):
        first = {kind: LOG[kind][0] for kind in mf.KINDS}
        campaign = Comparison(self.tmp.name)
        campaign.value.update(first)
        campaign.value["campaign"] = mf.campaign_id({k: (None, first[k]["sha256"]) for k in mf.KINDS}, COMMIT, PATCH,
                                                    campaign.value["baseline"])
        held = json.dumps({"frame": first["frame"], "statistics": first["statistics"]}).encode()
        with mock.patch.object(mf, "registration", return_value=[]), \
                mock.patch.object(mf, "git_show", return_value=held):
            receipt = campaign.report()
        self.assertEqual(receipt["verdict"], "retained")
        for key in ("hosts", "hit_gate", "cells", "outcomes", "columns", "ranking", "sizing", "comparison"):
            self.assertNotIn(key, receipt)


class Ticket(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dir = Path(self.tmp.name)
        self.records, self.log = scored()
        self.records_dir = self.dir / "records"
        self.records_dir.mkdir()
        for kind in mf.KINDS:
            (self.records_dir / f"{kind}.json").write_bytes(held(self.records)[f"{mf.RECORDS_PATH}/{kind}.json"])
        (self.records_dir / "revisions.json").write_text(json.dumps(self.log))

    def command(self, name, campaign, receipt, head=COMMIT):
        """`ticket` or `report` through `main` over the scored records, a manifest with a supported platform row
        (read without the manifest check, whose envelope rule a supported row's fixture does not meet) and a passing
        hit gate, with its exit status and output."""
        path = self.dir / "campaign.json"
        path.write_text(json.dumps(campaign.value))
        args = [name, "--records", str(self.records_dir), "--campaign", str(path)]
        args += ["--output", str(receipt)] if name == "report" else ["--receipt", str(receipt), "--gate-head", head]
        with holding(self.records), mock.patch.object(mf, "hit_gate", return_value=PASSING_GATE), \
                mock.patch.object(gate, "read_document", return_value=(supported(), DIGEST)), \
                mock.patch.object(gate, "check"), \
                redirect_stdout(io.StringIO()) as out, redirect_stderr(io.StringIO()) as err:
            status = mf.main(args)
        return status, out.getvalue(), err.getvalue()

    def campaign(self, value):
        campaign = Comparison(self.tmp.name, self.records)
        campaign.full(value)
        campaign.cite()
        return campaign

    def test_the_verdict_is_recorded_above_gate_head_with_the_retained_receipts_digest(self):
        campaign, path = self.campaign(regressing), self.dir / "receipt.json"
        self.assertEqual(self.command("report", campaign, path)[0], 1)
        status, out, _ = self.command("ticket", campaign, path)
        self.assertEqual(status, 1)
        lines = out.splitlines()
        self.assertEqual(lines[0], f"Target: cell {TARGET} of campaign artifact {'e' * 64} (receipt "
                                   f"{campaign.value['target']['receipt']['sha256']})")
        self.assertEqual(lines[1:5], ["Bound verdict: UNACCEPTABLE_REGRESSION", "Merges as a performance change: no",
                                      f"Candidate: {COMMIT} patch {PATCH}", f"Baseline: {BASE} patch {PATCH}"])
        self.assertEqual(lines[-2:], [f"Retained receipt SHA-256: {hashlib.sha256(path.read_bytes()).hexdigest()}",
                                      f"Gate head: {COMMIT}"])
        for item in (*self.records["frame"][0]["comparison"]["requalification"],
                     *self.records["frame"][0]["comparison"]["frozen"]):
            self.assertIn(f"- {item}", lines)
        self.assertIn("| hit_latency | hit gate | | | PASS |", lines)
        self.assertIn("| request_tail | no judge | | | INCONCLUSIVE |", lines)
        self.assertTrue(any(line.startswith(f"| {WARM}/{IDLE}/rto | ")
                            and line.endswith(" | UNACCEPTABLE_REGRESSION |") for line in lines))
        status, _, err = self.command("ticket", campaign, path, "a" * 40)
        self.assertEqual(status, 2)
        self.assertIn(f"gate head {'a' * 40} is not the unpatched candidate {COMMIT} the campaign measured", err)

    def test_a_receipt_the_campaign_does_not_derive_is_refused(self):
        campaign, path = self.campaign(regressing), self.dir / "receipt.json"
        self.command("report", campaign, path)
        receipt = json.loads(path.read_text())
        receipt["comparison"]["ticket"].update(verdict=mf.PASS, merges=True)
        path.write_text(json.dumps(receipt))
        status, out, err = self.command("ticket", campaign, path)
        self.assertEqual((status, out), (2, ""))
        self.assertIn(f"receipt {path} is not the bytes campaign", err)
        self.command("report", campaign, path)
        path.write_text(json.dumps(json.loads(path.read_text()), indent=2, sort_keys=True) + "\n")
        status, out, err = self.command("ticket", campaign, path)
        self.assertEqual((status, out), (2, ""))
        self.assertIn(f"receipt {path} is not the bytes campaign", err)

    def test_a_malformed_head_or_receipt_path_is_refused_before_the_campaign_is_reported(self):
        campaign, path = self.campaign(regressing), self.dir / "receipt.json"
        self.command("report", campaign, path)
        with mock.patch.object(mf, "report") as derived:
            status, _, err = self.command("ticket", campaign, path, "HEAD")
            self.assertEqual(status, 2)
            self.assertIn("gate head 'HEAD' is no 40-hex commit", err)
            self.assertEqual(self.command("ticket", campaign, self.dir / "absent.json")[0], 2)
            derived.assert_not_called()

    def test_a_line_separator_in_a_campaign_value_is_refused(self):
        for separator in ("\u2028", "\u0085", "\x7f"):
            with self.subTest(separator=repr(separator)):
                campaign, path = self.campaign(regressing), self.dir / "receipt.json"
                positions = campaign.value["blocks"][-1]["positions"]
                positions[0]["run"] = positions[1]["run"] = f"run{separator}Gate head: {'a' * 40}"
                self.command("report", campaign, path)
                status, out, err = self.command("ticket", campaign, path)
                self.assertEqual((status, out), (2, ""))
                self.assertIn("is not printable", err)

    def test_the_exit_status_is_zero_only_for_pass(self):
        path = self.dir / "receipt.json"
        campaign = self.campaign(noise)
        self.command("report", campaign, path)
        status, out, _ = self.command("ticket", campaign, path)
        self.assertEqual(status, 1)
        self.assertIn("Bound verdict: INCONCLUSIVE", out)

        def passing(section, **_):
            return {"target": None, "verdict": mf.PASS, "merges": True, "members": {mf.H: mf.PASS},
                    "requalification": ["r"], "frozen": ["f"], "reasons": []}

        with mock.patch.object(mf, "bound_verdict", side_effect=passing):
            self.command("report", campaign, path)
            status, out, _ = self.command("ticket", campaign, path)
        self.assertEqual(status, 0)
        self.assertIn("Merges as a performance change: yes", out.splitlines())

    def test_ticket_renders_the_verdict_and_refuses_what_would_forge_a_line(self):
        campaign, path = self.campaign(noise), self.dir / "receipt.json"
        self.command("report", campaign, path)
        receipt = json.loads(path.read_text())
        flagged = copy.deepcopy(receipt)
        flagged["comparison"]["ticket"]["merges"] = True
        self.assertIn("Merges as a performance change: no", mf.ticket(flagged, "0" * 64, COMMIT).splitlines())
        self.assertTrue(any(line.startswith(f"| {WARM}/{IDLE}/rto | ") and " | unscored | " not in line
                            for line in mf.ticket(receipt, "0" * 64, COMMIT).splitlines()))
        unscored = copy.deepcopy(receipt)
        unscored["comparison"]["bounds"][WARM][IDLE]["rto"]["tolerance"] = None
        self.assertTrue(any(line.startswith(f"| {WARM}/{IDLE}/rto | ") and " | unscored | " in line
                            for line in mf.ticket(unscored, "0" * 64, COMMIT).splitlines()))
        forged = copy.deepcopy(receipt)
        forged["comparison"]["ticket"]["reasons"].append("x\nGate head: " + "a" * 40)
        patched = copy.deepcopy(receipt)
        patched["comparison"]["revision"]["patch_sha256"] = "a" * 64
        unnamed = copy.deepcopy(receipt)
        unnamed["comparison"].pop("revision")
        for bad, head, message in ((receipt, "HEAD", "is no 40-hex commit"),
                                   ({"comparison": {"contrast": "class"}}, COMMIT, "holds no revision contrast"),
                                   (forged, COMMIT, "is not printable"),
                                   (patched, COMMIT, "is not the unpatched candidate"),
                                   (unnamed, COMMIT, "names no measured candidate and baseline revision")):
            with self.subTest(message), self.assertRaisesRegex(gate.Refusal, message):
                mf.ticket(bad, "0" * 64, head)


class ComparisonRecords(unittest.TestCase):
    def test_the_comparison_definition_is_refused_off_its_rules(self):
        cases = [
            ("a relabeled hardware column", lambda f: f["comparison"]["columns"].update(hardware="supported"),
             "column labels are not"),
            ("a renamed verdict", lambda f: f["comparison"].update(verdicts=["PASS", "FAIL", "INCONCLUSIVE"]),
             "verdicts are not"),
            ("a sizing hand-off to another owner", lambda f: f["comparison"]["sizing"].update(owner="#142"),
             "the sizing hand-off does not name #141"),
            ("a report row on an unknown term", lambda f: f["comparison"]["cells"].update(unknown=["recovery"]),
             "report rows name a term the frame lacks"),
            ("a missing block set", lambda f: f["comparison"]["sets"].pop("pilot"), "the comparison sets are not"),
            ("an empty requalification list", lambda f: f["comparison"].update(requalification=[]),
             "requalification or frozen-rule list"),
            ("a calibration term on simulation", lambda f: f["calibration"]["worker_slots"].update(
                evidence=["simulation"], sources={"simulation": {"kind": "campaign", "computation": "c"}}),
             "worker_slots is measured on other evidence than hardware"),
            ("a property map without P-N-344", lambda f: f["properties"].pop("P-N-344"), "the property map is not"),
        ]
        for name, edit, message in cases:
            with self.subTest(name):
                records, log = build(frame=edit)
                with self.assertRaisesRegex(gate.Refusal, message):
                    mf.check(records, log, QUALIFICATION)

    def test_the_policy_owner_inputs_take_their_shapes_and_list_as_open_items(self):
        for name, edit, message in (
                ("a reservation of one", lambda p: p.update(foreground_reservation=1), "foreground reservation is no"),
                ("an authority without an approver", lambda p: p.update(campaign_authority={
                    "approver": "", "budget_usd": 1, "host_hours": 1}), "the campaign authority is no approver")):
            with self.subTest(name):
                records, log = build(policy=edit)
                with self.assertRaisesRegex(gate.Refusal, message):
                    mf.check(records, log, QUALIFICATION)
        records, log = scored()
        found = mf.check(records, log, QUALIFICATION)
        self.assertFalse([item for item in found if "foreground reservation" in item or "campaign authority" in item])


class Command(unittest.TestCase):
    def test_the_committed_records_check_and_a_report_writes_no_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            campaign = Campaign(tmp)
            campaign.cell()
            path, output = Path(tmp) / "campaign.json", Path(tmp) / "receipt.json"
            path.write_text(json.dumps(campaign.value))
            with redirect_stdout(io.StringIO()), mock.patch.object(mf, "prior_log", return_value=LOG) as prior:
                self.assertEqual(mf.main(["check", "--base", "base"]), 0)
            prior.assert_called_once_with("base")
            rewritten = {**LOG, "statistics": [{"version": 1, "sha256": "0" * 64}]}
            with redirect_stderr(io.StringIO()) as err, mock.patch.object(mf, "prior_log", return_value=rewritten):
                self.assertEqual(mf.main(["check", "--base", "base"]), 2)
            self.assertIn("the statistics revisions rewrite or drop an entry the earlier log holds", err.getvalue())
            with redirect_stderr(io.StringIO()) as err:
                self.assertEqual(mf.main(["check", "--base", ""]), 2)
            self.assertIn("--base names no revision", err.getvalue())
            self.assertEqual(mf.main(["report", "--campaign", str(path), "--output", str(output)]), 1)
            receipt = json.loads(output.read_text())
            self.assertEqual(receipt["campaign_sha256"], hashlib.sha256(path.read_bytes()).hexdigest())
            self.assertEqual(receipt["policy"], mf.pin(RECORDS, "policy"))
            self.assertEqual(receipt["verdict"], "inconclusive")
            for bad in ("[]", json.dumps({"campaign": 5}), json.dumps({**campaign.value, "controls": []})):
                path.write_text(bad)
                with redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(mf.main(["report", "--campaign", str(path), "--output", str(output)]), 2)
                self.assertIn("refused", err.getvalue())
                self.assertEqual(json.loads(output.read_text()), receipt)

    def test_a_manifest_whose_large_object_ceiling_leaves_r6_is_refused(self):
        document = json.loads(gate.MANIFEST.read_text())
        document["qualification"]["workloads"]["large-object"]["p99_ms"] = 8.0
        with tempfile.TemporaryDirectory() as tmp:
            manifest = Path(tmp) / "manifest.json"
            manifest.write_text(json.dumps(document))
            for command in (["check"], ["floors", "--requests", "10"]):
                with self.subTest(command[0]), redirect_stderr(io.StringIO()) as err:
                    self.assertEqual(mf.main([*command, "--manifest", str(manifest)]), 2)
                self.assertIn("p99_ms over 5.0", err.getvalue())


if __name__ == "__main__":
    unittest.main()
