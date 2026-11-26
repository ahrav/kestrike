#!/usr/bin/env python3
"""Exercise sizing-worksheet.py: the committed worksheet's checks and open items, its evaluation over a comparison
receipt that measurement-frame.py's own cell, column and calibration code builds, the per-host L_h and shared L_S of
each step, the binding row, resource and path, the elasticities against finite differences, the occupancy rows, the
unscored and conditional labels, and each refusal rule, over synthetic measured inputs."""

import copy
import hashlib
import importlib.util
import io
import json
import math
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("sizing_worksheet", ROOT / "scripts/sizing-worksheet.py")
assert SPEC is not None and SPEC.loader is not None
sw = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(sw)
mf, gate = sw.mf, sw.gate

LANE = gate.lane_module()
DOCUMENT, MANIFEST_SHA256 = gate.read_document(gate.MANIFEST, LANE)
RECORDS, _ = mf.load(mf.RECORDS)
WORKSHEET = sw.load(sw.WORKSHEET)
FRAME = RECORDS["frame"][0]
E_MAX = FRAME["envelope"]["e_max"]
OBJECTS = 1 << 22
STORE_KEYS = ("store-qualification", "store-outage", "store-restore", "store-throttle")
STORE = [WORKSHEET["assumptions"][a] for a in STORE_KEYS]
JUDGE = hashlib.sha256((ROOT / "scripts/measurement-frame.py").read_bytes()).hexdigest()

MEASURED = {"detection": 2.0, "authority": 0.5, "coverage": 1.5, "fresh_host_attachment": 40.0,
            "l_data_ratio": 1.25, "store_requests": 600.0, "checkpoint_units": 2.0, "peak_ram": 8e9,
            "activation_cpu": 10.0, "cold_refill": 900.0}
SAMPLES = 2000
CALIBRATED = {"volume_bandwidth": 1.1e9, "volume_iops": 16000.0, "host_bandwidth": 1.1e10, "host_iops": 260000.0,
              "ram_build_rate": 2e9, "worker_cpu": 0.001, "worker_slots": 8.0}
UNCERTAINTY = {name: value / 1000 for name, value in CALIBRATED.items()}
OWNER = {"shards_per_host": 4, "standbys_per_host": 4, "handoffs_per_host": 1, "enrollments_per_host": 1,
         "concurrent_recoveries_per_host": 2, "concurrent_recoveries_per_az": 50, "shards_per_az": 2000,
         "standby_cap_per_az": 2500, "live_attaches_per_volume": 3, "checkpoint_slots": 4, "delta_blocks": 262144,
         "extents_per_object": 16, "mutation_rate": 100, "foreground_link_share": 0.2, "foreground_iops_share": 0.1,
         "host_attachment_limit": 27, "host_ram_bytes": 1.28e11, "recovery_share_rate": 1e10, "recovery_helpers": 5,
         "store_request_headroom": 20000, "store_burst_window": 2.0, "concurrent_volume_losses": 10,
         "replacement_attaches_per_host": 1, "volume_create_burst": 20,
         "volume_bytes_headroom": 5e14, "volume_iops_headroom": 1e6}
HANDOFF = {"recovery_ops": 200000, "index_bytes": 6e9, "volume_create_latency": 120, "fresh_host_designation": 30,
           "recovery_ram": 2e9, "shard_ram": 1e9, "runtime_ram": 4e9, "replacement_store_requests": 900,
           "designation_store_requests": 12}
ENVELOPE = {"n_max": OBJECTS, "volume_size_bytes": 1 << 40, "iops": 16000}
READ_BYTES = (1 + math.ceil(E_MAX / 41) + OWNER["delta_blocks"]) * 4096
TAKEOVER = "standby-takeover"


def encode(document):
    return (json.dumps(document, indent=1) + "\n").encode()


def records(drift_band: "float | None" = 0.05):
    """Committed records with the statistics' drift band edited, the policy's foreground reservation declared and the
    frame envelope's N_max, volume size and IOPS filled; a None band keeps the committed value."""
    docs = {kind: copy.deepcopy(RECORDS[kind][0]) for kind in mf.KINDS}
    docs["frame"]["envelope"].update(ENVELOPE)
    if drift_band is not None:
        docs["statistics"]["drift_band"] = drift_band
    docs["policy"]["foreground_reservation"] = 0.25
    return {kind: (doc, hashlib.sha256(encode(doc)).hexdigest()) for kind, doc in docs.items()}


def worksheet(held, handoff=True, quantile: "str | None" = "p99", edit=None):
    """The committed worksheet pinned to `held`, with the owner inputs and quantiles recorded and, with `handoff`,
    each handoff input recorded as an owner input, so every hole is filled."""
    w = copy.deepcopy(WORKSHEET)
    for kind in sw.PINNED:
        w[kind] = mf.pin(held, kind)
    for name, value in OWNER.items():
        w["inputs"][name]["value"] = value
    for name, value in (HANDOFF if handoff else {}).items():
        w["inputs"][name] = {"kind": "owner", "unit": w["inputs"][name]["unit"], "owner": "test", "value": value}
    for scenario in w["scenarios"].values():
        scenario["quantile"] = quantile
    if edit:
        edit(w)
    return w


class Rig:
    """A temporary directory holding evidence files, a comparison receipt and an inputs file."""

    def __init__(self, test):
        self.dir = Path(tempfile.mkdtemp())
        test.addCleanup(shutil.rmtree, self.dir)
        self.count = 0

    def file(self, data):
        self.count += 1
        path = self.dir / f"f{self.count}"
        path.write_bytes(data)
        return {"path": str(path), "sha256": hashlib.sha256(data).hexdigest()}


def cell_key(field, cls, stratum, evidence="hardware"):
    values = {"campaign": "measure-0", "commit": "c" * 40, "patch_sha256": mf.NO_PATCH, "cpu_family": "zen4",
              "class": cls, "field": field, "stratum": stratum, "evidence": evidence, "host": "h1",
              "samples_sha256": None, "n_max": OBJECTS if evidence in mf.HEADER["n_max"] else None}
    return json.dumps([values[k] for k in mf.IDENTITY])


def receipt(rig, held, *, objects_measured=OBJECTS, drift=0.0, sizing=True, cells=None, clock="trusted",
            admitted=True, end_uncertainty=1.0, volume_size_bytes=ENVELOPE["volume_size_bytes"], edit=None):
    """A comparison receipt for `held`, its cells built by measurement-frame.py's `judge_cell`, its columns by
    `columns` and its calibration by `calibrate`. Each measured input's cell is the worksheet's field, class and
    stratum (or each `cells` spec of field, class, stratum and evidence kind), on host h1 with a hardware header
    measuring `objects_measured` objects. The end phase's uncertainties are the start's times `end_uncertainty`;
    `edit` changes the parsed document before it is written."""
    frame, policy = held["frame"][0], held["policy"][0]
    header = dict.fromkeys(mf.HEADER)
    header.update(e_max=E_MAX, n_max=OBJECTS, objects_measured=objects_measured,
                  volume_size_bytes=volume_size_bytes, iops=ENVELOPE["iops"])
    host = {"instance": "i-1", "cpu_family": "zen4", "clock": clock, "admitted": admitted, "reasons": []}
    terms = {**frame["fields"], **frame["stages"]}
    out = {}
    for spec in cells or [(i["field"], i["class"], i["stratum"]) for i in WORKSHEET["inputs"].values()
                          if i["kind"] == "measured"]:
        cell = {"class": spec[1], "field": spec[0], "stratum": spec[2], "evidence": (*spec, "hardware")[3],
                "host": "h1"}
        out[cell_key(*spec)] = mf.judge_cell(cell, term=terms[spec[0]], host=host, header=header,
                                             envelope=frame["envelope"], offered=None,
                                             platforms=DOCUMENT["platforms"], bound={}, summarize_samples=None)
    evidence = {phase: rig.file(phase.encode()) for phase in ("start", "end")}
    values = {name: {"value": v, "uncertainty": UNCERTAINTY[name]} for name, v in CALIBRATED.items()}
    drifted = {name: {"value": v["value"] * (1 + drift), "uncertainty": v["uncertainty"] * end_uncertainty}
               for name, v in values.items()}
    phases = {"start": values, "end": drifted}
    trusted = {**host, "clock": "trusted", "admitted": True}
    section, _ = mf.calibrate({phase: {"host": "h1", "volumes": ["vol-1"], "evidence": evidence[phase],
                                       "values": phases[phase]} for phase in phases},
                              frame["calibration"], held["statistics"][0]["drift_band"],
                              policy["foreground_reservation"], set(), {"h1": trusted}, {"h1"})
    document = {"envelope": mf.ENVELOPE, "records": {kind: mf.pin(held, kind) for kind in mf.KINDS}, "cells": out,
                "judge_sha256": JUDGE, "manifest_sha256": MANIFEST_SHA256, "campaign": "measure-0",
                "hosts": {"h1": host}, "reasons": [], "ranking": {"withheld": []},
                "columns": mf.columns(frame, header, out, DOCUMENT["platforms"]),
                "sizing": {"owner": "#141", "cells": [k for k in out if json.loads(k)[5] in
                                                       frame["comparison"]["sizing"]["fields"]] if sizing else []},
                "comparison": {"calibration": section}}
    if edit:
        edit(document)
    return rig.file(encode(document))


def values(rig, measured=MEASURED, statistic="p99", cells=None, samples=SAMPLES, censored=0):
    out = {}
    for name, value in measured.items():
        entry = WORKSHEET["inputs"][name]
        key = (cells or {}).get(name) or cell_key(entry["field"], entry["class"], entry["stratum"])
        out[name] = [{"statistic": statistic, "cell": key, "value": value, "samples": samples,
                      "censored": censored, "evidence": rig.file(name.encode())}]
    return out


def run(w, held, document):
    return sw.evaluate(w, held, document, "0" * 64, "1" * 64, MANIFEST_SHA256)


def full(test, *, edit=None, held=None, supplied=None, **kwargs):
    """The evaluation with every hole filled, under the committed formulas."""
    rig, held = Rig(test), held or records()
    w = worksheet(held, edit=edit)
    return run(w, held, {"receipt": receipt(rig, held, **kwargs), "values": supplied or values(rig)})


def floor(name):
    return CALIBRATED[name] - UNCERTAINTY[name]


def takeover_rows():
    """The standby takeover's expected row values with every hole filled."""
    published = OWNER["shards_per_host"] * OWNER["mutation_rate"] * MEASURED["checkpoint_units"]
    link = floor("host_bandwidth") * (1 - OWNER["foreground_link_share"]) - 2 * published * 4096
    ops = floor("host_iops") * (1 - OWNER["foreground_iops_share"]) - 2 * published
    k = OWNER["concurrent_recoveries_per_host"]
    return {"volume_read": READ_BYTES / floor("volume_bandwidth"),
            "volume_ops": HANDOFF["recovery_ops"] / floor("volume_iops"),
            "share_read": (OWNER["shards_per_host"] + k) * READ_BYTES / OWNER["recovery_share_rate"],
            "host_read": k * READ_BYTES / link, "host_ops": k * HANDOFF["recovery_ops"] / ops,
            "index_build": k * HANDOFF["index_bytes"] / floor("ram_build_rate"),
            "worker_cpu": k * MEASURED["activation_cpu"] / floor("worker_slots"),
            "attempt_cpu": MEASURED["activation_cpu"] / OWNER["recovery_helpers"],
            "store_steps": MEASURED["authority"] + MEASURED["coverage"], "detection": MEASURED["detection"]}


class Committed(unittest.TestCase):
    def test_the_committed_worksheet_checks_and_lists_every_owner_handoff_quantile_and_envelope_hole(self):
        found = sw.check(WORKSHEET, RECORDS)
        owners = [n for n, i in WORKSHEET["inputs"].items() if i["kind"] == "owner"]
        self.assertEqual(sorted(owners), sorted(OWNER))
        self.assertCountEqual(found, [
            *(f"scenario {s} records no quantile" for s in WORKSHEET["scenarios"]),
            *(f"the frame envelope declares no {key}" for key in ENVELOPE),
            *(f"input {n} has no measured source: {WORKSHEET['inputs'][n]['owner']}: "
              f"{WORKSHEET['inputs'][n]['draft']}" for n in HANDOFF),
            *(f"owner input {n} is unrecorded ({WORKSHEET['inputs'][n]['owner']})" for n in OWNER)])

    def test_the_committed_worksheet_scores_nothing_and_names_every_missing_input(self):
        """On the committed records and owner inputs no row of any scenario scores: owner inputs are unrecorded,
        no quantile is recorded, and the committed policy's null foreground reservation leaves the calibration with
        a reason, so no binding resource or tightest row is named."""
        rig = Rig(self)
        out = run(WORKSHEET, RECORDS, {"receipt": receipt(rig, RECORDS), "values": values(rig)})
        for name, scenario in out["scenarios"].items():
            self.assertEqual((scenario["label"], scenario["probability"]), ("conditional scenario", "not identified"))
            self.assertEqual(scenario["estimate"], sw.ESTIMATE)
            self.assertIsNone(scenario["binding"], name)
            self.assertIn("withheld", scenario["capacity"], name)
            for row_name, row in scenario["rows"].items():
                self.assertEqual(row["status"], "unscored", row_name)
        rows = out["scenarios"][TAKEOVER]["rows"]
        self.assertIn("detection: the owner records no quantile for this scenario", rows["detection"]["missing"])
        self.assertIn("owner input store_request_headroom is unrecorded (store owner (#123))",
                      rows["store_load"]["missing"])
        self.assertIn("volume_bandwidth: the receipt's calibration holds reasons: the policy declares no foreground "
                      "reservation, so the worker slots are measured under none", rows["volume_read"]["missing"])
        self.assertIn("recovery_ops has no measured source: #137: The recovery record a credited receipt binds "
                      "counts the device operations the warm load issues.", rows["volume_ops"]["missing"])
        self.assertIn("the frame envelope declares no volume_size_bytes", rows["protected_history"]["missing"])
        self.assertIn("owner input standby_cap_per_az is unrecorded (fleet owners (#91 Q11))",
                      rows["census_encoding"]["missing"])

    def test_the_cli_validates_the_records_checks_and_evaluates_and_refuses_with_exit_2(self):
        rig = Rig(self)
        inputs = rig.file(encode({"receipt": receipt(rig, RECORDS), "values": values(rig)}))
        output = rig.dir / "worksheet.json"
        with redirect_stdout(io.StringIO()) as printed:
            self.assertEqual(sw.main(["check"]), 0)
        self.assertIn("scenario standby-takeover records no quantile", json.loads(printed.getvalue())["open"])
        self.assertEqual(sw.main(["evaluate", "--inputs", inputs["path"], "--output", str(output)]), 0)
        written = json.loads(output.read_text())
        self.assertEqual(written["inputs_sha256"], inputs["sha256"])
        self.assertEqual(written["worksheet_sha256"], hashlib.sha256(sw.WORKSHEET.read_bytes()).hexdigest())
        bad = rig.file(encode({"receipt": receipt(rig, RECORDS), "values": {"volume_bandwidth": []}}))
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sw.main(["evaluate", "--inputs", bad["path"]]), 2)
        self.assertIn("volume_bandwidth, which is no measured input", err.getvalue())
        unlogged = rig.dir / "records"
        shutil.copytree(mf.RECORDS, unlogged)
        (unlogged / "frame.json").write_bytes((mf.RECORDS / "frame.json").read_bytes() + b"\n")
        with redirect_stderr(io.StringIO()) as err:
            self.assertEqual(sw.main(["check", "--records", str(unlogged)]), 2)
        self.assertIn("is not its last logged revision", err.getvalue())


class Evaluation(unittest.TestCase):
    def test_the_standby_takeover_names_its_binding_resource_path_and_levels(self):
        """With every hole filled the shared volume's read of one slot at E_max and the delta region binds: 27.9 GB
        at the volume's calibrated floor exceeds every host row, the store steps and detection, so the binding row
        is volume_read, a shared row, on the path detection, store_steps, volume_read."""
        out = full(self)["scenarios"][TAKEOVER]
        steps, expected = out["steps"], takeover_rows()
        for name, value in expected.items():
            self.assertAlmostEqual(out["rows"][name]["value"], value, places=9, msg=name)
        read = steps[2]
        self.assertAlmostEqual(read["L_S"], expected["volume_read"])
        self.assertAlmostEqual(read["L_h"], max(expected[r] for r in ("share_read", "host_read", "host_ops",
                                                                     "index_build", "worker_cpu", "attempt_cpu")))
        self.assertAlmostEqual(read["time"], MEASURED["l_data_ratio"] * expected["volume_read"])
        self.assertEqual((steps[1]["binding"], steps[1]["L_h"]), ("store_steps", None))
        self.assertEqual(out["binding"], {"row": "volume_read", "resource": "volume-bandwidth", "level": "shared",
                                          "path": ["detection", "store_steps", "volume_read"]})
        self.assertAlmostEqual(out["time"], expected["detection"] + expected["store_steps"] + read["time"])

    def test_a_concurrent_host_load_moves_the_binding_to_the_successors_link(self):
        """Sixteen concurrent recoveries on one successor, under a recovery share wide enough for them, read sixteen
        slots over its link, which then binds as the host-level L_h above the shared volume's L_S."""
        def edit(w):
            w["inputs"]["concurrent_recoveries_per_host"].update(value=16)
            w["inputs"]["recovery_share_rate"].update(value=1e11)
        out = full(self, edit=edit)
        scenario = out["scenarios"][TAKEOVER]
        self.assertEqual((scenario["binding"]["row"], scenario["binding"]["level"]), ("host_read", "host"))
        read = scenario["steps"][2]
        self.assertGreater(read["L_h"], read["L_S"])

    def test_a_small_recovery_share_binds_the_read_on_the_owners_part(self):
        """The recovery I/O share splits its rate over the host's owners, so a share below the volume's floor times
        the owner count binds the read at the successor."""
        out = full(self, edit=lambda w: w["inputs"]["recovery_share_rate"].update(value=1e9))
        self.assertEqual(out["scenarios"][TAKEOVER]["binding"]["row"], "share_read")

    def test_the_fresh_host_path_adds_its_designation_and_attachment_and_the_volume_loss_is_a_separate_cold_scenario(
            self):
        out = full(self)["scenarios"]
        fresh, cold = out["fresh-host-recovery"], out["actual-volume-loss"]
        self.assertEqual(fresh["binding"]["path"], ["fresh_host_designation", "fresh_host_attachment", "detection",
                                                    "store_steps", "volume_read"])
        self.assertAlmostEqual(fresh["time"] - out[TAKEOVER]["time"],
                               HANDOFF["fresh_host_designation"] + MEASURED["fresh_host_attachment"])
        self.assertIn("designated-host-detection", fresh["assumptions"])
        self.assertEqual((fresh["binding"]["row"], fresh["binding"]["resource"], fresh["binding"]["level"]),
                         ("fresh_host_attachment", "stage", "shared"))
        self.assertEqual(fresh["capacity"]["rows"][-2:], ["standby_census", "census_encoding"])
        requests = HANDOFF["designation_store_requests"] + MEASURED["store_requests"]
        self.assertAlmostEqual(fresh["rows"]["fresh_host_store_load"]["value"], OWNER["concurrent_recoveries_per_az"]
                               * requests / (OWNER["store_burst_window"] * OWNER["store_request_headroom"]))
        self.assertNotIn("store_load", fresh["rows"])
        edged = full(self, edit=lambda w: w["inputs"]["store_request_headroom"].update(value=15100))["scenarios"]
        self.assertEqual((edged[TAKEOVER]["unfit"], edged["fresh-host-recovery"]["unfit"]),
                         ([], ["fresh_host_store_load"]))
        crowded = full(self, edit=lambda w: w["inputs"]["shards_per_az"].update(value=3000))["scenarios"]
        self.assertEqual(crowded["fresh-host-recovery"]["unfit"], ["standby_census"])
        attached = sum(OWNER[n] for n in ("shards_per_host", "standbys_per_host", "handoffs_per_host",
                                          "enrollments_per_host", "replacement_attaches_per_host"))
        self.assertAlmostEqual(cold["rows"]["replacement_attachments"]["value"], attached / 27)
        self.assertEqual(cold["class"], "volume-loss-control")
        self.assertEqual(cold["binding"], {"row": "cold_refill", "resource": "stage", "level": "shared",
                                           "path": ["volume_create", "cold_refill"]})
        self.assertEqual(set(cold["rows"]), {"volume_create", "cold_refill", "replacement_attachments", "volume_create_quota",
                                             "volume_bytes_quota", "volume_iops_quota", "replacement_store_load",
                                             "replacement_history", "replacement_extent_rows"})
        for name, warm in (("replacement_history", "protected_history"), ("replacement_extent_rows", "extent_rows")):
            self.assertEqual(cold["rows"][name]["value"], out[TAKEOVER]["rows"][warm]["value"], name)
        dense = full(self, edit=lambda w: w["inputs"]["extents_per_object"].update(value=128))["scenarios"]
        self.assertEqual(dense["actual-volume-loss"]["unfit"], ["replacement_extent_rows"])
        long = full(self, edit=lambda w: w["inputs"]["delta_blocks"].update(value=1 << 28))["scenarios"]
        self.assertEqual(long["actual-volume-loss"]["unfit"], ["replacement_history"])
        self.assertIn(WORKSHEET["assumptions"]["cold-refill-concurrency"], cold["assumptions"].values())
        load = cold["rows"]["replacement_store_load"]
        self.assertAlmostEqual(load["value"], OWNER["concurrent_volume_losses"] * HANDOFF["replacement_store_requests"]
                               / (OWNER["store_burst_window"] * OWNER["store_request_headroom"]))
        self.assertEqual(([c for c in load["conditions"] if c in STORE], load["fits"]), (STORE, True))
        throttled = full(self, edit=lambda w: w["inputs"]["store_request_headroom"].update(value=4000))["scenarios"]
        self.assertEqual(throttled["actual-volume-loss"]["unfit"], ["replacement_store_load"])
        unsourced = full(self, edit=lambda w: w["inputs"].update(
            replacement_store_requests=WORKSHEET["inputs"]["replacement_store_requests"]))["scenarios"]
        self.assertEqual(unsourced["actual-volume-loss"]["capacity"]["withheld"],
                         ["row replacement_store_load is unscored"])
        self.assertNotIn("cold_refill", out[TAKEOVER]["rows"])
        self.assertEqual(cold["capacity"]["tightest"], "volume_create_quota")
        self.assertEqual(cold["rows"]["volume_create_quota"]["value"], 0.5)
        self.assertAlmostEqual(cold["rows"]["volume_iops_quota"]["value"], 10 * 16000 / 1e6)
        self.assertEqual([c for c in cold["rows"]["volume_create"]["conditions"] if c in STORE], STORE)

    def test_the_occupancy_rows_size_attachments_ram_history_store_and_extent_rows_apart(self):
        out = full(self)["scenarios"][TAKEOVER]
        rows = out["rows"]
        attached = sum(OWNER[n] for n in ("shards_per_host", "standbys_per_host", "handoffs_per_host",
                                          "enrollments_per_host"))
        k = OWNER["concurrent_recoveries_per_host"]
        prefix = (1 + OWNER["checkpoint_slots"] * (1 + math.ceil(E_MAX / 41)) + OWNER["delta_blocks"]) * 4096
        ram = HANDOFF["runtime_ram"] + (OWNER["shards_per_host"] + k) * (HANDOFF["index_bytes"] + HANDOFF["shard_ram"]) \
            + k * HANDOFF["recovery_ram"]
        expected = {"store_load": OWNER["concurrent_recoveries_per_az"] * MEASURED["store_requests"]
                    / (OWNER["store_burst_window"] * OWNER["store_request_headroom"]),
                    "host_attachments": attached / OWNER["host_attachment_limit"],
                    "volume_attachments": OWNER["live_attaches_per_volume"] / 3,
                    "host_ram": ram / OWNER["host_ram_bytes"],
                    "campaign_ram": MEASURED["peak_ram"] / OWNER["host_ram_bytes"],
                    "protected_history": prefix / ENVELOPE["volume_size_bytes"],
                    "extent_rows": OBJECTS * OWNER["extents_per_object"] / E_MAX,
                    "standby_census": OWNER["shards_per_az"] / OWNER["standby_cap_per_az"],
                    "census_encoding": OWNER["standby_cap_per_az"] / 4096}
        for name, value in expected.items():
            self.assertAlmostEqual(rows[name]["value"], value, places=12, msg=name)
            self.assertIs(rows[name]["fits"], True, name)
        self.assertEqual(out["capacity"]["tightest"], max(expected, key=lambda n: expected[n]))
        self.assertEqual(out["capacity"]["tightest"], "volume_attachments")
        self.assertEqual(out["unfit"], [])

    def test_an_overloaded_store_and_a_host_without_attachments_read_does_not_fit(self):
        """A store headroom below the recoveries' request rate reads store_load past 1 with fits false, and a zero
        attachment limit reads host_attachments unbounded with fits false and as the tightest row."""
        out = full(self, edit=lambda w: w["inputs"]["store_request_headroom"].update(value=4000))
        store = out["scenarios"][TAKEOVER]["rows"]["store_load"]
        self.assertAlmostEqual(store["value"], 3.75)
        self.assertIs(store["fits"], False)
        self.assertEqual(out["scenarios"][TAKEOVER]["capacity"]["tightest"], "store_load")
        self.assertEqual(out["scenarios"][TAKEOVER]["unfit"], ["store_load"])
        out = full(self, edit=lambda w: w["inputs"]["host_attachment_limit"].update(value=0))
        rows = out["scenarios"][TAKEOVER]["rows"]
        self.assertEqual((rows["host_attachments"]["status"], rows["host_attachments"]["fits"]), ("unbounded", False))
        self.assertEqual(out["scenarios"][TAKEOVER]["capacity"]["tightest"], "host_attachments")

    def test_elasticities_match_finite_differences_and_the_scenario_sensitivity_weighs_step_times(self):
        """Each conditional row's elasticity in every scenario equals a central finite difference of the evaluator
        on each owner and handoff input it varies with; `ceil`'s pass-through derivative over e_max has its closed
        form. The scenario's sensitivity is the step-time-weighted sum of its binding rows' elasticities plus the
        ratio's. The differences run with COUNTS empty, so a count input takes the fractional steps they need."""
        base = full(self)["scenarios"]
        fills = {**OWNER, **HANDOFF}
        lifted = mock.patch.object(sw, "COUNTS", frozenset())
        lifted.start()
        self.addCleanup(lifted.stop)
        for scenario, out in base.items():
            for row, entry in out["rows"].items():
                if entry["status"] != "conditional":
                    continue
                for name in sorted(sw.names(WORKSHEET["rows"][row]["value"]) & set(fills)):
                    h = 1e-6 * fills[name]
                    ups = [full(self, edit=lambda w, n=name, v=fills[name] + d: w["inputs"][n].update(value=v))
                           ["scenarios"][scenario]["rows"][row]["value"] for d in (h, -h)]
                    numeric = (ups[0] - ups[1]) / (2 * h) * fills[name] / entry["value"]
                    self.assertAlmostEqual(entry["elasticity"].get(name, 0.0), numeric, places=5, msg=f"{row} {name}")
        takeover = base[TAKEOVER]
        self.assertAlmostEqual(takeover["rows"]["host_read"]["elasticity"]["concurrent_recoveries_per_host"], 1.0)
        self.assertAlmostEqual(takeover["rows"]["volume_read"]["elasticity"]["volume_bandwidth"], -1.0)
        self.assertAlmostEqual(takeover["rows"]["volume_read"]["elasticity"]["e_max"],
                               (E_MAX / 41) * 4096 / READ_BYTES)
        t = [s["time"] for s in takeover["steps"]]
        steps = MEASURED["authority"] + MEASURED["coverage"]
        self.assertAlmostEqual(takeover["sensitivity"]["l_data_ratio"], t[2] / sum(t))
        self.assertAlmostEqual(takeover["sensitivity"]["volume_bandwidth"], -t[2] / sum(t))
        self.assertAlmostEqual(takeover["sensitivity"]["detection"], t[0] / sum(t))
        self.assertAlmostEqual(takeover["sensitivity"]["authority"], t[1] / sum(t) * MEASURED["authority"] / steps)

    def test_a_tied_binding_withholds_the_sensitivity(self):
        """Two rows tied at a step's largest value leave the scenario time with no derivative, so the step lists the
        tie and the sensitivity reads null."""
        def edit(w):
            w["rows"]["detection_again"] = dict(w["rows"]["detection"])
            w["scenarios"][TAKEOVER]["steps"][0]["rows"].append("detection_again")

        out = full(self, edit=edit)["scenarios"][TAKEOVER]
        self.assertEqual(out["steps"][0]["tied"], ["detection", "detection_again"])
        self.assertIsNone(out["sensitivity"])
        sensitivity = full(self)["scenarios"][TAKEOVER]["sensitivity"]
        self.assertTrue(isinstance(sensitivity, dict) and sensitivity)

    def test_a_link_or_helper_pool_with_no_capacity_is_unbounded_and_binds(self):
        """A divisor below zero (a foreground share of the whole link) and a divisor of zero (no recovery helpers)
        each read unbounded, bind the scenario and leave it with no sensitivity."""
        for name, value, row in (("foreground_link_share", 1, "host_read"), ("recovery_helpers", 0, "attempt_cpu")):
            out = full(self, edit=lambda w, n=name, v=value: w["inputs"][n].update(value=v))
            scenario = out["scenarios"][TAKEOVER]
            self.assertEqual(scenario["rows"][row]["status"], "unbounded", name)
            self.assertEqual(scenario["binding"]["row"], row, name)
            self.assertEqual(scenario["time"], "unbounded", name)
            self.assertNotIn("sensitivity", scenario)

    def test_every_scenario_is_labeled_conditional_and_rows_carry_their_conditions(self):
        out = full(self)["scenarios"]
        for scenario in out.values():
            self.assertEqual((scenario["label"], scenario["probability"]), ("conditional scenario", "not identified"))
        takeover = out[TAKEOVER]
        for name in ("store_steps", "store_load"):
            conditions = takeover["rows"][name]["conditions"]
            self.assertEqual([c for c in conditions if c in STORE], STORE, name)
        self.assertEqual(STORE[0], mf.COLUMNS["store"])
        self.assertTrue(set(sw.STORE) <= set(takeover["assumptions"]))
        self.assertIn("host-loss-keeps-volume", takeover["assumptions"])
        self.assertNotIn("host-loss-keeps-volume", out["actual-volume-loss"]["assumptions"])
        detection = takeover["rows"]["detection"]["conditions"]
        self.assertIn("detection: Inconclusive: platform row unsupported", detection)
        self.assertIn("detection: cell verdict inconclusive", detection)
        self.assertIn("detection: no judge on this revision reads detection evidence", detection)
        self.assertIn("volume_bandwidth: Inconclusive: platform row unsupported",
                      takeover["rows"]["volume_read"]["conditions"])
        self.assertIn("owner input store_request_headroom = 20000 (store owner (#123))",
                      takeover["rows"]["store_load"]["conditions"])
        self.assertIn("l_data_ratio: cell verdict inconclusive", takeover["steps"][2]["conditions"])

    def test_the_receipts_reasons_reach_every_measured_and_calibrated_row(self):
        rig, held = Rig(self), records()
        reason = "control aa is unrun"

        def note(d):
            d["reasons"].append(reason)
            d["ranking"]["withheld"].append(reason)
        ref = receipt(rig, held, edit=note)
        out = run(worksheet(held), held, {"receipt": ref, "values": values(rig)})
        self.assertEqual(out["receipt_reasons"], [reason])
        rows = out["scenarios"][TAKEOVER]["rows"]
        self.assertIn("detection: the receipt withholds its ranking on 1 control notes, listed in receipt_reasons",
                      rows["detection"]["conditions"])
        self.assertIn("volume_bandwidth: the receipt withholds its ranking on 1 control notes, listed in "
                      "receipt_reasons", rows["volume_read"]["conditions"])
        fault = "the campaign id is not measure-1, the one its records and revision derive"
        ref = receipt(rig, held, edit=lambda d: d["reasons"].append(fault))
        out = run(worksheet(held), held, {"receipt": ref, "values": values(rig)})
        problem = f"the receipt's campaign is unestablished: {fault}"
        self.assertEqual(out["receipt_reasons"], [problem])
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"], [f"detection: {problem}"])
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["volume_read"]["missing"], [f"volume_bandwidth: {problem}"])


class Unscored(unittest.TestCase):
    def missing(self, row, scenario=TAKEOVER, **kwargs):
        """The missing inputs of `row` in `scenario` filled but for `kwargs`, and the scenario."""
        out = full(self, **kwargs)["scenarios"][scenario]
        self.assertEqual(out["rows"][row]["status"], "unscored")
        return out["rows"][row]["missing"], out

    def test_a_handoff_input_stays_unscored_and_withholds_the_binding(self):
        rig, held = Rig(self), records()
        out = run(worksheet(held, handoff=False), held, {"receipt": receipt(rig, held), "values": values(rig)})
        scenario = out["scenarios"][TAKEOVER]
        self.assertIsNone(scenario["binding"])
        self.assertEqual(scenario["withheld"], ["row volume_ops is unscored", "row host_ops is unscored",
                                                "row index_build is unscored"])
        self.assertEqual(scenario["rows"]["volume_read"]["status"], "conditional")
        self.assertEqual(scenario["capacity"]["withheld"], ["row host_ram is unscored"])
        self.assertIn("row fresh_host_designation is unscored", out["scenarios"]["fresh-host-recovery"]["withheld"])
        self.assertIn("volume_create_latency has no measured source: #134: The reconciler's actual-volume-loss "
                      "path records the loss judgment, the create request and the replacement volume's attach.",
                      out["scenarios"]["actual-volume-loss"]["rows"]["volume_create"]["missing"])

    def test_an_unrecorded_quantile_a_value_at_another_quantile_or_below_the_floor_is_missing(self):
        rig, held = Rig(self), records()
        out = run(worksheet(held, quantile=None), held, {"receipt": receipt(rig, held), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"],
                         ["detection: the owner records no quantile for this scenario"])
        out = run(worksheet(held), held, {"receipt": receipt(rig, held), "values": values(rig, statistic="p90")})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"],
                         ["detection has no measured value at p99"])
        for samples, kind in ((999, "edge"), (99, "beyond the sample")):
            out = run(worksheet(held), held, {"receipt": receipt(rig, held), "values": values(rig, samples=samples)})
            self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"],
                             [f"detection: p99 over {samples} samples reads {kind}, so it reports no quantile"])
        out = run(worksheet(held), held, {"receipt": receipt(rig, held), "values": values(rig, samples=1000)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["status"], "conditional")

    def test_a_cell_of_another_class_field_or_stratum_is_missing_so_host_loss_never_takes_a_cold_measurement(self):
        for spec in (("detection", "volume-loss-control", "recovery"), ("coverage", "warm-takeover", "recovery"),
                     ("detection", "warm-takeover", "publication")):
            with self.subTest(spec):
                key = cell_key(*spec)
                rig, held = Rig(self), records()
                document = {"receipt": receipt(rig, held, cells=[spec]),
                            "values": values(rig, measured={"detection": 2.0}, cells={"detection": key})}
                out = run(worksheet(held), held, document)
                self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"], [
                    f"detection: cell {key} measures {'/'.join(spec)}, not detection/warm-takeover/recovery"])

    def test_a_cell_of_another_evidence_kind_an_untrusted_clock_or_an_unadmitted_host_is_missing(self):
        """The receipt's judgement of a cell decides admission: a simulation cell of a hardware-only field, a host
        whose clock is untrusted (a degraded cell) and a host the receipt did not admit each keep the value out."""
        spec = ("checkpoint_units", "warm-takeover", "publication")
        simulated = cell_key(*spec, "simulation")
        rig, held = Rig(self), records()
        document = {"receipt": receipt(rig, held, cells=[(*spec, "simulation")]),
                    "values": values(rig, measured={"checkpoint_units": 2.0}, cells={"checkpoint_units": simulated})}
        out = run(worksheet(held), held, document)
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["host_read"]["status"], "conditional")
        detection = cell_key("detection", "warm-takeover", "recovery", "simulation")
        document = {"receipt": receipt(rig, held, cells=[("detection", "warm-takeover", "recovery", "simulation")]),
                    "values": values(rig, measured={"detection": 2.0}, cells={"detection": detection})}
        out = run(worksheet(held), held, document)
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"], [
            f"detection: cell {detection} is no hardware evidence of an admitted host with a trusted clock"])
        key = cell_key("detection", "warm-takeover", "recovery")
        for clock, admitted in (("untrusted", True), ("trusted", False)):
            with self.subTest(clock=clock, admitted=admitted):
                missing, _ = self.missing("detection", clock=clock, admitted=admitted)
                self.assertEqual(missing, [
                    f"detection: cell {key} is no hardware evidence of an admitted host with a trusted clock"])

    def test_a_sizing_field_outside_the_receipts_sizing_hand_off_is_missing(self):
        missing, out = self.missing("store_load", sizing=False)
        self.assertIn("row store_load is unscored", out["capacity"]["withheld"])
        key = cell_key("store_requests", "warm-takeover", "recovery")
        self.assertEqual(missing, [f"store_requests: cell {key} is not in the receipt's sizing hand-off"])

    def test_inputs_measured_at_another_object_count_or_volume_size_are_not_extrapolated(self):
        for row, name in (("campaign_ram", "peak_ram"), ("worker_cpu", "activation_cpu"),
                          ("store_load", "store_requests"), ("host_read", "checkpoint_units"),
                          ("store_steps", "coverage")):
            missing, out = self.missing(row, objects_measured=1 << 18)
            key = cell_key(name, "warm-takeover", "recovery" if name != "checkpoint_units" else "publication")
            self.assertIn(f"{name}: cell {key} was measured at objects_measured {1 << 18}, not n_max {OBJECTS}, and no "
                          "value is extrapolated", missing)
        self.assertIsNone(out["binding"])
        self.assertTrue(any(w.startswith("l_data_ratio: cell") for w in out["withheld"]), out["withheld"])
        missing, out = self.missing("cold_refill", "actual-volume-loss", volume_size_bytes=1 << 39)
        key = cell_key("cold_refill", "volume-loss-control", "recovery")
        self.assertEqual(missing, [f"cold_refill: cell {key} was measured at volume_size_bytes {1 << 39}, not the "
                                   f"envelope's {1 << 40}, and no value is extrapolated"])
        self.assertIsNone(out["binding"])
        missing, out = self.missing("cold_refill", "actual-volume-loss", objects_measured=1 << 18)
        self.assertEqual(missing, [f"cold_refill: cell {key} was measured at objects_measured {1 << 18}, not n_max "
                                   f"{OBJECTS}, and no value is extrapolated"])
        self.assertIsNone(out["binding"])

    def test_a_drifted_or_malformed_calibration_a_missing_band_or_a_foreign_receipt_admits_no_rate(self):
        missing, _ = self.missing("volume_read", drift=0.2)
        self.assertEqual(len(missing), 1)
        self.assertRegex(missing[0], r"^volume_bandwidth: calibration terms \[.*'volume_bandwidth'.*\] drift past "
                                     r"the band 0.05$")
        missing, _ = self.missing("volume_read", drift=0.049)
        self.assertRegex(missing[0], r"^volume_bandwidth: the uncertainty of calibration terms "
                                     r"\[.*'volume_bandwidth'.*\] spans the drift band 0.05$")

        def term(field, value):
            return lambda d: d["comparison"]["calibration"]["terms"]["host_iops"]["end"].update({field: value})

        for edit in (term("uncertainty", -1.0), term("value", float("nan")),
                     lambda d: d["comparison"]["calibration"].update(reasons=None)):
            rig, held = Rig(self), records()
            out = run(worksheet(held), held, {"receipt": receipt(rig, held, edit=edit), "values": values(rig)})
            (why,) = out["scenarios"][TAKEOVER]["rows"]["volume_read"]["missing"]
            self.assertRegex(why, "^volume_bandwidth: (calibration term host_iops lacks a positive start or end value with a "
                                  "non-negative uncertainty|the receipt's calibration holds no list)")
        rig, held = Rig(self), records(drift_band=None)
        out = run(worksheet(held), held, {"receipt": receipt(rig, held), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["volume_read"]["missing"], [
            "volume_bandwidth: the statistics version declares no drift band, so no calibration is stable"])
        other = records(drift_band=0.07)
        out = run(worksheet(held), held, {"receipt": receipt(rig, other), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"], [
            "detection: the receipt was judged under other records than the committed ones"])
        for edit, why in ((lambda d: d.update(envelope={"version": 0}), "the receipt's format envelope is not"),
                          (lambda d: d.pop("comparison"), "the receipt holds no comparison"),
                          (lambda d: d.update(hosts=[]), "the receipt's cells, columns, hosts")):
            rig, held = Rig(self), records()
            out = run(worksheet(held), held, {"receipt": receipt(rig, held, edit=edit), "values": values(rig)})
            self.assertIn(why, out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"][0])
        ref = receipt(rig, held)
        out = run(worksheet(held), held, {"receipt": {**ref, "sha256": "0" * 64}, "values": values(rig)})
        self.assertRegex(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"][0],
                         "^detection: comparison receipt .* is not the file its SHA-256 names$")

    def test_the_calibrated_floor_is_the_lower_phase_and_a_non_positive_floor_is_missing(self):
        """With the end phase's uncertainty three times the start's and a drift of one percent upward, the floor is
        the start value less its uncertainty, and an end uncertainty equal to its value leaves no positive floor."""
        out = full(self, drift=0.01, end_uncertainty=3.0, held=records(drift_band=0.1))["scenarios"][TAKEOVER]
        start, end = floor("volume_bandwidth"), CALIBRATED["volume_bandwidth"] * 1.01 - 3 * UNCERTAINTY[
            "volume_bandwidth"]
        self.assertLess(start, end)
        self.assertAlmostEqual(out["rows"]["volume_read"]["value"], READ_BYTES / start)
        out = full(self, drift=-0.01, end_uncertainty=3.0, held=records(drift_band=0.1))["scenarios"][TAKEOVER]
        end = CALIBRATED["volume_bandwidth"] * 0.99 - 3 * UNCERTAINTY["volume_bandwidth"]
        self.assertAlmostEqual(out["rows"]["volume_read"]["value"], READ_BYTES / end)

        def whole(d):
            for phase in ("start", "end"):
                entry = d["comparison"]["calibration"]["terms"]["volume_bandwidth"][phase]
                entry["uncertainty"] = entry["value"] / 2
        rig, held = Rig(self), records(drift_band=2.0)
        out = run(worksheet(held), held, {"receipt": receipt(rig, held, edit=whole), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["volume_read"]["status"], "conditional")

        def gone(d):
            terms = d["comparison"]["calibration"]["terms"]["volume_bandwidth"]
            terms["start"]["uncertainty"] = 0.0
            terms["end"]["uncertainty"] = terms["end"]["value"]
        out = run(worksheet(held), held, {"receipt": receipt(rig, held, edit=gone), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["volume_read"]["missing"],
                         ["volume_bandwidth's calibrated floor 0.0 is not positive"])

    def test_evidence_off_its_digest_is_missing(self):
        rig, held = Rig(self), records()
        supplied = values(rig)
        supplied["detection"][0]["evidence"]["sha256"] = "0" * 64
        out = run(worksheet(held), held, {"receipt": receipt(rig, held), "values": supplied})
        (why,) = out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"]
        self.assertRegex(why, "^detection: evidence .* is not the file its SHA-256 names$")

    def test_a_cell_key_without_every_identity_value_is_missing(self):
        """A receipt cell keyed by the identity before N_max joined it names no cell identity, so its value is
        missing."""
        rig, held = Rig(self), records()
        key = cell_key("detection", "warm-takeover", "recovery")
        short = json.dumps(json.loads(key)[:-1])
        ref = receipt(rig, held, edit=lambda d: d["cells"].update({short: d["cells"].pop(key)}))
        out = run(worksheet(held), held, {"receipt": ref, "values": values(rig, cells={"detection": short})})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["detection"]["missing"], [
            f"detection: cell {short} is no cell identity of {len(mf.IDENTITY)} values"])


class Admission(unittest.TestCase):
    def detection(self, held=None, quantile="p99", supplied=None, **kwargs):
        rig, held = Rig(self), held or records()
        out = run(worksheet(held, quantile=quantile), held,
                  {"receipt": receipt(rig, held, **kwargs), "values": (supplied or values)(rig)})
        return out, out["scenarios"][TAKEOVER]["rows"]["detection"]

    def test_a_receipt_of_another_judge_or_manifest_or_a_cell_of_another_campaign_admits_nothing(self):
        for edit in (lambda d: d.update(judge_sha256="0" * 64), lambda d: d.update(manifest_sha256="0" * 64)):
            _, row = self.detection(edit=edit)
            self.assertEqual(row["missing"], ["detection: the receipt was judged by another measurement-frame.py or "
                                              "manifest than the committed ones"])
        key = cell_key("detection", "warm-takeover", "recovery")
        _, row = self.detection(edit=lambda d: d.update(campaign="measure-1"))
        self.assertEqual(row["missing"], [f"detection: cell {key} belongs to campaign measure-0, not the receipt's"])

    def test_the_output_states_whose_declarations_the_receipt_and_the_values_are(self):
        """A receipt no campaign derived scores a row, and a receipt of another judge scores none; the output of both
        states that the receipt's judgments and the inputs file's values are their producer's declarations and which
        digests `evaluate` compares."""
        text = ("the receipt's judgments and the inputs file's values, sample counts and censored counts are their "
                "producer's declarations; evaluate compares the receipt file and each evidence file with its "
                "referenced SHA-256, and the judge, manifest and record digests the receipt states with the "
                "committed ones")
        out, row = self.detection()
        self.assertEqual((row["status"], out["provenance"]), ("conditional", text))
        out, row = self.detection(edit=lambda d: d.update(judge_sha256="0" * 64))
        self.assertEqual((row["status"], out["provenance"]), ("unscored", text))

    def test_a_field_admit_reads_off_its_shape_refuses_the_receipt(self):
        key = cell_key("detection", "warm-takeover", "recovery")
        why = "the receipt's cells, columns, hosts, sizing hand-off, reasons or campaign are off their shape"
        for edit in (lambda d: d["cells"][key].pop("verdict"), lambda d: d["columns"].pop("store"),
                     lambda d: d["cells"][key].update(header=[]), lambda d: d.pop("ranking"),
                     lambda d: d["columns"]["hardware"].pop("label")):
            out, row = self.detection(edit=edit)
            self.assertEqual(row["missing"], [f"detection: {why}"])
            self.assertEqual(out["receipt_reasons"], [why])

    def test_a_quantile_over_censored_runs_or_below_its_own_floor_is_missing(self):
        """p99 over 2000 samples ranks the 1980th, so 20 censored runs leave it among the completed ones and 21 do
        not; p999 needs 10000 samples and p90 100 for ten expected exceedances."""
        _, row = self.detection(supplied=lambda rig: values(rig, censored=20))
        self.assertEqual(row["status"], "conditional")
        self.assertIn("detection: p99 over 2000 samples with 20 censored, 20 expected exceedances, as the inputs file "
                      "states", row["conditions"])
        _, row = self.detection(supplied=lambda rig: values(rig, censored=21))
        self.assertEqual(row["missing"], ["detection: p99 over 2000 samples ranks among its 21 censored runs"])
        for quantile, samples, status in (("p999", 10000, "conditional"), ("p999", 9999, "unscored"),
                                          ("p90", 100, "conditional"), ("p90", 99, "unscored")):
            _, row = self.detection(quantile=quantile,
                                    supplied=lambda rig, q=quantile, n=samples: values(rig, statistic=q, samples=n))
            self.assertEqual(row["status"], status, (quantile, samples))

    def test_a_missing_ratio_alone_withholds_the_binding_and_an_early_step_can_bind(self):
        out, _ = self.detection(supplied=lambda rig: values(rig, measured={
            k: v for k, v in MEASURED.items() if k != "l_data_ratio"}))
        scenario = out["scenarios"][TAKEOVER]
        self.assertEqual(scenario["withheld"], ["l_data_ratio has no measured value at p99"])
        self.assertIsNone(scenario["binding"])
        out, _ = self.detection(supplied=lambda rig: values(rig, measured={**MEASURED, "detection": 1000.0}))
        self.assertEqual(out["scenarios"][TAKEOVER]["binding"]["row"], "detection")

    def test_a_calibration_without_a_worksheet_term_or_a_value_past_float_range(self):
        rig, held = Rig(self), records()
        out = run(worksheet(held), held, {"receipt": receipt(rig, held, edit=lambda d: d["comparison"]["calibration"][
            "terms"].pop("volume_bandwidth")), "values": values(rig)})
        self.assertEqual(out["scenarios"][TAKEOVER]["rows"]["volume_read"]["missing"],
                         ["volume_bandwidth: the receipt's calibration holds no term volume_bandwidth"])
        with self.assertRaises(gate.Refusal) as caught:
            self.detection(supplied=lambda rig: values(rig, measured={**MEASURED, "detection": 10 ** 400}))
        self.assertIn("row detection evaluates to inf", str(caught.exception))


class Constants(unittest.TestCase):
    def crate(self, files):
        """The directory of one crate holding the Rust `files` by path, inside a temporary directory the frame module
        reads as the repository."""
        root = Path(tempfile.mkdtemp()).resolve()
        self.addCleanup(shutil.rmtree, root)
        for path, text in {"Cargo.toml": "", **files}.items():
            target = root / "crate" / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text)
        patch = mock.patch.object(mf, "ROOT", root)
        patch.start()
        self.addCleanup(patch.stop)
        return root / "crate"

    def test_a_rust_constant_evaluates_from_its_file_or_reads_as_none(self):
        crate = self.crate({"src/lib.rs": (
            "pub const A: usize = 4_096;\nconst B: u64 = (A as u64 + 2) * 3;\n"
            "pub const C: usize = (1 << 10) >> 2;\nconst D: usize = crate::x::A / 41usize;\n"
            "const E: usize = 1 - 2;\nconst F: usize = 1;\nconst F: usize = 2;\n"
            "const G: &str = \"x\";\nconst H: usize = F;\nconst I: usize = 0x10 + A as usize * 2;\n")})
        for name, value in (("A", 4096), ("B", 12294), ("C", 256), ("D", 99), ("E", None), ("F", None), ("G", None),
                            ("H", None), ("I", 8208), ("MISSING", None)):
            self.assertEqual(sw.constant(str(crate / "src/lib.rs"), name), value, name)

    def test_a_cast_keeps_a_value_its_integer_target_holds_and_reads_as_none_otherwise(self):
        """A cast's value is its operand's where the target is a primitive integer type holding it. Rust wraps a
        value the target does not hold, so those read as none: a narrowing, a reinterpreted sign, a narrowing inside
        a widening. A float target and a type alias, whose widths the evaluator does not know, read as none too."""
        crate = self.crate({"src/lib.rs": (
            "pub const J: u8 = 300usize as u8;\npub const K: i64 = 0xC200_0000_0000_0000_u64 as i64;\n"
            "pub const M: u32 = (1u64 << 40) as u32;\npub const L: u64 = (4096usize / 96) as u64;\n"
            "pub const TOP: u8 = 255usize as u8;\npub const OVER: u8 = 256usize as u8;\n"
            "pub const SIGNED: i8 = 127u8 as i8;\npub const WRAPPED: i8 = 128u8 as i8;\n"
            "pub const WIDE: i64 = 9_223_372_036_854_775_807u64 as i64;\n"
            "pub const POINTER: usize = 18_446_744_073_709_551_615u128 as usize;\n"
            "pub const PAST: usize = 18_446_744_073_709_551_616u128 as usize;\n"
            "pub const A: usize = 4096;\npub const NESTED: u64 = A as u8 as u64;\n"
            "pub const FLOAT: f64 = 7 as f64;\ntype Word = u32;\npub const ALIAS: Word = 5 as Word;\n")})
        for name, value in (("J", None), ("K", None), ("M", None), ("L", 42), ("TOP", 255), ("OVER", None),
                            ("SIGNED", 127), ("WRAPPED", None), ("WIDE", (1 << 63) - 1),
                            ("POINTER", (1 << 64) - 1), ("PAST", None), ("NESTED", None), ("FLOAT", None),
                            ("ALIAS", None)):
            self.assertEqual(sw.constant(str(crate / "src/lib.rs"), name), value, name)

    def test_a_rust_constant_reads_production_declarations_alone(self):
        """A constant's value comes from the `const` items of a build without `test`. A comment, a string, a
        test-gated item, a test-gated module's file and an integration test's file that hold the name count for
        nothing, in the constant's file and across its crate. A `crate::` path names the crate's one production
        declaration, so a private constant of the same name in the naming file makes it ambiguous and never stands
        for it; a bare name reads its own file alone, so a name the file imports reads as none and another module's
        constant of that name never stands for it; a path rooted elsewhere, such as a primitive type's associated
        constant, reads as none."""
        crate = self.crate({
            "src/lib.rs": ("mod layout;\nmod records;\nmod shadowed;\nmod dependent;\nmod limits;\n"
                           "#[cfg(test)]\nmod probes;\n"),
            "src/layout.rs": "pub const IO_UNIT: usize = 4096;\npub const SLOTS: usize = 8;\npub const MAX: usize = 10;\n",
            "src/records.rs": (
                "// const MAX_ATTACHED: usize = 2;\n"
                "pub const MAX_ATTACHED: usize = 3;\n"
                "pub const NOTE: &str = \"const MAX_ATTACHED: usize = 4;\";\n"
                "pub const UNIT_ENTRIES: u64 = ((crate::layout::IO_UNIT - 160) / 96) as u64;\n"
                "pub const IMPORTED: usize = IO_UNIT / 2;\n"
                "pub const FOREIGN: usize = usize::MAX / 2;\n"
                "#[cfg(test)]\nmod probe {\n    const IO_UNIT: usize = 512;\n    const MAX_ATTACHED: usize = 5;\n}\n"),
            "src/shadowed.rs": ("const SLOTS: usize = 2;\npub const HALF: usize = crate::layout::SLOTS / 2;\n"
                                "pub const OWN: usize = SLOTS * 3;\n"),
            "src/probes.rs": "pub const IO_UNIT: usize = 2;\n",
            "src/dependent.rs": "use dep::LIMIT;\npub const DOUBLE: usize = LIMIT * 2;\n",
            "src/limits.rs": "const LIMIT: usize = 8;\n",
            "tests/it.rs": "const IO_UNIT: usize = 1;\n"})
        for path, name, value in (("src/records.rs", "MAX_ATTACHED", 3), ("src/records.rs", "UNIT_ENTRIES", 41),
                                  ("src/records.rs", "IMPORTED", None), ("src/records.rs", "FOREIGN", None),
                                  ("src/dependent.rs", "DOUBLE", None),
                                  ("src/shadowed.rs", "HALF", None), ("src/shadowed.rs", "OWN", 6)):
            with self.subTest(path=path, name=name):
                self.assertEqual(sw.constant(str(crate / path), name), value)
        for path, found in (("src/layout.rs", [(str(crate / "src/layout.rs"), "4096")]), ("src/records.rs", []),
                            ("src/probes.rs", []), ("tests/it.rs", [])):
            with self.subTest(path=path):
                self.assertEqual(sw.declared(str(crate / path), "IO_UNIT"), found)


class Refusals(unittest.TestCase):
    def refused(self, edit, message):
        w = copy.deepcopy(WORKSHEET)
        edit(w)
        with self.assertRaises(gate.Refusal) as caught:
            sw.check(w, RECORDS)
        self.assertIn(message, str(caught.exception))

    def test_each_worksheet_rule_refuses_by_its_message(self):
        def add(name, entry, row=None):
            def edit(w):
                w["inputs"][name] = entry
                if row:
                    w["rows"]["host_ram"]["value"] += f" + {name}"
            return edit

        def steps(name, rows, **more):
            return lambda w: w["scenarios"][name]["steps"].append({"rows": rows, **more})

        def value(row, expression):
            return lambda w: w["rows"][row].update(value=expression)

        def shared(w):
            w["rows"]["iops_share"] = {"level": "shared", "resource": "quota", "unit": "ratio", "value": "iops / iops",
                                       "meaning": "a row both families read"}
            for name in (TAKEOVER, "actual-volume-loss"):
                w["scenarios"][name]["capacity"].append("iops_share")

        cases = [
            (add("loss_probability", {"kind": "owner", "unit": "probability", "owner": "x", "value": None}, True),
             "input loss_probability unit 'probability' is not one of"),
            (lambda w: w["scenarios"][TAKEOVER].update(weight=0.3), "scenario standby-takeover keys are not"),
            (lambda w: w["scenarios"][TAKEOVER].update(**{"class": "warm"}),
             "scenario standby-takeover names no frame class or no trigger"),
            (lambda w: w["scenarios"][TAKEOVER].update(quantile="p95"), "scenario standby-takeover quantile is none"),
            (steps(TAKEOVER, ["cold_refill"]),
             "scenario standby-takeover of class warm-takeover reads cold_refill, bound to volume-loss-control"),
            (steps(TAKEOVER, ["volume_create"]),
             "scenario standby-takeover of class warm-takeover reads volume_create_latency, bound to volume-loss-control"),
            (shared, "rows ['iops_share'] serve both a host-loss scenario and the volume-loss control"),
            (lambda w: (w["rows"].update(loss=dict(w["rows"]["volume_create_quota"])),
                        w["scenarios"][TAKEOVER]["capacity"].append("loss")),
             "scenario standby-takeover of class warm-takeover reads concurrent_volume_losses, bound to "
             "volume-loss-control"),
            (steps(TAKEOVER, ["host_ram"]), "scenario standby-takeover has a step that is no list of time rows"),
            (steps(TAKEOVER, ["detection"], ratio="foreground_link_share"),
             "scenario standby-takeover scales a step by no measured ratio input"),
            (lambda w: w["inputs"]["l_data_ratio"].update(store=True),
             "scenario standby-takeover scales a step by a store input"),
            (lambda w: w["inputs"]["cold_refill"].update(**{"class": "warm-takeover"}),
             "measured input cold_refill is no frame field of its unit, class and stratum"),
            (lambda w: w["inputs"]["store_requests"].update(evidence=["store", "hardware"]),
             "measured input store_requests holds `at` keys outside the frame header of its evidence kinds"),
            (lambda w: w["inputs"]["peak_ram"].update(evidence=["simulation"]),
             "measured input peak_ram admits evidence kinds outside its field's"),
            (lambda w: w["inputs"]["recovery_ops"].update(**{"class": "warm"}), "input recovery_ops names no frame class"),
            (value("detection", "detection + " * 600 + "detection"), "an expression holds more than 2048 characters"),
            *((lambda w, k=key: w["rows"]["store_load"]["assumptions"].remove(k),
               "row store_load reads a store input without every store assumption") for key in STORE_KEYS),
            (value("host_ram", "e_max * unit_entries / host_ram_bytes"),
             "row host_ram sizes RAM from persisted extent rows"),
            (lambda w: w["scenarios"]["fresh-host-recovery"]["assumptions"].remove("host-loss-keeps-volume"),
             "scenario fresh-host-recovery does not carry host-loss-keeps-volume"),
            (lambda w: w["scenarios"]["fresh-host-recovery"]["assumptions"].append("store-hope"),
             "scenario fresh-host-recovery names an unknown assumption"),
            (lambda w: w["scenarios"]["actual-volume-loss"].update(assumptions=["host-loss-keeps-volume"]),
             "scenario actual-volume-loss does not carry actual-volume-loss"),
            (lambda w: w["assumptions"].update({"store-qualification": "the owner accepts the store as qualified"}),
             "the store-qualification assumption is not the frame's store column label"),
            (lambda w: w["assumptions"].pop("store-restore"), "the assumptions omit a store"),
            (add("spare", {"kind": "owner", "unit": "shards", "owner": "x", "value": None}),
             "inputs ['spare'] are read by no scenario"),
            (lambda w: w["rows"].update(spare=dict(w["rows"]["detection"])), "rows ['spare'] belong to no scenario"),
            (value("detection", "detection * fleet_failure_rate"),
             "row detection reads undeclared inputs ['fleet_failure_rate']"),
            (value("detection", "ceil + detection"), "row detection reads undeclared inputs ['ceil']"),
            (value("detection", "__import__('os').getcwd()"), "calls something other than ceil(x)"),
            (value("detection", "detection ** 2"), "holds Pow, not arithmetic"),
            (value("host_ram", "runtime_ram * 96 / host_ram_bytes"), "holds Constant, not arithmetic"),
            (value("detection", "-detection"), "holds UnaryOp, not arithmetic"),
            (lambda w: w["inputs"]["detection"].update(field="detector"), "measured input detection is no frame field"),
            (lambda w: w["inputs"]["peak_ram"].update(unit="units"), "measured input peak_ram is no frame field"),
            (lambda w: w["inputs"]["peak_ram"]["at"].update(objects_measured="detection"),
             "input peak_ram is measured at no envelope/structural/owner input"),
            (lambda w: w["inputs"]["peak_ram"]["at"].update(rate_hz="n_max"),
             "measured input peak_ram holds `at` keys outside the frame header"),
            (lambda w: w["inputs"]["shards_per_host"].update(at={"objects_measured": "n_max"}),
             "input shards_per_host is no"),
            (lambda w: w["inputs"]["volume_bandwidth"].update(term="advertised_bandwidth"),
             "calibrated input volume_bandwidth is no C2 term"),
            (add("e_min", {"kind": "envelope", "unit": "extents"}, True),
             "envelope input e_min is no key of the frame's envelope"),
            (lambda w: w["inputs"]["io_unit"].update(symbol="pub const IO_BYTES"), "structural input io_unit:"),
            (lambda w: w["inputs"]["io_unit"].update(value=4095),
             "structural input io_unit records 4095, but crates/kestrike/src/storage/layout.rs declares IO_UNIT "
             "as 4096"),
            (lambda w: w["inputs"]["unit_entries"].update(value=42), "declares UNIT_ENTRIES as 41"),
            (lambda w: w["inputs"]["io_unit"].update(kind="advertised"), "input io_unit is no"),
            (lambda w: w["scenarios"][TAKEOVER]["capacity"].append("detection"),
             "scenario standby-takeover has a capacity row that is no ratio row"),
            (lambda w: w["frame"].update(version=1), "the worksheet pins another frame than the committed one"),
            (lambda w: w["properties"].pop("R17"), "the property map does not name"),
            *((lambda w, k=slots: w["inputs"]["checkpoint_slots"].update(value=k),
               "owner input checkpoint_slots is below its floor min_slots") for slots in (0, 1, 2)),
            (lambda w: w["inputs"]["checkpoint_slots"].update(floor="max_attached"),
             "owner input checkpoint_slots is below its floor max_attached or names no structural input of its unit"),
            (lambda w: w["inputs"]["checkpoint_slots"].update(floor=["min_slots"]),
             "owner input checkpoint_slots is below its floor ['min_slots'] or names no structural input of its unit"),
            (lambda w: w["inputs"]["checkpoint_slots"].pop("floor"), "inputs ['min_slots'] are read by no scenario"),
            (lambda w: w["inputs"]["detection"].update(floor="min_slots"), "input detection is no"),
            (lambda w: w["inputs"]["min_slots"].update(value=4), "declares MIN_SLOTS as 3"),
            *((lambda w, n=name, v=bad: w["inputs"][n].update(value=v),
               f"owner input {name} names no owner or holds a value that is no")
              for name, bad in (("checkpoint_slots", 2.5), ("concurrent_volume_losses", 0.5),
                                ("delta_blocks", 262144.0), ("shards_per_host", True),
                                ("host_ram_bytes", -1), ("mutation_rate", math.inf))),
        ]
        for edit, message in cases:
            with self.subTest(message):
                self.refused(edit, message)

    def test_a_row_that_rises_with_a_floor_or_evaluates_negative_or_overflows_is_refused(self):
        cases = [(lambda w: w["rows"]["detection"].update(value="fresh_host_attachment / detection"),
                  "row detection falls as measured inputs ['detection'] rise"),
                 (lambda w: w["rows"]["volume_read"].update(value="volume_bandwidth / io_unit"),
                  "row volume_read rises with calibrated inputs ['volume_bandwidth']"),
                 (lambda w: w["rows"]["detection"].update(value="detection - fresh_host_attachment"),
                  "row detection evaluates to -38.0"),
                 (lambda w: w["inputs"]["extents_per_object"].update(value=1e308), "row extent_rows evaluates to inf")]
        for edit, message in cases:
            with self.subTest(message), self.assertRaises(gate.Refusal) as caught:
                full(self, edit=edit)
            self.assertIn(message, str(caught.exception))

    def test_the_inputs_file_supplies_measured_values_only(self):
        rig, held = Rig(self), records()
        w, ref = worksheet(held), receipt(rig, held)
        entry = {"statistic": "p99", "cell": "x", "value": 1.0, "samples": SAMPLES, "censored": 0,
                 "evidence": rig.file(b"e")}
        cases = [({"volume_bandwidth": [entry]}, "volume_bandwidth, which is no measured input"),
                 ({"store_request_headroom": [entry]}, "store_request_headroom, which is no measured input"),
                 ({"io_unit": [entry]}, "io_unit, which is no measured input"),
                 ({"recovery_ops": [entry]}, "recovery_ops, which is no measured input"),
                 ({"detection": [entry, entry]}, "the values of detection are not one positive value per quantile"),
                 ({"detection": [{**entry, "value": 0}]}, "the values of detection are not one positive value"),
                 ({"detection": [{**entry, "samples": 0}]}, "the values of detection are not one positive value"),
                 ({"detection": [{**entry, "samples": 2000.0}]}, "the values of detection are not one positive value"),
                 ({"detection": [{**entry, "censored": 2001}]}, "the values of detection are not one positive value")]
        for supplied, message in cases:
            with self.subTest(message), self.assertRaises(gate.Refusal) as caught:
                run(worksheet(held, handoff=False), held, {"receipt": ref, "values": supplied})
            self.assertIn(message, str(caught.exception))
        with self.assertRaises(gate.Refusal):
            run(w, held, {"receipt": ref, "values": {}, "probability": 0.01})


if __name__ == "__main__":
    unittest.main()
