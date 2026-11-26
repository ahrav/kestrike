#!/usr/bin/env python3
"""Exercise hit-gate.py's manifest validation, schedule, seeded draw, statistics, block comparison, pacing, campaign
safety, sample binding and receipt over the committed manifest and synthetic samples."""

import copy
import functools
import hashlib
import importlib.util
import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from collections.abc import Callable
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hit_gate", ROOT / "scripts/hit-gate.py")
assert SPEC is not None and SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(gate)

DOCUMENT = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())
IDS = gate.obligation_ids(ROOT / "verification/obligations.json")
MAIN, CANDIDATE, DIGEST = "a" * 40, "b" * 40, "d" * 64
SEED = gate.campaign_seed(DIGEST, MAIN, CANDIDATE)
CAMPAIGN = gate.campaign_id(SEED)
CELL = ("request-weighted", "idle", 0)
RATE, REQUESTS = 2000, 25_000
BUILD = {"CARGO_PROFILE_DEV_OPT_LEVEL": "3"}


def filled():
    """The committed manifest with the open items an approved campaign would fill; the phases other than idle and
    the recovery stay blocked, since no receipt binds their evidence."""
    document = copy.deepcopy(DOCUMENT)
    document["platforms"]["x86_64-nitro-ebs"]["supported"] = True
    q = document["qualification"]
    q["offered_rate"] = RATE
    q["build_environment"] = dict(BUILD)
    q["protocol"] = {"null_blocks": 2, "blocks": 2, "repeats": 1, "requests": REQUESTS, "max_lag_us": 1000,
                     "position_hits": 1000, "max_non_hits": 100, "band_coverage": 0.5,
                     "tolerance_ms": {"p90": 0.05, "p99": 0.2}}
    for workload in q["workloads"].values():
        workload.pop("blocked")
    q["recovery"]["n_max"] = 1 << 28
    q["preservation"]["qualified"] = True
    return document


def samples(n, latency: "int | Callable[[int], int]", lag=0, wait=0, stratum="hit", source=0):
    """`n` samples 10 us apart; sample i's latency is `latency(i)` us, or `latency + i % 100` for an integer. Each is
    first attempted `lag` us after its intended send and admitted `wait` us after that."""
    def at(i):
        return latency(i) if callable(latency) else latency + i % 100

    return [[10 * i, 10 * i + lag, 10 * i + lag + wait, 10 * i + at(i), i % 4, stratum, source] for i in range(n)]


def run(block, slot, arm, values, null=False):
    return {"id": f"r{block}{slot}", "block": block, "slot": slot, "arm": arm, "null": null, "samples": values,
            "source": 0}


def campaign_runs(a_us, b_us, n=25_000, templates=("ABBA", "BAAB", "ABBA", "BAAB")):
    """Two null blocks of main at `a_us`, then two candidate blocks, one run per position of n samples each."""
    return [run(block, slot, arm, samples(n, a_us if block < 2 or arm == "A" else b_us), null=block < 2)
            for block, pattern in enumerate(templates) for slot, arm in enumerate(pattern)]


SAFETY = {"tag": {"key": "kestrike-campaign", "value": CAMPAIGN}, "owner": "qualification", "budget_usd": 40,
          "deadline": "2031-01-01T00:00:00Z", "teardown_on_failure": True, "preexisting": ["vol-other"],
          "resources": [{"id": "i-1", "tags": {"kestrike-campaign": CAMPAIGN, "owner": "qualification"}}],
          "teardown": ["i-1"], "standing": ["i-owner", "i-client", "vol-1"], "residue": []}


ADDRESS = {"owner": "10.0.1.5", "client": "10.0.1.7"}
PEER = {"owner": ADDRESS["client"], "client": ADDRESS["owner"]}


class Lane:
    """The lane's judge_profile for receipts the test writes: it credits a receipt set whose roles name the
    revision the judge requires, so the gate's own binding rules are what the tests exercise."""

    def judge_profile(self, platforms, profile_name, profile, receipts, digest, revision):
        revisions = {r["hardware"].get("revision") for r in receipts}
        return revisions == {revision}, [f"receipts name {sorted(revisions)}"]


class Manifest(unittest.TestCase):
    def test_the_committed_manifest_validates_and_lists_what_blocks_a_pass(self):
        found = gate.check(DOCUMENT, IDS)
        for item in ("platform row x86_64-nitro-ebs is unsupported", "the workload manifest declares no offered_rate",
                     "the protocol declares no null_blocks", "the protocol declares no position_hits",
                     "the protocol declares no max_non_hits", "the recovery manifest declares no n_max",
                     "the qualification declares no build_environment, so no build profile is pinned"):
            self.assertIn(item, found)
        for prefix in ("phase publish is blocked", "workload request-weighted is blocked", "recovery is blocked",
                       "preservation takeover-history-suffix-damage-qualification-failure is unqualified"):
            self.assertTrue(any(item.startswith(prefix) for item in found), prefix)
        self.assertEqual(sorted(item.split(":")[0] for item in gate.check(filled(), IDS)),
                         ["phase publish is blocked", "phase scan is blocked", "phase takeover is blocked",
                          "recovery is blocked"])

    def test_each_malformed_field_is_refused(self):
        def nominal_large(q):
            q["workloads"]["request-weighted"].update(large_object=True, p99_ms=5.0)

        edits = {
            "p90 over the 1 ms ceiling": lambda q: q["workloads"]["request-weighted"].update(p90_ms=1.2),
            "a 400-digit p90": lambda q: q["workloads"]["request-weighted"].update(p90_ms=10 ** 400),
            "p99 over 3 ms without a large-object declaration": lambda q: q["workloads"]["request-weighted"].update(p99_ms=4.0),
            "large-object p99 over 5 ms": lambda q: q["workloads"]["large-object"].update(p99_ms=5.5),
            "the nominal workload claims the large-object ceiling": nominal_large,
            "no nominal workload": lambda q: q["workloads"].pop("request-weighted"),
            "fewer than 100,000 hits": lambda q: q.update(min_hits=99_999),
            "a build environment without an optimization level": lambda q: q.update(build_environment={}),
            "a pacing ladder that rises": lambda q: q["pacing"].update(ladder_permille=[50, 100]),
            "a pacing share over 10%": lambda q: q["pacing"].update(ladder_permille=[150, 50]),
            "a recovery bound past 15 s": lambda q: q["recovery"].update(first_hit_s=20),
            "a target past the bound": lambda q: q["recovery"].update(target_s=16),
            "another E_max": lambda q: q["recovery"].update(e_max=1 << 27),
            "an unblocked recovery": lambda q: q["recovery"].pop("blocked"),
            "a phase set without scan": lambda q: q["phases"].pop("scan"),
            "an unblocked publish phase": lambda q: q["phases"]["publish"].pop("blocked"),
            "one null block": lambda q: q["protocol"].update(null_blocks=1),
            "a null block count past 2^63": lambda q: q["protocol"].update(null_blocks=2 ** 63),
            "a cell of more than 4,096 runs": lambda q: q["protocol"].update(blocks=600, repeats=2, requests=10_000),
            "a cell of more samples than the judge holds": lambda q: q["protocol"].update(blocks=300, requests=1 << 20),
            "candidate blocks that cannot reach min_hits": lambda q: q["protocol"].update(requests=24_999),
            "a position hit floor past a position's requests": lambda q: q["protocol"].update(
                position_hits=q["protocol"]["repeats"] * REQUESTS + 1),
            "a band coverage the null blocks cannot give": lambda q: q["protocol"].update(band_coverage=0.9),
            "requests that leave less than the margin": lambda q: q["protocol"].update(requests=RATE * 481),
            "a boolean count": lambda q: q["protocol"].update(repeats=True),
            "a negative non-hit bound": lambda q: q["protocol"].update(max_non_hits=-1),
            "a boolean non-hit bound": lambda q: q["protocol"].update(max_non_hits=False),
            "no catalog obligation": lambda q: q["preservation"].update(obligation="absent"),
            "interface roles off the profile": lambda q: q["interface"]["roles"].update(client=["other"]),
            "a run identity without its repeat": lambda q: q["interface"].update(run_identity="{campaign}"),
        }
        for name, edit in edits.items():
            with self.subTest(name):
                document = filled()
                edit(document["qualification"])
                with self.assertRaises(gate.Refusal):
                    gate.check(document, IDS)
        document = filled()
        document["qualification"]["protocol"].update(requests=RATE * 480)
        gate.check(document, IDS)
        document = filled()
        document["qualification"]["protocol"].update(max_non_hits=0)
        gate.check(document, IDS)
        document = filled()
        document["qualification"]["protocol"].update(
            position_hits=document["qualification"]["protocol"]["repeats"] * REQUESTS)
        gate.check(document, IDS)
        document = filled()
        document["profiles"]["hit-gate"]["roles"]["owner"].pop("env")
        with self.assertRaisesRegex(gate.Refusal, "KESTRIKE_SERVE_SECONDS"):
            gate.check(document, IDS)


class Schedule(unittest.TestCase):
    def test_the_schedule_is_seeded_null_blocks_first_and_balanced_abba_and_baab(self):
        protocol = {"null_blocks": 3, "blocks": 5, "repeats": 2}
        order = gate.schedule(7, CELL, protocol)
        self.assertEqual(order, gate.schedule(7, CELL, protocol), "one seed fixes one order")
        self.assertEqual(len(order), 8 * 4 * 2)
        self.assertEqual([row[4] for row in order], [True] * 24 + [False] * 40, "A/A null blocks come first")
        self.assertNotEqual(order, gate.schedule(8, CELL, protocol))
        for seed in range(20):
            for null_blocks, blocks in ((2, 2), (3, 5), (4, 7)):
                order = gate.schedule(seed, CELL, {"null_blocks": null_blocks, "blocks": blocks, "repeats": 1})
                patterns = ["".join(row[3] for row in order if row[0] == block) for block in range(null_blocks + blocks)]
                self.assertLessEqual(set(patterns), {"ABBA", "BAAB"})
                for group in (patterns[:null_blocks], patterns[null_blocks:]):
                    self.assertLessEqual(abs(group.count("ABBA") - group.count("BAAB")), 1, (seed, group))

    def test_the_order_for_a_fixed_seed_is_pinned(self):
        order = gate.schedule(7, CELL, {"null_blocks": 3, "blocks": 5, "repeats": 1})
        self.assertEqual(["".join(row[3] for row in order if row[0] == block) for block in range(8)],
                         ["BAAB", "ABBA", "ABBA", "BAAB", "BAAB", "ABBA", "ABBA", "ABBA"])

    def test_the_seed_and_campaign_follow_the_manifest_and_the_revisions(self):
        self.assertEqual(SEED, gate.campaign_seed(DIGEST, MAIN, CANDIDATE))
        self.assertNotEqual(SEED, gate.campaign_seed("e" * 64, MAIN, CANDIDATE))
        self.assertNotEqual(SEED, gate.campaign_seed(DIGEST, MAIN, "c" * 40))
        self.assertEqual(CAMPAIGN, f"hit-gate-{SEED:016x}")

    def test_the_draw_and_the_intended_times_are_the_cells(self):
        """net::host_pair_tests::hit_gate::the_schedule_draws_records_by_the_workload_weights pins these values;
        Judge.test_the_judge_admits_the_cells_intended_times_at_a_rate_that_leaves_a_remainder pins the intended
        times through the judge."""
        self.assertEqual([gate.draw(7, i, [1, 1, 1, 1]) for i in range(12)], [3, 2, 0, 2, 1, 3, 3, 2, 1, 3, 3, 2])
        self.assertEqual([gate.draw(gate.U64 - 5, i, [1, 1, 1, 1]) for i in range(12)],
                         [2, 2, 1, 1, 0, 3, 1, 2, 1, 2, 2, 0], "seed + i wraps past 2^64")
        self.assertEqual({gate.draw(7, i, [0, 0, 1, 0]) for i in range(100)}, {2})


class Statistics(unittest.TestCase):
    def test_quantiles_are_nearest_rank(self):
        values = list(range(1, 101))
        self.assertEqual([gate.quantile(values, q) for q in gate.QUANTILES.values()], [50, 90, 99, 100])

    def test_latency_runs_from_the_intended_send_through_a_late_admission(self):
        stats, hits = gate.arm_stats([run(0, 0, "B", samples(100, 600, lag=20, wait=480))], [[1, 0]] * 4)
        self.assertEqual(hits[0], 600, "a GET admitted 500 us late counts its wait from the intended send")
        self.assertEqual((stats["pooled_lag_p99"], stats["lag_max"]), (0.02, 0.02))
        self.assertEqual((stats["pooled_wait_p99"], stats["wait_max"]), (0.48, 0.48))

    def test_residual_owner_traffic_is_counted_apart_by_stratum_and_never_pooled(self):
        values = samples(1_000, 100) + samples(500, 9_000, source=1) + samples(7, 100, stratum="miss", source=1)
        stats, _ = gate.arm_stats([run(0, 0, "B", values)], [[1, 0]] * 4)
        self.assertEqual(stats["hits"], 1_000)
        self.assertEqual(stats["residual"], {"hit": 500, "miss": 7, "refused": 0, "error": 0})
        self.assertLess(stats["p99"], 1.0)
        self.assertGreater(stats["residual_p99"], 9.0)

    def test_misses_refusals_and_errors_are_counted_beside_the_hits(self):
        values = samples(90, 100) + samples(5, 100, stratum="miss") + samples(5, 100, stratum="refused")
        stats, _ = gate.arm_stats([run(0, 0, "B", values)], [[1, 0]] * 4)
        self.assertEqual((stats["strata"], stats["hits"]), ({"hit": 90, "miss": 5, "refused": 5, "error": 0}, 90))


class Cell(unittest.TestCase):
    def setUp(self):
        self.q = filled()["qualification"]

    def judge(self, runs, workload="request-weighted"):
        return gate.judge_cell(self.q, workload, runs)

    def test_a_shortfall_of_hits_is_inconclusive(self):
        result = self.judge(campaign_runs(200, 200, n=24_999))
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertIn("under 100000", result["reasons"][0])

    def test_an_equal_candidate_passes_the_comparison_and_the_ceilings(self):
        result = self.judge(campaign_runs(200, 200))
        self.assertEqual(result["verdict"], "pass", result["reasons"])
        self.assertEqual(result["arms"]["B"]["hits"], 100_000)
        self.assertEqual(result["comparison"]["p99"]["coverage"], 2 / 3)

    def test_each_absolute_ceiling_binds_alone_whatever_the_comparison_says(self):
        cases = {
            "p90 at 1.039 ms": (lambda i: 950 + i % 100, "request-weighted", ["p90"]),
            "p99 at exactly 3 ms": (lambda i: 3_000 if i % 100 >= 98 else 100, "request-weighted", ["p99"]),
            "p99 just under 3 ms": (lambda i: 2_999 if i % 100 >= 98 else 100, "request-weighted", []),
            "large-object p99 at 4 ms": (lambda i: 4_000 if i % 100 >= 98 else 100, "large-object", []),
            "large-object p99 at 5 ms": (lambda i: 5_000 if i % 100 >= 98 else 100, "large-object", ["p99"]),
        }
        for name, (latency, workload, broken) in cases.items():
            with self.subTest(name):
                runs = campaign_runs(0, 0)
                for r in runs:
                    r["samples"] = samples(25_000, latency)
                result = self.judge(runs, workload)
                self.assertEqual(result["comparison"]["p99"]["verdict"], "pass", "main and candidate are equal")
                self.assertEqual(result["verdict"], "fail" if broken else "pass", result["reasons"])
                self.assertEqual([reason.split()[1] for reason in result["reasons"]], broken)

    def test_a_short_main_arm_keeps_the_candidates_ceiling_failure(self):
        runs = campaign_runs(200, 3_500)
        for r in runs:
            if r["arm"] == "A" and not r["null"]:
                r["samples"] = r["samples"][:20_000]
        result = self.judge(runs)
        self.assertEqual(result["verdict"], "fail")
        self.assertTrue(any("arm A pooled 80000" in reason for reason in result["reasons"]))
        self.assertTrue(any(reason.startswith("candidate p99") for reason in result["reasons"]))

    def test_a_short_candidate_arm_with_a_failing_comparison_is_inconclusive(self):
        runs = campaign_runs(200, 600)
        for r in runs:
            if r["arm"] == "B" and not r["null"]:
                r["samples"] = r["samples"][:20_000]
        result = self.judge(runs)
        self.assertEqual(result["comparison"]["p99"]["verdict"], "fail")
        self.assertEqual(result["verdict"], "inconclusive")

    def test_a_regression_past_the_tolerance_and_band_fails(self):
        result = self.judge(campaign_runs(200, 600))
        self.assertEqual(result["comparison"]["p99"]["verdict"], "fail")
        self.assertEqual(result["verdict"], "fail")

    def test_a_difference_at_exactly_the_tolerance_passes(self):
        result = self.judge(campaign_runs(200, 250))
        self.assertEqual(result["comparison"]["p90"]["candidate"], [0.05, 0.05])
        self.assertEqual(result["comparison"]["p90"]["verdict"], "pass", result["comparison"]["p90"])

    def test_a_nonzero_band_decides_each_side_of_the_tolerance(self):
        """With an A/A band of 40 us and a p99 tolerance of 200 us, a contrast of 160 us passes at exactly d + band =
        tolerance, 170 us passes the tolerance alone but not with the band, 230 us exceeds the tolerance but not by
        the band, and 250 us fails."""
        for b_shift, verdict in ((160, "pass"), (170, "inconclusive"), (230, "inconclusive"), (250, "fail")):
            with self.subTest(b_shift=b_shift):
                runs = campaign_runs(200, 200 + b_shift)
                runs[1]["samples"] = samples(25_000, 240)
                runs[2]["samples"] = samples(25_000, 240)
                c = self.judge(runs)["comparison"]["p99"]
                self.assertEqual((c["band"], c["verdict"]), (0.04, verdict), c)

    def test_repeats_pool_within_their_position(self):
        self.q["protocol"]["repeats"] = 2
        runs = [{**r, "id": f"{r['id']}x"} for r in campaign_runs(200, 200, n=12_500)]
        extra = [{**r, "id": f"{r['id']}y", "samples": samples(12_500, 300 if not r["null"] and r["arm"] == "B" else 200)}
                 for r in campaign_runs(200, 200, n=12_500)]
        c = self.judge(runs + extra)["comparison"]["p99"]
        self.assertEqual(c["candidate"], [0.099, 0.099],
                         "each B position's p99 pools both repeats: 398 us over its 200 and 300 us runs, against 299 us")

    def test_every_candidate_block_must_agree(self):
        runs = campaign_runs(200, 200)
        for r in runs:
            if r["block"] == 3 and r["arm"] == "B":
                r["samples"] = samples(25_000, 700)
        mixed = self.judge(runs)["comparison"]["p99"]
        self.assertEqual((mixed["candidate"], mixed["verdict"]), ([0.0, 0.5], "inconclusive"))

    def test_a_block_position_short_of_position_hits_makes_the_comparison_inconclusive(self):
        for name, values in (("no hits", samples(25_000, 200, stratum="miss")),
                             ("one hit short", samples(999, 200) + samples(24_001, 200, stratum="miss"))):
            with self.subTest(name):
                runs = campaign_runs(200, 200)
                runs[13]["samples"] = values
                runs[14]["samples"] = samples(50_000, 200)
                result = self.judge(runs)
                self.assertGreaterEqual(result["arms"]["B"]["hits"], 100_000)
                self.assertEqual(result["comparison"]["p99"]["missing_blocks"], [3])
                self.assertEqual(result["verdict"], "inconclusive")

    def test_residual_owner_hits_leave_the_block_contrasts_unchanged(self):
        runs = campaign_runs(200, 200)
        for r in runs:
            if not r["null"] and r["arm"] == "B":
                r["samples"] = r["samples"] + samples(5_000, 9_000, source=1)
        result = self.judge(runs)
        self.assertEqual(result["comparison"]["p99"]["candidate"], [0.0, 0.0])
        self.assertEqual((result["arms"]["B"]["hits"], result["verdict"]), (100_000, "pass"))

    def test_a_drift_linear_in_position_cancels_in_either_order(self):
        for templates in (("ABBA", "BAAB", "ABBA", "BAAB"), ("BAAB", "ABBA", "BAAB", "ABBA")):
            with self.subTest(templates=templates):
                runs = campaign_runs(0, 0, templates=templates)
                for r in runs:
                    r["samples"] = samples(25_000, 200 + 300 * r["slot"])
                result = self.judge(runs)
                self.assertEqual(result["comparison"]["p99"]["candidate"], [0.0, 0.0])
                self.assertEqual(result["comparison"]["p99"]["verdict"], "pass")

    def test_a_generator_limited_run_is_inconclusive_whatever_its_latencies_show(self):
        runs = campaign_runs(200, 200)
        runs[9]["samples"] = samples(25_000, 200, lag=100)
        self.q["protocol"]["max_lag_us"] = 50
        result = self.judge(runs)
        self.assertEqual(result["comparison"]["p99"]["verdict"], "pass", "the lag leaves every latency as it was")
        self.assertEqual(result["verdict"], "inconclusive")
        self.assertTrue(result["reasons"][0].startswith("generator-limited"), result["reasons"])
        self.q["protocol"]["max_lag_us"] = 1000
        runs = campaign_runs(200, 200)
        pause = samples(25_000, 200)
        pause[24_990] = [249_900, 251_400, 251_400, 255_000, pause[24_990][4], "hit", 0]
        runs[9]["samples"] = pause
        for r in runs:
            if not r["null"] and r["arm"] == "B":
                r["samples"] = samples(25_000, 3_500) if r is not runs[9] else pause
        result = self.judge(runs)
        self.assertEqual(result["verdict"], "inconclusive", "a pause on one request in 25,000 limits the run")
        self.assertTrue(any(reason.startswith("candidate p99") for reason in result["reasons"]))

    def extended(self, base, arm, *extras):
        """`base` with each of `extras` appended to the samples of one candidate-block run of `arm`, in run order."""
        runs = [dict(r) for r in base]
        for r, extra in zip([r for r in runs if not r["null"] and r["arm"] == arm], extras):
            r["samples"] = r["samples"] + extra
        return runs

    def test_a_candidate_that_backs_up_the_client_slots_fails_on_its_latencies(self):
        """Every candidate GET is first attempted on time, waits 2,000 us for a client slot and ends past the
        ceilings. The wait is latency the owner caused, so the ceilings fail the cell; the generator bound reads
        the first attempt and stays quiet."""
        runs = campaign_runs(200, 200)
        for r in runs:
            if not r["null"] and r["arm"] == "B":
                r["samples"] = samples(25_000, 3_500, wait=2_000)
        result = self.judge(runs)
        self.assertEqual(result["verdict"], "fail", result["reasons"])
        self.assertFalse(any(reason.startswith("generator-limited") for reason in result["reasons"]), result["reasons"])
        self.assertTrue(any(reason.startswith("candidate p99") for reason in result["reasons"]), result["reasons"])
        self.assertEqual(result["arms"]["B"]["wait_max"], 2.0)

    def test_routed_non_hits_past_the_bound_fail_the_candidate_whatever_its_hit_latencies_show(self):
        """The quantiles cover hits alone, so a GET the owner refuses or misses, or one the client times out after
        30 s, leaves them. Under a bound of 100, a candidate arm whose 100,000 hits match the main arm's passes with
        100 routed non-hit samples and fails with 101 that need every stratum and both runs to reach the count; 101 on
        the main arm leave the cell inconclusive, and samples of another source count on neither arm."""
        def refused(n):
            return samples(n, 150, stratum="refused")

        cases = {
            "100 candidate GETs refused": ("B", [refused(100)], "pass"),
            "101 candidate GETs refused, timed out or missed over two runs":
                ("B", [refused(50), samples(26, 30_000_000, stratum="error") + samples(25, 150, stratum="miss")],
                 "fail"),
            "101 main GETs refused": ("A", [refused(101)], "inconclusive"),
            "101 misses of another source": ("B", [samples(101, 150, stratum="miss", source=1)], "pass"),
        }
        base = campaign_runs(200, 200)
        for name, (arm, extras, verdict) in cases.items():
            with self.subTest(name):
                result = self.judge(self.extended(base, arm, *extras))
                self.assertEqual(result["arms"]["B"]["hits"], 100_000)
                self.assertEqual({c["verdict"] for c in result["comparison"].values()}, {"pass"},
                                 "the hit latencies are the main arm's")
                self.assertEqual(result["verdict"], verdict, result["reasons"])
                self.assertEqual(result["reasons"], [] if verdict == "pass" else
                                 [f"arm {arm} pooled 101 routed non-hit samples, over 100"])

    def test_the_non_hit_bound_binds_a_candidate_short_of_min_hits_but_not_a_generator_limited_run(self):
        """A candidate that refuses a fifth of its GETs pools 80,000 hits: the refusals are measured, so the cell
        fails instead of waiting for more hits. A generator-limited run keeps the cell inconclusive, since its
        samples do not measure the offered load."""
        runs = campaign_runs(200, 200)
        for r in runs:
            if not r["null"] and r["arm"] == "B":
                r["samples"] = samples(20_000, 200) + samples(5_000, 150, stratum="refused")
        result = self.judge(runs)
        self.assertEqual(result["reasons"], ["arm B pooled 80000 hits, under 100000",
                                             "arm B pooled 20000 routed non-hit samples, over 100"])
        self.assertEqual(result["verdict"], "fail")
        runs[0]["samples"] = samples(25_000, 2_000, lag=1_001)
        result = self.judge(runs)
        self.assertTrue(result["reasons"][0].startswith("generator-limited"), result["reasons"])
        self.assertEqual(result["verdict"], "inconclusive")


class Verdicts(unittest.TestCase):
    def test_pass_needs_every_verdict_to_pass(self):
        self.assertEqual(gate.worst(["pass", "pass"]), "pass")
        for verdicts in ([], ["pass", "passed"], ["pass", None], ["pass", "inconclusive"]):
            self.assertEqual(gate.worst(verdicts), "inconclusive", verdicts)
        self.assertEqual(gate.worst(["fail", "handoff"]), "handoff")


class Pacing(unittest.TestCase):
    LADDER = [100, 50, 25]

    def test_the_first_passing_share_is_selected(self):
        self.assertEqual(gate.pacing(self.LADDER, {100: "pass", 50: "pass"})["permille"], 100)
        self.assertEqual(gate.pacing(self.LADDER, {100: "fail", 50: "pass"})["permille"], 50)
        self.assertEqual(gate.pacing(self.LADDER, {100: "fail", 50: "fail", 25: "pass"})["permille"], 25)

    def test_a_share_without_a_verdict_stops_the_ladder(self):
        for verdicts in ({}, {100: "inconclusive", 50: "pass"}, {50: "pass"}):
            with self.subTest(verdicts=verdicts):
                self.assertEqual(gate.pacing(self.LADDER, verdicts)["verdict"], "inconclusive")

    def test_failing_every_share_returns_the_architectural_blocker(self):
        selected = gate.pacing(self.LADDER, {100: "fail", 50: "fail", 25: "fail"})
        self.assertEqual(selected["verdict"], "handoff")
        self.assertIn("25 permille", selected["reason"])

    def judged(self, verdict, identity=None):
        document = filled()
        q = document["qualification"]
        runs = [{"workload": w, "phase": phase, "permille": permille, "block": 0, "slot": 0, "repeat": 0,
                 "receipts": []}
                for w in q["workloads"] for phase, permille in [(p, 0) for p in gate.PHASES if p != "publish"]
                + [("publish", p) for p in q["pacing"]["ladder_permille"]]]
        for phase in q["phases"].values():
            phase.pop("blocked", None)

        def judge_runs(lane, document, digest, cell, runs, main, candidate):
            admitted = identity(cell) if identity else None
            return {"verdict": verdict[cell[2]], "reasons": [], **({"identity": admitted} if admitted else {})}

        with mock.patch.object(gate, "check", return_value=[]), mock.patch.object(gate, "judge_runs", judge_runs):
            return gate.judge(document, DIGEST, IDS, {"campaign": CAMPAIGN, "main": MAIN, "candidate": CANDIDATE,
                                                      "safety": SAFETY, "runs": runs}, Lane())

    def test_a_stepped_past_share_does_not_fail_the_campaign(self):
        """Publish cells reach the verdict only through the selection, so a failed 10% share beside a passing 5% share
        leaves the campaign short only of the blocked recovery."""
        receipt = self.judged({100: "fail", 50: "pass", 25: "pass", 0: "pass"})
        self.assertEqual(receipt["cells"]["request-weighted/publish/100"]["verdict"], "fail")
        self.assertEqual(receipt["pacing"], {"verdict": "pass", "permille": 50})
        self.assertEqual(receipt["recovery"]["verdict"], "inconclusive")
        self.assertEqual(receipt["verdict"], "inconclusive")

    def test_admitted_cells_on_more_than_one_identity_leave_the_campaign_inconclusive(self):
        """Each cell's runs share one identity, and the campaign's admitted cells share it too: a cell admitted on
        another host pair is named beside the first admitted cell, and a cell that admitted no runs is passed over."""
        one = {"toolchain": {"rustc": "1"}, "owner": {"instance": "i-owner", "volumes": ["vol-1"]}}
        other = {"toolchain": {"rustc": "1"}, "owner": {"instance": "i-owner-2", "volumes": ["vol-2"]}}
        verdicts = {100: "pass", 50: "pass", 25: "pass", 0: "pass"}

        def named(receipt):
            return [reason for reason in receipt["reasons"] if "request-weighted/idle/0" in reason]

        self.assertEqual(named(self.judged(verdicts, lambda cell: one)), [])
        mixed = named(self.judged(verdicts, lambda cell: other if cell[:2] == ("large-object", "idle") else one))
        self.assertEqual(len(mixed), 1, mixed)
        self.assertIn("['large-object/idle/0']", mixed[0])
        self.assertEqual(named(self.judged(verdicts, lambda cell: None if cell[0] == "large-object" else one)), [])
        toolchain = {**one, "toolchain": {"rustc": "2"}}
        self.assertEqual(len(named(self.judged(verdicts, lambda cell: toolchain if cell[1] == "scan" else one))), 1)

    def test_an_inconclusive_share_stops_the_ladder_instead_of_stepping_down(self):
        receipt = self.judged({100: "inconclusive", 50: "pass", 25: "pass", 0: "pass"})
        self.assertEqual(receipt["pacing"]["verdict"], "inconclusive")
        self.assertIsNone(receipt["pacing"]["permille"])


class Safety(unittest.TestCase):
    def test_a_guarded_campaign_has_no_gap(self):
        self.assertEqual(gate.safety_gaps(SAFETY, CAMPAIGN), [])
        self.assertEqual(gate.safety_gaps({**SAFETY, "budget_usd": 10 ** 400}, CAMPAIGN), [])

    def test_each_missing_guard_is_exactly_its_gap(self):
        untagged = "i-1 lacks the campaign tag or the ownership guard"
        no_ids = "no create, teardown, standing or preexisting-resource record of non-empty string ids"
        edits = {
            "untagged create": ({"resources": [{"id": "i-1", "tags": {"owner": "qualification"}}]}, [untagged]),
            "no owner": ({"owner": ""}, ["no ownership guard", untagged]),
            "no budget": ({"budget_usd": 0}, ["no budget or UTC deadline"]),
            "no deadline": ({"deadline": "soon"}, ["no budget or UTC deadline"]),
            "an impossible deadline": ({"deadline": "2031-02-30T00:00:00Z"}, ["no budget or UTC deadline"]),
            "no teardown on failure": ({"teardown_on_failure": False}, ["no teardown on failure"]),
            "a preexisting resource torn down": ({"teardown": ["i-1", "vol-other"]},
                                                 ["the campaign touched preexisting resources ['vol-other']",
                                                  "teardown ['i-1', 'vol-other'] is not every create ['i-1']"]),
            "no preexisting inventory": ({"preexisting": None}, [no_ids]),
            "a create with no id": ({"resources": [{"tags": {}}], "teardown": [None]}, [no_ids]),
            "a create never torn down": ({"teardown": []}, ["teardown [] is not every create ['i-1']"]),
            "no standing list": ({"standing": None}, [no_ids]),
            "a standing id that is no string": ({"standing": ["i-owner", 7]}, [no_ids]),
            "an empty standing id": ({"standing": [""]}, [no_ids]),
            "a create also listed as standing": ({"standing": ["i-1"]},
                                                 ["standing resources ['i-1'] are also creates or torn down"]),
            "a standing resource torn down": ({"standing": ["i-owner"], "teardown": ["i-1", "i-owner"]},
                                              ["standing resources ['i-owner'] are also creates or torn down",
                                               "teardown ['i-1', 'i-owner'] is not every create ['i-1']"]),
            "a preexisting resource listed as standing": (
                {"standing": ["vol-other"]}, ["the campaign touched preexisting resources ['vol-other']"]),
            "residue found": ({"residue": ["i-1"]}, ["residue verification found ['i-1']"]),
        }
        for name, (edit, gaps) in edits.items():
            with self.subTest(name):
                self.assertEqual(gate.safety_gaps({**SAFETY, **edit}, CAMPAIGN), gaps)
        self.assertEqual(gate.safety_gaps(None, CAMPAIGN), ["the campaign records no safety manifest"])
        for campaign in (None, "", "c2"):
            with self.subTest(campaign=campaign):
                self.assertIn("the campaign's dedicated tag must carry the campaign id",
                              gate.safety_gaps(SAFETY, campaign))

    def test_each_bound_host_and_volume_is_a_guarded_create_or_a_standing_resource(self):
        """`bound` holds the host instances and volumes the admitted runs' receipts name. Each of those ids is a
        create the manifest guards or a resource it declares standing; an id in neither list, or in the list the
        campaign must leave alone, is a gap."""
        guarded = {"kestrike-campaign": CAMPAIGN, "owner": "qualification"}

        def created(*ids):
            return {"resources": [{"id": i, "tags": guarded} for i in ids], "teardown": list(ids)}

        neither = "the admitted runs bind {}, which the safety manifest lists neither as creates nor as standing"
        cases = {
            "every bound id standing": ({}, []),
            "every bound id a guarded create": ({**created("i-owner", "i-client", "vol-1"), "standing": []}, []),
            "hosts standing and the volume a create": ({**created("vol-1"), "standing": ["i-owner", "i-client"]}, []),
            "no bound id listed": ({"standing": []}, [neither.format(["i-client", "i-owner", "vol-1"])]),
            "no list at all": ({**created(), "standing": []}, [neither.format(["i-client", "i-owner", "vol-1"])]),
            "the volume unlisted": ({"standing": ["i-owner", "i-client"]}, [neither.format(["vol-1"])]),
            "a host unlisted beside creates": ({**created("i-owner", "vol-1"), "standing": []},
                                               [neither.format(["i-client"])]),
            "a bound volume the campaign must leave alone": (
                {"preexisting": ["vol-1"], "standing": ["i-owner", "i-client"]},
                ["the campaign touched preexisting resources ['vol-1']"]),
            "a bound host the campaign must leave alone, listed as standing": (
                {"preexisting": ["i-owner"]}, ["the campaign touched preexisting resources ['i-owner']"]),
        }
        for name, (safety, gaps) in cases.items():
            with self.subTest(name):
                self.assertEqual(gate.safety_gaps({**SAFETY, **safety}, CAMPAIGN, {"i-owner", "i-client", "vol-1"}),
                                 gaps)


@functools.cache
def body(latency_us, shift):
    """The sample lines of one run: request i's latency is `latency_us + (i + shift) % 100`, so runs with distinct
    shifts hold distinct lines but one latency multiset, since 25,000 is a multiple of 100."""
    weights = DOCUMENT["qualification"]["workloads"][CELL[0]]["weights"]
    rows = ((i * 1_000_000 // RATE, gate.draw(SEED, i, weights)) for i in range(REQUESTS))
    return "".join(f'[{t},{t},{t},{t + latency_us + (i + shift) % 100},{r},"hit",0]\n' for i, (t, r) in enumerate(rows))


class Judge(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hit-gate-")
        self.addCleanup(temp.cleanup)
        self.dir = Path(temp.name)
        self.document = filled()
        self.q = self.document["qualification"]

    def samples_text(self, latency_us, previous, shift=0, rows=None, **header):
        spec = self.q["workloads"][CELL[0]]
        head = {"workload": CELL[0], "records": spec["records"], "weights": spec["weights"], "rate": RATE,
                "requests": REQUESTS, "seed": SEED, "previous": previous, "slots": 2, "source": 0,
                "started_unix_ms": 0, **header}
        return json.dumps(head) + "\n" + (body(latency_us, shift) if rows is None else rows)

    def write_run(self, position, revision, text, count=REQUESTS, observed=1):
        block, slot, repeat = position
        fields = {"campaign": CAMPAIGN, "workload": CELL[0], "phase": CELL[1], "permille": CELL[2],
                  "block": block, "slot": slot, "repeat": repeat}
        episode = self.q["interface"]["run_identity"].format(**fields)
        path = self.dir / f"{episode}.samples"
        path.write_text(text)
        detail = f"samples {count} hits {count} sha256 {hashlib.sha256(text.encode()).hexdigest()}"
        receipts = []
        for role, cases in self.q["interface"]["roles"].items():
            mappings = {"functions": [f"0000:00:1{role[0]}.0"], "volume": "vol-1" if role == "owner" else None,
                        "address": ADDRESS[role], "sha256": hashlib.sha256(role.encode()).hexdigest()}
            case = {"id": cases[0], "inputs": {"KESTRIKE_HIT_SAMPLES": str(path), "KESTRIKE_PEER": PEER[role]},
                    "mappings": mappings, "mappings_after": mappings["sha256"],
                    "observed": [{"name": "hit-gate", "detail": detail}] * observed if cases[0] == self.q["cell"] else []}
            hardware = {"role": role, "episode": episode, "revision": revision, "host": {"instance": f"i-{role}"},
                        "toolchain": {"rustc": "1", "cargo": "1"}, "dependencies": ["d"],
                        "build_environment": dict(BUILD), "cases": [case]}
            (self.dir / f"{episode}.{role}.json").write_text(json.dumps({"hardware": hardware}))
            receipts.append(str(self.dir / f"{episode}.{role}.json"))
        return {**{k: fields[k] for k in gate.RUN_FIELDS[1:]}, "receipts": receipts}

    def campaign(self, b_us=200, unchained=None, text=None):
        """The cell's schedule run in order, each run's samples naming its predecessor's digest, except run
        `unchained`, which names none; `text(index, previous)` replaces a run's samples when it returns them."""
        runs, previous = [], "none"
        for index, row in enumerate(gate.schedule(SEED, CELL, self.q["protocol"])):
            written = text(index, previous) if text else None
            if written is None:
                written = self.samples_text(200 if row[4] or row[3] == "A" else b_us,
                                            "none" if index == unchained else previous, shift=index)
            revision = MAIN if row[4] or row[3] == "A" else CANDIDATE
            runs.append(self.write_run(row[:3], revision, written))
            previous = hashlib.sha256(written.encode()).hexdigest()
        return {"campaign": CAMPAIGN, "main": MAIN, "candidate": CANDIDATE, "safety": SAFETY, "runs": runs}

    def edit_receipts(self, campaign, index, edit):
        """Applies `edit(role, section)` to every receipt of campaign run `index`."""
        for path in campaign["runs"][index]["receipts"]:
            receipt = json.loads(Path(path).read_text())
            edit(receipt["hardware"]["role"], receipt["hardware"])
            Path(path).write_text(json.dumps(receipt))

    def judged(self, campaign):
        return gate.judge(self.document, DIGEST, IDS, campaign, Lane())

    def idle(self, campaign):
        return self.judged(campaign)["cells"]["request-weighted/idle/0"]

    def test_bound_runs_of_a_filled_manifest_pass_their_cell_and_render_a_receipt(self):
        campaign = self.campaign()
        receipt = self.judged(campaign)
        cell = receipt["cells"]["request-weighted/idle/0"]
        self.assertEqual(receipt["envelope"], gate.ENVELOPE)
        self.assertEqual(cell["verdict"], "pass", cell)
        self.assertEqual([entry["id"] for entry in cell["runs"]],
                         [self.q["interface"]["run_identity"].format(campaign=CAMPAIGN, workload=CELL[0], phase=CELL[1],
                                                                     permille=0, block=r[0], slot=r[1], repeat=r[2])
                          for r in gate.schedule(SEED, CELL, self.q["protocol"])])
        self.assertEqual(cell["identity"]["owner"]["volumes"], ["vol-1"])
        self.assertEqual({role: cell["identity"][role]["address"] for role in ADDRESS}, ADDRESS)
        built = hashlib.sha256(json.dumps(["d"]).encode()).hexdigest()
        self.assertEqual(cell["identity"].get("dependencies"), {"main": built, "candidate": built},
                         "the identity the campaign compares names each revision's dependency set")
        self.assertEqual((receipt["main"], receipt["candidate"], receipt["seed"]), (MAIN, CANDIDATE, SEED))
        self.assertEqual(receipt["judge_sha256"], hashlib.sha256((ROOT / "scripts/hit-gate.py").read_bytes()).hexdigest())
        self.assertEqual(receipt["recovery"]["verdict"], "inconclusive")
        self.assertEqual(receipt["pacing"]["verdict"], "inconclusive", "no publish cell was measured")
        self.assertEqual(receipt["cells"]["large-object/idle/0"]["reasons"], ["no runs of the declared cell"])
        self.assertEqual(receipt["verdict"], "inconclusive")
        json.loads(json.dumps(receipt))

    def test_a_failed_preservation_qualification_is_the_handoff(self):
        self.q["preservation"]["qualified"] = False
        receipt = self.judged(self.campaign())
        self.assertEqual(receipt["verdict"], "handoff")
        self.assertEqual(receipt["handoff"]["obligation"], "takeover-history-suffix-damage-qualification-failure")

    def test_a_regressed_candidate_fails_its_cell(self):
        receipt = self.judged(self.campaign(b_us=800))
        self.assertEqual(receipt["cells"]["request-weighted/idle/0"]["verdict"], "fail")
        self.assertEqual(receipt["verdict"], "fail")

    def test_each_unbound_or_mismatched_run_moves_a_passing_cell_off_pass(self):
        def samples_path(campaign, index):
            client = json.loads(Path(campaign["runs"][index]["receipts"][1]).read_text())["hardware"]
            return Path(client["cases"][0]["inputs"]["KESTRIKE_HIT_SAMPLES"])

        def faster_first_sample(campaign):
            path = samples_path(campaign, 0)
            lines = path.read_text().splitlines()
            first = json.loads(lines[1])
            first[3] -= 50
            path.write_text("\n".join([lines[0], json.dumps(first, separators=(",", ":")), *lines[2:]]) + "\n")

        def run5(edit):
            return lambda campaign: self.edit_receipts(campaign, 5, edit)

        def owner(**fields):
            return run5(lambda role, s: s.update(fields) if role == "owner" else None)

        def every_role(**fields):
            return run5(lambda role, s: s.update(fields))

        def owner_case(**fields):
            return run5(lambda role, s: s["cases"][0]["mappings"].update(fields) if role == "owner" else None)

        def client_case(edit):
            return run5(lambda role, s: edit(s["cases"][0]) if role == "client" else None)

        def peer(role, value):
            return run5(lambda r, s: s["cases"][0]["inputs"].update(KESTRIKE_PEER=value) if r == role else None)

        def address(role, value):
            return run5(lambda r, s: s["cases"][0]["mappings"].update(address=value) if r == role else None)

        def after(role, edit):
            return run5(lambda r, s: edit(s["cases"][0]) if r == role else None)

        def another_pair(campaign):
            address("owner", "10.0.1.6")(campaign)
            peer("client", "10.0.1.6")(campaign)

        tampers = {
            "a samples file other than the one printed": (faster_first_sample, "is not the one the cell printed"),
            "a candidate revision other than the receipts'": (lambda c: c.update(candidate="c" * 40),
                                                               "the campaign id is not"),
            "a missing run": (lambda c: c["runs"].pop(), "not exactly the cell's schedule"),
            "a foreign episode": (every_role(episode="e-other"), "ran in another episode"),
            "a duplicated observe line": (client_case(lambda case: case.update(observed=case["observed"] * 2)),
                                          "printed 2 hit-gate sample lines"),
            "no observe line": (client_case(lambda case: case.update(observed=[])), "printed 0 hit-gate sample lines"),
            "a second hit-gate line of another shape": (
                client_case(lambda case: case["observed"].append({"name": "hit-gate", "detail": "samples many"})),
                "printed 2 hit-gate sample lines"),
            "one hit-gate line of another shape": (
                client_case(lambda case: case.update(observed=[{"name": "hit-gate", "detail": "samples many"}])),
                "hit-gate line 'samples many'"),
            "another host": (owner(host={"instance": "i-other"}), "differ in host, volume"),
            "another volume": (owner_case(volume="vol-2"), "differ in host, volume"),
            "other owner functions": (owner_case(functions=["0000:00:1f.1"]), "differ in host, volume"),
            "no volume": (owner_case(volume=None), "records no bound volume"),
            "a volume that is no string": (owner_case(volume=7), "records a malformed volume"),
            "no host instance": (owner(host={}), "records no host instance"),
            "a client routed to another owner": (peer("client", "10.0.1.99"), "routes to '10.0.1.99'"),
            "a client peer padded with a space": (peer("client", ADDRESS["owner"] + " "), "routes to"),
            "an owner that lists another client": (peer("owner", "10.0.1.8"), "owner lists peers ['10.0.1.8']"),
            "an owner that lists a second client": (peer("owner", ADDRESS["client"] + ",10.0.1.8"),
                                                    "owner lists peers"),
            "an owner with no peer input": (run5(lambda r, s: s["cases"][0]["inputs"].pop("KESTRIKE_PEER")
                                                 if r == "owner" else None), "owner lists peers"),
            "an owner receipt with no address": (address("owner", None), "role owner records no ENI address"),
            "a client receipt with no address": (address("client", None), "role client records no ENI address"),
            "an address that is no string": (address("owner", 7), "role owner records no ENI address"),
            "another owner address on one run": (another_pair, "differ in host, volume"),
            "an owner mappings file replaced during its case": (
                after("owner", lambda case: case.update(mappings_after="0" * 64)), "role owner's mappings file"),
            "a client mappings file replaced during its case": (
                after("client", lambda case: case.update(mappings_after="0" * 64)), "role client's mappings file"),
            "a mappings file unreadable at its case's end": (
                after("owner", lambda case: case.update(mappings_after=None)), "role owner's mappings file"),
            "a receipt with no digest at its case's end": (
                after("client", lambda case: case.pop("mappings_after")), "role client's mappings file"),
            "a receipt with neither mappings digest": (
                after("owner", lambda case: (case.pop("mappings_after"), case["mappings"].pop("sha256"))),
                "role owner's mappings file"),
            "another toolchain": (every_role(toolchain={"rustc": "2", "cargo": "1"}), "toolchain"),
            "another main dependency set": (every_role(dependencies=["e"]), "built different dependencies"),
            "another build environment": (every_role(build_environment={"CARGO_PROFILE_DEV_OPT_LEVEL": "0"}),
                                          "built under another environment"),
        }
        for name, (tamper, reason) in tampers.items():
            with self.subTest(name):
                campaign = self.campaign()
                tamper(campaign)
                cell = self.idle(campaign)
                self.assertEqual(cell["verdict"], "inconclusive", cell)
                self.assertTrue(any(reason in r for r in cell["reasons"]), cell["reasons"])

    def test_a_cell_routed_to_another_owner_in_every_run_is_inconclusive(self):
        """The client's peer input is the same in every run and names an address other than the one the credited
        owner's mappings bind, so equal inputs across runs do not admit the cell."""
        campaign = self.campaign()
        for index in range(len(campaign["runs"])):
            self.edit_receipts(campaign, index, lambda role, s: s["cases"][0]["inputs"].update(
                KESTRIKE_PEER="10.0.1.99") if role == "client" else None)
        cell = self.idle(campaign)
        self.assertEqual(cell["verdict"], "inconclusive", cell)
        self.assertTrue(any("routes to '10.0.1.99'" in r for r in cell["reasons"]), cell["reasons"])

    def test_an_owner_that_binds_no_volume_is_inconclusive_whatever_the_client_binds(self):
        """The owner serves the measured volume, so its receipt must name one; a volume the client's mappings file
        binds stands in for none."""
        campaign = self.campaign()

        def swap(role, section):
            section["cases"][0]["mappings"].update(volume=None if role == "owner" else "vol-9")

        for index in range(len(campaign["runs"])):
            self.edit_receipts(campaign, index, swap)
        cell = self.idle(campaign)
        self.assertEqual(cell["verdict"], "inconclusive", cell)
        self.assertTrue(any("role owner records no bound volume" in r for r in cell["reasons"]), cell["reasons"])

    def test_roles_that_record_one_eni_address_are_inconclusive(self):
        """Two hosts' ENIs hold two addresses. Receipts whose owner and client record one address make each peer
        input name its own role's address, so the route binding shows nothing and the cell is inconclusive."""
        campaign = self.campaign()

        def one_address(role, section):
            case = section["cases"][0]
            case["mappings"].update(address=ADDRESS["owner"])
            case["inputs"].update(KESTRIKE_PEER=ADDRESS["owner"])

        for index in range(len(campaign["runs"])):
            self.edit_receipts(campaign, index, one_address)
        cell = self.idle(campaign)
        self.assertEqual(cell["verdict"], "inconclusive", cell)
        self.assertTrue(any(f"share the ENI address '{ADDRESS['owner']}'" in r for r in cell["reasons"]),
                        cell["reasons"])

    def test_roles_that_share_one_host_are_inconclusive(self):
        """The gate measures a remote client. Receipts whose owner and client name one instance, each with its own
        ENI address, bind no host pair, so the cell is inconclusive in every run."""
        campaign = self.campaign()
        for index in range(len(campaign["runs"])):
            self.edit_receipts(campaign, index, lambda role, s: s.update(host={"instance": "i-one"}))
        cell = self.idle(campaign)
        self.assertEqual(cell["verdict"], "inconclusive", cell)
        self.assertTrue(any("share the host 'i-one'" in r for r in cell["reasons"]), cell["reasons"])

    def test_an_owner_list_is_read_as_the_cell_reads_it(self):
        """The owner cell trims each entry of its peer list, so a padded entry that names the client is admitted."""
        campaign = self.campaign()
        for index in range(len(campaign["runs"])):
            self.edit_receipts(campaign, index, lambda role, s: s["cases"][0]["inputs"].update(
                KESTRIKE_PEER=f" {ADDRESS['client']} ") if role == "owner" else None)
        self.assertEqual(self.idle(campaign)["verdict"], "pass")

    def test_the_candidate_may_resolve_other_dependencies_than_main(self):
        campaign = self.campaign()
        rows = gate.schedule(SEED, CELL, self.q["protocol"])
        for index, row in enumerate(rows):
            if not row[4] and row[3] == "B":
                self.edit_receipts(campaign, index, lambda role, s: s.update(dependencies=["d", "e"]))
        self.assertEqual(self.idle(campaign)["verdict"], "pass")

    def test_a_run_with_another_client_plan_is_inconclusive(self):
        def text(index, previous):
            return self.samples_text(200, previous, shift=index, slots=3) if index == 4 else None

        cell = self.idle(self.campaign(text=text))
        self.assertEqual(cell["reasons"], ["Refusal: the runs differ in client slots or source"])

    def test_a_run_not_chained_to_its_predecessor_is_inconclusive(self):
        cell = self.idle(self.campaign(unchained=2))
        self.assertEqual(cell["verdict"], "inconclusive")
        self.assertIn("names none as its predecessor", cell["reasons"][0])
        self.assertIn("did not run in schedule order", cell["reasons"][0])

    def test_control_a_run_that_reuses_another_runs_lines_under_a_chained_header_is_inconclusive(self):
        def text(index, previous):
            return self.samples_text(200, previous, shift=0) if index == 3 else None

        cell = self.idle(self.campaign(text=text))
        self.assertEqual(cell["reasons"], ["Refusal: two runs hold the same sample lines"])

    def test_the_safety_manifest_is_asked_about_the_hardware_an_admitted_cell_binds(self):
        """The receipts of an admitted cell bind two host instances and the owner's volume, and the judge asks the
        safety manifest about those three ids. A manifest that lists none of them is the campaign's one reason, with
        the three named, and the cell's own verdict stays as judged."""
        receipt = self.judged({**self.campaign(), "safety": {**SAFETY, "standing": []}})
        cell = receipt["cells"]["request-weighted/idle/0"]
        self.assertEqual(cell["verdict"], "pass", cell)
        self.assertEqual((cell["identity"]["owner"]["instance"], cell["identity"]["client"]["instance"],
                          cell["identity"]["owner"]["volumes"]), ("i-owner", "i-client", ["vol-1"]))
        self.assertEqual(receipt["reasons"], ["the admitted runs bind ['i-client', 'i-owner', 'vol-1'], which the "
                                              "safety manifest lists neither as creates nor as standing"])

    def test_the_safety_manifest_is_asked_about_runs_admitted_before_their_cell_is_refused(self):
        """Run 5 breaks the chain, so the cell is refused and has no identity. `admit` returned for runs 0 to 5, whose
        receipts bind the two hosts and the owner's volume, so the safety manifest is asked about those three ids
        beside the cell's own refusal. With run 5 on a volume the campaign must leave alone, that volume is the
        campaign's reason: the ids are the union over the runs, the chain-breaking one included."""
        campaign = self.campaign(unchained=5)
        receipt = self.judged({**campaign, "safety": {**SAFETY, "standing": []}})
        cell = receipt["cells"]["request-weighted/idle/0"]
        self.assertEqual(cell["verdict"], "inconclusive", cell)
        self.assertNotIn("identity", cell)
        self.assertEqual(receipt["reasons"], ["the admitted runs bind ['i-client', 'i-owner', 'vol-1'], which the "
                                              "safety manifest lists neither as creates nor as standing"])
        self.assertEqual(cell["bound"], ["i-client", "i-owner", "vol-1"])

        def other_volume(role, section):
            if role == "owner":
                section["cases"][0]["mappings"]["volume"] = "vol-other"

        self.edit_receipts(campaign, 5, other_volume)
        receipt = self.judged(campaign)
        self.assertIn("names none as its predecessor", receipt["cells"]["request-weighted/idle/0"]["reasons"][0])
        self.assertEqual(receipt["reasons"], ["the campaign touched preexisting resources ['vol-other']"])

    def test_a_cell_that_admits_no_run_binds_no_hardware_for_the_safety_manifest(self):
        """Run 0's receipts name another episode, so `admit` refuses it and the cell admits no run. A refused run
        adds no id and admission stops there, so the later runs, whose receipts bind the two hosts and the volume,
        add none either: the cell binds nothing and the safety manifest is asked about no hardware."""
        campaign = {**self.campaign(), "safety": {**SAFETY, "standing": []}}
        self.edit_receipts(campaign, 0, lambda role, section: section.update(episode="e-other"))
        receipt = self.judged(campaign)
        cell = receipt["cells"]["request-weighted/idle/0"]
        self.assertIn("ran in another episode", cell["reasons"][0])
        self.assertEqual(cell["bound"], [])
        self.assertEqual(receipt["reasons"], [])

    def test_campaign_level_defects_are_named_in_the_receipt(self):
        cases = {
            "a retried repeat": (lambda c: c["runs"].append(dict(c["runs"][0])), "repeats an identity"),
            "an unguarded campaign": (lambda c: c.update(safety=None), "the campaign records no safety manifest"),
            "one revision for both arms": (lambda c: c.update(candidate=MAIN), "no distinct main and candidate revisions"),
            "no candidate": (lambda c: c.pop("candidate"), "no distinct main and candidate revisions"),
            "another campaign id": (lambda c: c.update(campaign="c2"), f"the campaign id is not {CAMPAIGN}"),
        }
        for name, (tamper, reason) in cases.items():
            with self.subTest(name):
                campaign = self.campaign()
                tamper(campaign)
                receipt = self.judged(campaign)
                self.assertIn(reason, " / ".join(receipt["reasons"]))
                self.assertEqual(receipt["verdict"], "inconclusive")
        campaign = self.campaign()
        campaign.update(candidate=MAIN)
        self.assertEqual(self.idle(campaign)["reasons"], ["no distinct main and candidate revisions"])
        self.q["protocol"]["position_hits"] = None
        with mock.patch.object(gate, "check", return_value=[]):
            self.assertEqual(self.idle(self.campaign())["reasons"], ["no predeclared protocol"])

    def test_a_relocated_samples_artifact_is_judged_by_its_printed_digest(self):
        for altered in (False, True):
            with self.subTest(altered=altered):
                campaign = self.campaign()
                for index, run in enumerate(campaign["runs"]):
                    client = json.loads(Path(run["receipts"][1]).read_text())["hardware"]
                    copied = self.dir / f"collected-{altered}-{index}.samples"
                    Path(client["cases"][0]["inputs"]["KESTRIKE_HIT_SAMPLES"]).rename(copied)
                    if altered and index == 0:
                        copied.write_bytes(copied.read_bytes().replace(b'"hit",0]', b'"hit",1]', 1))
                    run["samples"] = str(copied)
                cell = self.idle(campaign)
                self.assertEqual(cell["verdict"], "inconclusive" if altered else "pass", cell["reasons"])
                if altered:
                    self.assertIn("is not the one the cell printed", cell["reasons"][0])

    def bind(self, text, count=REQUESTS):
        """A client section and run whose printed digest binds `text` and prints `count` samples."""
        run = self.write_run((0, 0, 0), MAIN, text, count=count)
        section = json.loads(Path(run["receipts"][1]).read_text())["hardware"]
        return section, {**run, "workload": CELL[0]}

    def test_the_judge_admits_the_cells_intended_times_at_a_rate_that_leaves_a_remainder(self):
        """At 3 GETs per second the cell intends request i at floor(i * 1,000,000 / 3) us, the values
        net::host_pair_tests::hit_gate::the_schedule_draws_records_by_the_workload_weights pins. The judge admits
        those five samples and refuses the same samples spaced by the truncated interval, 333,333 us."""
        self.q["offered_rate"], self.q["protocol"]["requests"] = 3, 5

        def bound(intended):
            rows = "".join(f'[{t},{t},{t},{t + 200},{gate.draw(SEED, i, [1, 1, 1, 1])},"hit",0]\n'
                           for i, t in enumerate(intended))
            section, run = self.bind(self.samples_text(200, "none", rate=3, requests=5, rows=rows), count=5)
            return gate.bound_samples(section, run, self.q, SEED)[1]

        self.assertEqual([s[gate.INTENDED] for s in bound([0, 333_333, 666_666, 1_000_000, 1_333_333])],
                         [0, 333_333, 666_666, 1_000_000, 1_333_333])
        with self.assertRaisesRegex(gate.Refusal, "sample 3's intended send is off the fixed-interval"):
            bound([i * 333_333 for i in range(5)])

    def test_samples_of_another_plan_are_refused_by_the_rule_that_names_it(self):
        def spaced(rate, n):
            return "".join(f'[{i * 1_000_000 // rate},{i * 1_000_000 // rate},{i * 1_000_000 // rate},'
                           f'{i * 1_000_000 // rate + 200},'
                           f'{gate.draw(SEED, i, [1, 1, 1, 1])},"hit",0]\n' for i in range(n))

        cases = {
            "another rate": (self.samples_text(200, "none", rate=1000, rows=spaced(1000, REQUESTS)), REQUESTS,
                             "another rate, request count or seed"),
            "another seed": (self.samples_text(200, "none", seed=SEED + 1), REQUESTS,
                             "another rate, request count or seed"),
            "another workload": (self.samples_text(200, "none", weights=[0, 0, 1, 0]), REQUESTS, "another workload"),
            "a short run printed and written whole": (self.samples_text(200, "none", requests=10, rows=spaced(RATE, 10)),
                                                      10, "another count than the protocol's"),
            "a printed count off the file": (self.samples_text(200, "none"), REQUESTS - 1,
                                             "another count than the protocol's"),
            "more lines than declared": (self.samples_text(200, "none") + "not json\n" * 5, REQUESTS,
                                         "another count than the protocol's"),
            "a boolean slots value": (self.samples_text(200, "none", slots=True), REQUESTS, "header field is malformed"),
            "a negative start": (self.samples_text(200, "none", started_unix_ms=-1), REQUESTS,
                                 "header field is malformed"),
            "a malformed predecessor": (self.samples_text(200, "x"), REQUESTS, "header field is malformed"),
            "an uppercase predecessor": (self.samples_text(200, "A" * 64), REQUESTS, "header field is malformed"),
        }
        for name, (text, count, reason) in cases.items():
            with self.subTest(name):
                section, run = self.bind(text, count)
                with self.assertRaisesRegex(gate.Refusal, reason):
                    gate.bound_samples(section, run, self.q, SEED)
        section, run = self.bind("[]\n" + body(200, 0))
        with self.assertRaisesRegex(gate.Refusal, "header keys"):
            gate.bound_samples(section, run, self.q, SEED)

    def test_a_malformed_or_off_schedule_sample_is_refused(self):
        t, r = 1_000_000 // RATE, gate.draw(SEED, 1, [1, 1, 1, 1])
        cases = {
            "a boolean intended send": ([True, 0, 0, 5, r, "hit", 0], "is not"),
            "a first attempt before the intended send": ([t, t - 1, t, t + 5, r, "hit", 0], "is not"),
            "an admission before the first attempt": ([t, t + 2, t + 1, t + 5, r, "hit", 0], "is not"),
            "an end before the admission": ([t, t, t + 9, t + 5, r, "hit", 0], "is not"),
            "a sample with no first attempt": ([t, t, t + 5, r, "hit", 0], "is not"),
            "an unknown stratum": ([t, t, t + 5, r, "cached", 0], "is not"),
            "a float record": ([t, t, t, t + 5, float(r), "hit", 0], "is not"),
            "a boolean record": ([t, t, t, t + 5, True, "hit", 0], "is not"),
            "a record past the workload": ([t, t, t, t + 5, 4, "hit", 0], "is not"),
            "an intended send off the schedule": ([t + 1, t + 1, t + 1, t + 5, r, "hit", 0], "off the fixed-interval"),
            "a record other than the draw": ([t, t, t, t + 5, (r + 1) % 4, "hit", 0], "seeded draw"),
        }
        for name, (sample, reason) in cases.items():
            with self.subTest(name):
                lines = self.samples_text(200, "none").splitlines()
                section, run = self.bind("\n".join([lines[0], lines[1], json.dumps(sample), *lines[3:]]) + "\n")
                with self.assertRaisesRegex(gate.Refusal, reason):
                    gate.bound_samples(section, run, self.q, SEED)

    def test_malformed_campaigns_and_run_coordinates_are_refused(self):
        for name, campaign in {"a list": [], "no id": {"runs": []}, "an empty id": {"campaign": "", "runs": []}}.items():
            with self.subTest(name), self.assertRaises(gate.Refusal):
                self.judged(campaign)
        for name, edit in {"a float share": {"permille": 0.0}, "a boolean block": {"block": False},
                           "a negative slot": {"slot": -1}, "a receipts string": {"receipts": "r.json"}}.items():
            with self.subTest(name):
                campaign = self.campaign()
                campaign["runs"][0].update(edit)
                with self.assertRaisesRegex(gate.Refusal, "malformed coordinates"):
                    self.judged(campaign)

    def test_a_cell_outside_the_manifest_is_inconclusive(self):
        campaign = self.campaign()
        for r in campaign["runs"]:
            r.update(phase="publish", permille=30)
        receipt = self.judged(campaign)
        self.assertEqual(receipt["cells"]["request-weighted/publish/30"]["reasons"], ["the cell is outside the manifest"])
        self.assertEqual(receipt["verdict"], "inconclusive")

    def test_blocked_phases_and_workloads_stay_inconclusive_under_the_committed_manifest(self):
        campaign = {"campaign": CAMPAIGN, "main": MAIN, "candidate": CANDIDATE, "safety": SAFETY,
                    "runs": [{"workload": "request-weighted", "phase": "publish", "permille": 100, "block": 0,
                              "slot": 0, "repeat": 0, "receipts": []}]}
        receipt = gate.judge(DOCUMENT, DIGEST, IDS, campaign, Lane())
        publish = receipt["cells"]["request-weighted/publish/100"]
        self.assertEqual(publish["verdict"], "inconclusive")
        self.assertEqual(len(publish["reasons"]), 2, "the workload's and the phase's blockers")
        self.assertEqual(receipt["pacing"]["verdict"], "inconclusive")
        self.assertEqual(receipt["verdict"], "handoff")

    def test_the_real_lane_refuses_receipts_of_another_manifest(self):
        lane = gate.lane_module()
        campaign = self.campaign()
        self.edit_receipts(campaign, 0, lambda role, s: s.update(profile="hit-gate", manifest_sha256="e" * 64))
        for path in campaign["runs"][0]["receipts"]:
            receipt = json.loads(Path(path).read_text())
            Path(path).write_text(json.dumps({**receipt, "envelope": lane.ENVELOPE}))
        run = {**campaign["runs"][0], "id": "r"}
        with self.assertRaisesRegex(gate.Refusal, "ran under manifest_sha256 'e+', not the current manifest's d+"):
            gate.admit(lane, self.document, DIGEST, run, MAIN, SEED)


class Files(unittest.TestCase):
    def test_a_read_stops_at_the_limit(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            path = Path(temp) / "f"
            path.write_bytes(b"x" * 64)
            with mock.patch.object(gate, "READ_LIMIT", 64):
                self.assertEqual(gate.read_file(path, "file"), b"x" * 64)
            with mock.patch.object(gate, "READ_LIMIT", 63), self.assertRaisesRegex(gate.Refusal, "exceeds 63 bytes"):
                gate.read_file(path, "file")

    def test_a_read_refuses_a_file_over_its_callers_limit_before_reading_it(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            path = Path(temp) / "f"
            path.write_bytes(b"x" * 64)
            self.assertEqual(gate.read_file(path, "file", 64), b"x" * 64)
            with mock.patch.object(gate.os, "fdopen", side_effect=AssertionError("the file was read")), \
                    self.assertRaisesRegex(gate.Refusal, "exceeds 63 bytes"):
                gate.read_file(path, "file", 63)

    def test_a_directory_is_refused_by_name(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp, \
                self.assertRaisesRegex(gate.Refusal, "is not a regular file"):
            gate.read_file(temp, "file")


class Command(unittest.TestCase):
    def call(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = gate.main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_the_committed_manifest_checks_and_judges_no_pass(self):
        code, out, _ = self.call("check")
        self.assertEqual(code, 0)
        self.assertIn("the workload manifest declares no offered_rate", json.loads(out)["open"])
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            campaign = Path(temp) / "campaign.json"
            text = json.dumps({"campaign": "c1", "runs": [], "safety": {**SAFETY, "budget_usd": 10 ** 400}})
            campaign.write_text(text)
            code, out, _ = self.call("judge", "--campaign", str(campaign))
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(out)["verdict"], "handoff")
            self.assertEqual(json.loads(out)["campaign_sha256"], hashlib.sha256(text.encode()).hexdigest())
            for text in ("{", "[]", "[" * 100_000, json.dumps({"campaign": "c1", "runs": [{"block": True}]})):
                with self.subTest(text=text[:20]):
                    campaign.write_text(text)
                    code, _, err = self.call("judge", "--campaign", str(campaign))
                    self.assertEqual(code, 2)
                    self.assertIn("refused", err)
        code, _, err = self.call("schedule", "--main", MAIN, "--candidate", CANDIDATE, "--workload",
                                 "request-weighted", "--phase", "idle")
        self.assertEqual(code, 2, "an undeclared protocol has no schedule")

    def test_the_schedule_command_prints_the_judges_campaign_seed_and_order(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            manifest = Path(temp) / "manifest.json"
            document = filled()
            document["platforms"]["x86_64-nitro-ebs"]["supported"] = False
            manifest.write_text(json.dumps(document))
            digest = hashlib.sha256(manifest.read_bytes()).hexdigest()
            seed = gate.campaign_seed(digest, MAIN, CANDIDATE)
            code, out, err = self.call("schedule", "--manifest", str(manifest), "--main", MAIN, "--candidate",
                                       CANDIDATE, "--workload", "request-weighted", "--phase", "idle")
            self.assertEqual(code, 0, err)
            lines = [json.loads(line) for line in out.splitlines()]
            self.assertEqual(lines[0], {"campaign": gate.campaign_id(seed), "seed": seed})
            self.assertEqual([tuple(row.values()) for row in lines[1:]],
                             gate.schedule(seed, CELL, filled()["qualification"]["protocol"]))
            for argv in (("--main", MAIN, "--candidate", MAIN, "--workload", "request-weighted", "--phase", "idle"),
                         ("--main", MAIN, "--candidate", CANDIDATE, "--workload", "request-weighted", "--phase",
                          "publish", "--permille", "30")):
                with self.subTest(argv=argv):
                    code, out, _ = self.call("schedule", "--manifest", str(manifest), *argv)
                    self.assertEqual((code, out), (2, ""))

    def test_a_special_file_is_refused_instead_of_read(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            fifo = Path(temp) / "campaign.json"
            os.mkfifo(fifo)
            code, _, err = self.call("judge", "--campaign", str(fifo))
            self.assertEqual(code, 2)
            self.assertIn("not a regular file", err)

    def test_a_manifest_the_lane_refuses_is_refused(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            manifest = Path(temp) / "manifest.json"
            manifest.write_text(json.dumps({**DOCUMENT, "extra": {}}))
            code, _, err = self.call("check", "--manifest", str(manifest))
            self.assertEqual(code, 2)
            self.assertIn("top-level keys", err)

    def test_the_receipt_replaces_only_a_regular_file_at_the_output_path(self):
        with tempfile.TemporaryDirectory(prefix="hit-gate-") as temp:
            campaign, target, output = (Path(temp) / name for name in ("campaign.json", "target", "receipt.json"))
            campaign.write_text(json.dumps({"campaign": "c1", "runs": []}))
            output.write_text("an earlier receipt\n")
            code, _, _ = self.call("judge", "--campaign", str(campaign), "--output", str(output))
            self.assertEqual(code, 1)
            self.assertEqual(json.loads(output.read_text())["verdict"], "handoff")
            mask = os.umask(0)
            os.umask(mask)
            self.assertEqual(output.stat().st_mode & 0o777, 0o666 & ~mask)
            target.write_text("kept\n")
            output.unlink()
            output.symlink_to(target)
            code, _, err = self.call("judge", "--campaign", str(campaign), "--output", str(output))
            self.assertEqual(code, 2)
            self.assertIn("not a regular file", err)
            self.assertEqual(target.read_text(), "kept\n")
            self.assertTrue(output.is_symlink())
            code, _, err = self.call("judge", "--campaign", str(campaign), "--output", str(Path(temp) / "no" / "r"))
            self.assertEqual(code, 2)
            self.assertIn("refused", err)


if __name__ == "__main__":
    unittest.main()
