#!/usr/bin/env python3
"""Exercise select-tests.py on harness output seeded from real invocations."""

import contextlib
import copy
import importlib.util
import io
import json
import re
import subprocess
import sys
import tempfile
import unittest
import unittest.mock
from collections import Counter
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/select-tests.py"
SPEC = importlib.util.spec_from_file_location("select_tests", SCRIPT)
assert SPEC is not None and SPEC.loader is not None
select_tests = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(select_tests)
RECEIPTS_SPEC = importlib.util.spec_from_file_location("verify_receipts", ROOT / "scripts/verify-receipts.py")
assert RECEIPTS_SPEC is not None and RECEIPTS_SPEC.loader is not None
RECEIPTS = importlib.util.module_from_spec(RECEIPTS_SPEC)
RECEIPTS_SPEC.loader.exec_module(RECEIPTS)
try:
    COMMITTED = json.loads((ROOT / "scripts/test-inventory.json").read_text())
    REGISTRY = json.loads((ROOT / "scripts/test-registry.json").read_text())
    CATALOG = json.loads((ROOT / "verification/obligations.json").read_text())
    INVENTORY = select_tests.load_inventory(select_tests.INVENTORY)
except (OSError, ValueError, select_tests.Refusal) as error:
    raise SystemExit(f"test-select-tests: unreadable inventory, registry or catalog: {error}") from error

IGNORE_ATTRIBUTE = re.compile(
    r'#\[ignore\s*=\s*"((?:[^"\\]|\\.)*)"\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)'
)
MIRI_IGNORE_ATTRIBUTE = re.compile(
    r'#\[cfg_attr\(\s*miri,\s*ignore\s*=\s*"((?:[^"\\]|\\.)*)"\s*,?\s*\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+(\w+)'
)
MIRI_HEADER = "     Running unittests src/lib.rs (/tmp/miri-target/miri/x86_64-unknown-linux-gnu/debug/deps/kestrike-2d37337a438c04e5)"

LOOM_HEADER = "     Running unittests src/lib.rs (/tmp/loom-target/release/deps/kestrike-9b91aa9cade47514)"
CREDIT_MODEL_TESTS = len(INVENTORY["loom"]["credit_model"]["tests"])
LOOM_SUMMARY = (f"test result: ok. {CREDIT_MODEL_TESTS} passed; 0 failed; 0 ignored; 0 measured; 1484 filtered out; "
                "finished in 0.79s")
ORDINARY_HEADER = "     Running unittests src/lib.rs (target/debug/deps/kestrike-b42c7cc1393e6040)"
REQUIRED = INVENTORY["ordinary"]["kestrike"]["required"]["kestrike"]
UNRELATED = [
    "bind::binder_tests::a_bind_that_dies_midway_leaves_a_record_release_restores",
    "storage::writable_tests::with_reads_holding_every_read_slot_a_fill_still_publishes",
]
MODULE_WITNESSES = [
    "net::oracle_endpoint_tests::a_failed_owner_keeps_its_custody_while_a_healthy_owner_serves",
    "oracle::custody_tests::a_cancel_keeps_storage_custody_until_the_exact_terminal",
    "storage::oracle_custody_tests::a_buffer_freed_at_the_cancel_fails_the_live_count",
]
ORDINARY_RUNNABLE = UNRELATED + REQUIRED["tests"] + [name for name in MODULE_WITNESSES if name not in REQUIRED["tests"]]
WORKER_HEADER = "     Running src/worker.rs (target/debug/deps/sim_worker-0123abcd)"
WORKER_REQUIRED = INVENTORY["ordinary"]["kestrike"]["required"]["sim_worker"]
WORKER_CASES = WORKER_REQUIRED["tests"] + ["worker::the_protocol_reports_failures_and_refusals"]
WORKER_IGNORED = INVENTORY["ordinary"]["kestrike"]["ignored"]["sim_worker"]
ORDINARY_IGNORED = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
ASAN_IGNORED = INVENTORY["asan"]["ignored"]["kestrike"]
QUALIFIED_HEADERS = {"campaigns": WORKER_HEADER, "long-run": WORKER_HEADER, "search": ORDINARY_HEADER, "search-nightly": ORDINARY_HEADER,
                     "isa-x86-64": ORDINARY_HEADER, "isa-aarch64": ORDINARY_HEADER}
SEARCH_LISTED = UNRELATED + ["net::serve_search_tests::the_shallow_search_exhausts_its_bound"]
SEARCH_IGNORED = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
CAMPAIGNS = select_tests.selection_of(INVENTORY["qualified"]["campaigns"])
QUALIFIED_LISTED = {
    "campaigns": CAMPAIGNS + WORKER_IGNORED, "long-run": WORKER_CASES + WORKER_IGNORED,
    "search": SEARCH_LISTED + SEARCH_IGNORED, "search-nightly": SEARCH_LISTED + SEARCH_IGNORED,
    **{lane: UNRELATED + select_tests.selection_of(INVENTORY["qualified"][lane]) + ORDINARY_IGNORED for lane in ("isa-x86-64", "isa-aarch64")},
}
QUALIFIED_IGNORED = {"campaigns": WORKER_IGNORED, "long-run": WORKER_IGNORED, "search": SEARCH_IGNORED, "search-nightly": SEARCH_IGNORED,
                     "isa-x86-64": ORDINARY_IGNORED, "isa-aarch64": ORDINARY_IGNORED}
X86_HMAC = "x86_64 avx512f=true avx512bw=true vpclmulqdq=true"
# The run identities of the warm-cycle seeds 1 to 16, as the long-run case prints them.
WARM_CYCLE_IDENTITIES = ["f437f622cbdab38c", "c0ddcf29cfa9ccf5", "cd4a8ecb45591738", "f5d0e913be2b17c5", "f9a96b18bdbc8885", "3c389ac1bd5232f8", "1f78180355903527", "61195ea60eea35dd", "e6d55169e934cd4b", "e254a05032eb110f", "1b65f768eea78011", "a7e8571646ff0d0f", "e54340cc524948a3", "fb7ab2d68c9c6af8", "88753fc9e1f4d728", "2de7dfcabcea0290"]
SLOT_REUSE_IDENTITIES = ["9f73e8a4174670b8", "2eb9a2d95cd8b653", "627f4eee90d30434", "f3d618f882832f57", "7b470cb45f657604", "4ef8c7f33c92e693", "4423bb6fc94b545d", "606fb58a89cccff3", "d6287e173ee6500e", "9089cbdc6c434b82", "7a2c58732c836eed", "b124dba9b8cc5003", "8498278e23e247f7", "a0529f2e9fea1df9", "e404933ae5655daf", "a423cbfbe0581788"]
# Each row's lines as the worker and the search print them on a passing run.
ROW_LINES = {
    "worker-campaigns": [
        f"bundle: {'07' * 32} recorded alike by two fresh processes, complete pass with every obligation fired",
        f"bundle: contended digest {'c0' * 32} recorded alike by two fresh processes and replayed in a third, reaching every chaos point",
        "replay: the planted bundle reproduced in fresh processes; its regression of 28 kept steps reproduced Bytes in another",
        "replay: the acked bundle reproduced in fresh processes; its regression of 29 kept steps reproduced History in another",
        "replay: the corrupted bundle reproduced in fresh processes; its regression of 40 kept steps reproduced Bytes in another",
        "replay: the panicking bundle reduced under its panic in fresh processes; its regression of 28 kept steps reruns to the "
        "run panicked at crates/kestrike/src/net/world_tests.rs:1806:13: a planted panic once the upload published",
        "vocabulary: the old planted bundle decodes 7 declared and 37 carried action codes to their kinds, a complete violation of Bytes",
        "explore: the composed-bounded tree of 5 leaves explored alike in two fresh processes",
        f"cluster: cluster-broad digest {'5c' * 32} recorded alike in two fresh processes and replayed in a third",
        f"session: 3 windows committed and replayed alike by fresh processes, chain {'1e' * 32}",
    ],
    "history-cohorts": [f"cohort: {name} digest {'8d' * 32} ended as declared and replayed in a fresh process"
                        for name in INVENTORY["qualified"]["campaigns"]["rows"][1]["members"]],
    "serve-search-shallow": ["serve-search-shallow: Exhaustive Totals { alphabet: 12, states: 15494, transitions: 34361, "
                             "high_water: 56, memory: 87373319, depth: 5 }"],
    "serve-search-nightly": ["serve-search-nightly: Exhaustive Totals { alphabet: 12, states: 128171, transitions: 305447, "
                             "high_water: 69, memory: 746684190, depth: 6 }"],
    "serve-search-prefinal-ack": ["serve-search-prefinal-ack: Exhaustive Totals { alphabet: 12, states: 70576, transitions: "
                                  "176333, high_water: 87, memory: 455836145, depth: 5 } witnesses: "
                                  "ef-09-completed-held-release ef-09-prefinal-ack-complete"],
    "serve-search-completed-held": ["serve-search-completed-held: Exhaustive Totals { alphabet: 12, states: 30563, transitions: "
                                    "77544, high_water: 72, memory: 206654743, depth: 5 } witnesses: "
                                    "ef-09-completed-held-release ef-09-prefinal-ack-complete"],
    "serve-search-pressed": ["serve-search-pressed: Exhaustive Totals { alphabet: 9, states: 126827, transitions: 349995, "
                             "high_water: 60, memory: 817621270, depth: 7 } activations: 952"],
    "long-run-gate": [
        "long-run: churn: seed 10 collide true actions 409600; 279981 of 409503 checks at the fixture occupancy; "
        "333021 units published, 5371 turnovers",
        "long-run: churn witnesses: 20 situations fired 371060 times, 33 fault members injected 186904 and affected 167405 times",
        "long-run: mixed witnesses: all 8 fired",
        "long-run: marks: device_commands 3/4, device_growth 0/0",
    ],
    "scaled-seeds": [
        *(f"scaled: units=64 slots=16 chunk=8192 reserve=2 seed {seed} collide {str(seed % 4 == 3).lower()} actions 409600: "
          "complete; 365086 of 409503 checks at the fixture occupancy, 113946 units published, 1837 turnovers" for seed in range(12)),
        "scaled: seed witnesses: 20 situations fired 4423628 times, 33 fault members injected 2217312 and affected 1803046 "
        "times; 4001045 of 4914034 checks at the fixture occupancy; lifecycle and poisoned-gate phases ran",
    ],
    "scaled-geometries": [
        *(f"scaled: units={units} slots=33 chunk={chunk} reserve={reserve} seed {seed} collide false actions 409600: complete; "
          "261969 of 409503 checks at the fixture occupancy, 372280 units published, 5909 turnovers"
          for units, chunk, reserve in ((65, 4096, 2), (129, 16384, 32)) for seed in range(12)),
        "scaled: geometry units=65 slots=33 chunk=4096 reserve=2 witnesses: reserve and fragmentation fired; "
        "4410212 of 4914033 checks at the fixture occupancy",
        "scaled: geometry units=129 slots=33 chunk=16384 reserve=32 witnesses: reserve and fragmentation fired; "
        "4089422 of 4914034 checks at the fixture occupancy",
    ],
    "warm-cycles": [
        *(f"cycles: seed {seed} cycles 32: safety pass; containment pass; retention pass; progress pass; quiescent conservation pass; "
          f"publish-aligned conservation inconclusive [no checkpoint or frontier publication follows a quiescent boundary]; "
          f"plateau inconclusive [no accepted plateau band]; identity {identity}"
          for seed, identity in enumerate(WARM_CYCLE_IDENTITIES, start=1)),
        "cycles: census: covered 4 gap 4 undecided 8 not-required 24; gaps [ProcessDeath/qualified-persistence, "
        "ProcessDeath/root-or-admission-publication, HostOrDevice/qualified-persistence, "
        "HostOrDevice/root-or-admission-publication]",
        "cycles: composed: restarts 169 takeovers 112 designated 57 interrupted 64 unknown 44 after-preempt 30 stale "
        "36 fresh-hosts 16 unauthorized 105 damaged 28 repaired 62 landings 127 chain-full 448 fills 81 invalidations "
        "279 captures 512",
        "cycles: unscored: successor checkpoint publication and consolidation; duplicate extents; both roots "
        "affected; log-full and quarantine-full; missing REMOVE and REPLACE dependencies, covered by the directed "
        "suffix histories; a delayed old-tenure write after its successor's fence; a second fresh host; a GET racing "
        "a mutation, excluded by the drain before each mutation; every row unit of the checkpoint damaged, which the "
        "warm load refuses as a whole slot; an INVALIDATE or a flip of a FILL the cycles published",
        "cycles: discovery: 16 seeds of 32 cycles, unpowered; every run passed its four verdicts and its quiescent conservation, "
        "and no run is a confirmation",
    ],
    "publishing-cycles": [
        "publishing: seed 1 cycles 8: every warm load held the published cut plus the suffix; publications 17; fills 29; removals 27; checks 96; suffix loads 7; identity 5ab696ba1ee89fca",
        "publishing: seed 2 cycles 8: every warm load held the published cut plus the suffix; publications 17; fills 29; removals 27; checks 96; suffix loads 7; identity 378c0418eced25bb",
        "publishing: seed 3 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 29; removals 27; checks 96; suffix loads 4; identity e69deda3aa09c116",
        "publishing: seed 4 cycles 8: every warm load held the published cut plus the suffix; publications 18; fills 28; removals 28; checks 96; suffix loads 7; identity 68507c078b8239c1",
        "publishing: seed 5 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 30; removals 26; checks 96; suffix loads 5; identity 3a382ca444f3ce81",
        "publishing: seed 6 cycles 8: every warm load held the published cut plus the suffix; publications 18; fills 28; removals 28; checks 96; suffix loads 5; identity 755620e688ad0083",
        "publishing: seed 7 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 28; removals 28; checks 96; suffix loads 6; identity a669ece6ceb36978",
        "publishing: seed 8 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 29; removals 27; checks 96; suffix loads 5; identity ae402d11d0c6065c",
        "publishing: seed 9 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 29; removals 27; checks 96; suffix loads 6; identity 42f9362c385f6ed6",
        "publishing: seed 10 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 29; removals 27; checks 96; suffix loads 6; identity 0b56a3a2a3982e08",
        "publishing: seed 11 cycles 8: every warm load held the published cut plus the suffix; publications 22; fills 29; removals 27; checks 96; suffix loads 6; identity 25a818c4c15dcdb5",
        "publishing: seed 12 cycles 8: every warm load held the published cut plus the suffix; publications 19; fills 28; removals 28; checks 96; suffix loads 6; identity ce0e7c48f2e7a71b",
        "publishing: seed 13 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 30; removals 26; checks 96; suffix loads 7; identity 306357ef2402290e",
        "publishing: seed 14 cycles 8: every warm load held the published cut plus the suffix; publications 21; fills 29; removals 27; checks 96; suffix loads 5; identity 171fde2ae56d245c",
        "publishing: seed 15 cycles 8: every warm load held the published cut plus the suffix; publications 22; fills 29; removals 27; checks 96; suffix loads 5; identity d2b616348cb9e6d7",
        "publishing: seed 16 cycles 8: every warm load held the published cut plus the suffix; publications 20; fills 29; removals 27; checks 96; suffix loads 5; identity f43ad7dd0185f5b0",
        "publishing: 16 seeds of 8 restarts; publications 321; fills 462; removals 434; checks 1536",
    ],
    "rolling-cycles": [
        "rolling: seed 1 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 0; placement 4; early 2; fills 102; removals 99; checks 108; identity 73c9ef6f253323f1",
        "rolling: seed 2 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 0; slot 2; placement 4; early 2; fills 106; removals 102; checks 108; identity cac9989f212719cf",
        "rolling: seed 3 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 3; slot 1; placement 4; early 0; fills 136; removals 135; checks 108; identity 06226a81e3fcfb10",
        "rolling: seed 4 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 3; slot 3; placement 1; early 1; fills 120; removals 116; checks 108; identity d2b9417e49bc92d3",
        "rolling: seed 5 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 2; placement 2; early 2; fills 102; removals 100; checks 108; identity 789458280012f4bb",
        "rolling: seed 6 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 2; placement 2; early 2; fills 105; removals 102; checks 108; identity fdd623a18ec7dddd",
        "rolling: seed 7 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 1; placement 5; early 1; fills 121; removals 117; checks 108; identity 7ee280abb871c4e2",
        "rolling: seed 8 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 4; placement 1; early 2; fills 106; removals 105; checks 108; identity 3684bc5c5223bd1f",
        "rolling: seed 9 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 3; placement 2; early 1; fills 119; removals 115; checks 108; identity 718720743f70b32f",
        "rolling: seed 10 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 3; placement 1; early 3; fills 90; removals 89; checks 108; identity 000fc3231fef7e5c",
        "rolling: seed 11 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 3; placement 1; early 3; fills 97; removals 95; checks 108; identity c16300b92d900d9f",
        "rolling: seed 12 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 2; placement 2; early 2; fills 106; removals 107; checks 108; identity 9c6c7451c970a795",
        "rolling: seed 13 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 4; placement 1; early 2; fills 105; removals 107; checks 108; identity de04c1d1e1637706",
        "rolling: seed 14 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 2; slot 3; placement 2; early 1; fills 115; removals 111; checks 108; identity c2fd72b039cca769",
        "rolling: seed 15 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 2; placement 2; early 3; fills 94; removals 92; checks 108; identity 12e99220faeb3ab3",
        "rolling: seed 16 cycles 8: every tenure after a roll held every acknowledged mutation; handoff 1; slot 1; placement 3; early 3; fills 89; removals 86; checks 108; identity 83933b03f36b5d8d",
        "rolling: 16 seeds of 8 rolls; handoff 25; slot 36; placement 37; early 30; fills 1713; removals 1678; checks 1728",
    ],
    "handoff-cycles": [
        "handoff: seed 1 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 4; restarts 4; fills 36; removals 35; checks 108; identity 59d3ea764c62f61e",
        "handoff: seed 2 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 5; restarts 3; fills 33; removals 36; checks 108; identity 2bad465d22292ee2",
        "handoff: seed 3 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 7; restarts 1; fills 36; removals 34; checks 108; identity f6c832ae6c9d144b",
        "handoff: seed 4 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 4; restarts 4; fills 36; removals 35; checks 108; identity 5fcc58ac4e7de87d",
        "handoff: seed 5 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 3; restarts 5; fills 35; removals 33; checks 108; identity 97120616cee3c65f",
        "handoff: seed 6 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 3; restarts 5; fills 35; removals 32; checks 108; identity ac622e6f17b4f416",
        "handoff: seed 7 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 3; restarts 5; fills 35; removals 33; checks 108; identity dfc33fc859bc8b5a",
        "handoff: seed 8 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 4; restarts 4; fills 38; removals 35; checks 108; identity 5e5c2e12f8e4fd7a",
        "handoff: seed 9 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 5; restarts 3; fills 33; removals 34; checks 108; identity 3e735d738fef6564",
        "handoff: seed 10 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 4; restarts 4; fills 33; removals 29; checks 108; identity e230f2d068aeebdf",
        "handoff: seed 11 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 3; restarts 5; fills 37; removals 37; checks 108; identity 9c0eb72c855a6181",
        "handoff: seed 12 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 2; restarts 6; fills 37; removals 37; checks 108; identity 10a333f05efa7c87",
        "handoff: seed 13 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 3; restarts 5; fills 35; removals 32; checks 108; identity 0a20bccdbae3e520",
        "handoff: seed 14 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 2; restarts 6; fills 37; removals 39; checks 108; identity 30b8ca688971d2ca",
        "handoff: seed 15 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 4; restarts 4; fills 37; removals 36; checks 108; identity 004e8d0980edded7",
        "handoff: seed 16 cycles 8: every tenure after a planned exit held every acknowledged mutation; transfers 6; restarts 2; fills 37; removals 37; checks 108; identity b57cd57c9c490c94",
        "handoff: 16 seeds of 8 planned exits; transfers 62; restarts 66; fills 570; removals 554; checks 1728",
    ],
    "fleet-replay": [
        *(f"fleet: pinned {member}: credit pass; digest {'f1' * 32}"
          for member in ("six root 1", "six root 2", "dense root 1", "dense root 2", "host-loss root 1", "host-loss root 2",
                         "crash-table root 1")),
        "fleet: 7 pinned digests reported alike by two fresh processes",
    ],
    "fleet-roots": [
        *(f"fleet: root {root} hosts {hosts} shards {shards}: one owner per tenure pass; volume kept pass; retained set pass; "
          f"settle or blocker pass; host share pass; untouched shards pass; credit pass; identity {'f1' * 8}"
          for hosts, shards in ((6, 6), (4, 8)) for root in range(1, 17)),
        "fleet: roots: 32 runs passed, 0 takeovers, settle at most 19 of 64 rounds",
    ],
    "fleet-scheduled-roots": [
        *(f"fleet: scheduled volume {check}: pass"
          for check in ("no-fault root 2", "impaired root 2", "impaired-brief root 2", "stall root 2", "control enroll-back root 2",
                        "lost-alone root 2", "correlated root 2", "correlated-late root 2", "control loss-evidence root 2",
                        "correlated-replay root 1", "held-race-rerun-first root 1")),
        *(f"fleet: scheduled volume replace-{boundary}-{ending} root 1: pass"
          for boundary in ("replacement", "createopen", "createissued", "createcreated", "recordattach", "addspare", "flip")
          for ending in ("acknowledged", "committed", "lost")),
        "fleet: scheduled volume: 11 checks and 21 crash cells passed",
        *(f"fleet: scheduled zone {check}: pass" for check in ("loss root 2", "loss-replay root 1", "settle root 2")),
        "fleet: scheduled zone: 3 checks passed",
        *(f"fleet: scheduled repair-and-host {check} root 2: pass"
          for check in ("settle", "reenroll", "standby-loss", "double-loss", "partition-repair", "census-full", "attach-cap", "foreign",
                        "racing", "partition-loss", "false-suspicion", "deposed-owner", "dense",
                        "census-and-settle-controls")),
        *(f"fleet: scheduled repair-and-host {check} root 2: pass"
          for check in ("unknown-confirm-committed", "unknown-confirm-lost", "unknown-reserve-committed", "unknown-reserve-lost",
                        "unknown-page-committed", "unknown-page-lost", "regressed-reads")),
        *(f"fleet: scheduled repair-and-host {check}: pass"
          for check in ("census-and-settle-siblings root 1", "census-and-settle-siblings root 2",
                        "standby-need-dropped root 2", "pinned root 2", "unknown-confirm-committed root 1",
                        "unknown-reserve-committed root 1", "unknown-reserve-lost root 1", "unknown-page-lost root 1",
                        "takeover-unknown-committed root 1", "handoff root 2", "handoff-ended root 2")),
        *(f"fleet: scheduled repair-and-host {kind}-{call}-{ending} root 1: pass"
          for kind in ("enroll", "fresh")
          for index, call in enumerate(("reserve", "record", "attach", "enroll", "designate"))
          for at, ending in enumerate(("acknowledged", "committed", "lost"))
          if not (at == index % 3 and (kind == "fresh") == (index % 2 == 1))),
        "fleet: scheduled repair-and-host: 32 checks and 25 crash cells passed",
        *(f"fleet: scheduled alarms-{scenario} root 1: pass"
          for scenario in ("host-loss", "partition-loss", "partition-loss-at", "false-suspicion", "owner-pause", "owner-isolation", "page-regressed", "record-regressed", "settle", "tiny-settle", "az-settle", "reenroll", "standby-loss", "standby-silent", "double-loss", "partition-repair", "partition-repair-at", "census-full", "attach-survivor", "attach-closed", "foreign", "racing", "slot-moved", "handoff", "handoff-ended", "zone-loss", "zone-impaired", "zone-deposed")),
        *(f"fleet: scheduled alarms-unknown-{write}-{ending} root 1: pass"
          for write in ("confirm", "reserve", "page") for ending in ("committed", "lost")),
        *(f"fleet: scheduled alarms-{kind}-{call}-{ending} root 1: pass"
          for kind in ("enroll", "fresh")
          for call in ("reserve", "record", "attach", "enroll", "designate")
          for ending in ("acknowledged", "committed", "lost")),
        *(f"fleet: scheduled alarms-control-{control}-row root 1: pass" for control in ("missing", "extra")),
        "fleet: scheduled alarms: 64 sets passed, 1 not run, 27 not judged, 2 controls failed by the rule",
    ],
    "slot-reuse-cycles": [
        *(f"cycles: seed {seed} cycles 24: safety pass; containment pass; retention pass; progress pass; quiescent conservation pass; "
          f"publish-aligned conservation inconclusive [no checkpoint or frontier publication follows a quiescent boundary]; "
          f"plateau inconclusive [no accepted plateau band]; identity {identity}"
          for seed, identity in enumerate(SLOT_REUSE_IDENTITIES, start=1)),
        "cycles: slot-reuse: 16 seeds of 24 cycles; replacements 384 drops 384 preempts 9 live-max 3; every run passed its "
        "four verdicts and its quiescent conservation, and no replaced host returned",
    ],
    "deeper-suffix-trees": [
        "deeper-suffix: depth=4 children=3 faults=12 advances=16: 57 nodes credited, 36 leaves walked alike, 77 unexplored, "
        "deepest leaf 4, 0 problems",
        "deeper-suffix: depth=7 children=2 faults=12 advances=16: 254 nodes credited, 128 leaves walked alike, 281 unexplored, "
        "deepest leaf 7, 0 problems",
        "deeper-suffix: 2 trees complete within their bounds, every leaf passing",
    ],
    # The witness lines the architecture qualification tests print on a host with every feature of their kernels.
    "x86-crc-chains": ["isa: crc-chains ran 1905 times; x86_64 sse4.2=true pclmulqdq=true"],
    "x86-crc-narrow": ["isa: crc-narrow ran 2000 times; x86_64 sse4.2=true pclmulqdq=true"],
    "x86-crc-wide": ["isa: crc-wide ran 1408 times; x86_64 sse4.2=true pclmulqdq=true avx512f=true vpclmulqdq=true"],
    **{f"x86-hmac-{count}": [f"isa: hmac-wide-{count} ran 2 times; {X86_HMAC}"] for count in (9, 15, 16, 17)},
    "x86-index-full-groups": ["isa: index-vector ran 1 times; x86_64 avx512f=true vpclmulqdq=true"],
    "aarch64-sha2-chains": [f"isa: sha2-{chains} ran 2278 times; aarch64 sha2=true" for chains in ("two", "three", "four")],
    "aarch64-sha2-one": ["isa: sha2-one ran 1694 times; aarch64 sha2=true sha3=true"],
    "aarch64-sha2-one-request": ["isa: sha2-one-request ran 1536 times; aarch64 sha2=true sha3=true"],
    "aarch64-sha2-lone": ["isa: sha2-lone ran 82 times; aarch64 sha2=true sha3=true", "isa: hmac-lone ran 8 times; aarch64 sha2=true sha3=true", "isa: group-lone ran 4 times; aarch64 sha2=true sha3=true"],
    "aarch64-crc-lanes": ["isa: crc-lanes ran 1905 times; aarch64 crc=true aes=true"],
    "aarch64-crc-instruction": ["isa: crc-instruction ran 15665 times; aarch64 crc=true"],
    "aarch64-crc-pmull": ["isa: crc-pmull ran 2816 times; aarch64 crc=true aes=true"],
    "aarch64-polyval-pmull": ["isa: polyval-pmull ran 28806 times; aarch64 neon=true aes=true sha3=true"],
    "aarch64-hmac-quad": ["isa: hmac-quad-16 ran 528 times; aarch64 sha2=true"],
    "aarch64-sha2-tail": ["isa: sha2-tail ran 12 times; aarch64 sha2=true", "isa: hmac-tail ran 12 times; aarch64 sha2=true"],
    "aarch64-entropy-svc": ["isa: entropy-svc ran 8 times; aarch64 svc=true"],
}
PUT_SOURCES = {"net::put_tests::": "net/put_tests.rs", "net::upload_tests::": "net/upload_tests.rs"}
def put_census_problems(registry, sources):
    """Compare the PUT and upload ignores the registry and the source modules record.

    The two must name the same tests, and each registered row is
    `flaky-quarantine`, the class the nightly job repeats.
    """
    put_modules = tuple(sources)
    rows = sorted((row for row in registry["rows"] if row["cfg"] == "ordinary" and row["id"].startswith(put_modules)), key=lambda row: row["id"])
    registered = [row["id"] for row in rows]
    problems, source = [], []
    for module, text in sources.items():
        found = IGNORE_ATTRIBUTE.findall(text)
        if text.count("#[ignore") != len(found):
            problems.append(f"{module} carries an ignore attribute without cause text on a test fn")
        source += [module + name for _, name in found]
    if registered != sorted(source):
        problems.append(f"the registry {registered} and the source {sorted(source)} disagree")
    problems += [
        f"{row['id']} is {row['class']}; an ignored PUT or upload test is flaky-quarantine so the nightly job repeats it"
        for row in rows if row["class"] != "flaky-quarantine"
    ]
    return problems


def listing(names, header=None):
    lines = [header] if header else []
    lines += [f"{name}: test" for name in names]
    lines += ["", f"{len(names)} test{'s' if len(names) != 1 else ''}, 0 benchmarks"]
    return "\n".join(lines) + "\n"


def outcomes(ran, ignored=(), failed=()):
    lines = [f"test {name} ... {'FAILED' if name in failed else 'ok'}" for name in ran]
    lines += [f"test {name} ... ignored, needs the fence" for name in ignored]
    return "\n".join(lines) + "\n"


def ordinary_run(runnable=ORDINARY_RUNNABLE, ignored=None, header=ORDINARY_HEADER):
    ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"] if ignored is None else ignored
    return f"{header}\n{outcomes(runnable, ignored)}{summary(len(runnable), 0, len(ignored))}\n"


def loom_run(module="credit_model", header=LOOM_HEADER):
    declared = INVENTORY["loom"][module]
    ran = [name for name in declared["tests"] if name not in declared["ignored"]]
    return f"{header}\n\nrunning {len(declared['tests'])} tests\n{outcomes(ran, declared['ignored'])}\n{summary(len(ran), 0, len(declared['ignored']), 1484)}\n"


def summary(passed, failed, ignored, filtered=0):
    return (
        f"test result: {'ok' if failed == 0 else 'FAILED'}. {passed} passed; {failed} failed; "
        f"{ignored} ignored; 0 measured; {filtered} filtered out; finished in 0.79s"
    )


class SelectTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-select-")
        self.addCleanup(self.temp.cleanup)
        self.dir = Path(self.temp.name)

    def file(self, name, text):
        path = self.dir / name
        path.write_text(text)
        return str(path)

    def select(self, *args):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False,
        )
        try:
            return result.returncode, json.loads(result.stdout)
        except ValueError:
            self.fail(f"no JSON report: {result.stdout!r} {result.stderr!r}")

    def loom(self, names=None, ignored=None, output=None, exit_code=0, module="credit_model"):
        declared = INVENTORY["loom"][module]
        names = declared["tests"] if names is None else names
        ignored = declared["ignored"] if ignored is None else ignored
        args = [
            "run" if output is not None else "listing", "--cfg", "loom", "--module", module,
            "--list", self.file("list", listing(names, LOOM_HEADER)),
            "--ignored", self.file("ignored", listing(ignored, LOOM_HEADER)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args)

    def ordinary(self, runnable=ORDINARY_RUNNABLE, ignored=None, output=None, exit_code=0):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        ignored = declared if ignored is None else ignored
        args = [
            "run" if output is not None else "listing", "--cfg", "ordinary", "--crate", "kestrike",
            "--target", "kestrike",
            "--list", self.file("list", listing(runnable + ignored, ORDINARY_HEADER)),
            "--ignored", self.file("ignored", listing(ignored, ORDINARY_HEADER)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args)

    def test_accepts_the_declared_loom_module_and_its_run(self):
        code, report = self.loom(output=loom_run())
        self.assertEqual(code, 0, report)
        counts = report["targets"]["credit_model"]
        self.assertEqual((counts["listed"], counts["executed"], counts["observed_ignored"]),
                         (CREDIT_MODEL_TESTS, CREDIT_MODEL_TESTS, 0))

    def test_each_loom_module_key_filters_only_its_own_module(self):
        source = ROOT / "crates/kestrike/src"
        names = set()
        for path in source.rglob("*.rs"):
            names.update(path.relative_to(source).with_suffix("").parts)
            names.update(re.findall(r"\b(?:mod|fn)\s+(\w+)", path.read_text(encoding="utf-8")))
        for module, declared in INVENTORY["loom"].items():
            with self.subTest(module=module):
                self.assertTrue(all(f"::{module}::" in f"::{name}" for name in declared["tests"]), declared["tests"])
                self.assertEqual(sorted(name for name in names if module in name), [module])

    def test_a_loom_ignore_row_is_keyed_by_module(self):
        name = "storage::credit_model::dropping_both_fences_hides_a_credit"
        ignored = select_tests.parse_listing(listing([name], LOOM_HEADER), "--ignored")
        row = {"cfg": "loom", "target": "credit_model", "id": name, "class": "brittle-bound", "cause": "x"}
        today = date.fromisoformat("2026-10-09")
        self.assertEqual(select_tests.judge_registry({("loom", "credit_model", name): row}, ("loom",), "credit_model", ignored, today), [])
        with self.assertRaises(select_tests.Refusal):
            select_tests.judge_registry({("loom", "kestrike", name): row}, ("loom",), "credit_model", ignored, today)

    def test_accepts_the_declared_ordinary_ignores_and_their_run(self):
        code, report = self.ordinary(output=ordinary_run())
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["kestrike"]["runnable"], len(ORDINARY_RUNNABLE))

    def test_the_inventory_records_its_reconciled_baseline(self):
        self.assertRegex(INVENTORY["baseline"], r"^[0-9a-f]{40}$")
        code, report = self.ordinary()
        self.assertEqual((code, report["baseline"]), (0, INVENTORY["baseline"]), report)
        witnesses = report["targets"]["kestrike"]["witnesses"]
        self.assertEqual(witnesses["controls"], sorted(REQUIRED["tests"]))
        self.assertEqual(witnesses["runnable_modules"], {
            module: sum(name.startswith(module + "::") for name in ORDINARY_RUNNABLE) for module in REQUIRED["modules"]
        })
        self.assertTrue(all(witnesses["runnable_modules"].values()), witnesses)
        self.assertNotIn("executed_modules", witnesses)

    def test_the_catalog_target_requires_every_catalog_test_once(self):
        named = {
            test for record in CATALOG["records"] if record["job"] == "workspace"
            for test in [*record["tests"], *(c["test"] for c in record["controls"])]
        }
        other_target_tests = {
            test for target, witnesses in INVENTORY["ordinary"]["kestrike"]["required"].items()
            if target != "kestrike" for test in witnesses["tests"]
        }
        self.assertEqual(set(REQUIRED["tests"]) & named, named - other_target_tests)
        explicit = COMMITTED["ordinary"]["kestrike"]["required"]["kestrike"]["tests"]
        self.assertEqual(set(explicit) & named, set())
        control = sorted(named - other_target_tests)[0]
        kept = [name for name in ORDINARY_RUNNABLE if name != control]
        code, report = self.ordinary(runnable=kept)
        self.assertEqual(code, 1, report)
        self.assertIn(f"omits required controls ['{control}']", report["reason"])
        repeated = copy.deepcopy(COMMITTED)
        repeated["ordinary"]["kestrike"]["required"]["kestrike"]["tests"].append(control)
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.declare(repeated, registry, CATALOG)
        self.assertEqual(refused.exception.code, 1)
        self.assertIn(f"repeats catalog workspace tests in kestrike: ['{control}']", str(refused.exception))

    def test_each_registry_row_binds_a_declared_target(self):
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        for cfg, target in (("ordinary", "nowhere"), ("loom", "kestrike"), ("miri", "kernel_tools")):
            row = {"cfg": cfg, "target": target, "id": "storage::x_tests::an_ignore", "class": "brittle-bound", "cause": "x"}
            with self.subTest(cfg=cfg), self.assertRaises(select_tests.Refusal) as refused:
                select_tests.declare(COMMITTED, {**registry, (cfg, target, row["id"]): row}, CATALOG)
            self.assertIn(f"names {cfg} target {target}, which the inventory does not declare", str(refused.exception))
        loom = {"cfg": "loom", "target": "credit_model", "id": "storage::credit_model::undeclared", "class": "brittle-bound", "cause": "x"}
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.declare(COMMITTED, {**registry, ("loom", "credit_model", loom["id"]): loom}, CATALOG)
        self.assertIn("ignores tests it does not declare", str(refused.exception))
        ignored = {
            row["id"] for row in REGISTRY["rows"] if row["cfg"] == "ordinary" and row["target"] == "kestrike"
        }
        self.assertEqual(set(INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]), ignored)

    def test_every_required_witness_names_a_source_test(self):
        source = ROOT / "crates/kestrike/src"
        for module in REQUIRED["modules"]:
            path = source.joinpath(*module.split("::"))
            files = sorted(path.rglob("*.rs")) if path.is_dir() else [path.with_suffix(".rs")]
            self.assertTrue(any(f.is_file() and "#[test]" in f.read_text(encoding="utf-8") for f in files), module)
        for name in REQUIRED["tests"]:
            function = name.rsplit("::", 1)[-1]
            self.assertRegex(RECEIPTS.module_file(name, "kestrike")[0], rf"\bfn {function}\(", name)

    def test_rejects_an_omitted_put_module_while_unrelated_tests_remain(self):
        for module in REQUIRED["modules"]:
            kept = [name for name in ORDINARY_RUNNABLE if not name.startswith(module + "::")]
            code, report = self.ordinary(runnable=kept)
            self.assertEqual(code, 1, report)
            self.assertIn(f"no runnable test of required modules ['{module}']", report["reason"])
            self.assertEqual(report["targets"]["kestrike"]["runnable"], len(kept))

    def test_rejects_an_omitted_put_control_while_unrelated_tests_remain(self):
        for control in (REQUIRED["tests"][0], REQUIRED["tests"][-1]):
            kept = [name for name in ORDINARY_RUNNABLE if name != control]
            code, report = self.ordinary(runnable=kept)
            self.assertEqual(code, 1, report)
            self.assertIn(f"omits required controls ['{control}']", report["reason"])
            ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
            code, report = self.ordinary(runnable=kept, ignored=ignored + [control])
            self.assertEqual(code, 1, report)
            self.assertIn(f"ignored tests without a registry row ['kestrike: {control}']", report["reason"])

    def test_rejects_a_run_that_renames_a_required_control_or_module(self):
        ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        control = REQUIRED["tests"][0]
        ran = [f"{name}_renamed" if name == control else name for name in ORDINARY_RUNNABLE]
        code, report = self.ordinary(output=ordinary_run(runnable=ran))
        self.assertEqual(code, 4, report)
        self.assertIn(f"executed tests outside the listing ['{control}_renamed']", report["reason"])
        self.assertNotIn("executed_modules", report["targets"]["kestrike"]["witnesses"],
                         "a refused run records no executed witnesses")
        module = "storage::oracle_custody_tests::"
        ran = [name.replace(module, "storage::other_tests::", 1) if name.startswith(module) else name for name in ORDINARY_RUNNABLE]
        code, report = self.ordinary(output=ordinary_run(runnable=ran))
        self.assertEqual(code, 4, report)
        self.assertIn("executed tests outside the listing ['storage::other_tests::", report["reason"])
        ran = [name for name in ORDINARY_RUNNABLE if name != control]
        code, report = self.ordinary(output=f"{ORDINARY_HEADER}\n{outcomes(ran, ignored)}{summary(len(ran), 0, 16)}\n")
        self.assertEqual(code, 4, report)
        self.assertIn(f"executed {len(ran)} of {len(ran) + 1} runnable", report["reason"])
        code, report = self.ordinary(output=ordinary_run())
        self.assertEqual(code, 0, report)
        witnesses = report["targets"]["kestrike"]["witnesses"]
        self.assertEqual(witnesses["executed_modules"], witnesses["runnable_modules"])
        self.assertEqual(witnesses["executed_modules"], {
            module: sum(name.startswith(module + "::") for name in ORDINARY_RUNNABLE) for module in REQUIRED["modules"]
        })

    def test_rejects_zero_selection(self):
        code, report = self.loom(names=[], ignored=[])
        self.assertEqual(code, 3, report)

    def test_rejects_a_module_without_a_listing(self):
        code, report = self.loom(names=[], ignored=[], module="grace_model")
        self.assertEqual(code, 3, report)
        code, report = self.ordinary(runnable=[], ignored=[])
        self.assertEqual(code, 3, report)
        missing = self.file("other", listing(["only_test"], "     Running tests/x.rs (target/debug/deps/x-0123abcd)"))
        code, report = self.select(
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--list", missing,
            "--ignored", self.file("none", ""),
        )
        self.assertEqual(code, 1, report)
        self.assertIn("absent", report["reason"])

    def test_rejects_an_omitted_control(self):
        names = [name for name in INVENTORY["loom"]["grace_model"]["tests"] if "negative_control" not in name]
        code, report = self.loom(names=names, module="grace_model")
        self.assertEqual(code, 1, report)
        self.assertIn("omits", report["reason"])

    def test_rejects_an_unexpected_ignore(self):
        declared = INVENTORY["loom"]["credit_model"]
        code, report = self.loom(ignored=declared["ignored"] + [declared["tests"][0]])
        self.assertEqual(code, 1, report)
        code, report = self.ordinary(ignored=INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"] + ["extra::ignored"])
        self.assertEqual(code, 1, report)

    def test_rejects_a_duplicate_name(self):
        declared = INVENTORY["loom"]["credit_model"]["tests"]
        code, report = self.loom(names=declared + [declared[0]])
        self.assertEqual(code, 1, report)
        self.assertIn("twice", report["reason"])

    def test_rejects_an_executed_count_below_declared_runnable(self):
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(7, 0, 0)}\n")
        self.assertEqual(code, 4, report)
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(0, 0, 1)}\n", module="writable_model")
        self.assertEqual(code, 4, report)

    def test_rejects_a_failure_or_a_nonzero_exit(self):
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(7, 1, 0)}\n")
        self.assertEqual(code, 4, report)
        self.assertIn("failed 1", report["reason"])
        code, report = self.loom(output=f"{LOOM_HEADER}\n{LOOM_SUMMARY}\n", exit_code=101)
        self.assertEqual(code, 4, report)

    def test_rejects_a_malformed_or_missing_summary(self):
        code, report = self.loom(output=f"{LOOM_HEADER}\ntest result: ok. 6 passed; 0 failed\n")
        self.assertEqual(code, 4, report)
        self.assertIn("malformed", report["reason"])
        code, report = self.ordinary(output=f"{ORDINARY_HEADER}\n")
        self.assertEqual(code, 4, report)
        self.assertIn("no summary", report["reason"])

    def test_rejects_a_cancel_or_timeout_marker(self):
        output = f"{LOOM_HEADER}\n{LOOM_SUMMARY}\n##[error]The operation was canceled.\n"
        code, report = self.loom(output=output)
        self.assertEqual(code, 4, report)

    def test_an_unknown_module_or_a_bad_input_is_a_tool_failure(self):
        code, report = self.select(
            "listing", "--cfg", "loom", "--module", "absent_model",
            "--list", self.file("l", listing(["a"], LOOM_HEADER)), "--ignored", self.file("i", listing([], LOOM_HEADER)),
        )
        self.assertEqual(code, 2, report)
        self.assertIn("not in the inventory", report["reason"])
        binary = self.dir / "binary"
        binary.write_bytes(b"\xff\xfe")
        code, report = self.select("listing", "--cfg", "loom", "--module", "credit_model", "--list", str(binary), "--ignored", str(binary))
        self.assertEqual(code, 2, report)
        self.assertIn("unreadable input", report["reason"])
        code, report = self.select(
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "bogus",
            "--list", self.file("l", listing(ORDINARY_RUNNABLE, ORDINARY_HEADER)), "--ignored", self.file("i", ""),
        )
        self.assertEqual(code, 2, report)
        self.assertIn("not declared", report["reason"])
        broken = copy.deepcopy(COMMITTED)
        del broken["loom"]["credit_model"]["tests"]
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.load_inventory(self.file("inventory.json", json.dumps(broken)))
        self.assertEqual(refused.exception.code, 2)
        self.assertIn("malformed inventory", str(refused.exception))
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.load_inventory(self.file("inventory.json", "{"))
        self.assertIn("unreadable inventory", str(refused.exception))

    def test_the_committed_inventory_is_the_only_inventory(self):
        fabricated = {"loom": {"tiny": {"target": "tiny", "tests": ["tiny::one"], "ignored": []}}, "ordinary": {}}
        header = "     Running unittests src/lib.rs (target/debug/deps/tiny-0123abcd)"
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT), "listing", "--cfg", "loom", "--module", "tiny",
                "--inventory", self.file("inventory.json", json.dumps(fabricated)),
                "--list", self.file("l", listing(["tiny::one"], header)), "--ignored", self.file("i", listing([], header)),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unrecognized arguments: --inventory", result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(select_tests.check_inventory(COMMITTED), None)
        result = subprocess.run(
            [
                sys.executable, str(SCRIPT), "listing", "--cfg", "ordinary",
                "--registry", self.file("registry.json", json.dumps({"rows": []})),
                "--list", self.file("l", listing(["tiny::one"], header)), "--ignored", self.file("i", listing([], header)),
            ],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2, result.stdout)
        self.assertIn("unrecognized arguments: --registry", result.stderr)
        self.assertEqual(result.stdout, "")

    def test_each_inventory_rule_refuses_a_malformed_inventory(self):
        def broken(edit):
            inventory = copy.deepcopy(COMMITTED)
            edit(inventory)
            return inventory

        edits = [
            lambda inv: inv["loom"]["credit_model"]["tests"].append(inv["loom"]["credit_model"]["tests"][0]),
            lambda inv: inv["loom"]["credit_model"].update(ignored=[]),
            lambda inv: inv["miri"].update(ignored=[]),
            lambda inv: inv["ordinary"]["kestrike"].pop("targets"),
            lambda inv: inv["ordinary"]["kestrike"].update(ignored={}),
            lambda inv: inv["ordinary"]["spdk-sys"]["targets"].append("kestrike"),
            lambda inv: inv.update(loom=[]),
            lambda inv: inv.pop("baseline"),
            lambda inv: inv.update(baseline="8677e86"),
            lambda inv: inv["ordinary"]["kestrike"]["required"].update(bogus={"modules": [], "tests": []}),
            lambda inv: inv["ordinary"]["kestrike"]["required"]["kestrike"].pop("modules"),
            lambda inv: inv["ordinary"]["kestrike"]["required"]["kestrike"]["modules"].append("oracle"),
            lambda inv: inv["ordinary"]["kestrike"]["required"]["sim_worker"].update(tests=[]),
            lambda inv: inv["ordinary"]["kestrike"]["required"]["sim_worker"].update(catalog="workspace"),
            lambda inv: inv.pop("asan"),
            lambda inv: inv["asan"].update(targets=[]),
            lambda inv: inv["asan"]["targets"].append("sim_worker"),
            lambda inv: inv["asan"]["targets"].append("another_target"),
            lambda inv: inv["asan"]["required"].pop("kestrike"),
            lambda inv: inv["asan"]["required"]["kestrike"].update(modules=[]),
            lambda inv: inv["asan"]["required"]["spdk_sys"]["tests"].append(inv["asan"]["required"]["spdk_sys"]["tests"][0]),
        ]
        for edit in edits:
            self.assertIsNotNone(select_tests.check_inventory(broken(edit)), edit)

    def test_rejects_an_undeclared_target(self):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        other = "     Running tests/z.rs (target/debug/deps/z-0123abcd)"
        code, report = self.select(
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike",
            "--list", self.file("l", listing(ORDINARY_RUNNABLE + declared, ORDINARY_HEADER) + listing(["z"], other)),
            "--ignored", self.file("i", listing(declared, ORDINARY_HEADER)),
        )
        self.assertEqual(code, 1, report)
        self.assertIn("undeclared targets", report["reason"])

    def test_a_loom_listing_names_one_binary(self):
        declared = INVENTORY["loom"]["credit_model"]
        other = "     Running unittests src/lib.rs (/tmp/loom-target/release/deps/other-0123abcd)"
        for list_text, ignored_text in [
            (listing(declared["tests"], LOOM_HEADER) + listing(["x"], other), listing(declared["ignored"], LOOM_HEADER)),
            (listing(declared["tests"], LOOM_HEADER), listing(declared["ignored"], LOOM_HEADER) + listing([], other)),
            (listing(declared["tests"], LOOM_HEADER), listing(declared["ignored"], other)),
        ]:
            code, report = self.select(
                "listing", "--cfg", "loom", "--module", "credit_model",
                "--list", self.file("l", list_text), "--ignored", self.file("i", ignored_text),
            )
            self.assertEqual(code, 1, report)
            self.assertIn("spans targets", report["reason"])

    def test_a_headerless_listing_is_a_tool_failure(self):
        declared = INVENTORY["loom"]["credit_model"]
        headed = listing(declared["tests"], LOOM_HEADER), listing(declared["ignored"], LOOM_HEADER)
        bare = listing(declared["tests"]), listing(declared["ignored"])
        for list_text, ignored_text in [bare, (headed[0], bare[1]), (bare[0], headed[1])]:
            code, report = self.select(
                "run", "--cfg", "loom", "--module", "credit_model",
                "--list", self.file("l", list_text), "--ignored", self.file("i", ignored_text),
                "--output", self.file("o", f"running 6 tests\n{LOOM_SUMMARY}\n"), "--exit", "0",
            )
            self.assertEqual(code, 2, report)
            self.assertIn("before any Running header", report["reason"])
        ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        code, report = self.select(
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike",
            "--list", self.file("l", listing(ORDINARY_RUNNABLE + ignored)), "--ignored", self.file("i", listing(ignored)),
        )
        self.assertEqual(code, 2, report)
        self.assertIn("before any Running header", report["reason"])

    def test_each_cancel_or_timeout_marker_refuses_the_run(self):
        markers = [
            "##[error]The operation was canceled.",
            "##[error]The job running on runner x has exceeded the maximum execution time and timed out.",
            "error: test failed, to rerun pass `-p kestrike --lib` (signal: 9, SIGKILL: kill)",
            "  process didn't exit successfully: `kestrike-9b91` (signal: 15, SIGTERM: termination signal)",
            "Killed",
            "Terminated",
        ]
        for marker in markers:
            code, report = self.loom(output=f"{LOOM_HEADER}\n{LOOM_SUMMARY}\n{marker}\n")
            self.assertEqual(code, 4, marker)
            self.assertIn("cancel or timeout", report["reason"])

    def test_each_registry_cause_repeats_its_source_ignore_attribute(self):
        self.maxDiff = None
        source, interpreted, unexplained = Counter(), Counter(), []
        for path in sorted((ROOT / "crates").rglob("*.rs")):
            if "target" in path.relative_to(ROOT).parts:
                continue
            text = path.read_text(encoding="utf-8")
            for cause, name in IGNORE_ATTRIBUTE.findall(text):
                source[(name, re.sub(r"\\(.)", r"\1", cause))] += 1
            found = MIRI_IGNORE_ATTRIBUTE.findall(text)
            if len(re.findall(r"cfg_attr\(\s*miri,\s*ignore", text)) != len(found):
                unexplained.append(str(path.relative_to(ROOT)))
            for cause, name in found:
                interpreted[(name, re.sub(r"\\(.)", r"\1", cause))] += 1
        self.assertEqual(unexplained, [], "cfg_attr(miri, ignore) attributes without cause text on a test fn")
        # Under the interpreter a test keeps its ordinary ignore text, which takes precedence over a miri attribute.
        kestrike = {row["id"].rsplit("::", 1)[-1]: row["cause"] for row in REGISTRY["rows"] if row["cfg"] == "ordinary" and row["target"] == "kestrike"}
        effective = Counter(interpreted)
        for (name, cause), count in source.items():
            if kestrike.get(name) == cause:
                effective[(name, cause)] += count
        for cfg, expected in (("ordinary", source), ("miri", effective)):
            cfgs = (cfg, "loom", "asan") if cfg == "ordinary" else (cfg,)
            registered = Counter((row["id"].rsplit("::", 1)[-1], row["cause"]) for row in REGISTRY["rows"] if row["cfg"] in cfgs)
            self.assertEqual(
                (sorted((registered - expected).elements()), sorted((expected - registered).elements())), ([], []),
                f"{cfg}: (registry causes without a matching source ignore text, source ignore texts without a matching row)",
            )

    def test_the_miri_registry_rows_repeat_the_ordinary_class_of_an_ordinary_ignore(self):
        ordinary = {row["id"]: row for row in REGISTRY["rows"] if row["cfg"] == "ordinary" and row["target"] == "kestrike"}
        for row in REGISTRY["rows"]:
            if row["cfg"] == "miri" and row["id"] in ordinary:
                self.assertEqual((row["class"], row["cause"]), (ordinary[row["id"]]["class"], ordinary[row["id"]]["cause"]), row["id"])
            elif row["cfg"] == "miri":
                self.assertIn(row["class"], {"interpreter-exclusion", "brittle-bound"}, row["id"])

    def miri(self, names=None, ignored=None, output=None, exit_code=0, header=MIRI_HEADER):
        declared = INVENTORY["miri"]
        names = declared["tests"] + declared["ignored"] if names is None else names
        ignored = declared["ignored"] if ignored is None else ignored
        args = [
            "run" if output is not None else "listing", "--cfg", "miri",
            "--list", self.file("list", listing(names, header)),
            "--ignored", self.file("ignored", listing(ignored, header)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args)

    def miri_run(self, ran=None, failed=(), filtered=None, tail=""):
        declared = INVENTORY["miri"]
        ran = declared["tests"] if ran is None else ran
        filtered = len(declared["ignored"]) if filtered is None else filtered
        lines = [f"test {name}{' - should panic' if 'nic_tests' in name else ''} ... {'FAILED' if name in failed else 'ok'}" for name in ran]
        passed = len(ran) - len(failed)
        return f"{MIRI_HEADER}\n\nrunning {len(ran)} tests\n" + "\n".join(lines) + f"\n\n{summary(passed, len(failed), 0, filtered)}\n{tail}"

    def test_accepts_the_scoped_miri_selection_and_its_run(self):
        code, report = self.miri()
        self.assertEqual(code, 0, report)
        counts = report["targets"]["kestrike"]
        declared = INVENTORY["miri"]
        selected, ignored = len(declared["tests"]), len(declared["ignored"])
        self.assertEqual((counts["selected"], counts["runnable"], counts["interpreter_ignored"]), (selected, selected, ignored))
        code, report = self.miri(output=self.miri_run())
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["kestrike"]["executed"], selected)

    def test_a_miri_selection_refuses_a_missing_duplicate_or_ignored_id_and_zero_selection(self):
        declared = INVENTORY["miri"]
        code, report = self.miri(names=declared["tests"][1:] + declared["ignored"])
        self.assertEqual(code, 1, report)
        self.assertIn(f"omits selected tests ['{declared['tests'][0]}']", report["reason"])
        code, report = self.miri(names=declared["tests"] + declared["tests"][:1] + declared["ignored"])
        self.assertEqual(code, 1, report)
        self.assertIn("twice", report["reason"])
        code, report = self.miri(ignored=declared["ignored"] + declared["tests"][:1])
        self.assertEqual(code, 1, report)
        self.assertIn("without a registry row", report["reason"])
        code, report = self.miri(names=[], ignored=[])
        self.assertEqual(code, 3, report)
        registry = copy.deepcopy(REGISTRY)
        registry["rows"].append({"cfg": "miri", "target": "kestrike", "id": declared["tests"][0], "class": "interpreter-exclusion", "cause": "a selected ignore"})
        with unittest.mock.patch.object(select_tests, "REGISTRY", self.file("registry.json", json.dumps(registry))), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = select_tests.main([
                "listing", "--cfg", "miri",
                "--list", self.file("list", listing(declared["tests"] + declared["ignored"], MIRI_HEADER)),
                "--ignored", self.file("ignored", listing(declared["ignored"] + declared["tests"][:1], MIRI_HEADER)),
            ])
        try:
            report = json.loads(stdout.getvalue())
        except ValueError:
            self.fail(f"no JSON report: {stdout.getvalue()!r}")
        self.assertEqual(code, 1, report)
        self.assertIn(f"the miri cfg selects tests the interpreter ignores: ['{declared['tests'][0]}']", report["reason"])

    def test_a_miri_selection_reconciles_the_whole_interpreter_ignore_list(self):
        declared = INVENTORY["miri"]
        code, report = self.miri(ignored=declared["ignored"][1:])
        self.assertEqual(code, 1, report)
        self.assertIn("absent from the --ignored listing", report["reason"])
        code, report = self.miri(names=declared["tests"] + declared["ignored"] + ["storage::extra_tests::an_unregistered_ignore"],
                                 ignored=declared["ignored"] + ["storage::extra_tests::an_unregistered_ignore"])
        self.assertEqual(code, 1, report)
        self.assertIn("without a registry row", report["reason"])
        registry = copy.deepcopy(REGISTRY)
        registry["rows"].append({"cfg": "miri", "target": "kestrike", "id": "storage::extra_tests::a_stale_row", "class": "interpreter-exclusion", "cause": "a stale cause"})
        code, report = self.judged_with_registry(self.file("registry.json", json.dumps(registry)), cfg="miri")
        self.assertEqual(code, 1, report)
        self.assertIn("declares ignores absent from the --ignored listing ['storage::extra_tests::a_stale_row']", report["reason"])

    def sweep(self, blocks=None, exit_code=0, tail=""):
        declared, sweep = INVENTORY["miri"], INVENTORY["miri_sweep"]
        lines = [MIRI_HEADER]
        for seed, ran in (blocks if blocks is not None else [(seed, sweep["tests"]) for seed in range(sweep["seeds"])]):
            lines += [f"Trying seed: {seed}", "", f"running {len(ran)} tests", *(f"test {name} ... ok" for name in ran),
                      "", summary(len(ran), 0, 0, len(declared["ignored"]) + len(sweep["tests"]) - len(ran)), ""]
        return self.select(
            "run", "--cfg", "miri-sweep",
            "--list", self.file("list", listing(sweep["tests"] + declared["ignored"], MIRI_HEADER)),
            "--ignored", self.file("ignored", listing(declared["ignored"], MIRI_HEADER)),
            "--output", self.file("output", "\n".join(lines) + "\n" + tail), "--exit", str(exit_code),
        )

    def test_a_complete_sweep_credits_every_kernel_at_every_seed(self):
        sweep = INVENTORY["miri_sweep"]
        self.assertEqual((len(sweep["tests"]), sweep["seeds"]), (3, 64))
        self.assertTrue(all(name.rsplit("::", 1)[-1].startswith("miri_weak_memory_") for name in sweep["tests"]))
        code, report = self.sweep()
        self.assertEqual(code, 0, report)
        self.assertEqual((report["targets"]["kestrike"]["executed"], report["targets"]["kestrike"]["seeds"]), (192, 64))

    def test_a_sweep_refuses_a_partial_range_a_wrong_id_a_failing_seed_or_an_unsupported_operation(self):
        sweep = INVENTORY["miri_sweep"]
        every = [(seed, sweep["tests"]) for seed in range(sweep["seeds"])]
        other = "storage::weak_memory_tests::miri_weak_memory_another_kernel"
        for blocks, tail, code, reason in (
            (every[:-1], "", 4, "covered seeds"),
            (every[:-1] + [(62, sweep["tests"])], "", 4, "covered seeds"),
            (every[:5] + [(5, sweep["tests"][:2] + [other])] + every[6:], "", 4, "seed 5:"),
            (every[:7] + [(7, sweep["tests"][:2] + sweep["tests"][:1])] + every[8:], "", 4, "seed 7:"),
            (every[:63], "Trying seed: 63\n##[error]The operation was canceled.\n", 4, "cancel or timeout"),
            (every[:63], "Trying seed: 63\n", 4, "seed 63:"),
            (every[:10], "FAILING SEED: 10\n", 4, "seed 10 failed"),
            (every[:3], "error: unsupported operation: can't call foreign function `x` on OS `linux`\n", 2, "unsupported operation"),
        ):
            with self.subTest(reason=reason):
                got, report = self.sweep(blocks, tail=tail)
                self.assertEqual(got, code, report)
                self.assertIn(reason, report["reason"])
        got, report = self.sweep(exit_code=101)
        self.assertEqual(got, 4, report)

    def test_a_miri_run_refuses_a_failure_omission_truncation_or_cancel(self):
        declared = INVENTORY["miri"]
        nic = next(name for name in declared["tests"] if "nic_tests" in name)
        for output, reason in (
            (self.miri_run(failed=[nic]), "failed 1 tests"),
            (self.miri_run(ran=declared["tests"][1:] + declared["tests"][1:2]), "omits listed executed tests"),
            (self.miri_run(filtered=0), f"filtered out 0 tests, expected {len(declared['ignored'])}"),
            (self.miri_run().rsplit("test result:", 1)[0], "produced 0 summaries"),
            (self.miri_run(tail="##[error]The operation was canceled.\n"), "cancel or timeout"),
        ):
            with self.subTest(reason=reason):
                code, report = self.miri(output=output)
                self.assertEqual(code, 4, report)
                self.assertIn(reason, report["reason"])
        code, report = self.miri(output=self.miri_run(), exit_code=101)
        self.assertEqual(code, 4, report)

    def registry(self, edit):
        registry = copy.deepcopy(REGISTRY)
        edit(registry["rows"])
        return self.file("registry.json", json.dumps(registry))

    def with_registry(self, registry, today="2026-10-09"):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        ignored = select_tests.parse_listing(listing(declared, ORDINARY_HEADER), "--ignored")
        try:
            rows = select_tests.load_registry(registry, INVENTORY["baseline"])
            gaps = select_tests.judge_registry(rows, ("ordinary",), None, ignored, date.fromisoformat(today))
        except select_tests.Refusal as refusal:
            return refusal.code, {"reason": str(refusal), "policy_gaps": []}
        return 0, {"reason": None, "policy_gaps": gaps}

    def test_an_ignore_without_a_registry_row_fails(self):
        code, report = self.with_registry(self.registry(lambda rows: rows.pop(
            next(at for at, row in enumerate(rows) if row["cfg"] == "ordinary" and row["id"] == "storage::churn_tests::churn_replay"))))
        self.assertEqual(code, 1, report)
        self.assertIn("without a registry row", report["reason"])

    def test_the_registry_records_the_inventory_baseline(self):
        self.assertEqual(REGISTRY["baseline"], INVENTORY["baseline"])
        document = copy.deepcopy(REGISTRY)
        document["baseline"] = "0123456789abcdef0123456789abcdef01234567"
        code, report = self.with_registry(self.file("registry.json", json.dumps(document)))
        self.assertEqual(code, 1, report)
        self.assertIn("records baseline 0123456789abcdef0123456789abcdef01234567, the inventory", report["reason"])
        for baseline in ("8677e862", 7, None):
            document["baseline"] = baseline
            code, report = self.with_registry(self.file("registry.json", json.dumps(document)))
            self.assertEqual(code, 2, report)
            self.assertIn("40-digit lowercase hexadecimal", report["reason"])
        del document["baseline"]
        code, report = self.with_registry(self.file("registry.json", json.dumps(document)))
        self.assertEqual(code, 2, report)
        self.assertIn("unreadable registry", report["reason"])
        document["baseline"] = "0123456789abcdef0123456789abcdef01234567"
        code, report = self.judged_with_registry(self.file("registry.json", json.dumps(document)))
        self.assertEqual(code, 1, report)
        self.assertIn("records baseline 0123456789abcdef0123456789abcdef01234567, the inventory", report["reason"])

    def judged_with_registry(self, registry, cfg="ordinary"):
        """Run the script's judgment in process against another registry path, as `judge` wires it."""
        if cfg == "miri":
            declared = INVENTORY["miri"]
            argv = [
                "listing", "--cfg", "miri",
                "--list", self.file("list", listing(declared["tests"] + declared["ignored"], MIRI_HEADER)),
                "--ignored", self.file("ignored", listing(declared["ignored"], MIRI_HEADER)),
            ]
        else:
            declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
            argv = [
                "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike",
                "--list", self.file("list", listing(ORDINARY_RUNNABLE + declared, ORDINARY_HEADER)),
                "--ignored", self.file("ignored", listing(declared, ORDINARY_HEADER)),
            ]
        with unittest.mock.patch.object(select_tests, "REGISTRY", registry), \
                contextlib.redirect_stdout(io.StringIO()) as stdout:
            code = select_tests.main(argv)
        try:
            return code, json.loads(stdout.getvalue())
        except ValueError:
            self.fail(f"no JSON report: {stdout.getvalue()!r}")

    def test_the_put_and_upload_census_holds(self):
        sources = {module: (ROOT / "crates/kestrike/src" / path).read_text(encoding="utf-8") for module, path in PUT_SOURCES.items()}
        self.assertEqual(put_census_problems(REGISTRY, sources), [])

    def test_a_registered_put_ignore_satisfies_the_census(self):
        name = "net::put_tests::a_put_that_flakes"
        cause = "flaky: the PUT races its own retry"
        registry = copy.deepcopy(REGISTRY)
        registry["rows"].append({"cfg": "ordinary", "target": "kestrike", "id": name, "class": "flaky-quarantine", "cause": cause})
        sources = {"net::put_tests::": f'#[test]\n#[ignore = "{cause}"]\nfn a_put_that_flakes() {{}}\n', "net::upload_tests::": ""}
        self.assertEqual(put_census_problems(registry, sources), [])
        unregistered = dict(sources, **{"net::upload_tests::": f'#[ignore = "{cause}"]\nfn an_upload_that_flakes() {{}}\n'})
        self.assertIn("disagree", put_census_problems(registry, unregistered)[0])
        bare = dict(sources, **{"net::upload_tests::": "#[ignore]\nfn an_upload_that_flakes() {}\n"})
        self.assertEqual(
            put_census_problems(registry, bare),
            ["net::upload_tests:: carries an ignore attribute without cause text on a test fn"],
        )

    def test_a_put_ignore_outside_the_quarantine_fails_the_census(self):
        # The nightly job repeats flaky-quarantine rows, so an ignored PUT or
        # upload test takes that class.
        name = "net::put_tests::a_put_that_replays"
        cause = "replays a captured trace; run on demand"
        registry = copy.deepcopy(REGISTRY)
        registry["rows"].append({"cfg": "ordinary", "target": "kestrike", "id": name, "class": "diagnostic-replay", "cause": cause})
        sources = {"net::put_tests::": f'#[test]\n#[ignore = "{cause}"]\nfn a_put_that_replays() {{}}\n', "net::upload_tests::": ""}
        self.assertEqual(
            put_census_problems(registry, sources),
            [f"{name} is diagnostic-replay; an ignored PUT or upload test is flaky-quarantine so the nightly job repeats it"],
        )

    def test_a_row_with_two_classes_or_an_unknown_class_fails(self):
        def second_class(rows):
            row = next(row for row in rows if row["cfg"] == "ordinary" and row["id"] == "storage::churn_tests::churn_replay")
            rows.append(dict(row, **{"class": "brittle-bound"}))

        code, report = self.with_registry(self.registry(second_class))
        self.assertEqual(code, 1, report)
        self.assertIn("twice", report["reason"])
        code, report = self.with_registry(self.registry(lambda rows: rows.append(dict(rows[0]))))
        self.assertEqual(code, 1, report)
        code, report = self.with_registry(self.registry(lambda rows: rows[0].pop("cause")))
        self.assertEqual(code, 2, report)
        code, report = self.with_registry(self.registry(
            lambda rows: rows[0].update(**{"class": ["hardware-privileged", "flaky-quarantine"]})))
        self.assertEqual(code, 1, report)
        def relabel(rows):
            row = next(row for row in rows if row["class"] == "hardware-privileged")
            row.update({"class": "flaky-quarantine", "recipe": "python3 scripts/reproduce-test.py"})

        code, report = self.with_registry(self.registry(relabel))
        self.assertEqual(code, 1, report)
        self.assertIn("states no flakiness", report["reason"])
        code, report = self.with_registry(self.registry(lambda rows: rows[0].update(**{"class": "flaky"})))
        self.assertEqual(code, 1, report)

    def test_flaky_rows_without_ticket_expiry_or_recipe_are_policy_gaps(self):
        def quarantine(**fields):
            def edit(rows):
                row = next(row for row in rows if row["cfg"] == "ordinary" and row["id"] == "storage::churn_tests::churn_replay")
                row.update({"class": "flaky-quarantine", "cause": "flaky: replay timing", "recipe": "r",
                            "ticket": "#1", "date": "2026-10-01",
                            "expiry": "2026-12-01", "first_failure": "run 1"}, **fields)
            return self.registry(edit)

        code, report = self.with_registry(quarantine())
        self.assertEqual((code, report["policy_gaps"]), (0, []))
        code, report = self.with_registry(quarantine(ticket=None, recipe=None))
        self.assertEqual(code, 0, report)
        self.assertEqual(report["policy_gaps"], ["storage::churn_tests::churn_replay lacks text for ticket, recipe"])
        code, report = self.with_registry(quarantine(), today="2027-01-01")
        self.assertEqual(code, 0, report)
        self.assertIn("expired on 2026-12-01", report["policy_gaps"][0])
        code, report = self.with_registry(quarantine(expiry="2027-03-01"))
        self.assertIn("more than 90 days", report["policy_gaps"][0])
        code, report = self.with_registry(quarantine(expiry="never"))
        self.assertIn("ISO date", report["policy_gaps"][0])
        code, report = self.with_registry(quarantine(date="2027-09-01", expiry="2027-08-31"))
        self.assertIn("dated 2027-09-01, after 2026-10-09", report["policy_gaps"][0])
        code, report = self.with_registry(quarantine(date="2026-10-01", expiry="2026-09-30"))
        self.assertIn("before its date 2026-10-01", report["policy_gaps"][0])
        typed = quarantine(ticket=1, date=20261001, expiry=20261201, recipe=["r"], first_failure={"run": 1})
        code, report = self.with_registry(typed)
        self.assertEqual(
            report["policy_gaps"],
            ["storage::churn_tests::churn_replay lacks text for ticket, date, expiry, recipe, first_failure"],
        )

    def test_a_registry_row_answers_only_for_its_own_target(self):
        def move(rows):
            row = next(row for row in rows if row["cfg"] == "ordinary" and row["id"] == "storage::churn_tests::churn_replay")
            row["target"] = "kernel_tools"

        code, report = self.with_registry(self.registry(move))
        self.assertEqual(code, 1, report)
        self.assertIn("without a registry row", report["reason"])

    def test_a_loom_run_without_a_known_module_is_a_tool_failure(self):
        declared = INVENTORY["loom"]["credit_model"]
        for module in ([], ["--module", "nope"]):
            code, report = self.select(
                "listing", "--cfg", "loom", *module,
                "--list", self.file("l", listing(declared["tests"], LOOM_HEADER)),
                "--ignored", self.file("i", listing(declared["ignored"], LOOM_HEADER)),
            )
            self.assertEqual(code, 2, report)

    def test_a_removed_module_declaration_cannot_pass_with_fewer_tests(self):
        declared = INVENTORY["loom"]["credit_model"]
        code, report = self.loom(names=declared["tests"][:-1])
        self.assertEqual(code, 1, report)
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(7, 0, 0)}\n")
        self.assertEqual(code, 4, report)

    def test_rejects_an_undeclared_listed_test(self):
        code, report = self.loom(names=INVENTORY["loom"]["credit_model"]["tests"] + ["storage::credit_model::extra"])
        self.assertEqual(code, 1, report)
        self.assertIn("undeclared tests", report["reason"])

    def test_rejects_a_declared_ignore_that_runs(self):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        code, report = self.ordinary(ignored=declared[:-1])
        self.assertEqual(code, 1, report)
        self.assertIn("absent from the --ignored listing", report["reason"])

    def test_rejects_an_ignore_outside_the_listing_or_its_targets(self):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        args = [
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike",
            "--list", self.file("list", listing(ORDINARY_RUNNABLE + declared[:-1], ORDINARY_HEADER)),
            "--ignored", self.file("ignored", listing(declared, ORDINARY_HEADER)),
        ]
        code, report = self.select(*args)
        self.assertEqual(code, 1, report)
        stray = listing(declared, ORDINARY_HEADER) + listing(["x"], "     Running tests/y.rs (target/debug/deps/y-0123abcd)")
        args[-1] = self.file("ignored", stray)
        args[-3] = self.file("list", listing(ORDINARY_RUNNABLE + declared, ORDINARY_HEADER))
        code, report = self.select(*args)
        self.assertEqual(code, 1, report)

    def test_rejects_an_ignored_count_that_differs_from_the_declared_one(self):
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(CREDIT_MODEL_TESTS, 0, 1)}\n")
        self.assertEqual(code, 4, report)
        self.assertIn("ignored 1, declared 0", report["reason"])

    def test_rejects_an_executed_count_above_declared_runnable(self):
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(CREDIT_MODEL_TESTS + 1, 0, 0)}\n")
        self.assertEqual(code, 4, report)
        self.assertIn(f"executed {CREDIT_MODEL_TESTS + 1} of {CREDIT_MODEL_TESTS} runnable", report["reason"])

    def test_rejects_summaries_from_another_target(self):
        other = "     Running tests/x.rs (target/debug/deps/x-0123abcd)"
        code, report = self.loom(output=f"{LOOM_HEADER}\n{LOOM_SUMMARY}\n{other}\n{summary(1, 0, 0)}\n")
        self.assertEqual(code, 4, report)
        code, report = self.loom(output=f"{LOOM_HEADER}\n{summary(3, 0, 1)}\n{summary(3, 0, 1)}\n")
        self.assertEqual(code, 4, report)
        code, report = self.loom(output=f"{other}\n{LOOM_SUMMARY}\n")
        self.assertEqual(code, 4, report)
        code, report = self.ordinary(output=f"{ORDINARY_HEADER}\n{summary(2, 0, 16)}\n{other}\n{summary(1, 0, 0)}\n")
        self.assertEqual(code, 4, report)
        self.assertIn("unlisted targets", report["reason"])

    def test_rejects_a_repeated_ordinary_summary(self):
        repeated = f"{ORDINARY_HEADER}\n{summary(1, 0, 16)}\n{ORDINARY_HEADER}\n{summary(1, 0, 0)}\n"
        code, report = self.ordinary(output=repeated)
        self.assertEqual(code, 4, report)
        self.assertIn("2 summaries", report["reason"])

    def test_rejects_a_filtered_ordinary_run(self):
        # The same --skip on both listings and the run drops a runnable test
        # from each, so listed and executed still agree; only the summary's
        # filtered-out count exposes the omission.
        skipped = f"{ORDINARY_HEADER}\n{summary(len(ORDINARY_RUNNABLE) - 1, 0, len(ORDINARY_IGNORED), filtered=1)}\n"
        code, report = self.ordinary(runnable=ORDINARY_RUNNABLE[1:], output=skipped)
        self.assertEqual(code, 4, report)
        self.assertIn("filtered out 1", report["reason"])
        code, report = self.ordinary(output=ordinary_run())
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["kestrike"]["filtered"], 0)
        code, report = self.loom(output=loom_run())
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["credit_model"]["filtered"], 1484)

    def test_a_loom_listing_names_the_declared_binary(self):
        other = LOOM_HEADER.replace("kestrike-", "not_the_kestrike-")
        declared = INVENTORY["loom"]["credit_model"]
        code, report = self.select(
            "run", "--cfg", "loom", "--module", "credit_model",
            "--list", self.file("l", listing(declared["tests"], other)),
            "--ignored", self.file("i", listing(declared["ignored"], other)),
            "--output", self.file("o", loom_run(header=other)), "--exit", "0",
        )
        self.assertEqual(code, 1, report)
        self.assertIn("names binary not_the_kestrike", report["reason"])

    def test_a_loom_run_executes_the_listed_tests(self):
        count = len(INVENTORY["loom"]["publication_model"]["tests"])
        witness = [f"storage::witness_tests::case_{index}" for index in range(count)]
        output = f"{LOOM_HEADER}\n{outcomes(witness)}{summary(count, 0, 0, 1488)}\n"
        code, report = self.loom(output=output, module="publication_model")
        self.assertEqual(code, 4, report)
        self.assertIn("executed tests outside the listing", report["reason"])
        code, report = self.loom(output=f"{LOOM_HEADER}\n{LOOM_SUMMARY}\n")
        self.assertEqual(code, 4, report)
        self.assertIn(f"0 executed outcomes for a summary of {CREDIT_MODEL_TESTS}", report["reason"])
        code, report = self.loom(output=loom_run("publication_model"), module="publication_model")
        self.assertEqual(code, 0, report)

    def test_a_listing_needs_its_test_count_footer(self):
        declared = INVENTORY["loom"]["publication_model"]
        killed = (
            f"{LOOM_HEADER}\nKilled\n"
            "error: test failed, to rerun pass `-p kestrike --lib` (signal: 9, SIGKILL: kill)\n"
        )
        code, report = self.select(
            "listing", "--cfg", "loom", "--module", "publication_model",
            "--list", self.file("l", listing(declared["tests"], LOOM_HEADER)), "--ignored", self.file("i", killed),
        )
        self.assertEqual(code, 2, report)
        self.assertIn("footer", report["reason"])
        count = len(declared["tests"])
        short = listing(declared["tests"], LOOM_HEADER).replace(f"{count} tests", f"{count - 1} tests")
        code, report = self.select(
            "listing", "--cfg", "loom", "--module", "publication_model",
            "--list", self.file("l", short), "--ignored", self.file("i", listing([], LOOM_HEADER)),
        )
        self.assertEqual(code, 2, report)
        self.assertIn(f"counts {count - 1}", report["reason"])

    def test_a_missing_ignored_capture_is_a_tool_failure(self):
        kernel = "     Running tests/kernel_tools.rs (target/debug/deps/kernel_tools-0123abcd)"
        loom = INVENTORY["loom"]["writable_model"]
        for ignored_text in ["", "error: could not execute process `kernel_tools-0123abcd` (never executed)\n"]:
            code, report = self.select(
                "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kernel_tools",
                "--list", self.file("l", listing(["a_missing_tool_is_not_found"], kernel)),
                "--ignored", self.file("i", ignored_text),
            )
            self.assertEqual(code, 2, report)
            self.assertIn("lacks targets", report["reason"])
            code, report = self.select(
                "listing", "--cfg", "loom", "--module", "writable_model",
                "--list", self.file("l", listing(loom["tests"], LOOM_HEADER)),
                "--ignored", self.file("i", ignored_text),
            )
            self.assertEqual(code, 2, report)
            self.assertIn("lacks targets", report["reason"])

    def test_a_worker_listing_without_its_cases_is_refused_beside_a_listed_library(self):
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        library = listing(ORDINARY_RUNNABLE + declared, ORDINARY_HEADER)
        base = [
            "listing", "--cfg", "ordinary", "--crate", "kestrike", "--target", "kestrike", "--target", "sim_worker",
            "--ignored", self.file("i", listing(declared, ORDINARY_HEADER) + listing(WORKER_IGNORED, WORKER_HEADER)),
        ]
        code, report = self.select(*base, "--list", self.file("l", library + listing(WORKER_IGNORED, WORKER_HEADER)))
        self.assertEqual(code, 1, report)
        self.assertIn("sim_worker lists no runnable test of required modules", report["reason"])
        code, report = self.select(*base, "--list", self.file("l", library + listing(WORKER_CASES + WORKER_IGNORED, WORKER_HEADER)))
        self.assertEqual(code, 0, report)
        witnesses = report["targets"]["sim_worker"]["witnesses"]
        self.assertEqual(witnesses["controls"], sorted(WORKER_REQUIRED["tests"]))
        self.assertTrue(all(witnesses["runnable_modules"].values()), witnesses)

    def test_every_required_worker_witness_names_a_case(self):
        text = (ROOT / "crates/kestrike/src/worker.rs").read_text(encoding="utf-8")
        for module in WORKER_REQUIRED["modules"]:
            self.assertIn(f'"{module}::', text, module)
        for name in WORKER_REQUIRED["tests"]:
            self.assertIn(f'"{name}"', text, name)

    def test_the_worker_target_refuses_zero_selection_and_a_cut_run(self):
        header = WORKER_HEADER
        names = WORKER_CASES
        base = ["--cfg", "ordinary", "--crate", "kestrike", "--target", "sim_worker"]
        only_ignored = self.file("e", listing(WORKER_IGNORED, header))
        code, report = self.select("listing", *base, "--list", only_ignored, "--ignored", only_ignored)
        self.assertEqual(code, 3, report)
        listed, ignored = self.file("l", listing(names + WORKER_IGNORED, header)), self.file("i", listing(WORKER_IGNORED, header))
        run = ["run", *base, "--list", listed, "--ignored", ignored]
        complete = f"{header}\n{outcomes(names, WORKER_IGNORED)}{summary(len(names), 0, len(WORKER_IGNORED))}\n"
        code, report = self.select(*run, "--output", self.file("o", complete), "--exit", "0")
        self.assertEqual(code, 0, report)
        for cut, exit_code in [(f"{header}\n{outcomes(names)}", "124"), (f"{header}\n{outcomes(names[:1])}", "130")]:
            code, report = self.select(*run, "--output", self.file("o", cut), "--exit", exit_code)
            self.assertNotEqual(code, 0, report)
            self.assertFalse(report["credited"], report)

    def qualified(self, lane, names=None, ignored=None, output=None, exit_code=0, header=None):
        """Judge LANE's listing, or its run when OUTPUT is given, over a listing of the lane's target."""
        names = QUALIFIED_LISTED[lane] if names is None else names
        ignored = QUALIFIED_IGNORED[lane] if ignored is None else ignored
        header = QUALIFIED_HEADERS[lane] if header is None else header
        args = [
            "run" if output is not None else "listing", "--cfg", "qualified", "--module", lane,
            "--list", self.file("list", listing(names, header)),
            "--ignored", self.file("ignored", listing(ignored, header)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args)

    def qualified_output(self, lane, ran=None, failed=(), filtered=None, tail="", lines=None):
        """A run of LANE's selection by exact ID that prints every row's sample lines, or LINES."""
        selection = select_tests.selection_of(INVENTORY["qualified"][lane])
        ran = selection if ran is None else ran
        filtered = len(QUALIFIED_LISTED[lane]) - len(selection) if filtered is None else filtered
        lines = [line for row in INVENTORY["qualified"][lane]["rows"] for line in ROW_LINES[row["id"]]] if lines is None else lines
        passed = len(ran) - len(failed)
        printed = "".join(f"{line}\n" for line in lines)
        return (f"{QUALIFIED_HEADERS[lane]}\n\nrunning {len(ran)} tests\n{printed}"
                f"{outcomes(ran, failed=failed)}\n{summary(passed, len(failed), 0, filtered)}\n{tail}")

    GUEST_HEADER = "     Running unittests src/lib.rs (guest/kestrike-0123456789abcdef)"

    def qemu(self, names=None, ignored=None, output=None, exit_code=0, header=GUEST_HEADER):
        """Judge the guest lane's listings: the host's kestrike listing (its ordinary ignores among `names`) and,
        with `output`, the guest console as the run."""
        names = ORDINARY_RUNNABLE + ORDINARY_IGNORED if names is None else names
        ignored = ORDINARY_IGNORED if ignored is None else ignored
        args = [
            "run" if output is not None else "listing", "--cfg", "qemu",
            "--list", self.file("list", listing(names, header)),
            "--ignored", self.file("ignored", listing(ignored, header)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args)

    def qemu_output(self, ran=None, failed=(), filtered=None, tail=""):
        """A guest console as libtest prints it under --nocapture: each case named before its reports, and its
        outcome alone on a later line."""
        ran = INVENTORY["qemu"]["tests"] if ran is None else ran
        filtered = len(ORDINARY_RUNNABLE) + len(ORDINARY_IGNORED) - 1 if filtered is None else filtered
        passed = len(ran) - len(failed)
        cases = "".join(f"test {name} ... guest-binder: default refused\nguest-binder: bound\n[    4.0] nvme nvme0: pci function\n"
                        f"guest-binder: released\n{'FAILED' if name in failed else 'ok'}\n" for name in ran)
        return (f"{self.GUEST_HEADER}\n[    0.000000] Linux version 6.12.0\nguest-binder: ready kernel=6.12.0\nrunning {len(ran)} tests\n"
                f"{cases}\n{summary(passed, len(failed), 0, filtered)}\nguest-binder: exit 0\n{tail}")

    def test_a_summary_whose_status_disagrees_with_its_failed_count_is_an_execution_mismatch(self):
        for status, failed in (("FAILED", 0), ("ok", 1)):
            with self.subTest(status=status):
                text = (f"{ORDINARY_HEADER}\ntest a ... ok\ntest result: {status}. 1 passed; {failed} failed; 0 ignored; "
                        "0 measured; 0 filtered out; finished in 0.1s\n")
                with self.assertRaises(select_tests.Refusal) as refused:
                    select_tests.parse_summaries(text)
                self.assertEqual(refused.exception.code, select_tests.EXECUTION_MISMATCH)
                self.assertIn("summary status disagrees with its failed count", str(refused.exception))

    def test_nocapture_outcomes_count_each_case_once_with_its_last_outcome_before_the_next_boundary(self):
        """libtest under --nocapture names a case before it runs and prints its outcome alone afterwards."""
        result = "test result: FAILED. 3 passed; 1 failed; 1 ignored; 0 measured; 0 filtered out; finished in 0.1s"
        text = "\n".join([
            ORDINARY_HEADER,
            "test a ... first report", "second report", "ok",
            "test b ... ", "a bare start, the report on its own line", "ok",
            "test c ... prints ok", "ok", "then panics", "FAILED",
            "test d ... never finished",
            "test e ... ignored, needs hardware",
            "test f ... report", "ok",
            "test g ... cut by the next target",
            "     Running unittests src/main.rs (target/debug/deps/other-0123abcd)",
            "ok",
            result,
        ]) + "\n"
        summaries = select_tests.parse_summaries(text)
        cache = summaries["kestrike"]
        self.assertEqual((cache["ok"], cache["FAILED"], cache["ignored_names"]), (["a", "b", "f"], ["c"], ["e"]))
        self.assertEqual(summaries["other"]["ok"], [], "an outcome alone with no started case counts nothing")
        self.assertEqual(summaries["other"]["lines"], 1)
        suffixed = select_tests.parse_summaries(f"{ORDINARY_HEADER}\ntest h ... report\nignored, a reason\n{result}\n")
        self.assertEqual(suffixed["kestrike"]["ignored_names"], ["h"])
        unsummarized = select_tests.parse_summaries(f"{ORDINARY_HEADER}\ntest i ... report\nok\n")
        self.assertEqual(unsummarized["kestrike"]["ok"], ["i"], "the end of the text commits the last case")

    def test_the_qemu_entry_selects_the_guest_case_among_the_ordinary_ignores(self):
        declared = INVENTORY["qemu"]
        self.assertEqual((declared["crate"], declared["target"]), ("kestrike", "kestrike"))
        self.assertEqual(declared["tests"], ["bind::guest_tests::the_binder_binds_and_releases_the_guest_s_controller"])
        self.assertLessEqual(set(declared["tests"]), set(ORDINARY_IGNORED))
        for edit in (
            lambda inv: inv.pop("qemu"),
            lambda inv: inv["qemu"].update(tests=[]),
            lambda inv: inv["qemu"].update(target="spdk_sys"),
        ):
            inventory = copy.deepcopy(COMMITTED)
            edit(inventory)
            self.assertIsNotNone(select_tests.check_inventory(inventory), edit)
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        inventory = copy.deepcopy(COMMITTED)
        inventory["qemu"]["tests"].append(ORDINARY_RUNNABLE[0])
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.declare(inventory, registry, CATALOG)
        self.assertIn(f"the qemu entry selects tests its target does not ignore: ['{ORDINARY_RUNNABLE[0]}']", str(refused.exception))

    def test_a_qemu_run_credits_only_the_guest_case_executed_ok_by_exact_id_against_the_host_listing(self):
        code, report = self.qemu()
        self.assertEqual(code, 0, report)
        self.assertEqual(report["cfg"], "qemu")
        counts = report["targets"]["kestrike"]
        self.assertEqual((counts["selected"], counts["runnable"], counts["declared_ignored"]), (1, 1, 0))
        code, report = self.qemu(output=self.qemu_output())
        self.assertEqual(code, 0, report)
        counts = report["targets"]["kestrike"]
        self.assertEqual((counts["executed"], counts["observed_ignored"], counts["filtered"]),
                         (1, 0, len(ORDINARY_RUNNABLE) + len(ORDINARY_IGNORED) - 1))
        listed = len(ORDINARY_RUNNABLE) + len(ORDINARY_IGNORED)
        for name, output, exit_code, reason in (
            ("a stale guest executable", self.qemu_output(filtered=listed - 3), 0, f"filtered out {listed - 3} tests, expected {listed - 1}"),
            ("no execution", self.qemu_output(ran=[], filtered=listed), 0, "executed 0 of 1 runnable tests"),
            ("a failed case", self.qemu_output(failed=INVENTORY["qemu"]["tests"]), 101, "failed 1 tests"),
            ("a cut console", f"{self.GUEST_HEADER}\nguest-binder: ready\nrunning 1 test\n", 124, "produced no summary"),
            ("a case that never finished", self.qemu_output().replace("released\nok\n", "released\n"), 0,
             "kestrike reports 0 executed outcomes for a summary of 1"),
            ("a nonzero exit", self.qemu_output(), 6, "the run exited 6"),
        ):
            with self.subTest(case=name):
                code, report = self.qemu(output=output, exit_code=exit_code)
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"], report)
                self.assertIn(reason, report["reason"])
        code, report = self.qemu(names=WORKER_CASES, ignored=[], header=WORKER_HEADER)
        self.assertEqual(code, 1, report)
        self.assertIn("the qemu listing spans targets ['sim_worker'], declared kestrike", report["reason"])

    def blocked(self, lane, **kwargs):
        """The run's code, report and the blocked reasons of each row, keyed by row id."""
        code, report = self.qualified(lane, output=self.qualified_output(lane, **kwargs))
        return code, report, {row["id"]: row["reasons"] for row in report["rows"] if not row["credited"]}

    def test_every_qualified_test_row_has_exactly_one_witness_fixture(self):
        rows = {
            row["id"] for lane in INVENTORY["qualified"].values() if "target" in lane
            for row in lane["rows"]
        }
        self.assertSetEqual(rows, set(ROW_LINES))

    def test_every_qualified_test_lane_credits_its_rows_executed_ok_by_exact_id(self):
        self.assertEqual(sorted(QUALIFIED_HEADERS), ["campaigns", "isa-aarch64", "isa-x86-64", "long-run", "search", "search-nightly"])
        for lane, declared in INVENTORY["qualified"].items():
            if "target" not in declared:
                continue
            with self.subTest(lane=lane):
                code, report = self.qualified(lane)
                self.assertEqual(code, 0, report)
                self.assertEqual((report["cfg"], report["module"]), ("qualified", lane))
                selection = select_tests.selection_of(declared)
                counts = report["targets"][declared["target"]]
                self.assertEqual((counts["selected"], counts["runnable"], counts["declared_ignored"]), (len(selection), len(selection), 0))
                code, report = self.qualified(lane, output=self.qualified_output(lane))
                self.assertEqual(code, 0, report)
                counts = report["targets"][declared["target"]]
                self.assertEqual((counts["executed"], counts["observed_ignored"], counts["filtered"]),
                                 (len(selection), 0, len(QUALIFIED_LISTED[lane]) - len(selection)))
                self.assertEqual([(row["id"], row["credited"]) for row in report["rows"]],
                                 [(row["id"], True) for row in declared["rows"]])

    def test_the_qualified_schema_refuses_each_malformed_row_and_lane(self):
        self.assertIsNone(select_tests.check_inventory(COMMITTED))
        long_run = INVENTORY["qualified"]["long-run"]
        self.assertEqual(long_run["rows"][0]["tests"], ["long_run::the_long_run_gate_passes"])
        self.assertLessEqual(set(select_tests.selection_of(long_run)), set(WORKER_IGNORED))
        q = "qualified"
        edits = {
            "no qualified map": lambda inv: inv.pop(q),
            "a repeated row id": lambda inv: inv[q]["search"]["rows"][0].update(id="frame-fuzz"),
            "a duplicate selection": lambda inv: inv[q]["long-run"]["rows"][1]["tests"].append("long_run::the_long_run_gate_passes"),
            "a test in two rows": lambda inv: inv[q]["long-run"]["rows"][1].update(
                tests=["long_run::the_long_run_gate_passes"]),
            "an empty tests list": lambda inv: inv[q]["search"]["rows"][0].update(tests=[]),
            "zero executions": lambda inv: inv[q]["fuzz-smoke"]["rows"][0].update(executions=0),
            "a fuzz row without executions": lambda inv: inv[q]["fuzz"]["rows"][1].pop("executions"),
            "a boolean execution count": lambda inv: inv[q]["fuzz"]["rows"][0].update(executions=True),
            "a search without its bound": lambda inv: inv[q]["search"]["rows"][0].pop("bound"),
            "a malformed bound": lambda inv: inv[q]["search"]["rows"][0].update(bound="("),
            "a malformed witness": lambda inv: inv[q]["search"]["rows"][0].update(witnesses=["("]),
            "a row with no witness or member": lambda inv: inv[q]["search"]["rows"][0].update(witnesses=[]),
            "a cohort without members": lambda inv: inv[q]["campaigns"]["rows"][1].pop("members"),
            "a member expression without a group": lambda inv: inv[q]["campaigns"]["rows"][1].update(member="^cohort: "),
            "a repeated member": lambda inv: inv[q]["long-run"]["rows"][2]["members"].append("units=65 slots=33 chunk=4096 reserve=2"),
            "zero seeds": lambda inv: inv[q]["long-run"]["rows"][1].update(seeds=0),
            "another kind": lambda inv: inv[q]["search"]["rows"][0].update(kind="fuzz"),
            "another tier": lambda inv: inv[q]["search"].update(tier="weekly"),
            "an empty lane": lambda inv: inv[q]["search"].update(rows=[]),
            "a lane outside its crate": lambda inv: inv[q]["search"].update(crate="spdk-sys"),
            "a fuzz row without seconds": lambda inv: inv[q]["fuzz-smoke"]["rows"][0].update(seconds=0),
            "a fuzz target twice": lambda inv: inv[q]["fuzz-smoke"]["rows"][1].update(target="frame"),
            "an unknown fuzz target": lambda inv: inv[q]["fuzz-smoke"]["rows"][0].update(target="header"),
            "a missing fuzz target": lambda inv: inv[q]["fuzz"]["rows"].pop(),
            "a member expression with two groups": lambda inv: inv[q]["campaigns"]["rows"][1].update(member="^(a)(b)$"),
            "an isa lane without its arch": lambda inv: inv[q]["isa-x86-64"].pop("arch"),
            "an isa lane of another arch": lambda inv: inv[q]["isa-aarch64"].update(arch="riscv64"),
            "an isa lane without features": lambda inv: inv[q]["isa-x86-64"].update(features=[]),
            "an isa lane naming a feature twice": lambda inv: inv[q]["isa-aarch64"]["features"].append("sha2"),
            "an isa lane with a search row": lambda inv: inv[q]["isa-x86-64"]["rows"][0].update(kind="search", bound="^x$"),
            "an isa row in a search lane": lambda inv: inv[q]["search"]["rows"][0].update(kind="isa"),
        }
        for name, edit in edits.items():
            with self.subTest(edit=name):
                inventory = copy.deepcopy(COMMITTED)
                edit(inventory)
                self.assertIsNotNone(select_tests.check_inventory(inventory), name)
        # declare() reads the registry to refuse a lane selection on the wrong side of its target's ignores.
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        for name, edit, wrong in (
            ("an ignored test in a runnable lane", lambda inv: inv[q]["search"]["rows"][0].update(
                tests=["net::serve_search_tests::the_nightly_search_exhausts_its_bound"]),
             "net::serve_search_tests::the_nightly_search_exhausts_its_bound"),
            ("a runnable test in an ignored lane", lambda inv: inv[q]["long-run"]["rows"][0].update(
                tests=["worker::cases_run_on_one_thread"]), "worker::cases_run_on_one_thread"),
        ):
            with self.subTest(edit=name):
                inventory = copy.deepcopy(COMMITTED)
                edit(inventory)
                self.assertIsNone(select_tests.check_inventory(inventory), name)
                with self.assertRaises(select_tests.Refusal) as refused:
                    select_tests.declare(inventory, registry, CATALOG)
                self.assertEqual(refused.exception.code, 1)
                self.assertIn(f"selects tests on the wrong side of its target's ignores: ['{wrong}']", str(refused.exception))

    ASAN_SPDK_HEADER = "     Running unittests src/lib.rs (/tmp/asan/x86_64-unknown-linux-gnu/debug/deps/spdk_sys-b25a6d8b23b3044e)"
    ASAN_CACHE_HEADER = "     Running unittests src/lib.rs (/tmp/asan/x86_64-unknown-linux-gnu/debug/deps/kestrike-9182b89a273caa7d)"

    def asan(self, controls=None, witnesses=None, ignored=None, output=None, exit_code=0):
        """Judge the sanitized lane's listings of its two targets: the spdk-sys shim `controls` (every required one
        by default) and the kestrike `witnesses` (one per required module and every required test by default)
        beside the lane's ignores."""
        required = INVENTORY["asan"]["required"]
        controls = required["spdk_sys"]["tests"] if controls is None else controls
        witnesses = [*[f"{m}::a_sanitized_witness" for m in required["kestrike"]["modules"]], *required["kestrike"]["tests"]] if witnesses is None else witnesses
        ignored = ASAN_IGNORED if ignored is None else ignored
        spdk = [*controls, "registry_tests::a_registry_probe"]
        cache = [*witnesses, *UNRELATED]
        args = [
            "run" if output is not None else "listing", "--cfg", "asan",
            "--list", self.file("list", listing(spdk, self.ASAN_SPDK_HEADER) + listing(cache + ignored, self.ASAN_CACHE_HEADER)),
            "--ignored", self.file("ignored", listing([], self.ASAN_SPDK_HEADER) + listing(ignored, self.ASAN_CACHE_HEADER)),
        ]
        if output is not None:
            args += ["--output", self.file("output", output), "--exit", str(exit_code)]
        return self.select(*args), spdk, cache

    def asan_output(self, spdk, cache, ignored=None, failed=(), spdk_filtered=0):
        ignored = ASAN_IGNORED if ignored is None else ignored
        text = f"{self.ASAN_SPDK_HEADER}\n{outcomes(spdk, failed=failed)}{summary(len(spdk) - len(set(spdk) & set(failed)), len(set(spdk) & set(failed)), 0, spdk_filtered)}\n"
        text += f"{self.ASAN_CACHE_HEADER}\n{outcomes(cache, ignored, failed)}{summary(len(cache) - len(set(cache) & set(failed)), len(set(cache) & set(failed)), len(ignored))}\n"
        return text

    def test_the_asan_entry_names_the_lanes_two_targets_their_controls_and_the_attributed_modules(self):
        asan = INVENTORY["asan"]
        self.assertEqual(asan["targets"], ["spdk_sys", "kestrike"])
        self.assertEqual(asan["required"]["kestrike"]["modules"], ["bind", "native", "index"])
        self.assertEqual(asan["required"]["spdk_sys"]["tests"], [
            "shim_tests::a_one_byte_header_read_is_reported_at_the_shim_frame",
            "shim_tests::the_golden_header_checksums_to_its_published_value",
        ])
        sanitized = [row["id"] for row in REGISTRY["rows"] if row["cfg"] == "asan" and row["target"] == "kestrike"]
        self.assertEqual(asan["ignored"], {"spdk_sys": [], "kestrike": ORDINARY_IGNORED + sanitized},
                         "the sanitized build ignores what the ordinary and asan registry rows ignore")
        declarations = (ROOT / "crates/kestrike/src/mod.rs").read_text()
        for module in asan["required"]["kestrike"]["modules"]:
            self.assertIn(f"pub mod {module};", declarations)
        shim = (ROOT / "crates/spdk-sys/src/shim_tests.rs").read_text()
        for name in asan["required"]["spdk_sys"]["tests"]:
            self.assertIn(f"fn {name.rsplit('::', 1)[1]}()", shim)

    def test_the_asan_entry_refuses_a_control_the_registry_ignores(self):
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        control = COMMITTED["asan"]["required"]["spdk_sys"]["tests"][0]
        rows = dict(registry)
        rows[("ordinary", "spdk_sys", control)] = {"cfg": "ordinary", "target": "spdk_sys", "id": control, "class": "hardware-privileged", "cause": "x"}
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.declare(COMMITTED, rows, CATALOG)
        self.assertEqual(refused.exception.code, 1)
        self.assertIn(f"the asan entry requires controls it ignores in spdk_sys: ['{control}']", str(refused.exception))

    def test_an_asan_registry_row_ignores_a_test_only_the_sanitized_build_compiles(self):
        registry = select_tests.load_registry(select_tests.REGISTRY, COMMITTED["baseline"])
        name = "native::chain_tests::real::a_sanitized_only_case"
        row = {"cfg": "asan", "target": "kestrike", "id": name, "class": "hardware-privileged", "cause": "x"}
        rows = {**registry, ("asan", "kestrike", name): row}
        declared = select_tests.declare(COMMITTED, rows, CATALOG)
        self.assertIn(name, declared["asan"]["ignored"]["kestrike"])
        self.assertNotIn(name, declared["ordinary"]["kestrike"]["ignored"]["kestrike"],
                         "the ordinary build compiles no sanitized-only test")
        self.assertEqual(select_tests.judge_registry(rows, select_tests.REGISTRY_ROWS["asan"], None,
                                                     {"kestrike": [name, *ORDINARY_IGNORED]}, date(2026, 10, 19)), [])
        with self.assertRaises(select_tests.Refusal) as refused:
            select_tests.judge_registry(rows, select_tests.REGISTRY_ROWS["qualified"], None, {"kestrike": [name]}, date(2026, 10, 19))
        self.assertIn(f"ignored tests without a registry row ['kestrike: {name}']", str(refused.exception))
        for fault, extra, reason in (
            ("an unsanitized target", {("asan", "sim_worker", name): {**row, "target": "sim_worker"}},
             f"registry row {name} names asan target sim_worker"),
            ("an ordinary ignore", {("asan", "kestrike", ORDINARY_IGNORED[0]): {**row, "id": ORDINARY_IGNORED[0]}},
             f"the asan registry rows repeat ordinary ignores of kestrike: ['{ORDINARY_IGNORED[0]}']"),
        ):
            with self.subTest(fault=fault):
                with self.assertRaises(select_tests.Refusal) as refused:
                    select_tests.declare(COMMITTED, {**registry, **extra}, CATALOG)
                self.assertEqual(refused.exception.code, 1)
                self.assertIn(reason, str(refused.exception))

    def test_every_real_native_chain_case_is_a_hardware_ignore_the_asan_lane_never_requires(self):
        source = (ROOT / "crates/kestrike/src/native/chain_tests/real.rs").read_text()
        cases = re.findall(r'#\[ignore\s*=\s*"[^"]*"\]\s*fn (\w+)\(\) \{\s*run\("(\w+)"\);', source)
        called = re.findall(r'^\s*run\("(\w+)"\);', source, re.MULTILINE)
        self.assertEqual(len(called), 12, "each real case runs one fresh child")
        self.assertEqual([case for case, _ in cases], called, "every real case that initializes the environment is ignored")
        self.assertEqual([case for case, name in cases if case != name], [])
        rows = {row["id"]: row for row in REGISTRY["rows"] if row["cfg"] == "asan" and row["target"] == "kestrike"}
        prefix = "native::chain_tests::real::"
        for case in called:
            with self.subTest(case=case):
                self.assertIn(prefix + case, rows, "the sanitized build declares the case's ignore")
                self.assertEqual(rows[prefix + case]["class"], "hardware-privileged")
                self.assertNotIn(prefix + case, INVENTORY["asan"]["required"]["kestrike"]["tests"])

    def test_an_asan_listing_and_run_are_credited_with_each_modules_attribution(self):
        (code, report), spdk, cache = self.asan()
        self.assertEqual(code, 0, report)
        self.assertEqual(report["cfg"], "asan")
        self.assertEqual(report["targets"]["spdk_sys"]["witnesses"]["controls"], INVENTORY["asan"]["required"]["spdk_sys"]["tests"])
        # UNRELATED holds a bind test beside the module's witness.
        native = 1 + len(INVENTORY["asan"]["required"]["kestrike"]["tests"])
        self.assertEqual(report["targets"]["kestrike"]["witnesses"]["runnable_modules"], {"bind": 2, "native": native, "index": 1})
        self.assertEqual(report["targets"]["kestrike"]["declared_ignored"], len(ASAN_IGNORED))
        (code, report), _, _ = self.asan(output=self.asan_output(spdk, cache))
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["kestrike"]["witnesses"]["executed_modules"], {"bind": 2, "native": native, "index": 1})
        self.assertEqual(report["targets"]["spdk_sys"]["witnesses"]["executed_modules"], {"shim_tests": 2})
        self.assertEqual((report["targets"]["spdk_sys"]["executed"], report["targets"]["kestrike"]["executed"]), (len(spdk), len(cache)))

    def test_an_asan_listing_refuses_an_unsanitized_build_a_missing_module_and_a_filtered_run(self):
        required = INVENTORY["asan"]["required"]
        (code, report), _, _ = self.asan(controls=required["spdk_sys"]["tests"][1:])
        self.assertEqual(code, 1, report)
        self.assertIn("spdk_sys omits required controls ['shim_tests::a_one_byte_header_read_is_reported_at_the_shim_frame']", report["reason"])
        (code, report), _, _ = self.asan(witnesses=["bind::a_sanitized_witness", "native::a_sanitized_witness"])
        self.assertEqual(code, 1, report)
        self.assertIn("kestrike lists no runnable test of required modules ['index']", report["reason"])
        (code, report), _, _ = self.asan(ignored=ASAN_IGNORED[1:])
        self.assertEqual(code, 1, report)
        self.assertIn("declares ignores absent from the --ignored listing", report["reason"])
        (code, report), spdk, cache = self.asan()
        for name, output, exit_code, reason in (
            ("a filtered run", self.asan_output(spdk, cache, spdk_filtered=1), 0, "spdk_sys filtered out 1 tests"),
            ("a failed control", self.asan_output(spdk, cache, failed=spdk[:1]), 101, "spdk_sys failed 1 tests"),
            ("a cut run", f"{self.ASAN_SPDK_HEADER}\n{outcomes(spdk)}", 143, "spdk_sys produced 0 summaries"),
            ("a nonzero exit", self.asan_output(spdk, cache), 1, "the run exited 1"),
        ):
            with self.subTest(case=name):
                (code, report), _, _ = self.asan(output=output, exit_code=exit_code)
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"])
                self.assertIn(reason, report["reason"])

    def test_each_native_chain_judge_id_requires_its_own_completed_asan_result(self):
        required = [name for name in INVENTORY["asan"]["required"]["kestrike"]["tests"] if name.startswith("native::chain_tests::")]
        real = (ROOT / "crates/kestrike/src/native/chain_tests/real.rs").read_text()
        judges = (ROOT / "crates/kestrike/src/native/chain_tests.rs").read_text()
        self.assertEqual(required, [
            "native::chain_tests::real::the_real_case_inventory_is_frozen",
            "native::chain_tests::real::the_native_judge_accepts_exact_boundaries_and_rejects_changed_custody",
            "native::chain_tests::real::the_native_judge_refuses_aggregate_completion_missing_boundaries_and_duplicates",
            "native::chain_tests::the_invalid_contract_judge_requires_a_fatal_asan_report_and_the_free_shim_frame",
        ])
        for name in required:
            source = real if name.startswith("native::chain_tests::real::") else judges
            self.assertIn(f"#[test]\nfn {name.rsplit('::', 1)[1]}()", source)
        _, spdk, cache = self.asan()
        witnesses = [name for name in cache if name not in UNRELATED]
        for name in required:
            with self.subTest(id=name, fault="absent listing"):
                (code, report), _, _ = self.asan(witnesses=[test for test in witnesses if test != name])
                self.assertEqual(code, 1, report)
                self.assertFalse(report["credited"])
                self.assertIn(name, report["reason"])
            with self.subTest(id=name, fault="duplicate listing"):
                (code, report), _, _ = self.asan(witnesses=[*witnesses, name])
                self.assertEqual(code, 1, report)
                self.assertFalse(report["credited"])
            with self.subTest(id=name, fault="ignored listing"):
                (code, report), _, _ = self.asan(witnesses=[test for test in witnesses if test != name], ignored=[*ASAN_IGNORED, name])
                self.assertEqual(code, 1, report)
                self.assertFalse(report["credited"])
                self.assertIn(f"ignored tests without a registry row ['kestrike: {name}']", report["reason"])
            with self.subTest(id=name, fault="failed run"):
                (code, report), _, _ = self.asan(output=self.asan_output(spdk, cache, failed=[name]), exit_code=101)
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"])
            with self.subTest(id=name, fault="missing result"):
                (code, report), _, _ = self.asan(output=self.asan_output(spdk, [test for test in cache if test != name]))
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"])
            with self.subTest(id=name, fault="duplicate result"):
                (code, report), _, _ = self.asan(output=self.asan_output(spdk, [*cache, name]))
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"])
        output = self.asan_output(spdk, cache)
        cache_summary = summary(len(cache), 0, len(ASAN_IGNORED))
        for fault, bad in [("filtered", output.replace(cache_summary, summary(len(cache), 0, len(ASAN_IGNORED), 1))),
                           ("interrupted", output.replace(cache_summary, ""))]:
            with self.subTest(fault=fault):
                (code, report), _, _ = self.asan(output=bad)
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"])

    def test_the_qualified_cfg_refuses_a_fuzz_or_unknown_lane(self):
        for lane in ("fuzz-smoke", "absent"):
            with self.subTest(lane=lane):
                code, report = self.select("listing", "--cfg", "qualified", "--module", lane,
                                           "--list", self.file("l", listing(["a"], ORDINARY_HEADER)),
                                           "--ignored", self.file("i", listing([], ORDINARY_HEADER)))
                self.assertEqual(code, 2, report)
                self.assertIn("needs --module naming a test lane", report["reason"])

    def test_a_qualified_lane_refuses_zero_selection_another_target_and_a_mismatched_ignore(self):
        code, report = self.qualified("long-run", names=[], ignored=[])
        self.assertEqual(code, 3, report)
        code, report = self.qualified("long-run", names=WORKER_CASES, ignored=[], header=ORDINARY_HEADER)
        self.assertEqual(code, 1, report)
        self.assertIn("the long-run listing spans targets ['kestrike']", report["reason"])
        code, report = self.qualified("long-run", ignored=[])
        self.assertEqual(code, 1, report)
        self.assertIn("declares ignores absent from the --ignored listing", report["reason"])
        code, report = self.qualified("long-run", ignored=WORKER_IGNORED + WORKER_CASES[:1])
        self.assertEqual(code, 1, report)
        self.assertIn("ignored tests without a registry row", report["reason"])
        missing = QUALIFIED_LISTED["campaigns"][1:]
        code, report = self.qualified("campaigns", names=missing)
        self.assertEqual(code, 1, report)
        self.assertIn(f"lists no runnable tests ['{QUALIFIED_LISTED['campaigns'][0]}']", report["reason"])

    def test_a_qualified_run_refuses_no_execution_a_failure_a_cut_run_and_a_nonzero_exit(self):
        gate = select_tests.selection_of(INVENTORY["qualified"]["long-run"])
        listed = len(QUALIFIED_LISTED["long-run"])
        cases = [
            ("no execution", self.qualified_output("long-run", ran=[], filtered=listed), 0, f"executed 0 of {len(gate)} runnable tests"),
            ("a failure", self.qualified_output("long-run", failed=gate[:1]), 101, "failed 1 tests"),
            ("another case run", self.qualified_output("long-run", ran=gate[1:] + WORKER_CASES[:1]), 0, "executed tests outside the listing"),
            ("an unfiltered run", self.qualified_output("long-run", filtered=0), 0, f"filtered out 0 tests, expected {listed - len(gate)}"),
            ("a missing summary", f"{WORKER_HEADER}\n\nrunning 3 tests\nlong-run: churn: seed 10\n", 0, "produced no summary"),
            ("a timeout marker", self.qualified_output("long-run", tail="##[error]The operation was canceled.\n"), 0, "cancel or timeout marker"),
            ("a nonzero exit", self.qualified_output("long-run"), 124, "the run exited 124"),
        ]
        for name, output, exit_code, reason in cases:
            with self.subTest(case=name):
                code, report = self.qualified("long-run", output=output, exit_code=exit_code)
                self.assertEqual(code, 4, report)
                self.assertFalse(report["credited"], report)
                self.assertIn(reason, report["reason"])

    def test_a_capped_or_interrupted_search_blocks_its_row(self):
        capped = ROW_LINES["serve-search-shallow"][0].replace(": Exhaustive ", ": Incomplete ")
        code, report, blocked = self.blocked("search", lines=[capped])
        self.assertEqual(code, 4, report)
        self.assertEqual(list(blocked), ["serve-search-shallow"])
        self.assertIn("bound incomplete: 0 lines match", blocked["serve-search-shallow"][0])
        self.assertIn("blocked rows: serve-search-shallow: bound incomplete", report["reason"])
        shallower = ROW_LINES["serve-search-shallow"][0].replace("depth: 5 }", "depth: 4 }")
        code, report, blocked = self.blocked("search", lines=[shallower])
        self.assertEqual((code, list(blocked)), (4, ["serve-search-shallow"]), report)
        code, report, blocked = self.blocked("search", tail="##[error]The operation was canceled.\n")
        self.assertEqual(code, 4, report)
        self.assertIn("cancel or timeout marker", blocked["serve-search-shallow"][0])
        code, report = self.qualified("search", output=self.qualified_output("search"), exit_code=143)
        self.assertEqual(code, 4, report)
        self.assertIn("the run exited 143", report["reason"])
        others = [line for row in INVENTORY["qualified"]["long-run"]["rows"] if row["id"] != "deeper-suffix-trees" for line in ROW_LINES[row["id"]]]
        deeper = ROW_LINES["deeper-suffix-trees"]
        code, report, blocked = self.blocked("long-run", lines=others + deeper[:-1])
        self.assertEqual((code, list(blocked)), (4, ["deeper-suffix-trees"]), report)
        self.assertIn("bound incomplete: 0 lines match", blocked["deeper-suffix-trees"][0])
        code, report, blocked = self.blocked("long-run", lines=others + [deeper[0], deeper[1].replace("leaf 7", "leaf 6"), deeper[2]])
        deeper_row = next(row for row in INVENTORY["qualified"]["long-run"]["rows"] if row["id"] == "deeper-suffix-trees")
        self.assertEqual(blocked, {"deeper-suffix-trees": [f"missing witness {deeper_row['witnesses'][1]!r}"]})

    def test_an_edited_warm_cycle_line_blocks_only_its_row(self):
        rows = INVENTORY["qualified"]["long-run"]["rows"]
        others = [line for row in rows if row["id"] != "warm-cycles" for line in ROW_LINES[row["id"]]]
        cycles = ROW_LINES["warm-cycles"]
        census = next(line for line in cycles if line.startswith("cycles: census: "))
        composed = next(line for line in cycles if line.startswith("cycles: composed: "))
        unscored = next(line for line in cycles if line.startswith("cycles: unscored: "))
        for name, before, after in (
            ("a gap filled", census, census.replace("covered 4 gap 4", "covered 5 gap 3")),
            ("a recovery kind unreached", composed, composed.replace(" stale 36 ", " stale 0 ")),
            ("a fresh host missed", composed, composed.replace(" fresh-hosts 16 ", " fresh-hosts 15 ")),
            ("an unscored case dropped", unscored, unscored.replace("; a second fresh host", "")),
            ("a failed verdict", cycles[0], cycles[0].replace("retention pass", "retention FAIL [a rule] at the history")),
            ("a publish-aligned pass", cycles[0], cycles[0].replace("publish-aligned conservation inconclusive "
                                                                   "[no checkpoint or frontier publication follows a quiescent boundary]",
                                                                   "publish-aligned conservation pass")),
        ):
            with self.subTest(edit=name):
                self.assertNotEqual(before, after)
                edited = [after if line == before else line for line in cycles]
                code, report, blocked = self.blocked("long-run", lines=others + edited)
                self.assertEqual((code, list(blocked)), (4, ["warm-cycles"]), report)

    def test_an_edited_publishing_cycle_line_blocks_only_its_row(self):
        rows = INVENTORY["qualified"]["long-run"]["rows"]
        others = [line for row in rows if row["id"] != "publishing-cycles" for line in ROW_LINES[row["id"]]]
        cycles = ROW_LINES["publishing-cycles"]
        seed = cycles[0]
        summary = next(line for line in cycles if line.startswith("publishing: 16 seeds "))
        for name, before, after in (
            ("no publication", seed, re.sub(r"; publications [0-9]+;", "; publications 0;", seed)),
            ("a short check count", seed, seed.replace("; checks 96;", "; checks 95;")),
            ("no suffix load", seed, re.sub(r"; suffix loads [0-9]+;", "; suffix loads 0;", seed)),
            ("a short identity", seed, re.sub(r"identity ([0-9a-f]{15})[0-9a-f]$", r"identity \1", seed)),
            ("a short summary check count", summary, summary.replace("checks 1536", "checks 1535")),
            ("another restart count", summary, summary.replace("of 8 restarts", "of 7 restarts")),
        ):
            with self.subTest(edit=name):
                self.assertNotEqual(before, after)
                edited = [after if line == before else line for line in cycles]
                code, report, blocked = self.blocked("long-run", lines=others + edited)
                self.assertEqual((code, list(blocked)), (4, ["publishing-cycles"]), report)

    def test_a_fleet_settle_count_past_the_bound_blocks_only_its_row(self):
        rows = INVENTORY["qualified"]["long-run"]["rows"]
        others = [line for row in rows if row["id"] != "fleet-roots" for line in ROW_LINES[row["id"]]]
        fleet = ROW_LINES["fleet-roots"]
        closing = "settle at most 19 of 64 rounds"
        self.assertTrue(fleet[-1].endswith(closing))
        for count, credited in ((0, False), (3, False), (4, True), (64, True), (65, False), (100, False), ("064", False), ("07", False)):
            with self.subTest(count=count):
                edited = fleet[:-1] + [fleet[-1].replace(closing, f"settle at most {count} of 64 rounds")]
                code, report, blocked = self.blocked("long-run", lines=others + edited)
                self.assertEqual((code, list(blocked)), (0, []) if credited else (4, ["fleet-roots"]), report)
        second = fleet + [fleet[-1].replace(closing, "settle at most 65 of 64 rounds")]
        code, report, blocked = self.blocked("long-run", lines=others + second)
        self.assertEqual((code, list(blocked)), (4, ["fleet-roots"]), report)
        self.assertIn("bound incomplete: 2 lines match", blocked["fleet-roots"][0])

    def test_a_missing_scheduled_fleet_check_or_crash_cell_blocks_only_its_row(self):
        rows = INVENTORY["qualified"]["search-nightly"]["rows"]
        others = [line for row in rows if row["id"] != "fleet-scheduled-roots" for line in ROW_LINES[row["id"]]]
        scheduled = ROW_LINES["fleet-scheduled-roots"]
        self.assertEqual(len(scheduled), 162)
        witnesses = next(row for row in rows if row["id"] == "fleet-scheduled-roots")["witnesses"]
        code, report, blocked = self.blocked("search-nightly", lines=others + scheduled)
        self.assertEqual((code, blocked), (0, {}), report)
        for name, lines, reason in (
            ("a skipped check", [line for line in scheduled if " lost-alone root 2" not in line], "skipped members ['volume lost-alone root 2']"),
            ("a skipped cell", [line for line in scheduled if " replace-flip-committed " not in line],
             "skipped members ['volume replace-flip-committed root 1']"),
            ("a repeated cell", scheduled + scheduled[11:12], "repeated members ['volume replace-replacement-acknowledged root 1']"),
            ("another root", scheduled + [scheduled[0].replace("root 2", "root 3")], "unexpected members ['volume no-fault root 3']"),
            ("a short count", [line.replace("21 crash cells", "20 crash cells") for line in scheduled], f"missing witness {witnesses[0]!r}"),
            ("a skipped zone check", [line for line in scheduled if " zone loss-replay " not in line], "skipped members ['zone loss-replay root 1']"),
            ("a skipped repair check", [line for line in scheduled if " census-full " not in line],
             "skipped members ['repair-and-host census-full root 2']"),
            ("a short zone count", [line.replace("zone: 3 checks", "zone: 2 checks") for line in scheduled], f"missing witness {witnesses[1]!r}"),
            ("a skipped enrollment cell", [line for line in scheduled if " fresh-designate-committed " not in line],
             "skipped members ['repair-and-host fresh-designate-committed root 1']"),
            ("a short repair count", [line.replace("host: 32 checks", "host: 31 checks") for line in scheduled],
             f"missing witness {witnesses[2]!r}"),
            ("a skipped alarm set", [line for line in scheduled if " alarms-census-full " not in line],
             "skipped members ['alarms-census-full root 1']"),
            ("a skipped alarm control", [line for line in scheduled if " alarms-control-extra-row " not in line],
             "skipped members ['alarms-control-extra-row root 1']"),
            ("a short alarm count", [line.replace("alarms: 64 sets", "alarms: 63 sets") for line in scheduled],
             f"missing witness {witnesses[3]!r}"),
        ):
            with self.subTest(edit=name):
                code, report, blocked = self.blocked("search-nightly", lines=others + lines)
                self.assertEqual((code, blocked), (4, {"fleet-scheduled-roots": [reason]}), report)

    def test_an_edited_slot_reuse_line_blocks_only_its_row(self):
        rows = INVENTORY["qualified"]["long-run"]["rows"]
        others = [line for row in rows if row["id"] != "slot-reuse-cycles" for line in ROW_LINES[row["id"]]]
        cycles = ROW_LINES["slot-reuse-cycles"]
        totals = cycles[-1]
        for name, before, after in (
            ("a replacement short", totals, totals.replace("replacements 384 ", "replacements 383 ")),
            ("a replacement extra", totals, totals.replace("replacements 384 ", "replacements 385 ")),
            ("a drop extra", totals, totals.replace(" drops 384 ", " drops 385 ")),
            ("a drop short", totals, totals.replace(" drops 384 ", " drops 383 ")),
            ("no preempt", totals, totals.replace(" preempts 9 ", " preempts 0 ")),
            ("a fourth live attach", totals, totals.replace(" live-max 3;", " live-max 4;")),
            ("two live attaches", totals, totals.replace(" live-max 3;", " live-max 2;")),
            ("a failed verdict", cycles[0], cycles[0].replace("containment pass", "containment FAIL [a rule] at cycle 1")),
        ):
            with self.subTest(edit=name):
                self.assertNotEqual(before, after)
                edited = [after if line == before else line for line in cycles]
                code, report, blocked = self.blocked("long-run", lines=others + edited)
                self.assertEqual((code, list(blocked)), (4, ["slot-reuse-cycles"]), report)

    def test_a_missing_or_repeated_witness_blocks_its_row(self):
        lines = [line for row in INVENTORY["qualified"]["campaigns"]["rows"] for line in ROW_LINES[row["id"]]]
        dropped = [line for line in lines if not line.startswith("bundle: ")]
        code, report, blocked = self.blocked("campaigns", lines=dropped)
        self.assertEqual(code, 4, report)
        self.assertEqual(list(blocked), ["worker-campaigns"])
        self.assertTrue(blocked["worker-campaigns"][0].startswith("missing witness '^bundle: "), blocked)
        code, report, blocked = self.blocked("campaigns", lines=lines + lines[:1])
        self.assertTrue(blocked["worker-campaigns"][0].startswith("repeated witness '^bundle: "), blocked)
        unarmed = [line for line in lines if not line.startswith("bundle: contended ")]
        self.assertEqual(len(unarmed), len(lines) - 1)
        code, report, blocked = self.blocked("campaigns", lines=unarmed)
        self.assertEqual((code, list(blocked)), (4, ["worker-campaigns"]), report)
        self.assertTrue(blocked["worker-campaigns"][0].startswith("missing witness '^bundle: contended "), blocked)
        gate = [line for line in ROW_LINES["long-run-gate"] if not line.startswith("long-run: mixed witnesses")]
        others = [line for row in INVENTORY["qualified"]["long-run"]["rows"] if row["id"] != "long-run-gate" for line in ROW_LINES[row["id"]]]
        code, report, blocked = self.blocked("long-run", lines=gate + others)
        self.assertEqual(list(blocked), ["long-run-gate"], report)
        self.assertIn("missing witness '^long-run: mixed witnesses", blocked["long-run-gate"][0])

    def test_an_unreached_or_feature_short_kernel_leaves_its_isa_row_uncredited(self):
        """A kernel that did not run, ran on a host short of one feature of its predicate, or printed its line twice
        leaves its row blocked while the scalar result checks pass and every other row credits."""
        lines = [line for row in INVENTORY["qualified"]["isa-x86-64"]["rows"] for line in ROW_LINES[row["id"]]]
        hmac = ROW_LINES["x86-hmac-16"][0]
        for name, replacement in (
            ("unreached", f"isa: hmac-wide-16 unreached; {X86_HMAC}"),
            ("zero count", f"isa: hmac-wide-16 ran 0 times; {X86_HMAC}"),
            ("feature short", hmac.replace("avx512bw=true", "avx512bw=false")),
            ("another architecture", "isa: hmac-wide-16 unreached; host aarch64 lacks x86_64"),
            ("another batch's count", hmac.replace("hmac-wide-16", "hmac-wide-15")),
        ):
            with self.subTest(witness=name):
                code, report, blocked = self.blocked("isa-x86-64", lines=[replacement if line == hmac else line for line in lines])
                self.assertEqual(code, 4, report)
                self.assertIn("x86-hmac-16", blocked, report)
                self.assertTrue(blocked["x86-hmac-16"][0].startswith("missing witness '^isa: hmac-wide-16 ran "), blocked)
                self.assertLessEqual(set(blocked), {"x86-hmac-15", "x86-hmac-16"}, blocked)
        code, report, blocked = self.blocked("isa-aarch64", lines=[
            line for row in INVENTORY["qualified"]["isa-aarch64"]["rows"] for line in ROW_LINES[row["id"]]
            if not line.startswith("isa: sha2-three ")])
        self.assertEqual((code, list(blocked)), (4, ["aarch64-sha2-chains"]), report)
        self.assertIn("missing witness '^isa: sha2-three ran ", blocked["aarch64-sha2-chains"][0])

    def test_a_skipped_unexpected_or_repeated_member_blocks_its_row(self):
        rows = INVENTORY["qualified"]["long-run"]["rows"]
        seeds = ROW_LINES["scaled-seeds"]
        other = [line for row in rows if row["id"] != "scaled-seeds" for line in ROW_LINES[row["id"]]]
        for name, members, reason in (
            ("skipped", [line for line in seeds if " seed 3 " not in line], "skipped members ['units=64 slots=16 chunk=8192 reserve=2 seed 3']"),
            ("unexpected", seeds + [seeds[0].replace(" seed 0 ", " seed 12 ")], "unexpected members ['units=64 slots=16 chunk=8192 reserve=2 seed 12']"),
            ("repeated", seeds + seeds[1:2], "repeated members ['units=64 slots=16 chunk=8192 reserve=2 seed 1']"),
        ):
            with self.subTest(member=name):
                code, report, blocked = self.blocked("long-run", lines=other + members)
                self.assertEqual(code, 4, report)
                self.assertEqual(blocked, {"scaled-seeds": [reason]}, report)
        by_id = {row["id"]: row for row in rows}
        self.assertEqual(select_tests.members_of(by_id["scaled-seeds"]), [f"units=64 slots=16 chunk=8192 reserve=2 seed {seed}" for seed in range(12)])
        self.assertEqual(len(select_tests.members_of(by_id["scaled-geometries"])), 24)
        first = INVENTORY["qualified"]["campaigns"]["rows"][1]["members"][0]
        code, report, blocked = self.blocked("campaigns", lines=ROW_LINES["worker-campaigns"] + ROW_LINES["history-cohorts"][1:] + ROW_LINES["fleet-replay"])
        self.assertEqual((code, blocked), (4, {"history-cohorts": [f"skipped members ['{first}']"]}), report)

    def test_a_skipped_or_duplicate_selection_blocks_the_lane_and_its_row(self):
        selection = select_tests.selection_of(INVENTORY["qualified"]["campaigns"])
        listed = len(QUALIFIED_LISTED["campaigns"])
        skipped = self.qualified_output("campaigns", ran=selection[1:], filtered=listed - len(selection) + 1)
        code, report = self.qualified("campaigns", output=skipped)
        self.assertEqual(code, 4, report)
        self.assertIn(f"executed {len(selection) - 1} of {len(selection)} runnable tests", report["reason"])
        self.assertEqual([row["id"] for row in report["rows"] if not row["credited"]], ["worker-campaigns"])
        self.assertIn(f"tests ['{selection[0]}'] did not pass", report["rows"][0]["reasons"][0])
        duplicate = self.qualified_output("campaigns", ran=selection + selection[:1], filtered=listed - len(selection))
        code, report = self.qualified("campaigns", output=duplicate)
        self.assertEqual(code, 4, report)
        self.assertFalse(report["credited"], report)
        self.assertIn(f"executed {len(selection) + 1} of {len(selection)} runnable tests", report["reason"])
        self.assertEqual([(row["id"], row["credited"]) for row in report["rows"]],
                         [("worker-campaigns", False), ("history-cohorts", True), ("fleet-replay", True)])
        self.assertEqual(report["rows"][0]["reasons"], [f"tests ['{selection[0]}'] ran more than once"])

    def test_consumes_doc_test_summaries_like_any_target(self):
        doc_header = "   Doc-tests kestrike"
        doc_tests = ["crates/kestrike/src/storage/os.rs - storage::os::Platform (line 146)"]
        declared = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        base = [
            "listing", "--cfg", "ordinary", "--crate", "kestrike",
            "--target", "kestrike", "--target", "doc:kestrike",
            "--list", self.file("list", listing(ORDINARY_RUNNABLE + declared, ORDINARY_HEADER) + listing(doc_tests, doc_header)),
            "--ignored", self.file("ignored", listing(declared, ORDINARY_HEADER) + listing([], doc_header)),
        ]
        run = f"{ordinary_run()}{doc_header}\n{outcomes(doc_tests)}{summary(1, 0, 0)}\n"
        code, report = self.select("run", *base[1:], "--output", self.file("output", run), "--exit", "0")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["doc:kestrike"]["executed"], 1)
        merged = f"{run}{summary(0, 0, 0)}\n"
        code, report = self.select("run", *base[1:], "--output", self.file("output", merged), "--exit", "0")
        self.assertEqual(code, 0, report)
        code, report = self.select("run", *base[1:], "--output", self.file("output", ordinary_run()), "--exit", "0")
        self.assertEqual(code, 4, report)

    def test_a_mode_suffix_on_an_outcome_line_maps_to_the_listed_bare_name(self):
        # The lines libtest prints for a should_panic test, a compile_fail
        # doc-test and a no_run doc-test of `campaign-supervisor`.
        header = "     Running unittests src/lib.rs (target/debug/deps/campaign_supervisor-f73d96a7c4a05f19)"
        doc_header = "   Doc-tests campaign_supervisor"
        panicking = "record::stored_tests::a_record_for_another_stores_directory_panics"
        plain = "record::stored_tests::typed_replacement_checks_the_bound_before_mutation"
        docs = [
            "crates/campaign-supervisor/src/record/identity.rs - record::identity::JobId (line 22)",
            "crates/campaign-supervisor/src/store/mod.rs - store (line 43)",
            "crates/campaign-supervisor/src/record/identity.rs - record::identity::JobId (line 15)",
        ]
        declared = INVENTORY["ordinary"]["campaign-supervisor"]["ignored"]["campaign_supervisor"]
        doc_listing = f"{doc_header}\n{docs[1]}: test\n{docs[2]}: test\n\n2 tests, 0 benchmarks\n{docs[0]}: test\n\n1 test, 0 benchmarks\n"
        base = [
            "--cfg", "ordinary", "--crate", "campaign-supervisor",
            "--target", "campaign_supervisor", "--target", "doc:campaign_supervisor",
            "--list", self.file("list", listing([plain, panicking] + declared, header) + doc_listing),
            "--ignored", self.file("ignored", listing(declared, header) + listing([], doc_header)),
        ]
        run = (
            f"{header}\ntest {plain} ... ok\ntest {panicking} - should panic ... ok\n"
            f"{outcomes([], declared)}{summary(2, 0, len(declared))}\n{doc_header}\n"
            f"test {docs[1]} - compile ... ok\ntest {docs[2]} ... ok\n{summary(2, 0, 0)}\n"
            f"test {docs[0]} - compile fail ... ok\n{summary(1, 0, 0)}\n"
        )
        code, report = self.select("listing", *base)
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["doc:campaign_supervisor"]["listed"], 3)
        code, report = self.select("run", *base, "--output", self.file("output", run), "--exit", "0")
        self.assertEqual(code, 0, report)
        self.assertEqual(report["targets"]["campaign_supervisor"]["executed"], 2)
        self.assertEqual(report["targets"]["doc:campaign_supervisor"]["executed"], 3)
        other = run.replace(f"test {panicking} - should panic ... ok", f"test {panicking} - benchmark ... ok")
        code, report = self.select("run", *base, "--output", self.file("output", other), "--exit", "0")
        self.assertEqual(code, 4, report)
        self.assertIn("executed tests outside the listing", report["reason"])
        footer = f"\n{len(declared) + 2} tests, 0 benchmarks\n"
        twice = listing([plain, panicking] + declared, header).replace(footer, footer * 2)
        code, report = self.select("listing", *base[:8], "--list", self.file("twice", twice + doc_listing), *base[10:])
        self.assertEqual(code, 2, report)
        self.assertIn("two test count footers", report["reason"])

    def test_rejects_a_failed_or_repeated_outcome_under_a_clean_summary(self):
        declared = INVENTORY["loom"]["credit_model"]
        ran = [name for name in declared["tests"] if name not in declared["ignored"]]
        failed = f"{LOOM_HEADER}\n{outcomes(ran, declared['ignored'], failed=ran[:1])}{LOOM_SUMMARY}\n"
        code, report = self.loom(output=failed)
        self.assertEqual(code, 4, report)
        self.assertIn("failed outcomes", report["reason"])
        repeated = f"{LOOM_HEADER}\n{outcomes(ran + ran[:1], declared['ignored'])}{LOOM_SUMMARY}\n"
        code, report = self.loom(output=repeated)
        self.assertEqual(code, 4, report)
        self.assertIn(f"{CREDIT_MODEL_TESTS + 1} executed outcomes", report["reason"])

    def test_rejects_an_ordinary_listing_without_runnable_tests(self):
        code, report = self.ordinary(runnable=[])
        self.assertEqual(code, 3, report)
        self.assertIn("runnable", report["reason"])

    def test_an_ordinary_run_executes_the_listed_tests(self):
        ignored = INVENTORY["ordinary"]["kestrike"]["ignored"]["kestrike"]
        other = ORDINARY_RUNNABLE[2:] + [f"storage::witness_tests::case_{index}" for index in range(2)]
        code, report = self.ordinary(output=ordinary_run(runnable=other))
        self.assertEqual(code, 4, report)
        self.assertIn("executed tests outside the listing", report["reason"])
        code, report = self.ordinary(output=f"{ORDINARY_HEADER}\n{summary(len(ORDINARY_RUNNABLE), 0, len(ignored))}\n")
        self.assertEqual(code, 4, report)
        self.assertIn(f"0 executed outcomes for a summary of {len(ORDINARY_RUNNABLE)}", report["reason"])
        swapped = ordinary_run(
            runnable=ORDINARY_RUNNABLE[:1] + ignored[:1] + ORDINARY_RUNNABLE[2:],
            ignored=[ORDINARY_RUNNABLE[1]] + ignored[1:],
        )
        code, report = self.ordinary(output=swapped)
        self.assertEqual(code, 4, report)
        self.assertIn("executed tests outside the listing", report["reason"])
        code, report = self.ordinary(output=ordinary_run(runnable=ORDINARY_RUNNABLE[:1] * 2 + ORDINARY_RUNNABLE[2:]))
        self.assertEqual(code, 4, report)
        self.assertIn("omits listed executed tests", report["reason"])

    def test_strips_cargo_color_from_every_input(self):
        def colored(text):
            return text.replace("     Running", "\x1b[1m\x1b[92m     Running\x1b[0m").replace("... ok", "... \x1b[32mok\x1b[0m")

        declared = INVENTORY["loom"]["credit_model"]
        code, report = self.select(
            "run", "--cfg", "loom", "--module", "credit_model",
            "--list", self.file("l", colored(listing(declared["tests"], LOOM_HEADER))),
            "--ignored", self.file("i", colored(listing(declared["ignored"], LOOM_HEADER))),
            "--output", self.file("o", colored(loom_run())), "--exit", "0",
        )
        self.assertEqual(code, 0, report)


if __name__ == "__main__":
    unittest.main()
