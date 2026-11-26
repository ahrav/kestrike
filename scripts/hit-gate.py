#!/usr/bin/env python3
"""Judge the open-loop hit-latency qualification from hardware-lane receipts.

Usage:
  hit-gate.py check [--manifest F] [--obligations F]
  hit-gate.py schedule --main SHA --candidate SHA --workload W --phase P [--permille N] [--manifest F]
                       [--obligations F]
  hit-gate.py judge --campaign F [--manifest F] [--obligations F] [--output F]

The predeclared qualification is the `qualification` object of
`scripts/hardware-profiles.json`, so every lane receipt's `manifest_sha256`
binds the protocol it ran under, and `judge` credits a run only through
`hardware-lane.py`'s own `judge_profile` under the current manifest digest.
Every command first validates the whole manifest with the lane's
`check_manifest`. `check` validates the qualification and lists the open items
that keep a judgment from passing. `schedule` prints the campaign id and the
workload seed every run of a declared cell uses, then the cell's run order.
`judge` writes a receipt whose `verdict` is `pass`, `fail`, `inconclusive` or
`handoff`, and exits 0 only for `pass` and 1 for any other verdict. It exits 2
and writes no receipt for a refused input: a malformed manifest, obligation
catalog, campaign file or run coordinate, or a failed receipt write; a file
already at `--output` then stays as it was, so only exit status 0 or 1 shows
that the file is this invocation's receipt. A malformed, unreadable or unbound
lane receipt or samples file makes only its cell inconclusive, with the fault
as the cell's reason.

The gate receipt holds the envelope, `manifest_sha256`, `campaign_sha256` (the
campaign file's bytes), `judge_sha256` (this script's bytes, recorded as
provenance and compared with nothing; it does not cover `hardware-lane.py`),
the campaign id, revisions and seed, the open items, one result per cell with
the run ids and samples digests it admitted and, as `bound`, the host instances
and volumes of its admitted runs, which a cell refused after it admitted runs
keeps, the pacing selection, the recovery result, the preservation handoff when
there is one, and the verdict.

The campaign file is a JSON object the campaign driver writes. Receipts bind
the campaign id, revisions and runs; the safety object is the driver's own
statement, checked for completeness, for consistency with the campaign id,
and against the host instances and volumes the admitted runs' receipts bind:
each of those ids must be a create the object guards or a resource it declares
standing. A run is admitted when `admit` returns for it. A run `admit`
refuses, every run after a cell's first refusal, and every run of a cell the
judge does not admit run by run (one off its schedule, blocked, outside the
manifest or behind a campaign blocker) binds nothing, so the object is asked
about that hardware only in a judgment that admits those runs. Which ids are
standing, and its teardown and residue lists, are taken on the file's word.
  campaign   `hit-gate-` and the seed in 16 hex digits, as `schedule` prints
             it; each run's lane episode is the interface's `run_identity`
             built from it, which the receipts bind. One manifest and revision
             pair therefore has one campaign, and a retry of it takes a
             reviewed manifest change that alters the digest. A lane sweep
             refuses an episode whose log its observer directory holds; the
             caller names that directory and no receipt records it. That
             each run identity ran once is therefore the driver's own
             statement, taken on the file's word as the safety object is.
  main, candidate
             the pinned main and candidate revisions, distinct non-empty
             strings; every receipt of an arm must name its arm's revision.
  safety     `tag` {key, value = campaign}, `owner`, `budget_usd`, `deadline`
             (UTC, `YYYY-MM-DDTHH:MM:SSZ`), `teardown_on_failure` true,
             `preexisting` (the ids the campaign must not touch), `resources`
             (each {id, tags}, whose tags map the tag key to the campaign id
             and `owner` to the safety `owner`), `teardown` (ids), `standing`
             (the ids of the hosts and volumes the campaign runs on and did
             not create, an empty list when it created them all) and `residue`
             (the ids residue verification found, an empty list when none);
             every id is a non-empty string. A gap is reported as such.
  runs       a list of {workload, phase, permille, block, slot, repeat,
             receipts, samples?}: the run's cell and schedule position, the
             paths of its lane receipts, one per profile role, and optionally
             the path of the samples artifact collected from the client host,
             whose bytes must hash to the digest the cell printed; without it
             the judge opens the path the client receipt recorded as
             `KESTRIKE_HIT_SAMPLES`. Paths are opened as given, so a relative
             path resolves against the judge's working directory.

A gated cell is one workload, phase and publish share. The publish share
(`permille`) caps aggregate checkpoint write and readback traffic in
thousandths of the qualified volume bandwidth, so the ladder 100, 50, 25 is
10%, 5% and 2.5%; it is 0 outside the pacing phase. A cell's schedule is
`null_blocks` A/A blocks of the main revision, then `blocks`
main-vs-candidate blocks. Each block is four positions in ABBA or BAAB order,
each position `repeats` runs, at most MAX_RUNS runs and MAX_CELL_SAMPLES
samples a cell. A run's plan ends at least SERVE_MARGIN_S seconds before the
owner's serving window does, which leaves time for the client's device
bring-up and session open, the drain of queued GETs, the samples write and
sync, and the quiet GET before the close tail. Each group of blocks takes the
two orders in counts that differ by at most one, shuffled by a seed that is
the SHA-256 of the manifest digest and the two revisions, so neither the order
nor the workload seed is a producer's choice. Every run is one lane episode
with one credited receipt per profile role, and its client receipt binds the
run's samples file by the SHA-256 its `observe: hit-gate` line printed. The
samples file must hold exactly the protocol's request count of lines after its
header, which is checked on the raw bytes before any sample is parsed. The
header must carry the manifest's workload, records and weights, the offered
rate, the request count and the derived workload seed; each sample's intended
send must follow the fixed-interval arrival schedule from the first one and its
record must be the seeded draw for its index. A run's `previous` header field
names the digest of the run before it in schedule order, `none` for the first,
so a run whose samples were written before its predecessor's cannot take its
place, and no two runs of a cell may hold the same sample lines.

A run's receipts must bind its hardware and route. Each role's mappings file
must have the digest at its case's end that the lane read before it spawned
the case. The case holds the state directory's bind lock while it runs, so
`kestrike-bind` cannot republish the file meanwhile; a plain write restored
to the same bytes before the case ends is the driver's own statement, taken on
its word as the safety object is. The roles run on distinct host instances,
each role's mappings file records its own ENI address, the client's
`KESTRIKE_PEER` is the owner's address, and the owner's `KESTRIKE_PEER`
lists the client's address alone, so the samples were routed to the credited
owner while it served that one client. Every run of a cell must share one
host, volume, PCI functions, ENI addresses, toolchain and client plan, the
runs of each revision one dependency set, and every run must have built under
the qualification's `build_environment`, which pins the Cargo profile's
optimization level. The cells that admit their runs must share that host,
volume, PCI functions, ENI addresses and toolchain, and each revision's
dependency set, across the campaign; a campaign whose admitted cells differ in
any of them is inconclusive.

A sample is `[intended_us, attempted_us, admitted_us, end_us, record, stratum,
source]`: its intended send, the first client pass at or after it, the pass
at which the client admitted the GET, and its end. A sample's latency is its
end minus its intended send in whole microseconds, so queueing behind the
client's slots counts. The gate pools the hits of the
run's routed owner, its header `source`; samples tagged with any other source
are residual traffic, counted by stratum and never pooled. The idle phase's
activity interval is the whole run. The other phases need an activity interval
that a credited receipt binds, and no cell prints one on this revision, so the
manifest marks them blocked and their cells stay inconclusive.

The comparison is per block: each block yields one observation
d = (Q(B1) + Q(B2) - Q(A1) - Q(A2)) / 2 for each gated quantile, where Q is the
quantile of one position's pooled repeats, so an additive drift linear in
position cancels in either order. A position with fewer than the protocol's
`position_hits` routed-owner hits leaves its block missing. The uncertainty
band is the widest |d| of the A/A null blocks; under exchangeable null blocks
a further null block exceeds it with probability at most
1 / (null_blocks + 1), and the protocol's `band_coverage` must not exceed
null_blocks / (null_blocks + 1). Applying the band to candidate blocks assumes
they share the null blocks' noise; it is the campaign's measured A/A spread,
not a false-failure bound for correlated EBS tails. The comparison passes when
every candidate block's d plus the band is at most the tolerance, fails when
every block's d minus the band exceeds it, and is inconclusive otherwise, when
the band itself exceeds the tolerance, or when a declared block is missing.

A cell's verdict takes measurement validity first. A run in which any
request's first attempt comes more than the protocol's `max_lag_us` after its
intended send is generator-limited, and its cell is inconclusive whatever its
latencies show. The wait from the first attempt to the admission is time
behind the client's slots, which the owner's responses cause; it stays in the
latency and is reported as `wait`.
Otherwise two bounds bind on the candidate arm whatever the comparison says.
The quantiles cover hits only, so a GET the owner refuses or misses, or one
the client times out, leaves them; the protocol's `max_non_hits` is the most
routed-owner samples other than hits that an arm may pool over the candidate
blocks, and a candidate arm past it fails the cell however many hits it
pools. The absolute workload ceilings bind once the candidate arm pools
`min_hits` hits over the candidate blocks: its pooled p90 below `p90_ms` and
p99 below `p99_ms`, where only a workload other than `request-weighted` that
declares `large_object` may take the 5 ms p99 ceiling. A breached ceiling
fails the cell. Otherwise an arm short of `min_hits`, or a main arm past
`max_non_hits`, leaves it inconclusive, and the comparison decides.

Pacing takes the manifest's publish-share ladder in order: it selects the
first share at which every workload's publish cell passes, moves to the next
share only after a failed gate, stops inconclusive at a share without a
verdict, and returns the publish path's architecture as the blocker when every
share fails. Publish cells enter the verdict only through this selection.
Recovery is inconclusive until a declared recovery case prints a record that
a credited receipt binds; the manifest's recovery object predeclares its
bounds. A failed preservation qualification makes the verdict `handoff`
whatever was measured. A missing declared cell, a safety gap or any absent
evidence is `inconclusive`; nothing in this judgment invents a pass.
"""

import argparse
import hashlib
import importlib.util
import json
import math
import os
import random
import re
import stat
import sys
import tempfile
from datetime import datetime
from fractions import Fraction
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "hardware-profiles.json"
OBLIGATIONS = HERE.parent / "verification/obligations.json"
ENVELOPE = {"version": 1, "section": "hit-gate"}
PHASES = ("idle", "publish", "takeover", "scan")
NOMINAL = "request-weighted"
QUANTILES = {"p50": Fraction(1, 2), "p90": Fraction(9, 10), "p99": Fraction(99, 100), "p999": Fraction(999, 1000)}
GATED = ("p90", "p99")
QUALIFICATION_KEYS = {"profile", "cell", "workloads", "offered_rate", "min_hits", "build_environment", "phases",
                      "protocol", "pacing", "recovery", "preservation", "interface"}
PROTOCOL_COUNTS = ("null_blocks", "blocks", "repeats", "requests", "max_lag_us", "position_hits")
PROTOCOL_KEYS = {*PROTOCOL_COUNTS, "max_non_hits", "band_coverage", "tolerance_ms"}
SAMPLES = re.compile(r"samples (\d+) hits (\d+) sha256 ([0-9a-f]{64})")
DIGEST = re.compile(r"[0-9a-f]{64}")
STRATA = ("hit", "miss", "refused", "error")
HEADER_KEYS = {"workload", "records", "weights", "rate", "requests", "seed", "previous", "slots", "source",
               "started_unix_ms"}
RUN_FIELDS = ("campaign", "workload", "phase", "permille", "block", "slot", "repeat")
INTENDED, ATTEMPTED, ADMITTED, END, RECORD, STRATUM, SOURCE = range(7)
U64 = 1 << 64
GAMMA = 0x9E37_79B9_7F4A_7C15
READ_LIMIT = 1 << 30
MAX_REQUESTS = 1 << 22
MAX_RUNS = 4096
MAX_CELL_SAMPLES = 1 << 25
SERVE_MARGIN_S = 120
OPT_LEVEL = "CARGO_PROFILE_DEV_OPT_LEVEL"


class Refusal(Exception):
    pass


FAULTS = (Refusal, OSError, ValueError, KeyError, TypeError, AttributeError, IndexError, RecursionError,
          ArithmeticError, MemoryError)


def lane_module():
    spec = importlib.util.spec_from_file_location("hardware_lane", HERE / "hardware-lane.py")
    if spec is None or spec.loader is None:
        raise Refusal("scripts/hardware-lane.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def parse(text, what):
    """`text` decoded as JSON, or a Refusal naming `what`."""
    try:
        return json.loads(text)
    except (ValueError, TypeError, RecursionError) as error:
        raise Refusal(f"{what} is not JSON: {error}") from error


def read_file(path, what, limit=None):
    """The bytes of the regular file at `path`, at most `limit` of them (READ_LIMIT when the caller passes none), or a
    Refusal naming `what`. The size check reads the open descriptor before any byte of the file, so a file over the
    limit costs no read. The open never blocks, so a FIFO or device at the path is refused instead of read, and the
    read asks for the size the file had when opened plus one byte, so a file that grew after the check is refused
    instead of truncated."""
    if limit is None:
        limit = READ_LIMIT
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC)
    except (OSError, TypeError, ValueError) as error:
        raise Refusal(f"{what} {path!r} is unreadable: {error}") from error
    try:
        info = os.fstat(descriptor)
        if not stat.S_ISREG(info.st_mode):
            raise Refusal(f"{what} {path!r} is not a regular file")
        if info.st_size > limit:
            raise Refusal(f"{what} {path!r} exceeds {limit} bytes")
        with os.fdopen(descriptor, "rb") as file:
            descriptor = None
            data = file.read(info.st_size + 1)
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(data) > info.st_size:
        raise Refusal(f"{what} {path!r} grew while it was read")
    return data


def integer(value, low=0, high=U64 - 1):
    return isinstance(value, int) and not isinstance(value, bool) and low <= value <= high


def positive(value):
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return value > 0 if isinstance(value, int) else math.isfinite(value) and value > 0


def microseconds(milliseconds):
    """A declared millisecond value as exact microseconds."""
    return Fraction(str(milliseconds)) * 1000


def draw(seed, i, weights):
    """Request `i`'s record: the first SplitMix64 output seeded with `seed + i`, modulo the weight sum, located in the
    cumulative weights, as the cell's `Plan::record` draws it."""
    z = (seed + i + GAMMA) % U64
    z = ((z ^ (z >> 30)) * 0xBF58_476D_1CE4_E5B9) % U64
    z = ((z ^ (z >> 27)) * 0x94D0_49BB_1331_11EB) % U64
    left = (z ^ (z >> 31)) % sum(weights)
    for n, weight in enumerate(weights):
        if left < weight:
            return n
        left -= weight
    raise AssertionError("a draw below the weight sum lies in one record's range")


def campaign_seed(digest, main, candidate):
    """The schedule and workload seed of a campaign over `main` and `candidate` under the manifest `digest`."""
    return int(hashlib.sha256(f"{digest}/{main}/{candidate}".encode()).hexdigest()[:16], 16)


def campaign_id(seed):
    return f"hit-gate-{seed:016x}"


def revisions(main, candidate):
    """Whether `main` and `candidate` name two distinct revisions."""
    return isinstance(main, str) and isinstance(candidate, str) and bool(main) and bool(candidate) and main != candidate


def declared_cells(q):
    """Every cell the qualification declares: each workload in each phase other than the pacing phase at share 0,
    and in the pacing phase at each ladder share."""
    ladder, publish = q["pacing"]["ladder_permille"], q["pacing"]["phase"]
    return ([(w, p, 0) for w in q["workloads"] for p in PHASES if p != publish]
            + [(w, publish, permille) for permille in ladder for w in q["workloads"]])


def undeclared(q):
    """The open item for each value a judgment needs that the qualification leaves undeclared."""
    protocol = q["protocol"]
    items = ["the workload manifest declares no offered_rate"] if q["offered_rate"] is None else []
    if q["build_environment"] is None:
        items.append("the qualification declares no build_environment, so no build profile is pinned")
    items += [f"the protocol declares no {key}" for key in (*PROTOCOL_COUNTS, "max_non_hits", "band_coverage")
              if protocol[key] is None]
    items += [f"the protocol declares no {name} tolerance" for name, v in protocol["tolerance_ms"].items() if v is None]
    return items


def check(document, obligation_ids):
    """Raise Refusal at the first malformed field of the manifest's qualification; return its open items, each a
    reason the committed evidence cannot yet pass."""
    def need(condition, message):
        if not condition:
            raise Refusal(f"malformed qualification: {message}")

    q = document.get("qualification")
    need(isinstance(q, dict) and set(q) == QUALIFICATION_KEYS, "keys")
    need(all(isinstance(q[key], dict) for key in ("workloads", "phases", "protocol", "pacing", "recovery",
                                                  "preservation", "interface")), "sections are objects")
    profile = document["profiles"].get(q["profile"])
    need(isinstance(profile, dict), f"profile {q['profile']!r} is not declared")
    cases = {role: [case["id"] for case in spec["cases"]] for role, spec in profile["roles"].items()}
    need(any(q["cell"] in ids for ids in cases.values()), "the cell is no case of the profile")
    workloads = q["workloads"]
    need(NOMINAL in workloads, f"workloads must include {NOMINAL}")
    for name, workload in workloads.items():
        need(isinstance(workload, dict), f"workload {name}")
        records, weights = workload.get("records"), workload.get("weights")
        need(isinstance(records, list) and records and all(
            isinstance(r, list) and len(r) == 2 and all(integer(v) for v in r) for r in records),
            f"workload {name} records")
        need(isinstance(weights, list) and len(weights) == len(records)
             and all(integer(w) for w in weights) and sum(weights) > 0, f"workload {name} weights")
        large = workload.get("large_object", False)
        need(large is False or (large is True and name != NOMINAL), f"workload {name} large_object")
        ceiling = 5.0 if large else 3.0
        need(positive(workload.get("p90_ms")) and workload["p90_ms"] <= 1.0, f"workload {name} p90_ms over 1.0")
        need(positive(workload.get("p99_ms")) and workload["p99_ms"] <= ceiling, f"workload {name} p99_ms over {ceiling}")
        need(set(workload) <= {"records", "weights", "large_object", "p90_ms", "p99_ms", "blocked"}
             and isinstance(workload.get("blocked", ""), str), f"workload {name} keys")
    need(q["offered_rate"] is None or integer(q["offered_rate"], 1, 1_000_000), "offered_rate")
    need(integer(q["min_hits"], 100_000), "min_hits below 100,000")
    need(q["build_environment"] is None or (isinstance(q["build_environment"], dict) and all(
        isinstance(k, str) and isinstance(v, str) for k, v in q["build_environment"].items())
        and q["build_environment"].get(OPT_LEVEL)), f"build_environment must pin {OPT_LEVEL}")
    need(tuple(q["phases"]) == PHASES, f"phases {PHASES}")
    for name, phase in q["phases"].items():
        need(isinstance(phase, dict) and set(phase) <= {"blocked"} and isinstance(phase.get("blocked", ""), str),
             f"phase {name}")
        need(name == "idle" or phase.get("blocked"),
             f"phase {name} is unblocked, but only the idle phase's activity interval, the whole run, is bound")
    protocol = q["protocol"]
    need(set(protocol) == PROTOCOL_KEYS, "protocol keys")
    need(all(protocol[key] is None or integer(protocol[key], 1, MAX_CELL_SAMPLES) for key in PROTOCOL_COUNTS),
         "protocol counts")
    need(all(protocol[key] is None or protocol[key] >= 2 for key in ("null_blocks", "blocks")),
         "protocol null_blocks and blocks are at least 2")
    need(protocol["max_non_hits"] is None or integer(protocol["max_non_hits"], 0, MAX_CELL_SAMPLES),
         "protocol max_non_hits")
    need(protocol["requests"] is None or protocol["requests"] <= MAX_REQUESTS, "protocol requests over the cell's bound")
    counts = [protocol[key] for key in ("null_blocks", "blocks", "repeats")]
    if None not in counts:
        runs = 4 * (counts[0] + counts[1]) * counts[2]
        need(runs <= MAX_RUNS, f"a cell of {runs} runs exceeds {MAX_RUNS}")
        need(protocol["requests"] is None or runs * protocol["requests"] <= MAX_CELL_SAMPLES,
             f"a cell's samples exceed {MAX_CELL_SAMPLES}")
        need(protocol["requests"] is None or 2 * counts[1] * counts[2] * protocol["requests"] >= q["min_hits"],
             "the candidate blocks cannot reach min_hits")
        need(None in (protocol["requests"], protocol["position_hits"])
             or protocol["position_hits"] <= counts[2] * protocol["requests"],
             "a block position cannot reach position_hits")
    coverage = protocol["band_coverage"]
    need(coverage is None or (positive(coverage) and coverage < 1), "protocol band_coverage")
    need(coverage is None or protocol["null_blocks"] is None
         or Fraction(str(coverage)) <= Fraction(protocol["null_blocks"], protocol["null_blocks"] + 1),
         "protocol null_blocks too few for band_coverage")
    need(isinstance(protocol["tolerance_ms"], dict) and set(protocol["tolerance_ms"]) == set(GATED)
         and all(v is None or positive(v) for v in protocol["tolerance_ms"].values()), "protocol tolerance_ms")
    serve = profile["roles"].get("owner", {}).get("env", {}).get("KESTRIKE_SERVE_SECONDS")
    need(isinstance(serve, str) and serve.isdigit() and int(serve) > SERVE_MARGIN_S,
         f"the owner role declares no KESTRIKE_SERVE_SECONDS above {SERVE_MARGIN_S}")
    deadline = next(case["deadline"] for spec in profile["roles"].values() for case in spec["cases"]
                    if case["id"] == q["cell"])
    need(int(serve) + SERVE_MARGIN_S <= deadline, "the owner's serving window and the close tail outlast the cell's deadline")
    need(None in (protocol["requests"], q["offered_rate"])
         or protocol["requests"] <= (int(serve) - SERVE_MARGIN_S) * q["offered_rate"],
         f"a run's requests at the offered rate leave less than {SERVE_MARGIN_S} s of the owner's serving window")
    ladder = q["pacing"].get("ladder_permille")
    need(q["pacing"].get("phase") == "publish" and isinstance(ladder, list) and ladder
         and all(integer(p, 1) for p in ladder) and ladder == sorted(set(ladder), reverse=True)
         and ladder[0] <= 100, "pacing ladder")
    recovery = q["recovery"]
    need(recovery.get("e_max") == 1 << 28 and positive(recovery.get("first_hit_s"))
         and recovery["first_hit_s"] <= 15 and positive(recovery.get("target_s"))
         and recovery["target_s"] <= recovery["first_hit_s"], "recovery bounds")
    need(recovery.get("n_max") is None or integer(recovery["n_max"], 1), "recovery n_max")
    need(isinstance(recovery.get("loss_causes"), list) and all(isinstance(c, str) and c for c in recovery["loss_causes"]),
         "recovery loss_causes")
    need(isinstance(recovery.get("blocked"), str) and recovery["blocked"],
         "recovery is unblocked, but no case prints a receipt-bound recovery record")
    preservation = q["preservation"]
    need(preservation.get("obligation") in obligation_ids, "preservation names no catalog obligation")
    need(isinstance(preservation.get("qualified"), bool) and isinstance(preservation.get("handoff"), str)
         and preservation["handoff"], "preservation")
    interface = q["interface"]
    need(set(interface) == {"roles", "readiness", "repeats", "run_identity", "restoration", "class", "witness"}
         and all(isinstance(interface[key], str) and interface[key]
                 for key in ("readiness", "repeats", "run_identity", "restoration", "class", "witness")),
         "interface keys")
    need(interface["roles"] == cases, "interface roles differ from the profile's roles and cases")
    need(all("{" + field + "}" in interface["run_identity"] for field in RUN_FIELDS), "run_identity fields")
    need(any(interface["witness"] in witness for spec in profile["roles"].values() for case in spec["cases"]
             if case["id"] == q["cell"] for witness in case["witnesses"]), "the cell declares no interface witness")

    open_items = [f"platform row {row} is unsupported" for row, disposition in profile["platforms"].items()
                  if disposition == "runs" and not document["platforms"][row]["supported"]]
    open_items += [f"workload {name} is blocked: {w['blocked']}" for name, w in workloads.items() if w.get("blocked")]
    open_items += [f"phase {name} is blocked: {p['blocked']}" for name, p in q["phases"].items() if p.get("blocked")]
    open_items += undeclared(q)
    if recovery["n_max"] is None:
        open_items.append("the recovery manifest declares no n_max")
    open_items.append(f"recovery is blocked: {recovery['blocked']}")
    if not preservation["qualified"]:
        open_items.append(f"preservation {preservation['obligation']} is unqualified: {preservation['handoff']}")
    return open_items


def schedule(seed, cell, protocol):
    """The run order of one cell: (block, slot, repeat, arm, null) with the A/A null blocks first. Each group of blocks
    takes ABBA and BAAB in counts that differ by at most one, in a seeded shuffle."""
    rng = random.Random(f"{seed}/{'/'.join(map(str, cell))}")
    templates = []
    for count in (protocol["null_blocks"], protocol["blocks"]):
        group = (["ABBA", "BAAB"] * count)[:count]
        rng.shuffle(group)
        templates += group
    return [(block, slot, repeat, arm, block < protocol["null_blocks"])
            for block, pattern in enumerate(templates) for slot, arm in enumerate(pattern)
            for repeat in range(protocol["repeats"])]


def quantile(values, q):
    """The nearest-rank q quantile of sorted `values`."""
    return values[max(0, math.ceil(q * len(values)) - 1)]


def latency_us(sample):
    return sample[END] - sample[INTENDED]


def lag_us(sample):
    """How late the generator first reached the request."""
    return sample[ATTEMPTED] - sample[INTENDED]


def wait_us(sample):
    """How long the request then waited for the client to admit it."""
    return sample[ADMITTED] - sample[ATTEMPTED]


def routed(run):
    """The samples of the run's routed owner."""
    return [s for s in run["samples"] if s[SOURCE] == run["source"]]


def hit_latencies(samples):
    """The unsorted latencies in microseconds of the hits among `samples`."""
    return [latency_us(s) for s in samples if s[STRATUM] == "hit"]


def ms(value):
    return None if value is None else float(Fraction(value) / 1000)


def arm_stats(runs, records):
    """One arm's pooled statistics over `runs` in milliseconds, and the arm's sorted hit latencies in microseconds."""
    serving = [s for run in runs for s in routed(run)]
    residual = [s for run in runs for s in run["samples"] if s[SOURCE] != run["source"]]
    served = [s for s in serving if s[STRATUM] == "hit"]
    hits = sorted(map(latency_us, served))
    residual_hits = sorted(hit_latencies(residual))
    lags, waits = sorted(map(lag_us, serving)), sorted(map(wait_us, serving))
    stats = {"hits": len(hits), "samples": len(serving),
             "strata": {name: sum(s[STRATUM] == name for s in serving) for name in STRATA},
             "residual": {name: sum(s[STRATUM] == name for s in residual) for name in STRATA},
             "residual_p99": ms(quantile(residual_hits, QUANTILES["p99"])) if residual_hits else None,
             "pooled_lag_p99": ms(quantile(lags, QUANTILES["p99"])) if lags else None,
             "lag_max": ms(lags[-1]) if lags else None,
             "pooled_wait_p99": ms(quantile(waits, QUANTILES["p99"])) if waits else None,
             "wait_max": ms(waits[-1]) if waits else None}
    stats.update({name: ms(quantile(hits, q)) if hits else None for name, q in QUANTILES.items()})
    sizes = {}
    for s in served:
        sizes.setdefault(str(records[s[RECORD]][0]), []).append(latency_us(s))
    for values in sizes.values():
        values.sort()
    stats["sizes"] = {size: {"hits": len(v), "p90": ms(quantile(v, QUANTILES["p90"])),
                             "p99": ms(quantile(v, QUANTILES["p99"]))} for size, v in sorted(sizes.items())}
    return stats, hits


def compare(runs, protocol):
    """Per gated quantile, the block contrasts, the A/A band and the comparison's verdict."""
    positions = {}
    for run in runs:
        positions.setdefault((run["null"], run["block"]), {}).setdefault((run["slot"], run["arm"]), []).append(run)
    contrasts = {name: {"null": [], "candidate": []} for name in GATED}
    missing = []
    for (null, block), slots in sorted(positions.items()):
        pooled = {key: sorted(v for r in group for v in hit_latencies(routed(r))) for key, group in slots.items()}
        if len(pooled) != 4 or any(len(values) < protocol["position_hits"] for values in pooled.values()):
            missing.append(block)
            continue
        for name in GATED:
            q = {key: quantile(values, QUANTILES[name]) for key, values in pooled.items()}
            d = Fraction(sum(v for (_, arm), v in q.items() if arm == "B")
                         - sum(v for (_, arm), v in q.items() if arm == "A"), 2)
            contrasts[name]["null" if null else "candidate"].append(d)
    out = {}
    for name in GATED:
        null, candidate = contrasts[name]["null"], contrasts[name]["candidate"]
        tolerance = microseconds(protocol["tolerance_ms"][name])
        band = max(map(abs, null), default=None)
        if (missing or len(null) != protocol["null_blocks"] or len(candidate) != protocol["blocks"]
                or band is None or band > tolerance):
            verdict = "inconclusive"
        elif all(d + band <= tolerance for d in candidate):
            verdict = "pass"
        elif all(d - band > tolerance for d in candidate):
            verdict = "fail"
        else:
            verdict = "inconclusive"
        out[name] = {"null": [ms(d) for d in null], "candidate": [ms(d) for d in candidate], "band": ms(band),
                     "coverage": float(Fraction(len(null), len(null) + 1)), "tolerance": ms(tolerance),
                     "missing_blocks": missing, "verdict": verdict}
    return out


def judge_cell(q, workload, runs):
    """One gated cell's verdict from its admitted runs, in the header's order: a generator-limited run makes it
    inconclusive, then a candidate arm past max_non_hits or a breached candidate ceiling fails it, then an arm short
    of min_hits or a main arm past max_non_hits makes it inconclusive, and otherwise the comparison decides. Every
    reason is kept."""
    spec, protocol = q["workloads"][workload], q["protocol"]
    reasons = []
    limited = [run["id"] for run in runs if max(map(lag_us, run["samples"])) > protocol["max_lag_us"]]
    if limited:
        reasons.append(f"generator-limited: a request's first attempt lags its intended send by more than "
                       f"{protocol['max_lag_us']} us in {limited}")
    arms, pooled = {}, {}
    for arm in "AB":
        arms[arm], pooled[arm] = arm_stats([r for r in runs if not r["null"] and r["arm"] == arm], spec["records"])
    short = [arm for arm in "AB" if arms[arm]["hits"] < q["min_hits"]]
    reasons += [f"arm {arm} pooled {arms[arm]['hits']} hits, under {q['min_hits']}" for arm in short]
    non_hits = {arm: arms[arm]["samples"] - arms[arm]["hits"] for arm in "AB"}
    excess = [arm for arm in "AB" if non_hits[arm] > protocol["max_non_hits"]]
    reasons += [f"arm {arm} pooled {non_hits[arm]} routed non-hit samples, over {protocol['max_non_hits']}"
                for arm in excess]
    breached = "B" in excess
    if "B" not in short:
        for name in GATED:
            limit, value = microseconds(spec[f"{name}_ms"]), quantile(pooled["B"], QUANTILES[name])
            if value >= limit:
                breached = True
                reasons.append(f"candidate {name} {ms(value)} ms is not below the absolute {ms(limit)} ms")
    comparison = compare(runs, protocol)
    for name, c in comparison.items():
        if c["verdict"] == "fail":
            reasons.append(f"{name} regresses past {c['tolerance']} ms in every block: {c['candidate']}")
        elif c["verdict"] == "inconclusive":
            reasons.append(f"{name} comparison is inconclusive: band {c['band']}, blocks {c['candidate']}, "
                           f"missing blocks {c['missing_blocks']}")
    if limited:
        verdict = "inconclusive"
    elif breached:
        verdict = "fail"
    elif short or excess:
        verdict = "inconclusive"
    else:
        verdict = worst([c["verdict"] for c in comparison.values()])
    return {"arms": arms, "comparison": comparison, "reasons": reasons, "verdict": verdict}


def worst(verdicts):
    """The combined verdict: handoff, then fail, then inconclusive; pass only when every verdict is pass."""
    for verdict in ("handoff", "fail", "inconclusive"):
        if verdict in verdicts:
            return verdict
    return "pass" if verdicts and all(v == "pass" for v in verdicts) else "inconclusive"


def pacing(ladder, verdicts):
    """Select the publish share: the first ladder share that passes, moving on only past a failed gate."""
    for permille in ladder:
        verdict = verdicts.get(permille, "inconclusive")
        if verdict == "pass":
            return {"verdict": "pass", "permille": permille}
        if verdict != "fail":
            return {"verdict": "inconclusive", "permille": None, "reason": f"no hit-gate verdict at {permille} permille"}
    return {"verdict": "handoff", "permille": None,
            "reason": f"the hit gate fails at every publish share down to {ladder[-1]} permille; cadence alone cannot "
                      "fix latency during a publish, so the publish path's architecture returns as the blocker"}


def safety_gaps(safety, campaign, bound=()):
    """Why a campaign's safety manifest does not guard every AWS create it records, or does not account for the
    host instances and volumes `bound`, the ones the admitted runs' receipts name: each is a create or a standing
    resource, and none is preexisting."""
    if not isinstance(safety, dict):
        return ["the campaign records no safety manifest"]
    gaps = []
    tag = safety.get("tag")
    if not (isinstance(campaign, str) and campaign and isinstance(tag, dict) and isinstance(tag.get("key"), str)
            and tag["key"] and tag.get("value") == campaign):
        gaps.append("the campaign's dedicated tag must carry the campaign id")
        tag = None
    if not isinstance(safety.get("owner"), str) or not safety["owner"]:
        gaps.append("no ownership guard")
    try:
        datetime.strptime(str(safety.get("deadline")), "%Y-%m-%dT%H:%M:%SZ")
        dated = True
    except ValueError:
        dated = False
    if not positive(safety.get("budget_usd")) or not dated:
        gaps.append("no budget or UTC deadline")
    if safety.get("teardown_on_failure") is not True:
        gaps.append("no teardown on failure")
    resources, teardown, preexisting = safety.get("resources"), safety.get("teardown"), safety.get("preexisting")
    standing = safety.get("standing")

    def ids(values):
        return all(isinstance(v, str) and v for v in values)

    if not (isinstance(resources, list) and all(isinstance(r, dict) for r in resources)
            and ids(r.get("id") for r in resources) and isinstance(teardown, list) and ids(teardown)
            and isinstance(preexisting, list) and ids(preexisting)
            and isinstance(standing, list) and ids(standing)):
        return gaps + ["no create, teardown, standing or preexisting-resource record of non-empty string ids"]
    created, bound = {r["id"] for r in resources}, set(bound)
    for resource in resources:
        tags = resource.get("tags") if isinstance(resource.get("tags"), dict) else {}
        if tag is None or tags.get(tag["key"]) != campaign or tags.get("owner") != safety.get("owner"):
            gaps.append(f"{resource['id']} lacks the campaign tag or the ownership guard")
    if touched := sorted((created | set(teardown) | set(standing) | bound) & set(preexisting)):
        gaps.append(f"the campaign touched preexisting resources {touched}")
    if both := sorted(set(standing) & (created | set(teardown))):
        gaps.append(f"standing resources {both} are also creates or torn down")
    if unlisted := sorted(bound - created - set(standing) - set(preexisting)):
        gaps.append(f"the admitted runs bind {unlisted}, which the safety manifest lists neither as creates nor as "
                    "standing")
    if set(teardown) != created:
        gaps.append(f"teardown {sorted(set(teardown))} is not every create {sorted(created)}")
    if safety.get("residue") != []:
        gaps.append(f"residue verification found {safety.get('residue')!r}")
    return gaps


def bound_samples(section, run, q, seed):
    """The samples a client receipt's cell case binds by digest, as (header, samples, file digest, lines digest), or
    raise Refusal. The run's `samples` path, when given, names the collected copy; the cell's own path is used
    otherwise."""
    entry = next((case for case in section.get("cases", []) if case.get("id") == q["cell"]), None)
    if entry is None:
        raise Refusal("the client receipt ran no hit-gate cell")
    lines = [e.get("detail", "") for e in entry.get("observed", []) if e.get("name") == "hit-gate"]
    if len(lines) != 1:
        raise Refusal(f"the cell printed {len(lines)} hit-gate sample lines")
    printed = SAMPLES.fullmatch(lines[0]) if isinstance(lines[0], str) else None
    if printed is None:
        raise Refusal(f"the cell's hit-gate line {lines[0]!r} is not `samples N hits N sha256 DIGEST`")
    count, _, digest = printed.groups()
    path = run.get("samples") or (entry.get("inputs") or {}).get("KESTRIKE_HIT_SAMPLES")
    data = read_file(path, "samples file")
    if hashlib.sha256(data).hexdigest() != digest:
        raise Refusal(f"samples file {path!r} is not the one the cell printed")
    requests = q["protocol"]["requests"]
    if int(count) != requests or data.count(b"\n") != requests + 1 or not data.endswith(b"\n"):
        raise Refusal(f"the samples file holds another count than the protocol's {requests} requests")
    head, _, body = data.partition(b"\n")
    header = parse(head, "the samples header")
    spec = q["workloads"][run["workload"]]
    if not (isinstance(header, dict) and set(header) == HEADER_KEYS):
        raise Refusal(f"the samples header keys are not {sorted(HEADER_KEYS)}")
    if not all(integer(header[key]) for key in ("rate", "requests", "seed", "slots", "source", "started_unix_ms")) \
            or not (header["previous"] == "none" or DIGEST.fullmatch(str(header["previous"]))):
        raise Refusal("a samples header field is malformed")
    if (header["workload"], header["records"], header["weights"]) != (run["workload"], spec["records"], spec["weights"]):
        raise Refusal(f"the samples ran another workload than {run['workload']}")
    if (header["rate"], header["requests"], header["seed"]) != (q["offered_rate"], requests, seed):
        raise Refusal("the samples ran another rate, request count or seed than the protocol declares")
    samples = [parse(line, "a sample") for line in body.split(b"\n")[:-1]]
    for i, s in enumerate(samples):
        if not (isinstance(s, list) and len(s) == 7
                and all(integer(s[k]) for k in (INTENDED, ATTEMPTED, ADMITTED, END, SOURCE))
                and integer(s[RECORD], 0, len(spec["records"]) - 1) and s[STRATUM] in STRATA
                and s[INTENDED] <= s[ATTEMPTED] <= s[ADMITTED] <= s[END]):
            raise Refusal(f"sample {i} is not [intended_us, attempted_us, admitted_us, end_us, record, stratum, source]")
        if s[INTENDED] - samples[0][INTENDED] != i * 1_000_000 // header["rate"]:
            raise Refusal(f"sample {i}'s intended send is off the fixed-interval schedule")
        if s[RECORD] != draw(seed, i, spec["weights"]):
            raise Refusal(f"sample {i}'s record is not the seeded draw")
    return header, samples, digest, hashlib.sha256(body).hexdigest()


def admit(lane, document, digest, run, revision, seed):
    """One run's samples once its receipts credit under the current manifest and bind them, or raise Refusal."""
    q = document["qualification"]
    receipts = [parse(read_file(path, "receipt"), f"receipt {path}") for path in run["receipts"]]
    credited, reasons = lane.judge_profile(document["platforms"], q["profile"], document["profiles"][q["profile"]],
                                           receipts, digest, revision)
    if not credited:
        raise Refusal(f"run {run['id']} is uncredited: {reasons[0]}")
    sections = {r["hardware"]["role"]: r["hardware"] for r in receipts}
    if any(section.get("episode") != run["id"] for section in sections.values()):
        raise Refusal(f"run {run['id']} ran in another episode")
    client = next(role for role, ids in q["interface"]["roles"].items() if q["cell"] in ids)
    header, samples, file_digest, lines_digest = bound_samples(sections[client], run, q, seed)
    if sections[client].get("build_environment") != q["build_environment"]:
        raise Refusal(f"run {run['id']} built under another environment than the qualification declares")
    identity, peers = {"toolchain": sections[client].get("toolchain")}, {}
    for role, section in sections.items():
        instance = (section.get("host") or {}).get("instance")
        if not (isinstance(instance, str) and instance):
            raise Refusal(f"run {run['id']} role {role} records no host instance")
        mappings = [case.get("mappings") or {} for case in section.get("cases", [])]
        volumes = [m.get("volume") for m in mappings]
        if not all(v is None or (isinstance(v, str) and v) for v in volumes):
            raise Refusal(f"run {run['id']} role {role} records a malformed volume {volumes}")
        for case in section.get("cases", []):
            before = (case.get("mappings") or {}).get("sha256")
            if not (isinstance(before, str) and DIGEST.fullmatch(before) and case.get("mappings_after") == before):
                raise Refusal(f"run {run['id']} role {role}'s mappings file has another digest at its case's end than "
                              "before it, or none")
        addresses = [m.get("address") for m in mappings]
        if not (addresses and all(isinstance(a, str) and a and a == addresses[0] for a in addresses)):
            raise Refusal(f"run {run['id']} role {role} records no ENI address")
        identity[role] = {"instance": instance, "functions": [m.get("functions") for m in mappings], "volumes": volumes,
                          "address": addresses[0]}
        peers[role] = [(case.get("inputs") or {}).get("KESTRIKE_PEER") for case in section.get("cases", [])]
    for role in sections.keys() - {client}:
        if not (identity[role]["volumes"] and all(identity[role]["volumes"])):
            raise Refusal(f"run {run['id']} role {role} records no bound volume")
    for field, what in (("instance", "host"), ("address", "ENI address")):
        values = [identity[role][field] for role in sections]
        if shared := sorted(value for value in set(values) if values.count(value) > 1):
            raise Refusal(f"run {run['id']}'s roles share the {what} {shared[0]!r}; the gate measures a remote client")
    for role in sections.keys() - {client}:
        # The client cell parses its peer as given; the owner cell splits its list on commas and trims each entry.
        if strays := [peer for peer in peers[client] if peer != identity[role]["address"]]:
            raise Refusal(f"run {run['id']}'s client routes to {strays[0]!r}, not role {role}'s address "
                          f"{identity[role]['address']!r}")
        for peer in peers[role]:
            listed = [entry.strip() for entry in peer.split(",")] if isinstance(peer, str) else None
            if listed != [identity[client]["address"]]:
                raise Refusal(f"run {run['id']} role {role} lists peers {listed}, not the one client "
                              f"{identity[client]['address']!r}")
    return {"samples": samples, "source": header["source"], "previous": header["previous"], "file": file_digest,
            "lines": lines_digest, "plan": (header["slots"], header["source"]), "identity": identity,
            "dependencies": sections[client].get("dependencies")}


def coordinates(run):
    """Whether a campaign run names its cell and schedule position with the declared types."""
    return (isinstance(run, dict) and isinstance(run.get("workload"), str) and isinstance(run.get("phase"), str)
            and all(integer(run.get(k)) for k in ("permille", "block", "slot", "repeat"))
            and isinstance(run.get("receipts"), list) and all(isinstance(p, str) for p in run["receipts"])
            and isinstance(run.get("samples", ""), str))


def judge(document, digest, obligation_ids, campaign, lane, campaign_sha256=None):
    """The gate receipt for `campaign` under the manifest `document` whose bytes have SHA-256 `digest`."""
    if not (isinstance(campaign, dict) and isinstance(campaign.get("campaign"), str) and campaign["campaign"]
            and isinstance(campaign.get("runs", []), list)):
        raise Refusal("the campaign is not an object with a non-empty campaign id and a runs list")
    q = document["qualification"]
    open_items = check(document, obligation_ids)
    main, candidate = campaign.get("main"), campaign.get("candidate")
    seed = campaign_seed(digest, main, candidate) if revisions(main, candidate) else None
    receipt = {"envelope": ENVELOPE, "manifest_sha256": digest, "campaign_sha256": campaign_sha256,
               "judge_sha256": hashlib.sha256(read_file(__file__, "judge")).hexdigest(),
               "campaign": campaign["campaign"], "main": main, "candidate": candidate, "seed": seed,
               "open": open_items, "cells": {}, "reasons": []}
    verdicts = ["inconclusive"] if open_items else []
    blocker = None
    if seed is None:
        blocker = "no distinct main and candidate revisions"
    elif campaign["campaign"] != campaign_id(seed):
        blocker = f"the campaign id is not {campaign_id(seed)}, the one campaign of this manifest and revision pair"
    elif undeclared(q):
        blocker = "no predeclared protocol"
    if blocker:
        receipt["reasons"].append(blocker)
        verdicts.append("inconclusive")
    cells, seen = {}, set()
    for index, run in enumerate(campaign.get("runs", [])):
        if not coordinates(run):
            raise Refusal(f"campaign run {index} has malformed coordinates")
        run["id"] = q["interface"]["run_identity"].format(campaign=campaign["campaign"],
                                                          **{k: run[k] for k in RUN_FIELDS[1:]})
        if run["id"] in seen:
            receipt["reasons"].append(f"run {run['id']} repeats an identity; a stopped repeat is missing, never retried")
            verdicts.append("inconclusive")
        seen.add(run["id"])
        cells.setdefault((run["workload"], run["phase"], run["permille"]), []).append(run)
    declared, publish = declared_cells(q), q["pacing"]["phase"]
    for cell in [*declared, *(cell for cell in cells if cell not in declared)]:
        workload, phase, permille = cell
        runs = cells.get(cell)
        if cell not in declared:
            result = {"verdict": "inconclusive", "reasons": ["the cell is outside the manifest"]}
        elif blocked := [r for r in (q["workloads"][workload].get("blocked"), q["phases"][phase].get("blocked")) if r]:
            result = {"verdict": "inconclusive", "reasons": blocked}
        elif not runs:
            result = {"verdict": "inconclusive", "reasons": ["no runs of the declared cell"]}
        elif blocker:
            result = {"verdict": "inconclusive", "reasons": [blocker]}
        else:
            result = judge_runs(lane, document, digest, cell, runs, main, candidate)
        receipt["cells"][f"{workload}/{phase}/{permille}"] = result
        if phase != publish or cell not in declared:
            verdicts.append(result["verdict"])
    identities = {name: json.dumps(result["identity"], sort_keys=True) for name, result in receipt["cells"].items()
                  if "identity" in result}
    if len(set(identities.values())) > 1:
        first = next(iter(identities))
        receipt["reasons"].append(f"cells {[name for name in identities if identities[name] != identities[first]]} "
                                  f"ran on another host, volume, PCI functions, ENI address, toolchain or dependency "
                                  f"set than {first}")
        verdicts.append("inconclusive")
    bound = {i for result in receipt["cells"].values() for i in result.get("bound", ())}
    if gaps := safety_gaps(campaign.get("safety"), campaign["campaign"], bound):
        receipt["reasons"] += gaps
        verdicts.append("inconclusive")
    ladder = q["pacing"]["ladder_permille"]
    shares = {permille: worst([receipt["cells"][f"{w}/{publish}/{permille}"]["verdict"] for w in q["workloads"]])
              for permille in ladder}
    receipt["pacing"] = pacing(ladder, shares)
    verdicts.append(receipt["pacing"]["verdict"])
    receipt["recovery"] = {"verdict": "inconclusive", "reasons": [q["recovery"]["blocked"]]}
    verdicts.append("inconclusive")
    if not q["preservation"]["qualified"]:
        receipt["handoff"] = {"obligation": q["preservation"]["obligation"], "reason": q["preservation"]["handoff"]}
        verdicts.append("handoff")
    receipt["verdict"] = worst(verdicts)
    return receipt


def judge_runs(lane, document, digest, cell, runs, main, candidate):
    """Admit one cell's runs against its schedule, then judge the cell. Once the runs are the schedule, the result's
    `bound` holds the host instances and volumes of every run `admit` returned, whether or not the cell is refused
    afterwards. Admission stops at the first refusal, so a run `admit` refuses and every run after the first refusal
    add nothing."""
    q, seed = document["qualification"], campaign_seed(digest, main, candidate)
    expected = schedule(seed, cell, q["protocol"])
    by_position = {(r["block"], r["slot"], r["repeat"]): r for r in runs}
    if set(by_position) != {e[:3] for e in expected} or len(runs) != len(expected):
        return {"verdict": "inconclusive", "reasons": ["the runs are not exactly the cell's schedule"]}
    admitted, previous, bound = [], "none", set()
    try:
        for block, slot, repeat, arm, null in expected:
            run = by_position[(block, slot, repeat)]
            revision = main if null or arm == "A" else candidate
            entry = admit(lane, document, digest, run, revision, seed)
            for role in q["interface"]["roles"]:
                bound.update(i for i in (entry["identity"][role]["instance"], *entry["identity"][role]["volumes"]) if i)
            if entry["previous"] != previous:
                raise Refusal(f"run {run['id']} names {entry['previous']} as its predecessor, not {previous}: "
                              "the runs did not run in schedule order, A/A null first")
            previous = entry["file"]
            admitted.append({**entry, "id": run["id"], "block": block, "slot": slot, "arm": arm, "null": null,
                             "revision": revision})
        evidence = [{"id": run["id"], "samples_sha256": run["file"]} for run in admitted]
        if len({run["lines"] for run in admitted}) != len(admitted):
            raise Refusal("two runs hold the same sample lines")
        if len({json.dumps(run["identity"], sort_keys=True) for run in admitted}) != 1:
            raise Refusal("the runs differ in host, volume, PCI functions, ENI address or toolchain")
        built = {}
        for name, revision in (("main", main), ("candidate", candidate)):
            sets = {json.dumps(run["dependencies"]) for run in admitted if run["revision"] == revision}
            if len(sets) != 1:
                raise Refusal(f"the runs of revision {revision} built different dependencies")
            built[name] = hashlib.sha256(sets.pop().encode()).hexdigest()
        if len({run["plan"] for run in admitted}) != 1:
            raise Refusal("the runs differ in client slots or source")
        result = judge_cell(q, cell[0], admitted)
    except FAULTS as error:
        return {"verdict": "inconclusive", "reasons": [f"{type(error).__name__}: {error}"], "bound": sorted(bound)}
    return {**result, "runs": evidence, "identity": {**admitted[0]["identity"], "dependencies": built},
            "bound": sorted(bound)}


def read_document(path, lane):
    """The manifest at `path`, validated whole by the lane, and the SHA-256 of its bytes."""
    data = read_file(path, "manifest")
    document = parse(data, f"manifest {path}")
    try:
        lane.check_manifest(document)
    except lane.Stop as error:
        raise Refusal(str(error)) from error
    return document, hashlib.sha256(data).hexdigest()


def obligation_ids(path):
    return {record["id"] for record in parse(read_file(path, "catalog"), f"catalog {path}")["records"]}


def write_receipt(path, text):
    """Replaces the regular file at `path`, or creates it, with `text` through a new sibling file synced before the
    rename. An existing entry that is not a regular file, a link included, is refused and left as it was. The receipt
    takes the mode an ordinary create gets under the process umask."""
    target = Path(path)
    try:
        if not stat.S_ISREG(os.lstat(target).st_mode):
            raise Refusal(f"--output {path!r} names an existing entry that is not a regular file")
    except FileNotFoundError:
        pass
    descriptor, temporary = tempfile.mkstemp(dir=target.parent, prefix=f".{target.name}.")
    try:
        mask = os.umask(0)
        os.umask(mask)
        os.fchmod(descriptor, 0o666 & ~mask)
        with os.fdopen(descriptor, "w") as file:
            file.write(text)
            file.flush()
            os.fsync(file.fileno())
        os.replace(temporary, target)
    except BaseException:
        os.unlink(temporary)
        raise


def main(argv=None):
    parser = argparse.ArgumentParser(description="Judge the open-loop hit-latency qualification.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "schedule", "judge"):
        command = commands.add_parser(name)
        command.add_argument("--manifest", default=str(MANIFEST))
        command.add_argument("--obligations", default=str(OBLIGATIONS))
    for flag in ("--main", "--candidate", "--workload", "--phase"):
        commands.choices["schedule"].add_argument(flag, required=True)
    commands.choices["schedule"].add_argument("--permille", type=int, default=0)
    commands.choices["judge"].add_argument("--campaign", required=True)
    commands.choices["judge"].add_argument("--output")
    args = parser.parse_args(argv)
    try:
        lane = lane_module()
        document, digest = read_document(args.manifest, lane)
        ids = obligation_ids(args.obligations)
        if args.command == "check":
            print(json.dumps({"open": check(document, ids)}, indent=1))
            return 0
        if args.command == "schedule":
            q = document["qualification"]
            check(document, ids)
            cell = (args.workload, args.phase, args.permille)
            if cell not in declared_cells(q):
                raise Refusal(f"the qualification declares no cell {cell}")
            if not revisions(args.main, args.candidate):
                raise Refusal("the schedule needs distinct main and candidate revisions")
            if None in (q["protocol"]["null_blocks"], q["protocol"]["blocks"], q["protocol"]["repeats"]):
                raise Refusal("the protocol declares no block or repeat counts")
            seed = campaign_seed(digest, args.main, args.candidate)
            print(json.dumps({"campaign": campaign_id(seed), "seed": seed}))
            for block, slot, repeat, arm, null in schedule(seed, cell, q["protocol"]):
                print(json.dumps({"block": block, "slot": slot, "repeat": repeat, "arm": arm, "null": null}))
            return 0
        data = read_file(args.campaign, "campaign")
        receipt = judge(document, digest, ids, parse(data, f"campaign {args.campaign}"), lane,
                        hashlib.sha256(data).hexdigest())
        text = json.dumps(receipt, indent=1, sort_keys=True) + "\n"
        if args.output:
            write_receipt(args.output, text)
        else:
            sys.stdout.write(text)
    except FAULTS as error:
        print(f"hit-gate: refused: {error}", file=sys.stderr)
        return 2
    return 0 if receipt["verdict"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
