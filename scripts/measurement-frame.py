#!/usr/bin/env python3
"""Check the warm-recovery measurement frame and its policy, and report a campaign against them.

Usage:
  measurement-frame.py check [--records DIR] [--manifest F] [--obligations F] [--base REV]
  measurement-frame.py floors --requests N [--records DIR] [--manifest F] [--obligations F]
  measurement-frame.py report --campaign F [--records DIR] [--manifest F] [--obligations F] [--output F]
  measurement-frame.py ticket --campaign F --receipt F --gate-head SHA [--records DIR] [--manifest F] [--obligations F]

The records are four JSON files of `verification/measurement/`: `frame.json`, `statistics.json`, `policy.json` and
`revisions.json`; the sizing worksheet `sizing.json` beside them pins the frame and statistics versions it reads. The
frame fixes the parent specifications by the SHA-256 of their issue bodies, the evidence kinds,
the classes, the envelope, the conditional header with the evidence kinds each key applies to, the population and
arrival definitions, every measured field with its unit, direction, evidence kinds and one source per evidence kind, the
separate recovery stage terms, the C2 calibration terms, the comparison definition (its contrasts, block sets, required
report rows and the classes a row is limited to, column labels, verdict names, requalification list, frozen Step 8 rules
and the #141 sizing hand-off), the floor rule, the controls with their predeclared outcomes, the run discipline, the
retired axes, the property map and the digest of the hit gate's `qualification` object in
`scripts/hardware-profiles.json`. The statistics version fixes the units, contrasts, strata, horizons, bounds, alpha,
power, the block contrast, order bound, pilot floor, bound verdict and drift rules and the open statistical inputs. The
policy names the frame and statistics versions by SHA-256 and holds the family, the per-outcome unit, normalization,
boundary and smallest effect (the smallest effect and the budget rows are in the row's unit), H and F, the readiness
bands and windows, the request deadline, the request tail's edge thresholds, the cold class's zero retained hits, one
budget row per class and family member, the calibration's foreground reservation and the campaign authority.
`revisions.json` logs every version of each record with the SHA-256 of its bytes, in order from version 1.

Every command first validates the manifest with the hit gate's own `check`. This script fixes each record's content
apart from its owner inputs: `FIXED` holds the canonical SHA-256 of each record with its version, pins, envelope
values other than E_max, population manifest, parent body digests, field and calibration sources, qualification
digest, statistical inputs, budgets, readiness inputs, class list, F's percentile and budget, the declared edge
thresholds, the foreground reservation and the campaign authority nulled,
so a relogged record that changes a definition, unit, direction, rule or label is refused until this script changes
with it. The named checks state the same rules with their own messages: the classes, envelope and header keys, the
family, the stages, the quantiles and the 4,000-request floor example, the floors, the controls, the retired axes,
the run identity, R6's ceilings (p90 below 1 ms, p99 below 3 ms, a large-object p99 below 5 ms), the samples readers
and the bound and edge-interval rules `level` and `wilson` implement and the censoring rule `per_request` applies.

`check` validates the four records against the manifest's qualification and prints the open items: every input the
records leave null and each provisional choice, each a reason no quantitative verdict can pass. Fields whose only source
is a ticket or handoff are not listed; whether their producers landed is the owners' to show. It refuses, with exit 2, a
record whose bytes differ from its logged SHA-256 for its version, so an edit that changes a value, an `accepted` status
for the provisional alpha or power included, is a new logged version. With `--base REV` it also refuses a log whose
entries do not extend the log committed at REV unchanged; a REV that names no commit, or whose log is unreadable or
lacks a kind, is refused. A field source must resolve to a declaration in the repository. `crates/source-anchors` parses
a Rust file and lists its items, named fields and enum variants, each as in a build without `test` or gated out of every
such build by an attribute of its own or of an enclosing item: a `cfg` whose predicate is false without `test`, a
`cfg_attr` that applies one in every such build, or a test attribute. The symbol is one of the listed declarations, and
a producer's is in production and outside test files; text in a comment, a literal, a macro or a function body is no
declaration, and a file that does not parse is refused. A Python source declares the symbol as a `def` or a `class` at
module level or in a class body of its syntax tree, and a source in any other language is refused. A producer's Rust
file is also a module in such a build: the `mod name;` line that declares it in the file above, and each ancestor's, is
ungated, up to a crate root where Cargo's default layout puts one: `src/lib.rs` or `src/main.rs` beside a `Cargo.toml`,
a file in `src/bin` or the `main.rs` of a directory there, or a file with no file above it whose module directory holds
`Cargo.toml`. A file that no file above it declares, and that is no such root, is refused, a target that `Cargo.toml`
places elsewhere included. Outside this check's sight: a module file declared with a `#[path]` attribute or from inside
an inline module (each refused as undeclared), a declaration only a macro expansion produces, and a `cfg` predicate that
no build satisfies for a reason other than `test`. Resolving a Rust source runs `cargo run --package source-anchors`, so
every command needs the Rust toolchain.

`floors` prints the floor kind of each reported quantile for a stratum of N requests: with e = N * (1 - q)
expected exceedances, e >= 10 reports the quantile, 1 <= e < 10 reports a Wilson rate marked `edge`, and e < 1 is
`beyond the sample`. It also prints the family size m, the per-tail level familywise_alpha / (2 m) and its normal
quantile z, at which every Wilson interval is computed. The Wilson interval is descriptive: its nominal coverage
assumes independent requests, and an open-loop stall delays every request scheduled during it.

`report` reads a campaign file the campaign driver writes and writes a receipt whose `verdict` is `fail`,
`inconclusive`, `handoff`, `exploratory` or `retained`, exiting 1. It exits 2 and writes nothing for a refused input:
malformed records, manifest or campaign, or a campaign naming a frame, statistics or policy version the log does not
hold. Every supplied campaign field is shape-checked, and the host and cell lists bounded, before the policy decides
how the campaign is read. The campaign holds:
  policy, frame, statistics
             {version, sha256} of each record the runs were registered under. A campaign naming no policy reads
             `exploratory` and counts for nothing. One naming an earlier logged policy reads `retained` once its
             revision's commit holds the three records it names and its campaign id is the one they derive: it is
             registered under that version, this policy never re-judges it, and the receipt establishes no verdict for
             it. Whether it was judged, and with what verdict, is for a receipt issued under its own version to show.
             Such a campaign whose frame or statistics pin is not the one its held policy names is refused.
  revision   {commit, patch_sha256}: the 40-hex commit and the SHA-256 of the out-of-tree patch, which for an unpatched
             build is the SHA-256 of no bytes. The commit must hold the three records the campaign names at
             `verification/measurement/`; it is the hit gate's candidate, whose hash seeds every run's schedule and
             workload, so the records precede the runs.
  campaign   `measure-` and the first 16 hex digits of SHA-256 over the digests of the frame, statistics and policy the
             campaign names, the commit and the patch digest, and a revision contrast's baseline commit and patch
             digest, joined by `/`.
  header     the frame's conditional header, every key present. A value off its type or the frame's envelope, or a
             rate off the qualification's offered rate, makes the campaign inconclusive; a null value makes
             inconclusive each cell whose evidence kind the key applies to.
  hosts      [{id, instance, cpu_family, physical_cores, jobs, clock, reference, outcome: {path, sha256}}]: each
             host's lane instance and reference-workload outcome file. A host counts only when its CPU family is the
             header's (when the header declares one), that file's SHA-256 equals the one admitted reference host's
             of its CPU family and its jobs do not exceed its physical cores; `clock` is `trusted` or `untrusted`,
             and an untrusted host's cells read `degraded`. The core counts, the clock and the outcome file are the
             driver's declarations.
  controls   {name: {observed, evidence: {path, sha256}}} for every frame control. A missing control, an evidence
             file off its digest or an observed outcome other than the declared one names its fault; a declared
             outcome still reads inconclusive, since no judge on this revision derives it from the evidence. The
             `aa` and `calibration-drift` controls are computed instead, from the null blocks' and the calibration's
             declared values, and read unreached without a contrast; their campaign entries are not read. A computed
             outcome that matches its declared one still withholds ranking and PASS, since those values are the
             driver's declarations.
  hit_gate   optional {path, sha256}: the hit gate's campaign file, judged by `scripts/hit-gate.py`'s own `judge` under
             the manifest. Its verdict decides nothing unless its candidate is the campaign's commit, the campaign is
             unpatched, every instance its cells ran on is an admitted host's, the client's with a trusted clock, and
             the campaign id, registration, header and controls stand; otherwise it reads inconclusive, or `handoff`
             when the gate hands off preservation. A revision contrast's bound verdict reads the gate's own verdict
             for H, since its validity faults already withhold a decision and an underived control withholds PASS
             alone. Its samples bind cells only when its candidate and the registration stand, the campaign is
             unpatched and every role of their gate cell ran on an admitted host: the gate's lane credits a run only
             from an unmodified tree of its revision.
  cells      [{class, field, stratum, evidence, host, samples?: {path, sha256}, header?}]: `header` overrides campaign
             header keys that apply to the cell's evidence kind. A cell whose effective header holds a value off its
             type or the frame's envelope, a rate off the qualification's offered rate, a CPU family other than its
             host's, or a platform row that is unsupported or outside the manifest names that reason. A cell whose
             evidence kind its field does not admit reads inconclusive with that reason. Only H and the request tail
             have a reader, the hit gate's samples; every other cell reads inconclusive. A samples cell reads samples
             the hit gate admitted for a non-null candidate-arm run of a decided gate cell, whose phase is the cell's
             stratum and whose client instance is the cell host's; only such samples are read, once per digest, whatever
             the platform row, whose reason keeps the cell inconclusive beside its summary. Its summaries follow the
             floor rule: H over the routed owner's samples by size stratum with its outcome counts and residual-owner
             counts, and the request tail over every original request, one tail per outcome with routed and residual
             counts. No hit-gate run binds a recovery class, platform row or CPU identity, so every samples cell also
             reads inconclusive; its summaries describe and score nothing.
  contrast   optional `class` or `revision`. A class contrast runs the volume-loss control as arm A and the block's
             class as arm B on one build under the block's posture and reports descriptive bounds; a revision contrast
             runs `baseline`'s build as arm A and the campaign's commit as arm B on the block's class and posture and
             takes the bound verdict. Only a campaign with a contrast holds blocks, a calibration or a safety
             manifest.
  baseline   {commit, patch_sha256} of a revision contrast's arm A, and only of one. A baseline equal to the
             campaign's revision runs one build as both arms: it is a comparison reason, so the bound verdict reads
             INCONCLUSIVE.
  target     a revision contrast's optional {receipt: {path, sha256}, cell}: the measurement-frame receipt and the
             cell key of the binding term the optimization attacks; the receipt must hold that cell, whose IDENTITY
             values name the target's class and field.
  safety     the hit gate's AWS safety manifest (`safety_gaps`), whose standing or created resources cover every
             campaign host's instance and every volume the blocks and the calibration name, plus `host_hours`; its
             budget and host hours must lie within the policy's campaign authority, and a null authority approves
             nothing. The volumes are the driver's declarations.
  calibration
             {start, end}: each {host, volumes, evidence: {path, sha256}, values: {term: {value, uncertainty}}} for
             every frame C2 term, a positive finite value with a non-negative finite uncertainty, the half-width in
             the term's unit of the interval the driver declares to hold it. Both phases run on one admitted host
             with a trusted clock that ran a usable block, measure the same volumes and cite two evidence files;
             evidence a scored position also names is no measurement apart from scored elapsed time. The drift
             control applies the statistics' drift rule to each term. The values and uncertainties are the driver's
             declarations: only the evidence digests are checked.
  blocks     [{set, class, posture, order, hosts, volumes, positions: [{arm, run, evidence: {path, sha256},
             outcomes}]}]: `set` is `null`, `pilot` or `held-out`, `class` a class, `posture` one of the hit gate's
             phases, `order` ABBA or BAAB. A block's order is slots 4i to 4i + 3 of
             `gate.schedule(campaign id, (set, class, posture), {null_blocks: 0, blocks: n, repeats: 1})`, i its index
             and n the count of the blocks the campaign lists for its set, class and posture. A block whose positions
             are not one run per slot of that order, whose hosts are not all admitted, that carries a run id or an
             evidence file another position also names, whose evidence files are off their digests, that names no
             class, or that runs the cold class outside the null set of a class contrast is missing. `outcomes` maps
             each family member outside the hit gate's readers, except the warm-only retained-hit recovery and held
             capacity wherever an arm runs the cold class, to a positive value in its policy row's unit,
             `{"censored": v}` when the value is worse than v, or for a member with levels one such value per level
             keyed by the level's decimal text; any other key is a campaign reason. A block on an
             untrusted-clock host holds no value read off a clock. The arms, the placement and the values are the
             driver's declarations: no judge on this revision derives them from the evidence files, whose digests
             alone are checked, so no bound verdict passes.
Paths are opened as given, so a relative path resolves against the working directory.

For a contrast, each class and posture stratum and each block member (and level) of `member_keys` takes a paired log
contrast per complete block and a distribution-free order-statistic bound on the median contrast at familywise_alpha /
(2 m L S) per tail, S the statistics' declared comparison strata, over the null blocks and over the held-out blocks;
while none are declared, or the campaign lists others, no bound decides. The A/A control reads null when every entry
with held-out contrasts holds an A/A bound within plus or minus its tolerance, every A/A bound is bounded, which takes
at least the fewest null blocks whose order rank at the per-tail level is positive, and every one covers zero; one
bound excluding zero reads not-null. The held-out blocks must number the statistics' fixed horizon; the pilot blocks set
the tolerance from the smallest effect and their arm A median in the member's direction, and the floor, the fewest
blocks at which the order bound passes with the power's probability under normal contrasts of the pilot's standard
deviation; the horizon must reach the floor and that planning power itself. A stratum whose blocks run on two host
sets, a null or pilot block missing the member's value, a hardware header key left null, an unsupported platform row
and an open F or readiness input each keep the bounds they reach from deciding; null owner inputs leave a bound
unscored.

The receipt holds the envelope, the frame, statistics and policy pins the campaign names (null when it names none),
`records` with the committed pins, `manifest_sha256` (the manifest file's bytes), `campaign_sha256` (the campaign file's
bytes), `judge_sha256` (this script's bytes, which `ticket` compares as part of the whole receipt; it covers neither
`hit-gate.py`, `hardware-lane.py` nor `crates/source-anchors`, whose rules decide whether `check` admits the records
before any receipt is written), the campaign id, the open items, this script's reasons and the verdict. A receipt read
under the current policy also holds the hosts' admissions, `hit_gate`, the cells and the per-class outcomes. `hit_gate`
holds its verdict and this script's reasons; once the gate judged its campaign file it also holds `gate`, the gate
receipt's provenance with the gate's own `judge_sha256` (the bytes of `hit-gate.py`), open items, reasons and per-cell
verdicts and reasons without its arm statistics, `receipt_sha256`, the canonical SHA-256 of the whole gate receipt, and
the preservation handoff when there is one. Each cell's key is the JSON array text of its IDENTITY values: the derived
campaign id, the commit, the patch digest, its host's CPU family or `undeclared`, its class, field, stratum, evidence
kind and host, and its samples digest or null, and its effective N_max for hardware and simulation evidence or null; a
cell repeating a key is dropped with a campaign reason. The receipt also holds `columns`, one per evidence kind with its
conditional header, its label (`Inconclusive: platform row unsupported` on the hardware column unless the header's
platform row and every hardware cell's effective row are supported manifest rows, and on the store column the condition
on #123's ST1 to ST8, always) and one row per class and required field/stratum, limited to the row's classes, `unrun`
until a cell fills it; a cell outside the required rows fills none; `ranking`, withheld while any control has not
reached its declared outcome, which every campaign on this revision shows; `sizing`, the store-request and
checkpoint-unit cells handed to #141; and, for a contrast, `comparison` with the measured revision and baseline, its
calibration, block counts, bounds by class and posture, reasons and, for a revision contrast, `ticket`: the cited
target, the bound verdict, whether it merges as a performance change (only PASS), each member's verdict, the
requalification and frozen rules and its reasons. UNACCEPTABLE_REGRESSION needs a standing campaign (its registration
and id, its header and platform row, every control except one whose declared outcome no judge derives, the AWS safety
manifest and authority, a baseline other than its own revision, the blocks, the calibration and the target), every
stratum holding every member key, and one regressing member. PASS needs the same, every control derived, block values
derived from their evidence, accepted alpha and power, every member passing, H by the hit gate's verdict between the
unpatched baseline and the candidate, a request-tail bound no judge on this revision draws, and the target's member
bounded below zero; on this revision it is unreachable. Anything else is INCONCLUSIVE. `exploratory` and `retained`
receipts hold no hosts, gate, cells, outcomes or comparison.

Every family member has one verdict per class (`outcome`): H's reads inconclusive, since the hit gate judges no
recovery class; F's reads `unscored` while `f.budget_ms` is null; the cold class's retained-hit recovery and held
capacity read inconclusive, since it retains no hit and restores no capacity; any other member reads `unscored` while
its budget row is null and `inconclusive` once it holds a budget, since this statistics version declares no budget
bound. The receipt's verdict is the worst of the open items, this script's reasons, the host admissions, the gate's
verdict, the cells, the outcomes and the comparison (`fail` for UNACCEPTABLE_REGRESSION), so on this revision it is
never a pass.

`ticket` reports the campaign again under the committed records and manifest, refuses a receipt file whose bytes are not
the receipt it derives, which depends on this script's bytes, the hit gate's when it judges, the manifest, the records,
the current policy and every evidence file, and prints the derived result-to-ticket block that ends with `Gate head:
SHA`: the cited campaign artifact and cell, the measured candidate and baseline, the bound verdict, whether it merges as
a performance change (only PASS does), each member's bound against its tolerance (`unscored` without one), the reasons,
the requalification, the frozen Step 8 rules and the SHA-256 of the receipt file, the retained hashed copy. It exits 0
for PASS and 1 for any other verdict. It exits 2 for a refused campaign, a receipt it does not derive, a receipt without
a bound verdict, a head that is no 40-hex commit or not the unpatched candidate the campaign measured, and a value
holding a character that is not printable, which could add a line to the block."""

import argparse
import ast
import copy
import functools
import hashlib
import importlib.util
import json
import math
import re
import subprocess
import sys
from fractions import Fraction
from pathlib import Path
from statistics import NormalDist, median, stdev

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RECORDS = ROOT / "verification/measurement"
RECORDS_PATH = "verification/measurement"
KINDS = ("frame", "statistics", "policy")
ENVELOPE = {"version": 1, "section": "measurement-frame"}
EVIDENCE = ("model", "simulation", "hardware", "store")
CLASSES = {"warm-takeover": "treatment", "same-host-restart": "reported apart", "volume-loss-control": "control"}
COLD = "volume-loss-control"
PARENTS = {"specification": "#91", "ticket": "#92", "contract": "#120", "comparison": "#139"}
SOURCES = ("producer", "campaign", "ticket", "handoff")
HANDOFF = "completion-plan U5"
LABELS = {"state": ("published", "abandoned"), "bound": ("entries", "words")}
UNITS = {"us", "s", "bytes/s", "lsn", "requests", "attempts", "units", "bytes", "entries", "passes", "gauge",
         "suffixes", "ratio", "cpu-s", "ops/s"}
TIMING = {"us", "s", "bytes/s", "cpu-s", "ops/s"}
H, F, RETAINED, TAIL = "hit_latency", "fill_latency", "retained_hit_recovery", "request_tail"
READERS = (H, TAIL)
FAMILY = ("first_safe_hit", RETAINED, "sustained_fill_readiness", "rto", TAIL, "origin_demand", "goodput",
          "held_capacity", "peak_ram", H, F)
WARM = ("s_membership", "certified_cut", "certified_frontier", "eligible_exclusions", "fault_local_damage",
        "preserved_unaffected_bytes", "protected_history_pressure", "interruption_ancestry")
STAGES = ("detection", "fresh_host_attachment", "authority", "coverage", "read_decode_install",
          "first_correct_recovered_hit", "full_load_readiness")
CONTROLS = {"aa": "null", "always-miss": "retention-fails", "leaked-capacity": "plateau-fails",
            "foreground-hog": "hit-gate-fails", "advertised-rate": "uncredited", "calibration-drift": "stable"}
CONTRASTS = ("class", "revision")
SETS = ("null", "pilot", "held-out")
ORDERS = ("ABBA", "BAAB")
COLUMNS = {"hardware": "Inconclusive: platform row unsupported",
           "store": "Conditional: #123 records no ST1 to ST8 qualification"}
PASS, REGRESSION, UNDECIDED = VERDICTS = ("PASS", "UNACCEPTABLE_REGRESSION", "INCONCLUSIVE")
VERDICT_NAMES = ("pass", "fail", "inconclusive", "handoff")
COMPARISON_KEYS = {"contrasts", "sets", "cells", "row_classes", "columns", "verdicts", "requalification", "frozen",
                   "sizing"}
SIZING = "#141"
DERIVED = ("aa", "calibration-drift")
WARM_ONLY = (RETAINED, "held_capacity")
PROPERTIES = {"P-N-341", "P-N-343", "P-N-344"}
IDENTITY = ("campaign", "commit", "patch_sha256", "cpu_family", "class", "field", "stratum", "evidence", "host",
            "samples_sha256", "n_max")
ENVELOPE_KEYS = ("n_max", "e_max", "volume_size_bytes", "iops", "host_sharing", "platform_row", "cpu_family",
                 "workload_sha256")
MEASURED = ["hardware", "simulation"]
HEADER = {"rate": MEASURED, "locality": MEASURED, "ticks_per_second": ["simulation"],
          "b_pages": ["model", "hardware", "simulation"], "k_slots": ["model", "hardware", "simulation"],
          "s_units_per_slot": ["model", "hardware", "simulation"], "n_max": MEASURED, "e_max": MEASURED,
          "device_model": ["hardware"], "cpu_family": ["hardware"], "objects_measured": MEASURED,
          "always_miss_saturates": MEASURED, "volume_size_bytes": ["hardware"], "iops": ["hardware"],
          "host_sharing": ["hardware"], "platform_row": ["hardware"], "workload_sha256": MEASURED,
          "c_page": ["store"]}
FLOORS = {"quantile": 10, "edge": 1}
NO_PATCH = hashlib.sha256(b"").hexdigest()
GATE_PROVENANCE = ("manifest_sha256", "judge_sha256", "campaign", "main", "candidate", "seed", "open", "reasons")
FLOOR_EXAMPLE = {"requests": 4000, "kinds": {"p50": "quantile", "p90": "quantile", "p99": "quantile", "p999": "edge"}}
RETIRED = {"names": ["c7", "mq-3", "tau"], "prefixes": ["bind", "currency"]}
R6 = {"nominal": {"p90_ms": 1.0, "p99_ms": 3.0}, "large_object": {"p90_ms": 1.0, "p99_ms": 5.0}}
PROVISIONAL = {"familywise_alpha": 0.05, "power": 0.9}
RULES = {
    "bounds": {"method": "Bonferroni", "per_tail": "familywise_alpha / (2 m), m the policy family's member count"},
    "edge_interval": "Wilson score interval at the per-tail level; descriptive, its nominal coverage assumes "
                     "independent requests",
    "censoring": "a timeout is censored at its deadline and ranks above every completed latency; the hit gate's "
                 "samples format records no timeout or deadline, so each outcome's tail holds its completed "
                 "latencies uncensored and a cell holding errors reads inconclusive",
    "hit_latency": "the hit gate's protocol: its A/A band, ABBA and BAAB block contrasts, ceilings and hit floor",
    "block_contrast": "per complete block and member, d = (ln B1 + ln B2 - ln A1 - ln A2) / 2 over the block's four "
                      "positions, signed so that a positive d is worse in the member's direction; a member with "
                      "levels takes one contrast per level, and a block with a position off its seeded order, on an "
                      "unadmitted host, naming no class or, in a class contrast, running the cold class outside the "
                      "null set, or holding a missing or non-positive value is missing for that member",
    "order_bound": "a distribution-free bound on the median contrast: the k-th smallest and k-th largest of n "
                   "contrasts, k the largest count with P(Binomial(n, 1/2) < k) at most the per-tail level, which a "
                   "member with L levels divides by L and S declared class and posture comparison strata divide by "
                   "S; with no such k the bound is unbounded, and a censored contrast bounds only the side its "
                   "censoring keeps",
    "pilot_floor": "held-out blocks per class and posture stratum and member: the fewest n at which the order "
                   "bound's upper side is at most the tolerance with at least the power's probability when the "
                   "contrasts are normal with median zero and the pilot contrasts' standard deviation, a planning "
                   "power the fixed horizon must also reach; the tolerance is ln(1 + smallest effect / the pilot's "
                   "arm A median) for a lower-is-better member and -ln(1 - smallest effect / that median) for a "
                   "higher-is-better one, and a censored pilot value leaves both unsized. The floor sizes the "
                   "non-inferiority side alone and gives no power to the target's improvement",
    "bound_verdict": "PASS when the campaign stands, every control's outcome and the block and calibration values "
                     "are derived from their evidence, the frame's envelope and population are frozen, alpha and "
                     "power are accepted, every family member's upper bound is at most its tolerance and the cited "
                     "target's member holds an upper bound below zero under its posture; UNACCEPTABLE_REGRESSION "
                     "when the campaign stands, its controls standing or underived, and any member's lower bound "
                     "exceeds its tolerance; INCONCLUSIVE otherwise, which never "
                     "merges as a performance change. H takes the hit gate's verdict between the unpatched baseline "
                     "and the candidate; the request tail takes none, the hit gate bounding hit latency alone",
    "drift": "a calibration quantity's uncertainty is the half-width, in its unit, of the interval the driver "
             "declares to hold it; its relative drift ranges from max(0, |end - start| - both half-widths) / (start "
             "+ its half-width) to (|end - start| + both half-widths) / (start - its half-width), and it is stable "
             "when the largest is at most the drift band, drifted when the smallest exceeds it, and unresolved "
             "otherwise or when the start's half-width reaches the start",
}
PROSE = ("units", "contrast", "slopes", "strata", "pilot", "aa", "attempts", "repeatability")
READINESS = ("fill_band", "fill_window_s", "full_load_window_s", "request_deadline_ms")
FRAME_KEYS = {"record", "version", "parent", "evidence", "classes", "envelope", "header", "population", "arrival",
              "fields", "stages", "calibration", "comparison", "floors", "controls", "discipline", "retired",
              "properties", "hit_gate"}
ARRIVAL_KEYS = {"tape", "intended_send_us", "seed", "buckets", "attempts", "terminal", "censoring"}
STATISTICS_KEYS = {"record", "version", *PROSE, *RULES, "horizon", "familywise_alpha", "power", "sample_size",
                   "plateau_bands", "drift_band", "budget_bound", "comparison_strata"}
POLICY_KEYS = {"record", "version", "frame", "statistics", "family", "outcomes", "h", "f", "readiness",
               "request_tail_edge_ms", "class_list", "cold_retained_hits", "budgets", "counted_by",
               "foreground_reservation", "campaign_authority"}
CAMPAIGN_KEYS = {"campaign", "policy", "frame", "statistics", "revision", "header", "hosts", "controls", "cells",
                 "hit_gate", "contrast", "baseline", "safety", "calibration", "blocks", "target"}
FIELD_KEYS = {"unit", "direction", "estimand", "evidence", "sources", "levels", "samples"}
FIXED = {"frame": "91fb0d721a97c0ae36790f750edd17d116bf0ad587ad49dc58dc7c0e7352063a",
         "statistics": "48308613b41895c3e24e44fa4503bf63665a2af325c8af31be224069f99a0d29",
         "policy": "e6fc60176a95f306fe750909c6990ca67852cf5023a729b227e67c10c2c64f35"}
COMMIT = re.compile(r"[0-9a-f]{40}")
TICKET = re.compile(r"#[1-9][0-9]*")
SNAKE = re.compile(r"[a-z][a-z0-9]*(_[a-z0-9]+)*")
KEYWORD = r"(fn|struct|enum|const|static|type|trait|mod|def|class)"
DECLARATION = re.compile(rf"(pub(\([a-z]+\))? )?{KEYWORD} \w+|pub(\([a-z]+\))? (?!{KEYWORD}\b)\w+")
VARIANT = re.compile(r"[A-Z]\w*")


def gate_module():
    spec = importlib.util.spec_from_file_location("hit_gate", HERE / "hit-gate.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("scripts/hit-gate.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = gate_module()
Refusal = gate.Refusal
MAX_HOSTS = MAX_CELLS = gate.MAX_RUNS


def need(condition, message):
    if not condition:
        raise Refusal(f"malformed measurement records: {message}")


def text(value):
    return isinstance(value, str) and bool(value)


def digest(value):
    return isinstance(value, str) and bool(gate.DIGEST.fullmatch(value))


def is_pin(value):
    """Whether `value` is a {version, sha256} pin with an integer version from 1 and a SHA-256 string."""
    return (isinstance(value, dict) and set(value) == {"version", "sha256"} and gate.integer(value["version"], 1)
            and digest(value["sha256"]))


def is_ref(value):
    """Whether `value` names a file by a non-empty path and a SHA-256 string."""
    return isinstance(value, dict) and set(value) == {"path", "sha256"} and text(value["path"]) and digest(value["sha256"])


def fraction(value):
    return gate.positive(value) and value < 1


VALUES = {"rate": gate.positive, "locality": text, "ticks_per_second": gate.positive,
          "b_pages": lambda v: gate.integer(v, 1), "k_slots": lambda v: gate.integer(v, 1),
          "s_units_per_slot": lambda v: gate.integer(v, 1), "n_max": lambda v: gate.integer(v, 1),
          "e_max": lambda v: gate.integer(v, 1), "device_model": text, "cpu_family": text,
          "objects_measured": lambda v: gate.integer(v, 0), "always_miss_saturates": lambda v: isinstance(v, bool),
          "volume_size_bytes": lambda v: gate.integer(v, 1), "iops": gate.positive, "host_sharing": text,
          "platform_row": text, "workload_sha256": digest, "c_page": lambda v: gate.integer(v, 1)}


def canonical(value):
    """The SHA-256 of `value`'s sorted, compact JSON, which a whitespace or key-order edit leaves unchanged."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def fixed(kind, document):
    """The canonical SHA-256 of a validated record with its owner inputs nulled: the content this script fixes."""
    d = copy.deepcopy(document)
    d["version"] = None
    if kind == "frame":
        d["envelope"] = {key: value if key == "e_max" else None for key, value in d["envelope"].items()}
        d["population"]["manifest"] = None
        for part in PARENTS:
            d["parent"][part]["body_sha256"] = None
        for term in (*d["fields"].values(), *d["stages"].values(), *d["calibration"].values()):
            term["sources"] = None
        d["hit_gate"]["qualification_sha256"] = None
    elif kind == "statistics":
        d["horizon"]["blocks"] = d["sample_size"]["value"] = d["plateau_bands"] = d["drift_band"] = None
        d["familywise_alpha"] = d["power"] = d["comparison_strata"] = None
    else:
        d["frame"] = d["statistics"] = d["class_list"] = d["foreground_reservation"] = d["campaign_authority"] = None
        for member, row in d["outcomes"].items():
            row["unit"] = row["normalization"] = row["smallest_effect"] = None
            if member not in (H, F):
                row["boundary"] = None
        d["f"]["percentile"] = d["f"]["budget_ms"] = None
        d["h"]["edge"]["p50"] = d["h"]["edge"]["p999"] = None
        d["readiness"] = dict.fromkeys(d["readiness"])
        d["request_tail_edge_ms"] = dict.fromkeys(d["request_tail_edge_ms"])
        d["budgets"] = {cls: dict.fromkeys(rows) for cls, rows in d["budgets"].items()}
    return canonical(d)


def load(directory):
    """The records under `directory` as {kind: (document, sha256)} and the revision log."""
    records = {}
    for kind in KINDS:
        data = gate.read_file(Path(directory) / f"{kind}.json", kind)
        records[kind] = (gate.parse(data, kind), hashlib.sha256(data).hexdigest())
    log = gate.parse(gate.read_file(Path(directory) / "revisions.json", "revision log"), "revision log")
    return records, log


def git_show(revision, path):
    """`path`'s bytes at `revision` of this repository, read by blob id with replacement refs off, or None when the
    revision's tree has no entry at `path`. A Refusal when `revision` names no commit here, or when the entry is no
    blob, exceeds READ_LIMIT bytes or cannot be read."""
    def git(*args):
        return subprocess.run(["git", "--no-replace-objects", "-C", str(ROOT), *args], capture_output=True,
                              check=False)

    if not text(revision) or git("rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}").returncode != 0:
        raise Refusal(f"revision {revision!r} names no commit of this repository")
    entry = git("rev-parse", "--verify", "--quiet", f"{revision}:{path}")
    if entry.returncode != 0:
        return None
    blob = entry.stdout.decode().strip()
    kind, size = git("cat-file", "-t", blob), git("cat-file", "-s", blob)
    if kind.stdout.strip() != b"blob" or size.returncode != 0:
        raise Refusal(f"{path} at {revision} is no readable blob")
    if int(size.stdout) > gate.READ_LIMIT:
        raise Refusal(f"{path} at {revision} exceeds {gate.READ_LIMIT} bytes")
    shown = git("cat-file", "blob", blob)
    if shown.returncode != 0:
        raise Refusal(f"{path} at {revision} cannot be read")
    return shown.stdout


def prior_log(base):
    """The revision log committed at `base`, or None when `base` holds none."""
    data = git_show(base, f"{RECORDS_PATH}/revisions.json")
    if data is None:
        return None
    log = gate.parse(data, f"the revision log at {base}")
    if not (isinstance(log, dict) and all(isinstance(log.get(kind), list) for kind in KINDS)):
        raise Refusal(f"the revision log at {base} does not list every kind of {KINDS}")
    return log


def pin(records, kind):
    document, sha256 = records[kind]
    return {"version": document["version"], "sha256": sha256}


def floor_kind(requests, q):
    """The floor kind of quantile `q` over `requests` requests, from its expected exceedances."""
    expected = requests * (1 - q)
    if expected >= FLOORS["quantile"]:
        return "quantile"
    return "edge" if expected >= FLOORS["edge"] else "beyond the sample"


def level(statistics, policy):
    """The family size m, the per-tail level familywise_alpha / (2 m) and its upper normal quantile z, taken as the
    negated lower quantile so a small tail keeps its precision."""
    m = len(policy["family"])
    tail = statistics["familywise_alpha"]["value"] / (2 * m)
    return m, tail, -NormalDist().inv_cdf(tail)


def wilson(k, n, z):
    """The Wilson score interval of k exceedances in n requests at normal quantile z. It is descriptive: its nominal
    coverage assumes independent requests."""
    center = (k + z * z / 2) / (n + z * z)
    half = z * math.sqrt(k * (n - k) / n + z * z / 4) / (n + z * z)
    return max(0.0, center - half), min(1.0, center + half)


def summarize(values, z, limits=None):
    """The floor-rule summary of sorted completed `values` in microseconds. An edge quantile reports the Wilson rate
    of values at or over its limit in `limits`, exact microseconds by quantile name, when the policy declares one."""
    n = len(values)
    out: dict[str, object] = {"requests": n}
    for name, q in gate.QUANTILES.items():
        kind = floor_kind(n, q)
        entry: dict[str, object] = {"kind": kind}
        limit = (limits or {}).get(name)
        if kind == "quantile":
            entry["value_us"] = gate.quantile(values, q)
        elif kind == "edge" and limit is not None:
            k = sum(v >= limit for v in values)
            low, high = wilson(k, n, z)
            entry |= {"threshold_ms": gate.ms(limit), "exceedances": k, "rate": k / n, "low": low, "high": high}
        elif kind == "edge":
            entry["reason"] = "the policy declares no edge threshold for this quantile"
        out[name] = entry
    return out


@functools.lru_cache(maxsize=64)
def rust_declarations(content):
    """The declarations of the Rust source `content` as (build, kind, text) rows, as `crates/source-anchors` lists
    them: build is `production` or `gated`, kind is `item`, `field`, `variant`, `module` for a `mod name;` line
    among the file's own items, or `value` for a `const`'s text, ` = ` and its integer-arithmetic initializer. A
    Refusal when the lister does not run or the source does not parse."""
    command = ["cargo", "run", "--quiet", "--package", "source-anchors"]
    try:
        done = subprocess.run(command, cwd=HERE.parent, input=content.encode(), capture_output=True, check=False,
                              timeout=600)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise Refusal(f"`{' '.join(command)}` did not run: {error}") from error
    if done.returncode != 0:
        raise Refusal((done.stderr.decode(errors="replace").strip().splitlines() or ["source-anchors failed"])[-1])
    return tuple(tuple(line.split("\t")) for line in done.stdout.decode().splitlines())


def python_declarations(content):
    """The `def name` and `class name` declarations of the Python source `content` at module level and in class
    bodies, as its syntax tree holds them. A Refusal when the source does not parse."""
    try:
        pending = [ast.parse(content)]
    except (SyntaxError, ValueError) as error:
        raise Refusal(f"does not parse as Python: {error}") from error
    found = set()
    while pending:
        for node in pending.pop().body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                found.add(f"def {node.name}")
            elif isinstance(node, ast.ClassDef):
                found.add(f"class {node.name}")
                pending.append(node)
    return found


def repository_path(path):
    """Why `path`, joined to the repository root, does not resolve to a path inside the repository, or None; and the
    resolved path when it does."""
    try:
        target = (ROOT / path).resolve(strict=True)
    except (OSError, RuntimeError, ValueError) as error:
        return f"path {path} does not resolve: {error}", None
    if ROOT not in target.parents:
        return f"path {path} is outside the repository", None
    return None, target


def parent_gates(target):
    """Whether the Rust file `target` is a module that every `mod` line declaring it gates out of a build without
    `test`, on that line or on an ancestor module's. The files above it are the `mod.rs`, `lib.rs` and `main.rs` of
    its directory and the file named for that directory, inside the repository, and a declaring line is a
    `mod name;` among such a file's own items. A crate root reads as ungated, where Cargo's default layout puts
    one: `src/lib.rs` and `src/main.rs` beside a `Cargo.toml`, a file in `src/bin`, a `main.rs` in a directory of
    `src/bin`, and a file with no file above it whose module directory holds `Cargo.toml`. A Refusal for any other
    file that no file above it declares."""
    folder = target.parent
    if (folder.parts[-2:] == ("src", "bin") or target.name == "main.rs" and folder.parent.parts[-2:] == ("src", "bin")
            or target.name in ("lib.rs", "main.rs") and folder.name == "src"
            and (folder.parent / "Cargo.toml").is_file()):
        return False
    name, directory = (folder.name, folder.parent) if target.name == "mod.rs" else (target.stem, folder)
    line, gates = re.compile(rf"(pub(\([^)]*\))? )?mod {re.escape(name)}"), []
    parents = [parent for parent in (directory / "mod.rs", directory / "lib.rs", directory / "main.rs",
                                     directory.parent / f"{directory.name}.rs")
               if parent != target and ROOT in parent.parents and parent.is_file()]
    for parent in parents:
        try:
            rows = rust_declarations(gate.read_file(parent, "source").decode(errors="replace"))
        except Refusal as error:
            raise Refusal(f"its parent module {parent.relative_to(ROOT)}: {error}") from error
        gates += [build == "gated" or parent_gates(parent) for build, kind, name in rows
                  if kind == "module" and line.fullmatch(name)]
    if parents and not gates:
        raise Refusal(f"no `mod {name};` line in {' or '.join(str(p.relative_to(ROOT)) for p in parents)} declares "
                      f"{target.relative_to(ROOT)}")
    if not parents and not (directory / "Cargo.toml").is_file():
        raise Refusal(f"no file above {target.relative_to(ROOT)} declares it, and it is no crate root")
    return bool(gates) and all(gates)


def resolve(source, producer):
    """Why a repository anchor `{path, symbol}` fails to resolve, or None: the path resolves to a regular Rust or
    Python file inside the repository whose syntax tree declares the symbol, any visibility scope standing for the
    symbol's own. The symbol is a declaration led by a keyword or by `pub`, or a bare enum variant. In a Rust file it
    is an item, a named field or, for a bare name, a variant that `rust_declarations` lists; in a Python file it is
    one of `python_declarations`. A producer's path has no test component, its Rust declaration is in a build
    without `test`, and so is the module its file holds (`parent_gates`)."""
    path, symbol = source.get("path"), source.get("symbol")
    if not (text(path) and text(symbol)):
        return "names no path and symbol"
    variant = bool(VARIANT.fullmatch(symbol))
    scoped = re.fullmatch(r"pub(\([a-z]+\))? (.*)", symbol)
    if not (DECLARATION.fullmatch(symbol) or variant):
        return f"symbol {symbol!r} is no declaration or enum variant"
    problem, target = repository_path(path)
    if target is None:
        return problem
    if target.suffix not in (".rs", ".py"):
        return f"source {path} is neither Rust nor Python, the sources this check reads"
    parts = target.relative_to(ROOT).parts
    if producer and (any(p in ("tests", "tests.rs") or p.endswith(("_tests", "_tests.rs")) for p in parts)
                     or parts[-1].startswith("test-")):
        return f"producer {path} is test code"
    try:
        content = gate.read_file(target, f"source {path}").decode(errors="replace")
    except Refusal as error:
        return str(error)
    try:
        if target.suffix == ".py":
            found = symbol in python_declarations(content)
        else:
            scope = r"pub(\([^)]*\))? " + re.escape(scoped.group(2)) if scoped else re.escape(symbol)
            found = any((kind == "variant") == variant and re.fullmatch(scope, name)
                        and (build == "production" or not producer) for build, kind, name in rust_declarations(content))
            if producer and parent_gates(target):
                return f"producer {path} is test code"
    except Refusal as error:
        return f"source {path}: {error}" if target.suffix == ".rs" else f"source {path} {error}"
    return None if found else f"{path} declares no {symbol!r} outside docstrings and test items"


def source_problem(source):
    """Why one field source is malformed, or None: a producer names a production file and declaration, a campaign
    its computation and an optional anchor, a ticket its owner and draft text, and a handoff the completion plan's
    report unit, labels from the closed label table and draft text."""
    if not isinstance(source, dict) or source.get("kind") not in SOURCES:
        return f"kind is not one of {SOURCES}"
    kind = source["kind"]
    if kind == "producer":
        if set(source) != {"kind", "path", "symbol"}:
            return "a producer names other keys than a path and a symbol"
        return resolve(source, producer=True)
    if kind == "campaign":
        if not (set(source) in ({"kind", "computation"}, {"kind", "computation", "path", "symbol"})
                and text(source["computation"])):
            return "a campaign source names no computation or more than one anchor"
        return resolve(source, producer=False) if "path" in source else None
    if not (text(source.get("draft")) and text(source.get("owner"))):
        return f"a {kind} source names no owner or no draft text"
    if kind == "ticket":
        return None if set(source) == {"kind", "owner", "draft"} and TICKET.fullmatch(source["owner"]) else \
            "a ticket source names other keys or an owner that is not a #number"
    labels = source.get("labels")
    if set(source) != {"kind", "owner", "draft", "labels"} or source["owner"] != HANDOFF:
        return f"an unowned gap hands off to another owner than {HANDOFF} or without labels"
    if not (isinstance(labels, dict) and labels and all(
            name in LABELS and isinstance(values, list) and values and len(set(map(str, values))) == len(values)
            and all(isinstance(v, str) and v in LABELS[name] for v in values) for name, values in labels.items())):
        return f"labels are not drawn from the closed label table {LABELS}"
    return None


def check_term(name, term, keys):
    need(isinstance(term, dict) and set(term) <= keys and {"unit", "estimand", "evidence", "sources"} <= set(term),
         f"{name} has other keys than {sorted(keys)} or lacks one")
    unit = term["unit"]
    need(isinstance(unit, str) and unit in UNITS and text(term["estimand"]),
         f"{name} unit {unit!r} is not one of {sorted(UNITS)} or its estimand is empty")
    evidence = term["evidence"]
    need(isinstance(evidence, list) and evidence and all(isinstance(e, str) for e in evidence)
         and set(evidence) <= set(EVIDENCE) and len(set(evidence)) == len(evidence),
         f"{name} evidence kinds are empty, repeated or undeclared")
    need(unit not in TIMING or "simulation" not in evidence,
         f"{name} is a timing in {unit}, yet admits simulation evidence, which never supplies one")
    need(isinstance(term["sources"], dict) and set(term["sources"]) == set(evidence),
         f"{name} does not name one source per evidence kind")
    for kind, source in term["sources"].items():
        problem = source_problem(source)
        need(problem is None, f"{name} {kind} source: {problem}")


def retired(name):
    """Whether `name` holds a retired axis: a retired name as a run of its `_`, `-` or `.` tokens, or a token
    starting with a retired prefix."""
    tokens = re.split(r"[_\-.]", name.lower())
    runs = {"_".join(tokens[i:j]) for i in range(len(tokens)) for j in range(i + 1, len(tokens) + 1)}
    return any("_".join(re.split(r"[_\-.]", n)) in runs for n in RETIRED["names"]) or any(
        t.startswith(tuple(RETIRED["prefixes"])) for t in tokens)


def texts(value):
    """Whether `value` is a non-empty list of distinct non-empty strings."""
    return isinstance(value, list) and bool(value) and all(map(text, value)) and len(set(value)) == len(value)


def check_comparison(comparison, terms):
    """Validate the frame's comparison definition: the contrasts and block sets this judge reads, each campaign
    report row's required term and strata, the classes a row is limited to, the column labels, the verdict names, the
    requalification and frozen-rule lists a ticket states and the sizing hand-off's fields."""
    need(isinstance(comparison, dict) and set(comparison) == COMPARISON_KEYS,
         f"the comparison keys are not {sorted(COMPARISON_KEYS)}")
    for key, names in (("contrasts", CONTRASTS), ("sets", SETS)):
        table = comparison[key]
        need(isinstance(table, dict) and tuple(table) == names and all(map(text, table.values())),
             f"the comparison {key} are not {names}, each with its meaning")
    cells = comparison["cells"]
    need(isinstance(cells, dict) and bool(cells) and all(name in terms and texts(s) for name, s in cells.items()),
         "the comparison's report rows name a term the frame lacks or no distinct strata")
    only = comparison["row_classes"]
    need(isinstance(only, dict) and all(name in cells and texts(c) and set(c) <= set(CLASSES)
                                        for name, c in only.items()),
         "the comparison's row classes name a row outside the report rows or a class outside the classes")
    need(comparison["columns"] == COLUMNS, f"the comparison's column labels are not {COLUMNS}")
    need(comparison["verdicts"] == list(VERDICTS), f"the comparison's verdicts are not {VERDICTS}")
    need(texts(comparison["requalification"]) and texts(comparison["frozen"]),
         "the requalification or frozen-rule list is no list of distinct statements")
    sizing = comparison["sizing"]
    need(isinstance(sizing, dict) and set(sizing) == {"owner", "fields"} and sizing["owner"] == SIZING
         and texts(sizing["fields"]) and all(name in terms for name in sizing["fields"]),
         f"the sizing hand-off does not name {SIZING} and frame fields")


def check_frame(frame, qualification):
    """Validate the frame; return its open items."""
    need(isinstance(frame, dict) and set(frame) == FRAME_KEYS and frame["record"] == "frame"
         and gate.integer(frame["version"], 1), "frame keys, record name or version")
    parent = frame["parent"]
    need(isinstance(parent, dict) and set(parent) == {*PARENTS, "digest"} and text(parent["digest"])
         and all(isinstance(parent[k], dict) and parent[k].get("issue") == issue and digest(parent[k].get("body_sha256"))
                 and set(parent[k]) == {"issue", "body_sha256"} for k, issue in PARENTS.items()),
         f"the parent does not pin {PARENTS} by their body SHA-256 under a stated digest rule")
    need(isinstance(frame["evidence"], dict) and set(frame["evidence"]) == set(EVIDENCE)
         and all(map(text, frame["evidence"].values())), f"the evidence kinds are not {EVIDENCE}")
    classes = frame["classes"]
    need(isinstance(classes, dict) and tuple(classes) == tuple(CLASSES)
         and all(isinstance(c, dict) and set(c) == {"cold", "role", "meaning"} and c["cold"] is (name == COLD)
                 and c["role"] == CLASSES[name] and text(c["meaning"]) for name, c in classes.items()),
         f"the classes are not {CLASSES}, of which only {COLD} is cold")
    envelope = frame["envelope"]
    need(isinstance(envelope, dict) and tuple(envelope) == ENVELOPE_KEYS, f"the envelope keys are not {ENVELOPE_KEYS}")
    need(gate.integer(envelope["e_max"]) and envelope["e_max"] == 1 << 28,
         f"e_max {envelope['e_max']!r} is not 2^28 extent rows")
    recovery = qualification["recovery"]
    need((envelope["n_max"], envelope["e_max"]) == (recovery.get("n_max"), recovery.get("e_max")),
         f"the envelope's n_max and e_max differ from the qualification's {recovery.get('n_max')} and "
         f"{recovery.get('e_max')}")
    bad = [key for key, value in envelope.items() if value is not None and not VALUES[key](value)]
    need(not bad, f"envelope values {bad} are off their types")
    need(frame["header"] == HEADER, f"the header is not {HEADER}")
    population = frame["population"]
    need(isinstance(population, dict) and "manifest" in population, "the population is no object with a manifest")
    manifest = population["manifest"]
    if manifest is not None:
        need(isinstance(manifest, dict) and set(manifest) == {"path", "sha256"} and text(manifest["path"]),
             "the population manifest names no file by a path string")
        problem, target = repository_path(manifest["path"])
        if target is not None:
            problem = evidence_problem({**manifest, "path": str(target)}, "population manifest")[0]
        need(problem is None, f"the population manifest does not resolve: {problem}")
        need(envelope["workload_sha256"] == manifest["sha256"],
             "the population manifest's digest is not the envelope's workload_sha256")
    need(manifest is not None or envelope["workload_sha256"] is None,
         "the envelope declares a workload_sha256 without a population manifest that holds it")
    arrival = frame["arrival"]
    need(isinstance(arrival, dict) and set(arrival) == ARRIVAL_KEYS
         and arrival["terminal"] == ["timeout", "refused", "error"] and arrival["censoring"] == RULES["censoring"]
         and all(text(v) for k, v in arrival.items() if k not in ("terminal", "censoring")),
         "the arrival section is off its keys, terminal outcomes or censoring rule")
    fields, stages = frame["fields"], frame["stages"]
    need(isinstance(fields, dict), "the fields are no object")
    missing = sorted((set(WARM) | set(FAMILY)) - set(fields))
    need(not missing, f"fields lack {missing}")
    for name, field in fields.items():
        need(isinstance(name, str) and bool(SNAKE.fullmatch(name)), f"field name {name!r} is not lower snake case")
        check_term(name, field, FIELD_KEYS)
        need(field.get("direction") in ("lower", "higher"), f"{name} direction is not lower or higher")
        reader = name in READERS
        need(("samples" in field) == reader and (not reader or (field["samples"] == "hit-gate" and field["unit"] == "us"
                                                                and field["evidence"] == ["hardware"])),
             f"{name} names a samples reader other than the hit gate's for {READERS} on hardware in us")
    need(fields[RETAINED].get("levels") == [50, 90, 99], f"{RETAINED} levels are not [50, 90, 99]")
    need(isinstance(stages, dict) and tuple(stages) == STAGES, f"the stages are not {STAGES}")
    for name, stage in stages.items():
        check_term(name, stage, {"unit", "estimand", "evidence", "sources"})
        need(stage["unit"] == "s", f"stage {name} is not in seconds")
    calibration = frame["calibration"]
    need(isinstance(calibration, dict) and bool(calibration), "the calibration declares no C2 terms")
    for name, term in calibration.items():
        need(isinstance(name, str) and bool(SNAKE.fullmatch(name)),
             f"calibration term {name!r} is not lower snake case")
        check_term(name, term, {"unit", "estimand", "evidence", "sources"})
        need(term["evidence"] == ["hardware"], f"calibration term {name} is measured on other evidence than hardware")
    check_comparison(frame["comparison"], {**fields, **stages})
    floors = frame["floors"]
    need(isinstance(floors, dict) and set(floors) == {*FLOORS, "quantiles", "example"}
         and all(gate.integer(floors[k]) and floors[k] == v for k, v in FLOORS.items()),
         f"the floors are not {FLOORS} expected exceedances")
    need(floors["quantiles"] == {name: str(q) for name, q in gate.QUANTILES.items()},
         "the quantiles are not p50, p90, p99 and p999 at 1/2, 9/10, 99/100 and 999/1000")
    need(json.dumps(floors["example"], sort_keys=True) == json.dumps(FLOOR_EXAMPLE, sort_keys=True),
         f"the floor example is not {FLOOR_EXAMPLE}")
    controls = frame["controls"]
    need(isinstance(controls, dict) and all(isinstance(c, dict) for c in controls.values())
         and {name: c.get("expected") for name, c in controls.items()} == CONTROLS
         and all(text(c.get("meaning")) for c in controls.values()), f"the controls are not {CONTROLS}")
    discipline = frame["discipline"]
    need(isinstance(discipline, dict) and discipline.get("identity") == list(IDENTITY)
         and all(text(v) for k, v in discipline.items() if k != "identity"), f"the run identity is not {IDENTITY}")
    need(frame["retired"] == RETIRED, f"the retired axes are not {RETIRED}")
    need(not (hits := [n for n in fields if retired(n)]), f"retired axes {hits}")
    need(isinstance(frame["properties"], dict) and set(frame["properties"]) == PROPERTIES,
         f"the property map is not {sorted(PROPERTIES)}")
    expected = {"judge": "scripts/hit-gate.py", "qualification_sha256": canonical(qualification)}
    need(frame["hit_gate"] == expected, f"the frame pins another hit gate than {expected}")
    found = fixed("frame", frame)
    need(found == FIXED["frame"], f"the frame changes content this script fixes: it hashes to {found}, not "
                                  f"{FIXED['frame']}")
    open_items = [f"the envelope declares no {key}" for key, value in envelope.items() if value is None]
    open_items.append("the frame names no frozen population manifest" if manifest is None else
                      "no check here validates the population manifest's contents against its manifest fields")
    return open_items


def check_statistics(statistics):
    need(isinstance(statistics, dict) and set(statistics) == STATISTICS_KEYS and statistics["record"] == "statistics"
         and gate.integer(statistics["version"], 1), "statistics keys, record name or version")
    need(all(text(statistics[key]) for key in PROSE), f"statistics {PROSE} are not all text")
    for key, rule in RULES.items():
        need(statistics[key] == rule, f"the statistics {key} is not the rule this judge applies, {rule!r}")
    open_items = []
    for name, provisional in PROVISIONAL.items():
        value = statistics[name]
        need(isinstance(value, dict) and set(value) == {"value", "status"}
             and value["status"] in ("provisional", "accepted") and fraction(value["value"]),
             f"{name} is no fraction in (0, 1) with a provisional or accepted status")
        need(value["status"] == "accepted" or value["value"] == provisional, f"provisional {name} is not {provisional}")
        if value["status"] == "provisional":
            open_items.append(f"{name} {value['value']} is provisional, so every result is discovery, not powered "
                              "confirmation")
    need(statistics["familywise_alpha"]["value"] / (2 * len(FAMILY)) > 0,
         "the familywise alpha's per-tail level underflows to zero")
    horizon, sample_size = statistics["horizon"], statistics["sample_size"]
    need(isinstance(horizon, dict) and set(horizon) == {"fixed", "extension", "blocks"} and horizon["fixed"] is True
         and horizon["extension"] is False
         and (horizon["blocks"] is None or gate.integer(horizon["blocks"], 2, MAX_CELLS)),
         f"the horizon is not fixed without extension over a block count from 2 to {MAX_CELLS}, the most blocks a "
         "campaign holds")
    need(isinstance(sample_size, dict) and set(sample_size) == {"from", "value"} and text(sample_size["from"])
         and (sample_size["value"] is None or gate.integer(sample_size["value"], 1)),
         "the sample size is no positive count")
    bands = statistics["plateau_bands"]
    need(bands is None or (isinstance(bands, dict) and bands and all(
        text(k) and gate.positive(v) for k, v in bands.items())), "plateau bands are no resource-to-band table")
    need(statistics["drift_band"] is None or gate.positive(statistics["drift_band"]), "the drift band is not positive")
    need(statistics["budget_bound"] is None, "this judge applies no budget bound; a version naming one needs a judge")
    strata = statistics["comparison_strata"]
    need(strata is None or (texts(strata) and all(
        s.partition("/")[0] in CLASSES and s.partition("/")[2] in gate.PHASES for s in strata)),
         "the comparison strata are no distinct class/posture names")
    found = fixed("statistics", statistics)
    need(found == FIXED["statistics"], f"the statistics change content this script fixes: they hash to {found}, not "
                                       f"{FIXED['statistics']}")
    open_items += [f"the statistics version declares no {label}" for label, value in (
        ("horizon block count", horizon["blocks"]), ("sample size from the power target", sample_size["value"]),
        ("plateau bands", bands), ("calibration drift band", statistics["drift_band"]),
        ("comparison strata", strata)) if value is None]
    return open_items + ["the statistics version declares no budget bound"]


def outcome(policy, cls, member):
    """One family member's per-class verdict before any judge scores it: `inconclusive` for H, for the cold class's
    warm-only members and for a set budget; `unscored` while F's or the member's budget is null."""
    if member == H or cls == COLD and member in WARM_ONLY:
        return "inconclusive"
    budget = policy["f"]["budget_ms"] if member == F else policy["budgets"][cls][member]
    return "unscored" if budget is None else "inconclusive"


def check_policy(records):
    policy, frame = records["policy"][0], records["frame"][0]
    need(isinstance(policy, dict) and set(policy) == POLICY_KEYS and policy["record"] == "policy"
         and gate.integer(policy["version"], 1), "policy keys, record name or version")
    for kind in ("frame", "statistics"):
        need(is_pin(policy[kind]) and policy[kind] == pin(records, kind),
             f"the policy names another {kind} version than the committed one, {pin(records, kind)}")
    need(policy["family"] == list(FAMILY), f"the family is not {FAMILY}")
    outcomes = policy["outcomes"]
    need(isinstance(outcomes, dict) and list(outcomes) == list(FAMILY), "the outcomes are not one row per member")
    for member, o in outcomes.items():
        need(isinstance(o, dict) and set(o) == {"unit", "normalization", "boundary", "smallest_effect"}
             and text(o["unit"]) and all(o[k] is None or text(o[k]) for k in ("normalization", "boundary"))
             and (o["smallest_effect"] is None or gate.positive(o["smallest_effect"])),
             f"outcome {member} is no row of a unit, text or null normalization and boundary and a positive or "
             "null smallest effect")
        need(o["normalization"] is not None or o["unit"] == frame["fields"][member]["unit"],
             f"outcome {member}'s unit {o['unit']!r} is not its field's {frame['fields'][member]['unit']!r}, yet it "
             "names no normalization")
    need(outcomes[H]["normalization"] is None and outcomes[H]["smallest_effect"] is None,
         "H's row holds a normalization or smallest effect, but H follows the hit gate's protocol")
    h, f, readiness, tail = policy["h"], policy["f"], policy["readiness"], policy["request_tail_edge_ms"]
    need(isinstance(h, dict) and set(h) == {"boundary", *R6, "reported", "strata", "edge"}
         and json.dumps({k: h[k] for k in R6}, sort_keys=True) == json.dumps(R6, sort_keys=True),
         f"H is not R6's {R6} with its boundary, reports and edge thresholds")
    need(isinstance(h["edge"], dict) and list(h["edge"]) == list(gate.QUANTILES)
         and (h["edge"]["p90"], h["edge"]["p99"]) == ("p90_ms", "p99_ms")
         and all(v in (None, "p90_ms", "p99_ms") for v in h["edge"].values()),
         "H's edge thresholds do not rate p90 at p90_ms and p99 at p99_ms, or name another ceiling")
    need(isinstance(f, dict) and set(f) == {"boundary", "percentile", "budget_ms"}
         and (f["percentile"] is None or fraction(f["percentile"]))
         and (f["budget_ms"] is None or gate.positive(f["budget_ms"])),
         "F is no boundary with a percentile in (0, 1) and a positive budget, each or null")
    need(text(h["boundary"]) and h["boundary"] == outcomes[H]["boundary"], "H's boundary differs from its outcome row")
    need(text(f["boundary"]) and f["boundary"] == outcomes[F]["boundary"], "F's boundary differs from its outcome row")
    need(isinstance(readiness, dict) and tuple(readiness) == READINESS
         and all(v is None or gate.positive(v) for v in readiness.values()),
         f"the readiness inputs are not {READINESS}, each positive or null")
    need(isinstance(tail, dict) and list(tail) == list(gate.QUANTILES)
         and all(v is None or gate.positive(v) for v in tail.values()),
         "the request tail's edge thresholds are not one positive or null millisecond value per quantile")
    class_list = policy["class_list"]
    need(class_list is None or (isinstance(class_list, list) and all(isinstance(c, str) for c in class_list)
                                and len(set(class_list)) == len(class_list) and set(class_list) == set(CLASSES)),
         f"the class list is not the classes {list(CLASSES)}")
    cold = policy["cold_retained_hits"]
    need(isinstance(cold, dict) and list(cold) == [COLD] and gate.integer(cold[COLD]) and cold[COLD] == 0,
         f"the cold class's retained hits are not {{{COLD!r}: 0}}")
    budgets = policy["budgets"]
    need(isinstance(budgets, dict) and tuple(budgets) == tuple(CLASSES)
         and all(isinstance(rows, dict) and list(rows) == list(FAMILY) for rows in budgets.values()),
         "the budgets are not one row per class and family member")
    bad = [f"{cls}.{member}" for cls, rows in budgets.items() for member, v in rows.items()
           if not (v is None or gate.positive(v))]
    need(not bad, f"budget rows {bad} are neither positive nor null")
    need(all(budgets[c][m] is None for c in CLASSES for m in (H, F)),
         "H's and F's budget rows hold a value, but their ceilings and budget live in h and f")
    need(budgets[COLD][RETAINED] is None, "the cold class holds a retained-hit recovery budget, but it retains no hit")
    need(budgets[COLD]["held_capacity"] is None,
         "the cold class holds a held-capacity budget, but it restores no capacity")
    need(policy["counted_by"] == ["#139", "#140", "#142"], "the policy counts for other tickets than #139, "
                                                               "#140 and #142")
    reservation, authority = policy["foreground_reservation"], policy["campaign_authority"]
    need(reservation is None or fraction(reservation), "the foreground reservation is no fraction in (0, 1)")
    need(authority is None or (isinstance(authority, dict)
                               and set(authority) == {"approver", "budget_usd", "host_hours"}
                               and text(authority["approver"]) and gate.positive(authority["budget_usd"])
                               and gate.positive(authority["host_hours"])),
         "the campaign authority is no approver with a positive budget_usd and host_hours")
    found = fixed("policy", policy)
    need(found == FIXED["policy"], f"the policy changes content this script fixes: it hashes to {found}, not "
                                   f"{FIXED['policy']}")
    open_items = [f"F declares no accepted {key}" for key in ("percentile", "budget_ms") if f[key] is None]
    open_items += [f"the policy declares no {key}" for key, value in readiness.items() if value is None]
    open_items += [f"H declares no edge threshold for {name}" for name, value in h["edge"].items() if value is None]
    open_items += [f"the request tail declares no edge threshold for {name}" for name, value in tail.items()
                   if value is None]
    if class_list is None:
        open_items.append("the policy names no readiness-review class list")
    if reservation is None:
        open_items.append("the policy declares no foreground reservation for the calibration's worker slots")
    if authority is None:
        open_items.append("the policy names no campaign authority, budget or host-hour limit")
    open_items += [f"{member} declares no {key}" for member, row in outcomes.items() if member != H
                   for key, value in row.items() if value is None]
    unscored = sum(outcome(policy, cls, member) == "unscored" for cls in CLASSES for member in FAMILY if member != F)
    if unscored:
        open_items.append(f"{unscored} budget rows hold no accepted budget and read unscored")
    return open_items


def check_log(records, log, prior=None):
    """Validate the revision log: each kind's entries are versions 1 to n with their digests, the last is the
    committed record, and with `prior` every entry of the earlier log stands unchanged at the start."""
    need(isinstance(log, dict) and set(log) == set(KINDS), f"the revision log keys are not {KINDS}")
    for kind in KINDS:
        entries, document = log[kind], records[kind][0]
        need(isinstance(entries, list) and entries and all(map(is_pin, entries))
             and [e["version"] for e in entries] == list(range(1, len(entries) + 1)),
             f"{kind} revisions are not versions 1 to n with their digests")
        need(isinstance(document, dict) and gate.integer(document.get("version"), 1)
             and entries[-1] == pin(records, kind),
             f"{kind} version {document.get('version') if isinstance(document, dict) else None} with SHA-256 "
             f"{records[kind][1]} is not its last logged revision")
        if prior is not None:
            need(entries[:len(prior[kind])] == prior[kind],
                 f"the {kind} revisions rewrite or drop an entry the earlier log holds")


def check(records, log, qualification, prior=None):
    """Raise Refusal at the first malformed record; return the open items."""
    check_log(records, log, prior)
    open_items = check_frame(records["frame"][0], qualification)
    open_items += check_statistics(records["statistics"][0])
    return open_items + check_policy(records)


def campaign_id(records, commit, patch, baseline=None):
    """The campaign id the records, the measured commit and patch digest, and a revision contrast's baseline derive."""
    joined = "/".join([*(records[kind][1] for kind in KINDS), commit, patch,
                       *((baseline["commit"], baseline["patch_sha256"]) if baseline else ())])
    return f"measure-{hashlib.sha256(joined.encode()).hexdigest()[:16]}"


def evidence_problem(ref, what):
    """Why the raw evidence `{path, sha256}` does not resolve, or None; and its bytes when it does."""
    if not is_ref(ref):
        return f"{what} names no path and SHA-256", None
    try:
        data = gate.read_file(ref["path"], what)
    except Refusal as error:
        return str(error), None
    if hashlib.sha256(data).hexdigest() != ref["sha256"]:
        return f"{what} {ref['path']!r} is not the file its SHA-256 names", None
    return None, data


def host_shape(host):
    return (isinstance(host, dict) and text(host.get("id")) and text(host.get("instance"))
            and text(host.get("cpu_family")) and host.get("clock") in ("trusted", "untrusted")
            and isinstance(host.get("reference"), bool))


def cell_shape(cell):
    return (isinstance(cell, dict) and all(text(cell.get(k)) for k in ("class", "field", "stratum", "evidence", "host"))
            and ("samples" not in cell or is_ref(cell["samples"]))
            and ("header" not in cell or (isinstance(cell["header"], dict) and all(
                key in HEADER and cell["evidence"] in HEADER[key] for key in cell["header"]))))


def is_revision(r):
    return (isinstance(r, dict) and set(r) == {"commit", "patch_sha256"} and isinstance(r["commit"], str)
            and bool(COMMIT.fullmatch(r["commit"])) and digest(r["patch_sha256"]))


def block_shape(block):
    """Whether `block` is a block of a known set, posture and order whose hosts and volumes are named and whose
    positions each name an arm, a run, raw evidence and an outcome table. Completeness is judged, not shaped: a block
    of fewer positions reads missing."""
    return (isinstance(block, dict) and set(block) == {"set", "class", "posture", "order", "hosts", "volumes",
                                                       "positions"}
            and block["set"] in SETS and text(block["class"]) and block["posture"] in gate.PHASES
            and block["order"] in ORDERS and texts(block["hosts"]) and texts(block["volumes"])
            and isinstance(block["positions"], list) and len(block["positions"]) <= 4
            and all(isinstance(p, dict) and set(p) == {"arm", "run", "evidence", "outcomes"} and p["arm"] in ("A", "B")
                    and text(p["run"]) and is_ref(p["evidence"]) and isinstance(p["outcomes"], dict)
                    for p in block["positions"]))


def calibration_shape(value):
    return isinstance(value, dict) and set(value) == {"start", "end"} and all(
        isinstance(e, dict) and set(e) == {"host", "volumes", "evidence", "values"} and text(e["host"])
        and texts(e["volumes"]) and is_ref(e["evidence"]) and isinstance(e["values"], dict) for e in value.values())


SHAPES = {
    "campaign": text,
    **{kind: lambda v: v is None or is_pin(v) for kind in KINDS},
    "revision": is_revision,
    "baseline": is_revision,
    "contrast": lambda v: v in CONTRASTS,
    "safety": lambda v: isinstance(v, dict),
    "calibration": calibration_shape,
    "blocks": lambda v: isinstance(v, list) and len(v) <= MAX_CELLS and all(map(block_shape, v)),
    "target": lambda v: isinstance(v, dict) and set(v) == {"receipt", "cell"} and is_ref(v["receipt"])
    and text(v["cell"]),
    "header": lambda v: isinstance(v, dict),
    "hit_gate": is_ref,
    "controls": lambda v: isinstance(v, dict) and all(
        isinstance(c, dict) and isinstance(c.get("observed"), str) and is_ref(c.get("evidence")) for c in v.values()),
    "cells": lambda v: isinstance(v, list) and len(v) <= MAX_CELLS and all(map(cell_shape, v)),
    "hosts": lambda v: (isinstance(v, list) and len(v) <= MAX_HOSTS and all(map(host_shape, v))
                        and len({h["id"] for h in v}) == len(v) and len({h["instance"] for h in v}) == len(v)),
}


def check_shape(campaign):
    """Refuse a campaign whose supplied fields are off their types or past their bounds, whatever policy it names,
    before any evidence file is opened."""
    if not (isinstance(campaign, dict) and set(campaign) <= CAMPAIGN_KEYS):
        raise Refusal(f"the campaign is not an object of the keys {sorted(CAMPAIGN_KEYS)}")
    bad = sorted(key for key, test in SHAPES.items() if key in campaign and not test(campaign[key]))
    if bad:
        raise Refusal(f"the campaign's {bad} are off their types (hosts and cells at most {MAX_HOSTS} and "
                      f"{MAX_CELLS}, hosts with distinct ids and instances)")


def admit_hosts(hosts, family):
    """Each host's admission: its CPU family is the header's `family` when that is declared, its jobs fit its
    physical cores, and its outcome file's digest equals the one admitted reference host's of its CPU family."""
    out, digests = {}, {}
    for host in hosts:
        reasons = []
        jobs, cores = host.get("jobs"), host.get("physical_cores")
        if not (gate.integer(jobs, 1) and gate.integer(cores, 1)):
            reasons.append(f"host {host['id']} declares no positive jobs and physical_cores")
        elif jobs > cores:
            reasons.append(f"host {host['id']} runs more jobs than its physical cores")
        if family is not None and host["cpu_family"] != family:
            reasons.append(f"host {host['id']}'s CPU family {host['cpu_family']} is not the header's {family}")
        problem = evidence_problem(host.get("outcome"), f"host {host['id']} outcome file")[0]
        if problem:
            reasons.append(problem)
        digests[host["id"]] = None if problem else host["outcome"]["sha256"]
        out[host["id"]] = {"instance": host["instance"], "cpu_family": host["cpu_family"], "clock": host["clock"],
                           "reasons": reasons}
    alone = {name: not entry["reasons"] for name, entry in out.items()}
    references = {}
    for host in hosts:
        if host["reference"]:
            references.setdefault(host["cpu_family"], []).append(host["id"])
    for host in hosts:
        entry, refs = out[host["id"]], references.get(host["cpu_family"], [])
        if len(refs) != 1:
            entry["reasons"].append(f"CPU family {host['cpu_family']} has {len(refs)} reference hosts, not one")
        elif not alone[refs[0]]:
            entry["reasons"].append(f"reference host {refs[0]} is not admitted on its own")
        elif digests[host["id"]] != digests[refs[0]]:
            entry["reasons"].append(f"host {host['id']}'s outcome digest differs from reference host {refs[0]}'s")
    for entry in out.values():
        entry["admitted"] = not entry["reasons"]
    return out


def parse_samples(data, workload, qualification):
    """A hit-gate samples file of `workload` as its header and samples, or raise Refusal. The line count is checked
    on the raw bytes before any line is decoded. The hit gate's `bound_samples` checked the same bytes before it
    admitted their digest; this reader keeps its own checks so a summary never rests on an undecoded assumption."""
    requests = qualification["protocol"]["requests"]
    lines = data.count(b"\n")
    if not data.endswith(b"\n") or lines - 1 > gate.MAX_REQUESTS or requests not in (None, lines - 1):
        raise Refusal(f"the samples file holds another line count than a header and the protocol's {requests} "
                      f"requests, at most {gate.MAX_REQUESTS}")
    head, _, body = data.partition(b"\n")
    header = gate.parse(head, "the samples header")
    spec = qualification["workloads"][workload]
    if not (isinstance(header, dict) and set(header) == gate.HEADER_KEYS
            and all(gate.integer(header[k]) for k in ("rate", "requests", "seed", "slots", "source", "started_unix_ms"))
            and (header["previous"] == "none" or digest(header["previous"]))
            and (header["workload"], header["records"], header["weights"]) == (workload, spec["records"],
                                                                               spec["weights"])):
        raise Refusal(f"the samples header is not the hit gate's header of workload {workload}")
    samples = [gate.parse(line, "a sample") for line in body.split(b"\n")[:-1]]
    fields = (gate.INTENDED, gate.ATTEMPTED, gate.ADMITTED, gate.END, gate.SOURCE)
    if not all(isinstance(s, list) and len(s) == 7 and all(gate.integer(s[k]) for k in fields)
               and gate.integer(s[gate.RECORD], 0, len(spec["records"]) - 1) and s[gate.STRATUM] in gate.STRATA
               and s[gate.INTENDED] <= s[gate.ATTEMPTED] <= s[gate.ADMITTED] <= s[gate.END] for s in samples):
        raise Refusal("a sample is not [intended_us, attempted_us, admitted_us, end_us, record, stratum, source]")
    return header, samples


def per_request(data, workload, policy, qualification, z):
    """Both reader fields' floor-rule summaries of one hit-gate samples file, each with the reasons it credits
    nothing, from one parse. H: the routed owner's hits overall and by size stratum against each quantile's declared
    ceiling of the workload, its outcome counts and the residual owners' counts. The request tail: every original
    request, one tail per outcome against the policy's tail thresholds, with routed and residual counts."""
    header, samples = parse_samples(data, workload, qualification)
    spec = qualification["workloads"][workload]
    buckets = {name: [] for name in gate.STRATA}
    counts = {"routed": dict.fromkeys(gate.STRATA, 0), "residual": dict.fromkeys(gate.STRATA, 0)}
    sizes = {}
    for s in samples:
        stratum, latency = s[gate.STRATUM], gate.latency_us(s)
        buckets[stratum].append(latency)
        routed = s[gate.SOURCE] == header["source"]
        counts["routed" if routed else "residual"][stratum] += 1
        if routed and stratum == "hit":
            sizes.setdefault(str(header["records"][s[gate.RECORD]][0]), []).append(latency)
    for values in (*buckets.values(), *sizes.values()):
        values.sort()
    def reason(errors):
        return [f"the samples format records no timeout or deadline, so {errors} error outcomes cannot be censored "
                "at a deadline"] if errors else []

    edge = {name: None if key is None else gate.microseconds(spec[key]) for name, key in policy["h"]["edge"].items()}
    hits = sorted(v for values in sizes.values() for v in values)
    h = {"strata": counts["routed"], "residual": counts["residual"], "hits": summarize(hits, z, edge),
         "sizes": {size: summarize(v, z, edge) for size, v in sorted(sizes.items())}}
    limits = {name: None if v is None else gate.microseconds(v) for name, v in policy["request_tail_edge_ms"].items()}
    tail = {"strata": {name: len(v) for name, v in buckets.items()}, **counts,
            "tails": {name: summarize(v, z, limits) for name, v in buckets.items()}}
    return {H: (h, reason(counts["routed"]["error"])), TAIL: (tail, reason(len(buckets["error"])))}


def demote(result, reasons):
    """`result` with `reasons` added and its verdict inconclusive, or `handoff` when the gate hands off preservation."""
    return {**result, "reasons": [*result["reasons"], *reasons],
            "verdict": "handoff" if "handoff" in result else "inconclusive"}


def hit_gate(ref, *, commit, hosts, document, manifest_sha256, ids, lane):
    """H's campaign-level verdict from the hit gate's own judgment of the named campaign file, and the samples digests
    it admitted for non-null candidate-arm runs of decided gate cells, each with its run, workload, phase and client
    instance. A gate cell with a role on a host the campaign does not admit binds none of its runs, and a digest that
    another run of the gate's cells also carries binds no cell; each demotes the verdict. The binding rests on the gate
    receipt's contract: a cell key is `workload/phase/permille`, a decided cell lists its admitted runs in
    `gate.schedule` order under the receipt's seed with one identity for every run, and arm B of a non-null block runs
    the candidate; the client role is the interface role whose cases include the qualification's cell, as the gate's
    `admit` takes it."""
    if ref is None:
        return {"verdict": "inconclusive", "reasons": ["the campaign names no hit-gate campaign"]}, {}
    problem, data = evidence_problem(ref, "hit-gate campaign")
    if problem:
        return {"verdict": "inconclusive", "reasons": [problem]}, {}
    receipt = gate.judge(document, manifest_sha256, ids, gate.parse(data, "hit-gate campaign"), lane, ref["sha256"])
    result = {"verdict": receipt["verdict"], "reasons": [], "receipt_sha256": canonical(receipt), "gate": {
        **{k: receipt.get(k) for k in GATE_PROVENANCE},
        "cells": {key: {"verdict": c["verdict"], "reasons": c["reasons"]} for key, c in receipt["cells"].items()}}}
    if "handoff" in receipt:
        result["handoff"] = receipt["handoff"]
    if receipt.get("candidate") != commit:
        return demote(result, ["the hit gate judged another candidate than the commit"]), {}
    q = document["qualification"]
    client = next(role for role, cases in q["interface"]["roles"].items() if q["cell"] in cases)
    by_instance = {host["instance"]: (name, host) for name, host in hosts.items()}
    reasons, bound, carriers = [], {}, {}
    for key, cell in receipt["cells"].items():
        decided = cell["verdict"] in ("pass", "fail")
        if not cell.get("runs"):
            if decided:
                raise Refusal(f"hit-gate cell {key} reads {cell['verdict']} with no admitted runs or identity")
            continue
        for run in cell["runs"]:
            carriers.setdefault(run["samples_sha256"], []).append(f"{key} {run['id']}")
        admitted = True
        for role, value in cell["identity"].items():
            if role in ("toolchain", "dependencies"):
                continue
            name, host = by_instance.get(value["instance"], (None, None))
            if host is None or not host["admitted"]:
                admitted = False
                reasons.append(f"hit-gate cell {key} role {role} ran on instance {value['instance']}, which no "
                               "admitted campaign host names")
            elif role == client and host["clock"] != "trusted":
                reasons.append(f"hit-gate cell {key}'s client host {name} has an untrusted clock")
        if not decided:
            continue
        workload, phase, permille = key.rsplit("/", 2)
        plan = gate.schedule(receipt["seed"], (workload, phase, int(permille)), q["protocol"])
        if len(plan) != len(cell["runs"]):
            raise Refusal(f"hit-gate cell {key} admitted {len(cell['runs'])} runs, not its schedule's {len(plan)}")
        for i, run in enumerate(cell["runs"]):
            _, _, _, arm, null = plan[i]
            if admitted and arm == "B" and not null:
                bound[run["samples_sha256"]] = {"run": run["id"], "workload": workload, "phase": phase,
                                                "client": cell["identity"][client]["instance"]}
    for digest, runs in carriers.items():
        if len(runs) > 1 and bound.pop(digest, None):
            reasons.append(f"hit-gate runs {' and '.join(sorted(runs))} carry the same samples {digest}, so those "
                           "samples bind no cell")
    return (demote(result, reasons) if reasons else result), bound


def platform_problem(row, platforms):
    """Why the platform row `row` credits nothing against the manifest's `platforms`, or None for a supported row
    and for a null one, which its header key names as undeclared."""
    if row is None:
        return None
    if not isinstance(row, str) or row not in platforms:
        return f"platform row {row!r} is not in the manifest"
    return None if platforms[row].get("supported") is True else COLUMNS["hardware"]


def judge_cell(cell, *, term, host, header, envelope, offered, platforms, bound, summarize_samples):
    """One cell's receipt entry: its evidence kind, effective header, degradation, bound run, summary and every
    reason it reads inconclusive. The effective header decides the cell's own reasons: its rate against `offered`,
    the qualification's offered rate or None while that is undeclared, its CPU family against its host's and its
    platform row against `platforms`, the manifest's rows. `summarize_samples(ref, workload)` returns a bound samples
    file's summaries by field."""
    if term is None or cell["class"] not in CLASSES or cell["evidence"] not in EVIDENCE:
        return {"verdict": "inconclusive", "reasons": ["the cell names no frame field, class or evidence kind"]}
    kind = cell["evidence"]
    if kind not in term["evidence"]:
        return {"verdict": "inconclusive", "reasons": [
            f"field {cell['field']} admits no {kind} evidence; a column credits only its own kind"]}
    reasons = [] if host else [f"the cell names an undeclared host {cell['host']!r}"]
    if host and not host["admitted"]:
        reasons.append(f"host {cell['host']} is not admitted")
    degraded = bool(host) and host["clock"] == "untrusted"
    if degraded:
        reasons.append(f"host {cell['host']}'s clock is untrusted, so its cells read degraded")
    applicable = {key: cell.get("header", {}).get(key, header[key]) for key, kinds in HEADER.items() if kind in kinds}
    for key, value in applicable.items():
        if value is None:
            reasons.append(f"header {key} is undeclared for {kind} evidence")
        elif not VALUES[key](value):
            reasons.append(f"header {key} {value!r} is off its type")
        elif envelope.get(key) is not None and value != envelope[key]:
            reasons.append(f"header {key} is not the envelope's {envelope[key]}")
        elif key == "rate" and offered is not None and value != offered:
            reasons.append(f"header rate {value} is not the qualification's offered rate {offered}")
        elif key == "cpu_family" and host and value != host["cpu_family"]:
            reasons.append(f"header cpu_family {value} is not host {cell['host']}'s {host['cpu_family']}")
    entry = {"evidence": kind, "header": applicable, "degraded": degraded, "verdict": "inconclusive"}
    platform = platform_problem(applicable.get("platform_row"), platforms)
    if platform:
        reasons.append(platform)
    if cell["field"] not in READERS:
        return {**entry, "reasons": [*reasons, f"no judge on this revision reads {cell['field']} evidence"]}
    ref = cell.get("samples")
    run = bound.get(ref["sha256"]) if ref else None
    if run is None:
        return {**entry, "reasons": [
            *reasons, "the hit gate admitted these samples for no non-null candidate-arm run of a decided cell"]}
    entry["run"] = {"id": run["run"], "workload": run["workload"]}
    mismatch = [] if cell["stratum"] == run["phase"] else [
        f"the cell's stratum {cell['stratum']} is not hit-gate run {run['run']}'s phase {run['phase']}"]
    if host is None or host["instance"] != run["client"]:
        mismatch.append(f"host {cell['host']} is not hit-gate run {run['run']}'s client instance {run['client']}")
    if mismatch:
        return {**entry, "reasons": [*reasons, *mismatch]}
    summaries, faults = summarize_samples(ref, run["workload"])
    reasons += ["no hit-gate run binds a recovery class, so the cell's class is the campaign's statement",
                "the hit gate's run identity records no platform row or CPU identity, so the cell's are the "
                "campaign's statement"]
    if summaries is not None:
        entry["summary"], more = summaries[cell["field"]]
        reasons += more
    return {**entry, "reasons": [*reasons, *faults]}


def finite(value, zero=False):
    """`value` as a finite float when it is a positive number, or zero when `zero` holds, else None."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        x = float(value)
    except OverflowError:
        return None
    return x if math.isfinite(x) and (x > 0 or zero and x == 0) else None


RESERVATION = "the policy declares no foreground reservation, so the worker slots are measured under none"


def term_drift(name, pair):
    """(why the calibration term `name`'s [start, end] entries hold no drift range, or None; and its section entry
    {start, end, drift, range}). Each entry is {value, uncertainty}: a positive finite value and a non-negative finite
    half-width below the start value. The range runs from max(0, |end - start| - both half-widths) / (start + its
    half-width) to (|end - start| + both half-widths) / (start - its half-width)."""
    read = [(finite(v["value"]), finite(v["uncertainty"], zero=True)) if isinstance(v, dict)
            and set(v) == {"value", "uncertainty"} else (None, None) for v in pair]
    (a, u), (b, w) = read
    if a is None or u is None or b is None or w is None:
        return f"calibration term {name} lacks a positive start or end value with a non-negative uncertainty", None
    if a <= u:
        return f"calibration term {name}'s start uncertainty reaches zero, so its drift is unbounded", None
    drift, low, high = abs(b - a) / a, max(0.0, abs(b - a) - u - w) / (a + u), (abs(b - a) + u + w) / (a - u)
    if not math.isfinite(high):
        return f"calibration term {name}'s drift is no finite number", None
    return None, {"start": pair[0], "end": pair[1], "drift": drift, "range": [low, high]}


def calibrate(calibration, terms, band, reservation, scored, hosts, block_hosts):
    """The C2 calibration section and the drift control's derivation (observed, reasons). Each phase names the host
    it ran on, admitted with a trusted clock, the same at start and end and one of `block_hosts`, the hosts of the
    usable blocks; the same volumes; and its own evidence file, apart from the other phase's and from every scored
    position's: calibration evidence a scored position also names is no measurement apart from scored elapsed time.
    Each frame term needs a positive finite start and end value with a non-negative finite uncertainty, the
    half-width in the term's unit of the interval the driver declares to hold it. A term's relative drift ranges over
    those intervals: at least max(0, |end - start| - both half-widths) / (start + its half-width), at most
    (|end - start| + both half-widths) / (start - its half-width). The control reads `stable` when every term's
    largest drift is at most the statistics' drift band and `drifted` when some term's smallest drift exceeds it; it
    stays unreached (observed None) while a phase, a term or the band is missing or a term's range spans the band.
    The values are the driver's declarations beside a digest check of their evidence files."""
    if calibration is None:
        reasons = ["the campaign holds no calibration"]
        return {"terms": {}, "reasons": reasons}, (None, reasons)
    reasons, out, phases = [], {}, (("start", calibration["start"]), ("end", calibration["end"]))
    for name, phase in phases:
        problem = evidence_problem(phase["evidence"], f"calibration {name} evidence")[0]
        if problem or phase["evidence"]["sha256"] in scored:
            reasons.append(problem or f"the calibration's {name} evidence is a scored position's, so it is not "
                                      "measured apart from scored elapsed time")
        host = hosts.get(phase["host"])
        if not (host and host["admitted"]):
            reasons.append(f"the calibration's {name} host {phase['host']} is no admitted host")
        elif host["clock"] == "untrusted":
            reasons.append(f"the calibration's {name} host {phase['host']} has an untrusted clock, so its rates are "
                           "not measured")
    start, end = calibration["start"], calibration["end"]
    if start["host"] != end["host"]:
        reasons.append("the calibration's start and end ran on different hosts, so their drift compares nothing")
    if start["evidence"]["sha256"] == end["evidence"]["sha256"]:
        reasons.append("the calibration's start and end name one evidence file, so they are one measurement")
    if set(start["volumes"]) != set(end["volumes"]):
        reasons.append("the calibration's start and end measured different volumes, so their drift compares nothing")
    if not block_hosts:
        reasons.append("the campaign holds no usable block, so the calibration's drift describes no scored host")
    elif start["host"] not in block_hosts:
        reasons.append(f"the calibration host {start['host']} ran no usable block, so its drift describes no scored "
                       "host")
    for name in terms:
        pair = [phase["values"].get(name) for _, phase in phases]
        problem, entry = term_drift(name, pair)
        if problem:
            reasons.append(problem)
            continue
        out[name] = entry
    section = {"terms": out, "reasons": [*reasons, *([] if reservation is not None else [RESERVATION])]}
    if reasons or band is None:
        return section, (None, reasons or ["the statistics version declares no drift band"])
    if any(term["range"][0] > band for term in out.values()):
        return section, ("drifted", [])
    if spanned := [name for name, term in out.items() if term["range"][1] > band]:
        return section, (None, [f"the uncertainty of calibration terms {spanned} spans the drift band"])
    return section, ("stable", [])


def observation(value, direction):
    """One position value as (signed log interval, value, censored), or None for a value that is neither a positive
    finite number nor {"censored": such a number}. The signed log is positive-worse in `direction`; a censored value
    is known only to be worse than recorded, so its interval is unbounded on the worse side."""
    censored = isinstance(value, dict) and set(value) == {"censored"}
    x = finite(value["censored"] if censored else value)
    if x is None:
        return None
    s = math.log(x) if direction == "lower" else -math.log(x)
    return (s, math.inf if censored else s), x, censored


def block_contrast(block, member, at, direction):
    """One block's paired log contrast interval for `member` at level `at` (None for a member without levels), its
    exact arm A values and whether any position is censored, or None when a position holds no usable value."""
    sides, values, censored = {"A": [], "B": []}, [], False
    for position in block["positions"]:
        value = position["outcomes"].get(member)
        if at is not None:
            value = value.get(str(at)) if isinstance(value, dict) else None
        seen = observation(value, direction)
        if seen is None:
            return None
        interval, x, cut = seen
        sides[position["arm"]].append(interval)
        censored = censored or cut
        if position["arm"] == "A" and not cut:
            values.append(x)
    low = (sum(lo for lo, _ in sides["B"]) - sum(hi for _, hi in sides["A"])) / 2
    high = (sum(hi for _, hi in sides["B"]) - sum(lo for lo, _ in sides["A"])) / 2
    return (low, high), values, censored


def order_rank(n, tail):
    """The order-statistic rank of n contrasts at `tail`: the largest k with P(Binomial(n, 1/2) < k) <= tail, or 0
    when no k exists, read off `ranks`."""
    return next(reversed([k for _, k in ranks(tail, n)]), 0)


def order_bound(intervals, tail):
    """The order-statistic bound [low, high] on the median of contrasts given as (low, high) intervals: the k-th
    smallest low and k-th largest high, k the `order_rank` of their count. A side is None where no such k exists or
    the order statistic is a censored side's infinity."""
    k = order_rank(len(intervals), tail)
    if k == 0:
        return [None, None]
    low = sorted(lo for lo, _ in intervals)[k - 1]
    high = sorted((hi for _, hi in intervals), reverse=True)[k - 1]
    return [low if math.isfinite(low) else None, high if math.isfinite(high) else None]


def ranks(tail, limit):
    """(n, `order_rank(n, tail)`) for n from 1 to `limit`, each carried from the one before: with S(n, k) the sum of
    C(n, i) over i < k, S(n + 1, k) = 2 S(n, k) - C(n, k - 1), and the rank never falls as n grows."""
    room, k, total, below, at = Fraction(tail), 0, 0, 0, 1
    for n in range(1, limit + 1):
        prior = below * (k - 1) // (n - k + 1) if k >= 2 else 0
        total = 2 * total - below
        below, at = below + prior, at + below
        while k < n and total + at <= room * 2 ** n:
            total += at
            below, at = at, at * (n - k) // (k + 1)
            k += 1
        yield n, k


def sign_power(n, k, q):
    """P(Binomial(n, q) < k): the chance that fewer than k of n contrasts exceed the tolerance when each does with
    probability q, which is the chance that the k-th largest contrast is at most the tolerance."""
    if q <= 0:
        return 1.0 if k > 0 else 0.0
    step, term, total = math.log(q) - math.log1p(-q), n * math.log1p(-q), 0.0
    for i in range(k):
        total += math.exp(term)
        term += math.log(n - i) - math.log(i + 1) + step
    return min(total, 1.0)


def floor_powers(tail, q, limit):
    """(n, k, P(Binomial(n, q) < k)) for n from 1 to `limit`, k the order rank `ranks` carries, each probability
    carried from the one before: with X_n ~ Binomial(n, q), P(X_n < k) = P(X_{n-1} < k) - q P(X_{n-1} = k - 1), and
    each step of the rank adds P(X_n = j). Every step evaluates a constant number of point masses, so the scan is
    linear in `limit`; `sign_power` sums the same probability term by term for one n."""
    if q <= 0:
        yield from ((n, k, 1.0 if k > 0 else 0.0) for n, k in ranks(tail, limit))
        return
    log_q, log_p = math.log(q), math.log1p(-q)

    def mass(n, j):
        return math.exp(math.lgamma(n + 1) - math.lgamma(j + 1) - math.lgamma(n - j + 1) + j * log_q
                        + (n - j) * log_p)

    below, k = 0.0, 0
    for n, rank in ranks(tail, limit):
        if k:
            below -= q * mass(n - 1, k - 1)
        for j in range(k, rank):
            below += mass(n, j)
        k = rank
        yield n, k, min(max(below, 0.0), 1.0)


def exceedance(s, tolerance):
    """The chance that a normal contrast of median zero and standard deviation `s` exceeds `tolerance`."""
    return 0.0 if s == 0 else 1 - NormalDist().cdf(tolerance / s)


def pilot_floor(tail, power, s, tolerance):
    """The fewest held-out blocks whose order bound's upper side is at most `tolerance` with probability `power`
    when the contrasts are normal with median zero and standard deviation `s`: the least n up to MAX_CELLS, or None
    when none reaches it. A contrast past the tolerance with probability q of at least 1/2 leaves the power at most
    the per-tail level, since P(Binomial(n, q) < k) <= P(Binomial(n, 1/2) < k) <= tail."""
    q = exceedance(s, tolerance)
    if q >= 0.5 and power > tail:
        return None
    return next((n for n, k, reach in floor_powers(tail, q, MAX_CELLS) if k and reach >= power), None)


def tolerance_of(effect, center, direction):
    """The log contrast the smallest effect makes against the pilot's arm A median `center`: ln(1 + effect / center)
    for a lower-is-better member and -ln(1 - effect / center) for a higher-is-better one; None when that is no finite
    positive number, as for an effect at or past a higher-is-better median."""
    try:
        ratio = effect / center
        value = math.log1p(ratio) if direction == "lower" else -math.log1p(-ratio)
    except (ArithmeticError, ValueError):
        return None
    return value if math.isfinite(value) and value > 0 else None


def timed(unit):
    """Whether a value in `unit` may be read off a clock: every unit except the frame's own untimed units, so a
    normalized policy unit such as a rate per millisecond counts as clocked."""
    return unit not in UNITS - TIMING


def member_keys(frame, cls, contrast):
    """The bound keys every stratum of class `cls` holds under `contrast`: each block-read family member, one key per
    level of a member with levels, without the warm-only members where an arm runs the cold class, which retains no
    hit and holds no restored capacity: on the cold class, and on every class of a class contrast, whose arm A is the
    cold control."""
    fields = frame["fields"]
    cold = cls == COLD or contrast == "class"
    return [member if at is None else f"{member}/{at}" for member in FAMILY if member not in READERS
            and not (cold and member in WARM_ONLY) for at in fields[member].get("levels") or [None]]


def outcome_keys(fields, outcomes):
    """The bound keys a position's `outcomes` table names, in `member_keys` form: `member/level` for each level key
    of a member whose field declares levels and whose value is a level table, the member name otherwise."""
    keys = set()
    for member, value in outcomes.items():
        if fields.get(member, {}).get("levels") and isinstance(value, dict):
            keys.update(f"{member}/{at}" for at in value)
        else:
            keys.add(member)
    return keys


def inputs(member, policy):
    """The reasons the policy's open inputs keep `member`'s bound from deciding: F's percentile, and the readiness
    band and window that define sustained fill readiness."""
    if member == F and policy["f"]["percentile"] is None:
        return ["the policy declares no F percentile, so fill_latency's measured value is undefined"]
    if member == "sustained_fill_readiness":
        return [f"the policy declares no readiness {key}, so sustained fill readiness is undefined"
                for key in ("fill_band", "fill_window_s") if policy["readiness"][key] is None]
    return []


def member_bound(sets, member, at, field, row, tail, *, horizon, supplied, power, name, shared):
    """One stratum's bound entry on `member` at level `at`: the usable contrast count per set, the held-out bound,
    the A/A bound, the pilot's tolerance and floor and every reason the bound decides nothing. `supplied` counts the
    stratum's held-out blocks, `name` labels it and `shared` holds its stratum-wide reasons. A degraded block (an
    untrusted clock) holds no value read off a clock."""
    contrasts, values, censored = {kind: [] for kind in SETS}, [], False
    clocked = timed(field["unit"]) or timed(row["unit"])
    for kind in SETS:
        for block, degraded in sets.get(kind, []):
            seen = None if degraded and clocked else block_contrast(block, member, at, field["direction"])
            if seen is not None:
                contrasts[kind].append(seen[0])
                if kind == "pilot":
                    values += seen[1]
                    censored = censored or seen[2]
    reasons, tolerance, floor, held = list(shared), None, None, contrasts["held-out"]
    short = [kind for kind in ("null", "pilot") if len(contrasts[kind]) < len(sets.get(kind, []))]
    reasons += [f"{len(contrasts[kind])} of the {len(sets[kind])} usable {kind} blocks hold a usable value"
                for kind in short]
    if horizon is None:
        reasons.append("the statistics version declares no horizon block count")
    elif supplied != horizon:
        reasons.append(f"{name} holds {supplied} held-out blocks, not the fixed horizon's {horizon}")
    elif len(held) < horizon:
        reasons.append(f"{len(held)} of the fixed horizon's {horizon} held-out blocks hold a usable value")
    effect = row["smallest_effect"]
    if effect is None:
        reasons.append(f"the policy declares no smallest effect for {member}, so its bound is unscored")
    elif censored:
        reasons.append("a censored pilot value leaves the tolerance and the floor unsized")
    elif not values:
        reasons.append("no exact pilot arm A value sets the tolerance")
    else:
        tolerance = tolerance_of(effect, median(values), field["direction"])
        if tolerance is None:
            reasons.append(f"the smallest effect {effect} makes no finite positive tolerance against the pilot's "
                           f"arm A median {median(values)}")
    pilot = contrasts["pilot"]
    if not censored and len(pilot) < 2:
        reasons.append("fewer than two exact pilot contrasts size the floor")
    elif tolerance is not None:
        s = stdev([lo for lo, _ in pilot])
        floor = pilot_floor(tail, power, s, tolerance)
        if floor is None:
            reasons.append(f"no horizon up to {MAX_CELLS} blocks reaches the power")
        elif horizon is not None and floor > horizon:
            reasons.append(f"the fixed horizon of {horizon} blocks is under the pilot floor of {floor}")
        elif horizon is not None and (reach := sign_power(horizon, order_rank(horizon, tail),
                                                          exceedance(s, tolerance))) < power:
            reasons.append(f"the fixed horizon of {horizon} blocks reaches a planning power of {reach:.4g}, under "
                           f"the declared {power}")
    aa = None if not contrasts["null"] else [None, None] if "null" in short else order_bound(contrasts["null"], tail)
    return {"blocks": {kind: len(v) for kind, v in contrasts.items()}, "bound": order_bound(held, tail),
            "aa": aa, "tolerance": tolerance,
            "floor": floor, "reasons": reasons}


def decide(entry):
    """A bound entry's verdict: UNACCEPTABLE_REGRESSION when its lower bound exceeds its tolerance, PASS when its
    upper bound is at most it, INCONCLUSIVE otherwise or while the entry holds a reason."""
    low, high = entry["bound"]
    if entry["reasons"] or entry["tolerance"] is None:
        return UNDECIDED
    if low is not None and low > entry["tolerance"]:
        return REGRESSION
    return PASS if high is not None and high <= entry["tolerance"] else UNDECIDED


def bound_entries(bounds):
    """Each bound entry of a comparison under its `class/posture/member` key."""
    return {f"{cls}/{posture}/{key}": entry for cls, postures in bounds.items() for posture, rows in postures.items()
            for key, entry in rows.items()}


def aa_control(bounds):
    """The A/A control's derivation (observed, reasons) from the bound entries: `not-null` when any A/A bound
    excludes zero; unreached while an entry with held-out contrasts holds no A/A bound, an A/A bound is unbounded, or
    an entry with held-out contrasts holds an A/A bound reaching past its tolerance or no tolerance; `null` when every
    A/A bound covers zero within that band."""
    table = bound_entries(bounds)
    aa = {key: e["aa"] for key, e in table.items() if e["aa"] is not None}
    if any(low is not None and low > 0 or high is not None and high < 0 for low, high in aa.values()):
        return "not-null", []
    if not aa:
        return None, ["the campaign holds no A/A null block with a usable value"]
    absent = [key for key, e in table.items() if e["aa"] is None and e["blocks"]["held-out"]]
    unbounded = [key for key, (low, high) in aa.items() if low is None or high is None]
    wide = [key for key, (low, high) in aa.items() if key not in unbounded and table[key]["blocks"]["held-out"]
            and (table[key]["tolerance"] is None or low < -table[key]["tolerance"] or high > table[key]["tolerance"])]
    reasons = [*([f"the entries {absent} hold held-out contrasts but no A/A contrast"] if absent else []),
               *([f"the A/A bounds on {unbounded} are unbounded"] if unbounded else []),
               *([f"the A/A bounds on {wide} reach past their tolerance or hold none"] if wide else [])]
    return (None, reasons) if reasons else ("null", [])


def measure(campaign, *, seed, hosts, frame, statistics, policy):
    """The comparison section of a campaign that declares a contrast, and the derived A/A and calibration-drift
    controls as {name: (observed, reasons)}. Blocks group by class, posture and set; each block's order must be slots
    4i to 4i + 3 of `gate.schedule(seed, (set, class, posture), {null_blocks: 0, blocks: n, repeats: 1})`, i its index
    among the n blocks the campaign lists for its group, its positions one run per slot of that order, its hosts
    admitted, and its run identities and evidence files carried by no other position; every block carrying a
    repeated run or file is missing. A class and posture whose blocks run on more than one host set pools host strata,
    so none of its bounds decides. Every member of `member_keys` takes one bound per class, posture and level at
    familywise_alpha / (2 m L S) per tail, S the declared comparison strata, or the listed ones while none are
    declared. A revision contrast whose baseline is the campaign's own {commit, patch_sha256} runs one build as both
    arms, which is a reason of the section."""
    blocks, reasons, groups, usable = campaign.get("blocks", []), [], {}, {}
    if campaign.get("baseline") == campaign["revision"]:
        reasons.append("the baseline is the campaign's own revision, so both arms run one build and no bound is a "
                       "revision effect")
    runs, files = {}, {}
    for position in (p for block in blocks for p in block["positions"]):
        runs[position["run"]] = runs.get(position["run"], 0) + 1
        files[position["evidence"]["sha256"]] = files.get(position["evidence"]["sha256"], 0) + 1
    for block in blocks:
        groups.setdefault((block["class"], block["posture"], block["set"]), []).append(block)
    for (cls, posture, kind), group in sorted(groups.items()):
        plan = gate.schedule(seed, (kind, cls, posture), {"null_blocks": 0, "blocks": len(group), "repeats": 1})
        for i, block in enumerate(group):
            name, faults = f"{kind} block {i} of {cls}/{posture}", []
            order = "".join(p[3] for p in plan[4 * i:4 * i + 4])
            if cls not in CLASSES:
                faults.append(f"{name} names no class")
            elif campaign["contrast"] == "class" and kind != "null" and cls == COLD:
                faults.append(f"{name} runs the cold control as arm B, which a class contrast keeps for a treatment")
            if block["order"] != order:
                faults.append(f"{name} runs {block['order']}, not its seeded order {order}")
            if "".join(p["arm"] for p in block["positions"]) != block["order"]:
                faults.append(f"{name} is incomplete: its positions are not one run per slot of its order")
            faults += [f"{name} ran on {h}, which is no admitted host" for h in block["hosts"]
                       if not hosts.get(h, {}).get("admitted")]
            for position in block["positions"]:
                run, ref = position["run"], position["evidence"]
                if runs[run] > 1:
                    faults.append(f"{name} carries run {run}, which another position also names; a stopped run is "
                                  "missing, never retried")
                if files[ref["sha256"]] > 1:
                    faults.append(f"{name} run {run} names evidence another position also names")
                problem = evidence_problem(ref, f"{name} run {run} evidence")[0]
                faults += [problem] if problem else []
            reasons += faults
            if not faults:
                degraded = any(hosts[h]["clock"] == "untrusted" for h in block["hosts"])
                usable.setdefault((cls, posture), {}).setdefault(kind, []).append((block, degraded))
    reads, named = {}, set()
    for block in blocks:
        if block["class"] not in reads:
            reads[block["class"]] = set(member_keys(frame, block["class"], campaign["contrast"]))
        for position in block["positions"]:
            named |= outcome_keys(frame["fields"], position["outcomes"]) - reads[block["class"]]
    if extra := sorted(named):
        reasons.append(f"block positions name {extra}, which no block contrast reads")
    block_hosts = {h for stratum in usable.values() for kind in stratum.values() for block, _ in kind
                   for h in block["hosts"]}
    calibration, drift = calibrate(campaign.get("calibration"), frame["calibration"], statistics["drift_band"],
                                   policy["foreground_reservation"], set(files), hosts, block_hosts)
    horizon, power = statistics["horizon"]["blocks"], statistics["power"]["value"]
    strata = sorted({(cls, posture) for cls, posture, _ in groups if cls in CLASSES})
    declared = statistics["comparison_strata"]
    listed = [f"{cls}/{posture}" for cls, posture in strata]
    family = ["the statistics version declares no comparison strata, so the per-tail level has no fixed family"
              ] if declared is None else [] if sorted(declared) == listed else [
        f"the campaign's strata {listed} are not the declared comparison strata {sorted(declared)}"]
    tail = level(statistics, policy)[1] / max(1, len(declared or strata))
    bounds = {}
    for cls, posture in strata:
        name = f"{cls}/{posture}"
        sets = usable.get((cls, posture), {})
        pools = {frozenset(block["hosts"]) for kind in sets.values() for block, _ in kind}
        pooled = [f"{name}'s blocks run on {len(pools)} host sets, so its bounds would pool host strata"] if len(
            pools) > 1 else []
        supplied = len(groups.get((cls, posture, "held-out"), []))
        rows = bounds.setdefault(cls, {}).setdefault(posture, {})
        for key in member_keys(frame, cls, campaign["contrast"]):
            member, _, at = key.partition("/")
            field = frame["fields"][member]
            rows[key] = member_bound(sets, member, at or None, field, policy["outcomes"][member],
                                     tail / len(field.get("levels") or [None]), horizon=horizon, supplied=supplied,
                                     power=power, name=name, shared=[*family, *pooled, *inputs(member, policy)])
    section = {"contrast": campaign["contrast"], "revision": campaign["revision"],
               "baseline": campaign.get("baseline"),
               "blocks": {f"{c}/{p}/{k}": len(g) for (c, p, k), g in sorted(groups.items())},
               "calibration": calibration, "bounds": bounds, "reasons": reasons}
    return section, {"aa": aa_control(bounds), "calibration-drift": drift}


def authority_gaps(campaign, policy, hosts):
    """Why the campaign's AWS safety manifest or its approval falls short: the hit gate's safety gaps over the
    campaign's host instances and the volumes its blocks and calibration name, then the policy's campaign authority
    against the manifest's budget and host hours. The volumes are the campaign's declarations."""
    safety, authority = campaign.get("safety"), policy["campaign_authority"]
    calibration = campaign.get("calibration") or {}
    bound = {host["instance"] for host in hosts.values()} | {
        volume for block in campaign.get("blocks", []) for volume in block["volumes"]} | {
        volume for phase in calibration.values() for volume in phase["volumes"]}
    gaps = gate.safety_gaps(safety, campaign.get("campaign"), bound)
    if authority is None:
        return [*gaps, "the policy names no campaign authority, so no budget or host-hour limit approves the campaign"]
    for key in ("budget_usd", "host_hours"):
        stated = safety.get(key) if isinstance(safety, dict) else None
        if not gate.positive(stated) or stated > authority[key]:
            gaps.append(f"the safety manifest's {key} {stated!r} is not within the campaign authority's "
                        f"{authority[key]}")
    return gaps


def cited(target):
    """The campaign artifact and cell a revision contrast's target cites, and why the citation does not resolve: the
    file must be its SHA-256's bytes and a measurement-frame receipt whose campaign SHA-256 is a digest and whose
    cells hold the cell as a judged entry, its key IDENTITY values naming the receipt's campaign id, a class, a field
    and a stratum. These checks fix the cited file's shape; they authenticate no campaign behind it."""
    if target is None:
        return None, "the revision contrast cites no campaign artifact and cell"
    problem, data = evidence_problem(target["receipt"], "target receipt")
    if problem:
        return None, problem
    try:
        receipt = gate.parse(data, "the target receipt")
    except Refusal as error:
        return None, str(error)
    if not (isinstance(receipt, dict) and receipt.get("envelope") == ENVELOPE
            and digest(receipt.get("campaign_sha256")) and isinstance(receipt.get("cells"), dict)):
        return None, "the target receipt is no measurement-frame receipt with a campaign SHA-256 and cells"
    if target["cell"] not in receipt["cells"]:
        return None, f"the target receipt holds no cell {target['cell']}"
    entry, named = receipt["cells"][target["cell"]], identity_values(target["cell"])
    if not (named and text(named["class"]) and named["class"] in CLASSES and text(named["field"])
            and text(named["stratum"])):
        return None, f"the target cell {target['cell']} is no cell identity"
    if not (isinstance(entry, dict) and entry.get("verdict") in VERDICT_NAMES):
        return None, f"the target receipt holds no judged entry for cell {target['cell']}"
    if named["campaign"] != receipt.get("campaign"):
        return None, f"the target cell names campaign {named['campaign']}, not the receipt's {receipt.get('campaign')}"
    return {"campaign_sha256": receipt["campaign_sha256"], "receipt_sha256": target["receipt"]["sha256"],
            "cell": target["cell"], "class": named["class"], "field": named["field"],
            "stratum": named["stratum"]}, None


def identity_values(key):
    """A cell key's IDENTITY values by name; an empty table for a key that is no JSON array of one value per name."""
    try:
        named = json.loads(key)
    except (ValueError, RecursionError):
        return {}
    if not (isinstance(named, list) and len(named) == len(IDENTITY)):
        return {}
    return {name: named[i] for i, name in enumerate(IDENTITY)}


def reader_verdicts(h, baseline, candidate):
    """H's and the request tail's bound verdicts with the reasons each holds none. H takes the hit gate's own verdict
    `h` when the gate judged the baseline as its main revision and neither the baseline nor the candidate is patched,
    since the hit gate builds only an unmodified tree; the request tail takes none, since the hit gate bounds hit
    latency alone."""
    gate_main, reasons = h.get("gate", {}).get("main"), []
    if gate_main is not None and gate_main != baseline["commit"]:
        reasons.append("the hit gate judged another main revision than the baseline, so H takes no bound verdict")
    reasons += [f"the {role} is patched and the hit gate builds only an unmodified tree, so H takes no bound verdict"
                for role, revision in (("baseline", baseline), ("candidate", candidate))
                if revision["patch_sha256"] != NO_PATCH]
    decided = gate_main is not None and not reasons
    hit = {"pass": PASS, "fail": REGRESSION}.get(h["verdict"], UNDECIDED) if decided else UNDECIDED
    if hit == UNDECIDED and not reasons:
        reasons.append(f"the hit gate reads {h['verdict']}, so H holds no decided bound")
    reasons.append("no judge on this revision bounds the request tail between the baseline and the candidate, the hit "
                   "gate bounding hit latency alone")
    return {H: hit, TAIL: UNDECIDED}, reasons


def improvement(bounds, target):
    """Why the cited target's member shows no improvement: every bound entry of the target's class on its field,
    each level included, must hold an upper bound below zero, under the target's posture when its stratum names one
    and under every bounded posture otherwise."""
    if target is None:
        return []
    postures = bounds.get(target["class"], {})
    if target["stratum"] in gate.PHASES:
        postures = {target["stratum"]: postures[target["stratum"]]} if target["stratum"] in postures else {}
    rows = [e for posture in postures.values() for key, e in posture.items()
            if key.partition("/")[0] == target["field"]]
    if not rows:
        return [f"no bound covers the target's {target['field']} on {target['class']}/{target['stratum']}, so no "
                "improvement is measured"]
    if not all(e["bound"][1] is not None and e["bound"][1] < 0 for e in rows):
        return [f"the target's {target['field']} on {target['class']} holds no upper bound below zero, so the "
                "candidate shows no measured improvement"]
    return []


def bound_verdict(section, *, h, validity, uncredited, statistics, frame, target):
    """A revision contrast's result-to-ticket section. PASS only when `validity` and `uncredited` are empty, alpha
    and power are accepted, every stratum holds every member key and every member passes, and the cited target's
    member improves; UNACCEPTABLE_REGRESSION when `validity` is empty, every stratum is complete and any member
    regresses; INCONCLUSIVE otherwise, which merges as no performance change. `h` is the hit gate's own result, before
    the receipt demotes it for the campaign's faults: `validity` already holds every fault that withholds a
    regression, and `uncredited` holds the reasons that withhold credit but no regression."""
    readers, gaps = reader_verdicts(h, section["baseline"], section["revision"])
    members = {**{key: decide(e) for key, e in bound_entries(section["bounds"]).items()}, **readers}
    incomplete = [f"{cls}/{posture} holds bounds on {sorted(rows)}, not on {keys}"
                  for cls, postures in section["bounds"].items()
                  for keys in [sorted(member_keys(frame, cls, section["contrast"]))]
                  for posture, rows in postures.items() if sorted(rows) != keys]
    accepted = all(statistics[name]["status"] == "accepted" for name in PROVISIONAL)
    withheld = [*uncredited, *improvement(section["bounds"], target),
                *([] if accepted else ["alpha or power is provisional, so a passing bound is discovery, not powered "
                                       "confirmation"]),
                *([] if section["bounds"] else ["no stratum holds a bound"])]
    if validity or incomplete:
        verdict = UNDECIDED
    elif REGRESSION in members.values():
        verdict = REGRESSION
    else:
        verdict = PASS if not withheld and set(members.values()) == {PASS} else UNDECIDED
    return {"target": target, "verdict": verdict, "merges": verdict == PASS, "members": members,
            "requalification": frame["comparison"]["requalification"], "frozen": frame["comparison"]["frozen"],
            "reasons": [*validity, *incomplete, *gaps, *withheld]}


def columns(frame, header, cells, platforms):
    """The four evidence columns: each one's conditional header, the label that keeps it unscored (the hardware
    column's while the header's platform row or any hardware cell's effective row is null or no supported manifest
    row, the store column's always) and one row per class and required field/stratum, limited to the row's classes,
    `unrun` until a cell of that kind fills it with the worst of its cells' verdicts. A cell outside the required
    rows fills none; it stays in the receipt's cells. A row folds every N_max column and host of its cells."""
    terms, required, only = {**frame["fields"], **frame["stages"]}, frame["comparison"]["cells"], frame[
        "comparison"]["row_classes"]
    platform_rows = [header.get("platform_row"), *(cell["header"].get("platform_row") for cell in cells.values()
                                                   if cell.get("evidence") == "hardware" and "header" in cell)]
    supported = all(row is not None and platform_problem(row, platforms) is None for row in platform_rows)
    out = {kind: {"header": {key: header[key] for key, kinds in HEADER.items() if kind in kinds},
                  "label": COLUMNS.get(kind) if kind == "store" or kind == "hardware" and not supported else None,
                  "rows": {cls: {f"{name}/{s}": "unrun" for name, strata in required.items()
                                 if kind in terms[name]["evidence"] and cls in only.get(name, CLASSES)
                                 for s in strata} for cls in CLASSES}}
           for kind in EVIDENCE}
    for identity, cell in cells.items():
        values = identity_values(identity)
        rows = out.get(values["evidence"], {}).get("rows", {}).get(values["class"], {})
        key = f"{values['field']}/{values['stratum']}"
        if key in rows:
            rows[key] = cell["verdict"] if rows[key] == "unrun" else gate.worst([rows[key], cell["verdict"]])
    return out


DECLARED = ("the block outcomes and calibration values are the campaign driver's declarations, which no judge on this "
            "revision derives from their evidence")


def frame_gaps(frame):
    """Why the frame's open inputs withhold credit from a bound: each envelope value and the population manifest it
    leaves null, which keep the header and workload of the blocks unfrozen."""
    return [*(f"the envelope declares no {key}, so the blocks' header is unfrozen" for key, value in
              frame["envelope"].items() if value is None),
            *(["the frame names no frozen population manifest, so the blocks' workload is unfrozen"]
              if frame["population"]["manifest"] is None else [])]


def hardware_gaps(header, platforms):
    """Why the campaign header keeps every hardware block from deciding: a hardware header key it leaves null, and
    a platform row that is no supported manifest row."""
    gaps = [f"header {key} is undeclared for hardware evidence, so no block bound decides" for key, kinds in
            HEADER.items() if "hardware" in kinds and header[key] is None]
    problem = platform_problem(header["platform_row"], platforms)
    return [*gaps, *([f"{problem}, so no block bound decides"] if problem else [])]


def registration(campaign):
    """Why the campaign's commit does not show that the records it names preceded its runs, as reasons."""
    commit = campaign["revision"]["commit"]
    try:
        held = {kind: git_show(commit, f"{RECORDS_PATH}/{kind}.json") for kind in KINDS}
    except Refusal as error:
        return [f"{error}, so nothing shows the records preceded the runs"]
    return [f"commit {commit} does not hold {kind} version {campaign[kind]['version']}, so nothing shows it preceded "
            "the runs" for kind, data in held.items()
            if data is None or hashlib.sha256(data).hexdigest() != campaign[kind]["sha256"]]


def report(records, log, campaign, campaign_sha256, *, document, manifest_sha256, ids, lane):
    """The report receipt of `campaign` under the committed records and the manifest `document`."""
    frame, statistics, policy = (records[kind][0] for kind in KINDS)
    qualification = document["qualification"]
    open_items = check(records, log, qualification)
    check_shape(campaign)
    receipt = {"envelope": ENVELOPE, **{kind: campaign.get(kind) for kind in KINDS},
               "records": {kind: pin(records, kind) for kind in KINDS}, "manifest_sha256": manifest_sha256,
               "campaign_sha256": campaign_sha256,
               "judge_sha256": hashlib.sha256(gate.read_file(__file__, "judge")).hexdigest(),
               "campaign": campaign.get("campaign"), "open": open_items, "reasons": []}
    for kind in KINDS:
        named = campaign.get(kind)
        if named is not None and named not in log[kind]:
            raise Refusal(f"the campaign names {kind} {named}, which the revision log does not hold")
    if campaign.get("policy") is None:
        return {**receipt, "verdict": "exploratory",
                "reasons": ["the campaign names no policy version, so it counts for nothing"]}
    if any(campaign.get(kind) is None for kind in KINDS) or "revision" not in campaign:
        raise Refusal("a campaign naming a policy names no frame, statistics or revision")
    contrast = campaign.get("contrast")
    if ("baseline" in campaign) != (contrast == "revision") or "target" in campaign and contrast != "revision":
        raise Refusal("a revision contrast names a baseline and may cite a target; no other campaign names either")
    if contrast is None and {"blocks", "calibration", "safety"} & set(campaign):
        raise Refusal("blocks, a calibration and a safety manifest belong to a campaign that declares a contrast")
    registered = registration(campaign)
    commit, patch = campaign["revision"]["commit"], campaign["revision"]["patch_sha256"]
    expected = campaign_id({kind: (None, campaign[kind]["sha256"]) for kind in KINDS}, commit, patch,
                           campaign.get("baseline"))
    provenance = registered + ([f"the campaign id is not {expected}, the one its records and revision derive"]
                               if campaign.get("campaign") != expected else [])
    if campaign["policy"] != pin(records, "policy"):
        if not registered:
            held = gate.parse(git_show(commit, f"{RECORDS_PATH}/policy.json"), "the campaign's policy record")
            if not isinstance(held, dict) or (held.get("frame"), held.get("statistics")) != (
                    campaign["frame"], campaign["statistics"]):
                raise Refusal("the campaign names another frame or statistics version than its policy")
        if provenance:
            return {**receipt, "verdict": "inconclusive", "reasons": provenance}
        return {**receipt, "verdict": "retained", "reasons": [
            f"the campaign is registered under policy version {campaign['policy']['version']}, its commit holding "
            f"the records it names; policy version {policy['version']} does not re-judge it, and this receipt "
            "establishes no verdict for it: whether it was judged, and with what verdict, is for a receipt issued "
            "under its own version to show"]}
    if (campaign["frame"], campaign["statistics"]) != (pin(records, "frame"), pin(records, "statistics")):
        raise Refusal("the campaign names another frame or statistics version than its policy")
    header = campaign.get("header")
    if not (isinstance(header, dict) and set(header) == set(HEADER)):
        raise Refusal(f"the campaign header keys are not {sorted(HEADER)}")
    faults = [f"header {key} {value!r} is off its type" for key, value in header.items()
              if value is not None and not VALUES[key](value)]
    faults += [f"header {key} is not the envelope's {value}" for key, value in frame["envelope"].items()
               if value is not None and header[key] is not None and header[key] != value]
    offered = qualification["offered_rate"]
    if offered is not None and header["rate"] is not None and header["rate"] != offered:
        faults.append(f"header rate {header['rate']} is not the qualification's offered rate {offered}")
    hosts = admit_hosts(campaign.get("hosts", []), header["cpu_family"])
    section, derived = measure(campaign, seed=expected, hosts=hosts, frame=frame, statistics=statistics,
                               policy=policy) if contrast else (None, {
                                   name: (None, ["the campaign declares no contrast"]) for name in DERIVED})
    controls, unjudged = [], []
    for name, expected_outcome in CONTROLS.items():
        control = campaign.get("controls", {}).get(name)
        if name in derived:
            observed, why = derived[name]
            if observed is None:
                controls.append(f"control {name} is unreached: {'; '.join(why)}")
            elif observed != expected_outcome:
                controls.append(f"control {name} derived {observed!r}, not its declared {expected_outcome!r}")
            else:
                unjudged.append(f"control {name} derived {expected_outcome!r} from values the campaign driver "
                                "declares, which no judge on this revision derives from their evidence")
                controls.append(unjudged[-1])
            continue
        if control is None:
            controls.append(f"control {name} is unrun")
            continue
        problem = evidence_problem(control["evidence"], f"control {name} evidence")[0]
        if problem:
            controls.append(problem)
        elif control["observed"] != expected_outcome:
            controls.append(f"control {name} observed {control['observed']!r}, not its declared {expected_outcome!r}")
        else:
            unjudged.append(f"control {name} reports {expected_outcome!r}, but no judge on this revision derives its "
                            "outcome from its evidence")
            controls.append(unjudged[-1])
    faults += controls
    receipt["reasons"] = reasons = [*provenance, *faults]
    _, _, z = level(statistics, policy)
    h, bound = hit_gate(campaign.get("hit_gate"), commit=commit, hosts=hosts, document=document,
                        manifest_sha256=manifest_sha256, ids=ids, lane=lane)
    gate_result = h
    if provenance:
        h, bound = demote(h, ["the campaign's registration or id is unestablished, so the hit gate's samples bind "
                              "nothing and its verdict decides nothing"]), {}
    elif faults:
        h = demote(h, ["the campaign's header or controls are unestablished, so the hit gate's verdict decides "
                       "nothing"])
    if campaign.get("hit_gate") is not None and patch != NO_PATCH:
        h, bound = demote(h, ["the hit gate's lane admits only an unmodified tree of the commit, so no gate run is a "
                              f"build of patch {patch}; an unpatched campaign declares {NO_PATCH}"]), {}
    terms, cache = {**frame["fields"], **frame["stages"]}, {}

    def summarize_samples(ref, workload):
        problem, data = evidence_problem(ref, "cell samples")
        if problem:
            return None, [problem]
        if ref["sha256"] not in cache:
            try:
                cache[ref["sha256"]] = (per_request(data, workload, policy, qualification, z), [])
            except gate.FAULTS as error:
                cache[ref["sha256"]] = (None, [f"{type(error).__name__}: {error}"])
        return cache[ref["sha256"]]

    receipt["cells"] = {}
    for cell in campaign.get("cells", []):
        values = {"campaign": expected, "commit": commit, "patch_sha256": patch,
                  "cpu_family": hosts.get(cell["host"], {}).get("cpu_family", "undeclared"),
                  **{k: cell[k] for k in ("class", "field", "stratum", "evidence", "host")},
                  "samples_sha256": cell.get("samples", {}).get("sha256"),
                  "n_max": cell.get("header", {}).get("n_max", header["n_max"]) if cell["evidence"] in HEADER[
                      "n_max"] else None}
        identity = json.dumps([values[k] for k in IDENTITY])
        if identity in receipt["cells"]:
            reasons.append(f"cell {identity} repeats a run identity")
            continue
        receipt["cells"][identity] = judge_cell(
            cell, term=terms.get(cell["field"]), host=hosts.get(cell["host"]), header=header,
            envelope=frame["envelope"], offered=offered, platforms=document["platforms"], bound=bound,
            summarize_samples=summarize_samples)
    receipt["outcomes"] = {cls: {member: outcome(policy, cls, member) for member in FAMILY} for cls in CLASSES}
    receipt.update(hosts=hosts, hit_gate=h, columns=columns(frame, header, receipt["cells"], document["platforms"]),
                   ranking={"withheld": controls}, sizing={"owner": SIZING, "cells": [
                       identity for identity in receipt["cells"]
                       if identity_values(identity)["field"] in frame["comparison"]["sizing"]["fields"]]})
    verdicts = ["inconclusive" for host in hosts.values() if not host["admitted"]]
    if section is not None:
        section["reasons"] += [*authority_gaps(campaign, policy, hosts),
                               *hardware_gaps(header, document["platforms"])]
        if contrast == "revision":
            target, problem = cited(campaign.get("target"))
            drift_why = derived["calibration-drift"][1]
            validity = [*provenance, *(fault for fault in faults if fault not in unjudged), *section["reasons"],
                        *(r for r in section["calibration"]["reasons"] if r not in drift_why),
                        *([problem] if problem else [])]
            section["ticket"] = bound_verdict(section, h=gate_result, validity=validity,
                                              uncredited=[*unjudged, DECLARED, *frame_gaps(frame)],
                                              statistics=statistics, frame=frame, target=target)
            verdicts += ["fail"] if section["ticket"]["verdict"] == REGRESSION else []
        receipt["comparison"] = {**section, "declared": DECLARED}
    verdicts += [h["verdict"], *(cell["verdict"] for cell in receipt["cells"].values())]
    verdicts += [v if v != "unscored" else "inconclusive" for rows in receipt["outcomes"].values() for v in rows.values()]
    receipt["verdict"] = gate.worst(["inconclusive", *verdicts])
    return receipt


def bound_text(value, absent="unbounded"):
    return absent if value is None else f"{value:.6g}"


def ticket(receipt, receipt_sha256, head):
    """The result-to-ticket block of a revision contrast's receipt, which ends with the `Gate head:` line: the cited
    campaign artifact and cell, the measured candidate and baseline, the bound verdict, whether it merges as a
    performance change (only PASS does), each member's bound against its tolerance, the reasons, the
    requalification, the frozen Step 8 rules and the SHA-256 of the retained receipt file. A Refusal for a receipt
    without a bound verdict, a head that is not the unpatched candidate the campaign measured, or a value holding a
    control character, which would add a line to the block."""
    section = receipt.get("comparison") if isinstance(receipt, dict) else None
    result = section.get("ticket") if isinstance(section, dict) else None
    if not (isinstance(section, dict) and isinstance(result, dict) and result.get("verdict") in VERDICTS):
        raise Refusal("the receipt holds no revision contrast's bound verdict")
    if not (isinstance(head, str) and COMMIT.fullmatch(head)):
        raise Refusal(f"gate head {head!r} is no 40-hex commit")
    candidate, baseline = section.get("revision"), section.get("baseline")
    if not (isinstance(candidate, dict) and isinstance(baseline, dict) and is_revision(candidate)
            and is_revision(baseline)):
        raise Refusal("the receipt's comparison names no measured candidate and baseline revision")
    if (candidate["commit"], candidate["patch_sha256"]) != (head, NO_PATCH):
        raise Refusal(f"gate head {head} is not the unpatched candidate {candidate['commit']} the campaign measured")
    target, table, rows = result["target"], bound_entries(section["bounds"]), []
    for key, verdict in result["members"].items():
        entry = table.get(key)
        rows.append(f"| {key} | {'hit gate' if key == H else 'no judge'} | | | {verdict} |" if entry is None else
                    f"| {key} | {bound_text(entry['bound'][0])} | {bound_text(entry['bound'][1])} | "
                    f"{bound_text(entry['tolerance'], 'unscored')} | {verdict} |")
    cites = "Target: no resolved campaign artifact and cell"
    if isinstance(target, dict):
        cites = (f"Target: cell {target['cell']} of campaign artifact {target['campaign_sha256']} (receipt "
                 f"{target['receipt_sha256']})")
    verdict = result["verdict"]
    lines = [
        cites,
        f"Bound verdict: {verdict}",
        f"Merges as a performance change: {'yes' if verdict == PASS else 'no'}",
        f"Candidate: {candidate['commit']} patch {candidate['patch_sha256']}",
        f"Baseline: {baseline['commit']} patch {baseline['patch_sha256']}", "",
        "| member | low | high | tolerance | verdict |", "| --- | --- | --- | --- | --- |", *rows, "",
        "Reasons:", *(f"- {reason}" for reason in result["reasons"] or ["none"]), "",
        "Requalification:", *(f"- {item}" for item in result["requalification"]), "",
        "Frozen Step 8 rules kept:", *(f"- {item}" for item in result["frozen"]), "",
        f"Retained receipt SHA-256: {receipt_sha256}", f"Gate head: {head}", ""]
    if any(line and not line.isprintable() for line in lines):
        raise Refusal("a value of the receipt holds a character that is not printable, which could add a line to the "
                      "ticket block")
    return "\n".join(lines)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Check the measurement frame and report a campaign against it.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "floors", "report", "ticket"):
        command = commands.add_parser(name)
        command.add_argument("--records", default=str(RECORDS))
        command.add_argument("--manifest", default=str(gate.MANIFEST))
        command.add_argument("--obligations", default=str(gate.OBLIGATIONS))
    commands.choices["check"].add_argument("--base")
    commands.choices["floors"].add_argument("--requests", type=int, required=True)
    commands.choices["report"].add_argument("--campaign", required=True)
    commands.choices["report"].add_argument("--output")
    commands.choices["ticket"].add_argument("--campaign", required=True)
    commands.choices["ticket"].add_argument("--receipt", required=True)
    commands.choices["ticket"].add_argument("--gate-head", required=True)
    args = parser.parse_args(argv)
    try:
        lane = gate.lane_module()
        document, manifest_sha256 = gate.read_document(args.manifest, lane)
        ids = gate.obligation_ids(args.obligations)
        gate.check(document, ids)
        records, log = load(args.records)
        if args.command == "check":
            if args.base is not None and not args.base:
                raise Refusal("--base names no revision")
            prior = prior_log(args.base) if args.base else None
            print(json.dumps({"open": check(records, log, document["qualification"], prior)}, indent=1))
            return 0
        if args.command == "floors":
            if args.requests < 0:
                raise Refusal("--requests is negative")
            check(records, log, document["qualification"])
            statistics, policy = records["statistics"][0], records["policy"][0]
            m, tail, z = level(statistics, policy)
            kinds = {name: floor_kind(args.requests, q) for name, q in gate.QUANTILES.items()}
            print(json.dumps({"requests": args.requests, "kinds": kinds, "m": m, "per_tail": tail, "z": z}))
            return 0
        held = b""
        if args.command == "ticket":
            if not COMMIT.fullmatch(args.gate_head):
                raise Refusal(f"gate head {args.gate_head!r} is no 40-hex commit")
            held = gate.read_file(args.receipt, "receipt")
        data = gate.read_file(args.campaign, "campaign")
        receipt = report(records, log, gate.parse(data, f"campaign {args.campaign}"), hashlib.sha256(data).hexdigest(),
                         document=document, manifest_sha256=manifest_sha256, ids=ids, lane=lane)
        out = json.dumps(receipt, indent=1, sort_keys=True) + "\n"
        if args.command == "ticket":
            if held != out.encode():
                raise Refusal(f"receipt {args.receipt} is not the bytes campaign {args.campaign} derives under this "
                              "script, the hit gate, the committed records, the manifest and the evidence files")
            sys.stdout.write(ticket(receipt, hashlib.sha256(held).hexdigest(), args.gate_head))
            return 0 if receipt["comparison"]["ticket"]["verdict"] == PASS else 1
        if args.output:
            gate.write_receipt(args.output, out)
        else:
            sys.stdout.write(out)
    except gate.FAULTS as error:
        print(f"measurement-frame: refused: {error}", file=sys.stderr)
        return 2
    return 1


if __name__ == "__main__":
    sys.exit(main())
