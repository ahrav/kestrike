#!/usr/bin/env python3
"""Assemble warm-recovery acceptance by failure class and evidence kind from the receipts the existing judges derive.

Usage:
  acceptance.py check [--record F] [--records DIR] [--manifest F] [--obligations F]
  acceptance.py judge --inputs F [--record F] [--records DIR] [--manifest F] [--obligations F] [--output F]

The record is `verification/measurement/acceptance.json`. It pins the parent specification and contract by the
frame's body digests and this ticket by its own, the committed frame, statistics and policy versions and the bytes of
the sizing worksheet, and holds:
  columns       safety, containment, retention, progress and conservation, each mapped to #120 properties and
                requirements.
  sources       each evidence source, one receipt identity: its issue (a ticket `#N`, or an issue ISSUES names),
                evidence kind (a frame evidence kind), judge,
                the classes and columns it may credit and, for an `obligation` source, its catalog records and
                for a model source the `verification/quint/expected.json` case families those records name; the
                #122 source names FAMILIES. An `obligation` source is model evidence of Quint records, simulation
                evidence of JOBS records or store evidence of non-Quint records whose catalog property names STORE. A
                `package` source is
                judged by `scripts/recovery-packages.py` and a `comparison` source by `scripts/measurement-frame.py
                report`; both are hardware.
  classes       each failure class: its frame class (null when the frame measures no stratum of it), `cold`, its
                manifest package, its meaning, its citations `source:item` by evidence kind and column, and `unrun`,
                the reason for each evidence kind it cites nothing of. An item is a catalog record id, the package
                verdict a column reads (`residuals` for conservation), or a comparison row `field/stratum` whose field
                ROWS lists under the column.
  retention     S at the certified cut and frontier, its terms, the four eligible exclusions and the outcomes that
                never satisfy preservation.
  quantitative  the policy family members each column scores.
  reopen        the store-restore reopen claim with the records of the owner's store source it requires for
                namespace and coverage.
  excluded, unrun, assumptions, properties
                separately owned classes with their owners, unmeasured domains, the assumptions every verdict rests
                on by identity (ASSUMED), and the frame's P-N-341 entry.
`check` validates the frame, statistics, policy, revision log, manifest qualification and packages through their
owning judges (measurement-frame's check runs `cargo` to resolve its source anchors, so check and judge need the Rust
toolchain) and refuses a catalog that repeats a record id, then refuses, with exit 2, a record off these rules: a pin
other than the committed records' or the sizing worksheet's bytes; columns that together map no #120 P1 to P10;
parent digests other than the frame's, or a ticket pin other than {issue, body_sha256}; a source whose judge produces
no evidence of its kind; a citation whose source's kind is not the kind it is cited under (P-N-341: a simulation
source never fills a hardware cell); a citation of a source by a class outside the source's classes, of a package
other than the class's own, whose manifest class is the class, or of a comparison row by a class without a frame
class, outside the frame's row classes or under a column ROWS does not list for its field, so no class inherits
another class's receipt; a citation list that is empty or repeats an entry; classes whose frame classes are not
FRAMES, which holds every frame class of measurement-frame, or that leave a manifest package without a class; an
obligation source crediting the cold control beside a warm class; a catalog record in two sources; a source or record
no class or reopen requirement cites, or cited sources
that quote no receipt of one of ISSUES, each an issue under its evidence kind; a class that is cold other than exactly
when its frame class is the volume-loss control, or a cold class beside the one; a retention citation in the cold
class; the cold refill cited by a warm class; a warm class whose hardware retention cites comparison rows but not
every retention term's row; a kind both cited and unrun, or neither; a source record of a job its kind excludes; a
family case no source record names or a record case expected.json lacks; retention exclusions other than R2's four or
a `never` list other than NEVER; a quantitative map that does not cover the policy family once; reopen requirements
other than namespace and coverage, since TableId detection or a generation jump alone reopens nothing, or naming a
record of no store source of the reopen owner; excluded classes that drop or change a manifest exclusion, drop the
staging owners or name a class; unrun domains without UNRUN or assumptions without ASSUMED. It prints the open gates
(the owning judges' open items except the package legs, hit-gate phases and recovery it lists as unrun domains and
refuses to miss, the classes without a frame class, the unqualified preservation, the blocked model cases and the
store label), the unrun domains (the record's, each class's unrun kinds and uncited kind columns, each manifest
package's unrun legs, the hit-gate phases and recovery the qualification blocks, each frame field or stage that is no
comparison row, each comparison row no ROWS column reads and the closed reopen requirements), the assumptions and the
excluded classes.


`judge` reads an inputs file:
  revision     the 40-hex commit every piece of evidence must name.
  lanes        [{job, module, evidence}]: a lane's evidence directory with its `receipt.json`, credited by
               `scripts/verify-receipts.py credit --receipt --read-only`, which re-derives the receipt from the
               evidence where the lane recorded it and judges it at the revision against the committed catalog,
               within LANE_TIMEOUT seconds, writing nothing. An evidence directory holding, at any depth, a symbolic
               link, an entry that is neither a regular file nor a directory or a directory that cannot be listed, a
               receipt naming an input by an absolute or `..` path, a receipt, catalog or `verify-receipts.py` that
               changes while the child runs, a run naming another catalog or Quint manifest, and a child that prints
               no report each credit no lane; the reason names the child's exit status and last stderr line. A lane's
               identity holds `receipt_sha256`, the SHA-256 of its `receipt.json`, and `judge_sha256`, the SHA-256 of
               `verify-receipts.py`'s bytes.
  packages     {package: campaign file}, re-judged by `scripts/recovery-packages.py`'s `judge`.
  comparisons  {class: campaign file}, re-reported by `scripts/measurement-frame.py`'s `report`; one file may serve
               several classes, each reading only its own frame class's rows and outcomes.
  sizing       optional inputs file of `scripts/sizing-worksheet.py evaluate`, evaluated over the pinned bytes.
Paths are opened as given. A citation reads `pass`, `fail`, `inconclusive` or `unrun` with its receipt identity and
reason. A catalog record passes when the lane of its job and module judged it and holds no refusal that names it or
names no record; a withheld, unjudged or refused record is inconclusive, and one whose job has no lane is unrun. A
package verdict passes only from a credited package receipt of the class's own package and class at the revision; a
failed rule there fails. A comparison row or member reads the receipt's value for the class's frame class; a pass is
inconclusive while the receipt holds a fault or a withheld control, since a retention row credits only once the
always-miss control fails retention, and safe misses never establish it. Evidence a judge refuses, or that names
another revision, package or class, a patched tree or an unsupported platform (the hardware column's label), is
inconclusive whatever it reads. A kind cell is the worst of its citations, `unrun` when every one is or the class
cites nothing of the kind in the column; a structural column is the worst over the class's kinds, an unrun kind
keeping it from passing. The cold class's retention reads `not claimed` and it scores no warm-only member, and a warm
class's retention is at most inconclusive while the manifest's preservation qualification is false, as is a
quantitative column scoring a RETAINS member. A quantitative member reads `unrun` without a comparison and `unscored`
for a class without a frame class, every row holding a budget (`budget_ms` for F) and reasons; a member other than H
passes only with its accepted budget and the policy inputs that define it. H carries the pinned policy's R6 ceilings
and boundary and the qualification digest with the hit-gate receipt identity (#137), and F its separately declared
boundary, percentile and budget_ms. A quantitative column passes only when every member passes, the policy names a
class list, the frame names a population manifest and every envelope value, and alpha and power are accepted. Sizing
scenarios join the classes of their frame class as conditional entries with no verdict. The reopen claim reads `open`
only when every requirement names records a lane credited, `closed` otherwise; it is reported apart from acceptance.


The receipt holds the envelope, the record's, inputs file's, manifest's, catalog's, expected.json's and this script's
SHA-256, the parent and record pins, the revision, the population manifest and statistics status, the gates, unrun
domains, assumptions, excluded classes, retention rule, reopen claim, each judged evidence's identity, per class its
columns, budget row with its canonical SHA-256, H and F rows and sizing entries, and the verdict, the worst over the
classes; `accepted` needs a `pass` verdict and no open gate. The store gate stays open until #123 qualifies the
store, so no receipt is accepted on this revision. `judge` exits 0 only when accepted, 1 otherwise, and 2 for a
refused record or inputs file.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
RECORD = ROOT / "verification/measurement/acceptance.json"
QUINT = ROOT / "verification/quint/expected.json"
ENVELOPE = {"version": 1, "section": "acceptance"}
LANE_TIMEOUT = 900


def load(name, file):
    spec = importlib.util.spec_from_file_location(name, HERE / file)
    if spec is None or spec.loader is None:
        raise SystemExit(f"scripts/{file} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


sw = load("sizing_worksheet", "sizing-worksheet.py")
rp = load("recovery_packages", "recovery-packages.py")
mf, SIZING = sw.mf, sw.WORKSHEET
gate = mf.gate
Refusal = gate.Refusal
FAULTS = (*gate.FAULTS, rp.Refusal)
JUDGE_SHA256 = hashlib.sha256(gate.read_file(__file__, "judge")).hexdigest()
COLUMNS = ("safety", "containment", "retention", "progress", "conservation")
VERDICT = {**{column: column for column in COLUMNS}, "conservation": "residuals"}
JUDGES = {"obligation": ("model", "simulation", "store"), "package": ("hardware",), "comparison": ("hardware",)}
JOBS = {"model": {"quint"}, "simulation": {"workspace", "long-run"}}
STORE = "#123"
PROPERTIES = {f"#120 P{n}" for n in range(1, 11)}
KEYS = {"record", "version", "parent", "records", "columns", "sources", "classes", "retention", "quantitative",
        "reopen", "excluded", "unrun", "assumptions", "properties"}
SOURCE_KEYS = {"issue", "kind", "judge", "evidence", "classes", "columns"}
CLASS_KEYS = {"frame", "cold", "package", "meaning", "evidence", "unrun"}
ISSUES = {("blotter issue 1193", "simulation"), ("#122", "model"), ("#136", "simulation"), ("#140", "simulation"),
          ("#140", "hardware"), ("#134", "simulation"), ("#139", "hardware")}
FRAMES = {"host-loss": "warm-takeover", "same-host-restart": "same-host-restart",
          "actual-volume-loss": "volume-loss-control"}
RETAINS = {mf.RETAINED, "origin_demand"}
FAMILIES = ["join-capture-suffix-", "join-coverage-preserve-", "join-prefix-saturation-"]
TERMS = ["s_membership", "certified_cut", "certified_frontier", "eligible_exclusions", "fault_local_damage",
         "preserved_unaffected_bytes", "recent_unprotected_suffix"]
ROWS = {"retention": set(TERMS),
        "progress": {"first_safe_hit", "full_load_readiness", "cold_refill", "origin_excess", "hit_latency",
                     "fill_latency", "l_data_ratio", "candidate_validation", "activation_cpu"},
        "conservation": {"peak_ram", "engine_charge"}}
EXCLUSIONS = ["recorded eviction", "acknowledged invalidation", "expiry", "successful replacement"]
NEVER = ["safe miss", "generic Stale eviction", "cold host-loss outcome", "all entries evicted"]
REOPEN = {"claim", "owner", "contract", "requires", "insufficient"}
INSUFFICIENT = ["TableId detection", "an arbitrary generation jump"]
UNRUN = ("power-loss", "provider-phenomena", "store-restore")
ASSUMED = ("model", "simulation", "proxy", "hardware", "store", "sizing")
INPUT_KEYS = {"revision", "lanes", "packages", "comparisons", "sizing"}
text, texts = mf.text, mf.texts


def need(condition, message, what="acceptance record"):
    if not condition:
        raise Refusal(f"malformed {what}: {message}")


def check_source(name, s, record, ctx, owner):
    need(isinstance(s, dict), f"source {name} is no object")
    keys = SOURCE_KEYS | ({"records"} | ({"families"} if s.get("kind") == "model" else set())
                          if s.get("judge") == "obligation" else set())
    need(set(s) == keys, f"source {name} keys are not {sorted(keys)}")
    need((mf.TICKET.fullmatch(str(s["issue"])) or any(s["issue"] == issue for issue, _ in ISSUES))
         and s["kind"] in mf.EVIDENCE and text(s["evidence"]), f"source {name}")
    need(s["judge"] in JUDGES and s["kind"] in JUDGES[s["judge"]],
         f"source {name}: judge {s['judge']!r} produces no {s['kind']} evidence")
    need(texts(s["classes"]) and set(s["classes"]) <= set(record["classes"]), f"source {name} classes")
    need(texts(s["columns"]) and set(s["columns"]) <= set(COLUMNS), f"source {name} columns")
    need(s["kind"] != "store" or s["issue"] == STORE, f"source {name}: store evidence belongs to {STORE}")
    if s["judge"] != "obligation":
        need(s["issue"] != "#122", f"source {name} quotes #122, whose join records only an obligation source binds")
        return
    catalog, cases = ctx["catalog"], set(ctx["quint"]["tests"])
    need(texts(s["records"]), f"source {name} records are no distinct non-empty list")
    need(all(r in catalog for r in s["records"]), f"source {name} names an unknown record")
    for r in s["records"]:
        need(owner.setdefault(r, name) == name, f"record {r} belongs to sources {owner[r]} and {name}")
        job = catalog[r]["job"]
        need(job in JOBS[s["kind"]] if s["kind"] in JOBS else job not in JOBS["model"],
             f"record {r} of job {job} is not {s['kind']} evidence")
        need(s["kind"] != "store" or str(catalog[r].get("property", "")).startswith(f"{STORE} "),
             f"record {r} declares no {STORE} property, so it is no store evidence")
    if s["kind"] == "model":
        named = {t for r in s["records"] for t in [*catalog[r]["tests"], *(c["test"] for c in catalog[r]["controls"])]}
        need(texts(s["families"]), f"source {name} families are no distinct non-empty list")
        need(named <= cases, f"source {name} names a case expected.json lacks")
        for family in s["families"]:
            members = {case for case in cases if case.startswith(family)}
            need(members and members <= named, f"family {family} holds a case no record of source {name} names")
    need(s["issue"] != "#122" or s.get("families") == FAMILIES, f"source {name} binds no families {FAMILIES}")


def check_citation(name, c, kind, column, cite, record, ctx):
    source, _, item = cite.partition(":") if isinstance(cite, str) else ("", "", "")
    s = record["sources"].get(source)
    if s is None or not item:
        raise Refusal(f"malformed acceptance record: class {name} cites {cite!r}, which names no source and item")
    need(s["kind"] == kind, f"class {name} cites {s['kind']} source {source} under {kind}: a column credits only its "
         "own evidence kind (P-N-341)")
    need(name in s["classes"], f"class {name} cites source {source}, which credits {s['classes']}: no class inherits "
         "another class's receipt")
    need(column in s["columns"], f"class {name} cites source {source} under {column}")
    need(not (column == "retention" and c["cold"]), f"class {name} cites retention: actual volume loss starts cold and "
         "claims no retention of S")
    frame = ctx["records"]["frame"][0]
    if s["judge"] == "obligation":
        need(item in s["records"], f"class {name} cites {cite}, a record outside source {source}")
    elif s["judge"] == "package":
        need(c["package"] is not None and item == VERDICT[column],
             f"class {name} cites {cite} under {column}: a class reads its own package's {VERDICT[column]} verdict")
    else:
        field, _, stratum = item.partition("/")
        need(c["cold"] or field != "cold_refill", f"class {name} cites the cold refill, which measures only the "
             "actual-volume-loss control")
        need(field in ROWS.get(column, ()), f"class {name} cites {cite} under {column}, which that row never measures")
        need(c["frame"] is not None and stratum in frame["comparison"]["cells"].get(field, [])
             and c["frame"] in frame["comparison"]["row_classes"].get(field, mf.CLASSES)
             and kind in {**frame["fields"], **frame["stages"]}[field]["evidence"],
             f"class {name} cites {cite}, which is no {kind} comparison row of its frame class")
    return s["judge"], item


def check_class(name, c, record, ctx):
    frame, document = ctx["records"]["frame"][0], ctx["document"]
    need(isinstance(c, dict) and set(c) == CLASS_KEYS and text(c["meaning"]), f"class {name} keys")
    need(c["frame"] is None or c["frame"] in mf.CLASSES, f"class {name} frame class {c['frame']!r}")
    need(c["cold"] is (c["frame"] is not None and frame["classes"][c["frame"]]["cold"]),
         f"class {name} is cold exactly when its frame class is the volume-loss control")
    packages = document["packages"]["packages"]
    need(c["package"] is None or packages.get(c["package"], {}).get("class") == name,
         f"class {name} names package {c['package']!r}, whose manifest class is not {name}")
    evidence, unrun = c["evidence"], c["unrun"]
    need(isinstance(evidence, dict) and isinstance(unrun, dict) and not set(evidence) & set(unrun)
         and set(evidence) | set(unrun) == set(mf.EVIDENCE) and all(text(v) for v in unrun.values()),
         f"class {name} cites or declares unrun each evidence kind of {list(mf.EVIDENCE)}, never both")
    rows = set()
    for kind, columns in evidence.items():
        need(isinstance(columns, dict) and columns and set(columns) <= set(COLUMNS), f"class {name} {kind} columns")
        for column, cites in columns.items():
            need(texts(cites), f"class {name} {kind} {column} citations are no distinct non-empty list")
            for cite in cites:
                judge, item = check_citation(name, c, kind, column, cite, record, ctx)
                if (kind, column, judge) == ("hardware", "retention", "comparison"):
                    rows.add(item)
    cells = frame["comparison"]["cells"]
    required = {f"{t}/{s}" for t in TERMS if "hardware" in frame["fields"][t]["evidence"] for s in cells.get(t, [])}
    need(not rows or required <= rows, f"class {name} cites hardware retention rows without {sorted(required - rows)}: "
         "retention accounts for damage and the recent unprotected suffix")


def check(record, ctx):
    """Raise Refusal at the first rule `record` breaks; return its gates and unrun domains."""
    records, document = ctx["records"], ctx["document"]
    frame, policy = records["frame"][0], records["policy"][0]
    need(isinstance(record, dict) and set(record) == KEYS, f"keys are not {sorted(KEYS)}")
    need(record["record"] == "acceptance" and gate.integer(record["version"], 1), "record kind and version")
    parent = record["parent"]
    need(isinstance(parent, dict) and {k: parent.get(k) for k in ("digest", "specification", "contract")} == {
        k: frame["parent"][k] for k in ("digest", "specification", "contract")}, "parent digests are not the frame's")
    ticket = parent.get("ticket")
    need(set(parent) == {"digest", "specification", "contract", "ticket"} and isinstance(ticket, dict)
         and set(ticket) == {"issue", "body_sha256"} and ticket["issue"] == "#142"
         and mf.digest(ticket["body_sha256"]), "the ticket pin")
    need(record["records"] == {**{kind: mf.pin(records, kind) for kind in mf.KINDS}, "sizing": ctx["sizing_sha256"]},
         "the record pins are not the committed frame, statistics, policy and sizing worksheet")
    columns = record["columns"]
    need(set(VERDICT.values()) == set(rp.KINDS), f"package verdicts {sorted(rp.KINDS)} are not one per column", "judge")
    need(set(FRAMES.values()) == set(mf.CLASSES),
         f"FRAMES {sorted(FRAMES.values())} are not the frame classes {sorted(mf.CLASSES)}", "judge")
    need(isinstance(columns, dict) and list(columns) == list(COLUMNS) and all(
        isinstance(v, dict) and set(v) == {"maps", "meaning"} and texts(v["maps"]) and text(v["meaning"])
        for v in columns.values()) and set().union(*(v["maps"] for v in columns.values())) >= PROPERTIES,
         f"columns are not {list(COLUMNS)}, together mapped to #120 P1 to P10")
    sources, classes = record["sources"], record["classes"]
    need(isinstance(sources, dict) and isinstance(classes, dict) and classes, "sources")
    owner = {}
    for name, source in sources.items():
        check_source(name, source, record, ctx, owner)
    for name, c in classes.items():
        check_class(name, c, record, ctx)
    need(sum(c["cold"] for c in classes.values()) == 1, "one class is the cold control")
    need({name: c["frame"] for name, c in classes.items() if c["frame"] is not None} == FRAMES,
         f"the classes do not hold the frame classes {FRAMES}, so one would read another's rows")
    need({c["package"] for c in classes.values()} >= set(document["packages"]["packages"]),
         "the classes do not cover every manifest package")
    for name, s in sources.items():
        need(s["judge"] != "obligation" or len({classes[x]["cold"] for x in s["classes"]}) == 1,
             f"source {name} credits the cold control beside a warm class")
    retention = record["retention"]
    need(isinstance(retention, dict) and set(retention) == {"set", "terms", "exclusions", "never"}
         and text(retention["set"]) and retention["terms"] == TERMS, "retention terms")
    need(retention["exclusions"] == EXCLUSIONS, f"eligible exclusions are not R2's {EXCLUSIONS}")
    need(retention["never"] == NEVER, f"the outcomes that never satisfy preservation are not {NEVER}")
    quantitative = record["quantitative"]
    need(isinstance(quantitative, dict) and set(quantitative) == set(COLUMNS) and all(
        isinstance(v, list) for v in quantitative.values()), "the quantitative map is no member list per column")
    members = [m for column in COLUMNS for m in quantitative[column]]
    need(sorted(members) == sorted(policy["family"]),
         "the quantitative map does not cover the policy family once")
    reopen = record["reopen"]
    need(isinstance(reopen, dict) and set(reopen) == REOPEN and all(text(reopen[k]) for k in ("claim", "contract"))
         and reopen["owner"] == STORE and reopen["insufficient"] == INSUFFICIENT, "reopen claim")
    need(isinstance(reopen["requires"], dict) and set(reopen["requires"]) == {"namespace", "coverage"},
         "a store-restore reopen rests on namespace and complete coverage evidence: TableId detection or a generation "
         "jump alone reopens nothing")
    required = [r for ids in reopen["requires"].values() for r in ids or []]
    need(all(v is None or texts(v) for v in reopen["requires"].values()) and all(
        r in owner and sources[owner[r]]["kind"] == "store" and sources[owner[r]]["issue"] == reopen["owner"]
        for r in required), f"reopen requirements name records of a {reopen['owner']} store source or null")
    cites = [cite.partition(":") for c in classes.values() for kinds in c["evidence"].values()
             for listed in kinds.values() for cite in listed]
    cited = {source for source, _, _ in cites} | {owner[r] for r in required}
    need(set(sources) == cited, f"sources {sorted(set(sources) - cited)} are cited by no class or reopen requirement")
    unused = set(owner) - {item for _, _, item in cites} - set(required)
    need(not unused, f"records {sorted(unused)} are cited by no class or reopen requirement")
    quoted = {(sources[name]["issue"], sources[name]["kind"]) for name in cited}
    need(quoted.issuperset(ISSUES), f"sources quote no receipt of {sorted(ISSUES - quoted)}")
    excluded, manifest = record["excluded"], document["packages"]["excluded"]
    need(isinstance(excluded, dict) and all(text(v) for v in excluded.values()) and not set(excluded) & set(classes)
         and {k: excluded.get(k) for k in manifest} == manifest and "staging" in excluded,
         "excluded classes keep every manifest exclusion and its owner and the staging owners, apart from the classes")
    need(isinstance(record["unrun"], dict) and set(UNRUN) <= set(record["unrun"])
         and all(text(v) for v in record["unrun"].values()), f"unrun domains do not keep {list(UNRUN)}")
    assumptions = record["assumptions"]
    need(isinstance(assumptions, dict) and set(ASSUMED) <= set(assumptions) and all(map(text, assumptions.values())),
         f"assumptions are not one per {list(ASSUMED)}")
    need(record["properties"] == {"P-N-341": frame["properties"]["P-N-341"]}, "properties are not the frame's P-N-341")
    legs = {f"package {name} leg {leg}": why for name, p in document["packages"]["packages"].items()
            for leg, why in p["unrun"].items()}
    gates = [f"class {name} has no frame stratum or policy budget row, so its quantitative members read unscored"
             for name, c in classes.items() if c["frame"] is None]
    q = document["qualification"]
    listed = {*(f"{leg} is unrun: {why}" for leg, why in legs.items()),
              *(f"phase {phase} is blocked: {p['blocked']}" for phase, p in q["phases"].items() if "blocked" in p),
              *([f"recovery is blocked: {q['recovery']['blocked']}"] if "blocked" in q["recovery"] else [])}
    need(listed <= set(ctx["open"]), "the owners' open items no longer name each unrun leg, phase and recovery",
         "owner report")
    gates += [item for item in ctx["open"] if item not in listed]
    for case_gate in sorted(set(ctx["quint"]["blocked"].values())):
        count = sum(v == case_gate for v in ctx["quint"]["blocked"].values())
        gates.append(f"{count} model cases are blocked on {case_gate}")
    gates.append(mf.COLUMNS["store"])
    unrun = [f"{name}: {why}" for name, why in record["unrun"].items()]
    unrun += [f"class {name} {kind}: {why}" for name, c in classes.items() for kind, why in c["unrun"].items()]
    unrun += [f"class {name} cites no {kind} evidence under {column}" for name, c in classes.items()
              for kind, columns in c["evidence"].items() for column in COLUMNS
              if column not in columns and not (c["cold"] and column == "retention")]
    unrun += [f"{leg}: {why}" for leg, why in legs.items()]
    unrun += [f"hit-gate phase {phase}: {p['blocked']}" for phase, p in q["phases"].items() if "blocked" in p]
    unrun += [f"recovery qualification: {q['recovery']['blocked']}"] if "blocked" in q["recovery"] else []
    cells, read = frame["comparison"]["cells"], set().union(*ROWS.values())
    need(read - set(TERMS) <= set(cells), f"ROWS reads {sorted(read - set(TERMS) - set(cells))}, which are no "
         "comparison rows", "judge")
    unrun += [f"{t} is no comparison row, so no hardware citation measures it"
              for t in {**frame["fields"], **frame["stages"]} if t not in cells]
    unrun += [f"comparison row {t} is read under no column" for t in cells if t not in read]
    unrun += [f"the reopen claim is closed: no {key} record of {reopen['owner']}"
              for key, value in reopen["requires"].items() if value is None]
    return gates, unrun


def quantitative_gaps(ctx):
    """Why no quantitative column can pass under the committed records."""
    frame, statistics, policy = (ctx["records"][kind][0] for kind in mf.KINDS)
    gaps = ["the policy names no readiness-review class list, so no class is accepted for scoring"] if policy[
        "class_list"] is None else []
    gaps += mf.frame_gaps(frame)
    gaps += [f"{key} {statistics[key]['value']} is provisional" for key in ("familywise_alpha", "power")
             if statistics[key]["status"] != "accepted"]
    return gaps


def combine(verdicts):
    """Fail, then inconclusive; unrun when every verdict is; pass only when every verdict passes."""
    if verdicts and all(v == "unrun" for v in verdicts):
        return "unrun"
    return gate.worst(verdicts)


def demoted(verdict, reasons):
    return "inconclusive" if reasons and verdict == "pass" else verdict


def decided(verdict, binding, reasons):
    """`verdict` at the judged revision: evidence bound elsewhere decides nothing, and a reason keeps a pass open."""
    return ("inconclusive", [*binding, *reasons]) if binding else (demoted(verdict, reasons), reasons)


def lane_verdict(record_id, lanes, catalog):
    entry = catalog[record_id]
    lane = lanes.get((entry["job"], entry.get("module")))
    if lane is None:
        return "unrun", [f"no lane evidence for job {entry['job']}" + (
            f" module {entry['module']}" if entry.get("module") else "")], None
    if "missing" in lane:
        return "inconclusive", [lane["missing"]], None
    identity = {"job": entry["job"], "module": entry.get("module"), "receipt_sha256": lane["receipt_sha256"],
                "judge_sha256": lane["judge_sha256"]}
    if record_id in lane.get("blocked", {}):
        return "inconclusive", [f"withheld at {sorted(set(lane['blocked'][record_id].values()))}"], identity
    if record_id not in lane["obligations"]:
        return "inconclusive", ["the lane's credit judged no such record"], identity
    refused = [r for r in lane["refusals"] if r.get("record") in (None, record_id)]
    return ("inconclusive", [f"{r['code']}: {r['reason']}" for r in refused], identity) if refused else (
        "pass", [], identity)


def package_verdict(entry, item, revision, package, cls):
    if entry is None:
        return "unrun", ["no package campaign"]
    if "missing" in entry:
        return "inconclusive", [entry["missing"]]
    binding = [] if (entry["package"], entry["class"]) == (package, cls) else [
        f"the campaign is package {entry['package']} of class {entry['class']}, not {package} of {cls}"]
    binding += [] if entry["revision"] == revision else [f"the package ran at {entry['revision']}, not {revision}"]
    raw = entry["verdicts"][item]
    verdict = "pass" if raw == "pass" else "fail" if raw.startswith("fail") else "inconclusive"
    reasons = [] if verdict == "pass" else [raw]
    if not entry["credited"]:
        reasons += [f"the package is uncredited: {'; '.join([*entry['open'], *entry['reasons']]) or 'a kind failed'}"]
    return decided(verdict, binding, reasons)


def comparison_read(entry, revision, frame_class, key, *, rows, extra=()):
    """`frame_class`'s hardware row `key` (its outcome `key` unless `rows`) in the comparison `entry`'s receipt,
    decided at `revision` with `extra` reasons."""
    if entry is None:
        return "unrun", ["no comparison campaign"]
    if "missing" in entry:
        return "inconclusive", [entry["missing"]]
    receipt = entry["receipt"]
    if "columns" not in receipt:
        return "inconclusive", [f"the comparison reads {receipt['verdict']}: {'; '.join(receipt['reasons'])}"]
    label = receipt["columns"]["hardware"]["label"]
    binding = [] if (entry["revision"], entry["patch"]) == (revision, mf.NO_PATCH) else [
        f"the campaign ran at {entry['revision']} with patch {entry['patch']}, not the unpatched {revision}"]
    binding += [label] if label else []
    reasons = list(dict.fromkeys([*receipt["reasons"], *receipt["ranking"]["withheld"], *extra]))
    values = receipt["columns"]["hardware"]["rows"] if rows else receipt["outcomes"]
    return decided(values[frame_class][key], binding, reasons)


def member_row(member, c, entry, policy, frame, revision):
    if c["frame"] is None:
        return {"budget_ms" if member == mf.F else "budget": None, "verdict": "unscored",
                "reasons": ["no frame stratum or policy budget row for this class"]}
    budget = policy["f"]["budget_ms"] if member == mf.F else policy["budgets"][c["frame"]][member]
    extra = [*([] if budget is not None or member == mf.H else [f"{member} declares no accepted budget"]),
             *mf.inputs(member, policy)]
    verdict, reasons = comparison_read(entry, revision, c["frame"], member, rows=False, extra=extra)
    row = {"budget_ms" if member == mf.F else "budget": budget, "verdict": verdict, "reasons": reasons}
    receipt = entry.get("receipt") if entry else None
    if member == mf.H:
        row.update(source="#137", ceilings={"nominal": policy["h"]["nominal"],
                                             "large_object": policy["h"]["large_object"]},
                   boundary=policy["h"]["boundary"], qualification_sha256=frame["hit_gate"]["qualification_sha256"],
                   hit_gate=receipt and receipt.get("hit_gate") and {
                       "verdict": receipt["hit_gate"]["verdict"],
                       "receipt_sha256": receipt["hit_gate"].get("receipt_sha256")})
    elif member == mf.F:
        row.update(boundary=policy["f"]["boundary"], percentile=policy["f"]["percentile"])
    return row


def judge_class(name, c, record, ctx, evidence, ids, revision, preserved):
    """One class's columns, budget row and verdict from the judged `evidence` and its identities `ids`."""
    frame, _, policy = (ctx["records"][kind][0] for kind in mf.KINDS)
    comparison = evidence["comparisons"].get(name)
    package = evidence["packages"].get(c["package"])
    held = {kind: (entry, identity if isinstance(identity, dict) else None) for kind, entry, identity in (
        ("package", package, ids["packages"].get(c["package"])),
        ("comparison", comparison, ids["comparisons"].get(name)))}
    handoff = ctx["document"]["qualification"]["preservation"]["handoff"]
    gaps = quantitative_gaps(ctx)
    out = {key: c[key] for key in ("frame", "cold", "package", "meaning")}
    out["columns"], verdicts = {}, []
    for column in COLUMNS:
        kinds = {kind: {"verdict": "unrun", "reason": why} for kind, why in c["unrun"].items()}
        for kind, columns in c["evidence"].items():
            cited = []
            for cite in columns.get(column, []):
                source, _, item = cite.partition(":")
                judge = record["sources"][source]["judge"]
                if judge == "obligation":
                    verdict, reasons, identity = lane_verdict(item, evidence["lanes"], ctx["catalog"])
                else:
                    entry, identity = held[judge]
                    verdict, reasons = package_verdict(entry, item, revision, c["package"], name) if (
                        judge == "package") else comparison_read(entry, revision, c["frame"], item, rows=True)
                cited.append({"source": source, "issue": record["sources"][source]["issue"], "item": item,
                              "verdict": verdict, "reasons": reasons, "identity": identity})
            kinds[kind] = {"verdict": combine([e["verdict"] for e in cited]), "citations": cited} if cited else {
                "verdict": "unrun", "reason": f"no {kind} citation for this column"}
        structural = {"verdict": combine([k["verdict"] for k in kinds.values()]), "kinds": kinds, "reasons": []}
        if column == "retention" and c["cold"]:
            structural = {"verdict": "not claimed", "kinds": kinds, "reasons": [
                "actual volume loss starts cold; its retention of S is no claim and certifies no host-loss recovery"]}
        elif column == "retention" and not preserved:
            structural["reasons"].append(handoff)
            structural["verdict"] = demoted(structural["verdict"], structural["reasons"])
        members = {m: member_row(m, c, comparison, policy, frame, revision) for m in record["quantitative"][column]
                   if not (c["cold"] and m in mf.WARM_ONLY)}
        reasons = [*gaps, *([handoff] if RETAINS & set(members) and not preserved and not c["cold"] else [])]
        quantitative = {"verdict": demoted(gate.worst([row["verdict"] for row in members.values()]), reasons)
                        if members else "none", "members": members, "reasons": reasons if members else []}
        out["columns"][column] = {"structural": structural, "quantitative": quantitative}
        verdicts += [v for v in (structural["verdict"], quantitative["verdict"]) if v not in ("not claimed", "none")]
    row = policy["budgets"][c["frame"]] if c["frame"] else None
    out["budgets"] = {"row": row, "sha256": row and mf.canonical(row)}
    out["sizing"] = [{"scenario": scenario, **{k: s.get(k) for k in ("label", "probability", "binding", "withheld")},
                      "verdict": "none"}
                     for scenario, s in (evidence.get("sizing") or {}).get("scenarios", {}).items()
                     if c["frame"] is not None and s["class"] == c["frame"]]
    out["verdict"] = combine(verdicts)
    return out


def check_inputs(inputs, record):
    def ok(condition, message):
        need(condition, message, "inputs file")

    ok(isinstance(inputs, dict) and set(inputs) <= INPUT_KEYS and "revision" in inputs, f"keys within {INPUT_KEYS}")
    ok(isinstance(inputs["revision"], str) and mf.COMMIT.fullmatch(inputs["revision"]), "no 40-hex revision")
    lanes = inputs.get("lanes", [])
    ok(isinstance(lanes, list) and all(isinstance(lane, dict) and set(lane) == {"job", "module", "evidence"} and text(
        lane["job"]) and (lane["module"] is None or text(lane["module"])) and text(lane["evidence"]) for lane in lanes),
       "a lane is not {job, module, evidence}")
    ok(len({(lane["job"], lane["module"]) for lane in lanes}) == len(lanes), "two lanes name one job and module")
    named = {c["package"] for c in record["classes"].values()} - {None}
    framed = {name for name, c in record["classes"].items() if c["frame"] is not None}
    for key, allowed in (("packages", named), ("comparisons", framed)):
        value = inputs.get(key, {})
        ok(isinstance(value, dict) and set(value) <= allowed and all(text(v) for v in value.values()),
           f"{key} name paths of {sorted(allowed)} only")
    ok(inputs.get("sizing") is None or text(inputs["sizing"]), "sizing names an inputs file")


def identities(evidence):
    """Each judged piece of evidence's receipt identity, or the reason its judge refused it; a lane is keyed by the
    JSON array of its job and module."""
    lanes = {json.dumps([job, module]): e.get("missing") or {
        key: e.get(key) for key in ("credited", "refusals", "blocked", "receipt_sha256", "judge_sha256")}
        for (job, module), e in evidence["lanes"].items()}
    packages = {name: e.get("missing") or {"campaign_sha256": e["campaign_sha256"], "receipt_sha256": mf.canonical(e)}
                for name, e in evidence["packages"].items()}
    shared = {id(e): e.get("missing") or {"campaign_sha256": e["receipt"]["campaign_sha256"],
                                          "receipt_sha256": mf.canonical(e["receipt"])}
              for e in evidence["comparisons"].values()}
    comparisons = {name: shared[id(e)] for name, e in evidence["comparisons"].items()}
    sizing = evidence.get("sizing")
    return {"lanes": lanes, "packages": packages, "comparisons": comparisons,
            "sizing": sizing and (sizing.get("missing") or mf.canonical(sizing))}


def judge(record, inputs, ctx, judges, record_sha256, inputs_sha256):
    """The acceptance receipt of `inputs` under `record`, with `judges` re-deriving each piece of evidence."""
    gates, unrun = check(record, ctx)
    check_inputs(inputs, record)
    revision = inputs["revision"]

    def judged(call, *args):
        try:
            return call(*args)
        except FAULTS as error:
            return {"missing": f"refused: {type(error).__name__}: {error}"}

    evidence = {"lanes": {(lane["job"], lane["module"]): judged(judges.lane, lane["job"], lane["module"],
                                                                lane["evidence"], revision)
                          for lane in inputs.get("lanes", [])},
                "packages": {name: judged(judges.package, path) for name, path in inputs.get("packages", {}).items()}}
    files = {path: judged(judges.comparison, path) for path in set(inputs.get("comparisons", {}).values())}
    evidence["comparisons"] = {name: files[path] for name, path in inputs.get("comparisons", {}).items()}
    if inputs.get("sizing"):
        evidence["sizing"] = judged(judges.sizing, inputs["sizing"])
    frame, statistics = ctx["records"]["frame"][0], ctx["records"]["statistics"][0]
    preserved = ctx["document"]["qualification"]["preservation"]["qualified"] is True
    closed = []
    for key, ids in record["reopen"]["requires"].items():
        if ids is None:
            closed.append(f"no {key} record")
        for r in ids or []:
            verdict, why, _ = lane_verdict(r, evidence["lanes"], ctx["catalog"])
            if verdict != "pass":
                closed.append(f"{key} record {r} is uncredited: {'; '.join(why)}")
    ids = identities(evidence)
    receipt = {"envelope": ENVELOPE, "record_sha256": record_sha256, "inputs_sha256": inputs_sha256,
               "judge_sha256": JUDGE_SHA256,
               **{k: ctx[k] for k in ("manifest_sha256", "catalog_sha256", "quint_sha256")},
               "revision": revision, "parent": record["parent"], "records": record["records"],
               "population": frame["population"]["manifest"],
               "statistics": {k: statistics[k] for k in ("familywise_alpha", "power")},
               "gates": gates, "unrun": unrun, "assumptions": record["assumptions"], "excluded": record["excluded"],
               "retention": record["retention"],
               "reopen": {**record["reopen"], "verdict": "closed" if closed else "open", "reasons": closed},
               "evidence": ids,
               "classes": {name: judge_class(name, c, record, ctx, evidence, ids, revision, preserved)
                           for name, c in record["classes"].items()}}
    receipt["verdict"] = combine([c["verdict"] for c in receipt["classes"].values()])
    receipt["accepted"] = receipt["verdict"] == "pass" and not gates
    return receipt


def lane_pins():
    """The SHA-256 of the committed catalog and Quint manifest the lane judge reads."""
    return [hashlib.sha256(gate.read_file(path, what)).hexdigest()
            for path, what in ((gate.OBLIGATIONS, "committed catalog"), (QUINT, "Quint manifest"))]


class Judges:
    """The existing judges, each re-deriving its receipt from the evidence a path names."""

    def __init__(self, ctx, hardware_lane, log):
        self.ctx, self.lane_module, self.log = ctx, hardware_lane, log

    def lane(self, job, module, evidence, revision):
        pinned = [self.ctx["catalog_sha256"], self.ctx["quint_sha256"]]
        if lane_pins() != pinned:
            raise Refusal("the lane judge credits against the committed catalog and Quint manifest, not the ones "
                          "this run names")
        root = Path(evidence).resolve()
        if not root.is_dir():
            raise Refusal(f"lane evidence {evidence!r} is no directory")
        def unlisted(error):
            raise Refusal(f"lane evidence {evidence!r} holds a directory that cannot be listed: {error}") from error

        for directory, folders, files in os.walk(root, onerror=unlisted):
            for entry in (Path(directory, name) for name in (*folders, *files)):
                if entry.is_symlink() or not (entry.is_file() or entry.is_dir()):
                    raise Refusal(f"lane evidence {evidence!r} holds {str(entry.relative_to(root))!r}, a symbolic "
                                  "link or special file")
        data = gate.read_file(root / "receipt.json", f"lane receipt of {evidence!r}")
        receipt = gate.parse(data, f"lane receipt of {evidence!r}")
        names = receipt.get("inputs") if isinstance(receipt, dict) else None
        if isinstance(names, dict) and any(Path(n).is_absolute() or ".." in Path(n).parts for n in names):
            raise Refusal(f"the lane receipt of {evidence!r} names an input outside the repository and its evidence")
        verifier = HERE / "verify-receipts.py"
        judge_data = gate.read_file(verifier, "lane judge")
        argv = [sys.executable, str(verifier), "credit", "--job", job, "--evidence", str(root),
                "--revision", revision, "--receipt", str(root / "receipt.json"), "--read-only",
                *(["--module", module] if module else [])]
        env = {key: value for key, value in os.environ.items() if key != "GITHUB_STEP_SUMMARY"}
        try:
            done = subprocess.run(argv, capture_output=True, check=False, cwd=ROOT, env=env, timeout=LANE_TIMEOUT)
        except subprocess.TimeoutExpired as error:
            raise Refusal(f"verify-receipts credit ran past {LANE_TIMEOUT} s") from error
        if (gate.read_file(root / "receipt.json", "lane receipt") != data or lane_pins() != pinned
                or gate.read_file(verifier, "lane judge") != judge_data):
            raise Refusal(f"the lane receipt of {evidence!r}, the committed catalog or the lane judge changed while "
                          "it was judged")
        line = done.stdout.decode(errors="replace").partition("\n")[0]
        try:
            result = json.loads(line)
        except ValueError:
            result = None
        if not isinstance(result, dict) or "obligations" not in result:
            crash = result.get("crash") if isinstance(result, dict) else line or "no report"
            stderr = done.stderr.decode(errors="replace").strip().rpartition("\n")[2]
            raise Refusal(f"verify-receipts credited nothing (exit {done.returncode}): {crash}; {stderr}")
        return {**result, "receipt_sha256": hashlib.sha256(data).hexdigest(),
                "judge_sha256": hashlib.sha256(judge_data).hexdigest()}

    def package(self, path):
        data = gate.read_file(path, "package campaign")
        return rp.judge(self.ctx["document"], self.ctx["manifest_sha256"], gate.parse(data, f"campaign {path}"),
                        self.lane_module, hashlib.sha256(data).hexdigest())

    def comparison(self, path):
        data = gate.read_file(path, "comparison campaign")
        campaign = gate.parse(data, f"campaign {path}")
        receipt = mf.report(self.ctx["records"], self.log, campaign, hashlib.sha256(data).hexdigest(),
                            document=self.ctx["document"], manifest_sha256=self.ctx["manifest_sha256"],
                            ids=set(self.ctx["catalog"]), lane=self.lane_module)
        revision = campaign.get("revision") or {}
        return {"receipt": receipt, "revision": revision.get("commit"), "patch": revision.get("patch_sha256")}

    def sizing(self, path):
        raw = gate.read_file(path, "sizing inputs file")
        return sw.evaluate(gate.parse(self.ctx["sizing"], "sizing worksheet"), self.ctx["records"],
                           gate.parse(raw, path), self.ctx["sizing_sha256"], hashlib.sha256(raw).hexdigest(),
                           self.ctx["manifest_sha256"])


def context(args, lane):
    """The committed documents every command reads, with their digests and their owners' open items."""
    document, manifest_sha256 = gate.read_document(args.manifest, lane)
    catalog_data, quint_data = gate.read_file(args.obligations, "catalog"), gate.read_file(QUINT, "Quint manifest")
    catalog = gate.parse(catalog_data, "catalog")
    ids = [r["id"] for r in catalog["records"]]
    need(len(set(ids)) == len(ids), "a record id repeats", "catalog")
    qualification = gate.check(document, set(ids))
    records, log = mf.load(args.records)
    sizing = gate.read_file(SIZING, "sizing worksheet")
    return {"document": document, "manifest_sha256": manifest_sha256, "records": records,
            "open": list(dict.fromkeys([*qualification, *mf.check(records, log, document["qualification"]),
                                        *rp.check(document)])),
            "catalog": {r["id"]: r for r in catalog["records"]}, "quint": gate.parse(quint_data, "Quint manifest"),
            "catalog_sha256": hashlib.sha256(catalog_data).hexdigest(),
            "quint_sha256": hashlib.sha256(quint_data).hexdigest(),
            "sizing": sizing, "sizing_sha256": hashlib.sha256(sizing).hexdigest()}, log


def main(argv=None):
    parser = argparse.ArgumentParser(description="Assemble warm-recovery acceptance by class and evidence kind.")
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("check", "judge"):
        command = commands.add_parser(name)
        command.add_argument("--record", default=str(RECORD))
        command.add_argument("--records", default=str(mf.RECORDS))
        command.add_argument("--manifest", default=str(gate.MANIFEST))
        command.add_argument("--obligations", default=str(gate.OBLIGATIONS))
    commands.choices["judge"].add_argument("--inputs", required=True)
    commands.choices["judge"].add_argument("--output")
    args = parser.parse_args(argv)
    try:
        lane = gate.lane_module()
        ctx, log = context(args, lane)
        data = gate.read_file(args.record, "acceptance record")
        record = gate.parse(data, "acceptance record")
        if args.command == "check":
            gates, unrun = check(record, ctx)
            print(json.dumps({"gates": gates, "unrun": unrun, "assumptions": record["assumptions"],
                              "excluded": record["excluded"]}, indent=1))
            return 0
        raw = gate.read_file(args.inputs, "inputs file")
        receipt = judge(record, gate.parse(raw, "inputs file"), ctx, Judges(ctx, lane, log),
                        hashlib.sha256(data).hexdigest(), hashlib.sha256(raw).hexdigest())
        out = json.dumps(receipt, indent=1, sort_keys=True) + "\n"
        if args.output:
            gate.write_receipt(args.output, out)
        else:
            sys.stdout.write(out)
    except FAULTS as error:
        print(f"acceptance: refused: {error}", file=sys.stderr)
        return 2
    return 0 if receipt["accepted"] else 1


if __name__ == "__main__":
    sys.exit(main())
