#!/usr/bin/env python3
"""Judge the controller-reset (CR-1) recovery package and the process-kill control of the reboot package (PK-1)
from hardware-lane receipts.

Usage:
  recovery-packages.py check [--manifest F]
  recovery-packages.py judge --campaign F [--manifest F] [--output F]

The packages are the `packages` object of `scripts/hardware-profiles.json`, so every lane receipt's
`manifest_sha256` binds the package definitions it ran under. Every command first validates the whole manifest with
the lane's `check_manifest`, then the `packages` object:
  interface  the role, readiness, restoration, repeat and stop contract each package run follows: `repeats`, the
             repeat count from 1 to 64 or null while the platform owner has not approved one; `run_identity`, the
             lane episode of each repeat, `{campaign}-{package}-r{repeat}`; `readiness`, `restoration`, the `stop`
             roster of conditions that end a campaign, `witness`, the observed line names every repeat prints, and
             `legs`, the qualified recovery path's authority and coverage words a repeat's retained line must name,
             or null while no qualified path runs in a package case.
  credit     the native class and credit interface, null: this judge binds no such interface, so a value is refused.
             `owner` names the owners.
  packages   per package its `class`, its warm `recovery` class, its `injection` kind, the lane `profile`, `role`
             and `case` it runs, its class-specific `persistence` statement, its uncredited simulated-device `proxy`
             test, its injection `authority`, null or {approver, injection} with the approver's name and the
             package's own injection, and `unrun`, the legs no case runs, by reason.
  excluded   the packages this judge never judges, each with its owner.
A package's injection fixes its class: `controller-disable` is `controller-reset` and `sigkill` is `process-kill`.
`check` refuses any other pairing, so a kill is never labeled power loss or a reboot and a controller reset never
host loss, and refuses a recovery class other than `same-host-restart`, since a reset or kill recovers warm on its
own volume and the cold replacement is the actual-volume-loss control. `check` prints every open item: each
unsupported platform row, each row on which a package's profile is not `runs` (the lane credits no receipt there),
each owner input a package lacks (see `gaps`), and each unrun leg, which stays outside its package's credit.

`judge` reads a campaign file the campaign driver writes:
  campaign   `package-` and the first 16 hex digits of SHA-256 over the manifest digest, the package and the
             revision, joined by `/`, so one manifest, package and revision have one campaign.
  package    a key of the `packages` object.
  revision   the 40-hex commit every receipt must name.
  runs       [{repeat, receipt}], at most 64: the repeat number from 1 and the path of its lane receipt. Each
             repeat's lane episode is its run identity. The case's output files, the `.stdout` and `.stderr`
             siblings the lane writes beside the receipt, are the run's raw artifacts.
  stopped    optional {repeat, reason}: the repeat at which the campaign stopped and the roster condition that
             stopped it. No run follows it.
  safety     the hit gate's AWS safety manifest (`safety_gaps`), whose creates or standing resources cover every
             host instance and volume the admitted repeats bind, with teardown and no residue.
Paths are opened as given, so a relative path resolves against the working directory.

Each repeat runs as its own lane run under a fresh observer log, `hardware-lane.py run --observer DIR --episode <run
identity>`: the lane records a case's start event and its `observe:` lines only there, and a sweep qualifies only
when KESTRIKE_EPISODE is the run identity and the host runs the package role alone. A repeat is admitted when the
lane's own `judge_profile` credits its receipt under the current manifest digest and revision, its episode is its
run identity, its case's start event names the package's profile, role, case and run identity and is the integer
first event of that episode's log, its mappings file kept one digest across the case, it records a host instance and
a bound volume, and its raw artifacts bind its lines: every witness the case declares appears in the raw output as
often as the receipt counts it, the raw stderr artifact holds exactly one complete `observe:` line of each witness
name and of its injection, each equal to the one line of that name the receipt records, the raw stdout artifact
holds none of them, each of those lines begins with every witness the case declares for its name, so a declared
witness found only inside another line admits no repeat, the libtest summary the raw artifacts give is the
receipt's, each line matches its fixed shape
with every number inside its source type and spelled as the case prints it, the retained line names the run
identity as its episode, and it measures both or neither of its unaffected and affected bytes. Receipts and the
campaign file refuse a repeated object key. That a run identity ran once beyond its observer log's first start is
the campaign driver's statement, since a rerun under another observer directory leaves no trace in the receipt. A repeat that is not admitted is
missing evidence: it carries the first reason, the lane's own for an uncredited receipt, every verdict of it reads
inconclusive, and the campaign must record its stop at that repeat. A cycle that breaks a rule of its case is such a
repeat: each hardware case prints its retained, residual and persisted lines only after its own judge passed, so
the case fails, the lane leaves its receipt uncredited, and the repeat is missing with the lane's reason, the
case's exit and libtest summary; the case's panic line in the raw stderr artifact names the rule. A `fail <rule>`
verdict therefore marks an admitted repeat whose lines disagree with its case's pass, with each other or with
their order, or whose receipt carries another restoration than the declared one. An admitted repeat takes five
independent verdicts, each `pass`, `fail <rule>` or `inconclusive`, the last when a rule's evidence is unmeasured
and no rule failed:
  safety       no wrong read (`ExactBytes`), the covered object missed (`CoveredObjectMisses`) and no fill
               reservation overlapped a served object (`DisjointAllocation`).
  containment  the exact injection observable: CC.EN and CSTS.RDY read zero after the controller disable, or the
               child died by signal 9 (`InjectionObserved`); the `persisted` line names the checkpoint the injection
               line names and follows it in the raw stderr artifact (`PersistenceWitnessed`), a consistency and order
               check over two lines one process prints; the receipt carries the declared restoration
               (`RestorationDeclared`); and `RestorationObserved`, unmeasured: no record binds a repeat's restoration
               outcome, or PK-1's containment of the killed child's DMA, to its run, so containment passes no repeat.
  retention    every member of S served (`RetainedSetServed`); the retained line's checkpoint session is the persisted
               checkpoint's, its recovered session is above it, and the line follows the injection line in the raw
               stderr artifact (`RecoveredFromTheCheckpoint`); the bytes of the members served equal the unaffected
               bytes and the unaffected and affected bytes sum to the eligible bytes, unmeasured when the line reports
               a damaged unit (`UnaffectedBytesServed`); and the load's counts agree on both lines, the checkpoint
               captured S and the covered entry, the load covers every captured entry, and it installed S plus the
               covered entry exactly when that entry served (`LoadCounts`). The
               case's own judge holds the covered entry to an omission; here a served covered object fails safety
               alone. Correct misses never pass.
  progress     a first warm hit, measured in microseconds from the recovered tenure's attach to its first exact
               read (`FirstWarmHit`), and at least one fill reservation at Live (`FillAtLive`), which the case's own
               judge counts under `DisjointAllocation`.
  residuals    every signed residual reads `+0` (`ResidualsZero`), the retired slots counted against the fill
               reservations the cycle dropped, and the residual line follows the injection line in the raw stderr
               artifact (`ResidualsAfterTheInjection`), since the inventory is the recovered tenure's; the retired
               bytes and the pool-wide waste the line also prints are recorded and not judged.

The package's verdict per kind is the worst over its repeats: a failed rule, then inconclusive. A campaign reason is
a wrong campaign id, repeats out of order, a stop, a stop reason off the roster, a run past the stop, a repeat count
other than the declared one, a missing repeat without its stop, a receipt or raw stderr artifact two repeats share
(honest repeats can print the same stdout, which holds no witness line, so stdout is not compared), admitted repeats
on different platform rows, toolchains,
dependency sets or build environments, a retained line naming other legs than the declared ones, or a safety gap.
Credit needs every kind `pass`, no campaign reason and no open item of the package's own (see `gaps`); a supported
row is the lane's condition for each admitted repeat. On this revision `RestorationObserved` and the null credit
interface leave every package uncredited. A package short of credit reads `fail` when a kind failed and
`inconclusive` otherwise, and its unrun legs are listed beside it. The receipt holds the envelope,
`manifest_sha256`, `campaign_sha256`, `judge_sha256` (this script's bytes, provenance compared with nothing), the
campaign, package, class, recovery class, persistence statement, injection authority, revision, open items, excluded
packages, unrun legs, the admitted repeats' shared identity, each repeat's run identity, receipt and raw artifact
digests, measurements (S, its served, eligible, unaffected and affected bytes, the first warm hit, the authority
and coverage legs the retained line names, the signed residuals, the retirement counts, the persisted checkpoint and
the injection) and verdicts, the package verdicts, the reasons, `credited` and the verdict. `judge` exits 0 only for
a credited package, 1 for any other verdict, and 2 with no receipt for refused input: a malformed manifest,
packages object or campaign file, or a failed receipt write.
"""

import argparse
import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MANIFEST = HERE / "hardware-profiles.json"
ENVELOPE = {"version": 1, "section": "recovery-packages"}
WARM = "same-host-restart"
MAX_REPEATS = 64
KINDS = ("safety", "containment", "retention", "progress", "residuals")
INTERFACE_KEYS = {"repeats", "run_identity", "readiness", "restoration", "stop", "witness", "legs"}
PACKAGE_KEYS = {"class", "recovery", "injection", "profile", "role", "case", "persistence", "proxy", "authority",
                "unrun"}
CAMPAIGN_KEYS = {"campaign", "package", "revision", "runs", "stopped", "safety"}
WITNESS = ("retained", "residual", "persisted")
COMMIT = re.compile(r"[0-9a-f]{40}")
WORD = re.compile(r"[!-~]+")
N = "[0-9]{1,20}"
CAPTURED = rf"captured slot [0-9]{{1,10}} session {N} capture [0-9]{{1,10}} units [0-9]{{1,10}} entries {N}"
CAPTURED_FIELDS = re.compile(rf"captured slot ({N}) session ({N}) capture ({N}) units ({N}) entries ({N})")
U32, U64, I64 = (1 << 32) - 1, (1 << 64) - 1, (1 << 63) - 1
INJECTIONS = {
    "controller-disable": ("controller-reset",
                           re.compile(rf"cc 0x([0-9a-f]{{1,8}}) csts 0x([0-9a-f]{{1,8}}) after ({CAPTURED})")),
    "sigkill": ("process-kill", re.compile(rf"signal ([0-9]{{1,3}}) pid ([0-9]{{1,10}}) after ({CAPTURED})")),
}
RETAINED = re.compile(
    rf"S (?P<served>{N})/(?P<eligible>{N}) bytes (?P<bytes>{N}) wrong (?P<wrong>{N}) "
    rf"eligible-bytes (?P<eligible_bytes>{N}) unaffected-bytes (?P<unaffected_bytes>{N}|unmeasured) "
    rf"affected-bytes (?P<affected_bytes>{N}|unmeasured) damaged-units (?P<damaged_units>{N}) "
    rf"omitted (?P<omitted>{N}) installed (?P<installed>{N}) covered-miss (?P<covered_miss>true|false) "
    rf"reserved (?P<reserved>{N}) overlapping (?P<overlapping>{N}) first-hit-us (?P<first_hit_us>{N}|none) "
    r"session 0x(?P<session>[0-9a-f]{1,16}) over checkpoint session 0x(?P<checkpoint_session>[0-9a-f]{1,16}) "
    r"authority (?P<authority>[!-~]+) coverage (?P<coverage>[!-~]+) episode (?P<episode>[!-~]+)")
COUNTS = {"served": U64, "eligible": U64, "bytes": U64, "wrong": U64, "eligible_bytes": U64, "damaged_units": U32,
          "omitted": U64, "installed": U64, "reserved": U64, "overlapping": U64}
RESIDUALS = ("filling", "reserved-bytes", "pending-marks", "escrow-units", "quarantined", "resident-slots",
             "retired-slots")
RETIREMENT = ("retired-bytes", "waste")
RESIDUAL = re.compile(" ".join([*(rf"{name} ([+-]{N})" for name in RESIDUALS),
                                *(rf"{name} ({N})" for name in RETIREMENT)]))
PERSISTED = re.compile(rf"({CAPTURED}) installed ({N}) omitted ({N})")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise SystemExit(f"{path} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


gate = load("hit_gate", HERE / "hit-gate.py")
Refusal = gate.Refusal


def check(document):
    """Raise Refusal at the first malformed field of the manifest's `packages` object; return its open items."""
    def need(condition, message):
        if not condition:
            raise Refusal(f"malformed packages: {message}")

    def text(value):
        return isinstance(value, str) and bool(value)

    p = document.get("packages")
    need(isinstance(p, dict) and set(p) == {"interface", "credit", "owner", "packages", "excluded"}, "top-level keys")
    interface = p["interface"]
    need(isinstance(interface, dict) and set(interface) == INTERFACE_KEYS, "interface keys")
    repeats = interface["repeats"]
    need(repeats is None or gate.integer(repeats, 1, MAX_REPEATS), f"repeats is a count from 1 to {MAX_REPEATS} or null")
    need(interface["run_identity"] == "{campaign}-{package}-r{repeat}", "run identity")
    need(all(text(interface[key]) for key in ("readiness", "restoration")), "readiness and restoration")
    need(isinstance(interface["stop"], list) and interface["stop"] and all(text(c) for c in interface["stop"]),
         "stop roster")
    need(interface["witness"] == list(WITNESS), f"witness names {list(WITNESS)}")
    legs = interface["legs"]
    need(legs is None or isinstance(legs, dict) and set(legs) == {"authority", "coverage"}
         and all(isinstance(v, str) and WORD.fullmatch(v) for v in legs.values())
         and legs["authority"] != "fixture" and legs["coverage"] != "harness",
         "legs is null or the qualified authority and coverage words, neither the fixture authority nor the "
         "harness-built coverage")
    need(p["credit"] is None, "the credit interface is null: this judge binds no native class and credit interface")
    need(text(p["owner"]), "owner")
    need(isinstance(p["excluded"], dict) and all(text(v) for v in p["excluded"].values()),
         "excluded packages name their owners")
    need(isinstance(p["packages"], dict) and p["packages"], "packages")
    platforms, profiles = document["platforms"], document["profiles"]
    open_items = [f"platform row {name} is unsupported" for name, row in platforms.items() if not row["supported"]]
    for name, package in p["packages"].items():
        need(isinstance(package, dict) and set(package) == PACKAGE_KEYS, f"package {name} keys")
        need(text(package["profile"]) and text(package["role"]) and text(package["case"]),
             f"package {name} profile, role and case")
        profile = profiles.get(package["profile"]) or {}
        open_items += [f"package {name}'s profile {package['profile']} is {disposition} on platform row {row}"
                       for row, disposition in profile.get("platforms", {}).items() if disposition != "runs"]
        need(name not in p["excluded"], f"package {name} is also excluded")
        need(isinstance(package["injection"], str) and package["injection"] in INJECTIONS,
             f"package {name} injection {package['injection']!r}")
        label = INJECTIONS[package["injection"]][0]
        need(package["class"] == label,
             f"package {name} labels its {package['injection']} injection {package['class']!r}, not {label!r}")
        need(package["recovery"] == WARM, f"package {name} recovers by {package['recovery']!r}: a reset or kill "
             f"recovers warm as {WARM}, and cold replacement is the actual-volume-loss control")
        role = profile.get("roles", {}).get(package["role"]) or {}
        cases = {case["id"]: case for case in role.get("cases", [])}
        need(package["case"] in cases and len(cases) == 1 and len(profile["roles"]) == 1,
             f"package {name} names no one-role, one-case profile running {package['case']!r}")
        witnesses = cases[package["case"]]["witnesses"]
        need(all(any(w.startswith(f"observe: {line} ") for w in witnesses) for line in (*WITNESS, label)),
             f"package {name}'s case declares no witness for one of its lines")
        need(all(text(package[key]) for key in ("persistence", "proxy")), f"package {name} persistence and proxy")
        authority = package["authority"]
        need(authority is None or isinstance(authority, dict) and set(authority) == {"approver", "injection"}
             and text(authority["approver"]) and authority["injection"] == package["injection"],
             f"package {name} authority is null or an approver of its own injection")
        need(isinstance(package["unrun"], dict) and all(text(v) for v in package["unrun"].values()),
             f"package {name} unrun legs")
        open_items += [item for item in gaps(p, name) if item not in open_items]
        open_items += [f"package {name} leg {leg} is unrun: {why}" for leg, why in package["unrun"].items()]
    return open_items


def gaps(p, name):
    """The open items that keep package `name` of the `packages` object `p` uncredited whatever its repeats show:
    the owner inputs it lacks and the restoration record no package binds."""
    package = p["packages"][name]
    items = ["the package interface declares no repeat count"] if p["interface"]["repeats"] is None else []
    if p["interface"]["legs"] is None:
        items.append("the package interface declares no qualified authority and coverage legs, so a repeat "
                     "recovered under a fixture authority and harness-built coverage earns no credit")
    items.append(f"no native class and credit interface: {p['owner']}")
    if package["authority"] is None:
        items.append(f"package {name} declares no injection authority")
    items.append(f"package {name} binds no record of each repeat's restoration outcome"
                 + (" or of the deployment owner's containment of the killed child's DMA"
                    if package["injection"] == "sigkill" else ""))
    items.append("no repeat binds the host's reservation and a clear custody check at its start, so a direct lane "
                 "run establishes no host exclusion")
    return items


def credit(open_items, reasons, kinds):
    """Whether a package with these open items, campaign reasons and per-kind verdicts earns credit: none of the
    first two and every kind `pass`."""
    return not (open_items or reasons) and bool(kinds) and all(v == "pass" for v in kinds.values())


def parse(data, what):
    """`data` decoded as JSON with every object's keys distinct, or a Refusal naming `what`."""
    def distinct(pairs):
        keys = [key for key, _ in pairs]
        if len(set(keys)) != len(keys):
            raise Refusal(f"{what} repeats an object key")
        return dict(pairs)

    try:
        return json.loads(data, object_pairs_hook=distinct)
    except (ValueError, TypeError, RecursionError) as error:
        raise Refusal(f"{what} is not JSON: {error}") from error


def campaign_id(digest, package, revision):
    return "package-" + hashlib.sha256(f"{digest}/{package}/{revision}".encode()).hexdigest()[:16]


def complete_lines(text):
    """The complete lines of a decoded raw artifact, split as the lane's relay splits them."""
    return text[:text.rfind("\n") + 1].splitlines()


def lines(entry, texts, names):
    """Each named line's (detail, position in the raw stderr artifact), or raise Refusal: the raw stderr artifact
    holds exactly one complete line of each name, equal to the one the receipt records, and raw stdout holds none."""
    stderr, stdout = complete_lines(texts["stderr"]), complete_lines(texts["stdout"])
    found = {}
    for name in names:
        prefix = f"observe: {name} "
        raw = [(i, line[len(prefix):]) for i, line in enumerate(stderr) if line.startswith(prefix)]
        if len(raw) != 1:
            raise Refusal(f"the raw stderr artifact holds {len(raw)} {name} lines, not one")
        if any(line.startswith(prefix) for line in stdout):
            raise Refusal(f"the raw stdout artifact holds a {name} line")
        events = [e for e in entry.get("observed", []) if isinstance(e, dict) and e.get("name") == name]
        if len(events) != 1 or events[0].get("detail") != raw[0][1]:
            raise Refusal(f"the receipt records {len(events)} {name} lines, not the one the raw stderr artifact holds")
        found[name] = (raw[0][1], raw[0][0])
    return found


def number(text, high, what, signed=False):
    """`text` as an integer within its source type, spelled as the Rust formatter spells it, or raise Refusal."""
    value = int(text)
    spelled = f"{value:+}" if signed else str(value)
    if spelled != text or not (-high - 1 if signed else 0) <= value <= high:
        raise Refusal(f"the {what} {text!r} is outside its type or not as the case prints it")
    return value


def checkpoint_fields(text):
    """A captured checkpoint's slot, session, capture, units and entries within their types, or raise Refusal."""
    match = CAPTURED_FIELDS.fullmatch(text)
    if match is None:
        raise Refusal(f"the checkpoint {text!r} is off its shape")
    slot, session, capture, units, entries = match.groups()
    return {"slot": number(slot, U32, "checkpoint slot"), "session": number(session, U64, "checkpoint session"),
            "capture": number(capture, U32, "checkpoint capture"), "units": number(units, U32, "checkpoint units"),
            "entries": number(entries, U64, "checkpoint entries")}


def hexadecimal(text, high, what):
    value = int(text, 16)
    if format(value, "x") != text or value > high:
        raise Refusal(f"the {what} 0x{text} is outside its type or not as the case prints it")
    return value


def measure(package, found):
    """The repeat's measurements from its lines, or raise Refusal for a line off its shape or a number outside its
    source type."""
    label, shape = INJECTIONS[package["injection"]]
    shapes = {"retained": RETAINED, "residual": RESIDUAL, "persisted": PERSISTED, label: shape}
    matches = {}
    for name, (detail, _) in found.items():
        match = shapes[name].fullmatch(detail)
        if match is None:
            raise Refusal(f"the {name} line {detail!r} is off its shape")
        matches[name] = match
    retained, injected, residual = matches["retained"], matches[label].groups(), matches["residual"].groups()
    split = retained["unaffected_bytes"], retained["affected_bytes"]
    if (split[0] == "unmeasured") != (split[1] == "unmeasured"):
        raise Refusal(f"the retained line measures one of its unaffected and affected bytes: {split}")
    checkpoint, installed, omitted = matches["persisted"].groups()
    m: dict[str, object] = {name: number(retained[name], high, name) for name, high in COUNTS.items()}
    m.update({
        "unaffected_bytes": None if split[0] == "unmeasured" else number(split[0], U64, "unaffected bytes"),
        "affected_bytes": None if split[1] == "unmeasured" else number(split[1], U64, "affected bytes"),
        "covered_miss": retained["covered_miss"] == "true",
        "first_hit_us": (None if retained["first_hit_us"] == "none"
                         else number(retained["first_hit_us"], U64, "first hit")),
        "session": hexadecimal(retained["session"], U64, "recovered session"),
        "checkpoint_session": hexadecimal(retained["checkpoint_session"], U64, "checkpoint session"),
        "authority": retained["authority"], "coverage": retained["coverage"], "episode": retained["episode"],
        "residuals": {name: number(residual[i], I64, name, signed=True) for i, name in enumerate(RESIDUALS)},
        "retirement": {name: number(residual[len(RESIDUALS) + i], U64, name) for i, name in enumerate(RETIREMENT)},
        "persisted": {"checkpoint": checkpoint, **checkpoint_fields(checkpoint),
                      "installed": number(installed, U64, "installed"), "omitted": number(omitted, U64, "omitted")},
    })
    if package["injection"] == "controller-disable":
        m["injection"] = {"cc": hexadecimal(injected[0], U32, "cc"), "csts": hexadecimal(injected[1], U32, "csts"),
                          "after": injected[2]}
    else:
        m["injection"] = {"signal": number(injected[0], 255, "signal"), "pid": number(injected[1], U32, "pid"),
                          "after": injected[2]}
    checkpoint_fields(m["injection"]["after"])
    return m


def verdicts(package, case, entry, m, positions):
    """The five independent verdicts of one admitted repeat."""
    def judged(*rules):
        failed = [rule for rule, holds in rules if holds is not True and holds is not None]
        if failed:
            return f"fail {failed[0]}"
        return "inconclusive" if any(holds is None for _, holds in rules) else "pass"

    injection, label = m["injection"], INJECTIONS[package["injection"]][0]
    exact = (injection["cc"] & 1 == 0 and injection["csts"] & 1 == 0 if package["injection"] == "controller-disable"
             else injection["signal"] == 9)
    persisted = m["persisted"]
    unaffected = None if m["damaged_units"] else m["unaffected_bytes"]
    return {
        "safety": judged(("ExactBytes", m["wrong"] == 0), ("CoveredObjectMisses", m["covered_miss"]),
                         ("DisjointAllocation", m["overlapping"] == 0)),
        "containment": judged(
            ("InjectionObserved", exact),
            ("PersistenceWitnessed", persisted["checkpoint"] == injection["after"]
             and positions[label] < positions["persisted"]),
            ("RestorationDeclared", entry.get("restoration") == case["restoration"]),
            ("RestorationObserved", None)),
        "retention": judged(
            ("RetainedSetServed", m["served"] == m["eligible"] > 0),
            ("RecoveredFromTheCheckpoint", m["checkpoint_session"] == persisted["session"] < m["session"]
             and positions[label] < positions["retained"]),
            ("UnaffectedBytesServed", None if unaffected is None
             else m["bytes"] == unaffected and unaffected + m["affected_bytes"] == m["eligible_bytes"]),
            ("LoadCounts", m["installed"] == persisted["installed"] and m["omitted"] == persisted["omitted"]
             and m["installed"] + m["omitted"] == persisted["entries"] == m["eligible"] + 1
             and m["installed"] == m["eligible"] + (0 if m["covered_miss"] else 1))),
        "progress": judged(("FirstWarmHit", m["first_hit_us"] is not None), ("FillAtLive", m["reserved"] > 0)),
        "residuals": judged(("ResidualsZero", not any(m["residuals"].values())),
                            ("ResidualsAfterTheInjection", positions[label] < positions["residual"])),
    }


def admit(lane, document, digest, package, run_id, path, revision):
    """One repeat's record, the host instance and volume it binds, and its build identity, or raise Refusal when its
    receipt earns no lane credit or its raw artifacts do not bind it."""
    data = gate.read_file(path, "receipt")
    receipt = parse(data, f"receipt {path}")
    record = {"receipt": {"path": path, "sha256": hashlib.sha256(data).hexdigest()}}
    profile = document["profiles"][package["profile"]]
    credited, reasons = lane.judge_profile(document["platforms"], package["profile"], profile, [receipt], digest,
                                           revision)
    if not credited:
        raise Refusal(f"uncredited: {reasons[0]}")
    section = receipt["hardware"]
    if section.get("episode") != run_id:
        raise Refusal(f"ran in episode {section.get('episode')!r}, not {run_id}")
    entry = section["cases"][0]
    case = profile["roles"][package["role"]]["cases"][0]
    start = entry.get("start")
    if not isinstance(start, dict):
        raise Refusal("the receipt records no start event, which the lane writes only under an observer log "
                      "(hardware-lane.py run --observer DIR --episode <run identity>, with a fresh log)")
    expected = {"kind": "start", "episode": run_id, "profile": package["profile"], "role": package["role"],
                "case": package["case"]}
    if any(start.get(key) != value for key, value in expected.items()):
        raise Refusal(f"the start event names {[start.get(key) for key in expected]}, not {list(expected.values())}")
    if not (gate.integer(start.get("ordinal")) and start["ordinal"] == 1):
        raise Refusal(f"the case's start is event {start.get('ordinal')!r} of its episode's log, not its first, so the "
                      "log holds an earlier event of that episode")
    mappings = entry.get("mappings") if isinstance(entry.get("mappings"), dict) else {}
    before = mappings.get("sha256")
    if not (isinstance(before, str) and gate.DIGEST.fullmatch(before) and entry.get("mappings_after") == before):
        raise Refusal("the mappings file has another digest at the case's end than before it, or none")
    instance, volume = (section.get("host") or {}).get("instance"), mappings.get("volume")
    for value, what in ((instance, "host instance"), (volume, "bound volume")):
        if not (isinstance(value, str) and value):
            raise Refusal(f"the receipt records no {what}")
    stem = Path(path).parent / lane.artifact_name(package["case"])
    raws = {kind: gate.read_file(f"{stem}.{kind}", f"raw {kind} artifact") for kind in ("stdout", "stderr")}
    record["artifacts"] = {kind: hashlib.sha256(raw).hexdigest() for kind, raw in raws.items()}
    texts = {kind: raw.decode(errors="replace") for kind, raw in raws.items()}
    output = texts["stdout"].strip() + "\n" + texts["stderr"].strip()
    if [line for line in output.splitlines() if line.startswith("test result:")] != entry.get("summary"):
        raise Refusal("the receipt's libtest summary is not the one its raw artifacts give")
    counts = entry.get("witness_counts") if isinstance(entry.get("witness_counts"), dict) else {}
    for witness in case["witnesses"]:
        if not (output.count(witness) > 0 and counts.get(witness) == output.count(witness)):
            raise Refusal(f"the raw artifacts hold {output.count(witness)} of the declared witness {witness!r} and "
                          f"the receipt counts {counts.get(witness)!r}")
    found = lines(entry, texts, (*WITNESS, INJECTIONS[package["injection"]][0]))
    for name, (detail, _) in found.items():
        for witness in case["witnesses"]:
            if witness.startswith(f"observe: {name} ") and not f"observe: {name} {detail}".startswith(witness):
                raise Refusal(f"the {name} line does not carry the declared witness {witness!r}")
    m = measure(package, found)
    if m["episode"] != run_id:
        raise Refusal(f"the retained line names episode {m['episode']!r}, not {run_id}")
    record.update(measurements=m, verdicts=verdicts(package, case, entry, m, {n: at for n, (_, at) in found.items()}))
    identity = {"row": (section.get("platform") or {}).get("row"), "toolchain": section.get("toolchain"),
                "dependencies": section.get("dependencies"), "build_environment": section.get("build_environment")}
    return record, {instance, volume}, identity


def worst(values):
    """A failed rule, then inconclusive; pass only when every repeat passed."""
    for prefix in ("fail", "inconclusive"):
        if found := sorted(v for v in values if v.startswith(prefix)):
            return found[0]
    return "pass" if values and all(v == "pass" for v in values) else "inconclusive"


def judge(document, digest, campaign, lane, campaign_sha256=None):
    """The package receipt for `campaign` under the manifest `document` whose bytes have SHA-256 `digest`."""
    check(document)
    p = document["packages"]
    if not (isinstance(campaign, dict) and set(campaign) <= CAMPAIGN_KEYS and isinstance(campaign.get("campaign"), str)
            and isinstance(campaign.get("package"), str) and campaign["package"] in p["packages"]
            and isinstance(campaign.get("runs"), list)):
        raise Refusal("the campaign is not an object naming its id, a declared package and a runs list")
    name, revision, runs, stopped = campaign["package"], campaign.get("revision"), campaign["runs"], campaign.get("stopped")
    package = p["packages"][name]
    if not (isinstance(revision, str) and COMMIT.fullmatch(revision)):
        raise Refusal("the campaign names no 40-hex revision")
    if len(runs) > MAX_REPEATS:
        raise Refusal(f"the campaign lists {len(runs)} runs, more than the {MAX_REPEATS} repeats a package may declare")
    if not all(isinstance(r, dict) and set(r) == {"repeat", "receipt"} and gate.integer(r["repeat"], 1, MAX_REPEATS)
               and isinstance(r["receipt"], str) for r in runs):
        raise Refusal("a campaign run is not {repeat, receipt}")
    if stopped is not None and not (isinstance(stopped, dict) and set(stopped) == {"repeat", "reason"}
                                    and gate.integer(stopped["repeat"], 1)):
        raise Refusal("the stop is not {repeat, reason}")
    receipt = {"envelope": ENVELOPE, "manifest_sha256": digest, "campaign_sha256": campaign_sha256,
               "judge_sha256": hashlib.sha256(gate.read_file(__file__, "judge")).hexdigest(),
               "campaign": campaign["campaign"], "package": name, "class": package["class"],
               "recovery": package["recovery"], "persistence": package["persistence"],
               "authority": package["authority"], "revision": revision, "open": gaps(p, name),
               "excluded": p["excluded"], "unrun": package["unrun"], "identity": None, "repeats": [], "reasons": []}
    reasons = receipt["reasons"]
    if campaign["campaign"] != (expected := campaign_id(digest, name, revision)):
        reasons.append(f"the campaign id is not {expected}, the one campaign of this manifest, package and revision")
    repeats = [r["repeat"] for r in runs]
    if repeats != list(range(1, len(runs) + 1)):
        reasons.append(f"the runs are repeats {repeats}, not 1 to {len(runs)} in order, each once")
    if stopped is not None:
        reasons.append(f"the campaign stopped at repeat {stopped['repeat']}: {stopped['reason']}")
        if stopped["reason"] not in p["interface"]["stop"]:
            reasons.append(f"the stop reason {stopped['reason']!r} is not on the stop roster")
        if stopped["repeat"] != len(runs):
            reasons.append(f"the campaign stopped at repeat {stopped['repeat']} and ran {len(runs)}")
    declared, legs = p["interface"]["repeats"], p["interface"]["legs"]
    if declared is not None and len(runs) != declared:
        reasons.append(f"the campaign ran {len(runs)} repeats, not the declared {declared}")
    bound, kinds, digests = set(), {kind: [] for kind in KINDS}, set()
    for run in runs:
        run_id = p["interface"]["run_identity"].format(campaign=campaign["campaign"], package=name,
                                                       repeat=run["repeat"])
        try:
            record, hardware, identity = admit(lane, document, digest, package, run_id, run["receipt"], revision)
        except gate.FAULTS as error:
            record = {"missing": f"{type(error).__name__}: {error}"}
            if not (stopped and stopped["repeat"] == run["repeat"]):
                reasons.append(f"repeat {run['repeat']} is missing evidence and the campaign records no stop at it")
            for values in kinds.values():
                values.append("inconclusive")
        else:
            bound |= hardware
            if receipt["identity"] is None:
                receipt["identity"] = identity
            elif json.dumps(identity, sort_keys=True) != json.dumps(receipt["identity"], sort_keys=True):
                reasons.append(f"repeat {run['repeat']} ran on another platform row, toolchain, dependency set or "
                               "build environment than the campaign's first admitted repeat")
            m = record["measurements"]
            if legs is not None and (m["authority"], m["coverage"]) != (legs["authority"], legs["coverage"]):
                reasons.append(f"repeat {run['repeat']} recovered under authority {m['authority']} and coverage "
                               f"{m['coverage']}, not the declared legs {legs['authority']} and {legs['coverage']}")
            evidence = {record["receipt"]["sha256"], record["artifacts"]["stderr"]}
            if evidence & digests:
                reasons.append(f"repeat {run['repeat']} shares a receipt or raw stderr artifact with an earlier repeat")
            digests |= evidence
            for kind, verdict in record["verdicts"].items():
                kinds[kind].append(verdict)
        receipt["repeats"].append({"repeat": run["repeat"], "run": run_id, **record})
    reasons += gate.safety_gaps(campaign.get("safety"), campaign["campaign"], bound)
    receipt["verdicts"] = {kind: worst(values) for kind, values in kinds.items()}
    receipt["credited"] = credit(receipt["open"], reasons, receipt["verdicts"])
    failed = any(v.startswith("fail") for v in receipt["verdicts"].values())
    receipt["verdict"] = "pass" if receipt["credited"] else "fail" if failed else "inconclusive"
    return receipt


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Judge the controller-reset package and the process-kill control of the reboot package.")
    commands = parser.add_subparsers(dest="command", required=True)
    for command in ("check", "judge"):
        commands.add_parser(command).add_argument("--manifest", default=str(MANIFEST))
    commands.choices["judge"].add_argument("--campaign", required=True)
    commands.choices["judge"].add_argument("--output")
    args = parser.parse_args(argv)
    try:
        lane = gate.lane_module()
        document, digest = gate.read_document(args.manifest, lane)
        if args.command == "check":
            print(json.dumps({"open": check(document)}, indent=1))
            return 0
        data = gate.read_file(args.campaign, "campaign")
        receipt = judge(document, digest, parse(data, f"campaign {args.campaign}"), lane,
                        hashlib.sha256(data).hexdigest())
        text = json.dumps(receipt, indent=1, sort_keys=True) + "\n"
        if args.output:
            gate.write_receipt(args.output, text)
        else:
            sys.stdout.write(text)
    except gate.FAULTS as error:
        print(f"recovery-packages: refused: {error}", file=sys.stderr)
        return 2
    return 0 if receipt["credited"] else 1


if __name__ == "__main__":
    sys.exit(main())
