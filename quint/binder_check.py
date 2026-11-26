"""Binder model cases: exhaustive safety, reachability, broken variants and the traces the Rust replay reads."""

from pathlib import Path

CONSTANTS = {"LOCK_GAP": "false", "COOPERATING": "Set((0, 1), (1, 0))"}
# The replay runs the committed traces in this directory, relative to the repository root.
FIXTURES = "crates/kestrike/src/bind/replay_fixtures"
REPLAY_TEST = "bind::replay_tests::generated_traces_replay"
ACTIONS = ("bindOwner", "bindPreflight", "bindDeviceLock", "consultRecords", "resolveHops", "publish",
           "secondCapture", "setOverride", "unbind", "vfioBind", "bindReturn", "crash", "liveOwnerRefusal",
           "releaseOwner", "readRecord", "releaseDeviceLock", "releaseConsult", "groupGuard", "restoreUnbind",
           "restoreOverride", "restoreBind", "restoreOriginalOverride", "networkBatch", "unlink", "releaseReturn",
           "rollbackUnbind", "rollbackOverride", "rollbackBind", "rollbackOriginalOverride", "rollbackNetworkBatch",
           "rollbackReturn")
OUTCOMES = ("preflight-refused", "contention-refused", "other-owner-refused", "published", "second-capture-refused",
            "driver-refused", "bound", "crash-before-publish", "crash-after-publish", "fresh-release-refuses-missing",
            "guard-refused", "fresh-release-restores", "rolled-back", "live-owner-refused")
# Each property's broken variant: the constants or the one model text it changes.
BROKEN = {
    "lock-gap": ("OneLiveRecordPerVfioDevice", {"LOCK_GAP": "true"}, []),
    "one-way": ("OneLiveRecordPerVfioDevice", {"COOPERATING": "Set((0, 1))"}, []),
    "unrecorded-move": ("RecordBeforeDriverExit", {},
                        [("present: st.present.replaceAt(a, true),\n      records:", "present: st.present,\n      records:")]),
    "release-ignores-record": ("ReleaseRestoresOwnRecordOnly", {},
                               [("requests: st.requests.replaceAt(a, st.records.nth(a))",
                                 "requests: st.requests.replaceAt(a, DEVICES)")]),
}
# The scope of a failed bind's rollback, as an invariant of the checked instance, and the witnesses that its states
# are reached.
ROLLBACK = '''  /// A binder at a rollback write of device `d`, or at the rollback's network commands, moved that device: its
  /// bind wrote the device's override. A rollback reaches its record's removal, and its return, only with every
  /// device it moved back on its kernel driver with the override as found and, for the ENI, the four network
  /// values restored.
  val RollbackOnlyMoved = ACTORS.forall(a => and {
    DEVICES.forall(d => (st.pc.nth(a) >= 40 + 4 * d and st.pc.nth(a) <= 43 + 4 * d) implies
      st.moved.nth(a).contains(d)),
    st.pc.nth(a) == 48 implies st.moved.nth(a).contains(1),
    Set(49, 50).contains(st.pc.nth(a)) implies and {
      st.moved.nth(a).forall(d => st.driver.nth(d) == 0 and st.overrides.nth(d) == 0),
      st.moved.nth(a).contains(1) implies st.network % 16 == 15,
    },
  })
  /// Witness: a failed bind that moved both devices reaches its record's removal after its network commands.
  val neverRollsBackBoth = ACTORS.forall(a =>
    not(st.pc.nth(a) == 49 and st.moved.nth(a) == Set(0, 1) and last.act == "rollbackNetworkBatch"))
  /// Witness: a failed bind of both devices that moved the controller alone reaches its record's removal.
  val neverRollsBackTheControllerAlone = ACTORS.forall(a =>
    not(st.pc.nth(a) == 49 and st.moved.nth(a) == Set(0) and st.requests.nth(a) == Set(0, 1)))
'''
# The state a release removes its record in, as an invariant of the checked instance, and the witnesses that its
# states are reached.
UNLINK = '''  /// A release is at its record's removal only with every device its raw record names back on its kernel driver
  /// with the override as found and, when the record names the ENI, the four network values restored.
  val UnlinkOnlyAfterRestores = ACTORS.forall(a => st.pc.nth(a) == 35 implies and {
    st.releasedNames.nth(a).forall(d => st.driver.nth(d) == 0 and st.overrides.nth(d) == 0),
    st.releasedNames.nth(a).contains(1) implies st.network % 16 == 15,
  })
  /// Witness: a release that took both group guards, so found both devices on vfio-pci, reaches its record's
  /// removal.
  val neverUnlinksUnderBothGuards = ACTORS.forall(a =>
    not(st.pc.nth(a) == 35 and st.guards.nth(0) == a and st.guards.nth(1) == a))
  /// Witness: a release of a record of both devices that took no guard, as after a killed release or a bind
  /// killed before its first driver write, reaches its record's removal.
  val neverUnlinksWithNothingToUnbind = ACTORS.forall(a =>
    not(st.pc.nth(a) == 35 and st.releasedNames.nth(a) == Set(0, 1) and st.guards == [-1, -1]))
'''
CONTROLLER, ENI = 0, 1


def start(a, devices):
    """A bind through its device locks."""
    return [f"bindOwner({a}, Set({', '.join(map(str, devices))}))", f"bindPreflight({a}, true)",
            *(f"bindDeviceLock({a}, {d})" for d in devices)]


def publish(a, devices):
    """A bind from its consultation through its record."""
    return [f"consultRecords({a})", *([f"resolveHops({a})"] if ENI in devices else []), f"publish({a})"]


def move(a, d, through=4):
    """The first `through` of a bind's four steps on device `d`: second capture, override, unbind, vfio-pci bind."""
    return [f"{step}({a}, {d}, true)" for step in ("secondCapture", "setOverride", "unbind", "vfioBind")][:through]


def bind(a, devices):
    """A whole bind."""
    return start(a, devices) + publish(a, devices) + [step for d in devices for step in move(a, d)] + [f"bindReturn({a})"]


def read(a, devices):
    """A release through its consultation."""
    return [f"releaseOwner({a})", f"readRecord({a})", *(f"releaseDeviceLock({a}, {d})" for d in devices),
            f"releaseConsult({a})"]


def restore(a, d, kind="restore", start=0):
    """A restore or rollback of device `d` from step `start`: unbind, override, bind, original override."""
    return [f"{kind}{step}({a}, {d})" for step in ("Unbind", "Override", "Bind", "OriginalOverride")][start:]


def network(a, kind="networkBatch"):
    return [f"{kind}({a})"] * 4


def campaign():
    """The campaign both binders run: every action, every outcome but a refused guard, and a kill in each driver
    state of the controller."""
    a, b, both = 0, 1, [CONTROLLER, ENI]
    release_unmoved = read(a, both) + restore(a, CONTROLLER, start=3) + restore(a, ENI, start=3) + network(a) + \
        [f"unlink({a})", f"releaseReturn({a})"]
    return [
        # A kill under the controller's lock leaves no record, and a fresh release refuses.
        *start(a, [CONTROLLER]), f"crash({a})", f"releaseOwner({a})", f"readRecord({a})",
        # Binder 1 loses the controller's lock to a live binder 0, which is then killed after its record.
        *start(a, both)[:3], f"liveOwnerRefusal({a})", *start(b, both)[:3], f"bindDeviceLock({a}, {ENI})",
        *publish(a, both), f"crash({a})",
        # Binder 0's surviving record refuses binder 1, and a fresh release removes it with no device moved.
        *start(b, both), f"consultRecords({b})", *release_unmoved,
        # A release of both devices under their guards is killed after its first network command and repeated.
        *bind(a, both), *read(a, both), f"groupGuard({a}, {CONTROLLER}, true)", f"groupGuard({a}, {ENI}, true)",
        *restore(a, CONTROLLER), *restore(a, ENI), f"networkBatch({a})", f"crash({a})", *release_unmoved,
        # A refused second capture of the ENI rolls the controller back.
        *start(a, both), *publish(a, both), *move(a, CONTROLLER), f"secondCapture({a}, {ENI}, false)",
        *restore(a, CONTROLLER, "rollback"), f"unlink({a})", f"rollbackReturn({a})",
        # A refused vfio-pci bind of the ENI rolls it back from driverless and restores its network state.
        *start(a, [ENI]), *publish(a, [ENI]), *move(a, ENI, 3), f"vfioBind({a}, {ENI}, false)",
        *restore(a, ENI, "rollback", 1), *network(a, "rollbackNetworkBatch"), f"unlink({a})", f"rollbackReturn({a})",
        # Each binder holds one device, and each releases its own.
        *bind(b, [ENI]), *bind(a, [CONTROLLER]), *read(a, [CONTROLLER]), f"groupGuard({a}, {CONTROLLER}, true)",
        *restore(a, CONTROLLER), f"unlink({a})", f"releaseReturn({a})", *read(b, [ENI]),
        f"groupGuard({b}, {ENI}, true)", *restore(b, ENI), *network(b), f"unlink({b})", f"releaseReturn({b})",
        # A kill with the controller driverless: binder 1's preflight refuses and a fresh release rebinds it.
        *start(a, [CONTROLLER]), *publish(a, [CONTROLLER]), *move(a, CONTROLLER, 3), f"crash({a})",
        *start(b, [CONTROLLER])[:2], *read(a, [CONTROLLER]), *restore(a, CONTROLLER, start=1), f"unlink({a})",
        f"releaseReturn({a})",
        # A kill with the controller on vfio-pci: binder 1 refuses at preflight, is killed under the ENI's lock and
        # refuses at binder 0's record, and a fresh release restores the controller under its guard.
        *start(a, both), *publish(a, both), *move(a, CONTROLLER), f"crash({a})", *start(b, [CONTROLLER])[:2],
        *start(b, [ENI]), f"crash({b})", *start(b, [ENI]), f"consultRecords({b})", *read(a, both),
        f"groupGuard({a}, {CONTROLLER}, true)", *restore(a, CONTROLLER), *restore(a, ENI, start=3), *network(a),
        f"unlink({a})", f"releaseReturn({a})",
    ]


def fixture_recipes(family="binder"):
    """The recipe of each committed trace. `lock_gap_prefix` is the lock-gap variant's shortest violation up to the
    second binder's device lock, which the model with the lock held refuses."""
    return {"campaign": campaign(),
            "lock_gap_prefix": start(0, [CONTROLLER]) + ["consultRecords(0)"] + start(1, [CONTROLLER])}


def fixtures():
    """Each committed trace: its model and the recipe it records under `#meta.binder`."""
    return {name: ("binder.qnt", {"recipe": recipe}) for name, recipe in fixture_recipes().items()}


def cases(Case):
    yield Case("binder-typecheck", command="typecheck", family="binder")
    yield Case("binder-safety", invariant="safety", family="binder")
    yield Case("binder-campaign", invariant="safety", family="binder", recipe=campaign())
    yield Case("binder-replay", command="replay", family="binder")
    for action in ACTIONS:
        yield Case(f"binder-reach-{action}", invariant="unreached", expected="violation", family="binder",
                   extra=f'  val unreached = last.act != "{action}"\n')
    for outcome in OUTCOMES:
        yield Case(f"binder-reach-{outcome}", invariant="unreached", expected="violation", family="binder",
                   extra=f'  val unreached = st.outcome != "{outcome}"\n')
    for name, (prop, settings, mutations) in BROKEN.items():
        yield Case(f"binder-mutant-{name}", invariant=prop, expected="violation", family="binder", settings=settings,
                   mutations=mutations)
    yield Case("binder-rollback-only-moved", invariant="RollbackOnlyMoved", family="binder", extra=ROLLBACK)
    yield Case("binder-reach-rollback-of-both", invariant="neverRollsBackBoth",
               expected="violation", family="binder", extra=ROLLBACK)
    yield Case("binder-reach-rollback-of-the-controller-alone", invariant="neverRollsBackTheControllerAlone",
               expected="violation", family="binder", extra=ROLLBACK)
    yield Case("binder-mutant-rollback-follows-request", invariant="RollbackOnlyMoved", expected="violation",
               family="binder", extra=ROLLBACK,
               mutations=[("if (d == 0 and st.moved.nth(a).contains(1)) restorePc(1, true)",
                           "if (d == 0 and st.requests.nth(a).contains(1)) restorePc(1, true)")])
    yield Case("binder-mutant-rollback-skips-network", invariant="RollbackOnlyMoved", expected="violation",
               family="binder", extra=ROLLBACK,
               mutations=[("else if (st.moved.nth(a).contains(1)) 48 else 49", "else 49")])
    yield Case("binder-mutant-rollback-always-runs-network", invariant="RollbackOnlyMoved", expected="violation",
               family="binder", extra=ROLLBACK,
               mutations=[("else if (st.moved.nth(a).contains(1)) 48 else 49", "else 48")])
    yield Case("binder-mutant-rollback-keeps-override", invariant="RollbackOnlyMoved", expected="violation",
               family="binder", extra=ROLLBACK,
               mutations=[("48 else 49), overrides: st.overrides.replaceAt(d, 0) }", "48 else 49) }")])
    yield Case("binder-mutant-rollback-skips-rebind", invariant="RollbackOnlyMoved", expected="violation",
               family="binder", extra=ROLLBACK,
               mutations=[("43 + 4 * d), driver: st.driver.replaceAt(d, 0) }", "43 + 4 * d) }")])
    yield Case("binder-unlink-only-after-restores", invariant="UnlinkOnlyAfterRestores", family="binder", extra=UNLINK)
    yield Case("binder-reach-guarded-unlink", invariant="neverUnlinksUnderBothGuards",
               expected="violation", family="binder", extra=UNLINK)
    yield Case("binder-reach-unlink-with-nothing-to-unbind", invariant="neverUnlinksWithNothingToUnbind",
               expected="violation", family="binder", extra=UNLINK)
    yield Case("binder-mutant-release-skips-network", invariant="UnlinkOnlyAfterRestores", expected="violation",
               family="binder", extra=UNLINK,
               mutations=[("else if (st.requests.nth(a).contains(1)) 34 else 35", "else 35")])
    yield Case("binder-mutant-release-keeps-override", invariant="UnlinkOnlyAfterRestores", expected="violation",
               family="binder", extra=UNLINK,
               mutations=[("overrides: st.overrides.replaceAt(d, 0), releaseWrites: released(a, d) },",
                           "releaseWrites: released(a, d) },")])
    yield Case("binder-mutant-release-skips-rebind", invariant="UnlinkOnlyAfterRestores", expected="violation",
               family="binder", extra=UNLINK,
               mutations=[("29 + 4 * d), driver: st.driver.replaceAt(d, 0), releaseWrites", "29 + 4 * d), releaseWrites")])


def inputs(case, source):
    text = (source / "binder.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        turns = {}
        for at, action in enumerate(case.recipe):
            turns.setdefault(action, []).append(str(at))
        extra += "  action recipe = all {\n    turn' = turn + 1,\n    any {\n" + "".join(
            f"      all {{ Set({', '.join(at)}).contains(turn), {action} }},\n" for action, at in turns.items()) + \
            "    }\n  }\n"
    constants = {**CONSTANTS, **case.settings}
    bindings = ", ".join(f"{name} = {value}" for name, value in constants.items())
    return {"binder.qnt": text, "case.qnt": f'module binderCase {{\n  import binder({bindings}).* from "./binder"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact", REPLAY_TEST, "--nocapture"]
    if case.command == "typecheck":
        return [quint, "typecheck", "binder.qnt"]
    return [quint, "verify", "case.qnt", "--main", "binderCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


def generate(quint, output):
    """Write each fixture recipe's trace, `NAME.itf.json`, under `output`, with its recipe and the model's digest."""
    import hashlib
    import json
    import subprocess
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    for name, actions in fixture_recipes().items():
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=actions, settings={})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "binderCase", "--step", "recipe", "--backend", "typescript",
                        "--mbt", "--invariant", "safety", "--seed", "0x915", "--max-samples", "1",
                        "--max-steps", str(len(actions)), "--out-itf", str(trace)], cwd=directory, check=True)
        data = json.loads(trace.read_text())
        if len(data["states"]) != len(actions) + 1:
            raise ValueError(f"{name}: recipe stopped before its final action")
        data["#meta"] = {"binder": {"recipe": actions,
                                    "model_sha256": hashlib.sha256((source / "binder.qnt").read_bytes()).hexdigest()}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
