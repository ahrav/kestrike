"""Key-operation model cases: typecheck, free-scheduler safety, each property, reachability witnesses, the directed
runs, the planted mutations and the committed traces the Rust replay reads.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe and its last state holds the run's outcome, and the run's reach case shows the recipe
ends in a state holding that outcome. A mutant replaces model text and must violate its named property first at the
last step of its recipe; the runner requires the violation's trace to hold that step's states plus the initial one.
`generate` writes each run's trace, which `crates/kestrike/src/storage/keyops_fixtures` holds and
`storage::keyops_replay_tests` replays against `Storage` and feeds to the history oracle.
"""

from pathlib import Path

CONSTANTS = {"BOUND": "16", "UNITS": "3"}
# The instance every recipe runs at. A trace of it holds at most two reserved fills, the two labels of one key the
# history oracle's domain admits, and still reaches a reservation refused for space.
TWO = {"UNITS": "2"}
INVARIANTS = ("HitIsLive", "NoServeAtDeadline", "ExpiredIsLapsed", "PublishComplete", "RevokedNeverPublishes", "ReuseAtZero", "EvictNoReuse",
              "RejectOwnsNothing", "RefusalKeepsIncumbent", "OneMapping", "OneAttempt", "UnitsConserved", "RemovalLegal",
              "ClosedAdmitsNothing")
# The witnesses the free scheduler reaches at BOUND 12, the last at two units, where two held slots refuse a third fill.
WITNESSES = ("witnessHit", "witnessExpired", "witnessReplaced", "witnessRevoked", "witnessSuperseded", "witnessIncomplete",
             "witnessLatePublish", "witnessSwept", "witnessEvicted", "witnessReplacing", "witnessHeld", "witnessLateTerminal",
             "witnessInProgress", "witnessFillSlotsFull", "witnessRetainLimit", "witnessClosedRefusal", "witnessCleanReserve")
WITNESS_SETTINGS = {"witnessCleanReserve": TWO}


def filled(n, slot, ok="true"):
    """A grant of attempt `n`, its reservation of `slot`, its submit and the write's terminal."""
    return ["begin", f"reserve({n})", f"receive({n})", f"writeDone({slot}, {ok})"]


# Attempt 1 published on slot 0 under deadline 2, its publisher holding the first lease.
PUBLISHED = filled(1, 0) + ["publish(1, 2)"]
# Each run, its recipe and the outcome its last state holds.
RUNS = {
    # A fill publishes, a lookup hits to the right limit, the deadline passes, the sweep waits for the last lease and
    # then removes the object, service returns the unit after a certification, and a second fill reuses it.
    "expiry": (filled(1, 0) + ["publish(1, 1)", "lookup", "lookup", "release(0)", "expire", "tick", "lookup", "expire",
                               "release(0)", "expire", "service", "certify", "service"] + filled(2, 0)
               + ["publish(2, 2)", "lookup"],
               'witnessReused and ev.res == "Hit" and ev.label == 2 and st.ended == Set(1)'),
    # An eviction finds the leased incumbent held while its replacement uploads; the publication replaces the
    # incumbent under its publisher's lease, which holds the retired unit through a service visit, so a third fill
    # finds no unit, and the unit returns once the lease is released.
    "replace": (PUBLISHED + ["begin", "reserve(2)", "receive(2)", "evict", "writeDone(1, true)", "publish(2, 2)", "lookup",
                             "certify", "service", "serviceFills", "begin", "reserve(3)", "release(0)", "service",
                             "release(1)", "release(1)"],
                'ev.res == "Released" and st.ledger == { free: 1, reserved: 0, resident: 1, retired: 0 } '
                "and st.ended == Set(1) and st.pubs.size() == 2"),
    # An invalidation ends the mapping and revokes the attempt uploading beside it: the table refuses a third record
    # until service frees a departed one, and the revoked fill's publication is refused.
    "revoke": (PUBLISHED + ["release(0)", "begin", "begin", "reserve(2)", "receive(2)", "writeDone(1, true)", "invalidate",
                            "lookup", "begin", "serviceFills", "begin", "publish(2, 2)", "certify", "service"],
               'ev.res == "Returned" and st.ledger.free == 2 and st.voided == Set(2) and st.pubs.size() == 1'),
    # An invalidation revokes an attempt before its receive, which is refused and whose abort returns the unit at
    # once; a failed write leaves the next fill unpublishable, and its record stays the key's attempt until fill
    # service frees it.
    "refuse": (["begin", "reserve(1)", "invalidate", "receive(1)", "abort(1)", "lookup"] + filled(2, 0, "false")
               + ["publish(2, 2)", "begin", "service", "serviceFills", "begin"],
               'ev.res == "Granted" and st.ledger.free == 2 and st.voided == Set(1) and st.pubs.size() == 0'),
    # An aborted fill's outstanding write holds its unit past a service visit and past the next publication; its
    # late terminal lets service return the unit.
    "abandon": (["begin", "reserve(1)", "receive(1)", "abort(1)", "service", "begin", "serviceFills"] + filled(2, 1)
                + ["publish(2, 2)", "writeDone(0, true)", "service", "lookup"],
                'ev.res == "Hit" and st.ledger == { free: 1, reserved: 0, resident: 1, retired: 0 }'),
    # An eviction is refused while an attempt is current; that attempt's publication past its deadline is refused and
    # the incumbent keeps serving; the eviction then removes the unleased incumbent, and after a close a reservation
    # is refused.
    "evict": (PUBLISHED + ["evict", "release(0)", "begin", "evict", "reserve(2)", "receive(2)", "writeDone(1, true)",
                           "tick", "publish(2, 1)", "lookup", "release(0)", "evict", "lookup", "certify", "service",
                           "serviceFills", "begin", "close", "reserve(3)"],
              'ev.res == "Closed" and st.ledger.free == 2 and st.ended == Set(1) and st.pubs.size() == 1'),
    # Close refuses a receive, a grant, a lookup and an invalidation, leaves the held leases valid, and two
    # close-service calls drain the storage.
    "close": (PUBLISHED + ["lookup", "begin", "reserve(2)", "close", "receive(2)", "begin", "lookup", "invalidate",
                           "publish(2, 2)", "closeService", "release(0)", "release(0)", "closeService"],
              "witnessDrained"),
    # A written fill's publication after close is refused and close service returns its unit.
    "shut": (filled(1, 0) + ["lookup", "close", "publish(1, 2)", "closeService"],
             'ev.res == "Returned" and st.ledger.free == 2 and st.pubs.size() == 0 and st.fills.size() == 0'),
}
# Each mutant: the property it must break, its recipe and its replacements of the model's text.
MUTANTS = {
    # An invalidation that records the end and keeps the mapping: the next lookup hits the ended label.
    "invalidate-keeps-mapping": ("HitIsLive", PUBLISHED + ["invalidate", "release(0)", "lookup"],
                                 [("val unmapped = found.fold(st, (acc, i) => unmap(acc, i))",
                                   "val unmapped = { ...st, ended: st.ended.union(found.map(i => st.slots.get(i).label)) }")]),
    # A lookup that serves at the deadline's second.
    "lookup-serves-at-deadline": ("NoServeAtDeadline", filled(1, 0) + ["publish(1, 1)", "release(0)", "tick", "lookup"],
                                  [('else if (st.clock >= st.slots.get(v).deadline) "Expired"',
                                    'else if (st.clock > st.slots.get(v).deadline) "Expired"')]),
    # A publication admitted at its deadline's second.
    "publish-at-deadline": ("NoServeAtDeadline", filled(1, 0) + ["tick", "publish(1, 1)"],
                            [('else if (st.clock >= d) "Expired"', 'else if (st.clock > d) "Expired"')]),
    # A lookup that answers Expired one second early.
    "expired-early": ("ExpiredIsLapsed", filled(1, 0) + ["publish(1, 1)", "lookup"],
                      [('else if (st.clock >= st.slots.get(v).deadline) "Expired"',
                        'else if (st.clock + 1 >= st.slots.get(v).deadline) "Expired"')]),
    # A publication that only requires the write submitted.
    "publish-before-terminal": ("PublishComplete", ["begin", "reserve(1)", "receive(1)", "publish(1, 2)"],
                                [('val res = if (slot.write != "ok") "Incomplete"', 'val res = if (slot.write == "none") "Incomplete"')]),
    # A publication that accepts a failed write.
    "publish-after-failure": ("PublishComplete", filled(1, 0, "false") + ["publish(1, 2)"],
                              [('val res = if (slot.write != "ok") "Incomplete"',
                                'val res = if (slot.write != "ok" and slot.write != "failed") "Incomplete"')]),
    # A publication that ignores its attempt's revocation.
    "publish-ignores-revocation": ("RevokedNeverPublishes", filled(1, 0) + ["invalidate", "publish(1, 2)"],
                                   [('else if (f.revoked) "Superseded"\n              else if (st.clock >= d)',
                                     'else if (st.clock >= d)')]),
    # A service visit that returns a slot whatever its count.
    "service-ignores-count": ("ReuseAtZero", PUBLISHED + ["invalidate", "certify", "service"],
                              [("else if (refs(unanchored, slot) == 0) returned(unanchored, slot) else unanchored",
                                "else returned(unanchored, slot)")]),
    # A service visit that releases an anchor no certification covered.
    "service-skips-grace": ("ReuseAtZero", PUBLISHED + ["release(0)", "invalidate", "service"],
                            [("val anchored = old.anchor and not(old.cert)", "val anchored = false")]),
    # A replacement that returns the incumbent's unit at once, under its lease.
    "replace-frees-incumbent": ("EvictNoReuse", PUBLISHED + filled(2, 1) + ["publish(2, 2)"],
                                [("val displaced = incumbents.fold(gone, (acc, i) => unmap(acc, i))",
                                  "val displaced = incumbents.fold(gone, (acc, i) => returned(unmap(acc, i), i))")]),
    # An abort that cancels a fill whose write is outstanding.
    "abort-cancels-written": ("EvictNoReuse", ["begin", "reserve(1)", "receive(1)", "abort(1)"],
                              [('if (f.slot < 0) gone else if (st.slots.get(f.slot).write == "none") returned(gone, f.slot)',
                                "if (f.slot < 0) gone else if (true) returned(gone, f.slot)")]),
    # A reservation refused as superseded that keeps the slot it claimed.
    "refused-reserve-keeps-slot": ("RejectOwnsNothing", ["begin", "invalidate", "reserve(1)"],
                                   [('if (res == "Reserved") claimed else setFill(st, { ...f, departed: true })',
                                     'if (res == "Reserved" or res == "Superseded") claimed else setFill(st, { ...f, departed: true })')]),
    # A receive refused as revoked that still submits its write.
    "refused-receive-submits": ("RejectOwnsNothing", ["begin", "reserve(1)", "invalidate", "receive(1)"],
                                [('        if (res == "Submitted") { ...st, slots: st.slots.set(f.slot,',
                                  '        if (res != "Closed") { ...st, slots: st.slots.set(f.slot,')]),
    # A publication refused past its deadline that still displaces the incumbent.
    "refused-publish-displaces": ("RefusalKeepsIncumbent", PUBLISHED + ["release(0)"] + filled(2, 1) + ["tick", "publish(2, 1)"],
                                  [('val disposed = if (slot.write == "none") returned(gone, f.slot) else retire(gone, f.slot)',
                                    'val disposed = if (slot.write == "none") returned(gone, f.slot) else retire(displaced, f.slot)')]),
    # A publication that leaves the incumbent mapped.
    "publish-keeps-incumbent": ("OneMapping", PUBLISHED + filled(2, 1) + ["publish(2, 2)"],
                                [("val displaced = incumbents.fold(gone, (acc, i) => unmap(acc, i))", "val displaced = gone")]),
    # A grant that ignores the key's current attempt.
    "begin-ignores-current": ("OneAttempt", ["begin", "begin"],
                              [('else if (st.fills.exists(f => not(f.revoked))) "InProgress"', 'else if (false) "InProgress"')]),
    # A return that leaves the ledger as it was.
    "return-skips-ledger": ("UnitsConserved", ["begin", "reserve(1)", "abort(1)"],
                            [('ledger: move(s.ledger, term(old.state), "free") }', "ledger: s.ledger }")]),
    # An expiry sweep that ignores the deadline.
    "expire-ignores-deadline": ("RemovalLegal", PUBLISHED + ["release(0)", "expire"],
                                [("val due = resident(st).filter(x => refs(st, x) == 1 and st.clock >= st.slots.get(x).deadline)",
                                  "val due = resident(st).filter(x => refs(st, x) == 1)")]),
    # An expiry sweep that removes a leased object.
    "expire-removes-leased": ("RemovalLegal", filled(1, 0) + ["publish(1, 1)", "tick", "expire"],
                              [("val due = resident(st).filter(x => refs(st, x) == 1 and st.clock >= st.slots.get(x).deadline)",
                                "val due = resident(st).filter(x => st.clock >= st.slots.get(x).deadline)")]),
    # An eviction that ignores the key's current attempt.
    "evict-ignores-attempt": ("RemovalLegal", PUBLISHED + ["release(0)", "begin", "evict"],
                              [('else if (replacing) "Replacing"', 'else if (false) "Replacing"')]),
    # A lookup that ignores the close.
    "lookup-ignores-close": ("ClosedAdmitsNothing", PUBLISHED + ["release(0)", "close", "lookup"],
                             [('val res = if (st.closed) "Closed" else if (found.size() == 0) "Missing"',
                               'val res = if (false) "Closed" else if (found.size() == 0) "Missing"')]),
}


def cases(Case):
    yield Case("keyops-typecheck", command="typecheck", family="keyops")
    yield Case("keyops-safety", invariant="safety", family="keyops")
    yield Case("keyops-safety-two-units", invariant="safety", family="keyops", settings=TWO)
    yield Case("keyops-replay", command="replay", family="keyops")
    for name in INVARIANTS:
        yield Case(f"keyops-{name}", invariant=name, family="keyops", settings={"BOUND": "12"})
    for witness in WITNESSES:
        yield Case(f"keyops-reach-{witness}", invariant="unreached", expected="violation", family="keyops",
                   settings={"BOUND": "12", **WITNESS_SETTINGS.get(witness, {})}, extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        settings = {"BOUND": str(len(recipe)), **TWO}
        yield Case(f"keyops-run-{name}", invariant="runSafety", family="keyops", recipe=recipe, settings=settings,
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"keyops-run-{name}-reached", invariant="unreached", expected="violation", family="keyops",
                   recipe=recipe, settings=settings,
                   extra=f"  val unreached = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (prop, recipe, mutations) in MUTANTS.items():
        yield Case(f"keyops-mutant-{name}", invariant=prop, expected="violation", family="keyops", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **TWO}, mutations=mutations, trace=len(recipe) + 1)


def inputs(case, source):
    text = (source / "keyops.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    units = case.settings.get("UNITS", CONSTANTS["UNITS"])
    return {"keyops.qnt": text,
            "case.qnt": f'module keyopsCase {{\n  import keyops(BOUND = {bound}, UNITS = {units}).* from "./keyops"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "replay":
        return ["cargo", "test", "-p", "kestrike", "--lib", "--", "--ignored", "--exact",
                "storage::keyops_replay_tests::generated_keyops_traces_replay", "--nocapture"]
    if case.command == "typecheck":
        return [quint, "typecheck", "keyops.qnt"]
    return [quint, "verify", "case.qnt", "--main", "keyopsCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])


def fixture_recipes(family):
    """Each committed trace's recipe: every run's."""
    return {name: recipe for name, (recipe, _) in RUNS.items()}


def fixtures():
    """Each committed trace: its model and the recipe it records under `#meta.keyops`."""
    return {name: ("keyops.qnt", {"recipe": recipe}) for name, recipe in fixture_recipes("keyops").items()}


def generate(quint, output):
    """Write each run's trace, with its recipe and the model's digest, into the new directory `output`."""
    import hashlib
    import json
    import subprocess
    from types import SimpleNamespace
    source = Path(__file__).resolve().parent
    for name, (recipe, _) in RUNS.items():
        case = SimpleNamespace(name=name, mutations=[], extra="", recipe=recipe, settings={"BOUND": str(len(recipe)), **TWO})
        directory = output / name
        directory.mkdir(parents=True)
        for filename, text in inputs(case, source).items():
            (directory / filename).write_text(text)
        trace = output / (name + ".itf.json")
        subprocess.run([quint, "run", "case.qnt", "--main", "keyopsCase", "--step", "recipe", "--backend", "typescript",
                        "--mbt", "--invariant", "safety", "--seed", "0x1169", "--max-samples", "1",
                        "--max-steps", str(len(recipe)), "--n-traces", "1", "--out-itf", str(trace)],
                       cwd=directory, check=True, timeout=60)
        try:
            data = json.loads(trace.read_text())
        except (OSError, ValueError) as error:
            raise ValueError(f"{name}: Quint wrote no readable trace: {error}") from error
        if len(data["states"]) != len(recipe) + 1:
            raise ValueError(f"{name}: recipe stopped before its final action")
        data["#meta"] = {"keyops": {"recipe": recipe, "model_sha256": hashlib.sha256((source / "keyops.qnt").read_bytes()).hexdigest()}}
        trace.write_text(json.dumps(data, separators=(",", ":")) + "\n")


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--quint", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    generate(args.quint, args.output.resolve())
