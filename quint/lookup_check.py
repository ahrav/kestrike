"""Check the finite lookup model: safety, a reachability witness per action, per outcome and per refinement named in `lookup.qnt`, directed runs, and mutations of the model that its invariants reject."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "8"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "lookup.qnt").read_text()))
RUNS = {
    "lookup-run-replaceUnderLease": (
        ["publish(0)", "lookup(0)", "replace(0)", "lookup(0)", "certify", "service", "drop(1)", "service"],
        'st.ev.serviced == 1 and st.objs.get(1).phase == "Returned" and st.objs.get(2).rights == 1 and st.names.get(0) == 2'),
    "lookup-run-removeThenReclaim": (
        ["publish(0)", "remove(0)", "lookup(0)", "certify", "service"],
        'st.objs.get(1).phase == "Returned" and st.ev.released == 1 and st.ev.serviced == 1 and not(st.bad)'),
    "lookup-run-expiryAndClose": (
        ["publish(0)", "publish(1)", "expire", "lookup(0)", "close", "lookup(1)", "remove(1)"],
        'st.closed and st.late and st.objs.get(2).phase == "Retired" and IDS.forall(id => st.objs.get(id).rights == 0)'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "lookup-mutant-hit-on-the-replaced-object": (
        "HitOnVisible", ["publish(0)", "replace(0)", "lookup(0)"],
        ("val id = s.names.get(k)", "val id = if (s.names.get(k) > 1) s.names.get(k) - 1 else s.names.get(k)")),
    "lookup-mutant-hit-on-the-other-key": (
        "HitOnVisible", ["publish(0)", "publish(1)", "lookup(0)"],
        ("val id = s.names.get(k)", "val id = s.names.get(1 - k)")),
    "lookup-mutant-hit-after-the-removal": (
        "HitOnVisible", ["publish(0)", "remove(0)", "lookup(0)"],
        ("{...s, era: s.era + 1, names: s.names.set(k, NONE),", "{...s, era: s.era + 1, names: s.names,")),
    "lookup-mutant-hit-past-the-deadline": (
        "HitOnVisible", ["publish(0)", "expire", "lookup(0)"],
        ('else if (s.late) result(s, "Expired", NONE)', 'else if (false) result(s, "Expired", NONE)')),
    "lookup-mutant-hit-after-the-close": (
        "HitOnVisible", ["publish(0)", "close", "lookup(0)"],
        ('if (s.closed) result(s, "Closed", NONE)', 'if (false) result(s, "Closed", NONE)')),
    "lookup-mutant-return-under-a-lease": (
        "HitRetained", ["publish(0)", "lookup(0)", "remove(0)", "certify", "service"],
        ('phase: if (not(anchored) and o.rights == 0) "Returned" else o.phase}', 'phase: if (not(anchored)) "Returned" else o.phase}')),
}


def cases(Case):
    yield Case("lookup-typecheck", command="typecheck", family="lookup")
    yield Case("lookup-safety", invariant="safety", family="lookup")
    for witness in WITNESSES:
        yield Case(f"lookup-reach-{witness}", invariant="unreached", expected="violation", family="lookup",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="lookup", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="lookup", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="lookup", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "lookup.qnt").read_text()
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
    return {"lookup.qnt": text, "case.qnt": f'module lookupCase {{\n  import lookup(BOUND = {bound}).* from "./lookup"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "lookup.qnt"]
    return [quint, "verify", "case.qnt", "--main", "lookupCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
