"""Check the finite reclaim model: safety, a reachability witness per action, per outcome and per refinement named in `reclaim.qnt`, directed runs, and mutations of the model that its invariants reject."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "11"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "reclaim.qnt").read_text()))
ANCHOR_LAST = ["unlease", "retire", "certify", "certify", "service"]
PINNED = ["enter(0)", "unlease", "retire", "certify", "certify", "service"]
RUNS = {
    "reclaim-run-anchorLast": (
        ANCHOR_LAST,
        'st.ev.returned and st.ev.released and st.phase == "Free" and st.certified == 2 and st.returns == 1'),
    "reclaim-run-rightLast": (
        ["retire", "certify", "certify", "service", "unlease", "service"],
        'st.ev.returned and not(st.ev.released) and st.phase == "Free" and st.returns == 1'),
    "reclaim-run-pinnedReaderHolds": (
        PINNED + ["exit(0)", "certify", "certify", "service"],
        'st.ev.returned and st.ev.released and st.certified == 2 and st.phase == "Free"'),
    "reclaim-run-reuse": (
        ANCHOR_LAST + ["republish"] + ANCHOR_LAST + ["republish"],
        'st.inc == 3 and st.phase == "Resident" and st.era == 3 and st.rights == 1'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "reclaim-mutant-return-under-a-right": (
        "ReadersPrecedeReuse", ["retire", "certify", "certify", "service"],
        ("val returns = not(anchored) and s.rights == 0", "val returns = not(anchored)")),
    "reclaim-mutant-bound-ignores-the-pins": (
        "ReadersPrecedeReuse", PINNED,
        ("val bound = least(s.pass.start, s.pass.low)", "val bound = s.pass.start")),
    "reclaim-mutant-release-at-the-certified-era": (
        "ReadersPrecedeReuse", PINNED,
        ("val releases = s.anchored and s.stamp < s.certified", "val releases = s.anchored and s.stamp <= s.certified")),
    "reclaim-mutant-return-keeps-the-slot-retired": (
        "ReturnsOnce", ANCHOR_LAST + ["service"],
        ('phase: if (returns) "Free" else s.phase,', "phase: s.phase,")),
    "reclaim-mutant-republish-keeps-the-incarnation": (
        "ReusedAsNext", ANCHOR_LAST + ["republish"],
        ('result({...s, inc: s.inc + 1, phase: "Resident"', 'result({...s, inc: s.inc, phase: "Resident"')),
}


def cases(Case):
    yield Case("reclaim-typecheck", command="typecheck", family="reclaim")
    yield Case("reclaim-safety", invariant="safety", family="reclaim")
    for witness in WITNESSES:
        yield Case(f"reclaim-reach-{witness}", invariant="unreached", expected="violation", family="reclaim",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="reclaim", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="reclaim", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="reclaim", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "reclaim.qnt").read_text()
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
    return {"reclaim.qnt": text, "case.qnt": f'module reclaimCase {{\n  import reclaim(BOUND = {bound}).* from "./reclaim"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "reclaim.qnt"]
    return [quint, "verify", "case.qnt", "--main", "reclaimCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
