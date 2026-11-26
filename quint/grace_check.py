"""Check the finite grace model: safety, a reachability witness per outcome, directed runs, and mutations of the model that its invariant rejects."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "10"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "grace.qnt").read_text()))
READER_FIRST = ["pin(0)", "observe(0)", "remove", "retire", "begin", "visit", "visit", "complete", "release"]
RUNS = {
    "grace-run-readerBeforePass": (
        READER_FIRST,
        'st.ev.res == "Held" and st.certified == 1 and st.stamp == 1 and st.copies.get(0) and not(st.released)'),
    "grace-run-passBeforeReader": (
        ["begin", "visit", "pin(0)", "observe(0)", "visit", "remove", "retire", "complete", "release"],
        'st.ev.res == "Held" and st.certified == 1 and st.stamp == 1 and st.copies.get(0) and not(st.released)'),
    "grace-run-releaseAfterUnpin": (
        READER_FIRST + ["unpin(0)", "begin", "visit", "visit", "complete", "release", "reuse"],
        'st.reused and st.certified == 2 and READERS.forall(r => not(st.copies.get(r)))'),
    "grace-run-terminalRefusesPins": (
        ["pin(0)", "elsewhere", "elsewhere", "pin(1)", "pin(0)"],
        'st.ev.res == "Terminal" and st.pins.get(0) == 1 and st.pins.get(1) == 0 and st.era == 3'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "grace-mutant-release-at-the-certified-era": (
        "Protected", READER_FIRST,
        ("if (s.stamp < s.certified) result(", "if (s.stamp <= s.certified) result(")),
    "grace-mutant-certify-from-an-incomplete-pass": (
        "Protected", ["pin(1)", "observe(1)", "remove", "retire", "begin", "visit", "complete", "release"],
        ("st.pass.next == RECORDS, st' = completed(", "st.pass.next >= 1, st' = completed(")),
    "grace-mutant-bound-ignores-the-pins": (
        "Protected", READER_FIRST,
        ("val bound = least(s.pass.start, s.pass.low)", "val bound = s.pass.start")),
    "grace-mutant-retire-before-the-removal": (
        "Protected", ["retire", "pin(0)", "observe(0)", "begin", "visit", "visit", "complete", "release"],
        ("st.stamp == 0, not(st.visible), st' = retired(", "st.stamp == 0, st' = retired(")),
}


def cases(Case):
    yield Case("grace-typecheck", command="typecheck", family="grace")
    yield Case("grace-safety", invariant="safety", family="grace")
    for witness in WITNESSES:
        yield Case(f"grace-reach-{witness}", invariant="unreached", expected="violation", family="grace",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="grace", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="grace", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="grace", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "grace.qnt").read_text()
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
    return {"grace.qnt": text, "case.qnt": f'module graceCase {{\n  import grace(BOUND = {bound}).* from "./grace"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "grace.qnt"]
    return [quint, "verify", "case.qnt", "--main", "graceCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
