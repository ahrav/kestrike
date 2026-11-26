"""Check the finite register model: safety, a reachability witness per action, per outcome and per refinement named in `register.qnt`, directed runs, and mutations of the model that its invariants reject."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "8"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "register.qnt").read_text()))
RUNS = {
    "register-run-closeRacesAnEntry": (
        ["register", "interval(0)", "intervalRacingClose(0)", "interval(0)", "register"],
        'st.ev.res == "Closed" and st.closed and st.recs.get(0).pin == 0 and st.recs.get(0).intervals == 1 and '
        'not(st.recs.get(1).claimed)'),
    "register-run-leakedGuardBlocks": (
        ["register", "leak(0)", "interval(0)", "drop(0)", "register", "interval(0)"],
        'st.ev.res == "Ok" and st.recs.get(0).intervals == 2 and st.recs.get(0).pin == 0 and not(st.recs.get(0).leaked)'),
    "register-run-limitAndReturn": (
        ["register", "register", "register", "drop(0)", "registerRacingClose"],
        'st.ev.res == "Closed" and st.closed and not(st.recs.get(0).claimed) and st.recs.get(1).claimed'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "register-mutant-registration-after-the-close": (
        "AdmittedOnlyWhileOpen", ["close", "register"],
        ('if (s.closed) result(s, "Closed", NONE)\n    else if (r == NONE)', 'if (false) result(s, "Closed", NONE)\n    else if (r == NONE)')),
    "register-mutant-registration-across-the-close": (
        "AdmittedOnlyWhileOpen", ["registerRacingClose"],
        ('else if (closing) result({...s, closed: true}, "Closed", NONE)', 'else if (false) result({...s, closed: true}, "Closed", NONE)')),
    "register-mutant-entry-across-the-close": (
        "AdmittedOnlyWhileOpen", ["register", "intervalRacingClose(0)"],
        ("val closed = s.closed or closing", "val closed = s.closed")),
    "register-mutant-refused-entry-keeps-its-pin": (
        "RefusedEntryKeepsNoNewPin", ["register", "close", "interval(0)"],
        ('recs: s.recs.set(r, {...rec, pin: INACTIVE})}, "Closed", 0)', 'recs: s.recs.set(r, {...rec, pin: ERA})}, "Closed", 0)')),
    "register-mutant-entry-clears-a-leaked-pin": (
        "RefusedEntryKeepsNoNewPin", ["register", "leak(0)", "interval(0)"],
        ('if (rec.leaked) result(s, "Leaked", 0)',
         'if (rec.leaked) result({...s, recs: s.recs.set(r, {...rec, pin: INACTIVE})}, "Leaked", 0)')),
    "register-mutant-leaked-guard-drops-its-pin": (
        "LeakedPinStays", ["register", "leak(0)"],
        ("pin: if (leaks) ERA else INACTIVE, leaked: leaks", "pin: INACTIVE, leaked: leaks")),
}


def cases(Case):
    yield Case("register-typecheck", command="typecheck", family="register")
    yield Case("register-safety", invariant="safety", family="register")
    for witness in WITNESSES:
        yield Case(f"register-reach-{witness}", invariant="unreached", expected="violation", family="register",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="register", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="register", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="register", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "register.qnt").read_text()
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
    return {"register.qnt": text, "case.qnt": f'module registerCase {{\n  import register(BOUND = {bound}).* from "./register"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "register.qnt"]
    return [quint, "verify", "case.qnt", "--main", "registerCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
