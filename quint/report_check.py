"""Check the finite reservation-report model: safety, a reachability witness per outcome, directed runs and mutations of each invariant."""
import re
from pathlib import Path

CONSTANTS = {"BOUND": "7"}
WITNESSES = tuple(re.findall(r"(?m)^  val (witness\w+) =", (Path(__file__).resolve().parent / "report.qnt").read_text()))
ACCEPT = 'submitReport(0, 0, "Accept")'
LATE = [ACCEPT, "timeout(0, 1)", "read(0, 1)", "post(0, true, true)", "poll(3)", "read(0, 1)"]
RUNS = {
    "report-run-lateTerminal": (
        LATE,
        'st.ev.res == "None" and st.timedOut == Set({slot: 0, gen: 1}) and st.abandoned == 0 and st.pending == 0 and '
        'ENTRIES.forall(e => st.entries.get(e) == {idle: true, snap: NOTOK})'),
    "report-run-snapshotReuse": (
        [ACCEPT, "post(0, true, true)", "poll(3)", "read(0, 1)", 'submitReport(1, 0, "Refuse")', "read(0, 1)"],
        'st.ev.res == "None" and st.healthy == Set({slot: 0, gen: 1}) and st.pending == 0 and st.tick == 0'),
    "report-run-identityRefused": (
        [ACCEPT, 'submitReport(1, 0, "Accept")', "post(1, true, false)", "post(0, false, true)", "poll(3)", "read(1, 1)"],
        'st.ev.res == "None" and st.healthy == Set() and st.pending == 0 and st.free == [2, 1, 0]'),
    "report-run-shareLeft": (
        ["submitData", "submitData", ACCEPT, 'submitReport(1, 0, "Accept")', 'submitReport(2, 0, "Accept")'],
        'st.ev.res == "TableFull" and st.free == [] and st.pending == 2 and st.spare == 1'),
    "report-run-quota": (
        ['submitReport(1, 2, "Accept")', 'submitReport(2, 2, "Accept")', 'submitReport(2, 0, "Accept")',
         'submitReport(3, 0, "Accept")'],
        'st.ev.res == "Accepted" and st.tick == 3 and st.pending == 2'),
    "report-run-stopAcrossCalls": (
        [ACCEPT, "submitData", "cancel(1, 1)", "timeout(0, 1)", 'quiesce("Pending", 3)', 'quiesce("Stopped", 1)', "poll(3)"],
        'st.ev.out == [{slot: 1, gen: 1, kind: "Abandoned", status: "None", refused: false}] and st.free == [2, 0, 1] and '
        'st.pending == 0 and st.abandoned == 0 and st.spare == 2'),
    "report-run-cancelThenTimeout": (
        [ACCEPT, "cancel(0, 1)", "timeout(0, 1)", "timeout(0, 1)", "post(0, true, true)", "poll(3)", "read(0, 1)"],
        'st.ev.res == "None" and st.timedOut == Set({slot: 0, gen: 1}) and st.abandoned == 0 and st.pending == 0'),
    "report-run-dataBesideReport": (
        ["submitData", 'submitReport(0, 0, "Accept")', "timeout(0, 1)", "post(0, false, true)", "post(1, true, true)", "poll(1)",
         "poll(3)", "read(1, 1)"],
        'st.ev.res == "Some" and st.spare == 2 and st.free == [2, 0, 1] and st.timedOut == Set()'),
    "report-run-unwoundStop": (
        ['submitReport(0, 0, "Unwind")', 'submitReport(1, 0, "Accept")', 'quiesce("Stopped", 3)'],
        'st.ev.out == [{slot: 0, gen: 1, kind: "Reservation", status: "None", refused: false}] and st.pending == 0 and '
        'st.ev.res == "DeviceStopped"'),
    "report-run-stopPastFreeSlot": (
        [ACCEPT, "submitData", "post(0, true, true)", "poll(3)", 'quiesce("Stopped", 1)'],
        'st.ev.out == [{slot: 1, gen: 1, kind: "Quiesced", status: "None", refused: false}] and '
        'st.ev.res == "DeviceStopped" and st.free == [2, 0, 1] and st.spare == 2'),
}
# Each mutation names the invariant that rejects it, the recipe that reaches the violation and the one changed text.
MUTANTS = {
    "report-mutant-late-terminal-publishes": (
        "TimedOutEstablishesNothing", LATE[:5],
        ('val earned = r.kind == "Report" and r.phase == "Accepted" and p.ok', 'val earned = r.kind == "Report" and p.ok')),
    "report-mutant-refused-identity-publishes": (
        "SnapshotOnlyAfterHealthySuccess", [ACCEPT, "post(0, true, false)", "poll(3)"],
        ("if (earned and p.valid) {slot: p.slot, gen: p.gen} else NOTOK", "if (earned) {slot: p.slot, gen: p.gen} else NOTOK")),
    "report-mutant-refusal-keeps-buffer-lent": (
        "ReserveRetained", ['submitReport(0, 0, "Refuse")'],
        ('result({...taken, recs: taken.recs.set(slot, {...EMPTY, gen: gen}),\n      entries: taken.entries.set(at, {idle: true, snap: NOTOK})}, "Refused")',
         'result({...taken, recs: taken.recs.set(slot, {...EMPTY, gen: gen})}, "Refused")')),
    "report-mutant-data-ignores-share": (
        "DataLeavesShare", ["submitData", "submitData"],
        ('else if (s.free.length() + s.pending <= SHARE) result(s, "TableFull")', 'else if (s.free.length() == 0) result(s, "TableFull")')),
    "report-mutant-quota-unchecked": (
        "TickAdvances", ['submitReport(1, 0, "Accept")', 'submitReport(1, 0, "Accept")'],
        ('else if (s.tick >= ordinal) result(s, "TickQuota")', 'else if (false) result(s, "TickQuota")')),
}


def cases(Case):
    yield Case("report-typecheck", command="typecheck", family="report")
    yield Case("report-safety", invariant="safety", family="report")
    for witness in WITNESSES:
        yield Case(f"report-reach-{witness}", invariant="unreached", expected="violation", family="report",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(name, invariant="runSafety", family="report", recipe=recipe, settings={"BOUND": str(len(recipe))},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
        yield Case(f"{name}-reached", invariant="runWitness", expected="violation", family="report", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, extra=f"  val runWitness = not(turn == {len(recipe)} and ({outcome}))\n")
    for name, (invariant, recipe, mutation) in MUTANTS.items():
        yield Case(name, invariant=invariant, expected="violation", family="report", recipe=recipe,
                   settings={"BOUND": str(len(recipe))}, mutations=[mutation])


def inputs(case, source):
    text = (source / "report.qnt").read_text()
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
    return {"report.qnt": text, "case.qnt": f'module reportCase {{\n  import report(BOUND = {bound}).* from "./report"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "report.qnt"]
    return [quint, "verify", "case.qnt", "--main", "reportCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
