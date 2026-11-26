"""Check the P7 accounting model: inductive log and slot invariants, bounded safety, refusal witnesses and controls.

An inductive case starts from every typed state of one part that satisfies that part's invariant, the other part
at its initial value, takes one step of the model and checks the invariant and the P7 properties it implies. A
mutant replaces model text and must break its invariant in that one step.
"""

CONSTANTS = {"BOUND": "8", "INIT": "init"}
INDUCTIVE = {"log": ("initLog", "LogInductive"), "slots": ("initSlots", "SlotInductive")}
WITNESSES = ("witnessRefusedChain", "witnessRefusedQueue", "witnessRefusedReserved", "witnessRefusedSlot",
             "witnessChainCleared", "witnessWrapped", "witnessQuarantined", "witnessSettled",
             "witnessTakeoverNamed", "witnessWriteBesideNamed", "witnessAbandonedPending",
             "witnessSettledByWrite")
MUTANTS = {
    # A quarantined slot goes free with no barrier: an earlier attempt may still land on a slot a capture can take.
    "grace-release": ("slots", ("    settle,\n", "    settle,\n    nondet k = SLOTS.oneOf() graceRelease(k),\n")),
    # A recorded Publish refused before sending frees its slot although a unit write of the tenure reached it.
    "abandon-frees-pending": ("slots", ('slotStep("abandonPending", { ...slots, status: slots.status.set(k, left(slots, k)) })',
                                        'slotStep("abandonPending", { ...slots, status: slots.status.set(k, "free") })')),
    # A sent Publish whose outcome is unknown is abandoned as refused before sending: the store may still apply it.
    "abandon-unknown": ("slots", ('    slots.status.get(k) == "submitted",\n    slotStep("abandonPending"',
                                  '    slots.status.get(k) == "pending",\n    slotStep("abandonPending"')),
    # A slot leaving the set goes free although a unit write of the tenure reached it.
    "left-frees-exposed": ("slots", ('if (s.exposed.contains(k)) "quarantined" else "free"', '"free"')),
    # A reservation takes a slot that is possibly named.
    "reserve-pending": ("slots", ('count(slots, "reserved") == 0, slots.status.get(k) == "free",',
                                  'count(slots, "reserved") == 0, slots.status.get(k) != "reserved",')),
    # A successor's capacity ignores the required history below its start.
    "wrap-before-floor": ("log", ("capacity: minOf(log.floor, log.reserved) + J }", "capacity: log.reserved + J }")),
    # A suffix is recorded past the chain's cap.
    "chain-uncapped": ("log", ("all { not(log.own), log.chain < CHAIN,", "all { not(log.own),")),
    # An append is acknowledged with the queue at its bound.
    "queue-uncapped": ("log", ("all { log.own, log.head < log.reserved, log.head - log.durable < QUEUE,",
                               "all { log.own, log.head < log.reserved,")),
    # An append is acknowledged at the recorded reserved end.
    "append-past-reserved": ("log", ("all { log.own, log.head < log.reserved, log.head - log.durable < QUEUE,",
                                     "all { log.own, log.head < log.capacity, log.head - log.durable < QUEUE,")),
    # An extension records an end past the capacity.
    "extend-past-capacity": ("log", ("log.own, log.reserved < end, end <= log.capacity,",
                                     "log.own, log.reserved < end,")),
}


def cases(Case):
    yield Case("saturation-typecheck", command="typecheck", family="saturation")
    yield Case("saturation-safety", invariant="safety", family="saturation")
    for part, (init, invariant) in INDUCTIVE.items():
        yield Case(f"saturation-inductive-{part}", invariant=invariant, family="saturation",
                   settings={"BOUND": "1", "INIT": init})
    for witness in WITNESSES:
        yield Case(f"saturation-reach-{witness}", invariant="unreached", expected="violation", family="saturation",
                   extra=f"  val unreached = not({witness})\n")
    for name, (part, mutation) in MUTANTS.items():
        init, invariant = INDUCTIVE[part]
        yield Case(f"saturation-mutant-{name}", invariant=invariant, expected="violation", family="saturation",
                   settings={"BOUND": "1", "INIT": init}, mutations=[mutation], trace=2)


def inputs(case, source):
    text = (source / "saturation.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    return {"saturation.qnt": text,
            "case.qnt": f'module saturationCase {{\n  import saturation(BOUND = {bound}).* from "./saturation"\n'
                        f'{case.extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "saturation.qnt"]
    init = case.settings.get("INIT", CONSTANTS["INIT"])
    if init not in ("init", "initLog", "initSlots"):
        raise ValueError(f"{case.name}: unknown initial action {init}")
    return [quint, "verify", "case.qnt", "--main", "saturationCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant,
            "--init", init]
