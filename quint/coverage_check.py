"""Coverage model cases: typecheck, each safety invariant, reachability witnesses, the directed runs and the planted
mutations.

A run is a recipe of model actions that restricts the scheduler to one schedule; it passes only when TLC checks
`safety` over the whole recipe, one state per action after `init`, and its last state holds the run's outcome. Runs
start with every page unfenced. The other cases start with tenure 1's pages fenced, so the free scheduler reaches a
later tenure's fences after an earlier tenure's acknowledgment; `coverage-safety-unfenced`, `fence-unconditional` and
`invalidate-before-fenced` start unfenced.

- `successorRefusesAckedFill`: tenure 1 acknowledges INVALIDATE(1, 1); tenure 2 fences both pages, adopts the entry
  and refuses FILL(1, 1).
- `successorRefusesAckedFillsOnBothPages`: the acknowledged entries on both pages reach tenure 2's coverage, and
  tenure 2 refuses both FILLs.
- `coverLosesToSuccessorFence`: tenure 1's coverage write, submitted before tenure 2 fences both pages and applied
  after, fails on the version; tenure 1's re-read shows the newer fence, and tenure 1 withdraws and never acknowledges.
- `confirmAfterFenceTimeout`: a fence's reply times out, the next read shows the tenure's own fence, and the tenure
  adopts the page only on the confirming write's acknowledged success.
- `newerFenceWithdraws`: a fence read finds a newer tenure's fence, and the reader withdraws without adopting.
- `saturationCoveredInFlight`: an INVALIDATE beyond `CPAGE` writes its page saturated, and the saturation is in the
  tenure's coverage while the write is in flight.
- `ackBeforeSuccessorFence`: tenure 1 acknowledges before tenure 2 fences the page, and tenure 2 adopts the entry.
- `successorFenceBeforeCover`: tenure 2's fence commits before tenure 1's coverage write applies; the write fails,
  tenure 1's re-read withdraws it with no acknowledgment, and tenure 2's coverage holds nothing of tenure 1.
- `rereadAfterCondition`: a retry on the basis a timeout left stale fails its condition; the re-read supplies the
  current version, and the fresh write is acknowledged.
- `saturateAfterReject`: the store rejects a coverage write as oversized; the tenure re-reads, writes the page
  saturated with no entries, and acknowledges on that write's success.
- `carryAfterConfirm`: tenure 2's fence of the page that tenure 1 acknowledged on commits but times out; the next
  read shows tenure 2's own fence, the confirming write adopts the entry, and tenure 2 refuses the covered FILL.
- `fenceLosesRace`: tenure 2's fence, read before tenure 1's coverage write applies, fails its condition; the fresh
  fence adopts the acknowledged entry, and tenure 2 refuses the covered FILL.
- `successorRefusesFillOfAckedResident`: tenure 1 fills (1, 1) and acknowledges INVALIDATE(1, 1); tenure 2, whose
  coverage starts empty, fences both pages and refuses the FILL of (1, 1), so the covered version never becomes
  resident under tenure 2.
- `successorAdmitsUncoveredKey`: tenure 1 fills (2, 1) and acknowledges INVALIDATE(1, 1); tenure 2 fences both pages,
  admits the FILL of the uncovered (2, 1) and refuses the covered (1, 1).
- `fencedBeforeFirstFill`: tenure 2 fences every page before its first FILL admission, refuses the FILL of the version
  tenure 1's acknowledged INVALIDATE covers and admits an uncovered one.
"""

CONSTANTS = {"BOUND": "9", "TENURES": "2", "FENCED_FIRST": "true"}
UNFENCED = {"FENCED_FIRST": "false"}
INVARIANTS = ("NoAckBeforeAuthoritative", "CoverageNeverDecreases", "FencedCoverageComplete", "NoCoveredResidency",
              "FenceOrder", "NoAdoptionFromUnknown")
WITNESSES = ("witnessFencedAll", "witnessCarryForward", "witnessConfirmed", "witnessWithdrawn",
             "witnessCommittedTimeout", "witnessFillRefused", "witnessAck", "witnessSaturated")
MUTANTS = {
    "fence-on-read": ("FencedCoverageComplete", ("val readAdopts = false", "val readAdopts = true")),
    "fence-on-read-order": ("FenceOrder", ("val readAdopts = false", "val readAdopts = true")),
    "ack-before-cas": ("NoAckBeforeAuthoritative",
                       ("acks' = acks, resident' = resident.exclude(Set((t, k, v))),",
                        "acks' = acks.union(Set({ t: t, k: k, v: v, id: nextId })), "
                        "resident' = resident.exclude(Set((t, k, v))),")),
    "adopt-own-fence-on-read": ("NoAdoptionFromUnknown", ("val ownReadAdopts = false", "val ownReadAdopts = true")),
    "fill-before-fenced": ("NoCoveredResidency", ("val ready = fenced.get(t) == PAGES", "val ready = true")),
    "cover-after-submit": ("NoCoveredResidency",
                           ("cov' = cov.set(t, extend(cov.get(t), p, value)),", "cov' = cov,")),
    "fence-unconditional": ("CoverageNeverDecreases", ("val newer = pg.fence > t", "val newer = false")),
    "fence-adopts-empty": ("FencedCoverageComplete",
                           ("val absorbed = r.value", "val absorbed = { ...r.value, entries: Set() }")),
    "invalidate-before-fenced": ("NoAckBeforeAuthoritative",
                                 ("live(t), fenced.get(t) == PAGES, not(awaiting(t, p)), nextId <= REQUESTS, tick,",
                                  "live(t), not(awaiting(t, p)), nextId <= REQUESTS, tick,")),
    "ack-on-committed-timeout": ("NoAckBeforeAuthoritative",
                                 ("keepFills, withdrawn' = withdrawn,\n    acks' = acks,",
                                  "keepFills, withdrawn' = withdrawn,\n    acks' = if (r.kind == \"cover\" and "
                                  "results.keys().contains(r.id) and results.get(r.id).ok) "
                                  "acks.union(Set({ t: r.t, k: r.k, v: r.v, id: r.id })) else acks,")),
    "cover-drops-entry": ("NoAckBeforeAuthoritative",
                          ("else { ...pg, entries: grown, ver: pg.ver + 1 }", "else { ...pg, ver: pg.ver + 1 }")),
    "ack-on-failed-reply": ("NoAckBeforeAuthoritative",
                            ("withdrawn' = withdrawn, keepCoverage, acks' = acks, adoptions' = adoptions, "
                             "succeeded' = succeeded,",
                             "withdrawn' = withdrawn, keepCoverage, acks' = if (r.kind == \"cover\") "
                             "acks.union(Set({ t: r.t, k: r.k, v: r.v, id: r.id })) else acks, adoptions' = adoptions, "
                             "succeeded' = succeeded.union(Set(r.id)),")),
}
MUTANT_SETTINGS = {"fence-unconditional": UNFENCED, "invalidate-before-fenced": UNFENCED}


def fence(t, p, at):
    """Tenure `t` fences page `p` with request `at`: read and submit, apply, and the acknowledged success."""
    return [f"fence({t}, {p})", f"applyId({at})", f"replyId({at})"]


def invalidate(t, k, v, at):
    """Tenure `t` acknowledges INVALIDATE(k, v) through request `at`."""
    return [f"invalidate({t}, {k}, {v})", f"applyId({at})", f"replyId({at})"]


FIRST = fence(1, 0, 1) + fence(1, 1, 2)
RUNS = {
    "successorRefusesAckedFill": (FIRST + invalidate(1, 1, 1, 3) + fence(2, 0, 4) + fence(2, 1, 5)
                                  + ["fill(2, 1, 1)"],
                                  "refused == Set((2, 1, 1)) and acks.exists(a => a.t == 1) "
                                  "and covered(cov.get(2), 1, 1)"),
    "successorRefusesAckedFillsOnBothPages": (FIRST + invalidate(1, 1, 1, 3) + invalidate(1, 2, 1, 4) + fence(2, 0, 5)
                                              + fence(2, 1, 6) + ["fill(2, 1, 1)", "fill(2, 2, 1)"],
                                              "acks.size() == 2 and refused == Set((2, 1, 1), (2, 2, 1))"),
    "coverLosesToSuccessorFence": (FIRST + ["invalidate(1, 1, 1)"] + fence(2, 0, 4) + fence(2, 1, 5)
                                   + ["applyId(3)", "replyId(3)", "reread(1, 0)"],
                                   "withdrawn == Set(1) and acks == Set() and fenced.get(2) == PAGES"),
    "confirmAfterFenceTimeout": (["fence(1, 0)", "applyId(1)", "timeoutId(1)", "fence(1, 0)", "applyId(2)",
                                  "replyId(2)"],
                                 "timedOut == Set(1) and adoptions == Set({ t: 1, p: 0, basis: 2 })"),
    "newerFenceWithdraws": (fence(2, 0, 1) + ["fence(1, 0)"],
                            "withdrawn == Set(1) and adoptions.forall(a => a.t == 2)"),
    "saturationCoveredInFlight": (FIRST + invalidate(1, 1, 1, 3) + ["invalidate(1, 3, 1)"],
                                  "inflight.exists(r => r.id == 4 and r.value.sat and r.value.entries == Set()) "
                                  "and cov.get(1).sat == Set(0) and not(pages.get(0).sat)"),
    "ackBeforeSuccessorFence": (FIRST + invalidate(1, 1, 1, 3) + fence(2, 0, 4),
                                "fenced.get(2) == Set(0) and covered(cov.get(2), 1, 1)"),
    "successorFenceBeforeCover": (FIRST + ["invalidate(1, 1, 1)", "fence(2, 0)", "applyId(4)", "applyId(3)",
                                           "replyId(3)", "reread(1, 0)", "replyId(4)"],
                                  "withdrawn == Set(1) and acks == Set() and fenced.get(2) == Set(0) "
                                  "and cov.get(2) == { entries: Set(), sat: Set() }"),
    "rereadAfterCondition": (FIRST + ["invalidate(1, 1, 1)", "applyId(3)", "timeoutId(3)", "invalidate(1, 1, 1)",
                                      "applyId(4)", "replyId(4)", "reread(1, 0)"] + invalidate(1, 1, 1, 5),
                             "not(results.get(4).ok) and acks == Set({ t: 1, k: 1, v: 1, id: 5 })"),
    "saturateAfterReject": (FIRST + ["invalidate(1, 1, 1)", "rejectId(3)", "replyId(3)", "saturateId(3)",
                                     "applyId(4)", "replyId(4)"],
                            "results.get(3).rejected and pages.get(0) == { fence: 1, ver: 2, entries: Set(), sat: true } "
                            "and acks == Set({ t: 1, k: 1, v: 1, id: 4 })"),
    "carryAfterConfirm": (FIRST + invalidate(1, 1, 1, 3) + ["fence(2, 0)", "applyId(4)", "timeoutId(4)", "fence(2, 0)",
                                                         "applyId(5)", "replyId(5)"] + fence(2, 1, 6)
                          + ["fill(2, 1, 1)"],
                          "timedOut == Set(4) and results.get(4).ok and results.get(5).kind == \"confirm\" "
                          "and adoptions.exists(a => a.t == 2 and a.p == 0 and a.basis == 5) "
                          "and refused == Set((2, 1, 1))"),
    "fenceLosesRace": (FIRST + ["invalidate(1, 1, 1)", "fence(2, 0)", "applyId(3)", "replyId(3)", "applyId(4)",
                                "replyId(4)"] + fence(2, 0, 5) + fence(2, 1, 6) + ["fill(2, 1, 1)"],
                       "not(results.get(4).ok) and acks == Set({ t: 1, k: 1, v: 1, id: 3 }) "
                       "and refused == Set((2, 1, 1))"),
    "successorRefusesFillOfAckedResident": (FIRST + ["fill(1, 1, 1)"] + invalidate(1, 1, 1, 3) + fence(2, 0, 4)
                                            + fence(2, 1, 5) + ["fill(2, 1, 1)"],
                                            "acks.exists(a => a.t == 1 and a.k == 1 and a.v == 1) "
                                            "and not(resident.contains((1, 1, 1))) "
                                            "and refused == Set((2, 1, 1)) and resident.forall(r => r._1 != 2)"),
    "successorAdmitsUncoveredKey": (FIRST + ["fill(1, 2, 1)"] + invalidate(1, 1, 1, 3) + fence(2, 0, 4) + fence(2, 1, 5)
                                    + ["fill(2, 2, 1)", "fill(2, 1, 1)"],
                                    "resident.contains((2, 2, 1)) and refused == Set((2, 1, 1))"),
    "fencedBeforeFirstFill": (FIRST + invalidate(1, 1, 1, 3) + fence(2, 0, 4) + fence(2, 1, 5)
                              + ["fill(2, 1, 1)", "fill(2, 2, 1)"],
                              "fenced.get(2) == PAGES and refused == Set((2, 1, 1)) and resident == Set((2, 2, 1))"),
}


def cases(Case):
    yield Case("coverage-typecheck", command="typecheck", family="coverage")
    yield Case("coverage-safety", invariant="safety", family="coverage")
    yield Case("coverage-safety-unfenced", invariant="safety", family="coverage", settings=UNFENCED)
    for name in INVARIANTS:
        yield Case(f"coverage-{name}", invariant=name, family="coverage")
    for witness in WITNESSES:
        yield Case(f"coverage-reach-{witness}", invariant="unreached", expected="violation", family="coverage",
                   extra=f"  val unreached = not({witness})\n")
    for name, (recipe, outcome) in RUNS.items():
        yield Case(f"coverage-run-{name}", invariant="runSafety", family="coverage", recipe=recipe,
                   settings={"BOUND": str(len(recipe)), **UNFENCED},
                   extra=f"  val runSafety = safety and (turn == {len(recipe)} implies ({outcome}))\n")
    for name, (prop, *mutations) in MUTANTS.items():
        yield Case(f"coverage-mutant-{name}", invariant=prop, expected="violation", family="coverage",
                   mutations=mutations, settings=MUTANT_SETTINGS.get(name, {}))


def inputs(case, source):
    text = (source / "coverage.qnt").read_text()
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    bindings = ", ".join(f"{name} = {case.settings.get(name, value)}" for name, value in CONSTANTS.items())
    extra = case.extra
    if case.recipe:
        picks = {}
        for at, action in enumerate(case.recipe):
            picks.setdefault(action, []).append(str(at))
        extra += "  action recipe = any {\n" + "".join(
            f'    all {{ Set({", ".join(turns)}).contains(turn), {action} }},\n' for action, turns in picks.items()) + "  }\n"
    return {"coverage.qnt": text,
            "case.qnt": f'module coverageCase {{\n  import coverage({bindings}).* from "./coverage"\n{extra}}}\n'}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "coverage.qnt"]
    return [quint, "verify", "case.qnt", "--main", "coverageCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant] + (
                ["--step", "recipe"] if case.recipe else [])
