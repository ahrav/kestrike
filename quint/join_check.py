"""Join cases: the composed projections of `joins.qnt`, each checked from its prefix root under its joint scheduler.

A projection module imports two accepted models as instances; its joint steps are their actions, and its `safety` is
both models' `safety` and its joint invariants. `check.projection_cases` expands each declaration of `PROJECTIONS`
into a `safety` case, one reach case per witness and one case per mutant, each mutant a property, the witness that
triggers it and replacements of the projection module's text. A case's instance is its projection module with
`BOUND` bound and the case's definitions added, beside copies of the two source models; a reduction replaces text of
a source model's copy for every case of its projection. The typecheck case checks `joins.qnt` beside the unreduced
source models.
"""

import re

CONSTANTS = {"BOUND": "12"}
PROJECTIONS = {
    "capture-suffix": {
        "module": "captureSuffix", "sources": ("capture.qnt", "suffix.qnt"),
        # A side list of one entry, so the second saved member abandons a pass over two keys.
        "reductions": [("capture.qnt", "pure val CAP = 2", "pure val CAP = 1")],
        # Two entries inserted, their INSERT blocks durable.
        "prefix": ["bind(0, 1)", "publish(0)", "seal", "blockDone", "bind(1, 2)", "publish(1)", "seal", "blockDone"],
        "step": "step", "settings": {"BOUND": "24"},
        "witnesses": ["witnessSavedExcluded", "witnessSavedKept", "witnessReuseAfterDurable", "witnessLostMidPass",
                      "witnessAbandonedRecovered", "witnessRefusedInPass"],
        "mutants": {
            # The allocator takes back a removed entry's unit before the REMOVE's block is durable.
            "release-ignores-hold": ("AllocatorHonorsHold", "witnessReuseAfterDurable", [(
                "first, C::st.retiring.filter(e => e.slot == s).forall(e => not(S::held.contains(e.unit))),", "first,")]),
            # The capture's checkpoint is published as an atomic checkpoint of the suffix's live set at completion.
            "pass-published-at-completion": ("CutIsCapture", "witnessSavedExcluded", [
                ("C::start, S::startPass, idOf' = idOf", "C::start, keepS, idOf' = idOf"),
                ("C::complete, S::publishPass,", "C::complete, S::publish,")]),
        },
    },
    "coverage-preserve": {
        "module": "coveragePreserve", "sources": ("coverage.qnt", "preserve.qnt"), "reductions": [],
        # Both keys filled under tenure 1's fenced coverage, captured, published and settled: the cut S = {1, 2}.
        "prefix": ["fill(0)", "fill(1)", "capture", "publish", "settle"],
        "step": "step", "settings": {"BOUND": "19"},
        "witnesses": ["witnessAckedExcludedRetained", "witnessSuccessorRefusesAcked", "witnessFailedCasRetained",
                      "witnessLostReplyRetained"],
        "mutants": {
            # The successor recovers before its fences adopt the pages.
            "recover-before-page-fence": ("ExclusionCovered", "witnessAckedExcludedRetained", [(
                "action recover = all { C::fenced.get(P::st.ten) == C::PAGES, joint(", "action recover = all { joint(")]),
            # Preservation takes the invalidation as evidence when its page write is submitted.
            "exclusion-at-submission": ("ExclusionCovered", "witnessFailedCasRetained", [
                ('joint("invalidate"), C::invalidate(P::st.srv, k + 1, 1), keepP,',
                 'joint("invalidate"), C::invalidate(P::st.srv, k + 1, 1), P::drop(k, "invalidate"),'),
                ('all { host(r.t), acked, P::st.live.get(r.k - 1) != 0, joint("ack"), C::replyId(i), '
                 'P::drop(r.k - 1, "invalidate") },',
                 'all { host(r.t), acked, joint("ack"), C::replyId(i), keepP },')]),
        },
    },
    "prefix-saturation": {
        "module": "prefixSaturation", "sources": ("prefix.qnt", "saturation.qnt"), "reductions": [],
        "step": "step", "settings": {"BOUND": "11"},
        "witnesses": ["witnessReuseAfterSettle", "witnessConfirmSettles", "witnessPendingKeepsFloor",
                      "witnessUnknownNamedRecovered"],
        "mutants": {
            # A Publish whose outcome the host never learned raises the floor to its cut.
            "floor-on-unknown-outcome": ("ReachableHistoryIntact", "witnessUnknownNamedRecovered", [(
                "P::unresolved(p), keepS, keepGhost } }", "P::unresolved(p), S::publish(cutOf.get(p.capture)), keepGhost } }")]),
            # The floor rises to the head when a capture's Publish is submitted.
            "floor-at-capture": ("ReachableHistoryIntact", "witnessReuseAfterSettle", [(
                "P::capture(1), keepS, took' = took,", "P::capture(1), S::publish(S::log.head), took' = took,")]),
        },
    },
}
SOURCES = sorted({source for projection in PROJECTIONS.values() for source in projection["sources"]})


def projection(case):
    """Return the name and declaration of the projection a join case checks; a case of no projection raises."""
    for name, declared in PROJECTIONS.items():
        if case.name.startswith(f"join-{name}-"):
            return name, declared
    raise ValueError(f"{case.name}: names no projection")


def module_text(text, module):
    """Return the text of `module` in `joins.qnt`, from its `module` line through its closing brace."""
    found = re.search(rf"(?ms)^module {module} \{{\n.*?^\}}\n", text)
    if found is None:
        raise ValueError(f"joins.qnt declares no module {module}")
    return found.group(0)


def inputs(case, source):
    joins = (source / "joins.qnt").read_text()
    if case.command == "typecheck":
        return {"joins.qnt": joins, **{name: (source / name).read_text() for name in SOURCES}}
    _, declared = projection(case)
    texts = {name: (source / name).read_text() for name in declared["sources"]}
    for name, old, new in declared["reductions"]:
        if texts[name].count(old) != 1:
            raise ValueError(f"{case.name}: reduction target in {name} is not unique")
        texts[name] = texts[name].replace(old, new)
    text = module_text(joins, declared["module"])
    for old, new in case.mutations:
        if text.count(old) != 1:
            raise ValueError(f"{case.name}: mutation target is not unique")
        text = text.replace(old, new)
    bound = case.settings.get("BOUND", CONSTANTS["BOUND"])
    text = text.replace(f"module {declared['module']} {{\n", "module joinCase {\n", 1)
    text = text.replace("  const BOUND: int\n", f"  pure val BOUND = {bound}\n", 1)
    return {**texts, "case.qnt": text[:text.rindex("}")] + case.extra + "}\n"}


def command(case, quint, directory, port):
    if case.command == "typecheck":
        return [quint, "typecheck", "joins.qnt"]
    return [quint, "verify", "case.qnt", "--main", "joinCase", "--server-endpoint", f"127.0.0.1:{port}",
            "--backend", "tlc", "--tlc-config", str(directory / "tlc.json"), "--invariant", case.invariant,
            "--step", case.step]
