#!/usr/bin/env python3
"""Check that judge-rc11.py credits only a complete, declared, matching herd7 result per litmus test.

The result tests write synthetic herd7 output in the format herd7 7.58
prints into an evidence directory, run the judge's command line as the lane
does, and read its report and receipt. The declaration and relation tests
call the judge in process on the committed declaration and litmus files, or
on a copy with one planted defect, and check that the defect is named before
any herd7 output is read.
"""

import copy
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-rc11.py"
SPEC = importlib.util.spec_from_file_location("judge_rc11", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise SystemExit("test-judge-rc11: scripts/judge-rc11.py cannot be loaded")
JUDGE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(JUDGE)
try:
    EXPECTED = json.loads((ROOT / "verification/rc11/expected.json").read_text())
except (OSError, ValueError) as error:
    raise SystemExit(f"test-judge-rc11: unreadable declaration: {error}") from error
LITMUS_DIR = ROOT / "verification/rc11/litmus"
LITMUS = sorted(LITMUS_DIR.glob("*.litmus"))
CUTOFF_PRODUCTION = "C0-cutoff-production-pin-first"
CUTOFF_COPIES = (CUTOFF_PRODUCTION, "C1-cutoff-read-first", "C2-cutoff-admitted-reachable", "C3-cutoff-refused-reachable")
CUTOFF_ENTRANT = "P0 (atomic_int* pin, atomic_int* closed) {"
TERMINAL_OWN = "T0-terminal-removal-own-fence"
TERMINAL_COPIES = (TERMINAL_OWN, "T1-terminal-removal-fence-dropped", "T2-terminal-removal-observed")
TERMINAL_FENCE = "  atomic_thread_fence(memory_order_release);\n"
TERMINAL_HOLDER = "P1 (atomic_int* handed, atomic_int* field) {"
L1, G1, G10 = "L1-both-fences", "G1-grace-all-fences", "G10-composite-all-fences"
G14, G15 = "G14-composite-claim-fence-dropped", "G15-composite-pin-fence-dropped"
G3, G4, G5 = "G3-grace-reader-fence-alone", "G4-grace-retire-fence-dropped", "G5-grace-certify-fence-dropped"
G11, G12, G13 = "G11-composite-retire-fence-dropped", "G12-composite-certify-fence-dropped", "G13-composite-reader-fences-alone"
S0, S1, S2 = "S0-sequence-bracket-committed", "S1-sequence-bracket-committed-fence-dropped", "S2-sequence-bracket-open"
S3 = "S3-sequence-bracket-open-fence-dropped"
F0, F2, F3 = "F0-fill-terminal-production", "F2-fill-terminal-acquire-dropped", "F3-fill-terminal-acquire-fence"
SEQUENCE_COMMIT = "atomic_store_explicit(seq,2,memory_order_seq_cst);"
MISSING = object()


def explored_lines(text):
    """The lines herd7 explores: the initializer and thread bodies, without the name line, comments or condition."""
    lines = [line.strip() for line in re.sub(r"\(\*.*?\*\)", "", text, flags=re.S).splitlines() if line.strip()]
    return [line for line in lines[1:] if not line.startswith("exists")]


def cutoff_program_drift(texts):
    """Names of the cutoff tests whose program departs from C0's.

    C2 and C3 show which entry outcomes C0's program reaches, so each must be
    C0's program; C1 is C0's program with the entrant's two accesses swapped.
    """
    production = explored_lines(texts[CUTOFF_PRODUCTION])
    entrant = production.index(CUTOFF_ENTRANT) + 1
    control = [*production[:entrant], production[entrant + 1], production[entrant], *production[entrant + 2:]]
    expected = {CUTOFF_COPIES[1]: control, **dict.fromkeys(CUTOFF_COPIES[2:], production)}
    return sorted(name for name, lines in expected.items() if explored_lines(texts[name]) != lines)


def terminal_program_drift(texts):
    """Names of the terminal tests whose program departs from T0's.

    T2 shows which reader outcome T0's program reaches, so it must be T0's
    program; T1 is T0's program with the next holder's release fence removed.
    """
    own = explored_lines(texts[TERMINAL_OWN])
    holder = own.index(TERMINAL_HOLDER)
    fence = own.index(TERMINAL_FENCE.strip(), holder)
    expected = {TERMINAL_COPIES[1]: [*own[:fence], *own[fence + 1:]], TERMINAL_COPIES[2]: own}
    return sorted(name for name, lines in expected.items() if explored_lines(texts[name]) != lines)


def sibling_drift(texts):
    """Names of the tests whose program departs from the sibling it is written against.

    S2 is S0's program without the writer's final commit store, which S0
    holds once. F3 is F0's program with the observer's acquire load of the
    state word made relaxed and an acquire fence before its terminal load.
    """
    s0, s2, f0, f3 = (JUDGE.program(texts[name]) for name in (S0, S2, F0, F3))
    writer = s0.threads[0]
    open_bracket = s0._replace(threads=(writer._replace(body=writer.body[:-1]), *s0.threads[1:]))
    drift = [S2] if writer.body.count(SEQUENCE_COMMIT) != 1 or writer.body[-1] != SEQUENCE_COMMIT or s2 != open_bracket else []
    producer, observer = f0.threads
    state_load, terminal_load = observer.body
    fenced = observer._replace(body=(state_load.replace("memory_order_acquire", "memory_order_relaxed"),
                                     "atomic_thread_fence(memory_order_acquire);", terminal_load))
    if f3 != f0._replace(threads=(producer, fenced)):
        drift.append(F3)
    return drift


def output(name, declared, verdict=None, positive=None, negative=3, header="Allowed", tail=""):
    sometimes = declared["outcome"] == "Sometimes"
    positive = (1 if sometimes else 0) if positive is None else positive
    verdict = verdict or ("Ok" if sometimes else "No")
    observation = "Sometimes" if positive and negative else ("Never" if not positive else "Always")
    return "\n".join([
        f"Test {name} {header}", "States 4", "0:r0=0; 1:r0=0;", verdict, "Witnesses",
        f"Positive: {positive} Negative: {negative}", f"Condition {declared['condition']}",
        f"Observation {name} {observation} {positive} {negative}", f"Time {name} 0.00", "Hash=0123abcd", "",
    ]) + tail


class JudgeRc11(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-rc11-")
        self.addCleanup(self.temp.cleanup)
        self.evidence = Path(self.temp.name) / "evidence"
        self.evidence.mkdir()
        self.identity = {
            "version": "7.58, Rev: exported", "binary": {"path": "/bin/herd7", "sha256": "0" * 64},
            "libdir": "/lib/herd", "closure": dict(EXPECTED["closure"]),
            "tests": {path.stem: self.digest(path) for path in LITMUS},
        }
        self.write()

    @staticmethod
    def digest(path):
        return hashlib.sha256(path.read_bytes()).hexdigest()

    def write(self, outputs=None, exits=None, argvs=None):
        (self.evidence / "identity.json").write_text(json.dumps(self.identity))
        (self.evidence / "pins.txt").write_text("- herd7 7.58, Rev: exported; sha256 " + "0" * 64 + "\n")
        for name, declared in EXPECTED["tests"].items():
            text = (outputs or {}).get(name, output(name, declared))
            (self.evidence / f"herd-{name}.txt").write_text(text)
            (self.evidence / f"herd-{name}.exit").write_text(f"{(exits or {}).get(name, 0)}\n")
            argv = (argvs or {}).get(name, ["/bin/herd7", *EXPECTED["options"], "-show", "prop", "-o", "/e/graphs", str(LITMUS_DIR / f"{name}.litmus")])
            (self.evidence / f"herd-{name}.argv").write_text("\n".join(argv) + "\n")

    def judge(self):
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence), "--revision", "0" * 40],
            capture_output=True, text=True, check=False,
        )
        try:
            report = json.loads((self.evidence / "report.json").read_text())
            receipt = json.loads((self.evidence / "receipt.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the judge wrote no report: {error} {result.stderr}")
        self.assertEqual(result.returncode, report["code"], report)
        return report, receipt

    def test_the_declaration_matches_the_committed_litmus_files(self):
        self.assertEqual(sorted(EXPECTED["tests"]), [path.stem for path in LITMUS])
        self.assertEqual(EXPECTED["options"], ["-model", "rc11.cat", "-speedcheck", "false"])
        self.assertEqual(EXPECTED["herd7"], "7.58")
        outcomes = {name: declared["outcome"] for name, declared in EXPECTED["tests"].items()}
        self.assertEqual(outcomes, {
            "L0-no-fences": "Sometimes", "L1-both-fences": "Never", "L2a-park-fence-dropped": "Sometimes",
            "L2b-scan-fence-dropped": "Sometimes", "L3-intermediary-fence-unordered": "Sometimes",
            "L4-intermediary-fence-hb-before-scan-fence": "Never", "L5-scan-fence-hb-before-intermediary-fence": "Sometimes",
            "L6-production-seqcst-accesses": "Never", "L7-mixed-seqcst-rmw-vs-fenced": "Never",
            "G0-grace-production-seqcst": "Never", "G1-grace-all-fences": "Never",
            "G2-grace-pin-fence-dropped": "Sometimes", "G3-grace-reader-fence-alone": "Sometimes",
            "G4-grace-retire-fence-dropped": "Never", "G5-grace-certify-fence-dropped": "Never",
            "G6-grace-bump-relaxed": "Sometimes", "G7-grace-start-relaxed": "Sometimes",
            "G8-claim-production-seqcst": "Never", "G9-claim-misencoded": "Sometimes",
            "G10-composite-all-fences": "Never", "G11-composite-retire-fence-dropped": "Never",
            "G12-composite-certify-fence-dropped": "Never", "G13-composite-reader-fences-alone": "Sometimes",
            "G14-composite-claim-fence-dropped": "Never", "G15-composite-pin-fence-dropped": "Sometimes",
            "C0-cutoff-production-pin-first": "Never", "C1-cutoff-read-first": "Sometimes",
            "C2-cutoff-admitted-reachable": "Sometimes", "C3-cutoff-refused-reachable": "Sometimes",
            "T0-terminal-removal-own-fence": "Never", "T1-terminal-removal-fence-dropped": "Sometimes",
            "T2-terminal-removal-observed": "Sometimes", "T3-terminal-removal-terminator-fence-dropped": "Never",
            "S0-sequence-bracket-committed": "Never", "S1-sequence-bracket-committed-fence-dropped": "Sometimes",
            "S2-sequence-bracket-open": "Never", "S3-sequence-bracket-open-fence-dropped": "Sometimes",
            "F0-fill-terminal-production": "Never", "F1-fill-terminal-release-dropped": "Sometimes",
            "F2-fill-terminal-acquire-dropped": "Sometimes", "F3-fill-terminal-acquire-fence": "Never",
        })
        for path in LITMUS:
            condition = EXPECTED["tests"][path.stem]["condition"]
            self.assertIn(condition, path.read_text(), path.name)

    def test_every_grace_shape_reaches_its_condition_in_some_test(self):
        # Pairing Never and Sometimes expectations provides a reachability
        # control for each condition.
        shapes = {}
        for name, declared in EXPECTED["tests"].items():
            if name.startswith("G"):
                shapes.setdefault(declared["condition"], set()).add(declared["outcome"])
        self.assertEqual(len(shapes), 3, shapes)
        for condition, outcomes in shapes.items():
            self.assertEqual(outcomes, {"Never", "Sometimes"}, condition)

    def test_the_cutoff_shape_pairs_its_production_and_control_and_reaches_both_entries(self):
        # The production entry and the cutoff-first control share the
        # missed-pin condition; the two witnesses reach each entry outcome.
        cutoff = {name: EXPECTED["tests"][name] for name in CUTOFF_COPIES}
        self.assertEqual(cutoff["C0-cutoff-production-pin-first"]["condition"], cutoff["C1-cutoff-read-first"]["condition"])
        self.assertEqual({declared["outcome"] for declared in cutoff.values()}, {"Never", "Sometimes"})
        self.assertEqual([cutoff[name]["condition"] for name in ("C2-cutoff-admitted-reachable", "C3-cutoff-refused-reachable")],
                         ["exists (0:r0=0 /\\ 2:r0=1 /\\ 2:r1=1)", "exists (0:r0=1)"])

    def test_the_cutoff_witnesses_and_control_run_the_production_program(self):
        texts = {name: (LITMUS_DIR / f"{name}.litmus").read_text() for name in CUTOFF_COPIES}
        self.assertEqual(cutoff_program_drift(texts), [])
        pin_store = "atomic_store_explicit(pin, 1, memory_order_seq_cst);"
        relaxed = pin_store.replace("seq_cst", "relaxed")
        witness = dict(texts, **{"C2-cutoff-admitted-reachable": texts["C2-cutoff-admitted-reachable"].replace(pin_store, relaxed)})
        self.assertEqual(cutoff_program_drift(witness), ["C2-cutoff-admitted-reachable"])
        unswapped = dict(texts, **{"C1-cutoff-read-first": texts["C0-cutoff-production-pin-first"]})
        self.assertEqual(cutoff_program_drift(unswapped), ["C1-cutoff-read-first"])
        production = dict(texts, **{CUTOFF_PRODUCTION: texts[CUTOFF_PRODUCTION].replace(pin_store, relaxed)})
        self.assertEqual(cutoff_program_drift(production), sorted(set(CUTOFF_COPIES) - {CUTOFF_PRODUCTION}))

    def test_the_terminal_removal_shape_pairs_its_fenced_holder_and_control(self):
        # The fenced removal and the dropped-fence control share the
        # old-sequence acceptance condition; the witness reaches the copy.
        terminal = {name: EXPECTED["tests"][name] for name in TERMINAL_COPIES}
        self.assertEqual(terminal[TERMINAL_COPIES[0]]["condition"], terminal[TERMINAL_COPIES[1]]["condition"])
        self.assertEqual([terminal[name]["outcome"] for name in TERMINAL_COPIES], ["Never", "Sometimes", "Sometimes"])
        self.assertEqual(terminal[TERMINAL_COPIES[2]]["condition"],
                         terminal[TERMINAL_COPIES[0]]["condition"].replace(" /\\ 2:r2=0", ""))

    def test_the_terminal_witness_and_control_run_the_fenced_program(self):
        # The witness runs T0's program to test reachability up to the
        # recheck; the control removes the next holder's fence from T0's
        # program.
        texts = {name: (LITMUS_DIR / f"{name}.litmus").read_text() for name in TERMINAL_COPIES}
        self.assertEqual(terminal_program_drift(texts), [])
        own = texts[TERMINAL_OWN]
        mutations = {
            "initializer": own.replace("{ seq = 0;", "{ seq = 2;"),
            "terminator fence": own.replace("memory_order_seq_cst);\n" + TERMINAL_FENCE, "memory_order_seq_cst);\n", 1),
            "reader recheck": own.replace("int r2 = atomic_load_explicit(seq, memory_order_seq_cst);\n", ""),
        }
        for label, mutated in mutations.items():
            self.assertNotEqual(mutated, own, label)
            self.assertEqual(terminal_program_drift(dict(texts, **{TERMINAL_OWN: mutated})),
                             sorted(TERMINAL_COPIES[1:]), label)
        fenced = texts[TERMINAL_COPIES[1]].replace(
            "memory_order_acquire);\n", "memory_order_acquire);\n" + TERMINAL_FENCE)
        self.assertEqual(terminal_program_drift(dict(texts, **{TERMINAL_COPIES[1]: fenced})), [TERMINAL_COPIES[1]])
        unfenced = texts[TERMINAL_COPIES[2]].replace("memory_order_acquire);\n" + TERMINAL_FENCE, "memory_order_acquire);\n")
        self.assertEqual(terminal_program_drift(dict(texts, **{TERMINAL_COPIES[2]: unfenced})), [TERMINAL_COPIES[2]])

    def test_every_variant_names_its_base_and_the_committed_relations_hold(self):
        bases = {name: declared.get("drops_from") for name, declared in EXPECTED["tests"].items() if "drops_from" in declared}
        self.assertEqual(bases, {
            "L0-no-fences": L1, "L2a-park-fence-dropped": L1, "L2b-scan-fence-dropped": L1,
            "G2-grace-pin-fence-dropped": G1, "G3-grace-reader-fence-alone": G1, "G4-grace-retire-fence-dropped": G1,
            "G5-grace-certify-fence-dropped": G1, "G11-composite-retire-fence-dropped": G10,
            "G12-composite-certify-fence-dropped": G10, "G13-composite-reader-fences-alone": G10,
            "G14-composite-claim-fence-dropped": G10, "G15-composite-pin-fence-dropped": G10,
            "T1-terminal-removal-fence-dropped": TERMINAL_OWN, "T3-terminal-removal-terminator-fence-dropped": TERMINAL_OWN,
            "S1-sequence-bracket-committed-fence-dropped": "S0-sequence-bracket-committed",
            "S3-sequence-bracket-open-fence-dropped": "S2-sequence-bracket-open",
            "F2-fill-terminal-acquire-dropped": F3,
        })
        joints = {name: declared["joint"] for name, declared in EXPECTED["tests"].items() if "joint" in declared}
        self.assertEqual(joints, {G4: G3, G5: G3, G11: G13, G12: G13})
        fences = {name: len(JUDGE.fence_lines(JUDGE.program(JUDGE.read_litmus(name))))
                  for name, declared in EXPECTED["tests"].items() if "base" in declared}
        self.assertEqual(fences, {L1: 2, G1: 3, G10: 4, TERMINAL_OWN: 2, S0: 1, S2: 1, F3: 1})
        # Each variant's dropped fences, so a redundant reason or a control
        # stays bound to the fence it names.
        drops = {name: sorted(JUDGE.dropped(JUDGE.program(JUDGE.read_litmus(base)), JUDGE.program(JUDGE.read_litmus(name))))
                 for name, base in bases.items()}
        self.assertEqual(drops, {
            "L0-no-fences": [("P0", 2), ("P1", 2)], "L2a-park-fence-dropped": [("P0", 2)], "L2b-scan-fence-dropped": [("P1", 2)],
            "G2-grace-pin-fence-dropped": [("P0", 2)], G3: [("P1", 2), ("P2", 2)], G4: [("P1", 2)], G5: [("P2", 2)],
            G11: [("P1", 2)], G12: [("P2", 2)], G13: [("P1", 2), ("P2", 2)], G14: [("P0", 2)], G15: [("P0", 5)],
            "T1-terminal-removal-fence-dropped": [("P1", 2)], "T3-terminal-removal-terminator-fence-dropped": [("P0", 2)],
            S1: [("P0", 2)], "S3-sequence-bracket-open-fence-dropped": [("P0", 2)], F2: [("P1", 2)],
        })
        self.assertEqual(JUDGE.relation_defects(EXPECTED, JUDGE.read_litmus), [])

    def test_the_open_bracket_and_the_fenced_observer_keep_their_siblings_programs(self):
        texts = {name: JUDGE.read_litmus(name) for name in (S0, S2, F0, F3)}
        self.assertEqual(sibling_drift(texts), [])
        reader = "  int r1 = atomic_load_explicit(field, memory_order_seq_cst);"
        producer = "  atomic_store_explicit(terminal, 2, memory_order_relaxed);"
        field = "  atomic_store_explicit(field, 2, memory_order_relaxed);\n"
        commit = "  atomic_store_explicit(seq, 2, memory_order_seq_cst);\n"
        fence = "  atomic_thread_fence(memory_order_acquire);\n"
        terminal = "  int r1 = atomic_load_explicit(terminal, memory_order_relaxed);\n"
        for needle, name in ((reader, S2), (producer, F3), (field + commit, S0), (fence, F3), (terminal, F3)):
            self.assertEqual(texts[name].count(needle), 1, needle)
        plants = {
            "a changed reader in S2": (S2, texts[S2].replace(reader, reader.replace("seq_cst", "acquire"))),
            "S2 keeping the commit": (S2, texts[S0]),
            "S0 with its commit before the field store": (S0, texts[S0].replace(field + commit, commit + field)),
            "S0 without its commit": (S0, texts[S2]),
            "S0 with its commit twice": (S0, texts[S0].replace(commit, commit + commit)),
            "a changed producer in F3": (F3, texts[F3].replace(producer, producer.replace("relaxed", "release"))),
            "a SeqCst fence in F3": (F3, texts[F3].replace(fence, fence.replace("acquire", "seq_cst"))),
            "an extra observer statement in F3": (F3, texts[F3].replace(terminal, terminal + "  int r2 = atomic_load_explicit(state, memory_order_relaxed);\n")),
        }
        for label, (name, planted) in plants.items():
            with self.subTest(label=label):
                self.assertNotEqual(planted, texts[name])
                self.assertEqual(sibling_drift(dict(texts, **{name: planted})), [S2 if name == S0 else name])

    def test_one_variant_may_drop_several_fences_of_one_thread(self):
        pin_fence = "  atomic_store_explicit(pin, 1, memory_order_release);\n  atomic_thread_fence(memory_order_seq_cst);\n"
        text = JUDGE.read_litmus(G14)
        self.assertEqual(text.count(pin_fence), 1)
        planted = text.replace(pin_fence, "  atomic_store_explicit(pin, 1, memory_order_release);\n")
        self.assertEqual(JUDGE.dropped(JUDGE.program(JUDGE.read_litmus(G10)), JUDGE.program(planted)), {("P0", 2), ("P0", 5)})

    def relation_defects(self, change=None, texts=None):
        """The defects of the committed declaration after `change`, with `texts` in place of committed litmus files."""
        declared = copy.deepcopy(EXPECTED)
        if change:
            change(declared["tests"])
        texts = texts or {}
        return JUDGE.relation_defects(declared, lambda name: texts[name] if name in texts else JUDGE.read_litmus(name))

    def test_a_variant_that_also_changes_an_ordering_or_another_part_is_refused(self):
        text = JUDGE.read_litmus(G15)
        tail = "  int r2 = atomic_load_explicit(pin, memory_order_acquire);\n}"
        header = "P0 (atomic_int* claimed, atomic_int* era, atomic_int* pin, atomic_int* bucket) {"
        pin = "atomic_store_explicit(pin, 1, memory_order_release);"
        self.assertEqual((text.count(header), text.count(pin)), (1, 1))
        plants = {
            "a changed ordering": text.replace(pin, pin.replace("release", "relaxed")),
            "initial state": text.replace("{ claimed = 0;", "{ claimed = 1;"),
            "an extra statement at a thread's end": text.replace(tail, tail.replace("\n}", "\n  int r3 = atomic_load_explicit(era, memory_order_acquire);\n}")),
            "a missing thread": text.split("P2 (")[0] + "exists" + text.split("exists", 1)[1],
            "a renamed thread": text.replace("P2 (", "P3 ("),
            "another thread parameter list": text.replace(header, header.replace(", atomic_int* bucket", ", atomic_int* bucket, atomic_int* spare")),
            "another litmus condition": text.replace("exists (0:r1=1", "exists (0:r1=0"),
            "a removed statement that is no fence": text.replace("  int r2 = atomic_load_explicit(bucket, memory_order_acquire);\n", ""),
            "a renamed register": text.replace("int r1 = atomic_load_explicit(era", "intr1 = atomic_load_explicit(era"),
            "an unchanged copy of the base": JUDGE.read_litmus(G10),
        }
        for label, planted in plants.items():
            with self.subTest(label=label):
                self.assertNotEqual(planted, text)
                self.assertIn(f"{G15} is not {G10} with fence lines removed", self.relation_defects(texts={G15: planted}))

    def test_litmus_text_outside_the_read_shape_is_refused(self):
        # Each plant breaks one rule of the shape `program` reads, and the
        # refusal names that rule.
        base = JUDGE.read_litmus(G10)
        claim = "  atomic_thread_fence(memory_order_seq_cst);\n  int r1 = atomic_load_explicit(era, memory_order_acquire);\n"
        load = "  int r2 = atomic_load_explicit(bucket, memory_order_acquire);\n"
        condition = "exists (0:r1=1 /\\ 0:r2=1 /\\ 2:r0=2 /\\ (2:r1=0 \\/ 2:r2=0))"
        p2 = "P2 (atomic_int* era, atomic_int* claimed, atomic_int* pin) {\n"
        comment_end = "reader's record) or 2:r2=0 (the pass saw no pin). *)"
        state = "its initial state is no single `{ NAME = INTEGER; ... }` line"
        repeated = "thread P0 holds the same fence twice among adjacent fence lines"
        compact = JUDGE.compact(condition)
        for needle in (claim, load, condition, p2, comment_end, "}\n\nP0 (", "  int r2 = atomic_load_explicit(pin, memory_order_acquire);\n}\n"):
            self.assertEqual(base.count(needle), 1, needle)
        plants = {
            "a program on the name line": (base.replace("\n", " { x = 0; }\n", 1), "its first line is no `C NAME` line"),
            "an empty file": ("", "its first line is no `C NAME` line"),
            "a name line alone": ("C G10-composite-all-fences\n", "its initial state is no single `{ NAME = INTEGER; ... }` line"),
            "a program inside the leading comment": (base.replace(comment_end, comment_end[:-2] + "\n" + base.split(comment_end)[1] + " << *)"),
                                                     "a comment before its initial state holds a brace or a line that opens with `KEY=`"),
            "a test option inside the leading comment": (base.replace(comment_end, comment_end[:-2] + "\nVariant=SC *)"),
                                                         "a comment before its initial state holds a brace or a line that opens with `KEY=`"),
            "an unclosed comment": (base.replace(comment_end, comment_end[:-2]), "a comment before its initial state is unclosed or nested"),
            "a nested comment": (base.replace(comment_end, "(* inner *) " + comment_end), "a comment before its initial state is unclosed or nested"),
            "a parenthesized dereference and a cast around a fence": (
                base.replace(claim, "  int r8 = (*claimed);\n" + claim + "  int r9 = (int*)0;\n"), "a `(*` or `*)` stands outside the comments before its initial state"),
            "a C comment in a body": (base.replace(load, load.rstrip("\n") + " // observe\n"), "it holds a C comment"),
            "a block comment opener in a body": (base.replace(load, "  int r9 = 0 /* x;\n" + load), "it holds a C comment"),
            "a block comment closer in a body": (base.replace(load, "  int r9 = 0 */ x;\n" + load), "it holds a C comment"),
            "a thread header on the initial state's line": (base.replace("}\n\nP0 (", "} P0 ("), state),
            "a token after the initial state": (base.replace("}\n\nP0 (", "} int\n\nP0 ("), state),
            "a brace pair inside the initial state": (base.replace("{ claimed = 0;", "{ claimed = 0; { x = 1; }"), state),
            "a typed initial state entry": (base.replace("{ claimed = 0;", "{ int .g = 1; claimed = 0;"), state),
            "a one-line thread on a header line": (base.replace(p2, "P3 (atomic_int* era) { int r0 = 0; }\n\n" + p2),
                                                   "'P3(atomic_int*era){int r0=0;}' is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "a brace inside a thread body": (base.replace(load, "  if (r1 == 7) { }\n" + load),
                                             "thread P0 holds 'if(r1==7){}', which is no single straight-line statement"),
            "a braceless if before a fence": (base.replace(claim, "  if (r0 == 0)\n" + claim),
                                              "thread P0 holds 'if(r0==0)', which is no single straight-line statement"),
            "a one-line if": (base.replace(load, "  if (r1 == 1) r1 = 2;\n" + load), "thread P0 holds 'if(r1==1)r1=2;', which is no single straight-line statement"),
            "a one-line while": (base.replace(load, "  while (r1 == 0) r1 = 1;\n" + load),
                                 "thread P0 holds 'while(r1==0)r1=1;', which is no single straight-line statement"),
            "a statement wrapped across two lines": (base.replace(load, load.replace("(bucket, ", "(bucket,\n    ")),
                                                     "thread P0 holds 'int r2=atomic_load_explicit(bucket,', which is no single straight-line statement"),
            "two statements on one line": (base.replace(load, load.rstrip("\n") + " int r3 = 0;\n"),
                                           "thread P0 holds 'int r2=atomic_load_explicit(bucket,memory_order_acquire);int r3=0;', "
                                           "which is no single straight-line statement"),
            "a fence sharing a line with a load": (base.replace(claim, claim.replace(";\n  int r1", "; int r1")), "thread P0 holds a fence that shares its line"),
            "a fence on a thread's header line": (base.replace(p2, p2.rstrip("\n") + " atomic_thread_fence(memory_order_seq_cst);\n"),
                                                  "'P2(atomic_int*era,atomic_int*claimed,atomic_int*pin){atomic_thread_fence(memory_order_seq_cst);' "
                                                  "is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "the same fence on two adjacent lines": (base.replace(claim, "  atomic_thread_fence(memory_order_seq_cst);\n" + claim), repeated),
            "a fence repeated within one run of fences": (
                base.replace(claim, "  atomic_thread_fence(memory_order_seq_cst);\n  atomic_thread_fence(memory_order_release);\n" + claim), repeated),
            "a thread with no closing line": (base.replace("  int r2 = atomic_load_explicit(pin, memory_order_acquire);\n}\n",
                                                           "  int r2 = atomic_load_explicit(pin, memory_order_acquire);\n"),
                                              "thread P2 has no closing `}` line"),
            "no condition": (base.replace(condition, ""), "it has no condition line"),
            "a filter before the condition": (base.replace(condition, "filter (0:r2=0)\n" + condition),
                                              "'filter(0:r2=0)' is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "a filter on the condition's line": (base.replace(condition, "filter (0:r2=0) " + condition),
                                                 "'filter(0:r2=0)exists(0:r1=1/\\\\0:r2=1/\\\\2:r0=2/\\\\(2:r1=0\\\\/2:r2=0))' is neither a thread header "
                                                 "nor its one final `exists`, `~exists` or `forall` line"),
            "a statement after the threads": (base.replace(condition, "int r9 = 0;\n" + condition),
                                              "'int r9=0;' is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "a locations line on the condition's line": (base.replace(condition, "locations [pin;] " + condition),
                                                         f"{'locations[pin;]' + compact!r} is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "a filter after locations on the condition's line": (
                base.replace(condition, "locations [pin;] filter (0:r2=0) " + condition),
                f"{'locations[pin;]filter(0:r2=0)' + compact!r} is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
            "a trailer on the condition's line": (base.replace(condition, condition + " << note"), "its condition line holds a `<<` trailer"),
            "a condition wrapped across two lines": (base.replace(condition, condition.replace(" /\\ 2:r0", "\n/\\ 2:r0")),
                                                     "'exists(0:r1=1/\\\\0:r2=1' is neither a thread header nor its one final `exists`, `~exists` or `forall` line"),
        }
        for label, (planted, reason) in plants.items():
            with self.subTest(label=label):
                self.assertNotEqual(planted, base)
                with self.assertRaises(JUDGE.Unreadable) as unread:
                    JUDGE.program(planted)
                self.assertEqual(str(unread.exception), reason)
                self.assertIn(f"{G10} has no readable litmus program: {reason}", self.relation_defects(texts={G10: planted}))
        divided = base.replace(load, "  int r3 = r1 / *bucket;\n" + load)
        self.assertEqual(JUDGE.program(divided).threads[0].body[-2], "int r3=r1/ *bucket;")
        distinct = base.replace(claim, "  atomic_thread_fence(memory_order_release);\n" + claim)
        self.assertEqual(JUDGE.program(distinct).threads[0].body[1:3],
                         ("atomic_thread_fence(memory_order_release);", "atomic_thread_fence(memory_order_seq_cst);"))
        self.assertEqual(JUDGE.program(base.replace(comment_end, comment_end + " (* a *) (* b *)\n(* c *)")), JUDGE.program(base))
        for entry, state in (("claimed = -1;", "{claimed= -1;era=1;pin=0;bucket=1;}"), ("claimed =-1;", "{claimed=-1;era=1;pin=0;bucket=1;}")):
            self.assertEqual(JUDGE.program(base.replace("claimed = 0;", entry)).state, state)

    def test_a_trailer_on_a_variants_condition_line_is_refused(self):
        condition = "exists (1:r0=1 /\\ 1:r1=1)"
        text = JUDGE.read_litmus(F2)
        self.assertEqual(text.count(condition), 1)
        trailed = text.replace(condition, condition + " << note")
        reason = f"{F2} has no readable litmus program: its condition line holds a `<<` trailer"

        def strip(tests):
            del tests[F2]["drops_from"]
        for change in (None, strip):
            with self.subTest(drops_from=change is None):
                self.assertIn(reason, self.relation_defects(change, texts={F2: trailed}))

    def test_a_wrapped_variant_without_its_base_is_refused(self):
        # A wrapped statement makes the variant unreadable rather than a
        # program unrelated to its base, with or without its drops_from.
        load = "  int r2 = atomic_load_explicit(bucket, memory_order_acquire);\n"
        text = JUDGE.read_litmus(G15)
        self.assertEqual(text.count(load), 1)
        wrapped = text.replace(load, load.replace("(bucket, ", "(bucket,\n    "))
        reason = "thread P0 holds 'int r2=atomic_load_explicit(bucket,', which is no single straight-line statement"

        def strip(tests):
            del tests[G15]["drops_from"]
        for change in (None, strip):
            with self.subTest(drops_from=change is None):
                self.assertIn(f"{G15} has no readable litmus program: {reason}", self.relation_defects(change, texts={G15: wrapped}))

    def test_an_unreadable_litmus_file_is_refused(self):
        for error in (FileNotFoundError("absent"), UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")):
            def read(name, error=error):
                if name == G15:
                    raise error
                return JUDGE.read_litmus(name)
            with self.subTest(error=type(error).__name__):
                self.assertIn(f"{G15} has no readable litmus program: {error}", JUDGE.relation_defects(EXPECTED, read))

    def test_a_test_name_that_could_leave_the_litmus_directory_is_refused(self):
        empty = Path(self.temp.name) / "empty"
        empty.mkdir()
        for name in ("G1\x00", "\ud800", "../G1-grace-all-fences", "nested/G1-grace-all-fences"):
            declared = copy.deepcopy(EXPECTED)
            declared["tests"][name] = copy.deepcopy(EXPECTED["tests"][G1])
            with self.subTest(name=name):
                defect = f"{name!r} is no test name: an ASCII word character, then word characters, `.`, `+` and `-`"
                self.assertEqual(JUDGE.relation_defects(declared, JUDGE.read_litmus), [defect])
                with self.assertRaises(JUDGE.Refusal) as refused:
                    JUDGE.judge(empty, declared)
                self.assertEqual((refused.exception.code, str(refused.exception)), (JUDGE.TOOL_FAILURE, f"relation defect: {defect}"))

    def test_an_empty_or_malformed_test_set_is_refused(self):
        empty = Path(self.temp.name) / "empty"
        empty.mkdir()
        cases = {"no tests": (dict(EXPECTED, tests={}), "the declaration declares no tests"),
                 "a list of tests": (dict(EXPECTED, tests=[]), "the declaration's tests are no object of test objects"),
                 "no tests key": ({key: value for key, value in EXPECTED.items() if key != "tests"},
                                  "the declaration's tests are no object of test objects"),
                 "a list root": ([], "the declaration's tests are no object of test objects")}
        for label, (declared, defect) in cases.items():
            with self.subTest(label=label):
                self.assertEqual(JUDGE.relation_defects(declared, JUDGE.read_litmus), [defect])
        with self.assertRaises(JUDGE.Refusal) as refused:
            JUDGE.judge(empty, dict(EXPECTED, tests={}))
        self.assertEqual((refused.exception.code, str(refused.exception)), (JUDGE.TOOL_FAILURE, "relation defect: the declaration declares no tests"))

    def test_a_non_object_declaration_root_writes_a_refusal_report_and_receipt(self):
        read_json = JUDGE.read_json
        for root in ([1], "tests", 7, True, [], None):
            empty = Path(self.temp.name) / f"empty-{type(root).__name__}-{bool(root)}"
            empty.mkdir()

            def planted(path, root=root):
                return root if path == JUDGE.EXPECTED else read_json(path)
            with self.subTest(root=root), mock.patch.object(JUDGE, "read_json", planted):
                report, receipt = JUDGE.derive(empty, "0" * 40)
                self.assertEqual((report["code"], report["reason"]),
                                 (JUDGE.TOOL_FAILURE, "relation defect: the declaration's tests are no object of test objects"))
                self.assertEqual((receipt["completion"], receipt["executions"], receipt["selection"]["credited"]), ("tool failure", 0, False))
                self.assertIsNone(receipt["bounds"]["options"])

    def test_a_variant_under_another_condition_is_refused(self):
        def change(tests):
            tests[G15]["condition"] = "exists (0:r1=1)"
        self.assertEqual(self.relation_defects(change), [f"{G15} declares another condition than its base {G10}",
                                                         f"no variant of {G10} drops its P0 fence at statement 5 alone"])

    def test_a_deleted_variant_leaves_its_fence_without_a_single_drop(self):
        # Deleting G11, G12 or L2a leaves a fence that only a joint variant
        # drops, in the writer's, the maintainer's or the parker's thread.
        for name, base, thread in ((G14, G10, "P0"), (G11, G10, "P1"), (G12, G10, "P2"), ("L2a-park-fence-dropped", L1, "P0")):
            def change(tests, name=name):
                del tests[name]
            with self.subTest(name=name):
                self.assertEqual(self.relation_defects(change), [f"no variant of {base} drops its {thread} fence at statement 2 alone"])

    def test_a_base_that_lost_every_variant_is_refused(self):
        # S0, S2 and F3 have one variant each and G10 has five, so deleting
        # them leaves a declared base whose variant set is empty.
        composite = [G11, G12, G13, G14, G15]
        for base, gone, fences in ((S0, [S1], [("P0", 2)]), (S2, [S3], [("P0", 2)]), (F3, [F2], [("P1", 2)]),
                                   (G10, composite, [("P0", 2), ("P0", 5), ("P1", 2), ("P2", 2)])):
            def change(tests, gone=gone):
                for name in gone:
                    del tests[name]
            with self.subTest(base=base):
                self.assertEqual(self.relation_defects(change), [
                    *(f"no variant of {base} drops its {thread} fence at statement {position} alone" for thread, position in fences),
                    f"{base} has no Sometimes variant"])

    def test_a_joint_that_is_no_sometimes_variant_dropping_the_fences_is_refused(self):
        # A Never joint, the variant itself, a joint of another base and a
        # joint that keeps the variant's fence.
        for name, joint, base in ((G4, G5, G1), (G11, G11, G10), (G4, G13, G1), (G4, "G2-grace-pin-fence-dropped", G1)):
            def change(tests, name=name, joint=joint):
                tests[name]["joint"] = joint
            with self.subTest(name=name, joint=joint):
                self.assertEqual(self.relation_defects(change), [
                    f"{name} names joint {joint!r}, which is no Sometimes variant of {base} dropping its fences"])

    def test_a_joint_or_reason_on_a_test_that_is_no_never_variant_is_refused(self):
        plants = {"a Sometimes variant's joint": (G15, "joint", G13), "a Sometimes variant's joint at a Never test": (G15, "joint", G14),
                  "a Sometimes variant's reason": (G15, "redundant", "planted"), "a base's reason": (G10, "redundant", "planted"),
                  "a standalone test's dangling joint": ("L3-intermediary-fence-unordered", "joint", "nothing")}
        for label, (name, key, value) in plants.items():
            def change(tests, name=name, key=key, value=value):
                tests[name][key] = value
            with self.subTest(label=label):
                self.assertEqual(self.relation_defects(change), [f"{name} declares {key}, which only a Never variant carries"])

    def test_a_drops_from_that_names_no_declared_test_is_refused(self):
        def change(tests):
            tests[G14]["drops_from"] = "G16-composite-undeclared"
        self.assertIn(f"{G14} drops_from 'G16-composite-undeclared', which is no declared test", self.relation_defects(change))

    def test_a_drops_from_that_names_a_test_declaring_no_base_is_refused(self):
        def change(tests):
            del tests[S0]["base"]
        self.assertEqual(self.relation_defects(change), [f"{S1} drops_from {S0}, which declares no base"])

    def test_a_declared_base_that_holds_no_fence_is_refused(self):
        def change(tests):
            tests[F0]["base"] = True
        self.assertEqual(self.relation_defects(change), [f"{F0} has no Sometimes variant"])

    def test_a_never_variant_without_a_reason_is_refused(self):
        # G4 keeps a valid joint, so a joint does not stand in for a reason.
        for name in (G14, G4):
            def missing(tests, name=name):
                del tests[name]["redundant"]
            with self.subTest(name=name):
                self.assertEqual(self.relation_defects(missing), [f"{name} is a Never variant with no redundant reason"])

    def test_a_test_entry_that_is_no_object_is_refused(self):
        def change(tests):
            tests[G14] = ["x"]
        self.assertEqual(self.relation_defects(change), ["the declaration's tests are no object of test objects"])

    def test_a_missing_or_malformed_declared_field_is_refused(self):
        malformed = "a {} that is no nonempty string"
        plants = {"blank redundant": ("redundant", " ", malformed), "numeric redundant": ("redundant", 0, malformed),
                  "list drops_from": ("drops_from", [G10], malformed), "null drops_from": ("drops_from", None, malformed),
                  "list joint": ("joint", [G15], malformed), "numeric outcome": ("outcome", 1, malformed),
                  "blank header": ("header", "", malformed), "numeric header": ("header", 0, malformed),
                  "missing condition": ("condition", MISSING, "no {}"), "missing outcome": ("outcome", MISSING, "no {}"),
                  "missing header": ("header", MISSING, "no {}"), "false base": ("base", False, "a {} that is not true"),
                  "string base": ("base", "true", "a {} that is not true"), "numeric base": ("base", 1, "a {} that is not true")}
        for label, (key, value, defect) in plants.items():
            def change(tests, key=key, value=value):
                if value is MISSING:
                    del tests[G14][key]
                else:
                    tests[G14][key] = value
            with self.subTest(label=label):
                self.assertEqual(self.relation_defects(change), [f"{G14} declares {defect.format(key)}"])

        def both(tests):
            tests[G14]["outcome"] = "Always"
            del tests[G14]["condition"]
        self.assertEqual(self.relation_defects(both), [f"{G14} declares no condition", f"{G14} declares outcome 'Always', not Sometimes or Never"])

    def test_a_missing_header_is_refused_before_a_result_is_judged(self):
        declared = copy.deepcopy(EXPECTED)
        del declared["tests"][G14]["header"]
        with self.assertRaises(JUDGE.Refusal) as refused:
            JUDGE.judge(self.evidence, declared)
        self.assertEqual((refused.exception.code, str(refused.exception)), (JUDGE.TOOL_FAILURE, f"relation defect: {G14} declares no header"))

    def test_an_unsupported_outcome_is_refused_before_a_matching_result_is_read(self):
        # A declared Always would otherwise match an Always observation and
        # skip the Sometimes and Never count checks.
        declared = copy.deepcopy(EXPECTED)
        declared["tests"][G14]["outcome"] = "Always"
        self.assertEqual(JUDGE.relation_defects(declared, JUDGE.read_litmus), [f"{G14} declares outcome 'Always', not Sometimes or Never"])
        self.write({G14: output(G14, EXPECTED["tests"][G14], positive=1, negative=0, verdict="Ok")})
        with self.assertRaises(JUDGE.Refusal) as refused:
            JUDGE.judge(self.evidence, declared)
        self.assertEqual((refused.exception.code, str(refused.exception)),
                         (JUDGE.TOOL_FAILURE, f"relation defect: {G14} declares outcome 'Always', not Sometimes or Never"))

    def test_a_base_without_a_sometimes_variant_is_refused(self):
        def change(tests):
            tests[S1].update(outcome="Never", redundant="planted")
        self.assertEqual(self.relation_defects(change), [f"{S0} has no Sometimes variant"])

    def test_a_base_declared_sometimes_is_refused(self):
        # Every outcome of a base is an outcome of each variant, so a Sometimes
        # base makes each variant Sometimes whichever fences it drops.
        for base in (L1, G1, G10, TERMINAL_OWN, S0, S2, F3):
            def change(tests, base=base):
                tests[base]["outcome"] = "Sometimes"
            with self.subTest(base=base):
                self.assertEqual(self.relation_defects(change), [f"{base} is a base declared Sometimes, not Never"])

    def test_a_respaced_copy_without_its_base_is_refused(self):
        original = JUDGE.read_litmus(G15)
        respaced = {"exists (0:r1=1 /\\ 0:r2=1": "exists(0:r1=1/\\0:r2=1", "int r0 = ": "int  r0  =  "}
        text = original
        for needle, spaced in respaced.items():
            self.assertIn(needle, text)
            text = text.replace(needle, spaced)

        def change(tests):
            del tests[G15]["drops_from"]
        self.assertIn(f"{G15} is {G10} with fence lines removed and names no drops_from", self.relation_defects(change, texts={G15: text}))

    def test_a_variant_stripped_of_its_base_is_refused(self):
        # S1 is S0's only variant, so stripping its drops_from leaves the
        # declared base S0 no variant, and the unnamed-copy rule names S1.
        def change(tests):
            del tests[S1]["drops_from"]
        unnamed = f"{S1} is {S0} with fence lines removed and names no drops_from"
        self.assertEqual(self.relation_defects(change), [
            f"no variant of {S0} drops its P0 fence at statement 2 alone", f"{S0} has no Sometimes variant", unnamed])

        # With S0's base removed as well, only the unnamed-copy rule names S1.
        def unlist(tests):
            change(tests)
            del tests[S0]["base"]
        self.assertEqual(self.relation_defects(unlist), [unnamed])

    def test_a_relation_defect_is_refused_before_any_output_is_read(self):
        declared = copy.deepcopy(EXPECTED)
        del declared["tests"][G15]["drops_from"]
        empty = Path(self.temp.name) / "empty"
        empty.mkdir()
        with self.assertRaises(JUDGE.Refusal) as refused:
            JUDGE.judge(empty, declared)
        self.assertEqual((refused.exception.code, refused.exception.completion), (JUDGE.TOOL_FAILURE, "tool failure"))
        self.assertEqual(str(refused.exception), "relation defect: " + "; ".join([
            f"no variant of {G10} drops its P0 fence at statement 5 alone",
            f"{G15} is {G10} with fence lines removed and names no drops_from"]))

    def test_matching_complete_results_credit_every_test(self):
        report, receipt = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)
        self.assertEqual(sorted(report["tests"]), sorted(EXPECTED["tests"]))
        self.assertEqual((receipt["completion"], receipt["executions"]), ("completed", len(EXPECTED["tests"])))
        self.assertTrue(receipt["selection"]["credited"])
        bound = set(receipt["inputs"])
        self.assertLessEqual({"identity.json", "pins.txt", "report.json", "verification/rc11/expected.json",
                              "scripts/test-inventory.json", "verification/obligations.json"}, bound)
        self.assertLessEqual({f"verification/rc11/litmus/{path.name}" for path in LITMUS}, bound)

    def test_each_malformed_or_mismatched_result_is_refused(self):
        sometimes, never = "L2a-park-fence-dropped", "L1-both-fences"
        s, n = EXPECTED["tests"][sometimes], EXPECTED["tests"][never]
        cases = [
            ({sometimes: output(sometimes, s, header="Forbidden")}, {}, 1, "answers Forbidden"),
            ({sometimes: output(sometimes, s, positive=0, verdict="No")}, {}, 1, "is Never, declared Sometimes"),
            ({never: output(never, n, positive=1, verdict="Ok")}, {}, 1, "is Sometimes, declared Never"),
            ({sometimes: output(sometimes, s, negative=0)}, {}, 1, "is Always, declared Sometimes"),
            ({never: output(never, n, negative=0)}, {}, 1, "zero positives over a nonempty domain"),
            ({sometimes: output(sometimes, s, verdict="Loop Ok")}, {}, 3, "reports Loop Ok"),
            ({never: output(never, n, verdict="Loop No")}, {}, 3, "reports Loop No"),
            ({sometimes: 'Warning: File "x.litmus": unrolling limit exceeded at While, legal outcomes may be missing.\n'
                         + output(sometimes, s)}, {}, 3, "warns"),
            ({sometimes: output(sometimes, s, verdict="No")}, {}, 1, "Sometimes needs Ok"),
            ({never: output(never, n).replace("States 4", "States 0")}, {}, 1, "zero positives over a nonempty domain"),
            ({sometimes: output(sometimes, s, verdict="Ok No")}, {}, 2, "prints 0 verdict lines"),
            ({sometimes: output(sometimes, s) + output(sometimes, s)}, {}, 2, "prints 2 Test lines"),
            ({sometimes: output(sometimes, s).split("Observation")[0]}, {}, 2, "prints 0 Observation lines"),
            ({sometimes: output(sometimes, s).replace("Hash=0123abcd", "")}, {}, 2, "prints 0 Hash lines"),
            ({sometimes: output(sometimes, s).replace(s["condition"], "exists (0:r0=1)")}, {}, 2, "checks 'exists (0:r0=1)'"),
            ({}, {sometimes: 2}, 2, "exited 2"),
            ({}, {sometimes: 124}, 3, "interrupted"),
        ]
        for outputs, exits, code, reason in cases:
            with self.subTest(reason=reason):
                self.write(outputs, exits)
                report, receipt = self.judge()
                self.assertEqual(report["code"], code, report)
                self.assertIn(reason, report["reason"])
                self.assertFalse(receipt["selection"]["credited"])
                self.assertEqual(receipt["executions"], 0)

    def test_an_interrupted_run_is_a_timeout_and_a_cut_off_run_is_exhausted(self):
        self.write({}, {"L0-no-fences": 143})
        _, receipt = self.judge()
        self.assertEqual(receipt["completion"], "timeout")
        self.write({"L0-no-fences": output("L0-no-fences", EXPECTED["tests"]["L0-no-fences"], verdict="Loop Ok")})
        _, receipt = self.judge()
        self.assertEqual(receipt["completion"], "exhausted")
        self.write({"L0-no-fences": output("L0-no-fences", EXPECTED["tests"]["L0-no-fences"]).split("Hash")[0]})
        _, receipt = self.judge()
        self.assertEqual(receipt["completion"], "tool failure")

    def test_a_command_other_than_the_declared_one_is_refused(self):
        name = "L1-both-fences"
        base = ["/bin/herd7", *EXPECTED["options"]]
        display = ["-show", "prop", "-o", "/e/graphs"]
        litmus = str(LITMUS_DIR / f"{name}.litmus")
        for argv in (
            [*base, "-through", "invalid", *display, litmus],
            [*base, "-model", "sc.cat", *display, litmus],
            [*base, "-skipchecks", "sc", *display, litmus],
            [base[0], "-model", "sc.cat", "-speedcheck", "false", *display, litmus],
            [*base, *display, str(LITMUS_DIR / "L0-no-fences.litmus")],
            [*base, *display, f"/elsewhere/{name}.litmus"],
            ["/usr/local/bin/herd7", *base[1:], *display, litmus],
        ):
            with self.subTest(argv=argv):
                self.write(argvs={name: argv})
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(f"{name} ran", report["reason"])
                self.assertEqual(receipt["executions"], 0)

    def test_a_missing_or_undeclared_output_is_refused(self):
        (self.evidence / "herd-L6-production-seqcst-accesses.txt").unlink()
        report, _ = self.judge()
        self.assertEqual(report["code"], 2, report)
        self.assertIn("L6-production-seqcst-accesses has no recorded run", report["reason"])
        self.write()
        (self.evidence / "herd-L8-extra.txt").write_text("Test L8-extra Allowed\n")
        report, _ = self.judge()
        self.assertEqual(report["code"], 2, report)
        self.assertIn("undeclared tests ['L8-extra']", report["reason"])

    def test_identity_drift_or_widened_options_refuse_reuse(self):
        drifts = [
            (lambda i: i.update(version="7.57, Rev: exported"), "herd7 reports"),
            (lambda i: i["closure"].update({"cos.cat": "f" * 64}), "model closure"),
            (lambda i: i["closure"].pop("stdlib.cat"), "model closure"),
            (lambda i: i["tests"].update({"L1-both-fences": "e" * 64}), "litmus files changed"),
        ]
        original = copy.deepcopy(self.identity)
        for edit, reason in drifts:
            with self.subTest(reason=reason):
                self.identity = copy.deepcopy(original)
                edit(self.identity)
                self.write()
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(reason, report["reason"])
                self.assertEqual(receipt["completion"], "tool failure")

    def test_identity_refuses_a_model_file_herd7_would_load_first(self):
        libdir = Path(self.temp.name) / "lib"
        libdir.mkdir()
        for name in ("rc11.cat", "stdlib.cat"):
            (libdir / name).write_text("let x = 0\n")
        herd = Path(self.temp.name) / "herd7"
        herd.write_text("#!/usr/bin/env bash\necho '7.58, Rev: exported'\n")
        herd.chmod(0o755)
        work = Path(self.temp.name) / "work"
        work.mkdir()
        command = [sys.executable, str(SCRIPT), "identity", "--herd7", str(herd), "--libdir", str(libdir), "--evidence", str(work / "e")]
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, check=False,
                                env={"PATH": "/usr/bin:/bin", "HERDLIB": str(libdir)})
        self.assertEqual(result.returncode, 2)
        self.assertIn("HERDLIB is set", result.stderr)
        (work / "rc11.cat").write_text("let x = 1\n")
        result = subprocess.run(command, cwd=work, capture_output=True, text=True, check=False, env={"PATH": "/usr/bin:/bin"})
        self.assertEqual(result.returncode, 2)
        self.assertIn("closure files ['rc11.cat']", result.stderr)

    def test_identity_follows_includes_and_records_each_digest(self):
        libdir = Path(self.temp.name) / "lib"
        libdir.mkdir()
        (libdir / "rc11.cat").write_text('C RC11\ninclude "cos.cat"\n')
        (libdir / "cos.cat").write_text('include "cos-ok-opt.cat"\ninclude "cos-no-opt.cat"\n')
        (libdir / "cos-ok-opt.cat").write_text('include "cross.cat"\n')
        (libdir / "cos-no-opt.cat").write_text('include "cross.cat"\n')
        (libdir / "cross.cat").write_text("let x = 0\n")
        (libdir / "stdlib.cat").write_text("let y = 0\n")
        herd = Path(self.temp.name) / "herd7"
        herd.write_text("#!/usr/bin/env bash\necho '7.58, Rev: exported'\n")
        herd.chmod(0o755)
        evidence = Path(self.temp.name) / "identity"
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "identity", "--herd7", str(herd), "--libdir", str(libdir), "--evidence", str(evidence)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        try:
            identity = json.loads((evidence / "identity.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"no identity.json: {error}")
        self.assertEqual(sorted(identity["closure"]), ["cos-no-opt.cat", "cos-ok-opt.cat", "cos.cat", "cross.cat", "rc11.cat", "stdlib.cat"])
        self.assertEqual(identity["binary"]["sha256"], self.digest(herd))
        self.assertIn(f"- herd7 7.58, Rev: exported; sha256 {self.digest(herd)}", (evidence / "pins.txt").read_text())
        (libdir / "cross.cat").unlink()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "identity", "--herd7", str(herd), "--libdir", str(libdir), "--evidence", str(evidence)],
            capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 2)
        self.assertIn("cross.cat", result.stderr)


    def cli(self):
        return subprocess.run([sys.executable, str(SCRIPT), "judge", "--evidence", str(self.evidence), "--revision", "0" * 40],
                              capture_output=True, text=True, check=False)

    def test_a_receipt_input_or_report_the_judge_cannot_use_exits_2_without_a_report(self):
        pins, report = self.evidence / "pins.txt", self.evidence / "report.json"
        argv = self.evidence / f"herd-{sorted(EXPECTED['tests'])[0]}.argv"
        provenance = pins.read_text()
        plants = (
            ("a pins directory", lambda: (pins.unlink(), pins.mkdir()), lambda: (pins.rmdir(), pins.write_text(provenance))),
            ("an unreadable command record", lambda: argv.chmod(0), lambda: argv.chmod(0o644)),
            ("a report directory", report.mkdir, report.rmdir),
        )
        for name, plant, restore in plants:
            with self.subTest(plant=name):
                if name == "an unreadable command record" and os.geteuid() == 0:
                    self.skipTest("root reads a file of any mode")
                plant()
                result = self.cli()
                restore()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertTrue(result.stderr.startswith("judge-rc11: "), result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(report.exists() or (self.evidence / "receipt.json").exists())

    def test_pins_outside_utf8_are_recorded_with_replacement_characters(self):
        (self.evidence / "pins.txt").write_bytes(b"\xff\xfe")
        report, receipt = self.judge()
        self.assertEqual(report["code"], 0, report)
        self.assertEqual(receipt["tool"]["provenance"], ["\ufffd\ufffd"])
        self.assertEqual(receipt["inputs"]["pins.txt"], self.digest(self.evidence / "pins.txt"))

    def test_an_identity_of_another_shape_or_nested_past_the_parser_is_refused_with_a_report(self):
        for text in ("[]", '{"version": 5}', "[" * 100_000):
            with self.subTest(text=text[:20]):
                (self.evidence / "identity.json").write_text(text)
                report, receipt = self.judge()
                self.assertEqual((report["code"], receipt["executed"]), (2, []), report)
                self.assertTrue(report["reason"].startswith("malformed evidence: "), report)


if __name__ == "__main__":
    unittest.main()
