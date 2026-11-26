#!/usr/bin/env python3
"""Self-checks for scripts/scan-tag-compare.py: the dependency judgment on recorded x86-64 and AArch64
extents, synthetic falsifiers, ELF admission and symbol resolution over synthetic images, the build identity
and the run's credit."""

import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
FIXTURES = ROOT / "verification/tag-compare/fixtures"


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


scan = load("scan_tag_compare", ROOT / "scripts/scan-tag-compare.py")
barriers_fixture = load("test_scan_barriers", ROOT / "scripts/test-scan-barriers.py")
DECLARATION = scan.load_declaration(scan.DECLARATION)
SITES = DECLARATION["sites"]
# The fixtures' x86-64 extents and the AArch64 unfolded extent come from a linked reproduction crate, `tcx`.
CALLEES = {**DECLARATION["callees"], "tcx::accepted": 0, "tcx::rejected": 0}
TEST_DECLARATION = {**DECLARATION, "callees": CALLEES}
COPY = [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"]


def read_json(path):
    try:
        return json.loads(Path(path).read_text())
    except (OSError, ValueError) as error:
        raise AssertionError(f"unreadable {path}: {error}") from error


def fixture(name):
    return (FIXTURES / f"{name}.txt").read_text()


def complete_identity(digest):
    return {"revision": "abc", "ci": {"GITHUB_RUN_ID": "1"}, "executable": "x", "sha256": digest,
            "profile": "release", "cargo_profile": {"opt_level": "3", "debug_assertions": False, "test": True},
            "lto": "false",
            "profile_env": {"CARGO_PROFILE_RELEASE_LTO": "false"}, "rustflags": "-C symbol-mangling-version=v0",
            "target_features": ["neon"], "native_build": ["- pin"]}


def callers_ran(evidence, callers=None, code="0", passed=None):
    """Record the callers' run under `evidence` as libtest reports it: each caller `ok` and the summary line."""
    callers = read_json(scan.DECLARATION)["callers"] if callers is None else callers
    passed = len(callers) if passed is None else passed
    (evidence / "callers.txt").write_text("".join(f"test {name} ... ok\n" for name in callers)
                                          + f"\ntest result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured\n")
    (evidence / "exit.txt").write_text(f"{code}\n")


def extents(machine, decision, control):
    return {"machine": machine, "sha256": "d" * 64, "objdump": {}, "sites": {
        "tag-decision": {"address": "0x0", "size": 4, "disassembly": fixture(decision)},
        "early-return-control": {"address": "0x0", "size": 4, "disassembly": fixture(control)}}}


def listing(*lines):
    """An objdump extent of `lines`, four bytes each, ending in `ret`; a branch to a bare `0x40` lands on that
    final `ret`, annotated as objdump annotates a target inside the function."""
    lines = [*lines, *([] if lines and lines[-1] == "ret" else ["ret"])]
    last = 4 * (len(lines) - 1)
    lines = [re.sub(r"\b0x4[08]$", f"{last:#x} <f+{last:#x}>", line) if re.match(r"(b\.|cb|tb|j)", line) else line
             for line in lines]
    return "\n".join(f"  {4 * index:x}:\t{line}" for index, line in enumerate(lines))


class Judgment(unittest.TestCase):
    def test_the_folded_comparison_passes_and_the_early_return_is_flagged_on_both_targets(self):
        for machine in ("x86-64", "aarch64"):
            with self.subTest(machine=machine):
                decision = scan.judge_extent(machine, fixture(f"{machine}-decision"), CALLEES)
                self.assertEqual((decision["verdict"], decision["reason"]), ("pass", None))
                roles = [entry for entry in decision["extent"] if entry.get("role")]
                self.assertEqual([entry["role"] for entry in roles], ["decision value", "decision"])
                self.assertTrue(all(entry["depends"] == "tag[0-15] expected[0-15]" for entry in roles))
                self.assertEqual(decision["decision"], [roles[-1]["address"]])
                control = scan.judge_extent(machine, fixture(f"{machine}-early-return"), CALLEES)
                self.assertEqual(control["verdict"], "flagged")
                partial = [entry for entry in control["extent"] if entry.get("role", "").startswith("falsifier")]
                self.assertEqual(len(partial), 16, "one early return per tag byte")
                self.assertEqual([entry["depends"] for entry in partial[:2]],
                                 ["tag[0] expected[0]", "tag[1] expected[1]"])
                self.assertIn("a branch on a partial comparison", control["reason"])

    def test_the_unfolded_word_comparison_selects_on_its_low_half_on_aarch64_only(self):
        arm = scan.judge_extent("aarch64", fixture("aarch64-unfolded"), CALLEES)
        self.assertEqual(arm["verdict"], "flagged")
        ccmp = next(entry for entry in arm["extent"] if entry["instruction"].startswith("ccmp"))
        self.assertEqual((ccmp["depends"], ccmp["role"]),
                         ("tag[0-7] expected[0-7]", "falsifier: a conditional select on a partial comparison"))
        self.assertEqual(scan.judge_extent("x86-64", fixture("x86-64-unfolded"), CALLEES)["verdict"], "pass")

    def test_each_synthetic_falsifier_is_named(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11",
                "orr x8, x8, x9", "cmp x8, #0"]
        cases = {
            "a memory address": full + ["ldrb w2, [x3, x8]", "b.eq 0x40", "ret"],
            "a second decision branch": full + ["b.eq 0x40", "b.ne 0x48", "ret"],
            "a branch on a partial comparison": ["ldr x8, [x0]", "ldr x9, [x1]", "cmp x8, x9", "b.ne 0x40", "ret"],
            "paths reach no conditional branch": full + ["cset w0, eq", "ret"],
        }
        for reason, lines in cases.items():
            with self.subTest(reason=reason):
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                self.assertEqual(judged["verdict"], "flagged")
                self.assertIn(reason, judged["reason"])
        stack = full[:-1] + ["str x8, [sp, #8]", "ldr x12, [sp, #8]", "cmp x12, #0", "b.eq 0x40", "ret"]
        self.assertEqual(scan.judge_extent("aarch64", listing(*stack), CALLEES)["verdict"], "pass",
                         "a value through a stack slot keeps its dependency")
        x86 = listing("mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rsi]", "cmp rax, rcx", "cmove rdx, r8",
                      "ret")
        self.assertIn("a conditional select on a partial comparison", scan.judge_extent("x86-64", x86, CALLEES)["reason"])

    def test_what_the_model_cannot_follow_refuses_the_site(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x8, x8, x9"]
        refusals = {
            "an unmodeled instruction fmla": ["fmla v0.4s, v1.4s, v2.4s"],
            "at an address the model does not track": ["mov x9, #3", "ldrb w8, [x0, x9]", "cbnz w8, 0x40"],
            "the model does not track": ["add x8, x0, #0", "add x8, x8, x2", "ldrb w9, [x8]", "cbnz w9, 0x40"],
            "a store through an argument pointer": ["ldrb w8, [x0]", "strb w8, [x0, #1]"],
            "whose argument count the declaration does not name": full + ["bl 0x100 <memcmp>", "cbz w0, 0x40"],
            "a backward branch": full + ["cmp x8, #0", "b.ne 0x4 <tag_compare_decision+0x4>"],
        }
        for reason, lines in refusals.items():
            with self.subTest(reason=reason), self.assertRaisesRegex(scan.Refusal, reason):
                scan.judge_extent("aarch64", listing(*lines), CALLEES)
        for undecoded in ("<unknown>", ".word\t0x12345678"):
            lines = listing(*full, "cmp x8, #0", "b.eq 0x40", "ret").splitlines()
            lines.insert(6, f"  18:\t{undecoded}")
            with self.subTest(undecoded=undecoded), self.assertRaisesRegex(scan.Refusal, "an undecoded instruction"):
                scan.judge_extent("aarch64", "\n".join(lines), CALLEES)
        lines = listing(*full, "cmp x8, #0", "b.eq 0x40", "ret").splitlines()
        lines.insert(6, "\t\t...")
        with self.assertRaisesRegex(scan.Refusal, "an undecoded instruction '...'"):
            scan.judge_extent("aarch64", "\n".join(lines), CALLEES)
        for operand in ("byte ptr [rdi + rcx]", "byte ptr [rcx + rdi]"):
            with self.subTest(operand=operand), self.assertRaisesRegex(scan.Refusal, "does not track"):
                scan.judge_extent("x86-64", listing(f"movzx eax, {operand}", "test al, al", "jne 0x40"), CALLEES)

    def test_a_partial_branch_on_any_forward_path_is_flagged(self):
        """Paths that skip a clear, a call or a dead write still carry their bytes to the branch they reach."""
        full = ["ldp x10, x11, [x0]", "ldp x12, x13, [x1]", "eor x10, x10, x12", "eor x11, x11, x13",
                "orr x14, x10, x11"]
        listings = {
            "a skipped clear": ["ldrb w8, [x0]", "cbz x3, 0xc <f+0xc>", "mov w8, #0", "cbnz w8, 0x18 <f+0x18>",
                                *full[:1], "ret", "ret"],
            "a reject block after a call": full + ["cbnz x14, 0x20 <f+0x20>",
                                                   "bl 0x900 <kestrike::net::tag_compare_tests::accepted>", "ret",
                                                   "cbnz x10, 0x28 <f+0x28>", "ret", "ret"],
            "a dead write": full + ["b 0x1c <f+0x1c>", "mov x10, #0", "cbnz x10, 0x24 <f+0x24>", "ret", "ret"],
        }
        for name, lines in listings.items():
            with self.subTest(path=name):
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                self.assertEqual(judged["verdict"], "flagged", judged["reason"])
                self.assertIn("falsifier: a branch on a partial comparison", judged["falsifiers"])
        with self.assertRaisesRegex(scan.Refusal, "whose argument count the declaration does not name"):
            scan.judge_extent("aarch64", listing(*full, "cbnz x14, 0x1c <f+0x1c>", "b 0x900 <memcmp>", "ret"), CALLEES)
        for operand in ("[rcx + 4*rax]", "[rcx + rax*4]", "[4*rax + 0x1000]"):
            scaled = listing("movzx eax, byte ptr [rdi]", "lea rcx, [rip + 0x100]", f"movzx edx, byte ptr {operand}")
            with self.subTest(operand=operand):
                self.assertIn("a memory address on a partial comparison",
                              scan.judge_extent("x86-64", scaled, CALLEES)["falsifiers"][0])
        partial = listing("movzx eax, byte ptr [rdi]", "cmp al, byte ptr [rsi]", "mov rcx, qword ptr [rdi]",
                          "inc rcx", "jb 0x18 <f+0x18>", "ret", "ret")
        with self.assertRaisesRegex(scan.Refusal, "updated in part"):
            scan.judge_extent("x86-64", partial, CALLEES)

    def test_an_unfollowed_transfer_refuses_the_site(self):
        full = ["ldp x10, x11, [x0]", "ldp x12, x13, [x1]", "eor x10, x10, x12", "eor x11, x11, x13",
                "orr x14, x10, x11"]
        refusals = {
            "an indirect transfer": (["adr x16, 0x30 <f+0x30>", "br x16", "ret"], "aarch64"),
            "which names no symbol": ([*full, "cbnz x14, 0x24", "ret"], "aarch64"),
            "whose argument count": ([*full, "cmp x14, #0", "b.ne 0x900 <memcmp>", "ret"], "aarch64"),
            "a pointer the model does not follow": (["mov x0, sp", "bl 0x900 <subtle::black_box::<u8>>", "ret"],
                                                    "aarch64"),
            "a return through x8": (["ldr x8, [x0]", "ret x8"], "aarch64"),
        }
        for reason, (lines, machine) in refusals.items():
            with self.subTest(reason=reason), self.assertRaisesRegex(scan.Refusal, reason):
                scan.judge_extent(machine, listing(*lines), CALLEES)
        with self.assertRaisesRegex(scan.Refusal, "an indirect transfer"):
            scan.judge_extent("x86-64", listing("jmp qword ptr [rip + 0x100]"), CALLEES)
        bt = listing("movzx edx, byte ptr [rdi]", "cmp dl, byte ptr [rsi]", "mov rcx, qword ptr [rdi]", "bt rcx, 3",
                     "je 0x40")
        with self.assertRaisesRegex(scan.Refusal, "updated in part"):
            scan.judge_extent("x86-64", bt, CALLEES)

    def test_an_always_taken_condition_is_a_jump_and_a_link_register_return_is_a_return(self):
        """`b.al` and `b.nv` hold on every flag state, so neither is a decision on the comparison."""
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x8, x8, x9",
                "cmp x8, #0"]
        for always in ("b.al", "b.nv"):
            with self.subTest(always=always):
                judged = scan.judge_extent("aarch64", listing(*full, f"{always} 0x40", "ret"), CALLEES)
                self.assertEqual((judged["verdict"], judged["paths"], judged["decision"]), ("flagged", 1, []))
                self.assertIn("paths reach no conditional branch", judged["reason"])
        self.assertEqual(scan.judge_extent("aarch64", listing(*full, "b.eq 0x40", "ret x30"), CALLEES)["verdict"], "pass")

    def test_a_vector_lane_operand_is_data_and_an_insert_keeps_the_other_lanes(self):
        """`v0.b[0]` names a lane, not a memory location: an extract carries that lane's bytes alone, and an insert
        replaces one lane and keeps the rest."""
        extract = listing("ldr q0, [x0]", "ldr q1, [x1]", "eor v0.16b, v0.16b, v1.16b", "umov w8, v0.b[0]",
                          "cbz w8, 0x40")
        judged = scan.judge_extent("aarch64", extract, CALLEES)
        umov = next(entry for entry in judged["extent"] if entry["instruction"].startswith("umov"))
        self.assertEqual((judged["verdict"], umov["data"]), ("flagged", "tag[0] expected[0]"))
        self.assertEqual(judged["falsifiers"], ["falsifier: a branch on a partial comparison"])
        for insert in ("ins v0.b[0], w8", "mov v0.b[0], w8"):
            with self.subTest(insert=insert):
                lines = ["ldr q0, [x0]", "mov w8, #0", insert, "mov x9, v0.d[0]", "cbz x9, 0x40"]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"], branch["role"]),
                                 ("flagged", "tag[1-7]", "falsifier: a branch on a partial comparison"))
        wide = listing("ldr q0, [x0]", "ldr q1, [x1]", "eor v0.16b, v0.16b, v1.16b", "mov x8, v0.d[1]", "cbz x8, 0x40")
        branch = next(entry for entry in scan.judge_extent("aarch64", wide, CALLEES)["extent"]
                      if entry["instruction"].startswith("cbz"))
        self.assertEqual(branch["depends"], "tag[8-15] expected[8-15]")

    def test_a_wide_lane_compare_and_a_vector_immediate_keep_their_lanes_bytes(self):
        """`cmeq` on lanes wider than a byte depends on the whole lane, and the vector-immediate `orr`/`bic` modify
        the destination in place, so its bytes stay as sources."""
        cases = {"cmeq v0.2d, v1.2d, #0": (["ldr b1, [x0]", "cmeq v0.2d, v1.2d, #0"], "tag[0]"),
                 "cmeq d0, d1, #0": (["ldr b1, [x0]", "cmeq d0, d1, #0"], "tag[0]"),
                 "orr v0.4s, #0x1": (["ldr q0, [x0]", "orr v0.4s, #0x1"], "tag[1]"),
                 "bic v0.8h, #0xff": (["ldr q0, [x0]", "bic v0.8h, #0xff"], "tag[1]")}
        for name, (lines, kept) in cases.items():
            with self.subTest(case=name):
                judged = scan.judge_extent("aarch64", listing(*lines, "umov w8, v0.b[1]", "cbnz w8, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbnz"))
                self.assertEqual((judged["verdict"], branch.get("depends"), branch.get("role")),
                                 ("flagged", kept, "falsifier: a branch on a partial comparison"))
        exact = listing("ldr q0, [x0]", "ldr q1, [x1]", "cmeq v0.16b, v0.16b, v1.16b", "umov w8, v0.b[1]", "cbnz w8, 0x40")
        branch = next(entry for entry in scan.judge_extent("aarch64", exact, CALLEES)["extent"]
                      if entry["instruction"].startswith("cbnz"))
        self.assertEqual(branch["depends"], "tag[1] expected[1]", "a byte compare stays byte by byte")
        for compare, kept in (("cmeq v0.2d, v0.2d, v1.2d", "tag[0-7] expected[0-7]"), ("cmeq v0.4s, v0.4s, v1.4s", "tag[0-3] expected[0-3]"),
                              ("cmeq v0.8h, v0.8h, v1.8h", "tag[0-1] expected[0-1]")):
            with self.subTest(compare=compare):
                wide = listing("ldr q0, [x0]", "ldr q1, [x1]", compare, "umov w8, v0.b[1]", "cbnz w8, 0x40")
                branch = next(entry for entry in scan.judge_extent("aarch64", wide, CALLEES)["extent"]
                              if entry["instruction"].startswith("cbnz"))
                self.assertEqual(branch["depends"], kept, "a wide compare stays within its lane")

    def test_an_extract_is_a_byte_permutation(self):
        """`ext` concatenates its sources and takes sixteen bytes from the immediate offset."""
        for offset, kept in (("#8", "tag[8]"), ("#0", "tag[0]"), ("#15", "tag[15]")):
            with self.subTest(offset=offset):
                lines = ["ldr q1, [x0]", "ldr q2, [x1]", f"ext v0.16b, v1.16b, v2.16b, {offset}", "umov w3, v0.b[0]", "cbnz w3, 0x40"]
                branch = next(entry for entry in scan.judge_extent("aarch64", listing(*lines), CALLEES)["extent"]
                              if entry["instruction"].startswith("cbnz"))
                self.assertEqual(branch["depends"], kept)
        lines = ["ldr q1, [x0]", "ldr q2, [x1]", "ext v0.16b, v1.16b, v2.16b, #8", "umov w3, v0.b[8]", "cbnz w3, 0x40"]
        branch = next(entry for entry in scan.judge_extent("aarch64", listing(*lines), CALLEES)["extent"]
                      if entry["instruction"].startswith("cbnz"))
        self.assertEqual(branch["depends"], "expected[0]")
        half = ["ldr d1, [x0]", "ldr d2, [x1]", "ext v0.8b, v1.8b, v2.8b, #4", "umov w3, v0.b[4]", "cbnz w3, 0x40"]
        judged = scan.judge_extent("aarch64", listing(*half), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbnz"))
        self.assertEqual(branch.get("depends"), "expected[0]", "the 8-byte form joins the low halves")
        ext = next(entry for entry in judged["extent"] if entry["instruction"].startswith("ext"))
        self.assertEqual(ext["data"], "tag[4-7] expected[0-3]", "the upper half is empty")

    def test_an_arrangement_names_its_width_and_a_reduction_reads_only_it(self):
        """`v0.8b` covers eight bytes: a reduction over it reads half the vector, and a write to it clears the rest."""
        lines = ["ldr q0, [x0]", "ldr q1, [x1]", "addv b0, v0.8b", "addv b1, v1.8b", "umov w8, v0.b[0]", "umov w9, v1.b[0]",
                 "cmp w8, w9", "b.ne 0x40"]
        judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("b.ne"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7] expected[0-7]"))
        cleared = listing("ldr q0, [x0]", "orr v0.8b, v0.8b, v0.8b", "mov x8, v0.d[1]", "cbz x8, 0x40")
        judged = scan.judge_extent("aarch64", cleared, CALLEES)
        self.assertIn("paths reach no conditional branch", judged["reason"], "a 64-bit arrangement write clears the upper half")

    def test_an_always_true_select_reads_no_flags(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9", "cmp x12, #0"]
        for select in ("csel x3, xzr, xzr, al", "csel x3, xzr, xzr, nv", "cset x3, al", "csel x3, xzr, x12, al",
                       "csinc x3, xzr, x12, nv"):
            with self.subTest(select=select):
                judged = scan.judge_extent("aarch64", listing(*full, select, "ldrb w4, [x0]", "orr x3, x3, x4", "cbz x3, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"], judged["falsifiers"]),
                                 ("flagged", "tag[0]", ["falsifier: a branch on a partial comparison"]))
        judged = scan.judge_extent("aarch64", listing(*full, "ccmp xzr, xzr, #0, al", "b.eq 0x40"), CALLEES)
        self.assertEqual((judged["verdict"], judged["decision"]), ("flagged", []), "an unconditional ccmp replaces the flags")
        self.assertIn("paths reach no conditional branch", judged["reason"])
        judged = scan.judge_extent("aarch64", listing(*full[:-1], "ldrb w4, [x0]", "cmp x12, #0", "ccmp x4, #0, #0, al", "b.eq 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("b.eq"))
        self.assertEqual(branch["depends"], "tag[0]")

    def test_byte_local_and_constant_idioms_keep_their_shape(self):
        """`mvn` and `bswap` move each byte's dependency; a self-compare, an immediate mask and a register `movq`
        narrow it as the hardware does."""
        arm = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        judged = scan.judge_extent("aarch64", listing(*arm, "mvn x12, x12", "cbz w12, 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-3,8-11] expected[0-3,8-11]"))
        judged = scan.judge_extent("aarch64", listing(*arm, "cmp x12, x12", "b.eq 0x40"), CALLEES)
        self.assertIn("paths reach no conditional branch", judged["reason"], "an AArch64 self-compare sets constant flags")
        x86 = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]",
               "xor rcx, qword ptr [rsi + 8]", "or rax, rcx"]
        cases = {"bswap rax; test al, al": (["bswap rax", "test al, al", "jne 0x40"], "tag[7,15] expected[7,15]"),
                 "and rax, 0xff": (["and rax, 255", "test rax, rax", "jne 0x40"], "tag[0,8] expected[0,8]"),
                 "and eax, -256": (["and eax, -256", "test eax, eax", "jne 0x40"], "tag[1-3,9-11] expected[1-3,9-11]"),
                 "or rax, -256": (["or rax, -256", "test rax, rax", "jne 0x40"], "tag[0,8] expected[0,8]"),
                 "test rax, 0xff00": (["test rax, 65280", "jne 0x40"], "tag[1,9] expected[1,9]")}
        for name, (lines, kept) in cases.items():
            with self.subTest(case=name):
                judged = scan.judge_extent("x86-64", listing(*x86, *lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        for constant in ("and rax, 0", "cmp rax, rax"):
            with self.subTest(constant=constant):
                judged = scan.judge_extent("x86-64", listing(*x86, constant, "je 0x40"), CALLEES)
                self.assertEqual(judged["decision"], [], constant)
                self.assertIn("paths reach no conditional branch", judged["reason"])
        simd = listing("movdqu xmm0, xmmword ptr [rdi]", "pxor xmm0, xmmword ptr [rsi]", "movq xmm1, xmm0", "pmovmskb eax, xmm1",
                       "test eax, eax", "je 0x40")
        judged = scan.judge_extent("x86-64", simd, CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("je"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7] expected[0-7]"))

    def test_aarch64_logical_immediates_mask_their_bytes(self):
        arm = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        cases = {"tst x12, #0xff": (["tst x12, #0xff", "b.ne 0x40"], "tag[0,8] expected[0,8]"),
                 "and x12, x12, #0xff00": (["and x12, x12, #0xff00", "cbz x12, 0x40"], "tag[1,9] expected[1,9]"),
                 "ands x12, x12, #0xff": (["ands x12, x12, #0xff", "b.eq 0x40"], "tag[0,8] expected[0,8]"),
                 "orr x12, x12, #0xffffffffffffff00": (["orr x12, x12, #0xffffffffffffff00", "cbz x12, 0x40"], "tag[0,8] expected[0,8]")}
        for name, (lines, kept) in cases.items():
            with self.subTest(case=name):
                judged = scan.judge_extent("aarch64", listing(*arm, *lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if re.match(r"(b\.|cb)", entry["instruction"]))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        decision = scan.judge_extent("aarch64", fixture("aarch64-decision"), CALLEES)
        self.assertEqual(decision["verdict"], "pass", "`tst w0, #0xff` keeps the black_box result's low byte")

    def test_byte_reversals_and_shuffles_are_permutations(self):
        arm = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        cases = {"rev x12, x12": "tag[4-7,12-15] expected[4-7,12-15]", "rbit x12, x12": "tag[4-7,12-15] expected[4-7,12-15]",
                 "rev16 x12, x12": "tag[0-3,8-11] expected[0-3,8-11]", "rev32 x12, x12": "tag[0-3,8-11] expected[0-3,8-11]"}
        for reverse, kept in cases.items():
            with self.subTest(reverse=reverse):
                judged = scan.judge_extent("aarch64", listing(*arm, reverse, "cbz w12, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        judged = scan.judge_extent("aarch64", listing(*arm, "rev16 w13, w12", "cbz w13, 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual(branch["depends"], "tag[0-3,8-11] expected[0-3,8-11]", "a w reversal covers four bytes")
        vectors = {"rbit v3.16b, v2.16b": ("umov w8, v3.b[0]", "tag[0] expected[0]"),
                   "rev16 v3.16b, v2.16b": ("umov w8, v3.b[0]", "tag[1] expected[1]"),
                   "rev32 v3.8h, v2.8h": ("umov w8, v3.h[0]", "tag[2-3] expected[2-3]"),
                   "rev64 v3.4s, v2.4s": ("umov w8, v3.s[0]", "tag[4-7] expected[4-7]")}
        for reverse, (extract, kept) in vectors.items():
            with self.subTest(reverse=reverse):
                lines = ["ldr q0, [x0]", "ldr q1, [x1]", "eor v2.16b, v0.16b, v1.16b", reverse, extract, "cbz w8, 0x40"]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        x86 = ["movdqu xmm0, xmmword ptr [rdi]", "pxor xmm0, xmmword ptr [rsi]"]
        shuffles = {"psrldq xmm0, 8": "tag[8-15] expected[8-15]", "pslldq xmm0, 8": None,
                    "punpckhqdq xmm0, xmm0": "tag[8-15] expected[8-15]", "punpcklqdq xmm0, xmm1": "tag[0-7] expected[0-7]"}
        for shuffle, kept in shuffles.items():
            with self.subTest(shuffle=shuffle):
                judged = scan.judge_extent("x86-64", listing(*x86, "pxor xmm1, xmm1", shuffle, "movq rax, xmm0", "test rax, rax", "jne 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
                self.assertEqual((judged["verdict"], branch.get("depends")), ("flagged", kept))

    def test_moves_and_extractions_keep_byte_positions(self):
        """`fmov`, `umov`, `ins` and `dup` move bytes positionally, `extr` selects from the concatenation, vector
        `cnt` and `pmovmskb` work per byte or per half, and `bt` reads the byte that holds its bit."""
        folded = ["ldr q0, [x0]", "ldr q1, [x1]", "eor v0.16b, v0.16b, v1.16b"]
        cases = {"fmov x8, d0": (["fmov x8, d0", "cbz w8, 0x40"], "tag[0-3] expected[0-3]"),
                 "umov w8, v0.s[1]": (["umov w8, v0.s[1]", "cbz w8, 0x40"], "tag[4-7] expected[4-7]"),
                 "dup v2.4s, w8": (["umov w8, v0.s[2]", "dup v2.4s, w8", "umov w9, v2.s[3]", "cbz w9, 0x40"], "tag[8-11] expected[8-11]"),
                 "ins v2.s[1], w8": (["umov w8, v0.s[2]", "ins v2.s[1], w8", "umov w9, v2.b[5]", "cbz w9, 0x40"], "tag[9] expected[9]"),
                 "cnt v0.16b": (["cnt v0.16b, v0.16b", "umov w8, v0.b[0]", "cbz w8, 0x40"], "tag[0] expected[0]")}
        for name, (lines, kept) in cases.items():
            with self.subTest(case=name):
                judged = scan.judge_extent("aarch64", listing(*folded, *lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        for extract, kept in (("extr x12, x8, x9, #32", "expected[4-7]"), ("extr x12, x8, x9, #4", "expected[0-4]")):
            with self.subTest(extract=extract):
                judged = scan.judge_extent("aarch64", listing("ldr x8, [x0]", "ldr x9, [x1]", extract, "cbz w12, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual(branch["depends"], kept)
        for idiom in ("eon x12, x12, x12", "orn x12, x12, x12"):
            with self.subTest(idiom=idiom):
                lines = ["ldr x12, [x0]", idiom, "ldrb w13, [x1]", "orr x12, x12, x13", "cbz x12, 0x40"]
                branch = next(entry for entry in scan.judge_extent("aarch64", listing(*lines), CALLEES)["extent"]
                              if entry["instruction"].startswith("cbz"))
                self.assertEqual(branch["depends"], "expected[0]")
        x86 = ["movdqu xmm0, xmmword ptr [rdi]", "pxor xmm0, xmmword ptr [rsi]"]
        judged = scan.judge_extent("x86-64", listing(*x86, "pmovmskb eax, xmm0", "test al, al", "jne 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7] expected[0-7]"))
        judged = scan.judge_extent("x86-64", listing(*x86, "pandn xmm0, xmm0", "movq xmm1, qword ptr [rdi]", "por xmm0, xmm1",
                                                      "pmovmskb eax, xmm0", "test eax, eax", "jne 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual(branch["depends"], "tag[0-7]", "self-pandn is zero")
        judged = scan.judge_extent("x86-64", listing(*x86, "andnps xmm0, xmm0", "movq xmm1, qword ptr [rdi]", "por xmm0, xmm1",
                                                      "pmovmskb eax, xmm0", "test eax, eax", "jne 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual(branch["depends"], "tag[0-7]", "self-andnps is zero")
        bit = listing("mov rax, qword ptr [rdi]", "xor rax, qword ptr [rsi]", "test al, al", "bt rax, 0", "jc 0x40")
        judged = scan.judge_extent("x86-64", bit, CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jc"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0] expected[0]"))

    def test_extensions_nops_and_argument_stores(self):
        """Extensions keep the bytes they copy and sign-extend from the top one; a shifted vector immediate stays
        byte-local; a memory-form `nop` touches nothing; a store through an argument pointer refuses the site."""
        folded = ["ldr q0, [x0]", "ldr q1, [x1]", "eor v0.16b, v0.16b, v1.16b", "fmov x8, d0"]
        cases = {"uxtb w8, w8": "tag[0] expected[0]", "uxth w8, w8": "tag[0-1] expected[0-1]",
                 "sxtb w8, w8": "tag[0] expected[0]", "sxth x8, w8": "tag[0-1] expected[0-1]",
                 "sxtw x8, w8": "tag[0-3] expected[0-3]"}
        for extend, kept in cases.items():
            with self.subTest(extend=extend):
                judged = scan.judge_extent("aarch64", listing(*folded, extend, "cbz x8, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", kept))
        judged = scan.judge_extent("aarch64", listing("ldr q0, [x0]", "orr v0.4s, #0x1, lsl #8", "umov w8, v0.b[2]", "cbz w8, 0x40"), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual(branch["depends"], "tag[2]", "a shifted vector immediate keeps the other bytes")
        x86 = listing("nop word ptr cs:[rax + rax]", "mov rax, qword ptr [rdi]", "nop dword ptr [rax]", "test rax, rax", "jne 0x40")
        judged = scan.judge_extent("x86-64", x86, CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual((judged["verdict"], branch["depends"], judged["falsifiers"]),
                         ("flagged", "tag[0-7]", ["falsifier: a branch on a partial comparison"]))
        for sign, machine in (("sxtw x8, w8", None), ("ldrsw x8, [x0]", "aarch64"), ("ldrsh x8, [x0]", "aarch64"), ("ldrsb x8, [x0]", "aarch64")):
            lines = [*folded, sign] if machine is None else [sign]
            with self.subTest(sign=sign):
                judged = scan.judge_extent("aarch64", listing(*lines, "tbnz x8, #63, 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("tbnz"))
                top = {"sxtw x8, w8": "tag[3] expected[3]", "ldrsw x8, [x0]": "tag[3]", "ldrsh x8, [x0]": "tag[1]", "ldrsb x8, [x0]": "tag[0]"}[sign]
                self.assertEqual(branch["depends"], top, "the sign bytes come from the top copied byte")
        signed = listing("movsxd rax, dword ptr [rdi]", "bswap rax", "test al, al", "jne 0x40")
        branch = next(entry for entry in scan.judge_extent("x86-64", signed, CALLEES)["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual(branch["depends"], "tag[3]")
        for store, machine in (("str xzr, [x0]", "aarch64"), ("mov qword ptr [rdi], 0", "x86-64")):
            with self.subTest(store=store), self.assertRaisesRegex(scan.Refusal, "through an argument pointer"):
                scan.judge_extent(machine, listing(store), CALLEES)

    def test_bounded_counts_and_vector_immediate_masks(self):
        """A bit count fits one byte, so its upper bytes are constant; a vector immediate fixes the bytes it fills."""
        arm = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x8, x8, x9"]
        for count in ("clz x8, x8", "cls x8, x8", "cnt x8, x8"):
            with self.subTest(count=count):
                judged = scan.judge_extent("aarch64", listing(*arm, count, "tbnz x8, #8, 0x40"), CALLEES)
                self.assertEqual(judged["decision"], [], count)
                self.assertIn("paths reach no conditional branch", judged["reason"])
                low = scan.judge_extent("aarch64", listing(*arm, count, "tbnz x8, #0, 0x40"), CALLEES)
                self.assertEqual(low["verdict"], "pass", "the low byte carries every source byte")
        x86 = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]", "xor rcx, qword ptr [rsi + 8]",
               "or rax, rcx"]
        for count in ("popcnt rax, rax", "lzcnt rax, rax", "tzcnt rax, rax"):
            with self.subTest(count=count):
                judged = scan.judge_extent("x86-64", listing(*x86, count, "test rax, 65280", "jne 0x40"), CALLEES)
                self.assertEqual(judged["decision"], [], count)
        masks = {"bic v0.8h, #0xff, lsl #8": "tag[0,2]", "orr v0.4s, #0xff": "tag[1-3]", "bic v0.16b, #0xff": None}
        for mask, kept in masks.items():
            with self.subTest(mask=mask):
                lines = ["ldr q0, [x0]", mask, "umov w8, v0.s[0]", "cbz w8, 0x40"]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual(branch.get("depends"), kept)

    def test_a_vector_store_writes_only_its_width(self):
        lines = ["movzx eax, byte ptr [rdi]", "mov qword ptr [rsp + 8], rax", "movdqu xmm1, xmmword ptr [rdi]",
                 "pxor xmm1, xmmword ptr [rsi]", "movq qword ptr [rsp], xmm1", "mov rcx, qword ptr [rsp + 8]", "test rcx, rcx",
                 "jne 0x40"]
        judged = scan.judge_extent("x86-64", listing(*lines), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0]"))

    def test_a_call_replaces_the_link_register(self):
        lines = ["ldr x30, [x0]", "ldrb w19, [x0]", "bl 0x900 <kestrike::net::tag_compare_tests::accepted>",
                 "orr x3, x30, x19", "cbz x3, 0x40"]
        judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0]"))

    def test_movk_replaces_one_halfword_and_keeps_the_others(self):
        lines = ["ldr x8, [x0]", "movk x8, #0x1234, lsl #16", "movk x8, #0x1234, lsl #32", "movk x8, #0x1234, lsl #48",
                 "cbz x8, 0x40"]
        judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-1]"))
        low = listing("ldr x8, [x0]", "movk x8, #0x1234", "cbz x8, 0x40")
        branch = next(entry for entry in scan.judge_extent("aarch64", low, CALLEES)["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual(branch["depends"], "tag[2-7]")

    def test_a_complement_keeps_each_bytes_dependency(self):
        x86 = listing("mov rax, qword ptr [rdi]", "not rax", "test al, al", "jne 0x40")
        judged = scan.judge_extent("x86-64", x86, CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("jne"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0]"))

    def test_a_test_bit_branch_reads_the_byte_that_holds_its_bit(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        for test, kept in (("tbz x12, #0, 0x40", "tag[0,8] expected[0,8]"), ("tbnz x12, #29, 0x40", "tag[3,11] expected[3,11]")):
            with self.subTest(test=test):
                judged = scan.judge_extent("aarch64", listing(*full, test), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("tb"))
                self.assertEqual((judged["verdict"], branch["depends"], branch["role"]),
                                 ("flagged", kept, "falsifier: a branch on a partial comparison"))

    def test_an_aarch64_self_combination_clears_its_register(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        for idiom in ("eor x12, x12, x12", "sub x12, x12, x12", "bic x12, x12, x12"):
            with self.subTest(idiom=idiom):
                lines = [*full, idiom, "ldrb w13, [x0]", "orr x12, x12, x13", "cbz x12, 0x40"]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0]"))
        vector = ["ldr q0, [x0]", "ldr q1, [x1]", "eor v0.16b, v0.16b, v1.16b", "eor v0.16b, v0.16b, v0.16b",
                  "ldr d1, [x0]", "orr v0.16b, v0.16b, v1.16b", "mov x8, v0.d[0]", "cbz x8, 0x40"]
        judged = scan.judge_extent("aarch64", listing(*vector), CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7]"))

    def test_a_call_clobbers_the_upper_half_of_v8_to_v15(self):
        """The AArch64 procedure call standard preserves only the low 64 bits of `v8`-`v15` across a call."""
        for lane, kept in (("v8.d[1]", None), ("v8.d[0]", "tag[0-7]")):
            with self.subTest(lane=lane):
                lines = ["ldr q8, [x0]", "bl 0x900 <kestrike::net::tag_compare_tests::accepted>", f"mov x9, {lane}",
                         "cbz x9, 0x40"]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((judged["verdict"], branch.get("depends")), ("flagged", kept))
                if kept is None:
                    self.assertIn("paths reach no conditional branch", judged["reason"])

    def test_a_declared_conditional_tail_call_ends_its_path_and_is_listed(self):
        lines = ["ldp x10, x11, [x0]", "ldp x12, x13, [x1]", "eor x10, x10, x12", "eor x11, x11, x13",
                 "orr x14, x10, x11", "cmp x14, #0",
                 "b.ne 0x900 <kestrike::net::tag_compare_tests::rejected>",
                 "b 0x904 <kestrike::net::tag_compare_tests::accepted>"]
        judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
        self.assertEqual((judged["verdict"], judged["paths"]), ("pass", 2))
        self.assertEqual(judged["calls"], ["kestrike::net::tag_compare_tests::accepted",
                                           "kestrike::net::tag_compare_tests::rejected"])

    def test_the_walk_caps_its_paths(self):
        def forks(count):
            return [line for k in range(count) for line in (f"cbz x3, {8 * k + 8:#x} <f+{8 * k + 8:#x}>", "nop")]
        self.assertEqual(scan.judge_extent("aarch64", listing(*forks(12)), CALLEES)["paths"], 4096)
        with self.assertRaisesRegex(scan.Refusal, "more than 4096 paths"):
            scan.judge_extent("aarch64", listing(*forks(13)), CALLEES)

    def test_a_call_result_carries_only_the_arguments_its_callee_takes(self):
        lines = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x2, x8, x9",
                 "mov x0, x8", "bl 0x100 <subtle::black_box::<u8>>", "tst w0, #0xff", "b.eq 0x28 <f+0x28>", "ret", "ret"]
        judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
        self.assertEqual(judged["verdict"], "flagged", "the low half alone reaches black_box")
        self.assertEqual(judged["falsifiers"], ["falsifier: a branch on a partial comparison"])

    def test_flags_survive_an_instruction_that_keeps_them(self):
        x86 = listing("movzx eax, byte ptr [rdi]", "cmp al, byte ptr [rsi]", "movdqu xmm0, xmmword ptr [rdi]",
                      "movdqu xmm1, xmmword ptr [rsi]", "pxor xmm0, xmm1", "jne 0x1c <f+0x1c>", "ret", "ret")
        judged = scan.judge_extent("x86-64", x86, CALLEES)
        self.assertEqual(judged["verdict"], "flagged")
        self.assertIn("tag[0] expected[0]", [entry.get("depends") for entry in judged["extent"]])

    def test_a_bitfield_insert_keeps_the_bytes_outside_its_field(self):
        """`bfi` and `bfxil` replace one field of the destination, so its other bits keep their tag bytes."""
        full = ["ldp x10, x11, [x0]", "ldp x12, x13, [x1]", "eor x10, x10, x12", "eor x11, x11, x13",
                "orr x14, x10, x11", "cmp x14, #0", "b.eq 0x34 <f+0x34>", "ret", "ret"]
        # `bfi` replaces bits 8-15 and keeps tag[0]; `bfxil` replaces bits 0-7 and keeps tag[1].
        cases = {"bfi x8, x9, #8, #8": ("ldrb w8, [x0]", "tag[0]"),
                 "bfxil x8, x9, #0, #8": ("ldrh w8, [x0]", "tag[0-1]")}
        for insert, (load, kept) in cases.items():
            with self.subTest(insert=insert):
                lines = [load, "mov x9, #0", insert, "cbz x8, 0x14 <f+0x14>", "nop", *full]
                judged = scan.judge_extent("aarch64", listing(*lines), CALLEES)
                self.assertEqual(judged["verdict"], "flagged", judged["reason"])
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("cbz"))
                self.assertEqual((branch.get("depends"), branch.get("role")),
                                 (kept, "falsifier: a branch on a partial comparison"))

    def test_an_overwrite_instruction_reads_no_stale_destination(self):
        """`popcnt`, `lzcnt`, `tzcnt`, `pmovmskb` and three-operand `imul` write their destination without reading
        it, so the bytes it held before do not reach the result."""
        halves = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]",
                  "xor rcx, qword ptr [rsi + 8]"]
        for overwrite in ("popcnt rcx, rax", "lzcnt rcx, rax", "tzcnt rcx, rax", "imul rcx, rax, 1"):
            with self.subTest(overwrite=overwrite):
                judged = scan.judge_extent("x86-64", listing(*halves, overwrite, "test rcx, rcx", "je 0x40"), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("je"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7] expected[0-7]"))
        simd = listing("mov rax, qword ptr [rsi]", "movq xmm1, qword ptr [rdi]", "pmovmskb eax, xmm1", "test eax, eax",
                       "je 0x40")
        judged = scan.judge_extent("x86-64", simd, CALLEES)
        branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("je"))
        self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7]"))

    def test_a_zero_idiom_clears_its_register_on_every_width(self):
        """Self-`xor`/`sub` write every flag, so they also end a partial flag update; SIMD self-`pxor`,
        `xorps` and `pcmpeqb` produce an input-independent constant and leave the flags alone."""
        judged = scan.judge_extent("x86-64", listing("mov rax, qword ptr [rdi]", "inc rax", "xor ecx, ecx",
                                                      "je 0x40"), CALLEES)
        self.assertEqual(judged["verdict"], "flagged", "a self-xor after a partial flag update is a full flag write")
        self.assertIn("paths reach no conditional branch", judged["reason"])
        for idiom in ("pxor xmm0, xmm0", "xorps xmm0, xmm0", "pcmpeqb xmm0, xmm0"):
            with self.subTest(idiom=idiom):
                lines = ["movdqu xmm0, xmmword ptr [rdi]", "pxor xmm0, xmmword ptr [rsi]", idiom,
                         "movq xmm1, qword ptr [rdi]", "por xmm0, xmm1", "pmovmskb eax, xmm0", "test eax, eax", "je 0x40"]
                judged = scan.judge_extent("x86-64", listing(*lines), CALLEES)
                branch = next(entry for entry in judged["extent"] if entry["instruction"].startswith("je"))
                self.assertEqual((judged["verdict"], branch["depends"]), ("flagged", "tag[0-7]"), judged["reason"])

    def test_a_partial_flag_update_over_independent_flags_refuses_the_condition(self):
        """`inc` keeps CF: a `jc` after `xor ecx, ecx; inc rax` reads a flag the tags never reached."""
        full = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]",
                "xor rcx, qword ptr [rsi + 8]", "or rax, rcx"]
        with self.assertRaisesRegex(scan.Refusal, "updated in part"):
            scan.judge_extent("x86-64", listing(*full, "xor ecx, ecx", "inc rax", "jc 0x40"), CALLEES)

    def test_an_exclusive_store_writes_an_independent_status(self):
        full = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        for store in ("stxr w12, x13, [sp]", "stlxr w12, x13, [sp]", "stxp w12, x13, x14, [sp]"):
            with self.subTest(store=store):
                judged = scan.judge_extent("aarch64", listing(*full, store, "cbnz w12, 0x40"), CALLEES)
                self.assertEqual((judged["verdict"], judged["decision"]), ("flagged", []))
                self.assertIn("paths reach no conditional branch", judged["reason"])

    def test_a_trap_ends_its_path(self):
        x86 = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]",
               "xor rcx, qword ptr [rsi + 8]", "or rax, rcx"]
        arm = ["ldp x8, x9, [x0]", "ldp x10, x11, [x1]", "eor x8, x8, x10", "eor x9, x9, x11", "orr x12, x8, x9"]
        cases = {"ud2": ("x86-64", x86 + ["ud2", "test rax, rax", "je 0x40"]),
                 "int3": ("x86-64", x86 + ["int3", "test rax, rax", "je 0x40"]),
                 "hlt": ("x86-64", x86 + ["hlt", "test rax, rax", "je 0x40"]),
                 "brk #0x1": ("aarch64", arm + ["brk #0x1", "cbz x12, 0x40"]),
                 "udf #0x0": ("aarch64", arm + ["udf #0x0", "cbz x12, 0x40"])}
        for trap, (machine, lines) in cases.items():
            with self.subTest(trap=trap):
                judged = scan.judge_extent(machine, listing(*lines), CALLEES)
                self.assertEqual((judged["verdict"], judged["paths"], judged["decision"]), ("flagged", 1, []))
                self.assertIn("paths reach no conditional branch", judged["reason"])

    def test_a_pointer_survives_only_a_64_bit_copy_and_never_a_spill(self):
        """A 32-bit move or add truncates the address, so the result is no tracked pointer; a store of a tracked
        pointer, which the model does not follow through memory, refuses the site."""
        truncated = {"mov w2, w0": "aarch64", "add w2, w0, #8": "aarch64", "mov edx, edi": "x86-64",
                     "lea edx, [rdi + 8]": "x86-64", "add edi, 8": "x86-64"}
        for copy, machine in truncated.items():
            load = "ldr x8, [x2]" if machine == "aarch64" else (
                "mov rax, qword ptr [rdi]" if copy.startswith("add") else "mov rax, qword ptr [rdx]")
            with self.subTest(copy=copy), self.assertRaisesRegex(scan.Refusal, "does not track"):
                scan.judge_extent(machine, listing(copy, load), CALLEES)
        spills = {"str x0, [sp, #8]": "aarch64", "stp x29, x1, [sp, #-16]!": "aarch64",
                  "mov qword ptr [rsp - 8], rdi": "x86-64", "push rsi": "x86-64"}
        for spill, machine in spills.items():
            with self.subTest(spill=spill), self.assertRaisesRegex(scan.Refusal, "a tracked pointer"):
                scan.judge_extent(machine, listing(spill), CALLEES)

    def test_a_one_operand_multiply_writes_its_product_to_rax_and_rdx(self):
        """One-operand `imul` multiplies the accumulator by its operand into `rdx:rax`, or `ax` for a byte operand."""
        full = ["mov rax, qword ptr [rdi]", "mov rcx, qword ptr [rdi + 8]", "xor rax, qword ptr [rsi]",
                "xor rcx, qword ptr [rsi + 8]", "or rax, rcx", "je 0x38 <f+0x38>", "ret", "ret"]
        for accumulator in ("rax", "rdx"):
            with self.subTest(accumulator=accumulator):
                lines = ["movzx ecx, byte ptr [rdi]", "mov eax, 1", "imul rcx", f"test {accumulator}, {accumulator}",
                         "je 0x18 <f+0x18>", "nop", "xor ecx, ecx", *full]
                judged = scan.judge_extent("x86-64", listing(*lines), CALLEES)
                self.assertEqual(judged["verdict"], "flagged", judged["reason"])
                branch = next(entry for entry in judged["extent"] if entry["address"] == "0x10")
                self.assertEqual((branch.get("depends"), branch.get("role")),
                                 ("tag[0]", "falsifier: a branch on a partial comparison"))
        byte = listing("movzx ecx, byte ptr [rdi]", "mov eax, 1", "imul cl", "test eax, eax", "jne 0x40")
        self.assertEqual(scan.judge_extent("x86-64", byte, CALLEES)["falsifiers"],
                         ["falsifier: a branch on a partial comparison"], "a byte multiply writes `ax`")


class Run(unittest.TestCase):
    def test_the_run_credits_only_when_the_decision_passes_and_the_control_is_flagged(self):
        for machine in ("x86-64", "aarch64"):
            report = scan.judge(extents(machine, f"{machine}-decision", f"{machine}-early-return"),
                                complete_identity("d" * 64), TEST_DECLARATION, "abc")
            self.assertEqual((report["code"], report["credited"]), (scan.CREDITED, True), report.get("reason"))
            credited_control = scan.judge(extents(machine, f"{machine}-decision", f"{machine}-decision"),
                                          complete_identity("d" * 64), TEST_DECLARATION, "abc")
            self.assertEqual((credited_control["code"], credited_control["credited"]), (scan.OFF, False))
            self.assertIn("early-return-control pass, expected control", credited_control["reason"])
        failed = scan.judge(extents("aarch64", "aarch64-unfolded", "aarch64-early-return"),
                            complete_identity("d" * 64), TEST_DECLARATION, "abc")
        self.assertEqual((failed["code"], failed["credited"]), (scan.OFF, False))

    def test_an_incomplete_identity_is_refused_before_judging(self):
        gaps = {"the identity lacks lto": {"lto": ""},
                "not the release profile": {"profile": "test"},
                "opt_level": {"cargo_profile": {"opt_level": "0", "debug_assertions": True, "test": True}},
                "debug_assertions": {"cargo_profile": {"opt_level": "3", "debug_assertions": True, "test": True}},
                "pins CARGO_PROFILE_RELEASE_LTO=false": {"profile_env": {"CARGO_PROFILE_DEV_LTO": "false"}},
                "the identity binds LTO 'true'": {"lto": "true", "profile_env": {"CARGO_PROFILE_RELEASE_LTO": "true"}},
                "the executable is": {"sha256": "e" * 64},
                "the identity lacks rustflags": {"rustflags": None},
                "the identity lacks native_build": {"native_build": []}}
        for reason, change in gaps.items():
            with self.subTest(reason=reason):
                report = scan.judge(extents("aarch64", "aarch64-decision", "aarch64-early-return"),
                                    {**complete_identity("d" * 64), **change}, TEST_DECLARATION, "abc")
                self.assertEqual((report["code"], report["credited"]), (scan.REFUSED, False))
                self.assertIn(reason, report["reason"])
                self.assertNotIn("sites", report)

    def test_an_identity_built_at_another_revision_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            recorded = extents("aarch64", "aarch64-decision", "aarch64-early-return")
            (evidence / "extents.json").write_text(json.dumps(recorded))
            (evidence / "identity.json").write_text(json.dumps(complete_identity("d" * 64)))
            (evidence / "pins.txt").write_text("- pin\n")
            callers_ran(evidence)
            report, receipt = scan.derive(evidence, "def")
            self.assertEqual((report["code"], report["credited"]), (scan.REFUSED, False))
            self.assertIn("the identity binds revision 'abc', the judgment is for 'def'", report["reason"])
            self.assertEqual((receipt["revision"], receipt["executed"], receipt["completion"]),
                             ("def", [], "tool failure"))

    def test_the_judgment_requires_the_callers_run_to_pass(self):
        """The receipt binds the callers' libtest output and exit status, and the judgment refuses evidence whose
        run is missing, exited nonzero, or reports a caller or count other than the declaration's."""
        callers = read_json(scan.DECLARATION)["callers"]
        cases = {"no recorded callers' run": None,
                 "exited 101": {"code": "101"},
                 "does not report": {"passed": len(callers) + 1},
                 "no ok line for": {"callers": [name + "_other" for name in callers]}}
        for reason, change in cases.items():
            with self.subTest(reason=reason), tempfile.TemporaryDirectory() as tmp:
                evidence = Path(tmp)
                (evidence / "extents.json").write_text(json.dumps(extents("aarch64", "aarch64-decision", "aarch64-early-return")))
                (evidence / "identity.json").write_text(json.dumps(complete_identity("d" * 64)))
                (evidence / "pins.txt").write_text("- pin\n")
                if change is not None:
                    callers_ran(evidence, **change)
                report, receipt = scan.derive(evidence, "abc")
                self.assertEqual((report["code"], report["credited"], receipt["completion"]),
                                 (scan.REFUSED, False, "tool failure"))
                self.assertIn(reason, report["reason"])
                self.assertNotIn("sites", report)

    def test_the_identity_refuses_an_unpinned_lto_and_an_empty_feature_list(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "kestrike-1"
            exe.write_bytes(b"\x7fELF")
            line = json.dumps({"reason": "compiler-artifact", "executable": str(exe),
                               "profile": {"opt_level": "3", "debug_assertions": False, "test": True},
                               "target": {"name": "kestrike", "kind": ["lib"]}})
            pinned = {"CARGO_PROFILE_RELEASE_LTO": "false", "RUSTFLAGS": "-C symbol-mangling-version=v0"}
            with mock.patch.dict(os.environ, pinned):
                record = scan.identity([line], "neon,aes", ["- pin"])
                self.assertEqual((record["sha256"], record["profile"], record["lto"]),
                                 (hashlib.sha256(b"\x7fELF").hexdigest(), "release", "false"))
                self.assertEqual(scan.identity_gaps(record, record["sha256"], record["revision"]), [])
                with self.assertRaisesRegex(scan.Refusal, "no target features"):
                    scan.identity([line], "", ["- pin"])
            with mock.patch.dict(os.environ, {}, clear=True), \
                    self.assertRaisesRegex(scan.Refusal, "CARGO_PROFILE_RELEASE_LTO is unset"):
                scan.identity([line], "neon", ["- pin"])

    def test_the_declaration_needs_a_pass_site_and_a_control_naming_its_falsifier(self):
        cases = {"a pass site and a control site": ([SITES[0]], {}),
                 "a control, and only a control": ([SITES[0], {**SITES[1], "flags": None}], {}),
                 "share a symbol": ([SITES[0], {**SITES[0], "site": "other", "expect": "control", "flags": "x"}], {}),
                 "share a name": ([SITES[0], {**SITES[1], "site": SITES[0]["site"]}], {}),
                 "argument count": (SITES, {"memcmp": "three"})}
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "decl.json"
            for reason, (sites, callees) in cases.items():
                path.write_text(json.dumps({"sites": sites, "callees": callees, "callers": ["t"]}))
                with self.subTest(reason=reason), self.assertRaisesRegex(scan.Refusal, reason):
                    scan.load_declaration(path)
            path.write_text(json.dumps({"sites": SITES, "callees": {}, "callers": ["t", "t"]}))
            with self.assertRaisesRegex(scan.Refusal, "each declared caller test once"):
                scan.load_declaration(path)


class Admission(unittest.TestCase):
    def record(self, image, objdump=None):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kestrike"
            path.write_bytes(image)
            listing_path = Path(tmp) / "listing.txt"
            listing_path.write_text(fixture("aarch64-decision"))
            objdump = objdump or [sys.executable, "-c", f"print(open({str(listing_path)!r}).read())"]
            return scan.record_extents(path, SITES, objdump, COPY)

    def test_both_machines_are_admitted_and_each_site_resolves_to_one_symbol(self):
        functions = [("tag_compare_decision", [0] * 4), ("tag_compare_early_return", [0] * 4)]
        for machine, name in ((scan.EM_X86_64, "x86-64"), (scan.EM_AARCH64, "aarch64")):
            with self.subTest(machine=name), mock.patch.object(scan.subprocess, "run", wraps=scan.subprocess.run) as run:
                recorded = self.record(barriers_fixture.elf(functions, machine=machine))
                self.assertEqual(recorded["machine"], name)
                self.assertEqual(recorded["sites"]["tag-decision"]["size"], 16)
                self.assertIn("tag_compare_decision", recorded["sites"]["tag-decision"]["disassembly"])
                decodes = [call.args[0] for call in run.call_args_list if any(str(arg).startswith("--start-address") for arg in call.args[0])]
                self.assertTrue(decodes and all("-z" in argv for argv in decodes), "objdump decodes zero runs")

    def test_another_machine_a_missing_symbol_and_an_extent_outside_its_section_are_refused(self):
        with self.assertRaises(Exception) as refused:
            self.record(barriers_fixture.elf([("tag_compare_decision", [0])], machine=40))
        self.assertIn("not one of [62, 183]", str(refused.exception))
        recorded = self.record(barriers_fixture.elf([("tag_compare_decision", [0] * 4),
                                                     ("tag_compare_decision", [0] * 4)]))
        self.assertEqual(recorded["sites"]["tag-decision"], {"refused": "2 function symbols named tag_compare_decision"})
        self.assertEqual(recorded["sites"]["early-return-control"],
                         {"refused": "0 function symbols named tag_compare_early_return"})
        outside = self.record(barriers_fixture.elf([("tag_compare_decision", [0], 0x9000, 16)]))
        self.assertIn("outside one executable PROGBITS section", outside["sites"]["tag-decision"]["refused"])

    def test_the_judgment_derives_from_the_recorded_evidence_alone(self):
        with tempfile.TemporaryDirectory() as tmp:
            evidence = Path(tmp)
            recorded = extents("aarch64", "aarch64-decision", "aarch64-early-return")
            (evidence / "extents.json").write_text(json.dumps(recorded))
            (evidence / "identity.json").write_text(json.dumps(complete_identity("d" * 64)))
            (evidence / "pins.txt").write_text("- pin\n")
            callers_ran(evidence)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(scan.main(["judge", "--evidence", tmp, "--revision", "abc"]), scan.CREDITED)
            report, receipt = scan.derive(evidence, "abc")
            self.assertEqual(report, read_json(evidence / "report.json"))
            self.assertEqual((receipt["job"], receipt["executed"], receipt["completion"]),
                             ("tag-compare-aarch64", ["early-return-control", "tag-decision"], "completed"))
            self.assertEqual(receipt["tool"]["provenance"], ["- pin"])
            self.assertLessEqual({"callers.txt", "exit.txt", "extents.json", "identity.json", "scripts/scan-barriers.py",
                                  "scripts/scan-tag-compare.py"}, set(receipt["inputs"]))

    def test_the_limits_command_prints_every_limit(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(scan.main(["limits"]), scan.CREDITED)
        self.assertEqual(out.getvalue().splitlines(), scan.LIMITS)


if __name__ == "__main__":
    unittest.main()
