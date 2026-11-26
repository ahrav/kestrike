#!/usr/bin/env python3
"""Self-checks for scripts/scan-barriers.py over synthetic ELF64 files: the
decoder vectors against both predicates, neighbor barriers, admission
refusals with the inspected extent, artifact selection and the build identity."""

import contextlib
import importlib.util
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("scan_barriers", ROOT / "scripts/scan-barriers.py")
assert SPEC is not None and SPEC.loader is not None
scan = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(scan)

ISH, SY, ISHLD, ISHST, NSHLD, NSH = 0xD5033BBF, 0xD5033FBF, 0xD50339BF, 0xD5033ABF, 0xD50335BF, 0xD50337BF
NOP, DSB_SY, RET = 0xD503201F, 0xD5033F9F, 0xD65F03C0
TEXT = 0x1000
IDENTITY = [sys.executable, "-c", "import sys; sys.stdout.write(sys.stdin.read())"]
SITES = [{"site": "begin", "symbol": "begin", "order": "release"},
         {"site": "run", "symbol": "run", "order": "acquire"}]


def elf(functions, machine=scan.EM_AARCH64, kind=scan.ET_DYN, flags=scan.SHF_EXECINSTR, data=1, truncate=0,
        text_offset=None):
    """An ELF64 image whose text holds each function's words in order; a function is (name, words) or
    (name, words, address, size) to place or size its symbol apart from its words."""
    text, symbols = b"", []
    for function in functions:
        name, words = function[0], function[1]
        address = TEXT + len(text)
        text += struct.pack(f"<{len(words)}I", *words)
        symbols.append((name, *(function[2:] or (address, 4 * len(words)))))
    strtab, entries = b"\0", [bytes(24)]
    for name, address, size in symbols:
        entries.append(struct.pack("<IBBHQQ", len(strtab), scan.STT_FUNC, 0, 1, address, size))
        strtab += name.encode() + b"\0"
    symtab = b"".join(entries)
    body = text + symtab + strtab
    text_at, sym_at, str_at = 64, 64 + len(text), 64 + len(text) + len(symtab)
    shoff = 64 + len(body)
    headers = [bytes(64),
               struct.pack("<IIQQQQIIQQ", 0, scan.SHT_PROGBITS, flags | 0x2, TEXT,
                           text_at if text_offset is None else text_offset, len(text), 0, 0, 4, 0),
               struct.pack("<IIQQQQIIQQ", 0, scan.SHT_SYMTAB, 0, 0, sym_at, len(symtab), 3, 1, 8, 24),
               struct.pack("<IIQQQQIIQQ", 0, 3, 0, 0, str_at, len(strtab), 0, 0, 1, 0)]
    header = bytearray(64)
    header[:6] = bytes([0x7F, ord("E"), ord("L"), ord("F"), 2, data])
    struct.pack_into("<HH", header, 16, kind, machine)
    struct.pack_into("<Q", header, 40, shoff)
    struct.pack_into("<HH", header, 58, 64, len(headers))
    image = bytes(header) + body + b"".join(headers)
    return image[:len(image) - truncate] if truncate else image


class ScanBarriers(unittest.TestCase):
    def run_scan(self, image, sites=SITES):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kestrike"
            path.write_bytes(image)
            code, report = scan.scan(path, sites, IDENTITY, {"profile": "dev"})
        return code, report

    def site(self, report, name):
        return next(entry for entry in report["sites"] if entry["site"] == name)

    def test_each_decoder_vector_meets_the_acquire_and_release_rules(self):
        vectors = {ISH: (True, True), SY: (True, True), ISHLD: (True, False), ISHST: (False, False),
                   NSHLD: (False, False), NSH: (False, False), NOP: (False, False), DSB_SY: (False, False),
                   RET: (False, False)}
        for word, (acquire, release) in vectors.items():
            with self.subTest(word=hex(word)):
                self.assertEqual(scan.sufficient("acquire", word), acquire)
                self.assertEqual(scan.sufficient("release", word), release)
        self.assertEqual([scan.decode(word) for word in (ISH, SY, ISHLD, ISHST, NSHLD, NSH)],
                         ["DMB ISH", "DMB SY", "DMB ISHLD", "DMB ISHST", "DMB NSHLD", "DMB NSH"])
        self.assertIsNone(scan.decode(NOP))
        self.assertIsNone(scan.decode(DSB_SY))

    def test_sufficient_barriers_in_every_extent_credit_the_scan(self):
        code, report = self.run_scan(elf([("begin", [NOP, ISH, RET]), ("run", [ISHLD, RET])]))
        self.assertEqual(code, scan.CREDITED, report)
        self.assertTrue(report["credited"])
        self.assertEqual(self.site(report, "begin")["barriers"][0]["offset"], 4)
        self.assertEqual(self.site(report, "run")["words"], 2)
        self.assertEqual(len(report["sha256"]), 64)
        self.assertEqual(report["identity"], {"profile": "dev"})
        self.assertEqual(len(report["limits"]), 2)
        self.assertTrue(any(limit.startswith("physical clock") for limit in report["limits"]))

    def test_a_site_lists_the_functions_it_calls(self):
        bl_to_next = 0x94000000 | 1
        code, report = self.run_scan(elf([("begin", [NOP, bl_to_next]), ("callee", [ISH]), ("run", [ISHLD])]))
        self.assertEqual(code, scan.MISSING)
        self.assertEqual(self.site(report, "begin")["calls"], ["callee"])
        self.assertEqual(scan.call_offset(0x97FFFFFF), -4)
        self.assertIsNone(scan.call_offset(RET))

    def test_an_acquire_only_barrier_at_a_release_site_earns_nothing(self):
        code, report = self.run_scan(elf([("begin", [ISHLD, ISHST, NSH, RET]), ("run", [ISHLD])]))
        self.assertEqual(code, scan.MISSING, report)
        self.assertEqual(self.site(report, "begin")["verdict"], "fail")
        self.assertEqual(len(self.site(report, "begin")["barriers"]), 3)
        self.assertFalse(report["credited"])

    def test_weak_barriers_at_the_acquire_site_earn_nothing(self):
        code, report = self.run_scan(elf([("begin", [ISH]), ("run", [ISHST, NSHLD, NSH, NOP])]))
        self.assertEqual(code, scan.MISSING)
        self.assertEqual(self.site(report, "run")["verdict"], "fail")

    def test_a_barrier_in_the_following_symbol_earns_nothing(self):
        code, report = self.run_scan(elf([("begin", [NOP, RET]), ("neighbor", [ISH]), ("run", [ISHLD])]))
        self.assertEqual(code, scan.MISSING)
        self.assertEqual(self.site(report, "begin")["barriers"], [])

    def test_a_barrier_past_a_short_symbol_size_earns_nothing(self):
        code, report = self.run_scan(elf([("begin", [NOP, ISH], TEXT, 4), ("run", [ISHLD])]))
        self.assertEqual(code, scan.MISSING)
        self.assertEqual(self.site(report, "begin")["words"], 1)

    def test_the_wrong_artifact_is_refused_before_decoding(self):
        functions = [("begin", [ISH]), ("run", [ISHLD])]
        for image, reason in ((elf(functions, machine=62), "not one of [183]"),
                              (elf(functions, kind=1), "not a linked executable"),
                              (elf(functions, data=2), "little-endian"),
                              (b"MZ" + bytes(100), "not an ELF file")):
            with self.subTest(reason=reason):
                code, report = self.run_scan(image)
                self.assertEqual(code, scan.REFUSED)
                self.assertIn(reason, report["reason"])
                self.assertNotIn("sites", report)
                self.assertFalse(report["credited"])

    def test_bad_symbols_are_refused_with_the_inspected_extent(self):
        cases = {
            "missing": ([("run", [ISHLD])], "0 function symbols"),
            "ambiguous": ([("begin", [ISH]), ("begin", [ISH]), ("run", [ISHLD])], "2 function symbols"),
            "zero size": ([("begin", [ISH], TEXT, 0), ("run", [ISHLD])], "zero size"),
            "misaligned": ([("begin", [ISH, ISH], TEXT + 2, 4), ("run", [ISHLD])], "multiple of four"),
            "uneven size": ([("begin", [ISH, ISH], TEXT, 6), ("run", [ISHLD])], "multiple of four"),
            "outside its section": ([("begin", [ISH], TEXT, 64), ("run", [ISHLD])], "outside its section"),
        }
        for name, (functions, reason) in cases.items():
            with self.subTest(case=name):
                code, report = self.run_scan(elf(functions))
                self.assertEqual(code, scan.REFUSED, report)
                begin = self.site(report, "begin")
                self.assertEqual(begin["verdict"], "refused")
                self.assertIn(reason, begin["reason"])
                if name == "ambiguous":
                    self.assertEqual(len(begin["extents"]), 2)
                elif name != "missing":
                    self.assertIn("address", begin)
                    self.assertIn("size", begin)
                self.assertFalse(report["credited"])

    def test_a_non_executable_section_and_a_truncated_file_are_refused(self):
        code, report = self.run_scan(elf([("begin", [ISH]), ("run", [ISHLD])], flags=0))
        self.assertEqual(code, scan.REFUSED)
        self.assertIn("not executable", self.site(report, "begin")["reason"])
        code, report = self.run_scan(elf([("begin", [ISH]), ("run", [ISHLD])], truncate=8))
        self.assertEqual(code, scan.REFUSED)
        self.assertIn("outside the file", report["reason"])

    def test_an_extent_past_the_end_of_the_file_is_refused(self):
        code, report = self.run_scan(elf([("begin", [ISH]), ("run", [ISHLD])], text_offset=1 << 20))
        self.assertEqual(code, scan.REFUSED)
        self.assertIn("past the end of the file", self.site(report, "begin")["reason"])
        self.assertIn("address", self.site(report, "begin"))

    def test_a_promotion_suffix_from_the_demangler_still_matches(self):
        suffixed = [sys.executable, "-c",
                    "import sys; sys.stdout.write(''.join(l.rstrip('\\n') + ' (.llvm.7)\\n' for l in sys.stdin))"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kestrike"
            path.write_bytes(elf([("begin", [ISH]), ("run", [ISHLD])]))
            code, report = scan.scan(path, SITES, suffixed, None)
        self.assertEqual(code, scan.CREDITED, report)

    def test_a_demangler_that_drops_a_name_is_refused(self):
        dropping = [sys.executable, "-c", "import sys; sys.stdout.write(''.join(sys.stdin.readlines()[1:]))"]
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "kestrike"
            path.write_bytes(elf([("begin", [ISH]), ("run", [ISHLD])]))
            code, report = scan.scan(path, SITES, dropping, None)
        self.assertEqual(code, scan.REFUSED)
        self.assertIn("returned", report["reason"])

    def test_demangled_suffixes_are_dropped_before_matching(self):
        self.assertEqual(scan.SUFFIXES.sub("", "kestrike::f (.llvm.123)"), "kestrike::f")
        self.assertEqual(scan.SUFFIXES.sub("", "kestrike::f::h0123456789abcdef"), "kestrike::f")
        self.assertEqual(scan.SUFFIXES.sub("", "kestrike::f::h01"), "kestrike::f::h01")

    def test_the_declaration_needs_unique_named_sites_with_an_order(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "expected.json"
            for sites in ([], [{"site": "a", "symbol": "s", "order": "seqcst"}],
                          [{"site": "a", "symbol": "s", "order": "release"}, {"site": "b", "symbol": "s", "order": "release"}],
                          [{"site": "a", "order": "release"}], [{"site": "a", "symbol": "", "order": "release"}],
                          [{"site": "a", "symbol": 5, "order": "release"}], ["a"], [{"symbol": "s", "order": "release"}]):
                path.write_text(json.dumps({"sites": sites}))
                with self.subTest(sites=sites), self.assertRaises(scan.Refusal):
                    scan.load_declaration(path)
        sites = scan.load_declaration(scan.DECLARATION)
        self.assertEqual([site["order"] for site in sites], ["release", "release", "acquire", "acquire"])

    def test_selection_needs_exactly_one_library_test_executable(self):
        with tempfile.TemporaryDirectory() as tmp:
            exe = Path(tmp) / "kestrike-0"
            exe.write_bytes(b"")

            def artifact(name="kestrike", kind="lib", test=True):
                return json.dumps({"reason": "compiler-artifact", "executable": str(exe),
                                   "profile": {"test": test}, "target": {"name": name, "kind": [kind]}})
            self.assertEqual(scan.select([artifact(), artifact(test=False), artifact(name="sim_worker", kind="test")]), exe)
            for lines in ([], [artifact(), artifact()], [artifact(kind="test")]):
                with self.subTest(lines=len(lines)), self.assertRaises(scan.Refusal):
                    scan.select(lines)

    def test_the_identity_binds_the_selected_artifact_profile_revision_and_run(self):
        profile = {"opt_level": "1", "debuginfo": "line-tables-only", "test": True}
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            exe = tmp / "kestrike-1"
            exe.write_bytes(b"")
            (tmp / "build.json").write_text("not json\n" + json.dumps(
                {"reason": "compiler-artifact", "executable": str(exe), "profile": profile,
                 "target": {"name": "kestrike", "kind": ["lib"]}}) + "\n")
            (tmp / "pins.txt").write_text("- SPDK 25.5.1\n- rustc 1.99.0\n")
            argv = ["identity", "--cargo-json", str(tmp / "build.json"), "--target-features", "neon,lse",
                    "--pins", str(tmp / "pins.txt"), "--output", str(tmp / "identity.json")]
            env = {"CARGO_PROFILE_DEV_LTO": "false", "CARGO_PROFILE_DEV_OPT_LEVEL": "1", "RUSTFLAGS": "-C symbol-mangling-version=v0",
                   "GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "barriers"}
            with mock.patch.dict(os.environ, env):
                self.assertEqual(scan.main(argv), scan.CREDITED)
            identity = json.loads((tmp / "identity.json").read_text())
            revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
            self.assertEqual(identity, {
                "revision": revision, "ci": {"GITHUB_RUN_ID": "7", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": "barriers"},
                "executable": str(exe), "profile": "test", "cargo_profile": profile, "lto": "false",
                "profile_env": {"CARGO_PROFILE_DEV_LTO": "false", "CARGO_PROFILE_DEV_OPT_LEVEL": "1"},
                "rustflags": "-C symbol-mangling-version=v0", "target_features": ["neon", "lse"],
                "native_build": ["- SPDK 25.5.1", "- rustc 1.99.0"]})
            refusals = {"CARGO_PROFILE_DEV_LTO": ("CARGO_PROFILE_DEV_LTO", argv),
                        "target features": (None, [*argv[:4], "", *argv[5:]])}
            for reason, (unset, args) in refusals.items():
                with self.subTest(reason=reason), mock.patch.dict(os.environ, env):
                    if unset:
                        del os.environ[unset]
                    err = io.StringIO()
                    with contextlib.redirect_stderr(err):
                        self.assertEqual(scan.main(args), scan.REFUSED)
                    self.assertIn(reason, err.getvalue())

    def test_the_limits_command_prints_every_limit(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(scan.main(["limits"]), scan.CREDITED)
        self.assertEqual(out.getvalue().splitlines(), scan.LIMITS)

    def test_the_command_writes_a_report_and_exits_with_its_verdict(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            (tmp / "x").write_bytes(elf([("begin", [ISH]), ("run", [NOP])]))
            (tmp / "decl.json").write_text(json.dumps({"sites": SITES}))
            code = scan.main(["scan", "--executable", str(tmp / "x"), "--output", str(tmp / "r.json"),
                              "--declaration", str(tmp / "decl.json"), "--demangler", "cat"])
            self.assertEqual(code, scan.MISSING)
            self.assertEqual(self.site(json.loads((tmp / "r.json").read_text()), "run")["verdict"], "fail")


if __name__ == "__main__":
    unittest.main()
