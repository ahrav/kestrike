#!/usr/bin/env python3
"""Self-checks for scripts/judge-kani.py: complete harness runs credit and every unusable or mismatched run is refused."""

import argparse
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-kani.py"
_spec = importlib.util.spec_from_file_location("judge_kani", SCRIPT)
if _spec is None or _spec.loader is None:
    raise SystemExit(f"test-judge-kani: {SCRIPT} cannot be loaded")
judge_kani = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(judge_kani)
EXPECTED = judge_kani.declaration()
_fixture_spec = importlib.util.spec_from_file_location("test_judge_genmc", ROOT / "scripts/test-judge-genmc.py")
if _fixture_spec is None or _fixture_spec.loader is None:
    raise SystemExit("test-judge-kani: scripts/test-judge-genmc.py cannot be loaded")
genmc_fixture = importlib.util.module_from_spec(_fixture_spec)
_fixture_spec.loader.exec_module(genmc_fixture)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def profile(name):
    return sorted(set(EXPECTED["profiles"]["pr"]) | set(EXPECTED["profiles"][name]))


def verified(name, checks=None, covers=None, unreachable=None):
    """The result lines Kani's terse output prints for one complete, successful run of `name`, at its declared unreachable count."""
    covers = EXPECTED["harnesses"][name]["covers"] if covers is None else covers
    unreachable = EXPECTED["harnesses"][name]["unreachable"] if unreachable is None else unreachable
    checks = reached(unreachable) if checks is None else checks
    lines = ["VERIFICATION RESULT:", f" ** 0 of {checks} failed" + (f" ({unreachable} unreachable)" if unreachable else "")]
    if covers:
        lines.append(f" ** {covers} of {covers} cover properties satisfied")
    return lines + ["VERIFICATION:- SUCCESSFUL", "Verification Time: 1.25s"]


def reached(unreachable):
    """The check total of a default result: 40, or one reached check above a pin of 40 or more unreachable checks."""
    return max(40, unreachable + 1)


def run_text(names, results, complete=None):
    """A terse `-j 2` run: each harness starts on a thread, and its result follows under that thread."""
    lines = ["Kani Rust Verifier 0.68.0 (cargo plugin)", "CBMC 6.11.0", "    Finished `dev` profile target(s) in 1.0s"]
    for index, name in enumerate(names):
        thread = index % 2
        lines.append(f"Thread {thread}: Checking harness {name}...")
        lines.append(f"Thread {thread}: ")
        lines += results.get(name, verified(name))
    count = len(names)
    lines += ["Manual Harness Summary:",
              complete if complete is not None else f"Complete - {count} successfully verified harnesses, 0 failures, {count} total.", ""]
    return "\n".join(lines)


# The literal `cargo -Zunstable-options config get --format json` output in crates/kestrike with the
# repository's .cargo/config.toml.
LSE_CONFIG = '{"target":{"cfg(target_arch = \\"aarch64\\")":{"rustdocflags":["-C","target-feature=+lse"],"rustflags":["-C","target-feature=+lse"]}}}\n'
EXEMPTIONS = ("miri", "kani", "loom", "protocol_contract")
# The crate's aarch64 guard attribute with every whitespace run removed.
GUARD = f'#[cfg(all(target_arch="aarch64",not(target_feature="lse"),not(any({",".join(EXEMPTIONS)}))))]'
# The guard item: its attribute, then one call of the builtin through its absolute path, which no `use` import or
# macro named `compile_error` can rebind, holding one cooked string literal and at most a trailing comma. The path
# assumes `::core` names the standard core crate; a root `extern crate ... as core` is outside this check.
GUARD_ITEM = re.compile(r"^(#\[cfg\([^\]]*\)\])\s*\n::core::compile_error!\(\s*(\"(?:[^\"\\]|\\.)*\")\s*,?\s*\);",
                        re.MULTILINE | re.DOTALL)
INCLUDE_TREE = re.compile(r'^::core::include!\("mod\.rs"\);[ \t]*$', re.MULTILINE)
# A string continuation, a backslash before a newline and the whitespace after it, which rustc drops from a cooked
# literal; an escaped backslash is matched first so it never starts one.
CONTINUATION = re.compile(r"\\(\\|\n[ \t\r\n]*)")
MESSAGE_NAMES = (re.compile(re.escape("-C target-feature=+lse")), re.compile(r"(?<![A-Z_])RUSTFLAGS\b"),
                 re.compile(r"\bCARGO_ENCODED_RUSTFLAGS\b"), re.compile(r"(?<![A-Z_])RUSTDOCFLAGS\b"),
                 re.compile(r"\bCARGO_ENCODED_RUSTDOCFLAGS\b"))
# A Cargo config file at any depth, legacy name included, and a `.cargo` entry itself, which Git tracks only as a
# file or a symlink.
CARGO_CONFIG = re.compile(r"(^|/)\.cargo(/config(\.toml)?)?\Z")


def first_item(masked, match):
    """Whether `match` starts the first item of `masked`, a source whose comments and literals are blanked.

    Only inner attributes whose text holds no `cfg(`, with Rust whitespace allowed before the parenthesis, may
    precede it, so no earlier item, outer attribute, macro or crate-level `cfg` can disable or wrap it. This is a
    text check; it does not expand attribute macros.
    """
    prefix = masked[:match.start()].strip()
    while prefix.startswith("#!["):
        depth = 0
        for end, char in enumerate(prefix):
            depth += {"[": 1, "]": -1}.get(char, 0)
            if char == "]" and depth == 0:
                break
        else:
            return False
        if re.search(rf"\bcfg{judge_kani.GAP}*\(", prefix[3:end]):
            return False
        prefix = prefix[end + 1:].strip()
    return prefix == ""


def outside_literals(code, match):
    """The attribute `match` captured in `code`, with whitespace removed outside its string literals."""
    begin, end = match.span(1)
    literals = [(start, stop) for _, start, stop in judge_kani.rc11.rust_lexemes(code) if start < end and stop > begin]
    return "".join(char for index, char in enumerate(code[begin:end], begin)
                   if not char.isspace() or any(start <= index < stop for start, stop in literals))


def cargo_configs(listing):
    """The tracked Cargo config entries of `listing`, the NUL-separated bytes `git ls-files -z` prints."""
    return [name for name in listing.decode("utf-8", "surrogateescape").split("\0") if CARGO_CONFIG.search(name)]


def configuration_faults(config, manifest, tree, roots, build, configs):
    """Return how the committed files depart from the LSE build the guard enforces.

    The parsed config must equal the one `target` table both judges admit, and it must be the repository's
    only tracked Cargo config entry (`configs` lists them). The module tree, read with its comments blanked,
    must open with the guard: a `::core::compile_error!` call whose only attribute, with whitespace removed,
    is `GUARD` and whose one cooked message literal, with its continuations folded, matches every pattern of
    `MESSAGE_NAMES`. The crate manifest must select the files read here: `src/lib.rs` as the library root,
    `src/worker.rs` as the root of the `sim_worker` test target and `build.rs` as the build script, when one
    runs. Each root must open with the `::core::include!` of the module tree after its inner attributes. The
    build script's code, with its comments blanked, must hold no literal `rustc-cfg=` directive for an
    exemption; this is a source lint and does not see a directive that a format string assembles.
    """
    faults = []
    if judge_kani.TOML.loads(config) != {"target": judge_kani.genmc.ADMITTED_TARGET}:
        faults.append("the config file is not the admitted target table")
    if list(configs) != [".cargo/config.toml"]:
        faults.append(f"the repository holds Cargo config files {sorted(configs)}")
    code = judge_kani.code_text(tree, "mod.rs")
    masked = judge_kani.verus.masked_literals(code)
    guards = [match for match in GUARD_ITEM.finditer(code) if outside_literals(code, match) == GUARD and first_item(masked, match)]
    if not guards:
        faults.append("the module tree does not open with the guard")
    elif not all(name.search(CONTINUATION.sub(lambda m: m[0] if m[1] == "\\" else "", guards[0].group(2)))
                 for name in MESSAGE_NAMES):
        faults.append("the guard's message omits the flag or a variable")
    package = judge_kani.TOML.loads(manifest)
    if package.get("lib", {}).get("path", "src/lib.rs") != "src/lib.rs" or package["package"].get("autolib") is False:
        faults.append("the manifest does not select src/lib.rs as the library root")
    if [target.get("path") for target in package.get("test", []) if target.get("name") == "sim_worker"] != ["src/worker.rs"]:
        faults.append("the manifest does not select src/worker.rs as the sim_worker root")
    # `build = true` enables Cargo's `build.rs` lookup and `build = false` disables it; a string names one build script.
    script = package["package"].get("build", True)
    if not isinstance(script, bool) and script != "build.rs":
        faults.append("the manifest does not select build.rs as the build script")
    for name, text in roots.items():
        code = judge_kani.code_text(text, name)
        masked = judge_kani.verus.masked_literals(code)
        if not any(first_item(masked, match) for match in INCLUDE_TREE.finditer(code)):
            faults.append(f"{name} does not open with the include of the module tree")
    if re.search(rf"rustc-cfg=({'|'.join(EXEMPTIONS)})\b", judge_kani.code_text(build, "build.rs")):
        faults.append("the build script sets an exemption cfg")
    return faults


class JudgeKani(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-kani-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.home = base / "home"
        bundle = self.home / f"kani-{EXPECTED['kani']}"
        (bundle / "bin").mkdir(parents=True)
        for name in ("kani-compiler", "kani-driver", "cbmc"):
            (bundle / "bin" / name).write_text(f"{name}\n")
        (bundle / "rust-toolchain-version").write_text("nightly-2026-08-21-x86_64-unknown-linux-gnu")
        self.toolchain = base / "rustup/toolchains/nightly-2026-08-21-x86_64-unknown-linux-gnu"
        (self.toolchain / "lib").mkdir(parents=True)
        (self.toolchain / "lib/librustc_driver.so").write_text("driver\n")
        (bundle / "toolchain").symlink_to(self.toolchain)
        self.cargo_kani = base / "cargo-kani"
        self.cargo_kani.write_text(f"#!/usr/bin/env bash\necho 'Kani Rust Verifier {EXPECTED['kani']} (cargo plugin)'\necho 'CBMC 6.11.0'\n")
        self.cargo_kani.chmod(0o755)
        self.evidence = base / "evidence"
        self.target = base / "target"

    def run_script(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False)

    def identify(self):
        result = self.run_script("identity", "--kani-home", str(self.home), "--cargo-kani", str(self.cargo_kani),
                                 "--evidence", str(self.evidence))
        self.assertEqual(result.returncode, 0, result.stderr)

    def command(self, names, extra=()):
        argv = ["cargo", "kani", "-p", EXPECTED["package"], "--exact"]
        for name in names:
            argv += ["--harness", name]
        return [*argv, "-j", "2", "--output-format", "terse", "--target-dir", str(self.target), *extra,
                "-Z", "unstable-options", "--cbmc-args", *EXPECTED["cbmc"]]

    def comparison_argv(self, names, arm):
        """The argv the comparison lane records for one arm: the run without the `cbmc` arguments or the run under them."""
        argv = ["cargo", "kani", "-p", EXPECTED["package"], "--exact"]
        for name in names:
            argv += ["--harness", name]
        argv += ["-j", "2", "--output-format", "terse", "--target-dir", str(self.target), "-Z", "unstable-options",
                 "--export-json", str(self.evidence / f"compare-{arm}.json")]
        return argv + (["--cbmc-args", *EXPECTED["cbmc"]] if arm == "with" else [])

    def record_comparison(self, without, under, names=None, argv=None, exits=None, kani=EXPECTED["kani"], cbmc="6.11.0 (cbmc-6.11.0)"):
        """Write a comparison as the lane records it: each arm's argv, exit code and export of `{harness: (status, checks)}`."""
        self.evidence.mkdir(parents=True, exist_ok=True)
        for arm, harnesses in (("without", without), ("with", under)):
            listed = list(harnesses) if names is None else names
            (self.evidence / f"compare-{arm}.argv").write_text("\n".join((argv or {}).get(arm, self.comparison_argv(listed, arm))) + "\n")
            (self.evidence / f"compare-{arm}.exit").write_text((exits or {}).get(arm, "0") + "\n")
            results = [{"harness_id": harness, "status": status, "checks": checks} for harness, (status, checks) in harnesses.items()]
            (self.evidence / f"compare-{arm}.json").write_text(json.dumps(
                {"metadata": {"kani_version": kani}, "tools": {"cbmc": cbmc}, "verification_results": {"results": results}}))

    def write_runs(self, cases="pr", results=None, exit_code=0, argv=None, listed=None, text=None, config="{}", batches=None):
        """Write the evidence of one run of `cases` as the lane writes it: each batch's command, output and exit code,
        in the one-batch form `kani.KIND` or the form `kani-N.KIND`, and the run record. `argv`, `text` and
        `exit_code` set batch 1 of a one-batch profile and every batch otherwise; `batches` maps a batch number to
        its own `argv`, `text` or `exit_code`."""
        files = {}
        for name in listed if listed is not None else EXPECTED["harnesses"]:
            files.setdefault("crates/kestrike/src/lib.rs", []).append(name)
        self.evidence.mkdir(parents=True, exist_ok=True)
        for path in self.evidence.iterdir():
            if judge_kani.BATCH_FILE.fullmatch(path.name) or path.name == judge_kani.RUN_RECORD:
                path.unlink()
        (self.evidence / "cargo-config.json").write_text(config)
        (self.evidence / "Cargo.lock").write_text('[[package]]\nname = "kestrike"\nversion = "0.1.0"\n')
        (self.evidence / "kani-list.json").write_text(json.dumps({"standard-harnesses": files}))
        planned = judge_kani.batches(EXPECTED, cases)
        for number, names in enumerate(planned, 1):
            stems = judge_kani.batch_files(len(planned))[number - 1]
            own = (batches or {}).get(number, {})
            (self.evidence / stems["argv"]).write_text("\n".join(own.get("argv", argv if argv is not None else self.command(names))) + "\n")
            (self.evidence / stems["txt"]).write_text(own.get("text", text if text is not None else run_text(names, results or {})))
            (self.evidence / stems["exit"]).write_text(f"{own.get('exit_code', exit_code)}\n")
        self.write_record(cases)

    def write_record(self, cases, invocation="a" * 32, revision="0" * 40, **changes):
        """Write the run record the lane writes for the batch files present, every batch at `revision` on a clean
        tree and the run complete, then apply `changes` to its top-level keys."""
        count = len(judge_kani.batches(EXPECTED, cases))
        lock = sha256(self.evidence / "Cargo.lock") if (self.evidence / "Cargo.lock").is_file() else None
        runs = []
        for number, stems in enumerate(judge_kani.batch_files(count), 1):
            argv = self.evidence / stems["argv"]
            if not argv.is_file():
                continue
            lines = argv.read_text(errors="replace").splitlines()
            runs.append({"index": number, "harnesses": [lines[at + 1] for at in range(len(lines) - 1) if lines[at] == "--harness"],
                         "digests": {kind: sha256(self.evidence / name) for kind, name in stems.items()},
                         "revision": revision, "clean": True, "lock": lock, "start": 10.0 * number, "end": 10.0 * number + 5})
        run = {"invocation": invocation, "profile": cases, "revision": revision, "clean": True, "lock": lock, "workers": 2, "cap": None,
               "total": 1800, "started": 1.0, "clock": 1.0, "count": count, "runs": runs, "timeout": None, "complete": len(runs) == count,
               **changes}
        (self.evidence / judge_kani.RUN_RECORD).write_text(json.dumps(run))
        return run

    def judge(self, cases="pr"):
        for output in ("report.json", "receipt.json"):
            (self.evidence / output).unlink(missing_ok=True)
        result = self.run_script("judge", "--profile", cases, "--evidence", str(self.evidence), "--revision", "0" * 40)
        try:
            report = json.loads((self.evidence / "report.json").read_text())
            receipt = json.loads((self.evidence / "receipt.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the judge wrote no readable report: {error}; {result.stderr}")
        self.assertEqual(result.returncode, report["code"], result.stderr)
        return report, receipt

    def test_the_declaration_names_each_harness_once_in_one_profile(self):
        pr, scheduled = set(EXPECTED["profiles"]["pr"]), set(EXPECTED["profiles"]["scheduled"])
        self.assertEqual(pr | scheduled, set(EXPECTED["harnesses"]))
        self.assertFalse(pr & scheduled)
        self.assertEqual(EXPECTED["kani"], "0.68.0")
        for path in EXPECTED["sources"]:
            source = (ROOT / path).read_text()
            self.assertIn("#[cfg(kani)]", source, path)
        for name, declared in EXPECTED["harnesses"].items():
            self.assertGreaterEqual(declared["covers"], 1, name)
        pinned = {name: declared["unreachable"] for name, declared in EXPECTED["harnesses"].items() if declared["unreachable"]}
        self.assertEqual(pinned, judge_kani.read_json(judge_kani.EXPECTED).get("unreachable", {}))
        path = Path(self.temp.name) / "expected.json"
        first = next(iter(judge_kani.read_json(judge_kani.EXPECTED)["singles"]))
        for case, change, reason in (
                ("a single with no cover", lambda d: d["singles"].update({first: 0}), "every harness needs at least 1"),
                ("a family with no cover", lambda d: next(iter(d["families"].values())).update(covers=0), "every harness needs at least 1"),
                ("a Boolean cover count", lambda d: d["singles"].update({first: True}), "every harness needs at least 1"),
                ("a pin on no declared harness", lambda d: d.setdefault("unreachable", {}).update({"net::absent::verification::proof": 1}), "names no declared harness"),
                ("a zero pin", lambda d: d.setdefault("unreachable", {}).update({first: 0}), "a pin is a positive count"),
                ("a Boolean pin", lambda d: d.setdefault("unreachable", {}).update({first: True}), "a pin is a positive count"),
                ("a pin table that is no map", lambda d: d.update(unreachable=[[first, 1]]), "must map harness names to counts"),
                ("a null source", lambda d: d["sources"].append(None), "sources must be a list of repository paths"),
                ("sources that are no list", lambda d: d.update(sources=d["sources"][0]), "sources must be a list of repository paths")):
            with self.subTest(case=case):
                declared = judge_kani.read_json(judge_kani.EXPECTED)
                change(declared)
                path.write_text(json.dumps(declared))
                with self.assertRaisesRegex(judge_kani.Refusal, reason):
                    judge_kani.declaration(path)
        # Each harness requires at least 1 cover and defaults to 0 unreachable checks.
        declared = judge_kani.read_json(judge_kani.EXPECTED)
        declared["singles"][first] = 1
        declared.pop("unreachable", None)
        path.write_text(json.dumps(declared))
        loaded = judge_kani.declaration(path)
        self.assertEqual(loaded["harnesses"][first]["covers"], 1)
        self.assertEqual({harness["unreachable"] for harness in loaded["harnesses"].values()}, {0})

    def test_each_family_of_chunk_length_bands_and_its_declared_gaps_tile_every_admitted_length(self):
        families = {}
        for name, declared in EXPECTED["harnesses"].items():
            if "family" in declared:
                families.setdefault(declared["family"], []).append((tuple(declared["units"]), name))
        self.assertEqual(sorted(families), sorted(EXPECTED["families"]))
        self.assertEqual(sorted(EXPECTED["gaps"]), ["handoff", "layout_total", "local_layout", "record_length", "windows"])
        for family, bands in families.items():
            pieces = [(tuple(gap), None) for gap in EXPECTED["gaps"].get(family, [])] + bands
            at = 1
            for (lo, hi), name in sorted(pieces):
                self.assertEqual(lo, at, f"{family} leaves an undeclared gap or an overlap at {at}")
                self.assertLess(lo, hi, name or "gap")
                if name is None:
                    # A gap Verus items close may hold a power of two; an open gap may not.
                    powers = [1 << k for k in range(20) if lo <= 1 << k < hi]
                    if not EXPECTED["closures"][family]:
                        self.assertEqual(powers, [], f"{family}'s gap {lo}..{hi} holds a power of two the bands prove")
                else:
                    self.assertTrue(name.endswith(f"::{family}_units_{lo}_{hi}"), name)
                at = hi
            self.assertEqual(at, 1 << 20, f"{family} stops at {at}, short of every u32 chunk length")

    def test_every_declared_gap_rests_on_verified_verus_items_named_in_each_receipt(self):
        verus = json.loads((ROOT / "verification/verus/expected.json").read_text())
        for family, items in EXPECTED["closures"].items():
            self.assertTrue(items, f"{family} declares a gap no Verus item closes")
            gapless = {f"kani:{name}" for name, spec in EXPECTED["families"].items() if not spec["gaps"]}
            self.assertLessEqual(set(items), set(verus["tests"]) | gapless, family)
        stated = judge_kani.gap_assumptions(EXPECTED)
        self.assertEqual(len(stated), len(EXPECTED["gaps"]))
        self.assertTrue(all(line.startswith("closed: ") for line in stated), stated)
        handoff = next(line for line in stated if line.startswith("closed: handoff "))
        for row in EXPECTED["trusts"]["handoff"]:
            self.assertIn(row, handoff.split("; trusts ")[1].split(", "))
        with tempfile.TemporaryDirectory() as temp:
            declared = json.loads(judge_kani.EXPECTED.read_text())
            declared["families"]["handoff"]["closed_by"] = ["proof::absent"]
            path = Path(temp) / "expected.json"
            path.write_text(json.dumps(declared))
            with self.assertRaisesRegex(judge_kani.Refusal, "handoff's gaps rest on proof::absent"):
                judge_kani.declaration(path)
            declared["families"]["handoff"]["closed_by"] = ["kani:layout_total"]
            path.write_text(json.dumps(declared))
            with self.assertRaisesRegex(judge_kani.Refusal, "nor a gapless family proves"):
                judge_kani.declaration(path)
            declared["families"]["handoff"]["closed_by"] = ["proof::handoff"]
            declared["families"]["handoff"]["trusts"] = ["Command::absent"]
            path.write_text(json.dumps(declared))
            with self.assertRaisesRegex(judge_kani.Refusal, "handoff's gaps trust Command::absent"):
                judge_kani.declaration(path)
            del declared["families"]["handoff"]["closed_by"], declared["families"]["handoff"]["trusts"]
            path.write_text(json.dumps(declared))
            self.assertIn("unproved: handoff at chunk lengths 5..6", "\n".join(judge_kani.gap_assumptions(judge_kani.declaration(path))))

    def test_each_band_file_is_the_declarations_rendering_and_its_module_includes_it(self):
        self.assertEqual(judge_kani.stale_band_sources(EXPECTED), [])
        rendered = judge_kani.band_sources(EXPECTED)
        for family, spec in EXPECTED["families"].items():
            path = judge_kani.band_file(spec["module"])
            text = rendered[path]
            self.assertIn(f"bands! {{\n    {spec['check']}:\n", text, family)
            for lo, hi in spec["bands"]:
                self.assertIn(f"    {family}_units_{lo}_{hi} => ({lo}, {hi}),\n", text)
            self.assertEqual(len(re.findall(rf"\b{family}_units_\d+_\d+ =>", text)), len(spec["bands"]), family)
            self.assertIn(f'    include!("{path.name}");\n', judge_kani.module_source(spec["module"]).read_text(), family)
        declared = judge_kani.read_json(judge_kani.EXPECTED)
        spec = next(iter(declared["families"].values()))
        spec["bands"] = spec["bands"][:-1]
        self.assertEqual(judge_kani.stale_band_sources(declared), [str(judge_kani.band_file(spec["module"]).relative_to(ROOT))])
        declared = judge_kani.read_json(judge_kani.EXPECTED)
        orphaned = declared["families"].pop("handoff")
        self.assertEqual(judge_kani.stale_band_sources(declared), [str(judge_kani.band_file(orphaned["module"]).relative_to(ROOT))])

    def test_bands_writes_the_rendered_files_and_leaves_every_other_band_file_alone(self):
        with tempfile.TemporaryDirectory() as temp, mock.patch.object(judge_kani, "ROOT", Path(temp)):
            for path in judge_kani.band_sources(EXPECTED):
                path.parent.mkdir(parents=True, exist_ok=True)
            stray = Path(temp) / "crates/kestrike/src/stray_kani_bands.rs"
            stray.write_text("local work\n")
            self.assertEqual(judge_kani.main(["bands"]), 0)
            self.assertTrue(stray.exists(), "bands removed a band file it does not render")
            self.assertEqual(stray.read_text(), "local work\n")
            self.assertEqual(judge_kani.stale_band_sources(EXPECTED), ["crates/kestrike/src/stray_kani_bands.rs"])

    def cover_counts_match(self, expected):
        """Assert each harness's module is a declared source and its cover count matches the check function read from that module."""
        for name, declared in expected["harnesses"].items():
            family = expected["families"].get(declared.get("family"))
            module, function = (family["module"], family["check"]) if family else name.rsplit("::", 1)
            source = judge_kani.module_source(module)
            self.assertIn(str(source.relative_to(ROOT)), expected["sources"], name)
            source = source.read_text()
            body = re.search(rf"\n    fn {function}\(.*?\n    }}\n", source, re.S)
            self.assertIsNotNone(body, f"{function} in {module}")
            self.assertEqual(body.group(0).count("kani::cover!("), declared["covers"], name)

    def test_each_declared_cover_count_is_the_source_count_within_its_module(self):
        self.cover_counts_match(EXPECTED)
        declared = judge_kani.read_json(judge_kani.EXPECTED)
        declared["families"]["handoff"]["module"] = "net::geometry::verification"
        # Moving the family renames its harnesses, so the pins on the old names leave with it and the compared list follows.
        declared["unreachable"] = {name: count for name, count in declared.get("unreachable", {}).items() if "::handoff_units_" not in name}
        declared["compared"] = [name.replace("storage::volume::read::verification::handoff_units_", "net::geometry::verification::handoff_units_")
                                for name in declared["compared"]]
        path = Path(self.temp.name) / "expected.json"
        path.write_text(json.dumps(declared))
        with self.assertRaisesRegex(AssertionError, "handed_off_chunks_lie_inside_the_command_buffer in net::geometry::verification"):
            self.cover_counts_match(judge_kani.declaration(path))
        declared = judge_kani.read_json(judge_kani.EXPECTED)
        declared["sources"].remove("crates/kestrike/src/storage/volume/read.rs")
        path.write_text(json.dumps(declared))
        with self.assertRaisesRegex(AssertionError, "crates/kestrike/src/storage/volume/read.rs"):
            self.cover_counts_match(judge_kani.declaration(path))

    def test_a_declaration_that_names_a_harness_twice_is_refused(self):
        declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
        family = next(iter(declared["families"].values()))
        family["bands"].append(family["bands"][0])
        path = Path(self.temp.name) / "expected.json"
        path.write_text(json.dumps(declared))
        with self.assertRaises(judge_kani.Refusal) as refused:
            judge_kani.declaration(path)
        self.assertIn("names a harness twice", str(refused.exception))

    def test_a_declaration_with_other_cbmc_arguments_is_refused(self):
        """The declaration passes CBMC the field-sensitivity size and nothing else, so no declared argument disables a check."""
        option, size = EXPECTED["cbmc"]
        self.assertEqual(option, "--max-field-sensitivity-array-size")
        path = Path(self.temp.name) / "expected.json"

        def load(cbmc):
            declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
            if cbmc is None:
                del declared["cbmc"]
            else:
                declared["cbmc"] = cbmc
            path.write_text(json.dumps(declared))
            return judge_kani.declaration(path)

        for cbmc in (None, [], [option], [option, "0"], [option, "7"], [option, "00"], [option, "064"], [option, "0128"], [option, "128x"],
                     [option, "12800"], [option, int(size)], [option, size, "--no-assertions"], ["--unwind", "1"], ["--no-assertions", size]):
            with self.subTest(cbmc=cbmc):
                with self.assertRaises(judge_kani.Refusal) as refused:
                    load(cbmc)
                self.assertIn("cbmc arguments must be", str(refused.exception))
        self.assertEqual(load([option, size])["cbmc"], [option, size])

    def test_a_declaration_with_another_field_sensitivity_size_is_refused(self):
        """The comparison with and without the argument ran at one size, and another size changes how CBMC represents other arrays, so only the compared size loads."""
        option, size = EXPECTED["cbmc"]
        path = Path(self.temp.name) / "expected.json"
        # CBMC defaults to a field-sensitivity array size of 64.
        for other in ("64", str(int(size) - 1), str(int(size) + 1), str(int(size) * 2), "10", "9999"):
            with self.subTest(size=other):
                declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
                declared["cbmc"] = [option, other]
                path.write_text(json.dumps(declared))
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.declaration(path)
                self.assertIn(f"cbmc arguments must be {option} {size}", str(refused.exception))
                self.assertIn("another size repeats that comparison", str(refused.exception))

    def test_the_cbmc_arguments_hold_only_under_the_compared_kani_release(self):
        """The argument was compared with and without under one Kani release; a declaration of another refuses it."""
        self.assertEqual(judge_kani.COMPARED, {"0.68.0": ("6.11.0", "128")})
        path = Path(self.temp.name) / "expected.json"
        for version in ("0.69.0", "0.67.0", "0.68.1", None):
            with self.subTest(kani=version):
                declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
                declared["kani"] = version
                path.write_text(json.dumps(declared))
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.declaration(path)
                self.assertIn("compared with and without under Kani 0.68.0", str(refused.exception))

    def test_every_declared_harness_is_compared_or_verifies_only_with_the_cbmc_arguments(self):
        """A harness is in exactly one of `compared` and `argument_only`; the refusal of one in neither names the two
        export runs and the comparison, so a new harness is compared before the declaration loads."""
        self.assertEqual(set(EXPECTED["compared"]) | set(EXPECTED["argument_only"]), set(EXPECTED["harnesses"]))
        self.assertEqual(set(EXPECTED["compared"]) & set(EXPECTED["argument_only"]), set())
        path = Path(self.temp.name) / "expected.json"
        first, only = EXPECTED["compared"][0], next(iter(EXPECTED["argument_only"]))

        def refused(change):
            declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
            change(declared)
            path.write_text(json.dumps(declared))
            with self.assertRaises(judge_kani.Refusal) as caught:
                judge_kani.declaration(path)
            self.assertEqual(caught.exception.code, judge_kani.TOOL_FAILURE)
            return str(caught.exception)

        neither = refused(lambda d: d["compared"].remove(first))
        self.assertIn(f"{first} is in neither compared nor argument_only", neither)
        run = f"cargo kani -p {EXPECTED['package']} --exact --harness {first} ... -Z unstable-options --export-json"
        self.assertIn(f"run `bash scripts/rust-lane.sh kani-compare {first}`", neither)
        self.assertIn(f"`{run} compare-without.json`", neither)
        self.assertIn(f"`{run} compare-with.json --cbmc-args {' '.join(EXPECTED['cbmc'])}`", neither)
        self.assertIn("`judge-kani.py compare` compare the two runs", neither)
        self.assertIn(f"{only} is in neither", refused(lambda d: d["argument_only"].pop(only)))
        self.assertIn(f"{first} is listed in both", refused(lambda d: d["argument_only"].update({first: "ran out of memory"})))
        self.assertIn("other::proof is listed in compared or argument_only and names no declared harness", refused(lambda d: d["compared"].append("other::proof")))
        self.assertIn("names no declared harness", refused(lambda d: d["argument_only"].update({"other::proof": "ran out of memory"})))
        for change in (lambda d: d["compared"].append(first), lambda d: d.pop("compared"), lambda d: d.update(compared={first: True}),
                       lambda d: d["compared"].append(5)):
            self.assertIn("compared list must hold harness names, each once", refused(change))
        for change in (lambda d: d["argument_only"].update({only: ""}), lambda d: d["argument_only"].update({only: " "}),
                       lambda d: d["argument_only"].update({only: 5}), lambda d: d.pop("argument_only"), lambda d: d.update(argument_only=[only])):
            self.assertIn("argument_only map must give each harness the figures", refused(change))

    def test_the_comparison_accepts_only_a_dropped_successful_unwinding_assertion(self):
        """`compare` holds the equality behind the `cbmc` arguments: each planted difference of another kind fails it."""
        name, other = EXPECTED["compared"][:2]

        def check(function, category, description, status, line="7"):
            return {"function": function, "category": category, "description": description, "status": status,
                    "location": {"file": "src/lib.rs", "line": line, "column": "5"}}

        base = [check("f", "assertion", "the rule holds", "Success"), check("f", "assertion", "never reached", "Unreachable", "8"),
                check("g", "unwind", "unwinding assertion loop 0", "Success", "9"), check("f", "cover", "cover condition: seen", "Satisfied", "10")]

        def compared(without, under, **changes):
            self.record_comparison(without, under, **changes)
            result = self.run_script("compare", "--evidence", str(self.evidence))
            return result.returncode, result.stdout + result.stderr

        code, text = compared({name: ("Success", base), other: ("Success", base)}, {name: ("Success", base), other: ("Success", base[:2] + base[3:])})
        self.assertEqual(code, 0, text)
        report = json.loads(text)
        self.assertEqual((report["harnesses"], report["equal"], report["differing"], report["unwinding_assertions_dropped"]), (2, 2, {}, {other: 1}))
        swapped = [{**base[0], "status": "Failure"}, *base[1:]]
        planted = [
            # A check under the arguments that the run without them does not report, or reports with another status or place.
            ([*base, check("f", "assertion", "a new check", "Success", "11")], "checks under the arguments are absent or of another status"),
            (swapped, "checks under the arguments are absent or of another status"),
            ([{**base[0], "location": {"file": "src/lib.rs", "line": "70", "column": "5"}}, *base[1:]], "checks under the arguments are absent or of another status"),
            # A check missing under the arguments that is no successful unwinding assertion.
            (base[1:], "checks other than successful unwinding assertions are missing under the arguments"),
            # The covers and the unreachable count.
            (base[:3], "the covers or their statuses differ"),
            ([*base[:3], {**base[3], "status": "Unsatisfiable"}], "the covers or their statuses differ"),
            ([base[0], {**base[1], "status": "Success"}, *base[2:]], "1 checks are unreachable without the arguments and 0 under them"),
        ]
        for under, reason in planted:
            with self.subTest(reason=reason, under=[c["description"] + ":" + c["status"] for c in under]):
                code, text = compared({name: ("Success", base)}, {name: ("Success", under)})
                self.assertEqual(code, 1, text)
                self.assertIn(reason, "".join(json.loads(text)["differing"][name]))
        # An unwinding assertion that failed or was unreachable without the arguments is no dropped success.
        for status in ("Failure", "Unreachable"):
            with self.subTest(unwind=status):
                without = [*base[:2], {**base[2], "status": status}, base[3]]
                code, text = compared({name: ("Success", without)}, {name: ("Success", base[:2] + base[3:])})
                self.assertEqual(code, 1, text)
                self.assertIn("checks other than successful unwinding assertions are missing", "".join(json.loads(text)["differing"][name]))
        code, text = compared({name: ("Failure", base)}, {name: ("Success", base)})
        self.assertEqual(code, 1, text)
        self.assertIn("the runs end Failure without the arguments and Success under them", text)
        one = {name: ("Success", base)}
        for without, under, changes, reason in (
                (one, {other: ("Success", base)}, {"names": [name]}, "the exports hold other harnesses than the 1 the recorded runs name"),
                (one, {name: ("Success", base), other: ("Success", base)}, {"names": [name]}, "the exports hold other harnesses than the 1"),
                (one, one, {"cbmc": "6.12.0 (cbmc-6.12.0)"}, "the declaration compares under Kani"),
                (one, one, {"kani": "0.69.0"}, "the declaration compares under Kani"),
                ({"other::proof": ("Success", base)}, {"other::proof": ("Success", base)}, {}, "where a comparison holds declared harnesses"),
                ({}, {}, {"names": [name]}, "where a comparison holds declared harnesses")):
            with self.subTest(reason=reason):
                code, text = compared(without, under, **changes)
                self.assertEqual(code, 2, text)
                self.assertIn(reason, text)
        self.record_comparison(one, one)
        (self.evidence / "compare-with.json").write_text('{"metadata": {}}')
        result = self.run_script("compare", "--evidence", str(self.evidence))
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("is no `cargo kani --export-json` file", result.stderr)

    def test_the_comparison_reads_the_two_runs_the_lane_recorded(self):
        """The export names no command, so `compare` takes each arm from its recorded argv: the same harnesses, the run
        without the `cbmc` arguments ending at its export and the run under them ending with the declared arguments."""
        name, other = EXPECTED["compared"][:2]
        checks = [{"function": "f", "category": "assertion", "description": "the rule holds", "status": "Success",
                   "location": {"file": "src/lib.rs", "line": "7", "column": "5"}}]
        runs = {name: ("Success", checks)}
        self.record_comparison(runs, runs)
        result = self.run_script("compare", "--evidence", str(self.evidence))
        self.assertEqual(result.returncode, 0, result.stderr)
        tail = ["--cbmc-args", *EXPECTED["cbmc"]]
        without, under = self.comparison_argv([name], "without"), self.comparison_argv([name], "with")
        # The lane records the export under EVIDENCE as it was given, so another spelling of the same path is the same record.
        spelled = {arm: [str(self.evidence) + "/./compare-" + arm + ".json" if a == str(self.evidence / f"compare-{arm}.json") else a for a in argv]
                   for arm, argv in (("without", without), ("with", under))}
        self.record_comparison(runs, runs, argv=spelled)
        result = self.run_script("compare", "--evidence", str(self.evidence) + "//")
        self.assertEqual(result.returncode, 0, result.stderr)
        planted = [
            # Both runs without the arguments, both under them, and the two swapped.
            ({"with": under[:-len(tail)]}, "compare-with.argv is"),
            ({"without": [*without, *tail]}, "compare-without.argv is"),
            ({"without": under, "with": without}, "compare-without.argv is"),
            # One export given to both runs.
            ({"with": [*under[:-len(tail) - 1], str(self.evidence / "compare-without.json"), *tail]}, "compare-with.argv is"),
            # Other arguments, another size, another harness set, no harness.
            ({"with": [*under[:-1], str(int(EXPECTED["cbmc"][1]) * 2)]}, "compare-with.argv is"),
            ({"with": [*under, "--no-assertions"]}, "compare-with.argv is"),
            ({"with": ["--no-assertions" if a == "--export-json" else a for a in under]}, "compare-with.argv is"),
            ({"without": ["--verbose" if a == "unstable-options" else a for a in without]}, "compare-without.argv is"),
            ({"with": [a for a in under if a != "--exact"]}, "compare-with.argv is"),
            ({"with": self.comparison_argv([other], "with")}, "the two recorded runs name different harnesses"),
            ({"without": self.comparison_argv([], "without"), "with": self.comparison_argv([], "with")}, "compare-without.argv is"),
        ]
        for argv, reason in planted:
            with self.subTest(reason=reason, arms=sorted(argv)):
                self.record_comparison(runs, runs, argv=argv)
                result = self.run_script("compare", "--evidence", str(self.evidence))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(reason, result.stderr)
        for arm, code in (("without", "137"), ("with", "1"), ("with", "")):
            with self.subTest(arm=arm, code=code):
                self.record_comparison(runs, runs, exits={arm: code})
                result = self.run_script("compare", "--evidence", str(self.evidence))
                self.assertEqual(result.returncode, 2, result.stdout)
                self.assertIn(f"the run {arm} the cbmc arguments " + (f"exited {code}" if code else "records no exit code"), result.stderr)
        self.record_comparison(runs, runs)
        (self.evidence / "compare-with.argv").unlink()
        result = self.run_script("compare", "--evidence", str(self.evidence))
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_the_comparison_runs_for_a_harness_that_no_list_names_yet(self):
        """A new harness is compared before it is listed, so `compare` loads the declaration without the list check
        that refuses it everywhere else."""
        name = EXPECTED["compared"][0]
        declared = json.loads((ROOT / "verification/kani/expected.json").read_text())
        declared["compared"].remove(name)
        path = Path(self.temp.name) / "expected.json"
        path.write_text(json.dumps(declared))
        with self.assertRaises(judge_kani.Refusal) as refused:
            judge_kani.declaration(path)
        self.assertIn(f"{name} is in neither compared nor argument_only", str(refused.exception))
        checks = [{"function": "f", "category": "assertion", "description": "the rule holds", "status": "Success",
                   "location": {"file": "src/lib.rs", "line": "7", "column": "5"}}]
        self.record_comparison({name: ("Success", checks)}, {name: ("Success", checks)})
        loader, output = judge_kani.declaration, io.StringIO()
        with mock.patch.object(judge_kani, "declaration", lambda *args, **kwargs: loader(path, **kwargs)), contextlib.redirect_stdout(output):
            code = judge_kani.compare(argparse.Namespace(evidence=str(self.evidence)))
        self.assertEqual(code, 0, output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["equal"], 1)

    def test_the_admission_proofs_cover_every_place_of_two_and_three_entries_once(self):
        """An admission into N entries has one proof per place of the record's shard, 2N + 1 places; a repeated index would leave a place unproved."""
        source = judge_kani.module_source("failover::standbys::population_kani::verification").read_text()
        called = sorted(re.findall(r"\n    fn an_admission_into_\w+\(\) \{\n        let seen = Admission::any\(\)\.at_place::<(\d)>\((\d)\);", source))
        self.assertEqual(called, [("2", str(at)) for at in range(5)] + [("3", str(at)) for at in range(7)])
        self.assertEqual(source.count(".at_place::<"), len(called), "an at_place call outside a declared admission proof")

    def test_a_manifest_that_configures_kani_is_refused(self):
        judge = judge_kani
        judge.check_manifests()
        manifest = Path(self.temp.name) / "Cargo.toml"
        for text in ('[package.metadata.kani]\nflags = { default-unwind = "1" }\n',
                     '[workspace.metadata.kani.flags]\nno-unwinding-checks = true\n',
                     '[package]\nmetadata.kani.flags.no-overflow-checks = true\n',
                     '["\\u006bani".flags]\nno-unwinding-checks = true\n',
                     '[package.metadata."\\u006bani".flags]\nno-unwinding-checks = true\n',
                     '[package]\nmetadata = { note = "#", kani = { flags = { default-unwind = "1" } } }\n',
                     "[target]\n'cfg(kani)'.dependencies.k = { package = 'kani', version = '0.0.1' }\n",
                     '[dependencies]\nk = { package = "k\\u0061ni", version = "0.0.1" }\n',
                     '[build-dependencies]\nk = { package = "k\\u0061ni_macros", version = "1" }\n',
                     '[workspace.dependencies]\nk = { package = "k\\u0061ni_core", version = "1" }\n',
                     '[dev-dependencies]\n"k\\u0061ni" = { package = "other", version = "1" }\n',
                     '[target.x86_64-unknown-linux-gnu.dependencies]\n"k\\u0061ni" = "1"\n',
                     "[target]\n'cfg(kani)'.dependencies.k = { package = 'Kani', version = '0.0.1' }\n",
                     '[patch.crates-io]\nk = { package = "k\\u0061ni", path = "../k" }\n'):
            with self.subTest(text=text):
                manifest.write_text('[lints.rust]\nunexpected_cfgs = { check-cfg = ["cfg(kani)"] }\n' + text)
                with self.assertRaises(judge.Refusal) as refused:
                    judge.check_manifests((manifest,))
                self.assertIn("configures Kani", str(refused.exception))
        # check_manifests accepts libc under cfg(kani) and skips dependency fields that are not tables.
        for text in ("[target.'cfg(kani)'.dependencies]\nlibc = \"0.2\"\n", 'dependencies = "x"\ntarget = 1\n[workspace]\ndependencies = [1]\n'):
            with self.subTest(text=text):
                manifest.write_text('[lints.rust]\nunexpected_cfgs = { check-cfg = ["cfg(kani)"] }\n' + text)
                judge.check_manifests((manifest,))
        self.assertEqual({path.parent for path in judge.MANIFESTS}, {ROOT, *judge.COMPILED})

    def test_manifests_without_a_toml_parser_or_unparsable_are_refused(self):
        judge = judge_kani
        manifest = Path(self.temp.name) / "Cargo.toml"
        manifest.write_text('[lints.rust]\nunexpected_cfgs = { check-cfg = ["cfg(kani)"] }\n')
        judge.check_manifests((manifest,))
        parser, judge.TOML = judge.TOML, None
        try:
            with self.assertRaises(judge.Refusal) as refused:
                judge.check_manifests((manifest,))
        finally:
            judge.TOML = parser
        self.assertIn("no TOML parser", str(refused.exception))
        manifest.write_text("[package\n")
        with self.assertRaises(judge.Refusal) as refused:
            judge.check_manifests((manifest,))
        self.assertIn("does not parse", str(refused.exception))

    def test_kani_names_outside_the_admitted_set_or_the_declared_sources_are_refused(self):
        judge_kani.check_surface(EXPECTED)
        root = Path(self.temp.name) / "tree"
        declared_source = root / EXPECTED["sources"][0]
        undeclared = root / "crates/kestrike/src/undeclared.rs"
        # Each expected refusal shows that the scan reads past a manifest and a Kani-free source listed first.
        manifest, plain = root / "crates/kestrike/Cargo.toml", root / "crates/kestrike/src/plain.rs"
        cases = (
            (declared_source, "#[kani::proof]\n#[kani::stub(a, b)]\nfn harness() {}\n", ":2 uses kani::stub"),
            (undeclared, "fn harness() { kani::assume(true); }\n", "undeclared.rs:1 uses kani:: outside the declared sources"),
            (declared_source, "use kani::{any, cover};\n", "kani::{"),
            (declared_source, "use kani::*;\n", "kani::*"),
            (declared_source, "fn harness() { let x: u8 = kani::any_where(|_| true); }\n", "kani::any_where"),
            (declared_source, "use kani as k;\nfn harness() { let x: u8 = k::any(); }\n", "spells `kani as NAME`"),
            (declared_source, "fn harness() { kani /* gap */ ::\n    stub(); }\n", "uses kani::stub"),
            (declared_source, "use kani\n    as k;\n", "spells `kani as NAME`"),
            (undeclared, "fn widen(kani: u8) -> u16 { kani as u16 }\n", ":1 spells `kani as NAME`"),
            (declared_source, "fn harness() { kani\u200e::stub(); }\n", "uses kani::stub"),
            (undeclared, "fn harness() { kani\u200f::assume(true); }\n", "outside the declared sources"),
            (declared_source, "use kani\u200eas\u200ek;\n", "spells `kani as NAME`"),
            (declared_source, "#[macro_use]\n// the prelude\nextern crate kani;\n#[solver(cadical)]\nfn harness() {}\n", ":3 declares extern crate kani,"),
            (undeclared, "#[macro_use]\nextern crate r#kani;\n", ":2 declares extern crate r#kani,"),
            (undeclared, "extern crate kani_macros;\n", ":1 declares extern crate kani_macros,"),
            (undeclared, "extern\ncrate\u200ekani;\n", ":1 declares extern crate kani,"),
            (declared_source, "#[kanitool::should_panic]\nfn harness() {}\n", ":1 spells kanitool"),
            (undeclared, "#[cfg_attr(test, kanitool::solver(cadical))]\nfn harness() {}\n", ":1 spells kanitool"),
            (declared_source, "#[r#kanitool::should_panic]\nfn harness() {}\n", ":1 spells kanitool"),
            # rustc drops a first line that starts with `#!` and no `[`, so line 2 is code there.
            (declared_source, b"#!/*\nfn harness() { kani::stub(); }\n// */\n", ":1 starts with a `#!` line"),
            (declared_source, "\ufeff#!/*\nfn harness() { kani::stub(); }\n// */\n", ":1 starts with a `#!` line"),
            # rustc reads U+00A0 and U+001C after `#!` as tokens, so it drops these first lines as shebangs and line 2 is code.
            (declared_source, "#!\u00a0[/*\nfn harness() { kani::stub(); }\n// */\n", ":1 starts with a `#!` line"),
            (undeclared, "#!\x1c[/*\nfn harness() { kani::assume(false); }\n// */\n", ":1 starts with a `#!` line"),
            # rustc parses `#! [` with an ASCII space as an inner attribute; check_surface requires `#![`.
            (declared_source, "#! [allow(dead_code)]\n#[kani::proof]\nfn harness() { kani::cover!(true); }\n", ":1 starts with a `#!` line"),
            (undeclared, b"// kani\n\xff\n", "is not UTF-8"),
            # rustc ends a line comment at LF, so the `/*` after a lone CR is comment text and line 2 is code.
            (declared_source, b"// note\r/* \nfn harness() { kani::stub(); }\n// */\n", ":2 uses kani::stub"),
            (undeclared, "/* kani::proof\nfn harness() {}\n", "never closes"),
            # check_surface refuses a restricted Kani name inside a string literal too.
            (declared_source, 'const S: &str = "kani::any_where";\n', "kani::any_where"),
            # rustc reads the `r` or `br` after a literal as that literal's suffix, so the quote after it opens a cooked string
            # and the harness call on the next line is code. The comment lexer opens a raw string at that `r`, and the scan
            # refuses the file at the line of that `r`.
            (declared_source, '#[kani::proof]\nconst S: &str = stringify!("x"r"\\"/*");\nfn harness() { kani::stub(); }\n// */\n',
             ":2 opens a raw string directly after"),
            (undeclared, "const S: &str = stringify!('x'br\"\\\"/*\");\nfn harness() { kani::assume(false); }\n// */\n",
             ":1 opens a raw string directly after"),
            # rustc reads the last `r` of `r#r` or `'r#r` as the name of a raw identifier or lifetime, and so does the comment
            # lexer: the quote after it opens a cooked string that holds the `/*`, and the scan refuses the call on line 2.
            (declared_source, 'const S: &str = stringify!(r#r"\\"/*");\nfn harness() { kani::stub(); }\n// */\n', ":2 uses kani::stub"),
            (declared_source, "const S: &str = stringify!('r#r\"\\\"/*\");\nfn harness() { kani::stub(); }\n// */\n", ":2 uses kani::stub"),
            # In the 2015 and 2018 editions rustc reads `a\u00b7r` as one identifier, because U+00B7 continues an identifier.
            (declared_source, 'const S: &str = stringify!(a\u00b7r"\\"/*");\nfn harness() { kani::stub(); }\n// */\n', ":1 opens a raw string directly after"),
            # A raw string that opens at a token boundary passes, and `r` or `#r` inside a cooked string is text.
            (declared_source, 'const M: [&str; 4] = ["r", "#r", r"\\d", r#"a"b"#];\nconst B: &[u8] = (br"x");\n'
                              "#[kani::proof]\nfn harness() { kani::cover!(true); }\n", None),
            (declared_source, "// #[kani::stub(a, b)]\n/* use kani::*; */\n#[kani::proof]\nfn harness() { kani::cover!(true); }\n", None),
            (undeclared, "// kani::assume(false);\n/// `use kani as k;`\n// extern crate kani;\n// #[kanitool::proof]\nfn harness() {}\n", None),
            (declared_source, b"// note\r kani::stub();\nfn harness() {}\n", None),
            (declared_source, "#![allow(dead_code)]\n#[kani::proof]\nfn harness() { kani::cover!(true); }\n", None),
            # The text rule permits a local module named `kani`, even outside the declared sources.
            (undeclared, "mod kani {\n    pub fn assert(_: bool, _: &'static str) {}\n}\n", None),
        )
        for path, text, reason in cases:
            with self.subTest(text=text):
                shutil.rmtree(root, ignore_errors=True)
                path.parent.mkdir(parents=True, exist_ok=True)
                manifest.write_text("[package]\nname = \"kani\"\n")
                plain.write_text("fn plain() {}\n")
                path.write_bytes(text if isinstance(text, bytes) else text.encode())
                listing = [manifest, plain, path]
                with mock.patch.object(judge_kani, "ROOT", root), mock.patch.object(judge_kani, "compiled_sources", lambda listing=listing: listing):
                    if reason is None:
                        judge_kani.check_surface(EXPECTED)
                    else:
                        with self.assertRaises(judge_kani.Refusal) as refused:
                            judge_kani.check_surface(EXPECTED)
                        self.assertIn(reason, str(refused.exception))
                        self.assertEqual(refused.exception.code, judge_kani.TOOL_FAILURE)

    def test_the_judgment_refuses_a_kani_use_the_source_rule_refuses(self):
        self.identify()
        self.write_runs()
        report, derived = judge_kani.derive(self.evidence, "0" * 40, "pr")
        self.assertEqual(report["code"], 0, report)
        dropped = {**EXPECTED, "sources": EXPECTED["sources"][1:]}
        with mock.patch.object(judge_kani, "declaration", lambda path=None: dropped):
            report, derived = judge_kani.derive(self.evidence, "0" * 40, "pr")
        self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
        self.assertIn(f"{EXPECTED['sources'][0]}:", report["reason"])
        self.assertIn("uses kani:: outside the declared sources", report["reason"])
        self.assertEqual((derived["executed"], derived["selection"]["credited"]), ([], False))

    def test_an_unreadable_listing_or_source_refuses_with_a_report_and_an_uncredited_receipt(self):
        listing = mock.Mock(stdout=b"crates/kestrike/src/\xff.rs\0")
        with mock.patch.object(judge_kani.subprocess, "run", return_value=listing), self.assertRaises(judge_kani.Refusal) as refused:
            judge_kani.compiled_sources()
        self.assertEqual(refused.exception.code, judge_kani.TOOL_FAILURE)
        self.assertIn("not UTF-8", str(refused.exception))
        self.identify()
        self.write_runs()

        def unlisted():
            raise judge_kani.Refusal(judge_kani.TOOL_FAILURE, "git ls-files lists a compiled path that is not UTF-8")

        absent = [*judge_kani.MANIFESTS, ROOT / "crates/kestrike/src/absent_source.rs"]
        for sources, reason in ((unlisted, "not UTF-8"), (lambda: absent, "cannot read an input")):
            with self.subTest(reason=reason), mock.patch.object(judge_kani, "compiled_sources", sources):
                report, derived = judge_kani.derive(self.evidence, "0" * 40, "pr")
                self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
                self.assertIn(reason, report["reason"])
                self.assertEqual((derived["executed"], derived["selection"]["credited"]), ([], False))
                self.assertIn("verification/kani/expected.json", derived["inputs"])

    def test_a_refused_declaration_exits_2_without_a_report(self):
        fresh = Path(self.temp.name) / "fresh"
        fresh.mkdir()

        def refused(path=None):
            raise judge_kani.Refusal(judge_kani.TOOL_FAILURE, "the declaration names a harness twice")

        with mock.patch.object(judge_kani, "declaration", refused):
            code = judge_kani.main(["judge", "--profile", "pr", "--evidence", str(fresh), "--revision", "0" * 40])
        self.assertEqual(code, judge_kani.TOOL_FAILURE)
        self.assertEqual(sorted(path.name for path in fresh.iterdir()), [])

    def test_complete_runs_credit_the_profile(self):
        self.identify()
        self.write_runs()
        report, receipt = self.judge()
        self.assertEqual(report["code"], 0, report)
        self.assertEqual((receipt["module"], receipt["executed"], receipt["completion"]), ("pr", profile("pr"), "completed"))
        self.assertEqual(receipt["executions"], sum(reached(EXPECTED["harnesses"][name]["unreachable"]) for name in profile("pr")))
        self.assertTrue(set(EXPECTED["sources"]) <= set(receipt["inputs"]))
        for name in ("verification/verus/expected.json", "verification/verus/inventory.json"):
            self.assertEqual(receipt["inputs"].get(name), sha256(ROOT / name), f"{name}, which the gap closures were checked against, is unbound")
        # The harness build compiles the whole package and its path dependency, so the receipt binds every file of both.
        for name in ("crates/kestrike/src/storage/layout.rs", "crates/kestrike/build.rs", "crates/spdk-sys/src/lib.rs",
                     "crates/spdk-sys/Cargo.toml"):
            self.assertIn(name, receipt["inputs"])
        tracked = set(subprocess.run(["git", "-C", str(ROOT), "ls-files"], capture_output=True, text=True, check=True).stdout.split())
        self.assertEqual({name for name in receipt["inputs"] if "/" in name or name == "Cargo.toml"} - tracked, set())
        self.assertIn("cargo-config.json", receipt["inputs"])
        self.assertEqual(receipt["inputs"].get("Cargo.lock"), sha256(self.evidence / "Cargo.lock"), "the resolved lock file the proof built with is unbound")

    def test_evidence_without_the_pins_or_lock_file_a_receipt_binds_is_refused(self):
        self.identify()
        self.write_runs()
        pins = (self.evidence / "pins.txt").read_bytes()
        for name in ("pins.txt", "Cargo.lock"):
            with self.subTest(name=name):
                original = (self.evidence / name).read_bytes()
                (self.evidence / name).unlink()
                report, receipt = self.judge()
                self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
                self.assertIn(f"no regular file {name}", report["reason"])
                self.assertEqual((receipt["executed"], receipt["selection"]["credited"]), ([], False))
                (self.evidence / name).mkdir()
                report, _ = self.judge()
                self.assertIn(f"no regular file {name}", report["reason"])
                (self.evidence / name).rmdir()
                (self.evidence / name).write_bytes(original)
        (self.evidence / "pins.txt").write_bytes(pins + b"\xff\n")
        report, receipt = self.judge()
        self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
        self.assertIn("pins.txt is not UTF-8", report["reason"])
        self.assertFalse(receipt["selection"]["credited"])
        (self.evidence / "pins.txt").write_bytes(pins)
        report, _ = self.judge()
        self.assertEqual(report["code"], 0, report)

    def test_cargo_configuration_that_shapes_the_build_is_refused(self):
        self.identify()
        for config, entry in (({"profile": {"dev": {"debug-assertions": False}}}, "profile"),
                              ({"build": {"rustc-wrapper": "sccache"}}, "build.rustc-wrapper"),
                              ({"env": {"RUSTFLAGS": "--cfg x"}}, "env.RUSTFLAGS")):
            with self.subTest(entry=entry):
                self.write_runs(config=json.dumps(config))
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(f"the cargo configuration sets {entry}", report["reason"])
                self.assertEqual(receipt["executed"], [])
        for config, entry in (({"alias": {"kani": "run --bin fake"}}, "alias.kani"),
                              ({"env": {"KANI_HOME": {"value": "/other", "force": True}}}, "env.KANI_HOME"),
                              ({"env": {"KANI_TARGET": "/other"}}, "env.KANI_TARGET")):
            with self.subTest(entry=entry):
                self.write_runs(config=json.dumps(config))
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(entry, report["reason"] or "")
                self.assertEqual(receipt["executed"], [])
        self.write_runs(config=json.dumps({"env": {"TMPDIR": "/scratch"}, "alias": {"b": "build"}}))
        report, _ = self.judge()
        self.assertEqual(report["code"], 0, report)
        (self.evidence / "cargo-config.json").unlink()
        report, _ = self.judge()
        self.assertIn("no recorded cargo configuration", report["reason"])

    def test_only_the_repository_lse_target_table_is_admitted(self):
        self.identify()
        self.write_runs(config=LSE_CONFIG)
        report, _ = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)
        for name, config, refused in genmc_fixture.lse_target_variants(LSE_CONFIG):
            with self.subTest(variant=name):
                self.write_runs(config=json.dumps(config))
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertTrue(report["reason"].endswith(f"the cargo configuration sets {refused}"), report)
                self.assertEqual(receipt["executed"], [])

    def test_the_committed_configuration_is_admitted_and_guarded(self):
        # No enabled job builds for aarch64, so this check watches the config file and the guard together.
        source = judge_kani.verus.source_text
        config = (ROOT / ".cargo/config.toml").read_text(encoding="utf-8")
        manifest = (ROOT / "crates/kestrike/Cargo.toml").read_text(encoding="utf-8")
        tree = source(ROOT / "crates/kestrike/src/mod.rs")
        roots = {name: source(ROOT / "crates/kestrike/src" / name) for name in ("lib.rs", "worker.rs")}
        build = source(ROOT / "crates/kestrike/build.rs")
        listing = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-z"], capture_output=True, check=True).stdout
        configs = cargo_configs(listing)
        self.assertEqual(configuration_faults(config, manifest, tree, roots, build, configs), [])
        guard = GUARD_ITEM.search(tree)
        assert guard is not None
        item = tree[guard.start():guard.end()]
        base = {"config": config, "manifest": manifest, "tree": tree, "roots": roots, "build": build, "configs": configs}
        guards, message = "the module tree does not open with the guard", "the guard's message omits the flag or a variable"
        include = '::core::include!("mod.rs");'

        def root(name, new, old=include):
            return {"roots": {**roots, name: roots[name].replace(old, new, 1)}}

        def unopened(name):
            return f"{name} does not open with the include"

        def read_back(text):
            # A planted tree goes through the reader of the committed files, which keeps a lone CR as rustc does.
            path = Path(self.temp.name) / "mod.rs"
            path.write_bytes(text.encode("utf-8"))
            return {"tree": source(path)}

        def message_without(old, new=""):
            return {"tree": tree.replace(old, new, 1)}, message

        faults = {
            "a changed flag": ({"config": config.replace('"target-feature=+lse"', '"target-feature=+rcpc"', 1)},
                               "the config file is not the admitted target table"),
            "an added flag": ({"config": config.replace('"target-feature=+lse"]', '"target-feature=+lse", "-C", "opt-level=3"]', 1)},
                              "the config file is not the admitted target table"),
            "a redirected library root": ({"manifest": manifest.replace("[[test]]", '[lib]\npath = "src/other.rs"\n\n[[test]]', 1)},
                                          "the manifest does not select src/lib.rs as the library root"),
            "a disabled library autodiscovery": ({"manifest": manifest.replace("publish = false", "publish = false\nautolib = false", 1)},
                                                 "the manifest does not select src/lib.rs as the library root"),
            "a redirected worker root": ({"manifest": manifest.replace('path = "src/worker.rs"', 'path = "tests/sim_worker.rs"', 1)},
                                         "the manifest does not select src/worker.rs as the sim_worker root"),
            # Without a path, Cargo reads the target named `sim_worker` from tests/sim_worker.rs.
            "a worker target without its path": ({"manifest": manifest.replace('path = "src/worker.rs"\n', "", 1)},
                                                 "the manifest does not select src/worker.rs as the sim_worker root"),
            "a renamed worker target": ({"manifest": manifest.replace('name = "sim_worker"', 'name = "other_worker"', 1)},
                                        "the manifest does not select src/worker.rs as the sim_worker root"),
            "a redirected build script": ({"manifest": manifest.replace("publish = false", 'publish = false\nbuild = "other.rs"', 1)},
                                          "the manifest does not select build.rs as the build script"),
            "a list of build scripts": ({"manifest": manifest.replace("publish = false", 'publish = false\nbuild = ["build.rs", "other.rs"]', 1)},
                                        "the manifest does not select build.rs as the build script"),
            "a removed guard": ({"tree": tree.replace(item, "")}, guards),
            "a guard inside a comment": ({"tree": tree.replace(item, "/*\n" + item + "\n*/")}, guards),
            "a guard joined to a line comment by lone CRs": (read_back(tree.replace("\n" + item, "\r" + item.replace("\n", "\r"), 1)),
                                                             guards),
            "a guard inside a module": ({"tree": tree.replace(item, "mod guarded {\n" + item + "\n}")}, guards),
            "a stacked cfg attribute": ({"tree": tree.replace(item, "#[cfg(test)]\n" + item)}, guards),
            "a fifth exemption": ({"tree": tree.replace("protocol_contract))", "protocol_contract, test))", 1)}, guards),
            "an added conjunct": ({"tree": tree.replace('not(target_feature = "lse"),', 'not(target_feature = "lse"),\n    target_os = "linux",', 1)},
                                  guards),
            "a bare compile_error call": ({"tree": tree.replace("::core::compile_error!(", "compile_error!(", 1)}, guards),
            "a call holding more than the message": ({"tree": tree.replace('ancestors."\n);', 'ancestors.".to_owned()\n);', 1)}, guards),
            "a second message argument": ({"tree": tree.replace('ancestors."\n);', 'ancestors.", "more"\n);', 1)}, guards),
            "a message without the flag": message_without("pass `-C target-feature=+lse`", "pass the feature"),
            "a message without RUSTFLAGS": message_without("RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS"),
            "a message without CARGO_ENCODED_RUSTFLAGS": message_without("RUSTFLAGS and CARGO_ENCODED_RUSTFLAGS,", "RUSTFLAGS,"),
            "a message without RUSTDOCFLAGS": message_without("RUSTDOCFLAGS and CARGO_ENCODED_RUSTDOCFLAGS", "CARGO_ENCODED_RUSTDOCFLAGS"),
            "a message without CARGO_ENCODED_RUSTDOCFLAGS": message_without("RUSTDOCFLAGS and CARGO_ENCODED_RUSTDOCFLAGS for", "RUSTDOCFLAGS for"),
            "a message whose flag holds an escaped backslash before a newline": message_without(
                "pass `-C target-feature=+lse`", "pass `-C target-\\\\\n     feature=+lse`"),
            "a spaced architecture name": ({"tree": tree.replace('target_arch = "aarch64"', 'target_arch = "aarch 64"', 1)}, guards),
            "a spaced feature name": ({"tree": tree.replace('target_feature = "lse"', 'target_feature = "l se"', 1)}, guards),
            "a root without the include": (root("worker.rs", ""), unopened("worker.rs")),
            "a bare include": (root("lib.rs", 'include!("mod.rs");'), unopened("lib.rs")),
            "a commented include": (root("lib.rs", "// " + include), unopened("lib.rs")),
            "a root including the tree inside a module": (root("lib.rs", "mod nested {\n" + include + "\n}"), unopened("lib.rs")),
            "an include under a cfg": (root("worker.rs", "#[cfg(any())]\n" + include), unopened("worker.rs")),
            "a macro definition before the guard": ({"tree": tree.replace(item, "macro_rules! compile_error { ($($t:tt)*) => {}; }\n" + item)},
                                                    guards),
            "a guard inside a discarding macro": ({"tree": tree.replace(item, "discard!(\n;\n" + item + "\n);")}, guards),
            "an include inside a discarding macro": (root("lib.rs", "discard!(\n;\n" + include + "\n);"), unopened("lib.rs")),
            "a crate-level cfg on a root": (root("lib.rs", '#![cfg(not(target_arch = "aarch64"))]\n#![cfg_attr(', "#![cfg_attr("),
                                            unopened("lib.rs")),
            "a cfg_attr applying a crate-level cfg": (root("lib.rs", '#![cfg_attr(target_arch = "aarch64", cfg(any()))]\n#![cfg_attr(', "#![cfg_attr("),
                                                      unopened("lib.rs")),
            "a nested Cargo config file": ({"configs": cargo_configs(listing + b"crates/kestrike/.cargo/config.toml\0")},
                                           "the repository holds Cargo config files"),
            "a nested legacy Cargo config file": ({"configs": cargo_configs(listing + b"crates/kestrike/.cargo/config\0")},
                                                  "the repository holds Cargo config files"),
        }
        for mark in ("\u200e", "\u200f"):
            faults[f"a cfg_attr applying a cfg spaced by U+{ord(mark):04X}"] = (
                root("worker.rs", f'#![cfg_attr(target_arch = "aarch64", cfg{mark}(any()))]\n#![allow(', "#![allow("), unopened("worker.rs"))
        for exemption in EXEMPTIONS:
            faults[f"a build script setting {exemption}"] = (
                {"build": build + f'\nfn more() {{ println!("cargo::rustc-cfg={exemption}"); }}\n'}, "the build script sets an exemption cfg")
        for name, (change, fault) in faults.items():
            with self.subTest(fault=name):
                self.assertNotEqual({**base, **change}, base, "the planted fault left the text unchanged")
                found = configuration_faults(**{**base, **change})
                self.assertTrue(any(entry.startswith(fault) for entry in found), found)
        for name, change in {
                # A literal holding brackets in an inner attribute is no attribute boundary.
                "a bracket inside a doc literal": root("lib.rs", '#![doc = "{ ]"]\n' + include),
                "a forbid lint before the include": root("lib.rs", "#![forbid(unsafe_op_in_unsafe_fn)]\n" + include),
                "a recursion limit before the include": root("worker.rs", '#![recursion_limit = "256"]\n' + include),
                "a recursion limit under cfg_attr before the include": root("worker.rs", '#![cfg_attr(all(), recursion_limit = "256")]\n' + include),
                "a line comment after the include": root("worker.rs", include + " // the module tree"),
                "an explicit library root of src/lib.rs": {"manifest": manifest.replace("[[test]]", '[lib]\npath = "src/lib.rs"\n\n[[test]]', 1)},
                "an explicit build script of build.rs": {"manifest": manifest.replace("publish = false", 'publish = false\nbuild = "build.rs"', 1)},
                # `build = true` selects the package's build.rs; `build = false` disables the build script.
                "a build script selected by true": {"manifest": manifest.replace("publish = false", "publish = false\nbuild = true", 1)},
                "a disabled build script": {"manifest": manifest.replace("publish = false", "publish = false\nbuild = false", 1)},
                "a trailing comma after the message": {"tree": tree.replace('ancestors."\n);', 'ancestors.",\n);', 1)},
                "a continuation inside the flag": {"tree": tree.replace("pass `-C target-feature=+lse`", "pass `-C target-\\\n     feature=+lse`", 1)},
                "a build script comment naming an exemption": {"build": build + "\n// cargo::rustc-cfg=loom is never printed.\n"},
        }.items():
            with self.subTest(admitted=name):
                self.assertNotEqual({**base, **change}, base, "the planted change left the text unchanged")
                self.assertEqual(configuration_faults(**{**base, **change}), [])

    def test_the_cargo_config_census_reads_every_tracked_entry(self):
        # `git ls-files -z` prints names unquoted and unterminated by newlines, so a name Git would quote, a name that
        # is not UTF-8 and a `.cargo` symlink all reach the match, and a newline-suffixed lookalike does not.
        listing = (b".cargo/config.toml\0.cargo/mutants.toml\0crates/caf\xc3\xa9/.cargo/config.toml\0crates/x/.cargo/config\0"
                   b"tools/.cargo\0unrelated\xff.rs\0crates/\xff/.cargo/config.toml\0crates/y/.cargo/config.toml\n\0")
        self.assertEqual(cargo_configs(listing),
                         [".cargo/config.toml", "crates/café/.cargo/config.toml", "crates/x/.cargo/config", "tools/.cargo",
                          "crates/\udcff/.cargo/config.toml"])

    def test_each_profile_runs_in_the_declared_batches_of_its_sorted_harnesses(self):
        """A profile's batches cut its sorted harnesses in order, each batch within the profile's budget and closed
        only before a harness that would pass it; a harness that weighs the budget runs alone, and pr's budget
        cuts its heaviest harnesses into at least two batches."""
        weights, budgets = EXPECTED["weights"], EXPECTED["batch_budget"]
        for name in EXPECTED["profiles"]:
            with self.subTest(profile=name):
                planned, budget = judge_kani.batches(EXPECTED, name), budgets[name]
                self.assertEqual([harness for batch in planned for harness in batch], profile(name))
                load = [sum(weights.get(harness, 1) for harness in batch) for batch in planned]
                self.assertTrue(all(0 < weight <= budget for weight in load), load)
                for batch, after, weight in zip(planned, planned[1:], load):
                    self.assertGreater(weight + weights.get(after[0], 1), budget, (batch, after[0]))
                for harness in profile(name):
                    if weights.get(harness, 1) == budget:
                        self.assertIn([harness], planned, f"{harness} weighs the budget and runs with others")
        self.assertGreaterEqual(len(judge_kani.batches(EXPECTED, "scheduled")), 2)
        # The pr profile's heaviest harnesses weigh the scheduled budget, and pr's own budget keeps them out of one batch.
        self.assertEqual(max(weights.get(harness, 1) for harness in profile("pr")), budgets["scheduled"])
        heavy = {harness for harness in profile("pr") if weights.get(harness, 1) == budgets["scheduled"]}
        self.assertGreaterEqual(sum(1 for batch in judge_kani.batches(EXPECTED, "pr") if heavy & set(batch)), 2)
        self.assertEqual(judge_kani.batch_files(1), [{"argv": "kani.argv", "txt": "kani.txt", "exit": "kani.exit"}])
        self.assertEqual(judge_kani.batch_files(2)[1], {"argv": "kani-2.argv", "txt": "kani-2.txt", "exit": "kani-2.exit"})
        printed = self.run_script("batches", "--profile", "scheduled")
        self.assertEqual(printed.returncode, 0, printed.stderr)
        self.assertEqual([line.split(" ") for line in printed.stdout.splitlines()], judge_kani.batches(EXPECTED, "scheduled"))
        declared = json.loads(judge_kani.EXPECTED.read_text())
        light = next(harness for harness in EXPECTED["profiles"]["scheduled"] if harness not in weights)
        pr_load = sum(weights.get(harness, 1) for harness in profile("pr"))
        for changes, reason in (({"batch_budget": {"pr": 128}}, "must map each profile"), ({"batch_budget": {"pr": 128, "scheduled": 0}}, "positive count"),
                                ({"batch_budget": {"pr": 128, "scheduled": "8"}}, "positive count"),
                                ({"batch_budget": {"pr": 128, "scheduled": 8, "nightly": 8}}, "must map each profile"),
                                ({"batch_budget": None}, "must map each profile"),
                                ({"weights": {**weights, "absent::proof": 2}}, "the weight of absent::proof names no declared harness"),
                                ({"weights": {**weights, light: 0}}, "a weight is a positive count"),
                                ({"weights": {**weights, light: "2"}}, "a weight is a positive count"),
                                ({"weights": {**weights, light: budgets["scheduled"] + 1}}, f"passes the scheduled profile's batch budget of {budgets['scheduled']}"),
                                ({"weights": []}, "must map harness names")):
            with self.subTest(changes=str(changes)[:60]):
                path = Path(self.temp.name) / "expected.json"
                path.write_text(json.dumps({**declared, **changes}))
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.declaration(path)
                self.assertIn(reason, str(refused.exception))
        # A pr budget below its harnesses' summed weight loads and cuts pr like any profile.
        path.write_text(json.dumps({**declared, "batch_budget": {**budgets, "pr": pr_load - 1}}))
        self.assertEqual(len(judge_kani.batches(judge_kani.declaration(path), "pr")), 2)

    def test_a_pr_profile_of_two_batches_is_judged_batch_by_batch_and_its_receipt_binds_both(self):
        """A `pr` budget below the profile's summed weight cuts `pr` in two, here with its three heaviest harnesses in
        two batches. The judge credits the run from kani-1 and kani-2 files, its receipt binds the run record and
        both batches' files, and a failure in one batch refuses the profile."""
        weights, budgets = EXPECTED["weights"], EXPECTED["batch_budget"]
        heavy = [name for name in profile("pr") if weights.get(name, 1) == budgets["scheduled"]]
        budget = sum(weights.get(name, 1) for name in profile("pr")[:profile("pr").index(heavy[-1])])
        split = {**EXPECTED, "batch_budget": {**budgets, "pr": budget}}
        planned = judge_kani.batches(split, "pr")
        self.assertEqual((len(planned), [name for batch in planned for name in batch]), (2, profile("pr")))
        self.assertEqual([[name for name in batch if name in heavy] for batch in planned], [heavy[:-1], heavy[-1:]])
        files = [judge_kani.RUN_RECORD, *(f"kani-{number}.{kind}" for number in (1, 2) for kind in ("argv", "txt", "exit"))]
        self.assertEqual(judge_kani.evidence_files(split, "pr"), files)
        self.identify()
        failing = {planned[1][0]: [line.replace(" ** 0 of", " ** 1 of", 1).replace("SUCCESSFUL", "FAILED") for line in verified(planned[1][0])]}
        with mock.patch.dict(EXPECTED, {"batch_budget": split["batch_budget"]}), \
                mock.patch.object(judge_kani, "declaration", lambda path=None: split):
            self.write_runs("pr")
            report, receipt = judge_kani.derive(self.evidence, "0" * 40, "pr")
            self.assertEqual(sorted(path.name for path in self.evidence.iterdir() if judge_kani.BATCH_FILE.fullmatch(path.name)), sorted(files[1:]))
            self.assertEqual((report["code"], receipt["executed"]), (0, profile("pr")), report)
            self.assertEqual(report["harnesses"].keys(), set(profile("pr")))
            for name in files:
                self.assertEqual(receipt["inputs"].get(name), sha256(self.evidence / name), f"{name} is unbound")
            self.write_runs("pr", batches={2: {"text": run_text(planned[1], failing).replace("0 failures", "1 failures").replace(
                f"{len(planned[1])} successfully", f"{len(planned[1]) - 1} successfully"), "exit_code": 1}})
            report, receipt = judge_kani.derive(self.evidence, "0" * 40, "pr")
            self.assertEqual((report["code"], report["harnesses"]), (1, {}), report)
            self.assertIn("(batch 2 of 2)", report["reason"])

    def test_the_cut_follows_the_weights_and_a_run_of_another_cut_is_refused(self):
        """Moving a weight moves the cut; a run recorded under the old cut is refused against the new declaration."""
        self.identify()
        self.write_runs("scheduled")
        report, _ = judge_kani.derive(self.evidence, "0" * 40, "scheduled")
        self.assertEqual(report["code"], 0, report)
        weights, budget = EXPECTED["weights"], EXPECTED["batch_budget"]["scheduled"]
        heavy = next(name for name in profile("scheduled") if weights.get(name, 1) == budget)
        light = next(name for name in profile("scheduled") if name not in weights)
        for moved in ({name: weight for name, weight in weights.items() if name != heavy}, {**weights, light: budget}):
            with self.subTest(moved=sorted(set(moved) ^ set(weights))):
                changed = {**EXPECTED, "weights": moved}
                self.assertNotEqual(judge_kani.batches(changed, "scheduled"), judge_kani.batches(EXPECTED, "scheduled"))
                with mock.patch.object(judge_kani, "declaration", lambda path=None: changed):
                    report, receipt = judge_kani.derive(self.evidence, "0" * 40, "scheduled")
                self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
                self.assertRegex(report["reason"], "batches; the scheduled profile declares|batch files differ|the lane ran|another harness list")
                self.assertEqual(receipt["executed"], [])

    def test_the_pr_profile_keeps_its_declared_files_and_its_receipt_shape(self):
        """The pr profile writes the files of its declared batches, and its receipt holds the lane's common keys, its
        evidence inputs naming those files, the run record and the common evidence files."""
        self.identify()
        self.write_runs("pr")
        report, receipt = self.judge("pr")
        self.assertEqual(report["code"], 0, report)
        files = judge_kani.evidence_files(EXPECTED, "pr")
        self.assertEqual(files, [judge_kani.RUN_RECORD, *(name for stems in judge_kani.batch_files(len(judge_kani.batches(EXPECTED, "pr")))
                                                          for name in stems.values())])
        self.assertEqual(sorted(path.name for path in self.evidence.iterdir() if judge_kani.BATCH_FILE.fullmatch(path.name)), sorted(files[1:]))
        self.assertEqual(sorted(receipt), ["assumptions", "bounds", "ci", "completion", "detail", "executed", "executions", "failed", "inputs",
                                           "job", "lane", "module", "replay", "revision", "selection", "tool", "violation"])
        evidence = {name for name in receipt["inputs"] if "/" not in name} - {"Cargo.toml"}
        self.assertEqual(evidence, {"identity.json", "pins.txt", "report.json", "cargo-config.json", "kani-list.json", "Cargo.lock", *files})
        self.assertEqual(report["harnesses"].keys(), set(profile("pr")))

    def test_a_budget_of_a_profiles_summed_weight_runs_it_as_one_batch_in_the_one_file_form(self):
        """For each profile, a budget of the profile's summed weight cuts it into one batch, which the loader accepts
        and the judge credits from kani.argv, kani.txt and kani.exit; a budget one lower cuts it in two, and the
        one-file run is refused against the committed cut of several batches."""
        weights, budgets = EXPECTED["weights"], EXPECTED["batch_budget"]
        self.identify()
        for name in EXPECTED["profiles"]:
            with self.subTest(profile=name):
                load = sum(weights.get(harness, 1) for harness in profile(name))
                whole = {**EXPECTED, "batch_budget": {**budgets, name: load}}
                self.assertEqual(judge_kani.batches(whole, name), [profile(name)])
                self.assertEqual(len(judge_kani.batches({**EXPECTED, "batch_budget": {**budgets, name: load - 1}}, name)), 2)
                self.assertEqual(judge_kani.evidence_files(whole, name), [judge_kani.RUN_RECORD, "kani.argv", "kani.txt", "kani.exit"])
                path = Path(self.temp.name) / "expected.json"
                path.write_text(json.dumps({**json.loads(judge_kani.EXPECTED.read_text()), "batch_budget": whole["batch_budget"]}))
                self.assertEqual(judge_kani.batches(judge_kani.declaration(path), name), [profile(name)])
                with mock.patch.dict(EXPECTED, {"batch_budget": whole["batch_budget"]}), \
                        mock.patch.object(judge_kani, "declaration", lambda path=None, whole=whole: whole):
                    self.write_runs(name)
                    report, receipt = judge_kani.derive(self.evidence, "0" * 40, name)
                self.assertEqual(sorted(path.name for path in self.evidence.iterdir() if judge_kani.BATCH_FILE.fullmatch(path.name)),
                                 ["kani.argv", "kani.exit", "kani.txt"])
                self.assertEqual((report["code"], receipt["executed"]), (0, profile(name)), report)
                self.assertEqual(report["harnesses"].keys(), set(profile(name)))
                for file in (judge_kani.RUN_RECORD, "kani.argv", "kani.txt", "kani.exit"):
                    self.assertEqual(receipt["inputs"].get(file), sha256(self.evidence / file), f"{file} is unbound")
                self.assertGreaterEqual(len(judge_kani.batches(EXPECTED, name)), 2)
                report, receipt = judge_kani.derive(self.evidence, "0" * 40, name)
                self.assertEqual((report["code"], receipt["executed"]), (judge_kani.TOOL_FAILURE, []), report)

    def test_a_profile_of_several_batches_credits_only_when_every_batch_credits_alone(self):
        """Each batch is judged from its own command, output and exit code against the run record; one refused batch,
        a missing or stray batch file, a record of another run, revision or tree, or a joined output refuses the
        whole profile and credits no harness."""
        self.identify()
        planned = judge_kani.batches(EXPECTED, "scheduled")
        count, first, second = len(planned), planned[0], planned[1]
        self.write_runs("scheduled")
        report, receipt = self.judge("scheduled")
        self.assertEqual(report["code"], 0, report)
        self.assertEqual(receipt["executed"], profile("scheduled"))
        files = judge_kani.evidence_files(EXPECTED, "scheduled")
        self.assertEqual(len(files), 1 + 3 * count)
        for name in files:
            self.assertEqual(receipt["inputs"].get(name), sha256(self.evidence / name), f"{name} is unbound")
        failing = {second[0]: [line.replace(" ** 0 of", " ** 1 of", 1).replace("SUCCESSFUL", "FAILED") for line in verified(second[0])]}
        other = self.command(second)
        other[other.index("-j") + 1] = "3"

        def joined():
            self.write_runs("scheduled", batches={1: {"text": run_text(first, {}) + run_text(second, {})}})

        def swapped():
            self.write_runs("scheduled", batches={1: {"argv": self.command(second), "text": run_text(second, {})},
                                                  2: {"argv": self.command(first), "text": run_text(first, {})}})

        def doubled():
            self.write_runs("scheduled", batches={2: {"argv": self.command([first[0], *second]), "text": run_text([first[0], *second], {})}})

        def missing():
            self.write_runs("scheduled")
            for path in self.evidence.glob(f"kani-{count}.*"):
                path.unlink()

        def stray(name):
            def write():
                self.write_runs("scheduled")
                (self.evidence / name).write_text("0\n")
            return write

        def recorded(**changes):
            def write():
                self.write_runs("scheduled")
                self.write_record("scheduled", **changes)
            return write

        def batch_entry(**changes):
            def write():
                self.write_runs("scheduled")
                run = json.loads((self.evidence / judge_kani.RUN_RECORD).read_text())
                run["runs"][1].update(changes)
                (self.evidence / judge_kani.RUN_RECORD).write_text(json.dumps(run))
            return write

        def elsewhere():
            # Batch 2's files come from another invocation of the same revision, whose times differ.
            self.write_runs("scheduled")
            (self.evidence / "kani-2.txt").write_text(run_text(second, {}).replace("Verification Time: 1.25s", "Verification Time: 1.5s"))

        def reordered():
            self.write_runs("scheduled")
            run = json.loads((self.evidence / judge_kani.RUN_RECORD).read_text())
            run["runs"][0]["index"], run["runs"][1]["index"] = 2, 1
            (self.evidence / judge_kani.RUN_RECORD).write_text(json.dumps(run))

        def timed_out(at):
            def write():
                self.write_runs("scheduled", batches={at: {"exit_code": 124}} if at <= count else None)
                for later in range(at + 1, count + 1):
                    for path in self.evidence.glob(f"kani-{later}.*"):
                        path.unlink()
                self.write_record("scheduled", timeout=min(at, count), complete=False)
            return write

        cases = [
            (lambda: self.write_runs("scheduled", results=failing, batches={2: {"exit_code": 1}}), 1, f"fails 1 of 40 checks (batch 2 of {count})"),
            (joined, 2, f"no result for [] (batch 1 of {count})"),
            (swapped, 2, "the lane ran"),
            (doubled, 2, "the lane ran"),
            (missing, 2, f"missing ['kani-{count}.argv', 'kani-{count}.exit', 'kani-{count}.txt']"),
            (stray(f"kani-{count + 1}.txt"), 2, f"stray ['kani-{count + 1}.txt']"),
            (stray("kani.exit"), 2, "stray ['kani.exit']"),
            (stray("kani-01.argv"), 2, "stray ['kani-01.argv']"),
            (stray("kani-2.extra.txt"), 2, "stray ['kani-2.extra.txt']"),
            (elsewhere, 2, "the files of kani-2 differ from the digests kani-run.json records"),
            (recorded(revision="1" * 40), 2, f"records revision '{'1' * 40}', not the judged '{'0' * 40}'"),
            (recorded(clean=False), 2, "records a tree whose tracked files differed"),
            (recorded(count=count + 1), 2, f"records {count + 1} batches; the scheduled profile declares {count}"),
            (recorded(complete=False), 2, "not marked complete"),
            (recorded(invocation=""), 2, "names no invocation"),
            (recorded(workers=3), 2, "kani-run.json records 3 workers"),
            (batch_entry(revision="1" * 40), 2, "records batch 2 at revision"),
            (batch_entry(clean=False), 2, "on a changed tree"),
            (batch_entry(harnesses=[*second, first[0]]), 2, "another harness list"),
            (reordered, 2, "records the batches [2, 1"),
            (lambda: self.write_runs("scheduled", batches={2: {"argv": other}}), 2, "kani-run.json records 2 workers"),
            (lambda: self.write_runs("scheduled", batches={2: {"text": run_text(second, {}).replace("0.68.0 (cargo plugin)", "0.69.0 (cargo plugin)")}}), 2,
             "the run reports Kani ['Kani Rust Verifier 0.69.0 (cargo plugin)']"),
            (lambda: self.write_runs("scheduled", batches={2: {"text": run_text(second, {}).replace("CBMC 6.11.0\n", "")}}), 2, "the run reports CBMC []"),
            (timed_out(2), 3, "interrupted (exit 124) (batch 2"),
            (timed_out(count + 1), 3, f"ran out at batch {count} of {count}"),
        ]
        def unbound_interrupt():
            self.write_runs("scheduled")
            (self.evidence / "kani-2.exit").write_text("124\n")

        def entries(change):
            def write():
                self.write_runs("scheduled")
                run = json.loads((self.evidence / judge_kani.RUN_RECORD).read_text())
                change(run["runs"])
                (self.evidence / judge_kani.RUN_RECORD).write_text(json.dumps(run))
            return write

        cases += [
            (unbound_interrupt, 2, "the files of kani-2 differ from the digests"),
            (lambda: (timed_out(2)(), self.write_record("scheduled", timeout=2, complete=False, revision="1" * 40)), 2, "not the judged"),
            (recorded(clean=1), 2, "records a tree whose tracked files differed"),
            (batch_entry(clean=1), 2, "on a changed tree"),
            (batch_entry(lock="0" * 64), 2, "batch 2 against another Cargo.lock"),
            (recorded(lock=None), 2, "records another Cargo.lock"),
            (batch_entry(end=float("nan")), 2, "records batch 2 from"),
            (batch_entry(end=True), 2, "records batch 2 from"),
            (batch_entry(start=9.0, end=1.0), 2, "records batch 2 from"),
            (recorded(timeout=0, complete=False), 2, "records the timeout 0"),
            (recorded(timeout=count + 1, complete=False), 2, f"records the timeout {count + 1}"),
            (recorded(timeout="2", complete=False), 2, "records the timeout '2'"),
            (recorded(count=True), 2, "records True batches"),
            (recorded(workers=0), 2, "records workers 0"),
            (recorded(workers=True), 2, "records workers True"),
            (recorded(total="1800"), 2, "records total '1800'"),
            (recorded(cap=1), 2, "records the worker bound 1 beside 2 workers"),
            (recorded(runs={}), 2, "records no list of batches"),
            (recorded(runs=[1]), 2, "records no list of batches"),
            (entries(lambda runs: runs.append({**runs[-1], "index": len(runs) + 1})), 2, "where the lane records 1 to at most"),
            (entries(lambda runs: runs.pop()), 2, "marked complete without"),
            (entries(lambda runs: runs[0].update(index=True)), 2, "records the batches [True"),
            (lambda: (self.write_runs("scheduled"), (self.evidence / judge_kani.RUN_RECORD).unlink()), 2, "holds no run record"),
        ]
        if count > 2:
            cases.append((timed_out(count - 1), 3, "interrupted (exit 124)"))
        for index, (write, code, reason) in enumerate(cases):
            with self.subTest(case=index, reason=reason):
                write()
                report, receipt = self.judge("scheduled")
                self.assertEqual(report["code"], code, report)
                self.assertIn(reason, report["reason"])
                self.assertEqual((report["harnesses"], receipt["executed"], receipt["selection"]["credited"]), ({}, [], False))
        # The worker count is compared as a number: -j 02 is the record's 2 workers.
        padded = self.command(second)
        padded[padded.index("-j") + 1] = "02"
        self.write_runs("scheduled", batches={2: {"argv": padded}})
        report, _ = self.judge("scheduled")
        self.assertEqual(report["code"], 0, report)
        self.write_runs("scheduled")
        report, _ = self.judge("scheduled")
        self.assertEqual(report["code"], 0, report)

    def test_cases_prints_each_profiles_harnesses_in_order(self):
        for name in EXPECTED["profiles"]:
            with self.subTest(profile=name):
                printed = self.run_script("cases", "--profile", name)
                self.assertEqual((printed.returncode, printed.stdout.split()), (0, profile(name)), printed.stderr)

    def test_the_run_record_follows_the_lane_batch_by_batch(self):
        """`record` writes one invocation at the checked-out revision, each batch in order as it is recorded with the
        digests of its files and the lock file, and marks the run complete only when every batch is recorded and no
        timeout is; a malformed option or an index out of order refuses with exit 2 and leaves the record."""
        evidence = self.evidence
        evidence.mkdir(parents=True)
        planned = judge_kani.batches(EXPECTED, "scheduled")
        files = judge_kani.batch_files(len(planned))

        def record(*args, code=0):
            result = self.run_script("record", *args, "--evidence", str(evidence))
            self.assertEqual(result.returncode, code, result.stderr)
            return json.loads((evidence / judge_kani.RUN_RECORD).read_text())

        revision = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
        for timeout, done in ((None, True), (len(planned), False)):
            with self.subTest(timeout=timeout):
                run = record("begin", "--profile", "scheduled", "--workers", "2", "--cap", "4", "--total", "1800")
                self.assertEqual((run["profile"], run["revision"], run["workers"], run["cap"], run["count"], run["runs"], run["complete"]),
                                 ("scheduled", revision, 2, 4, len(planned), [], False))
                self.assertEqual(run["lock"], sha256(ROOT / "Cargo.lock") if (ROOT / "Cargo.lock").is_file() else None)
                self.assertRegex(run["invocation"], "^[0-9a-f]{32}$")
                remaining, elapsed = self.run_script("record", "remaining", "--evidence", str(evidence)).stdout.split()
                self.assertLessEqual(int(remaining), 1800)
                self.assertGreaterEqual(float(elapsed), 0)
                for number, names in enumerate(planned, 1):
                    (evidence / files[number - 1]["argv"]).write_text("\n".join(self.command(names)) + "\n")
                    (evidence / files[number - 1]["txt"]).write_text(run_text(names, {}))
                    (evidence / files[number - 1]["exit"]).write_text("0\n")
                    run = record("batch", "--index", str(number), "--start", str(number))
                    entry = run["runs"][-1]
                    self.assertEqual((entry["index"], entry["harnesses"], entry["revision"], entry["lock"]), (number, names, revision, run["lock"]))
                    self.assertEqual(entry["digests"], {kind: sha256(evidence / name) for kind, name in files[number - 1].items()})
                    self.assertEqual(entry["start"], number)
                    self.assertGreaterEqual(entry["end"], 0)
                if timeout:
                    record("timeout", "--index", str(timeout))
                self.assertIs(record("complete")["complete"], done)
        run = record("begin", "--profile", "scheduled", "--workers", "2", "--total", "1800")
        self.assertIsNone(run["cap"])
        for args in (("batch", "--index", "2", "--start", "0"), ("batch", "--index", "0", "--start", "0"), ("batch", "--index", "x", "--start", "0"),
                     ("batch", "--index", "1", "--start", "nan"), ("timeout", "--index", str(len(planned) + 1)), ("timeout", "--index", "3")):
            with self.subTest(args=args):
                self.assertEqual(record(*args, code=2), run)
        for total in ("0", "x"):
            with self.subTest(total=total):
                result = self.run_script("record", "begin", "--profile", "scheduled", "--workers", "2", "--total", total, "--evidence", str(evidence))
                self.assertEqual(result.returncode, 2, result.stderr)
        record("timeout", "--index", "1")
        self.assertEqual(record("complete")["timeout"], 1)
        self.assertIs(record("complete")["complete"], False)

    def tree_repo(self):
        """Return a repository holding the committed files `a.txt`, the empty `e.txt` and `d/x.txt`, and a `git` that
        runs in it."""
        root = Path(self.temp.name) / "repo"
        (root / "d").mkdir(parents=True)

        def git(*args):
            return subprocess.run(["git", "-C", str(root), *args], capture_output=True, check=True, text=True).stdout
        git("init", "-q")
        git("config", "user.email", "test@example.invalid")
        git("config", "user.name", "test")
        (root / "a.txt").write_text("a\n")
        (root / "e.txt").write_text("")
        (root / "d/x.txt").write_text("x\n")
        git("add", ".")
        git("commit", "-qm", "a")
        return root, git

    def test_the_tree_state_names_every_tracked_change_and_flag(self):
        """A tree is clean when every tracked file shows its commit's bytes: untracked files leave it clean, and a
        tracked edit, a staged change, a staged change whose working file is restored, an intent-to-add entry on a path
        committed as an empty file, a staged change in either half of a split index, an assume-unchanged or
        skip-worktree flag, or a sparse checkout's skip-worktree entries make it changed, each sampled after the
        run's refresh of the index, as the run record samples it; a path that is not UTF-8 compares by its bytes."""
        root, git = self.tree_repo()
        with mock.patch.object(judge_kani, "ROOT", root), mock.patch.object(judge_kani.rc11, "ROOT", root):
            judge_kani.refresh_index()
            revision = git("rev-parse", "HEAD").strip()
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            (root / "b.txt").write_text("untracked\n")
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            (root / "a.txt").write_text("edited\n")
            self.assertEqual(judge_kani.tree_state(), (revision, False))
            git("add", "a.txt")
            self.assertEqual(judge_kani.tree_state(), (revision, False))
            (root / "a.txt").write_text("a\n")
            self.assertEqual(judge_kani.tree_state(), (revision, False), "a staged change under a restored file")
            git("reset", "-q", "--hard")
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            git("add", "-N", "b.txt")
            self.assertEqual(judge_kani.tree_state(), (revision, False), "an intent-to-add entry")
            git("rm", "-q", "--cached", "b.txt")
            # An intent-to-add entry of a path committed as an empty file lists the committed mode and object.
            git("rm", "-q", "--cached", "e.txt")
            git("add", "-N", "e.txt")
            self.assertEqual(judge_kani.tree_state(), (revision, False), "an intent-to-add entry on an empty committed file")
            git("rm", "-q", "--cached", "e.txt")
            git("add", "e.txt")
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            for flag in ("--assume-unchanged", "--skip-worktree"):
                with self.subTest(flag=flag):
                    git("update-index", flag, "a.txt")
                    self.assertEqual(judge_kani.tree_state(), (revision, False))
                    git("update-index", flag.replace("--", "--no-"), "a.txt")
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            git("config", "core.splitIndex", "true")
            git("update-index", "--split-index")
            judge_kani.refresh_index()
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            (root / "a.txt").write_text("split\n")
            git("add", "a.txt")
            (root / "a.txt").write_text("a\n")
            self.assertEqual(judge_kani.tree_state(), (revision, False), "a staged change in the split index's own half")
            git("update-index", "--no-split-index")
            git("update-index", "--split-index")
            self.assertEqual(judge_kani.tree_state(), (revision, False), "a staged change in the split index's shared half")
            git("reset", "-q")
            git("update-index", "--no-split-index")
            git("config", "--unset", "core.splitIndex")
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            for args in (("--no-cone", "/*.txt"), ("--cone", "--sparse-index", "nothing")):
                with self.subTest(sparse=args):
                    git("sparse-checkout", "set", *args)
                    self.assertEqual(judge_kani.tree_state(), (revision, False), "a sparse checkout's skip-worktree entries")
                    git("sparse-checkout", "disable")
                    self.assertEqual(judge_kani.tree_state(), (revision, True))
            # A path that is not UTF-8, printed unquoted, compares by its bytes: committed it reads as clean, and a
            # staged change to it reads as changed.
            git("config", "core.quotePath", "false")
            odd = root / os.fsdecode(b"odd-\xff.txt")
            odd.write_text("odd\n")
            git("add", "--", odd.name)
            git("commit", "-qm", "odd")
            revision = git("rev-parse", "HEAD").strip()
            self.assertEqual(judge_kani.tree_state(), (revision, True))
            odd.write_text("staged\n")
            git("add", "--", odd.name)
            odd.write_text("odd\n")
            self.assertEqual(judge_kani.tree_state(), (revision, False))

    def test_the_refresh_keeps_every_entry_and_a_later_sample_still_finds_a_same_size_edit(self):
        """The run's refresh writes stat data only: every entry's mode, object, stage, path and flag stays as it was.
        After it, a same-size edit whose modification time is set back, made in a later second than the file's last
        inode change, still shows as a change through the inode change time git compares.
        The refresh also writes the index when every entry matches its file and only shares the index's second, the
        state a checkout leaves. A checkout whose git skips that time gets no refresh, so its samples still compare
        by content the files written in the index's second; a held index lock makes the refresh fail and leaves the
        index as it was; every sample reads the index with optional locks off and leaves it as it was."""
        for config in (None, ("core.checkStat", "minimal"), ("core.trustctime", "false")):
            with self.subTest(config=config):
                root, git = self.tree_repo()
                if config:
                    git("config", *config)
                index, tracked, second = root / ".git/index", root / "a.txt", int(time.time()) - 100
                # An index older than its files: every entry matches its file and none is older than the index, so
                # git has only the index's own time to write.
                os.utime(index, (second, second))
                stamp = (index.read_bytes(), index.stat().st_mtime_ns)
                with mock.patch.object(judge_kani, "ROOT", root):
                    judge_kani.refresh_index()
                if config:
                    self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), stamp, "a refresh where git skips the inode change time")
                else:
                    self.assertNotEqual(index.stat().st_mtime_ns, stamp[1], "the refresh wrote no index for entries that share its second")
                for path in (tracked, index):
                    os.utime(path, (second, second))
                entries = git("ls-files", "-v", "-s", "-z")
                stamp = (index.read_bytes(), index.stat().st_mtime_ns)
                calls = []

                def run(command, *args, calls=calls, real_run=subprocess.run, **kwargs):
                    calls.append(list(command))
                    return real_run(command, *args, **kwargs)
                with mock.patch.object(judge_kani, "ROOT", root), mock.patch.object(judge_kani.rc11, "ROOT", root):
                    judge_kani.refresh_index()
                    self.assertEqual(git("ls-files", "-v", "-s", "-z"), entries, "the refresh changed an entry")
                    if config:
                        self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), stamp, "a refresh where git skips the inode change time")
                    else:
                        self.assertNotEqual(index.stat().st_mtime_ns, stamp[1], "the refresh wrote no index")
                    # The edit falls in a later second than the file's last inode change, as an edit after the run's
                    # start does.
                    time.sleep(1.1)
                    refreshed = (index.read_bytes(), index.stat().st_mtime_ns)
                    revision = git("rev-parse", "HEAD").strip()
                    with mock.patch.object(judge_kani.subprocess, "run", run):
                        self.assertEqual(judge_kani.tree_state(), (revision, True))
                        tracked.write_text("b\n")
                        os.utime(tracked, (second, second))
                        for _ in range(2):
                            self.assertEqual(judge_kani.tree_state(), (revision, False), "a same-size edit with its time set back")
                        tracked.write_text("a\n")
                        self.assertEqual(judge_kani.tree_state(), (revision, True))
                    self.assertEqual([call for call in calls if call[0] == "git" and "--no-optional-locks" not in call], [],
                                     "a sample ran git with optional locks on")
                    self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), refreshed, "a sample wrote the index")
                    self.assertFalse((root / ".git/index.lock").exists())
                    (root / ".git/index.lock").write_text("")
                    os.utime(index, (second, second))
                    held = (index.read_bytes(), index.stat().st_mtime_ns)
                    judge_kani.refresh_index()
                    self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), held, "a refresh under a held lock")
                    self.assertEqual(judge_kani.tree_state(), (revision, True))
                    (root / ".git/index.lock").unlink()
                    # A status that cannot read the index reads as a changed tree.
                    index.write_bytes(b"not an index")
                    self.assertEqual(judge_kani.tree_state()[1], False, "a failed status")
                shutil.rmtree(root)

    def test_the_run_record_keeps_each_sample_of_the_tree(self):
        """`record` writes each sample's tree state where it was taken: a tracked edit present only at batch 1 makes
        that batch's entry changed while `begin` and batch 2 stay clean, and the judge refuses the run for batch 1; a
        `begin` refused for its options leaves the checkout's index as it was."""
        root, git = self.tree_repo()
        (root / "Cargo.lock").write_text("")
        git("add", "Cargo.lock")
        git("commit", "-qm", "lock")
        revision = git("rev-parse", "HEAD").strip()
        evidence = self.evidence
        evidence.mkdir(parents=True)
        shutil.copyfile(root / "Cargo.lock", evidence / "Cargo.lock")
        with mock.patch.object(judge_kani, "ROOT", root), mock.patch.object(judge_kani.rc11, "ROOT", root), \
                contextlib.redirect_stdout(io.StringIO()):
            def record(*args):
                self.assertEqual(judge_kani.main(["record", *args, "--evidence", str(evidence)]), judge_kani.CREDITED)
            # A refused begin leaves the checkout's index as it was.
            index = root / ".git/index"
            old = int(time.time()) - 100
            os.utime(index, (old, old))
            stamp = (index.read_bytes(), index.stat().st_mtime_ns)
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(judge_kani.main(["record", "begin", "--profile", "pr", "--workers", "2", "--total", "0", "--evidence", str(evidence)]), 2)
            self.assertEqual((index.read_bytes(), index.stat().st_mtime_ns), stamp, "a refused begin refreshed the index")
            record("begin", "--profile", "pr", "--workers", "2", "--total", "1800")
            count = json.loads((evidence / judge_kani.RUN_RECORD).read_text())["count"]
            self.assertGreaterEqual(count, 2)
            for number in range(1, count + 1):
                (root / "a.txt").write_text("edited\n" if number == 1 else "a\n")
                record("batch", "--index", str(number), "--start", "0")
            record("complete")
        run = json.loads((evidence / judge_kani.RUN_RECORD).read_text())
        self.assertEqual([run["clean"], *(entry["clean"] for entry in run["runs"])], [True, False, *[True] * (count - 1)])
        self.assertEqual({run["revision"], *(entry["revision"] for entry in run["runs"])}, {revision})
        with self.assertRaisesRegex(judge_kani.Refusal, "records batch 1 .* on a changed tree"):
            judge_kani.check_provenance(evidence, run, revision)

    def test_a_pr_run_never_stands_in_for_the_scheduled_domain(self):
        self.identify()
        self.write_runs("pr")
        report, _ = self.judge("scheduled")
        self.assertEqual(report["code"], 2, report)
        self.assertIn("kani-run.json records a run of the 'pr' profile, not 'scheduled'", report["reason"])
        # A record that names the scheduled profile beside the pr run's files still credits nothing.
        count = len(judge_kani.batches(EXPECTED, "scheduled"))
        self.write_record("pr", profile="scheduled", count=count, complete=True, runs=[
            {**entry, "index": number} for number, entry in enumerate((self.write_record("pr")["runs"] * count)[:count], 1)])
        report, _ = self.judge("scheduled")
        self.assertEqual(report["code"], 2, report)
        self.assertRegex(report["reason"], "no recorded run|batch files differ")
        self.write_runs("scheduled")
        report, receipt = self.judge("scheduled")
        self.assertEqual((report["code"], receipt["module"]), (0, "scheduled"), report)
        report, _ = self.judge("nightly")
        self.assertIn("profile 'nightly' is not declared", report["reason"])

    def test_the_judgment_takes_the_cbmc_version_from_the_identified_kani(self):
        """The identity records what the identified `cargo kani --version` prints, the CBMC it runs included; a run log
        that names the compared CBMC credits nothing when the identified Kani reports another CBMC or none."""
        self.identify()
        self.write_runs()
        report, receipt = self.judge()
        self.assertEqual(report["code"], 0, report)
        for lines, reported in ((["CBMC 6.12.0"], "['6.12.0']"), ([], "[]"), (["CBMC 6.11.0", "CBMC 6.12.0"], "['6.11.0', '6.12.0']")):
            with self.subTest(identified=lines):
                echoes = "".join(f"echo '{line}'\n" for line in [f"Kani Rust Verifier {EXPECTED['kani']} (cargo plugin)", *lines])
                self.cargo_kani.write_text(f"#!/usr/bin/env bash\n{echoes}")
                self.identify()
                self.write_runs()
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(f"the identified Kani reports CBMC {reported}", report["reason"])
                self.assertEqual(receipt["executed"], [])

    def test_each_unusable_or_mismatched_run_is_refused(self):
        """Each case plants its command or output in the first batch of pr, or its results and exit code in every batch."""
        self.identify()
        names = judge_kani.batches(EXPECTED, "pr")[0]
        stems = judge_kani.batch_files(len(judge_kani.batches(EXPECTED, "pr")))[0]
        name = names[0]
        covers = EXPECTED["harnesses"][name]["covers"]
        failing = [line.replace(" ** 0 of 40 failed", " ** 1 of 40 failed") for line in verified(name)]
        failing = [line.replace("VERIFICATION:- SUCCESSFUL", "VERIFICATION:- FAILED") for line in failing]
        dropped = [line for line in verified(name) if "VERIFICATION:-" not in line]

        def summarized(summary, lines=None):
            return [summary if " failed" in line and line.startswith(" ** ") else line for line in (lines or verified(name))]

        jobs = self.command(names)
        jobs[jobs.index("-j") + 1] = "\u00b2"
        serial, oversized = self.command(names), self.command(names)
        serial[serial.index("-j") + 1] = "1"
        oversized[oversized.index("-j") + 1] = "9" * 5000
        pin = EXPECTED["harnesses"][name]["unreachable"] or 3

        def beside(extra):
            lines = verified(name)
            return [*lines[:-1], extra, lines[-1]]
        # The summary header and the Complete line, printed after the first result and ahead of the others.
        body, trailer = run_text(names, {}).split("Manual Harness Summary:\n")
        moved = body.replace("Verification Time: 1.25s\n", "Verification Time: 1.25s\nManual Harness Summary:\n" + trailer, 1)
        cases = [
            ({"results": {name: failing}, "exit_code": 1}, 1, "fails 1 of 40 checks"),
            ({"results": {name: [*failing[:-1], " ** WARNING: A Rust construct that is not currently supported by Kani was found to be reachable. "
                                                "Check the results for more details.", failing[-1]]}, "exit_code": 1}, 1, "fails 1 of 40 checks"),
            ({"results": {name: summarized(" ** 1 of 40 failed (39 undetermined)", failing)}, "exit_code": 1}, 1, "fails 1 of 40 checks"),
            ({"results": {name: summarized(" ** 1 of 9 failed (3 undetermined,2 unreachable)", failing)}, "exit_code": 1}, 1, "fails 1 of 9 checks"),
            ({"results": {name: summarized(" ** 0 of 40 failed (3 undetermined)")}}, 1, "leaves 3 of 40 checks undetermined"),
            ({"results": {name: summarized(" ** 0 of 40 failed ()")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(" ** 0 of 40 failed (3 undetermined,)")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(" ** 0 of 40 failed (" + "9" * 5000 + " unreachable)")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(" ** 0 of 40 failed (0 undetermined3 unreachable)")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(" ** 0 of 40 failed (3 undetermined3 unreachable)")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(" ** 0 of 40 failed (0 unreachable)")}}, 2, "malformed check summary line"),
            ({"results": {name: summarized(f" ** 0 of {pin - 1} failed ({pin} unreachable)")}}, 2, "counts exceed its total"),
            ({"results": {name: beside(" ** 0 of 40 failed (" + "9" * 19 + " unreachable)")}}, 2, "malformed check summary line"),
            ({"results": {name: beside(f" ** {covers} of {covers} cover properties satisfied (" + "9" * 19 + " unreachable)")}}, 2,
             "malformed cover summary line"),
            ({"results": {name: beside("VERIFICATION:- FAILED")}}, 2, "result lines; a credited result is exactly"),
            ({"results": {name: [line.replace("1.25s", "1..2s") for line in verified(name)]}}, 2, "Verification Time lines"),
            ({"results": {name: verified(name, covers=covers + 1)}}, 1, "covers, declared"),
            ({"results": {name: verified(name, covers=covers - 1)}}, 1, "covers, declared"),
            ({"results": {name: [line.replace(f" ** {covers} of {covers} cover", f" ** {covers - 1} of {covers} cover") for line in verified(name)]}},
             1, f"satisfies {covers - 1} of {covers} covers, declared {covers}"),
            ({"results": {name: [line for line in verified(name) if "cover properties" not in line]}}, 1, f"satisfies 0 of 0 covers, declared {covers}"),
            ({"results": {name: verified(name, checks=0, unreachable=0)}}, 2, "checked no property"),
            ({"exit_code": 124}, 3, "interrupted"),
            ({"exit_code": 101}, 2, "exited 101"),
            ({"results": {name: dropped}}, 2, "VERIFICATION:- SUCCESSFUL lines"),
            ({"text": run_text(names, {}).replace(f"Checking harness {name}...", "Checking harness other::proof...")}, 2, "no result for"),
            ({"text": run_text(names, {}, complete="Complete - 1 successfully verified harnesses, 0 failures, 1 total.")}, 2, "Complete lines"),
            ({"text": run_text([*names, name], {})}, 2, "two results"),
            ({"text": run_text(names, {}).replace("CBMC 6.11.0", "CBMC 6.12.0")}, 2, "the run reports CBMC ['6.12.0']"),
            ({"text": run_text(names, {}).replace("CBMC 6.11.0\n", "")}, 2, "the run reports CBMC []"),
            ({"text": run_text(names, {}).replace("CBMC 6.11.0", "CBMC 6.11.0\nCBMC 6.11.0")}, 2, "the run reports CBMC ['6.11.0', '6.11.0']"),
            # The result Kani prints for a harness whose CBMC process ran out of memory.
            ({"results": {name: ["CBMC failed", "VERIFICATION:- FAILED", "CBMC appears to have run out of memory. You may want to rerun your "
                                 "proof in an environment with additional memory or use stubbing to reduce the size of the code the verifier "
                                 "reasons about."]}, "exit_code": 1}, 2, f"{name} prints 0 check summary lines"),
            ({"argv": self.command(names, ["--no-overflow-checks"])}, 2, "the lane ran"),
            ({"argv": self.command(names[1:])}, 2, "the lane ran"),
            ({"argv": [a for a in self.command(names) if a != "--exact"]}, 2, "the lane ran"),
            ({"argv": self.command(names) + ["--default-unwind", "1"]}, 2, "the lane ran"),
            ({"argv": self.command(names)[:-5]}, 2, "the lane ran"),
            ({"argv": self.command(names)[:-2]}, 2, "the lane ran"),
            ({"argv": [*self.command(names)[:-1], str(int(EXPECTED["cbmc"][1]) * 2)]}, 2, "the lane ran"),
            ({"argv": [*self.command(names)[:-2], "--no-assertions", *EXPECTED["cbmc"]]}, 2, "the lane ran"),
            ({"argv": jobs}, 2, "the lane ran"),
            ({"argv": serial}, 2, "the lane ran"),
            ({"argv": oversized}, 2, "the lane ran"),
            ({"text": run_text(names, {}) + "Complete - 1 successfully verified harnesses, 0 failures, 1 total.\n"}, 2, "Complete lines"),
            ({"results": {name: [*verified(name), "VERIFICATION:- FAILED"]}}, 2, "outside its harness results"),
            *(({"text": text}, 2, "outside its harness results") for text in (
                run_text(names, {}).replace(f"Checking harness {name}...\n", f"Checking harness {name}...\nVERIFICATION:- FAILED\n"),
                run_text(names, {}) + "VERIFICATION:- FAILED\n",
                run_text(names, {}).replace("Manual Harness Summary:\n", f"Manual Harness Summary:\nVerification failed for - {name}\n"),
                run_text(names, {}).replace("Manual Harness Summary:\n", ""),
                run_text(names, {}).replace("Manual Harness Summary:\n", "Manual Harness Summary:\n" * 2),
                run_text(names, {}).replace("Manual Harness Summary:\n", "") + "Manual Harness Summary:\n",
                moved)),
            *(({"text": run_text(names, {}) + f"Complete{gap}- 0 successfully verified harnesses, 1 failures, 1 total.\n"}, 2, "Complete lines")
              for gap in ("  ", "", "\t")),
            ({"results": {name: [line.replace(f" ** {covers} of {covers} cover properties satisfied",
                                              f" ** {covers - 1} of {covers} cover properties satisfied (1 unreachable)") for line in verified(name)]}},
             1, f"satisfies {covers - 1} of {covers} covers (0 undetermined, 1 unreachable), declared {covers}"),
            ({"results": {name: [line.replace(f" ** {covers} of {covers} cover", f" ** {'9' * 19} of {covers} cover") for line in verified(name)]}},
             2, "malformed cover summary line"),
        ]
        zero = next((n for n in names if EXPECTED["harnesses"][n]["unreachable"] == 0), None)
        if zero:
            cases.append(({"results": {zero: verified(zero, unreachable=1)}}, 1, f"{zero} reports 1 unreachable checks, declared 0"))
            # The judge exits 1 when the unreachable count differs from its declaration, even with an extra result line.
            counted = verified(zero, unreachable=1)
            cases.append(({"results": {zero: [*counted[:-1], "VERIFICATION:- FAILED", counted[-1]]}}, 1, f"{zero} reports 1 unreachable checks, declared 0"))
        pinned = next((n for n in names if EXPECTED["harnesses"][n]["unreachable"]), None)
        if pinned:
            declared = EXPECTED["harnesses"][pinned]["unreachable"]
            cases.append(({"results": {pinned: verified(pinned, unreachable=0)}}, 1, f"{pinned} reports 0 unreachable checks, declared {declared}"))
            cases.append(({"results": {pinned: verified(pinned, unreachable=declared + 1)}}, 1,
                          f"{pinned} reports {declared + 1} unreachable checks, declared {declared}"))
        for index, (runs, code, reason) in enumerate(cases):
            with self.subTest(case=index, reason=reason):
                first = {kind: runs[kind] for kind in ("argv", "text") if kind in runs}
                self.write_runs(**{key: value for key, value in runs.items() if key not in first}, batches={1: first})
                report, receipt = self.judge()
                self.assertEqual(report["code"], code, report)
                self.assertIn(reason, report["reason"])
                self.assertEqual(receipt["executed"], [])
        self.write_runs()
        (self.evidence / stems["argv"]).write_bytes(b"cargo\nkani\n--target-dir\n\xff\n")
        self.write_record("pr")
        report, receipt = self.judge()
        self.assertEqual(report["code"], 2, report)
        self.assertIn(f"{stems['argv']} is not UTF-8", report["reason"])
        self.assertEqual(receipt["executed"], [])
        # A credited result is exactly its five lines: a sixth line of any spelling, or another first line, refuses.
        result = [line.strip() for line in verified("in::process::proof", covers=2, unreachable=0)]
        extras = ("** 1  of 40 failed", "**  1 of 40 failed", "** 1 of  40 failed", "** 1 of 40  failed", "**1 of 40 failed", "** 1\tof 40 failed",
                  "** 0  of 2 cover properties satisfied", "** 0 of 2 cover  properties satisfied", "** 1 of 40failed", "** 1of 40 failed",
                  "VERIFICATION:- FAILED", "** 1 of 40 FAILED", "** 1 of 40 checks failed", "* 1 of 40 failed", "** 0 of 2 covers satisfied")
        for lines in (*([*result[:-1], extra, result[-1]] for extra in extras), ["VERIFICATION OUTCOME:", *result[1:]]):
            with self.subTest(lines=lines):
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.judge_harness("in::process::proof", {"covers": 2, "unreachable": 0}, lines)
                self.assertEqual(refused.exception.code, judge_kani.TOOL_FAILURE)
                self.assertIn("result lines; a credited result is exactly", str(refused.exception))
        self.assertEqual(judge_kani.judge_harness("in::process::proof", {"covers": 2, "unreachable": 0}, result)["checks"], 40)
        # Each harness must report exactly its declared number of unreachable checks, including zero.
        for declared, reported in ((0, 1), (3, 0), (3, 4), (3, 3)):
            with self.subTest(declared=declared, reported=reported):
                lines = [line.strip() for line in verified("in::process::proof", covers=2, unreachable=reported)]
                harness = {"covers": 2, "unreachable": declared}
                if declared == reported:
                    self.assertEqual(judge_kani.judge_harness("in::process::proof", harness, lines)["unreachable"], reported)
                    continue
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.judge_harness("in::process::proof", harness, lines)
                self.assertEqual(refused.exception.code, judge_kani.MISMATCH)
                self.assertIn(f"reports {reported} unreachable checks, declared {declared}", str(refused.exception))
        # A result whose every check is unreachable refuses even at its declared pin with every cover satisfied; one
        # reached check above the pin is eligible.
        harness = {"covers": 5, "unreachable": 44}
        for total in (44, 45):
            with self.subTest(total=total):
                lines = [line.strip() for line in verified("in::process::proof", checks=total, covers=5, unreachable=44)]
                if total > 44:
                    self.assertEqual(judge_kani.judge_harness("in::process::proof", harness, lines)["checks"], total)
                    continue
                with self.assertRaises(judge_kani.Refusal) as refused:
                    judge_kani.judge_harness("in::process::proof", harness, lines)
                self.assertEqual(refused.exception.code, judge_kani.TOOL_FAILURE)
                self.assertIn("reaches none of its 44 checks", str(refused.exception))

    def test_a_package_whose_harnesses_differ_from_the_declaration_is_refused(self):
        self.identify()
        declared = sorted(EXPECTED["harnesses"])
        for listed, reason in ((declared[1:], "missing"), ([*declared, "extra::proof"], "undeclared ['extra::proof']")):
            with self.subTest(reason=reason):
                self.write_runs(listed=listed)
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(reason, report["reason"])

    def test_evidence_json_of_another_shape_or_nested_past_the_parser_is_refused_with_a_report(self):
        self.identify()
        self.write_runs()
        deep = "[" * 100_000 + "]" * 100_000
        version = json.dumps(f"Kani Rust Verifier {EXPECTED['kani']} (cargo plugin)")
        # These two shapes reach a check's own refusal; every other one raises inside the judgment.
        checked = {'{"version": "", "cargo_kani": []}': "Kani reports ''", '{"standard-harnesses": {"f": [5]}}': "undeclared [5]"}
        for name, texts in (("identity.json", ("[]", '{"version": 5}', '{"version": "", "cargo_kani": []}', f'{{"version": {version}, "cargo_kani": "x"}}',
                                               f'{{"version": {version}, "cargo_kani": {{"path": 5}}}}', deep)),
                            ("kani-list.json", ("[]", '{"standard-harnesses": [1]}', '{"standard-harnesses": {"f": 5}}',
                                                '{"standard-harnesses": {"f": [5]}}', '{"standard-harnesses": {"f": [5, "a"]}}',
                                                '{"standard-harnesses": {"f": [[1]]}}', deep)),
                            ("cargo-config.json", ('{"env": [1]}', '{"env": 5}', '{"build": 5}', '{"alias": ["kani"]}', '{"alias": 5}',
                                                   '{"alias": "kani"}', '{"alias": null}', deep))):
            original = (self.evidence / name).read_text()
            for text in texts:
                with self.subTest(name=name, text=text[:40]):
                    (self.evidence / name).write_text(text)
                    report, receipt = self.judge()
                    self.assertEqual(report["code"], judge_kani.TOOL_FAILURE, report)
                    self.assertIn(checked.get(text, "malformed evidence"), report["reason"])
                    self.assertEqual((receipt["executed"], receipt["selection"]["credited"]), ([], False))
            (self.evidence / name).write_text(original)
        report, _ = self.judge()
        self.assertEqual(report["code"], 0, report)

    def test_a_changed_or_other_kani_installation_is_refused(self):
        bundle = self.home / f"kani-{EXPECTED['kani']}"
        (bundle / "lib").mkdir()
        (bundle / "lib/libkani.rlib").write_text("kani library\n")
        self.identify()
        self.write_runs()
        report, _ = self.judge()
        self.assertEqual(report["code"], 0, report)
        for path, text in ((bundle / "bin/cbmc", "other\n"), (bundle / "lib/libkani.rlib", "other library\n"),
                           (self.toolchain / "lib/librustc_driver.so", "other driver\n")):
            with self.subTest(path=path.name):
                original = path.read_text()
                path.write_text(text)
                report, _ = self.judge()
                self.assertIn("changed since the identity was taken", report["reason"] or "", report)
                path.write_text(original)
        other = self.toolchain.with_name("nightly-2026-09-01-x86_64-unknown-linux-gnu")
        shutil.copytree(self.toolchain, other)
        bundle.joinpath("toolchain").unlink()
        (bundle / "toolchain").symlink_to(other)
        report, _ = self.judge()
        self.assertIn("changed since the identity was taken", report["reason"] or "", report)
        self.cargo_kani.write_text("#!/usr/bin/env bash\necho 'Kani Rust Verifier 0.67.0 (cargo plugin)'\n")
        self.identify()
        report, _ = self.judge()
        self.assertIn("declared 0.68.0", report["reason"])


if __name__ == "__main__":
    unittest.main()
