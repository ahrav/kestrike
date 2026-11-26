#!/usr/bin/env python3
"""Inspect the linked release realization of the authentication tag
comparison on x86-64 and AArch64.

Usage:
  scan-tag-compare.py limits
  scan-tag-compare.py select --cargo-json FILE
  scan-tag-compare.py identity --cargo-json FILE --target-features LIST --pins FILE
      --output FILE
  scan-tag-compare.py scan --executable PATH --evidence DIR
      [--objdump CMD] [--demangler CMD]
  scan-tag-compare.py judge --evidence DIR [--revision REV]

`select` prints the one kestrike library-test executable of a
`cargo test --release -p kestrike --lib --no-run --message-format=json`
build, or refuses when the build names none or several.

`identity` writes the build identity: the checked-out revision, the CI run,
attempt and job, the executable and its sha256, the `release` profile with
the profile Cargo reports, the LTO setting, every `CARGO_PROFILE_*`
override, `RUSTFLAGS`, the comma-separated target features and the
native-build pin lines. Cargo's JSON omits LTO, so the lane pins
`CARGO_PROFILE_RELEASE_LTO` and the identity refuses when it is unset, when
the feature list is empty and when git names no revision.

`scan` admits a little-endian ELF64 executable for x86-64 (`e_machine` 62)
or AArch64 (183), resolves each declared site to exactly one function symbol
whose extent lies inside one executable `PROGBITS` section, decodes the
extent with the pinned LLVM `--objdump` (Intel syntax on x86-64), records
`extents.json` (the machine, the executable's sha256, the objdump command
and version, and each site's address, size and disassembly, keyed by site
name) in `--evidence`, and judges it.

`judge` derives `report.json` and the lane's `receipt.json` from
`extents.json`, `identity.json` and the committed declaration, and the
receipt binds `pins.txt`, the callers' run (`callers.txt` and `exit.txt`)
and the committed inputs; `derive` is the same judgment for
`verify-receipts.py`. The judgment refuses an identity that lacks a field,
names another revision, an optimization level other than 3, debug
assertions or LTO, or binds another executable digest, and a callers' run
that is missing, exited nonzero, or reports a caller or count other than the
declaration's.

The judgment follows each byte of the two 16-byte inputs, `tag` through the
first argument pointer and `expected` through the second, through registers,
flags and stack slots, along every path the extent's forward branches open:
a load through an argument pointer carries the bytes it reads, bitwise
operations combine bytes lane by lane, other arithmetic spreads every source
byte over its result, and a call's result carries the bytes of the
arguments the declaration's `callees` gives its callee. A conditional
branch, conditional select or compare, or memory address that depends on
some input bytes but not all 32 is a falsifier: it acts on a partial
comparison. A memory address that depends on all 32 bytes is also a
falsifier. The site passes when it has no falsifier and every path takes
exactly one conditional branch on all 32 bytes, the final decision; a select
on all 32 bytes materializes that decision. A trap ends its path. A backward
branch, an undeclared callee, an access the model cannot locate, a store of
input bytes outside the stack, a store of a tracked pointer, a line the
disassembler leaves undecoded, a return through a register other than the
link register and an instruction outside the modeled set refuse the site.
The report keeps every instruction with the bytes it depends on and its
role, the number of paths walked and the functions the extent calls.

A `pass` site must pass and a `control` site must be flagged with the
falsifier its `flags` names; the run credits when every site meets its
expectation.

Exit 0 credits the run, 1 is a site off its expectation, 2 is a refusal.
"""

import argparse
import functools
import hashlib
import importlib.util
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECLARATION = ROOT / "verification/tag-compare/expected.json"
CREDITED, OFF, REFUSED = 0, 1, 2
EM_X86_64, EM_AARCH64 = 62, 183
MACHINES = {EM_X86_64: "x86-64", EM_AARCH64: "aarch64"}
TAG_LEN, INPUTS = 16, ("tag", "expected")
FULL = frozenset((which, at) for which in range(len(INPUTS)) for at in range(TAG_LEN))
NONE = frozenset()
LIMITS = [
    "linked extent only: the judgment covers the declared callers' own instructions and lists each callee they "
    "call; a callee's result carries the bytes of as many arguments as the declaration gives it",
    "anchor proxy: the decision caller realizes the production comparison in the release library-test build; other "
    "sites that inline it are outside the judgment",
    "forward paths: the walk follows every path through the extent's forward branches, up to 4096, and "
    "refuses a backward branch",
    "over-approximation: arithmetic spreads every source byte over its result, so a full dependency can stand "
    "for a partial one; the callers' tests at every mismatch position cover the decision's meaning",
    "dependency, not timing: a credited site has no partial-comparison branch, select or address in its "
    "extent; instruction latency and microarchitectural timing are outside the judgment",
]
IDENTITY_FIELDS = ("revision", "ci", "executable", "sha256", "profile", "cargo_profile", "lto", "profile_env",
                   "rustflags", "target_features", "native_build")


class Refusal(Exception):
    pass


@functools.cache
def load_barriers():
    """The barrier scan's module, loaded once so its `Refusal` is one class across every caller."""
    spec = importlib.util.spec_from_file_location("scan_barriers", ROOT / "scripts/scan-barriers.py")
    if spec is None or spec.loader is None:
        raise Refusal("scripts/scan-barriers.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(lines, features, pins):
    """The build identity of the executable `select` names."""
    barriers = load_barriers()
    message = barriers.artifact(lines)
    lto = os.environ.get("CARGO_PROFILE_RELEASE_LTO")
    if not lto:
        raise Refusal("the build pins no LTO setting: CARGO_PROFILE_RELEASE_LTO is unset")
    features = [feature for feature in features.split(",") if feature]
    if not features:
        raise Refusal("the compiler reported no target features")
    revision = barriers.load_rc11().git_revision()
    if not revision:
        raise Refusal("git names no checked-out revision")
    return {"revision": revision,
            "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
            "executable": message["executable"],
            "sha256": hashlib.sha256(Path(message["executable"]).read_bytes()).hexdigest(),
            "profile": "release", "cargo_profile": message["profile"], "lto": lto,
            "profile_env": {key: value for key, value in sorted(os.environ.items()) if key.startswith("CARGO_PROFILE_")},
            "rustflags": os.environ.get("RUSTFLAGS"), "target_features": features, "native_build": pins}


def identity_gaps(record, digest, revision):
    """Why `record` cannot bind the inspected executable whose sha256 is `digest` to the judged `revision`."""
    if not isinstance(record, dict):
        return ["no identity"]
    gaps = [f"the identity lacks {field}" for field in IDENTITY_FIELDS if record.get(field) in (None, "", [], {})]
    if record.get("revision") != revision:
        gaps.append(f"the identity binds revision {record.get('revision')!r}, the judgment is for {revision!r}")
    profile = record.get("cargo_profile") or {}
    if record.get("profile") != "release" or profile.get("opt_level") != "3" or profile.get("debug_assertions") is not False:
        gaps.append(f"profile {record.get('profile')!r} with {profile!r}, not the release profile "
                    "(opt_level 3, debug_assertions off)")
    if record.get("lto") != "false" or (record.get("profile_env") or {}).get("CARGO_PROFILE_RELEASE_LTO") != "false":
        gaps.append(f"the identity binds LTO {record.get('lto')!r} under {record.get('profile_env')!r}; "
                    "the procedure pins CARGO_PROFILE_RELEASE_LTO=false")
    if record.get("sha256") != digest:
        gaps.append(f"the identity binds sha256 {record.get('sha256')}, the executable is {digest}")
    return gaps


def load_declaration(path):
    """The declaration's sites, callees and callers: sites with distinct symbols, each expecting `pass` or `control`,
    at least one of each, every control naming the falsifier it flags, each callee's argument count, and the
    caller tests the lane runs, each once."""
    try:
        declaration = json.loads(Path(path).read_text())
        sites, callees, callers = declaration["sites"], declaration["callees"], declaration["callers"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Refusal(f"unreadable declaration {path}: {error}") from error
    if not isinstance(sites, list) or not sites:
        raise Refusal("the declaration names no sites")
    for site in sites:
        if not isinstance(site, dict) or not all(isinstance(site.get(key), str) and site[key] for key in ("site", "symbol")):
            raise Refusal(f"a site without a name and symbol: {site!r}")
        if site.get("expect") not in ("pass", "control"):
            raise Refusal(f"site {site['site']} expects {site.get('expect')!r}, not pass or control")
        if (site["expect"] == "control") != isinstance(site.get("flags"), str):
            raise Refusal(f"site {site['site']}: a control, and only a control, names the falsifier it flags")
    if len({site["symbol"] for site in sites}) != len(sites):
        raise Refusal("two sites share a symbol")
    if len({site["site"] for site in sites}) != len(sites):
        raise Refusal("two sites share a name")
    if {site["expect"] for site in sites} != {"pass", "control"}:
        raise Refusal("the declaration needs a pass site and a control site")
    if not isinstance(callees, dict) or not all(isinstance(count, int) and count >= 0 for count in callees.values()):
        raise Refusal("callees must map each callee to its argument count")
    if (not isinstance(callers, list) or not callers or len(set(callers)) != len(callers)
            or not all(isinstance(name, str) and name for name in callers)):
        raise Refusal("callers must list each declared caller test once")
    return {"sites": sites, "callees": callees, "callers": callers}


def callers_gaps(evidence, callers):
    """Why the recorded callers' run under `evidence` does not show every declared caller passing once."""
    try:
        code = (evidence / "exit.txt").read_text().strip()
        output = (evidence / "callers.txt").read_text()
    except OSError as error:
        return [f"no recorded callers' run: {error}"]
    gaps = [] if code == "0" else [f"the callers exited {code}"]
    gaps += [f"no ok line for {name}" for name in callers
             if not re.search(rf"^test {re.escape(name)} \.\.\. ok$", output, re.M)]
    if not re.search(rf"^test result: ok\. {len(callers)} passed; 0 failed; 0 ignored;", output, re.M):
        gaps.append(f"the callers' run does not report {len(callers)} passed, 0 failed, 0 ignored")
    return gaps


# Each register holds one dependency set per byte.
X86_ALIASES = {}
for name in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp"):
    X86_ALIASES.update({name: (name, 8), "e" + name[1:]: (name, 4), name[1:]: (name, 2)})
for name, low in (("rax", "al"), ("rbx", "bl"), ("rcx", "cl"), ("rdx", "dl"), ("rsi", "sil"), ("rdi", "dil"),
                  ("rbp", "bpl"), ("rsp", "spl")):
    X86_ALIASES[low] = (name, 1)
for number in range(8, 16):
    X86_ALIASES.update({f"r{number}": (f"r{number}", 8), f"r{number}d": (f"r{number}", 4),
                        f"r{number}w": (f"r{number}", 2), f"r{number}b": (f"r{number}", 1)})
for number in range(16):
    X86_ALIASES[f"xmm{number}"] = (f"xmm{number}", 16)
X86_ARGS, X86_CALL_ARGS = ("rdi", "rsi"), ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
X86_CLOBBERED = ("rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", *(f"xmm{n}" for n in range(16)))
A64_ARGS, A64_CALL_ARGS = ("x0", "x1"), tuple(f"x{n}" for n in range(8))
A64_CLOBBERED = (*(f"x{n}" for n in range(19)), "x30", *(f"v{n}" for n in range(8)), *(f"v{n}" for n in range(16, 32)))
A64_WIDTH = {"x": 8, "w": 4, "q": 16, "d": 8, "s": 4, "h": 2, "b": 1, "v": 16}
A64_LANE = re.compile(r"v\d+\.([bhsd])\[(\d+)\]")
# Calls keep the low eight bytes of these registers and may replace the upper eight.
A64_HALF_KEPT = tuple(f"v{n}" for n in range(8, 16))


def element(operand):
    """The byte size of a vector arrangement's or scalar register's element, such as 8 for `v0.2d` and `d0`."""
    match = re.fullmatch(r"v\d+\.\d*([bhsd])|([bhsd])\d+", operand.strip().lower())
    return A64_WIDTH[match.group(1) or match.group(2)] if match else 1


def lane(operand):
    """(first byte, byte count) of the lane an AArch64 vector lane operand such as `v0.b[3]` names, or None."""
    match = A64_LANE.fullmatch(operand.strip().lower())
    if not match:
        return None
    size = A64_WIDTH[match.group(1)]
    return int(match.group(2)) * size, size


def register(arch, text):
    """(canonical name, width in bytes) of a register operand, ("zero", width) for a zero register, or None."""
    text = text.strip().lower()
    if arch == "x86-64":
        return X86_ALIASES.get(text)
    text, _, arrangement = text.partition(".")
    if text in ("sp", "wsp"):
        return ("sp", 8)
    if text in ("xzr", "wzr"):
        return ("zero", 8 if text == "xzr" else 4)
    if text in ("fp", "lr"):
        return ({"fp": "x29", "lr": "x30"}[text], 8)
    match = re.fullmatch(r"([xwqdshbv])(\d+)", text)
    if not match:
        return None
    kind, number = match.groups()
    shape = re.fullmatch(r"(\d+)([bhsd])", arrangement)
    width = int(shape.group(1)) * A64_WIDTH[shape.group(2)] if kind == "v" and shape else A64_WIDTH[kind]
    return (f"{'x' if kind in 'xw' else 'v'}{number}", width)


def split_operands(text):
    parts, depth, current = [], 0, ""
    for char in text:
        depth += (char == "[") - (char == "]")
        if char == "," and depth == 0:
            parts.append(current.strip())
            current = ""
        else:
            current += char
    if current.strip():
        parts.append(current.strip())
    return parts


def immediate(text):
    try:
        return int(text.strip().lstrip("#"), 0)
    except ValueError:
        return None


def signed(text, negative):
    """The immediate `text` names, negated when `negative`; an operand that names none refuses the site."""
    value = immediate(text)
    if value is None:
        raise Refusal(f"an operand {text!r} that names no immediate")
    return -value if negative else value


def locate(pointer, disp):
    """`pointer` moved by `disp` bytes; a read-only-data or selected location and an untracked pointer stay as given."""
    if pointer is None or pointer[0] in ("const", "selected"):
        return pointer
    return (*pointer[:-1], pointer[-1] + disp)


def memory(arch, operand):
    """Whether an operand names a memory location; an AArch64 vector lane such as `v0.b[0]` also carries brackets."""
    return operand.startswith("[") if arch == "aarch64" else "[" in operand


def union(values):
    out = NONE
    for value in values:
        out |= value
    return out


def masked(values, constant, fixed):
    """`values` with the bytes an immediate mask fixes dropped: a mask byte equal to `fixed` (0 for `and`/`test`,
    0xff for `or`) determines that byte of the result, so its dependency ends there."""
    width = len(values)
    mask = (constant & ((1 << 8 * width) - 1)).to_bytes(width, "little")
    return [value if mask[k] != fixed else NONE for k, value in enumerate(values)]


class Machine:
    """The dependency state of one extent's instructions taken in address order. `pointer` maps a register
    holding an address to ("arg", input, offset), ("stack", offset from the entry stack pointer) or ("const",),
    a PC-relative address of read-only data. `callees` maps each declared callee to its argument count."""

    def __init__(self, arch, callees=None):
        self.arch, self.regs, self.flags, self.stack, self.pointer = arch, {}, NONE, {}, {}
        self.callees, self.mixed = callees or {}, False
        for index, name in enumerate(X86_ARGS if arch == "x86-64" else A64_ARGS):
            self.pointer[name] = ("arg", index, 0)
        self.pointer["rsp" if arch == "x86-64" else "sp"] = ("stack", 0)

    def fork(self):
        other = Machine.__new__(Machine)
        other.__dict__.update(self.__dict__, regs={name: list(values) for name, values in self.regs.items()},
                              stack=dict(self.stack), pointer=dict(self.pointer))
        return other

    def condition(self):
        """The flags a condition reads; flags an instruction updated in part refuse the site."""
        if self.mixed:
            raise Refusal("a condition on flags an instruction updated in part")
        return self.flags

    def reg(self, operand):
        found = register(self.arch, operand)
        return found[0] if found else None

    def read(self, operand):
        found = register(self.arch, operand)
        if found is None or found[0] == "zero":
            return [NONE] * (found[1] if found else 8)
        values = self.regs.get(found[0]) or [NONE] * 16
        at = lane(operand)
        return values[at[0]:at[0] + at[1]] if at else values[:found[1]]

    def write(self, operand, values):
        """Set a register's byte dependencies and drop its pointer. An x86-64 write narrower than 32 bits and a
        vector lane write keep the other bytes; every other write zeroes them."""
        found = register(self.arch, operand)
        if found is None:
            raise Refusal(f"an unmodeled destination {operand!r}")
        name, width = found
        if name == "zero":
            return
        old = self.regs.get(name) or [NONE] * 16
        at = lane(operand)
        if at:
            start, width = at
            self.regs[name] = old[:start] + (list(values) + [NONE] * 16)[:width] + old[start + width:]
        else:
            merge = self.arch == "x86-64" and width < 4
            self.regs[name] = (list(values) + [NONE] * 16)[:width] + (old[width:] if merge else [NONE] * (16 - width))
        self.pointer.pop(name, None)

    def address(self, operand):
        """The location a memory operand names, the input bytes its address depends on, and its pre-indexed
        writeback as (register, new location). An address that depends on input bytes is ("selected",); an
        index register beside a tracked pointer, or a base the model does not track, refuses the site."""
        inner = operand[operand.index("[") + 1:operand.rindex("]")]
        if self.arch == "x86-64":
            base, disp, depends, index = None, 0, NONE, False
            for sign, term in re.findall(r"([+-]?)\s*([^+-]+)", inner.replace(" ", "")):
                if immediate(term) is not None:
                    disp += signed(term, sign == "-")
                elif term == "rip":
                    base = "rip"
                elif "*" not in term and base is None and self.reg(term) in self.pointer:
                    base = self.reg(term)
                else:
                    named = [part for part in term.split("*") if register(self.arch, part)]
                    if len(named) != 1:
                        raise Refusal(f"an address term {term!r} the model does not read")
                    depends |= union(self.read(named[0]))
                    index = True
            pointer, writeback = ("const",) if base == "rip" else self.pointer.get(base), None
        else:
            parts = [part.strip() for part in inner.split(",")]
            base, disp, depends, index = self.reg(parts[0]), 0, NONE, False
            for part in parts[1:]:
                if immediate(part) is not None:
                    disp = immediate(part)
                elif self.reg(part.split()[0]):
                    depends |= union(self.read(part.split()[0]))
                    index = True
            if base not in self.pointer:
                depends |= union(self.read(parts[0]))
            pointer = self.pointer.get(base)
            writeback = (base, locate(pointer, disp)) if operand.endswith("!") and pointer else None
        if depends:
            return ("selected",), depends, None
        if pointer is None or (index and pointer[0] != "const"):
            raise Refusal(f"a memory access {operand!r} at an address the model does not track")
        return locate(pointer, disp), depends, writeback

    def load(self, location, width, depends=NONE):
        if location[0] == "const":
            return [NONE] * width
        if location[0] == "selected":
            return [depends] * width
        if location[0] == "arg":
            _, which, offset = location
            return [frozenset({(which, offset + k)}) if 0 <= offset + k < TAG_LEN else NONE for k in range(width)]
        return [self.stack.get(location[1] + k, NONE) for k in range(width)]

    def store(self, location, values):
        """Record stack bytes; a store through an argument pointer, or of input bytes to any other non-stack,
        non-selected location, refuses the site."""
        if location[0] == "stack":
            for k, value in enumerate(values):
                self.stack[location[1] + k] = value
        elif location[0] == "arg":
            raise Refusal("a store through an argument pointer, which the model does not follow")
        elif location[0] != "selected" and union(values):
            raise Refusal("a store of input bytes outside the stack")

    def source(self, operand, width):
        if "[" in operand:
            location, depends, _ = self.address(operand)
            return self.load(location, width, depends)
        if register(self.arch, operand) is None:
            if immediate(operand) is None:
                raise Refusal(f"an unmodeled operand {operand!r}")
            return [NONE] * width
        return self.read(operand)

    def stored(self, operand, width):
        """The bytes a store writes from `operand`; a tracked pointer, which the model does not follow through
        memory, refuses the site."""
        if self.reg(operand) in self.pointer:
            raise Refusal(f"a store of {operand}, a tracked pointer the model does not follow through memory")
        return self.source(operand, width)

    def width(self, operand, default=8):
        found = register(self.arch, operand)
        if found:
            return found[1]
        for word, size in (("xmmword", 16), ("qword", 8), ("dword", 4), ("word", 2), ("byte", 1)):
            if operand.startswith(word):
                return size
        return default

    def call(self, callee, arguments, clobbered, result):
        """A direct call to a declared callee: its result carries the bytes of the arguments it takes."""
        name = next((known for known in self.callees if callee == known or (callee or "").startswith(known + "::<")), None)
        if name is None:
            raise Refusal(f"a call to {callee or 'an indirect target'}, whose argument count the declaration does not name")
        taken = arguments[:self.callees[name]]
        if any(register in self.pointer for register in taken):
            raise Refusal(f"a call to {callee} through a pointer the model does not follow into the callee")
        depends = union(union(self.read(register)) for register in taken)
        for name in clobbered:
            self.regs.pop(name, None)
            self.pointer.pop(name, None)
        for name in A64_HALF_KEPT if self.arch == "aarch64" else ():
            if name in self.regs:
                self.regs[name][8:] = [NONE] * 8
        self.regs[result] = [depends] * 8 + [NONE] * 8
        self.flags = NONE


def describe(depends):
    """The input bytes a dependency names, as `tag[a-b] expected[c-d]`."""
    out = []
    for which, name in enumerate(INPUTS):
        runs = []
        for at in sorted(at for kind, at in depends if kind == which):
            if runs and runs[-1][1] == at - 1:
                runs[-1][1] = at
            else:
                runs.append([at, at])
        if runs:
            out.append(f"{name}[{','.join(str(a) if a == b else f'{a}-{b}' for a, b in runs)}]")
    return " ".join(out)


X86_CC = r"(o|no|b|nb|ae|nae|c|nc|e|z|ne|nz|be|nbe|a|na|s|ns|p|np|pe|po|l|nl|ge|nge|le|nle|g|ng)"
X86_MOVES = {"mov", "movzx", "movsx", "movsxd", "movq", "movd", "movdqu", "movdqa", "movups", "movaps", "lddqu"}
X86_BITWISE = {"xor", "or", "and", "not", "pxor", "por", "pand", "pandn", "xorps", "orps", "andps", "andnps", "pcmpeqb"}
X86_SPREAD = {"add", "sub", "adc", "sbb", "neg", "inc", "dec", "imul", "shl", "shr", "sar", "rol", "ror",
              "bswap", "popcnt", "lzcnt", "tzcnt", "bsf", "bsr", "pmovmskb", "pshufb", "psrldq", "pslldq",
              "punpcklqdq", "punpckhqdq"}
X86_FLAGS_ONLY = {"cmp", "test", "ptest"}
X86_OVERWRITE = {"popcnt", "lzcnt", "tzcnt"}
# Self-combinations produce constant bytes: zero for `xor`, `sub`, `pxor`, `xorps`, `pandn` and `andnps`, all ones for
# `pcmpeqb`.
X86_ZERO_IDIOMS = {"xor", "sub", "pxor", "xorps", "pcmpeqb", "pandn", "andnps"}
# Instructions that update the flags in part: `inc` and `dec` keep CF, a shift by `cl` keeps every flag at a
# zero count, a rotate writes only CF and OF, and `bt` writes only CF.
X86_PART_FLAGS = {"inc", "dec", "shl", "shr", "sar", "rol", "ror", "bt"}
# Instructions that leave the flags as they were.
X86_KEEP_FLAGS = {"not", "bswap", "pxor", "por", "pand", "pandn", "xorps", "orps", "andps", "andnps", "pcmpeqb",
                  "pmovmskb", "pshufb", "psrldq", "pslldq", "punpcklqdq", "punpckhqdq"}
X86_NEUTRAL = {"nop", "endbr64", "int3", "ud2", "hlt", "ret"}
# Traps end their path.
X86_TRAPS, A64_TRAPS = {"ud2", "int3", "hlt"}, {"udf", "brk"}
A64_BITWISE = {"and", "orr", "eor", "bic", "orn", "eon", "ands", "bics", "mvn", "cmeq"}
A64_SPREAD = {"add", "sub", "adds", "subs", "neg", "negs", "adc", "adcs", "sbc", "sbcs", "ngc", "ngcs", "mul",
              "madd", "msub", "umulh", "smulh", "lsl", "lsr", "asr", "ror", "ubfx", "sbfx", "ubfiz", "sbfiz", "bfi",
              "bfxil", "extr", "uxtb", "uxth", "sxtb", "sxth", "sxtw", "rev", "rev16", "rev32", "rbit", "clz", "cls",
              "cnt", "addv", "umaxv", "uminv", "uaddlv", "fmov", "dup", "ins", "umov", "ext"}
A64_CARRY = {"adc", "adcs", "sbc", "sbcs", "ngc", "ngcs"}
# Bitfield inserts replace one field of the destination and keep its other bits, so the destination is a source.
A64_INSERTS = {"bfi", "bfxil"}
# Self-combinations produce constant bytes: zero for `eor`, `sub`, `subs`, `bic` and `bics`, all ones for `cmeq`,
# `eon` and `orn`.
A64_ZERO_IDIOMS = {"eor", "sub", "subs", "bic", "bics", "cmeq", "eon", "orn"}
A64_FLAGS = {"adds", "subs", "negs", "adcs", "sbcs", "ngcs", "ands", "bics"}
A64_SELECTS = {"csel", "csinc", "csinv", "csneg", "cset", "csetm", "cinc", "cinv", "cneg", "fcsel"}
# The `al` and `nv` conditions hold on every flag state, so these branches are unconditional.
A64_ALWAYS = {"b.al", "b.nv"}
A64_NEUTRAL = {"nop", "hint", "bti", "paciasp", "autiasp", "pacibsp", "autibsp", "prfm", "dmb", "dsb", "isb",
               "udf", "brk"}


def x86(machine, mnemonic, ops, acts, callee):
    """Apply one x86-64 instruction, appending each (kind, dependency) it acts on to `acts`."""
    if mnemonic in X86_NEUTRAL:
        return
    if mnemonic in ("jmp", "call"):
        target = union(machine.source(ops[0], 8)) if callee is None and immediate(ops[0]) is None else NONE
        if target:
            acts.append(("branch", target))
        if mnemonic == "call" or callee is not None:
            machine.call(callee, X86_CALL_ARGS, X86_CLOBBERED, "rax")
        return
    if mnemonic == "push":
        machine.pointer["rsp"] = locate(machine.pointer["rsp"], -8)
        machine.store(machine.pointer["rsp"], machine.stored(ops[0], 8))
        return
    if mnemonic == "pop":
        machine.write(ops[0], machine.load(machine.pointer["rsp"], 8))
        machine.pointer["rsp"] = locate(machine.pointer["rsp"], 8)
        return
    if re.fullmatch("j" + X86_CC, mnemonic):
        acts.append(("branch", machine.condition()))
        return
    destination = ops[0] if ops else ""
    width = machine.width(destination)
    if re.fullmatch("(set|cmov)" + X86_CC, mnemonic):
        acts.append(("select", machine.condition()))
        moved = machine.read(destination) + machine.source(ops[1], width) if len(ops) > 1 else []
        machine.write(destination, [union(moved) | machine.flags] * width)
        return
    if mnemonic == "lea":
        # `lea` writes the computed address to the destination, so its input bytes become the destination's data.
        location, depends, _ = machine.address(ops[1])
        acts[:] = [act for act in acts if act[0] != "address"]
        machine.write(destination, [depends] * width)
        if location is not None and not depends and width == 8:
            machine.pointer[machine.reg(destination)] = location
        return
    if mnemonic in X86_MOVES:
        size = machine.width(ops[1], width) if mnemonic.startswith("movs") or mnemonic == "movzx" else min(width, machine.width(ops[1], width))
        if mnemonic == "movq":
            size = min(size, 8)
        if "[" in destination:
            machine.store(machine.address(destination)[0], machine.stored(ops[1], size)[:size])
            return
        values = machine.source(ops[1], size)[:size]
        if mnemonic.startswith("movs"):
            values = values + [values[-1]] * (width - size)
        pointer = machine.pointer.get(machine.reg(ops[1]))
        machine.write(destination, values)
        if pointer is not None and width == 8:
            machine.pointer[machine.reg(destination)] = pointer
        return
    if mnemonic == "pshufd":
        old, order = machine.source(ops[1], 16), signed(ops[2], False)
        machine.write(destination, [old[4 * ((order >> (2 * (k // 4))) & 3) + k % 4] for k in range(16)])
        return
    if mnemonic in ("psrldq", "pslldq"):
        old, count = machine.read(destination), min(signed(ops[1], False), 16)
        machine.write(destination, old[count:] + [NONE] * count if mnemonic == "psrldq" else [NONE] * count + old[:16 - count])
        return
    if mnemonic in ("punpcklqdq", "punpckhqdq"):
        half = slice(0, 8) if mnemonic == "punpcklqdq" else slice(8, 16)
        machine.write(destination, machine.read(destination)[half] + machine.source(ops[1], 16)[half])
        return
    if mnemonic == "pmovmskb":
        # Each result byte holds the sign bits of one eight-byte half of the source; the upper bytes are zero.
        bits = machine.source(ops[1], 16)
        machine.write(destination, [union(bits[:8]), union(bits[8:16])] + [NONE] * (width - 2))
        return
    if mnemonic == "imul" and len(ops) == 1:
        # One-operand `imul` multiplies the accumulator by its operand into `ax` for a byte operand, else into
        # `dx:ax`, `edx:eax` or `rdx:rax`.
        size = machine.width(ops[0])
        product = union(machine.read("rax")[:size] + machine.source(ops[0], size))
        machine.write({1: "ax", 2: "ax", 4: "eax", 8: "rax"}[size], [product] * max(size, 2))
        if size > 1:
            machine.write({2: "dx", 4: "edx", 8: "rdx"}[size], [product] * size)
        machine.flags, machine.mixed = product, False
        return
    if mnemonic in X86_ZERO_IDIOMS and len(ops) == 2 and ops[0] == ops[1]:
        machine.write(destination, [NONE] * width)
        if mnemonic in ("xor", "sub"):
            machine.flags, machine.mixed = NONE, False
        return
    overwrite = mnemonic in X86_OVERWRITE or (mnemonic == "imul" and len(ops) == 3)
    left = [NONE] * width if overwrite else machine.source(destination, width)
    right = machine.source(ops[1], width) if len(ops) > 1 else [NONE] * width
    if mnemonic in ("and", "or", "test") and len(ops) == 2 and immediate(ops[1]) is not None:
        left = masked(left, immediate(ops[1]), 0xff if mnemonic == "or" else 0)
    if mnemonic in X86_FLAGS_ONLY:
        same = mnemonic == "cmp" and ops[0] == ops[1]
        machine.flags, machine.mixed = NONE if same else union(left + right), False
        return
    if mnemonic == "bswap":
        machine.write(destination, left[::-1])
        return
    if mnemonic == "bt":
        bit = immediate(ops[1])
        tested = left[bit % (8 * width) // 8] if bit is not None else union(left + right)
        machine.mixed = machine.mixed or machine.flags != tested
        machine.flags = tested
        return
    if mnemonic in X86_BITWISE:
        values = [left[k] | right[k] for k in range(width)]
    elif mnemonic in X86_SPREAD:
        values = [union(left + right) | (machine.condition() if mnemonic in ("adc", "sbb") else NONE)] * width
        if mnemonic in X86_OVERWRITE:
            # A bit count fits one byte; the upper bytes are constant.
            values = values[:1] + [NONE] * (width - 1)
    else:
        raise Refusal(f"an unmodeled instruction {mnemonic} {', '.join(ops)}")
    pointer = machine.pointer.get(machine.reg(destination))
    if mnemonic in X86_PART_FLAGS:
        machine.mixed = machine.mixed or machine.flags != union(values)
        machine.flags = union(values)
    elif mnemonic not in X86_KEEP_FLAGS:
        machine.flags, machine.mixed = union(values), False
    if "[" in destination:
        machine.store(machine.address(destination)[0], values)
    else:
        machine.write(destination, values)
    if pointer is not None and mnemonic in ("add", "sub") and immediate(ops[1]) is not None and width == 8:
        machine.pointer[machine.reg(destination)] = locate(pointer, signed(ops[1], mnemonic == "sub"))


def a64(machine, mnemonic, ops, acts, callee):
    """Apply one AArch64 instruction, appending each (kind, dependency) it acts on to `acts`."""
    base = mnemonic.split(".")[0]
    if base == "mov" and any("[" in op for op in ops):
        # A lane move is an insert into a vector lane or an extract from one.
        base = "ins" if "[" in ops[0] else "umov"
    if base == "b" and "." in mnemonic and mnemonic not in A64_ALWAYS:
        acts.append(("branch", machine.condition()))
        return
    if base == "b":
        if callee is not None:
            machine.call(callee, A64_CALL_ARGS, A64_CLOBBERED, "x0")
        return
    if base in ("cbz", "cbnz"):
        acts.append(("branch", union(machine.read(ops[0]))))
        return
    if base in ("tbz", "tbnz"):
        acts.append(("branch", machine.read(ops[0])[signed(ops[1], False) // 8]))
        return
    if base == "ret":
        if ops and machine.reg(ops[0]) != "x30":
            raise Refusal(f"a return through {ops[0]}, an indirect transfer the walk does not follow")
        return
    if base in A64_NEUTRAL:
        return
    if base in ("br", "blr", "bl"):
        target = union(machine.read(ops[0])) if base != "bl" else NONE
        if target:
            acts.append(("branch", target))
        if base != "br":
            machine.call(callee if base == "bl" else None, A64_CALL_ARGS, A64_CLOBBERED, "x0")
        return
    if base.startswith(("ld", "st")):
        memory_access(machine, base, ops)
        return
    if base in ("ccmp", "ccmn"):
        compared = union(machine.read(ops[0]) + machine.source(ops[1], 8))
        if ops[-1].strip().lower() in ("al", "nv"):
            machine.flags = compared
            return
        acts.append(("select", machine.condition()))
        machine.flags |= compared
        return
    destination, width = ops[0], machine.width(ops[0])
    if base in A64_SELECTS:
        # The `al` and `nv` conditions hold for every flag state, so these selects depend on their register
        # operands alone.
        always = ops[-1].strip().lower() in ("al", "nv")
        if not always:
            acts.append(("select", machine.condition()))
        moved = [machine.read(ops[1])] if always else [machine.read(op) for op in ops[1:] if register(machine.arch, op)]
        machine.write(destination, [union(sum(moved, [])) | (NONE if always else machine.flags)] * width)
        return
    if base in ("cmp", "cmn", "tst"):
        same = base == "cmp" and len(ops) == 2 and ops[0] == ops[1]
        tested = machine.read(ops[0])
        if base == "tst" and immediate(ops[1]) is not None:
            tested = masked(tested, immediate(ops[1]), 0)
        machine.flags = NONE if same else union(tested + machine.source(ops[1], 8))
        return
    if base in ("adr", "adrp"):
        machine.write(destination, [NONE] * width)
        machine.pointer[machine.reg(destination)] = ("const",)
        return
    if base == "movk":
        # `movk` replaces one halfword with its immediate and keeps the other bytes.
        values = machine.read(destination)
        at = signed(ops[2].split()[-1], False) // 8 if len(ops) > 2 else 0
        values[at:at + 2] = [NONE, NONE]
        machine.write(destination, values)
        return
    if base in ("mov", "movz", "movn"):
        moved = len(ops) > 1 and register(machine.arch, ops[1]) is not None
        pointer = machine.pointer.get(machine.reg(ops[1])) if moved else None
        machine.write(destination, machine.read(ops[1])[:width] if moved else [NONE] * width)
        if pointer is not None and width == 8:
            machine.pointer[machine.reg(destination)] = pointer
        return
    if (base in ("add", "sub") and len(ops) == 3 and machine.reg(ops[1]) in machine.pointer
            and immediate(ops[2]) is not None and width == 8):
        pointer = machine.pointer[machine.reg(ops[1])]
        machine.write(destination, [NONE] * width)
        machine.pointer[machine.reg(destination)] = locate(pointer, signed(ops[2], base == "sub"))
        return
    if base in A64_ZERO_IDIOMS and len(ops) == 3 and ops[1] == ops[2]:
        machine.write(destination, [NONE] * width)
        if base in A64_FLAGS:
            machine.flags = NONE
        return
    sources = [machine.read(op) for op in ops[1:] if register(machine.arch, op)]
    if base in ("and", "ands", "orr") and len(ops) == 3 and immediate(ops[2]) is not None and machine.reg(destination)[0] == "x":
        sources = [masked(sources[0], immediate(ops[2]), 0xff if base == "orr" else 0)]
    vector = machine.reg(destination)[0] == "v"
    if base in ("rev", "rev16", "rev32", "rev64", "rbit"):
        # Elements of the arrangement's size reverse within each group; a vector `rbit` keeps every byte in place.
        old = (sources[0] + [NONE] * 16)[:width]
        size = element(destination) if vector else 1
        group = {"rev16": 2, "rev32": 4, "rev64": 8}.get(base, 1 if vector else len(old))
        machine.write(destination, [old[k - k % group + (group // size - 1 - k % group // size) * size + k % size]
                                    for k in range(len(old))])
        return
    if base in ("fmov", "umov", "ins"):
        # Register moves keep byte positions; an immediate `fmov` writes a constant.
        machine.write(destination, ((sources[0] if sources else []) + [NONE] * 16)[:width])
        return
    if base == "dup":
        size = element(destination)
        machine.write(destination, (sources[0] + [NONE] * 16)[:size] * (width // size))
        return
    if base == "extr":
        # `extr` takes `width` bytes of the concatenation (second source low, first source high) from the bit
        # offset; an unaligned offset makes each byte depend on the two source bytes it straddles.
        joined = (sources[1] + [NONE] * 16)[:width] + (sources[0] + [NONE] * 16)[:width]
        lsb = signed(ops[3], False)
        machine.write(destination, [joined[(lsb + 8 * k) // 8] | joined[(lsb + 8 * k + 7) // 8] for k in range(width)])
        return
    if base in A64_INSERTS:
        # Bitfield inserts modify the destination in place.
        sources.append(machine.read(destination))
    constant = immediate(ops[1]) if base in ("orr", "bic") and len(ops) > 1 else None
    if constant is not None:
        # A vector immediate modifies the destination in place; its bits, tiled over the elements, fix every byte
        # they fill (`orr` sets it, `bic` clears it).
        size = element(destination)
        shift = signed(ops[2].split()[-1], False) if len(ops) > 2 else 0
        pattern = ((constant << shift) & ((1 << 8 * size) - 1)).to_bytes(size, "little")
        sources = [masked(machine.read(destination), int.from_bytes(pattern * (width // size), "little"), 0xff)]
    if base in ("clz", "cls", "cnt") and not vector:
        # A bit count fits one byte; the upper bytes are constant.
        machine.write(destination, [union(sum(sources, []))] + [NONE] * (width - 1))
        return
    if base == "ext":
        # `ext` is a byte permutation: each destination byte keeps the dependency of the source byte it takes.
        half = 8 if destination.lower().endswith(".8b") else 16
        joined = (sources[0] + [NONE] * 16)[:half] + (sources[1] + [NONE] * 16)[:half]
        machine.write(destination, joined[signed(ops[3], False):][:half])
        return
    shifted = any(re.match(r"(lsl|lsr|asr|ror|uxt|sxt)", op) for op in ops[2:]) and immediate(ops[1] if len(ops) > 1 else "") is None
    if base in ("uxtb", "uxth", "sxtb", "sxth", "sxtw"):
        size = {"b": 1, "h": 2, "w": 4}[base[-1]]
        low = (sources[0] + [NONE] * 16)[:size]
        machine.write(destination, low + [low[-1] if base[0] == "s" else NONE] * (width - size))
        return
    if (base in A64_BITWISE or (base == "cnt" and vector)) and not shifted and sources:
        rows = [(row + [NONE] * 16)[:width] for row in sources]
        # A compare of lanes wider than a byte makes every byte of a lane depend on the whole lane.
        size = element(destination) if base == "cmeq" else 1
        values = [union(row[j] for row in rows for j in range(k - k % size, k - k % size + size)) for k in range(width)]
    elif base in A64_SPREAD or base in A64_BITWISE:
        values = [union(sum(sources, [])) | (machine.condition() if base in A64_CARRY else NONE)] * width
    else:
        raise Refusal(f"an unmodeled instruction {mnemonic} {', '.join(ops)}")
    if base in A64_FLAGS:
        machine.flags = union(values)
    machine.write(destination, values)


def memory_access(machine, base, ops):
    """An AArch64 load or store, single or paired, with pre- and post-indexed writeback."""
    where = next(index for index, op in enumerate(ops) if memory(machine.arch, op))
    registers, operand = ops[:where], ops[where]
    post = immediate(ops[where + 1]) if len(ops) > where + 1 else None
    location, depends, writeback = machine.address(operand)
    form = re.fullmatch(r"(ld|st)(?:a|l)?x?(r|ur|p|np)(s?)([bhw]?)", base)
    if form is None:
        raise Refusal(f"an unmodeled memory access {base} {', '.join(ops)}")
    extend, size = form.group(3) == "s", {"b": 1, "h": 2, "w": 4}.get(form.group(4), 0)
    if re.fullmatch(r"st[al]?x[rp][bhw]?", base):
        # An exclusive store writes its status to its first register; the status bytes carry an empty dependency.
        machine.write(registers[0], [NONE] * 4)
        registers = registers[1:]
    for index, reg in enumerate(registers):
        width = size or machine.width(reg)
        at = locate(location, index * width)
        if base.startswith("ld"):
            values = machine.load(at, width, depends)
            if extend:
                values = values + [values[-1]] * (machine.width(reg) - width)
            machine.write(reg, values)
        else:
            machine.store(at, machine.stored(reg, width)[:width])
    target = machine.reg(operand[operand.index("[") + 1:].split(",")[0].rstrip("]!"))
    if writeback:
        machine.pointer[writeback[0]] = writeback[1]
    elif post is not None and target in machine.pointer:
        machine.pointer[target] = locate(machine.pointer[target], post)


LINE = re.compile(r"^\s*([0-9a-f]+):\s+([a-z][a-z0-9.]*)\s*(.*?)\s*$")
# `ADDRESSED` matches decoded instructions and undecoded words alike, so `parse` refuses the undecoded ones.
ADDRESSED = re.compile(r"^\s*[0-9a-f]+:\s")
PATHS = 4096
X86_BRANCHES = re.compile("j" + X86_CC)


def parse(arch, text):
    """Each instruction as (address, mnemonic, text, operands, callee, target): `callee` names a symbol the
    instruction transfers to outside its own function, `target` the address a direct branch or call names."""
    program = []
    for line in text.splitlines():
        match = LINE.match(line)
        if not match:
            if ADDRESSED.match(line) or line.strip() == "...":
                raise Refusal(f"an undecoded instruction {line.strip()!r}")
            continue
        address, mnemonic, rest = match.groups()
        named = re.search(r"\s<(.+)>\s*$", rest)
        callee = named.group(1) if named and not re.search(r"\+0x[0-9a-f]+$", named.group(1)) else None
        rest = re.sub(r"\s*//.*$" if arch == "aarch64" else r"\s*#.*$", "", re.sub(r"\s<.+>\s*$", "", rest))
        operands = split_operands(rest)
        target = immediate(operands[-1]) if named and operands else None
        moves = transfer(arch, mnemonic) in ("conditional", "jump") or mnemonic in ("bl", "call")
        if moves and not named and operands and immediate(operands[-1]) is not None:
            raise Refusal(f"a transfer at 0x{address} to {operands[-1]}, which names no symbol")
        program.append((int(address, 16), mnemonic, f"{mnemonic} {rest}".strip(), operands, callee, target))
    return program


def transfer(arch, mnemonic):
    """How an instruction moves control: "conditional", "jump", "return" for a return or a trap, both of which end
    the path, or None for the next instruction."""
    if arch == "x86-64":
        if X86_BRANCHES.fullmatch(mnemonic):
            return "conditional"
        return "return" if mnemonic in X86_TRAPS else {"jmp": "jump", "ret": "return"}.get(mnemonic)
    if mnemonic in A64_ALWAYS:
        return "jump"
    if mnemonic.startswith("b.") or mnemonic in ("cbz", "cbnz", "tbz", "tbnz"):
        return "conditional"
    return "return" if mnemonic in A64_TRAPS else {"b": "jump", "br": "jump", "ret": "return"}.get(mnemonic)


def judge_extent(arch, text, callees):
    """The annotated extent of one site's disassembly and its verdict, judged over every path through it;
    `callees` maps each callee the extent may call to its argument count."""
    program = parse(arch, text)
    if not program:
        raise Refusal("the extent holds no instruction")
    at = {address: index for index, (address, *_) in enumerate(program)}
    notes = [{"data": NONE, "depends": NONE, "roles": set()} for _ in program]
    calls, decisions, undecided, paths = set(), set(), 0, 0
    pending = [(Machine(arch, callees), 0, 0)]
    while pending:
        machine, index, decided = pending.pop()
        while index is not None:
            if index >= len(program):
                raise Refusal("a path runs past the end of the extent")
            address, mnemonic, instruction, operands, callee, target = program[index]
            moves = transfer(arch, mnemonic)
            inside = target is not None and callee is None and moves in ("conditional", "jump")
            if moves in ("conditional", "jump") and target is None:
                raise Refusal(f"an indirect transfer at {address:#x}, whose target the walk does not follow")
            if inside and target not in at:
                raise Refusal(f"a branch at {address:#x} to {target:#x}, which no instruction of the extent starts")
            if inside and target <= address:
                raise Refusal(f"a backward branch at {address:#x}, a loop the walk does not model")
            if callee is not None and (mnemonic in ("bl", "call") or moves is not None):
                calls.add(callee)
            acts = [("address", depends) for op in operands if memory(arch, op) and mnemonic != "nop"
                    for depends in [machine.address(op)[1]] if depends]
            tail = callee if moves == "conditional" else None
            (x86 if arch == "x86-64" else a64)(machine, mnemonic, operands, acts,
                                               None if inside or tail else callee)
            note = notes[index]
            if operands and register(arch, operands[0]):
                note["data"] |= union(machine.read(operands[0]))
            elif mnemonic in ("cmp", "cmn", "tst", "test", "ptest"):
                note["data"] |= machine.flags
            for kind, depends in acts:
                if not depends:
                    continue
                note["depends"] |= depends
                if depends != FULL:
                    acted = {"branch": "a branch", "select": "a conditional select"}.get(kind, "a memory address")
                    note["roles"].add(f"falsifier: {acted} on a partial comparison")
                elif kind == "branch":
                    decided += 1
                    note["roles"].add("decision" if decided == 1 else "falsifier: a second decision branch")
                    decisions.add(index)
                else:
                    note["roles"].add("decision value" if kind == "select"
                                      else "falsifier: a memory address selected by the comparison")
            if moves == "conditional":
                if inside:
                    pending.append((machine.fork(), at[target], decided))
                elif tail is not None:
                    taken = machine.fork()
                    taken.call(tail, *((X86_CALL_ARGS, X86_CLOBBERED, "rax") if arch == "x86-64"
                                       else (A64_CALL_ARGS, A64_CLOBBERED, "x0")))
                    paths += 1
                    undecided += decided == 0
                index += 1
            elif moves == "jump":
                index = at[target] if inside else None
            elif moves == "return":
                index = None
            else:
                index += 1
        paths += 1
        undecided += decided == 0
        if paths > PATHS:
            raise Refusal(f"more than {PATHS} paths through the extent")
    extent = []
    for index, (address, _, instruction, *_rest) in enumerate(program):
        note, entry = notes[index], {"address": hex(address), "instruction": instruction}
        if note["data"]:
            entry["data"] = describe(note["data"])
        if note["depends"]:
            entry["depends"] = describe(note["depends"])
        if note["roles"]:
            entry["role"] = "; ".join(sorted(note["roles"]))
        extent.append(entry)
    falsifiers = [entry for entry in extent if "falsifier" in entry.get("role", "")]
    if falsifiers:
        first = falsifiers[0]
        verdict, reason = "flagged", f"{len(falsifiers)} falsifiers, first {first['instruction']} at {first['address']} ({first['role']})"
    elif undecided:
        verdict, reason = "flagged", f"{undecided} of {paths} paths reach no conditional branch on every byte of both inputs"
    else:
        verdict, reason = "pass", None
    return {"verdict": verdict, "reason": reason, "extent": extent, "calls": sorted(calls), "paths": paths,
            "decision": [extent[index]["address"] for index in sorted(decisions)],
            "falsifiers": sorted({role for entry in falsifiers for role in entry["role"].split("; ")
                                  if role.startswith("falsifier")})}


def judge(extents, identity_record, declaration, revision):
    """The report over the recorded extents at `revision`: each site judged and held to its expectation."""
    report = {"identity": identity_record, "limits": LIMITS, "credited": False, "code": REFUSED}
    gaps = identity_gaps(identity_record, extents.get("sha256"), revision)
    if gaps:
        report["reason"] = "; ".join(gaps)
        return report
    arch = extents.get("machine")
    if arch not in MACHINES.values():
        report["reason"] = f"machine {arch!r}"
        return report
    report.update(machine=arch, sha256=extents["sha256"], objdump=extents.get("objdump"), sites=[])
    for site in declaration["sites"]:
        recorded = extents.get("sites", {}).get(site["site"])
        entry = {"site": site["site"], "symbol": site["symbol"], "expect": site["expect"]}
        if not recorded or recorded.get("refused"):
            entry.update(verdict="refused", reason=(recorded or {}).get("refused") or "no recorded extent")
        else:
            entry.update(address=recorded["address"], size=recorded["size"])
            try:
                entry.update(judge_extent(arch, recorded["disassembly"], declaration["callees"]))
            except (Refusal, ValueError, KeyError, IndexError, TypeError, StopIteration) as refusal:
                entry.update(verdict="refused", reason=str(refusal) or type(refusal).__name__)
        entry["met"] = (entry["verdict"] == "pass" if site["expect"] == "pass" else
                        entry["verdict"] == "flagged"
                        and any(site["flags"] in role for role in entry.get("falsifiers", [])))
        report["sites"].append(entry)
    report["credited"] = all(entry["met"] for entry in report["sites"])
    refused = any(entry["verdict"] == "refused" for entry in report["sites"])
    report["code"] = REFUSED if refused else CREDITED if report["credited"] else OFF
    report["reason"] = None if report["credited"] else "; ".join(
        f"{entry['site']} {entry['verdict']}, expected {entry['expect']}: {entry.get('reason')}"
        for entry in report["sites"] if not entry["met"])
    return report


def record_extents(executable, sites, objdump, demangler):
    """Admit the executable and record each site's disassembly, or the reason it was refused."""
    barriers = load_barriers()
    image = Path(executable).read_bytes()
    headers = barriers.sections(image, tuple(MACHINES))
    machine = MACHINES[int.from_bytes(image[18:20], "little")]
    symbols = barriers.functions(image, headers)
    names = barriers.demangle([name for name, *_ in symbols], demangler)
    found = {}
    for index, (_, shndx, value, size) in enumerate(symbols):
        found.setdefault(names[index], []).append((shndx, value, size))
    extents = {"machine": machine, "sha256": hashlib.sha256(image).hexdigest(),
               "objdump": {"command": objdump, "version": barriers.tool_version(objdump)}, "sites": {}}
    for site in sites:
        matches = found.get(site["symbol"], [])
        if len(matches) != 1:
            extents["sites"][site["site"]] = {"refused": f"{len(matches)} function symbols named {site['symbol']}"}
            continue
        shndx, value, size = matches[0]
        section = headers[shndx] if 0 < shndx < len(headers) else None
        if (not size or section is None or section["type"] != barriers.SHT_PROGBITS
                or not section["flags"] & barriers.SHF_EXECINSTR
                or not section["addr"] <= value < value + size <= section["addr"] + section["size"]):
            extents["sites"][site["site"]] = {"refused": "an extent outside one executable PROGBITS section"}
            continue
        syntax = ["--x86-asm-syntax=intel"] if machine == "x86-64" else []
        result = subprocess.run([*objdump, "-d", "-z", "-C", "--no-show-raw-insn", *syntax, f"--start-address={value:#x}",
                                 f"--stop-address={value + size:#x}", str(executable)],
                                capture_output=True, text=True, check=False)
        if result.returncode:
            raise Refusal(f"the disassembler exited {result.returncode}: {result.stderr.strip()[:200]}")
        extents["sites"][site["site"]] = {"address": hex(value), "size": size, "disassembly": result.stdout}
    return extents


def receipt(evidence, revision, report, machine):
    """The lane receipt: hashes of the evidence and committed inputs, and the met sites when the run credits."""
    pins = evidence / "pins.txt"
    names = ("identity.json", "pins.txt", "extents.json", "callers.txt", "exit.txt", "report.json")
    inputs = {name: hashlib.sha256((evidence / name).read_bytes()).hexdigest()
              for name in names if (evidence / name).is_file()}
    for path in (ROOT / "scripts/test-inventory.json", ROOT / "scripts/test-registry.json",
                 ROOT / "verification/obligations.json", DECLARATION, Path(__file__).resolve(),
                 ROOT / "scripts/scan-barriers.py"):
        inputs[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    met = sorted(entry["site"] for entry in report.get("sites", []) if entry.get("met"))
    credited = bool(report.get("credited"))
    job = f"tag-compare-{machine}"
    return {
        "job": job, "module": None, "lane": job, "revision": revision, "inputs": inputs,
        "tool": {"name": "scan-tag-compare",
                 "provenance": pins.read_text().strip().splitlines() if pins.exists() else []},
        "assumptions": LIMITS, "bounds": {"machine": report.get("machine"), "sha256": report.get("sha256")},
        "completion": "completed" if report.get("code") in (CREDITED, OFF) else "tool failure",
        "violation": None, "detail": report.get("reason"),
        "selection": {"credited": credited, "reason": report.get("reason")},
        "executions": len(met) if credited else 0, "executed": met if credited else [], "failed": [],
        "replay": f"bash scripts/rust-lane.sh {job}",
        "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
    }


def derive(evidence, revision):
    """The report and receipt the recorded evidence supports, writing neither."""
    evidence, extents = Path(evidence), {}
    try:
        extents = json.loads((evidence / "extents.json").read_text())
        identity_record = json.loads((evidence / "identity.json").read_text())
        declaration = load_declaration(DECLARATION)
        gaps = callers_gaps(evidence, declaration["callers"])
        if gaps:
            raise Refusal("; ".join(gaps))
        report = judge(extents, identity_record, declaration, revision)
    except (OSError, ValueError, Refusal) as refusal:
        report = {"credited": False, "code": REFUSED, "reason": str(refusal), "limits": LIMITS}
    return report, receipt(evidence, revision, report, extents.get("machine") if isinstance(extents, dict) else None)


def write_judgment(evidence, revision):
    report, derived = derive(evidence, revision)
    (evidence / "report.json").write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    derived["inputs"]["report.json"] = hashlib.sha256((evidence / "report.json").read_bytes()).hexdigest()
    (evidence / "receipt.json").write_text(json.dumps(derived, indent=2, sort_keys=True) + "\n")
    for entry in report.get("sites", []):
        print(f"scan-tag-compare: {entry['site']}: {entry['verdict']}, expected {entry['expect']}"
              + (f" ({entry['reason']})" if entry.get("reason") else ""), file=sys.stderr)
    if report.get("reason"):
        print(f"scan-tag-compare: {report['reason']}", file=sys.stderr)
    return report["code"]


def main(argv=None):
    parser = argparse.ArgumentParser(description="Inspect the linked tag comparison's control flow.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("limits")
    commands.add_parser("select").add_argument("--cargo-json", required=True)
    built = commands.add_parser("identity")
    for flag in ("--cargo-json", "--target-features", "--pins", "--output"):
        built.add_argument(flag, required=True)
    scanned = commands.add_parser("scan")
    scanned.add_argument("--executable", required=True)
    scanned.add_argument("--evidence", required=True)
    scanned.add_argument("--objdump", default="llvm-objdump")
    scanned.add_argument("--demangler", default="llvm-cxxfilt")
    judged = commands.add_parser("judge")
    judged.add_argument("--evidence", required=True)
    judged.add_argument("--revision")
    args = parser.parse_args(argv)
    if args.command == "limits":
        print("\n".join(LIMITS))
        return CREDITED
    barriers = load_barriers()
    try:
        if args.command == "select":
            print(barriers.select(Path(args.cargo_json).read_text(errors="replace").splitlines()))
            return CREDITED
        if args.command == "identity":
            lines = Path(args.cargo_json).read_text(errors="replace").splitlines()
            pins = Path(args.pins).read_text().splitlines()
            Path(args.output).write_text(json.dumps(identity(lines, args.target_features, pins), indent=2) + "\n")
            return CREDITED
        evidence = Path(args.evidence)
        if args.command == "scan":
            extents = record_extents(args.executable, load_declaration(DECLARATION)["sites"], args.objdump.split(),
                                     args.demangler.split())
            (evidence / "extents.json").write_text(json.dumps(extents, indent=2, sort_keys=True) + "\n")
        revision = args.revision if args.command == "judge" and args.revision else barriers.load_rc11().git_revision()
        return write_judgment(evidence, revision)
    except (Refusal, barriers.Refusal, OSError, ValueError) as refusal:
        print(f"scan-tag-compare: refused: {refusal}", file=sys.stderr)
        return REFUSED


if __name__ == "__main__":
    sys.exit(main())
