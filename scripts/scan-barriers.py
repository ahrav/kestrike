#!/usr/bin/env python3
"""Scan the linked AArch64 kestrike library-test executable for a
sufficient barrier inside each declared function's extent.

Usage:
  scan-barriers.py limits
  scan-barriers.py select --cargo-json FILE
  scan-barriers.py identity --cargo-json FILE --target-features LIST --pins FILE
      --output FILE
  scan-barriers.py scan --executable PATH --output FILE [--declaration FILE]
      [--demangler CMD] [--identity FILE]

`limits` prints the limits every result carries, one per line.

`select` reads `cargo test -p kestrike --lib --no-run --message-format=json`
output and prints the one test-profile executable of the kestrike library,
or refuses when the build names none or several.

`identity` writes the build identity a scan report carries: the checked-out
revision, the CI run, attempt and job, the executable `select` names, the
`test` profile with the profile Cargo reports for that artifact, the LTO
setting, every `CARGO_PROFILE_*` override, `RUSTFLAGS`, the comma-separated
target features and the native-build pin lines. Cargo's JSON omits LTO, so
the lane pins `CARGO_PROFILE_DEV_LTO` and the identity refuses when it is
unset; it also refuses an empty feature list and a missing revision.

`scan` admits the executable before it decodes anything: a little-endian
ELF64 executable or shared object for AArch64 (`e_machine` 183), whose
symbol table holds exactly one function symbol per declared name, each with
a nonzero size that is a multiple of four, a four-byte-aligned address, and
an extent wholly inside one executable `PROGBITS` section and inside the
file. Names are demangled with `--demangler` (default `llvm-cxxfilt`), and
an LLVM `.llvm.<n>` promotion suffix and a legacy `::h<hash>` suffix are
dropped before matching. It then decodes every four-byte word inside each
extent and credits the site only when one of them is a sufficient barrier
for the site's order:

- release: `DMB ISH` 0xd5033bbf or `DMB SY` 0xd5033fbf;
- acquire: those two or `DMB ISHLD` 0xd50339bf.

Each scanned site also lists the functions its `BL` words call, so a site
whose barrier moved into an outlined callee shows where it went.

`DMB ISHST`, `DMB NSHLD`, `DMB NSH`, every other `DMB` and every non-`DMB`
word earn nothing, and a barrier outside the extent, in a neighboring
symbol, earns nothing.

The report records the executable's path and sha256, its machine, the
demangler and its version, the identity `identity` wrote, each site's
symbol, address, size, word count, the barriers found and its verdict, and
the limits every result carries. A refused site records the extent
inspected, when one was found. The report gates the lane and credits no
obligation record.

Exit 0 credits every site, 1 is a site without a sufficient barrier, 2 is a
refused selection, executable, declaration or symbol.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import re
import struct
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DECLARATION = ROOT / "verification/barriers/expected.json"
CREDITED, MISSING, REFUSED = 0, 1, 2
EM_AARCH64, ET_EXEC, ET_DYN = 183, 2, 3
SHT_PROGBITS, SHT_SYMTAB, SHF_EXECINSTR, STT_FUNC = 1, 2, 0x4, 2
DMB_MASK, DMB_BASE = 0xFFFFF0FF, 0xD50330BF
DMB_OPTIONS = {0b1111: "SY", 0b1110: "ST", 0b1101: "LD", 0b1011: "ISH", 0b1010: "ISHST", 0b1001: "ISHLD",
               0b0111: "NSH", 0b0110: "NSHST", 0b0101: "NSHLD", 0b0011: "OSH", 0b0010: "OSHST", 0b0001: "OSHLD"}
RELEASE = frozenset({0xD5033BBF, 0xD5033FBF})
SUFFICIENT = {"release": RELEASE, "acquire": RELEASE | {0xD50339BF}}
LIMITS = [
    "function-level presence: a credited site has a sufficient barrier somewhere in its function's extent, "
    "not on any particular path through it",
    "physical clock: barrier presence says nothing about the publication counter's clock ordering, which the "
    "platform owner's proof covers",
]
SUFFIXES = re.compile(r"( \(\.llvm\.\d+\))+$|::h[0-9a-f]{16}$")


class Refusal(Exception):
    pass


def decode(word):
    """The mnemonic of a `DMB` word, or None for any other instruction."""
    if word & DMB_MASK != DMB_BASE:
        return None
    option = (word >> 8) & 0xF
    return f"DMB {DMB_OPTIONS.get(option, f'#{option}')}"


def call_offset(word):
    """The byte offset a `BL` word branches to, or None for any other instruction."""
    if word & 0xFC000000 != 0x94000000:
        return None
    imm26 = word & 0x03FFFFFF
    return 4 * (imm26 - (1 << 26) if imm26 & (1 << 25) else imm26)


def sufficient(order, word):
    return word in SUFFICIENT[order]


def artifact(lines):
    """The one Cargo JSON message naming the kestrike library's test-profile executable."""
    found = []
    for line in lines:
        try:
            message = json.loads(line)
        except ValueError:
            continue
        target = message.get("target", {})
        if (message.get("reason") == "compiler-artifact" and message.get("executable")
                and message.get("profile", {}).get("test") and target.get("name") == "kestrike"
                and "lib" in target.get("kind", [])):
            found.append(message)
    executables = [message["executable"] for message in found]
    if len(found) != 1 or not Path(executables[0]).is_file():
        raise Refusal(f"the build named {len(found)} kestrike library-test executables: {executables}")
    return found[0]


def select(lines):
    return Path(artifact(lines)["executable"])


def load_rc11():
    spec = importlib.util.spec_from_file_location("judge_rc11", ROOT / "scripts/judge-rc11.py")
    if spec is None or spec.loader is None:
        raise Refusal("scripts/judge-rc11.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def identity(lines, features, pins):
    """The build identity of the executable `select` names, bound to the checked-out revision and CI run."""
    message = artifact(lines)
    lto = os.environ.get("CARGO_PROFILE_DEV_LTO")
    if not lto:
        raise Refusal("the build pins no LTO setting: CARGO_PROFILE_DEV_LTO is unset")
    features = [feature for feature in features.split(",") if feature]
    if not features:
        raise Refusal("the compiler reported no target features")
    revision = load_rc11().git_revision()
    if not revision:
        raise Refusal("git names no checked-out revision")
    return {"revision": revision,
            "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
            "executable": message["executable"], "profile": "test", "cargo_profile": message["profile"], "lto": lto,
            "profile_env": {key: value for key, value in sorted(os.environ.items()) if key.startswith("CARGO_PROFILE_")},
            "rustflags": os.environ.get("RUSTFLAGS"), "target_features": features, "native_build": pins}


def sections(image, machines=(EM_AARCH64,)):
    """The section headers of an admitted ELF64 executable or shared object for one of `machines`."""
    if len(image) < 64 or image[:4] != b"\x7fELF":
        raise Refusal("not an ELF file")
    if image[4] != 2 or image[5] != 1:
        raise Refusal("not a little-endian ELF64 file")
    e_type, e_machine = struct.unpack_from("<HH", image, 16)
    if e_machine not in machines:
        raise Refusal(f"machine {e_machine}, not one of {list(machines)}")
    if e_type not in (ET_EXEC, ET_DYN):
        raise Refusal(f"ELF type {e_type}, not a linked executable or shared object")
    shoff, = struct.unpack_from("<Q", image, 40)
    shentsize, shnum = struct.unpack_from("<HH", image, 58)
    if shentsize != 64 or shoff + shnum * 64 > len(image):
        raise Refusal("the section header table lies outside the file")
    headers = []
    for index in range(shnum):
        name, kind, flags, addr, offset, size, link = struct.unpack_from("<IIQQQQI", image, shoff + index * 64)
        headers.append({"type": kind, "flags": flags, "addr": addr, "offset": offset, "size": size, "link": link})
    return headers


def functions(image, headers):
    """Every function symbol as (mangled name, section index, address, size)."""
    tables = [header for header in headers if header["type"] == SHT_SYMTAB]
    if len(tables) != 1:
        raise Refusal(f"{len(tables)} symbol tables, not one")
    table = tables[0]
    if table["link"] >= len(headers):
        raise Refusal("the symbol table names no string table")
    strings = headers[table["link"]]
    if table["offset"] + table["size"] > len(image) or strings["offset"] + strings["size"] > len(image):
        raise Refusal("the symbol or string table lies outside the file")
    found = []
    for at in range(table["offset"], table["offset"] + table["size"] - 23, 24):
        name, info, _other, shndx, value, size = struct.unpack_from("<IBBHQQ", image, at)
        if info & 0xF != STT_FUNC:
            continue
        start = strings["offset"] + name
        end = image.find(b"\0", start, strings["offset"] + strings["size"])
        if end < 0:
            raise Refusal("a symbol name runs past its string table")
        found.append((image[start:end].decode("utf-8", "replace"), shndx, value, size))
    return found


def demangle(names, demangler):
    if not names:
        return []
    try:
        result = subprocess.run(demangler, input="\n".join(names) + "\n", capture_output=True, text=True, check=True)
    except (OSError, subprocess.CalledProcessError) as error:
        raise Refusal(f"the demangler {demangler} failed: {error}") from error
    lines = result.stdout.splitlines()
    if len(lines) != len(names):
        raise Refusal(f"the demangler returned {len(lines)} names for {len(names)}")
    return [SUFFIXES.sub("", line) for line in lines]


def tool_version(command):
    try:
        result = subprocess.run([command[0], "--version"], capture_output=True, text=True, check=False)
    except OSError:
        return None
    return (result.stdout or result.stderr).strip().splitlines()[:2]


def load_declaration(path):
    try:
        declaration = json.loads(Path(path).read_text())
        sites = declaration["sites"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        raise Refusal(f"unreadable declaration {path}: {error}") from error

    def named(site, key):
        return isinstance(site, dict) and isinstance(site.get(key), str) and site[key] != ""

    if (not isinstance(sites, list) or not sites
            or any(not named(site, "symbol") or not named(site, "site") or site.get("order") not in SUFFICIENT
                   for site in sites)
            or len({site["symbol"] for site in sites}) != len(sites)):
        raise Refusal("the declaration needs sites with unique symbols, a name and an order of release or acquire")
    return sites


def scan_site(image, headers, site, matches, names):
    """The verdict for one declared site given the function symbols whose demangled name is its symbol, and
    every function's demangled name by address, which names the calls an extent makes."""
    entry = {"site": site["site"], "symbol": site["symbol"], "order": site["order"]}
    if len(matches) != 1:
        entry.update(verdict="refused", reason=f"{len(matches)} function symbols named {site['symbol']}",
                     extents=[{"address": hex(value), "size": size} for _, value, size in matches])
        return entry
    shndx, value, size = matches[0]
    entry.update(address=hex(value), size=size)
    section = headers[shndx] if 0 < shndx < len(headers) else None
    problem = None
    if size == 0:
        problem = "zero size"
    elif value % 4 or size % 4:
        problem = "an address or size that is not a multiple of four"
    elif section is None or section["type"] != SHT_PROGBITS or not section["flags"] & SHF_EXECINSTR:
        problem = "a section that is not executable PROGBITS"
    elif value < section["addr"] or value + size > section["addr"] + section["size"]:
        problem = "an extent outside its section"
    elif section["offset"] + (value - section["addr"]) + size > len(image):
        problem = "an extent past the end of the file"
    if problem or section is None:
        entry.update(verdict="refused", reason=problem)
        return entry
    start = section["offset"] + (value - section["addr"])
    words = struct.unpack_from(f"<{size // 4}I", image, start)
    barriers = [{"offset": 4 * index, "word": f"{word:#010x}", "name": name,
                 "sufficient": sufficient(site["order"], word)}
                for index, word in enumerate(words) if (name := decode(word))]
    calls = sorted({value + 4 * index + branch for index, word in enumerate(words)
                    if (branch := call_offset(word)) is not None})
    entry.update(words=len(words), barriers=barriers, calls=[names.get(target, hex(target)) for target in calls])
    credited = any(barrier["sufficient"] for barrier in barriers)
    entry.update(verdict="pass" if credited else "fail",
                 reason=None if credited else f"no {site['order']} barrier among {len(barriers)} DMB words")
    return entry


def scan(executable, sites, demangler, identity):
    report = {"executable": str(executable), "declaration": [dict(site) for site in sites],
              "ci": {key: os.environ.get(key) for key in ("GITHUB_RUN_ID", "GITHUB_RUN_ATTEMPT", "GITHUB_JOB")},
              "demangler": {"command": demangler, "version": tool_version(demangler)},
              "identity": identity, "limits": LIMITS, "credited": False}
    try:
        image = Path(executable).read_bytes()
    except OSError as error:
        report.update(reason=f"unreadable executable: {error}")
        return REFUSED, report
    report["sha256"] = hashlib.sha256(image).hexdigest()
    try:
        headers = sections(image)
        symbols = functions(image, headers)
        names = demangle([name for name, *_ in symbols], demangler)
    except (Refusal, struct.error) as refusal:
        report.update(reason=str(refusal))
        return REFUSED, report
    report["machine"] = "aarch64"
    by_name = {}
    for index, (_, shndx, value, size) in enumerate(symbols):
        by_name.setdefault(names[index], []).append((shndx, value, size))
    addresses = {value: names[index] for index, (_, _, value, _) in enumerate(symbols)}
    report["sites"] = [scan_site(image, headers, site, by_name.get(site["symbol"], []), addresses) for site in sites]
    verdicts = {entry["verdict"] for entry in report["sites"]}
    report["credited"] = verdicts == {"pass"}
    if "refused" in verdicts:
        return REFUSED, report
    return (CREDITED if report["credited"] else MISSING), report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Scan AArch64 function extents for sufficient barriers.")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("limits")
    chosen = commands.add_parser("select")
    chosen.add_argument("--cargo-json", required=True)
    built = commands.add_parser("identity")
    built.add_argument("--cargo-json", required=True)
    built.add_argument("--target-features", required=True)
    built.add_argument("--pins", required=True)
    built.add_argument("--output", required=True)
    scanned = commands.add_parser("scan")
    scanned.add_argument("--executable", required=True)
    scanned.add_argument("--output", required=True)
    scanned.add_argument("--declaration", default=str(DECLARATION))
    scanned.add_argument("--demangler", default="llvm-cxxfilt")
    scanned.add_argument("--identity")
    args = parser.parse_args(argv)
    if args.command == "limits":
        print("\n".join(LIMITS))
        return CREDITED
    try:
        if args.command == "select":
            print(select(Path(args.cargo_json).read_text(errors="replace").splitlines()))
            return CREDITED
        if args.command == "identity":
            lines = Path(args.cargo_json).read_text(errors="replace").splitlines()
            pins = Path(args.pins).read_text().splitlines()
            Path(args.output).write_text(json.dumps(identity(lines, args.target_features, pins), indent=2) + "\n")
            return CREDITED
        sites = load_declaration(args.declaration)
        recorded = json.loads(Path(args.identity).read_text()) if args.identity else None
    except (Refusal, OSError, ValueError) as refusal:
        print(f"scan-barriers: refused: {refusal}", file=sys.stderr)
        return REFUSED
    code, report = scan(args.executable, sites, args.demangler.split(), recorded)
    Path(args.output).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    for entry in report.get("sites", []):
        print(f"scan-barriers: {entry['site']}: {entry['verdict']}"
              + (f" ({entry['reason']})" if entry.get("reason") else ""), file=sys.stderr)
    if report.get("reason"):
        print(f"scan-barriers: refused: {report['reason']}", file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
