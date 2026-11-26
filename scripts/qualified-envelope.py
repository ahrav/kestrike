#!/usr/bin/env python3
"""Write the qualified envelope an enveloped domain's receipt binds.

Usage:
  qualified-envelope.py asan --record FILE --bindings FILE --target TRIPLE --rustflags=FLAGS
      --sanitizer NAME --compilers TEXT --configure SHA --archives SHA --lineage SHA|unrecorded
      --runtime FILE --rustc TEXT --llvm VERSION --build-minutes N --run-minutes N
  qualified-envelope.py qemu --artifact FILE --compilers TEXT --configure SHA --lineage SHA|unrecorded
      --host-kernel TEXT --host-machine TEXT --runner NAME --accel kvm|tcg
      --inputs FILE --executable FILE --initrd FILE --cpus N --memory-mib N --backing-mib N
      --handshake-minutes N --run-minutes N

Both domains share the envelope's core: the domain, the run and its attempt
(`GITHUB_RUN_ID` and `GITHUB_RUN_ATTEMPT`, or `local` outside Actions, so
both fields are always explicit), the target, the rustc flags, the install
record with the target and header digest it records, the generated output
directory with the generator digest and the generator toolchain line
recorded in its `bindings.rs`, the native archives' compilers and the
configure and archive digests, the install record's lineage identity (the
record's sha256 when the record carries the controlled build's lineage,
`unrecorded` when it carries none; any other value is refused), and the lane's deadlines beside the
measurement in `verification/<domain>/measurement.json` they derive from.
`scripts/verify-receipts.py` credits each domain from these fields.

The `asan` envelope adds the sanitizer and the Rust sanitizer runtime
archive with its digest and the compiler and LLVM that supply it. Its
deadlines are the build (with its listing) and the run.

The `qemu` envelope adds the portable artifact reference the guest runs
against (`--artifact`, the record the hardware build publishes: `target`,
`rustflags`, `generated`, `header_digest`, `generator_digest`, `archives`,
`install` and `source`), checked against the committed install record
`generated` names under `crates/spdk-sys/src/generated/installs`, which
must record the same target and header digest, and the output it names,
whose `bindings.rs` must record the same generator digest; the host
(kernel, machine, runner, accelerator); the guest inputs file, the test
executable the lane built at this revision and the initrd it appended that
executable to, each with its digest. Its deadlines are the guest's
handshake and the run, and its measurement names the `host` it was taken on
as a record of `machine` (its `uname -m`), `runners`, the runner
registrations that share the measured machine and its quota, and `accel`,
the accelerator it ran under: this envelope's machine and accelerator must
be those and its runner one of those registrations. Its guest CPU count,
memory and backing size must equal the measurement's `guest` record; the
receipt verifier checks the envelope and the harness bounds independently.

A deadline that is not a positive whole number of minutes or is shorter
than its measured basis times the lane's factor (4 for the build and the
handshake, 10 for the run), with each QEMU inventory namespace member's
declared deadline and output drain added to the guest run's bound, an install
record missing its target or header
digest or recording another target, a bindings file missing its generator
digest or generator line, a missing runtime archive, an artifact reference
off the committed records, a missing input, or a measurement missing a
field, of another domain or host, with a figure that is not a positive
number or with a peak over its memory is a refusal: the script prints the
reason on stderr and exits 1, so the lane fails before it judges a run.
`measurement_gaps` and
`deadline_gaps` state these rules once; `scripts/verify-receipts.py` applies
them to the envelope it credits.
"""

import argparse
import hashlib
import json
import math
import os
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
# The committed install records and the generated outputs they name.
INSTALLS = ROOT / "crates/spdk-sys/src/generated/installs"
OUTPUTS = ROOT / "crates/spdk-sys/src/generated/outputs"
# Each deadline's factor over the measured seconds it derives from.
FACTORS = {"build": 4, "handshake": 4, "run": 10}
# Each domain's deadlines, in the order its lane applies them.
DEADLINES = {"asan": ("build", "run"), "qemu": ("handshake", "run")}
ARTIFACT_FIELDS = ("target", "rustflags", "generated", "header_digest", "generator_digest", "archives", "install", "source")
# The QEMU accelerators the guest lane runs under; a measurement holds under the one it was taken with.
ACCELERATORS = ("kvm", "tcg")
GUEST_RESOURCES = ("cpus", "memory_mib", "backing_mib")
# The install record carries the target, the header digest and the output it selects; the output's bindings.rs
# the generator digest and toolchain line.
RECORDED = {
    "record": {
        "target": re.compile(r"^Target: (\S+)\.", re.M),
        "header_digest": re.compile(r"^Header digest: ([0-9a-f]{64})$", re.M),
    },
    "bindings": {
        "generator_digest": re.compile(r"^// Generator digest: ([0-9a-f]{64})$", re.M),
        "generator": re.compile(r"^// (bindgen [^\n]*)$", re.M),
    },
}
OUTPUT = re.compile(r"^Output: (\S+)$", re.M)


class Refusal(Exception):
    pass


def measurement_path(domain):
    return ROOT / "verification" / domain / "measurement.json"


def figures(domain):
    """The measured figures `domain`'s deadlines and memory bounds read: each lane builds before it runs."""
    return (*(f"{name}_seconds" for name in DEADLINES[domain]), "build_peak_rss_mib", "peak_rss_mib", "cpus", "memory_mib")


def sha256(path):
    try:
        return hashlib.sha256(Path(path).read_bytes()).hexdigest()
    except OSError as error:
        raise Refusal(f"unreadable {path}: {error}") from error


def recorded(record, bindings):
    """Return the target and header digest the install `record` records and the generator digest and toolchain
    line the output's `bindings` records."""
    found = {}
    for kind, path in (("record", record), ("bindings", bindings)):
        try:
            text = Path(path).read_text(encoding="utf-8")
        except OSError as error:
            raise Refusal(f"unreadable {kind} {path}: {error}") from error
        for name, pattern in RECORDED[kind].items():
            match = pattern.search(text)
            if match is None:
                raise Refusal(f"{path} records no {name.replace('_', ' ')} line")
            found[name] = match.group(1)
    return found


def positive(value, kinds=(int, float)):
    return not isinstance(value, bool) and isinstance(value, kinds) and value > 0


def measurement_gaps(measured, domain):
    """Return why `measured` is no basis for `domain`'s deadlines: not a record, a missing field, another
    domain, a figure that is not a positive number, a build or run peak over the measured memory, or, for the
    guest lane, a host that is not a record of a machine, a nonempty list of runner registrations and an
    accelerator, or a guest record without positive integer cpus, memory_mib and backing_mib. The writer
    refuses the first gap and `scripts/verify-receipts.py` refuses every gap of the envelope it credits."""
    if not isinstance(measured, dict):
        return ["the measurement is not a record"]
    missing = [key for key in ("domain", *figures(domain), "host", "date") if key not in measured]
    if missing:
        return [f"the measurement lacks {missing}"]
    gaps = []
    if measured["domain"] != domain:
        gaps.append(f"the measurement is of domain {measured['domain']!r}, expected {domain!r}")
    unmeasured = [key for key in figures(domain) if not positive(measured[key])]
    gaps += [f"the measurement records {key} as {measured[key]!r}; a positive number is required" for key in unmeasured]
    if not unmeasured:
        for key, phase in (("build_peak_rss_mib", "build"), ("peak_rss_mib", "run")):
            if measured[key] > measured["memory_mib"]:
                gaps.append(f"the measured {phase} peak {measured[key]} MiB exceeds the measured memory {measured['memory_mib']} MiB")
    if domain == "qemu":
        guest = measured.get("guest")
        if not isinstance(guest, dict) or any(not positive(guest.get(key), int) for key in GUEST_RESOURCES):
            gaps.append("the measurement needs positive integer guest cpus, memory_mib and backing_mib")
    host = measured["host"]
    if domain == "qemu" and not measured_host(host):
        gaps.append(f"the measurement names its host as {host!r}; the guest lane needs a record of its machine, "
                    "its runner registrations and its accelerator")
    return gaps


def measured_host(host):
    """Whether `host` names a machine, a nonempty list of named runner registrations and one of the accelerators."""
    if not isinstance(host, dict):
        return False
    machine, runners = host.get("machine"), host.get("runners")
    return (
        isinstance(machine, str) and bool(machine)
        and isinstance(runners, list) and bool(runners) and all(isinstance(name, str) and name for name in runners)
        and host.get("accel") in ACCELERATORS
    )


def unmeasured_seconds(domain, name):
    """The seconds `domain`'s `name` deadline adds to its factor times the measured seconds: for the guest lane's
    run, each QEMU inventory namespace member's declared deadline plus the inventory's `member_drain_seconds`. The
    guest binder case runs each member in a child after the measured binder checks. `ExactChild::finish` kills a
    child still running at its deadline, and once the child has ended it waits up to `member_drain_seconds` for
    the child's two output pipes to close."""
    if (domain, name) != ("qemu", "run"):
        return 0
    qemu = json.loads((ROOT / "scripts/test-inventory.json").read_text(encoding="utf-8"))["qemu"]
    return sum(case["deadline_seconds"] + qemu["member_drain_seconds"] for case in qemu["namespace_cases"])


def deadline_gaps(measured, deadlines, domain):
    """Return why `deadlines` fall short of a valid measurement `measured` for `domain`: not a record, a factor
    other than the lane's, a deadline that is not a positive whole number of minutes, or one under its factor
    times the measured seconds plus its `unmeasured_seconds`."""
    if not isinstance(deadlines, dict):
        return ["the deadlines are not a record"]
    gaps = []
    for name in DEADLINES[domain]:
        factor = FACTORS[name]
        written, minutes, seconds = deadlines.get(f"{name}_factor"), deadlines.get(f"{name}_minutes"), measured[f"{name}_seconds"]
        if written != factor:
            gaps.append(f"the {name} factor {written!r} is not the lane's factor {factor}")
        if not positive(minutes, int):
            gaps.append(f"the {name} deadline {minutes}m is no positive bound")
            continue
        added = unmeasured_seconds(domain, name)
        least = math.ceil((seconds * factor + added) / 60)
        if minutes < least:
            members = f" plus the namespace members' {added} s" if added else ""
            gaps.append(f"the {name} deadline {minutes}m is below {factor} times the measured {seconds} s{members} ({least}m)")
    return gaps


def host_gaps(measured, host):
    """Return why the guest lane's `host` is not the machine its measurement was taken on, not one of the runner
    registrations the measurement names, or not under the accelerator it was measured under."""
    taken = measured["host"]
    gaps = []
    if taken["machine"] != host.get("machine"):
        gaps.append(f"the measurement was taken on machine {taken['machine']!r}, this run is on {host.get('machine')!r}")
    if host.get("runner") not in taken["runners"]:
        gaps.append(f"the measurement was taken on runners {taken['runners']!r}, this run is on {host.get('runner')!r}")
    if taken["accel"] != host.get("accel"):
        gaps.append(f"the measurement was taken under accelerator {taken['accel']!r}, this run is under {host.get('accel')!r}")
    return gaps



def guest_resource_gaps(measured, resources):
    """Refuse guest settings outside the configuration whose runtime and memory were measured."""
    expected = measured.get("guest") if isinstance(measured, dict) else None
    if not isinstance(expected, dict) or not isinstance(resources, dict):
        return ["the measured or actual guest resources are missing"]
    return [f"guest {key} {resources.get(key)!r} differs from measured {expected.get(key)!r}"
            for key in GUEST_RESOURCES
            if not positive(resources.get(key), int) or resources.get(key) != expected.get(key)]


def measurement(path, domain):
    """Return the recorded measurement of `domain`, refusing the first of its `measurement_gaps`."""
    try:
        measured = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Refusal(f"unreadable measurement {path}: {error}") from error
    gaps = measurement_gaps(measured, domain)
    if gaps:
        raise Refusal(f"{path}: {gaps[0]}")
    return measured


def deadlines(domain, measured, minutes):
    """Return `domain`'s deadlines from `minutes` per name with the lane's factors, refusing the first of
    their `deadline_gaps`."""
    written = {}
    for name in DEADLINES[domain]:
        written[f"{name}_minutes"], written[f"{name}_factor"] = minutes[name], FACTORS[name]
    gaps = deadline_gaps(measured, written, domain)
    if gaps:
        raise Refusal(gaps[0])
    return written


def core(domain, environ, *, record, bindings, target, rustflags, native, measured, minutes):
    """The envelope fields both domains share, with the install record's recorded target checked against
    `target`."""
    found = recorded(record, bindings)
    if found.pop("target") != target:
        raise Refusal(f"{record} records another target than {target}")
    return {
        "domain": domain,
        "attempt": environ.get("GITHUB_RUN_ATTEMPT") or "local",
        "run": environ.get("GITHUB_RUN_ID") or "local",
        "target": target,
        "rustflags": rustflags,
        "install": str(record),
        "generated": str(Path(bindings).parent),
        **found,
        "native": native,
        "deadlines": deadlines(domain, measured, minutes),
        "measured": measured,
    }


def asan_envelope(args, environ, measured):
    runtime = Path(args.runtime)
    if not runtime.is_file():
        raise Refusal(f"the sanitizer runtime {runtime} is missing")
    envelope = core("asan", environ, record=args.record, bindings=args.bindings, target=args.target, rustflags=args.rustflags,
                    native={"compilers": args.compilers, "configure": args.configure, "archives": args.archives,
                            "lineage": lineage(args.record, args.lineage)},
                    measured=measured, minutes={"build": args.build_minutes, "run": args.run_minutes})
    envelope["sanitizer"] = args.sanitizer
    envelope["runtime"] = {"archive": str(runtime), "sha256": sha256(runtime), "rustc": args.rustc, "llvm": args.llvm}
    return envelope


LINEAGE_LINE = re.compile(r"^(Source|Patches|Build inputs|Compilers|Configure|Archive): ", re.M)


def lineage(record, identity):
    """Return `identity` when it is `record`'s lineage identity: the record's sha256 when it carries a lineage
    line, `unrecorded` when it carries none. Raise `Refusal` when `record` is unreadable or `identity` differs."""
    try:
        text = Path(record).read_text(encoding="utf-8")
    except OSError as error:
        raise Refusal(f"unreadable record {record}: {error}") from error
    expected = sha256(record) if LINEAGE_LINE.search(text) else "unrecorded"
    if identity != expected:
        raise Refusal(f"the lineage {identity} is not {expected}, the identity of {record}; the record is stale")
    return identity


def output_bindings(record):
    """Return the `bindings.rs` of the committed output the install `record` names."""
    try:
        match = OUTPUT.search(Path(record).read_text(encoding="utf-8"))
    except OSError as error:
        raise Refusal(f"unreadable record {record}: {error}") from error
    if match is None:
        raise Refusal(f"{record} records no output line")
    bindings = OUTPUTS / match.group(1) / "bindings.rs"
    if not bindings.is_file():
        raise Refusal(f"{record} names the output {match.group(1)}, which {OUTPUTS} lacks")
    return bindings


def artifact_reference(path):
    """Return the portable artifact reference at `path`, every field filled, naming a committed install record
    whose target and header digest it repeats and whose output's bindings record its generator digest, with
    that record and bindings file."""
    try:
        reference = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError) as error:
        raise Refusal(f"unreadable artifact reference {path}: {error}") from error
    missing = [field for field in ARTIFACT_FIELDS if not isinstance(reference.get(field), str) or not reference[field]]
    if missing:
        raise Refusal(f"the artifact reference {path} lacks {missing}")
    name = reference["generated"]
    record = INSTALLS / name
    if name in (".", "..") or Path(name).name != name or not record.is_file():
        raise Refusal(f"the artifact reference names install record {name!r}, which {INSTALLS} lacks")
    bindings = output_bindings(record)
    found = recorded(record, bindings)
    for field, source in (("header_digest", record), ("generator_digest", bindings)):
        if found[field] != reference[field]:
            raise Refusal(f"the artifact's {field} {reference[field]} differs from the committed {found[field]} in {source}")
    return {field: reference[field] for field in ARTIFACT_FIELDS}, record, bindings


def qemu_envelope(args, environ, measured):
    artifact, record, bindings = artifact_reference(args.artifact)
    envelope = core("qemu", environ, record=record, bindings=bindings, target=artifact["target"], rustflags=artifact["rustflags"],
                    native={"compilers": args.compilers, "configure": args.configure, "archives": artifact["archives"],
                            "lineage": lineage(record, args.lineage)},
                    measured=measured, minutes={"handshake": args.handshake_minutes, "run": args.run_minutes})
    envelope["artifact"] = artifact
    envelope["host"] = {"kernel": args.host_kernel, "machine": args.host_machine, "runner": args.runner, "accel": args.accel}
    envelope["guest"] = {key: getattr(args, key) for key in GUEST_RESOURCES}
    gaps = host_gaps(measured, envelope["host"]) + guest_resource_gaps(measured, envelope["guest"])
    if gaps:
        raise Refusal(gaps[0])
    for field in ("inputs", "executable", "initrd"):
        envelope[field] = {"path": getattr(args, field), "sha256": sha256(getattr(args, field))}
    return envelope


def envelope(args, environ=os.environ, measurement_file=None):
    measured = measurement(measurement_file or measurement_path(args.domain), args.domain)
    return (asan_envelope if args.domain == "asan" else qemu_envelope)(args, environ, measured)


def parser():
    parser = argparse.ArgumentParser(description="Write an enveloped domain's envelope.")
    domains = parser.add_subparsers(dest="domain", required=True)
    asan = domains.add_parser("asan")
    for name in ("record", "bindings", "target", "rustflags", "sanitizer", "compilers", "configure", "archives", "lineage", "runtime", "rustc", "llvm"):
        asan.add_argument(f"--{name}", required=True)
    asan.add_argument("--build-minutes", type=int, required=True)
    asan.add_argument("--run-minutes", type=int, required=True)
    qemu = domains.add_parser("qemu")
    for name in ("artifact", "compilers", "configure", "lineage", "host-kernel", "host-machine", "runner", "inputs", "executable", "initrd"):
        qemu.add_argument(f"--{name}", required=True)
    qemu.add_argument("--accel", choices=ACCELERATORS, required=True)
    for name in GUEST_RESOURCES:
        qemu.add_argument(f"--{name.replace('_', '-')}", type=int, required=True)
    qemu.add_argument("--handshake-minutes", type=int, required=True)
    qemu.add_argument("--run-minutes", type=int, required=True)
    return parser


def main(argv=None):
    args = parser().parse_args(argv)
    try:
        print(json.dumps(envelope(args), indent=2, sort_keys=True))
    except Refusal as refusal:
        print(f"qualified-envelope: {refusal}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
