#!/usr/bin/env python3
"""Exercise hardware-lane.py with a fake cargo, a fake test executable and fake controllers.

--ci selects smoke tests only for verified push or pull-request changes outside the hardware paths.
Without --ci, unittest discovers every test or runs the names supplied on the command line.
"""

import contextlib
import ctypes
import functools
import hashlib
import importlib.util
import io
import json
import mmap
import os
import platform
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import types
import unittest
from pathlib import Path
from unittest import mock

# Orphaned descendants reparent to this process, so the cleanup checks see a stray process as alive.
if ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) != 0:
    raise OSError(ctypes.get_errno(), "prctl(PR_SET_CHILD_SUBREAPER) failed")

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/hardware-lane.py"
MANIFEST = ROOT / "scripts/hardware-profiles.json"
SPDK = "storage::device::spdk::hardware_tests::"
OUTCOME = SPDK + "the_spdk_driver_passes_every_outcome_row_on_the_volume"
CONTRACT = SPDK + "the_spdk_driver_meets_the_disk_contract"
STOPS = SPDK + "the_spdk_driver_stops_with_dispatched_reads_and_writes_outstanding"
CONTAINMENT = SPDK + "a_watchdog_expiry_during_a_pre_proof_stall_escalates_to_the_controller"
CONTAINED = ("fenced", "device contained", "host contained", "contained")
OWNER = "net::host_pair_tests::the_owner_serves_the_volume"
TWO_OWNERS = "net::host_pair_tests::the_client_fetches_from_two_owners"
PAIR_WITNESSES = ["pressure at the limits", "healed with an exact GET", "history 3 windows judged by the oracle"]
# The fake fills each `{NAME}` from its environment, so one plan entry serves both clients of a two-owner profile.
TWO_OWNER_WITNESSES = ["failure owner {KESTRIKE_STOPPED} in cycle 1",
                       "healthy owner {KESTRIKE_CLIENT} served exact bytes after owner {KESTRIKE_STOPPED} stopped"]
CLIENT = "net::host_pair_tests::the_client_fetches_the_volume"
# A warm-cycle package case prints these lines after its judge passes; the fake executable fills
# `{KESTRIKE_EPISODE}` from the lane's environment.
PACKAGE_FIXTURE = json.loads((ROOT / "scripts/recovery-package-lines.json").read_text())
PACKAGE_LINES = [PACKAGE_FIXTURE["retained"].removesuffix(" episode e") + " episode {KESTRIKE_EPISODE}",
                 PACKAGE_FIXTURE["residual"], PACKAGE_FIXTURE["persisted"]]
PLACEMENT = "storage::init::tests::native_a_second_allowed_node_takes_a_moved_page_and_the_expanded_mask"
PAGEMAP = "native::dma::tests::privileged_page_map_addresses_are_present_and_match_dpdk"
ENVIRONMENT = "native::env_tests::the_environment_registers_and_verifies_a_hugepage_arena_then_finishes_in_order"
# The witness lines the prerequisites role's cases print on a privileged host with a second allowed node.
PREREQUISITE_WITNESSES = {
    ENVIRONMENT: {"observe": ["dma-witness Iommu iova Va registered pages 18 of 2097152 bytes translated 37748736 "
                              "bytes physical queries 0 mappings 1; mapping base 0x7f0000000000 iova 0x7f0000000000 extent 37748736; "
                              "CapEff: 000001ffffffffff; user namespace user:[4026531837]"]},
    PAGEMAP: {"observe": ["physical-query 4 pages present nonzero and equal to rte_mem_virt2phy"]},
    PLACEMENT: {"observe": ["placement second node 1 beside node 0: moved page followed, old mask refused, "
                            "expanded mask accepted at 4096 byte pages"]},
}

EXECUTABLE = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, signal, subprocess, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "plan.json").read_text())
    args = sys.argv[1:]
    test = args[-1] if "--list" in args else args[args.index("--exact") + 1]
    case = plan["cases"].get(test, {})
    if "--list" in args:
        count = case.get("ignored" if "--ignored" in args else "listed", 1)
        print("\\n".join([f"{test}: test"] * count))
        sys.exit(0)
    with (state / "runs.txt").open("a") as out:
        out.write(test + " " + os.environ.get("KESTRIKE_EPISODE", "") + "\\n")
    seen = {name: value for name, value in os.environ.items() if name.startswith("KESTRIKE_")}
    seen["RUNNER_TRACKING_ID"] = os.environ.get("RUNNER_TRACKING_ID")
    (state / f"{test}.env.json").write_text(json.dumps(seen))
    (state / f"{test}.client-{os.environ.get('KESTRIKE_CLIENT', '')}.env.json").write_text(json.dumps(seen))
    outcome = case.get("outcome", "pass")
    passed = f"test {test} ... ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s"
    if case.get("block_receipt"):
        Path(os.readlink("/proc/self/fd/1")).parent.joinpath("receipt.json").mkdir()
    if "rewrite_mappings" in case:
        Path(os.environ["KESTRIKE_MAPPINGS"]).write_text(case["rewrite_mappings"])
    if "break_observer" in case:
        log = Path(case["break_observer"]) / (os.environ["KESTRIKE_EPISODE"] + ".jsonl")
        log.unlink()
        log.mkdir()
    if "--nocapture" in args and not case.get("mute"):
        time.sleep(case.get("ready_after", 0))
        print("startup: identify: owner serving until 600s or SIGTERM", flush=True)
    if "say" in case:
        time.sleep(case.get("delay", 0))
        print(case["say"], file=sys.stderr, flush=True)
    for chunk in case.get("raw", []):
        time.sleep(0.2)
        sys.stderr.buffer.write(bytes.fromhex(chunk))
        sys.stderr.buffer.flush()
    for line in case.get("observe", []):
        time.sleep(0.2)
        print("observe: " + line.format_map(os.environ), file=sys.stderr, flush=True)
    if outcome in ("custodian", "orphan"):
        (state / f"{test}.grandchild").write_text(str(os.getpid()))
        if outcome == "orphan":
            os.kill(os.getppid(), signal.SIGKILL)
        time.sleep(600)
    if outcome in ("hang", "stubborn", "leave") or case.get("leave"):
        if outcome == "stubborn":
            signal.signal(signal.SIGTERM, signal.SIG_IGN)
        child = subprocess.Popen([sys.executable, "-c",
            "import signal, time; signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(600)"])
        (state / f"{test}.grandchild").write_text(str(child.pid))
        if outcome in ("hang", "stubborn"):
            time.sleep(600)
    if outcome == "abort":
        os.kill(os.getpid(), signal.SIGSEGV)
    if outcome == "close":
        signal.signal(signal.SIGTERM, lambda *_: (print("close requested by SIGTERM\\n" + passed), sys.exit(0)))
        ready = state / f"{test}.starting"
        ready.write_text(str(os.getpid()))
        ready.replace(state / f"{test}.ready")
        time.sleep(600)
    if outcome == "channel":
        held = state / f"{test}.pid"
        held.write_text(str(os.getpid()))
        def closed(*_):
            with (state / "controller.log").open("a") as log:
                log.write("sigterm\\n")
            held.unlink(missing_ok=True)
            sys.exit(143)
        signal.signal(signal.SIGTERM, closed)
        if case.get("census", "early") == "early":
            print("census before stall: pending 1", file=sys.stderr, flush=True)
        for _ in range(case.get("requests", 1)):
            with open(os.environ["KESTRIKE_CONTROLLER_REQUESTS"], "w") as requests:
                requests.write(case.get("request", "contain " + os.environ["KESTRIKE_MAPPINGS"]) + case.get("terminator", "\\n"))
        with open(os.environ["KESTRIKE_CONTROLLER_ACKS"]) as acks:
            acks.readline()
        if "trailing" in case:
            with open(os.environ["KESTRIKE_CONTROLLER_REQUESTS"], "w") as requests:
                requests.write(case["trailing"])
        if case.get("census") == "late":
            print("census before stall: pending 1", file=sys.stderr, flush=True)
        print("stalled until the request\\ncontainment requests 1\\ncontroller acknowledged true\\n" + passed)
        held.unlink(missing_ok=True)
        sys.exit(0)
    if outcome == "serve":
        time.sleep(case.get("seconds", 1))
    if outcome == "fail":
        print(f"test {test} ... FAILED\\n\\ntest result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
        sys.exit(101)
    if outcome == "zero":
        print("test result: ok. 0 passed; 0 failed; 1 ignored; 0 measured; 9 filtered out; finished in 0.00s")
        sys.exit(0)
    if outcome == "double":
        print(f"test {test} ... ok\\n\\ntest result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
        sys.exit(0)
    if outcome == "stray":
        print("test other::test ... ok\\n\\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
        sys.exit(0)
    if outcome == "bare":
        print("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s")
        sys.exit(0)
    print(passed)
''')

CARGO = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    with (state / "cargo-calls.txt").open("a") as calls:
        calls.write(" ".join(sys.argv[1:]) + "\\n")
    if sys.argv[1:] == ["-V"]:
        print("cargo 1.99.0 (fake)")
        sys.exit(0)
    if sys.argv[1:2] == ["metadata"]:
        print(json.dumps({"packages": [{"name": "kestrike", "version": "0.1.0",
                                        "manifest_path": str(state / "pkg" / "Cargo.toml")}]}))
        sys.exit(0)
    with (state / "builds.txt").open("a") as out:
        out.write(" ".join(sys.argv[1:]) + "\\n")
    print(json.dumps({"reason": "compiler-artifact", "target": {"name": "kestrike", "kind": ["lib"]},
                      "profile": {"test": True}, "executable": str(state / "kestrike-fake")}))
''')

GIT = textwrap.dedent('''\
    #!/usr/bin/env python3
    import os, sys, time
    from pathlib import Path
    if sys.argv[1:2] == ["status"]:
        state = Path(os.environ["FAKE_STATE"])
        arrived = state / "git-arrived"
        arrived.mkdir(exist_ok=True)
        (arrived / str(os.getpid())).touch()
        deadline = time.monotonic() + float(os.environ["FAKE_GIT_WAIT"])
        while len(os.listdir(arrived)) < int(os.environ["FAKE_GIT_PARTIES"]) and time.monotonic() < deadline:
            time.sleep(0.01)
        with (state / "git-arrivals.txt").open("a") as out:
            out.write(f"{len(os.listdir(arrived))}\\n")
    os.execv(os.environ["FAKE_GIT"], ["git", *sys.argv[1:]])
''')


def state(pid):
    try:
        return Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
    except OSError:
        return None


def alive(pid):
    try:
        status = Path(f"/proc/{pid}/stat").read_text().rpartition(")")[2].split()[0]
    except OSError:
        return False
    return status != "Z"


def open_files(pid):
    """Read a process's open files, omitting descriptors it closes after the directory listing."""
    directory = f"/proc/{pid}/fd"
    paths = []
    for fd in os.listdir(directory):
        with contextlib.suppress(FileNotFoundError):
            paths.append(os.readlink(f"{directory}/{fd}"))
    return paths


class ProcessFiles(unittest.TestCase):
    def test_a_closed_descriptor_does_not_hide_the_remaining_open_files(self):
        with mock.patch.object(os, "listdir", return_value=["4", "6", "7"]), \
                mock.patch.object(os, "readlink", side_effect=["/custody/fis.lock", FileNotFoundError(), "pipe:[42]"]):
            self.assertEqual(open_files(123), ["/custody/fis.lock", "pipe:[42]"])
        with mock.patch.object(os, "listdir", return_value=["4"]), \
                mock.patch.object(os, "readlink", side_effect=FileNotFoundError):
            self.assertEqual(open_files(123), [], "a closed reservation is not reported as held")

    def test_an_unreadable_process_or_descriptor_is_not_a_partial_snapshot(self):
        with mock.patch.object(os, "listdir", side_effect=FileNotFoundError), self.assertRaises(FileNotFoundError):
            open_files(123)
        with mock.patch.object(os, "listdir", return_value=["4"]), \
                mock.patch.object(os, "readlink", side_effect=PermissionError), self.assertRaises(PermissionError):
            open_files(123)


@functools.cache
def pci_function():
    """The first PCI function in this host's sysfs: the envelope fixture declares it and the mappings fixture binds it."""
    functions = sorted(os.listdir("/sys/bus/pci/devices")) if os.path.isdir("/sys/bus/pci/devices") else []
    assert functions, "the lane self-tests need a host with a PCI function in sysfs for the envelope's devices"
    return functions[0]


def host_envelope():
    """An approved envelope this host's facts reproduce: its observed fields as the lane reads them, with
    `cpu_features` cut to two of the host's features, one PCI function's identity, and placeholder values for the
    row-recorded fields. The lane runs as a subprocess and reads the live host, so the fixture needs a host that
    exposes every observed fact; one that hides DMI or hugepage facts fails here by name."""
    lane = lane_module()
    facts = lane.host_facts({"envelope": {"devices": {pci_function(): None}}})
    declared = {field: f"test {field}" for field in lane.ENVELOPE_FIELDS if field not in lane.OBSERVED}
    assert len(facts["cpu_features"]) >= 2, "the envelope fixture needs a host reporting two CPU features"
    unread = [field for field in lane.OBSERVED if facts[field] in lane.UNREAD]
    assert not unread, f"the envelope fixture needs a host exposing {unread}, which this host leaves unreadable"
    return {**declared, **{field: facts[field] for field in lane.OBSERVED}, "cpu_features": facts["cpu_features"][:2]}


def lane_module():
    spec = importlib.util.spec_from_file_location("hardware_lane", SCRIPT)
    lane = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lane)
    return lane


class MappingsFormat(unittest.TestCase):
    def test_the_judge_accepts_the_format_the_binder_reads(self):
        """`MAPPINGS_FORMAT` tracks `FORMAT` in `bind/mappings.rs`, so a format change there moves the judge too."""
        source = (ROOT / "crates/kestrike/src/bind/mappings.rs").read_text()
        declared = re.search(r'^const FORMAT: &str = "(\d+)";$', source, re.MULTILINE)
        self.assertIsNotNone(declared, "mappings.rs declares FORMAT")
        self.assertEqual(lane_module().MAPPINGS_FORMAT, declared.group(1))

    def test_the_lane_reads_the_bound_functions_under_the_keys_the_binder_writes(self):
        """The envelope check reads each bound PCI function from the mappings file's key for it, so a key renamed in
        `bind/mappings.rs` fails here instead of leaving the lane reading no function."""
        source = (ROOT / "crates/kestrike/src/bind/mappings.rs").read_text()
        for key in (*lane_module().MAPPED_FUNCTIONS, lane_module().MAPPED_VOLUME, lane_module().MAPPED_ADDRESS):
            with self.subTest(key=key):
                self.assertIn(f'    "{key}",\n', source)

    def test_the_mappings_facts_record_the_bound_volume_and_address_from_the_digested_bytes(self):
        """The facts name the volume an owner's mappings file binds, and None for a client's that binds only its ENI,
        and the ENI address each file binds, None for a file that binds no ENI; the digest covers the bytes the
        fields were read from."""
        lane = lane_module()
        with tempfile.TemporaryDirectory(prefix="mappings-") as temp:
            owner, client = Path(temp) / "owner", Path(temp) / "client"
            owner.write_text("format=3\nnvme.volume=vol-0abc\nnvme.bdf=0000:00:1e.0\neni.ipv4=10.0.1.5\n"
                             "eni.bdf=0000:00:06.0\n")
            client.write_text("format=3\neni.ipv4=10.0.1.7\neni.bdf=0000:00:07.0\n")
            facts = lane.mappings_facts({"KESTRIKE_MAPPINGS": str(owner)})
            self.assertEqual((facts["volume"], facts["functions"]), ("vol-0abc", ["0000:00:06.0", "0000:00:1e.0"]))
            self.assertEqual(facts["sha256"], hashlib.sha256(owner.read_bytes()).hexdigest())
            self.assertIsNone(lane.mappings_facts({"KESTRIKE_MAPPINGS": str(client)})["volume"])
            self.assertEqual(facts.get("address"), "10.0.1.5")
            self.assertEqual(lane.mappings_facts({"KESTRIKE_MAPPINGS": str(client)}).get("address"), "10.0.1.7")
            client.write_text("format=3\nnvme.bdf=0000:00:1e.0\n")
            self.assertIsNone(lane.mappings_facts({"KESTRIKE_MAPPINGS": str(client)})["address"])


class PlatformAdmission(unittest.TestCase):
    def test_a_manifest_refusal_is_the_defect_every_host_reads(self):
        """The sweep starts the roles of consecutive profiles `manifest_refusal` refuses on its row at once and charges
        them only their end events, which is safe because `platform_defect` refuses each such role before its build.
        For every support flag and disposition, a manifest refusal is the defect itself whatever host the role runs
        on, and a profile the manifest admits reaches the host checks: a host inside the envelope passes and a host of
        another machine is refused for its machine."""
        lane = lane_module()
        envelope = {**{field: f"approved {field}" for field in lane.OBSERVED}, "cpu_features": ["fpu"],
                    "devices": {"0000:00:1f.0": "0x1d0f:0x0065"},
                    "cpu_family": {"vendor_id": "GenuineIntel", "cpu family": "6", "model": "143"}}
        inside = {**envelope, "machine": "x86_64"}
        foreign = {**inside, "machine": "aarch64"}
        for supported in (True, False):
            for disposition in lane.DISPOSITIONS:
                with self.subTest(supported=supported, disposition=disposition):
                    row = {"machine": "x86_64", "supported": supported, "owner": "owner", "envelope": envelope}
                    profile = {"platforms": {"row": disposition}}
                    refusal = lane.manifest_refusal("row", row, profile)
                    self.assertEqual(refusal is None, supported and disposition == "runs")
                    if refusal is not None:
                        self.assertTrue(refusal.startswith("Inconclusive: "), refusal)
                        for host in (inside, foreign):
                            self.assertEqual(lane.platform_defect("row", row, profile, host), refusal)
                    else:
                        self.assertIsNone(lane.platform_defect("row", row, profile, inside))
                        self.assertIn("names machine x86_64, not the host's 'aarch64'",
                                      lane.platform_defect("row", row, profile, foreign))


class HostFacts(unittest.TestCase):
    def test_the_cpu_features_are_those_every_processor_record_reports(self):
        """A feature one processor record lacks is no host feature, so the envelope's `cpu_features` must hold on
        every processor, as the architecture qualification lanes require; a `vmx flags` line names no CPU feature."""
        lane = lane_module()
        real = lane.read
        x86 = "flags\t\t: fpu sse4_2 pclmulqdq avx512f vpclmulqdq\nvmx flags\t: ept\n"
        arm = "Features\t: fp asimd aes pmull\n"
        for cpuinfo, features in (
            (f"processor\t: 0\n{x86}\nprocessor\t: 1\n{x86.replace(' vpclmulqdq', '')}",
             ["avx512f", "fpu", "pclmulqdq", "sse4_2"]),
            (f"processor\t: 0\n{x86}\nprocessor\t: 1\n{x86}", ["avx512f", "fpu", "pclmulqdq", "sse4_2", "vpclmulqdq"]),
            (f"processor\t: 0\n{arm}", ["aes", "asimd", "fp", "pmull"]),
            (f"processor\t: 0\n{arm}\nprocessor\t: 1\n", []),
            (f"processor\t: 0\n{arm}\nprocessor 1\n{arm}", []),
            ("processor\t: 0\n", []),
        ):
            with self.subTest(cpuinfo=cpuinfo):
                lane.read = lambda path, cpuinfo=cpuinfo: cpuinfo if path == "/proc/cpuinfo" else real(path)
                self.assertEqual(sorted(lane.host_facts()["cpu_features"]), features)


    def test_the_cpu_family_is_the_identity_every_processor_record_reports(self):
        """The CPU family is the raw identity lines every processor record reports: MIDR implementer and part on
        aarch64, whose cpuinfo has no `model name` line, and vendor, family and model on x86_64. No processor
        record, records that disagree, a record that repeats, lacks or blanks a line, or a machine with no identity
        lines leave it unreadable, which no envelope matches; the CPU model falls back to the same lines."""
        lane = lane_module()
        reproducer = lane.reproducer
        core = ("processor\t: {n}\nBogoMIPS\t: 2000.00\nFeatures\t: fp asimd aes pmull\nCPU implementer\t: 0x41\n"
                "CPU architecture: 8\nCPU variant\t: 0x0\nCPU part\t: {part}\nCPU revision\t: 1\n")
        arm = "\n".join(core.format(n=n, part="0xd4f") for n in range(2))
        x86 = "processor\t: 0\nvendor_id\t: GenuineIntel\ncpu family\t: 6\nmodel\t\t: 143\nmodel name\t: Xeon\n"
        graviton = {"CPU implementer": "0x41", "CPU part": "0xd4f"}
        self.assertNotIn("model name", arm)
        real = lane.read
        for cpuinfo, machine, family in (
            (arm, "aarch64", graviton),
            (core.format(n=0, part="0xd4f") + "\n" + core.format(n=1, part="0xd40"), "aarch64", None),
            (core.format(n=0, part="0xd40") + core.format(n=1, part="0xd4f"), "aarch64", None),
            (arm.replace("CPU part\t: 0xd4f\n", "CPU part\t: 0xd4f\nCPU part\t: 0xd4f\n"), "aarch64", None),
            (arm.replace("CPU part\t: 0xd4f\n", "", 1), "aarch64", None),
            (arm.replace("CPU part\t: 0xd4f\n", ""), "aarch64", None),
            (arm.replace("CPU part\t: 0xd4f\n", "CPU part\t:\n"), "aarch64", None),
            (arm.replace("processor\t: 1\n", "processor 1\n"), "aarch64", None),
            ("", "aarch64", None),
            (arm, "riscv64", None),
            (x86, "x86_64", {"vendor_id": "GenuineIntel", "cpu family": "6", "model": "143"}),
        ):
            with self.subTest(machine=machine, family=family, cpuinfo=cpuinfo[:40]):
                self.assertEqual(reproducer.cpu_identity(cpuinfo, machine), family)
                with mock.patch.object(lane.platform, "machine", return_value=machine), \
                        mock.patch.object(lane.platform, "processor", return_value="fallback"), \
                        mock.patch.object(lane, "read", side_effect=lambda path, cpuinfo=cpuinfo:
                                          cpuinfo if path == "/proc/cpuinfo" else real(path)):
                    host = lane.host_facts()
                    self.assertEqual(host["cpu_family"], family or "unreadable")
                    self.assertEqual(host["cpu"], reproducer.cpu_model(cpuinfo), "one cpuinfo read feeds both")
        for cpuinfo, machine, model in (
            (arm, "aarch64", "CPU implementer 0x41, CPU part 0xd4f"),
            (x86, "x86_64", "Xeon"),
            (x86.replace("Xeon", ""), "x86_64", "vendor_id GenuineIntel, cpu family 6, model 143"),
            (x86.replace("model name\t: Xeon", "model name"), "x86_64", "vendor_id GenuineIntel, cpu family 6, model 143"),
            (x86 + "model name\t: Xeon\n", "x86_64", "fallback"),
            ("", "aarch64", "fallback"),
        ):
            with self.subTest(model=model), mock.patch.object(reproducer.platform, "machine", return_value=machine), \
                    mock.patch.object(reproducer.platform, "processor", return_value="fallback"):
                self.assertEqual(reproducer.cpu_model(cpuinfo), model)
        with mock.patch.object(reproducer.platform, "machine", return_value="aarch64"), \
                mock.patch.object(reproducer.Path, "read_text", return_value=arm):
            self.assertEqual(reproducer.cpu_model(), "CPU implementer 0x41, CPU part 0xd4f")
        with mock.patch.object(reproducer.Path, "read_text", side_effect=OSError), \
                mock.patch.object(reproducer.platform, "processor", return_value=""):
            self.assertEqual(reproducer.cpu_model(), "unknown")


class ReadinessWait(unittest.TestCase):
    """`wait_after` judges a predecessor's readiness and end from one snapshot of the observer log."""

    def test_the_wait_counts_every_predecessor_case_deadline_and_its_observer_waits(self):
        """Over the shipped manifest: one predecessor case for `host-pair/client`, two for the two-owner clients."""
        lane = lane_module()
        manifest = json.loads(MANIFEST.read_text())
        allowance = lane.OBSERVER_OPERATIONS * lane.OBSERVER_SECONDS
        self.assertEqual(lane.readiness_wait(manifest["profiles"]["host-pair"], "client"), 1800 + allowance)
        self.assertEqual(lane.readiness_wait(manifest["profiles"]["host-pair-two-owners"], "client-a"), 2 * (1800 + allowance))
        self.assertEqual(lane.readiness_wait(manifest["profiles"]["host-pair"], "owner"), 0)

    def test_a_readiness_published_just_before_the_end_still_acknowledges(self):
        """Between two separate reads a predecessor can publish readiness and end; the later read alone sees the end."""
        lane = lane_module()
        ready = {"profile": "host-pair", "role": "owner", "kind": "ready", "ordinal": 1}
        end = {"profile": "host-pair", "role": "owner", "kind": "end", "ordinal": 2}

        class Snapshots(lane.Observer):
            def __init__(self):
                super().__init__(None, "snap", "host-pair", "client")
                self.snapshots = [[], [ready, end]]

            def events(self):
                return self.snapshots.pop(0) if len(self.snapshots) > 1 else self.snapshots[0]

            def append(self, kind, **fields):
                return {"kind": kind, **fields}

        waiter = types.SimpleNamespace(role={"after": "owner"}, wait=5, terminated=None, observer=Snapshots())
        ack = lane.Lane.wait_after(waiter, {"id": CLIENT, "deadline": 5})
        self.assertIsNotNone(ack, "the readiness the log holds is acknowledged, whichever read first saw the end")
        self.assertEqual(ack["acknowledges"], 1)


class StopProof(unittest.TestCase):
    """`group_running` reads every task of a member: `/proc/<pid>/stat` alone reports the thread-group leader."""

    def test_a_hold_proves_the_group_stopped_before_it_reports_custody(self):
        """`hold` is the path a lane error takes; it owes the operator the same stop proof as containment."""
        lane = lane_module()
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"], start_new_session=True)
        self.addCleanup(lambda: (os.killpg(process.pid, signal.SIGKILL), process.wait()))
        holder = lane.Lane.__new__(lane.Lane)
        holder.held = []
        custody = Path(tempfile.mkdtemp(prefix="hardware-lane-custody-"))
        self.addCleanup(shutil.rmtree, custody)
        holder.args = types.SimpleNamespace(custody=str(custody), episode="proof", profile="spdk-volume", role="owner")
        entry = {"id": CONTRACT}
        holder.hold(entry, process)
        marker = json.loads((custody / f"{process.pid}.json").read_text())
        self.assertEqual((marker["pgid"], marker["custody"]), (process.pid, entry["custody"]), "the held group leaves its marker")
        self.assertEqual(entry["stopped"], "every member stopped before custody was reported")
        self.assertEqual(lane.group_running(process.pid), [], "the hold returned only once the group had stopped")
        self.assertIn("held: process group", entry["custody"])
        self.assertEqual(holder.held, [(process.pid, entry["custody"])])
        lane.stopped = lambda pgid, limit: [pgid + 1]
        holder.held, entry = [], {"id": CONTRACT}
        holder.hold(entry, process)
        self.assertIn("still running", entry["stopped"])
        self.assertTrue(entry["custody"].startswith("unknown:"), "a member still running is no stopped group")
        self.assertNotIn("stopped until", entry["custody"])
        self.assertEqual(holder.held, [(process.pid, entry["custody"])], "the operator still owns the group, told what was proved")

    def test_a_kill_of_a_group_that_already_ended_sends_nothing_and_marks_nothing(self):
        """The case ended between the supervisor's last poll and its kill: there is nothing to kill, so the host's
        kill marker is not written and the case's exit stands for the judge to refuse."""
        lane = lane_module()
        process = subprocess.Popen([sys.executable, "-c", "pass"], start_new_session=True)
        process.wait()
        killer = lane.Lane.__new__(lane.Lane)
        custody = Path(tempfile.mkdtemp(prefix="hardware-lane-custody-"))
        self.addCleanup(shutil.rmtree, custody)
        killer.args = types.SimpleNamespace(custody=str(custody), episode="ended", profile="p", role="owner-a")
        entry = {"id": CONTRACT}
        self.assertEqual(killer.kill({"id": CONTRACT, "grace": 1}, entry, process, {}), 0)
        self.assertNotIn("killed", entry)
        self.assertEqual(list(custody.glob("*.json")), [], "no marker for a kill that was never sent")
        # The group ends between the check and the signal: the signal finds no group, so the marker written for it
        # is removed again and no kill is recorded.
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"], start_new_session=True)
        self.addCleanup(lambda: (os.killpg(live.pid, signal.SIGKILL), live.wait()))
        import unittest.mock
        with unittest.mock.patch.object(lane.os, "killpg", side_effect=ProcessLookupError):
            killer.kill({"id": CONTRACT, "grace": 1}, entry, live, {})
        self.assertNotIn("killed", entry)
        self.assertEqual(list(custody.glob("*.json")), [], "the marker for a signal that found no group is removed")

    def test_a_member_runs_while_any_of_its_tasks_runs(self):
        lane = lane_module()
        with tempfile.TemporaryDirectory(prefix="proc-") as root:
            proc = Path(root)
            (proc / "self").mkdir()
            for pid, states in ((300, ["T", "T"]), (301, ["T", "R"]), (302, ["Z"]), (400, ["R"])):
                (proc / str(pid) / "task").mkdir(parents=True)
                pgid = 300 if pid < 400 else 400
                (proc / str(pid) / "stat").write_text(f"{pid} (kestrike) {states[0]} 1 {pgid} {pgid} 0 -1\n")
                for n, state in enumerate(states):
                    task = proc / str(pid) / "task" / str(pid + 100 * n)
                    task.mkdir()
                    (task / "stat").write_text(f"{pid + 100 * n} (kestrike) {state} 1 {pgid} {pgid} 0 -1\n")
            self.assertEqual(lane.group_running(300, proc), [301], "a stopped leader with a running test thread still runs")
            self.assertEqual(lane.group_running(400, proc), [400])
            self.assertEqual(lane.group_running(500, proc), [])


class Lane(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        """No lane test may touch the host's custody directory: every run and sweep names one under its own state."""
        cls.host_custody = Path(lane_module().CUSTODY_DIR)
        cls.host_custody_existed = cls.host_custody.exists()

    @classmethod
    def tearDownClass(cls):
        if not cls.host_custody_existed:
            assert not cls.host_custody.exists(), f"a test created {cls.host_custody}; pass --custody under the fake state"

    def kill_held(self):
        """Ends every process a test left behind: recorded helpers and any case still running from the fake state."""
        for path in [*self.state.glob("*.grandchild"), *self.state.glob("*.pid")]:
            with contextlib.suppress(ProcessLookupError, ValueError):
                pid = int(path.read_text())
                os.killpg(os.getpgid(pid), signal.SIGKILL)
        for pid in os.listdir("/proc"):
            if pid.isdigit() and str(self.state).encode() in self.cmdline(pid):
                with contextlib.suppress(ProcessLookupError):
                    os.kill(int(pid), signal.SIGKILL)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hardware-lane-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.addCleanup(self.kill_held)
        (self.state / "pkg").mkdir()
        for name, text in (("kestrike-fake", EXECUTABLE), ("cargo", CARGO)):
            (self.state / name).write_text(text)
            (self.state / name).chmod(0o755)
        self.manifest = json.loads(MANIFEST.read_text())
        self.manifest["platforms"]["x86_64-nitro-ebs"].update(supported=True, machine=platform.machine(),
                                                               envelope=host_envelope())
        for profile in self.manifest["profiles"].values():
            for role in profile["roles"].values():
                for case in role["cases"]:
                    case.update(deadline=20, grace=2)
        self.plan({})
        self.env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                        KESTRIKE_PEER="10.0.1.9", KESTRIKE_IDLE_OBSERVATION_MS="1",
                        KESTRIKE_RECOVERY_DEADLINE_MS="5000")
        self.mappings_file(self.state / "mappings")
        self.env.pop("KESTRIKE_HARDWARE_ROLES", None)
        self.env["KESTRIKE_HARDWARE_PLATFORM"] = "x86_64-nitro-ebs"
        # The lane runs in its own clean checkout, as a CI job does, so a receipt's tree state and revision are real.
        self.checkout = self.state / "checkout"
        self.checkout.mkdir()
        (self.checkout / "tracked").write_text("tracked\n")
        git = ["git", "-c", "user.name=lane", "-c", "user.email=lane@example", "-c", "commit.gpgsign=false"]
        for command in (["init", "-q"], ["add", "tracked"], ["commit", "-q", "-m", "tracked"]):
            subprocess.run([*git, *command], cwd=self.checkout, check=True, capture_output=True)
        self.revision = subprocess.run(["git", "rev-parse", "HEAD"], cwd=self.checkout, check=True,
                                       capture_output=True, text=True).stdout.strip()

    def plan(self, cases):
        (self.state / "plan.json").write_text(json.dumps({"cases": cases}))

    def write_manifest(self):
        path = self.state / "manifest.json"
        path.write_text(json.dumps(self.manifest))
        return path

    def start(self, *args):
        argv = [sys.executable, str(SCRIPT), *args, "--manifest", str(self.write_manifest())]
        if args[0] != "judge":
            argv += ["--cargo", str(self.state / "cargo")]
        elif "--revision" not in args:
            argv += ["--revision", self.revision]
        if args[0] in ("run", "sweep"):
            argv += ["--artifacts", str(self.state / "artifacts"), "--custody", str(self.state / "custody")]
        return subprocess.Popen(argv, cwd=self.checkout, env=self.env, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)

    def lane(self, *args):
        process = self.start(*args)
        out, err = process.communicate(timeout=120)
        return process.returncode, out, err

    def receipt(self, err):
        """The receipt a run names: its hardware section and its path."""
        path = next(line.split(": ", 1)[1] for line in err.splitlines() if line.startswith("receipt: "))
        return json.loads(Path(path).read_text())["hardware"], path

    def test_the_lane_credits_exactly_the_declared_cases_with_their_hash_counts_and_witnesses(self):
        self.env["RUNNER_TRACKING_ID"] = "github_job_1"
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section, _ = self.receipt(err)
        self.assertTrue(section["credited"])
        self.assertIsNone(section["first_failure"])
        self.assertEqual(section["executable"]["sha256"],
                         hashlib.sha256((self.state / "kestrike-fake").read_bytes()).hexdigest())
        self.assertEqual([(case["id"], case["listed"], case["ignored"], case["executed"]) for case in section["cases"]],
                         [(CONTRACT, 1, 1, 1), (STOPS, 1, 1, 1)])
        self.assertEqual(section["cases"][0]["inputs"]["KESTRIKE_MAPPINGS"], str(self.state / "mappings"))
        self.assertEqual(len((self.state / "builds.txt").read_text().splitlines()), 1, "one build")
        self.assertEqual(len((self.state / "runs.txt").read_text().splitlines()), 2, "one attempt per case")
        self.assertIsNone(json.loads((self.state / f"{CONTRACT}.env.json").read_text())["RUNNER_TRACKING_ID"],
                          "the runner's orphan cleanup cannot find a case, so a held group outlives the job")
        self.assertEqual([str(path) for path in (self.state / "artifacts").rglob("*") if ":" in path.name], [],
                         "upload-artifact refuses a file path holding a colon")

    def test_the_judge_credits_only_retained_witness_counts_that_meet_the_current_manifest_it_names(self):
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section, receipt = self.receipt(err)
        manifest = self.write_manifest()
        self.assertEqual(section["manifest_sha256"], hashlib.sha256(manifest.read_bytes()).hexdigest())
        declared = self.manifest["profiles"]["spdk-volume-stop"]["roles"]["owner"]["cases"]
        self.assertEqual([case["witness_counts"] for case in section["cases"]],
                         [{witness: 1 for witness in case["witnesses"]} for case in declared])
        code, out, _ = self.lane("judge", "--profile", "spdk-volume-stop", receipt)
        self.assertEqual(code, 0, "a valid receipt credits under its unchanged manifest: " + out)

        def judge(edit):
            forged = json.loads(Path(receipt).read_text())
            edit(forged["hardware"])
            path = self.state / "forged.json"
            path.write_text(json.dumps(forged))
            return self.lane("judge", "--profile", "spdk-volume-stop", str(path))

        first = declared[0]
        for name, edit, reason in (
            ("a foreign manifest digest", lambda section: section.update(manifest_sha256="0" * 64),
             f"ran under manifest_sha256 '{'0' * 64}', not the current manifest's"),
            ("no manifest digest", lambda section: section.pop("manifest_sha256"), "records no manifest_sha256"),
            ("no witness counts", lambda section: section["cases"][0].pop("witness_counts"), "records no witness_counts"),
            ("an empty deficit beside an unseen witness",
             lambda section: section["cases"][0].update(witness_counts={first["witnesses"][0]: 0}, missing_witnesses=[]),
             f"lacks witnesses {first['witnesses']}"),
            ("an empty deficit beside an unrecorded witness",
             lambda section: section["cases"][0].update(witness_counts={}, missing_witnesses=[]),
             f"lacks witnesses {first['witnesses']}"),
            ("a witness count as a flag",
             lambda section: section["cases"][0].update(witness_counts={first["witnesses"][0]: True}),
             f"lacks witnesses {first['witnesses']}"),
        ):
            with self.subTest(name):
                code, out, _ = judge(edit)
                self.assertEqual(code, 1, name)
                self.assertIn(reason, out, name)

        added = "late witness: "
        first["witnesses"].append(added)
        current = hashlib.sha256(self.write_manifest().read_bytes()).hexdigest()
        code, out, _ = self.lane("judge", "--profile", "spdk-volume-stop", receipt)
        self.assertEqual(code, 1, "a witness the manifest added after the run uncredits the receipt: " + out)
        self.assertIn(f"lacks witnesses {[added]!r}", out)
        self.assertIn(f"not the current manifest's {current}", out)
        # Rebinding the receipt to the current manifest leaves the added witness as the one reason.
        code, out, _ = judge(lambda section: section.update(manifest_sha256=current))
        self.assertEqual(code, 1, out)
        self.assertIn(f"lacks witnesses {[added]!r}", out)
        self.assertNotIn("manifest_sha256", out)
        # The producer records zero in `witness_counts` for each declared witness absent from the case output.
        self.plan({CONTRACT: {"outcome": "bare"}})
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertEqual(section["cases"][0]["witness_counts"], {witness: 0 for witness in first["witnesses"]})

    def test_the_receipt_records_the_mappings_digest_again_when_the_case_ends(self):
        """The lane digests the mappings file before it spawns the case and again when the case ends, so a file
        replaced in between shows as two digests in the receipt; the lane's own credit reads the first alone."""
        before = (self.state / "mappings").read_text()
        after = before + "eni.mtu=9001\n"
        self.plan({OUTCOME: {"rewrite_mappings": after}})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        entry = self.receipt(err)[0]["cases"][0]
        self.assertEqual(entry["mappings"]["sha256"], hashlib.sha256(before.encode()).hexdigest())
        self.assertEqual(entry.get("mappings_after"), hashlib.sha256(after.encode()).hexdigest())
        self.plan({})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        entry = self.receipt(err)[0]["cases"][0]
        self.assertEqual(entry.get("mappings_after"), entry["mappings"]["sha256"])

    def test_a_launched_role_credits_only_under_the_identity_its_caller_supplied(self):
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section, receipt = self.receipt(err)
        lane = lane_module()
        manifest, document = self.write_manifest(), json.loads(Path(receipt).read_text())
        path = self.state / "mappings"
        mappings = lane.mappings_facts({"KESTRIKE_MAPPINGS": str(path)})
        self.assertEqual((mappings["path"], mappings["sha256"], mappings["format"]),
                         (str(path), hashlib.sha256(path.read_bytes()).hexdigest(), "3"))
        self.assertEqual(section["cases"][0]["mappings"], mappings)
        launched = {"profile": "spdk-volume-stop", "role": "owner", "episode": section["episode"],
                    "revision": self.revision, "mappings": mappings}
        self.assertEqual(lane.judge_launch(manifest, document, launched), [])
        for name, value in (("profile", "spdk-volume"), ("role", "client"), ("episode", "e9"), ("revision", "f" * 40),
                            ("mappings", {**mappings, "sha256": "0" * 64})):
            with self.subTest(name):
                reasons = lane.judge_launch(manifest, document, {**launched, name: value})
                self.assertTrue(reasons and f"not the launched {value!r}" in reasons[0], reasons)
        forged = json.loads(json.dumps(document))
        forged["hardware"]["cases"][0]["witness_counts"] = {}
        self.assertIn("lacks witnesses", " ".join(lane.judge_launch(manifest, forged, launched)),
                      "the launched identity alone earns nothing: the evidence is judged as `judge` judges it")
        forged = json.loads(json.dumps(document))
        forged["hardware"]["cases"][0].pop("mappings")
        self.assertIn(f"records mappings [None, {forged['hardware']['cases'][1]['mappings']!r}], not the launched",
                      lane.judge_launch(manifest, forged, launched)[0])
        for name in ("profile", "role", "episode", "revision"):
            with self.subTest(f"no {name}"):
                forged["hardware"] = {key: value for key, value in document["hardware"].items() if key != name}
                self.assertIn(f"names {name} None, not the launched {launched[name]!r}",
                              lane.judge_launch(manifest, forged, launched)[0])
        # Registry coverage is required even when the receipt's manifest digest matches.
        del self.manifest["profiles"]["prerequisites"]
        uncovered = self.write_manifest()
        forged = json.loads(json.dumps(document))
        forged["hardware"]["manifest_sha256"] = hashlib.sha256(uncovered.read_bytes()).hexdigest()
        with self.assertRaisesRegex(lane.Stop, "hardware-privileged registry rows differ"):
            lane.judge_launch(uncovered, forged, launched)

    def test_each_defect_leaves_the_role_uncredited_and_the_first_failure_persists(self):
        defects = {
            "zero listed": ({"listed": 0}, "listed 0"),
            "duplicate": ({"listed": 2, "ignored": 2}, "listed 2"),
            "not ignored": ({"ignored": 0}, "ignored 0"),
            "failure": ({"outcome": "fail"}, "exited 101"),
            "zero executed": ({"outcome": "zero"}, "0 passed"),
            "count only": ({"outcome": "double"}, "2 passed"),
            "missing witness": ({"outcome": "bare"}, "lacks witnesses"),
            "another test's count": ({"outcome": "stray"}, "lacks witnesses"),
        }
        for name, (case, reason) in defects.items():
            with self.subTest(name):
                self.plan({CONTRACT: case})
                code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
                self.assertEqual(code, 1, out + err)
                section, _ = self.receipt(err)
                self.assertFalse(section["credited"])
                self.assertIn(CONTRACT, section["first_failure"])
                self.assertIn(reason, section["first_failure"])
                self.assertEqual([case["id"] for case in section["cases"]], [CONTRACT], "the role ends at its first failure")
                runs = self.state / "runs.txt"
                self.assertNotIn(STOPS, runs.read_text() if runs.exists() else "", "the later case never ran")

    def test_a_modified_tree_builds_and_runs_nothing(self):
        """`judge` credits only a clean tree, so a run from a modified one would spend the devices for no evidence."""
        (self.checkout / "tracked").write_text("modified\n")
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertTrue(section["dirty"])
        self.assertIn("modified tree", section["first_failure"])
        self.assertFalse((self.state / "builds.txt").exists(), "a modified tree builds nothing")
        self.assertFalse((self.state / "runs.txt").exists(), "a modified tree runs no case")

    def test_an_untracked_file_outside_the_artifacts_builds_and_runs_nothing(self):
        """An untracked build input changes what the revision names; the lane's own artifacts are the one exception."""
        (self.checkout / "build-input.toml").write_text("stray\n")
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertEqual(section["untracked"], ["build-input.toml"])
        self.assertIn("untracked", section["first_failure"])
        self.assertFalse((self.state / "builds.txt").exists(), "an untracked input builds nothing")
        (self.checkout / "build-input.toml").unlink()
        def run_with_artifacts(artifacts):
            argv = [sys.executable, str(SCRIPT), "run", "--profile", "spdk-volume", "--role", "owner", "--manifest",
                    str(self.write_manifest()), "--cargo", str(self.state / "cargo"), "--artifacts", artifacts,
                    "--custody", str(self.state / "custody")]
            process = subprocess.Popen(argv, cwd=self.checkout, env=self.env, stdout=subprocess.PIPE,
                                       stderr=subprocess.PIPE, text=True)
            out, err = process.communicate(timeout=120)
            return process.returncode, out, err

        code, out, err = run_with_artifacts("evidence/hardware")
        self.assertEqual(code, 0, out + err)
        section, path = self.receipt(err)
        self.assertEqual(section["artifacts"], "evidence/hardware")
        self.assertTrue(section["untracked"] and all(entry.startswith("evidence/hardware/") for entry in section["untracked"]),
                        f"the untracked record lists the files under the collapsed `evidence/` entry: {section['untracked']}")
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", path)
        self.assertEqual(code, 0, out)
        forged = json.loads(Path(path).read_text())
        forged["hardware"]["untracked"].append("evidence/stray.toml")
        Path(path).write_text(json.dumps(forged))
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", path)
        self.assertEqual(code, 1, "a file beside the artifacts under the same untracked parent is an input")
        self.assertIn("untracked", out)
        (self.checkout / "evidence" / "stray.toml").write_text("stray\n")
        code, out, err = run_with_artifacts("evidence/hardware")
        self.assertEqual(code, 1, out + err)
        self.assertIn("evidence/stray.toml", self.receipt(err)[0]["first_failure"])
        (self.checkout / "evidence" / "stray.toml").unlink()
        code, out, err = run_with_artifacts(".")
        self.assertEqual(code, 1, out + err)
        self.assertIn("untracked", self.receipt(err)[0]["first_failure"], "the checkout itself is no artifacts directory")

    def test_the_disk_contract_cases_declare_their_idle_observation_interval(self):
        """The profile that runs the shared disk contract on the bound volume names the idle observation interval
        as a case input, so a role file without the platform owner's interval leaves the role uncredited."""
        contract = "storage::device::spdk::hardware_tests::the_spdk_driver_meets_the_disk_contract"
        cases = [(name, case) for name, profile in json.loads(MANIFEST.read_text())["profiles"].items()
                 for role in profile["roles"].values() for case in role["cases"] if case["id"] == contract]
        self.assertEqual([name for name, _ in cases], ["spdk-volume-stop"])
        for name, case in cases:
            self.assertIn("KESTRIKE_IDLE_OBSERVATION_MS", case["inputs"], name)
        del self.env["KESTRIKE_IDLE_OBSERVATION_MS"]
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn("lacks inputs ['KESTRIKE_IDLE_OBSERVATION_MS']", self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "a role without the interval runs no case")

    def test_a_host_outside_the_approved_envelope_builds_nothing_and_its_receipt_never_credits(self):
        """The run refuses a host whose observed fact differs from the platform row's approved envelope before any
        build, and the judge refuses a credited receipt whose recorded host differs from the row in any observed
        field; a supported row whose envelope leaves a field unfilled is a malformed manifest."""
        lane = lane_module()
        row = self.manifest["platforms"]["x86_64-nitro-ebs"]
        approved = dict(row["envelope"])
        bdf = next(iter(approved["devices"]))
        changes = {"instance_type": f"not {approved['instance_type']}",
                   "cpu_features": [*approved["cpu_features"], "no-such-feature"],
                   "cpu_family": {line: f"not {value}" for line, value in approved["cpu_family"].items()},
                   "kernel": f"not {approved['kernel']}", "firmware": f"not {approved['firmware']}",
                   "vfio": "noiommu" if approved["vfio"] != "noiommu" else "iommu",
                   "numa_nodes": f"not {approved['numa_nodes']}", "page_size": approved["page_size"] * 2,
                   "hugepage_size": f"not {approved['hugepage_size']}", "devices": {bdf: "0xffff:0xffff"}}
        self.assertEqual(set(changes), set(lane.OBSERVED))
        self.assertTrue(all(value != approved[field] for field, value in changes.items()), changes)
        for field, value in changes.items():
            with self.subTest(field=field):
                row["envelope"] = {**approved, field: value}
                code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
                self.assertEqual(code, 1, out + err)
                failure = self.receipt(err)[0]["first_failure"]
                self.assertIn("outside platform row x86_64-nitro-ebs's envelope", failure)
                self.assertIn(field, failure)
                self.assertFalse((self.state / "builds.txt").exists(), f"a host outside the envelope builds nothing: {field}")
        row["envelope"] = approved
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        _, receipt = self.receipt(err)
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", receipt)
        self.assertEqual(code, 0, out)
        for field, value in changes.items():
            with self.subTest(judged=field):
                forged = json.loads(Path(receipt).read_text())
                forged["hardware"]["host"][field] = value if field != "cpu_features" else approved["cpu_features"][:1]
                path = self.state / f"outside-{field}.json"
                path.write_text(json.dumps(forged))
                code, out, _ = self.lane("judge", "--profile", "spdk-volume", str(path))
                self.assertEqual(code, 1, field)
                self.assertIn("outside platform row x86_64-nitro-ebs's envelope", out, field)
                self.assertIn(field, out)
        for field, value, reason in (("volume", None, "short of ['volume']"),
                                     ("devices", {bdf: None}, "short of ['devices']"),
                                     ("kernel", "unreadable", "short of ['kernel']"),
                                     ("kernal", "6.12", "envelope")):
            with self.subTest(malformed=field):
                row["envelope"] = {**approved, field: value}
                code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
                self.assertEqual(code, 2, out + err)
                self.assertIn(reason, out + err)
        # The baseline's observed values match independent reads of this host.
        self.assertEqual((approved["kernel"], approved["page_size"]), (os.uname().release, mmap.PAGESIZE))
        sysfs = Path("/sys/bus/pci/devices") / bdf
        self.assertEqual(approved["devices"][bdf],
                         f"{(sysfs / 'vendor').read_text().strip()}:{(sysfs / 'device').read_text().strip()}")

    def test_a_case_whose_mappings_bind_a_function_outside_the_envelope_runs_nothing_and_never_credits(self):
        """The envelope's devices name the PCI functions the platform owner approves, so a case whose mappings file
        binds any other function runs no device work, and the judge refuses a receipt whose recorded mappings bind
        one or record no bound function."""
        declared, undeclared = pci_function(), "0000:ff:1f.7"
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section, receipt = self.receipt(err)
        self.assertEqual(section["cases"][0]["mappings"]["functions"], [declared])
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", receipt)
        self.assertEqual(code, 0, out)
        (self.state / "runs.txt").unlink()
        (self.state / "mappings").write_text(f"format=3\nnvme.bdf={declared}\neni.bdf={undeclared}\n")
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn(f"binds PCI functions ['{undeclared}'] outside platform row x86_64-nitro-ebs's envelope",
                      self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "a case binding an undeclared function runs no device work")
        for name, edit, reason in (
            ("an undeclared function", lambda case: case["mappings"].update(functions=[declared, undeclared]),
             f"binds PCI functions ['{undeclared}'] outside platform row x86_64-nitro-ebs's envelope"),
            ("no bound function", lambda case: case["mappings"].update(functions=[]), "records no PCI function"),
            ("no record of bound functions", lambda case: case["mappings"].pop("functions"), "records no PCI function"),
            ("mappings that are no record", lambda case: case.update(mappings="mappings"), "no mappings identity"),
        ):
            with self.subTest(judged=name):
                forged = json.loads(Path(receipt).read_text())
                edit(forged["hardware"]["cases"][0])
                path = self.state / f"mapped-{len(name)}.json"
                path.write_text(json.dumps(forged))
                code, out, _ = self.lane("judge", "--profile", "spdk-volume", str(path))
                self.assertEqual(code, 1, name)
                self.assertIn(reason, out, name)

    def test_each_r8gb_size_has_its_own_unsupported_aarch64_row_and_every_profile_a_disposition_there(self):
        """The checked-in manifest holds one aarch64 row per r8gb size, each unsupported until the platform owner
        approves it, and every profile names its disposition on every row: each runs on the x86_64 row except the
        warm-cycle packages, which are pending on every row because their tenures run under fixture authority and
        the process-kill case kills a device-holding child outside the lane's kill custody; the FIS profiles, whose
        job routes to x64 hosts alone, are excluded from the aarch64 rows, and every other profile is pending
        there."""
        manifest = json.loads(MANIFEST.read_text())
        arm = {name: row for name, row in manifest["platforms"].items() if row["machine"] == "aarch64"}
        self.assertEqual(sorted(arm), ["aarch64-r8gb-4xlarge-ebs", "aarch64-r8gb-8xlarge-ebs"])
        lane = lane_module()
        for name, row in arm.items():
            with self.subTest(row=name):
                self.assertFalse(row["supported"])
                self.assertEqual(set(row["envelope"]), set(lane.ENVELOPE_FIELDS))
        self.assertIn("cpu_family", manifest["platforms"]["x86_64-nitro-ebs"]["envelope"])
        for name, profile in manifest["profiles"].items():
            with self.subTest(profile=name):
                self.assertEqual(set(profile["platforms"]), set(manifest["platforms"]))
                held = name in ("cr1-controller-reset", "pk1-process-kill")
                self.assertEqual(profile["platforms"]["x86_64-nitro-ebs"], "pending" if held else "runs")
                wanted = "excluded" if name in ("fis-read", "fis-write", "fis-stop") else "pending"
                self.assertEqual({profile["platforms"][row] for row in arm}, {wanted})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner",
                                   "--platform", "aarch64-r8gb-4xlarge-ebs")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(self.receipt(err)[0]["first_failure"],
                         "Inconclusive: platform row unsupported: aarch64-r8gb-4xlarge-ebs")
        self.assertFalse((self.state / "builds.txt").exists(), "a run on an unsupported row builds nothing")
        code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", "owner", "--platform", "no-such-row",
                                 "--episode", "no-such-row", "--observer", str(self.state / "observer"))
        self.assertEqual(code, 2, out)
        self.assertIn("no platform row 'no-such-row'", out)
        events = [json.loads(line) for line in (self.state / "observer" / "no-such-row.jsonl").read_text().splitlines()]
        self.assertEqual([(event["role"], event["kind"], event["status"]) for event in events], [("owner", "end", 2)],
                         "the platform refusal still records the role's end for the roles waiting on it")
        del self.env["KESTRIKE_HARDWARE_PLATFORM"]
        code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 2, out)
        self.assertIn("no platform row named; name the host's row with --platform or KESTRIKE_HARDWARE_PLATFORM", out)
        observer = self.state / "observer"
        (observer / "corrupt.jsonl").write_text("{not json\n")
        code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", "owner", "--platform", "no-such-row",
                                 "--episode", "corrupt", "--observer", str(observer))
        self.assertEqual(code, 2, out)
        self.assertIn("no platform row 'no-such-row'", out, "a malformed observer log keeps the refusal's reason")
        for episode, edit, reason in (
            ("bad-manifest", lambda: self.manifest["profiles"]["spdk-volume"].update(retries=1), "declares retries"),
            ("bad-role", lambda: None, "no role 'nobody'"),
        ):
            with self.subTest(refusal=episode):
                saved = json.loads(json.dumps(self.manifest))
                edit()
                role = "nobody" if episode == "bad-role" else "owner"
                code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", role, "--platform",
                                         "x86_64-nitro-ebs", "--episode", episode, "--observer", str(observer))
                self.manifest.clear()
                self.manifest.update(saved)
                self.assertEqual(code, 2, out)
                self.assertIn(reason, out)
                events = [json.loads(line) for line in (observer / f"{episode}.jsonl").read_text().splitlines()]
                self.assertEqual([(event["role"], event["kind"], event["status"]) for event in events],
                                 [(role, "end", 2)], "a refused manifest or role still records the role's end")
        self.env["KESTRIKE_HARDWARE_ROLES"] = "spdk-volume/owner"
        code, out, _ = self.lane("sweep", "--custody", str(self.state / "custody"))
        self.assertEqual(code, 2, out)
        self.assertIn("no platform row named; name the host's row with --platform or KESTRIKE_HARDWARE_PLATFORM", out)
        code, out, _ = self.lane("sweep", "--custody", str(self.state / "custody"), "--platform", "no-such-row")
        self.assertEqual(code, 2, out)
        self.assertIn("no platform row 'no-such-row'; name the host's row with --platform or KESTRIKE_HARDWARE_PLATFORM",
                      out)
        self.assertFalse((self.state / "builds.txt").exists(), "a host naming no row runs nothing")
        earlier = set(self.state.rglob("receipt.json"))
        code, out, _ = self.lane("sweep", "--custody", str(self.state / "custody"), "--platform", "x86_64-nitro-ebs")
        self.assertEqual(code, 0, out)
        receipts = [json.loads(path.read_text())["hardware"] for path in set(self.state.rglob("receipt.json")) - earlier]
        self.assertEqual([(receipt["profile"], receipt["platform"]["row"]) for receipt in receipts],
                         [("spdk-volume", "x86_64-nitro-ebs")], "the sweep hands its row to each role it runs")

    def test_a_mismatched_machine_cpu_family_or_disposition_builds_nothing_and_reads_inconclusive(self):
        """A row whose machine or CPU family differs from the host, or on which the profile does not run, builds
        nothing and reads `Inconclusive`; the judge recomputes each from the manifest, so an edited or unreadable
        identity in a receipt never credits."""
        lane = lane_module()
        row = self.manifest["platforms"]["x86_64-nitro-ebs"]
        approved = dict(row["envelope"])
        self.assertTrue(approved["cpu_family"] and approved["cpu_family"] not in lane.UNREAD, approved)
        other = {line: f"not {value}" for line, value in approved["cpu_family"].items()}
        machine = "x86_64" if platform.machine() == "aarch64" else "aarch64"
        foreign = dict.fromkeys(lane.reproducer.IDENTITY_LINES[machine], "0x1")
        for name, edit, reason in (
            ("another machine", lambda: row.update(machine=machine, envelope={**approved, "cpu_family": foreign}),
             f"Inconclusive: platform row x86_64-nitro-ebs names machine {machine}, not the host's {platform.machine()!r}"),
            ("another CPU family with identical features", lambda: row["envelope"].update(cpu_family=other),
             "Inconclusive: the host is outside platform row x86_64-nitro-ebs's envelope: the host's cpu_family"),
            ("a pending disposition", lambda: self.manifest["profiles"]["spdk-volume"]["platforms"].update(
                {"x86_64-nitro-ebs": "pending"}),
             "Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is pending"),
            ("an excluded disposition", lambda: self.manifest["profiles"]["spdk-volume"]["platforms"].update(
                {"x86_64-nitro-ebs": "excluded"}),
             "Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is excluded"),
        ):
            with self.subTest(run=name):
                try:
                    edit()
                    code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
                    self.assertEqual(code, 1, out + err)
                    self.assertIn(reason, self.receipt(err)[0]["first_failure"])
                    self.assertFalse((self.state / "builds.txt").exists(), f"{name} builds nothing")
                finally:
                    row.update(machine=platform.machine(), envelope=dict(approved))
                    self.manifest["profiles"]["spdk-volume"]["platforms"]["x86_64-nitro-ebs"] = "runs"
        for name, family in (("no CPU family", None), ("a partial CPU family", dict(list(approved["cpu_family"].items())[1:])),
                             ("a blank CPU family line", dict.fromkeys(approved["cpu_family"], " ")),
                             ("one blank CPU family line", {**approved["cpu_family"], next(iter(approved["cpu_family"])): ""}),
                             ("a padded CPU family line",
                              {line: f" {value}" for line, value in approved["cpu_family"].items()}),
                             ("another machine's CPU family lines", foreign)):
            with self.subTest(envelope=name):
                row["envelope"] = {**approved, "cpu_family": family}
                code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
                self.assertEqual(code, 2, out + err)
                self.assertIn("short of ['cpu_family']", out + err, "a supported row without its CPU family is incomplete")
        row.update(machine="arm64", envelope=dict(approved))
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 2, out + err)
        self.assertIn("names machine 'arm64', which has no CPU identity lines", out + err)
        row.update(machine=platform.machine(), envelope=dict(approved))
        host = lane.host_facts({"envelope": approved})
        self.assertEqual(host["cpu_family"], approved["cpu_family"])
        self.assertIn("cpu_family 'unreadable'",
                      lane.platform_defect("x86_64-nitro-ebs", row, self.manifest["profiles"]["spdk-volume"],
                                           {**host, "cpu_family": "unreadable"}))
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        self.assertIn("spdk-volume/owner: credited on platform row x86_64-nitro-ebs\n", out)
        _, receipt = self.receipt(err)
        for name, value in (("an edited identity", other), ("an unreadable identity", "unreadable"),
                            ("no identity", None)):
            with self.subTest(judged=name):
                forged = json.loads(Path(receipt).read_text())
                forged["hardware"]["host"]["cpu_family"] = value
                path = self.state / f"family-{len(name)}.json"
                path.write_text(json.dumps(forged))
                code, out, _ = self.lane("judge", "--profile", "spdk-volume", str(path))
                self.assertEqual(code, 1, name)
                self.assertIn("Inconclusive: the host is outside platform row x86_64-nitro-ebs's envelope: "
                              "the host's cpu_family", out, name)
        for name, edit, reason in (
            ("another machine", lambda hardware: hardware["host"].update(machine=machine),
             f"Inconclusive: platform row x86_64-nitro-ebs names machine {platform.machine()}, not the host's {machine!r}"),
            ("no machine", lambda hardware: hardware["host"].pop("machine"),
             f"names machine {platform.machine()}, not a host that records no machine"),
            ("a host that is no object", lambda hardware: hardware.update(host="x86_64"),
             f"names machine {platform.machine()}, not a host that records no machine"),
            ("no platform row", lambda hardware: hardware["platform"].pop("row"), "the receipt names no platform row"),
            ("a list platform row", lambda hardware: hardware["platform"].update(row=["x86_64-nitro-ebs"]),
             "the receipt names no platform row"),
            ("a platform that is no object", lambda hardware: hardware.update(platform="x86_64-nitro-ebs"),
             "the receipt names no platform row"),
            ("numeric CPU features", lambda hardware: hardware["host"].update(cpu_features=7),
             "the host lacks the envelope's cpu_features"),
            ("unhashable CPU features", lambda hardware: hardware["host"].update(cpu_features=[["fpu"]]),
             "the host lacks the envelope's cpu_features"),
            ("devices that are no object", lambda hardware: hardware["host"].update(devices=["0000:00:1f.0"]),
             "the host's devices"),
            ("an unknown platform row", lambda hardware: hardware["platform"].update(row="no-such-row"),
             "the receipt names no platform row of the manifest: 'no-such-row'"),
        ):
            with self.subTest(judged=name):
                forged = json.loads(Path(receipt).read_text())
                edit(forged["hardware"])
                path = self.state / f"forged-{name.replace(' ', '-')}.json"
                path.write_text(json.dumps(forged))
                code, out, _ = self.lane("judge", "--profile", "spdk-volume", str(path))
                self.assertEqual(code, 1, out)
                self.assertIn(reason, out)
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", receipt)
        self.assertEqual(code, 0, out)
        self.assertEqual(out, "spdk-volume: credited on platform row x86_64-nitro-ebs\n")
        rerun = json.loads(Path(receipt).read_text())
        for disposition in ("pending", "excluded"):
            with self.subTest(disposition=disposition):
                self.manifest["profiles"]["spdk-volume"]["platforms"]["x86_64-nitro-ebs"] = disposition
                code, out, _ = self.lane("judge", "--profile", "spdk-volume", receipt)
                self.assertEqual(code, 1, out)
                self.assertIn(f"Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is {disposition}",
                              out, "the judge applies the current manifest's disposition, so a credited receipt stops crediting")
        self.assertEqual(rerun, json.loads(Path(receipt).read_text()))

    def test_the_hit_gate_admits_a_run_this_lane_wrote_once_its_roles_name_two_hosts(self):
        """`hit-gate.py admit` reads the lane's receipts. One run of the hit-gate profile's two roles through this
        lane, each role with its own mappings file and peer, credits under the real `judge_profile` and binds its
        samples by the observe line the lane recorded. With both receipts naming one instance the run is refused
        for the shared host, and with two instances it is admitted with the facts the lane wrote."""
        spec = importlib.util.spec_from_file_location("hit_gate", ROOT / "scripts/hit-gate.py")
        gate = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(gate)
        cell = "net::host_pair_tests::hit_gate::the_client_drives_the_open_loop_hit_gate"
        q = self.manifest["qualification"]
        q.update(offered_rate=3, build_environment={"CARGO_PROFILE_DEV_OPT_LEVEL": "3"})
        q["protocol"].update(requests=5)
        workload, seed = q["workloads"]["request-weighted"], 7
        header = {"workload": "request-weighted", "records": workload["records"], "weights": workload["weights"],
                  "rate": 3, "requests": 5, "seed": seed, "previous": "none", "slots": 2, "source": 0,
                  "started_unix_ms": 0}
        text = json.dumps(header) + "\n" + "".join(
            f'[{t},{t},{t},{t + 200},{gate.draw(seed, i, workload["weights"])},"hit",0]\n'
            for i, t in enumerate(i * 1_000_000 // 3 for i in range(5)))
        samples = self.state / "run.samples"
        samples.write_text(text)
        digest = hashlib.sha256(text.encode()).hexdigest()
        mappings = {"owner": self.state / "owner" / "mappings", "client": self.state / "client" / "mappings"}
        for path in mappings.values():
            path.parent.mkdir()
        mappings["owner"].write_text(
            f"format=3\nnvme.volume=vol-0abc\nnvme.bdf={pci_function()}\neni.ipv4=10.0.1.5\n")
        mappings["client"].write_text(f"format=3\neni.bdf={pci_function()}\neni.ipv4=10.0.1.7\n")
        for name in lane_module().BUILD_ENVIRONMENT:
            self.env.pop(name, None)
        self.env.update(CARGO_PROFILE_DEV_OPT_LEVEL="3", KESTRIKE_SERVE_SECONDS="600",
                        KESTRIKE_HIT_WORKLOAD="request-weighted", KESTRIKE_HIT_RATE="3",
                        KESTRIKE_HIT_REQUESTS="5", KESTRIKE_HIT_SEED=str(seed),
                        KESTRIKE_HIT_PREVIOUS="none", KESTRIKE_HIT_SAMPLES=str(samples))
        self.plan({OWNER: {"outcome": "serve", "seconds": 2},
                   cell: {"observe": [f"hit-gate samples 5 hits 5 sha256 {digest}"]}})
        observer = self.state / "observer"
        self.env.update(KESTRIKE_MAPPINGS=str(mappings["owner"]), KESTRIKE_PEER="10.0.1.7")
        owner = self.start("run", "--profile", "hit-gate", "--role", "owner", "--episode", "gate-1",
                           "--observer", str(observer))
        self.env.update(KESTRIKE_MAPPINGS=str(mappings["client"]), KESTRIKE_PEER="10.0.1.5")
        code, out, err = self.lane("run", "--profile", "hit-gate", "--role", "client", "--episode", "gate-1",
                                   "--observer", str(observer))
        owner_out, owner_err = owner.communicate(timeout=60)
        self.assertEqual((owner.returncode, code), (0, 0), owner_out + owner_err + out + err)
        manifest = self.write_manifest()
        document, bound = json.loads(manifest.read_text()), hashlib.sha256(manifest.read_bytes()).hexdigest()
        receipts = [self.receipt(owner_err)[1], self.receipt(err)[1]]
        run = {"id": "gate-1", "workload": "request-weighted", "receipts": receipts}

        def name_hosts(*instances):
            for path, instance in zip(receipts, instances):
                receipt = json.loads(Path(path).read_text())
                receipt["hardware"]["host"]["instance"] = instance
                Path(path).write_text(json.dumps(receipt))

        name_hosts("i-one", "i-one")
        with self.assertRaisesRegex(gate.Refusal, "roles share the host 'i-one'"):
            gate.admit(gate.lane_module(), document, bound, run, self.revision, seed)
        name_hosts("i-owner", "i-client")
        admitted = gate.admit(gate.lane_module(), document, bound, run, self.revision, seed)
        self.assertEqual(admitted["file"], digest)
        self.assertEqual(len(admitted["samples"]), 5)
        self.assertEqual(admitted["identity"]["owner"],
                         {"instance": "i-owner", "functions": [[pci_function()]], "volumes": ["vol-0abc"],
                          "address": "10.0.1.5"})
        self.assertEqual(admitted["identity"]["client"],
                         {"instance": "i-client", "functions": [[pci_function()]], "volumes": [None],
                          "address": "10.0.1.7"})

    def test_roles_on_different_platform_rows_never_credit_one_profile(self):
        """The judge credits a profile only when every role's receipt names the same platform row."""
        approved = self.manifest["platforms"]["x86_64-nitro-ebs"]["envelope"]
        self.manifest["platforms"]["aarch64-r8gb-4xlarge-ebs"].update(supported=True, machine=platform.machine(),
                                                                       envelope=dict(approved))
        self.manifest["profiles"]["host-pair"]["platforms"]["aarch64-r8gb-4xlarge-ebs"] = "runs"
        self.plan({OWNER: {"outcome": "serve", "seconds": 2}, CLIENT: {"observe": PAIR_WITNESSES}})
        observer = self.state / "observer"
        owner = self.start("run", "--profile", "host-pair", "--role", "owner", "--episode", "rows",
                           "--observer", str(observer))
        code, out, err = self.lane("run", "--profile", "host-pair", "--role", "client", "--episode", "rows",
                                   "--observer", str(observer), "--platform", "aarch64-r8gb-4xlarge-ebs")
        owner_out, owner_err = owner.communicate(timeout=60)
        self.assertEqual((owner.returncode, code), (0, 0), owner_out + owner_err + out + err)
        self.assertIn("host-pair/client: credited on platform row aarch64-r8gb-4xlarge-ebs\n", out)
        self.assertIn("host-pair/owner: credited on platform row x86_64-nitro-ebs\n", owner_out)
        code, out, _ = self.lane("judge", "--profile", "host-pair", self.receipt(owner_err)[1], self.receipt(err)[1])
        self.assertEqual(code, 1, out)
        self.assertIn("the roles ran under different platform rows", out)

    def test_an_unsupported_platform_or_a_missing_input_leaves_the_role_uncredited(self):
        self.manifest["platforms"]["x86_64-nitro-ebs"]["supported"] = False
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertEqual(self.receipt(err)[0]["first_failure"], "Inconclusive: platform row unsupported: x86_64-nitro-ebs")
        self.assertFalse((self.state / "builds.txt").exists(), "an unsupported platform builds nothing")
        self.assertFalse((self.state / "runs.txt").exists(), "an unsupported platform runs no case")
        self.manifest["platforms"]["x86_64-nitro-ebs"]["supported"] = True
        self.env["KESTRIKE_MAPPINGS"] = "mappings"
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn("relative KESTRIKE_MAPPINGS 'mappings'", self.receipt(err)[0]["first_failure"],
                      "the case runs from the package root, so a relative path names no one file")
        self.env["KESTRIKE_MAPPINGS"] = str(self.state / "mappings")
        (self.state / "mappings").write_text("format=2\n")
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn("names no readable mappings file of format 3", self.receipt(err)[0]["first_failure"],
                      "a case the judge would refuse for its mappings identity runs no device work")
        self.assertFalse((self.state / "runs.txt").exists())
        self.mappings_file(self.state / "mappings")
        self.env["KESTRIKE_RELEASE_STATE_DIR"] = "scratch"
        code, out, err = self.lane("run", "--profile", "prerequisites", "--role", "host")
        self.assertEqual(code, 1, out + err)
        self.assertIn("relative KESTRIKE_RELEASE_STATE_DIR 'scratch'", self.receipt(err)[0]["first_failure"],
                      "the state directory names the mappings file the case opens, so it follows the same rule")
        self.env["KESTRIKE_RELEASE_STATE_DIR"] = str(self.state / "scratch")
        self.mappings_file(self.state / "scratch" / "mappings")
        self.plan(PREREQUISITE_WITNESSES)
        code, out, err = self.lane("run", "--profile", "prerequisites", "--role", "host")
        self.assertEqual(code, 0, out + err)
        section, path = self.receipt(err)
        self.assertEqual(section["cases"][0]["mappings"]["path"], str(self.state / "scratch" / "mappings"),
                         "the receipt records the identity of the mappings file under the state directory")
        code, out, _ = self.lane("judge", "--profile", "prerequisites", path)
        self.assertEqual(code, 0, out)
        forged = json.loads(Path(path).read_text())
        forged["hardware"]["cases"][0].pop("mappings")
        Path(path).write_text(json.dumps(forged))
        code, out, _ = self.lane("judge", "--profile", "prerequisites", path)
        self.assertEqual(code, 1, out)
        self.assertIn("no mappings identity", out)
        self.env.pop("KESTRIKE_MAPPINGS")
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn("lacks inputs ['KESTRIKE_MAPPINGS']", self.receipt(err)[0]["first_failure"])

    def test_a_refused_row_runs_no_cargo_or_rustc_and_records_the_tree_it_refused(self):
        """A role whose platform row is unsupported, carries another disposition or excludes the host from its
        envelope stops before every cargo and rustc probe, so its receipt names no toolchain or dependencies, and
        still records the revision and tree state it refused from. A role its row runs probes both and records them."""
        rustc = self.state / "rustc"
        rustc.write_text(f"#!/bin/sh\necho \"$@\" >> {self.state / 'rustc-calls.txt'}\necho 'rustc 1.99.0 (fake)'\n")
        rustc.chmod(0o755)
        self.env["RUSTC"] = str(rustc)
        clean = json.loads(json.dumps(self.manifest))
        for row, edit, reason in (
            ("aarch64-r8gb-4xlarge-ebs", lambda manifest: None,
             "Inconclusive: platform row unsupported: aarch64-r8gb-4xlarge-ebs"),
            ("x86_64-nitro-ebs", lambda manifest: manifest["profiles"]["spdk-volume-stop"]["platforms"].update(
                {"x86_64-nitro-ebs": "pending"}),
             "Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is pending"),
            ("x86_64-nitro-ebs", lambda manifest: manifest["platforms"]["x86_64-nitro-ebs"]["envelope"].update(
                kernel="another kernel"),
             "Inconclusive: the host is outside platform row x86_64-nitro-ebs's envelope: the host's kernel"),
        ):
            with self.subTest(reason=reason):
                self.manifest = json.loads(json.dumps(clean))
                edit(self.manifest)
                code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner", "--platform", row)
                self.assertEqual(code, 1, out + err)
                section = self.receipt(err)[0]
                self.assertTrue(section["first_failure"].startswith(reason), section["first_failure"])
                self.assertFalse((self.state / "cargo-calls.txt").exists(), "a refused row runs no cargo")
                self.assertFalse((self.state / "rustc-calls.txt").exists(), "a refused row runs no rustc")
                self.assertNotIn("toolchain", section)
                self.assertNotIn("dependencies", section)
                self.assertEqual((section["revision"], section["dirty"]), (self.revision, False))
        self.manifest = clean
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section = self.receipt(err)[0]
        self.assertEqual(section["toolchain"], {"rustc": "rustc 1.99.0 (fake)", "cargo": "cargo 1.99.0 (fake)"})
        self.assertEqual(section["dependencies"], ["kestrike 0.1.0"])
        self.assertIn("metadata --format-version 1", (self.state / "cargo-calls.txt").read_text().splitlines())
        self.assertEqual((self.state / "rustc-calls.txt").read_text(), "-vV\n")

    def test_a_host_pair_role_without_its_peer_address_is_uncredited_before_it_starts(self):
        """The owner and every single-owner client read `KESTRIKE_PEER`, so each case declares it: the lane
        reports the missing input instead of starting a case that would bind its devices and then panic."""
        self.env.pop("KESTRIKE_PEER", None)
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        for profile, role in (("host-pair", "owner"), ("host-pair", "client"), ("host-pair-two-owners", "owner-a"),
                              ("host-pair-two-owners", "owner-b"), ("host-pair-two-owners-sigkill", "owner-a"),
                              ("host-pair-two-owners-sigkill", "owner-b"), ("host-pair-put", "client"),
                              ("host-pair-put", "reader")):
            code, out, err = self.lane("run", "--profile", profile, "--role", role)
            self.assertEqual(code, 1, out + err)
            failure = self.receipt(err)[0]["first_failure"]
            self.assertIn("lacks inputs [", failure, f"{profile}/{role}")
            self.assertIn("'KESTRIKE_PEER'", failure, f"{profile}/{role}")
        self.assertFalse((self.state / "runs.txt").exists(), "no case started")

    def test_a_deadline_asks_for_containment_and_holds_the_group_unless_it_is_acknowledged(self):
        missing = self.state / "no-such-controller"
        controllers = {
            "acknowledged": (f'echo "contained {OUTCOME}"', True, "contained"),
            "refused": ("exit 3", False, "exit 3"),
            "delayed": ("sleep 5", False, "no answer within 1.0 s"),
            "lost acknowledgement": ("exit 0", False, "exit 0: "),
            "undecodable answer": (r"printf '\377'", False, "exit 0: \ufffd"),
            "no controller": (None, False, "no controller"),
            "unavailable": (missing, False, "unavailable"),
        }
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"].update(ready="owner serving until", closing="close requested by SIGTERM")
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(
            deadline=1, grace=1, closes_on_sigterm=True)
        for name, (body, acknowledged, answer) in controllers.items():
            with self.subTest(name):
                arguments = []
                if body is missing:
                    arguments = ["--controller", str(missing)]
                elif body is not None:
                    controller = self.state / f"controller-{len(name)}"
                    controller.write_text(f"#!/bin/sh\n{body}\n")
                    controller.chmod(0o755)
                    arguments = ["--controller", str(controller)]
                self.plan({OUTCOME: {"outcome": "stubborn"}})
                code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner",
                                           *arguments, "--controller-seconds", "1")
                self.assertEqual(code, 1 if acknowledged else 4, out + err)
                section, _ = self.receipt(err)
                case = section["cases"][0]
                self.assertEqual((case["stop"], case["grace"]), ("deadline", "alive after grace"))
                self.assertGreaterEqual(case["seconds"], 2, "the deadline and then the grace elapsed")
                self.assertEqual(case["containment"]["acknowledged"], acknowledged)
                self.assertIn(answer, case["containment"]["answer"])
                self.assertIn("cut off", section["first_failure"])
                grandchild = int((self.state / f"{OUTCOME}.grandchild").read_text())
                if acknowledged:
                    self.assertFalse(alive(grandchild), "an acknowledged containment lets the lane stop the group")
                    self.assertNotIn("custody", case)
                else:
                    self.assertEqual(state(grandchild), "T", "an unproven containment leaves the group stopped")
                    self.assertIn("held: process group", case["custody"])
                    self.assertIn("custody held: process group", out)
                self.kill_held()

    def test_a_containment_channel_credits_only_one_exchange_the_controller_proves(self):
        mappings = self.env["KESTRIKE_MAPPINGS"]
        proven = "; ".join(f'echo "{word} {mappings}"' for word in
                           ("fenced", "device contained", "host contained", "contained"))
        controllers = {
            "proven": (proven, {}, 0, None, True),
            "proven for an endpoint holding a form feed": (proven.replace(mappings, mappings + "\f"), {"mappings": "\f"}, 0, None, True),
            "no host containment": (f'echo "fenced {mappings}"; echo "contained {mappings}"', {}, 1, "cut off", False),
            "proven then failed": (proven + "; exit 3", {}, 1, "cut off", False),
            "two requests": (proven, {"requests": 2}, 1, "2 containment exchanges", True),
            "census after the request": (proven, {"census": "late"}, 1, "with a census", True),
            "unterminated at exit": (proven, {"trailing": "contain"}, 1, "2 containment exchanges", True),
        }
        self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(deadline=2, grace=1)
        for name, (body, fake, code, reason, acknowledged) in controllers.items():
            with self.subTest(name):
                mappings = self.env["KESTRIKE_MAPPINGS"] = str(self.state / ("mappings" + fake.pop("mappings", "")))
                self.mappings_file(Path(mappings))
                controller = self.state / f"controller-{len(name)}"
                controller.write_text(textwrap.dedent(f"""\
                    #!/bin/sh
                    printf '%s\\n' "$*" >> {self.state}/controller.log
                    if [ "$1" = contain ]; then echo "contained {CONTAINMENT}"; exit 0; fi
                    {body}
                    """))
                controller.chmod(0o755)
                self.plan({CONTAINMENT: {"outcome": "channel", **fake}})
                # The role's file supplies the external input alone; the lane synthesizes the channel's two.
                role_file = self.state / "owner.env"
                role_file.write_text(f"KESTRIKE_MAPPINGS={mappings}\n")
                got, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner",
                                          "--controller", str(controller), "--environment", str(role_file))
                self.assertEqual(got, code, out + err)
                section, receipt_path = self.receipt(err)
                run_dir = Path(receipt_path).parent
                self.assertEqual([path.name for path in run_dir.iterdir() if ":" in path.name or path.is_fifo()], [],
                                 "the evidence tree holds no FIFO and no colon the artifact upload refuses")
                exchanges = section["cases"][0]["channel"]
                self.assertEqual(len(exchanges), fake.get("requests", 1) + ("trailing" in fake))
                if "trailing" in fake:
                    self.assertEqual(exchanges[1]["answer"], "unterminated at the case's exit")
                self.assertEqual(exchanges[0]["request"], f"contain {mappings}")
                census = [] if fake.get("census") == "late" else ["census before stall: pending 1"]
                self.assertEqual(exchanges[0]["census"], census, "the census comes from the case's stderr")
                self.assertEqual(exchanges[0]["acknowledged"], acknowledged)
                if reason:
                    self.assertIn(reason, section["first_failure"])
                logged = (self.state / "controller.log").read_text()
                self.assertIn(f'"case": "{CONTAINMENT}", "endpoint": {json.dumps(mappings)}', logged)
                (self.state / "controller.log").unlink()
                if code == 0:
                    self.assertEqual(self.lane("judge", "--profile", "spdk-containment", receipt_path)[0], 0,
                                     "the judge credits the receipt the run credited")
                    for defect, edit in (
                        ("no exchange", lambda case: case.update(channel=[])),
                        ("unacknowledged", lambda case: case["channel"][0].update(acknowledged=False)),
                        ("no census", lambda case: case["channel"][0].update(census=[])),
                        ("a second exchange", lambda case: case["channel"].append(dict(case["channel"][0]))),
                        ("another endpoint", lambda case: case["channel"][0].update(request="contain /elsewhere")),
                    ):
                        forged = json.loads(Path(receipt_path).read_text())
                        edit(forged["hardware"]["cases"][0])
                        path = self.state / "forged-channel.json"
                        path.write_text(json.dumps(forged))
                        judged, out, _ = self.lane("judge", "--profile", "spdk-containment", str(path))
                        self.assertEqual(judged, 1, f"{defect}: {out}")
                        self.assertIn("containment exchange", out, defect)

    def test_a_case_parked_on_its_channel_is_contained_before_any_signal_reaches_it(self):
        closes = {
            "acknowledged": (f'echo "contained {CONTAINMENT}"', 1),
            "refused": ("exit 3", 4),
        }
        self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(deadline=2, grace=1)
        for name, (close, code) in closes.items():
            with self.subTest(name):
                controller = self.state / f"controller-{name}"
                controller.write_text(textwrap.dedent(f"""\
                    #!/bin/sh
                    echo "$1" >> {self.state}/controller.log
                    if [ "$1" = contain ]; then {close}; fi
                    """))
                controller.chmod(0o755)
                self.plan({CONTAINMENT: {"outcome": "channel"}})
                got, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner",
                                          "--controller", str(controller), "--controller-seconds", "1")
                self.assertEqual(got, code, out + err)
                section, _ = self.receipt(err)
                case = section["cases"][0]
                self.assertFalse(case["channel"][0]["acknowledged"])
                self.assertEqual(case["grace"], "not requested: the case does not close on SIGTERM")
                self.assertEqual(case["stopped"], "every member stopped before the controller was asked")
                logged = (self.state / "controller.log").read_text().splitlines()
                self.assertEqual(logged[:2], ["contain-endpoint", "contain"],
                                 "the controller is asked before any signal reaches the parked case")
                pid = int((self.state / f"{CONTAINMENT}.pid").read_text())
                if code == 4:
                    self.assertEqual(state(pid), "T", "a refused containment leaves the case stopped")
                    self.assertIn("custody held: process group", out)
                else:
                    self.assertFalse(alive(pid), "an acknowledged containment lets the lane end the stopped case")
                self.kill_held()
                (self.state / "controller.log").unlink()

    def test_a_line_other_than_a_request_never_reaches_the_controller(self):
        controller = self.state / "controller"
        controller.write_text(f"#!/bin/sh\necho \"$1\" >> {self.state}/controller.log\n")
        controller.chmod(0o755)
        self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(deadline=2, grace=1)
        self.plan({CONTAINMENT: {"outcome": "channel", "request": "contain "}})
        code, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner",
                                   "--controller", str(controller))
        self.assertEqual(code, 4, out + err)
        section, _ = self.receipt(err)
        self.assertEqual(section["cases"][0]["channel"][0]["answer"], "not relayed")
        self.assertEqual((self.state / "controller.log").read_text(), "contain\n", "only the close path asked")
        self.assertEqual(state(int((self.state / f"{CONTAINMENT}.pid").read_text())), "T")
        self.kill_held()

    def test_a_frame_past_the_limit_or_a_foreign_endpoint_is_never_relayed(self):
        requests = {
            "long": ({"request": "contain " + "x" * 4096}, "not relayed: frame past 4096 bytes"),
            "unterminated": ({"request": "contain " + "x" * 5000, "terminator": ""}, "not relayed: frame past 4096 bytes"),
            "exactly a frame, unterminated": ({"request": "contain " + "x" * 4088, "terminator": ""},
                                              "not relayed: frame past 4096 bytes"),
            "foreign endpoint": ({"request": "contain /elsewhere"}, "not relayed: endpoint is not KESTRIKE_MAPPINGS"),
        }
        controller = self.state / "controller"
        controller.write_text(f"#!/bin/sh\necho \"$1\" >> {self.state}/controller.log\n")
        controller.chmod(0o755)
        self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(deadline=2, grace=1)
        for name, (fake, answer) in requests.items():
            with self.subTest(name):
                (self.state / "controller.log").unlink(missing_ok=True)
                self.plan({CONTAINMENT: {"outcome": "channel", **fake}})
                code, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner",
                                           "--controller", str(controller))
                self.assertEqual(code, 4, out + err)
                section, _ = self.receipt(err)
                exchanges = section["cases"][0]["channel"]
                self.assertEqual([(e["answer"], e["acknowledged"]) for e in exchanges], [(answer, False)])
                self.assertLessEqual(len(exchanges[0]["request"]), 4096, "the record keeps at most one frame")
                self.assertEqual((self.state / "controller.log").read_text(), "contain\n", "only the close path asked")
                self.assertEqual(state(int((self.state / f"{CONTAINMENT}.pid").read_text())), "T")
                self.kill_held()
                (self.state / "controller.log").unlink(missing_ok=True)

    def test_the_relay_ends_at_a_second_exchange(self):
        mappings = self.env["KESTRIKE_MAPPINGS"]
        controller = self.state / "controller"
        controller.write_text(textwrap.dedent(f"""\
            #!/bin/sh
            echo "$1" >> {self.state}/controller.log
            if [ "$1" = contain ]; then echo "contained {CONTAINMENT}"; exit 0; fi
            {"; ".join(f'echo "{word} {mappings}"' for word in CONTAINED)}
            """))
        controller.chmod(0o755)
        self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(deadline=2, grace=1)
        self.plan({CONTAINMENT: {"outcome": "channel", "requests": 50}})
        code, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner",
                                   "--controller", str(controller))
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        exchanges = section["cases"][0]["channel"]
        self.assertEqual([(e["request"], e["acknowledged"]) for e in exchanges],
                         [(f"contain {mappings}", True), (f"contain {mappings}", False)])
        self.assertEqual(exchanges[1]["answer"], "not relayed: a second exchange")
        self.assertEqual((self.state / "controller.log").read_text().count("contain-endpoint"), 1,
                         "the controller is asked once")
        self.assertIn("2 containment exchanges", section["first_failure"])

    def test_a_containment_case_without_a_controller_is_reported_unrun(self):
        self.plan({CONTAINMENT: {"outcome": "channel"}})
        code, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertIn("unrun: no containment controller", section["first_failure"])
        self.assertIn("unrun", section["cases"][0])
        self.assertFalse((self.state / "runs.txt").exists(), "the case never started")

    def test_a_case_that_died_by_a_signal_ends_the_role_without_a_containment_request(self):
        """A reaped leader holds no memory, so there is nothing to contain; the role's evidence is complete at its defect."""
        self.plan({CONTRACT: {"outcome": "abort"}})
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertIn("exited -11", section["first_failure"])
        self.assertEqual([case["id"] for case in section["cases"]], [CONTRACT])
        self.assertEqual(len((self.state / "runs.txt").read_text().splitlines()), 1, "the later case never ran")
        for key in ("containment", "custody", "stop"):
            self.assertNotIn(key, section["cases"][0])

    def test_a_held_group_ends_the_role_before_its_next_case(self):
        self.manifest["profiles"]["spdk-volume-stop"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=1)
        self.plan({CONTRACT: {"outcome": "stubborn"}})
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 4, out + err)
        section, _ = self.receipt(err)
        self.assertEqual([case["id"] for case in section["cases"]], [CONTRACT])
        self.assertNotIn(STOPS, (self.state / "runs.txt").read_text())
        self.assertIn("custody held: process group", out)
        markers = sorted((self.state / "custody").glob("*.json"))
        self.assertEqual(len(markers), 1, "the held group's marker quarantines the host")
        marker = json.loads(markers[0].read_text())
        self.assertEqual((marker["profile"], marker["role"], marker["case"]), ("spdk-volume-stop", "owner", CONTRACT))
        self.assertEqual(markers[0].stem, str(marker["pgid"]))
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume-stop/owner")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn(f"custody held on this host: ['process group {marker['pgid']} of spdk-volume-stop/owner", out)
        self.assertEqual(len((self.state / "runs.txt").read_text().splitlines()), 1, "the quarantined host ran no case")
        lane = lane_module()
        self.assertEqual(set(marker["members"]), {str(pid) for pid in lane.group_members(marker["pgid"])},
                         "the marker names each stopped member with its start time")
        # While the group is stopped: its recorded members hold memory; the same pids with other start times are
        # other processes and hold none; a marker from another boot names nothing here.
        recorded = {int(pid): started for pid, started in marker["members"].items()}
        self.assertTrue(lane.members_hold_memory(recorded))
        self.assertFalse(lane.members_hold_memory({pid: started + 1 for pid, started in recorded.items()}),
                         "a live pid with another start time is no member")
        self.assertTrue(lane.group_still_held(marker["pgid"], recorded))
        self.assertFalse(lane.group_still_held(marker["pgid"], {pid: started + 1 for pid, started in recorded.items()}),
                         "a group whose leader is a new process with the same pid is that process's own")
        stale = dict(marker, boot="00000000-0000-0000-0000-000000000000")
        (self.state / "custody" / "stale.json").write_text(json.dumps(stale))
        reused = dict(marker, members={pid: started + 1 for pid, started in marker["members"].items()})
        (self.state / "custody" / "reused.json").write_text(json.dumps(reused))
        self.env["KESTRIKE_EPISODE"] = "held-1b"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertNotIn("stale.json", out)
        self.assertEqual(sorted(path.name for path in (self.state / "custody").glob("*.json")), [markers[0].name],
                         "the sweep removed the other-boot marker and the reused-pid marker, and kept the live group's")
        self.kill_held()
        for _ in range(200):
            if not lane.members_hold_memory({int(pid): started for pid, started in marker["members"].items()}):
                break
            time.sleep(0.05)
        self.plan({})
        self.env["KESTRIKE_EPISODE"] = "held-2"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        self.assertEqual(sorted((self.state / "custody").glob("*.json")), [], "a marker whose group is gone is removed")
        # A custody directory this account cannot write refuses the sweep before any role; root writes anywhere.
        if os.getuid() != 0:
            (self.state / "custody").chmod(0o500)
            self.addCleanup((self.state / "custody").chmod, 0o700)
            code, out, _ = self.lane("sweep")
            self.assertEqual(code, 2, out)
            self.assertIn("custody directory", out)

    def test_the_controller_is_asked_once_every_group_member_is_stopped_and_its_helpers_end_with_it(self):
        """The containment protocol promises a stopped group; a controller's own helpers end with its window."""
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=1)
        checker = self.state / "controller-check"
        checker.write_text(textwrap.dedent(f'''\
            #!{sys.executable}
            import json, sys
            from pathlib import Path
            request = json.loads(sys.argv[2])
            states = {{}}
            for entry in Path("/proc").iterdir():
                if entry.name.isdigit():
                    try:
                        fields = (entry / "stat").read_text().rpartition(")")[2].split()
                    except OSError:
                        continue
                    if int(fields[2]) == request["pid"]:
                        states[int(entry.name)] = fields[0]
            Path("{self.state}/seen.json").write_text(json.dumps(states))
            if states and all(state in "Tt" for state in states.values()):
                print("contained " + request["case"])
            else:
                sys.exit(3)
            '''))
        checker.chmod(0o755)
        self.plan({OUTCOME: {"outcome": "hang"}})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner", "--controller", str(checker))
        self.assertEqual(code, 1, out + err)
        case = self.receipt(err)[0]["cases"][0]
        seen = json.loads((self.state / "seen.json").read_text())
        self.assertEqual(len(seen), 2, f"the leader and its helper were both in the group: {seen}")
        self.assertTrue(case["containment"]["acknowledged"], f"the controller saw every member stopped: {seen}")
        self.assertEqual(case["stopped"], "every member stopped before the controller was asked")
        self.kill_held()
        forking = self.state / "controller-fork"
        forking.write_text(f"#!/bin/sh\nsleep 600 &\necho $! > {self.state}/helper.pid\nsleep 5\n")
        forking.chmod(0o755)
        self.plan({OUTCOME: {"outcome": "custodian"}})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner", "--controller", str(forking),
                                   "--controller-seconds", "1")
        self.assertEqual(code, 4, out + err)
        case = self.receipt(err)[0]["cases"][0]
        self.assertIn("no answer within 1.0 s", case["containment"]["answer"])
        helper = int((self.state / "helper.pid").read_text())
        self.assertFalse(alive(helper), "the controller's helper ended with the controller's window")
        self.kill_held()

    def test_a_case_without_a_close_handler_is_stopped_before_containment_and_never_sent_sigterm(self):
        """SIGTERM's default action would end such a case and release its memory before containment."""
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"].update(ready="owner serving until", closing="close requested by SIGTERM")
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=1)
        shapes = {"never closes on SIGTERM": (False, {}, "does not close on SIGTERM"),
                  "closes on SIGTERM but has not reported readiness": (True, {"mute": True}, "readiness")}
        for shape, (closes, plan, grace) in shapes.items():
            self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0]["closes_on_sigterm"] = closes
            for name, body, acknowledged in (("no controller", None, False),
                                             ("acknowledged", f'echo "contained {OUTCOME}"', True)):
                with self.subTest(f"{shape}, {name}"):
                    arguments = []
                    if body is not None:
                        controller = self.state / "controller-ack"
                        controller.write_text(f"#!/bin/sh\n{body}\n")
                        controller.chmod(0o755)
                        arguments = ["--controller", str(controller)]
                    self.plan({OUTCOME: {"outcome": "custodian", **plan}})
                    code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner", *arguments)
                    self.assertEqual(code, 1 if acknowledged else 4, out + err)
                    case = self.receipt(err)[0]["cases"][0]
                    self.assertNotIn("close_requested", case)
                    self.assertEqual("ready" in case, not plan, "a muted case reported no readiness")
                    self.assertIn("not requested", case["grace"])
                    self.assertIn(grace, case["grace"])
                    self.assertEqual(case["containment"]["acknowledged"], acknowledged)
                    custodian = int((self.state / f"{OUTCOME}.grandchild").read_text())
                    if acknowledged:
                        self.assertFalse(alive(custodian), "an acknowledged containment lets the lane stop the group")
                    else:
                        self.assertEqual(state(custodian), "T", "the custodian stays stopped with its memory")
                    self.kill_held()

    def test_a_descendant_outliving_its_passing_case_is_stopped_and_contained_before_it_is_killed(self):
        """A helper the case forked inherits its device descriptors, so it holds custody as the case did."""
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"].update(ready="owner serving until", closing="close requested by SIGTERM")
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=2)
        exits = {"passed and exited": ({"outcome": "leave"}, False),
                 "closed on SIGTERM within grace": ({"outcome": "close", "leave": True}, True)}
        for exit_name, (plan, closes) in exits.items():
            for name, body, acknowledged in (("no controller", None, False),
                                             ("acknowledged", f'echo "contained {OUTCOME}"', True)):
                with self.subTest(f"{exit_name}, {name}"):
                    arguments = []
                    if body is not None:
                        controller = self.state / "controller-ack"
                        controller.write_text(f"#!/bin/sh\n{body}\n")
                        controller.chmod(0o755)
                        arguments = ["--controller", str(controller)]
                    self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0]["closes_on_sigterm"] = closes
                    self.plan({OUTCOME: plan})
                    code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner", *arguments)
                    self.assertEqual(code, 1 if acknowledged else 4, out + err)
                    section, _ = self.receipt(err)
                    case = section["cases"][0]
                    if closes:
                        self.assertEqual((case["exit"], case["grace"]), (None, "exited within grace"))
                    else:
                        self.assertEqual(case["exit"], 0, "the leader passed and exited")
                        self.assertNotIn("close_requested", case, "an exited leader has no close to request")
                        self.assertIn("left descendants running", section["first_failure"])
                    self.assertIn("descendants", case)
                    self.assertEqual(case["containment"]["acknowledged"], acknowledged)
                    descendant = int((self.state / f"{OUTCOME}.grandchild").read_text())
                    if acknowledged:
                        self.assertFalse(alive(descendant), "an acknowledged containment lets the lane kill the group")
                        self.assertNotIn("custody", case)
                    else:
                        self.assertEqual(state(descendant), "T", "an uncontained descendant stays stopped with its memory")
                        self.assertIn("held: process group", case["custody"])
                        self.assertIn("custody held: process group", out)
                    self.kill_held()

    def test_an_observer_failure_closes_the_case_through_containment_and_keeps_the_receipt(self):
        observer = self.state / "observer"
        self.plan({OWNER: {"outcome": "stubborn", "break_observer": str(observer)}})
        code, out, err = self.lane("run", "--profile", "host-pair", "--role", "owner", "--episode", "broken",
                                   "--observer", str(observer))
        self.assertEqual(code, 4, out + err)
        section, _ = self.receipt(err)
        case = section["cases"][0]
        self.assertIn("readiness", section["first_failure"])
        self.assertFalse(case["containment"]["acknowledged"])
        self.assertIn("held: process group", case["custody"])
        self.assertIn("custody held: process group", out)
        self.kill_held()

    def run_in_process(self, lane, on_end, episode):
        """Runs `spdk-volume-stop/owner` through `lane.main` in this process with `Observer.append` calling `on_end`
        before recording an `end` event; returns the exit code and the captured output."""
        recorded = lane.Observer.append

        def append(observer, kind, **fields):
            if kind == "end":
                on_end()
            return recorded(observer, kind, **fields)

        lane.Observer.append = append
        handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        environment, cwd = dict(os.environ), os.getcwd()
        os.environ.update(self.env)
        os.chdir(self.checkout)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out, contextlib.redirect_stderr(io.StringIO()) as err:
                code = lane.main(["run", "--profile", "spdk-volume-stop", "--role", "owner", "--episode", episode,
                                  "--observer", str(self.state / "observer"), "--manifest", str(self.write_manifest()),
                                  "--cargo", str(self.state / "cargo"), "--artifacts", str(self.state / "artifacts"),
                                  "--custody", str(self.state / "custody")])
        finally:
            lane.Observer.append = recorded
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(environment)
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
        return code, out.getvalue(), err.getvalue()

    def test_an_end_event_the_log_refuses_leaves_the_receipt_uncredited(self):
        """`credited` follows the exit status: a role whose end event failed to record exits 2 and claims no credit."""
        def refuse():
            raise OSError(28, "the observer log is full")

        code, out, err = self.run_in_process(lane_module(), refuse, "ending")
        self.assertEqual(code, 2, out + err)
        section, _ = self.receipt(err)
        self.assertIn("could not record its end", section["first_failure"])
        self.assertFalse(section["credited"], "a receipt that records a failure claims no credit")
        self.assertEqual([case["exit"] for case in section["cases"]], [0, 0], "the cases themselves passed")

    def test_a_group_marker_that_cannot_be_written_keeps_the_sentinel(self):
        """When the group's marker fails after the spawn, the pre-spawn sentinel stays, so the host stays quarantined."""
        lane = lane_module()
        written = lane.write_custody_marker

        def refuse_group_markers(directory, name, **record):
            if name.isdigit():
                raise OSError(28, "no space for the group's marker")
            return written(directory, name, **record)

        lane.write_custody_marker = refuse_group_markers
        try:
            code, out, err = self.run_in_process(lane, lambda: None, "no-marker")
        finally:
            lane.write_custody_marker = written
        self.assertEqual(code, 1, out + err)
        self.assertIn("custody marker could not be written", self.receipt(err)[0]["first_failure"])
        sentinels = sorted((self.state / "custody").glob("starting-*.json"))
        self.assertEqual(len(sentinels), 1, "the sentinel outlives a failed group marker")
        self.assertIsNone(json.loads(sentinels[0].read_text())["pgid"])

    def test_a_sentinel_that_cannot_be_written_starts_no_case(self):
        """Without the sentinel nothing guards the host while the case runs, so the case does not start."""
        lane = lane_module()
        written = lane.write_custody_marker

        def refuse_sentinels(directory, name, **record):
            if name.startswith("starting-"):
                raise OSError(28, "no space for the sentinel")
            return written(directory, name, **record)

        lane.write_custody_marker = refuse_sentinels
        try:
            code, out, err = self.run_in_process(lane, lambda: None, "no-sentinel")
        finally:
            lane.write_custody_marker = written
        self.assertEqual(code, 2, out + err)
        self.assertIn("custody sentinel could not be written", self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "no case ran")

    def test_the_sweep_s_marker_for_a_dead_supervisor_takes_over_its_sentinel(self):
        """A supervisor killed between its sentinel and its group's marker leaves the sentinel; the sweep's marker
        for that supervisor names the case it was starting and replaces the sentinel, one marker per lost supervisor."""
        lane = lane_module()
        custody = self.state / "custody"
        lane.write_custody_marker(custody, "starting-4242", pgid=None, supervisor=4242, episode="e", profile="p",
                                  role="r", case="the::case", custody="unknown: the::case was starting")
        lane.mark_dead_supervisor(custody, "p/r", 4242, "e", "unknown; its supervisor died by signal 9")
        self.assertEqual([m.name for m in sorted(custody.glob("*.json"))], ["supervisor-4242.json"])
        marker = json.loads((custody / "supervisor-4242.json").read_text())
        self.assertEqual((marker["pgid"], marker["case"]), (None, "the::case"))
        self.assertIn("the::case was starting", marker["custody"])
        lane.mark_dead_supervisor(custody, "p/r", 4343, "e", "unknown; its supervisor died by signal 9")
        self.assertNotIn("case", json.loads((custody / "supervisor-4343.json").read_text()))

    def test_a_spawn_that_fails_removes_the_sentinel(self):
        """A case the kernel refuses to start has no group, so the sentinel written for it guards nothing."""
        lane = lane_module()
        popen = lane.subprocess.Popen

        def refuse(argv, **options):
            # The build runs through the same module; only the case, spawned into its own session with its
            # environment, is refused.
            if options.get("start_new_session") and "env" in options:
                raise PermissionError(13, "the test executable is not runnable")
            return popen(argv, **options)

        lane.subprocess.Popen = refuse
        try:
            code, out, err = self.run_in_process(lane, lambda: None, "no-spawn")
        finally:
            lane.subprocess.Popen = popen
        self.assertEqual(code, 2, out + err)
        self.assertIn("PermissionError", self.receipt(err)[0]["first_failure"])
        self.assertEqual(list((self.state / "custody").glob("*.json")), [], "no marker outlives a case that never ran")

    def test_a_signal_during_the_sentinel_write_starts_no_case(self):
        """A signal that lands while the sentinel is written ends the role interrupted with no case spawned."""
        lane = lane_module()
        written = lane.write_custody_marker

        def signal_during_sentinel(directory, name, **record):
            written(directory, name, **record)
            if name.startswith("starting-"):
                os.kill(os.getpid(), signal.SIGTERM)

        lane.write_custody_marker = signal_during_sentinel
        try:
            code, out, err = self.run_in_process(lane, lambda: None, "signalled-sentinel")
        finally:
            lane.write_custody_marker = written
        self.assertEqual(code, 5, out + err)
        self.assertIn("interrupted by signal 15 before", self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "no case ran")
        self.assertEqual(list((self.state / "custody").glob("*.json")), [], "the sentinel went with the unstarted case")

    def test_an_unreadable_boot_identity_holds_every_marker_and_writes_none(self):
        """Markers are judged against the current boot's identity; without it the sweep removes nothing and the lane
        writes nothing, so neither a stale nor a missing marker can admit work beside a held group."""
        lane = lane_module()
        custody = self.state / "custody"
        # PID_MAX_LIMIT is the exclusive upper bound for Linux process IDs, so this marker's group is distinct
        # from every group on the host and only the sweep's judgement decides its fate.
        unheld = 1 << 22
        lane.write_custody_marker(custody, str(unheld), pgid=unheld, members={}, custody="held")
        (custody / "unbooted.json").write_text(json.dumps({"pgid": None, "custody": "written with no boot"}))
        unreadable = lane.BOOT_ID
        lane.BOOT_ID = str(self.state / "no-such-boot-id")
        try:
            held = lane.held_custody(custody)
            with self.assertRaises(OSError) as refused:
                lane.write_custody_marker(custody, "4343", pgid=4343, members={}, custody="held")
        finally:
            lane.BOOT_ID = unreadable
        self.assertEqual(len(held), 2, held)
        self.assertTrue(all("boot identity" in line and "unreadable" in line for line in held), held)
        self.assertIn("boot identity", str(refused.exception))
        self.assertEqual(sorted(m.name for m in custody.glob("*.json")), [f"{unheld}.json", "unbooted.json"])
        # With the identity back, the boot-less marker is still held and the ended group's marker goes.
        self.assertEqual([line for line in lane.held_custody(custody) if "unbooted" in line and "unreadable" in line
                          ].__len__(), 1)
        self.assertEqual(sorted(m.name for m in custody.glob("*.json")), ["unbooted.json"])

    def test_the_observer_s_readiness_lookup_sees_only_this_profile_s_role_past_the_frontier(self):
        """The FIS controller takes the log's frontier before it spawns a case and asks for the role's readiness past
        it, so an earlier run's readiness, another role's and another profile's are all passed over."""
        lane = lane_module()
        observer = lane.Observer(self.state / "observer", "frontier", "fis-read", "fis")
        earlier = lane.Observer(self.state / "observer", "frontier", "fis-read", "owner").append("ready")
        self.assertEqual(observer.ready("owner")["ordinal"], earlier["ordinal"])
        frontier = max(event["ordinal"] for event in observer.events())
        self.assertIsNone(observer.ready("owner", after=frontier), "the earlier readiness lies at the frontier")
        lane.Observer(self.state / "observer", "frontier", "fis-read", "peer").append("ready")
        lane.Observer(self.state / "observer", "frontier", "fis-write", "owner").append("ready")
        lane.Observer(self.state / "observer", "frontier", "fis-read", "owner").append("start")
        self.assertIsNone(observer.ready("owner", after=frontier), "another role, another profile, another kind")
        later = lane.Observer(self.state / "observer", "frontier", "fis-read", "owner").append("ready")
        self.assertEqual(observer.ready("owner", after=frontier)["ordinal"], later["ordinal"])

    def test_the_observer_log_is_opened_to_its_own_name_and_a_planted_symlink_is_an_error(self):
        """Every read and append opens the log with O_NOFOLLOW, so a symlink another process plants under its name
        after any earlier check is an error rather than a path to follow, and the file it points at stays as it was."""
        lane = lane_module()
        observer = lane.Observer(self.state / "observer", "linked", "fis-read", "owner")
        observer.append("ready")
        target = self.state / "elsewhere.jsonl"
        target.write_text("kept\n")
        observer.path.unlink()
        observer.path.symlink_to(target)
        with self.assertRaises(OSError):
            observer.append("start")
        with self.assertRaises(OSError):
            observer.events()
        self.assertEqual(target.read_text(), "kept\n")
        target.unlink()
        with self.assertRaises(OSError):
            observer.events()
        observer.path.unlink()
        self.assertEqual(observer.events(), [], "an absent log has no events")

    def test_a_durable_marker_holds_across_boots_until_an_operator_removes_it(self):
        """A marker for a hazard outside this host's processes, such as a FIS fault whose end is unconfirmed, names
        nothing a reboot ends: the sweep holds it whatever boot wrote it, and only an operator removes it."""
        lane = lane_module()
        custody = self.state / "custody"
        custody.mkdir()
        (custody / "fis-e1.json").write_text(json.dumps({
            "durable": True, "pgid": None, "boot": "another-boot", "profile": "fis-read", "role": "owner",
            "episode": "e1", "custody": "the FIS fault's end is unconfirmed (EXP1)"}))
        held = lane.held_custody(custody)
        self.assertEqual(len(held), 1, held)
        self.assertIn("unconfirmed", held[0])
        self.assertIn("remove", held[0])
        self.assertTrue((custody / "fis-e1.json").exists(), "the sweep removes no durable marker")
        (custody / "fis-e1.json").unlink()
        self.assertEqual(lane.held_custody(custody), [])

    def test_a_marker_whose_process_group_is_no_positive_integer_is_held(self):
        """A current-boot marker whose pgid is a string, a boolean or zero names no group the sweep can look up, so it
        holds the host and stays on disk instead of reading as a group that ended."""
        lane = lane_module()
        custody = self.state / "custody"
        custody.mkdir()
        for name, pgid in (("string", "4343"), ("boolean", True), ("zero", 0)):
            (custody / f"{name}.json").write_text(json.dumps({
                "pgid": pgid, "members": {}, "boot": lane.boot_id(), "profile": "hit-gate", "role": "owner",
                "episode": "e1", "custody": "held"}))
        held = lane.held_custody(custody)
        self.assertEqual(len(held), 3, held)
        self.assertTrue(all("unreadable process group" in line for line in held), held)
        self.assertEqual(sorted(m.name for m in custody.glob("*.json")), ["boolean.json", "string.json", "zero.json"])

    def test_a_marker_with_a_malformed_boot_or_member_identity_is_held(self):
        """A marker whose boot is no string, or whose members name a pid that is no positive ASCII decimal or a start
        time that is no positive integer, names no identity the sweep can judge, so it holds and stays on disk."""
        lane = lane_module()
        custody = self.state / "custody"
        custody.mkdir()
        # PID_MAX_LIMIT bounds Linux process IDs, so this group is no group on the host.
        unheld = 1 << 22
        cases = {"boot-number": {"boot": 7, "members": {}}, "boot-list": {"boot": [lane.boot_id()], "members": {}},
                 "boolean-start": {"members": {str(unheld): True}}, "negative-start": {"members": {str(unheld): -1}},
                 "unicode-pid": {"members": {"\u0664\u0663": 5}}, "zero-pid": {"members": {"0": 5}}}
        for name, fields in cases.items():
            (custody / f"{name}.json").write_text(json.dumps({
                "pgid": unheld, "boot": lane.boot_id(), "profile": "hit-gate", "role": "owner", "episode": "e1",
                "custody": "held", **fields}))
        held = lane.held_custody(custody)
        self.assertEqual(len(held), len(cases), held)
        self.assertEqual(sorted(m.stem for m in custody.glob("*.json")), sorted(cases))

    def test_a_malformed_current_boot_identity_holds_every_marker_and_writes_none(self):
        """A current boot identity of any shape other than the kernel's UUID is unreadable: a marker of this boot
        whose group is gone is held and stays on disk, and the lane writes no marker under it."""
        lane = lane_module()
        custody = self.state / "custody"
        # Linux process-group IDs fall below PID_MAX_LIMIT (1 << 22).
        unheld = 1 << 22
        lane.write_custody_marker(custody, str(unheld), pgid=unheld, members={}, custody="held")
        malformed = self.state / "boot-id"
        malformed.write_text("not-a-boot-id\n")
        readable, lane.BOOT_ID = lane.BOOT_ID, str(malformed)
        try:
            held = lane.held_custody(custody)
            with self.assertRaises(OSError):
                lane.write_custody_marker(custody, "4343", pgid=4343, members={}, custody="held")
        finally:
            lane.BOOT_ID = readable
        self.assertEqual(len(held), 1, held)
        self.assertIn("boot identity", held[0])
        self.assertEqual([m.name for m in custody.glob("*.json")], [f"{unheld}.json"])
        self.assertEqual(lane.held_custody(custody), [], "with the identity readable the ended group's marker goes")

    def test_a_marker_that_records_no_member_holds_while_its_group_lives(self):
        """A marker with an empty census records no start time to tell a reused number from the group it marked, so
        it holds while the group has a live member and goes once the group has none."""
        lane = lane_module()
        custody = self.state / "custody"
        child = subprocess.Popen(["sleep", "60"], start_new_session=True)
        try:
            lane.write_custody_marker(custody, str(child.pid), pgid=child.pid, members={}, profile="hit-gate",
                                      role="owner", episode="e1", custody="held")
            held = lane.held_custody(custody)
            self.assertEqual(len(held), 1, held)
            self.assertIn(f"process group {child.pid}", held[0])
            self.assertTrue((custody / f"{child.pid}.json").exists(), "the marker of a live group stays")
        finally:
            child.kill()
            child.wait()
        self.assertEqual(lane.held_custody(custody), [])
        self.assertFalse((custody / f"{child.pid}.json").exists(), "the ended group's marker goes")

    def test_a_marker_whose_member_started_at_tick_zero_is_held(self):
        """The kernel's first tasks start at clock tick 0 and a case's processes start long after boot, so a census
        that records 0 for a member holds no start time of that member: the marker holds and stays on disk while
        the group lives."""
        lane = lane_module()
        custody = self.state / "custody"
        child = subprocess.Popen(["sleep", "60"], start_new_session=True)
        try:
            lane.write_custody_marker(custody, str(child.pid), pgid=child.pid, members={str(child.pid): 0},
                                      profile="hit-gate", role="owner", episode="e1", custody="held")
            held = lane.held_custody(custody)
            self.assertEqual(len(held), 1, held)
            self.assertIn("unreadable members", held[0])
            self.assertTrue((custody / f"{child.pid}.json").exists())
        finally:
            child.kill()
            child.wait()

    def test_a_marker_with_two_spellings_of_one_member_pid_is_held(self):
        """A census that names one pid as `7` and as `07` reads as two entries and one process, so its start time
        is unreadable: the marker holds and stays on disk while the group lives, whichever spelling comes last."""
        lane = lane_module()
        custody = self.state / "custody"
        custody.mkdir()
        child = subprocess.Popen(["sleep", "60"], start_new_session=True)
        try:
            started = lane.group_members(child.pid)[child.pid]
            for name, members in (("padded-last", {str(child.pid): started, f"0{child.pid}": started + 1}),
                                  ("padded-first", {f"0{child.pid}": started + 1, str(child.pid): started}),
                                  ("padded-alone", {f"0{child.pid}": started})):
                # Written as given: the marker writer sorts its keys, which would put the padded spelling first.
                (custody / f"{name}.json").write_text(json.dumps({
                    "boot": lane.boot_id(), "pgid": child.pid, "members": members, "profile": "hit-gate",
                    "role": "owner", "episode": "e1", "custody": "held"}))
            held = lane.held_custody(custody)
            self.assertEqual(len(held), 3, held)
            self.assertTrue(all("unreadable members" in line for line in held), held)
            self.assertEqual(sorted(m.stem for m in custody.glob("*.json")),
                             ["padded-alone", "padded-first", "padded-last"])
        finally:
            child.kill()
            child.wait()

    def test_a_marker_whose_boot_is_malformed_is_held(self):
        """The sweep removes a marker for a well-formed identity of an earlier boot; a marker whose boot string has
        any other shape is held and stays on disk."""
        lane = lane_module()
        custody = self.state / "custody"
        custody.mkdir()
        # Linux process-group IDs fall below PID_MAX_LIMIT (1 << 22).
        unheld = 1 << 22
        boots = {"words": "not-a-boot-id", "upper-case": lane.boot_id().upper(), "short": lane.boot_id()[:-1],
                 "padded": lane.boot_id() + "\n"}
        for name, boot in boots.items():
            (custody / f"{name}.json").write_text(json.dumps({
                "pgid": unheld, "members": {}, "boot": boot, "profile": "hit-gate", "role": "owner", "episode": "e1",
                "custody": "held"}))
        held = lane.held_custody(custody)
        self.assertEqual(len(held), len(boots), held)
        self.assertEqual(sorted(m.stem for m in custody.glob("*.json")), sorted(boots))
        other = "0" * 8 + "-0000-4000-8000-" + "0" * 12
        self.assertNotEqual(other, lane.boot_id())
        (custody / "earlier.json").write_text(json.dumps({
            "pgid": unheld, "members": {}, "boot": other, "profile": "hit-gate", "role": "owner", "episode": "e1",
            "custody": "held"}))
        self.assertEqual(len(lane.held_custody(custody)), len(boots))
        self.assertFalse((custody / "earlier.json").exists(), "the earlier boot's marker goes")

    def test_a_signal_during_the_end_record_leaves_the_role_interrupted(self):
        """A SIGTERM that arrives while the end event waits for the observer lock interrupts the role; the receipt
        claims no credit for a run the lane was told to stop."""
        code, out, err = self.run_in_process(lane_module(), lambda: os.kill(os.getpid(), signal.SIGTERM), "signalled")
        self.assertEqual(code, 5, out + err)
        section, _ = self.receipt(err)
        self.assertIn("interrupted by signal 15", section["first_failure"])
        self.assertFalse(section["credited"])

    def test_a_receipt_write_failure_still_reports_held_custody(self):
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=1)
        self.plan({OUTCOME: {"outcome": "stubborn", "block_receipt": True}})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 4, out + err)
        self.assertIn("receipt.json could not be written", out)
        self.assertIn("custody held: process group", out)
        self.kill_held()

    def test_every_declared_case_keeps_stdout_for_the_libtest_witness(self):
        """Under --nocapture --test-threads=1 libtest writes `test ID ... `, then the test's stdout, then `ok`."""
        source = ROOT / "crates/kestrike/src"
        printing = re.compile(r"(?<![\w])print(?:ln)?!\(")
        modules = {case["id"].rsplit("::", 1)[0] for profile in self.manifest["profiles"].values()
                   for role in profile["roles"].values() for case in role["cases"]}
        for module in sorted(modules):
            with self.subTest(module):
                path = source.joinpath(*module.split("::")).with_suffix(".rs")
                if not path.exists() and module.endswith("::tests"):
                    path = source.joinpath(*module.split("::")[:-1]).with_suffix(".rs")
                self.assertEqual(printing.findall(path.read_text()), [], f"{path} prints to stdout")

    def test_an_owner_closed_by_a_sigterm_the_lane_did_not_send_is_uncredited(self):
        """A signalled owner passes its shortened assertions and exits 0; only the lane's own close may credit nothing."""
        self.manifest["profiles"]["host-pair"]["roles"]["owner"]["cases"][0].update(deadline=20, grace=5)
        self.plan({OWNER: {"outcome": "close"}})
        process = self.start("run", "--profile", "host-pair", "--role", "owner")
        ready = self.state / f"{OWNER}.ready"
        for _ in range(400):
            if ready.exists():
                break
            time.sleep(0.05)
        self.assertTrue(ready.exists(), "this fixture's owner installed its close handler")
        os.kill(int(ready.read_text()), signal.SIGTERM)
        out, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 1, out + err)
        section, _ = self.receipt(err)
        case = section["cases"][0]
        self.assertEqual(case["exit"], 0, "the signalled owner exited 0 with a passing summary")
        self.assertNotIn("close_requested", case, "the lane requested no close")
        self.assertIn("closed on a SIGTERM", section["first_failure"])
        self.assertEqual(case["closed"], "close requested by SIGTERM")

    def test_a_held_observer_lock_closes_the_case_within_its_bound_rather_than_hanging_the_supervisor(self):
        """A readiness record that cannot take the log lock is an observer failure; the supervisor keeps its deadline."""
        import fcntl
        observer = self.state / "observer"
        self.plan({OWNER: {"outcome": "serve", "mute": True, "say": "owner serving until", "delay": 1, "seconds": 30}})
        process = self.start("run", "--profile", "host-pair", "--role", "owner", "--episode", "lock-1",
                             "--observer", str(observer))
        log_path = observer / "lock-1.jsonl"
        for _ in range(600):
            if log_path.exists() and '"kind": "start"' in log_path.read_text():
                break
            time.sleep(0.05)
        else:
            self.fail("the case started")
        log = log_path.open("a+")
        self.addCleanup(log.close)
        fcntl.flock(log, fcntl.LOCK_EX)
        begun = time.monotonic()
        out, err = process.communicate(timeout=120)
        elapsed = time.monotonic() - begun
        self.assertEqual(process.returncode, 4, out + err)
        section, _ = self.receipt(err)
        self.assertIn("could not record its readiness", section["first_failure"])
        self.assertLess(elapsed, 20, "the lock wait is bounded and the case closed through the observer-failure path")
        self.assertIn("observer failure", section["cases"][0]["stop"])
        fcntl.flock(log, fcntl.LOCK_UN)
        self.kill_held()

    def test_a_sigterm_to_the_lane_requests_the_close_and_keeps_the_cut_off_output_uncredited(self):
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"].update(ready="owner serving until", closing="close requested by SIGTERM")
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0]["closes_on_sigterm"] = True
        for outcome, grace in (("close", "exited within grace"), ("hang", "exited within grace")):
            with self.subTest(outcome):
                self.plan({OUTCOME: {"outcome": outcome}})
                (self.state / "runs.txt").unlink(missing_ok=True)
                process = self.start("run", "--profile", "spdk-volume", "--role", "owner")
                for _ in range(400):
                    if (self.state / "runs.txt").exists():
                        break
                    time.sleep(0.05)
                time.sleep(0.3)
                process.send_signal(signal.SIGTERM)
                out, err = process.communicate(timeout=60)
                self.assertEqual(process.returncode, 4 if outcome == "hang" else 5, out + err)
                section, _ = self.receipt(err)
                case = section["cases"][0]
                self.assertEqual((case["stop"], case["grace"]), ("lane signal 15", grace))
                self.assertIn("close_requested", case)
                self.assertEqual("containment" in case, outcome == "hang", "only an unfinished case asks for containment")
                self.assertIn("cut off", section["first_failure"])
                self.assertFalse(section["credited"])
                if outcome == "hang":
                    grandchild = int((self.state / f"{OUTCOME}.grandchild").read_text())
                    self.assertEqual(state(grandchild), "T", "an uncontained descendant stays stopped, not freed")
                    self.kill_held()

    def test_a_signal_during_the_start_record_starts_no_case(self):
        """A SIGTERM that arrives while the start event waits for the observer lock leaves the case unstarted."""
        import fcntl
        observer = self.state / "observer"
        log_path = observer / "held-start.jsonl"
        log_path.parent.mkdir(parents=True)
        log_path.write_text("")
        log = log_path.open("a+")
        self.addCleanup(log.close)
        fcntl.flock(log, fcntl.LOCK_EX)
        process = self.start("run", "--profile", "spdk-volume-stop", "--role", "owner", "--episode", "held-start",
                             "--observer", str(observer))
        for _ in range(400):
            if (self.state / "builds.txt").exists():
                break
            time.sleep(0.05)
        else:
            self.fail("the role built")
        time.sleep(1.0)
        process.send_signal(signal.SIGTERM)
        time.sleep(0.3)
        fcntl.flock(log, fcntl.LOCK_UN)
        out, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 5, out + err)
        self.assertFalse((self.state / "runs.txt").exists(), "a case the lane was told to stop before it began never ran")
        self.assertIn("before", self.receipt(err)[0]["first_failure"])

    def test_the_reset_profile_credits_a_real_reset_then_an_exact_get_in_one_episode(self):
        """The reset profile's chain binds the client's reset, with its recorded pause, to a later exact GET
        that names that reset, the bytes' digest and the declared post-reset bound; a chain missing either
        element, a GET joined to another reset, a GET before the reset, other bytes or another bound refuses."""
        owner, client = "net::ena_hardware_tests::the_owner_serves", "net::ena_hardware_tests::the_client_fetches"
        chain = self.manifest["profiles"]["ena-reset"]["conjunction"][0]
        digest = chain[1].split(" sha256 ")[1].split()[0]
        reset = "reset 1 recovered link up llq unchanged pause 840 us"
        get = f"post-reset-get after reset 1 sha256 {digest} outcome complete within 500 ms request RequestId(7) after 9000 us"
        self.env.update(KESTRIKE_ALLOW_RESET="1", KESTRIKE_POST_RESET_GET_MS="500")
        self.plan({owner: {"outcome": "serve", "seconds": 2}, client: {"observe": [reset, get]}})
        observer = self.state / "observer"
        serving = self.start("run", "--profile", "ena-reset", "--role", "owner", "--episode", "r1",
                             "--observer", str(observer))
        code, out, err = self.lane("run", "--profile", "ena-reset", "--role", "client", "--episode", "r1",
                                   "--observer", str(observer))
        owner_out, owner_err = serving.communicate(timeout=60)
        self.assertEqual((serving.returncode, code), (0, 0), owner_out + owner_err + out + err)
        _, owner_receipt = self.receipt(owner_err)
        client_section, client_receipt = self.receipt(err)
        self.assertEqual(client_section["cases"][0]["inputs"]["KESTRIKE_POST_RESET_GET_MS"], "500")
        code, out, _ = self.lane("judge", "--profile", "ena-reset", owner_receipt, client_receipt)
        self.assertEqual(code, 0, out)
        for name, details, reason in (
            ("no reset", [get], "lacks client:reset 1 recovered"),
            ("no GET", [reset], "lacks client:post-reset-get after reset 1"),
            ("a GET after another reset", [reset.replace("reset 1", "reset 2"), get.replace("reset 1", "reset 2")],
             "lacks client:reset 1 recovered"),
            ("a GET joined to an unrelated reset", [reset, get.replace("after reset 1", "after reset 2")],
             "lacks client:post-reset-get after reset 1"),
            ("the GET before the reset", [get, reset], "lacks client:post-reset-get after reset 1"),
            ("other bytes", [reset, get.replace(digest, "0" * 64)], "lacks client:post-reset-get after reset 1"),
            ("another bound", [reset, get.replace("within 500 ms", "within 900 ms")], "lacks client:post-reset-get"),
            ("no recorded pause", [reset.replace(" pause 840 us", ""), get], "lacks client:reset 1 recovered"),
        ):
            forged = json.loads(Path(client_receipt).read_text())
            events = forged["hardware"]["cases"][0]["observed"]
            # Each forged line keeps the frontier of the recorded event of its name and takes the next recorded ordinal.
            templates = {event["name"]: event for event in events}
            ordinals = sorted(event["ordinal"] for event in events)
            forged["hardware"]["cases"][0]["observed"] = [
                {**templates[line.partition(" ")[0]], "detail": line.partition(" ")[2], "ordinal": ordinal}
                for line, ordinal in zip(details, ordinals)]
            path = self.state / f"reset-{name.replace(' ', '-')}.json"
            path.write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "ena-reset", owner_receipt, str(path))
            self.assertEqual(code, 1, name)
            self.assertIn(reason, out, name)

    def test_the_prerequisites_role_credits_positive_translations_and_a_real_second_node_only(self):
        """The prerequisites role credits only when the registration earned its address witness, the privileged
        page map gave positive translations and a second allowed node took a moved page; a one-node host's
        classification, or a missing translation witness, leaves the role uncredited naming the witness."""
        self.env["KESTRIKE_RELEASE_STATE_DIR"] = str(self.state / "scratch")
        self.mappings_file(self.state / "scratch" / "mappings")
        self.plan(PREREQUISITE_WITNESSES)
        code, out, err = self.lane("run", "--profile", "prerequisites", "--role", "host")
        self.assertEqual(code, 0, out + err)
        for case, line, missing in (
            (PLACEMENT, "placement one-node host, node 0 alone: second-node evidence absent", "observe: placement second node "),
            (PAGEMAP, "physical-query 0 pages present nonzero and equal to rte_mem_virt2phy",
             "observe: physical-query 4 pages present nonzero"),
            (ENVIRONMENT, "startup report without a witness", "observe: dma-witness "),
        ):
            with self.subTest(case=case):
                (self.state / "runs.txt").unlink(missing_ok=True)
                self.plan({**PREREQUISITE_WITNESSES, case: {"observe": [line]}})
                code, out, err = self.lane("run", "--profile", "prerequisites", "--role", "host")
                self.assertEqual(code, 1, out + err)
                self.assertIn(f"{case} lacks witnesses ['{missing}", self.receipt(err)[0]["first_failure"])

    def test_a_paired_profile_credits_only_from_both_roles_in_one_episode(self):
        self.plan({OWNER: {"outcome": "serve", "seconds": 2}, CLIENT: {"observe": PAIR_WITNESSES}})
        observer = self.state / "observer"
        owner = self.start("run", "--profile", "host-pair", "--role", "owner", "--episode", "e1",
                          "--observer", str(observer))
        code, out, err = self.lane("run", "--profile", "host-pair", "--role", "client", "--episode", "e1",
                                   "--observer", str(observer))
        owner_out, owner_err = owner.communicate(timeout=60)
        self.assertEqual((owner.returncode, code), (0, 0), owner_out + owner_err + out + err)
        owner_section, owner_receipt = self.receipt(owner_err)
        client_section, client_receipt = self.receipt(err)
        ready = owner_section["cases"][0]["ready"]
        ack = client_section["cases"][0]["ack"]
        self.assertEqual((ready["role"], ready["kind"], ack["acknowledges"]), ("owner", "ready", ready["ordinal"]))
        self.assertLess(ready["ordinal"], client_section["cases"][0]["start"]["ordinal"])
        code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, client_receipt)
        self.assertEqual(code, 0, out)
        code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt)
        self.assertEqual(code, 1)
        self.assertIn("role client has 0 receipts", out)
        for name, edit, code_expected, reason in (
            ("another episode", lambda s: s.update(episode="e2"), 1, "different episodes"),
            ("another toolchain", lambda s: s["toolchain"].update(rustc="rustc 1.0.0 (other)"), 1, "different toolchains"),
            ("another dependency resolution", lambda s: s.update(dependencies=["libc 0.2.0"]), 1, "different dependencies"),
            ("another build environment", lambda s: s.update(build_environment={"RUSTFLAGS": "-C target-cpu=native"}), 1,
             "different build environments"),
            ("another executable digest from another host's build", lambda s: s["executable"].update(sha256="0" * 64), 0, ""),
        ):
            moved = json.loads(Path(client_receipt).read_text())
            edit(moved["hardware"])
            other = self.state / "other.json"
            other.write_text(json.dumps(moved))
            code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, str(other))
            self.assertEqual(code, code_expected, f"{name}: {out}")
            self.assertIn(reason, out, name)
        observed = client_section["cases"][0]["observed"]
        self.assertEqual([event["name"] for event in observed], ["pressure", "healed", "history"])
        self.assertGreaterEqual(observed[0]["after"]["owner"], ready["ordinal"], "the frontier covers the readiness")
        self.assertLess(observed[0]["ordinal"], observed[1]["ordinal"])

        def observed_edit(change):
            return lambda section: change(section["cases"][0]["observed"])

        def misroute(events):
            events[0]["role"] = "owner"

        def reorder(events):
            events[0]["name"], events[1]["name"] = events[1]["name"], events[0]["name"]

        skewed = json.loads(Path(client_receipt).read_text())
        for event in skewed["hardware"]["cases"][0]["observed"]:
            event["wall_diagnostic"], event["monotonic_ns"] = 0.0, 0
        path = self.state / "skewed.json"
        path.write_text(json.dumps(skewed))
        code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, str(path))
        self.assertEqual(code, 0, "wall time and monotonic samples never order the hosts: " + out)
        for name, edit, reason in (
            ("no conjunction", observed_edit(list.clear), "lacks client:pressure"),
            ("reordered", observed_edit(reorder), "lacks client:healed after"),
            ("wall clock", observed_edit(lambda events: events[1].pop("ordinal")), "wall time only"),
            ("misrouted", observed_edit(misroute), "misrouted event"),
            ("frontier", observed_edit(lambda events: events[0]["after"].update(owner=events[0]["ordinal"] + 3)),
             "frontier its observer order contradicts"),
            ("frontier role", observed_edit(lambda events: events[1]["after"].update(owner=events[0]["ordinal"])),
             "frontier its observer order contradicts"),
            ("frontier omits", observed_edit(lambda events: events[0]["after"].clear()),
             "frontier its observer order contradicts"),
            ("frontier deleted", observed_edit(lambda events: events[0].pop("after")),
             "frontier its observer order contradicts"),
        ):
            forged = json.loads(Path(client_receipt).read_text())
            edit(forged["hardware"])
            path = self.state / f"{name}.json"
            path.write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, str(path))
            self.assertEqual(code, 1, name)
            self.assertIn(reason, out, name)
        owner_hash = json.loads(Path(owner_receipt).read_text())["hardware"]["executable"]["sha256"]
        process = self.start("judge", "--profile", "host-pair", "--sha256", owner_hash, owner_receipt, client_receipt)
        _, err = process.communicate(timeout=60)
        self.assertEqual(process.returncode, 2, "the judge takes no executable digest: builds differ by host")
        self.assertIn("unrecognized arguments: --sha256", err)
        for text in ("inf", "nan", "-1"):
            process = self.start("run", "--profile", "host-pair", "--role", "owner", "--controller-seconds", text)
            _, err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 2, f"a controller wait of {text} never reaches its timeout path")
            self.assertIn("finite duration", err)
        code, out, _ = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner", "--controller", "   ",
                                 "--episode", "blank-controller", "--observer", str(self.state / "observer"))
        self.assertEqual(code, 2, "a controller of only whitespace is refused before any case: " + out)
        self.assertIn("names no command", out)
        events = [json.loads(line) for line in (self.state / "observer" / "blank-controller.jsonl").read_text().splitlines()]
        self.assertEqual([(event["role"], event["kind"], event["status"]) for event in events], [("owner", "end", 2)],
                         "the refusal still records the role's end for the roles waiting on it")
        code, out, _ = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner", "--controller", "unbalanced '",
                                 "--episode", "unbalanced-controller", "--observer", str(self.state / "observer"))
        self.assertEqual(code, 2, out)
        self.assertIn("is not a shell command", out)
        events = [json.loads(line) for line in (self.state / "observer" / "unbalanced-controller.jsonl").read_text().splitlines()]
        self.assertEqual([(event["role"], event["kind"], event["status"]) for event in events], [("owner", "end", 2)])
        row = self.manifest["platforms"]["x86_64-nitro-ebs"]
        machine = "x86_64" if platform.machine() == "aarch64" else "aarch64"
        foreign = dict.fromkeys(lane_module().reproducer.IDENTITY_LINES[machine], "0x1")
        for name, edit in (("withdrawn support", lambda: row.update(supported=False)),
                           ("another machine", lambda: row.update(machine=machine,
                                                                  envelope={**row["envelope"], "cpu_family": foreign}))):
            saved = dict(row)
            edit()
            code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, client_receipt)
            self.assertEqual(code, 1, f"{name}: the manifest's platform row, not the receipt's copy, decides")
            self.assertIn("platform row", out, name)
            row.update(saved)
        for name, edit, reason in (
            ("empty", lambda section: section.update(cases=[]), "ran []"),
            ("credit as a string", lambda section: section.update(credited="false"), "uncredited"),
            ("another test's command", lambda section: section["cases"][0]["command"].__setitem__(2, "other::case"),
             "a command other than the exact-ID run"),
            ("a command without --exact", lambda section: section["cases"][0]["command"].pop(1),
             "a command other than the exact-ID run"),
            ("another executable in the command", lambda section: section["cases"][0]["command"].__setitem__(0, "/tmp/other"),
             "a command other than the exact-ID run"),
            ("dirty", lambda section: section.update(dirty=True), "modified tree"),
            ("uncounted", lambda section: section["cases"][0].update(listed=0), "ran"),
            ("another platform row", lambda section: section["platform"].update(row="other"), "platform row"),
            ("missing input", lambda section: section["cases"][0]["inputs"].pop("KESTRIKE_MAPPINGS"),
             "lacks inputs ['KESTRIKE_MAPPINGS']"),
            ("undeclared input", lambda section: section["cases"][0]["inputs"].update(KESTRIKE_ALLOW_RESET="1"),
             "inputs ['KESTRIKE_ALLOW_RESET'] the manifest does not declare"),
            ("an input that is no string", lambda section: section["cases"][0]["inputs"].update(KESTRIKE_PEER=7),
             "not an environment of strings"),
            ("no mappings identity", lambda section: section["cases"][0].pop("mappings"), "no mappings identity"),
            ("mappings from another path", lambda section: section["cases"][0]["mappings"].update(path="/elsewhere"),
             "no mappings identity"),
            ("mappings by a relative path", lambda section: (section["cases"][0]["inputs"].update(KESTRIKE_MAPPINGS="mappings"),
                                                              section["cases"][0]["mappings"].update(path="mappings")),
             "no mappings identity"),
            ("mappings without a digest", lambda section: section["cases"][0]["mappings"].update(sha256="abc"),
             "no mappings identity"),
            ("mappings without a format", lambda section: section["cases"][0]["mappings"].update(format=None),
             "no mappings identity"),
            ("mappings in another format", lambda section: section["cases"][0]["mappings"].update(format="4"),
             "no mappings identity"),
            ("unacknowledged readiness", lambda section: section["cases"][0].pop("ack"), "readiness"),
            ("failed exit", lambda section: section["cases"][0].update(exit=101), "exited 101"),
            ("missing witness", lambda section: section["cases"][0].update(missing_witnesses=["x"]), "lacks witnesses"),
            ("descendants", lambda section: section["cases"][0].update(descendants="left running"), "descendants"),
            ("stopped", lambda section: section["cases"][0].update(stop="deadline"), "stopped by deadline"),
            ("no duration", lambda section: section["cases"][0].pop("seconds"), "no duration within its 20 s deadline"),
            ("duration past the deadline", lambda section: section["cases"][0].update(seconds=20 + 6), "no duration within"),
            ("duration as a flag", lambda section: section["cases"][0].update(seconds=True), "no duration within"),
            ("custody", lambda section: section["cases"][0].update(custody="held"), "custody"),
            ("no summary", lambda section: section["cases"][0].update(summary=[]), "exited 0 with []"),
            ("failing summary", lambda section: section["cases"][0].update(
                summary=["test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 0.00s"]),
             "exited 0 with"),
            ("two summaries", lambda section: section["cases"][0].update(summary=section["cases"][0]["summary"] * 2),
             "exited 0 with"),
            ("closed on a signal", lambda section: section["cases"][0].update(closed="close requested by SIGTERM"),
             "closed on a SIGTERM"),
            ("no evidence", lambda section: [section.pop(key) for key in ("platform", "host", "toolchain")], "platform row"),
        ):
            forged = json.loads(Path(client_receipt).read_text())
            edit(forged["hardware"])
            path = self.state / f"{name}.json"
            path.write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "host-pair", owner_receipt, str(path))
            self.assertEqual(code, 1, name)
            self.assertIn(reason, out, name)
            self.assertIn("role client", out, name)
        for name, edit, reason in (
            ("no episode", lambda section: section.update(episode=None), "episode"),
            ("no revision", lambda section: section.pop("revision"), "revision"),
            ("no digest", lambda section: section.update(executable={}), "executable digest"),
            ("no toolchain", lambda section: section.update(toolchain={}), "toolchain"),
            ("no cargo in the toolchain", lambda section: section["toolchain"].pop("cargo"), "toolchain"),
            ("untyped toolchain", lambda section: section.update(toolchain={"rustc": True, "cargo": True}), "toolchain"),
            ("boolean attempt fields", lambda section: section.update(attempts_allowed=True, retries=False), "retry"),
            ("a retry allowed", lambda section: section.update(attempts_allowed=2), "retry"),
            ("retries declared", lambda section: section.update(retries=1), "retry"),
            ("no attempt fields", lambda section: [section.pop(key) for key in ("attempts_allowed", "retries")], "retry"),
            ("no dependencies", lambda section: section.pop("dependencies"), "dependencies"),
            ("no build environment", lambda section: section.pop("build_environment"), "build environment"),
            ("untyped dependencies", lambda section: section.update(dependencies=[True]), "dependencies"),
            ("untyped build environment", lambda section: section.update(build_environment={"RUSTFLAGS": False}),
             "build environment"),
            ("short digest", lambda section: section["executable"].update(sha256="abc"), "executable digest"),
            ("digest outside hexadecimal", lambda section: section["executable"].update(sha256="g" * 64), "executable digest"),
        ):
            paths = []
            for receipt in (owner_receipt, client_receipt):
                forged = json.loads(Path(receipt).read_text())
                edit(forged["hardware"])
                paths.append(self.state / f"{name}-{len(paths)}.json")
                paths[-1].write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "host-pair", *map(str, paths))
            self.assertEqual(code, 1, f"{name}: both receipts agree on a missing identity")
            self.assertIn(reason, out, name)
        stale = []
        for receipt in (owner_receipt, client_receipt):
            forged = json.loads(Path(receipt).read_text())
            forged["hardware"]["revision"] = "f" * 40
            stale.append(self.state / f"stale-{len(stale)}.json")
            stale[-1].write_text(json.dumps(forged))
        code, out, _ = self.lane("judge", "--profile", "host-pair", *map(str, stale))
        self.assertEqual(code, 1, "receipts that agree on another revision than the judged one earn no credit")
        self.assertIn("revision", out)
        code, out, _ = self.lane("judge", "--profile", "host-pair", "--revision", "f" * 40, *map(str, stale))
        self.assertEqual(code, 0, out)
        for name, edit_owner, edit_client in (
            ("a bare acknowledgement", lambda s: None, lambda s: s["cases"][0].update(ack=True)),
            ("an acknowledgement of another ordinal", lambda s: None,
             lambda s: s["cases"][0]["ack"].update(acknowledges=s["cases"][0]["ack"]["acknowledges"] + 7)),
            ("no readiness to acknowledge", lambda s: s["cases"][0].pop("ready"), lambda s: None),
            ("an acknowledgement from another episode", lambda s: None,
             lambda s: s["cases"][0]["ack"].update(episode="e9")),
            ("an acknowledgement logged before the readiness", lambda s: None,
             lambda s: s["cases"][0]["ack"].update(ordinal=s["cases"][0]["ack"]["acknowledges"] - 1)),
            ("a start logged before the acknowledgement", lambda s: None,
             lambda s: s["cases"][0]["start"].update(ordinal=s["cases"][0]["ack"]["ordinal"] - 1)),
            ("an acknowledgement for another case", lambda s: None,
             lambda s: s["cases"][0]["ack"].update(case="other::case")),
            ("a readiness naming another case", lambda s: s["cases"][0]["ready"].update(case="other::case"), lambda s: None),
            ("a readiness logged before its case started",
             lambda s: s["cases"][0]["start"].update(ordinal=s["cases"][0]["ready"]["ordinal"] + 1), lambda s: None),
            ("a predecessor start that is no start event", lambda s: s["cases"][0].update(start={"ordinal": 0}), lambda s: None),
            ("a predecessor start from another role", lambda s: s["cases"][0]["start"].update(role="client"), lambda s: None),
            ("boolean ordinals", lambda s: s["cases"][0]["start"].update(ordinal=False) or s["cases"][0]["ready"].update(ordinal=True),
             lambda s: s["cases"][0]["ack"].update(acknowledges=True, ordinal=2) or s["cases"][0]["start"].update(ordinal=3)),
            ("a start for another case", lambda s: None,
             lambda s: s["cases"][0]["start"].update(case="other::case")),
        ):
            paths = []
            for receipt, edit in ((owner_receipt, edit_owner), (client_receipt, edit_client)):
                forged = json.loads(Path(receipt).read_text())
                edit(forged["hardware"])
                paths.append(self.state / f"ack-{len(paths)}.json")
                paths[-1].write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "host-pair", *map(str, paths))
            self.assertEqual(code, 1, f"{name}: the client's acknowledgement must name the owner's recorded readiness")
            self.assertIn("readiness", out, name)

    def test_invalid_bytes_and_a_line_written_in_pieces_relay_each_observation_once_whole(self):
        # Splitting the UTF-8 encoding of "µ" across writes lets a poll see the line's first half alone.
        raw = [b"\xff\xfe diagnostic\n".hex(), b"observe: torn \xc2".hex(), b"\xb5s whole\n".hex()]
        self.plan({OUTCOME: {"raw": raw, "observe": ["after the pieces"]}})
        code, out, err = self.lane("run", "--profile", "spdk-volume", "--role", "owner", "--episode", "u1",
                                   "--observer", str(self.state / "observer"))
        self.assertEqual(code, 0, out + err)
        case = self.receipt(err)[0]["cases"][0]
        self.assertEqual([(event["name"], event["detail"]) for event in case["observed"]],
                         [("torn", "\u00b5s whole"), ("after", "the pieces")])

    def test_the_sigkill_profile_is_unrun_without_abrupt_death_evidence_and_kills_at_its_point_with_it(self):
        self.plan({OWNER: {"outcome": "serve", "seconds": 30}})
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertIn("unrun: no abrupt-death evidence named by KESTRIKE_ABRUPT_DEATH_EVIDENCE",
                      section["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "the owner never started")
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 1
        started = time.monotonic()
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a",
                                   "--observer", str(self.state / "observer"))
        self.assertEqual(code, 0, out + err)
        self.assertLess(time.monotonic() - started, 20, "the lane killed the owner, not its deadline")
        case = self.receipt(err)[0]["cases"][0]
        self.assertEqual((case["exit"], case["killed"]["kind"]), (-signal.SIGKILL, "killed"))
        self.assertLess(case["ready"]["ordinal"], case["killed"]["ordinal"])
        self.assertEqual(case["evidence"]["sha256"], hashlib.sha256(b"{}").hexdigest())
        # The role itself left the host's kill marker, so a runner ended before the sweep collects it changes nothing.
        marker = json.loads(next((self.state / "custody").glob("killed-*.json")).read_text())
        self.assertEqual((marker["pgid"], marker["role"], marker["case"]), (None, "owner-a", case["id"]), marker)
        self.plan({OWNER: {"outcome": "serve", "seconds": 1}})
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 10
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a")
        self.assertEqual(code, 1, out + err)
        self.assertIn("was not killed at its declared point; exit 0", self.receipt(err)[0]["first_failure"])

    def test_the_reset_and_kill_packages_credit_only_the_whole_retained_set_under_a_supported_row(self):
        """The committed manifest holds both warm-cycle packages pending on every row, so a supported row and a run
        printing every witness still leave each Inconclusive. Under a `runs` disposition each earns credit only once
        every witness its profile declares printed: a missing fault witness or one member short leaves that witness
        missing, the process-kill package is unrun without the deployment owner's
        abrupt-death evidence, and the judge refuses a credited receipt once the profile is pending again or the row
        is unsupported."""
        cycle = SPDK + "warm_cycle::"
        reset, killed = (cycle + "a_controller_reset_after_a_quiesced_close_keeps_the_retained_set_warm",
                         cycle + "a_killed_owner_keeps_the_retained_set_warm_for_its_restart")
        retained = "retained S 23/23 bytes 1012 omitted 1 installed 23 covered-miss true reserved 41 overlapping 0"
        faults = {reset: "controller-reset cc 0x460000 csts 0x0 after captured slot 0",
                  killed: "process-kill signal 9 pid 7 after captured slot 0"}
        profiles = {reset: "cr1-controller-reset", killed: "pk1-process-kill"}
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.plan({case: {"observe": [fault, retained, *PACKAGE_LINES[1:]]} for case, fault in faults.items()})
        for profile in profiles.values():
            code, out, err = self.lane("run", "--profile", profile, "--role", "owner")
            self.assertEqual(code, 1, out + err)
            self.assertEqual(self.receipt(err)[0]["first_failure"],
                             "Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is pending")
        for profile in profiles.values():
            self.manifest["profiles"][profile]["platforms"]["x86_64-nitro-ebs"] = "runs"
        receipts = {}
        for case, profile in profiles.items():
            code, out, err = self.lane("run", "--profile", profile, "--role", "owner")
            self.assertEqual(code, 0, out + err)
            receipts[profile] = self.receipt(err)[1]
            self.assertEqual(self.lane("judge", "--profile", profile, receipts[profile])[0], 0)
        expected = {reset: "observe: controller-reset cc ", killed: "observe: process-kill signal 9 "}
        for case, profile in profiles.items():
            for observe, missing in (([retained, *PACKAGE_LINES[1:]], expected[case]),
                                     ([faults[case], retained.replace("23/23", "22/23"), *PACKAGE_LINES[1:]],
                                      "observe: retained S 23/23 ")):
                self.plan({case: {"observe": observe}})
                code, out, err = self.lane("run", "--profile", profile, "--role", "owner")
                self.assertEqual(code, 1, out + err)
                self.assertEqual(self.receipt(err)[0]["cases"][0]["missing_witnesses"], [missing])
        del self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"]
        code, out, err = self.lane("run", "--profile", "pk1-process-kill", "--role", "owner")
        self.assertEqual(code, 1, out + err)
        self.assertIn("unrun: no abrupt-death evidence named by KESTRIKE_ABRUPT_DEATH_EVIDENCE",
                      self.receipt(err)[0]["first_failure"])
        for profile, receipt in receipts.items():
            self.manifest["profiles"][profile]["platforms"]["x86_64-nitro-ebs"] = "pending"
            code, out, _ = self.lane("judge", "--profile", profile, receipt)
            self.assertNotEqual(code, 0, out)
            self.assertIn("the profile's disposition on platform row x86_64-nitro-ebs is pending", out)
            self.manifest["profiles"][profile]["platforms"]["x86_64-nitro-ebs"] = "runs"
        self.manifest["platforms"]["x86_64-nitro-ebs"]["supported"] = False
        for profile, receipt in receipts.items():
            code, out, _ = self.lane("judge", "--profile", profile, receipt)
            self.assertNotEqual(code, 0, out)
            self.assertIn("platform row unsupported: x86_64-nitro-ebs", out)

    def test_package_campaigns_judge_from_lane_receipts_and_stay_uncredited_on_the_committed_owner_inputs(self):
        """One repeat of each package, run by the lane in its run identity's episode under an observer log, feeds the
        package judge with the real lane. Under the committed pending disposition the repeat is missing evidence with
        the lane's reason. Under a `runs` disposition safety, retention, progress and residuals pass from the receipt's
        lines and raw artifacts, containment waits on the restoration record no package binds, and the package reads
        inconclusive on the committed owner inputs. The repeat binds the volume the mappings file names, so a safety
        manifest that lists only the host leaves that volume unaccounted; a run without the observer log is missing
        for its absent start event, and under an unsupported row the same receipt is a missing repeat with the
        lane's reason."""
        spec = importlib.util.spec_from_file_location("recovery_packages", ROOT / "scripts/recovery-packages.py")
        assert spec is not None and spec.loader is not None
        packages = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(packages)
        lane = lane_module()
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        (self.state / "mappings").write_text(f"format=3\nnvme.volume=vol-0pkg\nnvme.bdf={pci_function()}\n")
        digest = hashlib.sha256(self.write_manifest().read_bytes()).hexdigest()
        for name, profile, injection in (("CR-1", "cr1-controller-reset", PACKAGE_FIXTURE["controller-reset"]),
                                         ("PK-1", "pk1-process-kill", PACKAGE_FIXTURE["process-kill"])):
            with self.subTest(name):
                package = self.manifest["packages"]["packages"][name]
                campaign = packages.campaign_id(digest, name, self.revision)
                self.plan({package["case"]: {"observe": [injection, *PACKAGE_LINES]}})
                code, out, err = self.lane("run", "--profile", profile, "--role", "owner",
                                           "--episode", f"{campaign}-{name}-r1",
                                           "--observer", str(self.state / "observer"))
                self.assertEqual(code, 1, out + err)
                pending = {"campaign": campaign, "package": name, "revision": self.revision,
                           "runs": [{"repeat": 1, "receipt": self.receipt(err)[1]}],
                           "stopped": {"repeat": 1, "reason": "a repeat the lane leaves uncredited"}}
                held = packages.judge(self.manifest, digest, pending, lane)
                self.assertIn("the profile's disposition on platform row x86_64-nitro-ebs is pending",
                              held["repeats"][0]["missing"])
                self.assertEqual(held["verdict"], "inconclusive")
                self.manifest["profiles"][profile]["platforms"]["x86_64-nitro-ebs"] = "runs"
                digest = hashlib.sha256(self.write_manifest().read_bytes()).hexdigest()
                campaign = packages.campaign_id(digest, name, self.revision)
                code, out, err = self.lane("run", "--profile", profile, "--role", "owner",
                                           "--episode", f"{campaign}-{name}-r1",
                                           "--observer", str(self.state / "observer"))
                self.assertEqual(code, 0, out + err)
                section, receipt = self.receipt(err)
                self.assertEqual(section["cases"][0]["mappings"]["volume"], "vol-0pkg")
                self.assertEqual(section["cases"][0]["start"]["ordinal"], 1)
                written = json.loads(Path(receipt).read_text())
                written["hardware"]["host"]["instance"] = "i-pkg"
                Path(receipt).write_text(json.dumps(written))
                safety = {"tag": {"key": "kestrike-campaign", "value": campaign}, "owner": "qualification",
                          "budget_usd": 10, "deadline": "2031-01-01T00:00:00Z", "teardown_on_failure": True,
                          "preexisting": [], "resources": [], "teardown": [], "standing": ["i-pkg", "vol-0pkg"],
                          "residue": []}
                run = {"campaign": campaign, "package": name, "revision": self.revision,
                       "runs": [{"repeat": 1, "receipt": receipt}], "safety": safety}
                judged = packages.judge(self.manifest, digest, run, lane)
                self.assertEqual(judged["reasons"], [], judged)
                self.assertEqual(judged["verdicts"], {"safety": "pass", "containment": "inconclusive",
                                                      "retention": "pass", "progress": "pass", "residuals": "pass"})
                self.assertEqual(judged["verdict"], "inconclusive")
                self.assertIn(f"package {name} declares no injection authority", judged["open"])
                self.assertEqual(judged["repeats"][0]["measurements"]["unaffected_bytes"], 1012)
                self.assertEqual(judged["identity"]["row"], "x86_64-nitro-ebs")
                unlisted = packages.judge(self.manifest, digest, {**run, "safety": {**safety, "standing": ["i-pkg"]}},
                                          lane)
                self.assertIn("the admitted runs bind ['vol-0pkg'], which the safety manifest lists neither as "
                              "creates nor as standing", unlisted["reasons"])
                unsupported = json.loads(json.dumps(self.manifest))
                unsupported["platforms"]["x86_64-nitro-ebs"]["supported"] = False
                missing = packages.judge(unsupported, digest, run, lane)
                self.assertIn("platform row unsupported: x86_64-nitro-ebs", missing["repeats"][0]["missing"])
                self.assertEqual(missing["verdicts"]["retention"], "inconclusive")
                code, out, err = self.lane("run", "--profile", profile, "--role", "owner",
                                           "--episode", f"{campaign}-{name}-r1")
                self.assertEqual(code, 0, out + err)
                unobserved = packages.judge(self.manifest, digest,
                                            {**run, "runs": [{"repeat": 1, "receipt": self.receipt(err)[1]}]}, lane)
                self.assertIn("only under an observer log", unobserved["repeats"][0]["missing"])

    def test_a_kill_the_observer_could_not_record_still_marks_the_host_and_holds_the_sweep(self):
        """The observer lock is held when the kill is recorded: the marker went down before the SIGKILL, the receipt
        records the kill as unrecorded, and the sweep reads that as a kill sent."""
        import fcntl
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 2
        self.plan({OWNER: {"outcome": "serve", "seconds": 30}})
        observer = self.state / "observer"
        process = self.start("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a",
                             "--episode", "lock-kill", "--observer", str(observer))
        log_path = observer / "lock-kill.jsonl"
        for _ in range(600):
            if log_path.exists() and '"kind": "ready"' in log_path.read_text():
                break
            time.sleep(0.05)
        else:
            self.fail("the case became ready")
        log = log_path.open("a+")
        self.addCleanup(log.close)
        fcntl.flock(log, fcntl.LOCK_EX)
        out, err = process.communicate(timeout=120)
        fcntl.flock(log, fcntl.LOCK_UN)
        self.assertEqual(process.returncode, 2, out + err)
        section, _ = self.receipt(err)
        self.assertIn("could not record its kill", section["first_failure"])
        case = section["cases"][0]
        self.assertEqual(case["exit"], -signal.SIGKILL)
        self.assertIn("unrecorded", case["killed"], "the receipt records the kill the observer could not")
        self.assertTrue((self.state / "custody" / "killed-lock-kill.json").exists(), "the marker preceded the kill")
        lane = lane_module()
        self.assertTrue(lane.sent_kill(err), "the sweep reads the unrecorded kill as a kill sent")
        self.kill_held()

    def test_a_kill_whose_marker_cannot_be_written_is_withheld_and_the_case_closed(self):
        """A directory where the kill marker would go makes its write fail: the SIGKILL is withheld, since nothing
        would guard the host, and the case is closed as on a lane signal with the failure named."""
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 1
        self.plan({OWNER: {"outcome": "serve", "seconds": 30}})
        (self.state / "custody" / "killed-withheld.json").mkdir(parents=True)
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a",
                                   "--episode", "withheld")
        self.assertEqual(code, 1, out + err)
        section, _ = self.receipt(err)
        self.assertIn("was not killed: its kill marker could not be written", section["first_failure"])
        case = section["cases"][0]
        self.assertNotIn("killed", case, "no SIGKILL was sent")
        self.assertNotEqual(case["exit"], -signal.SIGKILL)
        self.assertEqual(case["stop"], "kill withheld: its marker could not be written")
        self.assertNotIn("custody", case, "the closed case holds nothing")
        self.assertEqual([m.name for m in (self.state / "custody").glob("*.json")], ["killed-withheld.json"],
                         "the closed case left no group marker")
        self.kill_held()

    def test_the_sigkill_profile_credits_only_a_killed_owner_beside_a_healthy_one(self):
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        # The ambient environment supplies client-a's pinned index and stopped owner, so the role runs without a file.
        self.env.update(KESTRIKE_ABRUPT_DEATH_EVIDENCE=str(evidence), KESTRIKE_PEERS="10.0.0.1,10.0.0.2",
                        KESTRIKE_CLIENT="0", KESTRIKE_STOPPED="0")
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 0
        # The roles run and are judged under the manifest's profile with client-b and its conjunction chain removed.
        profile = self.manifest["profiles"]["host-pair-two-owners-sigkill"]
        full = json.loads(json.dumps(profile))
        profile["roles"].pop("client-b")
        profile["conjunction"] = [chain for chain in profile["conjunction"] if not any("client-b:" in e for e in chain)]
        self.plan({OWNER: {"outcome": "serve", "seconds": 4}, TWO_OWNERS: {"observe": TWO_OWNER_WITNESSES}})
        observer = ["--episode", "k1", "--observer", str(self.state / "observer")]
        roles = {role: self.start("run", "--profile", "host-pair-two-owners-sigkill", "--role", role, *observer)
                 for role in ("owner-a", "owner-b")}
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "client-a", *observer)
        self.assertEqual(code, 0, out + err)
        receipts = [self.receipt(err)[1]]
        for role, process in roles.items():
            role_out, role_err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 0, role + role_out + role_err)
            receipts.append(self.receipt(role_err)[1])
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", *receipts)
        self.assertEqual(code, 0, out)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"] = full
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", *receipts)
        self.assertEqual(code, 1, "client-b never ran: " + out)
        self.assertIn("role client-b has 0 receipts", out)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"] = profile
        swapped = json.loads(Path(receipts[0]).read_text())
        swapped["hardware"]["cases"][0]["inputs"]["KESTRIKE_STOPPED"] = "1"
        path = self.state / "swapped.json"
        path.write_text(json.dumps(swapped))
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", str(path), *receipts[1:])
        self.assertEqual(code, 1, out)
        self.assertIn("differ from the role's declared", out, "the client's stopped owner is pinned by its role")
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["client-a"]["env"]["KESTRIKE_STOPPED"] = "1"
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", str(path), *receipts[1:])
        self.assertEqual(code, 1, out)
        self.assertIn("lacks client-a:failure owner {KESTRIKE_STOPPED}", out, "the failed index names the killed owner")
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["client-a"]["env"]["KESTRIKE_STOPPED"] = "0"
        unproven = json.loads(Path(receipts[2]).read_text())
        unproven["hardware"]["cases"][0].pop("evidence")
        path = self.state / "unproven.json"
        path.write_text(json.dumps(unproven))
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", *receipts[:2], str(path))
        self.assertEqual(code, 1, out)
        self.assertIn("do not share one KESTRIKE_ABRUPT_DEATH_EVIDENCE evidence file", out)
        unkilled = json.loads(Path(receipts[1]).read_text())
        unkilled["hardware"]["cases"][0].pop("killed")
        path = self.state / "unkilled.json"
        path.write_text(json.dumps(unkilled))
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners-sigkill", receipts[0], str(path),
                                 receipts[2])
        self.assertEqual(code, 1, out)
        self.assertIn("lacks owner-a:killed", out)

    def test_a_lane_signal_before_the_kill_point_closes_the_case_instead_of_killing_it(self):
        """A SIGTERM to the lane that arrives before the scheduled kill takes the close path: the case gets
        SIGTERM, no `killed` event is appended, and the run is interrupted rather than credited from a kill."""
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 0
        self.plan({OWNER: {"outcome": "close", "ready_after": 3}})
        process = self.start("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a")
        for _ in range(400):
            if (self.state / "runs.txt").exists():
                break
            time.sleep(0.05)
        else:
            self.fail("the owner did not start")
        # The stopped lane resumes with both a pending signal and an owner whose close handler is installed.
        process.send_signal(signal.SIGSTOP)
        try:
            for _ in range(400):
                if state(process.pid) == "T" and (self.state / f"{OWNER}.ready").exists():
                    break
                time.sleep(0.05)
            else:
                self.fail("the stopped lane's owner did not install its close handler")
            process.send_signal(signal.SIGTERM)
        finally:
            process.send_signal(signal.SIGCONT)
        out, err = process.communicate(timeout=60)
        section, _ = self.receipt(err)
        case = section["cases"][0]
        self.assertEqual((process.returncode, case.get("stop"), case.get("grace"), "killed" in case),
                         (5, "lane signal 15", "exited within grace", False), out + err + json.dumps(case))
        self.assertFalse(section["credited"])

    def test_a_killed_role_whose_group_outlives_its_sigkill_is_held_and_uncredited(self):
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 1
        # This process is the subreaper (PR_SET_CHILD_SUBREAPER above) and never waits, so the SIGKILLed
        # grandchild stays a zombie member of the case's group, standing in for a member stuck in teardown.
        self.plan({OWNER: {"outcome": "hang"}})
        started = time.monotonic()
        code, out, err = self.lane("run", "--profile", "host-pair-two-owners-sigkill", "--role", "owner-a")
        self.assertEqual(code, 4, out + err)
        self.assertLess(time.monotonic() - started, 20, "the grace bounds the wait after the kill")
        section, _ = self.receipt(err)
        self.assertIn("process group outlived its scheduled SIGKILL", section["first_failure"])
        self.assertIn("held: process group", section["cases"][0]["custody"])
        self.assertIn("custody held: process group", out)
        self.kill_held()

    def test_a_dependent_role_waits_as_long_as_its_predecessors_may_take_to_report_readiness(self):
        """The wait is the predecessors' case deadlines, so a client with a short deadline of its own still
        acknowledges an owner that becomes ready late within the owner's deadline."""
        self.manifest["profiles"]["host-pair"]["roles"]["client"]["cases"][0]["deadline"] = 3
        self.manifest["profiles"]["host-pair"]["roles"]["owner"]["cases"][0]["deadline"] = 20
        self.plan({OWNER: {"outcome": "serve", "mute": True, "say": "owner serving until", "delay": 5, "seconds": 2},
                   CLIENT: {"observe": PAIR_WITNESSES}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="late-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        self.assertIn("host-pair/client: credited", out, "the client's own 3 s deadline does not cut its wait short")

    def test_a_refused_role_file_still_records_the_role_s_end(self):
        """A `run` whose `--environment` is refused writes no receipt, yet the roles waiting on it must stop waiting."""
        code, out, err = self.lane("run", "--profile", "host-pair", "--role", "owner", "--episode", "refused-1",
                                   "--observer", str(self.state / "observer"), "--environment", "owner.env")
        self.assertEqual(code, 2, out + err)
        self.assertIn("is not an absolute path", out)
        log = self.state / "observer" / "refused-1.jsonl"
        self.assertTrue(log.exists(), "the refusal is recorded in the observer log")
        events = [json.loads(line) for line in log.read_text().splitlines()]
        self.assertEqual([(event["role"], event["kind"], event["status"]) for event in events], [("owner", "end", 2)])

    def test_a_role_s_cases_record_one_value_per_repeated_input(self):
        """One role runs its cases from one environment, so a receipt whose cases disagree on an input is forged."""
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner")
        self.assertEqual(code, 0, out + err)
        section, path = self.receipt(err)
        self.assertEqual(len(section["cases"]), 2)
        for name, edit in (
            ("another mappings path in the second case",
             lambda s: s["cases"][1]["inputs"].update(KESTRIKE_MAPPINGS="/elsewhere/mappings")),
            ("another mappings digest in the second case", lambda s: s["cases"][1]["mappings"].update(sha256="0" * 64)),
        ):
            forged = json.loads(Path(path).read_text())
            edit(forged["hardware"])
            other = self.state / "varying.json"
            other.write_text(json.dumps(forged))
            code, out, _ = self.lane("judge", "--profile", "spdk-volume-stop", str(other))
            self.assertEqual(code, 1, f"{name}: {out}")
            self.assertIn("record different values", out, name)

    def observer_end(self, episode, profile, role):
        """An observer log in which `role` already ended without readiness, so a dependent stops waiting at once."""
        log = self.state / "observer" / f"{episode}.jsonl"
        log.parent.mkdir(parents=True, exist_ok=True)
        log.write_text(json.dumps({"episode": episode, "ordinal": 1, "profile": profile, "role": role, "kind": "end",
                                   "status": 1}) + "\n")

    def test_a_client_without_its_owner_readiness_is_uncredited(self):
        self.observer_end("lonely", "host-pair", "owner")
        code, out, err = self.lane("run", "--profile", "host-pair", "--role", "client", "--episode", "lonely",
                                   "--observer", str(self.state / "observer"))
        self.assertEqual(code, 1, out + err)
        self.assertIn("without the owner role's readiness", self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "the client case never started")

    def test_a_case_naming_half_a_channel_is_rejected(self):
        case = self.manifest["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0]
        case["inputs"].remove("KESTRIKE_CONTROLLER_REQUESTS")
        code, out, err = self.lane("run", "--profile", "spdk-containment", "--role", "owner")
        self.assertEqual(code, 2, out + err)
        self.assertIn("names half a channel", out + err)

    def test_a_dependent_role_stops_waiting_once_its_predecessor_ended_without_readiness(self):
        """An owner that fails before its readiness line ends the client's wait at once, so a failed setup
        releases the runner instead of holding it for the whole readiness window."""
        self.plan({OWNER: {"outcome": "fail", "mute": True, "seconds": 0}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="early",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        begun = time.monotonic()
        code, out, _ = self.lane("sweep")
        elapsed = time.monotonic() - begun
        self.assertEqual(code, 1, out)
        self.assertIn("host-pair/owner: not credited", out)
        self.assertIn("without the owner role's readiness", out)
        self.assertLess(elapsed, 12, "the client's 20 s readiness window ended with the owner's run, not by its deadline")
        events = [json.loads(line) for line in (self.state / "observer" / "early.jsonl").read_text().splitlines()]
        self.assertEqual([event["role"] for event in events if event["kind"] == "end"], ["owner", "client"],
                         "each role records its end once")

    def test_the_containment_profile_is_the_last_the_sweep_continues_past(self):
        """A credited containment case leaves its endpoint fenced, and the sweep runs the profiles in manifest
        order, so every profile that uses the endpoint afterwards would fail; the manifest lists it after
        every other profile. The kill profile closes the manifest: its killed host awaits containment and
        the sweep exits held after it, so the profiles after it would run nowhere."""
        self.assertEqual(list(self.manifest["profiles"])[-2:], ["spdk-containment", "host-pair-two-owners-sigkill"])

    def test_a_malformed_manifest_or_uncovered_registry_row_is_rejected(self):
        clean = json.loads(json.dumps(self.manifest))
        owner = ("profiles", "spdk-volume-stop", "roles", "owner", "cases")
        for edit, reason in (
            (lambda m: m["profiles"]["spdk-volume"].update(retries=1), "declares retries"),
            (lambda m: m["platforms"].update({"r8gb/4xl": m["platforms"]["x86_64-nitro-ebs"]}), "is not an episode name"),
            (lambda m: m.update(platforms=list(m["platforms"])), "platforms and profiles must be objects"),
            (lambda m: m["platforms"]["x86_64-nitro-ebs"]["envelope"].update(cpu_features="fpu sse4_2"),
             "short of ['cpu_features']"),
            (lambda m: m["profiles"]["spdk-volume"]["platforms"].pop("aarch64-r8gb-4xlarge-ebs"), "one disposition"),
            (lambda m: m["profiles"]["spdk-volume"]["platforms"].update({"x86_64-nitro-ebs": "maybe"}), "one disposition"),
            (lambda m: m["profiles"]["spdk-volume"].update(platform="x86_64-nitro-ebs"), "profile spdk-volume"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(expected=0), "expects no test"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=float("inf")),
             "finite positive deadline"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(grace=True), "finite positive deadline"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"].update(ready=1, closing="close requested by SIGTERM"),
             "readiness and closing lines are non-empty strings"),
            (lambda m: m["profiles"]["host-pair-put"]["roles"]["client"].pop("ready"), "declares no readiness line"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0]["inputs"].append("KESTRIKE_EPISODE"),
             "KESTRIKE_EPISODE, which the lane sets itself"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"].update(env={"KESTRIKE_EPISODE": "e1"}),
             "KESTRIKE_EPISODE, which the lane sets itself"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(closes_on_sigterm=True),
             "closes on SIGTERM without a readiness and a closing line"),
            (lambda m: (m["profiles"]["spdk-containment"]["roles"]["owner"].update(ready="census", closing="done"),
                        m["profiles"]["spdk-containment"]["roles"]["owner"]["cases"][0].update(closes_on_sigterm=True)),
             "closes on SIGTERM while parked on its containment channel"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"].update(env={"CLIENT": "0"}), "env"),
            (lambda m: m["profiles"].update(late=m["profiles"]["spdk-volume"]), "follows the kill profile"),
            (lambda m: m["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"].update(kill=True), "kill"),
            (lambda m: m["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"].update(kill=float("inf")), "kill"),
            (lambda m: m["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["cases"].append(
                dict(m["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["cases"][0], id="net::other")),
             "kill role runs one case"),
            (lambda m: m["profiles"]["host-pair-two-owners-sigkill"].pop("evidence"), "evidence"),
            (lambda m: m["profiles"]["host-pair"].update(conjunction=["client:pressure"]), "conjunction"),
            (lambda m: m["profiles"]["host-pair"].update(conjunction=[["reader:pressure"]]), "conjunction"),
            (lambda m: m["profiles"]["host-pair"].update(conjunction=[[]]), "conjunction"),
            (lambda m: m["profiles"]["spdk-volume"]["roles"]["owner"].update(env={"KESTRIKE_CLIENT": 0}), "env"),
            (lambda m: m["profiles"]["host-pair-put"]["roles"]["reader"]["env"].update(KESTRIKE_CLIENT="0"),
             "one client index for two roles"),
            (lambda m: m[owner[0]][owner[1]][owner[2]][owner[3]][owner[4]].append(
                m[owner[0]][owner[1]][owner[2]][owner[3]][owner[4]][0]), "names a case twice"),
            (lambda m: m.update(extra={}), "top-level keys"),
            (lambda m: m.update(qualification=[]), "top-level keys"),
            (lambda m: m.pop("version"), "top-level keys"),
        ):
            self.manifest = json.loads(json.dumps(clean))
            edit(self.manifest)
            code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
            self.assertEqual(code, 2, out)
            self.assertIn(reason, out)
        self.manifest = json.loads(MANIFEST.read_text())
        del self.manifest["profiles"]["prerequisites"]
        code, out, _ = self.lane("run", "--profile", "spdk-volume", "--role", "owner")
        self.assertEqual(code, 2, out)
        self.assertIn("hardware-privileged registry rows differ", out)
        code, out, _ = self.lane("judge", "--profile", "spdk-volume", str(self.state / "absent.json"))
        self.assertEqual(code, 2, "judge applies the registry check before reading any receipt: " + out)
        self.assertIn("hardware-privileged registry rows differ", out)

    def test_the_sweep_lists_every_unprovisioned_role_as_unrun_and_credits_nothing(self):
        """A host provisioned for no role fails the sweep, so a misrouted job is red; a provisioned host lists the
        roles it lacks as unrun and credits none."""
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("provisioned for no hardware case", out)
        self.assertFalse((self.state / "builds.txt").exists())
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume-stop/owner")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        roles = sum(len(profile["roles"]) for profile in self.manifest["profiles"].values())
        self.assertEqual(out.count("unrun; this host is not provisioned for it"), roles - 1)
        self.assertIn("a sweep credits none", out)

    def test_the_sweep_starts_consecutive_profiles_its_row_does_not_run_at_once_and_each_runnable_one_alone(self):
        """The roles of consecutive profiles the row does not run start together, since each stops before its
        build; a profile the row runs starts after the group before it exits, and the next group after it. Each
        role runs `git status` before its platform check; the fake git holds that call until three roles have
        arrived or the wait ends and records how many had arrived."""
        bin_dir = self.state / "bin"
        bin_dir.mkdir()
        (bin_dir / "git").write_text(GIT)
        (bin_dir / "git").chmod(0o755)
        self.env.update(PATH=f"{bin_dir}{os.pathsep}{self.env['PATH']}", FAKE_GIT=shutil.which("git"),
                        FAKE_GIT_PARTIES="3", FAKE_GIT_WAIT="1.5",
                        KESTRIKE_HARDWARE_ROLES="clockbound-host/host spdk-volume/owner spdk-volume-attach/owner")
        self.assertEqual(list(self.manifest["profiles"])[:3], ["clockbound-host", "spdk-volume", "spdk-volume-attach"])
        code, out, _ = self.lane("sweep", "--platform", "aarch64-r8gb-4xlarge-ebs")
        self.assertEqual(code, 1, out)
        self.assertEqual(out.count("not credited: Inconclusive: platform row unsupported: aarch64-r8gb-4xlarge-ebs"), 3)
        self.assertEqual((self.state / "git-arrivals.txt").read_text().split(), ["3", "3", "3"],
                         "every role of the unsupported row's profiles runs at once")
        shutil.rmtree(self.state / "git-arrived")
        (self.state / "git-arrivals.txt").unlink()
        for name in ("clockbound-host", "spdk-volume-attach"):
            self.manifest["profiles"][name]["platforms"]["x86_64-nitro-ebs"] = "pending"
        code, out, _ = self.lane("sweep", "--platform", "x86_64-nitro-ebs")
        self.assertEqual(code, 1, out)
        self.assertIn("spdk-volume/owner: credited on platform row x86_64-nitro-ebs", out)
        self.assertEqual(out.count("Inconclusive: the profile's disposition on platform row x86_64-nitro-ebs is pending"),
                         2)
        self.assertEqual((self.state / "git-arrivals.txt").read_text().split(), ["1", "2", "3"],
                         "the runnable profile between two pending ones starts alone, after the first and before the last")

    def test_the_sweep_refuses_an_undeclared_role_and_keys_readiness_by_profile(self):
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/onwer")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("undeclared roles ['host-pair/onwer']", out)
        self.plan({OWNER: {"outcome": "serve", "seconds": 1}})
        self.manifest["profiles"]["host-pair"]["roles"]["owner"]["cases"][0]["deadline"] = 1
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair-put/owner host-pair/client", KESTRIKE_EPISODE="mixed",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 1, out)
        self.assertIn("host-pair/client: not credited", out)
        self.assertIn("without the owner role's readiness", out)
        self.assertIn("host-pair-put/owner: credited", out)

    def test_the_sweep_refuses_a_role_set_past_its_budget_and_stops_after_held_custody(self):
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume/owner spdk-volume-stop/owner")
        for text in ("nan", "inf"):
            process = self.start("sweep", "--budget-seconds", text)
            _, err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 2, f"a budget of {text} binds nothing")
            self.assertIn("finite duration", err)
        self.assertFalse((self.state / "builds.txt").exists(), "a refused budget builds nothing")
        code, out, _ = self.lane("sweep", "--budget-seconds", "10")
        self.assertEqual(code, 2, out)
        self.assertIn("past the 10.0 s budget", out)
        lane = lane_module()
        runnable = lane.role_seconds(self.manifest["profiles"]["spdk-volume"], "owner")
        self.manifest["profiles"]["spdk-volume-stop"]["platforms"]["x86_64-nitro-ebs"] = "pending"
        code, out, _ = self.lane("sweep", "--budget-seconds", str(runnable))
        self.assertEqual(code, 2, out)
        self.assertIn(f"need up to {runnable + lane.OBSERVER_SECONDS} s", out,
                      "a runnable profile keeps its case bound and a pending one costs its end event")
        self.manifest["profiles"]["spdk-volume"]["platforms"]["x86_64-nitro-ebs"] = "pending"
        code, out, _ = self.lane("sweep", "--budget-seconds", str(2 * lane.OBSERVER_SECONDS - 1))
        self.assertEqual(code, 2, out)
        self.assertIn(f"need up to {2 * lane.OBSERVER_SECONDS} s", out, "each refused role's end event is charged")
        self.env.update(GITHUB_RUN_ID="7", GITHUB_RUN_ATTEMPT="2")
        for row in ("x86_64-nitro-ebs", "aarch64-r8gb-4xlarge-ebs"):
            with self.subTest(episode_row=row):
                code, out, _ = self.lane("sweep", "--budget-seconds", "10", "--platform", row)
                self.assertEqual(code, 1, out)
                self.assertIn("not credited: Inconclusive", out)
                self.assertNotIn("budget", out, "a role its row stops before any build costs no case bound")
                self.assertNotIn("already", out)
                self.assertFalse((self.state / "builds.txt").exists(), out)
                self.assertTrue((self.state / "artifacts" / "observer" / f"7-2-{row}.jsonl").exists(),
                                "a CI episode names its platform row, so the legs of one run open distinct logs")
        del self.env["GITHUB_RUN_ID"], self.env["GITHUB_RUN_ATTEMPT"]
        for name in ("spdk-volume", "spdk-volume-stop"):
            self.manifest["profiles"][name]["platforms"]["x86_64-nitro-ebs"] = "runs"
        self.manifest["platforms"]["x86_64-nitro-ebs"]["supported"] = False
        code, out, _ = self.lane("sweep", "--budget-seconds", "10")
        self.assertNotIn("budget", out, "an unsupported row charges no case bound")
        self.assertFalse((self.state / "builds.txt").exists(), out)
        self.manifest["platforms"]["x86_64-nitro-ebs"]["supported"] = True
        self.manifest["profiles"]["host-pair"]["roles"]["client"]["cases"][0].update(deadline=1, grace=1)
        self.manifest["profiles"]["host-pair"]["roles"]["owner"]["cases"][0].update(deadline=1)
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/client")
        code, out, _ = self.lane("sweep", "--budget-seconds", "10")
        self.assertEqual(code, 2, out)
        self.assertIn("past the 10.0 s budget", out, "the readiness wait and the controller window count")
        self.assertFalse((self.state / "builds.txt").exists())
        without_stop = 1 + 1 + 1 + lane.CONTROLLER_SECONDS
        code, out, _ = self.lane("sweep", "--budget-seconds", str(without_stop))
        self.assertEqual(code, 2, out)
        self.assertIn(f"past the {without_stop} s budget", out,
                      "the stop proof and its repeat in hold count: a budget that omits them is refused")
        without_observer = without_stop + 2 * lane.STOP_SECONDS
        code, out, _ = self.lane("sweep", "--budget-seconds", str(without_observer))
        self.assertEqual(code, 2, out)
        self.assertIn(f"past the {without_observer} s budget", out,
                      "the observer lock waits count: a budget that omits them is refused")
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume/owner spdk-volume-stop/owner")
        self.manifest["profiles"]["spdk-volume"]["roles"]["owner"]["cases"][0].update(deadline=1, grace=1)
        self.plan({OUTCOME: {"outcome": "stubborn"}})
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn("custody held: process group", out)
        self.assertIn("- spdk-volume-stop/owner: unrun; custody is held or unknown", out)
        self.kill_held()

    def test_the_sweep_starts_no_later_profile_after_a_role_supervisor_dies(self):
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume/owner spdk-volume-stop/owner")
        self.plan({OUTCOME: {"outcome": "orphan"}})
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn("custody unknown", out)
        self.assertIn("- spdk-volume-stop/owner: unrun; custody is held or unknown", out)
        self.kill_held()
        markers = sorted((self.state / "custody").glob("supervisor-*.json"))
        self.assertEqual(len(markers), 1, "a supervisor lost to a signal leaves a marker with no group")
        marker = json.loads(markers[0].read_text())
        self.assertEqual((marker["pgid"], marker["profile"], marker["role"]), (None, "spdk-volume", "owner"))
        self.plan({})
        # Each sweep opens its own episode.
        self.env["KESTRIKE_EPISODE"] = "orphan-2"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, "the marker holds until an operator removes it: " + out)
        self.assertIn("an unknown group of spdk-volume/owner", out)
        self.assertEqual(sorted((self.state / "custody").glob("*.json")), markers)
        markers[0].unlink()
        self.env["KESTRIKE_EPISODE"] = "orphan-3"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)

    def test_a_sweep_exits_held_while_another_process_holds_the_host_reservation(self):
        """A FIS campaign, or another sweep, holds the custody directory's reservation for its life; a sweep that
        finds it held runs no role, so the two never both pass an empty custody check on one host."""
        import fcntl
        custody = self.state / "custody"
        custody.mkdir(exist_ok=True)
        holder = os.open(custody / "fis.lock", os.O_RDWR | os.O_CREAT)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume-stop/owner")
        self.plan({OWNER: {"outcome": "serve", "seconds": 1}})
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn("another sweep or FIS controller holds this host", out)
        self.assertFalse((self.state / "runs.txt").exists(), "the reserved host ran no case")
        fcntl.flock(holder, fcntl.LOCK_UN)
        code, out, _ = self.lane("sweep")
        self.assertNotEqual(code, 4, "a released reservation admits the sweep: " + out)

    def test_a_role_supervisor_inherits_the_sweep_s_host_reservation(self):
        """The sweep's role supervisors hold the reservation the sweep took, so a sweep killed alone, before a
        supervisor publishes its custody sentinel, leaves the host reserved by the supervisor it spawned."""
        import fcntl
        self.plan({OWNER: {"outcome": "serve", "mute": True, "say": "owner serving until", "seconds": 60}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner", KESTRIKE_EPISODE="reserved-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        sweep = self.start("sweep")
        for _ in range(600):
            if (self.state / "runs.txt").exists():
                break
            time.sleep(0.05)
        else:
            self.fail("the owner's case started")
        supervisors = [int(pid) for pid in os.listdir("/proc") if pid.isdigit()
                       and b"--episode\0reserved-1\0" in self.cmdline(pid)
                       and str(self.state).encode() in self.cmdline(pid)]
        self.assertEqual(len(supervisors), 1, "one run supervisor for the owner")
        held = open_files(supervisors[0])
        self.assertTrue(any(path.endswith("custody/fis.lock") for path in held), f"the supervisor's files: {held}")
        os.kill(sweep.pid, signal.SIGKILL)
        sweep.communicate(timeout=60)
        probe = os.open(self.state / "custody" / "fis.lock", os.O_RDWR)
        self.addCleanup(os.close, probe)
        with self.assertRaises(OSError, msg="the dead sweep's reservation is held on by its supervisor"):
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_a_sweep_and_supervisor_killed_mid_case_leave_the_case_group_s_marker(self):
        """The runner kills a cancelled job's sweep and supervisors together, while the case's own session survives;
        the marker written at the case's start keeps the next sweep off this host until the group is gone."""
        self.plan({OWNER: {"outcome": "serve", "mute": True, "say": "owner serving until", "seconds": 60}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner", KESTRIKE_EPISODE="cut-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        sweep = self.start("sweep")
        for _ in range(600):
            if (self.state / "runs.txt").exists():
                break
            time.sleep(0.05)
        else:
            self.fail("the owner's case started")
        time.sleep(0.5)
        supervisors = [int(pid) for pid in os.listdir("/proc") if pid.isdigit() and b"--episode\0cut-1\0" in self.cmdline(pid)
                       and str(self.state).encode() in self.cmdline(pid)]
        self.assertEqual(len(supervisors), 1, "one run supervisor for the owner")
        os.kill(sweep.pid, signal.SIGKILL)
        os.kill(supervisors[0], signal.SIGKILL)
        sweep.communicate(timeout=60)
        markers = sorted((self.state / "custody").glob("*.json"))
        self.assertEqual(len(markers), 1, "the case's start left its group's marker")
        marker = json.loads(markers[0].read_text())
        self.assertTrue(marker["custody"].startswith("running: process group"), marker)
        self.assertTrue(lane_module().members_hold_memory({int(pid): started for pid, started in marker["members"].items()}),
                        "the case outlives its supervisor")
        self.plan({})
        self.env["KESTRIKE_EPISODE"] = "cut-2"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn(f"process group {marker['pgid']} of host-pair/owner (episode cut-1)", out)
        self.kill_held()
        for _ in range(200):
            if not lane_module().members_hold_memory({int(pid): started for pid, started in marker["members"].items()}):
                break
            time.sleep(0.05)
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)

    def test_a_descendant_outliving_its_leader_keeps_the_case_group_s_marker(self):
        """With the sweep and supervisor gone, a leader that exits and leaves a child in the group still holds
        devices through that child; the marker names the leader alone, and the group's lifetime keeps it."""
        self.plan({OWNER: {"outcome": "leave", "mute": True, "say": "owner serving until", "delay": 2}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner", KESTRIKE_EPISODE="left-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        sweep = self.start("sweep")
        for _ in range(600):
            if (self.state / "runs.txt").exists():
                break
            time.sleep(0.05)
        else:
            self.fail("the owner's case started")
        time.sleep(0.3)
        supervisors = [int(pid) for pid in os.listdir("/proc") if pid.isdigit() and b"--episode\0left-1\0" in self.cmdline(pid)
                       and str(self.state).encode() in self.cmdline(pid)]
        self.assertEqual(len(supervisors), 1)
        os.kill(sweep.pid, signal.SIGKILL)
        os.kill(supervisors[0], signal.SIGKILL)
        sweep.communicate(timeout=60)
        marker = json.loads(next((self.state / "custody").glob("*.json")).read_text())
        lane = lane_module()
        for _ in range(200):
            if not lane.members_hold_memory({int(pid): started for pid, started in marker["members"].items()}):
                break
            time.sleep(0.05)
        else:
            self.fail("the leader exited after its delay, leaving its child")
        self.assertTrue(lane.group_members(marker["pgid"]), "the child stays in the group")
        self.plan({})
        self.env["KESTRIKE_EPISODE"] = "left-2"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, "the group lives on in its descendant: " + out)
        self.kill_held()
        for _ in range(200):
            if not lane.group_members(marker["pgid"]):
                break
            time.sleep(0.05)
        self.env["KESTRIKE_EPISODE"] = "left-3"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)

    def test_a_dead_supervisor_stops_the_profile_s_other_roles_at_once(self):
        """The sweep watches every started role; a supervisor lost to a signal leaves its case without a deadline."""
        self.plan({OWNER: {"outcome": "serve", "seconds": 30}, CLIENT: {"outcome": "orphan"}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="lost-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        begun = time.monotonic()
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertLess(time.monotonic() - begun, 15, "the owner was stopped as soon as the client's supervisor died")
        self.assertIn("host-pair/client: custody unknown", out)
        self.assertIn("host-pair/owner: not credited", out)
        self.assertIn("lane signal 15", out, "the owner's supervisor took its case through the close path")
        self.kill_held()

    def test_the_put_reader_starts_only_after_the_writer_published(self):
        writer = "net::host_pair_tests::the_client_puts_an_object_onto_the_volume"
        self.plan({OWNER: {"outcome": "serve", "seconds": 4},
                   writer: {"say": "sources at publication"}})
        roles = " ".join((
            "host-pair-put/owner",
            f"host-pair-put/client={self.role_env('client', KESTRIKE_MAPPINGS=f'{self.state}/client/mappings', KESTRIKE_PEER='10.0.1.5', KESTRIKE_CLIENT='0')}",
            f"host-pair-put/reader={self.role_env('reader', KESTRIKE_MAPPINGS=f'{self.state}/reader/mappings', KESTRIKE_PEER='10.0.1.5', KESTRIKE_CLIENT='1')}",
        ))
        self.env.update(KESTRIKE_HARDWARE_ROLES=roles, KESTRIKE_EPISODE="put-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        reader = "net::host_pair_tests::an_independent_client_reads_the_put_back"
        self.assertEqual(json.loads((self.state / f"{reader}.env.json").read_text())["KESTRIKE_CLIENT"], "1")
        self.assertEqual(json.loads((self.state / f"{writer}.env.json").read_text())["KESTRIKE_CLIENT"], "0")
        events = [json.loads(line) for line in (self.state / "observer" / "put-1.jsonl").read_text().splitlines()]
        published = [event["ordinal"] for event in events if event["kind"] == "ready" and event["role"] == "client"]
        read = [event["ordinal"] for event in events if event["kind"] == "start" and event["role"] == "reader"]
        self.assertEqual(len(published), 1, "the writer reports its publication")
        self.assertLess(published[0], read[0], "the reader starts after the PUT published")

    def test_the_sweep_exits_held_after_a_kill_and_the_kill_profile_is_the_manifests_last(self):
        """SIGKILL ends the owner's processes without their teardown, so the host awaits the deployment
        owner's containment: the sweep runs every role of the kill profile, the manifest's last, and exits
        held even though the killed role itself exits credited. A kill role that never killed, here for want
        of abrupt-death evidence, leaves the sweep's exit to its credit alone."""
        self.assertTrue("kill" in list(self.manifest["profiles"].values())[-1]["roles"]["owner-a"],
                        "the kill profile is the manifest's last")
        evidence = self.state / "evidence.json"
        evidence.write_text("{}")
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume-stop/owner host-pair-two-owners-sigkill/owner-a "
                                                   "host-pair-two-owners-sigkill/owner-b")
        self.manifest["profiles"]["host-pair-two-owners-sigkill"]["roles"]["owner-a"]["kill"] = 0
        self.plan({OWNER: {"outcome": "serve", "seconds": 4}})
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 1, out)
        self.assertIn("unrun: no abrupt-death evidence", out)
        self.assertNotIn("awaits the deployment owner's containment", out)
        self.env["KESTRIKE_ABRUPT_DEATH_EVIDENCE"] = str(evidence)
        # Each sweep opens its own episode.
        self.env["KESTRIKE_EPISODE"] = "killed-2"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn("- spdk-volume-stop/owner (episode", out)
        self.assertIn("host-pair-two-owners-sigkill/owner-a (episode", out)
        self.assertIn("host-pair-two-owners-sigkill/owner-b (episode", out)
        self.assertIn("the killed owner's host awaits the deployment owner's containment", out)
        runs = (self.state / "runs.txt").read_text()
        self.assertEqual((runs.count(OWNER), runs.count(CONTRACT), runs.count(STOPS)), (2, 2, 2), runs)
        # The kill leaves a marker with no group, so the next sweep (and a FIS campaign on this host) refuses the
        # host before any role until an operator removes it.
        marker = json.loads((self.state / "custody" / "killed-killed-2.json").read_text())
        self.assertEqual((marker["pgid"], marker["role"], marker.get("durable")), (None, "owner-a", None), marker)
        self.assertIn("awaits the deployment owner's containment", marker["custody"])
        self.env["KESTRIKE_EPISODE"] = "killed-3"
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 4, out)
        self.assertIn("remove", out)
        self.assertIn("killed-killed-2.json", out)
        self.assertEqual((self.state / "runs.txt").read_text(), runs, "no role ran on the held host")

    def test_an_episode_is_one_file_name_and_the_sweep_opens_a_fresh_observer_log(self):
        """An episode names one file in the observer directory, and a sweep refuses an episode whose log exists."""
        for episode in ("../escape", "/abs/olute", ".hidden"):
            process = self.start("run", "--profile", "spdk-volume-stop", "--role", "owner", "--episode", episode,
                                 "--observer", str(self.state / "observer"))
            _, err = process.communicate(timeout=60)
            self.assertEqual(process.returncode, 2, f"{episode}: {err}")
            self.assertIn("is not an episode name", err)
        self.env.update(KESTRIKE_HARDWARE_ROLES="spdk-volume-stop/owner", KESTRIKE_EPISODE="../escape",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("is not an episode name", out)
        self.observer_end("stale", "spdk-volume-stop", "owner")
        self.env.update(KESTRIKE_EPISODE="stale")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("already has an observer log", out)
        self.assertFalse((self.state / "builds.txt").exists(), "a refused episode builds nothing")

    def test_the_sweep_runs_a_provisioned_pair_at_once_in_one_episode_through_one_observer(self):
        self.plan({OWNER: {"outcome": "serve", "seconds": 2}, CLIENT: {"observe": PAIR_WITNESSES}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="sweep-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        process = self.start("sweep")
        out, err = process.communicate(timeout=120)
        self.assertEqual(process.returncode, 0, out + err)
        self.assertIn("- host-pair/owner (episode sweep-1): ", out)
        self.assertIn("\nhost-pair/owner: credited", out)
        self.assertIn("\nhost-pair/client: credited", out)
        events = [json.loads(line) for line in (self.state / "observer" / "sweep-1.jsonl").read_text().splitlines()]
        self.assertEqual([event["ordinal"] for event in events], list(range(1, len(events) + 1)))
        ready = next(event for event in events if event["kind"] == "ready")
        ack = next(event for event in events if event["kind"] == "ack")
        self.assertEqual(ack["acknowledges"], ready["ordinal"])

    def test_the_sweep_stops_the_roles_it_started_when_its_own_startup_fails(self):
        """A supervisor that outlives a failed sweep would keep its case outside every containment path."""
        profiles = self.manifest["profiles"]
        self.manifest["profiles"] = {"host-pair": profiles["host-pair"], **profiles}
        self.plan({OWNER: {"outcome": "close"}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner", KESTRIKE_EPISODE="short-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        # The sweep starts the owner, then its first report, the unprovisioned client, fails on the closed pipe.
        process = self.start("sweep")
        process.stdout.close()
        _, err = process.communicate(timeout=120)
        leftovers = [int(pid) for pid in os.listdir("/proc") if pid.isdigit()
                     and str(self.state).encode() in self.cmdline(pid)]
        for pid in leftovers:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        self.assertNotEqual(process.returncode, 0, err)
        self.assertEqual(leftovers, [], "no supervisor or case of the episode outlives the sweep")

    def test_a_sweep_that_fails_while_a_started_role_holds_custody_still_reports_held(self):
        """The roles' own exits decide custody: a sweep whose second spawn fails while its owner is left held
        exits 4 and names the held role, rather than 2 for its own failure."""
        lane = lane_module()
        spawned, popen = [], lane.subprocess.Popen

        def second_spawn_fails(*args, **kwargs):
            spawned.append(args)
            if len(spawned) == 2:
                raise OSError(11, "no process slots")
            return popen(*args, **kwargs)

        self.plan({OWNER: {"outcome": "hang"}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="held-sweep",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        lane.subprocess.Popen = second_spawn_fails
        handlers = {signum: signal.getsignal(signum) for signum in (signal.SIGTERM, signal.SIGINT)}
        environment, cwd = dict(os.environ), os.getcwd()
        os.environ.update(self.env)
        os.chdir(self.checkout)
        try:
            with contextlib.redirect_stdout(io.StringIO()) as out:
                code = lane.main(["sweep", "--manifest", str(self.write_manifest()), "--cargo", str(self.state / "cargo"),
                                  "--artifacts", str(self.state / "artifacts"), "--custody", str(self.state / "custody")])
        finally:
            lane.subprocess.Popen = popen
            os.chdir(cwd)
            os.environ.clear()
            os.environ.update(environment)
            for signum, handler in handlers.items():
                signal.signal(signum, handler)
            self.kill_held()
        self.assertEqual(len(spawned), 2, "the owner spawned, the client's spawn failed")
        self.assertEqual(code, 4, out.getvalue())
        # The SIGTERM may reach the owner's supervisor before its handler is installed: custody is then unknown.
        self.assertRegex(out.getvalue(),
                         r"custody stays with \['host-pair/owner \(custody (held|unknown; its supervisor died by signal 15)\)'\]")
        self.assertIn("no process slots", out.getvalue())

    def test_the_sweep_waits_for_every_started_role_when_a_report_fails_during_collection(self):
        """A role already collected is reaped once; the roles after it are still waited for."""
        profiles = self.manifest["profiles"]
        self.manifest["profiles"] = {"host-pair": profiles["host-pair"], **profiles}
        # The owner fails at once; the client serves on, and its containment takes the controller three seconds.
        controller = self.state / "controller-slow"
        controller.write_text(f'#!/bin/sh\nsleep 3\necho "contained {CLIENT}"\n')
        controller.chmod(0o755)
        self.plan({OWNER: {"outcome": "fail", "say": "owner failing", "delay": 2}, CLIENT: {"outcome": "serve", "seconds": 30}})
        self.env.update(KESTRIKE_HARDWARE_ROLES="host-pair/owner host-pair/client", KESTRIKE_EPISODE="short-2",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"),
                        KESTRIKE_HARDWARE_CONTROLLER=str(controller))
        process = self.start("sweep")
        process.stdout.close()
        _, err = process.communicate(timeout=120)
        leftovers = [int(pid) for pid in os.listdir("/proc") if pid.isdigit()
                     and str(self.state).encode() in self.cmdline(pid)]
        for pid in leftovers:
            with contextlib.suppress(ProcessLookupError):
                os.kill(pid, signal.SIGKILL)
        self.assertNotEqual(process.returncode, 0, err)
        self.assertNotIn("ValueError", err)
        self.assertEqual(leftovers, [], "the client's supervisor was waited for after the owner's report failed")

    @staticmethod
    def cmdline(pid):
        try:
            return Path(f"/proc/{pid}/cmdline").read_bytes()
        except OSError:
            return b""

    def role_env(self, name, **pairs):
        """A role's environment file under the fake state directory, with the mappings file it names in place."""
        path = self.state / f"{name}.env"
        path.write_text("".join(f"{key}={value}\n" for key, value in pairs.items()))
        if "KESTRIKE_MAPPINGS" in pairs:
            self.mappings_file(Path(pairs["KESTRIKE_MAPPINGS"]))
        return str(path)

    @staticmethod
    def mappings_file(path):
        """A mappings file a case could read, binding the PCI function the envelope fixture declares: the lane
        records its path, digest, format and bound functions in the receipt."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(f"format=3\nnvme.bdf={pci_function()}\n")

    def two_owner_roles(self, **overrides):
        """`KESTRIKE_HARDWARE_ROLES` for the two-owner profile: distinct state directories, pinned clients."""
        state = self.state
        files = {
            "owner-a": dict(KESTRIKE_MAPPINGS=f"{state}/owner-a/mappings", KESTRIKE_PEER="10.0.1.7,10.0.1.8",
                            KESTRIKE_SERVE_SECONDS="300"),
            "owner-b": dict(KESTRIKE_MAPPINGS=f"{state}/owner-b/mappings", KESTRIKE_PEER="10.0.1.7,10.0.1.8",
                            KESTRIKE_SERVE_SECONDS="600"),
            "client-a": dict(KESTRIKE_MAPPINGS=f"{state}/client-a/mappings", KESTRIKE_CLIENT="0",
                             KESTRIKE_STOPPED="0", KESTRIKE_PEERS="10.0.1.5,10.0.1.6"),
            "client-b": dict(KESTRIKE_MAPPINGS=f"{state}/client-b/mappings", KESTRIKE_CLIENT="1",
                             KESTRIKE_STOPPED="1", KESTRIKE_PEERS="10.0.1.6,10.0.1.5"),
        }
        for role, pairs in overrides.items():
            files[role].update(pairs)
        return " ".join(f"host-pair-two-owners/{role}={self.role_env(role, **pairs)}" for role, pairs in files.items())

    def test_a_chained_role_waits_one_readiness_window_per_predecessor(self):
        """owner-a -> owner-b -> clients: every role starts at once, so a client's wait spans both owners' startups."""
        profile = self.manifest["profiles"]["host-pair-two-owners"]
        for name, role in profile["roles"].items():
            role["cases"][0]["deadline"] = 3 if name.startswith("client") else 6
        self.plan({OWNER: {"outcome": "serve", "mute": True, "say": "owner serving until", "delay": 2, "seconds": 3},
                   TWO_OWNERS: {"observe": TWO_OWNER_WITNESSES}})
        self.env.update(KESTRIKE_HARDWARE_ROLES=self.two_owner_roles(), KESTRIKE_EPISODE="chain-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"), KESTRIKE_CLIENT="7")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        for role in ("owner-a", "owner-b", "client-a", "client-b"):
            self.assertIn(f"\nhost-pair-two-owners/{role}: credited", out)
        events = [json.loads(line) for line in (self.state / "observer" / "chain-1.jsonl").read_text().splitlines()]
        ready = {event["role"]: event["ordinal"] for event in events if event["kind"] == "ready"}
        acks = {event["role"]: event["acknowledges"] for event in events if event["kind"] == "ack"}
        self.assertEqual(acks, {"owner-b": ready["owner-a"], "client-a": ready["owner-b"], "client-b": ready["owner-b"]})
        client = "net::host_pair_tests::the_client_fetches_from_two_owners"
        for index, peers in (("0", "10.0.1.5,10.0.1.6"), ("1", "10.0.1.6,10.0.1.5")):
            seen = json.loads((self.state / f"{client}.client-{index}.env.json").read_text())
            self.assertEqual((seen["KESTRIKE_CLIENT"], seen["KESTRIKE_STOPPED"], seen["KESTRIKE_PEERS"]),
                             (index, index, peers), "the role's file beats the ambient KESTRIKE_CLIENT=7")
        receipts = sorted((self.state / "artifacts").rglob("receipt.json"))
        self.assertEqual(len(receipts), 4)
        for path in receipts:
            receipt = json.loads(path.read_text())
            self.assertEqual(receipt["hardware"]["environment_file"]["sha256"],
                             hashlib.sha256(Path(receipt["hardware"]["environment_file"]["path"]).read_bytes()).hexdigest())
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners", *map(str, receipts))
        self.assertEqual(code, 0, out)
        client_b = next(path for path in receipts if json.loads(path.read_text())["hardware"]["role"] == "client-b")
        forged = json.loads(client_b.read_text())
        forged["hardware"]["cases"][0]["inputs"]["KESTRIKE_CLIENT"] = "0"
        client_b.write_text(json.dumps(forged))
        code, out, _ = self.lane("judge", "--profile", "host-pair-two-owners", *map(str, receipts))
        self.assertEqual(code, 1, "a receipt whose recorded client index differs from the role's declaration earns no credit")
        self.assertIn("differ from the role's declared", out)

    def test_soak_smoke_receives_every_declared_reservation_and_serving_input(self):
        case = "soak_tests::the_soak_smoke_drains_on_the_bound_volume"
        inputs = {
            "KESTRIKE_N_REG": "3",
            "KESTRIKE_N_RESV": "2",
            "KESTRIKE_T_REPORT": "10",
            "KESTRIKE_T_PA": "20",
            "KESTRIKE_N_RETRY": "1",
            "KESTRIKE_SERVING_WINDOW_US": "1000",
            "KESTRIKE_REPORT_PERIOD_US": "100",
            "KESTRIKE_CLOCK_ERROR_US": "0",
        }
        self.env.update(inputs, KESTRIKE_ALLOW_RESET="1")
        self.plan({case: {"observe": ['"lifecycle": "drained"', "queue_full: true", "held_read: true", "healed: true"]}})
        code, out, err = self.lane("run", "--profile", "soak-smoke", "--role", "owner", "--episode", "reservation-inputs")
        self.assertEqual(code, 0, out + err)
        seen = json.loads((self.state / f"{case}.env.json").read_text())
        for name, value in inputs.items():
            self.assertEqual(seen[name], value)
        self.assertEqual(seen["KESTRIKE_MAPPINGS"], str(self.state / "mappings"))
        self.assertNotIn("KESTRIKE_ALLOW_RESET", seen)
        section, _ = self.receipt(err)
        self.assertEqual(set(section["cases"][0]["inputs"]), set(inputs) | {"KESTRIKE_MAPPINGS"})

    def test_a_case_sees_only_the_hardware_controls_its_manifest_declares_for_it(self):
        """`KESTRIKE_ALLOW_RESET` turns a fetch into a reset; a case receives the inputs its manifest names,
        whether the ambient environment or a role file supplied them, and the lane's episode."""
        self.env["KESTRIKE_ALLOW_RESET"] = "1"
        code, out, err = self.lane("run", "--profile", "spdk-volume-stop", "--role", "owner", "--episode", "iso-0")
        self.assertEqual(code, 0, out + err)
        seen = json.loads((self.state / f"{CONTRACT}.env.json").read_text())
        self.assertNotIn("KESTRIKE_ALLOW_RESET", seen, "an ambient flag the case does not declare stays out")
        self.assertEqual(seen["KESTRIKE_MAPPINGS"], str(self.state / "mappings"), "an ambient declared input serves")
        section, path = self.receipt(err)
        self.assertEqual(sorted(section["cases"][0]["inputs"]), ["KESTRIKE_IDLE_OBSERVATION_MS", "KESTRIKE_MAPPINGS"],
                         "the receipt records the inputs the case received")
        artifact = json.loads((Path(path).parent / "artifact.json").read_text())
        self.assertEqual([name for name in artifact["environment"] if name.startswith("KESTRIKE_")], [],
                         "the build record names no case input; the receipt's per-case inputs carry them")
        client = "net::ena_hardware_tests::the_client_fetches"
        self.plan({"net::ena_hardware_tests::the_owner_serves": {"outcome": "serve", "seconds": 3}})
        roles = " ".join((
            f"ena-pair/owner={self.role_env('owner', KESTRIKE_MAPPINGS=f'{self.state}/owner/mappings', KESTRIKE_PEER='10.0.1.9')}",
            f"ena-pair/client={self.role_env('client', KESTRIKE_MAPPINGS=f'{self.state}/client/mappings', KESTRIKE_PEER='10.0.1.5')}",
        ))
        self.env.update(KESTRIKE_HARDWARE_ROLES=roles, KESTRIKE_EPISODE="iso-1",
                        KESTRIKE_HARDWARE_OBSERVER=str(self.state / "observer"))
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 0, out)
        seen = json.loads((self.state / f"{client}.env.json").read_text())
        self.assertNotIn("KESTRIKE_ALLOW_RESET", seen, "the ambient reset flag stays out of a role that brought its file")
        self.assertEqual(seen["KESTRIKE_EPISODE"], "iso-1", "the lane's own control still reaches the case")
        self.assertEqual(seen["KESTRIKE_PEER"], "10.0.1.5")

    def test_a_role_runs_only_with_the_inputs_its_profile_declares_for_it(self):
        """Pinned values come from the role's file and are checked at run; the ambient environment cannot stand in."""
        code, out, err = self.lane("run", "--profile", "host-pair-put", "--role", "reader", "--episode", "pin-1",
                                   "--observer", str(self.state / "observer"))
        self.assertEqual(code, 1, out + err)
        self.assertIn("lacks inputs ['KESTRIKE_CLIENT']", self.receipt(err)[0]["first_failure"])
        self.env["KESTRIKE_CLIENT"] = "0"
        code, out, err = self.lane("run", "--profile", "host-pair-put", "--role", "reader", "--episode", "pin-2",
                                   "--observer", str(self.state / "observer"))
        self.assertEqual(code, 1, out + err)
        self.assertIn("inputs {'KESTRIKE_CLIENT': '0'} differ from the role's declared {'KESTRIKE_CLIENT': '1'}",
                      self.receipt(err)[0]["first_failure"])
        self.assertFalse((self.state / "runs.txt").exists(), "the case never started")

    def test_the_sweep_refuses_a_malformed_role_environment_before_any_role_starts(self):
        files = {
            "no assignment": "KESTRIKE_CLIENT\n",
            "foreign name": "FOO=1\n",
            "lower case": "kestrike_client=1\n",
        }
        for name, text in files.items():
            with self.subTest(name):
                path = self.state / "bad.env"
                path.write_text(text)
                self.env.update(KESTRIKE_HARDWARE_ROLES=f"host-pair/owner={path}")
                code, out, _ = self.lane("sweep")
                self.assertEqual(code, 2, out)
                self.assertIn("is not an KESTRIKE_ assignment", out)
        for name, path in (("relative", "owner.env"), ("missing", str(self.state / "absent.env")),
                           ("a directory", str(self.state))):
            with self.subTest(name):
                self.env.update(KESTRIKE_HARDWARE_ROLES=f"host-pair/owner={path}")
                code, out, _ = self.lane("sweep")
                self.assertEqual(code, 2, out)
                self.assertIn("role environment", out)
        self.assertIn("is not a regular file", out, "a directory is refused before any read, as a FIFO or device would be")
        self.env.update(KESTRIKE_HARDWARE_ROLES=f"host-pair/owner={self.role_env('short', KESTRIKE_PEER='10.0.1.9')}")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("lacks ['KESTRIKE_MAPPINGS']", out, "the ambient mappings file cannot stand in for the role's")
        self.assertFalse((self.state / "builds.txt").exists(), "a refused environment builds nothing")
        self.env.update(KESTRIKE_HARDWARE_ROLES=f"host-pair/onwer={self.role_env('typo', KESTRIKE_CLIENT='0')}")
        code, out, _ = self.lane("sweep")
        self.assertEqual(code, 2, out)
        self.assertIn("undeclared roles ['host-pair/onwer']", out)


SMOKE_TESTS = ("MappingsFormat", "HostFacts", "ReadinessWait", "StopProof", "ProcessFiles", "CISelection")
HARDWARE_PATHS = {
    ".github/workflows/agent-checks.yml", ".github/workflows/hardware.yml",
    "scripts/hardware-lane.py", "scripts/hardware-profiles.json", "scripts/test-hardware-lane.py",
    "scripts/recovery-packages.py", "scripts/recovery-package-lines.json", "scripts/hit-gate.py",
    "scripts/reproduce-test.py", "scripts/select-tests.py", "scripts/qualified-envelope.py",
    "scripts/verify-receipts.py", "scripts/rust-lane.sh", "scripts/test-inventory.json",
    "scripts/test-registry.json", "verification/obligations.json",
}
HARDWARE_TREES = ("crates/kestrike/", "crates/spdk-sys/")


def ci_selection(environ=None, root=ROOT):
    """Only a verified push or pull-request diff outside the hardware paths admits the smoke suite."""
    environ = os.environ if environ is None else environ
    event_name = environ.get("GITHUB_EVENT_NAME")
    if event_name not in ("pull_request", "push"):
        return None, "scheduled, manual or unknown event"
    try:
        event = json.loads(Path(environ["GITHUB_EVENT_PATH"]).read_text())
        if event_name == "pull_request":
            base, head = (event["pull_request"][side]["sha"] for side in ("base", "head"))
        else:
            base, head = event["before"], event["after"]
        for revision in (base, head):
            if not isinstance(revision, str) or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", revision):
                raise ValueError("revision is not a full commit ID")
            subprocess.run(["git", "cat-file", "-e", revision + "^{commit}"], cwd=root,
                           check=True, capture_output=True, timeout=10)
        changed = subprocess.run(["git", "diff", "--no-ext-diff", "--no-textconv", "--name-only",
                                  "--no-renames", "-z", base, head, "--"], cwd=root,
                                 check=True, capture_output=True, timeout=10).stdout
        if changed and not changed.endswith(b"\0"):
            raise ValueError("incomplete diff paths")
        paths = [os.fsdecode(path) for path in changed.split(b"\0") if path]
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError):
        return None, "event or commit range could not be verified"
    if any(path in HARDWARE_PATHS or path.startswith(HARDWARE_TREES) for path in paths):
        return None, "hardware paths changed"
    return SMOKE_TESTS, "no hardware paths changed"


class CISelection(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory(prefix="hardware-selection-")
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name) / "checkout"
        self.root.mkdir()
        self.event = Path(temp.name) / "event.json"
        self.git("init", "-q")
        self.git("commit", "--allow-empty", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD").strip()

    def git(self, *args):
        return subprocess.run(["git", "-c", "user.name=lane", "-c", "user.email=lane@example",
                               "-c", "commit.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                              cwd=self.root, check=True, capture_output=True, text=True).stdout

    def commit(self, path):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text("changed\n")
        self.git("add", "--", path)
        self.git("commit", "-qm", "change")
        return self.git("rev-parse", "HEAD").strip()

    def selection(self, event_name, base, head):
        event = ({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}}
                 if event_name == "pull_request" else {"before": base, "after": head})
        self.event.write_text(json.dumps(event))
        return ci_selection({"GITHUB_EVENT_NAME": event_name, "GITHUB_EVENT_PATH": str(self.event)}, self.root)[0]

    def test_unrelated_push_and_pull_request_changes_select_only_smoke(self):
        head = self.commit("docs/guide.md")
        for event in ("push", "pull_request"):
            with self.subTest(event=event):
                self.assertEqual(self.selection(event, self.base, head), SMOKE_TESTS)
        self.assertEqual(SMOKE_TESTS, ("MappingsFormat", "HostFacts", "ReadinessWait", "StopProof", "ProcessFiles", "CISelection"))

    def test_each_hardware_dependency_selects_the_full_suite(self):
        for path in sorted(HARDWARE_PATHS) + [tree + "src/lib.rs" for tree in HARDWARE_TREES]:
            with self.subTest(path=path):
                head = self.commit(path)
                self.assertIsNone(self.selection("pull_request", self.base, head))
                self.assertIsNone(self.selection("push", self.base, head))
                self.base = head

    def test_schedule_manual_and_unknown_events_select_the_full_suite(self):
        for event in ("schedule", "workflow_dispatch", "workflow_run", "merge_group", "", None):
            with self.subTest(event=event):
                self.assertIsNone(ci_selection({"GITHUB_EVENT_NAME": event}, self.root)[0])

    def test_missing_or_malformed_events_select_the_full_suite(self):
        self.assertIsNone(ci_selection({"GITHUB_EVENT_NAME": "push"}, self.root)[0])
        env = {"GITHUB_EVENT_NAME": "pull_request", "GITHUB_EVENT_PATH": str(self.event)}
        self.assertIsNone(ci_selection(env, self.root)[0])
        for text in ("{", "null", "[]", "{}", '{"pull_request": []}', '{"pull_request": {"base": null}}'):
            with self.subTest(text=text):
                self.event.write_text(text)
                self.assertIsNone(ci_selection(env, self.root)[0])

    def test_bad_missing_and_non_commit_revisions_select_the_full_suite(self):
        head = self.commit("notes.txt")
        blob = self.git("rev-parse", "HEAD:notes.txt").strip()
        for revision in (None, [], "HEAD", "--output=escaped", "$(touch escaped)", "0" * 40, "1" * 40, blob):
            for base, tip in ((revision, head), (self.base, revision)):
                with self.subTest(base=base, head=tip):
                    self.assertIsNone(self.selection("push", base, tip))
        self.assertFalse((self.root / "escaped").exists())

    def test_git_errors_and_timeouts_select_the_full_suite(self):
        for error in (OSError("missing git"), subprocess.CalledProcessError(1, "git"),
                      subprocess.TimeoutExpired("git", 10)):
            with self.subTest(error=type(error).__name__), mock.patch.object(subprocess, "run", side_effect=error):
                self.assertIsNone(self.selection("push", self.base, self.base))
        ok = subprocess.CompletedProcess([], 0, stdout=b"")
        with mock.patch.object(subprocess, "run", side_effect=[ok, ok, subprocess.CalledProcessError(1, "git")]):
            self.assertIsNone(self.selection("push", self.base, self.base))
        with mock.patch.object(subprocess, "run", side_effect=[ok, ok, subprocess.CompletedProcess([], 0, b"truncated")]):
            self.assertIsNone(self.selection("push", self.base, self.base))

    def test_hostile_filenames_remain_literal_paths(self):
        for path in ("--output=escaped", "notes/$(touch escaped)", "notes/\nscripts/hardware-lane.py",
                     os.fsdecode(b"notes/\xff")):
            head = self.commit(path)
        self.assertEqual(self.selection("push", self.base, head), SMOKE_TESTS)
        self.assertFalse((self.root / "escaped").exists())
        head = self.commit("scripts/hardware-lane.py")
        self.assertIsNone(self.selection("push", self.base, head))

    def test_renaming_a_hardware_file_away_still_selects_the_full_suite(self):
        base = self.commit("scripts/hardware-lane.py")
        self.git("mv", "scripts/hardware-lane.py", "ordinary.txt")
        self.git("commit", "-qm", "rename")
        self.assertIsNone(self.selection("push", base, self.git("rev-parse", "HEAD").strip()))

    def test_manual_arguments_and_full_discovery_remain_the_default(self):
        with mock.patch.object(unittest, "main") as run, mock.patch.dict(os.environ, GITHUB_EVENT_NAME="push"):
            main(["test-hardware-lane.py", "HostFacts", "-v"])
            run.assert_called_once_with(argv=["test-hardware-lane.py", "HostFacts", "-v"], defaultTest=None)
        with mock.patch.object(unittest, "main") as run, mock.patch.dict(os.environ, GITHUB_EVENT_NAME="schedule"), \
                contextlib.redirect_stdout(io.StringIO()):
            main(["test-hardware-lane.py", "--ci"])
            run.assert_called_once_with(argv=["test-hardware-lane.py"], defaultTest=None)

    def test_ci_smoke_is_a_default_without_overriding_explicit_test_names(self):
        with mock.patch.object(sys.modules[__name__], "ci_selection", return_value=(SMOKE_TESTS, "verified diff")), \
                mock.patch.object(unittest, "main") as run, contextlib.redirect_stdout(io.StringIO()):
            main(["test-hardware-lane.py", "--ci"])
            run.assert_called_with(argv=["test-hardware-lane.py"], defaultTest=SMOKE_TESTS)
            main(["test-hardware-lane.py", "--ci", "HostFacts", "-v"])
            run.assert_called_with(argv=["test-hardware-lane.py", "HostFacts", "-v"], defaultTest=SMOKE_TESTS)


def main(argv=None):
    argv = list(sys.argv if argv is None else argv)
    tests = None
    if "--ci" in argv[1:]:
        argv.remove("--ci")
        tests, reason = ci_selection()
        print(f"hardware self-tests: {'full' if tests is None else 'smoke'} ({reason})", flush=True)
    unittest.main(argv=argv, defaultTest=tests)


if __name__ == "__main__":
    main()
