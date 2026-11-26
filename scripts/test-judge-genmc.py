#!/usr/bin/env python3
"""Check that judge-genmc.py admits only the declared toolchain and credits only complete, matching case results.

The fixtures are synthetic: a toolchain directory with an identity in the
form `verification/genmc/provision.sh` writes, and case outputs in the form
GenMC v0.19.0 prints, including the exit 42 it uses for a safety violation.
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
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/judge-genmc.py"
try:
    EXPECTED = json.loads((ROOT / "verification/genmc/expected.json").read_text())
except (OSError, ValueError) as error:
    raise SystemExit(f"test-judge-genmc: unreadable declaration: {error}") from error
PACKAGE = ROOT / EXPECTED["package"]


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def tree(root):
    digest = hashlib.sha256()
    for path in sorted(p for p in Path(root).rglob("*") if p.is_file() and "target" not in p.relative_to(root).parts):
        digest.update(str(path.relative_to(root)).encode() + b"\0" + sha256(path).encode() + b"\n")
    return digest.hexdigest()


RUSTC_VV = (
    "rustc {release} ({short} 2026-07-26)\nbinary: rustc\ncommit-hash: {commit}\ncommit-date: 2026-07-26\n"
    "host: x86_64-unknown-linux-gnu\nrelease: {release}\nLLVM version: {llvm}\n"
)


def write_rustc(toolchain, **identity):
    """Place a rustc stub under `toolchain/bin` that reports the declared identity and return its path."""
    fields = dict(EXPECTED["rustc"], **identity)
    rustc = Path(toolchain) / "bin/rustc"
    rustc.parent.mkdir(parents=True, exist_ok=True)
    rustc.write_text("#!/usr/bin/env bash\ncat <<'VV'\n" + RUSTC_VV.format(short=fields["commit"][:9], **fields) + "VV\n")
    rustc.chmod(0o755)
    return rustc


def falsifier_line(case="wrap_falsifier", check=0):
    """The line of the `check!` invocation that carries the case's `check`th declared message."""
    declared = EXPECTED["cases"][case]
    source = (PACKAGE / declared["file"]).read_text().splitlines()
    message = next(number for number, text in enumerate(source, 1) if f'c"{declared["checks"][check]}"' in text)
    return next(number for number in range(message, 0, -1) if "check!(" in source[number - 1])


def profile(name):
    return sorted(set(EXPECTED["profiles"]["pr"]) | set(EXPECTED["profiles"][name]))


def load_judge():
    spec = importlib.util.spec_from_file_location("judge_genmc", SCRIPT)
    if spec is None or spec.loader is None:
        raise SystemExit(f"test-judge-genmc: {SCRIPT} cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


JUDGE = load_judge()
KERNEL = str(Path(EXPECTED["package"]) / "src/grace_kernel.rs")
REGISTER, RELEASE = "crates/kestrike/src/storage/register.rs", "crates/kestrike/src/storage/release.rs"
SEQUENCE, BUCKET = "crates/kestrike/src/index/sequence.rs", "crates/kestrike/src/index/bucket.rs"
SCAN = "crates/kestrike/src/index/scan.rs"
TERMINAL_KERNEL = str(Path(EXPECTED["package"]) / "src/terminal_kernel.rs")
JOIN_KERNEL = str(Path(EXPECTED["package"]) / "src/join_kernel.rs")
JOIN = "crates/kestrike/src/storage/join.rs"
ATTEMPT = "crates/kestrike/src/storage/attempt.rs"
ROW = "crates/kestrike/src/storage/row.rs"
WRITABLE = "crates/kestrike/src/storage/writable.rs"
REMOVE, WORD = "crates/kestrike/src/storage/remove.rs", "crates/kestrike/src/storage/word.rs"
ALLOCATION, SLOT = "crates/kestrike/src/storage/allocation.rs", "crates/kestrike/src/storage/slot.rs"
CUTOFF = str(Path(EXPECTED["package"]) / "src/cutoff_kernel.rs")

# One or more mutants per binding entry: the class of drift, the file, and
# replacements of text that occurs once in it. A mutant of a scoped entry
# keeps the original operation's text in a trailing item of the file, so a
# guard that only looked for the text would accept it; the one file-scoped
# entry keeps its other occurrence, the loom forwarder invocation.
MUTANTS = {
    "claim-load": [("moved", KERNEL, [(
        "    if SLOT.claimed.load(S::CLAIM_LOAD) <= record {\n        SLOT.claimed.fetch_max(record + 1, S::CLAIM_RAISE);\n    }\n",
        "    SLOT.claimed.fetch_max(record + 1, S::CLAIM_RAISE);\n    let _ = SLOT.claimed.load(S::CLAIM_LOAD) <= record;\n")]),
        ("weakened", REGISTER, [("if bound.load(Ordering::SeqCst) <= index {", "if bound.load(Ordering::Acquire) <= index {")])],
    "claim-raise": [
        ("weakened", REGISTER, [("bound.fetch_max(index + 1, Ordering::SeqCst);", "bound.fetch_max(index + 1, Ordering::AcqRel);")]),
        ("weakened", KERNEL, [("    const CLAIM_RAISE: Ordering = Ordering::SeqCst;\n    const BOUND_LOAD",
                               "    const CLAIM_RAISE: Ordering = Ordering::AcqRel;\n    const BOUND_LOAD")]),
    ],
    "claim-before-pin": [("moved", KERNEL, [(
        "    claim(record);\n    check!(\n        pin::<_, S>(&SLOT.era, &SLOT.records[record]).is_ok(),\n        c\"pin refused\"\n    );\n",
        "    check!(\n        pin::<_, S>(&SLOT.era, &SLOT.records[record]).is_ok(),\n        c\"pin refused\"\n    );\n    claim(record);\n")])],
    "pass-bound-load": [("moved", KERNEL, [(
        "    let mut cursor = PassCursor::begin::<_, S>(&SLOT.era);\n    let bound = SLOT.claimed.load(S::BOUND_LOAD);\n",
        "    let bound = SLOT.claimed.load(S::BOUND_LOAD);\n    let mut cursor = PassCursor::begin::<_, S>(&SLOT.era);\n")]),
        ("weakened", "crates/kestrike/src/storage/release.rs", [(
            "eras.claimed_bound.load(Ordering::SeqCst);", "eras.claimed_bound.load(Ordering::Acquire);")])],
    "sequence-first-load": [("weakened", SEQUENCE, [("let value = sequence.load(Ordering::SeqCst);", "let value = sequence.load(Ordering::Acquire);")])],
    "sequence-second-load": [("weakened", SEQUENCE, [("sequence.load(Ordering::SeqCst) == started", "sequence.load(Ordering::Acquire) == started")])],
    "sequence-odd-store": [
        ("missing", SEQUENCE, [(
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        W::fence_release();\n", "        W::fence_release();\n")]),
        ("weakened", SEQUENCE, [("sequence.store(stable + 1, Ordering::SeqCst);", "sequence.store(stable + 1, Ordering::Release);")]),
    ],
    "sequence-odd-fence": [
        ("moved", SEQUENCE, [(
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        W::fence_release();\n",
            "        W::fence_release();\n        sequence.store(stable + 1, Ordering::SeqCst);\n")]),
        ("missing", SEQUENCE, [(
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        W::fence_release();\n",
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        /* outer /* inner */ W::fence_release(); */\n")]),
        ("missing", SEQUENCE, [(
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        W::fence_release();\n",
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        let _ = \"W::fence_release();\";\n")]),
        ("missing", SEQUENCE, [(
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        W::fence_release();\n",
            "        sequence.store(stable + 1, Ordering::SeqCst);\n        let _ = r#\"\" W::fence_release();\"#;\n")]),
    ],
    "sequence-fence-release": [("weakened", SEQUENCE, [("$fence(Ordering::Release);", "$fence(Ordering::Relaxed);")])],
    "sequence-forward-load": [("masked", SEQUENCE, [("Self::load(self, order)", "Self::load(self, Ordering::Relaxed)")])],
    "sequence-forward-store": [("masked", SEQUENCE, [("Self::store(self, value, order);", "Self::store(self, value, Ordering::Relaxed);")])],
    "sequence-fence-function": [("masked", SEQUENCE, [(
        "forward_seq_word!(std::sync::atomic::AtomicU64, std::sync::atomic::fence);",
        "forward_seq_word!(std::sync::atomic::AtomicU64, std::sync::atomic::compiler_fence);")])],
    "sequence-commit": [("weakened", SEQUENCE, [("self.sequence.store(committed, Ordering::SeqCst);", "self.sequence.store(committed, Ordering::Release);")])],
    "sequence-terminal-store": [("duplicated", SEQUENCE, [(
        "    sequence.store(TERMINAL, Ordering::SeqCst);\n    W::fence_release();\n",
        "    sequence.store(TERMINAL, Ordering::SeqCst);\n    W::fence_release();\n    sequence.store(TERMINAL, Ordering::SeqCst);\n")]),
        ("weakened", SEQUENCE, [("sequence.store(TERMINAL, Ordering::SeqCst);", "sequence.store(TERMINAL, Ordering::Release);")])],
    "sequence-terminal-fence": [("missing", SEQUENCE, [(
        "    sequence.store(TERMINAL, Ordering::SeqCst);\n    W::fence_release();\n", "    sequence.store(TERMINAL, Ordering::SeqCst);\n")])],
    "bucket-control-load": [("moved", TERMINAL_KERNEL, [(
        "    let copy = FIELD.load(Ordering::SeqCst);\n    if copy == NEW {\n        OBSERVED.store(true, Ordering::SeqCst);\n    }\n    if still(&SEQUENCE, started) {\n",
        "    if still(&SEQUENCE, started) {\n        let copy = FIELD.load(Ordering::SeqCst);\n")]), ("weakened", SCAN, [("self.control.load(Ordering::SeqCst)", "self.control.load(Ordering::Acquire)")])],
    "bucket-next-load": [("weakened", SCAN, [("self.next.load(Ordering::SeqCst)", "self.next.load(Ordering::Relaxed)")])],
    "bucket-identity-load": [("weakened", SCAN, [("self.pairs[pair].word.load(Ordering::SeqCst)", "self.pairs[pair].word.load(Ordering::Acquire)")])],
    "bucket-bare-pair-store": [("weakened", BUCKET, [(
        "            .store(Identity::new(tag, id).pack(), Ordering::Relaxed);\n        self.control\n            .store(control_with(control, pair, tag), Ordering::Relaxed);\n    }\n\n    /// Stores the overflow link",
        "            .store(Identity::new(tag, id).pack(), Ordering::Release);\n        self.control\n            .store(control_with(control, pair, tag), Ordering::Relaxed);\n    }\n\n    /// Stores the overflow link")])],
    "bucket-bare-control-store": [("masked", BUCKET, [(
        "            .store(control_with(control, pair, tag), Ordering::Relaxed);\n    }\n\n    /// Stores the overflow link",
        "            .store(control_without(control, pair), Ordering::Relaxed);\n    }\n\n    /// Stores the overflow link")])],
    "retire-stamp": [("weakened", KERNEL, [("self.fingerprint.store(era, Ordering::Release);", "self.fingerprint.store(era, Ordering::Relaxed);")])],
    "retire-stamp-before-park": [("moved", KERNEL, [(
        "    SLOT.record.stamp(stamp.retire_era);\n    check!(\n        park_word(&SLOT.record.ident, 1, ANCHORED),\n        c\"the retirement park failed\"\n    );\n",
        "    check!(\n        park_word(&SLOT.record.ident, 1, ANCHORED),\n        c\"the retirement park failed\"\n    );\n    SLOT.record.stamp(stamp.retire_era);\n")])],
    "anchored-park-load": [("duplicated", KERNEL, [(
        "    let mut current = slot_word.load(Ordering::Relaxed);\n    while let Some(next) = word::parked",
        "    let mut current = slot_word.load(Ordering::Relaxed);\n    current = slot_word.load(Ordering::Relaxed);\n    while let Some(next) = word::parked")])],
    "anchored-park": [("weakened", KERNEL, [(
        "slot_word.compare_exchange(current, next, Ordering::AcqRel, Ordering::Relaxed)",
        "slot_word.compare_exchange(current, next, Ordering::Release, Ordering::Relaxed)")])],
    "anchored-retire-update": [
        ("weakened", ALLOCATION, [("ident.try_update(Ordering::AcqRel, Ordering::Relaxed, |current| {",
                                   "ident.try_update(Ordering::Release, Ordering::Relaxed, |current| {")]),
        ("masked", ALLOCATION, [("                Some((current | set) ^ departure)\n", "                Some(current | set)\n")]),
    ],
    "bucket-pair-publish": [("lost",  "crates/kestrike/src/storage/publish.rs", [(
        "        None => hold.buckets[place.bucket].publish_pair(place.pair, place.control, route.tag(), id),\n",
        "        None => {}\n")])],
    "bucket-link-publish": [("missing", "crates/kestrike/src/storage/publish.rs", [(
        "        hold.buckets[popped.tail].link(popped.link);\n", "")])],
    "install-stores-inside-bracket": [("moved", "crates/kestrike/src/storage/publication.rs", [(
        "            store(&tables.hold, &route, id, &placement);\n            custody.advance(phase::STORED);\n"
        "            cut(Cut::MidStores);\n            let sequence = commit(control, busy, &placement);\n",
        "            custody.advance(phase::STORED);\n            cut(Cut::MidStores);\n"
        "            let sequence = commit(control, busy, &placement);\n            store(&tables.hold, &route, id, &placement);\n")])],
    "removal-clear-inside-bracket": [
        ("unanchored", REMOVE, [
            ("        record.clear_pair(found.place.pair, found.place.control);\n", ""),
            ("    let sequence = busy.map_or(TERMINAL, Busy::commit);\n    probe::event(Event::Committed { sequence });\n    Ok(Cleared {",
             "    let sequence = busy.map_or(TERMINAL, Busy::commit);\n    probe::event(Event::Committed { sequence });\n"
             "    if let Some(found) = &found {\n        hold.buckets[found.place.bucket].clear_pair(found.place.pair, found.place.control);\n"
              "        let record = &hold.buckets[found.place.bucket];\n        record.clear_pair(found.place.pair, found.place.control);\n    }\n    Ok(Cleared {")]),
        ("unanchored", REMOVE, [
            ("    let sequence = busy.map_or(TERMINAL, Busy::commit);\n    probe::event(Event::Committed { sequence });\n    Ok(Cleared {",
             "    Ok(Cleared {"),
            ("    if let Some(found) = found {\n        let record = &hold.buckets[found.place.bucket];\n",
             "    let sequence = busy.map_or(TERMINAL, Busy::commit);\n    probe::event(Event::Committed { sequence });\n"
             "    if let Some(found) = found {\n        let record = &hold.buckets[found.place.bucket];\n")]),
    ],
    "removal-carry-link-inside-bracket": [("moved", REMOVE, [
        ("            hold.buckets[prev].link(OverflowLink::from_raw(carried));\n            record.link(OverflowLink::NONE);\n",
         "            record.link(OverflowLink::NONE);\n"),
        ("    let busy = sequence.map(|stable| Busy::begin(&control.sequence, stable));\n",
         "    if let Some((prev, _, carried)) = recycle {\n        hold.buckets[prev].link(OverflowLink::from_raw(carried));\n    }\n"
         "    let busy = sequence.map(|stable| Busy::begin(&control.sequence, stable));\n")])],
    "removal-forget-link-inside-bracket": [("moved", REMOVE, [
        ("            record.link(OverflowLink::NONE);\n            hold.stack[top] = overflow;\n",
         "            hold.stack[top] = overflow;\n"),
        ("        let record = &hold.buckets[found.place.bucket];\n        record.clear_pair(found.place.pair, found.place.control);\n"
         "        if let Some((prev, overflow, carried)) = recycle {\n",
         "        let record = &hold.buckets[found.place.bucket];\n        record.link(OverflowLink::NONE);\n"
         "        record.clear_pair(found.place.pair, found.place.control);\n        if let Some((prev, overflow, carried)) = recycle {\n")])],
    "claim-link-inside-bracket": [("moved", "crates/kestrike/src/storage/place_claim.rs", [(
        "        tables.hold.buckets[popped.tail].link(popped.link);\n        busy.commit();\n",
        "        busy.commit();\n        tables.hold.buckets[popped.tail].link(popped.link);\n")])],
    "entry-cutoff-load": [
        ("moved", REGISTER, [(
            "        let record = self.record();\n        grace::pin::<_, Sequential>(",
            "        let record = self.record();\n        let _ = self.storage.closed().load(Ordering::SeqCst);\n"
            "        grace::pin::<_, Sequential>("), (
            "        probe::note(Primitive::Load);\n        if self.storage.closed().load(Ordering::SeqCst) {\n            grace::unpin(&record.pin);",
            "        probe::note(Primitive::Load);\n        if false {\n            grace::unpin(&record.pin);")]),
        ("moved", CUTOFF, [(
        "    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c\"pin refused\");\n    if CLOSED.load(Ordering::SeqCst) {\n",
        "    let closed = CLOSED.load(Ordering::SeqCst);\n    check!(pin::<_, Sequential>(&ERA, &PIN).is_ok(), c\"pin refused\");\n    if closed {\n")]),
        ("weakened", REGISTER, [("if self.storage.closed().load(Ordering::SeqCst) {", "if self.storage.closed().load(Ordering::Acquire) {")]),
    ],
    "close-store": [("weakened", CUTOFF, [("CLOSED.store(true, Ordering::SeqCst);", "CLOSED.store(true, Ordering::Release);")])],
    "scan-cutoff-load": [("weakened", "crates/kestrike/src/storage/reserve.rs", [(
        "self.is_live() && self.closed().load(std::sync::atomic::Ordering::SeqCst)",
        "self.is_live() && self.closed().load(std::sync::atomic::Ordering::Acquire)")])],
    "terminal-removal-fence": [
        ("missing", TERMINAL_KERNEL, [("    #[cfg(fence = \"own\")]\n    std::sync::atomic::fence(Ordering::Release);\n", "")]),
        ("weakened", "crates/kestrike/src/storage/remove.rs", [(
            "        fence(Ordering::Release);\n    }\n    if joint.is_some() {",
            "        fence(Ordering::Relaxed);\n    }\n    if joint.is_some() {")]),
    ],
    "terminal-bare-store": [
        ("weakened", TERMINAL_KERNEL, [("FIELD.store(NEW, Ordering::Relaxed);", "FIELD.store(NEW, Ordering::Release);")]),
        ("weakened", BUCKET, [(
            ".store(control_without(control, pair), Ordering::Relaxed);\n    }\n\n    /// Writes raw words",
            ".store(control_without(control, pair), Ordering::Release);\n    }\n\n    /// Writes raw words")]),
    ],
    "join-record-failure": [
        ("masked", WRITABLE, [("self.record.row.record_failure(failure);", "self.record.row.record_failure(FillFailure::Closed);")]),
        ("moved", JOIN_KERNEL, [(
            "    ROW.record_failure(FAILURE);\n    #[cfg(not(seam = \"relaxeddepart\"))]\n    let departed = fill::depart(&STATE, ORIGINAL);\n",
            "    #[cfg(not(seam = \"relaxeddepart\"))]\n    let departed = fill::depart(&STATE, ORIGINAL);\n    ROW.record_failure(FAILURE);\n")]),
    ],
    "join-refusal-failure": [
        ("masked", "crates/kestrike/src/storage/publication.rs", [("record.row.record_failure(failure);", "record.row.record_failure(FillFailure::Closed);")]),
    ],
    "join-follower-observe": [
        ("masked", JOIN, [("fill::observe(self.state, self.serial.get() + 1)", "fill::observe(self.state, self.serial.get() + 2)")]),
        ("missing", JOIN_KERNEL, [("    let record = fill::observe(&STATE, 2);\n", "    let record = fill::decode(STATE.load(Ordering::Acquire), 2);\n")]),
    ],
    "join-follower-terminal": [
        ("duplicated", JOIN_KERNEL, [("                let terminal = ROW.terminal();", "                let _ = ROW.terminal();\n                let terminal = ROW.terminal();")]),
    ],
    "join-detach": [
        ("missing", JOIN, [("let previous = self.row.detach();", "let previous = 1;")]),
        ("moved", JOIN_KERNEL, [("    #[cfg(not(seam = \"relaxedobserve\"))]\n    let record = fill::observe(&STATE, 2);\n",
                                 "    #[cfg(not(seam = \"earlydetach\"))]\n    ROW.detach();\n    #[cfg(not(seam = \"relaxedobserve\"))]\n    let record = fill::observe(&STATE, 2);\n"),
                                ("    }\n    #[cfg(not(seam = \"earlydetach\"))]\n    ROW.detach();\n}\n", "    }\n}\n")]),
    ],
    "join-service-observe": [
        ("duplicated", JOIN_KERNEL, [("    let departed = matches!(\n        fill::observe(&STATE, NEXT),", "    let _ = fill::observe(&STATE, NEXT);\n    let departed = matches!(\n        fill::observe(&STATE, NEXT),")]),
    ],
    "join-service-observers": [
        ("missing", JOIN_KERNEL, [("let free = departed && ROW.observers() == 0;", "let free = departed;")]),
    ],
    "join-detach-release": [
        ("weakened", ROW, [("self.observers.fetch_sub(1, Ordering::Release)", "self.observers.fetch_sub(1, Ordering::Relaxed)")]),
    ],
    "join-observers-acquire": [
        ("weakened", ROW, [("self.observers.load(Ordering::Acquire)", "self.observers.load(Ordering::Relaxed)")]),
    ],
    "join-regrant-reset": [
        ("missing", ATTEMPT, [(
            "    row.reset().map_err(|_| BeginError::Corrupt)?;\n    probe::note(Primitive::Store);\n",
            "    probe::note(Primitive::Store);\n")]),
    ],
    "retain-current-load": [("weakened", KERNEL, [("SLOT.record.ident.load(Ordering::Acquire),\n                1",
                                                   "SLOT.record.ident.load(Ordering::Relaxed),\n                1")])],
    "publication-anchor": [("weakened", KERNEL, [("self.ident.fetch_add(REF, Ordering::Release);", "self.ident.fetch_add(REF, Ordering::Relaxed);")])],
    "publication-install": [("weakened", WORD, [(
        "slot_word.compare_exchange(current, next, Ordering::Release, Ordering::Relaxed)",
        "slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)")])],
    "reuse-from-count": [("masked", KERNEL, [("released_to.unwrap_or(word::refs(sighted))",
                                              "released_to.unwrap_or(word::refs(SLOT.record.ident.load(Ordering::Acquire)))")])],
    "retain-exchange": [("weakened", KERNEL, [(
        "slot_word.compare_exchange(current, next, Ordering::Relaxed, Ordering::Relaxed)",
        "slot_word.compare_exchange(current, next, Ordering::Acquire, Ordering::Relaxed)")])],
    "right-release": [("weakened", KERNEL, [("SLOT.record.ident.fetch_sub(REF, Ordering::Release);",
                                             "SLOT.record.ident.fetch_sub(REF, Ordering::Relaxed);")])],
    "state-flip": [
        ("weakened", WORD, [("slot_word.fetch_xor(from.bits() ^ to.bits() ^ policy, Ordering::Relaxed)",
                             "slot_word.fetch_xor(from.bits() ^ to.bits() ^ policy, Ordering::Release)")]),
        ("masked", WORD, [("slot_word.fetch_xor(from.bits() ^ to.bits() ^ policy, Ordering::Relaxed)",
                           "slot_word.fetch_xor(from.bits() ^ to.bits(), Ordering::Relaxed)")]),
    ],
    "state-flip-bind": [("masked", ALLOCATION, [(
        "word::move_state(ident, SlotState::Filling, SlotState::Resident, linked)",
        "word::move_state(ident, SlotState::Filling, SlotState::Retired, linked)")])],
    "bind-fingerprint-store": [
        ("weakened", KERNEL, [("self.fingerprint.store(!KEY_HASH, Ordering::Relaxed);", "self.fingerprint.store(!KEY_HASH, Ordering::Release);")]),
        ("weakened", SLOT, [("self.fingerprint.store(fingerprint, Ordering::Relaxed);", "self.fingerprint.store(fingerprint, Ordering::Release);")]),
        ("moved", KERNEL, [(
            "        self.fingerprint.store(!KEY_HASH, Ordering::Relaxed);\n        self.ident.fetch_xor(\n"
            "            SlotState::Filling.bits() ^ SlotState::Resident.bits(),\n            Ordering::Relaxed,\n        );\n",
            "        self.ident.fetch_xor(\n            SlotState::Filling.bits() ^ SlotState::Resident.bits(),\n            Ordering::Relaxed,\n        );\n"
            "        self.fingerprint.store(!KEY_HASH, Ordering::Relaxed);\n")]),
    ],
    "bind-fingerprint": [("moved", ALLOCATION, [(
        "        record.set_fingerprint(fingerprint);\n        let expires_at_s = deadline_seconds(expires_at_ticks);\n",
        "        let expires_at_s = deadline_seconds(expires_at_ticks);\n"),
        ("        tables.queue().link_with(slot, bind);\n",
         "        tables.queue().link_with(slot, bind);\n        record.set_fingerprint(fingerprint);\n")])],
    "anchored-sighting": [("weakened", KERNEL, [(
        "let sighted = SLOT.record.ident.load(Ordering::Acquire);",
        "let sighted = SLOT.record.ident.load(Ordering::Relaxed);")])],
    "retire-era-read": [("moved", KERNEL, [
        ("    let sighted = SLOT.record.ident.load(Ordering::Acquire);\n",
         "    let era = SLOT.record.fingerprint.load(Ordering::Relaxed);\n"
         "    let sighted = SLOT.record.ident.load(Ordering::Acquire);\n"),
        ("releasable(SLOT.record.fingerprint.load(Ordering::Relaxed), certified)", "releasable(era, certified)")])],
    "anchor-release": [("weakened", RELEASE, [(
        "            Ordering::AcqRel,\n            Ordering::Relaxed,\n        ) {\n            Ok(_) => break,",
        "            Ordering::Release,\n            Ordering::Relaxed,\n        ) {\n            Ok(_) => break,")])],
    "reserve-return-clear": [
        ("masked", "crates/kestrike/src/storage/reserve.rs", [("!(FLAGS | VISITED | STATE | POLICY | MARKER),\n        Ordering::Relaxed,",
                                                                "!(FLAGS | VISITED | STATE | POLICY),\n        Ordering::Relaxed,")]),
        ("masked", KERNEL, [("slot_word.fetch_and(\n        !(FLAGS | VISITED | STATE | POLICY | MARKER),",
                             "slot_word.fetch_and(\n        !(FLAGS | VISITED | STATE | POLICY),")]),
        ("missing", KERNEL, [("slot_word.fetch_and(\n        !(FLAGS | VISITED | STATE | POLICY | MARKER),\n        Ordering::Relaxed,\n    )",
                              "slot_word.swap(INCARNATION & 1, Ordering::Relaxed)")]),
        ("missing", KERNEL, [("    let previous = slot_word.fetch_and(\n        !(FLAGS | VISITED | STATE | POLICY | MARKER),\n        Ordering::Relaxed,\n    );\n",
                              "    // slot_word.fetch_and(!(FLAGS | VISITED | STATE | POLICY | MARKER), Ordering::Relaxed);\n"
                              "    /* slot_word.fetch_and(!(FLAGS | VISITED | STATE | POLICY | MARKER), Ordering::Relaxed); */\n"
                              "    let previous = slot_word.swap(1, Ordering::Relaxed);\n")]),
    ],
    "reserve-next-claim": [
        ("weakened", KERNEL, [("                Ordering::Release,\n                Ordering::Relaxed,\n            )\n            .is_ok(),",
                               "                Ordering::Relaxed,\n                Ordering::Relaxed,\n            )\n            .is_ok(),")]),
        ("masked", KERNEL, [("                u64::from(incarnation - 1),\n", "                free,\n")]),
    ],
}


SYMPTOM = {"lost": " appears 1 times in ", "moved": "operation no longer comes", "missing": " appears 0 times in ", "duplicated": " appears 2 times in ",
           "masked": "operands are", "weakened": "orderings are", "unanchored": " appears 0 times in its scope"}


def read_repo(path):
    return (ROOT / path).read_text()


def mutated(path, replacements, keep=True):
    """The file at `path` with each replacement applied once and, when `keep`, the replaced text appended in a
    trailing item. A file-scoped entry passes `keep=False`, since the trailer would add an occurrence inside its
    scope."""
    text = read_repo(path)
    for old, new in replacements:
        if text.count(old) != 1:
            raise AssertionError(f"{old!r} occurs {text.count(old)} times in {path}")
        text = text.replace(old, new)
    return text + ("\nfn kept_elsewhere() {\n" + "".join(old for old, _ in replacements) + "\n}\n" if keep else "")


def graph_of(text):
    """The error graph GenMC writes for `text`: one node per printed event, the ERROR event marked."""
    nodes = []
    for thread, event, label in re.findall(r"^\s*\((\d+), (\d+)\): (.*)$", text, re.M):
        if label.startswith("ERROR "):
            label = f'ERROR <FONT COLOR="gray"> {label[len("ERROR "):]}</FONT>'
        nodes.append(f'\t"({thread}, {event})" [label=<{label}>, tooltip="({thread}, {event})"]')
    return "strict digraph {\n" + "\n".join(nodes) + "\n}\n"


def positive(executions=3):
    return "\n".join([
        "GenMC v0.19.0 (LLVM 22.1.8)", "*** Compilation complete.", "*** Transformation complete.",
        "*** Verification complete.", "No errors were detected.",
        f"Number of complete executions explored: {executions}", "Total wall-clock time: 0.49s", "",
    ])


def violation(line=None, file=None, case="wrap_falsifier"):
    line = falsifier_line(case) if line is None else line
    file = Path(EXPECTED["cases"][case]["file"]).name if file is None else file
    return "\n".join([
        "GenMC v0.19.0 (LLVM 22.1.8)", "*** Compilation complete.", "*** Transformation complete.",
        "Error: Safety violation!", "Event (0, 4) in graph:", "<-1, 0>:", f"\t(0, 4): ERROR {file}:{line}",
        "*** Verification unsuccesful.", "Number of complete executions explored: 0", "Total wall-clock time: 0.44s", "",
    ])


LSE_CONFIG = '{"target":{"cfg(target_arch = \\"aarch64\\")":{"rustdocflags":["-C","target-feature=+lse"],"rustflags":["-C","target-feature=+lse"]}}}\n'


def lse_target_variants(config=LSE_CONFIG):
    """Each altered form of the admitted `target` table of `config`, a captured `cargo config get` output, and the
    admitted table beside or under another shaping table, with the entry the judge refuses for it."""
    key = 'cfg(target_arch = "aarch64")'
    admitted = json.loads(config)["target"]

    def altered(change):
        target = copy.deepcopy(admitted)
        change(target)
        return {"target": target}, "target"
    return [
        ("a second target key", *altered(lambda t: t.update({"x86_64-unknown-linux-gnu": {"rustflags": ["-C", "target-feature=+lse"]}}))),
        ("a linker", *altered(lambda t: t[key].update({"linker": "/usr/bin/ld"}))),
        ("a changed flag", *altered(lambda t: t[key].update({"rustflags": ["-C", "target-feature=+lse,+rcpc"]}))),
        ("a changed rustdoc flag", *altered(lambda t: t[key].update({"rustdocflags": ["-C", "target-feature=+lse,+rcpc"]}))),
        ("an added flag", *altered(lambda t: t[key]["rustdocflags"].extend(["-C", "opt-level=3"]))),
        ("an added rustc flag", *altered(lambda t: t[key]["rustflags"].extend(["-C", "opt-level=3"]))),
        ("target-cpu", *altered(lambda t: t[key].update({"rustflags": ["-C", "target-cpu=neoverse-v2"]}))),
        ("rustflags missing", *altered(lambda t: t[key].pop("rustflags"))),
        ("rustdocflags missing", *altered(lambda t: t[key].pop("rustdocflags"))),
        ("the admitted value under another key", {"target": {"cfg(all())": admitted[key]}}, "target"),
        ("the admitted value under two keys", {"target": {**admitted, "cfg(all())": admitted[key]}}, "target"),
        ("a reversed flag list", *altered(lambda t: t[key]["rustflags"].reverse())),
        ("beside a profile", {"target": admitted, "profile": {"dev": {"opt-level": 3}}}, "profile"),
        ("beside a debug-assertions profile", {"target": admitted, "profile": {"dev": {"debug-assertions": False}}}, "profile"),
        ("beside a build flag", {"target": admitted, "build": {"rustflags": ["--cfg", "loom"]}}, "build.rustflags"),
        ("beside an env entry", {"target": admitted, "env": {"RUSTFLAGS": "--cfg loom"}}, "env.RUSTFLAGS"),
        ("the admitted value under unstable", {"unstable": admitted}, "unstable"),
    ]


class JudgeGenmc(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-genmc-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.toolchain = base / "toolchain"
        (self.toolchain / "build/bin").mkdir(parents=True)
        self.binary = self.toolchain / "build/bin/genmc"
        self.binary.write_text("genmc\n")
        self.std = self.toolchain / "genmc-std"
        (self.std / "src").mkdir(parents=True)
        (self.std / "src/lib.rs").write_text("pub use std::*;\n")
        self.library = base / "lib64/libLLVM.so.22.1"
        self.library.parent.mkdir()
        self.library.write_bytes(b"libLLVM 22.1.8-1131\n")
        bin_dir = base / "bin"
        bin_dir.mkdir()
        (bin_dir / "ldd").write_text(
            "#!/usr/bin/env bash\n"
            "printf '\\tlinux-vdso.so.1 (0x00007fff)\\n\\tlibLLVM.so.22.1 => %s (0x00007f00)\\n' \"$STUB_LDD_LIBLLVM\"\n"
        )
        (bin_dir / "ldd").chmod(0o755)
        self.env = dict(os.environ, PATH=f"{bin_dir}:{os.environ['PATH']}", STUB_LDD_LIBLLVM=str(self.library))
        self.sysroot = base / "rust/toolchains/nightly-2026-07-27-x86_64-unknown-linux-gnu"
        self.rustc = write_rustc(self.sysroot)
        self.identity = {
            "upstream": EXPECTED["upstream"], "llvm": EXPECTED["llvm"], "clang": "clang version 22.1.8",
            "rustc": dict(EXPECTED["rustc"], name="nightly-2026-07-27", toolchain=str(self.sysroot), sha256=sha256(self.rustc)),
            "cxx": "g++ (GCC) 14.2.1 20250110 (Red Hat 14.2.1-7)",
            "patches": {path.name: sha256(path) for path in sorted((ROOT / "verification/genmc/patches").glob("*.patch"))},
            "recipe": sha256(ROOT / "verification/genmc/provision.sh"),
            "binary": {"path": str(self.binary), "sha256": sha256(self.binary)},
            "libllvm": {"path": str(self.library), "sha256": sha256(self.library)},
            "genmc_std": {"path": str(self.std), "tree": tree(self.std)},
        }
        self.write_toolchain()
        self.evidence = base / "evidence"
        self.evidence.mkdir()

    def write_toolchain(self):
        (self.toolchain / "identity.json").write_text(json.dumps(self.identity))

    def run_script(self, *args):
        return subprocess.run([sys.executable, str(SCRIPT), *args], capture_output=True, text=True, check=False, env=self.env)

    def admit(self):
        return self.run_script("identity", "--toolchain", str(self.toolchain), "--evidence", str(self.evidence))

    def manifest(self, name):
        return str(ROOT / Path(EXPECTED["package"]).parent / f"run-{name}" / "Cargo.toml")

    def lane_env(self, name):
        return {"CASE": name, "RUSTUP_TOOLCHAIN": "nightly-2026-07-27", "RUSTC": str(self.rustc),
                "RUSTC_WRAPPER": "", "RUSTC_WORKSPACE_WRAPPER": ""}

    def write_runs(self, outputs=None, exits=None, argvs=None, envs=None, graphs=True, intrinsics=None, cases="pr", config="{}\n"):
        if config is not None:
            (self.evidence / "cargo-config.json").write_text(config)
        for name in profile(cases):
            declared = EXPECTED["cases"][name]
            text = (outputs or {}).get(name, positive() if declared["expect"] == "positive" else violation(case=name))
            code = (exits or {}).get(name, 0 if declared["expect"] == "positive" else 42)
            argv = (argvs or {}).get(name, [str(self.binary), *EXPECTED["options"],
                                            f"--dump-error-graph={self.evidence / f'genmc-{name}.dot'}", self.manifest(name)])
            called = (intrinsics or {}).get(name, declared.get("intrinsics"))
            if called is not None:
                (self.evidence / f"genmc-{name}.intrinsics").write_text("\n".join(called) + "\n")
            env = (envs or {}).get(name, self.lane_env(name))
            (self.evidence / f"genmc-{name}.txt").write_text(text)
            (self.evidence / f"genmc-{name}.exit").write_text(f"{code}\n")
            (self.evidence / f"genmc-{name}.argv").write_text("\n".join(argv) + "\n")
            (self.evidence / f"genmc-{name}.env").write_text("".join(f"{k}={v}\n" for k, v in env.items()))
            if graphs and declared["expect"] == "violation":
                (self.evidence / f"genmc-{name}.dot").write_text(graph_of(text))

    def judge(self, cases="pr"):
        result = self.run_script("judge", "--profile", cases, "--evidence", str(self.evidence), "--revision", "0" * 40)
        try:
            report = json.loads((self.evidence / "report.json").read_text())
            receipt = json.loads((self.evidence / "receipt.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the judge wrote no report: {error} {result.stderr}")
        self.assertEqual(result.returncode, report["code"], report)
        return report, receipt

    def test_the_declaration_names_the_pinned_route_and_cases(self):
        self.assertEqual(EXPECTED["upstream"], "9f6c4c0772d0c42b325681581acc6a0f3eb9b5f7")
        self.assertEqual((EXPECTED["llvm"], EXPECTED["rustc"]["llvm"]), ("22.1.8", "22.1.8"))
        self.assertEqual(EXPECTED["options"], ["-rc11", "--disable-estimation"])
        qualification = {"sb_sc": "positive", "sb_prior_rmw": "positive", "sb_relaxed": "violation",
                         "intrinsic_boundaries": "positive", "wrap_falsifier": "violation"}
        self.assertEqual({name: EXPECTED["cases"][name]["expect"] for name in qualification}, qualification)
        credit = {f"credit-{strength}-{state}": "positive" if strength in ("seq", "fenced") or state == "empty" else "violation"
                  for strength in ("seq", "fenced", "nopark", "noclear") for state in ("empty", "stale", "pool1", "two")}
        grace = {f"grace{readers}-{strength}": "positive" if strength in ("seq", "fenced", "weakretire", "weakcertify") else "violation"
                 for readers in ("1", "2")
                 for strength in ("seq", "fenced", "weakpin", "readeralone", "weakretire", "weakcertify", "bumprelaxed", "startrelaxed")}
        grace["grace1-claimmisencoded"] = grace["grace2-claimmisencoded"] = "violation"
        cutoff = {"cutoff-pinfirst": "positive", "cutoff-cutofffirst": "violation", "cutoff-admitted": "violation",
                  "cutoff-refused": "violation", "cutoff-refusalkeeps": "violation"}
        cutoff.update({"terminal-own": "positive", "terminal-none": "violation", "terminal-observed": "violation"})
        join = {"join-production": "positive", "join-relaxedobserve": "violation", "join-relaxeddepart": "violation",
                "join-earlydetach": "violation", "join-ignoresobservers": "violation"}
        self.assertEqual({name: case["expect"] for name, case in EXPECTED["cases"].items()},
                         {**qualification, **credit, **grace, **cutoff, **join})
        self.assertEqual(EXPECTED["profiles"]["scheduled"], sorted(name for name in grace if name.startswith("grace2-")))
        self.assertEqual(sorted(EXPECTED["profiles"]["pr"]), sorted(set(EXPECTED["cases"]) - set(EXPECTED["profiles"]["scheduled"])))
        for name, case in EXPECTED["cases"].items():
            if name.startswith("credit-") and case["expect"] == "violation":
                self.assertEqual(case["checks"], ["a record holding credits is flagged"], name)
            if name.startswith("grace") and case["expect"] == "violation":
                self.assertEqual(case["checks"], ["protection violated: anchor released under a pinned reader",
                                                  "protection violated: a pinned reader's retain refused"], name)
        self.assertEqual(EXPECTED["cases"]["intrinsic_boundaries"]["intrinsics"], sorted(
            f"llvm.{op}.i64" for op in ("uadd.sat", "usub.sat", "umin", "umax", "smin", "smax")))
        self.assertEqual(len(sorted((ROOT / "verification/genmc/patches").glob("*.patch"))), 3)

    def test_the_declared_toolchain_is_admitted_and_each_drift_is_refused(self):
        result = self.admit()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(f"- GenMC {EXPECTED['upstream']}; genmc sha256 {sha256(self.binary)}", (self.evidence / "pins.txt").read_text())
        original = copy.deepcopy(self.identity)
        drifts = [
            (lambda i: i.update(upstream="0" * 40), "builds GenMC"),
            (lambda i: i.update(llvm="23.1.0"), "links LLVM"),
            (lambda i: i["rustc"].update(commit="f" * 40), "rustc"),
            (lambda i: i["patches"].pop(next(iter(i["patches"]))), "patches other than the committed ones"),
            (lambda i: i["patches"].update({next(iter(i["patches"])): "e" * 64}), "patches other than the committed ones"),
            (lambda i: i.update(recipe="d" * 64), "another revision of provision.sh"),
            (lambda i: i["binary"].update(sha256="c" * 64), "genmc binary changed"),
            (lambda i: i["genmc_std"].update(tree="b" * 64), "genmc-std changed"),
            (lambda i: i.pop("libllvm"), "libLLVM genmc loads changed"),
            (lambda i: i["libllvm"].update(sha256="a" * 64), "libLLVM genmc loads changed"),
            (lambda i: i["rustc"].update(sha256="9" * 64), "rustc binary changed"),
            (lambda i: i["rustc"].pop("sha256"), "rustc binary changed"),
            (lambda i: i["rustc"].update(toolchain=str(self.sysroot / "elsewhere")), "rustc binary changed"),
        ]
        for edit, reason in drifts:
            with self.subTest(reason=reason):
                self.identity = copy.deepcopy(original)
                edit(self.identity)
                self.write_toolchain()
                result = self.admit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(reason, result.stderr)

    def test_a_shared_llvm_replaced_after_the_build_is_refused(self):
        # The recorded version string names the build's LLVM; the library
        # digest names the code genmc loads now.
        self.assertEqual(self.admit().returncode, 0)
        self.library.write_bytes(b"libLLVM 22.1.9-1200\n")
        result = self.admit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("libLLVM genmc loads changed", result.stderr)

    def test_a_rustc_that_reports_another_identity_is_refused(self):
        self.assertEqual(self.admit().returncode, 0)
        for identity, reason in (({"commit": "f" * 40}, "f" * 40), ({"llvm": "23.1.0"}, "23.1.0"), ({"release": "1.98.0"}, "1.98.0")):
            with self.subTest(identity=identity):
                write_rustc(self.sysroot, **identity)
                self.identity["rustc"]["sha256"] = sha256(self.rustc)
                self.write_toolchain()
                result = self.admit()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn("rustc now reports", result.stderr)
                self.assertIn(reason, result.stderr)
        self.rustc.write_text("#!/usr/bin/env bash\nexit 1\n")
        self.identity["rustc"]["sha256"] = sha256(self.rustc)
        self.write_toolchain()
        result = self.admit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("rustc -vV failed", result.stderr)

    def test_a_libllvm_bound_elsewhere_at_run_time_is_refused(self):
        other = Path(self.temp.name) / "elsewhere/libLLVM.so.22.1"
        other.parent.mkdir()
        other.write_bytes(self.library.read_bytes())
        self.assertEqual(self.admit().returncode, 0)
        self.env["STUB_LDD_LIBLLVM"] = str(other)
        result = self.admit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(f"genmc now loads {other}", result.stderr)
        self.env["STUB_LDD_LIBLLVM"] = ""
        result = self.admit()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn("loads no libLLVM", result.stderr)

    def test_a_case_manifest_named_through_a_symlinked_checkout_is_the_cases_own(self):
        checkout = Path(self.temp.name) / "checkout"
        checkout.symlink_to(ROOT, target_is_directory=True)
        argvs = {
            name: [str(self.binary), *EXPECTED["options"], f"--dump-error-graph={self.evidence / f'genmc-{name}.dot'}",
                   str(checkout / Path(EXPECTED["package"]).parent / f"run-{name}" / "Cargo.toml")]
            for name in EXPECTED["cases"]
        }
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs(argvs=argvs)
        report, _ = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)

    def test_evidence_named_by_a_relative_path_is_judged_as_the_lane_recorded_it(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        result = subprocess.run(
            [sys.executable, str(SCRIPT), "judge", "--profile", "pr", "--evidence", self.evidence.name, "--revision", "0" * 40],
            cwd=self.temp.name, capture_output=True, text=True, check=False, env=self.env,
        )
        try:
            report = json.loads((self.evidence / "report.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"the judge wrote no report: {error} {result.stderr}")
        self.assertEqual((result.returncode, report["verdict"]), (0, "credited"), report)

    def test_complete_matching_runs_credit_every_case(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        report, receipt = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)
        self.assertEqual(report["cases"]["wrap_falsifier"], {"result": "violation", "at": f"qualification.rs:{falsifier_line()}", "executions": 0})
        self.assertEqual(report["cases"]["sb_sc"], {"result": "positive", "executions": 3})
        self.assertEqual((receipt["completion"], receipt["executed"], receipt["module"]), ("completed", profile("pr"), "pr"))
        self.assertNotIn("grace2-seq", report["cases"])
        self.assertLessEqual({"verification/genmc/expected.json", "verification/genmc/provision.sh",
                              "verification/genmc/packages/kernels/src/qualification.rs",
                              *(f"crates/kestrike/src/storage/{module}.rs" for module in ("credit", "grace", "word")),
                              *EXPECTED["transcribed"]},
                             set(receipt["inputs"]))
        self.assertLessEqual({"crates/kestrike/src/index/sequence.rs", "crates/kestrike/src/storage/register.rs",
                              "crates/kestrike/src/storage/release.rs", "crates/kestrike/src/storage/slot.rs",
                              "crates/kestrike/src/storage/reserve.rs", "crates/kestrike/src/storage/config.rs"}, set(receipt["inputs"]))

    def test_each_unusable_or_mismatched_run_is_refused(self):
        self.assertEqual(self.admit().returncode, 0)
        cases = [
            ({"sb_sc": violation()}, {"sb_sc": 42}, 1, "exited 42, declared positive"),
            ({"sb_sc": positive(0)}, {}, 1, "explored no complete execution"),
            ({"sb_sc": positive() + "Number of blocked executions seen: 4\n"}, {}, 1, "pruned executions"),
            ({"sb_sc": positive().replace("No errors were detected.\n", "")}, {}, 2, "prints 0 No errors lines"),
            ({"sb_sc": positive().replace("*** Transformation complete.\n", "")}, {}, 2, "prints 0 transformation lines"),
            ({"sb_sc": "Code generator does not support intrinsic function 'llvm.uadd.sat.i64'!\n" + positive()}, {}, 2, "aborted"),
            ({"sb_sc": positive().replace("*** Verification complete.", "Constant unimplemented for type: { ptr, ptr }")}, {"sb_sc": 134}, 2, "aborted"),
            ({}, {"sb_sc": 124}, 3, "interrupted"),
            ({"wrap_falsifier": positive()}, {"wrap_falsifier": 0}, 1, "exited 0, declared a violation"),
            ({"wrap_falsifier": violation().replace("Error: Safety violation!\n", "")}, {}, 2, "Safety violation"),
            ({"wrap_falsifier": violation(line=falsifier_line() - 1)}, {}, 1, "failed at qualification.rs:"),
            ({"wrap_falsifier": violation(file="check.rs", line=17)}, {}, 1, "failed at check.rs:17"),
            ({"wrap_falsifier": violation() + "\t(1, 2): ERROR qualification.rs:5\n"}, {}, 2, "reports 2 ERROR events"),
            ({"wrap_falsifier": "\n".join(line for line in violation().splitlines() if "ERROR" not in line)}, {}, 2, "reports 0 ERROR events"),
            ({"wrap_falsifier": violation()}, {"wrap_falsifier": 1}, 2, "exited 1, declared a violation"),
            ({"wrap_falsifier": violation() + "No errors were detected.\n"}, {}, 2, "prints 1 No errors lines beside a violation"),
            ({"wrap_falsifier": violation().replace("*** Verification unsuccesful.", "*** Verification complete.\n*** Verification unsuccesful.")},
             {}, 2, "prints 1 Verification complete lines beside a violation"),
        ]
        for outputs, exits, code, reason in cases:
            with self.subTest(reason=reason):
                self.write_runs(outputs, exits)
                report, receipt = self.judge()
                self.assertEqual(report["code"], code, report)
                self.assertIn(reason, report["reason"])
                self.assertEqual(receipt["executions"], 0)
        for called in ([], ["llvm.uadd.sat.i64"], [*EXPECTED["cases"]["intrinsic_boundaries"]["intrinsics"][1:]]):
            with self.subTest(intrinsics=called):
                self.write_runs(intrinsics={"intrinsic_boundaries": called})
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn("intrinsic_boundaries's bitcode calls", report["reason"])
        self.write_runs()
        (self.evidence / "genmc-intrinsic_boundaries.intrinsics").unlink()
        report, _ = self.judge()
        self.assertIn("intrinsic_boundaries's bitcode calls []", report["reason"])
        self.write_runs(graphs=False)
        (self.evidence / "genmc-wrap_falsifier.dot").unlink(missing_ok=True)
        report, _ = self.judge()
        self.assertIn("left no error graph", report["reason"])

    def test_a_pr_run_never_stands_in_for_the_scheduled_domain(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs(cases="scheduled")
        report, _ = self.judge("pr")
        self.assertEqual(report["code"], 2, report)
        self.assertIn("outside the pr profile", report["reason"])
        report, receipt = self.judge("scheduled")
        self.assertEqual(report["code"], 0, report)
        self.assertEqual((receipt["module"], receipt["executed"]), ("scheduled", profile("scheduled")))
        for path in self.evidence.glob("genmc-grace2-*"):
            path.unlink()
        report, _ = self.judge("scheduled")
        self.assertEqual(report["code"], 2, report)
        self.assertIn("grace2-", report["reason"])
        report, _ = self.judge("nightly")
        self.assertIn("profile 'nightly' is not declared", report["reason"])

    def test_a_graph_from_another_run_is_refused(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        nopark = self.evidence / "genmc-credit-nopark-two.dot"
        for graph in ("strict digraph {\n}\n", (self.evidence / "genmc-sb_relaxed.dot").read_text(),
                      graph_of(violation(case="credit-nopark-two")).replace("(0, 4)", "(1, 4)")):
            with self.subTest(graph=graph[:40]):
                nopark.write_text(graph)
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn("credit-nopark-two's graph", report["reason"])

    def test_thread_ends_and_blocked_joins_take_no_graph_node(self):
        self.assertEqual(self.admit().returncode, 0)
        text = violation(case="credit-nopark-two")
        graph = graph_of(text)
        ended = text.replace("<-1, 0>:", "<-1, 0>:\n\t(0, 5): BLOCK[join]\n<0, 1> thread:\n\t(1, 1): THREAD_END\n<0, 2> thread:\n\t(2, 1): THREAD_END")
        drawn = graph.replace("\n}", '\n\t"(2, 1)" [label=<THREAD_END>, tooltip="(2, 1)"]\n}')
        self.write_runs(outputs={"credit-nopark-two": ended})
        (self.evidence / "genmc-credit-nopark-two.dot").write_text(drawn)
        report, _ = self.judge()
        self.assertEqual(report["code"], 0, report)

    def test_a_grace_control_credits_either_pinned_reader_check(self):
        self.assertEqual(self.admit().returncode, 0)
        for check in (0, 1):
            with self.subTest(check=check):
                text = violation(falsifier_line("grace1-weakpin", check), case="grace1-weakpin")
                self.write_runs(outputs={"grace1-weakpin": text})
                report, _ = self.judge()
                self.assertEqual(report["code"], 0, report)

    def test_each_case_agrees_with_the_litmus_tests_it_names(self):
        litmus = json.loads((ROOT / "verification/rc11/expected.json").read_text())["tests"]
        for name, case in EXPECTED["cases"].items():
            named = name.startswith(("grace", "cutoff-", "terminal-")) or (name.startswith("credit-") and not name.endswith("-empty")) \
                or (name.startswith("join-") and name not in ("join-earlydetach", "join-ignoresobservers"))
            self.assertEqual(bool(case["litmus"]), named, name)
            outcomes = {litmus[test]["outcome"] for test in case.get("litmus", [])}
            if named:
                self.assertEqual(outcomes, {"Never"} if case["expect"] == "positive" else {"Sometimes"}, name)
        composite = {"fenced": "G10-composite-all-fences", "weakretire": "G11-composite-retire-fence-dropped",
                     "weakcertify": "G12-composite-certify-fence-dropped", "readeralone": "G13-composite-reader-fences-alone"}
        for readers in ("1", "2"):
            for strength, test in composite.items():
                self.assertIn(test, EXPECTED["cases"][f"grace{readers}-{strength}"]["litmus"], f"grace{readers}-{strength}")
        JUDGE.check_correspondence(EXPECTED)
        for name, litmus, reason in (
            ("grace1-weakretire", ["G2-grace-pin-fence-dropped"], "grace1-weakretire is declared positive and its litmus tests"),
            ("credit-nopark-two", ["L1-both-fences"], "credit-nopark-two is declared violation and its litmus tests"),
            ("grace1-seq", ["G99-absent"], "grace1-seq names an undeclared litmus test"),
            ("grace1-bumprelaxed", None, "grace1-bumprelaxed names no litmus list"),
            ("grace1-weakpin", ["G2-grace-pin-fence-dropped", "G4-grace-retire-fence-dropped"],
             "grace1-weakpin is declared violation and its litmus tests"),
        ):
            with self.subTest(name=name):
                drifted = json.loads(json.dumps(EXPECTED))
                if litmus is None:
                    del drifted["cases"][name]["litmus"]
                else:
                    drifted["cases"][name]["litmus"] = litmus
                with self.assertRaises(JUDGE.Refusal) as refused:
                    JUDGE.check_correspondence(drifted)
                self.assertIn(reason, str(refused.exception))

    def test_the_kernel_stand_in_keeps_the_production_terminal_era(self):
        config = (ROOT / "crates/kestrike/src/storage/config.rs").read_text()
        stand_in = (PACKAGE / "src/storage.rs").read_text()
        line = "pub(crate) const ERA_TERMINAL: u64 = 1 << 63;"
        self.assertIn(line, config)
        self.assertIn(line, stand_in)
        for module in ("credit", "grace", "word"):
            self.assertIn(f'#[path = "../../../../../crates/kestrike/src/storage/{module}.rs"]', stand_in)
            self.assertTrue((PACKAGE / "src" / f"../../../../../crates/kestrike/src/storage/{module}.rs").resolve().is_file())

    def test_every_binding_entry_holds_and_each_of_its_mutants_drifts(self):
        self.assertEqual(JUDGE.transcription_drift(EXPECTED, read_repo), [])
        ids = [entry["id"] for entry in EXPECTED["bindings"]]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertEqual(set(MUTANTS), set(ids))
        self.assertEqual([name for name, mutants in MUTANTS.items() if not mutants], [], "every binding entry has a mutant")
        self.assertLessEqual({"moved", "missing", "duplicated", "masked", "weakened"},
                             {kind for mutants in MUTANTS.values() for kind, _, _ in mutants})
        strong = sorted(entry["id"] for entry in EXPECTED["bindings"] if set(entry["orderings"]) - {"Relaxed"})
        self.assertEqual([name for name in strong if not any(kind == "weakened" for kind, _, _ in MUTANTS[name])], [],
                         "every binding stronger than Relaxed has an ordering-change mutant")
        entries = {entry["id"]: entry for entry in EXPECTED["bindings"]}
        for name, mutants in MUTANTS.items():
            for kind, path, replacements in mutants:
                with self.subTest(entry=name, kind=kind):
                    scoped = all(site["scope"] for site in (entries[name].get("production"), entries[name].get("kernel")) if site)
                    changed = mutated(path, replacements, keep=scoped)
                    drift = JUDGE.transcription_drift(EXPECTED, lambda other: changed if other == path else read_repo(other))
                    site = entries[name].get("production") if path.startswith("crates/") else entries[name]["kernel"]
                    symptom = f" {site['call']}{SYMPTOM[kind]}" if kind in ("lost", "missing", "duplicated") else SYMPTOM[kind]
                    self.assertTrue(any(line.startswith(f"{name}: ") and symptom in line for line in drift), drift)

    def test_the_bindings_name_the_return_mask_claim_era_and_sequence_operations_production_performs(self):
        entries = {entry["id"]: entry for entry in EXPECTED["bindings"]}
        self.assertEqual(entries["reserve-return-clear"]["operands"], ["!(FLAGS | VISITED | STATE | POLICY | MARKER)"])
        self.assertNotIn("operands", entries["reserve-return-clear"]["kernel"])
        self.assertEqual((entries["reserve-next-claim"]["orderings"], "operands" in entries["reserve-next-claim"]["kernel"]),
                         (["Release", "Relaxed"], False))
        self.assertEqual((entries["retire-stamp"]["kind"], entries["retire-stamp"]["orderings"]), ("store", ["Release"]))
        self.assertEqual(entries["retire-era-read"]["kernel"]["after"], ["anchored-sighting"])
        self.assertEqual(entries["claim-before-pin"]["kernel"]["before"], ["pin::<_, S>(&SLOT.era, &SLOT.records[record])"])
        catalog = {record["id"]: record for record in json.loads((ROOT / "verification/obligations.json").read_text())["records"]}
        for entry in EXPECTED["bindings"]:
            with self.subTest(entry=entry["id"]):
                self.assertEqual(catalog[entry["obligation"]]["job"], "genmc")
                self.assertIn(f"`{entry['id']}`", catalog[entry["obligation"]]["reference"])
        self.assertIn("mc-correspondence-contract", catalog)

    def test_the_cutoff_control_is_the_production_entry_with_the_cutoff_read_first(self):
        # The control's body is the production entrant's after the binding
        # mutant that moves the cutoff load ahead of the pin.
        normalized = JUDGE.normalized
        kernel = read_repo(CUTOFF)
        production = JUDGE.bodies(normalized(kernel), "fn entrant")
        control = JUDGE.bodies(normalized(kernel), "fn entrant_cutoff_first")
        self.assertEqual((len(production), len(control)), (1, 1))
        old, new = MUTANTS["entry-cutoff-load"][1][2][0]
        refusal_cfg = normalized('#[cfg(not(refusal = "keeps"))]')
        expected = production[0].replace(normalized(old), normalized(new)).replace(refusal_cfg, "")
        self.assertEqual(expected, control[0])

    def test_an_unbound_strength_a_wrong_kind_or_a_production_file_outside_the_transcribed_list_drifts(self):
        kernel = read_repo(KERNEL).replace("    const COMMIT: Ordering = Ordering::SeqCst;\n",
                                      "    const COMMIT: Ordering = Ordering::SeqCst;\n    const CUTOFF: Ordering = Ordering::SeqCst;\n", 1)
        self.assertEqual(JUDGE.transcription_drift(EXPECTED, lambda path: kernel if path == KERNEL else read_repo(path)),
                         [f"{KERNEL} transcribes CUTOFF in its strength and no binding entry binds it"])
        unnamed = copy.deepcopy(EXPECTED)
        unnamed["strengths"] = []
        self.assertIn("claim-load: the kernel names S::CLAIM_LOAD, which no declared strength of "
                      f"{KERNEL} defines", JUDGE.transcription_drift(unnamed, read_repo))
        misnamed = copy.deepcopy(EXPECTED)
        next(entry for entry in misnamed["bindings"] if entry["id"] == "claim-raise")["kind"] = "load"
        self.assertEqual(JUDGE.transcription_drift(misnamed, read_repo)[:2],
                         ["claim-raise: the production bound.fetch_max is no load",
                          "claim-raise: the kernel SLOT.claimed.fetch_max is no load"])
        def entry(declared, name):
            return next(item for item in declared["bindings"] if item["id"] == name)
        absent = copy.deepcopy(EXPECTED)
        entry(absent, "claim-load")["kernel"]["before"] = ["claim-raise", "S::fence_after_claim()"]
        unlocated = copy.deepcopy(EXPECTED)
        entry(unlocated, "claim-raise")["kernel"]["call"] = "SLOT.claimed.fetch_min"
        elsewhere = copy.deepcopy(EXPECTED)
        entry(elsewhere, "claim-load")["kernel"]["before"] = ["pass-bound-load"]
        for declared, line in (
            (absent, "claim-load: the kernel anchor 'S::fence_after_claim()' appears 0 times in its scope"),
            (unlocated, "claim-load: the kernel anchor entry claim-raise was not located"),
            (elsewhere, "claim-load: the kernel anchor entry pass-bound-load sits in another scope"),
        ):
            with self.subTest(line=line):
                self.assertIn(line, JUDGE.transcription_drift(declared, read_repo))
        commented = read_repo(KERNEL).replace("    S::fence_claim();\n",
                                              "    S::fence_claim();\n    // SLOT.claimed.load(S::CLAIM_LOAD);\n", 1)
        self.assertEqual(JUDGE.transcription_drift(EXPECTED, lambda path: commented if path == KERNEL else read_repo(path)), [])
        # Quote, comment and bracket delimiters inside char and string literals are literal contents: the lexer
        # consumes each literal whole, so the bound store and the scope and argument list that hold it stay intact.
        literals = read_repo(SEQUENCE).replace("        sequence.store(stable + 1, Ordering::SeqCst);\n",
                                               "        let _ = ('\"', '\\'', \"\\\" /* //\", b'\"', r\"*/\", '}', '{', '(', ')', ',');\n"
                                               "        sequence.store(stable + 1, Ordering::SeqCst);\n", 1)
        self.assertNotEqual(literals, read_repo(SEQUENCE))
        self.assertEqual(JUDGE.transcription_drift(EXPECTED, lambda path: literals if path == SEQUENCE else read_repo(path)), [])
        # After a char literal with a `\x` or `\u{...}` escape, or after a lifetime such as `'r`, the lexer reads the
        # following quoted string as one literal, so its `/*` is text and the bound store stays visible to the drift check.
        for prefix in ("let _ = ['\\x41','\"']; let _ = \"/*\";", "let _ = ['\\u{0_41}','\"']; let _ = \"/*\";",
                       "m!('r\"x\\\"/* /* */\");", "m!('br\"x\\\"/* /* */\");"):
            with self.subTest(prefix=prefix):
                shaped = read_repo(SEQUENCE).replace("        sequence.store(stable + 1, Ordering::SeqCst);\n",
                                                     f"        {prefix}\n        sequence.store(stable + 1, Ordering::SeqCst);\n"
                                                     "        // */\n", 1)
                self.assertNotEqual(shaped, read_repo(SEQUENCE))
                self.assertEqual(JUDGE.transcription_drift(EXPECTED, lambda path: shaped if path == SEQUENCE else read_repo(path)), [])
        narrowed = copy.deepcopy(EXPECTED)
        narrowed["transcribed"].remove(REGISTER)
        self.assertEqual(JUDGE.transcription_drift(narrowed, read_repo),
                         [f"{name}: {REGISTER} is not among the transcribed files"
                          for name in ("claim-load", "claim-raise", "entry-cutoff-load")])

    def test_drift_refuses_as_its_own_class_before_any_case_is_adjudicated(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        path, replacements = MUTANTS["reserve-return-clear"][1][1:]
        changed = mutated(path, replacements)
        original = JUDGE.read_source
        with unittest.mock.patch.dict(os.environ, self.env):
            with unittest.mock.patch.object(JUDGE, "read_source", lambda other: changed if other == path else original(other)):
                report, receipt = JUDGE.derive(self.evidence, "0" * 40, "pr")
            healthy, _ = JUDGE.derive(self.evidence, "0" * 40, "pr")
        self.assertEqual((report["code"], report["verdict"], report["credited"], report["cases"]),
                         (2, "correspondence drift", False, {}), report)
        self.assertTrue(report["reason"].startswith("correspondence drift: reserve-return-clear: "), report["reason"])
        self.assertEqual((receipt["completion"], receipt["executed"]), ("correspondence drift", []))
        self.assertEqual((healthy["code"], healthy["verdict"]), (0, "credited"), healthy)

    def test_another_command_environment_or_case_set_is_refused(self):
        self.assertEqual(self.admit().returncode, 0)
        graph = f"--dump-error-graph={self.evidence / 'genmc-sb_sc.dot'}"
        manifest = self.manifest("sb_sc")
        for argv in (
            ["/usr/bin/genmc", *EXPECTED["options"], graph, manifest],
            [str(self.binary), "-rc11", graph, manifest],
            [str(self.binary), *EXPECTED["options"], "--bound=2", graph, manifest],
            [str(self.binary), *EXPECTED["options"], graph, self.manifest("sb_prior_rmw")],
            [str(self.binary), *EXPECTED["options"], graph, str(Path(self.temp.name) / "elsewhere/run-sb_sc/Cargo.toml")],
            [str(self.binary), *EXPECTED["options"], "--dump-error-graph=/tmp/stale.dot", manifest],
        ):
            with self.subTest(argv=argv):
                self.write_runs(argvs={"sb_sc": argv})
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn("sb_sc ran", report["reason"])
        for env in (
            dict(self.lane_env("sb_prior_rmw"), CASE="sb_sc") | {"CASE": "sb_prior_rmw"},
            {"CASE": "sb_sc", "RUSTUP_TOOLCHAIN": "nightly-2026-07-27"},
            dict(self.lane_env("sb_sc"), RUSTC="/usr/bin/rustc"),
            dict(self.lane_env("sb_sc"), RUSTC_WRAPPER="sccache"),
            dict(self.lane_env("sb_sc"), RUSTC_WORKSPACE_WRAPPER="sccache"),
        ):
            with self.subTest(env=env):
                self.write_runs(envs={"sb_sc": env})
                report, _ = self.judge()
                self.assertIn("sb_sc ran with", report["reason"])
        self.write_runs()
        (self.evidence / "genmc-extra.txt").write_text(positive())
        report, _ = self.judge()
        self.assertIn("outside the pr profile ['extra']", report["reason"])

    def test_an_evidence_path_the_judge_cannot_read_is_refused_with_a_report(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        recorded = self.evidence / "genmc-sb_sc.env"
        recorded.unlink()
        recorded.mkdir()
        report, receipt = self.judge()
        self.assertEqual((report["code"], receipt["executed"]), (2, []), report)
        self.assertTrue(report["reason"].startswith("the judgment cannot read an input"), report)

    def test_a_receipt_input_the_judge_cannot_read_exits_2_without_a_report(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        pins, config, report = (self.evidence / name for name in ("pins.txt", "cargo-config.json", "report.json"))
        provenance = pins.read_text()
        plants = (
            ("a pins directory", lambda: (pins.unlink(), pins.mkdir()), lambda: (pins.rmdir(), pins.write_text(provenance))),
            ("an unreadable configuration", lambda: config.chmod(0), lambda: config.chmod(0o644)),
            ("a report directory", report.mkdir, report.rmdir),
        )
        for name, plant, restore in plants:
            with self.subTest(plant=name):
                if name == "an unreadable configuration" and os.geteuid() == 0:
                    self.skipTest("root reads a file of any mode")
                plant()
                result = self.run_script("judge", "--profile", "pr", "--evidence", str(self.evidence), "--revision", "0" * 40)
                restore()
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertTrue(result.stderr.startswith("judge-genmc: "), result.stderr)
                self.assertNotIn("Traceback", result.stderr)
                self.assertFalse(report.exists() or (self.evidence / "receipt.json").exists())

    def test_pins_outside_utf8_are_recorded_with_replacement_characters(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        (self.evidence / "pins.txt").write_bytes(b"\xff\xfe")
        report, receipt = self.judge()
        self.assertEqual(report["code"], 0, report)
        self.assertEqual(receipt["tool"]["provenance"], ["\ufffd\ufffd"])
        self.assertEqual(receipt["inputs"]["pins.txt"], sha256(self.evidence / "pins.txt"))

    def test_cargo_configuration_that_shapes_the_build_is_refused(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs(config=json.dumps({"env": {"TMPDIR": "/scratch"}, "net": {"git-fetch-with-cli": True}, "build": {"jobs": 4}}))
        report, _ = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)
        for config, entry in (
            ({"build": {"rustc": "/usr/bin/rustc"}}, "build.rustc"),
            ({"build": {"rustc-wrapper": "sccache"}}, "build.rustc-wrapper"),
            ({"build": {"target": "aarch64-unknown-linux-gnu"}}, "build.target"),
            ({"build": {"rustflags": ["-C", "opt-level=3"]}}, "build.rustflags"),
            ({"build": {"build-dir": "/elsewhere"}}, "build.build-dir"),
            ({"profile": {"dev": {"opt-level": 3}}}, "profile"),
            ({"target": {"x86_64-unknown-linux-gnu": {"linker": "/usr/bin/ld"}}}, "target"),
            ({"unstable": {"build-std": ["std"]}}, "unstable"),
            ({"patch": {"crates-io": {}}}, "patch"),
            ({"source": {"crates-io": {"replace-with": "vendored"}}}, "source"),
            ({"env": {"CASE": {"value": "sb_sc", "force": True}}}, "env.CASE"),
            ({"env": {"RUSTC_BOOTSTRAP": "1"}}, "env.RUSTC_BOOTSTRAP"),
            ({"env": {"CARGO_BUILD_RUSTC": "/usr/bin/rustc"}}, "env.CARGO_BUILD_RUSTC"),
        ):
            with self.subTest(entry=entry):
                self.write_runs(config=json.dumps(config))
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(f"the cargo configuration sets {entry}", report["reason"])
                config_command = subprocess.run([sys.executable, "scripts/judge-genmc.py", "config", "--evidence", str(self.evidence)], cwd=ROOT,
                                                capture_output=True, text=True, check=False)
                self.assertEqual(config_command.returncode, 2, config_command.stderr)
                self.assertIn(f"the cargo configuration sets {entry}", config_command.stderr)
        self.write_runs()
        self.assertEqual(subprocess.run([sys.executable, "scripts/judge-genmc.py", "config", "--evidence", str(self.evidence)], cwd=ROOT,
                                        capture_output=True, text=True, check=False).returncode, 0)
        self.write_runs(config=None)
        (self.evidence / "cargo-config.json").unlink()
        report, _ = self.judge()
        self.assertIn("no recorded cargo configuration", report["reason"])
        self.write_runs(config="not json\n")
        report, _ = self.judge()
        self.assertIn("cargo configuration is unreadable", report["reason"])
        # The judge reports malformed evidence when nesting exceeds the JSON decoder's recursion limit.
        self.write_runs(config="[" * 100000)
        report, receipt = self.judge()
        self.assertEqual((report["code"], receipt["executed"]), (2, []), report)
        self.assertTrue(report["reason"].startswith("malformed evidence: RecursionError"), report)
        command = subprocess.run([sys.executable, "scripts/judge-genmc.py", "config", "--evidence", str(self.evidence)],
                                 cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(command.returncode, 2, command.stderr)
        self.assertTrue(command.stderr.startswith("judge-genmc: malformed evidence: RecursionError"), command.stderr)
        for config in ('{"build": 5}', '{"env": 5}', '{"env": [1, "A"]}', '{"env": []}', '{"build": null}'):
            with self.subTest(config=config):
                self.write_runs(config=config)
                report, receipt = self.judge()
                self.assertEqual((report["code"], receipt["executed"]), (2, []), report)
                key = next(iter(json.loads(config)))
                reason = f"malformed evidence: the recorded cargo configuration's {key} is not a table"
                self.assertEqual(report["reason"], reason)
                command = subprocess.run([sys.executable, "scripts/judge-genmc.py", "config", "--evidence", str(self.evidence)],
                                         cwd=ROOT, capture_output=True, text=True)
                self.assertEqual((command.returncode, command.stderr.strip()), (2, f"judge-genmc: {reason}"))

    def test_only_the_repository_lse_target_table_is_admitted(self):
        self.assertEqual(self.admit().returncode, 0)
        # The literal `cargo -Zunstable-options config get --format json` output in
        # verification/genmc/packages/kernels with the repository's .cargo/config.toml.
        self.write_runs(config=LSE_CONFIG)
        report, _ = self.judge()
        self.assertEqual((report["code"], report["verdict"]), (0, "credited"), report)
        for name, config, refused in lse_target_variants():
            with self.subTest(variant=name):
                self.write_runs(config=json.dumps(config))
                report, receipt = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertTrue(report["reason"].endswith(f"the cargo configuration sets {refused}"), report)
                self.assertEqual(receipt["executed"], [])

    def test_the_judged_identity_must_still_match_the_declaration(self):
        self.assertEqual(self.admit().returncode, 0)
        self.write_runs()
        report, _ = self.judge()
        self.assertEqual(report["verdict"], "credited", report)
        try:
            recorded = json.loads((self.evidence / "identity.json").read_text())
        except (OSError, ValueError) as error:
            self.fail(f"admission wrote no readable identity: {error}")
        for edit, reason in (
            (lambda i: i.update(upstream="0" * 40), "builds GenMC"),
            (lambda i: i["rustc"].update(commit="f" * 40), "rustc"),
            (lambda i: i["patches"].update({next(iter(i["patches"])): "e" * 64}), "patches other than the committed ones"),
            (lambda i: i["binary"].update(sha256="c" * 64), "genmc binary changed"),
            (lambda i: i["genmc_std"].update(tree="b" * 64), "genmc-std changed"),
            (lambda i: i["libllvm"].update(sha256="a" * 64), "libLLVM genmc loads changed"),
            (lambda i: i.pop("cxx"), "C++ compiler"),
            (lambda i: i["rustc"].update(sha256="9" * 64), "rustc binary changed"),
        ):
            with self.subTest(reason=reason):
                drifted = copy.deepcopy(recorded)
                edit(drifted)
                (self.evidence / "identity.json").write_text(json.dumps(drifted))
                report, _ = self.judge()
                self.assertEqual(report["code"], 2, report)
                self.assertIn(reason, report["reason"])
        (self.evidence / "identity.json").write_text(json.dumps(recorded))
        self.env["STUB_LDD_LIBLLVM"] = str(Path(self.temp.name) / "elsewhere.so")
        report, _ = self.judge()
        self.assertIn("genmc now loads", report["reason"])


PROVISION_STUBS = {
    "llvm-config-22": "#!/usr/bin/env bash\ncase $1 in --version) echo ${STUB_LLVM:-22.1.8} ;; --cmakedir) echo /llvm/cmake ;; esac\n",
    "clang-22": "#!/usr/bin/env bash\necho ${STUB_CLANG:-22.1.8}\n",
    "gcc-14": "#!/usr/bin/env bash\necho ${STUB_CC:-14}\n",
    "g++-14": "#!/usr/bin/env bash\necho ${STUB_CXX:-14}\n",
    "rustc": "#!/usr/bin/env bash\necho /nonexistent-sysroot\n",
    "git": "#!/usr/bin/env bash\nexit 1\n",
}


class ProvisionRecipe(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="kestrike-provision-")
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        stubs = base / "bin"
        stubs.mkdir()
        for name, body in PROVISION_STUBS.items():
            (stubs / name).write_text(body)
            (stubs / name).chmod(0o755)
        self.prefix = base / "prefix"
        self.env = {"PATH": f"{stubs}:/usr/bin:/bin", "NIGHTLY": "nightly-2026-07-27", "HOME": str(base)}

    def provision(self, **env):
        return subprocess.run(["bash", str(ROOT / "verification/genmc/provision.sh"), str(self.prefix)],
                              env={**self.env, **env}, capture_output=True, text=True, check=False, timeout=60)

    def test_the_checker_is_configured_without_ambient_compiler_flags(self):
        stubs = Path(self.env["PATH"].split(":")[0])
        (stubs / "git").write_text(
            "#!/usr/bin/env bash\n"
            'case " $* " in *" rev-parse "*) echo 9f6c4c0772d0c42b325681581acc6a0f3eb9b5f7 ;; esac\n'
        )
        (stubs / "cmake").write_text(
            "#!/usr/bin/env bash\n"
            'if [ "$1" = --build ]; then printf \'%s\\n\' "$@" > "$STUB_CMAKE_BUILD"; exit 0; fi\n'
            'printf \'%s\\n\' "$@" > "$STUB_CMAKE_ARGV"\n'
            'env | grep -E \'^(C|CXX|CPP|LD)FLAGS=|^CMAKE_\' > "$STUB_CMAKE_ENV" || true\n'
        )
        for name in ("git", "cmake"):
            (stubs / name).chmod(0o755)
        argv, env = Path(self.temp.name) / "cmake.argv", Path(self.temp.name) / "cmake.env"
        build = Path(self.temp.name) / "cmake.build"
        self.provision(CFLAGS="-O0", CXXFLAGS="-fsanitize=address -DNDEBUG", CPPFLAGS="-DTRACE", LDFLAGS="-Wl,-z,now",
                       CMAKE_TOOLCHAIN_FILE="/elsewhere/toolchain.cmake", STUB_CMAKE_ARGV=str(argv), STUB_CMAKE_ENV=str(env), STUB_CMAKE_BUILD=str(build))
        configure = argv.read_text().splitlines()
        self.assertEqual(configure[:4], ["-S", str(self.prefix / "src"), "-B", str(self.prefix / "build")], configure)
        self.assertLessEqual({
            "-DCMAKE_BUILD_TYPE=RelWithDebInfo", f"-DCMAKE_C_COMPILER={stubs}/gcc-14", f"-DCMAKE_CXX_COMPILER={stubs}/g++-14",
            "-DCMAKE_PREFIX_PATH=/llvm/cmake;/nonexistent-sysroot/bin", f"-DCLANGPATH={stubs}/clang-22",
            "-DCMAKE_C_FLAGS=", "-DCMAKE_CXX_FLAGS=", "-DCMAKE_EXE_LINKER_FLAGS=", "-DCMAKE_SHARED_LINKER_FLAGS=",
            "-DCMAKE_MODULE_LINKER_FLAGS=", "-DENABLE_RUST=ON",
        }, set(configure))
        self.assertEqual(env.read_text(), "")
        self.assertEqual(build.read_text().splitlines(), ["--build", str(self.prefix / "build"), "--parallel", "2"])

    def test_wrong_prerequisite_versions_fail_before_fetching_source(self):
        stubs = Path(self.env["PATH"].split(":")[0])
        calls = Path(self.temp.name) / "calls"
        (stubs / "git").write_text('#!/usr/bin/env bash\necho git >> "$STUB_CALLS"\nexit 1\n')
        for name in ("sudo", "apt-get", "dnf", "rustup"):
            (stubs / name).write_text(f'#!/usr/bin/env bash\necho {name} >> "$STUB_CALLS"\nexit 1\n')
            (stubs / name).chmod(0o755)
        for variable, value in (("STUB_LLVM", "22.1.7"), ("STUB_CLANG", "22.1.7"),
                                ("STUB_CC", "13"), ("STUB_CXX", "15")):
            with self.subTest(variable=variable):
                result = self.provision(**{variable: value}, STUB_CALLS=str(calls))
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse(calls.exists(), "provision changed prerequisites or fetched before checking versions")
        result = self.provision(STUB_CALLS=str(calls))
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(calls.read_text(), "git\n")

    def test_missing_llvm_fails_without_installing_packages(self):
        stubs = Path(self.env["PATH"].split(":")[0])
        (stubs / "llvm-config-22").unlink()
        for name in ("bash", "dirname", "mkdir"):
            (stubs / name).symlink_to(Path("/usr/bin") / name)
        result = self.provision(PATH=str(stubs))
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse((self.prefix / "src").exists())


if __name__ == "__main__":
    unittest.main()
