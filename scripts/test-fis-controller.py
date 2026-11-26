#!/usr/bin/env python3
"""Exercise fis-controller.py with a fake AWS CLI and a fake hardware lane."""

import argparse
import ast
import contextlib
import fcntl
import hashlib
import importlib.util
import io
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import unittest.mock
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts/fis-controller.py"
VOLUME = "vol-0123456789abcdef0"
# The PCI function the mappings fixture binds and each platform row's envelope declares.
BDF = "0000:00:1f.0"
# The controller requires a recognized platform row before making AWS calls or running cases.
os.environ["KESTRIKE_HARDWARE_PLATFORM"] = "x86_64-nitro-ebs"

AWS = textwrap.dedent('''\
    #!/usr/bin/env python3
    import json, os, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "aws.json").read_text())
    args = sys.argv[1:]
    with (state / "calls.log").open("a") as log:
        log.write(" ".join(args[:2]) + "\\n")
    # Every request is logged whole, so a test reads the volumes, IDs, filters and tokens each call named.
    with (state / "requests.log").open("a") as log:
        log.write(" ".join(args) + "\\n")
    with (state / "attempts.log").open("a") as log:
        log.write(args[1] + "=" + os.environ.get("AWS_MAX_ATTEMPTS", "-") + "\\n")
    service, verb = args[0], args[1]
    # FIS caps a client token at 64 characters and refuses a longer one as a validation error.
    if "--client-token" in args and len(args[args.index("--client-token") + 1]) > 64:
        sys.exit(254)
    if verb in plan.get("hang", {}):
        time.sleep(plan["hang"][verb])
    if verb in plan.get("hang_after_start", {}) and (state / "starts").exists():
        time.sleep(plan["hang_after_start"][verb])
    if (service, verb) == ("ec2", "describe-volumes"):
        describes = state / "describes"
        taken = int(describes.read_text()) + 1 if describes.exists() else 1
        describes.write_text(str(taken))
        if taken == plan.get("exit_case_at_describe"):
            (state / "exit-case").write_text("")
            time.sleep(1)
        if taken == plan.get("unmap_at_describe"):
            Path(os.environ["KESTRIKE_MAPPINGS"]).write_text("")
        if taken == plan.get("unlink_mappings_at_describe"):
            Path(os.environ["KESTRIKE_MAPPINGS"]).unlink()
        if taken == plan.get("plant_marker_symlink_at_describe"):
            (state / "custody").mkdir(exist_ok=True)
            (state / "elsewhere-marker").write_text("kept")
            (state / "custody" / "fis-e1.json").symlink_to(state / "elsewhere-marker")
        later = "volumes_later" in plan and taken >= plan.get("volumes_later_from", 2)
        volumes = plan["volumes_later"] if later else plan["volumes"]
        # `volumes_in` answers by the phase at the call's entry, even when readiness arrives during the call.
        if "volumes_in" in plan:
            readiness = lambda: any('"kind": "ready"' in path.read_text()
                                    for path in (state / "observer").glob("*.jsonl"))
            phase = ("started" if (state / "starts").exists() else "created" if (state / "creates").exists()
                     else "ready" if readiness() else "waiting" if (state / "lane-ran").exists() else "before")
            with (state / "describe-phases.log").open("a") as log:
                log.write(phase + "\\n")
            # `waiting_from` N plants the waiting answer, the mark and the hold from the Nth waiting-phase describe on.
            waited = (state / "describe-phases.log").read_text().split().count("waiting")
            planted = phase != "waiting" or waited >= plan.get("waiting_from", 1)
            if planted and phase == "waiting":
                (state / "waiting-describe").write_text("")
                held = time.monotonic() + 20
                while plan.get("hold_waiting") and not readiness() and time.monotonic() < held:
                    time.sleep(0.02)
                # A held describe logs whether the case's readiness released it, the premise of a test that plants
                # an answer at the one describe of the wait.
                if plan.get("hold_waiting"):
                    with (state / "describe-holds.log").open("a") as log:
                        log.write(("ready" if readiness() else "unready") + "\\n")
            answer = plan["volumes_in"].get(phase, volumes) if planted else volumes
            if answer == "fail":
                sys.exit(255)
            if isinstance(answer, dict) and "raw" in answer:
                print(answer["raw"])
                sys.exit(0)
            if isinstance(answer, dict):
                time.sleep(answer["hang"])
                answer = volumes
            with (state / "describe-replies.log").open("a") as log:
                log.write(phase + "\\n")
            volumes = answer
        print(json.dumps({"Volumes": volumes}))
    elif (service, verb) == ("fis", "create-experiment-template"):
        armed = list((state / "custody").glob("fis-*.json")) if (state / "custody").is_dir() else []
        (state / "armed-at-create").write_text(str(len(armed)))
        if armed:
            (state / "armed-text-at-create").write_text(json.loads(armed[0].read_text())["custody"])
        (state / "template.json").write_text(args[args.index("--cli-input-json") + 1])
        with (state / "create-tokens.log").open("a") as log:
            log.write((args[args.index("--client-token") + 1] if "--client-token" in args else "-") + "\\n")
        creates = state / "creates"
        taken = int(creates.read_text()) + 1 if creates.exists() else 1
        creates.write_text(str(taken))
        if taken <= plan.get("create_lost", 0):
            sys.exit(255)
        print(json.dumps({"experimentTemplate": {"id": 7 if taken <= plan.get("create_bad_id", 0) else "EXT1"}}))
    elif (service, verb) == ("fis", "start-experiment"):
        armed = list((state / "custody").glob("fis-*.json")) if (state / "custody").is_dir() else []
        (state / "armed-at-start").write_text(str(len(armed)))
        if armed:
            (state / "armed-text").write_text(json.loads(armed[0].read_text())["custody"])
        if not plan.get("start", True):
            sys.exit(254)
        with (state / "start-tokens.log").open("a") as log:
            log.write((args[args.index("--client-token") + 1] if "--client-token" in args else "-") + "\\n")
        with (state / "start-tags.log").open("a") as log:
            log.write((args[args.index("--tags") + 1] if "--tags" in args else "-") + "\\n")
        starts = state / "starts"
        taken = int(starts.read_text()) + 1 if starts.exists() else 1
        starts.write_text(str(taken))
        if not (state / "started").exists():
            (state / "started").write_text(str(time.time()))
        if taken <= plan.get("start_lost", 0):
            sys.exit(255)
        print(json.dumps({"experiment": {"id": 7 if taken <= plan.get("start_bad_id", 0) else "EXP1"}}))
    elif (service, verb) == ("fis", "get-experiment"):
        if args[args.index("--id") + 1] == "EXP0":
            print(json.dumps({"experiment": {"id": "EXP0", "state": {"status": "running"},
                                             "actions": {"fault": {"state": {"status": "running"}}}}}))
            sys.exit(0)
        started = float((state / "started").read_text())
        gets = state / "gets"
        taken = int(gets.read_text()) + 1 if gets.exists() else 1
        gets.write_text(str(taken))
        if taken <= plan.get("raw_first_gets", 0):
            print(plan["get_raw"])
            sys.exit(0)
        if taken <= plan.get("lost_first_gets", 0):
            sys.exit(255)
        if plan.get("lost") == "watch" or plan.get("lost") == "final" and time.time() - started > 0.5:
            sys.exit(255)
        if plan.get("lost") == "after_stop" and (state / "stopped").exists():
            gets = state / "gets-after-stop"
            taken = int(gets.read_text()) + 1 if gets.exists() else 1
            gets.write_text(str(taken))
            if taken > 1:
                sys.exit(255)
        if plan.get("flaky") and not (state / "flaked").exists():
            (state / "flaked").write_text("")
            sys.exit(255)
        ran = time.time() - started
        duration = plan.get("run_seconds")
        if plan.get("terminal_on_timeout") and any('"name": "timeout"' in path.read_text()
                                                   for path in (state / "observer").glob("*.jsonl")):
            # The experiment ends the moment the case's timeout is in the log, so the terminal poll follows it.
            duration = 0
        if duration is None:
            template = json.loads((state / "template.json").read_text())
            duration = int(template["actions"]["fault"]["parameters"]["duration"][2:-1])
        alarm = plan.get("alarm_at_seconds")
        if alarm is not None and ran > alarm and not (state / "stopped").exists():
            (state / "alarmed").write_text("")
            duration = alarm
        stopping = plan.get("stopping_seconds", 0)
        ended = (state / "stopped").exists() and time.time() - float((state / "stopped").read_text() or 0) >= stopping
        status = ("stopped" if ended
                  else "stopped" if (state / "alarmed").exists() and ran > alarm + plan.get("terminal_lag_seconds", 0)
                  else plan.get("final", "completed")
                  if ran > duration + plan.get("terminal_lag_seconds", 0)
                  or ((state / "done").exists() and not plan.get("stop_refused") and not plan.get("stop_lost"))
                  else "initiating" if ran < plan.get("initiating_seconds", 0) else "running")
        partial = plan.get("partial") or (plan.get("partial_on_terminal") and status in ("completed", "stopped"))
        action = ("failed" if partial else "pending" if status == "initiating"
                  else "running" if status == "running" and ran <= duration + plan.get("action_lag_seconds", 0)
                  else "completed")
        # The experiment carries the template's snapshot, as FIS reports it; `mutated` names fields another
        # principal's update changed before the start.
        shape = json.loads((state / "template.json").read_text()) if (state / "template.json").exists() else {}
        fault = dict(shape.get("actions", {}).get("fault", {}), state={"status": action})
        experiment = {"id": "EXP1", "state": {"status": status}, "startTime": "t0", "endTime": "t1",
                      "actions": {"fault": fault}, "targets": shape.get("targets", {}),
                      "roleArn": shape.get("roleArn"), "stopConditions": shape.get("stopConditions", [])}
        for field, value in plan.get("mutated", {}).items():
            if field == "actionId":
                fault["actionId"] = value
            elif field == "parameters":
                fault["parameters"] = dict(fault.get("parameters", {}), **value)
            elif field == "resourceArns":
                experiment["targets"] = {"Volumes": dict(shape["targets"]["Volumes"], resourceArns=value)}
            else:
                experiment[field] = value
        print(json.dumps({"experiment": experiment}))
    elif (service, verb) == ("fis", "stop-experiment"):
        stops = state / "stop-calls"
        asked = int(stops.read_text()) + 1 if stops.exists() else 1
        stops.write_text(str(asked))
        with (state / "stopped-ids.log").open("a") as log:
            log.write(args[args.index("--id") + 1] + "\\n")
        if plan.get("stop_refused") or (state / "alarmed").exists() or asked <= plan.get("stop_refusals", 0):
            sys.exit(254)
        if args[args.index("--id") + 1] == "EXP0":
            sys.exit(254)
        (state / "stopped").write_text(str(time.time()))
        if plan.get("stop_lost"):
            sys.exit(255)
        print(json.dumps({"experiment": {"id": "EXP1"}}))
    elif (service, verb) == ("fis", "list-experiments"):
        listings = state / "listings"
        taken = int(listings.read_text()) + 1 if listings.exists() else 1
        listings.write_text(str(taken))
        # `discovery_pages` answers the listing before the template's deletion the way `experiment_pages` answers it
        # after.
        pages = plan.get("experiment_pages") if (state / "template-deleted").exists() else plan.get("discovery_pages")
        if pages is not None:
            # The deleted template's listing in pages keyed by the starting token each request names, "" for the
            # first: a page lists `own` (the controller's experiment), `twin` (a second live experiment under the
            # controller's request tag) and `foreign` (another principal's, live) entries and the next page's token,
            # or fails, hangs or answers in another shape.
            flags = {"--next-token": "next", "--starting-token": "cli_next"}
            given = [flag for flag in flags if flag in args]
            token = args[args.index(given[0]) + 1] if given else ""
            with (state / "page-tokens.log").open("a") as log:
                log.write((token or "-") + "\\n")
            with (state / "page-times.log").open("a") as log:
                log.write(str(time.time()) + "\\n")
            if given and all(page.get(flags[given[0]]) != token for page in pages.values()):
                sys.exit(252)
            page = pages[token]
            time.sleep(page.get("sleep", 0))
            if page.get("fail"):
                sys.exit(255)
            if page.get("malformed"):
                print(json.dumps({"experiments": [{"state": {"status": "completed"}}]}))
                sys.exit(0)
            tags = (state / "start-tags.log").read_text().split() if (state / "start-tags.log").exists() else []
            own = dict([tags[0].split("=", 1)]) if tags and "=" in tags[0] else {}
            entries = {"own": {"id": "EXP1", "state": {"status": page.get("own_status", "completed")}, "tags": own},
                       "twin": {"id": "EXP2", "state": {"status": "running"}, "tags": own},
                       "foreign": {"id": "EXP0", "state": {"status": "running"}, "tags": {"request": "another"}}}
            listing = {"experiments": [entries[name] for name in page.get("experiments", [])]}
            if "next" in page:
                listing["nextToken"] = page["next"]
            if "cli_next" in page:
                listing["NextToken"] = page["cli_next"]
            print(json.dumps(listing))
            sys.exit(0)
        if plan.get("listed_malformed") and (state / "template-deleted").exists():
            print(json.dumps({"experiments": [{"state": {"status": "completed"}}]}))
            sys.exit(0)
        if taken <= plan.get("list_failures", 0):
            sys.exit(255)
        # `list_empty_first` N answers the first N listings empty, as a listing that lags an accepted start does.
        if taken <= plan.get("list_empty_first", 0):
            print(json.dumps({"experiments": []}))
            sys.exit(0)
        listed = plan.get("listed_status", "running")
        tags = (state / "start-tags.log").read_text().split() if (state / "start-tags.log").exists() else []
        own = dict([tags[0].split("=", 1)]) if tags and "=" in tags[0] else {}
        experiments = [{"id": "EXP1", "state": {"status": listed}, "tags": own}] if (state / "started").exists() else []
        if plan.get("listed_twins") and experiments:
            experiments.insert(0, {"id": "EXP0", "state": {"status": "running"}, "tags": {"request": "another"}})
        twin = plan.get("listed_twin_after_deletion")
        if twin and (state / "template-deleted").exists():
            status = twin if isinstance(twin, str) else "running"
            experiments.insert(0, {"id": "EXP0", "state": {"status": status}, "tags": {"request": "another"}})
        if plan.get("listed_without_own"):
            experiments = [found for found in experiments if found["id"] != "EXP1"]
        if plan.get("listed_foreign_only"):
            experiments = [{"id": "EXP0", "state": {"status": "completed"}, "tags": {"request": "another"}}]
        print(json.dumps({"experiments": experiments}))
    elif (service, verb) == ("fis", "list-experiment-templates"):
        template_listings = state / "template-listings"
        taken = int(template_listings.read_text()) + 1 if template_listings.exists() else 1
        template_listings.write_text(str(taken))
        if taken <= plan.get("list_templates_lost", 0):
            sys.exit(255)
        exists = (state / "template.json").exists() and not (state / "template-deleted").exists()
        exists = exists and taken > plan.get("template_visible_after_listings", 0)
        tags = json.loads((state / "template.json").read_text())["tags"] if exists else {}
        templates = [{"id": "EXT1", "tags": tags}] if exists else []
        if plan.get("stale_template"):
            templates.insert(0, {"id": "EXT0", "tags": {"episode": tags.get("episode", "e1"), "request": "earlier"}})
        listing = {"experimentTemplates": templates}
        if plan.get("templates_paged"):
            # A first page of other templates, with the rest behind a token the caller would have to follow.
            listing = {"experimentTemplates": [{"id": "EXT0", "tags": {}}], "nextToken": "more"}
        if plan.get("templates_cli_paged"):
            listing = {"experimentTemplates": [{"id": "EXT0", "tags": {}}], "NextToken": "more"}
        # `templates_tokens` adds continuation fields to the listing as given, a null one included.
        listing.update(plan.get("templates_tokens", {}))
        print(json.dumps(listing))
    elif (service, verb) == ("fis", "delete-experiment-template"):
        deletes = state / "deletes"
        taken = int(deletes.read_text()) + 1 if deletes.exists() else 1
        deletes.write_text(str(taken))
        with (state / "deleted-ids.log").open("a") as log:
            log.write(args[args.index("--id") + 1] + "\\n")
        if (state / "template-deleted").exists():
            sys.exit(254)
        if taken <= plan.get("delete_failures", 0):
            sys.exit(255)
        (state / "template-deleted").write_text("")
        if plan.get("delete_lost"):
            sys.exit(255)
        print(json.dumps({"experimentTemplate": {"id": "EXT1"}}))
    elif (service, verb) == ("ec2", "describe-volume-status"):
        samples = state / "status-samples"
        taken = int(samples.read_text()) + 1 if samples.exists() else 1
        samples.write_text(str(taken))
        status = "impaired" if taken <= plan.get("impaired_samples", 0) else plan.get("volume_status", "ok")
        if "status_raw" in plan:
            print(plan["status_raw"])
            sys.exit(0)
        requested = args[args.index("--volume-ids") + 1] if "--volume-ids" in args else None
        statuses = [] if plan.get("no_status") else [{"VolumeId": plan.get("status_volume", requested),
                                                      "VolumeStatus": {"Status": status}}]
        print(json.dumps({"VolumeStatuses": statuses}))
    else:
        sys.exit(2)
''')

LANE = textwrap.dedent('''\
    #!/usr/bin/env python3
    import hashlib, importlib.util, json, os, signal, sys, time
    from pathlib import Path
    state = Path(os.environ["FAKE_STATE"])
    plan = json.loads((state / "lane.json").read_text())
    # The merged lane sends no SIGTERM to a FIS case: a signal after readiness stops and holds the group, exit 4.
    held = {"ready": False}
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(4 if held["ready"] or plan.get("hold_before_ready") else 1))
    if plan.get("chatter_bytes"):
        sys.stdout.write("x" * plan["chatter_bytes"] + "\\n")
        sys.stdout.flush()
    open_files = [os.readlink(f"/proc/self/fd/{fd}") for fd in os.listdir("/proc/self/fd")
                  if os.path.exists(f"/proc/self/fd/{fd}")]
    (state / "lane-holds-reservation").write_text(str(any(f.endswith("custody/fis.lock") for f in open_files)))
    abandoned = lambda: Path(os.environ["KESTRIKE_FIS_ABANDONED"]).exists() and not plan.get("ignore_abandon")

    def settle():
        receipt = state / "lane-receipt.json"
        if "receipt_text" in plan:
            receipt.write_text(plan["receipt_text"])
            (state / "done").write_text("")
            (state / "settled").write_text("")
            print(f"receipt: {receipt}", file=sys.stderr)
            sys.exit(1)
        # A case abandoned after its test already failed under the fault reports that failure.
        failed = plan.get("failed_before_abandon")
        receipt.write_text(json.dumps({"hardware": {"credited": False, "first_failure": "case lacks witnesses",
                                                    "cases": [{"id": "case", "exit": 101 if failed else 0, "summary": [
                                                        "test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 1.00s"
                                                        if failed else
                                                        "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 1.00s"]}]}}))
        (state / "done").write_text("")
        (state / "settled").write_text("")
        print(f"receipt: {receipt}", file=sys.stderr)
        sys.exit(1)
    spec = importlib.util.spec_from_file_location("lane", os.environ["LANE_SCRIPT"])
    lane = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(lane)
    args = sys.argv[1:]
    value = lambda flag: args[args.index(flag) + 1]
    (state / "lane-ran").write_text(os.environ.get("KESTRIKE_FIS_TIMEOUT_US", ""))
    with (state / "launches.log").open("a") as log:
        log.write(value("--profile") + "/" + value("--role") + "\\n")
    (state / "lane-deadline").write_text(os.environ.get("KESTRIKE_FIS_DEADLINE_SECONDS", ""))
    observer = lane.Observer(value("--observer"), value("--episode"), value("--profile"), value("--role"))
    if plan.get("no_ready"):
        sys.exit(1)
    relayed = []
    for name in plan.get("pre_observe", []):
        relayed.append(observer.append("observed", frontier=True, name=name, detail="", case="case"))
    time.sleep(plan.get("ready_after_seconds", 0))
    begun = time.monotonic()
    while plan.get("ready_after_describe") and not (state / "waiting-describe").exists():
        if abandoned():
            settle()
        if time.monotonic() - begun > 20:
            sys.exit(3)
        time.sleep(0.02)
    # `setup_after_describe` keeps the case in its setup, deaf to the abandon mark, for that many seconds after the
    # controller's waiting-phase describe began.
    if "setup_after_describe" in plan:
        begun = time.monotonic()
        while not (state / "waiting-describe").exists() and time.monotonic() - begun < 20:
            time.sleep(0.02)
        time.sleep(plan["setup_after_describe"])
        (state / "setup-ended").write_text(str(time.time()))
    observer.append("ready", case="case")
    held["ready"] = True
    if plan.get("exit_after_ready"):
        sys.exit(1)
    if plan.get("die_after_ready"):
        os.kill(os.getpid(), signal.SIGKILL)
    begun = time.monotonic()
    # KESTRIKE_FIS_STARTED gates the observations on the controller's fault-start mark; observe_on_started
    # gates them on the fake AWS accepting the start instead.
    started = (lambda: (state / "started").exists()) if plan.get("observe_on_started") else (
        lambda: Path(os.environ["KESTRIKE_FIS_STARTED"]).exists())
    while not started():
        if abandoned():
            settle()
        if (state / "exit-case").exists():
            sys.exit(1)
        if time.monotonic() - begun > 20:
            sys.exit(3)
        time.sleep(0.05)
    if plan.get("observe_on_started"):
        time.sleep(0.2)
    # Another lane role sharing the episode's log appends its own observations, which are no witness for this case.
    other = lane.Observer(value("--observer"), value("--episode"), value("--profile"), "other")
    for name in plan.get("foreign_observe", []):
        other.append("observed", name=name, detail="", after={}, case="other-case")
    linger = time.monotonic() + plan.get("linger_seconds", 0)
    while time.monotonic() < linger:
        if abandoned():
            settle()
        time.sleep(0.02)
    for name in plan.get("observe", []):
        if name in plan.get("after_end", ["restored"]):
            ended = Path(os.environ["KESTRIKE_FIS_ENDED"])
            begun = time.monotonic()
            while not ended.exists() and time.monotonic() - begun < 20:
                if abandoned():
                    settle()
                time.sleep(0.05)
            if ended.exists():
                samples = state / "status-samples"
                (state / "lane-saw-ended-after-status-samples").write_text(samples.read_text() if samples.exists() else "0")
        wait = plan.get("after_started_seconds", {}).get(name)
        if wait is not None:
            begun = float((state / "started").read_text())
            while time.time() - begun < wait:
                time.sleep(0.02)
        relayed.append(observer.append("observed", frontier=True, name=name, detail="", case="case"))
        pause = time.monotonic() + plan.get("seconds", 0.2)
        while time.monotonic() < pause:
            if abandoned():
                settle()
            time.sleep(0.02)
    receipt = state / "lane-receipt.json"
    summary = ("test result: FAILED. 0 passed; 1 failed; 0 ignored; 0 measured; 9 filtered out; finished in 1.00s"
               if plan.get("failed") else
               "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out; finished in 1.00s")
    # The receipt is the one a lane run of the declared case writes on a host inside its platform row's envelope,
    # so the hardware judge can validate it; the plan's `case` and `receipt` maps replace its fields.
    text = Path(value("--manifest")).read_bytes()
    manifest = json.loads(text)
    profile = manifest["profiles"][value("--profile")]
    row = os.environ["KESTRIKE_HARDWARE_PLATFORM"]
    approved = manifest["platforms"][row]
    declared = profile["roles"][value("--role")]["cases"][0]
    executable = str(state / "kestrike-fake")
    inputs = {name: os.environ[name] for name in declared["inputs"] if name in os.environ}
    case = {"id": declared["id"], "listed": 1, "ignored": 1, "executed": 1, "seconds": 1.0,
            "command": [executable, *lane.case_arguments(declared)], "inputs": inputs,
            "mappings": lane.mappings_facts(inputs), "witness_counts": {witness: 1 for witness in declared["witnesses"]},
            "missing_witnesses": [], "observed": relayed}
    case.update({"exit": -6, "summary": []} if plan.get("aborted") else
                {"exit": 101 if plan.get("failed") else 0, "summary": [summary]})
    case.update(plan.get("case", {}))
    hardware = {
        "profile": value("--profile"), "role": value("--role"), "episode": value("--episode"),
        "revision": lane.git_revision(), "manifest_sha256": hashlib.sha256(text).hexdigest(),
        "platform": {"row": row, **approved},
        "host": {**{field: approved["envelope"][field] for field in lane.OBSERVED}, "machine": approved["machine"]},
        "dirty": False, "untracked": [], "artifacts": "artifacts",
        "toolchain": {"rustc": "rustc 1.99.0 (fake)", "cargo": "cargo 1.99.0 (fake)"}, "dependencies": ["libc 0.2.0"],
        "build_environment": {}, "executable": {"path": executable, "sha256": "0" * 64}, "attempts_allowed": 1,
        "retries": 0, "credited": plan.get("credited", True), "first_failure": plan.get("first_failure"),
        "cases": plan.get("cases", [case])}
    hardware.update(plan.get("receipt", {}))
    for name in plan.get("drop", []):
        hardware.pop(name)
    receipt.write_text(plan.get("receipt_text") or json.dumps({"envelope": lane.ENVELOPE, "hardware": hardware}))
    if plan.get("corrupt_manifest"):
        Path(value("--manifest")).write_text(plan["corrupt_manifest"])
    (state / "done").write_text("")
    if not plan.get("no_receipt"):
        print(f"receipt: {receipt}", file=sys.stderr)
    sys.exit(plan.get("exit", 0))
''')

DISPOSABLE = [{"Key": "disposable", "Value": "true"}]


def script_module(name):
    """The module of `scripts/<name>.py`, loaded from its file."""
    spec = importlib.util.spec_from_file_location(name.replace("-", "_"), ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise RuntimeError(f"scripts/{name}.py cannot be loaded")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def lane_module():
    return script_module("hardware-lane")


def approved_envelope(lane, machine):
    """A complete envelope for a platform row of `machine`: a placeholder for each field, in the shapes the manifest
    check requires, with `BDF` the one PCI function it declares."""
    return {**{field: f"test {field}" for field in lane.ENVELOPE_FIELDS}, "cpu_features": ["fpu"],
            "cpu_family": {line: f"test {line}" for line in lane.reproducer.IDENTITY_LINES[machine]},
            "devices": {BDF: "0x1d0f:0x8061"}}


def volume(**changes):
    described = {"VolumeId": VOLUME, "VolumeType": "gp3", "Tags": DISPOSABLE,
                 "Attachments": [{"InstanceId": "i-1", "State": "attached"}]}
    described.update(changes)
    return described


class Controller(unittest.TestCase):
    def setUp(self):
        self.host_custody_existed = Path("/var/tmp/kestrike-hardware-custody").exists()
        self.temp = tempfile.TemporaryDirectory(prefix="fis-controller-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        for name, text in (("aws", AWS), ("lane", LANE)):
            (self.state / name).write_text(text)
            (self.state / name).chmod(0o755)
        (self.state / "mappings").write_text(f"format=3\nnvme.volume={VOLUME}\nnvme.bdf={BDF}\n")
        # The cases run under the hardware manifest with each platform row supported under a complete envelope. The
        # fake lane records a host inside that envelope, so a judge-valid receipt credits here.
        lane = lane_module()
        hardware = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())
        for row in hardware["platforms"].values():
            row.update(supported=True, envelope=approved_envelope(lane, row["machine"]))
        self.hardware_manifest = self.state / "hardware-profiles.json"
        self.hardware_manifest.write_text(json.dumps(hardware))
        self.operator = {"account": "111122223333", "region": "us-east-1", "role_arn": "arn:aws:iam::1:role/fis",
                         "volumes": [VOLUME], "attachments": {VOLUME: ["i-1"]}, "effect_timeout_seconds": 2,
                         "stop_alarms": []}
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})

    def plan(self, aws=None, lane=None):
        if aws is not None:
            (self.state / "aws.json").write_text(json.dumps(aws))
        if lane is not None:
            (self.state / "lane.json").write_text(json.dumps(lane))

    def manifest(self, **changes):
        manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        self.loaded = manifest
        for profile in manifest["profiles"].values():
            profile.update(changes)
        path = self.state / "fis-profiles.json"
        path.write_text(json.dumps(manifest))
        return path

    def run_episode(self, profile="fis-read-latency", command="episode", manifest=None, keep_observer=False,
                    aws_seconds=None, episode="e1", keep_custody=False, extra=(), environ=None):
        if not keep_observer:
            shutil.rmtree(self.state / "observer", ignore_errors=True)
        if not keep_custody:
            shutil.rmtree(self.state / "custody", ignore_errors=True)
        for marker in ("done", "stopped", "flaked", "started", "status-samples", "listings", "alarmed", "describes",
                       "starts", "start-tokens.log", "deletes", "creates", "create-tokens.log", "template-deleted",
                       "gets-after-stop", "lane-deadline", "settled", "deleted-ids.log", "exit-case",
                       "template-listings", "lane-saw-ended-after-status-samples", "armed-at-start", "stop-calls",
                       "lane-holds-reservation", "start-tags.log", "gets", "armed-at-create", "armed-text",
                       "armed-text-at-create", "page-tokens.log", "page-times.log", "lane-ran", "waiting-describe",
                       "describe-phases.log", "describe-replies.log", "attempts.log", "launches.log",
                       "stopped-ids.log", "describe-holds.log", "setup-ended"):
            (self.state / marker).unlink(missing_ok=True)
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), command, "--operator", str(self.state / "operator.json"),
                "--artifacts", str(self.state / "artifacts"), "--observer", str(self.state / "observer"),
                "--episode", episode, "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--poll", "0.05", "--manifest", str(manifest or self.manifest(duration_seconds=1)),
                "--custody", str(self.state / "custody"), "--hardware-manifest", str(self.hardware_manifest)]
        argv += ["--aws-seconds", str(aws_seconds)] if aws_seconds is not None else []
        argv += list(extra)
        argv += ["--profile", profile] if command == "episode" else ["--profiles", profile]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"), **(environ or {}))
        done = subprocess.run(argv, env=env, capture_output=True, text=True, timeout=120, check=False)
        receipt = next((line.split(": ", 1)[1] for line in done.stderr.splitlines() if line.startswith("receipt: ")),
                       None)
        section: dict = json.loads(Path(receipt).read_text())["fis"] if receipt else {}
        return done.returncode, done.stdout + done.stderr, section

    def readiness_grade(self, rewrite=None, pinned=None):
        """The readiness judge's grade and reason for the episode receipt and the lane receipt the last run wrote,
        under the manifests that run used, or under the fault-injection manifest bytes `pinned`; `rewrite` edits
        the episode's section first."""
        path = self.state / "artifacts" / "fis-fis-read-latency-e1.json"
        receipt = json.loads(path.read_text())
        if rewrite:
            receipt["fis"].update(rewrite)
            path.write_text(json.dumps(receipt))
        lane_receipt = receipt["fis"]["lane_receipt"]
        revision = json.loads(Path(lane_receipt).read_text())["hardware"]["revision"]
        readiness = script_module("readiness")
        judges = readiness.Judges({"acceptance_ctx": None, "log": None, "fis": self.loaded, "files": {
            "hardware_profiles_sha256": self.hardware_manifest.read_bytes(),
            "fis_profiles_sha256": pinned or (self.state / "fis-profiles.json").read_bytes()}}, lane_module())
        graded = readiness.fis_grade(judges.fis("fis-read-latency", {"episode": str(path), "lane": lane_receipt},
                                                revision), revision)
        return graded["grade"], graded["reason"]

    def tearDown(self):
        # Every run passes --custody under the fake state; the host's directory is the sweep's, left as found.
        self.assertEqual(Path("/var/tmp/kestrike-hardware-custody").exists(), self.host_custody_existed,
                         "a test touched the host's custody directory; pass --custody under the fake state")
        self.assertEqual(self.undocumented(), [], "the controller sent a request outside its documented ones")

    def calls(self):
        log = self.state / "calls.log"
        return log.read_text().splitlines() if log.exists() else []

    def test_a_target_the_contract_refuses_is_invalid_before_any_injection(self):
        cases = {
            "empty": ({"volumes": []}, None, "empty target list"),
            "unexpected": ({"volumes": ["vol-other"]}, None, "unexpected targets"),
            "ineligible": ({}, [volume(VolumeType="unlisted")], "ineligible"),
            "non-disposable": ({}, [volume(Tags=[])], "not tagged disposable"),
            "multi-attach": ({"attachments": {VOLUME: ["i-1", "i-2"]}},
                             [volume(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                  {"InstanceId": "i-2", "State": "attached"}])],
                             "single-attachment profile"),
            "detaching": ({}, [volume(Attachments=[{"InstanceId": "i-1", "State": "detaching"}])], "not attached"),
            "attaching": ({}, [volume(Attachments=[{"InstanceId": "i-1", "State": "attaching"}])], "not attached"),
            "unstated attachment": ({}, [volume(Attachments=[{"InstanceId": "i-1"}])], "not attached"),
            "busy": ({}, [volume(Attachments=[{"InstanceId": "i-1", "State": "busy"}])], "not attached"),
            "detached": ({}, [volume(Attachments=[{"InstanceId": "i-1", "State": "detached"}])], "not attached"),
            "undeclared attachment": ({"attachments": {VOLUME: []}}, None, "not the declared set"),
            "absent attachment": ({}, [volume(Attachments=[])], "not the declared set"),
            "multi-attach enabled": ({}, [volume(MultiAttachEnabled=True)], "Multi-Attach"),
        }
        base = dict(self.operator)
        for name, (operator, volumes, reason) in cases.items():
            with self.subTest(name):
                self.operator = {**base, **operator}
                self.plan(aws={"volumes": volumes or [volume()]})
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was injected")
                self.assertFalse((self.state / "lane-ran").exists(), "the case never started")

    def test_a_credited_lane_receipt_holds_only_when_the_judge_validates_it_under_the_launched_identity(self):
        mappings = {"path": str(self.state / "mappings"), "sha256": "0" * 64, "format": "3"}
        cases = {
            "a credited flag beside a lacking witness": ({"case": {"witness_counts": {}}}, "lacks witnesses"),
            "a credited flag beside a failed exit": ({"case": {"exit": 101}}, "exited 101"),
            "another episode": ({"receipt": {"episode": "e9"}}, "names episode 'e9', not the launched 'e1'"),
            "another revision": ({"receipt": {"revision": "f" * 40}}, f"names revision '{'f' * 40}', not the launched"),
            "another profile": ({"receipt": {"profile": "fis-write"}}, "names profile 'fis-write', not the launched 'fis-read'"),
            "another role": ({"receipt": {"role": "client"}}, "names role 'client', not the launched 'owner'"),
            "other mappings": ({"case": {"mappings": mappings}}, f"records mappings [{mappings!r}], not the launched"),
            "no identity": ({"drop": ["profile", "role", "episode", "revision"]}, "names profile None, not the launched"),
        }
        for name, (lane, reason) in cases.items():
            with self.subTest(name):
                self.plan(lane={"observe": ["timeout", "restored"], **lane})
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn("the hardware judge rejects the case's lane receipt: ", section["first_failure"])
                self.assertIn(reason, section["first_failure"])
                self.assertFalse(section["release_proof"], "a rejected receipt never reaches the witnessed path")
                self.assertFalse({"hardware_manifest", "lane_receipt_sha256", "profile_sha256",
                                  "fis_profiles_sha256"} & set(section),
                                 "a rejected receipt names no binding of a credited one")
        # A hardware manifest that cannot be parsed or checked once the case ended leaves the case uncredited with
        # that reason.
        valid = self.hardware_manifest.read_bytes()
        for name, text in (("unparsed", "{"), ("malformed", "{}")):
            with self.subTest(f"an {name} hardware manifest"):
                self.hardware_manifest.write_bytes(valid)
                self.plan(lane={"observe": ["timeout", "restored"], "corrupt_manifest": text})
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(f"cannot be judged against the hardware manifest {self.hardware_manifest}: ",
                              section["first_failure"])
                self.assertFalse(section["release_proof"])

    def test_an_episode_with_its_timeout_restoration_and_credited_case_holds(self):
        self.plan(aws={"volumes": [volume()], "initiating_seconds": 0.5})
        # The receipt names the hardware manifest by its resolved path. The manifest is reached through a symlink and
        # the state directory can also be symlinked, so the expected path resolves both.
        manifest, self.hardware_manifest = self.hardware_manifest, self.state / "hardware-link.json"
        self.hardware_manifest.symlink_to(manifest)
        code, out, section = self.run_episode()
        self.assertEqual(code, 0, out)
        self.assertEqual((section["verdict"], section["status"], section["experiment_id"]), ("HELD", "COMPLETED", "EXP1"))
        self.assertEqual(section["attachment"], "single", "the receipt names the profile's attachment mode")
        self.assertTrue(section["release_proof"], "restored bytes after the fault ended are the release proof")
        self.assertEqual(section["hardware_manifest"], {
            "path": str(manifest.resolve()), "sha256": hashlib.sha256(manifest.read_bytes()).hexdigest()})
        lane_receipt = json.loads(Path(section["lane_receipt"]).read_text())["hardware"]
        self.assertEqual(lane_receipt["revision"], subprocess.run(["git", "-C", str(ROOT), "rev-parse", "HEAD"],
                                                                  capture_output=True, text=True).stdout.strip())
        # The credited episode names the lane receipt bytes its credit was judged from and the profile row it ran, by
        # the digests the readiness judge compares, and that judge verifies the episode from the two files as written.
        self.assertEqual((section["lane_receipt_sha256"], section["profile_sha256"]),
                         (hashlib.sha256(Path(section["lane_receipt"]).read_bytes()).hexdigest(),
                          script_module("measurement-frame").canonical(self.loaded["profiles"]["fis-read-latency"])))
        self.assertEqual(self.readiness_grade(), ("VERIFIED", "the episode reads HELD"))
        # The episode also names the fault-injection manifest file it ran under, by its bytes. The controller admits
        # targets by that file's top-level fields, so a judge pinned to a file with the same profile row and another
        # eligible-types list reads the episode STALE.
        ran = (self.state / "fis-profiles.json").read_bytes()
        self.assertEqual(section["fis_profiles_sha256"], hashlib.sha256(ran).hexdigest())
        relaxed = json.loads(ran)
        relaxed["eligible_types"][relaxed["profiles"]["fis-read-latency"]["action"]].append("unlisted")
        grade, reason = self.readiness_grade(pinned=json.dumps(relaxed).encode())
        self.assertEqual(grade, "STALE", reason)
        self.assertIn("ran under fault-injection manifest", reason)
        # The credited receipt names the mappings file the controller supplied, by its own bytes.
        mappings = self.state / "mappings"
        facts = lane_module().mappings_facts({"KESTRIKE_MAPPINGS": str(mappings)})
        self.assertEqual((facts["path"], facts["sha256"], facts["format"]),
                         (str(mappings), hashlib.sha256(mappings.read_bytes()).hexdigest(), "3"))
        self.assertEqual(json.loads(Path(section["lane_receipt"]).read_text())["hardware"]["cases"][0]["mappings"], facts)
        self.assertEqual(section["first_timeout"]["name"], "timeout")
        self.assertGreater(section["first_timeout"]["ordinal"], section["effect_window"]["start_ordinal"])
        self.assertFalse((self.state / "artifacts" / "fis-e1.started").exists(), "the start mark is cleared after the case")
        self.assertIsNone(section["abort"])
        self.assertIn("fis delete-experiment-template", self.calls())
        window = section["effect_window"]
        self.assertEqual((window["start_time"], window["end_time"]), ("t0", "t1"))
        self.assertLess(window["start_ordinal"], window["end_ordinal"])
        self.assertEqual((self.state / "lane-ran").read_text(), "1000000", "the case's timeout sits below the delay")
        template = json.loads((self.state / "template.json").read_text())
        fault = template["actions"]["fault"]
        self.assertEqual(fault["actionId"], "aws:ebs:volume-io-latency")
        self.assertEqual(fault["parameters"]["readIOLatencyMilliseconds"], "2000")
        self.assertEqual(fault["parameters"]["writeIOPercentage"], "0.1", "the action's least percentage")
        self.assertEqual(fault["parameters"]["writeIOLatencyMilliseconds"], "10", "the action's least latency")
        self.assertEqual(template["targets"]["Volumes"]["resourceArns"],
                         [f"arn:aws:ec2:us-east-1:111122223333:volume/{VOLUME}"])

    def test_an_injection_without_a_timeout_after_the_fault_started_is_incomplete_and_its_abort_proves_no_release(self):
        for name, lane in {"no timeout": {"observe": ["restored"]},
                           "timeout before the fault": {"pre_observe": ["timeout"], "observe": ["restored"]}}.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()], "run_seconds": 100}, lane=lane)
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn("without an observed timeout", section["first_failure"])
                self.assertEqual(section["abort"], "stopped", "the stop was issued and the experiment seen ended")
                self.assertFalse(section["release_proof"])
                calls = self.calls()
                self.assertIn("fis stop-experiment", calls)
                self.assertGreater(len(calls) - 1 - calls[::-1].index("fis get-experiment"),
                                   calls.index("fis stop-experiment"),
                                   "the controller polled the experiment after asking it to stop")

    def test_a_timeout_the_case_observes_while_the_experiment_initiates_earns_no_credit(self):
        self.plan(aws={"volumes": [volume()], "initiating_seconds": 1.0, "run_seconds": 100},
                  lane={"observe": ["timeout", "restored"], "observe_on_started": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("without an observed timeout", section["first_failure"])
        self.assertNotIn("first_timeout", section)

    def test_an_early_stop_the_case_proves_halts_the_experiment_and_holds(self):
        """The ten-second duration leaves the stop, proven about a second after the mark, well inside the bound
        on a loaded runner; the controller's early stop still ends the fake experiment."""
        self.plan(lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual(code, 0, out)
        self.assertEqual((section["verdict"], section["status"], section["abort"]), ("HELD", "HALTED", "stopped"))
        self.assertTrue(section["release_proof"], "a stop proven under the fault is the release proof")
        template = json.loads((self.state / "template.json").read_text())
        self.assertEqual(template["actions"]["fault"]["actionId"], "aws:ebs:pause-volume-io")

    def test_a_stop_the_case_proves_only_after_the_fault_ended_earns_no_credit(self):
        self.plan(lane={"observe": ["timeout", "stop"], "after_end": ["stop"]})
        code, out, section = self.run_episode(profile="fis-family-stop")
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "COMPLETED"), out)
        self.assertIn("proven stop", section["first_failure"])
        self.assertIsNone(section["abort"], "the experiment completed on its own")

    def test_a_stop_proven_after_the_action_ended_but_before_its_terminal_report_earns_no_credit(self):
        """The action ends at two seconds and the experiment reports completed two seconds later; a stop the
        case proves between them came after I/O resumed, so the controller credits no stop under the fault."""
        self.plan(aws={"volumes": [volume()], "terminal_lag_seconds": 2},
                  lane={"observe": ["timeout", "stop"], "after_started_seconds": {"stop": 2.5}})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=2))
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "COMPLETED"), out)
        self.assertIn("proven stop", section["first_failure"])
        self.assertIsNone(section["abort"], "no stop was issued for a stop proven after the action ended")

    def test_a_stop_proven_while_the_api_still_reports_the_ended_action_running_earns_no_credit(self):
        """The pause cannot lift before the start request plus the declared duration; a stop proven after that
        point is not under the fault even while the API still reports the action running."""
        self.plan(aws={"volumes": [volume()], "action_lag_seconds": 1.5, "terminal_lag_seconds": 1.5},
                  lane={"observe": ["timeout", "stop"], "after_started_seconds": {"stop": 2.5}})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=2))
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "COMPLETED"), out)
        self.assertIn("proven stop", section["first_failure"])
        self.assertIsNone(section["abort"])

    def test_an_experiment_a_stop_condition_ended_earns_no_credit(self):
        self.plan(aws={"volumes": [volume()], "final": "stopped"}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "HALTED"), out)
        self.assertIn("stop condition", section["first_failure"])

    def test_a_stop_proven_after_an_alarm_lifted_the_fault_early_earns_no_credit(self):
        """An operator alarm lifts the fault one second in, inside the declared ten-second duration, while the API
        keeps reporting the action running for two more seconds. The stop the case proves at 1.4 s passes the
        bound and the fresh check, so the controller credits it and asks for a stop, which FIS refuses because
        the experiment already ended; the stopped terminal state then withdraws the credit and leaves the
        fault's end confirmed."""
        self.operator["stop_alarms"] = ["arn:aws:cloudwatch:us-east-1:111122223333:alarm:stalled"]
        self.plan(aws={"volumes": [volume()], "alarm_at_seconds": 1.0, "terminal_lag_seconds": 2.0,
                       "action_lag_seconds": 2.0},
                  lane={"observe": ["timeout", "stop"], "after_started_seconds": {"stop": 1.4}, "seconds": 2.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "HALTED"), out)
        self.assertIn("stop condition", section["first_failure"])
        self.assertEqual(section["abort"], "refused", "the controller's own stop came after the alarm's")
        self.assertIn("fis stop-experiment", self.calls())
        self.assertNotIn("stop_under_fault", section)
        self.assertFalse(section["release_proof"])
        self.assertNotIn("fault_end_unconfirmed", section, "the terminal state was observed")

    def test_a_case_that_aborted_under_the_fault_is_disproven(self):
        self.plan(lane={"observe": ["timeout"], "credited": False, "aborted": True, "exit": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "DISPROVEN"), out)
        self.assertIn("died by signal 6", section["first_failure"])

    def test_a_timeout_appended_just_before_the_terminal_poll_still_counts(self):
        """The case appends its timeout after the last poll that saw the action running and before the poll that
        sees the experiment ended: the timeout followed the fault's start, so the episode reads it and holds."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "terminal_on_timeout": True},
                  lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(manifest=self.manifest(duration_seconds=1))
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertIn("first_timeout", section)

    def test_an_experiment_that_ends_before_any_timeout_is_recorded_from_that_terminal_state(self):
        """An alarm ends the experiment half a second in, before the case observes a timeout; the controller
        records the terminal state it saw, issues no stop of its own, and leaves the fault's end confirmed."""
        self.plan(aws={"volumes": [volume()], "alarm_at_seconds": 0.5}, lane={"observe": ["restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "HALTED"), out)
        self.assertIn("ended stopped before", section["first_failure"])
        self.assertNotIn("fis stop-experiment", self.calls(), "no stop was issued for an experiment seen ended")
        self.assertNotIn("fault_end_unconfirmed", section)
        self.assertIsNone(section["abort"])

    def test_a_target_that_changes_during_the_readiness_wait_is_refused_before_injection(self):
        """The targets are described again once the case is ready and once more after the template is created;
        a volume that lost its disposable tag by the last check is INVALID and nothing is injected."""
        self.plan(aws={"volumes": [volume()], "volumes_later": [volume(Tags=[])], "volumes_later_from": 3})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("not tagged disposable", section["first_failure"])
        calls = self.calls()
        self.assertEqual(calls.count("ec2 describe-volumes"), 3)
        self.assertNotIn("fis start-experiment", calls)
        self.assertLess(calls.index("fis create-experiment-template"), len(calls) - 1 - calls[::-1].index("ec2 describe-volumes"),
                        "the second description follows the template's creation, right before the start")
        self.assertIn("fis delete-experiment-template", calls, "the created template is deleted")
        self.assertGreater(calls.index("fis list-experiments"), calls.index("fis delete-experiment-template"),
                           "no start was requested, so nothing is discovered; the deleted template's listing follows")
        self.assertNotIn("fis stop-experiment", calls)
        self.assertIsNone(section["abort"])
        self.assertNotIn("fault_end_unconfirmed", section)
        self.assertTrue((self.state / "lane-ran").exists(), "the case had started")
        self.assertEqual(section["case_exit"], 1, "the abandoned case settled and exited through the lane")
        self.assertTrue((self.state / "settled").exists())

    def test_a_standard_volume_runs_the_latency_profiles(self):
        self.plan(aws={"volumes": [volume(VolumeType="standard")]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)

    def test_the_disabled_direction_takes_the_target_type_s_least_latency(self):
        """An io2 volume admits 1 ms, so a read-only 1 ms profile's write side carries 1 ms at the least percentage, the
        slightest fault the action allows on that volume; a stronger write fault could trip the timeout under test."""
        self.plan(aws={"volumes": [volume(VolumeType="io2")]})
        code, out, section = self.run_episode(manifest=self.manifest(duration_seconds=1, latency_ms=1))
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        parameters = json.loads((self.state / "template.json").read_text())["actions"]["fault"]["parameters"]
        self.assertEqual((parameters["readIOLatencyMilliseconds"], parameters["writeIOPercentage"],
                          parameters["writeIOLatencyMilliseconds"]), ("1", "0.1", "1"))

    def test_a_volume_status_that_lags_the_experiment_is_polled_to_ok_before_the_fault_end_mark(self):
        """The case reads at normal latency once the fault-end mark appears, so the mark follows the volume's
        restoration: every status sample is taken before the mark, and an impaired volume gets no mark."""
        self.plan(aws={"volumes": [volume()], "impaired_samples": 3})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertGreaterEqual(self.calls().count("ec2 describe-volume-status"), 4)
        self.assertEqual(int((self.state / "lane-saw-ended-after-status-samples").read_text()), 4,
                         "the case saw the mark after the fourth sample read ok")
        self.plan(aws={"volumes": [volume()], "volume_status": "impaired"})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertNotIn("end_ordinal", section["effect_window"], "an impaired volume gets no fault-end mark")
        self.assertIn("case_exit", section, "cleanup abandoned the case")

    def test_a_case_without_restored_bytes_or_a_receipt_or_readiness_earns_no_credit(self):
        cases = {
            "no restored bytes": ({"observe": ["timeout"]}, "no restored bytes after the fault ended or proven stop"),
            "no lane receipt": ({"observe": ["timeout", "restored"], "no_receipt": True}, "no readable lane receipt"),
            "no readiness": ({"no_ready": True}, "before its readiness"),
        }
        for name, (lane, reason) in cases.items():
            with self.subTest(name):
                self.plan(lane=lane)
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(reason, section["first_failure"])

    def test_an_inconclusive_episode_rewritten_to_held_earns_no_readiness_credit(self):
        # Each run ends COMPLETED and INCONCLUSIVE with a credited lane receipt, since no restored bytes followed the
        # fault's end. The planted mutation rewrites the episode receipt to HELD with a release proof and, in the
        # second case, moves the fault window's end below the early restored event. The readiness judge reads the
        # fault window from the events the lane receipt records, so neither rewrite verifies.
        cases = {
            "no restored bytes": ({"observe": ["timeout"]}, lambda window: window),
            "restored before the fault ended": ({"observe": ["timeout", "restored"], "after_end": []},
                                                lambda window: {**window, "end_ordinal": window["start_ordinal"]}),
        }
        for name, (lane, moved) in cases.items():
            with self.subTest(name):
                self.plan(lane=lane)
                code, out, section = self.run_episode()
                self.assertEqual((code, section["status"], section["verdict"], section["release_proof"]),
                                 (1, "COMPLETED", "INCONCLUSIVE", False), out)
                self.assertIn("no restored bytes after the fault ended", section["first_failure"])
                self.assertEqual(self.readiness_grade(), ("UNVERIFIED", "the episode reads INCONCLUSIVE"))
                grade, reason = self.readiness_grade({"verdict": "HELD", "release_proof": True, "first_failure": None,
                                                      "effect_window": moved(section["effect_window"])})
                self.assertEqual(grade, "UNVERIFIED", reason)
                self.assertIn("fault window", reason)

    def test_a_case_that_fails_under_the_fault_before_its_restoration_is_disproven(self):
        self.plan(lane={"observe": ["timeout"], "credited": False, "failed": True, "exit": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "DISPROVEN"), out)
        self.assertIn("uncredited", section["first_failure"])

    def test_a_case_that_fails_under_a_partial_fault_leaves_the_row_invalid(self):
        """The action reports partial injection after the fault ran, and the case's test fails too: a fault that did
        not satisfy the profile qualifies nothing, so INVALID stands over the case's failure."""
        self.plan(aws={"volumes": [volume()], "partial_on_terminal": True},
                  lane={"observe": ["timeout", "restored"], "failed_before_abandon": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(section["case_exit"], 1, "the abandoned case reported its failed test")
        self.assertIn("partially", section["first_failure"])
        self.assertNotIn("diagnostic", section)

    def test_the_armed_marker_names_the_token_the_start_carries(self):
        """The marker armed before the start is the only record a hard kill or a reboot leaves, so it names the
        start's token, which the start request then carries."""
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        armed = (self.state / "armed-text").read_text()
        token = (self.state / "start-tokens.log").read_text().split()[0]
        self.assertEqual(token, section["start_token"])
        self.assertIn(f"start token {token}", armed)
        self.assertNotIn("None", armed.split("start token")[1])

    def test_a_retry_s_target_check_is_cut_at_the_start_window(self):
        """A start whose response was lost is retried after a fresh target check; that check ends with the start
        window, so a slow describe takes no time from the windows that follow."""
        self.operator["effect_timeout_seconds"] = 2
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "hang_after_start": {"describe-volumes": 3}},
                  lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(aws_seconds=10, manifest=self.manifest(case_seconds=600))
        self.assertEqual(code, 1, out)
        self.assertEqual(self.calls().count("ec2 describe-volumes"), 4, "the retry's describe was sent")
        self.assertEqual((self.state / "describes").read_text(), "3",
                         "the retry's describe was cut before the fake could answer")
        self.assertIn("did not start", section["first_failure"], "the window's end is the failure, as for a cut start")
        self.assertEqual(section["status"], "HALTED", "the discovered own start was live and stopped")

    def test_a_case_that_fails_after_the_fault_started_without_a_timeout_is_disproven(self):
        """The case's test fails after the fault started and before any timeout: the row is DISPROVEN, with the
        timeout the case never observed kept as the diagnostic beside it."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100},
                  lane={"observe": [], "credited": False, "failed": True, "exit": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "DISPROVEN"), out)
        self.assertIn("uncredited", section["first_failure"])
        self.assertRegex(section["diagnostic"], r"(?:before the case observed a timeout|without an observed timeout)",
                         "the earlier diagnostic is kept beside the verdict")
        self.assertIn("start_ordinal", section["effect_window"])
        self.assertNotIn("first_timeout", section)

    def test_a_signal_during_the_receipt_s_write_is_recorded_in_the_receipt(self):
        """A signal that arrives while the receipt is being written is pending once the write ends; the controller
        takes it into the outcome and writes the receipt again, so the durable text carries the interruption the
        exit code reports."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        module.Episode.cleanup = lambda self: None
        module.Episode.run = lambda self: None
        real, writes = module.write_file, []

        def signalled_write(path, text):
            real(path, text)
            writes.append(text)
            if len(writes) == 1:
                os.kill(os.getpid(), signal.SIGTERM)

        module.write_file = signalled_write
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual(code, 5, section)
        on_disk = json.loads((self.state / "artifacts" / "fis-fis-read-latency-unit.json").read_text())["fis"]
        self.assertEqual(on_disk["verdict"], "INCONCLUSIVE")
        self.assertIn("during cleanup", on_disk["first_failure"])
        self.assertEqual(len(writes), 2, "the receipt was written again after the signal")

    def test_a_passing_case_the_lane_leaves_uncredited_is_inconclusive_with_the_lane_reason(self):
        reason = "Inconclusive: platform row unsupported: x86_64-nitro-ebs"
        self.plan(lane={"observe": ["timeout", "restored"], "credited": False, "first_failure": reason, "exit": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("uncredited", section["first_failure"])
        self.assertIn(reason, section["first_failure"])

    def test_a_lane_receipt_with_malformed_cases_is_inconclusive_and_still_written(self):
        for cases in ([None], [{"id": "case", "summary": [7]}]):
            with self.subTest(cases=cases):
                self.plan(lane={"observe": ["timeout", "restored"], "credited": False, "cases": cases, "exit": 1})
                code, out, section = self.run_episode()
                self.assertEqual((code, section.get("verdict")), (1, "INCONCLUSIVE"), out)
                self.assertIn("no readable lane receipt", section["first_failure"])

    def test_an_experiment_or_a_case_that_outlives_its_time_is_stopped_and_earns_no_credit(self):
        self.plan(aws={"volumes": [volume()], "run_seconds": 100}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(manifest=self.manifest(duration_seconds=1))
        self.assertEqual((code, section["status"], section["abort"]), (1, "HALTED", "stopped"), out)
        self.assertIn("outlived its duration", section["first_failure"])
        # The bound at these parameters is 58 s, the case's declared seconds; the case itself runs about 80 s.
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"], "seconds": 40})
        code, out, section = self.run_episode(manifest=self.manifest(ready_seconds=1, duration_seconds=1, case_seconds=58),
                                              aws_seconds=1)
        self.assertNotEqual(section["verdict"], "HELD", out)
        self.assertEqual(section["case_exit"], 1, "the case past its seconds was abandoned and settled itself")
        self.assertTrue((self.state / "settled").exists())
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"], "seconds": 40, "ignore_abandon": True})
        code, out, section = self.run_episode(manifest=self.manifest(ready_seconds=1, duration_seconds=1, case_seconds=58),
                                              aws_seconds=1)
        self.assertEqual((code, section["case_exit"]), (4, 4), "a case that ignores the mark is held by the lane: " + out)
        self.assertIn("custody held", section["first_failure"])

    def test_lost_telemetry_failed_restoration_partial_injection_and_failed_start_earn_no_credit(self):
        cases = {
            "controller lost": ({"lost": "watch"}, {}, 1, "telemetry was lost", "CONTROLLER_LOST"),
            "final state lost": ({"lost": "final"}, {}, 1, "final state was lost", "CONTROLLER_LOST"),
            "no volume status": ({"no_status": True}, {}, 1, "not restored", "COMPLETED"),
            "ended failed": ({"final": "failed"}, {}, 1, "ended failed", "FAILED_TO_INJECT"),
            "not restored": ({"volume_status": "impaired"}, {}, 1, "not restored", "COMPLETED"),
            "partial": ({"partial": True}, {}, 2, "partially", "FAILED_TO_INJECT"),
            "failed to inject": ({"start": False}, {}, 1, "did not start", "FAILED_TO_INJECT"),
            "case uncredited": ({}, {"credited": False}, 1, "uncredited", "COMPLETED"),
            "custody held": ({}, {"exit": 4}, 4, "custody held", "COMPLETED"),
        }
        for name, (aws, lane, code, reason, status) in cases.items():
            with self.subTest(name):
                for marker in ("done", "stopped", "calls.log"):
                    (self.state / marker).unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()], **aws}, lane={"observe": ["timeout", "restored"], **lane})
                got, out, section = self.run_episode()
                self.assertEqual(got, code, out)
                self.assertNotEqual(section["verdict"], "HELD")
                self.assertIn(reason, section["first_failure"])
                if status:
                    self.assertEqual(section["status"], status)
                if name in ("controller lost", "final state lost"):
                    self.assertEqual(section["abort"], "issued", "a lost fault is asked to stop; its end stays unconfirmed")
                if name == "failed to inject":
                    self.assertIn("fis list-experiments", self.calls())
                    self.assertIsNone(section["abort"], "a listing that names no experiment stops nothing")
                    self.assertTrue(section.get("fault_end_unconfirmed"), "a start with no listed experiment is unproven")

    def test_a_malformed_operator_contract_is_rejected_and_the_campaign_lists_unprovisioned_profiles(self):
        self.operator.pop("stop_alarms")
        code, out, _ = self.run_episode()
        self.assertEqual(code, 2)
        self.assertIn("operator contract keys", out)
        self.operator["stop_alarms"] = []
        code, out, _ = self.run_episode(profile="fis-pause", command="campaign")
        self.assertEqual(code, 0, out)
        self.assertIn("- fis-read-latency: unrun", out)
        self.assertIn("fis-pause: HELD", out)
        self.assertIn("the matrix credits only with every profile HELD; 6 unrun", out)

    def test_an_unusable_hardware_manifest_is_rejected_before_any_aws_call(self):
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = ["episode", "--operator", str(self.state / "operator.json"), "--artifacts", str(self.state / "artifacts"),
                "--observer", str(self.state / "observer"), "--episode", "unusable", "--aws", str(self.state / "aws"),
                "--lane", str(self.state / "lane"), "--manifest", str(self.manifest(duration_seconds=1)),
                "--custody", str(self.state / "custody"), "--profile", "fis-read-latency"]
        (self.state / "torn.json").write_text('{"version": 1, "platforms": ')
        for path in (self.state / "torn.json", self.state / "missing.json"):
            with self.subTest(manifest=path.name):
                printed = io.StringIO()
                with contextlib.redirect_stdout(printed):
                    code = module.main([*argv, "--hardware-manifest", str(path)])
                self.assertEqual(code, 2, printed.getvalue())
                self.assertIn(f"rejected input: Rejected: the hardware manifest {path} is unusable",
                              printed.getvalue())
                self.assertEqual(self.calls(), [], "the refusal precedes every AWS call")

    def test_the_platform_row_is_admitted_from_the_hardware_manifest_the_case_runs_under(self):
        """The row check before any AWS call reads `--hardware-manifest`, the manifest the lane runs and is judged
        under: a row only that manifest declares runs, and a row only the checked-in manifest declares is refused."""
        hardware = json.loads(self.hardware_manifest.read_text())
        hardware["platforms"]["override-row"] = hardware["platforms"].pop("x86_64-nitro-ebs")
        for profile in hardware["profiles"].values():
            profile["platforms"]["override-row"] = profile["platforms"].pop("x86_64-nitro-ebs")
        self.hardware_manifest.write_text(json.dumps(hardware))
        saved = os.environ["KESTRIKE_HARDWARE_PLATFORM"]
        self.addCleanup(os.environ.__setitem__, "KESTRIKE_HARDWARE_PLATFORM", saved)
        with self.subTest("a row only the checked-in manifest declares"):
            os.environ["KESTRIKE_HARDWARE_PLATFORM"] = "x86_64-nitro-ebs"
            code, out, _ = self.run_episode()
            self.assertEqual(code, 2, out)
            self.assertIn("no platform row 'x86_64-nitro-ebs'; name the host's row with KESTRIKE_HARDWARE_PLATFORM",
                          out)
            self.assertEqual(self.calls(), [], "the refusal precedes every AWS call")
            self.assertFalse((self.state / "lane-ran").exists(), "the refusal precedes every case")
        with self.subTest("a row only the supplied manifest declares"):
            os.environ["KESTRIKE_HARDWARE_PLATFORM"] = "override-row"
            code, out, section = self.run_episode()
            self.assertEqual((code, section.get("verdict")), (0, "HELD"), out)

    def test_a_host_naming_no_platform_row_is_rejected_before_any_aws_call_or_case(self):
        saved = os.environ["KESTRIKE_HARDWARE_PLATFORM"]
        self.addCleanup(os.environ.__setitem__, "KESTRIKE_HARDWARE_PLATFORM", saved)
        for row, reason in ((None, "no platform row named; name the host's row with KESTRIKE_HARDWARE_PLATFORM"),
                            ("no-such-row", "no platform row 'no-such-row'; name the host's row with "
                                            "KESTRIKE_HARDWARE_PLATFORM")):
            with self.subTest(row=row):
                os.environ.pop("KESTRIKE_HARDWARE_PLATFORM", None)
                if row is not None:
                    os.environ["KESTRIKE_HARDWARE_PLATFORM"] = row
                code, out, _ = self.run_episode()
                self.assertEqual(code, 2, out)
                self.assertIn(reason, out)
                self.assertEqual(self.calls(), [], "the refusal precedes every AWS call")
                self.assertFalse((self.state / "lane-ran").exists(), "the refusal precedes every case")

    def test_a_campaign_starts_no_profile_after_one_that_left_custody_held(self):
        self.plan(lane={"observe": ["timeout", "restored"], "exit": 4})
        code, out, _ = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual(code, 4, out)
        self.assertEqual(self.calls().count("fis start-experiment"), 1, "no later profile was injected")
        self.assertIn("- fis-pause: unrun; custody is held", out)
        self.assertIn("the matrix credits only with every profile HELD; 6 unrun", out)

    def test_an_unknown_start_is_discovered_with_retries_and_an_unconfirmed_fault_end_stops_the_campaign(self):
        """A start whose outcome is unknown lists the template's experiments until the listing answers, within
        the effect timeout, and stops any live one; a fault whose end stays unconfirmed starts no later profile."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "list_failures": 2, "lost": "watch"})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["status"], section["experiment_id"]), (1, "HALTED", "EXP1"),
                         "the discovered experiment ran and was halted: " + out)
        self.assertEqual(self.calls().count("fis list-experiments"), 4,
                         "the discovery's listing was retried until it answered, and the deleted template's experiments were listed")
        self.assertIn("fis stop-experiment", self.calls())
        self.assertEqual(section["abort"], "issued")
        self.assertTrue(section.get("fault_end_unconfirmed"), out + json.dumps(section, indent=1))
        self.plan(aws={"volumes": [volume()], "start": False})
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, section = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual((code, section["status"]), (1, "FAILED_TO_INJECT"), out)
        listings = self.calls().count("fis list-experiments")
        self.assertGreaterEqual(listings, 1)
        self.assertLessEqual(listings, (2 // 0.05) + 2, "one discovery window, not three")
        self.assertIsNone(section["abort"], "an empty listing stops nothing")
        # An empty listing proves no rollback: FIS may yet list a start it accepted, so the end stays unconfirmed.
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertEqual(section["start_unconfirmed"], "no experiment listed")
        self.assertIn("fis-pause: unrun; the previous fault's end is unconfirmed", out)
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "list_failures": 1000})
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, _ = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual(code, 1, out)
        self.assertEqual(self.calls().count("fis create-experiment-template"), 1, "no later profile was injected")
        self.assertIn("- fis-pause: unrun; the previous fault's end is unconfirmed", out)

    def test_a_lost_start_response_is_retried_with_one_client_token(self):
        """The first `start-experiment` is accepted by FIS but its response is lost; the retry carries the same
        client token, so FIS returns the experiment it already started rather than a second one."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        tokens = (self.state / "start-tokens.log").read_text().split()
        self.assertEqual(len(tokens), 2, "the start was retried once")
        self.assertEqual(len(set(tokens)), 1, "both starts carried the same client token")
        self.assertNotEqual(tokens[0], "-", "a client token was sent")
        self.assertLessEqual(len(tokens[0]), 64, "a client token fits FIS's limit whatever the episode's name")
        self.assertEqual(tokens[0], section["start_token"])

    def test_the_case_deadline_covers_every_controller_phase_and_an_effect_timeout_past_the_case_is_rejected(self):
        """The case's deadline is the same bound the campaign budgets per episode, and a contract whose effect
        timeout makes that bound exceed the case's declared seconds is rejected before any call."""
        code, out, section = self.run_episode()
        self.assertEqual(code, 0, out)
        self.manifest()
        profile = self.loaded["profiles"]["fis-read-latency"]
        effect = self.operator["effect_timeout_seconds"]
        expected = profile["ready_seconds"] + 1 + 5 * effect + 3 * 60 + 2 * 60 + 2 * (effect + 60) + 7 * 5
        self.assertEqual((self.state / "lane-deadline").read_text(), str(expected))
        self.operator["effect_timeout_seconds"] = 600
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, _ = self.run_episode()
        self.assertEqual(code, 2, out)
        self.assertIn("rejected input", out)
        self.assertIn("effect_timeout_seconds", out)
        self.assertEqual(self.calls(), [])

    def test_a_lane_supervisor_that_dies_by_a_signal_leaves_custody_unknown_and_exits_held(self):
        """The lane's supervisor dies by SIGKILL after spawning its case, whose group may still hold the devices: the
        controller records the custody as unknown, exits held with the boot-scoped marker, and a campaign runs no
        later profile."""
        self.plan(aws={"volumes": [volume()]}, lane={"die_after_ready": True})
        code, out, section = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual(code, 4, out)
        self.assertIn("died by signal 9", section["custody_unknown"])
        self.assertEqual(section["case_exit"], -signal.SIGKILL)
        self.assertIn("fis-pause: unrun", out)
        marker = json.loads((self.state / "custody" / "fis-e1-fis-read-latency.json").read_text())
        self.assertIn("custody is unknown", marker["custody"])

    def test_an_event_another_role_appended_to_the_episode_log_is_no_witness_for_this_case(self):
        """Another lane role shares the episode's observer log and appends a timeout; this case's own role observed
        none, so the episode records no timeout and earns no credit."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100},
                  lane={"observe": [], "foreign_observe": ["timeout"], "linger_seconds": 5})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("without an observed timeout", section["first_failure"])
        self.assertNotIn("first_timeout", section)
        events = [json.loads(line) for line in (self.state / "observer" / "e1.jsonl").read_text().splitlines()]
        self.assertTrue(any(e.get("name") == "timeout" and e["role"] == "other" for e in events), "the foreign event is in the log")

    def test_a_case_that_exits_after_readiness_gets_no_fault(self):
        self.plan(lane={"exit_after_ready": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "FAILED_TO_INJECT"), out)
        self.assertIn("the case ended before", section["first_failure"])
        self.assertNotIn("fis start-experiment", self.calls(), "no fault is injected for a dead case")
        calls = self.calls()
        self.assertGreater(calls.index("fis list-experiments"), calls.index("fis delete-experiment-template"),
                           "no start was requested, so nothing is discovered; the deleted template's listing follows")
        self.assertNotIn("start_unconfirmed", section)
        self.assertNotIn("fault_end_unconfirmed", section)

    def test_a_proven_stop_whose_acknowledgement_was_lost_keeps_its_credit_without_stop_alarms(self):
        """FIS accepted the controller's stop and the acknowledgement was lost; with no stop alarm in the contract
        the stopped state can be the controller's alone, so the proven stop keeps its credit."""
        self.plan(aws={"volumes": [volume()], "stop_lost": True}, lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual((code, section["verdict"], section["status"], section["abort"]), (0, "HELD", "HALTED", "stopped"), out)
        self.assertIn("stop_under_fault", section)

    def test_a_proven_stop_whose_acknowledgement_was_lost_is_credited_when_the_watch_sees_the_end(self):
        """FIS accepted the stop, lost the acknowledgement and stayed `stopping` past the stop's own window; the
        watch sees the stopped state later and, with no stop alarm in the contract, credits the controller's stop."""
        self.plan(aws={"volumes": [volume()], "stop_lost": True, "stopping_seconds": 2.5},
                  lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual((code, section["verdict"], section["status"], section["abort"]), (0, "HELD", "HALTED", "stopped"), out)
        self.assertIn("stop_under_fault", section)

    def test_a_marker_that_cannot_be_lifted_keeps_the_host_quarantined_and_exits_held(self):
        """A marker the close-out cannot remove, here a directory planted at its name, stays and the episode exits
        held, so a campaign starts no later profile on the host."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        (self.state / "custody" / "fis-unit.json").mkdir(parents=True)
        module.Episode.cleanup = lambda self: None
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual(code, 4, section)
        self.assertIn("stays", section["quarantine"])
        self.assertTrue((self.state / "custody" / "fis-unit.json").is_dir())

    def test_a_receipt_that_cannot_be_written_is_inconclusive(self):
        """An episode with no receipt has no evidence: a write the artifacts refuse leaves the verdict INCONCLUSIVE
        and the exit nonzero."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        module.Episode.cleanup = lambda self: None
        module.Episode.run = lambda self: None
        def partial_write(path, text):
            # The text reached the file and its durability failed, as a directory sync failing after the rename
            # leaves it.
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text)
            raise OSError("no space left for the receipt")

        module.write_file = partial_write
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), section)
        self.assertIn("could not be written", section["first_failure"])
        self.assertFalse((self.state / "artifacts" / "fis-fis-read-latency-unit.json").exists(),
                         "a receipt whose durability failed is removed rather than left disagreeing with the exit")

    def test_a_file_is_written_whole_or_left_as_it_was_and_its_directories_are_synced(self):
        """`write_file` replaces the file in one step from a synced temporary: a durability failure leaves the previous
        version and no temporary; `make_directory` syncs every parent that gained an entry."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        synced = []
        module.sync_directory = lambda directory: synced.append(Path(directory))
        target = self.state / "deep" / "er" / "file.json"
        module.write_file(target, "one\n")
        self.assertEqual(target.read_text(), "one\n")
        self.assertEqual(synced, [self.state, self.state / "deep", target.parent], "each new parent, then the file's")
        real_fsync = module.os.fsync

        def failing_fsync(descriptor):
            raise OSError("the device is gone")

        module.os.fsync = failing_fsync
        try:
            with self.assertRaises(OSError):
                module.write_file(target, "two\n")
        finally:
            module.os.fsync = real_fsync
        self.assertEqual(target.read_text(), "one\n", "the previous version stands")
        self.assertEqual(sorted(p.name for p in target.parent.iterdir()), ["file.json"], "no temporary is left")

    def test_a_receipt_that_cannot_be_written_still_yields_the_held_exit(self):
        """The close-out's writes are guarded: a receipt the artifacts refuse leaves the exit code carrying the
        held result."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")

        def held_cleanup(self):
            self.section["custody_unknown"] = "modelled"

        module.Episode.cleanup = held_cleanup
        module.write_file = lambda path, text: (_ for _ in ()).throw(OSError("no space left for the receipt"))
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual(code, 4, section)
        self.assertFalse((self.state / "artifacts" / "fis-fis-read-latency-unit.json").exists())

    def test_a_stop_refused_once_is_asked_for_again_in_cleanup(self):
        """A stop call that failed in the run, its acceptance never seen, is sent again by cleanup, so a live
        experiment the controller decided to stop is stopped."""
        self.plan(aws={"volumes": [volume()], "stop_refusals": 1, "run_seconds": 100}, lane={"observe": ["restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["abort"]), (1, "stopped"), out)
        self.assertEqual(self.calls().count("fis stop-experiment"), 2, "the refused stop was asked for again")
        self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_an_unknown_start_that_lists_two_experiments_stays_unconfirmed_while_either_is(self):
        """The discovery lists a live experiment whose stop FIS refuses beside the completed one; the completed one's
        restoration confirms nothing about the live one, so the fault's end stays unconfirmed and both are named."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1, "volumes_later": [volume(Tags=[])], "volumes_later_from": 4,
                       "listed_status": "completed", "listed_twins": True})
        code, out, section = self.run_episode()
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertEqual(section["experiment_ids"], ["EXP0", "EXP1"])
        self.assertEqual(section["experiment_id"], "EXP1", "the receipt's experiment is the controller's own start")
        self.assertEqual(section["status"], "COMPLETED", "the run status follows the controller's own start")
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        record = json.loads(Path(section["quarantine"]).read_text())
        self.assertIn("experiment EXP0,", record["custody"], "the marker names the experiment whose end is unconfirmed")
        self.assertNotIn("EXP1", record["custody"])
        self.assertEqual(set(self.logged("stopped-ids.log")), {"EXP0"},
                         "the live experiment alone was asked to stop, again while its stop stayed refused")

    def test_the_lane_inherits_the_host_reservation(self):
        """The spawned lane holds the custody lock the controller took, so a controller killed before the lane
        publishes its own custody leaves the host reserved by the lane."""
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode()
        self.assertEqual(code, 0, out)
        self.assertEqual((self.state / "lane-holds-reservation").read_text(), "True")

    def test_a_discovery_that_lists_only_another_experiment_keeps_the_controller_s_start_unconfirmed(self):
        """Another experiment under the template, tagged with another request, is listed and stopped; it confirms
        nothing about the controller's own start, which stays unconfirmed with the host quarantined, and the deleted
        template's listing names it as a foreign experiment the marker names beside the unlisted start."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "listed_foreign_only": True})
        code, out, section = self.run_episode()
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertEqual(section["start_unconfirmed"], "the controller's own start was never listed")
        self.assertEqual(section["experiment_ids"], ["EXP0"])
        self.assertNotIn("experiment_id", section, "the receipt names no experiment the controller never saw")
        self.assertEqual(section["status"], "FAILED_TO_INJECT")
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        custody = json.loads(Path(section["quarantine"]).read_text())["custody"]
        self.assertIn("EXP0", custody)
        self.assertIn("the unlisted start tagged", custody)
        # A template in doubt beside the unlisted start: the marker names both, since deleting the template resolves
        # nothing about a start FIS may have accepted.
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "listed_foreign_only": True, "delete_failures": 1000})
        code, out, section = self.run_episode()
        custody = json.loads(Path(section["quarantine"]).read_text())["custody"]
        self.assertIn("template EXT1 may remain and admits starts", custody)
        self.assertIn("the unlisted start tagged", custody)
        # An unconfirmed foreign experiment and the unlisted start are separate doubts; the marker names both.
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "listed_twins": True, "listed_without_own": True})
        code, out, section = self.run_episode()
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"], out)
        self.assertEqual(section["start_unconfirmed"], "the controller's own start was never listed")
        custody = json.loads(Path(section["quarantine"]).read_text())["custody"]
        self.assertIn("EXP0", custody)
        self.assertIn("the unlisted start tagged", custody)

    def test_an_experiment_that_differs_from_the_controller_s_template_is_invalid_and_stopped(self):
        """Another principal updated the template between its creation and the start, so the experiment FIS runs
        is not the one the controller created: the first observation binds the experiment to the template, and one
        with another action, other or extra parameters, other targets, another selection mode, an extra target group,
        another role or other stop conditions is INVALID and stopped."""
        own = {"resourceType": "aws:ec2:ebs-volume", "selectionMode": "ALL",
               "resourceArns": [f"arn:aws:ec2:us-east-1:111122223333:volume/{VOLUME}"]}
        mutations = {"action": {"actionId": "aws:ebs:pause-volume-io"},
                     "parameters": {"parameters": {"duration": "PT600S"}},
                     "extra parameter": {"parameters": {"availabilityZoneIdentifier": "use1-az1"}},
                     "targets": {"resourceArns": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0other"]},
                     "selection mode": {"targets": {"Volumes": dict(own, selectionMode="PERCENT(5)")}},
                     "target filter": {"targets": {"Volumes": dict(own, filters=[{"path": "State", "values": ["in-use"]}])}},
                     "extra target group": {"targets": {"Volumes": own, "Instances": {
                         "resourceType": "aws:ec2:instance", "resourceArns": ["arn:aws:ec2:us-east-1:111122223333:instance/i-1"],
                         "selectionMode": "ALL"}}},
                     "role": {"roleArn": "arn:aws:iam::1:role/other"},
                     "stop conditions": {"stopConditions": [{"source": "aws:cloudwatch:alarm", "value": "x"}]}}
        for name, mutated in mutations.items():
            with self.subTest(name):
                self.plan(aws={"volumes": [volume()], "mutated": mutated, "run_seconds": 100},
                          lane={"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode(episode=f"m-{name.replace(' ', '-')}")
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertIn("differs from the template", section["first_failure"])
                self.assertEqual((section["status"], section["abort"]), ("HALTED", "stopped"))
                self.assertNotIn("effect_window", section, "no fault start was marked for a foreign experiment")
                # The experiment's targets may be other volumes, whose restoration the poll did not cover.
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / f"fis-m-{name.replace(' ', '-')}.json").exists())
                if name == "targets":
                    self.assertEqual(section["unbound_targets"], mutated["resourceArns"])
        # An experiment whose targets are selected some other way records no ARN, and a template in doubt beside
        # it: the marker names both, since the volumes that experiment hit are the operator's to confirm.
        self.plan(aws={"volumes": [volume()], "mutated": {"resourceArns": []}, "run_seconds": 100,
                       "delete_failures": 1000}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="m-unlisted-targets")
        self.assertEqual((code, section["verdict"], section["unbound_targets"]), (2, "INVALID", []), out)
        custody = json.loads((self.state / "custody" / "fis-m-unlisted-targets.json").read_text())["custody"]
        self.assertIn("may remain and admits starts", custody)
        self.assertIn("the FIS fault's end is unconfirmed", custody)
        # The first observations are lost, so the stop's full experiment is the first read; the binding runs there
        # and the mismatch keeps the quarantine. The discovery path reads the controller's own experiment once for
        # the same binding.
        for name, aws in {"lost first observations": {"lost_first_gets": 3},
                          "discovered start": {"start_lost": 1000}}.items():
            with self.subTest(name):
                self.plan(aws={"volumes": [volume()], "run_seconds": 100, **aws,
                               "mutated": {"resourceArns": ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0other"]}},
                          lane={"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode(episode=f"m-{name.replace(' ', '-')}")
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertEqual(section["unbound_targets"], ["arn:aws:ec2:us-east-1:111122223333:volume/vol-0other"])
                self.assertTrue(section["fault_end_unconfirmed"], out)
                custody = json.loads((self.state / "custody" / f"fis-m-{name.replace(' ', '-')}.json").read_text())
                self.assertIn("the FIS fault's end is unconfirmed", custody["custody"])
        # The discovery's binding read is lost while the stop's polls answer: the experiment stays unbound, and the
        # fault's end unconfirmed with the marker naming it.
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "lost_first_gets": 1, "run_seconds": 100},
                  lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="m-unread")
        self.assertEqual(code, 1, out)
        self.assertIn("never read", section["binding_unconfirmed"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertEqual(section["abort"], "stopped", "the stop went first and was seen through")
        custody = json.loads((self.state / "custody" / "fis-m-unread.json").read_text())["custody"]
        self.assertIn("the FIS fault's end is unconfirmed", custody)
        # A slow binding read takes nothing from the stop requests, which go first under the window.
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "run_seconds": 100, "hang": {"get-experiment": 3}},
                  lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="m-slow-read")
        self.assertIn("fis stop-experiment", self.calls(), "the live discovered experiment was asked to stop")
        self.assertIn(section["abort"], ("issued", "stopped"), out)
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), "the controller's own template binds: " + out)

    def test_the_target_arns_take_the_partition_of_the_operator_s_role(self):
        """A GovCloud or China operator names its role in that partition, and the template's targets follow it."""
        self.operator["role_arn"] = "arn:aws-us-gov:iam::1:role/fis"
        self.operator["region"] = "us-gov-west-1"
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        template = json.loads((self.state / "template.json").read_text())
        self.assertEqual(template["targets"]["Volumes"]["resourceArns"],
                         [f"arn:aws-us-gov:ec2:us-gov-west-1:111122223333:volume/{VOLUME}"])
        for bad in ("arn:aws:iam::1:user/fis", "fis", "arn::iam::1:role/fis"):
            with self.subTest(role=bad):
                self.operator["role_arn"] = bad
                self.plan(aws={"volumes": [volume()]})
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, section = self.run_episode()
                self.assertEqual(code, 2, out)
                self.assertIn("IAM role ARN", out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_a_chatty_case_never_blocks_on_its_output(self):
        """The case's output goes to its own log under the artifacts, so a case that writes more than a pipe holds
        before its readiness still reaches it, and the lane's receipt line is read from that log."""
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"], "chatter_bytes": 1 << 20})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertTrue(section["lane_receipt"], "the receipt line was read from the case's log")
        log = self.state / "artifacts" / "fis-e1.case.log"
        self.assertGreater(log.stat().st_size, 1 << 20)

    def test_a_signal_during_a_lost_start_s_retries_keeps_the_controller_s_loss_in_the_receipt(self):
        """The signal lands while the start is retried; cleanup discovers the accepted start, and the receipt keeps
        CONTROLLER_LOST as its run status beside the discovered experiment."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1000}, lane={"observe": ["timeout", "restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile",
                "fis-read-latency", "--operator", str(self.state / "operator.json"), "--artifacts",
                str(self.state / "artifacts"), "--observer", str(self.state / "observer"), "--episode", "s6",
                "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05",
                "--manifest", str(self.manifest(duration_seconds=1)), "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis start-experiment" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.3)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertEqual((section["status"], section["experiment_id"]), ("CONTROLLER_LOST", "EXP1"), out)

    def test_a_second_controller_on_the_host_exits_held_before_any_call(self):
        """The lane's host reservation under the custody directory admits one controller or sweep at a time, taken
        before the markers are read, so two campaigns, or a campaign and a sweep, cannot both pass an empty check."""
        custody = self.state / "custody"
        custody.mkdir(exist_ok=True)
        holder = os.open(custody / "fis.lock", os.O_RDWR | os.O_CREAT)
        self.addCleanup(os.close, holder)
        fcntl.flock(holder, fcntl.LOCK_EX)
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(keep_custody=True)
        self.assertEqual(code, 4, out)
        self.assertIn("another sweep or FIS controller holds this host", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_a_stop_whose_terminal_state_the_stop_observed_needs_no_second_look(self):
        """The stop confirms the experiment ended; telemetry that fails right after does not lose the episode."""
        self.plan(aws={"volumes": [volume()], "lost": "after_stop"}, lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual((code, section["verdict"], section["status"], section["abort"]), (0, "HELD", "HALTED", "stopped"), out)

    def test_a_proven_stop_polls_the_restoration_once(self):
        """`stop()` confirms the restoration after the terminal state; `restoration()` on the same experiment takes
        that result rather than a second window, and an impaired volume stays unconfirmed."""
        self.plan(aws={"volumes": [volume()], "volume_status": "impaired"},
                  lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10))
        self.assertEqual((code, section["abort"]), (1, "stopped"), out)
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        # One poll per episode: a later caller on the same terminal experiment takes the recorded result.
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        polls = []
        run.poll_restored = lambda: polls.append(1) or False
        self.assertFalse(run.restored())
        self.assertFalse(run.restored())
        self.assertEqual(len(polls), 1, "the second caller took the recorded result")

    def test_a_polling_sleep_is_cut_at_the_deadline_it_polls_toward(self):
        """A polling interval wider than a window never carries a loop past that window's deadline or the run
        deadline: each sleep is cut at the earliest of them."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=100.0, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        begun = time.monotonic()
        run.nap(time.monotonic() + 0.2)
        self.assertLess(time.monotonic() - begun, 1.0, "the sleep ends at the window's deadline")
        run.run_deadline = time.monotonic() + 0.2
        begun = time.monotonic()
        run.nap()
        self.assertLess(time.monotonic() - begun, 1.0, "the sleep ends at the run deadline")
        run.run_deadline = None
        begun = time.monotonic()
        run.nap(time.monotonic() - 5)
        self.assertLess(time.monotonic() - begun, 0.5, "a deadline already passed means no sleep")

    def test_an_aws_call_never_outlives_the_run_deadline(self):
        """Once the run's phases start, every AWS call is clamped to the time the run has left, so no phase can
        overrun the bound the campaign admitted and the case was given."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.plan(aws={"volumes": [volume()], "hang": {"describe-volume-status": 5}})
        self.manifest(duration_seconds=1)
        manifest = self.loaded
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws=str(self.state / "aws"), aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, manifest, "fis-read-latency", self.operator)
        os.environ["FAKE_STATE"] = str(self.state)
        self.addCleanup(os.environ.pop, "FAKE_STATE", None)
        begun = time.monotonic()
        self.assertIsNotNone(run.aws("ec2", "describe-volume-status", "--volume-ids", VOLUME),
                             "before the run starts, a call may take its time")
        self.assertGreater(time.monotonic() - begun, 4.5)
        run.run_deadline = time.monotonic() + 0.5
        begun = time.monotonic()
        self.assertIsNone(run.aws("ec2", "describe-volume-status", "--volume-ids", VOLUME),
                          "a call past the run deadline is cut off")
        self.assertLess(time.monotonic() - begun, 2.0)

    def test_a_start_retry_checks_the_targets_again(self):
        """The first start is accepted but its response lost; the volume loses its disposable tag before the
        retry, so the retry is refused, the accepted start stays unconfirmed and the receipt names its token."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1, "volumes_later": [volume(Tags=[])], "volumes_later_from": 4})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(len((self.state / "start-tokens.log").read_text().split()), 1, "no start after the refusal")
        self.assertIn("fis stop-experiment", self.calls(), "the start that may have been accepted is discovered and stopped")
        self.assertEqual((section["experiment_id"], section["status"]), ("EXP1", "HALTED"),
                         "the receipt names the experiment that ran and that it was halted")

    def test_a_discovered_experiment_that_already_ended_is_recorded_from_its_listed_state(self):
        """The accepted start's response is lost, the retry is refused, and by cleanup the listing reports the
        experiment completed: the receipt names it with the state it reached, and nothing is stopped."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1, "volumes_later": [volume(Tags=[])], "volumes_later_from": 4,
                       "listed_status": "completed"})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual((section["experiment_id"], section["status"]), ("EXP1", "COMPLETED"))
        self.assertNotIn("fis stop-experiment", self.calls())
        self.assertIsNone(section["abort"])

    def test_a_case_that_exits_during_a_retry_s_target_check_gets_no_second_start(self):
        """The first start is accepted with its response lost; the case exits while the retry's target check is
        in flight, so no retry is sent, and the accepted start is discovered and halted."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1, "exit_case_at_describe": 4})
        code, out, section = self.run_episode()
        self.assertEqual(len((self.state / "start-tokens.log").read_text().split()), 1, "one start, no retry: " + out)
        self.assertIn("fis list-experiments", self.calls())
        self.assertEqual((section["experiment_id"], section["status"]), ("EXP1", "HALTED"))

    def test_a_polling_interval_that_is_negative_or_not_finite_is_rejected_before_any_call(self):
        for value in ("-1", "nan", "inf"):
            with self.subTest(value=value):
                (self.state / "calls.log").unlink(missing_ok=True)
                argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                        str(self.state / "operator.json"), "--poll", value, "--artifacts", str(self.state / "artifacts")]
                done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertIn("finite duration", done.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_host_a_custody_marker_quarantines_runs_no_fis_profile(self):
        """A held case group from an earlier job leaves its marker under the custody directory; the controller
        refuses the host before any case is spawned or AWS call made, the way the sweep does, and exits held."""
        spec = importlib.util.spec_from_file_location("lane", str(ROOT / "scripts/hardware-lane.py"))
        lane = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lane)
        custody = self.state / "custody"
        custody.mkdir(exist_ok=True)
        (custody / "supervisor-4242.json").write_text(json.dumps({
            "boot": lane.boot_id(), "pgid": None, "profile": "spdk-volume", "role": "owner", "episode": "earlier",
            "custody": "supervisor died by a signal"}))
        self.plan(aws={"volumes": [volume()]})
        for command in ("episode", "campaign"):
            with self.subTest(command):
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, section = self.run_episode(command=command, keep_custody=True)
                self.assertEqual(code, 4, out)
                self.assertIn("custody held on this host", out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")
                self.assertFalse((self.state / "artifacts").exists(), "no case was spawned")

    def test_a_live_experiment_another_principal_started_from_the_template_keeps_the_quarantine(self):
        """The controller's own start ended and the volume restored, but once the template is deleted its listing
        names another live experiment, started after any earlier look and kept running by FIS past the deletion: the
        fault's end is unconfirmed, the durable marker stays and the episode earns no credit. A listing that never
        answers, or one without the controller's own experiment, holds the same, as does a retained template."""
        self.plan(aws={"volumes": [volume()], "listed_twin_after_deletion": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("EXP0", section["first_failure"])
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        self.assertEqual(section["experiment_id"], "EXP1", "the controller's own start stands in the receipt")
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the marker stays for an operator")
        calls = self.calls()
        self.assertLess(calls.index("fis delete-experiment-template"), len(calls) - 1 - calls[::-1].index("fis list-experiments"),
                        "the listing follows the deletion, after which the template admits nothing")
        for name, aws in {"unanswered": {"list_failures": 1000}, "without own": {"listed_without_own": True},
                          "retained": {"delete_failures": 1000}, "malformed": {"listed_malformed": True},
                          "ended twin": {"listed_twin_after_deletion": "completed"},
                          "discovered own": {"start_lost": 1000, "listed_twin_after_deletion": "completed"}}.items():
            with self.subTest(name):
                self.plan(aws={"volumes": [volume()], **aws})
                code, out, section = self.run_episode(episode=f"e-{name.replace(' ', '-')}")
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / f"fis-e-{name.replace(' ', '-')}.json").exists(),
                                f"{name}: the quarantine stays")
        # A case that failed under the fault beside another principal's experiment cannot be attributed to the
        # profile: the row is INCONCLUSIVE, with the case's failure kept as the diagnostic.
        self.plan(aws={"volumes": [volume()], "listed_twin_after_deletion": "completed"},
                  lane={"observe": ["timeout", "restored"], "credited": False, "failed": True, "exit": 1})
        code, out, section = self.run_episode(episode="e-contaminated")
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("EXP0", section["first_failure"])
        self.assertIn("uncredited", section["diagnostic"], "the case's failure is kept as the diagnostic")
        # A DISPROVEN that replaced an earlier failure gives it back its place: a timeout never observed fails the
        # row on its own, and the contamination stays named in the experiments and the marker.
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "listed_twin_after_deletion": "completed"},
                  lane={"observe": [], "credited": False, "failed": True, "exit": 1})
        code, out, section = self.run_episode(episode="e-contaminated-twice")
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertRegex(section["first_failure"], r"(?:before the case observed a timeout|without an observed timeout)")
        self.assertIn("uncredited", section["diagnostic"])
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        self.assertNotIn("first_timeout", section)
        self.assertIn("start_ordinal", section["effect_window"])
        self.assertTrue(section["fault_end_unconfirmed"])
        self.assertTrue((self.state / "custody" / "fis-e-contaminated-twice.json").exists())
        # The controller lists the deleted template's experiments when volume restoration is unconfirmed.
        self.plan(aws={"volumes": [volume()], "volume_status": "impaired", "listed_twin_after_deletion": True},
                  lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="e-unrestored-twin")
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("not restored", section["first_failure"])
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"], out)
        custody = json.loads((self.state / "custody" / "fis-e-unrestored-twin.json").read_text())["custody"]
        self.assertIn("EXP0", custody)
        # A listing that fails after a DISPROVEN case leaves the contamination possible.
        self.plan(aws={"volumes": [volume()], "list_failures": 1000},
                  lane={"observe": ["timeout", "restored"], "credited": False, "failed": True, "exit": 1})
        code, out, section = self.run_episode(episode="e-unlisted-after-disproof")
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("not listed", section["first_failure"])
        self.assertIn("uncredited", section["diagnostic"])
        self.assertIn("not listed", section["template_experiments_unconfirmed"])
        custody = json.loads((self.state / "custody" / "fis-e-unlisted-after-disproof.json").read_text())["custody"]
        self.assertIn("EXT1", custody)
        self.assertIn("experiments", custody)
        self.assertNotIn("experiment EXP1", custody, "the controller's own experiment ended and restored")
        # The controller's own experiment, its stop refused, is unconfirmed too: the marker and the receipt keep it
        # beside the foreign one, on the watched path and on the discovered-start path.
        self.plan(aws={"volumes": [volume()], "stop_refused": True, "run_seconds": 100, "listed_twin_after_deletion": True},
                  lane={"observe": ["restored"]})
        code, out, section = self.run_episode(episode="e-own-unended-twin")
        self.assertEqual(code, 1, out)
        custody = json.loads((self.state / "custody" / "fis-e-own-unended-twin.json").read_text())["custody"]
        self.assertIn("EXP1", custody)
        self.assertIn("EXP0", custody)
        self.plan(aws={"volumes": [volume()], "start_lost": 1000, "listed_twins": True, "stop_refused": True,
                       "run_seconds": 100}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="e-own-unended-discovered")
        self.assertEqual(code, 1, out)
        self.assertEqual(sorted(section["unconfirmed_experiments"]), ["EXP0", "EXP1"], out)
        custody = json.loads((self.state / "custody" / "fis-e-own-unended-discovered.json").read_text())["custody"]
        self.assertIn("EXP1", custody)

    def page_tokens(self):
        log = self.state / "page-tokens.log"
        return log.read_text().splitlines() if log.exists() else []

    def test_a_foreign_experiment_on_a_later_page_of_the_template_s_listing_keeps_the_quarantine(self):
        """Once the template is deleted, the controller follows each `nextToken` of its experiment listing: a first
        page naming only the controller's own ended experiment, with a token, and a second naming another
        principal's live experiment contaminate the row, keep the marker, record the foreign ID among the
        unconfirmed experiments and every page's IDs, and deny credit."""
        self.plan(aws={"volumes": [volume()], "experiment_pages": {
            "": {"experiments": ["own"], "next": "p2"}, "p2": {"experiments": ["foreign"]}}})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertEqual(self.page_tokens(), ["-", "p2"], "the second request starts at the first page's token")
        self.assertEqual(section["experiment_pages"], 2)
        self.assertEqual(section["experiment_ids"], ["EXP1", "EXP0"])
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the marker stays for an operator")

    def test_a_multi_page_listing_naming_only_the_own_experiment_lifts_the_quarantine(self):
        """A listing whose pages name only the controller's own experiment, on a later page here, is followed to its
        last page, records every page and lets the fault-end and restoration gates lift the marker. The third page's
        token arrives as a truncated CLI result's `NextToken`, which the controller follows too."""
        self.plan(aws={"volumes": [volume()], "experiment_pages": {
            "": {"experiments": [], "next": "p2"}, "p2": {"experiments": [], "cli_next": "p3"},
            "p3": {"experiments": ["own"]}}})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertEqual(self.page_tokens(), ["-", "p2", "p3"])
        self.assertEqual((section["experiment_pages"], section["experiment_ids"]), (3, ["EXP1"]))
        self.assertEqual(list((self.state / "custody").glob("fis-*.json")), [], "a confirmed end lifted it")

    def test_a_null_service_token_beside_a_cli_token_is_followed(self):
        """A page whose `nextToken` is null but whose `NextToken` names a continuation still has a next page: the
        controller follows it, so a foreign experiment listed there contaminates the row and keeps the marker."""
        self.plan(aws={"volumes": [volume()], "experiment_pages": {
            "": {"experiments": ["own"], "next": None, "cli_next": "p2"}, "p2": {"experiments": ["foreign"]}}})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertEqual(self.page_tokens(), ["-", "p2"], out)
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the marker stays for an operator")

    def test_an_incomplete_listing_records_the_experiments_its_answered_pages_named(self):
        """A first page naming the controller's own experiment and another principal's live one, followed by a page
        that fails, answers in another shape or repeats its token, leaves the scan incomplete, and the receipt and
        the marker still name the foreign experiment the answered page listed."""
        first = {"experiments": ["own", "foreign"], "next": "p2"}
        cases = {"late error": {"fail": True}, "malformed": {"malformed": True},
                 "repeated token": {"experiments": [], "next": "p2"}}
        for name, second in cases.items():
            with self.subTest(name):
                episode = f"e-named-{name.replace(' ', '-')}"
                self.plan(aws={"volumes": [volume()], "experiment_pages": {"": first, "p2": second}})
                code, out, section = self.run_episode(episode=episode, aws_seconds=1)
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn("template_experiments_unconfirmed", section, out)
                self.assertEqual(section["experiment_ids"], ["EXP1", "EXP0"], out)
                self.assertEqual(section["unconfirmed_experiments"], ["EXP0"], out)
                custody = json.loads((self.state / "custody" / f"fis-{episode}.json").read_text())["custody"]
                self.assertIn("EXP0", custody, "the marker names the foreign experiment the listing showed")

    def test_an_incomplete_experiment_listing_keeps_the_quarantine(self):
        """A later page that fails until the deadline, answers in another shape, names two continuation tokens,
        repeats an earlier token at once or after another page, or answers slower than the per-call allowance on every
        retry leaves the listing
        incomplete, and so do pages that each answer in time but together outlast the scan's one deadline: the
        reason is recorded, the marker stays, the pages read are counted, and every request starts within the scan's
        window."""
        chain = {"": {"experiments": ["own"], "next": "p2"}}
        chain.update({f"p{n}": {"experiments": [], "next": f"p{n + 1}", "sleep": 0.6} for n in range(2, 10)})
        chain["p10"] = {"experiments": []}
        cases = {
            "late error": ({"": {"experiments": ["own"], "next": "p2"}, "p2": {"fail": True}}, "not listed", 1),
            "malformed": ({"": {"experiments": ["own"], "next": "p2"}, "p2": {"malformed": True}}, "unreadable", 1),
            "two tokens": ({"": {"experiments": ["own"], "next": "p2"},
                            "p2": {"experiments": [], "next": "p3", "cli_next": "p4"}}, "two continuation tokens", 2),
            "repeated token": ({"": {"experiments": ["own"], "next": "p2"},
                                "p2": {"experiments": [], "next": "p2"}}, "continuation token", 2),
            "token cycle": ({"": {"experiments": ["own"], "next": "p2"}, "p2": {"experiments": [], "next": "p3"},
                             "p3": {"experiments": [], "next": "p2"}}, "continuation token", 3),
            "hung page": ({"": {"experiments": ["own"], "next": "p2"},
                           "p2": {"experiments": [], "sleep": 1.5}}, "not listed", 1),
            "deadline": (chain, "after", None),
        }
        for name, (pages, reason, read) in cases.items():
            with self.subTest(name):
                episode = f"e-{name.replace(' ', '-')}"
                self.plan(aws={"volumes": [volume()], "experiment_pages": pages})
                code, out, section = self.run_episode(episode=episode, aws_seconds=1)
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(reason, section["template_experiments_unconfirmed"], out)
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / f"fis-{episode}.json").exists(), "the quarantine stays")
                tokens = self.page_tokens()
                self.assertEqual(tokens[:2], ["-", "p2"], out)
                times = [float(line) for line in (self.state / "page-times.log").read_text().split()]
                # The scan's window is the effect timeout plus one AWS-call allowance from the deletion.
                window = self.operator["effect_timeout_seconds"] + 1
                self.assertLess(times[-1] - times[0], window, "no request starts past the scan's deadline")
                if read is not None:
                    self.assertEqual(section["experiment_pages"], read, out)
                else:
                    self.assertGreaterEqual(section["experiment_pages"], 3, "the scan advanced page by page")
                    self.assertNotIn("p10", tokens, "the deadline cut the chain")

    def test_the_quarantine_marker_is_armed_before_the_start_and_lifted_by_a_confirmed_end(self):
        """The durable marker exists when the template's creation request leaves, naming the creation's tag, so a
        hard kill or reboot from then on leaves the host quarantined with the template findable; an episode whose
        template is gone, whose experiment ended and whose volume restored lifts it."""
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertEqual((self.state / "armed-at-create").read_text(), "1", "the marker was armed before the creation")
        self.assertEqual((self.state / "armed-at-start").read_text(), "1", "the marker was armed before the start")
        token = (self.state / "create-tokens.log").read_text().split()[0]
        self.assertIn(f"template tagged request={token}", (self.state / "armed-text-at-create").read_text())
        self.assertEqual(list((self.state / "custody").glob("fis-*.json")), [], "a confirmed end lifted it")
        self.assertNotIn("quarantine", section)
        record_path = self.state / "custody" / "fis-e1.json"
        self.plan(aws={"volumes": [volume()], "start": False})
        code, out, section = self.run_episode()
        self.assertTrue(section.get("fault_end_unconfirmed"), out)
        self.assertTrue(record_path.exists(), "a start whose outcome is unknown keeps the marker")
        self.assertIn("after the episode", json.loads(record_path.read_text())["custody"])

    def test_an_arming_that_fails_sends_no_start_and_discovers_none(self):
        """A marker that cannot be written before the start, here a symlink planted at its name after the host's
        custody check, leaves no request marked: no start is sent, cleanup lists nothing, the receipt names no
        unconfirmed start, and the planted link is removed from the marker's name with its target untouched."""
        self.plan(aws={"volumes": [volume()], "plant_marker_symlink_at_describe": 2})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["status"]), (1, "CONTROLLER_LOST"), out)
        self.assertIn("Too many levels of symbolic links", section["first_failure"])
        self.assertNotIn("fis create-experiment-template", self.calls(), "the arming precedes the creation")
        self.assertNotIn("fis start-experiment", self.calls())
        self.assertNotIn("fis list-experiments", self.calls())
        self.assertNotIn("start_unconfirmed", section)
        self.assertNotIn("quarantine", section, "nothing was injected, so nothing is quarantined")
        self.assertFalse((self.state / "custody" / "fis-e1.json").is_symlink(), "the planted link is gone")
        self.assertEqual((self.state / "elsewhere-marker").read_text(), "kept")

    def test_an_unconfirmed_fault_end_quarantines_the_host_for_the_next_campaign(self):
        """A fault whose end stays unconfirmed may still act on the volume after the controller exits; the
        episode leaves a custody marker with no group, and the next campaign or sweep exits held until an
        operator removes it."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "volume_status": "impaired"},
                  lane={"observe": ["restored"]})
        code, out, section = self.run_episode()
        self.assertTrue(section.get("fault_end_unconfirmed"), out)
        marker = Path(section["quarantine"])
        self.assertTrue(marker.exists(), section["quarantine"])
        record = json.loads(marker.read_text())
        self.assertIsNone(record["pgid"])
        self.assertIn("unconfirmed", record["custody"])
        # The marker and the receipt name every resource an operator needs to confirm the fault over.
        self.assertIn("experiment EXP1", record["custody"])
        self.assertIn("template EXT1", record["custody"])
        self.assertIn(f"start token {section['start_token']}", record["custody"])
        self.assertEqual((section["experiment_id"], section["template_id"]), ("EXP1", "EXT1"))
        # The marker names nothing a reboot ends, so the sweep holds it from any boot.
        self.assertTrue(record["durable"])
        spec = importlib.util.spec_from_file_location("lane", str(ROOT / "scripts/hardware-lane.py"))
        lane = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(lane)
        marker.write_text(json.dumps({**record, "boot": "another-boot"}))
        self.assertEqual(len(lane.held_custody(marker.parent)), 1, "held across a reboot")
        self.assertTrue(marker.exists())
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, section = self.run_episode(command="campaign", keep_custody=True)
        self.assertEqual(code, 4, out)
        self.assertIn("custody held on this host", out)
        self.assertEqual(self.calls(), [], "nothing ran beside the unconfirmed fault")

    def test_an_operator_whose_cleanup_after_a_signal_outlasts_the_kill_grace_is_rejected(self):
        """The cleanup's four effect windows, each with one AWS call, the lane's close and the close-out must fit the
        step's kill grace; the widest contract that fits is admitted, one second more is rejected before any call."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        close = max(module.close_seconds(profile, module.lane.MANIFEST) for profile in manifest["profiles"].values())
        def widest(grace):
            return int((grace - close - module.CLOSE_OUT_SECONDS - 120) / module.CLEANUP_PATH_WINDOWS - 60)

        default = module.KILL_GRACE_SECONDS
        # A grace other than the default, which admits the suite's 2 s effect timeout and rejects the default's widest.
        narrow = close + module.CLOSE_OUT_SECONDS + module.CLEANUP_PATH_WINDOWS * (2 + 60) + 120
        cases = ((widest(default), None, 0), (widest(default) + 1, None, 2),
                 (widest(narrow), narrow, 0), (widest(narrow) + 1, narrow, 2), (widest(default), narrow, 2))
        for effect, grace, code in cases:
            with self.subTest(effect=effect, grace=grace):
                self.operator["effect_timeout_seconds"] = effect
                (self.state / "calls.log").unlink(missing_ok=True)
                extra = [] if grace is None else ["--kill-grace-seconds", str(grace)]
                got, out, section = self.run_episode(aws_seconds=60, extra=extra)
                self.assertEqual(got, code, out)
                if code == 2:
                    self.assertIn("kill grace", out)
                    self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_an_aws_call_limit_that_is_not_finite_is_rejected_before_any_call(self):
        for value in ("nan", "-5", "inf"):
            with self.subTest(value=value):
                (self.state / "calls.log").unlink(missing_ok=True)
                argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                        str(self.state / "operator.json"), "--aws-seconds", value, "--artifacts", str(self.state / "artifacts")]
                done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertIn("finite duration", done.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_symlink_planted_under_a_mark_s_name_is_refused_rather_than_followed(self):
        """A mark path keeps its own name in the resolved artifacts directory; a symlink there is refused before
        the case is spawned, and the file it points at is left as it was."""
        target = self.state / "elsewhere"
        target.write_text("kept\n")
        artifacts = self.state / "artifacts"
        artifacts.mkdir(exist_ok=True)
        (artifacts / "fis-e1.started").symlink_to(target)
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("is a symlink", section["first_failure"])
        self.assertEqual(target.read_text(), "kept\n", "the symlink's target was neither unlinked nor written")
        self.assertNotIn("fis create-experiment-template", self.calls())
        (artifacts / "fis-e1.started").unlink()

    def test_an_unwritable_custody_directory_is_rejected_before_any_call(self):
        """The quarantine fails closed: a custody directory this account cannot write refuses the run, since an
        unconfirmed fault could leave no marker."""
        if os.geteuid() == 0:
            self.skipTest("root writes everywhere")
        custody = self.state / "custody"
        custody.mkdir(exist_ok=True)
        custody.chmod(0o500)
        self.addCleanup(custody.chmod, 0o700)
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(keep_custody=True)
        self.assertEqual(code, 2, out)
        self.assertIn("not writable", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_a_symlink_planted_under_the_receipt_s_name_is_refused_rather_than_followed(self):
        target = self.state / "elsewhere-receipt"
        target.write_text("kept\n")
        artifacts = self.state / "artifacts"
        artifacts.mkdir(exist_ok=True)
        (artifacts / "fis-fis-read-latency-e1.json").symlink_to(target)
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode()
        self.assertEqual(code, 2, out)
        self.assertIn("receipt path", out)
        self.assertIn("is a symlink", out)
        self.assertEqual(target.read_text(), "kept\n", "the symlink's target was left as it was")
        self.assertEqual(self.calls(), [], "the refusal came before any call or spawn")
        (artifacts / "fis-fis-read-latency-e1.json").unlink()

    def test_a_symlink_planted_under_the_observer_log_s_name_is_refused_before_the_spawn(self):
        target = self.state / "elsewhere-log"
        target.write_text("kept\n")
        observer = self.state / "observer"
        observer.mkdir(exist_ok=True)
        (observer / "e1.jsonl").symlink_to(target)
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(keep_observer=True)
        self.assertEqual(code, 2, out)
        self.assertIn("observer log", out)
        self.assertIn("is a symlink", out)
        self.assertEqual(target.read_text(), "kept\n", "the symlink's target was left as it was")
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_a_run_its_deadline_cut_gets_one_stop_request_in_cleanup_and_leaves_the_fault_end_unconfirmed(self):
        """The run deadline passed with the experiment live: cleanup sends one stop request, the one call the bound
        holds for it, and leaves the fault's end unconfirmed for an operator; a run a signal ended early keeps its
        windows, so cleanup waits for the stop's end and polls the restoration."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        for interrupted, expected in ((False, ["fis stop-experiment"]),
                                      (True, ["fis stop-experiment", "fis get-experiment"])):
            with self.subTest(interrupted=interrupted):
                run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
                calls = []
                run.aws = lambda *argv, calls=calls, **_: calls.append(" ".join(argv[:2])) or None
                run.experiment_id, run.run_deadline, run.interrupted = "EXP1", time.monotonic() - 1, interrupted
                run.cleanup()
                self.assertEqual(sorted(set(calls)), sorted(expected), calls)
                self.assertEqual(run.section["abort"], "refused", "no acceptance was seen")
                self.assertTrue(run.section["fault_end_unconfirmed"])

    def test_a_run_deadline_that_passes_during_the_abandon_wait_still_cuts_cleanup_to_one_stop_request(self):
        """The watch returns with the stop accepted and its end unseen while the run deadline has a moment left; the
        abandon wait in `finish()` crosses that deadline, so cleanup has no run time left for the stop's wait and
        sends nothing more: the fault's end stays unconfirmed for an operator."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="bash -c 'trap \"\" TERM; sleep 60'", custody=str(self.state / "custody"))
        module.run_bound = lambda *_: 0.5
        module.phase_bound = lambda *_: 10.0
        run = module.Episode(args, self.loaded, "fis-read-latency", {**self.operator, "effect_timeout_seconds": 1})
        run.close_seconds = 0.5
        calls = []
        run.aws = lambda *argv, **_: calls.append(" ".join(argv[:2])) or None
        run.validate = lambda deadline=None: None
        run.observer.ready = lambda role, after=0: {"ordinal": after + 1}
        run.create = lambda token: "EXT1"
        run.start = lambda template: {"experiment": {"id": "EXP1"}}

        def watch():
            run.section["abort"], run.section["fault_end_unconfirmed"] = "issued", True
            run.fail("INCONCLUSIVE", "the experiment outlived its duration", "HALTED")
        run.watch = watch
        run.run()
        self.addCleanup(lambda: (run.case.kill(), run.case.wait()))
        self.assertIsNotNone(run.section["case_exit"], "finish abandoned and ended the case")
        begun = time.monotonic()
        run.cleanup()
        self.assertLess(time.monotonic() - begun, 1.5, "cleanup spent the deletion window only, no stop-wait window")
        self.assertEqual([call for call in calls if call.startswith("fis get-experiment")], [],
                         "no wait for the stop's end once the run deadline passed")
        self.assertTrue(run.section["fault_end_unconfirmed"])
        self.assertEqual(run.section["abort"], "issued", "the accepted stop is not asked for again")

    def test_a_case_that_outlives_its_seconds_under_a_live_experiment_is_abandoned_and_cleanup_stops_the_fault(self):
        """`finish()` abandons a case past its seconds and leaves a live experiment to cleanup, whose stop a cut run
        bounds to one request; the abandon wait and the lane's close are the only windows finish spends."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1, case_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", {**self.operator, "effect_timeout_seconds": 1})
        calls = []
        run.aws = lambda *argv, **_: calls.append(" ".join(argv[:2])) or None
        run.close_seconds = 0.5
        run.experiment_id, run.run_deadline = "EXP1", time.monotonic() - 1
        run.case = subprocess.Popen(["bash", "-c", "trap '' TERM; sleep 60"])
        self.addCleanup(lambda: (run.case.kill(), run.case.wait()))
        begun = time.monotonic()
        run.finish()
        self.assertLess(time.monotonic() - begun, 4.0, "one second for the case, the abandon wait, half to close")
        self.assertEqual(calls, [], "finish sent no AWS call; the live experiment is cleanup's")
        run.cleanup()
        self.assertEqual([call for call in calls if call.startswith("fis ")], ["fis stop-experiment", "fis delete-experiment-template"] if run.template_id else ["fis stop-experiment"])

    def test_a_phase_window_ends_with_the_run_deadline(self):
        """A phase's window is cut at the run deadline, so a phase that starts with little run time left ends with
        the run rather than at a later local deadline of its own."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        run.aws = lambda *argv, **_: None
        run.run_deadline = time.monotonic() + 0.3
        begun = time.monotonic()
        self.assertFalse(run.poll_restored())
        self.assertLess(time.monotonic() - begun, 1.0, "the restoration poll ended with the run, within the 2 s window")
        self.assertTrue(run.section["fault_end_unconfirmed"])
        run.run_deadline = None
        self.assertGreater(run.window(5.0) - time.monotonic(), 4.0, "with no run deadline the window is its own")

    def test_a_cleanup_that_fails_partway_still_leaves_the_quarantine_marker_and_the_receipt(self):
        """A cleanup error leaves whatever it did not confirm unconfirmed: the episode records the failure, writes
        the durable marker for a live experiment and still writes its receipt."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")

        def broken_cleanup(self):
            self.experiment_id = "EXP9"
            self.case = subprocess.Popen(["sleep", "30"])
            raise OSError("no space left for the abandonment mark")

        module.Episode.cleanup = broken_cleanup
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual(code, 4, "a case still alive after a failed cleanup is unknown custody: " + json.dumps(section))
        self.assertIn("may still hold the devices", section["custody_unknown"])
        self.assertEqual(section["status"], "CONTROLLER_LOST")
        self.assertTrue(Path(section["quarantine"]).exists(), "a live case keeps the host quarantined after the exit")
        self.assertIn("no space left", section["cleanup_failure"])
        self.assertTrue(section["fault_end_unconfirmed"])
        self.assertTrue(Path(section["quarantine"]).exists())
        receipt = self.state / "artifacts" / "fis-fis-read-latency-unit.json"
        self.assertEqual(json.loads(receipt.read_text())["fis"]["cleanup_failure"], section["cleanup_failure"])
        # A live case with no experiment and no start requested, say a lane still building, quarantines the host too.
        Path(section["quarantine"]).unlink()

        def broken_before_any_start(self):
            self.case = subprocess.Popen(["sleep", "30"])
            raise OSError("no space left for the abandonment mark")

        module.Episode.cleanup = broken_before_any_start
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertEqual(code, 4, json.dumps(section))
        self.assertNotIn("fault_end_unconfirmed", section)
        self.assertTrue(Path(section["quarantine"]).exists(), "the orphaned lane may still start its case")
        record = json.loads(Path(section["quarantine"]).read_text())
        self.assertIn("may still hold the devices", record["custody"], "the marker names the case in doubt")
        self.assertNotIn("fault's end is unconfirmed", record["custody"], "no fault is in doubt")
        self.assertNotIn("durable", record, "a case in doubt alone is a process hazard a reboot ends")
        self.assertIsNone(record["pgid"])
        # A template created, or requested, and not confirmed gone when cleanup failed admits starts, so the fault
        # stays in doubt and the durable marker names the template's tag; a template confirmed gone lifts nothing more.
        Path(section["quarantine"]).unlink()

        def broken_with_a_template(self):
            self.lost_creation = "unit-template-1"
            self.template_id = "EXT9"
            raise OSError("no space left for the deletion")

        module.Episode.cleanup = broken_with_a_template
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertNotEqual(code, 0, json.dumps(section))
        self.assertTrue(section["fault_end_unconfirmed"], "the template may remain")
        record = json.loads(Path(section["quarantine"]).read_text())
        self.assertIn("template tagged request=unit-template-1 may remain", record["custody"])
        self.assertTrue(record["durable"])
        Path(section["quarantine"]).unlink()

        def broken_after_the_deletion(self):
            self.lost_creation, self.template_gone = "unit-template-2", True
            raise OSError("no space left for the receipt line")

        module.Episode.cleanup = broken_after_the_deletion
        code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
        self.assertNotEqual(code, 0, json.dumps(section))
        self.assertNotIn("fault_end_unconfirmed", section, "the template was confirmed gone before the failure")
        self.assertNotIn("quarantine", section)

    def test_a_campaign_naming_no_profile_under_a_contract_is_rejected_rather_than_green(self):
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(profile="", command="campaign")
        self.assertEqual(code, 2, out)
        self.assertIn("names no profile", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_an_episode_name_that_is_not_one_path_component_is_rejected(self):
        for name in ("../escape", "a/b", "/abs", ".hidden"):
            with self.subTest(name=name):
                argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                        str(self.state / "operator.json"), "--episode", name, "--artifacts", str(self.state / "artifacts")]
                done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertIn("episode name", done.stderr)
                self.assertFalse((self.state / "artifacts").exists(), "nothing was written under the artifacts")

    def test_an_episode_name_whose_template_tag_would_overflow_is_rejected_before_any_case_runs(self):
        """The campaign's derived names, the template's `episode` tag `{episode}-{profile}` within FIS's 256-character
        tag value and the receipt's temporary `fis-{profile}-{episode}-{profile}.json.partial` within one file name
        component, bound the episode; one character past the tighter bound is refused, one at it is accepted, and the
        client tokens keep their fixed length whatever the name."""
        manifest = json.loads(Path(SCRIPT.parent / "fis-profiles.json").read_text())
        widest = max(map(len, manifest["profiles"]))
        room = min(256 - 1 - widest, 255 - len("fis-") - widest - 1 - 1 - widest - len(".json.partial"))
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(episode=("e" * room) + "x")
        self.assertEqual(code, 2, out)
        self.assertIn("1 characters too long", out)
        self.assertFalse((self.state / "artifacts").exists(), "nothing was written under the artifacts")
        self.assertEqual(self.calls(), [], "no AWS call was made")
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(episode="e" * room)
        self.assertEqual((code, section["verdict"]), (0, "HELD"), "a name at the bound runs the episode: " + out)
        self.assertLessEqual(len((self.state / "create-tokens.log").read_text().split()[0]), 64)
        # A wide profile name doubles in the campaign's receipt name, `fis-{profile}-{episode}-{profile}.json`.
        wide = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        wide["profiles"]["p" * 120] = wide["profiles"].pop("fis-write-latency")
        path = self.state / "wide-profiles.json"
        path.write_text(json.dumps(wide))
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, section = self.run_episode(episode="e" * 106, manifest=path)
        self.assertEqual(code, 2, out)
        self.assertIn("too long for the receipt file name", out)
        self.assertEqual(self.calls(), [], "no AWS call was made")
        # The receipt's temporary, `.json.partial`, is the longest name: with a 100-character profile the room for
        # the episode is 255 - 4 - 100 - 1 - 1 - 100 - 13 = 36 characters, and one more is refused before any call.
        wide["profiles"]["p" * 100] = wide["profiles"].pop("p" * 120)
        path.write_text(json.dumps(wide))
        code, out, section = self.run_episode(episode="e" * 37, manifest=path)
        self.assertEqual(code, 2, out)
        self.assertIn("1 characters too long for the receipt file name", out)
        self.assertEqual(self.calls(), [], "no AWS call was made")
        code, out, section = self.run_episode(episode="e" * 36, manifest=path)
        self.assertNotEqual(code, 2, out)
        self.assertIn("ec2 describe-volumes", self.calls(), "a name at the bound runs the episode")

    def test_a_signal_during_the_template_s_creation_keeps_the_host_quarantined_under_the_tag(self):
        """The creation request is in flight when the signal arrives, so FIS may hold a template under the tag: the
        fault's end stays unconfirmed, the receipt names the tag and the durable marker names it for the operator."""
        self.plan(aws={"volumes": [volume()], "hang": {"create-experiment-template": 5}},
                  lane={"observe": ["timeout", "restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile",
                "fis-read-latency", "--operator", str(self.state / "operator.json"), "--artifacts",
                str(self.state / "artifacts"), "--observer", str(self.state / "observer"), "--episode", "s5",
                "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05",
                "--manifest", str(self.manifest(duration_seconds=1)), "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis create-experiment-template" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.3)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        token = section.get("template_unconfirmed")
        self.assertEqual(token, section["template_token"], json.dumps(section, indent=1))
        marker = self.state / "custody" / "fis-s5.json"
        self.assertTrue(marker.exists(), "the marker armed before the creation stays")
        record = json.loads(marker.read_text())
        self.assertIn(f"template tagged request={token} may remain", record["custody"])
        self.assertTrue(record.get("durable"), record)

    def test_a_lost_template_creation_response_is_retried_with_one_client_token(self):
        self.plan(aws={"volumes": [volume()], "create_lost": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        tokens = (self.state / "create-tokens.log").read_text().split()
        self.assertEqual((len(tokens), len(set(tokens))), (2, 1), "one creation token, sent twice")
        self.assertNotEqual(tokens[0], "-")

    def test_a_template_whose_every_creation_response_was_lost_is_discovered_by_its_request_tag_and_deleted(self):
        self.plan(aws={"volumes": [volume()], "create_lost": 1000})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "FAILED_TO_INJECT"), out)
        self.assertIn("fis list-experiment-templates", self.calls(), "the template carrying this run's request tag is looked up")
        self.assertIn("fis delete-experiment-template", self.calls(), "the discovered template is deleted")
        self.assertNotIn("template_retained", section)

    def test_a_template_lost_at_creation_is_recovered_by_its_own_request_tag_beside_a_stale_one(self):
        """An earlier run of the same episode left a template; this run's creation loses every response. The
        recovery picks the template tagged with this run's request, and deletes that one."""
        self.plan(aws={"volumes": [volume()], "create_lost": 1000, "stale_template": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        deleted = (self.state / "deleted-ids.log").read_text().split()
        self.assertEqual(deleted, ["EXT1"], "this run's template, not the stale one, is deleted")
        self.assertNotIn("template_retained", section)

    def test_a_lost_discovery_listing_is_retried_in_cleanup_before_the_creation_token_is_forgotten(self):
        """Every creation response is lost and the first discovery listing fails too; cleanup retries the listing,
        finds the template under this run's request tag and deletes it. A listing that never answers records the
        tag whose template may remain."""
        self.plan(aws={"volumes": [volume()], "create_lost": 1000, "list_templates_lost": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertEqual((self.state / "deleted-ids.log").read_text().split(), ["EXT1"], out)
        self.assertNotIn("template_unconfirmed", section)
        self.assertNotIn("template_retained", section)
        self.plan(aws={"volumes": [volume()], "create_lost": 1000, "list_templates_lost": 1000})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        token = (self.state / "create-tokens.log").read_text().split()[0]
        self.assertEqual(section["template_unconfirmed"], token)
        # A template that may remain admits starts, so the host stays quarantined as for a retained one, with the
        # marker naming the tag the operator confirms or deletes by.
        self.assertTrue(section["fault_end_unconfirmed"], out)
        marker = json.loads((self.state / "custody" / "fis-e1.json").read_text())
        self.assertIn(f"template tagged request={token} may remain", marker["custody"])
        self.assertNotIn("None", marker["custody"])
        self.assertFalse((self.state / "deleted-ids.log").exists(), "nothing was deleted blind")
        self.assertGreater(int((self.state / "template-listings").read_text()), 1, "the discovery was retried")
        # With no start sent, the deleted template's listing names another principal's experiment: the marker names
        # it, since that experiment may still fault the volume past the template's deletion.
        self.plan(aws={"volumes": [volume()], "volumes_later": [volume(Tags=[])], "volumes_later_from": 3,
                       "listed_twin_after_deletion": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        marker = json.loads((self.state / "custody" / "fis-e1.json").read_text())
        self.assertIn("EXP0", marker["custody"], "the marker names the foreign experiment for the operator")

    def test_a_template_that_lists_late_after_a_lost_creation_is_still_found_and_deleted(self):
        """Every creation response is lost and the first answered listing shows nothing under the request tag;
        cleanup keeps polling until the template lists, then deletes it."""
        self.plan(aws={"volumes": [volume()], "create_lost": 1000, "template_visible_after_listings": 3})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertEqual((self.state / "deleted-ids.log").read_text().split(), ["EXT1"], out)
        self.assertNotIn("template_unconfirmed", section)
        self.assertGreaterEqual(int((self.state / "template-listings").read_text()), 4)

    def test_a_creation_whose_every_response_was_lost_leaves_the_fault_end_unconfirmed_and_halts_the_campaign(self):
        """Every `create-experiment-template` response is lost for the whole window and no discovery listing answers
        in cleanup: FIS may have made the template, which admits starts, so the receipt names its tag, the fault's end
        stays unconfirmed and the durable marker names the tag for the operator; the campaign starts no later profile,
        and nothing is started."""
        self.plan(aws={"volumes": [volume()], "create_lost": 1000, "list_templates_lost": 1000})
        code, out, section = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "FAILED_TO_INJECT"), out)
        self.assertIn("was not created", section["first_failure"])
        self.assertIsNone(section["template_id"])
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        token = (self.state / "create-tokens.log").read_text().split()[0]
        self.assertEqual(section["template_token"], token, "the receipt names the tag an operator finds the template under")
        self.assertEqual(section["template_unconfirmed"], token)
        marker = json.loads((self.state / "custody" / "fis-e1-fis-read-latency.json").read_text())
        self.assertIn(f"template tagged request={token} may remain", marker["custody"])
        self.assertTrue(marker["durable"])
        self.assertIn("fis-pause: unrun; the previous fault's end is unconfirmed", out)
        self.assertNotIn("fis start-experiment", self.calls(), "nothing was started")

    def test_a_manifest_profile_name_that_is_not_one_path_component_is_rejected_before_any_call(self):
        manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        manifest["profiles"]["../escape"] = manifest["profiles"]["fis-read-latency"]
        path = self.state / "escape-profiles.json"
        path.write_text(json.dumps(manifest))
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(manifest=path)
        self.assertEqual(code, 2, out)
        self.assertIn("manifest profile", out)
        self.assertIn("episode name", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")
        self.assertFalse((self.state / "artifacts").exists(), "nothing was written under the artifacts")

    def test_cleanup_cuts_every_call_at_the_window_s_deadline(self):
        """A discovery listing that would hang past the shared deadline is cut at it, so cleanup ends within the
        window and records what the cut listing left unconfirmed."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        # The first discovery listing is lost and the second answers at 2.4 s, past the 2 s deadline; the deletion
        # and its confirmation then have only what is left of the 1.5 s overrun.
        self.plan(aws={"volumes": [volume()], "list_templates_lost": 1,
                       "hang": {"list-experiment-templates": 1.2, "delete-experiment-template": 1.4}})
        (self.state / "template.json").write_text(json.dumps({"tags": {"episode": "unit", "request": "tok"}}))
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws=str(self.state / "aws"), aws_seconds=1.5, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        os.environ["FAKE_STATE"] = str(self.state)
        self.addCleanup(os.environ.pop, "FAKE_STATE", None)
        run.lost_creation = "tok"
        begun = time.monotonic()
        run.cleanup()
        self.assertLess(time.monotonic() - begun, self.operator["effect_timeout_seconds"] + 0.5,
                        "the window and the polling slack: every call is cut at the window's deadline")
        self.assertEqual(run.section["template_unconfirmed"], "tok", "the listing the window cut confirmed nothing")
        self.assertIsNone(run.run_deadline)

    def test_cleanup_s_template_discovery_and_deletion_share_one_effect_window(self):
        """A discovery that answers late leaves the deletion only what the window has left, so cleanup holds the
        two windows the bound counts whatever the path."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        begun = time.monotonic()
        calls = []

        def aws(*argv, **_):
            calls.append(argv[1])
            if argv[1] == "list-experiment-templates" and time.monotonic() - begun > 1.5:
                return {"experimentTemplates": [{"id": "EXT1", "tags": {"request": "tok"}}]}
            return None

        run.aws = aws
        run.lost_creation = "tok"
        run.cleanup()
        self.assertLess(time.monotonic() - begun, self.operator["effect_timeout_seconds"] + 1.0)
        self.assertIn("delete-experiment-template", calls, "the discovered template was handed to the deletion")
        self.assertEqual(run.section["template_retained"], "EXT1")

    def test_a_listing_of_another_shape_in_cleanup_counts_as_unanswered(self):
        """A `list-experiments` or `list-experiment-templates` response whose entries lack a string `id` or carry
        tags or a state that are not objects vouches for nothing: cleanup keeps polling for one it can read and, at
        the window's end, records the start or the template as unconfirmed, with the case still abandoned and the
        template still deleted."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        shapes = {"start": {"list-experiments": {"experiments": [{"id": "EXP1", "tags": None, "state": "running"}]},
                            "list-experiment-templates": {"experimentTemplates": []}},
                  "creation": {"list-experiments": {"experiments": []},
                               "list-experiment-templates": {"experimentTemplates": [{"tags": None}, {"id": 1}]}}}
        for name, answers in shapes.items():
            with self.subTest(name):
                args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                          aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                          observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                          lane="true", manifest="")
                run = module.Episode(args, self.loaded, "fis-read-latency", {**self.operator, "effect_timeout_seconds": 1})
                calls = []

                def aws(*argv, answers=answers, **_):
                    calls.append(argv[1])
                    return answers.get(argv[1], {"experimentTemplate": {"id": "EXT1"}} if argv[1] == "delete-experiment-template" else None)

                run.aws = aws
                run.section["start_token"] = "tok"
                if name == "start":
                    run.template_id, run.requested_ns = "EXT1", 1
                else:
                    run.lost_creation = "tok"
                run.cleanup()
                if name == "start":
                    self.assertEqual(run.section["start_unconfirmed"], "no listing answered")
                    self.assertEqual(run.section["status"], "FAILED_TO_INJECT", "a sent, unconfirmed start")
                    self.assertIn("delete-experiment-template", calls, "cleanup went on to the deletion")
                else:
                    self.assertEqual(run.section["template_unconfirmed"], "tok")
                self.assertTrue(run.section["fault_end_unconfirmed"])
                self.assertGreater(calls.count("list-experiments" if name == "start" else "list-experiment-templates"), 1,
                                   "the unreadable listing was retried")

    def test_a_lost_start_s_discovery_in_cleanup_ends_with_the_run_deadline(self):
        """The run deadline stands through cleanup's discovery of a start whose outcome is unknown, so its listing, the
        stop's wait and the restoration poll spend the run windows the start left rather than windows of their own,
        and the phase bound's two cleanup windows remain the abandon wait and the deletion."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=0.5, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", {**self.operator, "effect_timeout_seconds": 3})
        begun = time.monotonic()
        deleted_at = []

        def aws(*argv, **_):
            if argv[1] == "delete-experiment-template":
                deleted_at.append(time.monotonic() - begun)
                return {"experimentTemplate": {"id": "EXT1"}}
            return None

        run.aws = aws
        run.template_id, run.requested_ns, run.section["start_token"] = "EXT1", 1, "tok"
        run.run_deadline = begun + 1.0
        run.cleanup()
        self.assertEqual(run.section["start_unconfirmed"], "no listing answered")
        self.assertLess(deleted_at[0], 2.0, "the discovery ended with the run deadline, before a window of its own")
        self.assertIsNone(run.run_deadline)

    def test_a_manifest_profile_with_an_unknown_attachment_mode_is_rejected_before_any_call(self):
        """`single` and `multi-attach-one` are the attachment modes this controller implements; a profile naming
        another admits an undefined mode, so it is rejected input before any call, with two attachments declared or
        one."""
        manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        manifest["profiles"]["fis-read-latency"]["attachment"] = "shared"
        path = self.state / "attachment-profiles.json"
        path.write_text(json.dumps(manifest))
        self.operator["attachments"] = {VOLUME: ["i-1", "i-2"]}
        self.plan(aws={"volumes": [volume(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                     {"InstanceId": "i-2", "State": "attached"}])]})
        code, out, section = self.run_episode(manifest=path)
        self.assertEqual(code, 2, out)
        self.assertIn("rejected input", out)
        self.assertIn("attachment", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def multi_attach(self, **changes):
        """A Multi-Attach io2 volume held by the declared instance alone, the target a multi-attach-one profile admits;
        `changes` replace its fields."""
        return volume(VolumeType="io2", MultiAttachEnabled=True, **changes)

    @staticmethod
    def takeover_free(calls):
        """The no-takeover call-set check: every AWS call outside FIS only describes the volumes, so the controller sent
        no attach, detach or other takeover request, the rejected ones included, since the fake logs a call before it
        answers."""
        return {call for call in calls if not call.startswith("fis ")} <= {"ec2 describe-volumes",
                                                                             "ec2 describe-volume-status"}

    def logged(self, name):
        """The entries of a log the fakes append to, empty when the run wrote none."""
        path = self.state / name
        return path.read_text().split() if path.exists() else []

    # The controller's documented requests, each verb with its whole argument list. A target check asks for the
    # volume's full description by its ID alone, so the reply includes every attachment in every state; a listing of
    # experiments names the controller's template; a start carries one token as its client token and its request tag.
    REQUESTS = {
        "ec2 describe-volumes": f"--volume-ids {VOLUME}",
        "ec2 describe-volume-status": f"--volume-ids {VOLUME}",
        "fis create-experiment-template": r"--cli-input-json \{.*\} --client-token template-[0-9a-f]{32}",
        "fis start-experiment": r"--experiment-template-id EXT1 --client-token (start-[0-9a-f]{32}) --tags request=\1",
        "fis get-experiment": "--id EXP[01]",
        "fis stop-experiment": "--id EXP[01]",
        "fis list-experiments": r"--experiment-template-id EXT1( --(next|starting)-token \S+)?",
        "fis list-experiment-templates": "",
        "fis delete-experiment-template": "--id EXT1",
    }

    def undocumented(self):
        """The requests the fake AWS received, over every run of the test, that fall outside `REQUESTS`: another
        service or verb, such as an attach, a detach or a takeover, or a documented verb with other arguments, such
        as a filtered describe or a listing of every template's experiments."""
        path, off = self.state / "requests.log", []
        for request in path.read_text().splitlines() if path.exists() else []:
            verb = " ".join(request.split(" ")[:2])
            shape = self.REQUESTS.get(verb)
            documented = shape is not None and re.fullmatch(
                f"{re.escape(verb)}{' ' if shape else ''}{shape} --region \\S+ --output json", request)
            if not documented:
                off.append(request)
        return off

    @staticmethod
    def one_owner_case(launches, lane_profile):
        """The one-consumer check: the episode launched exactly one case, under `lane_profile` in the owner role."""
        return launches == [f"{lane_profile}/owner"]

    def test_a_multi_attach_profile_holds_on_a_multi_attach_volume_with_its_one_declared_attachment(self):
        """Each Multi-Attach profile runs its fault on a Multi-Attach volume while its one settled attachment is the
        declared instance. The fake AWS holds the readiness wait's describe open until the case posts its readiness,
        and the case posts it only after that describe began, so the wait's describe, the one after readiness and the
        one after the template's creation are each observed once. The receipt names the mode, the controller's calls
        only describe the volume and drive FIS, and the one case ran in the owner role."""
        latency = {"observe": ["timeout", "restored"]}
        # Literal expectations keep the profile checks independent of the code that builds the template and selects
        # the lane.
        cases = {"fis-read-latency-multi-attach": (latency, 1, "aws:ebs:volume-io-latency", "fis-read", {
                     "readIOPercentage": "100", "readIOLatencyMilliseconds": "2000", "writeIOPercentage": "0.1",
                     "writeIOLatencyMilliseconds": "1", "duration": "PT1S"}),
                 "fis-write-latency-multi-attach": (latency, 1, "aws:ebs:volume-io-latency", "fis-write", {
                     "readIOPercentage": "0.1", "readIOLatencyMilliseconds": "1", "writeIOPercentage": "100",
                     "writeIOLatencyMilliseconds": "2000", "duration": "PT1S"}),
                 "fis-family-stop-multi-attach": ({"observe": ["timeout", "stop"], "seconds": 1.0}, 10,
                                                  "aws:ebs:pause-volume-io", "fis-stop", {"duration": "PT10S"})}
        for profile, (lane, duration, action, lane_profile, parameters) in cases.items():
            with self.subTest(profile):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {}, "hold_waiting": True},
                          lane={**lane, "ready_after_describe": True})
                code, out, section = self.run_episode(profile=profile,
                                                      manifest=self.manifest(duration_seconds=duration))
                self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
                self.assertEqual(section["attachment"], "multi-attach-one")
                self.assertTrue(section["release_proof"])
                phases = self.logged("describe-phases.log")
                self.assertEqual([phases.count(phase) for phase in ("waiting", "ready", "created")], [1, 1, 1], phases)
                self.assertEqual(self.logged("describe-holds.log"), ["ready"],
                                 "the case's readiness released the wait's one describe")
                self.assertEqual(self.undocumented(), [], "every check read the volume's whole description")
                self.assertTrue(self.takeover_free(self.calls()), self.calls())
                template = json.loads((self.state / "template.json").read_text())
                fault = template["actions"]["fault"]
                self.assertEqual((fault["actionId"], fault["parameters"]), (action, parameters))
                # The whole document: one action, on the one group that holds the contract's volume and no other.
                request = template["tags"].pop("request")
                self.assertRegex(request, "^template-[0-9a-f]{32}$")
                self.assertEqual(template, {
                    "description": f"{profile} e1", "roleArn": "arn:aws:iam::1:role/fis",
                    "targets": {"Volumes": {"resourceType": "aws:ec2:ebs-volume", "selectionMode": "ALL",
                                            "resourceArns": [f"arn:aws:ec2:us-east-1:111122223333:volume/{VOLUME}"]}},
                    "actions": {"fault": {"actionId": action, "parameters": parameters,
                                          "targets": {"Volumes": "Volumes"}}},
                    "stopConditions": [{"source": "none"}], "tags": {"episode": "e1"}})
                self.assertTrue(self.one_owner_case(self.logged("launches.log"), lane_profile),
                                self.logged("launches.log"))

    def test_the_no_takeover_check_fails_on_a_planted_attach_request(self):
        """The planted control for `takeover_free` and for the request check every test ends with. Planted mutation:
        an `--aws` command that sends one `ec2 attach-volume` in an otherwise eligible Multi-Attach episode, as the
        episode's first call, right before the start, or as its last call. `takeover_free` fails on each run's call
        log, so it reads the whole log and sees a takeover request at the command boundary even when AWS refuses it,
        and the assertion in `tearDown` fails on the request log."""
        fake, planted = self.state / "aws", self.state / "planted"
        attach = f'if [ ! -e "{planted}" ]; then : > "{planted}"; "{fake}" ec2 attach-volume >/dev/null 2>&1; fi'
        wrappers = {
            "first": f'#!/bin/sh\n{attach}\nexec "{fake}" "$@"\n',
            "before the start": f'#!/bin/sh\nif [ "$2" = start-experiment ]; then {attach}; fi\nexec "{fake}" "$@"\n',
            "last": f'#!/bin/sh\n"{fake}" "$@"\ncode=$?\nif [ "$2" = list-experiments ]; then {attach}; fi\n'
                    'exit $code\n',
        }
        wrapper = self.state / "aws-takeover"
        for name, text in wrappers.items():
            with self.subTest(name):
                wrapper.write_text(text)
                wrapper.chmod(0o755)
                planted.unlink(missing_ok=True)
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()]}, lane={"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach",
                                                      extra=("--aws", str(wrapper)))
                self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
                calls = self.calls()
                self.assertEqual(calls.count("ec2 attach-volume"), 1, calls)
                if name == "first":
                    self.assertEqual(calls[0], "ec2 attach-volume")
                elif name == "last":
                    self.assertEqual(calls[-1], "ec2 attach-volume")
                else:
                    self.assertEqual(calls[calls.index("ec2 attach-volume") + 1], "fis start-experiment")
                self.assertFalse(self.takeover_free(calls), "the planted attach request fails the check")
                self.assertEqual(self.undocumented(), ["ec2 attach-volume"])
                with self.assertRaisesRegex(AssertionError, "outside its documented ones"):
                    self.tearDown()
                (self.state / "requests.log").unlink()

    def test_the_request_check_fails_on_a_filtered_describe_and_an_unfiltered_listing(self):
        """The planted control for the request check on a documented verb. Planted mutations, each an `--aws`
        command in an otherwise eligible Multi-Attach episode: one adds a `--query` to every describe, so a reply
        could carry part of the attachment set, and one drops the template from every experiment listing, so the
        listing would name every template's experiments. The check names exactly the altered requests, and the
        assertion in `tearDown` fails on them."""
        fake = self.state / "aws"
        mutations = {
            "a filtered describe": ("describe-volumes", 'args += ["--query", "Volumes[0]"]',
                                    f"ec2 describe-volumes --volume-ids {VOLUME} --region us-east-1 --output json "
                                    "--query Volumes[0]"),
            "an unfiltered listing": ("list-experiments", "del args[2:4]",
                                      "fis list-experiments --region us-east-1 --output json"),
        }
        wrapper = self.state / "aws-altered"
        for name, (verb, change, altered) in mutations.items():
            with self.subTest(name):
                wrapper.write_text(f'#!/usr/bin/env python3\nimport os, sys\nargs = sys.argv[1:]\n'
                                   f'if args[1] == "{verb}":\n    {change}\nos.execv("{fake}", ["{fake}", *args])\n')
                wrapper.chmod(0o755)
                self.plan(aws={"volumes": [self.multi_attach()]}, lane={"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach",
                                                      extra=("--aws", str(wrapper)))
                self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
                off = self.undocumented()
                self.assertEqual(set(off), {altered})
                self.assertEqual(len(off), self.calls().count(" ".join(altered.split(" ")[:2])))
                with self.assertRaisesRegex(AssertionError, "outside its documented ones"):
                    self.tearDown()
                (self.state / "requests.log").unlink()
                (self.state / "calls.log").unlink()

    @staticmethod
    def call_sites(source):
        """The AWS requests and the process launches the controller's source can make: the service and verb of every
        call of an `aws` method, None for one that is no string literal, and the function and callee of each call
        that starts a process, once per call site."""
        requests, launches = set(), []
        for function in (node for node in ast.walk(ast.parse(source)) if isinstance(node, ast.FunctionDef)):
            for call in (node for node in ast.walk(function) if isinstance(node, ast.Call)):
                callee = call.func
                if not (isinstance(callee, ast.Attribute) and isinstance(callee.value, ast.Name)):
                    continue
                if callee.attr == "aws":
                    requests.add(tuple(argument.value if isinstance(argument, ast.Constant) else None
                                       for argument in call.args[:2]))
                elif callee.value.id == "subprocess" or (callee.value.id == "os" and callee.attr.startswith(
                        ("system", "popen", "exec", "spawn", "posix_spawn", "fork"))):
                    launches.append((function.name, f"{callee.value.id}.{callee.attr}"))
        return requests, sorted(launches)

    # Every AWS request the controller's source can make, and its two process launches: the AWS command and the case.
    SOURCE_REQUESTS = {("ec2", "describe-volumes"), ("ec2", "describe-volume-status"),
                       ("fis", "create-experiment-template"), ("fis", "start-experiment"), ("fis", "get-experiment"),
                       ("fis", "stop-experiment"), ("fis", "list-experiments"), ("fis", "list-experiment-templates"),
                       ("fis", "delete-experiment-template")}
    SOURCE_LAUNCHES = [("aws", "subprocess.run"), ("run", "subprocess.Popen")]

    def test_the_controller_s_source_sends_only_describes_and_fis_calls(self):
        """The call-set check judges the requests the suite's episodes send; this check lists the call sites of the
        source, the ones on paths the episodes leave unrun included. Each call of an `aws` method names its service
        and verb as literals, the two describes and seven FIS verbs, and the calls into `subprocess` are the AWS
        command's and the case's. A request sent some other way is outside it. Planted mutations, each one line
        added to the source text: a detach request in the signal handler, a request whose verb is a variable, the
        `--aws` command run directly from cleanup, and a second case launched beside the first. The check differs
        from the expected requests and launches on each planted source."""
        source = SCRIPT.read_text()
        self.assertEqual(self.call_sites(source), (self.SOURCE_REQUESTS, self.SOURCE_LAUNCHES))
        handler = '        self.section["status"] = "CONTROLLER_LOST"\n        raise KeyboardInterrupt\n'
        cleanup = "        self.delete_template()\n\n    def reconcile(self, cut):\n"
        spawned = "        self.case = case\n"
        planted = {
            "a detach request": (handler, '        self.aws("ec2", "detach-volume", "--force")\n' + handler,
                                 (self.SOURCE_REQUESTS | {("ec2", "detach-volume")}, self.SOURCE_LAUNCHES)),
            "a verb in a variable": (handler, '        self.aws("ec2", self.verb)\n' + handler,
                                     (self.SOURCE_REQUESTS | {("ec2", None)}, self.SOURCE_LAUNCHES)),
            "a direct launch": (cleanup, '        subprocess.run([self.args.aws, "ec2", "detach-volume"])\n' + cleanup,
                                (self.SOURCE_REQUESTS, sorted(self.SOURCE_LAUNCHES + [("cleanup", "subprocess.run")]))),
            "a second case": (spawned, spawned + "        subprocess.Popen(argv)\n",
                              (self.SOURCE_REQUESTS, sorted(self.SOURCE_LAUNCHES + [("run", "subprocess.Popen")]))),
        }
        for name, (anchor, replacement, found) in planted.items():
            with self.subTest(name):
                self.assertEqual(source.count(anchor), 1)
                self.assertEqual(self.call_sites(source.replace(anchor, replacement)), found)

    def test_the_one_owner_case_check_fails_on_a_case_launched_in_another_role(self):
        """The planted control for `one_owner_case`. Planted mutation: a manifest whose Multi-Attach read profile
        launches its case in a role `second` the hardware manifest declares beside `owner`, on an eligible volume.
        The check fails on the episode's launch log, which names the role the lane was started in."""
        hardware = json.loads(self.hardware_manifest.read_text())
        roles = hardware["profiles"]["fis-read"]["roles"]
        roles["second"] = roles["owner"]
        self.hardware_manifest.write_text(json.dumps(hardware))
        path = self.manifest(duration_seconds=1)
        self.loaded["profiles"]["fis-read-latency-multi-attach"]["lane"]["role"] = "second"
        path.write_text(json.dumps(self.loaded))
        self.plan(aws={"volumes": [self.multi_attach()]}, lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach", manifest=path)
        self.assertIn("fis start-experiment", self.calls(), out)
        launches = self.logged("launches.log")
        self.assertEqual(launches, ["fis-read/second"])
        self.assertFalse(self.one_owner_case(launches, "fis-read"), "the planted role fails the check")

    def test_each_multi_attach_profile_is_its_single_twin_with_another_attachment_mode(self):
        """The checked-in Multi-Attach profiles are the read, write and family-stop profiles with the attachment mode
        alone changed, so a Multi-Attach episode runs the same fault, timeouts and lane case as its single twin."""
        profiles = json.loads((ROOT / "scripts/fis-profiles.json").read_text())["profiles"]
        twins = {}
        for name, profile in profiles.items():
            if profile["attachment"] == "multi-attach-one":
                self.assertTrue(name.endswith("-multi-attach"), name)
                twin = name.removesuffix("-multi-attach")
                self.assertIn(twin, profiles, f"{name} has a single twin")
                twins[twin] = name
                self.assertEqual({**profile, "attachment": "single"}, profiles[twin], name)
        self.assertEqual(sorted(twins), ["fis-family-stop", "fis-read-latency", "fis-write-latency"])

    def test_a_multi_attach_profile_refuses_any_other_volume_before_any_injection(self):
        """A Multi-Attach profile admits only a Multi-Attach volume whose one attachment, settled, is the declared
        instance: Multi-Attach disabled or unreported, no attachment, a second attachment settled or settling, and
        another instance are each INVALID, with nothing injected and no case started."""
        both = [{"InstanceId": "i-1", "State": "attached"}, {"InstanceId": "i-2", "State": "attached"}]
        cases = {
            "multi-attach disabled": (volume(VolumeType="io2", MultiAttachEnabled=False), "Multi-Attach disabled"),
            "multi-attach unreported": (volume(VolumeType="io2"), "Multi-Attach disabled"),
            "no attachment": (self.multi_attach(Attachments=[]), "0 attachments under a Multi-Attach profile"),
            "a second attachment": (self.multi_attach(Attachments=both), "2 attachments under a Multi-Attach profile"),
            "a second attachment settling": (
                self.multi_attach(Attachments=[both[0], {"InstanceId": "i-2", "State": "attaching"}]), "not attached"),
            "another instance": (self.multi_attach(Attachments=[{"InstanceId": "i-9", "State": "attached"}]),
                                 "not the declared set"),
        }
        # The one attachment in each state other than `attached`, the unstated one included.
        for state in ("attaching", "detaching", "detached", "busy", None):
            unsettled = {"InstanceId": "i-1", **({"State": state} if state else {})}
            cases[f"the one attachment {state or 'unstated'}"] = (self.multi_attach(Attachments=[unsettled]),
                                                                  f"{state or 'unknown'!r}, not attached")
        for name, (described, reason) in cases.items():
            with self.subTest(name):
                self.plan(aws={"volumes": [described]})
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was injected")
                self.assertTrue(self.takeover_free(self.calls()), self.calls())
                self.assertFalse((self.state / "lane-ran").exists(), "the case never started")
                self.assertEqual(section["status"], "NOT_STARTED")

    def test_a_second_attachment_at_any_recheck_invalidates_the_multi_attach_episode(self):
        """A second attachment that appears at one recheck alone, during the readiness wait, once the case is ready,
        once the template is created, or before the retry of a start whose response was lost, invalidates the
        episode: nothing more is started, and a start FIS may already have accepted is discovered, stopped by its ID
        and named in the receipt. The readiness wait's one describe is held open until the case is ready, so the
        `ready` answer reaches the describe after readiness alone, and the started phase's experiment runs past the
        stop's window unless stopped."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        # A creation or a start is sent again after a lost reply and after a reply that names no usable ID; the
        # check after the template follows a creation sent once or twice.
        for phase, waiting_from, resent in (("waiting", 1, {}), ("waiting", 2, {}), ("ready", 1, {}), ("created", 1, {}),
                                            ("created", 1, {"create_lost": 1}), ("created", 1, {"create_bad_id": 1}),
                                            ("started", 1, {"start_lost": 1}), ("started", 1, {"start_bad_id": 1})):
            with self.subTest(phase, waiting_from=waiting_from, resent=resent):
                (self.state / "calls.log").unlink(missing_ok=True)
                # With `waiting_from` set to 2, the first waiting-phase describe reports an eligible volume; the
                # second reports the added attachment.
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {phase: [second]}, "hold_waiting": True,
                               **resent, "run_seconds": 60,
                               "waiting_from": waiting_from},
                          lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertIn("2 attachments under a Multi-Attach profile", section["first_failure"])
                self.assertTrue((self.state / "lane-ran").exists(), "the case had started")
                self.assertEqual(self.logged("describe-replies.log").count(phase), waiting_from,
                                 "the planted describe of the phase took the second attachment")
                self.assertTrue(self.one_owner_case(self.logged("launches.log"), "fis-read"),
                                self.logged("launches.log"))
                calls = self.calls()
                self.assertTrue(self.takeover_free(calls), calls)
                if phase == "started":
                    self.assertEqual(len((self.state / "start-tokens.log").read_text().split()), 1,
                                     "no start after the refusal")
                    self.assertEqual((self.state / "stopped-ids.log").read_text().split(), ["EXP1"],
                                     "the start FIS may have accepted is stopped by its ID")
                    self.assertEqual((section["experiment_id"], section["status"], section["abort"]),
                                     ("EXP1", "HALTED", "stopped"))
                    self.assertEqual(section["volume_status"], ["ok"], "the volume's status confirmed the end")
                else:
                    self.assertNotIn("fis start-experiment", calls)
                    self.assertNotIn("fis stop-experiment", calls)
                    self.assertEqual((section["status"], section["abort"]), ("NOT_STARTED", None))
                self.assertEqual("fis create-experiment-template" in calls, phase in ("created", "started"))
                if phase in ("created", "started"):
                    self.assertEqual((self.state / "deleted-ids.log").read_text().split(), ["EXT1"],
                                     "the created template is deleted by its ID")
                self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_a_lost_multi_attach_start_is_sent_again_after_a_recheck_that_finds_the_target_unchanged(self):
        """The passing sibling of the rechecks before a retried start: the first start's response is lost, the retry's
        check describes the same eligible volume once, and the start goes out again under its one token, so the
        episode holds. A refusal in those tests comes from the planted change of the target."""
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {}, "hold_waiting": True, "start_lost": 1},
                  lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        phases = self.logged("describe-phases.log")
        self.assertEqual([phases.count(phase) for phase in ("waiting", "ready", "created", "started")],
                         [1, 1, 1, 1], phases)
        tokens = self.logged("start-tokens.log")
        self.assertEqual((len(tokens), len(set(tokens))), (2, 1), "one start token, sent twice")
        self.assertEqual(section["experiment_id"], "EXP1")
        self.assertTrue(self.one_owner_case(self.logged("launches.log"), "fis-read"), self.logged("launches.log"))

    def test_a_target_that_changes_at_any_recheck_invalidates_the_multi_attach_episode(self):
        """Each recheck reads the complete attachment set, so every change of the target a recheck observes, at the
        readiness wait, once the case is ready, once the template is created or before a lost start's retry,
        invalidates the episode: the one attachment moved to another instance, lost, leaving the settled state, joined
        by one still settling, or the volume's Multi-Attach switched off. The planted describe took the change,
        nothing more is started, and a start FIS may already have accepted is stopped by its ID and named."""
        settled = {"InstanceId": "i-1", "State": "attached"}
        changes = {
            "another instance": (self.multi_attach(Attachments=[{"InstanceId": "i-9", "State": "attached"}]),
                                 "not the declared set"),
            "no attachment": (self.multi_attach(Attachments=[]), "0 attachments under a Multi-Attach profile"),
            "detaching": (self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "detaching"}]),
                          "'detaching', not attached"),
            "a second attachment settling": (
                self.multi_attach(Attachments=[settled, {"InstanceId": "i-2", "State": "attaching"}]),
                "'attaching', not attached"),
            "multi-attach disabled": (volume(VolumeType="io2", MultiAttachEnabled=False), "Multi-Attach disabled"),
        }
        for phase in ("waiting", "ready", "created", "started"):
            for name, (changed, reason) in changes.items():
                with self.subTest(phase, change=name):
                    (self.state / "calls.log").unlink(missing_ok=True)
                    self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {phase: [changed]},
                                   "hold_waiting": True, "start_lost": 1 if phase == "started" else 0,
                                   "run_seconds": 60},
                              lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                    code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                    self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                    self.assertIn(reason, section["first_failure"])
                    self.assertEqual(self.logged("describe-replies.log").count(phase), 1,
                                     "the planted describe of the phase took the change")
                    self.assertEqual(len(self.logged("start-tokens.log")), 1 if phase == "started" else 0,
                                     "no start after the refusal")
                    self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"] if phase == "started" else [])
                    self.assertEqual(self.logged("deleted-ids.log"),
                                     ["EXT1"] if phase in ("created", "started") else [])
                    if phase == "started":
                        self.assertEqual((section["experiment_id"], section["status"], section["abort"]),
                                         ("EXP1", "HALTED", "stopped"))
                    self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_a_lost_start_s_discovery_polls_until_a_listing_names_it(self):
        """A lost start's retry is refused for a second attachment, and the template's first two listings come back
        empty, as a listing that lags an accepted start does. Discovery polls on within its window, so the third
        listing's start is stopped by its ID and named, and its end is confirmed."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                       "run_seconds": 60, "list_empty_first": 2})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        calls = self.calls()
        self.assertEqual(calls[:calls.index("fis stop-experiment")].count("fis list-experiments"), 3,
                         "two empty listings preceded the one that named the start")
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["experiment_id"], section["status"], section["abort"]), ("EXP1", "HALTED", "stopped"))
        self.assertNotIn("start_unconfirmed", section, out)
        self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_a_discovered_start_is_asked_to_stop_in_any_live_state_and_named_in_any_state(self):
        """A lost start's retry is refused for a second attachment, and the listing names the controller's start
        in a state other than running. Every state short of a terminal one is live, so the start is stopped by its
        ID and its end confirmed; a start that already ended is named with its state's run status."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        for state in ("pending", "initiating", "stopping"):
            with self.subTest(state):
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                               "run_seconds": 60, "listed_status": state})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
                self.assertEqual((section["experiment_id"], section["status"], section["abort"]),
                                 ("EXP1", "HALTED", "stopped"))
                self.assertNotIn("fault_end_unconfirmed", section, out)
        # A start listed ended is named with the run status of its state, and nothing is asked to stop.
        for state, status in (("completed", "COMPLETED"), ("failed", "FAILED_TO_INJECT"), ("stopped", "HALTED"),
                              ("cancelled", "HALTED")):
            with self.subTest(state):
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                               "run_seconds": 60, "listed_status": state})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertEqual(self.logged("stopped-ids.log"), [])
                self.assertEqual((section["experiment_id"], section["status"], section["abort"]),
                                 ("EXP1", status, None))
                self.assertEqual(section["volume_status"], ["ok"], "the volume's status confirmed the end")
                self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_a_discovered_start_is_stopped_first_and_its_end_needs_the_volume_s_status(self):
        """A lost start's retry is refused for a second attachment. With another principal's live experiment listed
        ahead of the controller's start, the controller's own start is the first asked to stop. With the volume
        reading impaired after the discovered start ended, the fault's end stays unconfirmed and the marker stays."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        base = {"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                "run_seconds": 60}
        self.plan(aws={**base, "listed_twins": True})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(section["experiment_ids"], ["EXP0", "EXP1"], "the other experiment is listed first")
        stopped = self.logged("stopped-ids.log")
        self.assertEqual(stopped[0], "EXP1", "the controller's own start is asked to stop first")
        self.assertIn("EXP0", stopped)
        self.assertEqual((section["experiment_id"], section["unconfirmed_experiments"]), ("EXP1", ["EXP0"]))
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.plan(aws={**base, "volume_status": "impaired"})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["abort"], section["volume_status"]), ("stopped", ["impaired"]))
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_two_late_listed_experiments_under_the_start_s_token_bind_none(self):
        """A lost start's retry is refused, discovery lists nothing, and the deleted template's listing names two
        live experiments under the start's token. The match is ambiguous, so the receipt binds neither, sends no
        stop, and names both as unconfirmed beside the unconfirmed start, with the marker kept."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                       "run_seconds": 60, "discovery_pages": {"": {"experiments": []}},
                       "experiment_pages": {"": {"experiments": ["own", "twin"], "own_status": "running"}}})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIsNone(section.get("experiment_id"), out)
        self.assertEqual(self.logged("stopped-ids.log"), [])
        self.assertEqual(section["unconfirmed_experiments"], ["EXP1", "EXP2"])
        self.assertEqual(section["start_unconfirmed"], "no experiment listed")
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_a_refused_retry_whose_start_no_listing_confirms_reads_failed_to_inject(self):
        """A start whose response was lost, a second attachment at the retry's check, and listings that never name
        the controller's start: one start was sent and none is confirmed, so the run status is FAILED_TO_INJECT
        beside the unconfirmed start, and the INVALID verdict stands."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        listings = {"the controller's own start was never listed": {"listed_foreign_only": True},
                    "no experiment listed": {"discovery_pages": {"": {"experiments": []}},
                                             "experiment_pages": {"": {"experiments": []}}},
                    "no listing answered": {"list_failures": 1000}}
        for unconfirmed, listing in listings.items():
            with self.subTest(unconfirmed):
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                               **listing}, lane={"observe": ["timeout", "restored"]})
                # A listing that never answers is retried through one AWS-call allowance after the deletion.
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach", aws_seconds=2)
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertEqual(len(self.logged("start-tokens.log")), 1, "no start after the refusal")
                self.assertEqual(section["status"], "FAILED_TO_INJECT", out)
                self.assertEqual(section["start_unconfirmed"], unconfirmed, out)
                self.assertIsNone(section.get("experiment_id"), out)
                self.assertTrue(section["fault_end_unconfirmed"], out)
                custody = json.loads((self.state / "custody" / "fis-e1.json").read_text())["custody"]
                self.assertIn(f"the unlisted start tagged {section['start_token']}", custody)

    def test_a_readiness_describe_that_fails_or_is_cut_refuses_the_multi_attach_episode(self):
        """The readiness wait's describe leaves the targets unread when it fails, or when the readiness deadline cuts
        it, even with the case's readiness posted on time while the describe was open; either is INCONCLUSIVE and
        nothing is created or started. The cut describe never reached its reply, so the readiness deadline, short of
        the call's own limit, cut it."""
        cases = {"failed": ("fail", "could not be described"),
                 "cut": ({"hang": 20}, "not described before the readiness deadline")}
        for name, (answer, reason) in cases.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"waiting": answer}},
                          lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach",
                                                      manifest=self.manifest(duration_seconds=1, ready_seconds=3))
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")
                self.assertIn("waiting", self.logged("describe-phases.log"))
                self.assertNotIn("waiting", self.logged("describe-replies.log"))
                ready = [event for path in (self.state / "observer").glob("*.jsonl")
                         for event in map(json.loads, path.read_text().splitlines()) if event.get("kind") == "ready"]
                self.assertEqual(len(ready), 1, "the case posted its readiness")

    def test_a_malformed_readiness_describe_is_recorded_and_the_receipt_written(self):
        """A describe reply of another shape, a JSON array or one nested past the decoder's limit, at the readiness
        wait's poll is unreadable telemetry: the episode is INCONCLUSIVE with its receipt written, the case settles,
        and nothing is created or started."""
        cases = {"an array": ("[]", "unreadable shape"),
                 "deep nesting": ("[" * 100000 + "]" * 100000, "could not be described")}
        for name, (raw, reason) in cases.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"waiting": {"raw": raw}}},
                          lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")
                self.assertTrue((self.state / "settled").exists(), "the case settled at the abandon mark")

    def test_the_readiness_wait_checks_the_targets_at_every_poll(self):
        """A Multi-Attach episode checks its targets once before the case is spawned, once at each poll of the
        readiness wait, each cut at the readiness deadline, and once more when the case is ready. The readiness log
        answers five polls with no event and the sixth with the case's readiness, and the check counts its calls."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest), aws="true", aws_seconds=10.0,
                                  poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="sh -c 'exec sleep 60' case", manifest="")
        for profile, waiting in (("fis-read-latency-multi-attach", 5), ("fis-read-latency", 0)):
            with self.subTest(profile):
                run = module.Episode(args, self.loaded, profile, self.operator)
                checks, polls = [], iter([None] * 5)
                run.validate = lambda deadline=None: checks.append("windowed" if deadline else "fixed") or True
                run.observer.ready = lambda role, after=0: next(polls, {"kind": "ready"})
                # The run ends at the template's creation, which this controller is given no answer for.
                run.create = lambda token: None
                with unittest.mock.patch.dict(os.environ, KESTRIKE_MAPPINGS=str(self.state / "mappings")):
                    run.run()
                run.case.kill()
                run.case.wait()
                self.assertEqual(checks, ["fixed"] + ["windowed"] * waiting + ["fixed"])
                self.assertIn("was not created", run.section["first_failure"])
        with self.subTest("a poll within one interval of the readiness deadline"):
            args.poll = 1.0
            run = module.Episode(args, self.loaded, "fis-read-latency-multi-attach", self.operator)
            checks, polls = [], iter([None])
            run.validate = lambda deadline=None: checks.append("windowed" if deadline else "fixed") or True
            run.observer.ready = lambda role, after=0: next(polls, {"kind": "ready"})
            run.create = lambda token: None
            # The readiness window ends half a second after the spawn, half a poll interval away.
            run.window = lambda seconds: time.monotonic() + 0.5
            with unittest.mock.patch.dict(os.environ, KESTRIKE_MAPPINGS=str(self.state / "mappings")):
                run.run()
            run.case.kill()
            run.case.wait()
            self.assertEqual(checks, ["fixed", "windowed", "fixed"])

    def test_a_refusal_in_the_readiness_wait_lets_the_case_reach_readiness_before_it_is_abandoned(self):
        """A case still in its setup holds its group when terminated. A refusal early in the readiness wait, for a
        second attachment, a failed describe or an unreadable reply, with the case's readiness more than one effect
        timeout away, leaves the case to reach its readiness, where it settles at the abandon mark: the episode
        exits with its verdict and no held group."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        refusals = {"a second attachment": ([second], 2, "INVALID", "2 attachments under a Multi-Attach profile"),
                    "a failed describe": ("fail", 1, "INCONCLUSIVE", "could not be described"),
                    "an unreadable reply": ({"raw": "[]"}, 1, "INCONCLUSIVE", "unreadable shape")}
        for name, (answer, exit_code, verdict, reason) in refusals.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"waiting": answer}},
                          lane={"observe": ["timeout", "restored"], "setup_after_describe": 3,
                                "hold_before_ready": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (exit_code, verdict), out)
                self.assertIn(reason, section["first_failure"])
                self.assertNotEqual(section["case_exit"], 4, out)
                self.assertNotIn("custody_unknown", section)
                self.assertTrue((self.state / "settled").exists(), "the case settled at the abandon mark")
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")
                self.assertEqual(section["status"], "NOT_STARTED")
                self.assertEqual(self.logged("describe-phases.log")[-1], "waiting", "the refusal preceded the readiness")
                self.assertEqual(self.logged("describe-phases.log").count("waiting"), 1,
                                 "the wait went on without another describe after the refusal")
                setup = float((self.state / "setup-ended").read_text()) \
                    - (self.state / "waiting-describe").stat().st_mtime
                self.assertGreater(setup, self.operator["effect_timeout_seconds"],
                                   "the case stayed in its setup past the abandon wait that follows a refusal")

    def test_a_start_makes_one_cli_attempt_whatever_the_parent_allows(self):
        """Every start request runs the CLI with AWS_MAX_ATTEMPTS=1, a lost start's retry included, so each resend
        goes back through the controller's target check; every other call keeps the parent's retry setting. The
        family-stop profile's proven stop and a lost deletion reply reach the stop and both listings."""
        self.plan(aws={"volumes": [volume()], "start_lost": 1, "delete_lost": True},
                  lane={"observe": ["timeout", "stop"], "seconds": 1.0})
        code, out, section = self.run_episode(profile="fis-family-stop", manifest=self.manifest(duration_seconds=10),
                                              environ={"AWS_MAX_ATTEMPTS": "5"})
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        attempts = [line.split("=") for line in self.logged("attempts.log")]
        self.assertEqual([value for verb, value in attempts if verb == "start-experiment"], ["1", "1"])
        others = {verb for verb, value in attempts if verb != "start-experiment"}
        self.assertLessEqual({"describe-volumes", "create-experiment-template", "get-experiment", "stop-experiment",
                              "delete-experiment-template", "list-experiment-templates", "list-experiments",
                              "describe-volume-status"}, others)
        self.assertEqual({value for verb, value in attempts if verb != "start-experiment"}, {"5"})

    def test_a_malformed_telemetry_sample_reads_as_unanswered_and_cleanup_still_settles(self):
        """A get-experiment or describe-volume-status reply of another shape is a sample that did not answer: one is
        retried within its window, and replies that stay malformed leave the fault's end unconfirmed while cleanup
        still stops the experiment by its ID, settles the case and deletes the template by its ID. A status reply
        the restoration poll cannot read at all ends the fault's reconciliation as the controller's loss, and cleanup
        still settles the case and deletes the template."""
        self.plan(aws={"volumes": [volume()], "raw_first_gets": 1, "get_raw": "[1]"})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        with self.subTest("a status row keyed by a list"):
            unhashable = {"VolumeStatuses": [{"VolumeId": [VOLUME], "VolumeStatus": {"Status": "ok"}}]}
            self.plan(aws={"volumes": [volume()], "status_raw": json.dumps(unhashable)})
            code, out, section = self.run_episode()
            self.assertEqual((code, section["verdict"], section["status"]), (1, "INCONCLUSIVE", "CONTROLLER_LOST"), out)
            self.assertIn("TypeError", section["cleanup_failure"])
            self.assertTrue(section["fault_end_unconfirmed"], out)
            self.assertEqual(section["case_exit"], 1, "the case was settled")
            self.assertNotIn("custody_unknown", section)
            self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"], "the template is deleted by its ID")
            self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")
        cases = {"every experiment sample": ({"raw_first_gets": 1000, "get_raw": "[1]"}, "telemetry was lost"),
                 "the volume status": ({"status_raw": "[1]"}, "not restored")}
        for name, (aws, reason) in cases.items():
            with self.subTest(name):
                self.plan(aws={"volumes": [volume()], **aws})
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertIn("case_exit", section, "the case was settled")
                self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"], "the template is deleted by its ID")
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")
                if name == "every experiment sample":
                    self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"], "the stop names the experiment")
                    self.assertEqual(section["abort"], "issued", "the stop was accepted and its end never seen")

    def test_an_experiment_sample_is_read_only_in_the_documented_shape(self):
        """Every reader of `get-experiment` takes a reply only when it carries an experiment whose state has a string
        status and whose actions, when present, are an object of objects, each with a state that, when present, is an
        object; any other reply reads as unanswered."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        running = {"id": "EXP1", "state": {"status": "running"}}
        for experiment in (running, {**running, "actions": {}},
                           {**running, "actions": {"fault": {"state": {"status": "running"}}}}):
            self.assertEqual(module.Episode.observed({"experiment": experiment}), experiment)
        unanswered = {
            "no reply": None, "an array": [1], "no experiment": {}, "an experiment that is no object": {"experiment": [running]},
            "no state": {"experiment": {"id": "EXP1"}}, "a state that is no object": {"experiment": {"state": "running"}},
            "no status": {"experiment": {"state": {}}}, "a status that is no string": {"experiment": {"state": {"status": 5}}},
            "actions in a list": {"experiment": {**running, "actions": []}},
            "null actions": {"experiment": {**running, "actions": None}},
            "an action that is no object": {"experiment": {**running, "actions": {"fault": "running"}}},
            "an action state that is no object": {"experiment": {**running, "actions": {"fault": {"state": "running"}}}},
            "a null action state": {"experiment": {**running, "actions": {"fault": {"state": None}}}},
        }
        for name, reply in unanswered.items():
            with self.subTest(name):
                self.assertIsNone(module.Episode.observed(reply))

    def test_the_episode_handlers_record_a_malformed_reply_s_error_and_write_the_receipt(self):
        """An AttributeError or RecursionError that escapes the run or the cleanup is the controller's loss: the
        episode records it, keeps the fault's end unconfirmed for a requested start, writes the marker and the
        receipt."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit", custody=str(self.state / "custody"),
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        receipt = self.state / "artifacts" / "fis-fis-read-latency-unit.json"

        def deep_run(self):
            raise RecursionError("maximum recursion depth exceeded")

        def broken_cleanup(self):
            self.experiment_id = "EXP9"
            raise AttributeError("'list' object has no attribute 'get'")

        def started_run(self):
            self.experiment_id = "EXP9"

        def requested_run(self):
            self.requested_ns = 1

        def broken_reconcile(self, cut):
            raise AttributeError("'list' object has no attribute 'get'")

        # A fault raised inside cleanup's reconciliation of the fault is caught there, so the cleanup's remaining
        # steps still run: `settled` records the template step.
        settled = []
        cases = {"the run": (deep_run, None, None, "RecursionError"),
                 "the cleanup": (lambda self: None, broken_cleanup, None, "AttributeError"),
                 "the reconciliation": (started_run, None, broken_reconcile, "AttributeError"),
                 "the reconciliation of a start with no experiment named": (requested_run, None, broken_reconcile,
                                                                            "AttributeError")}
        original, reconcile = module.Episode.cleanup, module.Episode.reconcile
        module.Episode.delete_template = lambda self: settled.append("template")
        for name, (run, cleanup, broken, kind) in cases.items():
            with self.subTest(name):
                shutil.rmtree(self.state / "custody", ignore_errors=True)
                receipt.unlink(missing_ok=True)
                settled.clear()
                module.Episode.run, module.Episode.cleanup = run, cleanup or original
                module.Episode.reconcile = broken or reconcile
                code, section = module.episode(args, self.loaded, "fis-read-latency", self.operator)
                written = json.loads(receipt.read_text())["fis"]
                self.assertEqual((code, written["verdict"], written["status"]), (1, "INCONCLUSIVE", "CONTROLLER_LOST"))
                self.assertIn(kind, written.get("cleanup_failure") or written["first_failure"])
                if cleanup or broken:
                    self.assertTrue(written["fault_end_unconfirmed"])
                    self.assertTrue(Path(written["quarantine"]).exists(), "the marker holds the host")
                self.assertEqual(settled, [] if cleanup else ["template"])

    def test_an_unreadable_describe_row_is_inconclusive_with_the_receipt_written(self):
        """A describe reply whose fields differ from the response format is unreadable telemetry at the readiness
        poll, and at the pre-run check under a single profile: the episode is INCONCLUSIVE, the controller's loss
        is not recorded, a started case settles, and nothing is created or started."""
        def row(**changes):
            described = self.multi_attach()
            described.update(changes)
            return json.dumps({"Volumes": [{key: value for key, value in described.items() if value is not None}]})
        cases = {
            "a null and a settling state": row(Attachments=[{"InstanceId": "i-1", "State": None},
                                                            {"InstanceId": "i-2", "State": "attaching"}]),
            "no Volumes": "{}",
            "Volumes not a list": json.dumps({"Volumes": {}}),
            "a volume without its type": json.dumps({"Volumes": [{**self.multi_attach(), "VolumeType": None}]}),
            "an attachment without its instance": row(Attachments=[{"State": "attached"}]),
            "a tag without its value": row(Tags=[{"Key": "disposable"}]),
        }
        for name, raw in cases.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"waiting": {"raw": raw}}},
                          lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn("unreadable shape", section["first_failure"])
                self.assertNotEqual(section["status"], "CONTROLLER_LOST")
                self.assertTrue((self.state / "settled").exists(), "the case settled at the abandon mark")
                self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")
        with self.subTest("a falsy non-boolean Multi-Attach flag"):
            (self.state / "calls.log").unlink(missing_ok=True)
            self.plan(aws={"volumes": [volume(MultiAttachEnabled=0)]})
            code, out, section = self.run_episode()
            self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
            self.assertIn("unreadable shape", section["first_failure"])
            self.assertFalse((self.state / "lane-ran").exists(), "the case never started")
            self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")

    def test_a_describe_reply_is_readable_only_in_the_documented_shape(self):
        """The target checks read a describe reply only when every field they read has its documented type: each
        field of another type, alone in an otherwise eligible reply, makes the reply unreadable, and a reply without
        its optional fields, or with a null Multi-Attach flag, stays readable."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        settled, tag = {"InstanceId": "i-1", "State": "attached"}, DISPOSABLE[0]
        readable = {
            "an eligible volume": [self.multi_attach()],
            "no volume": [],
            "no optional field": [{"VolumeId": VOLUME, "VolumeType": "io2"}],
            "a null Multi-Attach flag": [{**self.multi_attach(), "MultiAttachEnabled": None}],
            "an attachment without its state": [self.multi_attach(Attachments=[{"InstanceId": "i-1"}])],
        }
        for name, volumes in readable.items():
            with self.subTest(name):
                self.assertIs(module.readable({"Volumes": volumes}), True)
        unreadable = {
            "no object": [], "no Volumes": {}, "null Volumes": {"Volumes": None}, "Volumes in an object": {"Volumes": {}},
            "a volume that is no object": {"Volumes": [5]},
            "a volume beside one that is no object": {"Volumes": [self.multi_attach(), None]},
        }
        fields = {
            "a volume without its ID": {"VolumeId": None}, "a volume ID that is no string": {"VolumeId": 5},
            "a volume without its type": {"VolumeType": None}, "a type that is no string": {"VolumeType": ["io2"]},
            "a Multi-Attach flag in a string": {"MultiAttachEnabled": "true"},
            "a Multi-Attach flag in a number": {"MultiAttachEnabled": 1},
            "null attachments": {"Attachments": None}, "attachments in an object": {"Attachments": {}},
            "an attachment that is no object": {"Attachments": [settled, 5]},
            "an attachment without its instance": {"Attachments": [{"State": "attached"}]},
            "an instance that is no string": {"Attachments": [{**settled, "InstanceId": 1}]},
            "a null state": {"Attachments": [{**settled, "State": None}]},
            "null tags": {"Tags": None}, "tags in an object": {"Tags": {}},
            "a tag that is no object": {"Tags": [tag, "disposable"]},
            "a tag without its key": {"Tags": [{"Value": "true"}]},
            "a tag without its value": {"Tags": [{"Key": "disposable"}]},
            "a tag value that is no string": {"Tags": [{"Key": "disposable", "Value": True}]},
        }
        for name, change in fields.items():
            unreadable[name] = {"Volumes": [{**self.multi_attach(), **change}]}
        for name, reply in unreadable.items():
            with self.subTest(name):
                self.assertIs(module.readable(reply), False)

    def test_a_failed_describe_at_any_fixed_check_is_inconclusive(self):
        """A describe that fails at the check after readiness, after the template's creation or before a lost
        start's retry leaves the targets unread: the episode is INCONCLUSIVE, nothing more is started, the template
        is deleted by its ID, and a start FIS may have accepted is stopped by its ID."""
        for phase in ("ready", "created", "started"):
            with self.subTest(phase):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {phase: "fail"}, "hold_waiting": True,
                               "start_lost": 1 if phase == "started" else 0, "run_seconds": 60},
                          lane={"observe": ["timeout", "restored"], "ready_after_describe": True})
                code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
                self.assertIn("could not be described", section["first_failure"])
                self.assertEqual(len(self.logged("start-tokens.log")), 1 if phase == "started" else 0)
                self.assertEqual(self.logged("deleted-ids.log"), [] if phase == "ready" else ["EXT1"])
                if phase == "started":
                    self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
                    self.assertEqual(section["experiment_id"], "EXP1")

    def test_a_described_or_reported_volume_must_be_the_target(self):
        """The target checks read only a describe that names exactly the requested volumes, and restoration needs an
        `ok` row named by each target: a reply about another volume, about the target beside another volume, or
        about no volume is INVALID before the start, and an `ok` status for another volume confirms no restoration."""
        replies = {"another volume": [volume(VolumeId="vol-other")],
                   "the target beside another volume": [volume(), volume(VolumeId="vol-other")],
                   "no volume": []}
        for name, described in replies.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()], "volumes_in": {"created": described}})
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
                self.assertIn("a target volume was not described", section["first_failure"])
                self.assertNotIn("fis start-experiment", self.calls())
                self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"])
        self.plan(aws={"volumes": [volume()], "status_volume": "vol-other"})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("not restored", section["first_failure"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_the_mappings_file_is_a_regular_file_within_the_binder_s_byte_bound(self):
        """The controller reads the case's mappings from a regular file of at most 3276766 bytes, the binder's bound:
        a file of exactly that size is read to its last line, one a byte longer is refused, in single-byte and in
        two-byte characters, and a FIFO under the file's name is refused at once as no regular file, an INVALID
        target with nothing described or injected."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.MAPPINGS_BYTES, 3276766)
        path, line = self.state / "mappings", f"nvme.volume={VOLUME}\n".encode()
        with unittest.mock.patch.dict(os.environ, KESTRIKE_MAPPINGS=str(path)):
            path.write_bytes(b"#" * (3276766 - len(line) - 1) + b"\n" + line)
            self.assertEqual(path.stat().st_size, 3276766)
            self.assertEqual(module.mapped_volume(), VOLUME)
            for longer in (b"#" * (3276766 - len(line)) + b"\n" + line, "\u00e9".encode() * 1638384):
                path.write_bytes(longer)
                self.assertGreater(path.stat().st_size, 3276766)
                with self.assertRaisesRegex(module.Rejected, "larger than 3276766 bytes"):
                    module.mapped_volume()
        path.unlink()
        os.mkfifo(path)
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("not a regular file", section["first_failure"])
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_restoration_needs_one_ok_row_named_by_each_target(self):
        """The restoration poll confirms the fault's end only on a status reply that holds exactly one row for the
        target, reading `ok`: a reply of any other content or shape, polled to the window's end, leaves the fault's
        end unconfirmed and fails the episode."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest), aws="true", aws_seconds=10.0,
                                  poll=0.02, episode="unit", observer=str(self.state / "observer"),
                                  artifacts=str(self.state / "artifacts"), lane="true", manifest="")

        def row(name=VOLUME, status="ok"):
            return {"VolumeId": name, "VolumeStatus": {"Status": status}}

        replies = {
            "the target reads ok": ({"VolumeStatuses": [row()]}, True),
            "the target reads impaired": ({"VolumeStatuses": [row(status="impaired")]}, False),
            "another volume reads ok": ({"VolumeStatuses": [row("vol-other")]}, False),
            "no row": ({"VolumeStatuses": []}, False),
            "the target's row beside another volume's": ({"VolumeStatuses": [row(), row("vol-other")]}, False),
            "two rows for the target": ({"VolumeStatuses": [row(), row()]}, False),
            "a row without its status": ({"VolumeStatuses": [{"VolumeId": VOLUME}]}, False),
            "a status in a string": ({"VolumeStatuses": [{"VolumeId": VOLUME, "VolumeStatus": "ok"}]}, False),
            "a status in a list": ({"VolumeStatuses": [{"VolumeId": VOLUME, "VolumeStatus": ["ok"]}]}, False),
            "a row that is no object": ({"VolumeStatuses": ["ok"]}, False),
            "rows in an object": ({"VolumeStatuses": {VOLUME: "ok"}}, False),
            "a reply that is no object": ([row()], False),
            "no reply": (None, False),
        }
        for name, (reply, restored) in replies.items():
            with self.subTest(name):
                run = module.Episode(args, self.loaded, "fis-read-latency-multi-attach", self.operator)
                run.aws = lambda *argv, deadline=None, reply=reply: reply
                run.run_deadline = time.monotonic() + 0.1
                self.assertIs(run.poll_restored(), restored)
                self.assertEqual(run.section.get("fault_end_unconfirmed"), None if restored else True)
                self.assertEqual(run.section["first_failure"], None if restored else "the volume's I/O was not restored")

    def test_a_late_listed_start_is_bound_only_by_one_match_of_its_token(self):
        """A start first listed after the template's deletion is the controller's when exactly one listed
        experiment carries its token: the receipt names it, its listed state sets the run status unless the
        controller's loss is already recorded, a live one is asked to stop once, and its end stays unconfirmed.
        A listed status that is no string names no terminal state, so the start counts as live and is asked to
        stop. No match and two matches bind nothing and send nothing."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest), aws="true", aws_seconds=10.0,
                                  poll=0.02, episode="unit", observer=str(self.state / "observer"),
                                  artifacts=str(self.state / "artifacts"), lane="true", manifest="")

        def listed(ident, state, token="start-unit"):
            return {"id": ident, "state": {"status": state}, "tags": {"request": token}}

        foreign = listed("EXP0", "running", "another")
        # Each row: the listing, whether FIS accepts a stop, the section before, then the ID bound, the run status,
        # the abort and the stop requests expected.
        rows = {
            "a live start": ([foreign, listed("EXP1", "running")], True, {}, "EXP1", "HALTED", "issued", ["EXP1"]),
            "a live start whose stop is refused": ([listed("EXP1", "initiating")], False, {}, "EXP1", "HALTED",
                                                   "refused", ["EXP1"]),
            "a completed start": ([listed("EXP1", "completed")], True, {}, "EXP1", "COMPLETED", None, []),
            "a failed start": ([listed("EXP1", "failed")], True, {}, "EXP1", "FAILED_TO_INJECT", None, []),
            "a stopped start": ([listed("EXP1", "stopped")], True, {}, "EXP1", "HALTED", None, []),
            "a live start after the controller's loss": ([listed("EXP1", "running")], True,
                                                         {"status": "CONTROLLER_LOST"}, "EXP1", "CONTROLLER_LOST",
                                                         "issued", ["EXP1"]),
            "a live start beside one left unconfirmed": ([listed("EXP1", "running")], True,
                                                         {"unconfirmed_experiments": ["EXP0"]}, "EXP1", "HALTED",
                                                         "issued", ["EXP1"]),
            "a start whose status is a list": ([listed("EXP1", ["completed"])], True, {}, "EXP1", "HALTED", "issued",
                                               ["EXP1"]),
            "a start whose status is an object": ([listed("EXP1", {"status": "completed"})], True, {}, "EXP1",
                                                  "HALTED", "issued", ["EXP1"]),
            "a start whose status is null": ([listed("EXP1", None)], True, {}, "EXP1", "HALTED", "issued", ["EXP1"]),
            "no start under the token": ([foreign], True, {}, None, "FAILED_TO_INJECT", None, []),
            "two starts under the token": ([listed("EXP1", "running"), listed("EXP2", "running")], True, {}, None,
                                           "FAILED_TO_INJECT", None, []),
        }
        for name, (experiments, accepts, before, bound, status, abort, stops) in rows.items():
            with self.subTest(name):
                run = module.Episode(args, self.loaded, "fis-read-latency-multi-attach", self.operator)
                run.section.update({"start_token": "start-unit", "status": "FAILED_TO_INJECT", **before})
                sent = []
                run.aws = lambda *argv, deadline=None: sent.append(" ".join(argv)) or ({"experiment": {}} if accepts
                                                                                       else None)
                self.assertEqual(run.late_start(experiments), bound)
                self.assertEqual(sent, [f"fis stop-experiment --id {one}" for one in stops])
                self.assertEqual((run.section.get("experiment_id"), run.section["status"], run.section["abort"]),
                                 (bound, status, abort))
                earlier = before.get("unconfirmed_experiments", [])
                self.assertEqual(run.section.get("unconfirmed_experiments", []), earlier + ([bound] if bound else []))
                self.assertEqual(run.section.get("fault_end_unconfirmed"), True if bound else None)

    def test_a_create_or_start_reply_without_a_usable_id_counts_as_lost(self):
        """A creation or start acknowledgement whose ID is not a nonempty string counts as a lost response: the
        request is sent again with its one client token, and the episode runs on the ID FIS then names."""
        self.plan(aws={"volumes": [volume()], "create_bad_id": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        tokens = self.logged("create-tokens.log")
        self.assertEqual((len(tokens), len(set(tokens))), (2, 1), "one creation token, sent twice")
        self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"])
        self.plan(aws={"volumes": [volume()], "start_bad_id": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["experiment_id"]), (0, "HELD", "EXP1"), out)
        tokens = self.logged("start-tokens.log")
        self.assertEqual((len(tokens), len(set(tokens))), (2, 1), "one start token, sent twice")

    def test_a_lost_start_is_found_on_a_later_page_or_after_the_deletion_and_stopped(self):
        """A lost start's retry is refused for a second attachment. Discovery follows the listing's pages, so a start
        listed only on the second page is stopped by its ID and named; one listed only after the template's
        deletion is bound by its token, named, and asked to stop, with its end left unconfirmed."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        base = {"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                "run_seconds": 60}
        self.plan(aws={**base, "discovery_pages": {"": {"experiments": [], "next": "p2"},
                                                   "p2": {"experiments": ["own"], "own_status": "running"}}})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("p2", self.logged("page-tokens.log"), "the second page was read")
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["experiment_id"], section["abort"]), ("EXP1", "stopped"))
        self.assertNotIn("fault_end_unconfirmed", section, out)
        self.plan(aws={**base, "discovery_pages": {"": {"experiments": []}},
                       "experiment_pages": {"": {"experiments": ["own"], "own_status": "running"}}})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("2 attachments under a Multi-Attach profile", section["first_failure"])
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["experiment_id"], section["status"]), ("EXP1", "HALTED"))
        self.assertEqual(section["unconfirmed_experiments"], ["EXP1"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_a_lost_start_s_discovery_reads_every_page_before_it_stops_the_experiments_listed(self):
        """A lost start's retry is refused for a second attachment. The listing names the controller's start on its
        first page and another principal's live experiment on its second: discovery reads both pages before any
        stop, asks both to stop, its own start first, and the other's end stays unconfirmed with the marker kept. A
        second page that fails through the discovery window leaves the first page's start stopped and confirmed, and
        a second page of an unreadable shape ends the listing, so the start is stopped without another poll."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        base = {"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                "run_seconds": 60}
        first = {"experiments": ["own"], "own_status": "running", "next": "p2"}
        self.plan(aws={**base, "discovery_pages": {"": first, "p2": {"experiments": ["foreign"]}},
                       "experiment_pages": {"": {"experiments": ["own", "foreign"], "own_status": "stopped"}}})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        calls = self.calls()
        self.assertEqual(calls[:calls.index("fis stop-experiment")].count("fis list-experiments"), 2,
                         "both pages were read before the first stop")
        self.assertEqual(self.logged("page-tokens.log")[:2], ["-", "p2"])
        stopped = self.logged("stopped-ids.log")
        self.assertEqual(stopped[0], "EXP1", "the controller's own start is asked to stop first")
        self.assertIn("EXP0", stopped, "the experiment on the later page is asked to stop")
        self.assertEqual((section["experiment_id"], section["experiment_ids"]), ("EXP1", ["EXP1", "EXP0"]))
        self.assertEqual(section["unconfirmed_experiments"], ["EXP0"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")
        self.plan(aws={**base, "discovery_pages": {"": first, "p2": {"fail": True}}})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("p2", self.logged("page-tokens.log"), "the second page was asked for")
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["experiment_id"], section["abort"]), ("EXP1", "stopped"))
        self.assertNotIn("fault_end_unconfirmed", section, out)
        self.plan(aws={**base, "discovery_pages": {"": first, "p2": {"malformed": True}}})
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        calls = self.calls()
        self.assertEqual(calls[:calls.index("fis stop-experiment")].count("fis list-experiments"), 2,
                         "the listing that named the start was taken at its unreadable second page")
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1"])
        self.assertEqual((section["experiment_id"], section["abort"]), ("EXP1", "stopped"))

    def test_a_refused_stop_of_a_discovered_start_is_asked_for_again(self):
        """A discovered start whose first stop FIS refuses, still running, is asked to stop again within the one
        window; the second stop is accepted and the end confirmed."""
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                       "stop_refusals": 1, "run_seconds": 60})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(self.logged("stopped-ids.log"), ["EXP1", "EXP1"])
        self.assertEqual(section["abort"], "stopped")
        self.assertNotIn("fault_end_unconfirmed", section, out)
        # A stop FIS refuses through the whole window leaves the start live: the receipt says so and the marker stays.
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"started": [second]}, "start_lost": 1,
                       "stop_refused": True, "run_seconds": 60})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertGreater(len(self.logged("stopped-ids.log")), 1)
        self.assertEqual(set(self.logged("stopped-ids.log")), {"EXP1"})
        self.assertEqual((section["experiment_id"], section["status"], section["abort"]), ("EXP1", "HALTED", "refused"))
        self.assertEqual(section["unconfirmed_experiments"], ["EXP1"])
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_an_unreadable_first_observation_leaves_the_experiment_unbound(self):
        """A first observation whose fields the binding check cannot read counts as a mismatch: the experiment is
        INVALID and stopped, and its end stays unconfirmed with the marker kept although later samples read well."""
        malformed = {"experiment": {"id": "EXP1", "state": {"status": "running"},
                                    "actions": {"fault": {"state": {"status": "running"}}}, "stopConditions": 5}}
        self.plan(aws={"volumes": [volume()], "raw_first_gets": 1, "get_raw": json.dumps(malformed)})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertIn("differs from the template", section["first_failure"])
        self.assertIn("unbound_targets", section)
        self.assertTrue(section["fault_end_unconfirmed"], out)
        self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_an_over_nested_lane_receipt_is_unreadable_and_cleanup_deletes_the_template(self):
        """A lane receipt nested past the decoder's limit is no readable receipt, read after a run or from cleanup
        after a refusal, and cleanup goes on to delete the template."""
        deep = "[" * 100000 + "]" * 100000
        self.plan(aws={"volumes": [volume()]}, lane={"observe": ["timeout", "restored"], "receipt_text": deep})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("no readable lane receipt", section["first_failure"])
        second = self.multi_attach(Attachments=[{"InstanceId": "i-1", "State": "attached"},
                                                {"InstanceId": "i-2", "State": "attached"}])
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"created": [second]}, "hold_waiting": True},
                  lane={"observe": ["timeout", "restored"], "ready_after_describe": True, "receipt_text": deep})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach")
        self.assertEqual((code, section["verdict"]), (2, "INVALID"), out)
        self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"])
        self.assertNotIn("cleanup_failure", section)
        self.assertNotIn("template_retained", section)

    def test_a_listing_with_a_non_null_continuation_token_is_one_page_of_several(self):
        """A listing is complete only when both continuation fields are absent or null: a service or CLI token of
        any other value, the empty string included, marks it as one page of several."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for complete in ({}, {"nextToken": None}, {"NextToken": None}, {"nextToken": None, "NextToken": None}):
            self.assertIs(module.paged({"experimentTemplates": [], **complete}), False, complete)
        for token in ("more", "", 0, False):
            for spelling in ("nextToken", "NextToken"):
                self.assertIs(module.paged({"experimentTemplates": [], spelling: token}), True, (spelling, token))
        self.assertIs(module.paged([]), False)

    def test_a_lost_creation_is_discovered_only_from_a_complete_template_listing(self):
        """Every creation reply is lost. A listing with null continuation fields is complete, so the one template
        under the request tag is deleted; a listing naming that template on a page with a continuation proves no
        uniqueness, so nothing is deleted and the tag stays named as the template that may remain."""
        self.plan(aws={"volumes": [volume()], "create_lost": 1000,
                       "templates_tokens": {"nextToken": None, "NextToken": None}})
        code, out, section = self.run_episode()
        self.assertEqual(self.logged("deleted-ids.log"), ["EXT1"], out)
        self.assertNotIn("template_unconfirmed", section)
        for spelling in ("nextToken", "NextToken"):
            with self.subTest(spelling):
                self.plan(aws={"volumes": [volume()], "create_lost": 1000, "templates_tokens": {spelling: "more"}})
                code, out, section = self.run_episode()
                self.assertEqual(self.logged("deleted-ids.log"), [], out)
                self.assertEqual(section["template_unconfirmed"], self.logged("create-tokens.log")[0])
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")

    def test_a_case_that_never_readies_while_a_describe_is_cut_records_the_stall(self):
        """A Multi-Attach case that never posts its readiness, with the wait's describe cut by the readiness deadline,
        records the stall before its readiness, and nothing is created or started."""
        self.plan(aws={"volumes": [self.multi_attach()], "volumes_in": {"waiting": {"hang": 20}}},
                  lane={"observe": ["timeout", "restored"], "ready_after_seconds": 30})
        code, out, section = self.run_episode(profile="fis-read-latency-multi-attach",
                                              manifest=self.manifest(duration_seconds=1, ready_seconds=3))
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("stalled before its readiness", section["first_failure"])
        self.assertIn("waiting", self.logged("describe-phases.log"))
        self.assertNotIn("waiting", self.logged("describe-replies.log"))
        self.assertFalse(any(call.startswith("fis") for call in self.calls()), "nothing was created or started")

    def test_a_target_check_under_an_unimplemented_attachment_mode_is_invalid(self):
        """The target check branches on the profile's attachment mode, and a mode with no branch refuses the target,
        so a profile that reached the check under such a mode injects nothing."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1)
        self.loaded["profiles"]["fis-read-latency"]["attachment"] = "shared"
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", self.operator)
        run.aws = lambda *argv, deadline=None: {"Volumes": [volume()]}
        with unittest.mock.patch.dict(os.environ, KESTRIKE_MAPPINGS=str(self.state / "mappings")):
            self.assertIsNone(run.validate())
        self.assertEqual(run.section["verdict"], "INVALID")
        self.assertIn("'shared', which no target check implements", run.section["first_failure"])

    def test_the_target_check_gives_one_answer_whatever_the_episode_has_done(self):
        """The target check is one predicate of the volume's description, the contract and the profile. Each row of
        the table gets the same answer before the case is spawned, while the case runs, and once the template is
        created and a start sent, with and without a window's deadline: eligible, or INVALID with the row's reason.
        So every recheck reads the complete target under either mode, the checks both modes share included."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest), aws="true", aws_seconds=10.0,
                                  poll=0.05, episode="unit", observer=str(self.state / "observer"),
                                  artifacts=str(self.state / "artifacts"), lane="true", manifest="")
        one, two = ({"InstanceId": name, "State": "attached"} for name in ("i-1", "i-2"))
        bases = {"single": ("fis-read-latency", volume(), "single-attachment"),
                 "multi-attach-one": ("fis-read-latency-multi-attach", self.multi_attach(), "Multi-Attach")}
        elsewhere = self.state / "mappings-elsewhere"
        elsewhere.write_text("format=3\nnvme.volume=vol-other\n")
        # The check runs at every poll of a readiness wait, so each call closes the mappings file it opened.
        descriptors = len(os.listdir("/proc/self/fd"))
        for mode, (profile, base, kind) in bases.items():
            # Each row: the fields of the eligible description it changes, the reason, or None for an eligible
            # target, then the profile's latency, the mappings file and the instances the contract declares when
            # the row changes those.
            rows = {
                "the eligible volume": ({}, None),
                "an ineligible type": ({"VolumeType": "unlisted"}, "ineligible for the action"),
                "no tag": ({"Tags": []}, "not tagged disposable"),
                "a disposable tag of false": ({"Tags": [{"Key": "disposable", "Value": "false"}]},
                                              "not tagged disposable"),
                "a second attachment": ({"Attachments": [one, two]}, f"2 attachments under a {kind} profile"),
                "a second attachment settling": ({"Attachments": [one, {"InstanceId": "i-2", "State": "attaching"}]},
                                                 "'attaching', not attached"),
                "no attachment": ({"Attachments": []}, "not the declared set" if mode == "single" else
                                  "0 attachments under a Multi-Attach profile"),
                "another instance": ({"Attachments": [{"InstanceId": "i-9", "State": "attached"}]},
                                     "not the declared set"),
                "an unstated attachment": ({"Attachments": [{"InstanceId": "i-1"}]}, "'unknown', not attached"),
                "another volume": ({"VolumeId": "vol-other"}, "a target volume was not described"),
                "a latency above the bound": ({}, "outside", 60001),
                "a latency below the type's least": ({}, "outside", 0),
                "a target outside the mappings": ({}, "unexpected targets", None, elsewhere),
                "two attachments, both declared": ({"Attachments": [one, two]}, f"2 attachments under a {kind} profile",
                                                   None, None, ["i-1", "i-2"]),
                "no attachment and none declared": ({"Attachments": []}, None if mode == "single" else
                                                    "0 attachments under a Multi-Attach profile", None, None, []),
            }
            for state in ("attaching", "detaching", "detached", "busy"):
                rows[f"the one attachment {state}"] = ({"Attachments": [{"InstanceId": "i-1", "State": state}]},
                                                      f"{state!r}, not attached")
            if mode == "single":
                rows["Multi-Attach enabled"] = ({"MultiAttachEnabled": True}, "Multi-Attach enabled under a single")
            else:
                for name, flag in (("disabled", {"MultiAttachEnabled": False}), ("null", {"MultiAttachEnabled": None}),
                                   ("disabled on another type", {"MultiAttachEnabled": False, "VolumeType": "gp3"})):
                    rows[f"Multi-Attach {name}"] = (flag, "Multi-Attach disabled or unreported")
            replies = {name: ([{**base, **change}], *rest) for name, (change, *rest) in rows.items()}
            replies["no described volume"] = ([], "a target volume was not described")
            replies["a volume beside the target"] = ([base, {**base, "VolumeId": "vol-other"}],
                                                     "a target volume was not described")
            if mode == "multi-attach-one":
                replies["Multi-Attach unreported"] = (
                    [{key: value for key, value in base.items() if key != "MultiAttachEnabled"}],
                    "Multi-Attach disabled or unreported")
            for name, (described, reason, *rest) in replies.items():
                latency, mappings, declared = (*rest, None, None, None)[:3]
                operator = self.operator if declared is None else {**self.operator, "attachments": {VOLUME: declared}}
                for done in ("before the spawn", "the case running", "a start sent"):
                    for deadline in (None, time.monotonic() + 60):
                        with self.subTest(mode, row=name, done=done, windowed=deadline is not None):
                            self.manifest(duration_seconds=1)
                            if latency is not None:
                                self.loaded["profiles"][profile]["latency_ms"] = latency
                            run = module.Episode(args, self.loaded, profile, operator)
                            run.aws = lambda *argv, deadline=None, described=described: {"Volumes": described}
                            if done != "before the spawn":
                                run.case = unittest.mock.Mock(**{"poll.return_value": None})
                                run.run_deadline = time.monotonic() + 60
                            if done == "a start sent":
                                run.template_id, run.lost_creation, run.requested_ns = "EXT1", "template-unit", 1
                                run.section.update(template_id="EXT1", start_token="start-unit")
                            with unittest.mock.patch.dict(os.environ,
                                                          KESTRIKE_MAPPINGS=str(mappings or self.state / "mappings")):
                                answer = run.validate(deadline)
                            if reason is None:
                                self.assertIs(answer, True)
                                self.assertEqual((run.section["verdict"], run.section["first_failure"]), ("HELD", None))
                            else:
                                self.assertIsNone(answer)
                                self.assertEqual(run.section["verdict"], "INVALID", run.section["first_failure"])
                                self.assertIn(reason, run.section["first_failure"])
        self.assertEqual(len(os.listdir("/proc/self/fd")), descriptors)

    def test_a_multi_attach_contract_declares_one_instance_and_a_campaign_serves_one_mode(self):
        """A multi-attach-one profile takes exactly one declared instance for its volume, and one volume's Multi-Attach
        setting admits one mode, so a contract declaring none or two, and a campaign naming profiles of both modes,
        are rejected input before any call."""
        self.plan(aws={"volumes": [self.multi_attach()]})
        for declared in ([], ["i-1", "i-2"]):
            with self.subTest(declared=declared):
                self.operator["attachments"] = {VOLUME: declared}
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, _ = self.run_episode(profile="fis-read-latency-multi-attach")
                self.assertEqual(code, 2, out)
                self.assertIn("takes exactly one instance", out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")
        self.operator["attachments"] = {VOLUME: ["i-1"]}
        (self.state / "calls.log").unlink(missing_ok=True)
        code, out, _ = self.run_episode(profile="fis-read-latency fis-read-latency-multi-attach", command="campaign")
        self.assertEqual(code, 2, out)
        self.assertIn("one volume serves one mode", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_a_latency_profile_whose_direction_flags_are_not_booleans_is_rejected_before_any_call(self):
        """The template takes 100 percent of a direction the profile marks true and the least the action allows of the
        other, so a direction flag is a JSON boolean; the string "false" would read as a direction under test."""
        manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
        manifest["profiles"]["fis-read-latency"]["write"] = "false"
        path = self.state / "direction-profiles.json"
        path.write_text(json.dumps(manifest))
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(manifest=path)
        self.assertEqual(code, 2, out)
        self.assertIn("rejected input", out)
        self.assertIn("write", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")
        self.assertFalse((self.state / "template.json").exists(), "no template carried the misread direction")

    def test_a_profile_whose_latency_or_action_the_manifest_cannot_shape_is_rejected_before_any_call(self):
        """A latency profile's `latency_ms` is a whole number the template and the bounds check read, and a profile's
        action is one the manifest lists eligible types for; each shape the manifest cannot hold is rejected input
        before any call or spawn, with exit 2."""
        cases = {
            "missing latency": ("fis-read-latency", {"latency_ms": None}, "latency_ms"),
            "string latency": ("fis-read-latency", {"latency_ms": "10"}, "latency_ms"),
            "boolean latency": ("fis-read-latency", {"latency_ms": True}, "latency_ms"),
            "no direction": ("fis-read-latency", {"read": False}, "direction"),
            "unlisted action": ("fis-pause", {"action": "aws:ebs:detach-volume"}, "eligible_types"),
        }
        for name, (profile, changes, reason) in cases.items():
            with self.subTest(name):
                manifest = json.loads((ROOT / "scripts/fis-profiles.json").read_text())
                for key, value in changes.items():
                    if value is None:
                        del manifest["profiles"][profile][key]
                    else:
                        manifest["profiles"][profile][key] = value
                path = self.state / f"{name.replace(' ', '-')}-profiles.json"
                path.write_text(json.dumps(manifest))
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()]})
                code, out, section = self.run_episode(profile=profile, manifest=path)
                self.assertEqual(code, 2, out)
                self.assertIn("rejected input", out)
                self.assertIn(reason, out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")
                self.assertFalse((self.state / "lane-ran").exists(), "the case never started")

    def test_a_zero_polling_interval_is_rejected_before_any_call(self):
        """Every retry loop sleeps `--poll` between calls, so zero would poll the observer log and AWS without pause for
        each window; the option takes a positive duration."""
        self.plan(aws={"volumes": [volume()]})
        code, out, section = self.run_episode(extra=("--poll", "0"))
        self.assertEqual(code, 2, out)
        self.assertIn("--poll", out)
        self.assertEqual(self.calls(), [], "nothing was described or injected")
        self.assertFalse((self.state / "artifacts").exists(), "nothing was written under the artifacts")

    def test_the_default_lane_command_survives_a_space_in_the_interpreter_s_path(self):
        """The default `--lane` is split with `shlex.split` at the spawn, so it is joined with `shlex.join`: an
        interpreter or checkout path with a space or a quote comes back as the two arguments it names."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        executable, sys.executable = sys.executable, "/opt/o'brien tools/python3"
        try:
            args = module.parser().parse_args(["episode", "--operator", "o.json", "--profile", "p"])
        finally:
            sys.executable = executable
        self.assertEqual(shlex.split(args.lane), ["/opt/o'brien tools/python3", str(SCRIPT.parent / "hardware-lane.py")])

    def test_a_stop_confirms_the_fault_s_end_only_once_the_volume_is_restored(self):
        """An aborted experiment that FIS reports ended while the volume stays impaired leaves the fault's end
        unconfirmed, so the campaign starts no later profile against the unrestored volume."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "volume_status": "impaired"},
                  lane={"observe": ["restored"]})
        code, out, section = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
        self.assertEqual(code, 1, out)
        self.assertEqual(section["abort"], "stopped", out)
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertEqual(section["volume_status"], ["impaired"])
        self.assertIn("fis-pause: unrun; the previous fault's end is unconfirmed", out)
        self.assertEqual(self.calls().count("fis start-experiment"), 1, "the second profile injected nothing")

    def test_a_case_that_outlives_its_seconds_gets_the_lane_s_close_allowance_and_is_then_killed(self):
        """The first wait is the case's declared seconds; after the abandonment the lane has only its close
        allowance, so the whole finish is bounded by both and the kill records custody unknown."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.manifest(duration_seconds=1, case_seconds=3)
        operator = {**self.operator, "effect_timeout_seconds": 1}
        args = argparse.Namespace(hardware_manifest=str(self.hardware_manifest),
                                  aws="true", aws_seconds=10.0, poll=0.05, episode="unit",
                                  observer=str(self.state / "observer"), artifacts=str(self.state / "artifacts"),
                                  lane="true", manifest="")
        run = module.Episode(args, self.loaded, "fis-read-latency", operator)
        run.close_seconds = 0.5
        run.case = subprocess.Popen(["bash", "-c", "trap '' TERM; sleep 60"], stdout=subprocess.PIPE,
                                    stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        run.finish()
        self.assertLess(time.monotonic() - begun, 6.0, "three seconds for the case, one to abandon, half to close")
        self.assertIn("custody_unknown", run.section)
        self.assertIsNotNone(run.case.returncode)
        self.assertTrue(run.abandoned.exists(), "the abandon mark stays for a group that may still run")
        self.assertFalse(run.started.exists())
        # A supervisor that dies by a signal during the abandon wait leaves its group in the same doubt.
        run.section.pop("custody_unknown")
        run.case = subprocess.Popen(["bash", "-c", "sleep 0.3; kill -KILL $$"])
        run.finish(abandon=True)
        self.assertIn("died by signal 9", run.section["custody_unknown"])
        self.assertTrue(run.abandoned.exists(), "the mark stays for the dead supervisor's group")

    def test_an_experiment_that_failed_with_a_failed_action_is_a_partial_injection(self):
        """FIS reports the experiment failed and its fault action failed in one response; the controller classifies
        that as the partial injection the other paths record, INVALID, and polls the volume's restoration."""
        self.plan(aws={"volumes": [volume()], "final": "failed", "partial": True, "run_seconds": 0})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"], section["status"]), (2, "INVALID", "FAILED_TO_INJECT"), out)
        self.assertIn("partially", section["first_failure"])
        self.assertIn("ec2 describe-volume-status", self.calls(), "the restoration was polled")

    def test_a_mapping_that_goes_missing_after_the_spawn_is_invalid_and_still_leaves_a_receipt(self):
        """The mappings lose their volume between the pre-run check and the readiness check; the repeated target
        check refuses the target as INVALID, cleanup ends the case, and the episode writes its receipt."""
        for knob, reason in (("unmap_at_describe", "record no volume"),
                             ("unlink_mappings_at_describe", "cannot be read")):
            with self.subTest(knob):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()], knob: 1})
                code, out, section = self.run_episode()
                self.assertEqual((code, section.get("verdict")), (2, "INVALID"), out)
                self.assertIn(reason, section["first_failure"])
                self.assertIn("case_exit", section, "cleanup ended the case and recorded it")
                self.assertNotIn("fis create-experiment-template", self.calls(), "nothing was injected")
                (self.state / "mappings").write_text(f"format=3\nnvme.volume={VOLUME}\n")

    def test_a_failed_or_partial_fault_still_confirms_the_volume_s_restoration(self):
        """An experiment that ends failed, or whose action failed, may still be lifting a partial fault; the
        volume's restoration is polled on those paths too, and an impaired volume leaves the fault's end
        unconfirmed."""
        # Each path through `watch()` and `restoration()` that ends an injected experiment failed: the action
        # failed before the first timeout (`stop()`), the experiment failed before the first timeout, the
        # experiment ended failed after it, and the action failed after it.
        paths = {"partial before the timeout": ({"partial": True}, None),
                 "failed before the timeout": ({"final": "failed"}, {"observe": ["restored"]}),
                 "ended failed": ({"final": "failed"}, None),
                 "partial after the timeout": ({"partial_on_terminal": True}, None)}
        for name, (aws, lane) in paths.items():
            with self.subTest(name):
                (self.state / "calls.log").unlink(missing_ok=True)
                self.plan(aws={"volumes": [volume()], "volume_status": "impaired", **aws},
                          lane=lane or {"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode(profile="fis-read-latency fis-pause", command="campaign")
                self.assertNotEqual(code, 0, out)
                self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
                self.assertEqual(section["volume_status"], ["impaired"])
                self.assertIn("fis-pause: unrun; the previous fault's end is unconfirmed", out)
                self.assertEqual(self.calls().count("fis start-experiment"), 1, "the second profile injected nothing")
                self.plan(aws={"volumes": [volume()], **aws}, lane=lane or {"observe": ["timeout", "restored"]})
                code, out, section = self.run_episode()
                self.assertNotIn("fault_end_unconfirmed", section, out)
                self.assertIn("ec2 describe-volume-status", self.calls(), "the restoration was polled")
        self.plan(lane={"observe": ["timeout", "restored"]})

    def test_a_lost_deletion_response_leaves_a_deleted_template_unrecorded(self):
        """FIS deletes the template but the response is lost and every later deletion names a missing template;
        the listing shows it gone, so the episode stays HELD with nothing retained."""
        self.plan(aws={"volumes": [volume()], "delete_lost": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertNotIn("template_retained", section)
        self.assertIn("fis list-experiment-templates", self.calls())
        # A listing that answers with one page confirms nothing: the template may sit on a later page.
        # The template stays through the deletion window. A page naming other templates behind the service's
        # `nextToken` or a truncated CLI result's `NextToken` leaves the deletion unconfirmed.
        for spelling in ("templates_paged", "templates_cli_paged"):
            with self.subTest(spelling):
                self.plan(aws={"volumes": [volume()], "delete_failures": 1000, spelling: True})
                code, out, section = self.run_episode()
                self.assertEqual((code, section["verdict"], section["template_retained"]), (1, "INCONCLUSIVE", "EXT1"),
                                 out)
                self.assertTrue(section["fault_end_unconfirmed"], out)
                self.assertTrue((self.state / "custody" / "fis-e1.json").exists(), "the custody marker stays")
        # A complete listing with null continuation fields confirms deletion when it omits the template.
        self.plan(aws={"volumes": [volume()], "delete_lost": True,
                       "templates_tokens": {"nextToken": None, "NextToken": None}})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertNotIn("template_retained", section)

    def test_the_campaign_budget_counts_every_bounded_phase(self):
        """Each episode can spend the effect timeout waiting for the start, the first timeout, the terminal state,
        the stop, the restoration status and the template's deletion, so the budget check counts those windows."""
        self.operator["effect_timeout_seconds"] = 130
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "campaign", "--custody", str(self.state / "custody"), "--operator", str(self.state / "operator.json"),
                "--profiles", "fis-read-latency fis-pause", "--budget-seconds", "6000", "--aws", str(self.state / "aws")]
        done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
        self.assertEqual(done.returncode, 2, done.stdout)
        manifest = json.loads(Path(SCRIPT.parent / "fis-profiles.json").read_text())
        # Per profile: one pre-run target check of up to the AWS call limit, the phases from the spawn (two more target
        # checks, a stop request, cleanup's stop request, the listing after the deletion and the observer log's
        # bounded waits among them), the case's declared seconds and the lane's close (its case grace, then the lane's
        # stop and controller windows).
        lane = json.loads((ROOT / "scripts/hardware-profiles.json").read_text())
        close = {name: max(case["grace"] for case in lane["profiles"][profile["lane"]["profile"]]["roles"]
                           [profile["lane"]["role"]]["cases"]) + 10 + 30 for name, profile in manifest["profiles"].items()}
        needed = sum(60 + (profile["ready_seconds"] + profile["duration_seconds"] + 5 * 130 + 3 * 60 + 2 * 60 + 2 * (130 + 60) + 7 * 5)
                     + profile["case_seconds"] + close[name] for name, profile in manifest["profiles"].items()
                     if name in ("fis-read-latency", "fis-pause"))
        self.assertIn(f"need up to {needed} s, past the 6000 s budget", done.stdout)
        self.assertFalse((self.state / "calls.log").exists())

    def test_the_default_budget_holds_the_checked_in_profiles_under_a_minute_of_effect_timeout(self):
        """One campaign runs the profiles of one attachment mode, since one volume's Multi-Attach setting admits one;
        each mode's checked-in profiles under a 60 s effect timeout and 60 s AWS calls fit the controller's default
        budget; the lane's step constants are checked against the same bounds by test-rust-lane.py."""
        spec = importlib.util.spec_from_file_location("fis_controller", SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        manifest = json.loads(Path(SCRIPT.parent / "fis-profiles.json").read_text())
        operator = {**self.operator, "effect_timeout_seconds": 60}
        for mode in module.ATTACHMENT_MODES:
            with self.subTest(mode):
                chosen = [profile for profile in manifest["profiles"].values() if profile["attachment"] == mode]
                self.assertTrue(chosen, f"a checked-in profile runs under {mode}")
                needed = sum(module.episode_bound(profile, operator, 60.0, module.lane.MANIFEST) for profile in chosen)
                self.assertLessEqual(needed, module.DEFAULT_BUDGET_SECONDS, needed)

    def test_a_failed_template_deletion_is_retried_and_a_retained_template_earns_no_credit(self):
        self.plan(aws={"volumes": [volume()], "delete_failures": 1})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.assertEqual(self.calls().count("fis delete-experiment-template"), 2, "the deletion was retried")
        self.plan(aws={"volumes": [volume()], "delete_failures": 1000})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("template", section["first_failure"])
        self.assertEqual(section["template_retained"], "EXT1")
        # The experiment ended and the volume read ok, so the marker names the one doubt left: the template to delete.
        marker = json.loads((self.state / "custody" / "fis-e1.json").read_text())
        self.assertIn("template EXT1 may remain and admits starts", marker["custody"])
        self.assertNotIn("fault's end is unconfirmed", marker["custody"], "the receipt resolved the fault's end")
        self.assertTrue(marker["durable"])

    def test_an_operator_contract_without_a_positive_effect_timeout_is_rejected_before_any_call(self):
        for value in (0, -3, "60"):
            with self.subTest(value=value):
                self.operator["effect_timeout_seconds"] = value
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, _ = self.run_episode()
                self.assertEqual(code, 2, out)
                self.assertIn("effect_timeout_seconds", out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_an_operator_contract_with_a_malformed_field_is_rejected_before_any_call(self):
        base = dict(self.operator)
        for field, value in (("attachments", None), ("attachments", [VOLUME]), ("attachments", {VOLUME: "i-1"}),
                             ("volumes", VOLUME), ("volumes", [1]), ("stop_alarms", "alarm"), ("region", 7),
                             ("account", None), ("role_arn", [])):
            with self.subTest(field=field, value=value):
                self.operator = {**base, field: value}
                (self.state / "calls.log").unlink(missing_ok=True)
                code, out, _ = self.run_episode()
                self.assertEqual(code, 2, out)
                self.assertIn("rejected input", out)
                self.assertIn(field, out)
                self.assertEqual(self.calls(), [], "nothing was described or injected")

    def test_an_operator_document_that_is_not_an_object_is_rejected_before_any_call(self):
        for text in ("null", "[]", '"contract"', "7"):
            with self.subTest(text=text):
                (self.state / "operator.json").write_text(text)
                (self.state / "calls.log").unlink(missing_ok=True)
                argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                        str(self.state / "operator.json"), "--aws", str(self.state / "aws")]
                done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2, done.stdout + done.stderr)
                self.assertIn("rejected input", done.stdout)
                self.assertNotIn("Traceback", done.stderr)
                self.assertEqual(self.calls(), [])

    def test_a_readiness_event_left_by_an_earlier_run_of_the_same_episode_is_ignored(self):
        """An operator who reuses an `--episode` value leaves the earlier run's readiness in the observer log;
        the controller accepts only a readiness event appended after it launched this run's case."""
        code, out, _ = self.run_episode()
        self.assertEqual(code, 0, out)
        self.plan(lane={"no_ready": True})
        code, out, section = self.run_episode(keep_observer=True)
        self.assertEqual((code, section["verdict"]), (1, "INCONCLUSIVE"), out)
        self.assertIn("before its readiness", section["first_failure"])
        self.assertEqual(self.calls().count("fis start-experiment"), 1, "the second run injected nothing")
        self.plan(lane={"observe": ["timeout", "restored"]})
        code, out, section = self.run_episode(keep_observer=True)
        self.assertEqual((code, section["verdict"]), (0, "HELD"), "a third run's own readiness is seen past the stale ones: " + out)
        self.assertEqual(self.calls().count("fis start-experiment"), 2)

    def test_a_transient_telemetry_error_retries_and_a_refused_stop_is_recorded(self):
        self.plan(aws={"volumes": [volume()], "flaky": True})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["verdict"]), (0, "HELD"), out)
        self.plan(aws={"volumes": [volume()], "stop_refused": True, "run_seconds": 100}, lane={"observe": ["restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["abort"]), (1, "refused"), out)
        self.assertTrue(section["fault_end_unconfirmed"], "a refused stop with no terminal state seen")
        self.assertIn("fis get-experiment", self.calls()[self.calls().index("fis stop-experiment"):],
                      "the experiment was polled after the refusal, since the stop may have been accepted")
        # A stop FIS accepted whose response was lost: the poll sees the experiment stopped and the volume restored,
        # so nothing is unconfirmed; with no stop alarm in the contract the stopped state is the controller's own.
        self.plan(aws={"volumes": [volume()], "stop_lost": True, "run_seconds": 100}, lane={"observe": ["restored"]})
        code, out, section = self.run_episode()
        self.assertEqual((code, section["abort"]), (1, "stopped"), out)
        self.assertNotIn("fault_end_unconfirmed", section, out)

    def test_a_campaign_past_its_budget_or_naming_an_undeclared_profile_is_rejected(self):
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        twins = "fis-read-latency-multi-attach fis-family-stop-multi-attach"
        for profiles, budget, reason in (("fis-read-latency fis-pause", "100", "past the 100 s budget"),
                                         (twins, "100", "past the 100 s budget"),
                                         ("fis-read-latency fis-paus", "11000", "undeclared profiles ['fis-paus']")):
            with self.subTest(profiles):
                argv = [sys.executable, str(SCRIPT), "campaign", "--custody", str(self.state / "custody"), "--operator", str(self.state / "operator.json"),
                        "--artifacts", str(self.state / "artifacts"), "--observer", str(self.state / "observer"),
                        "--lane", str(self.state / "lane"),
                        "--profiles", profiles, "--budget-seconds", budget, "--aws", str(self.state / "aws")]
                done = subprocess.run(argv, capture_output=True, text=True, timeout=60, check=False)
                self.assertEqual(done.returncode, 2, done.stdout)
                self.assertIn(reason, done.stdout)
                self.assertFalse((self.state / "calls.log").exists(), "nothing was described or injected")

    def test_a_signal_during_cleanup_is_the_episode_s_failure_and_run_status(self):
        """A signal after the run's phases, while cleanup deletes the template, lets cleanup finish and marks the
        receipt interrupted with status CONTROLLER_LOST, so a receipt never claims HELD for an interrupted episode."""
        self.plan(aws={"volumes": [volume()], "hang": {"delete-experiment-template": 3}},
                  lane={"observe": ["timeout", "restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                str(self.state / "operator.json"), "--artifacts", str(self.state / "artifacts"),
                "--observer", str(self.state / "observer"), "--episode", "s1", "--aws", str(self.state / "aws"),
                "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05", "--manifest", str(self.manifest(duration_seconds=1)),
                "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis delete-experiment-template" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.5)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertEqual((section["verdict"], section["status"]), ("INCONCLUSIVE", "CONTROLLER_LOST"), out)
        self.assertIn("during cleanup", section["first_failure"])
        self.assertEqual(self.calls().count("fis delete-experiment-template"), 1, "cleanup finished its deletion")

    def test_a_signal_during_the_template_s_creation_leaves_its_tag_discovered_or_recorded(self):
        """A signal while the creation request is in flight still lets cleanup look for the request's tag, so a
        template FIS may have created is deleted or recorded as one that may remain."""
        self.plan(aws={"volumes": [volume()], "hang": {"create-experiment-template": 5}},
                  lane={"observe": ["timeout", "restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile", "fis-read-latency", "--operator",
                str(self.state / "operator.json"), "--artifacts", str(self.state / "artifacts"),
                "--observer", str(self.state / "observer"), "--episode", "s2", "--aws", str(self.state / "aws"),
                "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05", "--manifest", str(self.manifest(duration_seconds=1)),
                "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis create-experiment-template" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.5)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertIn("fis list-experiment-templates", self.calls(), "cleanup looked for the request's tag")
        deleted = (self.state / "deleted-ids.log").read_text().split() if (self.state / "deleted-ids.log").exists() else []
        unconfirmed = section.get("template_unconfirmed", "")
        self.assertTrue(deleted == ["EXT1"] or unconfirmed == section["template_token"], json.dumps(section, indent=1))

    def test_a_signal_during_the_restoration_poll_leaves_the_fault_end_unconfirmed_and_quarantined(self):
        """The experiment ended and the restoration poll is in flight when the signal arrives; cleanup runs the
        poll again, an impaired volume leaves the fault's end unconfirmed, and the quarantine marker is written."""
        self.plan(aws={"volumes": [volume()], "volume_status": "impaired", "hang": {"describe-volume-status": 1.5}},
                  lane={"observe": ["timeout", "restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile",
                "fis-read-latency", "--operator", str(self.state / "operator.json"), "--artifacts",
                str(self.state / "artifacts"), "--observer", str(self.state / "observer"), "--episode", "s3",
                "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05",
                "--manifest", str(self.manifest(duration_seconds=1)), "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while self.calls().count("ec2 describe-volume-status") < 1:
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.3)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertTrue(Path(section["quarantine"]).exists(), section.get("quarantine"))
        self.assertGreater(self.calls().count("ec2 describe-volume-status"), 1, "the poll ran again in cleanup")

    def test_a_signal_during_the_stop_s_wait_for_the_end_leaves_the_fault_end_unconfirmed_and_quarantined(self):
        """FIS accepted the stop and the experiment is still ending when the signal arrives; the fault's end stays
        unconfirmed and the quarantine marker is written."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "stopping_seconds": 30},
                  lane={"observe": ["restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile",
                "fis-read-latency", "--operator", str(self.state / "operator.json"), "--artifacts",
                str(self.state / "artifacts"), "--observer", str(self.state / "observer"), "--episode", "s4",
                "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05",
                "--manifest", str(self.manifest(duration_seconds=1)), "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis stop-experiment" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.3)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertEqual(section["abort"], "issued", out)
        self.assertTrue(section.get("fault_end_unconfirmed"), json.dumps(section, indent=1))
        self.assertTrue(Path(section["quarantine"]).exists(), section.get("quarantine"))

    def test_a_signal_during_the_stop_s_wait_lets_cleanup_see_the_end_and_lift_the_quarantine(self):
        """The stop was accepted and the signal arrives during the wait for the end; cleanup waits again, with no
        second request, sees the experiment end and the volume restored, and the quarantine is lifted."""
        self.plan(aws={"volumes": [volume()], "run_seconds": 100, "stopping_seconds": 1.0},
                  lane={"observe": ["restored"]})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "episode", "--custody", str(self.state / "custody"), "--profile",
                "fis-read-latency", "--operator", str(self.state / "operator.json"), "--artifacts",
                str(self.state / "artifacts"), "--observer", str(self.state / "observer"), "--episode", "s5",
                "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest), "--poll", "0.05",
                "--manifest", str(self.manifest(duration_seconds=1)), "--aws-seconds", "10"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis stop-experiment" not in self.calls():
            self.assertLess(time.monotonic() - begun, 60)
            time.sleep(0.05)
        time.sleep(0.2)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertEqual(section["abort"], "stopped", out)
        self.assertNotIn("fault_end_unconfirmed", section, json.dumps(section, indent=1))
        self.assertEqual(self.calls().count("fis stop-experiment"), 1, "no second stop request")
        self.assertEqual(list((self.state / "custody").glob("fis-*.json")), [], "the quarantine was lifted")

    def test_a_signal_stops_the_live_fault_keeps_the_receipt_and_starts_no_later_profile(self):
        self.plan(lane={"observe": ["timeout"], "seconds": 30})
        (self.state / "operator.json").write_text(json.dumps(self.operator))
        argv = [sys.executable, str(SCRIPT), "campaign", "--custody", str(self.state / "custody"), "--operator", str(self.state / "operator.json"),
                "--artifacts", str(self.state / "artifacts"), "--observer", str(self.state / "observer"),
                "--episode", "c1", "--aws", str(self.state / "aws"), "--lane", str(self.state / "lane"),
                "--hardware-manifest", str(self.hardware_manifest),
                "--poll", "0.05", "--manifest", str(self.manifest(duration_seconds=60)),
                "--profiles", "fis-read-latency fis-pause"]
        env = dict(os.environ, FAKE_STATE=str(self.state), KESTRIKE_MAPPINGS=str(self.state / "mappings"),
                   LANE_SCRIPT=str(ROOT / "scripts/hardware-lane.py"))
        controller = subprocess.Popen(argv, env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        begun = time.monotonic()
        while "fis start-experiment" not in self.calls():
            self.assertLess(time.monotonic() - begun, 30)
            time.sleep(0.1)
        time.sleep(1.0)
        controller.send_signal(signal.SIGTERM)
        out, err = controller.communicate(timeout=120)
        self.assertEqual(controller.returncode, 5, out + err)
        section = json.loads(next(Path(line.split(": ", 1)[1]) for line in err.splitlines()
                                  if line.startswith("receipt: ")).read_text())["fis"]
        self.assertEqual((section["status"], section["abort"]), ("CONTROLLER_LOST", "stopped"))
        self.assertIn("interrupted by signal", section["first_failure"])
        self.assertEqual(self.calls().count("fis start-experiment"), 1, "no later profile was injected")
        self.assertIn("- fis-pause: unrun; the campaign was interrupted", out)


if __name__ == "__main__":
    unittest.main()
