#!/usr/bin/env bash
# Usage: verification/reach/measure.sh FAMILY STATE SCRATCH
#
# docs/agents/simulation.md, "Measure the typed-outcome register", states
# where to run it and what STATE and SCRATCH hold. Each batch of five roots
# runs under a bound of BATCH_SECONDS (3600 by default).
set -euo pipefail

family=$1
state=$2
scratch=$3
batch_seconds=${BATCH_SECONDS:-3600}
if [[ ! "$batch_seconds" =~ ^[1-9][0-9]*$ ]]; then
  echo "measure.sh: BATCH_SECONDS must be a positive integer" >&2
  exit 2
fi
workers=${BATCH_WORKERS:-28}
if [[ ! "$workers" =~ ^[1-9][0-9]*$ ]]; then
  echo "measure.sh: BATCH_WORKERS must be a positive integer" >&2
  exit 2
fi
processors=$(nproc)
if ((workers > processors)); then workers=$processors; fi
flags="-C instrument-coverage -C target-feature=+lse"
# The named run is roots 1 to `last` of each profile, in batches of
# `width` roots. The recovery profiles, which the worker's listing marks
# `class=recovery`, run with `restarts` and `cluster-long` with `long`.
last=50
width=5
restarts=restarts=20
long=(turns=100000000 records=10000000 bytes=480000000)
if ((last % width != 0)); then
  echo "measure.sh: the last root $last is no multiple of the batch width $width" >&2
  exit 2
fi

checkout=$(git rev-parse --show-toplevel)
host=$(rustc -vV | sed -n 's/^host: //p')
if [[ $host != aarch64-* ]]; then
  echo "measure.sh: the named run is measured on an aarch64 host; this host is ${host:-unknown}" >&2
  exit 2
fi
tools="$(rustc --print sysroot)/lib/rustlib/$host/bin"
if [[ ! -x "$tools/llvm-profdata" ]]; then
  echo "measure.sh: run \`rustup component add llvm-tools\` first" >&2
  exit 2
fi
clean() {
  local status
  status=$(git -C "$checkout" status --porcelain --untracked-files=all)
  if [[ -n "$status" ]]; then
    echo "measure.sh: the checkout has uncommitted changes or untracked files" >&2
    exit 2
  fi
}
clean
case $state in /*) ;; *) state="$(pwd -P)/$state" ;; esac
case $scratch in /*) ;; *) scratch="$(pwd -P)/$scratch" ;; esac
if [[ -e "$scratch" || -L "$scratch" || -e "$state" || -L "$state" ]]; then
  echo "measure.sh: STATE and SCRATCH must be new directories" >&2
  exit 2
fi
commit=$(git -C "$checkout" rev-parse HEAD)

reach=(cargo run --locked --release --manifest-path "$checkout/verification/reach/tool/Cargo.toml" --)
sites=$("${reach[@]}" sites "$family")
if grep -q '^ambiguous ' <<< "$sites"; then
  grep '^ambiguous ' <<< "$sites" >&2
  echo "measure.sh: qualify these paths before measuring" >&2
  exit 2
fi

# The workspace lockfile is untracked, so the build resolves one when a
# fresh clone has none, and the archive records the lockfile it used.
campaign=$(cargo build --release -p campaign-supervisor --message-format=json-render-diagnostics |
  python3 -c '
import json, sys
found = [m["executable"] for m in map(json.loads, sys.stdin)
         if m.get("reason") == "compiler-artifact" and m["target"]["name"] == "campaign" and m.get("executable")]
assert len(found) == 1, found
print(found[0])')

mkdir -p "$(dirname "$state")" "$(dirname "$scratch")"
mkdir -m 0700 "$state"
mkdir -m 0700 "$scratch"
mkdir "$scratch/build" "$scratch/probe" "$scratch/prof" "$scratch/out" "$scratch/manifests"
archive="$state/archive"
env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="$flags" \
  CARGO_TARGET_DIR="$scratch/target" \
  LLVM_PROFILE_FILE="$scratch/build/%p.profraw" \
  "$campaign" sim archive --output "$archive"

# The workers run with the loader environment the supervisor gives an
# archived worker: no inherited LD_* variable or GLIBC_TUNABLES.
for name in $(compgen -e); do
  case $name in LD_* | GLIBC_TUNABLES) unset "$name" ;; esac
done
export archive scratch batch_seconds width
LD_LIBRARY_PATH="$archive/lib" LLVM_PROFILE_FILE="$scratch/probe/%p.profraw" \
  "$archive/worker" --capabilities > "$scratch/capabilities.txt"
if ! find "$scratch/probe" -name '*.profraw' -size +0 | grep -q .; then
  echo "measure.sh: the archived worker wrote no coverage profile" >&2
  exit 2
fi
profiles=$(awk '$1 == "profile:" && ($3 == "class=live" || $3 == "class=recovery") { print $2 }' \
  "$scratch/capabilities.txt")
if [[ -z "$profiles" ]] || grep -vqE '^[a-z0-9][a-z0-9-]*$' <<< "$profiles" ||
  [[ -n "$(sort <<< "$profiles" | uniq -d)" ]]; then
  echo "measure.sh: the worker's profile listing is empty, malformed or repeated" >&2
  exit 2
fi
recovery=$(awk '$1 == "profile:" && $3 == "class=recovery" { print $2 }' "$scratch/capabilities.txt")

# A sweep root takes one set of counts, and the sweep freezes one manifest
# for each profile under it. A completed freeze exits 0, or 1 for a verdict
# of its one-second sweep; any other status stops the script.
freeze() {
  local root=$1 status=0
  shift
  (cd "$scratch/build" && "$campaign" sweep --root "$state/$root" --archive "$archive" \
    --campaign reach --workers 1 --for 1 "$@" > /dev/null) || status=$?
  if ((status > 1)); then
    echo "measure.sh: the $root freeze exited $status" >&2
    exit 2
  fi
}
freeze default --profiles "$(paste -sd, <<< "$profiles")"
if [[ -n "$recovery" ]]; then
  freeze restarts --profiles "$(paste -sd, <<< "$recovery")" --set "$restarts"
fi
freeze long --profiles cluster-long --set "${long[0]}" --set "${long[1]}" --set "${long[2]}"
for profile in $profiles; do
  root=default
  for restarted in $recovery; do
    if [[ $profile == "$restarted" ]]; then root=restarts; fi
  done
  if [[ $profile == cluster-long ]]; then root=long; fi
  cp "$state/$root/manifests/$profile.manifest" "$scratch/manifests/"
done

firsts=$(seq 1 "$width" "$last")
for profile in $profiles; do
  for first in $firsts; do echo "$profile $first"; done
done > "$scratch/batches.list"

# Under `set -m` the pool leads its own process group, and
# `timeout --foreground` leaves each worker in that group, so one signal to
# the group reaches every batch. A worker that outlasts SIGTERM gets SIGKILL
# from its `timeout` 60 seconds later.
pool=
reap() {
  if [[ -n "$pool" ]]; then kill -TERM -- "-$pool" 2> /dev/null || true; fi
}
trap reap EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
set -m
xargs -a "$scratch/batches.list" -P "$workers" -n 2 sh -c 'seq "$2" $(($2 + width - 1)) |
  LD_LIBRARY_PATH="$archive/lib" LLVM_PROFILE_FILE="$scratch/prof/$1-$2-%p.profraw" \
  timeout --foreground --kill-after=60 "$batch_seconds" \
  "$archive/worker" --sweep "$scratch/manifests/$1.manifest" > "$scratch/out/$1-$2.out" ||
  { echo "measure.sh: the batch $1 $2 exited $?" >&2; exit 255; }' sh < /dev/null &
pool=$!
set +m
status=0
wait "$pool" || status=$?
if ((status != 0)); then exit "$status"; fi
pool=
trap - EXIT HUP INT TERM

python3 - "$scratch" "$profiles" "$recovery" "$restarts" "$(IFS=,; echo "${long[*]}")" \
  "$commit" "$flags" "$last" "$width" "$archive/build" <<'EOF'
import json, pathlib, sys
scratch, profiles, recovery, restarts, long, commit, flags, last, width, build = sys.argv[1:]
scratch, profiles, recovery = pathlib.Path(scratch), profiles.split(), recovery.split()
last, width = int(last), int(width)
def stop(message):
    print(f"measure.sh: {message}", file=sys.stderr)
    sys.exit(2)
provenance = json.loads(pathlib.Path(build).read_text())["record"]["provenance"]
built = (provenance["revision"], provenance["dirty"], provenance["untracked"], provenance["environment"].get("RUSTFLAGS"))
if built != (commit, False, 0, flags):
    stop(f"the archive was built from {built[0]} (dirty {built[1]}, untracked {built[2]}) with {built[3]!r}")
passes, merged, violations = {}, [], []
for profile in profiles:
    passes[profile] = 0
    for first in range(1, last + 1, width):
        out = scratch / "out" / f"{profile}-{first}.out"
        raw = [path for path in (scratch / "prof").glob(f"{profile}-{first}-*.profraw")
               if path.name.split("-")[:-1] == f"{profile}-{first}".split("-")]
        if len(raw) != 1 or raw[0].stat().st_size == 0:
            stop(f"the batch {profile} {first} wrote {len(raw)} profiles")
        lines = out.read_text().splitlines()
        blocks, block = [], None
        for line in lines[1:]:
            key, _, value = line.partition(": ")
            if key == "root":
                block = {"root": value}
            elif key == "end" and block is not None:
                blocks.append((block, value))
                block = None
            elif block is not None:
                if key in block and key in ("code", "terminal", "counts", "profile"):
                    stop(f"the batch {profile} {first}: root {block['root']} prints `{key}` twice")
                block[key] = value
        expected = [str(root) for root in range(first, first + width)]
        if lines[:1] != ["sweep: ready"] or block is not None or \
                [(b["root"], end) for b, end in blocks] != list(zip(expected, expected)):
            stop(f"the batch {profile} {first} printed other roots than {expected}")
        # A complete run of the scheduled profile prints code 0 when it
        # counts and code 1 when it does not. A refused, panicked,
        # unloadable or infrastructure root stops the script.
        for b, _ in blocks:
            code, terminal, counts = b.get("code"), b.get("terminal", ""), b.get("counts")
            credited = (code, counts) == ("0", "true") and terminal.startswith("complete pass ")
            complete = (code, counts) == ("1", "false") and terminal.startswith("complete ")
            if b.get("profile") != profile or not (credited or complete):
                shown = next((f"{key}: {b[key]}" for key in ("refused", "run", "load") if key in b),
                             f"code {code}, terminal {terminal!r}, counts {counts}, profile {b.get('profile')}")
                stop(f"the batch {profile} {first}: root {b['root']} is no complete run of {profile} ({shown})")
            passes[profile] += credited
            if terminal.startswith("complete violation"):
                violations.append(f"measure.sh: {profile} root {b['root']} ended in a violation "
                                  f"({out}); triage it through the supervisor's sweep")
        merged.append(str(raw[0]))
manifest = dict(line.split(" = ", 1)
                for line in (scratch / "manifests" / f"{profiles[0]}.manifest").read_text().splitlines())
counts = {profile: restarts for profile in recovery}
counts["cluster-long"] = long
run = {
    "commit": commit,
    "toolchain": manifest["toolchain"],
    "flags": flags,
    "build": manifest["build"],
    "worker": manifest["executable"],
    "profiles": profiles,
    "roots": f"1-{last}",
    "counts": dict(sorted(counts.items())),
    "no_pass": [profile for profile in profiles if passes[profile] == 0],
}
(scratch / "run.json").write_text(json.dumps(run))
(scratch / "merge.list").write_text("".join(f"{path}\n" for path in merged))
(scratch / "violations.txt").write_text("".join(f"{line}\n" for line in violations))
for profile in profiles:
    print(f"{profile}: {passes[profile]} of {last} roots pass")
EOF
cat "$scratch/violations.txt" >&2

"$tools/llvm-profdata" merge -sparse -f "$scratch/merge.list" -o "$scratch/merged.profdata"
"$tools/llvm-cov" export -format=text -instr-profile "$scratch/merged.profdata" "$archive/worker" \
  > "$scratch/export.json"

clean
if [[ "$(git -C "$checkout" rev-parse HEAD)" != "$commit" ]]; then
  echo "measure.sh: HEAD moved during the run" >&2
  exit 2
fi
if [[ -e "$checkout/verification/reach/$family.json" ]]; then
  echo "rows whose state or count the new run changes:"
  "${reach[@]}" compare "$family" --export "$scratch/export.json"
fi
"${reach[@]}" measure "$family" --export "$scratch/export.json" --run "$scratch/run.json"
cat "$scratch/violations.txt" >&2
