#!/usr/bin/env bash
set -Eeuo pipefail

: "${EVIDENCE:=$PWD/evidence}"
# Lanes and the processes they start may change directory, so a relative
# EVIDENCE is anchored to the directory the lane started in.
case $EVIDENCE in /*) ;; *) EVIDENCE=$PWD/$EVIDENCE ;; esac
: "${GITHUB_STEP_SUMMARY:=$EVIDENCE/summary.md}"
STABLE_CARGO=(cargo "+$STABLE")
REGISTRY_TESTS=4
# The simulation worker's protocol contract case, which the workspace lane runs under cfg(protocol_contract).
CONTRACT_CASE=contract::the_supervisor_parses_every_worker_form
mkdir -p "$EVIDENCE"
trap 'on_error "$LINENO" "$BASH_COMMAND"' ERR

CHILD=
TIMER=

stop_group() {
  local leader=$1 grace
  kill -TERM -- "-$leader" 2>/dev/null || true
  sleep 30 &
  grace=$!
  wait -n "$leader" "$grace" || true
  kill -KILL -- "-$leader" 2>/dev/null || true
  kill -KILL "$grace" 2>/dev/null || true
  wait "$grace" 2>/dev/null || true
  wait "$leader" 2>/dev/null || true
}

# Stops what remains of the process group a batch's leader led, once the leader has exited: TERM, up to 30
# seconds for the group to empty, then KILL, so no CBMC process of one batch runs beside the next.
drain_group() {
  local leader=$1 waited=0
  kill -0 -- "-$leader" 2>/dev/null || return 0
  kill -TERM -- "-$leader" 2>/dev/null || true
  while kill -0 -- "-$leader" 2>/dev/null && [ "$waited" -lt 300 ]; do
    sleep 0.1
    waited=$((waited + 1))
  done
  kill -KILL -- "-$leader" 2>/dev/null || true
}

# Background children inherit ignored SIGINT, so shutdown sends SIGTERM. The
# exit record marks the lane interrupted, whatever a judged run wrote before.
on_signal() {
  trap '' TERM INT
  printf '143\n' > "$EVIDENCE/exit.txt"
  [ -z "$TIMER" ] || kill "$TIMER" 2>/dev/null || true
  # `kill -0` fails for a leader this shell has reaped: the members that remain of its group hold its process ID
  # as their group ID, so the ID names no other process. Such a leader has no exit to wait for, and a stop kills
  # what remains of its group at once.
  if [ -n "$CHILD" ] && ! kill -0 "$CHILD" 2>/dev/null; then
    kill -KILL -- "-$CHILD" 2>/dev/null || true
  elif [ -n "$CHILD" ]; then
    stop_group "$CHILD"
  fi
  exit 143
}
trap on_signal TERM INT

# Runs a command as the leader of its own process group and stops the group when the limit passes. With --drain it
# also stops what remains of the group after the leader exits, and the group stays registered for a stop of the
# lane until that is done.
deadline() {
  local limit code=0 finished drain=
  [ "$1" != --drain ] || { drain=1; shift; }
  limit=$1
  shift
  setsid "$@" &
  CHILD=$!
  sleep "$limit" &
  TIMER=$!
  wait -n -p finished "$CHILD" "$TIMER" || code=$?
  if [ "$finished" = "$TIMER" ]; then
    echo "deadline: $1 passed $limit; stopping it" >&2
    stop_group "$CHILD"
    code=124
  else
    kill "$TIMER" 2>/dev/null || true
  fi
  if [ -n "$drain" ]; then
    TIMER=''
    drain_group "$CHILD"
  fi
  CHILD='' TIMER=''
  return "$code"
}

fail() {
  echo "::error::$1"
  printf '%s\n' "$1" > "$EVIDENCE/failure.txt"
  printf -- '- red: %s\n' "$1" >> "$GITHUB_STEP_SUMMARY"
  exit 1
}

on_error() {
  fail "rust-lane.sh failed at line $1: ${2%%$'\n'*}"
}

summary() {
  printf '%s\n' "$@" >> "$GITHUB_STEP_SUMMARY"
}

# pkg-config over the selected install's metadata alone.
native_pc() {
  PKG_CONFIG_PATH="$SPDK_PKG_CONFIG_PATH" PKG_CONFIG_LIBDIR="$SPDK_PKG_CONFIG_PATH" pkg-config "$@"
}

pins() {
  local header spdk dpdk
  target_dir
  # SPDK installs its headers under the bundled DPDK's prefix, and only
  # libdpdk's metadata names the include directory.
  native_pc --print-errors --exists libdpdk 2>"$EVIDENCE/pkg-config.txt" \
    || fail "DPDK metadata unavailable in $SPDK_PKG_CONFIG_PATH: $(cat "$EVIDENCE/pkg-config.txt")"
  INCLUDEDIR=$(native_pc --variable=includedir libdpdk 2>"$EVIDENCE/pkg-config.txt") \
    || fail "DPDK pkg-config: $(cat "$EVIDENCE/pkg-config.txt")"
  [ -n "$INCLUDEDIR" ] || fail "DPDK pkg-config names no includedir"
  header=$INCLUDEDIR/spdk/version.h
  spdk=$(awk '$1 == "#define" && $2 ~ /^SPDK_VERSION_(MAJOR|MINOR|PATCH)$/ {print $3}' "$header" 2>&1 \
    | paste -sd.) || fail "SPDK header: $spdk"
  dpdk=$(native_pc --modversion libdpdk 2>&1) \
    || fail "DPDK pkg-config: $dpdk"
  [ "$spdk" = "$SPDK_VERSION" ] || fail "SPDK $spdk, pinned $SPDK_VERSION"
  [ "$dpdk" = "$DPDK_VERSION" ] || fail "DPDK $dpdk, pinned $DPDK_VERSION"
  toolchain_pins
  PINS=("- SPDK $spdk at $SPDK_COMMIT; DPDK $dpdk at $DPDK_COMMIT"
    "- SPDK_PKG_CONFIG_PATH $SPDK_PKG_CONFIG_PATH; bindings crates/spdk-sys/src/generated"
    "${TOOLCHAIN_PINS[@]}")
}

toolchain_pins() {
  target_dir
  TOOLCHAIN_PINS=("- $(rustc "+$STABLE" --version); $(rustc "+$NIGHTLY" --version)"
    "- $("${STABLE_CARGO[@]}" fuzz --version); host $(uname -srm); CPU $CPU"
    "- target cache $CACHE_KEY")
}

toolchains() {
  rustup toolchain install "$STABLE" --profile minimal --component rustfmt,clippy \
    && rustup toolchain install "$NIGHTLY" --profile minimal --component miri,rust-src \
    && { [ "$("${STABLE_CARGO[@]}" fuzz --version 2>/dev/null)" = "cargo-fuzz $CARGO_FUZZ" ] \
      || "${STABLE_CARGO[@]}" install cargo-fuzz --version "$CARGO_FUZZ" --locked; }
}

# The host CPU keys the target cache: `model name` identifies it on x86, and
# on AArch64 the first core's `CPU implementer` and `CPU part` identify it.
target_dir() {
  CPU=$(awk -F': ' '/^model name/ {name = $2; exit}
    /^CPU implementer/ && implementer == "" {implementer = $2}
    /^CPU part/ && part == "" {part = $2}
    END {print name != "" ? name : implementer != "" && part != "" ? "implementer " implementer " part " part : ""}' \
    /proc/cpuinfo)
  [ -n "$CPU" ] || fail "/proc/cpuinfo names no CPU model"
  CACHE_KEY=$(printf '%s %s' "$CPU" "$STABLE" | sha256sum | cut -c1-16)
  export CARGO_TARGET_DIR="$HOME/.cache/kestrike-target/$CACHE_KEY${1:+-$1}"
}

step() {
  local name=$1 code
  shift
  "$@" > "$EVIDENCE/$name.txt" 2>&1 || {
    code=$?
    [ "$code" -ne 124 ] || printf '124\n' > "$EVIDENCE/exit.txt"
    tail -n 40 "$EVIDENCE/$name.txt"
    fail "$name failed; see $name.txt in the evidence"
  }
}

# Records the selected install's identities: the compilers its archives name,
# its configure record, the hash of every archive and the install record its
# target, sanitizer and flags select, with the generated output the record
# names. The compile evidence covers this host's architecture alone. Leaves
# the selection in NATIVE_RECORD, NATIVE_OUTPUT, NATIVE_SANITIZER,
# NATIVE_COMPILERS, NATIVE_CONFIGURE, NATIVE_ARCHIVES, NATIVE_LIBDIR and
# NATIVE_LINEAGE: the record's sha256 when it carries the controlled build's
# lineage, `unrecorded` otherwise. native_identity appends NATIVE_LINEAGE to PINS.
native_identity() {
  local includedir=$INCLUDEDIR libdir flags cflags libs roots line normalized sanitizer record records=() output compilers archives
  local configure_sha configure_keys measured lineage installs targets=() forms i
  libdir=$(native_pc --variable=libdir libdpdk 2>"$EVIDENCE/pkg-config.txt") \
    || fail "DPDK pkg-config: $(cat "$EVIDENCE/pkg-config.txt")"
  flags=$(native_pc --cflags libdpdk spdk_nvme spdk_env_dpdk 2>"$EVIDENCE/pkg-config.txt") \
    || fail "native pkg-config: $(cat "$EVIDENCE/pkg-config.txt")"
  read -r -a cflags <<<"$flags"
  [ "${cflags[0]}" = "-I$includedir" ] \
    || fail "the install's flags open with ${cflags[0]}, not its include root -I$includedir"
  roots=$(printf '%s\n' "${cflags[@]}" | grep -cxF -- "-I$includedir")
  [ "$roots" -eq 1 ] || fail "the install's flags name its include root -I$includedir $roots times"
  # The -lasan rule crates/spdk-sys/native/select.rs (sanitizer) reads an
  # ASan install by.
  libs=$(native_pc --static --libs libdpdk 2>"$EVIDENCE/pkg-config.txt") \
    || fail "DPDK link metadata: $(cat "$EVIDENCE/pkg-config.txt")"
  sanitizer=
  [[ " $libs " != *" -lasan "* ]] || sanitizer=address
  # The line crates/spdk-sys/native/select.rs (flags_line) selects by, with
  # the install's include root normalized as that module normalizes it.
  line="Target: $(uname -m)-unknown-linux-gnu.${sanitizer:+ Sanitizer: $sanitizer.} Flags: ${cflags[*]} -Inative"
  installs=(crates/spdk-sys/src/generated/installs/*)
  for record in "${installs[@]}"; do
    targets+=("$(grep -m1 '^Target: ' "$record" || true)")
  done
  normalized=$(crates/spdk-sys/native/install.sh normalize "$line" "${targets[@]}") \
    || fail "normalizing the install records' target lines failed"
  mapfile -t forms <<<"$normalized"
  for i in "${!installs[@]}"; do
    [ "${forms[i + 1]:-}" != "${forms[0]}" ] || records+=("${installs[i]}")
  done
  [ "${#records[@]}" -eq 1 ] || fail "${#records[@]} install records name \`$line\`"
  output=$(sed -n 's/^Output: //p' "${records[0]}")
  [ -d "crates/spdk-sys/src/generated/outputs/$output" ] \
    || fail "${records[0]} names the output $output, which crates/spdk-sys/src/generated/outputs lacks"
  measured=$(crates/spdk-sys/native/install.sh measure "$libdir" "$includedir" "$EVIDENCE" 2> "$EVIDENCE/measure.txt") \
    || fail "measuring the install: $(cat "$EVIDENCE/measure.txt")"
  compilers=$(sed -n 's/^Compilers: //p' <<<"$measured")
  configure_sha=$(sed -n 's/^Configure: //p' <<<"$measured")
  archives=$(sha256sum < "$EVIDENCE/native-archives.txt" | cut -c1-64)
  # A record carrying the controlled build's lineage must name the pinned commits and what this install
  # measures; the record's digest is the identity receipts and envelopes bind.
  lineage=$(grep -E '^(Source|Patches|Build inputs|Compilers|Configure|Archive): ' "${records[0]}" | LC_ALL=C sort || true)
  if [ -n "$lineage" ]; then
    ! grep -qxE 'Build inputs: (unrecorded|stale)' <<<"$lineage" \
      || fail "${records[0]} records no digest of its build inputs"
    printf '%s\n' "Source: SPDK $SPDK_COMMIT DPDK $DPDK_COMMIT" "$measured" | LC_ALL=C sort > "$EVIDENCE/native-lineage.txt"
    [ "$lineage" = "$(cat "$EVIDENCE/native-lineage.txt")" ] \
      || fail "${records[0]} records a lineage this install does not measure (native-lineage.txt); a changed source, patch set, compiler, configuration or archive needs a new controlled build record"
    NATIVE_LINEAGE=$(sha256sum < "${records[0]}" | cut -c1-64)
  else
    NATIVE_LINEAGE=unrecorded
  fi
  configure_keys=$(grep -E 'SPDK_CONFIG_ARCH|RTE_MACHINE' "$EVIDENCE/native-configure.txt" | paste -sd';')
  NATIVE_RECORD=${records[0]} NATIVE_OUTPUT=crates/spdk-sys/src/generated/outputs/$output
  NATIVE_SANITIZER=$sanitizer NATIVE_COMPILERS=$compilers NATIVE_LIBDIR=$libdir
  NATIVE_CONFIGURE=$configure_sha NATIVE_ARCHIVES=$archives
  PINS+=("- install record ${records[0]} lineage $NATIVE_LINEAGE")
  {
    echo "- selected install $includedir; record ${records[0]} with generated crates/spdk-sys/src/generated/outputs/$output for \`$line\`"
    echo "- install compilers $compilers"
    echo "- install configure settings $configure_sha: $configure_keys"
    echo "- install archives $(wc -l < "$EVIDENCE/native-archives.txt") with sha256 $archives (native-archives.txt)"
    echo "- install record lineage $NATIVE_LINEAGE"
    echo "- compiling here is evidence for $(uname -m) alone; every other architecture's directory needs a receipt from its own host"
    echo "- the one-copy registry check scans library names in the process map; renamed, shared or static duplicates are outside its evidence"
  } > "$EVIDENCE/native.txt"
}

preflight() {
  local listed modules
  pins
  native_identity
  modules=$(python3 -c 'import json; print(json.dumps(sorted(json.load(open("scripts/test-inventory.json"))["loom"])))')
  echo "loom-modules=$modules" >> "${GITHUB_OUTPUT:-/dev/null}"
  summary "### Native pins" "${PINS[@]}" "$(cat "$EVIDENCE/native.txt")" "- Loom modules $modules"
  step registry-list "${STABLE_CARGO[@]}" test -p spdk-sys --lib registry_tests -- --list
  listed=$(grep -c ': test$' "$EVIDENCE/registry-list.txt" || true)
  [ "$listed" -eq "$REGISTRY_TESTS" ] || fail "$listed registry tests listed, declared $REGISTRY_TESTS"
  step registry-run deadline 20m \
    "${STABLE_CARGO[@]}" test -p spdk-sys --lib registry_tests --no-fail-fast
  grep -Eq "^test result: ok\. $REGISTRY_TESTS passed; 0 failed; 0 ignored;" \
    "$EVIDENCE/registry-run.txt" || fail "the $REGISTRY_TESTS registry tests did not all pass"
  summary "- the $REGISTRY_TESTS device-free registry tests passed; no hardware qualification is claimed"
}

listings() {
  step list "${LIST[@]}" -- --list
  step ignored "${LIST[@]}" -- --list --ignored
  python3 scripts/select-tests.py listing "$@" --list "$EVIDENCE/list.txt" \
    --ignored "$EVIDENCE/ignored.txt" > "$EVIDENCE/selection.json"
}

judge() {
  local watchdog=$1 code
  shift
  code=0
  deadline "$watchdog" "${RUN[@]}" > "$EVIDENCE/run.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  python3 scripts/select-tests.py run "$@" --list "$EVIDENCE/list.txt" \
    --ignored "$EVIDENCE/ignored.txt" --output "$EVIDENCE/run.txt" --exit "$code" \
    > "$EVIDENCE/report.json"
}

workspace() {
  # Debug assertions and overflow checks keep their dev-profile defaults.
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  pins
  printf '%s\n' "${PINS[@]}" > "$EVIDENCE/pins.txt"
  step fmt deadline 5m "${STABLE_CARGO[@]}" fmt --all -- --check
  step check deadline 25m "${STABLE_CARGO[@]}" check --workspace
  step clippy deadline 25m "${STABLE_CARGO[@]}" clippy --workspace --all-targets -- -D warnings
  LIST=(deadline 15m "${STABLE_CARGO[@]}" test --workspace)
  listings --cfg ordinary
  RUN=("${STABLE_CARGO[@]}" test --workspace --no-fail-fast)
  judge 60m --cfg ordinary
  # The census self-test runs after judge writes the suite's evidence, so a census break fails the lane
  # with the Rust evidence in place.
  step census deadline 5m python3 scripts/test-classify-atomics.py
  # The worker's protocol contract case links the supervisor's parser only under its own cfg, built in a
  # target directory of its own so the flag leaves the cache the later lanes reuse unchanged. A run that
  # selects no case exits 0, so the lane also requires the case's passing line.
  step contract deadline 10m env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="--cfg protocol_contract" \
    CARGO_TARGET_DIR="$CARGO_TARGET_DIR-contract" "${STABLE_CARGO[@]}" test -p kestrike --test sim_worker \
    -- --exact "$CONTRACT_CASE"
  grep -qxF "test $CONTRACT_CASE ... ok" "$EVIDENCE/contract.txt" \
    || fail "the protocol contract case $CONTRACT_CASE did not run and pass; see contract.txt in the evidence"
}

# A test lane of the inventory's `qualified` map: its target built with the
# pinned stable under the workspace profile, its rows' tests run by exact ID,
# among the ignored cases when the lane declares them, with output uncaptured
# so credit needs those tests passed and each row's lines in run.txt. It
# reuses the workspace lane's target cache when it
# runs on the same host.
qualified() {
  local lane=$1 spec crate target ignored ids selector
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  pins
  printf '%s\n' "${PINS[@]}" > "$EVIDENCE/pins.txt"
  mapfile -t spec < <(python3 -c 'import json, sys
lane = json.load(open("scripts/test-inventory.json"))["qualified"][sys.argv[1]]
print(lane["crate"], lane["target"], "--ignored" if lane["ignored"] else "", *(t for row in lane["rows"] for t in row["tests"]), sep="\n")' "$lane")
  crate=${spec[0]} target=${spec[1]} ignored=${spec[2]} ids=("${spec[@]:3}")
  selector=(--test "$target")
  [ "$target" != "${crate//-/_}" ] || selector=(--lib)
  LIST=(deadline 15m "${STABLE_CARGO[@]}" test -p "$crate" "${selector[@]}")
  listings --cfg qualified --module "$lane"
  RUN=("${STABLE_CARGO[@]}" test -p "$crate" "${selector[@]}" -- ${ignored:+"$ignored"} --nocapture --exact "${ids[@]}")
  printf 'CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only %s\n' "${RUN[*]}" \
    > "$EVIDENCE/replay.txt"
  judge 30m --cfg qualified --module "$lane"
}

# An architecture qualification lane: the host must be the lane's declared
# architecture and every processor record of /proc/cpuinfo must report every
# feature the lane's inventory entry declares, in cpuinfo's names, or the lane
# fails before it builds, leaving every row uncredited. Its rows then run as
# any qualified lane's, each witness line naming its kernel's count and
# detected predicate, decided by runtime detection or the build configuration.
isa() {
  local lane=$1 arch features missing
  read -r arch features < <(python3 -c 'import json, sys
lane = json.load(open("scripts/test-inventory.json"))["qualified"][sys.argv[1]]
print(lane["arch"], " ".join(lane["features"]))' "$lane")
  [ "$(uname -m)" = "$arch" ] || fail "$lane qualifies $arch kernels; this host is $(uname -m)"
  missing=$(awk -F': ' -v want="$features" '/^(flags|Features)[[:space:]]*:/ {
      records++; delete have; split($2, list, " "); for (i in list) have[list[i]] = 1
      for (name in have) seen[name]++ }
    END { split(want, need, " "); for (i = 1; i in need; i++) if (seen[need[i]] != records || !records) printf " %s", need[i] }' /proc/cpuinfo)
  [ -z "$missing" ] || fail "this host's CPU lacks the $lane features${missing}; every row stays uncredited"
  summary "- $lane host $(uname -m) reports every declared feature on every processor: $features"
  qualified "$lane"
}

loom() {
  local module=$1 version
  toolchain_pins
  target_dir loom
  unset "${!LOOM_@}"
  env | { grep '^LOOM_' || true; } > "$EVIDENCE/loom-env.txt"
  [ ! -s "$EVIDENCE/loom-env.txt" ] || fail "LOOM_* variables survived clearing"
  version=$("${STABLE_CARGO[@]}" tree -p kestrike -i loom --target all --depth 0 \
    --prefix none | awk '{print $2; exit}')
  [ "$version" = "v$LOOM" ] || fail "loom $version, pinned $LOOM"
  printf '%s\n' "${TOOLCHAIN_PINS[@]}" "- loom $version" > "$EVIDENCE/pins.txt"
  export RUSTFLAGS="--cfg loom"
  unset CARGO_ENCODED_RUSTFLAGS
  LIST=(deadline 15m "${STABLE_CARGO[@]}" test -p kestrike --lib --release "$module")
  listings --cfg loom --module "$module"
  RUN=("${STABLE_CARGO[@]}" test -p kestrike --lib --release "$module" --no-fail-fast)
  judge 60m --cfg loom --module "$module"
}

ASAN_TARGET=x86_64-unknown-linux-gnu
ASAN_RUSTFLAGS="-Zsanitizer=address -Cforce-frame-pointers=yes"
# Deadlines in minutes for each sanitized listing, the first of which builds,
# and for the run; scripts/qualified-envelope.py refuses either below its factor times
# the basis verification/asan/measurement.json records.
ASAN_BUILD_MINUTES=15
ASAN_RUN_MINUTES=20

# The address-sanitized lane: the spdk-sys and kestrike library tests built
# with the pinned nightly's -Zbuild-std against the sanitized install
# SPDK_PKG_CONFIG_PATH names, judged under the asan cfg, with the qualified
# envelope the receipt binds written to qualified.json. The install's own
# -lasan selects the sanitized generated directory; an unsanitized install is
# refused before any build.
asan() {
  local sysroot runtime llvm symbolizer version envelope archive
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  pins
  native_identity
  [ "$NATIVE_SANITIZER" = address ] \
    || fail "the install in $SPDK_PKG_CONFIG_PATH links no -lasan; the ASan lane needs an --enable-asan install"
  # An object compiled under -fsanitize=address references __asan_init from
  # its module constructor. grep consumes the full listing so nm finishes
  # writing under pipefail.
  for archive in libspdk_nvme.a librte_eal.a; do
    nm --undefined-only "$NATIVE_LIBDIR/$archive" 2>/dev/null | grep ' U __asan_init$' > /dev/null \
      || fail "$NATIVE_LIBDIR/$archive references no __asan_init; the ASan lane needs archives compiled under -fsanitize=address"
  done
  target_dir asan
  unset CARGO_ENCODED_RUSTFLAGS
  export RUSTFLAGS="$ASAN_RUSTFLAGS" ASAN_OPTIONS=detect_leaks=0
  sysroot=$(rustc "+$NIGHTLY" --print sysroot)
  runtime=$sysroot/lib/rustlib/$ASAN_TARGET/lib/librustc-nightly_rt.asan.a
  [ -f "$runtime" ] || fail "the nightly supplies no address sanitizer runtime at $runtime"
  llvm=$(rustc "+$NIGHTLY" -vV | sed -n 's/^LLVM version: //p')
  [ -n "$llvm" ] || fail "the nightly reports no LLVM version"
  # The sanitizer runtime names report frames through llvm-symbolizer on
  # PATH, and the shim's overflow control requires the report to name the
  # shim frame.
  symbolizer=$(command -v llvm-symbolizer) \
    || fail "llvm-symbolizer is missing from PATH; the overflow control needs named frames; provision LLVM on the runner"
  version=$("$symbolizer" --version 2>&1) \
    || fail "llvm-symbolizer --version failed; provision LLVM on the runner"
  printf '%s\n' "${PINS[@]}" "- RUSTFLAGS=$RUSTFLAGS; ASAN_OPTIONS=$ASAN_OPTIONS" \
    "- llvm-symbolizer $symbolizer; $(printf '%s' "$version" | tr -s '[:space:]' ' ' | sed 's/ $//')" > "$EVIDENCE/pins.txt"
  envelope=$(python3 scripts/qualified-envelope.py asan --record "$NATIVE_RECORD" --bindings "$NATIVE_OUTPUT/bindings.rs" \
    --target "$ASAN_TARGET" \
    --rustflags="$RUSTFLAGS" --sanitizer address --compilers "$NATIVE_COMPILERS" --configure "$NATIVE_CONFIGURE" \
    --archives "$NATIVE_ARCHIVES" --lineage "$NATIVE_LINEAGE" --runtime "$runtime" --rustc "$(rustc "+$NIGHTLY" --version)" --llvm "$llvm" \
    --build-minutes "$ASAN_BUILD_MINUTES" --run-minutes "$ASAN_RUN_MINUTES") \
    || fail "the qualified envelope was refused"
  printf '%s\n' "$envelope" > "$EVIDENCE/qualified.json"
  LIST=(deadline "${ASAN_BUILD_MINUTES}m" cargo "+$NIGHTLY" test -Zbuild-std --target "$ASAN_TARGET" -p spdk-sys -p kestrike --lib)
  listings --cfg asan
  RUN=(cargo "+$NIGHTLY" test -Zbuild-std --target "$ASAN_TARGET" -p spdk-sys -p kestrike --lib --no-fail-fast)
  printf 'CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only SPDK_PKG_CONFIG_PATH=%s RUSTFLAGS="%s" ASAN_OPTIONS=%s %s\n' \
    "$SPDK_PKG_CONFIG_PATH" "$RUSTFLAGS" "$ASAN_OPTIONS" "${RUN[*]}" > "$EVIDENCE/replay.txt"
  judge "${ASAN_RUN_MINUTES}m" --cfg asan
}

# The ThreadSanitizer run over the library tests of the storage, index and
# client route modules, on aarch64 alone, and the planted race it must report.
# The filters select by substring; the listing check requires, per filter, a
# test whose ID starts with it.
TSAN_FILTERS=(storage:: index:: net::client::route)
TSAN_CONTROL=storage::gate::tests::negative_control_a_relaxed_take_races_the_guarded_counter
# The production gate under the control's contention workload; its passing
# line ties the control's report to the control's Relaxed take.
TSAN_POSITIVE=storage::gate::tests::contending_takers_and_waiters_never_overlap_and_see_each_other
TSAN_RACE="ThreadSanitizer: data race"
TSAN_FRAME=storage::gate::tests::contend
TSAN_ACCESS="^SUMMARY: $TSAN_RACE .*/storage/gate\.rs:[0-9]+:[0-9]+ "
TSAN_TARGET=aarch64-unknown-linux-gnu
TSAN_RUSTFLAGS="-Zsanitizer=thread -C target-feature=+lse"
# Deadlines in minutes for the listing, which builds, the run and the control. On an
# r8gb.4xlarge aarch64 host (Neoverse V2, 16 CPUs) at four Cargo jobs and four test
# threads, the cold build took 387 s at an 11.5 GB cgroup memory peak, and the run of
# 2548 tests took 92 s at 4.1 GB; the build deadline is 4 times the build and the run
# deadline 10 times the run, rounded up. The control took 0.41 s in each of three runs.
TSAN_BUILD_MINUTES=26
TSAN_RUN_MINUTES=16
TSAN_CONTROL_MINUTES=3

# The thread-sanitized step of the AArch64 job: the kestrike library tests
# built with the pinned nightly's -Zbuild-std under ThreadSanitizer, the
# selection run with the control skipped and no report allowed, then the
# control alone in the same executable, which must report its race. The
# runtime writes each process's reports to log_path.PID. Any regular file
# matching report.* under tsan-run/ fails the step, and one report.PID under
# tsan-control/ must hold both TSAN_FRAME and a TSAN_ACCESS line. The step
# clears both report directories and its record files before testing and
# appends to the step summary.
tsan() {
  local symbolizer version filter listed passed exe code found reports report run_reports control_reports
  run_reports=$EVIDENCE/tsan-run control_reports=$EVIDENCE/tsan-control
  rm -rf -- "$run_reports" "$control_reports"
  rm -f -- "$EVIDENCE"/{pins,pkg-config,replay,list,run,exit,control,controls,failure}.txt
  summary "- this step credits no obligation record; a clean run judges only the schedules that ran and is no evidence about reordering on a weakly ordered CPU"
  # The runtime splits TSAN_OPTIONS at whitespace, commas and colons and expands % patterns in log_path.
  case $EVIDENCE in *[[:space:],:%]*) fail "the evidence path $EVIDENCE holds a character TSAN_OPTIONS cannot carry in log_path" ;; esac
  [ "$(uname -m)" = aarch64 ] || fail "the ThreadSanitizer run needs a native AArch64 host, not $(uname -m)"
  symbolizer=$(command -v llvm-symbolizer) \
    || fail "llvm-symbolizer is missing from PATH; the reports need named frames; provision LLVM on the runner"
  version=$("$symbolizer" --version 2>&1) || fail "llvm-symbolizer --version failed; provision LLVM on the runner"
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  # The step needs Cargo's `Running` line visible, uncolored and in its concise form to extract the executable
  # path; the verbose form is the test command line, which holds the skipped control's ID.
  export CARGO_TERM_COLOR=never CARGO_TERM_QUIET=false CARGO_TERM_VERBOSE=false
  unset CARGO_ENCODED_RUSTFLAGS
  # RUSTFLAGS replaces the flags of .cargo/config.toml, so the lane carries its LSE flag itself.
  export RUSTFLAGS="$TSAN_RUSTFLAGS"
  pins
  target_dir tsan
  mkdir -p "$run_reports" "$control_reports"
  export TSAN_OPTIONS="halt_on_error=0 allocator_may_return_null=1 log_path=$run_reports/report"
  local control_options="halt_on_error=1 allocator_may_return_null=1 log_path=$control_reports/report"
  printf '%s\n' "${PINS[@]}" "- RUSTFLAGS=$RUSTFLAGS; TSAN_OPTIONS=$TSAN_OPTIONS" \
    "- llvm-symbolizer $symbolizer; $(printf '%s' "$version" | tr -s '[:space:]' ' ' | sed 's/ $//')" > "$EVIDENCE/pins.txt"
  local build=(cargo "+$NIGHTLY" test -Zbuild-std --target "$TSAN_TARGET" -p kestrike --lib)
  local run=("${build[@]}" -- "${TSAN_FILTERS[@]}" --skip "$TSAN_CONTROL")
  { printf '%q ' env -u CARGO_ENCODED_RUSTFLAGS CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only \
      CARGO_TERM_COLOR=never CARGO_TERM_QUIET=false CARGO_TERM_VERBOSE=false \
      "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" "SPDK_PKG_CONFIG_PATH=$SPDK_PKG_CONFIG_PATH" "RUSTFLAGS=$RUSTFLAGS" \
      "TSAN_OPTIONS=$TSAN_OPTIONS" "${run[@]}"; printf '\n'; } > "$EVIDENCE/replay.txt"
  step list deadline "${TSAN_BUILD_MINUTES}m" "${build[@]}" -- --list
  for filter in "${TSAN_FILTERS[@]}"; do
    listed=$(grep -c -- "^${filter}.*: test$" "$EVIDENCE/list.txt" || true)
    [ "$listed" -gt 0 ] || fail "no listed test starts with the filter $filter"
    summary "- ThreadSanitizer filter $filter lists $listed tests by prefix"
  done
  grep -qxF "$TSAN_CONTROL: test" "$EVIDENCE/list.txt" \
    || fail "the build lists no $TSAN_CONTROL; it compiled without cfg(kestrike_tsan)"
  code=0
  deadline "${TSAN_RUN_MINUTES}m" "${run[@]}" > "$EVIDENCE/run.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  reports=$(find "$run_reports" -type f -name 'report.*' -printf ' %f')
  [ "$code" -ne 124 ] \
    || fail "the sanitized run reached its ${TSAN_RUN_MINUTES}-minute deadline${reports:+ after writing reports$reports}; see run.txt${reports:+ and tsan-run/}"
  [ -z "$reports" ] || fail "the sanitized run wrote reports$reports; see tsan-run/"
  [ "$code" -eq 0 ] || fail "the sanitized run exited $code; see run.txt"
  grep -Eq '^test result: ok\. [1-9][0-9]* passed;' "$EVIDENCE/run.txt" \
    || fail "the sanitized run reported no passing test result; see run.txt"
  grep -qxF "test $TSAN_POSITIVE ... ok" "$EVIDENCE/run.txt" \
    || fail "the sanitized run holds no passing line for $TSAN_POSITIVE"
  ! grep -qF "$TSAN_CONTROL" "$EVIDENCE/run.txt" || fail "the sanitized run executed $TSAN_CONTROL"
  for filter in "${TSAN_FILTERS[@]}"; do
    passed=$(grep -c -- "^test ${filter}.* \.\.\. ok$" "$EVIDENCE/run.txt" || true)
    [ "$passed" -gt 0 ] || fail "the sanitized run passed no test that starts with the filter $filter"
    summary "- ThreadSanitizer filter $filter passed $passed tests"
  done
  exe=$(sed -n 's/^ *Running unittests src\/lib\.rs (\(.*\))$/\1/p' "$EVIDENCE/run.txt")
  # Two Running lines make a two-line path, which -x refuses.
  [ -n "$exe" ] && [ -x "$exe" ] || fail "the sanitized run names no one library-test executable"
  summary "- ThreadSanitizer run: $(grep -m1 '^test result:' "$EVIDENCE/run.txt") No report."
  local control=("$exe" --exact "$TSAN_CONTROL")
  { printf '%q ' env "TSAN_OPTIONS=$control_options" "${control[@]}"; printf '\n'; } >> "$EVIDENCE/replay.txt"
  code=0
  TSAN_OPTIONS="$control_options" \
    deadline "${TSAN_CONTROL_MINUTES}m" "${control[@]}" > "$EVIDENCE/control.txt" 2>&1 || code=$?
  found=absent
  # The control requires the TSAN_ACCESS summary and TSAN_FRAME in the same report file.
  for report in "$control_reports"/report.*; do
    [ -f "$report" ] && grep -qF -- "$TSAN_FRAME" "$report" && grep -qE -- "$TSAN_ACCESS" "$report" && found=found
  done
  printf '%s\t%s\t%s\n' "$TSAN_CONTROL" "$code" "$found" > "$EVIDENCE/controls.txt"
  if [ "$code" -eq 0 ] || [ "$code" -eq 124 ] || [ "$found" != found ]; then
    [ "$code" -ne 124 ] || printf '124\n' > "$EVIDENCE/exit.txt"
    fail "the ThreadSanitizer control $TSAN_CONTROL exited $code with its report $found; it must exit nonzero inside its deadline with '$TSAN_RACE' in $TSAN_FRAME at storage/gate.rs in a report file; see control.txt and tsan-control/"
  fi
  summary "- ThreadSanitizer control $TSAN_CONTROL exited $code and reported its race in $TSAN_FRAME"
}

LITMUS_TESTS=(
  "storage::litmus_tests::a_parked_credit_keeps_its_record_flagged_against_a_scan credit"
  "storage::litmus_tests::a_pinned_reader_is_seen_by_a_pass_that_starts_past_the_bump grace"
  "storage::litmus_tests::a_departed_failure_is_seen_with_its_terminal fill"
)
LITMUS_ROUNDS=10000000
# On an r8gb.4xlarge aarch64 host (Neoverse V2, 16 CPUs) at four Cargo
# jobs, the cold library-test build took 304 s and the three loops 28 s; the
# build deadline is 4 times the build and the run deadline 10 times the run,
# rounded up.
LITMUS_BUILD_MINUTES=21
LITMUS_RUN_MINUTES=5

# The native litmus step of the AArch64 job: the kestrike library tests
# built with the pinned stable in the workspace profile, whose aarch64 flags
# come from .cargo/config.toml, then the ignored loops by exact ID on one
# test thread. Each loop prints one line; the step requires, per loop, exactly
# one line naming aarch64, the declared rounds, no forbidden outcome at
# production strength and a positive count from the weakened twin.
litmus() {
  local entry name ids=() line lines code
  summary "- this step credits no obligation record; zero forbidden outcomes is a finite sample for one build on one CPU"
  [ "$(uname -m)" = aarch64 ] || fail "the litmus loops need a native AArch64 host, not $(uname -m)"
  local profile=(CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only)
  export "${profile[@]}"
  # A set flag variable replaces the LSE flag of .cargo/config.toml.
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS
  pins
  printf '%s\n' "${PINS[@]}" > "$EVIDENCE/pins.txt"
  for entry in "${LITMUS_TESTS[@]}"; do
    ids+=("${entry%% *}")
  done
  local build=("${STABLE_CARGO[@]}" test -p kestrike --lib)
  local run=("${build[@]}" -- --ignored --nocapture --test-threads=1 --exact "${ids[@]}")
  {
    printf 'env -u RUSTFLAGS -u CARGO_ENCODED_RUSTFLAGS'
    printf ' %q' "${profile[@]}" "CARGO_TARGET_DIR=$CARGO_TARGET_DIR" \
      ${SPDK_PKG_CONFIG_PATH+"SPDK_PKG_CONFIG_PATH=$SPDK_PKG_CONFIG_PATH"} "${run[@]}"
    printf '\n'
  } > "$EVIDENCE/replay.txt"
  step build deadline "${LITMUS_BUILD_MINUTES}m" "${build[@]}" --no-run
  code=0
  deadline "${LITMUS_RUN_MINUTES}m" "${run[@]}" > "$EVIDENCE/run.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -ne 124 ] || fail "the litmus loops reached their ${LITMUS_RUN_MINUTES}-minute deadline; see run.txt"
  # Every byte of a line is part of its record, and only ASCII digits form a
  # count: in the C locale grep's `.` matches each byte of a line. Reject NUL
  # bytes because GNU grep can suppress matching lines in binary input.
  local -x LC_ALL=C
  [ "$(tr -cd '\0' < "$EVIDENCE/run.txt" | wc -c)" -eq 0 ] || fail "the litmus run wrote a NUL byte; see run.txt"
  for entry in "${LITMUS_TESTS[@]}"; do
    name=${entry##* }
    line=$(grep -o "litmus: $name .*" "$EVIDENCE/run.txt" || true)
    lines=$(printf '%s' "$line" | grep -c . || true)
    [ "$lines" -eq 1 ] || fail "the $name loop printed $lines lines; it prints one"
    [[ "$line" =~ ^litmus:\ $name\ ran\ $LITMUS_ROUNDS\ rounds\;\ aarch64\ forbidden=0\ control=[1-9][0-9]*$ ]] \
      || fail "the $name loop did not report aarch64, $LITMUS_ROUNDS rounds, forbidden=0 and a positive control: $line"
    summary "- $line"
  done
  [ "$code" -eq 0 ] || fail "the litmus loops exited $code; see run.txt"
}

# Deadlines in minutes for the guest's ready handshake and for its run;
# scripts/qualified-envelope.py refuses either below its factor times the
# basis verification/qemu/measurement.json records under the runner quota.
QEMU_HANDSHAKE_MINUTES=5
QEMU_RUN_MINUTES=15
# The guest inputs the platform owner provisions, one
# `KESTRIKE_GUEST_NAME=value` line each in the file
# KESTRIKE_GUEST_INPUTS names, and the ones every run needs.
GUEST_INPUTS=(QEMU KERNEL INITRD ARTIFACT ACCEL MEMORY_MIB CPUS BACKING_MIB)
GUEST_REQUIRED=(QEMU KERNEL INITRD ARTIFACT)
# Where the guest's init finds the test executable the lane appends to its initrd.
GUEST_EXECUTABLE=usr/lib/kestrike/kestrike-tests

# Reads the guest inputs file into GUEST_<NAME> variables, refusing any other
# line, a repeated name and a carriage return.
guest_inputs() {
  local line name value ref seen=" "
  GUEST_ACCEL=kvm GUEST_MEMORY_MIB=2048 GUEST_CPUS=2 GUEST_BACKING_MIB=64
  GUEST_QEMU= GUEST_KERNEL= GUEST_INITRD= GUEST_ARTIFACT=
  [ -n "${KESTRIKE_GUEST_INPUTS:-}" ] \
    || fail "KESTRIKE_GUEST_INPUTS is unset; the platform owner provisions the guest inputs file"
  [ -f "$KESTRIKE_GUEST_INPUTS" ] \
    || fail "the guest inputs file $KESTRIKE_GUEST_INPUTS is missing; the platform owner provisions it"
  while IFS= read -r line || [ -n "$line" ]; do
    [[ $line != *$'\r'* ]] || fail "the guest inputs file holds a carriage return; write it with Unix line ends"
    [[ $line =~ ^[[:space:]]*(#.*)?$ ]] && continue
    [[ $line =~ ^KESTRIKE_GUEST_([A-Z_]+)=(.*)$ ]] \
      || fail "the guest inputs file holds a line outside KESTRIKE_GUEST_NAME=value: $line"
    name=${BASH_REMATCH[1]} value=${BASH_REMATCH[2]}
    [[ " ${GUEST_INPUTS[*]} " == *" $name "* ]] || fail "the guest inputs file names an unknown input $name"
    [[ $seen != *" $name "* ]] || fail "the guest inputs file sets KESTRIKE_GUEST_$name twice"
    seen+="$name "
    printf -v "GUEST_$name" '%s' "$value"
  done < "$KESTRIKE_GUEST_INPUTS"
  for name in "${GUEST_REQUIRED[@]}"; do
    ref=GUEST_$name
    [ -n "${!ref}" ] || fail "the guest inputs file sets no KESTRIKE_GUEST_$name"
  done
}

# The guest lane: the ignored guest binder case run by exact ID inside the
# disposable QEMU guest scripts/guest-binder.py starts from the provisioned
# inputs. The lane builds the kestrike library tests at this revision
# against the portable install the artifact reference names (its install
# record and archives must be the ones the reference names), with its
# rustflags, appends that executable to the provisioned initrd as a newc
# archive at GUEST_EXECUTABLE, and the guest runs it; the envelope binds the
# executable's and the combined initrd's digests, and the verifier requires
# the guest record's initrd digest to equal the combined one. The host lists
# the same build, so the guest's filtered-out count matches its census; the
# console is the run output the qemu cfg judges, and the harness's
# guest.json joins the receipt.
qemu() {
  local code=0 record install executable overlay initrd envelope size
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  guest_inputs
  [ -f "$GUEST_ARTIFACT" ] || fail "the artifact reference $GUEST_ARTIFACT is missing; the hardware build publishes it"
  install=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["install"])' "$GUEST_ARTIFACT") \
    || fail "the artifact reference $GUEST_ARTIFACT names no install"
  export SPDK_PKG_CONFIG_PATH=$install/lib/pkgconfig
  pins
  native_identity
  [ "$(basename "$NATIVE_RECORD")" = "$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["generated"])' "$GUEST_ARTIFACT")" ] \
    || fail "the artifact's install selects $NATIVE_RECORD, not the install record its reference names"
  [ "$NATIVE_ARCHIVES" = "$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["archives"])' "$GUEST_ARTIFACT")" ] \
    || fail "the artifact's install holds archives $NATIVE_ARCHIVES, not the archives its reference names"
  target_dir qemu
  unset CARGO_ENCODED_RUSTFLAGS
  RUSTFLAGS=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["rustflags"])' "$GUEST_ARTIFACT")
  export RUSTFLAGS
  printf '%s\n' "${PINS[@]}" "- RUSTFLAGS=$RUSTFLAGS" \
    "- guest inputs $KESTRIKE_GUEST_INPUTS; accel $GUEST_ACCEL; memory $GUEST_MEMORY_MIB MiB; cpus $GUEST_CPUS; backing $GUEST_BACKING_MIB MiB" \
    > "$EVIDENCE/pins.txt"
  LIST=(deadline 15m "${STABLE_CARGO[@]}" test -p kestrike --lib)
  listings --cfg qemu
  step build deadline 15m "${STABLE_CARGO[@]}" test -p kestrike --lib --no-run --message-format=json-render-diagnostics
  executable=$(python3 -c '
import json, sys
messages = [json.loads(line) for line in open(sys.argv[1]) if line.startswith("{")]
found = {m["executable"] for m in messages if m.get("reason") == "compiler-artifact" and m.get("executable")
         and m["target"]["name"] == "kestrike" and m["profile"]["test"]}
print(found.pop() if len(found) == 1 else "")' "$EVIDENCE/build.txt")
  [ -n "$executable" ] || fail "the build named no unique kestrike library test executable; see build.txt"
  # The kernel unpacks concatenated archives in order, so the appended executable lands in the guest's root. After
  # a compressed member, the kernel skips NUL padding and requires the next newc header to start at a 4-byte-aligned
  # offset, so NULs pad the base to that boundary.
  overlay=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/guest-overlay.XXXXXX")
  mkdir -p "$overlay/$(dirname "$GUEST_EXECUTABLE")"
  install -m 0755 "$executable" "$overlay/$GUEST_EXECUTABLE"
  initrd=$EVIDENCE/guest-initrd.img
  size=$(stat -c %s "$GUEST_INITRD")
  { cat "$GUEST_INITRD"; head -c $(((4 - size % 4) % 4)) /dev/zero
    (cd "$overlay" && find usr | LC_ALL=C sort | cpio --quiet -o -H newc --reproducible -R 0:0); } > "$initrd" \
    || fail "appending the test executable to the guest initrd failed"
  rm -rf "$overlay"
  envelope=$(python3 scripts/qualified-envelope.py qemu --artifact "$GUEST_ARTIFACT" --compilers "$NATIVE_COMPILERS" \
    --configure "$NATIVE_CONFIGURE" --lineage "$NATIVE_LINEAGE" --host-kernel "$(uname -r)" --host-machine "$(uname -m)" --runner "${RUNNER_NAME:-local}" \
    --cpus "$GUEST_CPUS" --memory-mib "$GUEST_MEMORY_MIB" --backing-mib "$GUEST_BACKING_MIB" \
    --accel "$GUEST_ACCEL" --inputs "$KESTRIKE_GUEST_INPUTS" --executable "$executable" --initrd "$initrd" \
    --handshake-minutes "$QEMU_HANDSHAKE_MINUTES" --run-minutes "$QEMU_RUN_MINUTES" 2> "$EVIDENCE/envelope.txt") \
    || fail "the qualified envelope was refused: $(cat "$EVIDENCE/envelope.txt")"
  printf '%s\n' "$envelope" > "$EVIDENCE/qualified.json"
  RUN=(python3 scripts/guest-binder.py --qemu "$GUEST_QEMU" --kernel "$GUEST_KERNEL" --initrd "$initrd"
    --artifacts "$EVIDENCE/guest" --accel "$GUEST_ACCEL" --memory-mib "$GUEST_MEMORY_MIB" --cpus "$GUEST_CPUS"
    --backing-mib "$GUEST_BACKING_MIB" --handshake-seconds $((QEMU_HANDSHAKE_MINUTES * 60))
    --deadline-seconds $((QEMU_RUN_MINUTES * 60)))
  { printf 'KESTRIKE_GUEST_INPUTS=%q ' "$KESTRIKE_GUEST_INPUTS"; printf '%q ' "${RUN[@]}"; printf '\n'; } > "$EVIDENCE/replay.txt"
  # The harness bounds its own run, so the wrapper allows it one more minute; a refused input leaves the
  # artifacts directory empty, with the harness's reason in guest.txt.
  rm -rf "$EVIDENCE/guest"
  mkdir -p "$EVIDENCE/guest"
  deadline "$((QEMU_RUN_MINUTES + 1))m" "${RUN[@]}" > "$EVIDENCE/guest.txt" 2>&1 || code=$?
  # The harness exits 5 for an interruption and 6 for its run deadline; both are the lane's timeout.
  [ "$code" -ne 5 ] && [ "$code" -ne 6 ] || code=124
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  record=$(find "$EVIDENCE/guest" -name guest.json | head -n 1; true)
  [ -z "$record" ] || cp "$record" "$EVIDENCE/guest.json"
  # The console is the case's libtest output under the header cargo prints for the executable the guest ran.
  {
    printf '     Running unittests src/lib.rs (%s)\n' "$executable"
    [ -z "$record" ] || [ ! -f "$(dirname "$record")/console.log" ] || cat "$(dirname "$record")/console.log"
  } > "$EVIDENCE/run.txt"
  python3 scripts/select-tests.py run --cfg qemu --list "$EVIDENCE/list.txt" --ignored "$EVIDENCE/ignored.txt" \
    --output "$EVIDENCE/run.txt" --exit "$code" > "$EVIDENCE/report.json"
}

# Default detectors and Stacked Borrows; the permissive-provenance flag only
# silences the integer-to-pointer warning, whose text would split libtest's
# outcome lines.
PROVENANCE_FLAG="-Zmiri-permissive-provenance"
CORPUS_FLAGS="-Zmiri-seed=0 $PROVENANCE_FLAG"

# Prepares the interpreter for one Miri lane with MIRIFLAGS=$1. A runner's
# ambient compiler or interpreter settings would change what is interpreted
# without failing the run, so only the lane's own survive. The sysroot is
# rebuilt per run, so no earlier job's copy is interpreted. Runs `miri setup`
# and writes miri-env.txt and pins.txt.
interpreter() {
  local version scoped
  toolchain_pins
  target_dir miri
  # Cargo reads rustflags from CARGO_ENCODED_RUSTFLAGS before any config file,
  # so its empty value also overrides config-file rustflags. A fresh
  # MIRI_SYSROOT directory isolates each run's sysroot.
  unset "${!MIRI@}" "${!CARGO_PROFILE_@}" "${!CARGO_BUILD_@}" RUSTFLAGS \
    RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER
  mapfile -t scoped < <(compgen -v | grep -E '^CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS$' || true)
  [ "${#scoped[@]}" -eq 0 ] || unset "${scoped[@]}"
  export CARGO_ENCODED_RUSTFLAGS=
  export MIRIFLAGS=$1
  MIRI_SYSROOT=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/miri-sysroot.XXXXXX")
  export MIRI_SYSROOT
  env | { grep -E '^(MIRI|RUSTFLAGS=|CARGO_ENCODED_RUSTFLAGS=|CARGO_BUILD_|CARGO_PROFILE_|CARGO_TARGET_[A-Z0-9_]+_RUSTFLAGS=|RUSTC_(WORKSPACE_)?WRAPPER=)' || true; } \
    | LC_ALL=C sort > "$EVIDENCE/miri-env.txt"
  [ "$(cat "$EVIDENCE/miri-env.txt")" = "$(printf 'CARGO_ENCODED_RUSTFLAGS=\nMIRIFLAGS=%s\nMIRI_SYSROOT=%s' "$1" "$MIRI_SYSROOT")" ] \
    || fail "ambient Miri, rustc flag or profile variables survived clearing"
  step setup deadline 10m cargo "+$NIGHTLY" miri setup
  version=$(cargo "+$NIGHTLY" miri --version)
  printf '%s\n' "${TOOLCHAIN_PINS[@]}" "- $version; MIRIFLAGS=$MIRIFLAGS" \
    "- build-time native pins, checked by preflight: SPDK $SPDK_VERSION at $SPDK_COMMIT; DPDK $DPDK_VERSION at $DPDK_COMMIT" \
    > "$EVIDENCE/pins.txt"
}

# Prints one line per entry of the inventory's $1 list at key $2.
declared() {
  python3 -c 'import json, sys; print("\n".join(json.load(open("scripts/test-inventory.json"))[sys.argv[1]][sys.argv[2]]))' "$1" "$2"
}

miri() {
  local ids
  interpreter "$CORPUS_FLAGS"
  mapfile -t ids < <(declared miri tests)
  RUN=(cargo "+$NIGHTLY" miri test -p kestrike --lib -- --exact "${ids[@]}" --test-threads=1)
  # The run interprets the selected IDs in one process from one seed, so only the
  # whole command replays its schedule; a per-ID command replays a failure
  # that reproduces in isolation. The empty CARGO_ENCODED_RUSTFLAGS outranks
  # RUSTFLAGS and every rustflags config source, so a replay from another
  # shell compiles with the lane's flags.
  {
    printf 'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="%s" %s\n' "$MIRIFLAGS" "${RUN[*]}"
    for id in "${ids[@]}"; do
      printf 'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="%s" cargo +%s miri test -p kestrike --lib -- --exact %s --test-threads=1\n' \
        "$MIRIFLAGS" "$NIGHTLY" "$id"
    done
  } > "$EVIDENCE/replay.txt"
  LIST=(deadline 10m cargo "+$NIGHTLY" miri test -p kestrike --lib)
  listings --cfg miri
  judge 20m --cfg miri
  miri_controls
}

# Each negative control of the inventory's `miri` entry runs on its own and
# must produce a nonzero exit and its declared diagnostic. Exit 124 is the
# deadline's stop, so a control that timed out fails whatever it printed and
# leaves 124 in exit.txt, as a stopped step does. controls.txt records each run's id, exit and whether the diagnostic
# appeared; the receipt binds it and credits the lane from those lines.
miri_controls() {
  local id diagnostic code n=0 controls found
  controls=$(python3 -c 'import json; [print(c["test"], c["diagnostic"], sep="\t") for c in json.load(open("scripts/test-inventory.json"))["miri"]["controls"]]') \
    || fail "the inventory's miri controls are unreadable"
  : > "$EVIDENCE/controls.txt"
  while IFS=$'\t' read -r id diagnostic; do
    [ -n "$id" ] || continue
    n=$((n + 1))
    code=0
    deadline 3m cargo "+$NIGHTLY" miri test -p kestrike --lib -- --exact "$id" --test-threads=1 \
      > "$EVIDENCE/control-$n.txt" 2>&1 || code=$?
    printf 'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="%s" cargo +%s miri test -p kestrike --lib -- --exact %s --test-threads=1\n' \
      "$MIRIFLAGS" "$NIGHTLY" "$id" >> "$EVIDENCE/replay.txt"
    found=absent
    ! grep -qF -- "$diagnostic" "$EVIDENCE/control-$n.txt" || found=found
    printf '%s\t%s\t%s\n' "$id" "$code" "$found" >> "$EVIDENCE/controls.txt"
    if [ "$code" -eq 0 ] || [ "$code" -eq 124 ] || [ "$found" != found ]; then
      [ "$code" -ne 124 ] || printf '124\n' > "$EVIDENCE/exit.txt"
      fail "the Miri control $id exited $code without the diagnostic '$diagnostic'; see control-$n.txt"
    fi
  done <<< "$controls"
  [ "$n" -gt 0 ] || fail "the inventory declares no miri control"
}

# The sweep's one rustc thread runs its seeds in order, so each seed's output
# stays one block. A refused sweep appends a one-seed replay for each seed the
# run reported failing before the lane fails.
miri_sweep() {
  local ids seeds flags seed
  seeds=$(python3 -c 'import json; print(json.load(open("scripts/test-inventory.json"))["miri_sweep"]["seeds"])')
  flags="-Zmiri-many-seeds=0..$seeds $PROVENANCE_FLAG -Zthreads=1"
  interpreter "$flags"
  mapfile -t ids < <(declared miri_sweep tests)
  RUN=(cargo "+$NIGHTLY" miri test -p kestrike --lib -- --exact "${ids[@]}" --test-threads=1)
  printf 'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="%s" %s\n' "$flags" "${RUN[*]}" > "$EVIDENCE/replay.txt"
  # A listing interprets no test, so one seed lists what every seed would.
  LIST=(deadline 10m cargo "+$NIGHTLY" miri test -p kestrike --lib)
  MIRIFLAGS=$CORPUS_FLAGS
  listings --cfg miri-sweep
  MIRIFLAGS=$flags
  judge 30m --cfg miri-sweep || {
    sed -n 's/^FAILING SEED: \([0-9][0-9]*\).*/\1/p' "$EVIDENCE/run.txt" | while read -r seed; do
      printf 'CARGO_ENCODED_RUSTFLAGS= MIRIFLAGS="-Zmiri-seed=%s %s" %s\n' "$seed" "$PROVENANCE_FLAG" "${RUN[*]}"
    done >> "$EVIDENCE/replay.txt"
    fail "the sweep was refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
  }
}

# Runner provisioning owns the checker installation. A job must refuse a
# missing or mismatched checker without installing packages or using sudo.
# The judgment also verifies the model closure and records the binary digest.
herdtools() {
  local herd version
  herd=$(command -v herd7) \
    || fail "herd7 is missing from PATH; provision herdtools7 $HERDTOOLS7 on the runner"
  version=$("$herd" -version) \
    || fail "herd7 -version failed; provision herdtools7 $HERDTOOLS7 on the runner"
  [[ "$version" == "$HERDTOOLS7,"* ]] \
    || fail "herd7 reports '$version'; the runner requires herdtools7 $HERDTOOLS7"
}

# herd7 loads a model file from its working directory or HERDLIB before its
# library directory, so every herd7 call runs from an empty directory with
# HERDLIB unset and absolute paths.
rc11() {
  local herd test name code options argv work root=$PWD
  herdtools
  herd=$(command -v herd7) || fail "herd7 is not installed"
  unset HERDLIB
  work=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/rc11.XXXXXX")
  cd "$work"
  step identity python3 "$root/scripts/judge-rc11.py" identity --herd7 "$herd" --libdir "$(herd7 -libdir)" \
    --evidence "$EVIDENCE"
  mapfile -t options < <(python3 "$root/scripts/judge-rc11.py" options)
  mkdir -p "$EVIDENCE/graphs"
  # The judge reads herd-<test>.argv, so the record and the run share one array.
  for test in "$root"/verification/rc11/litmus/*.litmus; do
    name=$(basename "$test" .litmus)
    argv=("$herd" "${options[@]}" -show prop -o "$EVIDENCE/graphs" "$test")
    printf '%s\n' "${argv[@]}" > "$EVIDENCE/herd-$name.argv"
    code=0
    deadline 1m "${argv[@]}" > "$EVIDENCE/herd-$name.txt" 2>&1 || code=$?
    printf '%s\n' "$code" > "$EVIDENCE/herd-$name.exit"
  done
  cd "$root"
  code=0
  python3 scripts/judge-rc11.py judge --evidence "$EVIDENCE" > /dev/null || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the RC11 judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

kani_toolchain() {
  local root="$HOME/.cache/kestrike-kani/$KANI"
  # `cargo kani setup` extracts the bundle before installing the toolchain
  # `rust-toolchain-version` names and linking it at `toolchain`.
  if [ -x "$root/bin/cargo-kani" ] && [ -f "$root/home/complete" ] && [ -x "$root/home/kani-$KANI/toolchain/bin/cargo" ]; then
    return
  fi
  rm -rf "$root/home"
  "${STABLE_CARGO[@]}" install --locked --root "$root" kani-verifier --version "$KANI"
  KANI_HOME="$root/home" "$root/bin/cargo-kani" setup
  touch "$root/home/complete"
}

# Prints the seconds of a positive deadline written as N, Ns, Nm or Nh, N in base 10 of at most 6 digits.
seconds_of() {
  local seconds
  [[ $1 =~ ^([0-9]{1,6})([smh]?)$ ]] || return 1
  seconds=$((10#${BASH_REMATCH[1]}))
  case ${BASH_REMATCH[2]} in
    h) seconds=$((seconds * 3600)) ;;
    m) seconds=$((seconds * 60)) ;;
  esac
  [ "$seconds" -gt 0 ] || return 1
  echo "$seconds"
}

# Clears the ambient compiler configuration, sets its caller's `root` and `jobs`, the latter from the default worker
# count in its argument, provisions Kani and exports the environment of a Kani run.
kani_setup() {
  local survived
  root="$HOME/.cache/kestrike-kani/$KANI"
  # Cargo replaces or wraps rustc, retargets and reflags a build from these
  # variables and from every config file it discovers under CARGO_HOME and the
  # ancestors of its working directory. Configuration discovered from
  # `crates/kestrike` includes configuration inherited from the repository
  # root, where the run starts. The `cargo install` that builds `cargo-kani`
  # reads the same variables, so they are cleared ahead of provisioning.
  # Cargo also reads target-scoped overrides (`CARGO_TARGET_<TRIPLE>_RUSTFLAGS`,
  # `_LINKER`, `_RUNNER`) and subcommand aliases (`CARGO_ALIAS_KANI`) from the
  # environment.
  unset RUSTC RUSTC_WRAPPER RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER \
    CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_TARGET RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS \
    RUSTUP_TOOLCHAIN "${!CARGO_TARGET_@}" "${!CARGO_PROFILE_@}" "${!CARGO_ALIAS_@}"
  survived=$(env | { grep -E '^(RUSTC(_WORKSPACE_WRAPPER|_WRAPPER)?=|RUSTFLAGS=|CARGO_ENCODED_RUSTFLAGS=|CARGO_BUILD_(RUSTC|RUSTFLAGS|TARGET)|CARGO_TARGET_|CARGO_PROFILE_|CARGO_ALIAS_)' || true; } \
    | cut -d= -f1 | sort | tr '\n' ' ')
  [ -z "$survived" ] || fail "ambient compiler, flag, target or profile overrides survived clearing: $survived"
  # The runner's per-job bound is CARGO_BUILD_JOBS. The run defaults to the
  # caller's worker count, two for the pr profile and a comparison and three
  # for the scheduled profile, or to the bound where it is lower; KANI_JOBS
  # sets another count within the bound.
  # kani-driver holds each harness's parsed CBMC output, about half of the
  # run's memory, and holds more of it at once with every worker: under the
  # heavy runner's four-CPU quota and 12 GiB memory maximum the pr profile at
  # four workers is killed for memory with the allocator's default arenas.
  jobs="${KANI_JOBS:-$1}"
  [ -n "${KANI_JOBS:-}" ] || [ -z "${CARGO_BUILD_JOBS:-}" ] || [ "$jobs" -le "$CARGO_BUILD_JOBS" ] || jobs=$CARGO_BUILD_JOBS
  [ "$jobs" -ge 2 ] || fail "the Kani run would use -j $jobs; the Kani judge credits only a run of 2 or more workers"
  [ -z "${CARGO_BUILD_JOBS:-}" ] || [ "$jobs" -le "$CARGO_BUILD_JOBS" ] \
    || fail "KANI_JOBS=$jobs exceeds the per-job worker bound CARGO_BUILD_JOBS=$CARGO_BUILD_JOBS"
  step provision deadline 40m bash scripts/rust-lane.sh kani-toolchain
  export KANI_HOME="$root/home" PATH="$root/bin:$PATH" KANI_TARGET="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/kani-target"
  # Two malloc arenas keep kani-driver's resident set about 1 GiB lower at
  # three workers.
  export MALLOC_ARENA_MAX=2
}

kani() {
  local profile=$1 root batches names name code argv jobs cbmc total
  local index count stem remaining begun listed=1
  # A run first removes every batch file of either form, the run record and the judgment, credit and failure of an
  # earlier run, so nothing of an earlier run with other batches stays beside this one.
  rm -f "$EVIDENCE"/kani.{argv,txt,exit} "$EVIDENCE"/kani-*.{argv,txt,exit} "$EVIDENCE"/kani-run.json{,.tmp} \
    "$EVIDENCE/kani-list.json" "$EVIDENCE/report.json" "$EVIDENCE/receipt.json" "$EVIDENCE/credit.json" \
    "$EVIDENCE/exit.txt" "$EVIDENCE/failure.txt" "$EVIDENCE/cargo-config.json" "$EVIDENCE/Cargo.lock"
  if [ "$profile" = pr ]; then kani_setup 2; else kani_setup 3; fi
  # Measured with the declaration's CBMC arguments on an aarch64 host. The pr
  # profile's 42 harnesses at this lane's two workers and two arenas: 779
  # CPU-seconds and 527 seconds with the build with no memory bound; 488 to
  # 501 seconds and a peak of 8.7 to 9.9 GiB over four runs under the heavy
  # runner's four-CPU quota, 11 GiB memory-high threshold and 12 GiB maximum.
  # In the two batches of the declared cut under those limits: 539 to 553
  # seconds and a peak of 7.8 to 9.4 GiB over three runs.
  # With the pending-count control's 43 harnesses in two batches under those
  # limits, three runs alone: 530 seconds and a peak of 7.2 GiB in each of two
  # with the build cached, 610 seconds and 9.9 GiB in one that built the crate.
  # The scheduled profile's 222 harnesses at three workers under the quota
  # with a 40 GiB maximum: 32,267 CPU-seconds, 184 minutes with the build and
  # a peak of 14.6 GiB. In the declared weighted batches at three workers
  # under the runner's limits, alone on a 16-vCPU Graviton4 share on
  # 2026-11-24, the scheduled profile took 280 minutes with the build and
  # 32,736 CPU-seconds and peaked at 10.51 GiB with no memory-high event.
  # The 210 minutes below are shorter than that run, so a scheduled run
  # that reaches them is judged a timeout and credits no record.
  if [ "$profile" = pr ]; then
    export KANI_TOTAL="${KANI_TOTAL:-30m}"
  else
    export KANI_TOTAL="${KANI_TOTAL:-210m}"
  fi
  total=$(seconds_of "$KANI_TOTAL") || fail "KANI_TOTAL=$KANI_TOTAL is no positive deadline of N, Ns, Nm or Nh"
  step identity python3 scripts/judge-kani.py identity --kani-home "$KANI_HOME" --cargo-kani "$root/bin/cargo-kani" \
    --evidence "$EVIDENCE"
  # One line a batch, its harnesses separated by spaces: the profile's sorted harnesses cut in order by the
  # declared weights within the profile's `batch_budget`.
  mapfile -t batches < <(python3 scripts/judge-kani.py batches --profile "$profile")
  [ -n "${batches[0]:-}" ] || fail "the $profile profile names no Kani harness"
  (cd crates/kestrike && cargo "+$NIGHTLY" -Zunstable-options config get --format json) > "$EVIDENCE/cargo-config.json"
  # `cargo kani list` builds the package under Kani and writes kani-list.json in its directory.
  step list deadline 20m env -C crates/kestrike CARGO_TARGET_DIR="$KANI_TARGET" cargo kani list --format json
  mv crates/kestrike/kani-list.json "$EVIDENCE/kani-list.json"
  # A listing whose harnesses differ from the declaration credits no batch, so the run goes to the judgment, which
  # refuses it by name.
  python3 scripts/judge-kani.py inventory --evidence "$EVIDENCE" > "$EVIDENCE/inventory.txt" 2>&1 || listed=0
  # The declaration's CBMC arguments close each command: Kani passes everything
  # after --cbmc-args through, so no Kani option may follow them.
  mapfile -t cbmc < <(python3 scripts/judge-kani.py arguments)
  [ "${#cbmc[@]}" -gt 0 ] || fail "the Kani declaration names no CBMC arguments"
  # Each batch is one `cargo kani` process, so kani-driver releases the parsed
  # CBMC output of a batch's harnesses when the batch exits. The batches run in
  # order in one target directory, which the listing built; each recompiles
  # kestrike with its harness list, reusing the dependencies, about 20
  # seconds on an aarch64 host. They share one total on the run record's
  # monotonic clock: each gets the whole seconds that remain. A batch that fails
  # is judged with the rest, so the run goes on to the next; the total running
  # out, or an interrupt, stops it. The judge reads each batch's argv, so the
  # record and the run share one array, and reads kani-run.json, which records
  # each batch as its child exits.
  count=${#batches[@]}
  [ "$listed" -eq 1 ] || count=0
  python3 scripts/judge-kani.py record begin --profile "$profile" --evidence "$EVIDENCE" --workers "$jobs" \
    --cap "${CARGO_BUILD_JOBS:-}" --total "$total"
  for ((index = 0; index < count; index++)); do
    stem=kani
    [ "$count" -eq 1 ] || stem=kani-$((index + 1))
    read -r remaining begun < <(python3 scripts/judge-kani.py record remaining --evidence "$EVIDENCE")
    if [ "$remaining" -le 0 ]; then
      python3 scripts/judge-kani.py record timeout --evidence "$EVIDENCE" --index $((index + 1))
      break
    fi
    read -ra names <<< "${batches[index]}"
    argv=(cargo kani -p kestrike --exact)
    for name in "${names[@]}"; do
      argv+=(--harness "$name")
    done
    argv+=(-j "$jobs" --output-format terse --target-dir "$KANI_TARGET" -Z unstable-options --cbmc-args "${cbmc[@]}")
    printf '%s\n' "${argv[@]}" > "$EVIDENCE/$stem.argv"
    code=0
    deadline --drain "$remaining" "${argv[@]}" > "$EVIDENCE/$stem.txt" 2>&1 || code=$?
    printf '%s\n' "$code" > "$EVIDENCE/$stem.exit"
    python3 scripts/judge-kani.py record batch --evidence "$EVIDENCE" --index $((index + 1)) --start "$begun"
    if [ "$code" -eq 124 ]; then
      python3 scripts/judge-kani.py record timeout --evidence "$EVIDENCE" --index $((index + 1))
      break
    fi
    [ "$code" -ne 130 ] && [ "$code" -ne 143 ] || break
  done
  python3 scripts/judge-kani.py record complete --evidence "$EVIDENCE"
  # The workspace lock file is ignored, so the build resolves the dependency
  # graph it proves against; the receipt binds that resolution.
  cp Cargo.lock "$EVIDENCE/Cargo.lock"
  code=0
  python3 scripts/judge-kani.py judge --profile "$profile" --evidence "$EVIDENCE" > /dev/null || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the Kani judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

# Runs the named harnesses once without the declaration's CBMC arguments and once under them, each with every check
# exported, records both commands and exit codes, and has the judge compare the two runs. The judge reads
# compare-without.argv and compare-with.argv, so each record and its run share one array. A harness joins the
# declaration's `compared` list after this lane passes for it.
kani_compare() {
  local root jobs cbmc arm argv code name
  [ "$#" -gt 0 ] || fail "usage: rust-lane.sh kani-compare HARNESS..."
  kani_setup 2
  export KANI_TOTAL="${KANI_TOTAL:-30m}"
  mapfile -t cbmc < <(python3 scripts/judge-kani.py arguments)
  [ "${#cbmc[@]}" -gt 0 ] || fail "the Kani declaration names no CBMC arguments"
  rm -f "$EVIDENCE"/compare-* "$EVIDENCE/compare.json"
  for arm in without with; do
    argv=(cargo kani -p kestrike --exact)
    for name in "$@"; do
      argv+=(--harness "$name")
    done
    argv+=(-j "$jobs" --output-format terse --target-dir "$KANI_TARGET" -Z unstable-options --export-json "$EVIDENCE/compare-$arm.json")
    [ "$arm" = without ] || argv+=(--cbmc-args "${cbmc[@]}")
    printf '%s\n' "${argv[@]}" > "$EVIDENCE/compare-$arm.argv"
    code=0
    deadline "$KANI_TOTAL" "${argv[@]}" > "$EVIDENCE/compare-$arm.txt" 2>&1 || code=$?
    printf '%s\n' "$code" > "$EVIDENCE/compare-$arm.exit"
  done
  code=0
  python3 scripts/judge-kani.py compare --evidence "$EVIDENCE" > "$EVIDENCE/compare.json" 2> "$EVIDENCE/compare.txt" || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the comparison refused: $(tail -n 1 "$EVIDENCE/compare.txt") $(head -c 2000 "$EVIDENCE/compare.json")"
}

# The patched checker is built once per nightly, recipe and patch set (each
# patch's name and digest, since the identity records patches by name) under
# the runner's cache, then checked against its identity before each run.
# GenMC runs `cargo clean` and `cargo build` in the package it is given and
# links every bitcode file under its target/*/deps, so each case runs in its
# own copy beside the package: kernels/ holds no build state and the manifest
# path names the case. Case arguments after the profile run only those
# cases of the profile, refuse a case outside it, and return 0 before the
# judgment, leaving the report, the receipt and credit to a full-profile
# run; each case's raw output stays in the evidence for a caller that judges
# each case itself. A case-list run removes the report, receipt, credit and
# exit record of a full-profile run from its evidence directory, since it
# replaces the case outputs that judgment read.
genmc() {
  local profile=$1 key prefix std toolchain case code options cases root=$PWD package=verification/genmc/packages argv survived listed member
  shift
  key=$({ printf '%s\n' "$NIGHTLY"; sha256sum verification/genmc/provision.sh verification/genmc/patches/*.patch; } \
    | sha256sum | cut -c1-16)
  prefix="$HOME/.cache/kestrike-genmc/$key"
  [ -f "$prefix/identity.json" ] || step provision deadline 40m bash verification/genmc/provision.sh "$prefix"
  step identity python3 scripts/judge-genmc.py identity --toolchain "$prefix" --evidence "$EVIDENCE"
  std=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["genmc_std"]["path"])' "$EVIDENCE/identity.json")
  toolchain=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["rustc"]["toolchain"])' "$EVIDENCE/identity.json")
  ln -sfn "$std" "$package/genmc-std"
  mapfile -t options < <(python3 scripts/judge-genmc.py options)
  mapfile -t cases < <(python3 scripts/judge-genmc.py cases --profile "$profile")
  [ "${#cases[@]}" -gt 0 ] || fail "the $profile profile names no GenMC case"
  for case in "$@"; do
    member=0
    for listed in "${cases[@]}"; do
      [ "$case" != "$listed" ] || member=1
    done
    [ "$member" -eq 1 ] || fail "$case is no GenMC case of the $profile profile"
  done
  for case in "$@"; do
    member=0
    for listed in "$@"; do
      [ "$case" != "$listed" ] || member=$((member + 1))
    done
    [ "$member" -eq 1 ] || fail "$case is named more than once"
  done
  [ "$#" -eq 0 ] || cases=("$@")
  # Cargo replaces or wraps rustc, retargets and reflags a build from these
  # variables and from every config file it discovers under CARGO_HOME and
  # the ancestors of its working directory. RUSTC names the identified
  # toolchain's compiler and the empty wrappers disable a configured one,
  # both ahead of any config file; GenMC's own `cargo build` inherits them.
  # The merged file configuration is recorded for the judge, which refuses
  # entries that shape the build.
  unset CARGO_BUILD_RUSTC CARGO_BUILD_RUSTC_WRAPPER CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER CARGO_BUILD_TARGET CARGO_BUILD_TARGET_DIR \
    CARGO_BUILD_BUILD_DIR RUSTFLAGS CARGO_ENCODED_RUSTFLAGS CARGO_BUILD_RUSTFLAGS "${!CARGO_TARGET_@}" "${!CARGO_PROFILE_@}"
  export RUSTUP_TOOLCHAIN=$NIGHTLY RUSTC="$toolchain/bin/rustc" RUSTC_WRAPPER='' RUSTC_WORKSPACE_WRAPPER=''
  survived=$(env | { grep -E '^(RUSTC(_WORKSPACE_WRAPPER|_WRAPPER)?=|RUSTFLAGS=|CARGO_ENCODED_RUSTFLAGS=|CARGO_BUILD_(RUSTC|RUSTFLAGS|TARGET|BUILD_DIR)|CARGO_TARGET_|CARGO_PROFILE_)' || true; } \
    | { grep -vxF -e "RUSTC=$RUSTC" -e RUSTC_WRAPPER= -e RUSTC_WORKSPACE_WRAPPER= || true; } | cut -d= -f1 | sort | tr '\n' ' ')
  [ -z "$survived" ] || fail "ambient compiler, flag, target or profile overrides survived clearing: $survived"
  (cd "$package/kernels" && cargo -Zunstable-options config get --format json) > "$EVIDENCE/cargo-config.json"
  step config python3 scripts/judge-genmc.py config --evidence "$EVIDENCE"
  # Every case output goes, a wider profile's included, so the judge sees
  # this profile's runs alone.
  rm -f "$EVIDENCE"/genmc-*
  [ "$#" -eq 0 ] || rm -f "$EVIDENCE/report.json" "$EVIDENCE/receipt.json" "$EVIDENCE/credit.json" "$EVIDENCE/exit.txt"
  for case in "${cases[@]}"; do
    rm -rf "$package/run-$case"
    mkdir -p "$package/run-$case"
    cp -r "$package/kernels/Cargo.toml" "$package/kernels/Cargo.lock" "$package/kernels/build.rs" \
      "$package/kernels/src" "$package/kernels/ops" "$package/run-$case/"
    CASE=$case step "check-$case" deadline 5m cargo check --locked --manifest-path "$package/run-$case/Cargo.toml"
    argv=("$prefix/build/bin/genmc" "${options[@]}" "--dump-error-graph=$EVIDENCE/genmc-$case.dot"
      "$root/$package/run-$case/Cargo.toml")
    printf '%s\n' "${argv[@]}" > "$EVIDENCE/genmc-$case.argv"
    printf 'CASE=%s\nRUSTUP_TOOLCHAIN=%s\nRUSTC=%s\nRUSTC_WRAPPER=\nRUSTC_WORKSPACE_WRAPPER=\n' "$case" "$RUSTUP_TOOLCHAIN" "$RUSTC" \
      > "$EVIDENCE/genmc-$case.env"
    code=0
    CASE=$case deadline 15m "${argv[@]}" > "$EVIDENCE/genmc-$case.txt" 2>&1 || code=$?
    printf '%s\n' "$code" > "$EVIDENCE/genmc-$case.exit"
    find "$package/run-$case/target" -name '*.bc' -exec llvm-dis-22 {} -o - \; 2> /dev/null \
      | grep -oE '@llvm\.(uadd|usub)\.sat\.i64\(|@llvm\.[us](min|max)\.i64\(' | tr -d '@(' | sort -u \
      > "$EVIDENCE/genmc-$case.intrinsics" || true
  done
  [ "$#" -eq 0 ] || return 0
  code=0
  python3 scripts/judge-genmc.py judge --profile "$profile" --evidence "$EVIDENCE" > /dev/null || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the GenMC judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

# The cache entry appears only when the digest-checked, fully extracted staging directory is renamed into place,
# so the next run retries installation after an interrupted fetch or extraction.
verus_install() {
  local prefix=$1 url=$2 digest=$3 staging=$1.partial
  rm -rf "$prefix" "$staging"
  mkdir -p "$staging"
  step fetch deadline 10m curl -fsSL -o "$staging/verus.zip" "$url"
  [ "$(sha256sum "$staging/verus.zip" | cut -d' ' -f1)" = "$digest" ] \
    || fail "the Verus archive digest differs from the declared $digest"
  step unpack unzip -q "$staging/verus.zip" -d "$staging"
  rm "$staging/verus.zip"
  mv "$staging" "$prefix"
}

verus() {
  local url digest toolchain version prefix bin code=0 verdict=0 argv library refusal
  refusal=$(python3 scripts/judge-verus.py command 2>&1 > "$EVIDENCE/verus.argv") \
    || fail "the Verus command declaration was refused${refusal:+: ${refusal##*$'\n'}}"
  mapfile -t argv < "$EVIDENCE/verus.argv"
  [ -n "${argv[0]:-}" ] || fail 'the Verus command declaration has no executable'
  read -r url digest toolchain version < <(python3 -c 'import json, sys
v = json.load(open(sys.argv[1]))["verus"]
print(v["archive"]["url"], v["archive"]["sha256"], v["toolchain"], v["version"])' verification/verus/expected.json)
  prefix=$HOME/.cache/kestrike-verus/$version
  bin=$prefix/verus-x86-linux
  [ -d "$prefix" ] || verus_install "$prefix" "$url" "$digest"
  step toolchain rustup toolchain install "$toolchain" --profile minimal
  export PATH="$bin:$PATH" VERUS_Z3_PATH="$bin/z3"
  if ! python3 scripts/judge-verus.py identity --verus "$bin/verus" --evidence "$EVIDENCE" > "$EVIDENCE/identity.txt" 2>&1; then
    verus_install "$prefix" "$url" "$digest"
    step identity python3 scripts/judge-verus.py identity --verus "$bin/verus" --evidence "$EVIDENCE"
  fi
  rm -rf verification/verus/target
  mkdir -p verification/verus/target/verus
  deadline 20m env -C verification/verus "${argv[@]}" > "$EVIDENCE/verus.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/verus.exit"
  cat verification/verus/target/verus/kestrike_verus.d > "$EVIDENCE/verus.d" 2>/dev/null || true
  target_dir
  step check deadline 15m "${STABLE_CARGO[@]}" check -p kestrike --lib --message-format=json-render-diagnostics
  # The check's artifact message identifies its library dep-info even when the check reuses existing output and the
  # shared target directory holds other kestrike units.
  library=$(python3 -c 'import json, sys
from pathlib import Path
found = []
for line in open(sys.argv[1], encoding="utf-8", errors="replace"):
    try:
        message = json.loads(line) if line.startswith("{") else {}
    except ValueError:
        continue
    target = message.get("target") or {}
    if message.get("reason") == "compiler-artifact" and target.get("name") == "kestrike" \
            and "lib" in target.get("kind", []) and not message["profile"]["test"]:
        found += [name for name in message["filenames"] if name.endswith(".rmeta")]
if len(found) != 1:
    sys.exit(f"cargo check reported {len(found)} kestrike library artifacts")
path = Path(found[0])
print(path.with_name(path.name[len("lib"):-len(".rmeta")] + ".d"))' "$EVIDENCE/check.txt")
  cat "$library" > "$EVIDENCE/cargo.d"
  step tree "${STABLE_CARGO[@]}" tree -p kestrike -e normal,build --prefix none --target all
  python3 scripts/judge-verus.py judge --evidence "$EVIDENCE" > /dev/null || verdict=$?
  printf '%s\n' "$verdict" > "$EVIDENCE/exit.txt"
  [ "$verdict" -eq 0 ] || fail "the Verus judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

# The JDK and the TLA+ tools jar are fetched once per declared digest into the runner's cache; the cache entry appears
# only when the digest-checked, fully extracted staging directory is renamed into place.
tlc_install() {
  local prefix=$1 staging=$1.partial java jar
  [ -n "${GH_TOKEN:-}" ] \
    || fail "GH_TOKEN must grant read access to the TLA+ tools release asset; locally, export GH_TOKEN=\$(gh auth token)"
  read -r java jar < <(python3 -c 'import json, sys; d = json.load(open(sys.argv[1]))
print(d["java"]["url"], d["jar"]["url"])' verification/tlc/expected.json)
  rm -rf "$prefix" "$staging"
  mkdir -p "$staging/jdk"
  step fetch deadline 10m curl -fsSL -o "$staging/jdk.tar.gz" "$java"
  step fetch tlc_fetch_jar "$staging" "$jar"
  python3 -c 'import json, sys; d = json.load(open(sys.argv[1]))
print(d["java"]["sha256"], "jdk.tar.gz"); print(d["jar"]["sha256"], "tla2tools.jar")' verification/tlc/expected.json \
    | (cd "$staging" && sha256sum --check --strict --quiet) || fail "a TLC tool archive differs from its declared digest"
  step unpack tar -xzf "$staging/jdk.tar.gz" -C "$staging/jdk" --strip-components=1
  rm "$staging/jdk.tar.gz"
  mv "$staging" "$prefix"
}

# curl reads the authorization header from a mode-0600 file to keep GH_TOKEN out of its argument list.
tlc_fetch_jar() {
  local staging=$1 url=$2 auth=$1/jar.auth code=0
  (umask 077 && printf 'Authorization: Bearer %s\n' "$GH_TOKEN" > "$auth")
  deadline 5m curl -fsSL -H "@$auth" -H "Accept: application/octet-stream" -o "$staging/tla2tools.jar" "$url" \
    || code=$?
  rm -f "$auth"
  return "$code"
}

tlc_prefix() {
  python3 -c 'import json, sys; d = json.load(open(sys.argv[1]))
print(d["java"]["sha256"][:16] + "-" + d["jar"]["sha256"][:16])' verification/tlc/expected.json | sed "s|^|$HOME/.cache/kestrike-tlc/|"
}

tlc_tools() {
  local prefix
  prefix=$(tlc_prefix)
  [ -f "$prefix/tla2tools.jar" ] || tlc_install "$prefix"
}

tlc() {
  local profile=$1 prefix workers code=0 verdict=0 argv
  prefix=$(tlc_prefix)
  step tlctools tlc_tools
  workers=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["workers"])' verification/tlc/expected.json)
  export PATH="$prefix/jdk/bin:$PATH"
  step identity python3 scripts/judge-tlc.py identity --java "$prefix/jdk/bin/java" --jar "$prefix/tla2tools.jar" \
    --evidence "$EVIDENCE"
  rm -rf "$EVIDENCE/tlc" "$EVIDENCE/results.json"
  argv=(python3 tla/check.py --jar "$prefix/tla2tools.jar" --workers "$workers" --tier "$profile"
    --output "$EVIDENCE/tlc")
  printf '%s\n' "${argv[@]}" > "$EVIDENCE/tlc.argv"
  # The run's limit is what the tool check and identity left of 105 minutes
  # since the lane started, so a cold tool install shortens the run and the
  # 110-minute workflow step keeps its last five minutes for the 30-second
  # shutdown grace period and the judgment.
  deadline "$((105 * 60 - SECONDS))s" "${argv[@]}" > "$EVIDENCE/tlc.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/tlc.exit"
  cp "$EVIDENCE/tlc/results.json" "$EVIDENCE/results.json" 2>/dev/null || true
  python3 scripts/judge-tlc.py judge --profile "$profile" --evidence "$EVIDENCE" > /dev/null || verdict=$?
  printf '%s\n' "$verdict" > "$EVIDENCE/exit.txt"
  [ "$verdict" -eq 0 ] || fail "the TLC judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

# The JDK, Node.js, Apalache and Quint archives are fetched once per declared digest into the runner's cache, and the cache
# entry appears only when every digest-checked archive is installed and the staging directory is renamed into place.
# `verification/quint/package-lock.json` pins each dependency's version and integrity, so `npm ci` installs the same tree
# after later registry releases, and the staged Node.js and `node_modules` trees must match their declared digests before
# the entry is published.
quint_install() {
  local prefix=$1 staging=$1.partial apalache name sha url
  apalache=$(quint_apalache)
  rm -rf "$prefix" "$staging"
  mkdir -p "$staging/jdk" "$staging/node" "$staging/home/$apalache" "$staging/npm"
  while read -r name sha url; do
    step fetch deadline 10m curl -fsSL -o "$staging/$name" "$url"
    printf '%s  %s\n' "$sha" "$name" >> "$staging/archives.sha256"
  done < <(python3 -c 'import json, sys; d = json.load(open(sys.argv[1]))
for tool, name in (("java", "jdk.tar.gz"), ("node", "node.tar.xz"), ("apalache", "apalache.tgz"), ("quint", "quint.tgz")):
    print(name, d[tool]["sha256"], d[tool]["url"])' verification/quint/expected.json)
  (cd "$staging" && sha256sum --check --strict --quiet archives.sha256) || fail "a Quint tool archive differs from its declared digest"
  step unpack tar -xzf "$staging/jdk.tar.gz" -C "$staging/jdk" --strip-components=1
  step unpack tar -xJf "$staging/node.tar.xz" -C "$staging/node" --strip-components=1
  step unpack tar -xzf "$staging/apalache.tgz" -C "$staging/home/$apalache"
  # The lockfile resolves Quint as `file:quint.tgz` beside it.
  cp verification/quint/package.json verification/quint/package-lock.json "$staging/npm/"
  mv "$staging/quint.tgz" "$staging/npm/quint.tgz"
  step npm deadline 10m "$staging/node/bin/node" "$staging/node/bin/npm" ci --prefix "$staging/npm" \
    --no-audit --no-fund --ignore-scripts
  # The declared digest covers the installed packages alone, without npm's hidden lockfile.
  rm "$staging/npm/node_modules/.package-lock.json" "$staging/npm/quint.tgz"
  rm "$staging/jdk.tar.gz" "$staging/node.tar.xz" "$staging/apalache.tgz" "$staging/archives.sha256"
  step trees python3 scripts/judge-quint.py trees --node "$staging/node" --modules "$staging/npm/node_modules"
  mv "$staging" "$prefix"
}

# Quint looks for Apalache under `QUINT_HOME/apalache-dist-VERSION`.
quint_apalache() {
  python3 -c 'import json, sys; print("apalache-dist-" + json.load(open(sys.argv[1]))["apalache"]["version"])' \
    verification/quint/expected.json
}

# The prefix names every archive digest and the declared `node_modules` digest, so a changed archive or Quint tree pin
# installs afresh.
quint_prefix() {
  python3 -c 'import json, sys; d = json.load(open(sys.argv[1]))
print("-".join([d[tool]["sha256"][:12] for tool in ("java", "node", "apalache", "quint")] + [d["quint"]["install"][:12]]))' \
    verification/quint/expected.json | sed "s|^|$HOME/.cache/kestrike-quint/|"
}

quint_tools() {
  local prefix
  prefix=$(quint_prefix)
  [ -x "$prefix/npm/node_modules/.bin/quint" ] || quint_install "$prefix"
}

# The Quint models' cases under the pinned tools, judged by scripts/judge-quint.py.
quint() {
  local prefix workers code=0 verdict=0 shard=$1 names name
  local -a argv identity=()
  if [ -n "$shard" ]; then
    names=$(python3 scripts/judge-quint.py shard --shard "$shard") || fail "could not select Quint shard $shard"
    [ -n "$names" ] || fail "Quint shard $shard selected no cases"
    identity=(--shard "$shard")
  fi
  prefix=$(quint_prefix)
  step quinttools quint_tools
  if [ -n "$shard" ]; then
    prefix=$(cd "$prefix" && pwd -P)
    EVIDENCE=$(cd "$EVIDENCE" && pwd -P)
  fi
  workers=$(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["workers"])' verification/quint/expected.json)
  export PATH="$prefix/jdk/bin:$prefix/node/bin:$PATH" QUINT_HOME="$prefix/home"
  # The Connect replay case builds the library tests under the workspace profile and the pinned stable.
  export RUSTUP_TOOLCHAIN="$STABLE" CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only
  target_dir
  step identity python3 scripts/judge-quint.py identity --java "$prefix/jdk/bin/java" --node "$prefix/node/bin/node" \
    --apalache "$prefix/home/$(quint_apalache)" \
    --quint "$prefix/npm/node_modules/.bin/quint" --evidence "$EVIDENCE" "${identity[@]}"
  rm -rf "$EVIDENCE/quint" "$EVIDENCE/results.json"
  argv=(python3 quint/check.py --quint "$prefix/npm/node_modules/.bin/quint" --workers "$workers"
    --output "$EVIDENCE/quint")
  if [ -n "$shard" ]; then
    while IFS= read -r name; do argv+=(--case "$name"); done <<< "$names"
  fi
  printf '%s\n' "${argv[@]}" > "$EVIDENCE/quint.argv"
  deadline 360m "${argv[@]}" > "$EVIDENCE/quint.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/quint.exit"
  cp "$EVIDENCE/quint/results.json" "$EVIDENCE/results.json" 2>/dev/null || true
  if [ -n "$shard" ]; then
    [ "$code" -eq 0 ] || fail "Quint shard $shard's runner exited $code"
    return
  fi
  python3 scripts/judge-quint.py judge --evidence "$EVIDENCE" > /dev/null || verdict=$?
  printf '%s\n' "$verdict" > "$EVIDENCE/exit.txt"
  [ "$verdict" -eq 0 ] || fail "the Quint judgment refused: $(python3 -c 'import json, sys; print(json.load(open(sys.argv[1]))["reason"])' "$EVIDENCE/report.json")"
}

# The fuzz lane $1, `fuzz` or `fuzz-smoke`: the frame target, then the worker's
# campaign and parser targets, each for the seconds its inventory row declares.
fuzz() {
  local dir=crates/kestrike/fuzz seeds runs code
  read -r FRAME_SECONDS CAMPAIGN_SECONDS RECORD_SECONDS WIRE_SECONDS < <(python3 -c 'import json, sys
seconds = {row["target"]: row["seconds"] for row in json.load(open("scripts/test-inventory.json"))["qualified"][sys.argv[1]]["rows"]}
print(*(seconds[target] for target in ("frame", "campaign", "record", "wire")))' "$1")
  toolchain_pins
  printf '%s\n' "${TOOLCHAIN_PINS[@]}" > "$EVIDENCE/pins.txt"
  target_dir fuzz
  mkdir -p "$EVIDENCE/seeds" "$EVIDENCE/artifacts"
  git -C "$dir" ls-files -z corpus/frame | (cd "$dir" && xargs -0 -I{} cp {} "$EVIDENCE/seeds/")
  seeds=$(git -C "$dir" ls-files corpus/frame | wc -l)
  printf '{"seeds": %s}\n' "$seeds" > "$EVIDENCE/fuzz.json"
  code=0
  deadline 20m cargo "+$NIGHTLY" fuzz run --fuzz-dir "$dir" --sanitizer address frame \
    "$EVIDENCE/seeds" -- -max_total_time="$FRAME_SECONDS" -dict="$PWD/$dir/frame.dict" \
    -artifact_prefix="$EVIDENCE/artifacts/" > "$EVIDENCE/run.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the fuzz run exited $code; crash inputs are in artifacts/"
  grep -q "seed corpus: files: $seeds " "$EVIDENCE/run.txt" \
    || fail "the run loaded other than the $seeds tracked seeds"
  runs=$(sed -n 's/^Done \([0-9]*\) runs in \([0-9]*\) second.*/\1 \2/p' "$EVIDENCE/run.txt")
  # libFuzzer runs one empty input beside the seeds before it mutates.
  [ "${runs%% *}" -gt "$((seeds + 1))" ] 2>/dev/null || fail "the run executed no input past its $seeds seeds"
  printf '{"seeds": %s, "runs": %s, "seconds": %s}\n' "$seeds" "${runs%% *}" "${runs##* }" \
    > "$EVIDENCE/fuzz.json"
  campaign_fuzz
}

# The worker's fuzz targets run in the simulation worker itself, built on
# the pinned nightly with AddressSanitizer and libFuzzer's coverage. The
# build proof comes first: it must instrument and link with the native pins
# before any input runs. Each target's seeds then each pass once. The
# planted target, run over the upload seed, is the wrong-byte control and
# must report its audit before it aborts nonzero. A timed run per target
# loads its seeds, must run past them and fail no input; a failure leaves
# its input, claim and any bundle in TARGET-artifacts/.
campaign_fuzz() {
  local exe code
  local flags="-Zsanitizer=address -Cpasses=sancov-module -Cllvm-args=-sanitizer-coverage-level=4"
  flags+=" -Cllvm-args=-sanitizer-coverage-inline-8bit-counters -Cllvm-args=-sanitizer-coverage-pc-table"
  flags+=" -Cllvm-args=-sanitizer-coverage-trace-compares -Cdebug-assertions"
  rm -rf "$EVIDENCE/campaign-control"
  mkdir -p "$EVIDENCE/campaign-control"
  code=0
  deadline 30m env -u CARGO_ENCODED_RUSTFLAGS RUSTFLAGS="$flags" cargo "+$NIGHTLY" test --release -p kestrike \
    --test sim_worker --no-run --target x86_64-unknown-linux-gnu --message-format=json \
    > "$EVIDENCE/campaign-build.json" 2> "$EVIDENCE/campaign-build.txt" || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the instrumented worker build exited $code"
  exe=$(python3 -c 'import json, sys
for line in open(sys.argv[1]):
    message = json.loads(line) if line.startswith("{") else {}
    if message.get("target", {}).get("name") == "sim_worker" and message.get("executable"):
        print(message["executable"])' "$EVIDENCE/campaign-build.json" | tail -n 1)
  [ -x "$exe" ] || fail "the instrumented build named no sim_worker executable"
  nm "$exe" > "$EVIDENCE/campaign-nm.txt" || fail "nm could not read the instrumented worker"
  grep -q ' __asan_init$' "$EVIDENCE/campaign-nm.txt" || fail "the worker links no AddressSanitizer runtime"
  grep -q ' LLVMFuzzerRunDriver$' "$EVIDENCE/campaign-nm.txt" || fail "the worker links no libFuzzer driver"
  target_seeds campaign "$exe"
  code=0
  deadline 10m "$exe" --fuzz planted --artifacts "$EVIDENCE/campaign-control" -- \
    "$EVIDENCE/campaign-seeds/upload.input" > "$EVIDENCE/campaign-control.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  python3 - "$EVIDENCE/campaign-control.txt" "$code" <<'EOF' || fail "the wrong-byte control did not audit before it aborted nonzero"
import sys
text, code = open(sys.argv[1], errors="replace").read(), int(sys.argv[2])
audit, crash = text.find("fuzz: audited and tore down planted: planted: complete violation"), text.find("deadly signal")
sys.exit(0 if code != 0 and 0 <= audit < crash else 1)
EOF
  target_run campaign "$exe" "$CAMPAIGN_SECONDS" 65536
  target_seeds record "$exe"
  # A record input is a format byte, a mode byte and at most 64 four-byte
  # ops; a wire input is a format byte and as many ops.
  target_run record "$exe" "$RECORD_SECONDS" 258
  target_seeds wire "$exe"
  target_run wire "$exe" "$WIRE_SECONDS" 257
}

# Writes TARGET's seeds and runs each once: every execution must pass and
# there must be one per seed. Inputs named as files run once each, and
# libFuzzer may run one of them again, hence at least one per seed.
target_seeds() {
  local target=$1 exe=$2 seeds code counts
  rm -rf "$EVIDENCE/$target-seeds" "$EVIDENCE/$target-artifacts"
  mkdir -p "$EVIDENCE/$target-seeds" "$EVIDENCE/$target-artifacts"
  code=0
  deadline 2m "$exe" --seeds "$target" "$EVIDENCE/$target-seeds" || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the worker wrote no $target seeds"
  seeds=$(find "$EVIDENCE/$target-seeds" -type f | wc -l)
  code=0
  deadline 5m "$exe" --fuzz "$target" --artifacts "$EVIDENCE/$target-artifacts" -- \
    "$EVIDENCE/$target-seeds"/* > "$EVIDENCE/$target-seeded.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  counts=$({ grep "^fuzz: $target " "$EVIDENCE/$target-seeded.txt" || true; } | tail -n 1)
  [[ "$code" -eq 0 && "$counts" =~ \ executed=([0-9]+)\ pass=([0-9]+)\  ]] \
    && [ "${BASH_REMATCH[1]}" -eq "${BASH_REMATCH[2]}" ] && [ "${BASH_REMATCH[2]}" -ge "$seeds" ] \
    || fail "the $target seed pass exited $code without passing all $seeds seeds: $counts"
}

# Fuzzes TARGET for SECONDS over its seeds with inputs up to MAX_LEN bytes;
# the run must load every seed, run past them, fail no input, and reach the
# oracle checkpoint: a positive `nonseed_pass` count on its counts line. A
# generated input is one whose run differs from every seed's, and the count
# is of those the oracle judged a pass. The result joins fuzz.json under
# `campaign`, or `parsers` for another target.
target_run() {
  local target=$1 exe=$2 seconds=$3 max_len=$4 seeds code runs reason
  seeds=$(find "$EVIDENCE/$target-seeds" -type f | wc -l)
  code=0
  deadline "$((seconds + 180))s" "$exe" --fuzz "$target" --artifacts "$EVIDENCE/$target-artifacts" -- -max_total_time="$seconds" \
    -max_len="$max_len" -timeout=60 -rss_limit_mb=8192 -artifact_prefix="$EVIDENCE/$target-artifacts/" \
    "$EVIDENCE/$target-seeds" > "$EVIDENCE/$target.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the $target fuzz run exited $code; its first failure is in $target-artifacts/"
  grep -q "seed corpus: files: $seeds " "$EVIDENCE/$target.txt" \
    || fail "the $target run loaded other than the worker's $seeds seeds"
  runs=$(sed -n 's/^Done \([0-9]*\) runs in \([0-9]*\) second.*/\1 \2/p' "$EVIDENCE/$target.txt")
  reason=$(python3 - "$EVIDENCE/fuzz.json" "$EVIDENCE/$target.txt" "$target" "$seeds" "${runs:-0 0}" 2>&1 <<'EOF'
import json, re, sys
path, log, target, seeds, runs = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4]), sys.argv[5].split()
lines = [line for line in open(log, errors="replace") if line.startswith(f"fuzz: {target} ")]
if not lines:
    sys.exit("it printed no counts line")
line = lines[-1]
counts = {key: int(value) for key, value in re.findall(r"(\w+)=(\d+)", line)}
# libFuzzer runs one empty input beside the seeds before it mutates.
if int(runs[0]) <= seeds + 1 or counts.get("failure") != 0 or counts.get("executed", 0) <= seeds + 1:
    sys.exit("it did not run past its seeds without a failure")
if counts.get("nonseed_pass", 0) <= 0:
    sys.exit("no generated input passed the oracle")
record = json.load(open(path))
result = {"seeds": seeds, "runs": int(runs[0]), "seconds": int(runs[1]), **counts}
if target == "campaign":
    record["campaign"] = result
else:
    record.setdefault("parsers", {})[target] = result
json.dump(record, open(path, "w"))
EOF
  ) || fail "the $target run earned no credit: $reason"
}

# The scan matches the demangler's output against the declared names
# exactly, so the lane requires the pinned LLVM's llvm-cxxfilt. Runner
# provisioning owns the installation; the lane refuses a missing or
# mismatched tool without installing packages.
demangler() {
  local major=${LLVM%%.*} version
  DEMANGLER=$(command -v "llvm-cxxfilt-$major") \
    || fail "llvm-cxxfilt-$major is missing from PATH; provision LLVM $LLVM on the runner"
  version=$("$DEMANGLER" --version 2>&1) \
    || fail "llvm-cxxfilt-$major --version failed; provision LLVM $LLVM on the runner"
  [[ "$version" == *"LLVM version $LLVM"* ]] \
    || fail "llvm-cxxfilt-$major reports '$version'; the runner requires LLVM $LLVM"
}

# The target features of the pinned stable under the lane's RUSTFLAGS, comma-separated, for a build identity.
build_target_features() {
  local flags
  read -r -a flags <<<"$RUSTFLAGS"
  rustc "+$STABLE" "${flags[@]}" --print cfg | sed -n 's/^target_feature="\(.*\)"$/\1/p' | paste -sd, -
}

# The AArch64 barrier scan: one library-test build under the workspace
# profile with v0 symbol names, the barrier callers run by exact ID, then
# scripts/scan-barriers.py checks each site in verification/barriers/expected.json
# for sufficient fences in its linked function extent.
barriers() {
  local exe code callers features
  summary "### Barrier scan limits"
  python3 scripts/scan-barriers.py limits | sed 's/^/- /' >> "$GITHUB_STEP_SUMMARY"
  [ "$(uname -m)" = aarch64 ] || fail "the barrier scan needs a native AArch64 host, not $(uname -m)"
  demangler
  export CARGO_PROFILE_DEV_OPT_LEVEL=1 CARGO_PROFILE_DEV_DEBUG=line-tables-only CARGO_PROFILE_DEV_LTO=false
  unset CARGO_ENCODED_RUSTFLAGS
  # RUSTFLAGS replaces the flags of .cargo/config.toml, so the lane carries its LSE flag itself.
  export RUSTFLAGS="-C symbol-mangling-version=v0 -C target-feature=+lse"
  pins
  target_dir barriers
  printf '%s\n' "${PINS[@]}" > "$EVIDENCE/pins.txt"
  code=0
  deadline 40m "${STABLE_CARGO[@]}" test -p kestrike --lib --no-run --message-format=json \
    > "$EVIDENCE/build.json" 2> "$EVIDENCE/build.txt" || code=$?
  [ "$code" -eq 0 ] || { printf '%s\n' "$code" > "$EVIDENCE/exit.txt"; fail "the library-test build exited $code"; }
  exe=$(python3 scripts/scan-barriers.py select --cargo-json "$EVIDENCE/build.json") \
    || fail "no unique kestrike library-test executable in the build"
  mapfile -t callers < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["callers"]))' \
    verification/barriers/expected.json)
  deadline 10m "$exe" --exact --test-threads=1 "${callers[@]}" > "$EVIDENCE/callers.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the barrier callers exited $code"
  grep -q "^test result: ok. ${#callers[@]} passed; 0 failed; 0 ignored;" "$EVIDENCE/callers.txt" \
    || fail "the barrier callers did not report ${#callers[@]} passed, 0 failed, 0 ignored"
  features=$(build_target_features)
  python3 scripts/scan-barriers.py identity --cargo-json "$EVIDENCE/build.json" --target-features "$features" \
    --pins "$EVIDENCE/pins.txt" --output "$EVIDENCE/identity.json" 2> "$EVIDENCE/identity.txt" \
    || fail "the build identity was refused; see identity.txt"
  code=0
  python3 scripts/scan-barriers.py scan --executable "$exe" --output "$EVIDENCE/report.json" \
    --demangler "$DEMANGLER" --identity "$EVIDENCE/identity.json" 2> "$EVIDENCE/scan.txt" || code=$?
  [ -f "$EVIDENCE/report.json" ] || fail "the barrier scan exited $code before writing report.json; see scan.txt"
  python3 - "$EVIDENCE/report.json" "$GITHUB_STEP_SUMMARY" "$code" <<'PY'
import json, sys
path, summary, code = sys.argv[1], sys.argv[2], int(sys.argv[3])
report = json.load(open(path))
identity = report.get("identity") or {}
ci = identity.get("ci") or {}
lines = [f"### Barrier scan: {'credited' if report['credited'] else 'red'} (exit {code})",
         f"- revision {identity.get('revision')}, run {ci.get('GITHUB_RUN_ID')} attempt {ci.get('GITHUB_RUN_ATTEMPT')}; "
         "the scan gates rust-gate and credits no obligation record",
         f"- `{report['executable']}` sha256 {report.get('sha256')}"]
lines += [f"- {site['site']}: {site['verdict']}, `{site['symbol']}` at {site.get('address')} "
          f"size {site.get('size')}, {len(site.get('barriers', []))} DMB words"
          + (f"; {site['reason']}" if site.get("reason") else "")
          + (f"; calls {', '.join(site['calls'])}" if site.get("calls") else "") for site in report.get("sites", [])]
lines += [f"- refused: {report['reason']}"] if report.get("reason") else []
open(summary, "a").write("\n".join(lines) + "\n")
PY
  [ "$code" -eq 0 ] || fail "the barrier scan exited $code; see report.json"
}

# The tag comparison inspection on lane $1's native host: one library-test
# build with the release profile and v0 symbol names, the declared callers run
# by exact ID, then scripts/scan-tag-compare.py decodes each site of
# verification/tag-compare/expected.json with the pinned LLVM objdump and
# judges its dependency on the two tags; the judgment writes the receipt the
# credit step reads.
tag_compare() {
  local lane=$1 arch=${1#tag-compare-} exe code callers features objdump version
  summary "### Tag comparison inspection limits"
  python3 scripts/scan-tag-compare.py limits | sed 's/^/- /' >> "$GITHUB_STEP_SUMMARY"
  [ "$(uname -m)" = "${arch/x86-64/x86_64}" ] || fail "$lane inspects $arch code; this host is $(uname -m)"
  demangler
  objdump=$(command -v "llvm-objdump-${LLVM%%.*}") \
    || fail "llvm-objdump-${LLVM%%.*} is missing from PATH; provision LLVM $LLVM on the runner"
  version=$("$objdump" --version 2>&1) || fail "$objdump --version failed; provision LLVM $LLVM on the runner"
  [[ "$version" == *"LLVM version $LLVM"* ]] || fail "$objdump reports '$version'; the runner requires LLVM $LLVM"
  export CARGO_PROFILE_RELEASE_LTO=false
  unset CARGO_ENCODED_RUSTFLAGS
  # RUSTFLAGS replaces the flags of .cargo/config.toml, so the aarch64 lane carries its LSE flag itself.
  export RUSTFLAGS="-C symbol-mangling-version=v0"
  [ "$arch" != aarch64 ] || RUSTFLAGS+=" -C target-feature=+lse"
  pins
  target_dir tag-compare
  printf '%s\n' "${PINS[@]}" "- objdump ${version//$'\n'/ }" > "$EVIDENCE/pins.txt"
  code=0
  deadline 50m "${STABLE_CARGO[@]}" test --release -p kestrike --lib --no-run --message-format=json \
    > "$EVIDENCE/build.json" 2> "$EVIDENCE/build.txt" || code=$?
  [ "$code" -eq 0 ] || { printf '%s\n' "$code" > "$EVIDENCE/exit.txt"; fail "the release library-test build exited $code"; }
  exe=$(python3 scripts/scan-tag-compare.py select --cargo-json "$EVIDENCE/build.json") \
    || fail "no unique kestrike library-test executable in the build"
  mapfile -t callers < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1]))["callers"]))' \
    verification/tag-compare/expected.json)
  deadline 10m "$exe" --exact --test-threads=1 "${callers[@]}" > "$EVIDENCE/callers.txt" 2>&1 || code=$?
  printf '%s\n' "$code" > "$EVIDENCE/exit.txt"
  [ "$code" -eq 0 ] || fail "the tag comparison callers exited $code"
  grep -q "^test result: ok. ${#callers[@]} passed; 0 failed; 0 ignored;" "$EVIDENCE/callers.txt" \
    || fail "the tag comparison callers did not report ${#callers[@]} passed, 0 failed, 0 ignored"
  features=$(build_target_features)
  python3 scripts/scan-tag-compare.py identity --cargo-json "$EVIDENCE/build.json" --target-features "$features" \
    --pins "$EVIDENCE/pins.txt" --output "$EVIDENCE/identity.json" 2> "$EVIDENCE/identity.txt" \
    || fail "the build identity was refused; see identity.txt"
  code=0
  python3 scripts/scan-tag-compare.py scan --executable "$exe" --evidence "$EVIDENCE" --objdump "$objdump" \
    --demangler "$DEMANGLER" 2> "$EVIDENCE/scan.txt" || code=$?
  [ -f "$EVIDENCE/report.json" ] || fail "the inspection exited $code before writing report.json; see scan.txt"
  python3 - "$EVIDENCE/report.json" "$GITHUB_STEP_SUMMARY" "$code" <<'PY'
import json, sys
path, summary, code = sys.argv[1], sys.argv[2], int(sys.argv[3])
report = json.load(open(path))
identity = report.get("identity") or {}
lines = [f"### Tag comparison inspection: {'credited' if report['credited'] else 'red'} (exit {code})",
         f"- {report.get('machine')} `{identity.get('executable')}` sha256 {report.get('sha256')}, "
         f"revision {identity.get('revision')}, LTO {identity.get('lto')}"]
lines += [f"- {site['site']} (expects {site['expect']}): {site['verdict']}, `{site['symbol']}` at "
          f"{site.get('address')} size {site.get('size')}, decision {site.get('decision')}"
          + (f"; {site['reason']}" if site.get("reason") else "")
          + (f"; calls {', '.join(site['calls'])}" if site.get("calls") else "") for site in report.get("sites", [])]
lines += [f"- refused: {report['reason']}"] if report.get("reason") and not report.get("sites") else []
open(summary, "a").write("\n".join(lines) + "\n")
PY
  [ "$code" -eq 0 ] || fail "the inspection exited $code; see report.json"
}

# Runs the hardware roles this host is provisioned for, each case once by exact
# ID; every other role is listed unrun. The lane stays outside the Rust gate:
# a profile credits only through `hardware-lane.py judge` over every role's
# receipt.
hardware() {
  local code=0
  export RUSTUP_TOOLCHAIN="$STABLE"
  target_dir hardware
  # The job's whole evidence tree is the lane's artifacts directory: every file the job's steps write under
  # the checkout, this log and the earlier `toolchains.txt` included, is the untracked content a role accepts.
  # An interruption still summarizes the roles the sweep reported.
  trap 'summary "### Hardware: interrupted" "$(cat "$EVIDENCE/hardware.txt")"; on_signal' TERM INT
  # The step allows 240 minutes; the budget leaves ten for the build and the summary.
  python3 scripts/hardware-lane.py sweep --artifacts "$EVIDENCE" --budget-seconds 13800 \
    > "$EVIDENCE/hardware.txt" 2>&1 || code=$?
  trap on_signal TERM INT
  summary "### Hardware: provisioned roles by exact ID" "$(cat "$EVIDENCE/hardware.txt")"
  [ "$code" -eq 0 ] || fail "a provisioned hardware role was not credited; see hardware.txt"
}

# Runs the FIS profiles KESTRIKE_FIS_PROFILES names under the operator
# contract KESTRIKE_FIS_OPERATOR names; a host without a contract is red,
# since only a provisioned one carries the job's label. Like the hardware lane it stays outside
# the Rust gate. KESTRIKE_HARDWARE_PLATFORM must name a row of the checked
# hardware manifest before the build starts. FIS_STEP_SECONDS is the workflow step's `timeout` budget
# (225 minutes): a campaign runs the profiles of one attachment mode, and the four
# single-attachment profiles, the largest such set, need 12900 s under a 60 s
# effect timeout, leaving the build about eight minutes before the campaign is refused.
# FIS_KILL_GRACE_SECONDS is the step's `--kill-after`, the time the controller's
# cleanup has after the step's signal; the controller admits only contracts
# whose cleanup fits it.
FIS_STEP_SECONDS=13500
FIS_KILL_GRACE_SECONDS=900
# The least campaign budget worth starting, the smallest checked-in profile's
# bound under a 60 s effect timeout with 60 s AWS calls; the build may take the
# step's time up to this remainder, and a smaller remainder fails the lane.
FIS_LEAST_BUDGET_SECONDS=3195
fis() {
  local code=0
  if [ -z "${KESTRIKE_FIS_OPERATOR:-}" ]; then
    # Only a registration provisioned with the contract carries the FIS job's label, so a host without one is
    # misprovisioned: red, as a host provisioned for no hardware role is.
    summary "### FIS: unrun"
    fail "this kestrike-fis host carries no operator contract; set KESTRIKE_FIS_OPERATOR"
  fi
  local refusal
  if ! refusal=$(PYTHONDONTWRITEBYTECODE=1 python3 -c '
import importlib.util, os, sys
spec = importlib.util.spec_from_file_location("lane", "scripts/hardware-lane.py")
lane = importlib.util.module_from_spec(spec)
spec.loader.exec_module(lane)
try:
    platforms = lane.read_manifest(lane.MANIFEST)[0]
except (lane.Stop, OSError) as error:
    sys.exit(str(error))
row = os.environ.get("KESTRIKE_HARDWARE_PLATFORM")
if row not in platforms:
    sys.exit(lane.platform_refusal(row, "KESTRIKE_HARDWARE_PLATFORM"))
' 2>&1); then
    summary "### FIS: unrun"
    fail "this kestrike-fis host cannot run the hardware lane: ${refusal}"
  fi
  export RUSTUP_TOOLCHAIN="$STABLE"
  target_dir fis
  local begun=$SECONDS budget
  # The build is bounded by the allowance the step leaves it, so a hung compile fails here rather than run the
  # step to its timeout.
  deadline "$((FIS_STEP_SECONDS - 120 - FIS_LEAST_BUDGET_SECONDS))s" \
    "${STABLE_CARGO[@]}" test -p kestrike --lib --no-run > "$EVIDENCE/fis-build.txt" 2>&1 \
    || fail "the kestrike library tests did not build before the campaign; see fis-build.txt"
  # The step allows FIS_STEP_SECONDS; the campaign receives what the build left, less two minutes for the
  # summary, and refuses a profile set that no longer fits before it starts any episode. As in the hardware
  # lane, the job's whole evidence tree is the artifacts directory each case accepts untracked files under:
  # this log, `fis-build.txt` and the earlier `toolchains.txt` lie there. An interruption still summarizes the
  # episodes the campaign reported.
  budget=$((FIS_STEP_SECONDS - 120 - (SECONDS - begun)))
  [ "$budget" -ge "$FIS_LEAST_BUDGET_SECONDS" ] \
    || fail "the build left the campaign $budget s of the step's $FIS_STEP_SECONDS s, under the least profile's $FIS_LEAST_BUDGET_SECONDS s"
  trap 'summary "### FIS: interrupted" "$(cat "$EVIDENCE/fis.txt")"; on_signal' TERM INT
  python3 scripts/fis-controller.py campaign --operator "$KESTRIKE_FIS_OPERATOR" \
    --budget-seconds "$budget" --kill-grace-seconds "$FIS_KILL_GRACE_SECONDS" \
    --artifacts "$EVIDENCE" --observer "$EVIDENCE/fis/observer" > "$EVIDENCE/fis.txt" 2>&1 || code=$?
  trap on_signal TERM INT
  summary "### FIS: qualification episodes" "$(cat "$EVIDENCE/fis.txt")"
  [ "$code" -eq 0 ] || fail "a FIS episode was not credited; see fis.txt"
}

quarantine() {
  export RUSTUP_TOOLCHAIN="$STABLE"
  target_dir quarantine
  python3 - "$EVIDENCE" "$GITHUB_STEP_SUMMARY" <<'EOF'
import importlib.util, json, os, platform, shlex, subprocess, sys
from datetime import date
from pathlib import Path

evidence, summary = Path(sys.argv[1]), sys.argv[2]


def say(*lines):
    with open(summary, "a") as out:
        out.write("".join(f"{line}\n" for line in lines))


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def recipe_args(recipe):
    if recipe[:2] != ["python3", "scripts/reproduce-test.py"]:
        return None
    try:
        return reproduce.parser().parse_args(recipe[2:])
    except SystemExit:
        return None


select = load("select_tests", "scripts/select-tests.py")
reproduce = load("reproduce_test", "scripts/reproduce-test.py")
try:
    registry = select.load_registry(select.REGISTRY, select.load_inventory(select.INVENTORY)["baseline"])
except select.Refusal as refusal:
    say("### Quarantine: red", f"- the registry was refused: {refusal}")
    print(f"::error::the registry was refused: {refusal}")
    sys.exit(1)
rows = [row for row in registry.values() if row["class"] == "flaky-quarantine"]
ordinary = {(row["target"], row["id"]) for row in rows if row["cfg"] == "ordinary"}
twins = [row for row in rows if row["cfg"] != "ordinary" and (row["target"], row["id"]) in ordinary]
rows = [row for row in rows if row not in twins]
rustc = subprocess.run(["rustc", "--version"], capture_output=True, text=True, check=False).stdout.strip()
run_id = os.environ.get("GITHUB_RUN_ID", "local")
attempt = os.environ.get("GITHUB_RUN_ATTEMPT", "1")
server, repository = os.environ.get("GITHUB_SERVER_URL"), os.environ.get("GITHUB_REPOSITORY")
link = f"{server}/{repository}/actions/runs/{run_id}" if server and repository else "this run"
say(f"### Quarantine: {len(rows)} flaky-quarantine row(s) by exact ID",
    f"- host {platform.node()} ({platform.machine()}), {rustc}",
    "- red for rejected input, build failure, crash (zero executed included), interruption, "
    "an unusable recipe or any exit without its matching verdict; a reproduction or a watchdog "
    "expiry is a reported finding",
    "- results are reports: none closes a ticket or lifts a quarantine, and a pass "
    "or `not reproduced` is not evidence of a fix",
    *([f"- policy gap: {gap}" for gap in select.policy_gaps(rows, date.today())] or ["- policy gaps: none"]),
    *(f"- `{row['id']}` ({row['cfg']}): reproduced through its ordinary row" for row in twins))
profile_env = {
    "RUSTUP_TOOLCHAIN": os.environ["STABLE"],
    "CARGO_PROFILE_DEV_OPT_LEVEL": "1",
    "CARGO_PROFILE_DEV_DEBUG": "line-tables-only",
}
profile_prefix = [f"{name}={value}" for name, value in profile_env.items()]
red = []
for row in rows:
    try:
        recipe = shlex.split(row.get("recipe") or "")
    except ValueError:
        recipe = []
    command, env = recipe, None
    if recipe[:len(profile_prefix)] == profile_prefix:
        command = recipe[len(profile_prefix):]
        env = {**os.environ, **profile_env}
    args = recipe_args(command)
    if row["cfg"] != "ordinary" or args is None or reproduce.registry_key(args) != (row["target"], row["id"]):
        say(f"- `{row['id']}`: not run; the recipe needs `python3 scripts/reproduce-test.py` with --package, "
            f"--attempts, --test {row['id']} and the --target that selects {row['target']} "
            "(`lib` for a crate's library tests), optionally preceded by exactly "
            f"`{shlex.join(profile_prefix)}`")
        red.append(f"{row['id']}: unusable recipe")
        continue
    say(f"- `{row['id']}`: running `{shlex.join(recipe)}`; a lane timeout leaves this as the last line")
    argv = [sys.executable, *command[1:], "--artifacts", str(evidence / "reproduce"),
            "--run-id", run_id, "--lane", "quarantine"]
    result = subprocess.run(argv, env=env, capture_output=True, text=True, errors="replace", check=False)
    with (evidence / "reproduce.log").open("a") as log:
        log.write(result.stdout + result.stderr)
    found = [line.split(": ", 1)[1] for line in result.stderr.splitlines() if line.startswith("artifact: ")]
    where = Path(found[0]).relative_to(evidence) if found else "no artifact"
    output = result.stdout.strip().splitlines()
    verdict = output[-1] if output else f"exit {result.returncode}"
    say(f"- `{row['id']}`: {verdict} (exit {result.returncode}); `{where}` in artifact "
        f"`evidence-quarantine-{run_id}-{attempt}` of {link}")
    try:
        record = json.loads(Path(found[0]).read_text()) if found else {}
    except (OSError, ValueError):
        record = {}
    if record.get("executable"):
        tried = record.get("attempts", [])
        last = (tried[-1].get("summary") or ["no summary"])[-1] if tried else "no attempt"
        say(f"- `{row['id']}`: executable `{Path(record['executable']['path']).name}` sha256 "
            f"`{record['executable']['sha256'][:16]}`, {len(tried)} of {record.get('attempts_requested')} "
            f"attempts, last `{last}`")
    if not reproduce.reported(result.returncode, verdict):
        red.append(f"{row['id']}: {verdict} (exit {result.returncode})")
for item in red:
    print(f"::error::{item}")
sys.exit(1 if red else 0)
EOF
}

report() {
  python3 - "$1" "$EVIDENCE" "${2:-}" >> "$GITHUB_STEP_SUMMARY" <<'EOF'
import importlib.util, json, os, re, subprocess, sys
from pathlib import Path

lane, evidence, module = sys.argv[1:4]
evidence = Path(evidence)


def load(name):
    try:
        return json.loads((evidence / name).read_text())
    except (OSError, ValueError):
        return None


failure = (evidence / "failure.txt").read_text().strip() if (evidence / "failure.txt").exists() else None
revision = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip() or "unknown"
if lane == "rc11":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### RC11 litmus oracle: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    print("### RC11 litmus oracle: credited")
    print(f"- revision {revision}")
    for name, counts in sorted(result["tests"].items()):
        print(f"- {name}: {counts['outcome']} ({counts['positive']} positive, {counts['negative']} negative)")
    print("- finite C11/RC11 litmus evidence for the inventoried encodings only; the Rust translation, compiler "
          "and hardware obligations stay separate")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
if lane == "genmc":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### GenMC {module} profile: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    print(f"### GenMC {module} profile: credited")
    print(f"- revision {revision}")
    domain, credited = "PR domain: qualification cases, the credit cases and one-reader grace", "the pr records only"
    if module == "scheduled":
        domain, credited = "scheduled domain: the PR cases and two-reader grace", "the pr and scheduled records"
    print(f"- {domain}; this receipt credits {credited}")
    for name, case in sorted(result["cases"].items()):
        where = f" at {case['at']}" if "at" in case else ""
        print(f"- {name}: {case['result']}{where}, {case['executions']} complete executions")
    options = " ".join(json.loads(Path("verification/genmc/expected.json").read_text())["options"])
    print(f"- genmc {options}, no exploration bound or loop unrolling option; shims: genmc-std "
          "thread::spawn_f, JoinHandle::join and __VERIFIER_assert_fail")
    print("- finite RC11 evidence for these standalone cases under GenMC's experimental Rust frontend; the kernels "
          "include the production credit, grace and word modules by path with a no-op probe, the production "
          "ERA_TERMINAL value, static memory, the thread shims above and a transcription of the index and "
          "registration operations; no C++20 or hardware equivalence is claimed")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
if lane == "kani":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### Kani {module} profile: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    print(f"### Kani {module} profile: credited")
    print(f"- revision {revision}")
    domain = "PR domain: the harnesses a manual dispatch runs"
    if module == "scheduled":
        domain = ("scheduled domain: every harness verification/kani/expected.json declares, at its stated bounds; "
                  "the declared gaps are checked by layout_tests and grant_tests")
    credited = "the pr and scheduled records" if module == "scheduled" else "the pr records only"
    print(f"- {domain}; this receipt credits {credited}")
    harnesses = result["harnesses"]
    print(f"- {len(harnesses)} harnesses, {sum(h['checks'] for h in harnesses.values())} checks, "
          f"{sum(h['covers'] for h in harnesses.values())} covers satisfied, "
          f"{sum(h['seconds'] for h in harnesses.values()):.0f} s of verification")
    for name, counts in sorted(harnesses.items(), key=lambda item: -item[1]["seconds"])[:10]:
        print(f"- {name}: {counts['checks']} checks, {counts['covers']} covers, {counts['seconds']:.1f} s")
    print("- bit-precise bounded proofs of each harness's stated domain under Kani's default checks; the "
          "reciprocal proof covers dividends below 2^24 and geometry_tests checks the exactness bound for every span")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
if lane == "verus":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### Verus proofs: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    print("### Verus proofs: credited")
    print(f"- revision {revision}")
    print(f"- {result['results']['verified']} items verified; {', '.join(result['results']['items'])}")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
if lane == "tlc":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### TLC {module} profile: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    credited = "the pr and scheduled records" if module == "scheduled" else "the pr records only"
    print(f"### TLC {module} profile: credited")
    print(f"- revision {revision}; this receipt credits {credited}")
    for name, case in sorted(result["cases"].items()):
        mode = ", final liveness" if case["liveness"] else ""
        print(f"- {name}: {case['distinct']} distinct states in {case['seconds']} s{mode}")
    unreached = result.get("unreached", {})
    for model, spans in sorted(unreached.items()):
        if isinstance(spans, str):
            print(f"- {model}: unreached spans unread: {spans}")
        elif isinstance(spans, list):
            for span in spans:
                print(f"- {model}: unreached span of {span['section']} at {span['at']}: `{span['text']}`")
    if unreached and all(spans == [] for spans in unreached.values()):
        read = result.get("unreached_read", {})
        print(f"- no listed span is unreached: {read.get('cases')} cases and {read.get('span_lines')} span lines read")
    print("- finite instances at the bounds each configuration states; no refinement mapping to the implementation")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
if lane == "quint":
    result = load("report.json")
    if failure or result is None or not result.get("credited"):
        reason = failure or (result or {}).get("reason") or "the judgment did not run"
        print(f"### Quint models: red\n- revision {revision}\n- reason: {reason}")
        sys.exit()
    cases = result["cases"]
    print("### Quint models: credited")
    print(f"- revision {revision}")
    for name, case in sorted(cases.items()):
        if "blocked" in case:
            print(f"- {name}: withheld at {case['blocked']}; no credit")
        if case["command"] == "typecheck":
            print(f"- {name}: the model typechecks")
        elif case["command"] == "replay" and "longest" not in case:
            print(f"- {name}: core replay, {case['traces']} traces, {case['actions']} actions, every decision matched")
        elif case["command"] == "replay":
            print(f"- {name}: implementation replay, separate from the model results: {case['traces']} Connect traces, "
                  f"{case['actions']} actions, longest {case['longest']}, every action reached, every projected state matched")
        elif "traces" in case:
            lengths = case["lengths"]
            print(f"- {name}: {case['traces']} traces of {lengths['min']} to {lengths['max']} states; "
                  f"{sum(1 for hit in case['witnessed'].values() if hit)} of {len(case['witnessed'])} witnesses seen")
        else:
            shape = f"; counterexample of {case['trace']} states" if "trace" in case else ""
            loop = f", loop {case['lasso'][0]} to {case['lasso'][1]}" if "lasso" in case else ""
            depth = f", depth {case['depth']}" if case["depth"] is not None else ""
            print(f"- {name}: {case['distinct']} distinct states{depth}{shape}{loop}, {case['seconds']} s")
    print("- model results: finite checks at the stated constants, whose guarantees cover this model instance; the "
          "Connect replay reports implementation agreement over its generated traces")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
    sys.exit()
spec = importlib.util.spec_from_file_location("select_tests", "scripts/select-tests.py")
select = importlib.util.module_from_spec(spec)
spec.loader.exec_module(select)
inventory = select.load_inventory(select.INVENTORY)
if lane in ("fuzz", "fuzz-smoke"):
    title = "Frame, campaign and parser fuzz" + (" smoke" if lane == "fuzz-smoke" else "")
    seconds = {row["target"]: row["seconds"] for row in inventory["qualified"][lane]["rows"]}
    result = load("fuzz.json") or {}
    if failure or result.get("runs", 0) <= result.get("seeds", 0) + 1 or "campaign" not in result \
            or set(result.get("parsers", {})) != {"record", "wire"}:
        print(f"### {title}: red\n- revision {revision}\n- reason: {failure or 'the run did not finish'}")
        sys.exit()
    fuzz = subprocess.run(["cargo", f"+{os.environ['STABLE']}", "fuzz", "--version"],
                          capture_output=True, text=True).stdout.strip()
    print(f"### {title}: passed")
    print(f"- revision {revision}")
    print(f"- {fuzz}, sanitizer address, {result['seeds']} seed files, {seconds['frame']} s requested, "
          f"{result['runs']} executions in {result['seconds']} s")
    print("- claims robustness only: parse never panics and accepted frames re-encode")
    campaign = result["campaign"]
    print(f"- campaign: instrumented worker, {campaign['seeds']} seeds each passed, wrong-byte control audited "
          f"before its abort, {campaign['runs']} runs in {campaign['seconds']} s, none failed, "
          f"{campaign['nonseed_pass']} generated passes")
    for name, parser in sorted(result["parsers"].items()):
        print(f"- {name}: instrumented worker, {parser['seeds']} seeds each passed, {parser['runs']} runs in "
              f"{parser['seconds']} s, none failed, {parser['nonseed_pass']} generated passes; the real path "
              "against its literal reference")
    sys.exit()

title = {"loom": f"Loom {module}", "miri": "Miri ownership corpus", "sweep": "Miri weak-memory sweep",
         "long-run": "Long-run gate", "campaigns": "Worker campaigns", "search": "ServeCore search, pull-request bound",
         "search-nightly": "ServeCore search, nightly bounds", "asan": "Address-sanitized library tests",
         "qemu": "Guest binder in a disposable QEMU guest", "isa-x86-64": "x86-64 architecture qualification",
         "isa-aarch64": "AArch64 architecture qualification"}.get(lane, "Workspace suite")
report = load("report.json")
if report is None:
    selection = load("selection.json")
    verdict = selection["verdict"] if selection else "not reached"
    reason = failure or (selection or {}).get("reason") or "the run was not judged"
    print(f"### {title}: red\n- revision {revision}\n- listing {verdict}; run not judged; reason: {reason}")
    sys.exit()
# A refused judgment exits through the ERR trap, so failure.txt accompanies every refused report and the
# heading keeps that verdict; a failure after a credited report, a Miri control's, makes the lane red. The verdict
# is the selection report's; the credit step's line states the obligations' credit.
failed_after_credit = failure is not None and report["verdict"] == "credited"
heading = "red" if failed_after_credit else f"selection {report['verdict']}"
print(f"### {title}: {heading}")
print(f"- revision {revision}; census baseline {report['baseline']}")
if failed_after_credit:
    print(f"- reason: {failure}")
targets = report["targets"]
if lane == "loom":
    counts = targets.get(module, {})
    sources = [path.read_text() for path in Path("crates/kestrike/src").rglob(f"{module}.rs")]
    # Inline models have no module-named file; take only their block, not sibling models' bounds.
    inline = re.compile(rf"(?ms)^(?P<indent>[ \t]*)mod {re.escape(module)} \{{\n.*?^(?P=indent)\}}")
    for path in Path("crates/kestrike/src").rglob("*.rs"):
        sources.extend(match.group() for match in inline.finditer(path.read_text()))
    if len(sources) != 1:
        raise ValueError(f"expected one source for Loom {module}, found {len(sources)}")
    source = sources[0]
    constant = re.search(r"const PREEMPTION_BOUND: usize = (\d+);", source)

    def calls(name, index):
        values = []
        for match in re.finditer(rf"(?<![\w:]){name}\(", source):
            if source[max(0, match.start() - 3):match.start()] == "fn ":
                continue
            depth, start, args = 1, match.end(), []
            for at in range(match.end(), len(source)):
                char = source[at]
                if char in "([{":
                    depth += 1
                elif char in ")]}":
                    depth -= 1
                if depth == 1 and char == "," or depth == 0:
                    args.append(source[start:at].strip())
                    start = at + 1
                if depth == 0:
                    break
            if len(args) > index:
                values.append(args[index])
        return values

    bounds = {}
    for found in re.finditer(r"preemption_bound = Some\((\w+)\)", source):
        value = found.group(1)
        if value == "PREEMPTION_BOUND" and constant:
            value = constant.group(1)
        if value.isdigit():
            bounds[value] = bounds.get(value, 0) + 1
            continue
        helper = list(re.finditer(r"fn (\w+)\(([^)]*)\)", source[:found.start()]))[-1]
        params = [p.split(":")[0].strip() for p in helper.group(2).split(",")]
        for argument in calls(helper.group(1), params.index(value)):
            bounds[argument] = bounds.get(argument, 0) + 1
    unbounded = source.count("loom::model(")
    if unbounded:
        bounds["unbounded (loom::model)"] = unbounded
    stated = ", ".join(f"{bound} at {count} sites" for bound, count in sorted(bounds.items()))
    fences = inventory["loom"][module]["ignored"]
    print(f"- loom {os.environ['LOOM']}, LOOM_* cleared, preemption bounds: {stated}")
    print(f"- {counts.get('listed', 0)} listed, {counts.get('executed', 0)} executed, "
          f"{counts.get('observed_ignored', 0)} ignored")
    print(f"- excluded fence controls: {', '.join(fences) if fences else 'none'}")
    print("- covers the shimmed model only")
elif lane == "sweep":
    declared = inventory["miri_sweep"]
    counts = targets.get(inventory["miri"]["target"], {})
    print(f"- {counts.get('executed', 0)} executions: {len(declared['tests'])} kernels over seeds 0..{declared['seeds']} "
          "under -Zmiri-many-seeds with default weak-memory emulation and preemption")
    print(f"- kernels: {', '.join(f'`{name}`' for name in declared['tests'])}")
    print("- seeds are samples of schedules and weak-memory outcomes; SC-fence weakening evidence belongs to the "
          "RC11 lanes, and the publication bracket's physical clock sample lies outside these kernels")
    print("- open in this lane: removing the sequence bracket's Release fence went undetected over all 64 seeds")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
elif lane in inventory["qualified"]:
    declared = inventory["qualified"][lane]
    counts = targets.get(declared["target"], {})
    side = "among the ignored cases of" if declared["ignored"] else "in"
    print(f"- {counts.get('executed', 0)} of {sum(len(row['tests']) for row in declared['rows'])} selected cases executed "
          f"by exact ID {side} {declared['target']}, {counts.get('filtered', 0)} filtered out")
    for row in report.get("rows") or [{**row, "credited": False, "reasons": ["the run was not judged"]} for row in declared["rows"]]:
        print(f"- row {row['id']} ({row['kind']}): " + ("credited" if row["credited"] else f"blocked: {'; '.join(row['reasons'])}"))
    patterns = [pattern for row in declared["rows"] for pattern in [*row.get("witnesses", []), *([row["bound"]] if "bound" in row else [])]]
    run = evidence / "run.txt"
    for line in run.read_text(errors="replace").splitlines() if run.exists() else []:
        if any(re.search(pattern, line.strip()) for pattern in patterns):
            print(f"- {line.strip()}")
    if lane.startswith("isa-"):
        print("- test-build execution counts on this host's CPU: each kernel's count and detected predicate in its witness line; "
              "release-build code and other CPUs are outside its evidence")
    if lane == "long-run":
        print("- fixed manifests under the workspace dev profile: the gate's seed and root in its churn and mixed lines, the "
              "scaled seeds and geometries, the warm and slot-reuse cycles' seeds, the fleet's roots and the suffix trees in their rows; other seeds, roots, geometries and trees are outside its evidence")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
elif lane == "asan":
    envelope = load("qualified.json") or {}
    for target, counts in sorted(targets.items()):
        executed_modules = counts.get("witnesses", {}).get("executed_modules") or {}
        modules = ", ".join(f"{module} {count}" for module, count in sorted(executed_modules.items()))
        controls = ", ".join(f"`{name}`" for name in counts.get("witnesses", {}).get("controls", []))
        print(f"- {target}: {counts.get('executed', 0)} executed, {counts.get('observed_ignored', 0)} ignored; "
              f"controls {controls or 'none'}; attributed per module: {modules or 'none'}")
    print(f"- attempt {envelope.get('attempt')}; target {envelope.get('target')}; sanitizer {envelope.get('sanitizer')}; "
          f"rustflags `{envelope.get('rustflags')}`")
    print(f"- generated {envelope.get('generated')}; header digest {envelope.get('header_digest')}; "
          f"generator digest {envelope.get('generator_digest')}; generator {envelope.get('generator')}")
    native = envelope.get("native") or {}
    runtime = envelope.get("runtime") or {}
    print(f"- native compilers {native.get('compilers')}; configure {native.get('configure')}; archives {native.get('archives')}")
    print(f"- sanitizer runtime {runtime.get('archive')} sha256 {runtime.get('sha256')}; {runtime.get('rustc')}; LLVM {runtime.get('llvm')}")
    deadlines, measured = envelope.get("deadlines") or {}, envelope.get("measured") or {}
    print(f"- deadlines: build {deadlines.get('build_minutes')}m, at least {deadlines.get('build_factor')} times the measured "
          f"{measured.get('build_seconds')} s; run {deadlines.get('run_minutes')}m, at least {deadlines.get('run_factor')} times the "
          f"measured {measured.get('run_seconds')} s; measured peak {measured.get('peak_rss_mib')} MiB under "
          f"{measured.get('cpus')} CPUs and {measured.get('memory_mib')} MiB on {measured.get('date')}")
    print("- leak detection off; covers the sanitized Rust and native code of both library test binaries on this host alone")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
elif lane == "qemu":
    envelope, guest = load("qualified.json") or {}, load("guest.json") or {}
    declared = inventory["qemu"]
    counts = targets.get(declared["target"], {})
    print(f"- {counts.get('executed', 0)} of {len(declared['tests'])} guest cases executed by exact ID among the ignored cases of "
          f"{declared['target']}, {counts.get('filtered', 0)} filtered out; {', '.join(f'`{name}`' for name in declared['tests'])}")
    print(f"- guest outcome {guest.get('outcome')}; reports {guest.get('reports')}; ready {guest.get('ready')}; "
          f"guest exit {guest.get('guest_exit')}, QEMU exit {guest.get('qemu_exit')} in {guest.get('seconds')} s")
    identity = guest.get("identity") or {}
    print(f"- identity: volume {identity.get('volume')}, instance {identity.get('instance')}, model {identity.get('model')}, "
          f"pci {identity.get('pci')}; {guest.get('qemu_version')}")
    inputs = guest.get("inputs") or {}
    print("- inputs: " + "; ".join(f"{name} {(inputs.get(name) or {}).get('sha256')}" for name in ("qemu", "kernel", "initrd")))
    bounds, backing, cleanup = guest.get("bounds") or {}, guest.get("backing") or {}, guest.get("cleanup") or {}
    argv = guest.get("argv") or []
    iommu = [word for word in argv if "iommu" in word]
    print(f"- bounds {bounds}; backing {backing.get('bytes')} bytes, removed {cleanup.get('backing_removed')}; "
          f"IOMMU settings {iommu or 'absent'}")
    artifact, host = envelope.get("artifact") or {}, envelope.get("host") or {}
    print(f"- attempt {envelope.get('attempt')}; artifact {artifact.get('generated')} target {artifact.get('target')} "
          f"header digest {artifact.get('header_digest')} generator digest {artifact.get('generator_digest')} "
          f"archives {artifact.get('archives')} install {artifact.get('install')} from {artifact.get('source')}")
    print(f"- host {host.get('kernel')} {host.get('machine')} accel {host.get('accel')}; inputs file {(envelope.get('inputs') or {}).get('sha256')}")
    deadlines, measured = envelope.get("deadlines") or {}, envelope.get("measured") or {}
    members = sum(case["deadline_seconds"] + declared.get("member_drain_seconds", 0) for case in declared.get("namespace_cases", []))
    print(f"- deadlines: handshake {deadlines.get('handshake_minutes')}m, at least {deadlines.get('handshake_factor')} times the measured "
          f"{measured.get('handshake_seconds')} s; run {deadlines.get('run_minutes')}m, at least {deadlines.get('run_factor')} times the "
          f"measured {measured.get('run_seconds')} s plus the namespace members' {members} s; measured peak {measured.get('peak_rss_mib')} MiB under "
          f"{measured.get('cpus')} CPUs and {measured.get('memory_mib')} MiB on {measured.get('date')}")
    print("- covers the binder over the guest's emulated controller behind its IOMMU; physical DMA and containment stay with the hardware lanes")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
elif lane == "miri":
    declared = inventory["miri"]
    counts = targets.get(declared["target"], {})
    print(f"- {counts.get('executed', 0)} of {len(declared['tests'])} selected IDs executed at seed 0 on one test thread; "
          f"{counts.get('interpreter_ignored', 0)} interpreter ignores reconciled against the registry")
    print(f"- IDs: {', '.join(f'`{name}`' for name in declared['tests'])}")
    controls = evidence / "controls.txt"
    for row in controls.read_text().splitlines() if controls.exists() else []:
        test, code, diagnostic = (row.split("\t") + ["", ""])[:3]
        print(f"- control `{test}`: exit {code}, diagnostic {diagnostic}")
    print("- detectors: Stacked Borrows aliasing (the default model), data races, weak memory and leaks, "
          "all at their defaults, with isolation enabled; no detector is disabled")
    print("- limit: one sampled schedule at seed 0; weak-memory emulation bounds store buffers and is incomplete, "
          "so an SC-fence weakening can go undetected")
    print("- limit: integer-to-pointer casts are accepted without warning across the run; the heap test platform's "
          "deallocation pointer, rebuilt from a stored address, is the known site, and strict-provenance "
          "compatibility is unestablished")
    print("- covers interpreted heap and simulated-device paths only")
    print("- pins; the native pins are build-time inputs, not interpreted coverage:")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
else:
    per_crate = {}
    for crate, declared in inventory["ordinary"].items():
        per_crate[crate] = sum(targets.get(t, {}).get("observed_ignored", 0) for t in declared["targets"])
    executed = sum(t.get("executed", 0) for t in targets.values())
    ignored = ", ".join(f"{count} {crate}" for crate, count in per_crate.items())
    print(f"- {executed} executed; ignored per crate: {ignored}")
    for target, counts in sorted(targets.items()):
        executed_modules = counts.get("witnesses", {}).get("executed_modules")
        if executed_modules:
            modules = ", ".join(f"{module} {count}" for module, count in sorted(executed_modules.items()))
            print(f"- {target} witnesses: {len(counts['witnesses']['controls'])} "
                  f"required controls executed; tests executed per required module: {modules}")
    pins = evidence / "pins.txt"
    if pins.exists():
        print(pins.read_text().rstrip())
if report["reason"]:
    print(f"- reason: {report['reason']}")
EOF
}

case "${1:-}" in
  toolchains) step toolchains toolchains ;;
  preflight) preflight ;;
  workspace) workspace ;;
  long-run | campaigns | search | search-nightly) qualified "$1" ;;
  isa-x86-64 | isa-aarch64) isa "$1" ;;
  loom) loom "${2:?usage: rust-lane.sh loom MODULE}" ;;
  miri) miri ;;
  asan) asan ;;
  tsan) tsan ;;
  litmus) litmus ;;
  qemu) qemu ;;
  sweep) miri_sweep ;;
  herdtools) step herdtools herdtools ;;
  rc11) rc11 ;;
  verus) verus ;;
  genmc) genmc "${2:?usage: rust-lane.sh genmc pr|scheduled [CASE...]}" "${@:3}" ;;
  kani) kani "${2:?usage: rust-lane.sh kani pr|scheduled}" ;;
  kani-compare) shift; kani_compare "$@" ;;
  kani-toolchain) kani_toolchain ;;
  tlctools) step tlctools tlc_tools ;;
  tlc) tlc "${2:?usage: rust-lane.sh tlc pr|scheduled}" ;;
  quinttools) step quinttools quint_tools ;;
  quint) quint "${2:-}" ;;
  fuzz | fuzz-smoke) fuzz "$1" ;;
  quarantine) quarantine ;;
  hardware) hardware ;;
  fis) fis ;;
  barriers) barriers ;;
  tag-compare-x86-64 | tag-compare-aarch64) tag_compare "$1" ;;
  summary)
    case "${2:-}" in
      workspace | long-run | campaigns | search | search-nightly | isa-x86-64 | isa-aarch64 | fuzz | fuzz-smoke | miri | asan | qemu | sweep | rc11 | verus | quint) report "$2" ;;
      genmc) report genmc "${3:?usage: rust-lane.sh summary genmc PROFILE}" ;;
      kani) report kani "${3:?usage: rust-lane.sh summary kani PROFILE}" ;;
      tlc) report tlc "${3:?usage: rust-lane.sh summary tlc PROFILE}" ;;
      loom) report loom "${3:?usage: rust-lane.sh summary loom MODULE}" ;;
      *) echo "usage: rust-lane.sh summary workspace|long-run|campaigns|search|search-nightly|isa-x86-64|isa-aarch64|fuzz|fuzz-smoke|miri|asan|qemu|sweep|rc11|verus|quint|genmc PROFILE|kani PROFILE|tlc PROFILE|loom MODULE" >&2; exit 2 ;;
    esac ;;
  *)
    echo "usage: rust-lane.sh toolchains|preflight|workspace|long-run|campaigns|search|search-nightly|isa-x86-64|isa-aarch64|loom MODULE|miri|asan|tsan|litmus|qemu|sweep|herdtools|rc11|verus|genmc PROFILE [CASE...]|kani PROFILE|tlctools|tlc PROFILE|quinttools|quint [SHARD]|fuzz|fuzz-smoke|quarantine|hardware|fis|barriers|tag-compare-x86-64|tag-compare-aarch64|summary LANE" >&2
    exit 2 ;;
esac
