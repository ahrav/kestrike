#!/usr/bin/env bash
# The controlled native build of the pinned SPDK release with its bundled DPDK,
# and the sole writer of an install record's lineage.
#
# Usage:
#   crates/spdk-sys/native/install.sh build PREFIX [CONFIGURE_OPTION...]
#   crates/spdk-sys/native/install.sh record PREFIX
#   crates/spdk-sys/native/install.sh measure LIBDIR INCLUDEDIR DIR
#   crates/spdk-sys/native/install.sh normalize LINE...
#
# PREFIX, LIBDIR, INCLUDEDIR and DIR are absolute paths: the script runs from
# crates/spdk-sys, where it reads native/patches and src/generated/installs.
# `build` installs under PREFIX alone, so a `--prefix` or `--libdir` among the
# CONFIGURE_OPTIONs is refused, and PREFIX starts absent or empty, so the
# lineage measures this build's archives alone.
#
# `build` clones SPDK_URL (default https://github.com/spdk/spdk) into a fresh
# tree and checks out SPDK_COMMIT with its dpdk submodule at DPDK_COMMIT and
# its isa-l and isa-l-crypto submodules. It applies
# native/patches/*.patch in name order, configures with the options
# crates/spdk-sys/src/lib.rs names, `--prefix=PREFIX` and each
# CONFIGURE_OPTION (`--target-arch=x86-64-v2`, `--enable-asan`), builds with
# the DPDK driver set and installs. It keeps the effective build inputs (the
# configure options, make variables, compiler version and compiler
# environment) as PREFIX/share/spdk-sys/build-inputs.txt, writes
# PREFIX/share/spdk-sys/build.txt (the `Source` line of the checked-out
# commits and the lineage `measure` takes of the fresh install), and runs
# `record`.
#
# `record` rewrites the lineage of the install record the install selects,
# src/generated/installs/<target>-<core>[-asan], whose target line must equal
# the install's with the include root normalized and whose `Header digest`
# must equal the install's headers' (native/header-digest.sh): build.txt's
# `Source` line and the install's measurement, which must equal the
# measurement build.txt holds. regenerate.sh rewrites a record without its
# lineage, so run it before `record` when the headers change; `record` refuses
# a record whose header digest is other than the install's. An install without
# build.txt carries no controlled build, and `record` refuses it.
#
# `measure` writes DIR/native-archives.txt, the `sha256sum` listing of
# LIBDIR's libspdk_*.a and librte_*.a in the C locale, and
# DIR/native-configure.txt, the `SPDK_CONFIG_` and `RTE_MACHINE` defines of
# INCLUDEDIR, and prints the lineage lines: `Patches` (the digest of the
# repository's native/patches set), `Build inputs` (the sha256 of the install's
# build-inputs.txt, `unrecorded` without one, or `stale` when it lacks a
# configure option or make variable this script names), `Compilers` (the
# `.comment` entries of every static archive in LIBDIR), `Configure` (the
# configure text's sha256) and one `Archive` line per static archive in
# LIBDIR. The lanes measure the selected install with it and compare against
# the record.
#
# `normalize` prints each target LINE with its first `-I` token other than
# `-Inative` replaced by `-I<includedir>`, one per line.
# crates/spdk-sys/native/select.rs uses this normalized form to select a
# record; `record` and the lanes use it to compare target lines.
set -euo pipefail
cd "$(dirname "$0")/.."

SPDK_COMMIT=44b23be7c35469bc0aba4b942c08c935125e2315
DPDK_COMMIT=cf36799c473a686fa14fde9af97f917a2125d3d5
CONFIGURE=(--without-shared --disable-tests --disable-unit-tests --disable-examples --disable-apps
  --without-crypto --without-fuse --without-uring --without-rdma --without-vhost --without-virtio
  --without-vfio-user --without-idxd --without-iscsi-initiator --without-xnvme --without-nvme-cuse
  --without-ocf --without-fio --without-usdt --without-avahi --without-golang --without-sma --without-daos
  --without-rbd --without-ublk --without-aio-fsdev --without-fc --without-vtune)
MAKE_VARIABLES=(DPDKBUILD_FLAGS=-Denable_driver_sdk=true
  "DPDK_DRIVERS=bus bus/pci bus/vdev mempool/ring net/ena power/acpi power/amd_pstate power/cppc power/intel_pstate power/intel_uncore power/kvm_vm")

die() {
  echo "install.sh: $*" >&2
  exit 1
}

# The script runs from crates/spdk-sys, so a relative path argument would resolve against that directory.
absolute() {
  local path
  for path; do
    [[ $path == /* ]] || die "$path is relative; name an absolute path"
  done
}

patches() {
  (shopt -s nullglob; cd native && export LC_ALL=C && for patch in patches/*.patch; do sha256sum "$patch"; done) \
    | sha256sum | cut -c1-64
}

build_inputs() {
  local inputs=$1 option lines text
  [ -f "$inputs" ] || { echo unrecorded; return; }
  mapfile -t lines < "$inputs"
  printf -v text '\n%s' "${lines[@]}"
  for option in "${CONFIGURE[@]/#/configure }" "${MAKE_VARIABLES[@]/#/make }"; do
    [[ $text$'\n' == *$'\n'"$option"$'\n'* ]] || { echo stale; return; }
  done
  sha256sum < "$inputs" | cut -c1-64
}

measure() (
  local libdir=$1 includedir=$2 dir=$3 scratch digests archives slice files jobs=() job i compilers sums=() line
  local spdk=() rte=() lines
  scratch=$(mktemp -d)
  trap 'wait; rm -rf "$scratch"' EXIT
  (
    { grep '^#define SPDK_CONFIG_' "$includedir/spdk/config.h" \
        && grep '^#define RTE_MACHINE ' "$includedir/rte_build_config.h"; } \
      > "$dir/native-configure.txt" || die "the install records no configure settings"
    echo "Patches: $(patches)"
    echo "Build inputs: $(build_inputs "$libdir/../share/spdk-sys/build-inputs.txt")"
    echo "Configure: $(sha256sum < "$dir/native-configure.txt" | cut -c1-64)"
  ) > "$scratch/digests" &
  digests=$!
  (cd "$libdir" && export LC_ALL=C && printf '%s\0' *.a) > "$scratch/archives"
  mapfile -d '' -t archives < "$scratch/archives"
  slice=$(((${#archives[@]} + 3) / 4))
  for ((i = 0; i < ${#archives[@]}; i += slice)); do
    files=("${archives[@]:i:slice}")
    (cd "$libdir" && sha256sum -- "${files[@]}") > "$scratch/sums.$i" &
    jobs+=($!)
    (cd "$libdir" && readelf -p .comment "${files[@]/#/./}" 2>/dev/null | sed -n 's/^ *\[ *[0-9]*\] *//p') \
      > "$scratch/comments.$i" &
    jobs+=($!)
  done
  for job in "${jobs[@]}"; do
    wait "$job" || die "measuring the static archives in $libdir"
  done
  for ((i = 0; i < ${#archives[@]}; i += slice)); do
    mapfile -t -O "${#sums[@]}" sums < "$scratch/sums.$i"
  done
  for line in "${sums[@]}"; do
    case ${line#*  } in
      libspdk_*) spdk+=("$line") ;;
      librte_*) rte+=("$line") ;;
    esac
  done
  [ "${#spdk[@]}" -gt 0 ] && [ "${#rte[@]}" -gt 0 ] || die "hashing the archives in $libdir"
  printf '%s\n' "${spdk[@]}" "${rte[@]}" > "$dir/native-archives.txt"
  compilers=$(LC_ALL=C sort -u "$scratch"/comments.* | paste -sd';')
  [ -n "$compilers" ] || die "the native archives name no compiler"
  wait "$digests" || exit 1
  mapfile -t lines < "$scratch/digests"
  printf '%s\n' "${lines[0]}" "${lines[1]}" "Compilers: $compilers" "${lines[2]}"
  printf 'Archive: %s\n' "${sums[@]}"
)

normalize_include_root() {
  local token tokens out=() replaced=
  read -r -a tokens <<<"$1"
  for token in "${tokens[@]}"; do
    if [ -z "$replaced" ] && [[ $token == -I* && $token != -Inative ]]; then
      out+=("-I<includedir>")
      replaced=1
    else
      out+=("$token")
    fi
  done
  printf '%s' "${out[*]}"
}

# `record` and `build` run in subshells, so each one's EXIT trap removes its own scratch tree on every exit.
record() (
  local prefix=$1 pc target cflags core includedir roots libs sanitizer install line recorded scratch lineage
  local sources source headers
  local build=$prefix/share/spdk-sys/build.txt
  [ -f "$build" ] || die "$prefix holds no $build; only the controlled build writes a lineage"
  # The one Source line select.rs (lineage) requires of a record.
  sources=$(grep -c '^Source: ' "$build") || true
  [ "$sources" -eq 1 ] || die "$build names its Source $sources times; the controlled build writes one"
  source=$(grep '^Source: ' "$build")
  [[ $source == "Source: "?* ]] || die "$build names an empty Source"
  pc=$prefix/lib/pkgconfig
  target=$(uname -m)-unknown-linux-gnu
  read -r -a cflags <<<"$(PKG_CONFIG_PATH=$pc PKG_CONFIG_LIBDIR=$pc pkg-config --cflags libdpdk spdk_nvme spdk_env_dpdk)"
  core=$(printf '%s\n' "${cflags[@]}" | sed -n 's/^-m\(cpu\|arch\)=//p' | head -n 1)
  [ -n "$core" ] || die "the install's flags name no -mcpu or -march core"
  includedir=$(PKG_CONFIG_PATH=$pc PKG_CONFIG_LIBDIR=$pc pkg-config --variable=includedir libdpdk)
  # The include-root rule the readers apply: select.rs (include_root) and scripts/rust-lane.sh (native_identity).
  [ "${cflags[0]:-}" = "-I$includedir" ] \
    || die "the install's flags open with ${cflags[0]:-}, not its include root -I$includedir"
  roots=$(printf '%s\n' "${cflags[@]}" | grep -cxF -- "-I$includedir")
  [ "$roots" -eq 1 ] || die "the install's flags name its include root -I$includedir $roots times"
  libs=$(PKG_CONFIG_PATH=$pc PKG_CONFIG_LIBDIR=$pc pkg-config --static --libs libdpdk)
  sanitizer=
  [[ " $libs " != *" -lasan "* ]] || sanitizer=address
  install=src/generated/installs/$target-$core${sanitizer:+-asan}
  [ -f "$install" ] || die "no install record $install; run regenerate.sh against this install first"
  line="Target: $target.${sanitizer:+ Sanitizer: $sanitizer.} Flags: ${cflags[*]} -Inative"
  recorded=$(grep -m1 '^Target: ' "$install")
  [ "$(normalize_include_root "$recorded")" = "$(normalize_include_root "$line")" ] \
    || die "$install records \`$recorded\`, not this install's \`$line\`"
  # regenerate.sh rewrites a record whose headers changed, and drops its lineage, so the lineage lands on a record
  # whose Header digest is this install's.
  headers=$(native/header-digest.sh "$includedir" "${cflags[@]}")
  recorded=$(sed -n 's/^Header digest: //p' "$install" | head -n 1)
  [ "$recorded" = "$headers" ] \
    || die "$install records headers with digest ${recorded:-none}, and this install's headers digest $headers; run regenerate.sh against this install, then install.sh record $prefix"
  scratch=$(mktemp -d)
  trap 'rm -rf "$scratch"' EXIT
  lineage=$(measure "$prefix/lib" "$includedir" "$scratch")
  [ "$lineage" = "$(grep -v '^Source: ' "$build")" ] \
    || die "$prefix measures other than its controlled build recorded in $build"
  ! grep -qxE 'Build inputs: (unrecorded|stale)' <<<"$lineage" \
    || die "$prefix holds no build-inputs.txt naming every input this script names"
  # The complete record is assembled in scratch before the committed file is opened for writing.
  grep -v -E '^(Source|Patches|Build inputs|Compilers|Configure|Archive): ' "$install" > "$scratch/record"
  printf '%s\n' "$source" "$lineage" >> "$scratch/record"
  cat "$scratch/record" > "$install"
  echo "install.sh: wrote the lineage of $prefix to $install"
)

build() (
  local prefix=$1 tree spdk dpdk option
  shift
  # The build measures and records PREFIX, so the installation goes there and nowhere else.
  for option; do
    case $option in
      --prefix=*|--libdir=*) die "the configure option $option moves the installation away from PREFIX" ;;
    esac
  done
  # measure hashes every archive under PREFIX/lib, so the lineage describes this build alone when PREFIX starts empty.
  [ ! -e "$prefix" ] || [ -z "$(ls -A "$prefix")" ] \
    || die "$prefix is occupied; the controlled build installs into an empty PREFIX"
  tree=$(mktemp -d)
  trap 'rm -rf "$tree"' EXIT
  git clone --quiet "${SPDK_URL:-https://github.com/spdk/spdk}" "$tree/spdk"
  git -C "$tree/spdk" checkout --quiet "$SPDK_COMMIT"
  git -C "$tree/spdk" submodule update --quiet --init dpdk isa-l isa-l-crypto
  spdk=$(git -C "$tree/spdk" rev-parse HEAD)
  dpdk=$(git -C "$tree/spdk/dpdk" rev-parse HEAD)
  [ "$spdk" = "$SPDK_COMMIT" ] && [ "$dpdk" = "$DPDK_COMMIT" ] \
    || die "the tree holds SPDK $spdk and DPDK $dpdk, not $SPDK_COMMIT and $DPDK_COMMIT"
  for patch in $(cd native && LC_ALL=C; shopt -s nullglob; printf '%s\n' patches/*.patch); do
    git -C "$tree/spdk" apply --index "$PWD/native/$patch"
  done
  (cd "$tree/spdk" && ./configure "${CONFIGURE[@]}" "--prefix=$prefix" "$@" && make -j"$(nproc)" "${MAKE_VARIABLES[@]}" \
    && make install)
  mkdir -p "$prefix/share/spdk-sys"
  { printf 'configure %s\n' "${CONFIGURE[@]}" "--prefix=$prefix" "$@"
    printf 'make %s\n' "${MAKE_VARIABLES[@]}"
    printf 'cc %s\n' "$(${CC:-cc} --version | head -n 1)"
    printf 'env CC=%s CFLAGS=%s LDFLAGS=%s\n' "${CC:-}" "${CFLAGS:-}" "${LDFLAGS:-}"; } \
    > "$prefix/share/spdk-sys/build-inputs.txt"
  { echo "Source: SPDK $spdk DPDK $dpdk"
    measure "$prefix/lib" "$prefix/include" "$tree"; } > "$prefix/share/spdk-sys/build.txt"
  record "$prefix"
)

case "${1:-}" in
  build) [ $# -ge 2 ] || die "usage: install.sh build PREFIX [CONFIGURE_OPTION...]"; absolute "$2"; shift; build "$@" ;;
  record) [ $# -eq 2 ] || die "usage: install.sh record PREFIX"; absolute "$2"; record "$2" ;;
  measure) [ $# -eq 4 ] || die "usage: install.sh measure LIBDIR INCLUDEDIR DIR"; absolute "$2" "$3" "$4"; measure "$2" "$3" "$4" ;;
  normalize) shift; for line; do normalize_include_root "$line"; echo; done ;;
  *) die "usage: install.sh build PREFIX [CONFIGURE_OPTION...] | record PREFIX | measure LIBDIR INCLUDEDIR DIR | normalize LINE..." ;;
esac
