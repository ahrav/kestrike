#!/usr/bin/env bash
# Usage: bash scripts/tool.sh <tool> [argument ...]
set -euo pipefail

# The preparation runs in a command substitution, so none of its variables reaches the shell that execs the
# binary. It prints the path of the binary it built, under the top level, and nothing when it fails.

fail() {
  printf 'tool.sh: %s\n' "$1" >&2 || true
  exit 127
}

prepare() {
  local source directory top workflow pin host installed toolchain found cargo rustc name log
  local cleared=()
  source=${BASH_SOURCE[0]}
  while [[ -L $source ]]; do
    directory=$(CDPATH='' cd -P -- "$(dirname -- "$source")" && pwd -P) || fail "cannot find the top level"
    source=$(readlink -- "$source") || fail "cannot find the top level"
    [[ $source == /* ]] || source=$directory/$source
  done
  top=$(CDPATH='' cd -P -- "$(dirname -- "$source")/.." && pwd -P) || fail "cannot find the top level"
  workflow=$top/.github/workflows/agent-checks.yml
  pin=$(sed -n 's/^  STABLE: "\([^"]*\)"$/\1/p' "$workflow") || fail "cannot read $workflow"
  [[ $pin =~ ^[^[:space:]]+$ ]] || fail "$workflow pins no single STABLE toolchain"

  host=$(cd -- "$top" && env -u RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL=0 rustup show 2>/dev/null |
    sed -n 's/^Default host: //p') || true
  [[ $host =~ ^[^[:space:]/]+$ ]] || fail "rustup names no single host"
  installed=$(cd -- "$top" && env -u RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL=0 rustup toolchain list 2>/dev/null) ||
    fail "rustup lists no toolchains"
  found=
  while read -r toolchain _; do
    [[ $toolchain == "$pin-$host" ]] && found=yes
  done <<<"$installed"
  [[ -n $found ]] ||
    fail "the pinned toolchain $pin-$host is not installed; install it with: rustup toolchain install $pin"
  cargo=$(cd -- "$top" && env -u RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL=0 rustup which --toolchain "$pin" cargo 2>/dev/null) ||
    fail "the pinned toolchain $pin-$host has no cargo"
  rustc=$(dirname -- "$cargo")/rustc
  [[ -x $rustc ]] || fail "the pinned toolchain $pin-$host has no rustc"

  while IFS= read -r name; do
    case $name in
    CARGO_BUILD_JOBS) ;;
    RUSTFLAGS | CARGO_ENCODED_RUSTFLAGS | RUSTDOCFLAGS | CARGO_ENCODED_RUSTDOCFLAGS | RUSTDOC | \
      RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | CARGO_PROFILE_* | CARGO_BUILD_* | CARGO_TARGET_*)
      cleared+=(-u "$name")
      ;;
    esac
  done < <(compgen -e)

  if ! log=$(cd -- "$top" && env ${cleared[@]+"${cleared[@]}"} RUSTUP_TOOLCHAIN="$pin" RUSTUP_AUTO_INSTALL=0 \
    RUSTC="$rustc" "$cargo" build --quiet --package kestrike-tools \
    --bin kestrike-tools --target "$host" --target-dir "$top/target/tools" 2>&1); then
    printf '%s\n' "$log" >&2 || true
    fail "the build of kestrike-tools failed"
  fi
  printf '%s' "$top/target/tools/$host/debug/kestrike-tools"
}

set -- "$(prepare)" "$@"
[[ -n $1 ]] || exit 127
exec "$1" "${1%/target/tools/*/debug/kestrike-tools}" "${@:2}"
