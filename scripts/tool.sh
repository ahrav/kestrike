#!/usr/bin/env bash
# Usage: bash scripts/tool.sh <tool> [argument ...]
set -euo pipefail

# The preparation runs in a command substitution: its variables, its working directory and the environment
# it gives rustup and Cargo stay in that subshell, and the shell that execs the binary keeps the caller's.
# Its last step prints the path of the binary it built, under the top level; a failure exits before that
# step and writes its reason to standard error.

fail() {
  printf 'tool.sh: %s\n' "$1" >&2 || true
  exit 127
}

prepare() {
  local source directory top workflow line value at pin='' pins=0 rustup shown host='' installed toolchain found
  local cargo rustc wrapper name log
  local chunks=() fields=() lines=()
  source=${BASH_SOURCE[0]}
  [[ $source == */* ]] || source=./$source
  while [[ -L $source ]]; do
    directory=$(CDPATH='' cd -P -- "${source%/*}" && pwd -P && printf x) || fail "cannot find the top level"
    directory=${directory%$'\nx'}
    source=$(readlink -- "$source" && printf x) || fail "cannot find the top level"
    source=${source%$'\nx'}
    [[ $source == /* ]] || source=$directory/$source
  done
  [[ $source == */* ]] || source=./$source

  # rustup and Cargo run in the top level. Before changing to it, the preparation resolves a relative
  # RUSTUP_HOME and CARGO_HOME, and finds `rustup` on PATH, in the caller's directory.
  [[ -z ${RUSTUP_HOME-} || $RUSTUP_HOME == /* ]] || export RUSTUP_HOME=$PWD/$RUSTUP_HOME
  [[ -z ${CARGO_HOME-} || $CARGO_HOME == /* ]] || export CARGO_HOME=$PWD/$CARGO_HOME
  rustup=
  ! hash rustup 2>/dev/null || rustup=${BASH_CMDS[rustup]}
  [[ -z $rustup || $rustup == /* ]] || rustup=$PWD/$rustup
  CDPATH='' cd -P -- "${source%/*}/.." || fail "cannot find the top level"
  top=$PWD

  # After optional leading spaces and tabs, `STABLE: "` introduces a pin: the nonempty text before the next
  # `"` on the same line. A line ends at a line feed or a carriage return. The text is split at each `"`, so
  # a pin is the field after one that ends in a line's blanks and `STABLE: `. Each NUL byte reads as the
  # byte 0x02, which a bash string can hold; the parser treats both bytes as ordinary text. The 0x02 that
  # ends the text puts a field after every quote.
  workflow=$top/.github/workflows/agent-checks.yml
  [[ -f $workflow ]] || fail "$workflow is not a regular file"
  { mapfile -d '' chunks || true; } 2>/dev/null <"$workflow" || fail "cannot read $workflow"
  printf -v value '%s\2' ${chunks[@]+"${chunks[@]}"}
  set -f
  IFS='"'
  fields=($value)
  for ((at = 0; at + 2 < ${#fields[@]}; at++)); do
    line=${fields[at]}
    [[ $line == *'STABLE: ' ]] || continue
    line=${line%'STABLE: '}
    if [[ $line == *[$'\n\r']* ]]; then
      IFS=$'\n\r'
      lines=($line$'\2')
      line=${lines[-1]%$'\2'}
    elif ((at > 0)); then
      continue
    fi
    value=${fields[at + 1]}
    [[ $line != *[!$' \t']* && -n $value && $value != *[$'\n\r']* ]] || continue
    pin=$value
    pins=$((pins + 1))
  done
  IFS=$' \t\n'
  set +f
  ((pins == 1)) && [[ $pin =~ ^[^[:space:]]+$ ]] || fail "$workflow pins no single STABLE toolchain"

  [[ -n $rustup ]] || fail "rustup names no single host"
  unset RUSTUP_TOOLCHAIN
  export RUSTUP_AUTO_INSTALL=0

  shown=$("$rustup" show 2>/dev/null) || true
  mapfile -t lines <<<"$shown"
  for line in "${lines[@]}"; do
    [[ $line != 'Default host: '* ]] || host+=${host:+$'\n'}${line#'Default host: '}
  done
  [[ $host =~ ^[^[:space:]/]+$ ]] || fail "rustup names no single host"
  installed=$("$rustup" toolchain list 2>/dev/null) || fail "rustup lists no toolchains"
  found=
  while read -r toolchain _; do
    [[ $toolchain == "$pin-$host" ]] && found=yes
  done <<<"$installed"
  [[ -n $found ]] ||
    fail "the pinned toolchain $pin-$host is not installed; install it with: rustup toolchain install $pin"
  cargo=$("$rustup" which --toolchain "$pin" cargo 2>/dev/null) || fail "the pinned toolchain $pin-$host has no cargo"
  rustc=${cargo%/*}/rustc
  [[ -x $rustc ]] || fail "the pinned toolchain $pin-$host has no rustc"
  # Both wrappers outrank one that a Cargo configuration file names. Cargo keeps its cache of rustc's
  # answers in `target/tools/.rustc_info.json` only for a wrapper that is a file, so the wrapper is
  # `/usr/bin/env`, which starts rustc with the same arguments and environment. The empty value, which
  # Cargo reads as no wrapper, stands where that file is no executable or the rustc path holds a `=`,
  # which `env` would read as an assignment.
  wrapper=
  [[ ! -f /usr/bin/env || ! -x /usr/bin/env || $rustc == *=* ]] || wrapper=/usr/bin/env

  for name in "${!CARGO_PROFILE_@}" "${!CARGO_BUILD_@}" "${!CARGO_TARGET_@}"; do
    [[ $name == CARGO_BUILD_JOBS ]] || unset "$name"
  done
  unset RUSTFLAGS CARGO_ENCODED_RUSTFLAGS RUSTDOCFLAGS CARGO_ENCODED_RUSTDOCFLAGS RUSTDOC
  if ! log=$(RUSTUP_TOOLCHAIN=$pin RUSTC=$rustc RUSTC_WRAPPER=$wrapper RUSTC_WORKSPACE_WRAPPER=$wrapper \
    CARGO_BUILD_BUILD_DIR=target/tools "$cargo" build --quiet --package kestrike-tools --bin kestrike-tools \
    --target "$host" --target-dir "$top/target/tools" 2>&1); then
    printf '%s\n' "$log" >&2 || true
    fail "the build of kestrike-tools failed"
  fi
  printf '%s' "$top/target/tools/$host/debug/kestrike-tools"
}

set -- "$(prepare)" "$@"
[[ -n $1 ]] || exit 127
exec "$1" "${1%/target/tools/*/debug/kestrike-tools}" "${@:2}"
