#!/usr/bin/env bash
# Usage: bash scripts/tool.sh <tool> [argument ...]
set -euo pipefail

fail() {
  printf 'tool.sh: %s\n' "$1" >&2
  exit 127
}

top=$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P) || fail "cannot find the top level"
workflow=$top/.github/workflows/agent-checks.yml
pin=$(sed -n 's/^  STABLE: "\([^"]*\)"$/\1/p' "$workflow") || fail "cannot read $workflow"
[[ $pin =~ ^[^[:space:]]+$ ]] || fail "$workflow pins no single STABLE toolchain"

host=$(cd -- "$top" && env -u RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL=0 rustup show 2>/dev/null |
  sed -n 's/^Default host: //p') || true
[[ -n $host ]] || fail "rustup names no host"
installed=$(cd -- "$top" && env -u RUSTUP_TOOLCHAIN RUSTUP_AUTO_INSTALL=0 rustup toolchain list 2>/dev/null) ||
  fail "rustup lists no toolchains"
grep -qE "^${pin//./\\.}-${host}( |\$)" <<<"$installed" ||
  fail "the pinned toolchain $pin-$host is not installed; install it with: rustup toolchain install $pin"

cleared=()
while IFS= read -r name; do
  case $name in
  CARGO_BUILD_JOBS) ;;
  RUSTFLAGS | CARGO_ENCODED_RUSTFLAGS | RUSTDOCFLAGS | CARGO_ENCODED_RUSTDOCFLAGS | RUSTC | RUSTDOC | \
    RUSTC_WRAPPER | RUSTC_WORKSPACE_WRAPPER | CARGO_PROFILE_* | CARGO_BUILD_* | CARGO_TARGET_*)
    cleared+=(-u "$name")
    ;;
  esac
done < <(compgen -e)

if ! log=$(cd -- "$top" && env "${cleared[@]}" RUSTUP_TOOLCHAIN="$pin" RUSTUP_AUTO_INSTALL=0 \
  cargo build --quiet --package kestrike-tools --bin kestrike-tools --target-dir "$top/target/tools" 2>&1); then
  printf '%s\n' "$log" >&2
  fail "the build of kestrike-tools failed"
fi
exec "$top/target/tools/debug/kestrike-tools" "$top" "$@"
