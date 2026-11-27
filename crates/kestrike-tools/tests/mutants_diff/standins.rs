//! The POSIX `sh` programs that stand in for `cargo` and `git`.
//!
//! The `cargo` stand-in answers `-vV` and `mutants --version` from the plan directory, records every other
//! call in `calls` and answers a listing or a run with the files the plan holds for its shard: `list`,
//! `outcomes` and `at-hang`, with the suffix `-K-N` under `--shard K/N`. A call record is a sequence of fields,
//! each ended by a NUL byte: `call`, the argument count, the arguments, the working directory, then for each
//! name of [`RECORDED`] and for the `--in-diff` file's digest, the configuration's digest and the
//! `Cargo.lock` text, `S` and the value when it is set and `U` when it is not.

/// The variables a call record holds, in its order.
pub const RECORDED: [&str; 8] = [
    "CARGO_TARGET_DIR",
    "CARGO_BUILD_BUILD_DIR",
    "RUSTUP_TOOLCHAIN",
    "CARGO_PROFILE_DEV_OPT_LEVEL",
    "CARGO_PROFILE_DEV_DEBUG",
    "RUSTFLAGS",
    "CARGO_HOME",
    "RUSTUP_HOME",
];

/// The argument of every sleeper the stand-ins start, which names it in `/proc/<pid>/cmdline`.
pub const SLEEPER: &str = "600.125";

pub const CARGO: &str = r#"#!/bin/sh
state=$FAKE_STATE
plan=$state/plan
sleeper=600.125
publish() { printf '%s' "$2" > "$state/$1.tmp" && mv "$state/$1.tmp" "$state/$1"; }
if [ "$#" -eq 1 ] && [ "$1" = -vV ]; then
  printf 'cargo 1.99.0 (5f94df478 2026-08-27)\nrelease: 1.99.0\nhost: %s\n' "$(cat "$plan/host")"
  exit 0
fi
if [ "$#" -eq 2 ] && [ "$1" = mutants ] && [ "$2" = --version ]; then
  if [ -e "$plan/absent" ]; then
    echo 'error: no such command: `mutants`' >&2
    exit 101
  fi
  printf 'cargo-mutants %s\n' "$(cat "$plan/version")"
  exit 0
fi
value() {
  flag=$1
  shift
  while [ "$#" -gt 1 ]; do
    if [ "$1" = "$flag" ]; then
      printf '%s' "$2"
      return 0
    fi
    shift
  done
  return 1
}
listing=no
for arg; do
  if [ "$arg" = --list ]; then listing=yes; fi
done
suffix=
if shard=$(value --shard "$@"); then suffix="-${shard%%/*}-${shard#*/}"; fi
record=$state/record.tmp
: > "$record"
field() { printf '%s\0' "$1" >> "$record"; }
field call
field "$#"
for arg; do field "$arg"; done
field "$(pwd -P)"
for name in CARGO_TARGET_DIR CARGO_BUILD_BUILD_DIR RUSTUP_TOOLCHAIN CARGO_PROFILE_DEV_OPT_LEVEL \
  CARGO_PROFILE_DEV_DEBUG RUSTFLAGS CARGO_HOME RUSTUP_HOME; do
  if eval "[ \"\${$name+set}\" = set ]"; then eval "field \"S\$$name\""; else field U; fi
done
digest() {
  if [ -f "$1" ]; then field "S$(sha256sum < "$1" | cut -c1-64)"; else field U; fi
}
if diff=$(value --in-diff "$@"); then digest "$diff"; else field U; fi
digest .cargo/mutants.toml
if [ -f Cargo.lock ]; then { printf S; cat Cargo.lock; printf '\0'; } >> "$record"; else field U; fi
cat "$record" >> "$state/calls"
rm -f "$record"
terminate() {
  if [ -e "$plan/hold" ]; then
    publish terminating 15
    i=0
    while [ "$i" -lt 50 ] && [ ! -e "$state/release" ]; do
      sleep 0.1
      i=$((i + 1))
    done
  fi
  kill "$grandchild" "$idle" 2>/dev/null
  wait "$grandchild"
  publish terminated 15
  exit 1
}
hang() {
  setsid sleep "$sleeper" &
  grandchild=$!
  sleep "$sleeper" &
  idle=$!
  trap terminate TERM
  if [ -f crates/kestrike/src/lib.rs ]; then echo '// mutated in place' >> crates/kestrike/src/lib.rs; fi
  publish grandchild.pid "$grandchild"
  publish ready "$$"
  wait "$idle"
  exit 0
}
if [ "$listing" = yes ]; then
  if [ -e "$plan/list_exit" ]; then exit "$(cat "$plan/list_exit")"; fi
  if [ -e "$plan/list_hang" ]; then hang; fi
  if [ -e "$plan/raw_listing" ]; then
    cat "$plan/raw_listing"
  elif [ -e "$plan/list$suffix" ]; then
    cat "$plan/list$suffix"
  fi
  exit 0
fi
code=$(cat "$plan/exit")
if [ -e "$plan/drop_git" ]; then rm .git; fi
if [ -e "$plan/stray" ]; then
  sleep "$sleeper" &
  printf '%s' "$!" > "$state/grandchild.pid"
fi
out=$(value --output "$@")/mutants.out
mkdir -p "$out"
if [ -e "$plan/raw_outcomes" ]; then
  cp "$plan/raw_outcomes" "$out/outcomes.json"
  exit "$code"
fi
if [ -e "$plan/hang" ] && [ -e "$plan/at-hang$suffix" ]; then
  cp "$plan/at-hang$suffix" "$out/outcomes.json"
  hang
fi
if [ ! -e "$plan/no_outcomes" ]; then cp "$plan/outcomes$suffix" "$out/outcomes.json"; fi
exit "$code"
"#;

/// `GIT` runs the real Git named in place of `__REAL__`, or in the mode `FAKE_GIT_MODE` names: `fail-add`
/// exits 3 on a worktree add, `fail-remove` refuses a worktree removal with `fatal: refused`, `hang-add`
/// adds a locked worktree, publishes `ready` and sleeps, and `bad-rev` and `bad-base` make a successful
/// `rev-parse --verify` or `merge-base` print the byte 0xff and a line feed.
pub const GIT: &str = r#"#!/bin/sh
real=__REAL__
state=$FAKE_STATE
mode=${FAKE_GIT_MODE-}
has() {
  want=$1
  shift
  for arg; do
    if [ "$arg" = "$want" ]; then return 0; fi
  done
  return 1
}
if has worktree "$@" && has add "$@" && [ "$mode" = fail-add ]; then exit 3; fi
if { has rev-parse "$@" && has --verify "$@" && [ "$mode" = bad-rev ]; } ||
  { has merge-base "$@" && [ "$mode" = bad-base ]; }; then
  printf '\377\n'
  exit 0
fi
if has worktree "$@" && has remove "$@" && [ "$mode" = fail-remove ]; then
  echo 'fatal: refused' >&2
  exit 1
fi
if has worktree "$@" && has add "$@" && [ "$mode" = hang-add ]; then
  added=
  for arg; do
    shift
    set -- "$@" "$arg"
    if [ -z "$added" ] && [ "$arg" = add ]; then
      set -- "$@" --lock
      added=1
    fi
  done
  "$real" "$@" || exit 1
  printf '%s' "$$" > "$state/ready.tmp" && mv "$state/ready.tmp" "$state/ready"
  exec sleep 600.125
fi
exec "$real" "$@"
"#;
