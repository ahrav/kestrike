#!/usr/bin/env bash
# Prints the SHA-256 digest of every install header native/bindings.h
# includes, in byte-sorted path order, each as "<path relative to includedir>\0<bytes>".
# Usage: header-digest.sh <includedir> <cflags...>
#
# Each header's name record is a file in a scratch directory, so one cat
# process streams every record and its header in order.
set -euo pipefail
export LC_ALL=C
cd "$(dirname "$0")"
includedir=$1
shift
list=$(cc "$@" -I. -M -MT x bindings.h | tr ' \\' '\n\n' | grep "^$includedir/" | sort -u)
mapfile -t headers <<<"$list"
names=$(mktemp -d)
trap 'rm -rf "$names"' EXIT
files=()
for i in "${!headers[@]}"; do
  printf '%s\0' "${headers[i]#"$includedir"/}" >"$names/$i"
  files+=("$names/$i" "${headers[i]}")
done
sum=$(cat "${files[@]}" | sha256sum)
echo "${sum%% *}"
