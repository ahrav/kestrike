#!/usr/bin/env bash
# Usage: bash scripts/ci-scan-weakened-tests.sh --base BASE [--head HEAD]
#
# Run from the repository root so Bash can resolve `scripts/tool.sh`. The wrapper suspends workflow command
# processing so the runner treats the scan's output as data, and it keeps the resume token out of the scan's
# environment. The scan's standard error joins its standard output, so the runner reads every line of the
# scan between the stop line and the resume line.
set -euo pipefail

unset -v token
token=$(od -An -N16 -tx1 /dev/urandom | tr -d ' \n')
if [[ ! $token =~ ^[0-9a-f]{32}$ ]]; then
  printf 'ci-scan-weakened-tests.sh: the random source gave no token of 32 hex digits\n' >&2
  exit 1
fi
printf '::stop-commands::%s\n' "$token"
status=0
bash scripts/tool.sh scan-weakened-tests "$@" 2>&1 || status=$?
printf '::%s::\n' "$token"
exit "$status"
