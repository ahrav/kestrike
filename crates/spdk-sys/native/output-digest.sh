#!/usr/bin/env bash
# Usage: output-digest.sh <output directory>
set -euo pipefail
cd "$1"
sum=$(sha256sum bindings.rs layout.inc layout_table.rs | sha256sum)
echo "${sum:0:16}"
