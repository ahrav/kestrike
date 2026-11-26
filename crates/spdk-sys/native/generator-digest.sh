#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
sum=$(sha256sum regenerate.sh native/bindings.h native/shim.h native/layout_table.py native/macro_closure.py | sha256sum)
echo "${sum%% *}"
