#!/bin/bash
# Runs a command; if it fails, its error lines and the end of its output
# become annotations on the run (visible on the run's page and through the
# API without downloading logs).
#
#   .github/annotate.sh <command> [args…]
set -uo pipefail
log=$(mktemp)
"$@" 2>&1 | tee "$log"
status=${PIPESTATUS[0]}
if [ "$status" -ne 0 ]; then
    grep -E "error(\[E[0-9]+\])?:|error:|Error:|FAILED|panicked" "$log" | grep -v "^warning" | head -10 | while IFS= read -r line; do
        echo "::error::${line//%/%25}"
    done
    tail -60 "$log" | sed 's/%/%25/g' | awk 'BEGIN{ORS="%0A"} {print}' | sed 's/^/::error title=Output tail::/'
    echo
fi
exit "$status"
