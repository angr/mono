#!/usr/bin/env bash
#
# Run one CI matrix entry: every suite it names, at the given shard.
#
#   ci/run-job.sh "archinfo pyvex pypcode claripy cle"
#   ci/run-job.sh angr --shard 3 --of 10
#
# A failing suite does not stop the others -- one job reporting one failure
# when three suites broke is a second round trip nobody needs.

set -uo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
suites=${1:?which suites?}
shift

failed=()
for suite in $suites; do
    if ! "$root/ci/run-suite.sh" "$suite" "$@"; then
        failed+=("$suite")
    fi
done

if (( ${#failed[@]} )); then
    echo "Failed: ${failed[*]}" >&2
    exit 1
fi
