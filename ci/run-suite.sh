#!/usr/bin/env bash
#
# Run one component's own test suite against the Nix-built packages.
#
#   ci/run-suite.sh angr
#   ci/run-suite.sh angr --shard 3 --of 10
#   ci/run-suite.sh cle --workers 4 --pytest-args "-k elf -x"
#
# Options:
#   --shard N --of M   run pytest-split group N of M (default: the whole suite)
#   --workers N        xdist workers (default: the suite's setting, usually auto)
#   --results DIR      junit xml and log land here (default: test-results/)
#   --timeout SECONDS  per-test timeout (default 1800; 0 disables)
#   --pytest-args ARGS extra pytest arguments, word-split
#   --store-durations  record per-test timings into ci/durations/<suite>.json
#
# The suite runs from a directory that holds nothing but a symlink to the
# component's tests, because the component's *source* directory sits next to
# them in this tree and pytest would otherwise put it on sys.path -- importing
# a pure-Python `angr/` with no compiled rustylib in it instead of the package
# Nix built. The script checks where the import actually resolved and refuses
# to run a suite that is testing the source tree by accident.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
suite=
shard=1
of=1
workers=
results=$root/test-results
timeout_s=1800
pytest_args=
store_durations=0

usage() { sed -n '2,/^$/{s/^# \{0,1\}//p}' "${BASH_SOURCE[0]}"; }

while (( $# > 0 )); do
    case $1 in
        --help|-h) usage; exit 0 ;;
        --store-durations) store_durations=1; shift ;;
        --shard|--of|--workers|--results|--timeout|--pytest-args)
            (( $# >= 2 )) || { echo "$1 requires a value." >&2; exit 2; }
            case $1 in
                --shard) shard=$2 ;;
                --of) of=$2 ;;
                --workers) workers=$2 ;;
                --results) results=$2 ;;
                --timeout) timeout_s=$2 ;;
                --pytest-args) pytest_args=$2 ;;
            esac
            shift 2 ;;
        -*) echo "Unknown option: $1" >&2; usage >&2; exit 2 ;;
        *)  [[ -z $suite ]] || { echo "One suite at a time: $suite, $1" >&2; exit 2; }
            suite=$1; shift ;;
    esac
done

if [[ -z $suite ]]; then
    echo "Which suite? One of: $(python3 -c "
import json
print(' '.join(json.load(open('$root/ci/suites.json'))['suites']))
")" >&2
    exit 2
fi

# One line of unit-separated fields: a marker expression contains spaces,
# and an absent one is an empty field, which `read` would swallow if the
# separator were whitespace.
config=$(python3 - "$root/ci/suites.json" "$suite" <<'PY'
import json, sys

config = json.load(open(sys.argv[1]))
suite = config["suites"].get(sys.argv[2])
if suite is None:
    sys.exit(f"unknown suite: {sys.argv[2]}")
print("\x1f".join((
    suite.get("env", "test"),
    "1" if suite.get("forked") else "0",
    str(suite.get("workers", "auto")),
    "1" if suite.get("qt") else "0",
)))
PY
)
IFS=$'\x1f' read -r env forked cfg_workers qt <<<"$config"
workers=${workers:-$cfg_workers}

if [[ ! -d $root/$suite/tests ]]; then
    echo "No tests directory: $root/$suite/tests" >&2
    exit 2
fi
if [[ ! -e $root/binaries ]]; then
    "$root/ci/link-external.sh"
fi

# A neutral working directory: only the tests are visible from it.
run_dir=$root/.ci-run/$suite
rm -rf -- "$run_dir"
mkdir -p -- "$run_dir" "$results"
ln -sfn -- "$root/$suite/tests" "$run_dir/tests"

# angr writes LMDB stores for its type and function database; keep them out
# of the checkout so a test run never dirties the tree.
export RTDB_BASE=$results/rtdb
export PYTHONDONTWRITEBYTECODE=1
mkdir -p -- "$RTDB_BASE"

# angr's tests skip their "is angr/binaries beside me" check when in CI. The
# fixtures are linked above, so the check would pass anyway.
export CI=true

if (( qt )); then
    export QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-minimal:enable_fonts}
fi

in_env() { nix develop "$root#$env" --command "$@"; }

# The package under test must come from the Nix store, not from this tree.
# Every component's import name is its directory name without the dash.
module=${suite//-/}
if ! origin=$(cd -- "$run_dir" && in_env python3 -c "
import importlib, os
print(os.path.realpath(os.path.dirname(importlib.import_module('$module').__file__)))
"); then
    echo "$suite: cannot import $module in the '$env' environment (see above)." >&2
    exit 1
fi
case $origin in
    "$root"/*)
        echo "$suite: $module imported from the source tree ($origin), not the package Nix built." >&2
        exit 1
        ;;
    /nix/store/*) ;;
    *)
        echo "$suite: $module imported from an unexpected place ($origin)." >&2
        exit 1
        ;;
esac
echo "$suite: testing $module from $origin"

args=(-m pytest tests -p no:cacheprovider -q -rfEs -o addopts=
      --rootdir="$run_dir" --junitxml="$results/$suite-$shard.xml" --durations=25)
if [[ $workers != 0 && $workers != 1 ]]; then
    args+=(-n "$workers")
fi
if (( forked )); then
    # As upstream CI does: each test in its own process, so a file whose tests
    # each hold gigabytes does not accumulate them in one worker.
    args+=(--forked)
fi
if (( timeout_s > 0 )); then
    args+=(--timeout="$timeout_s" --timeout-method=thread)
fi

durations=$root/ci/durations/$suite.json
if (( store_durations )); then
    mkdir -p -- "$(dirname -- "$durations")"
    args+=(--store-durations --durations-path "$durations" --clean-durations)
elif (( of > 1 )); then
    args+=(--splits "$of" --group "$shard")
    if [[ -f $durations ]]; then
        args+=(--durations-path "$durations")
    fi
fi
if [[ -n $pytest_args ]]; then
    read -ra extra <<<"$pytest_args"
    args+=("${extra[@]}")
fi

log=$results/$suite-$shard.log
echo "=== $suite ${shard}/${of}: python3 ${args[*]}" | tee "$log"
start=$SECONDS
rc=0
(cd -- "$run_dir" && in_env python3 "${args[@]}") 2>&1 | tee -a "$log" || rc=${PIPESTATUS[0]}
echo "=== $suite ${shard}/${of} done: exit=$rc wall=$(( SECONDS - start ))s" | tee -a "$log"
exit "$rc"
