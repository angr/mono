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

# And the fixtures beside them. Most suites resolve `binaries` by walking up
# from a path they realpath first, which lands in the checkout and is fine --
# but angr/tests is a package, so pytest imports it through the symlink and
# `__file__` stays inside the run directory. `test_irsb.py` walks that
# lexically, looks for `.ci-run/binaries/tests/...`, and finding nothing
# sub-skips all six architectures inside a test that then reports PASSED.
# ci/run-native.py already links this for its own run directory.
ln -sfn -- "$root/binaries" "$run_dir/../binaries"

# Some suites resolve checked-in fixtures relative to their own directory --
# angr-platforms reads `<tests>/../test_programs` for its precompiled eBPF,
# BF and msp430 objects. A run directory holding only `tests` makes those
# tests fail with "Not a valid binary file", which reads as a real break and
# is not one. Named per suite in ci/suites.json rather than guessed.
while read -r fixture; do
    [[ -z $fixture ]] && continue
    # A name inside the component, not a route out of it: `..` or a leading
    # slash would link something from outside the suite's own tree into a run
    # directory whose whole point is holding nothing else.
    case $fixture in
        /* | *..*)
            echo "$suite: fixture must be a path inside the component: $fixture" >&2
            exit 1
            ;;
    esac
    [[ -e $root/$suite/$fixture ]] || {
        echo "$suite: no such fixture directory: $suite/$fixture" >&2
        exit 1
    }
    ln -sfn -- "$root/$suite/$fixture" "$run_dir/$fixture"
done < <(python3 -c "
import json
suite = json.load(open('$root/ci/suites.json'))['suites']['$suite']
print('\n'.join(suite.get('fixtures') or []))
")

# angr writes LMDB stores for its type and function database; keep them out
# of the checkout so a test run never dirties the tree.
# Removed first: a forked worker killed by the timeout never runs the parent's
# atexit hook, so its LMDB directory is left behind. 698 of them and 3 GB had
# accumulated locally, on a runner that has about 20 GB after the store.
export RTDB_BASE=$results/rtdb
export PYTHONDONTWRITEBYTECODE=1
rm -rf -- "$RTDB_BASE"
mkdir -p -- "$RTDB_BASE"

# angr's tests skip their "is angr/binaries beside me" check when in CI. The
# fixtures are linked above, so the check would pass anyway -- which was true
# of `bin_location` and not of the run-dir-relative path above, the one case
# the guard would have caught.
export CI=true

# No core files. angr's tests/utils/test_mp_stdio.py is a regression test for
# CPython aborting at interpreter shutdown when a forked child inherits a
# held stdin lock -- the abort is the behaviour under test -- and it drops
# three cores of about 250 MB every run of the suite. They were investigated
# on the suspicion that a forked child was crashing after reporting its
# result, which pytest-forked cannot see; bisecting the test directories put
# all three in that one file, and removing it removes them. So they are
# deliberate, and what they cost is disk on a runner that has ~20 GB for a
# store several of those wide.
# -S, the soft limit only. Plain `ulimit -c 0` sets the hard limit too, and a
# hard limit cannot be raised again by an unprivileged process -- which broke
# all six of tracer's tests: qemu_runner.py raises RLIMIT_CORE to infinity in
# a preexec_fn, because a core file is how it detects that the traced program
# crashed, and it got EPERM and a dead child instead. The soft limit still
# stops the deliberate dumps above, and lets anything that genuinely needs
# cores ask for them back.
ulimit -S -c 0 || true

if (( qt )); then
    export QT_QPA_PLATFORM=${QT_QPA_PLATFORM:-minimal:enable_fonts}
fi

in_env() { nix develop "$root#$env" --command "$@"; }

# The package under test must come from the Nix store, not from this tree.
# Every component's import name is its directory name without the dash --
# except angr-platforms, which is `angr_platforms`, so ci/suites.json can say
# so rather than have the rule grow a special case.
module=$(python3 -c "
import json
suite = json.load(open('$root/ci/suites.json'))['suites']['$suite']
print(suite.get('module') or '$suite'.replace('-', ''))
")
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
      --rootdir="$run_dir" --junitxml="$results/$suite-nix-$shard.xml"
      -o junit_family=legacy --durations=25)
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
# Named exclusions, out loud. A suite here runs everything a component
# ships, so the one test that cannot pass is enumerated in ci/suites.json
# with its reason, printed on every run, and counted in the summary -- not
# dropped by a `-k` nobody reads, and not left to report as a skip, which is
# the failure mode this repository exists to avoid.
# Into a variable first, not `while read < <(python3 ...)`: a crash inside a
# process substitution is invisible to `set -e`, so a malformed `excluded`
# would have been read as EOF and applied zero exclusions silently -- the
# same shape of bug as the tee pipe above.
if ! exclusions=$(python3 -c "
import json, sys
sys.path.insert(0, '$root/ci')
from exclusions import for_platform
suite = json.load(open('$root/ci/suites.json'))['suites']['$suite']
for test, reason in for_platform(suite, '$suite'):
    print(test)
    print(reason)
"); then
    echo "$suite: could not read the exclusion list; refusing to run a suite" \
         "whose exclusions are unknown." >&2
    exit 1
fi
exclusion_report=()
while read -r test && read -r reason; do
    exclusion_report+=("$suite: EXCLUDED $test" "    $reason")
    args+=(--deselect "$test")
done <<<"$exclusions"

if [[ -n $pytest_args ]]; then
    read -ra extra <<<"$pytest_args"
    args+=("${extra[@]}")
fi

log=$results/$suite-nix-$shard.log
echo "=== $suite ${shard}/${of}: python3 ${args[*]}" | tee "$log"
# After the log exists, not before: printed earlier, the one thing that says
# a test was deliberately not run went only to the console, and the console
# is not what the run uploads.
for line in "${exclusion_report[@]}"; do
    echo "$line" | tee -a "$log"
done
start=$SECONDS
# `|| rc=${PIPESTATUS[0]}` looks like it reports the suite, and does when
# pytest is what failed -- but when only `tee` fails the pipeline is non-zero,
# the `||` fires, and PIPESTATUS[0] is pytest's 0. A suite whose log could not
# be written reported green. Read both ends, and let either one fail the run.
set +e
(cd -- "$run_dir" && in_env python3 "${args[@]}") 2>&1 | tee -a "$log"
pipe=("${PIPESTATUS[@]}")
set -e
rc=${pipe[0]}
if (( pipe[1] != 0 )); then
    echo "tee failed writing $log (exit ${pipe[1]})" >&2
    (( rc == 0 )) && rc=${pipe[1]}
fi
echo "=== $suite ${shard}/${of} done: exit=$rc wall=$(( SECONDS - start ))s" | tee -a "$log"
exit "$rc"
