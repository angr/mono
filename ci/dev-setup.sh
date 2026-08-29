#!/usr/bin/env bash
#
# Make the source tree the thing that runs.
#
#   ci/dev-setup.sh
#   nix develop --command ci/run-suite.sh cle   # now testing your edits
#
# Nix builds each component into the store, which is what CI should test and
# exactly what you do not want while working: a one-line change means a
# rebuild before it runs. This installs every component into a .venv as an
# editable, so a Python edit takes effect on the next import and a native edit
# takes a rebuild of that component alone.
#
# The venv inherits the Nix environment's site-packages for third-party
# dependencies, and its own site-packages comes first on sys.path, so the
# editable components shadow the built ones.
#
# After changing native code -- angr's Rust extension, pyvex's or pypcode's
# CMake build -- re-run this script (or `pip install` that one component) to
# rebuild it.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
venv=$root/.venv

# Dependency order: a component's build imports the ones under it -- angr's
# unicornlib compiles against pyvex's headers.
components=(archinfo pyvex pypcode claripy cle angr angr-management)

nix develop "$root" --command bash -euo pipefail -c '
    root=$1
    venv=$2
    shift 2

    # The venv inherits site-packages from the interpreter that made it, so it
    # is bound to one revision of the dev environment. Rebuild it when that
    # moves, or a dependency added to the flake stays invisible here.
    stamp=$venv/.dev-env
    env_path=$(python3 -c "import sys; print(sys.base_prefix)")
    if [[ ! -x $venv/bin/python || $(cat -- "$stamp" 2>/dev/null) != "$env_path" ]]; then
        rm -rf -- "$venv"
        python3 -m venv --system-site-packages "$venv"
        printf "%s\n" "$env_path" > "$stamp"
    fi
    # `pip install -e A B C` makes only A editable; every path needs its own.
    args=()
    for component; do
        args+=(--editable "$root/$component")
    done
    "$venv/bin/pip" install --disable-pip-version-check --no-input \
        --no-build-isolation --no-deps "${args[@]}"
' _ "$root" "$venv" "${components[@]}"

echo
echo "Editable in $venv:"
"$venv/bin/python" - <<'PY'
import importlib

for name in ("archinfo", "pyvex", "pypcode", "claripy", "cle", "angr", "angrmanagement"):
    module = importlib.import_module(name)
    print(f"  {name:16} {module.__file__}")
PY
