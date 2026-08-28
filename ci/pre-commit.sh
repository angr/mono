#!/usr/bin/env bash
#
# Run one component's own pre-commit hooks, as its own repository.
#
#   ci/pre-commit.sh archinfo
#
# pre-commit resolves every path relative to the git root, not to the working
# directory, and the configs are written for a repository whose root is the
# component. Run it from here and both halves break: `--all-files` walks the
# whole tree, so archinfo's hooks stop on a Python 2 print statement in
# angr-platforms; and pypcode's `exclude: ^pypcode/sleigh` stops matching
# `pypcode/pypcode/sleigh`, so clang-format reformats several thousand
# vendored Ghidra sources.
#
# So the component is extracted into a scratch repository where it *is* the
# root, and the hooks run there against exactly the files upstream would see.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
component=${1:?which component?}

if [[ ! -f $root/$component/.pre-commit-config.yaml ]]; then
    echo "$component ships no .pre-commit-config.yaml." >&2
    exit 2
fi

work=$(mktemp -d)
trap 'rm -rf -- "$work"' EXIT

# Tracked files only, and only this component's.
git -C "$root" archive HEAD "$component" | tar -x -C "$work" --strip-components=1

git -C "$work" init --quiet
git -C "$work" add -A
git -C "$work" -c user.email=ci@example.com -c user.name=ci \
    commit --quiet --message "pre-commit scratch"

# pypcode's config carries `ci: skip: [pylint]`, so pre-commit.ci -- the
# thing that actually reports on upstream pull requests -- does not run it,
# and its `local` hook needs pylint on PATH besides. pylint is the ratchets
# lane's job here.
cd -- "$work"
SKIP=${SKIP:-pylint} pre-commit run --all-files --show-diff-on-failure
