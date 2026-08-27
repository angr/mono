#!/usr/bin/env bash
#
# Evaluate every output this flake claims, on every system it claims them for.
#
# `nix flake check` only looks at the system it is running on, so an
# expression that breaks on aarch64-darwin -- a missing attribute, a package
# nixpkgs marks unsupported there -- reaches a Mac user before it reaches CI.
# `--all-systems` does look, but it also tries to *build* what it finds, and an
# x86_64-linux runner asked for an aarch64-darwin derivation fails on the
# platform, which says nothing about the flake.
#
# Forcing each output's `drvPath` is the part worth having: it runs the whole
# evaluation, including the overlay's dependency resolution and its
# version-pin assertions, and stops there. Nothing is built.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

for output in packages devShells checks; do
    echo "evaluating $output for every system..."
    nix eval --json "$root#$output" \
        --apply 'o: builtins.mapAttrs (system: attrs: builtins.mapAttrs (name: d: d.drvPath) attrs) o' \
        > /dev/null
done

echo "every output evaluates on every system it is offered for."
