#!/usr/bin/env bash
#
# Materialise the two things this tree deliberately does not contain.
#
#   ci/link-external.sh            # both, from the flake inputs
#   ci/link-external.sh binaries   # just one
#
# * ./binaries    -- the angr/binaries fixture repository, 450 MB. Every suite
#                    resolves fixtures as `<its tests dir>/../../binaries`,
#                    which in this layout is the repository root.
# * ./pyvex/vex   -- the VEX sources pyvex's CMakeLists compiles. Needed only
#                    to build pyvex outside Nix; the Nix build gets its own
#                    copy of the same pinned input.
#
# Both arrive as copies rather than symlinks, because the Nix store is
# read-only and both get written to: VEX's build generates
# `vex/pub/libvex_guest_offsets.h` beside its own sources, and angr's angrdb
# suite copies a fixture out of the tree with `shutil.copy2` and then writes
# over the copy, which fails when the original is mode 444. Modes are carried
# over from the store with write added, rather than reset from the umask,
# because some fixtures are executables the suites run natively --
# tests/procedures/glibc runs one and diffs its output against the emulation.
#
# Both are gitignored, and re-running is safe: a copy already made from the
# same revision is left alone, and so is anything there this script did not
# put there.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)

materialise()
{
    local attr=$1 dest=$2 target stamp
    target=$(nix build --no-link --print-out-paths "$root#$attr")
    target=$(cd -- "$target" && pwd -P)
    stamp=$dest/.from-nix-store

    if [[ -e $dest && ! -f $stamp ]]; then
        echo "$dest exists and this script did not make it; leaving it alone." >&2
        return 1
    fi
    if [[ -f $stamp && $(cat -- "$stamp") == "$target" ]]; then
        echo "${dest#"$root"/} is already $target"
        return 0
    fi

    rm -rf -- "$dest"
    mkdir -p -- "$(dirname -- "$dest")"
    cp -r --no-preserve=ownership -- "$target" "$dest"
    chmod -R u+w -- "$dest"
    printf '%s\n' "$target" > "$stamp"
    echo "${dest#"$root"/} <- $target"
}

wanted=("$@")
(( ${#wanted[@]} )) || wanted=(binaries vex)

status=0
for what in "${wanted[@]}"; do
    case $what in
        binaries) materialise binaries "$root/binaries" || status=1 ;;
        vex) materialise vex-src "$root/pyvex/vex" || status=1 ;;
        *)
            echo "Nothing external called '$what'. Try: binaries vex" >&2
            exit 2
            ;;
    esac
done
exit "$status"
