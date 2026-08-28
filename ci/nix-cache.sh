#!/usr/bin/env bash
#
# Move a Nix store closure between CI jobs through a GitHub release.
#
#   ci/nix-cache.sh key                       # the cache key for this tree
#   ci/nix-cache.sh push <key> <installable>… # build, export, upload
#   ci/nix-cache.sh pull <key>                # download and unpack, if present
#
# Why a release and not just actions/cache: the warm closure for this tree is
# several gigabytes, one entry per source revision, and the Actions cache is a
# 10 GB LRU for the whole repository -- a busy afternoon evicts the entry that
# fourteen matrix jobs are about to ask for, and they all rebuild angr from
# source. Release assets have no such budget and no eviction, so the release is
# the authoritative copy and actions/cache is a same-datacentre fast path in
# front of it (the workflow tries the cache first and falls back to here).
#
# The unpacked directory is an ordinary Nix binary cache, so consumers add it
# as a substituter and fetch only the paths they actually need rather than
# importing the whole closure.
#
# The key is derived from the derivation the tree evaluates to, so it changes
# exactly when a rebuild would be needed and never when it would not.

set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cache_dir=${NIX_CACHE_DIR:-$root/.nix-cache}
tag=${NIX_CACHE_TAG:-nix-cache}
keep=${NIX_CACHE_KEEP:-5}
# Everything a CI job might need from the store, named one by one.
#
# Not an aggregate derivation over the lot: `linkFarmFromDrvs` keys its entries
# by derivation *name*, and both Python environments here are called
# `python3-3.12.13-env`, so one silently displaced the other and the published
# cache was missing an environment every test job needed. Listing the real
# things is both shorter and impossible to get wrong that way.
default_installables=(
    ".#test-env"
    ".#gui-env"
    ".#binaries"
    ".#angr"
    ".#angr-management-lib"
)

# Everything the built closure depends on: the pins, the Nix expressions, and
# each component's source tree. Git already hashes those trees, so the key is a
# hash of hashes -- no evaluation, no Nix needed, and it changes if and only if
# one of those inputs did. A README edit does not invalidate it, because
# component derivations take their own directory as `src`, not the whole tree.
key_for()
{
    local paths=(flake.nix flake.lock nix)
    local component
    while read -r component; do
        paths+=("$component")
    done < <(python3 -c "
import json
print('\n'.join(json.load(open('$root/mono.json'))['components']))
")
    # The system is part of the key, not just the sources: the closure for
    # aarch64-darwin shares none of its store paths with x86_64-linux, and
    # without this the second system to run finds the first one's asset,
    # concludes it is already published, and its consumers unpack gigabytes
    # containing nothing they can use.
    #
    # From uname, not from `nix eval builtins.currentSystem`: this runs in
    # the composite action's first step, before the Nix installer, so asking
    # Nix returned the fallback every time and the component was a no-op.
    local system
    system="$(uname -m)-$(uname -s | tr '[:upper:]' '[:lower:]')"
    printf '%s-%s\n' "$system" \
        "$(git -C "$root" rev-parse "${paths[@]/#/HEAD:}" | sha256sum | cut -c1-32)"
}

case ${1:-} in
    key)
        key_for
        ;;
    push)
        key=${2:?push needs a key}
        shift 2
        installables=("$@")
        (( ${#installables[@]} )) || installables=("${default_installables[@]}")
        # `select(.state == "uploaded")`, because a run cancelled mid-upload
        # leaves the asset in state "starter": present in the listing, and a
        # 404 for everyone who downloads it. Without the filter every later
        # run reports it published and exits, and the key stays wedged until
        # someone deletes the asset by hand.
        #
        # Process substitution rather than a pipe: `gh … | grep -q` makes grep
        # exit on the first match and kills gh with SIGPIPE, which under
        # `pipefail` is a non-zero pipeline -- a match reported as a miss.
        if grep -qxF "$key.tar.zst" < <(gh release view "$tag" --json assets \
                --jq '.assets[] | select(.state == "uploaded") | .name' 2>/dev/null); then
            echo "$key is already published; nothing to upload."
            exit 0
        fi
        nix build --no-link "${installables[@]}"

        # Built somewhere else and moved into place: the Nix daemon runs as
        # root and creates directories under a configured substituter, so
        # clearing $cache_dir in place can fail on paths this user cannot
        # remove.
        staging=$(mktemp -d "$root/.nix-cache-staging.XXXXXX")
        trap 'rm -rf -- "$staging" "$root/$key.tar.zst"' EXIT
        # zstd rather than the default xz: this cache lives for one revision,
        # and xz spends minutes to save a few percent of a gigabyte that will
        # be downloaded once over a fast link.
        nix copy --to "file://$staging?compression=zstd&parallel-compression=true" \
            "${installables[@]}"
        tar -C "$staging" -cf - . | zstd -1 -T0 -o "$root/$key.tar.zst" -f
        ls -lh "$root/$key.tar.zst"

        # Two runs can reach this together and the loser's `create` fails
        # with "already exists"; under `set -e` that would kill the script
        # after a successful build.
        gh release view "$tag" >/dev/null 2>&1 ||
            gh release create "$tag" --title "Nix store cache" --notes \
                "Binary caches for CI, one asset per source revision. Machine-managed; delete freely." ||
            gh release view "$tag" >/dev/null
        gh release upload "$tag" "$root/$key.tar.zst" --clobber

        # The same closure into the directory the workflow saves to
        # actions/cache. Without this, `push` deletes its staging directory
        # and leaves nothing behind, so the fast path in front of the release
        # is only ever populated by a re-run of an already-published key --
        # every first build sends the whole matrix to the release download.
        mkdir -p -- "$cache_dir"
        cp -a "$staging/." "$cache_dir/"

        # One asset per source revision adds up fast on a public repository.
        # Keep the newest few and drop the rest; a job whose asset was pruned
        # falls back to building, which is what it would have done anyway.
        # Never the key this run just published, and never fatal: a prune is
        # housekeeping, and a build that succeeded should not be failed by it.
        while read -r stale; do
            [[ $stale == "$key.tar.zst" ]] && continue
            echo "pruning $stale"
            gh release delete-asset "$tag" "$stale" --yes || true
        done < <(gh release view "$tag" --json assets \
            --jq '.assets | sort_by(.createdAt) | reverse | .['"$keep"':] | .[].name' || true)
        ;;
    pull)
        key=${2:?pull needs a key}
        if [[ -d $cache_dir && -f $cache_dir/nix-cache-info ]]; then
            echo "$cache_dir already populated."
            exit 0
        fi
        # stderr is kept: swallowing it made a rate limit, a 5xx and an auth
        # failure all indistinguishable from "this revision has no cache",
        # and the only symptom was fourteen jobs quietly building angr.
        if ! gh release download "$tag" --pattern "$key.tar.zst" --dir "$root" --clobber; then
            # Deliberately leave nothing behind. A substituter pointing at a
            # directory that does not exist is a warning Nix carries on past;
            # an empty one that gets saved as this revision's cache is a
            # poisoned key that every later job restores instead of the real
            # thing.
            echo "No cached closure for $key; the consumer will build from source."
            exit 0
        fi
        mkdir -p -- "$cache_dir"
        zstd -d -c "$root/$key.tar.zst" | tar -C "$cache_dir" -xf -
        rm -f -- "$root/$key.tar.zst"
        du -sh "$cache_dir"
        ;;
    *)
        sed -n '2,/^$/{s/^# \{0,1\}//p}' "${BASH_SOURCE[0]}" >&2
        exit 2
        ;;
esac
