#!/usr/bin/env python3
"""Snapshot the angr component repositories into this monorepo.

Each component is copied from its upstream default branch into a top-level
directory of the same name.  The upstream commit is recorded in ``mono.json``
so a snapshot can always be traced back and re-created.

Two things deliberately do not come in:

* ``.github/`` from a component.  Only the root workflow runs here, and all
  twelve components have one upstream -- thirty workflow files between them,
  every one of which would read as if it ran.
* ``pyvex/vex``.  VEX stays an external dependency; the flake's ``vex`` input
  is repinned to whatever commit pyvex's submodule names, so the pin follows
  upstream without the sources living here.

Usage:
    ci/import.py                        # every component, from upstream heads
    ci/import.py --component cle        # just one
    ci/import.py --cache-dir DIR        # reuse/keep clones here
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Components imported into the tree, in dependency order.
CORE = [
    "archinfo",
    "pyvex",
    "pypcode",
    "claripy",
    "cle",
    "angr",
    "angr-management",
]

# The dependents upstream tests on every core-component pull request.
#
# `ci-settings/ci-image/conf/repo-list.txt` records a dependency graph, and
# `test.py` runs the suite of everything transitively downstream of the repo
# under test: a change to archinfo runs thirteen suites, not one. Without
# these, a green run here means an API change was tried against angr and
# angr-management and nothing else.
#
# Two of them also matter to angr's own suite. Twenty-one tests are behind
# `skipUnless(pysoot)` -- fourteen decorated in
# `angr/tests/engines/test_java.py`, three more through the `create_project`
# helper it decorates, and four from the class decorator in
# `test_cfgfast_soot.py` -- and eighteen more are behind
# `skipUnless(tracer)`. Without those two in the tree, those tests do not
# fail -- they report as skips, which is worse.
ECOSYSTEM = [
    "pysoot",
    "tracer",
    "angr-platforms",
    "angrop",
    "phuzzer",
]

COMPONENTS = CORE + ECOSYSTEM

# The test fixtures. Vendored like a component and imported like one, but
# deliberately not *a* component: `ci/nix-cache.sh`'s key is built from
# `mono.json`'s component list, and putting 460 MB of fixtures in it would
# mean a one-file fixture change rebuilding every closure in the matrix.
# It is recorded under its own manifest key for exactly that reason, and
# `flake.nix` reaches into it for one 8.7 KB file and nothing else.
FIXTURES = "binaries"

IMPORTABLE = [*COMPONENTS, FIXTURES]

# Paths dropped from every component snapshot.
COMMON_EXCLUDES = [".git", ".github"]

# Extra per-component exclusions.
EXCLUDES = {
    # VEX stays external: pinned as a flake input, not vendored here.
    "pyvex": ["vex"],
    # FLIRT signatures and library docs are submodules of angr-management,
    # a couple of hundred megabytes between them and growing; they are
    # runtime data, not code under test. The pyinstaller lane clones both at
    # a pinned commit, so the frozen bundle still carries what upstream's
    # does.
    "angr-management": [
        "angrmanagement/resources/flirt_signatures",
        "angrmanagement/resources/library_docs",
    ],
}

BASE_URL = os.environ.get("ANGR_REPO_BASE_URL", "https://github.com/angr")


def run(*args: str, cwd: Path | None = None) -> str:
    return subprocess.run(
        args, cwd=cwd, check=True, capture_output=True, text=True
    ).stdout.strip()


def fetch(name: str, cache: Path) -> Path:
    """Return a checkout of ``name`` at its upstream default branch head."""
    dest = cache / name
    url = f"{BASE_URL}/{name}.git"
    if dest.exists():
        run("git", "-C", str(dest), "fetch", "--depth", "1", "origin", "HEAD")
        run("git", "-C", str(dest), "checkout", "--detach", "FETCH_HEAD")
    else:
        cache.mkdir(parents=True, exist_ok=True)
        run("git", "clone", "--depth", "1", url, str(dest))
    return dest


# Sibling pins inside a component's `[tool.uv.sources]`.
#
# Every component points its siblings at `git+https://github.com/angr/<name>`,
# which is the only thing that can work across repositories and is exactly
# wrong inside one: uv fetches archinfo from GitHub while an archinfo sits in
# the next directory, then refuses the tree for holding two conflicting URLs
# for one package. Worse, it would test a component against upstream's head
# rather than against the tree it is being changed in, which is the whole
# point of putting them together.
#
# So the import rewrites those entries to `{ workspace = true }`. It is the
# one edit made to imported source, it is mechanical, and mono.json records
# it per component.
SIBLING_SOURCE = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9._-]+)\s*=\s*\{[^}]*"
    r"git\s*=\s*[\"']https://github\.com/angr/(?P<repo>[A-Za-z0-9._-]+?)(?:\.git)?[\"'][^}]*\}\s*$",
    re.MULTILINE,
)


def use_workspace_sources(dest: Path) -> list[str]:
    """Repoint a component's sibling git sources at the workspace."""
    pyproject = dest / "pyproject.toml"
    if not pyproject.exists():
        return []

    rewritten = []

    def replace(match: re.Match) -> str:
        if match.group("repo") not in COMPONENTS:
            return match.group(0)
        rewritten.append(match.group("name"))
        return f"{match.group('indent')}{match.group('name')} = {{ workspace = true }}"

    text = pyproject.read_text()
    updated = SIBLING_SOURCE.sub(replace, text)
    if rewritten:
        pyproject.write_text(updated)
    return sorted(rewritten)


def submodule_commit(repo: Path, path: str) -> str:
    """The commit a gitlink points at, e.g. pyvex's `vex`."""
    line = run("git", "-C", str(repo), "ls-tree", "HEAD", path)
    _mode, kind, rest = line.split(maxsplit=2)
    if kind != "commit":
        raise SystemExit(f"{repo}/{path} is a {kind}, not a submodule")
    return rest.split()[0]


def repin_vex(commit: str) -> bool:
    """Point the flake's `vex` input at the commit pyvex's submodule names.

    VEX is the one dependency this repository deliberately does not vendor, so
    the pin has to be kept honest by hand -- or, since the answer is written
    down in pyvex's gitlink, here.
    """
    flake = ROOT / "flake.nix"
    text = flake.read_text()
    updated, count = re.subn(
        r'(url = "github:angr/vex/)[0-9a-f]{40}(")', rf"\g<1>{commit}\g<2>", text
    )
    if count != 1:
        raise SystemExit("could not find the vex input pin in flake.nix")
    if updated == text:
        return False
    flake.write_text(updated)
    subprocess.run(["nix", "flake", "lock"], cwd=ROOT, check=True)
    return True


def bucket(manifest: dict, name: str) -> dict:
    """The manifest section a name is recorded in.

    Fixtures are kept out of `components` so the Nix cache key, which is
    built from that list, never sees them.
    """
    key = "fixtures" if name == FIXTURES else "components"
    return manifest.setdefault(key, {})


def snapshot(name: str, src: Path, dest: Path) -> None:
    if dest.exists():
        shutil.rmtree(dest)
    excludes = set(COMMON_EXCLUDES) | set(EXCLUDES.get(name, []))

    def ignore(directory: str, entries: list[str]) -> set[str]:
        rel = Path(directory).resolve().relative_to(src.resolve())
        return {
            entry
            for entry in entries
            if str(rel / entry) in excludes or entry in excludes
        }

    shutil.copytree(src, dest, ignore=ignore, symlinks=True)


def from_trees(
    trees: Path, components: list[str], manifest: dict, manifest_path: Path
) -> int:
    """Snapshot components from trees somebody else assembled.

    The rollup skill merges each component's open pull requests onto upstream
    head and exports the result. Those trees still have to go through the same
    exclusions and the same `[tool.uv.sources]` rewrite an ordinary import
    applies, or the rollup would reintroduce the twelve component `.github`
    directories and point every sibling dependency back at GitHub. Doing it
    here rather than in the skill keeps one implementation of the rules.
    """
    applied = {}
    for candidate in ("rollup.json", "vibr.json"):
        if (trees / candidate).exists():
            applied = json.loads((trees / candidate).read_text())
            break

    for name in components:
        source = trees / name
        if not source.is_dir():
            continue
        snapshot(name, source, ROOT / name)
        workspaced = use_workspace_sources(ROOT / name)
        entry = applied.get("components", {}).get(name, {})
        prs = [p["number"] for p in entry.get("applied", [])]
        print(f"{name}: {len(prs)} pull request(s) merged onto {entry.get('base', '?')[:12]}",
              file=sys.stderr)
        bucket(manifest, name)[name] = {
            "upstream": f"https://github.com/angr/{name}",
            "commit": entry.get("base", ""),
            "committed_at": "",
            "subject": f"rollup of {len(prs)} open pull request(s)",
            "excluded": sorted(set(EXCLUDES.get(name, []))),
            "sibling_sources_repointed_at_workspace": workspaced,
            "rolled_up": prs,
        }

    for key in ("components", "fixtures"):
        if key in manifest:
            manifest[key] = dict(sorted(manifest[key].items()))
    manifest["imported_at"] = (
        dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
    )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", action="append", dest="components")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".import-cache")
    parser.add_argument(
        "--from-trees",
        type=Path,
        help="snapshot from an assembled directory instead of upstream, as the "
        "mono rollup does; expects <dir>/<component> and <dir>/rollup.json",
    )
    args = parser.parse_args()

    components = args.components or IMPORTABLE
    unknown = [c for c in components if c not in IMPORTABLE]
    if unknown:
        parser.error(f"unknown component(s): {', '.join(unknown)}")

    manifest_path = ROOT / "mono.json"
    manifest = {"schema": 1, "components": {}}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

    if args.from_trees:
        return from_trees(args.from_trees, components, manifest, manifest_path)

    for name in components:
        src = fetch(name, args.cache_dir)
        commit = run("git", "-C", str(src), "rev-parse", "HEAD")
        subject = run("git", "-C", str(src), "log", "-1", "--format=%s")
        committed = run("git", "-C", str(src), "log", "-1", "--format=%cI")
        print(f"{name}: {commit[:12]} {subject}", file=sys.stderr)
        snapshot(name, src, ROOT / name)
        workspaced = use_workspace_sources(ROOT / name)
        if name == "pyvex":
            vex = submodule_commit(src, "vex")
            manifest["external"] = {"vex": vex}
            if repin_vex(vex):
                print(f"vex: repinned to {vex[:12]}", file=sys.stderr)
        bucket(manifest, name)[name] = {
            "upstream": f"https://github.com/angr/{name}",
            "commit": commit,
            "committed_at": committed,
            "subject": subject,
            "excluded": sorted(set(EXCLUDES.get(name, []))),
            "sibling_sources_repointed_at_workspace": workspaced,
        }

    for key in ("components", "fixtures"):
        if key in manifest:
            manifest[key] = dict(sorted(manifest[key].items()))

    # Stamp a time only when something moved, so re-importing an unchanged
    # upstream leaves the manifest alone and the tree stays clean. Otherwise
    # the one command the README gives for regenerating the tree always
    # reports a diff, and "did upstream move?" cannot be answered by running
    # it.
    previous = json.loads(manifest_path.read_text()) if manifest_path.exists() else {}
    if {k: v for k, v in manifest.items() if k != "imported_at"} != {
        k: v for k, v in previous.items() if k != "imported_at"
    }:
        manifest["imported_at"] = (
            dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()
        )
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
