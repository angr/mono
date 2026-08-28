#!/usr/bin/env python3
"""Snapshot the angr component repositories into this monorepo.

Each component is copied from its upstream default branch into a top-level
directory of the same name.  The upstream commit is recorded in ``mono.json``
so a snapshot can always be traced back and re-created.

Two things deliberately do not come in:

* ``.github/`` from a component.  Only the root workflow runs here, and a
  dead copy of six upstream workflows per component reads as if it did.
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
COMPONENTS = [
    "archinfo",
    "pyvex",
    "pypcode",
    "claripy",
    "cle",
    "angr",
    "angr-management",
]

# Paths dropped from every component snapshot.
COMMON_EXCLUDES = [".git", ".github"]

# Extra per-component exclusions.
EXCLUDES = {
    # VEX stays external: pinned as a flake input, not vendored here.
    "pyvex": ["vex"],
    # 195 MB of FLIRT signatures and 7 MB of library docs are submodules of
    # angr-management; they are runtime data, not code under test.
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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", action="append", dest="components")
    parser.add_argument("--cache-dir", type=Path, default=ROOT / ".import-cache")
    args = parser.parse_args()

    components = args.components or COMPONENTS
    unknown = [c for c in components if c not in COMPONENTS]
    if unknown:
        parser.error(f"unknown component(s): {', '.join(unknown)}")

    manifest_path = ROOT / "mono.json"
    manifest = {"schema": 1, "components": {}}
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text())

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
        manifest["components"][name] = {
            "upstream": f"https://github.com/angr/{name}",
            "commit": commit,
            "committed_at": committed,
            "subject": subject,
            "excluded": sorted(set(EXCLUDES.get(name, []))),
            "sibling_sources_repointed_at_workspace": workspaced,
        }

    manifest["imported_at"] = dt.datetime.now(dt.timezone.utc).replace(
        microsecond=0
    ).isoformat()
    manifest["components"] = dict(sorted(manifest["components"].items()))
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
