#!/usr/bin/env python3
"""Fetch the pinned externals with git, on any platform.

`ci/link-external.sh` gets them out of the Nix store, which is the right
answer on Linux and no answer at all on Windows. Both read the same
`flake.lock`, so the Nix lane and the native lane are pinned to the same
commits and cannot drift.

    ci/fetch-external.py                # binaries and vex
    ci/fetch-external.py binaries       # just one
    ci/fetch-external.py --print-rev vex

Re-running is safe: a checkout already at the pinned commit is left alone.
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where each pinned input is materialised, relative to the repository root.
# The paths are where the component suites and builds already look: the test
# fixtures beside the components, VEX inside pyvex where its CMakeLists wants
# it.
DESTINATIONS = {
    "binaries": Path("binaries"),
    "vex": Path("pyvex") / "vex",
}


def pinned() -> dict[str, tuple[str, str]]:
    """Input name -> (clone url, commit), read from flake.lock."""
    lock = json.loads((ROOT / "flake.lock").read_text())
    out = {}
    for name, node in lock["nodes"].items():
        if name not in DESTINATIONS:
            continue
        locked = node["locked"]
        out[name] = (
            f"https://github.com/{locked['owner']}/{locked['repo']}",
            locked["rev"],
        )
    missing = set(DESTINATIONS) - set(out)
    if missing:
        raise SystemExit(f"flake.lock has no input for: {', '.join(sorted(missing))}")
    return out


def run(*args: str, cwd: Path | None = None, check: bool = True) -> str:
    result = subprocess.run(
        args, cwd=cwd, capture_output=True, text=True, check=check
    )
    return result.stdout.strip()


def head(path: Path) -> str | None:
    if not (path / ".git").exists():
        return None
    try:
        return run("git", "-C", str(path), "rev-parse", "HEAD")
    except subprocess.CalledProcessError:
        return None


def fetch(name: str, url: str, rev: str) -> None:
    dest = ROOT / DESTINATIONS[name]
    if head(dest) == rev:
        print(f"{DESTINATIONS[name]} is already at {rev[:12]}")
        return

    if not (dest / ".git").exists():
        # A directory left by the Nix lane is not a checkout; replace it.
        if dest.exists():
            shutil.rmtree(dest, ignore_errors=True)
        dest.parent.mkdir(parents=True, exist_ok=True)
        run("git", "init", "--quiet", str(dest))
        run("git", "-C", str(dest), "remote", "add", "origin", url)

    # Fetching the one commit keeps 450 MB of fixture history off the runner.
    run("git", "-C", str(dest), "fetch", "--quiet", "--depth", "1", "origin", rev)
    run("git", "-C", str(dest), "checkout", "--quiet", "--detach", "FETCH_HEAD")
    print(f"{DESTINATIONS[name]} <- {url}@{rev[:12]}")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("names", nargs="*", choices=[*DESTINATIONS, []], default=[])
    parser.add_argument(
        "--print-rev",
        metavar="NAME",
        help="print the pinned commit and exit, for a cache key",
    )
    args = parser.parse_args()

    revs = pinned()
    if args.print_rev:
        print(revs[args.print_rev][1])
        return 0

    for name in args.names or sorted(DESTINATIONS):
        url, rev = revs[name]
        fetch(name, url, rev)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
