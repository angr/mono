#!/usr/bin/env python3
"""The diff-relative pylint gate, as angr/ci-settings runs it.

Upstream does not require a clean pylint score; it requires that a file you
touched not score *worse* than it did before. `ci-settings`' own lint.py scores
each changed file at the merge base and again at HEAD and fails on a
regression, against ci-settings' pylintrc rather than any component's own
configuration. That is deliberate: a codebase this old does not pass pylint
outright, and a ratchet is what moves it the right way anyway.

Same gate here, over the whole tree at once -- one merge base, one list of
changed files, whichever components they happen to land in.

    ci/lint.py                  # against origin/main
    ci/lint.py --base HEAD~1
"""

from __future__ import annotations

import argparse
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PYLINTRC = ROOT / "ci" / "pylintrc"
BASE_TREE = ROOT / ".lint-base"

# Above this many changed files, upstream stops comparing and trusts you.
TRUST_THRESHOLD = 150

SCORE = re.compile(r"rated at (-?[\d.]+)/10")


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def score(target: Path, cwd: Path) -> float | None:
    """pylint score for one file, or None if it is not there."""
    if not target.exists():
        return None
    result = subprocess.run(
        [sys.executable, "-m", "pylint", "--rcfile", str(PYLINTRC), str(target)],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(cwd),
    )
    match = SCORE.search(result.stdout)
    if match is None:
        # pylint prints no score only when it could not parse the file at all.
        print(result.stdout[-2000:])
        return -10.0
    return float(match.group(1))


def compare(changed: list[str]) -> list[tuple[str, float, float]]:
    regressions = []
    for path in changed:
        after = score(ROOT / path, ROOT)
        if after is None:
            continue  # deleted
        before = score(BASE_TREE / path, BASE_TREE)
        if before is None:
            # A new file has nothing to regress against, so it must be clean.
            print(f"{path}: new file, {after:.2f}/10", flush=True)
            if after < 10.0:
                regressions.append((path, 10.0, after))
        else:
            print(f"{path}: {before:.2f} -> {after:.2f}", flush=True)
            if after < before:
                regressions.append((path, before, after))
    return regressions


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()

    base = git("merge-base", args.base, "HEAD")
    changed = [
        p
        for p in git("diff", "--name-only", base, "HEAD").splitlines()
        if p.endswith(".py")
    ]
    if not changed:
        print("no Python files changed.")
        return 0
    if len(changed) > TRUST_THRESHOLD:
        print(f"{len(changed)} Python files changed; not comparing scores.")
        return 0

    # A worktree of the base revision, not a pile of extracted files: pylint
    # resolves a module's package and its siblings, and scoring
    # `cle/cle/__init__.py` on its own in an empty directory reports -28/10
    # for imports that are simply not there. The comparison only means
    # something against the same shape of tree.
    subprocess.run(["rm", "-rf", str(BASE_TREE)], check=True)
    git("worktree", "add", "--detach", "--quiet", str(BASE_TREE), base)
    try:
        regressions = compare(changed)
    finally:
        git("worktree", "remove", "--force", str(BASE_TREE))

    if regressions:
        print("\npylint score regressed:", file=sys.stderr)
        for path, before, after in regressions:
            print(f"  {path}: {before:.2f} -> {after:.2f}", file=sys.stderr)
        return 1
    print("\nno pylint score regressed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
