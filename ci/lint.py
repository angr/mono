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

# Above this many changed files in one component, upstream stops comparing
# and trusts you. Counted per component, not across the tree: upstream applies
# it inside each repository, so a cross-cutting change of 60 files in angr and
# 60 in cle is two comfortable diffs there and one skipped gate here.
TRUST_THRESHOLD = 150

SCORE = re.compile(r"rated at (-?[\d.]+)/10")

# pylint prints no score for a file with nothing in it. Upstream reads that
# as a perfect 10; this treated it as a parse failure, so every new empty
# __init__.py -- there are 60 in this tree -- failed the gate.
NO_STATEMENTS = "0 statements analysed."


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
    if NO_STATEMENTS in result.stdout:
        return 10.0
    match = SCORE.search(result.stdout)
    if match is None:
        # A file pylint could not parse. Upstream scores that 0, and the
        # number matters: the scale is unbounded below (a short file with a
        # few unresolvable imports scores -32), so a sentinel in the middle
        # of the range reads as an improvement over a bad-but-parsing file.
        print(result.stdout[-2000:])
        return 0.0
    return float(match.group(1))


def merge_base(base: str) -> str:
    """The revision to compare against, or the previous commit on a branch.

    On a push to main the merge base of `origin/main` and HEAD is HEAD, the
    diff is empty, and the gate passes without looking at anything -- which is
    exactly the traffic this repository's main branch carries. Upstream has
    the same special case for master.
    """
    resolved = git("merge-base", base, "HEAD")
    if resolved == git("rev-parse", "HEAD"):
        return git("rev-parse", "HEAD^")
    return resolved


def component_of(path: str) -> str:
    return path.split("/", 1)[0]


def skipped_component(changed: list[str], path: str) -> bool:
    mine = component_of(path)
    count = sum(1 for p in changed if component_of(p) == mine)
    if count > TRUST_THRESHOLD:
        return True
    return False


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

    base = merge_base(args.base)
    changed = [
        p
        for p in git("diff", "--name-only", base, "HEAD").splitlines()
        if p.endswith(".py")
    ]
    if not changed:
        print("no Python files changed.")
        return 0

    # Per component, as upstream counts it.
    changed = [p for p in changed if not skipped_component(changed, p)]
    if not changed:
        print("every changed component is above the trust threshold.")
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
