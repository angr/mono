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
import json
import re
import subprocess
import sys
from pathlib import Path

import vendored

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
# __init__.py -- there are 59 tracked in this tree -- failed the gate.
NO_STATEMENTS = "0 statements analysed."


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def require_pylint() -> None:
    """Refuse to compare scores with no pylint to produce them.

    Without this the gate passed by accident: `score()` returns 0.0 for a file
    pylint could not parse, and an absent pylint produces no score either, so
    both revisions came back 0.0, compared equal, and the run printed "no
    pylint score regressed" over a comparison it had never made. A guard that
    reports all clear has to be able to report not clear.
    """
    result = subprocess.run(
        [sys.executable, "-m", "pylint", "--version"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        print(result.stdout[-2000:], file=sys.stderr)
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit("pylint does not run; the score ratchet cannot mean anything")


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
        #
        # stderr too: without it, "pylint emitted no score" and "pylint did
        # not run" looked identical here, and require_pylint() above exists
        # because the second one used to pass the gate.
        print(result.stdout[-2000:])
        print(result.stderr[-2000:], file=sys.stderr)
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


def components(tree: Path) -> set[str]:
    """The component directories a tree's `mono.json` records."""
    manifest_path = tree / "mono.json"
    if not manifest_path.exists():
        return set()
    manifest = json.loads(manifest_path.read_text())
    return {
        name
        for section in ("components", "fixtures")
        for name in manifest.get(section, {})
    }


def score_root(tree: Path, path: str) -> Path:
    """Where to run pylint on one file, so it scores as its own repository scores it.

    pylint asks isort whether an import is first-party or third-party, and
    isort answers from the working directory. Run it at the mono root and
    `archinfo/` is a directory right there, so `import archinfo` is a
    first-party import and any component file importing a sibling before
    pytest picks up `C0411 wrong-import-order` -- a message its own repository
    cannot produce, because there archinfo is an installed package like any
    other. Four cle test files lost this ratchet on nothing else.

    So each file is scored from its component's directory, which is the root
    of the repository it came from. `ci/pre-commit.sh` extracts a component
    into a scratch repository for the same reason: a component's tooling means
    what it meant upstream only when the component is the root.

    Everything outside a component -- `ci/` and the tree's own files -- keeps
    scoring from the mono root, which is its repository.
    """
    component = component_of(path)
    root = tree / component
    if component in components(tree) and root.is_dir():
        return root
    return tree


def skipped_component(changed: list[str], path: str) -> bool:
    mine = component_of(path)
    count = sum(1 for p in changed if component_of(p) == mine)
    if count > TRUST_THRESHOLD:
        return True
    return False


def compare(changed: list[str]) -> list[tuple[str, float, float]]:
    regressions = []
    for path in changed:
        after = score(ROOT / path, score_root(ROOT, path))
        if after is None:
            continue  # deleted
        before = score(BASE_TREE / path, score_root(BASE_TREE, path))
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

    require_pylint()
    base = merge_base(args.base)
    # A vendored submodule is source this repository does not write. Its
    # files arrive in one commit and would score as new code that has to
    # be perfect, which says nothing about the change under review.
    vendored_paths = vendored.paths()
    changed = [
        p
        for p in git("diff", "--name-only", base, "HEAD").splitlines()
        if p.endswith(".py")
        and not vendored.covers(p, vendored_paths)
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
    # something against the same shape of tree -- and both sides are scored
    # from the same place inside it, see `score_root`.
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
