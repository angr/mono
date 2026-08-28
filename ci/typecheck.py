#!/usr/bin/env python3
"""The diff-relative pyright gate, as angr/ci-settings runs it.

Same ratchet as ci/lint.py and for the same reason: upstream scores each
changed file's "badness" -- (errors * 10 + warnings) / lines -- at the merge
base and at HEAD, and fails if it goes up. Nothing here has to typecheck
cleanly; it has to not get worse.

    ci/typecheck.py
    ci/typecheck.py --base HEAD~1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BASE_TREE = ROOT / ".typecheck-base"


def git(*args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=True
    ).stdout.strip()


def merge_base(base: str) -> str:
    """The revision to compare against; see the note in ci/lint.py."""
    resolved = git("merge-base", base, "HEAD")
    if resolved == git("rev-parse", "HEAD"):
        return git("rev-parse", "HEAD^")
    return resolved


def require_pyright() -> None:
    """Same reason as ci/lint.py's require_pylint.

    This one already failed loudly -- an absent pyright raises FileNotFoundError
    out of subprocess -- but it failed as a traceback naming `pyright`, not as a
    sentence saying the gate cannot mean anything without it.
    """
    try:
        result = subprocess.run(
            ["pyright", "--version"], capture_output=True, text=True, check=False
        )
    except OSError as exc:
        raise SystemExit(
            f"pyright does not run ({exc}); the badness ratchet cannot mean anything"
        ) from exc
    if result.returncode != 0:
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit("pyright does not run; the badness ratchet cannot mean anything")


def badness(paths: list[Path]) -> dict[str, float]:
    """pyright badness per file: (errors * 10 + warnings) / lines."""
    if not paths:
        return {}
    result = subprocess.run(
        ["pyright", "--outputjson", *[str(p) for p in paths]],
        capture_output=True,
        text=True,
        check=False,
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(result.stdout[-2000:], file=sys.stderr)
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit("pyright produced no JSON") from exc

    counts: dict[str, list[int]] = {str(p): [0, 0] for p in paths}
    unattributed = 0
    for item in report.get("generalDiagnostics", []):
        f = item.get("file")
        if f not in counts:
            # Never silently: if pyright ever spells a path differently than
            # we do, every diagnostic lands here, both measurements come out
            # zero, and the ratchet passes everything forever.
            unattributed += 1
            continue
        if item.get("severity") == "error":
            counts[f][0] += 1
        elif item.get("severity") == "warning":
            counts[f][1] += 1
    if unattributed:
        raise SystemExit(
            f"pyright reported {unattributed} diagnostics against paths this "
            "script did not ask about; the comparison would be meaningless."
        )

    out = {}
    for f, (errors, warnings) in counts.items():
        try:
            lines = max(1, len(Path(f).read_text(encoding="utf-8", errors="replace").splitlines()))
        except OSError:
            lines = 1
        out[f] = (errors * 10 + warnings) / lines
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()

    require_pyright()
    base = merge_base(args.base)
    changed = [
        p
        for p in git("diff", "--name-only", base, "HEAD").splitlines()
        if p.endswith((".py", ".pyi")) and (ROOT / p).exists()
    ]
    if not changed:
        print("no Python files changed.")
        return 0

    head = badness([ROOT / p for p in changed])

    # Same reason as ci/lint.py: pyright needs the tree, not loose files.
    subprocess.run(["rm", "-rf", str(BASE_TREE)], check=True)
    git("worktree", "add", "--detach", "--quiet", str(BASE_TREE), base)
    try:
        base_paths = [BASE_TREE / p for p in changed if (BASE_TREE / p).exists()]
        before = badness(base_paths)
    finally:
        git("worktree", "remove", "--force", str(BASE_TREE))

    regressions = []
    for path in changed:
        after = head[str(ROOT / path)]
        # A file that did not exist scores against zero, as upstream does:
        # a new module is allowed no errors at all. Exempting new files meant
        # an arbitrarily broken one passed.
        was = before.get(str(BASE_TREE / path), 0.0)
        print(f"{path}: badness {was:.4f} -> {after:.4f}")
        if after > was:
            regressions.append((path, was, after))

    if regressions:
        print("\ntype badness increased:", file=sys.stderr)
        for path, was, after in regressions:
            print(f"  {path}: {was:.4f} -> {after:.4f}", file=sys.stderr)
        return 1
    print("\nno file got worse.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
