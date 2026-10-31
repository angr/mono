#!/usr/bin/env python3
"""The diff-relative pyright gate, as angr/ci-settings runs it.

Same ratchet as ci/lint.py and for the same reason: count each changed file's
pyright *errors* on both sides of the diff, and fail the file if the count
goes up. Nothing here has to typecheck cleanly; it has to not get worse. The
base side is the merge base, the same one ci/lint.py uses; upstream's script
scores master's tip instead.

Upstream used to score a per-line "badness" -- (errors * 10 + warnings) /
lines -- and angr/ci-settings#129 replaced it with the raw error count on
2026-09-01. This tree keeps its own copy of the scripts, because upstream's
run inside the CI image against one component checkout and this one is a
monorepo, so the rule has to be carried across by hand. Badness moved with the
file's length: deleting lines from a file that carried an error raised its
score, so a pure deletion failed, and a file that grew fast enough absorbed a
new error. It also counted a warning as a tenth of an error. None of that is
true any more.

    ci/typecheck.py
    ci/typecheck.py --base HEAD~1
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

import vendored

ROOT = Path(__file__).resolve().parent.parent
BASE_TREE = ROOT / ".typecheck-base"


class FileReport:
    """One file's error count, and every diagnostic pyright raised against it.

    A plain class rather than a dataclass: ci/tests loads these scripts by
    path, without registering them in `sys.modules`, and `dataclasses` looks
    the defining module up there to resolve annotations.
    """

    def __init__(self) -> None:
        self.errors = 0
        self.diagnostics: list[tuple[int, int, str, str]] = []


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
            f"pyright does not run ({exc}); the error ratchet cannot mean anything"
        ) from exc
    if result.returncode != 0:
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit("pyright does not run; the error ratchet cannot mean anything")


def typecheck_files(paths: list[Path], tree: Path) -> dict[str, FileReport]:
    """pyright's report per file: the error count, and every diagnostic.

    Run from `tree`, the same way ci/lint.py runs pylint from the tree it is
    scoring. pyright reads its default `exclude` -- `**/node_modules`,
    `**/__pycache__` and `**/.*` -- relative to the working directory, so from
    the repository root the baseline worktree `.typecheck-base` matched
    `**/.*` and pyright read none of it: `filesAnalyzed` came back 0, every
    baseline counted 0 errors, and against zero any file carrying one is a
    regression. From inside that tree the same files are just files.

    Warnings go in `diagnostics` and nowhere else: they are printed under a
    file that regressed, as upstream prints them, and ci-settings#129 stopped
    them counting towards the verdict.
    """
    if not paths:
        return {}
    result = subprocess.run(
        ["pyright", "--outputjson", *[str(p) for p in paths]],
        capture_output=True,
        text=True,
        check=False,
        cwd=str(tree),
    )
    try:
        report = json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        print(result.stdout[-2000:], file=sys.stderr)
        print(result.stderr[-2000:], file=sys.stderr)
        raise SystemExit("pyright produced no JSON") from exc

    out = {str(p): FileReport() for p in paths}
    unattributed = 0
    for item in report.get("generalDiagnostics", []):
        f = item.get("file")
        if f not in out:
            # Never silently: if pyright ever spells a path differently than
            # we do, every diagnostic lands here, both measurements come out
            # zero, and the ratchet passes everything forever.
            unattributed += 1
            continue
        severity = item["severity"]
        if severity == "error":
            out[f].errors += 1
        start = item.get("range", {"start": {"line": 1, "character": 1}})["start"]
        out[f].diagnostics.append(
            (start["line"], start["character"], severity, item["message"])
        )
    if unattributed:
        raise SystemExit(
            f"pyright reported {unattributed} diagnostics against paths this "
            "script did not ask about; the comparison would be meaningless."
        )

    # The other half of the same silence: a file pyright declined to read
    # produces no diagnostics and counts a clean 0 errors, which is what an
    # excluded baseline tree looked like for as long as it was hidden.
    analysed = int(report.get("summary", {}).get("filesAnalyzed", 0))
    if analysed < len(paths):
        raise SystemExit(
            f"pyright analysed {analysed} of the {len(paths)} files it was "
            "given; the comparison would be meaningless."
        )

    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", default="origin/main")
    args = parser.parse_args()

    require_pyright()
    base = merge_base(args.base)
    # A vendored submodule is source this repository does not write. Its
    # files arrive in one commit and would count as new code that has to
    # be perfect, which says nothing about the change under review.
    vendored_paths = vendored.paths()
    changed = [
        p
        for p in git("diff", "--name-only", base, "HEAD").splitlines()
        if p.endswith((".py", ".pyi"))
        and (ROOT / p).exists()
        and not vendored.covers(p, vendored_paths)
    ]
    if not changed:
        print("no Python files changed.")
        return 0

    head = typecheck_files([ROOT / p for p in changed], ROOT)

    # Same reason as ci/lint.py: pyright needs the tree, not loose files.
    subprocess.run(["rm", "-rf", str(BASE_TREE)], check=True)
    git("worktree", "add", "--detach", "--quiet", str(BASE_TREE), base)
    try:
        base_paths = [BASE_TREE / p for p in changed if (BASE_TREE / p).exists()]
        before = typecheck_files(base_paths, BASE_TREE)
    finally:
        git("worktree", "remove", "--force", str(BASE_TREE))

    regressions = []
    for path in changed:
        after = head[str(ROOT / path)]
        # A file that did not exist counts against zero, as upstream does:
        # a new module is allowed no errors at all. Exempting new files meant
        # an arbitrarily broken one passed.
        was = before.get(str(BASE_TREE / path), FileReport()).errors
        print(f"{path}: errors {was} -> {after.errors}")
        if after.errors > was:
            regressions.append((path, was, after))

    if regressions:
        print("\npyright errors increased:", file=sys.stderr)
        for path, was, after in regressions:
            print(f"  {path}: {was} -> {after.errors}", file=sys.stderr)
            # Upstream prints the diagnostics under the file that regressed,
            # which is the difference between a number and something to fix.
            for line, char, severity, text in sorted(after.diagnostics):
                print(f"    {path}:{line}:{char}: [{severity}] {text}", file=sys.stderr)
        return 1
    print("\nno file got worse.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
