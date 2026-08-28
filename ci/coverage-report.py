#!/usr/bin/env python3
"""Combine the coverage lane's output and gate on it.

Upstream sends everything to Codecov, which merges the shards, renders the
result and comments on the pull request. This repository has no Codecov
project, so the merging and the rendering happen here -- and, because an
artifact nobody reads is not a gate, so does a ratchet against
``ci/coverage.json``.

Three kinds of coverage come out of one instrumented build:

* Python, from ``coverage``. One database per suite per lane per shard, named
  ``.coverage.<suite>.<tag>.<shard>``, combined per component -- per
  component and not all at once, because each has its own ``[tool.coverage]``
  section and a merged database has no single valid rcfile.
* C, from ``gcov`` via ``gcovr``, over angr's ``native`` and pypcode's
  extension.
* Rust, from the ``.profraw`` files the instrumented ``rustylib`` wrote,
  merged with ``llvm-profdata`` and exported with ``llvm-cov``.

    ci/coverage-report.py test-results
    ci/coverage-report.py test-results --baseline ci/coverage.json
    ci/coverage-report.py test-results --baseline ci/coverage.json --update-baseline
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where each component's C sources live, for gcovr. angr's are one level
# deeper than upstream's because the component sits in a subdirectory here.
C_SOURCES = {
    "angr": ROOT / "angr" / "native",
    "pypcode": ROOT / "pypcode",
}

# The instrumented extension llvm-cov attributes the .profraw files to.
def run(*args: str | Path, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, check=check
    )


def coverage_cmd() -> Sequence[str]:
    """However `coverage` can be invoked here, or a refusal saying it cannot.

    The summary job is not the coverage job and has no .venv-native, so this
    cannot assume `sys.executable -m coverage` works. Same rule as the lint
    and typecheck ratchets: a gate that cannot run its tool must say so, not
    report nothing and pass.
    """
    on_path = shutil.which("coverage")
    candidates: list[list[str]] = [[sys.executable, "-m", "coverage"]]
    if on_path is not None:
        candidates.insert(0, [on_path])
    for candidate in candidates:
        if run(*candidate, "--version", check=False).returncode == 0:
            return candidate
    raise SystemExit("coverage does not run; the coverage gate cannot mean anything")


def suites() -> list[str]:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    return [job["suite"] for job in config.get("coverage", [])]


def expected() -> list[str]:
    """Every measurement this repository intends to have.

    Without this, a metric that fails every time is invisible: the C and Rust
    helpers return None on any error, main() omits the key, and a ratchet that
    only compares the keys it was given has nothing to compare. Rust coverage
    could have been silently unmeasured forever.
    """
    names = []
    for suite in suites():
        names.append(f"{suite}:python")
        if suite in C_SOURCES:
            names.append(f"{suite}:c")
    names.append("angr:rust")
    return names


def python_percent(results: Path, suite: str, coverage: Sequence[str]) -> float | None:
    """Combine one component's shards and return its line percentage."""
    shards = sorted(results.glob(f".coverage.{suite}.*"))
    if not shards:
        return None
    # The generated config, not the component's pyproject: it carries the
    # [paths] section that makes ten shards and an editable install one tree.
    rcfile = results / f"coveragerc-{suite}.ini"
    if not rcfile.exists():
        rcfile = ROOT / suite / "pyproject.toml"
    combined = results / f".combined.{suite}"
    combined.unlink(missing_ok=True)
    # --keep, so a rerun of this script over the same artifacts is not
    # destructive; the shards are the only copy CI has.
    run(
        *coverage, "combine",
        f"--rcfile={rcfile}", f"--data-file={combined}", "--keep", *shards,
    )
    report = run(
        *coverage, "json",
        f"--rcfile={rcfile}", f"--data-file={combined}",
        "-o", str(results / f"coverage-{suite}.json"),
        check=False,
    )
    if report.returncode != 0:
        print(report.stdout[-2000:], file=sys.stderr)
        print(report.stderr[-2000:], file=sys.stderr)
        raise SystemExit(f"coverage json failed for {suite}")
    data = json.loads((results / f"coverage-{suite}.json").read_text())
    return round(data["totals"]["percent_covered"], 2)


def native(results: Path) -> dict[str, float]:
    """C and Rust, as ci/native-coverage.py measured them in each shard.

    They cannot be measured here: gcov's .gcda and the instrumented
    rustylib .so live in the coverage job's workspace and are not uploaded.
    Each shard writes its own numbers instead, and the highest is the one
    kept -- a floor check wants the best evidence that a line was reached,
    and no shard runs the whole suite.
    """
    best: dict[str, float] = {}
    for path in sorted(results.glob("native-*.json")):
        for name, value in json.loads(path.read_text()).items():
            best[name] = max(best.get(name, 0.0), float(value))
    return best


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=Path("test-results"))
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--update-baseline", action="store_true")
    # Coverage moves by a fraction of a percent when a test is added, and a
    # gate that fires on noise gets switched off. Upstream's Codecov default
    # is the same idea.
    parser.add_argument("--tolerance", type=float, default=1.0)
    args = parser.parse_args()

    coverage = coverage_cmd()

    observed: dict[str, float] = {}
    for suite in suites():
        py = python_percent(args.results, suite, coverage)
        if py is not None:
            observed[f"{suite}:python"] = py
    observed.update(native(args.results))

    missing = sorted(set(expected()) - set(observed))

    if not observed:
        print("No coverage data found.")
        # The lane uploads with if-no-files-found: error, so an empty results
        # directory here means the artifacts did not arrive, not that nothing
        # was measured.
        return 1

    print("| measurement | covered |")
    print("| --- | ---: |")
    for name, pct in sorted(observed.items()):
        print(f"| {name} | {pct:.2f}% |")

    if missing:
        print(f"\nnot measured: {', '.join(missing)}")

    if args.baseline is None:
        return 0

    if args.update_baseline:
        budget = json.loads(args.baseline.read_text()) if args.baseline.exists() else {}
        untouched = sorted(set(budget) - set(observed))
        budget.update(observed)
        args.baseline.write_text(json.dumps(dict(sorted(budget.items())), indent=2) + "\n")
        print(f"\nwrote {args.baseline}: {', '.join(sorted(observed))}")
        if untouched:
            print(f"left alone (not in this run): {', '.join(untouched)}")
        return 0

    budget = json.loads(args.baseline.read_text())
    regressions = []
    for name in missing:
        regressions.append(f"  {name}: expected, but this run measured nothing")
    for name in sorted(set(budget) - set(observed) - set(missing)):
        regressions.append(f"  {name}: recorded, but this run measured nothing")
    for name, pct in sorted(observed.items()):
        floor = budget.get(name)
        if floor is None:
            regressions.append(f"  {name}: {pct:.2f}%, no baseline recorded")
        elif pct < floor - args.tolerance:
            regressions.append(f"  {name}: {pct:.2f}%, baseline {floor:.2f}%")

    if regressions:
        print(f"\ncoverage fell below {args.baseline}:", file=sys.stderr)
        for line in regressions:
            print(line, file=sys.stderr)
        print(
            f"\nTolerance is {args.tolerance:.2f} points. Raise the baseline on "
            "purpose, or find the tests that stopped running.",
            file=sys.stderr,
        )
        return 1
    print(f"\nno measurement fell below {args.baseline}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
