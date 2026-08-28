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
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Where each component's C sources live, for gcovr. angr's are one level
# deeper than upstream's because the component sits in a subdirectory here.
C_SOURCES = {
    "angr": ROOT / "angr" / "native",
    "pypcode": ROOT / "pypcode",
}

# The instrumented extension llvm-cov attributes the .profraw files to.
RUST_OBJECT = ROOT / "angr" / "angr"

def run(*args: str, check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, check=check
    )


def coverage_cmd() -> list[str]:
    """However `coverage` can be invoked here, or a refusal saying it cannot.

    The summary job is not the coverage job and has no .venv-native, so this
    cannot assume `sys.executable -m coverage` works. Same rule as the lint
    and typecheck ratchets: a gate that cannot run its tool must say so, not
    report nothing and pass.
    """
    for candidate in ([shutil.which("coverage")], [sys.executable, "-m", "coverage"]):
        if candidate[0] is None:
            continue
        if run(*candidate, "--version", check=False).returncode == 0:
            return list(candidate)
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


def python_percent(results: Path, suite: str, coverage: list[str]) -> float | None:
    """Combine one component's shards and return its line percentage."""
    shards = sorted(results.glob(f".coverage.{suite}.*"))
    if not shards:
        return None
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


def c_percent(results: Path, suite: str) -> float | None:
    """gcovr over the component's native sources, if any object was built."""
    source = C_SOURCES.get(suite)
    if source is None or not source.exists() or shutil.which("gcovr") is None:
        return None
    out = results / f"coverage-{suite}-native.xml"
    result = run(
        "gcovr", "-r", str(source), "--xml-pretty", "-o", str(out),
        "--json-summary-pretty", "--json-summary", str(results / f"c-{suite}.json"),
        check=False,
    )
    if result.returncode != 0 or not (results / f"c-{suite}.json").exists():
        print(result.stderr[-1000:], file=sys.stderr)
        return None
    summary = json.loads((results / f"c-{suite}.json").read_text())
    return round(summary.get("line_percent", 0.0), 2)


def rust_percent(results: Path) -> float | None:
    """Merge the .profraw the forked test processes wrote, and export."""
    profraw = sorted(results.glob("*.profraw"))
    objects = sorted(RUST_OBJECT.glob("rustylib*.so"))
    profdata = shutil.which("llvm-profdata") or shutil.which("cargo-profdata")
    cov = shutil.which("llvm-cov")
    if not profraw or not objects or not profdata or not cov:
        return None
    merged = results / "rust.profdata"
    if run(profdata, "merge", "-sparse", "-o", str(merged), *profraw,
           check=False).returncode != 0:
        return None
    export = run(cov, "export", str(objects[0]), f"--instr-profile={merged}",
                 "--format=text", "--summary-only", check=False)
    if export.returncode != 0:
        print(export.stderr[-1000:], file=sys.stderr)
        return None
    (results / "coverage-rust.json").write_text(export.stdout)
    totals = json.loads(export.stdout)["data"][0]["totals"]
    return round(totals["lines"]["percent"], 2)


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
        c = c_percent(args.results, suite)
        if c is not None:
            observed[f"{suite}:c"] = c
    rust = rust_percent(args.results)
    if rust is not None:
        observed["angr:rust"] = rust

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
