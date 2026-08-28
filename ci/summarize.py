#!/usr/bin/env python3
"""Turn a directory of junit XML files into one markdown table.

    ci/summarize.py test-results

Written for the CI job summary, but it reads the same files ci/run-suite.sh
leaves behind locally, so it also answers "what did that run actually do".
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def counts(path: Path) -> tuple[int, int, int, int, float]:
    root = ET.parse(path).getroot()
    suites = [root] if root.tag == "testsuite" else list(root)

    def total(attr: str) -> int:
        return sum(int(s.get(attr, 0)) for s in suites)

    tests, failures, errors, skipped = (
        total("tests"),
        total("failures"),
        total("errors"),
        total("skipped"),
    )
    time = sum(float(s.get("time", 0)) for s in suites)
    return tests, failures, errors, skipped, time


# Results are tagged `<suite>-<lane>` so two platforms do not collide. The
# Nix lane is the one that runs every suite in full, on one platform, against
# a pinned closure -- so it is the lane whose skip count means something
# stable. A native lane runs a subset, sometimes only a collection, and skips
# for platform reasons that are not a regression.
NIX_LANE = "-nix"


def base_suite(name: str) -> str:
    head, sep, _ = name.partition(NIX_LANE)
    return head if sep else name.rsplit("-linux-", 1)[0].rsplit("-darwin-", 1)[0]


def deselected() -> dict[str, int]:
    """How many tests each suite names in ci/suites.json's `excluded` map."""
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    return {
        name: len(suite.get("excluded", {}) or {})
        for name, suite in config["suites"].items()
    }


def ratchet(per_suite: dict, path: Path, update: bool) -> int:
    """Fail when a suite skips more tests than it is budgeted.

    Only the Nix lane, which runs every suite in full on one platform against
    a pinned closure. A skip is not a failure to pytest, so a dependency that
    stops being importable turns tests off and leaves the run green. That
    happened twice here: six architectures inside a PASSED test once the
    fixture symlink was missing, and thirty-nine tests for as long as pysoot
    and tracer sat in the tree unpackaged. Neither was caught by CI; both were
    caught by a person reading counts across commits.

    So the counts are written down. Raising a budget is a deliberate edit with
    a diff, which is the whole point -- the same shape as the pylint and
    pyright ratchets, and for the same reason.
    """
    observed = {
        suite[: -len(NIX_LANE)]: int(row[3])
        for suite, row in per_suite.items()
        if suite.endswith(NIX_LANE)
    }
    if not observed:
        print(
            f"\n{path}: no Nix-lane results in this run; nothing to check.",
            file=sys.stderr,
        )
        return 0

    if update:
        path.write_text(json.dumps(dict(sorted(observed.items())), indent=2) + "\n")
        print(f"\nwrote {path}")
        return 0

    budget = json.loads(path.read_text())
    regressions = []
    for suite, count in sorted(observed.items()):
        allowed = budget.get(suite)
        if allowed is None:
            regressions.append(f"  {suite}: {count} skipped, no budget recorded")
        elif count > allowed:
            regressions.append(f"  {suite}: {count} skipped, budget {allowed}")

    if regressions:
        print(f"\nmore tests skipped than {path} allows:", file=sys.stderr)
        for line in regressions:
            print(line, file=sys.stderr)
        print(
            "\nA suite that skips is a suite that did not run. Find the "
            "dependency that went missing, or raise the budget on purpose.",
            file=sys.stderr,
        )
        return 1
    print(f"\nno suite skipped more than {path} allows.")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=Path("test-results"))
    parser.add_argument(
        "--baseline",
        type=Path,
        help="ci/skips.json: fail if any suite skips more than it records",
    )
    parser.add_argument(
        "--update-baseline",
        action="store_true",
        help="rewrite the baseline from this run instead of checking it",
    )
    args = parser.parse_args()

    per_suite: dict[str, list[int | float]] = defaultdict(lambda: [0, 0, 0, 0, 0.0, 0.0])
    for xml in sorted(args.results.rglob("*.xml")):
        # <suite>-<shard>.xml
        suite = xml.stem.rsplit("-", 1)[0]
        tests, failures, errors, skipped, time = counts(xml)
        row = per_suite[suite]
        row[0] += tests
        row[1] += failures
        row[2] += errors
        row[3] += skipped
        row[4] += time
        # The shards run at the same time, so the suite's contribution to wall
        # time is its slowest shard, not the sum.
        row[5] = max(row[5], time)

    if not per_suite:
        print("No test results found.")
        # Every lane that reaches here uploads XML, so an empty
        # directory means a suite vanished rather than passed.
        return 1

    excluded = deselected()

    print("| suite | tests | passed | failed | errors | skipped | deselected | slowest shard |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |")
    totals = [0, 0, 0, 0, 0.0]
    for suite, (tests, failures, errors, skipped, time, slowest) in sorted(per_suite.items()):
        passed = tests - failures - errors - skipped
        print(
            f"| {suite} | {tests} | {passed} | {failures} | {errors} | {skipped} "
            f"| {excluded.get(base_suite(suite), 0)} | {slowest / 60:.1f} min |"
        )
        for i, value in enumerate((tests, failures, errors, skipped)):
            totals[i] += value
        totals[4] = max(totals[4], slowest)
    tests, failures, errors, skipped = (int(v) for v in totals[:4])
    print(
        f"| **total** | {tests} | {tests - failures - errors - skipped} | {failures} "
        f"| {errors} | {skipped} | {sum(excluded.values())} | {totals[4] / 60:.1f} min |"
    )

    if args.baseline:
        return ratchet(per_suite, args.baseline, args.update_baseline)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
