#!/usr/bin/env python3
"""Turn a directory of junit XML files into one markdown table.

    ci/summarize.py test-results

Written for the CI job summary, but it reads the same files ci/run-suite.sh
leaves behind locally, so it also answers "what did that run actually do".
"""

from __future__ import annotations

import argparse
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path


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


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("results", type=Path, nargs="?", default=Path("test-results"))
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

    print("| suite | tests | passed | failed | errors | skipped | slowest shard |")
    print("| --- | ---: | ---: | ---: | ---: | ---: | ---: |")
    totals = [0, 0, 0, 0, 0.0]
    for suite, (tests, failures, errors, skipped, time, slowest) in sorted(per_suite.items()):
        passed = tests - failures - errors - skipped
        print(
            f"| {suite} | {tests} | {passed} | {failures} | {errors} | {skipped} "
            f"| {slowest / 60:.1f} min |"
        )
        for i, value in enumerate((tests, failures, errors, skipped)):
            totals[i] += value
        totals[4] = max(totals[4], slowest)
    tests, failures, errors, skipped = (int(v) for v in totals[:4])
    print(
        f"| **total** | {tests} | {tests - failures - errors - skipped} | {failures} "
        f"| {errors} | {skipped} | {totals[4] / 60:.1f} min |"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
