#!/usr/bin/env python3
"""Check that the run created every job the matrices name.

    gh api --paginate \
      "repos/$REPO/actions/runs/$RUN/jobs?per_page=100" --jq '.jobs[].name' \
      | ci/run-shape.py

A matrix job's cells do not exist until its `needs:` resolve. When `warm`
fails, the fifteen `test` cells are therefore never created -- not red, not
skipped, absent -- and the run shows 82 jobs where the workflow means 96.
Nothing inside the run can see that from `needs.*.result`, which reads
`skipped` for an uncreated matrix and for a plain job alike, so two rollups
were triaged as complete results over less than half the Nix lane
(angr/mono#10).

So compare the names the run actually has against the labels `ci/matrix.py`
emits and fail on a missing one. An absent lane then reads as a failure
saying which lane, instead of as a smaller number nobody counted.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

# A sibling in ci/, imported the way ci/lint.py imports `vendored`: the
# script's own directory is on the path when it runs as `ci/run-shape.py`.
import matrix


def expected() -> list[str]:
    """Every job name the three matrices produce.

    The prefixes mirror the `name:` templates in .github/workflows/ci.yml:
    the `test` and `native` jobs are named by their label alone, the coverage
    lane prefixes `coverage · `. A template change here is a template change
    there; nothing else derives one from the other.
    """
    names = [entry["label"] for entry in matrix.entries()]
    names += [entry["label"] for entry in matrix.native_entries()]
    names += [f"coverage · {entry['label']}" for entry in matrix.coverage_entries()]
    return names


def missing(names: list[str], present: set[str]) -> list[str]:
    return sorted({name for name in names if name not in present})


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "names",
        nargs="?",
        help="file of job names, one per line; stdin by default",
    )
    args = parser.parse_args()

    text = (
        Path(args.names).read_text(encoding="utf-8") if args.names else sys.stdin.read()
    )
    present = {line.strip() for line in text.splitlines() if line.strip()}
    if not present:
        # An empty listing is the failure this guard exists to catch wearing
        # the guard's own clothes: a token without `actions: read`, or a
        # paginated call that errored into an empty pipe, would otherwise
        # report every lane missing and read as a catastrophe.
        print("no job names were read; the jobs listing was empty", file=sys.stderr)
        return 1

    gone = missing(expected(), present)
    if gone:
        print(
            f"{len(gone)} job(s) the matrices name were never created in this run:",
            file=sys.stderr,
        )
        for name in gone:
            print(f"  {name}", file=sys.stderr)
        print(
            "A matrix cell is not created at all when its `needs:` fail, so "
            "these did not run and nothing else in the run says so.",
            file=sys.stderr,
        )
        return 1

    print(f"all {len(expected())} matrix jobs were created")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
