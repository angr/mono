#!/usr/bin/env python3
"""Expand ci/suites.json into the GitHub Actions test matrix.

    ci/matrix.py            # JSON array of matrix entries
    ci/matrix.py --list     # one job per line, for running the same set locally
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def entries() -> list[dict]:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    known = set(config["suites"])

    out = []
    for job in config["jobs"]:
        suites = job["suites"]
        unknown = [s for s in suites if s not in known]
        if unknown:
            raise SystemExit(f"{job['label']}: no such suite: {', '.join(unknown)}")
        shards = job.get("shards", 1)
        if shards > 1 and len(suites) != 1:
            raise SystemExit(f"{job['label']}: a sharded job runs exactly one suite")
        for shard in range(1, shards + 1):
            out.append(
                {
                    "label": job["label"] if shards == 1 else f"{job['label']} {shard}/{shards}",
                    # Artifact names cannot hold the spaces and slashes a
                    # human-readable label wants.
                    "id": job["label"] if shards == 1 else f"{job['label']}-{shard}-of-{shards}",
                    "suites": " ".join(suites),
                    "shard": shard,
                    "shards": shards,
                }
            )
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="plain text, one job per line")
    args = parser.parse_args()

    if args.list:
        for entry in entries():
            print(f"{entry['label']}\t{entry['suites']}\t{entry['shard']}/{entry['shards']}")
    else:
        print(json.dumps(entries()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
