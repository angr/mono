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


def validate(config: dict) -> None:
    """Refuse a matrix that quietly drops a suite.

    Every one of these was accepted before, and each produced a green run
    over less than it looked like: `"shards": 0` deleted the entire angr
    suite, removing a suite from every job left it untested with nothing to
    say so, and a typo in a native entry passed here and failed much later.
    """
    known = set(config["suites"])

    covered: set[str] = set()
    for job in config["jobs"]:
        unknown = sorted(set(job["suites"]) - known)
        if unknown:
            raise SystemExit(f"{job['label']}: no such suite: {', '.join(unknown)}")
        if job.get("shards", 1) < 1:
            raise SystemExit(f"{job['label']}: shards must be at least 1")
        if job.get("shards", 1) > 1 and len(job["suites"]) != 1:
            raise SystemExit(f"{job['label']}: a sharded job runs exactly one suite")
        covered.update(job["suites"])

    missing = sorted(known - covered)
    if missing:
        raise SystemExit(f"no job runs: {', '.join(missing)}")

    for job in config["native"]:
        named = job.get("suites", []) + job.get("collect", [])
        if not named:
            raise SystemExit(f"native entry for {job['os']} names no suites")
        unknown = sorted(set(named) - known)
        if unknown:
            raise SystemExit(f"native {job['os']}: no such suite: {', '.join(unknown)}")


def entries() -> list[dict]:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    validate(config)

    out = []
    for job in config["jobs"]:
        suites = job["suites"]
        shards = job.get("shards", 1)
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
    parser.add_argument("--native", action="store_true", help="the non-Nix matrix instead")
    args = parser.parse_args()

    if args.native:
        config = json.loads((ROOT / "ci" / "suites.json").read_text())
        validate(config)
        native = []
        for job in config["native"]:
            suites = job.get("suites", [])
            collect = job.get("collect", [])
            native.append(
                {
                    **job,
                    "suites": " ".join(suites),
                    "collect": " ".join(collect),
                    "label": f"{'+'.join(suites + collect)} · {job['os']} py{job['python']}",
                    "id": f"{'-'.join(suites + collect)}-{job['os']}-py{job['python']}",
                }
            )
        print(json.dumps(native))
        return 0

    if args.list:
        for entry in entries():
            print(f"{entry['label']}\t{entry['suites']}\t{entry['shard']}/{entry['shards']}")
    else:
        print(json.dumps(entries()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
