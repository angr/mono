#!/usr/bin/env python3
"""Expand ci/suites.json into the GitHub Actions test matrix.

    ci/matrix.py            # JSON array of matrix entries
    ci/matrix.py --list     # one job per line, for running the same set locally
"""

from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# The two native fields that reach a `run:` string and a `runs-on:`. Every
# other field this file emits is either a suite name checked against
# suites.json or an integer.
RUNNERS = {
    "ubuntu-22.04",
    "ubuntu-24.04",
    "ubuntu-24.04-arm",
    "ubuntu-latest",
    "windows-2022",
    "windows-2025",
    "windows-latest",
    "macos-14",
    "macos-15",
    "macos-15-intel",
    "macos-26",
    "macos-latest",
}
# `\Z` not `$`, which also matches before a trailing newline, and ASCII
# digits only -- `\d` is Unicode by default, so "3.\uff11\uff12" passed.
PYTHON = re.compile(r"^3\.\d{1,2}\Z", re.ASCII)

# Suites the native lane cannot serve, and why. Both need something the Nix
# test shell provides and a uv venv does not: pysoot needs a JVM on PATH and
# JAVA_HOME, tracer needs a 32-bit loader for the ELFs it runs under qemu.
# Naming one in a `native` entry would install, run, and fail a long way from
# the cause, so it is refused here instead.
NIX_ONLY = {
    "tracer": "needs a 32-bit loader; the native lane sets no QEMU_LD_PREFIX",
    # 74 of angrop's assertions are `Keystone is not installed!`. The Nix test
    # environment carries keystone-engine; adding it to the native install
    # would put it on every job including linux-aarch64, where it has no
    # wheel. Covered in the Nix lane, 122 passing.
    "angrop": "needs keystone-engine, which has no aarch64 Linux wheel",
}

# The reverse: suites the Nix lane cannot serve. phuzzer needs
# shellphish-afl, a prebuilt AFL that nixpkgs does not carry and pip does.
NATIVE_ONLY = {"phuzzer": "needs shellphish-afl, which nixpkgs does not carry"}


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

    missing = sorted(known - covered - set(NATIVE_ONLY))
    if missing:
        raise SystemExit(f"no job runs: {', '.join(missing)}")
    for suite in sorted(set(config["jobs"] and covered) & set(NATIVE_ONLY)):
        raise SystemExit(f"{suite} is native-lane only: {NATIVE_ONLY[suite]}")

    for job in config.get("coverage", []):
        if job["suite"] not in known:
            raise SystemExit(f"coverage: no such suite: {job['suite']}")
        if job.get("shards", 1) < 1:
            raise SystemExit(f"coverage {job['suite']}: shards must be at least 1")

    for job in config["native"]:
        named = job.get("suites", []) + job.get("collect", [])
        # `with` is installed but not run: angr's twenty-one
        # skipUnless(pysoot) tests need pysoot importable wherever angr's
        # suite runs, and pysoot's own suite is a separate matter.
        for extra in job.get("with", []):
            if extra not in known:
                raise SystemExit(f"native {job['os']}: no such component: {extra}")
        if not named:
            raise SystemExit(f"native entry for {job['os']} names no suites")
        unknown = sorted(set(named) - known)
        if unknown:
            raise SystemExit(f"native {job['os']}: no such suite: {', '.join(unknown)}")
        # `os` and `python` were the two fields nothing here looked at, and
        # both land in the workflow -- one as `runs-on:`, one in a `run:`
        # command. A gate that exists to refuse a matrix that quietly does
        # the wrong thing should not skip the fields that choose what runs.
        if job["os"] not in RUNNERS:
            raise SystemExit(f"native {job['os']}: not a known runner label")
        # The same two checks the Nix jobs get. A native entry could set
        # shards: 0 and delete its own suite, or shard two suites at once and
        # run each of them twice.
        if job.get("shards", 1) < 1:
            raise SystemExit(f"native {job['os']}: shards must be at least 1")
        if job.get("shards", 1) > 1 and len(named) != 1:
            raise SystemExit(f"native {job['os']}: a sharded job runs exactly one suite")
        if not PYTHON.match(str(job["python"])):
            raise SystemExit(f"native {job['os']}: bad python {job['python']!r}")
        for suite in named:
            if suite in NIX_ONLY:
                raise SystemExit(
                    f"native {job['os']}: {suite} is Nix-lane only: {NIX_ONLY[suite]}"
                )


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
    parser.add_argument("--coverage", action="store_true", help="the coverage matrix")
    args = parser.parse_args()

    if args.coverage:
        config = json.loads((ROOT / "ci" / "suites.json").read_text())
        validate(config)
        out = []
        for job in config.get("coverage", []):
            suite = job["suite"]
            shards = job.get("shards", 1)
            for shard in range(1, shards + 1):
                out.append(
                    {
                        "suite": suite,
                        "components": " ".join([suite, *job.get("with", [])]),
                        "shard": shard,
                        "shards": shards,
                        "label": suite + (f" {shard}/{shards}" if shards > 1 else ""),
                        "id": f"{suite}-{shard}-of-{shards}",
                    }
                )
        print(json.dumps(out))
        return 0

    if args.native:
        config = json.loads((ROOT / "ci" / "suites.json").read_text())
        validate(config)
        native = []
        for job in config["native"]:
            suites = job.get("suites", [])
            collect = job.get("collect", [])
            # Sharded, like the Nix jobs. This branch had no shard expansion
            # at all, so `--shard/--of` never reached run-native.py and
            # pytest-split never engaged off Nix -- which is fine while every
            # native entry is one shard and wrong the moment one is not. Two
            # shards would also have collided on `results-<id>`, and the
            # second upload would have failed the job.
            shards = job.get("shards", 1)
            name = "+".join(suites + collect)
            base = f"{'-'.join(suites + collect)}-{job['os']}-py{job['python']}"
            for shard in range(1, shards + 1):
                native.append(
                    {
                        **job,
                        "suites": " ".join(suites),
                        "collect": " ".join(collect),
                        # What the environment has to serve, so a job need not
                        # build components no suite of its own will import.
                        "components": " ".join(
                            dict.fromkeys(suites + collect + job.get("with", []))
                        ),
                        "shard": shard,
                        "shards": shards,
                        "label": f"{name} · {job['os']} py{job['python']}"
                        + (f" {shard}/{shards}" if shards > 1 else ""),
                        "id": base + (f"-{shard}-of-{shards}" if shards > 1 else ""),
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
