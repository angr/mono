#!/usr/bin/env python3
"""Measure this shard's C and Rust coverage, where the inputs still exist.

gcov writes its `.gcda` beside the object it compiled, and llvm-cov reads a
profile against the instrumented shared object that produced it. Neither
survives into the artifact the coverage job uploads, so both have to be
turned into numbers here, in the job that built them, rather than in
`summary` from the leftovers.

    ci/native-coverage.py angr --out test-results/native-angr-1.json
"""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

C_SOURCES = {"angr": ROOT / "angr" / "native", "pypcode": ROOT / "pypcode"}
RUST_OBJECT = ROOT / "angr" / "angr"


def run(*args, check: bool = False) -> subprocess.CompletedProcess:
    return subprocess.run(
        [str(a) for a in args], capture_output=True, text=True, check=check
    )


def c_percent(suite: str, results: Path) -> float | None:
    """gcovr over the component's native sources, or a reason it could not.

    Every `return None` here used to be silent, and "nothing measured" is
    indistinguishable from "measured zero" in a report. Each one says which
    precondition failed, because that is the difference between a component
    with no C and a build that was never instrumented.
    """
    source = C_SOURCES.get(suite)
    if source is None:
        print(f"{suite}: no C sources recorded", file=sys.stderr)
        return None
    if not source.exists():
        print(f"{suite}: {source} does not exist", file=sys.stderr)
        return None
    if shutil.which("gcovr") is None:
        print(f"{suite}: gcovr is not on PATH", file=sys.stderr)
        return None
    notes = len(list(source.rglob("*.gcno")))
    data = len(list(source.rglob("*.gcda")))
    print(f"{suite}: {notes} .gcno and {data} .gcda under {source}", file=sys.stderr)
    if not data:
        # .gcno without .gcda means it was compiled instrumented and never
        # run; neither means the build ignored CFLAGS altogether.
        print(
            f"{suite}: no gcov data -- "
            + ("the instrumented objects were never executed" if notes
               else "the build was not instrumented"),
            file=sys.stderr,
        )
        return None
    summary = results / f"c-{suite}.json"
    out = run("gcovr", "-r", str(source), "--json-summary-pretty",
              "--json-summary", str(summary))
    if out.returncode != 0 or not summary.exists():
        print(out.stderr[-1000:], file=sys.stderr)
        return None
    return round(json.loads(summary.read_text()).get("line_percent", 0.0), 2)


def rust_percent(results: Path) -> float | None:
    """Merge this shard's profiles, or say which piece was missing."""
    profraw = sorted(results.glob("*.profraw"))
    objects = sorted(RUST_OBJECT.glob("rustylib*.so"))
    profdata = shutil.which("llvm-profdata")
    cov = shutil.which("llvm-cov")
    missing = [
        name
        for name, present in (
            (".profraw files", profraw),
            ("rustylib*.so", objects),
            ("llvm-profdata", profdata),
            ("llvm-cov", cov),
        )
        if not present
    ]
    if missing:
        print(f"rust: missing {', '.join(missing)}", file=sys.stderr)
        return None
    merged = results / "rust.profdata"
    if run(profdata, "merge", "-sparse", "-o", merged, *profraw).returncode != 0:
        return None
    export = run(cov, "export", objects[0], f"--instr-profile={merged}",
                 "--format=text", "--summary-only")
    if export.returncode != 0:
        print(export.stderr[-1000:], file=sys.stderr)
        return None
    totals = json.loads(export.stdout)["data"][0]["totals"]
    return round(totals["lines"]["percent"], 2)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--results", type=Path, default=Path("test-results"))
    args = parser.parse_args()

    measured = {}
    c = c_percent(args.suite, args.results)
    if c is not None:
        measured[f"{args.suite}:c"] = c
    if args.suite == "angr":
        rust = rust_percent(args.results)
        if rust is not None:
            measured["angr:rust"] = rust

    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(measured, indent=2) + "\n")
    print(f"{args.out}: {measured or 'nothing measured'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
