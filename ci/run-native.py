#!/usr/bin/env python3
"""Run component suites without Nix, the way upstream's own CI does.

The Nix lane is the better test -- it pins everything down to the C library --
and it only exists on Linux. Windows and macOS are where upstream gates, so
they get the same suites through `uv`, against the same component sources and
the same external commits, because both lanes read `flake.lock`.

    ci/run-native.py --install
    ci/run-native.py archinfo pyvex pypcode claripy cle
    ci/run-native.py angr --smoke

`--install` builds the environment; without it the script assumes one is
already there, so a job can install once and run several suites.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv-native"

# Install order matters: a component's build imports the ones under it --
# angr's unicornlib compiles against pyvex's headers.
CORE = ["archinfo", "pyvex", "pypcode", "claripy", "cle", "angr", "angr-management"]

# Upstream's dependents. `--ecosystem` adds them, because they are what makes
# a core API change fail before it is merged rather than after.
ECOSYSTEM = ["pysoot", "tracer", "angr-platforms", "angrop", "phuzzer"]

# The extras upstream installs alongside angr.
ANGR_EXTRAS = "[angrdb,unicorn,llm]"


def venv_python() -> Path:
    return VENV / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python"
    )


def run(*args: str, cwd: Path | None = None, env: dict | None = None) -> None:
    printable = " ".join(str(a) for a in args)
    print(f"+ {printable}", flush=True)
    subprocess.run([str(a) for a in args], cwd=cwd, env=env, check=True)


def install(python_version: str, ecosystem: bool = False) -> None:
    """Build the environment the way ci-settings' ga-build.sh builds it.

    Component by component, in dependency order, each with `--no-sources` so
    every `[tool.uv.sources]` entry is ignored: the sibling git URLs, angr's
    `angr-data = { git = ..., branch = "master" }`, all of it. The components
    resolve to the ones installed here and the third-party packages resolve
    from PyPI against the pins the components actually declare.

    angr build-requires pyvex, and with sources off there is no
    `pyvex==9.3.4.dev0` on PyPI to satisfy that, so pyvex is built into a
    wheel first and angr is pointed at it with `--find-links`. Upstream hits
    the same wall and solves it the same way.
    """
    # pyvex compiles VEX out of ./vex and the suites read ../../binaries;
    # both are pinned in flake.lock rather than tracked here.
    run(sys.executable, ROOT / "ci" / "fetch-external.py")

    run("uv", "venv", "--python", python_version, str(VENV))
    env = {**os.environ, "VIRTUAL_ENV": str(VENV)}
    python = str(venv_python())

    def install_one(*args: str) -> None:
        run("uv", "pip", "install", "--python", python, "--no-sources", *args, env=env)

    # The test tooling first, so a component build cannot pick a different one.
    # The stubs are upstream's: pyright sees them there, and a ratchet that
    # does not is a ratchet that disagrees with the one it ports.
    install_one(
        "pytest", "pytest-xdist", "pytest-timeout", "pytest-split",
        "pytest-forked", "sortedcontainers-stubs>=2.4.3", "types-pefile",
    )

    install_one(str(ROOT / "archinfo"))
    run("uv", "build", "--out-dir", str(ROOT / "pyvex" / "dist"), str(ROOT / "pyvex"), env=env)
    install_one(str(ROOT / "pyvex"))
    install_one(str(ROOT / "pypcode"))
    install_one(str(ROOT / "claripy"))
    install_one(str(ROOT / "cle"))
    install_one("-f", str(ROOT / "pyvex" / "dist"), str(ROOT / "angr") + ANGR_EXTRAS)

    if ecosystem:
        for name in ECOSYSTEM:
            install_one("-f", str(ROOT / "pyvex" / "dist"), str(ROOT / name))

    # After angr, as upstream does, and with its llm extra: angr-management's
    # MCP suite skips itself unless fastmcp and uvicorn are importable.
    install_one("-f", str(ROOT / "pyvex" / "dist"), str(ROOT / "angr-management") + "[llm]")


def tag() -> str:
    """What distinguishes this lane's results from another's.

    Every lane wrote `<suite>-<shard>.xml`, and the summary job merges all of
    them into one directory -- so claripy's five runs across five platforms
    became one row, whichever landed last.
    """
    return f"{sys.platform}-py{sys.version_info.major}.{sys.version_info.minor}"


def suite_config(name: str) -> dict:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    suite = config["suites"].get(name)
    if suite is None:
        raise SystemExit(f"unknown suite: {name}")
    return suite


def stage(name: str) -> Path:
    """A directory holding only this suite's tests, with fixtures beside it.

    The component's source sits next to its tests in this tree, and pytest
    would put that directory on sys.path -- importing a source tree with no
    compiled extension in it rather than what was installed. Same reason as
    ci/run-suite.sh; see the note there.
    """
    run_dir = ROOT / ".ci-run-native" / name
    if run_dir.exists():
        shutil.rmtree(run_dir)
    run_dir.mkdir(parents=True)
    shutil.copytree(ROOT / name / "tests", run_dir / "tests")

    # Every suite resolves fixtures as `<its tests dir>/../../binaries`. The
    # tests are copied rather than linked -- see link_dir for why -- so that
    # path now points beside the run directories, and the fixtures have to be
    # reachable from there too.
    link_dir(ROOT / "binaries", ROOT / ".ci-run-native" / "binaries")
    return run_dir


def run_suite(name: str, shard: int, of: int, workers: str) -> int:
    """Run one suite from a directory that holds only its tests.

    The component's source sits next to its tests in this tree, and pytest
    would put that directory on sys.path -- importing a source tree with no
    compiled extension in it rather than what was installed. Same reason as
    ci/run-suite.sh; see the note there.
    """
    run_dir = stage(name)

    results = ROOT / "test-results"
    results.mkdir(exist_ok=True)

    config = suite_config(name)
    args = [
        str(venv_python()), "-m", "pytest", "tests",
        "-p", "no:cacheprovider", "-q", "-rfEs", "-o", "addopts=",
        f"--rootdir={run_dir}",
        f"--junitxml={results / f'{name}-{tag()}-{shard}.xml'}",
        "--durations=25",
    ]
    if workers not in ("0", "1"):
        args += ["-n", workers]
    if config.get("forked") and os.name != "nt":
        # pytest-forked needs fork(2); Windows has none.
        args += ["--forked"]
    if of > 1:
        args += ["--splits", str(of), "--group", str(shard)]
        durations = ROOT / "ci" / "durations" / f"{name}.json"
        if durations.exists():
            args += ["--durations-path", str(durations)]

    env = {**os.environ, "CI": "true", "PYTHONDONTWRITEBYTECODE": "1",
           "RTDB_BASE": str(results / "rtdb")}
    if config.get("qt") and sys.platform.startswith("linux"):
        # Only on Linux, where a CI runner genuinely has no display. Upstream
        # sets this nowhere in its own test job, and forcing the minimal
        # platform on macOS changes Qt's focus handling: test_combo_prop
        # double-clicks a property and asks for focusWidget(), which comes
        # back None there and a QComboBox on the real platform.
        env.setdefault("QT_QPA_PLATFORM", "minimal:enable_fonts")

    print(f"+ {' '.join(args)}", flush=True)
    return subprocess.run(args, cwd=run_dir, env=env, check=False).returncode


def collect(name: str) -> int:
    """Upstream's `installation` job: `uv run pytest --collect-only tests`.

    Importing the package proves almost nothing -- collection imports all 326
    of angr's test modules and every symbol they pull out of it, which is what
    actually catches a refactor that does not survive the platform.
    """
    run_dir = stage(name)
    args = [
        str(venv_python()), "-m", "pytest", "tests",
        "--collect-only", "-q", "-p", "no:cacheprovider", "-o", "addopts=",
        f"--rootdir={run_dir}",
    ]
    print(f"+ {' '.join(args)}", flush=True)
    env = {**os.environ, "CI": "true", "PYTHONDONTWRITEBYTECODE": "1"}
    return subprocess.run(args, cwd=run_dir, env=env, check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suites", nargs="*")
    parser.add_argument("--install", action="store_true")
    parser.add_argument(
        "--ecosystem",
        action="store_true",
        help="also install the dependents upstream tests core changes against",
    )
    parser.add_argument(
        "--python",
        default=f"{sys.version_info.major}.{sys.version_info.minor}",
        help="Python version for the environment (default: the one running this)",
    )
    parser.add_argument(
        "--collect", action="store_true", help="collect the suite, do not run it"
    )
    parser.add_argument("--shard", type=int, default=1)
    parser.add_argument("--of", type=int, default=1)
    parser.add_argument("--workers", default="auto")
    args = parser.parse_args()

    if args.install:
        install(args.python, ecosystem=args.ecosystem)

    failed = []
    for name in args.suites:
        rc = (
            collect(name)
            if args.collect
            else run_suite(name, args.shard, args.of, args.workers)
        )
        print(f"=== {name}: exit={rc}", flush=True)
        if rc != 0:
            failed.append(name)

    if failed:
        print(f"Failed: {' '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
