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
COMPONENTS = ["archinfo", "pyvex", "pypcode", "claripy", "cle", "angr", "angr-management"]

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


def install(python_version: str) -> None:
    # pyvex compiles VEX out of ./vex and angr's tests read ../../binaries;
    # both are pinned in flake.lock rather than tracked here.
    run(sys.executable, ROOT / "ci" / "fetch-external.py")

    run("uv", "venv", "--python", python_version, str(VENV))

    targets = []
    for name in COMPONENTS:
        spec = str(ROOT / name)
        if name == "angr":
            spec += ANGR_EXTRAS
        targets.append(spec)

    env = {**os.environ, "VIRTUAL_ENV": str(VENV)}
    # Editable, so a suite tests this tree and not a copy of it.
    run("uv", "pip", "install", "--python", str(venv_python()), *(
        arg for target in targets for arg in ("--editable", target)
    ), env=env)
    run("uv", "pip", "install", "--python", str(venv_python()),
        "pytest", "pytest-xdist", "pytest-timeout", "pytest-split", env=env)


def link_dir(target: Path, link: Path) -> None:
    """Point `link` at `target` without copying it.

    Windows has no symlink for an unprivileged process, but it does have
    directory junctions, and `mklink /J` needs no privilege at all.
    """
    if link.exists():
        return
    link.parent.mkdir(parents=True, exist_ok=True)
    if os.name == "nt":
        subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)],
            check=True,
            capture_output=True,
        )
    else:
        link.symlink_to(target, target_is_directory=True)


def suite_config(name: str) -> dict:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    suite = config["suites"].get(name)
    if suite is None:
        raise SystemExit(f"unknown suite: {name}")
    return suite


def run_suite(name: str, shard: int, of: int, workers: str) -> int:
    """Run one suite from a directory that holds only its tests.

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

    results = ROOT / "test-results"
    results.mkdir(exist_ok=True)

    config = suite_config(name)
    args = [
        str(venv_python()), "-m", "pytest", "tests",
        "-p", "no:cacheprovider", "-q", "-rfEs", "-o", "addopts=",
        f"--rootdir={run_dir}",
        f"--junitxml={results / f'{name}-{shard}.xml'}",
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
    if config.get("qt"):
        env.setdefault("QT_QPA_PLATFORM", "minimal:enable_fonts")

    print(f"+ {' '.join(args)}", flush=True)
    return subprocess.run(args, cwd=run_dir, env=env, check=False).returncode


def smoke(name: str) -> int:
    """What upstream runs for angr on Windows and macOS: does it install and import."""
    module = name.replace("-", "")
    code = (
        f"import {module}; "
        f"print('{module}', getattr({module}, '__version__', 'ok'))"
    )
    print(f"+ {venv_python()} -c {code!r}", flush=True)
    return subprocess.run([str(venv_python()), "-c", code], check=False).returncode


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suites", nargs="*")
    parser.add_argument("--install", action="store_true")
    parser.add_argument(
        "--python",
        default=f"{sys.version_info.major}.{sys.version_info.minor}",
        help="Python version for the environment (default: the one running this)",
    )
    parser.add_argument("--smoke", action="store_true", help="import only, no suite")
    parser.add_argument("--shard", type=int, default=1)
    parser.add_argument("--of", type=int, default=1)
    parser.add_argument("--workers", default="auto")
    args = parser.parse_args()

    if args.install:
        install(args.python)

    failed = []
    for name in args.suites:
        rc = smoke(name) if args.smoke else run_suite(name, args.shard, args.of, args.workers)
        print(f"=== {name}: exit={rc}", flush=True)
        if rc != 0:
            failed.append(name)

    if failed:
        print(f"Failed: {' '.join(failed)}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
