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
import platform
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from exclusions import for_platform  # noqa: E402  pylint: disable=wrong-import-position

ROOT = Path(__file__).resolve().parent.parent
VENV = ROOT / ".venv-native"

# Install order matters: a component's build imports the ones under it --
# angr's unicornlib compiles against pyvex's headers.
CORE = ["archinfo", "pyvex", "pypcode", "claripy", "cle", "angr", "angr-management"]

# Upstream's dependents. `--ecosystem` adds them, because they are what makes
# a core API change fail before it is merged rather than after.
# Each dependent, and how far into CORE it actually needs. Four of them need
# angr; pysoot needs nothing from CORE at all -- jpype1 and frozendict, and
# `requires-python = ">=3.10"` against angr's ">=3.12". Treating them alike
# put angr in front of pysoot and made its 3.10 and 3.11 cells impossible to
# build, which is two of the twelve upstream runs.
ECOSYSTEM = {
    "pysoot": [],
    "tracer": ["angr"],
    "angr-platforms": ["angr"],
    "angrop": ["angr"],
    "phuzzer": ["angr"],
}

def angr_extras() -> str:
    """The extras upstream installs alongside angr.

    angr's own dev group is `angr[angrdb,keystone,unicorn,llm]`, and its
    tests import keystone -- `Exception: Keystone is not installed!` failed
    every Windows and macOS shard of its suite the first time they ran for
    real. keystone-engine has no aarch64 Linux wheel, which is the one place
    it has to be left out; upstream's angr-management marks it the same way.
    """
    extras = ["angrdb", "unicorn", "llm"]
    if not (sys.platform.startswith("linux") and platform.machine().lower() in
            ("aarch64", "arm64")):
        extras.insert(1, "keystone")
    return "[" + ",".join(extras) + "]"

# Set by --coverage. The coverage lane runs the same suites on the same OS and
# Python as a native entry does, so without this both write
# `pypcode-linux-x86_64-py3.12-1.xml` and the summary job's merge keeps one.
COVERAGE_LANE = False


def venv_python() -> Path:
    return VENV / ("Scripts" if os.name == "nt" else "bin") / (
        "python.exe" if os.name == "nt" else "python"
    )


def run(*args: str | Path, cwd: Path | None = None, env: dict | None = None) -> None:
    printable = " ".join(str(a) for a in args)
    print(f"+ {printable}", flush=True)
    subprocess.run([str(a) for a in args], cwd=cwd, env=env, check=True)


def needed_core(names: list[str]) -> list[str]:
    """The prefix of CORE an install has to cover for these suites.

    Install order is dependency order, so covering a component means covering
    everything under it -- the answer is always a prefix. Stopping at the
    deepest suite actually asked for is what makes x86_64 macOS possible:
    `core_affinity2` 0.16.1, a Rust dependency of angr, passes `&mut bool`
    where the Mach `thread_policy_get` binding wants `*mut u32`, so angr does
    not compile there at all. Upstream tests pyvex on macos-15-intel and does
    not test angr on any x86_64 macOS, and a job that wants pyvex should not
    have to build angr to get it.
    """
    if not names:
        return CORE
    # A dependent pulls the prefix out to whatever it needs, however shallow
    # the CORE names beside it are. Getting that wrong is quiet: the install
    # succeeds and the suite fails on an import.
    deepest = -1
    for n in names:
        if n not in CORE and n not in ECOSYSTEM:
            # A name nothing here recognises. Build everything rather than
            # guess: a typo that installs nothing fails much later, on an
            # import, and looks like a broken suite.
            return CORE
        if n in CORE:
            deepest = max(deepest, CORE.index(n))
        for dep in ECOSYSTEM.get(n, []):
            deepest = max(deepest, CORE.index(dep))
    # Below zero means every name asked for was a dependent that needs
    # nothing from CORE -- pysoot on its own. Not the same as asking for
    # nothing, which is handled above and means everything.
    return CORE[: deepest + 1]


def install(
    python_version: str,
    ecosystem: bool = False,
    only: list[str] | None = None,
    coverage: bool = False,
) -> None:
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

    # --clear so a second install replaces the environment rather than
    # refusing; the components install non-editable here, as upstream
    # installs them, so a stale one silently tests yesterday's source.
    run("uv", "venv", "--clear", "--python", python_version, str(VENV))
    env = {**os.environ, "VIRTUAL_ENV": str(VENV)}
    python = str(venv_python())

    # Editable under --coverage. gcov writes its .gcno beside the object it
    # compiled and its .gcda beside that at run time, and the instrumented
    # rustylib .so has to be the one still on disk when llvm-cov reads the
    # .profraw -- all of which a non-editable install throws away with the
    # temporary build directory. Non-editable stays the default, because that
    # is how upstream installs and a coverage build is not the build under
    # test.
    editable = ["--editable"] if coverage else []

    def install_one(*args: str) -> None:
        run("uv", "pip", "install", "--python", python, "--no-sources", *args, env=env)

    def install_component(*args: str) -> None:
        # Build isolation stays on: it only decides where the build backend
        # comes from, not where the compiled objects land, and turning it off
        # would mean pinning scikit-build-core, setuptools-rust and cmake into
        # this venv by hand.
        #
        # `--editable` goes immediately before the path, not at the front:
        # the callers that pass `-f <dir>` first produced
        # `uv pip install --editable -f <dir> <path>`, and uv read `-f` as the
        # value of `--editable`. That was every coverage cell except pypcode.
        install_one(*args[:-1], *editable, args[-1])

    # The test tooling first, so a component build cannot pick a different one.
    # The stubs are upstream's: pyright sees them there, and a ratchet that
    # does not is a ratchet that disagrees with the one it ports.
    install_one(
        "pytest", "pytest-xdist", "pytest-timeout", "pytest-split",
        # Windows and macOS only in effect; see run_suite.
        "pytest-rerunfailures",
        *(["pytest-cov", "coverage[toml]"] if coverage else []),
        "pytest-forked", "sortedcontainers-stubs>=2.4.3", "types-pefile",
        # cle's test_cclemory compiles a CFFI module at run time, and cffi
        # imports setuptools to do it. A uv venv has no setuptools; this
        # suite only passed because angr-management's dependencies happened
        # to pull one in, so trimming the install to what a job needs is what
        # made it visible.
        "setuptools",
    )

    core = CORE if ecosystem else needed_core(only or [])
    print(f"+ installing: {' '.join(core)}", flush=True)
    dist = str(ROOT / "pyvex" / "dist")

    if "archinfo" in core:
        install_component(str(ROOT / "archinfo"))
    if "pyvex" in core:
        run("uv", "build", "--out-dir", dist, str(ROOT / "pyvex"), env=env)
        install_component(str(ROOT / "pyvex"))
    if "pypcode" in core:
        install_component(str(ROOT / "pypcode"))
    if "claripy" in core:
        install_component(str(ROOT / "claripy"))
    if "cle" in core:
        install_component(str(ROOT / "cle"))
    if "angr" in core:
        install_component("-f", dist, str(ROOT / "angr") + angr_extras())

    # `--ecosystem` installs all of them; `--for` installs the ones a job
    # actually names. Without the second, a native entry naming angrop
    # installed the whole of CORE and then failed to import angrop, because
    # needed_core() only knows about CORE and everything else fell through to
    # "install everything".
    for name in ECOSYSTEM if ecosystem else [n for n in ECOSYSTEM if n in (only or [])]:
        if name == "phuzzer":
            # AFL itself, as a prebuilt wheel. nixpkgs does not carry it,
            # which is why phuzzer is a native-lane suite and not a Nix one.
            install_one("shellphish-afl")
        # `-f <dist>` only where the dependent actually needs angr, which is
        # the only thing that wants the locally built pyvex wheel. pysoot
        # needs nothing from CORE, so pyvex is never built for it and the
        # directory does not exist -- uv fails with "Failed to read
        # '--find-links' directory". That was all twelve pysoot cells; it
        # passed here only because this checkout had a pyvex/dist left over
        # from an earlier run.
        links = ["-f", dist] if ECOSYSTEM[name] else []
        install_component(*links, str(ROOT / name))

    # After angr, as upstream does, and with its llm extra: angr-management's
    # MCP suite skips itself unless fastmcp and uvicorn are importable.
    if "angr-management" in core:
        install_component("-f", dist, str(ROOT / "angr-management") + "[llm]")


def tag() -> str:
    """What distinguishes this lane's results from another's.

    Every lane wrote `<suite>-<shard>.xml`, and the summary job merges all of
    them into one directory -- so claripy's five runs across five platforms
    became one row, whichever landed last.

    The architecture is part of it, not just the platform. macos-15 and
    macos-15-intel are both `darwin`, both run pyvex, and both wrote
    `pyvex-darwin-py3.12-1.xml`; `merge-multiple: true` put the two on top of
    each other, and the summary job died parsing the result. Before it died
    it was quietly reporting one of those platforms twice.
    """
    version = f"py{sys.version_info.major}.{sys.version_info.minor}"
    lane = "-coverage" if COVERAGE_LANE else ""
    return f"{sys.platform}-{platform.machine().lower()}-{version}{lane}"


def suite_config(name: str) -> dict:
    config = json.loads((ROOT / "ci" / "suites.json").read_text())
    suite = config["suites"].get(name)
    if suite is None:
        raise SystemExit(f"unknown suite: {name}")
    return suite


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

    # And whatever else the suite names, as ci/run-suite.sh does. Only
    # angr-platforms uses this today -- its precompiled objects live at
    # `<tests>/../test_programs` -- but the two lanes reading the same
    # ci/suites.json and acting on different parts of it is how a suite comes
    # to pass in one and fail in the other for no reason anybody can see.
    for fixture in suite_config(name).get("fixtures") or []:
        if fixture.startswith("/") or ".." in Path(fixture).parts:
            raise SystemExit(
                f"{name}: fixture must be a path inside the component: {fixture}"
            )
        source = ROOT / name / fixture
        if not source.exists():
            raise SystemExit(f"{name}: no such fixture directory: {name}/{fixture}")
        link_dir(source, run_dir / fixture)
    return run_dir


def coverage_rcfile(name: str, module: str, results: Path) -> Path:
    """A config that records paths `coverage combine` can reconcile later.

    Two things the component's own pyproject cannot say. `relative_files`,
    because the suite runs from `.ci-run-native/<suite>/` and the absolute
    paths recorded there exist on no other machine -- combining the shards in
    the summary job failed with "No source for code". And a `[paths]` section
    mapping the run directory's `tests/` and the installed package back onto
    the component, so ten shards and an editable install are recognised as
    one tree.

    Written beside the results so the artifact carries it, and generated
    rather than committed into the component, which stays as upstream has it.
    """
    # Imported here, not at the top: this script runs under the matrix's
    # own Python, and pysoot's cells go down to 3.10, where tomllib does not
    # exist. Only the coverage lane calls this, and that lane is 3.12 and
    # 3.13 -- but a module-level import broke both 3.10 cells outright.
    import tomllib  # pylint: disable=import-outside-toplevel

    with (ROOT / name / "pyproject.toml").open("rb") as handle:
        declared = tomllib.load(handle).get("tool", {}).get("coverage", {})

    def section(title: str, extra: dict) -> str:
        merged = {**declared.get(title, {}), **extra}
        lines = [f"[{title}]"]
        for key, value in merged.items():
            if isinstance(value, list):
                lines.append(f"{key} =")
                lines += [f"    {item}" for item in value]
            elif isinstance(value, bool):
                lines.append(f"{key} = {'True' if value else 'False'}")
            else:
                lines.append(f"{key} = {value}")
        return "\n".join(lines) + "\n"

    # The component's own settings are carried over, not replaced. angr's
    # `patch = ["_exit"]` is what keeps a forked child's coverage from being
    # thrown away, and its exclude_lines are what upstream reports against;
    # writing a config from scratch quietly dropped both.
    #
    # `omit` on top: the protobuf stubs are generated at build time and
    # gitignored, so they exist in this job and not in the one that combines,
    # where coverage stops on "No source for code".
    omit = [*declared.get("run", {}).get("omit", []), "*/protos/*_pb2.py"]
    rcfile = results / f"coveragerc-{name}.ini"
    rcfile.write_text(
        section("run", {"relative_files": True, "omit": omit})
        + "\n"
        + section("report", {"omit": omit})
        + "\n"
        "[paths]\n"
        f"source =\n"
        f"    {name}/{module}/\n"
        f"    */{name}/{module}/\n"
        f"    */site-packages/{module}/\n"
        f"    {module}/\n"
        "tests =\n"
        f"    {name}/tests/\n"
        f"    */{name}/tests/\n"
        "    tests/\n"
    )
    return rcfile


def run_suite(
    name: str, shard: int, of: int, workers: str, coverage: bool = False
) -> int:
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
    # Named exclusions, as ci/run-suite.sh applies them. Dormant while no
    # native entry runs angr for real, and wrong the moment one does.
    excluded = for_platform(config, name, lane="coverage" if coverage else "test")
    args = [
        str(venv_python()), "-m", "pytest", "tests",
        "-p", "no:cacheprovider", "-q", "-rfEs", "-o", "addopts=",
        f"--rootdir={run_dir}",
        f"--junitxml={results / f'{name}-{tag()}-{shard}.xml'}",
        # As upstream pins it: Codecov's test-results ingestion reads
        # the legacy family, not pytest's xunit2 default.
        "-o",
        "junit_family=legacy",
        # As the Nix lane sets it. pytest-timeout is installed here and was
        # never used, so a wedged test had nothing between it and the job's
        # ninety-minute ceiling -- which kills the runner and leaves no junit
        # to say which test it was.
        "--timeout=1800",
        "--timeout-method=thread",
        "--durations=25",
    ]
    if workers == "auto" and sys.platform == "win32":
        # Two, not one per core. Linux runs every test in its own process
        # (--forked), so a test that corrupts memory cannot reach its
        # neighbours; Windows has no fork(2), so an xdist worker runs many
        # tests in one process and a fault cascades through everything it
        # picks up afterwards -- 26 failures in a shard, all the same
        # `access violation`, and 52 reruns that could not help because the
        # process was already poisoned. Fewer workers means less concurrent
        # unicorn and VEX state on a runner with four cores and 16 GB.
        workers = "2"
    if workers not in ("0", "1"):
        args += ["-n", workers]
    if sys.platform in ("win32", "darwin"):
        # angr's native engines crash an xdist worker every so often on these
        # two platforms -- `worker 'gw2' crashed while running
        # test_veritesting_a`, one failure in 1356 -- and upstream's own
        # nightly fails the same way on the same tests. A rerun distinguishes
        # that from a real failure, which fails every attempt, instead of
        # deselecting a test that passes nearly always. Linux does not need
        # it and does not get it.
        args += [
            "--reruns", "2",
            # Both shapes the instability takes. A crashed xdist worker is
            # reported as "worker 'gwN' crashed"; unicorn faulting inside the
            # process comes back as an OSError naming an access violation,
            # and one of those cascades through every later test the worker
            # picks up -- the same shard gave 36 failures, then 1, then 35
            # across three runs. A real failure still fails all three
            # attempts, which is how test_similarity_fauxware was identified
            # as deterministic rather than flaky.
            "--only-rerun", "crashed",
            "--only-rerun", "access violation",
        ]

    if config.get("forked") and os.name != "nt" and sys.platform != "darwin":
        # pytest-forked needs fork(2); Windows has none. macOS has it and
        # must not use it here: forking a process that has started a JVM
        # (jpype, for pysoot) or touched CoreFoundation aborts, and angr's
        # macOS shards died on `Fatal Python error: Aborted` until this.
        # Upstream agrees -- its nightly runs Windows and macOS as
        # `pytest -n auto --splits N --group M` with no --forked at all, and
        # only the Linux container lane forks.
        args += ["--forked"]
    for test, reason in excluded:
        print(f"{name}: EXCLUDED {test}\n    {reason}", flush=True)
        args += ["--deselect", test]

    if coverage:
        # Explicitly, not through the component's addopts: `-o addopts=` above
        # wipes those, which is deliberate (pypcode's name pytest-cov flags
        # that the ordinary lane has no plugin for) and means coverage has to
        # be asked for here.
        module = config.get("module") or name.replace("-", "")
        args += [
            f"--cov={module}",
            "--cov=tests",
            f"--cov-config={coverage_rcfile(name, module, results)}",
            "--cov-report=",
        ]
    if of > 1:
        args += ["--splits", str(of), "--group", str(shard)]
        durations = ROOT / "ci" / "durations" / f"{name}.json"
        if durations.exists():
            args += ["--durations-path", str(durations)]

    env = {**os.environ, "CI": "true", "PYTHONDONTWRITEBYTECODE": "1",
           "RTDB_BASE": str(results / "rtdb")}
    if coverage:
        # One database per suite per lane per shard, all under test-results so
        # the artifact carries them. coverage's default lands in the run
        # directory, which the next stage() removes.
        env["COVERAGE_FILE"] = str(results / f".coverage.{name}.{tag()}.{shard}")
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
    parser.add_argument(
        "--coverage",
        action="store_true",
        help="install editable and measure coverage, as upstream's coverage.yml does",
    )
    parser.add_argument(
        "--print-python",
        action="store_true",
        help="print the environment's interpreter and exit; a caller in a "
        "shell should not have to know that Windows puts it in Scripts/",
    )
    parser.add_argument(
        "--for",
        dest="wanted",
        default="",
        help="space-separated suites this environment has to serve "
        "(default: every component)",
    )
    args = parser.parse_args()

    global COVERAGE_LANE
    COVERAGE_LANE = args.coverage

    if args.print_python:
        print(venv_python())
        return 0

    if args.install:
        install(
            args.python,
            ecosystem=args.ecosystem,
            only=args.wanted.split(),
            coverage=args.coverage,
        )

    failed = []
    for name in args.suites:
        rc = (
            collect(name)
            if args.collect
            else run_suite(name, args.shard, args.of, args.workers, args.coverage)
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
