"""What protects a suite from a test that faults the interpreter.

`ci/run-native.py` gives every suite one of two things: `--forked`, which puts
each test in its own process, or a retry for the xdist worker a fault takes
down. It used to choose the retry by platform, which left the suites
`ci/suites.json` marks `forked: false` with neither on Linux -- so a Qt
segfault in angr-management has turned three jobs red there, on three
different branches. These tests pin the invariant that made that possible:
exactly one protection, for every suite, on every platform.
"""

from __future__ import annotations

import importlib.util
import json
import sys
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

CI = Path(__file__).resolve().parent.parent

# Every platform run-native.py runs on, as `sys.platform` and `os.name` say
# it. Windows is the only one where `os.name` is not "posix".
PLATFORMS = [("linux", "posix"), ("darwin", "posix"), ("win32", "nt")]


def load(name: str) -> ModuleType:
    """`ci/<name>` as a module, by path rather than by import."""
    # ci/ on the path first, as it is for a script run as ci/run-native.py:
    # the module imports `exclusions` as a sibling.
    if str(CI) not in sys.path:
        sys.path.insert(0, str(CI))
    path = CI / name
    spec = importlib.util.spec_from_file_location(f"mono_ci_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path} does not load as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def suites() -> dict[str, dict]:
    with (CI / "suites.json").open() as handle:
        return json.load(handle)["suites"]


class Isolation(unittest.TestCase):
    """`isolation()` over every suite the tree defines."""

    def setUp(self) -> None:
        self.native = load("run-native.py")
        self.suites = suites()
        # The tree these tests are written against: something has to fork,
        # and something has to not, or they would pass over an empty set.
        self.assertTrue(any(c.get("forked") for c in self.suites.values()))
        self.assertTrue(any(not c.get("forked") for c in self.suites.values()))

    def isolation(self, config: dict, platform: str, osname: str) -> list[str]:
        with mock.patch.object(sys, "platform", platform), mock.patch.object(
            self.native.os, "name", osname
        ):
            return self.native.isolation(config)

    def test_every_suite_is_protected_somehow(self) -> None:
        """Neither protection is the state that produced the false red."""
        for name, config in self.suites.items():
            for platform, osname in PLATFORMS:
                with self.subTest(suite=name, platform=platform):
                    args = self.isolation(config, platform, osname)
                    self.assertTrue(
                        "--forked" in args or "--reruns" in args,
                        f"{name} on {platform} gets no protection at all",
                    )

    def test_never_both(self) -> None:
        """A forked test cannot crash a worker, so it is not also retried."""
        for name, config in self.suites.items():
            for platform, osname in PLATFORMS:
                with self.subTest(suite=name, platform=platform):
                    args = self.isolation(config, platform, osname)
                    self.assertNotEqual("--forked" in args, "--reruns" in args)

    def test_unforked_suites_are_retried_on_linux(self) -> None:
        """The hole this closes: `forked: false` and Linux, where it landed."""
        unforked = [n for n, c in self.suites.items() if not c.get("forked")]
        self.assertIn("angr-management", unforked)
        for name in unforked:
            with self.subTest(suite=name):
                args = self.isolation(self.suites[name], "linux", "posix")
                self.assertEqual(args[:2], ["--reruns", "2"])

    def test_nothing_forks_away_from_linux(self) -> None:
        """Forking after CoreFoundation or a JVM starts aborts; see forks()."""
        for name, config in self.suites.items():
            for platform, osname in [("darwin", "posix"), ("win32", "nt")]:
                with self.subTest(suite=name, platform=platform):
                    self.assertNotIn(
                        "--forked", self.isolation(config, platform, osname)
                    )

    def test_a_retry_never_hides_an_ordinary_failure(self) -> None:
        """--reruns is always filtered, so only a crash-shaped failure repeats.

        pytest-rerunfailures reschedules a crashed xdist worker on the rerun
        budget alone, without consulting these regexes -- they decide what is
        retried among failures raised inside a test, and an assertion matches
        neither.
        """
        for name, config in self.suites.items():
            for platform, osname in PLATFORMS:
                with self.subTest(suite=name, platform=platform):
                    args = self.isolation(config, platform, osname)
                    if "--reruns" not in args:
                        continue
                    self.assertEqual(
                        [a for a, b in zip(args, args[1:]) if a == "--only-rerun"],
                        ["--only-rerun", "--only-rerun"],
                    )
                    self.assertEqual(
                        [b for a, b in zip(args, args[1:]) if a == "--only-rerun"],
                        ["crashed", "access violation"],
                    )


class Forks(unittest.TestCase):
    """`forks()` on its own, since `isolation()` is defined in terms of it."""

    def setUp(self) -> None:
        self.native = load("run-native.py")

    def forks(self, config: dict, platform: str, osname: str) -> bool:
        with mock.patch.object(sys, "platform", platform), mock.patch.object(
            self.native.os, "name", osname
        ):
            return self.native.forks(config)

    def test_linux_follows_the_suite(self) -> None:
        self.assertTrue(self.forks({"forked": True}, "linux", "posix"))
        self.assertFalse(self.forks({"forked": False}, "linux", "posix"))
        self.assertFalse(self.forks({}, "linux", "posix"))

    def test_elsewhere_never_forks(self) -> None:
        for platform, osname in [("darwin", "posix"), ("win32", "nt")]:
            with self.subTest(platform=platform):
                self.assertFalse(self.forks({"forked": True}, platform, osname))


if __name__ == "__main__":
    unittest.main()
