"""What `ci/lint.py` scores, and where it scores it from.

Both of these went wrong silently. A ratchet that reports a regression nobody
can act on and a ratchet that reports nothing are the same failure: the number
stops meaning what it says.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

CI = Path(__file__).resolve().parent.parent


def load(name: str) -> ModuleType:
    """`ci/<name>` as a module, by path rather than by import."""
    # ci/ on the path first: lint.py imports `vendored` as a sibling, which
    # only resolves when ci/ is the script's directory, as it is in CI.
    if str(CI) not in sys.path:
        sys.path.insert(0, str(CI))
    path = CI / name
    spec = importlib.util.spec_from_file_location(f"mono_ci_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path} does not load as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


# pylint's report, trimmed to the two lines this reads.
def report(statements: int, rating: str) -> str:
    return f"\n{statements} statements analysed.\n\nYour code has been rated at {rating}/10\n"


class ParseScoreTests(unittest.TestCase):
    """Reading a score out of what pylint printed."""

    def setUp(self) -> None:
        self.lint = load("lint.py")

    def test_the_score_is_the_score(self) -> None:
        self.assertEqual(self.lint.parse_score(report(53, "9.81")), 9.81)
        self.assertEqual(self.lint.parse_score(report(526, "10.00")), 10.0)
        self.assertEqual(self.lint.parse_score(report(12, "-32.50")), -32.5)

    def test_a_count_ending_in_zero_is_not_zero(self) -> None:
        """"30 statements analysed." contains "0 statements analysed."."""
        for statements in (10, 30, 100, 1230):
            self.assertEqual(
                self.lint.parse_score(report(statements, "9.67")),
                9.67,
                f"{statements} statements read as none",
            )

    def test_an_empty_file_still_scores_ten(self) -> None:
        """An empty __init__.py: no score printed, and upstream reads it as 10."""
        self.assertEqual(self.lint.parse_score("\n0 statements analysed.\n"), 10.0)

    def test_no_score_at_all(self) -> None:
        """A file pylint could not parse; the caller decides what that is worth."""
        self.assertIsNone(self.lint.parse_score("Traceback (most recent call last):\n"))


class ScoredFromTests(unittest.TestCase):
    """Which directory a file is scored from."""

    def setUp(self) -> None:
        self.lint = load("lint.py")
        self.lint.imported_components.cache_clear()
        self.addCleanup(self.lint.imported_components.cache_clear)
        self.tree = Path(tempfile.mkdtemp(prefix="mono-"))
        self.addCleanup(shutil.rmtree, self.tree, ignore_errors=True)
        (self.tree / "mono.json").write_text(
            json.dumps(
                {
                    "components": {"archinfo": {}, "cle": {}},
                    "fixtures": {"binaries": {}},
                }
            ),
            encoding="utf-8",
        )

    def test_a_component_is_scored_at_its_root(self) -> None:
        self.assertEqual(
            self.lint.scored_from(self.tree, "cle/tests/test_soname.py"),
            (self.tree / "cle", "tests/test_soname.py"),
        )

    def test_the_fixtures_are_a_repository_too(self) -> None:
        self.assertEqual(
            self.lint.scored_from(self.tree, "binaries/tests_src/x/build.py"),
            (self.tree / "binaries", "tests_src/x/build.py"),
        )

    def test_this_repositorys_own_files_stay_put(self) -> None:
        for path in ("ci/lint.py", "ci/tests/test_lint.py", "setup.py"):
            self.assertEqual(self.lint.scored_from(self.tree, path), (self.tree, path))

    def test_the_manifest_decides(self) -> None:
        """Not a top-level directory being present: the manifest says what was imported."""
        (self.tree / "nix").mkdir()
        self.assertEqual(
            self.lint.scored_from(self.tree, "nix/overlay.py"), (self.tree, "nix/overlay.py")
        )


if __name__ == "__main__":
    unittest.main()
