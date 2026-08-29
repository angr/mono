"""What `ci/run-shape.py` counts, and what it refuses.

The defect it exists for is an absence: when `warm` fails, the fifteen `test`
cells are never created, so the run is green over 82 of 96 jobs and nothing in
it disagrees. These tests pin the two readings that matter -- a complete run
passes, and a run missing a lane fails naming that lane.
"""

from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType

CI = Path(__file__).resolve().parent.parent


def load(name: str) -> ModuleType:
    """`ci/<name>` as a module, by path rather than by import."""
    # ci/ on the path first: run-shape.py imports `matrix` as a sibling, which
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


class ExpectedNames(unittest.TestCase):
    """The set of job names the guard demands the run contain."""

    def setUp(self) -> None:
        self.shape = load("run-shape.py")
        self.matrix = load("matrix.py")

    def test_every_matrix_label_is_expected(self) -> None:
        """The three lanes, under the names ci.yml gives their jobs."""
        expected = self.shape.expected()
        self.assertEqual(len(expected), len(set(expected)), "duplicate job name")
        for entry in self.matrix.entries():
            self.assertIn(entry["label"], expected)
        for entry in self.matrix.native_entries():
            self.assertIn(entry["label"], expected)
        # The coverage lane is the one whose job name is not its label.
        for entry in self.matrix.coverage_entries():
            self.assertIn(f"coverage · {entry['label']}", expected)

    def test_a_complete_run_passes(self) -> None:
        present = set(self.shape.expected()) | {"Summary", "Plan", "Warm the store"}
        self.assertEqual(self.shape.missing(self.shape.expected(), present), [])

    def test_an_uncreated_lane_is_named(self) -> None:
        """What a failed `warm` does: the cells are absent, not red."""
        expected = self.shape.expected()
        present = set(expected)
        nix = [entry["label"] for entry in self.matrix.entries()]
        present -= set(nix)
        self.assertEqual(self.shape.missing(expected, present), sorted(nix))

    def test_extra_jobs_are_not_an_error(self) -> None:
        """The run has jobs no matrix names -- Plan, warm, docs, Summary."""
        present = set(self.shape.expected()) | {"a job nothing here expects"}
        self.assertEqual(self.shape.missing(self.shape.expected(), present), [])


if __name__ == "__main__":
    unittest.main()
