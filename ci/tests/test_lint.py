#!/usr/bin/env python3
"""`ci/lint.py`, and where it stands when it scores a file.

pylint asks isort whether an import is first-party, isort answers from the
working directory, and this repository's working directory has `archinfo/`
in it. So a component file that imports a sibling before pytest picked up
`C0411 wrong-import-order` here and nowhere else, and four cle test files
lost the ratchet on that alone -- angr/mono#4.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

CI = Path(__file__).resolve().parents[1]
if str(CI) not in sys.path:
    sys.path.insert(0, str(CI))

# The sibling module, reachable through the sys.path line above and
# not through anything pylint can see from here.
import lint  # noqa: E402  pylint: disable=import-error,wrong-import-position

# A component file that imports a sibling component and then a third-party
# package. Upstream this is ordinary and clean; the import order is only
# wrong if `archinfo` is first-party, which it is only here.
COMPONENT_FILE = '''"""A test in a component."""

from __future__ import annotations

import os

import archinfo
import pytest


def test_it():
    """It."""
    assert os.name and archinfo and pytest
'''


def have_pylint() -> bool:
    return (
        subprocess.run(
            [sys.executable, "-m", "pylint", "--version"],
            capture_output=True,
            check=False,
        ).returncode
        == 0
    )


class ScoreRoot(unittest.TestCase):
    """Which directory a file is scored from."""

    def setUp(self):
        self.tree = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tree, True)
        for name in ("archinfo", "cle", "binaries", "ci"):
            (self.tree / name).mkdir()
        (self.tree / "mono.json").write_text(
            json.dumps(
                {
                    "schema": 1,
                    "components": {"archinfo": {}, "cle": {}},
                    "fixtures": {"binaries": {}},
                }
            )
        )

    def test_a_component_file_is_scored_from_its_component(self):
        self.assertEqual(
            lint.score_root(self.tree, "cle/tests/test_soname.py"), self.tree / "cle"
        )
        self.assertEqual(
            lint.score_root(self.tree, "binaries/tests/conftest.py"),
            self.tree / "binaries",
        )

    def test_everything_else_is_scored_from_the_tree(self):
        # `ci/` is this repository's own code, and this repository is its root.
        self.assertEqual(lint.score_root(self.tree, "ci/lint.py"), self.tree)
        self.assertEqual(lint.score_root(self.tree, "setup.py"), self.tree)
        # A component the manifest does not know about is not a component.
        (self.tree / "vendor").mkdir()
        self.assertEqual(lint.score_root(self.tree, "vendor/thing.py"), self.tree)

    def test_a_tree_with_no_manifest_still_scores(self):
        (self.tree / "mono.json").unlink()
        self.assertEqual(lint.score_root(self.tree, "cle/tests/test_soname.py"), self.tree)


@unittest.skipUnless(have_pylint(), "pylint is not installed")
class SiblingImports(unittest.TestCase):
    """The score itself, through pylint, with mono's own pylintrc."""

    def setUp(self):
        self.tree = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tree, True)
        (self.tree / "archinfo").mkdir()
        (self.tree / "archinfo" / "__init__.py").write_text('"""archinfo."""\n')
        self.target = self.tree / "cle" / "tests" / "test_sibling_import.py"
        self.target.parent.mkdir(parents=True)
        self.target.write_text(COMPONENT_FILE)
        (self.tree / "mono.json").write_text(
            json.dumps({"schema": 1, "components": {"archinfo": {}, "cle": {}}})
        )

    def test_the_monorepo_root_invents_a_wrong_import_order(self):
        """The defect, as a number: the same file, two working directories."""
        from_mono = lint.score(self.target, self.tree)
        from_component = lint.score(self.target, self.tree / "cle")
        assert from_mono is not None and from_component is not None
        self.assertLess(
            from_mono,
            from_component,
            "scoring from the mono root should be the thing that costs points",
        )

    def test_the_gate_scores_it_from_the_component(self):
        self.assertEqual(
            lint.score(self.target, lint.score_root(self.tree, "cle/tests/x.py")),
            lint.score(self.target, self.tree / "cle"),
        )


if __name__ == "__main__":
    unittest.main()
