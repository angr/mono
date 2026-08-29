#!/usr/bin/env python3
"""`ci/import.py`, mostly the rollup path.

The ordinary path is exercised every time somebody re-imports; the
`--from-trees` path is exercised once a rollup, by a script in another
repository, and its output is a manifest nobody reads until a gate reading it
does the wrong thing. That is how angr/mono#4 happened: the entry it built by
hand had no `vendored_submodules`, so `ci/vendored.py` reported nothing
vendored and `ci/pre-commit.sh` linted the 181 VEX sources it exists to strip.
"""

from __future__ import annotations

import importlib.util
import json
import shutil
import sys
import tempfile
import unittest
from pathlib import Path
from typing import Any

CI = Path(__file__).resolve().parents[1]
if str(CI) not in sys.path:
    sys.path.insert(0, str(CI))

# The sibling module, reachable through the sys.path line above and
# not through anything pylint can see from here.
import vendored  # noqa: E402  pylint: disable=import-error,wrong-import-position

VEX_COMMIT = "46d7aa5e18b1c6a2a2fc4beeadb9722ac67919da"


def load_importer() -> Any:
    """`ci/import.py` as a module.

    It cannot be imported by name -- `import` is a keyword -- which is also
    why nothing else in this tree imports it.
    """
    spec = importlib.util.spec_from_file_location("mono_import", CI / "import.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)


class FromTrees(unittest.TestCase):
    """The rollup import path, against a tree shaped like one an assembler writes."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.tmp, True)
        self.trees = self.tmp / "trees"
        self.mono = self.tmp / "mono"
        self.mono.mkdir()
        self.importer = load_importer()
        self.importer.ROOT = self.mono

        write(self.trees / "pyvex" / "pyvex" / "__init__.py", "")
        write(self.trees / "pyvex" / "vex" / "priv" / "main_main.c", "/* VEX */\n")
        write(self.trees / "pyvex" / ".gitmodules", '[submodule "vex"]\n\tpath = vex\n')
        write(self.trees / "pyvex" / ".github" / "workflows" / "ci.yml", "on: push\n")
        write(
            self.trees / "pyvex" / "pyproject.toml",
            "[tool.uv.sources]\n"
            'archinfo = { git = "https://github.com/angr/archinfo" }\n',
        )
        self.rollup = {
            "schema": 1,
            "components": {
                "pyvex": {
                    "base": "ab18a834ba4a5320c3415eff971092ef2b940779",
                    "applied": [{"number": 564}, {"number": 576}],
                    "submodules": {"vex": VEX_COMMIT},
                }
            },
        }

    def run_import(self):
        write(self.trees / "rollup.json", json.dumps(self.rollup))
        manifest_path = self.mono / "mono.json"
        manifest = {"schema": 1, "components": {}}
        self.assertEqual(
            self.importer.from_trees(self.trees, ["pyvex"], manifest, manifest_path), 0
        )
        return json.loads(manifest_path.read_text()), manifest_path

    def test_records_the_vendored_submodule(self):
        """The defect: a rollup manifest that does not say what it vendored."""
        manifest, manifest_path = self.run_import()
        self.assertEqual(
            manifest["components"]["pyvex"]["vendored_submodules"], {"vex": VEX_COMMIT}
        )
        # What every downstream gate actually asks.
        self.assertEqual(vendored.for_component("pyvex", manifest_path), ["vex"])
        self.assertEqual(vendored.paths(manifest_path), ["pyvex/vex"])
        self.assertTrue(vendored.covers("pyvex/vex/priv/main_main.c", ["pyvex/vex"]))

    def test_agrees_with_the_ordinary_path(self):
        """Both paths describe a component with the same keys.

        The two drifted because each built its entry by hand. They share one
        builder now, and this is the assertion that keeps them sharing it.
        """
        manifest, _ = self.run_import()
        ordinary = self.importer.manifest_entry(
            "pyvex",
            commit="ab18a834ba4a5320c3415eff971092ef2b940779",
            committed_at="2026-08-01T00:00:00+00:00",
            subject="upstream head",
            workspaced=["archinfo"],
            vendored={"vex": VEX_COMMIT},
        )
        rolled = manifest["components"]["pyvex"]
        self.assertEqual(set(ordinary) - set(rolled), set())
        # A rollup says one thing more, and only one.
        self.assertEqual(set(rolled) - set(ordinary), {"rolled_up"})
        self.assertEqual(rolled["rolled_up"], [564, 576])

    def test_applies_the_same_exclusions_and_rewrite(self):
        self.run_import()
        self.assertTrue((self.mono / "pyvex" / "vex" / "priv" / "main_main.c").exists())
        self.assertFalse((self.mono / "pyvex" / ".github").exists())
        self.assertFalse((self.mono / "pyvex" / ".gitmodules").exists())
        self.assertIn(
            "archinfo = { workspace = true }",
            (self.mono / "pyvex" / "pyproject.toml").read_text(),
        )

    def test_refuses_a_tree_whose_manifest_lost_the_pin(self):
        """Vendored sources with no record of where they came from."""
        del self.rollup["components"]["pyvex"]["submodules"]
        with self.assertRaises(SystemExit) as caught:
            self.run_import()
        self.assertIn("vex", str(caught.exception))

    def test_refuses_a_tree_that_never_checked_the_submodule_out(self):
        shutil.rmtree(self.trees / "pyvex" / "vex")
        with self.assertRaises(SystemExit) as caught:
            self.run_import()
        self.assertIn("vex", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
