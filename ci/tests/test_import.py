"""What `ci/import.py` writes into mono.json, and what reads it back.

The rollup path is the one with no CI of its own: `--from-trees` runs once per
rollup, on a branch, and everything downstream of the manifest it writes is a
gate that reports on something else. When it stopped recording the vendored
submodule, what went red was pyvex's pre-commit job over 112 VEX sources.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

CI = Path(__file__).resolve().parent.parent

# A commit the merge of several pyvex pull requests' VEX branches ended up at.
# It exists only in the assembler's mirror, which is why the tree that carries
# the files is the only thing that can say where they came from.
VEX_COMMIT = "46d7aa5e18b1c6a2a2fc4beeadb9722ac67919da"


def load(name: str) -> ModuleType:
    """`ci/<name>` as a module, since `import.py` is not a name that imports."""
    path = CI / name
    spec = importlib.util.spec_from_file_location(f"mono_ci_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path} does not load as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FromTreesTests(unittest.TestCase):
    """`ci/import.py --from-trees`, as `rollup.sh` calls it."""

    def setUp(self) -> None:
        self.importer = load("import.py")
        self.vendored = load("vendored.py")
        tmp = Path(tempfile.mkdtemp(prefix="mono-"))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        self.root = tmp / "mono"
        self.root.mkdir()
        # The importer writes to a module-level ROOT; a test gets its own.
        setattr(self.importer, "ROOT", self.root)
        self.trees = tmp / "trees"
        self.manifest_path = self.root / "mono.json"

    def assemble(self, with_vex: bool = True) -> None:
        """An assembled pyvex tree, in the shape the rollup skill exports one.

        The submodule is ordinary files by this point and `.gitmodules` still
        names it, which is exactly why nothing downstream can tell the drop
        from pyvex's own sources without being told.
        """
        component = self.trees / "pyvex"
        (component / "pyvex").mkdir(parents=True)
        (component / "pyvex" / "__init__.py").write_text("", encoding="utf-8")
        (component / ".gitmodules").write_text(
            '[submodule "vex"]\n\tpath = vex\n', encoding="utf-8"
        )
        if with_vex:
            (component / "vex" / "priv").mkdir(parents=True)
            (component / "vex" / "priv" / "guest_arm_toIR.c").write_text(
                "/* vendored */\n", encoding="utf-8"
            )
        (self.trees / "rollup.json").write_text(
            json.dumps(
                {
                    "components": {
                        "pyvex": {
                            "base": "a" * 40,
                            "applied": [{"number": 564}, {"number": 576}],
                            "submodules": {"vex": VEX_COMMIT} if with_vex else {},
                        }
                    }
                }
            ),
            encoding="utf-8",
        )

    def run_import(self) -> dict:
        """Import the assembled trees and return the manifest they produced."""
        manifest: dict = {"schema": 1, "components": {}}
        with contextlib.redirect_stderr(io.StringIO()):
            self.importer.from_trees(
                self.trees, ["pyvex"], manifest, self.manifest_path
            )
        return json.loads(self.manifest_path.read_text(encoding="utf-8"))

    def test_the_manifest_records_the_submodule(self) -> None:
        self.assemble()
        entry = self.run_import()["components"]["pyvex"]
        self.assertEqual(entry["vendored_submodules"], {"vex": VEX_COMMIT})
        self.assertEqual(entry["rolled_up"], [564, 576])

    def test_the_gates_can_see_the_drop(self) -> None:
        """The point of the key: `ci/vendored.py` is what the gates ask."""
        self.assemble()
        self.run_import()
        self.assertEqual(
            self.vendored.for_component("pyvex", self.manifest_path), ["vex"]
        )
        self.assertEqual(self.vendored.paths(self.manifest_path), ["pyvex/vex"])

    def test_a_tree_that_forgot_to_say(self) -> None:
        """A tree carrying the files and no record of them still records them."""
        self.assemble()
        (self.trees / "rollup.json").write_text(
            json.dumps({"components": {"pyvex": {"base": "a" * 40}}}),
            encoding="utf-8",
        )
        entry = self.run_import()["components"]["pyvex"]
        self.assertEqual(entry["vendored_submodules"], {"vex": ""})

    def test_a_missing_submodule_stops_the_import(self) -> None:
        """Half a pyvex pull request is the failure this exists to prevent."""
        self.assemble(with_vex=False)
        with self.assertRaises(SystemExit):
            self.run_import()

    def test_gitmodules_stays_out_of_the_tree(self) -> None:
        self.assemble()
        self.run_import()
        self.assertFalse((self.root / "pyvex" / ".gitmodules").exists())
        self.assertTrue((self.root / "pyvex" / "vex" / "priv").is_dir())


if __name__ == "__main__":
    unittest.main()
