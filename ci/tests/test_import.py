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
import os
import shutil
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path
from types import ModuleType
from unittest import mock

CI = Path(__file__).resolve().parent.parent

# A commit the merge of several pyvex pull requests' VEX branches ended up at.
# It exists only in the assembler's mirror, which is why the tree that carries
# the files is the only thing that can say where they came from.
VEX_COMMIT = "46d7aa5e18b1c6a2a2fc4beeadb9722ac67919da"
RESOURCES = {
    "angrmanagement/resources/flirt_signatures": "1" * 40,
    "angrmanagement/resources/library_docs": "2" * 40,
}


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

    def run_import(self, component: str = "pyvex") -> dict:
        """Import the assembled trees and return the manifest they produced."""
        manifest: dict = {"schema": 1, "components": {}}
        with contextlib.redirect_stderr(io.StringIO()):
            self.importer.from_trees(
                self.trees, [component], manifest, self.manifest_path
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

    def management_tree(self) -> Path:
        component = self.trees / "angr-management"
        for path in (*RESOURCES, "vendor/nested/code"):
            (component / path).mkdir(parents=True)
            (component / path / "data.txt").write_text(path + "\n", encoding="utf-8")
        (self.trees / "rollup.json").write_text(json.dumps({
            "components": {"angr-management": {
                "base": "a" * 40,
                "submodules": {**RESOURCES, "vendor/nested/code": VEX_COMMIT},
            }}
        }), encoding="utf-8")
        return component

    def test_excluded_resources_keep_pins_and_nested_sources_keep_content(self) -> None:
        self.management_tree()
        entry = self.run_import("angr-management")["components"]["angr-management"]
        self.assertEqual(entry["excluded_submodules"], RESOURCES)
        self.assertEqual(entry["excluded"], sorted(RESOURCES))
        self.assertEqual(entry["vendored_submodules"], {"vendor/nested/code": VEX_COMMIT})
        for path in RESOURCES:
            self.assertFalse((self.root / "angr-management" / path).exists())
        self.assertEqual(
            (self.root / "angr-management/vendor/nested/code/data.txt").read_text(),
            "vendor/nested/code\n",
        )
        self.assertEqual(
            self.vendored.for_component("angr-management", self.manifest_path),
            ["vendor/nested/code"],
        )

    def test_excluded_resource_without_exact_provenance_stops_import(self) -> None:
        self.management_tree()
        manifest_path = self.trees / "rollup.json"
        manifest = json.loads(manifest_path.read_text())
        pins = manifest["components"]["angr-management"]["submodules"]
        path = next(iter(RESOURCES))
        for pin in (None, "", "main", "a" * 39):
            with self.subTest(pin=pin):
                pins[path] = pin
                manifest_path.write_text(json.dumps(manifest))
                with self.assertRaisesRegex(SystemExit, "needs an exact commit"):
                    self.run_import("angr-management")
        del pins[path]
        manifest_path.write_text(json.dumps(manifest))
        with self.assertRaisesRegex(SystemExit, "needs an exact commit"):
            self.run_import("angr-management")
        self.assertFalse((self.root / "angr-management").exists())

    def test_plain_import_records_gitlinks_without_resource_checkouts(self) -> None:
        component = self.root.parent / "upstream"
        component.mkdir()

        def git(*args: str) -> None:
            subprocess.run(["git", "-C", str(component), *args], check=True,
                           capture_output=True, text=True)

        git("init", "--quiet")
        git("config", "user.name", "Test")
        git("config", "user.email", "test@example.invalid")
        (component / "source.txt").write_text("component source\n")
        git("add", "source.txt")
        for path, sha in RESOURCES.items():
            git("update-index", "--add", "--cacheinfo", f"160000,{sha},{path}")
        git("-c", "commit.gpgsign=false", "commit", "--quiet", "-m", "Resource pins")
        with mock.patch.object(self.importer, "fetch", return_value=component), \
                mock.patch.object(sys, "argv", ["import.py", "--component", "angr-management"]), \
                contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(self.importer.main(), 0)
        entry = json.loads(self.manifest_path.read_text())["components"]["angr-management"]
        self.assertEqual(entry["excluded_submodules"], RESOURCES)
        self.assertNotIn("vendored_submodules", entry)
        self.assertEqual((self.root / "angr-management/source.txt").read_text(), "component source\n")
        for path in RESOURCES:
            self.assertFalse((self.root / "angr-management" / path).exists())

    def run_bundle_resources(self) -> subprocess.CompletedProcess:
        workflow = (CI.parent / ".github/workflows/ci.yml").read_text()
        step = workflow.split("      - name: Resource submodules\n", 1)[1]
        step = step.split("      # `-m PyInstaller`", 1)[0]
        script = textwrap.dedent(step.split("        run: |\n", 1)[1])
        directory = self.root / "angr-management/angrmanagement/resources"
        directory.mkdir(parents=True, exist_ok=True)
        bin_dir = self.root / "bin"
        bin_dir.mkdir(exist_ok=True)
        git = bin_dir / "git"
        git.write_text(f"#!{sys.executable}\n" +
                       "import json, os, sys\n"
                       "with open(os.environ['GIT_CALLS'], 'a') as f:\n"
                       "    f.write(json.dumps(sys.argv[1:]) + '\\n')\n")
        git.chmod(0o755)
        env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}",
               "VENV_PY": sys.executable, "GIT_CALLS": str(self.root / "git-calls")}
        return subprocess.run(["bash", "-e", "-c", script], cwd=directory, env=env,
                              capture_output=True, text=True)

    def test_bundle_checks_out_the_imported_resource_pins(self) -> None:
        self.management_tree()
        self.run_import("angr-management")
        result = self.run_bundle_resources()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.root / "git-calls").read_text().splitlines()]
        self.assertEqual(calls, [
            ["clone", "--filter=blob:none", "https://github.com/angr/flirt_signatures", "flirt_signatures"],
            ["-C", "flirt_signatures", "checkout", "--detach", "--quiet", RESOURCES[next(iter(RESOURCES))]],
            ["clone", "--filter=blob:none", "https://github.com/angr/library_docs", "library_docs"],
            ["-C", "library_docs", "checkout", "--detach", "--quiet", RESOURCES["angrmanagement/resources/library_docs"]],
        ])

    def test_bundle_missing_pin_stops_before_fetching(self) -> None:
        self.management_tree()
        manifest = self.run_import("angr-management")
        del manifest["components"]["angr-management"]["excluded_submodules"][next(iter(RESOURCES))]
        self.manifest_path.write_text(json.dumps(manifest))
        result = self.run_bundle_resources()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("KeyError", result.stderr)
        self.assertFalse((self.root / "git-calls").exists())

    def test_tracked_manifest_supplies_the_bundle_pins(self) -> None:
        shutil.copyfile(CI.parent / "mono.json", self.manifest_path)
        manifest = json.loads(self.manifest_path.read_text())
        pins = manifest["components"]["angr-management"]["excluded_submodules"]
        self.assertEqual(set(pins), set(RESOURCES))
        result = self.run_bundle_resources()
        self.assertEqual(result.returncode, 0, result.stderr)
        calls = [json.loads(line) for line in (self.root / "git-calls").read_text().splitlines()]
        self.assertEqual([call[-1] for call in calls if call[0] == "-C"], [pins[path] for path in RESOURCES])

    def test_bundle_refuses_a_branch_instead_of_a_commit(self) -> None:
        self.management_tree()
        manifest = self.run_import("angr-management")
        manifest["components"]["angr-management"]["excluded_submodules"][next(iter(RESOURCES))] = "main"
        self.manifest_path.write_text(json.dumps(manifest))
        result = self.run_bundle_resources()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("need exact commits", result.stderr)
        self.assertFalse((self.root / "git-calls").exists())


if __name__ == "__main__":
    unittest.main()
