"""Which copy of a sibling the detached component resolves against.

The bug this pins is not a crash. `ci/unworkspace.py` rewrote every workspace
source to upstream's master, so the Pyodide lane tested cle against an
archinfo the monorepo tree does not contain and reported the disagreement as
cle's. Nothing in the run said which archinfo it had.
"""

from __future__ import annotations

import importlib.util
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import ModuleType

CI = Path(__file__).resolve().parent.parent

CLE = """\
[project]
name = "cle"
dependencies = ["archinfo==9.3.4.dev0", "pyvex==9.3.4.dev0"]

[tool.uv.sources]
archinfo = { workspace = true }
pyvex = { workspace = true }
bitarray = { index = "pyodide" }
"""


def load(name: str) -> ModuleType:
    """`ci/<name>` as a module, by path rather than by import."""
    if str(CI) not in sys.path:
        sys.path.insert(0, str(CI))
    path = CI / name
    spec = importlib.util.spec_from_file_location(f"mono_ci_{path.stem}", path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"{path} does not load as a module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree(root: Path, siblings: list[str]) -> Path:
    """A detached cle, with `siblings` extracted beside it."""
    component = root / "cle"
    component.mkdir()
    (component / "pyproject.toml").write_text(CLE, encoding="utf-8")
    for name in siblings:
        (root / name).mkdir()
        (root / name / "pyproject.toml").write_text(
            f'[project]\nname = "{name}"\n', encoding="utf-8"
        )
    return component


def run(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(CI / "unworkspace.py"), *args],
        capture_output=True,
        text=True,
        check=False,
    )


class Rewrite(unittest.TestCase):
    """What each workspace source becomes."""

    def test_a_sibling_in_the_tree_becomes_a_path_source(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            component = tree(Path(tmp), ["archinfo", "pyvex"])
            result = run(str(component))
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (component / "pyproject.toml").read_text(encoding="utf-8")
            self.assertIn('archinfo = { path = "../archinfo" }', text)
            self.assertIn('pyvex = { path = "../pyvex" }', text)
            self.assertNotIn("github.com/angr", text)
            # Sources that are not workspace sources are left alone.
            self.assertIn('bitarray = { index = "pyodide" }', text)

    def test_a_missing_sibling_still_falls_back_to_upstream(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            component = tree(Path(tmp), ["archinfo"])
            result = run(str(component))
            self.assertEqual(result.returncode, 0, result.stderr)
            text = (component / "pyproject.toml").read_text(encoding="utf-8")
            self.assertIn('archinfo = { path = "../archinfo" }', text)
            self.assertIn(
                'pyvex = { git = "https://github.com/angr/pyvex.git", branch = "master" }',
                text,
            )
            self.assertIn("NOT what gets tested", result.stderr)

    def test_require_siblings_refuses_the_silent_fallback(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            component = tree(Path(tmp), ["archinfo"])
            result = run(str(component), "--require-siblings")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("pyvex", result.stderr)

    def test_every_sibling_present_satisfies_require_siblings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            component = tree(Path(tmp), ["archinfo", "pyvex"])
            result = run(str(component), "--require-siblings")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_a_bare_directory_is_not_a_sibling(self) -> None:
        """A `git archive` that dropped the component leaves an empty dir."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            component = tree(root, ["archinfo"])
            (root / "pyvex").mkdir()
            module = load("unworkspace.py")
            self.assertIsNone(module.sibling(component, "pyvex"))
            self.assertIsNotNone(module.sibling(component, "archinfo"))


if __name__ == "__main__":
    unittest.main()
