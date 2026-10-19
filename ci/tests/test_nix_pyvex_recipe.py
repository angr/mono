"""Exercise the pyvex wheel metadata rewrite on both upstream backend versions."""

import os
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path


WORKSPACE = Path(__file__).resolve().parents[2]
HELPER = WORKSPACE / "nix/pyvex_build_system.py"
PROJECT = """[build-system]
requires = ["scikit-build-core ~= 1.0.2", "cffi >= 1.0.3;implementation_name == 'cpython'"]
build-backend = "scikit_build_core.build"

[project]
name = "pyvex"
description = "A Python interface to libVEX and VEX IR"
requires-python = ">=3.12"
dependencies = ["bitstring<5", "cffi>=1.0.3;implementation_name == 'cpython'"]
dynamic = ["version"]

[project.optional-dependencies]
fuzzing = ["atheris>=2.3.0"]

[tool.scikit-build]
build-dir = "scikit_build"

[tool.scikit-build.metadata.version]
provider = "scikit_build_core.metadata.regex"
input = "pyvex/__init__.py"
"""


def helper_python():
    candidates = [sys.executable]
    if os.environ.get("ANGR_GATE_ENV"):
        candidates.append(str(Path(os.environ["ANGR_GATE_ENV"]) / "bin/python"))
    roots = [WORKSPACE]
    if os.environ.get("ANGR_AGENTIC_ROOT"):
        roots.append(Path(os.environ["ANGR_AGENTIC_ROOT"]))
    candidates.extend(str(root / "scratch/nix-roots/primary/gate-env/bin/python") for root in roots)
    for candidate in dict.fromkeys(candidates):
        try:
            probe = subprocess.run(
                [candidate, "-P", "-c", "import tomlkit; from packaging.requirements import Requirement"],
                capture_output=True, check=False,
            )
        except OSError:
            continue
        if probe.returncode == 0:
            return candidate
    return None


class PyvexRecipeTest(unittest.TestCase):
    """Check supported metadata rewrites and reject unexpected build layouts."""

    @classmethod
    def setUpClass(cls):
        cls.python = helper_python()
        if cls.python is None:
            raise unittest.SkipTest(
                "no interpreter with tomlkit and packaging in this interpreter, ANGR_GATE_ENV or rooted gate-env; "
                "run the pyvex-build-metadata flake check"
            )

    def rewrite(self, text, *, fails=False):
        interpreter = self.python
        assert interpreter is not None
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "pyproject.toml"
            path.write_text(text, encoding="utf-8")
            done = subprocess.run([interpreter, "-P", str(HELPER)], cwd=directory,
                                  capture_output=True, text=True, check=False)
            if fails:
                self.assertNotEqual(done.returncode, 0)
                self.assertIn("ValueError:", done.stderr)
                self.assertEqual(path.read_text(encoding="utf-8"), text)
            else:
                self.assertEqual(done.returncode, 0, done.stderr)
            return path.read_text(encoding="utf-8")

    def test_old_and_new_backend_versions_preserve_remaining_metadata(self):
        for version in ("0.12.2", "1.0.2"):
            with self.subTest(version=version):
                original = PROJECT.replace("1.0.2", version)
                before = tomllib.loads(original)
                self.assertIn(version, before["build-system"]["requires"][0])
                rewritten = self.rewrite(original)
                after = tomllib.loads(rewritten)
                self.assertEqual(after["build-system"], {
                    "requires": ["setuptools", *before["build-system"]["requires"][1:]],
                    "build-backend": "setuptools.build_meta",
                })
                setuptools = after["tool"].pop("setuptools")
                self.assertEqual(setuptools["dynamic"], {"version": {"attr": "pyvex.__version__"}})
                self.assertEqual(setuptools["packages"]["find"]["include"], ["pyvex*"])
                self.assertEqual(setuptools["package-data"]["pyvex"],
                                 ["py.typed", "lib/*", "include/*", "include/*/*"])
                after["build-system"] = before["build-system"]
                self.assertEqual(after, before)

    def test_unrelated_requirements_and_comments_are_retained(self):
        source = PROJECT.replace('"scikit-build-core ~= 1.0.2",',
                                 '"wheel >= 0.45; python_version >= \'3.12\'", "scikit_build_core >= 7",')
        source += '\n# Keep a future tool configuration.\n[tool.future]\nvalue = "unrelated"\n'
        result = self.rewrite(source)
        requirements = tomllib.loads(result)["build-system"]["requires"]
        self.assertEqual(requirements[0], "wheel >= 0.45; python_version >= '3.12'")
        self.assertEqual(requirements[1], "setuptools")
        self.assertEqual(requirements[2], "cffi >= 1.0.3;implementation_name == 'cpython'")
        self.assertIn('\n# Keep a future tool configuration.\n[tool.future]\nvalue = "unrelated"\n', result)

    def test_unexpected_backend_or_missing_requirement_is_refused(self):
        source = PROJECT
        for changed in (
            source.replace('build-backend = "scikit_build_core.build"', 'build-backend = "other.build"'),
            source.replace('[build-system]', '[build-system]\nbackend-path = ["."]'),
            source.replace('"scikit-build-core ~= 1.0.2", ', ''),
            source.replace('"scikit-build-core ~= 1.0.2"', '"scikit-build-core[extra] ~= 1.0.2"'),
        ):
            with self.subTest(changed=changed.splitlines()[:4]):
                self.rewrite(changed, fails=True)

    def test_changed_version_contract_and_existing_setuptools_are_refused(self):
        source = PROJECT
        for changed in (
            source.replace('input = "pyvex/__init__.py"', 'input = "VERSION"'),
            source.replace('dynamic = ["version"]', 'dynamic = ["version", "dependencies"]'),
            source + '\n[tool.setuptools]\ninclude-package-data = false\n',
        ):
            with self.subTest(changed=changed[-100:]):
                self.rewrite(changed, fails=True)


if __name__ == "__main__":
    unittest.main()
