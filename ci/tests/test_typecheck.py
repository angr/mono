"""What `ci/typecheck.py` measures the baseline with.

Both of these were silent. pyright reads its default `exclude` -- which
includes `**/.*` -- relative to the working directory, so the baseline
worktree `.typecheck-base`, scored from the repository root, was never read at
all: every baseline scored 0.0000, and against zero any file carrying a
diagnostic is a regression. On mono `main` at 71c3813, carrying no pull
requests, 37 entries all read 0.0000 and 21 of them failed the gate.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import sys
import unittest
import unittest.mock
from collections.abc import Iterator
from pathlib import Path
from types import ModuleType, SimpleNamespace

CI = Path(__file__).resolve().parent.parent
ROOT = CI.parent


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


@contextlib.contextmanager
def pyright_says(module: ModuleType, report: dict) -> Iterator[unittest.mock.Mock]:
    """Run `module`'s pyright call against a canned report."""
    run = SimpleNamespace(stdout=json.dumps(report), stderr="", returncode=0)
    with unittest.mock.patch.object(module.subprocess, "run", return_value=run) as ran:
        yield ran


class BaseTreeTests(unittest.TestCase):
    """Where the baseline worktree goes, and where pyright reads it from."""

    def setUp(self) -> None:
        self.typecheck = load("typecheck.py")

    def test_the_baseline_tree_is_not_committed(self) -> None:
        ignored = (ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
        self.assertIn(f"/{self.typecheck.BASE_TREE.name}/", ignored)

    def test_pyright_runs_from_the_tree_it_is_scoring(self) -> None:
        """The whole fix: `**/.*` is matched against the working directory."""
        report = {"generalDiagnostics": [], "summary": {"filesAnalyzed": 1}}
        tree = self.typecheck.BASE_TREE
        with pyright_says(self.typecheck, report) as ran:
            self.typecheck.badness([tree / "ci" / "typecheck.py"], tree)
        self.assertEqual(ran.call_args.kwargs["cwd"], str(tree))

    def test_each_tree_is_scored_from_its_own_root(self) -> None:
        """The head tree from the repository root, the baseline from inside it."""
        typecheck = self.typecheck
        scored_from: list[Path] = []

        def git(*args: str) -> str:
            if args[0] == "merge-base":
                return "0" * 40
            if args[0] == "rev-parse":
                return "1" * 40
            if args[0] == "diff":
                return "ci/typecheck.py"
            return ""

        def badness(paths: list[Path], tree: Path) -> dict[str, float]:
            scored_from.append(tree)
            return {str(path): 0.0 for path in paths}

        with contextlib.ExitStack() as stack:
            patch = stack.enter_context
            patch(unittest.mock.patch.object(typecheck, "require_pyright"))
            patch(unittest.mock.patch.object(typecheck, "git", git))
            patch(unittest.mock.patch.object(typecheck, "badness", badness))
            # The `rm -rf` before the worktree is added; `git` above is what
            # would have created it, so nothing exists to remove.
            patch(unittest.mock.patch.object(typecheck.subprocess, "run"))
            patch(unittest.mock.patch.object(sys, "argv", ["typecheck.py"]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(typecheck.main(), 0)

        self.assertEqual(scored_from, [typecheck.ROOT, typecheck.BASE_TREE])


class BadnessTests(unittest.TestCase):
    """Reading pyright's report."""

    def setUp(self) -> None:
        self.typecheck = load("typecheck.py")

    def test_a_file_pyright_declined_to_read_is_not_a_clean_score(self) -> None:
        report = {"generalDiagnostics": [], "summary": {"filesAnalyzed": 0}}
        with pyright_says(self.typecheck, report):
            with self.assertRaises(SystemExit) as caught:
                self.typecheck.badness([ROOT / "ci" / "typecheck.py"], ROOT)
        self.assertIn("analysed 0 of the 1 files", str(caught.exception))

    def test_a_file_with_no_diagnostics_scores_zero(self) -> None:
        report = {"generalDiagnostics": [], "summary": {"filesAnalyzed": 1}}
        path = ROOT / "ci" / "typecheck.py"
        with pyright_says(self.typecheck, report):
            self.assertEqual(self.typecheck.badness([path], ROOT), {str(path): 0.0})


if __name__ == "__main__":
    unittest.main()
