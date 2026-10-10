"""What `ci/typecheck.py` measures the baseline with.

Both of these were silent. pyright reads its default `exclude` -- which
includes `**/.*` -- relative to the working directory, so the baseline
worktree `.typecheck-base`, scored from the repository root, was never read at
all: every baseline came back clean, and against zero any file carrying one
error is a regression. On mono `main` at 71c3813, carrying no pull
requests, 37 entries all read a perfect baseline and 21 of them failed the
gate.
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


def diagnostic(path: Path, severity: str) -> dict:
    """One entry of pyright's `generalDiagnostics`, against `path`."""
    return {
        "file": str(path),
        "severity": severity,
        "range": {"start": {"line": 1, "character": 0}},
        "message": f"a {severity}",
    }


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
            self.typecheck.typecheck_files([tree / "ci" / "typecheck.py"], tree)
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

        def typecheck_files(paths: list[Path], tree: Path) -> dict:
            scored_from.append(tree)
            return {str(path): typecheck.FileReport() for path in paths}

        with contextlib.ExitStack() as stack:
            patch = stack.enter_context
            patch(unittest.mock.patch.object(typecheck, "require_pyright"))
            patch(unittest.mock.patch.object(typecheck, "git", git))
            patch(
                unittest.mock.patch.object(
                    typecheck, "typecheck_files", typecheck_files
                )
            )
            # The `rm -rf` before the worktree is added; `git` above is what
            # would have created it, so nothing exists to remove.
            patch(unittest.mock.patch.object(typecheck.subprocess, "run"))
            patch(unittest.mock.patch.object(sys, "argv", ["typecheck.py"]))
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(typecheck.main(), 0)

        self.assertEqual(scored_from, [typecheck.ROOT, typecheck.BASE_TREE])


class ErrorCountTests(unittest.TestCase):
    """Reading pyright's report, and what counts towards the verdict.

    angr/ci-settings#129 retired the per-line badness score --
    (errors * 10 + warnings) / lines -- for the raw error count. These pin
    the new rule, because this tree carries its own copy of the script and
    nothing else would notice it drifting back.
    """

    def setUp(self) -> None:
        self.typecheck = load("typecheck.py")

    def test_a_file_pyright_declined_to_read_is_not_a_clean_count(self) -> None:
        report = {"generalDiagnostics": [], "summary": {"filesAnalyzed": 0}}
        with pyright_says(self.typecheck, report):
            with self.assertRaises(SystemExit) as caught:
                self.typecheck.typecheck_files([ROOT / "ci" / "typecheck.py"], ROOT)
        self.assertIn("analysed 0 of the 1 files", str(caught.exception))

    def test_a_file_with_no_diagnostics_counts_no_errors(self) -> None:
        report = {"generalDiagnostics": [], "summary": {"filesAnalyzed": 1}}
        path = ROOT / "ci" / "typecheck.py"
        with pyright_says(self.typecheck, report):
            counted = self.typecheck.typecheck_files([path], ROOT)
        self.assertEqual(counted[str(path)].errors, 0)

    def test_errors_are_counted_one_each(self) -> None:
        """Not ten each, and not divided by the file's length."""
        path = ROOT / "ci" / "typecheck.py"
        report = {
            "generalDiagnostics": [diagnostic(path, "error") for _ in range(3)],
            "summary": {"filesAnalyzed": 1},
        }
        with pyright_says(self.typecheck, report):
            counted = self.typecheck.typecheck_files([path], ROOT)
        self.assertEqual(counted[str(path)].errors, 3)

    def test_warnings_do_not_count_towards_the_verdict(self) -> None:
        """They are still collected, so a regression can print them."""
        path = ROOT / "ci" / "typecheck.py"
        report = {
            "generalDiagnostics": [
                diagnostic(path, "warning"),
                diagnostic(path, "information"),
            ],
            "summary": {"filesAnalyzed": 1},
        }
        with pyright_says(self.typecheck, report):
            counted = self.typecheck.typecheck_files([path], ROOT)
        self.assertEqual(counted[str(path)].errors, 0)
        self.assertEqual(len(counted[str(path)].diagnostics), 2)

    def test_a_diagnostic_for_a_file_we_did_not_ask_about_is_fatal(self) -> None:
        path = ROOT / "ci" / "typecheck.py"
        report = {
            "generalDiagnostics": [diagnostic(ROOT / "ci" / "lint.py", "error")],
            "summary": {"filesAnalyzed": 1},
        }
        with pyright_says(self.typecheck, report):
            with self.assertRaises(SystemExit) as caught:
                self.typecheck.typecheck_files([path], ROOT)
        self.assertIn("did not ask about", str(caught.exception))


class VerdictTests(unittest.TestCase):
    """Which way the comparison runs, end to end through `main`."""

    def setUp(self) -> None:
        self.typecheck = load("typecheck.py")

    def run_main(self, base_errors: int, head_errors: int) -> tuple[int, str]:
        typecheck = self.typecheck
        changed = "ci/typecheck.py"

        def git(*args: str) -> str:
            if args[0] == "merge-base":
                return "0" * 40
            if args[0] == "rev-parse":
                return "1" * 40
            if args[0] == "diff":
                return changed
            return ""

        def typecheck_files(_paths: list[Path], tree: Path) -> dict:
            report = typecheck.FileReport()
            report.errors = head_errors if tree == typecheck.ROOT else base_errors
            report.diagnostics = [(1, 0, "error", "no") for _ in range(report.errors)]
            return {str(tree / changed): report}

        out = io.StringIO()
        with contextlib.ExitStack() as stack:
            patch = stack.enter_context
            patch(unittest.mock.patch.object(typecheck, "require_pyright"))
            patch(unittest.mock.patch.object(typecheck, "git", git))
            patch(
                unittest.mock.patch.object(
                    typecheck, "typecheck_files", typecheck_files
                )
            )
            patch(unittest.mock.patch.object(typecheck.subprocess, "run"))
            patch(unittest.mock.patch.object(sys, "argv", ["typecheck.py"]))
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(out):
                status = typecheck.main()
        return status, out.getvalue()

    def test_more_errors_than_the_base_fails(self) -> None:
        status, out = self.run_main(base_errors=1, head_errors=2)
        self.assertEqual(status, 1)
        self.assertIn("ci/typecheck.py: errors 1 -> 2", out)
        self.assertIn("pyright errors increased:", out)

    def test_fewer_errors_than_the_base_passes(self) -> None:
        status, out = self.run_main(base_errors=2, head_errors=1)
        self.assertEqual(status, 0)
        self.assertIn("no file got worse.", out)

    def test_the_same_count_passes(self) -> None:
        status, out = self.run_main(base_errors=3, head_errors=3)
        self.assertEqual(status, 0)
        self.assertIn("no file got worse.", out)

    def test_a_file_clean_at_the_base_fails_on_its_first_error(self) -> None:
        """The base counts no errors, so the first one is a regression."""
        status, out = self.run_main(base_errors=0, head_errors=1)
        self.assertEqual(status, 1)
        self.assertIn("ci/typecheck.py: errors 0 -> 1", out)


if __name__ == "__main__":
    unittest.main()
