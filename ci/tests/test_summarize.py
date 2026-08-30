"""What `ci/summarize.py` counts as a skip.

The skip ratchet exists to catch tests that stopped running without anyone
noticing. pytest writes an xfail into the junit XML as a skip, so the ratchet
was spending its budget on tests that ran and failed exactly as their own
decorator said they would.
"""

from __future__ import annotations

import contextlib
import importlib.util
import io
import json
import shutil
import sys
import tempfile
import unittest
import unittest.mock
from pathlib import Path
from types import ModuleType

CI = Path(__file__).resolve().parent.parent


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


# As pytest writes it: the testsuite carries the totals, and an xfail is a
# `<skipped type="pytest.xfail">` inside a testcase that also carries a time.
# `notrun` is `@pytest.mark.xfail(run=False)`, which pytest labels `[NOTRUN]`
# because it never executed the body.
def junit(passed: int, skipped: int, xfailed: int, notrun: int = 0) -> str:
    cases = [f'<testcase classname="t.T" name="p{i}" time="0.01" />' for i in range(passed)]
    cases += [
        f'<testcase classname="t.T" name="s{i}" time="0.01">'
        f'<skipped type="pytest.skip" message="no fixture" /></testcase>'
        for i in range(skipped)
    ]
    cases += [
        f'<testcase classname="t.T" name="x{i}" time="0.01">'
        f'<skipped type="pytest.xfail" message="" /></testcase>'
        for i in range(xfailed)
    ]
    cases += [
        f'<testcase classname="t.T" name="n{i}" time="0.01">'
        f'<skipped type="pytest.xfail" message="[NOTRUN] switched off" /></testcase>'
        for i in range(notrun)
    ]
    tests = passed + skipped + xfailed + notrun
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<testsuites name="pytest tests">'
        f'<testsuite name="pytest" errors="0" failures="0" '
        f'skipped="{skipped + xfailed + notrun}" '
        f'tests="{tests}" time="1.0">{"".join(cases)}</testsuite></testsuites>'
    )


class CountsTests(unittest.TestCase):
    """What one junit file says ran, skipped and xfailed."""

    def setUp(self) -> None:
        self.summarize = load("summarize.py")
        self.dir = Path(tempfile.mkdtemp(prefix="mono-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)

    def write(
        self, name: str, passed: int, skipped: int, xfailed: int, notrun: int = 0
    ) -> Path:
        path = self.dir / name
        path.write_text(junit(passed, skipped, xfailed, notrun), encoding="utf-8")
        return path

    def test_an_xfail_is_not_a_skip(self) -> None:
        """The suite's own `skipped` attribute counts both; these do not."""
        path = self.write("angr-nix-1.xml", passed=10, skipped=2, xfailed=3)
        tests, failures, errors, skipped, xfailed, _time = self.summarize.counts(path)
        self.assertEqual((tests, failures, errors), (15, 0, 0))
        self.assertEqual(skipped, 2)
        self.assertEqual(xfailed, 3)

    def test_a_run_with_no_xfails_reads_the_same_as_before(self) -> None:
        path = self.write("cle-nix-1.xml", passed=10, skipped=9, xfailed=0)
        _tests, _failures, _errors, skipped, xfailed, _time = self.summarize.counts(path)
        self.assertEqual((skipped, xfailed), (9, 0))

    def test_an_xfail_that_never_ran_stays_a_skip(self) -> None:
        """`run=False` is the shape the ratchet exists for; pytest labels it."""
        path = self.write("angr-nix-1.xml", passed=10, skipped=2, xfailed=3, notrun=1)
        tests, _failures, _errors, skipped, xfailed = self.summarize.counts(path)[:5]
        self.assertEqual(tests, 16)
        self.assertEqual(skipped, 3)
        self.assertEqual(xfailed, 3)


class RatchetTests(unittest.TestCase):
    """The whole path: junit files in, budget verdict out."""

    def setUp(self) -> None:
        self.summarize = load("summarize.py")
        self.dir = Path(tempfile.mkdtemp(prefix="mono-"))
        self.addCleanup(shutil.rmtree, self.dir, ignore_errors=True)
        self.results = self.dir / "test-results"
        self.results.mkdir()

    def run_summarize(self, budget: dict[str, int]) -> tuple[int, str, str]:
        baseline = self.dir / "skips.json"
        baseline.write_text(json.dumps(budget), encoding="utf-8")
        argv = ["summarize.py", str(self.results), "--baseline", str(baseline)]
        out, err = io.StringIO(), io.StringIO()
        with unittest.mock.patch.object(sys, "argv", argv):
            with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                status = self.summarize.main()
        return status, out.getvalue(), err.getvalue()

    def write(
        self, name: str, passed: int, skipped: int, xfailed: int, notrun: int = 0
    ) -> None:
        (self.results / name).write_text(
            junit(passed, skipped, xfailed, notrun), encoding="utf-8"
        )

    def test_an_xfail_does_not_spend_the_budget(self) -> None:
        """angr/mono#16: 28 skips and 3 xfails against a budget of 28."""
        self.write("angr-nix-1.xml", passed=3376, skipped=28, xfailed=3)
        status, out, err = self.run_summarize({"angr": 28})
        self.assertEqual(status, 0, err)
        self.assertIn("no suite skipped more than", out)

    def test_a_real_skip_over_budget_still_fails(self) -> None:
        self.write("angr-nix-1.xml", passed=3376, skipped=29, xfailed=3)
        status, _out, err = self.run_summarize({"angr": 28})
        self.assertEqual(status, 1)
        self.assertIn("angr: 29 skipped, budget 28", err)

    def test_turning_a_test_off_with_run_false_still_spends_the_budget(self) -> None:
        """The route the split would otherwise have opened, and it is easier."""
        self.write("angr-nix-1.xml", passed=3376, skipped=28, xfailed=3, notrun=1)
        status, _out, err = self.run_summarize({"angr": 28})
        self.assertEqual(status, 1)
        self.assertIn("angr: 29 skipped, budget 28", err)

    def test_an_xfail_is_not_reported_as_a_pass(self) -> None:
        """Taking them out of the skips must not fold them into `passed`."""
        self.write("angr-nix-1.xml", passed=10, skipped=2, xfailed=3)
        _status, out, _err = self.run_summarize({"angr": 2})
        row = next(line for line in out.splitlines() if line.startswith("| angr-nix "))
        self.assertEqual(
            [cell.strip() for cell in row.strip("|").split("|")][:6],
            ["angr-nix", "15", "10", "0", "0", "2"],
        )


if __name__ == "__main__":
    unittest.main()
