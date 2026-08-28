"""Which named exclusions apply on the platform this run is on.

An exclusion is usually a fact about a test everywhere -- angr's CGC
random-syscall desync is the same on every machine. Some are not: the tests
that crash under Windows' native engines pass on Linux, and deselecting them
everywhere would hide a real regression on the platform where they work.

So a value in ``excluded`` is either a reason, applying everywhere:

    "tests/x.py::test_y": "why"

or an object naming the platforms it applies to, as ``sys.platform`` spells
them (``linux``, ``darwin``, ``win32``):

    "tests/x.py::test_y": {"reason": "why", "platforms": ["win32"]}
"""

from __future__ import annotations

import sys


def for_platform(suite: dict, name: str, platform: str | None = None) -> list[tuple[str, str]]:
    """The (test, reason) pairs to deselect for this suite here."""
    platform = platform or sys.platform
    excluded = suite.get("excluded", {})
    if not isinstance(excluded, dict):
        raise SystemExit(f"suites.json: {name}.excluded is not an object")

    out = []
    for test, value in excluded.items():
        if isinstance(value, str):
            out.append((test, value))
            continue
        if not isinstance(value, dict) or "reason" not in value:
            raise SystemExit(
                f"suites.json: {name}.excluded[{test!r}] is neither a reason "
                "nor an object with one"
            )
        platforms = value.get("platforms")
        if platforms is None or platform in platforms:
            where = "" if platforms is None else f" [{', '.join(platforms)}]"
            out.append((test, value["reason"] + where))
    return out
