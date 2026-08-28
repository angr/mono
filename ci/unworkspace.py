#!/usr/bin/env python3
"""Undo the import's workspace rewrite in a detached copy of a component.

`ci/import.py` repoints each component's sibling `[tool.uv.sources]` entries
at the workspace, which is the only thing that can work inside this
repository. A component extracted *out* of it -- the Pyodide job builds cle
that way, because `uv sync` inside a workspace member resolves the whole
workspace -- then declares `archinfo = { workspace = true }` with no
workspace to belong to, and uv refuses it.

This puts back the git sources upstream ships, so the detached copy resolves
the way upstream's own repository does.

    ci/unworkspace.py /tmp/work/cle
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

WORKSPACE = re.compile(
    r"^(?P<indent>\s*)(?P<name>[A-Za-z0-9._-]+)\s*=\s*\{\s*workspace\s*=\s*true\s*\}\s*$",
    re.MULTILINE,
)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()

    pyproject = args.directory / "pyproject.toml"
    if not pyproject.exists():
        raise SystemExit(f"{pyproject} does not exist")

    names: list[str] = []

    def replace(match: re.Match) -> str:
        names.append(match.group("name"))
        url = f"https://github.com/angr/{match.group('name')}.git"
        return (
            f"{match.group('indent')}{match.group('name')} = "
            f'{{ git = "{url}", branch = "master" }}'
        )

    text = pyproject.read_text()
    updated = WORKSPACE.sub(replace, text)
    if not names:
        print(f"{pyproject}: no workspace sources to undo", file=sys.stderr)
        return 0
    pyproject.write_text(updated)
    print(f"{pyproject}: {', '.join(names)} -> upstream git sources")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
