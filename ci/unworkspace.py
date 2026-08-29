#!/usr/bin/env python3
"""Undo the import's workspace rewrite in a detached copy of a component.

`ci/import.py` repoints each component's sibling `[tool.uv.sources]` entries
at the workspace, which is the only thing that can work inside this
repository. A component extracted *out* of it -- the Pyodide job builds cle
that way, because `uv sync` inside a workspace member resolves the whole
workspace -- then declares `archinfo = { workspace = true }` with no
workspace to belong to, and uv refuses it.

What replaces the workspace source decides what the job is testing. A sibling
copied out of this tree alongside the component keeps the answer about this
tree; upstream's git source answers about upstream's master instead, and the
difference is invisible in the failure. It cost six cle failures on a rollup
whose branch contained the fix -- `module 'archinfo' has no attribute
'ArchMIPSN32'`, from an archinfo the tree carries and upstream does not
(angr/mono#9). So a sibling sitting next to the directory becomes a path
source, and only a sibling that is not there falls back to git.

    ci/unworkspace.py /tmp/work/cle
    ci/unworkspace.py /tmp/work/cle --require-siblings
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


def sibling(directory: Path, name: str) -> Path | None:
    """The copy of `name` beside `directory`, if one was extracted with it."""
    candidate = directory.parent / name
    if (candidate / "pyproject.toml").is_file():
        return candidate
    return None


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument(
        "--require-siblings",
        action="store_true",
        help="fail rather than fall back to upstream for a missing sibling",
    )
    args = parser.parse_args()

    directory = args.directory
    pyproject = directory / "pyproject.toml"
    if not pyproject.exists():
        raise SystemExit(f"{pyproject} does not exist")

    from_tree: list[str] = []
    from_upstream: list[str] = []

    def replace(match: re.Match) -> str:
        name = match.group("name")
        indent = match.group("indent")
        if sibling(directory, name) is not None:
            from_tree.append(name)
            return f'{indent}{name} = {{ path = "../{name}" }}'
        from_upstream.append(name)
        url = f"https://github.com/angr/{name}.git"
        return f'{indent}{name} = {{ git = "{url}", branch = "master" }}'

    text = pyproject.read_text(encoding="utf-8")
    updated = WORKSPACE.sub(replace, text)
    if not from_tree and not from_upstream:
        print(f"{pyproject}: no workspace sources to undo", file=sys.stderr)
        return 0
    pyproject.write_text(updated, encoding="utf-8")

    if from_tree:
        print(f"{pyproject}: {', '.join(from_tree)} -> this tree's copy")
    if from_upstream:
        # Loud either way. A silent fallback is how the Pyodide lane spent
        # months testing cle against an archinfo the tree does not contain.
        print(
            f"{pyproject}: {', '.join(from_upstream)} -> upstream git sources; "
            "this tree's version of them is NOT what gets tested",
            file=sys.stderr,
        )
        if args.require_siblings:
            raise SystemExit(
                "--require-siblings: extract "
                + ", ".join(from_upstream)
                + f" beside {directory} so the job tests this tree"
            )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
