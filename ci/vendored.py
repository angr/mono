#!/usr/bin/env python3
"""The paths in this tree that came out of a component's submodule.

`ci/import.py` vendors them -- `pyvex/vex` is the only one -- so a component
and the sources it compiles are one commit here rather than a pin in another
repository. They are third-party drops nobody edits in this tree, which is
what the gates reading a diff need to know: a vendored file is not a file
somebody wrote, so scoring it as new code says nothing about the change
under review, and a component's own hooks never saw it upstream either.

    ci/vendored.py                    # every path, as <component>/<path>
    ci/vendored.py --component pyvex  # that component's, relative to it
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def for_component(name: str, manifest_path: Path | None = None) -> list[str]:
    """The submodule paths vendored into one component, relative to it."""
    manifest = json.loads((manifest_path or ROOT / "mono.json").read_text())
    for section in ("components", "fixtures"):
        entry = manifest.get(section, {}).get(name)
        if entry is not None:
            return sorted(entry.get("vendored_submodules", {}))
    return []


def paths(manifest_path: Path | None = None) -> list[str]:
    """`<component>/<submodule path>` for every vendored submodule."""
    manifest = json.loads((manifest_path or ROOT / "mono.json").read_text())
    out = []
    for section in ("components", "fixtures"):
        for name in manifest.get(section, {}):
            out += [f"{name}/{path}" for path in for_component(name, manifest_path)]
    return sorted(out)


def covers(path: str, vendored: list[str] | None = None) -> bool:
    """Is `path` inside a vendored submodule?"""
    candidates = paths() if vendored is None else vendored
    return any(path == root or path.startswith(f"{root}/") for root in candidates)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--component", help="only this one, relative to it")
    args = parser.parse_args()
    found = for_component(args.component) if args.component else paths()
    print("\n".join(found))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
