"""Check resource addresses and GC references without building the angr family."""

from __future__ import annotations

import argparse
import json
import shutil
import subprocess
from pathlib import Path


def nix_string(value: str | Path) -> str:
    return json.dumps(str(value)).replace("${", r"\${")


def run(*args: str) -> str:
    return subprocess.check_output(args, text=True).strip()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--nixpkgs", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=False)
    module = Path(__file__).resolve().parents[1] / "resources.nix"

    first = args.work_dir / "first"
    resource_root = first / "angrmanagement/resources"
    (resource_root / "flirt_signatures").mkdir(parents=True)
    (resource_root / "library_docs").mkdir()
    (resource_root / "flirt_signatures/payload.txt").write_text("resource bytes\n")
    (resource_root / "library_docs/payload.json").write_text("[]\n")
    (first / "version.txt").write_text("one\n")
    second = args.work_dir / "second"
    shutil.copytree(first, second)
    (second / "version.txt").write_text("two\n")
    (second / "angrmanagement/resources/flirt_signatures/.git").write_text(
        "irrelevant gitdir\n"
    )
    changed = args.work_dir / "changed"
    shutil.copytree(first, changed)
    (changed / "angrmanagement/resources/flirt_signatures/payload.txt").write_text(
        "changed bytes\n"
    )
    immutable_hash = run("nix", "hash", "path", str(resource_root / "flirt_signatures"))

    prefix = f"""
      let
        pkgs = import (builtins.toPath {nix_string(args.nixpkgs.resolve())}) {{}};
        resources = source: import (builtins.toPath {nix_string(module)}) {{
          inherit pkgs;
          managementSource = source;
        }};
        first = resources (builtins.toPath {nix_string(first.resolve())});
        second = resources (builtins.toPath {nix_string(second.resolve())});
        changed = resources (builtins.toPath {nix_string(changed.resolve())});
        explicit = resources {{
          outPath = builtins.toPath {nix_string(changed.resolve())};
          resourceSources = {{
            flirt-signatures = builtins.toPath {nix_string((resource_root / "flirt_signatures").resolve())};
          }};
        }};
        immutable = resources {{
          outPath = builtins.toPath {nix_string(changed.resolve())};
          resourceSources.flirt-signatures = {{
            outPath = builtins.toPath {nix_string((resource_root / "flirt_signatures").resolve())};
            narHash = {nix_string(immutable_hash)};
          }};
        }};
      in
    """
    identities = json.loads(
        run(
            "nix-instantiate",
            "--eval",
            "--strict",
            "--read-write-mode",
            "--json",
            "--expr",
            prefix
            + """{
          first = toString first.flirt-signatures;
          second = toString second.flirt-signatures;
          changed = toString changed.flirt-signatures;
          explicit = toString explicit.flirt-signatures;
          immutable = toString immutable.flirt-signatures;
          docsFirst = toString first.library-docs;
          docsChanged = toString changed.library-docs;
        }""",
        )
    )
    assert identities["first"] == identities["second"], identities
    assert identities["first"] != identities["changed"], identities
    assert identities["first"] == identities["explicit"], identities
    assert identities["first"] == identities["immutable"], identities
    assert identities["docsFirst"] == identities["docsChanged"], identities

    # Two differently named installed packages must keep the one data output
    # alive through symlinks at the paths the GUI resolves at runtime.
    wrappers = (
        prefix
        + """
      pkgs.linkFarm "resource-identity-check" (map (name: {
        inherit name;
        path = pkgs.runCommand name {} ''
          mkdir -p "$out/angrmanagement/resources"
          ln -s ${first.flirt-signatures} "$out/angrmanagement/resources/flirt_signatures"
          ln -s ${first.library-docs} "$out/angrmanagement/resources/library_docs"
        '';
      }) [ "management-one" "management-two" ])
    """
    )
    root = args.work_dir / "result"
    output = Path(
        run(
            "nix-build",
            "--expr",
            wrappers,
            "--out-link",
            str(root.resolve()),
            "--cores",
            "1",
            "--max-jobs",
            "1",
        ).splitlines()[-1]
    )
    closure = run("nix-store", "--query", "--requisites", str(output)).splitlines()
    assert identities["first"] in closure, closure
    assert identities["docsFirst"] in closure, closure
    for name in ("management-one", "management-two"):
        installed = output / name / "angrmanagement/resources/flirt_signatures"
        assert installed.is_symlink(), installed
        assert installed.resolve() == Path(identities["first"]), installed
        assert (installed / "payload.txt").read_text() == "resource bytes\n"
    identity = json.loads(run("nix", "path-info", "--json", identities["first"]))
    entry = identity[identities["first"]] if isinstance(identity, dict) else identity[0]
    assert entry["ca"].startswith("fixed:r:sha256:"), entry
    report = {
        "identities": identities,
        "closure": closure,
        "content_address": entry["ca"],
    }
    (args.work_dir / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    print(
        "PASS: content identity, selected source, changed bytes, symlink lookup, GC closure, fixed-output address"
    )


if __name__ == "__main__":
    main()
