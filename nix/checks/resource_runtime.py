"""Run under a built GUI environment to check its shared resource defaults."""

from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import angrmanagement
from angrmanagement.config.config_manager import ConfigurationManager
from angrmanagement.data import signatures
from angrmanagement.data.library_docs import LibraryDocs

import angr.flirt


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    args.work_dir.mkdir(parents=True, exist_ok=True)

    config = ConfigurationManager()
    flirt = Path(config.flirt_signatures_root)
    docs = Path(config.library_docs_root)
    assert str(flirt).startswith("/nix/store/") and flirt.is_dir(), flirt
    assert str(docs).startswith("/nix/store/") and docs.is_dir(), docs
    installed = Path(angrmanagement.__file__).parent / "resources"
    assert (installed / "flirt_signatures").is_symlink(), installed
    assert (installed / "flirt_signatures").resolve() == flirt.resolve()
    assert (installed / "library_docs").is_symlink(), installed
    assert (installed / "library_docs").resolve() == docs.resolve()

    with patch.object(signatures, "Conf", config):
        signatures.init_flirt_signatures()
        signature_count = sum(
            len(items) for items in angr.flirt.FLIRT_SIGNATURES_BY_ARCH.values()
        )
        assert signature_count > 0, flirt
        documentation = LibraryDocs()
        documentation.load_func_docs(config.library_docs_root)
        documentation_count = sum(len(items) for items in documentation.func_docs)
        assert documentation_count > 0, docs

        # A user-provided directory must override the packaged defaults. An
        # empty directory deliberately has no signatures or documentation.
        with tempfile.TemporaryDirectory(dir=args.work_dir) as custom:
            config.flirt_signatures_root = custom
            signatures.init_flirt_signatures()
            assert not angr.flirt.FLIRT_SIGNATURES_BY_ARCH
            config.library_docs_root = custom
            documentation.load_func_docs(config.library_docs_root)
            assert not documentation.func_docs

    print(
        json.dumps(
            {
                "flirt": str(flirt),
                "docs": str(docs),
                "signature_count": signature_count,
                "documentation_count": documentation_count,
                "custom_directories_override_defaults": True,
            },
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    main()
