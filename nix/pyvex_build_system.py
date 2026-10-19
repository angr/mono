"""Select setuptools for pyvex's Python wheel while Nix supplies its native artifacts."""

from pathlib import Path

import tomlkit
from packaging.requirements import Requirement
from packaging.utils import canonicalize_name


def rewrite(text: str) -> str:
    document = tomlkit.parse(text)
    build = document.get("build-system", {})
    if build.get("build-backend") != "scikit_build_core.build" or "backend-path" in build:
        raise ValueError("pyvex must use the external scikit_build_core.build backend")
    requirements = build.get("requires")
    if not isinstance(requirements, list) or not all(isinstance(item, str) for item in requirements):
        raise ValueError("pyvex build-system.requires must be an array of requirements")
    parsed = [Requirement(item) for item in requirements]
    backends = [index for index, item in enumerate(parsed) if canonicalize_name(item.name) == "scikit-build-core"]
    if len(backends) != 1:
        raise ValueError("pyvex needs exactly one scikit-build-core build requirement")
    backend = parsed[backends[0]]
    if backend.extras or backend.url or backend.marker:
        raise ValueError("pyvex scikit-build-core requirement has unsupported extras, URL or marker")
    project = document.get("project", {})
    if project.get("name") != "pyvex" or project.get("dynamic") != ["version"]:
        raise ValueError("pyvex must declare its project name and only a dynamic version")
    tool = document.get("tool", {})
    version = tool.get("scikit-build", {}).get("metadata", {}).get("version", {})
    if version != {"provider": "scikit_build_core.metadata.regex", "input": "pyvex/__init__.py"}:
        raise ValueError("pyvex version must come from pyvex/__init__.py")
    if "setuptools" in tool:
        raise ValueError("pyvex already has setuptools configuration; reconcile it before changing backends")

    # Other requirements retain their constraints and markers for the build frontend to check.
    requirements[backends[0]] = "setuptools"
    build["build-backend"] = "setuptools.build_meta"
    tool["setuptools"] = {
        "packages": {"find": {"include": ["pyvex*"]}},
        "dynamic": {"version": {"attr": "pyvex.__version__"}},
        "package-data": {"pyvex": ["py.typed", "lib/*", "include/*", "include/*/*"]},
    }
    return tomlkit.dumps(document)


if __name__ == "__main__":
    path = Path("pyproject.toml")
    path.write_text(rewrite(path.read_text(encoding="utf-8")), encoding="utf-8")
