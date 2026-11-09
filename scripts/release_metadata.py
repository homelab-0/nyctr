"""Validate release identifiers before they reach image tags or workflow outputs."""

from __future__ import annotations

import argparse
import ast
import json
import re
import tomllib
from pathlib import Path

VERSION_PATTERN = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)\.(0|[1-9][0-9]*))?"


def release_metadata(tag: str, repository: str, revision: str) -> dict[str, str]:
    """Build bounded image metadata from a version tag, repository, and exact commit.

    Reject build metadata, shell syntax, newlines, and moving branch names. The
    release workflow separately proves that this commit belongs to main.
    """
    if len(tag) > 100 or not re.fullmatch(VERSION_PATTERN, tag):
        raise ValueError("Use vMAJOR.MINOR.PATCH or vMAJOR.MINOR.PATCH-alpha.N, -beta.N, or -rc.N")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,99}/[A-Za-z0-9][A-Za-z0-9_.-]{0,99}", repository):
        raise ValueError("Repository must be an owner/name pair")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Revision must be a full lowercase Git commit SHA")
    image = "ghcr.io/" + repository.lower()
    return {
        "image": image,
        "version": tag.removeprefix("v"),
        "version_tag": image + ":" + tag,
        "commit_tag": image + ":sha-" + revision,
        "revision": revision,
    }


def _read_json(root: Path, relative_path: str) -> dict:
    """Read version metadata as a JSON object without executing package lifecycle code."""
    try:
        data = json.loads((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, ValueError):
        raise ValueError(f"Cannot read valid release metadata from {relative_path}") from None
    if not isinstance(data, dict):
        raise ValueError(f"Release metadata must be an object in {relative_path}")
    return data


def _api_runtime_version(root: Path) -> str:
    """Read one literal API version assignment through AST, never by importing the application."""
    relative_path = "services/api/nyctr/__init__.py"
    try:
        tree = ast.parse((root / relative_path).read_text(encoding="utf-8"))
    except (OSError, UnicodeError, SyntaxError):
        raise ValueError(f"Cannot read a static API version from {relative_path}") from None
    assignments = []
    for node in tree.body:
        targets = node.targets if isinstance(node, ast.Assign) else [node.target] if isinstance(node, ast.AnnAssign) else []
        if any(isinstance(target, ast.Name) and target.id == "__version__" for target in targets):
            assignments.append(node.value)
    if (len(assignments) != 1 or not isinstance(assignments[0], ast.Constant)
            or not isinstance(assignments[0].value, str)):
        raise ValueError(f"Require exactly one literal __version__ assignment in {relative_path}")
    return assignments[0].value


def validate_source_versions(version: str, root: Path) -> None:
    """Require release, runtime, package, and lockfile versions to identify the same code.

    Web and runtime metadata use the release's SemVer spelling. The Python package
    uses its canonical PEP 440 spelling: alpha.N becomes aN, beta.N becomes bN,
    and rc.N becomes rcN. Every source is parsed as data; none is imported or run.
    """
    if len(version) > 99 or not re.fullmatch(VERSION_PATTERN, "v" + version):
        raise ValueError("Cannot validate source versions for an unsupported release version")
    python_version = version
    if "-" in version:
        base, prerelease = version.split("-", 1)
        stage, number = prerelease.split(".", 1)
        python_version = base + {"alpha": "a", "beta": "b", "rc": "rc"}[stage] + number
    relative_path = "services/api/pyproject.toml"
    try:
        project = tomllib.loads((root / relative_path).read_text(encoding="utf-8")).get("project", {})
    except (OSError, UnicodeError, ValueError):
        raise ValueError(f"Cannot read valid release metadata from {relative_path}") from None
    if not isinstance(project, dict):
        raise ValueError(f"Release project metadata must be a table in {relative_path}")
    package = _read_json(root, "apps/web/package.json")
    lock = _read_json(root, "apps/web/package-lock.json")
    packages = lock.get("packages", {})
    lock_root = packages.get("") if isinstance(packages, dict) else None
    if not isinstance(lock_root, dict):
        raise ValueError("Missing root package metadata in apps/web/package-lock.json")
    sources = {
        "services/api/nyctr/__init__.py": (_api_runtime_version(root), version),
        "services/api/pyproject.toml": (project.get("version"), python_version),
        "apps/web/package.json": (package.get("version"), version),
        "apps/web/package-lock.json version": (lock.get("version"), version),
        "apps/web/package-lock.json root package": (lock_root.get("version"), version),
    }
    for source, (actual, expected) in sources.items():
        if actual != expected:
            raise ValueError(f"Source version mismatch in {source}; expected {expected}")


def main() -> None:
    """Check source consistency before emitting image metadata or appending GitHub output lines."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Source checkout to validate; defaults to this script's repository")
    args = parser.parse_args()
    try:
        metadata = release_metadata(args.tag, args.repository, args.revision)
        validate_source_versions(metadata["version"], args.source_root)
    except ValueError as error:
        parser.error(str(error))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for name, value in metadata.items():
                output.write(f"{name}={value}\n")
    print(json.dumps(metadata))


if __name__ == "__main__":
    main()
