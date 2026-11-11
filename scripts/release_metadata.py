"""Decide whether the checkout is an unreleased version, and validate release identifiers
before they reach image tags or workflow outputs."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
import tomllib
from pathlib import Path

VERSION_PATTERN = r"v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-(?:alpha|beta|rc)\.(0|[1-9][0-9]*))?"
NOTES_DIRECTORY = "docs/release-notes"
# GitHub refuses a release body over 125,000 characters; leave room for the artifact list.
MAX_NOTES_BYTES = 100_000


def release_metadata(tag: str, repository: str, revision: str) -> dict[str, str]:
    """Build bounded image and chart metadata from a version tag, repository, and exact commit.

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
    # Charts live beside the image under the same owner, in their own namespace,
    # so an image and a chart can never share a tag by accident.
    chart_registry = "oci://ghcr.io/" + repository.lower().split("/", 1)[0] + "/charts"
    return {
        "image": image,
        "chart_registry": chart_registry,
        "version": tag.removeprefix("v"),
        "version_tag": image + ":" + tag,
        "commit_tag": image + ":sha-" + revision,
        "revision": revision,
    }


def verify_git_tag(tag: str, revision: str, root: Path) -> None:
    """Require a validated local tag to peel to the exact expected commit.

    Resolve only refs/tags/<tag>^{commit}, including annotated tags, without shell
    interpolation or network access. Missing, non-commit, or moved tags raise
    ValueError before the caller emits any publication metadata.
    """
    if len(tag) > 100 or not re.fullmatch(VERSION_PATTERN, tag):
        raise ValueError("Cannot verify an unsupported release tag")
    if not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise ValueError("Tag verification requires a full lowercase Git commit SHA")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "--verify", "--end-of-options", f"refs/tags/{tag}^{{commit}}"],
            capture_output=True, text=True, check=False, timeout=10,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Cannot resolve the release tag from the source checkout") from None
    if result.returncode != 0:
        raise ValueError("Release tag is missing or does not reference a commit")
    if result.stdout.strip() != revision:
        raise ValueError("Release tag does not resolve to the expected commit")


def tag_is_published(tag: str, root: Path, remote: str = "origin") -> bool:
    """Ask the remote itself whether a release tag exists, so a stale or shallow checkout cannot hide one.

    Publishing a version twice would move a released image tag, so every failure
    to get a clear answer raises instead of being read as "not published".
    """
    if len(tag) > 100 or not re.fullmatch(VERSION_PATTERN, tag):
        raise ValueError("Cannot look up an unsupported release tag")
    try:
        result = subprocess.run(
            ["git", "-C", str(root), "ls-remote", "--tags", "--end-of-options", remote, f"refs/tags/{tag}"],
            capture_output=True, text=True, check=False, timeout=60,
        )
    except (OSError, subprocess.TimeoutExpired):
        raise ValueError("Cannot ask the remote whether the release tag exists") from None
    if result.returncode != 0:
        raise ValueError("Cannot ask the remote whether the release tag exists")
    lines = [line for line in result.stdout.splitlines() if line.strip()]
    if any(not re.fullmatch(rf"[0-9a-f]{{40,64}}\trefs/tags/{re.escape(tag)}(\^\{{\}})?", line) for line in lines):
        raise ValueError("The remote returned an unexpected answer for the release tag")
    return bool(lines)


def release_notes_path(tag: str, root: Path) -> str:
    """Return the repository path of a version's reviewed release notes, which must exist and say something."""
    if len(tag) > 100 or not re.fullmatch(VERSION_PATTERN, tag):
        raise ValueError("Cannot locate notes for an unsupported release tag")
    relative_path = f"{NOTES_DIRECTORY}/{tag}.md"
    path = root / relative_path
    try:
        if path.is_symlink() or not path.is_file():
            raise ValueError(f"Missing release notes: add {relative_path} before releasing {tag}")
        if path.stat().st_size > MAX_NOTES_BYTES:
            raise ValueError(f"Release notes in {relative_path} are too long for a release body")
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        raise ValueError(f"Cannot read release notes from {relative_path}") from None
    if not text.strip():
        raise ValueError(f"Release notes in {relative_path} are empty")
    return relative_path


def release_plan(root: Path, remote: str = "origin") -> dict[str, str]:
    """Decide from the checkout alone whether it is a version that has not been released yet.

    The version is the one the source declares. It is released when the remote
    has no tag for it. An unreleased version must come with its release notes,
    so a version bump without them stops here and never reaches publication.
    """
    tag = "v" + _api_runtime_version(root)
    if len(tag) > 100 or not re.fullmatch(VERSION_PATTERN, tag):
        raise ValueError("The source declares a version that cannot be released: "
                         "use MAJOR.MINOR.PATCH or MAJOR.MINOR.PATCH-alpha.N, -beta.N, or -rc.N")
    validate_source_versions(tag.removeprefix("v"), root)
    if tag_is_published(tag, root, remote):
        return {"release": "false", "tag": tag, "prerelease": "false", "notes": ""}
    return {"release": "true", "tag": tag, "prerelease": "true" if "-" in tag else "false",
            "notes": release_notes_path(tag, root)}


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
    """Check source consistency before emitting a plan or image metadata, or appending GitHub output lines."""
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--plan", action="store_true",
                      help="Report whether the source version is unreleased, instead of emitting image metadata")
    mode.add_argument("--tag")
    parser.add_argument("--repository")
    parser.add_argument("--revision")
    parser.add_argument("--github-output", type=Path)
    parser.add_argument("--source-root", type=Path, default=Path(__file__).resolve().parents[1],
                        help="Source checkout to validate; defaults to this script's repository")
    parser.add_argument("--remote", default="origin",
                        help="Git remote asked whether a release tag exists; defaults to origin")
    checks = parser.add_mutually_exclusive_group()
    checks.add_argument("--verify-git-tag", action="store_true",
                        help="Require the local release tag to resolve to the exact revision before emitting metadata")
    checks.add_argument("--require-unreleased", action="store_true",
                        help="Require the remote to have no such release tag before emitting metadata")
    args = parser.parse_args()
    if args.plan and (args.repository or args.revision or args.verify_git_tag or args.require_unreleased):
        parser.error("--plan takes only --source-root, --remote and --github-output")
    if not args.plan and not (args.repository and args.revision):
        parser.error("--tag requires --repository and --revision")
    try:
        if args.plan:
            metadata = release_plan(args.source_root, args.remote)
        else:
            metadata = release_metadata(args.tag, args.repository, args.revision)
            validate_source_versions(metadata["version"], args.source_root)
            if args.verify_git_tag:
                verify_git_tag(args.tag, args.revision, args.source_root)
            if args.require_unreleased and tag_is_published(args.tag, args.source_root, args.remote):
                raise ValueError("This version already has a release tag; released versions are never published again")
    except ValueError as error:
        parser.error(str(error))
    if args.github_output:
        with args.github_output.open("a", encoding="utf-8") as output:
            for name, value in metadata.items():
                output.write(f"{name}={value}\n")
    print(json.dumps(metadata))


if __name__ == "__main__":
    main()
