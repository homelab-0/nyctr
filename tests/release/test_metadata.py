"""Protect the publication boundary from ambiguous tags and output injection."""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path

import pytest

SPEC = importlib.util.spec_from_file_location(
    "release_metadata", Path(__file__).resolve().parents[2] / "scripts/release_metadata.py"
)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)
REVISION = "a" * 40


@pytest.mark.parametrize("tag", ["v0.1.0-alpha.1", "v1.0.0", "v2.3.4-beta.0", "v2.3.4-rc.1"])
def test_version_and_commit_tags_identify_the_same_release(tag):
    """Retain prerelease identity and the full commit without creating a latest tag."""
    result = MODULE.release_metadata(tag, "Homelab-0/Nyctr", REVISION)
    assert result == {
        "image": "ghcr.io/homelab-0/nyctr",
        "chart_registry": "oci://ghcr.io/homelab-0/charts",
        "version": tag[1:],
        "version_tag": "ghcr.io/homelab-0/nyctr:" + tag,
        "commit_tag": "ghcr.io/homelab-0/nyctr:sha-" + REVISION,
        "revision": REVISION,
    }


@pytest.mark.parametrize("tag", [
    "main", "latest", "v1.0", "v01.0.0", "v1.0.0-alpha.01", "v1.0.0+build",
    "v1.0.0\nimage=attacker", "v1.0.0;exit", "v1.0.0-$(whoami)", "v1.0.0/extra",
])
def test_rejects_ambiguous_or_executable_release_tags(tag):
    """Reject tags that could change output records, registry destinations, or commands."""
    with pytest.raises(ValueError):
        MODULE.release_metadata(tag, "homelab-0/nyctr", REVISION)


@pytest.mark.parametrize("repository", ["nyctr", "a/b/c", "a/b\nimage=x", "a/$(id)", "a/../b"])
def test_rejects_unexpected_registry_namespaces(repository):
    """Keep publication in a single validated repository namespace."""
    with pytest.raises(ValueError):
        MODULE.release_metadata("v0.1.0-alpha.1", repository, REVISION)


@pytest.mark.parametrize("revision", ["main", "abc1234", "A" * 40, "a" * 40 + "\n"])
def test_requires_an_exact_commit_revision(revision):
    """Do not permit mutable refs or injected output lines as a build identity."""
    with pytest.raises(ValueError):
        MODULE.release_metadata("v0.1.0-alpha.1", "homelab-0/nyctr", revision)


def source_tree(tmp_path, version="0.1.0-alpha.1", python_version="0.1.0a1"):
    """Build static version metadata for an isolated release checkout without application dependencies."""
    api = tmp_path / "services/api"
    web = tmp_path / "apps/web"
    (api / "nyctr").mkdir(parents=True)
    web.mkdir(parents=True)
    (api / "nyctr/__init__.py").write_text(f'__version__ = "{version}"\n', encoding="utf-8")
    (api / "pyproject.toml").write_text(f'[project]\nversion = "{python_version}"\n', encoding="utf-8")
    (web / "package.json").write_text(json.dumps({"version": version}), encoding="utf-8")
    (web / "package-lock.json").write_text(json.dumps({"version": version,
                                                     "packages": {"": {"version": version}}}), encoding="utf-8")
    return tmp_path


@pytest.mark.parametrize("version,python_version", [
    ("0.1.0-alpha.1", "0.1.0a1"), ("1.0.0", "1.0.0"),
    ("2.3.4-beta.0", "2.3.4b0"), ("2.3.4-rc.1", "2.3.4rc1"),
])
def test_source_versions_match_canonical_python_prerelease_spelling(tmp_path, version, python_version):
    """Recognize equivalent SemVer and canonical PEP 440 versions for each supported release stage."""
    MODULE.validate_source_versions(version, source_tree(tmp_path, version, python_version))


def test_current_checkout_versions_are_consistent():
    """Keep the checked-in web, API, package, and lockfile versions aligned before any release is made."""
    root = Path(__file__).resolve().parents[2]
    version = json.loads((root / "apps/web/package.json").read_text(encoding="utf-8"))["version"]
    MODULE.validate_source_versions(version, root)


@pytest.mark.parametrize("source", ["runtime", "python", "web", "lock", "lock_root"])
def test_rejects_a_mismatch_in_every_version_source(tmp_path, source):
    """Prevent a matching subset of metadata from hiding a stale runtime, package, or lockfile version."""
    root = source_tree(tmp_path)
    if source == "runtime":
        (root / "services/api/nyctr/__init__.py").write_text('__version__ = "9.9.9"\n', encoding="utf-8")
    elif source == "python":
        (root / "services/api/pyproject.toml").write_text('[project]\nversion = "9.9.9"\n', encoding="utf-8")
    elif source == "web":
        (root / "apps/web/package.json").write_text('{"version": "9.9.9"}', encoding="utf-8")
    else:
        path = root / "apps/web/package-lock.json"
        lock = json.loads(path.read_text(encoding="utf-8"))
        (lock if source == "lock" else lock["packages"][""])["version"] = "9.9.9"
        path.write_text(json.dumps(lock), encoding="utf-8")
    with pytest.raises(ValueError, match="Source version mismatch"):
        MODULE.validate_source_versions("0.1.0-alpha.1", root)


def test_rejects_release_tag_that_disagrees_with_otherwise_consistent_sources(tmp_path):
    """A syntactically valid release tag cannot relabel an unrelated application version."""
    root = source_tree(tmp_path)
    metadata = MODULE.release_metadata("v9.9.9", "homelab-0/nyctr", REVISION)
    with pytest.raises(ValueError, match="Source version mismatch"):
        MODULE.validate_source_versions(metadata["version"], root)


def test_api_version_is_read_without_importing_or_executing_code(tmp_path):
    """Verify a literal assignment even when importing that file would immediately fail."""
    root = source_tree(tmp_path)
    (root / "services/api/nyctr/__init__.py").write_text(
        '__version__ = "0.1.0-alpha.1"\nraise RuntimeError("Application code was executed")\n', encoding="utf-8"
    )
    MODULE.validate_source_versions("0.1.0-alpha.1", root)


@pytest.mark.parametrize("assignment", [
    '__version__ = get_version()\n',
    '__version__ = "0.1.0-alpha.1"\n__version__ = "0.1.0-alpha.1"\n',
    'other_name = "0.1.0-alpha.1"\n',
])
def test_dynamic_missing_or_duplicate_runtime_versions_are_rejected(tmp_path, assignment):
    """Refuse version declarations whose value cannot be established by one literal AST assignment."""
    root = source_tree(tmp_path)
    (root / "services/api/nyctr/__init__.py").write_text(assignment, encoding="utf-8")
    with pytest.raises(ValueError, match="literal __version__"):
        MODULE.validate_source_versions("0.1.0-alpha.1", root)


@pytest.mark.parametrize("path,payload", [
    ("apps/web/package.json", "not JSON"),
    ("apps/web/package.json", "[]"),
    ("apps/web/package-lock.json", '{"version":"0.1.0-alpha.1","packages":{}}'),
    ("services/api/pyproject.toml", "not TOML"),
    ("services/api/pyproject.toml", "project = false"),
    ("services/api/nyctr/__init__.py", "invalid python syntax"),
])
def test_malformed_source_metadata_fails_closed(tmp_path, path, payload):
    """Missing structure or invalid source syntax must block publication rather than bypass comparison."""
    root = source_tree(tmp_path)
    (root / path).write_text(payload, encoding="utf-8")
    with pytest.raises(ValueError):
        MODULE.validate_source_versions("0.1.0-alpha.1", root)


def test_cli_checks_versions_before_writing_workflow_outputs(tmp_path):
    """Reject a mislabeled checkout before creating or appending any publishable GitHub output."""
    root = source_tree(tmp_path)
    output = tmp_path / "github-output"
    output.write_text("existing=value\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(MODULE.__file__), "--tag", "v9.9.9",
                             "--repository", "homelab-0/nyctr", "--revision", REVISION,
                             "--source-root", str(root), "--github-output", str(output)],
                            capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode != 0 and "Source version mismatch" in result.stderr
    assert result.stdout == ""
    assert output.read_text(encoding="utf-8") == "existing=value\n"


def test_cli_default_source_root_is_the_script_checkout_not_the_current_directory(tmp_path):
    """Validate repository versions when the release helper runs from an unrelated working directory."""
    root = Path(__file__).resolve().parents[2]
    version = json.loads((root / "apps/web/package.json").read_text(encoding="utf-8"))["version"]
    result = subprocess.run([sys.executable, str(MODULE.__file__), "--tag", "v" + version,
                             "--repository", "homelab-0/nyctr", "--revision", REVISION],
                            cwd=tmp_path, capture_output=True, text=True, check=False, timeout=10)
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout)["version"] == version


def git(root, *args):
    """Run local Git fixture commands without hooks, signing, or changes to operator configuration."""
    result = subprocess.run(["git", "-C", str(root), "-c", "user.name=Nyctr release tests",
                             "-c", "user.email=release-tests@example.test", "-c", "commit.gpgsign=false",
                             "-c", "tag.gpgsign=false", "-c", "core.hooksPath=/dev/null", *args],
                            capture_output=True, text=True, check=True, timeout=10)
    return result.stdout.strip()


@pytest.fixture
def git_source(tmp_path):
    """Create a real disposable Git repository with consistent synthetic application versions."""
    root = source_tree(tmp_path)
    git(root, "init", "--quiet", "--initial-branch=main", "--object-format=sha1")
    git(root, "add", "--all")
    git(root, "commit", "--quiet", "-m", "Synthetic release source")
    return root, git(root, "rev-parse", "HEAD")


@pytest.mark.parametrize("annotated", [False, True])
def test_git_guard_accepts_matching_lightweight_and_annotated_tags(git_source, annotated):
    """Peel both tag types to their commit rather than comparing an annotated tag's object ID."""
    root, revision = git_source
    args = ["-a", "-m", "Synthetic release tag"] if annotated else []
    git(root, "tag", *args, "v0.1.0-alpha.1")
    MODULE.verify_git_tag("v0.1.0-alpha.1", revision, root)


def test_git_guard_rejects_a_tag_moved_to_another_commit(git_source):
    """A tag retargeted after the expected source revision was chosen must not authorize publication."""
    root, revision = git_source
    git(root, "tag", "v0.1.0-alpha.1")
    git(root, "commit", "--quiet", "--allow-empty", "-m", "Subsequent synthetic source")
    git(root, "tag", "--force", "v0.1.0-alpha.1")
    with pytest.raises(ValueError, match="does not resolve to the expected commit"):
        MODULE.verify_git_tag("v0.1.0-alpha.1", revision, root)


@pytest.mark.parametrize("target", ["missing", "tree"])
def test_git_guard_requires_a_tag_reference_to_a_commit(git_source, target):
    """Reject a same-named branch or a tree tag instead of accepting ambiguous or non-commit refs."""
    root, revision = git_source
    if target == "missing":
        git(root, "branch", "v0.1.0-alpha.1")
    else:
        git(root, "tag", "v0.1.0-alpha.1", git(root, "rev-parse", "HEAD^{tree}"))
    with pytest.raises(ValueError, match="missing or does not reference a commit"):
        MODULE.verify_git_tag("v0.1.0-alpha.1", revision, root)


@pytest.mark.parametrize("tag,revision", [("--help", REVISION), ("v0.1.0-alpha.1\nHEAD", REVISION),
                                        ("v0.1.0-alpha.1", "main")])
def test_git_guard_validates_identifiers_before_invoking_git(tmp_path, monkeypatch, tag, revision):
    """Malformed identifiers must fail validation without reaching the subprocess boundary."""
    def unexpected_git(*args, **kwargs):
        """Fail if an invalid tag or revision is allowed to reach Git."""
        pytest.fail("Git was invoked before identifier validation")

    monkeypatch.setattr(MODULE.subprocess, "run", unexpected_git)
    with pytest.raises(ValueError):
        MODULE.verify_git_tag(tag, revision, tmp_path)


@pytest.mark.parametrize("matching", [False, True])
def test_cli_git_guard_runs_before_metadata_or_workflow_output(git_source, matching):
    """Only a matching local release tag permits stdout metadata and GitHub output append."""
    root, tagged_revision = git_source
    git(root, "tag", "v0.1.0-alpha.1")
    git(root, "commit", "--quiet", "--allow-empty", "-m", "Second synthetic commit")
    revision = tagged_revision if matching else git(root, "rev-parse", "HEAD")
    output = root / "github-output"
    output.write_text("existing=value\n", encoding="utf-8")
    result = subprocess.run([sys.executable, str(MODULE.__file__), "--tag", "v0.1.0-alpha.1",
                             "--repository", "homelab-0/nyctr", "--revision", revision,
                             "--source-root", str(root), "--github-output", str(output), "--verify-git-tag"],
                            capture_output=True, text=True, check=False, timeout=10)
    if matching:
        assert result.returncode == 0, result.stderr
        assert json.loads(result.stdout)["revision"] == tagged_revision
        assert f"revision={tagged_revision}\n" in output.read_text(encoding="utf-8")
    else:
        assert result.returncode != 0 and "does not resolve to the expected commit" in result.stderr
        assert result.stdout == ""
        assert output.read_text(encoding="utf-8") == "existing=value\n"
