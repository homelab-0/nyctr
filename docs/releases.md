# Container and chart releases

Nyctr is an experimental alpha. The release workflow is implemented, but a
release exists only after its publication run has succeeded. Source builds and
the isolated acceptance stack remain usable before the first publication.

## What triggers publication

A release is made by merging a version change to `main`. Nobody creates a tag or
a GitHub Release by hand.

Every push to `main` runs `.github/workflows/release.yml`. Its first job reads
the version the source declares and asks the remote whether a tag for that
version exists. If it does, the run ends there, which is what happens for every
ordinary merge. A pull request never publishes anything.

When the version has no tag, the same run, for that exact commit:

1. Requires the version's release notes, `docs/release-notes/v<version>.md`.
2. Runs the reusable CI workflow, including API, frontend, container, chart, and
   isolated integration checks.
3. Checks out the exact commit with persisted Git credentials disabled, verifies
   that it belongs to `main`, validates the version against the API, Python
   package, frontend, and lockfile metadata before constructing registry tags,
   and asks the remote once more that the version is still unreleased. Chart
   tests also require its version and application version to match.
4. Builds and publishes `linux/amd64` and `linux/arm64` images to
   `ghcr.io/<repository-owner>/<repository-name>`.
5. Includes BuildKit SBOM/provenance metadata and creates a GitHub provenance
   attestation for the published image digest.
6. Packages the Helm chart with the release version as both its chart version
   and its application version, and pushes it to
   `oci://ghcr.io/<repository-owner>/charts/nyctr`. This happens after the image,
   so a chart version never exists without its image.
7. Creates the GitHub Release and its tag at that commit, last. The body is the
   release notes file followed by the image digest, the chart reference and the
   source commit. Versions with `-alpha.N`, `-beta.N` or `-rc.N` are marked as
   prereleases.
8. Confirms that the new tag identifies the published commit.

### When a release run fails

The tag is created only after everything is published, so a failure before the
last job leaves no tag and no release. Until the release exists, treat any image
or chart tag from a failed run as unpublished. First look at which job failed
and whether the release and tag exist, then choose:

- **Re-run the failed jobs of that run** (Actions page, "Re-run failed jobs").
  This keeps the run's commit and the results of the jobs that passed. Prefer it
  whenever the publish job succeeded and only the release job failed: the
  release is then created for the image digest that was already attested.
  Running the publish job again builds a new image and moves the version tag to
  a different digest, leaving the first attestation pointing at an image the
  tag no longer names.
- **Start a new run** (`workflow_dispatch` on `main`). This releases whatever
  `main` declares now, at its current commit. That is the same version only if
  no later merge changed it, so check the version on `main` first. It rebuilds
  and republishes everything.
- **If the release and tag already exist**, neither helps: every later run sees
  the tag and stops at the plan. That happens when the last step, which
  confirms the tag points at the published commit, is the one that failed. Do
  not move the tag. Compare the tag's commit with the run's commit. If they
  differ, the tag was created by something else while the run was in progress:
  withdraw the release, say so in its notes, and publish the next version.

Only the publication job receives package-write and attestation permissions, and
only the final job may write to the repository, to create the release. No
provider credentials or deployment secrets belong in build arguments or images.
Actions are pinned to reviewed commit SHAs; update those pins deliberately.

Because a merge is what releases, review a pull request that changes the version
as a release. Do not create a tag or a GitHub Release by hand: the workflow
would see the tag and publish nothing for it.

Accepted tags are `vMAJOR.MINOR.PATCH` and
`vMAJOR.MINOR.PATCH-alpha.N`, `-beta.N`, or `-rc.N`, for example
`v0.1.0-alpha.1`. That example is not a claim that the image is available.
Publication creates the exact version tag and a full-commit `sha-<commit>` tag.
There is no floating `latest` tag. Deploy by digest for a fixed artifact.

The chart is published from `v0.1.0-alpha.2` onwards, under the release version
without the leading `v`, for example `0.1.0-alpha.2`. A chart does not choose an
image: set `image.digest` to the digest recorded by the same release.

## Maintainer release checklist

In one pull request:

- Change the version in the API (`services/api/nyctr/__init__.py`), the Python
  package, the frontend package and lockfile, and the chart's version and
  application version. Tests fail if any of them disagree.
- Add `docs/release-notes/v<version>.md`. A test fails without it.
- Run the isolated acceptance instructions and retain a report that identifies
  the exact source commit, operating system, architecture, and tested scenarios.

Then:

- Merge it. The release workflow starts on its own.
- Wait for the release workflow to complete. A failed publication or attestation
  step is not a completed release, even if an image tag was created earlier.
- Verify package visibility and access. The image and the chart are two separate
  GHCR packages. On the first publication of each, ensure the package is public
  before documenting anonymous pulls; repository visibility alone is not
  evidence of package visibility.
- Record the resulting digest in deployment configuration and verify the image's
  provenance with `gh attestation verify oci://<image>@<digest> --repo <owner>/<repo>`.

Do not move a released tag to repair a problem. Publish a new version and retain
the previous digest for reproducible investigations or application rollback.

## Using a published image with Compose

Set `NYCTR_IMAGE` to the digest listed in a release's notes. The image override
retains the existing Compose security and database settings. For the local demo:

```sh
export NYCTR_IMAGE=ghcr.io/homelab-0/nyctr@sha256:<verified-release-digest>
docker compose -f compose.yaml -f deploy/compose/compose.image.yaml \
  up --no-build --pull always --wait -d
```

Replace the placeholder before running the command. For live configuration,
insert `-f deploy/compose/compose.production.yaml` before the image override and
use the documented `.env.production` settings. Keep live and demonstration
databases separate. The Dockerfile and chart use the same application image.

## Rollback and schema limits

Record the deployed digest, chart version, values, and database backup. Current
alpha changes must describe any schema migration explicitly. Rolling back an
image does not roll back a database schema; restore or upgrade only according
to the release's tested migration procedure. Do not assume arbitrary older
images can read a newer database.

## References

- [GitHub: publishing Docker images](https://docs.github.com/en/actions/tutorials/publish-packages/publish-docker-images)
- [GitHub: verifying artifact attestations](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations/verifying-the-provenance-of-artifacts)
- [Docker: multi-platform images with GitHub Actions](https://docs.docker.com/build/ci/github-actions/multi-platform/)
