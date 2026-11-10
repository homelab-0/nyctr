# Container and chart releases

Nyctr is an experimental alpha. The release workflow is implemented, but a
release exists only after its publication run has succeeded. Source builds and
the isolated acceptance stack remain usable before the first publication.

## What triggers publication

Publishing a GitHub Release triggers `.github/workflows/release.yml`. Both stable
and prerelease versions use that event. A pull request or ordinary branch push
does not publish an image or a chart. The workflow:

1. Runs the reusable CI workflow against the exact release commit, including API,
   frontend, container, chart, and isolated integration checks.
2. Checks out the exact commit with persisted Git credentials disabled and
   verifies that it belongs to `main`.
3. Validates the version identifier against the API, Python package, frontend,
   and lockfile metadata before constructing registry tags, and confirms the
   fetched release tag still identifies that exact commit. Chart tests also
   require its application version to match the API and frontend.
4. Builds and publishes `linux/amd64` and `linux/arm64` images to
   `ghcr.io/<repository-owner>/<repository-name>`.
5. Includes BuildKit SBOM/provenance metadata and creates a GitHub provenance
   attestation for the published image digest.
6. Packages the Helm chart with the release version as both its chart version
   and its application version, and pushes it to
   `oci://ghcr.io/<repository-owner>/charts/nyctr`. This happens after the image,
   so a chart version never exists without its image.
7. Records the immutable `image@sha256:...` reference and the chart reference
   in the workflow summary.

Only the publication job receives package-write and attestation permissions. No
provider credentials or deployment secrets belong in build arguments or images.
Actions are pinned to reviewed commit SHAs; update those pins deliberately.

Accepted tags are `vMAJOR.MINOR.PATCH` and
`vMAJOR.MINOR.PATCH-alpha.N`, `-beta.N`, or `-rc.N`, for example
`v0.1.0-alpha.1`. That example is not a claim that the image is available.
Publication creates the exact version tag and a full-commit `sha-<commit>` tag.
There is no floating `latest` tag. Deploy by digest for a fixed artifact.

The chart is published from `v0.1.0-alpha.2` onwards, under the release version
without the leading `v`, for example `0.1.0-alpha.2`. A chart does not choose an
image: set `image.digest` to the digest recorded by the same release.

## Maintainer release checklist

- Merge the reviewed change and confirm its CI results.
- Keep API, Python package, frontend, lockfile, chart version and chart
  application-version metadata aligned with the intended release. Update the README's release status
  when preparing the first published version.
- Run the isolated acceptance instructions and retain a report that identifies
  the exact source commit, operating system, architecture, and tested scenarios.
- Create the version tag on the tested commit in `main` and publish its GitHub
  Release, marking alpha/beta/rc releases as prereleases.
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

Set `NYCTR_IMAGE` to a digest copied from a successful release. The image override
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
