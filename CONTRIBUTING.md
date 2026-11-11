# Contributing to Nyctr

Thank you for helping build a clear, usable network security platform. Start with
the README and roadmap. For a large feature or provider integration, open a
proposal describing the user problem, available evidence, and supported APIs.

## Local workflow

1. Fork or create a feature branch from `main`.
2. Follow the README development setup and use synthetic demo data.
3. Make one coherent change, including its documentation and relevant tests.
4. Run the backend tests, frontend tests, and frontend build. Exercise the container
   if packaging changes. Include actual results and any limitations in your pull request.
5. Open a pull request describing the problem, behavior, and verification.

Do not include private network inventories, real browsing history, passwords,
API tokens or exported authentication sessions in reports, screenshots or fixtures.

## Packaged application testing

Use the [independent Docker acceptance guide](docs/testing/cloudex.md) for a fresh
installation, browser workflows, connector diagnostics against local HTTPS
fixtures, and restart persistence. This suite needs no access to a homelab,
production provider, or identity provider. Record the exact tested commit and
which scenarios actually ran.

Changes to the Helm chart should run `python -m pytest tests/deployment -q` with
Helm available. CI checks Helm 3 and 4, installs the chart in a disposable kind
cluster, and exercises PostgreSQL persistence. The container jobs run natively
on AMD64 and ARM64; the provider acceptance job uses an internal Docker network.
Release metadata checks run with `python -m pytest tests/release -q`. Creating a
pull request does not publish an image or deploy the application. Merging one
that changes the version does release it, automatically: see
[docs/releases.md](docs/releases.md). Leave the version alone unless the pull
request is meant to be a release.

## Integration contributions

Adapters normalize provider data into the shared resource, relationship and
observation model. State the supported provider/API version, permission needs,
pagination behavior, rate limits, and capabilities that remain unavailable.
Use official API documentation and synthetic contract fixtures. Include tests
for missing fields, provider errors, page limits, attribution, and TLS/redirect
handling. A live environment check is useful evidence but is never a substitute
for reproducible tests.

Nyctr's core and console name no vendor. A new source is one module that declares
its contract; start from [docs/integration-contract.md](docs/integration-contract.md)
and do not add a provider check to a core module or the web app. Two tests in
`services/api/tests/test_registry.py` enforce this.

Keep collection read only. Provider changes live only in
`services/api/nyctr/integrations/actions.py` behind `NYCTR_PROVIDER_WRITES`. A new
kind of change requires its own design review, verification of the result and
tests for the disabled path; adding a button is insufficient.

## User interface contributions

Preserve the Nyctr theme, keyboard support, readable status labels and responsive
layout. Implement loading, empty and failure states. Keep dangerous or unavailable
actions out of ambiguous success flows. Graph functionality must support pan,
zoom, focus and inspection without accidental text selection.

Run `npm --prefix apps/web run format` before submitting frontend changes.
Run `npm --prefix apps/web test` for the frontend regression suite. CI checks
formatting with `format:check` alongside the tests and TypeScript build.

## Review expectations

Authorization, identity attribution, retention, risk explanation and provider
requests need tests for denied and uncertain outcomes. Keep changes understandable
and dependencies purposeful. Explain any new dependency and pin the resulting
lockfile. Generated code is welcome when its author reviews and verifies it.

Contributions are submitted under the project's Apache-2.0 license. Maintainers
review and merge changes; no response-time commitment is implied during alpha.
