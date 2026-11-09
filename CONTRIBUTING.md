# Contributing to Nyctr

Thank you for helping build a clear, usable network security platform. Start with
the README and roadmap. For a large feature or provider integration, open a
proposal describing the user problem, available evidence, and supported APIs.

## Local workflow

1. Fork or create a feature branch from `main`.
2. Follow the README development setup and use synthetic demo data.
3. Make one coherent change, including its documentation and relevant tests.
4. Run the backend tests and frontend build. Exercise the container if packaging
   changes. Include actual results and any limitations in your pull request.
5. Open a pull request describing the problem, behavior, and verification.

Do not include private network inventories, real browsing history, passwords,
API tokens or exported authentication sessions in reports, screenshots or fixtures.

## Integration contributions

Adapters normalize provider data into the shared resource, relationship and
observation model. State the supported provider/API version, permission needs,
pagination behavior, rate limits, and capabilities that remain unavailable.
Use official API documentation and synthetic contract fixtures. Include tests
for missing fields, provider errors, page limits, attribution, and TLS/redirect
handling. A live environment check is useful evidence but is never a substitute
for reproducible tests.

Keep collection read only. A new write-capable integration requires the approved
execution architecture and its own design review; adding a button is insufficient.

## User interface contributions

Preserve the Nyctr theme, keyboard support, readable status labels and responsive
layout. Implement loading, empty and failure states. Keep dangerous or unavailable
actions out of ambiguous success flows. Graph functionality must support pan,
zoom, focus and inspection without accidental text selection.

Run `npm --prefix apps/web run format` before submitting frontend changes.
CI checks the formatting with `format:check` alongside the TypeScript build.

## Review expectations

Authorization, identity attribution, retention, risk explanation and provider
requests need tests for denied and uncertain outcomes. Keep changes understandable
and dependencies purposeful. Explain any new dependency and pin the resulting
lockfile. Generated code is welcome when its author reviews and verifies it.

Contributions are submitted under the project's Apache-2.0 license. Maintainers
review and merge changes; no response-time commitment is implied during alpha.
