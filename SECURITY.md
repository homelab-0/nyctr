# Security policy

Nyctr handles network topology, DNS observations and potentially sensitive device
relationships. Treat your deployment and database as sensitive infrastructure.

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/homelab-0/nyctr/security/advisories/new)
when enabled for this repository. If that option is unavailable, open an issue
requesting a private reporting channel without including exploit details, logs,
credentials, personal data or sensitive network addresses. A maintainer will
arrange a private channel. Do not send secrets as part of a report.

Include the affected commit/version, deployment mode, prerequisites, minimal
reproduction, expected versus actual behavior, and impact. Use synthetic data.

## Supported versions

The project is in its initial alpha. Security fixes target the latest `main`
revision; no supported stable release or response-time SLA is promised yet.

## Security boundaries

- Public health and authentication configuration are intentionally minimal.
- Authentication, roles, CSRF and member scoping are enforced by the API.
- Demo mode uses known credentials and fabricated data. It cannot collect live
  infrastructure and must never be used as a production deployment.
- Provider credentials are resolved by restricted server-side environment
  references. They must not be returned to the web client or logged.
- Current collectors send only GET requests and verify TLS. Provider-specific
  read permissions should also be selected where available.
- The first release has no provider write endpoint, automatic access grant or
  autonomous AI action.

Read [the security model](docs/security-model.md) for data provenance, identity,
retention and the planned approval/execution design. These are implementation
boundaries, not a claim that the alpha has undergone an independent security audit.
