# Security model and release boundaries

## What the initial application protects

The API authenticates users, enforces administrator/member permissions and checks
CSRF on authenticated mutations. Sessions are revocable server-side records.
Provider credentials are server environment secrets referenced by a restricted
name; arbitrary environment variables are not available as credential sources.
The web client receives evidence and sanitized configuration, not credentials.

Collectors send GET only. There are no firewall mutations, DNS allowlist writes,
AI tool calls, automatic grants or execution endpoints in this version. Internal
request review is a workflow decision and must never be displayed as restored
connectivity.

## Threats considered

| Threat | Required boundary |
| --- | --- |
| Member requests another person's event by ID | Server authorization, including event-time ownership and current access |
| Shared upstream resolver is mistaken for a person | Unattributed events remain administrator-only |
| Stale block becomes an access grant | Reject stale requests; later plans must revalidate evidence |
| Provider redirects leak an API key | No redirected credential-bearing requests |
| Configured endpoint targets internal metadata | Explicit console host allowlist, HTTPS validation, reserved-address restrictions |
| Provider returns misleading successful HTTP status | Parse provider-level errors; never treat missing/error data as safe |
| Log text or domain is used as prompt instructions | Future AI treats source text as untrusted evidence and cannot execute |
| Model invents confidence or permissions | Unknown risk remains unknown; external authorization owns decisions |
| Temporary exception survives restart | Future durable leases and reconciliation, before writes are enabled |

## Deployment responsibilities

Use HTTPS, retain secure cookies in live deployments, keep the service behind
appropriate network controls, and protect database backups. Set a strong initial
administrator password or configure OIDC. Configure narrowly scoped provider
credentials where their APIs support it. Never disable TLS verification to make
a console connection succeed; configure a valid trust chain instead.

Demo and live databases must be separate. Demo is for evaluation using known
accounts and synthetic events. Do not expose demo to an untrusted network.

## Limitations to resolve before a production release

- Complete independent review of authentication, OIDC mappings, SSRF boundaries,
  source parsing and member visibility.
- End-to-end validation against supported real provider versions, including
  missing telemetry and asymmetric routing.
- Documented retention/deletion jobs and backup/restore exercises. Hiding stale
  inbox events is not equivalent to deleting stored observations.
- Multi-process-safe throttling and job concurrency if scaling beyond one process.
- Audit export and tamper-evidence. A database audit table is not an immutable log.
- Explicit schema upgrade and rollback testing beyond the initial schema.
- Image signing/SBOM publication, pinned release images and upgrade policy.

## Future change authorization

An approval must bind to an exact action and resource scope. The execution
service checks that scope independently from the UI and analysis service. It
records the attempted provider operation, response and post-change verification.
Plan changes or detected configuration drift invalidate the original approval.

A profile-wide DNS exception may affect more than one person. That effective
scope must be shown before approval. Never silently convert a domain request
into a broad shared-CDN IP allow rule.

No block reason, no reputation hit, or a low numeric risk score is insufficient
to prove safety. Any future automatic temporary grant must satisfy an explicit
administrator policy and must fail closed on missing required evidence.
