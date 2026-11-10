# Security model and release boundaries

## What the initial application protects

The API authenticates users, enforces administrator/member permissions and checks
CSRF on authenticated mutations. Sessions are revocable server-side records.
Provider credentials are server environment secrets referenced by a restricted
name; arbitrary environment variables are not available as credential sources.
The web client receives evidence and sanitized configuration, not credentials.

Collectors send GET only. There are no firewall mutations and no AI tool calls.

Nyctr can change a provider in three narrow ways, all in
`nyctr/integrations/actions.py`: add or remove one NextDNS allowlist entry,
create or delete one UniFi hotspot voucher, and authorise or unauthorise one UniFi
guest client. Each function refuses to run before any network call unless the
operator named the provider in `NYCTR_PROVIDER_WRITES`, validates its inputs
(a plain domain name, never a URL or wildcard), and reads back the result. Demo
mode simulates every change and never contacts a provider.

Every decision records what happened at the provider: `simulated`, `applied`,
`not_applied` or `failed`. A decision is never displayed as restored or removed
connectivity unless it was applied. With writes disabled, an approval is stored
as not applied and the administrator is told to make the change by hand.

Nyctr acts without a person only under two administrator-written rules, both off
until switched on:

- The access rule may open a request when the score is at or below the written
  limit (which the code caps at 60), the block came from a privacy list, the
  member is under the daily cap, and no administrator denied that address before.
  An unknown score, a security or household block, a missing DNS source, disabled
  writes or a provider failure all leave the request waiting for a person.
- The guest cut-off rule unauthorises a guest device after a written number of
  threat-list lookups within a written number of minutes. It counts stored
  observations. No model output is an input to either rule.

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
| Temporary exception survives restart | Leases are database rows; a background task and every lease read close what has expired, and a failed removal stays open, visible and retried |
| Expiry removes a rule Nyctr did not create | A pre-existing allowlist entry is recorded as not owned and never removed; overlapping leases keep the entry until the last one ends |
| A guest is cut off on a guessed identity | DNS lookups are tied to a guest only by an administrator link or a unique name match, which is labelled inferred and shown in the guest's timeline |
| A guest device attacks the system that polices it | Nyctr is never the captive portal and nothing on the guest network needs to reach it; a guard test fails if any API route answers without a session ([guest Wi-Fi design](guest-wifi.md)) |
| Someone forges the collection nudge | It needs a shared secret, reads nothing from the request, only starts a read-only collection, and runs at most once every 30 seconds |
| Model is told to act by text in a log or request | The model has no tools or credentials; evidence is passed as data in a bounded pack with addresses, emails, codes and identifiers removed |
| Model cites something it was not shown | Citations are resolved against the pack on the server and dropped when they do not match |
| Graph query exhausts the server | Administrator-only, query-only, with length, depth and returned-object limits |

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
  Lease reconciliation, scheduled collection and the assistant's rate limit run
  inside the single API process.
- The NextDNS allowlist calls follow the documented rule for nested array
  endpoints and the UniFi calls follow the 11.0.97 contract. Neither has been
  exercised against the live service.
- A guest "lock out" re-cuts the device at each collection. It is not a
  UniFi-side block and a device that changes its hardware address evades it.
- The risk score reads only the block reason and the shape of the name. It is
  not a reputation service and must not be presented as one.
- Device recognition in the member portal matches the connecting address to
  inventory among devices already assigned to the caller. It does not work
  through NAT or a proxy that hides the member's LAN address.
- Audit export and tamper-evidence. A database audit table is not an immutable log.
- Explicit schema upgrade and rollback testing beyond the initial schema.
- Image signing/SBOM publication, pinned release images and upgrade policy.

## Change authorization

An approval binds to one domain on one DNS source for a stated time. The lease
records the attempted provider operation, its outcome and whether Nyctr owns the
entry. Still to do: bind approvals to an immutable plan digest, separate the
execution service from the API process, and invalidate approvals on detected
configuration drift.

A profile-wide DNS exception may affect more than one person. That effective
scope must be shown before approval. Never silently convert a domain request
into a broad shared-CDN IP allow rule.

No block reason, no reputation hit, or a low numeric risk score is insufficient
to prove safety. An automatic temporary grant must satisfy the explicit
administrator rule and fails closed on missing evidence.
