# Nyctr API

FastAPI and SQLAlchemy backend for the first Nyctr implementation. It stores
identity, inventory, typed relationships, block observations, access requests,
source-collection state, leases, guest passes and audit events. Collection is
read only. Provider changes are confined to `nyctr/integrations/actions.py` and
are off unless `NYCTR_PROVIDER_WRITES` names the provider. A decision and what
happened at the provider are recorded separately.

## Development

From this directory, using Python 3.12 or later:

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
NYCTR_MODE=demo NYCTR_PUBLIC_URL=http://localhost:5173 \
  .venv/bin/uvicorn nyctr.main:app --host 127.0.0.1 --port 8000
```

Run the web development server separately and proxy `/api` to this server. Set
`NYCTR_PUBLIC_URL` to the origin the browser actually uses, including its port.
The application validates browser Origin headers on mutations and uses a CSRF
token on every authenticated state-changing request.

Demo credentials are `admin@nyctr.demo` and `jamie@nyctr.demo`, each with password
`nyctr-demo`. These accounts are created only when `NYCTR_MODE=demo` is explicitly
configured. Demo mode cannot create or run live integrations. Never expose demo
mode to an untrusted network.

```bash
.venv/bin/pytest
.venv/bin/ruff check nyctr tests
```

The tests use in-memory/file-backed SQLite, HTTP transports with recorded fixture
shapes, and locally signed test identity tokens. They do not call live network
equipment or an actual identity provider. PostgreSQL is the deployment target.

## Configuration

| Variable | Purpose |
| --- | --- |
| `NYCTR_MODE` | `live` (default) or explicitly `demo`. A database cannot switch between modes. |
| `NYCTR_DATABASE_URL` | SQLAlchemy URL. Deployment example: `postgresql+psycopg://nyctr:password@postgres/nyctr`. Local default: `sqlite:///./nyctr.db`. |
| `NYCTR_PUBLIC_URL` | Exact browser origin, e.g. `https://nyctr.example.org`. Used for Origin validation and OIDC callback. |
| `NYCTR_COOKIE_SECURE` | Defaults to true in live mode, false in demo. Live deployment should use HTTPS. |
| `NYCTR_BOOTSTRAP_ADMIN_EMAIL` | Initial local administrator email. |
| `NYCTR_BOOTSTRAP_ADMIN_PASSWORD` | Initial administrator password, minimum 12 characters. Existing user credentials are not overwritten on restart. |
| `NYCTR_LOCAL_LOGIN_ENABLED` | `true` by default. Disable when using OIDC exclusively. |
| `NYCTR_SESSION_HOURS` | Session lifetime, 1–24 hours; default 12. |
| `NYCTR_BLOCK_RETENTION_HOURS` | Maximum live block-inbox lifetime, 1–168 hours; default 24. |
| `NYCTR_STATIC_DIR` | Optional built frontend directory containing `index.html`; API routes retain precedence. |
| `NYCTR_CONNECTOR_SECRET_<NAME>` | Server-only integration credential. Persist only its variable name in connection settings. |
| `NYCTR_CONNECTOR_HOSTS` | Explicit comma-separated UniFi HTTPS host allowlist; see the integration setup documentation. |
| `NYCTR_CONNECTOR_CA_BUNDLE` | Optional server-side path to a PEM CA bundle used to validate connector HTTPS certificates. Use a valid chain and matching hostname; TLS verification cannot be disabled. |
| `NYCTR_OIDC_ISSUER` | Exact HTTPS issuer identifier, including trailing slash where required by your provider. |
| `NYCTR_OIDC_CLIENT_ID` | OIDC client identifier. |
| `NYCTR_OIDC_CLIENT_SECRET` | Confidential client secret. Configure in the deployment secret store. |
| `NYCTR_OIDC_ADMIN_GROUPS` | Exact comma-separated trusted group values that grant the administrator role. Empty means no OIDC administrators. |
| `NYCTR_OIDC_ALLOWED_GROUPS` | Optional comma-separated groups allowed to sign in. Admin groups are also allowed. Empty permits any valid identity from the configured issuer. |
| `NYCTR_OIDC_GROUPS_CLAIM` | Signed ID-token claim containing a list of group strings; default `groups`. |

On first live startup, configure a local bootstrap administrator or OIDC. No
default live credentials exist. Local passwords use scrypt with a random salt.
Session cookies contain random tokens whose hashes are stored in the database;
sessions can be revoked, expire, and rotate on login. Cookies are HTTP-only and
SameSite=Lax. Only metadata and authentication setup are public API endpoints;
the OpenAPI document describes schemas without returning runtime data or secrets.

## OIDC

Configure the confidential application callback as:

```text
https://nyctr.example.org/api/auth/oidc/callback
```

The implementation uses authorization code flow with S256 PKCE. It stores nonce,
code verifier, expiry and hashed state/browser binding in the database. ID tokens
must have a trusted asymmetric signature, expected issuer/audience, valid expiry,
subject and exact nonce. A claimed `nonce_supported=false` never bypasses checks.
The flow is consumed once. Provider tokens are discarded after verification and
never returned to the frontend.

Accounts are bound to issuer plus subject, not email. An IdP identity cannot take
over a local account by supplying its email address. Only configured groups from
the verified ID token determine the role. Ensure Authentik or another provider
includes your group claim in its ID token; a group claim existing only on the
userinfo endpoint is not used in this implementation.

## Evidence and member privacy

Graph edges carry `observed`, `configured` or `inferred` evidence types. They are
relationships, not a proof of a complete forwarding path. The demo policy findings
are explicitly synthetic; this first version does not run a live posture analysis
or produce a model-generated risk score. Unknown risk is `null`.

Members can see events only when a device is classified personal/shared, its
ownership is verified at the time of the event, and the member is currently
authorized. IP addresses alone never establish ownership. Personal devices also
check the current owner. Infrastructure, unattributed and expired observations do
not enter a member's inbox. NextDNS observations remain administrator-only until
trusted cross-source attribution is implemented.

`PUT /api/devices/{id}/assignment` is an administrator-only API for explicit device
classification and user grants. Its body is `{classification,user_ids}`. Personal
devices require one owner, shared devices require one or more users, and
infrastructure/unassigned devices have no member grants. Assignment changes are
temporal; they never backdate access. PostgreSQL row locks serialize changes to a
device's grants.

Inbox expiry is enforced at read/request time. Expired observations are deleted
when the inbox is read. Access requests retain their domain/device snapshot so
inbox cleanup does not erase the request or its audit trail. Duplicate requests
from the same user for the same event return the original request. An expired
event cannot create a new request. Request review accepts only `reviewed` or
`denied`; execution and temporary exceptions are not present in this version.

## Integration diagnostics

`POST /api/integrations/{integration_id}/diagnostics` checks a saved integration
without importing its inventory or observations. It requires an administrator
session and the usual CSRF header, accepts no credentials from the browser, and
is disabled in demo mode. The existing per-integration collection lease excludes
simultaneous diagnostics and collection. A completed check restores the prior
collection status, error and last-success time; it does not turn an older failed
collection into a successful one.

The diagnostic revalidates the saved configuration and restricted secret
reference, then uses the existing GET-only collector with verified HTTPS and
bounded pagination, response sizes and deadlines. The adapter's 60-second limit
and the endpoint's outer 90-second limit also apply to diagnostics. It does not
test arbitrary URLs or follow provider redirects.

Completed reports use HTTP 200, including reports that diagnose a failure. The
response contains `checked_at`, `duration_ms`, fixed stage `checks`, a
`capabilities` list, explicit `evidence_gaps`, and optional `snapshot_counts`.
Authentication/CSRF denials use 401/403, missing integrations use 404, and demo
mode or an already-busy integration uses 409. No provider bodies, source device
names, browsing domains, API keys or raw exception messages appear in a report.
The audit records the outcome, fixed failure categories and counts only.

Each check separates configuration, server credential availability, connectivity,
TLS, provider authentication and response-contract parsing. A received HTTPS
401/403 response verifies a transport exchange but reports failed provider
authentication. A connection failure without a typed TLS cause leaves TLS
unknown. DNS resolution and routing are not presented as independently verified
tests. HTTP 200 alone does not establish accepted credentials or valid data.

Capabilities report adapter implementation separately from this diagnostic's
verification. `verified` means the relevant bounded source data passed the
implemented parser; `unknown` means it was not established; `unavailable` covers
explicitly disabled logging or features that are not implemented. The overall
`outcome` is `verified` when the supported reads complete, `partial` when some
reads succeed but coverage is incomplete, and `failed` when no supported read is
verified. This is not a security score or an assertion of complete network
posture. Counts are returned only after a complete in-memory snapshot exists;
failed partial collections return `snapshot_counts: null`.

NextDNS upstream identity remains unverified, absent policy sections remain
unknown, and source-disabled logging is shown explicitly. An empty log query
does not prove an absence of blocked connections. UniFi discovery with no visible
sites verifies only discovery, since inventory endpoints were not exercised.
Configured UniFi policies never stand in for observed firewall events or proven
end-to-end reachability. The current adapter has no firewall-event receiver.

Diagnostics are a synchronous, ephemeral check. They do not add scheduled work,
persist a diagnostic report, change provider configuration, or grant access.

## Collection and schema lifecycle

UniFi Network, NextDNS and the experimental Proxmox adapter expose bounded
read-only snapshot collection.
Collection has a 90-second deadline and a database-backed per-integration lease.
Failed collection preserves the prior snapshot. Source identifiers are
integration-namespaced. Existing device grants survive successful refreshes, and
missing resources are marked missing rather than silently reassigned or deleted.
Event replays never extend their original inbox expiry.

Schema initialization is explicit and versioned in `nyctr/database.py` and the
`schema_versions` table. Version 1 creates only an empty, dedicated database;
unknown schemas and unsupported versions fail closed. PostgreSQL advisory locks
serialize initial migration and bootstrap. Future model changes require a new
explicit migration; changing the models alone does not upgrade a database.

The first implementation runs bounded collection in the HTTP request. Durable
background analysis, scheduled collection, an expiry executor, approved network
mutations and AI provider routing are subsequent milestones. Audit is append-only
through the application API, not a tamper-proof external audit store.
