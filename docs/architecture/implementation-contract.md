# Foundation implementation contract

This is the working contract for Nyctr's first implementation. The HTTP API is
under `/api`; all JSON property names use snake_case. Lists are JSON arrays unless
specified. Errors use FastAPI's `detail` string. Version: `0.1.0-alpha.1`.

## Identity

- `GET /api/health` -> `{status, version}` (public).
- `GET /api/auth/config` -> `{mode: "demo"|"live", local_enabled, oidc_enabled}`.
- `POST /api/auth/login` with `{email,password}` -> session user. HTTP-only cookie.
- `GET /api/auth/me` -> `{id,email,name,role: "admin"|"member",csrf_token,mode}`.
- `POST /api/auth/logout` -> `{ok:true}`.
- `GET /api/auth/oidc/login` and `/api/auth/oidc/callback` when configured.
- Every state-changing authenticated request requires `X-CSRF-Token`.
- Demo identities: `admin@nyctr.demo` and `jamie@nyctr.demo`, password `nyctr-demo`.
  These exist only in explicitly enabled demo mode; live collectors are disabled
  in demo mode. In live mode bootstrap a local administrator from environment.

## Admin data

- `GET /api/overview` -> `{resource_count,relationship_count,finding_count,
  recent_block_count,integration_count,mode}`.
- `GET /api/resources` -> Resource[].
- `GET /api/graph?focus=<optional-id>&depth=1` -> `{nodes:Resource[],edges:Relationship[]}`.
  Without focus, all data is returned; depth is bounded to 1–3.
- `GET /api/findings` -> Finding[].
- `GET /api/integrations` -> Integration[].
- `POST /api/integrations` with `{provider,name,config,secret_ref}` -> Integration.
- `POST /api/integrations/{id}/sync` -> `{ok,resource_count,observation_count}`.
- `GET /api/audit` -> `{id,created_at,actor_id,action,target_id,details}`[].

Resource: `{id,name,kind,provider,source_id,site_id,observed_at,evidence_kind,
classification,owner_id,attributes}`. `kind`: site, gateway, switch, access_point,
network, client, host, workload, dns_profile, domain, policy. `evidence_kind`:
observed, configured, inferred. `classification`: personal, shared, infrastructure,
unassigned. IDs are integration-namespaced. `attributes` holds provider details.

Relationship: `{id,source,target,kind,provider,evidence_kind,observed_at,attributes}`.
Kinds are descriptive: contains, connects_to, member_of, hosted_by, governed_by,
resolves_via. Connections do not prove reachability.

Finding: `{id,title,severity,summary,resource_ids,relationship_ids,evidence,status}`.
Severity: high, medium, low, informational. Evidence is an array of strings.

Integration: `{id,provider,name,status,last_sync,last_error,config,secret_ref,
capabilities}`. Providers: demo, unifi_network, nextdns, unifi_fabric. Credentials
are resolved from environment by reference and never returned. Capabilities are
strings. Unsupported providers appear in the UI as planned, never connected.

## Member-safe inbox and requests

- `GET /api/blocks` -> Block[]; members see only fresh events on devices assigned
  to them at event time and currently authorized. Admins may see all recent events.
- `GET /api/devices` -> Resource[] permitted to the caller.
- `GET /api/requests` -> AccessRequest[] permitted to the caller.
- `POST /api/requests` with `{block_id,reason,duration_minutes}` -> AccessRequest.
  Duration bounded to 15–240 minutes. Reject stale or unauthorized blocks.
- `POST /api/requests/{id}/review` with `{decision:"reviewed"|"denied",note}`
  is admin-only and records an internal review; it NEVER grants access.

Block: `{id,device_id,device_name,domain,source,reason,observed_at,expires_at,
evidence_kind,attribution,risk_score,risk_explanation}`. Unknown risk is null.
AccessRequest: `{id,block_id,domain,device_name,requester_id,reason,duration_minutes,
status,created_at,review_note}`. Initial status `pending`; no execution endpoint.

## Integration adapter boundary

Adapters are independent of the database and web framework. Implement in
`nyctr/integrations/`: `async collect(provider, integration_id, config, api_key)`
returns a `Snapshot` with lists `resources`, `relationships`, `blocks`, and
`capabilities`. Dictionaries match the above contracts. Incoming NextDNS blocks
without reliable device mapping remain unattributed/admin-only. GET-only transport,
TLS verification, no credential forwarding on redirects, bounded pagination.

Only `NYCTR_CONNECTOR_SECRET_[A-Z0-9_]+` references may resolve to environment
secrets. UniFi HTTPS endpoint hosts must be explicitly allowed by the server's
`NYCTR_CONNECTOR_HOSTS` setting. NextDNS uses the fixed official API endpoint.
Full source snapshots carry integration ID and collection time. No live writes.
