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
- `POST /api/integrations/{id}/sync` -> `{ok,resource_count,observation_count,partial}`.
- `GET /api/audit` -> `{id,created_at,actor_id,action,target_id,details}`[].

Resource: `{id,name,kind,provider,source_id,site_id,observed_at,evidence_kind,
classification,owner_id,attributes}`. `kind`: site, gateway, switch, access_point,
network, client, host, bridge, workload, dns_profile, domain, policy. `evidence_kind`:
observed, configured, inferred. `classification`: personal, shared, infrastructure,
unassigned. IDs are integration-namespaced. `attributes` holds provider details.

Relationship: `{id,source,target,kind,provider,evidence_kind,observed_at,attributes}`.
Kinds are descriptive: contains, connects_to, member_of, hosted_by, governed_by,
resolves_via, same_device. Connections do not prove reachability. `/api/graph`
also returns relationships with provider `nyctr` and evidence `inferred`, computed
at read time by matching hardware address, VLAN tag or address across sources.

Finding: `{id,title,severity,summary,resource_ids,relationship_ids,evidence,status}`.
Severity: high, medium, low, informational. Evidence is an array of strings.

Integration: `{id,provider,name,status,last_sync,last_error,config,secret_ref,
capabilities}`. Providers: unifi_network, nextdns, proxmox (experimental). Credentials
are resolved from environment by reference and never returned. Capabilities are
strings. Unsupported providers appear in the UI as planned, never connected.

## Member-safe inbox and requests

- `GET /api/blocks` -> Block[]; members see only fresh events on devices assigned
  to them at event time and currently authorized. Admins may see all recent events.
- `GET /api/devices` -> Resource[] permitted to the caller.
- `GET /api/requests` -> AccessRequest[] permitted to the caller.
- `POST /api/requests` with `{block_id,reason,duration_minutes}` -> AccessRequest.
  Duration bounded to 15–240 minutes. Reject stale or unauthorized blocks. The
  request is assessed immediately; the access rule may set `auto_approved` and
  open a lease.
- `POST /api/requests/{id}/review` with
  `{decision:"reviewed"|"denied"|"approved",note,minutes?}` is admin-only.
  `reviewed` and `denied` change nothing on the network. `approved` opens a
  temporary lease whose `execution` says whether the provider was changed.
- `POST /api/blocks/find` with `{domain}` -> Block[] among events the caller may see.
- `GET /api/me/device` -> `{device_id,name,simulated}`; only among the caller's devices.

Block: `{id,device_id,device_name,domain,source,reason,reason_codes,observed_at,
expires_at,evidence_kind,attribution,risk_score,risk_band,risk_category,
risk_factors,risk_explanation}`. `risk_score` is computed by `nyctr.risk` from the
stored reason; unknown risk is null with band `unknown`. `attribution`: assigned,
inferred, unverified or unattributed. Members see only `assigned`.
AccessRequest: `{id,block_id,domain,device_name,requester_id,reason,duration_minutes,
status,created_at,review_note,risk_score,risk_category,risk_factors,decided_by,
decision_note}`. Status: pending, auto_approved, approved, denied or reviewed.

## Access rule, leases and suggestions

- `GET /api/rules` (admin) -> `{access,guest,writes,sources,collect_interval_seconds}`.
  The last is the interval in force (0 when the schedule is off), kept for the
  current Setup page.
- `GET /api/collection` (any signed-in user). A member gets
  `{enabled,interval_seconds,next_at}`. An administrator gets
  `{enabled,interval_seconds,next_at,source,choices}`; `source` says where the
  value came from: console (saved with the route below), deployment, default
  or demo. `PUT /api/collection` (admin) with
  `{enabled,minutes}` where minutes is one of `choices`; 409 in demo mode.
  `writes` maps `nextdns` and `unifi_network` to simulated, enabled or disabled.
- `PUT /api/rules/access` with `{enabled,max_score 0–60,max_minutes 15–240,per_day 1–20}`.
- `PUT /api/rules/guest` with `{enabled,hits 1–50,minutes 1–120}`.
- `GET /api/leases` -> Lease[]; members see their own. Reading reconciles expiry.
- `POST /api/leases/{id}/end` (admin). 502 if the provider entry could not be
  removed; the lease stays active with `last_error`.
- `GET /api/suggestions` (admin) -> `{domain,times,people,last_at,risk_score,scope}`[].
- `POST /api/suggestions` with `{domain,action:"make_permanent"|"dismiss"}`.
- `GET /api/device-links`, `PUT /api/device-links` with `{source_id,device_id|null}`.
- `GET /api/users` (admin) -> `{id,name,email,role,active}`[].

Lease: `{id,request_id,integration_id,domain,device_name,requester_id,kind:
"temporary"|"permanent",status:"active"|"ended",ended_reason,execution:
"simulated"|"applied"|"not_applied"|"failed",owned,scope,decided_by,risk_score,
created_at,expires_at,ended_at,last_error}`. `decided_by` is `rule` or a user ID.

## Guest Wi-Fi

- `GET /api/guests` (admin) -> `{writes,rule,sources,passes,devices,not_collected}`.
- `POST /api/guests/passes` with `{name,minutes 30–10080,guest_limit 1–20}`.
  409 when UniFi writes are disabled.
- `POST /api/guests/passes/{id}/end`.
- `POST /api/guests/actions` with
  `{device_id,action:"cut"|"restore"|"lock"|"admit",reason?,minutes?}`. `admit`
  authorises a device in state `waiting` for 30 to 10080 minutes.
- `GET|POST /api/hooks/collect` (Bearer token) or `/api/hooks/collect/{token}`:
  starts a read-only collection. 404 unless `NYCTR_NUDGE_TOKEN` is set and matches.
- `POST /api/demo/guest-activity` exists only in demo mode.

A guest device's `state` is derived from actions that were applied or simulated:
online, waiting, cut, locked or offline. `pass.evidence` is always `inferred`.
`joined_by` is `pass`, `administrator` or null. `portal` is
`{served_by:"unifi",nyctr_in_guest_path:false,wifi:[{name,enabled,captive_portal,
network}],notice,nudge}`. Nyctr has no guest-facing route.

## Queries and assistant

- `POST /api/graph/query` with `{query,variables?}` (admin) -> GraphQL `{data,errors}`.
  Queries only; at most 6000 characters, 10 levels and 20000 returned objects.
- `GET /api/attention` (admin) -> ranked `{kind,id,severity,title,detail,at}`[]. No model.
- `GET /api/assistant` -> `{provider:"model"|"sample"|"off",model}`.
- `POST /api/assistant/ask` with `{question,finding_id?}` ->
  `{answer,references:[{ref,kind,id,label}],provider,model}`. `[[ref]]` tokens in
  `answer` resolve to `references`. 409 when no model is configured in live mode.
- `POST /api/findings/{id}/insight` -> `{take,reasoning,next_steps,confidence,
  provider,model,created_at}`; cached until the finding's evidence changes.

## Integration adapter boundary

Adapters are independent of the database and web framework. Implement in
`nyctr/integrations/`: `async collect(provider, integration_id, config, api_key)`
returns a `Snapshot` with lists `resources`, `relationships`, `blocks`,
`capabilities` and `vouchers`. Dictionaries match the above contracts. Incoming NextDNS blocks
without reliable device mapping remain unattributed/admin-only. GET-only transport,
TLS verification, no credential forwarding on redirects, bounded pagination.

Only `NYCTR_CONNECTOR_SECRET_[A-Z0-9_]+` references may resolve to environment
secrets. UniFi HTTPS endpoint hosts must be explicitly allowed by the server's
`NYCTR_CONNECTOR_HOSTS` setting. NextDNS uses the fixed official API endpoint.
Full source snapshots carry integration ID and collection time. Collection never
writes. Provider changes are confined to `nyctr/integrations/actions.py`, each
taking an explicit `allowed` flag derived from `NYCTR_PROVIDER_WRITES`.

## Schema

Schema version 2. `migrate` upgrades a version-1 database in place by creating
the new tables (settings, leases, device_links, guest_passes, guest_actions,
sightings, insights) and adding nullable columns to observations and
access_requests. No existing row is rewritten.
