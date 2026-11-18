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
- `GET /api/integrations` -> Integration[], each with `gaps`: `{id,title,summary}`[] for
  what its last stored collection could not read (empty when it read everything).
- `POST /api/integrations` with `{provider,name,config,secret_ref}` -> Integration.
- `POST /api/integrations/{id}/sync` -> `{ok,resource_count,observation_count,partial,gaps}`;
  `gaps` is how many things that collection could not read.
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

- `GET /api/blocks` -> BlockList: one page of at most 200 events, newest first.
  Members see only fresh events on devices assigned to them at event time and
  currently authorized. Admins may see all recent events. That rule is applied in
  the database query before the page is cut and before anything is counted, so
  a member's totals, counts and page boundaries come only from events they may see.
  Optional `band` (`high`, `medium`, `low`, `unknown`) and `q` (text found in the
  address, device name or reason) narrow the rows; `before` takes the `next` value
  of the page above and returns the rows strictly older than its last one, so
  events stored between two requests are neither skipped nor repeated.
- `GET /api/devices` -> Resource[] permitted to the caller.
- `GET /api/requests` -> AccessRequest[] permitted to the caller.
- `POST /api/requests` with `{block_id,reason,duration_minutes}` -> AccessRequest.
  Duration bounded to 15–240 minutes. Reject stale or unauthorized blocks.
  Sending it again returns the stored event for that member and block, the row
  with no device id, including a row stored before the basis column, and does
  not file a second one. A statement for a device is a different request and
  is not returned. The request is assessed immediately; the access rule may
  set `auto_approved` and open a lease.
- `POST /api/requests/{id}/review` with
  `{decision:"reviewed"|"denied"|"approved",note,minutes?}` is admin-only.
  `reviewed` and `denied` change nothing on the network. `approved` opens a
  temporary lease whose `execution` says whether the provider was changed.
- `POST /api/blocks/find` with `{domain}` -> Block[] among events the caller may see.
- `GET /api/blocks/one?id=` -> Block, for an event on any page of the list. An event that is
  missing, expired or not visible to the caller answers the same 404.
- `GET /api/me/device` -> `{device_id,name,simulated,how,reason,message}`; only among the
  caller's devices. `how` is `assigned` or `signed_in`. With recognition at sign-in switched on,
  the first request after signing in ties the caller to the one device the gateway says holds
  the request's address; when no device is recognised, `reason` is a code and `message` the
  sentence to show (never whose a device is). A request over IPv6 is refused by rule with the
  reason `ipv6`, an address that two sites or two sources both use with `two_networks`, and a
  tie the database was too busy to write with `busy`; none is an error.
  In the demonstration the page does not ask a gateway. It chooses a permitted
  client whose stored address is this request's address, or else the first
  personal device the member may use, by name and then by id. A stored address
  on a device the member may not use is not chosen.
- `GET /api/presence` -> `{items}`: a member's own ties in force; for an administrator every
  tie and conflict on record, with `enabled` and `reach_back_hours`. An item is
  `{id,kind,user_id,user_name,device_id,device_name,basis,first_at,last_at,ended_at}`, `kind`
  being `tie` or `conflict`. An administrator's items also carry `address` (where the request
  came from) and `mac` (the device's hardware address); a member's never do. Both are deleted
  with the record, 90 days after a tie ends or after a conflict's last attempt.
- `PUT /api/presence` with `{enabled}`, `{reach_back_hours}` (0 to 24) or both is admin-only
  and answers the setting now in force. A part left out stays as stored, so a page that still
  shows an older switch cannot put it back by saving the hours. Switching it off ends every
  tie; a shorter reach applies to ties already made.
- `DELETE /api/presence/{id}` ends a tie at once: a member their own, an administrator any.
  An assignment that changes a device's classification, owner or named people
  (`PUT /api/devices/{id}/assignment`) also ends, in the same transaction, every tie on it
  held by anyone it does not name. Each ending writes one `presence.ended` audit record with
  the device, `user_id` and, unless a person ended that one tie, `because`: `assignment`,
  `switched_off`, `lapsed` (written by the worker) or `device_removed`. A tie that had lapsed
  and not yet been recorded when its device went is recorded as `lapsed`, with `ended_at`.
  `ended_at` in the list is the recorded ending or, until the worker records it, 30 days after
  `last_at`.
  A new tie's reach starts at the later of `first_at` minus `reach_back_hours`, the device's
  last `device.assignment_changed` record and, unless the device is shared, the end of the
  last tie another person held on it. A tie made on stored inventory (`basis: stored`) reaches
  back to nothing: its reach starts at `first_at`. A tie an assignment keeps has its reach moved
  to that assignment, also when the save changed nothing. The `presence.tied`,
  `presence.conflict` and `presence.ended` records carry `device_name`. Only a source whose
  integration declares `devices.lookup` is considered when the address is placed. `PUT
  /api/presence` and the write of a tie hold the stored setting's row, so no tie commits after
  recognition is switched off; a sign-in that lost that race answers `off`. A sign-in takes
  that row before it reads who is tied to the device, so of two people signing in on one
  unshared device at the same moment one is tied and the other is answered `other_person`.
  Every writer of a tie (a sign-in, `PUT /api/presence`, an assignment, `DELETE
  /api/presence/{id}` and the worker's closing of lapsed ties) takes its locks in one order
  before it reads a tie: the setting's row first and the ties last. A sign-in, an assignment
  and forgetting take the one device's row in between; `PUT /api/presence` and the worker take
  no device's row, so they cannot wait on a collection that is being stored while it waits on
  them. So an assignment saved while the setting is being changed is never overwritten by it.

BlockList: `{rows,next,page_size,total,matching,oldest_at,newest_at,counts}`. `rows`
is Block[]. `total`, `oldest_at`, `newest_at` and `counts` (`band`, `source` as
`{total,unnamed}` per kind of source, `named`, `unnamed`) describe every event
the caller may see, whatever the filter or page; `matching` is how many pass the
filter. Every stored event the caller may see is read once per request to be
scored and counted, so the cost grows with what is stored, not with the page.

Block: `{id,device_id,device_name,domain,source,reason,reason_codes,observed_at,
expires_at,evidence_kind,attribution,risk_score,risk_band,risk_category,
risk_factors,risk_explanation}`. `risk_score` is computed by `nyctr.risk` from the
stored reason; unknown risk is null with band `unknown`. `attribution`: assigned,
inferred, unverified or unattributed. Members see only `assigned`, on a device assigned to
them or one they are tied to by signing in on it (`nyctr/deps.py` decides, nowhere else).
AccessRequest: `{id,block_id,domain,device_name,requester_id,reason,duration_minutes,
status,created_at,review_note,risk_score,risk_category,risk_factors,decided_by,
decision_note}`. Status: pending, auto_approved, approved, denied or reviewed.

## Access rule, leases and suggestions

- `GET /api/rules` (admin) -> `{access,guest,writes,sources}`.
- `GET /api/collection` (any signed-in user). A member gets
  `{enabled,interval_seconds,next_at}`. An administrator gets
  `{enabled,interval_seconds,next_at,source,choices}`; `source` says where the
  value came from: console (saved with the route below), deployment, default
  or demo. `PUT /api/collection` (admin) with
  `{enabled,minutes}` where minutes is one of `choices`; 409 in demo mode.
  `writes` maps `nextdns` and `unifi_network` to simulated, enabled or disabled.
- `PUT /api/rules/access` with `{enabled,allow_statement,per_day 1–20,daily_total 1–100,
  ad_tracker:{mode,max_score 0–60,max_minutes 15–240},
  threat_feed:{mode,max_minutes 15–240,min_registered_days 30–3650}}`. `mode` is
  off, shadow (record only) or on for `ad_tracker`, and only off for
  `threat_feed`, whose `max_minutes` cannot be above `ad_tracker`'s. No other
  tier can be named. `allow_statement` defaults to false. Left out of a save, it
  is stored false. Off, a statement always waits for a person. On, the rule
  decides it as any other request. A deliberate block or an unknown score still
  waits. A stored statement is opened only while the account is active and the
  member still has an assignment or a live tie on the device stored with the
  request. The account is read again from the database before the opening,
  again after the claim on that source entry is held, and again after a
  provider has been asked. If the account or the device no longer qualifies
  before the provider is asked, the claim is given back and nothing is sent.
  If it no longer qualifies after the provider has been asked, the request
  waits, and an entry this opening added is removed on the next upkeep tick.
  The sign-in does not have to remain. An event request, and a row whose basis
  is empty, is left on the path that filed it. No route files a statement.
  The form before tiers (`{enabled,max_score,max_minutes,
  per_day}`) is read from storage and refused here. Read back, its daily total
  is the old limit for each person times the number of active accounts, from
  1 to 100. A rule written with this route starts at 10 when the total is left
  out. Each request the rule looks
  at leaves an audit record `rule.access_checked` with
  `{domain,tier,outcome: may_open|would_open|waits,checks,limits,minutes?,why?}`.
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
  A source that stored only part of a collection also carries `action`: `edit` or `card`.
- `GET /api/assistant` -> `{provider:"model"|"sample"|"off",model}`.
- `GET /api/model` (admin) -> `{connected,endpoint,model,secret_ref,key:"reference"|
  "server"|"none",trace,timeout_seconds,source:"console"|"deployment"|"none",problem,
  editable,hosts,styles,seconds}`. Never the key. `PUT /api/model` (admin) with
  `{endpoint,model,secret_ref?,trace?,timeout_seconds?}` -> the same; 422 in plain
  words when a rule fails or the body has another shape (nothing sent is repeated), 409 in demo. `POST /api/model/test` (admin) ->
  `{outcome:"reachable"|"refused"|"not_reachable"|"wrong_shape"|"too_slow",status}`;
  409 when no model is connected or the saved one may not be used or cannot be read.
  `hosts` are the allowed servers as written (`https://name`, `http://name:4000`).
  `GET /api/attention` lists a saved model that cannot be used as `kind:"model"`.
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

Schema version 2: `migrate` upgrades a version-1 database in place by creating
the new tables (settings, leases, device_links, guest_passes, guest_actions,
sightings, insights) and adding nullable columns to observations and
access_requests. No existing row is rewritten.

Schema version 3 adds one table, `device_presence` (sign-in ties and conflicts), and alters
nothing else. The upgrade from version 2 is tested on SQLite and PostgreSQL 17 with every
stored row compared before and after.

Schema version 4 adds the fact cache (`fact_cache`) and the list of names Nyctr
itself looked up (`own_lookups`). Nothing that exists is altered.

Schema version 5 adds two nullable columns on `integrations`, `sync_holder` and
`sync_heartbeat`. No existing row is rewritten. Heartbeats are written and
compared with the database clock. A start of Nyctr that finds a collection
whose holder is a different one, and whose heartbeat is older than 60 seconds,
records it as cut short by a restart. A missed beat is recorded as no sign of
life, and a collection cancelled before it stored is recorded as stopped. None
of these leave the source marked as collecting.

Schema version 6 adds one table, `analyses`, a stored verdict on a blocked name.
Nothing that exists is altered.
