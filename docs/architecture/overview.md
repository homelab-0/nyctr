# Architecture

## Product scope

Nyctr connects network inventory, policy configuration, observed behavior and
identity to explain posture and access. The workspace includes topology,
relationship exploration, findings, port posture, DNS/firewall investigations,
member requests, integration health, AI analysis and controlled remediation.
The initial implementation deliberately establishes the data and authorization
boundaries before adding write-capable automation.

## Initial runtime

The application has a React/TypeScript web client, a FastAPI backend and a
PostgreSQL database. One application image contains the compiled frontend and
Python service. SQLite supports local development and isolated tests. Provider
adapters are independent Python modules, not separate microservices.

The API owns identity, authorization and persistence. The frontend cannot choose
its role or widen a query's member scope. Read-only collection is currently
initiated by an administrator and bounded per request. Durable scheduled
collection and background analysis will be separate worker responsibilities.

## Core data

| Entity | Responsibility |
| --- | --- |
| Resource | Provider-namespaced site, network, device, workload, destination or policy |
| Relationship | Typed edge with source, collection time and evidence kind |
| Observation | Event, destination, reason, source time and expiry |
| Device assignment | Identity authorization with time-valid attribution |
| Finding | Explanation, affected resources, supporting evidence and uncertainty |
| Access request | Durable user intent linked to a specific eligible observation |
| Integration | Provider, validated configuration, secret reference and collection health |
| Audit record | Actor, action, target, time and sanitized outcome |

Resources use provider/integration namespaces. Similar names and IP addresses do
not merge identities. Provider keys, device labels and addresses can change; a
future reconciliation layer must preserve evidence before joining records.

Each graph edge is **observed**, **configured**, or **inferred**. Physical
attachment, VLAN membership, hosting, policy application and DNS resolution are
different relationships. Unknown or stale evidence stays visible. There is no
claim of a proven end-to-end traffic path merely because nodes are connected.

## Integration contract

Each adapter validates its configuration and returns a normalized snapshot with
resources, relationships, observations and capabilities. The API persists the
snapshot transactionally and records collection status. Source IDs are stable
within an integration. Collection uses verified HTTPS, bounded requests and
pagination, sanitized failures and no credential forwarding across redirects.

Provider capability reporting is explicit. A configured API credential does not
prove that event logs are available. UniFi Network's future event receiver will
be a channel within that integration. An optional generic receiver can later
support other sources without creating a duplicate UniFi provider.

UniFi Fabric will group Site Manager connection/setup in the UI. Its API endpoint,
credentials and collection coverage remain separately modeled. The supplied
Carrier/ISP Fabric subscriber contract does not establish support for
organizational Blueprint/Canvas controls.

## Analysis and execution

The intended flow is collection → normalized evidence → analysis → proposal →
authorization → execution → verification. Each step has an explicit owner.
The alpha implements the read path and internal request review. It has no
infrastructure change executor.

Deterministic analysis should establish facts and policy semantics before AI
summarizes them. AI responses must refer to authorized evidence, identify gaps
and return structured proposals. Provider credentials stay outside model context.
A configurable model-provider boundary will support LiteLLM and future Spektr
routing. An external MCP surface is a separate, authenticated read interface;
it does not give external agents ambient mutation privileges.

When execution is implemented, an administrator's UI action must authorize the
exact normalized plan: target, provider operation, object/scope, duration,
preconditions and plan digest. The executor independently verifies identity,
policy and drift. Changed plans require renewed approval. A successful provider
response and verified restoration of user access are separate outcomes.

Preauthorized temporary grants will require a deterministic administrator policy
with limits. AI cannot author or broaden that policy. Durable leases, ownership
tracking, overlapping requests, restart recovery and failed revocation are
required before automatic grants are enabled.

## Identity and member privacy

Local authentication and optional OIDC create server sessions. OIDC provider
subjects are authoritative; display names and email claims alone cannot grant
administrator rights. Explicit trusted group mapping determines roles.

A member sees only observations associated with an eligible personal/shared
device, attributed at event time and still authorized at read time. An upstream
DNS profile or gateway address often represents multiple people, so unidentified
events remain administrator-visible. Infrastructure devices are excluded from
the member workflow unless intentionally classified and assigned.

Inbox freshness and durable history are separate. Expired entries disappear
from the requestable inbox; existing requests retain their evidence snapshot and
audit trail. New requests and future execution revalidate the source evidence.

## Operational scope

This first version is one workspace and one application process. It is not a
multi-tenant SaaS. Start with one replica for migration/bootstrap and collection.
Future horizontal scaling needs migration coordination, distributed throttling,
job leases and stronger audit retention controls. See the roadmap for the gates
before production and write-capable operation.
