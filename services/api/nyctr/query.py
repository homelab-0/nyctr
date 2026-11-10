"""A read-only GraphQL view over stored evidence, for administrators.

There are no mutations. Each request loads inventory once, then resolves the
query in memory under three limits: query length, nesting depth, and the total
number of objects returned. The same schema is what the assistant's evidence is
described in, so a person can check anything it says.
"""

from __future__ import annotations

import json
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from graphql import GraphQLError, build_schema, graphql_sync, parse
from graphql.language import FieldNode, FragmentDefinitionNode, OperationDefinitionNode
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from . import risk
from .deps import admin, get_db
from .links import derived_links
from .models import Finding, Integration, Lease, Observation, Relationship, Resource, utc, utcnow
from .security import audit

router = APIRouter(prefix="/api")
MAX_QUERY = 6000
MAX_DEPTH = 10
MAX_OBJECTS = 20000

SDL = '''
"Which way to follow a link from a resource."
enum Direction { OUT IN BOTH }

"Match resources by one of their source attributes."
input AttrFilter {
  "Attribute name, for example vlanId, model or status."
  key: String!
  "Value must equal this text."
  eq: String
  "Value must contain this text."
  contains: String
  "Attribute must be present (true) or absent (false)."
  exists: Boolean
}

"One thing a source reported: a device, network, rule, workload, DNS profile and so on."
type Resource {
  id: ID!
  name: String!
  "site, gateway, switch, access_point, network, client, host, bridge, workload, dns_profile, domain or policy."
  kind: String!
  "unifi_network, nextdns, proxmox or demo."
  provider: String!
  "observed, configured or inferred."
  evidence: String!
  "personal, shared, infrastructure or unassigned."
  classification: String!
  "The person a personal device belongs to."
  owner: String
  observedAt: String!
  "True when the latest collection no longer listed it."
  missing: Boolean!
  "One source attribute as text."
  attr(key: String!): String
  "All source attributes as JSON text."
  attributes: String!
  "The network this resource is a member of, when a source or a match says so."
  network: Resource
  links(kind: String, direction: Direction = BOTH, first: Int = 50): [Link!]!
  "Resources one link away."
  neighbors(kind: String, linkKind: String, direction: Direction = BOTH, first: Int = 50): [Resource!]!
  "Recent blocked lookups tied to this device."
  blocks(first: Int = 20): [Block!]!
}

"A relationship between two resources. It never proves traffic can flow."
type Link {
  id: ID!
  kind: String!
  "observed, configured or inferred. Inferred links were worked out by Nyctr."
  evidence: String!
  provider: String!
  "Why Nyctr inferred this link, when it did."
  basis: String
  source: Resource
  target: Resource
}

"One blocked DNS lookup."
type Block {
  id: ID!
  domain: String!
  reason: String!
  observedAt: String!
  deviceName: String!
  "assigned, inferred, unverified or unattributed."
  attribution: String!
  "Rule-based score from 0 to 100. Null means unknown, not safe."
  riskScore: Int
  "low, medium, high or unknown."
  riskBand: String!
  device: Resource
}

type Finding {
  id: ID!
  title: String!
  severity: String!
  status: String!
  summary: String!
  evidence: [String!]!
  resources: [Resource!]!
}

"An exception Nyctr is responsible for."
type Lease {
  id: ID!
  domain: String!
  "temporary or permanent."
  kind: String!
  status: String!
  "simulated, applied, not_applied or failed: what happened at the provider."
  execution: String!
  scope: String!
  decidedBy: String!
  riskScore: Int
  createdAt: String!
  expiresAt: String
}

type Source {
  id: ID!
  name: String!
  provider: String!
  status: String!
  lastSync: String
  capabilities: [String!]!
  resources(kind: String, first: Int = 100): [Resource!]!
}

type Query {
  "Any resources, filtered."
  resources(kind: [String!], provider: String, classification: String, evidence: String, search: String,
            where: [AttrFilter!], first: Int = 100): [Resource!]!
  resource(id: ID!): Resource
  "Client devices."
  devices(search: String, classification: String, first: Int = 100): [Resource!]!
  networks(first: Int = 200): [Resource!]!
  "Virtual machines and containers. firewall: false finds guests with the firewall off."
  workloads(firewall: Boolean, first: Int = 200): [Resource!]!
  "Firewall and DNS rules."
  policies(provider: String, first: Int = 200): [Resource!]!
  links(kind: String, evidence: String, first: Int = 200): [Link!]!
  blocks(domain: String, hours: Int = 24, minScore: Int, attribution: String, first: Int = 100): [Block!]!
  findings(severity: String, status: String): [Finding!]!
  leases(status: String, first: Int = 100): [Lease!]!
  sources: [Source!]!
}
'''


class Context:
    """Evidence loaded once per query, with indexes and a shared object budget."""

    def __init__(self, db: Session):
        """Load inventory, links (including inferred ones) and fresh blocks."""
        rows = list(db.scalars(select(Resource).order_by(Resource.name)))
        self.db = db
        self.resources = {row.id: self._resource(row) for row in rows}
        self.links = [self._link(columns) for columns in (
            {"id": r.id, "source": r.source, "target": r.target, "kind": r.kind, "provider": r.provider,
             "evidence_kind": r.evidence_kind, "attributes": r.attributes}
            for r in db.scalars(select(Relationship)))]
        self.links += [self._link(edge) for edge in derived_links(rows)]
        self.outgoing: dict[str, list[dict]] = {}
        self.incoming: dict[str, list[dict]] = {}
        for link in self.links:
            self.outgoing.setdefault(link["_source"], []).append(link)
            self.incoming.setdefault(link["_target"], []).append(link)
        self.budget = MAX_OBJECTS

    def take(self, items: list, first: int | None = None) -> list:
        """Apply a list limit and charge the result against the per-query object budget."""
        limit = max(0, min(first if first is not None else 100, 500))
        items = items[:limit]
        self.budget -= len(items)
        if self.budget < 0:
            raise GraphQLError(f"This query returns more than {MAX_OBJECTS} objects. Narrow it or lower `first`.")
        return items

    @staticmethod
    def _resource(row: Resource) -> dict[str, Any]:
        """Shape one inventory row for the schema."""
        return {"id": row.id, "name": row.name, "kind": row.kind, "provider": row.provider,
                "evidence": row.evidence_kind, "classification": row.classification, "owner": row.owner_id,
                "observedAt": utc(row.observed_at).isoformat(), "_attrs": row.attributes or {},
                "missing": bool((row.attributes or {}).get("missing_from_latest_snapshot"))}

    @staticmethod
    def _link(data: dict[str, Any]) -> dict[str, Any]:
        """Shape one relationship for the schema."""
        return {"id": data["id"], "kind": data["kind"], "evidence": data["evidence_kind"],
                "provider": data["provider"], "basis": (data.get("attributes") or {}).get("basis"),
                "_source": data["source"], "_target": data["target"]}

    def around(self, resource_id: str, direction: str, kind: str | None) -> list[dict]:
        """Return links touching a resource in the requested direction."""
        found = []
        if direction in ("OUT", "BOTH"):
            found += self.outgoing.get(resource_id, [])
        if direction in ("IN", "BOTH"):
            found += self.incoming.get(resource_id, [])
        return [link for link in found if not kind or link["kind"] == kind]


def _text(value: Any) -> str | None:
    """Render an attribute value as text for the `attr` field."""
    if value is None:
        return None
    return value if isinstance(value, str) else json.dumps(value, sort_keys=True, default=str)


def _matches(resource: dict, filters: list[dict] | None) -> bool:
    """Apply attribute filters to one resource."""
    for item in filters or []:
        value = resource["_attrs"].get(item["key"])
        if item.get("exists") is not None and (value is not None) != item["exists"]:
            return False
        text = _text(value) or ""
        if item.get("eq") is not None and text != item["eq"]:
            return False
        if item.get("contains") is not None and item["contains"].lower() not in text.lower():
            return False
    return True


def _block(row: Observation) -> dict[str, Any]:
    """Shape one blocked lookup, scored by the same rules the rest of the product uses."""
    assessment = risk.assess(row.domain, row.reason, row.reason_codes)
    return {"id": row.id, "domain": row.domain, "reason": row.reason,
            "observedAt": utc(row.observed_at).isoformat(), "deviceName": row.device_name,
            "attribution": row.attribution, "riskScore": assessment.score, "riskBand": assessment.band,
            "_device": row.device_id}


def _fresh_blocks(ctx: Context, hours: int = 24) -> list[dict]:
    """Load unexpired blocks within the requested window, newest first."""
    hours = max(1, min(hours, 168))
    rows = ctx.db.scalars(select(Observation).where(
        Observation.expires_at > utcnow(), Observation.observed_at > utcnow() - timedelta(hours=hours))
        .order_by(Observation.observed_at.desc()).limit(2000))
    return [_block(row) for row in rows]


def _q_resources(_root, info, kind=None, provider=None, classification=None, evidence=None, search=None,
                 where=None, first=100):
    """Resolve the general resource filter."""
    ctx: Context = info.context
    needle = (search or "").lower()
    found = [r for r in ctx.resources.values()
             if (not kind or r["kind"] in kind) and (not provider or r["provider"] == provider)
             and (not classification or r["classification"] == classification)
             and (not evidence or r["evidence"] == evidence)
             and (not needle or needle in r["name"].lower() or needle in r["id"].lower())
             and _matches(r, where)]
    return ctx.take(found, first)


def _q_workloads(_root, info, firewall=None, first=200):
    """Resolve workloads, optionally by whether any firewall protection is switched on."""
    ctx: Context = info.context
    found = []
    for r in ctx.resources.values():
        if r["kind"] != "workload":
            continue
        nics = [n for n in r["_attrs"].get("nics") or [] if isinstance(n, dict)]
        protected = r["_attrs"].get("firewall_enabled") is not False and (
            not nics or any(n.get("firewall") for n in nics))
        if firewall is None or firewall == protected:
            found.append(r)
    return ctx.take(found, first)


def _r_network(resource, info):
    """Follow a member_of link from a resource to its network."""
    ctx: Context = info.context
    for link in ctx.outgoing.get(resource["id"], []):
        target = ctx.resources.get(link["_target"])
        if link["kind"] == "member_of" and target and target["kind"] == "network":
            return target
    return None


def _r_neighbors(resource, info, kind=None, linkKind=None, direction="BOTH", first=50):  # noqa: N803
    """Resolve the resources one link away."""
    ctx: Context = info.context
    seen, found = set(), []
    for link in ctx.around(resource["id"], direction, linkKind):
        other = link["_target"] if link["_source"] == resource["id"] else link["_source"]
        node = ctx.resources.get(other)
        if node and other not in seen and (not kind or node["kind"] == kind):
            seen.add(other)
            found.append(node)
    return ctx.take(found, first)


def _q_blocks(_root, info, domain=None, hours=24, minScore=None, attribution=None, first=100):  # noqa: N803
    """Resolve recent blocks with optional domain, score and attribution filters."""
    ctx: Context = info.context
    needle = (domain or "").lower()
    found = [b for b in _fresh_blocks(ctx, hours)
             if (not needle or needle in b["domain"]) and (not attribution or b["attribution"] == attribution)
             and (minScore is None or (b["riskScore"] is not None and b["riskScore"] >= minScore))]
    return ctx.take(found, first)


def _q_findings(_root, info, severity=None, status=None):
    """Resolve findings."""
    ctx: Context = info.context
    rows = ctx.db.scalars(select(Finding).order_by(Finding.title))
    return ctx.take([{"id": f.id, "title": f.title, "severity": f.severity, "status": f.status,
                      "summary": f.summary, "evidence": f.evidence, "_resources": f.resource_ids}
                     for f in rows if (not severity or f.severity == severity)
                     and (not status or f.status == status)], 500)


def _q_leases(_root, info, status=None, first=100):
    """Resolve leases."""
    ctx: Context = info.context
    rows = ctx.db.scalars(select(Lease).order_by(Lease.created_at.desc()).limit(500))
    return ctx.take([{"id": x.id, "domain": x.domain, "kind": x.kind, "status": x.status,
                      "execution": x.execution, "scope": x.scope, "decidedBy": x.decided_by,
                      "riskScore": x.risk_score, "createdAt": utc(x.created_at).isoformat(),
                      "expiresAt": utc(x.expires_at).isoformat() if x.expires_at else None}
                     for x in rows if not status or x.status == status], first)


def _q_sources(_root, info):
    """Resolve connected sources without configuration or secret references."""
    ctx: Context = info.context
    return ctx.take([{"id": i.id, "name": i.name, "provider": i.provider, "status": i.status,
                      "lastSync": utc(i.last_sync).isoformat() if i.last_sync else None,
                      "capabilities": i.capabilities}
                     for i in ctx.db.scalars(select(Integration).order_by(Integration.name))], 100)


def _source_resources(source, info, kind=None, first=100):
    """Resolve the resources one source reported."""
    ctx: Context = info.context
    prefix = source["id"]
    rows = ctx.db.scalars(select(Resource.id).where(Resource.integration_id == prefix))
    found = [ctx.resources[i] for i in rows if i in ctx.resources and (not kind or ctx.resources[i]["kind"] == kind)]
    return ctx.take(found, first)


def _kind(*kinds):
    """Build a resolver for a fixed set of resource kinds with optional search and classification."""
    def resolve(_root, info, search=None, classification=None, provider=None, first=100):
        return _q_resources(None, info, kind=list(kinds), search=search, classification=classification,
                            provider=provider, first=first)
    return resolve


def _make_schema():
    """Build the schema once and attach resolvers for computed fields."""
    schema = build_schema(SDL)
    fields = {
        "Query": {
            "resources": _q_resources, "resource": lambda _r, info, id: info.context.resources.get(id),
            "devices": _kind("client"), "networks": _kind("network"), "policies": _kind("policy"),
            "workloads": _q_workloads, "blocks": _q_blocks, "findings": _q_findings, "leases": _q_leases,
            "sources": _q_sources,
            "links": lambda _r, info, kind=None, evidence=None, first=200: info.context.take(
                [x for x in info.context.links if (not kind or x["kind"] == kind)
                 and (not evidence or x["evidence"] == evidence)], first),
        },
        "Resource": {
            "attr": lambda r, _info, key: _text(r["_attrs"].get(key)),
            "attributes": lambda r, _info: json.dumps(r["_attrs"], sort_keys=True, default=str),
            "network": _r_network, "neighbors": _r_neighbors,
            "links": lambda r, info, kind=None, direction="BOTH", first=50: info.context.take(
                info.context.around(r["id"], direction, kind), first),
            "blocks": lambda r, info, first=20: info.context.take(
                [b for b in _fresh_blocks(info.context, 168) if b["_device"] == r["id"]], first),
        },
        "Link": {"source": lambda x, info: info.context.resources.get(x["_source"]),
                 "target": lambda x, info: info.context.resources.get(x["_target"])},
        "Block": {"device": lambda b, info: info.context.resources.get(b["_device"]) if b["_device"] else None},
        "Finding": {"resources": lambda f, info: [info.context.resources[i] for i in f["_resources"]
                                                  if i in info.context.resources]},
        "Source": {"resources": _source_resources},
    }
    for type_name, resolvers in fields.items():
        for field_name, resolver in resolvers.items():
            schema.type_map[type_name].fields[field_name].resolve = resolver
    return schema


SCHEMA = _make_schema()


def _depth(node, fragments, seen=()) -> int:
    """Measure selection nesting, following fragments once each to stay bounded."""
    selections = getattr(getattr(node, "selection_set", None), "selections", None) or ()
    deepest = 0
    for child in selections:
        if isinstance(child, FieldNode):
            deepest = max(deepest, 1 + _depth(child, fragments, seen))
        elif hasattr(child, "name") and not isinstance(child, FieldNode):
            name = child.name.value
            if name in fragments and name not in seen:
                deepest = max(deepest, _depth(fragments[name], fragments, seen + (name,)))
        else:
            deepest = max(deepest, _depth(child, fragments, seen))
    return deepest


def run(db: Session, query: str, variables: dict | None = None) -> dict[str, Any]:
    """Validate limits, execute a read-only query and return GraphQL-shaped data and errors."""
    if len(query) > MAX_QUERY:
        return {"data": None, "errors": [{"message": f"Query is longer than {MAX_QUERY} characters."}]}
    try:
        document = parse(query)
    except GraphQLError as error:
        return {"data": None, "errors": [error.formatted]}
    fragments = {d.name.value: d for d in document.definitions if isinstance(d, FragmentDefinitionNode)}
    for definition in document.definitions:
        if isinstance(definition, OperationDefinitionNode):
            if definition.operation.value != "query":
                return {"data": None, "errors": [{"message": "Only queries are supported. Nothing can be changed here."}]}
            if _depth(definition, fragments) > MAX_DEPTH:
                return {"data": None, "errors": [{"message": f"Query is nested deeper than {MAX_DEPTH} levels."}]}
    result = graphql_sync(SCHEMA, query, context_value=Context(db), variable_values=variables or {})
    body: dict[str, Any] = {"data": result.data}
    if result.errors:
        body["errors"] = [{"message": e.message, "path": e.path} if e.original_error is None
                          or isinstance(e.original_error, GraphQLError)
                          else {"message": "This field could not be resolved.", "path": e.path}
                          for e in result.errors]
    return body


class QueryInput(BaseModel):
    """A GraphQL document and optional variables."""
    model_config = ConfigDict(extra="forbid")
    query: str = Field(min_length=1, max_length=MAX_QUERY)
    variables: dict | None = None


@router.post("/graph/query")
def graph_query(body: QueryInput, user=Depends(admin), db: Session = Depends(get_db)):
    """Run one read-only query for an administrator and record that it ran, not what it returned."""
    if body.variables and len(json.dumps(body.variables)) > 4000:
        raise HTTPException(422, "Variables are too large")
    result = run(db, body.query, body.variables)
    audit(db, user.id, "graph.queried", None, characters=len(body.query), errors=len(result.get("errors", [])))
    db.commit()
    return result
