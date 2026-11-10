"""The read-only graph query endpoint and its limits."""

from nyctr import query


def run(client, headers, text, **variables):
    """Post one query as an administrator."""
    response = client.post("/api/graph/query", headers=headers, json={"query": text, "variables": variables or None})
    assert response.status_code == 200, response.text
    return response.json()


def test_members_and_anonymous_callers_cannot_query(client, member_headers):
    """The graph is administrator-only and a mutation still needs CSRF."""
    assert client.post("/api/graph/query", headers=member_headers, json={"query": "{ sources { id } }"}).status_code == 403
    assert client.post("/api/graph/query", json={"query": "{ sources { id } }"}).status_code == 403


def test_inventory_filters_and_nested_links(client, admin_headers):
    """Typed filters, attribute filters and one-hop traversal return stored evidence."""
    data = run(client, admin_headers, """{
      workloads(firewall: false) { name attr(key: "vmid") network { name } }
      networks { name attr(key: "vlanId") }
      guests: devices(search: "pixel") { name evidence blocks(first: 10) { domain riskBand } }
      tagged: resources(kind: ["network"], where: [{key: "vlanId", eq: "80"}]) { name neighbors(kind: "client") { name } }
    }""")["data"]
    assert data["workloads"] == [{"name": "Media indexer", "attr": "204", "network": {"name": "Servers"}}]
    assert {"name": "Guest network", "attr": "80"} in data["networks"]
    assert {b["riskBand"] for b in data["guests"][0]["blocks"]} == {"high", "low"}
    assert {n["name"] for n in data["tagged"][0]["neighbors"]} == {"Priya's iPhone", "HVAC-Laptop", "Pixel 8",
                                                                "Galaxy-S24"}


def test_inferred_links_are_labelled_and_secrets_are_not_in_the_schema(client, admin_headers):
    """Cross-source matches are marked inferred with their basis; secret references cannot be queried."""
    links = run(client, admin_headers, '{ links(evidence: "inferred") { kind provider basis source { name } target { name } } }')
    pairs = {(x["source"]["name"], x["target"]["name"], x["kind"]) for x in links["data"]["links"]}
    assert ("Compute-01", "compute-01", "same_device") in pairs
    assert ("Photo service", "Servers", "member_of") in pairs
    assert all(x["provider"] == "nyctr" and x["basis"] for x in links["data"]["links"])
    bad = run(client, admin_headers, "{ sources { id secretRef config } }")
    assert bad["data"] is None and "secretRef" in bad["errors"][0]["message"]


def test_only_bounded_read_queries_run(client, admin_headers):
    """Mutations, deep nesting, oversized queries and oversized results are all refused."""
    assert "Only queries" in run(client, admin_headers, "mutation { x }")["errors"][0]["message"]
    deep = "{ devices { " + "neighbors { " * 10 + "id" + " }" * 10 + " } }"
    assert "nested deeper" in run(client, admin_headers, deep)["errors"][0]["message"]
    assert client.post("/api/graph/query", headers=admin_headers,
                       json={"query": "{ sources { id } } " + "#" * 7000}).status_code == 422
    assert "Syntax Error" in run(client, admin_headers, "{ devices { ")["errors"][0]["message"]
    wide = "{ resources(first: 500) { neighbors(first: 500) { neighbors(first: 500) { neighbors(first: 500) { id } } } } }"
    original = query.MAX_OBJECTS
    query.MAX_OBJECTS = 200
    try:
        result = run(client, admin_headers, wide)
    finally:
        query.MAX_OBJECTS = original
    assert any("more than" in e["message"] for e in result["errors"])


def test_schema_can_be_explored_and_running_a_query_is_audited_without_its_text(client, admin_headers):
    """Introspection drives the explorer; the audit records that a query ran, not what it asked."""
    types = run(client, admin_headers, "{ __schema { types { name fields { name description } } } }")
    names = {t["name"] for t in types["data"]["__schema"]["types"]}
    assert {"Resource", "Link", "Block", "Finding", "Lease", "Source"} <= names
    event = next(x for x in client.get("/api/audit").json() if x["action"] == "graph.queried")
    assert set(event["details"]) == {"characters", "errors"}


def test_blocks_are_read_once_per_query_not_once_per_resource(client, app, admin_headers, monkeypatch):
    """Asking every resource for its blocks reads and scores the window a single time."""
    scored = []
    real = query._block
    monkeypatch.setattr(query, "_block", lambda row: (scored.append(row.id), real(row))[1])
    result = run(client, admin_headers, "{ resources(first: 60) { name blocks { domain } } }")
    assert "errors" not in result and len(result["data"]["resources"]) > 10
    assert len(scored) == len(set(scored)) > 0
    assert any(row["blocks"] for row in result["data"]["resources"])
