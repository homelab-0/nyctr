"""The integration contract: the core asks for capabilities and never names a vendor."""

import re
from pathlib import Path

import pytest
from conftest import LIVE_MEMBER, live_app, live_signin, seed_live_member
from fastapi.testclient import TestClient

from nyctr import access, risk
from nyctr.config import Settings
from nyctr.integrations import IntegrationError, Snapshot, capabilities_for, registry, validate_config
from nyctr.integrations.registry import ConfigField, Provider

ROOT = Path(__file__).resolve().parents[1] / "nyctr"
WEB = Path(__file__).resolve().parents[3] / "apps" / "web" / "src"
VENDOR = re.compile(r"unifi|ubiquiti|nextdns|proxmox|pi-?hole", re.I)


def test_every_integration_declares_a_coherent_contract():
    """Each shipped integration names its reads, its capabilities and exactly the actions those need."""
    found = registry.providers()
    assert {"unifi_network", "nextdns", "proxmox", "pihole"} <= set(found)
    for provider in found.values():
        assert provider.reads and provider.name and provider.summary and provider.fields
        assert provider.provides <= set(registry.CAPABILITIES)
        assert ("dns.exceptions" in provider.provides) == bool(provider.allow_domain and provider.disallow_domain)
        assert ("guest.passes" in provider.provides) == bool(provider.issue_pass and provider.end_pass)
        assert ("guest.control" in provider.provides) == bool(provider.guest_access)
        described = provider.describe("disabled")
        assert "secret" not in {field["key"] for field in described["fields"]}
        assert described["write_mode"] == ("disabled" if provider.changes else "none")
    assert registry.writable() == {"unifi_network", "nextdns"}
    assert capabilities_for("nextdns") == ["profile:read", "dns_policies:read", "blocked_dns_logs:read"]
    assert capabilities_for("never_heard_of_it") == []


def test_core_modules_never_name_a_vendor():
    """Vendor names live in `integrations/` and the demo seed only.

    A core module that names a vendor has grown a special case the next
    integration would not get. Fail here so it is fixed on purpose.
    """
    offenders = []
    for path in sorted(ROOT.glob("*.py")):
        if path.name == "seed.py":
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if VENDOR.search(line):
                offenders.append(f"{path.name}:{number}: {line.strip()[:80]}")
    assert offenders == []


def test_the_console_never_names_a_vendor():
    """The web app renders sources from the catalog, so its code holds no vendor name either."""
    offenders = []
    for path in sorted(WEB.rglob("*.ts*")):
        if ".test." in path.name or "/test/" in path.as_posix():
            continue
        for number, line in enumerate(path.read_text().splitlines(), 1):
            if VENDOR.search(line):
                offenders.append(f"{path.relative_to(WEB)}:{number}: {line.strip()[:80]}")
    assert offenders == []


def test_catalog_lists_what_each_integration_adds(client, admin_headers, member_headers):
    """Administrators get the catalog the console is built from; members do not."""
    assert client.get("/api/integrations/catalog").status_code == 403  # member session is the latest sign-in
    client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"})
    body = client.get("/api/integrations/catalog").json()
    by_id = {row["id"]: row for row in body["providers"]}
    assert [c["id"] for c in body["capabilities"]] == list(registry.CAPABILITIES)
    assert {c["id"] for c in by_id["nextdns"]["provides"]} == {"dns.blocks", "dns.exceptions"}
    assert {c["id"] for c in by_id["pihole"]["provides"]} == {"dns.blocks"}
    assert by_id["pihole"]["write_mode"] == "none" and by_id["pihole"]["status"] == "experimental"
    assert by_id["unifi_network"]["write_mode"] == "simulated"  # demo
    assert [f["key"] for f in by_id["unifi_network"]["fields"]] == ["base_url", "site_id"]
    sources = client.get("/api/integrations").json()
    assert {row["provider_name"] for row in sources} == {"UniFi Network", "NextDNS", "Proxmox VE", "Pi-hole"}


def test_unknown_integrations_are_refused_everywhere(tmp_path):
    """An unregistered name cannot be validated, connected, or granted write permission."""
    with pytest.raises(IntegrationError):
        validate_config("unifi_fabric", {})
    with pytest.raises(ValueError, match="NYCTR_PROVIDER_WRITES"):
        Settings(mode="demo", provider_writes="unifi_fabric")
    with pytest.raises(ValueError, match="NYCTR_PROVIDER_WRITES"):
        Settings(mode="demo", provider_writes="pihole")  # registered, but it has nothing Nyctr can change
    app = live_app(tmp_path)
    with TestClient(app) as client:
        headers = live_signin(client)
        response = client.post("/api/integrations", headers=headers, json={
            "provider": "unifi_fabric", "name": "X", "config": {}, "secret_ref": "NYCTR_CONNECTOR_SECRET_X"})
        assert response.status_code == 422


def _fake_resolver() -> Provider:
    """A made-up DNS source that reports blocks and can change nothing."""
    async def collect(_id, _config, _key):
        """Return an empty snapshot; the test inserts evidence directly."""
        return Snapshot()

    return Provider(id="acme_dns", name="Acme Resolver", summary="Test only.", letter="A", tone="grey",
                    fields=(ConfigField("base_url", "Address"),), reads=(("blocked_dns_logs:read", "Blocks"),),
                    provides=frozenset({"dns.blocks"}), validate=lambda config: config, collect=collect)


def test_a_new_integration_changes_behaviour_by_declaration_alone(tmp_path, monkeypatch):
    """Registering one declaration is enough for the core to treat a new source correctly.

    The made-up source reports blocks but declares no way to open them. With
    the access rule on and a low score, the request still waits for a person
    and the reason names the source; an approval is recorded as not applied.
    """
    monkeypatch.setattr(registry, "_cache", {**registry.providers(), "acme_dns": _fake_resolver()})
    app = live_app(tmp_path)
    with TestClient(app) as client:
        seed_live_member(app, reason="Advert tracker list", codes=())
        with app.state.session_factory() as db:
            from nyctr.models import Integration, Observation

            db.add(Integration(id="acme", provider="acme_dns", name="Office resolver", config={},
                               secret_ref="NYCTR_CONNECTOR_SECRET_ACME", status="connected"))
            block = db.get(Observation, "dns:block:one")
            block.integration_id, block.source = "acme", "acme_dns"
            db.commit()
        admin_headers = live_signin(client)
        client.put("/api/rules/access", headers=admin_headers,
                   json={"enabled": True, "max_score": 30, "max_minutes": 60, "per_day": 3})
        rules = client.get("/api/rules").json()
        assert {s["provider_name"]: s["write_mode"] for s in rules["sources"]}["Acme Resolver"] == "none"
        member = live_signin(client, LIVE_MEMBER)
        row = client.post("/api/requests", headers=member, json={
            "block_id": "dns:block:one", "reason": "Need the gallery", "duration_minutes": 60}).json()
        assert row["status"] == "pending" and row["risk_score"] == 16
        assert row["decision_note"] == "Nyctr cannot open addresses at Office resolver, so a person decides."
        admin_headers = live_signin(client)
        client.post(f"/api/requests/{row['id']}/review", headers=admin_headers,
                    json={"decision": "approved", "note": "Fine by me"})
        lease = client.get("/api/leases").json()[0]
        assert lease["execution"] == "not_applied" and lease["owned"] is False


def test_feature_mode_distinguishes_missing_from_read_only(tmp_path):
    """`none` means no connected source offers the feature; `disabled` means one does but may not be changed."""
    app = live_app(tmp_path)
    with TestClient(app):
        with app.state.session_factory() as db:
            assert access.feature_mode(db, app.state.settings, "dns.exceptions") == "none"
        seed_live_member(app)
        with app.state.session_factory() as db:
            assert access.feature_mode(db, app.state.settings, "dns.exceptions") == "disabled"
            assert access.feature_mode(db, app.state.settings, "compute") == "none"
    assert risk.assess("x.example", "", [], "acme_dns").score is None


def test_the_demo_shows_two_dns_sources_behaving_differently(client):
    """In the seeded demo the same request flow gives a different outcome per source, by declaration.

    The first DNS source can open addresses, so the access rule opens a
    low-risk block from it. The second only reports blocks and does not say
    what kind of list matched: its block is unscored, waits for a person, and
    an approval is recorded as not applied even in demo mode.
    """
    member = client.post("/api/auth/login", json={"email": "jamie@nyctr.demo", "password": "nyctr-demo"}).json()
    headers = {"X-CSRF-Token": member["csrf_token"]}
    blocks = {b["id"]: b for b in client.get("/api/blocks").json()}
    assert blocks["block-print"]["risk_score"] is None and blocks["block-fonts"]["risk_score"] == 16
    assert "does not say" in blocks["block-print"]["risk_factors"][0]["label"]
    opened = client.post("/api/requests", headers=headers, json={
        "block_id": "block-fonts", "reason": "Fonts for a client deck", "duration_minutes": 60}).json()
    waiting = client.post("/api/requests", headers=headers, json={
        "block_id": "block-print", "reason": "Ordering prints", "duration_minutes": 60}).json()
    assert opened["status"] == "auto_approved" and waiting["status"] == "pending"
    assert waiting["integration_id"] == "demo-pihole"
    admin = client.post("/api/auth/login", json={"email": "admin@nyctr.demo", "password": "nyctr-demo"}).json()
    headers = {"X-CSRF-Token": admin["csrf_token"]}
    rules = client.get("/api/rules").json()
    modes = {source["id"]: source["write_mode"] for source in rules["sources"]}
    assert modes["demo-nextdns"] == "simulated" and modes["demo-pihole"] == "none"
    assert rules["writes"] == {"access": "simulated", "guests": "simulated"}
    review = client.post(f"/api/requests/{waiting['id']}/review", headers=headers,
                         json={"decision": "approved", "note": "Fine"})
    assert review.status_code == 200
    leases = {lease["domain"]: lease for lease in client.get("/api/leases").json()}
    assert leases["cdn.printshop.example"]["execution"] == "not_applied"
    assert leases["fonts.partner-metrics.example"]["execution"] == "simulated"
