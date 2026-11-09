"""Synthetic data exists only in explicit demo mode, isolated from live databases."""

from datetime import timedelta

from sqlalchemy import select, text

from .config import Settings
from .models import (
    DeviceGrant,
    Finding,
    Integration,
    Observation,
    Relationship,
    Resource,
    User,
    Workspace,
    utcnow,
)
from .security import hash_password


def bootstrap(db, settings: Settings):
    if db.bind.dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(73912802)"))
    workspace = db.get(Workspace, "default")
    if workspace and workspace.mode != settings.mode:
        raise RuntimeError("Database mode mismatch. Demo and live must use separate databases.")
    if not workspace:
        db.add(Workspace(id="default", mode=settings.mode))
        db.flush()
    if settings.mode == "demo":
        if not db.get(User, "user-admin"):
            seed_demo(db)
    elif settings.bootstrap_admin_email and settings.bootstrap_admin_password:
        if len(settings.bootstrap_admin_password) < 12:
            raise RuntimeError("Bootstrap administrator password must contain at least 12 characters")
        email = settings.bootstrap_admin_email.strip().casefold()
        existing = db.scalar(select(User).where(User.email == email, User.oidc_subject.is_(None)))
        if not existing:
            db.add(User(email=email, name="Administrator", role="admin",
                        password_hash=hash_password(settings.bootstrap_admin_password)))
    if settings.mode == "live" and not db.scalar(select(User.id).limit(1)) and not settings.oidc_enabled:
        raise RuntimeError("Configure NYCTR_BOOTSTRAP_ADMIN_EMAIL/PASSWORD or OIDC before first live startup")
    if settings.mode == "live" and not settings.local_login_enabled and not settings.oidc_enabled:
        raise RuntimeError("At least one sign-in method must be configured")
    db.commit()


def seed_demo(db):
    now = utcnow()
    password = hash_password("nyctr-demo")
    for id_, name, email, role in [
        ("user-admin", "Alex Morgan", "admin@nyctr.demo", "admin"),
        ("user-jamie", "Jamie Morgan", "jamie@nyctr.demo", "member"),
    ]:
        db.add(User(id=id_, name=name, email=email, role=role, password_hash=password))
    db.flush()
    for id_, name, provider, caps in [
        ("demo-unifi", "Milkyway · UniFi Network", "unifi_network", ["inventory", "networks", "policies"]),
        ("demo-nextdns", "Home DNS · NextDNS", "nextdns", ["dns_configuration", "dns_blocks"]),
        ("demo-compute", "Compute cluster · example", "demo", ["synthetic_workloads"]),
    ]:
        db.add(Integration(id=id_, name=name, provider=provider, status="demo", last_sync=now,
                           config={"demo": True}, capabilities=caps, secret_ref=""))
    db.flush()
    resources = [
        ("site-home", "Milkyway", "site", "demo-unifi", "infrastructure", None, {"location": "Home lab"}),
        ("gateway", "Milkyway gateway", "gateway", "demo-unifi", "infrastructure", None, {"model": "UDM SE", "ip": "10.20.65.1"}),
        ("switch-core", "Core aggregation", "switch", "demo-unifi", "infrastructure", None, {"model": "Aggregation switch", "ports": 8}),
        ("ap-basement", "Basement access point", "access_point", "demo-unifi", "infrastructure", None, {"model": "Wireless AP"}),
        ("network-lan", "Trusted LAN", "network", "demo-unifi", "infrastructure", None, {"vlan": 65, "subnet": "10.20.65.0/24"}),
        ("network-guest", "Guest network", "network", "demo-unifi", "infrastructure", None, {"vlan": 80, "subnet": "10.20.80.0/24"}),
        ("network-iot", "IoT network", "network", "demo-unifi", "infrastructure", None, {"vlan": 67, "subnet": "10.20.67.0/24"}),
        ("laptop-jamie", "Jamie's MacBook", "client", "demo-unifi", "personal", "user-jamie", {"ip": "10.20.65.42", "platform": "macOS"}),
        ("tablet-family", "Family tablet", "client", "demo-unifi", "shared", None, {"ip": "10.20.65.51", "platform": "iPadOS"}),
        ("workstation", "Alex's workstation", "client", "demo-unifi", "personal", "user-admin", {"ip": "10.20.65.28", "platform": "Linux"}),
        ("washer", "Laundry appliance", "client", "demo-unifi", "infrastructure", None, {"ip": "10.20.67.80", "category": "IoT"}),
        ("old-laptop", "Reassigned laptop", "client", "demo-unifi", "personal", "user-admin", {"ip": "10.20.65.62"}),
        ("host-compute", "Compute-01", "host", "demo-compute", "infrastructure", None, {"platform": "Proxmox", "ip": "10.20.66.3"}),
        ("workload-photos", "Photo service", "workload", "demo-compute", "infrastructure", None, {"port": 443, "protocol": "HTTPS"}),
        ("workload-management", "Management console", "workload", "demo-compute", "infrastructure", None, {"port": 8006, "protocol": "HTTPS"}),
        ("policy-guest", "Guest → services", "policy", "demo-unifi", "infrastructure", None, {"action": "allow", "port": 8006, "review": "source scope too broad"}),
        ("dns-home", "Home DNS profile", "dns_profile", "demo-nextdns", "infrastructure", None, {"scope": "All devices using this profile"}),
    ]
    for id_, name, kind, integration, classification, owner, attrs in resources:
        provider = "nextdns" if integration == "demo-nextdns" else "proxmox" if integration == "demo-compute" else "unifi_network"
        db.add(Resource(id=id_, integration_id=integration, name=name, kind=kind, provider=provider,
                        source_id="example-" + id_, site_id="site-home", observed_at=now,
                        evidence_kind="configured" if kind in {"network", "policy", "dns_profile"} else "observed",
                        classification=classification, owner_id=owner, attributes={**attrs, "demo": True}))
    db.flush()
    edges = [
        ("site-home", "gateway", "contains"), ("gateway", "switch-core", "connects_to"),
        ("switch-core", "ap-basement", "connects_to"), ("gateway", "network-lan", "contains"),
        ("gateway", "network-guest", "contains"), ("gateway", "network-iot", "contains"),
        ("ap-basement", "laptop-jamie", "connects_to"), ("ap-basement", "tablet-family", "connects_to"),
        ("laptop-jamie", "network-lan", "member_of"), ("tablet-family", "network-lan", "member_of"),
        ("switch-core", "workstation", "connects_to"), ("washer", "network-iot", "member_of"),
        ("switch-core", "host-compute", "connects_to"), ("workload-photos", "host-compute", "hosted_by"),
        ("workload-management", "host-compute", "hosted_by"),
        ("network-guest", "policy-guest", "governed_by"), ("policy-guest", "workload-management", "governed_by"),
        ("network-lan", "dns-home", "resolves_via"),
    ]
    for index, (source, target, kind) in enumerate(edges):
        db.add(Relationship(id=f"edge-{index}", integration_id="demo-unifi", source=source, target=target,
                            kind=kind, provider="demo", evidence_kind="configured", observed_at=now,
                            attributes={"demo": True}))
    for device, user in [("laptop-jamie", "user-jamie"), ("tablet-family", "user-jamie"),
                         ("tablet-family", "user-admin"), ("workstation", "user-admin")]:
        db.add(DeviceGrant(device_id=device, user_id=user, valid_from=now - timedelta(days=30)))
    db.add(DeviceGrant(device_id="old-laptop", user_id="user-jamie", valid_from=now - timedelta(days=30),
                       valid_until=now - timedelta(hours=1)))
    db.add(DeviceGrant(device_id="old-laptop", user_id="user-admin", valid_from=now - timedelta(hours=1)))
    events = [
        ("block-gallery", "laptop-jamie", "Jamie's MacBook", "click.shootproof.com", "nextdns", "Blocked by a configured privacy list", 8),
        ("block-tablet", "tablet-family", "Family tablet", "gallery.example.com", "nextdns", "Blocked by a custom denylist entry", 26),
        ("block-admin", "workstation", "Alex's workstation", "downloads.example.net", "nextdns", "Threat-intelligence category matched", 12),
        ("block-washer", "washer", "Laundry appliance", "telemetry.appliance.example", "nextdns", "IoT outbound policy", 3),
        ("block-unattributed", None, "Unknown source device", "metrics.example.org", "nextdns", "Upstream DNS query lacks device identity", 5),
        ("block-old-owner", "old-laptop", "Reassigned laptop", "work.example.net", "nextdns", "Historical event before device reassignment", 120),
        ("block-expired", "laptop-jamie", "Jamie's MacBook", "old.example.com", "nextdns", "Expired inbox fixture", 3000),
    ]
    for id_, device, name, domain, source, reason, age in events:
        when = now - timedelta(minutes=age)
        db.add(Observation(id=id_, integration_id="demo-nextdns", device_id=device, device_name=name,
                           domain=domain, source=source, reason=reason, observed_at=when,
                           expires_at=when + timedelta(hours=24), evidence_kind="observed",
                           attribution="assigned" if device else "unattributed", risk_score=None,
                           risk_explanation="Synthetic example. The block reason alone does not establish safety; an independent risk assessment has not run."))
    db.add(Finding(id="finding-guest-management", title="Review guest access to management services", severity="medium",
                   summary="A configured allow policy includes the management port. This is a policy finding, not evidence that an end-to-end connection succeeded.",
                   resource_ids=["network-guest", "gateway", "policy-guest", "workload-management"],
                   relationship_ids=["edge-15", "edge-16"],
                   evidence=["Synthetic policy Guest → services includes TCP 8006.", "Route, return path and host-firewall coverage remain unverified."], status="open"))
    db.add(Finding(id="finding-dns-attribution", title="Upstream DNS lacks per-device attribution", severity="informational",
                   summary="Some DNS observations identify only the upstream resolver. These remain administrator-only until device attribution is established.",
                   resource_ids=["gateway", "dns-home"], relationship_ids=[],
                   evidence=["Synthetic DNS event contains no reliable endpoint identity.", "A resolver profile is not a person."], status="open"))
