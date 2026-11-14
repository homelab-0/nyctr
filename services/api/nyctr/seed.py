"""Synthetic data exists only in explicit demo mode, isolated from live databases."""

from datetime import timedelta

from sqlalchemy import select, text

from .analysis import refresh_findings
from .config import Settings
from .models import (
    AccessRequest,
    DeviceGrant,
    Finding,
    GuestAction,
    GuestPass,
    Integration,
    Lease,
    Observation,
    Relationship,
    Resource,
    Sighting,
    User,
    Workspace,
    utcnow,
)
from .policy import AccessRule, GuestRule, put_rule
from .security import hash_password


def bootstrap(db, settings: Settings):
    """Enforce database mode and initialize demo data or a configured local administrator.

    PostgreSQL advisory locking serializes bootstrap. Existing credentials are
    preserved. Mode mismatch, weak bootstrap passwords, or an unusable live
    authentication configuration raise RuntimeError before serving requests.
    """
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
    """Stage synthetic identities, topology, findings, grants, and varied block observations.

    Call only from explicit demo bootstrap. Fresh and stale events plus personal,
    shared, infrastructure, and unattributed devices exercise privacy boundaries;
    unknown risk remains null. The caller owns the final transaction commit.
    """
    now = utcnow()
    password = hash_password("nyctr-demo")
    for id_, name, email, role in [
        ("user-admin", "Alex Morgan", "admin@nyctr.demo", "admin"),
        ("user-jamie", "Jamie Rivera", "jamie@nyctr.demo", "member"),
    ]:
        db.add(User(id=id_, name=name, email=email, role=role, password_hash=password))
    db.flush()
    for id_, name, provider, caps in [
        ("demo-unifi", "Northgate UniFi Network", "unifi_network",
         ["sites:read", "devices:read", "clients:read", "networks:read", "firewall_policies:read",
          "guest_access:read", "hotspot_vouchers:read", "wifi_broadcasts:read"]),
        ("demo-nextdns", "Office DNS on NextDNS", "nextdns", ["profile:read", "dns_policies:read", "blocked_dns_logs:read"]),
        ("demo-compute", "Compute cluster on Proxmox", "proxmox",
         ["nodes:read", "bridges:read", "guests:read", "guest_network:read", "firewall_options:read"]),
        # A second DNS source of a different kind. Its integration reports blocks but cannot open
        # them, so the same request flow behaves differently here by declaration alone.
        ("demo-pihole", "Annex Pi-hole", "pihole", ["session:read", "blocked_dns_logs:read"]),
    ]:
        db.add(Integration(id=id_, name=name, provider=provider, status="demo", last_sync=now,
                           config={"demo": True}, capabilities=caps, secret_ref=""))
    db.flush()
    resources = [
        ("site-home", "Northgate", "site", "demo-unifi", "infrastructure", None, {"location": "Head office", "wifi": [
            {"name": "Northgate", "enabled": True, "captive_portal": False, "network_id": "example-network-lan"},
            {"name": "Northgate IoT", "enabled": True, "captive_portal": False, "network_id": "example-network-iot"},
            {"name": "Northgate Guest", "enabled": True, "captive_portal": True, "network_id": "example-network-guest"}]}),
        ("gateway", "Northgate gateway", "gateway", "demo-unifi", "infrastructure", None, {"model": "Cloud gateway", "ip": "192.0.2.1"}),
        ("switch-core", "Core aggregation", "switch", "demo-unifi", "infrastructure", None, {"model": "Aggregation switch", "ports": 8}),
        ("ap-basement", "Ground floor access point", "access_point", "demo-unifi", "infrastructure", None, {"model": "Wireless AP"}),
        ("network-lan", "Trusted LAN", "network", "demo-unifi", "infrastructure", None, {"vlan": 10, "subnet": "192.0.2.0/25"}),
        ("network-guest", "Guest network", "network", "demo-unifi", "infrastructure", None, {"vlan": 40, "subnet": "203.0.113.0/24", "purpose": "guest"}),
        ("network-iot", "IoT network", "network", "demo-unifi", "infrastructure", None, {"vlan": 30, "subnet": "192.0.2.128/25"}),
        ("laptop-jamie", "Jamie's MacBook", "client", "demo-unifi", "personal", "user-jamie", {"ip": "192.0.2.42", "mac": "00:00:5e:00:53:42", "platform": "macOS", "type": "WIRELESS"}),
        ("tablet-family", "Front desk tablet", "client", "demo-unifi", "shared", None, {"ip": "192.0.2.51", "mac": "00:00:5e:00:53:51", "platform": "iPadOS", "type": "WIRELESS"}),
        ("workstation", "Alex's workstation", "client", "demo-unifi", "personal", "user-admin", {"ip": "192.0.2.28", "mac": "00:00:5e:00:53:28", "platform": "Linux", "type": "WIRED"}),
        ("washer", "Lobby display", "client", "demo-unifi", "infrastructure", None, {"ip": "192.0.2.180", "mac": "00:00:5e:00:53:80", "category": "IoT", "type": "WIRELESS"}),
        ("old-laptop", "Reassigned laptop", "client", "demo-unifi", "personal", "user-admin", {"ip": "192.0.2.62", "mac": "00:00:5e:00:53:62", "type": "WIRELESS"}),
        ("host-compute", "Compute-01", "host", "demo-compute", "infrastructure", None, {"status": "online", "addresses": ["198.51.100.3"], "cluster_firewall_enabled": True}),
        ("workload-photos", "Document service", "workload", "demo-compute", "infrastructure", None, {"vmid": "101", "type": "vm", "node": "compute-01", "status": "running", "firewall_enabled": True, "nics": [{"bridge": "vmbr0", "mac": "00:00:5e:00:53:11", "vlan": 20, "firewall": True}], "port": 443}),
        ("workload-management", "Management console", "workload", "demo-compute", "infrastructure", None, {"vmid": "102", "type": "vm", "node": "compute-01", "status": "running", "firewall_enabled": True, "nics": [{"bridge": "vmbr0", "mac": "00:00:5e:00:53:12", "vlan": 20, "firewall": True}], "port": 8006}),
        ("policy-guest", "Guest → services", "policy", "demo-unifi", "infrastructure", None, {"action": "allow", "port": 8006, "review": "source scope too broad"}),
        ("dns-home", "Office DNS profile", "dns_profile", "demo-nextdns", "infrastructure", None, {"scope": "All devices using this profile", "logs_enabled": True}),
        # Added with the console MVP: a servers VLAN, a second access point, guests and Proxmox networking.
        ("network-servers", "Servers", "network", "demo-unifi", "infrastructure", None, {"vlan": 20, "subnet": "198.51.100.0/24"}),
        ("ap-upstairs", "First floor access point", "access_point", "demo-unifi", "infrastructure", None, {"model": "Wireless AP"}),
        ("client-compute", "compute-01", "client", "demo-unifi", "infrastructure", None, {"ip": "198.51.100.3", "mac": "00:00:5e:00:53:03", "type": "WIRED"}),
        ("guest-priya", "Priya's iPhone", "client", "demo-unifi", "unassigned", None, {
            "ip": "203.0.113.21", "mac": "00:00:5e:00:53:21", "type": "WIRELESS", "uplink": "example-ap-upstairs", "connected_at": _iso(now, 95),
            "guest": {"authorized": True, "method": "pass", "authorized_at": _iso(now, 94),
                      "expires_at": _iso(now, -386), "bytes": 412_000_000, "seconds": 5640}}),
        ("guest-hvac", "HVAC-Laptop", "client", "demo-unifi", "unassigned", None, {
            "ip": "203.0.113.34", "mac": "00:00:5e:00:53:34", "type": "WIRELESS", "uplink": "example-ap-basement", "connected_at": _iso(now, 41),
            "guest": {"authorized": True, "method": "pass", "authorized_at": _iso(now, 40),
                      "expires_at": _iso(now, -200), "bytes": 38_000_000, "seconds": 2400}}),
        ("guest-pixel", "Pixel 8", "client", "demo-unifi", "unassigned", None, {
            "ip": "203.0.113.47", "mac": "00:00:5e:00:53:47", "type": "WIRELESS", "uplink": "example-ap-basement", "connected_at": _iso(now, 27),
            "guest": {"authorized": False, "method": "pass", "authorized_at": _iso(now, 26),
                      "expires_at": _iso(now, -94), "bytes": 9_400_000, "seconds": 1200}}),
        ("guest-galaxy", "Galaxy-S24", "client", "demo-unifi", "unassigned", None, {
            "ip": "203.0.113.52", "mac": "00:00:5e:00:53:52", "type": "WIRELESS", "uplink": "example-ap-upstairs", "connected_at": _iso(now, 3),
            "guest": {"authorized": False}}),
        ("bridge-vmbr0", "vmbr0 on compute-01", "bridge", "demo-compute", "infrastructure", None, {"iface": "vmbr0", "node": "compute-01", "active": True, "vlan_aware": True, "ports": "enp3s0", "cidr": "198.51.100.3/24"}),
        ("workload-indexer", "Search indexer", "workload", "demo-compute", "infrastructure", None, {"vmid": "204", "type": "container", "node": "compute-01", "status": "running", "firewall_enabled": False, "nics": [{"bridge": "vmbr0", "mac": "00:00:5e:00:53:44", "vlan": 20, "firewall": False}]}),
        ("dns-label-jamie", "Jamies-MacBook-Pro", "client", "demo-nextdns", "unassigned", None, {"model": "MacBook Pro", "identity_verified": False}),
        ("dns-workshop", "Annex resolver", "dns_profile", "demo-pihole", "infrastructure", None, {"scope": "entire_resolver"}),
        ("dns-label-bench", "bench-pc", "client", "demo-pihole", "unassigned", None, {"ip": "192.0.2.190", "identity_verified": False}),
    ]
    for id_, name, kind, integration, classification, owner, attrs in resources:
        provider = {"demo-nextdns": "nextdns", "demo-compute": "proxmox",
                    "demo-pihole": "pihole"}.get(integration, "unifi_network")
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
        ("gateway", "network-servers", "contains"), ("switch-core", "ap-upstairs", "connects_to"),
        ("switch-core", "client-compute", "connects_to"), ("client-compute", "network-servers", "member_of"),
        ("ap-upstairs", "guest-priya", "connects_to"), ("ap-basement", "guest-hvac", "connects_to"),
        ("ap-basement", "guest-pixel", "connects_to"), ("guest-priya", "network-guest", "member_of"),
        ("guest-hvac", "network-guest", "member_of"), ("guest-pixel", "network-guest", "member_of"),
        ("ap-upstairs", "guest-galaxy", "connects_to"), ("guest-galaxy", "network-guest", "member_of"),
        ("workstation", "network-lan", "member_of"), ("old-laptop", "network-lan", "member_of"),
        ("bridge-vmbr0", "host-compute", "hosted_by"), ("workload-photos", "bridge-vmbr0", "connects_to"),
        ("workload-management", "bridge-vmbr0", "connects_to"), ("workload-indexer", "bridge-vmbr0", "connects_to"),
        ("workload-indexer", "host-compute", "hosted_by"), ("network-guest", "dns-home", "resolves_via"),
        ("network-iot", "dns-home", "resolves_via"),
    ]
    for index, (source, target, kind) in enumerate(edges):
        observed = kind == "connects_to" and not source.startswith("workload")
        provider = "proxmox" if source.startswith(("workload", "bridge")) else "nextdns" if target == "dns-home" else "unifi_network"
        db.add(Relationship(id=f"edge-{index}", integration_id="demo-unifi", source=source, target=target,
                            kind=kind, provider=provider, evidence_kind="observed" if observed else "configured",
                            observed_at=now, attributes={"demo": True}))
    for device, user in [("laptop-jamie", "user-jamie"), ("tablet-family", "user-jamie"),
                         ("tablet-family", "user-admin"), ("workstation", "user-admin")]:
        db.add(DeviceGrant(device_id=device, user_id=user, valid_from=now - timedelta(days=30)))
    db.add(DeviceGrant(device_id="old-laptop", user_id="user-jamie", valid_from=now - timedelta(days=30),
                       valid_until=now - timedelta(hours=1)))
    db.add(DeviceGrant(device_id="old-laptop", user_id="user-admin", valid_from=now - timedelta(hours=1)))
    privacy, threat = ["blocklist:hagezi-multi-pro-plusplus"], ["threat-intelligence-feeds"]
    events = [
        ("block-gallery", "laptop-jamie", "Jamie's MacBook", "click.proofing-studio.example", "HaGeZi Multi PRO++", privacy, 8),
        ("block-tablet", "tablet-family", "Front desk tablet", "gallery.imagehost.example", "Denylist", ["denylist"], 26),
        ("block-admin", "workstation", "Alex's workstation", "downloads.filemirror.example", "Threat Intelligence Feeds", threat, 12),
        ("block-washer", "washer", "Lobby display", "telemetry.display-vendor.example", "IoT outbound policy", [], 3),
        ("block-unattributed", None, "Unknown source device", "metrics.analytics-hub.example", "Upstream DNS query lacks device identity", [], 5),
        ("block-old-owner", "old-laptop", "Reassigned laptop", "work.intranet-tools.example", "Historical event before device reassignment", [], 120),
        ("block-expired", "laptop-jamie", "Jamie's MacBook", "old.archive-site.example", "Expired inbox fixture", [], 3000),
        ("block-fonts", "laptop-jamie", "Jamie's MacBook", "fonts.partner-metrics.example", "HaGeZi Multi PRO++", privacy, 19),
        ("block-verify", "laptop-jamie", "Jamie's MacBook", "account-verify.secure-login.example", "Newly Registered Domains", ["nrd"], 34),
        ("block-stream", "tablet-family", "Front desk tablet", "watch.streamhub.example", "Parental Control: streaming", ["parental-control:category"], 52),
        ("block-pixel-1", "guest-pixel", "Pixel 8", "c2.update-check.example", "Threat Intelligence Feeds", threat, 8),
        ("block-pixel-2", "guest-pixel", "Pixel 8", "cdn.update-check.example", "Threat Intelligence Feeds", threat, 9),
        ("block-pixel-3", "guest-pixel", "Pixel 8", "beacon.update-check.example", "Threat Intelligence Feeds", threat, 10),
        ("block-pixel-4", "guest-pixel", "Pixel 8", "ads.mobile-sdk.example", "HaGeZi Multi PRO++", privacy, 21),
        ("block-priya-1", "guest-priya", "Priya's iPhone", "metrics.social-app.example", "HaGeZi Multi PRO++", privacy, 44),
        ("block-print", "laptop-jamie", "Jamie's MacBook", "cdn.printshop.example", "On a subscribed blocklist", ["gravity"], 15),
    ]
    # Which source reported each block. Everything not listed came from the first DNS source.
    reported_by = {"block-print": ("demo-pihole", "pihole")}
    for id_, device, name, domain, reason, codes, age in events:
        when = now - timedelta(minutes=age)
        guest = bool(device and device.startswith("guest-"))
        integration, source = reported_by.get(id_, ("demo-nextdns", "nextdns"))
        db.add(Observation(id=id_, integration_id=integration, device_id=device, device_name=name,
                           domain=domain, source=source, reason=reason, reason_codes=codes, observed_at=when,
                           expires_at=when + timedelta(hours=24), evidence_kind="observed",
                           attribution="inferred" if guest else "assigned" if device else "unattributed",
                           risk_score=None,
                           risk_explanation="Synthetic example. A block reason alone does not establish safety."))
    _seed_access_and_guests(db, now)
    db.add(Finding(id="finding-guest-management", title="Review guest access to management services", severity="medium",
                   summary="A configured allow policy includes the management port. This is a policy finding, not evidence that an end-to-end connection succeeded.",
                   resource_ids=["network-guest", "gateway", "policy-guest", "workload-management"],
                   relationship_ids=["edge-15", "edge-16"],
                   evidence=["Synthetic policy Guest → services includes TCP 8006.", "Route, return path and host-firewall coverage remain unverified."], status="open"))
    db.add(Finding(id="finding-dns-attribution", title="Upstream DNS lacks per-device attribution", severity="informational",
                   summary="Some DNS observations identify only the upstream resolver. These remain administrator-only until device attribution is established.",
                   resource_ids=["gateway", "dns-home"], relationship_ids=[],
                   evidence=["Synthetic DNS event contains no reliable endpoint identity.", "A resolver profile is not a person."], status="open"))
    db.flush()
    refresh_findings(db)


def _iso(now, minutes_ago: int) -> str:
    """Format a demo timestamp relative to seeding time; negative values are in the future."""
    return (now - timedelta(minutes=minutes_ago)).isoformat()


def _seed_access_and_guests(db, now):
    """Stage written rules, a waiting request, past and current access, guest passes and one cut-off.

    Everything here is marked simulated: demo mode never contacts a provider.
    """
    put_rule(db, "access_rule", AccessRule(enabled=True, max_score=25, max_minutes=60, per_day=4), "user-admin")
    put_rule(db, "guest_rule", GuestRule(enabled=True, hits=3, minutes=5), "user-admin")
    db.add(AccessRequest(
        id="request-stream", block_id="block-stream", domain="watch.streamhub.example", device_name="Front desk tablet",
        requester_id="user-jamie", reason="The safety training video for new starters is hosted here.",
        duration_minutes=120, status="pending", created_at=now - timedelta(minutes=47), risk_score=60,
        risk_category="policy", integration_id="demo-nextdns",
        risk_factors=[{"label": "A content rule set by an administrator blocks this kind of site", "points": 60}],
        decision_note="This was blocked for safety or by an administrator's rule, so a person decides."))
    scope = "Everyone using Office DNS on NextDNS"
    for id_, domain, started, minutes, ended in [
        ("lease-news-1", "img.newsletter-cdn.example", 3 * 24 * 60, 60, True),
        ("lease-news-2", "img.newsletter-cdn.example", 26 * 60, 60, True),
        ("lease-recipes", "assets.supplier-catalogue.example", 22, 60, False),
    ]:
        created = now - timedelta(minutes=started)
        db.add(Lease(id=id_, integration_id="demo-nextdns", domain=domain, device_name="Jamie's MacBook",
                     requester_id="user-jamie", kind="temporary", execution="simulated", owned=True, scope=scope,
                     decided_by="rule", risk_score=16, created_at=created,
                     expires_at=created + timedelta(minutes=minutes),
                     status="ended" if ended else "active", ended_reason="expired" if ended else None,
                     ended_at=created + timedelta(minutes=minutes) if ended else None))
    for id_, name, code, minutes, activated, limit in [
        ("pass-priya", "Priya (visiting auditor)", "40218-77531", 480, 94, 2),
        ("pass-hvac", "HVAC contractor", "91034-22876", 240, 40, 1),
        ("pass-pixel", "Workshop attendees", "55620-18493", 120, 26, 4),
        ("pass-spare", "Spare for the front desk", "77102-33864", 240, None, 1),
    ]:
        start = now - timedelta(minutes=activated) if activated is not None else None
        db.add(GuestPass(id=id_, integration_id="demo-unifi", code=code, name=name, minutes=minutes,
                         guest_limit=limit, guest_count=1 if start else 0, issued_by="user-admin",
                         execution="simulated", created_at=now - timedelta(minutes=(activated or 0) + 30),
                         activated_at=start, expires_at=start + timedelta(minutes=minutes) if start else None))
    for device, uplink, first, last in [
        ("guest-priya", "example-ap-basement", 94, 61), ("guest-priya", "example-ap-upstairs", 60, 0),
        ("guest-hvac", "example-ap-basement", 40, 0), ("guest-pixel", "example-ap-basement", 26, 7),
        ("guest-galaxy", "example-ap-upstairs", 3, 0),
    ]:
        db.add(Sighting(device_id=device, uplink_id=uplink, first_seen=now - timedelta(minutes=first),
                        last_seen=now - timedelta(minutes=last)))
    db.add(GuestAction(device_id="guest-pixel", action="cut", actor="rule", execution="simulated",
                       created_at=now - timedelta(minutes=7),
                       reason="3 lookups of threat-listed addresses in 5 minutes"))
