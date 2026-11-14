"""The integration contract: what a provider declares and what the core may ask of it.

Nyctr's core never names a vendor. A feature asks the registry for an
integration that provides a capability ("dns.exceptions", "guest.passes") and
calls it through the functions declared here. Adding a provider means adding one
module that builds a `Provider` and listing it in `_MODULES`; nothing in the
core or the web app changes.

Adapters translate vendor fields into the neutral attributes the core reads:

- client: `ip`, `mac`, `uplink` (source id of the device it is attached to),
  `connected_at`, and for clients on guest access
  `guest: {authorized, method: "pass"|"console"|"other"|None, authorized_at, expires_at, bytes, seconds}`
- gateway, switch, access_point: `ip`, `mac`
- network: `vlan`
- workload: `nics: [{bridge, mac, vlan, firewall}]`, `firewall_enabled`
- host: `addresses`
- site: `wifi: [{name, enabled, captive_portal, network_id}]`
- dns_profile: `logs_enabled`

Anything else an adapter keeps is source detail for people to read and query.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import lru_cache
from importlib import import_module
from pathlib import Path
from typing import Any

from .core import IntegrationError, Snapshot

# Feature capabilities in the core's own vocabulary, with the words shown to people.
CAPABILITIES: dict[str, str] = {
    "inventory": "Devices, networks and rules",
    "dns.blocks": "Blocked lookups",
    "dns.exceptions": "Open a blocked address for a while",
    "guest.devices": "Who is on the guest Wi-Fi",
    "guest.passes": "Guest passes",
    "guest.control": "Let a guest on or cut one off",
    "compute": "Hosts, workloads and their network cards",
}
# Capabilities that change the provider. They work only when an operator allows the provider.
WRITES = frozenset({"dns.exceptions", "guest.passes", "guest.control"})

# Logo files ship beside the integrations; an integration names one of them and nothing else.
LOGOS = Path(__file__).parent / "logos"
_LOGO_TYPES = {"svg": "image/svg+xml", "png": "image/png"}
_LOGO_LIMIT = 96 * 1024
# The console shows a logo only as an image, where a browser runs nothing an SVG contains.
# Refusing active content here as well keeps such a file out of the repository altogether.
_ACTIVE_SVG = re.compile(rb"<\s*(script|foreignObject|iframe|object|embed)\b|\son[a-z]+\s*=|javascript:", re.I)


@lru_cache(maxsize=32)
def logo_uri(name: str) -> str:
    """Return a shipped logo file as an image `data:` URI, or raise if it is not a plain image.

    The catalogue carries the picture itself, so no route serves these files
    and a logo can never be opened as a page of its own.
    """
    match = re.fullmatch(r"[a-z0-9_]{1,32}\.(svg|png)", name)
    if not match:
        raise ValueError("A logo is a lower-case .svg or .png file name in the logos folder")
    data = (LOGOS / name).read_bytes()
    if not data or len(data) > _LOGO_LIMIT:
        raise ValueError(f"Logo {name} is empty or larger than {_LOGO_LIMIT} bytes")
    kind = match.group(1)
    if kind == "png" and not data.startswith(b"\x89PNG\r\n\x1a\n"):
        raise ValueError(f"Logo {name} is not a PNG image")
    if kind == "svg" and (b"<svg" not in data or _ACTIVE_SVG.search(data)):
        raise ValueError(f"Logo {name} is not a plain SVG image")
    return f"data:{_LOGO_TYPES[kind]};base64,{base64.b64encode(data).decode('ascii')}"


@dataclass(frozen=True)
class ConfigField:
    """One connection setting the console asks for. Secrets are never fields."""
    key: str
    label: str
    hint: str = ""
    placeholder: str = ""
    kind: str = "text"
    required: bool = True


@dataclass(frozen=True)
class Provider:
    """Everything the core and the console know about one kind of source."""
    id: str
    name: str
    summary: str
    letter: str
    tone: str
    validate: Callable[[dict[str, Any]], dict[str, Any]]
    collect: Callable[[str, dict[str, Any], str], Awaitable[Snapshot]]
    status: str = "stable"
    # Optional: the file name of this source's own logo in `logos/`. Without one the console shows `letter`.
    logo: str = ""
    secret_hint: str = ""
    fields: tuple[ConfigField, ...] = ()
    # What collection reads, as (id, label). Diagnostics report each one separately.
    reads: tuple[tuple[str, str], ...] = ()
    provides: frozenset[str] = field(default_factory=frozenset)
    # Product features this source cannot support, as (id, label, text). Shown with every test.
    limitations: tuple[tuple[str, str, str], ...] = ()
    # Evidence gaps that always apply to this source, as (id, title, text).
    gaps: tuple[tuple[str, str, str], ...] = ()
    # What a source of this kind never collects, each a few plain words. The Briefing lists these
    # under "Not collected" for every connected source, so say only what is true of every setup.
    not_collected: tuple[str, ...] = ()
    # Text for gap codes the adapter records during a collection: code -> (title, text).
    gap_notes: dict[str, tuple[str, str]] = field(default_factory=dict)
    # Optional: map one block reason (an identifier or a name) to (category, base score, explanation).
    # A score of None says "this source cannot tell", which the core keeps as unknown. A provider
    # that classifies is the only authority on its own reasons; the core's generic table is not used.
    classify: Callable[[str], tuple[str, int | None, str] | None] | None = None
    # Optional: the configured scope (for example a site) that actions apply to.
    scope: Callable[[dict[str, Any]], str | None] | None = None
    # Optional actions, present exactly for the write capabilities this provider declares.
    # allow_domain(config, key, domain, *, allowed) -> {"owned": bool, "verified": bool}
    allow_domain: Callable[..., Awaitable[dict[str, Any]]] | None = None
    # disallow_domain(config, key, domain, *, allowed) -> {"removed": bool, "verified": bool}
    disallow_domain: Callable[..., Awaitable[dict[str, Any]]] | None = None
    # issue_pass(config, key, scope, *, name, minutes, guest_limit, data_limit_mb, allowed) -> {"id", "code"}
    issue_pass: Callable[..., Awaitable[dict[str, Any]]] | None = None
    # end_pass(config, key, scope, pass_id, *, allowed) -> None
    end_pass: Callable[..., Awaitable[None]] | None = None
    # guest_access(config, key, scope, client_id, allow, *, minutes, allowed) -> {"authorized", "verified"}
    guest_access: Callable[..., Awaitable[dict[str, Any]]] | None = None

    @property
    def changes(self) -> list[str]:
        """Name, in the core's words, what Nyctr could change at this provider."""
        return [CAPABILITIES[c] for c in CAPABILITIES if c in self.provides and c in WRITES]

    def describe(self, write_mode: str) -> dict[str, Any]:
        """Serialize for the console. Contains no credential and no destination."""
        return {
            "id": self.id, "name": self.name, "summary": self.summary, "letter": self.letter,
            "tone": self.tone, "logo": logo_uri(self.logo) if self.logo else "",
            "status": self.status, "secret_hint": self.secret_hint,
            "fields": [{"key": f.key, "label": f.label, "hint": f.hint, "placeholder": f.placeholder,
                        "kind": f.kind, "required": f.required} for f in self.fields],
            "provides": [{"id": c, "name": CAPABILITIES[c], "changes_provider": c in WRITES}
                         for c in CAPABILITIES if c in self.provides],
            "reads": [{"id": read, "label": label} for read, label in self.reads],
            "changes": self.changes, "write_mode": write_mode if self.changes else "none",
            # What a source of this kind never gives Nyctr, however well a collection goes: the
            # cautions about its evidence, then the things it does not collect at all.
            "limits": [{"id": id_, "title": title, "summary": text} for id_, title, text in self.gaps],
            "not_collected": list(self.not_collected),
        }


# Each module exposes PROVIDER. Listing a module here is the only registration step.
_MODULES = ("unifi", "nextdns", "proxmox", "pihole")
_cache: dict[str, Provider] | None = None


def providers() -> dict[str, Provider]:
    """Load every provider once and check that each declares a coherent contract."""
    global _cache
    if _cache is None:
        loaded: dict[str, Provider] = {}
        for name in _MODULES:
            provider: Provider = import_module(f"{__package__}.{name}").PROVIDER
            unknown = provider.provides - set(CAPABILITIES)
            if unknown or provider.id in loaded:
                raise RuntimeError(f"Integration {provider.id} declares an invalid contract")
            needs = {"dns.exceptions": (provider.allow_domain, provider.disallow_domain),
                     "guest.passes": (provider.issue_pass, provider.end_pass),
                     "guest.control": (provider.guest_access,)}
            for capability, functions in needs.items():
                if (capability in provider.provides) != all(f is not None for f in functions):
                    raise RuntimeError(f"Integration {provider.id} declares {capability} without its actions")
            if not re.fullmatch(r"[a-z][a-z0-9_]{1,31}", provider.id) or not provider.reads:
                raise RuntimeError(f"Integration {provider.id} declares an invalid contract")
            if provider.logo:
                try:
                    logo_uri(provider.logo)
                except (OSError, ValueError) as error:
                    raise RuntimeError(f"Integration {provider.id} declares an unusable logo") from error
            loaded[provider.id] = provider
        _cache = loaded
    return _cache


def get(provider_id: str) -> Provider:
    """Return a provider or raise the error an administrator sees for an unknown one."""
    provider = providers().get(provider_id)
    if provider is None:
        raise IntegrationError("This kind of source is not implemented in this release.")
    return provider


def find(provider_id: str | None) -> Provider | None:
    """Return a provider if it exists; used where an unknown source is simply not capable."""
    return providers().get(provider_id or "")


def provides(provider_id: str | None, capability: str) -> bool:
    """Say whether a source of this kind offers a capability."""
    provider = find(provider_id)
    return provider is not None and capability in provider.provides


def with_capability(capability: str) -> list[str]:
    """List provider ids that offer a capability."""
    return [p.id for p in providers().values() if capability in p.provides]


def writable() -> set[str]:
    """Provider ids an operator may name in NYCTR_PROVIDER_WRITES."""
    return {p.id for p in providers().values() if p.provides & WRITES}


def name_of(provider_id: str | None, fallback: str = "the source") -> str:
    """Return a provider's display name for sentences shown to people."""
    provider = find(provider_id)
    return provider.name if provider else fallback
