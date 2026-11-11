"""The two addresses Nyctr can be served on.

The console address (`NYCTR_PUBLIC_URL`) is where administrators work. An
optional portal address (`NYCTR_PORTAL_URL`) is where members go to see what was
blocked and ask for access. Which one a request arrived on is read from its Host
header and compared with the two configured origins; URLs are only ever built
from those configured origins, never from the header.

On the portal address every session has member rights, whatever the account's
role, so the console's reads and changes are not reachable there. That narrows
what a session on the portal address can do. It is a network boundary only when
the operator also routes the two hostnames separately: a caller who can reach
the pod under the console's hostname is on the console address.
"""

from urllib.parse import urlsplit

from fastapi import Request

from .config import Settings

CONSOLE = "console"
PORTAL = "portal"
_DEFAULT_PORTS = {"http": "80", "https": "443"}


def _host(scheme: str, netloc: str) -> str:
    """Lower-case a host[:port] and drop the port when it is the scheme's default."""
    host = netloc.strip().lower()
    name, separator, port = host.rpartition(":")
    # "name:port" or "[v6]:port". A bare IPv6 literal has colons but no port to drop.
    if separator and port.isdigit() and (name.endswith("]") or ":" not in name):
        return name if port == _DEFAULT_PORTS.get(scheme) else host
    return host


def site_of(request: Request) -> str:
    """Name the address a request arrived on. Anything that is not the portal's host is the console."""
    settings: Settings = request.app.state.settings
    if not settings.portal_url:
        return CONSOLE
    portal = urlsplit(settings.portal_url)
    arrived = _host(portal.scheme, request.headers.get("host", ""))
    return PORTAL if arrived == _host(portal.scheme, portal.netloc) else CONSOLE


def origin_of(settings: Settings, site: str) -> str:
    """Return the configured origin of an address."""
    return settings.portal_url if site == PORTAL else settings.public_url


class PortalIdentity:
    """A signed-in account as the portal address sees it: the same person with member rights.

    Reads fall through to the account. The role is fixed, and nothing is ever
    written through this view, so the account itself is not changed.
    """

    role = "member"
    __slots__ = ("_user",)

    def __init__(self, user):
        object.__setattr__(self, "_user", user)

    def __getattr__(self, name):
        return getattr(object.__getattribute__(self, "_user"), name)

    def __setattr__(self, name, value):
        raise AttributeError("An account cannot be changed through the portal address")

    def administers_console(self) -> bool:
        """Say whether this person is an administrator on the console address, to offer them the way there."""
        return object.__getattribute__(self, "_user").role == "admin"


def members_use_portal(request: Request, user) -> bool:
    """Say whether this member should be sent to the portal address instead of signed in here.

    True only on the console address, for a member, when a portal address is
    configured. Without one, members and administrators share the one address.
    """
    settings: Settings = request.app.state.settings
    return bool(settings.portal_url) and site_of(request) == CONSOLE and user.role == "member"


def seen_as(request: Request, user):
    """Return the account with the rights it has on the address this request arrived on."""
    return PortalIdentity(user) if site_of(request) == PORTAL else user
