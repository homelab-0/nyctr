"""Which address a request came from. No other module reads the peer or a forwarded header.

The web server is started with its own forwarded-header handling off, so the
peer Nyctr sees is the real TCP peer. The rule:

1. A peer that is not in the operator's list of proxies is the client. Every
   header it sent is ignored.
2. A peer that is in the list: `X-Forwarded-For` is read from the right and the
   entry at position `proxy_hops` is taken. That is the one the operator's own
   proxy wrote. Entries to its left came from the client and are never read.
3. A missing or malformed entry gives no address.

No address is a real answer. A caller must handle `None` and must not fall back
to the peer or to another header. An address is evidence of where a request came
from, never of who sent it.
"""

from dataclasses import dataclass
from functools import lru_cache
from ipaddress import ip_address, ip_network

from starlette.requests import Request


@dataclass(frozen=True)
class Seen:
    """What one request showed: the address, and how it was worked out.

    `why` is `peer` (the peer is the client), `forwarded` (a listed proxy's entry
    was used), or the reason there is no address: `no_peer`, `missing`, `short`
    (fewer entries than hops) or `malformed`. `entry` counts from the right.
    """
    address: str | None
    peer: str | None
    via_proxy: bool
    why: str
    entry: int | None = None
    entries: int = 0


@lru_cache(maxsize=16)
def proxies(listed: str) -> tuple:
    """Read the operator's list of proxies: addresses and ranges, comma separated.

    Raises ValueError for anything else, so a wildcard or a hostname stops the
    server instead of being read as "believe everyone" or "believe nobody".
    """
    try:
        return tuple(ip_network(item.strip(), strict=False) for item in listed.split(",") if item.strip())
    except ValueError:
        raise ValueError("FORWARDED_ALLOW_IPS accepts only IP addresses and ranges, separated by commas") from None


def _ip(text: str):
    """Read a plain address. None for a name, a zone, or anything else that is not one address."""
    try:
        address = ip_address(text)
    except ValueError:
        return None
    if address.version == 6 and address.scope_id:
        return None
    return address.ipv4_mapped or address if address.version == 6 else address


def _entry(text: str):
    """Read one header entry as proxies write it: bare, `address:port`, `[v6]` or `[v6]:port`."""
    text = text.strip()
    host, port = text, None
    if text.startswith("["):
        host, closed, rest = text[1:].partition("]")
        if not closed or ":" not in host or (rest and not rest.startswith(":")):
            return None
        port = rest[1:] if rest else None
    elif text.count(":") == 1:
        host, _, port = text.partition(":")
    if port is not None and not (port.isascii() and port.isdigit() and int(port) <= 65535):
        return None
    return _ip(host)


def _listed(address, settings) -> bool:
    """Say whether this peer is one of the operator's proxies."""
    return any(address in network for network in proxies(settings.forwarded_allow_ips))


def seen(request: Request) -> Seen:
    """Work out the address of this request and say how, for the sign-in limit and the operator's check."""
    settings = request.app.state.settings
    client = request.scope.get("client")
    peer = _ip(str(client[0])) if client else None
    if peer is None:
        return Seen(None, None, False, "no_peer")
    if not _listed(peer, settings):
        return Seen(str(peer), str(peer), False, "peer")
    # Several header lines are one list, in the order they arrived: the proxy's entry is still last.
    entries = [x for line in request.headers.getlist("x-forwarded-for") for x in line.split(",")]
    hops = settings.proxy_hops
    if not any(x.strip() for x in entries):
        return Seen(None, str(peer), True, "missing")
    if len(entries) < hops:
        return Seen(None, str(peer), True, "short", entries=len(entries))
    address = _entry(entries[-hops])
    return Seen(str(address) if address else None, str(peer), True, "forwarded" if address else "malformed",
                entry=hops, entries=len(entries))


def client_address(request: Request) -> str | None:
    """Return the address this request came from, or None when Nyctr cannot tell."""
    return seen(request).address


class ForwardedScheme:
    """Take the scheme a listed proxy reports (`X-Forwarded-Proto`), and from nobody else.

    The web server did this before its own handling was switched off. Nyctr's
    cookies, redirects and sign-in return address do not use it: they come from
    the configured origins. It keeps `request.url` right for anything that does.
    """

    def __init__(self, app, settings):
        """Wrap the application with the settings that list the proxies."""
        self.app, self.settings = app, settings

    async def __call__(self, scope, receive, send):
        """Set the scheme only for one clean `http` or `https` value sent by a listed proxy."""
        if scope["type"] == "http" and scope.get("client"):
            peer = _ip(str(scope["client"][0]))
            said = [value for name, value in scope["headers"] if name == b"x-forwarded-proto"]
            scheme = said[0].decode("latin-1").strip().lower() if len(said) == 1 else ""
            if peer is not None and scheme in ("http", "https") and _listed(peer, self.settings):
                scope["scheme"] = scheme
        await self.app(scope, receive, send)
