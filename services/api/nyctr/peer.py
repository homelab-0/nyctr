"""Which address a request came from. No other module reads the peer or a forwarded header.

The web server is started with its own forwarded-header handling off, so the
peer Nyctr sees is the real TCP peer. The rule:

1. A peer that is not in the operator's list of proxies is the client. Every
   header it sent is ignored.
2. A peer that is in the list: `X-Forwarded-For` is read from the right and the
   entry at position `proxy_hops` is taken. That is the one the operator's own
   proxy wrote. Entries to its left came from the client and are never read.
   Every entry to its right must itself be a listed proxy: one that is not
   means the request did not pass them all, and gives no address.
3. A missing or malformed entry gives no address.

No address is a real answer. A caller must handle `None` and must not fall back
to the peer or to another header. An address is evidence of where a request came
from, never of who sent it.
"""

from dataclasses import dataclass
from functools import lru_cache
from ipaddress import collapse_addresses, ip_address, ip_network

from starlette.requests import Request


@dataclass(frozen=True)
class Seen:
    """What one request showed: the address, and how it was worked out.

    `why` is `peer` (the peer is the client), `forwarded` (a listed proxy's entry
    was used), or the reason there is no address: `no_peer`, `zone` (the peer
    is a link-local address with a zone, which matches no list and no device),
    `missing`, `short` (fewer entries than hops), `hops` (a hop count below
    one), `malformed`, or `unlisted` (an entry between the peer and the one to
    read is not a listed proxy; `unlisted` holds it). `entry` counts from the
    right and names the entry read or the one refused. `address_is_proxy` says
    the address read is itself on the list: too few hops are counted.
    """
    address: str | None
    peer: str | None
    via_proxy: bool
    why: str
    entry: int | None = None
    entries: int = 0
    unlisted: str | None = None
    address_is_proxy: bool = False


@lru_cache(maxsize=16)
def proxies(listed: str) -> tuple:
    """Read the operator's list of proxies: addresses and ranges, comma separated.

    Raises ValueError for anything else, so a wildcard or a hostname stops the
    server instead of being read as "believe everyone" or "believe nobody". A
    list whose ranges together cover every address of a family is the wildcard
    written another way, and is refused in the words the chart uses.
    """
    try:
        networks = tuple(ip_network(item.strip(), strict=False) for item in listed.split(",") if item.strip())
    except ValueError:
        networks = None
    if networks is None or any(merged.prefixlen == 0 for family in (4, 6)
                               for merged in collapse_addresses(x for x in networks if x.version == family)):
        raise ValueError("NYCTR_TRUSTED_PROXIES must contain only trusted proxy IP addresses or bounded ranges.")
    return networks


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
    return any(address in network for network in proxies(settings.proxy_list))


def seen(request: Request) -> Seen:
    """Work out the address of this request and say how, for the sign-in limit and the operator's check."""
    settings = request.app.state.settings
    client = request.scope.get("client")
    host = str(client[0]) if client else ""
    peer = _ip(host)
    if peer is None:
        zone = "%" in host and _ip(host.partition("%")[0]) is not None
        return Seen(None, host if zone else None, False, "zone" if zone else "no_peer")
    if not _listed(peer, settings):
        return Seen(str(peer), str(peer), False, "peer")
    # Several header lines are one list, in the order they arrived: the proxy's entry is still last.
    entries = [x for line in request.headers.getlist("x-forwarded-for") for x in line.split(",")]
    hops = settings.proxy_hops
    if hops < 1:
        # The settings refuse this. Counting from the right, 0 would be the leftmost entry: never read it.
        return Seen(None, str(peer), True, "hops")
    if not any(x.strip() for x in entries):
        return Seen(None, str(peer), True, "missing")
    if len(entries) < hops:
        return Seen(None, str(peer), True, "short", entries=len(entries))
    # The entries to the right of the one read are about the operator's own proxies. One that is
    # not listed means a request that went round a proxy and wrote the entry itself: no address.
    for position in range(1, hops):
        proxy = _entry(entries[-position])
        if proxy is None or not _listed(proxy, settings):
            return Seen(None, str(peer), True, "unlisted" if proxy else "malformed", entry=position,
                        entries=len(entries), unlisted=str(proxy) if proxy else None)
    address = _entry(entries[-hops])
    return Seen(str(address) if address else None, str(peer), True, "forwarded" if address else "malformed",
                entry=hops, entries=len(entries), address_is_proxy=bool(address and _listed(address, settings)))


def client_address(request: Request) -> str | None:
    """Return the address this request came from, or None when Nyctr cannot tell."""
    return seen(request).address
