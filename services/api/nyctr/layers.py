"""Where a block lives and what kind of thing blocked it, in words no vendor owns.

A layer is one place in the network where an address can be refused. A policy
descriptor says what refused it there. An integration states the kind and the
origin of each reason it reports, as facts about its source; anything it does
not state is unknown. What follows from those facts (whether a block is
deliberate, whether the access rule may ever open it) is worked out by the core.
"""

from __future__ import annotations

from dataclasses import dataclass

# In the order traffic meets them: the gateway's own filter answers a device first.
LAYERS = ("dns_gateway", "dns_upstream", "firewall", "intrusion")
# Where today's blocked lookups live. The other layers are declared and carry no data yet.
DNS_UPSTREAM = "dns_upstream"

# What refused the address. `list` is a list of advertising or tracking addresses, and `feed` is a
# feed of addresses reported as threats: a list or feed whose purpose the source does not state is
# `unknown`. `category` is a kind of site and `deny_entry` one address, each blocked by choice.
# `policy` and `region` are firewall rules, and `signature` is a recognised attack pattern.
KINDS = ("list", "feed", "category", "deny_entry", "policy", "region", "signature", "unknown")
# Who wrote what refused it: the people who run this network, the maker of the source, or someone else.
ORIGINS = ("administrator", "vendor", "third_party", "unknown")


@dataclass(frozen=True)
class Descriptor:
    """One reason an address was refused at one layer."""
    layer: str
    kind: str = "unknown"
    origin: str = "unknown"
    ref: str = ""  # The source's own identifier or name for the list, policy or signature.
    name: str = ""
    description: str = ""


def describe(layer: str, kind: object = None, origin: object = None, ref: str = "", name: str = "",
             description: str = "") -> Descriptor:
    """Build a descriptor from what an integration stated. A word outside the vocabulary becomes unknown."""
    if layer not in LAYERS:
        raise ValueError(f"{layer!r} is not a layer")
    return Descriptor(layer, kind if kind in KINDS else "unknown", origin if origin in ORIGINS else "unknown",
                      ref, name, description)


def deliberate(policy: Descriptor) -> bool | None:
    """Whether the block exists because an administrator chose it. None when that is not known.

    A category or a deny entry is always someone's choice, and so is anything an administrator
    wrote. A hit on a third party's or the vendor's list, feed or signature is not.
    """
    if policy.kind in ("category", "deny_entry") or policy.origin == "administrator":
        return True
    if policy.kind in ("list", "feed", "signature") and policy.origin in ("vendor", "third_party"):
        return False
    return None
