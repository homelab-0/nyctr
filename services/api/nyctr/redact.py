"""Remove addresses and email addresses from text before a model sees it.

The pattern is bounded, and it only ever sees a short prefix of the value, so a
long piece of text cannot make the search run away. The assistant and a verdict
on a blocked name both use this. It does not decide what a rule may do.
"""

from __future__ import annotations

import re

# IPv4, a hardware address written with colons, hyphens or dots, and an email.
# Each alternative is bounded, so the search stays linear in the length it is shown.
_ADDRESS = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    r"|\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b"
    r"|\b(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}\b"
    r"|[\w.+-]{1,64}@[\w.-]{1,80}",
    re.I,
)


def clean(value: object, limit: int = 240) -> str:
    """Replace addresses and emails, then keep at most `limit` characters.

    The search sees at most four times `limit` characters. A prefix with none
    of the marks an address uses is cut with no search.
    """
    window = str(value or "")[: limit * 4]
    if not any(mark in window for mark in ("@", ".", ":", "-")):
        return window[:limit]
    return _ADDRESS.sub("[removed]", window)[:limit]
