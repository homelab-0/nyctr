"""Protected file keys for model credentials, provisioned explicitly outside the database.

Only the offline ``init`` command creates a key. Reads never create or repair one.
The caller owns the encrypted payload's purpose and endpoint binding.
"""

from __future__ import annotations

import base64
import os
import re
import stat
import sys
from pathlib import Path

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

FILE_LIMIT = 4096
PAYLOAD_LIMIT = 8192
TOKEN_LIMIT = 12000


class KeyUnavailable(ValueError):
    """A fixed refusal that discloses neither the path nor key material."""

    def __init__(self):
        super().__init__("The model credential key is unavailable. Restore a protected key file and try again.")


def _path(path: str | Path) -> Path:
    name = Path(path)
    if not name.is_absolute() or "\x00" in str(name):
        raise KeyUnavailable()
    return name


def _owned(info: os.stat_result) -> bool:
    return info.st_uid in {0, os.geteuid()}


def read_keyring(path: str | Path) -> MultiFernet:
    """Read 1 to 3 canonical Fernet keys from a protected regular file, without caching.

    Operator-controlled projected symlinks are supported. Check the opened target
    descriptor; nonblocking open prevents a FIFO from waiting for a writer.
    """
    try:
        with os.fdopen(os.open(_path(path), os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC), "rb") as source:
            info = os.fstat(source.fileno())
            if not stat.S_ISREG(info.st_mode) or not _owned(info) or info.st_mode & 0o027:
                raise KeyUnavailable()
            if info.st_mode & stat.S_IRGRP and info.st_gid not in {os.getegid(), *os.getgroups()}:
                raise KeyUnavailable()
            if info.st_size > FILE_LIMIT:
                raise KeyUnavailable()
            raw = source.read(FILE_LIMIT + 1)
        keys = raw.removesuffix(b"\n").split(b"\n")
        if len(raw) > FILE_LIMIT or not 1 <= len(keys) <= 3 or len(set(keys)) != len(keys):
            raise KeyUnavailable()
        for key in keys:
            if not re.fullmatch(rb"[A-Za-z0-9_-]{43}=", key):
                raise KeyUnavailable()
            if base64.urlsafe_b64encode(base64.urlsafe_b64decode(key)) != key:
                raise KeyUnavailable()
        return MultiFernet([Fernet(key) for key in keys])
    except (OSError, ValueError, TypeError):
        raise KeyUnavailable() from None


def seal(payload: bytes, path: str | Path) -> bytes:
    """Encrypt bounded bytes with the file's first key. No file is changed."""
    try:
        if not isinstance(payload, bytes) or not 1 <= len(payload) <= PAYLOAD_LIMIT:
            raise KeyUnavailable()
        return read_keyring(path).encrypt(payload)
    except (OSError, TypeError, ValueError):
        raise KeyUnavailable() from None


def unseal(token: bytes, path: str | Path) -> bytes:
    """Authenticate and decrypt bounded bytes, with no token age limit or fallback."""
    try:
        if not isinstance(token, bytes) or not 1 <= len(token) <= TOKEN_LIMIT:
            raise KeyUnavailable()
        payload = read_keyring(path).decrypt(token)
        if not 1 <= len(payload) <= PAYLOAD_LIMIT:
            raise KeyUnavailable()
        return payload
    except (OSError, InvalidToken, TypeError, ValueError):
        raise KeyUnavailable() from None


def initialize(path: str | Path) -> None:
    """Create one key once in an existing private directory and sync it durably.

    Directory-relative exclusive creation refuses symlinks and concurrent losers.
    A partial file after interruption stays in place for explicit operator recovery.
    """
    try:
        name = _path(path)
        directory = os.open(name.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            info = os.fstat(directory)
            if not _owned(info) or info.st_mode & 0o077:
                raise KeyUnavailable()
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC
            descriptor = os.open(name.name, flags, 0o600, dir_fd=directory)
            with os.fdopen(descriptor, "wb") as target:
                os.fchmod(target.fileno(), 0o600)
                target.write(Fernet.generate_key() + b"\n")
                target.flush()
                os.fsync(target.fileno())
            os.fsync(directory)
        finally:
            os.close(directory)
    except (OSError, ValueError, TypeError):
        raise KeyUnavailable() from None


def main(argv: list[str] | None = None) -> int:
    """Run the explicit initializer, printing only fixed messages even on bad input."""
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 2 or args[0] != "init":
        print("Usage: python -m nyctr.model_secrets init ABSOLUTE_PATH", file=sys.stderr)
        return 2
    try:
        initialize(args[1])
    except KeyUnavailable as refusal:
        print(str(refusal), file=sys.stderr)
        return 1
    print("Model credential key file created.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
