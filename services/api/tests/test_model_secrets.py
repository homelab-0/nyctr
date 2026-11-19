"""Offline model-key storage: authenticated bytes, protected files, explicit creation."""

import base64
import os
import stat
import subprocess
import sys
import traceback
from pathlib import Path
from types import SimpleNamespace

import pytest
from conftest import live_app, live_signin
from cryptography.fernet import Fernet, InvalidToken
from fastapi.testclient import TestClient
from test_collection_store import POSTGRES, postgres_database

from nyctr import model_secrets as storage
from nyctr.config import Settings

CANARY = b"fabricated-model-key-NEVER-A-REAL-CREDENTIAL"


def ring(path, *keys):
    """Write test-only Fernet keys with the operator's documented file permissions."""
    path.write_bytes(b"\n".join(keys) + b"\n")
    path.chmod(0o600)
    return path


def refused(operation):
    """A refusal is always the same fixed message, including its displayed traceback."""
    with pytest.raises(storage.KeyUnavailable) as error:
        operation()
    shown = "".join(traceback.format_exception(error.type, error.value, error.tb))
    assert str(error.value) == str(storage.KeyUnavailable())
    assert CANARY.decode() not in shown
    return str(error.value)


def test_authenticated_roundtrip_is_randomized_and_keeps_canary_out_of_ciphertext(tmp_path):
    path = ring(tmp_path / "keyring", Fernet.generate_key())
    first, second = storage.seal(CANARY, path), storage.seal(CANARY, path)
    assert first != second and CANARY not in first + second
    assert storage.unseal(first, path) == storage.unseal(second, path) == CANARY
    damaged = bytearray(base64.urlsafe_b64decode(first))
    damaged[-1] ^= 1
    for token in (first[:-8], base64.urlsafe_b64encode(damaged), b"invalid-token"):
        refused(lambda token=token: storage.unseal(token, path))
    ring(path, Fernet.generate_key())
    refused(lambda: storage.unseal(first, path))


def test_rotation_and_restore_reread_the_file_on_each_operation(tmp_path):
    old, new = Fernet.generate_key(), Fernet.generate_key()
    path = ring(tmp_path / "keyring", old)
    original = storage.seal(CANARY, path)
    ring(path, new, old)
    assert storage.unseal(original, path) == CANARY
    rotated = storage.seal(storage.unseal(original, path), path)
    assert Fernet(new).decrypt(rotated) == CANARY
    with pytest.raises(InvalidToken):
        Fernet(old).decrypt(rotated)
    ring(path, new)
    assert storage.unseal(rotated, path) == CANARY
    refused(lambda: storage.unseal(original, path))
    ring(path, old)  # a matching old backup still opens its own ciphertext
    assert storage.unseal(original, path) == CANARY
    path.unlink()
    refused(lambda: storage.unseal(original, path))
    refused(lambda: storage.seal(CANARY, path))
    assert not path.exists()  # no repair or process-only key fallback


@pytest.mark.parametrize("contents", [b"", b"\n", b"not-a-key\n", b"A" * 4097])
def test_empty_malformed_and_oversized_files_are_not_repaired(tmp_path, contents):
    path = tmp_path / "keyring"
    path.write_bytes(contents)
    path.chmod(0o600)
    refused(lambda: storage.read_keyring(path))
    assert path.read_bytes() == contents


def test_the_keyring_is_bounded_distinct_and_canonical(tmp_path):
    key = Fernet.generate_key()
    alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    alias = key[:-2] + bytes([alphabet[alphabet.index(key[-2]) ^ 1]]) + b"="
    assert base64.urlsafe_b64decode(alias) == base64.urlsafe_b64decode(key)
    path = tmp_path / "keyring"
    for contents in (key + b"\n" + key, key + b"\n\n", key + b"\r\n", b" " + key,
                     alias, b"\n".join(Fernet.generate_key() for _ in range(4))):
        path.write_bytes(contents)
        path.chmod(0o600)
        refused(lambda: storage.read_keyring(path))
    ring(path, key, Fernet.generate_key(), Fernet.generate_key())
    assert storage.unseal(storage.seal(CANARY, path), path) == CANARY


@pytest.mark.parametrize("mode", [0o644, 0o620, 0o602, 0o604, 0o666])
def test_exposed_or_writable_key_files_are_refused(tmp_path, mode):
    path = ring(tmp_path / "keyring", Fernet.generate_key())
    path.chmod(mode)
    refused(lambda: storage.read_keyring(path))


def test_owner_and_group_checks_use_the_opened_descriptor(tmp_path, monkeypatch):
    path = ring(tmp_path / "keyring", Fernet.generate_key())
    path.chmod(0o440)
    real = os.fstat
    metadata = {"st_uid": 0, "st_gid": os.getegid()}

    def changed(descriptor):
        actual = real(descriptor)
        return SimpleNamespace(st_mode=actual.st_mode, st_size=actual.st_size, **metadata)

    monkeypatch.setattr(os, "fstat", changed)
    assert storage.unseal(storage.seal(CANARY, path), path) == CANARY  # root-owned projected file
    metadata["st_gid"] = max([os.getegid(), *os.getgroups()]) + 1
    refused(lambda: storage.read_keyring(path))
    metadata.update(st_gid=os.getegid(), st_uid=max(1, os.geteuid()) + 1)
    refused(lambda: storage.read_keyring(path))


def test_projected_symlink_target_is_checked_and_projection_can_change(tmp_path):
    first = ring(tmp_path / "first", Fernet.generate_key())
    second = ring(tmp_path / "second", Fernet.generate_key())
    projection = tmp_path / "..data"
    projection.symlink_to(first)
    path = tmp_path / "keyring"
    path.symlink_to(projection)
    token = storage.seal(CANARY, path)
    first.chmod(0o644)
    refused(lambda token=token: storage.unseal(token, path))
    first.chmod(0o600)
    projection.unlink()
    projection.symlink_to(second)
    refused(lambda token=token: storage.unseal(token, path))
    assert storage.unseal(storage.seal(CANARY, path), path) == CANARY


def test_fifo_is_refused_without_waiting_for_a_writer(tmp_path):
    fifo = tmp_path / "pipe"
    os.mkfifo(fifo, 0o600)
    code = ("from nyctr.model_secrets import read_keyring, KeyUnavailable; import sys\n"
            "try: read_keyring(sys.argv[1])\n"
            "except KeyUnavailable: sys.exit(0)\n"
            "sys.exit(1)")
    result = subprocess.run([sys.executable, "-c", code, str(fifo)], capture_output=True, timeout=5)
    assert result.returncode == 0 and result.stdout == result.stderr == b""
    refused(lambda: storage.read_keyring(tmp_path))  # directory
    refused(lambda: storage.read_keyring(Path("/dev/null")))  # device


def test_growth_past_the_read_bound_is_refused_even_when_initial_size_is_small(tmp_path, monkeypatch):
    path = ring(tmp_path / "keyring", Fernet.generate_key())
    path.write_bytes(b"x" * 4097)
    actual = path.stat()
    monkeypatch.setattr(os, "fstat", lambda _fd: SimpleNamespace(
        st_uid=actual.st_uid, st_gid=actual.st_gid, st_mode=actual.st_mode, st_size=0))
    refused(lambda: storage.read_keyring(path))


def test_io_failures_are_fixed_and_never_print_the_os_message(tmp_path, monkeypatch, capsys):
    name = tmp_path / CANARY.decode()

    def fail(*_args, **_kwargs):
        raise PermissionError(str(name))

    monkeypatch.setattr(os, "open", fail)
    refused(lambda: storage.read_keyring(name))
    refused(lambda: storage.initialize(name))
    assert storage.main(["init", str(name)]) == 1
    output = capsys.readouterr()
    assert output.out == "" and output.err == str(storage.KeyUnavailable()) + "\n"
    assert str(name) not in output.err


def test_payload_and_token_boundaries_are_enforced(tmp_path):
    path = ring(tmp_path / "keyring", Fernet.generate_key())
    maximum = b"x" * storage.PAYLOAD_LIMIT
    assert storage.unseal(storage.seal(maximum, path), path) == maximum
    for payload in (b"", b"x" * (storage.PAYLOAD_LIMIT + 1), "not bytes", None):
        refused(lambda payload=payload: storage.seal(payload, path))
    for token in (b"", b"x" * (storage.TOKEN_LIMIT + 1), "not bytes", None):
        refused(lambda token=token: storage.unseal(token, path))
    for payload in (b"", maximum + b"x"):
        token = storage.read_keyring(path).encrypt(payload)
        refused(lambda token=token: storage.unseal(token, path))


def test_initialize_is_exclusive_private_durable_and_prints_no_key(tmp_path, monkeypatch, capsys):
    path = tmp_path / "keyring"
    synced, real = [], os.fsync

    def sync(descriptor):
        synced.append(os.fstat(descriptor).st_mode)
        real(descriptor)

    monkeypatch.setattr(os, "fsync", sync)
    previous = os.umask(0o777)
    try:
        assert storage.main(["init", str(path)]) == 0
    finally:
        os.umask(previous)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert len(synced) == 2 and stat.S_ISREG(synced[0]) and stat.S_ISDIR(synced[1])
    created = path.read_bytes()
    assert len(created) == 45 and storage.unseal(storage.seal(CANARY, path), path) == CANARY
    assert capsys.readouterr().out == "Model credential key file created.\n"
    refused(lambda: storage.initialize(path))
    assert path.read_bytes() == created


def test_initializer_requires_an_existing_private_directory_and_refuses_symlinks(tmp_path):
    for mode in (0o755, 0o770, 0o707):
        tmp_path.chmod(mode)
        refused(lambda: storage.initialize(tmp_path / "keyring"))
        assert not (tmp_path / "keyring").exists()
    tmp_path.chmod(0o700)
    refused(lambda: storage.initialize(tmp_path / "missing" / "keyring"))
    target = ring(tmp_path / "target", Fernet.generate_key())
    before = target.read_bytes()
    path = tmp_path / "keyring"
    path.symlink_to(target)
    refused(lambda: storage.initialize(path))
    assert target.read_bytes() == before and path.is_symlink()
    path.unlink()
    path.symlink_to(tmp_path / "absent")
    refused(lambda: storage.initialize(path))
    assert not (tmp_path / "absent").exists()


def test_partial_initialization_is_never_overwritten_or_repaired(tmp_path, monkeypatch):
    path = tmp_path / "keyring"

    def interrupted():
        raise OSError(CANARY.decode())

    monkeypatch.setattr(Fernet, "generate_key", interrupted)
    refused(lambda: storage.initialize(path))
    assert path.read_bytes() == b""
    refused(lambda: storage.initialize(path))
    refused(lambda: storage.read_keyring(path))
    assert path.read_bytes() == b""


@pytest.mark.parametrize("failure_at", [1, 2])
def test_sync_failure_never_reports_success_or_overwrites_the_created_file(tmp_path, monkeypatch, failure_at):
    path = tmp_path / "keyring"
    calls = []

    def fail(descriptor):
        calls.append(descriptor)
        if len(calls) == failure_at:
            raise OSError(CANARY.decode())

    monkeypatch.setattr(os, "fsync", fail)
    refused(lambda: storage.initialize(path))
    created = path.read_bytes()
    assert len(created) == 45
    refused(lambda: storage.initialize(path))
    assert path.read_bytes() == created and len(calls) == failure_at


def test_two_initializer_processes_have_one_winner_without_key_output(tmp_path):
    path = tmp_path / "keyring"
    code = ("import sys; from nyctr.model_secrets import main; sys.stdin.read(1); "
            "sys.exit(main(['init', sys.argv[1]]))")
    processes = [subprocess.Popen([sys.executable, "-c", code, str(path)], stdin=subprocess.PIPE,
                                 stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
    try:
        for process in processes:
            process.stdin.write(b"x")
            process.stdin.flush()
        output = [process.communicate(timeout=5) for process in processes]
        assert sorted(process.returncode for process in processes) == [0, 1]
        assert sorted(out for out, _err in output) == [b"", b"Model credential key file created.\n"]
        assert sorted(err for _out, err in output) == [b"", (str(storage.KeyUnavailable()) + "\n").encode()]
        assert storage.unseal(storage.seal(CANARY, path), path) == CANARY
    finally:
        for process in processes:
            if process.poll() is None:
                process.kill()
                process.communicate()


@pytest.mark.parametrize("args", [[], [CANARY.decode()], ["init"], ["init", "/x", CANARY.decode()]])
def test_cli_usage_does_not_repeat_arguments(args, capsys):
    assert storage.main(args) == 2
    output = capsys.readouterr()
    assert output.out == "" and output.err == "Usage: python -m nyctr.model_secrets init ABSOLUTE_PATH\n"


def test_only_absolute_paths_are_accepted_without_reading_them(tmp_path, monkeypatch):
    for path in ("relative", "~/keyring", "/bad\x00name", "/bad\nname"):
        with pytest.raises(ValueError) as error:
            Settings(model_key_file=path)
        assert path not in str(error.value)
    monkeypatch.setenv("NYCTR_MODEL_KEY_FILE", str(tmp_path / "absent"))
    assert Settings().model_key_file == str(tmp_path / "absent")
    monkeypatch.delenv("NYCTR_MODEL_KEY_FILE")
    assert Settings().model_key_file == ""
    for path in ("relative", "~/keyring", "/bad\x00name"):
        refused(lambda path=path: storage.initialize(path))
        refused(lambda path=path: storage.read_keyring(path))


@pytest.mark.parametrize("database", ["sqlite", pytest.param("postgresql", marks=pytest.mark.postgres)])
def test_missing_key_file_neither_blocks_startup_nor_changes_existing_model_references(
        tmp_path, request, database, monkeypatch):
    place = postgres_database(request) if database == "postgresql" else {}
    if database == "postgresql" and not place:
        pytest.skip(f"No PostgreSQL server is named in {POSTGRES}")
    path = tmp_path / "absent"
    app = live_app(tmp_path, **place, model_key_file=str(path), ai_base_url="https://llm.example/v1",
                   ai_model="fabricated-model", ai_api_key=CANARY.decode())
    monkeypatch.setenv("NYCTR_MODEL_SECRET_TEST", CANARY.decode())
    with TestClient(app) as client:
        headers = live_signin(client)
        assert client.get("/api/health").status_code == 200
        assert client.get("/api/model").json()["key"] == "server"
        response = client.put("/api/model", headers=headers, json={
            "endpoint": "https://llm.example/v1", "model": "fabricated-model",
            "secret_ref": "NYCTR_MODEL_SECRET_TEST"})
        assert response.status_code == 200 and response.json()["key"] == "reference"
        assert CANARY.decode() not in response.text and not path.exists()
