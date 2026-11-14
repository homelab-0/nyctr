"""What the shared connector says when an HTTPS source does not answer, against local sockets only.

The errors here are the ones the pinned HTTP library really raises, chain and all: a read that
gets no answer on an HTTPS connection ends in `ssl.SSLWantReadError`, which a bare
`httpx.ReadTimeout("slow")` does not show.
"""

import asyncio
import socket
import ssl
import threading
from datetime import UTC, datetime, timedelta

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from nyctr.collection import classify
from nyctr.integrations import IntegrationError, core


@pytest.fixture(scope="module")
def certificate(tmp_path_factory):
    """A fabricated certificate for `localhost`: what the local server shows, and what a client may trust."""
    folder = tmp_path_factory.mktemp("fabricated-certificate")
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    made = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(hours=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
            .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
            .sign(key, hashes.SHA256()))
    (folder / "cert.pem").write_bytes(made.public_bytes(serialization.Encoding.PEM))
    (folder / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                                       serialization.PrivateFormat.PKCS8,
                                                       serialization.NoEncryption()))
    shown = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    shown.load_cert_chain(folder / "cert.pem", folder / "key.pem")
    return shown, ssl.create_default_context(cafile=str(folder / "cert.pem"))


@pytest.fixture
def silent_source():
    """Start a local server that accepts a connection and then never answers; with `shown`, after the handshake."""
    done, sockets = threading.Event(), []

    def start(shown: ssl.SSLContext | None) -> int:
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(4)
        sockets.append(listener)

        def serve():
            while not done.is_set():
                try:
                    connection, _ = listener.accept()
                except OSError:
                    return
                sockets.append(connection)
                try:
                    if shown is not None:
                        connection = shown.wrap_socket(connection, server_side=True)
                        sockets.append(connection)
                        connection.recv(4096)
                except OSError:
                    continue  # The client gave up on the certificate: nothing more to hold open.
                done.wait(10)

        threading.Thread(target=serve, daemon=True).start()
        return listener.getsockname()[1]

    yield start
    done.set()
    for held in sockets:
        held.close()


def failure(port: int, trust) -> IntegrationError:
    """Read from the local server through the shared connector and return how it failed."""
    async def read():
        async with httpx.AsyncClient(timeout=httpx.Timeout(0.4), verify=trust, trust_env=False) as client:
            await core.ReadClient(client, f"https://localhost:{port}").get("/x")

    with pytest.raises(IntegrationError) as caught:
        asyncio.run(read())
    return caught.value


def chain(error: BaseException) -> list[type]:
    """The types down an error's chain of causes."""
    found = []
    while error is not None and len(found) < 12:
        found.append(type(error))
        error = error.__cause__ or error.__context__
    return found


@pytest.mark.parametrize("stalls", ["after the handshake", "during the handshake"])
def test_an_https_source_that_does_not_answer_in_time_is_a_timeout_and_is_retried(certificate, silent_source, stalls,
                                                                                 monkeypatch):
    """No answer on an HTTPS connection is told as no answer, never as a certificate failure, and may pass by waiting."""
    shown, trust = certificate
    raised = []
    real = core._transport_category
    monkeypatch.setattr(core, "_transport_category", lambda error: raised.append(error) or real(error))
    error = failure(silent_source(shown if stalls == "after the handshake" else None), trust)
    # The honest case: the library's own timeout, with an SSLError at the bottom of its chain.
    assert isinstance(raised[0], httpx.TimeoutException)
    assert any(issubclass(kind, ssl.SSLError) for kind in chain(raised[0]))
    assert error.category == "timeout"
    assert str(error) == "The source did not answer in time. Check that it is running and can be reached."
    assert "certificate" not in str(error)
    # What follows from the category: the scheduled collection tries again, and an optional read
    # that timed out still fails the collection instead of being recorded as something the key may not read.
    assert classify(error, str(error)).may_pass is True
    assert core.must_stop(error) is True


def test_a_certificate_that_is_not_trusted_is_still_a_certificate_failure_and_is_not_retried(certificate,
                                                                                           silent_source):
    """The certificate sentence is kept for a certificate failure, which waiting will not fix."""
    shown, _trust = certificate
    error = failure(silent_source(shown), ssl.create_default_context())
    assert error.category == "tls" and "certificate" in str(error)
    assert classify(error, str(error)).may_pass is False
