"""Create a disposable acceptance CA and fixture leaf, never a production trust bypass."""

from __future__ import annotations

import argparse
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

CERTIFICATE_FILES = ("ca.pem", "fixture.pem", "fixture-key.pem", "combined-ca.pem")
FIXTURE_NAMES = {"fixture", "api.nextdns.io", "api.ui.com"}


def write_public_test_file(path: Path, content: bytes) -> None:
    """Publish a complete fixture file as 0644 so the non-root test service can read it.

    The leaf key is deliberately disposable and readable in the isolated test
    volume. The CA signing key is never written to disk.
    """
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(content)
    temporary.chmod(0o644)
    os.replace(temporary, path)


def existing_certificates_valid(directory: Path) -> bool:
    """Reuse a complete unexpired test CA without rotating trust under a running fixture."""
    files = [directory / name for name in CERTIFICATE_FILES]
    if not any(path.exists() for path in files):
        return False
    if not all(path.is_file() for path in files):
        raise RuntimeError("Incomplete test certificates; reset the acceptance volumes.")
    leaf = x509.load_pem_x509_certificate((directory / "fixture.pem").read_bytes())
    ca = x509.load_pem_x509_certificate((directory / "ca.pem").read_bytes())
    names = set(
        leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value.get_values_for_type(
            x509.DNSName
        )
    )
    if names != FIXTURE_NAMES or min(leaf.not_valid_after_utc, ca.not_valid_after_utc) <= datetime.now(UTC):
        raise RuntimeError("Test certificates expired or changed; reset the acceptance volumes.")
    return True


def create_certificates(directory: Path) -> None:
    """Generate a CA-signed HTTPS leaf and a combined public/test trust bundle.

    Only fixture, api.nextdns.io and api.ui.com are valid names. The Docker alias
    untrusted-fixture intentionally fails normal hostname verification.
    """
    directory.mkdir(parents=True, exist_ok=True, mode=0o755)
    if existing_certificates_valid(directory):
        return
    now = datetime.now(UTC)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Nyctr isolated acceptance CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=45))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
        .sign(ca_key, hashes.SHA256())
    )
    leaf = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture")]))
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=5))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sorted(FIXTURE_NAMES)]),
            critical=False,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False
        )
        .sign(ca_key, hashes.SHA256())
    )
    ca_pem = ca.public_bytes(serialization.Encoding.PEM)
    write_public_test_file(directory / "ca.pem", ca_pem)
    write_public_test_file(directory / "fixture.pem", leaf.public_bytes(serialization.Encoding.PEM))
    write_public_test_file(
        directory / "fixture-key.pem",
        leaf_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        ),
    )
    write_public_test_file(directory / "combined-ca.pem", Path(certifi.where()).read_bytes() + b"\n" + ca_pem)


def main() -> int:
    """Initialize the named test volume using dependencies already present in the runtime image."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("/acceptance-certs"))
    args = parser.parse_args()
    try:
        create_certificates(args.directory)
    except (OSError, ValueError, RuntimeError):
        print("Acceptance certificate initialization failed. Reset only this test project's volumes.")
        return 1
    print("Disposable acceptance certificates are ready; TLS verification remains enabled.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
