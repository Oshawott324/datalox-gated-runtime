"""Run-scoped certificate authority for isolated transparent HTTPS execution."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from datalox_gated_runtime.data_plane import normalize_authority


@dataclass(frozen=True)
class CertificatePaths:
    ca_certificate: Path
    gateway_certificate: Path
    gateway_private_key: Path


def generate_run_certificates(
    *,
    output_dir: Path,
    authorities: tuple[str, ...],
    now: datetime | None = None,
) -> CertificatePaths:
    if not authorities:
        raise ValueError("at least one provider authority is required")
    if output_dir.exists() and any(output_dir.iterdir()):
        raise ValueError("certificate output directory must be empty")
    output_dir.mkdir(parents=True, exist_ok=True)
    issued_at = (now or datetime.now(UTC)).astimezone(UTC)
    not_before = issued_at - timedelta(minutes=5)
    not_after = issued_at + timedelta(days=7)

    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Datalox Run CA")])
    ca_certificate = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
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
        .sign(ca_key, hashes.SHA256())
    )

    gateway_key = ec.generate_private_key(ec.SECP256R1())
    normalized = tuple(normalize_authority(item, scheme="https") for item in authorities)
    names = [_general_name(_host(authority)) for authority in normalized]
    gateway_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, _host(normalized[0]))])
    gateway_certificate = (
        x509.CertificateBuilder()
        .subject_name(gateway_name)
        .issuer_name(ca_certificate.subject)
        .public_key(gateway_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectAlternativeName(names), critical=False)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=True,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .sign(ca_key, hashes.SHA256())
    )

    paths = CertificatePaths(
        ca_certificate=output_dir / "ca.pem",
        gateway_certificate=output_dir / "gateway.pem",
        gateway_private_key=output_dir / "gateway-key.pem",
    )
    _exclusive_write(
        paths.ca_certificate,
        ca_certificate.public_bytes(serialization.Encoding.PEM),
        mode=0o644,
    )
    _exclusive_write(
        paths.gateway_certificate,
        gateway_certificate.public_bytes(serialization.Encoding.PEM),
        mode=0o644,
    )
    _exclusive_write(
        paths.gateway_private_key,
        gateway_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
        mode=0o600,
    )
    return paths


def _exclusive_write(path: Path, content: bytes, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        os.write(descriptor, content)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _host(authority: str) -> str:
    host = urlsplit(f"//{authority}").hostname
    if host is None:
        raise ValueError("invalid authority")
    return host


def _general_name(host: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(host))
    except ValueError:
        return x509.DNSName(host)
