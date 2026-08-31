import stat
from datetime import UTC, datetime
from pathlib import Path

from cryptography import x509
from provider_runtime_helpers import build_stateful_provider_bundle

from datalox_gated_runtime.interception import generate_run_certificates
from datalox_gated_runtime.interception.server import prepare_interception_run


def test_run_ca_signs_gateway_certificate_for_exact_provider_authorities(
    tmp_path: Path,
) -> None:
    paths = generate_run_certificates(
        output_dir=tmp_path / "certs",
        authorities=("api.provider.test", "events.provider.test"),
        now=datetime(2026, 8, 8, tzinfo=UTC),
    )

    ca = x509.load_pem_x509_certificate(paths.ca_certificate.read_bytes())
    gateway = x509.load_pem_x509_certificate(paths.gateway_certificate.read_bytes())
    alternative_names = gateway.extensions.get_extension_for_class(
        x509.SubjectAlternativeName
    ).value.get_values_for_type(x509.DNSName)

    assert ca.subject == gateway.issuer
    assert set(alternative_names) == {"api.provider.test", "events.provider.test"}
    assert stat.S_IMODE(paths.gateway_private_key.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.ca_certificate.stat().st_mode) == 0o644
    assert b"PRIVATE KEY" not in paths.ca_certificate.read_bytes()


def test_prepare_can_publish_only_ca_to_agent_trust_directory(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path)
    trust = tmp_path / "trust"

    prepare_interception_run(bundle_dirs=(bundle,), run_root=tmp_path / "private", trust_dir=trust)

    assert [path.name for path in trust.iterdir()] == ["ca.pem"]
    assert (trust / "ca.pem").read_bytes() == (
        tmp_path / "private/certificates/ca.pem"
    ).read_bytes()
    assert not (trust / "control-token").exists()
    assert not (trust / "gateway-key.pem").exists()
