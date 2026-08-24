from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]

PACKAGES = (
    (
        ROOT / "integrations" / "harbor" / "incident_customer_coordination_v0",
        "files",
        ("world", "id"),
        "incident_customer_coordination_v0",
    ),
    (
        ROOT / "integrations" / "mastra" / "commerce_support_ops_v0",
        "files_sha256",
        ("integration_id",),
        "mastra_commerce_support_ops_v0",
    ),
)


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


@pytest.mark.parametrize(("package", "hash_key", "identity_path", "integration_id"), PACKAGES)
def test_public_harness_package_manifest_is_complete_and_exact(
    package: Path,
    hash_key: str,
    identity_path: tuple[str, ...],
    integration_id: str,
) -> None:
    adapter = json.loads((package / "DATALOX_ADAPTER.json").read_text(encoding="utf-8"))
    expected = adapter[hash_key]

    identity: object = adapter
    for part in identity_path:
        assert isinstance(identity, dict)
        identity = identity[part]
    assert identity == integration_id
    assert set(expected) == {
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if path.is_file()
        and path.name != "DATALOX_ADAPTER.json"
        and not {"node_modules", ".datalox", ".ruff_cache"}.intersection(
            path.relative_to(package).parts
        )
    }
    for relative_path, digest in expected.items():
        assert _sha256(package / relative_path) == digest


def test_public_harness_examples_state_the_research_and_grounding_boundary() -> None:
    index = (ROOT / "integrations" / "README.md").read_text(encoding="utf-8").lower()
    assert "research question" in index
    assert "source-grounded provider shapes" in index
    assert "do not claim fidelity" in index

    for package, _, _, _ in PACKAGES:
        readme = (package / "README.md").read_text(encoding="utf-8").lower()
        assert "research question" in readme
        assert "synthetic" in readme
