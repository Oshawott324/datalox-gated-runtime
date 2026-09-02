from __future__ import annotations

import hashlib
import importlib.util
import json
from pathlib import Path

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    load_provider_admission,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.release import load_provider_release

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "envs" / "medusa_store_pagination_v0"
EVIDENCE = ENV / "evidence"
AUTHORITY = "api.medusa.local"


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _sha256(path: Path) -> str:
    return f"sha256:{hashlib.sha256(path.read_bytes()).hexdigest()}"


def _request(*, limit: str, offset: str) -> CallRequest:
    return CallRequest(
        scheme="https",
        authority=AUTHORITY,
        method="GET",
        path="/store/products",
        query={"limit": limit, "offset": offset},
    )


def test_retained_g2_evidence_passes_fail_closed_checker() -> None:
    checker = _load_script(
        ROOT / "scripts" / "providers" / "check-medusa-pagination-evidence.py",
        "check_medusa_pagination_evidence",
    )

    report = checker.check(EVIDENCE)

    assert report["status"] == "passed"
    assert report["provider_version"] == "2.16.0"
    assert report["observed_records"] == 50
    assert report["observed_requests"] == 16
    assert report["invalid_statuses"] == [500, 400, 500, 400]
    observations = json.loads((EVIDENCE / "observations.json").read_text(encoding="utf-8"))
    assert observations["schema_version"] == "datalox_medusa_pagination_observations_v2"
    assert observations["capture_path_projection"] == {
        "gate_path_template": "/{provider_id}{upstream_path}",
        "probe_config_path": "probes/medusa_pagination.json",
        "probe_config_sha256": _sha256(ROOT / "probes" / "medusa_pagination.json"),
        "provider_id": "medusa",
        "upstream_path_source": "probe_requests[*].path",
        "upstream_projection": "strip_first_gate_path_segment_v1",
    }
    assert all(
        row["gate_path"] == "/medusa/store/products"
        and row["upstream_path"] == "/store/products"
        and "path" not in row
        for row in observations["observations"]
    )


def test_runtime_source_is_reproducible_from_identifier_free_observations(tmp_path: Path) -> None:
    builder = _load_script(
        ROOT / "scripts" / "providers" / "build-medusa-pagination-runtime.py",
        "build_medusa_pagination_runtime",
    )
    generated = tmp_path / "gate_config.json"

    builder.build(EVIDENCE / "observations.json", generated)

    assert generated.read_bytes() == (ENV / "gate_config.json").read_bytes()
    payload = json.loads(generated.read_text(encoding="utf-8"))
    assert len(payload["response_cases"]) == 15
    assert "cursor" not in generated.read_text(encoding="utf-8").lower()


def test_complete_provider_release_chain_is_not_stale(tmp_path: Path) -> None:
    builder = _load_script(
        ROOT / "scripts" / "providers" / "build-medusa-pagination-release.py",
        "build_medusa_pagination_release",
    )
    rebuilt = tmp_path / "rebuilt"

    report = builder.build(EVIDENCE, rebuilt)

    assert report == {
        "output_root": str(rebuilt),
        "admission_sha256": "sha256:2f63dc62a258933a2b8f6658285c4501c6b6066eb1df25d13c53942def6e96ca",
        "release_manifest_digest": "sha256:d565982dbb8221c1fd9923fb9537330a992f5d77b49fcef51640aa85bfea4a3e",
    }
    relative_files = sorted(
        path.relative_to(rebuilt) for path in rebuilt.rglob("*") if path.is_file()
    )
    committed_files = sorted(path.relative_to(ENV) for path in ENV.rglob("*") if path.is_file())
    assert relative_files == committed_files
    for relative in relative_files:
        assert (rebuilt / relative).read_bytes() == (ENV / relative).read_bytes(), relative


def test_admitted_runtime_executes_native_medusa_offset_pages_and_reset(tmp_path: Path) -> None:
    bundle_dir = ENV / "provider-runtime"
    admission_path = ENV / "provider-admission.json"
    bundle = load_provider_runtime_bundle(bundle_dir)
    admission = load_provider_admission(admission_path)

    assert bundle.manifest.authorities == (AUTHORITY,)
    assert admission["admitted"] is True
    assert admission["provider_runtime_sha256"] == _sha256(bundle_dir / "provider-runtime.json")
    assert admission["operations"][0]["operation_id"] == "medusa.store.products.list"
    assert admission["operations"][0]["grounding"] == {
        "evidence_refs": ["medusa_pagination_g2"],
        "grounded": True,
        "level": "G2_SELF_HOSTED_REFERENCE",
    }

    runtime = ProviderRuntime(
        bundle_dir=bundle_dir,
        admission_path=admission_path,
        run_dir=tmp_path / "run",
    )
    try:
        first = runtime.handle(_request(limit="10", offset="0"))
        middle = runtime.handle(_request(limit="10", offset="20"))
        terminal = runtime.handle(_request(limit="10", offset="45"))
        beyond = runtime.handle(_request(limit="10", offset="60"))
        invalid = runtime.handle(_request(limit="invalid", offset="0"))
        reset = runtime.reset()
        repeated = runtime.handle(_request(limit="10", offset="0"))
    finally:
        runtime.close()

    assert (
        first.status_code == middle.status_code == terminal.status_code == beyond.status_code == 200
    )
    assert [len(response.body["products"]) for response in (first, middle, terminal, beyond)] == [
        10,
        10,
        5,
        0,
    ]
    assert [response.body["offset"] for response in (first, middle, terminal, beyond)] == [
        0,
        20,
        45,
        60,
    ]
    assert invalid.status_code == 400
    assert invalid.body["type"] == "invalid_data"
    assert reset["provider_state"] == {
        "protocol": "gate_config_v1",
        "shadow_state": {"mcp_tool_calls": [], "writes": []},
    }
    assert repeated.body == first.body


def test_oci_release_binds_the_exact_admission() -> None:
    release = load_provider_release(ENV / "provider-release")

    assert release.provider_id == "medusa"
    assert release.release_version == "2.16.0-pagination-v0"
    assert release.config["distribution_label"] == "public"
    assert release.config["operation_coverage"] == {
        "behaviors": {
            "async": 0,
            "duplicate": 1,
            "failure": 1,
            "pagination": 1,
            "readback": 0,
            "success": 1,
        },
        "read": 1,
        "total": 1,
        "write": 0,
    }
    assert release.profiles[0].provider_admission_sha256 == _sha256(ENV / "provider-admission.json")
