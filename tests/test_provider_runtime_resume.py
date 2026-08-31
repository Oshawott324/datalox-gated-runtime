from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    build_stateful_provider_bundle,
    write_replay_provider_config,
)
from test_provider_admission import _claims

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    ProviderRuntimeError,
    admit_provider_runtime,
    build_provider_runtime_from_gate_config,
)


def _admitted(
    tmp_path: Path,
    *,
    name: str = "provider-admission.json",
    admitted_at: datetime = datetime(2026, 8, 25, tzinfo=UTC),
) -> tuple[Path, Path]:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    admission = tmp_path / name
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=_claims(tmp_path),
        output_path=admission,
        admitted_at=admitted_at,
    )
    return bundle, admission


def _increment(runtime: ProviderRuntime, amount: int) -> None:
    response = runtime.handle(
        CallRequest(
            method="POST",
            authority=PROVIDER_AUTHORITY,
            path="/counter",
            body={"amount": amount},
        )
    )
    assert response.status_code == 200


def test_resume_preserves_world_state_and_extends_existing_ledger(tmp_path: Path) -> None:
    bundle, admission = _admitted(tmp_path)
    run_dir = tmp_path / "run"
    created = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=run_dir,
    )
    try:
        _increment(created, 2)
        before_close = created.export()
        assert before_close["provider_state"]["state"]["counter"] == 3
        assert len(before_close["call_evidence"]["events"]) == 1
    finally:
        created.close()

    resumed = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=admission,
        run_dir=run_dir,
        lifecycle="resume",
    )
    try:
        after_resume = resumed.export()
        assert after_resume["provider_state"] == before_close["provider_state"]
        assert after_resume["call_evidence"] == before_close["call_evidence"]

        read = resumed.handle(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/counter",
            )
        )
        assert read.status_code == 200
        assert read.body["counter"] == 3
        extended = resumed.export()
        assert len(extended["call_evidence"]["events"]) == 2
        assert extended["call_evidence"]["events"][0] == before_close["call_evidence"]["events"][0]
    finally:
        resumed.close()


def test_resume_preserves_gate_config_ledger_and_shadow_state(tmp_path: Path) -> None:
    bundle = tmp_path / "replay-provider"
    build_provider_runtime_from_gate_config(
        source_gate_config=write_replay_provider_config(tmp_path),
        output_dir=bundle,
        provider_id="replay_provider",
        authorities=(PROVIDER_AUTHORITY,),
    )
    run_dir = tmp_path / "run"
    created = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    try:
        created.handle(CallRequest(method="GET", authority=PROVIDER_AUTHORITY, path="/v1/records"))
        before_close = created.export()
    finally:
        created.close()

    resumed = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir, lifecycle="resume")
    try:
        assert resumed.export()["call_evidence"] == before_close["call_evidence"]
        resumed.handle(CallRequest(method="POST", authority=PROVIDER_AUTHORITY, path="/v1/records"))
        assert len(resumed.export()["call_evidence"]["events"]) == 2
    finally:
        resumed.close()


def test_create_rejects_existing_run_directory(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    runtime.close()

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)

    assert caught.value.code == "provider_runtime_run_exists"


def test_resume_rejects_missing_run_directory(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=bundle,
            run_dir=tmp_path / "missing-run",
            lifecycle="resume",
        )

    assert caught.value.code == "provider_runtime_run_missing"


def test_resume_rejects_tampered_run_metadata(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    runtime.close()
    metadata_path = run_dir / "provider-run.json"
    metadata = json.loads(metadata_path.read_text(encoding="utf-8"))
    metadata["provider_runtime_sha256"] = "sha256:" + "0" * 64
    metadata_path.write_text(json.dumps(metadata), encoding="utf-8")

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(bundle_dir=bundle, run_dir=run_dir, lifecycle="resume")

    assert caught.value.code == "provider_runtime_run_binding_mismatch"


def test_resume_rejects_different_admission_binding(tmp_path: Path) -> None:
    bundle, first_admission = _admitted(tmp_path)
    second_admission = tmp_path / "second-admission.json"
    claims = _claims(tmp_path)
    claims.write_text(claims.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims,
        output_path=second_admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(
        bundle_dir=bundle,
        admission_path=first_admission,
        run_dir=run_dir,
    )
    runtime.close()

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=bundle,
            admission_path=second_admission,
            run_dir=run_dir,
            lifecycle="resume",
        )

    assert caught.value.code == "provider_runtime_run_binding_mismatch"
    assert "provider_admission_sha256" in caught.value.details["mismatches"]


def test_resume_rejects_different_provider_runtime_binding(tmp_path: Path) -> None:
    first_bundle = build_stateful_provider_bundle(tmp_path / "first-bundle-root")
    second_bundle = build_stateful_provider_bundle(
        tmp_path / "second-bundle-root",
        authority="different.provider.example",
    )
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=first_bundle, run_dir=run_dir)
    runtime.close()

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(
            bundle_dir=second_bundle,
            run_dir=run_dir,
            lifecycle="resume",
        )

    assert caught.value.code == "provider_runtime_run_binding_mismatch"
    assert "provider_runtime_sha256" in caught.value.details["mismatches"]


@pytest.mark.parametrize(
    ("artifact", "code"),
    [
        ("provider-state.sqlite3", "provider_runtime_run_state_missing"),
        ("ledger.jsonl", "provider_runtime_run_ledger_missing"),
    ],
)
def test_resume_requires_complete_run_artifacts(
    tmp_path: Path,
    artifact: str,
    code: str,
) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    runtime.close()
    (run_dir / artifact).unlink()

    with pytest.raises(ProviderRuntimeError) as caught:
        ProviderRuntime(bundle_dir=bundle, run_dir=run_dir, lifecycle="resume")

    assert caught.value.code == code


def test_reset_remains_resumable_with_an_empty_ledger(tmp_path: Path) -> None:
    bundle = build_stateful_provider_bundle(tmp_path / "bundle-root")
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir)
    try:
        _increment(runtime, 4)
        reset_export = runtime.reset()
        assert reset_export["call_evidence"]["events"] == []
    finally:
        runtime.close()

    resumed = ProviderRuntime(bundle_dir=bundle, run_dir=run_dir, lifecycle="resume")
    try:
        assert resumed.export()["provider_state"] == reset_export["provider_state"]
        assert resumed.export()["call_evidence"]["events"] == []
    finally:
        resumed.close()
