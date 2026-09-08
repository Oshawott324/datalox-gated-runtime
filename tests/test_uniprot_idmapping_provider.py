from __future__ import annotations

import hashlib
import importlib.util
import json
from email.message import Message
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    load_provider_admission,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.release import load_provider_release
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "envs" / "uniprot_idmapping_v0"
AUTHORITY = "rest.uniprot.org"


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class _FakeResponse:
    def __init__(self, *, status: int, headers: Message, body: bytes) -> None:
        self.status = status
        self.headers = headers
        self._body = body

    def __enter__(self):
        return self

    def __exit__(self, *_args: object) -> None:
        return None

    def read(self) -> bytes:
        return self._body


class _FakeOpener:
    def __init__(self, response: _FakeResponse) -> None:
        self._response = response

    def open(self, _request: object, timeout: int):
        assert timeout == 30
        return self._response


def _request(
    method: str,
    path: str,
    *,
    body: object = None,
    query: dict[str, str] | None = None,
) -> CallRequest:
    return CallRequest(
        method=method,
        path=path,
        scheme="https",
        authority=AUTHORITY,
        headers=({"content-type": "application/x-www-form-urlencoded"} if method == "POST" else {}),
        body=body,
        query=query or {},
    )


def _submit(runtime: ProviderRuntime, *, identifier: str = "DATALOX_INPUT_A"):
    return runtime.handle(
        _request(
            "POST",
            "/idmapping/run",
            body={"from": "UniProtKB_AC-ID", "to": "UniRef100", "ids": identifier},
        )
    )


def test_source_runtime_admission_and_release_are_bound() -> None:
    source = validate_world_bundle(ENV / "source-world")
    runtime = load_provider_runtime_bundle(ENV / "provider-runtime")
    admission = load_provider_admission(ENV / "provider-admission.json")
    release = load_provider_release(ENV / "provider-release")

    assert source.manifest.bundle_version == "2026_03-idmapping-v0"
    assert runtime.manifest.authorities == (AUTHORITY,)
    assert set(runtime.manifest.behavior.required_runtime_capabilities) >= {
        "clock",
        "scheduled_events",
    }
    assert admission["provider_id"] == "uniprot"
    assert release.release_version == "2026_03-idmapping-v0"
    assert release.config["operation_coverage"] == {
        "total": 3,
        "read": 2,
        "write": 1,
        "behaviors": {
            "async": 1,
            "duplicate": 1,
            "failure": 3,
            "pagination": 0,
            "readback": 1,
            "success": 3,
        },
    }
    seed = json.loads((ENV / "provider-runtime" / "seed.json").read_text())
    assert set(seed).isdisjoint({"task", "expected", "hidden"})


def test_status_failure_authoring_mode_retains_private_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authoring = _load_script(
        ROOT / "scripts" / "providers" / "acquire-uniprot-idmapping-lifecycle.py",
        "acquire_uniprot_idmapping_lifecycle",
    )
    headers = Message()
    headers["Date"] = "Wed, 02 Sep 2026 15:07:22 GMT"
    headers["Content-Type"] = "application/json"
    headers["X-UniProt-Release"] = "2026_03"
    headers["X-API-Deployment-Date"] = "02-September-2026"
    body = b'{"messages":["fixture"],"url":"fixture"}'
    monkeypatch.setattr(
        authoring,
        "_opener",
        lambda _proxy: _FakeOpener(_FakeResponse(status=404, headers=headers, body=body)),
    )
    receipt_dir = tmp_path / "private" / "status-404"
    out = tmp_path / "sanitized.json"

    assert (
        authoring.main(
            [
                "--status-failure-only",
                "--nonexistent-job-id",
                "datalox-test-nonexistent",
                "--private-receipt-dir",
                str(receipt_dir),
                "--out",
                str(out),
            ]
        )
        == 0
    )
    sanitized = json.loads(out.read_text())
    manifest_raw = (receipt_dir / "manifest.json").read_bytes()
    assert sanitized["observed_at"] == "2026-09-02T15:07:22Z"
    assert sanitized["response_facts"] == {
        "content_type": "application/json",
        "json_type": "object",
        "messages_type": "list",
        "top_level_keys": ["messages", "url"],
    }
    assert sanitized["private_source_receipt"]["manifest_sha256"] == (
        "sha256:" + hashlib.sha256(manifest_raw).hexdigest()
    )
    assert (receipt_dir / "response.body").read_bytes() == body
    assert b"X-UniProt-Release: 2026_03" in (receipt_dir / "response.headers").read_bytes()


def test_status_failure_authoring_arguments_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authoring = _load_script(
        ROOT / "scripts" / "providers" / "acquire-uniprot-idmapping-lifecycle.py",
        "acquire_uniprot_idmapping_lifecycle_argument_gating",
    )
    monkeypatch.setattr(
        authoring,
        "_opener",
        lambda _proxy: pytest.fail("argument validation must precede network access"),
    )
    out = tmp_path / "sanitized.json"
    with pytest.raises(SystemExit):
        authoring.main(["--status-failure-only", "--out", str(out)])
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--status-failure-only",
                "--from-db",
                "UniProtKB_AC-ID",
                "--private-receipt-dir",
                str(tmp_path / "private"),
                "--out",
                str(out),
            ]
        )
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--status-failure-only",
                "--nonexistent-job-id",
                "contains/slash",
                "--private-receipt-dir",
                str(tmp_path / "private-path-segment"),
                "--out",
                str(out),
            ]
        )
    symlink = tmp_path / "private-symlink"
    symlink.symlink_to(ROOT)
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--status-failure-only",
                "--private-receipt-dir",
                str(symlink),
                "--out",
                str(out),
            ]
        )
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--status-failure-only",
                "--private-receipt-dir",
                str(symlink / "new-private-receipt"),
                "--out",
                str(out),
            ]
        )
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--execute-public-production-job",
                "--out",
                str(out),
            ]
        )
    with pytest.raises(SystemExit):
        authoring.main(
            [
                "--status-failure-only",
                "--private-receipt-dir",
                str(ROOT / "private-receipt-forbidden"),
                "--out",
                str(out),
            ]
        )


def test_status_failure_authoring_keeps_failed_private_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    authoring = _load_script(
        ROOT / "scripts" / "providers" / "acquire-uniprot-idmapping-lifecycle.py",
        "acquire_uniprot_idmapping_lifecycle_failed_receipt",
    )
    headers = Message()
    headers["Date"] = "Wed, 02 Sep 2026 15:07:22 GMT"
    headers["Content-Type"] = "text/plain"
    monkeypatch.setattr(
        authoring,
        "_opener",
        lambda _proxy: _FakeOpener(_FakeResponse(status=500, headers=headers, body=b"unexpected")),
    )
    receipt_dir = tmp_path / "failed-private-receipt"
    with pytest.raises(RuntimeError, match="unexpected_status"):
        authoring.main(
            [
                "--status-failure-only",
                "--private-receipt-dir",
                str(receipt_dir),
                "--out",
                str(tmp_path / "must-not-exist.json"),
            ]
        )
    manifest = json.loads((receipt_dir / "manifest.json").read_text())
    assert manifest["validation"] == {
        "error_code": "unexpected_status",
        "expected_json_shape": {
            "json_type": "object",
            "messages_type": "list",
            "top_level_keys": ["messages", "url"],
        },
        "expected_status_code": 404,
        "status": "failed",
    }
    assert (receipt_dir / "response.body").read_bytes() == b"unexpected"


def test_uniref_result_failure_authoring_is_read_only_and_receipted(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    support = _load_script(
        ROOT / "scripts" / "providers" / "acquire-uniprot-idmapping-lifecycle.py",
        "uniprot_lifecycle_support_for_uniref_failure",
    )
    acquisition = _load_script(
        ROOT / "scripts" / "providers" / "acquire-uniprot-idmapping-uniref-result-failure.py",
        "acquire_uniprot_uniref_result_failure",
    )
    headers = Message()
    headers["Date"] = "Wed, 02 Sep 2026 15:40:00 GMT"
    headers["Content-Type"] = "application/json"
    headers["X-UniProt-Release"] = "2026_03"
    headers["X-API-Deployment-Date"] = "02-September-2026"
    body = b'{"messages":["fixture"],"url":"fixture"}'
    monkeypatch.setattr(
        support,
        "_opener",
        lambda _proxy: _FakeOpener(_FakeResponse(status=404, headers=headers, body=body)),
    )
    receipt_dir = tmp_path / "uniref-result-404"
    result = acquisition.acquire(
        nonexistent_job_id="datalox-test-uniref-unknown",
        proxy=None,
        private_receipt_dir=receipt_dir,
        authoring=support,
    )
    manifest = json.loads((receipt_dir / "manifest.json").read_text())
    assert manifest["request"] == {
        "body_present": False,
        "credentials_present": False,
        "method": "GET",
        "path": "/idmapping/uniref/results/datalox-test-uniref-unknown",
        "path_template": "/idmapping/uniref/results/{unknown_job_id}",
        "query": {"format": "json", "size": "1"},
    }
    assert result["status_code"] == 404
    assert result["response_facts"]["top_level_keys"] == ["messages", "url"]
    assert result["private_source_receipt"]["manifest_sha256"] == (
        "sha256:" + hashlib.sha256((receipt_dir / "manifest.json").read_bytes()).hexdigest()
    )
    with pytest.raises(ValueError, match="path segment"):
        acquisition.acquire(
            nonexistent_job_id="contains/slash",
            proxy=None,
            private_receipt_dir=tmp_path / "must-not-exist",
            authoring=support,
        )
    with pytest.raises(SystemExit):
        acquisition.main(
            [
                "--private-receipt-dir",
                str(tmp_path / "cli-private"),
                "--out",
                str(tmp_path / "cli-public.json"),
            ]
        )


def test_grounded_async_lifecycle_and_stable_same_target(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=tmp_path / "run",
    )
    try:
        submitted = _submit(runtime)
        job_id = submitted.body["jobId"]
        after_submit = runtime.behavior_state_sha256()

        pending = runtime.handle(_request("GET", f"/idmapping/status/{job_id}"))
        assert pending.body == {"jobStatus": "RUNNING"}
        assert runtime.behavior_state_sha256() == after_submit

        unknown_result = runtime.handle(
            _request(
                "GET",
                "/idmapping/uniref/results/datalox-nonexistent-uniref-20260902",
                query={"format": "json", "size": "1"},
            )
        )
        assert unknown_result.status_code == 404
        assert sorted(unknown_result.body) == ["messages", "url"]

        advanced = runtime.advance_provider_time("2026-09-02T00:01:00Z")
        assert advanced["delivered_events"] == [
            {
                "event_id": f"complete:{job_id}",
                "deliver_at": "2026-09-02T00:01:00+00:00",
                "kind": "uniprot_idmapping_job_complete",
            }
        ]
        assert all("payload" not in event for event in advanced["delivered_events"])
        before_repeat = runtime.export()["provider_state"]
        repeated = runtime.advance_provider_time("2026-09-02T00:01:00Z")
        assert repeated["delivered_events"] == []
        assert runtime.export()["provider_state"] == before_repeat

        terminal = runtime.handle(_request("GET", f"/idmapping/status/{job_id}"))
        results = runtime.handle(
            _request(
                "GET",
                f"/idmapping/uniref/results/{job_id}",
                query={"format": "json", "size": "1"},
            )
        )
        assert terminal.status_code == 303
        assert terminal.headers["location"].endswith(f"/idmapping/uniref/results/{job_id}")
        assert set(results.body) == {"results"}
        assert results.body["results"][0]["from"] == "DATALOX_INPUT_A"
        assert set(results.body["results"][0]["to"]) == {
            "commonTaxon",
            "entryType",
            "id",
            "memberCount",
            "memberIdTypes",
            "members",
            "name",
            "organismCount",
            "organisms",
            "representativeMember",
            "seedId",
            "updated",
        }
    finally:
        runtime.close()


def test_unknown_status_matches_fresh_sanitized_error_shape(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=tmp_path / "run",
    )
    try:
        response = runtime.handle(_request("GET", "/idmapping/status/datalox-nonexistent-20260902"))
    finally:
        runtime.close()
    assert response.status_code == 404
    assert sorted(response.body) == ["messages", "url"]
    assert isinstance(response.body["messages"], list)


def test_pending_schedule_survives_close_and_resume(tmp_path: Path) -> None:
    run_dir = tmp_path / "run"
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=run_dir,
    )
    job_id = _submit(runtime).body["jobId"]
    runtime.close()

    resumed = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=run_dir,
        lifecycle="resume",
    )
    try:
        assert resumed.handle(_request("GET", f"/idmapping/status/{job_id}")).body == {
            "jobStatus": "RUNNING"
        }
        advanced = resumed.advance_provider_time("2026-09-02T00:01:00Z")
        assert len(advanced["delivered_events"]) == 1
        assert resumed.handle(_request("GET", f"/idmapping/status/{job_id}")).status_code == 303
    finally:
        resumed.close()


def test_two_runtimes_are_isolated_and_reset_clears_time_jobs_events(tmp_path: Path) -> None:
    runtimes = [
        ProviderRuntime(
            bundle_dir=ENV / "provider-runtime",
            admission_path=ENV / "provider-admission.json",
            run_dir=tmp_path / f"run-{index}",
        )
        for index in range(2)
    ]
    try:
        first_id = _submit(runtimes[0]).body["jobId"]
        second_id = _submit(runtimes[1], identifier="DATALOX_INPUT_B").body["jobId"]
        assert first_id == second_id == "datalox_job_000001"
        runtimes[0].advance_provider_time("2026-09-02T00:01:00Z")
        assert (
            runtimes[0].handle(_request("GET", f"/idmapping/status/{first_id}")).status_code == 303
        )
        assert runtimes[1].handle(_request("GET", f"/idmapping/status/{second_id}")).body == {
            "jobStatus": "RUNNING"
        }
        reset = runtimes[0].reset()["provider_state"]
        assert reset["simulation_time"] == "2026-09-02T00:00:00+00:00"
        assert reset["state"]["jobs"] == {}
        assert reset["scheduled_events"] == []
    finally:
        for runtime in runtimes:
            runtime.close()


def test_reverse_time_and_controller_auth_fail_safely(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=tmp_path / "direct",
    )
    try:
        with pytest.raises(ProviderRuntimeError) as caught:
            runtime.advance_provider_time("2026-09-01T23:59:59Z")
        assert caught.value.code == "world_clock_reverse_forbidden"
    finally:
        runtime.close()

    gateway = InterceptionGateway.from_admitted_bundles(
        bundle_admissions=((ENV / "provider-runtime", ENV / "provider-admission.json"),),
        run_root=tmp_path / "gateway",
        control_token="trusted-controller",
    )
    try:
        with TestClient(gateway.control_app) as controller:
            assert controller.get("/v1/providers/uniprot/time").status_code == 401
            authorized = controller.get(
                "/v1/providers/uniprot/time",
                headers={"x-datalox-control-token": "trusted-controller"},
            )
            assert authorized.json()["current_time"] == "2026-09-02T00:00:00+00:00"
        with TestClient(gateway.data_app) as agent:
            response = agent.get(
                "/v1/providers/uniprot/time",
                headers={"host": AUTHORITY},
            )
            assert response.status_code != 200
    finally:
        gateway.close()


def test_differential_executes_observed_relations_twice_across_reset() -> None:
    checker = _load_script(
        ROOT / "scripts" / "providers" / "check-uniprot-idmapping-lifecycle.py",
        "check_uniprot_idmapping_lifecycle",
    )
    restricted = ENV / "evidence" / "restricted"
    report = checker.check(ENV) if restricted.is_dir() else checker.validate_public_report(ENV)
    assert report["status"] == "passed"
    assert report["cycles"] == 2
    assert report["grounded_observation_count"] == 6
    assert report["first_cycle_sha256"] == report["second_cycle_sha256"]
    assert report["provider_wall_clock_claimed"] is False
    assert report["provider_reset_claimed"] is False
    assert report == json.loads(
        (ENV / "evidence" / "differential-report.json").read_text(encoding="utf-8")
    )


def test_builder_reproduces_every_committed_provider_artifact(tmp_path: Path) -> None:
    builder = _load_script(
        ROOT / "scripts" / "providers" / "build-uniprot-idmapping-release.py",
        "build_uniprot_idmapping_release",
    )
    rebuilt = tmp_path / "rebuilt"
    report = builder.build(ENV, rebuilt)
    assert (
        report["admission_sha256"]
        == "sha256:bf79f386ffcbe48f655cf8fb379be4b73a6ba9535b7892671caa9892d4005244"
    )
    assert (
        report["release_manifest_digest"]
        == "sha256:ae4abfe5b99a2bc659e25699b184a9f8df3aa8e24ecdfe5f1d6b32aceffa2147"
    )

    def files(root: Path) -> list[Path]:
        return sorted(
            path.relative_to(root)
            for path in root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and "restricted" not in path.parts
            and path.suffix != ".pyc"
        )

    assert files(rebuilt) == files(ENV)
    assert not (rebuilt / "evidence" / "restricted").exists()
    for relative in files(ENV):
        assert (rebuilt / relative).read_bytes() == (ENV / relative).read_bytes(), relative
