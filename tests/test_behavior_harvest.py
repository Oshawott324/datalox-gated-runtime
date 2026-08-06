from __future__ import annotations

import base64
import hashlib
import inspect
import json
from dataclasses import replace
from pathlib import Path
from typing import Any
from urllib.parse import urlencode

import pytest

import datalox_gated_runtime.behavior_harvest as harvest
import datalox_gated_runtime.behavior_harvest.runner as runner
from datalox_gated_runtime.behavior_harvest import (
    AssertionSpec,
    AuthContext,
    AuthGrantSpec,
    AuthProfile,
    AuthResponseFieldSpec,
    AuthoringPolicy,
    BehaviorContractError,
    BehaviorHarvestError,
    BehaviorHarvester,
    BehaviorRecipe,
    BehaviorStep,
    BindingSpec,
    BoundarySpec,
    CollectorSpec,
    ClientBasicAuthSpec,
    CompiledBehaviorTrace,
    ConnectorSpec,
    EvidenceCallSpec,
    HarvestBounds,
    IdentityPreflight,
    IsolationResetSpec,
    LoadedCapture,
    LoadedConnector,
    ProgramRequirements,
    RawTransportResponse,
    RequestTemplate,
    SecretSource,
    SourcePin,
    StaticIdentityProjection,
    StaticJsonInputSpec,
    canonical_contract_digest,
    compile_reference_trace,
    current_engine_identity,
    load_capture,
    run_compiled_behavior_trace,
)
from datalox_gated_runtime.behavior_harvest.contracts import (
    canonical_json_bytes,
    sha256_digest,
)
from datalox_gated_runtime.reference import ObservedResponse, ReferenceCall


def _status(code: int, assertion_id: str) -> AssertionSpec:
    return AssertionSpec(
        assertion_id=assertion_id,
        kind="status_equals",
        expected=code,
    )


def _request(method: str, path: Any, body: Any = None) -> RequestTemplate:
    return RequestTemplate(
        method=method,
        path=path,
        query={},
        body=body,
        headers={},
    )


def _source_pin() -> SourcePin:
    return SourcePin(
        pin_id="provider_contract",
        source_ref="https://docs.example.test/api",
        version="2026-07-30",
        sha256="sha256:" + "1" * 64,
    )


_DEFAULT_SECRET = b"widget-test-token"


def _default_auth() -> AuthProfile:
    return AuthProfile(
        profile_id="bearer",
        kind="secret",
        secret_sources=(
            SecretSource(
                name="api_token",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64", "bearer"),
            ),
        ),
        contexts=(
            AuthContext(
                context_id="anonymous",
                strategy_id="bearer",
                secret_source_names=("api_token",),
                actor_alias="api_actor",
                grant_required=False,
                grant=None,
            ),
        ),
    )


def _preflight() -> IdentityPreflight:
    return IdentityPreflight(
        strategy_id="tenant_identity",
        expected_identity={"tenant": "sandbox"},
        calls=(
            EvidenceCallSpec(
                call_id="identity",
                strategy_id="tenant_identity",
                auth_context_id="anonymous",
                request=_request("GET", "/identity"),
                assertions=(
                    _status(200, "identity_status"),
                    AssertionSpec(
                        assertion_id="identity_tenant",
                        kind="json_pointer_equals",
                        pointer="/tenant",
                        expected="sandbox",
                    ),
                ),
            ),
        ),
        identity_call_id="identity",
        identity_pointer="",
        authenticated_context_ids=(),
        static_projections=(),
    )


def _collector() -> CollectorSpec:
    return CollectorSpec(
        collector_id="events",
        kind="event",
        required=True,
        call=EvidenceCallSpec(
            call_id="events",
            strategy_id="event_collection",
            auth_context_id="anonymous",
            request=_request("GET", "/events"),
            assertions=(
                _status(200, "event_status"),
                AssertionSpec(
                    assertion_id="event_complete",
                    kind="json_pointer_equals",
                    pointer="/complete",
                    expected=True,
                ),
            ),
        ),
    )


def _connector(
    *,
    auth: AuthProfile | None = None,
    preflight: IdentityPreflight | None = None,
    collectors: tuple[CollectorSpec, ...] | None = None,
    max_requests: int = 8,
) -> ConnectorSpec:
    engine = current_engine_identity()
    return ConnectorSpec(
        connector_id="widget_sandbox",
        provider_id="widget",
        provider_version="v1",
        origin="https://sandbox.example.test",
        driver_kind="http",
        driver_id=engine.engine_id,
        driver_version=engine.engine_version,
        driver_source_sha256=engine.source_sha256,
        request_encoding="canonical_json",
        allowed_request_headers=(),
        boundary=BoundarySpec(
            kind="managed_sandbox",
            production_equivalence="limited",
            statement="A dedicated writable test tenant.",
        ),
        auth=auth or _default_auth(),
        identity_preflight=preflight or _preflight(),
        isolation=IsolationResetSpec(
            isolation_kind="run_scoped_resources",
            cleanup_kind="delete_run_resources",
            cleanup_strategy_id="delete_run",
            reset_kind="none",
            reset_strategy_id=None,
            reset_equivalence_claimed=False,
        ),
        authoring_policy=AuthoringPolicy(concurrency=1, write_retries=0),
        static_json_inputs=(),
        source_pins=(_source_pin(),),
        collectors=(_collector(),) if collectors is None else collectors,
        known_limitations=("Only the declared workflow is harvested.",),
        bounds=HarvestBounds(
            max_requests=max_requests,
            max_request_bytes=16384,
            max_response_bytes=16384,
            max_total_response_bytes=131072,
            max_polls=0,
            request_timeout_ms=5000,
            min_request_interval_ms=0,
        ),
    )


def _recipe(
    *,
    duplicate_outcome: str = "idempotent_success",
    resulting_outcome: str = "read_success",
) -> BehaviorRecipe:
    duplicate_assertions: tuple[AssertionSpec, ...] = (
        AssertionSpec(
            assertion_id="duplicate_exact_request",
            kind="request_equals_step",
            prior_step_id="activate",
        ),
    )
    if duplicate_outcome != "observe":
        duplicate_assertions += (
            _status(200, "duplicate_status"),
            AssertionSpec(
                assertion_id="duplicate_exact_response",
                kind="response_equals_step",
                prior_step_id="activate",
            ),
        )
    if resulting_outcome == "observe":
        resulting_assertions: tuple[AssertionSpec, ...] = (
            AssertionSpec(
                assertion_id="state_observed",
                kind="state_observe_step",
                pointer="/state",
                prior_step_id="before",
                prior_pointer="/state",
            ),
        )
    else:
        resulting_assertions = (
            _status(200, "result_status"),
            AssertionSpec(
                assertion_id="state_changed",
                kind="state_changes_from_step",
                pointer="/state",
                prior_step_id="before",
                prior_pointer="/state",
            ),
        )
    return BehaviorRecipe(
        program_id="widget_transition",
        seed=7,
        requirements=ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            BehaviorStep(
                step_id="before",
                operation_id="get_widget",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="widget_under_test",
                auth_context_id="anonymous",
                request=_request("GET", "/widgets/fixed"),
                bindings=(BindingSpec("widget_id", "/id", "string"),),
                assertions=(
                    _status(200, "before_status"),
                    AssertionSpec(
                        assertion_id="before_state",
                        kind="json_pointer_equals",
                        pointer="/state",
                        expected="new",
                    ),
                ),
            ),
            BehaviorStep(
                step_id="activate",
                operation_id="activate_widget",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="widget_under_test",
                auth_context_id="anonymous",
                request=_request(
                    "POST",
                    ("/widgets/", {"$binding": "widget_id"}, "/activate"),
                    {"action": "activate"},
                ),
                assertions=(
                    _status(200, "activate_status"),
                    AssertionSpec(
                        assertion_id="active_state",
                        kind="json_pointer_equals",
                        pointer="/state",
                        expected="active",
                    ),
                ),
            ),
            BehaviorStep(
                step_id="duplicate",
                operation_id="activate_widget",
                kind="mutation",
                role="duplicate",
                expected_outcome=duplicate_outcome,
                subject_id="widget_under_test",
                auth_context_id="anonymous",
                request=_request(
                    "POST",
                    ("/widgets/", {"$binding": "widget_id"}, "/activate"),
                    {"action": "activate"},
                ),
                assertions=duplicate_assertions,
            ),
            BehaviorStep(
                step_id="native_failure",
                operation_id="invalid_widget_transition",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="widget_under_test",
                auth_context_id="anonymous",
                request=_request(
                    "POST",
                    ("/widgets/", {"$binding": "widget_id"}, "/invalid"),
                    {"action": "invalid"},
                ),
                assertions=(
                    _status(409, "failure_status"),
                    AssertionSpec(
                        assertion_id="failure_code",
                        kind="json_pointer_equals",
                        pointer="/error",
                        expected="invalid_transition",
                    ),
                ),
            ),
            BehaviorStep(
                step_id="resulting_state",
                operation_id="get_widget",
                kind="read",
                role="resulting_state",
                expected_outcome=resulting_outcome,
                subject_id="widget_under_test",
                auth_context_id="anonymous",
                request=_request(
                    "GET",
                    ("/widgets/", {"$binding": "widget_id"}),
                ),
                assertions=resulting_assertions,
            ),
        ),
    )


class _FakeProvider:
    def __init__(
        self,
        *,
        activate_status: int = 200,
        duplicate_status: int = 200,
        invalid_activate_json: bool = False,
        identity: str = "sandbox",
        collector_status: int = 200,
        leak: str | None = None,
    ) -> None:
        self.calls: list[dict[str, Any]] = []
        self.state = "new"
        self.activate_status = activate_status
        self.duplicate_status = duplicate_status
        self.invalid_activate_json = invalid_activate_json
        self.identity = identity
        self.collector_status = collector_status
        self.leak = leak

    def exchange(self, **kwargs: Any) -> RawTransportResponse:
        self.calls.append(kwargs)
        target = kwargs["target"]
        method = kwargs["method"]
        if target == "/identity":
            return _json_response(200, {"tenant": self.identity})
        if target == "/events":
            return _json_response(
                self.collector_status,
                {"complete": self.collector_status == 200},
            )
        if target.startswith("/support/"):
            return _json_response(200, {"observed": target})
        if method == "GET" and target == "/widgets/fixed":
            body = {"id": "wid_001", "state": self.state}
            if self.leak is not None:
                body["leak"] = self.leak
            return _json_response(200, body)
        if target == "/widgets/wid_001/activate":
            self.state = "active"
            activation_count = len([item for item in self.calls if item["target"] == target])
            if self.invalid_activate_json:
                return RawTransportResponse(
                    status_code=200,
                    headers={"content-type": "application/json"},
                    body_bytes=b"{",
                )
            status = self.duplicate_status if activation_count > 1 else self.activate_status
            if status in {204, 205}:
                return RawTransportResponse(
                    status_code=status,
                    headers={},
                    body_kind="empty",
                    body_bytes=b"",
                )
            return _json_response(
                status,
                {"id": "wid_001", "state": "active"},
            )
        if target == "/widgets/wid_001/invalid":
            return _json_response(409, {"error": "invalid_transition"})
        if method == "GET" and target == "/widgets/wid_001":
            return _json_response(200, {"id": "wid_001", "state": self.state})
        raise AssertionError(f"unexpected provider call: {method} {target}")


def _json_response(status: int, value: Any) -> RawTransportResponse:
    return RawTransportResponse(
        status_code=status,
        headers={"content-type": "application/json"},
        body_bytes=canonical_json_bytes(value),
    )


def _write_contract(path: Path, value: Any) -> str:
    payload = canonical_json_bytes(value.to_dict()) + b"\n"
    path.write_bytes(payload)
    return sha256_digest(payload)


def _run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    provider: _FakeProvider | None = None,
    connector: ConnectorSpec | None = None,
    recipe: BehaviorRecipe | None = None,
    sensitive_values: dict[str, bytes] | None = None,
    static_input_paths: dict[str, Path] | None = None,
    expected_static_input_sha256: dict[str, str] | None = None,
) -> tuple[Any, Path, Path]:
    connector = connector or _connector()
    recipe = recipe or _recipe()
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, recipe)
    provider = provider or _FakeProvider()
    monkeypatch.setattr(
        runner._EngineHttp11Executor,
        "exchange",
        lambda self, **kwargs: provider.exchange(**kwargs),
    )
    output = tmp_path / "capture.json"
    result = BehaviorHarvester().run(
        connector_path=connector_path,
        recipe_path=recipe_path,
        expected_connector_sha256=connector_sha,
        expected_recipe_sha256=recipe_sha,
        expected_engine=current_engine_identity(),
        run_id="run_001",
        output_path=output,
        sensitive_values=(
            sensitive_values
            if sensitive_values is not None
            else {source.name: _DEFAULT_SECRET for source in connector.auth.secret_sources}
        ),
        static_input_paths=static_input_paths or {},
        expected_static_input_sha256=expected_static_input_sha256 or {},
        execute_sandbox_writes=True,
    )
    return result, connector_path, recipe_path


def _static_connector() -> tuple[ConnectorSpec, dict[str, Any]]:
    values = {
        "release": {
            "distribution": "OpenLMIS reference distribution",
            "version": "3.17.0",
        },
        "docker": {
            "images": {
                "requisition": "sha256:" + "a" * 64,
                "reference-data": "sha256:" + "b" * 64,
            }
        },
    }
    connector = _connector()
    preflight = replace(
        connector.identity_preflight,
        expected_identity={
            "tenant": "sandbox",
            "release": values["release"],
            "docker": values["docker"],
        },
        static_projections=(
            StaticIdentityProjection(
                output_key="release",
                input_id="release",
                pointer="",
            ),
            StaticIdentityProjection(
                output_key="docker",
                input_id="docker",
                pointer="",
            ),
        ),
    )
    connector = replace(
        connector,
        identity_preflight=preflight,
        static_json_inputs=(
            StaticJsonInputSpec(
                input_id="release",
                schema_id="openlmis_release_v1",
                max_bytes=4096,
                expected_json=values["release"],
            ),
            StaticJsonInputSpec(
                input_id="docker",
                schema_id="openlmis_docker_v1",
                max_bytes=4096,
                expected_json=values["docker"],
            ),
        ),
    )
    return connector, values


def _write_static_inputs(
    tmp_path: Path,
    values: dict[str, Any],
) -> tuple[dict[str, Path], dict[str, str]]:
    paths: dict[str, Path] = {}
    digests: dict[str, str] = {}
    for input_id, value in values.items():
        path = tmp_path / f"{input_id}.json"
        payload = canonical_json_bytes(value) + b"\n"
        path.write_bytes(payload)
        paths[input_id] = path
        digests[input_id] = sha256_digest(payload)
    return paths, digests


def test_closed_engine_harvests_and_revalidates_complete_capture(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider()
    result, connector_path, recipe_path = _run(
        tmp_path,
        monkeypatch,
        provider=provider,
    )

    assert len(provider.calls) == 7
    assert result.capture.complete is True
    assert result.capture.bindings["widget_id"] == "wid_001"
    loaded = load_capture(
        result.artifact_path,
        expected_sha256=result.artifact_sha256,
        connector_path=connector_path,
        expected_connector_sha256=result.capture.connector_sha256,
        recipe_path=recipe_path,
        expected_recipe_sha256=result.capture.recipe_sha256,
        expected_engine=current_engine_identity(),
        sensitive_values={"api_token": _DEFAULT_SECRET},
        static_input_paths={},
        expected_static_input_sha256={},
    )
    assert loaded.value == result.capture


def test_static_release_and_docker_identity_are_exact_and_not_http_counted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    provider = _FakeProvider()
    result, connector_path, recipe_path = _run(
        tmp_path,
        monkeypatch,
        provider=provider,
        connector=connector,
        static_input_paths=paths,
        expected_static_input_sha256=digests,
    )
    assert len(provider.calls) == 7
    assert [item.input_id for item in result.capture.static_input_receipts] == [
        "release",
        "docker",
    ]
    loaded = load_capture(
        result.artifact_path,
        expected_sha256=result.artifact_sha256,
        connector_path=connector_path,
        expected_connector_sha256=result.capture.connector_sha256,
        recipe_path=recipe_path,
        expected_recipe_sha256=result.capture.recipe_sha256,
        expected_engine=current_engine_identity(),
        sensitive_values={"api_token": _DEFAULT_SECRET},
        static_input_paths=paths,
        expected_static_input_sha256=digests,
    )
    assert loaded.value.static_input_receipts == result.capture.static_input_receipts


def test_static_input_missing_fails_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    paths.pop("docker")
    provider = _FakeProvider()
    with pytest.raises(BehaviorContractError, match="exactly cover"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            static_input_paths=paths,
            expected_static_input_sha256=digests,
        )
    assert provider.calls == []


def test_static_input_symlink_fails_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    docker_target = paths["docker"]
    docker_link = tmp_path / "docker-link.json"
    docker_link.symlink_to(docker_target)
    paths["docker"] = docker_link
    provider = _FakeProvider()
    with pytest.raises(BehaviorContractError, match="opened safely"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            static_input_paths=paths,
            expected_static_input_sha256=digests,
        )
    assert provider.calls == []


def test_static_input_wrong_digest_or_body_fails_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    provider = _FakeProvider()
    wrong_digests = dict(digests)
    wrong_digests["release"] = "sha256:" + "0" * 64
    with pytest.raises(BehaviorContractError, match="expected exact SHA-256"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            static_input_paths=paths,
            expected_static_input_sha256=wrong_digests,
        )
    assert provider.calls == []

    wrong_release = {
        "distribution": "OpenLMIS reference distribution",
        "version": "9.99.0",
    }
    wrong_payload = canonical_json_bytes(wrong_release) + b"\n"
    paths["release"].write_bytes(wrong_payload)
    matching_digests = dict(digests)
    matching_digests["release"] = sha256_digest(wrong_payload)
    with pytest.raises(BehaviorContractError, match="expected_json"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            static_input_paths=paths,
            expected_static_input_sha256=matching_digests,
        )
    assert provider.calls == []


@pytest.mark.parametrize(
    ("payload", "message"),
    (
        (b'{"version":"3.17.0","version":"forged"}\n', "duplicate JSON key"),
        (b'{"version":NaN}\n', "non-finite"),
    ),
)
def test_static_input_rejects_duplicate_and_nonfinite_json_before_http(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    payload: bytes,
    message: str,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    paths["release"].write_bytes(payload)
    digests["release"] = sha256_digest(payload)
    provider = _FakeProvider()
    with pytest.raises(BehaviorContractError, match=message):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            static_input_paths=paths,
            expected_static_input_sha256=digests,
        )
    assert provider.calls == []


def test_static_input_cannot_be_declared_without_identity_reference() -> None:
    connector = _connector()
    with pytest.raises(BehaviorContractError, match="must be referenced"):
        replace(
            connector,
            static_json_inputs=(
                StaticJsonInputSpec(
                    input_id="release",
                    schema_id="openlmis_release_v1",
                    max_bytes=1024,
                    expected_json={"version": "3.17.0"},
                ),
            ),
        )


def test_load_capture_rejects_forged_static_receipt_body(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, values = _static_connector()
    paths, digests = _write_static_inputs(tmp_path, values)
    result, connector_path, recipe_path = _run(
        tmp_path,
        monkeypatch,
        connector=connector,
        static_input_paths=paths,
        expected_static_input_sha256=digests,
    )
    raw = json.loads(result.artifact_path.read_text())
    raw["static_input_receipts"][0]["body"]["version"] = "forged"
    tampered = tmp_path / "tampered-static.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(payload)
    with pytest.raises(BehaviorContractError):
        load_capture(
            tampered,
            expected_sha256=sha256_digest(payload),
            connector_path=connector_path,
            expected_connector_sha256=result.capture.connector_sha256,
            recipe_path=recipe_path,
            expected_recipe_sha256=result.capture.recipe_sha256,
            expected_engine=current_engine_identity(),
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths=paths,
            expected_static_input_sha256=digests,
        )


def test_no_execution_callback_api_and_single_use_permit() -> None:
    assert not hasattr(harvest, "AdapterRegistry")
    assert not hasattr(harvest, "SandboxAdapter")
    permit = runner._SingleUseExchangePermit(object())  # type: ignore[arg-type]
    permit._used = True
    with pytest.raises(BehaviorHarvestError, match="exactly once"):
        permit.execute()


def test_loaded_contract_provenance_and_run_rehash_are_fail_closed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector()
    with pytest.raises(BehaviorContractError, match="load_connector"):
        LoadedConnector(
            connector,
            canonical_contract_digest(connector),
            _provenance=object(),
        )
    with pytest.raises(BehaviorContractError, match="load_capture"):
        LoadedCapture(
            object(),  # type: ignore[arg-type]
            "sha256:" + "0" * 64,
            _provenance=object(),
        )
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, _recipe())
    connector_path.write_bytes(connector_path.read_bytes() + b" ")
    calls: list[Any] = []
    monkeypatch.setattr(
        runner._EngineHttp11Executor,
        "exchange",
        lambda self, **kwargs: calls.append(kwargs),
    )
    with pytest.raises(BehaviorContractError, match="expected exact SHA-256"):
        BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=connector_sha,
            expected_recipe_sha256=recipe_sha,
            expected_engine=current_engine_identity(),
            run_id="rehash",
            output_path=tmp_path / "capture.json",
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )
    assert calls == []


def test_engine_identity_mismatch_blocks_before_any_provider_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector()
    recipe = _recipe()
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, recipe)
    calls: list[Any] = []
    monkeypatch.setattr(
        runner._EngineHttp11Executor,
        "exchange",
        lambda self, **kwargs: calls.append(kwargs),
    )
    forged_engine = replace(
        current_engine_identity(),
        source_sha256="sha256:" + "0" * 64,
    )
    with pytest.raises(BehaviorHarvestError, match="engine"):
        BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=connector_sha,
            expected_recipe_sha256=recipe_sha,
            expected_engine=forged_engine,
            run_id="bad_engine",
            output_path=tmp_path / "capture.json",
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )
    assert calls == []


def test_preflight_is_engine_executed_and_blocks_program(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(identity="wrong")
    with pytest.raises(BehaviorHarvestError, match="identity"):
        _run(tmp_path, monkeypatch, provider=provider)
    assert [item["target"] for item in provider.calls] == ["/identity"]


def test_required_collector_failure_prevents_publication(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(collector_status=503)
    with pytest.raises(BehaviorHarvestError, match="assertion|must return 2xx"):
        _run(tmp_path, monkeypatch, provider=provider)
    assert not (tmp_path / "capture.json").exists()
    assert (tmp_path / "capture.json.partial.jsonl").exists()


def test_observation_steps_capture_unknown_provider_behavior(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(duplicate_status=409)
    result, _, _ = _run(
        tmp_path,
        monkeypatch,
        provider=provider,
        recipe=_recipe(
            duplicate_outcome="observe",
            resulting_outcome="observe",
        ),
    )
    assert result.capture.exchanges[2].status_code == 409
    assert result.capture.exchanges[-1].status_code == 200
    assert result.capture.observed_relations == {"resulting_state.state_observed": "changed"}


def test_observational_mutation_rejects_500_and_records_terminal_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(duplicate_status=500)
    with pytest.raises(BehaviorHarvestError, match="2xx read, or 4xx"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            recipe=_recipe(
                duplicate_outcome="observe",
                resulting_outcome="observe",
            ),
        )
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal


@pytest.mark.parametrize("status", (202, 206, 207))
def test_partial_or_async_success_mutation_is_terminal_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    provider = _FakeProvider(activate_status=status)
    with pytest.raises(BehaviorHarvestError, match="status|completion"):
        _run(tmp_path, monkeypatch, provider=provider)
    assert not (tmp_path / "capture.json").exists()
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal
    assert "/widgets/wid_001/invalid" not in [item["target"] for item in provider.calls]


@pytest.mark.parametrize("status", (202, 206, 207))
def test_partial_or_async_duplicate_observation_is_terminal_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    provider = _FakeProvider(duplicate_status=status)
    with pytest.raises(BehaviorHarvestError, match="status|completed"):
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            recipe=_recipe(
                duplicate_outcome="observe",
                resulting_outcome="observe",
            ),
        )
    assert not (tmp_path / "capture.json").exists()
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal


@pytest.mark.parametrize("status", (200, 201, 204, 205))
def test_completed_mutation_statuses_are_publishable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    status: int,
) -> None:
    recipe = _recipe(duplicate_outcome="observe")
    recipe = replace(
        recipe,
        steps=(
            recipe.steps[0],
            replace(
                recipe.steps[1],
                assertions=(_status(status, "activate_completed"),),
            ),
            *recipe.steps[2:],
        ),
    )
    result, _, _ = _run(
        tmp_path,
        monkeypatch,
        provider=_FakeProvider(
            activate_status=status,
            duplicate_status=409,
        ),
        recipe=recipe,
    )
    assert result.capture.exchanges[1].status_code == status
    assert result.artifact_path.exists()


@pytest.mark.parametrize("status", (202, 206, 207, 226))
def test_contract_rejects_noncompleted_mutation_success_statuses(
    status: int,
) -> None:
    recipe = _recipe()
    with pytest.raises(BehaviorContractError, match="200, 201, 204, or 205"):
        replace(
            recipe.steps[1],
            assertions=(_status(status, "partial_mutation"),),
        )
    with pytest.raises(BehaviorContractError, match="200, 201, 204, or 205"):
        BehaviorStep(
            step_id="supporting_partial",
            operation_id="supporting_mutation",
            kind="mutation",
            role="supporting",
            expected_outcome="mutation_success",
            subject_id="widget_under_test",
            auth_context_id="anonymous",
            request=_request("POST", "/supporting"),
            assertions=(_status(status, "supporting_partial_status"),),
        )


def test_non_observational_success_rejects_500_and_records_terminal_unknown(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(duplicate_status=500)
    with pytest.raises(BehaviorHarvestError, match="status|completion"):
        _run(tmp_path, monkeypatch, provider=provider)
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal
    assert "/widgets/wid_001/invalid" not in [item["target"] for item in provider.calls]


def test_invalid_json_after_mutation_is_terminal_unknown_and_halts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    provider = _FakeProvider(invalid_activate_json=True)
    with pytest.raises(BehaviorHarvestError) as caught:
        _run(tmp_path, monkeypatch, provider=provider)
    assert caught.value.code == "unknown_mutation_completion"
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal
    assert [item["target"] for item in provider.calls] == [
        "/identity",
        "/widgets/fixed",
        "/widgets/wid_001/activate",
    ]


def test_invalid_mutation_binding_is_terminal_unknown_and_halts(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recipe = _recipe()
    activate = replace(
        recipe.steps[1],
        bindings=(BindingSpec("missing_created_id", "/missing", "string"),),
    )
    recipe = replace(
        recipe,
        steps=(recipe.steps[0], activate, *recipe.steps[2:]),
    )
    provider = _FakeProvider()
    with pytest.raises(BehaviorHarvestError):
        _run(tmp_path, monkeypatch, provider=provider, recipe=recipe)
    journal = (tmp_path / "capture.json.partial.jsonl").read_text()
    assert '"state":"terminal_unknown"' in journal
    assert [item["target"] for item in provider.calls] == [
        "/identity",
        "/widgets/fixed",
        "/widgets/wid_001/activate",
    ]


def test_status_204_and_205_require_exact_empty_representation() -> None:
    for status in (204, 205):
        with pytest.raises(BehaviorContractError, match="exactly zero"):
            RawTransportResponse(
                status_code=status,
                headers={},
                body_kind="json",
                body_bytes=b"{}",
            )
        assert (
            RawTransportResponse(
                status_code=status,
                headers={},
                body_kind="empty",
                body_bytes=b"",
            ).body_bytes
            == b""
        )


def test_head_can_capture_exact_empty_non_204_response() -> None:
    assert (
        RawTransportResponse(
            status_code=200,
            headers={},
            body_kind="empty",
            body_bytes=b"",
        ).body_bytes
        == b""
    )


def test_auth_strategy_requires_all_leak_variants() -> None:
    source = SecretSource(
        name="api_token",
        kind="environment",
        scan_variants=("raw",),
    )
    with pytest.raises(BehaviorContractError, match="omits variants"):
        AuthProfile(
            profile_id="bad_bearer",
            kind="secret",
            secret_sources=(source,),
            contexts=(
                AuthContext(
                    context_id="actor",
                    strategy_id="bearer",
                    secret_source_names=("api_token",),
                    actor_alias="actor",
                    grant_required=False,
                ),
            ),
        )


def test_secret_strategy_variants_scan_provider_and_persisted_surfaces(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = b"top secret"
    auth = AuthProfile(
        profile_id="bearer",
        kind="secret",
        secret_sources=(
            SecretSource(
                name="api_token",
                kind="environment",
                scan_variants=("raw", "base64", "bearer", "urlencoded"),
            ),
        ),
        contexts=(
            AuthContext(
                context_id="anonymous",
                strategy_id="bearer",
                secret_source_names=("api_token",),
                actor_alias="api_actor",
                grant_required=False,
                grant=None,
            ),
        ),
    )
    connector = _connector(auth=auth)
    provider = _FakeProvider(
        leak=base64.b64encode(secret).decode("ascii"),
    )
    with pytest.raises(BehaviorHarvestError) as caught:
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            sensitive_values={"api_token": secret},
        )
    assert caught.value.code == "sensitive_value_detected"
    journal = (tmp_path / "capture.json.partial.jsonl").read_bytes()
    assert secret not in journal
    assert base64.b64encode(secret) not in journal


def test_load_capture_revalidates_external_contract_and_capture_semantics(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, connector_path, recipe_path = _run(tmp_path, monkeypatch)
    raw = json.loads(result.artifact_path.read_text())
    raw["exchanges"][1]["request"]["target"] = "/forged"
    tampered = tmp_path / "tampered.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(payload)
    with pytest.raises(BehaviorContractError):
        load_capture(
            tampered,
            expected_sha256=sha256_digest(payload),
            connector_path=connector_path,
            expected_connector_sha256=result.capture.connector_sha256,
            recipe_path=recipe_path,
            expected_recipe_sha256=result.capture.recipe_sha256,
            expected_engine=current_engine_identity(),
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )


@pytest.mark.parametrize(
    "mutator",
    (
        lambda raw: raw["bindings"].__setitem__("widget_id", "forged"),
        lambda raw: raw["collector_exchanges"].clear(),
        lambda raw: raw["exchanges"][1].__setitem__(
            "auth_context_id",
            "forged_context",
        ),
        lambda raw: raw["exchanges"][1]["response"].__setitem__(
            "status_code",
            500,
        ),
        lambda raw: raw["connector"]["bounds"].__setitem__(
            "max_requests",
            1,
        ),
        lambda raw: raw["engine"].__setitem__(
            "source_sha256",
            "sha256:" + "0" * 64,
        ),
    ),
)
def test_load_capture_rejects_semantic_and_external_tampering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    mutator: Any,
) -> None:
    result, connector_path, recipe_path = _run(tmp_path, monkeypatch)
    raw = json.loads(result.artifact_path.read_text())
    mutator(raw)
    tampered = tmp_path / "tampered.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(payload)
    with pytest.raises((BehaviorContractError, BehaviorHarvestError)):
        load_capture(
            tampered,
            expected_sha256=sha256_digest(payload),
            connector_path=connector_path,
            expected_connector_sha256=result.capture.connector_sha256,
            recipe_path=recipe_path,
            expected_recipe_sha256=result.capture.recipe_sha256,
            expected_engine=current_engine_identity(),
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )


def _corrected_openlmis_order_recipe() -> BehaviorRecipe:
    subject = "requisition_under_test"
    before = BehaviorStep(
        step_id="initial_get",
        operation_id="get_requisition",
        kind="read",
        role="before",
        expected_outcome="read_success",
        subject_id=subject,
        auth_context_id="admin",
        request=_request("GET", "/requisitions/fixed"),
        bindings=(BindingSpec("requisition_id", "/id", "string"),),
        assertions=(_status(200, "initial_status"),),
    )
    submit = BehaviorStep(
        step_id="submit",
        operation_id="submit_requisition",
        kind="mutation",
        role="supporting",
        expected_outcome="mutation_success",
        subject_id=subject,
        auth_context_id="manager",
        request=_request(
            "POST",
            ("/requisitions/", {"$binding": "requisition_id"}, "/submit"),
        ),
        assertions=(_status(200, "submit_status"),),
    )
    forbidden = BehaviorStep(
        step_id="forbidden_authorize",
        operation_id="authorize_requisition",
        kind="mutation",
        role="native_failure",
        expected_outcome="native_failure",
        subject_id=subject,
        auth_context_id="manager",
        request=_request(
            "POST",
            ("/requisitions/", {"$binding": "requisition_id"}, "/authorize"),
        ),
        assertions=(
            _status(403, "forbidden_status"),
            AssertionSpec(
                assertion_id="forbidden_body",
                kind="json_pointer_type",
                pointer="",
                value_type="object",
            ),
        ),
    )
    authorize = replace(
        submit,
        step_id="authorize",
        operation_id="authorize_requisition",
        auth_context_id="admin",
        request=_request(
            "POST",
            ("/requisitions/", {"$binding": "requisition_id"}, "/authorize"),
        ),
        assertions=(_status(200, "authorize_status"),),
    )
    pre_reject = BehaviorStep(
        step_id="pre_reject_get",
        operation_id="get_requisition",
        kind="read",
        role="supporting",
        expected_outcome="read_success",
        subject_id=subject,
        auth_context_id="admin",
        request=_request(
            "GET",
            ("/requisitions/", {"$binding": "requisition_id"}),
        ),
        assertions=(_status(200, "pre_reject_status"),),
    )
    reject_request = _request(
        "POST",
        ("/requisitions/", {"$binding": "requisition_id"}, "/reject"),
    )
    reject = BehaviorStep(
        step_id="reject",
        operation_id="reject_requisition",
        kind="mutation",
        role="success",
        expected_outcome="mutation_success",
        subject_id=subject,
        auth_context_id="supervisor",
        request=reject_request,
        assertions=(_status(200, "reject_status"),),
    )
    duplicate = BehaviorStep(
        step_id="repeat_reject",
        operation_id="reject_requisition",
        kind="mutation",
        role="duplicate",
        expected_outcome="observe",
        subject_id=subject,
        auth_context_id="supervisor",
        request=reject_request,
        assertions=(
            AssertionSpec(
                assertion_id="repeat_exact_reject",
                kind="request_equals_step",
                prior_step_id="reject",
            ),
        ),
    )
    resulting = BehaviorStep(
        step_id="final_get",
        operation_id="get_requisition",
        kind="read",
        role="resulting_state",
        expected_outcome="observe",
        subject_id=subject,
        auth_context_id="admin",
        request=pre_reject.request,
        assertions=(
            AssertionSpec(
                assertion_id="final_matches_reject",
                kind="state_observe_step",
                pointer="/status",
                prior_step_id="reject",
                prior_pointer="/status",
            ),
        ),
    )
    return BehaviorRecipe(
        program_id="corrected_openlmis_sequence",
        seed=11,
        requirements=ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            before,
            submit,
            forbidden,
            authorize,
            pre_reject,
            reject,
            duplicate,
            resulting,
        ),
    )


def test_native_failure_can_precede_success_in_corrected_safe_sequence() -> None:
    recipe = _corrected_openlmis_order_recipe()
    assert [item.role for item in recipe.steps] == [
        "before",
        "supporting",
        "native_failure",
        "supporting",
        "supporting",
        "success",
        "duplicate",
        "resulting_state",
    ]


def test_duplicate_cannot_repeat_unrelated_operation_instead_of_success() -> None:
    recipe = _corrected_openlmis_order_recipe()
    submit = recipe.steps[1]
    duplicate = replace(
        recipe.steps[6],
        operation_id=submit.operation_id,
        request=submit.request,
        assertions=(
            AssertionSpec(
                assertion_id="repeat_submit_instead",
                kind="request_equals_step",
                prior_step_id=submit.step_id,
            ),
        ),
    )
    with pytest.raises(BehaviorContractError, match="sole success"):
        replace(
            recipe,
            steps=(*recipe.steps[:6], duplicate, recipe.steps[7]),
        )


def test_role_subject_order_and_status_contracts_are_fail_closed() -> None:
    recipe = _recipe()
    with pytest.raises(BehaviorContractError, match="one declared subject"):
        replace(
            recipe,
            steps=(
                *recipe.steps[:-1],
                replace(recipe.steps[-1], subject_id="other_subject"),
            ),
        )
    with pytest.raises(BehaviorContractError, match="order"):
        replace(
            recipe,
            steps=(
                recipe.steps[0],
                recipe.steps[1],
                recipe.steps[-1],
                recipe.steps[2],
                recipe.steps[3],
            ),
        )
    with pytest.raises(BehaviorContractError, match="200, 201, 204, or 205"):
        replace(
            recipe.steps[1],
            assertions=(_status(500, "bad_success_status"),),
        )


class _CompiledTarget:
    target_id = "local_replica"
    target_version = "v1"

    def __init__(self, *, divergent_final_state: bool = False) -> None:
        self.state = "new"
        self.calls: list[ReferenceCall] = []
        self.divergent_final_state = divergent_final_state

    def reset(self, seed: int) -> None:
        assert seed == 7
        self.state = "new"
        self.calls = []

    def execute(self, call: ReferenceCall) -> ObservedResponse:
        self.calls.append(call)
        if call.method == "GET" and call.path == "/widgets/fixed":
            return ObservedResponse(
                status_code=200,
                body={"id": "wid_alternate", "state": self.state},
                headers={"content-type": "application/json"},
            )
        if call.path == "/widgets/wid_alternate/activate":
            self.state = "active"
            return ObservedResponse(
                status_code=200,
                body={"id": "wid_alternate", "state": "active"},
                headers={"content-type": "application/json"},
            )
        if call.path == "/widgets/wid_alternate/invalid":
            return ObservedResponse(
                status_code=409,
                body={"error": "invalid_transition"},
                headers={"content-type": "application/json"},
            )
        if call.method == "GET" and call.path == "/widgets/wid_alternate":
            return ObservedResponse(
                status_code=200,
                body={
                    "id": "wid_alternate",
                    "state": ("divergent" if self.divergent_final_state else self.state),
                },
                headers={"content-type": "application/json"},
            )
        raise AssertionError(f"unexpected compiled call: {call.method} {call.path}")


def test_path_bound_compiler_and_runner_rebind_target_generated_ids(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, connector_path, recipe_path = _run(tmp_path, monkeypatch)
    compile_args = {
        "capture_path": result.artifact_path,
        "expected_capture_sha256": result.artifact_sha256,
        "connector_path": connector_path,
        "expected_connector_sha256": result.capture.connector_sha256,
        "recipe_path": recipe_path,
        "expected_recipe_sha256": result.capture.recipe_sha256,
        "expected_engine": current_engine_identity(),
        "sensitive_values": {"api_token": _DEFAULT_SECRET},
        "static_input_paths": {},
        "expected_static_input_sha256": {},
    }
    trace = compile_reference_trace(**compile_args)
    assert isinstance(trace, CompiledBehaviorTrace)
    assert "wid_001" not in repr(trace)

    target = _CompiledTarget()
    report = run_compiled_behavior_trace(target=target, **compile_args)
    assert report.passed is True
    assert target.calls[1].path == "/widgets/wid_alternate/activate"

    divergent = run_compiled_behavior_trace(
        target=_CompiledTarget(divergent_final_state=True),
        **compile_args,
    )
    assert divergent.passed is False
    assert any(mismatch.step_id == "resulting_state" for mismatch in divergent.mismatches)


def test_oauth_identity_uses_three_grants_without_hidden_preflight_call(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    contexts: list[AuthContext] = []
    sources: list[SecretSource] = []
    secrets: dict[str, bytes] = {}
    for actor in ("admin", "manager", "supervisor"):
        username_source = f"{actor}_username"
        password_source = f"{actor}_password"
        for source_name in (username_source, password_source):
            sources.append(
                SecretSource(
                    name=source_name,
                    kind="environment",
                    scan_variants=("raw", "urlencoded", "base64"),
                )
            )
        secrets[username_source] = f"login-{actor}@example.test".encode()
        secrets[password_source] = f"{actor}-password".encode()
        contexts.append(
            AuthContext(
                context_id=actor,
                strategy_id="oauth_password_grant",
                secret_source_names=(username_source, password_source),
                actor_alias=actor,
                grant_required=True,
                grant=AuthGrantSpec(
                    path="/oauth/token",
                    form_fields={"grant_type": "password"},
                    form_secret_fields={
                        "username": username_source,
                        "password": password_source,
                    },
                    token_pointer="/access_token",
                    response_fields={
                        "username": AuthResponseFieldSpec(
                            pointer="/username",
                            expected=actor,
                        ),
                        "token_type": AuthResponseFieldSpec(
                            pointer="/token_type",
                            expected="bearer",
                        ),
                        "scope": AuthResponseFieldSpec(
                            pointer="/scope",
                            expected="read write",
                        ),
                    },
                ),
            )
        )
    auth = AuthProfile(
        profile_id="oauth",
        kind="secret",
        secret_sources=tuple(sources),
        contexts=tuple(contexts),
    )
    preflight = IdentityPreflight(
        strategy_id="authenticated_actors",
        expected_identity={
            "tenant": "sandbox",
            "authenticated_contexts": [
                {
                    "context_id": actor,
                    "strategy_id": "oauth_password_grant",
                    "actor_alias": actor,
                }
                for actor in ("admin", "manager", "supervisor")
            ],
        },
        calls=(
            EvidenceCallSpec(
                call_id="identity",
                strategy_id="authenticated_actors",
                auth_context_id="admin",
                request=_request("GET", "/identity"),
                assertions=(
                    _status(200, "identity_status"),
                    AssertionSpec(
                        assertion_id="identity_tenant",
                        kind="json_pointer_equals",
                        pointer="/tenant",
                        expected="sandbox",
                    ),
                ),
            ),
        ),
        identity_call_id="identity",
        identity_pointer="",
        authenticated_context_ids=("admin", "manager", "supervisor"),
        static_projections=(),
    )
    connector = _connector(
        auth=auth,
        preflight=preflight,
        collectors=(),
        max_requests=12,
    )
    base_recipe = _recipe()
    supporting = tuple(
        BehaviorStep(
            step_id=f"support_{index}",
            operation_id=f"observe_support_{index}",
            kind="read",
            role="supporting",
            expected_outcome="read_success",
            subject_id="widget_under_test",
            auth_context_id="admin",
            request=_request("GET", f"/support/{index}"),
            assertions=(_status(200, f"support_{index}_status"),),
        )
        for index in range(1, 4)
    )
    expanded_steps = (
        *base_recipe.steps[:-1],
        *supporting,
        base_recipe.steps[-1],
    )
    oauth_steps = tuple(
        replace(
            step,
            auth_context_id=("manager" if step.role in {"success", "duplicate"} else "admin"),
        )
        for step in expanded_steps
    )
    recipe = replace(base_recipe, steps=oauth_steps)
    provider = _FakeProvider()
    original = provider.exchange

    def oauth_exchange(**kwargs: Any) -> RawTransportResponse:
        if kwargs["target"] == "/oauth/token":
            provider.calls.append(kwargs)
            actor = ("admin", "manager", "supervisor")[len(provider.calls) - 1]
            return _json_response(
                200,
                {
                    "access_token": f"token-{len(provider.calls)}",
                    "username": actor,
                    "token_type": "bearer",
                    "scope": "read write",
                },
            )
        return original(**kwargs)

    monkeypatch.setattr(
        runner._EngineHttp11Executor,
        "exchange",
        lambda self, **kwargs: oauth_exchange(**kwargs),
    )
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, recipe)
    result = BehaviorHarvester().run(
        connector_path=connector_path,
        recipe_path=recipe_path,
        expected_connector_sha256=connector_sha,
        expected_recipe_sha256=recipe_sha,
        expected_engine=current_engine_identity(),
        run_id="oauth_run",
        output_path=tmp_path / "capture.json",
        sensitive_values=secrets,
        static_input_paths={},
        expected_static_input_sha256={},
        execute_sandbox_writes=True,
    )
    assert len(provider.calls) == 12  # three grants, identity, eight program calls
    assert len(result.capture.auth_receipts) == 3
    assert len(result.capture.preflight_exchanges) == 1
    loaded = load_capture(
        result.artifact_path,
        expected_sha256=result.artifact_sha256,
        connector_path=connector_path,
        expected_connector_sha256=connector_sha,
        recipe_path=recipe_path,
        expected_recipe_sha256=recipe_sha,
        expected_engine=current_engine_identity(),
        sensitive_values=secrets,
        static_input_paths={},
        expected_static_input_sha256={},
    )
    assert len(loaded.value.auth_receipts) == 3
    raw = json.loads(result.artifact_path.read_text())
    raw["auth_receipts"][0]["observed_fields"]["username"] = "forged"
    tampered = tmp_path / "tampered_auth.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(payload)
    with pytest.raises(BehaviorContractError, match="safe observations"):
        load_capture(
            tampered,
            expected_sha256=sha256_digest(payload),
            connector_path=connector_path,
            expected_connector_sha256=connector_sha,
            recipe_path=recipe_path,
            expected_recipe_sha256=recipe_sha,
            expected_engine=current_engine_identity(),
            sensitive_values=secrets,
            static_input_paths={},
            expected_static_input_sha256={},
        )


def _oauth_basic_fixture() -> tuple[
    ConnectorSpec,
    BehaviorRecipe,
    dict[str, bytes],
]:
    auth = AuthProfile(
        profile_id="openlmis_oauth",
        kind="secret",
        secret_sources=(
            SecretSource(
                name="admin_password",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64"),
            ),
            SecretSource(
                name="client_secret",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64", "basic"),
            ),
        ),
        contexts=(
            AuthContext(
                context_id="admin",
                strategy_id="oauth_password_grant",
                secret_source_names=("admin_password", "client_secret"),
                actor_alias="administrator",
                grant_required=True,
                grant=AuthGrantSpec(
                    path="/oauth/token",
                    form_fields={
                        "grant_type": "password",
                        "username": "administrator",
                    },
                    form_secret_fields={"password": "admin_password"},
                    token_pointer="/access_token",
                    response_fields={
                        "username": AuthResponseFieldSpec(
                            pointer="/username",
                            expected="administrator",
                        ),
                        "token_type": AuthResponseFieldSpec(
                            pointer="/token_type",
                            expected="bearer",
                        ),
                        "scope": AuthResponseFieldSpec(
                            pointer="/scope",
                            expected="read write",
                        ),
                    },
                    client_basic_auth=ClientBasicAuthSpec(
                        client_id="user-client",
                        client_secret_source="client_secret",
                    ),
                ),
            ),
        ),
    )
    preflight = IdentityPreflight(
        strategy_id="tenant_identity",
        expected_identity={
            "tenant": "sandbox",
            "authenticated_contexts": [
                {
                    "context_id": "admin",
                    "strategy_id": "oauth_password_grant",
                    "actor_alias": "administrator",
                }
            ],
        },
        calls=(
            EvidenceCallSpec(
                call_id="identity",
                strategy_id="tenant_identity",
                auth_context_id="admin",
                request=_request("GET", "/identity"),
                assertions=(
                    _status(200, "identity_status"),
                    AssertionSpec(
                        assertion_id="identity_tenant",
                        kind="json_pointer_equals",
                        pointer="/tenant",
                        expected="sandbox",
                    ),
                ),
            ),
        ),
        identity_call_id="identity",
        identity_pointer="",
        authenticated_context_ids=("admin",),
        static_projections=(),
    )
    connector = _connector(
        auth=auth,
        preflight=preflight,
        collectors=(),
        max_requests=7,
    )
    recipe = replace(
        _recipe(),
        steps=tuple(replace(step, auth_context_id="admin") for step in _recipe().steps),
    )
    return (
        connector,
        recipe,
        {
            "admin_password": b"admin-password-value",
            "client_secret": b"client-secret-value",
        },
    )


class _OAuthBasicProvider(_FakeProvider):
    def __init__(
        self,
        *,
        auth_field_overrides: dict[str, str] | None = None,
        identity_leak: str | None = None,
    ) -> None:
        super().__init__()
        self.auth_field_overrides = auth_field_overrides or {}
        self.identity_leak = identity_leak

    def exchange(self, **kwargs: Any) -> RawTransportResponse:
        if kwargs["target"] == "/oauth/token":
            self.calls.append(kwargs)
            expected = "Basic " + base64.b64encode(b"user-client:client-secret-value").decode(
                "ascii"
            )
            assert kwargs["headers"]["authorization"] == expected
            fields = dict(item.split("=", 1) for item in kwargs["body"].decode("utf-8").split("&"))
            assert fields["username"] == "administrator"
            assert fields["password"] == "admin-password-value"
            assert "client_secret" not in fields
            body = {
                "access_token": "access-token-value",
                "username": "administrator",
                "token_type": "bearer",
                "scope": "read write",
            }
            body.update(self.auth_field_overrides)
            return _json_response(200, body)
        if kwargs["target"] == "/identity" and self.identity_leak is not None:
            self.calls.append(kwargs)
            return _json_response(
                200,
                {"tenant": "sandbox", "leak": self.identity_leak},
            )
        return super().exchange(**kwargs)


def test_oauth_basic_is_wire_only_and_auth_receipt_contains_only_safe_fields(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector, recipe, secrets = _oauth_basic_fixture()
    result, _, _ = _run(
        tmp_path,
        monkeypatch,
        provider=_OAuthBasicProvider(),
        connector=connector,
        recipe=recipe,
        sensitive_values=secrets,
    )
    receipt = result.capture.auth_receipts[0]
    assert receipt.authorization_applied is True
    assert receipt.client_id == "user-client"
    assert receipt.observed_fields == {
        "username": "administrator",
        "token_type": "bearer",
        "scope": "read write",
    }
    artifact = result.artifact_path.read_bytes()
    form_body = urlencode(
        sorted(
            {
                "grant_type": "password",
                "username": "administrator",
                "password": "admin-password-value",
            }.items()
        )
    ).encode()
    auth_response = canonical_json_bytes(
        {
            "access_token": "access-token-value",
            "username": "administrator",
            "token_type": "bearer",
            "scope": "read write",
        }
    )
    forbidden = (
        b"admin-password-value",
        b"client-secret-value",
        base64.b64encode(b"user-client:client-secret-value"),
        b"Basic " + base64.b64encode(b"user-client:client-secret-value"),
        b"access-token-value",
        base64.b64encode(b"access-token-value"),
        hashlib.sha256(form_body).hexdigest().encode(),
        hashlib.sha256(auth_response).hexdigest().encode(),
    )
    assert all(value not in artifact for value in forbidden)
    assert b"request_sha256" not in artifact
    assert b"response_body_sha256" not in artifact


@pytest.mark.parametrize(
    ("field", "value"),
    (
        ("username", "other-user"),
        ("token_type", "mac"),
        ("scope", "read"),
    ),
)
def test_auth_safe_field_mismatch_halts_before_program(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    field: str,
    value: str,
) -> None:
    connector, recipe, secrets = _oauth_basic_fixture()
    provider = _OAuthBasicProvider(auth_field_overrides={field: value})
    with pytest.raises(BehaviorHarvestError) as caught:
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            recipe=recipe,
            sensitive_values=secrets,
        )
    assert caught.value.code in {
        "auth_identity_mismatch",
        "auth_response_field_mismatch",
    }
    assert [item["target"] for item in provider.calls] == ["/oauth/token"]


@pytest.mark.parametrize(
    "leak",
    (
        base64.b64encode(b"user-client:client-secret-value").decode(),
        ("Basic " + base64.b64encode(b"user-client:client-secret-value").decode()),
        base64.b64encode(b"access-token-value").decode(),
    ),
)
def test_combined_basic_and_oauth_token_variants_are_scanned(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    leak: str,
) -> None:
    connector, recipe, secrets = _oauth_basic_fixture()
    provider = _OAuthBasicProvider(identity_leak=leak)
    with pytest.raises(BehaviorHarvestError) as caught:
        _run(
            tmp_path,
            monkeypatch,
            provider=provider,
            connector=connector,
            recipe=recipe,
            sensitive_values=secrets,
        )
    assert caught.value.code == "sensitive_value_detected"


def test_basic_client_secret_cannot_also_be_sent_in_form() -> None:
    with pytest.raises(BehaviorContractError, match="must not also appear"):
        AuthGrantSpec(
            path="/oauth/token",
            form_fields={"grant_type": "password", "username": "administrator"},
            form_secret_fields={
                "password": "admin_password",
                "client_secret": "client_secret",
            },
            token_pointer="/access_token",
            response_fields={
                "username": AuthResponseFieldSpec(
                    pointer="/username",
                    expected="administrator",
                )
            },
            client_basic_auth=ClientBasicAuthSpec(
                client_id="user-client",
                client_secret_source="client_secret",
            ),
        )


def test_basic_and_universal_scan_declarations_cannot_be_omitted() -> None:
    connector, _, _ = _oauth_basic_fixture()
    client_source = next(
        item for item in connector.auth.secret_sources if item.name == "client_secret"
    )
    with pytest.raises(BehaviorContractError, match="omits variants"):
        replace(
            connector.auth,
            secret_sources=tuple(
                replace(client_source, scan_variants=("raw", "urlencoded", "base64"))
                if item.name == "client_secret"
                else item
                for item in connector.auth.secret_sources
            ),
        )
    with pytest.raises(BehaviorContractError, match="omits variants"):
        replace(
            connector.auth,
            secret_sources=tuple(
                replace(client_source, scan_variants=("raw", "urlencoded", "basic"))
                if item.name == "client_secret"
                else item
                for item in connector.auth.secret_sources
            ),
        )


def test_write_consent_is_required_before_any_provider_interaction(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connector = _connector()
    recipe = _recipe()
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, recipe)
    calls: list[dict[str, Any]] = []
    monkeypatch.setattr(
        runner._EngineHttp11Executor,
        "exchange",
        lambda self, **kwargs: calls.append(kwargs),
    )
    with pytest.raises(BehaviorHarvestError) as caught:
        BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=connector_sha,
            expected_recipe_sha256=recipe_sha,
            expected_engine=current_engine_identity(),
            run_id="no_write_consent",
            output_path=tmp_path / "capture.json",
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )
    assert caught.value.code == "sandbox_write_consent_required"
    assert calls == []
    assert not (tmp_path / "capture.json.partial.jsonl").exists()


def test_public_harvester_has_no_callable_injection_surface() -> None:
    assert tuple(inspect.signature(BehaviorHarvester).parameters) == ()
    assert "monotonic" not in inspect.signature(BehaviorHarvester.run).parameters
    assert "sleep" not in inspect.signature(BehaviorHarvester.run).parameters


@pytest.mark.parametrize(
    "headers",
    (
        {"Host": "evil.example"},
        {"content-length": "999"},
        {"Transfer-Encoding": "chunked"},
        {"Connection": "keep-alive"},
        {"Proxy-Connection": "keep-alive"},
        {"TE": "trailers"},
        {"Trailer": "x-checksum"},
        {"Upgrade": "websocket"},
        {"Expect": "100-continue"},
    ),
)
def test_request_templates_cannot_control_origin_framing_or_connection(
    headers: dict[str, str],
) -> None:
    with pytest.raises(BehaviorContractError, match="origin, framing, or connection"):
        RequestTemplate(
            method="GET",
            path="/identity",
            query={},
            body=None,
            headers=headers,
        )


def test_connector_request_header_allowlist_is_exact() -> None:
    with pytest.raises(BehaviorContractError, match="not allowed"):
        replace(
            _connector(),
            identity_preflight=replace(
                _preflight(),
                calls=(
                    replace(
                        _preflight().calls[0],
                        request=RequestTemplate(
                            method="GET",
                            path="/identity",
                            headers={"if-match": "v1"},
                        ),
                    ),
                ),
            ),
        )
    connector = replace(
        _connector(),
        allowed_request_headers=("if-match",),
        identity_preflight=replace(
            _preflight(),
            calls=(
                replace(
                    _preflight().calls[0],
                    request=RequestTemplate(
                        method="GET",
                        path="/identity",
                        headers={"If-Match": "v1"},
                    ),
                ),
            ),
        ),
    )
    assert connector.allowed_request_headers == ("if-match",)


@pytest.mark.parametrize(
    "origin",
    (
        "https://127.0.0.1:8080",
        "http://localhost:8080",
        "http://10.0.0.1:8080",
        "http://example.test:8080",
        "http://127.0.0.1",
        "http://127.0.0.1:8080/",
        "http://127.0.0.1:8080/path",
    ),
)
def test_self_hosted_reference_requires_exact_loopback_origin(origin: str) -> None:
    connector, _ = _static_connector()
    with pytest.raises(
        BehaviorContractError,
        match="exact http|credential-free HTTP",
    ):
        replace(
            connector,
            origin=origin,
            boundary=BoundarySpec(
                kind="self_hosted_reference",
                production_equivalence="not_claimed",
                statement="Pinned local reference deployment.",
            ),
        )


def test_self_hosted_reference_accepts_exact_loopback_with_static_and_identity() -> None:
    connector, _ = _static_connector()
    accepted = replace(
        connector,
        origin="http://127.0.0.1:8080",
        boundary=BoundarySpec(
            kind="self_hosted_reference",
            production_equivalence="not_claimed",
            statement="Pinned local reference deployment.",
        ),
    )
    assert accepted.origin == "http://127.0.0.1:8080"


def test_remote_writable_boundary_requires_https() -> None:
    with pytest.raises(BehaviorContractError, match="HTTPS"):
        replace(_connector(), origin="http://sandbox.example.test")


def test_remote_sandbox_rejects_static_only_identity() -> None:
    connector, _ = _static_connector()
    with pytest.raises(BehaviorContractError, match="provider identity call"):
        replace(
            connector,
            identity_preflight=replace(
                connector.identity_preflight,
                calls=(),
                identity_call_id=None,
                identity_pointer=None,
                expected_identity={
                    "release": connector.static_json_inputs[0].expected_json,
                    "docker": connector.static_json_inputs[1].expected_json,
                },
            ),
        )


def test_evidence_calls_declare_only_2xx_statuses() -> None:
    with pytest.raises(BehaviorContractError, match="only 2xx"):
        replace(
            _preflight().calls[0],
            assertions=(_status(503, "bad_evidence_status"),),
        )


def test_auth_response_observation_names_must_be_safe() -> None:
    with pytest.raises(BehaviorContractError, match="safe observations"):
        AuthGrantSpec(
            path="/oauth/token",
            form_fields={"username": "administrator"},
            form_secret_fields={"password": "password"},
            token_pointer="/access_token",
            response_fields={
                "username": AuthResponseFieldSpec(
                    pointer="/username",
                    expected="administrator",
                ),
                "token": AuthResponseFieldSpec(
                    pointer="/token_type",
                    expected="bearer",
                ),
            },
        )


def test_each_native_failure_step_requires_its_own_status_and_json_assertion() -> None:
    recipe = _recipe()
    second_failure = replace(
        recipe.steps[3],
        step_id="second_native_failure",
        assertions=(_status(409, "second_failure_status"),),
    )
    with pytest.raises(BehaviorContractError, match="second_native_failure.*JSON-body"):
        replace(
            recipe,
            steps=(
                *recipe.steps[:-1],
                second_failure,
                recipe.steps[-1],
            ),
        )


def test_observational_resulting_state_cannot_predeclare_relation() -> None:
    recipe = _recipe(
        duplicate_outcome="observe",
        resulting_outcome="observe",
    )
    result = recipe.steps[-1]
    with pytest.raises(BehaviorContractError, match="cannot predeclare"):
        replace(
            recipe,
            steps=(
                *recipe.steps[:-1],
                replace(
                    result,
                    assertions=(
                        *result.assertions,
                        AssertionSpec(
                            assertion_id="assumed_change",
                            kind="state_changes_from_step",
                            pointer="/state",
                            prior_step_id="before",
                            prior_pointer="/state",
                        ),
                    ),
                ),
            ),
        )


@pytest.mark.parametrize(
    "value_type",
    ("array", "boolean", "integer", "null", "number", "object"),
)
def test_generated_bindings_are_string_only(value_type: str) -> None:
    with pytest.raises(BehaviorContractError, match="must be strings"):
        BindingSpec(
            binding_id="generated",
            pointer="/id",
            value_type=value_type,  # type: ignore[arg-type]
        )


def test_observed_relation_tampering_is_rejected_on_load(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    result, connector_path, recipe_path = _run(
        tmp_path,
        monkeypatch,
        provider=_FakeProvider(duplicate_status=409),
        recipe=_recipe(
            duplicate_outcome="observe",
            resulting_outcome="observe",
        ),
    )
    raw = json.loads(result.artifact_path.read_text())
    raw["observed_relations"]["resulting_state.state_observed"] = "equal"
    tampered = tmp_path / "tampered-relation.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(payload)
    with pytest.raises(BehaviorContractError, match="observed_relations"):
        load_capture(
            tampered,
            expected_sha256=sha256_digest(payload),
            connector_path=connector_path,
            expected_connector_sha256=result.capture.connector_sha256,
            recipe_path=recipe_path,
            expected_recipe_sha256=result.capture.recipe_sha256,
            expected_engine=current_engine_identity(),
            sensitive_values={"api_token": _DEFAULT_SECRET},
            static_input_paths={},
            expected_static_input_sha256={},
        )
