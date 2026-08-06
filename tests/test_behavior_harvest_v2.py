from __future__ import annotations

import base64
import hashlib
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any

import pytest

from datalox_gated_runtime import behavior_harvest as harvest_v1
from datalox_gated_runtime.behavior_harvest.engines import v2
from datalox_gated_runtime.behavior_harvest.engines.v2 import runner
from datalox_gated_runtime.behavior_harvest.engines.v2.contracts import (
    canonical_json_bytes,
    render_path_template,
    sha256_digest,
    thaw_json,
)
from datalox_gated_runtime.reference import ObservedResponse, ReferenceCall


REPO_ROOT = Path(__file__).resolve().parents[1]
V1_FIXTURE_ROOT = REPO_ROOT / "tests/fixtures/behavior_harvest_v1"
OPAQUE_SECRET = b"opaque-test-authorization-value"


def _status(code: int, assertion_id: str) -> v2.AssertionSpec:
    return v2.AssertionSpec(
        assertion_id=assertion_id,
        kind="status_equals",
        expected=code,
    )


def _request(method: str, path: Any) -> v2.RequestTemplate:
    return v2.RequestTemplate(method=method, path=path, query={}, body=None, headers={})


def _recipe() -> v2.BehaviorRecipe:
    bound_path = ("/resources/", {"$binding": "resource_id"}, "/action")
    return v2.BehaviorRecipe(
        program_id="integer_id_empty_response",
        seed=23,
        requirements=v2.ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            v2.BehaviorStep(
                step_id="before",
                operation_id="get_resource",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="resource",
                auth_context_id="actor",
                request=_request("GET", "/resources/fixed"),
                bindings=(
                    v2.BindingSpec(
                        "resource_id",
                        "/id",
                        "integer",
                        response_occurrences=(
                            v2.ResponseBindingOccurrence("before", "/id"),
                            v2.ResponseBindingOccurrence("resulting_state", "/id"),
                        ),
                    ),
                ),
                assertions=(
                    _status(200, "before_status"),
                    v2.AssertionSpec(
                        assertion_id="before_state",
                        kind="json_pointer_equals",
                        pointer="/state",
                        expected="new",
                    ),
                ),
            ),
            v2.BehaviorStep(
                step_id="empty_read",
                operation_id="empty_read",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="resource",
                auth_context_id="actor",
                request=_request("GET", "/empty-read"),
                assertions=(_status(200, "empty_read_status"),),
            ),
            v2.BehaviorStep(
                step_id="activate",
                operation_id="activate_resource",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="resource",
                auth_context_id="actor",
                request=_request("POST", bound_path),
                assertions=(_status(201, "activate_status"),),
            ),
            v2.BehaviorStep(
                step_id="duplicate",
                operation_id="activate_resource",
                kind="mutation",
                role="duplicate",
                expected_outcome="idempotent_success",
                subject_id="resource",
                auth_context_id="actor",
                request=_request("POST", bound_path),
                assertions=(
                    v2.AssertionSpec(
                        assertion_id="duplicate_request",
                        kind="request_equals_step",
                        prior_step_id="activate",
                    ),
                    _status(201, "duplicate_status"),
                    v2.AssertionSpec(
                        assertion_id="duplicate_response",
                        kind="response_equals_step",
                        prior_step_id="activate",
                    ),
                ),
            ),
            v2.BehaviorStep(
                step_id="native_failure",
                operation_id="invalid_resource_transition",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="resource",
                auth_context_id="actor",
                request=_request(
                    "POST",
                    ("/resources/", {"$binding": "resource_id"}, "/invalid"),
                ),
                assertions=(
                    _status(409, "failure_status"),
                    v2.AssertionSpec(
                        assertion_id="failure_code",
                        kind="json_pointer_equals",
                        pointer="/error",
                        expected="invalid_transition",
                    ),
                ),
            ),
            v2.BehaviorStep(
                step_id="resulting_state",
                operation_id="get_resource",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="resource",
                auth_context_id="actor",
                request=_request(
                    "GET",
                    ("/resources/", {"$binding": "resource_id"}),
                ),
                assertions=(
                    _status(200, "result_status"),
                    v2.AssertionSpec(
                        assertion_id="state_changed",
                        kind="state_changes_from_step",
                        pointer="/state",
                        prior_step_id="before",
                        prior_pointer="/state",
                    ),
                ),
            ),
        ),
    )


def _connector(origin: str) -> v2.ConnectorSpec:
    engine = v2.current_engine_identity()
    return v2.ConnectorSpec(
        connector_id="local_v2_reference",
        provider_id="fixture",
        provider_version="1",
        origin=origin,
        driver_kind="http",
        driver_id=engine.engine_id,
        driver_version=engine.engine_version,
        driver_source_sha256=engine.source_sha256,
        request_encoding="canonical_json",
        allowed_request_headers=(),
        boundary=v2.BoundarySpec(
            kind="self_hosted_reference",
            production_equivalence="not_claimed",
            statement="Disposable local reference.",
        ),
        auth=v2.AuthProfile(
            profile_id="opaque_authorization",
            kind="secret",
            secret_sources=(
                v2.SecretSource(
                    name="authorization_value",
                    kind="environment",
                    scan_variants=("raw", "urlencoded", "base64"),
                ),
            ),
            contexts=(
                v2.AuthContext(
                    context_id="actor",
                    strategy_id=v2.AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
                    secret_source_names=("authorization_value",),
                    actor_alias="actor",
                    grant_required=False,
                ),
            ),
        ),
        identity_preflight=v2.IdentityPreflight(
            strategy_id="identity",
            expected_identity={
                "tenant": "local",
                "deployment": {"version": "1"},
            },
            calls=(
                v2.EvidenceCallSpec(
                    call_id="identity",
                    strategy_id="identity",
                    auth_context_id="actor",
                    request=_request("GET", "/identity"),
                    assertions=(
                        _status(200, "identity_status"),
                        v2.AssertionSpec(
                            assertion_id="identity_tenant",
                            kind="json_pointer_equals",
                            pointer="/tenant",
                            expected="local",
                        ),
                    ),
                ),
            ),
            identity_call_id="identity",
            identity_pointer="",
            authenticated_context_ids=(),
            static_projections=(
                v2.StaticIdentityProjection(
                    output_key="deployment",
                    input_id="deployment",
                    pointer="",
                ),
            ),
        ),
        isolation=v2.IsolationResetSpec(
            isolation_kind="namespace",
            cleanup_kind="namespace_recreate",
            cleanup_strategy_id="recreate_namespace",
            reset_kind="snapshot_restore",
            reset_strategy_id="rebuild",
            reset_equivalence_claimed=True,
        ),
        authoring_policy=v2.AuthoringPolicy(concurrency=1, write_retries=0),
        static_json_inputs=(
            v2.StaticJsonInputSpec(
                input_id="deployment",
                schema_id="fixture_deployment_v1",
                max_bytes=1024,
                expected_json={"version": "1"},
            ),
        ),
        source_pins=(
            v2.SourcePin(
                pin_id="fixture_contract",
                source_ref="https://example.test/fixture-contract",
                version="1",
                sha256="sha256:" + "1" * 64,
            ),
        ),
        collectors=(),
        known_limitations=("Test fixture only.",),
        bounds=v2.HarvestBounds(
            max_requests=7,
            max_request_bytes=16384,
            max_response_bytes=16384,
            max_total_response_bytes=65536,
            max_polls=0,
            request_timeout_ms=5000,
        ),
    )


class _ProviderServer(ThreadingHTTPServer):
    def __init__(self, *, nonempty_non_json: bool) -> None:
        super().__init__(("127.0.0.1", 0), _ProviderHandler)
        self.nonempty_non_json = nonempty_non_json
        self.calls: list[tuple[str, str, str | None]] = []
        self.state = "new"


class _ProviderHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        self._handle()

    def do_POST(self) -> None:
        self._handle()

    def log_message(self, _format: str, *args: Any) -> None:
        return

    def _handle(self) -> None:
        server = self.server
        assert isinstance(server, _ProviderServer)
        server.calls.append((self.command, self.path, self.headers.get("Authorization")))
        if self.path == "/identity":
            self._json(200, {"tenant": "local"})
        elif self.path == "/resources/fixed":
            self._json(200, {"id": 42, "owner_id": 42, "state": server.state})
        elif self.path == "/empty-read":
            body = b"not-json" if server.nonempty_non_json else b""
            self._response(200, body, "text/plain")
        elif self.path == "/resources/42/action":
            server.state = "active"
            self._response(201, b"", "application/octet-stream")
        elif self.path == "/resources/42/invalid":
            self._json(409, {"error": "invalid_transition"})
        elif self.path == "/resources/42":
            self._json(200, {"id": 42, "owner_id": 42, "state": server.state})
        else:
            self._json(404, {"error": "not_found"})

    def _json(self, status: int, value: Any) -> None:
        self._response(status, canonical_json_bytes(value), "application/json")

    def _response(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)


def _write_contract(path: Path, value: Any) -> str:
    payload = canonical_json_bytes(value.to_dict()) + b"\n"
    path.write_bytes(payload)
    return sha256_digest(payload)


def _run_harvest(
    tmp_path: Path,
    *,
    nonempty_non_json: bool = False,
) -> tuple[Any, Path, Path, Path, str, _ProviderServer]:
    server = _ProviderServer(nonempty_non_json=nonempty_non_json)
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    connector = _connector(f"http://127.0.0.1:{server.server_port}")
    recipe = _recipe()
    connector_path = tmp_path / "connector.json"
    recipe_path = tmp_path / "recipe.json"
    static_path = tmp_path / "deployment.json"
    connector_sha = _write_contract(connector_path, connector)
    recipe_sha = _write_contract(recipe_path, recipe)
    static_payload = canonical_json_bytes({"version": "1"}) + b"\n"
    static_path.write_bytes(static_payload)
    output_path = tmp_path / "capture.json"
    try:
        result = v2.BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=connector_sha,
            expected_recipe_sha256=recipe_sha,
            expected_engine=v2.current_engine_identity(),
            run_id="v2_compatibility",
            output_path=output_path,
            sensitive_values={"authorization_value": OPAQUE_SECRET},
            static_input_paths={"deployment": static_path},
            expected_static_input_sha256={"deployment": sha256_digest(static_payload)},
            execute_sandbox_writes=True,
        )
    except Exception:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()
        raise
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    return result, connector_path, recipe_path, static_path, sha256_digest(static_payload), server


def _reload_args(
    result: Any,
    connector_path: Path,
    recipe_path: Path,
    static_path: Path,
    static_sha: str,
) -> dict[str, Any]:
    return {
        "capture_path": result.artifact_path,
        "expected_capture_sha256": result.artifact_sha256,
        "connector_path": connector_path,
        "expected_connector_sha256": result.capture.connector_sha256,
        "recipe_path": recipe_path,
        "expected_recipe_sha256": result.capture.recipe_sha256,
        "expected_engine": v2.current_engine_identity(),
        "sensitive_values": {"authorization_value": OPAQUE_SECRET},
        "static_input_paths": {"deployment": static_path},
        "expected_static_input_sha256": {"deployment": static_sha},
    }


def test_raw_authorization_empty_200_201_and_integer_path_capture(
    tmp_path: Path,
) -> None:
    result, connector_path, recipe_path, static_path, static_sha, server = _run_harvest(tmp_path)

    assert len(server.calls) == 7
    assert {authorization for _, _, authorization in server.calls} == {
        OPAQUE_SECRET.decode("utf-8")
    }
    assert all(not authorization.startswith("Bearer ") for _, _, authorization in server.calls)
    assert result.capture.bindings["resource_id"] == 42
    assert result.capture.exchanges[1].status_code == 200
    assert result.capture.exchanges[1].body_kind == "empty"
    assert result.capture.exchanges[1].body_bytes == 0
    assert result.capture.exchanges[1].body_sha256 == sha256_digest(b"")
    assert result.capture.exchanges[2].status_code == 201
    assert result.capture.exchanges[2].body_kind == "empty"
    assert result.capture.exchanges[2].request.path == "/resources/42/action"

    artifact = result.artifact_path.read_bytes()
    forbidden = (
        OPAQUE_SECRET,
        base64.b64encode(OPAQUE_SECRET),
        hashlib.sha256(OPAQUE_SECRET).hexdigest().encode("ascii"),
    )
    assert all(value not in artifact for value in forbidden)
    assert not result.artifact_path.with_name("capture.json.partial.jsonl").exists()

    reload_arguments = _reload_args(
        result,
        connector_path,
        recipe_path,
        static_path,
        static_sha,
    )
    loaded = v2.load_capture(
        path=reload_arguments.pop("capture_path"),
        expected_sha256=reload_arguments.pop("expected_capture_sha256"),
        **reload_arguments,
    )
    assert loaded.value == result.capture


def test_nonempty_non_json_fails_closed_without_secret_in_error_or_journal(
    tmp_path: Path,
) -> None:
    with pytest.raises(v2.BehaviorHarvestError) as caught:
        _run_harvest(tmp_path, nonempty_non_json=True)

    assert caught.value.code == "response_media_type_invalid"
    assert str(caught.value) == "response 'empty_read' must declare application/json"
    assert OPAQUE_SECRET.decode("utf-8") not in str(caught.value)
    journal = (tmp_path / "capture.json.partial.jsonl").read_bytes()
    assert OPAQUE_SECRET not in journal
    assert base64.b64encode(OPAQUE_SECRET) not in journal
    assert hashlib.sha256(OPAQUE_SECRET).hexdigest().encode("ascii") not in journal
    assert not (tmp_path / "capture.json").exists()


class _IntegerRebindingTarget:
    target_id = "integer_rebinding_target"
    target_version = "1"

    def __init__(self, exchanges: tuple[Any, ...], *, invalid_id: bool = False) -> None:
        self._exchanges = exchanges
        self._invalid_id = invalid_id
        self._index = 0
        self.calls: list[ReferenceCall] = []

    def reset(self, seed: int) -> None:
        assert seed == 23
        self._index = 0
        self.calls.clear()

    def execute(self, call: ReferenceCall) -> ObservedResponse:
        exchange = self._exchanges[self._index]
        expected_path = exchange.request.path.replace("/42", "/314")
        assert call.path == expected_path
        self.calls.append(call)
        body = thaw_json(exchange.body)
        if self._index in {0, 5}:
            body["id"] = 314
        if self._index == 0 and self._invalid_id:
            body["id"] = 314.5
        self._index += 1
        return ObservedResponse(
            status_code=exchange.status_code,
            body=body,
            headers=dict(exchange.headers),
        )


def test_integer_binding_compiler_differential_trace_and_coercion_failure(
    tmp_path: Path,
) -> None:
    result, connector_path, recipe_path, static_path, static_sha, _server = _run_harvest(tmp_path)
    arguments = _reload_args(
        result,
        connector_path,
        recipe_path,
        static_path,
        static_sha,
    )

    trace = v2.compile_reference_trace(**arguments)
    assert thaw_json(trace.steps[0].expected_body_template)["id"] == {"$binding": "resource_id"}
    assert thaw_json(trace.steps[0].expected_body_template)["owner_id"] == 42
    assert trace.steps[2].request.path == (
        "/resources/",
        {"$binding": "resource_id"},
        "/action",
    )
    target = _IntegerRebindingTarget(result.capture.exchanges)
    report = v2.run_compiled_behavior_trace(target=target, **arguments)
    assert report.passed is True
    assert target.calls[2].path == "/resources/314/action"

    invalid = v2.run_compiled_behavior_trace(
        target=_IntegerRebindingTarget(result.capture.exchanges, invalid_id=True),
        **arguments,
    )
    assert invalid.passed is False
    assert invalid.mismatches[0].code == "binding_coercion_invalid"


def test_integer_binding_collision_only_rewrites_explicit_response_occurrences(
    tmp_path: Path,
) -> None:
    result, connector_path, recipe_path, static_path, static_sha, _server = _run_harvest(tmp_path)
    arguments = _reload_args(
        result,
        connector_path,
        recipe_path,
        static_path,
        static_sha,
    )

    trace = v2.compile_reference_trace(**arguments)
    before = thaw_json(trace.steps[0].expected_body_template)
    resulting = thaw_json(trace.steps[-1].expected_body_template)
    assert before == {
        "id": {"$binding": "resource_id"},
        "owner_id": 42,
        "state": "new",
    }
    assert resulting == {
        "id": {"$binding": "resource_id"},
        "owner_id": 42,
        "state": "active",
    }
    assert v2.run_compiled_behavior_trace(
        target=_IntegerRebindingTarget(result.capture.exchanges),
        **arguments,
    ).passed


def test_integer_binding_occurrence_contract_fails_closed() -> None:
    with pytest.raises(v2.BehaviorContractError) as missing:
        v2.BindingSpec("resource_id", "/id", "integer")
    assert missing.value.code == "binding_occurrence_invalid"
    assert str(missing.value) == "integer bindings require explicit response occurrences"

    raw = _recipe().to_dict()
    raw["steps"][0]["bindings"][0]["response_occurrences"] = [
        {"step_id": "resulting_state", "pointer": "/id"}
    ]
    with pytest.raises(v2.BehaviorContractError) as no_definition:
        v2.BehaviorRecipe.from_dict(raw)
    assert no_definition.value.code == "binding_occurrence_invalid"
    assert str(no_definition.value) == (
        "binding 'resource_id' must declare its defining response occurrence"
    )


def test_integer_path_tampering_is_rejected_against_canonical_rendering(
    tmp_path: Path,
) -> None:
    result, connector_path, recipe_path, static_path, static_sha, _server = _run_harvest(tmp_path)
    raw = json.loads(result.artifact_path.read_text(encoding="utf-8"))
    exchange = raw["exchanges"][2]
    exchange["request"]["path"] = "/resources/042/action"
    exchange["request"]["target"] = "/resources/042/action"
    exchange["request_receipt"]["target"] = "/resources/042/action"
    tampered_path = tmp_path / "tampered.json"
    payload = canonical_json_bytes(raw) + b"\n"
    tampered_path.write_bytes(payload)
    arguments = _reload_args(
        result,
        connector_path,
        recipe_path,
        static_path,
        static_sha,
    )
    arguments["capture_path"] = tampered_path
    arguments["expected_capture_sha256"] = sha256_digest(payload)

    with pytest.raises(v2.BehaviorContractError, match="deterministic resolution"):
        v2.load_capture(
            path=arguments.pop("capture_path"),
            expected_sha256=arguments.pop("expected_capture_sha256"),
            **arguments,
        )


def test_invalid_new_forms_have_stable_codes_and_reject_partial_coercion() -> None:
    with pytest.raises(v2.BehaviorContractError) as auth_error:
        v2.AuthContext(
            context_id="actor",
            strategy_id="raw_authorization",
            secret_source_names=("secret",),
            actor_alias="actor",
            grant_required=False,
        )
    assert auth_error.value.code == "auth_strategy_invalid"
    assert str(auth_error.value) == (
        "auth_context.strategy_id is unsupported by behavior-harvest engine v2"
    )
    opaque_context = v2.AuthContext(
        context_id="opaque",
        strategy_id=v2.AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
        secret_source_names=("secret",),
        actor_alias="actor",
        grant_required=False,
    )
    with pytest.raises(v2.BehaviorContractError) as opaque_error:
        runner._authorization_header(
            opaque_context,
            token=None,
            sensitive_values={"secret": "not-ascii".replace("o", "\u00f6").encode()},
        )
    assert opaque_error.value.code == "auth_strategy_invalid"
    assert str(opaque_error.value) == ("opaque Authorization header source is missing or not ASCII")

    with pytest.raises(v2.BehaviorContractError) as framing_error:
        v2.RawTransportResponse(
            status_code=200,
            headers={},
            body_kind="json",
            body_bytes=b"",
        )
    assert framing_error.value.code == "response_body_framing_invalid"
    assert str(framing_error.value) == "zero-length response must use empty body framing"

    with pytest.raises(v2.BehaviorContractError) as partial_error:
        v2.RequestTemplate(
            method="GET",
            path=("/resources/prefix-", {"$binding": "resource_id"}),
        )
    assert partial_error.value.code == "binding_coercion_invalid"
    assert str(partial_error.value) == ("request.path bindings must occupy one whole path segment")

    for invalid in (-1, True, 1.5, {"id": 1}, " 1", "+1", "-1"):
        with pytest.raises(v2.BehaviorHarvestError) as coercion_error:
            render_path_template(
                ("/resources/", {"$binding": "resource_id"}),
                {"resource_id": invalid},
            )
        assert coercion_error.value.code == "binding_coercion_invalid"
        assert str(coercion_error.value) == (
            "path binding 'resource_id' must be a safe string or non-negative integer"
        )


def test_existing_authorization_strategies_keep_v1_wire_rendering() -> None:
    none = v2.AuthContext(
        context_id="none",
        strategy_id="none",
        secret_source_names=(),
        actor_alias="anonymous",
        grant_required=False,
    )
    bearer = v2.AuthContext(
        context_id="bearer",
        strategy_id="bearer",
        secret_source_names=("bearer_secret",),
        actor_alias="bearer_actor",
        grant_required=False,
    )
    oauth = v2.AuthContext(
        context_id="oauth",
        strategy_id="oauth_password_grant",
        secret_source_names=("password",),
        actor_alias="oauth_actor",
        grant_required=True,
        grant=v2.AuthGrantSpec(
            path="/oauth/token",
            form_fields={"username": "oauth_actor"},
            form_secret_fields={"password": "password"},
            token_pointer="/access_token",
            response_fields={
                "username": v2.AuthResponseFieldSpec(
                    pointer="/username",
                    expected="oauth_actor",
                )
            },
        ),
    )

    assert runner._authorization_header(none, token=None, sensitive_values={}) is None
    assert (
        runner._authorization_header(
            bearer,
            token=None,
            sensitive_values={"bearer_secret": b"existing-bearer"},
        )
        == "Bearer existing-bearer"
    )
    assert (
        runner._authorization_header(
            oauth,
            token=b"existing-oauth-token",
            sensitive_values={"password": b"unused-on-resource-request"},
        )
        == "Bearer existing-oauth-token"
    )


def test_v1_identity_and_old_artifact_round_trip_remain_exact() -> None:
    connector_path = V1_FIXTURE_ROOT / "sandbox_connector.json"
    recipe_path = V1_FIXTURE_ROOT / "widget_transition.behavior_recipe_v1.json"
    connector_raw = json.loads(connector_path.read_text(encoding="utf-8"))
    recipe_raw = json.loads(recipe_path.read_text(encoding="utf-8"))

    assert harvest_v1.current_engine_identity().to_dict() == {
        "engine_id": "behavior_harvest_http11",
        "engine_version": "1",
        "source_sha256": "sha256:2e44e4de720458dd8d3441f91eec8fbcbcd938c81c9aa171e191d0b40fdcd797",
    }
    assert v2.current_engine_identity().engine_id == "behavior_harvest_http11"
    assert v2.current_engine_identity().engine_version == "2"
    assert v2.current_engine_identity().source_sha256 != (
        harvest_v1.current_engine_identity().source_sha256
    )
    assert v2.current_engine_identity().source_sha256.startswith("sha256:")
    assert len(v2.current_engine_identity().source_sha256) == len("sha256:") + 64

    v1_connector = harvest_v1.ConnectorSpec.from_dict(connector_raw)
    v1_recipe = harvest_v1.BehaviorRecipe.from_dict(recipe_raw)
    v2_connector = v2.ConnectorSpec.from_dict(connector_raw)
    v2_recipe = v2.BehaviorRecipe.from_dict(recipe_raw)
    assert v1_connector.to_dict() == v2_connector.to_dict() == connector_raw
    assert v1_recipe.to_dict() == v2_recipe.to_dict() == recipe_raw
    assert canonical_json_bytes(v1_connector.to_dict()) == canonical_json_bytes(
        v2_connector.to_dict()
    )
    assert canonical_json_bytes(v1_recipe.to_dict()) == canonical_json_bytes(v2_recipe.to_dict())
