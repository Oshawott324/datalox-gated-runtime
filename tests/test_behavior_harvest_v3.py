from __future__ import annotations

import base64
import hashlib
import json
from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread
from typing import Any, Iterator

import pytest

from datalox_gated_runtime.behavior_harvest.engines import v2, v3
from datalox_gated_runtime.behavior_harvest.engines.v3 import runner as v3_runner
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (
    canonical_json_bytes,
    derive_secret_variants,
    sha256_digest,
)
from datalox_gated_runtime.reference import ObservedResponse, ReferenceCall


REPO_ROOT = Path(__file__).resolve().parents[1]
PRIMARY_ID = "11111111-1111-4111-8111-111111111111"
DUPLICATE_ID = "22222222-2222-4222-8222-222222222222"
REGENERATED_PRIMARY_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
REGENERATED_DUPLICATE_ID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
AUTH_SECRET = b"fixture-super-secret"
WDL_BYTES = b"workflow hello { call echo }\n"
INPUT_BYTES = b'{"hello.name":"v3"}\n'
BOUNDARY = "DataloxBoundaryV3"


def _status(code: int, assertion_id: str) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="status_equals",
        expected=code,
    )


def _request(
    method: str,
    path: Any,
    *,
    body: Any = None,
) -> v3.RequestTemplate:
    return v3.RequestTemplate(
        method=method,
        path=path,
        query={},
        body=body,
        headers={},
    )


def _multipart(*, options_literal: str = "{}") -> v3.MultipartFormDataSpec:
    return v3.MultipartFormDataSpec(
        boundary=BOUNDARY,
        parts=(
            v3.MultipartPartSpec(
                name="workflowSource",
                artifact_ref="workflow",
                filename="workflow.wdl",
                media_type="application/octet-stream",
            ),
            v3.MultipartPartSpec(
                name="workflowInputs",
                artifact_ref="inputs",
                filename="inputs.json",
                media_type="application/json",
            ),
            v3.MultipartPartSpec(
                name="workflowOptions",
                utf8_literal=options_literal,
                media_type="application/json",
            ),
        ),
    )


def _poll(
    *,
    max_attempts: int = 4,
    interval_ms: int = 1,
    deadline_ms: int = 2_000,
) -> v3.PollSpec:
    return v3.PollSpec(
        interval_ms=interval_ms,
        max_attempts=max_attempts,
        deadline_ms=deadline_ms,
        transient_http_statuses=(404,),
        status_pointer="/status",
        allowed_intermediate_values=("Submitted", "Running"),
        terminal_values=("Succeeded", "Failed"),
        accepted_terminal_values=("Succeeded",),
    )


def _recipe(
    *,
    poll: v3.PollSpec | None = None,
    options_literal: str = "{}",
) -> v3.BehaviorRecipe:
    poll = _poll() if poll is None else poll
    primary_path = ("/status/", {"$binding": "workflow_id"})
    result_path = ("/result/", {"$binding": "workflow_id"})
    multipart = _multipart(options_literal=options_literal)
    return v3.BehaviorRecipe(
        program_id="generic_v3_fixture",
        seed=31,
        requirements=v3.ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            v3.BehaviorStep(
                step_id="before",
                operation_id="before",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("GET", "/before"),
                assertions=(
                    _status(200, "before_status"),
                    v3.AssertionSpec(
                        assertion_id="before_state",
                        kind="json_pointer_equals",
                        pointer="/state",
                        expected="absent",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="submit",
                operation_id="submit",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("POST", "/api/workflows/v1", body=multipart),
                bindings=(
                    v3.BindingSpec(
                        binding_id="workflow_id",
                        pointer="/id",
                        value_type="string",
                        response_occurrences=(
                            v3.ResponseBindingOccurrence("submit", "/id"),
                            v3.ResponseBindingOccurrence("poll", "/id"),
                            v3.ResponseBindingOccurrence("resulting_state", "/id"),
                        ),
                        composed_string_occurrences=(
                            v3.ComposedStringBindingOccurrence(
                                step_id="poll",
                                pointer="/executionPath",
                                prefix="/tmp/executions/",
                                binding_id="workflow_id",
                                suffix="/call-echo",
                            ),
                            v3.ComposedStringBindingOccurrence(
                                step_id="resulting_state",
                                pointer="/resultPath",
                                prefix="/tmp/results/",
                                binding_id="workflow_id",
                                suffix=".json",
                            ),
                        ),
                    ),
                ),
                assertions=(_status(201, "submit_status"),),
            ),
            v3.BehaviorStep(
                step_id="duplicate",
                operation_id="submit",
                kind="mutation",
                role="duplicate",
                expected_outcome="idempotent_success",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("POST", "/api/workflows/v1", body=multipart),
                bindings=(
                    v3.BindingSpec(
                        binding_id="duplicate_id",
                        pointer="/id",
                        value_type="string",
                        response_occurrences=(v3.ResponseBindingOccurrence("duplicate", "/id"),),
                    ),
                ),
                assertions=(
                    v3.AssertionSpec(
                        assertion_id="duplicate_request",
                        kind="request_equals_step",
                        prior_step_id="submit",
                    ),
                    _status(201, "duplicate_status"),
                    v3.AssertionSpec(
                        assertion_id="duplicate_id_type",
                        kind="json_pointer_type",
                        pointer="/id",
                        value_type="string",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="native_failure",
                operation_id="invalid_submit",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("POST", "/invalid"),
                assertions=(
                    _status(400, "failure_status"),
                    v3.AssertionSpec(
                        assertion_id="failure_code",
                        kind="json_pointer_equals",
                        pointer="/error",
                        expected="source_required",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="poll",
                operation_id="poll_status",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("GET", primary_path),
                assertions=(
                    _status(200, "poll_status_code"),
                    v3.AssertionSpec(
                        assertion_id="poll_terminal",
                        kind="json_pointer_equals",
                        pointer="/status",
                        expected="Succeeded",
                    ),
                ),
                poll=poll,
            ),
            v3.BehaviorStep(
                step_id="resulting_state",
                operation_id="result",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="workflow",
                auth_context_id="actor",
                request=_request("GET", result_path),
                assertions=(
                    _status(200, "result_status"),
                    v3.AssertionSpec(
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


def _connector(
    origin: str,
    *,
    poll_attempts: int = 4,
    max_requests: int | None = None,
    max_request_bytes: int = 128 << 10,
    max_response_bytes: int = 16 << 10,
    max_total_response_bytes: int = 128 << 10,
    workflow_bytes: bytes = WDL_BYTES,
    workflow_max_bytes: int = 4_096,
    workflow_digest: str | None = None,
    min_request_interval_ms: int = 0,
) -> v3.ConnectorSpec:
    engine = v3.current_engine_identity()
    return v3.ConnectorSpec(
        connector_id="local_v3_reference",
        provider_id="fixture",
        provider_version="1",
        origin=origin,
        driver_kind="http",
        driver_id=engine.engine_id,
        driver_version=engine.engine_version,
        driver_source_sha256=engine.source_sha256,
        request_encoding="canonical_json",
        allowed_request_headers=(),
        boundary=v3.BoundarySpec(
            kind="self_hosted_reference",
            production_equivalence="not_claimed",
            statement="Disposable local V3 reference.",
        ),
        auth=v3.AuthProfile(
            profile_id="fixture_auth",
            kind="secret",
            secret_sources=(
                v3.SecretSource(
                    name="authorization",
                    kind="environment",
                    scan_variants=("raw", "urlencoded", "base64"),
                ),
            ),
            contexts=(
                v3.AuthContext(
                    context_id="actor",
                    strategy_id=v3.AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
                    secret_source_names=("authorization",),
                    actor_alias="fixture",
                    grant_required=False,
                ),
            ),
        ),
        identity_preflight=v3.IdentityPreflight(
            strategy_id="identity",
            expected_identity={
                "tenant": "local",
                "deployment": {"version": "1"},
            },
            calls=(
                v3.EvidenceCallSpec(
                    call_id="identity",
                    strategy_id="identity",
                    auth_context_id="actor",
                    request=_request("GET", "/identity"),
                    assertions=(
                        _status(200, "identity_status"),
                        v3.AssertionSpec(
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
                v3.StaticIdentityProjection(
                    output_key="deployment",
                    input_id="deployment",
                    pointer="",
                ),
            ),
        ),
        isolation=v3.IsolationResetSpec(
            isolation_kind="namespace",
            cleanup_kind="namespace_recreate",
            cleanup_strategy_id="recreate",
            reset_kind="snapshot_restore",
            reset_strategy_id="restore",
            reset_equivalence_claimed=True,
        ),
        authoring_policy=v3.AuthoringPolicy(),
        static_json_inputs=(
            v3.StaticJsonInputSpec(
                input_id="deployment",
                schema_id="fixture_deployment_v1",
                max_bytes=1_024,
                expected_json={"version": "1"},
            ),
        ),
        source_pins=(
            v3.SourcePin(
                pin_id="fixture",
                source_ref="https://example.test/v3",
                version="1",
                sha256="sha256:" + "1" * 64,
            ),
        ),
        collectors=(),
        known_limitations=("Fixture only.",),
        bounds=v3.HarvestBounds(
            max_requests=6 + poll_attempts if max_requests is None else max_requests,
            max_request_bytes=max_request_bytes,
            max_response_bytes=max_response_bytes,
            max_total_response_bytes=max_total_response_bytes,
            max_polls=poll_attempts,
            request_timeout_ms=2_000,
            min_request_interval_ms=min_request_interval_ms,
        ),
        static_artifact_inputs=(
            v3.StaticArtifactInputSpec(
                artifact_id="workflow",
                filename="workflow.wdl",
                media_type="application/octet-stream",
                max_bytes=workflow_max_bytes,
                expected_sha256=(
                    sha256_digest(workflow_bytes) if workflow_digest is None else workflow_digest
                ),
            ),
            v3.StaticArtifactInputSpec(
                artifact_id="inputs",
                filename="inputs.json",
                media_type="application/json",
                max_bytes=4_096,
                expected_sha256=sha256_digest(INPUT_BYTES),
            ),
        ),
    )


def _basic_api_key_auth() -> v3.AuthProfile:
    return v3.AuthProfile(
        profile_id="api_key_basic",
        kind="secret",
        secret_sources=(
            v3.SecretSource(
                name="api_key",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64", "basic"),
            ),
        ),
        contexts=(
            v3.AuthContext(
                context_id="actor",
                strategy_id=v3.AUTH_STRATEGY_HTTP_BASIC_API_KEY,
                secret_source_names=("api_key",),
                actor_alias="api_key_actor",
                grant_required=False,
            ),
        ),
    )


def _fixed_secret_headers_auth() -> v3.AuthProfile:
    return v3.AuthProfile(
        profile_id="fixed_provider_headers",
        kind="secret",
        secret_sources=(
            v3.SecretSource(
                name="key_id",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64", "header"),
            ),
            v3.SecretSource(
                name="secret_key",
                kind="environment",
                scan_variants=("raw", "urlencoded", "base64", "header"),
            ),
        ),
        contexts=(
            v3.AuthContext(
                context_id="actor",
                strategy_id=v3.AUTH_STRATEGY_FIXED_SECRET_HEADERS,
                secret_source_names=("key_id", "secret_key"),
                actor_alias="paper_account",
                grant_required=False,
                secret_headers={
                    "apca-api-key-id": "key_id",
                    "apca-api-secret-key": "secret_key",
                },
            ),
        ),
    )


class _Server(ThreadingHTTPServer):
    def __init__(
        self,
        poll_responses: list[tuple[int, dict[str, Any]]],
    ) -> None:
        super().__init__(("127.0.0.1", 0), _Handler)
        self.poll_responses = poll_responses
        self.calls: list[dict[str, Any]] = []
        self.submit_count = 0


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        body: dict[str, Any]
        if self.path == "/identity":
            status, body = 200, {"tenant": "local"}
        elif self.path == "/before":
            status, body = 200, {"state": "absent"}
        elif self.path == f"/status/{PRIMARY_ID}":
            if self.server.poll_responses:  # type: ignore[attr-defined]
                status, body = self.server.poll_responses.pop(0)  # type: ignore[attr-defined]
            else:
                status, body = (
                    200,
                    {
                        "id": PRIMARY_ID,
                        "status": "Succeeded",
                    },
                )
            if status == 200:
                body.setdefault("id", PRIMARY_ID)
                body.setdefault(
                    "executionPath",
                    f"/tmp/executions/{PRIMARY_ID}/call-echo",
                )
                body.setdefault("unrelatedEqualString", PRIMARY_ID)
                body.setdefault(
                    "literalBindingControl",
                    {"$binding": "workflow_id"},
                )
                body.setdefault(
                    "literalComposedBindingControl",
                    {
                        "$composed_binding": {
                            "prefix": "/provider/",
                            "binding_id": "workflow_id",
                            "suffix": "/literal",
                        }
                    },
                )
        elif self.path == f"/result/{PRIMARY_ID}":
            status, body = (
                200,
                {
                    "id": PRIMARY_ID,
                    "state": "complete",
                    "resultPath": f"/tmp/results/{PRIMARY_ID}.json",
                },
            )
        else:
            status, body = 404, {"error": "not_found"}
        self._respond(status, body, b"")

    def do_POST(self) -> None:
        length = int(self.headers.get("content-length", "0"))
        request_body = self.rfile.read(length)
        if self.path == "/api/workflows/v1":
            self.server.submit_count += 1  # type: ignore[attr-defined]
            workflow_id = (
                PRIMARY_ID
                if self.server.submit_count == 1  # type: ignore[attr-defined]
                else DUPLICATE_ID
            )
            status, body = 201, {"id": workflow_id, "status": "Submitted"}
        elif self.path == "/invalid":
            status, body = 400, {"error": "source_required"}
        else:
            status, body = 404, {"error": "not_found"}
        self._respond(status, body, request_body)

    def _respond(
        self,
        status: int,
        body: dict[str, Any],
        request_body: bytes,
    ) -> None:
        raw = canonical_json_bytes(body)
        self.server.calls.append(  # type: ignore[attr-defined]
            {
                "method": self.command,
                "path": self.path,
                "content_type": self.headers.get("content-type"),
                "body": request_body,
                "headers": {name.lower(): value for name, value in self.headers.items()},
            }
        )
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def log_message(self, format: str, *args: Any) -> None:
        del format, args


@contextmanager
def _server(
    poll_responses: list[tuple[int, dict[str, Any]]] | None = None,
) -> Iterator[_Server]:
    responses = (
        [
            (404, {"status": "missing"}),
            (200, {"status": "Submitted"}),
            (200, {"status": "Running"}),
            (200, {"status": "Succeeded"}),
        ]
        if poll_responses is None
        else poll_responses
    )
    server = _Server(responses)
    thread = Thread(target=server.serve_forever)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def _write_inputs(
    tmp_path: Path,
    *,
    origin: str,
    poll: v3.PollSpec | None = None,
    connector_options: dict[str, Any] | None = None,
    workflow_bytes: bytes = WDL_BYTES,
    options_literal: str = "{}",
    auth: v3.AuthProfile | None = None,
) -> dict[str, Any]:
    tmp_path.mkdir(parents=True, exist_ok=True)
    connector_options = {} if connector_options is None else connector_options
    poll = _poll() if poll is None else poll
    connector = _connector(
        origin,
        poll_attempts=poll.max_attempts,
        workflow_bytes=workflow_bytes,
        **connector_options,
    )
    if auth is not None:
        connector = replace(connector, auth=auth)
    recipe = _recipe(poll=poll, options_literal=options_literal)
    paths = {
        "connector": tmp_path / "connector.json",
        "recipe": tmp_path / "recipe.json",
        "deployment": tmp_path / "deployment.json",
        "workflow": tmp_path / "workflow.wdl",
        "inputs": tmp_path / "inputs.json",
        "capture": tmp_path / "capture.json",
    }
    payloads = {
        "connector": canonical_json_bytes(connector.to_dict()) + b"\n",
        "recipe": canonical_json_bytes(recipe.to_dict()) + b"\n",
        "deployment": b'{"version":"1"}\n',
        "workflow": workflow_bytes,
        "inputs": INPUT_BYTES,
    }
    for name, payload in payloads.items():
        paths[name].write_bytes(payload)
    return {
        "connector": connector,
        "recipe": recipe,
        "paths": paths,
        "digests": {name: sha256_digest(payload) for name, payload in payloads.items()},
    }


def _run(
    case: dict[str, Any],
    *,
    sensitive_values: dict[str, bytes] | None = None,
) -> v3.HarvestResult:
    paths = case["paths"]
    return v3.BehaviorHarvester().run(
        connector_path=paths["connector"],
        recipe_path=paths["recipe"],
        expected_connector_sha256=case["digests"]["connector"],
        expected_recipe_sha256=case["digests"]["recipe"],
        expected_engine=v3.current_engine_identity(),
        run_id="v3-test",
        output_path=paths["capture"],
        sensitive_values=(
            {"authorization": AUTH_SECRET} if sensitive_values is None else sensitive_values
        ),
        static_input_paths={"deployment": paths["deployment"]},
        expected_static_input_sha256={"deployment": case["digests"]["deployment"]},
        static_artifact_paths={
            "workflow": paths["workflow"],
            "inputs": paths["inputs"],
        },
        execute_sandbox_writes=True,
    )


def _golden_multipart() -> bytes:
    return (
        b"--DataloxBoundaryV3\r\n"
        b'Content-Disposition: form-data; name="workflowSource"; '
        b'filename="workflow.wdl"\r\n'
        b"Content-Type: application/octet-stream\r\n"
        b"\r\n" + WDL_BYTES + b"\r\n"
        b"--DataloxBoundaryV3\r\n"
        b'Content-Disposition: form-data; name="workflowInputs"; '
        b'filename="inputs.json"\r\n'
        b"Content-Type: application/json\r\n"
        b"\r\n" + INPUT_BYTES + b"\r\n"
        b"--DataloxBoundaryV3\r\n"
        b'Content-Disposition: form-data; name="workflowOptions"\r\n'
        b"Content-Type: application/json\r\n"
        b"\r\n"
        b"{}\r\n"
        b"--DataloxBoundaryV3--\r\n"
    )


class _RegeneratedTarget:
    target_id = "regenerated"
    target_version = "1"

    def reset(self, seed: int) -> None:
        assert seed == 31
        self.index = 0

    def execute(self, call: ReferenceCall) -> ObservedResponse:
        bodies = (
            {"state": "absent"},
            {"id": REGENERATED_PRIMARY_ID, "status": "Submitted"},
            {"id": REGENERATED_DUPLICATE_ID, "status": "Submitted"},
            {"error": "source_required"},
            {
                "id": REGENERATED_PRIMARY_ID,
                "status": "Succeeded",
                "executionPath": (f"/tmp/executions/{REGENERATED_PRIMARY_ID}/call-echo"),
                "unrelatedEqualString": PRIMARY_ID,
                "literalBindingControl": {"$binding": "workflow_id"},
                "literalComposedBindingControl": {
                    "$composed_binding": {
                        "prefix": "/provider/",
                        "binding_id": "workflow_id",
                        "suffix": "/literal",
                    }
                },
            },
            {
                "id": REGENERATED_PRIMARY_ID,
                "state": "complete",
                "resultPath": f"/tmp/results/{REGENERATED_PRIMARY_ID}.json",
            },
        )
        statuses = (200, 201, 201, 400, 200, 200)
        assert call.operation_id in {
            "before",
            "submit",
            "invalid_submit",
            "poll_status",
            "result",
        }
        result = ObservedResponse(
            status_code=statuses[self.index],
            body=bodies[self.index],
            headers={"content-type": "application/json"},
        )
        self.index += 1
        return result


def test_v3_multipart_poll_capture_and_compiled_conformance(
    tmp_path: Path,
) -> None:
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
        )
        result = _run(case)

    submissions = [call for call in server.calls if call["path"] == "/api/workflows/v1"]
    assert len(submissions) == 2
    assert submissions[0]["body"] == _golden_multipart()
    assert submissions[1] == submissions[0]
    assert submissions[0]["content_type"] == ("multipart/form-data; boundary=DataloxBoundaryV3")
    assert _golden_multipart().count(b"--DataloxBoundaryV3--\r\n") == 1

    attempts = [exchange for exchange in result.capture.exchanges if exchange.step_id == "poll"]
    assert [item.status_code for item in attempts] == [404, 200, 200, 200]
    assert [item.attempt_number for item in attempts] == [1, 2, 3, 4]
    assert [item.monotonic_elapsed_ms for item in attempts] == sorted(
        item.monotonic_elapsed_ms for item in attempts
    )
    terminal_poll = attempts[-1]
    assert terminal_poll.body["literalBindingControl"] == {"$binding": "workflow_id"}
    assert terminal_poll.body["literalComposedBindingControl"] == {
        "$composed_binding": {
            "prefix": "/provider/",
            "binding_id": "workflow_id",
            "suffix": "/literal",
        }
    }
    assert len(server.calls) == 10
    assert result.capture.static_artifact_receipts[0].to_dict() == {
        "artifact_id": "workflow",
        "filename": "workflow.wdl",
        "media_type": "application/octet-stream",
        "body_bytes": len(WDL_BYTES),
        "body_sha256": sha256_digest(WDL_BYTES),
    }
    assert "path" not in result.capture.static_artifact_receipts[0].to_dict()
    submit_receipts = [
        exchange.request_receipt
        for exchange in result.capture.exchanges
        if exchange.step_id in {"submit", "duplicate"}
    ]
    assert submit_receipts[0].body_sha256 == submit_receipts[1].body_sha256
    assert submit_receipts[0].raw_body == _golden_multipart()

    report = v3.run_compiled_behavior_trace(
        target=_RegeneratedTarget(),
        capture_path=result.artifact_path,
        expected_capture_sha256=result.artifact_sha256,
        connector_path=case["paths"]["connector"],
        expected_connector_sha256=case["digests"]["connector"],
        recipe_path=case["paths"]["recipe"],
        expected_recipe_sha256=case["digests"]["recipe"],
        expected_engine=v3.current_engine_identity(),
        sensitive_values={"authorization": AUTH_SECRET},
        static_input_paths={"deployment": case["paths"]["deployment"]},
        expected_static_input_sha256={"deployment": case["digests"]["deployment"]},
        static_artifact_paths={
            "workflow": case["paths"]["workflow"],
            "inputs": case["paths"]["inputs"],
        },
    )
    assert report.mismatches == ()


def test_v3_auth_contract_owns_basic_and_fixed_header_strategies() -> None:
    assert not hasattr(v2, "AUTH_STRATEGY_HTTP_BASIC_API_KEY")
    assert not hasattr(v2, "AUTH_STRATEGY_FIXED_SECRET_HEADERS")

    fixed = _fixed_secret_headers_auth()
    raw = fixed.to_dict()
    assert v3.AuthProfile.from_dict(raw).to_dict() == raw
    assert raw["contexts"][0]["secret_headers"] == {
        "apca-api-key-id": "key_id",
        "apca-api-secret-key": "secret_key",
    }

    fixed_variants = derive_secret_variants(
        fixed,
        {
            "key_id": b"PK_TEST_ID",
            "secret_key": b"SK_TEST_SECRET",
        },
    )
    assert b"apca-api-key-id: PK_TEST_ID" in fixed_variants
    assert b"apca-api-secret-key:SK_TEST_SECRET" in fixed_variants

    basic = _basic_api_key_auth()
    basic_variants = derive_secret_variants(basic, {"api_key": b"BASIC_TEST_KEY"})
    encoded = base64.b64encode(b"BASIC_TEST_KEY:")
    assert b"BASIC_TEST_KEY:" in basic_variants
    assert encoded in basic_variants
    assert b"Basic " + encoded in basic_variants

    with pytest.raises(v3.BehaviorContractError, match="omits variants"):
        replace(
            fixed,
            secret_sources=(
                replace(
                    fixed.secret_sources[0],
                    scan_variants=("raw", "urlencoded", "base64"),
                ),
                fixed.secret_sources[1],
            ),
        )
    with pytest.raises(v3.BehaviorContractError) as invalid_header:
        replace(
            fixed.contexts[0],
            secret_headers={"authorization": "key_id"},
            secret_source_names=("key_id",),
        )
    assert invalid_header.value.code == "auth_secret_header_invalid"
    collision_auth = replace(
        fixed,
        contexts=(
            replace(
                fixed.contexts[0],
                secret_headers={
                    "x-provider-credential": "key_id",
                    "x-provider-secret": "secret_key",
                },
            ),
        ),
    )
    with pytest.raises(v3.BehaviorContractError) as collision:
        replace(
            _connector("http://127.0.0.1:54321"),
            auth=collision_auth,
            allowed_request_headers=("x-provider-credential",),
        )
    assert collision.value.code == "auth_secret_header_collision"


@pytest.mark.parametrize(
    ("auth", "sensitive_values", "expected_wire_headers"),
    (
        (
            _basic_api_key_auth,
            {"api_key": b"BASIC_WIRE_KEY"},
            {"authorization": "Basic " + base64.b64encode(b"BASIC_WIRE_KEY:").decode("ascii")},
        ),
        (
            _fixed_secret_headers_auth,
            {
                "key_id": b"PK_WIRE_ID",
                "secret_key": b"SK_WIRE_SECRET",
            },
            {
                "apca-api-key-id": "PK_WIRE_ID",
                "apca-api-secret-key": "SK_WIRE_SECRET",
            },
        ),
    ),
    ids=("basic-api-key", "fixed-secret-headers"),
)
def test_v3_closed_auth_strategies_are_wire_only(
    tmp_path: Path,
    auth: Any,
    sensitive_values: dict[str, bytes],
    expected_wire_headers: dict[str, str],
) -> None:
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            auth=auth(),
        )
        result = _run(case, sensitive_values=sensitive_values)

    assert len(server.calls) == 10
    closed_auth_header_names = {
        "authorization",
        "apca-api-key-id",
        "apca-api-secret-key",
    }
    for call in server.calls:
        assert expected_wire_headers.items() <= call["headers"].items()
        assert not (closed_auth_header_names - set(expected_wire_headers)) & set(call["headers"])
    exchanges = (
        *result.capture.preflight_exchanges,
        *result.capture.exchanges,
        *result.capture.collector_exchanges,
    )
    for exchange in exchanges:
        assert not closed_auth_header_names & set(exchange.request.headers)
        assert not closed_auth_header_names & set(exchange.request_receipt.headers)

    artifact = result.artifact_path.read_bytes()
    for secret in sensitive_values.values():
        assert secret not in artifact
        assert base64.b64encode(secret) not in artifact
        assert hashlib.sha256(secret).hexdigest().encode("ascii") not in artifact
    for value in expected_wire_headers.values():
        assert value.encode("ascii") not in artifact
    assert not result.artifact_path.with_name("capture.json.partial.jsonl").exists()

    loaded = v3.load_capture(
        result.artifact_path,
        expected_sha256=result.artifact_sha256,
        connector_path=case["paths"]["connector"],
        expected_connector_sha256=case["digests"]["connector"],
        recipe_path=case["paths"]["recipe"],
        expected_recipe_sha256=case["digests"]["recipe"],
        expected_engine=v3.current_engine_identity(),
        sensitive_values=sensitive_values,
        static_input_paths={"deployment": case["paths"]["deployment"]},
        expected_static_input_sha256={"deployment": case["digests"]["deployment"]},
        static_artifact_paths={
            "workflow": case["paths"]["workflow"],
            "inputs": case["paths"]["inputs"],
        },
    )
    assert loaded.value == result.capture


@pytest.mark.parametrize(
    ("workflow_bytes", "options_literal"),
    (
        (
            b"prefix\r\n--DataloxBoundaryV3\r\nprovider-data",
            "{}",
        ),
        (
            WDL_BYTES,
            "--DataloxBoundaryV3\r\nprovider-data",
        ),
    ),
    ids=("artifact-embedded-delimiter", "literal-start-delimiter"),
)
def test_multipart_payload_boundary_collision_fails_before_dispatch(
    tmp_path: Path,
    workflow_bytes: bytes,
    options_literal: str,
) -> None:
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            workflow_bytes=workflow_bytes,
            options_literal=options_literal,
        )
        with pytest.raises(v3.BehaviorContractError) as caught:
            _run(case)

    assert caught.value.code == "multipart_boundary_collision"
    assert server.calls == []
    assert not case["paths"]["capture"].exists()
    assert not case["paths"]["capture"].with_name("capture.json.partial.jsonl").exists()


@pytest.mark.parametrize(
    ("mode", "expected_code"),
    (
        ("digest", "static_artifact_digest_mismatch"),
        ("oversize", "static_artifact_bytes_exceeded"),
        ("symlink", "multipart_contract_invalid"),
        ("secret", "static_artifact_secret_detected"),
    ),
)
def test_static_artifact_rejection_precedes_mutation(
    tmp_path: Path,
    mode: str,
    expected_code: str,
) -> None:
    workflow_bytes = AUTH_SECRET if mode == "secret" else WDL_BYTES
    options: dict[str, Any] = {}
    if mode == "oversize":
        options["workflow_max_bytes"] = len(workflow_bytes) - 1
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            connector_options=options,
            workflow_bytes=workflow_bytes,
        )
        if mode == "digest":
            case["paths"]["workflow"].write_bytes(b"tampered")
        elif mode == "symlink":
            target = tmp_path / "real.wdl"
            target.write_bytes(workflow_bytes)
            case["paths"]["workflow"].unlink()
            case["paths"]["workflow"].symlink_to(target)
        output = tmp_path / "new-output" / "capture.json"
        case["paths"]["capture"] = output
        with pytest.raises((v3.BehaviorContractError, v3.BehaviorHarvestError)) as caught:
            _run(case)
        assert caught.value.code == expected_code
        assert server.calls == []
        assert not output.parent.exists()


@pytest.mark.parametrize(
    ("responses", "poll", "expected_code", "poll_calls"),
    (
        (
            [(200, {"notStatus": "Running"})],
            _poll(),
            "poll_status_invalid",
            1,
        ),
        (
            [(200, {"status": "Failed"})],
            _poll(),
            "poll_terminal_unexpected",
            1,
        ),
        (
            [(200, {"status": "Submitted"}), (200, {"status": "Running"})],
            _poll(max_attempts=2),
            "poll_budget_exceeded",
            2,
        ),
        (
            [(404, {"status": "missing"}), (404, {"status": "missing"})],
            _poll(max_attempts=2),
            "poll_transient_exhausted",
            2,
        ),
        (
            [(200, {"status": "Submitted"}), (200, {"status": "Succeeded"})],
            _poll(max_attempts=2, interval_ms=50, deadline_ms=10),
            "poll_deadline_exceeded",
            1,
        ),
    ),
)
def test_poll_failures_stop_without_excess_dispatch(
    tmp_path: Path,
    responses: list[tuple[int, dict[str, Any]]],
    poll: v3.PollSpec,
    expected_code: str,
    poll_calls: int,
) -> None:
    with _server(responses) as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            poll=poll,
        )
        with pytest.raises(v3.BehaviorHarvestError) as caught:
            _run(case)
        assert caught.value.code == expected_code
    assert sum(call["path"].startswith("/status/") for call in server.calls) == poll_calls
    assert not case["paths"]["capture"].exists()


class _FakeClock:
    def __init__(self) -> None:
        self.current = 0.0

    def monotonic(self) -> float:
        return self.current

    def sleep(self, seconds: float) -> None:
        self.current += seconds


def test_poll_deadline_is_rechecked_after_global_rate_limit_sleep(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = _FakeClock()
    accounting = v3_runner._RunAccounting()
    monkeypatch.setattr(v3_runner, "time", clock)
    monkeypatch.setattr(v3_runner, "_RunAccounting", lambda: accounting)
    poll = _poll(max_attempts=2, interval_ms=1, deadline_ms=50)

    with _server([(200, {"status": "Succeeded"})]) as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            poll=poll,
            connector_options={"min_request_interval_ms": 100},
        )
        with pytest.raises(v3.BehaviorHarvestError) as caught:
            _run(case)

    assert caught.value.code == "poll_deadline_exceeded"
    assert sum(call["path"].startswith("/status/") for call in server.calls) == 0
    assert accounting.total_requests == 5
    assert accounting.total_poll_attempts == 0
    assert not case["paths"]["capture"].exists()


def test_static_planning_and_request_budget_fail_before_dispatch(
    tmp_path: Path,
) -> None:
    with _server() as server:
        underplanned = _write_inputs(
            tmp_path / "underplanned",
            origin=f"http://127.0.0.1:{server.server_port}",
            connector_options={"max_requests": 9},
        )
        with pytest.raises(v3.BehaviorContractError) as caught:
            _run(underplanned)
        assert caught.value.code == "poll_budget_exceeded"
        assert server.calls == []

    with _server() as server:
        too_small = _write_inputs(
            tmp_path / "request-small",
            origin=f"http://127.0.0.1:{server.server_port}",
            connector_options={"max_request_bytes": 64},
        )
        with pytest.raises(v3.BehaviorHarvestError) as caught:
            _run(too_small)
        assert caught.value.code == "request_bytes_exceeded"
        assert server.calls == []


def test_response_budgets_count_physical_poll_attempts(tmp_path: Path) -> None:
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
            connector_options={"max_total_response_bytes": 250},
        )
        with pytest.raises(v3.BehaviorHarvestError) as caught:
            _run(case)
        assert caught.value.code == "total_response_bytes_exceeded"
    assert len(server.calls) < 10


def test_capture_tamper_rejects_composed_occurrence(tmp_path: Path) -> None:
    with _server() as server:
        case = _write_inputs(
            tmp_path,
            origin=f"http://127.0.0.1:{server.server_port}",
        )
        result = _run(case)
    raw = json.loads(result.artifact_path.read_bytes())
    poll_exchange = next(
        exchange
        for exchange in raw["exchanges"]
        if exchange["step_id"] == "poll" and exchange["response"]["body"]["status"] == "Succeeded"
    )
    poll_exchange["response"]["body"]["executionPath"] = "/tmp/wrong"
    response_bytes = canonical_json_bytes(poll_exchange["response"]["body"])
    poll_exchange["response"]["body_base64"] = base64.b64encode(response_bytes).decode("ascii")
    poll_exchange["response"]["body_bytes"] = len(response_bytes)
    poll_exchange["response"]["body_sha256"] = sha256_digest(response_bytes)
    tampered = tmp_path / "tampered.json"
    tampered_bytes = canonical_json_bytes(raw) + b"\n"
    tampered.write_bytes(tampered_bytes)
    with pytest.raises(v3.BehaviorContractError) as caught:
        v3.load_capture(
            tampered,
            expected_sha256=sha256_digest(tampered_bytes),
            connector_path=case["paths"]["connector"],
            expected_connector_sha256=case["digests"]["connector"],
            recipe_path=case["paths"]["recipe"],
            expected_recipe_sha256=case["digests"]["recipe"],
            expected_engine=v3.current_engine_identity(),
            sensitive_values={"authorization": AUTH_SECRET},
            static_input_paths={"deployment": case["paths"]["deployment"]},
            expected_static_input_sha256={"deployment": case["digests"]["deployment"]},
            static_artifact_paths={
                "workflow": case["paths"]["workflow"],
                "inputs": case["paths"]["inputs"],
            },
        )
    assert caught.value.code == "binding_occurrence_invalid"


def test_occurrence_unknown_duplicate_and_overlap_are_rejected() -> None:
    recipe = _recipe()
    raw = recipe.to_dict()
    binding = raw["steps"][1]["bindings"][0]
    binding["response_occurrences"].append({"step_id": "unknown", "pointer": "/id"})
    with pytest.raises(v3.BehaviorContractError) as caught:
        v3.BehaviorRecipe.from_dict(raw)
    assert caught.value.code == "binding_occurrence_invalid"

    raw = recipe.to_dict()
    binding = raw["steps"][1]["bindings"][0]
    binding["composed_string_occurrences"].append(
        {
            "step_id": "poll",
            "pointer": "/executionPath/child",
            "prefix": "x",
            "binding_id": "workflow_id",
            "suffix": "",
        }
    )
    with pytest.raises(v3.BehaviorContractError) as caught:
        v3.BehaviorRecipe.from_dict(raw)
    assert caught.value.code == "binding_occurrence_invalid"


def test_old_forms_round_trip_and_frozen_v1_v2_sources_are_unchanged() -> None:
    connector_path = REPO_ROOT / "tests/fixtures/behavior_harvest_v1/sandbox_connector.json"
    recipe_path = (
        REPO_ROOT / "tests/fixtures/behavior_harvest_v1/widget_transition.behavior_recipe_v1.json"
    )
    connector_raw = json.loads(connector_path.read_bytes())
    recipe_raw = json.loads(recipe_path.read_bytes())
    assert v3.ConnectorSpec.from_dict(connector_raw).to_dict() == connector_raw
    assert v3.BehaviorRecipe.from_dict(recipe_raw).to_dict() == recipe_raw

    expected = {
        "src/datalox_gated_runtime/behavior_harvest/__init__.py": (
            "ec20ea1bcfb226f3bf69998ec78e3c8ce50edad0f6400dbcc9677632cca0021c"
        ),
        "src/datalox_gated_runtime/behavior_harvest/compiler.py": (
            "13bd3152314c2bd1cb87edcb04b98046cceec2d386f036770bb4ea303b266593"
        ),
        "src/datalox_gated_runtime/behavior_harvest/contracts.py": (
            "c1f844a97c5325b21094a3d4f7a7e256373cb1eb359753cafd8b64cb1454e3d8"
        ),
        "src/datalox_gated_runtime/behavior_harvest/runner.py": (
            "cb6d6f3b97792bf80db9061d8b1a2842db037b960b108cc0a61eb0cbf3568989"
        ),
        "src/datalox_gated_runtime/behavior_harvest/engines/v2/__init__.py": (
            "7b423f6c048f6def74c77da8f59186f29c2c22b43c94ffd925b8f3000905205f"
        ),
        "src/datalox_gated_runtime/behavior_harvest/engines/v2/compiler.py": (
            "824933b20d2491811257e9fadb0cbc3633e4e88855b26945c0fc30e4f4376815"
        ),
        "src/datalox_gated_runtime/behavior_harvest/engines/v2/contracts.py": (
            "4b303a543bb4e9f0332a01adb5697a7bbbb321ad31988ce8c52a747d5911ef1b"
        ),
        "src/datalox_gated_runtime/behavior_harvest/engines/v2/runner.py": (
            "15978826d15a14716f25e1965dbf695a7008728cfab9e0b83c12064082575da5"
        ),
    }
    for relative, digest in expected.items():
        assert hashlib.sha256((REPO_ROOT / relative).read_bytes()).hexdigest() == digest
    assert v2.ENGINE_VERSION == "2"
    assert v2.current_engine_identity().to_dict() == {
        "engine_id": "behavior_harvest_http11",
        "engine_version": "2",
        "source_sha256": "sha256:efbdea5510aead688bf128d3c2091db4650998d3e96a57bec2415018bcf81844",
    }
    assert v3.ENGINE_VERSION == "3"
    assert v3.current_engine_identity().to_dict() == {
        "engine_id": "behavior_harvest_http11",
        "engine_version": "3",
        "source_sha256": "sha256:cca5464a6412ddad1fc105e3f75ea776d980d5ed3d3f83e551913f4672d7259e",
    }


@pytest.mark.parametrize(
    "content_type",
    (
        "application/json",
        "Application/JSON; charset=utf-8",
        "application/problem+json",
        "application/vnd.gs1.epcis+json; charset=utf-8",
    ),
)
def test_v3_accepts_application_json_media_types(content_type: str) -> None:
    response = v3.RawTransportResponse(
        status_code=400,
        headers={"content-type": content_type},
        body_bytes=b"{}",
    )
    v3_runner._require_json_media_type(response, "native_failure")


@pytest.mark.parametrize(
    "content_type",
    (
        "text/json",
        "application/problem+xml",
        "application/+json",
        "application/problem +json",
        "application/problem+jsonx",
    ),
)
def test_v3_rejects_non_json_or_malformed_media_types(content_type: str) -> None:
    response = v3.RawTransportResponse(
        status_code=400,
        headers={"content-type": content_type},
        body_bytes=b"{}",
    )
    with pytest.raises(v3.BehaviorHarvestError) as caught:
        v3_runner._require_json_media_type(response, "native_failure")
    assert caught.value.code == "response_media_type_invalid"
