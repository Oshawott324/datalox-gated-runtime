#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Iterable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest.engines import v3  # noqa: E402
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (  # noqa: E402
    canonical_json_bytes,
    sha256_digest,
    validate_v3_connector_recipe,
)

ENV = ROOT / "envs/probed_opentrons_local_v0"
EVIDENCE = ENV / "evidence/behavior_harvest"
RECIPES = EVIDENCE / "recipes"
CAPTURES = EVIDENCE / "captures"
IDENTITY = EVIDENCE / "simulator_identity.json"
SOURCE_PINS = EVIDENCE / "official_source_pins.json"
DEPLOYMENT_EVIDENCE = EVIDENCE / "deployment_evidence.json"
SIMULATOR_PIP_FREEZE = EVIDENCE / "simulator_pip_freeze.txt"
PROTOCOL = ROOT / "tests/fixtures/opentrons/minimal_protocol.py"
PROTOCOL_VARIANT = ROOT / "tests/fixtures/opentrons/minimal_protocol_variant.py"
ORIGIN = "http://127.0.0.1:31950"
API_HEADER = {"opentrons-version": "*"}
MISSING_ID = "00000000-0000-4000-8000-000000000000"


def _status(code: int, assertion_id: str) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="status_equals",
        expected=code,
    )


def _pointer(
    assertion_id: str,
    pointer: str,
    expected: Any,
) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="json_pointer_equals",
        pointer=pointer,
        expected=expected,
    )


def _pointer_type(
    assertion_id: str,
    pointer: str,
    value_type: str,
) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="json_pointer_type",
        pointer=pointer,
        value_type=value_type,
    )


def _changes(
    assertion_id: str,
    pointer: str,
    prior_step_id: str,
    prior_pointer: str,
) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="state_changes_from_step",
        pointer=pointer,
        prior_step_id=prior_step_id,
        prior_pointer=prior_pointer,
    )


def _equals(
    assertion_id: str,
    pointer: str,
    prior_step_id: str,
    prior_pointer: str,
) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=assertion_id,
        kind="state_equals_step",
        pointer=pointer,
        prior_step_id=prior_step_id,
        prior_pointer=prior_pointer,
    )


def _exact_repeat(success_step_id: str) -> v3.AssertionSpec:
    return v3.AssertionSpec(
        assertion_id=f"repeat_{success_step_id}_request",
        kind="request_equals_step",
        prior_step_id=success_step_id,
    )


def _request(method: str, path: Any, body: Any = None) -> v3.RequestTemplate:
    return v3.RequestTemplate(
        method=method,
        path=path,
        query={},
        body=body,
        headers=API_HEADER,
    )


def _path(prefix: str, binding_id: str, suffix: str = "") -> tuple[Any, ...]:
    return (
        (prefix, {"$binding": binding_id}, suffix)
        if suffix
        else (
            prefix,
            {"$binding": binding_id},
        )
    )


def _step(
    *,
    step_id: str,
    operation_id: str,
    kind: str,
    role: str,
    expected_outcome: str,
    subject_id: str,
    request: v3.RequestTemplate,
    assertions: Iterable[v3.AssertionSpec],
    bindings: Iterable[v3.BindingSpec] = (),
    poll: v3.PollSpec | None = None,
) -> v3.BehaviorStep:
    return v3.BehaviorStep(
        step_id=step_id,
        operation_id=operation_id,
        kind=kind,
        role=role,
        expected_outcome=expected_outcome,
        subject_id=subject_id,
        auth_context_id="simulator",
        request=request,
        assertions=tuple(assertions),
        bindings=tuple(bindings),
        poll=poll,
    )


def _binding(
    binding_id: str,
    pointer: str,
    occurrences: Iterable[tuple[str, str]],
) -> v3.BindingSpec:
    return v3.BindingSpec(
        binding_id=binding_id,
        pointer=pointer,
        value_type="string",
        response_occurrences=tuple(
            v3.ResponseBindingOccurrence(step_id, occurrence_pointer)
            for step_id, occurrence_pointer in occurrences
        ),
    )


def _poll(
    status_pointer: str,
    *,
    intermediate: tuple[str, ...],
    terminal: tuple[str, ...],
    accepted: tuple[str, ...],
) -> v3.PollSpec:
    return v3.PollSpec(
        interval_ms=25,
        max_attempts=8,
        deadline_ms=5_000,
        transient_http_statuses=(),
        status_pointer=status_pointer,
        allowed_intermediate_values=intermediate,
        terminal_values=terminal,
        accepted_terminal_values=accepted,
    )


ANALYSIS_POLL = _poll(
    "/data/status",
    intermediate=("pending",),
    terminal=("completed", "failed"),
    accepted=("completed",),
)
RUN_POLL = _poll(
    "/data/status",
    intermediate=("idle", "running", "paused"),
    terminal=("succeeded", "failed", "stopped"),
    accepted=("succeeded",),
)


def _multipart(artifact_id: str, filename: str) -> v3.MultipartFormDataSpec:
    return v3.MultipartFormDataSpec(
        boundary="DataloxOpentronsV911Boundary",
        parts=(
            v3.MultipartPartSpec(
                name="files",
                artifact_ref=artifact_id,
                filename=filename,
                media_type="text/x-python",
            ),
        ),
    )


def _recipe(program_id: str, steps: Iterable[v3.BehaviorStep]) -> v3.BehaviorRecipe:
    return v3.BehaviorRecipe(
        program_id=program_id,
        seed=911,
        requirements=v3.ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=tuple(steps),
    )


def protocol_create_recipe() -> v3.BehaviorRecipe:
    multipart = _multipart("protocol", PROTOCOL.name)
    return _recipe(
        "opentrons_protocol_create_v1",
        (
            _step(
                step_id="before",
                operation_id="protocol.list",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="protocol",
                request=_request("GET", "/protocols"),
                assertions=(_status(200, "before_status"), _pointer("before_empty", "/data", [])),
            ),
            _step(
                step_id="create",
                operation_id="protocol.create",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="protocol",
                request=_request("POST", "/protocols", multipart),
                assertions=(
                    _status(201, "create_status"),
                    _pointer_type("protocol_id_type", "/data/id", "string"),
                    _pointer("analysis_pending", "/data/analysisSummaries/0/status", "pending"),
                ),
                bindings=(
                    _binding(
                        "protocol_id",
                        "/data/id",
                        (
                            ("create", "/data/id"),
                            ("duplicate", "/data/id"),
                            ("resulting", "/data/0/id"),
                        ),
                    ),
                    _binding(
                        "analysis_id",
                        "/data/analysisSummaries/0/id",
                        (
                            ("create", "/data/analysisSummaries/0/id"),
                            ("duplicate", "/data/analysisSummaries/0/id"),
                            ("analysis_complete", "/data/id"),
                            ("resulting", "/data/0/analysisSummaries/0/id"),
                        ),
                    ),
                ),
            ),
            _step(
                step_id="duplicate",
                operation_id="protocol.create",
                kind="mutation",
                role="duplicate",
                expected_outcome="idempotent_success",
                subject_id="protocol",
                request=_request("POST", "/protocols", multipart),
                assertions=(
                    _exact_repeat("create"),
                    _status(200, "duplicate_status"),
                    _equals("same_protocol", "/data/id", "create", "/data/id"),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id="protocol.create",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="protocol",
                request=_request("POST", "/protocols", {}),
                assertions=(
                    _status(422, "failure_status"),
                    _pointer("failure_id", "/errors/0/id", "InvalidRequest"),
                    _pointer("failure_pointer", "/errors/0/source/pointer", "/files"),
                ),
            ),
            _step(
                step_id="analysis_complete",
                operation_id="analysis.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="protocol",
                request=_request(
                    "GET",
                    _path("/protocols/", "protocol_id", "/analyses/")
                    + ({"$binding": "analysis_id"},),
                ),
                assertions=(
                    _status(200, "analysis_status"),
                    _pointer("analysis_completed", "/data/status", "completed"),
                    _pointer("analysis_result", "/data/result", "ok"),
                ),
                poll=ANALYSIS_POLL,
            ),
            _step(
                step_id="resulting",
                operation_id="protocol.list",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="protocol",
                request=_request("GET", "/protocols"),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("protocol_added", "/data", "before", "/data"),
                    _pointer("one_protocol", "/meta/totalLength", 1),
                ),
            ),
            _step(
                step_id="cleanup",
                operation_id="protocol.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="protocol",
                request=_request("DELETE", _path("/protocols/", "protocol_id")),
                assertions=(_status(200, "cleanup_status"),),
            ),
        ),
    )


def protocol_delete_recipe() -> v3.BehaviorRecipe:
    multipart = _multipart("protocol", PROTOCOL.name)
    return _recipe(
        "opentrons_protocol_delete_v1",
        (
            _step(
                step_id="setup",
                operation_id="protocol.create",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="protocol",
                request=_request("POST", "/protocols", multipart),
                assertions=(_status(201, "setup_status"),),
                bindings=(
                    _binding(
                        "protocol_id",
                        "/data/id",
                        (("setup", "/data/id"), ("before", "/data/0/id")),
                    ),
                ),
            ),
            _step(
                step_id="before",
                operation_id="protocol.list",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="protocol",
                request=_request("GET", "/protocols"),
                assertions=(
                    _status(200, "before_status"),
                    _pointer("before_count", "/meta/totalLength", 1),
                ),
            ),
            _step(
                step_id="delete",
                operation_id="protocol.delete",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="protocol",
                request=_request("DELETE", _path("/protocols/", "protocol_id")),
                assertions=(_status(200, "delete_status"), _pointer("delete_body", "", {})),
            ),
            _step(
                step_id="duplicate",
                operation_id="protocol.delete",
                kind="mutation",
                role="duplicate",
                expected_outcome="duplicate_failure",
                subject_id="protocol",
                request=_request("DELETE", _path("/protocols/", "protocol_id")),
                assertions=(
                    _exact_repeat("delete"),
                    _status(404, "duplicate_status"),
                    _pointer("duplicate_error", "/errors/0/id", "ProtocolNotFound"),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id="protocol.delete",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="protocol",
                request=_request("DELETE", f"/protocols/{MISSING_ID}"),
                assertions=(
                    _status(404, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", "ProtocolNotFound"),
                ),
            ),
            _step(
                step_id="resulting",
                operation_id="protocol.list",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="protocol",
                request=_request("GET", "/protocols"),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("protocol_removed", "/data", "before", "/data"),
                    _pointer("resulting_empty", "/data", []),
                ),
            ),
        ),
    )


def analysis_create_recipe() -> v3.BehaviorRecipe:
    multipart = _multipart("protocol", PROTOCOL.name)
    analysis_body = {"data": {"forceReAnalyze": True}}
    return _recipe(
        "opentrons_analysis_create_v1",
        (
            _step(
                step_id="setup_protocol",
                operation_id="protocol.create",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="analysis",
                request=_request("POST", "/protocols", multipart),
                assertions=(_status(201, "setup_status"),),
                bindings=(
                    _binding("protocol_id", "/data/id", (("setup_protocol", "/data/id"),)),
                    _binding(
                        "initial_analysis_id",
                        "/data/analysisSummaries/0/id",
                        (
                            ("setup_protocol", "/data/analysisSummaries/0/id"),
                            ("initial_complete", "/data/id"),
                            ("before", "/data/0/id"),
                            ("create", "/data/0/id"),
                            ("duplicate", "/data/0/id"),
                            ("resulting", "/data/0/id"),
                        ),
                    ),
                ),
            ),
            _step(
                step_id="initial_complete",
                operation_id="analysis.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="analysis",
                request=_request(
                    "GET",
                    _path("/protocols/", "protocol_id", "/analyses/")
                    + ({"$binding": "initial_analysis_id"},),
                ),
                assertions=(
                    _status(200, "initial_status"),
                    _pointer("initial_ok", "/data/result", "ok"),
                ),
                poll=ANALYSIS_POLL,
            ),
            _step(
                step_id="before",
                operation_id="analysis.list",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="analysis",
                request=_request("GET", _path("/protocols/", "protocol_id", "/analyses")),
                assertions=(
                    _status(200, "before_status"),
                    _pointer("before_count", "/meta/totalLength", 1),
                ),
            ),
            _step(
                step_id="create",
                operation_id="analysis.create",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="analysis",
                request=_request(
                    "POST", _path("/protocols/", "protocol_id", "/analyses"), analysis_body
                ),
                assertions=(
                    _status(201, "create_status"),
                    _pointer("created_pending", "/data/1/status", "pending"),
                ),
                bindings=(
                    _binding(
                        "analysis_id",
                        "/data/1/id",
                        (
                            ("create", "/data/1/id"),
                            ("duplicate", "/data/1/id"),
                            ("analysis_complete", "/data/id"),
                            ("resulting", "/data/1/id"),
                        ),
                    ),
                ),
            ),
            _step(
                step_id="duplicate",
                operation_id="analysis.create",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                subject_id="analysis",
                request=_request(
                    "POST", _path("/protocols/", "protocol_id", "/analyses"), analysis_body
                ),
                assertions=(
                    _exact_repeat("create"),
                    _pointer_type("duplicate_id_type", "/data/2/id", "string"),
                    _changes("distinct_analysis", "/data/2/id", "create", "/data/1/id"),
                ),
                bindings=(
                    _binding(
                        "duplicate_analysis_id",
                        "/data/2/id",
                        (
                            ("duplicate", "/data/2/id"),
                            ("duplicate_complete", "/data/id"),
                            ("resulting", "/data/2/id"),
                        ),
                    ),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id="analysis.create",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="analysis",
                request=_request(
                    "POST",
                    _path("/protocols/", "protocol_id", "/analyses"),
                    {"data": {"runTimeParameterValues": {"unknown": []}}},
                ),
                assertions=(
                    _status(422, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", "InvalidRequest"),
                ),
            ),
            _step(
                step_id="analysis_complete",
                operation_id="analysis.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="analysis",
                request=_request(
                    "GET",
                    _path("/protocols/", "protocol_id", "/analyses/")
                    + ({"$binding": "analysis_id"},),
                ),
                assertions=(
                    _status(200, "analysis_status"),
                    _pointer("analysis_ok", "/data/result", "ok"),
                ),
                poll=ANALYSIS_POLL,
            ),
            _step(
                step_id="duplicate_complete",
                operation_id="analysis.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                subject_id="analysis",
                request=_request(
                    "GET",
                    _path("/protocols/", "protocol_id", "/analyses/")
                    + ({"$binding": "duplicate_analysis_id"},),
                ),
                assertions=(
                    _status(200, "duplicate_analysis_status"),
                    _pointer("duplicate_ok", "/data/result", "ok"),
                ),
                poll=ANALYSIS_POLL,
            ),
            _step(
                step_id="resulting",
                operation_id="analysis.list",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="analysis",
                request=_request("GET", _path("/protocols/", "protocol_id", "/analyses")),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("analyses_added", "/data", "before", "/data"),
                    _pointer("resulting_count", "/meta/totalLength", 3),
                ),
            ),
            _step(
                step_id="cleanup",
                operation_id="protocol.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="analysis",
                request=_request("DELETE", _path("/protocols/", "protocol_id")),
                assertions=(_status(200, "cleanup_status"),),
            ),
        ),
    )


def _distinct_create_recipe(
    *,
    program_id: str,
    subject_id: str,
    operation_id: str,
    list_operation_id: str,
    list_path: str,
    create_path: str,
    create_body: Any,
    failure_body: Any,
    failure_error: str,
    delete_path_prefix: str,
) -> v3.BehaviorRecipe:
    return _recipe(
        program_id,
        (
            _step(
                step_id="before",
                operation_id=list_operation_id,
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id=subject_id,
                request=_request("GET", list_path),
                assertions=(_status(200, "before_status"), _pointer("before_empty", "/data", [])),
            ),
            _step(
                step_id="create",
                operation_id=operation_id,
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id=subject_id,
                request=_request("POST", create_path, create_body),
                assertions=(
                    _status(201, "create_status"),
                    _pointer_type("created_id", "/data/id", "string"),
                ),
                bindings=(
                    _binding(
                        "resource_id",
                        "/data/id",
                        (("create", "/data/id"), ("resulting", "/data/0/id")),
                    ),
                ),
            ),
            _step(
                step_id="duplicate",
                operation_id=operation_id,
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                subject_id=subject_id,
                request=_request("POST", create_path, create_body),
                assertions=(
                    _exact_repeat("create"),
                    _pointer_type("duplicate_id", "/data/id", "string"),
                    _changes("distinct_resource", "/data/id", "create", "/data/id"),
                ),
                bindings=(
                    _binding(
                        "duplicate_id",
                        "/data/id",
                        (("duplicate", "/data/id"), ("resulting", "/data/1/id")),
                    ),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id=operation_id,
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id=subject_id,
                request=_request("POST", create_path, failure_body),
                assertions=(
                    _status(422 if failure_error == "InvalidRequest" else 404, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", failure_error),
                ),
            ),
            _step(
                step_id="resulting",
                operation_id=list_operation_id,
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id=subject_id,
                request=_request("GET", list_path),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("resources_added", "/data", "before", "/data"),
                    _pointer("resulting_count", "/meta/totalLength", 2),
                ),
            ),
            _step(
                step_id="cleanup_primary",
                operation_id=f"{subject_id}.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id=subject_id,
                request=_request("DELETE", _path(delete_path_prefix, "resource_id")),
                assertions=(_status(200, "cleanup_primary_status"),),
            ),
            _step(
                step_id="cleanup_duplicate",
                operation_id=f"{subject_id}.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id=subject_id,
                request=_request("DELETE", _path(delete_path_prefix, "duplicate_id")),
                assertions=(_status(200, "cleanup_duplicate_status"),),
            ),
        ),
    )


def run_create_recipe() -> v3.BehaviorRecipe:
    return _distinct_create_recipe(
        program_id="opentrons_run_create_v1",
        subject_id="run",
        operation_id="run.create",
        list_operation_id="run.list",
        list_path="/runs",
        create_path="/runs",
        create_body={"data": {"protocolId": None}},
        failure_body={"data": {"protocolId": MISSING_ID}},
        failure_error="ProtocolNotFound",
        delete_path_prefix="/runs/",
    )


def offset_create_recipe() -> v3.BehaviorRecipe:
    valid = {
        "data": {
            "definitionUri": "opentrons/datalox_virtual_plate/1",
            "locationSequence": [{"kind": "onAddressableArea", "addressableAreaName": "1"}],
            "vector": {"x": 1.25, "y": -0.5, "z": 0.75},
        }
    }
    invalid = {
        "data": {
            "definitionUri": "opentrons/datalox_virtual_plate/1",
            "locationSequence": [{"kind": "onAddressableArea", "addressableAreaName": "1"}],
        }
    }
    return _distinct_create_recipe(
        program_id="opentrons_labware_offset_create_v1",
        subject_id="labware_offset",
        operation_id="labware_offset.create",
        list_operation_id="labware_offset.list",
        list_path="/labwareOffsets",
        create_path="/labwareOffsets",
        create_body=valid,
        failure_body=invalid,
        failure_error="InvalidRequest",
        delete_path_prefix="/labwareOffsets/",
    )


def _delete_recipe(
    *,
    program_id: str,
    subject_id: str,
    create_operation_id: str,
    list_operation_id: str,
    delete_operation_id: str,
    list_path: str,
    create_path: str,
    create_body: Any,
    delete_path_prefix: str,
    not_found_error: str,
) -> v3.BehaviorRecipe:
    return _recipe(
        program_id,
        (
            _step(
                step_id="setup",
                operation_id=create_operation_id,
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id=subject_id,
                request=_request("POST", create_path, create_body),
                assertions=(_status(201, "setup_status"),),
                bindings=(
                    _binding(
                        "resource_id", "/data/id", (("setup", "/data/id"), ("before", "/data/0/id"))
                    ),
                ),
            ),
            _step(
                step_id="before",
                operation_id=list_operation_id,
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id=subject_id,
                request=_request("GET", list_path),
                assertions=(
                    _status(200, "before_status"),
                    _pointer("before_count", "/meta/totalLength", 1),
                ),
            ),
            _step(
                step_id="delete",
                operation_id=delete_operation_id,
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id=subject_id,
                request=_request("DELETE", _path(delete_path_prefix, "resource_id")),
                assertions=(_status(200, "delete_status"),),
            ),
            _step(
                step_id="duplicate",
                operation_id=delete_operation_id,
                kind="mutation",
                role="duplicate",
                expected_outcome="duplicate_failure",
                subject_id=subject_id,
                request=_request("DELETE", _path(delete_path_prefix, "resource_id")),
                assertions=(
                    _exact_repeat("delete"),
                    _status(404, "duplicate_status"),
                    _pointer("duplicate_error", "/errors/0/id", not_found_error),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id=delete_operation_id,
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id=subject_id,
                request=_request("DELETE", f"{delete_path_prefix}{MISSING_ID}"),
                assertions=(
                    _status(404, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", not_found_error),
                ),
            ),
            _step(
                step_id="resulting",
                operation_id=list_operation_id,
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id=subject_id,
                request=_request("GET", list_path),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("resource_removed", "/data", "before", "/data"),
                    _pointer("resulting_empty", "/data", []),
                ),
            ),
        ),
    )


def run_delete_recipe() -> v3.BehaviorRecipe:
    return _delete_recipe(
        program_id="opentrons_run_delete_v1",
        subject_id="run",
        create_operation_id="run.create",
        list_operation_id="run.list",
        delete_operation_id="run.delete",
        list_path="/runs",
        create_path="/runs",
        create_body={"data": {"protocolId": None}},
        delete_path_prefix="/runs/",
        not_found_error="RunNotFound",
    )


def offset_delete_recipe() -> v3.BehaviorRecipe:
    return _delete_recipe(
        program_id="opentrons_labware_offset_delete_v1",
        subject_id="labware_offset",
        create_operation_id="labware_offset.create",
        list_operation_id="labware_offset.list",
        delete_operation_id="labware_offset.delete",
        list_path="/labwareOffsets",
        create_path="/labwareOffsets",
        create_body={
            "data": {
                "definitionUri": "opentrons/datalox_virtual_plate/1",
                "locationSequence": [{"kind": "onAddressableArea", "addressableAreaName": "1"}],
                "vector": {"x": 1.25, "y": -0.5, "z": 0.75},
            }
        },
        delete_path_prefix="/labwareOffsets/",
        not_found_error="LabwareOffsetNotFound",
    )


def command_create_recipe() -> v3.BehaviorRecipe:
    run_path = _path("/runs/", "run_id", "/commands")
    body = {
        "data": {
            "commandType": "waitForDuration",
            "params": {"seconds": 0.001, "message": "Datalox virtual wait"},
        }
    }
    return _recipe(
        "opentrons_run_command_create_v1",
        (
            _step(
                step_id="setup_run",
                operation_id="run.create",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="run_command",
                request=_request("POST", "/runs", {"data": {"protocolId": None}}),
                assertions=(_status(201, "setup_status"),),
                bindings=(_binding("run_id", "/data/id", (("setup_run", "/data/id"),)),),
            ),
            _step(
                step_id="before",
                operation_id="run_command.list",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="run_command",
                request=_request("GET", run_path),
                assertions=(_status(200, "before_status"), _pointer("before_empty", "/data", [])),
            ),
            _step(
                step_id="create",
                operation_id="run_command.create",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="run_command",
                request=_request("POST", run_path, body),
                assertions=(
                    _status(201, "create_status"),
                    _pointer("queued", "/data/status", "queued"),
                ),
                bindings=(
                    _binding(
                        "command_id",
                        "/data/id",
                        (("create", "/data/id"), ("resulting", "/data/0/id")),
                    ),
                ),
            ),
            _step(
                step_id="duplicate",
                operation_id="run_command.create",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                subject_id="run_command",
                request=_request("POST", run_path, body),
                assertions=(
                    _exact_repeat("create"),
                    _pointer_type("duplicate_id_type", "/data/id", "string"),
                    _changes("distinct_command", "/data/id", "create", "/data/id"),
                ),
                bindings=(
                    _binding(
                        "duplicate_command_id",
                        "/data/id",
                        (("duplicate", "/data/id"), ("resulting", "/data/1/id")),
                    ),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id="run_command.create",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="run_command",
                request=_request(
                    "POST",
                    run_path,
                    {
                        "data": {
                            "commandType": "waitForDuration",
                            "params": {"seconds": "bad", "message": "Datalox invalid wait"},
                        }
                    },
                ),
                assertions=(
                    _status(422, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", "InvalidRequest"),
                ),
            ),
            _step(
                step_id="resulting",
                operation_id="run_command.list",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="run_command",
                request=_request("GET", run_path),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("commands_added", "/data", "before", "/data"),
                    _pointer("resulting_count", "/meta/totalLength", 2),
                ),
            ),
            _step(
                step_id="cleanup",
                operation_id="run.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="run_command",
                request=_request("DELETE", _path("/runs/", "run_id")),
                assertions=(_status(200, "cleanup_status"),),
            ),
        ),
    )


def action_create_recipe() -> v3.BehaviorRecipe:
    command_path = _path("/runs/", "run_id", "/commands")
    action_path = _path("/runs/", "run_id", "/actions")
    run_get_path = _path("/runs/", "run_id")
    play = {"data": {"actionType": "play"}}
    return _recipe(
        "opentrons_run_action_create_v1",
        (
            _step(
                step_id="setup_run",
                operation_id="run.create",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="run_action",
                request=_request("POST", "/runs", {"data": {"protocolId": None}}),
                assertions=(_status(201, "setup_status"),),
                bindings=(
                    _binding(
                        "run_id",
                        "/data/id",
                        (
                            ("setup_run", "/data/id"),
                            ("before", "/data/id"),
                            ("resulting", "/data/id"),
                        ),
                    ),
                ),
            ),
            _step(
                step_id="setup_command",
                operation_id="run_command.create",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="run_action",
                request=_request(
                    "POST",
                    command_path,
                    {
                        "data": {
                            "commandType": "waitForDuration",
                            "params": {"seconds": 0.001, "message": "Datalox virtual wait"},
                        }
                    },
                ),
                assertions=(_status(201, "setup_command_status"),),
            ),
            _step(
                step_id="before",
                operation_id="run.get",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id="run_action",
                request=_request("GET", run_get_path),
                assertions=(
                    _status(200, "before_status"),
                    _pointer("before_idle", "/data/status", "idle"),
                ),
            ),
            _step(
                step_id="play",
                operation_id="run_action.create",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                subject_id="run_action",
                request=_request("POST", action_path, play),
                assertions=(
                    _status(201, "play_status"),
                    _pointer("play_type", "/data/actionType", "play"),
                ),
                bindings=(
                    _binding(
                        "action_id",
                        "/data/id",
                        (("play", "/data/id"), ("resulting", "/data/actions/0/id")),
                    ),
                ),
            ),
            _step(
                step_id="duplicate",
                operation_id="run_action.create",
                kind="mutation",
                role="duplicate",
                expected_outcome="duplicate_failure",
                subject_id="run_action",
                request=_request("POST", action_path, play),
                assertions=(
                    _exact_repeat("play"),
                    _status(409, "duplicate_status"),
                    _pointer("duplicate_error", "/errors/0/id", "RunActionNotAllowed"),
                ),
            ),
            _step(
                step_id="native_failure",
                operation_id="run_action.create",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id="run_action",
                request=_request("POST", action_path, {"data": {"actionType": "launch"}}),
                assertions=(
                    _status(422, "failure_status"),
                    _pointer("failure_error", "/errors/0/id", "InvalidRequest"),
                ),
            ),
            _step(
                step_id="resulting",
                operation_id="run.get",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id="run_action",
                request=_request("GET", run_get_path),
                assertions=(
                    _status(200, "resulting_status"),
                    _changes("run_completed", "/data/status", "before", "/data/status"),
                    _pointer("run_succeeded", "/data/status", "succeeded"),
                ),
                poll=RUN_POLL,
            ),
            _step(
                step_id="cleanup",
                operation_id="run.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                subject_id="run_action",
                request=_request("DELETE", _path("/runs/", "run_id")),
                assertions=(_status(200, "cleanup_status"),),
            ),
        ),
    )


PROGRAMS = {
    "protocol_create": protocol_create_recipe,
    "protocol_delete": protocol_delete_recipe,
    "analysis_create": analysis_create_recipe,
    "run_create": run_create_recipe,
    "run_delete": run_delete_recipe,
    "run_command_create": command_create_recipe,
    "run_action_create": action_create_recipe,
    "labware_offset_create": offset_create_recipe,
    "labware_offset_delete": offset_delete_recipe,
}
PROTOCOL_PROGRAMS = frozenset({"protocol_create", "protocol_delete", "analysis_create"})


def _connector(*, origin: str, include_protocol: bool) -> v3.ConnectorSpec:
    engine = v3.current_engine_identity()
    identity_body = json.loads(IDENTITY.read_text(encoding="utf-8"))
    source_pin_body = json.loads(SOURCE_PINS.read_text(encoding="utf-8"))
    source_tree = source_pin_body["sources"][0]
    api_surface = source_pin_body["sources"][1]
    source_archive = source_pin_body["sources"][2]
    artifacts: tuple[v3.StaticArtifactInputSpec, ...] = ()
    if include_protocol:
        artifacts = (
            v3.StaticArtifactInputSpec(
                artifact_id="protocol",
                filename=PROTOCOL.name,
                media_type="text/x-python",
                max_bytes=16_384,
                expected_sha256=sha256_digest(PROTOCOL.read_bytes()),
            ),
        )
    return v3.ConnectorSpec(
        connector_id=("opentrons_v911_protocol" if include_protocol else "opentrons_v911_json"),
        provider_id="opentrons_robot_server",
        provider_version="9.1.1",
        origin=origin,
        driver_kind="http",
        driver_id=engine.engine_id,
        driver_version=engine.engine_version,
        driver_source_sha256=engine.source_sha256,
        request_encoding="canonical_json",
        allowed_request_headers=("opentrons-version",),
        boundary=v3.BoundarySpec(
            kind="self_hosted_reference",
            production_equivalence="not_claimed",
            statement=(
                "Disposable official robot-server 9.1.1 with temporary persistence and "
                "Virtual Smoothie; virtual record lifecycle only."
            ),
        ),
        auth=v3.AuthProfile(
            profile_id="opentrons_local_no_auth",
            kind="none",
            secret_sources=(),
            contexts=(
                v3.AuthContext(
                    context_id="simulator",
                    strategy_id="none",
                    secret_source_names=(),
                    actor_alias="official_disposable_simulator",
                    grant_required=False,
                ),
            ),
        ),
        identity_preflight=v3.IdentityPreflight(
            strategy_id="opentrons_health",
            expected_identity={
                "apiLog": "/logs/api.log",
                "serialLog": "/logs/serial.log",
                "serverLog": "/logs/server.log",
                "apiSpec": "/openapi.json",
                "systemTime": "/system/time",
                "deployment": identity_body,
            },
            calls=(
                v3.EvidenceCallSpec(
                    call_id="health",
                    strategy_id="opentrons_health",
                    auth_context_id="simulator",
                    request=_request("GET", "/health"),
                    assertions=(
                        _status(200, "health_status"),
                        _pointer("health_api", "/api_version", "9.1.1"),
                        _pointer("health_model", "/robot_model", "OT-2 Standard"),
                        _pointer("health_serial", "/robot_serial", "simulator"),
                        _pointer("health_firmware", "/fw_version", "Virtual Smoothie"),
                    ),
                ),
            ),
            identity_call_id="health",
            identity_pointer="/links",
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
            cleanup_strategy_id="restart_temporary_persistence_simulator",
            reset_kind="tenant_recreate",
            reset_strategy_id="restart_temporary_persistence_simulator",
            reset_equivalence_claimed=False,
        ),
        authoring_policy=v3.AuthoringPolicy(),
        static_json_inputs=(
            v3.StaticJsonInputSpec(
                input_id="deployment",
                schema_id="datalox_opentrons_simulator_identity_v1",
                max_bytes=4_096,
                expected_json=identity_body,
            ),
        ),
        source_pins=(
            v3.SourcePin(
                pin_id="opentrons_source_tree",
                source_ref=source_tree["ref"],
                version=source_pin_body["source_commit"],
                sha256=source_tree["git_tree_response_sha256"],
            ),
            v3.SourcePin(
                pin_id="opentrons_openapi_surface",
                source_ref=api_surface["ref"],
                version="9.1.1",
                sha256=api_surface["sha256"],
            ),
            v3.SourcePin(
                pin_id="opentrons_complete_codeload_archive",
                source_ref=source_archive["ref"],
                version=source_pin_body["source_commit"],
                sha256=source_archive["sha256"],
            ),
        ),
        collectors=(),
        known_limitations=(
            "Virtual protocol, analysis, run, wait-command, run-action, and labware-offset records only.",
            "Physical robot motion, calibration, modules, cameras, maintenance, and machine-global settings are excluded.",
            "The official simulator is a behavior oracle for this virtual slice, not a production-equivalence claim.",
            "Functional reset equivalence is not claimed by the connector; it is tested separately by restarting temporary persistence.",
        ),
        bounds=v3.HarvestBounds(
            max_requests=40,
            max_request_bytes=256 << 10,
            max_response_bytes=2 << 20,
            max_total_response_bytes=8 << 20,
            max_polls=24,
            request_timeout_ms=10_000,
            min_request_interval_ms=0,
        ),
        static_artifact_inputs=artifacts,
    )


def _contract_paths(program: str) -> tuple[Path, Path]:
    connector_name = (
        "sandbox_connector_protocol.v3.json"
        if program in PROTOCOL_PROGRAMS
        else "sandbox_connector_json.v3.json"
    )
    return EVIDENCE / connector_name, RECIPES / f"{program}.behavior_recipe_v3.json"


def _write_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(payload)
    path.chmod(0o600)


def write_contracts(origin: str) -> dict[str, Any]:
    EVIDENCE.mkdir(parents=True, exist_ok=True)
    RECIPES.mkdir(parents=True, exist_ok=True)
    connectors = {
        False: _connector(origin=origin, include_protocol=False),
        True: _connector(origin=origin, include_protocol=True),
    }
    connector_paths = {
        False: EVIDENCE / "sandbox_connector_json.v3.json",
        True: EVIDENCE / "sandbox_connector_protocol.v3.json",
    }
    for include_protocol, connector in connectors.items():
        _write_private(
            connector_paths[include_protocol],
            canonical_json_bytes(connector.to_dict()) + b"\n",
        )
    recipe_paths: dict[str, Path] = {}
    for name, factory in PROGRAMS.items():
        recipe = factory()
        validate_v3_connector_recipe(connectors[name in PROTOCOL_PROGRAMS], recipe)
        recipe_path = RECIPES / f"{name}.behavior_recipe_v3.json"
        _write_private(recipe_path, canonical_json_bytes(recipe.to_dict()) + b"\n")
        recipe_paths[name] = recipe_path
    contract_files = [
        *connector_paths.values(),
        *recipe_paths.values(),
        DEPLOYMENT_EVIDENCE,
        IDENTITY,
        SIMULATOR_PIP_FREEZE,
        SOURCE_PINS,
    ]
    manifest = {
        "schema_id": "datalox_opentrons_behavior_contract_set_v1",
        "provider_id": "opentrons_robot_server",
        "provider_version": "9.1.1",
        "origin": origin,
        "engine": v3.current_engine_identity().to_dict(),
        "files": [
            {
                "path": path.relative_to(ROOT).as_posix(),
                "sha256": sha256_digest(path.read_bytes()),
            }
            for path in sorted(contract_files)
        ],
        "programs": sorted(PROGRAMS),
        "claim_boundary": "Contracts are capture authority, not provider evidence. Only validated capture files support observed behavior claims.",
    }
    manifest_path = EVIDENCE / "contract_manifest.json"
    _write_private(manifest_path, canonical_json_bytes(manifest) + b"\n")
    return manifest


def _verify_contract_manifest() -> dict[str, Any]:
    manifest_path = EVIDENCE / "contract_manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    for item in manifest["files"]:
        path = ROOT / item["path"]
        observed = sha256_digest(path.read_bytes())
        if observed != item["sha256"]:
            raise RuntimeError(f"contract digest mismatch: {path}")
    if manifest["engine"] != v3.current_engine_identity().to_dict():
        raise RuntimeError("installed behavior-harvest V3 engine differs from reviewed contract")
    return manifest


def capture(programs: list[str], *, run_prefix: str) -> dict[str, Any]:
    _verify_contract_manifest()
    CAPTURES.mkdir(parents=True, exist_ok=True)
    identity_digest = sha256_digest(IDENTITY.read_bytes())
    results = []
    for index, program in enumerate(programs, start=1):
        connector_path, recipe_path = _contract_paths(program)
        output_path = CAPTURES / f"{program}.capture_v3.json"
        if output_path.exists():
            raise RuntimeError(f"refusing to overwrite capture: {output_path}")
        static_artifacts = {"protocol": PROTOCOL} if program in PROTOCOL_PROGRAMS else {}
        result = v3.BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=sha256_digest(connector_path.read_bytes()),
            expected_recipe_sha256=sha256_digest(recipe_path.read_bytes()),
            expected_engine=v3.current_engine_identity(),
            run_id=f"{run_prefix}-{index:02d}-{program}",
            output_path=output_path,
            sensitive_values={},
            static_input_paths={"deployment": IDENTITY},
            expected_static_input_sha256={"deployment": identity_digest},
            static_artifact_paths=static_artifacts,
            execute_sandbox_writes=True,
        )
        results.append(
            {
                "program": program,
                "capture_path": output_path.relative_to(ROOT).as_posix(),
                "sha256": result.artifact_sha256,
                "exchange_count": len(result.capture.exchanges),
                "binding_count": len(result.capture.bindings),
            }
        )
    capture_manifest = {
        "schema_id": "datalox_opentrons_behavior_capture_set_v1",
        "provider_id": "opentrons_robot_server",
        "provider_version": "9.1.1",
        "source_commit": "ad074b80e267084f08065b6d559b791140dfa671",
        "boundary": "official_disposable_virtual_smoothie_simulator",
        "programs": results,
        "provider_observed_complete_program_count": len(results),
        "claim_boundary": "Observed against the exact official disposable simulator only; physical and production equivalence are not claimed.",
    }
    manifest_path = CAPTURES / "capture_manifest.json"
    _write_private(manifest_path, canonical_json_bytes(capture_manifest) + b"\n")
    return capture_manifest


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate or execute reviewed Opentrons 9.1.1 virtual lifecycle recipes."
    )
    parser.add_argument("--origin", default=ORIGIN)
    parser.add_argument("--write-contracts", action="store_true")
    parser.add_argument("--capture", action="append", choices=sorted(PROGRAMS))
    parser.add_argument("--capture-all", action="store_true")
    parser.add_argument("--execute-reviewed-simulator-writes", action="store_true")
    parser.add_argument("--run-prefix", default="opentrons-v911-20260805")
    args = parser.parse_args()
    if args.write_contracts:
        print(json.dumps(write_contracts(args.origin), indent=2, sort_keys=True))
    selected = sorted(PROGRAMS) if args.capture_all else (args.capture or [])
    if selected:
        if not args.execute_reviewed_simulator_writes:
            parser.error("capture requires --execute-reviewed-simulator-writes")
        if args.origin != ORIGIN:
            parser.error(f"capture origin must be exact {ORIGIN}")
        if os.environ.get("DATALOX_OPENTRONS_VIRTUAL_AUTHORING_APPROVED") != "1":
            parser.error("set DATALOX_OPENTRONS_VIRTUAL_AUTHORING_APPROVED=1 after review")
        print(json.dumps(capture(selected, run_prefix=args.run_prefix), indent=2, sort_keys=True))
    if not args.write_contracts and not selected:
        parser.error("choose --write-contracts, --capture, or --capture-all")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
