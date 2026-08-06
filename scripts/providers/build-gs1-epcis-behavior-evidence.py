#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "envs/gs1_epcis_2_0_1_v0/evidence/behavior_harvest"
RESET_EVIDENCE = EVIDENCE / "reset_equivalence.v1.json"
sys.path.insert(0, str(ROOT / "src"))

from datalox_gated_runtime.behavior_harvest.engines import v3  # noqa: E402

CONTEXT = ["https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld"]
QUERY_EVENTS_POINTER = "/epcisBody/queryResults/resultsBody/eventList"
HEADERS = {"gs1-epcis-version": "2.0.1", "gs1-cbv-version": "2.0.0"}


def _event(
    event_type: str,
    event_id: str,
    event_time: str,
    biz_step: str,
    disposition: str,
    location: str,
    **values: Any,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "@context": CONTEXT,
        "type": event_type,
        "eventTime": event_time,
        "eventTimeZoneOffset": "+00:00",
        "eventID": event_id,
        "bizStep": biz_step,
        "disposition": disposition,
        "readPoint": {"id": location},
        "bizLocation": {"id": location},
    }
    result.update(values)
    return result


def events() -> dict[str, dict[str, Any]]:
    manufacturer = "urn:epc:id:sgln:0614141.07346.0"
    manufacturer_read_point = "urn:epc:id:sgln:0614141.07346.1234"
    distribution_center = "urn:epc:id:sgln:0614141.07347.0"
    pallet = "urn:epc:id:sscc:0614141.1234567890"
    values = {
        "commissioning": _event(
            "ObjectEvent",
            "urn:uuid:10000000-0000-4000-8000-000000000001",
            "2026-08-05T08:20:00Z",
            "commissioning",
            "active",
            manufacturer,
            action="ADD",
            epcList=["urn:epc:id:sgtin:0614141.107346.2017"],
        ),
        "aggregation": _event(
            "AggregationEvent",
            "urn:uuid:20000000-0000-4000-8000-000000000001",
            "2026-08-05T09:00:00Z",
            "packing",
            "in_progress",
            manufacturer,
            action="ADD",
            parentID=pallet,
            childEPCs=[
                "urn:epc:id:sgtin:0614141.107346.2201",
                "urn:epc:id:sgtin:0614141.107346.2202",
            ],
        ),
        "shipping": _event(
            "TransactionEvent",
            "urn:uuid:30000000-0000-4000-8000-000000000001",
            "2026-08-05T10:00:00Z",
            "shipping",
            "in_transit",
            manufacturer,
            action="OBSERVE",
            epcList=[pallet],
            bizTransactionList=[
                {
                    "type": "po",
                    "bizTransaction": "urn:epcglobal:cbv:bt:0614141:PO-2026-001",
                }
            ],
            sourceList=[{"type": "location", "source": manufacturer}],
            destinationList=[{"type": "location", "destination": distribution_center}],
        ),
        "receiving": _event(
            "AssociationEvent",
            "urn:uuid:40000000-0000-4000-8000-000000000001",
            "2026-08-05T11:00:00Z",
            "receiving",
            "sellable_accessible",
            distribution_center,
            action="ADD",
            parentID=distribution_center,
            childEPCs=[pallet],
        ),
        "transformation": _event(
            "TransformationEvent",
            "urn:uuid:50000000-0000-4000-8000-000000000001",
            "2026-08-05T12:00:00Z",
            "assembling",
            "active",
            manufacturer,
            inputEPCList=["urn:epc:id:sgtin:0614141.107346.2501"],
            outputEPCList=["urn:epc:id:sgtin:0614141.107346.2502"],
            transformationID="urn:epc:id:gdti:0614141.07346.501",
        ),
        "decommission": _event(
            "ObjectEvent",
            "urn:uuid:70000000-0000-4000-8000-000000000001",
            "2026-08-05T15:00:00Z",
            "decommissioning",
            "inactive",
            manufacturer,
            action="DELETE",
            epcList=["urn:epc:id:sgtin:0614141.107346.2701"],
        ),
    }
    for value in values.values():
        value["readPoint"] = {"id": manufacturer_read_point}
    original = _event(
        "ObjectEvent",
        "urn:uuid:60000000-0000-4000-8000-000000000001",
        "2026-08-05T13:00:00Z",
        "inspecting",
        "sellable_accessible",
        "urn:epc:id:sgln:0614141.07999.0",
        action="OBSERVE",
        epcList=["urn:epc:id:sgtin:0614141.107346.2601"],
    )
    corrective = deepcopy(original)
    corrective["eventID"] = "urn:uuid:60000000-0000-4000-8000-000000000002"
    corrective["readPoint"] = {"id": "urn:epc:id:sgln:0614141.07348.1234"}
    corrective["bizLocation"] = {"id": "urn:epc:id:sgln:0614141.07348.0"}
    declaration = deepcopy(original)
    declaration["errorDeclaration"] = {
        "declarationTime": "2026-08-05T14:00:00Z",
        "reason": "incorrect_data",
        "correctiveEventIDs": [corrective["eventID"]],
    }
    values.update(
        correction_original=original,
        correction_corrective=corrective,
        correction=declaration,
    )
    return values


def _request(method: str, path: str, *, query: dict[str, Any] | None = None, body: Any = None):
    return v3.RequestTemplate(
        method=method,
        path=path,
        query={} if query is None else query,
        body=body,
        headers=HEADERS,
    )


def _status(code: int, assertion_id: str) -> v3.AssertionSpec:
    return v3.AssertionSpec(assertion_id=assertion_id, kind="status_equals", expected=code)


def _mutation_step(
    *,
    step_id: str,
    role: str,
    event: dict[str, Any],
    subject_id: str,
    operation_id: str,
    expected_outcome: str = "mutation_success",
) -> v3.BehaviorStep:
    return v3.BehaviorStep(
        step_id=step_id,
        operation_id=operation_id,
        kind="mutation",
        role=role,
        expected_outcome=expected_outcome,
        subject_id=subject_id,
        auth_context_id="reference_actor",
        request=_request("POST", "/events", body=event),
        assertions=(_status(201, f"{step_id}_status"),),
    )


def _recipe(program_id: str, event: dict[str, Any]) -> v3.BehaviorRecipe:
    subject_id = f"{program_id}_event"
    event_id = str(event["eventID"])
    invalid = deepcopy(event)
    invalid["eventID"] = event_id[:-3] + "099"
    invalid.pop("eventTime")
    success = _mutation_step(
        step_id="capture",
        role="success",
        event=event,
        subject_id=subject_id,
        operation_id="epcis.capture_event",
    )
    return v3.BehaviorRecipe(
        program_id=program_id,
        seed=20260805,
        requirements=v3.ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            v3.BehaviorStep(
                step_id="before",
                operation_id="epcis.query_events",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("GET", "/events", query={"EQ_eventID": event_id}),
                assertions=(
                    _status(200, "before_status"),
                    v3.AssertionSpec(
                        assertion_id="before_absent",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER,
                        expected=[],
                    ),
                ),
            ),
            success,
            v3.BehaviorStep(
                step_id="duplicate",
                operation_id="epcis.capture_event",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=success.request,
                assertions=(
                    v3.AssertionSpec(
                        assertion_id="duplicate_exact_request",
                        kind="request_equals_step",
                        prior_step_id="capture",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="native_failure",
                operation_id="epcis.capture_event",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("POST", "/events", body=invalid),
                assertions=(
                    _status(400, "native_failure_status"),
                    v3.AssertionSpec(
                        assertion_id="native_failure_type",
                        kind="json_pointer_equals",
                        pointer="/type",
                        expected="epcisException:ValidationException",
                    ),
                    v3.AssertionSpec(
                        assertion_id="native_failure_problem_status",
                        kind="json_pointer_equals",
                        pointer="/status",
                        expected=400,
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="resulting_state",
                operation_id="epcis.query_events",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("GET", "/events", query={"EQ_eventID": event_id}),
                assertions=(
                    _status(200, "resulting_state_status"),
                    v3.AssertionSpec(
                        assertion_id="event_list_changed",
                        kind="state_changes_from_step",
                        pointer=QUERY_EVENTS_POINTER,
                        prior_step_id="before",
                        prior_pointer=QUERY_EVENTS_POINTER,
                    ),
                    v3.AssertionSpec(
                        assertion_id="first_event_id",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER + "/0/eventID",
                        expected=event_id,
                    ),
                    v3.AssertionSpec(
                        assertion_id="duplicate_event_id",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER + "/1/eventID",
                        expected=event_id,
                    ),
                ),
            ),
        ),
    )


def _correction_recipe(values: dict[str, dict[str, Any]]) -> v3.BehaviorRecipe:
    declaration = values["correction"]
    event_id = str(declaration["eventID"])
    subject_id = "correction_event"
    invalid = deepcopy(declaration)
    invalid["eventID"] = event_id[:-3] + "099"
    invalid["errorDeclaration"].pop("declarationTime")
    success = _mutation_step(
        step_id="declare_error",
        role="success",
        event=declaration,
        subject_id=subject_id,
        operation_id="epcis.declare_error",
    )
    supporting = tuple(
        _mutation_step(
            step_id=step_id,
            role="supporting",
            event=values[event_key],
            subject_id=subject_id,
            operation_id="epcis.capture_event",
        )
        for step_id, event_key in (
            ("capture_original", "correction_original"),
            ("capture_corrective", "correction_corrective"),
        )
    )
    return v3.BehaviorRecipe(
        program_id="correction_transition",
        seed=20260805,
        requirements=v3.ProgramRequirements(
            success=True,
            duplicate=True,
            native_failure=True,
            resulting_state=True,
        ),
        steps=(
            *supporting,
            v3.BehaviorStep(
                step_id="before",
                operation_id="epcis.query_events",
                kind="read",
                role="before",
                expected_outcome="read_success",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("GET", "/events", query={"EQ_eventID": event_id}),
                assertions=(
                    _status(200, "before_status"),
                    v3.AssertionSpec(
                        assertion_id="original_event_id",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER + "/0/eventID",
                        expected=event_id,
                    ),
                ),
            ),
            success,
            v3.BehaviorStep(
                step_id="duplicate",
                operation_id="epcis.declare_error",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=success.request,
                assertions=(
                    v3.AssertionSpec(
                        assertion_id="duplicate_exact_request",
                        kind="request_equals_step",
                        prior_step_id="declare_error",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="native_failure",
                operation_id="epcis.declare_error",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("POST", "/events", body=invalid),
                assertions=(
                    _status(400, "native_failure_status"),
                    v3.AssertionSpec(
                        assertion_id="native_failure_type",
                        kind="json_pointer_equals",
                        pointer="/type",
                        expected="epcisException:ValidationException",
                    ),
                ),
            ),
            v3.BehaviorStep(
                step_id="resulting_state",
                operation_id="epcis.query_events",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                subject_id=subject_id,
                auth_context_id="reference_actor",
                request=_request("GET", "/events", query={"EQ_eventID": event_id}),
                assertions=(
                    _status(200, "resulting_state_status"),
                    v3.AssertionSpec(
                        assertion_id="event_list_changed",
                        kind="state_changes_from_step",
                        pointer=QUERY_EVENTS_POINTER,
                        prior_step_id="before",
                        prior_pointer=QUERY_EVENTS_POINTER,
                    ),
                    v3.AssertionSpec(
                        assertion_id="first_declaration_link",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER + "/1/errorDeclaration/correctiveEventIDs/0",
                        expected=values["correction_corrective"]["eventID"],
                    ),
                    v3.AssertionSpec(
                        assertion_id="duplicate_declaration_link",
                        kind="json_pointer_equals",
                        pointer=QUERY_EVENTS_POINTER + "/2/errorDeclaration/correctiveEventIDs/0",
                        expected=values["correction_corrective"]["eventID"],
                    ),
                ),
            ),
        ),
    )


def reference_system() -> dict[str, Any]:
    reset_evidence: dict[str, Any] | None = None
    if RESET_EVIDENCE.is_file():
        reset_evidence = json.loads(RESET_EVIDENCE.read_text(encoding="utf-8"))
    reset_claimed = bool(
        reset_evidence is not None
        and reset_evidence.get("schema_id") == "datalox_epcis_reset_equivalence_v1"
        and reset_evidence.get("passed") is True
    )
    result: dict[str, Any] = {
        "schema_id": "datalox_epcis_reference_system_v1",
        "provider_id": "gs1_epcis",
        "implementation": "FasTnT EPCIS",
        "license": "Apache-2.0",
        "source_url": "https://github.com/louisaxel-ambroise/epcis",
        "source_tag": "v2.8.2",
        "source_commit": "b164868e3ffd5c7cfb7e23de7b423617da3af97b",
        "image": "ghcr.io/louisaxel-ambroise/epcis:v2.8.2",
        "image_manifest_digest": "sha256:118a410f91b6f25cf858ca314b92c420a51a9e063b030d115e409ffa271a483b",
        "loaded_image_id": "sha256:118a410f91b6f25cf858ca314b92c420a51a9e063b030d115e409ffa271a483b",
        "docker_identity_semantics": (
            "Docker 29's containerd image store reports the pulled manifest descriptor "
            "digest as image Id for this digest-qualified reference."
        ),
        "observed_vendor_header": "2.8.1",
        "database": {
            "engine": "SQLite",
            "migration": "20250421102751_InitialV2_8_0",
            "initial_state": "migrated empty database",
        },
        "origin": "http://127.0.0.1:17882",
        "isolation": "dedicated disposable container with a dedicated SQLite writable layer",
        "reset": (
            "mutate the disposable repository, stop and remove its container, recreate "
            "from the pinned manifest, restore the captured migrated-empty SQLite snapshot, "
            "restart, then probe identity, empty state, and a fresh write/read behavior"
        ),
        "reset_equivalence_claimed": reset_claimed,
        "production_equivalence": "not_claimed",
    }
    if reset_claimed:
        result["reset_evidence"] = {
            "path": RESET_EVIDENCE.relative_to(EVIDENCE).as_posix(),
            "sha256": _sha256(RESET_EVIDENCE),
            "empty_snapshot_sha256": reset_evidence["empty_snapshot"]["sha256"],
        }
    return result


def connector(reference: dict[str, Any]) -> v3.ConnectorSpec:
    engine = v3.current_engine_identity()
    expected_identity = {
        "@context": "https://ref.gs1.org/standards/epcis/2.0.0/epcis-context.jsonld",
        "type": "Collection",
        "member": [],
        "reference": reference,
    }
    return v3.ConnectorSpec(
        connector_id="gs1_epcis_fastnt_v2_8_2_reference",
        provider_id="gs1_epcis",
        provider_version="2.0.1-fastnt-v2.8.2",
        origin=reference["origin"],
        driver_kind="http",
        driver_id=engine.engine_id,
        driver_version=engine.engine_version,
        driver_source_sha256=engine.source_sha256,
        request_encoding="canonical_json",
        allowed_request_headers=("gs1-epcis-version", "gs1-cbv-version"),
        boundary=v3.BoundarySpec(
            kind="self_hosted_reference",
            production_equivalence="not_claimed",
            statement="Pinned disposable open-source EPCIS reference; no production tenancy or certification is claimed.",
        ),
        auth=v3.AuthProfile(
            profile_id="synthetic_basic_authorization",
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
                    context_id="reference_actor",
                    strategy_id=v3.AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
                    secret_source_names=("authorization",),
                    actor_alias="disposable_reference_tenant",
                    grant_required=False,
                ),
            ),
        ),
        identity_preflight=v3.IdentityPreflight(
            strategy_id="empty_repository_identity",
            expected_identity=expected_identity,
            calls=(
                v3.EvidenceCallSpec(
                    call_id="reference_identity",
                    strategy_id="empty_repository_identity",
                    auth_context_id="reference_actor",
                    request=_request("GET", "/eventTypes"),
                    assertions=(
                        _status(200, "identity_status"),
                        v3.AssertionSpec(
                            assertion_id="identity_collection",
                            kind="json_pointer_equals",
                            pointer="/type",
                            expected="Collection",
                        ),
                        v3.AssertionSpec(
                            assertion_id="identity_empty",
                            kind="json_pointer_equals",
                            pointer="/member",
                            expected=[],
                        ),
                    ),
                ),
            ),
            identity_call_id="reference_identity",
            identity_pointer="",
            authenticated_context_ids=(),
            static_projections=(
                v3.StaticIdentityProjection(
                    output_key="reference",
                    input_id="reference_system",
                    pointer="",
                ),
            ),
        ),
        isolation=v3.IsolationResetSpec(
            isolation_kind="namespace",
            cleanup_kind="namespace_recreate",
            cleanup_strategy_id="sqlite_snapshot_restore",
            reset_kind="snapshot_restore",
            reset_strategy_id="migrated_empty_sqlite_restore",
            reset_equivalence_claimed=bool(reference["reset_equivalence_claimed"]),
        ),
        authoring_policy=v3.AuthoringPolicy(concurrency=1, write_retries=0),
        static_json_inputs=(
            v3.StaticJsonInputSpec(
                input_id="reference_system",
                schema_id="datalox_epcis_reference_system_v1",
                max_bytes=16_384,
                expected_json=reference,
            ),
        ),
        source_pins=(
            v3.SourcePin(
                pin_id="fastnt_release_image",
                source_ref="oci://ghcr.io/louisaxel-ambroise/epcis@sha256:118a410f91b6f25cf858ca314b92c420a51a9e063b030d115e409ffa271a483b",
                version="v2.8.2",
                sha256=reference["image_manifest_digest"],
            ),
            v3.SourcePin(
                pin_id="gs1_epcis_openapi",
                source_ref="https://ref.gs1.org/standards/epcis/2.0.1/openapi.json",
                version="2.0.1",
                sha256="sha256:3d33792c520d7a7a1d080382d956730bb07021c7dd1cc17229fce27b784d66fc",
            ),
        ),
        collectors=(),
        known_limitations=(
            "FasTnT is an open reference implementation, not a GS1 conformance certificate or production provider.",
            "The evidence covers selected EPCIS 2.0 JSON/REST write transitions and exact observed failure behavior.",
            "The v2.8.2 image reports GS1-Vendor-Version 2.8.1; both facts are preserved without reconciliation.",
        ),
        bounds=v3.HarvestBounds(
            max_requests=8,
            max_request_bytes=64 << 10,
            max_response_bytes=64 << 10,
            max_total_response_bytes=256 << 10,
            max_polls=0,
            request_timeout_ms=5_000,
            min_request_interval_ms=0,
        ),
    )


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def _sha256(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def build() -> None:
    reference = reference_system()
    value_by_name = events()
    recipes = {
        name: _recipe(f"{name}_transition", value_by_name[name])
        for name in (
            "commissioning",
            "aggregation",
            "shipping",
            "receiving",
            "transformation",
            "decommission",
        )
    }
    recipes["correction"] = _correction_recipe(value_by_name)
    _write_json(EVIDENCE / "reference_system.json", reference)
    _write_json(EVIDENCE / "sandbox_connector.v3.json", connector(reference).to_dict())
    for name, recipe in recipes.items():
        _write_json(EVIDENCE / f"{name}.behavior_recipe_v1.json", recipe.to_dict())
    _write_json(
        EVIDENCE / "core_program_coverage.json",
        {
            "schema_id": "datalox_epcis_behavior_program_coverage_v1",
            "provider_id": "gs1_epcis",
            "reference_system": "reference_system.json",
            "connector": "sandbox_connector.v3.json",
            "status": "observed_open_reference",
            "selected_write_operations": [
                "epcis.capture_event",
                "epcis.declare_error",
            ],
            "reset_equivalence": {
                "claimed": bool(reference["reset_equivalence_claimed"]),
                "evidence": (
                    {
                        "path": "reset_equivalence.v1.json",
                        "sha256": _sha256(RESET_EVIDENCE),
                    }
                    if reference["reset_equivalence_claimed"]
                    else None
                ),
            },
            "programs": [
                {
                    "transition": name,
                    "operation_id": (
                        "epcis.declare_error" if name == "correction" else "epcis.capture_event"
                    ),
                    "program_id": recipe.program_id,
                    "recipe": f"{name}.behavior_recipe_v1.json",
                    "recipe_sha256": _sha256(EVIDENCE / f"{name}.behavior_recipe_v1.json"),
                    "capture": f"captures/{name}.capture.v1.json",
                    "capture_sha256": _sha256(EVIDENCE / "captures" / f"{name}.capture.v1.json"),
                    "required_roles": [
                        "before",
                        "success",
                        "duplicate",
                        "native_failure",
                        "resulting_state",
                    ],
                }
                for name, recipe in recipes.items()
            ],
            "claims": {
                "production_equivalence": False,
                "gs1_conformance_certification": False,
                "reference_write_observation": True,
            },
        },
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    managed = {
        "reference_system.json",
        "sandbox_connector.v3.json",
        "core_program_coverage.json",
        *{
            f"{name}.behavior_recipe_v1.json"
            for name in (
                "commissioning",
                "aggregation",
                "shipping",
                "receiving",
                "transformation",
                "correction",
                "decommission",
            )
        },
    }
    before = {
        name: (EVIDENCE / name).read_bytes() if (EVIDENCE / name).exists() else None
        for name in managed
    }
    build()
    after = {name: (EVIDENCE / name).read_bytes() for name in managed}
    if args.check and before != after:
        print("GS1 EPCIS behavior-evidence artifacts were stale.", file=sys.stderr)
        return 1
    if args.check:
        print("GS1 EPCIS behavior-evidence artifacts are current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
