#!/usr/bin/env python3
"""Build deterministic OpenLMIS behavior-harvest recipes.

The recipes are authoring inputs only.  They make no provider-behavior claim;
an operation is promoted separately only after the generic authoring engine has
executed the recipe against the pinned disposable Reference Distribution.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
EVIDENCE = ROOT / "envs/openlmis_supply_chain_v0/evidence/behavior_harvest"


def assertion(
    assertion_id: str,
    kind: str,
    *,
    pointer: str | None = None,
    expected: object = None,
    value_type: str | None = None,
    prior_step_id: str | None = None,
    prior_pointer: str | None = None,
) -> dict[str, object]:
    return {
        "assertion_id": assertion_id,
        "kind": kind,
        "pointer": pointer,
        "expected": expected,
        "value_type": value_type,
        "pattern": None,
        "prior_step_id": prior_step_id,
        "prior_pointer": prior_pointer,
    }


def step(
    *,
    step_id: str,
    operation_id: str,
    kind: str,
    role: str,
    expected_outcome: str,
    actor: str,
    method: str,
    path: object,
    assertions: list[dict[str, object]],
    bindings: list[dict[str, str]] | None = None,
    subject_id: str = "fixture_requisition_6167e65c",
    query: dict[str, object] | None = None,
    body_value: object = None,
) -> dict[str, object]:
    return {
        "step_id": step_id,
        "operation_id": operation_id,
        "kind": kind,
        "role": role,
        "expected_outcome": expected_outcome,
        "subject_id": subject_id,
        "auth_context_id": actor,
        "request": {
            "method": method,
            "path": path,
            "query": query or {},
            "body": body_value,
            "headers": {},
        },
        "bindings": bindings or [],
        "assertions": assertions,
    }


def requisition_submit() -> dict[str, object]:
    fixture_id = "6167e65c-6f56-4aeb-bff5-fdfe84e01a21"
    bound_path = ["/api/requisitions/", {"$binding": "requisition_id"}]
    submit_path = [*bound_path, "/submit"]
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_requisition_submit_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_initiated_fixture",
                operation_id="requisition.get",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=f"/api/requisitions/{fixture_id}",
                bindings=[
                    {
                        "binding_id": "requisition_id",
                        "pointer": "/id",
                        "value_type": "string",
                    }
                ],
                assertions=[
                    assertion("fixture_read_status", "status_equals", expected=200),
                    assertion(
                        "fixture_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "fixture_is_initiated",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                ],
            ),
            step(
                step_id="submit_without_create_right",
                operation_id="requisition.submit",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="POST",
                path=submit_path,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="submit_initiated_requisition",
                operation_id="requisition.submit",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="POST",
                path=submit_path,
                assertions=[
                    assertion("submit_status", "status_equals", expected=200),
                    assertion(
                        "submitted_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "submitted_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="SUBMITTED",
                    ),
                    assertion(
                        "submit_changed_status",
                        "state_changes_from_step",
                        pointer="/status",
                        prior_step_id="read_initiated_fixture",
                        prior_pointer="/status",
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_submit",
                operation_id="requisition.submit",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="POST",
                path=submit_path,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="submit_initiated_requisition",
                    )
                ],
            ),
            step(
                step_id="read_after_repeat",
                operation_id="requisition.get",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path=bound_path,
                assertions=[
                    assertion(
                        "resulting_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "resulting_status_observation",
                        "state_observe_step",
                        pointer="/status",
                        prior_step_id="submit_initiated_requisition",
                        prior_pointer="/status",
                    ),
                ],
            ),
        ],
    }


def requisition_authorize() -> dict[str, object]:
    fixture_id = "6167e65c-6f56-4aeb-bff5-fdfe84e01a21"
    subject_id = "fixture_requisition_6167e65c"
    bound_path = ["/api/requisitions/", {"$binding": "requisition_id"}]
    authorize_path = [*bound_path, "/authorize"]
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_requisition_authorize_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_submitted_fixture",
                operation_id="requisition.get",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=f"/api/requisitions/{fixture_id}",
                subject_id=subject_id,
                bindings=[
                    {
                        "binding_id": "requisition_id",
                        "pointer": "/id",
                        "value_type": "string",
                    }
                ],
                assertions=[
                    assertion("fixture_read_status", "status_equals", expected=200),
                    assertion(
                        "fixture_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "fixture_is_submitted",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="SUBMITTED",
                    ),
                ],
            ),
            step(
                step_id="authorize_without_authorize_right",
                operation_id="requisition.authorize",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="srmanager2",
                method="POST",
                path=authorize_path,
                subject_id=subject_id,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="authorize_submitted_requisition",
                operation_id="requisition.authorize",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="administrator",
                method="POST",
                path=authorize_path,
                subject_id=subject_id,
                assertions=[
                    assertion("authorize_status", "status_equals", expected=200),
                    assertion(
                        "authorized_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "authorized_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="AUTHORIZED",
                    ),
                    assertion(
                        "authorize_changed_status",
                        "state_changes_from_step",
                        pointer="/status",
                        prior_step_id="read_submitted_fixture",
                        prior_pointer="/status",
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_authorize",
                operation_id="requisition.authorize",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="administrator",
                method="POST",
                path=authorize_path,
                subject_id=subject_id,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="authorize_submitted_requisition",
                    )
                ],
            ),
            step(
                step_id="read_after_repeat",
                operation_id="requisition.get",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path=bound_path,
                subject_id=subject_id,
                assertions=[
                    assertion(
                        "resulting_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "resulting_status_observation",
                        "state_observe_step",
                        pointer="/status",
                        prior_step_id="authorize_submitted_requisition",
                        prior_pointer="/status",
                    ),
                ],
            ),
        ],
    }


def requisition_transition(
    *,
    name: str,
    fixture_id: str,
    before_status: str,
    after_status: str,
    method: str,
    success_actor: str,
    failure_actor: str,
) -> dict[str, object]:
    subject_id = f"fixture_requisition_{fixture_id[:8]}"
    bound_path = ["/api/requisitions/", {"$binding": "requisition_id"}]
    transition_path = [*bound_path, f"/{name}"]
    success_step = f"{name}_{before_status.lower()}_requisition"
    before_step = f"read_{before_status.lower()}_fixture"
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": f"openlmis_requisition_{name}_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id=before_step,
                operation_id="requisition.get",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=f"/api/requisitions/{fixture_id}",
                subject_id=subject_id,
                bindings=[
                    {
                        "binding_id": "requisition_id",
                        "pointer": "/id",
                        "value_type": "string",
                    }
                ],
                assertions=[
                    assertion("fixture_read_status", "status_equals", expected=200),
                    assertion(
                        "fixture_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        f"fixture_is_{before_status.lower()}",
                        "json_pointer_equals",
                        pointer="/status",
                        expected=before_status,
                    ),
                ],
            ),
            step(
                step_id=f"{name}_without_required_right",
                operation_id=f"requisition.{name}",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor=failure_actor,
                method=method,
                path=transition_path,
                subject_id=subject_id,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id=success_step,
                operation_id=f"requisition.{name}",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor=success_actor,
                method=method,
                path=transition_path,
                subject_id=subject_id,
                assertions=[
                    assertion(f"{name}_status", "status_equals", expected=200),
                    assertion(
                        f"{name}_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        f"{name}_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected=after_status,
                    ),
                    assertion(
                        f"{name}_changed_status",
                        "state_changes_from_step",
                        pointer="/status",
                        prior_step_id=before_step,
                        prior_pointer="/status",
                    ),
                ],
            ),
            step(
                step_id=f"repeat_exact_{name}",
                operation_id=f"requisition.{name}",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor=success_actor,
                method=method,
                path=transition_path,
                subject_id=subject_id,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id=success_step,
                    )
                ],
            ),
            step(
                step_id="read_after_repeat",
                operation_id="requisition.get",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path=bound_path,
                subject_id=subject_id,
                assertions=[
                    assertion(
                        "resulting_identity",
                        "json_pointer_equals",
                        pointer="/id",
                        expected=fixture_id,
                    ),
                    assertion(
                        "resulting_status_observation",
                        "state_observe_step",
                        pointer="/status",
                        prior_step_id=success_step,
                        prior_pointer="/status",
                    ),
                ],
            ),
        ],
    }


def requisition_approve() -> dict[str, object]:
    return requisition_transition(
        name="approve",
        fixture_id="074a49af-12c3-429f-b5da-ed3f9e65787c",
        before_status="AUTHORIZED",
        after_status="APPROVED",
        method="POST",
        success_actor="psupervisor",
        failure_actor="srmanager2",
    )


def requisition_skip() -> dict[str, object]:
    prerequisite_id = "6167e65c-6f56-4aeb-bff5-fdfe84e01a21"
    facility_id = "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce"
    program_id = "dce17f2e-af3e-40ad-8e00-3496adef44c3"
    period_id = "c9287c65-67fa-4958-adb6-52069f2b1379"
    initiate_query = {
        "emergency": "false",
        "facility": facility_id,
        "program": program_id,
        "suggestedPeriod": period_id,
    }
    bound_path = ["/api/requisitions/", {"$binding": "created_requisition_id"}]
    skip_path = [*bound_path, "/skip"]
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_requisition_skip_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_apr_prerequisite",
                operation_id="requisition.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=f"/api/requisitions/{prerequisite_id}",
                assertions=[
                    assertion("apr_read_status", "status_equals", expected=200),
                    assertion(
                        "apr_is_initiated",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                ],
            ),
            step(
                step_id="delete_apr_prerequisite",
                operation_id="requisition.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="DELETE",
                path=f"/api/requisitions/{prerequisite_id}",
                assertions=[assertion("apr_delete_status", "status_equals", expected=204)],
            ),
            step(
                step_id="initiate_apr_requisition",
                operation_id="requisition.initiate",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="POST",
                path="/api/requisitions/initiate",
                query=initiate_query,
                bindings=[
                    {
                        "binding_id": "created_requisition_id",
                        "pointer": "/id",
                        "value_type": "string",
                    }
                ],
                assertions=[
                    assertion("initiate_status", "status_equals", expected=201),
                    assertion(
                        "initiated_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                ],
            ),
            step(
                step_id="read_newly_initiated_requisition",
                operation_id="requisition.get",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=bound_path,
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "before_is_initiated",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                ],
            ),
            step(
                step_id="skip_without_required_right",
                operation_id="requisition.skip",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="PUT",
                path=skip_path,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="skip_newly_initiated_requisition",
                operation_id="requisition.skip",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="PUT",
                path=skip_path,
                assertions=[
                    assertion("skip_status", "status_equals", expected=200),
                    assertion(
                        "skip_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="SKIPPED",
                    ),
                    assertion(
                        "skip_changed_status",
                        "state_changes_from_step",
                        pointer="/status",
                        prior_step_id="read_newly_initiated_requisition",
                        prior_pointer="/status",
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_skip",
                operation_id="requisition.skip",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="PUT",
                path=skip_path,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="skip_newly_initiated_requisition",
                    )
                ],
            ),
            step(
                step_id="read_after_repeat",
                operation_id="requisition.get",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path=bound_path,
                assertions=[
                    assertion(
                        "resulting_status_observation",
                        "state_observe_step",
                        pointer="/status",
                        prior_step_id="skip_newly_initiated_requisition",
                        prior_pointer="/status",
                    )
                ],
            ),
        ],
    }


def requisition_initiate() -> dict[str, object]:
    prerequisite_requisition_id = "6167e65c-6f56-4aeb-bff5-fdfe84e01a21"
    facility_id = "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce"
    program_id = "dce17f2e-af3e-40ad-8e00-3496adef44c3"
    period_id = "c9287c65-67fa-4958-adb6-52069f2b1379"
    initiate_query = {
        "emergency": "false",
        "facility": facility_id,
        "program": program_id,
        "suggestedPeriod": period_id,
    }
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_requisition_initiate_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_apr_prerequisite",
                operation_id="requisition.get",
                kind="read",
                role="supporting",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=f"/api/requisitions/{prerequisite_requisition_id}",
                subject_id="hc01_prg001_apr2017_prerequisite",
                assertions=[
                    assertion("apr_read_status", "status_equals", expected=200),
                    assertion(
                        "apr_is_initiated",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                ],
            ),
            step(
                step_id="delete_apr_prerequisite",
                operation_id="requisition.delete",
                kind="mutation",
                role="supporting",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="DELETE",
                path=f"/api/requisitions/{prerequisite_requisition_id}",
                subject_id="hc01_prg001_apr2017_prerequisite",
                assertions=[
                    assertion("apr_delete_status", "status_equals", expected=204),
                ],
            ),
            step(
                step_id="read_available_periods",
                operation_id="requisition.periods_for_initiate",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path="/api/requisitions/periodsForInitiate",
                subject_id="hc01_prg001_may2017_requisition",
                query={
                    "emergency": "false",
                    "facilityId": facility_id,
                    "programId": program_id,
                    "unfinished": "false",
                },
                assertions=[
                    assertion("periods_status", "status_equals", expected=200),
                    assertion(
                        "apr_period_available",
                        "json_pointer_equals",
                        pointer="/0/id",
                        expected=period_id,
                    ),
                ],
            ),
            step(
                step_id="initiate_without_create_right",
                operation_id="requisition.initiate",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="POST",
                path="/api/requisitions/initiate",
                subject_id="hc01_prg001_may2017_requisition",
                query=initiate_query,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="initiate_apr_requisition",
                operation_id="requisition.initiate",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="POST",
                path="/api/requisitions/initiate",
                subject_id="hc01_prg001_may2017_requisition",
                query=initiate_query,
                bindings=[
                    {
                        "binding_id": "created_requisition_id",
                        "pointer": "/id",
                        "value_type": "string",
                    }
                ],
                assertions=[
                    assertion("initiate_status", "status_equals", expected=201),
                    assertion(
                        "initiated_state",
                        "json_pointer_equals",
                        pointer="/status",
                        expected="INITIATED",
                    ),
                    assertion(
                        "initiated_period",
                        "json_pointer_equals",
                        pointer="/processingPeriod/id",
                        expected=period_id,
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_initiate",
                operation_id="requisition.initiate",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="POST",
                path="/api/requisitions/initiate",
                subject_id="hc01_prg001_may2017_requisition",
                query=initiate_query,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="initiate_apr_requisition",
                    )
                ],
            ),
            step(
                step_id="read_created_requisition",
                operation_id="requisition.get",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path=[
                    "/api/requisitions/",
                    {"$binding": "created_requisition_id"},
                ],
                subject_id="hc01_prg001_may2017_requisition",
                assertions=[
                    assertion(
                        "created_identity",
                        "json_pointer_type",
                        pointer="/id",
                        value_type="string",
                    ),
                    assertion(
                        "created_status_observation",
                        "state_observe_step",
                        pointer="/status",
                        prior_step_id="initiate_apr_requisition",
                        prior_pointer="/status",
                    ),
                ],
            ),
        ],
    }


def notification_create() -> dict[str, object]:
    user_id = "a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
    notification = {
        "userId": user_id,
        "important": False,
        "messages": {
            "email": {
                "subject": "Datalox behavior harvest 20260805",
                "body": "Disposable OpenLMIS notification behavior probe.",
            }
        },
    }
    read_query = {"userId": user_id, "page": 0, "size": 100}
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_notification_create_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_recipient_notifications_before",
                operation_id="notification.list_notifications",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path="/api/notifications",
                query=read_query,
                subject_id="administrator_notifications",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "one_baseline_notification",
                        "json_pointer_equals",
                        pointer="/totalElements",
                        expected=1,
                    ),
                ],
            ),
            step(
                step_id="create_without_send_right",
                operation_id="notification.create_notification",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="POST",
                path="/api/notifications",
                subject_id="administrator_notifications",
                body_value=notification,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="create_notification",
                operation_id="notification.create_notification",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="administrator",
                method="POST",
                path="/api/notifications",
                subject_id="administrator_notifications",
                body_value=notification,
                assertions=[assertion("create_status", "status_equals", expected=200)],
            ),
            step(
                step_id="repeat_exact_notification",
                operation_id="notification.create_notification",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="administrator",
                method="POST",
                path="/api/notifications",
                subject_id="administrator_notifications",
                body_value=notification,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="create_notification",
                    )
                ],
            ),
            step(
                step_id="read_recipient_notifications_after",
                operation_id="notification.list_notifications",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="administrator",
                method="GET",
                path="/api/notifications",
                query=read_query,
                subject_id="administrator_notifications",
                assertions=[
                    assertion("after_status", "status_equals", expected=200),
                    assertion(
                        "duplicate_created_two_records",
                        "json_pointer_equals",
                        pointer="/totalElements",
                        expected=3,
                    ),
                    assertion(
                        "notification_count_changed",
                        "state_changes_from_step",
                        pointer="/totalElements",
                        prior_step_id="read_recipient_notifications_before",
                        prior_pointer="/totalElements",
                    ),
                ],
            ),
        ],
    }


def notification_update_contact() -> dict[str, object]:
    user_id = "a337ec45-31a0-4f2b-9b2e-a105c4b669bb"
    path = f"/api/userContactDetails/{user_id}"
    update = {
        "referenceDataUserId": user_id,
        "phoneNumber": "+12025550101",
        "allowNotify": True,
        "emailDetails": {
            "email": "administrator@openlmis.org",
            "emailVerified": True,
        },
    }
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_notification_update_contact_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_contact_before",
                operation_id="notification.get_contact_details",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=path,
                subject_id="administrator_contact",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "phone_is_unset",
                        "json_pointer_equals",
                        pointer="/phoneNumber",
                        expected=None,
                    ),
                ],
            ),
            step(
                step_id="update_cross_user_without_right",
                operation_id="notification.update_contact_details",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="PUT",
                path=path,
                subject_id="administrator_contact",
                body_value=update,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_json_body",
                        "json_pointer_type",
                        pointer="",
                        value_type="object",
                    ),
                ],
            ),
            step(
                step_id="update_contact",
                operation_id="notification.update_contact_details",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="administrator",
                method="PUT",
                path=path,
                subject_id="administrator_contact",
                body_value=update,
                assertions=[
                    assertion("update_status", "status_equals", expected=200),
                    assertion(
                        "phone_updated",
                        "json_pointer_equals",
                        pointer="/phoneNumber",
                        expected="+12025550101",
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_contact_update",
                operation_id="notification.update_contact_details",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="administrator",
                method="PUT",
                path=path,
                subject_id="administrator_contact",
                body_value=update,
                assertions=[
                    assertion(
                        "exact_request_repeat",
                        "request_equals_step",
                        prior_step_id="update_contact",
                    )
                ],
            ),
            step(
                step_id="read_contact_after",
                operation_id="notification.get_contact_details",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                actor="administrator",
                method="GET",
                path=path,
                subject_id="administrator_contact",
                assertions=[
                    assertion("after_status", "status_equals", expected=200),
                    assertion(
                        "phone_persisted",
                        "json_pointer_equals",
                        pointer="/phoneNumber",
                        expected="+12025550101",
                    ),
                    assertion(
                        "phone_changed",
                        "state_changes_from_step",
                        pointer="/phoneNumber",
                        prior_step_id="read_contact_before",
                        prior_pointer="/phoneNumber",
                    ),
                ],
            ),
        ],
    }


def stock_create_physical_inventory() -> dict[str, object]:
    facility_id = "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce"
    program_id = "dce17f2e-af3e-40ad-8e00-3496adef44c3"
    body = {"facilityId": facility_id, "programId": program_id, "lineItems": []}
    search_query = {"facility": facility_id, "program": program_id, "isDraft": "true"}
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_stock_create_physical_inventory_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_drafts_before",
                operation_id="stock.list_physical_inventories",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path="/api/physicalInventories",
                query=search_query,
                subject_id="hc01_prg001_physical_inventory",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion("no_baseline_draft", "json_pointer_equals", pointer="", expected=[]),
                ],
            ),
            step(
                step_id="create_draft_without_right",
                operation_id="stock.create_physical_inventory",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="POST",
                path="/api/physicalInventories",
                subject_id="hc01_prg001_physical_inventory",
                body_value=body,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_body", "json_pointer_type", pointer="", value_type="object"
                    ),
                ],
            ),
            step(
                step_id="create_draft",
                operation_id="stock.create_physical_inventory",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="POST",
                path="/api/physicalInventories",
                subject_id="hc01_prg001_physical_inventory",
                body_value=body,
                bindings=[{"binding_id": "inventory_id", "pointer": "/id", "value_type": "string"}],
                assertions=[
                    assertion("create_status", "status_equals", expected=201),
                    assertion(
                        "created_id", "json_pointer_type", pointer="/id", value_type="string"
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_draft_create",
                operation_id="stock.create_physical_inventory",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="POST",
                path="/api/physicalInventories",
                subject_id="hc01_prg001_physical_inventory",
                body_value=body,
                assertions=[
                    assertion(
                        "exact_request_repeat", "request_equals_step", prior_step_id="create_draft"
                    )
                ],
            ),
            step(
                step_id="read_created_draft",
                operation_id="stock.get_physical_inventory",
                kind="read",
                role="resulting_state",
                expected_outcome="observe",
                actor="srmanager2",
                method="GET",
                path=["/api/physicalInventories/", {"$binding": "inventory_id"}],
                subject_id="hc01_prg001_physical_inventory",
                assertions=[
                    assertion(
                        "created_id_persisted",
                        "state_observe_step",
                        pointer="/id",
                        prior_step_id="create_draft",
                        prior_pointer="/id",
                    ),
                ],
            ),
        ],
    }


def stock_update_physical_inventory() -> dict[str, object]:
    inventory_id = "4015384d-6083-4728-871b-c3182d125faa"
    path = f"/api/physicalInventories/{inventory_id}"
    body = {
        "id": inventory_id,
        "programId": "dce17f2e-af3e-40ad-8e00-3496adef44c3",
        "facilityId": "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce",
        "occurredDate": None,
        "signature": "Datalox behavior harvest 20260805 v2",
        "documentNumber": None,
        "isStarter": False,
        "isDraft": True,
        "lineItems": [
            {
                "orderableId": "880cf2eb-7b68-4450-a037-a0dec1a17987",
                "stockOnHand": 70,
                "quantity": 70,
                "stockAdjustments": [],
                "extraData": {},
            }
        ],
    }
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_stock_update_physical_inventory_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_draft_before_update",
                operation_id="stock.get_physical_inventory",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path=path,
                subject_id="hc01_prg001_physical_inventory_update",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "signature_has_discovery_update",
                        "json_pointer_equals",
                        pointer="/signature",
                        expected="Datalox behavior harvest 20260805",
                    ),
                ],
            ),
            step(
                step_id="update_draft_without_right",
                operation_id="stock.update_physical_inventory",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="PUT",
                path=path,
                subject_id="hc01_prg001_physical_inventory_update",
                body_value=body,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_body", "json_pointer_type", pointer="", value_type="object"
                    ),
                ],
            ),
            step(
                step_id="update_draft",
                operation_id="stock.update_physical_inventory",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="PUT",
                path=path,
                subject_id="hc01_prg001_physical_inventory_update",
                body_value=body,
                assertions=[
                    assertion("update_status", "status_equals", expected=200),
                    assertion(
                        "signature_updated",
                        "json_pointer_equals",
                        pointer="/signature",
                        expected=body["signature"],
                    ),
                ],
            ),
            step(
                step_id="repeat_exact_draft_update",
                operation_id="stock.update_physical_inventory",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="PUT",
                path=path,
                subject_id="hc01_prg001_physical_inventory_update",
                body_value=body,
                assertions=[
                    assertion(
                        "exact_request_repeat", "request_equals_step", prior_step_id="update_draft"
                    )
                ],
            ),
            step(
                step_id="read_draft_after_update",
                operation_id="stock.get_physical_inventory",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path=path,
                subject_id="hc01_prg001_physical_inventory_update",
                assertions=[
                    assertion("after_status", "status_equals", expected=200),
                    assertion(
                        "signature_persisted",
                        "json_pointer_equals",
                        pointer="/signature",
                        expected=body["signature"],
                    ),
                    assertion(
                        "signature_changed",
                        "state_changes_from_step",
                        pointer="/signature",
                        prior_step_id="read_draft_before_update",
                        prior_pointer="/signature",
                    ),
                ],
            ),
        ],
    }


def stock_delete_physical_inventory() -> dict[str, object]:
    inventory_id = "4015384d-6083-4728-871b-c3182d125faa"
    path = f"/api/physicalInventories/{inventory_id}"
    search_query = {
        "facility": "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce",
        "program": "dce17f2e-af3e-40ad-8e00-3496adef44c3",
        "isDraft": "true",
    }
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_stock_delete_physical_inventory_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_draft_before_delete",
                operation_id="stock.get_physical_inventory",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path=path,
                subject_id="hc01_prg001_physical_inventory_delete",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "fixture_id", "json_pointer_equals", pointer="/id", expected=inventory_id
                    ),
                ],
            ),
            step(
                step_id="delete_draft_without_right",
                operation_id="stock.delete_physical_inventory",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="DELETE",
                path=path,
                subject_id="hc01_prg001_physical_inventory_delete",
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_body", "json_pointer_type", pointer="", value_type="object"
                    ),
                ],
            ),
            step(
                step_id="delete_draft",
                operation_id="stock.delete_physical_inventory",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="DELETE",
                path=path,
                subject_id="hc01_prg001_physical_inventory_delete",
                assertions=[assertion("delete_status", "status_equals", expected=204)],
            ),
            step(
                step_id="repeat_exact_draft_delete",
                operation_id="stock.delete_physical_inventory",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="DELETE",
                path=path,
                subject_id="hc01_prg001_physical_inventory_delete",
                assertions=[
                    assertion(
                        "exact_request_repeat", "request_equals_step", prior_step_id="delete_draft"
                    )
                ],
            ),
            step(
                step_id="read_drafts_after_delete",
                operation_id="stock.list_physical_inventories",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path="/api/physicalInventories",
                query=search_query,
                subject_id="hc01_prg001_physical_inventory_delete",
                assertions=[
                    assertion("after_status", "status_equals", expected=200),
                    assertion("draft_removed", "json_pointer_equals", pointer="", expected=[]),
                    assertion(
                        "draft_state_changed",
                        "state_changes_from_step",
                        pointer="",
                        prior_step_id="read_draft_before_delete",
                        prior_pointer="",
                    ),
                ],
            ),
        ],
    }


def stock_create_event() -> dict[str, object]:
    stock_card_id = "298e5448-7581-46e9-a271-0331723ac603"
    summary_query = {
        "facility": "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce",
        "program": "dce17f2e-af3e-40ad-8e00-3496adef44c3",
        "page": 0,
        "size": 100,
    }
    body = {
        "facilityId": "e6799d64-d10d-4011-b8c2-0e4d4a3f65ce",
        "programId": "dce17f2e-af3e-40ad-8e00-3496adef44c3",
        "signature": "Datalox behavior harvest",
        "documentNumber": "DATALOX-BEHAVIOR-20260805-STOCK-1",
        "lineItems": [
            {
                "orderableId": "880cf2eb-7b68-4450-a037-a0dec1a17987",
                "quantity": 1,
                "reasonId": "279d55bd-42e3-438c-a63d-9c021b185dae",
                "occurredDate": "2026-08-05",
                "stockAdjustments": [],
                "extraData": {},
            }
        ],
    }
    return {
        "schema_id": "datalox_behavior_recipe_v1",
        "program_id": "openlmis_stock_create_event_v1",
        "seed": 20260805,
        "requirements": {
            "success": True,
            "duplicate": True,
            "native_failure": True,
            "resulting_state": True,
        },
        "steps": [
            step(
                step_id="read_stock_card_before",
                operation_id="stock.list_stock_card_summaries",
                kind="read",
                role="before",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path="/api/stockCardSummaries",
                query=summary_query,
                subject_id="hc01_prg001_c500_stock_card",
                assertions=[
                    assertion("before_status", "status_equals", expected=200),
                    assertion(
                        "baseline_card",
                        "json_pointer_equals",
                        pointer="/content/0/id",
                        expected=stock_card_id,
                    ),
                    assertion(
                        "baseline_soh",
                        "json_pointer_equals",
                        pointer="/content/0/stockOnHand",
                        expected=70,
                    ),
                ],
            ),
            step(
                step_id="create_event_without_right",
                operation_id="stock.create_event",
                kind="mutation",
                role="native_failure",
                expected_outcome="native_failure",
                actor="psupervisor",
                method="POST",
                path="/api/stockEvents",
                subject_id="hc01_prg001_c500_stock_card",
                body_value=body,
                assertions=[
                    assertion("forbidden_status", "status_equals", expected=403),
                    assertion(
                        "forbidden_body", "json_pointer_type", pointer="", value_type="object"
                    ),
                ],
            ),
            step(
                step_id="create_event",
                operation_id="stock.create_event",
                kind="mutation",
                role="success",
                expected_outcome="mutation_success",
                actor="srmanager2",
                method="POST",
                path="/api/stockEvents",
                subject_id="hc01_prg001_c500_stock_card",
                body_value=body,
                assertions=[
                    assertion("create_status", "status_equals", expected=201),
                    assertion("event_id", "json_pointer_type", pointer="", value_type="string"),
                ],
            ),
            step(
                step_id="repeat_exact_event",
                operation_id="stock.create_event",
                kind="mutation",
                role="duplicate",
                expected_outcome="observe",
                actor="srmanager2",
                method="POST",
                path="/api/stockEvents",
                subject_id="hc01_prg001_c500_stock_card",
                body_value=body,
                assertions=[
                    assertion(
                        "exact_request_repeat", "request_equals_step", prior_step_id="create_event"
                    )
                ],
            ),
            step(
                step_id="read_stock_card_after",
                operation_id="stock.list_stock_card_summaries",
                kind="read",
                role="resulting_state",
                expected_outcome="read_success",
                actor="srmanager2",
                method="GET",
                path="/api/stockCardSummaries",
                query=summary_query,
                subject_id="hc01_prg001_c500_stock_card",
                assertions=[
                    assertion("after_status", "status_equals", expected=200),
                    assertion(
                        "duplicate_applied_twice",
                        "json_pointer_equals",
                        pointer="/content/0/stockOnHand",
                        expected=72,
                    ),
                    assertion(
                        "soh_changed",
                        "state_changes_from_step",
                        pointer="/content/0/stockOnHand",
                        prior_step_id="read_stock_card_before",
                        prior_pointer="/content/0/stockOnHand",
                    ),
                ],
            ),
        ],
    }


ARTIFACTS = {
    EVIDENCE / "requisition_submit.behavior_recipe_v1.json": requisition_submit,
    EVIDENCE / "requisition_authorize.behavior_recipe_v1.json": requisition_authorize,
    EVIDENCE / "requisition_approve.behavior_recipe_v1.json": requisition_approve,
    EVIDENCE / "requisition_skip.behavior_recipe_v1.json": requisition_skip,
    EVIDENCE / "requisition_initiate.behavior_recipe_v1.json": requisition_initiate,
    EVIDENCE / "notification_create.behavior_recipe_v1.json": notification_create,
    EVIDENCE / "notification_update_contact.behavior_recipe_v1.json": notification_update_contact,
    EVIDENCE
    / "stock_create_physical_inventory.behavior_recipe_v1.json": stock_create_physical_inventory,
    EVIDENCE
    / "stock_update_physical_inventory.behavior_recipe_v1.json": stock_update_physical_inventory,
    EVIDENCE
    / "stock_delete_physical_inventory.behavior_recipe_v1.json": stock_delete_physical_inventory,
    EVIDENCE / "stock_create_event.behavior_recipe_v1.json": stock_create_event,
}


def body(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stale: list[str] = []
    for path, build in ARTIFACTS.items():
        expected = body(build())
        if args.check:
            if not path.is_file() or path.read_text(encoding="utf-8") != expected:
                stale.append(str(path.relative_to(ROOT)))
        else:
            path.write_text(expected, encoding="utf-8")
            print(f"wrote {path.relative_to(ROOT)}")
    if stale:
        for path in stale:
            print(f"stale: {path}")
        return 1
    if args.check:
        print("OpenLMIS behavior recipes are current.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
