import hashlib
import json
from pathlib import Path

import jsonschema
from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    PROVIDER_ID,
    build_stateful_provider_bundle,
    write_replay_provider_config,
)

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    build_provider_runtime_from_gate_config,
    load_provider_runtime_bundle,
)

ROOT = Path(__file__).resolve().parents[1]


def _build(tmp_path: Path) -> Path:
    return build_stateful_provider_bundle(tmp_path)


def test_provider_bundle_has_no_task_episode_verifier_or_reward_contract(tmp_path: Path) -> None:
    bundle_dir = _build(tmp_path)
    manifest = json.loads((bundle_dir / "provider-runtime.json").read_text(encoding="utf-8"))

    forbidden_keys = {"task", "task_path", "episode", "episodes_path", "verifier_path", "reward"}
    assert forbidden_keys.isdisjoint(manifest)
    assert manifest["schema_version"] == "datalox_provider_runtime_v2"
    assert manifest["authorities"] == [PROVIDER_AUTHORITY]
    assert manifest["wire_protocol"] == "standard_http_v1"
    assert manifest["behavior"]["protocol"] == "world_v1_adapter"
    assert manifest["behavior"]["identity_path"] == "identity.json"
    assert json.loads((bundle_dir / "identity.json").read_text(encoding="utf-8")) == {
        "actor_id": "agent",
        "actor_role": "operator",
        "mode": "fixed",
        "schema_version": "datalox_provider_identity_v1",
    }
    assert not any(
        path.name in {"task.json", "episodes.jsonl", "verifier.json", "reward.json"}
        for path in bundle_dir.rglob("*")
    )
    loaded = load_provider_runtime_bundle(bundle_dir)
    assert "task" not in loaded.seed
    assert "hidden" not in loaded.seed
    assert "expected" not in loaded.seed
    assert not hasattr(loaded.implementation, "task")
    assert not hasattr(loaded.implementation, "verify")

    schema = json.loads(
        (ROOT / "schemas/provider-runtime-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(manifest)
    identity_schema = json.loads(
        (ROOT / "schemas/provider-identity-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(identity_schema)
    jsonschema.Draft202012Validator(identity_schema).validate(
        json.loads((bundle_dir / "identity.json").read_text(encoding="utf-8"))
    )


def test_provider_native_credentials_select_identity_and_agent_cannot_spoof_role(
    tmp_path: Path,
) -> None:
    from world_v1_helpers import create_valid_bundle

    from datalox_gated_runtime.provider_runtime import build_provider_runtime_from_world

    operator_token = "Bearer provider-test-operator"
    viewer_token = "Bearer provider-test-viewer"
    identity_path = tmp_path / "identity-policy.json"
    identity_path.write_text(
        json.dumps(
            {
                "schema_version": "datalox_provider_identity_v1",
                "mode": "credential_map",
                "principals": [
                    {
                        "principal_context_id": "provider_operator",
                        "actor_id": "operator-001",
                        "actor_role": "operator",
                        "credentials": [
                            {
                                "location": "header",
                                "name": "authorization",
                                "value_sha256": (
                                    "sha256:"
                                    + hashlib.sha256(operator_token.encode("utf-8")).hexdigest()
                                ),
                            }
                        ],
                    },
                    {
                        "principal_context_id": "provider_viewer",
                        "actor_id": "viewer-001",
                        "actor_role": "viewer",
                        "credentials": [
                            {
                                "location": "header",
                                "name": "authorization",
                                "value_sha256": (
                                    "sha256:"
                                    + hashlib.sha256(viewer_token.encode("utf-8")).hexdigest()
                                ),
                            }
                        ],
                    },
                ],
                "missing_identity": {
                    "status_code": 401,
                    "body": {"error": "provider_authentication_required"},
                    "headers": {"content-type": "application/json"},
                },
                "invalid_identity": {
                    "status_code": 403,
                    "body": {"error": "provider_identity_invalid"},
                    "headers": {"content-type": "application/json"},
                },
            },
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    source = create_valid_bundle(tmp_path / "identity-source")
    bundle = tmp_path / "identity-bundle"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id=PROVIDER_ID,
        authorities=(PROVIDER_AUTHORITY,),
        episode_id="episode-1",
        identity_policy_path=identity_path,
    )
    compiled_identity = (bundle / "identity.json").read_text(encoding="utf-8")
    assert operator_token not in compiled_identity
    assert viewer_token not in compiled_identity
    identity_schema = json.loads(
        (ROOT / "schemas/provider-identity-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator(identity_schema).validate(json.loads(compiled_identity))
    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=tmp_path / "identity-run")
    try:
        missing = runtime.handle(CallRequest("GET", "/counter"))
        assert missing.status_code == 401
        assert missing.body == {"error": "provider_authentication_required"}

        invalid = runtime.handle(
            CallRequest("GET", "/counter", headers={"authorization": "Bearer wrong"})
        )
        assert invalid.status_code == 403
        assert invalid.body == {"error": "provider_identity_invalid"}

        allowed = runtime.handle(
            CallRequest("GET", "/counter", headers={"authorization": operator_token})
        )
        assert allowed.status_code == 200
        assert allowed.body["actor_role"] == "operator"

        viewer_read = runtime.handle(
            CallRequest("GET", "/counter", headers={"authorization": viewer_token})
        )
        assert viewer_read.status_code == 200
        assert viewer_read.body["actor_role"] == "viewer"
        viewer_write = runtime.handle(
            CallRequest(
                "POST",
                "/counter",
                body={"amount": 9},
                headers={"authorization": viewer_token},
            )
        )
        assert viewer_write.status_code == 403
        assert viewer_write.decision.reason_code == "world_tool_hidden"

        spoofed = runtime.handle(
            CallRequest(
                "POST",
                "/counter",
                body={"amount": 9},
                headers={
                    "authorization": operator_token,
                    "x-datalox-actor-role": "viewer",
                },
            )
        )
        assert spoofed.status_code == 400
        assert spoofed.decision.reason_code == "provider_runtime_reserved_header"

        invented_control = runtime.handle(
            CallRequest(
                "GET",
                "/counter",
                headers={
                    "authorization": operator_token,
                    "x-datalox-invented-control": "value",
                },
            )
        )
        assert invented_control.status_code == 400
        assert invented_control.decision.reason_code == "provider_runtime_reserved_header"
        assert (
            runtime.handle(
                CallRequest("GET", "/counter", headers={"authorization": operator_token})
            ).body["counter"]
            == 1
        )

        for event in runtime.export()["call_evidence"]["events"]:
            assert "authorization" not in {name.lower() for name in event["request"]["headers"]}
            assert "x-datalox-actor-role" not in {
                name.lower() for name in event["request"]["headers"]
            }
    finally:
        runtime.close()


def test_provider_runtime_mutates_reads_back_and_resets_without_world_verifier(
    tmp_path: Path,
) -> None:
    bundle_dir = _build(tmp_path)
    runtime = ProviderRuntime(bundle_dir=bundle_dir, run_dir=tmp_path / "run")
    try:
        before = runtime.export()["provider_state"]["state"]
        response = runtime.handle(
            CallRequest(
                method="POST",
                path="/counter",
                authority=PROVIDER_AUTHORITY,
                body={"amount": 2},
            )
        )
        assert response.status_code == 200
        assert response.body["counter"] == 3
        readback = runtime.handle(
            CallRequest(
                method="GET",
                path="/counter",
                authority=PROVIDER_AUTHORITY,
            )
        )
        assert readback.status_code == 200
        assert readback.body["counter"] == 3
        mutated = runtime.export()["provider_state"]["state"]
        assert mutated != before

        reset = runtime.reset()
        assert reset["provider_state"]["state"] == before
        assert reset["call_evidence"]["events"] == []
    finally:
        runtime.close()


def test_gate_config_provider_bundle_replays_denies_and_resets_without_a_world(
    tmp_path: Path,
) -> None:
    bundle = tmp_path / "replay-provider"
    build_provider_runtime_from_gate_config(
        source_gate_config=write_replay_provider_config(tmp_path),
        output_dir=bundle,
        provider_id=PROVIDER_ID,
        authorities=(PROVIDER_AUTHORITY,),
    )
    raw = json.loads((bundle / "provider-runtime.json").read_text(encoding="utf-8"))
    assert raw["behavior"] == {
        "protocol": "gate_config_v1",
        "config_path": "gate-config.json",
    }
    compiled_config = json.loads((bundle / "gate-config.json").read_text(encoding="utf-8"))
    assert compiled_config["audit_rules"] == []
    assert compiled_config["policy"]["live_capture"] == []
    assert not {"live", "world", "mcp", "auth_profiles"} & set(compiled_config)

    runtime = ProviderRuntime(bundle_dir=bundle, run_dir=tmp_path / "run-replay")
    try:
        replay = runtime.handle(
            CallRequest(
                method="GET",
                authority=PROVIDER_AUTHORITY,
                path="/v1/records",
            )
        )
        assert replay.status_code == 200
        assert replay.response_case_id == "example:records:list"
        denied = runtime.handle(
            CallRequest(
                method="POST",
                authority=PROVIDER_AUTHORITY,
                path="/v1/records",
                body={"name": "must-not-write"},
            )
        )
        assert denied.status_code == 403
        assert denied.decision.reason_code == "example_replay_only"
        assert len(runtime.export()["call_evidence"]["events"]) == 2
        assert runtime.reset()["call_evidence"]["events"] == []
    finally:
        runtime.close()
