from __future__ import annotations

import asyncio
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import ProviderRuntime
from datalox_gated_runtime.provider_runtime.release import load_provider_release

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_ROOT = ROOT / "integrations" / "verifiers_dirty_integration"
sys.path.insert(0, str(INTEGRATION_ROOT))

from datalox_dirty_integration.contract import (  # noqa: E402
    TASK_INSTRUCTIONS,
    provider_admission_path,
    provider_config_path,
    provider_release_path,
    provider_runtime_bundle_path,
)
from datalox_dirty_integration.episode import CommerceEpisode  # noqa: E402
from datalox_dirty_integration.paired import calibrate, run_pair  # noqa: E402
from datalox_dirty_integration.policy import (  # noqa: E402
    LIST_PRODUCTS_OPERATION,
    SeededCommercePolicy,
    load_profile,
)
from datalox_dirty_integration.scoring import EvaluationOracle  # noqa: E402


def _episode(*, profile: str, seed: str, enabled: bool) -> CommerceEpisode:
    return CommerceEpisode(
        provider_config=provider_config_path(),
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
        policy=SeededCommercePolicy(load_profile(profile)),
        intervention_seed=seed,
        intervention_enabled=enabled,
    )


def _fixed_pages(episode: CommerceEpisode) -> list[dict[str, Any]]:
    return [
        {
            "status_code": response.status_code,
            "headers": response.headers,
            "body": response.body,
        }
        for response in (episode.list_products(offset=offset) for offset in range(0, 51, 10))
    ]


def _policy_schedule(profile: str, seed: str) -> tuple[str | None, ...]:
    with _episode(profile=profile, seed=seed, enabled=False) as episode:
        _fixed_pages(episode)
        events = episode.export()["intervention"]["events"]
        return tuple(event["decision"]["kind"] for event in events)


def _behavioral_event(event: dict[str, Any]) -> dict[str, Any]:
    normalized = deepcopy(event)
    normalized["base"].pop("event_id", None)
    source = normalized["decision"].get("source_base")
    if isinstance(source, dict):
        source.pop("event_id", None)
    return normalized


def test_episode_binds_the_exact_admitted_oci_release() -> None:
    release = load_provider_release(provider_release_path())
    with _episode(profile="clean", seed="7", enabled=False) as episode:
        exported = episode.export()
        intervention = exported["intervention"]

    assert exported["provider_release_digest"] == release.manifest_descriptor["digest"]
    assert exported["provider_release_config_sha256"] == release.manifest["config"]["digest"]
    assert exported["provider_release_version"] == release.release_version
    assert exported["provider_profile_id"] == "default"
    assert exported["provider_bundle_version"] == release.config["bundle_version"]
    assert exported["operation_contract_sha256"] == release.config["operation_contract_sha256"]
    assert intervention["provider"] == {
        "provider_id": release.provider_id,
        "release_version": release.release_version,
        "profile_id": "default",
        "bundle_version": release.config["bundle_version"],
        "release_config_sha256": release.manifest["config"]["digest"],
        "provider_runtime_sha256": release.profiles[0].provider_runtime_sha256,
        "provider_admission_sha256": release.profiles[0].provider_admission_sha256,
        "operation_contract_sha256": release.config["operation_contract_sha256"],
    }
    assert intervention["admitted_read_operation_ids"] == [LIST_PRODUCTS_OPERATION]


def test_off_mode_is_wire_equivalent_to_direct_provider_execution(tmp_path: Path) -> None:
    direct = ProviderRuntime(
        bundle_dir=provider_runtime_bundle_path(),
        admission_path=provider_admission_path(),
        run_dir=tmp_path / "direct-run",
    )
    try:
        with _episode(profile="hostile", seed="7", enabled=False) as episode:
            for offset in range(0, 51, 10):
                request = CallRequest(
                    method="GET",
                    scheme="https",
                    authority="api.medusa.local",
                    path="/store/products",
                    query={"limit": "10", "offset": str(offset)},
                    operation_id=LIST_PRODUCTS_OPERATION,
                )
                delivered = episode.list_products(offset=offset)
                base = direct.handle(request)
                assert (
                    delivered.status_code,
                    delivered.headers,
                    delivered.body,
                ) == (base.status_code, base.headers, base.body)
            events = episode.export()["intervention"]["events"]
    finally:
        direct.close()

    assert all(event["enabled"] is False for event in events)
    assert all(event["applied"] is False for event in events)
    assert all(
        event["base"]["response_sha256"] == event["delivered"]["response_sha256"]
        for event in events
    )


def test_switch_changes_delivery_only_not_seeded_decisions_or_base() -> None:
    with _episode(profile="hostile", seed="7", enabled=False) as off:
        _fixed_pages(off)
        off_export = off.export()
    with _episode(profile="hostile", seed="7", enabled=True) as on:
        _fixed_pages(on)
        on_export = on.export()

    off_events = off_export["intervention"]["events"]
    on_events = on_export["intervention"]["events"]
    assert off_export["initial_state_fingerprint"] == on_export["initial_state_fingerprint"]
    assert [event["event_id"] for event in off_events] == [event["event_id"] for event in on_events]
    assert [event["decision"]["decision_id"] for event in off_events] == [
        event["decision"]["decision_id"] for event in on_events
    ]
    assert [event["decision"]["action"] for event in off_events] == [
        event["decision"]["action"] for event in on_events
    ]
    assert [event["base"]["response_sha256"] for event in off_events] == [
        event["base"]["response_sha256"] for event in on_events
    ]
    assert any(event["applied"] for event in on_events)


def test_reset_reproduces_provider_and_intervention_behavior() -> None:
    with _episode(profile="hostile", seed="7", enabled=True) as episode:
        first = _fixed_pages(episode)
        first_trace = episode.export()["intervention"]
        episode.reset()
        second = _fixed_pages(episode)
        second_trace = episode.export()["intervention"]

    assert first == second
    assert [_behavioral_event(event) for event in first_trace["events"]] == [
        _behavioral_event(event) for event in second_trace["events"]
    ]


def test_policy_is_seed_deterministic_and_seed_sensitive() -> None:
    first = _policy_schedule("hostile", "7")
    assert first == _policy_schedule("hostile", "7")
    schedules = {_policy_schedule("hostile", str(seed)) for seed in range(1, 9)}
    assert len(schedules) > 1


def test_declared_calibration_separates_correctness_and_request_discipline() -> None:
    common = {
        "provider_config": provider_config_path(),
        "provider_admission": provider_admission_path(),
        "provider_runtime_bundle": provider_runtime_bundle_path(),
        "provider_release": provider_release_path(),
        "seeds": range(1, 11),
    }
    clean = calibrate(profile="clean", **common)
    hostile = calibrate(profile="hostile", **common)

    assert all(item["task_correctness"] == 1.0 for item in clean["careful"])
    assert all(item["request_discipline"] == 1.0 for item in clean["careful"])
    assert all(item["task_correctness"] == 1.0 for item in hostile["careful"])
    assert all(item["outcome"] == "submitted" for item in hostile["careful"])
    assert any(item["request_discipline"] < 1.0 for item in hostile["careful"])
    assert any(item["task_correctness"] < 1.0 for item in hostile["naive"])


def test_pair_is_portable_and_binds_one_controlled_variable(tmp_path: Path) -> None:
    output = tmp_path / "pair"
    comparison = run_pair(
        output=output,
        provider_config=provider_config_path(),
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
        profile="hostile",
        intervention_seed="7",
    )
    manifest = json.loads((output / "pair-manifest.json").read_text(encoding="utf-8"))
    rendered = json.dumps(manifest, sort_keys=True)

    assert all(comparison["binding_checks"].values())
    assert manifest["controlled_variable"] == {
        "name": "intervention_enabled",
        "off": False,
        "on": True,
    }
    assert "/Users/" not in rendered
    assert str(ROOT) not in rendered
    assert (output / "off" / "agent-trace.json").is_file()
    assert (output / "on" / "intervention-trace.json").is_file()


def test_task_plane_contains_no_intervention_hints_or_evaluation_truth() -> None:
    lowered = TASK_INSTRUCTIONS.lower()
    for marker in ("repeat", "quota", "type drift", "fault", "intervention", "retry"):
        assert marker not in lowered
    oracle = EvaluationOracle.from_provider_config(provider_config_path())
    for product in oracle.products:
        assert product["id"] not in TASK_INSTRUCTIONS
        assert product["title"] not in TASK_INSTRUCTIONS


@pytest.mark.skipif(
    importlib.util.find_spec("verifiers") is None,
    reason="Verifiers 0.3.1 is installed by the downstream integration package",
)
def test_verifiers_client_never_receives_private_provider_or_evaluation_objects() -> None:
    import verifiers as vf

    from datalox_gated_runtime.interception.interventions import DeliveryInterventionSession

    class RecordingClient(vf.Client):
        def __init__(self) -> None:
            super().__init__(object())
            self.states: list[dict[str, Any]] = []

        async def get_response(self, **kwargs: Any) -> Any:
            self.states.append(dict(kwargs["state"]))
            return vf.Response(
                id="recording-response",
                created=0,
                model=kwargs["model"],
                usage=vf.Usage(
                    prompt_tokens=1,
                    reasoning_tokens=0,
                    completion_tokens=1,
                    total_tokens=2,
                ),
                message=vf.ResponseMessage(
                    role="assistant",
                    content="done",
                    finish_reason="stop",
                    is_truncated=False,
                    tokens=None,
                ),
            )

        def setup_client(self, config: Any) -> Any:
            raise AssertionError("recording client does not use a client config")

        async def to_native_tool(self, tool: Any) -> Any:
            raise AssertionError("get_response is implemented directly")

        async def to_native_prompt(self, messages: Any) -> Any:
            raise AssertionError("get_response is implemented directly")

        async def get_native_response(self, *args: Any, **kwargs: Any) -> Any:
            raise AssertionError("get_response is implemented directly")

        async def raise_from_native_response(self, response: Any) -> None:
            raise AssertionError("get_response is implemented directly")

        async def from_native_response(self, response: Any) -> Any:
            raise AssertionError("get_response is implemented directly")

        async def close(self) -> None:
            return None

    class ErrorClient(RecordingClient):
        async def get_response(self, **kwargs: Any) -> Any:
            self.states.append(dict(kwargs["state"]))
            raise vf.ModelError("recording failure")

    async def run() -> None:
        environment = vf.load_environment(
            "datalox-dirty-integration",
            profile="hostile",
            intervention_enabled=True,
            intervention_seed="controller-private-seed",
            num_tasks=1,
        )
        client = RecordingClient()
        state = await environment.rollout(environment.dataset[0], client, "recording-model")
        assert client.states
        assert environment._episodes == {}
        await environment.rubric.score_rollout(state)
        assert state["metrics"]["reward_task_correctness"] == 0.0
        await environment.rubric.cleanup(state)
        assert environment._score_cache == {}

        forbidden_types = (
            CommerceEpisode,
            EvaluationOracle,
            ProviderRuntime,
            DeliveryInterventionSession,
        )
        for visible_state in client.states:
            assert not _contains_instance(visible_state, forbidden_types)
            rendered = json.dumps(_json_safe(visible_state), sort_keys=True).lower()
            for marker in (
                "controller-private-seed",
                "intervention_seed",
                "intervention_enabled",
                "profile_name",
                "datalox_episode",
                "evaluationoracle",
                "provider_config",
                "prod_datalox_pagination_",
            ):
                assert marker not in rendered

        failing_environment = vf.load_environment(
            "datalox-dirty-integration",
            profile="hostile",
            intervention_enabled=True,
            intervention_seed="controller-private-error-seed",
            num_tasks=1,
        )
        failing_client = ErrorClient()
        failed_state = await failing_environment.rollout(
            failing_environment.dataset[0], failing_client, "recording-model"
        )
        assert failed_state["error"] is not None
        assert failing_environment._episodes == {}
        assert failed_state["trajectory_id"] in failing_environment._score_cache
        await failing_environment.rubric.cleanup(failed_state)
        assert failing_environment._score_cache == {}

    asyncio.run(run())


def _contains_instance(value: Any, forbidden_types: tuple[type[Any], ...]) -> bool:
    if isinstance(value, forbidden_types):
        return True
    if isinstance(value, dict):
        return any(
            _contains_instance(key, forbidden_types) or _contains_instance(item, forbidden_types)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple, set)):
        return any(_contains_instance(item, forbidden_types) for item in value)
    return False


def _json_safe(value: Any) -> Any:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return type(value).__name__
