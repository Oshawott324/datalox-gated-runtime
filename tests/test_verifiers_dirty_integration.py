from __future__ import annotations

import asyncio
import hashlib
import importlib.util
import json
import sys
from copy import deepcopy
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from datalox_gated_runtime.interception.interventions import DeliveryInterventionSession
from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import ProviderRuntime
from datalox_gated_runtime.provider_runtime.release import load_provider_release

ROOT = Path(__file__).resolve().parents[1]
INTEGRATION_ROOT = ROOT / "integrations" / "verifiers_dirty_integration"
sys.path.insert(0, str(INTEGRATION_ROOT))
contract = importlib.import_module("datalox_dirty_integration.contract")
audit = importlib.import_module("datalox_dirty_integration.audit")
calibration = importlib.import_module("datalox_dirty_integration.calibration")
episode = importlib.import_module("datalox_dirty_integration.episode")
paired = importlib.import_module("datalox_dirty_integration.paired")
policy = importlib.import_module("datalox_dirty_integration.policy")
scoring = importlib.import_module("datalox_dirty_integration.scoring")

LIST_PRODUCTS_OPERATION = contract.LIST_PRODUCTS_OPERATION
MEDUSA_LOCAL_PUBLISHABLE_KEY = contract.MEDUSA_LOCAL_PUBLISHABLE_KEY
TASK_EMAIL = contract.TASK_EMAIL
TASK_FINAL_QUANTITY = contract.TASK_FINAL_QUANTITY
TASK_INSTRUCTIONS = contract.TASK_INSTRUCTIONS
TASK_REGION_ID = contract.TASK_REGION_ID
provider_admission_path = contract.provider_admission_path
provider_grounding_path = contract.provider_grounding_path
provider_release_path = contract.provider_release_path
provider_runtime_bundle_path = contract.provider_runtime_bundle_path
CommerceEpisode = episode.CommerceEpisode
audit_episode_export = audit.audit_episode_export
CalibrationAuditError = audit.CalibrationAuditError
calibrate = paired.calibrate
run_pair = paired.run_pair
run_public_calibration = calibration.run_public_calibration
SeededCommercePolicy = policy.SeededCommercePolicy
load_profile = policy.load_profile
EvaluationOracle = scoring.EvaluationOracle
request_discipline_for_episode = scoring.request_discipline_for_episode
task_correctness_for_episode = scoring.task_correctness_for_episode


def _episode(*, profile: str, seed: str, enabled: bool) -> CommerceEpisode:
    return CommerceEpisode(
        provider_grounding=provider_grounding_path(),
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


def _all_products(episode: CommerceEpisode) -> list[dict[str, Any]]:
    products: list[dict[str, Any]] = []
    for offset in range(0, 51, 10):
        response = episode.list_products(offset=offset)
        assert response.status_code == 200
        assert isinstance(response.body, dict)
        products.extend(response.body["products"])
    return products


def _lowest_variant(products: list[dict[str, Any]]) -> str:
    candidates = [
        (variant["calculated_price"]["calculated_amount"], variant["id"])
        for product in products
        for variant in product["variants"]
    ]
    return min(candidates)[1]


def _policy_schedule(profile: str, seed: str) -> tuple[str | None, ...]:
    with _episode(profile=profile, seed=seed, enabled=False) as episode:
        _fixed_pages(episode)
        return tuple(
            event["decision"]["kind"] for event in episode.export()["intervention"]["events"]
        )


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
                    headers={"x-publishable-api-key": MEDUSA_LOCAL_PUBLISHABLE_KEY},
                    operation_id=LIST_PRODUCTS_OPERATION,
                )
                delivered = episode.list_products(offset=offset)
                base = direct.handle(request)
                assert (delivered.status_code, delivered.headers, delivered.body) == (
                    base.status_code,
                    base.headers,
                    base.body,
                )
            events = episode.export()["intervention"]["events"]
    finally:
        direct.close()

    assert all(event["enabled"] is False for event in events)
    assert all(event["applied"] is False for event in events)
    assert all(
        event["base"]["response_sha256"] == event["delivered"]["response_sha256"]
        for event in events
    )
    assert all(event["base_sha256"] == event["base"]["response_sha256"] for event in events)
    assert all(
        event["delivered_sha256"] == event["delivered"]["response_sha256"] for event in events
    )
    assert all(event["observation_changed"] is False for event in events)


def test_independent_auditor_rejects_a_tool_observation_mismatch() -> None:
    with _episode(profile="realistic", seed="7", enabled=True) as episode:
        episode.list_products(offset=0)
        exported = episode.export()
    assert audit_episode_export(exported)["passed"] is True

    tampered = deepcopy(exported)
    tampered["delivered_calls"][0]["observation"]["body"]["count"] = "tampered"
    with pytest.raises(CalibrationAuditError, match="delivered tool observation mismatch"):
        audit_episode_export(tampered)


def test_provider_enforces_local_publishable_key_without_exporting_it(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=provider_runtime_bundle_path(),
        admission_path=provider_admission_path(),
        run_dir=tmp_path / "auth-run",
    )
    try:
        request = {
            "method": "GET",
            "scheme": "https",
            "authority": "api.medusa.local",
            "path": "/store/products",
            "query": {"limit": "10", "offset": "0"},
            "operation_id": LIST_PRODUCTS_OPERATION,
        }
        missing = runtime.handle(CallRequest(**request))
        invalid = runtime.handle(
            CallRequest(
                **request,
                headers={"x-publishable-api-key": "pk_wrong_local_value"},
            )
        )
    finally:
        runtime.close()

    assert missing.status_code == invalid.status_code == 400
    assert missing.body["type"] == invalid.body["type"] == "not_allowed"
    with _episode(profile="clean", seed="7", enabled=False) as episode:
        assert episode.list_products(offset=0).status_code == 200
        delivered = episode.export()["delivered_calls"]
    assert "headers" not in delivered[0]["request"]
    assert MEDUSA_LOCAL_PUBLISHABLE_KEY not in json.dumps(delivered, sort_keys=True)


def test_switch_changes_only_read_delivery_and_never_wraps_writes() -> None:
    with _episode(profile="hostile", seed="7", enabled=False) as off:
        _fixed_pages(off)
        off.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
        off_export = off.export()
    with _episode(profile="hostile", seed="7", enabled=True) as on:
        _fixed_pages(on)
        on.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
        on_export = on.export()

    off_events = off_export["intervention"]["events"]
    on_events = on_export["intervention"]["events"]
    assert off_export["initial_state_fingerprint"] == on_export["initial_state_fingerprint"]
    assert [event["event_id"] for event in off_events] == [event["event_id"] for event in on_events]
    assert [event["decision"]["action"] for event in off_events] == [
        event["decision"]["action"] for event in on_events
    ]
    assert [event["base"]["response_sha256"] for event in off_events] == [
        event["base"]["response_sha256"] for event in on_events
    ]
    assert any(event["applied"] for event in on_events)
    assert len(off_events) == len(on_events) == 6
    assert on_export["delivered_calls"][-1]["operation_id"].endswith("carts.create")


def test_provider_native_writes_use_generated_ids_and_controller_state_verification() -> None:
    oracle = EvaluationOracle()
    with _episode(profile="clean", seed="7", enabled=False) as episode:
        variant_id = _lowest_variant(_all_products(episode))
        created = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID)
        assert created.status_code == 200
        cart_id = created.body["cart"]["id"]
        assert cart_id not in TASK_INSTRUCTIONS

        added = episode.add_line_item(cart_id=cart_id, variant_id=variant_id, quantity=1)
        assert added.status_code == 200
        line_item_id = added.body["cart"]["items"][0]["id"]
        assert line_item_id not in TASK_INSTRUCTIONS

        updated = episode.update_line_item(
            cart_id=cart_id,
            line_item_id=line_item_id,
            quantity=TASK_FINAL_QUANTITY,
        )
        retrieved = episode.get_cart(cart_id=cart_id)
        assert updated.status_code == retrieved.status_code == 200
        assert retrieved.body["cart"]["items"] == updated.body["cart"]["items"]
        assert task_correctness_for_episode(episode, oracle) == 1.0
        assert request_discipline_for_episode(episode, oracle) == 1.0

        state = episode.export()["provider"]["provider_state"]["state"]
        assert set(state["carts"]) == {cart_id}
        assert state["carts"][cart_id]["items"][0]["id"] == line_item_id


def test_reset_reproduces_provider_writes_and_intervention_behavior() -> None:
    with _episode(profile="hostile", seed="7", enabled=True) as episode:
        first_pages = _fixed_pages(episode)
        first_cart = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID).body["cart"][
            "id"
        ]
        first_trace = episode.export()["intervention"]
        episode.reset()
        second_pages = _fixed_pages(episode)
        second_cart = episode.create_cart(email=TASK_EMAIL, region_id=TASK_REGION_ID).body["cart"][
            "id"
        ]
        second_trace = episode.export()["intervention"]

    assert first_pages == second_pages
    assert first_cart == second_cart
    assert [_behavioral_event(event) for event in first_trace["events"]] == [
        _behavioral_event(event) for event in second_trace["events"]
    ]


def test_policy_is_seed_deterministic_and_seed_sensitive() -> None:
    first = _policy_schedule("hostile", "7")
    assert first == _policy_schedule("hostile", "7")
    assert len({_policy_schedule("hostile", str(seed)) for seed in range(1, 9)}) > 1


def test_declared_calibration_separates_correctness_and_request_discipline() -> None:
    common = {
        "provider_grounding": provider_grounding_path(),
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
    assert all(item["outcome"] == "completed" for item in hostile["careful"])
    assert any(item["request_discipline"] < 1.0 for item in hostile["careful"])
    assert any(item["task_correctness"] < 1.0 for item in hostile["naive"])


def test_pair_is_portable_and_binds_one_controlled_variable(tmp_path: Path) -> None:
    output = tmp_path / "pair"
    comparison = run_pair(
        output=output,
        provider_grounding=provider_grounding_path(),
        provider_admission=provider_admission_path(),
        provider_runtime_bundle=provider_runtime_bundle_path(),
        provider_release=provider_release_path(),
        profile="hostile",
        intervention_seed="7",
    )
    manifest = json.loads((output / "pair-manifest.json").read_text(encoding="utf-8"))
    rendered = json.dumps(manifest, sort_keys=True)

    assert all(comparison["binding_checks"].values())
    assert comparison["independent_audit"]["passed"] is True
    assert manifest["controlled_variable"] == {
        "name": "intervention_enabled",
        "off": False,
        "on": True,
    }
    assert "/Users/" not in rendered
    assert str(ROOT) not in rendered
    assert (output / "off" / "agent-trace.json").is_file()
    assert (output / "on" / "intervention-trace.json").is_file()


def test_issue_6_calibration_is_canonical_and_discriminating() -> None:
    first = run_public_calibration(seeds=range(1, 4))
    second = run_public_calibration(seeds=range(1, 4))
    schema = json.loads(
        (ROOT / "schemas/verifiers-dirty-calibration-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(first)

    assert first == second
    assert first["report_semantic_sha256"] == second["report_semantic_sha256"]
    assert first["protocol"]["pair_count"] == 9
    assert all(first["branch_coverage"].values())
    assert first["acceptance"] == {
        "all_configured_branches_reached": True,
        "all_pairs_independently_audited": True,
        "false_acceptance_count": 0,
        "false_rejection_count": 0,
        "quality_discrimination_passed": True,
        "passed": True,
    }
    failures = {
        case["case_id"]: case["failed_check_ids"] for case in first["verifier_calibration"]["cases"]
    }
    assert failures["valid_careful"] == []
    assert failures["negative_incomplete_pagination"] == ["complete_catalog_before_write"]
    assert failures["negative_invalid_write"] == ["quantity_transition_correct"]
    assert failures["negative_write_after_quota"] == ["no_write_after_unresolved_read_failure"]
    quality = first["quality_discrimination"]
    assert quality["efficient"]["task_correctness"] == 1.0
    assert quality["redundant"]["task_correctness"] == 1.0
    assert quality["efficient"]["request_discipline"]["reason_codes"] == ["minimum_call_path"]
    assert quality["redundant"]["request_discipline"]["reason_codes"] == ["redundant_calls"]
    assert quality["observed_delta"] >= quality["minimum_material_delta"]


def test_public_issue_6_report_records_all_180_pairs() -> None:
    report_path = INTEGRATION_ROOT / "issue-6-calibration-report.json"
    report = json.loads(report_path.read_text(encoding="utf-8"))
    schema = json.loads(
        (ROOT / "schemas/verifiers-dirty-calibration-v1.schema.json").read_text(encoding="utf-8")
    )
    Draft202012Validator(schema).validate(report)
    semantic = dict(report)
    recorded_digest = semantic.pop("report_semantic_sha256")

    assert recorded_digest == audit.canonical_sha256(semantic)
    assert report["protocol"]["seed_count"] == 60
    assert report["protocol"]["pair_count"] == 180
    assert report["acceptance"]["passed"] is True
    assert report["provider_claim"] == "g1_source_grounded_synthetic_fixture"


def test_task_plane_contains_constraints_but_no_observation_or_evaluation_truth() -> None:
    lowered = TASK_INSTRUCTIONS.lower()
    for marker in (
        "repeat",
        "quota",
        "type drift",
        "fault",
        "intervention",
        "retry",
        "prod_datalox_",
        "variant_datalox_",
        "cart_datalox_",
        "cali_datalox_",
    ):
        assert marker not in lowered
    assert TASK_EMAIL in TASK_INSTRUCTIONS
    assert TASK_REGION_ID in TASK_INSTRUCTIONS
    assert str(TASK_FINAL_QUANTITY) in TASK_INSTRUCTIONS


def test_public_handoff_leads_with_a_real_verifiers_rollout() -> None:
    readme = (INTEGRATION_ROOT / "README.md").read_text(encoding="utf-8")
    live_position = readme.index("vf-eval datalox-dirty-integration")
    calibration_position = readme.index("datalox-dirty-pair")

    assert live_position < calibration_position
    assert "There is no reference solver" in readme
    assert "predetermined\noperation sequence" in readme
    assert "not a model rollout and must not be reported as one" in readme


@pytest.mark.skipif(
    importlib.util.find_spec("verifiers") is None,
    reason="Verifiers 0.3.1 is installed by the downstream integration package",
)
def test_verifiers_client_never_receives_private_provider_or_evaluation_objects(
    tmp_path: Path,
) -> None:
    import verifiers as vf

    class RecordingClient(vf.Client):
        def __init__(self) -> None:
            super().__init__(object())
            self.states: list[dict[str, Any]] = []

        async def get_response(self, **kwargs: Any) -> Any:
            self.states.append(dict(kwargs["state"]))
            return _stop_response(vf, kwargs["model"], "done")

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
            evidence_dir=tmp_path / "recording-evidence",
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
                "provider_grounding",
                "provider_state",
                MEDUSA_LOCAL_PUBLISHABLE_KEY,
                "prod_datalox_",
                "variant_datalox_",
                "evidence_dir",
                str(tmp_path).lower(),
            ):
                assert marker not in rendered

        failing_environment = vf.load_environment(
            "datalox-dirty-integration",
            profile="hostile",
            intervention_enabled=True,
            intervention_seed="controller-private-error-seed",
            evidence_dir=tmp_path / "error-evidence",
            num_tasks=1,
        )
        failed_state = await failing_environment.rollout(
            failing_environment.dataset[0], ErrorClient(), "recording-model"
        )
        assert failed_state["error"] is not None
        assert failing_environment._episodes == {}
        assert failed_state["trajectory_id"] in failing_environment._score_cache
        await failing_environment.rubric.cleanup(failed_state)
        assert failing_environment._score_cache == {}

    asyncio.run(run())


@pytest.mark.skipif(
    importlib.util.find_spec("verifiers") is None,
    reason="Verifiers 0.3.1 is installed by the downstream integration package",
)
def test_two_parallel_model_rollouts_use_observed_generated_ids_and_isolated_state(
    tmp_path: Path,
) -> None:
    import verifiers as vf

    class VerifiersObservationDrivenClient(ObservationDrivenClient, vf.Client):
        def __init__(self) -> None:
            vf.Client.__init__(self, object())
            ObservationDrivenClient.__init__(self, vf)

    async def run() -> None:
        evidence_dir = tmp_path / "evidence"
        environment = vf.load_environment(
            "datalox-dirty-integration",
            profile="clean",
            intervention_enabled=True,
            intervention_seed="7",
            evidence_dir=evidence_dir,
            num_tasks=2,
        )
        clients = [VerifiersObservationDrivenClient(), VerifiersObservationDrivenClient()]
        states = await asyncio.gather(
            *(
                environment.rollout(environment.dataset[index], clients[index], "observed-model")
                for index in range(2)
            )
        )
        for state in states:
            await environment.rubric.score_rollout(state)
            assert state["error"] is None
            assert state["metrics"]["reward_task_correctness"] == 1.0
            assert state["metrics"]["reward_request_discipline"] == 1.0

        assert environment._episodes == {}
        assert all(
            client.selected_calls[0] == {"name": "list_products", "arguments": {"offset": 0}}
            for client in clients
        )
        assert all(client.selected_calls[-1]["name"] == "get_cart" for client in clients)
        assert all(
            len([call for call in client.selected_calls if call["name"] == "list_products"]) == 6
            for client in clients
        )
        assert list(clients[0].cart_ids.values()) == list(clients[1].cart_ids.values())
        assert list(clients[0].line_item_ids.values()) == list(clients[1].line_item_ids.values())

        rollout_dirs = [path for path in evidence_dir.iterdir() if path.is_dir()]
        assert len(rollout_dirs) == 2
        for rollout_dir in rollout_dirs:
            manifest = json.loads((rollout_dir / "manifest.json").read_text(encoding="utf-8"))
            delivered = json.loads(
                (rollout_dir / "delivered-observations.json").read_text(encoding="utf-8")
            )
            verification = json.loads(
                (rollout_dir / "verification.json").read_text(encoding="utf-8")
            )
            assert manifest["intervention"]["enabled"] is True
            assert manifest["profile"] == "clean"
            assert len(delivered["calls"]) == 10
            assert verification["request_discipline"]["score"] == 1.0
            assert verification["task_correctness"]["score"] == 1.0
            for name, expected_digest in manifest["artifacts"].items():
                actual = "sha256:" + hashlib.sha256((rollout_dir / name).read_bytes()).hexdigest()
                assert actual == expected_digest

        for state in states:
            await environment.rubric.cleanup(state)
        assert environment._score_cache == {}

    asyncio.run(run())


class ObservationDrivenClient:
    """Test client whose identifiers and decisions come only from tool observations."""

    def __init__(self, vf: Any) -> None:
        self.vf = vf
        self.products: dict[str, dict[str, dict[str, Any]]] = {}
        self.cart_ids: dict[str, str] = {}
        self.line_item_ids: dict[str, str] = {}
        self.selected_variants: dict[str, str] = {}
        self.stage: dict[str, str] = {}
        self.selected_calls: list[dict[str, Any]] = []

    async def get_response(self, **kwargs: Any) -> Any:
        trajectory_id = kwargs["state"]["trajectory_id"]
        assert {tool.name for tool in kwargs["tools"]} == {
            "list_products",
            "create_cart",
            "get_cart",
            "add_line_item",
            "update_line_item",
            "delete_line_item",
        }
        last = kwargs["prompt"][-1]
        if last.role == "user":
            self.stage[trajectory_id] = "listing"
            return self._tool_response(kwargs["model"], "list_products", {"offset": 0})
        if last.role != "tool" or not isinstance(last.content, str):
            return _stop_response(self.vf, kwargs["model"], "Finished.")

        observation = json.loads(last.content)
        assert observation["status_code"] == 200
        body = observation["body"]
        stage = self.stage[trajectory_id]
        if stage == "listing":
            rows = self.products.setdefault(trajectory_id, {})
            for product in body["products"]:
                rows[product["id"]] = product
            if body["products"]:
                return self._tool_response(
                    kwargs["model"],
                    "list_products",
                    {"offset": body["offset"] + body["limit"]},
                )
            variant_id = _lowest_variant(list(rows.values()))
            self.selected_variants[trajectory_id] = variant_id
            self.stage[trajectory_id] = "created"
            return self._tool_response(
                kwargs["model"],
                "create_cart",
                {"email": TASK_EMAIL, "region_id": TASK_REGION_ID},
            )
        if stage == "created":
            cart_id = body["cart"]["id"]
            self.cart_ids[trajectory_id] = cart_id
            self.stage[trajectory_id] = "added"
            return self._tool_response(
                kwargs["model"],
                "add_line_item",
                {
                    "cart_id": cart_id,
                    "variant_id": self.selected_variants[trajectory_id],
                    "quantity": 1,
                },
            )
        if stage == "added":
            cart_id = self.cart_ids[trajectory_id]
            line_item_id = body["cart"]["items"][0]["id"]
            self.line_item_ids[trajectory_id] = line_item_id
            self.stage[trajectory_id] = "updated"
            return self._tool_response(
                kwargs["model"],
                "update_line_item",
                {
                    "cart_id": cart_id,
                    "line_item_id": line_item_id,
                    "quantity": TASK_FINAL_QUANTITY,
                },
            )
        if stage == "updated":
            self.stage[trajectory_id] = "retrieved"
            return self._tool_response(
                kwargs["model"],
                "get_cart",
                {"cart_id": self.cart_ids[trajectory_id]},
            )
        return _stop_response(self.vf, kwargs["model"], "Finished.")

    def _tool_response(self, model: str, name: str, arguments: dict[str, Any]) -> Any:
        self.selected_calls.append({"name": name, "arguments": arguments})
        return self.vf.Response(
            id=f"observation-driven-{len(self.selected_calls)}",
            created=0,
            model=model,
            usage=self.vf.Usage(
                prompt_tokens=1,
                reasoning_tokens=0,
                completion_tokens=1,
                total_tokens=2,
            ),
            message=self.vf.ResponseMessage(
                role="assistant",
                content=None,
                tool_calls=[
                    self.vf.ToolCall(
                        id=f"tool-{len(self.selected_calls)}",
                        name=name,
                        arguments=json.dumps(arguments),
                    )
                ],
                finish_reason="tool_calls",
                is_truncated=False,
                tokens=None,
            ),
        )

    def setup_client(self, config: Any) -> Any:
        raise AssertionError("observation-driven client does not use a client config")

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


def _stop_response(vf: Any, model: str, content: str) -> Any:
    return vf.Response(
        id="observation-driven-stop",
        created=0,
        model=model,
        usage=vf.Usage(
            prompt_tokens=1,
            reasoning_tokens=0,
            completion_tokens=1,
            total_tokens=2,
        ),
        message=vf.ResponseMessage(
            role="assistant",
            content=content,
            tool_calls=None,
            finish_reason="stop",
            is_truncated=False,
            tokens=None,
        ),
    )


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
