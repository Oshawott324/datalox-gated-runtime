from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest
from pylabrobot.liquid_handling import LiquidHandler
from pylabrobot.resources import (
    PLT_CAR_L5AC_A00,
    STARLetDeck,
    TIP_CAR_480_A00,
    Cor_96_wellplate_360ul_Fb,
    hamilton_96_tiprack_1000uL_filter,
    set_tip_tracking,
    set_volume_tracking,
)

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_core_coverage import evaluate_provider_core_coverage
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.sdk_adapters import (
    DataloxHamiltonSTARBackend,
    HAMILTON_STAR_ADAPTER_AUTHORITY,
    HamiltonSTARHttpTransport,
    HamiltonSTARResponse,
    HamiltonSTARScopeError,
)


ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "envs" / "pylabrobot_hamilton_star_v0"
EPISODE_ID = "pylabrobot-hamilton-star-transfer-001"


def _bundle(tmp_path: Path) -> Path:
    bundle = tmp_path / "hamilton-provider"
    build_provider_runtime_from_world(
        source_world_dir=ENV,
        output_dir=bundle,
        provider_id="pylabrobot_hamilton_star",
        authorities=(HAMILTON_STAR_ADAPTER_AUTHORITY,),
        episode_id=EPISODE_ID,
    )
    return bundle


def _runtime(tmp_path: Path) -> ProviderRuntime:
    return ProviderRuntime(bundle_dir=_bundle(tmp_path), run_dir=tmp_path / "run")


def _request(
    runtime: ProviderRuntime,
    method: str,
    path: str,
    body: dict | None = None,
):
    return runtime.handle(
        CallRequest(
            method=method,
            path=path,
            body=body,
            authority=HAMILTON_STAR_ADAPTER_AUTHORITY,
        )
    )


def _setup_body() -> dict:
    return {
        "num_channels": 8,
        "tip_spots": [
            {"name": "tips_tipspot_A1", "has_tip": True, "max_volume_ul": 1065},
            {"name": "tips_tipspot_A2", "has_tip": True, "max_volume_ul": 1065},
        ],
        "containers": [
            {"name": "source_well", "volume_ul": 200, "max_volume_ul": 360},
            {"name": "target_well", "volume_ul": 0, "max_volume_ul": 360},
        ],
        "waste_names": ["trash"],
    }


def _tip_command(path: str, *, spot: str = "tips_tipspot_A1") -> tuple[str, dict]:
    return path, {
        "operations": [{"channel": 0, "tip_spot": spot, "offset": {"x": 0, "y": 0, "z": 0}}]
    }


def _drop_command(*, destination: str = "tips_tipspot_A1") -> dict:
    return {
        "operations": [
            {
                "channel": 0,
                "destination": destination,
                "destination_kind": "tip_spot",
                "offset": {"x": 0, "y": 0, "z": 0},
            }
        ]
    }


def _liquid_command(container: str, volume: float) -> dict:
    return {
        "operations": [
            {
                "channel": 0,
                "container": container,
                "volume_ul": volume,
                "flow_rate": None,
                "liquid_height": None,
                "blow_out_air_volume": None,
                "offset": {"x": 0, "y": 0, "z": 0},
            }
        ]
    }


def _state(runtime: ProviderRuntime) -> dict:
    return runtime.export()["provider_state"]["state"]


def test_every_hamilton_star_write_has_readback_atomic_failure_and_reset(
    tmp_path: Path,
) -> None:
    runtime = _runtime(tmp_path)
    try:
        initial = _state(runtime)

        setup = _request(runtime, "POST", "/v1/liquid-handler/setup", _setup_body())
        assert setup.status_code == 200
        assert _request(runtime, "GET", "/v1/liquid-handler").body["status"] == "running"
        before_duplicate_setup = _state(runtime)
        duplicate_setup = _request(runtime, "POST", "/v1/liquid-handler/setup", _setup_body())
        assert duplicate_setup.status_code == 409
        assert duplicate_setup.body["error"]["code"] == "RuntimeError"
        assert _state(runtime) == before_duplicate_setup

        pickup_path, pickup_body = _tip_command("/v1/liquid-handler/commands/pick-up-tips")
        pickup = _request(runtime, "POST", pickup_path, pickup_body)
        assert pickup.status_code == 200
        assert _request(runtime, "GET", "/v1/liquid-handler/tips").body["channels"][0]["tip"]
        before_duplicate_pickup = _state(runtime)
        _path, second_pickup = _tip_command(pickup_path, spot="tips_tipspot_A2")
        duplicate_pickup = _request(runtime, "POST", pickup_path, second_pickup)
        assert duplicate_pickup.status_code == 409
        assert duplicate_pickup.body["error"]["code"] == "HasTipError"
        assert _state(runtime) == before_duplicate_pickup

        before_bad_aspirate = _state(runtime)
        bad_aspirate = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/aspirate",
            _liquid_command("source_well", 250),
        )
        assert bad_aspirate.status_code == 409
        assert bad_aspirate.body["error"]["code"] == "TooLittleLiquidError"
        assert _state(runtime) == before_bad_aspirate

        aspirate = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/aspirate",
            _liquid_command("source_well", 100),
        )
        assert aspirate.status_code == 200
        liquid_state = _request(runtime, "GET", "/v1/liquid-handler/liquids").body
        assert liquid_state["containers"]["source_well"]["volume_ul"] == 100
        assert liquid_state["channels"][0]["tip"]["volume_ul"] == 100

        before_bad_dispense = _state(runtime)
        bad_dispense = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/dispense",
            _liquid_command("target_well", 150),
        )
        assert bad_dispense.status_code == 409
        assert bad_dispense.body["error"]["code"] == "TooLittleLiquidError"
        assert _state(runtime) == before_bad_dispense

        dispense = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/dispense",
            _liquid_command("target_well", 100),
        )
        assert dispense.status_code == 200
        liquid_state = _request(runtime, "GET", "/v1/liquid-handler/liquids").body
        assert liquid_state["containers"]["target_well"]["volume_ul"] == 100
        assert liquid_state["channels"][0]["tip"]["volume_ul"] == 0

        drop = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/drop-tips",
            _drop_command(),
        )
        assert drop.status_code == 200
        assert _request(runtime, "GET", "/v1/liquid-handler/tips").body["tip_spots"][
            "tips_tipspot_A1"
        ]["has_tip"]
        before_duplicate_drop = _state(runtime)
        duplicate_drop = _request(
            runtime,
            "POST",
            "/v1/liquid-handler/commands/drop-tips",
            _drop_command(),
        )
        assert duplicate_drop.status_code == 409
        assert duplicate_drop.body["error"]["code"] == "NoTipError"
        assert _state(runtime) == before_duplicate_drop

        stopped = _request(runtime, "POST", "/v1/liquid-handler/stop", {})
        assert stopped.status_code == 200
        assert _request(runtime, "GET", "/v1/liquid-handler").body["status"] == "stopped"
        before_duplicate_stop = _state(runtime)
        duplicate_stop = _request(runtime, "POST", "/v1/liquid-handler/stop", {})
        assert duplicate_stop.status_code == 409
        assert duplicate_stop.body["error"]["code"] == "RuntimeError"
        assert _state(runtime) == before_duplicate_stop

        reset = runtime.reset()
        assert reset["provider_state"]["state"] == initial
        assert reset["call_evidence"]["events"] == []
    finally:
        runtime.close()


class _RuntimeTransport:
    def __init__(self, runtime: ProviderRuntime) -> None:
        self.runtime = runtime

    async def request(
        self,
        *,
        method: str,
        path: str,
        body: dict | None = None,
    ) -> HamiltonSTARResponse:
        response = _request(self.runtime, method, path, body)
        return HamiltonSTARResponse(response.status_code, response.body)


def test_native_pylabrobot_liquid_handler_calls_use_the_gated_provider_pack(
    tmp_path: Path,
) -> None:
    async def exercise() -> None:
        set_tip_tracking(True)
        set_volume_tracking(True)
        deck = STARLetDeck()
        tip_carrier = TIP_CAR_480_A00(name="tip_carrier")
        plate_carrier = PLT_CAR_L5AC_A00(name="plate_carrier")
        deck.assign_child_resource(tip_carrier, rails=1)
        deck.assign_child_resource(plate_carrier, rails=9)
        tips = hamilton_96_tiprack_1000uL_filter(name="tips")
        source = Cor_96_wellplate_360ul_Fb(name="source")
        target = Cor_96_wellplate_360ul_Fb(name="target")
        tip_carrier[0] = tips
        plate_carrier[0] = source
        plate_carrier[1] = target
        source_well = source.get_item("A1")
        target_well = target.get_item("A1")
        source_well.tracker.set_volume(200)

        runtime = _runtime(tmp_path)
        try:
            liquid_handler = LiquidHandler(
                backend=DataloxHamiltonSTARBackend(_RuntimeTransport(runtime)),
                deck=deck,
            )
            await liquid_handler.setup()
            await liquid_handler.pick_up_tips([tips.get_item("A1")])
            assert await liquid_handler.backend.request_tip_presence() == [
                True,
                False,
                False,
                False,
                False,
                False,
                False,
                False,
            ]
            await liquid_handler.aspirate([source_well], vols=[100])
            await liquid_handler.dispense([target_well], vols=[100])
            await liquid_handler.return_tips()
            await liquid_handler.stop()

            liquid_state = _request(runtime, "GET", "/v1/liquid-handler/liquids").body
            assert liquid_state["containers"][source_well.name]["volume_ul"] == 100
            assert liquid_state["containers"][target_well.name]["volume_ul"] == 100
            tip_state = _request(runtime, "GET", "/v1/liquid-handler/tips").body
            assert tip_state["tip_spots"][tips.get_item("A1").name]["has_tip"] is True
            assert all(channel["tip"] is None for channel in tip_state["channels"])
        finally:
            runtime.close()

    asyncio.run(exercise())


def test_hamilton_star_runtime_bundle_is_task_free_and_core_complete(tmp_path: Path) -> None:
    bundle = _bundle(tmp_path)
    names = {path.name for path in bundle.rglob("*") if path.is_file()}
    assert not {"task.json", "episodes.jsonl", "verifier.json", "reward.json"} & names
    manifest = json.loads((bundle / "provider-runtime.json").read_text(encoding="utf-8"))
    assert manifest["provider_id"] == "pylabrobot_hamilton_star"
    assert manifest["authorities"] == [HAMILTON_STAR_ADAPTER_AUTHORITY]
    assert manifest["behavior"]["protocol"] == "world_v1_adapter"

    coverage = evaluate_provider_core_coverage(
        ENV,
        expected_env_id="pylabrobot_hamilton_star_v0",
        expected_provider_id="pylabrobot_hamilton_star",
    )
    assert coverage["status"] == "core_complete", coverage["findings"]
    assert coverage["write_operation_count"] == 6
    assert coverage["provider_observed_write_operation_count"] == 6


def test_hamilton_star_adapter_rejects_out_of_scope_hardware() -> None:
    class _UnusedTransport:
        async def request(self, **kwargs):
            raise AssertionError(kwargs)

    backend = DataloxHamiltonSTARBackend(_UnusedTransport())
    with pytest.raises(HamiltonSTARScopeError, match="CoRe 96"):
        asyncio.run(backend.pick_up_tips96(None))
    with pytest.raises(HamiltonSTARScopeError, match="iSWAP"):
        asyncio.run(backend.pick_up_resource(None))


def test_hamilton_star_http_transport_uses_only_the_reserved_adapter_authority() -> None:
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return httpx.Response(200, json={"status": "running"})

    async def exercise() -> HamiltonSTARResponse:
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            transport = HamiltonSTARHttpTransport(client)
            return await transport.request(method="GET", path="/v1/liquid-handler")

    response = asyncio.run(exercise())
    assert response.status_code == 200
    assert len(seen) == 1
    assert seen[0].url == f"https://{HAMILTON_STAR_ADAPTER_AUTHORITY}/v1/liquid-handler"
