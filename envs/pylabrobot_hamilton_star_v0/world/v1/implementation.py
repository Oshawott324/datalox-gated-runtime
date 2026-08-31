from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import math
from typing import Any, Mapping

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import ActorContext, WorldImplementationV1
from datalox_gated_runtime.world_v1.session import WorldSession

from .contract import REWARD_ATOMS, ROUTES, TOOLS, TOOLS_BY_ID, WORLD_ID


@dataclass(frozen=True)
class HamiltonSTARWorldError(Exception):
    code: str
    message: str
    status: int


@dataclass(frozen=True)
class HamiltonSTARVerifierResult:
    passed: bool
    checks: tuple[dict[str, Any], ...]
    failure_codes: tuple[str, ...]
    reward_atoms: tuple[dict[str, Any], ...]
    reward: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verifier_type": WORLD_ID,
            "checks": list(self.checks),
            "failure_codes": list(self.failure_codes),
            "reward_atoms": list(self.reward_atoms),
            "reward": self.reward,
        }


def _number(value: Any, *, name: str, positive: bool = False) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise HamiltonSTARWorldError("ValueError", f"{name} must be a number.", 422)
    result = float(value)
    if not math.isfinite(result) or result < 0 or (positive and result == 0):
        qualifier = "positive" if positive else "non-negative"
        raise HamiltonSTARWorldError("ValueError", f"{name} must be {qualifier}.", 422)
    return result


def _name(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise HamiltonSTARWorldError("ValueError", f"{field} must be a non-empty name.", 422)
    return value


class HamiltonSTARWorld(WorldImplementationV1):
    def initialize_episode(self, *, session: WorldSession, episode: Mapping[str, Any]) -> None:
        session.reset(
            episode_id=str(episode["id"]),
            initial_state=deepcopy(dict(episode["state"])),
            initial_time=str(episode["metadata"]["clock"]),
        )

    def tool_schemas(self, *, actor: ActorContext) -> dict[str, dict[str, Any]]:
        return {
            item["id"]: deepcopy(item["input_schema"])
            for item in TOOLS
            if actor.role in item["list_roles"]
        }

    def operation_for_tool(self, tool_name: str) -> str | None:
        return tool_name if tool_name in TOOLS_BY_ID else None

    def tool_for_request(self, request: CallRequest) -> str | None:
        method = request.normalized_method()
        path = request.path.rstrip("/") or "/"
        for operation, (expected_method, expected_path, _family, _schema) in ROUTES.items():
            if method == expected_method and path == expected_path:
                return operation
        return None

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        del actor
        method, path, _family, _schema = ROUTES[tool_name]
        body = None if method == "GET" else deepcopy(dict(arguments))
        return CallRequest(method, path, body=body, operation_id=tool_name)

    def handle(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        session: WorldSession,
    ) -> WorldResponse | None:
        operation = self.tool_for_request(request)
        if operation is None:
            return None
        try:
            arguments = self._arguments(request)
            body, mutated = self._execute(operation, arguments, actor, session)
        except HamiltonSTARWorldError as error:
            session.append_event(
                "hamilton_star_operation_denied",
                {
                    "operation_id": operation,
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "reason_code": error.code,
                    "decision": "deny",
                },
            )
            return WorldResponse(
                error.status,
                {"error": {"code": error.code, "message": error.message}},
                False,
                WORLD_ID,
                operation,
                "deny",
                error.code,
                "Hamilton STAR dry-run operation rejected without mutation.",
            )
        return WorldResponse(
            200,
            body,
            mutated,
            WORLD_ID,
            operation,
            "shadow_write" if mutated else "replay",
            "world_state_write" if mutated else "world_state_read",
            "Hamilton STAR dry-run operation completed against isolated state.",
        )

    @staticmethod
    def _arguments(request: CallRequest) -> dict[str, Any]:
        if request.normalized_method() == "GET":
            return {}
        if not isinstance(request.body, Mapping):
            raise HamiltonSTARWorldError("ValueError", "Request body must be an object.", 422)
        return deepcopy(dict(request.body))

    def _execute(
        self,
        operation: str,
        arguments: Mapping[str, Any],
        actor: ActorContext,
        session: WorldSession,
    ) -> tuple[dict[str, Any], bool]:
        if operation == "system.get":
            return self._system_state(session), False
        if operation == "system.setup":
            return self._setup(arguments, actor, session), True
        if operation == "system.stop":
            return self._stop(actor, session), True
        if operation == "tips.get":
            return self._tip_state(session), False
        if operation == "tips.pick_up":
            return self._pick_up_tips(arguments, actor, session), True
        if operation == "tips.drop":
            return self._drop_tips(arguments, actor, session), True
        if operation == "liquids.get":
            return self._liquid_state(session), False
        if operation == "liquids.aspirate":
            return self._aspirate(arguments, actor, session), True
        if operation == "liquids.dispense":
            return self._dispense(arguments, actor, session), True
        raise AssertionError(operation)

    @staticmethod
    def _require_running(session: WorldSession) -> None:
        if session.get_state("status") != "running":
            raise HamiltonSTARWorldError(
                "RuntimeError",
                "The setup has not finished. See `setup`.",
                409,
            )

    @staticmethod
    def _operations(arguments: Mapping[str, Any]) -> list[dict[str, Any]]:
        values = arguments.get("operations")
        if (
            not isinstance(values, list)
            or not 1 <= len(values) <= 8
            or not all(isinstance(item, Mapping) for item in values)
        ):
            raise HamiltonSTARWorldError(
                "ValueError", "operations must contain between one and eight objects.", 422
            )
        return [dict(item) for item in values]

    @staticmethod
    def _channel(value: Any, channels: list[dict[str, Any]]) -> tuple[int, dict[str, Any]]:
        if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < len(channels):
            raise HamiltonSTARWorldError("ValueError", "channel must be between 0 and 7.", 422)
        return value, channels[value]

    def _setup(
        self, arguments: Mapping[str, Any], actor: ActorContext, session: WorldSession
    ) -> dict[str, Any]:
        if session.get_state("status") == "running":
            raise HamiltonSTARWorldError(
                "RuntimeError",
                "The setup has already finished. See `LiquidHandler.stop`.",
                409,
            )
        if arguments.get("num_channels") != 8:
            raise HamiltonSTARWorldError(
                "ValueError", "The selected Hamilton STAR scope requires eight channels.", 422
            )
        raw_tip_spots = arguments.get("tip_spots")
        raw_containers = arguments.get("containers")
        raw_waste = arguments.get("waste_names")
        if not isinstance(raw_tip_spots, list) or not isinstance(raw_containers, list):
            raise HamiltonSTARWorldError(
                "ValueError", "tip_spots and containers must be arrays.", 422
            )
        if not isinstance(raw_waste, list):
            raise HamiltonSTARWorldError("ValueError", "waste_names must be an array.", 422)

        tip_spots: dict[str, dict[str, Any]] = {}
        for raw in raw_tip_spots:
            if not isinstance(raw, Mapping) or not isinstance(raw.get("has_tip"), bool):
                raise HamiltonSTARWorldError("ValueError", "Invalid tip spot definition.", 422)
            name = _name(raw.get("name"), field="tip spot name")
            if name in tip_spots:
                raise HamiltonSTARWorldError("ValueError", f"Duplicate resource name: {name}.", 422)
            maximum = raw.get("max_volume_ul")
            if raw["has_tip"]:
                maximum = _number(maximum, name="max_volume_ul", positive=True)
            elif maximum is not None:
                maximum = _number(maximum, name="max_volume_ul", positive=True)
            tip_spots[name] = {"has_tip": raw["has_tip"], "max_volume_ul": maximum}

        containers: dict[str, dict[str, float]] = {}
        for raw in raw_containers:
            if not isinstance(raw, Mapping):
                raise HamiltonSTARWorldError("ValueError", "Invalid container definition.", 422)
            name = _name(raw.get("name"), field="container name")
            if name in tip_spots or name in containers:
                raise HamiltonSTARWorldError("ValueError", f"Duplicate resource name: {name}.", 422)
            volume = _number(raw.get("volume_ul"), name="volume_ul")
            maximum = _number(raw.get("max_volume_ul"), name="max_volume_ul", positive=True)
            if volume > maximum:
                raise HamiltonSTARWorldError(
                    "TooLittleVolumeError",
                    f"Not enough space in container: {volume}uL > {maximum}uL.",
                    409,
                )
            containers[name] = {"volume_ul": volume, "max_volume_ul": maximum}

        waste_names = [_name(value, field="waste name") for value in raw_waste]
        if len(set(waste_names)) != len(waste_names):
            raise HamiltonSTARWorldError("ValueError", "Waste names must be unique.", 422)
        overlap = set(waste_names) & (set(tip_spots) | set(containers))
        if overlap:
            raise HamiltonSTARWorldError(
                "ValueError", f"Duplicate resource name: {sorted(overlap)[0]}.", 422
            )

        session.set_state("status", "running")
        session.set_state("channels", [{"channel": index, "tip": None} for index in range(8)])
        session.set_state("tip_spots", tip_spots)
        session.set_state("containers", containers)
        session.set_state("waste_names", waste_names)
        self._record("system.setup", actor, session)
        return self._system_state(session)

    def _stop(self, actor: ActorContext, session: WorldSession) -> dict[str, Any]:
        self._require_running(session)
        session.set_state("status", "stopped")
        self._record("system.stop", actor, session)
        return self._system_state(session)

    def _pick_up_tips(
        self, arguments: Mapping[str, Any], actor: ActorContext, session: WorldSession
    ) -> dict[str, Any]:
        self._require_running(session)
        channels = deepcopy(session.get_state("channels"))
        tip_spots = deepcopy(session.get_state("tip_spots"))
        for operation in self._operations(arguments):
            _index, channel = self._channel(operation.get("channel"), channels)
            spot_name = _name(operation.get("tip_spot"), field="tip_spot")
            spot = tip_spots.get(spot_name)
            if spot is None:
                raise HamiltonSTARWorldError(
                    "ResourceNotFoundError", f"Tip spot {spot_name!r} was not found.", 404
                )
            if channel["tip"] is not None:
                raise HamiltonSTARWorldError("HasTipError", "Channel has tip", 409)
            if not spot["has_tip"]:
                raise HamiltonSTARWorldError(
                    "NoTipError", f"Tip spot {spot_name!r} does not have a tip.", 409
                )
            channel["tip"] = {
                "origin_tip_spot": spot_name,
                "max_volume_ul": spot["max_volume_ul"],
                "volume_ul": 0.0,
            }
            spot["has_tip"] = False
        session.set_state("channels", channels)
        session.set_state("tip_spots", tip_spots)
        self._record("tips.pick_up", actor, session)
        return self._tip_state(session)

    def _drop_tips(
        self, arguments: Mapping[str, Any], actor: ActorContext, session: WorldSession
    ) -> dict[str, Any]:
        self._require_running(session)
        channels = deepcopy(session.get_state("channels"))
        tip_spots = deepcopy(session.get_state("tip_spots"))
        waste_names = set(session.get_state("waste_names"))
        discarded = int(session.get_state("discarded_tip_count"))
        for operation in self._operations(arguments):
            _index, channel = self._channel(operation.get("channel"), channels)
            if channel["tip"] is None:
                raise HamiltonSTARWorldError("NoTipError", "Channel does not have a tip.", 409)
            destination = _name(operation.get("destination"), field="destination")
            kind = operation.get("destination_kind")
            if kind == "tip_spot":
                spot = tip_spots.get(destination)
                if spot is None:
                    raise HamiltonSTARWorldError(
                        "ResourceNotFoundError", f"Tip spot {destination!r} was not found.", 404
                    )
                if spot["has_tip"]:
                    raise HamiltonSTARWorldError("HasTipError", "Tip spot already has a tip.", 409)
                spot["has_tip"] = True
                spot["max_volume_ul"] = channel["tip"]["max_volume_ul"]
            elif kind == "waste":
                if destination not in waste_names:
                    raise HamiltonSTARWorldError(
                        "ResourceNotFoundError", f"Waste {destination!r} was not found.", 404
                    )
                discarded += 1
            else:
                raise HamiltonSTARWorldError(
                    "ValueError", "destination_kind must be tip_spot or waste.", 422
                )
            channel["tip"] = None
        session.set_state("channels", channels)
        session.set_state("tip_spots", tip_spots)
        session.set_state("discarded_tip_count", discarded)
        self._record("tips.drop", actor, session)
        return self._tip_state(session)

    def _aspirate(
        self, arguments: Mapping[str, Any], actor: ActorContext, session: WorldSession
    ) -> dict[str, Any]:
        self._require_running(session)
        channels = deepcopy(session.get_state("channels"))
        containers = deepcopy(session.get_state("containers"))
        for operation in self._operations(arguments):
            _index, channel = self._channel(operation.get("channel"), channels)
            tip = channel["tip"]
            if tip is None:
                raise HamiltonSTARWorldError(
                    "NoTipError", f"Channel {operation.get('channel')} does not have a tip.", 409
                )
            container_name = _name(operation.get("container"), field="container")
            container = containers.get(container_name)
            if container is None:
                raise HamiltonSTARWorldError(
                    "ResourceNotFoundError", f"Container {container_name!r} was not found.", 404
                )
            volume = _number(operation.get("volume_ul"), name="volume_ul", positive=True)
            if volume > container["volume_ul"]:
                raise HamiltonSTARWorldError(
                    "TooLittleLiquidError",
                    f"Not enough liquid in container: {volume}uL > {container['volume_ul']}uL.",
                    409,
                )
            free = tip["max_volume_ul"] - tip["volume_ul"]
            if volume > free:
                raise HamiltonSTARWorldError(
                    "TooLittleVolumeError",
                    f"Not enough space in tip: {volume}uL > {free}uL.",
                    409,
                )
            container["volume_ul"] -= volume
            tip["volume_ul"] += volume
        session.set_state("channels", channels)
        session.set_state("containers", containers)
        self._record("liquids.aspirate", actor, session)
        return self._liquid_state(session)

    def _dispense(
        self, arguments: Mapping[str, Any], actor: ActorContext, session: WorldSession
    ) -> dict[str, Any]:
        self._require_running(session)
        channels = deepcopy(session.get_state("channels"))
        containers = deepcopy(session.get_state("containers"))
        for operation in self._operations(arguments):
            _index, channel = self._channel(operation.get("channel"), channels)
            tip = channel["tip"]
            if tip is None:
                raise HamiltonSTARWorldError(
                    "NoTipError", f"Channel {operation.get('channel')} does not have a tip.", 409
                )
            container_name = _name(operation.get("container"), field="container")
            container = containers.get(container_name)
            if container is None:
                raise HamiltonSTARWorldError(
                    "ResourceNotFoundError", f"Container {container_name!r} was not found.", 404
                )
            volume = _number(operation.get("volume_ul"), name="volume_ul", positive=True)
            if volume > tip["volume_ul"]:
                raise HamiltonSTARWorldError(
                    "TooLittleLiquidError",
                    f"Not enough liquid in container: {volume}uL > {tip['volume_ul']}uL.",
                    409,
                )
            free = container["max_volume_ul"] - container["volume_ul"]
            if volume > free:
                raise HamiltonSTARWorldError(
                    "TooLittleVolumeError",
                    f"Not enough space in container: {volume}uL > {free}uL.",
                    409,
                )
            tip["volume_ul"] -= volume
            container["volume_ul"] += volume
        session.set_state("channels", channels)
        session.set_state("containers", containers)
        self._record("liquids.dispense", actor, session)
        return self._liquid_state(session)

    @staticmethod
    def _record(operation: str, actor: ActorContext, session: WorldSession) -> None:
        commands = session.get_state("commands")
        commands.append(
            {
                "sequence": len(commands) + 1,
                "operation": operation,
                "actor_id": actor.actor_id,
                "actor_role": actor.role,
            }
        )
        session.set_state("commands", commands)

    @staticmethod
    def _system_state(session: WorldSession) -> dict[str, Any]:
        return {
            "status": session.get_state("status"),
            "num_channels": len(session.get_state("channels")),
            "resource_counts": {
                "tip_spots": len(session.get_state("tip_spots")),
                "containers": len(session.get_state("containers")),
                "waste": len(session.get_state("waste_names")),
            },
            "command_count": len(session.get_state("commands")),
        }

    @staticmethod
    def _tip_state(session: WorldSession) -> dict[str, Any]:
        return {
            "channels": deepcopy(session.get_state("channels")),
            "tip_spots": deepcopy(session.get_state("tip_spots")),
            "discarded_tip_count": session.get_state("discarded_tip_count"),
        }

    @staticmethod
    def _liquid_state(session: WorldSession) -> dict[str, Any]:
        return {
            "channels": deepcopy(session.get_state("channels")),
            "containers": deepcopy(session.get_state("containers")),
        }

    def verify(
        self, *, session: WorldSession, episode: Mapping[str, Any]
    ) -> HamiltonSTARVerifierResult:
        del episode
        state = session.list_state()
        events = session.verifier_events()
        invoked = {
            event.get("operation_id")
            for event in events
            if event["event_type"] == "world_operation_started"
        }
        denied = [event for event in events if event["event_type"].endswith("_denied")]
        source = state["containers"].get("source_well", {})
        target = state["containers"].get("target_well", {})
        checks_raw = (
            (
                "transfer_completed",
                source.get("volume_ul") == 100.0 and target.get("volume_ul") == 100.0,
            ),
            (
                "tip_returned",
                state["tip_spots"].get("tips_tipspot_A1", {}).get("has_tip") is True
                and all(channel["tip"] is None for channel in state["channels"]),
            ),
            ("handler_stopped", state["status"] == "stopped"),
            ("all_operations_exercised", invoked == set(TOOLS_BY_ID)),
            ("no_denied_operations", not denied),
        )
        checks = tuple(
            {"failure_code": code, "passed": bool(passed)} for code, passed in checks_raw
        )
        failures = tuple(item["failure_code"] for item in checks if not item["passed"])
        atoms = tuple(
            {
                "id": code,
                "earned": code not in failures,
                "value": 1.0 if code not in failures else 0.0,
            }
            for code in REWARD_ATOMS
        )
        return HamiltonSTARVerifierResult(
            not failures,
            checks,
            failures,
            atoms,
            sum(item["value"] for item in atoms) / len(atoms),
        )

    def task(self, *, episode: Mapping[str, Any]) -> TaskBrief:
        task = episode["task"]
        return TaskBrief(
            task_id=str(task["task_id"]),
            title=str(task["title"]),
            instructions=str(task["instructions"]),
            success_criteria=tuple(str(item) for item in task["success_criteria"]),
        )


def create_world() -> HamiltonSTARWorld:
    return HamiltonSTARWorld()
