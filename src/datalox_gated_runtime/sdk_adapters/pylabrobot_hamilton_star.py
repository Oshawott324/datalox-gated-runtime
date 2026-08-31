"""PyLabRobot backend that routes Hamilton STAR dry-runs through Datalox.

The evaluated program keeps the normal :class:`pylabrobot.liquid_handling.LiquidHandler`
surface.  This backend is selected by the consumer's execution boundary and sends only
to a reserved, non-routable adapter authority that the Datalox sidecar owns.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol

import httpx
from pylabrobot.liquid_handling.backends import LiquidHandlerBackend
from pylabrobot.resources import Container, TipSpot, Trash


HAMILTON_STAR_ADAPTER_AUTHORITY = "pylabrobot-hamilton-star.invalid"


@dataclass(frozen=True)
class HamiltonSTARResponse:
    status_code: int
    body: Any


class HamiltonSTARTransport(Protocol):
    """Closed transport from the PyLabRobot backend to one Datalox provider runtime."""

    async def request(
        self,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> HamiltonSTARResponse: ...


class HamiltonSTARHttpTransport:
    """HTTPS transport for an injected Datalox Hamilton STAR sidecar."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        self._client = client

    async def request(
        self,
        *,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> HamiltonSTARResponse:
        response = await self._client.request(
            method,
            f"https://{HAMILTON_STAR_ADAPTER_AUTHORITY}{path}",
            json=body,
        )
        try:
            payload = response.json()
        except ValueError as exc:
            raise HamiltonSTARBackendError(
                code="invalid_adapter_response",
                message="The Datalox Hamilton STAR adapter returned non-JSON data.",
                status_code=response.status_code,
            ) from exc
        return HamiltonSTARResponse(response.status_code, payload)


@dataclass(frozen=True)
class HamiltonSTARBackendError(RuntimeError):
    code: str
    message: str
    status_code: int

    def __str__(self) -> str:
        return self.message


class HamiltonSTARScopeError(NotImplementedError):
    """Raised when code requests Hamilton hardware outside the declared dry-run slice."""


def _coordinate(value: Any) -> dict[str, float]:
    return {"x": float(value.x), "y": float(value.y), "z": float(value.z)}


def _optional_float(value: Any) -> float | None:
    return None if value is None else float(value)


class DataloxHamiltonSTARBackend(LiquidHandlerBackend):
    """Eight-channel Hamilton STAR dry-run backend backed by a Datalox provider pack.

    CoRe 96, iSWAP/resource movement, physical motion, calibration, and Hamilton
    liquid-class execution are intentionally outside this class's declared scope.
    """

    def __init__(self, transport: HamiltonSTARTransport) -> None:
        super().__init__()
        self._transport = transport
        self._num_channels = 8
        self._num_arms = 0
        self._head96_installed = False

    @property
    def num_channels(self) -> int:
        return self._num_channels

    async def _request(
        self,
        method: str,
        path: str,
        body: dict[str, Any] | None = None,
    ) -> Any:
        response = await self._transport.request(method=method, path=path, body=body)
        if 200 <= response.status_code < 300:
            return response.body
        error = response.body.get("error") if isinstance(response.body, dict) else None
        if isinstance(error, dict):
            code = error.get("code")
            message = error.get("message")
            if isinstance(code, str) and isinstance(message, str):
                raise HamiltonSTARBackendError(code, message, response.status_code)
        raise HamiltonSTARBackendError(
            "invalid_adapter_error",
            "The Datalox Hamilton STAR adapter returned an invalid error payload.",
            response.status_code,
        )

    async def setup(self, **backend_kwargs: Any) -> None:
        if backend_kwargs:
            raise HamiltonSTARScopeError(
                "Hamilton-specific setup options are outside the dry-run provider scope."
            )
        await super().setup()
        tip_spots: list[dict[str, Any]] = []
        containers: list[dict[str, Any]] = []
        waste_names: list[str] = []
        for resource in self.deck.get_all_children():
            if isinstance(resource, TipSpot):
                has_tip = resource.tracker.has_tip
                tip = resource.tracker.get_tip() if has_tip else None
                tip_spots.append(
                    {
                        "name": resource.name,
                        "has_tip": has_tip,
                        "max_volume_ul": (float(tip.maximal_volume) if tip is not None else None),
                    }
                )
            elif isinstance(resource, Trash):
                waste_names.append(resource.name)
            elif isinstance(resource, Container):
                containers.append(
                    {
                        "name": resource.name,
                        "volume_ul": float(resource.tracker.get_used_volume()),
                        "max_volume_ul": float(resource.max_volume),
                    }
                )
        await self._request(
            "POST",
            "/v1/liquid-handler/setup",
            {
                "num_channels": self.num_channels,
                "tip_spots": tip_spots,
                "containers": containers,
                "waste_names": waste_names,
            },
        )

    async def stop(self) -> None:
        await self._request("POST", "/v1/liquid-handler/stop", {})

    async def pick_up_tips(
        self,
        ops: list[Any],
        use_channels: list[int],
        **backend_kwargs: Any,
    ) -> None:
        self._reject_backend_kwargs(backend_kwargs)
        await self._request(
            "POST",
            "/v1/liquid-handler/commands/pick-up-tips",
            {
                "operations": [
                    {
                        "channel": channel,
                        "tip_spot": op.resource.name,
                        "offset": _coordinate(op.offset),
                    }
                    for op, channel in zip(ops, use_channels, strict=True)
                ]
            },
        )

    async def drop_tips(
        self,
        ops: list[Any],
        use_channels: list[int],
        **backend_kwargs: Any,
    ) -> None:
        self._reject_backend_kwargs(backend_kwargs)
        await self._request(
            "POST",
            "/v1/liquid-handler/commands/drop-tips",
            {
                "operations": [
                    {
                        "channel": channel,
                        "destination": op.resource.name,
                        "destination_kind": (
                            "waste" if isinstance(op.resource, Trash) else "tip_spot"
                        ),
                        "offset": _coordinate(op.offset),
                    }
                    for op, channel in zip(ops, use_channels, strict=True)
                ]
            },
        )

    async def aspirate(
        self,
        ops: list[Any],
        use_channels: list[int],
        **backend_kwargs: Any,
    ) -> None:
        self._reject_backend_kwargs(backend_kwargs)
        await self._liquid_command("aspirate", ops, use_channels)

    async def dispense(
        self,
        ops: list[Any],
        use_channels: list[int],
        **backend_kwargs: Any,
    ) -> None:
        self._reject_backend_kwargs(backend_kwargs)
        await self._liquid_command("dispense", ops, use_channels)

    async def _liquid_command(
        self,
        command: str,
        ops: list[Any],
        use_channels: list[int],
    ) -> None:
        await self._request(
            "POST",
            f"/v1/liquid-handler/commands/{command}",
            {
                "operations": [
                    {
                        "channel": channel,
                        "container": op.resource.name,
                        "volume_ul": float(op.volume),
                        "flow_rate": _optional_float(op.flow_rate),
                        "liquid_height": _optional_float(op.liquid_height),
                        "blow_out_air_volume": _optional_float(op.blow_out_air_volume),
                        "offset": _coordinate(op.offset),
                    }
                    for op, channel in zip(ops, use_channels, strict=True)
                ]
            },
        )

    async def request_tip_presence(self) -> list[bool]:
        body = await self._request("GET", "/v1/liquid-handler/tips")
        channels = body.get("channels") if isinstance(body, dict) else None
        if not isinstance(channels, list) or len(channels) != self.num_channels:
            raise HamiltonSTARBackendError(
                "invalid_tip_state",
                "The Datalox Hamilton STAR adapter returned invalid channel state.",
                500,
            )
        return [
            isinstance(channel, dict) and channel.get("tip") is not None for channel in channels
        ]

    def can_pick_up_tip(self, channel_idx: int, tip: Any) -> bool:
        return 0 <= channel_idx < self.num_channels and float(tip.maximal_volume) > 0

    async def pick_up_tips96(self, pickup: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("CoRe 96 tip pickup")

    async def drop_tips96(self, drop: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("CoRe 96 tip drop")

    async def aspirate96(self, aspiration: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("CoRe 96 aspiration")

    async def dispense96(self, dispense: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("CoRe 96 dispense")

    async def pick_up_resource(self, pickup: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("iSWAP resource pickup")

    async def move_picked_up_resource(self, move: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("iSWAP resource movement")

    async def drop_resource(self, drop: Any, **backend_kwargs: Any) -> None:
        raise self._unsupported("iSWAP resource drop")

    @staticmethod
    def _reject_backend_kwargs(backend_kwargs: dict[str, Any]) -> None:
        if backend_kwargs:
            names = ", ".join(sorted(backend_kwargs))
            raise HamiltonSTARScopeError(
                f"Hamilton-specific backend options are outside the dry-run scope: {names}."
            )

    @staticmethod
    def _unsupported(operation: str) -> HamiltonSTARScopeError:
        return HamiltonSTARScopeError(
            f"{operation} is outside the standard eight-channel Hamilton STAR dry-run scope."
        )
