"""Transparent gateway for one admitted provider-mediated composition session."""

from __future__ import annotations

import json
import math
import re
import secrets
import shutil
import threading
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, Header, Request
from fastapi.responses import JSONResponse

from datalox_gated_runtime.composition.events import (
    DeliveryOutcome,
    SessionEventEngine,
    SessionEventError,
)
from datalox_gated_runtime.composition.runtime_binding import (
    LoadedRuntimeComposition,
    load_runtime_composition,
)
from datalox_gated_runtime.composition.session import (
    CompositionProviderSession,
    CompositionSession,
    CompositionSessionError,
)
from datalox_gated_runtime.data_plane import ProviderBinding, create_data_plane_app
from datalox_gated_runtime.models import CallRequest, GateResponse
from datalox_gated_runtime.provider_runtime import ProviderRuntime
from datalox_gated_runtime.rollout.provider_set import LoadedMaterializedRolloutProviderSetV2

COMPOSITION_CONTROL_MAX_JSON_BYTES = 256 * 1024
_DELIVERY_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@-]{0,127}$")
_RESOLUTION_KINDS = frozenset({"delivered", "retryable_failure", "terminal_failure"})


@dataclass(frozen=True)
class CompositionControlError(ValueError):
    code: str
    message: str
    status_code: int = 400

    def __str__(self) -> str:
        return self.message


class _CompositionDataHandler:
    def __init__(self, session: CompositionSession) -> None:
        self._session = session

    def handle(self, request: CallRequest) -> GateResponse:
        return self._session.handle_agent_request(request)


class CompositionInterceptionGateway:
    """One atomic composed session behind unchanged provider authorities."""

    def __init__(
        self,
        *,
        loaded: LoadedRuntimeComposition,
        session: CompositionSession,
        control_token: str,
    ) -> None:
        if not isinstance(loaded, LoadedRuntimeComposition):
            raise TypeError("loaded must be a strict runtime composition")
        if not isinstance(session, CompositionSession):
            raise TypeError("session must be a CompositionSession")
        if not control_token:
            raise ValueError("control token must be non-empty")
        self.loaded = loaded
        self.session = session
        self._control_token = control_token
        self._lifecycle_lock = threading.RLock()
        self._final_export: dict[str, Any] | None = None

        handler = _CompositionDataHandler(session)
        shared_binding = ProviderBinding(handler=handler, lock=threading.RLock())
        authority_bindings: dict[str, ProviderBinding] = {}
        for binding in loaded.provider_set.bindings:
            for authority in binding.provider.authorities:
                if authority in authority_bindings:
                    raise ValueError(f"duplicate provider authority: {authority}")
                authority_bindings[authority] = shared_binding
        self.data_app = create_data_plane_app(authority_bindings)
        self.control_app = self._create_control_app()

    @classmethod
    def from_materialized_provider_set(
        cls,
        *,
        provider_set: LoadedMaterializedRolloutProviderSetV2,
        composition_pack_dir: Path,
        composition_admission_path: Path,
        session_root: Path,
        episode_seed: str,
        initial_time: str,
        control_token: str | None = None,
    ) -> CompositionInterceptionGateway:
        loaded = load_runtime_composition(
            provider_set=provider_set,
            pack_dir=composition_pack_dir,
            admission_path=composition_admission_path,
        )
        if session_root.exists() or session_root.is_symlink():
            raise ValueError("composition session directory must not already exist")
        session_root.mkdir(parents=True, mode=0o700)

        runtimes: dict[str, ProviderRuntime] = {}
        engine: SessionEventEngine | None = None
        try:
            for index, binding in enumerate(loaded.provider_set.bindings):
                provider_id = binding.provider.provider_id
                runtimes[provider_id] = ProviderRuntime(
                    bundle_dir=binding.bundle_dir,
                    admission_path=binding.admission_path,
                    run_dir=session_root / "providers" / f"{index:04d}",
                )
            engine = SessionEventEngine(
                session_root / "events" / "composition.sqlite3",
                episode_seed=episode_seed,
                initial_time=initial_time,
            )
            session = CompositionSession(
                pack=loaded.pack,
                admission=loaded.admission,
                providers={
                    provider_id: CompositionProviderSession(
                        release=loaded.releases[provider_id],
                        runtime=runtime,
                    )
                    for provider_id, runtime in runtimes.items()
                },
                event_engine=engine,
            )
        except BaseException:
            for runtime in runtimes.values():
                runtime.close()
            if engine is not None:
                engine.close()
            shutil.rmtree(session_root, ignore_errors=True)
            raise
        return cls(
            loaded=loaded,
            session=session,
            control_token=control_token or secrets.token_urlsafe(32),
        )

    @property
    def authorities(self) -> tuple[str, ...]:
        return tuple(
            authority
            for binding in self.loaded.provider_set.bindings
            for authority in binding.provider.authorities
        )

    def close(self) -> None:
        with self._lifecycle_lock:
            if self._final_export is None:
                self._final_export = self.session.finalize()

    def _create_control_app(self) -> FastAPI:
        app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

        def authorize(x_datalox_control_token: str | None = Header(default=None)) -> None:
            if x_datalox_control_token is None or not secrets.compare_digest(
                x_datalox_control_token,
                self._control_token,
            ):
                raise CompositionControlError(
                    "composition_control_unauthorized",
                    "The control token is invalid.",
                    401,
                )

        @app.exception_handler(CompositionControlError)
        async def composition_control_error(
            _request: Request,
            error: CompositionControlError,
        ) -> JSONResponse:
            return _control_error_response(error.code, error.message, error.status_code)

        @app.exception_handler(CompositionSessionError)
        async def composition_session_error(
            _request: Request,
            error: CompositionSessionError,
        ) -> JSONResponse:
            return _control_error_response(error.code, error.message, 409)

        @app.exception_handler(SessionEventError)
        async def composition_event_error(
            _request: Request,
            error: SessionEventError,
        ) -> JSONResponse:
            return _control_error_response(error.code, error.message, 409)

        @app.get("/health")
        def health(_: None = Depends(authorize)) -> dict[str, Any]:
            with self._lifecycle_lock:
                composition_delivery_time = (
                    self._final_export["composition_delivery_time"]
                    if self._final_export is not None
                    else self.session.composition_delivery_time
                )
                return {
                    "ok": True,
                    "session_kind": "admitted_composition",
                    "pack_id": self.loaded.pack.pack_id,
                    "providers": sorted(self.loaded.releases),
                    "time_scope": self.loaded.pack.time_scope,
                    "composition_delivery_time": composition_delivery_time,
                    "finalized": self._final_export is not None,
                }

        @app.get("/v1/composition/export")
        def export(_: None = Depends(authorize)) -> dict[str, Any]:
            with self._lifecycle_lock:
                if self._final_export is not None:
                    return self._final_export
                return self.session.export()

        @app.post("/v1/composition/reset")
        async def reset(request: Request, _: None = Depends(authorize)) -> dict[str, Any]:
            _require_empty_object(await _control_json(request))
            with self._lifecycle_lock:
                self._require_open()
                return self.session.reset()

        @app.post("/v1/composition/time/advance")
        async def advance(request: Request, _: None = Depends(authorize)) -> dict[str, str]:
            body = await _control_json(request)
            _exact_fields(body, {"to"})
            target = body["to"]
            if not isinstance(target, str):
                raise CompositionControlError(
                    "composition_control_time_invalid",
                    "The composition delivery-time target must be an RFC 3339 UTC string.",
                )
            with self._lifecycle_lock:
                self._require_open()
                return {"composition_delivery_time": self.session.advance_delivery_time_to(target)}

        @app.post("/v1/composition/deliveries/drain")
        async def drain(request: Request, _: None = Depends(authorize)) -> dict[str, Any]:
            _require_empty_object(await _control_json(request))
            with self._lifecycle_lock:
                self._require_open()
                results = self.session.drain_due()
                return {
                    "composition_delivery_time": self.session.composition_delivery_time,
                    "deliveries": [asdict(item) for item in results],
                }

        @app.post("/v1/composition/deliveries/{delivery_id}/resolve")
        async def resolve_unknown(
            delivery_id: str,
            request: Request,
            _: None = Depends(authorize),
        ) -> dict[str, Any]:
            if _DELIVERY_ID.fullmatch(delivery_id) is None:
                raise CompositionControlError(
                    "composition_control_delivery_id_invalid",
                    "The delivery id is invalid.",
                )
            body = await _control_json(request)
            outcome = _resolution_outcome(body)
            with self._lifecycle_lock:
                self._require_open()
                return asdict(self.session.resolve_unknown(delivery_id, outcome))

        @app.post("/v1/composition/finalize")
        async def finalize(request: Request, _: None = Depends(authorize)) -> dict[str, Any]:
            _require_empty_object(await _control_json(request))
            with self._lifecycle_lock:
                self._require_open()
                self._final_export = self.session.finalize()
                return self._final_export

        return app

    def _require_open(self) -> None:
        if self._final_export is not None:
            raise CompositionControlError(
                "composition_control_session_finalized",
                "The composed provider session has already been finalized.",
                409,
            )


async def _control_json(request: Request) -> dict[str, Any]:
    content_types = [
        value for name, value in request.scope.get("headers", []) if name.lower() == b"content-type"
    ]
    if len(content_types) != 1 or content_types[0].lower() != b"application/json":
        raise CompositionControlError(
            "composition_control_content_type_invalid",
            "The control request requires Content-Type: application/json.",
            415,
        )
    body = await request.body()
    if not body or len(body) > COMPOSITION_CONTROL_MAX_JSON_BYTES:
        raise CompositionControlError(
            "composition_control_body_invalid",
            "The control request body must be a bounded JSON object.",
        )
    try:
        parsed = json.loads(
            body.decode("utf-8"),
            object_pairs_hook=_unique_object,
            parse_constant=_reject_json_constant,
        )
        _require_finite_json(parsed)
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
        raise CompositionControlError(
            "composition_control_body_invalid",
            "The control request body must be valid finite JSON.",
        ) from exc
    if not isinstance(parsed, dict):
        raise CompositionControlError(
            "composition_control_body_invalid",
            "The control request body must contain a JSON object.",
        )
    return parsed


def _unique_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON object key")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"non-finite JSON constant: {value}")


def _require_finite_json(value: Any, *, depth: int = 0) -> None:
    if depth > 64:
        raise ValueError("JSON nesting exceeds the control-plane limit")
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("JSON number is not finite")
    if isinstance(value, dict):
        for item in value.values():
            _require_finite_json(item, depth=depth + 1)
    elif isinstance(value, list):
        for item in value:
            _require_finite_json(item, depth=depth + 1)


def _exact_fields(value: dict[str, Any], fields: set[str]) -> None:
    if set(value) != fields:
        raise CompositionControlError(
            "composition_control_fields_invalid",
            "The control request fields do not match the operation contract.",
        )


def _require_empty_object(value: dict[str, Any]) -> None:
    _exact_fields(value, set())


def _resolution_outcome(value: dict[str, Any]) -> DeliveryOutcome:
    _exact_fields(value, {"outcome", "status_code", "receipt"})
    kind = value["outcome"]
    if kind not in _RESOLUTION_KINDS:
        raise CompositionControlError(
            "composition_control_resolution_invalid",
            "The trusted resolution outcome is invalid.",
        )
    status_code = value["status_code"]
    if status_code is not None and (
        isinstance(status_code, bool)
        or not isinstance(status_code, int)
        or not 100 <= status_code <= 599
    ):
        raise CompositionControlError(
            "composition_control_resolution_invalid",
            "The trusted resolution status code is invalid.",
        )
    receipt = value["receipt"]
    if not isinstance(receipt, dict):
        raise CompositionControlError(
            "composition_control_resolution_invalid",
            "The trusted resolution receipt must be a JSON object.",
        )
    if kind == "delivered":
        error_code = None
        error_message = None
    elif kind == "retryable_failure":
        error_code = "composition_unknown_confirmed_not_applied"
        error_message = "The trusted controller confirmed that the write was not applied."
    else:
        error_code = "composition_unknown_confirmed_terminal"
        error_message = "The trusted controller confirmed a terminal delivery outcome."
    return DeliveryOutcome(
        kind=kind,
        receipt=receipt,
        status_code=status_code,
        error_code=error_code,
        error_message=error_message,
    )


def _control_error_response(code: str, message: str, status_code: int) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"code": code, "message": message}},
    )
