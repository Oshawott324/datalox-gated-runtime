from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass, field
import json
import logging
from pathlib import Path
import re
import secrets
import shutil
import time
from typing import Any, Callable, Mapping

from fastapi import FastAPI, Request
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from datalox_gated_runtime.mcp_server import build_server
from datalox_gated_runtime.public_export import build_public_run_export
from datalox_gated_runtime.session import create_session, finalize_session


_MCP_PATH = re.compile(r"^/sessions/([^/]+)/mcp/?$")
_LOGGER = logging.getLogger(__name__)


@dataclass
class _RemoteSession:
    session_id: str
    token: str
    example: str
    run_dir: Path
    expires_at: float
    mcp_app: ASGIApp
    mcp_lifespan: _ManagedMcpLifespan
    operation_lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    requests_idle: asyncio.Event = field(default_factory=asyncio.Event)
    operations_idle: asyncio.Event = field(default_factory=asyncio.Event)
    active_requests: int = 0
    active_operations: int = 0
    status: str = "active"
    public_export: dict[str, Any] | None = None

    def __post_init__(self) -> None:
        self.requests_idle.set()
        self.operations_idle.set()


class _ManagedMcpLifespan:
    """Keep a child ASGI lifespan in one owner task from enter through exit."""

    def __init__(self, app: Any) -> None:
        self.app = app
        self._started = asyncio.Event()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        self._start_error: BaseException | None = None

    async def start(self) -> None:
        self._task = asyncio.create_task(self._run())
        await self._started.wait()
        if self._start_error is not None:
            await self._task

    async def close(self) -> None:
        if self._task is None:
            return
        self._stop.set()
        await self._task
        self._task = None

    async def _run(self) -> None:
        try:
            async with self.app.router.lifespan_context(self.app):
                self._started.set()
                await self._stop.wait()
        except BaseException as exc:
            self._start_error = exc
            self._started.set()
            raise


class RemoteWorldService:
    """Multi-session, dry-run-only Streamable HTTP MCP service."""

    def __init__(
        self,
        *,
        runs_root: Path,
        allowed_examples: set[str] | frozenset[str],
        max_sessions: int,
        ttl_seconds: float,
        cleanup_interval_seconds: float = 5.0,
        allowed_hosts: list[str] | tuple[str, ...],
        allowed_origins: list[str] | tuple[str, ...],
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not allowed_examples:
            raise ValueError("allowed_examples must not be empty")
        if max_sessions < 1:
            raise ValueError("max_sessions must be at least 1")
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        if cleanup_interval_seconds <= 0:
            raise ValueError("cleanup_interval_seconds must be positive")
        if not allowed_hosts:
            raise ValueError("allowed_hosts must not be empty")

        self.runs_root = Path(runs_root).resolve()
        self.allowed_examples = frozenset(allowed_examples)
        self.max_sessions = max_sessions
        self.ttl_seconds = ttl_seconds
        self.cleanup_interval_seconds = cleanup_interval_seconds
        self.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=True,
            allowed_hosts=list(allowed_hosts),
            allowed_origins=list(allowed_origins),
        )
        self._clock = clock
        self._sessions: dict[str, _RemoteSession] = {}
        self._sessions_lock = asyncio.Lock()
        self._pending_creates = 0
        self._cleanup_task: asyncio.Task[None] | None = None
        self.control_app = FastAPI(lifespan=self._lifespan)
        self._register_routes()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            match = _MCP_PATH.fullmatch(scope.get("path", ""))
            if match is not None:
                await self._dispatch_mcp(match.group(1), scope, receive, send)
                return
        await self.control_app(scope, receive, send)

    @asynccontextmanager
    async def _lifespan(self, _: FastAPI):
        self.runs_root.mkdir(parents=True, exist_ok=True)
        self._cleanup_task = asyncio.create_task(self._cleanup_loop())
        try:
            yield
        finally:
            if self._cleanup_task is not None:
                self._cleanup_task.cancel()
                with suppress(asyncio.CancelledError):
                    await self._cleanup_task
            async with self._sessions_lock:
                sessions = list(self._sessions.values())
                self._sessions.clear()
            for session in sessions:
                async with session.operation_lock:
                    session.status = "shutdown"
                await self._close_and_remove(session)

    def _register_routes(self) -> None:
        @self.control_app.get("/health")
        async def health() -> dict[str, Any]:
            async with self._sessions_lock:
                active = sum(session.status == "active" for session in self._sessions.values())
            return {
                "ok": True,
                "service": "datalox_remote_world_service",
                "active_sessions": active,
                "max_sessions": self.max_sessions,
                "live_mode": False,
            }

        @self.control_app.post("/sessions")
        async def create_remote_session(request: Request) -> JSONResponse:
            payload, error = await _request_object(request)
            if error is not None:
                return error
            assert payload is not None
            unknown = sorted(set(payload) - {"example", "seed"})
            if unknown:
                return _error(
                    400,
                    "remote_session_request_invalid",
                    "Session request contains unsupported fields.",
                    {"fields": unknown},
                )
            example = payload.get("example")
            if not isinstance(example, str) or not example:
                return _error(
                    400,
                    "remote_session_request_invalid",
                    "example must be a non-empty string.",
                )
            if example not in self.allowed_examples:
                return _error(
                    403,
                    "remote_example_not_allowed",
                    "The requested example is not allowlisted.",
                    {"example": example},
                )
            seed = payload.get("seed")
            if seed is not None and (type(seed) is not int or seed < 0):
                return _error(
                    400,
                    "remote_session_request_invalid",
                    "seed must be a non-negative integer.",
                )
            try:
                return await self._create(example=example, seed=seed)
            except Exception:
                _LOGGER.exception("Remote session creation failed for example %s.", example)
                return _error(
                    500,
                    "remote_session_create_failed",
                    "The isolated remote session could not be created.",
                )

        @self.control_app.post("/sessions/{session_id}/finalize")
        async def finalize_remote_session(session_id: str, request: Request) -> JSONResponse:
            session, error = await self._authorized_session(session_id, request.headers)
            if error is not None:
                return error
            assert session is not None
            async with session.operation_lock:
                if self._expired(session) and session.status != "finalizing":
                    session.status = "expired"
                    expired = True
                elif session.status == "finalized" and session.public_export is not None:
                    return JSONResponse(session.public_export)
                elif session.status != "active":
                    return _error(410, "remote_session_unavailable", "Session is not active.")
                else:
                    session.status = "finalizing"
                    expired = False

            if expired:
                await self._unregister_and_remove(session)
                return _error(410, "remote_session_expired", "Session has expired.")

            try:
                await session.operations_idle.wait()
                await session.mcp_lifespan.close()
                await session.requests_idle.wait()
                audit = await asyncio.to_thread(finalize_session, session.run_dir)
                public_export = await asyncio.to_thread(
                    build_public_run_export,
                    session.run_dir,
                    session.example,
                    audit,
                )
            except Exception:
                _LOGGER.exception("Remote session finalization failed for %s.", session.session_id)
                async with session.operation_lock:
                    session.status = "finalize_failed"
                return _error(
                    500,
                    "remote_session_finalize_failed",
                    "Session finalization failed.",
                )
            async with session.operation_lock:
                session.public_export = public_export
                session.status = "finalized"
            return JSONResponse(public_export)

        @self.control_app.get("/sessions/{session_id}/export")
        async def get_public_export(session_id: str, request: Request) -> JSONResponse:
            session, error = await self._authorized_session(session_id, request.headers)
            if error is not None:
                return error
            assert session is not None
            async with session.operation_lock:
                if self._expired(session) and session.status != "finalizing":
                    session.status = "expired"
                    expired = True
                    public_export = None
                else:
                    expired = False
                    public_export = session.public_export
                    finalized = session.status == "finalized"
            if expired:
                await self._unregister_and_remove(session)
                return _error(410, "remote_session_expired", "Session has expired.")
            if not finalized or public_export is None:
                return _error(
                    409,
                    "remote_session_not_finalized",
                    "Finalize the session before requesting its public export.",
                )
            return JSONResponse(public_export)

        @self.control_app.delete("/sessions/{session_id}")
        async def delete_remote_session(session_id: str, request: Request) -> JSONResponse:
            session, error = await self._authorized_session(session_id, request.headers)
            if error is not None:
                return error
            assert session is not None
            async with session.operation_lock:
                if session.status == "finalizing":
                    return _error(
                        409,
                        "remote_session_finalizing",
                        "Session finalization is in progress.",
                    )
                session.status = "deleted"
            async with self._sessions_lock:
                if self._sessions.get(session_id) is session:
                    self._sessions.pop(session_id)
            await self._close_and_remove(session)
            return JSONResponse({"deleted": True, "session_id": session_id})

    async def _create(self, *, example: str, seed: int | None) -> JSONResponse:
        await self._cleanup_expired()
        async with self._sessions_lock:
            if len(self._sessions) + self._pending_creates >= self.max_sessions:
                return _error(
                    429,
                    "remote_session_capacity_reached",
                    "The remote session capacity has been reached.",
                    {"max_sessions": self.max_sessions},
                )
            self._pending_creates += 1

        session_id = f"rws_{secrets.token_urlsafe(24)}"
        token = secrets.token_urlsafe(32)
        run_dir = self.runs_root / session_id
        mcp_lifespan: _ManagedMcpLifespan | None = None
        try:
            await asyncio.to_thread(
                create_session,
                example=example,
                out_dir=run_dir,
                http_port=0,
                seed=seed,
            )
            server = build_server(
                run_dir,
                transport_security=self.transport_security,
                include_session_manifest_tool=False,
            )
            if not isinstance(server, FastMCP):
                raise ValueError(
                    "allowlisted remote examples must expose the FastMCP world surface"
                )
            mcp_app = server.streamable_http_app()
            mcp_lifespan = _ManagedMcpLifespan(mcp_app)
            await mcp_lifespan.start()
            task = _load_json_object(run_dir / "task.json")
        except BaseException:
            if mcp_lifespan is not None:
                with suppress(BaseException):
                    await mcp_lifespan.close()
            shutil.rmtree(run_dir, ignore_errors=True)
            async with self._sessions_lock:
                self._pending_creates -= 1
            raise

        session = _RemoteSession(
            session_id=session_id,
            token=token,
            example=example,
            run_dir=run_dir,
            expires_at=self._clock() + self.ttl_seconds,
            mcp_app=mcp_app,
            mcp_lifespan=mcp_lifespan,
        )
        async with self._sessions_lock:
            self._pending_creates -= 1
            self._sessions[session_id] = session

        return JSONResponse(
            {
                "schema_version": "datalox_remote_world_session_v1",
                "session_id": session_id,
                "token": token,
                "mcp_url": f"/sessions/{session_id}/mcp",
                "expires_in_seconds": self.ttl_seconds,
                "example": example,
                "task": task,
                "live_mode": False,
            },
            status_code=201,
        )

    async def _dispatch_mcp(
        self,
        session_id: str,
        scope: Scope,
        receive: Receive,
        send: Send,
    ) -> None:
        headers = _headers(scope)
        session, error = await self._authorized_session(session_id, headers)
        if error is not None:
            await error(scope, receive, send)
            return
        assert session is not None

        async with session.operation_lock:
            if session.status != "active":
                await _error(
                    410,
                    "remote_session_unavailable",
                    "Session is not active.",
                )(scope, receive, send)
                return
            if self._expired(session):
                session.status = "expired"
                expired = True
            else:
                expired = False
                session.active_requests += 1
                session.requests_idle.clear()
                is_operation = scope.get("method", "").upper() != "GET"
                if is_operation:
                    session.active_operations += 1
                    session.operations_idle.clear()

        if expired:
            await self._unregister_and_remove(session)
            await _error(
                410,
                "remote_session_expired",
                "Session has expired.",
            )(scope, receive, send)
            return

        child_scope = dict(scope)
        child_scope["path"] = "/mcp"
        child_scope["raw_path"] = b"/mcp"
        child_scope["root_path"] = ""
        try:
            await session.mcp_app(child_scope, receive, send)
        finally:
            async with session.operation_lock:
                session.active_requests -= 1
                if session.active_requests == 0:
                    session.requests_idle.set()
                if is_operation:
                    session.active_operations -= 1
                    if session.active_operations == 0:
                        session.operations_idle.set()

    async def _authorized_session(
        self,
        session_id: str,
        headers: Mapping[str, str],
    ) -> tuple[_RemoteSession | None, JSONResponse | None]:
        async with self._sessions_lock:
            session = self._sessions.get(session_id)
        if session is None:
            return None, _error(404, "remote_session_not_found", "Session was not found.")
        authorization = headers.get("authorization", "")
        scheme, separator, token = authorization.partition(" ")
        if (
            not separator
            or scheme.lower() != "bearer"
            or not token
            or not secrets.compare_digest(token, session.token)
        ):
            return None, _error(
                401,
                "remote_session_unauthorized",
                "A valid session bearer token is required.",
            )
        return session, None

    async def _cleanup_loop(self) -> None:
        while True:
            await asyncio.sleep(self.cleanup_interval_seconds)
            await self._cleanup_expired()

    async def _cleanup_expired(self) -> None:
        async with self._sessions_lock:
            expired = [session for session in self._sessions.values() if self._expired(session)]
        for session in expired:
            async with session.operation_lock:
                if session.status in {"finalizing", "expired", "deleted", "shutdown"}:
                    continue
                if not self._expired(session):
                    continue
                session.status = "expired"
            await self._unregister_and_remove(session)

    def _expired(self, session: _RemoteSession) -> bool:
        return self._clock() >= session.expires_at

    async def _close_and_remove(self, session: _RemoteSession) -> None:
        await session.operations_idle.wait()
        with suppress(Exception):
            await session.mcp_lifespan.close()
        await session.requests_idle.wait()
        await asyncio.to_thread(shutil.rmtree, session.run_dir, True)

    async def _unregister_and_remove(self, session: _RemoteSession) -> None:
        async with self._sessions_lock:
            if self._sessions.get(session.session_id) is session:
                self._sessions.pop(session.session_id)
                removed = True
            else:
                removed = False
        if removed:
            await self._close_and_remove(session)


def create_remote_world_app(
    *,
    runs_root: Path,
    allowed_examples: set[str] | frozenset[str],
    max_sessions: int = 8,
    ttl_seconds: float = 3600.0,
    cleanup_interval_seconds: float = 5.0,
    allowed_hosts: list[str] | tuple[str, ...],
    allowed_origins: list[str] | tuple[str, ...] = (),
) -> RemoteWorldService:
    return RemoteWorldService(
        runs_root=runs_root,
        allowed_examples=allowed_examples,
        max_sessions=max_sessions,
        ttl_seconds=ttl_seconds,
        cleanup_interval_seconds=cleanup_interval_seconds,
        allowed_hosts=allowed_hosts,
        allowed_origins=allowed_origins,
    )


async def _request_object(
    request: Request,
) -> tuple[dict[str, Any] | None, JSONResponse | None]:
    try:
        payload = await request.json()
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None, _error(
            400,
            "remote_session_request_invalid",
            "Request body must be valid JSON.",
        )
    if not isinstance(payload, dict):
        return None, _error(
            400,
            "remote_session_request_invalid",
            "Request body must be a JSON object.",
        )
    return payload, None


def _load_json_object(path: Path) -> dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, dict):
        raise ValueError(f"JSON object required: {path.name}")
    return payload


def _headers(scope: Scope) -> dict[str, str]:
    return {
        key.decode("latin-1").lower(): value.decode("latin-1")
        for key, value in scope.get("headers", [])
    }


def _error(
    status_code: int,
    code: str,
    message: str,
    details: dict[str, Any] | None = None,
) -> JSONResponse:
    error: dict[str, Any] = {"code": code, "message": message}
    if details:
        error["details"] = details
    return JSONResponse({"error": error}, status_code=status_code)
