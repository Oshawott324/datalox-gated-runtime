"""Trusted node-local pool for concurrent isolated rollout leases."""

from __future__ import annotations

import asyncio
import os
import secrets
import socket
import stat
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, Self

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.rollout.composition import (
    CompositionRolloutConfig,
    DockerCompositionRolloutLease,
)
from datalox_gated_runtime.rollout.docker import (
    DockerCommandResult,
    DockerRolloutError,
    DockerRolloutLease,
    DockerRolloutResult,
    RolloutSessionId,
)
from datalox_gated_runtime.rollout.provider_set import (
    load_rollout_provider_set,
    load_rollout_provider_set_v2,
)

POOL_ACQUIRE_REQUEST = "datalox_rollout_pool_acquire_request_v1"
POOL_ACQUIRE_RESPONSE = "datalox_rollout_pool_acquire_response_v1"
POOL_EXEC_REQUEST = "datalox_rollout_pool_exec_request_v1"
POOL_EXEC_RESPONSE = "datalox_rollout_pool_exec_response_v1"
POOL_FINALIZE_REQUEST = "datalox_rollout_pool_finalize_request_v1"
POOL_FINALIZE_RESPONSE = "datalox_rollout_pool_finalize_response_v1"
POOL_CANCEL_REQUEST = "datalox_rollout_pool_cancel_request_v1"
POOL_CANCEL_RESPONSE = "datalox_rollout_pool_cancel_response_v1"
POOL_ERROR_RESPONSE = "datalox_rollout_pool_error_response_v1"


@dataclass
class RolloutPoolError(ValueError):
    """Stable structured failure returned by the trusted rollout pool."""

    code: str
    message: str
    status_code: int = 400

    def __str__(self) -> str:
        return self.message


class _Lease(Protocol):
    @property
    def state(self) -> str: ...

    @property
    def initial_provider_fingerprint(self) -> str: ...

    @property
    def consumer_exit_codes(self) -> tuple[int, ...]: ...

    def exec(
        self,
        *,
        task_image: str,
        consumer_command: tuple[str, ...],
        capture_output: bool = True,
    ) -> DockerCommandResult: ...

    def finalize(self, *, output_dir: Path) -> DockerRolloutResult: ...

    def cancel(self) -> None: ...


LeaseFactory = Callable[..., _Lease]


@dataclass
class _PoolLeaseRecord:
    lease_id: str
    lease_token: str
    uid: str
    session_id: RolloutSessionId
    environment_seed: int
    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    lease: _Lease | None = None
    phase: str = "starting"

    @property
    def identity(self) -> tuple[str, RolloutSessionId]:
        return (self.uid, self.session_id)


@dataclass(frozen=True)
class AcquiredRolloutLease:
    lease_id: str
    lease_token: str
    initial_provider_fingerprint: str


@dataclass(frozen=True)
class RolloutExecResult:
    lease_id: str
    execution_index: int
    consumer_exit_code: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class FinalizedRolloutLease:
    lease_id: str
    output_dir: Path
    consumer_exit_codes: tuple[int, ...]


class RolloutPool:
    """Bounded owner of Docker leases configured by a trusted node operator."""

    def __init__(
        self,
        *,
        provider_set_path: Path,
        runtime_image: str,
        allowed_task_images: tuple[str, ...],
        capacity: int,
        artifacts_root: Path,
        lease_factory: LeaseFactory | None = None,
    ) -> None:
        loaded = load_rollout_provider_set(provider_set_path)
        self._initialize(
            runtime_image=runtime_image,
            allowed_task_images=allowed_task_images,
            capacity=capacity,
            artifacts_root=artifacts_root,
            lease_factory=lease_factory or DockerRolloutLease.start,
            lease_start_arguments={"provider_set_path": loaded.manifest_path},
        )

    @classmethod
    def from_provider_set_v2(
        cls,
        *,
        provider_set_v2_path: Path,
        registry: FilesystemProviderReleaseRegistry | Path,
        runtime_image: str,
        allowed_task_images: tuple[str, ...],
        capacity: int,
        artifacts_root: Path,
        lease_factory: LeaseFactory | None = None,
    ) -> RolloutPool:
        """Create a pool fixed to one immutable admitted Provider Set v2."""

        loaded_registry = (
            registry
            if isinstance(registry, FilesystemProviderReleaseRegistry)
            else FilesystemProviderReleaseRegistry.load(registry)
        )
        loaded = load_rollout_provider_set_v2(
            provider_set_v2_path,
            registry=loaded_registry,
        )
        self = cls.__new__(cls)
        self._initialize(
            runtime_image=runtime_image,
            allowed_task_images=allowed_task_images,
            capacity=capacity,
            artifacts_root=artifacts_root,
            lease_factory=lease_factory or DockerRolloutLease.start_provider_set_v2,
            lease_start_arguments={
                "provider_set_v2_path": loaded.manifest_path,
                "registry": loaded_registry,
            },
        )
        return self

    @classmethod
    def from_composition(
        cls,
        *,
        composition_config: CompositionRolloutConfig,
        runtime_image: str,
        allowed_task_images: tuple[str, ...],
        capacity: int,
        artifacts_root: Path,
        lease_factory: LeaseFactory | None = None,
    ) -> RolloutPool:
        """Create a pool fixed to one operator-selected admitted composition."""

        if not isinstance(composition_config, CompositionRolloutConfig):
            raise RolloutPoolError(
                "pool_composition_config_invalid",
                "composition_config must be a CompositionRolloutConfig",
            )
        self = cls.__new__(cls)
        self._initialize(
            runtime_image=runtime_image,
            allowed_task_images=allowed_task_images,
            capacity=capacity,
            artifacts_root=artifacts_root,
            lease_factory=lease_factory or DockerCompositionRolloutLease.start,
            lease_start_arguments={"composition_config": composition_config},
        )
        return self

    def _initialize(
        self,
        *,
        runtime_image: str,
        allowed_task_images: tuple[str, ...],
        capacity: int,
        artifacts_root: Path,
        lease_factory: LeaseFactory,
        lease_start_arguments: dict[str, object],
    ) -> None:
        if not isinstance(capacity, int) or isinstance(capacity, bool) or capacity < 1:
            raise RolloutPoolError("pool_capacity_invalid", "capacity must be a positive integer")
        if not allowed_task_images or any(
            not isinstance(image, str)
            or not image
            or image.strip() != image
            or any(character.isspace() for character in image)
            for image in allowed_task_images
        ):
            raise RolloutPoolError(
                "pool_task_images_invalid",
                "allowed_task_images must be a non-empty tuple of Docker image references",
            )
        if len(set(allowed_task_images)) != len(allowed_task_images):
            raise RolloutPoolError(
                "pool_task_images_duplicate",
                "allowed_task_images must not contain duplicates",
            )
        if (
            not runtime_image
            or runtime_image.strip() != runtime_image
            or any(character.isspace() for character in runtime_image)
        ):
            raise RolloutPoolError(
                "pool_runtime_image_invalid",
                "runtime_image must be a non-empty Docker image reference",
            )
        self._runtime_image = runtime_image
        self._allowed_task_images = frozenset(allowed_task_images)
        self._capacity = capacity
        self._artifacts_root = _prepare_artifacts_root(artifacts_root)
        self._lease_factory = lease_factory
        self._lease_start_arguments = lease_start_arguments
        self._lock = asyncio.Lock()
        self._records: dict[str, _PoolLeaseRecord] = {}
        self._identities: dict[tuple[str, RolloutSessionId], str] = {}
        self._closing = False

    @property
    def active_count(self) -> int:
        return len(self._records)

    async def acquire(
        self,
        *,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
    ) -> AcquiredRolloutLease:
        """Reserve capacity and create one provider-isolated rollout lease."""

        _validate_identity(uid, session_id, environment_seed)
        identity = (uid, session_id)
        record = _PoolLeaseRecord(
            lease_id=secrets.token_urlsafe(24),
            lease_token=secrets.token_urlsafe(32),
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
        )
        async with self._lock:
            if self._closing:
                raise RolloutPoolError("pool_shutting_down", "rollout pool is shutting down", 503)
            if identity in self._identities:
                raise RolloutPoolError(
                    "rollout_identity_active",
                    "uid and session_id already identify an active rollout lease",
                    409,
                )
            if len(self._records) >= self._capacity:
                raise RolloutPoolError(
                    "rollout_capacity_exceeded",
                    "rollout pool capacity is exhausted",
                    429,
                )
            self._records[record.lease_id] = record
            self._identities[identity] = record.lease_id

        try:
            async with record.lock:

                def started_after_cancellation(lease: _Lease) -> None:
                    record.lease = lease
                    record.phase = "active"

                record.lease = await _to_thread_owned(
                    self._lease_factory,
                    on_cancel_result=started_after_cancellation,
                    **self._lease_start_arguments,
                    runtime_image=self._runtime_image,
                    uid=uid,
                    session_id=session_id,
                    # This seed is rollout provenance. A fixed-seed provider bundle is not
                    # mutated or reseeded by the pool.
                    environment_seed=environment_seed,
                )
                record.phase = "active"
            async with self._lock:
                closing = self._closing
            if closing:
                await self._cancel_record(record)
                await self._remove_record(record)
                raise RolloutPoolError("pool_shutting_down", "rollout pool is shutting down", 503)
        except BaseException as exc:
            cleanup_error: DockerRolloutError | RolloutPoolError | None = None
            if record.lease is not None and record.phase == "active":
                try:
                    await self._cancel_record(record)
                except (DockerRolloutError, RolloutPoolError) as cancel_error:
                    cleanup_error = cancel_error
            await self._remove_record(record)
            if cleanup_error is not None:
                raise RolloutPoolError(
                    "rollout_start_cleanup_failed",
                    f"rollout start was interrupted ({exc}); cleanup failed ({cleanup_error})",
                    500,
                ) from cleanup_error
            if isinstance(exc, (asyncio.CancelledError, RolloutPoolError)):
                raise
            raise RolloutPoolError("rollout_start_failed", str(exc), 500) from exc
        if record.lease is None:
            await self._remove_record(record)
            raise RolloutPoolError("rollout_start_incomplete", "rollout lease did not start", 500)
        return AcquiredRolloutLease(
            lease_id=record.lease_id,
            lease_token=record.lease_token,
            initial_provider_fingerprint=record.lease.initial_provider_fingerprint,
        )

    async def exec(
        self,
        *,
        lease_id: str,
        lease_token: str,
        task_image: str,
        command: tuple[str, ...],
    ) -> RolloutExecResult:
        """Run one task command while retaining provider and workspace state."""

        if task_image not in self._allowed_task_images:
            raise RolloutPoolError(
                "task_image_not_allowed",
                "task image is not allowed by the trusted rollout pool",
                403,
            )
        _validate_command(command)
        record = await self._record(lease_id, lease_token)
        async with record.lock:
            self._require_active(record)
            if record.lease is None:
                raise RolloutPoolError(
                    "rollout_start_incomplete", "rollout lease did not start", 500
                )
            try:
                result = await _to_thread_owned(
                    record.lease.exec,
                    task_image=task_image,
                    consumer_command=command,
                    capture_output=True,
                )
            except DockerRolloutError as exc:
                raise RolloutPoolError("rollout_execution_failed", str(exc), 500) from exc
            execution_index = len(record.lease.consumer_exit_codes) - 1
            return RolloutExecResult(
                lease_id=record.lease_id,
                execution_index=execution_index,
                consumer_exit_code=result.returncode,
                stdout=result.stdout,
                stderr=result.stderr,
            )

    async def finalize(
        self,
        *,
        lease_id: str,
        lease_token: str,
    ) -> FinalizedRolloutLease:
        """Export evidence and remove a lease from the active pool."""

        record = await self._record(lease_id, lease_token)
        async with record.lock:
            self._require_active(record)
            if record.lease is None:
                raise RolloutPoolError(
                    "rollout_start_incomplete", "rollout lease did not start", 500
                )
            record.phase = "finalizing"
            output_dir = self._artifacts_root / record.lease_id
            try:

                def finalized_after_cancellation(_: DockerRolloutResult) -> None:
                    record.phase = "finalized"

                result = await _to_thread_owned(
                    record.lease.finalize,
                    on_cancel_result=finalized_after_cancellation,
                    output_dir=output_dir,
                )
            except DockerRolloutError as exc:
                cleanup_error: DockerRolloutError | None = None
                if getattr(record.lease, "state", None) == "active":
                    try:
                        await _to_thread_owned(record.lease.cancel)
                    except DockerRolloutError as cancel_error:
                        cleanup_error = cancel_error
                record.phase = "failed"
                await self._remove_record(record)
                if cleanup_error is not None:
                    raise RolloutPoolError(
                        "rollout_finalize_cleanup_failed",
                        f"finalize failed ({exc}); cleanup failed ({cleanup_error})",
                        500,
                    ) from cleanup_error
                raise RolloutPoolError("rollout_finalize_failed", str(exc), 500) from exc
            except asyncio.CancelledError:
                if record.phase != "finalized" and getattr(record.lease, "state", None) == "active":
                    try:
                        await _to_thread_owned(record.lease.cancel)
                    finally:
                        record.phase = "cancelled"
                await self._remove_record(record)
                raise
            record.phase = "finalized"
            exit_codes = record.lease.consumer_exit_codes
        await self._remove_record(record)
        return FinalizedRolloutLease(
            lease_id=record.lease_id,
            output_dir=result.output_dir,
            consumer_exit_codes=exit_codes,
        )

    async def cancel(self, *, lease_id: str, lease_token: str) -> None:
        """Destroy a lease without exporting it."""

        record = await self._record(lease_id, lease_token)
        try:
            await self._cancel_record(record)
        finally:
            await self._remove_record(record)

    async def shutdown(self) -> None:
        """Reject new work and clean every lease before returning."""

        async with self._lock:
            self._closing = True
            records = tuple(self._records.values())
        results = await asyncio.gather(
            *(self._cancel_record(record) for record in records),
            return_exceptions=True,
        )
        for record in records:
            await self._remove_record(record)
        failures = [result for result in results if isinstance(result, BaseException)]
        if failures:
            raise RolloutPoolError(
                "pool_shutdown_cleanup_failed",
                f"could not clean {len(failures)} rollout lease(s) during shutdown",
                500,
            )

    async def _record(self, lease_id: str, lease_token: str) -> _PoolLeaseRecord:
        if not isinstance(lease_id, str) or not lease_id:
            raise RolloutPoolError("lease_id_invalid", "lease_id must be non-empty")
        if not isinstance(lease_token, str) or not lease_token:
            raise RolloutPoolError("lease_token_invalid", "lease_token must be non-empty")
        async with self._lock:
            record = self._records.get(lease_id)
        if record is None:
            raise RolloutPoolError("rollout_lease_not_active", "rollout lease is not active", 404)
        if not secrets.compare_digest(record.lease_token, lease_token):
            raise RolloutPoolError(
                "rollout_lease_token_invalid", "rollout lease token is invalid", 403
            )
        return record

    async def _cancel_record(self, record: _PoolLeaseRecord) -> None:
        async with record.lock:
            if record.phase in {"finalized", "cancelled", "failed"}:
                return
            if record.lease is None:
                record.phase = "cancelled"
                return
            record.phase = "cancelling"
            try:

                def cancelled_after_cancellation(_: object) -> None:
                    record.phase = "cancelled"

                await _to_thread_owned(
                    record.lease.cancel,
                    on_cancel_result=cancelled_after_cancellation,
                )
            except DockerRolloutError as exc:
                record.phase = "failed"
                raise RolloutPoolError("rollout_cancel_failed", str(exc), 500) from exc
            record.phase = "cancelled"

    async def _remove_record(self, record: _PoolLeaseRecord) -> None:
        async with self._lock:
            if self._records.get(record.lease_id) is record:
                self._records.pop(record.lease_id)
            if self._identities.get(record.identity) == record.lease_id:
                self._identities.pop(record.identity)

    @staticmethod
    def _require_active(record: _PoolLeaseRecord) -> None:
        if record.phase != "active":
            raise RolloutPoolError(
                "rollout_lease_not_active",
                f"rollout lease is {record.phase}, not active",
                409,
            )


def create_rollout_pool_app(*, pool: RolloutPool, server_token: str) -> FastAPI:
    """Create the authenticated UDS control application for a rollout pool."""

    if not server_token:
        raise RolloutPoolError("server_token_invalid", "server token must be non-empty")
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def authenticate(request: Request, call_next: Callable[..., Any]) -> Any:
        authorization = request.headers.get("authorization", "")
        expected = f"Bearer {server_token}"
        if not secrets.compare_digest(authorization, expected):
            return _error_response(
                RolloutPoolError("pool_auth_invalid", "pool authorization failed", 401)
            )
        return await call_next(request)

    @app.post("/v1/leases/acquire")
    async def acquire(request: Request) -> JSONResponse:
        try:
            body = await _json_object(request)
            _exact_fields(
                body,
                {"schema_version", "uid", "session_id", "environment_seed"},
            )
            _schema(body, POOL_ACQUIRE_REQUEST)
            uid = body["uid"]
            session_id = body["session_id"]
            environment_seed = body["environment_seed"]
            _validate_identity(uid, session_id, environment_seed)
            result = await pool.acquire(
                uid=uid,
                session_id=session_id,
                environment_seed=environment_seed,
            )
            return JSONResponse(
                {
                    "schema_version": POOL_ACQUIRE_RESPONSE,
                    "lease_id": result.lease_id,
                    "lease_token": result.lease_token,
                    "initial_provider_fingerprint": result.initial_provider_fingerprint,
                }
            )
        except RolloutPoolError as exc:
            return _error_response(exc)

    @app.post("/v1/leases/{lease_id}/exec")
    async def execute(lease_id: str, request: Request) -> JSONResponse:
        try:
            body = await _json_object(request)
            _exact_fields(
                body,
                {"schema_version", "lease_token", "task_image", "command"},
            )
            _schema(body, POOL_EXEC_REQUEST)
            lease_token = _required_string(body["lease_token"], "lease_token")
            task_image = _required_string(body["task_image"], "task_image")
            command = _command_value(body["command"])
            result = await pool.exec(
                lease_id=lease_id,
                lease_token=lease_token,
                task_image=task_image,
                command=command,
            )
            return JSONResponse(
                {
                    "schema_version": POOL_EXEC_RESPONSE,
                    "lease_id": result.lease_id,
                    "execution_index": result.execution_index,
                    "consumer_exit_code": result.consumer_exit_code,
                    "stdout": result.stdout,
                    "stderr": result.stderr,
                }
            )
        except RolloutPoolError as exc:
            return _error_response(exc)

    @app.post("/v1/leases/{lease_id}/finalize")
    async def finalize(lease_id: str, request: Request) -> JSONResponse:
        try:
            body = await _json_object(request)
            _exact_fields(body, {"schema_version", "lease_token"})
            _schema(body, POOL_FINALIZE_REQUEST)
            result = await pool.finalize(
                lease_id=lease_id,
                lease_token=_required_string(body["lease_token"], "lease_token"),
            )
            return JSONResponse(
                {
                    "schema_version": POOL_FINALIZE_RESPONSE,
                    "lease_id": result.lease_id,
                    "output_dir": str(result.output_dir),
                    "consumer_exit_codes": list(result.consumer_exit_codes),
                }
            )
        except RolloutPoolError as exc:
            return _error_response(exc)

    @app.post("/v1/leases/{lease_id}/cancel")
    async def cancel(lease_id: str, request: Request) -> JSONResponse:
        try:
            body = await _json_object(request)
            _exact_fields(body, {"schema_version", "lease_token"})
            _schema(body, POOL_CANCEL_REQUEST)
            await pool.cancel(
                lease_id=lease_id,
                lease_token=_required_string(body["lease_token"], "lease_token"),
            )
            return JSONResponse(
                {
                    "schema_version": POOL_CANCEL_RESPONSE,
                    "lease_id": lease_id,
                    "state": "cancelled",
                }
            )
        except RolloutPoolError as exc:
            return _error_response(exc)

    return app


@dataclass(frozen=True)
class RolloutPoolEndpoint:
    socket: socket.socket
    socket_path: Path
    token_path: Path
    token: str

    def close(self) -> None:
        self.socket.close()
        self.socket_path.unlink(missing_ok=True)
        self.token_path.unlink(missing_ok=True)


def prepare_rollout_pool_endpoint(socket_path: Path) -> RolloutPoolEndpoint:
    """Create an authenticated mode-0600 Unix socket without opening a TCP listener."""

    if socket_path.is_symlink():
        raise RolloutPoolError(
            "pool_socket_symlink_forbidden", "pool socket path must not be a symbolic link"
        )
    socket_path = socket_path.absolute()
    token_path = Path(f"{socket_path}.token")
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    if socket_path.exists() or socket_path.is_symlink():
        raise RolloutPoolError("pool_socket_exists", "pool socket path already exists")
    if token_path.exists() or token_path.is_symlink():
        raise RolloutPoolError("pool_token_exists", "pool token path already exists")
    token = secrets.token_urlsafe(48)
    descriptor = os.open(token_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(descriptor, f"{token}\n".encode("ascii"))
    finally:
        os.close(descriptor)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        listener.bind(str(socket_path))
        os.chmod(socket_path, 0o600)
        listener.listen(128)
    except BaseException as exc:
        listener.close()
        socket_path.unlink(missing_ok=True)
        token_path.unlink(missing_ok=True)
        if isinstance(exc, OSError):
            raise RolloutPoolError(
                "pool_socket_bind_failed", f"could not bind pool Unix socket: {exc}"
            ) from exc
        raise
    return RolloutPoolEndpoint(listener, socket_path, token_path, token)


async def serve_rollout_pool(*, pool: RolloutPool, socket_path: Path) -> None:
    """Serve a trusted rollout pool until uvicorn requests normal shutdown."""

    import uvicorn

    endpoint = prepare_rollout_pool_endpoint(socket_path)
    app = create_rollout_pool_app(pool=pool, server_token=endpoint.token)
    server = uvicorn.Server(uvicorn.Config(app, log_level="info", access_log=False, lifespan="off"))
    try:
        await server.serve(sockets=[endpoint.socket])
    finally:
        try:
            shutdown = asyncio.create_task(pool.shutdown())
            try:
                await asyncio.shield(shutdown)
            except asyncio.CancelledError:
                await shutdown
                raise
        finally:
            endpoint.close()


class RolloutPoolClient:
    """Strict async client for the trusted node-local rollout pool."""

    def __init__(self, *, socket_path: Path, token_path: Path | None = None) -> None:
        self._socket_path = socket_path.absolute()
        self._token_path = (token_path or Path(f"{self._socket_path}.token")).absolute()
        self._token = _read_server_token(self._token_path)
        self._client = httpx.AsyncClient(
            transport=httpx.AsyncHTTPTransport(uds=str(self._socket_path)),
            base_url="http://datalox-rollout-pool",
            headers={"Authorization": f"Bearer {self._token}"},
            # A lease request owns a Docker lifecycle operation.  A generic HTTP read
            # timeout can abandon an in-flight acquire/exec while the node-local pool
            # is still completing it, leaving the caller without the resulting lease
            # identifier.  Connection, write, and pool waits remain bounded; the
            # caller's asyncio cancellation is the operation cancellation boundary.
            timeout=httpx.Timeout(connect=5.0, read=None, write=5.0, pool=5.0),
        )

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *_: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        await self._client.aclose()

    async def acquire(
        self,
        *,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
    ) -> RemoteRolloutLease:
        payload = await self._request(
            "/v1/leases/acquire",
            {
                "schema_version": POOL_ACQUIRE_REQUEST,
                "uid": uid,
                "session_id": session_id,
                "environment_seed": environment_seed,
            },
        )
        _exact_fields(
            payload,
            {
                "schema_version",
                "lease_id",
                "lease_token",
                "initial_provider_fingerprint",
            },
        )
        _schema(payload, POOL_ACQUIRE_RESPONSE)
        return RemoteRolloutLease(
            client=self,
            lease_id=_required_string(payload["lease_id"], "lease_id"),
            lease_token=_required_string(payload["lease_token"], "lease_token"),
            initial_provider_fingerprint=_required_string(
                payload["initial_provider_fingerprint"], "initial_provider_fingerprint"
            ),
        )

    @asynccontextmanager
    async def lease(
        self,
        *,
        uid: str,
        session_id: RolloutSessionId,
        environment_seed: int,
    ) -> AsyncIterator[RemoteRolloutLease]:
        """Finalize normally and cancel on any exception, including cancellation."""

        lease = await self.acquire(
            uid=uid,
            session_id=session_id,
            environment_seed=environment_seed,
        )
        try:
            yield lease
        except BaseException:
            cleanup = asyncio.create_task(lease.cancel())
            try:
                await asyncio.shield(cleanup)
            except asyncio.CancelledError:
                await cleanup
            raise
        else:
            await lease.finalize()

    async def _request(self, path: str, body: dict[str, object]) -> dict[str, object]:
        try:
            response = await self._client.post(path, json=body)
        except httpx.HTTPError as exc:
            raise RolloutPoolError(
                "pool_transport_failed",
                f"could not reach the node-local rollout pool: {exc}",
                502,
            ) from exc
        try:
            payload = response.json()
        except ValueError as exc:
            raise RolloutPoolError(
                "pool_response_invalid", "rollout pool returned invalid JSON", 502
            ) from exc
        if not isinstance(payload, dict):
            raise RolloutPoolError(
                "pool_response_invalid", "rollout pool returned a non-object response", 502
            )
        if response.status_code >= 400:
            _raise_remote_error(payload, response.status_code)
        return payload


@dataclass
class RemoteRolloutLease:
    """Client-side handle retained for an entire long-horizon agent loop."""

    client: RolloutPoolClient
    lease_id: str
    lease_token: str
    initial_provider_fingerprint: str
    state: str = "active"
    final_result: FinalizedRolloutLease | None = None

    async def exec(self, *, task_image: str, command: tuple[str, ...]) -> RolloutExecResult:
        self._require_active()
        payload = await self.client._request(
            f"/v1/leases/{self.lease_id}/exec",
            {
                "schema_version": POOL_EXEC_REQUEST,
                "lease_token": self.lease_token,
                "task_image": task_image,
                "command": list(command),
            },
        )
        _exact_fields(
            payload,
            {
                "schema_version",
                "lease_id",
                "execution_index",
                "consumer_exit_code",
                "stdout",
                "stderr",
            },
        )
        _schema(payload, POOL_EXEC_RESPONSE)
        result = RolloutExecResult(
            lease_id=_required_string(payload["lease_id"], "lease_id"),
            execution_index=_non_negative_int(payload["execution_index"], "execution_index"),
            consumer_exit_code=_exit_code(payload["consumer_exit_code"]),
            stdout=_string(payload["stdout"], "stdout"),
            stderr=_string(payload["stderr"], "stderr"),
        )
        _matching_lease_id(result.lease_id, self.lease_id)
        return result

    async def finalize(self) -> FinalizedRolloutLease:
        self._require_active()
        payload = await self.client._request(
            f"/v1/leases/{self.lease_id}/finalize",
            {
                "schema_version": POOL_FINALIZE_REQUEST,
                "lease_token": self.lease_token,
            },
        )
        _exact_fields(
            payload,
            {"schema_version", "lease_id", "output_dir", "consumer_exit_codes"},
        )
        _schema(payload, POOL_FINALIZE_RESPONSE)
        exit_codes = payload["consumer_exit_codes"]
        if not isinstance(exit_codes, list):
            raise RolloutPoolError(
                "pool_response_invalid", "consumer_exit_codes must be an array", 502
            )
        result = FinalizedRolloutLease(
            lease_id=_required_string(payload["lease_id"], "lease_id"),
            output_dir=Path(_required_string(payload["output_dir"], "output_dir")),
            consumer_exit_codes=tuple(_exit_code(value) for value in exit_codes),
        )
        _matching_lease_id(result.lease_id, self.lease_id)
        self.state = "finalized"
        self.final_result = result
        return result

    async def cancel(self) -> None:
        self._require_active()
        payload = await self.client._request(
            f"/v1/leases/{self.lease_id}/cancel",
            {
                "schema_version": POOL_CANCEL_REQUEST,
                "lease_token": self.lease_token,
            },
        )
        _exact_fields(payload, {"schema_version", "lease_id", "state"})
        _schema(payload, POOL_CANCEL_RESPONSE)
        _matching_lease_id(_required_string(payload["lease_id"], "lease_id"), self.lease_id)
        if payload["state"] != "cancelled":
            raise RolloutPoolError("pool_response_invalid", "cancel response state is invalid", 502)
        self.state = "cancelled"

    def _require_active(self) -> None:
        if self.state != "active":
            raise RolloutPoolError(
                "rollout_lease_not_active", f"rollout lease is {self.state}, not active", 409
            )


async def _json_object(request: Request) -> dict[str, object]:
    try:
        value = await request.json()
    except ValueError as exc:
        raise RolloutPoolError("request_json_invalid", "request body must be valid JSON") from exc
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise RolloutPoolError("request_object_required", "request body must be a JSON object")
    return value


def _error_response(error: RolloutPoolError) -> JSONResponse:
    return JSONResponse(
        {
            "schema_version": POOL_ERROR_RESPONSE,
            "error": {"code": error.code, "message": error.message},
        },
        status_code=error.status_code,
    )


def _raise_remote_error(payload: dict[str, object], status_code: int) -> None:
    _exact_fields(payload, {"schema_version", "error"})
    _schema(payload, POOL_ERROR_RESPONSE)
    raw_error = payload["error"]
    if not isinstance(raw_error, dict):
        raise RolloutPoolError("pool_response_invalid", "error response is invalid", 502)
    _exact_fields(raw_error, {"code", "message"})
    raise RolloutPoolError(
        _required_string(raw_error["code"], "error.code"),
        _required_string(raw_error["message"], "error.message"),
        status_code,
    )


def _schema(body: dict[str, object], expected: str) -> None:
    if body.get("schema_version") != expected:
        raise RolloutPoolError("schema_version_invalid", f"schema_version must be {expected!r}")


def _exact_fields(body: dict[str, object], expected: set[str]) -> None:
    actual = set(body)
    if actual != expected:
        raise RolloutPoolError(
            "message_fields_invalid",
            f"message fields do not match the contract; missing={sorted(expected - actual)!r}, "
            f"unknown={sorted(actual - expected)!r}",
        )


def _validate_identity(uid: object, session_id: object, environment_seed: object) -> None:
    _required_string(uid, "uid")
    if len(uid) > 256:
        raise RolloutPoolError("uid_invalid", "uid must be at most 256 characters")
    if isinstance(session_id, bool):
        raise RolloutPoolError(
            "session_id_invalid",
            "session_id must be a non-negative integer or non-empty string",
        )
    if isinstance(session_id, int):
        if session_id < 0:
            raise RolloutPoolError("session_id_invalid", "integer session_id must be non-negative")
    elif isinstance(session_id, str):
        _required_string(session_id, "session_id")
        if len(session_id) > 256:
            raise RolloutPoolError(
                "session_id_invalid", "string session_id must be at most 256 characters"
            )
    else:
        raise RolloutPoolError(
            "session_id_invalid",
            "session_id must be a non-negative integer or non-empty string",
        )
    _non_negative_int(environment_seed, "environment_seed")


def _validate_command(command: tuple[str, ...]) -> None:
    if not command or any(
        not isinstance(item, str) or not item or "\x00" in item for item in command
    ):
        raise RolloutPoolError(
            "command_invalid", "command must be a non-empty string array without NUL bytes"
        )


def _command_value(value: object) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise RolloutPoolError("command_invalid", "command must be a non-empty string array")
    command = tuple(value)
    _validate_command(command)
    return command


def _required_string(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value.strip() != value:
        raise RolloutPoolError(f"{field}_invalid", f"{field} must be a non-empty string")
    return value


def _string(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise RolloutPoolError(f"{field}_invalid", f"{field} must be a string")
    return value


def _non_negative_int(value: object, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise RolloutPoolError(f"{field}_invalid", f"{field} must be a non-negative integer")
    return value


def _exit_code(value: object) -> int:
    result = _non_negative_int(value, "consumer_exit_code")
    if result > 255:
        raise RolloutPoolError(
            "consumer_exit_code_invalid", "consumer_exit_code must not exceed 255"
        )
    return result


def _prepare_artifacts_root(path: Path) -> Path:
    if path.is_symlink():
        raise RolloutPoolError(
            "artifacts_root_symlink_forbidden", "artifacts root must not be a symbolic link"
        )
    path.mkdir(parents=True, exist_ok=True)
    resolved = path.resolve(strict=True)
    if not resolved.is_dir():
        raise RolloutPoolError("artifacts_root_invalid", "artifacts root must be a directory")
    return resolved


def _read_server_token(path: Path) -> str:
    if path.is_symlink():
        raise RolloutPoolError(
            "pool_token_symlink_forbidden", "pool token file must not be a symbolic link"
        )
    try:
        metadata = path.stat()
        mode = stat.S_IMODE(metadata.st_mode)
    except OSError as exc:
        raise RolloutPoolError(
            "pool_token_unreadable", f"could not read pool token metadata: {exc}"
        ) from exc
    if mode != 0o600:
        raise RolloutPoolError(
            "pool_token_permissions_invalid", "pool token file mode must be 0600"
        )
    if metadata.st_uid != os.geteuid():
        raise RolloutPoolError(
            "pool_token_owner_invalid", "pool token file must be owned by the current user"
        )
    try:
        token = path.read_text(encoding="ascii").strip()
    except (OSError, UnicodeError) as exc:
        raise RolloutPoolError(
            "pool_token_unreadable", f"could not read pool token: {exc}"
        ) from exc
    return _required_string(token, "pool_token")


def _matching_lease_id(observed: str, expected: str) -> None:
    if not secrets.compare_digest(observed, expected):
        raise RolloutPoolError(
            "pool_response_invalid", "response lease_id does not match the request", 502
        )


async def _to_thread_owned(
    function: Callable[..., Any],
    /,
    *args: object,
    on_cancel_result: Callable[[Any], None] | None = None,
    **kwargs: object,
) -> Any:
    """Let an in-flight blocking operation settle before propagating cancellation."""

    task = asyncio.create_task(asyncio.to_thread(function, *args, **kwargs))
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(task)
            break
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
            continue
        except BaseException:
            if cancellation is not None:
                raise cancellation
            raise
    if cancellation is not None:
        if on_cancel_result is not None:
            on_cancel_result(result)
        raise cancellation
    return result
