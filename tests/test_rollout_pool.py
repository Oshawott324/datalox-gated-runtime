from __future__ import annotations

import asyncio
import hashlib
import json
import stat
import threading
import uuid
from pathlib import Path
from typing import Any, ClassVar

import httpx
import jsonschema
import pytest
from world_v1_helpers import create_valid_bundle
from test_rollout_provider_set_v2 import _publish_example_release

from datalox_gated_runtime.provider_runtime import build_provider_runtime_from_world
from datalox_gated_runtime.rollout.docker import (
    DockerCommandResult,
    DockerRolloutError,
    DockerRolloutResult,
)
from datalox_gated_runtime.rollout.pool import (
    POOL_ACQUIRE_REQUEST,
    RolloutPool,
    RolloutPoolClient,
    RolloutPoolError,
    create_rollout_pool_app,
    prepare_rollout_pool_endpoint,
    serve_rollout_pool,
)
from datalox_gated_runtime.rollout.provider_set import (
    ProviderReleaseSelection,
    write_rollout_provider_set_v2,
)

ROOT = Path(__file__).resolve().parents[1]
FINGERPRINT = f"sha256:{'a' * 64}"


def _provider_set(tmp_path: Path) -> Path:
    source = create_valid_bundle(tmp_path / "source")
    bundle = tmp_path / "providers" / "orders"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id="orders",
        authorities=("api.orders.example",),
        episode_id="episode-1",
    )
    digest = hashlib.sha256((bundle / "provider-runtime.json").read_bytes()).hexdigest()
    manifest = tmp_path / "rollout-providers.json"
    manifest.write_text(
        json.dumps(
            {
                "schema_version": "datalox_rollout_provider_set_v1",
                "providers": [
                    {
                        "provider_id": "orders",
                        "bundle_path": "providers/orders",
                        "provider_runtime_sha256": f"sha256:{digest}",
                    }
                ],
            }
        )
    )
    return manifest


class FakeLease:
    instances: ClassVar[list[FakeLease]] = []
    start_threads: ClassVar[list[int]] = []

    def __init__(self, **metadata: Any) -> None:
        self.metadata = metadata
        self.initial_provider_fingerprint = FINGERPRINT
        self._exit_codes: list[int] = []
        self.commands: list[tuple[str, ...]] = []
        self.cancelled = False
        self.finalized = False
        self.workspace_counter = 0
        self.operation_threads: list[int] = []
        self.state = "active"
        self.__class__.instances.append(self)

    @classmethod
    def start(cls, **metadata: Any) -> FakeLease:
        cls.start_threads.append(threading.get_ident())
        return cls(**metadata)

    @property
    def consumer_exit_codes(self) -> tuple[int, ...]:
        return tuple(self._exit_codes)

    def exec(
        self,
        *,
        task_image: str,
        consumer_command: tuple[str, ...],
        capture_output: bool = True,
    ) -> DockerCommandResult:
        assert task_image == "task:allowed"
        assert capture_output is True
        self.operation_threads.append(threading.get_ident())
        self.commands.append(consumer_command)
        self.workspace_counter += 1
        exit_code = 31 if len(self.commands) == 1 else 0
        self._exit_codes.append(exit_code)
        return DockerCommandResult(
            exit_code,
            stdout=f"workspace={self.workspace_counter}\n",
            stderr=f"call={len(self.commands)}\n",
        )

    def finalize(self, *, output_dir: Path) -> DockerRolloutResult:
        self.operation_threads.append(threading.get_ident())
        output_dir.mkdir()
        self.finalized = True
        self.state = "finalized"
        return DockerRolloutResult(
            output_dir=output_dir.resolve(),
            consumer_exit_code=self._exit_codes[-1] if self._exit_codes else None,
        )

    def cancel(self) -> None:
        self.operation_threads.append(threading.get_ident())
        self.cancelled = True
        self.state = "cancelled"


def _pool(tmp_path: Path, *, capacity: int = 2) -> RolloutPool:
    FakeLease.instances.clear()
    FakeLease.start_threads.clear()
    return RolloutPool(
        provider_set_path=_provider_set(tmp_path),
        runtime_image="runtime:image",
        allowed_task_images=("task:allowed",),
        capacity=capacity,
        artifacts_root=tmp_path / "artifacts",
        lease_factory=FakeLease.start,
    )


def test_pool_accepts_only_resolved_admitted_provider_set_v2(tmp_path: Path) -> None:
    async def scenario() -> None:
        FakeLease.instances.clear()
        registry, reference = _publish_example_release(tmp_path)
        provider_set = write_rollout_provider_set_v2(
            selections=(ProviderReleaseSelection(reference, "default"),),
            registry=registry,
            output_path=tmp_path / "provider-set-v2.json",
        )
        pool = RolloutPool.from_provider_set_v2(
            provider_set_v2_path=provider_set.manifest_path,
            registry=registry,
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=FakeLease.start,
        )

        acquired = await pool.acquire(uid="worker-1", session_id="4", environment_seed=9)
        lease = FakeLease.instances[-1]
        assert lease.metadata["provider_set_v2_path"] == provider_set.manifest_path
        assert lease.metadata["registry"] is registry
        await pool.cancel(lease_id=acquired.lease_id, lease_token=acquired.lease_token)

    asyncio.run(scenario())


def test_pool_retains_state_within_lease_and_isolates_cross_lease_state(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path)
        one = await pool.acquire(uid="uid", session_id="0", environment_seed=91)
        two = await pool.acquire(uid="uid", session_id="1", environment_seed=91)

        first = await pool.exec(
            lease_id=one.lease_id,
            lease_token=one.lease_token,
            task_image="task:allowed",
            command=("first",),
        )
        second = await pool.exec(
            lease_id=one.lease_id,
            lease_token=one.lease_token,
            task_image="task:allowed",
            command=("second",),
        )
        independent = await pool.exec(
            lease_id=two.lease_id,
            lease_token=two.lease_token,
            task_image="task:allowed",
            command=("independent",),
        )

        assert one.lease_id != two.lease_id
        assert one.lease_token != two.lease_token
        assert first.consumer_exit_code == 31
        assert second.consumer_exit_code == 0
        assert first.stdout == "workspace=1\n"
        assert second.stdout == "workspace=2\n"
        assert independent.stdout == "workspace=1\n"
        assert second.stderr == "call=2\n"
        assert len(FakeLease.instances) == 2
        assert FakeLease.instances[0].metadata["uid"] == "uid"
        assert FakeLease.instances[0].metadata["session_id"] == "0"
        assert FakeLease.instances[0].metadata["environment_seed"] == 91
        assert all(thread != threading.get_ident() for thread in FakeLease.start_threads)
        assert all(
            thread != threading.get_ident()
            for lease in FakeLease.instances
            for thread in lease.operation_threads
        )

        finalized = await pool.finalize(lease_id=one.lease_id, lease_token=one.lease_token)
        assert finalized.consumer_exit_codes == (31, 0)
        assert finalized.output_dir.parent == (tmp_path / "artifacts").resolve()
        assert "uid" not in finalized.output_dir.name
        assert FakeLease.instances[0].finalized is True
        await pool.cancel(lease_id=two.lease_id, lease_token=two.lease_token)
        assert FakeLease.instances[1].cancelled is True
        assert pool.active_count == 0

        with pytest.raises(RolloutPoolError, match="not active"):
            await pool.exec(
                lease_id=one.lease_id,
                lease_token=one.lease_token,
                task_image="task:allowed",
                command=("again",),
            )

    asyncio.run(scenario())


def test_thirty_two_concurrent_grpo_siblings_are_isolated(tmp_path: Path) -> None:
    async def scenario() -> None:
        sibling_count = 32
        pool = _pool(tmp_path, capacity=sibling_count)
        acquired = await asyncio.gather(
            *(
                pool.acquire(uid="grpo-group", session_id=str(index), environment_seed=73)
                for index in range(sibling_count)
            )
        )
        assert len({item.lease_id for item in acquired}) == sibling_count
        assert len({item.lease_token for item in acquired}) == sibling_count
        assert {item.initial_provider_fingerprint for item in acquired} == {FINGERPRINT}

        executions = await asyncio.gather(
            *(
                pool.exec(
                    lease_id=item.lease_id,
                    lease_token=item.lease_token,
                    task_image="task:allowed",
                    command=("provider-call", str(index)),
                )
                for index, item in enumerate(acquired)
            )
        )
        assert [result.stdout for result in executions] == ["workspace=1\n"] * sibling_count
        assert all(lease.workspace_counter == 1 for lease in FakeLease.instances)

        finalized = await asyncio.gather(
            *(
                pool.finalize(lease_id=item.lease_id, lease_token=item.lease_token)
                for item in acquired
            )
        )
        assert len({result.output_dir for result in finalized}) == sibling_count
        assert pool.active_count == 0

    asyncio.run(scenario())


def test_pool_atomically_rejects_duplicate_identity_and_capacity(tmp_path: Path) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path, capacity=1)
        active = await pool.acquire(uid="same", session_id="4", environment_seed=0)
        with pytest.raises(RolloutPoolError) as duplicate:
            await pool.acquire(uid="same", session_id="4", environment_seed=0)
        assert duplicate.value.code == "rollout_identity_active"
        with pytest.raises(RolloutPoolError) as full:
            await pool.acquire(uid="other", session_id="4", environment_seed=0)
        assert full.value.code == "rollout_capacity_exceeded"
        await pool.cancel(lease_id=active.lease_id, lease_token=active.lease_token)

    asyncio.run(scenario())


def test_pool_preserves_framework_native_integer_and_string_session_identity(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path, capacity=2)
        native_uuid = "2d30d4f7-4097-4325-a3cb-7fbd2924c825"
        acquired = await pool.acquire(
            uid="slime-training-run",
            session_id=native_uuid,
            environment_seed=17,
        )
        assert FakeLease.instances[-1].metadata["session_id"] == native_uuid
        await pool.cancel(lease_id=acquired.lease_id, lease_token=acquired.lease_token)

        integer = await pool.acquire(uid="framework-run", session_id=0, environment_seed=17)
        string = await pool.acquire(uid="framework-run", session_id="0", environment_seed=17)
        assert FakeLease.instances[-2].metadata["session_id"] == 0
        assert FakeLease.instances[-1].metadata["session_id"] == "0"
        await pool.cancel(lease_id=integer.lease_id, lease_token=integer.lease_token)
        await pool.cancel(lease_id=string.lease_id, lease_token=string.lease_token)

        with pytest.raises(RolloutPoolError) as invalid:
            await pool.acquire(
                uid="framework-run",
                session_id=True,
                environment_seed=17,
            )
        assert invalid.value.code == "session_id_invalid"

    asyncio.run(scenario())


def test_failed_start_releases_identity_and_capacity(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    calls = 0

    def fail_once(**metadata: Any) -> FakeLease:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("start failed")
        return FakeLease.start(**metadata)

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=fail_once,
        )
        with pytest.raises(RolloutPoolError) as failed:
            await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        assert failed.value.code == "rollout_start_failed"
        assert pool.active_count == 0
        acquired = await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        await pool.cancel(lease_id=acquired.lease_id, lease_token=acquired.lease_token)

    asyncio.run(scenario())


def test_pool_rejects_untrusted_task_image_without_consuming_lease(tmp_path: Path) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path)
        acquired = await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        with pytest.raises(RolloutPoolError) as denied:
            await pool.exec(
                lease_id=acquired.lease_id,
                lease_token=acquired.lease_token,
                task_image="task:not-allowed",
                command=("true",),
            )
        assert denied.value.code == "task_image_not_allowed"
        assert pool.active_count == 1
        await pool.cancel(lease_id=acquired.lease_id, lease_token=acquired.lease_token)

    asyncio.run(scenario())


def test_shutdown_cleans_all_active_leases_and_rejects_new_work(tmp_path: Path) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path)
        await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        await pool.acquire(uid="uid", session_id="1", environment_seed=0)
        await pool.shutdown()
        assert pool.active_count == 0
        assert all(lease.cancelled for lease in FakeLease.instances)
        with pytest.raises(RolloutPoolError) as closing:
            await pool.acquire(uid="uid", session_id="2", environment_seed=0)
        assert closing.value.code == "pool_shutting_down"

    asyncio.run(scenario())


def test_cancellation_during_start_waits_then_cleans_reservation(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()
    created: list[FakeLease] = []

    def slow_start(**metadata: Any) -> FakeLease:
        entered.set()
        assert release.wait(timeout=5)
        lease = FakeLease(**metadata)
        created.append(lease)
        return lease

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=slow_start,
        )
        acquisition = asyncio.create_task(
            pool.acquire(uid="uid", session_id="0", environment_seed=0)
        )
        assert await asyncio.to_thread(entered.wait, 2)
        acquisition.cancel()
        await asyncio.sleep(0)
        assert not acquisition.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await acquisition
        assert len(created) == 1
        assert created[0].cancelled is True
        assert pool.active_count == 0

    asyncio.run(scenario())


def test_cancellation_during_start_reports_cleanup_failure(tmp_path: Path) -> None:
    entered = threading.Event()
    release = threading.Event()

    class CleanupFailingLease(FakeLease):
        def cancel(self) -> None:
            raise DockerRolloutError("cleanup failed")

    def slow_start(**metadata: Any) -> CleanupFailingLease:
        entered.set()
        assert release.wait(timeout=5)
        return CleanupFailingLease(**metadata)

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=slow_start,
        )
        acquisition = asyncio.create_task(
            pool.acquire(uid="uid", session_id="0", environment_seed=0)
        )
        assert await asyncio.to_thread(entered.wait, 2)
        acquisition.cancel()
        release.set()
        with pytest.raises(RolloutPoolError) as failed:
            await acquisition
        assert failed.value.code == "rollout_start_cleanup_failed"
        assert pool.active_count == 0

    asyncio.run(scenario())


def test_cancellation_during_exec_waits_for_docker_call_before_unlocking(
    tmp_path: Path,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    class SlowExecLease(FakeLease):
        def exec(
            self,
            *,
            task_image: str,
            consumer_command: tuple[str, ...],
            capture_output: bool = True,
        ) -> DockerCommandResult:
            entered.set()
            assert release.wait(timeout=5)
            return super().exec(
                task_image=task_image,
                consumer_command=consumer_command,
                capture_output=capture_output,
            )

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=SlowExecLease.start,
        )
        acquired = await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        execution = asyncio.create_task(
            pool.exec(
                lease_id=acquired.lease_id,
                lease_token=acquired.lease_token,
                task_image="task:allowed",
                command=("slow",),
            )
        )
        assert await asyncio.to_thread(entered.wait, 2)
        execution.cancel()
        await asyncio.sleep(0)
        assert not execution.done()
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await execution
        lease = FakeLease.instances[-1]
        assert lease.commands == [("slow",)]
        assert lease.consumer_exit_codes == (31,)
        await pool.cancel(
            lease_id=acquired.lease_id,
            lease_token=acquired.lease_token,
        )
        assert lease.cancelled is True

    asyncio.run(scenario())


def test_overlapping_exec_requests_are_strictly_serialized(tmp_path: Path) -> None:
    first_entered = threading.Event()
    release_first = threading.Event()
    created: list[SerialExecLease] = []

    class SerialExecLease(FakeLease):
        def exec(
            self,
            *,
            task_image: str,
            consumer_command: tuple[str, ...],
            capture_output: bool = True,
        ) -> DockerCommandResult:
            if not self.commands:
                first_entered.set()
                assert release_first.wait(timeout=5)
            return super().exec(
                task_image=task_image,
                consumer_command=consumer_command,
                capture_output=capture_output,
            )

    def start(**metadata: Any) -> SerialExecLease:
        lease = SerialExecLease(**metadata)
        created.append(lease)
        return lease

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=start,
        )
        acquired = await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        first = asyncio.create_task(
            pool.exec(
                lease_id=acquired.lease_id,
                lease_token=acquired.lease_token,
                task_image="task:allowed",
                command=("first",),
            )
        )
        assert await asyncio.to_thread(first_entered.wait, 2)
        second_started = asyncio.Event()

        async def run_second():
            second_started.set()
            return await pool.exec(
                lease_id=acquired.lease_id,
                lease_token=acquired.lease_token,
                task_image="task:allowed",
                command=("second",),
            )

        second = asyncio.create_task(run_second())
        await second_started.wait()
        await asyncio.sleep(0)
        assert created[0].commands == []
        release_first.set()
        first_result, second_result = await asyncio.gather(first, second)
        assert first_result.execution_index == 0
        assert second_result.execution_index == 1
        assert created[0].commands == [("first",), ("second",)]
        await pool.cancel(
            lease_id=acquired.lease_id,
            lease_token=acquired.lease_token,
        )

    asyncio.run(scenario())


def test_finalize_failure_cancels_still_active_lease(tmp_path: Path) -> None:
    class FailingFinalizeLease(FakeLease):
        def finalize(self, *, output_dir: Path) -> DockerRolloutResult:
            raise DockerRolloutError("artifact path exists")

    async def scenario() -> None:
        pool = RolloutPool(
            provider_set_path=_provider_set(tmp_path),
            runtime_image="runtime:image",
            allowed_task_images=("task:allowed",),
            capacity=1,
            artifacts_root=tmp_path / "artifacts",
            lease_factory=FailingFinalizeLease.start,
        )
        acquired = await pool.acquire(uid="uid", session_id="0", environment_seed=0)
        with pytest.raises(RolloutPoolError) as failed:
            await pool.finalize(
                lease_id=acquired.lease_id,
                lease_token=acquired.lease_token,
            )
        assert failed.value.code == "rollout_finalize_failed"
        lease = FakeLease.instances[-1]
        assert lease.cancelled is True
        assert pool.active_count == 0

    asyncio.run(scenario())


def test_socket_and_token_are_mode_0600_and_removed_on_close() -> None:
    socket_path = Path("/tmp") / f"datalox-test-{uuid.uuid4().hex}.sock"
    endpoint = prepare_rollout_pool_endpoint(socket_path)
    try:
        assert stat.S_IMODE(endpoint.socket_path.stat().st_mode) == 0o600
        assert stat.S_IMODE(endpoint.token_path.stat().st_mode) == 0o600
        assert endpoint.token_path.read_text().strip() == endpoint.token
    finally:
        endpoint.close()
    assert not endpoint.socket_path.exists()
    assert not endpoint.token_path.exists()


def test_server_cancellation_waits_for_pool_shutdown_and_removes_endpoint(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import uvicorn

    socket_path = Path("/tmp") / f"datalox-cancel-{uuid.uuid4().hex}.sock"

    class FakePool:
        def __init__(self) -> None:
            self.shutdown_complete = False

        async def shutdown(self) -> None:
            await asyncio.sleep(0)
            self.shutdown_complete = True

    class FakeServer:
        def __init__(self, _: object) -> None:
            pass

        async def serve(self, *, sockets: list[object]) -> None:
            assert len(sockets) == 1
            raise asyncio.CancelledError

    monkeypatch.setattr(uvicorn, "Config", lambda *args, **kwargs: object())
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    pool = FakePool()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(serve_rollout_pool(pool=pool, socket_path=socket_path))  # type: ignore[arg-type]
    assert pool.shutdown_complete is True
    assert not socket_path.exists()
    assert not Path(f"{socket_path}.token").exists()


def test_socket_and_client_token_symlinks_are_rejected(tmp_path: Path) -> None:
    socket_target = tmp_path / "socket-target"
    socket_link = tmp_path / "pool.sock"
    socket_link.symlink_to(socket_target)
    with pytest.raises(RolloutPoolError) as socket_error:
        prepare_rollout_pool_endpoint(socket_link)
    assert socket_error.value.code == "pool_socket_symlink_forbidden"
    assert not socket_target.exists()

    token_target = tmp_path / "token-target"
    token_target.write_text("server-secret\n")
    token_target.chmod(0o600)
    token_link = tmp_path / "client.sock.token"
    token_link.symlink_to(token_target)
    with pytest.raises(RolloutPoolError) as token_error:
        RolloutPoolClient(socket_path=tmp_path / "client.sock", token_path=token_link)
    assert token_error.value.code == "pool_token_symlink_forbidden"


def test_client_does_not_abandon_long_running_lifecycle_reads(tmp_path: Path) -> None:
    token_file = tmp_path / "pool.sock.token"
    token_file.write_text("server-secret\n")
    token_file.chmod(0o600)
    client = RolloutPoolClient(socket_path=tmp_path / "pool.sock")
    try:
        assert client._client.timeout.connect == 5.0
        assert client._client.timeout.read is None
        assert client._client.timeout.write == 5.0
        assert client._client.timeout.pool == 5.0
    finally:
        asyncio.run(client.aclose())


def test_client_reports_node_local_transport_failure_with_stable_code(tmp_path: Path) -> None:
    async def scenario() -> None:
        token_file = tmp_path / "pool.sock.token"
        token_file.write_text("server-secret\n")
        token_file.chmod(0o600)
        async with RolloutPoolClient(socket_path=tmp_path / "pool.sock") as client:
            with pytest.raises(RolloutPoolError) as failed:
                await client.acquire(uid="uid", session_id="0", environment_seed=0)
            assert failed.value.code == "pool_transport_failed"
            assert failed.value.status_code == 502

    asyncio.run(scenario())


def test_authenticated_app_rejects_unknown_fields_and_validates_messages(tmp_path: Path) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path)
        app = create_rollout_pool_app(pool=pool, server_token="server-secret")
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://pool"
        ) as unauthenticated:
            denied = await unauthenticated.post("/v1/leases/acquire", json={})
            assert denied.status_code == 401
            assert denied.json()["error"]["code"] == "pool_auth_invalid"
        async with httpx.AsyncClient(
            transport=transport,
            base_url="http://pool",
            headers={"Authorization": "Bearer server-secret"},
        ) as client:
            invalid = await client.post(
                "/v1/leases/acquire",
                json={
                    "schema_version": POOL_ACQUIRE_REQUEST,
                    "uid": "uid",
                    "session_id": "0",
                    "environment_seed": 0,
                    "task": "forbidden",
                },
            )
            assert invalid.status_code == 400
            assert invalid.json()["error"]["code"] == "message_fields_invalid"

            acquired = await client.post(
                "/v1/leases/acquire",
                json={
                    "schema_version": POOL_ACQUIRE_REQUEST,
                    "uid": "uid",
                    "session_id": "0",
                    "environment_seed": 0,
                },
            )
            assert acquired.status_code == 200
            schema = json.loads((ROOT / "schemas/rollout-pool-api-v1.schema.json").read_text())
            jsonschema.Draft202012Validator.check_schema(schema)
            jsonschema.Draft202012Validator(schema).validate(acquired.json())
            body = acquired.json()
            cancelled = await client.post(
                f"/v1/leases/{body['lease_id']}/cancel",
                json={
                    "schema_version": "datalox_rollout_pool_cancel_request_v1",
                    "lease_token": body["lease_token"],
                },
            )
            assert cancelled.status_code == 200
            jsonschema.Draft202012Validator(schema).validate(cancelled.json())

    asyncio.run(scenario())


def test_client_context_finalizes_zero_tool_success_and_cancels_exception(
    tmp_path: Path,
) -> None:
    async def scenario() -> None:
        pool = _pool(tmp_path)
        token_file = tmp_path / "pool.sock.token"
        token_file.write_text("server-secret\n")
        token_file.chmod(0o600)
        app = create_rollout_pool_app(pool=pool, server_token="server-secret")
        client = RolloutPoolClient(socket_path=tmp_path / "pool.sock")
        await client._client.aclose()
        client._client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app),
            base_url="http://pool",
            headers={"Authorization": "Bearer server-secret"},
        )
        async with client:
            async with client.lease(uid="no-tool", session_id="0", environment_seed=8) as lease:
                zero_tool_lease = lease
            assert zero_tool_lease.state == "finalized"
            assert zero_tool_lease.final_result is not None
            assert zero_tool_lease.final_result.consumer_exit_codes == ()
            assert FakeLease.instances[0].finalized is True

            with pytest.raises(RuntimeError, match="agent failed"):
                async with client.lease(uid="failed", session_id="1", environment_seed=8):
                    raise RuntimeError("agent failed")
            assert FakeLease.instances[1].cancelled is True

    asyncio.run(scenario())
