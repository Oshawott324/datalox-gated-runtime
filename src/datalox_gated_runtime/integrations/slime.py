"""slime custom-generate integration for isolated provider-state execution.

The module deliberately has no dependency on :mod:`slime`.  It wraps a
consumer-owned ``--custom-generate-function-path`` callable by structural use
of slime's current ``Sample`` contract.  The consumer still owns generation,
training fields, and reward calculation.
"""

from __future__ import annotations

import asyncio
import functools
import hashlib
import json
import os
from collections.abc import Awaitable, Callable
from contextvars import ContextVar
from dataclasses import dataclass
from pathlib import Path
from typing import ParamSpec, TypeVar

from datalox_gated_runtime.rollout.pool import (
    FinalizedRolloutLease,
    RemoteRolloutLease,
    RolloutExecResult,
    RolloutPoolClient,
)

SIDECAR_SCHEMA = "datalox_slime_evidence_sidecar_v1"
SIDECAR_FIELDS = {
    "schema_version",
    "identity_key",
    "uid",
    "session_id",
    "environment_seed",
    "lease_id",
    "initial_provider_fingerprint",
    "artifact_directory",
    "consumer_exit_codes",
}
SLIME_SAMPLE_STATUSES = {"pending", "completed", "truncated", "aborted", "failed"}

P = ParamSpec("P")
R = TypeVar("R")


@dataclass
class SlimeRolloutContractError(ValueError):
    """Stable failure for invalid slime integration inputs or evidence."""

    code: str
    message: str

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class SlimeRolloutIdentity:
    """Exact rollout identity supplied by slime and consumer metadata."""

    uid: str
    session_id: str
    environment_seed: int

    @property
    def key(self) -> str:
        value = json.dumps(
            {"session_id": self.session_id, "uid": self.uid},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hashlib.sha256(value).hexdigest()


@dataclass(frozen=True)
class SlimeEvidenceSidecar:
    """Provider-state evidence produced after one custom generation call."""

    identity: SlimeRolloutIdentity
    identity_key: str
    lease_id: str
    initial_provider_fingerprint: str
    artifact_directory: Path
    consumer_exit_codes: tuple[int, ...]


@dataclass(frozen=True)
class SlimeProviderExecution:
    """Context-local execution handle with an operator-fixed task image."""

    _lease: RemoteRolloutLease
    _task_image: str

    async def exec(self, command: tuple[str, ...]) -> RolloutExecResult:
        """Execute argv inside the current sample's isolated provider lease."""

        _validate_command(command)
        return await self._lease.exec(task_image=self._task_image, command=command)


_CURRENT_EXECUTION: ContextVar[SlimeProviderExecution | None] = ContextVar(
    "datalox_slime_provider_execution", default=None
)


def current_slime_provider_execution() -> SlimeProviderExecution:
    """Return the provider execution handle inherited by child asyncio tasks."""

    execution = _CURRENT_EXECUTION.get()
    if execution is None:
        raise SlimeRolloutContractError(
            "slime_rollout_context_missing",
            "provider execution is outside an active Datalox slime rollout",
        )
    return execution


def extract_slime_rollout_identity(sample: object) -> SlimeRolloutIdentity:
    """Read slime's session id and explicit Datalox metadata without derivation."""

    metadata = getattr(sample, "metadata", None)
    if not isinstance(metadata, dict) or not all(isinstance(key, str) for key in metadata):
        raise SlimeRolloutContractError(
            "slime_metadata_invalid", "sample.metadata must be a dictionary with string keys"
        )
    datalox = metadata.get("datalox")
    if not isinstance(datalox, dict) or not all(isinstance(key, str) for key in datalox):
        raise SlimeRolloutContractError(
            "slime_datalox_metadata_invalid",
            "sample.metadata.datalox must be a dictionary with string keys",
        )
    required_fields = {"uid", "environment_seed"}
    allowed_fields = required_fields | {"session_id"}
    if not required_fields.issubset(datalox) or not set(datalox).issubset(allowed_fields):
        missing = sorted(required_fields - set(datalox))
        unknown = sorted(set(datalox) - allowed_fields)
        raise SlimeRolloutContractError(
            "slime_datalox_metadata_invalid",
            f"sample.metadata.datalox fields are invalid; missing={missing!r}, unknown={unknown!r}",
        )

    uid = datalox["uid"]
    if not _is_bounded_string(uid):
        raise SlimeRolloutContractError(
            "slime_uid_invalid",
            "sample.metadata.datalox.uid must be a non-empty trimmed string of at most 256 characters",
        )
    environment_seed = datalox["environment_seed"]
    if not _is_non_negative_int(environment_seed):
        raise SlimeRolloutContractError(
            "slime_environment_seed_invalid",
            "sample.metadata.datalox.environment_seed must be a non-negative integer",
        )
    native_session_id = getattr(sample, "session_id", None)
    metadata_session_id = datalox.get("session_id")
    if native_session_id is None:
        if not _is_bounded_string(metadata_session_id):
            raise SlimeRolloutContractError(
                "slime_session_id_invalid",
                "sample.session_id or sample.metadata.datalox.session_id must supply an explicit session ID",
            )
        session_id = metadata_session_id
    else:
        if not _is_bounded_string(native_session_id):
            raise SlimeRolloutContractError(
                "slime_session_id_invalid",
                "sample.session_id must be a non-empty trimmed string of at most 256 characters",
            )
        session_id = native_session_id
        if metadata_session_id is not None:
            if not _is_bounded_string(metadata_session_id):
                raise SlimeRolloutContractError(
                    "slime_session_id_invalid",
                    "sample.metadata.datalox.session_id must be a bounded string when present",
                )
            if metadata_session_id != native_session_id:
                raise SlimeRolloutContractError(
                    "slime_session_id_mismatch",
                    "sample.session_id and sample.metadata.datalox.session_id must match exactly",
                )

    return SlimeRolloutIdentity(
        uid=uid,
        session_id=session_id,
        environment_seed=environment_seed,
    )


def slime_identity_metadata(sample: object) -> dict[str, dict[str, object]]:
    """Return exact metadata for consumer-owned ``TrajectoryManager`` fan-out."""

    identity = extract_slime_rollout_identity(sample)
    return {
        "datalox": {
            "uid": identity.uid,
            "session_id": identity.session_id,
            "environment_seed": identity.environment_seed,
        }
    }


class SlimeDataloxRuntime:
    """Wrap a user-owned slime custom generator with one provider-state lease."""

    def __init__(
        self,
        *,
        pool_socket_path: str | Path,
        pool_token_path: str | Path,
        task_image: str,
        evidence_sidecars_root: str | Path,
    ) -> None:
        self._pool_socket_path = _absolute_path(pool_socket_path, "pool_socket_path")
        self._pool_token_path = _absolute_path(pool_token_path, "pool_token_path")
        self._task_image = _task_image(task_image)
        self._evidence_sidecars_root = _absolute_path(
            evidence_sidecars_root, "evidence_sidecars_root"
        )

    @classmethod
    def from_slime_args(cls, args: object) -> SlimeDataloxRuntime:
        """Load exact adapter fields installed by slime ``--custom-config-path``."""

        return cls(
            pool_socket_path=_required_argument(args, "datalox_pool_socket_path"),
            pool_token_path=_required_argument(args, "datalox_pool_token_path"),
            task_image=_required_argument(args, "datalox_task_image"),
            evidence_sidecars_root=_required_argument(args, "datalox_evidence_sidecars_root"),
        )

    def custom_generate(self, generate: Callable[P, Awaitable[R]]) -> Callable[P, Awaitable[R]]:
        """Decorate a slime custom generator and return its output unchanged."""

        if not callable(generate):
            raise SlimeRolloutContractError(
                "slime_generate_invalid", "custom generate target must be callable"
            )

        @functools.wraps(generate)
        async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
            if len(args) < 3:
                raise SlimeRolloutContractError(
                    "slime_generate_call_invalid",
                    "slime custom generate must receive args, sample, and sampling_params",
                )
            sample = args[1]
            identity = extract_slime_rollout_identity(sample)
            client = RolloutPoolClient(
                socket_path=self._pool_socket_path,
                token_path=self._pool_token_path,
            )
            lease: RemoteRolloutLease | None = None
            try:
                lease = await _acquire_lease(client, identity)
                execution = SlimeProviderExecution(lease, self._task_image)
                context_token = _CURRENT_EXECUTION.set(execution)
                try:
                    output = await generate(*args, **kwargs)
                finally:
                    _CURRENT_EXECUTION.reset(context_token)

                identity_after_generation = extract_slime_rollout_identity(sample)
                if identity_after_generation != identity:
                    raise SlimeRolloutContractError(
                        "slime_identity_changed",
                        "custom generation changed the original sample's Datalox rollout identity",
                    )
                output_samples, statuses = _validate_generate_output(output)
                if "aborted" in statuses:
                    await _cancel_lease(lease)
                    return output
                for output_sample in output_samples:
                    if extract_slime_rollout_identity(output_sample) != identity:
                        raise SlimeRolloutContractError(
                            "slime_output_identity_mismatch",
                            "every returned Sample must preserve the original Datalox identity",
                        )

                try:
                    finalized = await _finalize_lease(lease)
                except BaseException:
                    if lease.state == "active":
                        await _cancel_lease(lease)
                    raise
                self._write_sidecar(identity, lease, finalized)
                return output
            except BaseException:
                if lease is not None and lease.state == "active":
                    await _cancel_lease(lease)
                raise
            finally:
                await client.aclose()

        return wrapped

    def evidence_for(self, sample: object) -> SlimeEvidenceSidecar:
        """Load finalized provider evidence for a custom reward function."""

        identity = extract_slime_rollout_identity(sample)
        path = self._sidecar_path(identity)
        try:
            value = json.loads(path.read_text(encoding="utf-8"))
        except FileNotFoundError as exc:
            raise SlimeRolloutContractError(
                "slime_evidence_missing",
                f"provider evidence is missing for slime identity {identity.key}",
            ) from exc
        except (OSError, UnicodeError, json.JSONDecodeError) as exc:
            raise SlimeRolloutContractError(
                "slime_evidence_invalid", f"could not read slime evidence sidecar: {exc}"
            ) from exc
        return _parse_sidecar(value, identity)

    def evidence_for_batch(self, samples: list[object]) -> list[SlimeEvidenceSidecar]:
        """Resolve provider evidence for every explicitly identified reward sample."""

        if not isinstance(samples, list) or not samples:
            raise SlimeRolloutContractError(
                "slime_evidence_batch_invalid",
                "batch reward must supply a non-empty list of Samples",
            )
        return [self.evidence_for(sample) for sample in samples]

    def _write_sidecar(
        self,
        identity: SlimeRolloutIdentity,
        lease: RemoteRolloutLease,
        finalized: FinalizedRolloutLease,
    ) -> None:
        output_dir = finalized.output_dir.absolute()
        payload = {
            "schema_version": SIDECAR_SCHEMA,
            "identity_key": identity.key,
            "uid": identity.uid,
            "session_id": identity.session_id,
            "environment_seed": identity.environment_seed,
            "lease_id": lease.lease_id,
            "initial_provider_fingerprint": lease.initial_provider_fingerprint,
            "artifact_directory": str(output_dir),
            "consumer_exit_codes": list(finalized.consumer_exit_codes),
        }
        encoded = (
            json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
        ).encode("utf-8")
        root = self._evidence_sidecars_root
        root.mkdir(parents=True, exist_ok=True)
        if root.is_symlink() or not root.is_dir():
            raise SlimeRolloutContractError(
                "slime_evidence_root_invalid",
                "evidence_sidecars_root must be a real directory, not a symbolic link",
            )
        path = self._sidecar_path(identity)
        try:
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError as exc:
            raise SlimeRolloutContractError(
                "slime_evidence_exists",
                f"provider evidence already exists for slime identity {identity.key}",
            ) from exc
        except OSError as exc:
            raise SlimeRolloutContractError(
                "slime_evidence_write_failed", f"could not create slime evidence sidecar: {exc}"
            ) from exc
        try:
            with os.fdopen(descriptor, "wb") as sidecar:
                descriptor = -1
                sidecar.write(encoded)
                sidecar.flush()
                os.fsync(sidecar.fileno())
        except OSError as exc:
            path.unlink(missing_ok=True)
            raise SlimeRolloutContractError(
                "slime_evidence_write_failed", f"could not write slime evidence sidecar: {exc}"
            ) from exc
        finally:
            if descriptor >= 0:
                os.close(descriptor)

    def _sidecar_path(self, identity: SlimeRolloutIdentity) -> Path:
        return self._evidence_sidecars_root / f"{identity.key}.json"


def datalox_custom_generate(
    generate: Callable[P, Awaitable[R]],
) -> Callable[P, Awaitable[R]]:
    """Use slime's custom config to wrap one user-owned custom generator."""

    if not callable(generate):
        raise SlimeRolloutContractError(
            "slime_generate_invalid", "custom generate target must be callable"
        )

    @functools.wraps(generate)
    async def wrapped(*args: P.args, **kwargs: P.kwargs) -> R:
        if len(args) < 3:
            raise SlimeRolloutContractError(
                "slime_generate_call_invalid",
                "slime custom generate must receive args, sample, and sampling_params",
            )
        runtime = SlimeDataloxRuntime.from_slime_args(args[0])
        bound = runtime.custom_generate(generate)
        return await bound(*args, **kwargs)

    return wrapped


async def _acquire_lease(
    client: RolloutPoolClient, identity: SlimeRolloutIdentity
) -> RemoteRolloutLease:
    lease, cancellation = await _settle_if_cancelled(
        client.acquire(
            uid=identity.uid,
            session_id=identity.session_id,
            environment_seed=identity.environment_seed,
        )
    )
    if cancellation is not None:
        await _cancel_lease(lease)
        raise cancellation
    return lease


async def _finalize_lease(lease: RemoteRolloutLease) -> FinalizedRolloutLease:
    finalized, cancellation = await _settle_if_cancelled(lease.finalize())
    if cancellation is not None:
        raise cancellation
    if not isinstance(finalized, FinalizedRolloutLease):
        raise SlimeRolloutContractError(
            "slime_finalize_invalid", "rollout pool returned an invalid finalized lease"
        )
    return finalized


async def _cancel_lease(lease: RemoteRolloutLease) -> None:
    cleanup = asyncio.create_task(lease.cancel())
    try:
        await asyncio.shield(cleanup)
    except asyncio.CancelledError:
        await cleanup


async def _settle_if_cancelled(awaitable: Awaitable[R]) -> tuple[R, asyncio.CancelledError | None]:
    operation = asyncio.create_task(awaitable)
    cancellation: asyncio.CancelledError | None = None
    while True:
        try:
            result = await asyncio.shield(operation)
            return result, cancellation
        except asyncio.CancelledError as exc:
            cancellation = cancellation or exc
            continue
        except BaseException:
            if cancellation is not None:
                raise cancellation
            raise


def _parse_sidecar(value: object, identity: SlimeRolloutIdentity) -> SlimeEvidenceSidecar:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise SlimeRolloutContractError(
            "slime_evidence_invalid", "slime evidence sidecar must be a JSON object"
        )
    if set(value) != SIDECAR_FIELDS or value.get("schema_version") != SIDECAR_SCHEMA:
        raise SlimeRolloutContractError(
            "slime_evidence_invalid", "slime evidence sidecar fields or schema are invalid"
        )
    if (
        value["identity_key"] != identity.key
        or value["uid"] != identity.uid
        or value["session_id"] != identity.session_id
        or value["environment_seed"] != identity.environment_seed
    ):
        raise SlimeRolloutContractError(
            "slime_evidence_identity_mismatch",
            "slime evidence sidecar does not match the requested sample identity",
        )
    lease_id = value["lease_id"]
    fingerprint = value["initial_provider_fingerprint"]
    artifact_directory = value["artifact_directory"]
    exit_codes = value["consumer_exit_codes"]
    if not _is_bounded_string(lease_id) or not _is_sha256(fingerprint):
        raise SlimeRolloutContractError(
            "slime_evidence_invalid", "slime evidence lease fields are invalid"
        )
    if not isinstance(artifact_directory, str) or not Path(artifact_directory).is_absolute():
        raise SlimeRolloutContractError(
            "slime_evidence_invalid", "slime evidence artifact_directory must be absolute"
        )
    artifact_path = Path(artifact_directory)
    if artifact_path.is_symlink() or not artifact_path.is_dir():
        raise SlimeRolloutContractError(
            "slime_evidence_invalid",
            "slime evidence artifact_directory must be an existing real directory",
        )
    if not isinstance(exit_codes, list) or any(not _is_exit_code(item) for item in exit_codes):
        raise SlimeRolloutContractError(
            "slime_evidence_invalid", "slime evidence consumer_exit_codes are invalid"
        )
    return SlimeEvidenceSidecar(
        identity=identity,
        identity_key=identity.key,
        lease_id=lease_id,
        initial_provider_fingerprint=fingerprint,
        artifact_directory=artifact_path,
        consumer_exit_codes=tuple(exit_codes),
    )


def _validate_generate_output(output: object) -> tuple[list[object], set[str]]:
    if isinstance(output, list):
        if not output:
            raise SlimeRolloutContractError(
                "slime_generate_output_invalid",
                "custom generation must return Sample or a non-empty list[Sample]",
            )
        samples = list(output)
    else:
        samples = [output]

    statuses: set[str] = set()
    for sample in samples:
        if isinstance(sample, list) or not hasattr(sample, "status"):
            raise SlimeRolloutContractError(
                "slime_generate_output_invalid",
                "custom generation must return Sample or a non-empty list[Sample]",
            )
        status = sample.status
        status_value = getattr(status, "value", status)
        if not isinstance(status_value, str) or status_value not in SLIME_SAMPLE_STATUSES:
            raise SlimeRolloutContractError(
                "slime_sample_status_invalid",
                f"returned Sample status must be one of {sorted(SLIME_SAMPLE_STATUSES)!r}",
            )
        statuses.add(status_value)
    return samples, statuses


def _absolute_path(value: object, field: str) -> Path:
    if not isinstance(value, (str, Path)):
        raise SlimeRolloutContractError(
            f"slime_{field}_invalid", f"{field} must be an absolute filesystem path"
        )
    if isinstance(value, str) and (not value or value.strip() != value):
        raise SlimeRolloutContractError(
            f"slime_{field}_invalid", f"{field} must be an absolute filesystem path"
        )
    path = Path(value)
    if not path.is_absolute():
        raise SlimeRolloutContractError(
            f"slime_{field}_invalid", f"{field} must be an absolute filesystem path"
        )
    return path


def _required_argument(args: object, field: str) -> object:
    if not hasattr(args, field):
        raise SlimeRolloutContractError(
            "slime_custom_config_invalid",
            f"--custom-config-path must define {field}",
        )
    return getattr(args, field)


def _task_image(value: object) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or any(character.isspace() for character in value)
    ):
        raise SlimeRolloutContractError(
            "slime_task_image_invalid", "task_image must be a non-empty Docker image reference"
        )
    return value


def _validate_command(command: object) -> None:
    if not isinstance(command, tuple) or not command:
        raise SlimeRolloutContractError(
            "slime_command_invalid", "command must be a non-empty tuple of argv strings"
        )
    if any(not isinstance(item, str) or not item or "\x00" in item for item in command):
        raise SlimeRolloutContractError(
            "slime_command_invalid",
            "every command item must be a non-empty string without NUL bytes",
        )


def _is_bounded_string(value: object) -> bool:
    return (
        isinstance(value, str)
        and bool(value)
        and value.strip() == value
        and len(value) <= 256
        and "\x00" not in value
    )


def _is_non_negative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _is_exit_code(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 255


def _is_sha256(value: object) -> bool:
    if not isinstance(value, str) or not value.startswith("sha256:"):
        return False
    digest = value.removeprefix("sha256:")
    return len(digest) == 64 and all(character in "0123456789abcdef" for character in digest)


__all__ = [
    "SlimeDataloxRuntime",
    "SlimeEvidenceSidecar",
    "SlimeProviderExecution",
    "SlimeRolloutContractError",
    "SlimeRolloutIdentity",
    "current_slime_provider_execution",
    "datalox_custom_generate",
    "extract_slime_rollout_identity",
    "slime_identity_metadata",
]
