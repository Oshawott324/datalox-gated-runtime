"""Strict loading for an ordered set of task-free provider runtime bundles."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntimeError,
    load_provider_admission,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.registry import (
    FilesystemProviderReleaseRegistry,
    parse_provider_release_reference,
)
from datalox_gated_runtime.provider_runtime.release import (
    OCI_MANIFEST_MEDIA_TYPE,
    PROVIDER_RELEASE_ARTIFACT_TYPE,
    PROVIDER_RELEASE_CONFIG_MEDIA_TYPE,
    PROVIDER_RELEASE_SCHEMA_VERSION,
    LoadedProviderRelease,
    ProviderReleaseProfile,
)

ROLLOUT_PROVIDER_SET_SCHEMA_VERSION = "datalox_rollout_provider_set_v1"
ROLLOUT_PROVIDER_SET_V2_SCHEMA_VERSION = "datalox_rollout_provider_set_v2"
MATERIALIZED_ROLLOUT_PROVIDER_SET_SCHEMA_VERSION = "datalox_materialized_rollout_provider_set_v2"
ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES = 1024 * 1024
_PROVIDER_RUNTIME_MANIFEST = "provider-runtime.json"
_MANIFEST_FIELDS = frozenset({"schema_version", "providers"})
_PROVIDER_FIELDS = frozenset({"provider_id", "bundle_path", "provider_runtime_sha256"})
_V2_MANIFEST_FIELDS = frozenset({"schema_version", "providers"})
_V2_PROVIDER_FIELDS = frozenset(
    {
        "provider_id",
        "release_reference",
        "release_manifest_sha256",
        "profile_id",
        "profile_layer_sha256",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "operation_contract_sha256",
        "authorities",
    }
)
_MATERIALIZED_V1_MANIFEST = "rollout-provider-set-v1.json"
_MATERIALIZED_CONTROLLER_MAP = "controller-provider-releases.json"
_MATERIALIZED_SOURCE_V2_MANIFEST = "source-rollout-provider-set-v2.json"
_MATERIALIZED_RELEASE_METADATA_ROOT = "release-metadata"
_MATERIALIZED_CONTROLLER_FIELDS = frozenset(
    {
        "schema_version",
        "source_manifest_path",
        "source_manifest_sha256",
        "provider_set_v1_path",
        "providers",
    }
)
_MATERIALIZED_PROVIDER_FIELDS = _V2_PROVIDER_FIELDS | {
    "provider_set_v1_index",
    "bundle_path",
    "admission_path",
    "release_manifest_path",
    "release_config_path",
    "release_config_sha256",
}


@dataclass
class RolloutProviderSetError(ValueError):
    """A stable, structured rollout provider-set validation failure."""

    code: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:
        return self.message


@dataclass(frozen=True)
class LoadedRolloutProvider:
    """One validated provider dependency with a resolved bundle directory."""

    provider_id: str
    bundle_dir: Path
    provider_runtime_sha256: str
    authorities: tuple[str, ...]


@dataclass(frozen=True)
class LoadedRolloutProviderSet:
    """An immutable, ordered provider dependency set."""

    manifest_path: Path
    providers: tuple[LoadedRolloutProvider, ...]


@dataclass(frozen=True)
class ProviderReleaseSelection:
    """The only caller-authored inputs for one immutable provider selection."""

    release_reference: str
    profile_id: str


@dataclass(frozen=True)
class LoadedRolloutProviderV2:
    """Registry-verified immutable metadata for one selected release profile."""

    provider_id: str
    release_reference: str
    release_manifest_sha256: str
    profile_id: str
    profile_layer_sha256: str
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_contract_sha256: str
    authorities: tuple[str, ...]


@dataclass(frozen=True)
class LoadedRolloutProviderSetV2:
    """An ordered provider set whose content is re-resolved from a trusted registry."""

    manifest_path: Path
    manifest_sha256: str
    manifest_bytes: bytes = field(repr=False, compare=False)
    providers: tuple[LoadedRolloutProviderV2, ...]


@dataclass(frozen=True)
class MaterializedRolloutProviderSetV2:
    """A safe local projection for the existing gateway and its controller."""

    root: Path
    provider_set_v1_path: Path
    controller_mapping_path: Path
    provider_set_v1: LoadedRolloutProviderSet
    providers: tuple[LoadedRolloutProviderV2, ...]


@dataclass(frozen=True)
class AdmittedRolloutProviderBinding:
    """One materialized runtime bound to its exact provider admission."""

    provider: LoadedRolloutProviderV2
    bundle_dir: Path
    admission_path: Path
    release_manifest_path: Path
    release_config_path: Path
    release_config_sha256: str
    release_config: dict[str, Any] = field(repr=False, compare=False)


@dataclass(frozen=True)
class LoadedMaterializedRolloutProviderSetV2:
    """A validated offline projection of one registry-backed provider set."""

    root: Path
    source_manifest_path: Path
    source_manifest_sha256: str
    provider_set_v1_path: Path
    provider_set_v1: LoadedRolloutProviderSet
    controller_mapping_path: Path
    bindings: tuple[AdmittedRolloutProviderBinding, ...]


def write_rollout_provider_set(
    *, bundle_dirs: tuple[Path, ...], output_path: Path
) -> LoadedRolloutProviderSet:
    """Write an ordered provider-set manifest beside its provider bundles."""

    if not bundle_dirs:
        raise RolloutProviderSetError(
            "rollout_provider_set_providers_invalid",
            "At least one provider runtime bundle is required.",
        )
    if output_path.exists() or output_path.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_output_exists",
            "Rollout provider-set output path already exists.",
            {"path": str(output_path)},
        )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_parent = output_path.parent.resolve(strict=True)
    entries: list[dict[str, str]] = []
    for bundle_dir in bundle_dirs:
        if bundle_dir.is_symlink():
            raise RolloutProviderSetError(
                "rollout_provider_set_symlink_forbidden",
                "Provider bundle paths must not be symbolic links.",
                {"path": str(bundle_dir)},
            )
        try:
            bundle = load_provider_runtime_bundle(bundle_dir)
        except ProviderRuntimeError as exc:
            raise RolloutProviderSetError(
                "rollout_provider_set_bundle_invalid",
                f"Provider runtime bundle is invalid: {exc}",
                {"path": str(bundle_dir), "provider_runtime_error": exc.code},
            ) from exc
        try:
            relative = bundle.root.relative_to(output_parent).as_posix()
        except ValueError as exc:
            raise RolloutProviderSetError(
                "rollout_provider_set_path_escape",
                "Provider bundles must be below the manifest directory.",
                {"path": str(bundle.root), "manifest_directory": str(output_parent)},
            ) from exc
        if relative in {"", "."}:
            raise RolloutProviderSetError(
                "rollout_provider_set_path_invalid",
                "The provider-set manifest must not be written inside a provider bundle root.",
            )
        entries.append(
            {
                "provider_id": bundle.manifest.provider_id,
                "bundle_path": relative,
                "provider_runtime_sha256": _sha256_file(
                    bundle.root / _PROVIDER_RUNTIME_MANIFEST,
                    provider_id=bundle.manifest.provider_id,
                ),
            }
        )

    payload = {
        "schema_version": ROLLOUT_PROVIDER_SET_SCHEMA_VERSION,
        "providers": entries,
    }
    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{output_path.name}.", suffix=".tmp", dir=output_parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
        load_rollout_provider_set(temporary_path)
        os.replace(temporary_path, output_path)
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return load_rollout_provider_set(output_path)


def load_rollout_provider_set(manifest_path: Path) -> LoadedRolloutProviderSet:
    """Load provider dependencies relative to one strict task-free manifest."""

    manifest_file = _resolve_manifest(manifest_path)
    raw = _load_json_object(manifest_file)
    if set(raw) != _MANIFEST_FIELDS:
        raise RolloutProviderSetError(
            "rollout_provider_set_manifest_invalid",
            "Rollout provider-set fields do not match the v1 contract.",
            {
                "missing": sorted(_MANIFEST_FIELDS - set(raw)),
                "unknown": sorted(set(raw) - _MANIFEST_FIELDS),
            },
        )
    if raw["schema_version"] != ROLLOUT_PROVIDER_SET_SCHEMA_VERSION:
        raise RolloutProviderSetError(
            "rollout_provider_set_schema_unsupported",
            "Unsupported rollout provider-set schema.",
        )
    raw_providers = raw["providers"]
    if not isinstance(raw_providers, list) or not raw_providers:
        raise RolloutProviderSetError(
            "rollout_provider_set_providers_invalid",
            "providers must be a non-empty ordered list.",
        )

    providers: list[LoadedRolloutProvider] = []
    provider_ids: set[str] = set()
    authority_owners: dict[str, str] = {}
    for index, raw_provider in enumerate(raw_providers):
        provider = _load_provider(
            raw_provider,
            index=index,
            manifest_dir=manifest_file.parent,
        )
        if provider.provider_id in provider_ids:
            raise RolloutProviderSetError(
                "rollout_provider_set_provider_duplicate",
                f"Provider id {provider.provider_id!r} is declared more than once.",
                {"provider_id": provider.provider_id, "index": index},
            )
        provider_ids.add(provider.provider_id)
        for authority in provider.authorities:
            owner = authority_owners.get(authority)
            if owner is not None:
                raise RolloutProviderSetError(
                    "rollout_provider_set_authority_duplicate",
                    f"Authority {authority!r} is owned by more than one provider bundle.",
                    {
                        "authority": authority,
                        "first_provider_id": owner,
                        "second_provider_id": provider.provider_id,
                    },
                )
            authority_owners[authority] = provider.provider_id
        providers.append(provider)

    return LoadedRolloutProviderSet(
        manifest_path=manifest_file,
        providers=tuple(providers),
    )


def _load_provider(
    raw: Any,
    *,
    index: int,
    manifest_dir: Path,
) -> LoadedRolloutProvider:
    if not isinstance(raw, dict) or set(raw) != _PROVIDER_FIELDS:
        fields = set(raw) if isinstance(raw, dict) else set()
        raise RolloutProviderSetError(
            "rollout_provider_set_provider_invalid",
            f"Provider entry {index} does not match the v1 contract.",
            {
                "index": index,
                "missing": sorted(_PROVIDER_FIELDS - fields),
                "unknown": sorted(fields - _PROVIDER_FIELDS),
            },
        )
    provider_id = _provider_id(raw["provider_id"], index=index)
    bundle_path = _relative_bundle_path(raw["bundle_path"], index=index)
    expected_digest = _sha256_value(raw["provider_runtime_sha256"], index=index)
    bundle_dir = _resolve_bundle_dir(
        manifest_dir,
        bundle_path,
        provider_id=provider_id,
    )
    provider_manifest = bundle_dir / _PROVIDER_RUNTIME_MANIFEST
    if provider_manifest.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_symlink_forbidden",
            "Provider runtime manifests must not be symbolic links.",
            {"provider_id": provider_id, "path": str(provider_manifest)},
        )
    actual_digest = _sha256_file(provider_manifest, provider_id=provider_id)
    if actual_digest != expected_digest:
        raise RolloutProviderSetError(
            "rollout_provider_set_digest_mismatch",
            f"provider-runtime.json digest does not match for {provider_id!r}.",
            {
                "provider_id": provider_id,
                "expected": expected_digest,
                "actual": actual_digest,
            },
        )
    try:
        bundle = load_provider_runtime_bundle(bundle_dir)
    except ProviderRuntimeError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_bundle_invalid",
            f"Provider runtime bundle {provider_id!r} is invalid: {exc}",
            {"provider_id": provider_id, "provider_runtime_error": exc.code},
        ) from exc
    if bundle.manifest.provider_id != provider_id:
        raise RolloutProviderSetError(
            "rollout_provider_set_provider_id_mismatch",
            "Provider entry id does not match its provider runtime bundle.",
            {
                "declared": provider_id,
                "bundle": bundle.manifest.provider_id,
            },
        )
    return LoadedRolloutProvider(
        provider_id=provider_id,
        bundle_dir=bundle.root,
        provider_runtime_sha256=actual_digest,
        authorities=bundle.manifest.authorities,
    )


def _resolve_manifest(path: Path) -> Path:
    if path.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_symlink_forbidden",
            "The rollout provider-set manifest must not be a symbolic link.",
            {"path": str(path)},
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_manifest_unreadable",
            f"Could not resolve rollout provider-set manifest: {exc}.",
            {"path": str(path)},
        ) from exc
    if not resolved.is_file():
        raise RolloutProviderSetError(
            "rollout_provider_set_manifest_unreadable",
            "Rollout provider-set manifest must be a file.",
            {"path": str(resolved)},
        )
    return resolved


def _resolve_bundle_dir(
    manifest_dir: Path,
    relative: str,
    *,
    provider_id: str,
) -> Path:
    candidate = manifest_dir
    for part in PurePosixPath(relative).parts:
        candidate = candidate / part
        if candidate.is_symlink():
            raise RolloutProviderSetError(
                "rollout_provider_set_symlink_forbidden",
                "Provider bundle paths must not traverse symbolic links.",
                {"provider_id": provider_id, "path": str(candidate)},
            )
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_bundle_unreadable",
            f"Could not resolve provider bundle {provider_id!r}: {exc}.",
            {"provider_id": provider_id, "path": str(candidate)},
        ) from exc
    if not resolved.is_relative_to(manifest_dir):
        raise RolloutProviderSetError(
            "rollout_provider_set_path_escape",
            "Provider bundle path escapes the rollout manifest directory.",
            {"provider_id": provider_id, "path": str(resolved)},
        )
    if not resolved.is_dir():
        raise RolloutProviderSetError(
            "rollout_provider_set_bundle_unreadable",
            "Provider bundle path must resolve to a directory.",
            {"provider_id": provider_id, "path": str(resolved)},
        )
    return resolved


def _relative_bundle_path(value: Any, *, index: int) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RolloutProviderSetError(
            "rollout_provider_set_path_invalid",
            f"Provider entry {index} has an invalid bundle_path.",
        )
    path = PurePosixPath(value)
    if (
        path.is_absolute()
        or path.as_posix() != value
        or ".." in path.parts
        or (len(value) >= 2 and value[0].isalpha() and value[1] == ":")
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_path_invalid",
            f"Provider entry {index} has an invalid bundle_path.",
        )
    return value


def _provider_id(value: Any, *, index: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or not _is_ascii_alphanumeric(value[0])
        or any(not (_is_ascii_alphanumeric(character) or character in "_-") for character in value)
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_provider_invalid",
            f"Provider entry {index} has an invalid provider_id.",
        )
    return value


def _is_ascii_alphanumeric(value: str) -> bool:
    return "a" <= value <= "z" or "A" <= value <= "Z" or "0" <= value <= "9"


def _sha256_value(value: Any, *, index: int) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_digest_invalid",
            f"Provider entry {index} has an invalid provider_runtime_sha256.",
        )
    return value


def _load_json_object(path: Path) -> dict[str, Any]:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_manifest_invalid",
            f"Could not load rollout provider-set manifest: {exc}.",
            {"path": str(path)},
        ) from exc
    if not isinstance(value, dict):
        raise RolloutProviderSetError(
            "rollout_provider_set_manifest_invalid",
            "Rollout provider-set manifest must contain an object.",
        )
    return value


def _sha256_file(path: Path, *, provider_id: str) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_bundle_unreadable",
            f"Could not read provider-runtime.json for {provider_id!r}: {exc}.",
            {"provider_id": provider_id, "path": str(path)},
        ) from exc
    return f"sha256:{digest.hexdigest()}"


def write_rollout_provider_set_v2(
    *,
    selections: tuple[ProviderReleaseSelection, ...],
    registry: FilesystemProviderReleaseRegistry | Path,
    output_path: Path,
) -> LoadedRolloutProviderSetV2:
    """Author an ordered provider set from immutable registry references and profiles."""

    if not selections:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_providers_invalid",
            "At least one provider release selection is required.",
        )
    destination, output_parent = _canonical_v2_output_path(output_path)
    if destination.exists() or destination.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_output_exists",
            "Rollout provider-set v2 output path already exists.",
            {"path": str(destination)},
        )
    loaded_registry = _trusted_registry(registry)
    providers = tuple(
        _resolve_v2_selection(loaded_registry, selection, index=index)
        for index, selection in enumerate(selections)
    )
    _validate_v2_uniqueness(providers)
    payload = {
        "schema_version": ROLLOUT_PROVIDER_SET_V2_SCHEMA_VERSION,
        "providers": [_v2_provider_payload(provider) for provider in providers],
    }

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=f".{destination.name}.", suffix=".tmp", dir=output_parent
    )
    temporary_path = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        load_rollout_provider_set_v2(temporary_path, registry=loaded_registry)
        temporary_path.chmod(0o444)
        _fsync_regular_file(temporary_path)
        try:
            os.link(temporary_path, destination)
        except FileExistsError as exc:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_output_exists",
                "Rollout provider-set v2 output path already exists.",
                {"path": str(destination)},
            ) from exc
        _fsync_directory(output_parent)
        temporary_path.unlink()
    except BaseException:
        temporary_path.unlink(missing_ok=True)
        raise
    return load_rollout_provider_set_v2(destination, registry=loaded_registry)


def load_rollout_provider_set_v2(
    manifest_path: Path,
    *,
    registry: FilesystemProviderReleaseRegistry | Path,
) -> LoadedRolloutProviderSetV2:
    """Strictly load a v2 set and re-resolve every field from trusted controller state."""

    loaded_registry = _trusted_registry(registry)
    manifest_file = _resolve_v2_manifest(manifest_path)
    raw, manifest_sha256, manifest_bytes = _load_v2_json_object(manifest_file)
    if set(raw) != _V2_MANIFEST_FIELDS:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_manifest_invalid",
            "Rollout provider-set fields do not match the v2 contract.",
            {
                "missing": sorted(_V2_MANIFEST_FIELDS - set(raw)),
                "unknown": sorted(set(raw) - _V2_MANIFEST_FIELDS),
            },
        )
    if raw["schema_version"] != ROLLOUT_PROVIDER_SET_V2_SCHEMA_VERSION:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_schema_unsupported",
            "Unsupported rollout provider-set v2 schema.",
        )
    raw_providers = raw["providers"]
    if not isinstance(raw_providers, list) or not raw_providers:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_providers_invalid",
            "providers must be a non-empty ordered list.",
        )

    providers: list[LoadedRolloutProviderV2] = []
    for index, raw_provider in enumerate(raw_providers):
        if not isinstance(raw_provider, dict) or set(raw_provider) != _V2_PROVIDER_FIELDS:
            fields = set(raw_provider) if isinstance(raw_provider, dict) else set()
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_provider_invalid",
                f"Provider entry {index} does not match the v2 contract.",
                {
                    "index": index,
                    "missing": sorted(_V2_PROVIDER_FIELDS - fields),
                    "unknown": sorted(fields - _V2_PROVIDER_FIELDS),
                },
            )
        reference = raw_provider["release_reference"]
        profile_id = raw_provider["profile_id"]
        if not isinstance(reference, str) or not isinstance(profile_id, str):
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_provider_invalid",
                f"Provider entry {index} has an invalid release selection.",
                {"index": index},
            )
        expected = _resolve_v2_selection(
            loaded_registry,
            ProviderReleaseSelection(reference, profile_id),
            index=index,
        )
        expected_payload = _v2_provider_payload(expected)
        if raw_provider != expected_payload:
            mismatched = sorted(
                field
                for field in _V2_PROVIDER_FIELDS
                if raw_provider.get(field) != expected_payload[field]
            )
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_binding_mismatch",
                f"Provider entry {index} does not match its immutable registry release.",
                {"index": index, "fields": mismatched},
            )
        providers.append(expected)
    immutable = tuple(providers)
    _validate_v2_uniqueness(immutable)
    return LoadedRolloutProviderSetV2(
        manifest_path=manifest_file,
        manifest_sha256=manifest_sha256,
        manifest_bytes=manifest_bytes,
        providers=immutable,
    )


def materialize_rollout_provider_set_v2(
    *,
    provider_set: Path | LoadedRolloutProviderSetV2,
    registry: FilesystemProviderReleaseRegistry | Path,
    output_dir: Path,
) -> MaterializedRolloutProviderSetV2:
    """Atomically materialize a v2 set into the current v1 gateway projection."""

    loaded_registry = _trusted_registry(registry)
    if isinstance(provider_set, LoadedRolloutProviderSetV2):
        loaded = provider_set
        _revalidate_loaded_v2_set(loaded, registry=loaded_registry)
    else:
        loaded = load_rollout_provider_set_v2(provider_set, registry=loaded_registry)

    destination, parent = _canonical_v2_output_path(output_dir)
    if destination.exists() or destination.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialize_output_exists",
            "Rollout provider-set materialization output already exists.",
            {"path": str(destination)},
        )

    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.", dir=parent))
    try:
        materialized_bundles: list[Path] = []
        controller_entries: list[dict[str, Any]] = []
        for index, provider in enumerate(loaded.providers):
            profile_root = temporary / "providers" / f"{index:04d}-{provider.provider_id}"
            try:
                profile = loaded_registry.materialize(
                    reference=provider.release_reference,
                    profile_id=provider.profile_id,
                    output_dir=profile_root,
                )
            except ProviderRuntimeError as exc:
                raise RolloutProviderSetError(
                    "rollout_provider_set_v2_materialization_invalid",
                    f"Could not materialize provider {provider.provider_id!r}: {exc}",
                    {
                        "provider_id": provider.provider_id,
                        "provider_runtime_error": exc.code,
                    },
                ) from exc
            materialized_bundles.append(profile.bundle_dir)
            release_metadata_parent = temporary / _MATERIALIZED_RELEASE_METADATA_ROOT
            release_metadata_parent.mkdir(mode=0o700, exist_ok=True)
            release_metadata_root = release_metadata_parent / f"{index:04d}"
            release_metadata_root.mkdir(mode=0o700)
            release_manifest_path = release_metadata_root / "provider-release-manifest.json"
            release_config_path = release_metadata_root / "provider-release-config.json"
            release_manifest_bytes = canonical_json_bytes(profile.release.manifest)
            release_config_bytes = canonical_json_bytes(profile.release.config)
            _exclusive_write_file(release_manifest_path, release_manifest_bytes, mode=0o444)
            _exclusive_write_file(release_config_path, release_config_bytes, mode=0o444)
            controller_entries.append(
                {
                    **_v2_provider_payload(provider),
                    "provider_set_v1_index": index,
                    "bundle_path": profile.bundle_dir.relative_to(temporary).as_posix(),
                    "admission_path": profile.admission_path.relative_to(temporary).as_posix(),
                    "release_manifest_path": release_manifest_path.relative_to(
                        temporary
                    ).as_posix(),
                    "release_config_path": release_config_path.relative_to(temporary).as_posix(),
                    "release_config_sha256": f"sha256:{hashlib.sha256(release_config_bytes).hexdigest()}",
                }
            )

        v1_path = temporary / _MATERIALIZED_V1_MANIFEST
        write_rollout_provider_set(
            bundle_dirs=tuple(materialized_bundles),
            output_path=v1_path,
        )
        source_manifest_path = temporary / _MATERIALIZED_SOURCE_V2_MANIFEST
        _exclusive_write_file(source_manifest_path, loaded.manifest_bytes, mode=0o444)
        controller_mapping = {
            "schema_version": MATERIALIZED_ROLLOUT_PROVIDER_SET_SCHEMA_VERSION,
            "source_manifest_path": _MATERIALIZED_SOURCE_V2_MANIFEST,
            "source_manifest_sha256": loaded.manifest_sha256,
            "provider_set_v1_path": _MATERIALIZED_V1_MANIFEST,
            "providers": controller_entries,
        }
        mapping_path = temporary / _MATERIALIZED_CONTROLLER_MAP
        with mapping_path.open("xb") as handle:
            handle.write(
                (json.dumps(controller_mapping, indent=2, sort_keys=True) + "\n").encode("utf-8")
            )
            handle.flush()
            os.fsync(handle.fileno())
        mapping_path.chmod(0o600)
        _validate_materialized_v2_tree(temporary)
        load_rollout_provider_set(v1_path)
        _publish_materialized_v2_directory(staged=temporary, destination=destination)
    finally:
        shutil.rmtree(temporary, ignore_errors=True)

    validated = load_materialized_rollout_provider_set_v2(destination)
    return MaterializedRolloutProviderSetV2(
        root=validated.root,
        provider_set_v1_path=validated.provider_set_v1_path,
        controller_mapping_path=validated.controller_mapping_path,
        provider_set_v1=validated.provider_set_v1,
        providers=loaded.providers,
    )


def load_materialized_rollout_provider_set_v2(
    root: Path,
) -> LoadedMaterializedRolloutProviderSetV2:
    """Load exact admitted bindings from a complete materialized v2 root."""

    materialized_root = _resolve_materialized_v2_root(root)
    _validate_materialized_v2_tree(materialized_root)
    controller_path = materialized_root / _MATERIALIZED_CONTROLLER_MAP
    raw, _, _ = _load_bounded_json_object(
        controller_path,
        invalid_code="rollout_provider_set_v2_materialized_invalid",
        size_code="rollout_provider_set_v2_materialized_size_limit_exceeded",
        description="Materialized provider-set controller map",
    )
    if set(raw) != _MATERIALIZED_CONTROLLER_FIELDS:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_invalid",
            "Materialized provider-set controller fields do not match the v2 contract.",
            {
                "missing": sorted(_MATERIALIZED_CONTROLLER_FIELDS - set(raw)),
                "unknown": sorted(set(raw) - _MATERIALIZED_CONTROLLER_FIELDS),
            },
        )
    if raw["schema_version"] != MATERIALIZED_ROLLOUT_PROVIDER_SET_SCHEMA_VERSION:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_schema_unsupported",
            "Unsupported materialized rollout provider-set schema.",
        )
    if raw["source_manifest_path"] != _MATERIALIZED_SOURCE_V2_MANIFEST:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_invalid",
            "Materialized provider-set source manifest path is invalid.",
        )
    if raw["provider_set_v1_path"] != _MATERIALIZED_V1_MANIFEST:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_invalid",
            "Materialized provider-set v1 path is invalid.",
        )
    source_digest = _v2_digest(
        raw["source_manifest_sha256"], field="source_manifest_sha256", index=None
    )
    source_path = _resolve_materialized_relative_file(
        materialized_root,
        raw["source_manifest_path"],
        field="source_manifest_path",
    )
    source_raw, actual_source_digest, _ = _load_v2_json_object(source_path)
    if actual_source_digest != source_digest:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_digest_mismatch",
            "Materialized provider-set source manifest digest does not match.",
            {"expected": source_digest, "actual": actual_source_digest},
        )
    source_providers = _validate_v2_raw_contract(source_raw)

    v1_path = _resolve_materialized_relative_file(
        materialized_root,
        raw["provider_set_v1_path"],
        field="provider_set_v1_path",
    )
    v1 = load_rollout_provider_set(v1_path)
    raw_providers = raw["providers"]
    if not isinstance(raw_providers, list) or len(raw_providers) != len(v1.providers):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_invalid",
            "Materialized provider bindings must exactly match the v1 provider count.",
        )
    if len(source_providers) != len(v1.providers):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_invalid",
            "Materialized source and v1 provider counts differ.",
        )

    bindings: list[AdmittedRolloutProviderBinding] = []
    for index, (raw_provider, source_provider, v1_provider) in enumerate(
        zip(raw_providers, source_providers, v1.providers, strict=True)
    ):
        if not isinstance(raw_provider, dict) or set(raw_provider) != _MATERIALIZED_PROVIDER_FIELDS:
            fields = set(raw_provider) if isinstance(raw_provider, dict) else set()
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialized_provider_invalid",
                f"Materialized provider entry {index} does not match the v2 contract.",
                {
                    "index": index,
                    "missing": sorted(_MATERIALIZED_PROVIDER_FIELDS - fields),
                    "unknown": sorted(fields - _MATERIALIZED_PROVIDER_FIELDS),
                },
            )
        metadata = {field: raw_provider[field] for field in _V2_PROVIDER_FIELDS}
        if metadata != _v2_provider_payload(source_provider):
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialized_binding_mismatch",
                f"Materialized provider entry {index} differs from its source v2 manifest.",
                {"index": index},
            )
        if raw_provider["provider_set_v1_index"] != index:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialized_order_invalid",
                "Materialized provider index does not match provider order.",
                {"index": index},
            )
        expected_bundle_path = v1_provider.bundle_dir.relative_to(materialized_root).as_posix()
        if raw_provider["bundle_path"] != expected_bundle_path:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialized_path_mismatch",
                "Materialized provider bundle path differs from the exact v1 binding.",
                {"index": index},
            )
        bundle_path = _resolve_materialized_relative_directory(
            materialized_root,
            raw_provider["bundle_path"],
            field="bundle_path",
        )
        admission_path = _resolve_materialized_relative_file(
            materialized_root,
            raw_provider["admission_path"],
            field="admission_path",
        )
        release_manifest_path = _resolve_materialized_relative_file(
            materialized_root,
            raw_provider["release_manifest_path"],
            field="release_manifest_path",
        )
        release_config_path = _resolve_materialized_relative_file(
            materialized_root,
            raw_provider["release_config_path"],
            field="release_config_path",
        )
        release_config_sha256 = _v2_digest(
            raw_provider["release_config_sha256"],
            field="release_config_sha256",
            index=index,
        )
        release_manifest, actual_release_manifest_sha256, release_manifest_bytes = (
            _load_bounded_json_object(
                release_manifest_path,
                invalid_code="rollout_provider_set_v2_release_manifest_invalid",
                size_code="rollout_provider_set_v2_materialized_size_limit_exceeded",
                description="Materialized provider release manifest",
            )
        )
        release_config, actual_release_config_sha256, release_config_bytes = (
            _load_bounded_json_object(
                release_config_path,
                invalid_code="rollout_provider_set_v2_release_config_invalid",
                size_code="rollout_provider_set_v2_materialized_size_limit_exceeded",
                description="Materialized provider release config",
            )
        )
        _validate_materialized_release_metadata(
            provider=source_provider,
            release_manifest=release_manifest,
            release_manifest_bytes=release_manifest_bytes,
            actual_release_manifest_sha256=actual_release_manifest_sha256,
            release_config=release_config,
            release_config_bytes=release_config_bytes,
            actual_release_config_sha256=actual_release_config_sha256,
            declared_release_config_sha256=release_config_sha256,
        )
        admission_digest = _sha256_regular_file(admission_path)
        admission = load_provider_admission(admission_path)
        operation_contract_sha256 = canonical_json_sha256(
            sorted(admission["operations"], key=lambda operation: operation["operation_id"])
        )
        mismatches: list[str] = []
        if source_provider.provider_id != v1_provider.provider_id:
            mismatches.append("provider_id")
        if source_provider.authorities != v1_provider.authorities:
            mismatches.append("authorities")
        if source_provider.provider_runtime_sha256 != v1_provider.provider_runtime_sha256:
            mismatches.append("provider_runtime_sha256")
        if admission_digest != source_provider.provider_admission_sha256:
            mismatches.append("provider_admission_sha256")
        if admission["provider_id"] != source_provider.provider_id:
            mismatches.append("admission.provider_id")
        if admission["provider_runtime_sha256"] != source_provider.provider_runtime_sha256:
            mismatches.append("admission.provider_runtime_sha256")
        if operation_contract_sha256 != source_provider.operation_contract_sha256:
            mismatches.append("operation_contract_sha256")
        bundle = load_provider_runtime_bundle(bundle_path)
        if admission["bundle_version"] != bundle.manifest.bundle_version:
            mismatches.append("admission.bundle_version")
        if mismatches:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialized_binding_mismatch",
                f"Materialized provider entry {index} fails admitted binding checks.",
                {"index": index, "fields": sorted(mismatches)},
            )
        bindings.append(
            AdmittedRolloutProviderBinding(
                provider=source_provider,
                bundle_dir=bundle_path,
                admission_path=admission_path,
                release_manifest_path=release_manifest_path,
                release_config_path=release_config_path,
                release_config_sha256=release_config_sha256,
                release_config=release_config,
            )
        )
    return LoadedMaterializedRolloutProviderSetV2(
        root=materialized_root,
        source_manifest_path=source_path,
        source_manifest_sha256=source_digest,
        provider_set_v1_path=v1_path,
        provider_set_v1=v1,
        controller_mapping_path=controller_path,
        bindings=tuple(bindings),
    )


def _trusted_registry(
    registry: FilesystemProviderReleaseRegistry | Path,
) -> FilesystemProviderReleaseRegistry:
    if isinstance(registry, FilesystemProviderReleaseRegistry):
        root = registry.root
    elif isinstance(registry, Path):
        root = registry
    else:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_registry_required",
            "A trusted provider release registry object or path is required.",
        )
    try:
        return FilesystemProviderReleaseRegistry.load(root)
    except ProviderRuntimeError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_registry_invalid",
            f"Provider release registry is invalid: {exc}",
            {"provider_runtime_error": exc.code, "path": str(root)},
        ) from exc


def _resolve_v2_selection(
    registry: FilesystemProviderReleaseRegistry,
    selection: ProviderReleaseSelection,
    *,
    index: int,
) -> LoadedRolloutProviderV2:
    if not isinstance(selection, ProviderReleaseSelection):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_selection_invalid",
            f"Provider selection {index} must contain only a release reference and profile id.",
            {"index": index},
        )
    if not isinstance(selection.release_reference, str) or not isinstance(
        selection.profile_id, str
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_selection_invalid",
            f"Provider selection {index} is invalid.",
            {"index": index},
        )
    try:
        release = registry.resolve(selection.release_reference)
    except ProviderRuntimeError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_invalid",
            f"Could not resolve provider release {selection.release_reference!r}: {exc}",
            {
                "index": index,
                "release_reference": selection.release_reference,
                "provider_runtime_error": exc.code,
            },
        ) from exc
    profile = next(
        (item for item in release.profiles if item.profile_id == selection.profile_id), None
    )
    if profile is None:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_profile_unknown",
            f"Provider release has no profile {selection.profile_id!r}.",
            {
                "index": index,
                "release_reference": selection.release_reference,
                "profile_id": selection.profile_id,
            },
        )
    return _loaded_v2_provider(
        release=release,
        profile=profile,
        release_reference=selection.release_reference,
    )


def _loaded_v2_provider(
    *,
    release: LoadedProviderRelease,
    profile: ProviderReleaseProfile,
    release_reference: str,
) -> LoadedRolloutProviderV2:
    return LoadedRolloutProviderV2(
        provider_id=release.provider_id,
        release_reference=release_reference,
        release_manifest_sha256=release.manifest_descriptor["digest"],
        profile_id=profile.profile_id,
        profile_layer_sha256=profile.layer["digest"],
        provider_runtime_sha256=profile.provider_runtime_sha256,
        provider_admission_sha256=profile.provider_admission_sha256,
        operation_contract_sha256=release.config["operation_contract_sha256"],
        authorities=tuple(release.config["authorities"]),
    )


def _v2_provider_payload(provider: LoadedRolloutProviderV2) -> dict[str, Any]:
    return {
        "provider_id": provider.provider_id,
        "release_reference": provider.release_reference,
        "release_manifest_sha256": provider.release_manifest_sha256,
        "profile_id": provider.profile_id,
        "profile_layer_sha256": provider.profile_layer_sha256,
        "provider_runtime_sha256": provider.provider_runtime_sha256,
        "provider_admission_sha256": provider.provider_admission_sha256,
        "operation_contract_sha256": provider.operation_contract_sha256,
        "authorities": list(provider.authorities),
    }


def _validate_v2_uniqueness(providers: tuple[LoadedRolloutProviderV2, ...]) -> None:
    provider_ids: set[str] = set()
    authority_owners: dict[str, str] = {}
    for index, provider in enumerate(providers):
        if provider.provider_id in provider_ids:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_provider_duplicate",
                f"Provider id {provider.provider_id!r} is selected more than once.",
                {"provider_id": provider.provider_id, "index": index},
            )
        provider_ids.add(provider.provider_id)
        for authority in provider.authorities:
            owner = authority_owners.get(authority)
            if owner is not None:
                raise RolloutProviderSetError(
                    "rollout_provider_set_v2_authority_duplicate",
                    f"Authority {authority!r} is owned by more than one provider release.",
                    {
                        "authority": authority,
                        "first_provider_id": owner,
                        "second_provider_id": provider.provider_id,
                    },
                )
            authority_owners[authority] = provider.provider_id


def _resolve_v2_manifest(path: Path) -> Path:
    if path.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_symlink_forbidden",
            "The rollout provider-set v2 manifest must not be a symbolic link.",
            {"path": str(path)},
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_manifest_unreadable",
            f"Could not resolve rollout provider-set v2 manifest: {exc}.",
            {"path": str(path)},
        ) from exc
    if not resolved.is_file():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_manifest_unreadable",
            "Rollout provider-set v2 manifest must be a file.",
            {"path": str(resolved)},
        )
    return resolved


def _load_v2_json_object(path: Path) -> tuple[dict[str, Any], str, bytes]:
    return _load_bounded_json_object(
        path,
        invalid_code="rollout_provider_set_v2_manifest_invalid",
        size_code="rollout_provider_set_v2_size_limit_exceeded",
        description="Rollout provider-set v2 manifest",
    )


def _load_bounded_json_object(
    path: Path,
    *,
    invalid_code: str,
    size_code: str,
    description: str,
) -> tuple[dict[str, Any], str, bytes]:
    try:
        flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise RolloutProviderSetError(
                    invalid_code,
                    f"{description} must be a regular file.",
                    {"path": str(path)},
                )
            if metadata.st_size > ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES:
                raise RolloutProviderSetError(
                    size_code,
                    f"{description} exceeds its size limit.",
                    {
                        "path": str(path),
                        "actual_size": metadata.st_size,
                        "max_bytes": ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES,
                    },
                )
            payload = handle.read(ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES + 1)
        if len(payload) > ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES:
            raise RolloutProviderSetError(
                size_code,
                f"{description} exceeds its size limit.",
                {"path": str(path), "max_bytes": ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES},
            )
        value = json.loads(payload.decode("utf-8"))
    except RolloutProviderSetError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise RolloutProviderSetError(
            invalid_code,
            f"Could not load {description.lower()}: {exc}.",
            {"path": str(path)},
        ) from exc
    if not isinstance(value, dict):
        raise RolloutProviderSetError(
            invalid_code,
            f"{description} must contain an object.",
        )
    return value, f"sha256:{hashlib.sha256(payload).hexdigest()}", payload


def _validate_v2_raw_contract(raw: dict[str, Any]) -> tuple[LoadedRolloutProviderV2, ...]:
    if set(raw) != _V2_MANIFEST_FIELDS:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_manifest_invalid",
            "Rollout provider-set fields do not match the v2 contract.",
        )
    if raw["schema_version"] != ROLLOUT_PROVIDER_SET_V2_SCHEMA_VERSION:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_schema_unsupported",
            "Unsupported rollout provider-set v2 schema.",
        )
    raw_providers = raw["providers"]
    if not isinstance(raw_providers, list) or not raw_providers:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_providers_invalid",
            "providers must be a non-empty ordered list.",
        )
    providers = tuple(
        _v2_provider_from_raw(raw_provider, index=index)
        for index, raw_provider in enumerate(raw_providers)
    )
    _validate_v2_uniqueness(providers)
    return providers


def _v2_provider_from_raw(raw: Any, *, index: int) -> LoadedRolloutProviderV2:
    if not isinstance(raw, dict) or set(raw) != _V2_PROVIDER_FIELDS:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_provider_invalid",
            f"Provider entry {index} does not match the v2 contract.",
        )
    provider_id = _v2_identifier(raw["provider_id"], field="provider_id", index=index)
    reference = raw["release_reference"]
    try:
        reference_provider_id, _ = parse_provider_release_reference(reference)
    except ProviderRuntimeError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_provider_invalid",
            f"Provider entry {index} has an invalid release reference.",
            {"index": index, "provider_runtime_error": exc.code},
        ) from exc
    if reference_provider_id != provider_id:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_provider_invalid",
            f"Provider entry {index} release reference does not match provider_id.",
            {"index": index},
        )
    profile_id = _v2_identifier(raw["profile_id"], field="profile_id", index=index)
    authorities = raw["authorities"]
    if (
        not isinstance(authorities, list)
        or not authorities
        or len(set(authorities)) != len(authorities)
        or any(not isinstance(authority, str) or not authority for authority in authorities)
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_provider_invalid",
            f"Provider entry {index} has invalid authorities.",
            {"index": index},
        )
    return LoadedRolloutProviderV2(
        provider_id=provider_id,
        release_reference=reference,
        release_manifest_sha256=_v2_digest(
            raw["release_manifest_sha256"], field="release_manifest_sha256", index=index
        ),
        profile_id=profile_id,
        profile_layer_sha256=_v2_digest(
            raw["profile_layer_sha256"], field="profile_layer_sha256", index=index
        ),
        provider_runtime_sha256=_v2_digest(
            raw["provider_runtime_sha256"], field="provider_runtime_sha256", index=index
        ),
        provider_admission_sha256=_v2_digest(
            raw["provider_admission_sha256"], field="provider_admission_sha256", index=index
        ),
        operation_contract_sha256=_v2_digest(
            raw["operation_contract_sha256"], field="operation_contract_sha256", index=index
        ),
        authorities=tuple(authorities),
    )


def _v2_identifier(value: Any, *, field: str, index: int) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or not _is_ascii_alphanumeric(value[0])
        or any(not (_is_ascii_alphanumeric(character) or character in "_.-") for character in value)
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_provider_invalid",
            f"Provider entry {index} has an invalid {field}.",
            {"index": index, "field": field},
        )
    return value


def _v2_digest(value: Any, *, field: str, index: int | None) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_digest_invalid",
            f"Invalid {field} digest.",
            {"field": field, **({"index": index} if index is not None else {})},
        )
    return value


def _revalidate_loaded_v2_set(
    loaded: LoadedRolloutProviderSetV2,
    *,
    registry: FilesystemProviderReleaseRegistry,
) -> None:
    actual_manifest_sha256 = f"sha256:{hashlib.sha256(loaded.manifest_bytes).hexdigest()}"
    if actual_manifest_sha256 != loaded.manifest_sha256:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_binding_mismatch",
            "Loaded provider-set bytes do not match their bound manifest digest.",
        )
    try:
        raw = json.loads(loaded.manifest_bytes.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_manifest_invalid",
            f"Loaded provider-set bytes are invalid JSON: {exc}.",
        ) from exc
    if not isinstance(raw, dict) or _validate_v2_raw_contract(raw) != loaded.providers:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_binding_mismatch",
            "Loaded provider-set metadata does not match its bound manifest bytes.",
        )
    resolved = tuple(
        _resolve_v2_selection(
            registry,
            ProviderReleaseSelection(provider.release_reference, provider.profile_id),
            index=index,
        )
        for index, provider in enumerate(loaded.providers)
    )
    if resolved != loaded.providers:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_binding_mismatch",
            "Loaded provider set no longer matches its immutable registry releases.",
        )
    _validate_v2_uniqueness(loaded.providers)


def _canonical_v2_output_path(path: Path) -> tuple[Path, Path]:
    if path.name in {"", ".", ".."}:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_output_invalid",
            "Rollout provider-set output name is invalid.",
            {"path": str(path)},
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_output_invalid",
            f"Could not resolve rollout provider-set output parent: {exc}.",
            {"path": str(path.parent)},
        ) from exc
    if not parent.is_dir():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_output_invalid",
            "Rollout provider-set output parent must be a directory.",
            {"path": str(parent)},
        )
    return parent / path.name, parent


def _resolve_materialized_v2_root(path: Path) -> Path:
    if path.is_symlink():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_symlink_forbidden",
            "Materialized provider-set root must not be a symbolic link.",
            {"path": str(path)},
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_unreadable",
            f"Could not resolve materialized provider-set root: {exc}.",
            {"path": str(path)},
        ) from exc
    if not resolved.is_dir():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_unreadable",
            "Materialized provider-set root must be a directory.",
            {"path": str(resolved)},
        )
    return resolved


def _validate_materialized_release_metadata(
    *,
    provider: LoadedRolloutProviderV2,
    release_manifest: dict[str, Any],
    release_manifest_bytes: bytes,
    actual_release_manifest_sha256: str,
    release_config: dict[str, Any],
    release_config_bytes: bytes,
    actual_release_config_sha256: str,
    declared_release_config_sha256: str,
) -> None:
    if actual_release_manifest_sha256 != provider.release_manifest_sha256:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_manifest_digest_mismatch",
            "Materialized provider release manifest differs from the selected release.",
        )
    if (
        set(release_manifest) != {"schemaVersion", "mediaType", "artifactType", "config", "layers"}
        or release_manifest.get("schemaVersion") != 2
        or release_manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or release_manifest.get("artifactType") != PROVIDER_RELEASE_ARTIFACT_TYPE
        or not isinstance(release_manifest.get("config"), dict)
        or not isinstance(release_manifest.get("layers"), list)
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_manifest_invalid",
            "Materialized provider release manifest does not match Provider Release v1.",
        )
    config_descriptor = release_manifest["config"]
    if (
        set(config_descriptor) != {"mediaType", "digest", "size"}
        or config_descriptor.get("mediaType") != PROVIDER_RELEASE_CONFIG_MEDIA_TYPE
        or config_descriptor.get("digest") != actual_release_config_sha256
        or config_descriptor.get("size") != len(release_config_bytes)
        or declared_release_config_sha256 != actual_release_config_sha256
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_config_digest_mismatch",
            "Materialized provider release config is not bound to its OCI manifest.",
        )
    if len(release_manifest_bytes) <= 0:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_manifest_invalid",
            "Materialized provider release manifest is empty.",
        )
    try:
        reference_provider_id, reference_release_version = parse_provider_release_reference(
            provider.release_reference
        )
    except ProviderRuntimeError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_config_invalid",
            "Selected provider release reference is invalid.",
            {"provider_runtime_error": exc.code},
        ) from exc
    required_config_fields = {
        "schema_version",
        "provider_id",
        "release_version",
        "authorities",
        "operation_contract_sha256",
        "operations",
        "profiles",
    }
    if (
        not required_config_fields.issubset(release_config)
        or release_config.get("schema_version") != PROVIDER_RELEASE_SCHEMA_VERSION
        or release_config.get("provider_id") != reference_provider_id
        or release_config.get("provider_id") != provider.provider_id
        or release_config.get("release_version") != reference_release_version
        or release_config.get("authorities") != list(provider.authorities)
        or release_config.get("operation_contract_sha256") != provider.operation_contract_sha256
        or not isinstance(release_config.get("operations"), list)
        or canonical_json_sha256(release_config["operations"]) != provider.operation_contract_sha256
        or not isinstance(release_config.get("profiles"), list)
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_config_invalid",
            "Materialized provider release config does not match the selected release metadata.",
        )
    profiles = [
        profile
        for profile in release_config["profiles"]
        if isinstance(profile, dict) and profile.get("profile_id") == provider.profile_id
    ]
    if len(profiles) != 1:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_config_invalid",
            "Materialized provider release config has no unique selected profile.",
        )
    profile = profiles[0]
    layer = profile.get("layer")
    manifest_layers = release_manifest["layers"]
    if (
        not isinstance(layer, dict)
        or layer.get("digest") != provider.profile_layer_sha256
        or layer not in manifest_layers
        or profile.get("provider_runtime_sha256") != provider.provider_runtime_sha256
        or profile.get("provider_admission_sha256") != provider.provider_admission_sha256
    ):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_release_config_invalid",
            "Materialized provider release profile does not match the selected profile binding.",
        )


def _resolve_materialized_relative_file(root: Path, value: Any, *, field: str) -> Path:
    return _resolve_materialized_relative_path(root, value, field=field, kind="file")


def _resolve_materialized_relative_directory(root: Path, value: Any, *, field: str) -> Path:
    return _resolve_materialized_relative_path(root, value, field=field, kind="directory")


def _resolve_materialized_relative_path(
    root: Path,
    value: Any,
    *,
    field: str,
    kind: str,
) -> Path:
    if not isinstance(value, str) or not value or "\\" in value:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_invalid",
            f"Materialized {field} must be a relative POSIX path.",
        )
    relative = PurePosixPath(value)
    if relative.is_absolute() or relative.as_posix() != value or ".." in relative.parts:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_invalid",
            f"Materialized {field} must be a contained relative POSIX path.",
        )
    candidate = root
    for part in relative.parts:
        candidate /= part
        if candidate.is_symlink():
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_symlink_forbidden",
                f"Materialized {field} must not traverse symbolic links.",
                {"path": str(candidate)},
            )
    try:
        resolved = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_invalid",
            f"Could not resolve materialized {field}: {exc}.",
            {"path": str(candidate)},
        ) from exc
    if not resolved.is_relative_to(root):
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_escape",
            f"Materialized {field} escapes its root.",
            {"path": str(resolved)},
        )
    valid_kind = resolved.is_file() if kind == "file" else resolved.is_dir()
    if not valid_kind:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_invalid",
            f"Materialized {field} must resolve to a {kind}.",
            {"path": str(resolved)},
        )
    return resolved


def _sha256_regular_file(path: Path) -> str:
    if path.is_symlink() or not path.is_file():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_path_invalid",
            "Expected a regular admission file.",
            {"path": str(path)},
        )
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_materialized_unreadable",
            f"Could not read materialized admission: {exc}.",
            {"path": str(path)},
        ) from exc
    return f"sha256:{digest.hexdigest()}"


def _exclusive_write_file(path: Path, payload: bytes, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as handle:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        path.chmod(mode)
        _fsync_regular_file(path)
    finally:
        os.close(descriptor)


def _publish_materialized_v2_directory(*, staged: Path, destination: Path) -> None:
    marker = staged / _MATERIALIZED_CONTROLLER_MAP
    if marker.is_symlink() or not marker.is_file():
        raise RolloutProviderSetError(
            "rollout_provider_set_v2_publication_invalid",
            "Materialized provider-set validity marker is missing from staging.",
        )
    reserved = False
    marker_published = False
    try:
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError as exc:
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_materialize_output_exists",
                "Rollout provider-set materialization output already exists.",
                {"path": str(destination)},
            ) from exc
        reserved = True
        destination.chmod(0o700)
        for child in sorted(staged.iterdir(), key=lambda path: path.name):
            if child.name == _MATERIALIZED_CONTROLLER_MAP:
                continue
            os.rename(child, destination / child.name)
        _fsync_directory(destination)
        os.rename(marker, destination / _MATERIALIZED_CONTROLLER_MAP)
        marker_published = True
        _fsync_directory(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if reserved and not marker_published:
            shutil.rmtree(destination, ignore_errors=True)
            _fsync_directory(destination.parent)
        raise


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_regular_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise RolloutProviderSetError(
                "rollout_provider_set_v2_publication_invalid",
                "Rollout provider-set publication source must be a regular file.",
                {"path": str(path)},
            )
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _validate_materialized_v2_tree(root: Path) -> None:
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories + files:
            path = current_path / name
            if path.is_symlink():
                raise RolloutProviderSetError(
                    "rollout_provider_set_v2_symlink_forbidden",
                    "Materialized provider sets must not contain symbolic links.",
                    {"path": str(path)},
                )
            if not (path.is_dir() or path.is_file()):
                raise RolloutProviderSetError(
                    "rollout_provider_set_v2_special_file_forbidden",
                    "Materialized provider sets may contain only directories and regular files.",
                    {"path": str(path)},
                )
