"""Immutable filesystem registry for content-addressed provider releases."""

from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.release import (
    PROVIDER_RELEASE_MAX_JSON_BYTES,
    LoadedProviderRelease,
    MaterializedProviderProfile,
    _canonical_output_destination,
    _fsync_directory,
    _identifier,
    _load_json_object,
    _media_type_size_limit,
    _publish_validated_directory,
    _resolve_directory,
    _sha256,
    _stream_size_and_sha256,
    _verified_descriptor_blob_path,
    _write_bytes,
    load_provider_release,
    load_provider_release_from_descriptor,
    materialize_provider_release_profile,
)

PROVIDER_RELEASE_REGISTRY_SCHEMA_VERSION = "datalox_provider_release_registry_v1"
PROVIDER_RELEASE_REGISTRY_TRUST_BOUNDARY = "single_os_user_local_filesystem_v1"

_REGISTRY_MARKER = {
    "schema_version": PROVIDER_RELEASE_REGISTRY_SCHEMA_VERSION,
    "trust_boundary": PROVIDER_RELEASE_REGISTRY_TRUST_BOUNDARY,
}


@dataclass(frozen=True)
class PublishedProviderRelease:
    reference: str
    manifest_digest: str
    release: LoadedProviderRelease


@dataclass(frozen=True)
class FilesystemProviderReleaseRegistry:
    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _validate_registry_root(self.root))

    @classmethod
    def create(cls, root: Path) -> FilesystemProviderReleaseRegistry:
        """Create one fresh registry with an immutable content store."""

        destination, parent = _canonical_output_destination(root)
        if destination.exists() or destination.is_symlink():
            _fail(
                "provider_registry_output_exists",
                "Provider release registry path already exists.",
                path=str(destination),
            )
        scratch = Path(tempfile.mkdtemp(prefix=f".{destination.name}.create-", dir=parent))
        staged = scratch / "registry"
        staged.mkdir(mode=0o700)
        (staged / "blobs").mkdir(mode=0o700)
        (staged / "blobs" / "sha256").mkdir(mode=0o700)
        (staged / "refs").mkdir(mode=0o700)
        _write_bytes(staged / "registry.json", canonical_json_bytes(_REGISTRY_MARKER), mode=0o444)
        try:
            _validate_registry_root(staged)
            _publish_validated_directory(
                staged=staged,
                destination=destination,
                validity_marker="registry.json",
                exists_code="provider_registry_output_exists",
            )
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        return cls(destination)

    @classmethod
    def load(cls, root: Path) -> FilesystemProviderReleaseRegistry:
        """Load a strict registry root without following internal links."""

        return cls(root)

    def publish(self, release: Path | LoadedProviderRelease) -> PublishedProviderRelease:
        """Publish content once and bind one provider@release-version reference forever."""

        registry_root = _validate_registry_root(self.root)
        if isinstance(release, Path):
            loaded = load_provider_release(release)
        else:
            loaded = load_provider_release_from_descriptor(
                root=release.root,
                manifest_descriptor=release.manifest_descriptor,
            )
        manifest = loaded.manifest_descriptor
        descriptors = [manifest, loaded.manifest["config"], *loaded.manifest["layers"]]
        for descriptor in descriptors:
            source = _verified_descriptor_blob_path(loaded.root, descriptor, name="release blob")
            self._publish_blob(registry_root, descriptor, source)

        reference = f"{loaded.provider_id}@{loaded.release_version}"
        ref_parent = self._ensure_reference_parent(registry_root, loaded.provider_id)
        ref_path = self._reference_path(registry_root, loaded.provider_id, loaded.release_version)
        ref_payload = canonical_json_bytes(manifest)
        self._publish_bytes(
            registry_root,
            ref_path,
            ref_payload,
            conflict_code="provider_registry_reference_conflict",
        )
        _fsync_directory(ref_parent)
        _validate_registry_root(registry_root)
        resolved = self.resolve(reference)
        if resolved.manifest_descriptor["digest"] != manifest["digest"]:
            _fail(
                "provider_registry_reference_conflict",
                "Provider release reference already points to different content.",
                reference=reference,
            )
        return PublishedProviderRelease(
            reference=reference,
            manifest_digest=manifest["digest"],
            release=resolved,
        )

    def resolve(self, reference: str) -> LoadedProviderRelease:
        """Resolve an immutable provider@release-version reference by content digest."""

        registry_root = _validate_registry_root(self.root)
        provider_id, release_version = parse_provider_release_reference(reference)
        path = self._reference_path(registry_root, provider_id, release_version)
        if path.is_symlink():
            _fail("provider_registry_symlink_forbidden", "Provider release ref is a symlink.")
        try:
            resolved = path.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            _fail(
                "provider_registry_reference_unknown",
                f"Could not resolve provider release reference: {exc}.",
                reference=reference,
            )
        refs_root = (registry_root / "refs").resolve(strict=True)
        if not resolved.is_relative_to(refs_root) or not resolved.is_file():
            _fail(
                "provider_registry_reference_invalid",
                "Provider release reference leaves the registry ref root.",
                reference=reference,
            )
        descriptor = _load_json_object(
            resolved,
            code="provider_registry_json_invalid",
            max_bytes=PROVIDER_RELEASE_MAX_JSON_BYTES,
        )
        loaded = load_provider_release_from_descriptor(
            root=registry_root, manifest_descriptor=descriptor
        )
        if loaded.provider_id != provider_id or loaded.release_version != release_version:
            _fail(
                "provider_registry_reference_binding_invalid",
                "Provider release ref does not match its release config.",
                reference=reference,
            )
        return loaded

    def materialize(
        self, *, reference: str, profile_id: str, output_dir: Path
    ) -> MaterializedProviderProfile:
        """Resolve and safely materialize one release profile."""

        _validate_registry_root(self.root)
        return materialize_provider_release_profile(
            release=self.resolve(reference), profile_id=profile_id, output_dir=output_dir
        )

    def _publish_blob(
        self,
        registry_root: Path,
        descriptor: dict[str, Any],
        source: Path,
    ) -> None:
        _require_registry_directory(registry_root, registry_root / "blobs")
        blob_root = _require_registry_directory(registry_root, registry_root / "blobs" / "sha256")
        target = blob_root / _sha256(descriptor["digest"], field="digest")[7:]
        self._publish_source(
            registry_root,
            target,
            source,
            expected_size=descriptor["size"],
            expected_digest=descriptor["digest"],
            max_bytes=_media_type_size_limit(descriptor["mediaType"]),
            conflict_code="provider_registry_blob_conflict",
        )

    def _publish_bytes(
        self,
        registry_root: Path,
        target: Path,
        payload: bytes,
        *,
        conflict_code: str,
    ) -> None:
        if len(payload) > PROVIDER_RELEASE_MAX_JSON_BYTES:
            _fail(
                "provider_release_size_limit_exceeded",
                "Registry JSON exceeds the Provider Release v1 size limit.",
            )
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".datalox-registry-object-", dir=registry_root.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o444)
            self._publish_source(
                registry_root,
                target,
                temporary,
                expected_size=len(payload),
                expected_digest=f"sha256:{hashlib.sha256(payload).hexdigest()}",
                max_bytes=PROVIDER_RELEASE_MAX_JSON_BYTES,
                conflict_code=conflict_code,
            )
        finally:
            temporary.unlink(missing_ok=True)

    def _publish_source(
        self,
        registry_root: Path,
        target: Path,
        source: Path,
        *,
        expected_size: int,
        expected_digest: str,
        max_bytes: int,
        conflict_code: str,
    ) -> None:
        parent = _require_registry_directory(registry_root, target.parent)
        if target.exists() or target.is_symlink():
            if target.is_symlink():
                _fail("provider_registry_symlink_forbidden", "Registry object is a symlink.")
            size, digest = _stream_size_and_sha256(target, max_bytes=max_bytes)
            if size != expected_size or digest != expected_digest:
                _fail(
                    conflict_code,
                    "Immutable registry object already contains different bytes.",
                    path=str(target),
                )
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".datalox-registry-copy-", dir=registry_root.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as output, source.open("rb") as input_handle:
                copied, digest = _copy_and_digest(input_handle, output, max_bytes=max_bytes)
                output.flush()
                os.fsync(output.fileno())
            if copied != expected_size or digest != expected_digest:
                _fail(
                    "provider_registry_blob_mismatch",
                    "Registry source does not match its content descriptor.",
                )
            temporary.chmod(0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                size, existing_digest = _stream_size_and_sha256(target, max_bytes=max_bytes)
                if size != expected_size or existing_digest != expected_digest:
                    _fail(
                        conflict_code,
                        "Immutable registry object won a race with different bytes.",
                        path=str(target),
                    )
            _fsync_directory(parent)
        finally:
            temporary.unlink(missing_ok=True)

    def _ensure_reference_parent(self, registry_root: Path, provider_id: str) -> Path:
        provider_id = _identifier(provider_id, field="provider_id")
        refs = _require_registry_directory(registry_root, registry_root / "refs")
        provider = refs / provider_id
        try:
            provider.mkdir(mode=0o700)
            provider.chmod(0o700)
            _fsync_directory(refs)
        except FileExistsError:
            pass
        return _require_registry_directory(registry_root, provider)

    def _reference_path(self, registry_root: Path, provider_id: str, release_version: str) -> Path:
        provider_id = _identifier(provider_id, field="provider_id")
        release_version = _identifier(release_version, field="release_version")
        refs_root = _require_registry_directory(registry_root, registry_root / "refs")
        path = refs_root / provider_id / f"{release_version}.json"
        if path.parent.exists() and path.parent.is_symlink():
            _fail("provider_registry_symlink_forbidden", "Provider ref directory is a symlink.")
        return path


def parse_provider_release_reference(reference: Any) -> tuple[str, str]:
    if not isinstance(reference, str) or reference.count("@") != 1:
        _fail(
            "provider_registry_reference_invalid",
            "Provider release references must use provider@release-version.",
        )
    provider_id, release_version = reference.split("@", 1)
    return (
        _identifier(provider_id, field="provider_id"),
        _identifier(release_version, field="release_version"),
    )


def _validate_registry_root(root: Path) -> Path:
    resolved = _resolve_directory(root, code="provider_registry_unreadable")
    expected_uid = os.getuid()
    for current, directories, files in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        _require_permissions(current_path, expected_mode=0o700, expected_uid=expected_uid)
        for name in directories + files:
            path = current_path / name
            if path.is_symlink():
                _fail(
                    "provider_registry_symlink_forbidden",
                    "Provider registry must not contain symbolic links.",
                    path=str(path),
                )
            if not (path.is_dir() or path.is_file()):
                _fail(
                    "provider_registry_special_file_forbidden",
                    "Provider registry contains a non-regular filesystem entry.",
                    path=str(path),
                )
            _require_permissions(
                path,
                expected_mode=0o700 if path.is_dir() else 0o444,
                expected_uid=expected_uid,
            )
    marker = _load_json_object(
        resolved / "registry.json",
        code="provider_registry_json_invalid",
        max_bytes=PROVIDER_RELEASE_MAX_JSON_BYTES,
    )
    if marker != _REGISTRY_MARKER:
        _fail("provider_registry_schema_unsupported", "Provider registry marker is invalid.")
    if {path.name for path in resolved.iterdir()} != {"registry.json", "refs", "blobs"}:
        _fail("provider_registry_layout_invalid", "Provider registry root entries are invalid.")
    refs = _require_registry_directory(resolved, resolved / "refs")
    blobs = _require_registry_directory(resolved, resolved / "blobs")
    if {path.name for path in blobs.iterdir()} != {"sha256"}:
        _fail("provider_registry_layout_invalid", "Provider registry blob layout is invalid.")
    blob_root = _require_registry_directory(resolved, blobs / "sha256")
    for blob in blob_root.iterdir():
        if (
            not blob.is_file()
            or len(blob.name) != 64
            or any(character not in "0123456789abcdef" for character in blob.name)
        ):
            _fail("provider_registry_layout_invalid", "Provider registry blob name is invalid.")
    for provider in refs.iterdir():
        _identifier(provider.name, field="provider_id")
        if not provider.is_dir():
            _fail("provider_registry_layout_invalid", "Provider ref owner must be a directory.")
        for ref in provider.iterdir():
            if not ref.is_file() or ref.suffix != ".json":
                _fail("provider_registry_layout_invalid", "Provider registry ref name is invalid.")
            _identifier(ref.stem, field="release_version")
    return resolved


def _require_permissions(path: Path, *, expected_mode: int, expected_uid: int) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        _fail("provider_registry_unreadable", f"Could not inspect registry permissions: {exc}.")
    if metadata.st_uid != expected_uid or stat.S_IMODE(metadata.st_mode) != expected_mode:
        _fail(
            "provider_registry_permissions_invalid",
            "Provider registry entries must be owner-controlled and immutable to writers.",
            path=str(path),
            expected_mode=oct(expected_mode),
            actual_mode=oct(stat.S_IMODE(metadata.st_mode)),
        )


def _require_registry_directory(root: Path, path: Path) -> Path:
    if path.is_symlink():
        _fail(
            "provider_registry_symlink_forbidden",
            "Provider registry directory is a symbolic link.",
            path=str(path),
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(
            "provider_registry_layout_invalid",
            f"Could not resolve provider registry directory: {exc}.",
            path=str(path),
        )
    if not resolved.is_relative_to(root) or not resolved.is_dir():
        _fail(
            "provider_registry_path_escape",
            "Provider registry directory leaves the registry root.",
            path=str(resolved),
        )
    _require_permissions(resolved, expected_mode=0o700, expected_uid=os.getuid())
    return resolved


def _copy_and_digest(source: BinaryIO, destination: BinaryIO, *, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    while chunk := source.read(1024 * 1024):
        total += len(chunk)
        if total > max_bytes:
            _fail(
                "provider_release_size_limit_exceeded",
                "Registry source exceeds its Provider Release v1 size limit.",
                actual_size=total,
                max_bytes=max_bytes,
            )
        digest.update(chunk)
        destination.write(chunk)
    return total, f"sha256:{digest.hexdigest()}"


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderRuntimeError(code, message, details)
