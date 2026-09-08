"""Append-only storage for provider-release drift assessments.

The assessment store is intentionally separate from the immutable Provider
Release registry v1.  An assessment binds evidence to one release manifest;
it never changes the release or enables provider access from the runtime.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Mapping

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError

PROVIDER_DRIFT_ASSESSMENT_SCHEMA_VERSION = "datalox_provider_drift_assessment_v1"
PROVIDER_ASSESSMENT_REGISTRY_SCHEMA_VERSION = "datalox_provider_assessment_registry_v1"
PROVIDER_ASSESSMENT_REGISTRY_ENTRY_SCHEMA_VERSION = "datalox_provider_assessment_registry_entry_v1"
PROVIDER_ASSESSMENT_REGISTRY_TRUST_BOUNDARY = "single_os_user_local_filesystem_v1"
PROVIDER_ASSESSMENT_MAX_JSON_BYTES = 8 * 1024 * 1024

_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
_RFC3339_UTC = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?Z$"
)
_ASSESSMENT_FIELDS = frozenset(
    {
        "schema_version",
        "assessment_id",
        "provider_id",
        "program_id",
        "observed_at",
        "baseline_measurement_sha256",
        "candidate_measurement_sha256",
        "release_manifest_sha256",
        "profile_id",
        "source_comparison",
        "replica_comparison",
        "status",
        "freshness_window_days",
        "expires_at",
    }
)
_COMPARISON_FIELDS = frozenset({"status", "report_sha256", "difference_count"})
_ENTRY_FIELDS = frozenset(
    {
        "schema_version",
        "assessment_id",
        "release_manifest_sha256",
        "profile_id",
        "program_id",
        "observed_at",
        "content_sha256",
    }
)
_ASSESSMENT_STATUSES = frozenset(
    {
        "current",
        "provider_drift_detected",
        "replica_mismatch",
        "reacquisition_blocked",
    }
)
_SOURCE_STATUSES = frozenset({"equal", "changed", "incomplete", "not_compared"})
_REPLICA_STATUSES = frozenset({"passed", "failed", "incomplete", "not_run"})
_MARKER = {
    "schema_version": PROVIDER_ASSESSMENT_REGISTRY_SCHEMA_VERSION,
    "trust_boundary": PROVIDER_ASSESSMENT_REGISTRY_TRUST_BOUNDARY,
}


@dataclass(frozen=True)
class PublishedProviderAssessment:
    assessment_id: str
    release_manifest_sha256: str
    profile_id: str
    program_id: str
    observed_at: str
    content_sha256: str
    assessment: dict[str, Any]


@dataclass(frozen=True)
class FilesystemProviderAssessmentRegistry:
    """A standalone, append-only local assessment store.

    Pass an assessment-specific root, conventionally ``<root>/assessments``.
    It must not be placed inside a Provider Release registry v1 because that
    format has a closed immutable top-level layout.
    """

    root: Path

    def __post_init__(self) -> None:
        object.__setattr__(self, "root", _validate_registry_root(self.root))

    @classmethod
    def create(cls, root: Path) -> FilesystemProviderAssessmentRegistry:
        destination, parent = _canonical_destination(root)
        if destination.exists() or destination.is_symlink():
            _fail(
                "provider_assessment_registry_output_exists",
                "Provider assessment registry path already exists.",
                path=str(destination),
            )
        scratch = Path(tempfile.mkdtemp(prefix=f".{destination.name}.create-", dir=parent))
        staged = scratch / "assessments"
        staged.mkdir(mode=0o700)
        (staged / "blobs").mkdir(mode=0o700)
        (staged / "blobs" / "sha256").mkdir(mode=0o700)
        (staged / "by-release").mkdir(mode=0o700)
        _write_exclusive(
            staged / "registry.json",
            canonical_json_bytes(_MARKER),
            mode=0o444,
        )
        try:
            _validate_registry_root(staged)
            reserved = False
            published_marker = False
            try:
                try:
                    destination.mkdir(mode=0o700)
                    reserved = True
                except FileExistsError:
                    _fail(
                        "provider_assessment_registry_output_exists",
                        "Provider assessment registry path already exists.",
                        path=str(destination),
                    )
                destination.chmod(0o700)
                for child in sorted(staged.iterdir(), key=lambda path: path.name):
                    if child.name == "registry.json":
                        continue
                    os.rename(child, destination / child.name)
                _fsync_directory(destination)
                os.rename(staged / "registry.json", destination / "registry.json")
                published_marker = True
                _fsync_directory(destination)
                _fsync_directory(parent)
            finally:
                if reserved and not published_marker:
                    shutil.rmtree(destination, ignore_errors=True)
                    _fsync_directory(parent)
        finally:
            shutil.rmtree(scratch, ignore_errors=True)
        return cls(destination)

    @classmethod
    def load(cls, root: Path) -> FilesystemProviderAssessmentRegistry:
        return cls(root)

    def publish_assessment(
        self, assessment: Mapping[str, Any] | Path
    ) -> PublishedProviderAssessment:
        """Publish one assessment, idempotently for identical canonical bytes."""

        registry_root = _validate_registry_root(self.root)
        value = _assessment_input(assessment)
        payload = canonical_json_bytes(value)
        if len(payload) > PROVIDER_ASSESSMENT_MAX_JSON_BYTES:
            _fail(
                "provider_assessment_size_limit_exceeded",
                "Provider assessment exceeds the v1 JSON size limit.",
            )
        content_sha256 = _sha256_bytes(payload)
        entry = {
            "schema_version": PROVIDER_ASSESSMENT_REGISTRY_ENTRY_SCHEMA_VERSION,
            "assessment_id": value["assessment_id"],
            "release_manifest_sha256": value["release_manifest_sha256"],
            "profile_id": value["profile_id"],
            "program_id": value["program_id"],
            "observed_at": value["observed_at"],
            "content_sha256": content_sha256,
        }
        entry_payload = canonical_json_bytes(entry)
        entry_parent = self._ensure_binding_parent(
            registry_root,
            release_manifest_sha256=value["release_manifest_sha256"],
            profile_id=value["profile_id"],
            program_id=value["program_id"],
        )
        entry_path = entry_parent / f"{value['assessment_id']}.json"

        blob_path = registry_root / "blobs" / "sha256" / content_sha256[7:]
        self._publish_bytes(
            registry_root,
            blob_path,
            payload,
            conflict_code="provider_assessment_registry_blob_conflict",
        )
        # Publish the identity record last. A crash may leave an unreachable
        # content blob, but it can never leave a visible entry with no blob.
        # O_EXCL-style hard linking makes concurrent claims of one id atomic.
        self._publish_bytes(
            registry_root,
            entry_path,
            entry_payload,
            conflict_code="provider_assessment_registry_identity_conflict",
        )
        _fsync_directory(entry_parent)
        _validate_registry_root(registry_root)
        return self.get(
            release_manifest_sha256=value["release_manifest_sha256"],
            profile_id=value["profile_id"],
            program_id=value["program_id"],
            assessment_id=value["assessment_id"],
        )

    def get(
        self,
        *,
        release_manifest_sha256: str,
        profile_id: str,
        program_id: str,
        assessment_id: str,
    ) -> PublishedProviderAssessment:
        registry_root = _validate_registry_root(self.root)
        binding = _binding(
            release_manifest_sha256=release_manifest_sha256,
            profile_id=profile_id,
            program_id=program_id,
        )
        safe_assessment_id = _identifier(assessment_id, field="assessment_id")
        parent = _binding_parent(registry_root, *binding)
        entry_path = parent / f"{safe_assessment_id}.json"
        if entry_path.is_symlink():
            _fail(
                "provider_assessment_registry_symlink_forbidden",
                "Provider assessment registry entry is a symbolic link.",
            )
        if not entry_path.is_file():
            _fail(
                "provider_assessment_registry_entry_unknown",
                "Provider assessment registry entry does not exist.",
                assessment_id=safe_assessment_id,
            )
        return _load_entry(registry_root, entry_path, expected_binding=binding)

    def list_assessments(
        self,
        *,
        release_manifest_sha256: str,
        profile_id: str,
        program_id: str,
    ) -> tuple[PublishedProviderAssessment, ...]:
        """List a binding deterministically by observation time and digest."""

        registry_root = _validate_registry_root(self.root)
        binding = _binding(
            release_manifest_sha256=release_manifest_sha256,
            profile_id=profile_id,
            program_id=program_id,
        )
        parent = _binding_parent(registry_root, *binding, missing_ok=True)
        if parent is None:
            return ()
        values = [
            _load_entry(registry_root, path, expected_binding=binding) for path in parent.iterdir()
        ]
        return tuple(
            sorted(
                values,
                key=lambda item: (_utc_timestamp(item.observed_at), item.content_sha256),
            )
        )

    def latest_assessment(
        self,
        *,
        release_manifest_sha256: str,
        profile_id: str,
        program_id: str,
    ) -> PublishedProviderAssessment | None:
        """Derive latest from validated timestamps and content digests."""

        assessments = self.list_assessments(
            release_manifest_sha256=release_manifest_sha256,
            profile_id=profile_id,
            program_id=program_id,
        )
        return assessments[-1] if assessments else None

    def assessment_status_at(
        self,
        *,
        release_manifest_sha256: str,
        profile_id: str,
        program_id: str,
        as_of: datetime,
    ) -> str | None:
        """Return the latest assessment's status at one trusted UTC instant.

        A latest assessment dated after ``as_of`` is rejected rather than
        silently treated as current or skipped.
        """

        latest = self.latest_assessment(
            release_manifest_sha256=release_manifest_sha256,
            profile_id=profile_id,
            program_id=program_id,
        )
        if latest is None:
            return None
        return assessment_status_at(latest.assessment, as_of=as_of)

    def load_blob(self, content_sha256: str) -> dict[str, Any]:
        registry_root = _validate_registry_root(self.root)
        digest = _sha256(content_sha256, field="content_sha256")
        return _load_assessment_blob(registry_root, digest)

    def _ensure_binding_parent(
        self,
        registry_root: Path,
        *,
        release_manifest_sha256: str,
        profile_id: str,
        program_id: str,
    ) -> Path:
        manifest_hex, safe_profile, safe_program = _binding(
            release_manifest_sha256=release_manifest_sha256,
            profile_id=profile_id,
            program_id=program_id,
        )
        current = _require_directory(registry_root, registry_root / "by-release")
        for component in (manifest_hex, safe_profile, safe_program):
            candidate = current / component
            try:
                candidate.mkdir(mode=0o700)
                candidate.chmod(0o700)
                _fsync_directory(current)
            except FileExistsError:
                pass
            current = _require_directory(registry_root, candidate)
        return current

    def _publish_bytes(
        self,
        registry_root: Path,
        target: Path,
        payload: bytes,
        *,
        conflict_code: str,
    ) -> None:
        parent = _require_directory(registry_root, target.parent)
        if target.exists() or target.is_symlink():
            _verify_existing(target, payload, conflict_code=conflict_code)
            return
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".datalox-assessment-object-", dir=registry_root.parent
        )
        temporary = Path(temporary_name)
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            temporary.chmod(0o444)
            try:
                os.link(temporary, target)
            except FileExistsError:
                _verify_existing(target, payload, conflict_code=conflict_code)
            _fsync_directory(parent)
        finally:
            temporary.unlink(missing_ok=True)


def validate_provider_drift_assessment(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached JSON representation of a v1 assessment."""

    if not isinstance(value, Mapping) or set(value) != _ASSESSMENT_FIELDS:
        _fail(
            "provider_drift_assessment_invalid",
            "Provider drift assessment fields are invalid.",
        )
    try:
        detached = json.loads(canonical_json_bytes(dict(value)).decode("utf-8"))
    except (TypeError, ValueError) as exc:
        _fail(
            "provider_drift_assessment_invalid",
            f"Provider drift assessment must be finite JSON: {exc}.",
        )
    if detached["schema_version"] != PROVIDER_DRIFT_ASSESSMENT_SCHEMA_VERSION:
        _fail(
            "provider_drift_assessment_schema_unsupported",
            "Provider drift assessment schema version is unsupported.",
        )
    for field in ("assessment_id", "provider_id", "program_id", "profile_id"):
        _identifier(detached[field], field=field)
    for field in (
        "baseline_measurement_sha256",
        "candidate_measurement_sha256",
        "release_manifest_sha256",
    ):
        _sha256(detached[field], field=field)
    observed_at = _utc_timestamp(detached["observed_at"])
    expires_at = _utc_timestamp(detached["expires_at"])
    freshness_window_days = detached["freshness_window_days"]
    if (
        not isinstance(freshness_window_days, int)
        or isinstance(freshness_window_days, bool)
        or freshness_window_days <= 0
    ):
        _fail(
            "provider_drift_assessment_invalid",
            "freshness_window_days must be a positive integer.",
        )
    if expires_at != observed_at + timedelta(days=freshness_window_days):
        _fail(
            "provider_drift_assessment_invalid",
            "expires_at must equal observed_at plus freshness_window_days.",
        )
    if detached["status"] not in _ASSESSMENT_STATUSES:
        _fail("provider_drift_assessment_invalid", "Provider drift status is invalid.")
    _comparison(
        detached["source_comparison"],
        field="source_comparison",
        allowed_statuses=_SOURCE_STATUSES,
    )
    _comparison(
        detached["replica_comparison"],
        field="replica_comparison",
        allowed_statuses=_REPLICA_STATUSES,
    )
    _validate_status_invariants(detached)
    return detached


def assessment_status_at(value: Mapping[str, Any], *, as_of: datetime) -> str:
    """Derive time-dependent staleness from an immutable assessment."""

    assessment = validate_provider_drift_assessment(value)
    trusted_as_of = _trusted_as_of(as_of)
    observed_at = _utc_timestamp(assessment["observed_at"])
    if trusted_as_of < observed_at:
        _fail(
            "provider_drift_assessment_as_of_precedes_observation",
            "as_of precedes the assessment observation time.",
        )
    if trusted_as_of >= _utc_timestamp(assessment["expires_at"]):
        return "stale"
    return assessment["status"]


def _assessment_input(value: Mapping[str, Any] | Path) -> dict[str, Any]:
    if isinstance(value, Path):
        raw, _ = _load_canonical_json_object(value, require_canonical=False)
        return validate_provider_drift_assessment(raw)
    return validate_provider_drift_assessment(value)


def _comparison(value: Any, *, field: str, allowed_statuses: frozenset[str]) -> None:
    if not isinstance(value, dict) or set(value) != _COMPARISON_FIELDS:
        _fail("provider_drift_assessment_invalid", f"{field} fields are invalid.")
    if value["status"] not in allowed_statuses:
        _fail("provider_drift_assessment_invalid", f"{field} status is invalid.")
    if value["report_sha256"] is not None:
        _sha256(value["report_sha256"], field=f"{field}.report_sha256")
    difference_count = value["difference_count"]
    if (
        not isinstance(difference_count, int)
        or isinstance(difference_count, bool)
        or difference_count < 0
    ):
        _fail(
            "provider_drift_assessment_invalid",
            f"{field}.difference_count must be a non-negative integer.",
        )


def _validate_status_invariants(value: Mapping[str, Any]) -> None:
    status = value["status"]
    source_status = value["source_comparison"]["status"]
    replica_status = value["replica_comparison"]["status"]
    valid = (
        (status == "current" and source_status == "equal" and replica_status == "passed")
        or (status == "provider_drift_detected" and source_status == "changed")
        or (
            status == "replica_mismatch" and source_status == "equal" and replica_status == "failed"
        )
        or (
            status == "reacquisition_blocked"
            and source_status in {"incomplete", "not_compared"}
            and replica_status in {"incomplete", "not_run"}
        )
    )
    if not valid:
        _fail(
            "provider_drift_assessment_status_inconsistent",
            "Provider drift status conflicts with its source or replica comparison.",
        )


def _load_entry(
    registry_root: Path,
    entry_path: Path,
    *,
    expected_binding: tuple[str, str, str],
) -> PublishedProviderAssessment:
    entry, _ = _load_canonical_json_object(entry_path, require_canonical=True)
    if set(entry) != _ENTRY_FIELDS:
        _fail(
            "provider_assessment_registry_entry_invalid",
            "Provider assessment registry entry fields are invalid.",
        )
    if entry["schema_version"] != PROVIDER_ASSESSMENT_REGISTRY_ENTRY_SCHEMA_VERSION:
        _fail(
            "provider_assessment_registry_entry_invalid",
            "Provider assessment registry entry schema is unsupported.",
        )
    assessment_id = _identifier(entry["assessment_id"], field="assessment_id")
    if entry_path.name != f"{assessment_id}.json":
        _fail(
            "provider_assessment_registry_entry_invalid",
            "Provider assessment entry filename does not match its assessment_id.",
        )
    actual_binding = _binding(
        release_manifest_sha256=entry["release_manifest_sha256"],
        profile_id=entry["profile_id"],
        program_id=entry["program_id"],
    )
    if actual_binding != expected_binding:
        _fail(
            "provider_assessment_registry_binding_invalid",
            "Provider assessment entry does not match its release/profile/program path.",
        )
    observed_at = entry["observed_at"]
    _utc_timestamp(observed_at)
    content_sha256 = _sha256(entry["content_sha256"], field="content_sha256")
    assessment = _load_assessment_blob(registry_root, content_sha256)
    for field in (
        "assessment_id",
        "release_manifest_sha256",
        "profile_id",
        "program_id",
        "observed_at",
    ):
        if assessment[field] != entry[field]:
            _fail(
                "provider_assessment_registry_binding_invalid",
                "Provider assessment blob does not match its immutable registry entry.",
                field=field,
            )
    return PublishedProviderAssessment(
        assessment_id=assessment_id,
        release_manifest_sha256=assessment["release_manifest_sha256"],
        profile_id=assessment["profile_id"],
        program_id=assessment["program_id"],
        observed_at=observed_at,
        content_sha256=content_sha256,
        assessment=assessment,
    )


def _load_assessment_blob(registry_root: Path, content_sha256: str) -> dict[str, Any]:
    blob = registry_root / "blobs" / "sha256" / content_sha256[7:]
    raw, payload = _load_canonical_json_object(blob, require_canonical=True)
    if _sha256_bytes(payload) != content_sha256:
        _fail(
            "provider_assessment_registry_blob_mismatch",
            "Provider assessment blob does not match its content digest.",
        )
    return validate_provider_drift_assessment(raw)


def _binding(
    *, release_manifest_sha256: str, profile_id: str, program_id: str
) -> tuple[str, str, str]:
    manifest = _sha256(release_manifest_sha256, field="release_manifest_sha256")
    return (
        manifest[7:],
        _identifier(profile_id, field="profile_id"),
        _identifier(program_id, field="program_id"),
    )


def _binding_parent(
    registry_root: Path,
    manifest_hex: str,
    profile_id: str,
    program_id: str,
    *,
    missing_ok: bool = False,
) -> Path | None:
    path = registry_root / "by-release" / manifest_hex / profile_id / program_id
    if missing_ok and not path.exists() and not path.is_symlink():
        return None
    return _require_directory(registry_root, path)


def _validate_registry_root(root: Path) -> Path:
    if root.is_symlink():
        _fail(
            "provider_assessment_registry_symlink_forbidden",
            "Provider assessment registry root is a symbolic link.",
        )
    try:
        resolved = root.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(
            "provider_assessment_registry_unreadable",
            f"Could not resolve provider assessment registry: {exc}.",
        )
    if not resolved.is_dir():
        _fail(
            "provider_assessment_registry_unreadable",
            "Provider assessment registry root must be a directory.",
        )
    expected_uid = os.getuid()
    for current, directories, files in os.walk(resolved, followlinks=False):
        current_path = Path(current)
        _require_permissions(current_path, expected_mode=0o700, expected_uid=expected_uid)
        for name in directories + files:
            path = current_path / name
            if path.is_symlink():
                _fail(
                    "provider_assessment_registry_symlink_forbidden",
                    "Provider assessment registry must not contain symbolic links.",
                    path=str(path),
                )
            if not (path.is_dir() or path.is_file()):
                _fail(
                    "provider_assessment_registry_special_file_forbidden",
                    "Provider assessment registry contains a special filesystem entry.",
                    path=str(path),
                )
            _require_permissions(
                path,
                expected_mode=0o700 if path.is_dir() else 0o444,
                expected_uid=expected_uid,
            )
    marker, _ = _load_canonical_json_object(resolved / "registry.json", require_canonical=True)
    if marker != _MARKER:
        _fail(
            "provider_assessment_registry_schema_unsupported",
            "Provider assessment registry marker is invalid.",
        )
    if {path.name for path in resolved.iterdir()} != {
        "registry.json",
        "blobs",
        "by-release",
    }:
        _fail(
            "provider_assessment_registry_layout_invalid",
            "Provider assessment registry root entries are invalid.",
        )
    blobs = _require_directory(resolved, resolved / "blobs")
    if {path.name for path in blobs.iterdir()} != {"sha256"}:
        _fail(
            "provider_assessment_registry_layout_invalid",
            "Provider assessment registry blob layout is invalid.",
        )
    for blob in _require_directory(resolved, blobs / "sha256").iterdir():
        if not blob.is_file() or re.fullmatch(r"[0-9a-f]{64}", blob.name) is None:
            _fail(
                "provider_assessment_registry_layout_invalid",
                "Provider assessment registry blob name is invalid.",
            )
    by_release = _require_directory(resolved, resolved / "by-release")
    for manifest in by_release.iterdir():
        if not manifest.is_dir() or re.fullmatch(r"[0-9a-f]{64}", manifest.name) is None:
            _fail(
                "provider_assessment_registry_layout_invalid",
                "Provider assessment release binding is invalid.",
            )
        for profile in manifest.iterdir():
            _identifier(profile.name, field="profile_id")
            if not profile.is_dir():
                _fail(
                    "provider_assessment_registry_layout_invalid",
                    "Provider assessment profile binding must be a directory.",
                )
            for program in profile.iterdir():
                _identifier(program.name, field="program_id")
                if not program.is_dir():
                    _fail(
                        "provider_assessment_registry_layout_invalid",
                        "Provider assessment program binding must be a directory.",
                    )
                for entry in program.iterdir():
                    if (
                        not entry.is_file()
                        or entry.suffix != ".json"
                        or _IDENTIFIER.fullmatch(entry.stem) is None
                    ):
                        _fail(
                            "provider_assessment_registry_layout_invalid",
                            "Provider assessment entry name is invalid.",
                        )
    return resolved


def _require_directory(root: Path, path: Path) -> Path:
    if path.is_symlink():
        _fail(
            "provider_assessment_registry_symlink_forbidden",
            "Provider assessment registry directory is a symbolic link.",
            path=str(path),
        )
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(
            "provider_assessment_registry_layout_invalid",
            f"Could not resolve provider assessment registry directory: {exc}.",
            path=str(path),
        )
    if not resolved.is_relative_to(root) or not resolved.is_dir():
        _fail(
            "provider_assessment_registry_path_escape",
            "Provider assessment registry directory leaves its root.",
            path=str(resolved),
        )
    _require_permissions(resolved, expected_mode=0o700, expected_uid=os.getuid())
    return resolved


def _load_canonical_json_object(
    path: Path, *, require_canonical: bool
) -> tuple[dict[str, Any], bytes]:
    if path.is_symlink():
        _fail(
            "provider_assessment_registry_symlink_forbidden",
            "Provider assessment JSON is a symbolic link.",
            path=str(path),
        )
    try:
        if not path.is_file():
            raise FileNotFoundError(path)
        size = path.stat().st_size
        if size > PROVIDER_ASSESSMENT_MAX_JSON_BYTES:
            _fail(
                "provider_assessment_size_limit_exceeded",
                "Provider assessment JSON exceeds the v1 size limit.",
            )
        payload = path.read_bytes()
        value = json.loads(
            payload.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_pairs,
        )
    except ProviderRuntimeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(
            "provider_assessment_registry_json_invalid",
            f"Could not load provider assessment JSON: {exc}.",
            path=str(path),
        )
    if not isinstance(value, dict):
        _fail(
            "provider_assessment_registry_json_invalid",
            "Provider assessment JSON must contain an object.",
        )
    try:
        canonical = canonical_json_bytes(value)
    except (TypeError, ValueError) as exc:
        _fail(
            "provider_assessment_registry_json_invalid",
            f"Provider assessment JSON must contain finite JSON values: {exc}.",
            path=str(path),
        )
    if require_canonical and payload != canonical:
        _fail(
            "provider_assessment_registry_tampered",
            "Provider assessment registry JSON is not in its published canonical form.",
            path=str(path),
        )
    return value, payload


def _canonical_destination(path: Path) -> tuple[Path, Path]:
    if path.name in {"", ".", ".."}:
        _fail(
            "provider_assessment_registry_output_invalid",
            "Provider assessment registry path is invalid.",
        )
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        parent = path.parent.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(
            "provider_assessment_registry_output_invalid",
            f"Could not resolve provider assessment registry parent: {exc}.",
        )
    if not parent.is_dir():
        _fail(
            "provider_assessment_registry_output_invalid",
            "Provider assessment registry parent must be a directory.",
        )
    return parent / path.name, parent


def _write_exclusive(path: Path, payload: bytes, *, mode: int) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def _verify_existing(path: Path, payload: bytes, *, conflict_code: str) -> None:
    if path.is_symlink():
        _fail(
            "provider_assessment_registry_symlink_forbidden",
            "Provider assessment registry object is a symbolic link.",
        )
    try:
        existing = path.read_bytes()
    except OSError as exc:
        _fail(
            "provider_assessment_registry_unreadable",
            f"Could not read provider assessment registry object: {exc}.",
        )
    if existing != payload:
        _fail(
            conflict_code,
            "Immutable provider assessment registry object contains different bytes.",
            path=str(path),
        )


def _require_permissions(path: Path, *, expected_mode: int, expected_uid: int) -> None:
    try:
        metadata = path.stat(follow_symlinks=False)
    except OSError as exc:
        _fail(
            "provider_assessment_registry_unreadable",
            f"Could not inspect provider assessment registry permissions: {exc}.",
        )
    mode = stat.S_IMODE(metadata.st_mode)
    if metadata.st_uid != expected_uid or mode != expected_mode:
        _fail(
            "provider_assessment_registry_permissions_invalid",
            "Provider assessment entries must be owner-controlled and immutable.",
            path=str(path),
            expected_mode=oct(expected_mode),
            actual_mode=oct(mode),
        )


def _identifier(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _IDENTIFIER.fullmatch(value) is None:
        _fail(
            "provider_drift_assessment_identifier_invalid",
            f"{field} is not a valid identifier.",
        )
    return value


def _sha256(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or _SHA256.fullmatch(value) is None:
        _fail(
            "provider_drift_assessment_digest_invalid",
            f"{field} is not a valid SHA-256 digest.",
        )
    return value


def _utc_timestamp(value: Any) -> datetime:
    if not isinstance(value, str) or _RFC3339_UTC.fullmatch(value) is None:
        _fail(
            "provider_drift_assessment_timestamp_invalid",
            "Timestamp must be RFC 3339 UTC using the Z suffix.",
        )
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ProviderRuntimeError(
            "provider_drift_assessment_timestamp_invalid",
            "Timestamp must be a valid RFC 3339 UTC value.",
            {},
        ) from exc
    return parsed.astimezone(UTC)


def _trusted_as_of(value: Any) -> datetime:
    if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() != timedelta(0):
        _fail(
            "provider_drift_assessment_as_of_invalid",
            "as_of must be an aware UTC datetime.",
        )
    return value.astimezone(UTC)


def _sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _reject_duplicate_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            _fail(
                "provider_assessment_registry_json_invalid",
                "Provider assessment JSON contains duplicate object keys.",
                key=key,
            )
        result[key] = value
    return result


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderRuntimeError(code, message, details)
