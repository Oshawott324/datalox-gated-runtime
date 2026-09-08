from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_runtime.assessment_registry import (
    FilesystemProviderAssessmentRegistry,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError

ROOT = Path(__file__).resolve().parents[1]
RELEASE = "sha256:" + "a" * 64


def _assessment(
    *,
    assessment_id: str = "openlmis-2026-09-04",
    observed_at: str = "2026-09-04T08:00:00Z",
    expires_at: str = "2026-10-04T08:00:00Z",
    status: str = "current",
) -> dict[str, object]:
    return {
        "schema_version": "datalox_provider_drift_assessment_v1",
        "assessment_id": assessment_id,
        "provider_id": "openlmis",
        "program_id": "notification.update_contact_details",
        "observed_at": observed_at,
        "baseline_measurement_sha256": "sha256:" + "b" * 64,
        "candidate_measurement_sha256": "sha256:" + "c" * 64,
        "release_manifest_sha256": RELEASE,
        "profile_id": "regional-network-v1",
        "source_comparison": {
            "status": "equal",
            "report_sha256": "sha256:" + "d" * 64,
            "difference_count": 0,
        },
        "replica_comparison": {
            "status": "passed",
            "report_sha256": "sha256:" + "e" * 64,
            "difference_count": 0,
        },
        "status": status,
        "freshness_window_days": 30,
        "expires_at": expires_at,
    }


def _entry_path(root: Path, assessment_id: str) -> Path:
    return (
        root
        / "by-release"
        / ("a" * 64)
        / "regional-network-v1"
        / "notification.update_contact_details"
        / f"{assessment_id}.json"
    )


def test_assessment_schema_and_registry_publish_are_strict_and_idempotent(
    tmp_path: Path,
) -> None:
    schema = json.loads(
        (ROOT / "schemas" / "provider-drift-assessment-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(_assessment())

    root = tmp_path / "assessments"
    registry = FilesystemProviderAssessmentRegistry.create(root)
    first = registry.publish_assessment(_assessment())
    second = registry.publish_assessment(_assessment())

    expected_payload = canonical_json_bytes(_assessment())
    expected_digest = "sha256:" + hashlib.sha256(expected_payload).hexdigest()
    assert first.content_sha256 == expected_digest
    assert second == first
    assert (root / "blobs" / "sha256" / expected_digest[7:]).read_bytes() == expected_payload
    assert _entry_path(root, "openlmis-2026-09-04").is_file()
    assert not any(path.name == "latest" for path in root.rglob("*"))


def test_assessment_identity_conflict_is_rejected(tmp_path: Path) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / "assessments")
    registry.publish_assessment(_assessment())
    changed = _assessment(status="replica_mismatch")
    changed["replica_comparison"] = {
        "status": "failed",
        "report_sha256": "sha256:" + "f" * 64,
        "difference_count": 1,
    }
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(changed)
    assert caught.value.code == "provider_assessment_registry_identity_conflict"


def test_list_and_latest_are_derived_from_validated_time_and_digest(tmp_path: Path) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / "assessments")
    late = registry.publish_assessment(
        _assessment(
            assessment_id="late",
            observed_at="2026-09-05T08:00:00Z",
            expires_at="2026-10-05T08:00:00Z",
        )
    )
    early = registry.publish_assessment(
        _assessment(
            assessment_id="early",
            observed_at="2026-09-03T08:00:00Z",
            expires_at="2026-10-03T08:00:00Z",
        )
    )
    same_time = registry.publish_assessment(
        _assessment(
            assessment_id="same-time",
            observed_at="2026-09-05T08:00:00Z",
            expires_at="2026-10-05T08:00:00Z",
        )
    )

    listed = registry.list_assessments(
        release_manifest_sha256=RELEASE,
        profile_id="regional-network-v1",
        program_id="notification.update_contact_details",
    )
    assert listed[0] == early
    assert listed[1:] == tuple(sorted((late, same_time), key=lambda item: item.content_sha256))
    assert (
        registry.latest_assessment(
            release_manifest_sha256=RELEASE,
            profile_id="regional-network-v1",
            program_id="notification.update_contact_details",
        )
        == listed[-1]
    )
    assert (
        registry.list_assessments(
            release_manifest_sha256="sha256:" + "0" * 64,
            profile_id="regional-network-v1",
            program_id="notification.update_contact_details",
        )
        == ()
    )


def test_registry_rejects_tampered_blob_entry_permissions_and_symlinks(tmp_path: Path) -> None:
    root = tmp_path / "assessments"
    registry = FilesystemProviderAssessmentRegistry.create(root)
    published = registry.publish_assessment(_assessment())
    blob = root / "blobs" / "sha256" / published.content_sha256[7:]
    blob.chmod(0o644)
    blob.write_bytes(blob.read_bytes() + b" ")
    blob.chmod(0o444)
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.load_blob(published.content_sha256)
    assert caught.value.code in {
        "provider_assessment_registry_tampered",
        "provider_assessment_registry_blob_mismatch",
    }

    root = tmp_path / "assessment-permissions"
    registry = FilesystemProviderAssessmentRegistry.create(root)
    registry.publish_assessment(_assessment())
    entry = _entry_path(root, "openlmis-2026-09-04")
    entry.chmod(0o644)
    with pytest.raises(ProviderRuntimeError) as caught:
        FilesystemProviderAssessmentRegistry.load(root)
    assert caught.value.code == "provider_assessment_registry_permissions_invalid"

    root = tmp_path / "assessment-links"
    FilesystemProviderAssessmentRegistry.create(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "by-release" / ("f" * 64)).symlink_to(outside, target_is_directory=True)
    with pytest.raises(ProviderRuntimeError) as caught:
        FilesystemProviderAssessmentRegistry.load(root)
    assert caught.value.code == "provider_assessment_registry_symlink_forbidden"


@pytest.mark.parametrize(
    ("field", "value", "code"),
    [
        ("profile_id", "../escape", "provider_drift_assessment_identifier_invalid"),
        ("program_id", "a/b", "provider_drift_assessment_identifier_invalid"),
        (
            "release_manifest_sha256",
            "sha256:../../escape",
            "provider_drift_assessment_digest_invalid",
        ),
        (
            "observed_at",
            "2026-09-04T08:00:00+00:00",
            "provider_drift_assessment_timestamp_invalid",
        ),
    ],
)
def test_registry_rejects_path_traversal_and_non_utc_timestamps(
    tmp_path: Path, field: str, value: str, code: str
) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / f"registry-{field}")
    assessment = _assessment()
    assessment[field] = value
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(assessment)
    assert caught.value.code == code


def test_registry_detects_entry_tampering_and_blob_binding_mismatch(tmp_path: Path) -> None:
    root = tmp_path / "assessments"
    registry = FilesystemProviderAssessmentRegistry.create(root)
    registry.publish_assessment(_assessment())
    entry = _entry_path(root, "openlmis-2026-09-04")
    raw = json.loads(entry.read_text(encoding="utf-8"))
    raw["observed_at"] = "2026-09-02T08:00:00Z"
    entry.chmod(0o644)
    entry.write_bytes(canonical_json_bytes(raw))
    entry.chmod(0o444)

    with pytest.raises(ProviderRuntimeError) as caught:
        registry.list_assessments(
            release_manifest_sha256=RELEASE,
            profile_id="regional-network-v1",
            program_id="notification.update_contact_details",
        )
    assert caught.value.code == "provider_assessment_registry_binding_invalid"


def test_assessment_requires_exact_expiry_and_rejects_unknown_fields(tmp_path: Path) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / "assessments")
    wrong_expiry = _assessment(expires_at="2026-10-03T08:00:00Z")
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(wrong_expiry)
    assert caught.value.code == "provider_drift_assessment_invalid"

    duplicate = tmp_path / "duplicate.json"
    duplicate.write_text('{"schema_version":"first","schema_version":"second"}', encoding="utf-8")
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(duplicate)
    assert caught.value.code == "provider_assessment_registry_json_invalid"

    unknown = _assessment()
    unknown["latest"] = True
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(unknown)
    assert caught.value.code == "provider_drift_assessment_invalid"


@pytest.mark.parametrize(
    ("status", "source_status", "replica_status"),
    [
        ("current", "changed", "passed"),
        ("current", "equal", "failed"),
        ("provider_drift_detected", "equal", "passed"),
        ("replica_mismatch", "changed", "failed"),
        ("replica_mismatch", "equal", "passed"),
        ("reacquisition_blocked", "equal", "not_run"),
        ("reacquisition_blocked", "incomplete", "passed"),
    ],
)
def test_assessment_rejects_cross_field_status_conflicts(
    tmp_path: Path, status: str, source_status: str, replica_status: str
) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(
        tmp_path / f"assessments-{status}-{source_status}-{replica_status}"
    )
    assessment = _assessment(status=status)
    assessment["source_comparison"]["status"] = source_status
    assessment["replica_comparison"]["status"] = replica_status
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(assessment)
    assert caught.value.code == "provider_drift_assessment_status_inconsistent"


@pytest.mark.parametrize(
    ("status", "source_status", "replica_status"),
    [
        ("provider_drift_detected", "changed", "not_run"),
        ("replica_mismatch", "equal", "failed"),
        ("reacquisition_blocked", "incomplete", "not_run"),
        ("reacquisition_blocked", "not_compared", "incomplete"),
    ],
)
def test_assessment_accepts_each_consistent_observed_status(
    tmp_path: Path, status: str, source_status: str, replica_status: str
) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(
        tmp_path / f"assessments-{status}-{source_status}-{replica_status}"
    )
    assessment = _assessment(status=status)
    assessment["source_comparison"]["status"] = source_status
    assessment["replica_comparison"]["status"] = replica_status
    published = registry.publish_assessment(assessment)
    assert published.assessment["status"] == status


def test_stale_is_derived_at_trusted_as_of_and_future_observations_fail(tmp_path: Path) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / "assessments")
    registry.publish_assessment(_assessment())
    binding = {
        "release_manifest_sha256": RELEASE,
        "profile_id": "regional-network-v1",
        "program_id": "notification.update_contact_details",
    }
    assert (
        registry.assessment_status_at(**binding, as_of=datetime(2026, 9, 20, tzinfo=UTC))
        == "current"
    )
    assert (
        registry.assessment_status_at(**binding, as_of=datetime(2026, 10, 4, 8, tzinfo=UTC))
        == "stale"
    )
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.assessment_status_at(**binding, as_of=datetime(2026, 9, 1, tzinfo=UTC))
    assert caught.value.code == "provider_drift_assessment_as_of_precedes_observation"
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.assessment_status_at(**binding, as_of=datetime(2026, 9, 20))
    assert caught.value.code == "provider_drift_assessment_as_of_invalid"


def test_stale_cannot_be_published_as_an_observed_result(tmp_path: Path) -> None:
    registry = FilesystemProviderAssessmentRegistry.create(tmp_path / "assessments")
    assessment = _assessment(status="stale")
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish_assessment(assessment)
    assert caught.value.code == "provider_drift_assessment_invalid"
