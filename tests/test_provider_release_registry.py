from __future__ import annotations

import hashlib
import io
import json
import stat
import tarfile
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from provider_runtime_helpers import (
    PROVIDER_AUTHORITY,
    build_stateful_provider_bundle,
    write_replay_provider_config,
)
from test_provider_admission import _claims

from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_runtime.admission import admit_provider_runtime
from datalox_gated_runtime.provider_runtime.bundle import (
    build_provider_runtime_from_gate_config,
    compute_provider_runtime_hashes,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime import release as release_module
from datalox_gated_runtime.provider_runtime.release import (
    PROVIDER_RELEASE_ARTIFACT_TYPE,
    PROVIDER_RELEASE_CONFIG_MEDIA_TYPE,
    PROVIDER_RELEASE_MAX_JSON_BYTES,
    PROVIDER_RELEASE_PROFILE_MEDIA_TYPE,
    ProviderReleaseProfileInput,
    _extract_profile_layer,
    build_provider_release,
    load_provider_release,
    materialize_provider_release_profile,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _profile(
    root: Path,
    *,
    profile_id: str,
    initial_counter: int = 1,
    add_long_path: bool = False,
) -> ProviderReleaseProfileInput:
    bundle = build_stateful_provider_bundle(root / "bundle-root")
    if initial_counter != 1:
        seed_path = bundle / "seed.json"
        seed = json.loads(seed_path.read_text(encoding="utf-8"))
        seed["initial_state"]["counter"] = initial_counter
        _write_json(seed_path, seed)
        source_path = bundle / "source.json"
        source = json.loads(source_path.read_text(encoding="utf-8"))
        source["reset_profile_fixture"] = profile_id
        _write_json(source_path, source)
    if add_long_path:
        long_asset = bundle / "runtime" / ("long-" + "a" * 120) / "behavior-metadata.json"
        _write_json(long_asset, {"purpose": "deterministic long-path coverage"})
    if initial_counter != 1 or add_long_path:
        manifest_path = bundle / "provider-runtime.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["content_hashes"] = compute_provider_runtime_hashes(bundle)
        _write_json(manifest_path, manifest)

    claims_root = root / "claims"
    claims_root.mkdir(parents=True)
    claims = _claims(claims_root)
    admission = root / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims,
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    return ProviderReleaseProfileInput(
        profile_id=profile_id,
        bundle_dir=bundle,
        admission_path=admission,
    )


def _tree_digests(root: Path) -> dict[str, str]:
    return {
        path.relative_to(root).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in sorted(root.rglob("*"))
        if path.is_file()
    }


def _gate_profile(root: Path, *, profile_id: str) -> ProviderReleaseProfileInput:
    root.mkdir(parents=True)
    source_config = write_replay_provider_config(root)
    bundle = root / "provider-bundle"
    build_provider_runtime_from_gate_config(
        source_gate_config=source_config,
        output_dir=bundle,
        provider_id="replay_provider",
        authorities=(PROVIDER_AUTHORITY,),
    )
    evidence = root / "evidence.json"
    evidence.write_text('{"source":"self-authored-test-contract"}\n', encoding="utf-8")

    def request(path: str, *, headers: dict[str, str] | None = None) -> dict[str, object]:
        return {
            "scheme": "https",
            "authority": PROVIDER_AUTHORITY,
            "method": "GET",
            "path": path,
            "query": {},
            "headers": headers or {},
            "body": None,
        }

    claims = {
        "schema_version": "datalox_provider_operation_claims_v1",
        "provider_id": "replay_provider",
        "bundle_version": "1.0.0",
        "evidence_sources": [
            {
                "evidence_id": "official_contract",
                "artifact_ref": "evidence.json",
                "artifact_sha256": "sha256:" + hashlib.sha256(evidence.read_bytes()).hexdigest(),
                "grounding_level": "G1_OFFICIAL_SOURCE",
                "observed_at": "2026-08-01T00:00:00Z",
                "valid_through": "2027-08-01T00:00:00Z",
                "distribution_label": "public",
                "rights_basis": "Self-authored test contract.",
            }
        ],
        "operations": [
            {
                "operation_id": "records.list",
                "native_surface": {
                    "type": "http",
                    "scheme": "https",
                    "authority": PROVIDER_AUTHORITY,
                    "method": "GET",
                    "path_template": "/v1/records",
                },
                "mutability": "read",
                "behavior_program": "records_list_program",
                "state_effects": [],
                "grounding": {
                    "level": "G1_OFFICIAL_SOURCE",
                    "evidence_refs": ["official_contract"],
                },
                "rights": {
                    "distribution_label": "public",
                    "behavior_distribution_basis": "Self-authored provider behavior.",
                },
                "covered_behaviors": ["success", "failure"],
            }
        ],
        "provider_invariants": [
            {
                "predicate_id": "calls_are_recorded",
                "source": "call_evidence",
                "operator": "type",
                "pointer": "/events",
                "expected_type": "array",
            }
        ],
        "receipt_predicates": [
            {
                "predicate_id": "response_is_object",
                "source": "response_body",
                "operator": "type",
                "pointer": "",
                "expected_type": "object",
            }
        ],
        "reset_profiles": [{"profile_id": "default", "kind": "compiled_seed"}],
        "behavior_probes": [
            {
                "probe_id": "records_behavior",
                "reset_profile": "default",
                "steps": [
                    {
                        "step_id": "success",
                        "operation_id": "records.list",
                        "request": request("/v1/records"),
                        "expected_status_code": 200,
                        "expected_decision_kind": "replay",
                        "covers": [{"operation_id": "records.list", "behavior": "success"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                    {
                        "step_id": "failure",
                        "operation_id": "records.list",
                        "request": request(
                            "/v1/records", headers={"x-datalox-actor-role": "operator"}
                        ),
                        "expected_status_code": 400,
                        "expected_decision_kind": "deny",
                        "covers": [{"operation_id": "records.list", "behavior": "failure"}],
                        "receipt_predicate_refs": ["response_is_object"],
                    },
                ],
            }
        ],
    }
    claims_path = root / "operation-claims.json"
    _write_json(claims_path, claims)
    admission = root / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    return ProviderReleaseProfileInput(profile_id, bundle, admission)


def _descriptor(media_type: str, payload: bytes) -> dict[str, object]:
    return {
        "mediaType": media_type,
        "digest": "sha256:" + hashlib.sha256(payload).hexdigest(),
        "size": len(payload),
    }


def _rewrite_release_config(release_path: Path, mutate: object) -> None:
    loaded = load_provider_release(release_path)
    config = json.loads(json.dumps(loaded.config))
    assert callable(mutate)
    mutate(config)
    config_payload = canonical_json_bytes(config)
    config_descriptor = _descriptor(PROVIDER_RELEASE_CONFIG_MEDIA_TYPE, config_payload)
    config_blob = release_path / "blobs" / "sha256" / str(config_descriptor["digest"])[7:]
    config_blob.write_bytes(config_payload)

    manifest = json.loads(json.dumps(loaded.manifest))
    manifest["config"] = config_descriptor
    manifest_payload = canonical_json_bytes(manifest)
    manifest_descriptor = {
        **_descriptor("application/vnd.oci.image.manifest.v1+json", manifest_payload),
        "artifactType": PROVIDER_RELEASE_ARTIFACT_TYPE,
        "annotations": loaded.manifest_descriptor["annotations"],
    }
    manifest_blob = release_path / "blobs" / "sha256" / str(manifest_descriptor["digest"])[7:]
    manifest_blob.write_bytes(manifest_payload)
    index = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [manifest_descriptor],
    }
    index_path = release_path / "index.json"
    index_path.chmod(0o644)
    index_path.write_bytes(canonical_json_bytes(index))


def test_multi_profile_release_is_deterministic_complete_and_materializable(
    tmp_path: Path,
) -> None:
    default = _profile(
        tmp_path / "default",
        profile_id="default",
        add_long_path=True,
    )
    backlog = _profile(
        tmp_path / "backlog",
        profile_id="backlog",
        initial_counter=7,
        add_long_path=True,
    )
    first_path = tmp_path / "release-one"
    second_path = tmp_path / "release-two"

    first = build_provider_release(
        profiles=(default, backlog), release_version="2026.08.25", output_dir=first_path
    )
    second = build_provider_release(
        profiles=(backlog, default), release_version="2026.08.25", output_dir=second_path
    )

    assert first.manifest_descriptor["digest"] == second.manifest_descriptor["digest"]
    assert _tree_digests(first_path) == _tree_digests(second_path)
    assert json.loads((first_path / "oci-layout").read_text()) == {"imageLayoutVersion": "1.0.0"}
    assert first.manifest["artifactType"] == PROVIDER_RELEASE_ARTIFACT_TYPE
    assert first.manifest["config"]["mediaType"] == PROVIDER_RELEASE_CONFIG_MEDIA_TYPE
    assert {layer["mediaType"] for layer in first.manifest["layers"]} == {
        PROVIDER_RELEASE_PROFILE_MEDIA_TYPE
    }
    assert [profile.profile_id for profile in first.profiles] == ["backlog", "default"]
    assert first.config["operations"][1]["rights"]["distribution_label"] == "public"
    assert first.config["evidence_sources"][0]["valid_through"] == "2027-08-01T00:00:00Z"
    assert "artifact_ref" not in first.config["evidence_sources"][0]
    assert first.config["evidence_sources"][0]["origin_artifact_ref"] == "evidence.json"
    assert (
        first.config["operation_claims_sha256"]
        == (first.config["profiles"][0]["operation_claims_sha256"])
    )
    assert first.config["provider_invariants"][0]["operator"] == "type"
    assert first.config["receipt_predicates"][0]["passed"] is True

    schema = json.loads(
        (ROOT / "schemas" / "provider-release-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(first.config)

    output = tmp_path / "materialized"
    materialized = materialize_provider_release_profile(
        release=first, profile_id="backlog", output_dir=output
    )
    seed = json.loads((materialized.bundle_dir / "seed.json").read_text(encoding="utf-8"))
    assert seed["initial_state"]["counter"] == 7
    assert materialized.admission_path.is_file()
    assert any(
        len(path.relative_to(materialized.bundle_dir).as_posix()) > 100
        for path in materialized.bundle_dir.rglob("*")
    )


def test_release_loader_rejects_blob_corruption_and_existing_materialization(
    tmp_path: Path,
) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release_path = tmp_path / "release"
    release = build_provider_release(
        profiles=(profile,), release_version="1.0.0", output_dir=release_path
    )
    existing = tmp_path / "existing"
    existing.mkdir()
    with pytest.raises(ProviderRuntimeError) as caught:
        materialize_provider_release_profile(
            release=release, profile_id="default", output_dir=existing
        )
    assert caught.value.code == "provider_release_materialize_output_exists"

    layer = release.profiles[0].layer
    blob = release_path / "blobs" / "sha256" / layer["digest"][7:]
    blob.chmod(0o644)
    blob.write_bytes(blob.read_bytes() + b"corrupt")
    with pytest.raises(ProviderRuntimeError) as caught:
        load_provider_release(release_path)
    assert caught.value.code == "provider_release_blob_mismatch"


def test_release_loader_validates_embedded_runtime_admission_binding(tmp_path: Path) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release_path = tmp_path / "release"
    build_provider_release(profiles=(profile,), release_version="1.0.0", output_dir=release_path)

    def mutate(config: dict[str, object]) -> None:
        profiles = config["profiles"]
        assert isinstance(profiles, list)
        profiles[0]["provider_runtime_sha256"] = "sha256:" + "0" * 64

    _rewrite_release_config(release_path, mutate)
    with pytest.raises(ProviderRuntimeError) as caught:
        load_provider_release(release_path)
    assert caught.value.code == "provider_release_materialized_binding_invalid"


def test_gate_config_release_rejects_multiple_profiles(tmp_path: Path) -> None:
    first = _gate_profile(tmp_path / "first", profile_id="default")
    second = _gate_profile(tmp_path / "second", profile_id="alternate")

    with pytest.raises(ProviderRuntimeError) as caught:
        build_provider_release(
            profiles=(first, second),
            release_version="1.0.0",
            output_dir=tmp_path / "release",
        )
    assert caught.value.code == "provider_release_gate_config_profiles_unsupported"
    assert not (tmp_path / "release").exists()


def test_profile_extractor_rejects_links_and_path_escapes(tmp_path: Path) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.GNU_FORMAT) as archive:
        info = tarfile.TarInfo("../escape")
        info.mtime = 0
        info.uid = 0
        info.gid = 0
        info.mode = 0o644
        info.size = 1
        archive.addfile(info, io.BytesIO(b"x"))
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(payload.getvalue(), tmp_path / "extract")
    assert caught.value.code == "provider_release_layer_path_invalid"

    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.GNU_FORMAT) as archive:
        link = tarfile.TarInfo("runtime/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/tmp/elsewhere"
        link.mtime = 0
        link.uid = 0
        link.gid = 0
        link.mode = 0o777
        archive.addfile(link)
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(payload.getvalue(), tmp_path / "extract-link")
    assert caught.value.code == "provider_release_layer_entry_forbidden"


def test_filesystem_registry_is_immutable_idempotent_and_materializes(tmp_path: Path) -> None:
    first_profile = _profile(tmp_path / "first-profile", profile_id="default")
    first_release = build_provider_release(
        profiles=(first_profile,),
        release_version="2026.08.25",
        output_dir=tmp_path / "first-release",
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")

    first_publish = registry.publish(first_release)
    second_publish = registry.publish(first_release)
    assert first_publish.reference == "example_provider@2026.08.25"
    assert second_publish.manifest_digest == first_publish.manifest_digest
    assert registry.resolve(first_publish.reference).manifest_descriptor["digest"] == (
        first_publish.manifest_digest
    )

    materialized = registry.materialize(
        reference=first_publish.reference,
        profile_id="default",
        output_dir=tmp_path / "registry-materialized",
    )
    assert materialized.bundle_dir.is_dir()
    assert materialized.admission_path.is_file()

    changed_profile = _profile(
        tmp_path / "changed-profile", profile_id="default", initial_counter=19
    )
    changed_release = build_provider_release(
        profiles=(changed_profile,),
        release_version="2026.08.25",
        output_dir=tmp_path / "changed-release",
    )
    with pytest.raises(ProviderRuntimeError) as caught:
        registry.publish(changed_release)
    assert caught.value.code == "provider_registry_reference_conflict"
    assert registry.resolve(first_publish.reference).manifest_descriptor["digest"] == (
        first_publish.manifest_digest
    )


def test_registry_rejects_symlinked_reference(tmp_path: Path) -> None:
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    provider = registry.root / "refs" / "example_provider"
    provider.mkdir(mode=0o700)
    (provider / "1.0.0.json").symlink_to(tmp_path / "outside.json")

    with pytest.raises(ProviderRuntimeError) as caught:
        registry.resolve("example_provider@1.0.0")
    assert caught.value.code == "provider_registry_symlink_forbidden"


def test_directory_publication_never_replaces_existing_or_racing_empty_output(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    existing = tmp_path / "existing-release"
    existing.mkdir()
    with pytest.raises(ProviderRuntimeError) as caught:
        build_provider_release(profiles=(profile,), release_version="1.0.0", output_dir=existing)
    assert caught.value.code == "provider_release_output_exists"
    assert list(existing.iterdir()) == []

    destination = tmp_path / "racing-release"
    original_publish = release_module._publish_validated_directory

    def create_racer(**kwargs: object) -> None:
        raced_destination = kwargs["destination"]
        assert isinstance(raced_destination, Path)
        raced_destination.mkdir()
        original_publish(**kwargs)

    monkeypatch.setattr(release_module, "_publish_validated_directory", create_racer)
    with pytest.raises(ProviderRuntimeError) as caught:
        build_provider_release(profiles=(profile,), release_version="1.0.1", output_dir=destination)
    assert caught.value.code == "provider_release_output_exists"
    assert list(destination.iterdir()) == []

    existing_registry = tmp_path / "existing-registry"
    existing_registry.mkdir()
    with pytest.raises(ProviderRuntimeError) as caught:
        FilesystemProviderReleaseRegistry.create(existing_registry)
    assert caught.value.code == "provider_registry_output_exists"
    assert list(existing_registry.iterdir()) == []


def test_registry_constructor_permissions_and_published_modes_are_strict(tmp_path: Path) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release = build_provider_release(
        profiles=(profile,), release_version="1.0.0", output_dir=tmp_path / "release"
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    registry.publish(release)

    for path in registry.root.rglob("*"):
        expected = 0o700 if path.is_dir() else 0o444
        assert stat.S_IMODE(path.stat().st_mode) == expected
    assert stat.S_IMODE(registry.root.stat().st_mode) == 0o700

    registry.root.chmod(0o755)
    with pytest.raises(ProviderRuntimeError) as caught:
        FilesystemProviderReleaseRegistry(registry.root)
    assert caught.value.code == "provider_registry_permissions_invalid"


def test_release_rejects_oversized_descriptor_before_blob_read(tmp_path: Path) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release_path = tmp_path / "release"
    build_provider_release(profiles=(profile,), release_version="1.0.0", output_dir=release_path)
    index_path = release_path / "index.json"
    index = json.loads(index_path.read_text(encoding="utf-8"))
    index["manifests"][0]["size"] = PROVIDER_RELEASE_MAX_JSON_BYTES + 1
    index_path.chmod(0o644)
    index_path.write_bytes(canonical_json_bytes(index))

    with pytest.raises(ProviderRuntimeError) as caught:
        load_provider_release(release_path)
    assert caught.value.code == "provider_release_size_limit_exceeded"


def test_profile_extraction_resource_limits_are_enforced(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    payload = io.BytesIO()
    with tarfile.open(fileobj=payload, mode="w", format=tarfile.GNU_FORMAT) as archive:
        for name in ("runtime", "runtime/a", "provider-admission.json"):
            info = tarfile.TarInfo(name + ("/" if name == "runtime" else ""))
            info.mtime = 0
            info.uid = 0
            info.gid = 0
            info.uname = ""
            info.gname = ""
            if name == "runtime":
                info.type = tarfile.DIRTYPE
                info.mode = 0o755
                archive.addfile(info)
            else:
                info.mode = 0o644
                info.size = 2
                archive.addfile(info, io.BytesIO(b"{}"))
    archive_bytes = payload.getvalue()

    monkeypatch.setattr(release_module, "PROVIDER_RELEASE_MAX_TAR_MEMBERS", 2)
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(archive_bytes, tmp_path / "member-limit")
    assert caught.value.code == "provider_release_member_limit_exceeded"

    monkeypatch.setattr(release_module, "PROVIDER_RELEASE_MAX_TAR_MEMBERS", 20_000)
    monkeypatch.setattr(release_module, "PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES", 1)
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(archive_bytes, tmp_path / "file-limit")
    assert caught.value.code == "provider_release_file_limit_exceeded"

    monkeypatch.setattr(release_module, "PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES", 128)
    monkeypatch.setattr(release_module, "PROVIDER_RELEASE_MAX_EXTRACTED_BYTES", 3)
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(archive_bytes, tmp_path / "total-limit")
    assert caught.value.code == "provider_release_extracted_limit_exceeded"

    monkeypatch.setattr(
        release_module, "PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES", len(archive_bytes) - 1
    )
    with pytest.raises(ProviderRuntimeError) as caught:
        _extract_profile_layer(archive_bytes, tmp_path / "layer-limit")
    assert caught.value.code == "provider_release_size_limit_exceeded"


def test_release_load_and_registry_publish_stream_profile_layers(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    profile = _profile(tmp_path / "profile", profile_id="default")
    release_path = tmp_path / "release"
    release = build_provider_release(
        profiles=(profile,), release_version="1.0.0", output_dir=release_path
    )
    layer = release.profiles[0].layer
    layer_path = release_path / "blobs" / "sha256" / layer["digest"][7:]
    original_read_bytes = Path.read_bytes

    def reject_layer_read_bytes(path: Path) -> bytes:
        if path == layer_path:
            raise AssertionError("profile layer was read wholesale")
        return original_read_bytes(path)

    monkeypatch.setattr(Path, "read_bytes", reject_layer_read_bytes)
    loaded = load_provider_release(release_path)
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    registry.publish(loaded)
