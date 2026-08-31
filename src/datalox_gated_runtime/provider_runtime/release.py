"""Immutable multi-profile provider releases stored as OCI image layouts."""

from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
from copy import deepcopy
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO, Mapping

from datalox_gated_runtime.json_digest import canonical_json_bytes, canonical_json_sha256
from datalox_gated_runtime.provider_runtime.admission import load_provider_admission
from datalox_gated_runtime.provider_runtime.bundle import (
    GateConfigBehaviorSpec,
    LoadedProviderRuntimeBundle,
    WorldV1BehaviorSpec,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.errors import ProviderRuntimeError

PROVIDER_RELEASE_SCHEMA_VERSION = "datalox_provider_release_v1"
OCI_IMAGE_LAYOUT_VERSION = "1.0.0"
OCI_INDEX_MEDIA_TYPE = "application/vnd.oci.image.index.v1+json"
OCI_MANIFEST_MEDIA_TYPE = "application/vnd.oci.image.manifest.v1+json"
PROVIDER_RELEASE_ARTIFACT_TYPE = "application/vnd.datalox.provider-release.v1"
PROVIDER_RELEASE_CONFIG_MEDIA_TYPE = "application/vnd.datalox.provider-release.config.v1+json"
PROVIDER_RELEASE_PROFILE_MEDIA_TYPE = "application/vnd.datalox.provider-release.profile.v1.tar"

# Provider Release v1 is a bounded artifact format. These limits are part of the
# loader contract and apply before untrusted content is allocated or extracted.
PROVIDER_RELEASE_MAX_JSON_BYTES = 8 * 1024 * 1024
PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES = 512 * 1024 * 1024
PROVIDER_RELEASE_MAX_TAR_MEMBERS = 20_000
PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES = 128 * 1024 * 1024
PROVIDER_RELEASE_MAX_EXTRACTED_BYTES = 512 * 1024 * 1024
PROVIDER_RELEASE_MAX_PATH_BYTES = 1024
PROVIDER_RELEASE_MAX_PATH_DEPTH = 32

_DISTRIBUTION_ORDER = {"public": 0, "restricted": 1, "private": 2}
_BEHAVIORS = ("success", "failure", "duplicate", "readback", "async", "pagination")
_CONFIG_FIELDS = frozenset(
    {
        "schema_version",
        "provider_id",
        "release_version",
        "bundle_version",
        "authorities",
        "distribution_label",
        "operation_claims_sha256",
        "evidence_sources",
        "evidence_sources_sha256",
        "operations",
        "operation_contract_sha256",
        "provider_invariants",
        "provider_invariants_sha256",
        "receipt_predicates",
        "receipt_predicates_sha256",
        "operation_coverage",
        "profiles",
    }
)
_PROFILE_FIELDS = frozenset(
    {
        "profile_id",
        "reset_profile_id",
        "layer",
        "provider_runtime_sha256",
        "provider_admission_sha256",
        "operation_claims_sha256",
        "distribution_label",
    }
)
_DESCRIPTOR_FIELDS = frozenset({"mediaType", "digest", "size"})


@dataclass(frozen=True)
class ProviderReleaseProfileInput:
    profile_id: str
    bundle_dir: Path
    admission_path: Path


@dataclass(frozen=True)
class ProviderReleaseProfile:
    profile_id: str
    reset_profile_id: str
    layer: dict[str, Any]
    provider_runtime_sha256: str
    provider_admission_sha256: str
    operation_claims_sha256: str
    distribution_label: str


@dataclass(frozen=True)
class LoadedProviderRelease:
    root: Path
    manifest_descriptor: dict[str, Any]
    manifest: dict[str, Any]
    config: dict[str, Any]
    profiles: tuple[ProviderReleaseProfile, ...]

    @property
    def provider_id(self) -> str:
        return self.config["provider_id"]

    @property
    def release_version(self) -> str:
        return self.config["release_version"]


@dataclass(frozen=True)
class MaterializedProviderProfile:
    root: Path
    bundle_dir: Path
    admission_path: Path
    release: LoadedProviderRelease
    profile: ProviderReleaseProfile


@dataclass(frozen=True)
class _ValidatedProfileInput:
    profile_id: str
    bundle: LoadedProviderRuntimeBundle
    admission_path: Path
    admission: dict[str, Any]
    admission_sha256: str
    evidence_sources: tuple[dict[str, Any], ...]
    operations: tuple[dict[str, Any], ...]
    invariants: tuple[dict[str, Any], ...]
    receipts: tuple[dict[str, Any], ...]
    distribution_label: str


def build_provider_release(
    *,
    profiles: tuple[ProviderReleaseProfileInput, ...],
    release_version: str,
    output_dir: Path,
) -> LoadedProviderRelease:
    """Build one deterministic task-free provider release as an OCI image layout."""

    if not profiles:
        _fail("provider_release_profiles_invalid", "At least one provider profile is required.")
    release_version = _identifier(release_version, field="release_version")
    profile_ids = [_identifier(item.profile_id, field="profile_id") for item in profiles]
    if len(set(profile_ids)) != len(profile_ids):
        _fail("provider_release_profile_duplicate", "Provider release profile ids must be unique.")

    validated = tuple(
        sorted(
            (_validate_profile_input(item) for item in profiles),
            key=lambda item: item.profile_id,
        )
    )
    _validate_profile_compatibility(validated)
    first = validated[0]
    destination, parent = _canonical_output_destination(output_dir)
    if destination.exists() or destination.is_symlink():
        _fail(
            "provider_release_output_exists",
            "Provider release output directory already exists.",
            path=str(destination),
        )
    scratch = Path(tempfile.mkdtemp(prefix=f".{destination.name}.build-", dir=parent))
    staged = scratch / "layout"
    staged.mkdir(mode=0o700)
    (staged / "blobs" / "sha256").mkdir(parents=True, mode=0o700)
    try:
        layers: list[dict[str, Any]] = []
        profile_configs: list[dict[str, Any]] = []
        for index, profile in enumerate(validated):
            layer_path = scratch / f"profile-{index}.tar"
            layer = _build_profile_layer(profile, layer_path)
            _install_blob_file(staged, layer, layer_path)
            layers.append(layer)
            profile_configs.append(
                {
                    "profile_id": profile.profile_id,
                    "reset_profile_id": "default",
                    "layer": deepcopy(layer),
                    "provider_runtime_sha256": _sha256_file(
                        profile.bundle.root / "provider-runtime.json"
                    ),
                    "provider_admission_sha256": profile.admission_sha256,
                    "operation_claims_sha256": profile.admission["operation_claims_sha256"],
                    "distribution_label": profile.distribution_label,
                }
            )

        evidence_sources = _release_evidence_sources(first.evidence_sources)
        operations = deepcopy(list(first.operations))
        invariants = deepcopy(list(first.invariants))
        receipts = deepcopy(list(first.receipts))
        config = {
            "schema_version": PROVIDER_RELEASE_SCHEMA_VERSION,
            "provider_id": first.bundle.manifest.provider_id,
            "release_version": release_version,
            "bundle_version": first.bundle.manifest.bundle_version,
            "authorities": list(first.bundle.manifest.authorities),
            "distribution_label": max(
                (item.distribution_label for item in validated),
                key=_DISTRIBUTION_ORDER.__getitem__,
            ),
            "operation_claims_sha256": first.admission["operation_claims_sha256"],
            "evidence_sources": evidence_sources,
            "evidence_sources_sha256": canonical_json_sha256(evidence_sources),
            "operations": operations,
            "operation_contract_sha256": canonical_json_sha256(operations),
            "provider_invariants": invariants,
            "provider_invariants_sha256": canonical_json_sha256(invariants),
            "receipt_predicates": receipts,
            "receipt_predicates_sha256": canonical_json_sha256(receipts),
            "operation_coverage": _operation_coverage(operations),
            "profiles": profile_configs,
        }
        _validate_release_config(config, layers=layers)
        config_payload = canonical_json_bytes(config)
        config_descriptor = _descriptor(PROVIDER_RELEASE_CONFIG_MEDIA_TYPE, config_payload)
        manifest = {
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST_MEDIA_TYPE,
            "artifactType": PROVIDER_RELEASE_ARTIFACT_TYPE,
            "config": config_descriptor,
            "layers": layers,
        }
        manifest_payload = canonical_json_bytes(manifest)
        manifest_descriptor = {
            **_descriptor(OCI_MANIFEST_MEDIA_TYPE, manifest_payload),
            "artifactType": PROVIDER_RELEASE_ARTIFACT_TYPE,
            "annotations": {
                "dev.datalox.provider.id": first.bundle.manifest.provider_id,
                "org.opencontainers.image.ref.name": release_version,
            },
        }
        index = {
            "schemaVersion": 2,
            "mediaType": OCI_INDEX_MEDIA_TYPE,
            "manifests": [manifest_descriptor],
        }
        _write_bytes(
            staged / "oci-layout",
            canonical_json_bytes({"imageLayoutVersion": OCI_IMAGE_LAYOUT_VERSION}),
            mode=0o444,
        )
        _write_bytes(staged / "index.json", canonical_json_bytes(index), mode=0o444)
        _write_blob(staged, config_descriptor["digest"], config_payload)
        _write_blob(staged, manifest_descriptor["digest"], manifest_payload)
        load_provider_release(staged)
        _publish_validated_directory(
            staged=staged,
            destination=destination,
            validity_marker="index.json",
            exists_code="provider_release_output_exists",
        )
    except BaseException:
        raise
    finally:
        shutil.rmtree(scratch, ignore_errors=True)
    return load_provider_release(destination)


def load_provider_release(layout_dir: Path) -> LoadedProviderRelease:
    """Strictly load and digest-check a Datalox provider release OCI layout."""

    root = _resolve_directory(layout_dir, code="provider_release_unreadable")
    _reject_links_and_special_files(root)
    layout = _load_json_object(root / "oci-layout", code="provider_release_layout_invalid")
    if layout.get("imageLayoutVersion") != OCI_IMAGE_LAYOUT_VERSION:
        _fail("provider_release_layout_invalid", "Unsupported OCI image layout version.")
    index = _load_json_object(root / "index.json", code="provider_release_index_invalid")
    if (
        set(index) != {"schemaVersion", "mediaType", "manifests"}
        or index.get("schemaVersion") != 2
        or index.get("mediaType") != OCI_INDEX_MEDIA_TYPE
        or not isinstance(index.get("manifests"), list)
        or len(index["manifests"]) != 1
    ):
        _fail("provider_release_index_invalid", "OCI index does not match the release contract.")
    manifest_descriptor = _manifest_descriptor(index["manifests"][0])
    manifest = _load_descriptor_json(root, manifest_descriptor, name="manifest")
    if (
        set(manifest) != {"schemaVersion", "mediaType", "artifactType", "config", "layers"}
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or manifest.get("artifactType") != PROVIDER_RELEASE_ARTIFACT_TYPE
    ):
        _fail(
            "provider_release_manifest_invalid",
            "OCI manifest does not match the provider release artifact contract.",
        )
    config_descriptor = _plain_descriptor(
        manifest["config"],
        expected_media_type=PROVIDER_RELEASE_CONFIG_MEDIA_TYPE,
        code="provider_release_config_descriptor_invalid",
    )
    raw_layers = manifest["layers"]
    if not isinstance(raw_layers, list) or not raw_layers:
        _fail("provider_release_manifest_invalid", "Provider release layers must be non-empty.")
    layers = [
        _plain_descriptor(
            item,
            expected_media_type=PROVIDER_RELEASE_PROFILE_MEDIA_TYPE,
            code="provider_release_layer_descriptor_invalid",
        )
        for item in raw_layers
    ]
    config = _load_descriptor_json(root, config_descriptor, name="config")
    profiles = _validate_release_config(config, layers=layers)
    annotations = manifest_descriptor["annotations"]
    if (
        annotations["dev.datalox.provider.id"] != config["provider_id"]
        or annotations["org.opencontainers.image.ref.name"] != config["release_version"]
    ):
        _fail(
            "provider_release_index_binding_invalid",
            "OCI index annotations do not match the provider release config.",
        )
    loaded = LoadedProviderRelease(
        root=root,
        manifest_descriptor=deepcopy(manifest_descriptor),
        manifest=manifest,
        config=config,
        profiles=profiles,
    )
    _validate_embedded_profiles(loaded)
    return loaded


def materialize_provider_release_profile(
    *,
    release: Path | LoadedProviderRelease,
    profile_id: str,
    output_dir: Path,
) -> MaterializedProviderProfile:
    """Safely materialize one immutable reset profile and revalidate its bindings."""

    loaded = (
        load_provider_release(release)
        if isinstance(release, Path)
        else load_provider_release_from_descriptor(
            root=release.root,
            manifest_descriptor=release.manifest_descriptor,
        )
    )
    profile_id = _identifier(profile_id, field="profile_id")
    profile = next((item for item in loaded.profiles if item.profile_id == profile_id), None)
    if profile is None:
        _fail(
            "provider_release_profile_unknown",
            f"Provider release has no profile {profile_id!r}.",
            profile_id=profile_id,
        )
    destination, parent = _canonical_output_destination(output_dir)
    if destination.exists() or destination.is_symlink():
        _fail(
            "provider_release_materialize_output_exists",
            "Provider profile materialization output already exists.",
            path=str(destination),
        )
    layer_path = _verified_descriptor_blob_path(loaded.root, profile.layer, name="profile layer")
    temporary = Path(tempfile.mkdtemp(prefix=f".{destination.name}.extract-", dir=parent))
    try:
        _extract_profile_layer_path(layer_path, temporary)
        _validate_materialized_profile(loaded, profile, temporary)
        _publish_validated_directory(
            staged=temporary,
            destination=destination,
            validity_marker="provider-admission.json",
            exists_code="provider_release_materialize_output_exists",
        )
    finally:
        shutil.rmtree(temporary, ignore_errors=True)
    root = destination.resolve(strict=True)
    return MaterializedProviderProfile(
        root=root,
        bundle_dir=root / "runtime",
        admission_path=root / "provider-admission.json",
        release=loaded,
        profile=profile,
    )


def load_provider_release_from_descriptor(
    *, root: Path, manifest_descriptor: Mapping[str, Any]
) -> LoadedProviderRelease:
    """Load a release from a trusted content store descriptor without a mutable index."""

    store = _resolve_directory(root, code="provider_release_unreadable")
    descriptor = _manifest_descriptor(manifest_descriptor)
    manifest = _load_descriptor_json(store, descriptor, name="manifest")
    if (
        set(manifest) != {"schemaVersion", "mediaType", "artifactType", "config", "layers"}
        or manifest.get("schemaVersion") != 2
        or manifest.get("mediaType") != OCI_MANIFEST_MEDIA_TYPE
        or manifest.get("artifactType") != PROVIDER_RELEASE_ARTIFACT_TYPE
    ):
        _fail("provider_release_manifest_invalid", "Provider release manifest is invalid.")
    config_descriptor = _plain_descriptor(
        manifest["config"],
        expected_media_type=PROVIDER_RELEASE_CONFIG_MEDIA_TYPE,
        code="provider_release_config_descriptor_invalid",
    )
    layers = [
        _plain_descriptor(
            item,
            expected_media_type=PROVIDER_RELEASE_PROFILE_MEDIA_TYPE,
            code="provider_release_layer_descriptor_invalid",
        )
        for item in manifest.get("layers", [])
    ]
    if not layers:
        _fail("provider_release_manifest_invalid", "Provider release layers must be non-empty.")
    config = _load_descriptor_json(store, config_descriptor, name="config")
    profiles = _validate_release_config(config, layers=layers)
    annotations = descriptor["annotations"]
    if (
        annotations["dev.datalox.provider.id"] != config["provider_id"]
        or annotations["org.opencontainers.image.ref.name"] != config["release_version"]
    ):
        _fail("provider_release_index_binding_invalid", "Provider release reference is invalid.")
    loaded = LoadedProviderRelease(
        root=store,
        manifest_descriptor=deepcopy(descriptor),
        manifest=manifest,
        config=config,
        profiles=profiles,
    )
    _validate_embedded_profiles(loaded)
    return loaded


def _validate_profile_input(item: ProviderReleaseProfileInput) -> _ValidatedProfileInput:
    profile_id = _identifier(item.profile_id, field="profile_id")
    bundle = load_provider_runtime_bundle(item.bundle_dir)
    admission_path = _resolve_regular_file(
        item.admission_path, code="provider_release_admission_unreadable"
    )
    admission = load_provider_admission(admission_path)
    runtime_sha256 = _sha256_file(bundle.root / "provider-runtime.json")
    if (
        admission["provider_runtime_sha256"] != runtime_sha256
        or admission["provider_id"] != bundle.manifest.provider_id
        or admission["bundle_version"] != bundle.manifest.bundle_version
    ):
        _fail(
            "provider_release_admission_binding_invalid",
            f"Admission does not bind profile {profile_id!r} to its provider runtime.",
            profile_id=profile_id,
        )
    reset_profiles = admission["reset_profiles"]
    if len(reset_profiles) != 1 or reset_profiles[0]["profile_id"] != "default":
        _fail(
            "provider_release_reset_profile_invalid",
            "Provider-runtime-v2 admissions must bind exactly one default reset profile.",
        )
    evidence_sources = tuple(
        sorted(
            (deepcopy(source) for source in admission["evidence_sources"]),
            key=lambda source: source["evidence_id"],
        )
    )
    operations = _operation_contract(admission)
    invariants = tuple(
        sorted(
            (deepcopy(predicate) for predicate in admission["provider_invariants"]),
            key=lambda predicate: predicate["predicate_id"],
        )
    )
    receipts = tuple(
        sorted(
            (deepcopy(predicate) for predicate in admission["receipt_predicates"]),
            key=lambda predicate: predicate["predicate_id"],
        )
    )
    labels = [operation["rights"]["distribution_label"] for operation in admission["operations"]]
    distribution = max(labels, key=_DISTRIBUTION_ORDER.__getitem__)
    return _ValidatedProfileInput(
        profile_id=profile_id,
        bundle=bundle,
        admission_path=admission_path,
        admission=admission,
        admission_sha256=_sha256_file(admission_path),
        evidence_sources=evidence_sources,
        operations=operations,
        invariants=invariants,
        receipts=receipts,
        distribution_label=distribution,
    )


def _validate_profile_compatibility(profiles: tuple[_ValidatedProfileInput, ...]) -> None:
    first = profiles[0]
    if isinstance(first.bundle.manifest.behavior, GateConfigBehaviorSpec) and len(profiles) != 1:
        _fail(
            "provider_release_gate_config_profiles_unsupported",
            "gate_config_v1 provider releases support exactly one reset profile.",
        )
    expected = (
        first.bundle.manifest.provider_id,
        first.bundle.manifest.bundle_version,
        first.bundle.manifest.authorities,
        first.admission["operation_claims_sha256"],
        first.evidence_sources,
        first.operations,
        first.invariants,
        first.receipts,
    )
    behavior_signature = _behavior_signature(first.bundle)
    for profile in profiles[1:]:
        actual = (
            profile.bundle.manifest.provider_id,
            profile.bundle.manifest.bundle_version,
            profile.bundle.manifest.authorities,
            profile.admission["operation_claims_sha256"],
            profile.evidence_sources,
            profile.operations,
            profile.invariants,
            profile.receipts,
        )
        if actual != expected:
            _fail(
                "provider_release_profile_contract_mismatch",
                "Provider release profiles do not share one provider contract.",
                profile_id=profile.profile_id,
            )
        if _behavior_signature(profile.bundle) != behavior_signature:
            _fail(
                "provider_release_profile_behavior_mismatch",
                "World reset profiles must share exact behavior, tools, roles, and identity assets.",
                profile_id=profile.profile_id,
            )


def _behavior_signature(bundle: LoadedProviderRuntimeBundle) -> str:
    behavior = bundle.manifest.behavior
    if isinstance(behavior, GateConfigBehaviorSpec):
        return canonical_json_sha256(
            {
                "protocol": behavior.protocol,
                "config_path": behavior.config_path,
                "content_hashes": bundle.manifest.content_hashes,
            }
        )
    if not isinstance(behavior, WorldV1BehaviorSpec):
        raise TypeError("unsupported provider behavior")
    excluded = {behavior.seed_path, bundle.manifest.source_path}
    return canonical_json_sha256(
        {
            "protocol": behavior.protocol,
            "implementation": behavior.implementation,
            "roles_path": behavior.roles_path,
            "tools_path": behavior.tools_path,
            "identity_path": behavior.identity_path,
            "default_actor_role": behavior.default_actor_role,
            "required_runtime_capabilities": list(behavior.required_runtime_capabilities),
            "content_hashes": {
                path: digest
                for path, digest in sorted(bundle.manifest.content_hashes.items())
                if path not in excluded
            },
        }
    )


def _operation_contract(admission: Mapping[str, Any]) -> tuple[dict[str, Any], ...]:
    return tuple(
        sorted(
            (deepcopy(operation) for operation in admission["operations"]),
            key=lambda operation: operation["operation_id"],
        )
    )


def _release_evidence_sources(
    evidence_sources: tuple[dict[str, Any], ...] | list[dict[str, Any]],
) -> list[dict[str, Any]]:
    return [
        {
            **{key: deepcopy(value) for key, value in source.items() if key != "artifact_ref"},
            "origin_artifact_ref": source["artifact_ref"],
        }
        for source in evidence_sources
    ]


def _operation_coverage(operation_contract: list[dict[str, Any]]) -> dict[str, Any]:
    reads = sum(operation["mutability"] == "read" for operation in operation_contract)
    writes = sum(operation["mutability"] == "write" for operation in operation_contract)
    return {
        "total": len(operation_contract),
        "read": reads,
        "write": writes,
        "behaviors": {
            behavior: sum(
                behavior in operation["covered_behaviors"] for operation in operation_contract
            )
            for behavior in _BEHAVIORS
        },
    }


def _build_profile_layer(profile: _ValidatedProfileInput, output_path: Path) -> dict[str, Any]:
    entries: dict[str, tuple[bool, Path | None]] = {"runtime": (True, None)}
    for path in sorted(profile.bundle.root.rglob("*")):
        if path.is_symlink():
            _fail("provider_release_symlink_forbidden", "Provider profile contains a symlink.")
        relative = path.relative_to(profile.bundle.root).as_posix()
        name = f"runtime/{relative}"
        if path.is_dir():
            entries[name] = (True, None)
        elif path.is_file():
            entries[name] = (False, path)
        else:
            _fail(
                "provider_release_special_file_forbidden",
                "Provider profile contains a non-regular filesystem entry.",
                path=str(path),
            )
    entries["provider-admission.json"] = (False, profile.admission_path)
    if len(entries) > PROVIDER_RELEASE_MAX_TAR_MEMBERS:
        _fail(
            "provider_release_member_limit_exceeded",
            "Provider profile has too many archive members.",
            actual_members=len(entries),
            max_members=PROVIDER_RELEASE_MAX_TAR_MEMBERS,
        )
    total_bytes = 0
    for name, (is_directory, source) in entries.items():
        _safe_tar_name(name)
        if is_directory:
            continue
        if not isinstance(source, Path):
            raise TypeError("regular profile entries require a source path")
        try:
            size = source.stat().st_size
        except OSError as exc:
            _fail("provider_release_input_unreadable", f"Could not stat profile input: {exc}.")
        if size > PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES:
            _fail(
                "provider_release_file_limit_exceeded",
                "Provider profile file exceeds its v1 size limit.",
                path=name,
                actual_size=size,
                max_bytes=PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES,
            )
        total_bytes += size
        if total_bytes > PROVIDER_RELEASE_MAX_EXTRACTED_BYTES:
            _fail(
                "provider_release_extracted_limit_exceeded",
                "Provider profile exceeds its total extracted-byte limit.",
                actual_size=total_bytes,
                max_bytes=PROVIDER_RELEASE_MAX_EXTRACTED_BYTES,
            )
    output_path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with output_path.open("xb") as output:
            archive = tarfile.open(fileobj=output, mode="w", format=tarfile.GNU_FORMAT)
            try:
                for name in sorted(entries):
                    is_dir, source = entries[name]
                    info = tarfile.TarInfo(f"{name}/" if is_dir else name)
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    if is_dir:
                        info.type = tarfile.DIRTYPE
                        info.mode = 0o755
                        archive.addfile(info)
                        continue
                    info.mode = 0o644
                    if not isinstance(source, Path):
                        raise TypeError("regular profile entries require a source path")
                    info.size = source.stat().st_size
                    with source.open("rb") as source_handle:
                        archive.addfile(info, source_handle)
            finally:
                archive.close()
    except (OSError, tarfile.TarError, ValueError) as exc:
        _fail("provider_release_layer_build_failed", f"Could not build provider layer: {exc}.")
    return _descriptor_file(PROVIDER_RELEASE_PROFILE_MEDIA_TYPE, output_path)


def _validate_release_config(
    config: Any, *, layers: list[dict[str, Any]]
) -> tuple[ProviderReleaseProfile, ...]:
    if not isinstance(config, dict) or set(config) != _CONFIG_FIELDS:
        _fail("provider_release_config_invalid", "Provider release config fields are invalid.")
    if config["schema_version"] != PROVIDER_RELEASE_SCHEMA_VERSION:
        _fail("provider_release_schema_unsupported", "Unsupported provider release schema.")
    _identifier(config["provider_id"], field="provider_id")
    _identifier(config["release_version"], field="release_version")
    if not isinstance(config["bundle_version"], str) or not config["bundle_version"]:
        _fail("provider_release_config_invalid", "bundle_version is invalid.")
    authorities = config["authorities"]
    if (
        not isinstance(authorities, list)
        or not authorities
        or any(not isinstance(item, str) or not item for item in authorities)
        or len(set(authorities)) != len(authorities)
    ):
        _fail("provider_release_config_invalid", "authorities are invalid.")
    _distribution_label(config["distribution_label"])
    _sha256(config["operation_claims_sha256"], field="operation_claims_sha256")
    _sha256(config["operation_contract_sha256"], field="operation_contract_sha256")
    evidence_sources = _evidence_list(config["evidence_sources"])
    if canonical_json_sha256(list(evidence_sources)) != config["evidence_sources_sha256"]:
        _fail("provider_release_config_invalid", "Evidence metadata digest is inconsistent.")
    operations = _operation_list(
        config["operations"], evidence=evidence_sources, authorities=frozenset(authorities)
    )
    if canonical_json_sha256(list(operations)) != config["operation_contract_sha256"]:
        _fail("provider_release_config_invalid", "Operation contract digest is inconsistent.")
    invariants = _predicate_list(
        config["provider_invariants"], field="provider_invariants", allow_response=False
    )
    receipts = _predicate_list(
        config["receipt_predicates"], field="receipt_predicates", allow_response=True
    )
    if canonical_json_sha256(list(invariants)) != config["provider_invariants_sha256"]:
        _fail("provider_release_config_invalid", "Provider invariant digest is inconsistent.")
    if canonical_json_sha256(list(receipts)) != config["receipt_predicates_sha256"]:
        _fail("provider_release_config_invalid", "Receipt predicate digest is inconsistent.")
    coverage = config["operation_coverage"]
    if not isinstance(coverage, dict) or set(coverage) != {"total", "read", "write", "behaviors"}:
        _fail("provider_release_config_invalid", "Operation coverage is invalid.")
    for field in ("total", "read", "write"):
        _nonnegative_integer(coverage[field], field=field)
    if coverage["total"] < 1 or coverage["read"] + coverage["write"] != coverage["total"]:
        _fail("provider_release_config_invalid", "Operation coverage counts are inconsistent.")
    behavior_counts = coverage["behaviors"]
    if not isinstance(behavior_counts, dict) or set(behavior_counts) != set(_BEHAVIORS):
        _fail("provider_release_config_invalid", "Behavior coverage is invalid.")
    for behavior, count in behavior_counts.items():
        _nonnegative_integer(count, field=behavior)
        if count > coverage["total"]:
            _fail("provider_release_config_invalid", "Behavior coverage exceeds operations.")
    if coverage != _operation_coverage(list(operations)):
        _fail("provider_release_config_invalid", "Operation coverage summary is inconsistent.")
    raw_profiles = config["profiles"]
    if not isinstance(raw_profiles, list) or not raw_profiles or len(raw_profiles) != len(layers):
        _fail("provider_release_config_invalid", "Provider release profiles are invalid.")
    profiles: list[ProviderReleaseProfile] = []
    profile_ids: set[str] = set()
    for index, (raw, layer) in enumerate(zip(raw_profiles, layers, strict=True)):
        if not isinstance(raw, dict) or set(raw) != _PROFILE_FIELDS:
            _fail("provider_release_config_invalid", f"Profile {index} fields are invalid.")
        profile_id = _identifier(raw["profile_id"], field="profile_id")
        if profile_id in profile_ids:
            _fail("provider_release_profile_duplicate", "Provider profile ids must be unique.")
        profile_ids.add(profile_id)
        if raw["reset_profile_id"] != "default" or raw["layer"] != layer:
            _fail("provider_release_profile_binding_invalid", "Profile layer binding is invalid.")
        for field in (
            "provider_runtime_sha256",
            "provider_admission_sha256",
            "operation_claims_sha256",
        ):
            _sha256(raw[field], field=field)
        if raw["operation_claims_sha256"] != config["operation_claims_sha256"]:
            _fail(
                "provider_release_profile_binding_invalid",
                "Profile operation claims do not match the release provenance context.",
            )
        label = _distribution_label(raw["distribution_label"])
        profiles.append(
            ProviderReleaseProfile(
                profile_id=profile_id,
                reset_profile_id="default",
                layer=deepcopy(layer),
                provider_runtime_sha256=raw["provider_runtime_sha256"],
                provider_admission_sha256=raw["provider_admission_sha256"],
                operation_claims_sha256=raw["operation_claims_sha256"],
                distribution_label=label,
            )
        )
    if [item.profile_id for item in profiles] != sorted(profile_ids):
        _fail("provider_release_config_invalid", "Provider profiles must be sorted by profile_id.")
    rights_labels = [item.distribution_label for item in profiles]
    rights_labels.extend(source["distribution_label"] for source in evidence_sources)
    rights_labels.extend(operation["rights"]["distribution_label"] for operation in operations)
    derived_label = max(rights_labels, key=_DISTRIBUTION_ORDER.__getitem__)
    if config["distribution_label"] != derived_label:
        _fail("provider_release_config_invalid", "Release distribution label is inconsistent.")
    return tuple(profiles)


def _extract_profile_layer(payload: bytes, destination: Path) -> None:
    if len(payload) > PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES:
        _fail(
            "provider_release_size_limit_exceeded",
            "Provider profile layer exceeds its v1 size limit.",
            actual_size=len(payload),
            max_bytes=PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES,
        )
    _extract_profile_archive(io.BytesIO(payload), destination)


def _extract_profile_layer_path(path: Path, destination: Path) -> None:
    size = path.stat().st_size
    if size > PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES:
        _fail(
            "provider_release_size_limit_exceeded",
            "Provider profile layer exceeds its v1 size limit.",
            actual_size=size,
            max_bytes=PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES,
        )
    try:
        with path.open("rb") as handle:
            _extract_profile_archive(handle, destination)
    except ProviderRuntimeError:
        raise
    except OSError as exc:
        _fail("provider_release_layer_invalid", f"Could not open provider layer: {exc}.")


def _extract_profile_archive(source_stream: BinaryIO, destination: Path) -> None:
    seen: set[str] = set()
    extracted_bytes = 0
    member_count = 0
    try:
        with tarfile.open(fileobj=source_stream, mode="r|") as archive:
            for member in archive:
                member_count += 1
                if member_count > PROVIDER_RELEASE_MAX_TAR_MEMBERS:
                    _fail(
                        "provider_release_member_limit_exceeded",
                        "Provider profile layer has too many archive members.",
                        max_members=PROVIDER_RELEASE_MAX_TAR_MEMBERS,
                    )
                name = _safe_tar_name(member.name)
                if name in seen:
                    _fail("provider_release_layer_duplicate", "Provider layer has duplicate paths.")
                seen.add(name)
                is_directory = member.isdir()
                if not (is_directory or member.isreg()):
                    _fail(
                        "provider_release_layer_entry_forbidden",
                        "Provider layer may contain only directories and regular files.",
                        path=name,
                    )
                expected_mode = 0o755 if is_directory else 0o644
                if (
                    member.mtime != 0
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.mode != expected_mode
                    or member.pax_headers
                ):
                    _fail(
                        "provider_release_layer_metadata_invalid",
                        "Provider layer metadata is not normalized.",
                        path=name,
                    )
                if name != "provider-admission.json" and not (
                    name == "runtime" or name.startswith("runtime/")
                ):
                    _fail(
                        "provider_release_layer_entry_forbidden",
                        "Provider layer contains an unexpected path.",
                        path=name,
                    )
                if member.size > PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES:
                    _fail(
                        "provider_release_file_limit_exceeded",
                        "Provider profile file exceeds its v1 size limit.",
                        path=name,
                        declared_size=member.size,
                        max_bytes=PROVIDER_RELEASE_MAX_PROFILE_FILE_BYTES,
                    )
                if not is_directory:
                    extracted_bytes += member.size
                    if extracted_bytes > PROVIDER_RELEASE_MAX_EXTRACTED_BYTES:
                        _fail(
                            "provider_release_extracted_limit_exceeded",
                            "Provider profile exceeds its total extracted-byte limit.",
                            actual_size=extracted_bytes,
                            max_bytes=PROVIDER_RELEASE_MAX_EXTRACTED_BYTES,
                        )
                target = destination.joinpath(*PurePosixPath(name).parts)
                if is_directory:
                    target.mkdir(parents=True, exist_ok=False)
                    continue
                target.parent.mkdir(parents=True, exist_ok=True)
                source = archive.extractfile(member)
                if source is None:
                    _fail("provider_release_layer_invalid", "Could not read provider layer entry.")
                with target.open("xb") as handle:
                    remaining = member.size
                    while remaining:
                        chunk = source.read(min(1024 * 1024, remaining))
                        if not chunk:
                            _fail(
                                "provider_release_layer_invalid",
                                "Provider layer entry ended before its declared size.",
                                path=name,
                            )
                        handle.write(chunk)
                        remaining -= len(chunk)
    except ProviderRuntimeError:
        raise
    except (OSError, tarfile.TarError, UnicodeError) as exc:
        _fail("provider_release_layer_invalid", f"Could not extract provider layer: {exc}.")
    if "runtime" not in seen or "provider-admission.json" not in seen:
        _fail("provider_release_layer_invalid", "Provider layer is incomplete.")


def _validate_materialized_profile(
    release: LoadedProviderRelease, profile: ProviderReleaseProfile, root: Path
) -> None:
    if set(path.name for path in root.iterdir()) != {"runtime", "provider-admission.json"}:
        _fail("provider_release_layer_invalid", "Materialized provider layer has extra assets.")
    bundle = load_provider_runtime_bundle(root / "runtime")
    admission_path = root / "provider-admission.json"
    admission = load_provider_admission(admission_path)
    if (
        bundle.manifest.provider_id != release.provider_id
        or bundle.manifest.bundle_version != release.config["bundle_version"]
        or list(bundle.manifest.authorities) != release.config["authorities"]
        or _sha256_file(bundle.root / "provider-runtime.json") != profile.provider_runtime_sha256
        or _sha256_file(admission_path) != profile.provider_admission_sha256
        or admission["provider_runtime_sha256"] != profile.provider_runtime_sha256
        or admission["operation_claims_sha256"] != profile.operation_claims_sha256
        or admission["operation_claims_sha256"] != release.config["operation_claims_sha256"]
        or admission["provider_id"] != release.provider_id
        or admission["bundle_version"] != release.config["bundle_version"]
    ):
        _fail(
            "provider_release_materialized_binding_invalid",
            "Materialized provider assets do not match the release config.",
            profile_id=profile.profile_id,
        )
    evidence_sources = _release_evidence_sources(
        sorted(admission["evidence_sources"], key=lambda source: source["evidence_id"])
    )
    if evidence_sources != release.config["evidence_sources"]:
        _fail(
            "provider_release_materialized_contract_invalid",
            "Materialized provider evidence metadata does not match the release.",
        )
    operations = list(_operation_contract(admission))
    if operations != release.config["operations"]:
        _fail(
            "provider_release_materialized_contract_invalid",
            "Materialized provider operation contract does not match the release.",
        )
    if (
        sorted(admission["provider_invariants"], key=lambda predicate: predicate["predicate_id"])
        != release.config["provider_invariants"]
    ):
        _fail(
            "provider_release_materialized_contract_invalid",
            "Materialized provider invariants do not match the release.",
        )
    if (
        sorted(admission["receipt_predicates"], key=lambda predicate: predicate["predicate_id"])
        != release.config["receipt_predicates"]
    ):
        _fail(
            "provider_release_materialized_contract_invalid",
            "Materialized receipt predicates do not match the release.",
        )
    labels = [operation["rights"]["distribution_label"] for operation in admission["operations"]]
    if max(labels, key=_DISTRIBUTION_ORDER.__getitem__) != profile.distribution_label:
        _fail(
            "provider_release_materialized_rights_invalid",
            "Materialized provider rights do not match the release.",
        )


def _validate_embedded_profiles(release: LoadedProviderRelease) -> None:
    for profile in release.profiles:
        layer_path = _verified_descriptor_blob_path(
            release.root, profile.layer, name="profile layer"
        )
        with tempfile.TemporaryDirectory(prefix="datalox-provider-release-validate-") as temporary:
            root = Path(temporary)
            _extract_profile_layer_path(layer_path, root)
            _validate_materialized_profile(release, profile, root)


def _manifest_descriptor(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != {
        "mediaType",
        "digest",
        "size",
        "artifactType",
        "annotations",
    }:
        _fail("provider_release_manifest_descriptor_invalid", "Manifest descriptor is invalid.")
    descriptor = _plain_descriptor(
        {field: value[field] for field in _DESCRIPTOR_FIELDS},
        expected_media_type=OCI_MANIFEST_MEDIA_TYPE,
        code="provider_release_manifest_descriptor_invalid",
    )
    annotations = value["annotations"]
    if (
        value["artifactType"] != PROVIDER_RELEASE_ARTIFACT_TYPE
        or not isinstance(annotations, dict)
        or set(annotations) != {"dev.datalox.provider.id", "org.opencontainers.image.ref.name"}
    ):
        _fail("provider_release_manifest_descriptor_invalid", "Manifest annotations are invalid.")
    provider_id = _identifier(annotations["dev.datalox.provider.id"], field="provider_id")
    release_version = _identifier(
        annotations["org.opencontainers.image.ref.name"], field="release_version"
    )
    return {
        **descriptor,
        "artifactType": PROVIDER_RELEASE_ARTIFACT_TYPE,
        "annotations": {
            "dev.datalox.provider.id": provider_id,
            "org.opencontainers.image.ref.name": release_version,
        },
    }


def _plain_descriptor(value: Any, *, expected_media_type: str, code: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != _DESCRIPTOR_FIELDS:
        _fail(code, "Content descriptor fields are invalid.")
    if value["mediaType"] != expected_media_type:
        _fail(code, "Content descriptor media type is invalid.")
    digest = _sha256(value["digest"], field="digest")
    size = value["size"]
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        _fail(code, "Content descriptor size is invalid.")
    limit = _media_type_size_limit(expected_media_type)
    if size > limit:
        _fail(
            "provider_release_size_limit_exceeded",
            "Content descriptor exceeds the Provider Release v1 size limit.",
            media_type=expected_media_type,
            declared_size=size,
            max_bytes=limit,
        )
    return {"mediaType": expected_media_type, "digest": digest, "size": size}


def _descriptor(media_type: str, payload: bytes) -> dict[str, Any]:
    limit = _media_type_size_limit(media_type)
    if len(payload) > limit:
        _fail(
            "provider_release_size_limit_exceeded",
            "Provider release content exceeds its v1 size limit.",
            media_type=media_type,
            actual_size=len(payload),
            max_bytes=limit,
        )
    return {"mediaType": media_type, "digest": _sha256_bytes(payload), "size": len(payload)}


def _descriptor_file(media_type: str, path: Path) -> dict[str, Any]:
    limit = _media_type_size_limit(media_type)
    size, digest = _stream_size_and_sha256(path, max_bytes=limit)
    if size < 1:
        _fail("provider_release_size_invalid", "Provider release content must be non-empty.")
    return {"mediaType": media_type, "digest": digest, "size": size}


def _load_descriptor_json(
    root: Path, descriptor: Mapping[str, Any], *, name: str
) -> dict[str, Any]:
    path = _verified_descriptor_blob_path(root, descriptor, name=name)
    return _load_json_object(
        path,
        code="provider_release_json_invalid",
        max_bytes=PROVIDER_RELEASE_MAX_JSON_BYTES,
    )


def _read_descriptor_blob(root: Path, descriptor: Mapping[str, Any], *, name: str) -> bytes:
    path = _verified_descriptor_blob_path(root, descriptor, name=name)
    if descriptor.get("mediaType") == PROVIDER_RELEASE_PROFILE_MEDIA_TYPE:
        _fail(
            "provider_release_stream_required",
            "Profile layers must be consumed through the streaming artifact path.",
        )
    try:
        return path.read_bytes()
    except OSError as exc:
        _fail("provider_release_blob_unreadable", f"Could not read provider release {name}: {exc}.")


def _verified_descriptor_blob_path(root: Path, descriptor: Mapping[str, Any], *, name: str) -> Path:
    digest = _sha256(descriptor.get("digest"), field="digest")
    media_type = descriptor.get("mediaType")
    limit = _media_type_size_limit(media_type)
    declared_size = descriptor.get("size")
    if not isinstance(declared_size, int) or isinstance(declared_size, bool) or declared_size < 1:
        _fail("provider_release_descriptor_invalid", f"Provider release {name} size is invalid.")
    if declared_size > limit:
        _fail(
            "provider_release_size_limit_exceeded",
            f"Provider release {name} exceeds its v1 size limit.",
            declared_size=declared_size,
            max_bytes=limit,
        )
    path = _blob_path(root, digest)
    _reject_path_links(root, path)
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail("provider_release_blob_unreadable", f"Could not resolve {name} blob: {exc}.")
    if not resolved.is_relative_to(root) or not resolved.is_file():
        _fail("provider_release_blob_invalid", f"Provider release {name} blob is invalid.")
    size, actual_digest = _stream_size_and_sha256(resolved, max_bytes=limit)
    if size != declared_size or actual_digest != digest:
        _fail(
            "provider_release_blob_mismatch",
            f"Provider release {name} descriptor does not match its blob.",
            declared_size=declared_size,
            actual_size=size,
        )
    return resolved


def _reject_path_links(root: Path, path: Path) -> None:
    try:
        relative = path.relative_to(root)
    except ValueError:
        _fail("provider_release_blob_invalid", "Provider release blob leaves its root.")
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            _fail(
                "provider_release_symlink_forbidden",
                "Provider release blob path traverses a symbolic link.",
                path=str(current),
            )


def _write_blob(root: Path, digest: str, payload: bytes) -> None:
    path = _blob_path(root, digest)
    path.parent.mkdir(parents=True, exist_ok=True)
    _write_bytes(path, payload, mode=0o444)


def _install_blob_file(root: Path, descriptor: Mapping[str, Any], source: Path) -> None:
    expected_size = descriptor["size"]
    expected_digest = descriptor["digest"]
    actual_size, actual_digest = _stream_size_and_sha256(
        source, max_bytes=_media_type_size_limit(descriptor["mediaType"])
    )
    if actual_size != expected_size or actual_digest != expected_digest:
        _fail("provider_release_blob_mismatch", "Built profile layer changed before install.")
    target = _blob_path(root, expected_digest)
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        existing_size, existing_digest = _stream_size_and_sha256(
            target, max_bytes=_media_type_size_limit(descriptor["mediaType"])
        )
        if existing_size != expected_size or existing_digest != expected_digest:
            _fail("provider_release_blob_mismatch", "Content-addressed blob already differs.")
        source.unlink()
        return
    os.rename(source, target)
    target.chmod(0o444)
    _fsync_file(target)
    _fsync_directory(target.parent)


def _blob_path(root: Path, digest: str) -> Path:
    digest = _sha256(digest, field="digest")
    return root / "blobs" / "sha256" / digest[7:]


def _write_bytes(path: Path, payload: bytes, *, mode: int = 0o444) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    path.chmod(mode)


def _canonical_output_destination(path: Path) -> tuple[Path, Path]:
    if path.name in {"", ".", ".."}:
        _fail("provider_release_output_invalid", "Output directory name is invalid.")
    path.parent.mkdir(parents=True, exist_ok=True)
    parent = path.parent.resolve(strict=True)
    if parent.is_symlink() or not parent.is_dir():
        _fail("provider_release_output_invalid", "Output parent must be a real directory.")
    return parent / path.name, parent


def _publish_validated_directory(
    *,
    staged: Path,
    destination: Path,
    validity_marker: str,
    exists_code: str,
) -> None:
    marker = staged / validity_marker
    if marker.is_symlink() or not marker.is_file():
        _fail("provider_release_publication_invalid", "Validity marker is missing from staging.")
    reserved = False
    marker_published = False
    try:
        try:
            destination.mkdir(mode=0o700)
        except FileExistsError:
            _fail(exists_code, "Output directory already exists.", path=str(destination))
        reserved = True
        destination.chmod(0o700)
        for child in sorted(staged.iterdir(), key=lambda path: path.name):
            if child.name == validity_marker:
                continue
            os.rename(child, destination / child.name)
        _fsync_directory(destination)
        os.rename(marker, destination / validity_marker)
        marker_published = True
        _fsync_directory(destination)
        _fsync_directory(destination.parent)
    except BaseException:
        if reserved and not marker_published:
            shutil.rmtree(destination, ignore_errors=True)
            _fsync_directory(destination.parent)
        raise


def _fsync_file(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _safe_tar_name(value: str) -> str:
    if not value or "\\" in value:
        _fail("provider_release_layer_path_invalid", "Provider layer path is invalid.")
    normalized = value[:-1] if value.endswith("/") else value
    parsed = PurePosixPath(normalized)
    if (
        not normalized
        or parsed.is_absolute()
        or parsed.as_posix() != normalized
        or ".." in parsed.parts
        or "." in parsed.parts
    ):
        _fail("provider_release_layer_path_invalid", "Provider layer path is invalid.")
    encoded_size = len(normalized.encode("utf-8"))
    if encoded_size > PROVIDER_RELEASE_MAX_PATH_BYTES:
        _fail(
            "provider_release_path_limit_exceeded",
            "Provider layer path exceeds its v1 byte limit.",
            path_bytes=encoded_size,
            max_bytes=PROVIDER_RELEASE_MAX_PATH_BYTES,
        )
    if len(parsed.parts) > PROVIDER_RELEASE_MAX_PATH_DEPTH:
        _fail(
            "provider_release_path_depth_exceeded",
            "Provider layer path exceeds its v1 depth limit.",
            path_depth=len(parsed.parts),
            max_depth=PROVIDER_RELEASE_MAX_PATH_DEPTH,
        )
    return normalized


def _reject_links_and_special_files(root: Path) -> None:
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        for name in directories + files:
            path = current_path / name
            if path.is_symlink():
                _fail(
                    "provider_release_symlink_forbidden",
                    "Provider release layouts must not contain symbolic links.",
                    path=str(path),
                )
            if not (path.is_dir() or path.is_file()):
                _fail(
                    "provider_release_special_file_forbidden",
                    "Provider release layouts may contain only directories and regular files.",
                    path=str(path),
                )


def _resolve_directory(path: Path, *, code: str) -> Path:
    if path.is_symlink():
        _fail("provider_release_symlink_forbidden", "Provider release path is a symlink.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(code, f"Could not resolve provider release directory: {exc}.", path=str(path))
    if not resolved.is_dir():
        _fail(code, "Provider release path must be a directory.", path=str(resolved))
    return resolved


def _resolve_regular_file(path: Path, *, code: str) -> Path:
    if path.is_symlink():
        _fail("provider_release_symlink_forbidden", "Provider release input is a symlink.")
    try:
        resolved = path.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        _fail(code, f"Could not resolve provider release input: {exc}.", path=str(path))
    if not resolved.is_file():
        _fail(code, "Provider release input must be a regular file.", path=str(resolved))
    return resolved


def _ensure_output_absent(path: Path, *, code: str) -> None:
    if path.exists() or path.is_symlink():
        _fail(code, "Output path already exists.", path=str(path))


def _load_json_object(
    path: Path, *, code: str, max_bytes: int = PROVIDER_RELEASE_MAX_JSON_BYTES
) -> dict[str, Any]:
    if path.is_symlink():
        _fail("provider_release_symlink_forbidden", "Provider release JSON is a symlink.")
    try:
        size = path.stat().st_size
        if size > max_bytes:
            _fail(
                "provider_release_size_limit_exceeded",
                "Provider release JSON exceeds its v1 size limit.",
                actual_size=size,
                max_bytes=max_bytes,
            )
        with path.open("rb") as handle:
            payload = handle.read(max_bytes + 1)
        if len(payload) > max_bytes:
            _fail(
                "provider_release_size_limit_exceeded",
                "Provider release JSON exceeds its v1 size limit.",
                max_bytes=max_bytes,
            )
        value = json.loads(payload.decode("utf-8"))
    except ProviderRuntimeError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        _fail(code, f"Could not load provider release JSON: {exc}.", path=str(path))
    if not isinstance(value, dict):
        _fail(code, "Provider release JSON must contain an object.")
    return value


def _identifier(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value.strip() != value
        or not _ascii_alphanumeric(value[0])
        or any(not (_ascii_alphanumeric(character) or character in "_.-") for character in value)
    ):
        _fail("provider_release_identifier_invalid", f"{field} is not a valid identifier.")
    return value


def _evidence_list(value: Any) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list):
        _fail("provider_release_config_invalid", "evidence_sources must be a list.")
    fields = {
        "evidence_id",
        "origin_artifact_ref",
        "artifact_sha256",
        "grounding_level",
        "observed_at",
        "valid_through",
        "distribution_label",
        "rights_basis",
    }
    result: list[dict[str, Any]] = []
    ids: set[str] = set()
    for index, source in enumerate(value):
        if not isinstance(source, dict) or set(source) != fields:
            _fail(
                "provider_release_config_invalid",
                f"evidence_sources[{index}] fields are invalid.",
            )
        evidence_id = _identifier(source["evidence_id"], field="evidence_id")
        if evidence_id in ids:
            _fail("provider_release_config_invalid", "Evidence ids must be unique.")
        ids.add(evidence_id)
        _relative_metadata_path(source["origin_artifact_ref"], field="origin_artifact_ref")
        _sha256(source["artifact_sha256"], field="artifact_sha256")
        _grounding_rank(source["grounding_level"])
        for field in ("observed_at", "valid_through", "rights_basis"):
            if not isinstance(source[field], str) or not source[field].strip():
                _fail("provider_release_config_invalid", f"Evidence {field} is invalid.")
        _distribution_label(source["distribution_label"])
        try:
            canonical_json_bytes(source)
        except (TypeError, ValueError) as exc:
            _fail("provider_release_config_invalid", f"Evidence metadata is not JSON: {exc}.")
        result.append(deepcopy(source))
    if [item["evidence_id"] for item in result] != sorted(ids):
        _fail("provider_release_config_invalid", "Evidence metadata must be sorted by id.")
    return tuple(result)


def _operation_list(
    value: Any,
    *,
    evidence: tuple[dict[str, Any], ...],
    authorities: frozenset[str],
) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        _fail("provider_release_config_invalid", "operations must be a non-empty list.")
    fields = {
        "operation_id",
        "native_surface",
        "mutability",
        "behavior_program",
        "state_effects",
        "grounding",
        "rights",
        "covered_behaviors",
    }
    surface_fields = {"type", "scheme", "authority", "method", "path_template"}
    evidence_ids = {source["evidence_id"] for source in evidence}
    result: list[dict[str, Any]] = []
    operation_ids: set[str] = set()
    for index, operation in enumerate(value):
        if not isinstance(operation, dict) or set(operation) != fields:
            _fail("provider_release_config_invalid", f"operations[{index}] fields are invalid.")
        operation_id = _identifier(operation["operation_id"], field="operation_id")
        if operation_id in operation_ids:
            _fail("provider_release_config_invalid", "Operation ids must be unique.")
        operation_ids.add(operation_id)
        surface = operation["native_surface"]
        if (
            not isinstance(surface, dict)
            or set(surface) != surface_fields
            or surface["type"] != "http"
            or surface["scheme"] != "https"
            or not isinstance(surface["authority"], str)
            or surface["authority"] not in authorities
            or not isinstance(surface["method"], str)
            or not surface["method"].isupper()
            or not isinstance(surface["path_template"], str)
            or not surface["path_template"].startswith("/")
        ):
            _fail("provider_release_config_invalid", "Operation native surface is invalid.")
        if operation["mutability"] not in {"read", "write"}:
            _fail("provider_release_config_invalid", "Operation mutability is invalid.")
        _identifier(operation["behavior_program"], field="behavior_program")
        state_effects = operation["state_effects"]
        if not isinstance(state_effects, list) or any(
            _identifier(effect, field="state_effect") != effect for effect in state_effects
        ):
            _fail("provider_release_config_invalid", "Operation state effects are invalid.")
        if len(set(state_effects)) != len(state_effects):
            _fail("provider_release_config_invalid", "Operation state effects must be unique.")
        if operation["mutability"] == "write" and not state_effects:
            _fail("provider_release_config_invalid", "Write operation state effects are required.")
        grounding = operation["grounding"]
        if (
            not isinstance(grounding, dict)
            or set(grounding) != {"level", "evidence_refs", "grounded"}
            or not isinstance(grounding["level"], str)
            or not isinstance(grounding["grounded"], bool)
            or not isinstance(grounding["evidence_refs"], list)
            or any(ref not in evidence_ids for ref in grounding["evidence_refs"])
            or len(set(grounding["evidence_refs"])) != len(grounding["evidence_refs"])
        ):
            _fail("provider_release_config_invalid", "Operation grounding is invalid.")
        grounding_rank = _grounding_rank(grounding["level"])
        if grounding["grounded"] is not (grounding_rank >= 2):
            _fail("provider_release_config_invalid", "Operation grounding result is inconsistent.")
        if grounding["evidence_refs"]:
            evidence_by_id = {source["evidence_id"]: source for source in evidence}
            supported_rank = max(
                _grounding_rank(evidence_by_id[ref]["grounding_level"])
                for ref in grounding["evidence_refs"]
            )
            if supported_rank < grounding_rank:
                _fail("provider_release_config_invalid", "Operation grounding is overstated.")
        rights = operation["rights"]
        if (
            not isinstance(rights, dict)
            or set(rights) != {"distribution_label", "behavior_distribution_basis"}
            or not isinstance(rights["behavior_distribution_basis"], str)
            or not rights["behavior_distribution_basis"].strip()
        ):
            _fail("provider_release_config_invalid", "Operation rights are invalid.")
        _distribution_label(rights["distribution_label"])
        behaviors = operation["covered_behaviors"]
        if (
            not isinstance(behaviors, dict)
            or not behaviors
            or set(behaviors) - set(_BEHAVIORS)
            or any(passed is not True for passed in behaviors.values())
        ):
            _fail("provider_release_config_invalid", "Operation behavior coverage is invalid.")
        required_behaviors = {"success", "failure"}
        if operation["mutability"] == "write":
            required_behaviors |= {"duplicate", "readback"}
        if not required_behaviors.issubset(behaviors):
            _fail(
                "provider_release_config_invalid",
                "Operation omits required behavior coverage.",
            )
        try:
            canonical_json_bytes(operation)
        except (TypeError, ValueError) as exc:
            _fail("provider_release_config_invalid", f"Operation is not JSON: {exc}.")
        result.append(deepcopy(operation))
    if [item["operation_id"] for item in result] != sorted(operation_ids):
        _fail("provider_release_config_invalid", "Operations must be sorted by operation_id.")
    return tuple(result)


def _relative_metadata_path(value: Any, *, field: str) -> str:
    if not isinstance(value, str) or not value or "\\" in value:
        _fail("provider_release_config_invalid", f"{field} is invalid.")
    parsed = PurePosixPath(value)
    if parsed.is_absolute() or parsed.as_posix() != value or ".." in parsed.parts:
        _fail("provider_release_config_invalid", f"{field} is invalid.")
    return value


def _grounding_rank(value: Any) -> int:
    if not isinstance(value, str):
        _fail("provider_release_config_invalid", "Grounding level is invalid.")
    parts = value.split("_")
    if (
        len(parts[0]) != 2
        or parts[0][0] != "G"
        or parts[0][1] not in "01234"
        or any(
            not part
            or any(not (character.isdigit() or "A" <= character <= "Z") for character in part)
            for part in parts[1:]
        )
    ):
        _fail("provider_release_config_invalid", "Grounding level is invalid.")
    return int(parts[0][1])


def _predicate_list(value: Any, *, field: str, allow_response: bool) -> tuple[dict[str, Any], ...]:
    if not isinstance(value, list) or not value:
        _fail("provider_release_config_invalid", f"{field} must be a non-empty list.")
    result: list[dict[str, Any]] = []
    predicate_ids: set[str] = set()
    for index, predicate in enumerate(value):
        if not isinstance(predicate, dict):
            _fail("provider_release_config_invalid", f"{field}[{index}] is invalid.")
        common = {"predicate_id", "source", "operator", "pointer", "passed"}
        operator = predicate.get("operator")
        if operator == "exists":
            expected_fields = common
        elif operator == "equals":
            expected_fields = common | {"expected"}
        elif operator == "type":
            expected_fields = common | {"expected_type"}
        else:
            _fail("provider_release_config_invalid", f"{field}[{index}] operator is invalid.")
        if set(predicate) != expected_fields:
            _fail("provider_release_config_invalid", f"{field}[{index}] fields are invalid.")
        predicate_id = _identifier(predicate["predicate_id"], field="predicate_id")
        if predicate_id in predicate_ids:
            _fail("provider_release_config_invalid", f"{field} predicate ids must be unique.")
        predicate_ids.add(predicate_id)
        allowed_sources = {"provider_state", "call_evidence"}
        if allow_response:
            allowed_sources.add("response_body")
        if predicate["source"] not in allowed_sources:
            _fail("provider_release_config_invalid", f"{field}[{index}] source is invalid.")
        if not _json_pointer(predicate["pointer"]) or predicate["passed"] is not True:
            _fail("provider_release_config_invalid", f"{field}[{index}] is invalid.")
        if operator == "type" and predicate["expected_type"] not in {
            "object",
            "array",
            "string",
            "number",
            "integer",
            "boolean",
            "null",
        }:
            _fail("provider_release_config_invalid", f"{field}[{index}] type is invalid.")
        try:
            canonical_json_bytes(predicate)
        except (TypeError, ValueError) as exc:
            _fail("provider_release_config_invalid", f"{field}[{index}] is not JSON: {exc}.")
        result.append(deepcopy(predicate))
    if [item["predicate_id"] for item in result] != sorted(predicate_ids):
        _fail("provider_release_config_invalid", f"{field} must be sorted by predicate_id.")
    return tuple(result)


def _json_pointer(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if value == "":
        return True
    if not value.startswith("/"):
        return False
    for token in value[1:].split("/"):
        index = 0
        while index < len(token):
            if token[index] != "~":
                index += 1
                continue
            if index + 1 >= len(token) or token[index + 1] not in "01":
                return False
            index += 2
    return True


def _ascii_alphanumeric(value: str) -> bool:
    return "a" <= value <= "z" or "A" <= value <= "Z" or "0" <= value <= "9"


def _distribution_label(value: Any) -> str:
    if value not in _DISTRIBUTION_ORDER:
        _fail("provider_release_rights_invalid", "Provider release distribution label is invalid.")
    return value


def _nonnegative_integer(value: Any, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        _fail("provider_release_config_invalid", f"{field} must be a non-negative integer.")
    return value


def _sha256(value: Any, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 71
        or not value.startswith("sha256:")
        or any(character not in "0123456789abcdef" for character in value[7:])
    ):
        _fail("provider_release_digest_invalid", f"{field} is not a valid SHA-256 digest.")
    return value


def _sha256_bytes(payload: bytes) -> str:
    return f"sha256:{hashlib.sha256(payload).hexdigest()}"


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError as exc:
        _fail("provider_release_input_unreadable", f"Could not hash provider release input: {exc}.")
    return f"sha256:{digest.hexdigest()}"


def _stream_size_and_sha256(path: Path, *, max_bytes: int) -> tuple[int, str]:
    digest = hashlib.sha256()
    total = 0
    try:
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                total += len(chunk)
                if total > max_bytes:
                    _fail(
                        "provider_release_size_limit_exceeded",
                        "Provider release content exceeds its v1 size limit.",
                        actual_size=total,
                        max_bytes=max_bytes,
                    )
                digest.update(chunk)
    except ProviderRuntimeError:
        raise
    except OSError as exc:
        _fail("provider_release_blob_unreadable", f"Could not stream provider content: {exc}.")
    return total, f"sha256:{digest.hexdigest()}"


def _media_type_size_limit(media_type: Any) -> int:
    if media_type == PROVIDER_RELEASE_PROFILE_MEDIA_TYPE:
        return PROVIDER_RELEASE_MAX_PROFILE_LAYER_BYTES
    if media_type in {
        OCI_MANIFEST_MEDIA_TYPE,
        PROVIDER_RELEASE_CONFIG_MEDIA_TYPE,
    }:
        return PROVIDER_RELEASE_MAX_JSON_BYTES
    _fail(
        "provider_release_media_type_unsupported",
        "Provider release descriptor has an unsupported media type.",
        media_type=media_type,
    )


def _fail(code: str, message: str, **details: Any) -> None:
    raise ProviderRuntimeError(code, message, details)
