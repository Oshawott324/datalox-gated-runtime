from __future__ import annotations

import json
import os
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path

import jsonschema
import pytest

from provider_runtime_helpers import build_stateful_provider_bundle
from test_provider_admission import _claims
from test_provider_release_registry import _profile

from datalox_gated_runtime.provider_runtime.admission import admit_provider_runtime
from datalox_gated_runtime.provider_runtime.bundle import compute_provider_runtime_hashes
from datalox_gated_runtime.provider_runtime.registry import FilesystemProviderReleaseRegistry
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.rollout import (
    ProviderReleaseSelection,
    RolloutProviderSetError,
    load_rollout_provider_set,
    load_materialized_rollout_provider_set_v2,
    load_rollout_provider_set_v2,
    materialize_rollout_provider_set_v2,
    write_rollout_provider_set_v2,
)
from datalox_gated_runtime.rollout.provider_set import (
    ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES,
)

ROOT = Path(__file__).resolve().parents[1]


def _write_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def _tamper_read_only_json(path: Path, value: object) -> None:
    path.chmod(0o600)
    try:
        _write_json(path, value)
    finally:
        path.chmod(0o444)


def _publish_example_release(
    tmp_path: Path,
) -> tuple[FilesystemProviderReleaseRegistry, str]:
    default = _profile(tmp_path / "default", profile_id="default")
    backlog = _profile(
        tmp_path / "backlog",
        profile_id="backlog",
        initial_counter=7,
    )
    release = build_provider_release(
        profiles=(default, backlog),
        release_version="2026.08.25",
        output_dir=tmp_path / "release",
    )
    registry = FilesystemProviderReleaseRegistry.create(tmp_path / "registry")
    published = registry.publish(release)
    return registry, published.reference


def _renamed_profile(
    root: Path,
    *,
    provider_id: str,
    authority: str,
) -> ProviderReleaseProfileInput:
    bundle = build_stateful_provider_bundle(root / "bundle-root", authority=authority)
    manifest_path = bundle / "provider-runtime.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["provider_id"] = provider_id
    manifest["content_hashes"] = compute_provider_runtime_hashes(bundle)
    _write_json(manifest_path, manifest)

    claims_dir = root / "claims"
    claims_dir.mkdir(parents=True)
    claims_path = _claims(claims_dir)
    claims = json.loads(claims_path.read_text(encoding="utf-8"))
    claims["provider_id"] = provider_id
    for operation in claims["operations"]:
        operation["native_surface"]["authority"] = authority
    for probe in claims["behavior_probes"]:
        for step in probe["steps"]:
            step["request"]["authority"] = authority
    _write_json(claims_path, claims)

    admission = root / "provider-admission.json"
    admit_provider_runtime(
        bundle_dir=bundle,
        claims_path=claims_path,
        output_path=admission,
        admitted_at=datetime(2026, 8, 25, tzinfo=UTC),
    )
    return ProviderReleaseProfileInput("default", bundle, admission)


def test_v2_authoring_is_deterministic_derived_and_profile_explicit(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selection = (ProviderReleaseSelection(reference, "backlog"),)
    first_path = tmp_path / "set-one.json"
    second_path = tmp_path / "set-two.json"

    first = write_rollout_provider_set_v2(
        selections=selection,
        registry=registry,
        output_path=first_path,
    )
    second = write_rollout_provider_set_v2(
        selections=selection,
        registry=registry.root,
        output_path=second_path,
    )

    assert first_path.read_bytes() == second_path.read_bytes()
    assert os.stat(first_path).st_mode & 0o777 == 0o444
    assert os.stat(second_path).st_mode & 0o777 == 0o444
    assert first.providers == second.providers
    provider = first.providers[0]
    release = registry.resolve(reference)
    profile = next(item for item in release.profiles if item.profile_id == "backlog")
    assert provider.provider_id == release.provider_id
    assert provider.release_manifest_sha256 == release.manifest_descriptor["digest"]
    assert provider.profile_layer_sha256 == profile.layer["digest"]
    assert provider.provider_runtime_sha256 == profile.provider_runtime_sha256
    assert provider.provider_admission_sha256 == profile.provider_admission_sha256
    assert provider.operation_contract_sha256 == release.config["operation_contract_sha256"]
    assert provider.authorities == tuple(release.config["authorities"])

    raw = json.loads(first_path.read_text(encoding="utf-8"))
    assert "registry" not in raw and "bundle_path" not in raw["providers"][0]
    schema = json.loads(
        (ROOT / "schemas/rollout-provider-set-v2.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(raw)
    with pytest.raises(RolloutProviderSetError) as exists:
        write_rollout_provider_set_v2(
            selections=selection,
            registry=registry,
            output_path=first_path,
        )
    assert exists.value.code == "rollout_provider_set_v2_output_exists"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("release_manifest_sha256", f"sha256:{'0' * 64}"),
        ("profile_layer_sha256", f"sha256:{'0' * 64}"),
        ("provider_runtime_sha256", f"sha256:{'0' * 64}"),
        ("provider_admission_sha256", f"sha256:{'0' * 64}"),
        ("operation_contract_sha256", f"sha256:{'0' * 64}"),
        ("provider_id", "tampered"),
        ("authorities", ["wrong.provider.example"]),
    ],
)
def test_v2_loader_rejects_tampered_derived_fields(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    registry, reference = _publish_example_release(tmp_path)
    path = tmp_path / "set.json"
    write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=path,
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["providers"][0][field] = value
    _tamper_read_only_json(path, raw)

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set_v2(path, registry=registry)
    assert caught.value.code == "rollout_provider_set_v2_binding_mismatch"
    assert field in caught.value.details["fields"]


def test_v2_loader_rejects_unknown_fields_and_requires_registry(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    path = tmp_path / "set.json"
    write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=path,
    )
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw["task"] = "forbidden"
    _tamper_read_only_json(path, raw)

    with pytest.raises(RolloutProviderSetError) as unknown:
        load_rollout_provider_set_v2(path, registry=registry)
    assert unknown.value.code == "rollout_provider_set_v2_manifest_invalid"
    with pytest.raises(RolloutProviderSetError) as required:
        load_rollout_provider_set_v2(path, registry=None)  # type: ignore[arg-type]
    assert required.value.code == "rollout_provider_set_v2_registry_required"

    linked_registry = tmp_path / "linked-registry"
    linked_registry.symlink_to(registry.root, target_is_directory=True)
    with pytest.raises(RolloutProviderSetError) as linked:
        load_rollout_provider_set_v2(path, registry=linked_registry)
    assert linked.value.code == "rollout_provider_set_v2_registry_invalid"
    assert linked.value.details["provider_runtime_error"] == "provider_release_symlink_forbidden"


def test_v2_rejects_unknown_profile_duplicate_provider_and_authority_collision(
    tmp_path: Path,
) -> None:
    registry, reference = _publish_example_release(tmp_path / "base")
    with pytest.raises(RolloutProviderSetError) as unknown:
        write_rollout_provider_set_v2(
            selections=(ProviderReleaseSelection(reference, "missing"),),
            registry=registry,
            output_path=tmp_path / "unknown.json",
        )
    assert unknown.value.code == "rollout_provider_set_v2_profile_unknown"

    with pytest.raises(RolloutProviderSetError) as duplicate:
        write_rollout_provider_set_v2(
            selections=(
                ProviderReleaseSelection(reference, "default"),
                ProviderReleaseSelection(reference, "backlog"),
            ),
            registry=registry,
            output_path=tmp_path / "duplicate.json",
        )
    assert duplicate.value.code == "rollout_provider_set_v2_provider_duplicate"

    shared_authority = "shared.provider.example"
    alpha = build_provider_release(
        profiles=(
            _renamed_profile(tmp_path / "alpha", provider_id="alpha", authority=shared_authority),
        ),
        release_version="1.0.0",
        output_dir=tmp_path / "alpha-release",
    )
    beta = build_provider_release(
        profiles=(
            _renamed_profile(tmp_path / "beta", provider_id="beta", authority=shared_authority),
        ),
        release_version="1.0.0",
        output_dir=tmp_path / "beta-release",
    )
    alpha_ref = registry.publish(alpha).reference
    beta_ref = registry.publish(beta).reference
    with pytest.raises(RolloutProviderSetError) as collision:
        write_rollout_provider_set_v2(
            selections=(
                ProviderReleaseSelection(alpha_ref, "default"),
                ProviderReleaseSelection(beta_ref, "default"),
            ),
            registry=registry,
            output_path=tmp_path / "collision.json",
        )
    assert collision.value.code == "rollout_provider_set_v2_authority_duplicate"


def test_v2_loader_rejects_changed_registry_reference(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    path = tmp_path / "set.json"
    write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=path,
    )
    provider_id, release_version = reference.split("@", 1)
    ref_path = registry.root / "refs" / provider_id / f"{release_version}.json"
    descriptor = json.loads(ref_path.read_text(encoding="utf-8"))
    descriptor["digest"] = f"sha256:{'0' * 64}"
    _tamper_read_only_json(ref_path, descriptor)

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set_v2(path, registry=registry.root)
    assert caught.value.code == "rollout_provider_set_v2_release_invalid"


def test_v2_materialization_is_safe_atomic_and_v1_compatible(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    second_release = build_provider_release(
        profiles=(
            _renamed_profile(
                tmp_path / "second-provider",
                provider_id="second_provider",
                authority="second.provider.example",
            ),
        ),
        release_version="1.0.0",
        output_dir=tmp_path / "second-release",
    )
    second_reference = registry.publish(second_release).reference
    manifest = tmp_path / "set.json"
    selected = write_rollout_provider_set_v2(
        selections=(
            ProviderReleaseSelection(reference, "backlog"),
            ProviderReleaseSelection(second_reference, "default"),
        ),
        registry=registry,
        output_path=manifest,
    )
    output = tmp_path / "materialized"

    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=output,
    )

    assert materialized.root == output.resolve()
    compatible = load_rollout_provider_set(materialized.provider_set_v1_path)
    assert tuple(item.provider_id for item in compatible.providers) == tuple(
        item.provider_id for item in selected.providers
    )
    seed = json.loads((compatible.providers[0].bundle_dir / "seed.json").read_text())
    assert seed["initial_state"]["counter"] == 7
    controller = json.loads(materialized.controller_mapping_path.read_text(encoding="utf-8"))
    assert controller["providers"][0]["release_reference"] == reference
    assert controller["providers"][0]["profile_id"] == "backlog"
    assert controller["providers"][1]["release_reference"] == second_reference
    admission = output / controller["providers"][0]["admission_path"]
    assert admission.is_file()
    assert os.stat(materialized.controller_mapping_path).st_mode & 0o777 == 0o600
    assert all(
        not path.is_symlink() and (path.is_dir() or path.is_file()) for path in output.rglob("*")
    )

    with pytest.raises(RolloutProviderSetError) as exists:
        materialize_rollout_provider_set_v2(
            provider_set=manifest,
            registry=registry,
            output_dir=output,
        )
    assert exists.value.code == "rollout_provider_set_v2_materialize_output_exists"


def test_v2_loader_rejects_oversized_manifest_before_json_decode(tmp_path: Path) -> None:
    registry, _ = _publish_example_release(tmp_path)
    oversized = tmp_path / "oversized.json"
    oversized.write_bytes(b"{" + b" " * ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES + b"}")

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set_v2(oversized, registry=registry)

    assert caught.value.code == "rollout_provider_set_v2_size_limit_exceeded"
    assert caught.value.details["max_bytes"] == ROLLOUT_PROVIDER_SET_V2_MAX_JSON_BYTES


def test_loaded_v2_materialization_uses_bound_manifest_digest_without_reopening(
    tmp_path: Path,
) -> None:
    registry, reference = _publish_example_release(tmp_path)
    manifest = tmp_path / "set.json"
    loaded = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=manifest,
    )
    bound_digest = loaded.manifest_sha256
    manifest.unlink()

    materialized = materialize_rollout_provider_set_v2(
        provider_set=loaded,
        registry=registry,
        output_dir=tmp_path / "materialized-from-loaded",
    )

    controller = json.loads(materialized.controller_mapping_path.read_text(encoding="utf-8"))
    assert controller["source_manifest_sha256"] == bound_digest


def test_v2_materialization_reserves_destination_without_replace_race(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "set.json",
    )
    output = tmp_path / "materialized-race"

    def materialize() -> str:
        try:
            materialize_rollout_provider_set_v2(
                provider_set=selected,
                registry=registry,
                output_dir=output,
            )
        except RolloutProviderSetError as exc:
            return exc.code
        return "published"

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(lambda _: materialize(), range(2)))

    assert sorted(results) == ["published", "rollout_provider_set_v2_materialize_output_exists"]
    assert (output / "controller-provider-releases.json").is_file()
    assert load_rollout_provider_set(output / "rollout-provider-set-v1.json").providers


def test_materialized_v2_loader_returns_exact_admitted_bindings(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "backlog"),),
        registry=registry,
        output_path=tmp_path / "set.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )

    loaded = load_materialized_rollout_provider_set_v2(materialized.root)

    assert loaded.source_manifest_sha256 == selected.manifest_sha256
    assert loaded.source_manifest_path.read_bytes() == selected.manifest_bytes
    assert len(loaded.bindings) == 1
    binding = loaded.bindings[0]
    assert binding.provider == selected.providers[0]
    assert binding.bundle_dir == loaded.provider_set_v1.providers[0].bundle_dir
    assert binding.admission_path.is_file()
    assert binding.release_config_path.is_file()
    assert binding.release_manifest_path.is_file()
    assert binding.release_config["operation_contract_sha256"] == (
        binding.provider.operation_contract_sha256
    )
    assert binding.release_config_sha256.startswith("sha256:")


def test_materialized_v2_loader_rejects_release_metadata_not_bound_to_source(
    tmp_path: Path,
) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "set.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )
    controller = json.loads(materialized.controller_mapping_path.read_text(encoding="utf-8"))
    controller["providers"][0]["profile_layer_sha256"] = f"sha256:{'0' * 64}"
    _write_json(materialized.controller_mapping_path, controller)

    with pytest.raises(RolloutProviderSetError) as caught:
        load_materialized_rollout_provider_set_v2(materialized.root)

    assert caught.value.code == "rollout_provider_set_v2_materialized_binding_mismatch"


def test_materialized_v2_loader_rejects_symlinked_admission(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "set.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )
    controller = json.loads(materialized.controller_mapping_path.read_text(encoding="utf-8"))
    admission = materialized.root / controller["providers"][0]["admission_path"]
    outside = tmp_path / "outside-admission.json"
    outside.write_bytes(admission.read_bytes())
    admission.unlink()
    admission.symlink_to(outside)

    with pytest.raises(RolloutProviderSetError) as caught:
        load_materialized_rollout_provider_set_v2(materialized.root)

    assert caught.value.code == "rollout_provider_set_v2_symlink_forbidden"


def test_materialized_v2_loader_rejects_release_config_tamper(tmp_path: Path) -> None:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "set.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )
    loaded = load_materialized_rollout_provider_set_v2(materialized.root)
    config_path = loaded.bindings[0].release_config_path
    config = json.loads(config_path.read_text(encoding="utf-8"))
    config["operation_contract_sha256"] = f"sha256:{'0' * 64}"
    _tamper_read_only_json(config_path, config)

    with pytest.raises(RolloutProviderSetError) as caught:
        load_materialized_rollout_provider_set_v2(materialized.root)

    assert caught.value.code == "rollout_provider_set_v2_release_config_digest_mismatch"
