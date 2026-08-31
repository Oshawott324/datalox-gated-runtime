from __future__ import annotations

import hashlib
import json
from dataclasses import FrozenInstanceError
from pathlib import Path

import jsonschema
import pytest
from world_v1_helpers import create_valid_bundle

from datalox_gated_runtime import cli
from datalox_gated_runtime.provider_runtime import build_provider_runtime_from_world
from datalox_gated_runtime.rollout import (
    RolloutProviderSetError,
    load_rollout_provider_set,
    write_rollout_provider_set,
)

ROOT = Path(__file__).resolve().parents[1]


def _build_provider(root: Path, *, provider_id: str, authority: str) -> Path:
    source = create_valid_bundle(root / "source")
    bundle = root / "bundle"
    build_provider_runtime_from_world(
        source_world_dir=source,
        output_dir=bundle,
        provider_id=provider_id,
        authorities=(authority,),
        episode_id="episode-1",
    )
    return bundle


def _manifest_digest(bundle: Path) -> str:
    value = (bundle / "provider-runtime.json").read_bytes()
    return f"sha256:{hashlib.sha256(value).hexdigest()}"


def _write_manifest(path: Path, providers: list[dict[str, str]], **extra: object) -> Path:
    path.write_text(
        json.dumps(
            {
                "schema_version": "datalox_rollout_provider_set_v1",
                "providers": providers,
                **extra,
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    return path


def _entry(manifest_dir: Path, bundle: Path, provider_id: str) -> dict[str, str]:
    return {
        "provider_id": provider_id,
        "bundle_path": bundle.relative_to(manifest_dir).as_posix(),
        "provider_runtime_sha256": _manifest_digest(bundle),
    }


def test_writer_creates_ordered_relative_content_addressed_manifest(tmp_path: Path) -> None:
    first = _build_provider(
        tmp_path / "providers" / "first",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    second = _build_provider(
        tmp_path / "providers" / "second",
        provider_id="orders",
        authority="orders.provider.example",
    )
    output = tmp_path / "rollout-providers.json"

    loaded = write_rollout_provider_set(bundle_dirs=(second, first), output_path=output)

    raw = json.loads(output.read_text(encoding="utf-8"))
    assert [item["provider_id"] for item in raw["providers"]] == ["orders", "inventory"]
    assert [item["bundle_path"] for item in raw["providers"]] == [
        "providers/second/bundle",
        "providers/first/bundle",
    ]
    assert tuple(item.provider_id for item in loaded.providers) == ("orders", "inventory")
    with pytest.raises(RolloutProviderSetError) as exists:
        write_rollout_provider_set(bundle_dirs=(first,), output_path=output)
    assert exists.value.code == "rollout_provider_set_output_exists"


def test_writer_rejects_bundle_outside_manifest_directory(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    with pytest.raises(RolloutProviderSetError) as failed:
        write_rollout_provider_set(
            bundle_dirs=(bundle,), output_path=tmp_path / "nested" / "providers.json"
        )
    assert failed.value.code == "rollout_provider_set_path_escape"


def test_provider_set_cli_writes_manifest(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    bundle = _build_provider(
        tmp_path / "providers" / "inventory",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    output = tmp_path / "rollout-providers.json"
    monkeypatch.setattr(
        "sys.argv",
        [
            "datalox-gate",
            "rollout",
            "provider-set",
            "--bundle",
            str(bundle),
            "--out",
            str(output),
        ],
    )
    assert cli.main() == 0
    assert load_rollout_provider_set(output).providers[0].provider_id == "inventory"


def test_schema_is_strict_and_loader_preserves_order_with_resolved_paths(tmp_path: Path) -> None:
    first = _build_provider(
        tmp_path / "providers" / "first",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    second = _build_provider(
        tmp_path / "providers" / "second",
        provider_id="orders",
        authority="orders.provider.example",
    )
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [_entry(tmp_path, second, "orders"), _entry(tmp_path, first, "inventory")],
    )

    schema = json.loads(
        (ROOT / "schemas/rollout-provider-set-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema).validate(
        json.loads(manifest.read_text(encoding="utf-8"))
    )

    loaded = load_rollout_provider_set(manifest)
    assert loaded.manifest_path == manifest.resolve()
    assert tuple(provider.provider_id for provider in loaded.providers) == (
        "orders",
        "inventory",
    )
    assert tuple(provider.bundle_dir for provider in loaded.providers) == (
        second.resolve(),
        first.resolve(),
    )
    assert loaded.providers[0].authorities == ("orders.provider.example",)
    with pytest.raises(FrozenInstanceError):
        loaded.providers[0].provider_id = "changed"  # type: ignore[misc]


@pytest.mark.parametrize(
    "forbidden_field",
    [
        "task",
        "prompt",
        "agent",
        "trainer",
        "verifier",
        "reward",
        "model",
        "credential",
        "upstream",
        "live_provider",
    ],
)
def test_loader_rejects_non_provider_dependency_fields(
    tmp_path: Path,
    forbidden_field: str,
) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [_entry(tmp_path, bundle, "inventory")],
        **{forbidden_field: "forbidden"},
    )

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_manifest_invalid"


@pytest.mark.parametrize(
    "bundle_path",
    ["/absolute/provider", "../provider", "providers/../provider", "C:/provider", r"a\b"],
)
def test_loader_rejects_non_local_bundle_paths(tmp_path: Path, bundle_path: str) -> None:
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [
            {
                "provider_id": "inventory",
                "bundle_path": bundle_path,
                "provider_runtime_sha256": f"sha256:{'0' * 64}",
            }
        ],
    )

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_path_invalid"


def test_loader_rejects_symlinked_bundle_path(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "outside" / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    symlink = tmp_path / "linked-provider"
    symlink.symlink_to(bundle, target_is_directory=True)
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [
            {
                "provider_id": "inventory",
                "bundle_path": symlink.name,
                "provider_runtime_sha256": _manifest_digest(bundle),
            }
        ],
    )

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_symlink_forbidden"


def test_loader_rejects_manifest_digest_mismatch(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    entry = _entry(tmp_path, bundle, "inventory")
    entry["provider_runtime_sha256"] = f"sha256:{'0' * 64}"
    manifest = _write_manifest(tmp_path / "rollout-providers.json", [entry])

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_digest_mismatch"


def test_loader_rejects_duplicate_provider_ids(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    entry = _entry(tmp_path, bundle, "inventory")
    manifest = _write_manifest(tmp_path / "rollout-providers.json", [entry, entry])

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_provider_duplicate"


def test_loader_rejects_duplicate_authorities_across_bundles(tmp_path: Path) -> None:
    first = _build_provider(
        tmp_path / "first",
        provider_id="inventory",
        authority="shared.provider.example",
    )
    second = _build_provider(
        tmp_path / "second",
        provider_id="orders",
        authority="shared.provider.example",
    )
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [_entry(tmp_path, first, "inventory"), _entry(tmp_path, second, "orders")],
    )

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_authority_duplicate"


def test_loader_rejects_bundle_provider_id_mismatch(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [_entry(tmp_path, bundle, "orders")],
    )

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_provider_id_mismatch"


def test_loader_delegates_inner_bundle_validation(tmp_path: Path) -> None:
    bundle = _build_provider(
        tmp_path / "provider",
        provider_id="inventory",
        authority="inventory.provider.example",
    )
    manifest = _write_manifest(
        tmp_path / "rollout-providers.json",
        [_entry(tmp_path, bundle, "inventory")],
    )
    (bundle / "seed.json").write_text("{}\n", encoding="utf-8")

    with pytest.raises(RolloutProviderSetError) as caught:
        load_rollout_provider_set(manifest)
    assert caught.value.code == "rollout_provider_set_bundle_invalid"
    assert caught.value.details["provider_runtime_error"] == "provider_runtime_hash_mismatch"
