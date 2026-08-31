from __future__ import annotations

import json
from pathlib import Path

import pytest

from test_rollout_provider_set_v2 import _publish_example_release, _renamed_profile

from datalox_gated_runtime.interception import server
from datalox_gated_runtime.interception.gateway import InterceptionGateway
from datalox_gated_runtime.provider_runtime.release import build_provider_release
from datalox_gated_runtime.rollout import (
    ProviderReleaseSelection,
    load_materialized_rollout_provider_set_v2,
    materialize_rollout_provider_set_v2,
    write_rollout_provider_set_v2,
)


def _admitted_binding(tmp_path: Path) -> tuple[Path, Path, Path]:
    registry, reference = _publish_example_release(tmp_path)
    selected = write_rollout_provider_set_v2(
        selections=(ProviderReleaseSelection(reference, "default"),),
        registry=registry,
        output_path=tmp_path / "provider-set-v2.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )
    binding = load_materialized_rollout_provider_set_v2(materialized.root).bindings[0]
    return binding.bundle_dir, binding.admission_path, binding.release_config_path


def test_prepare_admitted_interception_binds_runtime_and_admission_digests(
    tmp_path: Path,
) -> None:
    binding = _admitted_binding(tmp_path)
    run_root = tmp_path / "run"

    prepared_path = server.prepare_admitted_interception_run(
        bundle_admission_configs=(binding,),
        run_root=run_root,
        trust_dir=tmp_path / "trust",
    )

    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    assert prepared["schema_version"] == server.PREPARED_ADMITTED_RUN_SCHEMA
    assert prepared["bundles"][0]["manifest_sha256"].startswith("sha256:")
    assert prepared["bundles"][0]["admission_sha256"].startswith("sha256:")
    assert prepared["bundles"][0]["release_config_sha256"].startswith("sha256:")
    assert prepared["authorities"] == ["api.provider.example"]


def test_serve_admitted_uses_admission_enforcing_gateway(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _admitted_binding(tmp_path)
    run_root = tmp_path / "run"
    server.prepare_admitted_interception_run(
        bundle_admission_configs=(binding,),
        run_root=run_root,
    )
    observed: dict[str, object] = {}

    def fake_serve(*, gateway: InterceptionGateway, run_root: Path, host: str, port: int) -> None:
        observed.update({"gateway": gateway, "run_root": run_root, "host": host, "port": port})
        provider = next(iter(gateway.providers.values()))
        assert provider.runtime.export()["provider_assurance"][
            "provider_admission_sha256"
        ].startswith("sha256:")
        assert provider.release_config is not None
        assert provider.release_config["operation_contract_sha256"].startswith("sha256:")
        gateway.close()

    monkeypatch.setattr(server, "_serve_gateway_process", fake_serve)

    server.serve_admitted_interception_gateway(
        bundle_admission_configs=(binding,),
        run_root=run_root,
        host="127.0.0.1",
        port=8443,
        prepared=True,
    )

    assert observed["run_root"] == run_root
    assert observed["host"] == "127.0.0.1"
    assert observed["port"] == 8443


def test_serve_admitted_rejects_prepared_admission_digest_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _admitted_binding(tmp_path)
    run_root = tmp_path / "run"
    prepared_path = server.prepare_admitted_interception_run(
        bundle_admission_configs=(binding,),
        run_root=run_root,
    )
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    prepared["bundles"][0]["admission_sha256"] = f"sha256:{'0' * 64}"
    prepared_path.write_text(json.dumps(prepared), encoding="utf-8")
    monkeypatch.setattr(
        server,
        "_serve_gateway_process",
        lambda **_: pytest.fail("tampered prepared state must not start the gateway"),
    )

    with pytest.raises(ValueError, match="does not match admitted provider bindings"):
        server.serve_admitted_interception_gateway(
            bundle_admission_configs=(binding,),
            run_root=run_root,
            host="127.0.0.1",
            port=8443,
            prepared=True,
        )


def test_admitted_gateway_allocates_distinct_state_roots_for_same_named_runtime_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    registry, first_reference = _publish_example_release(tmp_path / "base")
    second_release = build_provider_release(
        profiles=(
            _renamed_profile(
                tmp_path / "second",
                provider_id="second_provider",
                authority="second.provider.example",
            ),
        ),
        release_version="1.0.0",
        output_dir=tmp_path / "second-release",
    )
    second_reference = registry.publish(second_release).reference
    selected = write_rollout_provider_set_v2(
        selections=(
            ProviderReleaseSelection(first_reference, "default"),
            ProviderReleaseSelection(second_reference, "default"),
        ),
        registry=registry,
        output_path=tmp_path / "provider-set-v2.json",
    )
    materialized = materialize_rollout_provider_set_v2(
        provider_set=selected,
        registry=registry,
        output_dir=tmp_path / "materialized",
    )
    bindings = load_materialized_rollout_provider_set_v2(materialized.root).bindings
    triples = tuple(
        (binding.bundle_dir, binding.admission_path, binding.release_config_path)
        for binding in bindings
    )
    run_root = tmp_path / "run"
    server.prepare_admitted_interception_run(bundle_admission_configs=triples, run_root=run_root)

    def fake_serve(*, gateway: InterceptionGateway, run_root: Path, host: str, port: int) -> None:
        del run_root, host, port
        state_roots = {provider.runtime.run_dir for provider in gateway.providers.values()}
        assert state_roots == {tmp_path / "run/providers/0000", tmp_path / "run/providers/0001"}
        gateway.close()

    monkeypatch.setattr(server, "_serve_gateway_process", fake_serve)
    server.serve_admitted_interception_gateway(
        bundle_admission_configs=triples,
        run_root=run_root,
        host="127.0.0.1",
        port=8443,
        prepared=True,
    )


def test_serve_admitted_rejects_prepared_release_config_digest_tamper(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    binding = _admitted_binding(tmp_path)
    run_root = tmp_path / "run"
    prepared_path = server.prepare_admitted_interception_run(
        bundle_admission_configs=(binding,),
        run_root=run_root,
    )
    prepared = json.loads(prepared_path.read_text(encoding="utf-8"))
    prepared["bundles"][0]["release_config_sha256"] = f"sha256:{'0' * 64}"
    prepared_path.write_text(json.dumps(prepared), encoding="utf-8")
    monkeypatch.setattr(
        server,
        "_serve_gateway_process",
        lambda **_: pytest.fail("tampered prepared state must not start the gateway"),
    )

    with pytest.raises(ValueError, match="does not match admitted provider bindings"):
        server.serve_admitted_interception_gateway(
            bundle_admission_configs=(binding,),
            run_root=run_root,
            host="127.0.0.1",
            port=8443,
            prepared=True,
        )
