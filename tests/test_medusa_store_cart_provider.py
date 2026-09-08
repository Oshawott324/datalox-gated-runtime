from __future__ import annotations

import importlib.util
import json
import shutil
from pathlib import Path

from datalox_gated_runtime.models import CallRequest
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntime,
    load_provider_admission,
    load_provider_runtime_bundle,
)
from datalox_gated_runtime.provider_runtime.release import load_provider_release
from datalox_gated_runtime.world_v1.bundle import validate_world_bundle

ROOT = Path(__file__).resolve().parents[1]
ENV = ROOT / "envs" / "medusa_store_cart_v0"
AUTHORITY = "api.medusa.local"
KEY = "pk_datalox_local_store"


def _load_script(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _request(
    method: str,
    path: str,
    *,
    body: object = None,
    key: str | None = KEY,
    query: dict[str, str] | None = None,
) -> CallRequest:
    return CallRequest(
        method=method,
        scheme="https",
        authority=AUTHORITY,
        path=path,
        headers={} if key is None else {"x-publishable-api-key": key},
        query={} if query is None else query,
        body=body,
    )


def _state(runtime: ProviderRuntime) -> dict[str, object]:
    return runtime.export()["provider_state"]["state"]


def test_source_world_and_task_free_provider_bundle_are_valid() -> None:
    source = validate_world_bundle(ENV / "source-world")
    bundle = load_provider_runtime_bundle(ENV / "provider-runtime")

    assert source.manifest.bundle_version == "2.16.0-store-cart-v0"
    assert bundle.manifest.bundle_version == "2.16.0-store-cart-v0"
    assert bundle.manifest.authorities == (AUTHORITY,)
    seed = json.loads((ENV / "provider-runtime" / "seed.json").read_text(encoding="utf-8"))
    assert set(seed).isdisjoint({"task", "expected", "hidden"})
    assert bundle.identity_policy is not None
    assert bundle.identity_policy.to_dict()["mode"] == "credential_map"


def test_builder_reproduces_every_committed_provider_artifact(tmp_path: Path) -> None:
    builder = _load_script(
        ROOT / "scripts" / "providers" / "build-medusa-store-cart-release.py",
        "build_medusa_store_cart_release",
    )
    public_source = tmp_path / "public-source"
    shutil.copytree(
        ENV,
        public_source,
        ignore=shutil.ignore_patterns("restricted", "__pycache__", "*.pyc"),
    )
    rebuilt = tmp_path / "rebuilt"

    report = builder.build(public_source, rebuilt)

    assert (
        report["admission_sha256"]
        == "sha256:f6f9807945160d13056f8973a4bf61e5224390b8e2785bfd2150bd075be9a6d6"
    )
    assert (
        report["release_manifest_digest"]
        == "sha256:19e8f978bbf64f73da17a8d1b343be1c584bf8a688b334339f36ea7c90f6a4d3"
    )

    def artifacts(root: Path) -> list[Path]:
        return sorted(
            path.relative_to(root)
            for path in root.rglob("*")
            if path.is_file()
            and "__pycache__" not in path.parts
            and "restricted" not in path.parts
            and path.suffix != ".pyc"
        )

    committed = artifacts(ENV)
    generated = artifacts(rebuilt)
    assert generated == committed
    for relative in committed:
        assert (rebuilt / relative).read_bytes() == (ENV / relative).read_bytes(), relative


def test_credential_policy_rejects_atomically_and_redacts_valid_key(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=tmp_path / "run",
    )
    try:
        initial = _state(runtime)
        missing = runtime.handle(
            _request("GET", "/store/products", key=None, query={"limit": "10", "offset": "0"})
        )
        invalid = runtime.handle(
            _request(
                "GET", "/store/products", key="pk_invalid", query={"limit": "10", "offset": "0"}
            )
        )
        assert _state(runtime) == initial
        valid = runtime.handle(
            _request("GET", "/store/products", query={"limit": "10", "offset": "0"})
        )
        serialized = json.dumps(runtime.export(), sort_keys=True)
    finally:
        runtime.close()

    assert (missing.status_code, invalid.status_code, valid.status_code) == (400, 400, 200)
    assert missing.body["type"] == invalid.body["type"] == "not_allowed"
    assert KEY not in serialized
    assert "x-publishable-api-key" not in serialized.lower()


def test_native_write_relations_atomicity_and_reset(tmp_path: Path) -> None:
    runtime = ProviderRuntime(
        bundle_dir=ENV / "provider-runtime",
        admission_path=ENV / "provider-admission.json",
        run_dir=tmp_path / "run",
    )
    try:
        initial = _state(runtime)
        create_request = _request(
            "POST",
            "/store/carts",
            body={"email": "test@example.test", "region_id": "region_datalox_us"},
        )
        first = runtime.handle(create_request)
        second = runtime.handle(create_request)
        cart_id = first.body["cart"]["id"]
        assert second.body["cart"]["id"] != cart_id
        add_request = _request(
            "POST",
            f"/store/carts/{cart_id}/line-items",
            body={"variant_id": "variant_datalox_pagination_001", "quantity": 1},
        )
        added = runtime.handle(add_request)
        duplicated = runtime.handle(add_request)
        line_id = added.body["cart"]["items"][0]["id"]
        assert duplicated.body["cart"]["items"] == [
            {**duplicated.body["cart"]["items"][0], "id": line_id, "quantity": 2}
        ]
        before_invalid = _state(runtime)
        invalid = runtime.handle(
            _request(
                "POST",
                f"/store/carts/{cart_id}/line-items",
                body={"variant_id": "variant_missing", "quantity": 1},
            )
        )
        assert invalid.status_code == 400
        assert _state(runtime) == before_invalid
        update_request = _request(
            "POST",
            f"/store/carts/{cart_id}/line-items/{line_id}",
            body={"quantity": 3},
        )
        updated = runtime.handle(update_request)
        before_duplicate_update = _state(runtime)
        duplicate_update = runtime.handle(update_request)
        assert duplicate_update.body == updated.body
        assert _state(runtime) == before_duplicate_update
        delete_request = _request("DELETE", f"/store/carts/{cart_id}/line-items/{line_id}")
        deleted = runtime.handle(delete_request)
        before_duplicate_delete = _state(runtime)
        duplicate_delete = runtime.handle(delete_request)
        assert deleted.body["deleted"] is duplicate_delete.body["deleted"] is True
        assert _state(runtime) == before_duplicate_delete
        reset = runtime.reset()
    finally:
        runtime.close()

    assert reset["provider_state"]["state"] == initial
    assert reset["provider_state"]["state"]["carts"] == {}


def test_two_provider_instances_isolate_generated_id_namespaces(tmp_path: Path) -> None:
    runtimes = [
        ProviderRuntime(
            bundle_dir=ENV / "provider-runtime",
            admission_path=ENV / "provider-admission.json",
            run_dir=tmp_path / f"run-{index}",
        )
        for index in range(2)
    ]
    try:
        created = [
            runtime.handle(
                _request(
                    "POST",
                    "/store/carts",
                    body={
                        "email": f"rollout-{index}@example.test",
                        "region_id": "region_datalox_us",
                    },
                )
            )
            for index, runtime in enumerate(runtimes)
        ]
        cart_ids = [response.body["cart"]["id"] for response in created]
        runtimes[0].handle(
            _request(
                "POST",
                f"/store/carts/{cart_ids[0]}/line-items",
                body={"variant_id": "variant_datalox_pagination_001", "quantity": 1},
            )
        )
        second_read = runtimes[1].handle(_request("GET", f"/store/carts/{cart_ids[1]}"))
    finally:
        for runtime in runtimes:
            runtime.close()

    assert cart_ids == ["cart_datalox_000001", "cart_datalox_000001"]
    assert second_read.body["cart"]["items"] == []


def test_differential_runs_observed_relations_twice_across_reset() -> None:
    checker = _load_script(
        ROOT / "scripts" / "providers" / "check-medusa-store-cart-lifecycle.py",
        "check_medusa_store_cart_lifecycle",
    )

    report = checker.check(ENV)

    assert report["status"] == "passed"
    assert report["cycles"] == 2
    assert report["observed_step_count"] == 23
    assert report["reset_removed_created_resources"] is True
    assert (
        report["steps"]
        == json.loads((ENV / "evidence" / "differential-report.json").read_text(encoding="utf-8"))[
            "steps"
        ]
    )


def test_admission_and_oci_release_cover_four_grounded_writes() -> None:
    admission = load_provider_admission(ENV / "provider-admission.json")
    release = load_provider_release(ENV / "provider-release")
    writes = [row for row in admission["operations"] if row["mutability"] == "write"]

    assert len(writes) == 4
    assert all(
        row["covered_behaviors"]
        == {"duplicate": True, "failure": True, "readback": True, "success": True}
        for row in writes
    )
    assert release.release_version == "2.16.0-store-cart-v0"
    assert release.config["operation_coverage"]["write"] == 4
    assert release.config["operation_coverage"]["behaviors"] == {
        "async": 0,
        "duplicate": 4,
        "failure": 6,
        "pagination": 1,
        "readback": 4,
        "success": 6,
    }
