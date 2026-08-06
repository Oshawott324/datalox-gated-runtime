from __future__ import annotations

import json
from pathlib import Path

import pytest

from datalox_gated_runtime.world_v1 import (
    ActorContext,
    WorldAuthorizationError,
    WorldBundleBackend,
    WorldBundleError,
    initialize_world_bundle_session,
    load_world_bundle,
    validate_world_bundle,
    compute_bundle_hashes,
)
from datalox_gated_runtime.models import CallRequest
from world_v1_helpers import create_valid_bundle, read_manifest, write_manifest


def _error_code(path: Path) -> str:
    with pytest.raises(WorldBundleError) as captured:
        validate_world_bundle(path)
    return captured.value.code


def test_valid_bundle_loads_exact_protocol_and_optional_metadata(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")

    bundle = load_world_bundle(root)

    assert bundle.manifest.world_id == "example_world_v1"
    assert bundle.implementation.schema_version == "datalox_world_bundle_v1"
    assert bundle.tools[0].source_refs == ("source-1",)
    assert bundle.tools[0].operation_family == "counter_management"
    assert bundle.validated.grounding_gaps[0]["gap"] == "errors"


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("episodes_path", "/tmp/episodes.jsonl"),
        ("roles_path", "world/../outside.json"),
    ],
)
def test_absolute_and_parent_paths_are_rejected(tmp_path: Path, field: str, value: str) -> None:
    root = create_valid_bundle(tmp_path / field)
    manifest = read_manifest(root)
    manifest[field] = value
    write_manifest(root, manifest)

    assert _error_code(root) == "world_bundle_path_invalid"


def test_symlink_escape_is_rejected(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (root / "escape.json").symlink_to(outside)
    manifest = read_manifest(root)
    manifest["content_hashes"]["escape.json"] = "sha256:" + "0" * 64
    write_manifest(root, manifest)

    assert _error_code(root) == "world_bundle_path_escape"


def test_unknown_manifest_field_is_rejected(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    manifest = read_manifest(root)
    manifest["surprise"] = True
    write_manifest(root, manifest)

    assert _error_code(root) == "world_bundle_manifest_unknown_field"


def test_missing_referenced_file_is_rejected(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    (root / "world" / "episodes.jsonl").unlink()

    assert _error_code(root) == "world_bundle_file_missing"


def test_invalid_and_mismatched_hashes_are_rejected(tmp_path: Path) -> None:
    invalid = create_valid_bundle(tmp_path / "invalid")
    manifest = read_manifest(invalid)
    manifest["content_hashes"]["world/roles.json"] = "not-a-hash"
    write_manifest(invalid, manifest)
    assert _error_code(invalid) == "world_bundle_hash_invalid"

    mismatch = create_valid_bundle(tmp_path / "mismatch")
    (mismatch / "world" / "roles.json").write_text('{"roles": []}', encoding="utf-8")
    assert _error_code(mismatch) == "world_bundle_hash_mismatch"


@pytest.mark.parametrize(
    ("relative_path", "collection", "code"),
    [
        ("world/episodes.jsonl", None, "world_bundle_duplicate_id"),
        ("world/roles.json", "roles", "world_bundle_duplicate_id"),
        ("world/tools.json", "tools", "world_bundle_duplicate_id"),
        ("world/sources.json", "sources", "world_bundle_duplicate_id"),
    ],
)
def test_duplicate_ids_are_rejected(
    tmp_path: Path, relative_path: str, collection: str | None, code: str
) -> None:
    root = create_valid_bundle(tmp_path / relative_path.replace("/", "_"))
    path = root / relative_path
    if collection is None:
        line = path.read_text(encoding="utf-8")
        path.write_text(line + line, encoding="utf-8")
    else:
        value = json.loads(path.read_text(encoding="utf-8"))
        value[collection].append(value[collection][0])
        path.write_text(json.dumps(value), encoding="utf-8")
    manifest = read_manifest(root)
    from datalox_gated_runtime.world_v1 import compute_bundle_hashes

    manifest["content_hashes"] = compute_bundle_hashes(root)
    write_manifest(root, manifest)

    assert _error_code(root) == code


def test_unsupported_capability_is_rejected(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    manifest = read_manifest(root)
    manifest["required_runtime_capabilities"].append("domain_telepathy")
    write_manifest(root, manifest)

    assert _error_code(root) == "world_bundle_capability_unsupported"


def test_mcp_response_body_sha256_capability_is_supported(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    manifest = read_manifest(root)
    manifest["required_runtime_capabilities"].append("mcp_response_body_sha256")
    write_manifest(root, manifest)

    bundle = validate_world_bundle(root)

    assert "mcp_response_body_sha256" in bundle.manifest.required_runtime_capabilities


def test_bundle_code_is_not_imported_before_hash_validation(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    sentinel = tmp_path / "imported"
    implementation = root / "world" / "implementation.py"
    implementation.write_text(
        f"from pathlib import Path\nPath({str(sentinel)!r}).write_text('bad')\n",
        encoding="utf-8",
    )

    with pytest.raises(WorldBundleError, match="hash mismatch"):
        load_world_bundle(root)
    assert not sentinel.exists()


def test_runtime_copy_adapter_is_transactional_and_role_scoped(tmp_path: Path) -> None:
    source = create_valid_bundle(tmp_path / "source")
    run_dir = tmp_path / "run"
    initialize_world_bundle_session(
        source_bundle_dir=source,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    source.rename(tmp_path / "source-moved")
    backend = WorldBundleBackend(run_dir=run_dir)

    response = backend.handle(
        CallRequest(
            method="POST",
            path="/counter",
            body={"amount": 2},
            headers={
                "x-datalox-actor-id": "operator-1",
                "x-datalox-actor-role": "operator",
            },
        )
    )
    assert response is not None and response.body == {"counter": 3, "actor_role": "operator"}
    assert backend.session.get_state("counter") == 3
    assert set(backend.tool_schemas(ActorContext("viewer-1", "viewer"))) == {"counter.read"}

    denied = backend.handle(
        CallRequest(
            method="POST",
            path="/counter",
            body={"amount": 10},
            headers={
                "x-datalox-actor-id": "viewer-1",
                "x-datalox-actor-role": "viewer",
            },
        )
    )
    assert denied is not None and denied.status_code == 403
    assert denied.reason_code == "world_tool_hidden"
    assert backend.session.get_state("counter") == 3
    assert any(event["type"] == "tool_invocation_denied" for event in backend.session.list_events())

    unknown_role = backend.handle(
        CallRequest(
            method="GET",
            path="/counter",
            headers={
                "x-datalox-actor-id": "intruder-1",
                "x-datalox-actor-role": "undeclared",
            },
        )
    )
    assert unknown_role is not None and unknown_role.status_code == 403
    assert unknown_role.reason_code == "world_actor_role_unknown"

    with pytest.raises(WorldAuthorizationError) as mcp_denied:
        backend.request_for_tool(
            "counter.increment",
            {"amount": 10},
            actor=ActorContext("viewer-1", "viewer"),
        )
    assert mcp_denied.value.code == "world_tool_hidden"
    denials = [event for event in backend.session.verifier_events() if event["decision"] == "deny"]
    assert len(denials) == 3
    assert all(event["request"] is not None for event in denials)

    run_files = {
        path.relative_to(run_dir).as_posix() for path in run_dir.rglob("*") if path.is_file()
    }
    assert not any(
        hidden_name in path
        for path in run_files
        for hidden_name in (
            "episodes.jsonl",
            "verifier.json",
            "sources.json",
            "reference.json",
        )
    )
    database_bytes = (run_dir / "world_v1.sqlite3").read_bytes()
    assert b"episodes.jsonl" not in database_bytes
    assert b"verifier.json" not in database_bytes
    assert b"sources.json" not in database_bytes
    assert b"reference.json" not in database_bytes
    backend.close()


def test_world_response_digest_event_is_not_persisted_on_rollback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_valid_bundle(tmp_path / "source")
    run_dir = tmp_path / "run"
    initialize_world_bundle_session(
        source_bundle_dir=source,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    backend = WorldBundleBackend(run_dir=run_dir)
    try:

        def boom(request, *, actor, session):
            session.set_state("counter", session.get_state("counter") + 1)
            raise RuntimeError("boom")

        monkeypatch.setattr(backend.bundle.implementation, "handle", boom)

        with pytest.raises(RuntimeError, match="boom"):
            backend.handle(
                CallRequest(
                    method="GET",
                    path="/counter",
                    headers={
                        "x-datalox-actor-id": "operator-1",
                        "x-datalox-actor-role": "operator",
                    },
                )
            )

        assert not any(
            event["type"] == "world_response_digest_recorded"
            for event in backend.session.list_events()
        )
    finally:
        backend.close()


def _declare_runtime_data(root: Path, paths: list[str]) -> None:
    declaration = root / "world" / "v1" / "runtime_data.json"
    declaration.parent.mkdir(parents=True, exist_ok=True)
    declaration.write_text(json.dumps({"paths": paths}), encoding="utf-8")
    manifest = read_manifest(root)
    manifest["content_hashes"] = compute_bundle_hashes(root)
    write_manifest(root, manifest)


@pytest.mark.parametrize(
    ("paths", "code"),
    (
        ([], "world_runtime_data_declaration_invalid"),
        ([" "], "world_runtime_data_declaration_invalid"),
        (["data/context.json", "data/context.json"], "world_runtime_data_declaration_invalid"),
        (["../outside.json"], "world_runtime_data_path_invalid"),
        (["/tmp/outside.json"], "world_runtime_data_path_invalid"),
        (["data/missing.json"], "world_runtime_data_missing"),
    ),
)
def test_runtime_data_declaration_rejects_invalid_paths(
    tmp_path: Path, paths: list[str], code: str
) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    _declare_runtime_data(root, paths)
    with pytest.raises(WorldBundleError) as captured:
        initialize_world_bundle_session(
            source_bundle_dir=root,
            run_dir=tmp_path / "run",
            episode_id="episode-1",
        )
    assert captured.value.code == code


def test_runtime_data_rejects_symlink_escape_and_missing_hash(tmp_path: Path) -> None:
    escaped = create_valid_bundle(tmp_path / "escaped")
    outside = tmp_path / "outside.json"
    outside.write_text("{}", encoding="utf-8")
    (escaped / "data").mkdir()
    (escaped / "data" / "context.json").write_text("{}", encoding="utf-8")
    _declare_runtime_data(escaped, ["data/context.json"])
    (escaped / "data" / "context.json").unlink()
    (escaped / "data" / "context.json").symlink_to(outside)
    with pytest.raises(WorldBundleError) as captured:
        initialize_world_bundle_session(
            source_bundle_dir=escaped,
            run_dir=tmp_path / "escaped-run",
            episode_id="episode-1",
        )
    assert captured.value.code == "world_bundle_path_escape"

    unhashed = create_valid_bundle(tmp_path / "unhashed")
    (unhashed / "data").mkdir()
    (unhashed / "data" / "context.json").write_text("{}", encoding="utf-8")
    _declare_runtime_data(unhashed, ["data/context.json"])
    manifest = read_manifest(unhashed)
    del manifest["content_hashes"]["data/context.json"]
    write_manifest(unhashed, manifest)
    with pytest.raises(WorldBundleError) as captured:
        initialize_world_bundle_session(
            source_bundle_dir=unhashed,
            run_dir=tmp_path / "unhashed-run",
            episode_id="episode-1",
        )
    assert captured.value.code == "world_bundle_hash_missing"


def test_runtime_data_rejects_paths_that_resolve_to_the_same_file(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    (root / "data").mkdir()
    (root / "data" / "context.json").write_text("{}", encoding="utf-8")
    _declare_runtime_data(root, ["data/context.json", "data/./context.json"])
    with pytest.raises(WorldBundleError) as captured:
        initialize_world_bundle_session(
            source_bundle_dir=root,
            run_dir=tmp_path / "run",
            episode_id="episode-1",
        )
    assert captured.value.code == "world_runtime_data_declaration_invalid"


def test_installed_runtime_data_is_copied_and_tamper_checked(tmp_path: Path) -> None:
    root = create_valid_bundle(tmp_path / "bundle")
    (root / "data").mkdir()
    (root / "data" / "context.json").write_text('{"value": 1}', encoding="utf-8")
    _declare_runtime_data(root, ["data/context.json"])
    run_dir = tmp_path / "run"
    initialize_world_bundle_session(
        source_bundle_dir=root,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    installed = run_dir / ".world_v1_code" / "data" / "context.json"
    assert installed.read_text(encoding="utf-8") == '{"value": 1}'
    installed.write_text('{"value": 2}', encoding="utf-8")
    with pytest.raises(WorldBundleError) as captured:
        WorldBundleBackend(run_dir=run_dir)
    assert captured.value.code == "world_bundle_runtime_code_hash_mismatch"


def test_tool_schema_projection_must_include_every_visible_tool(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    source = create_valid_bundle(tmp_path / "source")
    run_dir = tmp_path / "run"
    initialize_world_bundle_session(
        source_bundle_dir=source,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    backend = WorldBundleBackend(run_dir=run_dir)
    monkeypatch.setattr(backend.bundle.implementation, "tool_schemas", lambda *, actor: {})

    with pytest.raises(WorldBundleError) as captured:
        backend.tool_schemas(ActorContext("viewer-1", "viewer"))
    assert captured.value.code == "world_bundle_protocol_invalid"
    assert captured.value.context["missing_tool_ids"] == ["counter.read"]
    backend.close()


def test_run_private_executable_is_rehashed_before_import(tmp_path: Path) -> None:
    source = create_valid_bundle(tmp_path / "source")
    run_dir = tmp_path / "run"
    initialize_world_bundle_session(
        source_bundle_dir=source,
        run_dir=run_dir,
        episode_id="episode-1",
    )
    implementation = run_dir / ".world_v1_code" / "world" / "implementation.py"
    implementation.write_text("raise RuntimeError('tampered')\n", encoding="utf-8")

    with pytest.raises(WorldBundleError) as captured:
        WorldBundleBackend(run_dir=run_dir)
    assert captured.value.code == "world_bundle_runtime_code_hash_mismatch"
