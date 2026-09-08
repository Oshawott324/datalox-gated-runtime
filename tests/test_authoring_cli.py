from __future__ import annotations

import hashlib
import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

import jsonschema

from datalox_gated_runtime.authoring_cli import main, run_harvest_request
from datalox_gated_runtime.behavior_harvest.engines import v3
from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import thaw_json
from datalox_gated_runtime.provider_differential import load_grounding_measurement

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / "tests/fixtures/behavior_harvest_v1"


def _digest(path: Path) -> str:
    return "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()


def _request(tmp_path: Path) -> tuple[Path, Path, dict[str, str]]:
    connector_path = FIXTURE / "sandbox_connector.json"
    recipe_path = FIXTURE / "widget_transition.behavior_recipe_v1.json"
    connector = v3.load_connector(
        connector_path,
        expected_sha256=_digest(connector_path),
    ).value
    static_inputs: dict[str, dict[str, str]] = {}
    for item in connector.static_json_inputs:
        path = tmp_path / f"{item.input_id}.json"
        path.write_text(
            json.dumps(thaw_json(item.expected_json), sort_keys=True) + "\n",
            encoding="utf-8",
        )
        static_inputs[item.input_id] = {"path": str(path), "sha256": _digest(path)}
    secret_environment = {
        item.name: f"DATALOX_TEST_{index}"
        for index, item in enumerate(connector.auth.secret_sources)
    }
    request = {
        "schema_version": "datalox_behavior_authoring_run_v1",
        "run_id": "authoring-test-1",
        "connector": {"path": str(connector_path), "sha256": _digest(connector_path)},
        "recipe": {"path": str(recipe_path), "sha256": _digest(recipe_path)},
        "engine": v3.current_engine_identity().to_dict(),
        "secret_environment": secret_environment,
        "static_inputs": static_inputs,
        "static_artifacts": {},
    }
    request_path = tmp_path / "authoring-request.json"
    request_path.write_text(json.dumps(request, indent=2) + "\n", encoding="utf-8")
    return request_path, tmp_path / "capture.json", secret_environment


def test_authoring_request_schema_is_valid() -> None:
    schema = json.loads(
        (ROOT / "schemas/behavior-authoring-run-v1.schema.json").read_text(encoding="utf-8")
    )
    jsonschema.Draft202012Validator.check_schema(schema)


def test_authoring_cli_uses_only_digest_pinned_reviewed_inputs(
    tmp_path: Path, capsys: object
) -> None:
    request_path, output_path, secret_environment = _request(tmp_path)
    captured: dict[str, object] = {}

    def fake_run(_self: object, **kwargs: object) -> object:
        captured.update(kwargs)
        connector = v3.load_connector(
            kwargs["connector_path"],  # type: ignore[arg-type]
            expected_sha256=kwargs["expected_connector_sha256"],  # type: ignore[arg-type]
        ).value
        recipe = v3.load_recipe(
            kwargs["recipe_path"],  # type: ignore[arg-type]
            expected_sha256=kwargs["expected_recipe_sha256"],  # type: ignore[arg-type]
        ).value
        output_path.write_text("{}\n", encoding="utf-8")
        capture = type("Capture", (), {"connector": connector, "recipe": recipe})()
        return type(
            "Result",
            (),
            {
                "artifact_path": output_path,
                "artifact_sha256": _digest(output_path),
                "capture": capture,
            },
        )()

    environment = {name: f"secret-{name}" for name in secret_environment.values()}
    with (
        patch.dict(os.environ, environment, clear=False),
        patch.object(v3.BehaviorHarvester, "run", fake_run),
        patch.object(
            sys,
            "argv",
            [
                "datalox-author",
                "harvest",
                "--request",
                str(request_path),
                "--out",
                str(output_path),
                "--execute-sandbox-writes",
                "--json",
            ],
        ),
    ):
        assert main() == 0
    result = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert result["capture"] == str(output_path.resolve())
    assert captured["execute_sandbox_writes"] is True
    assert captured["expected_engine"] == v3.current_engine_identity()
    assert captured["sensitive_values"] == {
        name: environment[variable].encode("utf-8") for name, variable in secret_environment.items()
    }
    assert not any(secret in json.dumps(result) for secret in environment.values())


def test_authoring_cli_requires_exact_secret_bindings(tmp_path: Path, capsys: object) -> None:
    request_path, output_path, _ = _request(tmp_path)
    request = json.loads(request_path.read_text(encoding="utf-8"))
    request["secret_environment"] = {}
    request_path.write_text(json.dumps(request), encoding="utf-8")
    with patch.object(
        sys,
        "argv",
        [
            "datalox-author",
            "harvest",
            "--request",
            str(request_path),
            "--out",
            str(output_path),
            "--json",
        ],
    ):
        assert main() == 1
    error = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert error["error"]["code"] == "authoring_secret_binding_invalid"


def test_authoring_measurement_arguments_fail_before_provider_execution(
    tmp_path: Path, capsys: object
) -> None:
    request_path, output_path, _ = _request(tmp_path)
    with (
        patch.object(v3.BehaviorHarvester, "run") as provider_run,
        patch.object(
            sys,
            "argv",
            [
                "datalox-author",
                "harvest",
                "--request",
                str(request_path),
                "--out",
                str(output_path),
                "--measurement-out",
                str(tmp_path / "measurement.json"),
                "--json",
            ],
        ),
    ):
        assert main() == 1
    provider_run.assert_not_called()
    error = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert error["error"]["code"] == "authoring_measurement_arguments_invalid"


def test_authoring_output_collision_fails_before_provider_execution(
    tmp_path: Path, capsys: object
) -> None:
    request_path, output_path, _ = _request(tmp_path)
    with (
        patch.object(v3.BehaviorHarvester, "run") as provider_run,
        patch.object(
            sys,
            "argv",
            [
                "datalox-author",
                "harvest",
                "--request",
                str(request_path),
                "--out",
                str(output_path),
                "--compiled-out",
                str(output_path),
                "--json",
            ],
        ),
    ):
        assert main() == 1
    provider_run.assert_not_called()
    error = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert error["error"]["code"] == "authoring_output_collision"


def test_complete_measurement_requires_compiled_artifact_before_provider_execution(
    tmp_path: Path, capsys: object
) -> None:
    request_path, output_path, _ = _request(tmp_path)
    with (
        patch.object(v3.BehaviorHarvester, "run") as provider_run,
        patch.object(
            sys,
            "argv",
            [
                "datalox-author",
                "harvest",
                "--request",
                str(request_path),
                "--out",
                str(output_path),
                "--measurement-out",
                str(tmp_path / "measurement.json"),
                "--observed-at",
                "2026-09-07T10:00:00Z",
                "--rights-ref",
                "authorized-test-source",
                "--distribution",
                "restricted",
                "--json",
            ],
        ),
    ):
        assert main() == 1
    provider_run.assert_not_called()
    error = json.loads(capsys.readouterr().out)  # type: ignore[attr-defined]
    assert error["error"]["code"] == "authoring_measurement_arguments_invalid"


def test_authoring_emits_bound_program_and_grounding_measurement(tmp_path: Path) -> None:
    request_path, capture_path, secret_environment = _request(tmp_path)
    program_path = tmp_path / "program.json"
    measurement_path = tmp_path / "measurement.json"

    def fake_run(_self: object, **kwargs: object) -> object:
        connector = v3.load_connector(
            kwargs["connector_path"],  # type: ignore[arg-type]
            expected_sha256=kwargs["expected_connector_sha256"],  # type: ignore[arg-type]
        ).value
        recipe = v3.load_recipe(
            kwargs["recipe_path"],  # type: ignore[arg-type]
            expected_sha256=kwargs["expected_recipe_sha256"],  # type: ignore[arg-type]
        ).value
        capture_path.write_text("{}\n", encoding="utf-8")
        capture = type(
            "Capture",
            (),
            {
                "connector": connector,
                "connector_sha256": kwargs["expected_connector_sha256"],
                "recipe": recipe,
                "recipe_sha256": kwargs["expected_recipe_sha256"],
                "engine": kwargs["expected_engine"],
            },
        )()
        return type(
            "Result",
            (),
            {
                "artifact_path": capture_path,
                "artifact_sha256": _digest(capture_path),
                "capture": capture,
            },
        )()

    compiled_digest = "sha256:" + "c" * 64

    def fake_write(path: Path, _program: object) -> str:
        path.write_text("{}\n", encoding="utf-8")
        return compiled_digest

    environment = {name: f"secret-{name}" for name in secret_environment.values()}
    with (
        patch.dict(os.environ, environment, clear=False),
        patch.object(v3.BehaviorHarvester, "run", fake_run),
        patch(
            "datalox_gated_runtime.authoring_cli.compile_v3_reference_program",
            return_value=object(),
        ) as compile_program,
        patch(
            "datalox_gated_runtime.authoring_cli.write_compiled_behavior_program",
            side_effect=fake_write,
        ),
    ):
        result = run_harvest_request(
            request_path=request_path,
            output_path=capture_path,
            execute_sandbox_writes=True,
            compiled_output_path=program_path,
            measurement_output_path=measurement_path,
            observed_at="2026-09-07T10:00:00Z",
            rights_ref="authorized-test-source",
            distribution="restricted",
        )

    measurement = load_grounding_measurement(measurement_path)
    request = json.loads(request_path.read_text(encoding="utf-8"))
    assert measurement.capture_sha256 == result["capture_sha256"]
    assert measurement.connector_sha256 == request["connector"]["sha256"]
    assert measurement.recipe_sha256 == request["recipe"]["sha256"]
    assert measurement.harvest_engine_sha256 == v3.current_engine_identity().source_sha256
    assert measurement.compiled_program_sha256 == compiled_digest
    assert measurement.distribution == "restricted"
    assert result["compiled_program_sha256"] == compiled_digest
    assert result["measurement_sha256"] == measurement.sha256
    compile_program.assert_called_once()
    serialized = json.dumps(result) + measurement_path.read_text(encoding="utf-8")
    assert not any(secret in serialized for secret in environment.values())
