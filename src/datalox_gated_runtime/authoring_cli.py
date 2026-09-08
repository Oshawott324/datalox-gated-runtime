"""Explicit live-provider authoring entry point.

This executable is intentionally separate from the evaluated-agent runtime. It
loads only digest-pinned behavior-harvest inputs and never participates in a
rollout session.
"""

from __future__ import annotations

import argparse
import json
import os
import re
from pathlib import Path
from typing import Any

from datalox_gated_runtime.provider_differential.compiled_program import (
    compile_v3_reference_program,
    write_compiled_behavior_program,
)
from datalox_gated_runtime.behavior_harvest.engines import v3
from datalox_gated_runtime.json_digest import canonical_json_bytes
from datalox_gated_runtime.provider_differential import GroundingMeasurement

AUTHORING_RUN_SCHEMA_VERSION = "datalox_behavior_authoring_run_v1"
_IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")
_SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")


class AuthoringCliError(ValueError):
    """A stable authoring-command contract failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _load_json(path: Path) -> dict[str, Any]:
    def reject_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        value: dict[str, Any] = {}
        for key, item in pairs:
            if key in value:
                raise AuthoringCliError(
                    "authoring_request_json_invalid",
                    f"Authoring request contains duplicate key {key!r}.",
                )
            value[key] = item
        return value

    try:
        value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicates)
    except AuthoringCliError:
        raise
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise AuthoringCliError(
            "authoring_request_json_invalid",
            f"Could not load authoring request: {exc}.",
        ) from exc
    if type(value) is not dict:
        raise AuthoringCliError(
            "authoring_request_invalid",
            "Authoring request must contain one JSON object.",
        )
    return value


def _shape(
    value: Any,
    *,
    required: frozenset[str],
    path: str,
) -> dict[str, Any]:
    if type(value) is not dict:
        raise AuthoringCliError("authoring_request_invalid", f"{path} must be an object.")
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - required)
    if missing or unknown:
        raise AuthoringCliError(
            "authoring_request_invalid",
            f"{path} has an invalid shape; missing={missing}, unknown={unknown}.",
        )
    return value


def _identifier(value: Any, *, path: str) -> str:
    if type(value) is not str or _IDENTIFIER.fullmatch(value) is None:
        raise AuthoringCliError(
            "authoring_request_invalid",
            f"{path} must be a stable identifier.",
        )
    return value


def _digest(value: Any, *, path: str) -> str:
    if type(value) is not str or _SHA256.fullmatch(value) is None:
        raise AuthoringCliError(
            "authoring_request_invalid",
            f"{path} must be an exact SHA-256 digest.",
        )
    return value


def _path_entry(value: Any, *, path: str, base: Path, with_digest: bool) -> tuple[Path, str | None]:
    required = frozenset({"path", "sha256"}) if with_digest else frozenset({"path"})
    raw = _shape(value, required=required, path=path)
    raw_path = raw["path"]
    if type(raw_path) is not str or not raw_path:
        raise AuthoringCliError(
            "authoring_request_invalid",
            f"{path}.path must be a non-empty string.",
        )
    candidate = Path(raw_path)
    resolved = (
        (base / candidate).resolve(strict=True)
        if not candidate.is_absolute()
        else candidate.resolve(strict=True)
    )
    if not resolved.is_file():
        raise AuthoringCliError(
            "authoring_input_invalid",
            f"{path}.path must resolve to a file.",
        )
    expected = _digest(raw["sha256"], path=f"{path}.sha256") if with_digest else None
    return resolved, expected


def _named_entries(value: Any, *, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise AuthoringCliError("authoring_request_invalid", f"{path} must be an object.")
    result: dict[str, Any] = {}
    for name, item in value.items():
        result[_identifier(name, path=f"{path} key")] = item
    return result


def run_harvest_request(
    *,
    request_path: Path,
    output_path: Path,
    execute_sandbox_writes: bool,
    compiled_output_path: Path | None = None,
    measurement_output_path: Path | None = None,
    observed_at: str | None = None,
    rights_ref: str | None = None,
    distribution: str | None = None,
    source_reset_receipt_sha256: str | None = None,
) -> dict[str, Any]:
    measurement_fields = (observed_at, rights_ref, distribution)
    if measurement_output_path is None and any(item is not None for item in measurement_fields):
        raise AuthoringCliError(
            "authoring_measurement_arguments_invalid",
            "Measurement metadata requires --measurement-out.",
        )
    if measurement_output_path is not None and any(item is None for item in measurement_fields):
        raise AuthoringCliError(
            "authoring_measurement_arguments_invalid",
            "--measurement-out requires --observed-at, --rights-ref, and --distribution.",
        )
    if measurement_output_path is not None and compiled_output_path is None:
        raise AuthoringCliError(
            "authoring_measurement_arguments_invalid",
            "--measurement-out requires --compiled-out so the measurement binds the exact "
            "portable program artifact.",
        )
    _validate_output_plan(output_path, compiled_output_path, measurement_output_path)
    request_file = request_path.resolve(strict=True)
    raw = _shape(
        _load_json(request_file),
        required=frozenset(
            {
                "schema_version",
                "run_id",
                "connector",
                "recipe",
                "engine",
                "secret_environment",
                "static_inputs",
                "static_artifacts",
            }
        ),
        path="authoring_request",
    )
    if raw["schema_version"] != AUTHORING_RUN_SCHEMA_VERSION:
        raise AuthoringCliError(
            "authoring_request_version_unsupported",
            "Authoring request schema version is unsupported.",
        )
    run_id = _identifier(raw["run_id"], path="authoring_request.run_id")
    base = request_file.parent
    connector_path, connector_sha256 = _path_entry(
        raw["connector"], path="authoring_request.connector", base=base, with_digest=True
    )
    recipe_path, recipe_sha256 = _path_entry(
        raw["recipe"], path="authoring_request.recipe", base=base, with_digest=True
    )
    assert connector_sha256 is not None and recipe_sha256 is not None
    try:
        expected_engine = v3.EngineIdentity.from_dict(raw["engine"])
        connector = v3.load_connector(
            connector_path,
            expected_sha256=connector_sha256,
        ).value
    except (v3.BehaviorContractError, v3.BehaviorHarvestError) as exc:
        raise AuthoringCliError(
            getattr(exc, "code", "authoring_input_invalid"),
            str(exc),
        ) from exc

    secret_environment = _named_entries(
        raw["secret_environment"], path="authoring_request.secret_environment"
    )
    declared_secrets = {item.name: item for item in connector.auth.secret_sources}
    if set(secret_environment) != set(declared_secrets):
        raise AuthoringCliError(
            "authoring_secret_binding_invalid",
            "Authoring request must bind every declared secret source exactly once.",
        )
    sensitive_values: dict[str, bytes] = {}
    for name, environment_variable in secret_environment.items():
        if declared_secrets[name].kind != "environment":
            raise AuthoringCliError(
                "authoring_secret_source_unsupported",
                f"Generic authoring supports environment secret source {name!r} only.",
            )
        if (
            type(environment_variable) is not str
            or _IDENTIFIER.fullmatch(environment_variable) is None
        ):
            raise AuthoringCliError(
                "authoring_secret_binding_invalid",
                f"Environment variable binding for {name!r} is invalid.",
            )
        try:
            sensitive_values[name] = os.environ[environment_variable].encode("utf-8")
        except KeyError as exc:
            raise AuthoringCliError(
                "authoring_secret_missing",
                f"Required authoring environment variable is absent for {name!r}.",
            ) from exc

    static_inputs_raw = _named_entries(raw["static_inputs"], path="authoring_request.static_inputs")
    declared_inputs = {item.input_id for item in connector.static_json_inputs}
    if set(static_inputs_raw) != declared_inputs:
        raise AuthoringCliError(
            "authoring_static_input_binding_invalid",
            "Authoring request must bind every declared static JSON input exactly once.",
        )
    static_input_paths: dict[str, Path] = {}
    static_input_digests: dict[str, str] = {}
    for input_id, entry in static_inputs_raw.items():
        path, digest = _path_entry(
            entry,
            path=f"authoring_request.static_inputs.{input_id}",
            base=base,
            with_digest=True,
        )
        assert digest is not None
        static_input_paths[input_id] = path
        static_input_digests[input_id] = digest

    static_artifacts_raw = _named_entries(
        raw["static_artifacts"], path="authoring_request.static_artifacts"
    )
    declared_artifacts = {item.artifact_id for item in connector.static_artifact_inputs}
    if set(static_artifacts_raw) != declared_artifacts:
        raise AuthoringCliError(
            "authoring_static_artifact_binding_invalid",
            "Authoring request must bind every declared static artifact exactly once.",
        )
    static_artifact_paths = {
        artifact_id: _path_entry(
            entry,
            path=f"authoring_request.static_artifacts.{artifact_id}",
            base=base,
            with_digest=False,
        )[0]
        for artifact_id, entry in static_artifacts_raw.items()
    }

    try:
        result = v3.BehaviorHarvester().run(
            connector_path=connector_path,
            recipe_path=recipe_path,
            expected_connector_sha256=connector_sha256,
            expected_recipe_sha256=recipe_sha256,
            expected_engine=expected_engine,
            run_id=run_id,
            output_path=output_path,
            sensitive_values=sensitive_values,
            static_input_paths=static_input_paths,
            expected_static_input_sha256=static_input_digests,
            static_artifact_paths=static_artifact_paths,
            execute_sandbox_writes=execute_sandbox_writes,
        )
    except (v3.BehaviorContractError, v3.BehaviorHarvestError) as exc:
        raise AuthoringCliError(getattr(exc, "code", "behavior_harvest_failed"), str(exc)) from exc
    payload = {
        "schema_version": AUTHORING_RUN_SCHEMA_VERSION,
        "run_id": run_id,
        "capture": str(result.artifact_path.resolve()),
        "capture_sha256": result.artifact_sha256,
        "provider_id": result.capture.connector.provider_id,
        "provider_version": result.capture.connector.provider_version,
        "program_id": result.capture.recipe.program_id,
    }
    program_sha256: str | None = None
    if compiled_output_path is not None:
        try:
            program = compile_v3_reference_program(
                capture_path=result.artifact_path,
                expected_capture_sha256=result.artifact_sha256,
                connector_path=connector_path,
                expected_connector_sha256=connector_sha256,
                recipe_path=recipe_path,
                expected_recipe_sha256=recipe_sha256,
                expected_engine=expected_engine,
                sensitive_values=sensitive_values,
                static_input_paths=static_input_paths,
                expected_static_input_sha256=static_input_digests,
                static_artifact_paths=static_artifact_paths,
            )
            program_sha256 = write_compiled_behavior_program(
                compiled_output_path,
                program,
            )
        except v3.BehaviorContractError as exc:
            raise AuthoringCliError(
                getattr(exc, "code", "compiled_behavior_program_invalid"),
                str(exc),
            ) from exc
        payload["compiled_program"] = str(compiled_output_path.resolve())
        payload["compiled_program_sha256"] = program_sha256

    if measurement_output_path is not None:
        assert observed_at is not None and rights_ref is not None and distribution is not None
        assert program_sha256 is not None
        try:
            measurement = GroundingMeasurement(
                measurement_id=run_id,
                provider_id=result.capture.connector.provider_id,
                provider_version=result.capture.connector.provider_version,
                program_id=result.capture.recipe.program_id,
                observed_at=observed_at,
                capture_sha256=result.artifact_sha256,
                connector_sha256=result.capture.connector_sha256,
                recipe_sha256=result.capture.recipe_sha256,
                harvest_engine_sha256=result.capture.engine.source_sha256,
                compiled_program_sha256=program_sha256,
                completion="complete",
                rights_ref=rights_ref,
                distribution=distribution,
                source_reset_receipt_sha256=source_reset_receipt_sha256,
            )
        except Exception as exc:
            raise AuthoringCliError(
                getattr(exc, "code", "authoring_measurement_invalid"),
                str(exc),
            ) from exc
        _write_json_exclusive(measurement_output_path, measurement.to_dict())
        payload["measurement"] = str(measurement_output_path.resolve())
        payload["measurement_sha256"] = measurement.sha256
    return payload


def _validate_output_plan(*paths: Path | None) -> None:
    present = [path.absolute() for path in paths if path is not None]
    if len(present) != len(set(present)):
        raise AuthoringCliError(
            "authoring_output_collision",
            "Capture, compiled program, and measurement outputs must be different paths.",
        )
    for path in present:
        if not path.parent.is_dir():
            raise AuthoringCliError(
                "authoring_output_parent_invalid",
                f"Authoring output directory does not exist: {path.parent}.",
            )
        if path.exists() or path.is_symlink():
            raise AuthoringCliError(
                "authoring_output_exists",
                f"Authoring output already exists: {path}.",
            )


def _write_json_exclusive(path: Path, value: dict[str, Any]) -> None:
    if not path.parent.is_dir():
        raise AuthoringCliError(
            "authoring_output_parent_invalid",
            "Authoring output directory does not exist.",
        )
    body = canonical_json_bytes(value) + b"\n"
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError as exc:
        raise AuthoringCliError(
            "authoring_output_exists",
            f"Authoring output already exists: {path}.",
        ) from exc
    try:
        with os.fdopen(descriptor, "wb") as output:
            descriptor = -1
            output.write(body)
            output.flush()
            os.fsync(output.fileno())
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        path.unlink(missing_ok=True)
        raise


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="datalox-author")
    subcommands = parser.add_subparsers(dest="command", required=True)
    engine = subcommands.add_parser(
        "engine-identity", help="Print the installed digest-pinned authoring engine identity."
    )
    engine.add_argument("--json", action="store_true")
    harvest = subcommands.add_parser(
        "harvest", help="Run one reviewed provider behavior program against an authorized source."
    )
    harvest.add_argument("--request", required=True)
    harvest.add_argument("--out", required=True)
    harvest.add_argument(
        "--compiled-out",
        help="Write the portable, offline differential program produced from this capture.",
    )
    harvest.add_argument(
        "--measurement-out",
        help="Write a grounding measurement bound to this completed capture.",
    )
    harvest.add_argument("--observed-at")
    harvest.add_argument("--rights-ref")
    harvest.add_argument(
        "--distribution",
        choices=("public", "restricted", "private"),
    )
    harvest.add_argument("--source-reset-receipt-sha256")
    harvest.add_argument(
        "--execute-sandbox-writes",
        action="store_true",
        help="Explicitly authorize mutation steps in the reviewed behavior recipe.",
    )
    harvest.add_argument("--json", action="store_true")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    if args.command == "engine-identity":
        payload = v3.current_engine_identity().to_dict()
        print(json.dumps(payload, indent=2, sort_keys=True) if args.json else payload)
        return 0
    try:
        payload = run_harvest_request(
            request_path=Path(args.request),
            output_path=Path(args.out),
            execute_sandbox_writes=args.execute_sandbox_writes,
            compiled_output_path=(None if args.compiled_out is None else Path(args.compiled_out)),
            measurement_output_path=(
                None if args.measurement_out is None else Path(args.measurement_out)
            ),
            observed_at=args.observed_at,
            rights_ref=args.rights_ref,
            distribution=args.distribution,
            source_reset_receipt_sha256=args.source_reset_receipt_sha256,
        )
    except (AuthoringCliError, FileNotFoundError, OSError) as exc:
        code = getattr(exc, "code", "authoring_command_failed")
        error = {"error": {"code": code, "message": str(exc)}}
        if args.json:
            print(json.dumps(error, indent=2, sort_keys=True))
        else:
            parser.error(f"{code}: {exc}")
        return 1
    print(json.dumps(payload, indent=2, sort_keys=True) if args.json else payload["capture"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
