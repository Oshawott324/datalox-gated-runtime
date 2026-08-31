from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from datetime import UTC, datetime
from pathlib import Path

from datalox_gated_runtime.auth import preflight_auth
from datalox_gated_runtime.config import load_gate_config
from datalox_gated_runtime.composition.admission import (
    CompositionAdmissionError,
    validate_composition_authoring_inputs,
)
from datalox_gated_runtime.composition.authoring import (
    CompositionAuthoringError,
    admit_candidate_composition_pack,
)
from datalox_gated_runtime.composition.pack import (
    CompositionPackError,
    load_composition_pack,
)
from datalox_gated_runtime.documented_provider import compile_documented_provider_env
from datalox_gated_runtime.harness_adapters.envfactory import build_envfactory_projection
from datalox_gated_runtime.http_server import create_app
from datalox_gated_runtime.import_source_pack import import_source_pack
from datalox_gated_runtime.interception.control import (
    InterceptionControlError,
    export_provider_runs,
    reset_provider_runs,
)
from datalox_gated_runtime.interception.deployment import export_interception_deployment
from datalox_gated_runtime.interception.server import (
    check_interception_ready,
    prepare_admitted_interception_run,
    prepare_interception_run,
    serve_admitted_interception_gateway,
    serve_interception_gateway,
)
from datalox_gated_runtime.kubernetes_openapi import compile_kubernetes_openapi_env
from datalox_gated_runtime.mcp_server import run_mcp
from datalox_gated_runtime.promote import promote_session
from datalox_gated_runtime.provider_probe import (
    rollup_probe_reports,
    run_provider_auth_preflight,
    run_provider_probe,
)
from datalox_gated_runtime.provider_runtime import (
    ProviderRuntimeError,
    admit_provider_runtime,
    build_provider_runtime_from_gate_config,
    build_provider_runtime_from_world,
)
from datalox_gated_runtime.provider_runtime.registry import (
    FilesystemProviderReleaseRegistry,
)
from datalox_gated_runtime.provider_runtime.release import (
    ProviderReleaseProfileInput,
    build_provider_release,
)
from datalox_gated_runtime.rollout.docker import (
    DockerRolloutError,
    run_docker_rollout,
    run_docker_rollout_provider_set_v2,
)
from datalox_gated_runtime.rollout.composition import CompositionRolloutConfig
from datalox_gated_runtime.rollout.pool import RolloutPool, RolloutPoolError, serve_rollout_pool
from datalox_gated_runtime.rollout.provider_set import (
    ProviderReleaseSelection,
    RolloutProviderSetError,
    materialize_rollout_provider_set_v2,
    write_rollout_provider_set,
    write_rollout_provider_set_v2,
)
from datalox_gated_runtime.server_control import (
    pick_free_port,
    running_server_pid,
    start_server,
    stop_server,
)
from datalox_gated_runtime.session import (
    SessionCreationError,
    create_session,
    finalize_session,
    load_session_manifest,
)
from datalox_gated_runtime.verify import verify_replay, verify_report_payload
from datalox_gated_runtime.world_v1.admission import admit_world, write_admission_artifact
from datalox_gated_runtime.world_v1.admission_runtime import runtime_admission_callbacks
from datalox_gated_runtime.world_v1.contracts import ActorContext
from datalox_gated_runtime.world_v1.interop import export_world_interop


def _session_create(args: argparse.Namespace) -> int:
    try:
        manifest = create_session(
            example=args.example,
            out_dir=Path(args.out),
            http_port=args.port,
            seed=args.seed,
        )
    except SessionCreationError as exc:
        return _handle_command_error(args.json, str(exc), code=exc.code)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    payload = asdict(manifest)
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Session manifest written: {manifest.run_dir}/session_manifest.json")
        print(f"HTTP base URL: {manifest.http_base_url}")
    return 0


def _session_start(args: argparse.Namespace) -> int:
    run_dir = Path(args.out)
    running_pid = running_server_pid(run_dir)
    if running_pid is not None:
        return _handle_command_error(
            args.json, f"server already running for run directory: pid {running_pid}"
        )

    port = args.port if args.port is not None else pick_free_port()
    try:
        manifest = create_session(
            example=args.example,
            out_dir=run_dir,
            http_port=port,
            seed=args.seed,
        )
        server = start_server(run_dir=Path(manifest.run_dir), port=port)
    except SessionCreationError as exc:
        return _handle_command_error(args.json, str(exc), code=exc.code)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    payload = asdict(manifest)
    payload["server"] = server
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Session ready: {manifest.run_dir}")
        print(f"HTTP base URL: {manifest.http_base_url}")
        print(f"Server pid: {server['pid']}")
    return 0


def _session_stop(args: argparse.Namespace) -> int:
    try:
        payload = stop_server(Path(args.run))
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif payload["stopped"]:
        print("Server stopped.")
    else:
        print("Server already stopped.")
    return 0


def _session_finalize(args: argparse.Namespace) -> int:
    run_dir = Path(args.run)
    try:
        payload = finalize_session(run_dir)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    audit_path = run_dir / "audit.json"

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Audit result: {'passed' if payload['passed'] else 'failed'}")
        print(f"Audit file: {audit_path}")
    return 0 if payload["passed"] else 1


def _session_promote(args: argparse.Namespace) -> int:
    try:
        payload = promote_session(run_dir=Path(args.run), out_dir=Path(args.out))
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Promoted environment: {payload['out_dir']}")
        print(f"Response cases: {payload['response_case_count']}")
        print(f"Draft audit rules: {payload['draft_rule_count']}")
        print(f"Replay steps: {payload['replay_step_count']}")
    return 0


def _session_check(args: argparse.Namespace) -> int:
    run_dir = Path(args.run).resolve()
    manifest_path = run_dir / "session_manifest.json"
    if not manifest_path.exists():
        return _handle_command_error(args.json, f"session manifest not found: {manifest_path}")

    try:
        manifest = load_session_manifest(run_dir)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    gate_config_path = run_dir / "gate_config.json"
    try:
        gate_config = load_gate_config(gate_config_path)
    except (ValueError, FileNotFoundError) as exc:
        if args.json:
            payload = {
                "ok": False,
                "manifest_exists": True,
                "gate_config_valid": False,
                "response_case_count": 0,
                "expected_surfaces": manifest.expected_surfaces,
                "http_base_url": manifest.http_base_url,
                "commands": manifest.commands,
                "error": {"code": "invalid_gate_config", "message": str(exc)},
            }
            print(json.dumps(payload, indent=2, sort_keys=True))
            return 1
        return _handle_command_error(args.json, str(exc))

    payload = {
        "ok": True,
        "manifest_exists": True,
        "gate_config_valid": True,
        "response_case_count": len(gate_config.response_cases),
        "expected_surfaces": manifest.expected_surfaces,
        "http_base_url": manifest.http_base_url,
        "commands": manifest.commands,
    }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Session ready.")
    return 0


def _session_auth_preflight(args: argparse.Namespace) -> int:
    try:
        gate_config = load_gate_config(Path(args.run) / "gate_config.json")
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    profile_ids = []
    if gate_config.live is not None:
        profile_ids = [
            upstream.auth_profile
            for upstream in gate_config.live.upstreams.values()
            if upstream.auth_profile is not None
        ]
    proof = preflight_auth(gate_config.auth_profiles, profile_ids)
    payload = {
        "auth_preflight": proof.to_dict(),
        "profile_ids": list(dict.fromkeys(profile_ids)),
        "status": "completed" if proof.status == "passed" else "blocked",
    }
    if proof.status == "failed":
        payload["blocker"] = {
            "code": "missing_auth_env",
            "message": "Required auth environment variables are not set.",
            "missing_env": proof.missing_env,
        }

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif proof.status == "failed":
        print("Session auth preflight blocked: missing_auth_env")
    else:
        print("Session auth preflight passed.")
    return 0 if proof.status == "passed" else 1


def _env_verify_replay(args: argparse.Namespace) -> int:
    env_dir = Path(args.env)
    try:
        result = verify_replay(env_dir)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(verify_report_payload(result), indent=2, sort_keys=True))
    else:
        print(f"Fidelity: {'passed' if result.fidelity_passed else 'failed'}")
        print(f"Misses: {len(result.miss_paths)}")
        print(f"Report: {env_dir / 'verify_report.json'}")
    return 0 if result.fidelity_passed else 1


def _env_import_source_pack(args: argparse.Namespace) -> int:
    try:
        payload = import_source_pack(source_dir=Path(args.source), out_dir=Path(args.out))
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Imported source pack: {payload['out_dir']}")
        print(f"Response cases: {payload['response_case_count']}")
        print(f"Skipped cases: {payload['skipped_count']}")
    return 0


def _env_compile_kubernetes_openapi(args: argparse.Namespace) -> int:
    try:
        payload = compile_kubernetes_openapi_env(
            openapi_source=args.openapi,
            out_dir=Path(args.out),
            source_url=args.source_url,
            kubernetes_version=args.kubernetes_version,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Compiled Kubernetes OpenAPI env: {payload['out_dir']}")
        print(f"Response cases: {payload['response_case_count']}")
        print(f"Skipped GET operations: {payload['skipped_count']}")
    return 0


def _env_compile_documented_provider(args: argparse.Namespace) -> int:
    try:
        payload = compile_documented_provider_env(
            source=Path(args.source),
            out_dir=Path(args.out),
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))

    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Compiled documented provider env: {payload['out_dir']}")
        print(f"Response cases: {payload['response_case_count']}")
        print(f"Service families: {payload['family_count']}")
    return 0


def _env_admit_world(args: argparse.Namespace) -> int:
    env_dir = Path(args.env).resolve()
    admission_path = env_dir / "world_admission.json"
    try:
        admission_path.unlink(missing_ok=True)
        report = admit_world(
            env_dir,
            callbacks=runtime_admission_callbacks(),
        )
        if report.admitted:
            write_admission_artifact(report, path=admission_path)
    except (ValueError, FileNotFoundError, OSError) as exc:
        return _handle_command_error(args.json, str(exc))

    payload = report.to_dict()
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"World admission: {'passed' if report.admitted else 'failed'}")
        if report.admitted:
            print(f"Admission artifact: {admission_path}")
        else:
            for finding in report.findings:
                print(f"- {finding.code}: {finding.message}")
    return 0 if report.admitted else 1


def _env_export_world(args: argparse.Namespace) -> int:
    try:
        payload = export_world_interop(
            env_dir=Path(args.env),
            out_dir=Path(args.out),
            format=args.format,
            episode_id=args.episode,
        )
    except (ValueError, FileNotFoundError, OSError) as exc:
        return _handle_command_error(args.json, str(exc))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Exported {args.format}: {payload['out_dir']}")
    return 0


def _provider_probe(args: argparse.Namespace) -> int:
    exit_code, payload = run_provider_probe(
        config_path=Path(args.config),
        out_dir=Path(args.out),
    )
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif payload.get("status") == "blocked":
        blocker = payload.get("blocker", {})
        code = blocker.get("code") if isinstance(blocker, dict) else "blocked"
        print(f"Provider probe blocked: {code}")
    else:
        counts = payload.get("counts", {})
        print(f"Provider probe completed: {payload.get('provider_id')}")
        print(
            f"Requests attempted: {counts.get('attempted', 0) if isinstance(counts, dict) else 0}"
        )
    return exit_code


def _provider_auth_preflight(args: argparse.Namespace) -> int:
    exit_code, payload = run_provider_auth_preflight(config_path=Path(args.config))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    elif payload.get("status") == "blocked":
        blocker = payload.get("blocker", {})
        code = blocker.get("code") if isinstance(blocker, dict) else "blocked"
        print(f"Provider auth preflight blocked: {code}")
    else:
        print(f"Provider auth preflight passed: {payload.get('provider_id')}")
    return exit_code


def _provider_probe_rollup(args: argparse.Namespace) -> int:
    try:
        payload = rollup_probe_reports(Path(args.runs))
    except (ValueError, FileNotFoundError, json.JSONDecodeError) as exc:
        return _handle_command_error(args.json, str(exc))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Providers probed: {payload['providers_probed']}")
        print(f"Responses captured: {payload['responses_captured']}")
    return 0


def _provider_build_runtime(args: argparse.Namespace) -> int:
    try:
        if args.source_world:
            if not args.episode_id:
                raise ValueError("--episode-id is required with --source-world")
            manifest = build_provider_runtime_from_world(
                source_world_dir=Path(args.source_world),
                output_dir=Path(args.out),
                provider_id=args.provider_id,
                authorities=tuple(args.authority),
                episode_id=args.episode_id,
                identity_policy_path=(Path(args.identity_policy) if args.identity_policy else None),
            )
        else:
            if args.episode_id:
                raise ValueError("--episode-id applies only to --source-world")
            if args.identity_policy:
                raise ValueError("--identity-policy applies only to --source-world")
            manifest = build_provider_runtime_from_gate_config(
                source_gate_config=Path(args.source_gate_config),
                output_dir=Path(args.out),
                provider_id=args.provider_id,
                authorities=tuple(args.authority),
                bundle_version=args.bundle_version,
            )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))
    payload = {"manifest": str(manifest), "provider_id": args.provider_id}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Provider runtime manifest: {manifest}")
    return 0


def _provider_admit(args: argparse.Namespace) -> int:
    try:
        result = admit_provider_runtime(
            bundle_dir=Path(args.bundle),
            claims_path=Path(args.claims),
            output_path=Path(args.out),
        )
    except (ProviderRuntimeError, FileNotFoundError, OSError) as exc:
        code = exc.code if isinstance(exc, ProviderRuntimeError) else "provider_admission_failed"
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "admission": str(result.path),
        "admission_sha256": result.sha256,
        "provider_id": result.payload["provider_id"],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Provider admission: {result.path}")
        print(f"Digest: {result.sha256}")
    return 0


def _provider_release_build(args: argparse.Namespace) -> int:
    profiles = tuple(
        ProviderReleaseProfileInput(
            profile_id=profile_id,
            bundle_dir=Path(bundle),
            admission_path=Path(admission),
        )
        for profile_id, bundle, admission in args.profile
    )
    try:
        release = build_provider_release(
            profiles=profiles,
            release_version=args.release_version,
            output_dir=Path(args.out),
        )
    except (ProviderRuntimeError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code if isinstance(exc, ProviderRuntimeError) else "provider_release_build_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "provider_id": release.provider_id,
        "release_version": release.release_version,
        "release": str(release.root),
        "manifest_sha256": release.manifest_descriptor["digest"],
        "profiles": [profile.profile_id for profile in release.profiles],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Provider release: {payload['provider_id']}@{payload['release_version']}")
        print(f"OCI layout: {payload['release']}")
        print(f"Manifest: {payload['manifest_sha256']}")
    return 0


def _provider_registry_create(args: argparse.Namespace) -> int:
    try:
        registry = FilesystemProviderReleaseRegistry.create(Path(args.root))
    except (ProviderRuntimeError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code if isinstance(exc, ProviderRuntimeError) else "provider_registry_create_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {"registry": str(registry.root)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Provider registry: {registry.root}")
    return 0


def _provider_registry_publish(args: argparse.Namespace) -> int:
    try:
        registry = FilesystemProviderReleaseRegistry.load(Path(args.root))
        published = registry.publish(Path(args.release))
    except (ProviderRuntimeError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, ProviderRuntimeError)
            else "provider_registry_publish_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "registry": str(registry.root),
        "reference": published.reference,
        "manifest_sha256": published.manifest_digest,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Published provider release: {published.reference}")
        print(f"Manifest: {published.manifest_digest}")
    return 0


def _provider_registry_resolve(args: argparse.Namespace) -> int:
    try:
        registry = FilesystemProviderReleaseRegistry.load(Path(args.root))
        release = registry.resolve(args.reference)
    except (ProviderRuntimeError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, ProviderRuntimeError)
            else "provider_registry_resolve_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "registry": str(registry.root),
        "reference": args.reference,
        "provider_id": release.provider_id,
        "release_version": release.release_version,
        "manifest_sha256": release.manifest_descriptor["digest"],
        "profiles": [profile.profile_id for profile in release.profiles],
        "authorities": release.config["authorities"],
        "operation_contract_sha256": release.config["operation_contract_sha256"],
    }
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _provider_export_envfactory(args: argparse.Namespace) -> int:
    try:
        scenario_templates: dict[str, Path] = {}
        for declaration in args.scenario_template:
            template_id, separator, path = declaration.partition("=")
            if not separator or not template_id or not path:
                raise ValueError("--scenario-template must use TEMPLATE_ID=JSON_PATH")
            if template_id in scenario_templates:
                raise ValueError(f"duplicate scenario template id: {template_id}")
            scenario_templates[template_id] = Path(path)
        payload = build_envfactory_projection(
            source_world_dir=Path(args.source_world),
            trajectory_path=Path(args.trajectory),
            output_dir=Path(args.out),
            provider_id=args.provider_id,
            authorities=tuple(args.authority),
            episode_id=args.episode_id,
            server_name=args.server_name,
            scenario_templates=scenario_templates,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"EnvFactory projection: {payload['out_dir']}")
        print(f"Provider tools: {payload['tool_count']}")
    return 0


def _composition_provider_releases(args: argparse.Namespace) -> dict[str, Path]:
    result: dict[str, Path] = {}
    for provider_id, release_path in args.provider:
        if provider_id in result:
            raise ValueError(f"duplicate composition provider id: {provider_id}")
        result[provider_id] = Path(release_path)
    return result


def _composition_admitted_at(value: str | None) -> datetime | None:
    if value is None:
        return None
    if not value.endswith("Z"):
        raise ValueError("--admitted-at must be an RFC 3339 UTC timestamp ending in Z")
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except ValueError as exc:
        raise ValueError("--admitted-at must be a valid RFC 3339 UTC timestamp") from exc
    if parsed.utcoffset() != UTC.utcoffset(None):
        raise ValueError("--admitted-at must use UTC")
    return parsed.astimezone(UTC)


def _composition_validate(args: argparse.Namespace) -> int:
    try:
        releases = _composition_provider_releases(args)
        pack = load_composition_pack(Path(args.pack), provider_releases=releases)
        validated = validate_composition_authoring_inputs(
            pack=pack,
            provider_releases=releases,
            claims_path=Path(args.claims),
            admitted_at=_composition_admitted_at(args.admitted_at),
        )
    except (
        CompositionAdmissionError,
        CompositionAuthoringError,
        CompositionPackError,
        ProviderRuntimeError,
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        code = getattr(exc, "code", "composition_validate_failed")
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "valid": True,
        "pack_id": validated.pack.pack_id,
        "pack_version": validated.pack.pack_version,
        "composition_pack_sha256": validated.pack.canonical_sha256,
        "time_scope": validated.pack.time_scope,
        "claims_sha256": validated.claims_sha256,
        "provider_profiles": [
            {"provider_id": item.provider_id, "profile_id": item.profile_id}
            for item in validated.provider_profiles
        ],
        "required_coverage_count": len(validated.required_coverage),
        "probe_count": validated.probe_count,
        "step_count": validated.step_count,
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Composition authoring inputs valid: {validated.pack.pack_id}")
        print(f"Pack digest: {validated.pack.canonical_sha256}")
        print(f"Probe steps: {validated.step_count}")
    return 0


def _composition_admit(args: argparse.Namespace) -> int:
    try:
        releases = _composition_provider_releases(args)
        pack = load_composition_pack(Path(args.pack), provider_releases=releases)
        admission = admit_candidate_composition_pack(
            pack=pack,
            provider_releases=releases,
            claims_path=Path(args.claims),
            output_path=Path(args.out),
            work_dir=Path(args.run),
            admitted_at=_composition_admitted_at(args.admitted_at),
        )
    except (
        CompositionAdmissionError,
        CompositionAuthoringError,
        CompositionPackError,
        ProviderRuntimeError,
        FileNotFoundError,
        OSError,
        ValueError,
    ) as exc:
        code = getattr(exc, "code", "composition_admission_failed")
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "admission": str(admission.path),
        "admission_sha256": admission.canonical_sha256,
        "pack_id": admission.pack_id,
        "pack_version": admission.pack_version,
        "time_scope": admission.time_scope,
        "provider_profiles": [
            {"provider_id": item.provider_id, "profile_id": item.profile_id}
            for item in admission.provider_profiles
        ],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Composition admission: {admission.path}")
        print(f"Digest: {admission.canonical_sha256}")
    return 0


def _intercept_serve(args: argparse.Namespace) -> int:
    try:
        serve_interception_gateway(
            bundle_dirs=tuple(Path(path) for path in args.bundle),
            run_root=Path(args.run),
            host=args.host,
            port=args.port,
            prepared=args.prepared,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(False, str(exc))
    return 0


def _intercept_prepare(args: argparse.Namespace) -> int:
    try:
        path = prepare_interception_run(
            bundle_dirs=tuple(Path(item) for item in args.bundle),
            run_root=Path(args.run),
            trust_dir=Path(args.trust_dir) if args.trust_dir else None,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))
    payload = {"prepared": str(path)}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Prepared interception run: {path}")
    return 0


def _admitted_interception_bindings(
    args: argparse.Namespace,
) -> tuple[tuple[Path, Path, Path], ...]:
    bundles = tuple(Path(value) for value in args.bundle)
    admissions = tuple(Path(value) for value in args.admission)
    release_configs = tuple(Path(value) for value in args.release_config)
    if not (len(bundles) == len(admissions) == len(release_configs)):
        raise ValueError(
            "--bundle, --admission, and --release-config must be supplied the same number of times"
        )
    return tuple(zip(bundles, admissions, release_configs, strict=True))


def _intercept_prepare_admitted(args: argparse.Namespace) -> int:
    try:
        path = prepare_admitted_interception_run(
            bundle_admission_configs=_admitted_interception_bindings(args),
            run_root=Path(args.run),
            trust_dir=Path(args.trust_dir) if args.trust_dir else None,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))
    payload = {"prepared": str(path), "admitted": True}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Prepared admitted interception run: {path}")
    return 0


def _intercept_serve_admitted(args: argparse.Namespace) -> int:
    try:
        serve_admitted_interception_gateway(
            bundle_admission_configs=_admitted_interception_bindings(args),
            run_root=Path(args.run),
            host=args.host,
            port=args.port,
            prepared=args.prepared,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(False, str(exc))
    return 0


def _intercept_export(args: argparse.Namespace) -> int:
    try:
        path = export_interception_deployment(
            bundle_dirs=tuple(Path(item) for item in args.bundle),
            output_dir=Path(args.out),
            target=args.target,
            runtime_image=args.runtime_image,
            provider_image=args.provider_image,
            agent_container=args.agent_container,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(args.json, str(exc))
    payload = {"artifact": str(path), "target": args.target}
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Interception deployment artifact: {path}")
    return 0


def _intercept_ready(args: argparse.Namespace) -> int:
    try:
        payload = check_interception_ready(run_root=Path(args.run))
    except ValueError as exc:
        return _handle_command_error(args.json, str(exc), code="interception_not_ready")
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print("Interception gateway is ready.")
    return 0


def _intercept_control(args: argparse.Namespace) -> int:
    try:
        operation = export_provider_runs if args.operation == "export" else reset_provider_runs
        payload = operation(
            run_root=Path(args.run),
            provider_ids=tuple(args.provider_id),
        )
    except InterceptionControlError as exc:
        return _handle_command_error(args.json, str(exc), code="interception_control_failed")
    print(json.dumps(payload, indent=2, sort_keys=True))
    return 0


def _rollout_run(args: argparse.Namespace) -> int:
    if not args.consumer_command or args.consumer_command[0] != "--":
        return _handle_command_error(
            False,
            "consumer command must follow an explicit -- separator",
            code="rollout_command_missing",
        )
    consumer_command = tuple(args.consumer_command[1:])
    try:
        result = run_docker_rollout(
            provider_set_path=Path(args.provider_set),
            runtime_image=args.runtime_image,
            task_image=args.task_image,
            uid=args.uid,
            session_id=args.session_id,
            environment_seed=args.environment_seed,
            output_dir=Path(args.out),
            consumer_command=consumer_command,
        )
    except (DockerRolloutError, RolloutProviderSetError, FileNotFoundError, OSError) as exc:
        code = exc.code if isinstance(exc, RolloutProviderSetError) else "rollout_run_failed"
        return _handle_command_error(False, str(exc), code=code)
    print(f"Rollout export: {result.output_dir / 'rollout-export.json'}")
    return result.consumer_exit_code


def _rollout_run_v2(args: argparse.Namespace) -> int:
    if not args.consumer_command or args.consumer_command[0] != "--":
        return _handle_command_error(
            False,
            "consumer command must follow an explicit -- separator",
            code="rollout_command_missing",
        )
    consumer_command = tuple(args.consumer_command[1:])
    try:
        result = run_docker_rollout_provider_set_v2(
            provider_set_v2_path=Path(args.provider_set),
            registry=Path(args.registry),
            runtime_image=args.runtime_image,
            task_image=args.task_image,
            uid=args.uid,
            session_id=args.session_id,
            environment_seed=args.environment_seed,
            output_dir=Path(args.out),
            consumer_command=consumer_command,
        )
    except (DockerRolloutError, ProviderRuntimeError, RolloutProviderSetError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, (ProviderRuntimeError, RolloutProviderSetError))
            else "rollout_run_v2_failed"
        )
        return _handle_command_error(False, str(exc), code=code)
    print(f"Rollout export: {result.output_dir / 'rollout-export.json'}")
    return result.consumer_exit_code


def _rollout_provider_set(args: argparse.Namespace) -> int:
    try:
        provider_set = write_rollout_provider_set(
            bundle_dirs=tuple(Path(path) for path in args.bundle),
            output_path=Path(args.out),
        )
    except (RolloutProviderSetError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code if isinstance(exc, RolloutProviderSetError) else "provider_set_create_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "provider_set": str(provider_set.manifest_path),
        "providers": [provider.provider_id for provider in provider_set.providers],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Rollout provider set: {provider_set.manifest_path}")
        print(f"Providers: {', '.join(payload['providers'])}")
    return 0


def _rollout_provider_set_v2(args: argparse.Namespace) -> int:
    selections = tuple(
        ProviderReleaseSelection(release_reference=reference, profile_id=profile_id)
        for reference, profile_id in args.provider
    )
    try:
        provider_set = write_rollout_provider_set_v2(
            selections=selections,
            registry=Path(args.registry),
            output_path=Path(args.out),
        )
    except (ProviderRuntimeError, RolloutProviderSetError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, (ProviderRuntimeError, RolloutProviderSetError))
            else "provider_set_v2_create_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "provider_set": str(provider_set.manifest_path),
        "provider_set_sha256": provider_set.manifest_sha256,
        "providers": [provider.provider_id for provider in provider_set.providers],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Registry-backed provider set: {provider_set.manifest_path}")
        print(f"Digest: {provider_set.manifest_sha256}")
        print(f"Providers: {', '.join(payload['providers'])}")
    return 0


def _rollout_materialize_provider_set(args: argparse.Namespace) -> int:
    try:
        materialized = materialize_rollout_provider_set_v2(
            provider_set=Path(args.provider_set),
            registry=Path(args.registry),
            output_dir=Path(args.out),
        )
    except (ProviderRuntimeError, RolloutProviderSetError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, (ProviderRuntimeError, RolloutProviderSetError))
            else "provider_set_v2_materialize_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    payload = {
        "materialized_root": str(materialized.root),
        "provider_set": str(materialized.provider_set_v1_path),
        "controller_mapping": str(materialized.controller_mapping_path),
        "providers": [provider.provider_id for provider in materialized.providers],
    }
    if args.json:
        print(json.dumps(payload, indent=2, sort_keys=True))
    else:
        print(f"Materialized provider set: {materialized.root}")
        print(f"Controller mapping: {materialized.controller_mapping_path}")
    return 0


def _rollout_pool_serve(args: argparse.Namespace) -> int:
    import asyncio

    try:
        pool = RolloutPool(
            provider_set_path=Path(args.provider_set),
            runtime_image=args.runtime_image,
            allowed_task_images=tuple(args.task_image),
            capacity=args.capacity,
            artifacts_root=Path(args.artifacts_root),
        )
        asyncio.run(serve_rollout_pool(pool=pool, socket_path=Path(args.socket)))
    except KeyboardInterrupt:
        return 0
    except (RolloutPoolError, RolloutProviderSetError, FileNotFoundError, OSError) as exc:
        code = (
            exc.code
            if isinstance(exc, (RolloutPoolError, RolloutProviderSetError))
            else "pool_serve_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    return 0


def _rollout_pool_serve_v2(args: argparse.Namespace) -> int:
    import asyncio

    try:
        pool = RolloutPool.from_provider_set_v2(
            provider_set_v2_path=Path(args.provider_set),
            registry=Path(args.registry),
            runtime_image=args.runtime_image,
            allowed_task_images=tuple(args.task_image),
            capacity=args.capacity,
            artifacts_root=Path(args.artifacts_root),
        )
        asyncio.run(serve_rollout_pool(pool=pool, socket_path=Path(args.socket)))
    except KeyboardInterrupt:
        return 0
    except (
        ProviderRuntimeError,
        RolloutPoolError,
        RolloutProviderSetError,
        OSError,
    ) as exc:
        code = (
            exc.code
            if isinstance(
                exc,
                (ProviderRuntimeError, RolloutPoolError, RolloutProviderSetError),
            )
            else "pool_serve_v2_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    return 0


def _rollout_pool_serve_composition(args: argparse.Namespace) -> int:
    import asyncio

    try:
        config = CompositionRolloutConfig.load(
            provider_set_v2_path=Path(args.provider_set),
            registry=Path(args.registry),
            composition_pack_dir=Path(args.composition_pack),
            composition_admission_path=Path(args.composition_admission),
            episode_seed=args.episode_seed,
            initial_composition_delivery_time=args.initial_composition_delivery_time,
        )
        pool = RolloutPool.from_composition(
            composition_config=config,
            runtime_image=args.runtime_image,
            allowed_task_images=tuple(args.task_image),
            capacity=args.capacity,
            artifacts_root=Path(args.artifacts_root),
        )
        asyncio.run(serve_rollout_pool(pool=pool, socket_path=Path(args.socket)))
    except KeyboardInterrupt:
        return 0
    except (
        CompositionAdmissionError,
        CompositionPackError,
        ProviderRuntimeError,
        RolloutPoolError,
        RolloutProviderSetError,
        OSError,
        TypeError,
        ValueError,
    ) as exc:
        code = (
            exc.code
            if isinstance(
                exc,
                (
                    CompositionAdmissionError,
                    CompositionPackError,
                    ProviderRuntimeError,
                    RolloutPoolError,
                    RolloutProviderSetError,
                ),
            )
            else "pool_serve_composition_failed"
        )
        return _handle_command_error(args.json, str(exc), code=code)
    return 0


def _serve(args: argparse.Namespace) -> int:
    import uvicorn

    try:
        app = create_app(Path(args.run), server_token=args.server_token)
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(False, str(exc))
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _mcp(args: argparse.Namespace) -> int:
    try:
        actor_context = None
        if args.actor_id is not None or args.actor_role is not None:
            if args.actor_id is None or args.actor_role is None:
                raise ValueError("--actor-id and --actor-role must be supplied together")
            actor_context = ActorContext(actor_id=args.actor_id, role=args.actor_role)
        run_mcp(
            Path(args.run),
            actor_context=actor_context,
        )
    except (ValueError, FileNotFoundError) as exc:
        return _handle_command_error(False, str(exc))
    return 0


def _remote_serve(args: argparse.Namespace) -> int:
    import uvicorn

    from datalox_gated_runtime.remote_world_service import create_remote_world_app

    app = create_remote_world_app(
        runs_root=Path(args.runs_root),
        allowed_examples=set(args.allow_example),
        max_sessions=args.max_sessions,
        ttl_seconds=args.ttl_seconds,
        cleanup_interval_seconds=args.cleanup_interval_seconds,
        allowed_hosts=args.allowed_host,
        allowed_origins=args.allowed_origin,
    )
    uvicorn.run(app, host=args.host, port=args.port)
    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Transparent provider API interception and behavior authoring."
    )
    subcommands = parser.add_subparsers(dest="command", required=True)

    session_parser = subcommands.add_parser(
        "session", help="Manage legacy/reference gated sessions."
    )
    session_subcommands = session_parser.add_subparsers(dest="session_command", required=True)

    create_parser = session_subcommands.add_parser(
        "create", help="Create a new gated runtime session."
    )
    create_parser.add_argument(
        "--example", required=True, help="Example ID to load into the session."
    )
    create_parser.add_argument("--out", required=True, help="Output run directory.")
    create_parser.add_argument(
        "--port", type=int, required=True, help="HTTP port for this session."
    )
    create_parser.add_argument("--seed", type=int, help="Select a non-negative world episode seed.")
    create_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    create_parser.set_defaults(func=_session_create)

    start_parser = session_subcommands.add_parser(
        "start", help="Create a session and start its HTTP server."
    )
    start_parser.add_argument(
        "--example", required=True, help="Example ID to load into the session."
    )
    start_parser.add_argument("--out", required=True, help="Output run directory.")
    start_parser.add_argument("--port", type=int, help="HTTP port for this session.")
    start_parser.add_argument("--seed", type=int, help="Select a non-negative world episode seed.")
    start_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    start_parser.set_defaults(func=_session_start)

    stop_parser = session_subcommands.add_parser("stop", help="Stop a session HTTP server.")
    stop_parser.add_argument("--run", required=True, help="Run directory created by session start.")
    stop_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    stop_parser.set_defaults(func=_session_stop)

    finalize_parser = session_subcommands.add_parser(
        "finalize", help="Finalize a gated runtime session."
    )
    finalize_parser.add_argument(
        "--run", required=True, help="Run directory created by session create."
    )
    finalize_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    finalize_parser.set_defaults(func=_session_finalize)

    promote_parser = session_subcommands.add_parser(
        "promote",
        help="Compile a finalized capture run into a replay environment.",
    )
    promote_parser.add_argument("--run", required=True, help="Finalized capture run directory.")
    promote_parser.add_argument("--out", required=True, help="Output environment directory.")
    promote_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    promote_parser.set_defaults(func=_session_promote)

    check_parser = session_subcommands.add_parser(
        "check", help="Run preflight checks for a gated session."
    )
    check_parser.add_argument("--run", required=True, help="Run directory to inspect.")
    check_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    check_parser.set_defaults(func=_session_check)

    session_auth_parser = session_subcommands.add_parser(
        "auth-preflight",
        help="Validate live auth env requirements for a session without starting a server.",
    )
    session_auth_parser.add_argument("--run", required=True, help="Run directory to inspect.")
    session_auth_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    session_auth_parser.set_defaults(func=_session_auth_preflight)

    env_parser = subcommands.add_parser("env", help="Manage reference replay and world assets.")
    env_subcommands = env_parser.add_subparsers(dest="env_command", required=True)

    verify_replay_parser = env_subcommands.add_parser(
        "verify-replay",
        help="Verify that a compiled environment replays its captured trace.",
    )
    verify_replay_parser.add_argument(
        "--env", required=True, help="Compiled environment directory."
    )
    verify_replay_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    verify_replay_parser.set_defaults(func=_env_verify_replay)

    import_source_pack_parser = env_subcommands.add_parser(
        "import-source-pack",
        help="Import an API Gym source pack as a replay environment.",
    )
    import_source_pack_parser.add_argument("--source", required=True, help="Source-pack directory.")
    import_source_pack_parser.add_argument(
        "--out", required=True, help="Output environment directory."
    )
    import_source_pack_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    import_source_pack_parser.set_defaults(func=_env_import_source_pack)

    kubernetes_openapi_parser = env_subcommands.add_parser(
        "compile-kubernetes-openapi",
        help="Compile official Kubernetes OpenAPI GET schemas into a G1 replay environment.",
    )
    kubernetes_openapi_parser.add_argument(
        "--openapi",
        default="https://raw.githubusercontent.com/kubernetes/kubernetes/v1.36.2/api/openapi-spec/swagger.json",
        help="Kubernetes OpenAPI JSON path or URL.",
    )
    kubernetes_openapi_parser.add_argument(
        "--out", required=True, help="Output environment directory."
    )
    kubernetes_openapi_parser.add_argument(
        "--source-url",
        help="Official source URL to record when --openapi is a local file.",
    )
    kubernetes_openapi_parser.add_argument(
        "--kubernetes-version",
        help="Kubernetes version label to record; defaults to openapi.info.version.",
    )
    kubernetes_openapi_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    kubernetes_openapi_parser.set_defaults(func=_env_compile_kubernetes_openapi)

    documented_provider_parser = env_subcommands.add_parser(
        "compile-documented-provider",
        help="Compile official-doc-grounded GET responses into a G1 replay environment.",
    )
    documented_provider_parser.add_argument(
        "--source", required=True, help="Documented provider manifest JSON."
    )
    documented_provider_parser.add_argument(
        "--out", required=True, help="Output environment directory."
    )
    documented_provider_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    documented_provider_parser.set_defaults(func=_env_compile_documented_provider)

    admit_world_parser = env_subcommands.add_parser(
        "admit-world",
        help="Validate and execute admission checks for a world_bundle_v1 environment.",
    )
    admit_world_parser.add_argument("--env", required=True, help="World bundle directory.")
    admit_world_parser.add_argument(
        "--json", action="store_true", help="Emit the machine-readable admission report."
    )
    admit_world_parser.set_defaults(func=_env_admit_world)

    export_world_parser = env_subcommands.add_parser(
        "export-world",
        help="Build a legacy/reference OCI world package or HUD/Harbor adapter.",
    )
    export_world_parser.add_argument("--env", required=True, help="World bundle directory.")
    export_world_parser.add_argument("--out", required=True, help="New output directory.")
    export_world_parser.add_argument(
        "--format",
        choices=("oci", "hud", "harbor"),
        required=True,
        help="Canonical OCI context or target harness.",
    )
    export_world_parser.add_argument(
        "--episode",
        help="Episode ID to package; defaults to the world's first episode.",
    )
    export_world_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    export_world_parser.set_defaults(func=_env_export_world)

    provider_parser = subcommands.add_parser(
        "provider", help="Author and compile provider behavior."
    )
    provider_subcommands = provider_parser.add_subparsers(dest="provider_command", required=True)

    auth_preflight_parser = provider_subcommands.add_parser(
        "auth-preflight",
        help="Validate provider auth env requirements without touching the provider.",
    )
    auth_preflight_parser.add_argument(
        "--config", required=True, help="Provider probe config JSON."
    )
    auth_preflight_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    auth_preflight_parser.set_defaults(func=_provider_auth_preflight)

    probe_parser = provider_subcommands.add_parser(
        "probe", help="Probe a provider through the gate."
    )
    probe_parser.add_argument("--config", required=True, help="Provider probe config JSON.")
    probe_parser.add_argument("--out", required=True, help="Output probe run directory.")
    probe_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    probe_parser.set_defaults(func=_provider_probe)

    rollup_parser = provider_subcommands.add_parser(
        "probe-rollup",
        help="Aggregate provider probe reports under a runs directory.",
    )
    rollup_parser.add_argument("--runs", required=True, help="Directory containing probe runs.")
    rollup_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    rollup_parser.set_defaults(func=_provider_probe_rollup)

    build_runtime_parser = provider_subcommands.add_parser(
        "build-runtime",
        help="Compile one task-free provider runtime bundle from existing behavior code.",
    )
    build_runtime_source = build_runtime_parser.add_mutually_exclusive_group(required=True)
    build_runtime_source.add_argument(
        "--source-world", help="Existing admitted world bundle directory."
    )
    build_runtime_source.add_argument(
        "--source-gate-config", help="Existing HTTP replay/deny/shadow gate config."
    )
    build_runtime_parser.add_argument("--out", required=True, help="New provider bundle directory.")
    build_runtime_parser.add_argument("--provider-id", required=True)
    build_runtime_parser.add_argument("--episode-id", help="World reset seed to compile.")
    build_runtime_parser.add_argument(
        "--identity-policy",
        help="Provider-native credential-to-role policy for transparent HTTP execution.",
    )
    build_runtime_parser.add_argument(
        "--bundle-version",
        default="1.0.0",
        help="Provider bundle version for gate-config sources.",
    )
    build_runtime_parser.add_argument(
        "--authority",
        action="append",
        required=True,
        help="Exact HTTPS provider authority; repeat for multiple authorities.",
    )
    build_runtime_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    build_runtime_parser.set_defaults(func=_provider_build_runtime)

    admit_provider_parser = provider_subcommands.add_parser(
        "admit",
        help="Execute provider operation and reset claims against a task-free runtime bundle.",
    )
    admit_provider_parser.add_argument("--bundle", required=True)
    admit_provider_parser.add_argument("--claims", required=True)
    admit_provider_parser.add_argument("--out", required=True)
    admit_provider_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    admit_provider_parser.set_defaults(func=_provider_admit)

    release_build_parser = provider_subcommands.add_parser(
        "release-build",
        help="Build an immutable multi-profile OCI release from admitted provider runtimes.",
    )
    release_build_parser.add_argument(
        "--profile",
        action="append",
        nargs=3,
        required=True,
        metavar=("PROFILE_ID", "BUNDLE", "ADMISSION"),
        help="Admitted reset profile; repeat to add another profile.",
    )
    release_build_parser.add_argument("--release-version", required=True)
    release_build_parser.add_argument("--out", required=True)
    release_build_parser.add_argument("--json", action="store_true")
    release_build_parser.set_defaults(func=_provider_release_build)

    registry_create_parser = provider_subcommands.add_parser(
        "registry-create", help="Create a fresh immutable local provider-release registry."
    )
    registry_create_parser.add_argument("--root", required=True)
    registry_create_parser.add_argument("--json", action="store_true")
    registry_create_parser.set_defaults(func=_provider_registry_create)

    registry_publish_parser = provider_subcommands.add_parser(
        "registry-publish", help="Publish one OCI provider release under an immutable reference."
    )
    registry_publish_parser.add_argument("--root", required=True)
    registry_publish_parser.add_argument("--release", required=True)
    registry_publish_parser.add_argument("--json", action="store_true")
    registry_publish_parser.set_defaults(func=_provider_registry_publish)

    registry_resolve_parser = provider_subcommands.add_parser(
        "registry-resolve", help="Resolve and verify an immutable provider release reference."
    )
    registry_resolve_parser.add_argument("--root", required=True)
    registry_resolve_parser.add_argument("--reference", required=True)
    registry_resolve_parser.add_argument("--json", action="store_true")
    registry_resolve_parser.set_defaults(func=_provider_registry_resolve)

    export_envfactory_parser = provider_subcommands.add_parser(
        "export-envfactory",
        help="Compile one admitted provider world into an EnvFactory-native overlay.",
    )
    export_envfactory_parser.add_argument(
        "--source-world", required=True, help="Existing admitted provider world directory."
    )
    export_envfactory_parser.add_argument(
        "--trajectory",
        required=True,
        help="Grounded trajectory file used to observe successful output shapes.",
    )
    export_envfactory_parser.add_argument("--out", required=True)
    export_envfactory_parser.add_argument("--provider-id", required=True)
    export_envfactory_parser.add_argument("--episode-id", required=True)
    export_envfactory_parser.add_argument("--server-name")
    export_envfactory_parser.add_argument(
        "--authority",
        action="append",
        required=True,
        help="Exact HTTPS provider authority; repeat for multiple authorities.",
    )
    export_envfactory_parser.add_argument(
        "--scenario-template",
        action="append",
        default=[],
        metavar="TEMPLATE_ID=JSON_PATH",
        help="Add a validated reset checkpoint template; repeatable.",
    )
    export_envfactory_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    export_envfactory_parser.set_defaults(func=_provider_export_envfactory)

    composition_parser = subcommands.add_parser(
        "composition",
        help="Validate and admit provider-mediated composition behavior.",
    )
    composition_subcommands = composition_parser.add_subparsers(
        dest="composition_command",
        required=True,
    )
    composition_validate_parser = composition_subcommands.add_parser(
        "validate",
        help="Validate an authored Composition Pack and its exact probe claims.",
    )
    composition_validate_parser.add_argument("--pack", required=True)
    composition_validate_parser.add_argument("--claims", required=True)
    composition_validate_parser.add_argument(
        "--provider",
        action="append",
        nargs=2,
        required=True,
        metavar=("PROVIDER_ID", "RELEASE"),
        help="Exact Provider Release binding; repeat for each pack provider.",
    )
    composition_validate_parser.add_argument(
        "--admitted-at",
        help="Optional RFC 3339 UTC validation time; defaults to the current time.",
    )
    composition_validate_parser.add_argument("--json", action="store_true")
    composition_validate_parser.set_defaults(func=_composition_validate)

    composition_admit_parser = composition_subcommands.add_parser(
        "admit",
        help="Run candidate behavior probes twice and derive an immutable admission.",
    )
    composition_admit_parser.add_argument("--pack", required=True)
    composition_admit_parser.add_argument("--claims", required=True)
    composition_admit_parser.add_argument(
        "--provider",
        action="append",
        nargs=2,
        required=True,
        metavar=("PROVIDER_ID", "RELEASE"),
        help="Exact Provider Release binding; repeat for each pack provider.",
    )
    composition_admit_parser.add_argument(
        "--run",
        required=True,
        help="Fresh private directory for isolated candidate provider sessions.",
    )
    composition_admit_parser.add_argument("--out", required=True)
    composition_admit_parser.add_argument(
        "--admitted-at",
        help="Optional RFC 3339 UTC admission time; defaults to the current time.",
    )
    composition_admit_parser.add_argument("--json", action="store_true")
    composition_admit_parser.set_defaults(func=_composition_admit)

    intercept_parser = subcommands.add_parser(
        "intercept", help="Run transparent provider HTTPS interception."
    )
    intercept_subcommands = intercept_parser.add_subparsers(dest="intercept_command", required=True)
    intercept_prepare_parser = intercept_subcommands.add_parser(
        "prepare", help="Validate bundles and create CA/control assets before agent startup."
    )
    intercept_prepare_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    intercept_prepare_parser.add_argument(
        "--run", required=True, help="New isolated run directory."
    )
    intercept_prepare_parser.add_argument(
        "--trust-dir",
        help="Optional directory that receives only the public CA for the agent.",
    )
    intercept_prepare_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    intercept_prepare_parser.set_defaults(func=_intercept_prepare)

    intercept_prepare_admitted_parser = intercept_subcommands.add_parser(
        "prepare-admitted",
        help="Create CA/control assets for exact admitted provider release bindings.",
    )
    intercept_prepare_admitted_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    intercept_prepare_admitted_parser.add_argument(
        "--admission", action="append", required=True, help="Provider admission; repeatable."
    )
    intercept_prepare_admitted_parser.add_argument(
        "--release-config",
        action="append",
        required=True,
        help="Exact Provider Release config; repeatable in provider order.",
    )
    intercept_prepare_admitted_parser.add_argument(
        "--run", required=True, help="New isolated run directory."
    )
    intercept_prepare_admitted_parser.add_argument(
        "--trust-dir",
        help="Optional directory that receives only the public CA for the agent.",
    )
    intercept_prepare_admitted_parser.add_argument(
        "--json", action="store_true", help="Emit JSON output."
    )
    intercept_prepare_admitted_parser.set_defaults(func=_intercept_prepare_admitted)

    intercept_export_parser = intercept_subcommands.add_parser(
        "export",
        help="Export provider interception injection artifacts for an existing agent workload.",
    )
    intercept_export_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    intercept_export_parser.add_argument("--out", required=True, help="New output directory.")
    intercept_export_parser.add_argument(
        "--target", choices=("docker", "kubernetes"), required=True
    )
    intercept_export_parser.add_argument(
        "--runtime-image",
        required=True,
        help="Base Datalox runtime image used to build the provider image.",
    )
    intercept_export_parser.add_argument(
        "--provider-image",
        required=True,
        help="Resulting provider-bundle image reference used by the workload.",
    )
    intercept_export_parser.add_argument(
        "--agent-container",
        help="Existing agent container name; required for Kubernetes strategic merge patches.",
    )
    intercept_export_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    intercept_export_parser.set_defaults(func=_intercept_export)

    intercept_ready_parser = intercept_subcommands.add_parser(
        "ready", help="Check the private control plane for container health checks."
    )
    intercept_ready_parser.add_argument("--run", required=True)
    intercept_ready_parser.add_argument("--json", action="store_true", help="Emit JSON output.")
    intercept_ready_parser.set_defaults(func=_intercept_ready)

    intercept_control_parser = intercept_subcommands.add_parser(
        "control", help="Use the trusted Unix-socket provider control plane."
    )
    intercept_control_parser.add_argument("--run", required=True)
    intercept_control_parser.add_argument(
        "--provider-id", action="append", required=True, help="Provider id; repeatable."
    )
    intercept_control_parser.add_argument("--operation", choices=("export", "reset"), required=True)
    intercept_control_parser.add_argument("--json", action="store_true")
    intercept_control_parser.set_defaults(func=_intercept_control)

    intercept_serve_parser = intercept_subcommands.add_parser(
        "serve", help="Serve provider runtimes over TLS with a Unix control socket."
    )
    intercept_serve_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    intercept_serve_parser.add_argument("--run", required=True, help="New isolated run directory.")
    intercept_serve_parser.add_argument("--host", default="0.0.0.0")
    intercept_serve_parser.add_argument("--port", type=int, default=443)
    intercept_serve_parser.add_argument(
        "--prepared",
        action="store_true",
        help="Require assets created by intercept prepare instead of creating a new run.",
    )
    intercept_serve_parser.set_defaults(func=_intercept_serve)

    intercept_serve_admitted_parser = intercept_subcommands.add_parser(
        "serve-admitted",
        help="Serve exact admitted provider releases over transparent TLS.",
    )
    intercept_serve_admitted_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    intercept_serve_admitted_parser.add_argument(
        "--admission", action="append", required=True, help="Provider admission; repeatable."
    )
    intercept_serve_admitted_parser.add_argument(
        "--release-config",
        action="append",
        required=True,
        help="Exact Provider Release config; repeatable in provider order.",
    )
    intercept_serve_admitted_parser.add_argument(
        "--run", required=True, help="New isolated run directory."
    )
    intercept_serve_admitted_parser.add_argument("--host", default="0.0.0.0")
    intercept_serve_admitted_parser.add_argument("--port", type=int, default=443)
    intercept_serve_admitted_parser.add_argument(
        "--prepared",
        action="store_true",
        help="Require assets created by intercept prepare-admitted.",
    )
    intercept_serve_admitted_parser.set_defaults(func=_intercept_serve_admitted)

    rollout_parser = subcommands.add_parser(
        "rollout", help="Run consumer-owned work in isolated provider execution leases."
    )
    rollout_subcommands = rollout_parser.add_subparsers(dest="rollout_command", required=True)
    rollout_provider_set_parser = rollout_subcommands.add_parser(
        "provider-set",
        help="Write an ordered task-free provider-set manifest from runtime bundles.",
    )
    rollout_provider_set_parser.add_argument(
        "--bundle", action="append", required=True, help="Provider runtime bundle; repeatable."
    )
    rollout_provider_set_parser.add_argument("--out", required=True)
    rollout_provider_set_parser.add_argument("--json", action="store_true")
    rollout_provider_set_parser.set_defaults(func=_rollout_provider_set)
    rollout_provider_set_v2_parser = rollout_subcommands.add_parser(
        "provider-set-v2",
        help="Write a provider set from immutable registry references and reset profiles.",
    )
    rollout_provider_set_v2_parser.add_argument("--registry", required=True)
    rollout_provider_set_v2_parser.add_argument(
        "--provider",
        action="append",
        nargs=2,
        required=True,
        metavar=("PROVIDER@RELEASE", "PROFILE_ID"),
        help="Immutable release selection; repeat to compose providers.",
    )
    rollout_provider_set_v2_parser.add_argument("--out", required=True)
    rollout_provider_set_v2_parser.add_argument("--json", action="store_true")
    rollout_provider_set_v2_parser.set_defaults(func=_rollout_provider_set_v2)

    rollout_materialize_parser = rollout_subcommands.add_parser(
        "materialize-provider-set",
        help="Materialize a verified registry-backed provider set for local execution.",
    )
    rollout_materialize_parser.add_argument("--registry", required=True)
    rollout_materialize_parser.add_argument("--provider-set", required=True)
    rollout_materialize_parser.add_argument("--out", required=True)
    rollout_materialize_parser.add_argument("--json", action="store_true")
    rollout_materialize_parser.set_defaults(func=_rollout_materialize_provider_set)
    rollout_run_parser = rollout_subcommands.add_parser(
        "run", help="Run one Docker rollout against a task-free provider set."
    )
    rollout_run_parser.add_argument("--provider-set", required=True)
    rollout_run_parser.add_argument("--runtime-image", required=True)
    rollout_run_parser.add_argument("--task-image", required=True)
    rollout_run_parser.add_argument("--uid", required=True)
    rollout_run_parser.add_argument("--session-id", required=True)
    rollout_run_parser.add_argument("--environment-seed", type=int, required=True)
    rollout_run_parser.add_argument("--out", required=True)
    rollout_run_parser.add_argument(
        "consumer_command",
        nargs=argparse.REMAINDER,
        help="Consumer command after --; task, trainer, verifier, and reward remain consumer-owned.",
    )
    rollout_run_parser.set_defaults(func=_rollout_run)

    rollout_run_v2_parser = rollout_subcommands.add_parser(
        "run-v2",
        help="Run one Docker rollout from an admitted registry-backed provider set.",
    )
    rollout_run_v2_parser.add_argument("--registry", required=True)
    rollout_run_v2_parser.add_argument("--provider-set", required=True)
    rollout_run_v2_parser.add_argument("--runtime-image", required=True)
    rollout_run_v2_parser.add_argument("--task-image", required=True)
    rollout_run_v2_parser.add_argument("--uid", required=True)
    rollout_run_v2_parser.add_argument("--session-id", required=True)
    rollout_run_v2_parser.add_argument("--environment-seed", type=int, required=True)
    rollout_run_v2_parser.add_argument("--out", required=True)
    rollout_run_v2_parser.add_argument(
        "consumer_command",
        nargs=argparse.REMAINDER,
        help="Consumer command after --; task, trainer, verifier, and reward remain consumer-owned.",
    )
    rollout_run_v2_parser.set_defaults(func=_rollout_run_v2)

    rollout_pool_serve_parser = rollout_subcommands.add_parser(
        "pool-serve",
        help="Serve trusted isolated rollout leases over a mode-0600 Unix socket.",
    )
    rollout_pool_serve_parser.add_argument("--provider-set", required=True)
    rollout_pool_serve_parser.add_argument("--runtime-image", required=True)
    rollout_pool_serve_parser.add_argument(
        "--task-image",
        action="append",
        required=True,
        help="Allowed task image; repeat to allow another exact image.",
    )
    rollout_pool_serve_parser.add_argument("--capacity", type=int, required=True)
    rollout_pool_serve_parser.add_argument("--artifacts-root", required=True)
    rollout_pool_serve_parser.add_argument("--socket", required=True)
    rollout_pool_serve_parser.add_argument(
        "--json", action="store_true", help="Emit structured JSON for startup failures."
    )
    rollout_pool_serve_parser.set_defaults(func=_rollout_pool_serve)

    rollout_pool_serve_v2_parser = rollout_subcommands.add_parser(
        "pool-serve-v2",
        help="Serve admitted registry-backed rollout leases over a mode-0600 Unix socket.",
    )
    rollout_pool_serve_v2_parser.add_argument("--registry", required=True)
    rollout_pool_serve_v2_parser.add_argument("--provider-set", required=True)
    rollout_pool_serve_v2_parser.add_argument("--runtime-image", required=True)
    rollout_pool_serve_v2_parser.add_argument(
        "--task-image",
        action="append",
        required=True,
        help="Allowed task image; repeat to allow another exact image.",
    )
    rollout_pool_serve_v2_parser.add_argument("--capacity", type=int, required=True)
    rollout_pool_serve_v2_parser.add_argument("--artifacts-root", required=True)
    rollout_pool_serve_v2_parser.add_argument("--socket", required=True)
    rollout_pool_serve_v2_parser.add_argument(
        "--json", action="store_true", help="Emit structured JSON for startup failures."
    )
    rollout_pool_serve_v2_parser.set_defaults(func=_rollout_pool_serve_v2)

    rollout_pool_serve_composition_parser = rollout_subcommands.add_parser(
        "pool-serve-composition",
        help="Serve one admitted Composition Pack through the standard rollout-pool API.",
    )
    rollout_pool_serve_composition_parser.add_argument("--registry", required=True)
    rollout_pool_serve_composition_parser.add_argument("--provider-set", required=True)
    rollout_pool_serve_composition_parser.add_argument("--composition-pack", required=True)
    rollout_pool_serve_composition_parser.add_argument("--composition-admission", required=True)
    rollout_pool_serve_composition_parser.add_argument("--episode-seed", required=True)
    rollout_pool_serve_composition_parser.add_argument(
        "--initial-composition-delivery-time",
        required=True,
        help="Fixed RFC 3339 UTC start for the composition delivery scheduler.",
    )
    rollout_pool_serve_composition_parser.add_argument("--runtime-image", required=True)
    rollout_pool_serve_composition_parser.add_argument(
        "--task-image",
        action="append",
        required=True,
        help="Allowed task image; repeat to allow another exact image.",
    )
    rollout_pool_serve_composition_parser.add_argument("--capacity", type=int, required=True)
    rollout_pool_serve_composition_parser.add_argument("--artifacts-root", required=True)
    rollout_pool_serve_composition_parser.add_argument("--socket", required=True)
    rollout_pool_serve_composition_parser.add_argument(
        "--json", action="store_true", help="Emit structured JSON for startup failures."
    )
    rollout_pool_serve_composition_parser.set_defaults(func=_rollout_pool_serve_composition)

    serve_parser = subcommands.add_parser("serve", help="Run the HTTP server for a session.")
    serve_parser.add_argument(
        "--run", required=True, help="Run directory created by session create."
    )
    serve_parser.add_argument("--host", default="127.0.0.1", help="Host interface for HTTP server.")
    serve_parser.add_argument("--port", type=int, required=True, help="Port for HTTP server.")
    serve_parser.add_argument("--server-token", help=argparse.SUPPRESS)
    serve_parser.set_defaults(func=_serve)

    mcp_parser = subcommands.add_parser("mcp", help="Run the MCP server for a session.")
    mcp_parser.add_argument("--run", required=True, help="Run directory created by session create.")
    mcp_parser.add_argument("--actor-id", help="Runtime-owned actor identifier for world tools.")
    mcp_parser.add_argument("--actor-role", help="Declared world role for MCP tool scope.")
    mcp_parser.set_defaults(func=_mcp)

    remote_parser = subcommands.add_parser(
        "remote-serve",
        help="Serve allowlisted dry-run worlds as isolated Streamable HTTP MCP sessions.",
    )
    remote_parser.add_argument(
        "--runs-root",
        required=True,
        help="Private root directory for isolated remote session runs.",
    )
    remote_parser.add_argument(
        "--allow-example",
        action="append",
        required=True,
        help="Allowlisted example ID; repeat for each public world.",
    )
    remote_parser.add_argument("--host", default="127.0.0.1", help="Host interface.")
    remote_parser.add_argument("--port", type=int, default=7860, help="Public service port.")
    remote_parser.add_argument("--max-sessions", type=int, default=8)
    remote_parser.add_argument("--ttl-seconds", type=float, default=3600.0)
    remote_parser.add_argument("--cleanup-interval-seconds", type=float, default=5.0)
    remote_parser.add_argument(
        "--allowed-host",
        action="append",
        required=True,
        help="Allowed MCP Host value; supports an explicit :* port wildcard.",
    )
    remote_parser.add_argument(
        "--allowed-origin",
        action="append",
        default=[],
        help="Allowed MCP Origin value; repeat as needed.",
    )
    remote_parser.set_defaults(func=_remote_serve)

    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()
    return args.func(args)


def _handle_command_error(
    json_output: bool,
    message: str,
    *,
    code: str = "command_failed",
) -> int:
    if json_output:
        print(json.dumps({"error": {"code": code, "message": message}}))
        return 1
    print(f"error: {message}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
