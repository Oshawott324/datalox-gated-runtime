"""Bounded orchestration around Verifiers; tasks and agent loops stay native."""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
from contextlib import contextmanager
from fractions import Fraction
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from datalox_dirty_integration.audit import canonical_sha256
from datalox_dirty_integration.contract import repository_root
from datalox_dirty_integration.episode import CommerceEpisode, sha256_file
from datalox_dirty_integration.policy import SeededCommercePolicy, load_profile
from datalox_dirty_integration.repeat_contract import (
    ExperimentConfig,
    ModelConfig,
    build_schedule,
    experiment_json_schema,
    write_json_exclusive,
)
from datalox_dirty_integration.repeat_evidence import collect_slot, read_json


def capture_bindings(model: ModelConfig) -> dict[str, str]:
    """Inspect controller configuration without any provider or model call."""
    from datalox_dirty_integration.environment import load_environment
    from datalox_dirty_integration.repeat_native import native_sampling_args

    root = repository_root()
    integration = Path(__file__).resolve().parents[1]
    environment = load_environment(profile="clean", num_tasks=1)
    bindings = {
        "task.prompt": canonical_sha256(environment.dataset[0]["prompt"]),
        "task.tools": canonical_sha256(
            [tool.model_dump(exclude_none=True) for tool in environment.tool_defs]
        ),
        "native.sampling": canonical_sha256(
            {**environment.sampling_args, **native_sampling_args(SimpleNamespace(model=model))}
        ),
        "dependencies.versions": canonical_sha256(
            sorted(
                (item.metadata["Name"], item.version) for item in importlib.metadata.distributions()
            )
        ),
    }
    files = sorted((root / "src" / "datalox_gated_runtime").rglob("*.py"))
    files += sorted((integration / "datalox_dirty_integration").glob("*.py"))
    files += [
        integration / "pyproject.toml",
        integration / "uv.lock",
        integration / "upstream-contract.json",
    ]
    for path in files:
        bindings[f"file.{path.relative_to(root).as_posix()}"] = sha256_file(path)
    for name in ("clean", "hostile"):
        bindings[f"policy.{name}"] = SeededCommercePolicy(load_profile(name)).policy_sha256
    with CommerceEpisode(
        provider_grounding=environment.provider_grounding,
        provider_admission=environment.provider_admission,
        provider_runtime_bundle=environment.provider_runtime_bundle,
        provider_release=environment.provider_release,
        policy=SeededCommercePolicy(load_profile("clean")),
        intervention_seed="1",
        intervention_enabled=True,
    ) as episode:
        exported = episode.export()
        for name, key in {
            "release_digest": "provider_release_digest",
            "initial_state_fingerprint": "initial_state_fingerprint",
            "grounding_sha256": "provider_grounding_sha256",
            "runtime_sha256": "provider_runtime_sha256",
            "admission_sha256": "provider_admission_sha256",
            "operation_claims_sha256": "operation_claims_sha256",
            "operation_contract_sha256": "operation_contract_sha256",
        }.items():
            bindings[f"provider.{name}"] = exported[key]
    return bindings


def load_experiment(path: Path) -> ExperimentConfig:
    # Pydantic's strict JSON path accepts JSON arrays for declared tuples while
    # retaining strict scalar validation. Reject duplicate/nonfinite JSON first.
    value = read_json(path)
    return ExperimentConfig.model_validate_json(json.dumps(value, allow_nan=False))


def _atomic_json(path: Path, value: Any) -> None:
    descriptor, temporary = tempfile.mkstemp(prefix=".collection-", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(value, stream, sort_keys=True, indent=2, allow_nan=False)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def _exact_money(value: Any, label: str) -> Fraction:
    """Accept the canonical exact-money strings produced by the token auditor."""
    if type(value) is not str:
        raise ValueError(f"{label} requires a canonical exact-money string")
    try:
        amount = Fraction(value)
    except (ValueError, ZeroDivisionError, OverflowError) as error:
        raise ValueError(f"invalid {label}") from error
    if amount < 0 or str(amount) != value:
        raise ValueError(f"invalid or noncanonical {label}")
    return amount


def _verified_slot_cost(
    slot_path: Path, config: ExperimentConfig, row: dict[str, Any]
) -> tuple[Fraction, str, str]:
    """Release a hold only against collect_slot's fully audited, indexed result."""
    budget = row.get("native", {}).get("token_budget")
    if row.get("status") != "completed" or not isinstance(budget, dict):
        raise ValueError("completed slot requires audited token accounting")
    if budget.get("passed") is not True or budget.get("blocked") is not False:
        raise ValueError("slot token accounting must pass without an unresolved block")
    if _exact_money(budget.get("held_usd"), "slot held cost") != 0:
        raise ValueError("slot has an unresolved token charge")
    cap = Fraction(str(config.per_rollout_reservation_usd))
    if _exact_money(budget.get("limit_usd"), "slot limit") != cap:
        raise ValueError("slot token cap differs from the frozen reservation")
    spent = _exact_money(budget.get("spent_usd"), "slot spent cost")
    if spent > cap:
        raise ValueError("slot token cost exceeds its reserved cap")
    index_path = slot_path / "index.json"
    index = read_json(index_path)
    budget_sha256 = sha256_file(slot_path / "native" / "budget.json")
    if index.get("files", {}).get("native/budget.json") != budget_sha256:
        raise ValueError("slot budget ledger differs from its evidence index")
    if index.get("row_sha256") != canonical_sha256(row):
        raise ValueError("audited slot cost differs from its indexed row")
    return spent, budget_sha256, sha256_file(index_path)


@contextmanager
def _termination_guard():
    """Convert ordinary process termination into the same cleanup as Ctrl-C."""
    if threading.current_thread() is not threading.main_thread():
        raise RuntimeError("the repeat CLI's process supervisor requires the main thread")
    previous = signal.getsignal(signal.SIGTERM)

    def terminate(signum: int, frame: Any) -> None:
        raise KeyboardInterrupt("repeat collection terminated")

    signal.signal(signal.SIGTERM, terminate)
    try:
        yield
    finally:
        signal.signal(signal.SIGTERM, previous)


@_termination_guard()
def _launch_slot(config: ExperimentConfig, slot: Any, output: Path, manifest: Path) -> None:
    command = [
        sys.executable,
        "-m",
        "datalox_dirty_integration.repeats",
        "_slot",
        "--experiment",
        str(manifest),
        "--slot",
        slot.slot_id,
        "--output",
        str(output),
    ]
    output.mkdir(mode=0o700)
    write_json_exclusive(output / "command.json", {"argv": command})
    with (output / "process.log").open("x", encoding="utf-8") as log:
        process = subprocess.Popen(
            command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True
        )
        try:
            # Allow native cleanup/scoring after its declared rollout timeout.
            code = process.wait(timeout=config.per_rollout_timeout_seconds + 30)
            if code:
                raise RuntimeError(f"native_slot_exit_{code}")
        except BaseException:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGTERM)
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(process.pid, signal.SIGKILL)
                    process.wait()
            raise


def run_experiment(
    config: ExperimentConfig, output: Path, *, spend_approved: bool
) -> dict[str, Any]:
    """Collect every scheduled slot or retain an explicitly incomplete cohort."""
    if not spend_approved:
        raise ValueError("approve the experiment's token-spending cap before paid execution")
    if not os.environ.get(config.model.api_key_env):
        raise ValueError(
            f"required credential environment variable is unset: {config.model.api_key_env}"
        )
    if capture_bindings(config.model) != config.bindings:
        raise ValueError("frozen experiment inputs changed; prepare a new experiment")
    output = output.resolve()
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    (output / "slots").mkdir(mode=0o700)
    manifest = output / "experiment.json"
    write_json_exclusive(manifest, config.model_dump(mode="json"))
    write_json_exclusive(
        output / "schedule.json", [slot.model_dump(mode="json") for slot in config.schedule]
    )
    collection: dict[str, Any] = {
        "schema_version": "datalox_repeat_collection_v1",
        "experiment_sha256": canonical_sha256(config.model_dump(mode="json")),
        "status": "running",
        "spend_approved": True,
        "cost_accounting": "sequential_verified_token_settlement",
        "spent_cost_usd": "0",
        "held_cost_usd": "0",
        "slots": [
            {**slot.model_dump(mode="json"), "status": "unstarted"} for slot in config.schedule
        ],
    }
    collection_path = output / "collection.json"
    _atomic_json(collection_path, collection)
    spent = Fraction()
    reservation = Fraction(str(config.per_rollout_reservation_usd))
    limit = Fraction(str(config.max_total_cost_usd))
    try:
        for index, slot in enumerate(config.schedule):
            if spent + reservation > limit:
                collection.update(status="incomplete", stop_reason="reservation_budget_exhausted")
                break
            record = collection["slots"][index]
            record.update(status="running", reservation_usd=str(reservation))
            collection["held_cost_usd"] = str(reservation)
            # The full native slot cap is durable before the subprocess can bill.
            _atomic_json(collection_path, collection)
            try:
                slot_path = output / "slots" / slot.slot_id
                _launch_slot(config, slot, slot_path, manifest)
                row = collect_slot(slot_path, config, slot)
                cost, budget_sha256, index_sha256 = _verified_slot_cost(slot_path, config, row)
                spent += cost
                record.update(
                    status="completed",
                    token_cost_usd=str(cost),
                    budget_sha256=budget_sha256,
                    index_sha256=index_sha256,
                )
                collection.update(spent_cost_usd=str(spent), held_cost_usd="0")
            except (Exception, KeyboardInterrupt) as error:  # noqa: BLE001 - every failed slot retains its charge hold
                # An uncertain or unauditable charge retains the entire slot cap.
                record.update(status="collection_error", error_type=type(error).__name__)
                collection.update(status="incomplete", stop_reason="collection_error")
                break
            finally:
                _atomic_json(collection_path, collection)
        else:
            collection["status"] = "completed"
    finally:
        _atomic_json(collection_path, collection)
    return collection


def _audit_collection_costs(
    config: ExperimentConfig, collection: dict[str, Any], costs: dict[str, Fraction]
) -> None:
    """Recompute global spending and unresolved holds from the saved slot receipts."""
    if collection.get("cost_accounting") != "sequential_verified_token_settlement":
        raise ValueError("collection token-accounting contract differs")
    spent, held = Fraction(), Fraction()
    reservation = Fraction(str(config.per_rollout_reservation_usd))
    limit = Fraction(str(config.max_total_cost_usd))
    stopped = False
    failed = False
    for record in collection["slots"]:
        status = record["status"]
        if status == "unstarted":
            if any(
                key in record
                for key in ("reservation_usd", "token_cost_usd", "budget_sha256", "index_sha256")
            ):
                raise ValueError("unstarted slot contains a spending receipt")
            stopped = True
            continue
        if stopped or spent + held + reservation > limit:
            raise ValueError("slot dispatch violated the sequential spending cap")
        if _exact_money(record.get("reservation_usd"), "slot reservation") != reservation:
            raise ValueError("slot reservation differs from the frozen cap")
        if status == "completed":
            cost = costs[record["slot_id"]]
            if _exact_money(record.get("token_cost_usd"), "slot token cost") != cost:
                raise ValueError("collection token cost differs from audited native usage")
            spent += cost
        elif status == "collection_error":
            if any(key in record for key in ("token_cost_usd", "budget_sha256", "index_sha256")):
                raise ValueError("failed slot contains a released-charge receipt")
            held += reservation
            stopped = failed = True
        else:
            raise ValueError("collection has a nonterminal slot")
    if _exact_money(collection.get("spent_cost_usd"), "collection spent cost") != spent:
        raise ValueError("collection spent total differs from audited receipts")
    if _exact_money(collection.get("held_cost_usd"), "collection held cost") != held:
        raise ValueError("collection held total differs from unresolved reservations")
    if spent + held > limit:
        raise ValueError("collection exceeds its frozen spending cap")
    if not stopped:
        if collection.get("status") != "completed" or "stop_reason" in collection:
            raise ValueError("completed collection status differs from its slots")
    else:
        expected = "collection_error" if failed else "reservation_budget_exhausted"
        if collection.get("status") != "incomplete" or collection.get("stop_reason") != expected:
            raise ValueError("incomplete collection status differs from its slots")
        if not failed and spent + reservation <= limit:
            raise ValueError("budget-stop receipt still permits the next scheduled slot")


def analyze_experiment(source: Path, output: Path) -> dict[str, Any]:
    """Recheck retained bytes and produce deterministic reports without inference."""
    from datalox_dirty_integration.repeat_analysis import analyze_rows, render_summary

    source = source.resolve()
    config = load_experiment(source / "experiment.json")
    schedule = [slot.model_dump(mode="json") for slot in config.schedule]
    if read_json(source / "schedule.json") != schedule:
        raise ValueError("saved schedule differs from the frozen manifest")
    collection = read_json(source / "collection.json")
    if collection["experiment_sha256"] != canonical_sha256(config.model_dump(mode="json")):
        raise ValueError("collection manifest binding mismatch")
    if len(collection["slots"]) != len(schedule):
        raise ValueError("collection slot count differs from the schedule")
    rows = []
    costs: dict[str, Fraction] = {}
    for slot, recorded in zip(config.schedule, collection["slots"], strict=True):
        for key, value in slot.model_dump(mode="json").items():
            if recorded[key] != value:
                raise ValueError("collection slot identity changed")
        if recorded["status"] == "completed":
            slot_path = source / "slots" / slot.slot_id
            if recorded["index_sha256"] != sha256_file(slot_path / "index.json"):
                raise ValueError("slot index differs from collection receipt")
            row = collect_slot(slot_path, config, slot, verify_index=True)
            cost, budget_sha256, index_sha256 = _verified_slot_cost(slot_path, config, row)
            if recorded["index_sha256"] != index_sha256:
                raise ValueError("slot index changed during retained-evidence audit")
            if recorded.get("budget_sha256") != budget_sha256:
                raise ValueError("slot budget ledger differs from collection receipt")
            costs[slot.slot_id] = cost
            rows.append(row)
        elif recorded["status"] in {"collection_error", "unstarted"}:
            rows.append({**slot.model_dump(mode="json"), **recorded})
        else:
            raise ValueError("collection has a nonterminal slot; inspect the interrupted run")
    _audit_collection_costs(config, collection, costs)
    summary = analyze_rows(rows, schedule)
    output.mkdir(parents=True, mode=0o700, exist_ok=False)
    write_json_exclusive(output / "summary.json", summary)
    with (output / "summary.md").open("x", encoding="utf-8") as stream:
        stream.write(render_summary(summary))
    with (output / "rollouts.jsonl").open("x", encoding="utf-8") as stream:
        for row in rows:
            stream.write(json.dumps(row, sort_keys=True, allow_nan=False) + "\n")
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    actions = parser.add_subparsers(dest="action", required=True)
    prepare = actions.add_parser("prepare", help="Freeze configuration; makes no model calls")
    prepare.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--experiment-id", required=True)
    prepare.add_argument("--model", default="gpt-5.6-sol")
    prepare.add_argument("--repetitions", type=int, default=10)
    prepare.add_argument("--seeds", nargs="+", default=["1", "7", "23"])
    prepare.add_argument("--max-total-cost-usd", type=float, required=True)
    prepare.add_argument("--per-rollout-reservation-usd", type=float, required=True)
    prepare.add_argument("--max-completion-tokens", type=int, default=4096)
    prepare.add_argument("--request-timeout-seconds", type=float, default=120.0)
    prepare.add_argument("--connect-timeout-seconds", type=float, default=10.0)
    prepare.add_argument("--rollout-timeout-seconds", type=float, default=900.0)
    prepare.add_argument(
        "--source-revision", help="Exact checked-out commit; file hashes also bind uncommitted code"
    )
    run = actions.add_parser("run")
    run.add_argument("--experiment", type=Path, required=True)
    run.add_argument("--output", type=Path, required=True)
    run.add_argument("--spend-approved", action="store_true")
    analyze = actions.add_parser("analyze")
    analyze.add_argument("--source", type=Path, required=True)
    analyze.add_argument("--output", type=Path, required=True)
    schema = actions.add_parser("schema")
    schema.add_argument("--output", type=Path, required=True)
    worker = actions.add_parser("_slot", help=argparse.SUPPRESS)
    worker.add_argument("--experiment", type=Path, required=True)
    worker.add_argument("--slot", required=True)
    worker.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    if args.action == "prepare":
        model = ModelConfig(
            model=args.model,
            max_completion_tokens=args.max_completion_tokens,
            request_timeout_seconds=args.request_timeout_seconds,
            connect_timeout_seconds=args.connect_timeout_seconds,
        )
        revision = (
            args.source_revision
            or subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=repository_root(), text=True
            ).strip()
        )
        if args.source_revision is not None:
            checkout = subprocess.run(
                ["git", "rev-parse", "HEAD"],
                cwd=repository_root(),
                text=True,
                capture_output=True,
                check=False,
            )
            if checkout.returncode == 0 and revision != checkout.stdout.strip():
                raise ValueError("source revision must match the checked-out commit")
        config = ExperimentConfig(
            experiment_id=args.experiment_id,
            source_revision=revision,
            bindings=capture_bindings(model),
            model=model,
            seeds=tuple(args.seeds),
            repetitions=args.repetitions,
            per_rollout_timeout_seconds=args.rollout_timeout_seconds,
            max_total_cost_usd=args.max_total_cost_usd,
            per_rollout_reservation_usd=args.per_rollout_reservation_usd,
            schedule=build_schedule(tuple(args.seeds), args.repetitions),
        )
        write_json_exclusive(args.output, config.model_dump(mode="json"))
        print(f"Prepared {len(config.schedule)} slots; no model requests made.")
    elif args.action == "schema":
        write_json_exclusive(args.output, experiment_json_schema())
    elif args.action == "run":
        result = run_experiment(
            load_experiment(args.experiment),
            args.output,
            spend_approved=args.spend_approved,
        )
        print(json.dumps({"status": result["status"], "slots": len(result["slots"])}))
        return 0 if result["status"] == "completed" else 1
    elif args.action == "analyze":
        analyze_experiment(args.source, args.output)
    else:
        from datalox_dirty_integration.repeat_native import run_native_slot

        config = load_experiment(args.experiment)
        if not os.environ.get(config.model.api_key_env):
            raise ValueError("native slot requires the configured model credential")
        if capture_bindings(config.model) != config.bindings:
            raise ValueError("frozen inputs changed before native slot")
        slot = next(slot for slot in config.schedule if slot.slot_id == args.slot)
        run_native_slot(config, slot, args.output)
    return 0


def analyze_main(argv: list[str] | None = None) -> int:
    return main(["analyze", *(sys.argv[1:] if argv is None else argv)])


if __name__ == "__main__":
    raise SystemExit(main())
