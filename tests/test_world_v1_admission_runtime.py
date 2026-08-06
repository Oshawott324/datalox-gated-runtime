from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

import pytest

from datalox_gated_runtime.world_v1 import compute_bundle_hashes
from datalox_gated_runtime.world_v1.admission import (
    ParityOutcome,
    TrajectoryOutcome,
)
from datalox_gated_runtime.world_v1.admission_runtime import runtime_admission_callbacks
from datalox_gated_runtime.world_v1.errors import WorldBundleError
from world_v1_helpers import create_valid_bundle, read_manifest, write_manifest


IMPLEMENTATION = """
from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import WorldImplementationV1


@dataclass(frozen=True)
class Verdict:
    passed: bool
    failure_codes: tuple[str, ...]

    def to_dict(self):
        return {"passed": self.passed, "failure_codes": list(self.failure_codes)}


class AdmissionWorld(WorldImplementationV1):
    def initialize_episode(self, *, session, episode):
        session.reset(
            episode_id=episode["id"],
            initial_state=episode["initial_state"],
            initial_time=episode["initial_time"],
        )

    def tool_for_request(self, request):
        if request.path != "/counter":
            return None
        return "counter.read" if request.normalized_method() == "GET" else "counter.increment"

    def handle(self, request, *, actor, session):
        sentinel = os.environ.get("DATALOX_ADMISSION_RUNTIME_SENTINEL")
        if sentinel:
            Path(sentinel).write_text("handler-executed", encoding="utf-8")
        if request.path != "/counter":
            return None
        if request.normalized_method() == "POST":
            session.set_state(
                "counter",
                session.get_state("counter") + request.body["amount"],
            )
        return WorldResponse(
            status_code=200,
            body={"counter": session.get_state("counter"), "actor_role": actor.role},
            is_mutation=request.normalized_method() == "POST",
            world_id="example_world_v1",
            operation_id=request.operation_id,
            decision_kind=(
                "shadow_write" if request.normalized_method() == "POST" else "replay"
            ),
        )

    def tool_schemas(self, *, actor):
        schemas = {"counter.read": {"type": "object", "properties": {}}}
        if actor.role == "operator":
            schemas["counter.increment"] = {
                "type": "object",
                "properties": {"amount": {"type": "integer"}},
                "required": ["amount"],
            }
        return schemas

    def request_for_tool(self, tool_name, arguments, *, actor):
        if tool_name == "counter.read":
            return CallRequest(method="GET", path="/counter")
        return CallRequest(method="POST", path="/counter", body=dict(arguments))

    def operation_for_tool(self, tool_name):
        return tool_name

    def verify(self, *, session, episode):
        passed = session.get_state("counter") == episode["target_counter"]
        return Verdict(passed=passed, failure_codes=() if passed else ("counter_wrong",))

    def task(self, *, episode):
        return TaskBrief(
            task_id=episode["id"],
            title="Reach target counter",
            instructions="Increment the counter to its target.",
            success_criteria=["counter reaches target"],
        )


def create_world():
    return AdmissionWorld()
"""


def _bundle(tmp_path: Path) -> Path:
    root = create_valid_bundle(tmp_path / "bundle")
    (root / "world" / "implementation.py").write_text(IMPLEMENTATION, encoding="utf-8")
    episode = {
        "id": "episode-1",
        "initial_state": {"counter": 1},
        "initial_time": "2030-01-01T00:00:00+00:00",
        "target_counter": 2,
    }
    (root / "world" / "episodes.jsonl").write_text(
        json.dumps(episode, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    manifest = read_manifest(root)
    manifest["content_hashes"] = compute_bundle_hashes(root)
    write_manifest(root, manifest)
    return root


def _callback(value: Callable[..., Any] | None) -> Callable[..., Any]:
    assert value is not None
    return value


def _http_increment(amount: int = 1) -> dict[str, Any]:
    return {
        "surface": "http",
        "actor_role": "operator",
        "method": "POST",
        "path": "/counter",
        "body": {"amount": amount},
    }


def _mcp_increment(amount: int = 1) -> dict[str, Any]:
    return {
        "surface": "mcp",
        "actor_role": "operator",
        "tool_name": "counter.increment",
        "arguments": {"amount": amount},
    }


def test_reset_fingerprint_is_deterministic_and_export_is_complete(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    callbacks = runtime_admission_callbacks()
    reset = _callback(callbacks.reset_fingerprint)
    export = _callback(callbacks.export_session)

    assert reset(root, "episode-1") == reset(root, "episode-1")
    payload = export(root)
    assert payload["ok"] is True
    assert payload["world_id"] == "example_world_v1"
    assert str(payload["export_fingerprint"]).startswith("sha256:")


def test_reference_and_negative_trajectories_execute_in_fresh_sessions(
    tmp_path: Path,
) -> None:
    root = _bundle(tmp_path)
    run = _callback(runtime_admission_callbacks().run_trajectory)

    reference = run(
        root,
        {"episode_id": "episode-1", "steps": [_http_increment()]},
    )
    negative = run(root, {"episode_id": "episode-1", "steps": []})

    assert reference == TrajectoryOutcome(passed=True, failure_codes=())
    assert negative == TrajectoryOutcome(passed=False, failure_codes=("counter_wrong",))


def test_http_mcp_parity_matches_and_detects_different_outcomes(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    parity = _callback(runtime_admission_callbacks().run_parity)

    matched = parity(
        root,
        {
            "episode_id": "episode-1",
            "http_step": _http_increment(),
            "mcp_step": _mcp_increment(),
        },
    )
    mismatched = parity(
        root,
        {
            "episode_id": "episode-1",
            "http_step": _http_increment(1),
            "mcp_step": _mcp_increment(2),
        },
    )

    assert isinstance(matched, ParityOutcome) and matched.matched is True
    assert mismatched.matched is False
    assert mismatched.http_fingerprint != mismatched.mcp_fingerprint


@pytest.mark.parametrize(
    "trajectory",
    [
        {"episode_id": "episode-1", "steps": "not-a-list"},
        {"episode_id": "episode-1", "steps": ["not-an-object"]},
        {
            "episode_id": "episode-1",
            "steps": [{"surface": "shell", "actor_role": "operator"}],
        },
        {
            "episode_id": "episode-1",
            "steps": [
                {
                    "surface": "http",
                    "actor_role": "operator",
                    "method": "POST",
                }
            ],
        },
        {
            "episode_id": "episode-1",
            "steps": [
                {
                    **_http_increment(),
                    "query": {"page": 1},
                }
            ],
        },
        {
            "episode_id": "episode-1",
            "steps": [
                {
                    **_mcp_increment(),
                    "arguments": [],
                }
            ],
        },
        {
            "episode_id": "episode-1",
            "steps": [{**_http_increment(), "actor_id": {"not": "a string"}}],
        },
        {
            "episode_id": "episode-1",
            "steps": [{**_http_increment(), "body": {"amount": float("nan")}}],
        },
        {
            "episode_id": "episode-1",
            "steps": [{**_http_increment(), "method": " "}],
        },
    ],
)
def test_malformed_trajectory_steps_fail_before_any_handler_executes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    trajectory: dict[str, Any],
) -> None:
    root = _bundle(tmp_path)
    sentinel = tmp_path / "handler-sentinel"
    monkeypatch.setenv("DATALOX_ADMISSION_RUNTIME_SENTINEL", str(sentinel))
    run = _callback(runtime_admission_callbacks().run_trajectory)

    with pytest.raises(ValueError):
        run(root, trajectory)
    assert not sentinel.exists()


def test_later_malformed_step_prevents_earlier_valid_step_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle(tmp_path)
    sentinel = tmp_path / "handler-sentinel"
    monkeypatch.setenv("DATALOX_ADMISSION_RUNTIME_SENTINEL", str(sentinel))
    run = _callback(runtime_admission_callbacks().run_trajectory)

    with pytest.raises(ValueError, match="path"):
        run(
            root,
            {
                "episode_id": "episode-1",
                "steps": [
                    _http_increment(),
                    {
                        "surface": "http",
                        "actor_role": "operator",
                        "method": "POST",
                    },
                ],
            },
        )
    assert not sentinel.exists()


def test_parity_rejects_swapped_surfaces_before_handler_execution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    root = _bundle(tmp_path)
    sentinel = tmp_path / "handler-sentinel"
    monkeypatch.setenv("DATALOX_ADMISSION_RUNTIME_SENTINEL", str(sentinel))
    parity = _callback(runtime_admission_callbacks().run_parity)

    with pytest.raises(ValueError, match="must be http"):
        parity(
            root,
            {
                "episode_id": "episode-1",
                "http_step": _mcp_increment(),
                "mcp_step": _http_increment(),
            },
        )
    assert not sentinel.exists()


def test_invalid_bundle_hash_blocks_module_import(tmp_path: Path) -> None:
    root = _bundle(tmp_path)
    sentinel = tmp_path / "import-sentinel"
    implementation = root / "world" / "implementation.py"
    implementation.write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('imported', encoding='utf-8')\n",
        encoding="utf-8",
    )
    reset = _callback(runtime_admission_callbacks().reset_fingerprint)

    with pytest.raises(WorldBundleError) as captured:
        reset(root, "episode-1")
    assert captured.value.code == "world_bundle_hash_mismatch"
    assert not sentinel.exists()
