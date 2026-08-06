from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from datalox_gated_runtime.world_v1.bundle import compute_bundle_hashes


IMPLEMENTATION = """
from dataclasses import dataclass

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import WorldImplementationV1


@dataclass(frozen=True)
class Verdict:
    passed: bool

    def to_dict(self):
        return {"passed": self.passed}


class ExampleWorld(WorldImplementationV1):
    def initialize_episode(self, *, session, episode):
        session.reset(
            episode_id=episode["id"],
            initial_state=episode["initial_state"],
            initial_time=episode["initial_time"],
        )

    def tool_for_request(self, request):
        if request.path == "/counter":
            return "counter.read" if request.normalized_method() == "GET" else "counter.increment"
        return None

    def handle(self, request, *, actor, session):
        if request.path != "/counter":
            return None
        value = session.get_state("counter")
        if request.normalized_method() == "POST":
            session.set_state("counter", value + request.body["amount"])
            value = session.get_state("counter")
        return WorldResponse(
            status_code=200,
            body={"counter": value, "actor_role": actor.role},
            is_mutation=request.normalized_method() == "POST",
            world_id="example_world_v1",
            operation_id=request.operation_id,
            decision_kind="shadow_write" if request.normalized_method() == "POST" else "replay",
        )

    def tool_schemas(self, *, actor):
        result = {"counter.read": {"type": "object", "properties": {}}}
        if actor.role == "operator":
            result["counter.increment"] = {
                "type": "object",
                "properties": {"amount": {"type": "integer"}},
                "required": ["amount"],
            }
        return result

    def request_for_tool(self, tool_name, arguments, *, actor):
        if tool_name == "counter.read":
            return CallRequest(method="GET", path="/counter")
        return CallRequest(method="POST", path="/counter", body=dict(arguments))

    def operation_for_tool(self, tool_name):
        return tool_name

    def verify(self, *, session, episode):
        return Verdict(passed=session.get_state("counter") >= episode["initial_state"]["counter"])

    def task(self, *, episode):
        return TaskBrief(
            task_id=episode["id"],
            title="Increment counter",
            instructions="Increment the counter once.",
            success_criteria=["counter increased"],
        )


def create_world():
    return ExampleWorld()
"""


def _write_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")


def create_valid_bundle(root: Path) -> Path:
    (root / "world").mkdir(parents=True)
    (root / "skills" / "references").mkdir(parents=True)
    (root / "tests" / "trajectories").mkdir(parents=True)
    _write_json(root / "gate_config.json", {"config_id": "example"})
    _write_json(root / "task.json", {"task_id": "episode-1"})
    _write_json(root / "replay_script.json", {"steps": []})
    (root / "world" / "implementation.py").write_text(IMPLEMENTATION, encoding="utf-8")
    (root / "world" / "episodes.jsonl").write_text(
        json.dumps(
            {
                "id": "episode-1",
                "initial_state": {"counter": 1},
                "initial_time": "2030-01-01T00:00:00+00:00",
            },
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )
    _write_json(
        root / "world" / "roles.json",
        {
            "roles": [
                {"id": "operator", "description": "May read and mutate."},
                {"id": "viewer", "description": "May only read."},
            ]
        },
    )
    _write_json(
        root / "world" / "tools.json",
        {
            "tools": [
                {
                    "id": "counter.read",
                    "description": "Read counter.",
                    "list_roles": ["operator", "viewer"],
                    "invoke_roles": ["operator", "viewer"],
                    "input_schema": {"type": "object", "properties": {}},
                    "source_refs": ["source-1"],
                    "operation_family": "counter_management",
                },
                {
                    "id": "counter.increment",
                    "description": "Increment counter.",
                    "list_roles": ["operator"],
                    "invoke_roles": ["operator"],
                    "input_schema": {
                        "type": "object",
                        "properties": {"amount": {"type": "integer"}},
                        "required": ["amount"],
                    },
                    "source_refs": ["source-1"],
                    "operation_family": "counter_management",
                },
            ]
        },
    )
    _write_json(root / "world" / "verifier.json", {"assertions": []})
    _write_json(
        root / "world" / "sources.json",
        {
            "sources": [{"id": "source-1", "grounding": "G1"}],
            "grounding_gaps": [{"operation_family": "counter_management", "gap": "errors"}],
        },
    )
    (root / "skills" / "SKILL.md").write_text("# Example world\n", encoding="utf-8")
    _write_json(
        root / "tests" / "trajectories" / "reference.json",
        {"id": "reference", "kind": "reference", "steps": []},
    )
    manifest = {
        "schema_version": "datalox_world_bundle_v1",
        "world_id": "example_world_v1",
        "bundle_version": "1.0.0",
        "implementation": "world/implementation.py:create_world",
        "episodes_path": "world/episodes.jsonl",
        "roles_path": "world/roles.json",
        "tools_path": "world/tools.json",
        "verifier_path": "world/verifier.json",
        "sources_path": "world/sources.json",
        "default_actor_role": "operator",
        "required_runtime_capabilities": [
            "actors",
            "role_scoped_tools",
            "transactions",
        ],
        "trajectory_paths": ["tests/trajectories/reference.json"],
        "content_hashes": compute_bundle_hashes(root),
    }
    _write_json(root / "world" / "manifest.json", manifest)
    return root


def read_manifest(root: Path) -> dict[str, Any]:
    return json.loads((root / "world" / "manifest.json").read_text(encoding="utf-8"))


def write_manifest(root: Path, manifest: dict[str, Any]) -> None:
    _write_json(root / "world" / "manifest.json", manifest)
