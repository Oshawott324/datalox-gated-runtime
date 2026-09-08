from __future__ import annotations

import hashlib
import json
import re
from copy import deepcopy
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Mapping

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import ActorContext, WorldImplementationV1
from datalox_gated_runtime.world_v1.session import ScheduledWorldEvent, WorldSession

from .contract import (
    AUTHORITY,
    GET_RESULTS,
    GET_STATUS,
    SUBMIT_MAPPING,
    TOOLS,
    TOOLS_BY_ID,
    WORLD_ID,
)

_STATUS = re.compile(r"^/idmapping/status/([^/]+)$")
_RESULTS = re.compile(r"^/idmapping/uniref/results/([^/]+)$")
_COMPLETION_EVENT = "uniprot_idmapping_job_complete"


@dataclass(frozen=True)
class UniProtError(Exception):
    status: int
    body: dict[str, Any]


@dataclass(frozen=True)
class UniProtVerifierResult:
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verifier_type": WORLD_ID,
            "checks": [{"failure_code": "completed_job_exists", "passed": self.passed}],
            "failure_codes": [] if self.passed else ["completed_job_exists"],
            "reward_atoms": [
                {"id": "completed_job_exists", "earned": self.passed, "value": float(self.passed)}
            ],
            "reward": float(self.passed),
        }


class UniProtIdMappingWorld(WorldImplementationV1):
    def initialize_episode(self, *, session: WorldSession, episode: Mapping[str, Any]) -> None:
        session.reset(
            episode_id=str(episode["id"]),
            initial_state=deepcopy(dict(episode["state"])),
            initial_time=str(episode["metadata"]["clock"]),
        )

    def tool_schemas(self, *, actor: ActorContext) -> dict[str, dict[str, Any]]:
        if actor.role != "idmapping_client":
            return {}
        return {item["id"]: deepcopy(item["input_schema"]) for item in TOOLS}

    def operation_for_tool(self, tool_name: str) -> str | None:
        return tool_name if tool_name in TOOLS_BY_ID else None

    def tool_for_request(self, request: CallRequest) -> str | None:
        method = request.normalized_method()
        path = request.path.rstrip("/") or "/"
        if method == "POST" and path == "/idmapping/run":
            return SUBMIT_MAPPING
        if method == "GET" and _STATUS.fullmatch(path):
            return GET_STATUS
        if method == "GET" and _RESULTS.fullmatch(path):
            return GET_RESULTS
        return None

    def request_for_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
        *,
        actor: ActorContext,
    ) -> CallRequest:
        del actor
        values = dict(arguments)
        if tool_name == SUBMIT_MAPPING:
            return CallRequest(
                "POST",
                "/idmapping/run",
                scheme="https",
                authority=AUTHORITY,
                headers={"content-type": "application/x-www-form-urlencoded"},
                body=values,
                operation_id=tool_name,
            )
        job_id = str(values["job_id"])
        if tool_name == GET_STATUS:
            path = f"/idmapping/status/{job_id}"
        elif tool_name == GET_RESULTS:
            path = f"/idmapping/uniref/results/{job_id}"
        else:
            raise KeyError(tool_name)
        return CallRequest(
            "GET",
            path,
            scheme="https",
            authority=AUTHORITY,
            query=({"format": "json", "size": "1"} if tool_name == GET_RESULTS else {}),
            operation_id=tool_name,
        )

    def handle(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        session: WorldSession,
    ) -> WorldResponse | None:
        del actor
        operation = self.tool_for_request(request)
        if operation is None:
            return None
        try:
            body, status, headers, mutated = self._execute(operation, request, session)
        except UniProtError as error:
            return WorldResponse(
                error.status,
                error.body,
                False,
                WORLD_ID,
                operation,
                "deny",
                "provider_native_failure",
                "UniProt ID Mapping operation rejected atomically.",
            )
        return WorldResponse(
            status,
            body,
            mutated,
            WORLD_ID,
            operation,
            "shadow_write" if mutated else "replay",
            "world_state_write" if mutated else "world_state_read",
            "UniProt ID Mapping operation completed against isolated state.",
            headers,
        )

    def _execute(
        self,
        operation: str,
        request: CallRequest,
        session: WorldSession,
    ) -> tuple[dict[str, Any] | None, int, dict[str, str], bool]:
        if operation == SUBMIT_MAPPING:
            body, mutated = self._submit(request, session)
            return body, 200, {}, mutated
        job = self._job(request.path, session)
        if operation == GET_STATUS:
            if job["status"] == "RUNNING":
                return {"jobStatus": "RUNNING"}, 200, {}, False
            location = f"https://{AUTHORITY}/idmapping/uniref/results/{job['id']}"
            return None, 303, {"location": location}, False
        if operation == GET_RESULTS:
            if dict(request.query) != {"format": "json", "size": "1"}:
                raise UniProtError(400, {"messages": ["The result query is invalid"]})
            if job["status"] != "FINISHED":
                raise UniProtError(404, {"messages": ["Resource not found"]})
            return {"results": deepcopy(job["results"])}, 200, {}, False
        raise AssertionError(operation)

    def _submit(self, request: CallRequest, session: WorldSession) -> tuple[dict[str, Any], bool]:
        if not isinstance(request.body, Mapping):
            raise UniProtError(400, {"messages": ["A form body is required"]})
        form = dict(request.body)
        source = form.get("from")
        target = form.get("to")
        identifiers = form.get("ids")
        if source == "NOT_A_DB" and target == "ChEMBL":
            raise UniProtError(400, {"messages": ["The 'from' value has invalid format"]})
        if (
            source != "UniProtKB_AC-ID"
            or target != "UniRef100"
            or not isinstance(identifiers, str)
            or not identifiers.strip()
        ):
            raise UniProtError(400, {"messages": ["The mapping request is invalid"]})
        normalized = {"from": source, "to": target, "ids": identifiers}
        fingerprint = hashlib.sha256(
            json.dumps(normalized, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        request_index = deepcopy(session.get_state("request_index"))
        existing_job_id = request_index.get(fingerprint)
        if existing_job_id is not None:
            return {"jobId": existing_job_id}, False

        sequence = int(session.get_state("job_sequence")) + 1
        job_id = f"datalox_job_{sequence:06d}"
        mapping = session.get_state("mapping_fixture")
        submitted_ids = [item.strip() for item in identifiers.split(",") if item.strip()]
        results = [{"from": item, "to": mapping[item]} for item in submitted_ids if item in mapping]
        jobs = deepcopy(session.get_state("jobs"))
        jobs[job_id] = {
            "id": job_id,
            "request": normalized,
            "status": "RUNNING",
            "results": results,
        }
        request_index[fingerprint] = job_id
        session.set_state("job_sequence", sequence)
        session.set_state("jobs", jobs)
        session.set_state("request_index", request_index)
        deliver_at = datetime.fromisoformat(session.current_time()) + timedelta(seconds=60)
        session.schedule_event(
            event_id=f"complete:{job_id}",
            deliver_at=deliver_at,
            kind=_COMPLETION_EVENT,
            payload={"job_id": job_id},
        )
        return {"jobId": job_id}, True

    @staticmethod
    def _job(path: str, session: WorldSession) -> dict[str, Any]:
        matched = _STATUS.fullmatch(path.rstrip("/") or "/") or _RESULTS.fullmatch(
            path.rstrip("/") or "/"
        )
        if matched is None:
            raise AssertionError(path)
        job = session.get_state("jobs").get(matched.group(1))
        if job is None:
            raise UniProtError(
                404,
                {
                    "messages": ["Resource not found"],
                    "url": f"https://{AUTHORITY}{path}",
                },
            )
        return deepcopy(job)

    def handle_scheduled_event(
        self,
        event: ScheduledWorldEvent,
        *,
        session: WorldSession,
    ) -> None:
        if event.kind != _COMPLETION_EVENT:
            raise ValueError(f"unsupported UniProt scheduled event kind: {event.kind}")
        if not isinstance(event.payload, Mapping) or not isinstance(
            event.payload.get("job_id"), str
        ):
            raise ValueError("UniProt completion event payload is invalid")
        job_id = event.payload["job_id"]
        jobs = deepcopy(session.get_state("jobs"))
        job = jobs.get(job_id)
        if job is None or job["status"] != "RUNNING":
            raise ValueError("UniProt completion event does not reference one pending job")
        job["status"] = "FINISHED"
        jobs[job_id] = job
        session.set_state("jobs", jobs)
        session.append_event("uniprot_idmapping_job_finished", {"job_id": job_id})

    def verify(
        self,
        *,
        session: WorldSession,
        episode: Mapping[str, Any],
    ) -> UniProtVerifierResult:
        del episode
        jobs = session.get_state("jobs")
        return UniProtVerifierResult(any(job["status"] == "FINISHED" for job in jobs.values()))

    def task(self, *, episode: Mapping[str, Any]) -> TaskBrief:
        task = episode["task"]
        return TaskBrief(
            task_id=str(task["task_id"]),
            title=str(task["title"]),
            instructions=str(task["instructions"]),
            success_criteria=tuple(str(item) for item in task["success_criteria"]),
        )


def create_world() -> UniProtIdMappingWorld:
    return UniProtIdMappingWorld()
