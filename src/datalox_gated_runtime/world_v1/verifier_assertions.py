from __future__ import annotations

from abc import ABC, abstractmethod
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import re
from typing import Any, Mapping, Protocol, Sequence


JsonValue = dict[str, Any] | list[Any] | str | int | float | bool | None
Record = Mapping[str, Any]
_FAILURE_CODE = re.compile(r"^[a-z][a-z0-9_.-]*$")
_MISSING = object()
_SUCCESS_DECISIONS = {"replay", "shadow_read", "shadow_write", "live_capture"}


class SchemaValidator(Protocol):
    """Code-first validator supplied by a world implementation."""

    def __call__(self, body: JsonValue) -> bool: ...


@dataclass(frozen=True)
class VerifierWorkspace:
    """Domain-neutral, immutable-by-contract projection used by assertions.

    Runtime records are projected to plain mappings before verification.  Event
    records use the explicit keys ``event_id``, ``operation_id``, ``decision``,
    ``request``, ``mutation_scope``, ``actor_id``, ``actor_role`` and
    ``tool_name``.  The other collections are keyed by their stable record id.
    Timestamps are RFC 3339 strings or timezone-aware ``datetime`` values.
    """

    state: Mapping[str, JsonValue] = field(default_factory=dict)
    events: Sequence[Record] = field(default_factory=tuple)
    artifacts: Mapping[str, Record] = field(default_factory=dict)
    now: datetime | str | None = None
    evidence: Mapping[str, Record] = field(default_factory=dict)
    scheduled_events: Mapping[str, Record] = field(default_factory=dict)
    conversations: Mapping[str, Record] = field(default_factory=dict)
    handoffs: Mapping[str, Record] = field(default_factory=dict)


@dataclass(frozen=True)
class AssertionResult:
    ok: bool
    failure_code: str
    message: str
    evidence_refs: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "failure_code": self.failure_code,
            "message": self.message,
            "evidence_refs": list(self.evidence_refs),
        }


@dataclass(frozen=True)
class DeterministicVerificationResult:
    passed: bool
    assertions: tuple[AssertionResult, ...]
    failure_codes: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "assertions": [result.to_dict() for result in self.assertions],
            "failure_codes": list(self.failure_codes),
        }


@dataclass(frozen=True, kw_only=True)
class DeterministicAssertion(ABC):
    failure_code: str

    def __post_init__(self) -> None:
        if not _FAILURE_CODE.fullmatch(self.failure_code):
            raise ValueError(
                "failure_code must start with a lowercase letter and contain only "
                "lowercase letters, digits, '.', '_' or '-'"
            )

    @abstractmethod
    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult: ...

    def _result(
        self,
        ok: bool,
        *,
        pass_message: str,
        fail_message: str,
        evidence_refs: Sequence[str] = (),
    ) -> AssertionResult:
        return AssertionResult(
            ok=bool(ok),
            failure_code=self.failure_code,
            message=pass_message if ok else fail_message,
            evidence_refs=_unique_refs(evidence_refs),
        )


@dataclass(frozen=True, kw_only=True)
class StateEquals(DeterministicAssertion):
    state_view: str
    pointer: str
    expected: JsonValue

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        actual = _state_value(workspace, self.state_view, self.pointer)
        ok = actual is not _MISSING and actual == self.expected
        return self._result(
            ok,
            pass_message=f"State {self.state_view}{self.pointer} equals the expected value.",
            fail_message=f"State {self.state_view}{self.pointer} does not equal the expected value.",
            evidence_refs=(_state_ref(self.state_view, self.pointer),),
        )


@dataclass(frozen=True, kw_only=True)
class CrossStateEquals(DeterministicAssertion):
    left_state_view: str
    left_pointer: str
    right_state_view: str
    right_pointer: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        left = _state_value(workspace, self.left_state_view, self.left_pointer)
        right = _state_value(workspace, self.right_state_view, self.right_pointer)
        ok = left is not _MISSING and right is not _MISSING and left == right
        return self._result(
            ok,
            pass_message="The two state projections are equal.",
            fail_message=(
                f"State {self.left_state_view}{self.left_pointer} and "
                f"{self.right_state_view}{self.right_pointer} are not equal."
            ),
            evidence_refs=(
                _state_ref(self.left_state_view, self.left_pointer),
                _state_ref(self.right_state_view, self.right_pointer),
            ),
        )


@dataclass(frozen=True, kw_only=True)
class TextContains(DeterministicAssertion):
    state_view: str
    pointer: str
    required_text: tuple[str, ...]
    case_sensitive: bool = False

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.required_text or any(not value for value in self.required_text):
            raise ValueError("required_text must contain non-empty strings")

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        actual = _state_value(workspace, self.state_view, self.pointer)
        ok = isinstance(actual, str) and _contains_all(
            actual, self.required_text, case_sensitive=self.case_sensitive
        )
        return self._result(
            ok,
            pass_message=f"State text {self.state_view}{self.pointer} contains all required text.",
            fail_message=f"State text {self.state_view}{self.pointer} is missing required text.",
            evidence_refs=(_state_ref(self.state_view, self.pointer),),
        )


@dataclass(frozen=True, kw_only=True)
class UnorderedArrayProjectionEquals(DeterministicAssertion):
    state_view: str
    pointer: str
    item_pointer: str
    expected: tuple[JsonValue, ...]

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        actual = _state_value(workspace, self.state_view, self.pointer)
        projected: list[Any] = []
        if isinstance(actual, list):
            projected = [_resolve_pointer(item, self.item_pointer) for item in actual]
        ok = (
            isinstance(actual, list)
            and all(value is not _MISSING for value in projected)
            and Counter(_canonical_json(value) for value in projected)
            == Counter(_canonical_json(value) for value in self.expected)
        )
        return self._result(
            ok,
            pass_message="The unordered state projection equals the expected multiset.",
            fail_message=(
                f"The unordered projection of {self.state_view}{self.pointer} through "
                f"{self.item_pointer} does not equal the expected multiset."
            ),
            evidence_refs=(_state_ref(self.state_view, self.pointer),),
        )


@dataclass(frozen=True, kw_only=True)
class OperationPresent(DeterministicAssertion):
    operation_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, successful=True)
        return self._result(
            bool(matches),
            pass_message=f"Operation {self.operation_id} completed.",
            fail_message=f"Operation {self.operation_id} did not complete.",
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class OperationAbsent(DeterministicAssertion):
    operation_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, successful=True)
        return self._result(
            not matches,
            pass_message=f"Operation {self.operation_id} did not complete.",
            fail_message=f"Operation {self.operation_id} completed but must be absent.",
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class OperationDenied(DeterministicAssertion):
    operation_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, denied=True)
        return self._result(
            bool(matches),
            pass_message=f"Operation {self.operation_id} was denied.",
            fail_message=f"No denied attempt of operation {self.operation_id} was recorded.",
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class OperationsOrdered(DeterministicAssertion):
    operation_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        super().__post_init__()
        if not self.operation_ids or any(not value for value in self.operation_ids):
            raise ValueError("operation_ids must contain non-empty strings")

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        position = 0
        matched: list[Record] = []
        for event in workspace.events:
            if position == len(self.operation_ids):
                break
            if (
                event.get("operation_id") == self.operation_ids[position]
                and _decision(event) in _SUCCESS_DECISIONS
            ):
                matched.append(event)
                position += 1
        ok = position == len(self.operation_ids)
        return self._result(
            ok,
            pass_message="Required operations completed in order.",
            fail_message=(
                "Required operation sequence did not complete in order: "
                + " -> ".join(self.operation_ids)
                + "."
            ),
            evidence_refs=_event_refs(matched),
        )


@dataclass(frozen=True, kw_only=True)
class RequestValueEquals(DeterministicAssertion):
    operation_id: str
    pointer: str
    expected: JsonValue

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, successful=True)
        matching_events = [
            event
            for event in matches
            if _resolve_pointer(event.get("request", _MISSING), self.pointer) == self.expected
        ]
        return self._result(
            bool(matching_events),
            pass_message=(
                f"A completed {self.operation_id} request has the expected value at {self.pointer}."
            ),
            fail_message=(
                f"No completed {self.operation_id} request has the expected value at {self.pointer}."
            ),
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class MutationScopeEquals(DeterministicAssertion):
    operation_id: str
    expected_scope: tuple[str, ...]

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, successful=True)
        expected = Counter(self.expected_scope)
        matching_events = [event for event in matches if _scope_counter(event) == expected]
        return self._result(
            bool(matching_events),
            pass_message=f"Operation {self.operation_id} mutated exactly the expected scope.",
            fail_message=f"Operation {self.operation_id} did not mutate exactly the expected scope.",
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class MutationScopeContains(DeterministicAssertion):
    operation_id: str
    required_scope: tuple[str, ...]

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = _operation_events(workspace, self.operation_id, successful=True)
        required = Counter(self.required_scope)
        matching_events = [
            event
            for event in matches
            if _scope_counter(event) is not None and not (required - _scope_counter(event))
        ]
        return self._result(
            bool(matching_events),
            pass_message=f"Operation {self.operation_id} includes the required mutation scope.",
            fail_message=f"Operation {self.operation_id} is missing required mutation scope.",
            evidence_refs=_event_refs(matches),
        )


@dataclass(frozen=True, kw_only=True)
class ArtifactExists(DeterministicAssertion):
    artifact_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        ok = self.artifact_id in workspace.artifacts
        return self._result(
            ok,
            pass_message=f"Artifact {self.artifact_id} exists.",
            fail_message=f"Artifact {self.artifact_id} does not exist.",
            evidence_refs=(_artifact_ref(self.artifact_id),),
        )


@dataclass(frozen=True, kw_only=True)
class ArtifactSchemaMatches(DeterministicAssertion):
    artifact_id: str
    schema_name: str
    validator: SchemaValidator

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        artifact = workspace.artifacts.get(self.artifact_id)
        ok = False
        if artifact is not None and "structured_body" in artifact:
            try:
                validation = self.validator(artifact["structured_body"])
                ok = validation is True
            except Exception:
                # Bundle-authored validators are untrusted at admission time and fail closed.
                ok = False
        return self._result(
            ok,
            pass_message=f"Artifact {self.artifact_id} matches schema {self.schema_name}.",
            fail_message=f"Artifact {self.artifact_id} does not match schema {self.schema_name}.",
            evidence_refs=(_artifact_ref(self.artifact_id),),
        )


@dataclass(frozen=True, kw_only=True)
class ArtifactStatusEquals(DeterministicAssertion):
    artifact_id: str
    expected_status: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        artifact = workspace.artifacts.get(self.artifact_id)
        ok = artifact is not None and artifact.get("status") == self.expected_status
        return self._result(
            ok,
            pass_message=f"Artifact {self.artifact_id} has the expected lifecycle status.",
            fail_message=f"Artifact {self.artifact_id} does not have the expected lifecycle status.",
            evidence_refs=(_artifact_ref(self.artifact_id),),
        )


@dataclass(frozen=True, kw_only=True)
class ArtifactAuthorVisibilityEquals(DeterministicAssertion):
    artifact_id: str
    expected_author_role: str
    expected_visibility: tuple[str, ...]

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        artifact = workspace.artifacts.get(self.artifact_id)
        visibility = artifact.get("visibility") if artifact is not None else None
        ok = (
            artifact is not None
            and artifact.get("author_role") == self.expected_author_role
            and isinstance(visibility, list)
            and all(isinstance(value, str) for value in visibility)
            and Counter(visibility) == Counter(self.expected_visibility)
        )
        return self._result(
            ok,
            pass_message=f"Artifact {self.artifact_id} has the expected author and visibility.",
            fail_message=f"Artifact {self.artifact_id} has an unexpected author or visibility.",
            evidence_refs=(_artifact_ref(self.artifact_id),),
        )


@dataclass(frozen=True, kw_only=True)
class ArtifactLineageContains(DeterministicAssertion):
    artifact_id: str
    source_artifact_ids: tuple[str, ...] = ()
    evidence_refs: tuple[str, ...] = ()

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        artifact = workspace.artifacts.get(self.artifact_id)
        sources = artifact.get("source_artifact_ids") if artifact is not None else None
        evidence = artifact.get("evidence_refs") if artifact is not None else None
        ok = (
            artifact is not None
            and isinstance(sources, list)
            and all(isinstance(value, str) for value in sources)
            and isinstance(evidence, list)
            and all(isinstance(value, str) for value in evidence)
            and set(self.source_artifact_ids).issubset(sources)
            and set(self.evidence_refs).issubset(evidence)
        )
        return self._result(
            ok,
            pass_message=f"Artifact {self.artifact_id} contains the required evidence lineage.",
            fail_message=f"Artifact {self.artifact_id} is missing required evidence lineage.",
            evidence_refs=(_artifact_ref(self.artifact_id), *self.evidence_refs),
        )


@dataclass(frozen=True, kw_only=True)
class EvidenceFresh(DeterministicAssertion):
    evidence_ref: str
    max_age_seconds: int
    observed_at_field: str = "observed_at"

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.max_age_seconds < 0:
            raise ValueError("max_age_seconds must be non-negative")

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        now = _timestamp(workspace.now)
        evidence = workspace.evidence.get(self.evidence_ref)
        observed_at = (
            _timestamp(evidence.get(self.observed_at_field)) if evidence is not None else None
        )
        age = (now - observed_at).total_seconds() if now and observed_at else None
        ok = age is not None and 0 <= age <= self.max_age_seconds
        return self._result(
            ok,
            pass_message=f"Evidence {self.evidence_ref} is fresh at simulation time.",
            fail_message=f"Evidence {self.evidence_ref} is missing, future-dated, or stale.",
            evidence_refs=(self.evidence_ref, "clock:simulation"),
        )


@dataclass(frozen=True, kw_only=True)
class ScheduledEventDeliveryEquals(DeterministicAssertion):
    scheduled_event_id: str
    expected_delivered: bool

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        event = workspace.scheduled_events.get(self.scheduled_event_id)
        status = event.get("status") if event is not None else None
        delivered_event_ref = event.get("delivered_event_ref") if event is not None else None
        valid_delivery_state = (status == "pending" and delivered_event_ref is None) or (
            status == "delivered"
            and isinstance(delivered_event_ref, str)
            and bool(delivered_event_ref)
        )
        delivered = status == "delivered"
        ok = valid_delivery_state and delivered is self.expected_delivered
        expectation = "delivered" if self.expected_delivered else "not delivered"
        return self._result(
            ok,
            pass_message=f"Scheduled event {self.scheduled_event_id} is {expectation}.",
            fail_message=f"Scheduled event {self.scheduled_event_id} is not {expectation}.",
            evidence_refs=(f"scheduled-event:{self.scheduled_event_id}",),
        )


@dataclass(frozen=True, kw_only=True)
class ConversationComplete(DeterministicAssertion):
    conversation_id: str
    minimum_messages: int = 1

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.minimum_messages < 0:
            raise ValueError("minimum_messages must be non-negative")

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        conversation = workspace.conversations.get(self.conversation_id)
        messages = conversation.get("messages") if conversation is not None else None
        ok = (
            conversation is not None
            and conversation.get("status") == "closed"
            and isinstance(messages, list)
            and len(messages) >= self.minimum_messages
        )
        return self._result(
            ok,
            pass_message=f"Conversation {self.conversation_id} is complete.",
            fail_message=f"Conversation {self.conversation_id} is incomplete.",
            evidence_refs=(f"conversation:{self.conversation_id}",),
        )


@dataclass(frozen=True, kw_only=True)
class HandoffComplete(DeterministicAssertion):
    handoff_id: str

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        handoff = workspace.handoffs.get(self.handoff_id)
        ok = (
            handoff is not None
            and handoff.get("status") == "committed"
            and _timestamp(handoff.get("committed_at")) is not None
        )
        return self._result(
            ok,
            pass_message=f"Handoff {self.handoff_id} is committed.",
            fail_message=f"Handoff {self.handoff_id} is not committed.",
            evidence_refs=(f"handoff:{self.handoff_id}",),
        )


@dataclass(frozen=True, kw_only=True)
class DeadlineMet(DeterministicAssertion):
    deadline: datetime | str
    completion_evidence_ref: str | None = None
    completion_timestamp_field: str = "occurred_at"

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        deadline = _timestamp(self.deadline)
        refs: list[str] = ["clock:simulation"]
        if self.completion_evidence_ref is None:
            completed_at = _timestamp(workspace.now)
        else:
            refs.insert(0, self.completion_evidence_ref)
            record = workspace.evidence.get(self.completion_evidence_ref)
            completed_at = (
                _timestamp(record.get(self.completion_timestamp_field))
                if record is not None
                else None
            )
        ok = deadline is not None and completed_at is not None and completed_at <= deadline
        return self._result(
            ok,
            pass_message="The workflow completed by its simulation-time deadline.",
            fail_message="The workflow did not complete by its simulation-time deadline.",
            evidence_refs=refs,
        )


@dataclass(frozen=True, kw_only=True)
class ForbiddenActorToolAttemptAbsent(DeterministicAssertion):
    actor_id: str | None = None
    actor_role: str | None = None
    tool_name: str | None = None
    operation_id: str | None = None

    def __post_init__(self) -> None:
        super().__post_init__()
        if self.actor_id is None and self.actor_role is None:
            raise ValueError("a forbidden attempt assertion requires actor_id or actor_role")
        if self.tool_name is None and self.operation_id is None:
            raise ValueError("a forbidden attempt assertion requires tool_name or operation_id")

    def evaluate(self, workspace: VerifierWorkspace) -> AssertionResult:
        matches = [
            event
            for event in workspace.events
            if _matches_optional(event, "actor_id", self.actor_id)
            and _matches_optional(event, "actor_role", self.actor_role)
            and _matches_optional(event, "tool_name", self.tool_name)
            and _matches_optional(event, "operation_id", self.operation_id)
        ]
        return self._result(
            not matches,
            pass_message="No forbidden actor/tool attempt was recorded.",
            fail_message="A forbidden actor/tool attempt was recorded.",
            evidence_refs=_event_refs(matches),
        )


def evaluate_assertions(
    workspace: VerifierWorkspace,
    assertions: Sequence[DeterministicAssertion],
) -> DeterministicVerificationResult:
    results = tuple(assertion.evaluate(workspace) for assertion in assertions)
    failure_codes = tuple(result.failure_code for result in results if not result.ok)
    return DeterministicVerificationResult(
        passed=not failure_codes,
        assertions=results,
        failure_codes=failure_codes,
    )


def _state_value(workspace: VerifierWorkspace, state_view: str, pointer: str) -> Any:
    if state_view not in workspace.state:
        return _MISSING
    return _resolve_pointer(workspace.state[state_view], pointer)


def _resolve_pointer(value: Any, pointer: str) -> Any:
    if pointer == "":
        return value
    if not isinstance(pointer, str) or not pointer.startswith("/"):
        return _MISSING
    current = value
    for raw_part in pointer[1:].split("/"):
        part = raw_part.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if part not in current:
                return _MISSING
            current = current[part]
        elif isinstance(current, list):
            if not part.isdigit():
                return _MISSING
            index = int(part)
            if index >= len(current):
                return _MISSING
            current = current[index]
        else:
            return _MISSING
    return current


def _operation_events(
    workspace: VerifierWorkspace,
    operation_id: str,
    *,
    successful: bool = False,
    denied: bool = False,
) -> list[Record]:
    matches = [event for event in workspace.events if event.get("operation_id") == operation_id]
    if successful:
        return [event for event in matches if _decision(event) in _SUCCESS_DECISIONS]
    if denied:
        return [event for event in matches if _decision(event) == "deny"]
    return matches


def _decision(event: Record) -> Any:
    return event.get("decision")


def _event_refs(events: Sequence[Record]) -> tuple[str, ...]:
    refs = []
    for event in events:
        event_id = event.get("event_id")
        if isinstance(event_id, str) and event_id:
            refs.append(f"event:{event_id}")
    return _unique_refs(refs)


def _scope_counter(event: Record) -> Counter[str] | None:
    scope = event.get("mutation_scope")
    if not isinstance(scope, list) or any(not isinstance(value, str) for value in scope):
        return None
    return Counter(scope)


def _artifact_ref(artifact_id: str) -> str:
    return f"artifact:{artifact_id}"


def _state_ref(state_view: str, pointer: str) -> str:
    return f"state:{state_view}#{pointer}"


def _unique_refs(refs: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(ref for ref in refs if ref))


def _canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _contains_all(actual: str, expected: Sequence[str], *, case_sensitive: bool) -> bool:
    def normalize(value: str) -> str:
        normalized = value if case_sensitive else value.casefold()
        return " ".join(normalized.split())

    normalized_actual = normalize(actual)
    return all(normalize(value) in normalized_actual for value in expected)


def _timestamp(value: Any) -> datetime | None:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    else:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def _matches_optional(record: Record, key: str, expected: str | None) -> bool:
    return expected is None or record.get(key) == expected
