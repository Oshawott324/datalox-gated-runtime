from __future__ import annotations

import base64
import http.client
import math
import os
import re
import stat
import time
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Literal
from urllib.parse import quote_plus, urlencode, urlsplit

from datalox_gated_runtime.behavior_harvest.engines.v3.contracts import (
    AUTH_STRATEGY_FIXED_SECRET_HEADERS,
    AUTH_STRATEGY_HTTP_BASIC_API_KEY,
    AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER,
    _COMPLETED_MUTATION_STATUSES,
    AssertionSpec,
    AuthContext,
    AuthReceipt,
    BehaviorCapture,
    BehaviorContractError,
    BehaviorHarvestError,
    BehaviorStep,
    CapturedExchange,
    ConnectorSpec,
    DispatchRequest,
    EngineIdentity,
    EvidenceCallSpec,
    JsonValue,
    MultipartFormDataSpec,
    PollSpec,
    RawTransportResponse,
    RequestReceipt,
    RequestTemplate,
    StaticJsonReceipt,
    binding_type_matches,
    canonical_contract_digest,
    canonical_json_bytes,
    compute_observed_relations,
    derive_secret_variants,
    encode_request_target,
    encode_multipart_body,
    freeze_json,
    generated_binding_value_matches,
    load_connector,
    load_recipe,
    load_static_artifacts,
    load_static_json_receipts,
    parse_json_bytes,
    reject_sensitive_json,
    render_path_template,
    safe_headers,
    scan_sensitive_bytes,
    sha256_digest,
    thaw_json,
    validate_assertion_prefix,
    validate_v3_connector_recipe,
    validate_request_header_allowlist,
    validate_run_id,
)

ENGINE_ID = "behavior_harvest_http11"
ENGINE_VERSION = "3"
_HTTP_TOKEN = re.compile(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$")


@dataclass(frozen=True)
class HarvestResult:
    capture: BehaviorCapture
    artifact_path: Path
    artifact_sha256: str


@dataclass
class _RunAccounting:
    total_response_bytes: int = 0
    total_requests: int = 0
    total_poll_attempts: int = 0
    last_dispatch: float | None = None


class _EngineHttp11Executor:
    """Private, closed transport: one fresh connection and one HTTP exchange."""

    def exchange(
        self,
        *,
        origin: str,
        method: str,
        target: str,
        headers: Mapping[str, str],
        body: bytes,
        timeout_ms: int,
        max_response_bytes: int,
    ) -> RawTransportResponse:
        parsed = urlsplit(origin)
        connection_type = (
            http.client.HTTPSConnection if parsed.scheme == "https" else http.client.HTTPConnection
        )
        connection = connection_type(
            parsed.hostname,
            parsed.port,
            timeout=timeout_ms / 1000,
        )
        try:
            connection.request(
                method,
                target,
                body=body if body else None,
                headers=dict(headers),
            )
            response = connection.getresponse()
            response_body = response.read(max_response_bytes + 1)
            if len(response_body) > max_response_bytes:
                raise BehaviorHarvestError(
                    "response_bytes_exceeded",
                    "provider response exceeds max_response_bytes",
                )
            captured_headers = _capture_response_headers(response.getheaders())
            body_kind: Literal["empty", "json"] = "empty" if response_body == b"" else "json"
            return RawTransportResponse(
                status_code=response.status,
                headers=captured_headers,
                body_bytes=response_body,
                body_kind=body_kind,
            )
        finally:
            connection.close()


class _SingleUseExchangePermit:
    def __init__(self, executor: _EngineHttp11Executor) -> None:
        self._executor = executor
        self._used = False

    def execute(self, **kwargs: Any) -> RawTransportResponse:
        if self._used:
            raise BehaviorHarvestError(
                "exchange_permit_consumed",
                "a physical exchange permit can be consumed exactly once",
            )
        self._used = True
        return self._executor.exchange(**kwargs)


class BehaviorHarvester:
    def run(
        self,
        *,
        connector_path: os.PathLike[str] | str,
        recipe_path: os.PathLike[str] | str,
        expected_connector_sha256: str,
        expected_recipe_sha256: str,
        expected_engine: EngineIdentity,
        run_id: str,
        output_path: os.PathLike[str] | str,
        sensitive_values: Mapping[str, bytes],
        static_input_paths: Mapping[str, os.PathLike[str] | str],
        expected_static_input_sha256: Mapping[str, str],
        static_artifact_paths: Mapping[str, os.PathLike[str] | str] | None = None,
        execute_sandbox_writes: bool = False,
    ) -> HarvestResult:
        # Re-read exact reviewed artifacts immediately before planning any call.
        loaded_connector = load_connector(
            connector_path,
            expected_sha256=expected_connector_sha256,
        )
        loaded_recipe = load_recipe(
            recipe_path,
            expected_sha256=expected_recipe_sha256,
        )
        connector = loaded_connector.value
        recipe = loaded_recipe.value
        validate_v3_connector_recipe(connector, recipe)
        for step in recipe.steps:
            validate_request_header_allowlist(connector, step.request)
        engine = current_engine_identity()
        if not isinstance(expected_engine, EngineIdentity) or expected_engine != engine:
            raise BehaviorHarvestError(
                "engine_identity_mismatch",
                "expected engine id, version, and source digest must match installed bytes",
            )
        if (
            connector.driver_id != engine.engine_id
            or connector.driver_version != engine.engine_version
            or connector.driver_source_sha256 != engine.source_sha256
        ):
            raise BehaviorHarvestError(
                "engine_identity_mismatch",
                "connector does not pin the installed harvest engine exactly",
            )
        if any(item.kind == "mutation" for item in recipe.steps) and (
            execute_sandbox_writes is not True
        ):
            raise BehaviorHarvestError(
                "sandbox_write_consent_required",
                "behavior recipe contains mutations; pass execute_sandbox_writes=True",
            )
        run_id = validate_run_id(run_id)
        contexts = {item.context_id: item for item in connector.auth.contexts}
        referenced_contexts = {
            *[item.auth_context_id for item in recipe.steps],
            *[item.auth_context_id for item in connector.identity_preflight.calls],
            *[item.call.auth_context_id for item in connector.collectors],
        }
        if not referenced_contexts <= contexts.keys():
            raise BehaviorHarvestError(
                "auth_context_not_declared",
                "recipe or evidence calls reference undeclared auth contexts",
            )
        grants = tuple(item for item in connector.auth.contexts if item.grant_required)
        secret_variants = derive_secret_variants(
            connector.auth,
            sensitive_values,
        )
        static_receipts = load_static_json_receipts(
            connector,
            input_paths=static_input_paths,
            expected_sha256=expected_static_input_sha256,
        )
        for receipt in static_receipts:
            scan_sensitive_bytes(
                receipt.raw_body,
                secret_variants,
                path=f"static input {receipt.input_id}",
            )
        loaded_artifacts = load_static_artifacts(
            connector,
            artifact_paths={} if static_artifact_paths is None else static_artifact_paths,
        )
        artifact_bytes = {item.receipt.artifact_id: item.raw_body for item in loaded_artifacts}
        for artifact in loaded_artifacts:
            try:
                scan_sensitive_bytes(
                    artifact.raw_body,
                    secret_variants,
                    path=f"static artifact {artifact.receipt.artifact_id}",
                )
            except BehaviorHarvestError as error:
                raise BehaviorHarvestError(
                    "static_artifact_secret_detected",
                    "static artifact contains a declared secret representation",
                ) from error
        for step in recipe.steps:
            if not isinstance(step.request.body, MultipartFormDataSpec):
                continue
            assembled = encode_multipart_body(step.request.body, artifact_bytes)
            try:
                scan_sensitive_bytes(
                    assembled,
                    secret_variants,
                    path=f"assembled multipart request {step.step_id}",
                )
            except BehaviorHarvestError as error:
                raise BehaviorHarvestError(
                    "static_artifact_secret_detected",
                    "assembled multipart request contains a declared secret representation",
                ) from error
            if (
                len(
                    canonical_json_bytes(
                        RequestReceipt.from_body(
                            method=step.request.method,
                            target="/",
                            headers={},
                            body_bytes=assembled,
                        ).to_dict()
                    )
                )
                > connector.bounds.max_request_bytes
            ):
                raise BehaviorHarvestError(
                    "request_bytes_exceeded",
                    f"request {step.step_id!r} exceeds max_request_bytes",
                )
        output = Path(output_path)
        journal_path = output.with_name(f"{output.name}.partial.jsonl")
        _require_new_private_paths(output, journal_path)
        journal = _ExecutionJournal(journal_path, secret_variants)
        accounting = _RunAccounting()
        executor = _EngineHttp11Executor()
        token_by_context: dict[str, bytes] = {}
        dynamic_variants: tuple[bytes, ...] = ()

        auth_receipts: list[AuthReceipt] = []
        preflight_exchanges: list[CapturedExchange] = []
        program_exchanges: list[CapturedExchange] = []
        logical_program_exchanges: list[CapturedExchange] = []
        collector_exchanges: list[CapturedExchange] = []
        bindings: dict[str, JsonValue] = {}

        try:
            for context in grants:
                receipt, token = self._execute_grant(
                    connector=connector,
                    context=context,
                    sensitive_values=sensitive_values,
                    secret_variants=secret_variants + dynamic_variants,
                    accounting=accounting,
                    journal=journal,
                    executor=executor,
                )
                auth_receipts.append(receipt)
                token_by_context[context.context_id] = token
                dynamic_variants += _token_variants(token)

            all_variants = tuple(set(secret_variants + dynamic_variants))
            for call in connector.identity_preflight.calls:
                exchange = self._execute_evidence_call(
                    phase="preflight",
                    call=call,
                    connector=connector,
                    contexts=contexts,
                    token_by_context=token_by_context,
                    bindings={},
                    sensitive_values=sensitive_values,
                    secret_variants=all_variants,
                    accounting=accounting,
                    journal=journal,
                    executor=executor,
                    artifact_bytes=artifact_bytes,
                )
                preflight_exchanges.append(exchange)

            # Constructing this prefix capture is deferred, but identity evidence is
            # checked before the first program mutation.
            _validate_identity_preflight(
                connector,
                tuple(auth_receipts),
                tuple(preflight_exchanges),
                static_receipts,
            )

            for step_index, step in enumerate(recipe.steps):
                request = _resolve_request_template(
                    step.request,
                    bindings,
                    connector=connector,
                    step_id=step.step_id,
                    operation_id=step.operation_id,
                    kind=step.kind,
                    auth_context_id=step.auth_context_id,
                )
                exchanges = self._execute_program_step(
                    step=step,
                    request=request,
                    connector=connector,
                    context=contexts[step.auth_context_id],
                    token=token_by_context.get(step.auth_context_id),
                    secret_values=sensitive_values,
                    secret_variants=all_variants,
                    accounting=accounting,
                    journal=journal,
                    executor=executor,
                    prior_steps=recipe.steps[: step_index + 1],
                    prior_exchanges=tuple(logical_program_exchanges),
                    artifact_bytes=artifact_bytes,
                )
                program_exchanges.extend(exchanges)
                exchange = exchanges[-1]
                logical_program_exchanges.append(exchange)
                for binding in step.bindings:
                    value = _json_pointer(exchange.body, binding.pointer)
                    bindings[binding.binding_id] = value

            for collector in connector.collectors:
                exchange = self._execute_evidence_call(
                    phase="collector",
                    call=collector.call,
                    connector=connector,
                    contexts=contexts,
                    token_by_context=token_by_context,
                    bindings=bindings,
                    sensitive_values=sensitive_values,
                    secret_variants=all_variants,
                    accounting=accounting,
                    journal=journal,
                    executor=executor,
                    artifact_bytes=artifact_bytes,
                )
                collector_exchanges.append(exchange)

            capture = BehaviorCapture(
                run_id=run_id,
                connector=connector,
                connector_sha256=loaded_connector.exact_sha256,
                connector_canonical_sha256=canonical_contract_digest(connector),
                recipe=recipe,
                recipe_sha256=loaded_recipe.exact_sha256,
                recipe_canonical_sha256=canonical_contract_digest(recipe),
                engine=engine,
                static_input_receipts=static_receipts,
                static_artifact_receipts=tuple(item.receipt for item in loaded_artifacts),
                auth_receipts=tuple(auth_receipts),
                preflight_exchanges=tuple(preflight_exchanges),
                exchanges=tuple(program_exchanges),
                collector_exchanges=tuple(collector_exchanges),
                bindings=bindings,
                observed_relations=compute_observed_relations(
                    recipe.steps,
                    tuple(logical_program_exchanges),
                ),
            )
            artifact_bytes = canonical_json_bytes(capture.to_dict()) + b"\n"
            scan_sensitive_bytes(
                artifact_bytes,
                all_variants,
                path="final capture artifact",
            )
            _atomic_publish_no_overwrite(output, artifact_bytes)
            journal.remove()
            return HarvestResult(
                capture=capture,
                artifact_path=output,
                artifact_sha256=sha256_digest(artifact_bytes),
            )
        except Exception:
            # A partial journal is intentionally retained. There is no resume or
            # automatic cleanup after any provider interaction.
            raise

    def _execute_grant(
        self,
        *,
        connector: ConnectorSpec,
        context: AuthContext,
        sensitive_values: Mapping[str, bytes],
        secret_variants: tuple[bytes, ...],
        accounting: _RunAccounting,
        journal: _ExecutionJournal,
        executor: _EngineHttp11Executor,
    ) -> tuple[AuthReceipt, bytes]:
        grant = context.grant
        assert grant is not None
        fields = dict(grant.form_fields)
        for field, source_name in grant.form_secret_fields.items():
            try:
                fields[field] = sensitive_values[source_name].decode("utf-8")
            except UnicodeDecodeError as error:
                raise BehaviorContractError("OAuth form secrets must be UTF-8") from error
        body = urlencode(sorted(fields.items())).encode("utf-8")
        basic = grant.client_basic_auth
        wire_headers = {
            "accept": "application/json",
            "content-type": "application/x-www-form-urlencoded",
        }
        if basic is not None:
            try:
                client_secret = sensitive_values[basic.client_secret_source]
            except KeyError as error:
                raise BehaviorContractError(
                    "OAuth Basic client secret source is missing"
                ) from error
            authorization = base64.b64encode(
                basic.client_id.encode("utf-8") + b":" + client_secret
            ).decode("ascii")
            wire_headers["authorization"] = f"Basic {authorization}"
        if len(body) > connector.bounds.max_request_bytes:
            raise BehaviorHarvestError(
                "request_bytes_exceeded",
                f"auth grant {context.context_id!r} exceeds max_request_bytes",
            )
        journal.append(
            {
                "schema_id": "datalox_behavior_execution_journal_v1",
                "phase": "auth",
                "step_id": context.context_id,
                "operation_id": context.strategy_id,
                "state": "predispatch",
                "authorization_applied": basic is not None,
                "client_id": None if basic is None else basic.client_id,
            }
        )
        self._begin_dispatch(accounting, connector)
        try:
            response = _SingleUseExchangePermit(executor).execute(
                origin=connector.origin,
                method="POST",
                target=grant.path,
                headers=wire_headers,
                body=body,
                timeout_ms=connector.bounds.request_timeout_ms,
                max_response_bytes=connector.bounds.max_response_bytes,
            )
            self._account_response(response, connector, accounting)
            scan_sensitive_bytes(
                response.body_bytes,
                secret_variants,
                path=f"auth response {context.context_id}",
            )
            if not 200 <= response.status_code <= 299:
                raise BehaviorHarvestError(
                    "auth_grant_failed",
                    f"auth grant {context.context_id!r} returned non-2xx",
                )
            _require_json_media_type(response, context.context_id)
            body_value = parse_json_bytes(
                response.body_bytes,
                path=f"auth_response.{context.context_id}",
            )
            observed_fields: dict[str, JsonValue] = {}
            for name, field_spec in grant.response_fields.items():
                actual = _json_pointer(body_value, field_spec.pointer)
                if isinstance(actual, (Mapping, tuple)) or actual != field_spec.expected:
                    raise BehaviorHarvestError(
                        "auth_response_field_mismatch",
                        f"auth response field {name!r} did not match its safe expected value",
                    )
                observed_fields[name] = actual
            if observed_fields["username"] != context.actor_alias:
                raise BehaviorHarvestError(
                    "auth_identity_mismatch",
                    "provider-authenticated username does not match actor_alias",
                )
            token_value = _json_pointer(body_value, grant.token_pointer)
            if type(token_value) is not str or not token_value:
                raise BehaviorHarvestError(
                    "auth_token_invalid",
                    f"auth grant {context.context_id!r} did not return a string token",
                )
            token = token_value.encode("utf-8")
            receipt = AuthReceipt(
                context_id=context.context_id,
                strategy_id=context.strategy_id,
                actor_alias=context.actor_alias,
                response_status=response.status_code,
                provider_request_id=response.headers.get("x-request-id"),
                authorization_applied=basic is not None,
                client_id=None if basic is None else basic.client_id,
                observed_fields=observed_fields,
                completed=True,
            )
            journal.add_sensitive_variants(_token_variants(token))
        except Exception as error:
            journal.append_terminal(
                phase="auth",
                step_id=context.context_id,
                operation_id=context.strategy_id,
                state="failed",
                reason=type(error).__name__,
            )
            raise
        journal.append(
            {
                "schema_id": "datalox_behavior_execution_journal_v1",
                "phase": "auth",
                "step_id": context.context_id,
                "operation_id": context.strategy_id,
                "state": "complete",
                "status_code": response.status_code,
                "provider_request_id": receipt.provider_request_id,
                "authorization_applied": receipt.authorization_applied,
                "client_id": receipt.client_id,
                "observed_fields": thaw_json(receipt.observed_fields),
            }
        )
        return receipt, token

    def _execute_evidence_call(
        self,
        *,
        phase: Literal["collector", "preflight"],
        call: EvidenceCallSpec,
        connector: ConnectorSpec,
        contexts: Mapping[str, AuthContext],
        token_by_context: Mapping[str, bytes],
        bindings: Mapping[str, JsonValue],
        sensitive_values: Mapping[str, bytes],
        secret_variants: tuple[bytes, ...],
        accounting: _RunAccounting,
        journal: _ExecutionJournal,
        executor: _EngineHttp11Executor,
        artifact_bytes: Mapping[str, bytes],
    ) -> CapturedExchange:
        request = _resolve_request_template(
            call.request,
            bindings,
            connector=connector,
            step_id=call.call_id,
            operation_id=call.strategy_id,
            kind="read",
            auth_context_id=call.auth_context_id,
        )
        exchange = self._execute_request(
            phase=phase,
            subject_id=call.call_id,
            request=request,
            connector=connector,
            context=contexts[call.auth_context_id],
            token=token_by_context.get(call.auth_context_id),
            secret_values=sensitive_values,
            secret_variants=secret_variants,
            accounting=accounting,
            journal=journal,
            executor=executor,
            artifact_bytes=artifact_bytes,
        )
        _validate_standalone_assertions(call.assertions, exchange)
        if not 200 <= exchange.status_code <= 299:
            raise BehaviorHarvestError(
                "evidence_call_failed",
                f"{phase} call {call.call_id!r} must return 2xx",
            )
        return exchange

    def _execute_program_step(
        self,
        *,
        step: BehaviorStep,
        request: DispatchRequest,
        connector: ConnectorSpec,
        context: AuthContext,
        token: bytes | None,
        secret_values: Mapping[str, bytes],
        secret_variants: tuple[bytes, ...],
        accounting: _RunAccounting,
        journal: _ExecutionJournal,
        executor: _EngineHttp11Executor,
        prior_steps: tuple[BehaviorStep, ...],
        prior_exchanges: tuple[CapturedExchange, ...],
        artifact_bytes: Mapping[str, bytes],
    ) -> tuple[CapturedExchange, ...]:
        if step.poll is not None:
            return self._execute_poll_step(
                step=step,
                poll=step.poll,
                request=request,
                connector=connector,
                context=context,
                token=token,
                secret_values=secret_values,
                secret_variants=secret_variants,
                accounting=accounting,
                journal=journal,
                executor=executor,
                prior_steps=prior_steps,
                prior_exchanges=prior_exchanges,
                artifact_bytes=artifact_bytes,
            )
        dispatched = False
        try:
            exchange = self._execute_request(
                phase="program",
                subject_id=step.subject_id,
                request=request,
                connector=connector,
                context=context,
                token=token,
                secret_values=secret_values,
                secret_variants=secret_variants,
                accounting=accounting,
                journal=journal,
                executor=executor,
                artifact_bytes=artifact_bytes,
            )
            dispatched = True
            _validate_step_outcome(step, exchange.status_code)
            validate_assertion_prefix(
                prior_steps,
                prior_exchanges + (exchange,),
            )
            for binding in step.bindings:
                value = _json_pointer(exchange.body, binding.pointer)
                if not generated_binding_value_matches(value, binding.value_type):
                    raise BehaviorHarvestError(
                        "binding_coercion_invalid",
                        f"binding {binding.binding_id!r} has an invalid generated ID value",
                    )
            return (exchange,)
        except Exception as error:
            # _execute_request records terminal_unknown itself for post-dispatch
            # transport/parse failures. This covers semantic validation failures.
            if step.kind == "mutation" and dispatched:
                journal.append_terminal(
                    phase="program",
                    step_id=step.step_id,
                    operation_id=step.operation_id,
                    state="terminal_unknown",
                    reason=type(error).__name__,
                )
            raise

    def _execute_poll_step(
        self,
        *,
        step: BehaviorStep,
        poll: PollSpec,
        request: DispatchRequest,
        connector: ConnectorSpec,
        context: AuthContext,
        token: bytes | None,
        secret_values: Mapping[str, bytes],
        secret_variants: tuple[bytes, ...],
        accounting: _RunAccounting,
        journal: _ExecutionJournal,
        executor: _EngineHttp11Executor,
        prior_steps: tuple[BehaviorStep, ...],
        prior_exchanges: tuple[CapturedExchange, ...],
        artifact_bytes: Mapping[str, bytes],
    ) -> tuple[CapturedExchange, ...]:
        started = time.monotonic()
        deadline = started + poll.deadline_ms / 1000
        prior_dispatch: float | None = None
        attempts: list[CapturedExchange] = []
        for attempt_number in range(1, poll.max_attempts + 1):
            if prior_dispatch is not None:
                remaining_interval = poll.interval_ms / 1000 - (time.monotonic() - prior_dispatch)
                if remaining_interval > 0:
                    if time.monotonic() + remaining_interval - started > poll.deadline_ms / 1000:
                        raise BehaviorHarvestError(
                            "poll_deadline_exceeded",
                            f"poll {step.step_id!r} cannot dispatch within its deadline",
                        )
                    time.sleep(remaining_interval)
            elapsed_before = time.monotonic() - started
            if elapsed_before >= poll.deadline_ms / 1000:
                raise BehaviorHarvestError(
                    "poll_deadline_exceeded",
                    f"poll {step.step_id!r} reached its deadline before dispatch",
                )
            timeout_ms = max(
                1,
                min(
                    request.timeout_ms,
                    math.floor(poll.deadline_ms - elapsed_before * 1000),
                ),
            )
            exchange = self._execute_request(
                phase="program",
                subject_id=step.subject_id,
                request=request,
                connector=connector,
                context=context,
                token=token,
                secret_values=secret_values,
                secret_variants=secret_variants,
                accounting=accounting,
                journal=journal,
                executor=executor,
                artifact_bytes=artifact_bytes,
                poll_attempt=True,
                timeout_ms=timeout_ms,
                dispatch_deadline=deadline,
            )
            prior_dispatch = accounting.last_dispatch
            assert prior_dispatch is not None
            elapsed = time.monotonic() - started
            if elapsed > poll.deadline_ms / 1000:
                raise BehaviorHarvestError(
                    "poll_deadline_exceeded",
                    f"poll {step.step_id!r} exceeded its deadline",
                )
            exchange = replace(
                exchange,
                attempt_number=attempt_number,
                monotonic_elapsed_ms=math.ceil(elapsed * 1000),
            )
            attempts.append(exchange)
            if exchange.status_code in poll.transient_http_statuses:
                if attempt_number == poll.max_attempts:
                    raise BehaviorHarvestError(
                        "poll_transient_exhausted",
                        f"poll {step.step_id!r} exhausted transient attempts",
                    )
                continue
            if not 200 <= exchange.status_code <= 299:
                raise BehaviorHarvestError(
                    "poll_status_invalid",
                    f"poll {step.step_id!r} returned an undeclared HTTP status",
                )
            try:
                value = _json_pointer(exchange.body, poll.status_pointer)
            except BehaviorHarvestError as error:
                raise BehaviorHarvestError(
                    "poll_status_invalid",
                    f"poll {step.step_id!r} status pointer is malformed or missing",
                ) from error
            if type(value) is not str:
                raise BehaviorHarvestError(
                    "poll_status_invalid",
                    f"poll {step.step_id!r} status value must be a string",
                )
            if value in poll.accepted_terminal_values:
                _validate_step_outcome(step, exchange.status_code)
                validate_assertion_prefix(
                    prior_steps,
                    prior_exchanges + (exchange,),
                )
                return tuple(attempts)
            if value in poll.terminal_values:
                raise BehaviorHarvestError(
                    "poll_terminal_unexpected",
                    f"poll {step.step_id!r} reached unexpected terminal value {value!r}",
                )
            if value not in poll.allowed_intermediate_values:
                raise BehaviorHarvestError(
                    "poll_status_invalid",
                    f"poll {step.step_id!r} returned undeclared status value {value!r}",
                )
        raise BehaviorHarvestError(
            "poll_budget_exceeded",
            f"poll {step.step_id!r} exhausted max_attempts",
        )

    def _execute_request(
        self,
        *,
        phase: Literal["collector", "preflight", "program"],
        subject_id: str,
        request: DispatchRequest,
        connector: ConnectorSpec,
        context: AuthContext,
        token: bytes | None,
        secret_values: Mapping[str, bytes],
        secret_variants: tuple[bytes, ...],
        accounting: _RunAccounting,
        journal: _ExecutionJournal,
        executor: _EngineHttp11Executor,
        artifact_bytes: Mapping[str, bytes],
        poll_attempt: bool = False,
        timeout_ms: int | None = None,
        dispatch_deadline: float | None = None,
    ) -> CapturedExchange:
        if isinstance(request.body, MultipartFormDataSpec):
            body = encode_multipart_body(request.body, artifact_bytes)
        else:
            body = b"" if request.body is None else canonical_json_bytes(thaw_json(request.body))
        receipt = RequestReceipt.from_body(
            method=request.method,
            target=request.target,
            headers=request.headers,
            body_bytes=body,
        )
        request_record = canonical_json_bytes(receipt.to_dict())
        if len(request_record) > connector.bounds.max_request_bytes:
            raise BehaviorHarvestError(
                "request_bytes_exceeded",
                f"request {request.step_id!r} exceeds max_request_bytes",
            )
        scan_sensitive_bytes(
            request_record,
            secret_variants,
            path=f"request {request.step_id}",
        )
        journal.append(
            {
                "schema_id": "datalox_behavior_execution_journal_v1",
                "phase": phase,
                "step_id": request.step_id,
                "operation_id": request.operation_id,
                "kind": request.kind,
                "state": "predispatch",
                "request": request.to_dict(),
                "request_sha256": sha256_digest(request_record),
            }
        )
        wire_headers = dict(request.headers)
        if body:
            wire_headers.setdefault("content-type", "application/json")
        wire_headers.setdefault("accept", "application/json")
        auth_headers = _authentication_headers(
            context,
            token=token,
            sensitive_values=secret_values,
        )
        if set(auth_headers) & set(wire_headers):
            raise BehaviorContractError(
                "closed auth headers collide with engine or recipe request headers",
                code="auth_secret_header_collision",
            )
        wire_headers.update(auth_headers)
        dispatch_time = self._begin_dispatch(
            accounting,
            connector,
            poll_attempt=poll_attempt,
            dispatch_deadline=dispatch_deadline,
        )
        effective_timeout_ms = request.timeout_ms if timeout_ms is None else timeout_ms
        if dispatch_deadline is not None:
            effective_timeout_ms = min(
                effective_timeout_ms,
                max(1, math.floor((dispatch_deadline - dispatch_time) * 1000)),
            )
        dispatched = False
        try:
            dispatched = True
            response = _SingleUseExchangePermit(executor).execute(
                origin=connector.origin,
                method=request.method,
                target=request.target,
                headers=wire_headers,
                body=body,
                timeout_ms=effective_timeout_ms,
                max_response_bytes=connector.bounds.max_response_bytes,
            )
            self._account_response(response, connector, accounting)
            scan_sensitive_bytes(
                response.body_bytes,
                secret_variants,
                path=f"response {request.step_id}",
            )
            if response.body_kind == "json":
                _require_json_media_type(response, request.step_id)
                parsed_body = parse_json_bytes(
                    response.body_bytes,
                    path=f"response.{request.step_id}",
                )
            else:
                parsed_body = None
            reject_sensitive_json(
                parsed_body,
                path=f"response.{request.step_id}",
            )
            exchange = CapturedExchange.create(
                phase=phase,
                step_id=request.step_id,
                operation_id=request.operation_id,
                kind=request.kind,
                subject_id=subject_id,
                auth_context_id=request.auth_context_id,
                request=request,
                request_receipt=receipt,
                response=response,
                body=parsed_body,
            )
            scan_sensitive_bytes(
                canonical_json_bytes(exchange.to_dict()),
                secret_variants,
                path=f"exchange {request.step_id}",
            )
        except Exception as error:
            if request.kind == "mutation" and dispatched:
                journal.append_terminal(
                    phase=phase,
                    step_id=request.step_id,
                    operation_id=request.operation_id,
                    state="terminal_unknown",
                    reason=type(error).__name__,
                )
                raise BehaviorHarvestError(
                    "unknown_mutation_completion",
                    f"mutation {request.step_id!r} has no validated completion",
                ) from error
            journal.append_terminal(
                phase=phase,
                step_id=request.step_id,
                operation_id=request.operation_id,
                state="failed",
                reason=type(error).__name__,
            )
            raise
        journal.append(
            {
                "schema_id": "datalox_behavior_execution_journal_v1",
                "phase": phase,
                "step_id": request.step_id,
                "operation_id": request.operation_id,
                "state": "response_validated",
                "status_code": response.status_code,
                "body_sha256": exchange.body_sha256,
            }
        )
        return exchange

    def _begin_dispatch(
        self,
        accounting: _RunAccounting,
        connector: ConnectorSpec,
        *,
        poll_attempt: bool = False,
        dispatch_deadline: float | None = None,
    ) -> float:
        if accounting.total_requests >= connector.bounds.max_requests:
            raise BehaviorHarvestError(
                "poll_budget_exceeded" if poll_attempt else "request_limit_exceeded",
                "physical request budget is exhausted",
            )
        if poll_attempt and accounting.total_poll_attempts >= connector.bounds.max_polls:
            raise BehaviorHarvestError(
                "poll_budget_exceeded",
                "total poll attempt budget is exhausted",
            )
        if accounting.last_dispatch is not None:
            minimum = connector.bounds.min_request_interval_ms / 1000
            remaining = minimum - (time.monotonic() - accounting.last_dispatch)
            if remaining > 0:
                time.sleep(remaining)
        dispatch_time = time.monotonic()
        if dispatch_deadline is not None and dispatch_time >= dispatch_deadline:
            raise BehaviorHarvestError(
                "poll_deadline_exceeded",
                "poll deadline expired during global request rate limiting",
            )
        accounting.last_dispatch = dispatch_time
        accounting.total_requests += 1
        if poll_attempt:
            accounting.total_poll_attempts += 1
        return dispatch_time

    @staticmethod
    def _account_response(
        response: RawTransportResponse,
        connector: ConnectorSpec,
        accounting: _RunAccounting,
    ) -> None:
        if not isinstance(response, RawTransportResponse):
            raise BehaviorContractError("private executor returned an invalid transport response")
        if len(response.body_bytes) > connector.bounds.max_response_bytes:
            raise BehaviorHarvestError(
                "response_bytes_exceeded",
                "provider response exceeds max_response_bytes",
            )
        accounting.total_response_bytes += len(response.body_bytes)
        if accounting.total_response_bytes > connector.bounds.max_total_response_bytes:
            raise BehaviorHarvestError(
                "total_response_bytes_exceeded",
                "provider responses exceed max_total_response_bytes",
            )


def _capture_response_headers(
    headers: list[tuple[str, str]],
) -> Mapping[str, str]:
    allowlist = {
        "content-type",
        "etag",
        "location",
        "retry-after",
        "x-request-id",
    }
    captured: dict[str, str] = {}
    for raw_name, raw_value in headers:
        name = raw_name.lower()
        if name in allowlist and name not in captured:
            captured[name] = raw_value
    return safe_headers(captured, path="transport.response_headers")


def _authentication_headers(
    context: AuthContext,
    *,
    token: bytes | None,
    sensitive_values: Mapping[str, bytes],
) -> Mapping[str, str]:
    if context.strategy_id == "none":
        return {}
    if context.strategy_id == "bearer":
        source_name = context.secret_source_names[0]
        try:
            return {"authorization": "Bearer " + sensitive_values[source_name].decode("utf-8")}
        except (KeyError, UnicodeDecodeError) as error:
            raise BehaviorContractError("bearer auth source is missing or not UTF-8") from error
    if context.strategy_id == AUTH_STRATEGY_OPAQUE_AUTHORIZATION_HEADER:
        source_name = context.secret_source_names[0]
        try:
            raw = sensitive_values[source_name]
            value = raw.decode("ascii")
        except (KeyError, UnicodeDecodeError) as error:
            raise BehaviorContractError(
                "opaque Authorization header source is missing or not ASCII",
                code="auth_strategy_invalid",
            ) from error
        if (
            "\r" in value
            or "\n" in value
            or any(ord(character) < 0x20 or ord(character) == 0x7F for character in value)
        ):
            raise BehaviorContractError(
                "opaque Authorization header secret must be a safe single-line value",
                code="auth_strategy_invalid",
            )
        return {"authorization": value}
    if context.strategy_id == AUTH_STRATEGY_HTTP_BASIC_API_KEY:
        source_name = context.secret_source_names[0]
        try:
            raw = sensitive_values[source_name]
        except KeyError as error:
            raise BehaviorContractError(
                "HTTP Basic API-key source is missing",
                code="auth_strategy_invalid",
            ) from error
        encoded = base64.b64encode(raw + b":").decode("ascii")
        return {"authorization": f"Basic {encoded}"}
    if context.strategy_id == AUTH_STRATEGY_FIXED_SECRET_HEADERS:
        try:
            return {
                header: sensitive_values[source_name].decode("ascii")
                for header, source_name in context.secret_headers.items()
            }
        except (KeyError, UnicodeDecodeError) as error:
            raise BehaviorContractError(
                "fixed secret-header source is missing or not ASCII",
                code="auth_strategy_invalid",
            ) from error
    if context.strategy_id == "oauth_password_grant":
        if token is None:
            raise BehaviorHarvestError(
                "auth_token_missing",
                f"OAuth token for context {context.context_id!r} is unavailable",
            )
        return {"authorization": "Bearer " + token.decode("utf-8")}
    raise BehaviorContractError(
        "auth strategy is unsupported by behavior-harvest engine v3",
        code="auth_strategy_invalid",
    )


def _authorization_header(
    context: AuthContext,
    *,
    token: bytes | None,
    sensitive_values: Mapping[str, bytes],
) -> str | None:
    """Preserve the V3 compatibility helper for authorization-only strategies."""
    headers = _authentication_headers(
        context,
        token=token,
        sensitive_values=sensitive_values,
    )
    if set(headers) - {"authorization"}:
        raise BehaviorContractError(
            "auth strategy uses provider secret headers, not Authorization",
            code="auth_strategy_invalid",
        )
    return headers.get("authorization")


def _token_variants(token: bytes) -> tuple[bytes, ...]:
    try:
        encoded = quote_plus(token.decode("utf-8")).encode("ascii")
    except UnicodeDecodeError as error:
        raise BehaviorContractError("OAuth token must be UTF-8") from error
    return (
        token,
        base64.b64encode(token),
        encoded,
        b"Bearer " + token,
    )


def _resolve_request_template(
    template: RequestTemplate,
    bindings: Mapping[str, JsonValue],
    *,
    connector: ConnectorSpec,
    step_id: str,
    operation_id: str,
    kind: Literal["read", "mutation"],
    auth_context_id: str,
) -> DispatchRequest:
    resolved = _resolve_bindings(template.to_dict(), bindings)
    path = render_path_template(template.path, bindings)
    query = freeze_json(resolved["query"], path=f"request.{step_id}.query")
    if not isinstance(query, Mapping):
        raise BehaviorHarvestError(
            "request_query_invalid",
            "resolved request query must be an object",
        )
    if isinstance(template.body, MultipartFormDataSpec):
        body: JsonValue | MultipartFormDataSpec = template.body
    else:
        body = freeze_json(resolved["body"], path=f"request.{step_id}.body")
    resolved_headers = dict(
        safe_headers(
            resolved["headers"],
            path=f"request.{step_id}.headers",
        )
    )
    if isinstance(body, MultipartFormDataSpec):
        if "content-type" in resolved_headers:
            raise BehaviorContractError(
                "multipart Content-Type is derived from the pinned boundary",
                code="multipart_contract_invalid",
            )
        resolved_headers["content-type"] = f"multipart/form-data; boundary={body.boundary}"
    headers = safe_headers(resolved_headers, path=f"request.{step_id}.headers")
    reject_sensitive_json(query, path=f"request.{step_id}.query")
    if not isinstance(body, MultipartFormDataSpec):
        reject_sensitive_json(body, path=f"request.{step_id}.body")
    return DispatchRequest(
        step_id=step_id,
        operation_id=operation_id,
        kind=kind,
        auth_context_id=auth_context_id,
        method=template.method,
        path=path,
        query=query,
        body=body,
        headers=headers,
        timeout_ms=connector.bounds.request_timeout_ms,
        target=encode_request_target(path, query),
    )


def _resolve_bindings(
    value: Any,
    bindings: Mapping[str, JsonValue],
) -> Any:
    if isinstance(value, Mapping):
        if set(value.keys()) == {"$binding"}:
            binding_id = value["$binding"]
            try:
                return thaw_json(bindings[binding_id])
            except KeyError as error:
                raise BehaviorHarvestError(
                    "binding_missing",
                    f"binding {binding_id!r} is unavailable",
                ) from error
        return {key: _resolve_bindings(item, bindings) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_resolve_bindings(item, bindings) for item in value]
    return value


def _json_pointer(value: JsonValue, pointer: str) -> JsonValue:
    current = value
    if pointer == "":
        return current
    for raw_component in pointer.split("/")[1:]:
        component = raw_component.replace("~1", "/").replace("~0", "~")
        if isinstance(current, Mapping):
            if component not in current:
                raise BehaviorHarvestError(
                    "json_pointer_missing",
                    f"JSON pointer {pointer!r} does not exist",
                )
            current = current[component]
        elif type(current) is tuple:
            if not component.isascii() or not component.isdigit():
                raise BehaviorHarvestError(
                    "json_pointer_invalid",
                    f"JSON pointer {pointer!r} has a non-index component",
                )
            index = int(component)
            if index >= len(current):
                raise BehaviorHarvestError(
                    "json_pointer_missing",
                    f"JSON pointer {pointer!r} does not exist",
                )
            current = current[index]
        else:
            raise BehaviorHarvestError(
                "json_pointer_missing",
                f"JSON pointer {pointer!r} traverses a scalar",
            )
    return current


def _validate_identity_preflight(
    connector: ConnectorSpec,
    receipts: tuple[AuthReceipt, ...],
    exchanges: tuple[CapturedExchange, ...],
    static_receipts: tuple[StaticJsonReceipt, ...],
) -> None:
    projected: dict[str, JsonValue] = {}
    preflight = connector.identity_preflight
    if preflight.identity_call_id is not None:
        exchange = next(item for item in exchanges if item.step_id == preflight.identity_call_id)
        identity = _json_pointer(exchange.body, preflight.identity_pointer or "")
        if not isinstance(identity, Mapping):
            raise BehaviorHarvestError(
                "tenant_preflight_invalid",
                "provider identity projection must be an object",
            )
        projected.update(identity)
    if preflight.authenticated_context_ids:
        by_context = {item.context_id: item for item in receipts}
        try:
            projected["authenticated_contexts"] = freeze_json(
                [
                    {
                        "context_id": context_id,
                        "strategy_id": by_context[context_id].strategy_id,
                        "actor_alias": by_context[context_id].actor_alias,
                    }
                    for context_id in preflight.authenticated_context_ids
                ]
            )
        except KeyError as error:
            raise BehaviorHarvestError(
                "tenant_preflight_invalid",
                "required authenticated context has no successful grant receipt",
            ) from error
    static_by_id = {item.input_id: item for item in static_receipts}
    for projection in preflight.static_projections:
        if projection.output_key in projected:
            raise BehaviorHarvestError(
                "tenant_preflight_invalid",
                "static identity projection collides with another evidence key",
            )
        try:
            static_body = static_by_id[projection.input_id].body
        except KeyError as error:
            raise BehaviorHarvestError(
                "tenant_preflight_invalid",
                "required static identity input has no exact receipt",
            ) from error
        projected[projection.output_key] = _json_pointer(
            static_body,
            projection.pointer,
        )
    if freeze_json(projected) != preflight.expected_identity:
        raise BehaviorHarvestError(
            "tenant_preflight_mismatch",
            "observed sandbox identity does not match expected identity",
        )


def _validate_standalone_assertions(
    assertions: tuple[AssertionSpec, ...],
    exchange: CapturedExchange,
) -> None:
    for assertion in assertions:
        if assertion.kind == "status_equals":
            passed = exchange.status_code == assertion.expected
        elif assertion.kind == "status_in":
            assert isinstance(assertion.expected, tuple)
            passed = exchange.status_code in assertion.expected
        elif assertion.kind == "json_pointer_equals":
            assert assertion.pointer is not None
            passed = _json_pointer(exchange.body, assertion.pointer) == assertion.expected
        elif assertion.kind == "json_pointer_type":
            assert assertion.pointer is not None
            assert assertion.value_type is not None
            passed = binding_type_matches(
                _json_pointer(exchange.body, assertion.pointer),
                assertion.value_type,
            )
        elif assertion.kind == "json_pointer_pattern":
            import re

            assert assertion.pointer is not None
            assert assertion.pattern is not None
            actual = _json_pointer(exchange.body, assertion.pointer)
            passed = (
                type(actual) is str
                and re.fullmatch(
                    assertion.pattern,
                    actual,
                )
                is not None
            )
        else:
            raise BehaviorHarvestError(
                "evidence_assertion_invalid",
                "evidence calls only support local response assertions",
            )
        if not passed:
            raise BehaviorHarvestError(
                "evidence_assertion_failed",
                f"evidence assertion {assertion.assertion_id!r} failed",
            )


def _validate_step_outcome(step: BehaviorStep, status_code: int) -> None:
    if step.expected_outcome == "observe":
        if step.kind == "mutation":
            valid = status_code in _COMPLETED_MUTATION_STATUSES or 400 <= status_code <= 499
        else:
            valid = 200 <= status_code <= 299 or 400 <= status_code <= 499
        if not valid:
            raise BehaviorHarvestError(
                "step_outcome_invalid",
                f"observational step {step.step_id!r} status is not a completed "
                "mutation, 2xx read, or 4xx failure",
            )
        return
    if step.expected_outcome in {
        "idempotent_success",
        "mutation_success",
        "read_success",
    }:
        valid = (
            status_code in _COMPLETED_MUTATION_STATUSES
            if step.kind == "mutation"
            else 200 <= status_code <= 299
        )
    else:
        valid = 400 <= status_code <= 499
    if not valid:
        raise BehaviorHarvestError(
            "step_outcome_invalid",
            f"step {step.step_id!r} status does not satisfy expected outcome",
        )


def _require_json_media_type(
    response: RawTransportResponse,
    step_id: str,
) -> None:
    content_type = response.headers.get("content-type", "").split(";", 1)[0].strip()
    components = content_type.split("/", 1)
    valid = False
    if len(components) == 2 and all(_HTTP_TOKEN.fullmatch(item) for item in components):
        media_type, subtype = (item.lower() for item in components)
        valid = media_type == "application" and (
            subtype == "json" or (subtype.endswith("+json") and len(subtype) > len("+json"))
        )
    if not valid:
        raise BehaviorHarvestError(
            "response_media_type_invalid",
            f"response {step_id!r} must declare an application JSON media type",
        )


def current_engine_identity() -> EngineIdentity:
    return EngineIdentity(
        engine_id=ENGINE_ID,
        engine_version=ENGINE_VERSION,
        source_sha256=compute_engine_source_sha256(),
    )


def compute_engine_source_sha256() -> str:
    directory = Path(__file__).parent
    records: list[dict[str, Any]] = []
    for path in sorted(directory.glob("*.py"), key=lambda item: item.name):
        if path.is_symlink() or not path.is_file():
            raise BehaviorContractError("behavior-harvest engine source path is unsafe")
        raw = path.read_bytes()
        records.append(
            {
                "name": path.name,
                "bytes": len(raw),
                "sha256": sha256_digest(raw),
            }
        )
    if not records:
        raise BehaviorContractError("behavior-harvest engine source set is empty")
    return sha256_digest(canonical_json_bytes({"files": records}))


def _require_new_private_paths(output_path: Path, journal_path: Path) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if output_path.is_symlink() or journal_path.is_symlink():
        raise BehaviorHarvestError(
            "unsafe_artifact_path",
            "artifact path must not be a symlink",
        )
    if os.path.lexists(output_path) or os.path.lexists(journal_path):
        raise BehaviorHarvestError(
            "artifact_exists",
            "output or partial artifact already exists; overwrite is forbidden",
        )


class _ExecutionJournal:
    def __init__(
        self,
        path: Path,
        sensitive_variants: tuple[bytes, ...],
    ) -> None:
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
        self.path = path
        self._descriptor = os.open(path, flags, 0o600)
        self._sensitive_variants = sensitive_variants
        os.fsync(self._descriptor)
        _fsync_directory(path.parent)

    def append(self, value: Mapping[str, Any]) -> None:
        payload = canonical_json_bytes(dict(value)) + b"\n"
        scan_sensitive_bytes(
            payload,
            self._sensitive_variants,
            path="execution journal",
        )
        written = 0
        while written < len(payload):
            count = os.write(self._descriptor, payload[written:])
            if count <= 0:
                raise BehaviorHarvestError(
                    "journal_write_failed",
                    "execution journal write made no progress",
                )
            written += count
        os.fsync(self._descriptor)

    def add_sensitive_variants(self, variants: tuple[bytes, ...]) -> None:
        self._sensitive_variants = tuple(set(self._sensitive_variants + variants))

    def append_terminal(
        self,
        *,
        phase: str,
        step_id: str,
        operation_id: str,
        state: Literal["failed", "terminal_unknown"],
        reason: str,
    ) -> None:
        self.append(
            {
                "schema_id": "datalox_behavior_execution_journal_v1",
                "phase": phase,
                "step_id": step_id,
                "operation_id": operation_id,
                "state": state,
                "reason": reason,
            }
        )

    def remove(self) -> None:
        os.close(self._descriptor)
        self._descriptor = -1
        self.path.unlink()
        _fsync_directory(self.path.parent)

    def __del__(self) -> None:
        descriptor = getattr(self, "_descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)


def _atomic_publish_no_overwrite(path: Path, payload: bytes) -> None:
    temporary = path.with_name(f".{path.name}.publish")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        written = 0
        while written < len(payload):
            count = os.write(descriptor, payload[written:])
            if count <= 0:
                raise BehaviorHarvestError(
                    "artifact_write_failed",
                    "artifact write made no progress",
                )
            written += count
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    try:
        os.link(temporary, path, follow_symlinks=False)
        _fsync_directory(path.parent)
    except FileExistsError as error:
        raise BehaviorHarvestError(
            "artifact_exists",
            "capture appeared during publication; overwrite is forbidden",
        ) from error
    finally:
        temporary.unlink(missing_ok=True)
        _fsync_directory(path.parent)
    mode = stat.S_IMODE(path.stat(follow_symlinks=False).st_mode)
    if mode != 0o600:
        raise BehaviorHarvestError(
            "artifact_not_private",
            "published capture must have mode 0600",
        )


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(
        path,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
