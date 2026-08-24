from __future__ import annotations

from pathlib import Path
from typing import Any

from datalox_gated_runtime.models import CallRequest, WorldConfig
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.worlds.billing_support_v0 import services
from datalox_gated_runtime.worlds.billing_support_v0.sampler import sample_episode
from datalox_gated_runtime.worlds.billing_support_v0.state import resolve_state_db_path


class BillingSupportWorldBackend:
    world_id = "billing_support_v0"

    def __init__(self, *, run_dir: Path, config: WorldConfig) -> None:
        self.db_path = resolve_state_db_path(run_dir)
        self.config = config

    def handle(self, request: CallRequest) -> WorldResponse | None:
        method = request.normalized_method()
        parts = [part for part in request.path.split("/") if part]

        if method == "GET" and len(parts) == 3 and parts[:2] == ["support", "tickets"]:
            return WorldResponse(
                200, services.get_ticket(self.db_path, parts[2]), is_mutation=False
            )

        if method == "POST" and len(parts) == 4 and parts[:2] == ["support", "tickets"]:
            if parts[3] == "reply":
                body = _request_object(request.body)
                if body is None:
                    return WorldResponse(
                        400, _invalid_body("reply requires a JSON object body"), is_mutation=True
                    )
                public = body.get("public", True)
                if type(public) is not bool:
                    return WorldResponse(
                        400, _invalid_body("reply.public must be a bool"), is_mutation=True
                    )
                reply_body = body.get("body")
                if not isinstance(reply_body, str):
                    return WorldResponse(
                        400, _invalid_body("reply.body must be a string"), is_mutation=True
                    )
                return WorldResponse(
                    200,
                    services.add_reply(
                        self.db_path, ticket_id=parts[2], body=reply_body, public=public
                    ),
                    is_mutation=True,
                )
            if parts[3] == "close":
                return WorldResponse(
                    200,
                    services.close_ticket(self.db_path, ticket_id=parts[2]),
                    is_mutation=True,
                )

        if method == "GET" and len(parts) == 3 and parts[:2] == ["billing", "customers"]:
            return WorldResponse(
                200, services.get_customer(self.db_path, parts[2]), is_mutation=False
            )

        if method == "GET" and len(parts) == 3 and parts[:2] == ["billing", "invoices"]:
            return WorldResponse(
                200, services.get_invoice(self.db_path, parts[2]), is_mutation=False
            )

        if method == "GET" and len(parts) == 3 and parts[:2] == ["billing", "payments"]:
            return WorldResponse(
                200, services.get_payment(self.db_path, parts[2]), is_mutation=False
            )

        if method == "POST" and parts == ["billing", "refunds"]:
            body = _request_object(request.body)
            if body is None:
                return WorldResponse(
                    400, _invalid_body("refund requires a JSON object body"), is_mutation=True
                )
            payment_id = body.get("payment_id")
            reason = body.get("reason")
            ticket_id = body.get("ticket_id")
            amount = body.get("amount")
            if not isinstance(payment_id, str) or not payment_id.strip():
                return WorldResponse(
                    400, _invalid_body("refund.payment_id must be a string"), is_mutation=True
                )
            if not isinstance(reason, str) or not reason.strip():
                return WorldResponse(
                    400, _invalid_body("refund.reason must be a string"), is_mutation=True
                )
            if amount is not None and type(amount) is not int:
                return WorldResponse(
                    400, _invalid_body("refund.amount must be an int"), is_mutation=True
                )
            if ticket_id is not None and not isinstance(ticket_id, str):
                return WorldResponse(
                    400, _invalid_body("refund.ticket_id must be a string"), is_mutation=True
                )
            return WorldResponse(
                200,
                services.create_refund(
                    self.db_path,
                    payment_id=payment_id,
                    amount=amount,
                    reason=reason,
                    ticket_id=ticket_id,
                ),
                is_mutation=True,
            )

        return None


def initialize_world_state(*, run_dir: Path, config: WorldConfig) -> None:
    sample_episode(config=config, run_dir=run_dir)


def _request_object(body: dict[str, Any] | list[Any] | str | None) -> dict[str, Any] | None:
    if not isinstance(body, dict):
        return None
    return body


def _invalid_body(message: str) -> dict[str, Any]:
    return {
        "ok": False,
        "error": {
            "code": "invalid_world_request",
            "message": message,
            "details": {},
        },
    }
