from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from datalox_gated_runtime.worlds.billing_support_v0.state import (
    connect,
    dumps_json,
    insert_audit,
    insert_event,
    row_to_dict,
)

AGENT_EMAIL = "agent@billing-support.example"
SUPPORT_EMAIL = "support@api-gym.example"
ALLOWED_REFUND_REASONS = {"duplicate", "fraudulent", "requested_by_customer"}


def get_ticket(db_path: Path, ticket_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if ticket is None:
            return _error("ticket_not_found", "Ticket does not exist.", {"ticket_id": ticket_id})
        messages = conn.execute(
            "SELECT * FROM ticket_messages WHERE ticket_id = ? ORDER BY id",
            (ticket_id,),
        ).fetchall()
        data = row_to_dict(ticket)
        data["messages"] = [row_to_dict(row) for row in messages]
        return _ok(data)


def add_reply(
    db_path: Path,
    *,
    ticket_id: str,
    body: str,
    public: bool = True,
    actor_email: str = AGENT_EMAIL,
) -> dict[str, Any]:
    body = body.strip()
    if not body:
        return _error(
            "empty_reply", "Ticket replies require a non-empty body.", {"ticket_id": ticket_id}
        )

    now = _now()
    with connect(db_path) as conn:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if ticket is None:
            return _error("ticket_not_found", "Ticket does not exist.", {"ticket_id": ticket_id})
        conn.execute(
            """
            INSERT INTO ticket_messages (ticket_id, author_type, author_email, body, public, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (ticket_id, "agent", actor_email, body, int(public), now),
        )
        conn.execute("UPDATE tickets SET updated_at = ? WHERE id = ?", (now, ticket_id))
        if public:
            conn.execute(
                """
                INSERT INTO emails (
                  ticket_id, customer_id, to_email, from_email, subject, body, status, provider_message_id, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ticket_id,
                    ticket["customer_id"],
                    ticket["requester_email"],
                    SUPPORT_EMAIL,
                    f"Re: {ticket['subject']}",
                    body,
                    "sent",
                    f"msg_{ticket_id}_{_message_count(conn, ticket_id) + 1}",
                    now,
                ),
            )
        response = {"ticket_id": ticket_id, "public": public, "body": body}
        insert_event(
            conn,
            event_type="ticket.comment_created",
            object_type="ticket",
            object_id=ticket_id,
            payload=response,
            created_at=now,
        )
        insert_audit(
            conn,
            actor=actor_email,
            action="support.add_reply",
            object_type="ticket",
            object_id=ticket_id,
            request={"body": body, "public": public},
            response=response,
            created_at=now,
        )
        return _ok(response)


def close_ticket(
    db_path: Path, *, ticket_id: str, actor_email: str = AGENT_EMAIL
) -> dict[str, Any]:
    now = _now()
    with connect(db_path) as conn:
        ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
        if ticket is None:
            return _error("ticket_not_found", "Ticket does not exist.", {"ticket_id": ticket_id})
        conn.execute(
            "UPDATE tickets SET status = ?, updated_at = ?, closed_at = ? WHERE id = ?",
            ("solved", now, now, ticket_id),
        )
        response = {"ticket_id": ticket_id, "status": "solved"}
        insert_event(
            conn,
            event_type="ticket.solved",
            object_type="ticket",
            object_id=ticket_id,
            payload=response,
            created_at=now,
        )
        insert_audit(
            conn,
            actor=actor_email,
            action="support.close_ticket",
            object_type="ticket",
            object_id=ticket_id,
            request={},
            response=response,
            created_at=now,
        )
        return _ok(response)


def get_customer(db_path: Path, customer_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        customer = conn.execute("SELECT * FROM customers WHERE id = ?", (customer_id,)).fetchone()
        if customer is None:
            return _error(
                "customer_not_found", "Customer does not exist.", {"customer_id": customer_id}
            )
        data = row_to_dict(customer)
        data["subscriptions"] = [
            row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM subscriptions WHERE customer_id = ? ORDER BY created_at",
                (customer_id,),
            )
        ]
        data["invoices"] = [
            row_to_dict(row)
            for row in conn.execute(
                "SELECT * FROM invoices WHERE customer_id = ? ORDER BY created_at",
                (customer_id,),
            )
        ]
        return _ok(data)


def get_invoice(db_path: Path, invoice_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        invoice = conn.execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
        if invoice is None:
            return _error(
                "invoice_not_found", "Invoice does not exist.", {"invoice_id": invoice_id}
            )
        payments = conn.execute(
            "SELECT * FROM payments WHERE invoice_id = ? ORDER BY created_at, id",
            (invoice_id,),
        ).fetchall()
        data = row_to_dict(invoice)
        data["payments"] = [row_to_dict(row) for row in payments]
        return _ok(data)


def get_payment(db_path: Path, payment_id: str) -> dict[str, Any]:
    with connect(db_path) as conn:
        payment = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        if payment is None:
            return _error(
                "payment_not_found", "Payment does not exist.", {"payment_id": payment_id}
            )
        refunds = conn.execute(
            "SELECT * FROM refunds WHERE payment_id = ? ORDER BY created_at, id",
            (payment_id,),
        ).fetchall()
        data = row_to_dict(payment)
        data["refunds"] = [row_to_dict(row) for row in refunds]
        data["refundable_amount"] = payment["amount"] - payment["refunded_amount"]
        return _ok(data)


def create_refund(
    db_path: Path,
    *,
    payment_id: str,
    amount: int | None = None,
    reason: str,
    ticket_id: str | None = None,
    actor_email: str = AGENT_EMAIL,
) -> dict[str, Any]:
    reason = reason.strip()
    if reason not in ALLOWED_REFUND_REASONS:
        return _error(
            "invalid_refund_reason",
            "Refund reason must match a supported billing reason.",
            {"allowed_reasons": sorted(ALLOWED_REFUND_REASONS), "reason": reason},
        )

    now = _now()
    with connect(db_path) as conn:
        payment = conn.execute("SELECT * FROM payments WHERE id = ?", (payment_id,)).fetchone()
        if payment is None:
            return _error(
                "payment_not_found", "Payment does not exist.", {"payment_id": payment_id}
            )
        if ticket_id is not None:
            ticket = conn.execute("SELECT * FROM tickets WHERE id = ?", (ticket_id,)).fetchone()
            if ticket is None:
                return _error(
                    "ticket_not_found", "Ticket does not exist.", {"ticket_id": ticket_id}
                )
        if payment["status"] != "succeeded":
            return _error(
                "payment_not_refundable",
                "Only succeeded payments can be refunded.",
                {"payment_id": payment_id, "status": payment["status"]},
            )

        remaining = payment["amount"] - payment["refunded_amount"]
        refund_amount = remaining if amount is None else amount
        if type(refund_amount) is not int or refund_amount <= 0:
            return _error(
                "invalid_refund_amount",
                "Refund amount must be positive.",
                {"amount": refund_amount},
            )
        if refund_amount > remaining:
            return _error(
                "refund_amount_exceeds_remaining",
                "Refund amount exceeds the unrefunded payment amount.",
                {"payment_id": payment_id, "remaining": remaining, "requested": refund_amount},
            )

        refund_id = _next_refund_id(conn, payment_id)
        conn.execute(
            """
            INSERT INTO refunds (
              id, payment_id, amount, currency, status, reason, ticket_id, created_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                refund_id,
                payment_id,
                refund_amount,
                payment["currency"],
                "succeeded",
                reason,
                ticket_id,
                now,
                dumps_json({"created_by": actor_email}),
            ),
        )
        conn.execute(
            "UPDATE payments SET refunded_amount = refunded_amount + ? WHERE id = ?",
            (refund_amount, payment_id),
        )
        response = {
            "id": refund_id,
            "payment_id": payment_id,
            "amount": refund_amount,
            "currency": payment["currency"],
            "status": "succeeded",
            "reason": reason,
            "ticket_id": ticket_id,
        }
        insert_event(
            conn,
            event_type="refund.succeeded",
            object_type="refund",
            object_id=refund_id,
            payload=response,
            created_at=now,
        )
        insert_event(
            conn,
            event_type="charge.refunded",
            object_type="payment",
            object_id=payment_id,
            payload={"refund_id": refund_id, "amount": refund_amount, "reason": reason},
            created_at=now,
        )
        insert_audit(
            conn,
            actor=actor_email,
            action="billing.create_refund",
            object_type="payment",
            object_id=payment_id,
            request={"amount": amount, "reason": reason, "ticket_id": ticket_id},
            response=response,
            created_at=now,
        )
        return _ok(response)


def _ok(data: dict[str, Any]) -> dict[str, Any]:
    return {"ok": True, "data": data}


def _error(code: str, message: str, details: dict[str, Any]) -> dict[str, Any]:
    return {"ok": False, "error": {"code": code, "message": message, "details": details}}


def _now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _message_count(conn, ticket_id: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM ticket_messages WHERE ticket_id = ?", (ticket_id,)
    ).fetchone()
    return int(row["count"])


def _next_refund_id(conn, payment_id: str) -> str:
    row = conn.execute(
        "SELECT COUNT(*) AS count FROM refunds WHERE payment_id = ?", (payment_id,)
    ).fetchone()
    return f"re_{payment_id}_{int(row['count']) + 1}"
