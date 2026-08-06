from __future__ import annotations

import hashlib
import json
import random
from datetime import UTC, datetime, timedelta
from pathlib import Path

from datalox_gated_runtime.models import WorldConfig
from datalox_gated_runtime.worlds.billing_support_v0.state import (
    dumps_json,
    initialize_db,
    insert_event,
    metadata_path,
    world_dir,
)
from datalox_gated_runtime.worlds.billing_support_v0.state import connect

WORLD = "billing_support_v0"
BASE_TIME = datetime(2026, 2, 18, 15, 30, tzinfo=UTC)
SUPPORT_EMAIL = "support@api-gym.example"


def sample_episode(*, config: WorldConfig, run_dir: Path) -> None:
    if config.scenario != "duplicate_payment_refund":
        raise ValueError("billing_support_v0 supports only duplicate_payment_refund")

    directory = world_dir(run_dir)
    db_path = directory / config.state_db
    run_metadata_path = metadata_path(run_dir)
    if db_path.exists() or run_metadata_path.exists():
        raise FileExistsError(
            f"Run directory already contains billing_support_v0 state: {directory}"
        )

    initialize_db(db_path)
    _build_duplicate_payment_refund(db_path, config.seed)
    run_metadata = {
        "world": WORLD,
        "scenario": config.scenario,
        "seed": config.seed,
        "state_db": config.state_db,
        "verifier": config.verifier,
    }
    run_metadata_path.write_text(
        json.dumps(run_metadata, indent=2, sort_keys=True), encoding="utf-8"
    )


def _stable_prefix(scenario: str, seed: int) -> str:
    digest = hashlib.sha256(f"{WORLD}:{scenario}:{seed}".encode("utf-8")).hexdigest()
    return digest[:10]


def _rng(scenario: str, seed: int) -> random.Random:
    digest = hashlib.sha256(f"rng:{WORLD}:{scenario}:{seed}".encode("utf-8")).digest()
    return random.Random(int.from_bytes(digest[:8], "big"))


def _iso(days: int = 0, minutes: int = 0) -> str:
    return (BASE_TIME + timedelta(days=days, minutes=minutes)).isoformat().replace("+00:00", "Z")


def _scenario_context(scenario: str, seed: int) -> dict[str, str]:
    rng = _rng(scenario, seed)
    customer_pool = [
        ("Maya Patel", "maya.patel@example.test", "Northstar Analytics"),
        ("Jon Bell", "jon.bell@example.test", "Cedar Labs"),
        ("Elena Rossi", "elena.rossi@example.test", "Harbor Metrics"),
        ("Sam Rivera", "sam.rivera@example.test", "Brightpath Ops"),
    ]
    name, email, account = rng.choice(customer_pool)
    prefix = _stable_prefix(scenario, seed)
    return {
        "prefix": prefix,
        "account_id": f"acct_{prefix}",
        "customer_id": f"cus_{prefix}",
        "subscription_id": f"sub_{prefix}",
        "ticket_id": f"tkt_{prefix}",
        "customer_name": name,
        "customer_email": email,
        "account_name": account,
    }


def _insert_common_customer(conn, ctx: dict[str, str], *, created_at: str) -> None:
    conn.execute(
        """
        INSERT INTO accounts (id, name, support_plan, default_currency, created_at, metadata_json)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            ctx["account_id"],
            ctx["account_name"],
            "business",
            "usd",
            created_at,
            dumps_json({"crm_segment": "smb", "region": "us"}),
        ),
    )
    conn.execute(
        """
        INSERT INTO customers (
          id, account_id, email, name, phone, default_payment_method, delinquent, created_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ctx["customer_id"],
            ctx["account_id"],
            ctx["customer_email"],
            ctx["customer_name"],
            "+1-415-555-0137",
            "pm_card_visa_4242",
            0,
            created_at,
            dumps_json({"external_crm_id": f"crm_{ctx['prefix']}"}),
        ),
    )
    conn.execute(
        """
        INSERT INTO subscriptions (
          id, customer_id, status, plan_name, current_period_start, current_period_end,
          cancel_at_period_end, created_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ctx["subscription_id"],
            ctx["customer_id"],
            "active",
            "Growth",
            _iso(-20),
            _iso(10),
            0,
            created_at,
            dumps_json({"billing_interval": "month"}),
        ),
    )
    conn.execute(
        """
        INSERT INTO policies (id, policy_key, version, body_json, active, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (
            "pol_refund_standard_v1",
            "standard_refund_policy",
            "2026-02",
            dumps_json(
                {
                    "refund_window_days": 120,
                    "duplicate_payment_reason": "duplicate",
                    "allowed_reasons": ["duplicate", "fraudulent", "requested_by_customer"],
                }
            ),
            1,
            created_at,
        ),
    )


def _insert_ticket(
    conn,
    ctx: dict[str, str],
    *,
    subject: str,
    customer_body: str,
    tags: list[str],
    created_at: str,
) -> None:
    conn.execute(
        """
        INSERT INTO tickets (
          id, customer_id, requester_email, subject, status, priority, assignee_group,
          tags_json, created_at, updated_at, metadata_json
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ctx["ticket_id"],
            ctx["customer_id"],
            ctx["customer_email"],
            subject,
            "open",
            "normal",
            "billing-support",
            dumps_json(tags),
            created_at,
            created_at,
            dumps_json({"channel": "email"}),
        ),
    )
    conn.execute(
        """
        INSERT INTO ticket_messages (ticket_id, author_type, author_email, body, public, created_at)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        (ctx["ticket_id"], "customer", ctx["customer_email"], customer_body, 1, created_at),
    )
    conn.execute(
        """
        INSERT INTO emails (
          ticket_id, customer_id, to_email, from_email, subject, body, status, provider_message_id, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            ctx["ticket_id"],
            ctx["customer_id"],
            SUPPORT_EMAIL,
            ctx["customer_email"],
            subject,
            customer_body,
            "received",
            f"msg_{ctx['prefix']}_inbound",
            created_at,
        ),
    )


def _build_duplicate_payment_refund(db_path: Path, seed: int) -> None:
    scenario = "duplicate_payment_refund"
    ctx = _scenario_context(scenario, seed)
    invoice_id = f"in_{ctx['prefix']}_01"
    original_payment_id = f"py_{ctx['prefix']}_ok_01"
    duplicate_payment_id = f"py_{ctx['prefix']}_dup_02"
    amount = 4900
    created_at = _iso(-3)

    with connect(db_path) as conn:
        _insert_common_customer(conn, ctx, created_at=created_at)
        conn.execute(
            """
            INSERT INTO invoices (
              id, customer_id, subscription_id, number, status, collection_method, currency,
              amount_due, amount_paid, amount_remaining, attempt_count,
              due_date, paid_at, created_at, metadata_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                invoice_id,
                ctx["customer_id"],
                ctx["subscription_id"],
                f"BS-{ctx['prefix'].upper()}-001",
                "paid",
                "charge_automatically",
                "usd",
                amount,
                amount,
                0,
                1,
                _iso(-2),
                _iso(-2, 10),
                created_at,
                dumps_json({"duplicate_payment_candidate": duplicate_payment_id}),
            ),
        )
        for payment_id, metadata, created in (
            (original_payment_id, {"network_status": "approved_by_network"}, _iso(-2, 10)),
            (
                duplicate_payment_id,
                {"duplicate_of": original_payment_id, "network_status": "approved_by_network"},
                _iso(-2, 13),
            ),
        ):
            conn.execute(
                """
                INSERT INTO payments (
                  id, customer_id, invoice_id, amount, currency, status, payment_method,
                  payment_intent_id, charge_id, created_at, metadata_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    payment_id,
                    ctx["customer_id"],
                    invoice_id,
                    amount,
                    "usd",
                    "succeeded",
                    "card_visa_4242",
                    f"pi_{payment_id}",
                    f"ch_{payment_id}",
                    created,
                    dumps_json(metadata),
                ),
            )
        conn.execute(
            "UPDATE invoices SET latest_payment_id = ? WHERE id = ?",
            (original_payment_id, invoice_id),
        )
        _insert_ticket(
            conn,
            ctx,
            subject="Charged twice for the same invoice",
            customer_body=(
                f"I see two card charges for ${amount / 100:.2f} against invoice {invoice_id}. "
                "One looks like a duplicate. Please refund the extra charge."
            ),
            tags=["billing", "refund_request", "duplicate_payment"],
            created_at=_iso(-1),
        )
        expected = {
            "scenario": scenario,
            "ticket_id": ctx["ticket_id"],
            "customer_id": ctx["customer_id"],
            "invoice_id": invoice_id,
            "refund_payment_id": duplicate_payment_id,
            "do_not_refund_payment_id": original_payment_id,
            "refund_amount": amount,
            "refund_reason": "duplicate",
            "reply_must_mention": ["refund"],
        }
        insert_event(
            conn,
            event_type="expected_resolution.created",
            object_type="scenario",
            object_id=scenario,
            payload=expected,
            created_at=_iso(-1),
            visible_to_agent=False,
        )
