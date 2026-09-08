from __future__ import annotations

import re
from copy import deepcopy
from dataclasses import dataclass
from typing import Any, Mapping

from datalox_gated_runtime.models import CallRequest, TaskBrief
from datalox_gated_runtime.world_backend import WorldResponse
from datalox_gated_runtime.world_v1.contracts import ActorContext, WorldImplementationV1
from datalox_gated_runtime.world_v1.session import WorldSession

from .contract import (
    ADD_LINE_ITEM,
    AUTHORITY,
    CREATE_CART,
    DELETE_LINE_ITEM,
    LIST_PRODUCTS,
    REGION_ID,
    RETRIEVE_CART,
    REWARD_ATOMS,
    TOOLS,
    TOOLS_BY_ID,
    UPDATE_LINE_ITEM,
    WORLD_ID,
)

_CART = re.compile(r"^/store/carts/([^/]+)$")
_LINE_ITEMS = re.compile(r"^/store/carts/([^/]+)/line-items$")
_LINE_ITEM = re.compile(r"^/store/carts/([^/]+)/line-items/([^/]+)$")


@dataclass(frozen=True)
class MedusaError(Exception):
    status: int
    error_type: str
    message: str


@dataclass(frozen=True)
class MedusaVerifierResult:
    passed: bool
    checks: tuple[dict[str, Any], ...]
    failure_codes: tuple[str, ...]
    reward_atoms: tuple[dict[str, Any], ...]
    reward: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "passed": self.passed,
            "verifier_type": WORLD_ID,
            "checks": list(self.checks),
            "failure_codes": list(self.failure_codes),
            "reward_atoms": list(self.reward_atoms),
            "reward": self.reward,
        }


class MedusaStoreCartWorld(WorldImplementationV1):
    def initialize_episode(self, *, session: WorldSession, episode: Mapping[str, Any]) -> None:
        session.reset(
            episode_id=str(episode["id"]),
            initial_state=deepcopy(dict(episode["state"])),
            initial_time=str(episode["metadata"]["clock"]),
        )

    def tool_schemas(self, *, actor: ActorContext) -> dict[str, dict[str, Any]]:
        if actor.role != "store_operator":
            return {}
        return {item["id"]: deepcopy(item["input_schema"]) for item in TOOLS}

    def operation_for_tool(self, tool_name: str) -> str | None:
        return tool_name if tool_name in TOOLS_BY_ID else None

    def tool_for_request(self, request: CallRequest) -> str | None:
        method = request.normalized_method()
        path = request.path.rstrip("/") or "/"
        if method == "GET" and path == "/store/products":
            return LIST_PRODUCTS
        if method == "POST" and path == "/store/carts":
            return CREATE_CART
        if method == "GET" and _CART.fullmatch(path):
            return RETRIEVE_CART
        if method == "POST" and _LINE_ITEMS.fullmatch(path):
            return ADD_LINE_ITEM
        if method == "POST" and _LINE_ITEM.fullmatch(path):
            return UPDATE_LINE_ITEM
        if method == "DELETE" and _LINE_ITEM.fullmatch(path):
            return DELETE_LINE_ITEM
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
        if tool_name == LIST_PRODUCTS:
            return CallRequest(
                "GET",
                "/store/products",
                scheme="https",
                authority=AUTHORITY,
                headers={"x-publishable-api-key": "pk_datalox_local_store"},
                query={
                    key: str(values[key])
                    for key in ("limit", "offset")
                    if key in values
                },
                operation_id=tool_name,
            )
        if tool_name == CREATE_CART:
            return self._request("POST", "/store/carts", values, tool_name)
        cart_id = values.pop("cart_id")
        if tool_name == RETRIEVE_CART:
            return self._request("GET", f"/store/carts/{cart_id}", None, tool_name)
        if tool_name == ADD_LINE_ITEM:
            return self._request("POST", f"/store/carts/{cart_id}/line-items", values, tool_name)
        line_item_id = values.pop("line_item_id")
        path = f"/store/carts/{cart_id}/line-items/{line_item_id}"
        if tool_name == UPDATE_LINE_ITEM:
            return self._request("POST", path, values, tool_name)
        if tool_name == DELETE_LINE_ITEM:
            return self._request("DELETE", path, None, tool_name)
        raise KeyError(tool_name)

    @staticmethod
    def _request(method: str, path: str, body: Any, operation_id: str) -> CallRequest:
        return CallRequest(
            method,
            path,
            scheme="https",
            authority=AUTHORITY,
            headers={"x-publishable-api-key": "pk_datalox_local_store"},
            body=body,
            operation_id=operation_id,
        )

    def handle(
        self,
        request: CallRequest,
        *,
        actor: ActorContext,
        session: WorldSession,
    ) -> WorldResponse | None:
        operation = self.tool_for_request(request)
        if operation is None:
            return None
        try:
            body, mutated = self._execute(operation, request, session)
        except MedusaError as error:
            session.append_event(
                "medusa_store_operation_denied",
                {
                    "operation_id": operation,
                    "actor_id": actor.actor_id,
                    "actor_role": actor.role,
                    "reason_code": error.error_type,
                    "decision": "deny",
                },
            )
            return WorldResponse(
                error.status,
                {"type": error.error_type, "message": error.message},
                False,
                WORLD_ID,
                operation,
                "deny",
                error.error_type,
                "Medusa Store operation rejected atomically.",
            )
        return WorldResponse(
            200,
            body,
            mutated,
            WORLD_ID,
            operation,
            "shadow_write" if mutated else "replay",
            "world_state_write" if mutated else "world_state_read",
            "Medusa Store operation completed against isolated state.",
        )

    def _execute(
        self, operation: str, request: CallRequest, session: WorldSession
    ) -> tuple[dict[str, Any], bool]:
        if operation == LIST_PRODUCTS:
            return self._list_products(request), False
        if operation == CREATE_CART:
            return self._create_cart(request, session), True
        if operation == RETRIEVE_CART:
            return {"cart": self._cart_from_path(request.path, session)}, False
        if operation == ADD_LINE_ITEM:
            return self._add_line_item(request, session), True
        if operation == UPDATE_LINE_ITEM:
            return self._update_line_item(request, session)
        if operation == DELETE_LINE_ITEM:
            return self._delete_line_item(request, session)
        raise AssertionError(operation)

    @staticmethod
    def _catalog() -> list[dict[str, Any]]:
        return [
            {
                "id": f"prod_datalox_pagination_{index:03d}",
                "title": f"Datalox Pagination Product {index:03d}",
                "handle": f"datalox-pagination-product-{index:03d}",
                "description": "Self-authored deterministic Medusa catalog fixture.",
                "variants": [
                    {
                        "id": f"variant_datalox_pagination_{index:03d}",
                        "title": "Default",
                        "calculated_price": {
                            "calculated_amount": 999 + index,
                            "currency_code": "usd",
                        },
                    }
                ],
            }
            for index in range(1, 51)
        ]

    def _list_products(self, request: CallRequest) -> dict[str, Any]:
        limit = self._query_integer(request.query, "limit", 50)
        offset = self._query_integer(request.query, "offset", 0)
        if limit < 0 or offset < 0:
            raise MedusaError(500, "unknown_error", "An unknown error occurred.")
        if limit > 100:
            raise MedusaError(400, "invalid_data", "limit must be at most 100.")
        catalog = self._catalog()
        return {
            "products": deepcopy(catalog[offset : offset + limit]),
            "count": len(catalog),
            "offset": offset,
            "limit": limit,
        }

    @staticmethod
    def _query_integer(query: Mapping[str, Any], name: str, default: int) -> int:
        raw = query.get(name, default)
        if type(raw) is int:
            return raw
        if isinstance(raw, str) and raw.isdecimal():
            return int(raw)
        raise MedusaError(400, "invalid_data", f"{name} must be an integer.")

    def _create_cart(self, request: CallRequest, session: WorldSession) -> dict[str, Any]:
        body = self._body(request)
        region_id = body.get("region_id")
        if region_id != REGION_ID:
            raise MedusaError(404, "not_found", f"Region with id: {region_id} was not found.")
        email = body.get("email")
        if email is not None and (not isinstance(email, str) or not email.strip()):
            raise MedusaError(400, "invalid_data", "email must be a non-empty string.")
        sequence = int(session.get_state("cart_sequence")) + 1
        cart_id = f"cart_datalox_{sequence:06d}"
        cart = {
            "id": cart_id,
            "email": email,
            "region_id": REGION_ID,
            "currency_code": "usd",
            "items": [],
            "subtotal": 0,
            "total": 0,
        }
        carts = deepcopy(session.get_state("carts"))
        carts[cart_id] = cart
        session.set_state("cart_sequence", sequence)
        session.set_state("carts", carts)
        return {"cart": deepcopy(cart)}

    def _add_line_item(self, request: CallRequest, session: WorldSession) -> dict[str, Any]:
        cart_id = self._path_match(_LINE_ITEMS, request.path)[0]
        carts = deepcopy(session.get_state("carts"))
        cart = carts.get(cart_id)
        if cart is None:
            raise MedusaError(404, "not_found", f"Cart with id: {cart_id} was not found.")
        body = self._body(request)
        variant_id = body.get("variant_id")
        variant = self._variant(variant_id)
        quantity = body.get("quantity")
        if type(quantity) is not int or quantity < 1:
            raise MedusaError(400, "invalid_data", "quantity must be a positive integer.")
        existing = next((item for item in cart["items"] if item["variant_id"] == variant_id), None)
        if existing is None:
            sequence = int(session.get_state("line_item_sequence")) + 1
            existing = {
                "id": f"cali_datalox_{sequence:06d}",
                "variant_id": variant_id,
                "product_id": variant["product_id"],
                "title": variant["title"],
                "quantity": 0,
                "unit_price": variant["unit_price"],
            }
            cart["items"].append(existing)
            session.set_state("line_item_sequence", sequence)
        existing["quantity"] += quantity
        self._recalculate(cart)
        carts[cart_id] = cart
        session.set_state("carts", carts)
        return {"cart": deepcopy(cart)}

    def _update_line_item(
        self, request: CallRequest, session: WorldSession
    ) -> tuple[dict[str, Any], bool]:
        cart_id, line_item_id = self._path_match(_LINE_ITEM, request.path)
        carts = deepcopy(session.get_state("carts"))
        cart = carts.get(cart_id)
        if cart is None:
            raise MedusaError(404, "not_found", f"Cart with id: {cart_id} was not found.")
        body = self._body(request)
        quantity = body.get("quantity")
        if type(quantity) is not int or quantity < 0:
            raise MedusaError(400, "invalid_data", "quantity must be a non-negative integer.")
        item = next((row for row in cart["items"] if row["id"] == line_item_id), None)
        if item is None:
            raise MedusaError(404, "not_found", f"Line item with id: {line_item_id} was not found.")
        previous = item["quantity"]
        if quantity == 0:
            cart["items"] = [row for row in cart["items"] if row["id"] != line_item_id]
        else:
            item["quantity"] = quantity
        mutated = previous != quantity
        if mutated:
            self._recalculate(cart)
            carts[cart_id] = cart
            session.set_state("carts", carts)
        return {"cart": deepcopy(cart)}, mutated

    def _delete_line_item(
        self, request: CallRequest, session: WorldSession
    ) -> tuple[dict[str, Any], bool]:
        cart_id, line_item_id = self._path_match(_LINE_ITEM, request.path)
        carts = deepcopy(session.get_state("carts"))
        cart = carts.get(cart_id)
        if cart is None:
            raise MedusaError(500, "unknown_error", "An unknown error occurred.")
        previous = len(cart["items"])
        cart["items"] = [row for row in cart["items"] if row["id"] != line_item_id]
        mutated = len(cart["items"]) != previous
        if mutated:
            self._recalculate(cart)
            carts[cart_id] = cart
            session.set_state("carts", carts)
        return {
            "id": line_item_id,
            "object": "line-item",
            "deleted": True,
            "parent": deepcopy(cart),
        }, mutated

    def _cart_from_path(self, path: str, session: WorldSession) -> dict[str, Any]:
        cart_id = self._path_match(_CART, path)[0]
        cart = session.get_state("carts").get(cart_id)
        if cart is None:
            raise MedusaError(404, "not_found", f"Cart with id: {cart_id} was not found.")
        return deepcopy(cart)

    def _variant(self, variant_id: Any) -> dict[str, Any]:
        if not isinstance(variant_id, str):
            raise MedusaError(400, "invalid_data", "variant_id must be a string.")
        for product in self._catalog():
            variant = product["variants"][0]
            if variant["id"] == variant_id:
                return {
                    "product_id": product["id"],
                    "title": product["title"],
                    "unit_price": variant["calculated_price"]["calculated_amount"],
                }
        raise MedusaError(400, "invalid_data", f"Variant with id: {variant_id} was not found.")

    @staticmethod
    def _body(request: CallRequest) -> dict[str, Any]:
        if not isinstance(request.body, Mapping):
            raise MedusaError(400, "invalid_data", "Request body must be an object.")
        return dict(request.body)

    @staticmethod
    def _path_match(pattern: re.Pattern[str], path: str) -> tuple[str, ...]:
        matched = pattern.fullmatch(path.rstrip("/") or "/")
        if matched is None:
            raise AssertionError(path)
        return matched.groups()

    @staticmethod
    def _recalculate(cart: dict[str, Any]) -> None:
        subtotal = sum(
            item["unit_price"] * item["quantity"] for item in cart["items"]
        )
        cart["subtotal"] = subtotal
        cart["total"] = subtotal

    def verify(
        self, *, session: WorldSession, episode: Mapping[str, Any]
    ) -> MedusaVerifierResult:
        expected = episode.get("expected", {})
        carts = session.list_state()["carts"]
        cart = next(iter(carts.values()), None) if len(carts) == 1 else None
        items = cart.get("items", []) if isinstance(cart, dict) else []
        denied = [
            event
            for event in session.verifier_events()
            if event["event_type"] == "medusa_store_operation_denied"
        ]
        checks_raw = (
            ("cart_created", cart is not None and cart.get("email") == expected.get("email")),
            (
                "line_item_quantity_set",
                len(items) == 1
                and items[0].get("variant_id") == expected.get("variant_id")
                and items[0].get("quantity") == expected.get("quantity"),
            ),
            ("no_denied_operations", not denied),
        )
        checks = tuple(
            {"failure_code": code, "passed": bool(passed)} for code, passed in checks_raw
        )
        failures = tuple(item["failure_code"] for item in checks if not item["passed"])
        atoms = tuple(
            {"id": code, "earned": code not in failures, "value": float(code not in failures)}
            for code in REWARD_ATOMS
        )
        return MedusaVerifierResult(
            not failures,
            checks,
            failures,
            atoms,
            sum(item["value"] for item in atoms) / len(atoms),
        )

    def task(self, *, episode: Mapping[str, Any]) -> TaskBrief:
        task = episode["task"]
        return TaskBrief(
            task_id=str(task["task_id"]),
            title=str(task["title"]),
            instructions=str(task["instructions"]),
            success_criteria=tuple(str(item) for item in task["success_criteria"]),
        )


def create_world() -> MedusaStoreCartWorld:
    return MedusaStoreCartWorld()
