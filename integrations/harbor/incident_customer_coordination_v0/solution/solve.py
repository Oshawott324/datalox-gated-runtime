from __future__ import annotations

import json
from typing import Any
from urllib.request import Request, urlopen

BASE_URL = "http://world:8000/actors"
PROTOCOL_VERSION = "2025-11-25"

STEPS: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("incident_commander", "datadog.list_incidents", {}),
    ("incident_commander", "datadog.list_service_definitions", {}),
    ("incident_commander", "datadog.list_users", {}),
    (
        "incident_commander",
        "datadog.get_current_oncall",
        {"schedule_id": "10000000-0000-4000-8000-000000000000"},
    ),
    ("support_owner", "hubspot.list_owners", {}),
    ("support_owner", "hubspot.list_contacts", {}),
    ("support_owner", "hubspot.list_companies", {}),
    ("support_owner", "hubspot.list_deals", {}),
    ("support_owner", "hubspot.list_tickets", {}),
    ("support_owner", "hubspot.get_ticket", {"ticket_id": "40000"}),
    ("incident_commander", "jira.get_issue", {"issue_id": "OPS-100"}),
    ("incident_commander", "jira.list_priorities", {}),
    ("incident_commander", "jira.get_transitions", {"issue_id": "OPS-100"}),
    ("incident_commander", "jira.list_assignable_users", {}),
    ("support_owner", "jira.get_customer_request", {"request_id": "SUP-500"}),
    ("communications", "microsoft_graph.list_users", {}),
    (
        "communications",
        "microsoft_graph.get_calendar_view",
        {"user_id": "30000000-0000-4000-8000-000000000000"},
    ),
    (
        "incident_commander",
        "jira.update_issue",
        {
            "issue_id": "OPS-100",
            "fields": {
                "assignee": {"accountId": "712020:000000000000000000000000"},
                "priority": {"id": "1"},
            },
        },
    ),
    (
        "incident_commander",
        "jira.transition_issue",
        {"issue_id": "OPS-100", "transition": {"id": "3"}},
    ),
    (
        "support_owner",
        "hubspot.update_ticket",
        {
            "ticket_id": "40000",
            "properties": {
                "hs_pipeline_stage": "in_progress",
                "hs_ticket_priority": "HIGH",
                "hubspot_owner_id": "8000",
            },
        },
    ),
    (
        "communications",
        "microsoft_graph.create_message_draft",
        {
            "importance": "high",
            "subject": "Internal coordination: OPS-100 / northstar-retail-00-0.example.test",
            "body": {
                "contentType": "Text",
                "content": (
                    "Coordinate OPS-100 for checkout-api at 2026-07-13T10:30:00Z. "
                    "JSM request SUP-500 is from "
                    "ops@northstar-retail-00-0.example.test; Datadog severity is "
                    "SEV-1; confirmed customer impact is true; 1 account(s) are "
                    "linked and northstar-retail-00-0.example.test has the nearest "
                    "open renewal. This is an internal draft only."
                ),
            },
            "toRecipients": [
                {
                    "emailAddress": {
                        "address": "customer.success.00@operations.example.test",
                        "name": "Taylor Success 00",
                    }
                },
                {
                    "emailAddress": {
                        "address": "casey.chen@operations.example.test",
                        "name": "Casey Chen",
                    }
                },
            ],
        },
    ),
)


class McpClient:
    def __init__(self, role: str) -> None:
        self.url = f"{BASE_URL}/{role}/mcp"
        initialized, headers = self._post(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": PROTOCOL_VERSION,
                    "capabilities": {},
                    "clientInfo": {"name": "datalox-harbor-oracle", "version": "1"},
                },
            },
            session_id=None,
        )
        if "error" in initialized:
            raise RuntimeError(f"MCP initialize failed: {initialized['error']}")
        self.session_id = headers.get("Mcp-Session-Id")
        if not self.session_id:
            raise RuntimeError("MCP server did not return Mcp-Session-Id")
        self._post(
            {"jsonrpc": "2.0", "method": "notifications/initialized"},
            session_id=self.session_id,
            allow_empty=True,
        )

    def call(self, request_id: int, name: str, arguments: dict[str, Any]) -> None:
        message, _ = self._post(
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            },
            session_id=self.session_id,
        )
        if "error" in message:
            raise RuntimeError(f"{name} failed: {message['error']}")
        result = message.get("result")
        if not isinstance(result, dict) or result.get("isError") is True:
            raise RuntimeError(f"{name} returned an invalid MCP result: {result!r}")
        structured = result.get("structuredContent")
        if isinstance(structured, dict):
            status = structured.get("status_code")
            if isinstance(status, int) and status >= 400:
                raise RuntimeError(f"{name} returned status {status}: {structured!r}")

    def _post(
        self,
        payload: dict[str, Any],
        *,
        session_id: str | None,
        allow_empty: bool = False,
    ) -> tuple[dict[str, Any], Any]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "Content-Type": "application/json",
        }
        if session_id is not None:
            headers["Mcp-Session-Id"] = session_id
        request = Request(
            self.url,
            data=json.dumps(payload, separators=(",", ":")).encode(),
            headers=headers,
            method="POST",
        )
        with urlopen(request, timeout=30) as response:
            raw = response.read().decode()
            response_headers = response.headers
        if not raw.strip() and allow_empty:
            return {}, response_headers
        return _decode_message(raw), response_headers


def _decode_message(raw: str) -> dict[str, Any]:
    content = raw.strip()
    if content.startswith("{"):
        message = json.loads(content)
    else:
        data_lines = [line[5:].strip() for line in content.splitlines() if line.startswith("data:")]
        if not data_lines:
            raise RuntimeError(f"MCP response contained no data event: {content!r}")
        message = json.loads(data_lines[-1])
    if not isinstance(message, dict):
        raise TypeError("MCP response must be a JSON object")
    return message


def main() -> None:
    clients: dict[str, McpClient] = {}
    for request_id, (role, tool_name, arguments) in enumerate(STEPS, start=10):
        client = clients.get(role)
        if client is None:
            client = McpClient(role)
            clients[role] = client
        client.call(request_id, tool_name, arguments)


if __name__ == "__main__":
    main()
