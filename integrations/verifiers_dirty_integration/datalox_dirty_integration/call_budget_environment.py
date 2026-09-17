"""Native Verifiers extension: a controller-owned provider invocation limit.

The six original tools, episode, policy and rubric remain unchanged. The
controller dispatches each requested tool through StatefulToolEnv.env_response
and counts its recorded provider invocation, including writes and fault results.
"""

from __future__ import annotations

from typing import Any
import inspect
import json

import verifiers as vf

from datalox_dirty_integration.environment import (
    DataloxDirtyIntegrationEnv,
    list_products,
    create_cart,
    get_cart,
    add_line_item,
    update_line_item,
    delete_line_item,
)
from datalox_dirty_integration.repeat_arms import effect_digest


def provider_tool_binds(tool: dict[str, Any]) -> bool:
    """Use the real Python call signatures; annotations do not validate values."""
    tools = {
        function.__name__: function
        for function in (
            list_products,
            create_cart,
            get_cart,
            add_line_item,
            update_line_item,
            delete_line_item,
        )
    }
    function = tools.get(tool["name"])
    if function is None:
        return False
    try:
        arguments = json.loads(tool["arguments"])
        if not isinstance(arguments, dict):
            return False
        inspect.signature(function).bind(**{**arguments, "episode": None})
    except (TypeError, ValueError):
        return False
    return True


class CallBudgetIntegrationEnv(DataloxDirtyIntegrationEnv):
    def __init__(self, *, provider_call_budget: int | None, **kwargs: Any) -> None:
        if provider_call_budget is not None and (
            type(provider_call_budget) is not int or provider_call_budget != 12
        ):
            raise ValueError("V2 provider_call_budget must be 12 or None")
        self._provider_call_budget = provider_call_budget
        self._rejections: dict[str, dict[str, Any]] = {}
        super().__init__(**kwargs)

    @vf.stop(priority=90)
    async def harness_call_budget_exhausted(self, state: vf.State) -> bool:
        return state["trajectory_id"] in self._rejections

    async def env_response(
        self, messages: vf.Messages, state: vf.State, **kwargs: Any
    ) -> vf.Messages:
        # This is Verifiers' documented environment-response extension. Keep
        # its parsing, argument injection, error formatting and tool dispatch.
        assert isinstance(messages, list)
        last = messages[-1]
        assert isinstance(last, vf.AssistantMessage)
        assert last.tool_calls is not None
        episode = self._episodes[state["trajectory_id"]]
        delivered = []
        for tool in last.tool_calls:
            if (
                self._provider_call_budget is not None
                and len(episode.delivered_calls) >= self._provider_call_budget
                and provider_tool_binds(tool.model_dump())
            ):
                self._rejections[state["trajectory_id"]] = {
                    "requested_call_number": self._provider_call_budget + 1,
                    "tool": tool.model_dump(exclude_none=True),
                    "effect_sha256": effect_digest(episode.export()),
                }
                # A final environment response tells the native loop to check
                # stop predicates before asking the model again. It consists
                # solely of genuine observations already produced in this batch.
                state["final_env_response"] = delivered
                return delivered
            one_call = last.model_copy(update={"tool_calls": [tool]})
            delivered.extend(
                await super().env_response([*messages[:-1], one_call], state, **kwargs)
            )
        return delivered

    def _controller_evidence(self, state: vf.State, exported: dict[str, Any]) -> dict[str, Any]:
        rejection = self._rejections.pop(state["trajectory_id"], None)
        if rejection is not None and rejection["effect_sha256"] != effect_digest(exported):
            raise RuntimeError("provider or intervention state changed after budget rejection")
        return {
            "schema_version": "datalox_harness_call_budget_v1",
            "limit": self._provider_call_budget,
            "executed_provider_calls": len(exported["delivered_calls"]),
            "rejection": rejection,
            "termination_reason": state["stop_condition"],
        }

    async def cleanup(
        self, state: vf.State, task: object | None = None, resources: object | None = None
    ) -> None:
        try:
            await super().cleanup(state, task=task, resources=resources)
        finally:
            self._rejections.pop(state["trajectory_id"], None)
