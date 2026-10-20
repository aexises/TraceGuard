"""Explicit guarded native dispatch; approval-only consequential execution is unsupported."""

from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import dataclass
from decimal import Decimal
from pathlib import Path
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from traceguard.control.service import AuthorizationError
from traceguard.control.signing import canonical
from traceguard.integrations.gateway import SupervisionGateway
from traceguard.ledger import ExecutionLedger, ExecutionUnknown
from traceguard.supervisor.redaction import redact_value
from traceguard.types import Decision, ToolCall


@dataclass(frozen=True)
class InspectExecution:
    message: Any
    replayed: bool
    status: str = "succeeded"


class GuardedInspectExecutor:
    """Trusted application dispatch path for native str-result tools and stable native IDs.

    The application must exclusively expose this route to its agent/solver. Raw tool
    callbacks and provider credentials remain trusted and must be isolated separately.
    """

    def __init__(
        self,
        gateway: SupervisionGateway,
        *,
        task_id: str,
        ledger_path: Path,
        ledger_id: str,
        tools: list[Any],
        result_policy_version: str = "inspect-receipt-v1",
    ) -> None:
        from inspect_ai.tool import ToolDef

        if gateway.compiled is None or not task_id or not result_policy_version:
            raise ValueError(
                "guarded native dispatch requires strict authority and trusted task/policy"
            )
        self.gateway, self.task_id = gateway, task_id
        self.ledger = ExecutionLedger(ledger_path, expected_store_id=ledger_id)
        definitions = [ToolDef(tool) for tool in tools]
        self.tools = {tool.name: tool for tool in definitions}
        if len(self.tools) != len(definitions):
            raise ValueError("duplicate native tool names")
        from traceguard.policy.read_resources import EXTENSION

        for tool in definitions:
            actual = tool.parameters.model_dump(mode="json", exclude_none=True)
            approved = deepcopy(gateway.available_tools.get(tool.name, {}))
            approved.pop(EXTENSION, None)
            if actual != approved:
                raise ValueError("native handler schema differs from approved tool schema")
        if set(gateway.task_authority.allowed_tools or []) - set(self.tools):
            raise ValueError("approved native tool is unavailable")
        self.result_policy = hashlib.sha256(
            canonical(
                {
                    "version": result_policy_version,
                    "authority": gateway.compiled.digest,
                }
            )
        ).hexdigest()

    async def execute(
        self, native_call: Any, *, user_goal: str, history: list[Any]
    ) -> InspectExecution:
        from inspect_ai.model import ChatMessageTool

        from traceguard.integrations.inspect import _inspect_history_observations

        call = deepcopy(native_call)
        if not call.id or len(call.id) > 256 or call.parse_error:
            raise AuthorizationError("a valid stable native call ID is required")
        nonce = str(
            uuid5(
                NAMESPACE_URL,
                canonical(
                    {
                        "domain": self.ledger.store_id,
                        "task": self.task_id,
                        "native_id": call.id,
                    }
                ).decode(),
            )
        )
        proposed = ToolCall(
            task_id=self.task_id,
            step_id=0,
            call_id=nonce,
            tool_name=call.function,
            arguments=deepcopy(call.arguments),
        )
        observations = _inspect_history_observations(history)
        # Current hard authority precedes cached replay; result text is never accounting.
        checked = self.gateway.compiled.evaluate(user_goal, proposed, observations)
        if checked.decision is not Decision.ALLOW:
            raise AuthorizationError(checked.reason)
        proposed = self.gateway.compiled.normalize_read(proposed)
        payload = {"tool": proposed.tool_name, "arguments": proposed.arguments}
        digest = hashlib.sha256(canonical(payload)).hexdigest()
        try:
            existing = self.ledger.lookup(nonce)
        except KeyError:
            existing = None
        effective = proposed
        if existing is None:
            effective, decision = self.gateway.evaluate(
                task_id=self.task_id,
                step_id=0,
                user_goal=user_goal,
                tool_name=call.function,
                arguments=call.arguments,
                observations=observations,
            )
            if decision.decision is not Decision.ALLOW:
                raise AuthorizationError(decision.reason)
            # An effectful rewrite needs a distinct reviewed native proposal/ID. Do not
            # silently reuse an original native ID for changed arguments across retries.
            if (effective.tool_name, effective.arguments) != (
                proposed.tool_name,
                proposed.arguments,
            ):
                raise AuthorizationError("resubmit the validated rewrite as a new native call")
            effective.call_id = nonce
        replay = self.ledger.reserve(
            scope=("inspect", "application", self.gateway.compiled.digest, self.task_id),
            nonce=nonce,
            idempotency_key=nonce,
            digest=digest,
            effect_digest=digest,
            amount=Decimal(str(effective.arguments.get("amount", 0)))
            if effective.tool_name in {"send_money", "schedule_transaction"}
            else Decimal(0),
            budget_limit=str(self.gateway.task_authority.max_amount)
            if self.gateway.task_authority.max_amount is not None
            else None,
            repeatable=effective.tool_name in self.gateway.task_authority.repeatable_tools,
            result_policy=self.result_policy,
        )
        if replay is not None:
            if replay["result"] is None:
                raise ExecutionUnknown("native result is withheld or requires review")
            return InspectExecution(
                ChatMessageTool(
                    content=replay["result"], tool_call_id=call.id, function=call.function
                ),
                True,
            )
        try:
            value = await self.tools[effective.tool_name].tool(**deepcopy(effective.arguments))
            if not isinstance(value, str) or len(value.encode()) > 1_048_576:
                raise ValueError("guarded native tools require bounded UTF-8 string results")
            try:
                value = json.dumps(redact_value(json.loads(value)), sort_keys=True)
            except json.JSONDecodeError:
                value = redact_value(value)
        except BaseException as exc:
            self.ledger.finish(nonce, "unknown")
            if isinstance(exc, Exception):
                raise ExecutionUnknown(
                    "native dispatch outcome unknown; reconcile before retry"
                ) from exc
            raise
        self.ledger.finish(nonce, "succeeded", value, disposition="accepted_for_agent")
        self.gateway.observation(effective, value, source_type="inspect_tool")
        return InspectExecution(
            ChatMessageTool(content=value, tool_call_id=call.id, function=call.function), False
        )
