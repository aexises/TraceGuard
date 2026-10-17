"""Strict grant compilation and field-complete authority, independent of English verbs."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from traceguard.policy.effects import security_descriptors
from traceguard.types import Observation, SupervisorOutput, TaskAuthority, ToolCall


def validate_authority(
    authority: TaskAuthority, schemas: dict[str, dict[str, Any]] | None = None
) -> None:
    if authority.enforcement_mode != "strict":
        raise ValueError("strict authority must explicitly select strict enforcement")
    if authority.allowed_tools is None:
        raise ValueError("strict authority requires an explicit tool allowlist")
    allowed = set(authority.allowed_tools)
    configured = (
        set(authority.argument_values)
        | set(authority.resource_values)
        | set(authority.delegated_fields)
        | set(authority.generated_fields)
    )
    if configured - allowed:
        raise ValueError("constraints refer to tools outside the grant")
    if schemas is not None and allowed - set(schemas):
        raise ValueError("grant refers to unavailable tool schemas")
    if set(authority.repeatable_tools) - allowed:
        raise ValueError("repeat exceptions refer to tools outside the grant")
    for tool, fields in authority.generated_fields.items():
        permitted = security_descriptors()["generatable_fields"].get(tool, [])
        if set(fields) - set(permitted):
            raise ValueError(
                "generated fields cannot carry recipients, objects, commands or budgets"
            )
    for tool in allowed:
        groups = [
            set(mapping.get(tool, {}))
            for mapping in (
                authority.argument_values,
                authority.resource_values,
                authority.delegated_fields,
                authority.generated_fields,
            )
        ]
        if any(groups[i] & groups[j] for i in range(len(groups)) for j in range(i)):
            raise ValueError("a field cannot have conflicting authority definitions")
        properties = (schemas or {}).get(tool, {}).get("properties")
        fields = set().union(*groups) - {"requested_resources"}
        if properties is not None and fields - set(properties):
            raise ValueError("grant names fields absent from the tool schema")


def ungranted_fields(call: ToolCall, authority: TaskAuthority, effect: str) -> set[str]:
    explicit = (
        set(authority.argument_values.get(call.tool_name, {}))
        | set(authority.resource_values.get(call.tool_name, {}))
        | set(authority.delegated_fields.get(call.tool_name, {}))
        | set(authority.generated_fields.get(call.tool_name, []))
    )
    if authority.max_amount is not None and call.tool_name in {
        "send_money",
        "schedule_transaction",
    }:
        explicit.add("amount")
    fields = set(call.arguments) if effect in {"mutate", "command"} else set()
    if call.requested_resources:
        fields.add("requested_resources")
    # Only reviewed email optionals have known no-effect empty semantics.
    fields = {
        field
        for field in fields
        if not (
            call.tool_name == "send_email"
            and field in {"cc", "bcc", "attachments"}
            and call.arguments.get(field) in (None, [], {})
        )
    }
    return fields - explicit


@dataclass(frozen=True)
class CompiledAuthority:
    scope_json: str
    schemas_json: str
    digest: str

    @classmethod
    def compile(
        cls, authority: TaskAuthority, schemas: dict[str, dict[str, Any]]
    ) -> CompiledAuthority:
        validate_authority(authority, schemas)
        scope = json.dumps(
            authority.model_dump(mode="json"),
            sort_keys=True,
            allow_nan=False,
            separators=(",", ":"),
        )
        schema = json.dumps(schemas, sort_keys=True, allow_nan=False)
        descriptors = json.dumps(security_descriptors(), sort_keys=True)
        return cls(
            scope, schema, hashlib.sha256((scope + schema + descriptors).encode()).hexdigest()
        )

    def evaluate(
        self,
        goal: str,
        call: ToolCall,
        observations: list[Observation],
        previous_calls: Sequence[ToolCall] = (),
    ) -> SupervisorOutput:
        from traceguard.policy.authorization import check_authority, output
        from traceguard.supervisor.contracts import (
            SupervisorSchemaError,
            _validate_arguments_against_json_schema,
        )
        from traceguard.types import Decision, RiskLevel

        schemas = json.loads(self.schemas_json)
        if call.tool_name not in schemas:
            return output(Decision.ESCALATE, "strict-unknown-schema", "Tool schema is unavailable.")
        try:
            _validate_arguments_against_json_schema(call.arguments, schemas[call.tool_name])
        except SupervisorSchemaError:
            return output(Decision.ESCALATE, "strict-invalid-schema", "Arguments fail tool schema.")
        denied = check_authority(
            goal,
            call,
            observations,
            TaskAuthority.model_validate_json(self.scope_json),
            list(previous_calls),
        )
        return denied or output(
            Decision.ALLOW,
            "strict-compiled-grant",
            "Explicit field-complete grant permits this call.",
            RiskLevel.LOW,
        )
