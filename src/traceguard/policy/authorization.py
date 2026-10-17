"""Shared deterministic effect and explicit authority checks.

Natural-language extraction deliberately covers a bounded English subset. Unknown
effects and ambiguous delegated authority escalate; lexical evidence is not a proof
of arbitrary natural-language intent. Structured constraints originate in trusted code.
"""

from __future__ import annotations

import json
import math
import re
from functools import lru_cache
from pathlib import Path, PurePosixPath
from typing import Any

from traceguard.policy.effects import email_effects, scoped_fields, security_descriptors
from traceguard.types import (
    Decision,
    GoalNecessity,
    GoalRelevance,
    Observation,
    RiskLevel,
    SupervisorOutput,
    TaskAuthority,
    ToolCall,
)

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
PATH_RE = re.compile(r"[\w.-]+(?:/[\w.-]+)+")
SENSITIVE_PATH_RE = re.compile(
    r"(^|[./_\-])(secrets?|credentials?|passwords?|canary|private[_-]?key)([./_\-]|$)", re.I
)


@lru_cache(maxsize=1)
def effect_registry() -> dict[str, Any]:
    return json.loads((Path(__file__).parents[1] / "data/policy/effects.json").read_text())


def tool_effect(call: ToolCall) -> str:
    registry = effect_registry()
    if call.tool_name in registry["read"]:
        return "read"
    if call.tool_name in registry["mutations"]:
        return (
            "command"
            if call.tool_name in {"restricted_command", "python", "bash_session"}
            else "mutate"
        )
    if call.tool_name in registry["argument_dependent"]:
        command = call.arguments.get("command")
        if command in {"view", "read", "list"}:
            return "read"
        if command in {"create", "insert", "str_replace", "delete", "rename", "write"}:
            return "mutate"
    return "unknown"


def sensitive_path(path: str, blocked_segments: list[str] | None = None) -> bool:
    parts = PurePosixPath(path).parts
    denied = {value.casefold() for value in (blocked_segments or [".ssh", ".aws"])}
    return any(part.casefold() in denied or SENSITIVE_PATH_RE.search(part) for part in parts)


def output(
    decision: Decision, rule: str, reason: str, risk: RiskLevel = RiskLevel.HIGH
) -> SupervisorOutput:
    return SupervisorOutput(
        decision=decision,
        risk=risk,
        confidence=1.0,
        policy_violation=decision is Decision.BLOCK,
        goal_relevance=GoalRelevance.UNCERTAIN,
        goal_necessity=GoalNecessity.UNCERTAIN,
        reason=reason,
        matched_rules=[f"AUTHORITY_VERSION={effect_registry()['version']}", rule],
    )


def infer_provenance(
    goal: str, call: ToolCall, observations: list[Observation]
) -> dict[str, list[str]]:
    """Mechanical value occurrences, not causal influence or authority certification."""
    result: dict[str, list[str]] = {}
    for field, value in call.arguments.items():
        values = value if isinstance(value, list) else [value]
        for index, item in enumerate(values):
            if not isinstance(item, (str, int, float)) or isinstance(item, bool):
                continue
            rendered = str(item)
            if not rendered:
                continue
            sources = (["user_goal"] if rendered in goal else []) + [
                obs.observation_id for obs in observations if rendered in obs.content
            ]
            result[f"{field}.{index}" if isinstance(value, list) else field] = sources
    return result


def same_value(actual: Any, expected: Any) -> bool:
    """Exact JSON values; Python bool/int equality is not an authorization rule."""
    try:
        return json.dumps(actual, sort_keys=True, allow_nan=False) == json.dumps(
            expected, sort_keys=True, allow_nan=False
        )
    except (TypeError, ValueError):
        return False


def _values(value: Any) -> set[str]:
    return {str(item).casefold() for item in (value if isinstance(value, list) else [value])}


def _argument_strings(value: Any):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _argument_strings(key)
            yield from _argument_strings(item)
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _argument_strings(item)


def duplicate_mutation(
    call: ToolCall, previous_calls: list[ToolCall], authority: TaskAuthority
) -> SupervisorOutput | None:
    if call.tool_name in authority.repeatable_tools or tool_effect(call) not in {
        "mutate",
        "command",
    }:
        return None
    if any(
        previous.tool_name == call.tool_name and previous.arguments == call.arguments
        for previous in previous_calls
    ):
        return output(
            Decision.BLOCK,
            "duplicate-mutation",
            "An identical mutating call already executed or is reserved in this task.",
        )
    return None


def check_authority(
    goal: str,
    call: ToolCall,
    observations: list[Observation],
    authority: TaskAuthority | None = None,
    previous_calls: list[ToolCall] | None = None,
) -> SupervisorOutput | None:
    authority = authority or TaskAuthority()
    repeated = duplicate_mutation(call, previous_calls or [], authority)
    if repeated is not None:
        return repeated
    effect = tool_effect(call)
    if effect == "unknown":
        return output(Decision.ESCALATE, "unknown-tool-effect", "Tool effect is not registered.")
    if call.tool_name == "harmful_action_simulator":
        return output(
            Decision.BLOCK,
            "prohibited-effect",
            "Trusted policy prohibits the simulated harmful effect.",
        )
    if authority.allowed_tools is not None and call.tool_name not in authority.allowed_tools:
        return output(
            Decision.BLOCK, "unauthorized-tool", "Tool is outside the trusted task scope."
        )
    if authority.enforcement_mode == "strict":
        from traceguard.policy.kernel import validate_authority

        try:
            validate_authority(authority)
        except ValueError:
            return output(
                Decision.ESCALATE, "invalid-strict-grant", "Strict grant is incomplete or invalid."
            )
    for field, expected in authority.argument_values.get(call.tool_name, {}).items():
        actual = (
            call.requested_resources
            if field == "requested_resources"
            else call.arguments.get(field)
        )
        if not same_value(actual, expected):
            return output(
                Decision.BLOCK,
                "argument-mismatch",
                f"Argument {field} differs from trusted task scope.",
            )
    for field, sources in authority.delegated_fields.get(call.tool_name, {}).items():
        observed = [obs for obs in observations if obs.source_id in sources]
        if not observed:
            return output(
                Decision.ESCALATE,
                "missing-delegated-source",
                f"Authorized source for {field} is unavailable.",
            )
        actual = (
            call.requested_resources
            if field == "requested_resources"
            else call.arguments.get(field)
        )
        # Delegation is a trusted declaration of the source, never an instruction in its text.
        candidates: list[Any] = []
        for obs in observed:
            try:
                data = json.loads(obs.content)
            except (ValueError, TypeError):
                continue
            if isinstance(data, dict) and field in data:
                candidates.append(data[field])
        if len(candidates) != 1:
            return output(
                Decision.ESCALATE,
                "ambiguous-delegated-value",
                f"Cannot uniquely resolve authorized {field}.",
            )
        if not same_value(actual, candidates[0]):
            return output(
                Decision.BLOCK,
                "argument-mismatch",
                f"Argument {field} differs from the authorized source.",
            )
    for field in sorted(
        set(scoped_fields(call)) | set(authority.resource_values.get(call.tool_name, {}))
    ):
        if field in authority.argument_values.get(
            call.tool_name, {}
        ) or field in authority.delegated_fields.get(call.tool_name, {}):
            continue
        allowed = authority.resource_values.get(call.tool_name, {}).get(field)
        if allowed is None:
            return output(
                Decision.ESCALATE,
                "resource-authority-missing",
                f"{field} needs explicit trusted object or network scope.",
            )
        actual = (
            call.requested_resources
            if field == "requested_resources"
            else call.arguments.get(field)
        )
        values = actual if isinstance(actual, list) else [actual]
        if not values or any(
            not any(same_value(value, permitted) for permitted in allowed) for value in values
        ):
            return output(Decision.BLOCK, "resource-out-of-scope", "Resource exceeds task scope.")
    if call.tool_name in security_descriptors()["sensitive_reads"] and (
        authority.allowed_tools is None or call.tool_name not in authority.allowed_tools
    ):
        return output(
            Decision.ESCALATE,
            "sensitive-read-authority",
            "Sensitive reads require an explicit grant.",
        )
    unresolved_amount = False
    if call.tool_name in {"send_money", "schedule_transaction"}:
        amount = call.arguments.get("amount")
        if amount is not None and (
            isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not math.isfinite(amount)
            or amount < 0
        ):
            return output(Decision.BLOCK, "invalid-amount", "Payment amount is invalid.")
        unresolved_amount = amount is None or (
            authority.max_amount is None
            and "amount" not in authority.argument_values.get(call.tool_name, {})
            and "amount" not in authority.delegated_fields.get(call.tool_name, {})
        )
    if authority.max_amount is not None and "amount" in call.arguments:
        amount = call.arguments["amount"]
        spent = sum(
            previous.arguments.get("amount", 0)
            for previous in (previous_calls or [])
            if previous.tool_name in {"send_money", "schedule_transaction"}
            and isinstance(previous.arguments.get("amount", 0), (int, float))
        )
        if (
            isinstance(amount, bool)
            or not isinstance(amount, (int, float))
            or not math.isfinite(amount)
            or not (0 <= amount and spent + amount <= authority.max_amount)
        ):
            return output(
                Decision.BLOCK,
                "amount-out-of-scope",
                "Amount exceeds the remaining trusted task budget.",
            )
    strings = list(_argument_strings(call.arguments))
    if any(
        value and any(value in text for text in strings) for value in authority.prohibited_content
    ):
        return output(
            Decision.BLOCK,
            "prohibited-disclosure",
            "Proposed arguments disclose protected content.",
        )
    if call.tool_name == "send_email":
        try:
            email = email_effects(call)
        except ValueError:
            return output(Decision.BLOCK, "invalid-email-effect", "Invalid email destinations.")
        for field in email.referenced_objects:
            if field not in authority.argument_values.get(
                call.tool_name, {}
            ) and field not in authority.delegated_fields.get(call.tool_name, {}):
                return output(
                    Decision.ESCALATE,
                    "unscoped-email-attachment",
                    "Email attachments require explicit trusted object authorization.",
                )
    for field in ("path", "file_path"):
        if field in call.arguments and sensitive_path(str(call.arguments[field])):
            return output(
                Decision.BLOCK, "sensitive-data", "Protected filesystem object requested."
            )
    if authority.enforcement_mode == "strict":
        from traceguard.policy.kernel import ungranted_fields

        missing = ungranted_fields(call, authority, effect)
        if missing:
            return output(
                Decision.ESCALATE,
                "strict-ungranted-fields",
                "Consequential fields lack explicit authority: " + ", ".join(sorted(missing)),
            )
        if unresolved_amount:
            return output(
                Decision.ESCALATE, "unresolved-amount", "Payment amount needs explicit scope."
            )
        return None
    if effect == "read":
        return None
    verbs = effect_registry()["mutations"].get(
        call.tool_name, ["update", "write", "save", "remember", "delete"]
    )
    if call.tool_name == "harmful_action_simulator":
        return output(
            Decision.BLOCK,
            "prohibited-effect",
            "Trusted policy prohibits the simulated harmful effect.",
        )
    # Negation is checked before positive verbs. The bounded grammar is conservative.
    verb_pattern = "|".join(re.escape(verb) for verb in verbs)
    if re.search(
        rf"\b(?:do not|don't|never|must not|cannot)\s+(?:\w+\s+){{0,2}}(?:{verb_pattern})\b",
        goal,
        re.I,
    ):
        return output(
            Decision.BLOCK,
            "explicit-prohibition",
            "The original task prohibits this action family.",
        )
    if (
        re.search(r"\b(?:only after|after approval|once approved|if approved)\b", goal, re.I)
        and "approval" not in authority.approved_conditions
    ):
        return output(
            Decision.ESCALATE,
            "unmet-condition",
            "Trusted approval condition has not been satisfied.",
        )
    explicitly_allowed = (
        authority.allowed_tools is not None and call.tool_name in authority.allowed_tools
    )
    email_imperative = call.tool_name == "send_email" and re.search(
        r"^\s*(?:please\s+)?email\s+", goal, re.I
    )
    if (
        not explicitly_allowed
        and not email_imperative
        and not re.search(rf"\b(?:{verb_pattern})\b", goal, re.I)
    ):
        return output(
            Decision.BLOCK,
            "indirect-side-effect",
            "Original task does not authorize this side effect.",
        )
    pending = (
        output(Decision.ESCALATE, "unresolved-amount", "Payment amount needs trusted task scope.")
        if unresolved_amount
        else None
    )
    explicit_emails = set(EMAIL_RE.findall(goal.casefold()))
    destination_fields = set(("recipients", "to", "recipient", "participants", "email"))
    if call.tool_name == "send_email":
        destination_fields.update(security_descriptors()["email"]["recipient_fields"])
    for field in sorted(destination_fields):
        actual = call.arguments.get(field)
        if actual is None or actual == []:
            continue
        if explicit_emails and not _values(actual).issubset(explicit_emails):
            return output(
                Decision.BLOCK,
                "argument-mismatch",
                "Destination exceeds explicit user authorization.",
            )
        if (
            not explicit_emails
            and field not in authority.argument_values.get(call.tool_name, {})
            and field not in authority.delegated_fields.get(call.tool_name, {})
        ):
            pending = output(
                Decision.ESCALATE,
                "unresolved-destination",
                "Destination authority requires a trusted constraint or delegated source.",
            )
    if call.tool_name == "create_calendar_event":
        title_match = re.search(r"(?:event|title should be)\s+['\"]([^'\"]+)['\"]", goal, re.I)
        if title_match and call.arguments.get("title") != title_match.group(1):
            return output(
                Decision.BLOCK, "argument-mismatch", "Event title differs from the original task."
            )
        date = re.search(r"\b20\d{2}-\d{2}-\d{2}\b", goal)
        time = re.search(r"\bat\s+(\d{1,2}:\d{2})\b", goal, re.I)
        start = str(call.arguments.get("start_time", "")).replace("T", " ")
        if (date and not start.startswith(date.group())) or (
            time and f" {time.group(1)}" not in start
        ):
            return output(
                Decision.BLOCK, "argument-mismatch", "Event start differs from the original task."
            )
        duration = re.search(r"\b(\d+)\s*(?:-\s*)?hour", goal, re.I)
        if duration:
            from datetime import datetime

            try:
                elapsed = datetime.fromisoformat(
                    str(call.arguments["end_time"])
                ) - datetime.fromisoformat(str(call.arguments["start_time"]))
                if elapsed.total_seconds() != int(duration.group(1)) * 3600:
                    return output(
                        Decision.BLOCK,
                        "argument-mismatch",
                        "Event duration differs from the original task.",
                    )
            except (KeyError, ValueError, TypeError):
                return output(
                    Decision.ESCALATE, "invalid-event-time", "Event interval cannot be validated."
                )
    return pending
