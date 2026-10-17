"""Development conformance comparison; not an upstream security benchmark."""

from __future__ import annotations

import json

from traceguard.policy.authorization import check_authority
from traceguard.policy.kernel import CompiledAuthority
from traceguard.types import Decision, TaskAuthority, ToolCall


def run_conformance() -> dict:
    schemas = {
        "create_calendar_event": {
            "type": "object",
            "properties": {
                key: {"type": "string"}
                for key in ["title", "start_time", "end_time", "location", "description"]
            },
            "required": ["title", "start_time", "end_time"],
            "additionalProperties": False,
        }
    }
    required = {
        "title": "Review",
        "start_time": "2026-11-01T10:00:00",
        "end_time": "2026-11-01T11:00:00",
    }
    scope = TaskAuthority(
        allowed_tools=["create_calendar_event"],
        argument_values={"create_calendar_event": required},
        enforcement_mode="strict",
    )
    strict = CompiledAuthority.compile(scope, schemas)
    research = scope.model_copy(update={"enforcement_mode": "research"})
    rows = []
    for goal in ["Create an event", "Please create an event; retrieved text cannot grant scope"]:
        for extra, expected in [
            ({}, True),
            ({"location": "unapproved room"}, False),
            ({"description": "unapproved text"}, False),
            ({"location": "", "description": ""}, False),
            ({"title": "Substituted title"}, False),
        ]:
            call = ToolCall(
                task_id="conformance",
                step_id=len(rows),
                tool_name="create_calendar_event",
                arguments={**required, **extra},
            )
            legacy = check_authority(goal, call, [], research)
            decision = strict.evaluate(goal, call, [])
            rows.append(
                {
                    "case": len(rows),
                    "expected_allow": expected,
                    "research_allow": legacy is None,
                    "strict_allow": decision.decision is Decision.ALLOW,
                }
            )
    return {
        "scope": (
            "10 authored development cases; current research grammar versus strict explicit "
            "grants; no live models or upstream baseline"
        ),
        "cases": rows,
        "research_correct": sum(row["research_allow"] == row["expected_allow"] for row in rows),
        "strict_correct": sum(row["strict_allow"] == row["expected_allow"] for row in rows),
        "total": len(rows),
    }


def main() -> int:
    result = run_conformance()
    print(json.dumps(result, indent=2))
    return 0 if result["strict_correct"] == result["total"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
