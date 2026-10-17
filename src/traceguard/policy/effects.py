"""Reviewed security effect extraction; tool schemas alone do not describe authority."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path
from typing import Any

from traceguard.types import ToolCall


@lru_cache(maxsize=1)
def security_descriptors() -> dict[str, Any]:
    return json.loads((Path(__file__).parents[1] / "data/policy/security_effects.json").read_text())


@dataclass(frozen=True)
class EmailEffects:
    recipients: tuple[tuple[str, str], ...]
    referenced_objects: tuple[str, ...]


def email_effects(call: ToolCall) -> EmailEffects:
    descriptor = security_descriptors()["email"]
    recipients = []
    for field in descriptor["recipient_fields"]:
        values = call.arguments.get(field)
        if values is None:
            continue
        values = values if isinstance(values, list) else [values]
        if not all(isinstance(value, str) and value.strip() for value in values):
            raise ValueError(f"invalid email destination field: {field}")
        recipients.extend((field, value.casefold()) for value in values)
    objects = tuple(field for field in descriptor["object_fields"] if call.arguments.get(field))
    return EmailEffects(tuple(recipients), objects)


def scoped_fields(call: ToolCall) -> tuple[str, ...]:
    """Consequential object selectors and outbound requests need separate authority."""
    descriptors = security_descriptors()
    fields = set(descriptors["object_fields"].get(call.tool_name, []))
    fields.update(descriptors["network_fields"].get(call.tool_name, []))
    # New ID selectors cannot silently evade a descriptor for an existing operation.
    fields.update(field for field in call.arguments if field.endswith(("_id", "_ids")))
    return tuple(sorted(field for field in fields if field in call.arguments))
