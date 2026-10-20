"""Bounded JSON admission, shared by HTTP ingress and public action contracts."""

from __future__ import annotations

import json
from typing import Any


def validate_json(
    value: Any, *, max_bytes: int = 65_536, max_nodes: int = 4096, max_depth: int = 16
) -> None:
    stack = [(value, 0)]
    nodes = 0
    while stack:
        item, depth = stack.pop()
        nodes += 1
        if nodes > max_nodes or depth > max_depth:
            raise ValueError("JSON depth or node budget exceeded")
        if isinstance(item, dict):
            if len(item) > max_nodes or not all(isinstance(key, str) for key in item):
                raise ValueError("invalid JSON object")
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            if len(item) > max_nodes:
                raise ValueError("JSON collection budget exceeded")
            stack.extend((child, depth + 1) for child in item)
    try:
        encoded = json.dumps(value, allow_nan=False, separators=(",", ":")).encode()
    except (ValueError, TypeError, RecursionError) as exc:
        raise ValueError("invalid bounded JSON value") from exc
    if len(encoded) > max_bytes:
        raise ValueError("JSON byte budget exceeded")
