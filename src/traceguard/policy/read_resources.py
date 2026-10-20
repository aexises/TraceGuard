"""Schema-bound mappings for inspected read adapters, supplied by trusted integration code."""

from copy import deepcopy
from hashlib import sha256

from traceguard.control.signing import canonical
from traceguard.policy.effects import security_descriptors
from traceguard.types import ToolCall

EXTENSION = "x-traceguard-read-adapter"


def bind_read_schema(schema: dict, *, adapter_id: str, tool_name: str) -> dict:
    """Bind a reviewed implementation mapping; never call using model-selected identity."""
    reviewed = security_descriptors()["read_adapters"].get(adapter_id, {}).get(tool_name)
    if reviewed is None:
        raise ValueError("unsupported read adapter mapping")
    bound = deepcopy(schema)
    bound.pop(EXTENSION, None)
    properties = bound.get("properties", {})
    if set(properties) - set(reviewed["fields"]):
        raise ValueError("read schema has unreviewed selectors or options")
    for field in reviewed["resources"]:
        if field not in properties:
            raise ValueError("read schema is missing a reviewed resource selector")
        default = reviewed.get("defaults", {}).get(field)
        if field not in (bound.get("required") or []) and (
            default is None or properties[field].get("default") != default
        ):
            raise ValueError("unreviewed implicit read resource")
        if properties[field].get("default") not in (None, default):
            raise ValueError("read resource default differs from reviewed adapter")
    bound[EXTENSION] = {"id": adapter_id, "schema_digest": sha256(canonical(bound)).hexdigest()}
    return bound


def scoped_read_call(call: ToolCall, schema: dict) -> ToolCall:
    binding = schema.get(EXTENSION, {})
    adapter_id = binding.get("id", "")
    verified = bind_read_schema(schema, adapter_id=adapter_id, tool_name=call.tool_name)
    if verified[EXTENSION] != binding:
        raise ValueError("read adapter binding does not match the approved schema")
    reviewed = security_descriptors()["read_adapters"][adapter_id][call.tool_name]
    normalized = call.model_copy(deep=True)
    for field in reviewed["resources"]:
        if field not in normalized.arguments and field in reviewed.get("defaults", {}):
            normalized.arguments[field] = reviewed["defaults"][field]
        if normalized.arguments.get(field) is None:
            raise ValueError("read resource is missing")
    normalized.requested_resources = sorted(
        set(normalized.requested_resources) | set(reviewed.get("implicit", []))
    )
    return normalized
