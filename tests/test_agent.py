import json

from traceguard.agent import validate_task_agent_response_json


def test_task_agent_response_ignores_gateway_schema_extra_key():
    payload = {
        "kind": "tool_call",
        "tool_name": "calculator",
        "arguments": {"expression": "12 * 7"},
        "consumed_observation_ids": [],
        "requested_resources": [],
        "answer": None,
        "additionalProperties": False,
    }

    response = validate_task_agent_response_json(json.dumps(payload))

    assert response.kind == "tool_call"
    assert response.tool_name == "calculator"
    assert response.arguments == {"expression": "12 * 7"}
