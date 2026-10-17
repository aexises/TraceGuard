"""One fail-closed control-plane/cache matcher with explicit decision precedence."""

import re

from traceguard.control.models import ActionRequest, Decision, PolicyVersion, RuleMatch
from traceguard.policy.authorization import same_value
from traceguard.policy.network import target_within_scope

_INSTRUCTIONS = re.compile(
    r"(?i)\b(?:ignore (?:previous|all) instructions|system prompt|reveal secrets|exfiltrate)\b"
)
_PRECEDENCE = {Decision.BLOCK: 3, Decision.ESCALATE: 2, Decision.REWRITE: 1, Decision.ALLOW: 0}


def matches(match: RuleMatch, action: ActionRequest) -> bool:
    if match.kind is not None and match.kind != action.kind:
        return False
    if match.operation is not None and match.operation != action.operation:
        return False
    if match.target_prefix is not None:
        if action.kind.value == "http":
            if not target_within_scope(match.target_prefix, action.target or ""):
                return False
        elif not (action.target or "").startswith(match.target_prefix):
            return False
    if any(
        not same_value(action.arguments.get(key), value)
        for key, value in match.argument_equals.items()
    ):
        return False
    instructions = any(
        item.contains_instructions or bool(_INSTRUCTIONS.search(item.content))
        for item in action.evidence
    )
    return (
        match.contains_untrusted_instructions is None
        or match.contains_untrusted_instructions == instructions
    )


def select_rule(policy: PolicyVersion, action: ActionRequest):
    candidates = [rule for rule in policy.draft.rules if matches(rule.match, action)]
    return max(
        candidates,
        key=lambda rule: (_PRECEDENCE[rule.decision], rule.priority, rule.rule_id),
        default=None,
    )
