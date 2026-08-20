"""Fail-closed policy, review, audit, and signed-cache services.

The in-memory repository is deliberately small and deterministic for local development.
Production deployments replace it with transactional PostgreSQL, object storage, and KMS
adapters behind the same service boundary.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from datetime import UTC, datetime, timedelta
from typing import Any

from traceguard.control.models import (
    ActionRequest,
    Actor,
    AuditEvent,
    Decision,
    DecisionResponse,
    PolicyDraft,
    PolicyStatus,
    PolicyVersion,
    Review,
    ReviewResolution,
    Role,
    RuleMatch,
    SignedPolicyBundle,
)

_SECRET_PATTERN = re.compile(
    r"(?i)\b(?:api[_-]?key|password|secret|token)\s*[:=]\s*['\"]?[^\s,'\"]+"
)
_INSTRUCTION_PATTERN = re.compile(
    r"(?i)\b(?:ignore (?:previous|all) instructions|system prompt|reveal secrets|exfiltrate)\b"
)


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()


def redact(value: Any) -> Any:
    """Redact common credential assignments without retaining source payloads by default."""
    if isinstance(value, str):
        return _SECRET_PATTERN.sub("[REDACTED_SECRET]", value)
    if isinstance(value, list):
        return [redact(item) for item in value]
    if isinstance(value, dict):
        return {str(key): redact(item) for key, item in value.items()}
    return value


class AuthorizationError(PermissionError):
    pass


class ControlPlane:
    """A multi-tenant, fail-closed safety regulator service."""

    def __init__(self, signing_key: bytes, *, key_id: str = "development-hmac-v1") -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 bytes")
        self._signing_key = signing_key
        self._key_id = key_id
        self._policies: dict[str, list[PolicyVersion]] = {}
        self._audits: dict[str, list[AuditEvent]] = {}
        self._reviews: dict[str, Review] = {}
        self._idempotent: dict[tuple[str, str], DecisionResponse] = {}

    def create_draft(self, tenant_id: str, actor: Actor, draft: PolicyDraft) -> PolicyVersion:
        self._require(actor, Role.ADMIN)
        versions = self._policies.setdefault(tenant_id, [])
        policy = PolicyVersion(
            tenant_id=tenant_id,
            version=len(versions) + 1,
            draft=draft,
            created_by=actor.subject,
        )
        versions.append(policy)
        self._append_audit(
            tenant_id, "policy.drafted", actor.subject, {"policy_id": policy.policy_id}
        )
        return policy

    def submit_policy(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.ADMIN)
        policy = self._policy(tenant_id, policy_id)
        if policy.created_by != actor.subject:
            raise AuthorizationError("only the policy author may submit this draft")
        if policy.status is not PolicyStatus.DRAFT:
            raise ValueError("only drafts may be submitted")
        policy.status = PolicyStatus.PENDING_APPROVAL
        self._append_audit(tenant_id, "policy.submitted", actor.subject, {"policy_id": policy_id})
        return policy

    def approve_policy(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.APPROVER)
        policy = self._policy(tenant_id, policy_id)
        if policy.status is not PolicyStatus.PENDING_APPROVAL:
            raise ValueError("policy is not pending approval")
        if policy.created_by == actor.subject:
            raise AuthorizationError("policy author cannot approve their own change")
        for candidate in self._policies[tenant_id]:
            if candidate.status is PolicyStatus.ACTIVE:
                candidate.status = PolicyStatus.ROLLED_BACK
        policy.status = PolicyStatus.ACTIVE
        policy.approved_by = actor.subject
        policy.activated_at = datetime.now(UTC)
        self._append_audit(tenant_id, "policy.activated", actor.subject, {"policy_id": policy_id})
        return policy

    def rollback(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.APPROVER)
        target = self._policy(tenant_id, policy_id)
        if target.status is not PolicyStatus.ROLLED_BACK:
            raise ValueError("only a historical policy can be restored")
        for candidate in self._policies[tenant_id]:
            if candidate.status is PolicyStatus.ACTIVE:
                candidate.status = PolicyStatus.ROLLED_BACK
        target.status = PolicyStatus.ACTIVE
        target.approved_by = actor.subject
        target.activated_at = datetime.now(UTC)
        self._append_audit(tenant_id, "policy.rolled_back", actor.subject, {"policy_id": policy_id})
        return target

    def evaluate(self, actor: Actor, action: ActionRequest) -> DecisionResponse:
        self._require(actor, Role.AGENT)
        if actor.service_key_id is None:
            raise AuthorizationError("agent actions require a scoped service credential")
        key = (action.tenant_id, action.idempotency_key)
        if cached := self._idempotent.get(key):
            return cached
        policy = self.active_policy(action.tenant_id)
        if policy is None:
            result = self._decision(action, Decision.BLOCK, "no active policy", None)
        else:
            rule = self._matching_rule(policy, action)
            if rule is None:
                result = self._decision(
                    action, policy.draft.default_decision, "policy default", policy
                )
            else:
                result = self._decision(action, rule.decision, rule.reason, policy, rule.rewrite)
        audit = self._append_audit(
            action.tenant_id,
            "action.evaluated",
            actor.subject,
            {
                "action_id": action.action_id,
                "kind": action.kind.value,
                "operation": action.operation,
                "target": action.target,
                "arguments": redact(action.arguments),
                "provenance": action.provenance,
                "evidence": [redact(item.model_dump(mode="json")) for item in action.evidence],
                "decision": result.decision.value,
                "policy_id": result.policy_id,
            },
        )
        result.audit_id = audit.audit_id
        if result.decision is Decision.ESCALATE:
            review = Review(
                tenant_id=action.tenant_id, action_id=action.action_id, audit_id=audit.audit_id
            )
            self._reviews[review.review_id] = review
            result.review_id = review.review_id
            self._append_audit(
                action.tenant_id, "review.created", actor.subject, review.model_dump()
            )
        self._idempotent[key] = result
        return result

    def resolve_review(
        self,
        tenant_id: str,
        actor: Actor,
        review_id: str,
        resolution: ReviewResolution,
        reason: str,
    ) -> Review:
        self._require(actor, Role.REVIEWER)
        review = self._reviews.get(review_id)
        if review is None or review.tenant_id != tenant_id:
            raise KeyError("review not found")
        if review.status != "pending":
            raise ValueError("review has already been resolved")
        if review.expires_at < datetime.now(UTC):
            review.status = "expired"
            raise ValueError("review has expired")
        review.status = "resolved"
        review.resolution = resolution
        review.resolved_by = actor.subject
        review.reason = reason
        self._append_audit(tenant_id, "review.resolved", actor.subject, review.model_dump())
        return review

    def active_policy(self, tenant_id: str) -> PolicyVersion | None:
        return next(
            (
                item
                for item in reversed(self._policies.get(tenant_id, []))
                if item.status is PolicyStatus.ACTIVE
            ),
            None,
        )

    def signed_bundle(
        self, tenant_id: str, actor: Actor, ttl: timedelta = timedelta(minutes=15)
    ) -> SignedPolicyBundle:
        self._require(actor, Role.AGENT)
        policy = self.active_policy(tenant_id)
        if policy is None:
            raise ValueError("no active policy")
        issued_at = datetime.now(UTC)
        expires_at = issued_at + ttl
        bundle = SignedPolicyBundle(
            tenant_id=tenant_id,
            policy=policy,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self._key_id,
            signature="",
        )
        unsigned = bundle.model_dump(mode="json", exclude={"signature"})
        bundle.signature = hmac.new(
            self._signing_key, _canonical(unsigned), hashlib.sha256
        ).hexdigest()
        return bundle

    def export_audit(self, tenant_id: str, actor: Actor) -> dict[str, Any]:
        self._require(actor, Role.AUDITOR)
        events = self._audits.get(tenant_id, [])
        payload = {
            "tenant_id": tenant_id,
            "events": [event.model_dump(mode="json") for event in events],
        }
        return {
            **payload,
            "signature": hmac.new(
                self._signing_key, _canonical(payload), hashlib.sha256
            ).hexdigest(),
            "key_id": self._key_id,
        }

    def verify_audit_chain(self, tenant_id: str) -> bool:
        """Verify the tenant's append-only chain before export or external attestation."""
        previous: str | None = None
        for event in self._audits.get(tenant_id, []):
            body = {
                "tenant_id": event.tenant_id,
                "event_type": event.event_type,
                "actor": event.actor,
                "payload": event.payload,
                "previous_hash": previous,
            }
            if event.previous_hash != previous:
                return False
            if event.event_hash != hashlib.sha256(_canonical(body)).hexdigest():
                return False
            previous = event.event_hash
        return True

    def _decision(
        self,
        action: ActionRequest,
        decision: Decision,
        reason: str,
        policy: PolicyVersion | None,
        rewrite: dict[str, Any] | None = None,
    ) -> DecisionResponse:
        return DecisionResponse(
            decision=decision,
            reason=reason,
            policy_id=policy.policy_id if policy else None,
            policy_version=policy.version if policy else None,
            audit_id="pending",
            rewritten_arguments=rewrite,
        )

    @staticmethod
    def _matches(match: RuleMatch, action: ActionRequest) -> bool:
        if match.kind is not None and match.kind != action.kind:
            return False
        if match.operation is not None and match.operation != action.operation:
            return False
        if match.target_prefix is not None and not (action.target or "").startswith(
            match.target_prefix
        ):
            return False
        if any(action.arguments.get(key) != value for key, value in match.argument_equals.items()):
            return False
        has_instruction = any(
            item.untrusted
            and (item.contains_instructions or bool(_INSTRUCTION_PATTERN.search(item.content)))
            for item in action.evidence
        )
        return (
            match.contains_untrusted_instructions is None
            or match.contains_untrusted_instructions == has_instruction
        )

    def _matching_rule(self, policy: PolicyVersion, action: ActionRequest):
        for rule in sorted(policy.draft.rules, key=lambda item: item.priority, reverse=True):
            if self._matches(rule.match, action):
                return rule
        return None

    def _policy(self, tenant_id: str, policy_id: str) -> PolicyVersion:
        for policy in self._policies.get(tenant_id, []):
            if policy.policy_id == policy_id:
                return policy
        raise KeyError("policy not found")

    def _append_audit(
        self, tenant_id: str, event_type: str, actor: str, payload: dict[str, Any]
    ) -> AuditEvent:
        events = self._audits.setdefault(tenant_id, [])
        previous = events[-1].event_hash if events else None
        body = {
            "tenant_id": tenant_id,
            "event_type": event_type,
            "actor": actor,
            "payload": payload,
            "previous_hash": previous,
        }
        event = AuditEvent(**body, event_hash=hashlib.sha256(_canonical(body)).hexdigest())
        events.append(event)
        return event

    @staticmethod
    def _require(actor: Actor, role: Role) -> None:
        if role not in actor.roles:
            raise AuthorizationError(f"missing required role: {role.value}")
