"""Fail-closed policy, review, audit, and signed-cache services.

The in-memory repository is deliberately small and deterministic for local development.
Production deployments replace it with transactional PostgreSQL, object storage, and KMS
adapters behind the same service boundary.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import wraps
from threading import RLock
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
    SignedPolicyBundle,
)
from traceguard.control.signing import Signer, canonical
from traceguard.policy.matching import matches, select_rule
from traceguard.supervisor.redaction import redact_value

_canonical = canonical


def redact(value: Any) -> Any:
    return redact_value(value)


class AuthorizationError(PermissionError):
    pass


class IdempotencyConflict(ValueError):
    """An idempotency key cannot authorize changed work or stale policy."""


def action_digest(action: ActionRequest) -> str:
    payload = action.model_dump(
        mode="json", exclude={"action_id", "requested_at", "idempotency_key"}
    )
    return hashlib.sha256(_canonical(payload)).hexdigest()


@dataclass(frozen=True)
class DecisionReceipt:
    digest: str
    epoch: int
    expires_at: datetime
    result: DecisionResponse


def synchronized(method):
    @wraps(method)
    def locked(self, *args, **kwargs):
        with self._lock:
            return method(self, *args, **kwargs)

    return locked


class ControlPlane:
    """A multi-tenant, fail-closed safety regulator service."""

    def __init__(self, signing_key: bytes, *, key_id: str = "development-ed25519-v1") -> None:
        if len(signing_key) < 32:
            raise ValueError("signing_key must be at least 32 bytes")
        self._policy_signer = Signer(signing_key, "traceguard-policy-v1")
        self._audit_signer = Signer(signing_key, "traceguard-audit-v2")
        self._key_id = key_id
        self._policies: dict[str, list[PolicyVersion]] = {}
        self._audits: dict[str, list[AuditEvent]] = {}
        self._audit_heads: dict[str, tuple[int, str]] = {}
        self._reviews: dict[str, Review] = {}
        self._idempotent: dict[tuple[str, str, str, str], DecisionReceipt] = {}
        self._epochs: dict[str, int] = {}
        self._lock = RLock()

    @property
    def policy_public_key(self) -> bytes:
        return self._policy_signer.public_key

    @property
    def audit_public_key(self) -> bytes:
        return self._audit_signer.public_key

    @property
    def key_id(self) -> str:
        return self._key_id

    @synchronized
    def create_draft(self, tenant_id: str, actor: Actor, draft: PolicyDraft) -> PolicyVersion:
        self._require(actor, Role.ADMIN, tenant_id)
        versions = self._policies.setdefault(tenant_id, [])
        policy = PolicyVersion(
            tenant_id=tenant_id,
            version=len(versions) + 1,
            draft=draft.model_copy(deep=True),
            created_by=actor.subject,
        )
        versions.append(policy)
        self._append_audit(
            tenant_id, "policy.drafted", actor.subject, {"policy_id": policy.policy_id}
        )
        return policy.model_copy(deep=True)

    @synchronized
    def submit_policy(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.ADMIN, tenant_id)
        policy = self._policy(tenant_id, policy_id)
        if policy.created_by != actor.subject:
            raise AuthorizationError("only the policy author may submit this draft")
        if policy.status is not PolicyStatus.DRAFT:
            raise ValueError("only drafts may be submitted")
        policy.status = PolicyStatus.PENDING_APPROVAL
        self._append_audit(tenant_id, "policy.submitted", actor.subject, {"policy_id": policy_id})
        return policy.model_copy(deep=True)

    @synchronized
    def approve_policy(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.APPROVER, tenant_id)
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
        self._epochs[tenant_id] = self._epochs.get(tenant_id, 0) + 1
        self._append_audit(tenant_id, "policy.activated", actor.subject, {"policy_id": policy_id})
        return policy.model_copy(deep=True)

    @synchronized
    def rollback(self, tenant_id: str, actor: Actor, policy_id: str) -> PolicyVersion:
        self._require(actor, Role.APPROVER, tenant_id)
        target = self._policy(tenant_id, policy_id)
        if target.status is not PolicyStatus.ROLLED_BACK:
            raise ValueError("only a historical policy can be restored")
        for candidate in self._policies[tenant_id]:
            if candidate.status is PolicyStatus.ACTIVE:
                candidate.status = PolicyStatus.ROLLED_BACK
        target.status = PolicyStatus.ACTIVE
        target.approved_by = actor.subject
        target.activated_at = datetime.now(UTC)
        self._epochs[tenant_id] = self._epochs.get(tenant_id, 0) + 1
        self._append_audit(tenant_id, "policy.rolled_back", actor.subject, {"policy_id": policy_id})
        return target.model_copy(deep=True)

    @synchronized
    def evaluate(self, actor: Actor, action: ActionRequest) -> DecisionResponse:
        self._require(actor, Role.AGENT, action.tenant_id)
        if (
            actor.allowed_operations is not None
            and action.operation not in actor.allowed_operations
        ):
            raise AuthorizationError("operation is outside the service credential scope")
        if actor.service_key_id is None:
            raise AuthorizationError("agent actions require a scoped service credential")
        key = (action.tenant_id, actor.subject, actor.service_key_id, action.idempotency_key)
        digest = action_digest(action)
        epoch = self._epochs.get(action.tenant_id, 0)
        if cached := self._idempotent.get(key):
            if cached.digest != digest:
                raise IdempotencyConflict("idempotency key is bound to a different action")
            if cached.epoch != epoch or cached.expires_at <= datetime.now(UTC):
                raise IdempotencyConflict("decision receipt is stale; use a new idempotency key")
            return cached.result.model_copy(deep=True)
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
                tenant_id=action.tenant_id,
                action_id=action.action_id,
                audit_id=audit.audit_id,
                action_digest=digest,
                agent_subject=actor.subject,
                service_key_id=actor.service_key_id,
                task_id=action.task_id,
                policy_epoch=epoch,
            )
            self._reviews[review.review_id] = review
            result.review_id = review.review_id
            self._append_audit(
                action.tenant_id, "review.created", actor.subject, review.model_dump(mode="json")
            )
        self._idempotent[key] = DecisionReceipt(
            digest, epoch, datetime.now(UTC) + timedelta(minutes=5), result.model_copy(deep=True)
        )
        return result

    @synchronized
    def resolve_review(
        self,
        tenant_id: str,
        actor: Actor,
        review_id: str,
        resolution: ReviewResolution,
        reason: str,
    ) -> Review:
        self._require(actor, Role.REVIEWER, tenant_id)
        review = self._reviews.get(review_id)
        if review is None or review.tenant_id != tenant_id:
            raise KeyError("review not found")
        if review.status != "pending":
            raise ValueError("review has already been resolved")
        if review.policy_epoch != self._epochs.get(tenant_id):
            raise ValueError("review policy is stale")
        if review.agent_subject == actor.subject:
            raise AuthorizationError("action proposer cannot approve their own action")
        if review.expires_at < datetime.now(UTC):
            review.status = "expired"
            raise ValueError("review has expired")
        review.status = "resolved"
        review.resolution = resolution
        review.resolved_by = actor.subject
        review.reason = reason
        self._append_audit(
            tenant_id, "review.resolved", actor.subject, review.model_dump(mode="json")
        )
        return review.model_copy(deep=True)

    def active_policy(self, tenant_id: str) -> PolicyVersion | None:
        with self._lock:
            policy = next(
                (
                    item
                    for item in reversed(self._policies.get(tenant_id, []))
                    if item.status is PolicyStatus.ACTIVE
                ),
                None,
            )
            return policy.model_copy(deep=True) if policy is not None else None

    @synchronized
    def signed_bundle(
        self, tenant_id: str, actor: Actor, ttl: timedelta = timedelta(minutes=5)
    ) -> SignedPolicyBundle:
        self._require(actor, Role.AGENT, tenant_id)
        if actor.service_key_id is None:
            raise AuthorizationError("bundle requires a scoped service credential")
        if not timedelta(0) < ttl <= timedelta(minutes=5):
            raise ValueError("offline bundle TTL must be within five minutes")
        policy = self.active_policy(tenant_id)
        if policy is None:
            raise ValueError("no active policy")
        if actor.allowed_operations is not None:
            permitted = [
                rule
                for rule in policy.draft.rules
                if rule.decision is not Decision.ALLOW
                or rule.match.operation in actor.allowed_operations
            ]
            if not permitted:
                raise ValueError("no policy within credential operation scope")
            policy.draft.rules = permitted
        issued_at = datetime.now(UTC)
        expires_at = issued_at + ttl
        bundle = SignedPolicyBundle(
            tenant_id=tenant_id,
            policy=policy,
            issued_at=issued_at,
            expires_at=expires_at,
            key_id=self._key_id,
            signature="",
            audience=actor.subject,
            service_key_id=actor.service_key_id,
            policy_epoch=self._epochs[tenant_id],
        )
        unsigned = bundle.model_dump(mode="json", exclude={"signature"})
        bundle.signature = self._policy_signer.sign(unsigned)
        return bundle

    @synchronized
    def export_audit(self, tenant_id: str, actor: Actor) -> dict[str, Any]:
        self._require(actor, Role.AUDITOR, tenant_id)
        if not self.verify_audit_chain(tenant_id):
            raise ValueError("audit integrity check failed")
        events = self._audits.get(tenant_id, [])
        payload = {
            "tenant_id": tenant_id,
            "events": [event.model_dump(mode="json") for event in events],
            "count": len(events),
            "head_hash": events[-1].event_hash if events else None,
            "schema_version": "audit-v2",
        }
        return {
            **payload,
            "signature": self._audit_signer.sign(payload),
            "key_id": self._key_id + ":audit-v2",
            "algorithm": "Ed25519",
        }

    def verify_audit_chain(self, tenant_id: str) -> bool:
        with self._lock:
            previous = None
            events = self._audits.get(tenant_id, [])
            for index, event in enumerate(events, 1):
                if event.previous_hash != previous or event.sequence != index:
                    return False
                body = event.model_dump(mode="json", exclude={"event_hash"})
                if event.event_hash != hashlib.sha256(_canonical(body)).hexdigest():
                    return False
                previous = event.event_hash
            return (
                self._audit_heads.get(tenant_id) == (len(events), previous)
                if events
                else tenant_id not in self._audit_heads
            )

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
            action_digest=action_digest(action),
            policy_id=policy.policy_id if policy else None,
            policy_version=policy.version if policy else None,
            audit_id="pending",
            rewritten_arguments=rewrite,
        )

    _matches = staticmethod(matches)

    def _matching_rule(self, policy: PolicyVersion, action: ActionRequest):
        return select_rule(policy, action)

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
        event = AuditEvent(
            tenant_id=tenant_id,
            event_type=event_type,
            actor=actor,
            payload=redact(payload),
            previous_hash=previous,
            sequence=len(events) + 1,
            event_hash="",
        )
        event.event_hash = hashlib.sha256(
            _canonical(event.model_dump(mode="json", exclude={"event_hash"}))
        ).hexdigest()
        events.append(event)
        self._audit_heads[tenant_id] = (len(events), event.event_hash)
        return event

    @staticmethod
    def _require(actor: Actor, role: Role, tenant_id: str) -> None:
        if tenant_id not in actor.tenant_ids:
            raise AuthorizationError("principal is not authorized for this tenant")
        if role not in actor.roles:
            raise AuthorizationError(f"missing required role: {role.value}")
