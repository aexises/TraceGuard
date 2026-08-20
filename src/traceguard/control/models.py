"""Versioned public contracts for the TraceGuard control plane."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, HttpUrl, model_validator

API_VERSION = "v1"


class PublicModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Role(StrEnum):
    ADMIN = "admin"
    APPROVER = "approver"
    REVIEWER = "reviewer"
    AUDITOR = "auditor"
    AGENT = "agent"


class ActionKind(StrEnum):
    MODEL_REQUEST = "model_request"
    MODEL_RESPONSE = "model_response"
    TOOL = "tool"
    MEMORY_READ = "memory_read"
    MEMORY_WRITE = "memory_write"
    FILESYSTEM = "filesystem"
    EXECUTOR = "executor"
    HTTP = "http"


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    REWRITE = "REWRITE"


class PolicyStatus(StrEnum):
    DRAFT = "draft"
    PENDING_APPROVAL = "pending_approval"
    ACTIVE = "active"
    ROLLED_BACK = "rolled_back"


class ReviewResolution(StrEnum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class Actor(PublicModel):
    subject: str = Field(min_length=1, max_length=256)
    roles: set[Role] = Field(min_length=1)
    service_key_id: str | None = None


class Evidence(PublicModel):
    content: str = Field(default="", max_length=32_768)
    source: str = Field(min_length=1, max_length=128)
    untrusted: bool = False
    contains_instructions: bool = False


class ActionRequest(PublicModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=256)
    action_id: str = Field(default_factory=lambda: str(uuid4()))
    kind: ActionKind
    operation: str = Field(min_length=1, max_length=256)
    target: str | None = Field(default=None, max_length=2_048)
    arguments: dict[str, Any] = Field(default_factory=dict)
    provenance: list[str] = Field(default_factory=list, max_length=128)
    evidence: list[Evidence] = Field(default_factory=list, max_length=32)
    requested_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @model_validator(mode="after")
    def validate_http_target(self) -> ActionRequest:
        if self.kind is ActionKind.HTTP and not self.target:
            raise ValueError("HTTP actions require a target URL")
        return self


class RuleMatch(PublicModel):
    kind: ActionKind | None = None
    operation: str | None = Field(default=None, max_length=256)
    target_prefix: str | None = Field(default=None, max_length=2_048)
    argument_equals: dict[str, Any] = Field(default_factory=dict)
    contains_untrusted_instructions: bool | None = None


class PolicyRule(PublicModel):
    rule_id: str = Field(default_factory=lambda: str(uuid4()))
    name: str = Field(min_length=1, max_length=256)
    priority: int = Field(ge=0, le=10_000)
    match: RuleMatch
    decision: Decision
    reason: str = Field(min_length=1, max_length=1_024)
    rewrite: dict[str, Any] | None = None
    cache_eligible: bool = False

    @model_validator(mode="after")
    def validate_rewrite(self) -> PolicyRule:
        if self.decision is Decision.REWRITE and not self.rewrite:
            raise ValueError("REWRITE rules require a rewrite payload")
        if self.cache_eligible and self.decision is not Decision.ALLOW:
            raise ValueError("only ALLOW rules can be cache eligible")
        return self


class PolicyDraft(PublicModel):
    name: str = Field(min_length=1, max_length=256)
    rules: list[PolicyRule] = Field(min_length=1, max_length=1_000)
    default_decision: Decision = Decision.BLOCK


class PolicyVersion(PublicModel):
    policy_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    version: int = Field(ge=1)
    draft: PolicyDraft
    status: PolicyStatus = PolicyStatus.DRAFT
    created_by: str
    approved_by: str | None = None
    activated_at: datetime | None = None
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class DecisionResponse(PublicModel):
    decision: Decision
    reason: str
    policy_id: str | None = None
    policy_version: int | None = None
    audit_id: str
    review_id: str | None = None
    rewritten_arguments: dict[str, Any] | None = None
    from_cache: bool = False


class Review(PublicModel):
    review_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    action_id: str
    audit_id: str
    expires_at: datetime = Field(default_factory=lambda: datetime.now(UTC) + timedelta(hours=24))
    status: str = "pending"
    resolution: ReviewResolution | None = None
    resolved_by: str | None = None
    reason: str | None = None


class AuditEvent(PublicModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str | None = None
    event_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SignedPolicyBundle(PublicModel):
    tenant_id: str
    policy: PolicyVersion
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    key_id: str
    signature: str


class ResolveReviewRequest(PublicModel):
    resolution: ReviewResolution
    reason: str = Field(min_length=1, max_length=1_024)


class HttpAction(PublicModel):
    method: str = Field(min_length=1, max_length=16)
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None
