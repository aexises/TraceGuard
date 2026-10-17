"""Versioned public contracts for the TraceGuard control plane."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum
from typing import Any, Literal
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
    EXECUTOR = "executor"


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
    tenant_ids: frozenset[str] = Field(default_factory=frozenset)
    allowed_operations: frozenset[str] | None = None


class Evidence(PublicModel):
    content: str = Field(default="", max_length=32_768)
    source: str = Field(min_length=1, max_length=128)
    untrusted: Literal[True] = True
    contains_instructions: bool = False


class ActionRequest(PublicModel):
    tenant_id: str = Field(min_length=1, max_length=128)
    idempotency_key: str = Field(min_length=8, max_length=256)
    task_id: str = Field(default="default", min_length=1, max_length=256)
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
        if self.kind is ActionKind.HTTP:
            from traceguard.policy.network import destination

            if not self.target:
                raise ValueError("HTTP actions require a target URL")
            destination(self.target)
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
        if self.cache_eligible and (
            self.match.kind is not ActionKind.HTTP
            or self.match.operation not in {"GET", "HEAD"}
            or not self.match.target_prefix
        ):
            raise ValueError("offline grants require an explicit HTTP GET/HEAD destination scope")
        return self


class PolicyDraft(PublicModel):
    name: str = Field(min_length=1, max_length=256)
    rules: list[PolicyRule] = Field(min_length=1, max_length=1_000)
    default_decision: Literal[Decision.BLOCK, Decision.ESCALATE] = Decision.BLOCK

    @model_validator(mode="after")
    def unique_rule_ids(self) -> PolicyDraft:
        if len({rule.rule_id for rule in self.rules}) != len(self.rules):
            raise ValueError("policy rule identifiers must be unique")
        return self


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
    action_digest: str | None = None


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
    action_digest: str
    agent_subject: str
    service_key_id: str
    task_id: str
    policy_epoch: int = Field(ge=1)
    grant_nonce: str | None = None


class AuditEvent(PublicModel):
    audit_id: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    event_type: str
    actor: str
    payload: dict[str, Any]
    previous_hash: str | None = None
    event_hash: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    sequence: int = Field(ge=1)
    schema_version: Literal["audit-v2"] = "audit-v2"


class SignedPolicyBundle(PublicModel):
    tenant_id: str
    policy: PolicyVersion
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    key_id: str
    signature: str
    algorithm: Literal["Ed25519"] = "Ed25519"
    audience: str
    service_key_id: str
    policy_epoch: int = Field(ge=1)


class ResolveReviewRequest(PublicModel):
    resolution: ReviewResolution
    reason: str = Field(min_length=1, max_length=1_024)


class HttpAction(PublicModel):
    method: str = Field(min_length=1, max_length=16)
    url: HttpUrl
    headers: dict[str, str] = Field(default_factory=dict)
    json_body: dict[str, Any] | None = None


class ExecutionGrant(PublicModel):
    nonce: str = Field(default_factory=lambda: str(uuid4()))
    tenant_id: str
    task_id: str
    agent_subject: str
    service_key_id: str
    audience: str
    action_digest: str
    authority_digest: str
    adapter_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    policy_id: str
    policy_epoch: int = Field(ge=1)
    issued_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime
    repeatable: bool = False
    amount: str = "0"
    budget_limit: str | None = None
    key_id: str
    signature: str


class TaskRegistration(PublicModel):
    task_id: str = Field(min_length=1, max_length=256)
    agent_subject: str = Field(min_length=1, max_length=256)
    service_key_id: str = Field(min_length=1, max_length=256)
    authority: dict[str, Any]
    tool_schemas: dict[str, dict[str, Any]]
    adapter_digest: str = Field(pattern=r"^[0-9a-f]{64}$")


class GrantRequest(PublicModel):
    action: ActionRequest
    review_id: str | None = None
    executor_audience: str = Field(min_length=1, max_length=256)


class GrantValidation(PublicModel):
    action: ActionRequest
    grant: ExecutionGrant
