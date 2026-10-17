"""Shared, ownership-neutral contracts used across TraceGuard."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, model_validator

CONTRACT_VERSION = "types-v4"


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", validate_assignment=True)


class Decision(StrEnum):
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    REWRITE = "REWRITE"


class GoalRelevance(StrEnum):
    UNCERTAIN = "UNCERTAIN"
    IRRELEVANT = "IRRELEVANT"
    WEAK = "WEAK"
    STRONG = "STRONG"


class GoalNecessity(StrEnum):
    UNCERTAIN = "UNCERTAIN"
    UNNECESSARY = "UNNECESSARY"
    HELPFUL = "HELPFUL"
    NECESSARY = "NECESSARY"


class RiskLevel(StrEnum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TrustLabel(StrEnum):
    TRUSTED_SYSTEM = "TRUSTED_SYSTEM"
    USER_INPUT = "USER_INPUT"
    TRUSTED_TOOL = "TRUSTED_TOOL"
    UNTRUSTED_DOCUMENT = "UNTRUSTED_DOCUMENT"
    UNTRUSTED_TOOL = "UNTRUSTED_TOOL"
    AGENT_GENERATED = "AGENT_GENERATED"


class ExecutionTarget(StrEnum):
    DEFAULT = "DEFAULT"
    CONTAINER = "CONTAINER"
    SIMULATED = "SIMULATED"


class PostRunDisposition(StrEnum):
    ACCEPT_RESULT = "ACCEPT_RESULT"
    REWRITE_AND_RETRY = "REWRITE_AND_RETRY"
    BLOCK_RESULT = "BLOCK_RESULT"
    ESCALATE = "ESCALATE"


class ThreatModel(StrEnum):
    BENIGN = "BENIGN"
    POLICY_VIOLATION = "POLICY_VIOLATION"
    DIRECT_ATTACK = "DIRECT_ATTACK"
    INDIRECT_INJECTION = "INDIRECT_INJECTION"
    OBSERVATION_INJECTION = "OBSERVATION_INJECTION"
    MEMORY_POISONING = "MEMORY_POISONING"


class ToolCall(StrictModel):
    task_id: str
    step_id: int = Field(ge=0)
    tool_name: str = Field(min_length=1)
    arguments: dict[str, Any] = Field(default_factory=dict)
    consumed_observation_ids: list[str] = Field(default_factory=list)
    requested_resources: list[str] = Field(default_factory=list)
    call_id: str = Field(default_factory=lambda: str(uuid4()))


class Observation(StrictModel):
    content: str
    source_type: str
    source_id: str
    trust: TrustLabel
    provenance_chain: list[str] = Field(default_factory=list)
    may_contain_instructions: bool = False
    observation_id: str = Field(default_factory=lambda: str(uuid4()))


class TaskAuthority(StrictModel):
    """Trusted, caller-supplied constraints; never populated from retrieved instructions."""

    allowed_tools: list[str] | None = None
    repeatable_tools: list[str] = Field(default_factory=list)
    argument_values: dict[str, dict[str, Any]] = Field(default_factory=dict)
    resource_values: dict[str, dict[str, list[Any]]] = Field(default_factory=dict)
    enforcement_mode: Literal["research", "strict"] = "research"
    generated_fields: dict[str, list[str]] = Field(default_factory=dict)
    delegated_fields: dict[str, dict[str, list[str]]] = Field(default_factory=dict)
    max_amount: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    prohibited_content: list[str] = Field(default_factory=list)
    approved_conditions: list[str] = Field(default_factory=list)


class SupervisorOutput(StrictModel):
    decision: Decision
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    policy_violation: bool
    goal_relevance: GoalRelevance
    goal_necessity: GoalNecessity
    reason: str = Field(min_length=1)
    matched_rules: list[str] = Field(default_factory=list)
    rewritten_call: ToolCall | None = None
    execution_target: ExecutionTarget | None = None
    container_profile: str | None = None
    provider_metadata: dict[str, Any] = Field(default_factory=dict)

    @model_validator(mode="after")
    def validate_decision_payload(self) -> SupervisorOutput:
        if self.decision is Decision.REWRITE and self.rewritten_call is None:
            raise ValueError("REWRITE requires rewritten_call")
        if self.execution_target is ExecutionTarget.CONTAINER and not self.container_profile:
            raise ValueError("CONTAINER target requires container_profile")
        return self


class SandboxLimits(StrictModel):
    timeout_seconds: int = Field(default=20, ge=1, le=300)
    memory_mb: int = Field(default=256, ge=32, le=4096)
    cpu_count: float = Field(default=1.0, gt=0, le=4)
    pids: int = Field(default=64, ge=1, le=512)
    output_bytes: int = Field(default=65536, ge=1024, le=1048576)


class ExecutionPlan(StrictModel):
    effective_call: ToolCall
    target: ExecutionTarget
    sandbox_profile: str | None = None
    declared_input_paths: list[str] = Field(default_factory=list)
    limits: SandboxLimits = Field(default_factory=SandboxLimits)
    validated: bool = False
    validation_reason: str = ""

    @model_validator(mode="after")
    def validate_profile(self) -> ExecutionPlan:
        if self.target is ExecutionTarget.CONTAINER and not self.sandbox_profile:
            raise ValueError("container execution requires a sandbox profile")
        return self


class SandboxEvidence(StrictModel):
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    stdout_truncated: bool = False
    stderr_truncated: bool = False
    files_changed: list[str] = Field(default_factory=list)
    artifact_bytes: int = Field(default=0, ge=0)
    artifact_directory: str | None = None
    blocked_operations: list[str] = Field(default_factory=list)
    duration_ms: float = Field(default=0.0, ge=0.0)
    peak_memory_bytes: int | None = Field(default=None, ge=0)
    disk_usage_bytes: int | None = Field(default=None, ge=0)
    timed_out: bool = False
    profile: str


class PostRunAssessment(StrictModel):
    risk: RiskLevel
    confidence: float = Field(ge=0.0, le=1.0)
    evidence: list[str] = Field(default_factory=list)
    disposition: PostRunDisposition
    reason: str
    provider_metadata: dict[str, Any] = Field(default_factory=dict)


class TraceEvent(StrictModel):
    task_id: str
    step_id: int
    proposed_call: ToolCall
    effective_call: ToolCall | None = None
    safeguard_outputs: list[SupervisorOutput] = Field(default_factory=list)
    execution_plan: ExecutionPlan | None = None
    result_observation_id: str | None = None
    result_digest: str | None = None
    latency_ms: float = Field(default=0.0, ge=0.0)
    token_usage: int = Field(default=0, ge=0)
    policy_version: str
    episode_outcome: str | None = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(UTC))


class SafeguardConfig(StrictModel):
    supervisor_mode: Literal["none", "deterministic", "llm", "deterministic_llm"] | None = None
    defensive_prompt: bool = False
    deterministic_policy: bool = False
    llm_supervisor: bool = False
    post_run_reevaluation: bool = False
    block_replanning: bool = True
    max_block_replans: int = Field(default=2, ge=0, le=10)
