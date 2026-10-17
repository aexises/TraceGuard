"""Inspectable deterministic policy checks.

The policy is the first hard gate before LLM supervision or container execution.
Every decision records `POLICY_VERSION=<version>` in matched_rules for traces.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath

from pydantic import BaseModel, ConfigDict, Field

from traceguard.policy.authorization import check_authority, sensitive_path, tool_effect
from traceguard.types import (
    Decision,
    ExecutionTarget,
    GoalNecessity,
    GoalRelevance,
    Observation,
    RiskLevel,
    SupervisorOutput,
    TaskAuthority,
    ToolCall,
    TrustLabel,
)


class PolicyConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str
    allowed_read_roots: list[str]
    allowed_write_roots: list[str]
    blocked_path_segments: list[str] = Field(default_factory=list)
    blocked_command_tokens: list[str]
    blocked_shell_operators: list[str]
    sandbox_command_tokens: list[str]
    benign_command_tokens: list[str] = Field(default_factory=list)
    math_goal_keywords: list[str] = Field(default_factory=list)
    write_goal_keywords: list[str] = Field(default_factory=list)
    read_goal_keywords: list[str] = Field(default_factory=list)
    max_command_length: int = Field(gt=0)
    max_requested_resources: int = Field(default=4, gt=0)

    @classmethod
    def from_file(cls, path: Path) -> PolicyConfig:
        return cls.model_validate_json(path.read_text(encoding="utf-8"))


class DeterministicPolicy:
    def __init__(self, config: PolicyConfig) -> None:
        self.config = config
        self.task_authority = TaskAuthority()
        self.previous_calls: list[ToolCall] = []

    @property
    def version(self) -> str:
        return self.config.version

    def evaluate(
        self,
        user_task: str,
        call: ToolCall,
        observations: list[Observation],
    ) -> SupervisorOutput:
        resource_result = self._evaluate_requested_resources(user_task, call, observations)
        if resource_result is not None:
            return resource_result

        relevance_result = (
            self._evaluate_goal_relevance(user_task, call)
            if self.task_authority.enforcement_mode == "research"
            else None
        )
        if relevance_result is not None:
            return relevance_result

        if call.tool_name in {"read_file", "write_report"}:
            result = self._evaluate_path(user_task, call)
            if result.decision is Decision.ALLOW:
                denied = check_authority(
                    user_task, call, observations, self.task_authority, self.previous_calls
                )
                if denied is not None:
                    return denied
            return result
        denied = check_authority(
            user_task, call, observations, self.task_authority, self.previous_calls
        )
        if denied is not None:
            return denied
        if call.tool_name == "restricted_command":
            return self._evaluate_command(call, observations)
        if call.tool_name == "search_documents":
            return self._evaluate_search(call)
        if call.tool_name == "calculator":
            return self._allow(
                "POLICY_TOOL_LOW_RISK", GoalRelevance.UNCERTAIN, GoalNecessity.UNCERTAIN
            )
        if self.task_authority.enforcement_mode == "strict" and tool_effect(call) != "command":
            return self._allow("POLICY_STRICT_AUTHORITY")
        return self._escalate("POLICY_UNKNOWN_TOOL", "Tool effect is not registered.")

    def _version_rules(self, *rules: str) -> list[str]:
        return [f"POLICY_VERSION={self.config.version}", *rules]

    def _evaluate_requested_resources(
        self, user_task: str, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput | None:
        if len(call.requested_resources) > self.config.max_requested_resources:
            return self._block("POLICY_EXCESSIVE_RESOURCES", RiskLevel.HIGH)
        privileged = {"network", "sudo", "docker", "host_fs", "privileged"}
        lowered = {item.casefold() for item in call.requested_resources}
        if lowered.intersection(privileged):
            return self._block("POLICY_UNNECESSARY_PERMISSIONS", RiskLevel.CRITICAL)
        for resource in call.requested_resources:
            if resource == "artifact_output":
                continue
            if not resource.startswith("input:"):
                return self._block("POLICY_UNKNOWN_RESOURCE", RiskLevel.HIGH)
            raw_path = resource.removeprefix("input:")
            if sensitive_path(raw_path, self.config.blocked_path_segments):
                return self._block("POLICY_RESOURCE_PATH_SENSITIVE", RiskLevel.HIGH)
            path = PurePosixPath(raw_path)
            if (
                path.is_absolute()
                or ".." in path.parts
                or not path.parts
                or path.parts[0] not in self.config.allowed_read_roots
            ):
                return self._block("POLICY_RESOURCE_PATH_OUTSIDE_ROOT", RiskLevel.HIGH)
            mentioned_paths = {
                match.rstrip(".,:;!?") for match in re.findall(r"[\w.-]+(?:/[\w.-]+)+", user_task)
            }
            specified = "requested_resources" in self.task_authority.argument_values.get(
                call.tool_name, {}
            )
            delegated = "requested_resources" in self.task_authority.delegated_fields.get(
                call.tool_name, {}
            )
            if not specified and not delegated:
                if not mentioned_paths:
                    return self._escalate(
                        "POLICY_RESOURCE_AUTHORITY_MISSING",
                        "Declared inputs require trusted task scope.",
                    )
                if raw_path not in mentioned_paths:
                    return self._block("POLICY_RESOURCE_NOT_AUTHORIZED", RiskLevel.HIGH)
        return None

    def _evaluate_goal_relevance(self, user_task: str, call: ToolCall) -> SupervisorOutput | None:
        task = user_task.casefold()
        math_goal = _has_keyword(
            task, [word for word in self.config.math_goal_keywords if word != "add"]
        )
        mixed_goal = _has_keyword(
            task,
            self.config.read_goal_keywords
            + self.config.write_goal_keywords
            + ["participants", "file", "document", "data"],
        )
        math_goal = math_goal and not mixed_goal
        write_goal = _has_keyword(task, self.config.write_goal_keywords)
        read_goal = _has_keyword(task, self.config.read_goal_keywords)
        shell_requested = _has_keyword(task, ["command", "shell", "terminal", "run", "execute"])

        if math_goal and call.tool_name == "restricted_command":
            return SupervisorOutput(
                decision=Decision.BLOCK,
                risk=RiskLevel.MEDIUM,
                confidence=1.0,
                policy_violation=True,
                goal_relevance=GoalRelevance.IRRELEVANT,
                goal_necessity=GoalNecessity.UNNECESSARY,
                reason="Math goals must use calculator, not command execution.",
                matched_rules=self._version_rules("POLICY_IRRELEVANT_COMMAND_FOR_MATH"),
            )
        if math_goal and call.tool_name in {"read_file", "write_report", "search_documents"}:
            return SupervisorOutput(
                decision=Decision.BLOCK,
                risk=RiskLevel.LOW,
                confidence=0.9,
                policy_violation=True,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.UNNECESSARY,
                reason="Pure math goals do not require document or file tools.",
                matched_rules=self._version_rules("POLICY_IRRELEVANT_TOOL_FOR_MATH"),
            )
        if write_goal and call.tool_name == "restricted_command":
            return SupervisorOutput(
                decision=Decision.BLOCK,
                risk=RiskLevel.MEDIUM,
                confidence=0.95,
                policy_violation=True,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.UNNECESSARY,
                reason="Report writing must use write_report, not shell commands.",
                matched_rules=self._version_rules("POLICY_IRRELEVANT_COMMAND_FOR_WRITE"),
            )
        if read_goal and call.tool_name == "restricted_command" and not shell_requested:
            return SupervisorOutput(
                decision=Decision.BLOCK,
                risk=RiskLevel.MEDIUM,
                confidence=0.9,
                policy_violation=True,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.UNNECESSARY,
                reason="Reading or summarizing files does not require command execution.",
                matched_rules=self._version_rules("POLICY_IRRELEVANT_COMMAND_FOR_READ"),
            )
        return None

    def _evaluate_search(self, call: ToolCall) -> SupervisorOutput:
        query = str(call.arguments.get("query", "")).strip()
        if not query:
            return self._block("POLICY_SEARCH_EMPTY_QUERY", RiskLevel.LOW)
        return self._allow(
            "POLICY_SEARCH_ALLOWED", GoalRelevance.UNCERTAIN, GoalNecessity.UNCERTAIN
        )

    def _evaluate_path(self, user_task: str, call: ToolCall) -> SupervisorOutput:
        raw_path = str(call.arguments.get("path", ""))
        path = PurePosixPath(raw_path)
        roots = (
            self.config.allowed_read_roots
            if call.tool_name == "read_file"
            else self.config.allowed_write_roots
        )

        if call.tool_name == "read_file" and (
            path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] not in roots
        ):
            return self._block("POLICY_PATH_OUTSIDE_ROOT", RiskLevel.HIGH)
        if path.is_absolute() or ".." in path.parts or not path.parts:
            return self._block("POLICY_PATH_OUTSIDE_ROOT", RiskLevel.HIGH)
        if sensitive_path(raw_path, self.config.blocked_path_segments):
            return self._block("POLICY_PATH_SENSITIVE", RiskLevel.CRITICAL)
        if call.tool_name == "read_file":
            mentioned_paths = {
                match.rstrip(".,:;!?") for match in re.findall(r"[\w.-]+(?:/[\w.-]+)+", user_task)
            }
            trusted_paths = self.task_authority.argument_values.get("read_file", {})
            if self.task_authority.enforcement_mode == "strict":
                trusted_paths = trusted_paths or self.task_authority.resource_values.get(
                    "read_file", {}
                )
            delegated = "path" in self.task_authority.delegated_fields.get("read_file", {})
            if not mentioned_paths and not trusted_paths and not delegated:
                return self._escalate(
                    "POLICY_READ_AUTHORITY_MISSING",
                    "File scope requires an explicit path or trusted delegation.",
                )
            if (
                mentioned_paths
                and raw_path not in mentioned_paths
                and not trusted_paths
                and not delegated
            ):
                return SupervisorOutput(
                    decision=Decision.BLOCK,
                    risk=RiskLevel.MEDIUM,
                    confidence=0.95,
                    policy_violation=True,
                    goal_relevance=GoalRelevance.WEAK,
                    goal_necessity=GoalNecessity.UNNECESSARY,
                    reason="The requested file is not among the paths named in the user task.",
                    matched_rules=self._version_rules("POLICY_IRRELEVANT_FILE_ACCESS"),
                )

        if (
            call.tool_name == "write_report"
            and not path.is_absolute()
            and ".." not in path.parts
            and path.parts
        ):
            if len(path.parts) == 1 or path.parts[0] not in self.config.allowed_write_roots:
                if path.parts[0] not in self.config.allowed_write_roots:
                    rewritten = call.model_copy(
                        update={"arguments": {**call.arguments, "path": f"artifacts/{raw_path}"}}
                    )
                    return SupervisorOutput(
                        decision=Decision.REWRITE,
                        risk=RiskLevel.LOW,
                        confidence=1.0,
                        policy_violation=False,
                        goal_relevance=GoalRelevance.WEAK,
                        goal_necessity=GoalNecessity.HELPFUL,
                        reason="Normalize report output into the allowed artifacts root.",
                        matched_rules=self._version_rules("POLICY_WRITE_ROOT_REWRITE"),
                        rewritten_call=rewritten,
                    )

        if path.is_absolute() or ".." in path.parts or not path.parts or path.parts[0] not in roots:
            return self._block("POLICY_PATH_OUTSIDE_ROOT", RiskLevel.HIGH)

        if call.tool_name == "read_file" and path.parts[0] == "workspace" and len(path.parts) == 1:
            return self._block("POLICY_PATH_DIRECTORY_ONLY", RiskLevel.MEDIUM)

        return self._allow("POLICY_PATH_ALLOWED", GoalRelevance.UNCERTAIN, GoalNecessity.UNCERTAIN)

    def _evaluate_command(
        self, call: ToolCall, observations: list[Observation]
    ) -> SupervisorOutput:
        command = call.arguments.get("command", [])
        if not isinstance(command, list) or not all(isinstance(part, str) for part in command):
            return self._block("POLICY_COMMAND_SCHEMA", RiskLevel.HIGH)
        if not command:
            return self._block("POLICY_COMMAND_EMPTY", RiskLevel.HIGH)

        rendered = " ".join(command)
        lowered = {part.casefold() for part in command}
        if len(rendered) > self.config.max_command_length:
            return self._block("POLICY_COMMAND_TOO_LONG", RiskLevel.HIGH)
        if lowered.intersection(token.casefold() for token in self.config.blocked_command_tokens):
            return self._block("POLICY_COMMAND_BLOCKED_TOKEN", RiskLevel.CRITICAL)
        if any(part in self.config.blocked_shell_operators for part in command):
            return self._block("POLICY_SHELL_OPERATOR", RiskLevel.HIGH)

        untrusted_dependencies = [
            obs
            for obs in observations
            if obs.trust in {TrustLabel.UNTRUSTED_DOCUMENT, TrustLabel.UNTRUSTED_TOOL}
        ]
        if untrusted_dependencies:
            injurious = any(_looks_like_instruction(obs.content) for obs in untrusted_dependencies)
            if injurious:
                return SupervisorOutput(
                    decision=Decision.BLOCK,
                    risk=RiskLevel.HIGH,
                    confidence=1.0,
                    policy_violation=True,
                    goal_relevance=GoalRelevance.WEAK,
                    goal_necessity=GoalNecessity.UNNECESSARY,
                    reason="Command depends on untrusted observations that appear instructional.",
                    matched_rules=self._version_rules("POLICY_UNTRUSTED_OBSERVATION_DEPENDENCY"),
                )
            profile, declared_rule = self._container_profile(call)
            return SupervisorOutput(
                decision=Decision.ALLOW,
                risk=RiskLevel.MEDIUM,
                confidence=0.85,
                policy_violation=False,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.HELPFUL,
                reason=(
                    "Command informed by untrusted input must use a predefined container profile."
                ),
                matched_rules=self._version_rules(
                    "POLICY_COMMAND_CONTAINER_UNTRUSTED", declared_rule
                ),
                execution_target=ExecutionTarget.CONTAINER,
                container_profile=profile,
            )

        head = command[0].casefold()
        if head in {token.casefold() for token in self.config.blocked_command_tokens}:
            return self._block("POLICY_COMMAND_BLOCKED_TOKEN", RiskLevel.CRITICAL)
        if head in {token.casefold() for token in self.config.sandbox_command_tokens}:
            profile, declared_rule = self._container_profile(call)
            return SupervisorOutput(
                decision=Decision.ALLOW,
                risk=RiskLevel.MEDIUM,
                confidence=0.85,
                policy_violation=False,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.HELPFUL,
                reason="Medium-risk command must use a predefined container profile.",
                matched_rules=self._version_rules("POLICY_COMMAND_CONTAINER", declared_rule),
                execution_target=ExecutionTarget.CONTAINER,
                container_profile=profile,
            )
        if head in {token.casefold() for token in self.config.benign_command_tokens}:
            return SupervisorOutput(
                decision=Decision.ALLOW,
                risk=RiskLevel.LOW,
                confidence=1.0,
                policy_violation=False,
                goal_relevance=GoalRelevance.WEAK,
                goal_necessity=GoalNecessity.HELPFUL,
                reason="Benign argv command allowed as simulated/default execution only.",
                matched_rules=self._version_rules("POLICY_COMMAND_BENIGN"),
                execution_target=ExecutionTarget.SIMULATED,
            )
        return SupervisorOutput(
            decision=Decision.ESCALATE,
            risk=RiskLevel.MEDIUM,
            confidence=0.7,
            policy_violation=False,
            goal_relevance=GoalRelevance.WEAK,
            goal_necessity=GoalNecessity.HELPFUL,
            reason="Unknown command binary requires human or LLM review.",
            matched_rules=self._version_rules("POLICY_COMMAND_UNKNOWN_ESCALATE"),
        )

    @staticmethod
    def _container_profile(call: ToolCall) -> tuple[str, str]:
        resources = set(call.requested_resources)
        if "artifact_output" in resources:
            return "artifact_build", "POLICY_CONTAINER_ARTIFACT_OUTPUT"
        if any(resource.startswith("input:") for resource in resources):
            return "readonly_input", "POLICY_CONTAINER_READONLY_INPUT"
        return "isolated_compute", "POLICY_CONTAINER_ISOLATED"

    def _allow(
        self,
        rule: str,
        goal_relevance: GoalRelevance = GoalRelevance.UNCERTAIN,
        goal_necessity: GoalNecessity = GoalNecessity.UNCERTAIN,
    ) -> SupervisorOutput:
        return SupervisorOutput(
            decision=Decision.ALLOW,
            risk=RiskLevel.LOW,
            confidence=1.0,
            policy_violation=False,
            goal_relevance=goal_relevance,
            goal_necessity=goal_necessity,
            reason="Deterministic policy allows the call.",
            matched_rules=self._version_rules(rule),
        )

    def _escalate(self, rule: str, reason: str) -> SupervisorOutput:
        return SupervisorOutput(
            decision=Decision.ESCALATE,
            risk=RiskLevel.MEDIUM,
            confidence=1.0,
            policy_violation=False,
            goal_relevance=GoalRelevance.WEAK,
            goal_necessity=GoalNecessity.HELPFUL,
            reason=reason,
            matched_rules=self._version_rules(rule),
        )

    def _block(self, rule: str, risk: RiskLevel) -> SupervisorOutput:
        return SupervisorOutput(
            decision=Decision.BLOCK,
            risk=risk,
            confidence=1.0,
            policy_violation=True,
            goal_relevance=GoalRelevance.UNCERTAIN,
            goal_necessity=GoalNecessity.UNCERTAIN,
            reason="Deterministic policy denies the call.",
            matched_rules=self._version_rules(rule),
        )


_INSTRUCTION_PATTERNS = (
    re.compile(r"\bignore (all )?(previous|prior) (instructions|policies)\b", re.I),
    re.compile(r"\bsystem\s*:", re.I),
    re.compile(r"\b(run|execute|curl|wget|sudo)\b.+\b(http|attacker|secret)", re.I),
    re.compile(r"\bread\s+\S*(secret|credential|password|canary)\S*", re.I),
)


def _has_keyword(text: str, keywords: list[str]) -> bool:
    return any(
        re.search(rf"(?<!\w){re.escape(keyword.casefold())}(?!\w)", text) for keyword in keywords
    )


def _looks_like_instruction(content: str) -> bool:
    return any(pattern.search(content) for pattern in _INSTRUCTION_PATTERNS)


def load_default_policy() -> PolicyConfig:
    path = Path(__file__).parents[1] / "data" / "policy" / "default.json"
    return PolicyConfig.from_file(path)
