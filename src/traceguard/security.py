"""Supported strict tool boundary; legacy research heuristics remain opt-in by API choice."""

from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.sandbox.runner import ContainerRunner
from traceguard.supervisor.base import Supervisor
from traceguard.tools.registry import ToolRegistry
from traceguard.types import SafeguardConfig, TaskAuthority


class SecuredTools(TraceGuardRuntime):
    def __init__(
        self,
        tools: ToolRegistry,
        authority: TaskAuthority,
        *,
        supervisor: Supervisor | None = None,
        sandbox: ContainerRunner | None = None,
    ):
        strict = authority.model_copy(deep=True, update={"enforcement_mode": "strict"})
        super().__init__(
            tools,
            SafeguardConfig(deterministic_policy=True, llm_supervisor=supervisor is not None),
            policy=DeterministicPolicy(load_default_policy()),
            supervisor=supervisor,
            sandbox=sandbox,
            task_authority=strict,
        )
