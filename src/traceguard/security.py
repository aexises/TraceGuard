"""Strict embedded execution with an application-owned task and durable effects."""

from pathlib import Path

from traceguard.ledger import ExecutionLedger
from traceguard.policy.authorization import effect_registry
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
        task_id: str,
        ledger_path: Path | None = None,
        supervisor: Supervisor | None = None,
        sandbox: ContainerRunner | None = None,
    ):
        strict = authority.model_copy(deep=True, update={"enforcement_mode": "strict"})
        if not task_id or len(task_id) > 256:
            raise ValueError("application-owned task ID is required")
        effects = set(strict.allowed_tools or []) - set(effect_registry()["read"])
        if effects and ledger_path is None:
            raise ValueError("strict side effects require a private durable ledger_path")
        super().__init__(
            tools,
            SafeguardConfig(deterministic_policy=True, llm_supervisor=supervisor is not None),
            policy=DeterministicPolicy(load_default_policy()),
            supervisor=supervisor,
            sandbox=sandbox,
            task_authority=strict,
            effect_ledger=ExecutionLedger(ledger_path) if ledger_path is not None else None,
            bound_task_id=task_id,
        )
