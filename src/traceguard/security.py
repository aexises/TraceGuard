"""Strict embedded execution with an application-owned task and durable effects."""

from copy import copy
from dataclasses import replace
from pathlib import Path

from traceguard._enforcement import GuardedExecution
from traceguard.ledger import ExecutionLedger
from traceguard.policy.authorization import effect_registry
from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.release_gate import GuardedProvider, ReleaseGate
from traceguard.sandbox.runner import ContainerRunner
from traceguard.supervisor.base import Supervisor
from traceguard.tools.registry import ToolRegistry
from traceguard.types import EnforcementConfig, TaskAuthority


class SecuredTools(GuardedExecution):
    def __init__(
        self,
        tools: ToolRegistry,
        authority: TaskAuthority,
        *,
        task_id: str,
        ledger_path: Path | None = None,
        ledger_id: str | None = None,
        release_gate: ReleaseGate | None = None,
        model_input_label: str = "unclassified",
        supervisor: Supervisor | None = None,
        sandbox: ContainerRunner | None = None,
        post_run_reevaluation: bool = False,
        result_policy_version: str = "embedded-result-v1",
    ):
        strict = authority.model_copy(deep=True, update={"enforcement_mode": "strict"})
        self.release_gate = replace(
            release_gate or ReleaseGate(frozenset()),
            prohibited_literals=tuple(release_gate.prohibited_literals if release_gate else ())
            + tuple(strict.prohibited_content),
        )
        if supervisor is not None and hasattr(supervisor, "provider"):
            supervisor = copy(supervisor)
            supervisor.provider = GuardedProvider(
                supervisor.provider, self.release_gate, input_label=model_input_label
            )
        if not task_id or len(task_id) > 256:
            raise ValueError("application-owned task ID is required")
        effects = set(strict.allowed_tools or []) - set(effect_registry()["read"])
        if effects and ledger_path is None:
            raise ValueError("strict side effects require a private durable ledger_path")
        if ledger_path is not None and ledger_id is None:
            raise ValueError("trusted ledger_id is required with ledger_path")
        super().__init__(
            tools,
            EnforcementConfig(
                llm_supervisor=supervisor is not None,
                post_run_reevaluation=post_run_reevaluation,
            ),
            policy=DeterministicPolicy(load_default_policy()),
            supervisor=supervisor,
            sandbox=sandbox,
            task_authority=strict,
            effect_ledger=(
                ExecutionLedger(ledger_path, expected_store_id=ledger_id)
                if ledger_path is not None
                else None
            ),
            bound_task_id=task_id,
            result_policy_version=result_policy_version,
        )

    def release_answer(self, proposed: str, *, label: str = "unclassified") -> str:
        return self.release_gate.authorize("final_answer", proposed.encode(), label=label).decode()
