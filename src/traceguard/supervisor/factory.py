"""Supervisor-mode construction helpers."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Literal

from traceguard.policy.engine import DeterministicPolicy, PolicyConfig, load_default_policy
from traceguard.supervisor.base import Supervisor
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.supervisor.llm import GeminiSupervisor, OllamaSupervisor, QwenSupervisor
from traceguard.types import SafeguardConfig

SupervisorMode = Literal["none", "deterministic", "llm", "deterministic_llm"]
SupervisorProviderName = Literal["ollama", "qwen", "gemini", "heuristic"]

DEFAULT_OLLAMA_SUPERVISOR_MODEL = "qwen3:4b"
FALLBACK_OLLAMA_SUPERVISOR_MODEL = "qwen3:1.7b"
DEFAULT_OLLAMA_URL = "http://127.0.0.1:11434"


@dataclass(frozen=True)
class SupervisorRuntimeBundle:
    config: SafeguardConfig
    policy: DeterministicPolicy | None
    supervisor: Supervisor | None
    policy_version: str


def safeguard_config_for_mode(
    mode: SupervisorMode,
    *,
    defensive_prompt: bool = False,
    post_run_reevaluation: bool = False,
) -> SafeguardConfig:
    return SafeguardConfig(
        supervisor_mode=mode,
        defensive_prompt=defensive_prompt,
        deterministic_policy=mode in {"deterministic", "deterministic_llm"},
        llm_supervisor=mode in {"llm", "deterministic_llm"},
        post_run_reevaluation=post_run_reevaluation,
    )


def mode_from_safeguards(config: SafeguardConfig) -> SupervisorMode:
    if config.supervisor_mode is not None:
        return config.supervisor_mode
    if config.deterministic_policy and config.llm_supervisor:
        return "deterministic_llm"
    if config.deterministic_policy:
        return "deterministic"
    if config.llm_supervisor:
        return "llm"
    return "none"


def build_supervisor_bundle(
    config: SafeguardConfig,
    *,
    provider: SupervisorProviderName = "ollama",
    supervisor_model: str | None = None,
    ollama_url: str | None = None,
    gemini_api_key: str | None = None,
    gemini_base_url: str | None = None,
    timeout: float = 60.0,
    max_retries: int = 2,
    confidence_threshold: float = 0.55,
    enable_rewrite: bool = False,
    available_tools: dict[str, dict] | None = None,
    policy_config: PolicyConfig | None = None,
) -> SupervisorRuntimeBundle:
    mode = mode_from_safeguards(config)
    policy_config = policy_config or load_default_policy()
    policy = (
        DeterministicPolicy(policy_config)
        if mode in {"deterministic", "deterministic_llm"}
        else None
    )
    supervisor = (
        _build_llm_supervisor(
            provider=provider,
            supervisor_model=supervisor_model,
            ollama_url=ollama_url,
            gemini_api_key=gemini_api_key,
            gemini_base_url=gemini_base_url,
            timeout=timeout,
            max_retries=max_retries,
            confidence_threshold=confidence_threshold,
            enable_rewrite=enable_rewrite,
            available_tools=available_tools,
        )
        if mode in {"llm", "deterministic_llm"}
        else None
    )
    effective_config = config.model_copy(
        update={
            "supervisor_mode": mode,
            "deterministic_policy": policy is not None,
            "llm_supervisor": supervisor is not None,
        }
    )
    return SupervisorRuntimeBundle(
        config=effective_config,
        policy=policy,
        supervisor=supervisor,
        policy_version=policy_config.version,
    )


def _build_llm_supervisor(
    *,
    provider: SupervisorProviderName,
    supervisor_model: str | None,
    ollama_url: str | None,
    gemini_api_key: str | None,
    gemini_base_url: str | None,
    timeout: float,
    max_retries: int,
    confidence_threshold: float,
    enable_rewrite: bool,
    available_tools: dict[str, dict] | None,
) -> Supervisor:
    if provider == "heuristic":
        return HeuristicSupervisor()

    model = (
        supervisor_model or os.getenv("TRACEGUARD_OLLAMA_MODEL") or DEFAULT_OLLAMA_SUPERVISOR_MODEL
    )
    url = ollama_url or os.getenv("TRACEGUARD_OLLAMA_URL") or DEFAULT_OLLAMA_URL
    if provider in {"ollama", "qwen"}:
        llm_provider = OllamaSupervisor(
            model=model,
            url=url,
            model_tag=model,
            max_transport_retries=max_retries,
            timeout=timeout,
        )
    elif provider == "gemini":
        llm_provider = GeminiSupervisor(
            model=supervisor_model or os.getenv("TRACEGUARD_GEMINI_MODEL") or "gemini-3.5-flash",
            api_key=gemini_api_key,
            base_url=gemini_base_url,
            timeout=timeout,
            max_transport_retries=max_retries,
        )
    else:
        raise ValueError(f"unknown supervisor provider: {provider}")

    return QwenSupervisor(
        provider=llm_provider,
        available_tools=available_tools,
        confidence_threshold=confidence_threshold,
        enable_rewrite=enable_rewrite,
        deterministic_enabled=False,
    )
