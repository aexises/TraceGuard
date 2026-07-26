from traceguard.supervisor.factory import (
    DEFAULT_OLLAMA_SUPERVISOR_MODEL,
    build_supervisor_bundle,
    mode_from_safeguards,
    safeguard_config_for_mode,
)
from traceguard.supervisor.heuristic import HeuristicSupervisor
from traceguard.types import SafeguardConfig


def test_mode_config_maps_four_public_modes():
    assert mode_from_safeguards(SafeguardConfig()) == "none"
    assert mode_from_safeguards(safeguard_config_for_mode("none")) == "none"
    assert mode_from_safeguards(safeguard_config_for_mode("deterministic")) == "deterministic"
    assert mode_from_safeguards(safeguard_config_for_mode("llm")) == "llm"
    assert (
        mode_from_safeguards(safeguard_config_for_mode("deterministic_llm")) == "deterministic_llm"
    )


def test_heuristic_bundle_supports_offline_llm_mode():
    bundle = build_supervisor_bundle(
        safeguard_config_for_mode("llm"),
        provider="heuristic",
    )
    assert bundle.policy is None
    assert isinstance(bundle.supervisor, HeuristicSupervisor)
    assert bundle.config.llm_supervisor is True


def test_default_supervisor_model_is_qwen_4b():
    assert DEFAULT_OLLAMA_SUPERVISOR_MODEL == "qwen3:4b"
