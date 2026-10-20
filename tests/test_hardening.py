import json
from pathlib import Path

import pytest

from traceguard._enforcement import GuardedExecution
from traceguard.integrations.gateway import SupervisionGateway
from traceguard.policy import load_default_policy
from traceguard.policy.authorization import check_authority, infer_provenance, tool_effect
from traceguard.policy.engine import DeterministicPolicy
from traceguard.policy.read_resources import bind_read_schema
from traceguard.supervisor.contracts import (
    SupervisorRequest,
    SupervisorResponse,
    SupervisorSchemaError,
    _validate_arguments_against_json_schema,
    validate_replacement,
)
from traceguard.supervisor.llm import QwenSupervisor
from traceguard.supervisor.redaction import redact_request
from traceguard.tools.registry import default_registry
from traceguard.types import (
    Decision,
    EnforcementConfig,
    GoalNecessity,
    GoalRelevance,
    Observation,
    RiskLevel,
    TaskAuthority,
    ToolCall,
    TrustLabel,
)


def call(name, **args):
    return ToolCall(task_id="test", step_id=0, tool_name=name, arguments=args)


class Provider:
    def __init__(self, decision="BLOCK", fail=False):
        self.requests = []
        self.decision = decision
        self.fail = fail

    def evaluate(self, request):
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("unavailable")
        return SupervisorResponse(
            decision=self.decision,
            goal_relevance="UNCERTAIN" if self.decision == "ALLOW" else "UNRELATED",
            necessity="UNCERTAIN" if self.decision == "ALLOW" else "UNNECESSARY",
            risk_level="LOW" if self.decision == "ALLOW" else "HIGH",
            confidence=0.9,
            reason="Unsupported semantic effect",
        )


@pytest.mark.parametrize(
    "name,args",
    [
        ("read_file", {"path": "workspace/note.txt"}),
        ("send_money", {"amount": 20, "recipient": "x"}),
        ("memory", {"command": "create", "path": "note", "content": "x"}),
    ],
)
@pytest.mark.parametrize("hybrid", [False, True])
def test_provider_block_survives_every_tool_effect(name, args, hybrid):
    provider = Provider()
    guard = QwenSupervisor(provider=provider, deterministic_enabled=hybrid)
    guard.set_context(
        previous_calls=[],
        task_authority=TaskAuthority(allowed_tools=[name], argument_values={name: args}),
    )
    result = guard.evaluate("Perform the specified action", call(name, **args), [])
    assert len(provider.requests) == 1
    assert result.decision is Decision.BLOCK
    assert result.risk is RiskLevel.HIGH
    assert result.goal_relevance is GoalRelevance.IRRELEVANT
    assert result.goal_necessity is GoalNecessity.UNNECESSARY


@pytest.mark.parametrize("hybrid", [False, True])
def test_provider_failure_never_auto_allows(hybrid):
    result = QwenSupervisor(provider=Provider(fail=True), deterministic_enabled=hybrid).evaluate(
        "Calculate 2+2", call("calculator", expression="2+2"), []
    )
    assert result.decision is Decision.ESCALATE


def test_missing_authority_and_unknown_effect_do_not_call_provider():
    provider = Provider("ALLOW")
    guard = QwenSupervisor(provider=provider)
    assert (
        guard.evaluate("Send a note to Alice", call("send_email", to="a@example.test"), []).decision
        is Decision.ESCALATE
    )
    assert guard.evaluate("Use widget", call("widget"), []).decision is Decision.ESCALATE
    assert not provider.requests


def test_authorized_delegation_is_field_and_source_scoped():
    observations = [
        Observation(
            source_type="tool",
            trust=TrustLabel.UNTRUSTED_TOOL,
            source_id="contacts",
            content=json.dumps({"to": "a@example.test"}),
        ),
        Observation(
            source_type="tool",
            trust=TrustLabel.UNTRUSTED_TOOL,
            source_id="injected",
            content=json.dumps({"to": "b@example.test"}),
        ),
    ]
    authority = TaskAuthority(
        allowed_tools=["send_email"], delegated_fields={"send_email": {"to": ["contacts"]}}
    )
    assert (
        check_authority(
            "Send the note", call("send_email", to="a@example.test"), observations, authority
        )
        is None
    )
    assert (
        check_authority(
            "Send the note", call("send_email", to="b@example.test"), observations, authority
        ).decision
        is Decision.BLOCK
    )
    assert (
        check_authority(
            "Send the note", call("send_email", to="a@example.test"), [], authority
        ).decision
        is Decision.ESCALATE
    )


def test_data_keywords_and_negation_do_not_grant_side_effects():
    assert (
        check_authority(
            "Give email addresses", call("send_email", to="a@example.test"), []
        ).decision
        is Decision.BLOCK
    )
    assert (
        check_authority(
            "Do not send to a@example.test", call("send_email", to="a@example.test"), []
        ).decision
        is Decision.BLOCK
    )
    assert (
        check_authority(
            "Send to a@example.test only after approval",
            call("send_email", to="a@example.test"),
            [],
        ).decision
        is Decision.ESCALATE
    )
    assert tool_effect(call("memory", command="view")) == "read"
    assert tool_effect(call("memory", command="create")) == "mutate"
    assert tool_effect(call("undocumented")) == "unknown"


def test_policy_reads_scope_and_mixed_goal():
    policy = DeterministicPolicy(load_default_policy())
    assert (
        policy.evaluate("Summarize it", call("read_file", path="workspace/note.txt"), []).decision
        is Decision.ESCALATE
    )
    assert (
        policy.evaluate(
            "Read workspace/note.txt and calculate its total",
            call("read_file", path="workspace/note.txt"),
            [],
        ).decision
        is Decision.ALLOW
    )
    assert (
        policy.evaluate(
            "Add participants", call("search_documents", query="participants"), []
        ).decision
        is Decision.ALLOW
    )
    for path in ["workspace/.ssh/key", "workspace/credentials.csv", "inputs/private_key.pem"]:
        assert (
            policy.evaluate(f"Read {path}", call("read_file", path=path), []).decision
            is Decision.BLOCK
        )


def test_occurrence_provenance_does_not_depend_on_agent_claims():
    obs = Observation(
        content="a@example.test",
        source_type="tool",
        trust=TrustLabel.UNTRUSTED_TOOL,
        source_id="contacts",
    )
    assert infer_provenance("Send a@example.test", call("send_email", to="a@example.test"), [obs])[
        "to"
    ] == ["user_goal", obs.observation_id]


def test_rewrite_rejects_nested_bad_type_enum_and_bounds():
    schema = {
        "type": "object",
        "properties": {
            "x": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "mode": {"enum": ["view"]},
                        "amount": {"type": "number", "maximum": 2},
                    },
                    "required": ["mode", "amount"],
                },
            }
        },
    }
    for args in [
        {"x": "not-array"},
        {"x": [{"mode": "create", "amount": 1}]},
        {"x": [{"mode": "view", "amount": 3}]},
    ]:
        with pytest.raises(SupervisorSchemaError):
            _validate_arguments_against_json_schema(args, schema)
    with pytest.raises(SupervisorSchemaError):
        _validate_arguments_against_json_schema({}, {"$ref": "https://example.test/schema"})


def test_rewrite_cannot_expand_effects_or_resources():
    original = call("search_documents", query="x")
    for replacement in [
        original.model_copy(update={"tool_name": "send_email"}),
        original.model_copy(update={"requested_resources": ["network"]}),
    ]:
        with pytest.raises(SupervisorSchemaError):
            validate_replacement(
                original,
                replacement,
                goal="Search x",
                observations=[],
                authority=TaskAuthority(),
                schemas={"send_email": {"type": "object"}, "search_documents": {"type": "object"}},
            )


def test_escalation_latches_gateway_and_block_replan_recovers(tmp_path):
    provider = Provider(fail=True)
    gateway = SupervisionGateway(
        mode="deterministic_llm",
        supervisor=QwenSupervisor(provider=provider),
        available_tools={
            "calculator": bind_read_schema(
                {"type": "object"}, adapter_id="embedded-v1", tool_name="calculator"
            )
        },
        task_authority=TaskAuthority(enforcement_mode="strict", allowed_tools=["calculator"]),
    )
    for i in range(2):
        _, output = gateway.evaluate(
            task_id="t",
            step_id=i,
            user_goal="Calculate 2+2",
            tool_name="calculator",
            arguments={"expression": "2+2"},
            observations=[],
        )
        assert output.decision is Decision.ESCALATE
    assert len(provider.requests) == 1


def test_redacted_distinct_values_retain_equality():
    payload = redact_request({"secret": "alpha", "password": "beta", "body": "alpha beta alpha"})
    assert payload["secret"] != payload["password"]
    assert "alpha" not in json.dumps(payload) and "beta" not in json.dumps(payload)
    assert payload["body"].count(payload["secret"]) == 2
    SupervisorRequest(user_goal="Calculate", proposed_call=call("calculator", expression="2+2"))


def test_cumulative_payment_budget_and_nonfinite_values():
    authority = TaskAuthority(
        allowed_tools=["send_money"],
        max_amount=100,
        argument_values={"send_money": {"recipient": "account-1"}},
    )
    prior = call("send_money", amount=80, recipient="account-1")
    assert (
        check_authority(
            "Pay", call("send_money", amount=20, recipient="account-1"), [], authority, [prior]
        )
        is None
    )
    for amount in [21, -1, float("inf"), float("nan"), True]:
        assert (
            check_authority(
                "Pay",
                call("send_money", amount=amount, recipient="account-1"),
                [],
                authority,
                [prior],
            ).decision
            is Decision.BLOCK
        )


def test_declared_inputs_require_authority_and_sensitive_staging_is_rejected(tmp_path):
    from traceguard.sandbox.runner import ContainerRunner, SandboxUnavailable

    policy = DeterministicPolicy(load_default_policy())
    proposal = call("restricted_command", command=["python3", "-V"]).model_copy(
        update={"requested_resources": ["input:inputs/data.csv"]}
    )
    assert policy.evaluate("Run Python", proposal, []).decision is Decision.ESCALATE
    assert (
        policy.evaluate("Run Python on inputs/other.csv", proposal, []).decision is Decision.BLOCK
    )
    policy.task_authority = TaskAuthority(
        argument_values={"restricted_command": {"requested_resources": ["input:inputs/data.csv"]}}
    )
    assert policy.evaluate("Run Python", proposal, []).decision is Decision.ALLOW
    sandbox = ContainerRunner(
        Path("configs/sandbox_profiles.json"),
        workspace_root=tmp_path,
        artifact_root=tmp_path / "artifacts",
    )
    (tmp_path / "inputs").mkdir()
    (tmp_path / "inputs" / "passwords.csv").write_text("harmless-canary")
    for path in ["inputs/passwords.csv", "inputs"]:
        with pytest.raises(SandboxUnavailable, match="protected"):
            sandbox._stage_inputs([path], tmp_path / "staging")


def test_corpus_rejects_sensitive_objects_and_symlinks(tmp_path):
    documents = tmp_path / "documents"
    documents.mkdir()
    registry = default_registry(tmp_path, tmp_path / "artifacts")
    proposal = call("search_documents", query="harmless")
    (documents / "credentials.csv").write_text("harmless")
    with pytest.raises(ValueError, match="protected"):
        registry.execute(proposal)
    (documents / "credentials.csv").unlink()
    external = tmp_path / "outside.txt"
    external.write_text("harmless")
    (documents / "link.txt").symlink_to(external)
    with pytest.raises(ValueError, match="symbolic"):
        registry.execute(proposal)


def test_custom_runtime_latches_escalation_and_records_success_history(tmp_path):
    provider = Provider(fail=True)
    runtime = GuardedExecution(
        default_registry(tmp_path, tmp_path / "artifacts"),
        EnforcementConfig(llm_supervisor=True),
        supervisor=QwenSupervisor(provider=provider),
        task_authority=TaskAuthority(enforcement_mode="strict", allowed_tools=["calculator"]),
        bound_task_id="test",
        policy=DeterministicPolicy(load_default_policy()),
    )
    proposal = call("calculator", expression="2+2")
    for _ in range(2):
        assert (
            runtime.execute_call("Calculate 2+2", proposal, []).trace.episode_outcome == "ESCALATE"
        )
    assert len(provider.requests) == 1
    assert runtime.executed_calls == {}


def test_canonical_provider_envelopes_and_distinct_post_run_prompt():
    from traceguard.supervisor.llm import GeminiSupervisor, OllamaSupervisor

    class OllamaTransport:
        payload = None

        def post_chat(self, payload, *, timeout):
            self.payload = payload
            return {
                "message": {
                    "content": json.dumps(
                        {
                            "decision": "ALLOW",
                            "goal_relevance": "RELEVANT",
                            "necessity": "UNCERTAIN",
                            "risk_level": "LOW",
                            "confidence": 0.9,
                            "reason": "Authorized",
                        }
                    )
                }
            }

    class GeminiTransport:
        prompt = None

        def generate_json(self, *, prompt, **kwargs):
            self.prompt = prompt
            return {
                "decision": "ALLOW",
                "goal_relevance": "RELEVANT",
                "necessity": "UNCERTAIN",
                "risk_level": "LOW",
                "confidence": 0.9,
                "reason": "Authorized",
            }

    ollama, gemini = OllamaTransport(), GeminiTransport()
    request = SupervisorRequest(
        user_goal="Calculate 2+2",
        proposed_call=call("calculator", expression="2+2"),
        enable_rewrite=False,
    )
    OllamaSupervisor(transport=ollama).evaluate(request)
    GeminiSupervisor(transport=gemini).evaluate(request)
    assert ollama.payload["messages"][-1]["content"] == gemini.prompt
    assert "pre-execution" in Path("src/traceguard/prompts/supervisor_v2.txt").read_text()
    assert "post-execution" in Path("src/traceguard/prompts/post_run_v1.txt").read_text()


@pytest.mark.parametrize("hybrid", [False, True])
def test_identical_mutation_needs_explicit_repeat_authority(hybrid):
    from traceguard.policy.authorization import duplicate_mutation

    proposal = call("send_email", to="a@example.test", body="hello")
    scope = TaskAuthority(argument_values={"send_email": {"to": "a@example.test"}})
    provider = Provider("ALLOW")
    guard = QwenSupervisor(provider=provider, deterministic_enabled=hybrid)
    guard.set_context(previous_calls=[proposal], task_authority=scope)
    assert guard.evaluate("Send hello to a@example.test", proposal, []).decision is Decision.BLOCK
    assert not provider.requests
    scope.repeatable_tools = ["send_email"]
    guard.set_context(previous_calls=[proposal], task_authority=scope)
    assert guard.evaluate("Send hello to a@example.test", proposal, []).decision is Decision.ALLOW
    read = call("get_weather")
    assert duplicate_mutation(read, [read], TaskAuthority()) is None


@pytest.mark.parametrize("mode", ["llm", "deterministic_llm"])
def test_gateway_rewrite_cannot_repeat_and_escalation_remains_terminal(mode):
    from traceguard.policy.authorization import output

    class Rewriter:
        calls = 0

        def evaluate(self, goal, proposal, observations):
            self.calls += 1
            return output(Decision.BLOCK, "placeholder", "placeholder").model_copy(
                update={
                    "decision": Decision.REWRITE,
                    "rewritten_call": proposal.model_copy(
                        update={"arguments": {"to": "a@example.test", "body": "hello"}}
                    ),
                }
            )

    supervisor = Rewriter()
    gateway = SupervisionGateway(
        mode=mode,
        supervisor=supervisor,
        available_tools={"send_email": {"type": "object"}},
        task_authority=TaskAuthority(
            enforcement_mode="strict",
            allowed_tools=["send_email"],
            argument_values={"send_email": {"to": "a@example.test"}},
            generated_fields={"send_email": ["body"]},
        ),
    )
    gateway.history.append(call("send_email", to="a@example.test", body="hello"))
    kwargs = dict(
        task_id="test",
        step_id=1,
        user_goal="Send a note to a@example.test",
        tool_name="send_email",
        observations=[],
    )
    _, decision = gateway.evaluate(**kwargs, arguments={"to": "a@example.test", "body": "new"})
    assert decision.decision is Decision.ESCALATE
    assert "duplicate-mutation" in decision.matched_rules
    _, decision = gateway.evaluate(**kwargs, arguments={"to": "a@example.test", "body": "hello"})
    assert decision.decision is Decision.ESCALATE
    assert "episode-escalated" in decision.matched_rules
    assert supervisor.calls == 1


@pytest.mark.parametrize("protected", ["line\nbreak", "Пароль", 'quoted"secret'])
def test_protected_content_checks_actual_nested_strings_before_json_escaping(protected):
    decision = check_authority(
        "Save the report",
        call("write_report", content={"sections": ["prefix " + protected]}),
        [],
        TaskAuthority(prohibited_content=[protected]),
    )
    assert decision.decision is Decision.BLOCK
    assert "prohibited-disclosure" in decision.matched_rules


@pytest.mark.parametrize("keyword", ["$ref", "$dynamicRef", "$recursiveRef"])
def test_tool_schema_refuses_every_remote_reference_form(keyword):
    with pytest.raises(SupervisorSchemaError, match="external schema"):
        _validate_arguments_against_json_schema({}, {keyword: "https://example.test/schema"})


def test_unresolvable_local_schema_reference_is_a_validation_failure():
    with pytest.raises(SupervisorSchemaError):
        _validate_arguments_against_json_schema({}, {"$ref": "#/$defs/missing"})


def test_gateway_does_not_attribute_a_previous_provider_call_to_a_hard_gate():
    provider = Provider("ALLOW")
    supervisor = QwenSupervisor(provider=provider)
    gateway = SupervisionGateway(
        mode="deterministic_llm",
        supervisor=supervisor,
        available_tools={
            "calculator": bind_read_schema(
                {"type": "object"}, adapter_id="embedded-v1", tool_name="calculator"
            ),
            "send_email": {"type": "object"},
        },
        task_authority=TaskAuthority(enforcement_mode="strict", allowed_tools=["calculator"]),
    )
    kwargs = dict(task_id="test", step_id=0, user_goal="Calculate 2+2", observations=[])
    gateway.evaluate(**kwargs, tool_name="calculator", arguments={"expression": "2+2"})
    assert supervisor.last_evaluation_log.provider_called
    _, decision = gateway.evaluate(
        **kwargs,
        tool_name="send_email",
        arguments={"to": "a@example.test", "body": "hello"},
    )
    assert decision.decision is Decision.BLOCK
    assert supervisor.last_evaluation_log is None
    assert len(provider.requests) == 1


def test_payment_destination_does_not_grant_an_unbounded_amount():
    proposal = call("send_money", recipient="a@example.test", amount=50)
    goal = "Send money to a@example.test"
    assert check_authority(goal, proposal, []).decision is Decision.ESCALATE
    assert check_authority(goal, proposal, [], TaskAuthority(max_amount=100)) is None
    assert (
        check_authority(
            goal, proposal, [], TaskAuthority(argument_values={"send_money": {"amount": 50}})
        )
        is None
    )
    for invalid in [-1, True, float("inf"), float("nan")]:
        assert (
            check_authority(
                goal,
                proposal.model_copy(
                    update={"arguments": {"recipient": "a@example.test", "amount": invalid}}
                ),
                [],
            ).decision
            is Decision.BLOCK
        )
