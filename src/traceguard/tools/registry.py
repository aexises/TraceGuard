"""Typed tools with narrow, testable side-effect boundaries.

Each tool declares side effects, risk class, trusted inputs, and output trust so
deterministic policy and supervisors can reason about calls without guessing.
"""

from __future__ import annotations

import ast
import json
import operator
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path, PurePath
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from traceguard.policy.authorization import sensitive_path
from traceguard.policy.read_resources import bind_read_schema
from traceguard.tools.filesystem import read_confined, write_confined
from traceguard.types import Observation, RiskLevel, ToolCall, TrustLabel

MAX_READ_BYTES = 262_144  # 256 KiB
MAX_WRITE_BYTES = 1_000_000
MAX_CALC_ABS_VALUE = 1e12
MAX_CALC_POW_EXPONENT = 8
MAX_CALC_NODES = 64


RiskClass = Literal["read", "write", "compute", "command"]


@dataclass(frozen=True)
class ToolSpec:
    """Static documentation and risk metadata for a registered tool."""

    name: str
    side_effects: str
    risk_class: RiskClass
    default_risk: RiskLevel
    trusted_inputs: str
    trusted_output: TrustLabel
    host_execution: bool
    notes: str = ""


class ToolArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SearchDocumentsArguments(ToolArguments):
    query: str = Field(min_length=1, max_length=500)


class ReadFileArguments(ToolArguments):
    path: str = Field(min_length=1, max_length=512)


class CalculatorArguments(ToolArguments):
    expression: str = Field(min_length=1, max_length=200)


class WriteReportArguments(ToolArguments):
    path: str = Field(min_length=1, max_length=512)
    content: str = Field(max_length=MAX_WRITE_BYTES)


class RestrictedCommandArguments(ToolArguments):
    command: list[str] = Field(min_length=1, max_length=64)


class ToolDefinition:
    def __init__(
        self,
        name: str,
        arguments_model: type[ToolArguments],
        handler: Callable[[ToolArguments], str],
        trust: TrustLabel,
        spec: ToolSpec,
        *,
        read_adapter_id: str | None = None,
    ) -> None:
        self.name = name
        self.arguments_model = arguments_model
        self.handler = handler
        self.trust = trust
        self.spec = spec
        self.read_adapter_id = read_adapter_id

    def validate(self, arguments: dict[str, Any]) -> ToolArguments:
        return self.arguments_model.model_validate(arguments)


class ToolRegistry:
    def __init__(self) -> None:
        self._tools: dict[str, ToolDefinition] = {}

    def register(self, tool: ToolDefinition) -> None:
        if tool.name in self._tools:
            raise ValueError(f"tool already registered: {tool.name}")
        self._tools[tool.name] = tool

    def get(self, name: str) -> ToolDefinition:
        try:
            return self._tools[name]
        except KeyError as exc:
            raise KeyError(f"unknown tool: {name}") from exc

    def schemas(self) -> dict[str, dict[str, Any]]:
        return {
            name: (
                bind_read_schema(
                    tool.arguments_model.model_json_schema(),
                    adapter_id=tool.read_adapter_id,
                    tool_name=name,
                )
                if tool.read_adapter_id is not None
                else tool.arguments_model.model_json_schema()
            )
            for name, tool in self._tools.items()
        }

    def catalog(self) -> dict[str, ToolSpec]:
        return {name: tool.spec for name, tool in self._tools.items()}

    def restricted_to(self, names: list[str]) -> ToolRegistry:
        """Return a registry exposing exactly an application-selected tool set."""
        requested = set(names)
        unknown = requested - set(self._tools)
        if unknown:
            raise ValueError(f"tool set includes unknown tools: {sorted(unknown)}")
        restricted = ToolRegistry()
        for name in names:
            restricted.register(self._tools[name])
        return restricted

    def execute(self, call: ToolCall) -> Observation:
        tool = self.get(call.tool_name)
        args = tool.validate(call.arguments)
        content = tool.handler(args)
        return Observation(
            content=content,
            source_type="tool",
            source_id=call.call_id,
            trust=tool.trust,
            provenance_chain=[*call.consumed_observation_ids, call.call_id],
            may_contain_instructions=tool.trust
            in {
                TrustLabel.UNTRUSTED_DOCUMENT,
                TrustLabel.UNTRUSTED_TOOL,
            },
        )


_OPERATORS: dict[type[ast.AST], Callable[..., float]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}


def _calculate(node: ast.AST, *, budget: list[int] | None = None) -> float:
    if budget is None:
        budget = [MAX_CALC_NODES]
    budget[0] -= 1
    if budget[0] < 0:
        raise ValueError("calculator expression too complex")

    if isinstance(node, ast.Expression):
        return _calculate(node.body, budget=budget)
    if (
        isinstance(node, ast.Constant)
        and isinstance(node.value, (int, float))
        and not isinstance(node.value, bool)
    ):
        value = float(node.value)
        if abs(value) > MAX_CALC_ABS_VALUE:
            raise ValueError("calculator literal out of bounds")
        return value
    if isinstance(node, ast.BinOp) and type(node.op) in _OPERATORS:
        left = _calculate(node.left, budget=budget)
        right = _calculate(node.right, budget=budget)
        if isinstance(node.op, ast.Pow):
            if abs(right) > MAX_CALC_POW_EXPONENT or abs(left) > 1_000:
                raise ValueError("exponentiation exceeds safety limits")
        result = _OPERATORS[type(node.op)](left, right)
        if abs(result) > MAX_CALC_ABS_VALUE:
            raise ValueError("calculator result out of bounds")
        return float(result)
    if isinstance(node, ast.UnaryOp) and type(node.op) in _OPERATORS:
        return _OPERATORS[type(node.op)](_calculate(node.operand, budget=budget))
    if isinstance(
        node, (ast.Name, ast.Attribute, ast.Call, ast.Subscript, ast.List, ast.Dict, ast.Tuple)
    ):
        raise ValueError("names, calls, and compound literals are not allowed")
    raise ValueError("unsupported calculator expression")


def evaluate_expression(expression: str) -> float:
    """Parse and evaluate a calculator expression with safety limits."""
    return _calculate(ast.parse(expression, mode="eval"))


def _load_document_corpus(workspace: Path) -> list[dict[str, str]]:
    """Load fixture-backed documents from workspace/documents/ when present."""
    docs_dir = workspace / "documents"
    if docs_dir.is_symlink():
        raise ValueError("symbolic-link document corpus is not allowed")
    if not docs_dir.is_dir():
        return []
    documents: list[dict[str, str]] = []
    for path in sorted(docs_dir.rglob("*")):
        if path.is_symlink():
            raise ValueError("symbolic links are not allowed in the document corpus")
        if not path.is_file():
            continue
        resolved = path.resolve()
        if docs_dir.resolve() not in resolved.parents:
            raise ValueError("document path escapes corpus root")
        relative = path.relative_to(workspace).as_posix()
        if sensitive_path(relative):
            raise ValueError("protected object in document corpus")
        text = read_confined(workspace, relative, max_bytes=MAX_READ_BYTES).decode("utf-8")
        documents.append({"path": relative, "text": text})
    return documents


def default_registry(workspace: Path, artifacts: Path) -> ToolRegistry:
    workspace = workspace.resolve()
    artifacts = artifacts.resolve()

    def search_documents(args: ToolArguments) -> str:
        assert isinstance(args, SearchDocumentsArguments)
        query = args.query.casefold()
        corpus = _load_document_corpus(workspace)
        matches = [doc for doc in corpus if query in doc["text"].casefold()]
        return json.dumps(
            {
                "query": args.query,
                "source": "workspace_fixtures",
                "matches": matches,
            }
        )

    def read_file(args: ToolArguments) -> str:
        assert isinstance(args, ReadFileArguments)
        try:
            return read_confined(workspace, args.path, max_bytes=MAX_READ_BYTES).decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ValueError("file is not valid UTF-8") from exc

    def calculator(args: ToolArguments) -> str:
        assert isinstance(args, CalculatorArguments)
        result = evaluate_expression(args.expression)
        return str(int(result) if result.is_integer() else result)

    def write_report(args: ToolArguments) -> str:
        assert isinstance(args, WriteReportArguments)
        encoded = args.content.encode("utf-8")
        if len(encoded) > MAX_WRITE_BYTES:
            raise ValueError(f"report exceeds write limit of {MAX_WRITE_BYTES} bytes")
        parts = PurePath(args.path).parts
        relative_path = str(Path(*parts[1:])) if parts and parts[0] == "artifacts" else args.path
        write_confined(artifacts, relative_path, encoded)
        return relative_path

    def restricted_command(args: ToolArguments) -> str:
        assert isinstance(args, RestrictedCommandArguments)
        # Never invokes a host shell. Runtime may replace this with an approved container plan.
        return json.dumps(
            {
                "status": "simulated",
                "marker": "TRACEGUARD_REQUIRES_EXECUTION_PLAN",
                "command": args.command,
                "host_execution": False,
            }
        )

    registry = ToolRegistry()
    registry.register(
        ToolDefinition(
            "search_documents",
            SearchDocumentsArguments,
            search_documents,
            TrustLabel.UNTRUSTED_DOCUMENT,
            ToolSpec(
                name="search_documents",
                side_effects=("Read-only search over fixture files under workspace/documents."),
                risk_class="read",
                default_risk=RiskLevel.LOW,
                trusted_inputs=("User query string and fixture files under workspace/documents."),
                trusted_output=TrustLabel.UNTRUSTED_DOCUMENT,
                host_execution=False,
                notes="Matches are untrusted and may embed indirect instructions.",
            ),
            read_adapter_id="embedded-v1",
        )
    )
    registry.register(
        ToolDefinition(
            "read_file",
            ReadFileArguments,
            read_file,
            TrustLabel.UNTRUSTED_DOCUMENT,
            ToolSpec(
                name="read_file",
                side_effects="Reads a UTF-8 text file under the workspace root; no writes.",
                risk_class="read",
                default_risk=RiskLevel.MEDIUM,
                trusted_inputs="Relative path within workspace (enforced by containment).",
                trusted_output=TrustLabel.UNTRUSTED_DOCUMENT,
                host_execution=False,
                notes=f"Hard-capped at {MAX_READ_BYTES} bytes; UTF-8 only.",
            ),
            read_adapter_id="embedded-v1",
        )
    )
    registry.register(
        ToolDefinition(
            "calculator",
            CalculatorArguments,
            calculator,
            TrustLabel.TRUSTED_TOOL,
            ToolSpec(
                name="calculator",
                side_effects="Pure arithmetic evaluation; no filesystem or network access.",
                risk_class="compute",
                default_risk=RiskLevel.LOW,
                trusted_inputs="Numeric AST expression without names, calls, or attributes.",
                trusted_output=TrustLabel.TRUSTED_TOOL,
                host_execution=False,
                notes="Rejects exponent/resource abuse and non-literal expressions.",
            ),
            read_adapter_id="embedded-v1",
        )
    )
    registry.register(
        ToolDefinition(
            "write_report",
            WriteReportArguments,
            write_report,
            TrustLabel.TRUSTED_TOOL,
            ToolSpec(
                name="write_report",
                side_effects="Creates or overwrites a report file under the artifacts root.",
                risk_class="write",
                default_risk=RiskLevel.MEDIUM,
                trusted_inputs="Relative path under artifacts and UTF-8 report content.",
                trusted_output=TrustLabel.TRUSTED_TOOL,
                host_execution=False,
                notes=f"Hard-capped at {MAX_WRITE_BYTES} UTF-8 bytes.",
            ),
        )
    )
    registry.register(
        ToolDefinition(
            "restricted_command",
            RestrictedCommandArguments,
            restricted_command,
            TrustLabel.UNTRUSTED_TOOL,
            ToolSpec(
                name="restricted_command",
                side_effects=(
                    "Returns a simulated execution marker only. Never runs a host shell; "
                    "container execution requires an approved runtime plan."
                ),
                risk_class="command",
                default_risk=RiskLevel.HIGH,
                trusted_inputs="Argv list without shell operators (policy-enforced).",
                trusted_output=TrustLabel.UNTRUSTED_TOOL,
                host_execution=False,
                notes="Host execution is forbidden by construction in the tool handler.",
            ),
        )
    )
    return registry
