import os
from unittest.mock import patch

import pytest

from traceguard.policy.engine import DeterministicPolicy, load_default_policy
from traceguard.runtime import TraceGuardRuntime
from traceguard.tools.filesystem import read_confined, write_confined
from traceguard.tools.registry import default_registry
from traceguard.types import SafeguardConfig, TaskAuthority, ToolCall


@pytest.mark.parametrize("alias", ["symlink", "hardlink", "parent"])
def test_reads_cannot_alias_other_objects(tmp_path, alias):
    source = tmp_path / "protected.txt"
    source.write_text("CANARY")
    if alias == "symlink":
        (tmp_path / "public.txt").symlink_to(source)
        path = "public.txt"
    elif alias == "hardlink":
        os.link(source, tmp_path / "public.txt")
        path = "public.txt"
    else:
        (tmp_path / "linked").symlink_to(tmp_path, target_is_directory=True)
        path = "linked/protected.txt"
    with pytest.raises(ValueError):
        read_confined(tmp_path, path, max_bytes=128)


def test_swap_after_parent_open_cannot_follow_symlink(tmp_path):
    (tmp_path / "public.txt").write_text("public")
    (tmp_path / "protected.txt").write_text("CANARY")
    original = os.open

    def swapped(name, flags, *args, **kwargs):
        if name == "public.txt":
            (tmp_path / name).unlink()
            (tmp_path / name).symlink_to(tmp_path / "protected.txt")
        return original(name, flags, *args, **kwargs)

    # Keep the capability test valid when os.open is replaced by a wrapper.
    with (
        patch("traceguard.tools.filesystem.os.open", swapped),
        patch("traceguard.tools.filesystem.os.supports_dir_fd", {swapped}),
    ):
        with pytest.raises(ValueError):
            read_confined(tmp_path, "public.txt", max_bytes=128)


def test_write_rejects_links_and_atomic_replacement_preserves_utility(tmp_path):
    (tmp_path / "protected.txt").write_text("CANARY")
    (tmp_path / "report.txt").symlink_to(tmp_path / "protected.txt")
    with pytest.raises(ValueError):
        write_confined(tmp_path, "report.txt", b"changed")
    assert (tmp_path / "protected.txt").read_text() == "CANARY"
    write_confined(tmp_path, "nested/report.txt", b"approved")
    assert read_confined(tmp_path, "nested/report.txt", max_bytes=128) == b"approved"


def test_two_runtimes_do_not_share_authority_or_caller_mutations(tmp_path):
    shared = DeterministicPolicy(load_default_policy())
    scope = TaskAuthority(allowed_tools=[])
    tools = default_registry(tmp_path, tmp_path / "artifacts")
    first = TraceGuardRuntime(
        tools, SafeguardConfig(deterministic_policy=True), policy=shared, task_authority=scope
    )
    TraceGuardRuntime(
        tools,
        SafeguardConfig(deterministic_policy=True),
        policy=shared,
        task_authority=TaskAuthority(allowed_tools=["write_report"]),
    )
    scope.allowed_tools.append("write_report")
    result = first.execute_call(
        "Write a report",
        ToolCall(
            task_id="t",
            step_id=0,
            tool_name="write_report",
            arguments={"path": "artifacts/report.txt", "content": "CANARY"},
        ),
        [],
    )
    assert result.trace.episode_outcome == "BLOCK"
    assert not (tmp_path / "artifacts/report.txt").exists()
