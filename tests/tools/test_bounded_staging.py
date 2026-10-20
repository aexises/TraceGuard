import os

import pytest

from traceguard.policy.authorization import sensitive_path
from traceguard.tools.filesystem import CopyBudget, copy_confined


def copy(tmp_path, raw="public.txt", **limits):
    copy_confined(
        tmp_path / "workspace",
        raw,
        tmp_path / "staged" / raw,
        budget=CopyBudget(**limits),
        prohibited=sensitive_path,
    )


@pytest.mark.parametrize("nested", [False, True])
def test_staging_rejects_hardlink_alias_to_protected_file(tmp_path, nested):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    protected = workspace / "secrets.txt"
    protected.write_text("HARMLESS_CANARY")
    parent = workspace / "data" if nested else workspace
    parent.mkdir(exist_ok=True)
    os.link(protected, parent / "public.txt")
    with pytest.raises(ValueError, match="non-aliased"):
        copy(tmp_path, "data" if nested else "public.txt")


@pytest.mark.parametrize("kind", ["symlink", "fifo", "nested_secret"])
def test_staging_rejects_alias_special_and_protected_descendants(tmp_path, kind):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    raw = "public.txt"
    if kind == "symlink":
        (workspace / raw).symlink_to("/does-not-exist")
    elif kind == "fifo":
        os.mkfifo(workspace / raw)
    else:
        raw = "data"
        (workspace / raw).mkdir()
        (workspace / raw / "secrets.txt").write_text("HARMLESS_CANARY")
    with pytest.raises((OSError, ValueError)):
        copy(tmp_path, raw)


@pytest.mark.parametrize(
    "limits", [{"max_bytes": 2}, {"max_file_bytes": 2}, {"max_entries": 1}, {"max_depth": 1}]
)
def test_staging_limits_apply_during_traversal(tmp_path, limits):
    workspace = tmp_path / "workspace" / "data"
    workspace.mkdir(parents=True)
    (workspace / "public.txt").write_text("safe fixture")
    with pytest.raises(ValueError, match="limit"):
        copy(tmp_path, "data", **limits)


def test_staging_checks_time_and_uses_opened_object_after_name_replacement(tmp_path, monkeypatch):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "public.txt").write_text("original safe fixture")
    (workspace / "secrets.txt").write_text("HARMLESS_CANARY")
    real_read = os.read
    swapped = False

    def read(descriptor, count):
        nonlocal swapped
        if not swapped:
            swapped = True
            (workspace / "public.txt").rename(workspace / "old.txt")
            (workspace / "public.txt").symlink_to(workspace / "secrets.txt")
        return real_read(descriptor, count)

    monkeypatch.setattr(os, "read", read)
    with pytest.raises(ValueError, match="changed"):
        copy(tmp_path)
    assert (tmp_path / "staged" / "public.txt").read_text() == "original safe fixture"
    budget = CopyBudget(started=0)
    with pytest.raises(ValueError, match="time limit"):
        budget.check()
