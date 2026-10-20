import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import pytest

import traceguard.release_gate as module
from traceguard.control.models import ActionRequest
from traceguard.isolated import ReportAdapter
from traceguard.release_gate import (
    COMMIT_MANIFEST,
    AlreadyPublished,
    ArtifactStore,
    PublicationUnknown,
    ReleaseGate,
)


def prepared(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    (source / "report.txt").write_text("Approved harmless report")
    store = ArtifactStore(tmp_path / "store")
    identity = store.ingest(source, ["report.txt"], action_digest="a" * 64)
    return store, identity, ReleaseGate(frozenset({"artifact"}))


def test_original_mirror_failure_cannot_reject_already_published_bundle(tmp_path, monkeypatch):
    store, identity, gate = prepared(tmp_path)
    original = module.write_confined

    def fail(directory, raw, data):
        if directory == store.private / identity and raw == "manifest.json":
            raise OSError("injected mirror failure")
        return original(directory, raw, data)

    monkeypatch.setattr(module, "write_confined", fail)
    published = store.release(identity, gate, label="public")
    restarted = ArtifactStore(store.root)
    assert restarted.manifest(identity)["status"] == "released"
    assert restarted.committed(identity)["action_digest"] == "a" * 64
    with pytest.raises(AlreadyPublished):
        restarted.reject(identity)
    assert restarted.release(identity, gate, label="public") == published
    assert (
        json.loads((store.private / identity / "manifest.json").read_bytes())["status"]
        == "quarantined"
    )


@pytest.mark.parametrize(
    "point", ["content", "commit", "bundle-sync", "before-rename", "after-rename", "parent-sync"]
)
def test_fault_boundaries_never_expose_partial_staging_and_restart_is_truthful(
    tmp_path, monkeypatch, point
):
    store, identity, gate = prepared(tmp_path)
    write, rename, sync = module.write_confined, Path.rename, module._sync_directory

    def faulty_write(directory, raw, data):
        if (
            directory.name.startswith(".publication-")
            and raw == ("report.txt" if point == "content" else COMMIT_MANIFEST)
            and point in {"content", "commit"}
        ):
            assert not list(store.released.iterdir())
            raise OSError("injected write failure")
        return write(directory, raw, data)

    def faulty_rename(source, target):
        if source.name.startswith(".publication-") and point in {"before-rename", "after-rename"}:
            assert not list(store.released.iterdir())
            if point == "after-rename":
                rename(source, target)
            raise OSError("injected rename failure")
        return rename(source, target)

    def faulty_sync(directory):
        if (point == "bundle-sync" and directory.name.startswith(".publication-")) or (
            point == "parent-sync" and directory == store.released
        ):
            raise OSError("injected directory sync failure")
        return sync(directory)

    with monkeypatch.context() as patch:
        patch.setattr(module, "write_confined", faulty_write)
        patch.setattr(Path, "rename", faulty_rename)
        patch.setattr(module, "_sync_directory", faulty_sync)
        with pytest.raises((OSError, PublicationUnknown)):
            store.release(identity, gate, label="public")
    restarted = ArtifactStore(store.root)
    committed = point in {"after-rename", "parent-sync"}
    assert (restarted.manifest(identity)["status"] == "released") == committed
    assert not list(store.private.glob(".publication-*"))
    if committed:
        assert restarted.committed(identity)["files"]
        with pytest.raises(AlreadyPublished):
            restarted.reject(identity)
    destination = restarted.release(identity, gate, label="public")
    assert (destination / "report.txt").read_text() == "Approved harmless report"
    assert len(list(store.released.iterdir())) == 1


@pytest.mark.parametrize(
    "fault", ["missing-commit", "bad-commit", "changed-file", "extra-file", "lost-bundle"]
)
def test_corrupt_publication_never_falls_back_to_private_status(tmp_path, fault):
    store, identity, gate = prepared(tmp_path)
    destination = store.release(identity, gate, label="public")
    if fault == "missing-commit":
        (destination / COMMIT_MANIFEST).unlink()
    elif fault == "bad-commit":
        (destination / COMMIT_MANIFEST).write_text("[]")
    elif fault == "changed-file":
        (destination / "report.txt").write_text("altered")
    elif fault == "extra-file":
        (destination / "uncommitted.txt").write_text("uncommitted")
    else:
        destination.rename(store.private / "lost-bundle")
    with pytest.raises(PublicationUnknown):
        store.manifest(identity)
    with pytest.raises(PublicationUnknown):
        store.reject(identity)


def test_concurrent_release_and_reject_have_one_consistent_commit_point(tmp_path):
    store, identity, gate = prepared(tmp_path)
    instances = [ArtifactStore(store.root), ArtifactStore(store.root)]

    def release():
        try:
            instances[0].release(identity, gate, label="public")
        except PermissionError:
            pass

    def reject():
        try:
            instances[1].reject(identity)
        except AlreadyPublished:
            pass

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(release), pool.submit(reject)]
        for future in futures:
            future.result()
    manifest = store.manifest(identity)
    assert (manifest["status"] == "released") == (store.released / identity).exists()


def test_fenced_migration_quarantines_unverifiable_legacy_release(tmp_path):
    store, identity, _ = prepared(tmp_path)
    legacy = store.released / identity
    legacy.mkdir()
    (legacy / "report.txt").write_text("legacy publication without commit evidence")
    with pytest.raises(PublicationUnknown):
        store.manifest(identity)
    with pytest.raises(ValueError, match="fence"):
        store.quarantine_legacy_publications(workers_and_consumers_fenced=False)
    assert store.quarantine_legacy_publications(workers_and_consumers_fenced=True) == [identity]
    assert not list(store.released.iterdir())
    assert list(store.private.glob("legacy-publication-*/report.txt"))


def test_report_provider_reconciliation_uses_public_commit_after_private_mirror_loss(tmp_path):
    adapter = ReportAdapter(tmp_path / "state", ReleaseGate(frozenset({"artifact"})))
    action = ActionRequest(
        tenant_id="tenant",
        task_id="task",
        idempotency_key="fixture-key",
        kind="tool",
        operation="write_report",
        arguments={"path": "report.txt", "content": "approved"},
    )
    receipt = json.loads(adapter.dispatch(action))
    identity = receipt["artifact_id"]
    (adapter.store.private / identity / "manifest.json").unlink()
    recovered = adapter.reconcile({"digest": receipt["action_digest"]}, identity)
    assert recovered.status == "succeeded"
    assert json.loads(adapter.dispatch(action)) == receipt
