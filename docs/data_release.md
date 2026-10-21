# Data release and artifact publication

Execution authority and permission to disclose data are separate decisions. Configure
allowed sinks and trusted classifications for artifacts, model-provider inputs and final
answers. Tool success alone does not authorize any of those releases.

## Collect container output into quarantine

The supported sandbox output profile uses Docker tmpfs with kernel-enforced byte and
inode limits. It never gives untrusted code a writable output bind mount on the host.
A detached bounded-lifetime container keeps tmpfs mounted while the command runs through
`docker exec` and a `python -I` exporter reads regular non-aliased files. Both exporter
and host enforce traversal/depth/count/byte budgets; collection failure withholds artifacts.
The host always removes the container and all remaining children. Inputs use the separate
descriptor-relative bounded copier. Profiles with unsupported runtime controls fail closed.

## Publish a complete authorized bundle

`ArtifactStore` ingests accepted bytes into a private `quarantine/` directory and records
file hashes. Post-run BLOCK_RESULT rejects the bundle. ACCEPT_RESULT does not publish it.
An application-owned `ReleaseGate` must authorize its label and `artifact` sink; release
rechecks every hash and file, then prepares files and `.traceguard-commit.json` together
under private quarantine. It flushes the files/directories, publishes the complete bundle
with one same-filesystem directory rename under the shared publisher lock, and flushes
both parent directories before acknowledging durability. The supported profile requires
POSIX local-filesystem rename/flock/fsync semantics and cooperating publishers; separate
network filesystems, replicated stores and privileged host mutation are not covered.

The public commit manifest is authoritative and binds identity, action digest when present,
file hashes, label, sink and a digest of trusted release policy. The private manifest is a
recoverable mirror. If updating the mirror fails after a durable publication, release
returns the committed bundle; `manifest` reconstructs public truth. A failed directory
flush/uncertain rename raises `PublicationUnknown`. Retry verifies the same committed
bundle and syncs parents without redispatch. Reconciliation uses verified public commits
and hashes, including after private mirror loss. Rejection after publication raises
`AlreadyPublished`; withdrawal needs a separate authorization and is not implemented.

## Verify before serving files

Consumers must use `ArtifactStore.committed` to verify the complete file set and hashes
before serving listed files; never enumerate and serve arbitrary release-directory bytes
or expose the commit manifest as user content. Missing/corrupt commits and changed or
extra files withhold consumption. Consumers must not receive quarantine or executor OS
credentials. Only read-only consumers may access committed bundles; handler code and
filesystem ownership remain trusted. The commit filename is reserved during ingestion.

## Migrate legacy publications

Fence publishers and consumers together before upgrading. Call
`quarantine_legacy_publications(workers_and_consumers_fenced=True)` to preserve unverifiable
legacy release directories in private `legacy-publication-*` folders. These may contain
previously exposed bytes; moving them cannot undo disclosure. Inspect and obtain new
release approval rather than inventing old commit evidence. Upgrade consumer visibility
rules before resuming service. A private mirror claiming release without a public commit
is an uncertain state, not proof that nothing was published. No automatic downgrade is supported.

## Classifications, formats and limits

The default supported formats are UTF-8 `.txt` and `.json`, served as inert data. Other
formats require explicit application approval and an appropriate consumer. Release gates
bound bytes, reject recognized structured credentials and explicitly declared protected
literals, and deny undeclared sinks or classifications. Labels must be assigned by trusted
application/source policy, never accepted from model output. This is a narrow classification
and release contract, not automatic semantic secret detection, causal taint tracking,
arbitrary binary scanning or a guarantee against encoded/covert disclosure.

## Gate model inputs and final answers

`GuardedProvider` checks the complete serialized request before any model-provider call,
including post-run evaluation. `SecuredTools` wraps known supervisor providers with this
guard and defaults to no external release permission. Set `release_gate` and a trusted
`model_input_label` explicitly when a model provider is allowed to receive those data.
`release_answer` checks the independent `final_answer` sink; tool execution permission
does not grant permission to publish its result.

## Configure release policy

The following fragment assumes an existing `ArtifactStore` and quarantined `artifact_id`.
The application must approve classification before invoking it:

```python
from traceguard.release_gate import ReleaseGate

gate = ReleaseGate(
    allowed_sinks=frozenset({"artifact", "final_answer"}),
    allowed_labels=frozenset({"public"}),
    prohibited_literals=("application-owned-private-canary",),
)
# After trusted approval/classification, not a model-selected label:
published = store.release(artifact_id, gate, label="public")
answer = gate.authorize("final_answer", b"Approved public answer", label="public")
```

Do not automatically classify all generated content as public. Real applications must
define classifications, origin authentication and allowed sink relationships, then test
credential and protected-data canaries through their actual consumers and model providers.
