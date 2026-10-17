# Quarantine and data release

The supported sandbox output profile uses Docker tmpfs with kernel-enforced byte and
inode limits. It never gives untrusted code a writable output bind mount on the host.
A detached bounded-lifetime container keeps tmpfs mounted while the command runs through
`docker exec` and a `python -I` exporter reads regular non-aliased files. Both exporter
and host enforce traversal/depth/count/byte budgets; collection failure withholds artifacts.
The host always removes the container and all remaining children. Inputs use the separate
descriptor-relative bounded copier. Profiles with unsupported runtime controls fail closed.

`ArtifactStore` ingests accepted bytes into a private `quarantine/` directory and records
file hashes. Post-run BLOCK_RESULT rejects the bundle. ACCEPT_RESULT does not publish it.
An application-owned `ReleaseGate` must authorize its label and `artifact` sink; release
rechecks every hash and file, then atomically publishes into `released/`. Rejection and
release serialize with a private file lock. Consumers must mount/serve only `released/`;
they must not receive the quarantine directory or the executor's OS credentials.

The default supported formats are UTF-8 `.txt` and `.json`, served as inert data. Other
formats require explicit application approval and an appropriate consumer. Release gates
bound bytes, reject recognized structured credentials and explicitly declared protected
literals, and deny undeclared sinks or classifications. Labels must be assigned by trusted
application/source policy, never accepted from model output. This is a narrow classification
and release contract, not automatic semantic secret detection, causal taint tracking,
arbitrary binary scanning or a guarantee against encoded/covert disclosure.

`GuardedProvider` checks the complete serialized request before any model-provider call,
including post-run evaluation. `SecuredTools` wraps known supervisor providers with this
guard and defaults to no external release permission. Set `release_gate` and a trusted
`model_input_label` explicitly when a model provider is allowed to receive those data.
`release_answer` checks the independent `final_answer` sink; tool execution permission
does not grant permission to publish its result.

Example application-owned policy:

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
