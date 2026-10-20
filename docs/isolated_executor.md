# Isolated report executor profile

This integration separates a persistent issuer, credential/authority-holding executor and
untrusted agent into three non-root containers. The agent receives only its short-lived
client certificate and approved task. It has no issuer seed, issuer/executor state volume,
Docker socket, writable host root or direct output-store authority. All communication is
mutually authenticated TLS 1.3; services map exact verified leaf-certificate fingerprints
to application-owned Actor scopes. Identity is never read from a caller-supplied Actor or
proxy header. Clients verify CA/hostname and pin the server certificate before sending work.

The issuer supports only grant issue/validation. The executor supports only strict
`write_report`, checks exact deployed Python/effect-descriptor hashes against the approved
artifact, validates the grant online before and after durable reservation, and releases
only application-approved public text/JSON through quarantine. Provider receipts bind the
exact action digest; report-store reconciliation verifies actual released file hashes.
No arbitrary command, email, payment, model forwarding or generic provider API is exposed
by this narrow profile.

Run the full disposable deployment from the installed package/source checkout:

```bash
docker build \
  --build-arg PYTHON_IMAGE=python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4 \
  --tag traceguard:local .
python -m benchmarks.isolation_canary --image traceguard:local \
  --output artifacts/isolation-canary.json
```

The runner creates a private temporary fixture, disposable one-hour certificates and a
Docker internal bridge. Its temporary CA private key is never written or mounted. The
agent, issuer and executor mount separate directories; only the owning service can write
its state. Every container drops capabilities, has a read-only root, limited CPU/memory/
PIDs and bounded temporary storage. The build context allowlist excludes local secrets,
artifacts, VCS and environment files. Containers/network/fixture are removed on exit.

Conformance checks actual approved report publication, scope and grant tampering,
cross-role validation denial, replay without a second effect, issuer restart with persistent
authority, missing private state/keys/socket in the agent, denied direct filesystem writes,
the internal network setting and a blocked direct external TCP probe. Host loopback tests
also reject an unregistered CA-valid certificate, a missing client certificate, wrong
server pin, credential revocation and an unapproved adapter artifact. These are disposable
integration canaries, not two external application pilots or a model security benchmark.

For deployment, provision certificates and read-only peer registries from your own trusted
workload PKI; configure distinct identities and narrow tenant/operation scopes. Do not use
fixture author/approver identities as human governance. Initialize the private authority
once; mount its seed only into the issuer, and pin the matching execution public key and
adapter release in the executor. Keep state local to the documented SQLite profile and
use the same ledger for all workers sharing an authority. Follow `authority_storage.md`
for fenced recovery, revocation and offline key rotation. Removing a certificate pin
from the service registry prevents its next application request; TLS expiry and online
credential revocation provide additional checks. Enforce per-workload network/mount policy
and rerun conformance in the actual target platform before claiming this profile there.

An internal Docker bridge supplies a concrete constrained local integration, not a claim
that all host services or every network protocol were independently audited. Host/root/
Docker administration, workload PKI, immutable images and trusted source classification
remain trust roots. The current integration does not supply an external CA service, KMS,
distributed fencing, production network perimeter or third-party credential connectors.

References: [Python TLS verification](https://docs.python.org/3.11/library/ssl.html),
[Docker bridge isolation](https://docs.docker.com/engine/network/drivers/bridge/).
