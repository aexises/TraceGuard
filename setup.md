# Setup and operations

TraceGuard supplies a security boundary around application-owned agents. It does not
supply an agent planner or conversation loop. The application must expose only approved
execution routes and prevent direct access to the protected handlers and credentials.

## Locked installation

Use Python 3.11 or newer and the committed `uv.lock`:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.13.1
uv sync --locked --extra dev --no-install-project
uv sync --locked --extra dev --no-build-isolation --no-editable
traceguard smoke
```

Optional extras are `gemini` for the Google provider SDK and `inspect` for native Inspect
integration. Add `--extra gemini` or `--extra inspect` to both sync commands when needed.
The Ollama transport uses its configured local HTTP endpoint. Load provider configuration
from the environment using `.env.example`; do not commit credentials or call paid models
as part of offline checks. Provider data release needs explicit application approval.

## Application and state configuration

Use `SecuredTools` with an application-approved task ID and `TaskAuthority`. Its explicit
allowlist and field/resource scope are mandatory; user prose is not executable permission.
Consequential tools require a private `ExecutionLedger`, provisioned once through trusted
administration. Store its returned identity in trusted configuration and reuse the same
ledger/domain across workers and restarts. Follow [ledger lifecycle](docs/ledger_lifecycle.md)
for backups, missing state, migration and recovery. Uncertain effects hold the task until
fenced, provider-verified reconciliation; changing a call ID or payload cannot clear a hold.

For native framework integration use [the Inspect execution route](docs/inspect_execution.md).
For a separately isolated agent use [the report executor](docs/isolated_executor.md).
Embedded application code and callbacks remain trusted.

## Verification

```bash
ruff check .
ruff format --check .
python -m pytest -q
python -m build --no-isolation
python -m traceguard.validation.release_checks --output artifacts/security
```

For live, harmless container tests, first pull the pinned image:

```bash
docker pull python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4
traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
```

Build a source-matching image before running the isolated probe. The executor rejects
an image whose installed adapter differs from the approved code:

```bash
docker build --build-arg PYTHON_IMAGE=python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4 --tag traceguard:local .
python -m traceguard.validation.isolation_canary --image traceguard:local --output artifacts/isolation.json
```

Run installed-wheel CLI/resource checks outside the source checkout. Keep fresh scan,
build and conformance evidence bound to the exact candidate. See
[verification](docs/verification.md) and [release assurance](docs/release_assurance.md).

## Control-plane deployment

`traceguard-api` exposes the control-plane HTTP boundary. In-memory development startup
requires `TRACEGUARD_ALLOW_IN_MEMORY=1`, a dedicated `TRACEGUARD_SIGNING_KEY` and
`TRACEGUARD_DEV_TOKEN`; never substitute development identity for a production integration.
The Kubernetes template is a single-replica development profile, with immutable image
references, read-only root and dropped capabilities. It does not supply production
identity, KMS, distributed fencing or replica-safe shared state.

Use `traceguard release-validate --base-image "$PYTHON_IMAGE" --release-image "$TRACEGUARD_IMAGE"`
to validate references. Add `--output-manifest artifacts/control-plane.yaml` to render a new
manifest. Registry existence/provenance, Kubernetes schema and target-host conformance
remain separate checks in [the control-plane guide](docs/control_plane.md).
