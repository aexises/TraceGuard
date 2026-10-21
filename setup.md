# Install, validate and run TraceGuard

Start with the offline embedded integration. Add Docker, native Inspect or model
supervision only when your application needs that boundary. TraceGuard supplies
security controls; your application supplies the agent loop and approved tasks.

## 1. Install from the repository

Use Python 3.11+ and `uv==0.13.1`. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install uv==0.13.1
uv sync --locked --extra dev --no-install-project
uv sync --locked --extra dev --no-build-isolation --no-editable
traceguard smoke
```

The first sync installs locked build dependencies. The second builds and installs the
package without an isolated build environment. Keep both steps and the committed
`uv.lock`; do not replace them with unbounded dependency upgrades.

Expected smoke output:

```json
{"authorized_result": "84", "strict": true}
```

This check uses disposable files and no model or external provider. Continue with the
[read example](README.md#try-it-locally) and [application integration](docs/integration.md).
No PyPI installation or supported release is assumed by these instructions.

### Optional dependencies and provider configuration

| Extra | Purpose | Installation |
| --- | --- | --- |
| `inspect` | Native Inspect tool integration | Add `--extra inspect` to both sync commands |
| `gemini` | Google provider SDK and OpenAI-compatible transport dependencies | Add `--extra gemini` to both sync commands |

Use `.env.example` as the list of environment settings; set values in your process or
approved secret loader. Do not assume the package loads that file automatically.
Ollama supervision uses its configured local HTTP endpoint. Optional model supervision
still requires strict authority and explicit model-input release permission.
Keep credentials out of source, artifacts and logs. Offline checks do not need them.

## 2. Connect your application

Create `SecuredTools` with a fixed application-approved task ID and an explicit
`TaskAuthority`. Expose only its guarded execution route to the agent.

Before enabling consequential actions, provision a private `ExecutionLedger` once through
trusted administration. Persist its identity in protected application configuration and
reuse the same store across workers and restarts. Do not provision during requests or
recreate missing state. Follow [ledger operations](docs/ledger_lifecycle.md) for recovery.

Choose [Inspect](docs/inspect_execution.md) for explicit native solver integration or the
[isolated executor](docs/isolated_executor.md) when the agent must not share the executor's
credentials and state. Embedded callbacks and host application code remain trusted.

## 3. Run engineering checks

With the locked development environment active:

```bash
ruff check .
ruff format --check .
python -m pytest -q
python -m build --no-isolation
```

Docker cases are opt-in; a default pytest run does not execute them. To validate the
installed wheel, use a fresh temporary environment and run outside the checkout:

```bash
CHECKOUT="$PWD"
WHEEL_CHECK="$(mktemp -d)"
python -m venv "$WHEEL_CHECK/venv"
"$WHEEL_CHECK/venv/bin/python" -m pip install "$CHECKOUT"/dist/*.whl
(
  cd "$WHEEL_CHECK"
  "$WHEEL_CHECK/venv/bin/traceguard" smoke
  "$WHEEL_CHECK/venv/bin/python" -c 'from traceguard.sandbox.config import default_sandbox_configuration_path, load_sandbox_configuration; load_sandbox_configuration(default_sandbox_configuration_path())'
)
```

Use a `dist/` containing only the candidate wheel. This isolates the source checkout;
the wheel command may resolve dependencies from the configured package index. Candidate
supply-chain scans separately use locked, hashed dependency exports.

## 4. Validate container boundaries

Start Docker and pull the immutable base used by the sandbox configuration:

```bash
export PYTHON_IMAGE='python@sha256:25976e9d34a0fab1f278cae931f34c8303d97bf0c0d7f85b6b4dcf641d7702a4'
docker pull "$PYTHON_IMAGE"
traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
```

Build from the candidate checkout and run the disposable three-container report probe:

```bash
docker build --build-arg PYTHON_IMAGE="$PYTHON_IMAGE" --tag traceguard:local .
python -m traceguard.validation.isolation_canary \
  --image traceguard:local --output artifacts/isolation.json
```

The adapter hash must match the approved source. Rebuild after governed adapter changes;
do not disable that check to reuse an older image. The probe checks real container
separation and harmless report effects, not a real customer deployment or provider pilot.
See [isolated executor operations](docs/isolated_executor.md) for its exact scope.

## 5. Run a local control-plane service

The bundled application deliberately uses in-memory state and a development token
resolver. For a disposable localhost service, generate dedicated credentials in the
process environment and bind explicitly to loopback:

```bash
export TRACEGUARD_ALLOW_IN_MEMORY=1
export TRACEGUARD_SIGNING_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TRACEGUARD_DEV_TOKEN="$(python -c 'import secrets; print(secrets.token_hex(32))')"
export TRACEGUARD_DEV_TENANT=tenant-a
python -m uvicorn traceguard.control.api:_development_app \
  --factory --host 127.0.0.1 --port 8080 --workers 1
```

In another terminal, `curl --fail http://127.0.0.1:8080/healthz` checks process health.
No policy is active initially, so action requests fail closed. The agent token cannot
administer policies. Restart loses this service's state; use an application factory
with `SQLiteControlPlane` for the bounded durable single-host profile.

`traceguard-api` starts the same development factory on **all interfaces**, port 8080.
Do not expose it without an appropriate network boundary. The supplied Kubernetes
template also uses a single-replica development profile, not production identity or
shared distributed state. See [control-plane deployment](docs/control_plane.md).

## 6. Prepare a release candidate

Generate fresh advisory, secret-scan and SBOM artifacts for the candidate:

```bash
python -m traceguard.validation.release_checks --output artifacts/security
python -m traceguard.validation.release_assurance --digest-only
python -m traceguard.validation.release_assurance
```

Scans require network access and complete fetched Git history. The final assurance
command is expected to fail until authentic external evidence and license approval
exist. Preserve that gate. [Verification](docs/verification.md) explains what each
check establishes; [release assurance](docs/release_assurance.md) lists promotion criteria.
