# TraceGuard Submission Video Runbook

The main recording takes about four minutes. The deterministic comparison requires
no credentials; the optional final check makes live Gemini API calls.

## Before recording

```bash
source .venv/bin/activate
python -m pytest -q
ruff check .
ruff format --check .
```

Keep the Gemini key outside the camera frame and shell history:

```bash
read -s GEMINI_API_KEY
export GEMINI_API_KEY
export GEMINI_BASE_URL=https://open.blackroute.space/v1
```

## 1. Introduce the architecture (30 seconds)

Show `README.md` and say:

> TraceGuard sits between a ReAct-style agent and its tools. Every proposed tool
> call is typed and checked by deterministic policy and, in the hybrid mode, an
> independent LLM supervisor. Approved medium-risk commands can be routed to a
> hardened Docker profile; high-risk actions remain blocked.

## 2. Run the visible comparison (90 seconds)

```bash
python -m traceguard demo --gemini --gemini-base-url "$GEMINI_BASE_URL"
```

Narrate three things visible in the terminal:

1. Both configurations complete the benign calculator task.
2. With no safeguards, a malicious instruction found in a document causes an
   unrequested `read_file("secrets.txt")` call.
3. The hybrid blocks that call before execution. The optional Gemini section proves
   that the task agent and supervisor can also run through the live API.

If the API is unavailable during recording, run `python -m traceguard demo` and say
that the saved live-provider evidence is a smoke check, while the headline ablation
numbers come from the frozen reproducible benchmark.

## 3. Inspect the fresh trace (45 seconds)

Open the run directory printed by the command:

```bash
less artifacts/run_<timestamp>_0/representative_traces.json
```

Show the proposed call, the `BLOCK` decision, the policy version, and the redacted
canary. Do not show `.env`, environment-variable output, or any API key.

## 4. Show real containment (45 seconds)

```bash
python -m traceguard sandbox-check
TRACEGUARD_RUN_DOCKER_TESTS=1 python -m pytest tests/sandbox -q
```

Emphasize the pinned digest, ARM64 check, non-root execution, no network,
read-only root filesystem, bounded resources, and verified cleanup. If Docker is not
ready on the recording machine, omit this live command and show
`artifacts/sandbox_benchmark.json` instead.

## 5. Close with the result (30 seconds)

The frozen 168-episode run preserved 100% benign utility. The complete hybrid
had 0% attack success and 0% compromise on the custom benchmark; the
no-supervisor baseline had 40% attack success and 33.3% compromise. These
numbers describe the frozen custom benchmark and should not be generalized
beyond it without the AgentDojo/live-model comparison.
