# Datalox with current veRL GRPO

The full lifecycle, isolation, failure, and ownership contract is in
[`docs/verl-grpo-rollouts.md`](../../docs/verl-grpo-rollouts.md).
The three checked information carriers are declared in
[`rollout-information-boundary.json`](rollout-information-boundary.json).

This integration keeps veRL's current V1 `ToolAgentLoop` workflow intact. Each
`rollout.n` sibling acquires one isolated Datalox lease for its complete
multi-turn loop. Provider-facing function tools submit argv to that lease; they
do not choose a task image, Datalox URL, proxy, MCP tool, reward, or verifier.

Why the extra task container: current veRL runs many `AgentLoop` coroutines in
the same Ray worker process. Process-wide DNS or environment mutation would mix
their provider state. Datalox therefore executes each provider call in the
lease's isolated Docker network while the model loop remains in the normal Ray
process.

Build the small consumer-owned dispatcher image:

```bash
docker build \
  -f integrations/verl/Dockerfile.task \
  -t datalox-verl-provider-call:example \
  integrations/verl
```

Create the ordered task-free provider set from already compiled provider
runtime bundles:

```bash
datalox-gate rollout provider-set \
  --bundle /opt/datalox/providers/provider-a \
  --bundle /opt/datalox/providers/provider-b \
  --out /opt/datalox/rollout-providers.json
```

Start one trusted pool per rollout node. The repeated `--task-image` option is
an exact allowlist; the model and function tool never receive it:

```bash
datalox-gate rollout pool-serve \
  --provider-set /opt/datalox/rollout-providers.json \
  --runtime-image datalox-gated-runtime:local \
  --task-image datalox-verl-provider-call:example \
  --capacity 64 \
  --artifacts-root /var/lib/datalox/rollouts \
  --socket /run/datalox/rollout-pool.sock
```

Mount the socket and its generated `.token` file into every veRL Ray node at
the same paths shown in `agent_loop.yaml`. Install Datalox in the veRL image so
the custom loop and `provider_tools.py` can import it. Then add the arguments in
`launch_fragment.sh` to the project's existing GRPO command.

The source dataset normally contains veRL's configured prompt column,
`agent_name`, and `extra_info`. `RLHFDataset` builds `raw_prompt`; V1 assigns the
runtime `uid`; and V1 expands `rollout.n` with `session_id=0..n-1`. The resulting
fields for sibling zero at `AgentLoopBase.run` look like
`agent_loop_rows.jsonl`. Every sibling keeps the same explicit
`extra_info.datalox.seed` but receives a different lease because its
`session_id` differs.

The dataset prompt contains only the task objective and constraints visible to
the agent before interaction. A model-selected function tool produces provider
observations during the loop. Evaluation ground truth remains in the
consumer-owned generator, oracle, reward, and verifier path and never enters
the prompt or tool result.

`provider_tools.py` is deliberately only an example tool. Replace its exact
provider URL and operation with the provider behavior pack your training task
uses. `provider_call.py` performs stdlib HTTPS against that unchanged URL from
inside the leased task container. Provider 4xx/5xx responses remain normal tool
observations. Transport failures and malformed dispatcher input fail loudly.

Datalox does not add a task, reward, verifier, or training recipe. veRL returns
the same `AgentLoopOutput` object produced by its own `ToolAgentLoop`; Datalox
only finalizes the provider-state evidence after that loop completes.
