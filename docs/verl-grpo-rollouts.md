# veRL and GRPO Rollouts

Datalox can supply isolated, resettable provider behavior to veRL without
becoming the task environment or changing the training algorithm.

This integration follows the repository-wide
[`rollout information boundary`](rollout-information-boundary.md). Dataset
prompts carry only task objectives and agent-visible constraints. Provider
responses and environment anomalies enter as function-tool results after the
model selects an operation. Evaluation ground truth remains in the consumer's
trusted task generator, oracle, reward, and verifier path.

The integration follows veRL's current V1 workflow:

```text
dataset prompt
  -> veRL creates one uid
  -> rollout.n creates session_id = 0..n-1
  -> DataloxToolAgentLoop acquires one provider-state lease per sibling
  -> veRL's normal ToolAgentLoop generates tokens and invokes function tools
  -> provider-facing tool code calls the exact provider HTTPS URL inside the lease
  -> Datalox finalizes provider state and execution evidence
  -> veRL receives its original AgentLoopOutput object unchanged
  -> veRL computes user-owned reward and GRPO advantages normally
```

This adapter was checked against the V1 `AgentLoopBase.run(sampling_params,
**dataset_fields)` and `ToolAgentLoop` contracts in veRL commit
`5439c8e0ba17029bc4e647086a9b4cbe7ef21409`.

## Why provider calls run in a small task container

Current veRL workers run many `AgentLoop` coroutines in one Ray process. DNS,
CA trust, and environment variables are process-wide, so changing them inside
one coroutine would mix provider state between GRPO siblings.

Datalox leaves the model loop in the normal Ray process. Each provider-facing
function tool submits only an argv command to a node-local Unix socket. The
trusted rollout pool executes that command in a transient task container
attached to the sibling's private Docker network and persistent workspace.

```text
Ray AgentLoopWorker
  -> mode-0600 Unix socket
  -> trusted bounded rollout pool
      -> lease for (uid, session_id)
          -> internal Docker network
          -> Datalox gateway with exact provider DNS aliases
          -> resettable provider state
          -> transient allowlisted task containers
          -> persistent per-lease workspace
```

The task container receives the public run CA and workspace only. It does not
receive provider bundles, the private provider run volume, control token,
gateway key, Docker socket, or a route to the public network.

## 1. Build the provider set

Compile each selected provider behavior pack into a task-free runtime bundle.
Place the bundles below one directory, then write the ordered, content-addressed
rollout manifest:

```bash
datalox-gate provider build-runtime \
  --source-world /authorized/source/world \
  --episode-id provider-seed-001 \
  --provider-id provider_a \
  --authority api.provider-a.example \
  --out /opt/datalox/providers/provider-a

datalox-gate rollout provider-set \
  --bundle /opt/datalox/providers/provider-a \
  --bundle /opt/datalox/providers/provider-b \
  --out /opt/datalox/rollout-providers.json
```

The provider-set manifest contains only ordered provider bundle paths, provider
IDs, and exact `provider-runtime.json` digests. Its schema cannot express a
task, prompt, agent, model, verifier, reward, credential, or live upstream.

## 2. Build the runtime and provider-call image

```bash
docker build -t datalox-gated-runtime:local .

docker build \
  -f integrations/verl/Dockerfile.task \
  -t datalox-verl-provider-call:example \
  integrations/verl
```

`integrations/verl/provider_call.py` is a strict stdlib HTTPS dispatcher. The
example `provider_tools.py` owns the provider operation and exact URL. The model
can supply declared tool arguments; it cannot select the task image, lease,
Datalox URL, proxy, MCP surface, or real upstream.

Each dispatcher request declares a bounded integer timeout from 1 through 300
seconds. That timeout is chosen by the consumer's tool implementation, not by
the model or Datalox.

Replace the example URL and tool arguments with the operation exposed by the
selected provider pack. Keep the normal provider URL:

```python
EXACT_PROVIDER_URL = "https://api.provider.com/v1/records"
```

## 3. Start one trusted pool on each rollout node

```bash
datalox-gate rollout pool-serve \
  --provider-set /opt/datalox/rollout-providers.json \
  --runtime-image datalox-gated-runtime:local \
  --task-image datalox-verl-provider-call:example \
  --capacity 64 \
  --artifacts-root /var/lib/datalox/rollouts \
  --socket /run/datalox/rollout-pool.sock
```

When the training tasks require admitted causal behavior across several
providers, start the same pool API from one operator-selected Composition Pack
instead:

```bash
datalox-gate rollout pool-serve-composition \
  --registry /opt/datalox/registry \
  --provider-set /opt/datalox/provider-set-v2.json \
  --composition-pack /opt/datalox/composition-pack \
  --composition-admission /opt/datalox/composition-admission.json \
  --episode-seed training-corpus-v1 \
  --initial-composition-delivery-time 2030-01-01T00:00:00Z \
  --runtime-image datalox-gated-runtime:local \
  --task-image datalox-verl-provider-call:example \
  --capacity 64 \
  --artifacts-root /var/lib/datalox/rollouts \
  --socket /run/datalox/rollout-pool.sock
```

This is an operator choice made once when the pool starts. Dataset rows, model
outputs, prompts, and function-tool arguments cannot select or replace the
Provider Set, registry, Composition Pack, admission, episode seed, or initial
delivery-scheduler time. Every GRPO sibling receives a fresh isolated session
from those same admitted inputs. The socket API, `DataloxToolAgentLoop`,
function tools, task image, and `AgentLoopOutput` contract remain unchanged.

Composition delivery time schedules retries and cross-provider delivery only;
it does not advance any provider's own simulated clock. Finalization writes the
complete provider exports, integration events, delivery outcomes, task exit
codes, and workspace under that sibling's normal rollout artifact directory.

The command creates the socket and `/run/datalox/rollout-pool.sock.token` with
mode `0600`. Mount those two paths into the trusted veRL Ray worker container.
Do not mount the Docker socket into veRL or the evaluated task container.

Set capacity to at least the maximum number of simultaneously active agent
loops that use that node-local pool. Capacity exhaustion is a hard structured
error; Datalox does not silently queue, retry, or share a lease.

## 4. Use the normal veRL agent-loop configuration

The checked example files are:

- `integrations/verl/agent_loop.yaml` — custom `ToolAgentLoop` target and trusted paths;
- `integrations/verl/provider_tools.py` — familiar `@function_tool` provider operation;
- `integrations/verl/launch_fragment.sh` — only the Datalox-related trainer flags;
- `integrations/verl/agent_loop_rows.jsonl` — sibling-zero fields visible at
  `AgentLoopBase.run`;
- `integrations/verl/Dockerfile.task` — the fixed allowlisted provider-call image.

Add the launch fragment's arguments to the project's existing model, data,
actor, reward, resource, logging, and checkpoint command:

```bash
bash integrations/verl/launch_fragment.sh \
  data.train_files=/path/to/train.parquet \
  data.val_files=/path/to/val.parquet \
  actor_rollout_ref.model.path=/path/to/model \
  trainer.n_gpus_per_node=8 \
  trainer.nnodes=1
```

The source dataset should keep the project's normal prompt column and include:

```json
{
  "agent_name": "datalox_tool_agent",
  "extra_info": {"datalox": {"seed": 17}}
}
```

veRL V1 generates `uid` when it samples the prompt and passes
`session_id=0..rollout.n-1` to the sibling loops. Datalox reads these exact
values; it does not derive, repair, or hash a substitute identity.

The prompt must contain only the task objective and constraints visible to the
agent before interaction. Do not place prefetched provider observations,
environment anomalies that have not occurred, expected state, answer keys, or
verifier criteria in the dataset row. The checked carriers are declared in
[`integrations/verl/rollout-information-boundary.json`](../integrations/verl/rollout-information-boundary.json).

`extra_info.datalox.seed` is rollout provenance. A provider runtime bundle has
one fixed compiled initial state. If training requires different initial
provider snapshots, compile separate provider bundles/provider sets and run
separate pools. The current pool does not pretend to reseed a fixed bundle.

## Lifecycle and failure behavior

One lease surrounds the complete call to veRL's own `ToolAgentLoop.run`:

- sequential tool calls retain provider state and `/workspace` files;
- different `(uid, session_id)` pairs cannot observe each other's state;
- function tools spawned with `asyncio.create_task` inherit the correct lease
  through a context variable;
- provider HTTP `4xx` and `5xx` responses remain provider observations;
- malformed dispatcher input and transport failure return nonzero task exits;
- normal loop completion exports final provider state, ledgers, task exit codes,
  and workspace artifacts;
- loop failure or cancellation destroys the lease without publishing a partial
  success artifact; and
- pool shutdown waits for active lease cleanup before removing its socket.

Commands within one lease are serialized because they share one provider state
and workspace. Separate leases execute concurrently.

## What remains owned by veRL and the user

Datalox does not modify:

- sampling parameters;
- prompt or response token IDs;
- response masks or log probabilities;
- routed experts or multimodal fields;
- reward model output;
- GRPO group formation or advantage calculation;
- task prompts, verifiers, datasets, or training recipes.

The adapter returns the exact `AgentLoopOutput` instance created by veRL's
`ToolAgentLoop`. Datalox supplies provider behavior and evidence only.

## Verification

Run the provider-set, Docker lease, pool, and veRL adapter checks:

```bash
python -m pytest -q \
  tests/test_rollout_provider_set.py \
  tests/test_rollout_docker.py \
  tests/test_rollout_pool.py \
  tests/test_verl_integration.py
```

The checked suite covers strict manifests, task-free schemas, 32 concurrent
GRPO siblings, state retention, cross-lease isolation, cancellation, shutdown
cleanup, unchanged `AgentLoopOutput`, child-task context propagation, provider
HTTP failure observations, and absence of a core veRL dependency.
