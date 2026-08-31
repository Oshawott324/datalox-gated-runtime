# Datalox with current THUDM/slime

The complete lifecycle and ownership contract is in
[`docs/slime-rollouts.md`](../../docs/slime-rollouts.md).
The task, observation, and evaluation carriers are declared in
[`rollout-information-boundary.json`](rollout-information-boundary.json) under
the repository-wide
[`rollout information boundary`](../../docs/rollout-information-boundary.md).

This adapter follows slime's normal agentic path:

```text
--custom-generate-function-path
  -> user-owned async generate(args, sample, sampling_params)
  -> one Datalox provider-state lease around that complete call
  -> user returns Sample or list[Sample]
  -> Datalox finalizes a provider-evidence sidecar
  -> --custom-rm-path loads that evidence if the user's reward needs it
```

It was checked against THUDM/slime commit
`a067ce6face6dfee297f219c470c406b8a5025f1` (2026-08-25). The adapter has no
runtime dependency on slime and does not replace its generation, token, mask,
reward, grouping, advantage, or optimizer logic.

The reviewed upstream files and digests are pinned in
[`upstream-contract.json`](upstream-contract.json). Verify an exact slime
checkout before adapting or upgrading the integration:

```bash
python scripts/check_slime_upstream_contract.py --source /path/to/slime
```

Build the fixed example provider-call image:

```bash
docker build \
  -f integrations/slime/Dockerfile.task \
  -t datalox-slime-provider-call:example \
  integrations/slime
```

Start the normal trusted rollout pool with that image in its operator allowlist,
then mount the pool socket and generated `.token` file into each slime rollout
node. The pool command and Provider Set are the same as for other parallel
training consumers.

## Use the native custom-generate path

Put the Datalox connection fields in slime's native custom config:

```yaml
datalox_pool_socket_path: /run/datalox/rollout-pool.sock
datalox_pool_token_path: /run/datalox/rollout-pool.sock.token
datalox_task_image: my-project/provider-tools@sha256:<digest>
datalox_evidence_sidecars_root: /var/lib/my-project/slime-provider-evidence
```

Then decorate the user-owned generation function:

```python
from datalox_gated_runtime.integrations.slime import (
    SlimeDataloxRuntime,
    datalox_custom_generate,
    slime_identity_metadata,
)
from integrations.slime.provider_tool import get_example_record


@datalox_custom_generate
async def generate(args, sample, sampling_params, evaluation=False):
    # Register the callback with the agent framework already used by this
    # project. It runs only after the model selects the provider tool. The
    # returned value enters the normal tool-result channel as an observation.
    return await run_my_existing_agent_loop(
        args,
        sample,
        sampling_params,
        tools={"get_example_record": get_example_record},
        evaluation=evaluation,
    )


async def reward(args, sample_or_samples, **kwargs):
    runtime = SlimeDataloxRuntime.from_slime_args(args)
    if isinstance(sample_or_samples, list):
        evidence = runtime.evidence_for_batch(sample_or_samples)
        return [
            await my_task_reward(
                args,
                sample,
                provider_evidence_directory=item.artifact_directory,
                **kwargs,
            )
            for sample, item in zip(sample_or_samples, evidence, strict=True)
        ]
    evidence = runtime.evidence_for(sample_or_samples)
    return await my_task_reward(
        args,
        sample_or_samples,
        provider_evidence_directory=evidence.artifact_directory,
        **kwargs,
    )
```

The model first receives only the consumer's task objective and visible
constraints in `sample.prompt`. A model-selected tool action invokes
`get_example_record`, and that action produces the provider observation. The
custom reward reads trusted evidence after finalization; it never makes its
ground truth available to the generator or model.

Point the usual slime arguments at those functions:

```bash
--custom-generate-function-path my_project.slime_task.generate \
--custom-rm-path my_project.slime_task.reward \
--custom-config-path my_project/slime_datalox.yaml \
--metadata-key metadata
```

[`provider_tool.py`](provider_tool.py) is the checked provider callback. It has
no Slime dependency and cannot read or mutate a `Sample`, prompt, reward, or
verifier value. Importing it performs no provider call. The consumer registers
it with the tool mechanism in the existing custom agent loop, so a provider
observation is created only by a model-selected action.

Set `SLIME_USER_GENERATE_PATH` and `SLIME_USER_REWARD_PATH` to the consumer's
existing functions, then add [`launch_fragment.sh`](launch_fragment.sh)'s
`SLIME_DATALOX_ARGS` array to the existing Slime command. Datalox does not ship
a generic generator because the consumer owns the agent loop, task semantics,
and training recipe.

Each source row must supply the explicit Datalox fields through slime's normal
metadata mapping:

```json
{
  "datalox": {
    "uid": "task-0042",
    "environment_seed": 17
  }
}
```

Current slime assigns a unique string `sample.session_id` before it calls
custom generation through `generate_and_rm_group`. Datalox uses that exact
value and the explicit `metadata.datalox.uid` as the lease identity. It does
not fall back to `index`, `group_index`, or a generated identifier.

The task image is fixed when the trusted pool and adapter start. Code inside
that image must call the exact provider URL, such as
`https://api.provider.example/v1/records`. The lease's internal DNS and TLS
boundary sends that request to Datalox with no provider egress. The model does
not receive the image name, pool socket, lease token, Datalox URL, or reset
control.

## Fan-out and reward evidence

One lease surrounds the original custom generation call. If user code returns
`list[Sample]`, every segment was produced under that same provider state. The
adapter returns the exact list object and exact sample objects without changing
their `rollout_id`, tokens, masks, log probabilities, reward, or status.

Current slime's `TrajectoryManager` constructs fresh fan-out `Sample` objects;
it does not copy the base sample's `session_id` or metadata. Pass the adapter's
pure identity metadata through the existing `extra_metadata` parameter:

```python
segments = await trajectory_manager.finish_session(
    session_id,
    base_sample=sample,
    reward=task_reward,
    extra_metadata={
        **task_segment_metadata,
        **slime_identity_metadata(sample),
    },
)
```

The wrapper verifies that every returned segment resolves to the exact original
identity. A fresh segment without this explicit propagation fails before
finalization. Slime calls a custom RM with `list[Sample]` for fan-out, so the
user reward must return a same-length `list[float]`; `evidence_for_batch`
performs one strict sidecar lookup per segment.

After normal completion, the adapter writes a mode-`0600` JSON sidecar keyed by
SHA-256 over the exact `(metadata.datalox.uid, sample.session_id)` pair. The
sidecar points to the rollout pool's finalized provider state, ledgers, task
exit codes, integration events, and workspace. `runtime.evidence_for(sample)`
performs strict identity and schema validation before a user reward reads it.
Its wire contract is
[`schemas/slime-evidence-sidecar-v1.schema.json`](../../schemas/slime-evidence-sidecar-v1.schema.json).
Mount the sidecar directory and finalized artifact root at the same absolute
paths in the generation and reward workers.

## Current boundary

This integration covers provider-facing commands invoked from slime custom
generation. It does not implement slime's persistent `Sandbox` protocol:
current Datalox rollout task containers are transient while only provider state
and `/workspace` persist between commands. A task that needs a durable mutable
container filesystem requires a separate persistent-sandbox delivery contract.

Current slime evaluation calls `generate_and_rm` directly and does not assign
`sample.session_id`. An eval row may instead declare the exact
`metadata.datalox.session_id`. When both forms exist, they must match exactly.
Because current slime deep-copies one row for `n_samples_per_eval_prompt`, a
row-level session ID is safe only with `n_samples_per_eval_prompt=1`; concurrent
copies would collide. Periodic evaluation also reuses the cached row and its
static ID across `eval_interval` rounds. Static metadata IDs therefore support
only a one-shot/manual eval where every execution has a globally unique ID.
Normal periodic eval and higher eval fan-out require slime or consumer code to
inject a fresh native session ID before every execution. The adapter never
derives an eval identity from `sample.index`.

If slime returns an `ABORTED` Sample, the adapter cancels the lease and writes
no evidence sidecar. Fully asynchronous requeue can therefore reuse the exact
same identity for a later attempt.
