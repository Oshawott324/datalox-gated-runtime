# THUDM/slime Provider-State Rollouts

Datalox supplies isolated, resettable provider behavior to current THUDM/slime
without becoming slime's environment, generation loop, or reward model.

This integration follows the repository-wide
[`rollout information boundary`](rollout-information-boundary.md). The initial
`Sample.prompt` carries only the consumer's task objective and agent-visible
constraints. Provider responses and environment anomalies enter through the
existing agent loop's observation or tool-result channel after the causal
action. Evaluation ground truth stays in trusted task generation, oracle, and
custom reward or verifier code.

The checked upstream contract is THUDM/slime commit
`a067ce6face6dfee297f219c470c406b8a5025f1` from 2026-08-25. Its preferred
agentic integration points are `--custom-generate-function-path` and
`--custom-rm-path`.

The exact reviewed source files are digest-pinned in
[`integrations/slime/upstream-contract.json`](../integrations/slime/upstream-contract.json).
Verify a checkout with:

```bash
python scripts/check_slime_upstream_contract.py --source /path/to/slime
```

```text
slime generate_and_rm_group
  -> assigns one native string Sample.session_id per original Sample
  -> launches sibling custom-generate calls concurrently
  -> Datalox acquires one isolated provider-state lease per Sample
  -> user custom generation owns the model and agent loop
  -> provider commands run in an operator-fixed task image inside that lease
  -> user returns the exact Sample or list[Sample]
  -> Datalox finalizes state and evidence
  -> slime applies the user's normal custom reward and training pipeline
```

## Why the lease belongs around custom generation

`generate_and_rm_group` creates concurrent asyncio tasks. Process-global DNS,
CA, proxy, or environment mutation would mix provider state between those
tasks. Datalox leaves slime and SGLang in their normal worker process. A
context-local execution handle submits provider-facing argv to the trusted
node-local rollout pool, which executes it inside the sample's private Docker
network.

The lease surrounds the original custom-generation call rather than each
returned segment. Current slime permits one custom generation to return
`list[Sample]` for context compaction, subagents, or other fan-out. Those
segments share one real agent execution and therefore one provider state. The
user remains responsible for slime's required shared `rollout_id` and any
reward distribution across the segments.

Current slime's `TrajectoryManager` creates new `Sample` objects and replaces
their metadata. Consumer fan-out code must merge
`slime_identity_metadata(base_sample)` into its `extra_metadata`. The helper is
pure and the wrapper does not mutate returned samples. Before finalization, the
wrapper verifies that the original sample and every returned segment resolve to
the exact identity acquired at the start. Missing propagation or any identity
change cancels the lease and fails closed.

## Exact identity contract

The adapter reads:

- `sample.session_id`: the native string session ID assigned by slime's group
  path, or an explicit `sample.metadata.datalox.session_id` when the native
  field is absent; and
- `sample.metadata.datalox.uid` and
  `sample.metadata.datalox.environment_seed`: explicit consumer fields loaded
  through slime's normal `--metadata-key` mapping.

The pool socket, token path, operator-fixed task image, and evidence directory
are loaded through slime's existing `--custom-config-path` mechanism. The
checked decorator reads the four required `datalox_*` attributes that slime
installs on `args`; it does not add a parallel launcher or training CLI.

It does not infer identity from `index`, `group_index`, prompt content, or a
hash of training data. Missing, malformed, or unexpected Datalox metadata is a
hard structured error before a pool lease is acquired. When native and metadata
session IDs both exist, exact equality is required.

The environment seed is recorded as provenance. It does not mutate a provider
release's compiled initial snapshot. Distinct initial provider snapshots still
require distinct admitted releases or provider sets selected by the operator.

## Provider call boundary

The consumer registers a provider callback with its existing agent framework.
That callback calls `current_slime_provider_execution().exec(argv)` only after
the model selects the corresponding provider operation. Importing the callback
or entering the decorated custom generator performs no provider call. The
returned provider response enters the normal tool-result channel; Datalox does
not prefetch it into the initial prompt.

The integration supplies the operator-fixed task image to the pool. The
evaluated model cannot select:

- the task image;
- the provider set or Composition Pack;
- a lease or reset operation;
- the Datalox control socket or token; or
- a rewritten provider endpoint.

The program inside the task image keeps the exact provider HTTPS URL. The
private lease network resolves that authority to Datalox and has no route to
the real provider. Provider HTTP failures remain provider observations; task
transport or command failures remain explicit nonzero task exits.

## Training output and reward ownership

The wrapper returns the exact object produced by the user custom generator. It
does not read or modify slime's:

- prompt or response tokens;
- response length or loss mask;
- rollout log probabilities or routing data;
- reward or reward-model selection;
- group, index, session, or rollout identifiers;
- fan-out list shape;
- advantage or optimizer inputs.

After successful finalization, Datalox writes a strict evidence sidecar under a
consumer-selected directory. Its key is SHA-256 over the canonical exact
`(uid, session_id)` identity, and its payload contains the original identity,
lease ID, initial provider fingerprint, finalized artifact directory, and task
exit codes. The public wire contract is
[`slime-evidence-sidecar-v1.schema.json`](../schemas/slime-evidence-sidecar-v1.schema.json).
The sidecar directory and the finalized rollout artifact root must be mounted
at the same absolute paths in generation and reward workers. A user
`--custom-rm-path` function may call
`runtime.evidence_for(sample)` to locate provider state and call evidence. The
user still decides how that evidence affects reward. Expected state, answer
keys, and verifier predicates remain trusted evaluation inputs and are never
passed back through `Sample.prompt` or a provider tool result.

For `list[Sample]` fan-out, current slime calls the custom RM in batch form. The
user function must return a same-length `list[float]` and can call
`runtime.evidence_for_batch(samples)` after explicit identity propagation. All
segments deliberately resolve to the same original provider evidence; the
user decides how a trajectory-level result maps to per-segment reward.

## Failure behavior

- User generation failure or cancellation cancels the provider lease and
  publishes no successful evidence sidecar.
- An `ABORTED` Sample cancels the lease and writes no sidecar, allowing a
  fully asynchronous requeue to reuse the same explicit identity.
- Lifecycle cancellation waits until an in-flight acquire, finalize, or cancel
  result is known, so the caller retains cleanup ownership.
- Finalization completes before the wrapped generator returns to slime.
- A repeated exact identity cannot overwrite existing reward evidence.
- Missing or mismatched evidence fails closed in the custom reward path.

## Supported and separate paths

The checked adapter supports standard and fully asynchronous slime rollouts
that reach custom generation through `generate_and_rm_group`. It also preserves
one-to-many `Sample` fan-out.

Current slime evaluation creates samples and calls `generate_and_rm` directly,
without assigning `sample.session_id`. An eval row can provide
`metadata.datalox.session_id`, but current slime deep-copies that row for
`n_samples_per_eval_prompt`. The row-level form therefore requires
`n_samples_per_eval_prompt=1` even for one round. Periodic evaluation reuses the
cached row and static ID in later `eval_interval` rounds, so metadata-only IDs
support one-shot/manual evaluation only when every execution has a globally
unique ID. Normal periodic eval and higher eval fan-out require slime or
consumer code to inject a distinct native session ID before every execution.
Datalox never manufactures one from the eval index.

This adapter is not a slime `Sandbox` backend. The current rollout pool uses
transient task containers with persistent provider state and `/workspace`.
Slime's general sandbox protocol additionally requires one persistent mutable
container filesystem across `exec`, `write_file`, and `read_file`. That is a
separate execution contract and is not claimed here.

The boundary-safe provider callback and exact wiring are in
[`integrations/slime/`](../integrations/slime/). Run its focused checks with:

```bash
python -m pytest -q tests/test_slime_integration.py
python scripts/check_slime_upstream_contract.py --source /path/to/slime
```
