# Datalox model-rollout intervention fixture for Verifiers

This is a downstream experiment fixture for Serhii Nazarov's
[`dirty-integration`](https://github.com/buildok/dirty-integration). It keeps
the familiar Verifiers 0.3.1 legacy loading surface while placing an admitted,
task-free Datalox provider runtime beneath the task:

```python
import verifiers as vf

common = {
    "profile": "hostile",
    "intervention_seed": "7",
}
off = vf.load_environment(
    "datalox-dirty-integration",
    intervention_enabled=False,
    **common,
)
on = vf.load_environment(
    "datalox-dirty-integration",
    intervention_enabled=True,
    **common,
)
```

The task rows contain only agent-visible instructions. The profile, mode, and
seed remain operator arguments on the environment and never enter the client-visible
Verifiers state. The model chooses every tool name and argument during the
rollout; the environment defines the available operation surface, not an action
sequence.

The consumer package owns the task, seeded policy, model loop, oracle, and two
reward components. Datalox owns the admitted base-provider execution and exact
delivery of the consumer's intervention decision.

## Run a real model rollout

Use the normal Verifiers evaluator. Set these to an inference provider and model
available in your existing Verifiers setup:

```bash
export INFERENCE_PROVIDER=prime
export MODEL=your-provider/your-model
```

Then run one intervention-on rollout:

```bash
uv run \
  --project integrations/verifiers_dirty_integration \
  vf-eval datalox-dirty-integration \
  --provider "$INFERENCE_PROVIDER" \
  --model "$MODEL" \
  --env-args '{"profile":"hostile","intervention_enabled":true,"intervention_seed":"7","num_tasks":1,"evidence_dir":"/tmp/datalox-serhii/live-on/evidence"}' \
  --num-examples 1 \
  --rollouts-per-example 1 \
  --max-concurrent 1 \
  --temperature 0 \
  --max-retries 0 \
  --output-dir /tmp/datalox-serhii/live-on/verifiers \
  --save-results \
  --disable-tui
```

The causal path is the ordinary Verifiers agent loop:

```text
task -> model-selected tool call -> provider observation -> later model-selected call
```

There is no reference solver or predetermined offset sequence in this path.
The Verifiers result directory records the model conversation and tool calls.
The controller-only evidence directory records the admitted provider execution,
intervention decisions, delivered observations, and scores under one hashed
rollout directory.

Run the comparison side by changing only `intervention_enabled` and the two
output paths:

```bash
uv run \
  --project integrations/verifiers_dirty_integration \
  vf-eval datalox-dirty-integration \
  --provider "$INFERENCE_PROVIDER" \
  --model "$MODEL" \
  --env-args '{"profile":"hostile","intervention_enabled":false,"intervention_seed":"7","num_tasks":1,"evidence_dir":"/tmp/datalox-serhii/live-off/evidence"}' \
  --num-examples 1 \
  --rollouts-per-example 1 \
  --max-concurrent 1 \
  --temperature 0 \
  --max-retries 0 \
  --output-dir /tmp/datalox-serhii/live-off/verifiers \
  --save-results \
  --disable-tui
```

These are independent model rollouts over identical task, provider release,
initial provider state, intervention policy, and intervention seed. Temperature
zero reduces inference variation but does not make every hosted model backend
bitwise deterministic. Treat model-output reproducibility as a separate control
from the deterministic provider and intervention schedules.

## Run the model-free calibration pair

The following command runs a deliberately scripted reference client. It proves
solvability, switch mechanics, trace separation, and reward calibration. It is
not a model rollout and must not be reported as one:

```bash
uv run \
  --project integrations/verifiers_dirty_integration \
  datalox-dirty-pair \
  --profile hostile \
  --intervention-seed 7 \
  --output /tmp/datalox-serhii-pair
```

The calibration command binds both sides to the same task digest, immutable OCI provider
release and profile, provider-state fingerprint, policy digest, and policy seed. Only
`intervention_enabled` changes.

```text
/tmp/datalox-serhii-pair/
├── pair-manifest.json
├── comparison.json
├── off/
│   ├── provider-export.json
│   ├── intervention-trace.json
│   ├── agent-trace.json
│   └── verification.json
└── on/
    ├── provider-export.json
    ├── intervention-trace.json
    ├── agent-trace.json
    └── verification.json
```

The off trace still records the counterfactual policy decision. It delivers the
base provider response unchanged. The on trace records and applies the same
decision. Agent actions may diverge after the first delivered-observation
change; that divergence is an experimental result, not a binding failure.

## Exact first slice

The base operation is pinned Medusa 2.16.0 Store API offset pagination:

```text
GET https://api.medusa.local/store/products?limit=10&offset=N
```

It uses the admitted first, middle, terminal, and beyond-terminal page behavior
in `envs/medusa_store_pagination_v0`. The interventions are:

- a provider-shaped pre-dispatch `429` quota response;
- a post-response repetition of an earlier base page; and
- a post-response `count` integer-to-decimal-string change.

Medusa exposes `limit` and `offset`, not an opaque cursor. The reference client
therefore validates the returned offset and retries the same provider-supported
request. It never decodes or manufactures a cursor. Native transport timeout
injection is outside this v1 slice because the in-process response boundary
cannot honestly reproduce a client transport timeout.

Task correctness and request discipline are separate reward functions.
Request discipline measures useful-provider-call efficiency and delivered 429s;
it does not change task correctness.

See [`docs/verifiers-dirty-integration.md`](../../docs/verifiers-dirty-integration.md)
for the evidence and information-plane contract. Third-party attribution and
the reviewed upstream digests are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
and [`upstream-contract.json`](upstream-contract.json).
