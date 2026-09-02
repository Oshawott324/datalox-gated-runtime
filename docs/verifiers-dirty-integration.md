# Verifiers paired delivery-intervention experiment

This checked integration is the first bounded experiment for the boundary
agreed with Serhii Nazarov:

```text
admitted provider-grounded behavior
  -> consumer-owned seeded intervention decision
  -> exact Datalox delivery
  -> agent observation
  -> consumer-owned task rewards
```

It is a downstream fixture. It does not add a task, fault distribution, oracle,
or reward to the reusable Datalox provider runtime.

## Execution modes

The public handoff uses Verifiers' normal `vf-eval` path. A model receives the
task and tool schemas, chooses each operation and argument, observes the
result, and chooses its next action. No operation sequence is supplied by
Datalox or the downstream environment.

The package also contains a model-free careful client and naive client. They
exist only to establish solvability, profile calibration, trace integrity, and
reward separation. `datalox-dirty-pair` runs that calibration client; its
`agent-trace.json` is a reference-strategy trace and is never evidence of a
model rollout.

Real model runs write the normal Verifiers result plus controller-only rollout
evidence when the operator supplies `evidence_dir`. The evidence is published
atomically under a directory named by the SHA-256 digest of the opaque
Verifiers trajectory id. It contains the provider export, intervention trace,
delivered observations, scores, and a digest-binding manifest. Neither the
evidence path nor its contents enter a later model turn.

## Controlled pair

The model-free calibration pair fixes:

- task text;
- Medusa provider config, runtime, operation-claims, and admission digests;
- initial provider-state fingerprint;
- intervention policy id, version, digest, and seed; and
- model-free reference-client implementation.

The controlled variable is `intervention_enabled`.

Independent off/on model rollouts fix the same environment-side inputs, but a
hosted inference backend may still produce different model samples even at
temperature zero. Provider/intervention determinism and inference determinism
are separate claims.

In off mode, the policy executes once per request and its counterfactual
decision is recorded. The admitted base response is delivered wire-data
equivalently. In on mode, Datalox applies that same decision without retrying,
normalizing, resampling, or choosing another outcome.

The core trace keeps three records separate:

```text
base: admitted provider binding, event id, response digest
intervention: policy/seed/index, decision, action digest, applied flag
delivered: exact status, headers, body, and digest seen by the agent
```

## Provider behavior

The exact base is the admitted Medusa 2.16.0 Store product collection at
`api.medusa.local`. It exposes native `limit` and `offset` pagination. The
fixture includes first, middle, terminal, and empty beyond-terminal responses,
and its provider admission executes those cases twice around reset.

The public records are self-authored. The pagination envelope, ordering, query
contract, statuses, and boundary behavior are grounded against the pinned
self-hosted provider fixture. The retained G2 artifact contains only
self-authored factual measurements and no captured provider payload bytes,
response text, credentials, or provider-generated identifiers.

Repeated-page intervention deliberately copies an earlier admitted base page.
It is not presented as observed Medusa behavior. Type drift changes `/count`
from the admitted integer to a decimal string; the task requires an integer
`reported_count`, so the agent must confront the change. Quota is a separate
pre-dispatch policy response.

Timeout is excluded. An in-process `GateResponse` cannot truthfully create the
same client behavior as a network-layer timeout, so v1 fails closed instead of
returning a JSON body labelled as a timeout.

## Information boundary

The task plane contains the collection objective and visible API constraints.
It contains no prefetched product, expected identifier, fault schedule, answer
key, or reward condition.

The observation plane receives a product page or intervention only after the
agent calls `list_products`. Intervention provenance is controller evidence;
it is not inserted in the provider response.

The evaluation plane owns `EvaluationOracle`, submission comparison, and
request-discipline calculation. Rollout episodes and the oracle live in
environment-private maps keyed by the opaque Verifiers trajectory id. Cleanup
computes two scalar scores, closes the episode on success or error, and keeps
those scalars private until the rubric reads them. The client-visible state
contains no episode, provider object, oracle, expected product, policy seed,
profile, or intervention mode. The hidden `episode` tool argument is omitted
from the Verifiers schema. See the checked carrier manifest at
[`integrations/verifiers_dirty_integration/rollout-information-boundary.json`](../integrations/verifiers_dirty_integration/rollout-information-boundary.json).

## Calibration and acceptance

The model-free careful client:

- follows only provider-supported integer offsets;
- checks that the returned offset matches its request;
- retries the same offset after a repeated page;
- deduplicates by provider id;
- normalizes a decimal-string count; and
- stops after the provider returns an empty page or a quota response.

The naive client advances its requested offset without validating the returned
offset and submits the first observed count without normalization.

Acceptance requires multiple declared seeds where:

- off and bypass deliver identical status, headers, and body;
- same policy seed gives the same decisions;
- reset reproduces provider and intervention state;
- the careful client completes every released seed;
- naive task correctness is lower on intervention-bearing seeds;
- excess calls and 429s reduce request discipline independently; and
- paired artifacts bind the exact admitted provider and contain no evaluation
  ground truth in the task or observation traces.
