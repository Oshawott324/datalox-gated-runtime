# Verifiers paired read-intervention and provider-write experiment

This checked integration exercises the boundary agreed with Serhii Nazarov:

```text
admitted Medusa behavior
  -> consumer-owned seeded read intervention
  -> exact delivered observation
  -> model-selected provider write
  -> controller-only state verification
```

It is a downstream consumer of Datalox. The reusable provider release contains
no task, model loop, fault distribution, answer key, verifier, or reward.

## A genuine rollout

The public handoff uses Verifiers' normal `vf-eval` loop. The model receives a
task and six provider tools, then chooses each operation and argument from the
conversation so far. The environment never supplies an action sequence.

The task requires the model to paginate the complete catalog, choose the
lowest-price variant, create one cart, add one unit, update the provider-issued
line item to quantity three, and retrieve the cart. Product, variant, cart, and
line-item identifiers arrive only after their causal provider calls.

The package also contains careful and naive model-free clients. They establish
solvability, deterministic switch behavior, and reward calibration only.
`datalox-dirty-pair` writes a reference-strategy trace; that trace is never
evidence of a model rollout.

## Controlled off/on pair

Both sides fix task text, Medusa runtime/admission/release digests, initial
provider-state fingerprint, intervention policy and seed, and reference-client
implementation. `intervention_enabled` is the only environment-side variable.

In off mode, the policy records its counterfactual decision and delivers the
base read response unchanged. In on mode, Datalox applies the same decision
without retrying, resampling, or normalizing. Writes bypass the intervention
session and execute directly against the same admitted provider runtime.

The controller trace separates:

```text
base: admitted provider binding and response digest
intervention: policy/seed/index, decision, action, applied flag
delivered: exact status, headers, and body seen by the model
provider state: cart and line-item effects used by the verifier
```

Every completed read exposes `base_sha256`, `delivered_sha256`, and
`observation_changed` in addition to the detailed base and delivered records.
The independent auditor recomputes policy decisions and action hashes, binds
the base digest to provider call evidence, binds the delivered digest to the
exact tool result, and creates a semantic comparison without envelope or event
IDs. An applied action can correctly record `observation_changed: false` when
its canonical output equals the base response.

## Grounded provider behavior

The pinned base is the bounded Medusa 2.16.0 Store release at
`api.medusa.local`. Product reads retain native limit/offset envelopes. Cart and
line-item calls retain provider-shaped request paths, synchronous response
envelopes, deterministic generated identifiers, duplicate behavior, invalid
write failures, and atomic readback in the admitted slice.

Public evidence records reviewed factual measurements and digests. Public
provider data remains self-authored. No captured payload bytes, credentials,
raw provider-generated identifiers, or tenant data are part of this fixture.

Repeated-page and type-drift interventions are explicitly consumer-authored
delivery behavior. A quota decision is pre-dispatch. None is represented as an
observed Medusa failure. Transport timeout injection remains outside this
slice.

The profile labels do not define a global severity order. The dimensions are:

| Profile | Repeat-page rate | Count-type-drift rate | Request quota |
| --- | ---: | ---: | ---: |
| `clean` | 0.00 | 0.00 | none |
| `realistic` | 0.15 | 0.25 | 12; quota response at index 13 |
| `hostile` | 0.30 | 0.50 | 16; quota response at index 17 |

The hostile profile has more post-response mutations and a less restrictive
quota. Interpret each dimension directly.

The controller injects the release's public local publishable-key placeholder.
It is not a model-selected argument and is omitted from delivered-call evidence.
Direct provider tests cover missing and invalid key responses.

## Information planes

The task plane contains only objectives and visible constraints: page size,
email, region, initial add quantity, and final quantity. It contains no product,
variant, cart, or line identifier; catalog answer; intervention schedule; or
reward implementation.

The observation plane receives provider responses only after model-selected
calls. Delivered responses preserve the provider envelope. Intervention
provenance stays in controller evidence rather than provider bodies.

The evaluation plane reads the isolated final provider state and delivered-call
history after rollout cleanup. It checks catalog completeness, the minimum
observed-price variant, provider-issued identifier flow, final cart state, and
confirmation retrieval. The client-visible Verifiers state contains no episode,
provider runtime, state export, oracle, policy seed, profile, mode, or evidence
path. The hidden `episode` tool parameter is absent from model schemas.

The machine-readable carrier contract is
[`integrations/verifiers_dirty_integration/rollout-information-boundary.json`](../integrations/verifiers_dirty_integration/rollout-information-boundary.json).

## Isolation and evidence

`setup_state` creates one provider runtime per opaque Verifiers trajectory id.
Two concurrent rollouts can receive the same deterministic cart identifier
while retaining independent SQLite state, call histories, scores, and evidence
directories. Cleanup verifies and closes each episode on both successful and
failed model runs.

When `evidence_dir` is set, cleanup atomically writes a digest-named directory
containing provider export, intervention trace, delivered observations,
verification scores, and a manifest binding every artifact. Evidence never
enters a later model turn.

## Repeated model-rollout baseline

The repeat experiment measures an unchanged agent on clean and hostile profiles
before introducing a candidate prompt or harness change. It is separate from
the model-free Issue #6 acceptance gate below. The
[September 12 pilot](serhii-noise-floor-20260912.md) reports 60 completed model
rollouts, the exact configuration, and a reviewed public evidence projection.

The default is GPT-5.6 Sol with medium reasoning, using the native Verifiers
0.3.1 Responses client and `Environment.evaluate` entry point. Live preflight
established that Sol's function tools with medium reasoning require Responses,
rather than Chat Completions. This is the same evaluator used
by `vf-eval`; the programmatic path exposes client retry and timeout settings
that the pinned CLI does not. Both evaluator and SDK retries are zero, rollout
concurrency is one, and parallel tool calls are disabled. The model chooses
its actions normally. Model seed and temperature are omitted, and the exact
effective configuration is recorded. The native client replays returned reasoning
items and tool results with `store=false` and the default processing tier.
The hosted inference backend is not
claimed immutable; the pinned client does not retain its backend fingerprint.

The primary cohort has two profiles, seeds `1`, `7`, and `23`, and ten repeats
per profile/seed: 60 slots. A separate two-slot clean/hostile smoke cohort uses
seed `7`; its results stay outside the pilot. Both profiles use the same task,
provider release, and initial state, with their declared policy enabled. Clean
applies no interventions and has no quota. Its seed labels are scheduling
blocks over the same task, not independent tenant coverage. Only product-list
requests advance the fault index; cart retrieval and writes bypass it.

The [repeat commands](../integrations/verifiers_dirty_integration/README.md#measure-repeated-run-variation)
follow three explicit stages:

- `datalox-dirty-repeat prepare` records a validated, digest-bound manifest and
  fixed schedule without inference.
- `datalox-dirty-repeat run` executes that schedule with a fresh provider state
  per native rollout. It requires the inference credential, an approved total
  cap, per-rollout allowances, and `--spend-approved`. A controller checks
  exact Responses input-token counts, reserves the maximum request token cost,
  and settles raw usage within each rollout's allowance.
- `datalox-dirty-repeat analyze` verifies retained native/controller artifacts
  and derives reports offline, without credentials or inference.

Separate smoke and pilot allocations must fit the operator's combined cap.
The scheduler reserves each slot's full allowance before launch, then releases
unused funds only after exact token settlement and native evidence pass audit.
A collection error retains the full allowance. An uncertain charge or
exhausted budget stops the cohort with explicit error and unstarted
slots. A model failing the task is valid completed data when its evidence is
complete and audited; it is not retried to obtain a passing answer.

Reports preserve task and request-discipline components separately, include
quota exposure and native truncation, and show success-only summaries alongside
all completed runs. Exact ordered request and observation comparisons retain
provider IDs, scalar types, duplicate calls, and query order. A first divergence
can be inspected with its logical read index, base receipt and available base
response, intervention decision, and delivered observation. Pairwise comparisons
reuse runs and do not increase the independent sample count.

Clean versus hostile includes both fault exposure and quota; its difference is
not a causal estimate of schedule coupling alone. The pilot derives descriptive
ranges rather than an automatic release threshold. Manifests, native outputs,
digest indexes, verifier reports, and analysis artifacts remain on the trusted
controller side and require data-release review before sharing.

## Public Issue #6 acceptance

Run the complete deterministic gate with:

```bash
uv run \
  --project integrations/verifiers_dirty_integration \
  datalox-dirty-calibrate \
  --seed-start 1 \
  --seed-count 60 \
  --output /tmp/datalox-issue-6-calibration.json
```

It runs 180 matched OFF/ON pairs, independently audits each pair, reaches every
configured read-intervention branch, and emits a compact schema-validated
report. Verifier calibration contains one valid trajectory and three explicit
negative trajectories: incomplete pagination, the already modeled invalid
quantity write, and a write after an intervention-visible quota failure. It
reports false acceptance and false rejection separately.

Quality calibration keeps task correctness at 1.0 for both clients. The
efficient client follows the ten-call minimum path; the redundant client reads
each catalog page twice. Their request-discipline evidence records the call
counts, efficiency factors, score difference, and reason codes.

This V1 experiment contains read interventions only. Its negative write uses
the fixture's existing synchronous invalid-quantity behavior. Write timeout and
unknown completion remain V2 concerns and are excluded from this protocol.

The checked result is
[`integrations/verifiers_dirty_integration/issue-6-calibration-report.json`](../integrations/verifiers_dirty_integration/issue-6-calibration-report.json).
It is self-authored aggregate evidence over the public G1 fixture and contains
no credentials, tenant identifiers, captured provider payloads, or restricted
provider evidence.
