# Provider Foundry and Composition Contract

This document fixes the construction and execution architecture for reusable
Datalox fuel. It prevents provider catalogs, user-owned worlds, and real
cross-provider integrations from being treated as the same artifact.

## Artifact chain

```text
authorized source behavior
  -> digest-bound grounding measurement and portable behavior program
  -> task-free provider runtime bundle
  -> provider operation claims
  -> derived Provider Admission
  -> task-independent State Profile and derived State Admission, when claimed
  -> immutable OCI Provider Release
  -> immutable registry reference and reset profile
  -> three-run source-versus-release differential attestation
  -> periodic source drift and append-only release assessment
  -> Provider Set or admitted Composition Pack
  -> one isolated transparent-interception session
  -> controller evidence consumed by the user's harness
```

The user still owns the task, agent, world-level verifier, reward, and training
loop. Datalox owns the provider-shaped behavior, reset boundary, causal
delivery machinery, and trustworthy provider/composition evidence.

Consumer-owned adversarial delivery policy is a separate optional layer after
provider execution. It can alter what the agent receives for an experiment, but
it cannot change the Provider Release's grounding or admission. See
[`Delivery Interventions`](delivery-interventions.md).

For rollout consumers, those owned components remain separated by the
[`rollout information boundary`](rollout-information-boundary.md): the agent
starts with objectives and visible constraints, the environment reveals
observations causally during interaction, and trusted generator/oracle/verifier
code alone receives evaluation ground truth.

## Provider Release

A Provider Release is the distributable admitted provider module. It binds:

- the exact provider authorities and native operation surfaces;
- the resettable runtime bundle and reset profile;
- an optional admitted, rights-bound State Profile for the exact reset seed;
- operation-level read/write/failure/duplicate/readback claims;
- provider invariants and reusable receipt predicates;
- grounding evidence, rights, distribution label, and content digests; and
- the derived Provider Admission that executed the claims and functional reset
  checks.

The release is an OCI artifact. The Datalox runtime image is separate: a
release contains provider behavior, while the runtime image supplies the
generic execution engine. A registry reference such as
`provider@release-version` is immutable.

The State Profile is provider-native rather than a normalized Datalox entity
model. It describes tenant content, lifecycle depth, relationships,
reachability, pagination, and reset evidence without containing a task or
evaluation truth. The provider profile selected by the operator binds its state
profile and admission digests into the OCI layer. A release profile without
state digests makes no admitted tenant-depth claim. See
[`Provider State Profiles`](provider-state-profiles.md).

## Provider Set: agent-mediated composition

A Provider Set selects exact immutable Provider Release profiles. It means only
that the modules share one isolated lease boundary, episode seed, and
controller evidence. Provider state and provider-native clocks remain
independent.

```text
agent reads provider A
  -> agent reasons about the result
  -> agent explicitly calls provider B
```

No webhook, background worker, object mapping, retry, or side effect is implied
by placing two releases in one Provider Set. This is the correct unit when the
consumer deliberately asks the evaluated agent to perform the integration.

## Composition Pack: provider-mediated composition

A Composition Pack represents hidden causal behavior that real services or an
integration layer perform without a new agent action:

```text
provider A accepts a write
  -> emits an observed event
  -> integration maps the payload
  -> provider B receives a write later
  -> retry, failure, or compensation may follow
```

Each causal edge declares exact source outcomes, finite source predicates,
target write operations, provider-owned principal contexts, finite payload
templates, provider-native event and correlation IDs, delivery delay, ordering,
idempotency, retry policy, terminal failure, and optional compensation.
Evidence, grounding, freshness, rights, and redistribution scope attach to
every claim. Identity and object-ID mappings belong to these explicit edges;
they are never inferred from a Provider Set.

Source predicates may inspect only declared, non-secret request fields,
provider-shaped response fields, and post-operation provider state. Their
finite JSON-pointer comparisons determine whether an observed provider outcome
actually emits a source event. Ambiguous matches fail closed. This prevents an
unrelated successful write from being treated as the webhook-producing action.

An authored Composition Pack has status `authored_not_admitted`. It is a claim,
not executable truth. Composition Admission must execute its exact probes twice
with a mutation-reset cycle and prove the same observable behavior. Admission
must cover every source and edge, including success, read-after-write,
duplicate/idempotency, ordering, terminal failure, declared retry exhaustion,
and every declared compensation trigger.

The runtime never infers a cross-provider mapping. An AI agent may replace an
integration only when the user-owned task explicitly makes that integration the
agent's job. It cannot reproduce an existing hidden background integration
unless the causal edges are represented and grounded.

## Deterministic session behavior

An admitted composed session owns a durable event queue and one
`composition_delivery_time`. Its required scope is
`delivery_scheduler_only_v1`: it controls edge delays, retry availability,
unknown-completion resolution, and compensation scheduling. It does not advance
provider-native clocks or execute provider-owned timers. Provider modules keep
their own admitted time semantics.

Deliveries are strictly ordered within `(edge_id, ordering_key)` while
independent streams may progress separately. Retry schedules are finite.
Timeout or executor failure becomes `unknown_completion`; the runtime does not
retry or compensate until a trusted controller resolves whether the write
occurred.

The agent data plane contains provider operations only. Delivery-time advance,
delivery drain, unknown resolution, reset, and evidence export stay on the
authenticated controller plane. Reset covers every provider module and the
event engine as one session operation.

Composition sessions are intentionally non-resumable in v1. A process or
container loss invalidates the lease, and the operator starts a fresh reset
lease. Datalox does not silently resume because a provider write and its source
event currently commit to separate durable stores. Honest crash-safe resume
requires a durable agent-call journal, coordinated provider commit/readback,
and a persisted reset generation. The durable event outbox does guarantee that
delivery outcomes, follow-up events, and compensation effects cannot split
inside a live lease.

## Acquisition backends

Provider behavior may enter the foundry through three explicit authoring paths:

1. A deployable native service or official simulator.
2. Reviewed declarative programs against an authorized writable sandbox.
3. A separately invoked gated live authoring run used for acquisition and
   drift checks.

All three compile to the same admitted Provider Release. Runtime schemas cannot
express provider forwarding, and evaluated-agent execution has no provider
network path.

The acquisition and release claims stay joined by the
[provider differential and drift loop](provider-differential-and-drift.md).
Provider Admission proves the declared local contract. A differential
attestation separately proves one complete observed behavior program against an
immutable release profile, including post-mutation reset and fresh-instance
equivalence. A later authorized acquisition distinguishes provider drift from a
replica regression without editing the frozen release.

## Consumer integration

Docker and Kubernetes place the generic runtime and selected admitted releases
beside the consumer's agent workload. The agent continues to call the exact
provider HTTPS authorities. DNS and the run-scoped CA terminate those calls at
Datalox inside the isolated boundary.

veRL/GRPO, HUD, Harbor, OpenEnv, EnvFactory, and custom harnesses are consumers
of the same session contract. They do not require separate Datalox-authored
worlds. They retain their native task and rollout structures and consume
provider state, call evidence, integration events, and admission digests from
the trusted session export.

## Acceptance boundary

The foundry is considered mechanically complete only when tests prove:

- strict claims, admission, OCI release, registry publication, and resolution;
- digest-bound acquisition, portable multi-attempt programs, immutable-release
  differential execution, and append-only freshness assessment;
- registry-backed provider selection with no caller-authored runtime paths;
- admitted exact-authority execution with zero provider egress;
- deterministic reset and isolated parallel sessions;
- explicit composition with time, order, retries, idempotency, unknown
  completion, compensation, and bounded durable evidence;
- conditional source emission that rejects ambiguous outcome matches;
- transparent Docker and Kubernetes consumption; and
- an end-to-end self-authored two-provider fixture that exercises the complete
  chain without becoming a Datalox-owned benchmark.
