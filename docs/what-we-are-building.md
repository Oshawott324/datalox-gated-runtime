# Grounded Provider Behavior for Tool-Using Agents

Datalox is building infrastructure for agents that do real work through APIs,
Model Context Protocol servers, and other software tools.

The goal is to make realistic tool use safe, repeatable, stateful, and verifiable:

> Let an agent keep calling the provider's normal URL while a controlled,
> offline runtime returns stateful provider-grounded behavior inside the user's
> own environment.

## Canonical product thesis

Datalox is a provider-behavior infrastructure company for agents. It is not a
benchmark, a world marketplace, a generic MCP catalog, or a raw catalog of
mocked endpoints.

The vocabulary is fixed:

- **fuel = reusable provider/API building blocks**;
- **world = a consumer-owned stateful composition of fuel**;
- **benchmark = a downstream consumer-owned evaluation**.

Fuel means reusable, source-grounded gated provider behavior packs. User-owned
worlds and benchmarks consume fuel.

Mocks are raw material. A component becomes valuable when it preserves provider
shape, wire behavior, state, side effects, permissions, failures, and known
gaps. The user owns the composed evaluation unit:

```text
user task/world + Datalox provider packs + user verifier/reward
```

Datalox provides the provider-behavior substrate. External systems own the task,
world, agent loop, planning, context, retries, memory, model routing, verifier,
and reward.

Rollout integrations preserve a strict
[`three-plane information boundary`](rollout-information-boundary.md): visible
task objectives and constraints arrive before interaction; provider and
environment observations arise causally during interaction; evaluation ground
truth stays with trusted generation, oracle, and verifier code.

## Product surface

The primary product unit is a construction-ready provider behavior pack. It
contains selected operation families, provider-shaped reads, local mutations or
explicit denials, transition and verifier atoms, provenance, and known gaps.

Reference worlds exist only to prove interoperability, reset, and composition.
They do not make Datalox the owner of a user's task or benchmark.

See [Provider Packs](provider-packs.md) for packaging and the data boundary.
See [Provider Foundry and Composition Contract](provider-foundry.md) for the
immutable release, registry, Provider Set, and provider-mediated composition
boundaries.

Several providers may be co-hosted without claiming that they interact. A
Provider Set supports agent-mediated work: the agent reads one provider and
explicitly calls another. Hidden background behavior such as webhooks,
transforms, retries, delays, and compensation requires a separately grounded
and admitted Composition Pack. Datalox never infers those causal edges from API
shape or provider proximity.

## Execution model

```text
user-owned task/world
  -> agent calls https://api.provider.example normally
  -> sandbox DNS/TLS terminates the call at Datalox
  -> Datalox applies grounded provider behavior to isolated state
  -> provider-shaped response returns to the agent
  -> trusted controller exports state and execution evidence
```

The gate makes one explicit decision per call: replay a recorded response; read
or mutate resettable provider state; shadow a permitted write; deny an unsafe
operation; or return a structured miss. Runtime provider access is forbidden.

Transparent HTTPS is the primary surface. HTTP/MCP developer and harness
projections use the same policy and state contracts and are not parallel sources
of truth.

## What provider behavior must preserve

A useful world preserves the parts of real work that single-call tests lose:

- identity, authorization, roles, and handoffs;
- generated identifiers and related objects;
- pagination, polling, asynchronous completion, and time;
- idempotency, duplicates, conflicts, and invalid transitions;
- stateful side effects and recovery;
- deterministic reset and isolation;
- hidden final-state and workflow verification.

Final-answer grading alone cannot prove these properties. A plausible message
does not establish that the correct record was read, a write was safe, or the
world ended in a valid state.

## Grounding labels are separate

The project separates three milestones:

- **replay completion** — declared local calls replay without misses;
- **world admission** — the resettable bundle passes structural, safety, and
  verifier checks;
- **provider behavior grounding** — observed provider or reference-system
  evidence supports the transition and failure behavior.

One label never implies another. See
[Provider Behavior Grounding](provider-behavior-grounding.md) and
[World Admission Rubric](world-admission-rubric.md).

## Sandbox-first acquisition

When a provider offers an adequate writable sandbox, Datalox should connect to
it, execute reviewed declarative recipes, and capture complete
before/write/duplicate/failure/after programs. It should not first implement a
second sandbox from documentation.

Local reimplementation is justified only for a named requirement such as
credential-free scale, deterministic reset, missing sandbox behavior, failure
injection, provider cost or limits, or an explicit partner need. Capture first
and model only the evidenced slice.

A provider runtime bundle can be injected into a consumer-owned Docker or
Kubernetes workload. HUD, Harbor, OpenEnv, and custom harnesses remain
downstream: they keep the task and verifier and use the same injection contract
instead of receiving a Datalox world package. A narrow Stripe workflow remains
a construction-machine regression;
specialized-provider work is tracked in
[Provider Behavior Grounding](provider-behavior-grounding.md#current-specialized-harvest-wave).

For parallel agent training, Datalox allocates one isolated provider-state
lease per consumer session. The trainer keeps its normal agent loop, tokens,
rewards, and optimization logic; provider-facing tool code keeps the provider's
exact HTTPS URL. The node-local rollout pool is a delivery mechanism for the
same task-free provider packs, not a Datalox-owned RL environment. The checked
The veRL/GRPO path is documented in
[veRL and GRPO Rollouts](verl-grpo-rollouts.md). The equivalent current
THUDM/slime path is documented in
[THUDM/slime Provider-State Rollouts](slime-rollouts.md).

## Safety boundary

Runtime live provider access is inexpressible for every HTTP method. The
evaluated agent may send provider-shaped authentication headers to the local
simulation; the runtime treats them as simulated inputs, redacts them from
evidence, and never forwards them.

Provider sandbox writes may occur only in a separate manually approved authoring
utility against an exact test account.

## Data and open source

The open-source surface is the runtime, schemas, validators, recipes, and safe
synthetic reference assets. Raw provider captures and compiled behavior programs
are separate data products with explicit distribution classifications.

Open-sourcing the engine does not require publishing the provider-behavior
corpus. See [Data Release Policy](data-release-policy.md).

## Non-goals

Datalox does not own general agent planning or memory, model routing, training
recipes, dataset split management, production provider writes by evaluated
agents, or claims that an ungrounded local transition matches provider behavior.

This boundary keeps the runtime focused: realistic, resettable provider
behavior with durable execution evidence inside worlds owned by others.
