# Product Definition

`datalox-gated-runtime` is the transparent call-path runtime that returns
stateful, provider-grounded responses without contacting the protected provider
during evaluated-agent execution.

The company/product thesis lives in
[Building Replayable Worlds for Tool-Using Agents](what-we-are-building.md).
The fixed product vocabulary and public provider-pack boundary live in
[Provider Packs](provider-packs.md). This file defines the runtime
boundary. Do not reinterpret this repo as a
bio-first benchmark, a generic MCP catalog, or a catalog of mocked endpoints.
Mocked and replayed APIs are inputs to stateful provider behavior packs consumed
by user-owned worlds.

In this project, **fuel means reusable gated provider behavior packs**. A
consumer-owned world composes fuel. The runtime serves and compiles the packs;
it does not own benchmark construction.

## Repository Role

This repo is the execution substrate. It consumes compiled provider runtime
bundles and transparently terminates provider-shaped HTTPS calls made inside an
isolated user-owned environment.

The repository also carries construction utilities and reference worlds. These
are interoperability and regression fixtures for the compiled contract; they
do not make customer-specific world authoring or hosted benchmark operations a
runtime product surface.

Adjacent layers have separate ownership:

- provider/API packs own operation families, source-grounded API shapes,
  reusable transition atoms, provenance, known gaps, and target use cases.
  Pack expansion is valid platform
  work, but it is not runtime work;
- consumer world-construction repos compose provider/API packs into tasks,
  episodes, hidden state, world-level verifiers, and reward schedules;
- customer agent systems own planning loops, context management, retries,
  memory, model routing, and tool-selection strategy;
- rollout collectors own run aggregation, split assignment, quality labels,
  eval reports, and training rows.

Parallel training frameworks may consume the runtime through isolated rollout
leases. The lease is only the provider-state execution boundary: the framework
keeps its native agent loop, token stream, rewards, grouping, advantages, and
optimizer behavior. See [veRL and GRPO Rollouts](verl-grpo-rollouts.md).

Separate ownership does not mean provider/API packs are not product. It means
this runtime owns their safe compiled execution contract while broad pack
research and canonical authoring remain in the adjacent pack layer.

## Definition

The runtime gates API/tool calls made by an agent. It can replay captured
responses, return mocked responses grounded in source evidence, shadow-write
state changes, deny dangerous calls, record the full session ledger, and export
evidence for audits, evals, SFT, and future RL.

```text
consumer task/world
  -> agent calls the unchanged provider URL
  -> isolated DNS/TLS sends the request to Datalox
  -> provider runtime handles the call against resettable state
  -> trusted controller exports the ledger and state
  -> consumer verifier/reward judges the outcome
```

## What This Repo Owns

- call request/response contracts
- policy decisions
- provider-native identity resolution into declared simulated roles
- response replay from captured cases
- shadow write ledger
- blocked-call error contracts
- session ledger
- post-run evidence primitives
- run export shape
- adapters that sit in the call path
- promotion and replay verification for compiled provider behavior
- source-pack imports that become replay environments
- traffic-derived environment artifacts and provenance metadata
- interface projections, including MCP tools, over existing workflow-shaped
  state and provider-shaped contracts
- strict loading and run-private execution of hashed provider-runtime bundles
- provider-neutral OCI/container injection artifacts that preserve the agent's
  normal provider URL and reserve reset/export for the trusted controller
- Docker and Kubernetes injection artifacts over that same provider runtime;
  HUD, Harbor, OpenEnv, and custom harnesses consume those artifacts without
  moving their task or verifier into Datalox
- ordered task-free provider sets and one private provider-state/workspace lease
  per consumer rollout session, exposed only through a trusted node-local Unix
  socket
- immutable admitted OCI Provider Releases and a registry that resolves exact
  provider release profiles without caller-authored runtime paths
- explicit provider-mediated Composition Packs with deterministic delivery
  time, conditional source emission, ordered events, idempotency, retry,
  unknown completion, and compensation; authored packs remain non-executable
  until their behavioral admission passes
- generic actor, transaction, artifact, simulation-clock, conversation, and
  handoff primitives
- reference-world admission used only for integration regression
- a local report generator that aggregates completed run exports without
  owning an agent planning loop
- a checked provider-core coverage evaluator that derives per-provider status
  from source-grounded operation, mutation, replay, readback, reset, negative,
  and gap evidence without treating replay or world admission as completeness

## What This Repo Does Not Own

- model routing
- customer agent harness internals such as context management, retries, memory,
  planners, or tool-selection policy
- generic API aggregation
- canonical provider/API pack authoring
- broad world construction operations, customer task-pack ownership, or
  hosted reward-schedule curation beyond the reference interoperability path
- mocked endpoint catalogs without stateful tasks and verifiers
- domain applications or benchmark definitions that assume workflows must move
  into Datalox-owned MCP apps
- open-ended provider research or source-pack curation that is not grounded in
  captured traffic, explicit source packs, provider docs, contracts, or
  test-mode probes
- dataset manifests or train/dev/test splits
- model training recipes
- mutation of consumer training outputs, tokens, masks, log probabilities,
  rewards, rollout grouping, advantages, or optimizer behavior
- any live provider execution in the evaluated-agent runtime
- agent-selected Datalox actors, roles, or internal identity headers
- ownership of HUD, Harbor, OpenEnv, or another harness's world lifecycle

Provider core completeness does not add a live-provider mode or move broad
provider research into this runtime. It validates compiled declarations against
their official-source-grounded scope. Human acceptance remains responsible for
rejecting a declaration that omitted a primary provider family. See
[Provider Core Completeness](provider-core-completeness.md).

## Why Not Premade Gyms Only

Premade gyms are too rigid for many real workflows. The natural user flow is:

```text
user gives task
agent acts normally
Datalox gates the calls
the session becomes a replayable environment artifact
```

The gym is often the output of gated execution, not the starting point.

## Why Consumer Verifiers Still Matter

The gate decides what happens for each call. It does not by itself decide
whether the agent solved the task correctly.

```text
gate: "POST /assay-results was shadow-written"
audit: "the result used stale evidence and should fail"
```

Consumer verifiers can inspect the task brief, exported call trace, provider
state, policies, source evidence, and final artifacts. Datalox may provide
reusable evidence predicates, but does not own the final reward.

## First Runtime Modes

```text
replay
  Return a captured response case.

shadow_write
  Accept a write into session state without touching the live provider.

deny
  Block a call with a structured error.

miss
  Record an unknown call for later capture or source-pack work.
```
