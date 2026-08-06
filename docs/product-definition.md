# Product Definition

`datalox-gated-runtime` is the call-path runtime for making normal agent tool
use safe, replayable, and verifiable.

The company/product thesis lives in
[Building Replayable Worlds for Tool-Using Agents](what-we-are-building.md).
The fixed product vocabulary and public provider-pack boundary live in
[Provider Packs](provider-packs.md). This file defines the runtime
boundary. Do not reinterpret this repo as a
bio-first benchmark, a generic MCP catalog, or a catalog of mocked endpoints.
Mocked and replayed APIs are inputs to stateful, verifiable API worlds.

In this project, **fuel means reusable gated API building blocks**. A world
composes fuel and a benchmark consumes worlds. The runtime must serve and
compile the building blocks without pretending that benchmark construction is
the same product task.

## Repository Role

This repo is the execution substrate. It consumes compiled environment
artifacts and exposes safe HTTP/MCP call paths for agents or external agent
systems.

The repository also carries a small construction skill, admission command,
evaluation-report utility, and admitted reference worlds. These are executable
interoperability and regression surfaces for the compiled contract; they do
not move broad provider-pack curation, customer-specific world authoring, or
hosted benchmark operations into the runtime product boundary.

Adjacent layers have separate ownership:

- provider/API packs own operation families, source-grounded API shapes,
  reusable transition atoms, reusable verifier atoms, reusable reward atoms,
  provenance, known gaps, and target worlds. Pack expansion is valid platform
  work, but it is not runtime work;
- world-construction repos compose provider/API packs into tasks, episodes,
  hidden state, world-level verifiers, and reward schedules;
- customer agent systems own planning loops, context management, retries,
  memory, model routing, and tool-selection strategy;
- rollout collectors own run aggregation, split assignment, quality labels,
  eval reports, and training rows.

Separate ownership does not mean provider/API packs are not product. It means
this runtime owns their safe compiled execution contract while broad pack
research and canonical authoring remain in the adjacent pack layer.

## Definition

The runtime gates API/tool calls made by an agent. It can replay captured
responses, return mocked responses grounded in source evidence, shadow-write
state changes, deny dangerous calls, record the full session ledger, and export
evidence for audits, evals, SFT, and future RL.

```text
task brief
  -> agent chooses and calls tools
  -> gated runtime handles each call
  -> call ledger and shadow state emerge
  -> post-run audit/verifier judges outcome
  -> run_export evidence
```

## What This Repo Owns

- call request/response contracts
- policy decisions
- response replay from captured cases
- shadow write ledger
- blocked-call error contracts
- session ledger
- post-run audit primitives
- run export shape
- adapters that sit in the call path
- promotion and replay verification for compiled environments
- source-pack imports that become replay environments
- traffic-derived environment artifacts and provenance metadata
- interface projections, including MCP tools, over existing workflow-shaped
  state and provider-shaped contracts
- strict loading and run-private execution of hashed `world_bundle_v1`
  artifacts
- provider-neutral, single-episode OCI packages that expose a fixed gated MCP
  endpoint and reserve finalization for the trusted controller
- thin HUD and Harbor delivery adapters over the canonical package
- generic actor, transaction, artifact, simulation-clock, conversation, and
  handoff primitives
- deterministic/optional-semantic verifier composition and reference world
  admission
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
- live provider execution without explicit approval

Provider core completeness does not add a live-write mode or move broad
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

## Why Verifiers Still Matter

The gate decides what happens for each call. It does not by itself decide
whether the agent solved the task correctly.

```text
gate: "POST /assay-results was shadow-written"
audit: "the result used stale evidence and should fail"
```

Post-run audits should inspect the task brief, call trace, shadow state,
policies, source evidence, and final artifacts.

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
