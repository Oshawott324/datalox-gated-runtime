# Building Replayable Worlds for Tool-Using Agents

Datalox is building infrastructure for agents that do real work through APIs,
Model Context Protocol servers, and other software tools.

The goal is to make realistic tool use safe, repeatable, stateful, and verifiable:

> Let an agent use tools normally, put a controlled runtime in the call path, and
> turn the resulting execution into a reusable environment.

## Canonical product thesis

Datalox is an API environment company for agents. It is not a biology benchmark,
not a science-first benchmark, not a generic MCP catalog, and not a raw catalog
of mocked endpoints.

The vocabulary is fixed:

- **fuel = reusable provider/API building blocks**;
- **world = a stateful composition of fuel**;
- **benchmark = a downstream consumer of worlds**.

Fuel means reusable, source-grounded gated API building blocks. Worlds compose
fuel; benchmarks consume worlds.

Mocks are raw material. A component becomes valuable when it preserves provider
shape, state, side effects, permissions, failures, and known gaps. An executable
world is the composed evaluation unit:

```text
API world + task pack + policy + state transitions + verifier + replay evidence
```

Datalox provides environment components and executable worlds. External agent
systems decide how an agent plans, manages context, retries, remembers, routes
models, and selects tools.

## Two parallel product surfaces

Two product tasks should advance in parallel:

1. **Construction-ready provider/API packs.** These contain selected operation
   families, provider-shaped reads, local mutations or explicit denials,
   transition and verifier atoms, provenance, known gaps, and target worlds.
2. **Executable worlds.** These compose packs into resettable environments with
   task state, action surfaces, dynamics, hidden verifiers, and run evidence.

Adding packs is not blocked on first building a world. A pack is acceptable when
it is construction-ready. A world is acceptable when it proves composition
through executable state and verifier evidence.

See [Provider Packs](provider-packs.md) for packaging and the data boundary.

## Execution model

```text
task
  -> agent discovers and calls tools
  -> Datalox gates each call
  -> responses, decisions, and state changes are recorded
  -> the final world state is verified
  -> the run becomes replayable evidence
```

The gate makes one explicit decision per call: replay a recorded response; read
or mutate resettable world state; shadow a permitted write; perform an explicitly
authorized live GET; deny an unsafe operation; or return a structured miss.

HTTP and MCP are projections over the same policy and state contracts. MCP is one
projection, not a parallel source of truth.

## What makes a world valuable

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

An admitted world can be projected into external evaluation harnesses without
creating a second state model. HUD and Harbor exports package the same world,
runtime, MCP surface, task, and verifier. They are delivery projections, not
new sources of provider truth. A narrow Stripe workflow remains the first
construction-machine regression, while the active specialized-provider work is
tracked in [Provider Behavior Grounding](provider-behavior-grounding.md#current-specialized-harvest-wave).
Both use the provider-neutral container and agent/controller boundary fixed in
[Portable World Packages](world-packages.md); neither makes Stripe the product
or the default next provider.

## Safety boundary

Runtime live writes are inexpressible. Live GETs require an allowlisted policy
rule and an explicit operator flag. Credentials are injected by the gate and
agent-supplied authentication headers are never forwarded.

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

This boundary keeps the runtime focused: realistic, resettable software worlds
with durable execution evidence.
