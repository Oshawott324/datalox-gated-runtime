# API Component and World Admission Rubric

This rubric keeps two different product-readiness questions separate:

1. Is a provider/API component reusable and construction-ready?
2. Is a composed world ready for agent evaluation or Agent CI?

A component does not need benchmark episodes to be product fuel. A world does
need stateful tasks and hidden verification. Do not reject a useful provider
pack merely because it is not a world, and do not call a raw replay case a
construction-ready pack merely because it executes.

## Registry Is Not Admission

`envs/registry.json` is an executable-asset inventory. It includes API shape
maps, replay assets, and admitted world candidates. Inclusion proves only the
declared layer. It does not upgrade grounding, pack readiness, or world
readiness.

The legacy registry `fidelity_passed` field records replay completion only. A
replay-complete asset can still be shallow, provider-incomplete, or weakly
grounded. Likewise, `world_admission.json` proves the composed world contract,
not provider core completeness. Provider core declarations and their strict
machine pass are defined separately in
[Provider Core Completeness](provider-core-completeness.md).

Provider-pack scope and the public data boundary are in
[Provider Packs](provider-packs.md).

## Endpoint Asset Levels

### `api_shape_map`

Use for static provider-shaped response cases that preserve endpoint paths,
request shape, response shape, and source provenance.

Minimum bar:

- provider-shaped response cases;
- an honest grounding label such as G1 documented or schema-derived;
- replay verification passes;
- no claim of observed permissions, pagination, errors, tenant state, or side
  effects unless separately grounded.

This is executable API fuel. It is not yet a construction-ready pack or a
product-quality world.

### `replay_asset`

Use for captured or probed replay environments that add traffic evidence,
audit rules, or permitted shadow outputs but do not yet expose reusable
state-transition contracts.

Minimum bar:

- replay verification passes;
- source/probe provenance is recorded;
- audit rules or required-call checks exist when the task requires them;
- replay needs no provider credential.

This is stronger API fuel and source material. It is not automatically a
construction-ready pack or stateful world.

### Construction-ready provider/API pack

This is a product building block, not a registry `intended_use` value. It may be
admitted independently of any benchmark.

Minimum bar:

- connected operation families rather than an isolated endpoint count;
- provider-shaped reads;
- explicit shadow-write candidates and explicit denied operations;
- reusable transition atoms;
- reusable verifier and reward atoms;
- source provenance and grounding per supported claim;
- known behavior gaps;
- target-world links or composition tests;
- stable request, response, and error contracts;
- no credential requirement for replay and no live-write path.

The pack may remain a provider/API component indefinitely. It does not have to
be promoted into a benchmark to remain valid product work.

### Core-complete provider scope

Use `core_complete` only when the checked provider-core evaluator passes every
declared, official-source-grounded family and capability. Mutable providers
need provider-shaped local writes with read-after-write, reset, and
negative/atomicity evidence. Officially read-only providers need source-grounded
read-only scope; non-mutating POST/query/job/process operations still require
local replay. No primary family may be excluded and no blocking gap may remain.

The result is machine-derived and absent from the declaration. Acceptance must
also review the official surface for omitted primary families, because a
declaration cannot prove its own scope completeness.

## World Level

### `agent_ci_candidate`

Use for resettable stateful worlds that compose API building blocks into
private evaluation or Agent-CI workflows.

Minimum bar:

- concrete task episodes;
- resettable per-session state;
- provider-shaped reads;
- permitted writes with read-after-write semantics;
- denied unsafe actions;
- hidden expected state or verifier inputs unavailable to the agent;
- verification of final state and required/forbidden process evidence;
- run exports with task, ledger, verifier outcome, and failure details;
- positive and negative trajectory tests.

## Construction-Ready Pack Checklist

Accept a pack as construction-ready only when:

- another construction agent can discover the supported operations and gaps;
- its replay, mutation, denial, and verification atoms are reusable without
  copying an entire world implementation;
- grounding strength is attached to claims rather than inferred from provider
  name or endpoint count;
- at least one composition test or target world demonstrates the contract;
- the pack remains credential-free during replay and cannot express live
  writes.

## Product-Quality World Checklist

Accept a world only when:

- it has realistic task families, not isolated endpoint calls;
- state transitions matter for task success;
- verifiers fail plausible wrong paths;
- agent-visible state is separated from hidden verifier state;
- replay fidelity is distinct from task correctness;
- grounding level and provenance are recorded for every source family;
- HTTP, MCP, or both project over the same state;
- positive and negative trajectory regressions pass.

## Rejection Rules

Reject an artifact as a **construction-ready pack** if it only counts mocked
endpoints, lacks reusable mutation/denial/verifier atoms, or hides grounding
gaps.

Reject an artifact as a **product-quality world** if it only validates
request/response shape, has no task-specific final-state invariant, exposes
hidden values, requires live writes, cannot reset without credentials, or
claims G1 examples prove production behavior.

The same artifact may still remain useful at its honest lower layer.

## Parallel Promotion Paths

```text
documentation / source pack / capture
  -> replay-verified gated response cases
  -> construction-ready provider/API pack

construction-ready packs
  -> composed resettable world
  -> admitted Agent-CI/private-eval world
```

Do not force every pack to become a world. Do not use world or benchmark work
as a substitute for missing reusable API components. Worlds are composition
proofs and downstream products built from the fuel.
