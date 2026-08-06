# Provider Packs

A provider pack is reusable fuel for constructing Datalox worlds. It is not a
benchmark, a complete product workflow, or a claim of production equivalence.

## Construction-ready pack

A construction-ready pack declares:

- provider identity, version, and selected operation families;
- provider-shaped request and response contracts;
- reads, mutable operations, and explicit denials;
- local transition and verifier atoms where applicable;
- authentication, sandbox, reset, and cleanup boundaries;
- provenance and grounding level per operation;
- known gaps and candidate worlds.

Mutable operations must have an executable local transition or an explicit
denial. A documentation response example does not ground write behavior.

## Public-source boundary

The public repository contains the generic runtime and a synthetic commerce
reference world. Provider-derived environments, captures, documentation
snapshots, and compiled behavior programs remain restricted unless every
artifact has a reviewed redistribution basis.

```text
open runtime + schemas + validators + reference world
                         |
                         +-- compiles restricted provider behavior data
                         +-- composes customer or partner worlds
```

Public summaries may disclose provider names, capability families, grounding
labels, known gaps, and content hashes without publishing raw payloads or
complete business-logic programs.

## Adding a provider

1. Reuse an existing pack or connector before creating a new one.
2. Audit the official sandbox, developer tenant, fixtures, event access, and
   reset boundary.
3. Select the smallest complete operation-family scope useful for a target world.
4. Declare all selected reads, writes, denials, and gaps.
5. Harvest complete behavior programs where provider writes are needed.
6. Keep provider writes outside the runtime.
7. Classify every resulting artifact before committing it.

See [Provider Core Completeness](provider-core-completeness.md),
[Provider Behavior Grounding](provider-behavior-grounding.md), and
[Data Release Policy](data-release-policy.md).
