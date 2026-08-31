# Provider Packs

A provider pack is reusable fuel that supplies stateful provider behavior inside
a user-owned world. It is not a benchmark, a complete product workflow, or a
claim of production equivalence.

## Construction-ready pack

A construction-ready pack declares:

- provider identity, version, and selected operation families;
- provider-shaped request and response contracts;
- reads, mutable operations, and explicit denials;
- local transition and verifier atoms where applicable;
- authentication, sandbox, reset, and cleanup boundaries;
- provenance and grounding level per operation;
- known gaps and candidate worlds.

An executable provider runtime bundle additionally declares exact intercepted
authorities, wire codecs, provider-native identity policy, seed/reset
contracts, and content hashes. It must run without a Datalox-owned task,
episode, reward, or world verifier.

The runtime bundle is the deployment unit. It supports two migration protocols
without duplicating existing behavior code:

- `world_v1_adapter` packages a stateful provider implementation and one reset
  seed while dropping task and verifier inputs;
- `gate_config_v1` packages existing HTTP response cases plus deny/shadow
  policy while dropping audits, credentials, MCP, worlds, and live upstreams.

Both are served through the same exact-authority HTTPS data plane. Docker and
Kubernetes injection provide DNS, run-CA trust, startup ordering, and egress
denial. A downstream harness keeps its own world lifecycle and consumes the
trusted state/ledger export through the private control plane.

An admitted runtime bundle becomes distributable as an immutable OCI Provider
Release. The release binds exact operation claims, admission evidence,
invariants, receipt predicates, rights, and one or more reset profiles. A local
registry gives each release an immutable `provider@version` reference. A
registry-backed Provider Set selects only release references and profiles; it
does not accept caller-authored runtime paths.

An ordered provider-set manifest can bind several runtime bundles to a
parallel rollout pool without adding a task or reward:

```bash
datalox-gate rollout provider-set \
  --bundle /opt/datalox/providers/provider-a \
  --bundle /opt/datalox/providers/provider-b \
  --out /opt/datalox/rollout-providers.json
```

Each consumer session receives a private reset provider state and workspace.
The same provider set may be consumed by veRL/GRPO or another training harness;
the harness retains its native loop and training semantics. See
[veRL and GRPO Rollouts](verl-grpo-rollouts.md).

A Provider Set describes independent modules. If real services cause hidden
cross-provider effects, those effects belong in an admitted Composition Pack
with explicit conditional source emission, event delivery, mapping,
delivery-scheduler time, ordering, idempotency, retry, unknown completion, and
compensation behavior. Provider-native clocks remain independent. See
[Provider Foundry and Composition Contract](provider-foundry.md).

The agent does not choose a Datalox actor or role. A stateful bundle either
declares one fixed principal for an intentionally single-principal fixture, or
maps exact commitments of provider-native credentials to declared actor
contexts. Missing and invalid credentials return declared provider-shaped
`4xx` responses. Internal `x-datalox-actor-*` headers are rejected on the data
plane, and credential values never enter behavior state or exported evidence.

For a provider whose native surface is an SDK rather than HTTP, the execution
boundary may supply a provider-specific SDK backend that speaks to the same
HTTPS data plane. Evaluated code must keep the provider's normal SDK methods;
the agent must not select a Datalox tool or rewritten call. The internal adapter
authority must be fixed, non-routable without injection, and explicitly labeled
as a Datalox projection rather than a provider endpoint. The
[PyLabRobot-backed Hamilton STAR pack](pylabrobot-hamilton-star-provider.md) is
the checked example.

Mutable operations must have an executable local transition or an explicit
denial. A documentation response example does not ground write behavior.

## Public-source boundary

The public repository contains the generic runtime and a synthetic commerce
reference world. Provider-derived environments, captures, documentation
snapshots, and compiled behavior programs remain restricted unless every
artifact has a reviewed redistribution basis.

```text
open runtime + schemas + validators + reference fixtures
                         |
                         +-- compiles restricted provider behavior data
                         +-- runs inside customer or partner worlds
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
