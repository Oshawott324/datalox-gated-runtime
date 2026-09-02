# Transparent Interception Contract

This document defines the execution contract of `datalox-gated-runtime`.
`product-contract.json` is the machine-readable source of truth.

## Product invariant

The user owns the world. That includes the task, agent, verifier, and reward.
Datalox supplies stateful provider behavior in the call path.

During rollouts, ownership also follows the
[`rollout information boundary`](rollout-information-boundary.md). Task input,
causal environment observations, and trusted evaluation ground truth have
separate carriers. Transparent interception changes where provider traffic is
served; it never turns a provider response into initial task text or exposes
verifier truth to the agent.

The agent keeps the exact provider URL.

```text
agent-visible request:  https://api.provider.example/v1/orders
network destination:    Datalox inside the isolated execution boundary
provider network calls: zero
```

For SDK-only providers that have no provider URL, the equivalent invariant is
that evaluated code keeps the native SDK method surface. The consumer's
execution boundary selects a Datalox backend whose closed internal HTTPS
projection uses a reserved non-routable authority. The agent does not select a
Datalox tool or rewrite its calls. See the
[PyLabRobot-backed Hamilton STAR provider](pylabrobot-hamilton-star-provider.md).

Datalox is not the task environment or benchmark. A Datalox reference world is
an integration fixture used to prove that provider packs compose; it is not a
primary distribution unit.

## Runtime and authoring separation

Runtime execution is offline with respect to protected providers. It may
accept inbound agent traffic and write run-private state and evidence, but it
must not open a provider connection. Unknown hosts and operations fail closed.
The runtime has no provider network path.

Provider access belongs only to explicit authoring commands used to acquire and
review behavior evidence. Authoring output may be compiled into a provider
behavior pack after data classification and review.

## Data plane

The provider-facing data plane preserves scheme, authority, method, raw and
decoded path, ordered query values, headers, media type, and body bytes until
the declared wire codec runs. The v1 bundle contract currently admits only the
strict `standard_http_v1` codec for JSON, form, text, and explicitly enveloped
binary responses; unsupported request media types fail closed.

The data plane returns provider-shaped responses. Datalox decisions, event IDs,
state exports, reset controls, health details, and finalization stay on the
trusted control plane and are not injected into successful provider responses.

A consumer may place a controller-fixed
[delivery intervention](delivery-interventions.md) after an admitted provider
runtime. Provider behavior and its ledger remain the base truth. The consumer's
seeded intervention decision and the exact observation delivered to the agent
are recorded in a separate trace and never presented as provider grounding.
With intervention mode `off`, the same counterfactual decision is recorded while
the base response is returned unchanged. The agent cannot select the policy,
seed, mode, or logical request index.

Identity follows the provider-shaped request, not an agent-selected Datalox
role. Each stateful runtime bundle contains an `identity.json` policy. A fixed
policy is sufficient for a single-principal fixture. A multi-principal pack
maps exact SHA-256 commitments of provider-native headers, cookies, or query
credentials to declared actor contexts and retains the provider-observed
missing/invalid identity responses. Credential values are removed before
behavior execution and ledger recording.

Every `x-datalox-*` name belongs to the internal control namespace. Such
headers are rejected on the agent data plane, so an agent
cannot promote itself by adding a role header. Trusted framework projections
use the runtime's internal actor invocation path and never put Datalox identity
headers on the simulated provider wire.

## Execution unit

The executable unit is a provider runtime bundle. It declares:

- exact provider authorities;
- provider-shaped routes and one declared wire protocol;
- resettable state and seed contracts;
- transition, failure, duplicate, and idempotency behavior;
- provenance, grounding, and known gaps; and
- content hashes for every runtime file.

It must not require a task, episode, reward, or world verifier. It also does not
require an agent or benchmark.

## Deployment boundary

DNS and TLS terminate at Datalox inside an isolated execution boundary.
Transparent HTTPS execution requires that controlled network boundary. The
Datalox launcher or a harness adapter supplies:

- provider-domain resolution to the Datalox gateway;
- a run-scoped certificate authority trusted inside the agent container;
- provider egress denial; and
- a controller-only channel for state and ledger export.

Docker and Kubernetes are the first concrete delivery integrations. OpenEnv,
HUD, Harbor, and other harnesses remain downstream consumers: they retain their
world lifecycle and place the same Datalox gateway beside the agent workload.
They do not receive a Datalox-owned task or verifier.

Provider Releases, Provider Sets, and Composition Packs preserve this same data
plane. A Provider Set only co-hosts independent modules. A provider-mediated
webhook or background integration executes only when an exact Composition Pack
and its derived admission are mounted on the controller side. The agent still
sees only the provider authorities.

## Compile a provider runtime

Existing stateful behavior can be migrated without rewriting its implementation:

```bash
datalox-gate provider build-runtime \
  --source-world envs/openlmis_supply_chain_v0 \
  --episode-id openlmis-supply-chain-001 \
  --provider-id openlmis \
  --authority api.openlmis.example \
  --identity-policy ./openlmis-identity.json \
  --out /tmp/openlmis-provider
```

The optional identity policy is validated against the world's declared roles
and the strict
[`schemas/provider-identity-v1.schema.json`](../schemas/provider-identity-v1.schema.json)
contract. Omit it only when every intercepted request intentionally runs as the
world's one fixed default principal. The file stores credential digests, never
credential values.

Existing replay, denial, and shadow-policy assets use the same bundle contract:

```bash
datalox-gate provider build-runtime \
  --source-gate-config envs/documented_datadog_v0/gate_config.json \
  --provider-id datadog \
  --authority api.datadoghq.com \
  --out /tmp/datadog-provider
```

The authority is exact and deployment-specific. Do not replace it with a
Datalox hostname. Compilation excludes task, verifier, reward, audit, MCP,
credential, and live-provider files and exposes only provider initialization,
route mapping, and request handling from a legacy world implementation. The
loader enforces the same strict contract documented in
[`schemas/provider-runtime-v2.schema.json`](../schemas/provider-runtime-v2.schema.json)
and verifies every content hash before execution.

Two behavior protocols currently reuse the repository's existing sources:

| Protocol | Input | Runtime behavior |
| --- | --- | --- |
| `world_v1_adapter` | Stateful provider implementation plus one reset seed | Provider-shaped reads, transitions, failures, and resettable state |
| `gate_config_v1` | HTTP response cases plus deny/shadow policy | Deterministic replay, explicit denials, and declared shadow writes |

The protocol is a capability statement, not a grounding label. A compiled G1
documentation example remains G1, and an unobserved local write remains
unobserved.

## Export container injection

Build the base runtime once, then export an authority-bound provider image
context and workload patch:

```bash
docker build -t datalox-runtime:local .

datalox-gate intercept export \
  --bundle /tmp/openlmis-provider \
  --target docker \
  --runtime-image datalox-runtime:local \
  --provider-image datalox-openlmis:local \
  --out /tmp/openlmis-docker

docker build \
  -f /tmp/openlmis-docker/Dockerfile.provider-runtimes \
  -t datalox-openlmis:local \
  /tmp/openlmis-docker
```

Merge `agent-service.fragment.json` into the consumer-owned Compose project.
The generated network is internal, the gateway receives the exact provider DNS
alias, and the agent receives only the public run CA. The control token,
gateway key, state, and ledger stay on a separate private volume. The agent
starts only after the private control plane reports the gateway healthy.
Every intercepted provider hostname is added to both `NO_PROXY` and
`no_proxy`, so an operator-level proxy can still serve model traffic without
receiving provider requests.

For an existing Kubernetes Deployment:

```bash
datalox-gate intercept export \
  --bundle /tmp/openlmis-provider \
  --target kubernetes \
  --runtime-image ghcr.io/example/datalox-runtime@sha256:<digest> \
  --provider-image ghcr.io/example/datalox-openlmis@sha256:<digest> \
  --agent-container agent \
  --out /tmp/openlmis-kubernetes
```

Apply the generated strategic-merge patch and NetworkPolicy in the consumer's
namespace. The patch uses Kubernetes native sidecar startup ordering (1.29+),
maps provider authorities to loopback, injects common CA environment variables,
and mounts no controller secret into the agent. The NetworkPolicy permits DNS
and an explicitly labeled in-cluster model gateway; it denies other pod egress,
including real provider addresses.

Runtimes whose TLS stack does not honor the injected PEM environment variables
must import the same run CA into their native trust store. That trust step is
the only agent-image-specific integration; request code and provider base URLs
remain unchanged.

## Parallel rollout leases

Training systems commonly run many agent loops as coroutines in a shared Ray
worker. Process-wide DNS or CA mutation cannot isolate those siblings. The
generic rollout pool therefore gives every consumer `(uid, session_id)` one
private provider-state lease, internal Docker network, and workspace. A
provider-facing function tool submits a command through a trusted node-local
Unix socket; a transient allowlisted task container executes the unchanged
provider HTTPS request inside that lease.

The pool manifest is an ordered set of content-addressed task-free provider
runtime bundles. The pool owns neither the task image's tool semantics nor the
trainer's agent loop, tokens, verifier, reward, or advantage calculation. The
model cannot select the task image, provider set, lease, Datalox endpoint, or
control operation.

The checked veRL/GRPO adapter keeps veRL's own `ToolAgentLoop` and returns its
`AgentLoopOutput` unchanged. The checked THUDM/slime adapter keeps slime's
native custom-generation and reward hooks and returns the exact `Sample` or
`list[Sample]` produced by user code. See
[veRL and GRPO Rollouts](verl-grpo-rollouts.md) and
[THUDM/slime Provider-State Rollouts](slime-rollouts.md).

## Trusted control plane

The data plane exposes only provider paths. Health, reset, state, and ledger
export are available solely over a mode-`0600` Unix socket with a run-scoped
token:

```text
GET  /health
GET  /v1/providers/{provider_id}/export
POST /v1/providers/{provider_id}/reset
```

The evaluated agent receives neither that socket nor its token. A harness may
reset between rollouts and pass the exported state and ledger to its own
verifier without giving Datalox ownership of the task or reward.

## Checked repository coverage

In the full source superset,
`python scripts/check_provider_runtime_coverage.py --check` recompiles every
registered provider-scoped asset one by one. In the public source tree,
`python scripts/check_provider_runtime_coverage.py --validate-report` validates
the released report without requiring the controlled provider corpus. The
report currently records 49 of 49 provider assets passing task-free compilation
and reset: 18 stateful `world_v1_adapter` sources and 31 `gate_config_v1`
sources. The two cross-provider reference worlds are excluded because they are
consumer-side compositions. See
[`docs/reports/provider-runtime-coverage.json`](reports/provider-runtime-coverage.json).

This is compilation coverage only. It does not upgrade core completeness,
provider-write evidence, or behavioral faithfulness.
