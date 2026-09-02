<div align="center">

# Datalox Gated Runtime

### Provider-grounded API behavior on the agent's normal call path

**Let an agent call the provider's real URL while an isolated Datalox runtime
returns stateful simulated behavior without contacting that provider.**

[Product thesis](docs/what-we-are-building.md) ·
[Provider packs](docs/provider-packs.md) ·
[Provider foundry](docs/provider-foundry.md) ·
[Transparent interception](docs/transparent-interception.md) ·
[Delivery interventions](docs/delivery-interventions.md) ·
[Rollout information boundary](docs/rollout-information-boundary.md) ·
[Behavior grounding](docs/provider-behavior-grounding.md) ·
[Behavior harvest](docs/provider-behavior-grounding.md#current-specialized-harvest-wave) ·
[Container injection](docs/transparent-interception.md#export-container-injection) ·
[veRL / GRPO](docs/verl-grpo-rollouts.md) ·
[THUDM/slime](docs/slime-rollouts.md) ·
[Runtime schema](schemas/provider-runtime-v2.schema.json) ·
[Identity schema](schemas/provider-identity-v1.schema.json)

</div>

> The user owns the task, world, agent, verifier, and reward. Datalox supplies
> resettable provider behavior underneath the API URLs their agent already uses.

During a rollout, the agent starts with the task objective and visible
constraints. Provider responses and environment anomalies appear only after
the causal interaction that reveals them. Evaluation ground truth remains in
trusted generator, oracle, and verifier code.

Most tool benchmarks ask whether a model can answer a question or complete one
API call. Real work is longer. It crosses roles and systems, creates related
objects, waits for asynchronous jobs, encounters conflicts, and leaves durable
state behind. A plausible final message does not prove that the workflow was
correct.

Datalox provides the provider-behavior substrate for testing that work.

```text
user-owned world/task/verifier
  -> agent calls https://api.provider.example normally
  -> isolated DNS/TLS routes that authority to Datalox
  -> provider-native credentials select a declared simulated principal
  -> Datalox returns provider-shaped reads, writes, failures, and state changes
  -> the ledger records decisions, responses, and side effects
  -> the user's harness judges the run
```

## What Datalox is—and is not

| Datalox is | Datalox is not |
| --- | --- |
| An open runtime for provider-shaped, stateful API behavior | A proxy for production API access |
| A way to inject reusable provider behavior into user-owned worlds | A directory of disconnected mocked endpoints |
| A call-path, state, and evidence layer for agent workflows | A world, task, verifier, agent, or model framework |
| A sandbox-first path for learning provider behavior | A claim that documentation examples reproduce production behavior |
| Infrastructure that benchmarks can run on | One benchmark or one vertical application |

The vocabulary is deliberate:

- **Fuel** is a reusable gated provider/API building block: operation contracts,
  behavior recipes, transitions, verifier atoms, provenance, and known gaps.
- **A world** is owned by the consumer and composes fuel with its tasks,
  dynamics, verifier, and reward.
- **A benchmark** is a downstream consumer-owned evaluation.

Fuel is not a benchmark. Datalox reference worlds are integration fixtures, not
the primary product. World admission is not automatically proof of provider
equivalence.

Fuel has two explicit composition levels:

- A **Provider Set** co-hosts independently admitted provider releases. The
  evaluated agent may read one provider and explicitly call another.
- An admitted **Composition Pack** supplies observed provider-mediated behavior
  such as webhooks, transforms, delays, retries, ordering, idempotency, partial
  failure, and compensation. Merely placing providers together never creates
  those hidden causal edges.

See [Provider Foundry and Composition Contract](docs/provider-foundry.md).

## Provider-shaped surfaces already represented

The current inventory spans infrastructure, business operations, healthcare,
science, and other specialized systems. Every tile below links to a public probe
declaration or grounding contract that can be inspected in this repository.

<div align="center">

### Infrastructure and observability

<table>
  <tr>
    <td align="center" width="120"><a href="probes/kubernetes_local.json"><img src="https://cdn.simpleicons.org/kubernetes/326CE5" width="40" alt="Kubernetes"/><br/><sub><b>Kubernetes</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/docker_engine.json"><img src="https://cdn.simpleicons.org/docker/2496ED" width="40" alt="Docker"/><br/><sub><b>Docker</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/opensearch.json"><img src="https://cdn.simpleicons.org/opensearch/005EB8" width="40" alt="OpenSearch"/><br/><sub><b>OpenSearch</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/grafana_oss.json"><img src="https://cdn.simpleicons.org/grafana/F46800" width="40" alt="Grafana"/><br/><sub><b>Grafana</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/datadog.json"><img src="https://cdn.simpleicons.org/datadog/632CA6" width="40" alt="Datadog"/><br/><sub><b>Datadog</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/sentry.json"><img src="https://cdn.simpleicons.org/sentry/362D59" width="40" alt="Sentry"/><br/><sub><b>Sentry</b></sub><br/><sub>Probe surface</sub></a></td>
  </tr>
</table>

### Business operations

<table>
  <tr>
    <td align="center" width="120"><a href="docs/provider-behavior-grounding.md#stripe-checkpoint"><img src="https://cdn.simpleicons.org/stripe/635BFF" width="40" alt="Stripe"/><br/><sub><b>Stripe</b></sub><br/><sub>Regression only</sub></a></td>
    <td align="center" width="120"><a href="probes/shopify_admin.json"><img src="https://cdn.simpleicons.org/shopify/7AB55C" width="40" alt="Shopify"/><br/><sub><b>Shopify</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/hubspot_crm.json"><img src="https://cdn.simpleicons.org/hubspot/FF7A59" width="40" alt="HubSpot"/><br/><sub><b>HubSpot</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/jira_cloud.json"><img src="https://cdn.simpleicons.org/jira/0052CC" width="40" alt="Jira"/><br/><sub><b>Jira</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/google_workspace.json"><img src="https://cdn.simpleicons.org/google/4285F4" width="40" alt="Google Workspace"/><br/><sub><b>Google Workspace</b></sub><br/><sub>Probe surface</sub></a></td>
    <td align="center" width="120"><a href="probes/microsoft_graph.json"><img src="docs/assets/provider-tiles/microsoft-graph.svg" width="40" alt="Microsoft Graph"/><br/><sub><b>Microsoft Graph</b></sub><br/><sub>Probe surface</sub></a></td>
  </tr>
</table>

### Healthcare, science, and specialized operations

<table>
  <tr>
    <td align="center" width="120"><a href="probes/hapi_fhir.json"><img src="docs/assets/provider-tiles/hapi-fhir.svg" width="40" alt="HAPI FHIR"/><br/><sub><b>HAPI FHIR</b></sub><br/><sub>Healthcare</sub></a></td>
    <td align="center" width="120"><a href="probes/openfda.json"><img src="docs/assets/provider-tiles/openfda.svg" width="40" alt="openFDA"/><br/><sub><b>openFDA</b></sub><br/><sub>Regulatory data</sub></a></td>
    <td align="center" width="120"><a href="probes/clinical_trials_gov.json"><img src="docs/assets/provider-tiles/clinical-trials.svg" width="40" alt="ClinicalTrials.gov"/><br/><sub><b>ClinicalTrials.gov</b></sub><br/><sub>Clinical research</sub></a></td>
    <td align="center" width="120"><a href="probes/rcsb_pdb.json"><img src="docs/assets/provider-tiles/rcsb-pdb.svg" width="40" alt="RCSB PDB"/><br/><sub><b>RCSB PDB</b></sub><br/><sub>Structural biology</sub></a></td>
    <td align="center" width="120"><a href="probes/opentrons_local.json"><img src="docs/assets/provider-tiles/opentrons.svg" width="40" alt="Opentrons"/><br/><sub><b>Opentrons</b></sub><br/><sub>Lab automation</sub></a></td>
    <td align="center" width="120"><a href="docs/pylabrobot-hamilton-star-provider.md"><img src="docs/assets/provider-tiles/hamilton-star.svg" width="40" alt="Hamilton STAR"/><br/><sub><b>Hamilton STAR</b></sub><br/><sub>Core-complete dry-run</sub></a></td>
  </tr>
  <tr>
    <td align="center" width="120"><a href="probes/nasa_cmr.json"><img src="https://cdn.simpleicons.org/nasa/E03C31" width="40" alt="NASA CMR"/><br/><sub><b>NASA CMR</b></sub><br/><sub>Earth science</sub></a></td>
  </tr>
</table>

</div>

Presence in this grid means that a provider or project is represented by a
probe, connector, capture path, pack, or world input. It does **not** mean that
every core operation is implemented, provider writes were observed, provider
data is publicly redistributed, or a local world is production-equivalent.
Those are separate, checked claims described in
[Provider Core Completeness](docs/provider-core-completeness.md) and
[Provider Behavior Grounding](docs/provider-behavior-grounding.md).

Provider names and logos belong to their respective owners and do not imply
affiliation or endorsement. Brand icons are served by
[Simple Icons](https://simpleicons.org/); neutral specialized-domain tiles in
[`docs/assets/provider-tiles/`](docs/assets/provider-tiles/) are self-authored
and are not official provider logos.

## What is open source

The Apache-2.0 release contains:

- the HTTP and MCP gating runtime;
- policy, replay, shadow-state, denial, ledger, and audit primitives;
- versioned provider-pack, behavior-recipe, and provider-runtime contracts;
- validators, compilers, admission checks, and verifier composition;
- public probe declarations and capture utilities;
- synthetic reference fixtures for interoperability and regression; and
- a deterministic public-source builder and release gate.

Raw provider responses, credentials, tenant identifiers, sandbox transcripts,
and compiled provider behavior programs are not automatically open data. They
remain excluded unless each artifact has an explicit redistribution basis and
passes the public-data gate. Open source users can capture and compile their own
authorized provider packs without publishing those payloads.

See [Data Release Policy](docs/data-release-policy.md) for the exact boundary.

## What happens on every tool call

The runtime makes one explicit decision:

| Decision | Observable behavior |
| --- | --- |
| `replay` | Return a declared captured or synthetic response case. |
| `shadow_read` | Read provider-shaped data from resettable local state. |
| `shadow_write` | Apply a deterministic local transition and record its side effects. |
| `deny` | Reject an unsafe or unsupported call with an agent-readable error. |
| `miss` | Record an unknown call so the environment can be extended deliberately. |

All live provider access is inexpressible in evaluated-agent execution.
Approved sandbox reads and writes belong to a separate, manually authorized
behavior-authoring process against an exact test account.

For stateful packs, identity is also provider-shaped. A fixed single-principal
policy or an explicit mapping from provider-native credential commitments to
declared roles lives in the runtime bundle. Agent requests containing internal
`x-datalox-*` control headers are rejected; credentials are consumed at
the boundary and excluded from behavior evidence.

For controlled robustness experiments, a consumer may add a switchable seeded
[delivery intervention](docs/delivery-interventions.md) after an admitted
provider response. The provider ledger remains the grounded base record; a
separate trace records the counterfactual or applied intervention and the exact
observation delivered to the agent. Datalox applies the consumer-owned policy
without choosing its distribution, retrying, or normalizing its output.

## Verify the transparent runtime offline

Requirements: Python 3.11 or newer. No provider account, API key, network
connection, or model is required.

Core HTTP/MCP gating and offline world execution are package-smoked on Linux,
macOS, and Windows. Secure composition event storage, transparent interception
control sockets, and rollout-pool serving currently require a POSIX host; use a
Linux container for those execution paths on Windows hosts. Unsupported
composition storage fails before creating session files with the stable code
`session_event_platform_unsupported`.

```bash
git clone https://github.com/Oshawott324/datalox-gated-runtime.git
cd datalox-gated-runtime
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -m pytest -q \
  tests/test_interception_tls.py \
  tests/test_provider_runtime_bundle.py \
  tests/test_interception_deployment.py
```

These checks exercise the actual provider-runtime entry point. They:

1. compile a task-free behavior bundle from existing stateful behavior;
2. start a real TLS listener for an exact provider authority;
3. call the unchanged `https://provider-authority/...` URL;
4. perform a local write and read the resulting state;
5. export and reset through a controller-only Unix socket;
6. prove that the agent cannot reach control paths or read controller secrets;
7. generate Docker and Kubernetes injection artifacts; and
8. keep the provider runtime free of tasks, verifiers, rewards, and upstream clients.

For the full build and injection commands, see
[Transparent Interception](docs/transparent-interception.md#compile-a-provider-runtime).

## Use a world from an existing agent framework

The repository also contains two self-contained framework examples:

- [Harbor incident coordination](integrations/harbor/incident_customer_coordination_v0/)
  is an ordinary Harbor task with role-scoped MCP tools and a separate hidden
  verifier.
- [Mastra commerce support](integrations/mastra/commerce_support_ops_v0/)
  uses Mastra MCPClient, Datasets, Experiments, and a deterministic scorer over
  a fresh world per dataset item.

Both examples run without provider credentials. They use synthetic episodes
with source-grounded provider shapes to test the framework integration
boundary, not to claim live-provider behavioral fidelity. See
[Harness Integrations](integrations/) for the shared research question.

## Use provider packs in veRL / GRPO

Current veRL users can keep their normal V1 `ToolAgentLoop`, function tools,
dataset, rewards, and GRPO command. Datalox wraps each `(uid, session_id)`
rollout sibling with a private reset provider state and workspace. Provider
tools still call the exact provider HTTPS URL; a trusted node-local pool runs
those calls inside the sibling's internal Docker network.

```bash
datalox-gate rollout provider-set \
  --bundle /opt/datalox/providers/provider-a \
  --out /opt/datalox/rollout-providers.json

datalox-gate rollout pool-serve \
  --provider-set /opt/datalox/rollout-providers.json \
  --runtime-image datalox-gated-runtime:local \
  --task-image datalox-verl-provider-call:example \
  --capacity 64 \
  --artifacts-root /var/lib/datalox/rollouts \
  --socket /run/datalox/rollout-pool.sock
```

For admitted behavior across multiple providers, use
`rollout pool-serve-composition` with a registry-backed Provider Set v2,
Composition Pack, composition admission, fixed episode seed, and fixed initial
delivery-scheduler time. It serves the same pool socket, so the veRL agent-loop
YAML, function tools, GRPO launch command, and `AgentLoopOutput` do not change.
The model and dataset cannot choose those operator-owned composition inputs.

The adapter returns veRL's original `AgentLoopOutput` object unchanged. See the
checked [veRL and GRPO rollout integration](docs/verl-grpo-rollouts.md) for the
agent-loop YAML, `@function_tool` example, task image, dataset fields, launch
fragment, isolation contract, and verification commands.

Current THUDM/slime users can keep the normal
`--custom-generate-function-path`, `--custom-rm-path`, and
`--custom-config-path` workflow. One provider-state lease surrounds the user's
original custom-generation call; `Sample` or `list[Sample]` outputs and reward
semantics remain owned by slime and the user. See the checked
[THUDM/slime integration](docs/slime-rollouts.md) and its boundary-safe provider
callback, dispatcher image, configuration, and launch fragment under
[`integrations/slime/`](integrations/slime/).

## Build provider behavior for your world

The default workflow is sandbox-first:

```text
audit official sandbox or disposable reference system
  -> declare the smallest complete operation-family scope
  -> execute reviewed behavior recipes outside the runtime
  -> capture before / write / duplicate / failure / after evidence
  -> compile the evidenced slice into reusable fuel
  -> compile an authority-bound provider runtime bundle
  -> inject that bundle into the consumer's isolated world
  -> let the consumer verify state, failures, reset, and known gaps
```

Do not rebuild a provider sandbox merely to increase a provider count. Local
reimplementation is justified when a concrete requirement needs offline scale,
deterministic reset, parallelism, missing sandbox behavior, controllable
failures, lower cost, or a distributable partner environment.

Start with [Provider Packs](docs/provider-packs.md), then read
[Provider Behavior Grounding](docs/provider-behavior-grounding.md) and
[Transparent Interception](docs/transparent-interception.md).

The portable construction path is provider-neutral. Current depth work applies
the same authoring, compilation, differential, reset, provider-runtime, and
container-injection contracts to specialized operational systems instead of
treating one well-built commercial sandbox as the product. HUD, Harbor,
OpenEnv, and custom harnesses remain downstream owners of their worlds. The checked provider-by-provider
status and exact claim boundaries are summarized in
[Provider Behavior Grounding](docs/provider-behavior-grounding.md#current-specialized-harvest-wave).

For harnesses that consume native MCP servers, the same provider runtime can be
projected without rewriting provider behavior. The EnvFactory adapter emits its
native tool, metadata, scenario, and config paths and includes a pinned patch
for state-isolated pass@k execution. See
[EnvFactory Provider Adapter](docs/envfactory-provider-projection.md).

## Repository map

| Path | Purpose |
| --- | --- |
| [`src/datalox_gated_runtime/provider_runtime/`](src/datalox_gated_runtime/provider_runtime/) | Task-free, content-addressed provider behavior bundles and resettable execution |
| [`src/datalox_gated_runtime/composition/`](src/datalox_gated_runtime/composition/) | Explicit provider-mediated causal edges, delivery-scheduler time, evidence, and admission |
| [`src/datalox_gated_runtime/sdk_adapters/`](src/datalox_gated_runtime/sdk_adapters/) | Execution-boundary adapters that preserve native SDK calls for providers without an HTTP API |
| [`src/datalox_gated_runtime/interception/`](src/datalox_gated_runtime/interception/) | Exact-authority TLS data plane, private control plane, and container injection |
| [`src/datalox_gated_runtime/rollout/`](src/datalox_gated_runtime/rollout/) | Task-free provider sets and isolated concurrent rollout leases |
| [`integrations/verl/`](integrations/verl/) | Current veRL `ToolAgentLoop`, function-tool, task-image, and GRPO launch example |
| [`integrations/slime/`](integrations/slime/) | Current THUDM/slime custom-generate, batch-reward, task-image, and launch example |
| [`docs/rollout-information-boundary.md`](docs/rollout-information-boundary.md) | Task, causal observation, and trusted evaluation separation contract |
| [`schemas/rollout-information-boundary-v1.schema.json`](schemas/rollout-information-boundary-v1.schema.json) | Machine-readable rollout information-plane declaration |
| [`src/datalox_gated_runtime/harness_adapters/`](src/datalox_gated_runtime/harness_adapters/) | Downstream harness projections over the same provider behavior runtime |
| [`src/datalox_gated_runtime/behavior_harvest/`](src/datalox_gated_runtime/behavior_harvest/) | Authoring-only provider behavior capture and compilation contracts |
| [`envs/commerce_support_ops_v0/`](envs/commerce_support_ops_v0/) | Public synthetic stateful reference world |
| [`probes/`](probes/) | Public provider probe declarations |
| [`scripts/check_provider_runtime_coverage.py`](scripts/check_provider_runtime_coverage.py) | Recompile/reset check for every registered provider asset |
| [`scripts/providers/`](scripts/providers/) | Manually approved provider/reference authoring and evidence checks |
| [`schemas/provider-runtime-v2.schema.json`](schemas/provider-runtime-v2.schema.json) | Current provider-runtime bundle contract |
| [`schemas/provider-runtime-v1.schema.json`](schemas/provider-runtime-v1.schema.json) | Historical provider-runtime v1 contract |
| [`schemas/provider-identity-v1.schema.json`](schemas/provider-identity-v1.schema.json) | Provider-native identity-to-role policy contract |
| [`schemas/provider-release-v1.schema.json`](schemas/provider-release-v1.schema.json) | Immutable OCI Provider Release contract |
| [`schemas/composition-pack-v1.schema.json`](schemas/composition-pack-v1.schema.json) | Authored provider-mediated composition claim contract |
| [`docs/world-packages.md`](docs/world-packages.md) | Legacy Datalox-owned world package compatibility path |
| [`scripts/public_release.py`](scripts/public_release.py) | Deterministic public-source builder and verifier |
| [`docs/`](docs/) | Product, grounding, admission, security, and data contracts |

## Develop and verify

With the locked `uv` environment:

```bash
uv sync --frozen --extra dev
uv run pytest -q
uv run ruff check . --select E4,E7,E9,F
```

Build and verify the exact public tree:

```bash
uv run python scripts/public_release.py check
uv run python scripts/public_release.py build --out .tmp/public-source
uv run python scripts/public_release.py verify-built --source .tmp/public-source
```

The release gate fails closed on unclassified data, missing or changed digests,
private machine paths, unresolved public documentation links, unexpected files,
test failures, formatting failures, or package-build failures.

## Current status

Datalox currently proves exact-authority TLS interception, zero runtime provider
clients, task-free provider bundle compilation, stateful local behavior,
controller-only reset/export, and Docker/Kubernetes injection. All 48 registered
provider-scoped assets pass compilation and reset under this contract; that does
not mean all 48 are core-complete, writable, or behaviorally equivalent to the
provider. The exact structural result is in
[`docs/reports/provider-runtime-coverage.json`](docs/reports/provider-runtime-coverage.json).
Public checkouts can validate that report with
`python scripts/check_provider_runtime_coverage.py --validate-report`; the full
controlled source superset uses `--check` to recompile every underlying asset.

The project is early. The most valuable contributions are complete behavior
programs, stronger reset and failure evidence, reusable verifier atoms, and
well-scoped worlds—not raw endpoint count.

## Contributing, security, and governance

Read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting code or provider
material. Do not put credentials, tenant data, provider payloads, or sandbox
write transcripts in a public issue or pull request.

Security reports follow [SECURITY.md](SECURITY.md). Project decisions and
release authority are described in [GOVERNANCE.md](GOVERNANCE.md), and support
channels are described in [SUPPORT.md](SUPPORT.md).

Licensed under the [Apache License 2.0](LICENSE).
