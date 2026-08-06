<div align="center">

# Datalox Gated Runtime

### Stateful, resettable, verifiable API worlds for tool-using agents

**Run long agent workflows against provider-shaped systems without giving the
evaluated agent live provider write access.**

[Product thesis](docs/what-we-are-building.md) ·
[Provider packs](docs/provider-packs.md) ·
[Behavior grounding](docs/provider-behavior-grounding.md) ·
[Behavior harvest](docs/provider-behavior-grounding.md#current-specialized-harvest-wave) ·
[Portable packages](docs/world-packages.md) ·
[World admission](docs/world-admission-rubric.md)

</div>

> Datalox sits between an agent and its tools. It decides what every call does,
> mutates resettable local state, records the execution, and verifies the final
> workflow.

Most tool benchmarks ask whether a model can answer a question or complete one
API call. Real work is longer. It crosses roles and systems, creates related
objects, waits for asynchronous jobs, encounters conflicts, and leaves durable
state behind. A plausible final message does not prove that the workflow was
correct.

Datalox provides the execution substrate for testing that work.

```text
task
  -> agent calls HTTP or MCP tools normally
  -> Datalox gates every call
  -> replayed reads and local writes change resettable world state
  -> the ledger records decisions, responses, and side effects
  -> hidden verifiers judge the final state and workflow evidence
  -> the run becomes replayable evidence
```

## What Datalox is—and is not

| Datalox is | Datalox is not |
| --- | --- |
| An open runtime for provider-shaped, stateful API environments | A proxy for unrestricted production API access |
| A way to compose reusable API building blocks into resettable worlds | A directory of disconnected mocked endpoints |
| A verifier and evidence layer for complete agent workflows | An agent framework, planner, memory system, or model router |
| A sandbox-first path for learning provider behavior | A claim that documentation examples reproduce production behavior |
| Infrastructure that benchmarks can run on | One benchmark or one vertical application |

The vocabulary is deliberate:

- **Fuel** is a reusable gated provider/API building block: operation contracts,
  behavior recipes, transitions, verifier atoms, provenance, and known gaps.
- **A world** composes fuel into a stateful environment with roles, tasks,
  reset, dynamics, and hidden verification.
- **A benchmark** consumes worlds to evaluate agents.

Fuel is not a benchmark. A provider pack is not automatically a complete world.
World admission is not automatically proof of provider equivalence.

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
- versioned provider-pack, behavior-recipe, and world-bundle contracts;
- validators, compilers, admission checks, and verifier composition;
- public probe declarations and capture utilities;
- a fully synthetic, stateful commerce reference world; and
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
| `live_capture` | Perform an explicitly approved live `GET` and capture its response. |
| `deny` | Reject an unsafe or unsupported call with an agent-readable error. |
| `miss` | Record an unknown call so the environment can be extended deliberately. |

Live provider writes are intentionally inexpressible in the runtime. Approved
sandbox writes belong to a separate, manually authorized behavior-authoring
process against an exact test account.

## Try a complete world offline

Requirements: Python 3.11 or newer. No provider account, API key, network
connection, or model is required.

```bash
git clone https://github.com/Oshawott324/datalox-gated-runtime.git
cd datalox-gated-runtime
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python scripts/demo/offline-world-smoke.py
```

The demo does more than ping an endpoint. It:

1. creates a fresh commerce-operations world;
2. discovers role-scoped provider-shaped tools;
3. reads initial state;
4. performs a multi-step workflow containing real local mutations;
5. verifies the final state and workflow evidence;
6. destroys and resets the world;
7. proves equivalent capabilities, observations, and initial state; and
8. replays the workflow and proves an equivalent final export.

It exits nonzero if mutation, verification, functional reset, or replay
equivalence fails.

## Build a provider-grounded world

The default workflow is sandbox-first:

```text
audit official sandbox or disposable reference system
  -> declare the smallest complete operation-family scope
  -> execute reviewed behavior recipes outside the runtime
  -> capture before / write / duplicate / failure / after evidence
  -> compile the evidenced slice into reusable fuel
  -> compose fuel into a resettable world
  -> verify state, failures, reset, and known gaps
```

Do not rebuild a provider sandbox merely to increase a provider count. Local
reimplementation is justified when a concrete requirement needs offline scale,
deterministic reset, parallelism, missing sandbox behavior, controllable
failures, lower cost, or a distributable partner environment.

Start with [Provider Packs](docs/provider-packs.md), then read
[Provider Behavior Grounding](docs/provider-behavior-grounding.md) and
[World Admission Rubric](docs/world-admission-rubric.md).

The portable construction path is provider-neutral. Current depth work applies
the same authoring, compilation, differential, reset, admission, OCI, HUD, and
Harbor contracts to specialized operational systems instead of treating one
well-built commercial sandbox as the product. The checked provider-by-provider
status and exact claim boundaries are summarized in
[Provider Behavior Grounding](docs/provider-behavior-grounding.md#current-specialized-harvest-wave).

## Repository map

| Path | Purpose |
| --- | --- |
| [`src/datalox_gated_runtime/`](src/datalox_gated_runtime/) | Gating, replay, state, ledger, audit, MCP, and world runtime |
| [`src/datalox_gated_runtime/behavior_harvest/`](src/datalox_gated_runtime/behavior_harvest/) | Authoring-only provider behavior capture and compilation contracts |
| [`envs/commerce_support_ops_v0/`](envs/commerce_support_ops_v0/) | Public synthetic stateful reference world |
| [`probes/`](probes/) | Public provider probe declarations |
| [`scripts/demo/offline-world-smoke.py`](scripts/demo/offline-world-smoke.py) | Credential-free end-to-end proof |
| [`scripts/providers/`](scripts/providers/) | Manually approved provider/reference authoring and evidence checks |
| [`docs/world-packages.md`](docs/world-packages.md) | Provider-neutral OCI package, gated endpoint, controller, HUD, and Harbor contract |
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

Datalox currently proves deterministic gated execution, stateful local worlds,
functional reset, replayable evidence, and verifier-driven evaluation. It does
not claim that every represented provider is core-complete or behaviorally
equivalent to production.

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
