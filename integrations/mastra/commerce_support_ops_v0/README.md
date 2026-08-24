# Datalox x Mastra: stateful commerce-support experiment

This is a small, runnable Mastra integration for evaluating an agent on a
stateful cross-service workflow. The agent investigates a duplicate payment
across Stripe-shaped billing, commerce orders, HubSpot-shaped support, Jira,
and Microsoft Graph-shaped scheduling, then performs the permitted refund and
internal coordination steps.

## Research question

Can Mastra own the agent, dataset, and experiment while each dataset item gets
a fresh external software world with provider-shaped MCP tools, resettable
state, and hidden state verification?

This package tests that boundary using Mastra's native evaluation primitives.
Mastra schedules and records the experiment; the packaged world owns episode
state, reset, tool policy, and the deterministic outcome.

The provider behavior is source-grounded and synthetic. No provider account or
credential is required. It is a reference integration for the Datalox runtime,
not a claim that the episode contains live customer data.

## Run it

Prerequisites: Node.js 22.13+ and a running Docker daemon.

```bash
npm install
npm run verify
```

`verify` runs three checks:

1. TypeScript and unit tests.
2. A keyless positive Mastra experiment that must receive reward `1`.
3. A keyless negative Mastra experiment that attempts a forbidden send and
   must receive reward `0`.

Both controls use Mastra Datasets, Experiments, MCPClient, and a deterministic
Mastra scorer. They validate the integration without pretending a scripted
policy measures model quality.

To evaluate a real Mastra agent:

```bash
export OPENAI_API_KEY=your-key
export MASTRA_MODEL=openai/gpt-5-mini  # optional; this is the default
npm run experiment
```

The command exits successfully even when the agent receives reward `0`; that
is an evaluation result, not an infrastructure failure. Docker, MCP, model
provider, finalization, or persistence failures still make the command fail.

Run Mastra Studio after an experiment to inspect the persisted dataset and
results:

```bash
npm run studio
```

## What happens per dataset item

```text
Mastra experiment task
  -> fresh Datalox world container
  -> role-scoped MCP endpoints
  -> Mastra agent and MCPClient
  -> trusted out-of-band finalizer
  -> hidden state reward
  -> Mastra scorer and experiment result
  -> container removed
```

The agent receives MCP tools, not Docker access, the mutable state database, or
the verifier. The host-side experiment task owns reset and finalization. This
is why the example uses Mastra's inline experiment task rather than a plain
`targetType: "agent"`: every item needs its own world lifecycle.

The selected episode requires evidence collection and coordinated writes
across six operation families and four actor roles. Dangerous operations remain
visible as realistic policy traps, but the gate denies them and the verifier
checks final state and process invariants instead of grading the agent's prose.

## Results

Local state is written under `.datalox/`:

- `mastra.db`: Mastra dataset and experiment records.
- `results/<run-id>/verdict.json`: the package-bound Datalox verdict.
- `results/<run-id>/run-result.json`: the visible target output plus verdict.
- `experiments/<experiment-id>.json`: a readable Mastra summary.

Set `DATALOX_DATA_DIR` to place these artifacts elsewhere.

## Reuse

The Mastra code is intentionally provider-agnostic. A second admitted Datalox
world can reuse the same controller, dataset task, and scorer. The world
package, role endpoint list, tool aliases, and task prompt are the integration
inputs that change.
