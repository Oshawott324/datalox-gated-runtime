# Harness Integrations

These examples test one research question:

> Can an independently produced, resettable software world plug into an
> existing agent framework while the framework owns the agent rollout and the
> world owns provider-shaped tools, episode state, reset, and hidden
> verification?

Both packages are self-contained and credential-free. They contain synthetic
episodes with source-grounded provider shapes. They test the integration and
evaluation boundary; they do not claim fidelity to live provider tenants.

| Framework | Example | What it proves | Credential-free check |
| --- | --- | --- | --- |
| Harbor | [Incident customer coordination](harbor/incident_customer_coordination_v0/) | A Datalox world can run as an ordinary Harbor task with role-scoped MCP tools and a separate state-based verifier. | `harbor run -p . -a oracle -o jobs` |
| Mastra | [Commerce support operations](mastra/commerce_support_ops_v0/) | Mastra can own its dataset and experiment while each item receives a fresh external world and a deterministic scorer over hidden world state. | `npm install && npm run verify` |

The examples deliberately include negative behavior that plausible final-answer
grading can miss. An unauthorized external send is denied and causes the run to
fail even when the agent could describe the intended workflow correctly.
