# Incident Customer Coordination

This is a Harbor 0.21 task for evaluating an agent on a stateful incident
workflow spanning Datadog, HubSpot, Jira/JSM, and Microsoft Graph.

## Research question

Can an independently produced, stateful software world be delivered as an
ordinary Harbor task without changing Harbor's runner, while the world retains
its reset lifecycle, provider-shaped MCP surface, and hidden state verifier?

This package tests that integration boundary. Harbor owns the agent trial and
reward collection; the packaged world owns episode state and verification.

The agent must investigate a production-service incident, reconcile customer
and ownership evidence across the four systems, and make four related changes:

- assign and prioritize the linked Jira issue;
- transition that issue to the available in-progress state;
- update the linked HubSpot ticket; and
- create an internal Microsoft Graph draft without sending it.

The exact task brief is in `instruction.md`.

## Why this task exists

The task is intended to exercise behavior that single-call tool tests miss:

- discovering identifiers from reads instead of relying on memorized values;
- reconciling stale and current ownership across services;
- selecting one account from competing customer and renewal evidence;
- carrying one policy decision consistently into several writes;
- preserving cross-call state; and
- avoiding plausible but forbidden side effects.

The verifier does not grade the agent's final prose. After the agent exits,
Harbor asks the world sidecar to finalize its persisted state and call ledger.
A separate verifier accepts only the resulting bound verdict.

## Grounding and limits

This package contains one resettable synthetic episode with source-grounded
provider shapes. It is G1 modeled behavior derived from official schemas and
documentation, not a recording of live tenant traffic. All people, companies,
accounts, incidents, and messages are synthetic. No provider account,
credential, or internet access is required during a run.

The package is evidence that Harbor can run and verify a cross-service,
stateful MCP task. It is not a claim of complete Datadog, HubSpot, Jira, or
Microsoft Graph production fidelity.

## Run the supplied reference solution

Requirements: Docker 24+ and Python 3.11+.

```bash
uv tool install harbor==0.21.0
docker info >/dev/null
harbor run -p . -a oracle -o jobs
```

The trial should finish with reward `1.0`. The reference solution is included
so the task can be validated without a model key.

## Run an agent

Use any Harbor-supported agent and model. For example:

```bash
harbor run -p . -a codex -m <model> -o jobs
```

Harbor mounts three controller-authorized MCP servers for the incident
commander, support owner, and communications roles. The agent can use their
normal Harbor MCP integration; it does not choose or send Datalox role headers.

## Package anatomy

- `instruction.md`: agent-visible task and success criteria.
- `task.toml`: Harbor 1.4 task metadata, MCP mounts, collection hook, and
  artifact declaration.
- `environment/world/`: immutable Datalox world image build context.
- `solution/`: Harbor Oracle reference solution.
- `tests/`: separate verifier image and fail-closed grader.
- `DATALOX_ADAPTER.json`: content hashes for the complete adapter package.

The episode exposes 22 role-scoped MCP tools. The intended successful path has
provider reads plus exactly four permitted state-changing calls. Unknown calls,
unauthorized role/tool combinations, and forbidden sends or incident mutations
are recorded and fail verification.
