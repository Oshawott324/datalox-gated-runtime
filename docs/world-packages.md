# Legacy Reference World Packages

> This is a compatibility and regression surface, not Datalox's primary
> delivery unit. New integrations should inject a task-free provider runtime
> into the consumer's existing Docker or Kubernetes world. HUD, Harbor, and
> other harnesses keep ownership of the task, agent, verifier, and reward.

A Datalox world package is the provider-neutral delivery unit for one admitted
world episode. It is an OCI build context, not an agent image and not a second
provider implementation.

```text
admitted world + selected episode + locked runtime
  -> runtime-only compiled episode template
  -> content-addressed OCI build context
  -> fixed gated MCP endpoint
  -> controller-only finalization and verdict
```

The adapters below exercise older Datalox-owned reference fixtures. They remain
useful tests, but they are not the current contract for integrating provider
behavior into an external world. That contract is documented in
[Transparent Interception](transparent-interception.md).

## Build one package

```bash
datalox-gate env export-world \
  --env envs/<environment-id> \
  --format oci \
  --out /private/operator/path/datalox-world

docker build -t datalox/world:local \
  /private/operator/path/datalox-world
```

Use `--episode <episode-id>` to select a non-default episode. The input world
must have a current successful `world_admission.json`; packaging never weakens
or silently refreshes admission.

The build context contains:

- `DATALOX_WORLD.json`, which binds the package, source world, selected episode,
  task, runtime lock, endpoint, and controller contract by SHA-256;
- `episode_template/`, a runtime-only compiled template containing the selected
  task, initialized SQLite state, executable world code, and explicitly declared
  runtime data;
- `runtime/`, the locked Datalox source and dependency lock; and
- a non-root, digest-pinned `Dockerfile`.

It does not copy authoring sources, evidence directories, trajectories,
captures, provider credentials, or an agent into the image.

## The package is still a gated endpoint

Every running package exposes exactly two network paths:

| Path | Purpose |
| --- | --- |
| `GET /health` | Readiness and exact world/episode identity. |
| `POST /mcp` | Streamable HTTP MCP endpoint backed by one shared `GatedRuntime`. |

The MCP surface includes `get_task`, `gate_request`, and the role-visible world
tools. `gate_request` accepts provider-shaped method, path, query, and body
arguments, so an agent can use the package as a gated HTTP-shaped API through
MCP. Calls still pass through Datalox policy, world state, ledger, and denial
contracts.

There is deliberately no network endpoint for session creation, reset,
finalization, export, or deletion. One container is one fresh episode. Start a
new container to reset it.

## Agent and controller boundary

The evaluated agent receives only the MCP endpoint. It must not receive a bind
mount of the run directory, a Docker socket, or a lifecycle token.

After the agent disconnects or stops, the trusted controller runs the
`controller.finalize_command` declared in `DATALOX_WORLD.json`. That command
verifies the package/run identity, finalizes the ledger and world verifier, and
atomically emits a small verdict bound to:

- package content digest;
- source world-manifest digest;
- world, bundle, episode, and task identities;
- audit digest and run-export digest; and
- pass/fail, reward, and failure codes.

An evaluated agent cannot call this command over HTTP or MCP and cannot read the
verdict before it finishes.

## Legacy MCP fixture path

An MCP-capable agent can connect directly to `http://<world-host>:8000/mcp` for
this legacy fixture.
The agent implementation remains outside the world image. This keeps the same
package usable from a local runner, a custom rollout system, HUD, Harbor, or a
future harness without rebuilding provider behavior for each one.

Legacy harness exports are convenience wrappers:

```bash
datalox-gate env export-world --env <world> --format hud --out <hud-dir>
datalox-gate env export-world --env <world> --format harbor --out <harbor-dir>
```

Both wrappers carry the exact `package_content_sha256` of their embedded
canonical package. Harbor runs the package as an isolated sidecar and collects
only the controller-produced verdict after the agent stops. HUD starts the same
static package service and grades through the same trusted finalizer.

## Distribution boundary

Runtime-only compilation reduces the artifact to executable state, code, task,
and declared runtime data. It does not grant redistribution rights. Every
package and harness adapter inherits the most restrictive classification of its
source world. Build outputs stay outside the repository unless separately
reviewed and classified for release.

## What this does not claim

Packaging proves that an admitted local world is portable, gated, resettable by
fresh instantiation, and externally callable. It does not prove that the local
behavior matches a provider. Provider grounding still requires reviewed
provider or reference-system evidence and a passing differential program.
