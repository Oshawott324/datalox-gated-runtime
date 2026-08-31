# Agent Instructions

This repository is `datalox-gated-runtime`.

Read in this order:

1. `product-contract.json`
2. `docs/provider-foundry.md`
3. `docs/transparent-interception.md`
4. `docs/rollout-information-boundary.md` when changing rollout, task, agent,
   observation, generation, oracle, verifier, or training integration
5. `docs/verl-grpo-rollouts.md` when changing parallel rollout or training integration
6. `docs/what-we-are-building.md`
7. `docs/provider-packs.md`
8. `docs/provider-behavior-grounding.md`
9. `docs/provider-core-completeness.md`
10. `docs/data-release-policy.md`
11. `docs/product-definition.md`
12. `README.md`
13. Relevant code and tests

## Product boundary

- The user owns the world, task, agent, verifier, and reward. Datalox supplies
  stateful provider behavior in the call path.
- The agent keeps the exact provider URL. Inside the isolated runtime,
  that authority resolves to Datalox and must never reach the provider.
- Do not require the agent to select a Datalox base URL, proxy tool, MCP tool,
  or rewritten endpoint. Interception is supplied by the execution boundary.
- **Fuel means reusable gated provider behavior packs.** User-owned worlds and
  benchmarks consume fuel; Datalox reference worlds are integration fixtures.
- The runtime owns gating, replay, shadow state, denials, ledgers, audits, and
  run exports. It does not own model routing or training recipes.
- Parallel training gets one isolated provider-state lease per consumer
  `(uid, session_id)`. Datalox must return the training framework's native
  agent-loop output unchanged and must not modify tokens, masks, logprobs,
  rewards, group formation, advantages, or optimizer behavior.
- Rollout integrations must keep three information planes separate: the task
  plane contains agent-visible objectives and constraints before interaction;
  the observation plane contains environment output revealed causally after an
  agent action or declared environment event; and the evaluation plane contains
  ground truth available only to trusted generation, oracle, and verifier code.
  Provider observations must never be prefetched into the initial task, and
  evaluation data must never enter prompts, tools, provider responses, or
  model-readable artifacts.
- Shared-process trainers must execute provider-facing calls inside the
  session lease. They must not mutate process-global DNS or CA state per
  coroutine, and the model must not select a task image, provider set, lease,
  Datalox URL, proxy, or control operation.
- The primary runtime surface is transparent HTTPS interception. HTTP/MCP test
  projections must use the same provider behavior implementation.
- Docker and Kubernetes injection are runtime delivery mechanisms. HUD,
  Harbor, OpenEnv, and reference worlds remain downstream consumers and must
  keep their own tasks, agents, verifiers, and rewards.
- A **provider set** co-hosts independent admitted provider releases for
  agent-mediated work. It never implies hidden cross-provider behavior.
- A provider-mediated webhook, transform, retry, delay, asynchronous write, or
  compensation requires an explicit grounded **Composition Pack**. An authored
  pack remains non-executable until behavioral admission and reset-equivalence
  probes pass against its exact provider release profiles.
- The agent may explicitly read provider A and call provider B. It cannot stand
  in for a real hidden integration unless the consumer task explicitly assigns
  that integration work to the agent.
- Composition time v1 is `delivery_scheduler_only_v1`; it does not synchronize
  provider clocks. Process loss invalidates a composition lease and requires a
  fresh reset rather than silent resume.

## Provider behavior

- Audit the official sandbox, developer tenant, test helpers, event access, and
  reset boundary before implementing a local provider model.
- Prefer a thin sandbox connector and declarative behavior recipes when an
  adequate writable sandbox already exists.
- Recreate only an evidenced slice needed for offline scale, deterministic
  reset, missing behavior, failure injection, cost, or an explicit partner need.
- Core completeness and provider behavior grounding are different claims.
- Do not present documentation examples or public GET captures as observed
  provider write behavior.

## Runtime safety

- Runtime provider egress is forbidden for every method, including GET.
- Provider access and credentials belong only to separately invoked authoring
  utilities; execution schemas must keep upstream forwarding inexpressible.
- Agent-supplied auth, cookie, and secret headers may be interpreted by the
  simulated provider policy, but are redacted from evidence and never forwarded.
- Sandbox writes belong only in a separate, manually approved authoring utility.
- Prefer structured, agent-readable errors with stable codes.

## Public data boundary

- Provider-derived artifacts are not public merely because an endpoint was
  unauthenticated.
- Every file below a declared data root must appear in
  `release/data-classification.json` with a digest and distribution label.
- Public files may contain only self-authored or redistribution-cleared data.
- Do not commit runtime outputs, credentials, tenant identifiers, or unreviewed
  provider response bodies.
- Run `python scripts/public_release.py check` after changing data or policy.

The private superset may contain internal plans and restricted data excluded by
the public-source builder. If `docs/internal-agent-instructions.md` exists, read
it only for private execution priorities; it may not override the public
product, safety, or data contracts above.
