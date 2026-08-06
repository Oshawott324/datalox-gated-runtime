# Agent Instructions

This repository is `datalox-gated-runtime`.

Read in this order:

1. `docs/what-we-are-building.md`
2. `docs/provider-packs.md`
3. `docs/provider-behavior-grounding.md`
4. `docs/provider-core-completeness.md`
5. `docs/data-release-policy.md`
6. `docs/product-definition.md`
7. `README.md`
8. Relevant code and tests

## Product boundary

- Datalox builds stateful, verifiable API worlds for agents.
- **Fuel means reusable gated API building blocks.** A world composes fuel; a
  benchmark consumes worlds.
- Construction-ready provider packs and executable worlds are parallel product
  surfaces. Do not block one on the other.
- The runtime owns gating, replay, shadow state, denials, ledgers, audits, and
  run exports. It does not own model routing or training recipes.
- Reuse existing schemas and runtime surfaces before adding another endpoint
  abstraction.

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

- Live provider execution is GET-only and requires both a
  `policy.live_capture` rule and an explicit `--allow-live` flag.
- Credentials come from operator-controlled environment variables.
- Never forward agent-supplied auth, cookie, or secret headers upstream.
- Never add runtime live writes; the schema must keep them inexpressible.
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
