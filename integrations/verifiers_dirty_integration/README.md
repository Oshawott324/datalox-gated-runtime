# Datalox paired intervention fixture for Verifiers

This is a downstream experiment fixture for Serhii Nazarov's
[`dirty-integration`](https://github.com/buildok/dirty-integration). It keeps
the familiar Verifiers 0.3.1 legacy loading surface while placing an admitted,
task-free Datalox provider runtime beneath the task:

```python
import verifiers as vf

common = {
    "profile": "hostile",
    "intervention_seed": "7",
}
off = vf.load_environment(
    "datalox-dirty-integration",
    intervention_enabled=False,
    **common,
)
on = vf.load_environment(
    "datalox-dirty-integration",
    intervention_enabled=True,
    **common,
)
```

The task rows contain only agent-visible instructions. The profile, mode, and
seed remain operator arguments on the environment and never enter the client-visible
Verifiers state.

The consumer package owns the task, seeded policy, model loop, oracle, and two
reward components. Datalox owns the admitted base-provider execution and exact
delivery of the consumer's intervention decision.

## Run the paired experiment

From the repository root, one command installs the two editable packages in an
isolated uv environment and writes both sides of the experiment:

```bash
uv run \
  --project integrations/verifiers_dirty_integration \
  datalox-dirty-pair \
  --profile hostile \
  --intervention-seed 7 \
  --output /tmp/datalox-serhii-pair
```

The command binds both sides to the same task digest, immutable OCI provider
release and profile, provider-state fingerprint, policy digest, and policy seed. Only
`intervention_enabled` changes.

```text
/tmp/datalox-serhii-pair/
├── pair-manifest.json
├── comparison.json
├── off/
│   ├── provider-export.json
│   ├── intervention-trace.json
│   ├── agent-trace.json
│   └── verification.json
└── on/
    ├── provider-export.json
    ├── intervention-trace.json
    ├── agent-trace.json
    └── verification.json
```

The off trace still records the counterfactual policy decision. It delivers the
base provider response unchanged. The on trace records and applies the same
decision. Agent actions may diverge after the first delivered-observation
change; that divergence is an experimental result, not a binding failure.

## Exact first slice

The base operation is pinned Medusa 2.16.0 Store API offset pagination:

```text
GET https://api.medusa.local/store/products?limit=10&offset=N
```

It uses the admitted first, middle, terminal, and beyond-terminal page behavior
in `envs/medusa_store_pagination_v0`. The interventions are:

- a provider-shaped pre-dispatch `429` quota response;
- a post-response repetition of an earlier base page; and
- a post-response `count` integer-to-decimal-string change.

Medusa exposes `limit` and `offset`, not an opaque cursor. The reference client
therefore validates the returned offset and retries the same provider-supported
request. It never decodes or manufactures a cursor. Native transport timeout
injection is outside this v1 slice because the in-process response boundary
cannot honestly reproduce a client transport timeout.

Task correctness and request discipline are separate reward functions.
Request discipline measures useful-provider-call efficiency and delivered 429s;
it does not change task correctness.

See [`docs/verifiers-dirty-integration.md`](../../docs/verifiers-dirty-integration.md)
for the evidence and information-plane contract. Third-party attribution and
the reviewed upstream digests are in [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md)
and [`upstream-contract.json`](upstream-contract.json).
