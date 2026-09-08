# Medusa 2.16.0 Store cart provider release

`envs/medusa_store_cart_v0` is a public, bounded Provider Release for a
self-hosted Medusa **2.16.0** Store API. Its purpose is to ground Datalox's
write lifecycle machinery in one writable reference release. It is not a claim
about Medusa Cloud, production tenants, or all Medusa behavior.

The task-free release exposes the original provider-shaped surface:

| Operation | Native route | Grounded lifecycle |
|---|---|---|
| List products | `GET /store/products` | 200 pagination; missing/invalid Store key 400 |
| Create cart | `POST /store/carts` | 200 create; exact repeat creates a second cart; invalid region 404 atomically |
| Retrieve cart | `GET /store/carts/{id}` | 200 readback; missing cart 404 |
| Add line item | `POST /store/carts/{id}/line-items` | 200 add; exact repeat increments the same line; invalid variant 400 atomically |
| Update line item | `POST /store/carts/{id}/line-items/{id}` | 200 quantity set; exact repeat leaves state unchanged; invalid quantity 400 atomically |
| Delete line item | `DELETE /store/carts/{id}/line-items/{id}` | 200 delete; exact repeat returns 200 without another mutation; missing cart returns the observed 500 shape |

All successful writes in this slice are synchronous 200 responses followed by
readback. This release contains **no async, webhook, eventual-consistency,
rate-limit, production authorization, payment, shipping, tax, inventory, or
promotion evidence**. Those behaviors require separate acquisition and
admission.

## Evidence boundary

The G2 grounding source is an exact, locally deployed MIT-licensed Medusa
2.16.0 release. A restricted, digest-bound grounding receipt retains exact
request and response bodies, ordered response headers, exact before/after
snapshots of the declared cart-state projection, and credential commitments. An offline checker
independently derives every promoted lifecycle fact from that receipt. Public
evidence retains only:

- exact release and route-source digests;
- native status and error-type facts;
- symbolic relationships such as “repeat create returns a distinct cart” and
  “repeat add increments the same line”;
- mutation/no-mutation and readback assertions.

The state evidence is deliberately bounded to two Medusa tables and excludes
timestamps:

- `cart`: `id`, `region_id`, `customer_id`, `sales_channel_id`, `email`,
  `currency_code`, shipping/billing address ids, `metadata`, `locale`, and
  completed/deleted presence;
- `cart_line_item`: ids, cart/product/variant links, descriptive product and
  variant fields, quantity, price/raw-price fields, shipping/discount/tax and
  custom-price/gift-card flags, option values, metadata, and deleted presence.

Therefore atomicity means no change within this exact cart-state projection;
it is not a claim about every Medusa database table or external side effect.

The public source retains no credential, tenant identifier, raw request or
response body, or provider-generated cart/line identifier. The restricted
receipt comes from a synthetic disposable tenant and is excluded from the
public-source builder. Runtime fixtures, deterministic
identifier values, and error messages are self-authored. The public local key
`pk_datalox_local_store` is a dummy fixture input, not a captured provider key.
Its value is stored only where the local SDK/tool fixture needs to inject it;
the compiled credential policy binds its digest and strips the header before
provider behavior and call evidence.

The retained source is
[`observations.json`](../envs/medusa_store_cart_v0/evidence/observations.json),
with exact source provenance in
[`provenance.json`](../envs/medusa_store_cart_v0/evidence/provenance.json).
The public
[`grounding-report.json`](../envs/medusa_store_cart_v0/evidence/grounding-report.json)
identifies the checked receipt digests without distributing its payloads.

## Three distinct checks

The release keeps these claims separate:

1. **Provider acquisition and grounding check:** the authoring-only utility
   executes the lifecycle against a freshly seeded disposable Medusa 2.16.0
   instance, writes a restricted exact receipt plus sanitized public facts,
   and the offline checker recomputes the promoted facts, response framing,
   complete duplicate-request identity, and cart-state projection continuity
   from raw evidence.
2. **Provider differential:** the local implementation is compared step by
   step with those retained statuses, ID relations, duplicate effects,
   failure atomicity, and readbacks.
3. **Local reset equivalence:** after mutations, the compiled runtime resets to
   its initial state and the complete local differential is repeated. This is
   local runtime evidence, not a claim that Medusa supplies an in-place tenant
   reset API.

The checked differential report contains every normalized step:
[`differential-report.json`](../envs/medusa_store_cart_v0/evidence/differential-report.json).

## Rebuild and verify

```bash
PYTHONPATH=src python scripts/providers/build-medusa-store-cart-release.py \
  --out /tmp/medusa-store-cart-release

PYTHONPATH=src python scripts/providers/check-medusa-store-cart-lifecycle.py \
  --json

PYTHONPATH=src python -m pytest -q \
  tests/test_medusa_store_cart_provider.py
```

The public builder validates the promoted observations, provenance, and
digest-bound grounding attestation, validates the source world, compiles the
credential-mapped task-free runtime, runs executable admission, builds the OCI
Provider Release, and runs the two-cycle differential. It neither reads nor
requires the restricted receipt. The reproducibility test removes restricted
evidence from its source fixture and requires every generated public byte to
match the committed release.

The stronger raw-to-public grounding gate remains deliberately separate:
`check-medusa-store-cart-grounding.py` reads the classified restricted receipt
and independently re-derives the public attestation. Run that checker in the
private authoring workspace before promoting a new receipt or changing the
public grounding report:

```bash
PYTHONPATH=src python scripts/providers/check-medusa-store-cart-grounding.py \
  --json

PYTHONPATH=src python -m pytest -q \
  tests/private/test_medusa_store_cart_grounding.py
```

## Re-acquire from a disposable reference

Acquisition is an explicit authoring action and never runs in provider-runtime
execution. Start a freshly seeded local Medusa 2.16.0 instance with zero carts,
provide its real local values through arguments/environment, and write into a
review directory outside the public data root:

```bash
export MEDUSA_PUBLISHABLE_API_KEY='...'
export MEDUSA_DATABASE_URL='postgresql://...'

PYTHONPATH=src python \
  scripts/providers/acquire-medusa-store-cart-lifecycle.py \
  --authorize-disposable-writes \
  --base-url http://127.0.0.1:9000 \
  --backend-root /path/to/exact-medusa-2.16.0-backend \
  --region-id "$MEDUSA_REGION_ID" \
  --variant-id "$MEDUSA_VARIANT_ID" \
  --observed-at "$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
  --private-receipt-dir /path/to/restricted-receipt-candidate \
  --out /tmp/medusa-store-cart-candidate
```

The utility verifies the exact package version and installed route digests,
checks the database is initially empty, executes real Store writes, validates
duplicate and atomic-failure relations, and writes the two artifacts through
separate explicit paths. Review the raw receipt for rights and sensitivity,
run `check-medusa-store-cart-grounding.py`, then promote it only under a
classified restricted evidence path. Destroy the disposable instance after
acquisition. Never place the restricted receipt in the public source tree.

## Downstream rollout use

The Verifiers integration consumes this release as provider behavior. The model
chooses provider calls and arguments from observations; Datalox does not supply
an action sequence. The consumer owns the task, intervention policy, verifier,
reward, and training loop. See
[`verifiers-dirty-integration.md`](verifiers-dirty-integration.md).
