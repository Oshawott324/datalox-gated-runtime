# Stripe Engineering Proof

This is the first vertical proof of the Datalox construction machine:

```text
reviewed Stripe test-mode acquisition
-> exact capture validation
-> reference-trace compilation
-> provider-versus-world differential
-> functional reset differential
-> admitted world
-> canonical OCI world package
-> HUD and Harbor adapters
```

Stripe is used because an isolated writable test environment is readily
available. The purpose is to prove this pipeline, not to rebuild or claim full
equivalence with the Stripe sandbox.

## Exact scope

The provider-grounded slice is the four-step
`idempotency_parameter_conflict` program:

1. create a synthetic test-mode customer with an idempotency key;
2. repeat the exact request and key;
3. reuse the key with different parameters and capture Stripe's native error;
4. read the created customer and verify the resulting state.

The compiler compares only fields asserted by the reviewed program. It does
not discard a mismatch, infer undocumented semantics, or widen this evidence
to the other Stripe operations.

The existing Stripe world remains a broader local implementation. Its world
admission proves local execution, reset, safety, and verifier behavior. Only
the four-step slice above becomes provider-grounded after a real capture and a
passing differential report.

## What is implemented

- The manually approved authoring runner and independent offline checker.
- A compiler from the validated Stripe capture to
  `datalox_reference_trace_v2`, followed by the provider-neutral
  `datalox_engineering_proof_v1` runner. Stripe no longer owns a separate
  differential target or proof orchestrator.
- An explicit comparison profile for status, customer identity binding,
  asserted customer fields, test-mode shape, duplicate response, and native
  idempotency error type.
- Two executions against fresh local worlds. Their observable transcript
  fingerprints must match, which makes reset behavioral rather than merely a
  comparison of two initial database hashes.
- World admission after the differential.
- A provider-neutral, runtime-only, content-addressed OCI package with fixed
  `/mcp`, no agent-accessible lifecycle API, and controller-only finalization.
- HUD `0.6.12` and Harbor `0.20.0` adapters that embed the exact same canonical
  package digest rather than copying or reimplementing Stripe behavior.

The Stripe world verifier was also tightened. A no-op session now receives
zero reward. Passing requires a linked customer, product, one-time price,
invoice item, finalized and paid invoice using `pm_card_visa`, credit note, and
read-after-write evidence for every resource in that chain.

## Current checkpoint

As of 2026-08-05, the complete offline machine passes a synthetic-transport
test that uses the real authoring runner, evidence checker, compiler, neutral
differential runner, world admission, canonical packager, and both adapters.

The real-provider checkpoint is **not complete**. This workspace has neither
`DATALOX_STRIPE_TEST_SECRET_KEY` nor an independently reviewed test account ID,
and no `testmode_transition_capture_v1.json` exists. No Stripe request was sent
while implementing or testing this proof.

## Run the real checkpoint

First load `DATALOX_STRIPE_TEST_SECRET_KEY` through an approved secret
mechanism. Do not paste it into a command, document, issue, or chat. The
`acct_...` test account ID is not a credential, but it must be reviewed exactly.

The pinned authoring identities are recorded in
[Provider Behavior Grounding](provider-behavior-grounding.md#stripe-checkpoint).
Run the manually approved capture with those exact identities:

```bash
python scripts/providers/capture-stripe-testmode-transitions.py \
  --execute-reviewed-testmode-writes \
  --expected-runner-sha256 sha256:3cd576baead6b64e9e4fa1697337b3611182520a27780bdf4c879ec8abb84500 \
  --expected-manifest-sha256 sha256:59c34ea273c707d2c191f8c7ca6f72c4366e422f3da3da922d169d4c078e8445 \
  --expected-source-pins-sha256 sha256:b7a6b50d9c1c0b618269d1a95fcc613cba9fd719366dd2414bfd2d7ebe9967ce \
  --expected-account-id acct_REVIEWED_TEST_ACCOUNT
```

Compute and independently review the completed capture digest, then run the
offline proof:

```bash
CAPTURE_SHA256="sha256:$(shasum -a 256 envs/stripe_billing_ops_v0/evidence/testmode_transition_capture_v1.json | cut -d' ' -f1)"

python scripts/providers/run-stripe-engineering-proof.py \
  --expected-capture-sha256 "$CAPTURE_SHA256" \
  --expected-account-id acct_REVIEWED_TEST_ACCOUNT \
  --out /private/operator/path/stripe-engineering-proof
```

`proof.json` reports every stage separately. The command exits successfully
only when both differentials pass, functional reset is equivalent, world
admission passes, the OCI package is built, and both adapters are generated.
The provider-side customer identifier used to bind the generated local ID is
not persisted in the proof report.

## Standalone world exports

Any validated `world_bundle_v1` can be projected without running the Stripe
proof:

```bash
datalox-gate env export-world \
  --env envs/stripe_billing_ops_v0 \
  --format oci \
  --out /private/operator/path/stripe-world

datalox-gate env export-world \
  --env envs/stripe_billing_ops_v0 \
  --format hud \
  --out /private/operator/path/stripe-hud

datalox-gate env export-world \
  --env envs/stripe_billing_ops_v0 \
  --format harbor \
  --out /private/operator/path/stripe-harbor
```

Exports are fresh-directory, content-hashed operator artifacts. HUD and Harbor
record the canonical package's exact `package_content_sha256`. All three inherit
the source world's most restrictive distribution classification. Generating an
export does not authorize publication. See
[Portable World Packages](world-packages.md) for the endpoint and controller
boundary.
